//! Dumb-http fetch fallback: read-only fetch from a static-file HTTP remote.
//!
//! A dumb server answers `info/refs` as plain text (no smart
//! `application/x-*-advertisement` document) and serves objects as files:
//! loose objects at `objects/xx/rest` (the zlib of `<type> <len>\0<body>`)
//! and packs listed by `objects/info/packs`. This client mirrors what `git`
//! does on the same fallback: discover refs from the text file, then cover
//! the wanted closure (pack files first when listed, loose objects for the
//! rest), walking links with the shared [`super::pack::object_links`]
//! grammar. Pack objects pass through [`super::pack::ingest_pack`] staging
//! first (dropped unpublished) and then every raw object stages once
//! finally through [`super::pack::stage_local_objects`]: double CPU work
//! for packed objects, a single publication, and identity verification
//! plus [`super::pack::IngestLimits`] matching the smart path byte for
//! byte.
//!
//! Push over dumb-http stays refused: static files accept no pack, so the
//! caller reports [`super::net::dumb_http_gap`].
//!
//! Every network hop reuses the HTTP client bounds (bounded connect and
//! I/O timeouts per request); the hop count is bounded by
//! `max_objects` (the closure walk refuses past it before downloading
//! more). Auth is the helper-then-environment header from
//! [`super::credentials::auth_header_for_url`], the same one smart-http
//! sends.
//!
//! Oracle anchors: `git/Documentation/gitprotocol-http.adoc` ("Dumb
//! Clients"), `git/http-backend.c` (`get_info_refs`, `get_loose_object`,
//! `get_info_packs`), `git/remote-curl.c` (smart-to-dumb fallback on a
//! missing advertisement document), `git/fetch-pack.c` (dumb closure walk
//! over loose plus packs).

use std::collections::{HashMap, HashSet};
use std::io::Read;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;
use ruk_core::store::types::ObjectKind;
#[cfg(test)]
use ruk_core::store::{EventContext, EventSource};

use super::fetch::{FetchWireRequest, ReceivedPack};
use super::has_object;
use super::http;
use super::pack::{IngestLimits, ingest_pack, object_links, stage_local_objects};
use super::pktline::RemoteMessages;
use super::refadv::{AdvertisedRef, Advertisement, Capabilities, ProtocolVersion};
use super::smart_http::{RpcCall, policy_headers};
use crate::{GitError, parse_oid_for};

/// Cap on pack files followed per fetch; the object count inside them is
/// still bounded by `max_objects` during the walk and staging.
const MAX_PACK_FILES: usize = 64;

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// Whether `err` is the dumb-http refusal: a server that answered
/// `info/refs` without the smart advertisement document. Fetch callers use
/// this to fall back here; push callers let it propagate (static files
/// accept no pack).
#[must_use]
pub fn is_dumb_gap(err: &GitError) -> bool {
    matches!(err, GitError::Unsupported { command } if command.contains("dumb-http"))
}

/// Maps a non-2xx status the way the smart client does: the endpoint
/// refused, so the remote is offline. A 404 names the missing repository
/// and a 401/403 names the auth failure; anything else echoes the status.
fn check_status(url: &str, status: u16) -> Result<(), GitError> {
    if http::is_success(status) {
        return Ok(());
    }
    let detail = match status {
        404 => format!("{url}: repository not found"),
        401 | 403 => format!("{url}: authentication failed with status {status}"),
        _ => format!("{url}: dumb-http endpoint refused status {status}"),
    };
    Err(GitError::Offline { detail })
}

/// Borrows owned headers for the HTTP client.
fn borrow(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// GETs `url` into memory, returning status plus body. Error statuses sink
/// nothing (the client reports them); callers map statuses per route.
fn get(url: &str, call: RpcCall<'_>) -> Result<(u16, Vec<u8>), GitError> {
    let owned = policy_headers(url, call.auth, &[("Accept", "*/*")], call.extra);
    let mut body = Vec::new();
    let (status, _) = http::get_to_writer(url, &borrow(&owned), &mut body)?;
    Ok((status, body))
}

/// The dumb ref list URL: `<base>/info/refs` with no service parameter. A
/// base carrying a query string keeps it, so no server-side parameter is
/// lost.
#[must_use]
pub fn dumb_refs_url(base: &str) -> String {
    match base.split_once('?') {
        Some((path, query)) => format!("{path}/info/refs?{query}"),
        None => format!("{base}/info/refs"),
    }
}

/// Parses a dumb `info/refs` body: one `<hex><tab-or-space><name>` line per
/// ref, each annotated tag followed by its `<hex><tab-or-space><name>^{[}...`
/// peel line (the `^{}` suffix attaches to the preceding tag line, mirroring
/// the oracle's `show_text_ref`). Empty lines are skipped; anything else
/// malformed is [`GitError::Corrupt`], including an orphan peel.
pub fn parse_dumb_info_refs(body: &[u8], kind: HashKind) -> Result<Vec<AdvertisedRef>, GitError> {
    let text = std::str::from_utf8(body).map_err(|_| corrupt("dumb info/refs is not UTF-8"))?;
    let mut refs: Vec<AdvertisedRef> = Vec::new();
    let mut by_name: HashMap<Vec<u8>, usize> = HashMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (hex, name) = line
            .split_once(['\t', ' '])
            .ok_or_else(|| corrupt(format!("dumb info/refs line without a separator: {line:?}")))?;
        if name.is_empty() {
            return Err(corrupt(format!(
                "dumb info/refs line without a name: {line:?}"
            )));
        }
        let oid = parse_oid_for(hex, kind).map_err(|err| match err {
            GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
            other => corrupt(other.to_string()),
        })?;
        if let Some(base) = name.strip_suffix("^{}") {
            let Some(&index) = by_name.get(base.as_bytes()) else {
                return Err(corrupt(format!(
                    "dumb info/refs peel without its ref: {line:?}"
                )));
            };
            if refs[index].peeled.is_some() {
                return Err(corrupt(format!("dumb info/refs repeats a peel: {line:?}")));
            }
            refs[index].peeled = Some(oid);
            continue;
        }
        if by_name.contains_key(name.as_bytes()) {
            return Err(corrupt(format!("dumb info/refs repeats a ref: {line:?}")));
        }
        by_name.insert(name.as_bytes().to_vec(), refs.len());
        refs.push(AdvertisedRef {
            name: name.as_bytes().to_vec(),
            oid: Some(oid),
            peeled: None,
            symref_target: None,
        });
    }
    Ok(refs)
}

/// The dumb `HEAD` resource URL: `<base>/HEAD` with no service parameter,
/// keeping a base query string like [`dumb_refs_url`].
#[must_use]
pub fn dumb_head_url(base: &str) -> String {
    match base.split_once('?') {
        Some((path, query)) => format!("{path}/HEAD?{query}"),
        None => format!("{base}/HEAD"),
    }
}

/// Parses a dumb `HEAD` body: one `ref: <name>` first line names the
/// default branch target. Anything else (a detached-HEAD oid, garbage, an
/// empty body) is no symref (`None`), never an error: callers that need no
/// default-branch info skip the row instead of failing the listing.
#[must_use]
pub fn parse_head_symref(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let target = text
        .lines()
        .next()
        .map(str::trim)
        .and_then(|line| line.strip_prefix("ref:"))
        .map(str::trim)?;
    if target.is_empty() || target.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    Some(target.to_owned())
}

/// Reads a dumb endpoint's `HEAD` symref target for listings: GETs the
/// text file the oracle fetches for dumb remotes (`git/remote-curl.c`
/// resolves it into the leading `HEAD` row). A 404 means the server holds
/// no `HEAD` resource (no row, not an error); other error statuses
/// propagate. The fetch lane never calls this: refspec expansion over
/// explicit refs needs no default-branch info.
///
/// # Errors
/// Transport failures from the HTTP client.
pub fn fetch_head_symref(base: &str, call: RpcCall<'_>) -> Result<Option<String>, GitError> {
    let url = dumb_head_url(base);
    let (status, body) = get(&url, call)?;
    if status == 404 {
        return Ok(None);
    }
    check_status(&url, status)?;
    Ok(parse_head_symref(&body))
}

/// Discovers a dumb endpoint's refs: GETs the text file and parses it with
/// the dumb grammar. The returned advertisement carries no capabilities.
/// Dumb servers negotiate nothing, so filter/depth requests warn and fetch
/// complete history. The `HEAD` resource is never requested here, so the
/// advertisement carries no symref/default-branch info; refspec expansion
/// over explicit refs is unaffected (listings read it separately through
/// [`fetch_head_symref`]).
///
/// # Errors
/// Transport failures from the HTTP client and grammar failures from the
/// text parse.
pub fn discover(base: &str, kind: HashKind, call: RpcCall<'_>) -> Result<Advertisement, GitError> {
    let url = dumb_refs_url(base);
    let (status, body) = get(&url, call)?;
    check_status(&url, status)?;
    Ok(Advertisement {
        version: ProtocolVersion::V0,
        capabilities: Capabilities::default(),
        refs: parse_dumb_info_refs(&body, kind)?,
        shallow: Vec::new(),
    })
}

/// Parses an `objects/info/packs` body into pack file names: lines reading
/// `P pack-<hash>.pack` name a pack, everything else (including the
/// oracle's empty single-`\n` body) is ignored.
fn pack_names(body: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    for line in String::from_utf8_lossy(body).lines() {
        let Some(rest) = line.strip_prefix('P').map(str::trim_start) else {
            continue;
        };
        let name = rest.split_whitespace().next().unwrap_or("");
        if name.starts_with("pack-") && name.ends_with(".pack") && !name.contains('/') {
            names.push(name.to_owned());
        }
    }
    names
}

/// Lists the pack files a dumb server holds: GETs `objects/info/packs`. A
/// 404 means no pack list (pack-less repositories answer that way), which
/// is an empty list, not an error; other error statuses propagate.
fn list_packs(base: &str, call: RpcCall<'_>) -> Result<Vec<String>, GitError> {
    let url = format!("{base}/objects/info/packs");
    let (status, body) = get(&url, call)?;
    if status == 404 {
        return Ok(Vec::new());
    }
    check_status(&url, status)?;
    Ok(pack_names(&body))
}

/// Inflates one loose object: the zlib of `<type> <len>\0<body>`. The
/// declared length must match the body exactly; unknown types are corrupt.
fn decode_loose(raw: &[u8]) -> Result<(ObjectKind, Vec<u8>), GitError> {
    let mut decoder = flate2::read::ZlibDecoder::new(raw);
    let mut framed = Vec::new();
    decoder
        .read_to_end(&mut framed)
        .map_err(|err| corrupt(format!("dumb loose object does not inflate: {err}")))?;
    let nul = framed
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| corrupt("dumb loose object has no header terminator"))?;
    let body = framed[nul + 1..].to_vec();
    let header = std::str::from_utf8(&framed[..nul])
        .map_err(|_| corrupt("dumb loose object header is not UTF-8"))?;
    let (type_name, len_text) = header.split_once(' ').ok_or_else(|| {
        corrupt(format!(
            "dumb loose object header without a length: {header:?}"
        ))
    })?;
    let declared: usize = len_text.parse().map_err(|_| {
        corrupt(format!(
            "dumb loose object length is not a number: {header:?}"
        ))
    })?;
    if declared != body.len() {
        return Err(corrupt(format!(
            "dumb loose object declares {declared} bytes but carries {}",
            body.len()
        )));
    }
    let kind = match type_name {
        "commit" => ObjectKind::Commit,
        "tree" => ObjectKind::Tree,
        "blob" => ObjectKind::Blob,
        "tag" => ObjectKind::Tag,
        _ => {
            return Err(corrupt(format!(
                "dumb loose object has no git type: {type_name:?}"
            )));
        }
    };
    Ok((kind, body))
}

/// Fetches one loose object at `objects/xx/rest`. A 404 is a corrupt
/// remote (the refs file advertised an object the server does not hold);
/// other error statuses are transport failures.
fn fetch_loose(
    base: &str,
    oid: Oid,
    max_bytes: u64,
    call: RpcCall<'_>,
) -> Result<(ObjectKind, Vec<u8>), GitError> {
    let hex = oid.to_hex();
    let (fan, rest) = hex.split_at(2);
    let url = format!("{base}/objects/{fan}/{rest}");
    let (status, body) = get(&url, call)?;
    match status {
        _ if http::is_success(status) => {}
        404 => {
            return Err(corrupt(format!(
                "dumb-http remote lacks object {hex} advertised in info/refs"
            )));
        }
        _ => check_status(&url, status)?,
    }
    let len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "dumb-http object length does not fit in 64 bits".to_owned(),
    })?;
    if len > max_bytes {
        return Err(GitError::Limit {
            detail: format!("dumb-http object of {len} bytes exceeds the {max_bytes}-byte cap"),
        });
    }
    decode_loose(&body)
}

/// Downloads one pack file into memory, capped at `max_bytes`. A 404 means
/// the pack vanished between the list and the fetch: `None`, so the caller
/// warns and continues loose.
fn fetch_pack_file(
    base: &str,
    name: &str,
    max_bytes: u64,
    call: RpcCall<'_>,
) -> Result<Option<Vec<u8>>, GitError> {
    let url = format!("{base}/objects/pack/{name}");
    let (status, body) = get(&url, call)?;
    if status == 404 {
        return Ok(None);
    }
    check_status(&url, status)?;
    let len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "dumb-http pack length does not fit in 64 bits".to_owned(),
    })?;
    if len > max_bytes {
        return Err(GitError::Limit {
            detail: format!("dumb-http pack of {len} bytes exceeds the {max_bytes}-byte cap"),
        });
    }
    Ok(Some(body))
}

/// Collects the raw objects inside downloaded pack files: each pack ingests
/// through the shared [`ingest_pack`] staging (identity-verified there),
/// then its payloads are read back out for the single final staging in
/// [`fetch_pack`]. Ingest stagings are dropped unpublished; their spools
/// release, so packs never publish before the refs do.
fn collect_pack_objects(
    base: &str,
    store: &Store,
    kind: HashKind,
    limits: IngestLimits,
    warnings: &mut Vec<String>,
    call: RpcCall<'_>,
) -> Result<Vec<(Oid, ObjectKind, Vec<u8>)>, GitError> {
    let interrupt = call.interrupt;
    let mut triples = Vec::new();
    let names = list_packs(base, call)?;
    if names.len() > MAX_PACK_FILES {
        return Err(GitError::Limit {
            detail: format!(
                "dumb-http lists {} packs, past the {MAX_PACK_FILES}-pack cap",
                names.len()
            ),
        });
    }
    for name in &names {
        interrupt.check("listing dumb-http packs")?;
        let Some(bytes) = fetch_pack_file(base, name, limits.max_pack_bytes, call)? else {
            warnings.push(format!(
                "dumb-http pack {name} vanished; fetching loose instead"
            ));
            continue;
        };
        let staged = ingest_pack(std::io::Cursor::new(bytes), kind, store, limits, interrupt)?;
        for oid in staged.oids() {
            let Some((pack_kind, payload)) = staged.payload(*oid) else {
                continue;
            };
            triples.push((*oid, pack_kind, payload.to_vec()));
        }
    }
    Ok(triples)
}

/// Fetches one pack-equivalent over dumb-http: covers every want's closure
/// (pack files first when listed, loose objects for the rest) and stages
/// the raw objects without publishing anything. The caller verifies and
/// publishes exactly like the smart-http fetch half.
///
/// Dumb servers negotiate nothing: `filter` and `depth` requests warn and
/// fetch complete history.
///
/// # Errors
/// [`GitError::Corrupt`] for advertised-but-missing objects and grammar
/// failures, [`GitError::Limit`] past `limits`, transport failures from
/// the HTTP client.
pub fn fetch_pack(
    base: &str,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    call: RpcCall<'_>,
) -> Result<ReceivedPack, GitError> {
    let interrupt = call.interrupt;
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let kind = store.hash_kind();
    let mut warnings = Vec::new();
    if let Some(filter) = req.filter {
        warnings.push(format!(
            "server is dumb-http; fetched full objects instead of {}",
            filter.spec()
        ));
    }
    if req.depth.is_some() {
        warnings.push("server is dumb-http; fetched complete history".to_owned());
    }
    let mut triples = collect_pack_objects(base, store, kind, limits, &mut warnings, call)?;
    let mut seen: HashSet<Oid> = triples.iter().map(|(oid, _, _)| *oid).collect();
    let max_objects = usize::try_from(limits.max_objects).map_err(|_| GitError::Limit {
        detail: "object count limit does not fit".to_owned(),
    })?;
    let mut queue: Vec<Oid> = req.wants.clone();
    while let Some(oid) = queue.pop() {
        if !seen.insert(oid) {
            continue;
        }
        if seen.len() > max_objects {
            return Err(GitError::Limit {
                detail: format!(
                    "dumb-http closure holds more than {} objects",
                    limits.max_objects
                ),
            });
        }
        if has_object(store, oid)? {
            continue;
        }
        interrupt.check("fetching dumb-http objects")?;
        let (obj_kind, payload) = fetch_loose(base, oid, limits.max_object_bytes, call)?;
        for link in links_of(obj_kind, &payload, kind)? {
            queue.push(link);
        }
        triples.push((oid, obj_kind, payload));
    }
    let staged = stage_local_objects(triples, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged,
        shallow: Vec::new(),
        unshallow: Vec::new(),
        warnings,
        progress: RemoteMessages::default(),
        refs: Vec::new(),
    })
}

/// The links one fetched object pulls into the closure: a commit pulls its
/// tree and parents, a tree its entries (gitlinks already excluded by the
/// parser), a tag its target, a blob nothing.
fn links_of(kind: ObjectKind, payload: &[u8], hash: HashKind) -> Result<Vec<Oid>, GitError> {
    let links = object_links(kind, payload, hash)?;
    let mut out = Vec::new();
    if let Some(tree) = links.tree {
        out.push(tree);
    }
    out.extend(links.parents);
    out.extend(links.entries.into_iter().map(|(oid, _)| oid));
    if let Some((target, _)) = links.tag_target {
        out.push(target);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Interrupt;
    use crate::transport::credentials::{AuthPolicy, TransportAuth};
    use std::io::Write as _;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    #[test]
    fn explicit_auth_sends_one_header_on_a_dumb_get() {
        use std::io::Read as _;

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let body = format!("{FOUR}\trefs/heads/main\n").into_bytes();
        let reply_body = body.clone();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if socket.read(&mut byte).expect("read head") == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply_body.len()
            )
            .expect("reply head");
            socket.write_all(&reply_body).expect("reply body");
            String::from_utf8_lossy(&head).into_owned()
        });
        let base = format!("http://127.0.0.1:{port}/a.git");
        let auth = AuthPolicy::explicit(TransportAuth {
            kind: crate::transport::credentials::TransportAuthKind::Bearer,
            credential: "injected".to_owned(),
            origin: TransportAuth::origin_of(&base).expect("loopback origin"),
        });
        let adv = discover(
            &base,
            HashKind::Sha1,
            RpcCall {
                extra: &[],
                auth: &auth,
                interrupt: &Interrupt::none(),
            },
        )
        .expect("dumb discover");
        assert_eq!(adv.refs.len(), 1);
        let head = server.join().expect("server");
        let auth_lines: Vec<&str> = head
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(auth_lines, ["authorization: Bearer injected"], "{head:?}");
    }

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn refs_url_has_no_service_parameter() {
        assert_eq!(
            dumb_refs_url("https://host.x/a.git"),
            "https://host.x/a.git/info/refs"
        );
        assert_eq!(
            dumb_refs_url("https://host.x/a?token=t"),
            "https://host.x/a/info/refs?token=t"
        );
    }

    #[test]
    fn head_url_and_symref_parse() {
        assert_eq!(
            dumb_head_url("https://host.x/a.git"),
            "https://host.x/a.git/HEAD"
        );
        assert_eq!(
            dumb_head_url("https://host.x/a?token=t"),
            "https://host.x/a/HEAD?token=t"
        );
        assert_eq!(
            parse_head_symref(b"ref: refs/heads/main\n"),
            Some("refs/heads/main".to_owned())
        );
        assert_eq!(
            parse_head_symref(b"ref: refs/heads/main"),
            Some("refs/heads/main".to_owned())
        );
        // Detached HEAD, garbage, and empty bodies carry no symref.
        assert_eq!(
            parse_head_symref(b"705446959e9d34f504c3c368dbf61264e603fa2d\n"),
            None
        );
        assert_eq!(parse_head_symref(b"not a ref\n"), None);
        assert_eq!(parse_head_symref(b""), None);
        assert_eq!(parse_head_symref(b"ref: \n"), None);
    }

    #[test]
    fn parses_text_refs_with_peels() {
        let body = format!("{FOUR}\trefs/heads/main\n{FOUR}\trefs/tags/v1\n").into_bytes();
        let refs = parse_dumb_info_refs(&body, HashKind::Sha1).expect("parse");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].oid, Some(oid(FOUR)));
        assert_eq!(refs[0].peeled, None);
    }

    #[test]
    fn parses_peel_lines_onto_their_tag() {
        let tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peeled = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let body = format!("{tag}\trefs/tags/v2\n{peeled}\trefs/tags/v2^{{}}\n").into_bytes();
        let refs = parse_dumb_info_refs(&body, HashKind::Sha1).expect("parse");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].oid, Some(oid(tag)));
        assert_eq!(refs[0].peeled, Some(oid(peeled)));
    }

    #[test]
    fn rejects_orphan_peels_dupes_and_bad_hex() {
        let orphan = format!("{FOUR}\trefs/tags/v2^{{}}\n").into_bytes();
        assert!(parse_dumb_info_refs(&orphan, HashKind::Sha1).is_err());
        let dupe = format!("{FOUR}\trefs/heads/main\n{FOUR}\trefs/heads/main\n").into_bytes();
        assert!(parse_dumb_info_refs(&dupe, HashKind::Sha1).is_err());
        assert!(parse_dumb_info_refs(b"nothex\trefs/heads/main\n", HashKind::Sha1).is_err());
        assert!(parse_dumb_info_refs(b"no-separator-here\n", HashKind::Sha1).is_err());
    }

    #[test]
    fn marks_only_the_dumb_gap() {
        assert!(is_dumb_gap(&super::super::net::dumb_http_gap("http://h/x")));
        assert!(!is_dumb_gap(&GitError::Invalid {
            detail: "other".to_owned()
        }));
    }

    #[test]
    fn pack_list_parses_only_pack_lines() {
        let body =
            b"P pack-abc123.pack\nP pack-def456.pack\n\n# comment\nP not-a-pack.idx\n".to_vec();
        let names = pack_names(&body);
        assert_eq!(names, vec!["pack-abc123.pack", "pack-def456.pack"]);
        assert!(pack_names(b"\n").is_empty());
    }

    #[test]
    fn loose_round_trips_through_zlib_framing() {
        let payload = b"hello dumb".to_vec();
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(format!("blob {}\0", payload.len()).as_bytes())
            .expect("header");
        encoder.write_all(&payload).expect("body");
        let framed = encoder.finish().expect("finish");
        let (kind, bytes) = decode_loose(&framed).expect("decode");
        assert_eq!(kind, ObjectKind::Blob);
        assert_eq!(bytes, payload);
        assert!(decode_loose(b"not zlib").is_err());
    }

    /// Serves a dumb remote on loopback from `server`: `info/refs` text,
    /// an empty pack list, and loose objects framed the way
    /// `git/http-backend.c` frames them. `total` bounds the served
    /// requests so the test never hangs on a miscount.
    fn fake_dumb_server(
        server: Store,
        refs_body: Vec<u8>,
        total: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
        let port = listener.local_addr().expect("addr").port();
        let base = format!("http://127.0.0.1:{port}/a.git");
        let handle = std::thread::spawn(move || {
            for _ in 0..total {
                let (socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("timeout");
                let path = read_get_path(&socket);
                let (status, content_type, body) = route(&server, &refs_body, &path);
                write_response(socket, status, content_type, &body);
            }
        });
        (base, handle)
    }

    /// Reads one GET request head and returns its path.
    fn read_get_path(socket: &std::net::TcpStream) -> String {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(socket.try_clone().expect("split"));
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).expect("request line");
            if line.is_empty() {
                panic!("client hung up mid-request");
            }
            head.extend_from_slice(&line);
            if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let request_line = text.lines().next().expect("request line");
        request_line
            .split_whitespace()
            .nth(1)
            .expect("path")
            .to_owned()
    }

    /// Routes one dumb GET: refs text, an empty pack list, or a framed
    /// loose object read back verified from the server store.
    fn route(server: &Store, refs_body: &[u8], path: &str) -> (u16, &'static str, Vec<u8>) {
        if path == "/a.git/info/refs" {
            return (200, "text/plain", refs_body.to_vec());
        }
        if path == "/a.git/objects/info/packs" {
            return (200, "text/plain", b"\n".to_vec());
        }
        if let Some(rest) = path.strip_prefix("/a.git/objects/") {
            let hex = rest.replace('/', "");
            let Ok(want) = Oid::from_hex(&hex) else {
                return (400, "text/plain", b"bad oid".to_vec());
            };
            let Ok((kind, bytes)) = super::super::read_object(server, want, u64::MAX) else {
                return (404, "text/plain", b"not found".to_vec());
            };
            if kind == ObjectKind::Conflict {
                return (404, "text/plain", b"not found".to_vec());
            }
            let type_name = match kind {
                ObjectKind::Commit => "commit",
                ObjectKind::Tree => "tree",
                ObjectKind::Blob => "blob",
                ObjectKind::Tag => "tag",
                ObjectKind::Conflict => "blob",
            };
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(format!("{type_name} {}\0", bytes.len()).as_bytes())
                .expect("header");
            encoder.write_all(&bytes).expect("body");
            return (
                200,
                "application/octet-stream",
                encoder.finish().expect("finish"),
            );
        }
        (404, "text/plain", b"no such route".to_vec())
    }

    /// Writes one HTTP/1.1 response with `Content-Length`.
    fn write_response(socket: std::net::TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Error",
        };
        let mut socket = socket;
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).expect("head");
        socket.write_all(body).expect("body");
    }

    /// Walks the server closure from `tips` to count the loose requests the
    /// client must make (every reachable object exactly once).
    fn closure_size(server: &Store, tips: &[Oid]) -> usize {
        let mut seen: HashSet<Oid> = HashSet::new();
        let mut queue: Vec<Oid> = tips.to_vec();
        while let Some(oid) = queue.pop() {
            if !seen.insert(oid) {
                continue;
            }
            let Ok((kind, bytes)) = super::super::read_object(server, oid, u64::MAX) else {
                continue;
            };
            let Ok(links) = object_links(kind, &bytes, server.hash_kind()) else {
                continue;
            };
            if let Some(tree) = links.tree {
                queue.push(tree);
            }
            queue.extend(links.parents);
            queue.extend(links.entries.into_iter().map(|(oid, _)| oid));
            if let Some((target, _)) = links.tag_target {
                queue.push(target);
            }
        }
        seen.len()
    }

    #[test]
    fn fetch_covers_the_closure_from_loose_objects() {
        use super::super::fetch::{publish_fetch, verify_closure};
        use super::super::session::test_support::{store_with_pack, test_store};
        use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTransaction, RefUpdate};
        use ruk_core::refs::prepare_checked_transaction;

        let kind = HashKind::Sha1;
        let server = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let tip = oid(FOUR);
        let update = RefUpdate {
            expected: RefExpect::Absent,
            change: RefChange::Set(ruk_core::refdata::RefTarget::Direct(tip)),
            name: RefName::new(b"refs/heads/main".to_vec()).expect("ref name"),
        };
        let prepared = prepare_checked_transaction(
            &server,
            &RefTransaction::new(kind, vec![update]).expect("tx"),
        )
        .expect("prepare");
        server
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        // One discovery GET, one pack-list GET, then one GET per closure
        // object: the server answers from its own store, so any miscount
        // hangs the test instead of passing silently.
        let total = 2 + closure_size(&server, &[tip]);
        let refs_body = format!("{FOUR}\trefs/heads/main\n").into_bytes();
        let (base, handle) = fake_dumb_server(server, refs_body, total);

        let adv = discover(
            &base,
            kind,
            RpcCall {
                extra: &[],
                auth: &AuthPolicy::explicit(TransportAuth::none()),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("discover");
        assert_eq!(adv.refs.len(), 1);
        assert_eq!(adv.refs[0].oid, Some(tip));

        let dest = test_store(kind);
        let req = FetchWireRequest {
            wants: vec![tip],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = fetch_pack(
            &base,
            &dest,
            &req,
            IngestLimits::default(),
            RpcCall {
                extra: &[],
                auth: &AuthPolicy::explicit(TransportAuth::none()),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("fetch");
        assert!(received.warnings.is_empty());
        verify_closure(
            &dest,
            &received.staged,
            &[tip],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure");
        publish_fetch(&dest, received.staged, &[]).expect("publish");
        assert!(dest.read(tip).is_ok());
        handle.join().expect("server");
    }

    #[test]
    fn fetch_warns_on_filter_and_depth() {
        use super::super::fetch::{Filter, publish_fetch, verify_closure};
        use super::super::session::test_support::{store_with_pack, test_store};
        use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTransaction, RefUpdate};
        use ruk_core::refs::prepare_checked_transaction;

        let kind = HashKind::Sha1;
        let server = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let tip = oid(FOUR);
        let update = RefUpdate {
            expected: RefExpect::Absent,
            change: RefChange::Set(ruk_core::refdata::RefTarget::Direct(tip)),
            name: RefName::new(b"refs/heads/main".to_vec()).expect("ref name"),
        };
        let prepared = prepare_checked_transaction(
            &server,
            &RefTransaction::new(kind, vec![update]).expect("tx"),
        )
        .expect("prepare");
        server
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        // Dumb servers negotiate nothing: the filter and depth requests
        // warn and the fetch covers complete history anyway. Publication is
        // idempotent on retry: staging the same closure twice publishes the
        // same objects, so a repeated fetch is a no-op, not a duplicate.
        let total = 2 + closure_size(&server, &[tip]);
        let refs_body = format!("{FOUR}\trefs/heads/main\n").into_bytes();
        let (base, handle) = fake_dumb_server(server, refs_body, total);
        let dest = test_store(kind);
        let req = FetchWireRequest {
            wants: vec![tip],
            haves: Vec::new(),
            filter: Some(Filter::BlobNone),
            depth: Some(1),
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = fetch_pack(
            &base,
            &dest,
            &req,
            IngestLimits::default(),
            RpcCall {
                extra: &[],
                auth: &AuthPolicy::explicit(TransportAuth::none()),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("fetch");
        assert_eq!(received.warnings.len(), 2);
        verify_closure(
            &dest,
            &received.staged,
            &[tip],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure");
        publish_fetch(&dest, received.staged, &[]).expect("publish");
        assert!(dest.read(tip).is_ok());
        handle.join().expect("server");
    }
}
