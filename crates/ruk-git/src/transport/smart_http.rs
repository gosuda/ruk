//! git smart-http client: stateless upload-pack and receive-pack over
//! HTTP(S).
//!
//! One `GET <base>/info/refs?service=<svc>` returns the pkt-line
//! advertisement (parsed by the same [`crate::transport::refadv`] grammar
//! as the stateful transports), then one `POST <base>/<svc>` carries the
//! whole request — wants, haves and `done`, or ref commands plus the pack
//! — and the response carries the same bytes the stateful server would
//! have written (NAK/ACK lines plus a side-band pack, or a report-status
//! document). Pack ingest, closure verification and push-plan states are
//! the shared [`crate::transport::fetch`] and [`crate::transport::push`]
//! halves; only the framing round-trips are HTTP.
//!
//! Negotiation mirrors the stateful v0 clients byte for byte (capability
//! lists, warning strings, report coverage), except the fetch ACK loop:
//! the single POST already contains `done`, so per-have verdicts (which
//! always carry a `continue`/`common`/`ready` suffix) are consumed and
//! only the bare post-`done` verdict ends the preamble. Stateful clients
//! break on the first verdict to send `done`; there is no second round
//! here.
//!
//! Auth is Bearer from `GIT_AUTH_TOKEN`, else Basic from `GIT_AUTH_USER`
//! plus `GIT_AUTH_PASSWORD` (see [`crate::transport::http::git_auth_header`]).
//! Git credential helpers and `http.<url>.extraHeader` stay named gaps:
//! no config parser for the latter exists, and the former is an
//! interactive-process contract this client does not run.
//!
//! Named gaps beside this module: dumb-http (a server answering
//! `info/refs` without the smart advertisement document), protocol v2
//! over HTTP (needs the `Git-Protocol` header plus command RPCs),
//! `git-upload-archive` over HTTP (no archive-reading verb consumes it),
//! and POST redirects (smart RPC endpoints never emit them; a 3xx names
//! its `Location` in the error).
//!
//! Oracle anchors: `git/remote-curl.c` (`discover_refs`, `check_smart_http`,
//! `rpc_service`, `fetch_git`), `git/fetch-pack.c` (`--stateless-rpc`
//! request shape, `send_request`), `git/send-pack.c` (stateless command
//! plus pack body), `git/upload-pack.c` (`--stateless-rpc` single-round
//! contract: wants to flush, haves to `done`), `git/builtin/receive-pack.c`
//! (commands to flush, pack to end of body), `git/Documentation/gitprotocol-http.adoc`.

use std::collections::HashMap;
use std::io::Cursor;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;

use super::Interrupt;
use super::fetch::{self, FetchWireRequest, ReceivedPack};
use super::http;
use super::net;
use super::pack::IngestLimits;
use super::pktline::{self, PktReader};
use super::push::{self, PushPlanRecord, PushWireRequest, RefOutcome};
use super::refadv::{self, Advertisement, Initial};
use crate::{GitError, parse_oid_for};

/// Which smart service one RPC round trip speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartService {
    /// `git-upload-pack`: the server sends objects.
    UploadPack,
    /// `git-receive-pack`: the server accepts objects.
    ReceivePack,
}

impl SmartService {
    /// The service name in URLs and `# service=` preambles.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    /// The `Content-Type` a discovery response must carry
    /// (`git/remote-curl.c` `check_smart_http` matches it exactly, and so
    /// does this client: anything else is dumb-http).
    #[must_use]
    pub fn advertisement_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }

    /// The `Content-Type` one RPC request carries.
    #[must_use]
    pub fn request_type(self) -> String {
        format!("application/x-{}-request", self.name())
    }

    /// The `Content-Type` one RPC response must carry.
    #[must_use]
    pub fn result_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

/// Normalizes an endpoint URL to the RPC base: the URL as spelled minus
/// trailing slashes, so `info/refs` and service paths join with one `/`.
///
/// # Errors
/// [`GitError::Invalid`] for a non-HTTP URL (checked through
/// [`http::url_authority`], which owns URL validation).
pub fn normalize_base(url: &str) -> Result<String, GitError> {
    http::url_authority(url)?;
    let base = url.trim_end_matches('/');
    if base.is_empty() {
        return Err(GitError::Invalid {
            detail: format!("http remote {url:?} has no usable base"),
        });
    }
    Ok(base.to_owned())
}

/// The discovery URL: `<base>/info/refs?service=<svc>`. A base that
/// already carries a query string keeps it after the service parameter,
/// so no server-side parameter is lost.
#[must_use]
pub fn refs_url(base: &str, service: SmartService) -> String {
    let (path, query) = match base.split_once('?') {
        Some((path, query)) => (path, format!("&{query}")),
        None => (base, String::new()),
    };
    format!("{path}/info/refs?service={}{query}", service.name())
}

/// The RPC URL: `<base>/<svc>`.
#[must_use]
pub fn rpc_url(base: &str, service: SmartService) -> String {
    format!("{base}/{}", service.name())
}

/// Builds owned request headers from `extra` plus the environment auth
/// header, when the environment carries one. Pure for tests; live callers
/// pass the process environment.
#[must_use]
pub fn request_headers(
    vars: &HashMap<String, String>,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = extra
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    if let Some((name, value)) = http::git_auth_header(vars) {
        out.push((name, value));
    }
    out
}

/// Collects the process environment for [`request_headers`].
fn live_headers(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    request_headers(&std::env::vars().collect(), extra)
}

/// Borrows owned headers for the HTTP client.
fn borrow(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// Maps a non-2xx RPC status the way the LFS verbs do: the endpoint
/// refused, so the remote is offline. A 404 names the missing repository
/// and a 401/403 names the auth failure; anything else echoes the status.
fn check_status(url: &str, status: u16) -> Result<(), GitError> {
    if http::is_success(status) {
        return Ok(());
    }
    let detail = match status {
        404 => format!("{url}: repository not found"),
        401 | 403 => format!("{url}: authentication failed with status {status}"),
        _ => format!("{url}: smart-http endpoint refused status {status}"),
    };
    Err(GitError::Offline { detail })
}

/// Discovers one smart-http endpoint's refs: GETs the advertisement and
/// parses it with the shared v0 grammar. A response without the smart
/// content type is dumb-http, the remaining HTTP gap.
///
/// # Errors
/// Transport failures from the HTTP client, [`GitError::Unsupported`] for
/// dumb-http servers and protocol v2 over HTTP, grammar failures from the
/// advertisement parse.
pub fn discover(
    base: &str,
    service: SmartService,
    kind: HashKind,
) -> Result<Advertisement, GitError> {
    let url = refs_url(base, service);
    let owned = live_headers(&[("Accept", "*/*")]);
    let mut body = Vec::new();
    let (status, reply) = http::get_to_writer(&url, &borrow(&owned), &mut body)?;
    check_status(&url, status)?;
    if http::header(&reply, "content-type") != Some(service.advertisement_type().as_str()) {
        return Err(net::dumb_http_gap(&url));
    }
    let mut pkt = PktReader::new(Cursor::new(body), Interrupt::none());
    match refadv::read_initial(&mut pkt, kind)? {
        Initial::Refs(adv) => Ok(adv),
        Initial::V2(_) => Err(GitError::Unsupported {
            command: "protocol v2 over smart-http (Git-Protocol header plus command RPCs are out of scope)"
                .to_owned(),
        }),
    }
}

/// Exact equality with `NAK`, mirroring the stateful fetch client.
fn is_nak(line: &[u8]) -> bool {
    line.len() == 3 && line.starts_with(b"NAK")
}

/// Reads a server OID the way the stateful fetch client does.
fn parse_server_oid(field: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field).map_err(|_| GitError::Corrupt {
        detail: "server sent a non-ASCII object id".to_owned(),
    })?;
    parse_oid_for(text, kind).map_err(|err| match err {
        GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
        other => GitError::Corrupt {
            detail: other.to_string(),
        },
    })
}

/// Fetches one pack over smart-http: POSTs the whole v0 request (wants,
/// haves, `done`) and ingests the streamed response, returning the
/// staging without publishing anything. The caller verifies and publishes
/// exactly like the stateful fetch half.
///
/// Capability lists and fallback warnings match the stateful client byte
/// for byte; `adv` is the [`discover`] document for this base.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see
/// [`super::pack::ingest_pack`] for pack errors.
pub fn fetch_pack(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<ReceivedPack, GitError> {
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let kind = store.hash_kind();
    let caps = &adv.capabilities;
    let mut warnings = Vec::new();
    let filter = match req.filter {
        Some(filter) if caps.has("filter") => Some(filter),
        Some(filter) => {
            warnings.push(format!(
                "server lacks filter; fetched full objects instead of {}",
                filter.spec()
            ));
            None
        }
        None => None,
    };
    let depth = match req.depth {
        Some(depth) if caps.has("shallow") => Some(depth),
        Some(_) => {
            warnings.push("server lacks shallow; fetched complete history".to_owned());
            None
        }
        None => None,
    };
    let mut caps_list = vec!["multi_ack_detailed", "thin-pack", "ofs-delta"];
    let sideband = if caps.has("side-band-64k") {
        caps_list.push("side-band-64k");
        Some(pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        caps_list.push("side-band");
        Some(pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    };
    if filter.is_some() {
        caps_list.push("filter");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    let mut out = Vec::new();
    for (index, want) in req.wants.iter().enumerate() {
        let mut line = format!("want {want}");
        if index == 0 {
            line.push(' ');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    for oid in &req.shallow {
        pktline::encode_data(&mut out, format!("shallow {oid}\n").as_bytes())?;
    }
    if let Some(depth) = depth {
        pktline::encode_data(&mut out, format!("deepen {depth}\n").as_bytes())?;
    }
    if let Some(filter) = filter {
        pktline::encode_data(&mut out, format!("filter {}\n", filter.spec()).as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    for oid in &req.haves {
        pktline::encode_data(&mut out, format!("have {oid}\n").as_bytes())?;
    }
    pktline::encode_data(&mut out, b"done\n")?;
    // Closes the single stateless round the way `send_request` does in
    // `git/fetch-pack.c`: the server breaks on `done` and leaves this
    // flush unread.
    pktline::encode_flush(&mut out);
    let url = rpc_url(base, SmartService::UploadPack);
    let request_type = SmartService::UploadPack.request_type();
    let result_type = SmartService::UploadPack.result_type();
    let owned = live_headers(&[
        ("Content-Type", request_type.as_str()),
        ("Accept", result_type.as_str()),
    ]);
    let (reader, status, reply) = http::post_open(&url, &borrow(&owned), &out)?;
    check_status(&url, status)?;
    if http::header(&reply, "content-type") != Some(SmartService::UploadPack.result_type().as_str())
    {
        return Err(GitError::Corrupt {
            detail: format!("{url}: upload-pack RPC answered a non-pack content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut shallow = Vec::new();
    let mut unshallow = Vec::new();
    let mut ack_bytes = 0usize;
    loop {
        interrupt.check("negotiating the fetch")?;
        let line = pkt.read_line("an acknowledgement")?.to_vec();
        ack_bytes += line.len();
        if ack_bytes > ruk_core::MAX_CONTROL_FRAME_BYTES {
            return Err(GitError::Limit {
                detail: "fetch negotiation exceeds the control bound".to_owned(),
            });
        }
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            shallow.push(parse_server_oid(rest, kind)?);
        } else if let Some(rest) = line.strip_prefix(b"unshallow ") {
            unshallow.push(parse_server_oid(rest, kind)?);
        } else if is_nak(&line) {
            break;
        } else if line.starts_with(b"ACK ") {
            // Single-round stateless: per-have verdicts always carry a
            // suffix, so only the bare post-`done` verdict ends the
            // preamble. Stateful clients break on the first verdict to
            // send `done`; ours is already sent.
            let suffixed = line.ends_with(b"continue")
                || line.ends_with(b"common")
                || line.ends_with(b"ready");
            if !suffixed {
                break;
            }
        } else {
            return Err(GitError::Corrupt {
                detail: format!("unexpected acknowledgement {}", line.escape_ascii()),
            });
        }
    }
    let (staged, progress) =
        fetch::read_pack_section(&mut pkt, sideband, kind, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged,
        shallow,
        unshallow,
        warnings,
        progress,
        refs: Vec::new(),
    })
}

/// Pushes over smart-http: POSTs the ref commands plus the pack in one
/// body and parses the streamed report, walking the same plan states as
/// the stateful push half. `adv` is the [`discover`] document for the
/// receive-pack service at this base.
///
/// # Errors
/// Capability, grammar, transport and store failures. Any error from
/// [`PushPlanRecord::begin_send`] onward persists `Uncertain` best-effort
/// before returning, exactly like [`super::push::push_over`].
pub fn push_pack(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    if req.updates.is_empty() {
        return Err(GitError::Invalid {
            detail: "push needs at least one update".to_owned(),
        });
    }
    if plan.updates != req.updates || plan.atomic != req.atomic {
        return Err(GitError::Invalid {
            detail: "push plan does not match the push request".to_owned(),
        });
    }
    for update in &req.updates {
        if update.name.is_empty() || update.name.iter().any(|b| *b == 0 || *b == b'\n') {
            return Err(GitError::Invalid {
                detail: "push update carries a malformed ref name".to_owned(),
            });
        }
    }
    let kind = store.hash_kind();
    push::persist(store, plan, kind, None)?;
    let outcome = push_pack_inner(base, adv, store, plan, req, interrupt);
    match outcome {
        Ok(outcomes) => Ok(outcomes),
        Err(err) => {
            plan.mark_uncertain();
            push::persist_best_effort(store, plan, kind);
            Err(err)
        }
    }
}

fn push_pack_inner(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    let kind = store.hash_kind();
    let caps = &adv.capabilities;
    let report_v2 = caps.has("report-status-v2");
    if !report_v2 && !caps.has("report-status") {
        plan.begin_send()?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Err(GitError::PushUncertain {
            detail: "server reports no push status; outcomes cannot be confirmed".to_owned(),
        });
    }
    let zero = kind.zero_oid();
    if req.updates.iter().any(|u| u.new == zero) && !caps.has("delete-refs") {
        return Err(GitError::Invalid {
            detail: "server does not advertise delete-refs".to_owned(),
        });
    }
    if req.atomic && !caps.has("atomic") {
        return Err(GitError::Invalid {
            detail: "server does not advertise atomic".to_owned(),
        });
    }
    let advertised: HashMap<&[u8], Oid> = adv
        .refs
        .iter()
        .filter_map(|r| r.oid.map(|oid| (r.name.as_slice(), oid)))
        .collect();
    let mut live: Vec<&push::PushUpdate> = Vec::with_capacity(req.updates.len());
    let mut outcomes: Vec<RefOutcome> = Vec::with_capacity(req.updates.len());
    for update in &req.updates {
        match advertised.get(update.name.as_slice()) {
            Some(current) if *current != update.old => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: format!(
                        "remote ref moved: advertised {current}, expected {}",
                        update.old
                    ),
                },
            }),
            None if update.old != zero => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: "remote ref is absent".to_owned(),
                },
            }),
            _ => live.push(update),
        }
    }
    if !outcomes.is_empty() && req.atomic {
        for update in live {
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: "atomic push refused locally: a sibling ref moved".to_owned(),
                },
            });
        }
        plan.refuse_locally(outcomes.clone())?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    if live.is_empty() {
        plan.refuse_locally(outcomes.clone())?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    let sideband = if caps.has("side-band-64k") {
        Some(pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        Some(pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    };
    let mut caps_list = vec![if report_v2 {
        "report-status-v2"
    } else {
        "report-status"
    }];
    if sideband == Some(pktline::LARGE_PACKET_MAX) {
        caps_list.push("side-band-64k");
    } else if sideband.is_some() {
        caps_list.push("side-band");
    }
    if caps.has("ofs-delta") {
        caps_list.push("ofs-delta");
    }
    if caps.has("atomic") && req.atomic {
        caps_list.push("atomic");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    let mut out = Vec::new();
    for (index, update) in live.iter().enumerate() {
        let mut line = format!(
            "{} {} {}",
            update.old.to_hex(),
            update.new.to_hex(),
            String::from_utf8_lossy(&update.name)
        );
        if index == 0 {
            line.push('\0');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    plan.begin_send()?;
    push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
    let mut entries = push::push_closure(store, kind, &live, interrupt)?;
    push::pair_thin_bases(store, kind, &live, &mut entries, interrupt)?;
    if !entries.is_empty() {
        let pack_entries: Vec<super::pack::PackEntry<'_>> =
            entries.iter().map(|entry| entry.as_entry()).collect();
        interrupt.check("sending the pack")?;
        if entries.iter().any(|entry| entry.base.is_some()) {
            super::pack::write_thin_pack(&mut out, kind, &pack_entries, interrupt)?;
        } else {
            super::pack::write_pack(&mut out, kind, &pack_entries, interrupt)?;
        }
    }
    // Closes the stateless round after the pack (`git/send-pack.c`
    // appends it the same way); the server reads the pack to the end of
    // the POST body and this flush stays unread.
    pktline::encode_flush(&mut out);
    let url = rpc_url(base, SmartService::ReceivePack);
    let request_type = SmartService::ReceivePack.request_type();
    let result_type = SmartService::ReceivePack.result_type();
    let owned = live_headers(&[
        ("Content-Type", request_type.as_str()),
        ("Accept", result_type.as_str()),
    ]);
    let (reader, status, reply) = http::post_open(&url, &borrow(&owned), &out)?;
    check_status(&url, status)?;
    if http::header(&reply, "content-type")
        != Some(SmartService::ReceivePack.result_type().as_str())
    {
        plan.mark_uncertain();
        push::persist_best_effort(store, plan, kind);
        return Err(GitError::Corrupt {
            detail: format!("{url}: receive-pack RPC answered a non-report content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let server = push::read_report(&mut pkt, sideband)?;
    push::check_report_covers_live(&live, &server)?;
    let mut report = server;
    report.extend(outcomes);
    plan.finalize(report.clone())?;
    push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn base_and_url_shapes() {
        assert_eq!(
            normalize_base("https://host.x/a.git/").expect("base"),
            "https://host.x/a.git"
        );
        assert_eq!(
            normalize_base("http://127.0.0.1:8080/a").expect("base"),
            "http://127.0.0.1:8080/a"
        );
        assert!(normalize_base("ftp://host.x/a").is_err());
        assert!(normalize_base("not a url").is_err());
        assert_eq!(
            refs_url("https://host.x/a.git", SmartService::UploadPack),
            "https://host.x/a.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            refs_url("https://host.x/a?token=t", SmartService::ReceivePack),
            "https://host.x/a/info/refs?service=git-receive-pack&token=t"
        );
        assert_eq!(
            rpc_url("https://host.x/a.git", SmartService::UploadPack),
            "https://host.x/a.git/git-upload-pack"
        );
        assert_eq!(
            SmartService::UploadPack.advertisement_type(),
            "application/x-git-upload-pack-advertisement"
        );
        assert_eq!(
            SmartService::ReceivePack.request_type(),
            "application/x-git-receive-pack-request"
        );
        assert_eq!(
            SmartService::UploadPack.result_type(),
            "application/x-git-upload-pack-result"
        );
    }

    #[test]
    fn auth_header_surface() {
        let vars = HashMap::from([("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned())]);
        let headers = request_headers(&vars, &[("Accept", "*/*")]);
        assert!(headers.contains(&("Accept".to_owned(), "*/*".to_owned())));
        assert!(headers.contains(&("authorization".to_owned(), "Bearer tok".to_owned())));
        // A bearer token wins over a user/password pair.
        let vars = HashMap::from([
            ("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned()),
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        let headers = request_headers(&vars, &[]);
        assert_eq!(headers.len(), 1);
        let vars = HashMap::from([
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        let headers = request_headers(&vars, &[]);
        assert_eq!(
            headers,
            vec![("authorization".to_owned(), "Basic dXNlcjpwYXNz".to_owned())]
        );
        assert!(request_headers(&HashMap::new(), &[]).is_empty());
    }

    /// One recorded request: head text plus raw body bytes.
    struct Recorded {
        head: String,
        body: Vec<u8>,
    }

    /// Serves canned replies on loopback, recording every request head
    /// plus body. Each reply names its framing: `chunked` emits
    /// `Transfer-Encoding: chunked` with the body in two chunks (so the
    /// client proves it never parses chunk-size text as pkt-line),
    /// otherwise `Content-Length`. Returns the base URL plus the join
    /// handle.
    fn fake_smart_server(
        replies: Vec<(u16, Vec<(String, String)>, Vec<u8>, bool)>,
    ) -> (String, std::thread::JoinHandle<Vec<Recorded>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body, chunked) in replies {
                let (socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("timeout");
                let (head, request_body) = read_request(&socket);
                requests.push(Recorded {
                    head,
                    body: request_body,
                });
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Error",
                };
                let mut reply = format!("HTTP/1.1 {status} {reason}\r\n");
                if chunked {
                    reply.push_str("Transfer-Encoding: chunked\r\n");
                } else {
                    reply.push_str(&format!("Content-Length: {}\r\n", body.len()));
                }
                for (name, value) in &headers {
                    reply.push_str(&format!("{name}: {value}\r\n"));
                }
                reply.push_str("Connection: close\r\n\r\n");
                let mut socket = socket;
                socket.write_all(reply.as_bytes()).expect("reply head");
                if chunked {
                    let (first, second) = body.split_at(body.len() / 2);
                    for chunk in [first, second] {
                        socket
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .expect("chunk size");
                        socket.write_all(chunk).expect("chunk");
                        socket.write_all(b"\r\n").expect("chunk end");
                    }
                    socket.write_all(b"0\r\n\r\n").expect("last chunk");
                } else {
                    socket.write_all(&body).expect("reply body");
                }
            }
            requests
        });
        (format!("http://127.0.0.1:{port}/a.git"), server)
    }

    /// Reads one request head plus its declared body from `socket`.
    fn read_request(socket: &std::net::TcpStream) -> (String, Vec<u8>) {
        let mut reader = std::io::BufReader::new(socket.try_clone().expect("split"));
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            use std::io::BufRead as _;
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
        let length = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().to_ascii_lowercase() == "content-length")
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        if length > 0 {
            reader.read_exact(&mut body).expect("request body");
        }
        (text, body)
    }

    /// One pkt-line advertisement document for `tip` under `HEAD` plus one
    /// branch, with the given capability words.
    fn advertisement_bytes(tip: &str, caps: &str) -> Vec<u8> {
        let mut out = Vec::new();
        pktline::encode_data(&mut out, b"# service=git-upload-pack\n").expect("frame");
        pktline::encode_flush(&mut out);
        let first = format!("{tip} HEAD\0{caps}\n");
        pktline::encode_data(&mut out, first.as_bytes()).expect("frame");
        let second = format!("{tip} refs/heads/main\n");
        pktline::encode_data(&mut out, second.as_bytes()).expect("frame");
        pktline::encode_flush(&mut out);
        out
    }

    /// Wraps `payload` in one side-band band-1 frame.
    fn sideband_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        let len = payload.len() + 5;
        frame.extend_from_slice(format!("{len:04x}").as_bytes());
        frame.push(1);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn discover_parses_the_advertisement() {
        let body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta symref=HEAD:refs/heads/main object-format=sha1",
        );
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            body,
            false,
        )]);
        let adv = discover(&base, SmartService::UploadPack, HashKind::Sha1).expect("discover");
        assert!(adv.capabilities.has("side-band-64k"));
        assert_eq!(adv.refs.len(), 2);
        assert_eq!(adv.refs[0].oid, Some(oid(FOUR)));
        assert_eq!(
            adv.refs[0].symref_target.as_deref(),
            Some(b"refs/heads/main".as_slice())
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .head
                .starts_with("GET /a.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            requests[0].head
        );
    }

    #[test]
    fn discover_names_dumb_http_as_the_gap() {
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![("Content-Type".to_owned(), "text/plain".to_owned())],
            format!("{FOUR}\trefs/heads/main\n").into_bytes(),
            false,
        )]);
        let err = discover(&base, SmartService::UploadPack, HashKind::Sha1).expect_err("dumb");
        assert!(
            matches!(err, GitError::Unsupported { .. }),
            "unexpected {err:?}"
        );
        assert!(err.to_string().contains("dumb-http"), "{err}");
        server.join().expect("server");
    }

    #[test]
    fn fetch_ingests_a_canned_pack() {
        use super::super::fetch::verify_closure;
        use super::super::session::test_support::test_store;

        let kind = HashKind::Sha1;
        let pack = include_bytes!("fixtures/basic.pack").to_vec();
        let adv_body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta object-format=sha1",
        );
        let mut result = b"0008NAK\n".to_vec();
        result.extend_from_slice(&sideband_frame(&pack));
        result.extend_from_slice(b"0000");
        // The pack reply is chunked: pkt-line must decode framing first
        // and never parse chunk-size text.
        let (base, server) = fake_smart_server(vec![
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.advertisement_type(),
                )],
                adv_body,
                false,
            ),
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.result_type(),
                )],
                result,
                true,
            ),
        ]);
        let adv = discover(&base, SmartService::UploadPack, kind).expect("discover");
        let dest = test_store(kind);
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = fetch_pack(
            &base,
            &adv,
            &dest,
            &req,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("fetch");
        assert!(received.warnings.is_empty());
        verify_closure(
            &dest,
            &received.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2);
        let post = &requests[1];
        assert!(
            post.head
                .starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Content-Type: application/x-git-upload-pack-request"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Accept: application/x-git-upload-pack-result"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(FOUR.len() + 6)
                .any(|w| w.starts_with(b"want ") && &w[5..5 + FOUR.len()] == FOUR.as_bytes()),
            "no want line in {:?}",
            post.body.escape_ascii().to_string()
        );
        assert!(post.body.windows(5).any(|w| w == b"done\n"), "no done line");
        assert!(post.body.ends_with(b"0000"), "no closing flush");
    }

    #[test]
    fn push_reports_ref_status() {
        use super::super::push::{PushUpdate, PushWireRequest};
        use super::super::session::test_support::{store_with_pack, test_store};
        use ruk_core::change::PlanId;

        let kind = HashKind::Sha1;
        let pack = include_bytes!("fixtures/basic.pack").to_vec();
        let store = store_with_pack(kind, &pack);
        let zero = kind.zero_oid();
        let mut adv_body = Vec::new();
        pktline::encode_data(&mut adv_body, b"# service=git-receive-pack\n").expect("frame");
        pktline::encode_flush(&mut adv_body);
        let first = format!(
            "{} capabilities^{{}}\0report-status-v2 report-status side-band-64k delete-refs ofs-delta object-format=sha1\n",
            zero.to_hex()
        );
        pktline::encode_data(&mut adv_body, first.as_bytes()).expect("frame");
        pktline::encode_flush(&mut adv_body);
        let mut report = sideband_frame(b"unpack ok\n");
        report.extend_from_slice(&sideband_frame(b"ok refs/heads/x\n"));
        report.extend_from_slice(b"0000");
        let (base, server) = fake_smart_server(vec![
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::ReceivePack.advertisement_type(),
                )],
                adv_body,
                false,
            ),
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::ReceivePack.result_type(),
                )],
                report,
                false,
            ),
        ]);
        // The test drives discovery itself so the advertisement (with its
        // capabilities) reaches the push half the way the verbs pass it.
        let adv = discover(&base, SmartService::ReceivePack, kind).expect("discover");
        let updates = vec![PushUpdate {
            name: b"refs/heads/x".to_vec(),
            old: zero,
            new: oid(FOUR),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
                let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let outcomes = push_pack(&base, &adv, &store, &mut plan, &req, &Interrupt::none())
            .expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].name, b"refs/heads/x");
        assert!(
            matches!(outcomes[0].result, super::super::push::RefResult::Ok),
            "{:?}",
            outcomes[0].result
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2);
        let post = &requests[1];
        assert!(
            post.head
                .starts_with("POST /a.git/git-receive-pack HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(b"refs/heads/x".len())
                .any(|w| w == b"refs/heads/x"),
            "no command line"
        );
        assert!(post.body.windows(4).any(|w| w == b"PACK"), "no pack bytes");
    }

    #[test]
    fn push_without_report_status_is_uncertain() {
        use super::super::push::{PushUpdate, PushWireRequest};
        use super::super::session::test_support::test_store;
        use ruk_core::change::PlanId;

        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let zero = kind.zero_oid();
        let updates = vec![PushUpdate {
            name: b"refs/heads/x".to_vec(),
            old: zero,
            new: oid(FOUR),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let adv = Advertisement {
            version: super::super::refadv::ProtocolVersion::V0,
            capabilities: super::super::refadv::Capabilities::default(),
            refs: Vec::new(),
            shallow: Vec::new(),
        };
        let err = push_pack(
            "http://127.0.0.1:9/a.git",
            &adv,
            &store,
            &mut plan,
            &req,
            &Interrupt::none(),
        )
        .expect_err("no report-status");
        assert!(
            matches!(err, GitError::PushUncertain { .. }),
            "unexpected {err:?}"
        );
    }
}
