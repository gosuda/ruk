//! Server half of protocol v2 `upload-pack`: capability advertisement plus
//! the `ls-refs` and `fetch` commands over the stateful stdio/SSH transport.
//!
//! Protocol selection rides on `GIT_PROTOCOL` the way the oracle's
//! `determine_protocol_version_server` reads it (`git/protocol.c`): the
//! client asks for v2 through its transport side channel (the SSH
//! `SendEnv`, the git-daemon extra parameter, the HTTP `Git-Protocol`
//! header), and the server speaks first in both versions, so no stdin
//! sniffing is involved. [`serve_upload_pack_v2`] runs only when
//! [`git_protocol_requests_v2`] says so; v0 stays the default everywhere
//! else, and `receive-pack` stays v0 unconditionally (protocol v2 defines
//! no push command, so there is no v2 shape to serve).
//!
//! - `ls-refs` answers ref rows with `symref-target`/`peeled` attributes
//!   exactly where the oracle puts them (`git/ls-refs.c` `send_ref`:
//!   `peeled` only on tag targets, unborn `HEAD` only when the client
//!   asked `unborn` *and* `symrefs`). Non-direct non-`HEAD` refs are
//!   skipped, mirroring the v0 half's advertisement.
//! - `fetch` answers a `done` request with one `packfile` section whose
//!   bytes are side-band-64k multiplexed, the form
//!   [`super::proto_v2::read_fetch_response`] already demultiplexes. A
//!   request without `done` gets `acknowledgments` + `NAK` + flush and the
//!   loop continues, the same always-correct posture as the v0 half's NAK
//!   answers. `filter` lines are refused like the v0 half refuses an
//!   unnegotiated `filter` capability (the `filter` feature is never
//!   advertised); `shallow`/`deepen` lines are consumed but not honored,
//!   serving full history the way the v0 half does.
//!
//! The loop ends on an empty request (a lone flush) or on EOF at a command
//! boundary, which is how a client that is done with the connection tears
//! down its end. Every other error aborts the connection the way the
//! oracle dies on protocol errors.
//!
//! Oracle anchors: `git/Documentation/gitprotocol-v2.adoc`,
//! `git/serve.c` (`protocol_v2_serve_loop`), `git/upload-pack.c`
//! (`upload_pack_v2`, `process_args`), `git/ls-refs.c`.

use std::io::{Read, Write};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::RefTarget;
use ruk_core::store::Store;
use ruk_core::store::types::ObjectKind;

use super::pack::{PackEntry, write_pack};
use super::pktline::{self, Packet, PktReader, encode_data, encode_flush, send};
use super::proto_v2;
use super::refadv::Capabilities;
use super::serve::HeadAdvertisement;
use super::session::{LocalFetchRequest, advertise, local_closure};
use super::{AGENT, Interrupt, has_object, read_object};
use crate::{GitError, parse_oid_for};

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// Whether the `GIT_PROTOCOL` environment value asks for protocol v2.
///
/// Mirrors the oracle's greatest-version selection (`git/protocol.c`
/// `determine_protocol_version_server`): the value is a colon-separated
/// list of `version=<n>` tokens, and v2 wins when any token names it. A
/// missing or unrelated value keeps the v0 default.
///
/// # Examples
///
/// ```
/// # use ruk_git::transport::serve_v2::git_protocol_requests_v2;
/// assert!(git_protocol_requests_v2(Some("version=2")));
/// assert!(!git_protocol_requests_v2(None));
/// ```
#[must_use]
pub fn git_protocol_requests_v2(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.split(':').any(|token| token.trim() == "version=2"))
}

/// The v2 capability advertisement this server speaks: `agent`, `ls-refs`
/// with `unborn`, a `fetch` without optional features the pack tail cannot
/// honor (no `shallow`, no `filter`, no `ref-in-want`), `server-option`,
/// and the store's `object-format`. The shape matches stock git's default
/// advertisement minus `shallow`, which would promise depth handling the
/// full-history pack tail does not do.
pub(crate) fn server_capabilities(kind: HashKind) -> Capabilities {
    let mut caps = Capabilities::default();
    caps.push_entry(format!("agent={AGENT}").as_bytes());
    caps.push_entry(b"ls-refs=unborn");
    caps.push_entry(b"fetch=wait-for-done");
    caps.push_entry(b"server-option");
    caps.push_entry(format!("object-format={}", kind.format_name()).as_bytes());
    caps
}

/// Serves one `upload-pack` session over protocol v2: writes the capability
/// advertisement, then serves `ls-refs` and `fetch` commands until the
/// client sends an empty request or closes the connection.
///
/// # Errors
///
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or a client object format that disagrees with
/// the store, plus closure, pack and transport failures.
pub fn serve_upload_pack_v2<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    if store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "serving store uses another object format".to_owned(),
        });
    }
    let caps = server_capabilities(kind);
    send(
        &mut writer,
        &proto_v2::encode_capability_advertisement(&caps)?,
    )?;
    let mut pkt = PktReader::new(reader, interrupt.clone());
    loop {
        match read_request(&mut pkt, store, kind)? {
            Request::Done => return Ok(()),
            Request::LsRefs(args) => serve_ls_refs(&mut writer, store, kind, head, &args)?,
            Request::Fetch(args) => serve_fetch(&mut writer, store, kind, &args, interrupt)?,
        }
    }
}

/// One parsed client request: either a command with its argument lines, or
/// the end of the session.
enum Request {
    /// An empty request (a lone flush) or EOF at a command boundary: the
    /// client is done with the connection.
    Done,
    /// `ls-refs` with its parsed arguments.
    LsRefs(LsRefsArgs),
    /// `fetch` with its parsed arguments.
    Fetch(FetchArgs),
}

/// What one `ls-refs` command asked for (`gitprotocol-v2.adoc` "ls-refs").
#[derive(Clone, Debug, Default)]
struct LsRefsArgs {
    /// Report `symref-target` attributes.
    symrefs: bool,
    /// Report `peeled` attributes on tags.
    peel: bool,
    /// Report an unborn `HEAD`.
    unborn: bool,
    /// `ref-prefix` filters; empty means every ref.
    prefixes: Vec<Vec<u8>>,
}

/// What one `fetch` command asked for (`gitprotocol-v2.adoc` "fetch").
///
/// Pack-shaping flags (`thin-pack`, `ofs-delta`, `no-progress`,
/// `include-tag`, `sideband-all`) are accepted and ignored: the pack tail
/// always emits a self-contained whole pack, which satisfies every one of
/// them. `shallow`/`deepen` lines are likewise consumed without effect.
#[derive(Clone, Debug, Default)]
struct FetchArgs {
    /// OIDs to retrieve (`want` lines).
    wants: Vec<Oid>,
    /// OIDs the client already holds (`have` lines).
    haves: Vec<Oid>,
    /// The client ended negotiation (`done`).
    done: bool,
    /// The client may send wants-free `have` probes (`wait-for-done`).
    wait_for_done: bool,
}

/// Reads one command request: the capability/command keys up to a
/// delimiter or flush, then the command arguments up to the flush.
///
/// An I/O failure at a fresh command boundary ends the session instead of
/// failing it: that is the client's normal teardown (it closes its end
/// when it has no more commands).
fn read_request<R: Read>(
    pkt: &mut PktReader<R>,
    store: &Store,
    kind: HashKind,
) -> Result<Request, GitError> {
    let Some(keys) = read_keys(pkt)? else {
        return Ok(Request::Done);
    };
    check_object_format(keys.object_format.as_deref(), kind)?;
    // A flush ends the keys with no argument section; only a delimiter
    // opens one. Reading args unconditionally would swallow the next
    // command's keys.
    let arg_lines = if keys.args_follow {
        read_args(pkt, &keys.command)?
    } else {
        Vec::new()
    };
    if keys.command == b"ls-refs" {
        Ok(Request::LsRefs(parse_ls_refs_args(&arg_lines)?))
    } else {
        Ok(Request::Fetch(parse_fetch_args(&arg_lines, kind, store)?))
    }
}

/// One request's capability/command keys: the command, the client object
/// format when the client sent one, and whether a delimiter opened an
/// argument section.
struct RequestKeys {
    command: Vec<u8>,
    object_format: Option<Vec<u8>>,
    args_follow: bool,
}

/// Reads the keys section up to its delimiter or flush: `None` for an
/// empty request (a lone flush) or EOF at a fresh command boundary, which
/// is the client's normal teardown.
fn read_keys<R: Read>(pkt: &mut PktReader<R>) -> Result<Option<RequestKeys>, GitError> {
    let mut command: Option<Vec<u8>> = None;
    let mut object_format: Option<Vec<u8>> = None;
    let mut seen_any = false;
    // Ends the keys section: `false` for a flush (no argument section
    // follows), `true` for a delimiter (arguments follow).
    let args_follow = loop {
        let packet = match pkt.read_packet() {
            Err(err) if !seen_any && matches!(err, GitError::Io { .. }) => {
                return Ok(None);
            }
            Err(err) => return Err(err),
            Ok(packet) => packet,
        };
        match packet {
            // A flush ends the keys with no argument section; only a
            // delimiter opens one.
            Packet::Flush => break false,
            Packet::Delimiter => break true,
            Packet::ResponseEnd => {
                return Err(corrupt("unexpected response-end in a command request"));
            }
            Packet::Data(_) => {
                let line = pkt.last_line().unwrap_or_default().to_vec();
                seen_any = true;
                parse_key_line(&line, &mut command, &mut object_format)?;
            }
        }
    };
    if !seen_any {
        return Ok(None);
    }
    let Some(command) = command else {
        return Err(corrupt("no command requested"));
    };
    Ok(Some(RequestKeys {
        command,
        object_format,
        args_follow,
    }))
}

/// Folds one keys-section line into the pending command or client format.
///
/// `agent` and `server-option` are informative only (the oracle's
/// `server-option` capability likewise carries no per-command meaning for
/// `upload-pack`); anything else unadvertised is a protocol error.
fn parse_key_line(
    line: &[u8],
    command: &mut Option<Vec<u8>>,
    object_format: &mut Option<Vec<u8>>,
) -> Result<(), GitError> {
    if let Some(name) = line.strip_prefix(b"command=") {
        if command.is_some() {
            return Err(corrupt("command requested twice"));
        }
        if name.is_empty() || name.contains(&b'=') || (name != b"ls-refs" && name != b"fetch") {
            return Err(corrupt(format!(
                "invalid command '{}'",
                line.escape_ascii()
            )));
        }
        *command = Some(name.to_vec());
    } else if line.starts_with(b"agent=") || line.starts_with(b"server-option") {
    } else if let Some(value) = line.strip_prefix(b"object-format=") {
        *object_format = Some(value.to_vec());
    } else {
        return Err(corrupt(format!(
            "unknown capability '{}'",
            line.escape_ascii()
        )));
    }
    Ok(())
}

/// Checks the client object format against the store; an absent line means
/// SHA-1, the oracle's default assumption.
fn check_object_format(format: Option<&[u8]>, kind: HashKind) -> Result<(), GitError> {
    let Some(value) = format else {
        if kind == HashKind::Sha1 {
            return Ok(());
        }
        return Err(GitError::ObjectFormat {
            detail: "client assumes sha1 but the store is not sha1".to_owned(),
        });
    };
    let remote = match value {
        b"sha1" => HashKind::Sha1,
        b"sha256" => HashKind::Sha256,
        _ => {
            return Err(GitError::ObjectFormat {
                detail: format!("client uses unknown object format {}", value.escape_ascii()),
            });
        }
    };
    if remote != kind {
        return Err(GitError::ObjectFormat {
            detail: format!("client uses {remote} but the store is {kind}"),
        });
    }
    Ok(())
}

/// Reads the argument lines up to their flush; `command` names the error.
fn read_args<R: Read>(pkt: &mut PktReader<R>, command: &[u8]) -> Result<Vec<Vec<u8>>, GitError> {
    let mut lines = Vec::new();
    loop {
        match pkt.read_packet()? {
            Packet::Flush => return Ok(lines),
            Packet::Delimiter | Packet::ResponseEnd => {
                return Err(corrupt(format!(
                    "expected flush after {} arguments",
                    String::from_utf8_lossy(command)
                )));
            }
            Packet::Data(_) => lines.push(pkt.last_line().unwrap_or_default().to_vec()),
        }
    }
}

/// Parses `ls-refs` argument lines; anything else is a protocol error, the
/// way the oracle dies on unexpected lines.
fn parse_ls_refs_args(lines: &[Vec<u8>]) -> Result<LsRefsArgs, GitError> {
    let mut args = LsRefsArgs::default();
    for line in lines {
        if line == b"peel" {
            args.peel = true;
        } else if line == b"symrefs" {
            args.symrefs = true;
        } else if line == b"unborn" {
            args.unborn = true;
        } else if let Some(prefix) = line.strip_prefix(b"ref-prefix ") {
            args.prefixes.push(prefix.to_vec());
        } else {
            return Err(corrupt(format!(
                "unexpected ls-refs argument '{}'",
                line.escape_ascii()
            )));
        }
    }
    Ok(args)
}

/// Parses `fetch` argument lines. `filter`, `want-ref`, `packfile-uris`
/// and the `deepen-since`/`deepen-not` spellings are refused: their
/// features are never advertised, so a client that sends them is not
/// gating on the advertisement.
fn parse_fetch_args(
    lines: &[Vec<u8>],
    kind: HashKind,
    store: &Store,
) -> Result<FetchArgs, GitError> {
    let mut args = FetchArgs::default();
    for line in lines {
        if let Some(rest) = line.strip_prefix(b"want ") {
            let oid = parse_fetch_oid(rest, kind)?;
            if !has_object(store, oid)? {
                return Err(corrupt(format!("not our ref {oid}")));
            }
            args.wants.push(oid);
        } else if let Some(rest) = line.strip_prefix(b"have ") {
            args.haves.push(parse_fetch_oid(rest, kind)?);
        } else if line == b"done" {
            args.done = true;
        } else if line == b"wait-for-done" {
            args.wait_for_done = true;
        } else if matches!(
            line.as_slice(),
            b"thin-pack" | b"ofs-delta" | b"no-progress" | b"include-tag" | b"sideband-all"
        ) {
            // Accepted base arguments the whole-pack tail trivially
            // satisfies; see [`FetchArgs`].
        } else if line.starts_with(b"shallow ") || line.starts_with(b"deepen") {
            // Consumed but not honored: full history is served, the same
            // fallback clients use against servers lacking those
            // capabilities.
        } else if line.starts_with(b"filter ") {
            return Err(corrupt("filtering capability not negotiated"));
        } else {
            return Err(corrupt(format!(
                "unexpected fetch argument '{}'",
                line.escape_ascii()
            )));
        }
    }
    Ok(args)
}

/// Reads one client OID the way the fetch clients do.
fn parse_fetch_oid(field: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field).map_err(|_| {
        corrupt(format!(
            "client sent a non-ASCII object id {}",
            field.escape_ascii()
        ))
    })?;
    parse_oid_for(text, kind).map_err(|err| match err {
        GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
        other => corrupt(other.to_string()),
    })
}

/// Whether `name` survives the `ref-prefix` filter: with no prefixes every
/// ref matches, the way the oracle treats an empty prefix list.
fn matches_prefixes(name: &[u8], prefixes: &[Vec<u8>]) -> bool {
    prefixes.is_empty() || prefixes.iter().any(|prefix| name.starts_with(prefix))
}

/// Peels a tag target to its final object, following nested tags. Returns
/// `None` for non-tag targets (the oracle reports no `peeled` attribute
/// for those) and for a tag that peels to itself.
fn peel_tag(store: &Store, oid: Oid, kind: HashKind) -> Result<Option<Oid>, GitError> {
    const TAG_READ_MAX: u64 = 1 << 20;
    const MAX_TAG_DEPTH: usize = 32;
    let (first_kind, _) = read_object(store, oid, TAG_READ_MAX)?;
    if first_kind != ObjectKind::Tag {
        return Ok(None);
    }
    let mut current = oid;
    for _ in 0..MAX_TAG_DEPTH {
        let (_, bytes) = read_object(store, current, TAG_READ_MAX)?;
        let Some(next) = parse_tag_target(&bytes, kind)? else {
            return Err(corrupt(format!("tag {current} names no object")));
        };
        let (next_kind, _) = read_object(store, next, TAG_READ_MAX)?;
        if next_kind != ObjectKind::Tag {
            return Ok(if next == oid { None } else { Some(next) });
        }
        current = next;
    }
    Err(corrupt(format!(
        "tag {oid} nests deeper than {MAX_TAG_DEPTH}"
    )))
}

/// The OID a tag object points at: the hex after its `object ` header line.
fn parse_tag_target(bytes: &[u8], kind: HashKind) -> Result<Option<Oid>, GitError> {
    for line in bytes.split(|b| *b == b'\n') {
        if let Some(hex) = line.strip_prefix(b"object ") {
            let text = std::str::from_utf8(hex)
                .map_err(|_| corrupt(format!("tag target is not ASCII: {}", hex.escape_ascii())))?;
            return parse_oid_for(text, kind)
                .map(Some)
                .map_err(|err| match err {
                    GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
                    other => corrupt(other.to_string()),
                });
        }
    }
    Ok(None)
}

/// Serves one `ls-refs` command: `HEAD` plus every direct ref that survives
/// the prefix filter, with `symref-target`/`peeled` attributes exactly
/// where the oracle puts them, then a flush.
fn serve_ls_refs<W: Write>(
    writer: &mut W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    args: &LsRefsArgs,
) -> Result<(), GitError> {
    let mut out = Vec::new();
    let zero = kind.zero_oid();
    if head.oid != zero {
        if matches_prefixes(b"HEAD", &args.prefixes) {
            let mut row = format!("{} HEAD", head.oid.to_hex()).into_bytes();
            if args.symrefs {
                if let Some(target) = head.symref.as_deref() {
                    row.extend_from_slice(b" symref-target:");
                    row.extend_from_slice(target);
                }
            }
            row.push(b'\n');
            encode_data(&mut out, &row)?;
        }
    } else if args.unborn && args.symrefs {
        // An unborn `HEAD` is reported only when the client asked for both
        // `unborn` and `symrefs`, mirroring `send_possibly_unborn_head`.
        if let Some(target) = head.symref.as_deref() {
            if matches_prefixes(b"HEAD", &args.prefixes) {
                let mut row = b"unborn HEAD symref-target:".to_vec();
                row.extend_from_slice(target);
                row.push(b'\n');
                encode_data(&mut out, &row)?;
            }
        }
    }
    for entry in advertise(store)? {
        let RefTarget::Direct(oid) = &entry.target else {
            continue;
        };
        if !matches_prefixes(&entry.name, &args.prefixes) {
            continue;
        }
        let mut row = oid.to_hex().into_bytes();
        row.push(b' ');
        row.extend_from_slice(&entry.name);
        if args.peel {
            if let Some(peeled) = peel_tag(store, *oid, kind)? {
                row.extend_from_slice(b" peeled:");
                row.extend_from_slice(peeled.to_hex().as_bytes());
            }
        }
        row.push(b'\n');
        encode_data(&mut out, &row)?;
    }
    encode_flush(&mut out);
    send(writer, &out)
}

/// Serves one `fetch` command. Without `done` the answer is
/// `acknowledgments` + `NAK` + flush and the session continues; with `done`
/// it is one `packfile` section with a side-band-64k multiplexed pack plus
/// a flush. A request with no wants (and no `wait-for-done`) answers
/// nothing, mirroring the oracle's guess that the client wants nothing.
fn serve_fetch<W: Write>(
    writer: &mut W,
    store: &Store,
    kind: HashKind,
    args: &FetchArgs,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    if args.wants.is_empty() && !args.wait_for_done {
        return Ok(());
    }
    if !args.done {
        let mut out = Vec::new();
        encode_data(&mut out, b"acknowledgments\n")?;
        encode_data(&mut out, b"NAK\n")?;
        encode_flush(&mut out);
        return send(writer, &out);
    }
    let req = LocalFetchRequest {
        wants: args.wants.clone(),
        haves: args.haves.clone(),
        filter: None,
        depth: None,
    };
    let closure = local_closure(store, kind, &req, interrupt)?;
    let entries: Vec<PackEntry<'_>> = closure
        .objects
        .iter()
        .map(|(oid, obj_kind, bytes)| PackEntry {
            oid: *oid,
            kind: *obj_kind,
            bytes,
            base: None,
        })
        .collect();
    let mut head = Vec::new();
    encode_data(&mut head, b"packfile\n")?;
    send(writer, &head)?;
    let mut sideband = SidebandWriter::new(writer);
    write_pack(&mut sideband, kind, &entries, interrupt)?;
    sideband.finish()?;
    let mut end = Vec::new();
    encode_flush(&mut end);
    send(writer, &end)
}

/// Largest band-1 payload per sideband frame; the frame stays far below
/// [`super::pktline::LARGE_PACKET_MAX`].
const SIDEBAND_CHUNK: usize = 32768;

/// Frames one writer's bytes as side-band-64k band-1 lines (`\x01` +
/// payload per pkt-line), the multiplexing the v2 `packfile` section
/// requires and [`super::proto_v2::read_fetch_response`] demultiplexes.
/// Partial frames go out on every flush, so the pack streams instead of
/// buffering whole.
struct SidebandWriter<'w, W: Write> {
    inner: &'w mut W,
    buf: Vec<u8>,
}

impl<'w, W: Write> SidebandWriter<'w, W> {
    fn new(inner: &'w mut W) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Emits the buffered remainder as one final band-1 frame, if any.
    fn finish(mut self) -> Result<(), GitError> {
        if !self.buf.is_empty() {
            let pending = std::mem::take(&mut self.buf);
            self.emit(&pending)?;
        }
        self.inner
            .flush()
            .map_err(|err| pktline::io_error("sending the packfile", &err))
    }

    /// Emits full chunks buffered so far, keeping only a short tail.
    fn pump(&mut self) -> Result<(), GitError> {
        while self.buf.len() >= SIDEBAND_CHUNK {
            let chunk: Vec<u8> = self.buf.drain(..SIDEBAND_CHUNK).collect();
            self.emit(&chunk)?;
        }
        Ok(())
    }

    /// Emits one band-1 frame around `chunk`.
    fn emit(&mut self, chunk: &[u8]) -> Result<(), GitError> {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1u8);
        payload.extend_from_slice(chunk);
        let mut frame = Vec::with_capacity(payload.len() + 4);
        encode_data(&mut frame, &payload)?;
        self.inner
            .write_all(&frame)
            .and_then(|()| self.inner.flush())
            .map_err(|err| pktline::io_error("sending the packfile", &err))
    }
}

impl<W: Write> Write for SidebandWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        self.pump().map_err(std::io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let pending = std::mem::take(&mut self.buf);
            self.emit(&pending).map_err(std::io::Error::other)?;
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fetch::verify_closure;
    use super::super::pack::{IngestLimits, ingest_pack};
    use super::super::pktline::{PktReader, encode_data};
    use super::super::refadv::{Initial, read_initial};
    use super::super::session::test_support::{store_with_pack, test_store};
    use super::*;
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    const THREE: &str = "7a4943e466a7ce4f4c56d9eeb89c8909b1c43d22";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn head() -> HeadAdvertisement {
        HeadAdvertisement {
            oid: oid(FOUR),
            symref: Some(b"refs/heads/main".to_vec()),
        }
    }

    fn set_ref(store: &Store, kind: HashKind, name: &[u8], target: Oid) {
        let update = RefUpdate {
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(target)),
            name: RefName::new(name.to_vec()).expect("ref name"),
        };
        let transaction = RefTransaction::new(kind, vec![update]).expect("transaction");
        let prepared = prepare_checked_transaction(store, &transaction).expect("prepare");
        store
            .publish(Vec::new(), &prepared.into_mutations())
            .expect("publish ref");
    }

    fn server_store() -> Store {
        let kind = HashKind::Sha1;
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        set_ref(&store, kind, b"refs/heads/main", oid(FOUR));
        store
    }

    fn frame(line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_data(&mut out, line).expect("frame");
        out
    }

    /// One scripted v2 session: the client keys plus one command's
    /// arguments, served to EOF (the client's normal teardown).
    fn serve_session(script: &[u8], store: &Store, kind: HashKind) -> Vec<u8> {
        let mut out = Vec::new();
        serve_upload_pack_v2(script, &mut out, store, kind, &head(), &Interrupt::none())
            .expect("serve");
        out
    }

    fn ls_refs_command(prefixes: &[&[u8]]) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=ls-refs\n"));
        script.extend_from_slice(&frame(b"agent=test\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(b"peel\n"));
        script.extend_from_slice(&frame(b"symrefs\n"));
        for prefix in prefixes {
            let mut line = b"ref-prefix ".to_vec();
            line.extend_from_slice(prefix);
            line.push(b'\n');
            script.extend_from_slice(&frame(&line));
        }
        script.extend_from_slice(b"0000");
        script
    }

    /// Skips the v2 capability advertisement, returning a reader over the
    /// first command response.
    fn past_advertisement<'a>(out: &'a [u8], kind: HashKind) -> PktReader<&'a [u8]> {
        let mut pkt = PktReader::new(out, Interrupt::none());
        match read_initial(&mut pkt, kind).expect("advertisement parses") {
            Initial::V2(caps) => {
                assert!(caps.has("agent"), "advertises agent");
                assert!(
                    caps.feature("ls-refs", "unborn"),
                    "advertises ls-refs=unborn"
                );
                assert!(
                    caps.feature("fetch", "wait-for-done"),
                    "advertises fetch=wait-for-done"
                );
                assert_eq!(
                    caps.value("object-format"),
                    Some(b"sha1".as_slice()),
                    "advertises the store format"
                );
            }
            Initial::Refs(_) => panic!("expected a v2 advertisement"),
        }
        pkt
    }

    #[test]
    fn git_protocol_env_selects_v2() {
        assert!(git_protocol_requests_v2(Some("version=2")));
        assert!(git_protocol_requests_v2(Some("version=1:version=2")));
        assert!(!git_protocol_requests_v2(None));
        assert!(!git_protocol_requests_v2(Some("version=0")));
        assert!(!git_protocol_requests_v2(Some("version=1")));
        assert!(!git_protocol_requests_v2(Some("")));
    }

    #[test]
    fn ls_refs_reports_head_and_main() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let out = serve_session(&ls_refs_command(&[]), &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        let refs = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        let main = refs
            .iter()
            .find(|row| row.name == b"refs/heads/main")
            .expect("main listed");
        assert_eq!(main.oid, Some(oid(FOUR)));
        assert_eq!(main.peeled, None, "a commit carries no peeled attribute");
        let head_row = refs.iter().find(|row| row.name == b"HEAD").expect("HEAD");
        assert_eq!(head_row.oid, Some(oid(FOUR)));
        assert_eq!(
            head_row.symref_target,
            Some(b"refs/heads/main".to_vec()),
            "symrefs honored"
        );
    }

    #[test]
    fn ls_refs_prefixes_limit_the_rows() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let out = serve_session(&ls_refs_command(&[b"refs/heads/"]), &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        let refs = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        assert!(
            refs.iter().all(|row| row.name.starts_with(b"refs/heads/")),
            "HEAD is outside the prefix: {:?}",
            refs.iter().map(|row| &row.name).collect::<Vec<_>>()
        );
        assert!(refs.iter().any(|row| row.name == b"refs/heads/main"));
    }

    #[test]
    fn ls_refs_without_delimiter_takes_no_arguments() {
        let kind = HashKind::Sha1;
        let store = server_store();
        // Keys ended by a flush carry no argument section; the server must
        // not read the next command's keys as arguments.
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=ls-refs\n"));
        script.extend_from_slice(b"0000");
        script.extend_from_slice(&ls_refs_command(&[]));
        let out = serve_session(&script, &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        let first = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        assert!(first.iter().any(|row| row.name == b"refs/heads/main"));
        let second = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        assert!(second.iter().any(|row| row.name == b"refs/heads/main"));
    }

    #[test]
    fn ls_refs_reports_unborn_head_only_when_asked() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let unborn = HeadAdvertisement {
            oid: kind.zero_oid(),
            symref: Some(b"refs/heads/main".to_vec()),
        };
        // The `unborn` argument reports the symref target without an OID.
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=ls-refs\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(b"symrefs\n"));
        script.extend_from_slice(&frame(b"unborn\n"));
        script.extend_from_slice(b"0000");
        let mut out = Vec::new();
        serve_upload_pack_v2(
            &script[..],
            &mut out,
            &store,
            kind,
            &unborn,
            &Interrupt::none(),
        )
        .expect("serve");
        let mut pkt = past_advertisement(&out, kind);
        let refs = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        assert_eq!(refs.len(), 1, "only the unborn HEAD: {refs:?}");
        assert_eq!(refs[0].name, b"HEAD");
        assert_eq!(refs[0].oid, None);
        assert_eq!(refs[0].symref_target, Some(b"refs/heads/main".to_vec()));
        // Without `unborn` the empty repository lists nothing.
        let mut bare = Vec::new();
        bare.extend_from_slice(&frame(b"command=ls-refs\n"));
        bare.extend_from_slice(b"0001");
        bare.extend_from_slice(b"0000");
        let mut out = Vec::new();
        serve_upload_pack_v2(
            &bare[..],
            &mut out,
            &store,
            kind,
            &unborn,
            &Interrupt::none(),
        )
        .expect("serve");
        let mut pkt = past_advertisement(&out, kind);
        let refs = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        assert!(refs.is_empty(), "silent unborn HEAD: {refs:?}");
    }

    #[test]
    fn ls_refs_peels_annotated_tags() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let tag_bytes =
            format!("object {FOUR}\ntype commit\ntag v1\ntagger test <t@t> 0 +0000\n\nv1\n");
        let prepared = store
            .prepare(
                ObjectKind::Tag,
                tag_bytes.len() as u64,
                &tag_bytes.as_bytes()[..],
                None,
            )
            .expect("prepare tag");
        let tag_oid = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish tag");
        set_ref(&store, kind, b"refs/tags/v1", tag_oid);
        let out = serve_session(&ls_refs_command(&[]), &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        let refs = super::super::refadv::read_ls_refs(&mut pkt, kind).expect("ls-refs");
        let tag = refs
            .iter()
            .find(|row| row.name == b"refs/tags/v1")
            .expect("tag listed");
        assert_eq!(tag.oid, Some(tag_oid));
        assert_eq!(tag.peeled, Some(oid(FOUR)), "tag peeled to its commit");
    }

    /// Builds one `command=fetch` request the way the v2 client frames it.
    fn fetch_command(store_caps: &Capabilities, wants: &[Oid], haves: &[Oid]) -> Vec<u8> {
        let cmd = proto_v2::FetchCommand {
            wants,
            haves,
            shallows: &[],
            depth: None,
            filter: None,
            thin_pack: false,
            ofs_delta: true,
            sideband_all: false,
        };
        proto_v2::fetch_request(store_caps, HashKind::Sha1, &cmd).expect("request")
    }

    #[test]
    fn fetch_serves_wants_minus_haves() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let caps = server_capabilities(kind);
        let mut script = fetch_command(&caps, &[oid(FOUR)], &[oid(THREE)]);
        // The test client framing ends at its flush; EOF then ends the
        // session the way a real client tears down.
        let out = serve_session(&script, &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        // The offering client already holds THREE, so the destination
        // starts with the full fixture published, the way a real client's
        // committed objects excuse the have-excluded parent.
        let dest = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let sections = proto_v2::read_fetch_response(
            &mut pkt,
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("fetch response");
        assert!(sections.shallow.is_empty());
        assert!(sections.staged.contains(oid(FOUR)));
        assert!(
            !sections.staged.contains(oid(THREE)),
            "the offered have stays out of the pack"
        );
        verify_closure(
            &dest,
            &sections.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure verifies");
    }

    #[test]
    fn fetch_without_done_answers_nak_and_continues() {
        let kind = HashKind::Sha1;
        let store = server_store();
        // A `have` probe with no `done`: acknowledgments, then the session
        // continues into a second `fetch` that finishes the pack.
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=fetch\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(format!("want {FOUR}\n").as_bytes()));
        script.extend_from_slice(&frame(format!("have {THREE}\n").as_bytes()));
        script.extend_from_slice(b"0000");
        let caps = server_capabilities(kind);
        script.extend_from_slice(&fetch_command(&caps, &[oid(FOUR)], &[oid(THREE)]));
        let out = serve_session(&script, &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        assert_eq!(
            pkt.read_line("section").expect("header").to_vec(),
            b"acknowledgments"
        );
        assert_eq!(
            pkt.read_line("verdict").expect("NAK").to_vec(),
            b"NAK",
            "the server never tracks common history"
        );
        assert!(
            matches!(pkt.read_packet().expect("acks flush"), Packet::Flush),
            "the acknowledgments section ends the first response"
        );
        let dest = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let sections = proto_v2::read_fetch_response(
            &mut pkt,
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("second fetch packs");
        assert!(sections.staged.contains(oid(FOUR)));
    }

    #[test]
    fn fetch_rejects_unknown_want_and_unadvertised_filter() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let unknown = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=fetch\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(format!("want {unknown}\n").as_bytes()));
        script.extend_from_slice(&frame(b"done\n"));
        script.extend_from_slice(b"0000");
        let mut out = Vec::new();
        let err = serve_upload_pack_v2(
            &script[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("unknown want");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=fetch\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(format!("want {FOUR}\n").as_bytes()));
        script.extend_from_slice(&frame(b"filter blob:none\n"));
        script.extend_from_slice(&frame(b"done\n"));
        script.extend_from_slice(b"0000");
        let mut out = Vec::new();
        let err = serve_upload_pack_v2(
            &script[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("unadvertised filter");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn unknown_command_and_mismatched_format_fail() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=push\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(b"0000");
        let mut out = Vec::new();
        let err = serve_upload_pack_v2(
            &script[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("unknown command");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=ls-refs\n"));
        script.extend_from_slice(&frame(b"object-format=sha256\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(b"0000");
        let mut out = Vec::new();
        let err = serve_upload_pack_v2(
            &script[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("format mismatch");
        assert!(matches!(err, GitError::ObjectFormat { .. }), "got {err:?}");
    }

    #[test]
    fn deepen_lines_are_consumed_not_honored() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let mut script = Vec::new();
        script.extend_from_slice(&frame(b"command=fetch\n"));
        script.extend_from_slice(b"0001");
        script.extend_from_slice(&frame(format!("want {FOUR}\n").as_bytes()));
        script.extend_from_slice(&frame(b"deepen 1\n"));
        script.extend_from_slice(&frame(b"done\n"));
        script.extend_from_slice(b"0000");
        let out = serve_session(&script, &store, kind);
        let mut pkt = past_advertisement(&out, kind);
        let dest = test_store(kind);
        let sections = proto_v2::read_fetch_response(
            &mut pkt,
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("full history served");
        verify_closure(
            &dest,
            &sections.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure verifies");
    }
}
