//! Server halves of the Git pack protocols: `upload-pack` (serves fetches)
//! and `receive-pack` (serves pushes). Protocol v0 only.
//!
//! Both halves speak the same grammars the client halves in
//! [`super::fetch`] and [`super::push`] parse, against the same stores:
//!
//! - `upload-pack` advertises refs with the capabilities this server
//!   implements (`multi_ack ofs-delta object-format agent`, plus `symref`
//!   for a symbolic `HEAD`), then runs one loop over haves, round-ending
//!   flushes, and the terminal `done`, mirroring the oracle's
//!   `get_common_commits`. Every flush is answered `NAK` without multi-round
//!   ACK tracking (always correct, at most a fatter pack), and the post-done
//!   verdict goes only to clients that negotiated multi-ack. The pack is
//!   self-contained, built by the shared
//!   [`local_closure`](super::session::local_closure) walk. Thin packs are
//!   never emitted, so `thin-pack` is not advertised; `filter` and
//!   `shallow`/`deepen` lines are consumed but not honored (full history is
//!   served, the same fallback clients use against servers lacking those
//!   capabilities), and a `filter` capability request is refused the way
//!   the oracle refuses unnegotiated filtering.
//! - `receive-pack` advertises refs with `report-status delete-refs
//!   ofs-delta push-options object-format agent`, reads update commands,
//!   then the push options (which precede the pack, like the oracle's
//!   `read_push_options`), ingests the pack (skipped for delete-only
//!   pushes, mirroring the oracle's `delete_only` gate), verifies the
//!   closure, stages the objects in quarantine (see [`super::hooks`]),
//!   runs the `pre-receive`/`update` phases, publishes objects plus commit
//!   rows only when those pass, diverts `refs/for/` commands to the
//!   `proc-receive` hook under the configured prefixes (see
//!   [`super::proc_receive`]), and applies surviving refs through the shared
//!   [`apply_refs`](super::session::apply_refs) CAS path, reporting
//!   per-ref `ok`/`ng` lines, before the `post-receive` phase. `atomic`
//!   and `push-cert` are not advertised; an `atomic` request that arrives
//!   anyway rejects every ref instead of desynchronizing the stream.
//!
//! The functions are generic over separate `Read`/`Write` halves so the CLI
//! verbs can run them buffered (scripted stdin) or streaming (live pipes).
//! An empty command list answers nothing, mirroring the oracle; a first
//! line of `version 2` is refused naming the supported version instead of
//! misparsing as `want`.
//!
//! Oracle anchors: `git/builtin/upload-pack.c`, `git/builtin/receive-pack.c`,
//! `git/upload-pack.c`, `git/send-pack.c`, `git/Documentation/protocol-v0.txt`.

use std::collections::HashSet;
use std::io::{Read, Write};

use ruk_core::LfsMode;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefRead, RefTarget};
use ruk_core::refs::StoreRefs;
use ruk_core::store::types::ObjectKind;
use ruk_core::store::{EventContext, EventSource, FactMutation, Store};

use super::fetch::{commit_record_facts, verify_closure};
use super::hooks::stage_quarantine;
use super::lfs::refusals_for_live;
use super::pack::{IngestLimits, PackEntry, StagedPack, ingest_pack, write_pack};
use super::pktline::{Packet, PktReader, encode_data, encode_flush, send};
use super::policy::{
    LandedRefs, NoPolicy, ReceiveBatch, ReceiveCommand, ReceivePolicy, RefVerdict,
};
use super::proc_receive::AlternateRef;
use super::push::{PushUpdate, RefResult};
use super::session::{LocalFetchRequest, advertise, apply_refs, local_closure};
use super::{AGENT, Interrupt, has_object};
use crate::{GitError, parse_oid_for};

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// `HEAD` as the wire advertisement needs it: the OID on the `HEAD` line
/// (zero when unborn) and the symbolic target for the `symref` capability.
#[derive(Clone, Debug)]
pub struct HeadAdvertisement {
    /// OID behind `HEAD`; the zero OID when unborn.
    pub oid: Oid,
    /// Symbolic target of `HEAD` (usually a branch); `None` when detached.
    pub symref: Option<Vec<u8>>,
}

fn object_format_value(kind: HashKind) -> &'static str {
    match kind {
        HashKind::Sha1 => "sha1",
        HashKind::Sha256 => "sha256",
    }
}

/// Flattens a message onto one short line for `unpack`/`ng` report lines.
fn sanitize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

/// Builds a v0 ref advertisement: one `HEAD` line (or a zeroed
/// `capabilities^{}` line for an empty repository, mirroring the oracle),
/// every direct ref, capabilities on the first line only, then a flush.
///
/// Symbolic non-`HEAD` refs are not advertised in v1; only `HEAD` carries a
/// symref, which is the common case by far.
fn advertisement(
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    caps: &str,
) -> Result<Vec<u8>, GitError> {
    let refs = advertise(store)?;
    let zero = kind.zero_oid();
    let mut rows: Vec<Vec<u8>> = Vec::with_capacity(refs.len() + 1);
    if refs.is_empty() && head.oid == zero {
        rows.push(format!("{} capabilities^{{}}", zero.to_hex()).into_bytes());
    } else {
        rows.push(format!("{} HEAD", head.oid.to_hex()).into_bytes());
        for entry in &refs {
            if let RefTarget::Direct(oid) = &entry.target {
                let mut row = oid.to_hex().into_bytes();
                row.push(b' ');
                row.extend_from_slice(&entry.name);
                rows.push(row);
            }
        }
    }
    let mut out = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let mut payload = row.clone();
        if index == 0 {
            payload.push(0);
            payload.extend_from_slice(caps.as_bytes());
        }
        payload.push(b'\n');
        encode_data(&mut out, &payload)?;
    }
    encode_flush(&mut out);
    Ok(out)
}

/// Reads one frame that must be data or a flush.
fn read_frame<R: Read>(pkt: &mut PktReader<R>, what: &str) -> Result<Option<Vec<u8>>, GitError> {
    let packet = pkt.read_packet()?;
    match packet {
        Packet::Flush => Ok(None),
        Packet::Data(_) => Ok(Some(packet.line().unwrap_or_default().to_vec())),
        other => Err(corrupt(format!("expected {what}, got {other:?}"))),
    }
}

/// Largest push-option count accepted: the oracle bounds nothing, but an
/// unbounded pre-pack read is a memory sink, and no real client (review
/// backends use at most four AGit keys) approaches this.
const MAX_PUSH_OPTIONS: u64 = 256;

/// One parsed `want` line: the requested OID and whether the client asked
/// for multi-ack negotiation on this line's capability list.
struct Want {
    oid: Oid,
    multi_ack: bool,
}

/// Parses `want <oid> [caps]`, refusing a `filter` capability the server
/// never advertised.
fn parse_want(line: &[u8], kind: HashKind) -> Result<Want, GitError> {
    let rest = line
        .strip_prefix(b"want ")
        .ok_or_else(|| corrupt(format!("expected want, got {}", line.escape_ascii())))?;
    let split = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    let (hex, caps) = rest.split_at(split);
    let mut multi_ack = false;
    for cap in caps.split(|b| *b == b' ') {
        if cap == b"filter" {
            return Err(corrupt("filtering capability not negotiated"));
        }
        if cap == b"multi_ack" || cap == b"multi_ack_detailed" {
            multi_ack = true;
        }
    }
    let hex = std::str::from_utf8(hex)
        .map_err(|_| corrupt(format!("want OID is not ASCII: {}", hex.escape_ascii())))?;
    Ok(Want {
        oid: parse_oid_for(hex, kind)?,
        multi_ack,
    })
}

/// Builds the capability line one `upload-pack` advertisement carries.
fn upload_caps(kind: HashKind, head: &HeadAdvertisement) -> String {
    let mut caps = format!(
        "multi_ack ofs-delta object-format={} agent={}",
        object_format_value(kind),
        AGENT
    );
    if let Some(target) = head.symref.as_deref() {
        caps.push_str(&format!(" symref=HEAD:{}", String::from_utf8_lossy(target)));
    }
    caps
}

/// Writes only the `upload-pack` ref advertisement: the discovery half of
/// a stateless git-service request.
///
/// # Errors
/// [`GitError::ObjectFormat`] for store/kind mismatch, plus store failures.
pub fn advertise_upload_pack(
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
) -> Result<Vec<u8>, GitError> {
    if store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "serving store uses another object format".to_owned(),
        });
    }
    advertisement(store, kind, head, &upload_caps(kind, head))
}

/// Serves one `upload-pack` session: writes the advertisement, negotiates
/// wants/haves, and emits a self-contained pack.
///
/// `filter`/`depth` are never negotiated (see the module docs); every other
/// error aborts the connection the way the oracle dies on protocol errors.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or foreign OIDs, [`GitError::Unsupported`] for
/// protocol v2, plus closure, pack and transport failures.
pub fn serve_upload_pack<R: Read, W: Write>(
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
    send(
        &mut writer,
        &advertisement(store, kind, head, &upload_caps(kind, head))?,
    )?;

    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut wants = Vec::new();
    let mut client_multi_ack = false;
    while let Some(line) = read_frame(&mut pkt, "want lines")? {
        if line == b"version 2" {
            return Err(GitError::Unsupported {
                command: "upload-pack over protocol v2 (this server speaks v0 only)".to_owned(),
            });
        }
        if line.starts_with(b"shallow ") {
            continue;
        }
        if line.starts_with(b"deepen") && (line.len() == 6 || matches!(line[6], b' ' | b'-')) {
            continue;
        }
        if line.starts_with(b"filter ") {
            return Err(corrupt("filtering capability not negotiated"));
        }
        let want = parse_want(&line, kind)?;
        if !has_object(store, want.oid)? {
            return Err(corrupt(format!("not our ref {}", want.oid)));
        }
        client_multi_ack |= want.multi_ack;
        wants.push(want.oid);
    }
    // One loop reads haves, round-ending flushes, and the terminal `done`,
    // mirroring the oracle's `get_common_commits`: a fresh clone sends
    // `done` with no haves at all, and multi-round clients flush between
    // batches. Every flush is answered `NAK`, which ends that round; the
    // server never tracks common history, which is always a correct (if
    // sometimes full) pack.
    let mut nak = Vec::new();
    encode_data(&mut nak, b"NAK\n")?;
    let mut haves = Vec::new();
    loop {
        let packet = pkt.read_packet()?;
        if matches!(packet, Packet::Flush) {
            send(&mut writer, &nak)?;
            continue;
        }
        let line = match packet {
            Packet::Data(_) => packet.line().unwrap_or_default().to_vec(),
            other => {
                return Err(corrupt(format!("expected haves or done, got {other:?}")));
            }
        };
        if line == b"done" {
            break;
        }
        let hex = line
            .strip_prefix(b"have ")
            .ok_or_else(|| corrupt(format!("expected have, got {}", line.escape_ascii())))?;
        let hex = std::str::from_utf8(hex)
            .map_err(|_| corrupt(format!("have OID is not ASCII: {}", hex.escape_ascii())))?;
        haves.push(parse_oid_for(hex, kind)?);
    }
    // The post-done verdict goes only to clients that negotiated multi-ack;
    // without it the pack follows `done` directly.
    if client_multi_ack {
        send(&mut writer, &nak)?;
    }
    let req = LocalFetchRequest {
        wants,
        haves,
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
    write_pack(&mut writer, kind, &entries, interrupt)?;
    writer
        .flush()
        .map_err(|err| super::pktline::io_error("sending the pack", &err))?;
    Ok(())
}

/// One parsed update command.
#[derive(Clone, Debug)]
struct Command {
    old: Oid,
    new: Oid,
    name: Vec<u8>,
}

fn parse_command(line: &[u8], kind: HashKind) -> Result<Command, GitError> {
    let mut parts = line.split(|b| *b == b' ');
    let old = part_oid(parts.next(), kind)?;
    let new = part_oid(parts.next(), kind)?;
    let name = parts
        .next()
        .ok_or_else(|| corrupt("update command has no ref name"))?;
    if parts.next().is_some() {
        return Err(corrupt("update command has extra fields"));
    }
    if name.is_empty() || name.contains(&0) {
        return Err(corrupt("update command has a malformed ref name"));
    }
    Ok(Command {
        old,
        new,
        name: name.to_vec(),
    })
}

fn part_oid(part: Option<&[u8]>, kind: HashKind) -> Result<Oid, GitError> {
    let bytes = part.ok_or_else(|| corrupt("update command has no OIDs"))?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| corrupt(format!("update OID is not ASCII: {}", bytes.escape_ascii())))?;
    parse_oid_for(text, kind)
}

/// Writes a `report-status` response: `unpack ok|<err>`, then per-ref
/// `ok`/`ng` lines in command order, then a flush.
fn send_report<W: Write>(
    writer: &mut W,
    unpack_err: Option<&str>,
    rows: &[(Vec<u8>, Result<(), String>)],
) -> Result<(), GitError> {
    let mut out = Vec::new();
    match unpack_err {
        None => encode_data(&mut out, b"unpack ok\n")?,
        Some(msg) => encode_data(&mut out, format!("unpack {}\n", sanitize(msg)).as_bytes())?,
    }
    for (name, result) in rows {
        let name = String::from_utf8_lossy(name);
        match result {
            Ok(()) => encode_data(&mut out, format!("ok {name}\n").as_bytes())?,
            Err(reason) => {
                encode_data(
                    &mut out,
                    format!("ng {name} {}\n", sanitize(reason)).as_bytes(),
                )?;
            }
        }
    }
    encode_flush(&mut out);
    send(writer, &out)
}

fn all_ng(commands: &[Command], reason: &str) -> Vec<(Vec<u8>, Result<(), String>)> {
    commands
        .iter()
        .map(|cmd| (cmd.name.clone(), Err(reason.to_owned())))
        .collect()
}

/// Ingests the pack that follows the update commands, verifies the new tips
/// over staged plus committed objects, and compiles the commit-record facts.
///
/// Publication deliberately waits until the hook phases pass, so hooks
/// observe staged objects through the quarantine directory and a refusal
/// drops the staging without ever publishing it.
fn ingest_and_verify<R: Read>(
    reader: R,
    store: &Store,
    kind: HashKind,
    news: &[Oid],
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<(StagedPack, Vec<FactMutation>), GitError> {
    let staged = ingest_pack(reader, kind, store, limits, interrupt)?;
    verify_closure(store, &staged, news, None, &[], interrupt)?;
    let facts = commit_record_facts(store, &staged)?;
    Ok((staged, facts))
}

/// One `<old> <new> <ref>` line of hook stdin.
fn hook_line(cmd: &Command) -> String {
    format!(
        "{} {} {}\n",
        cmd.old.to_hex(),
        cmd.new.to_hex(),
        String::from_utf8_lossy(&cmd.name),
    )
}

/// One landed `post-receive` line for a diverted command the hook
/// accepted: the review ref it reported, with the hook-supplied OIDs when
/// it sent `option old-oid` / `option new-oid`, else the pushed OIDs.
fn alternate_line(alternate: &AlternateRef, old: Oid, new: Oid) -> String {
    format!(
        "{} {} {}\n",
        alternate.old_oid.unwrap_or(old).to_hex(),
        alternate.new_oid.unwrap_or(new).to_hex(),
        String::from_utf8_lossy(&alternate.refname),
    )
}

/// Serves one `receive-pack` session: writes the advertisement, reads update
/// commands plus the pack, and reports per-ref outcomes.
///
/// Ingest, verification and publication failures still send a report (`unpack
/// <err>` with every ref `ng`) before returning the error, so the client
/// stays in sync; per-ref CAS rejections are outcomes, not errors.
///
/// Hook phases are disabled: this is the historical entry point preserved
/// for callers without a repository directory, served under [`NoPolicy`].
/// Pass [`ScriptPolicy`] to [`serve_receive_pack_with`] to enable
/// quarantine staging with `pre-receive`/`update`/`post-receive`
/// execution.
///
/// `lfs` is the store's pointer policy: under [`LfsMode::Deny`] a push
/// whose new-tip closure introduces a pointer blob refuses exactly those
/// ref updates with an `ng` line, the way hook refusals report in-band.
/// Under [`LfsMode::Pointers`] pointer bytes land plainly, which is what
/// ingest already does.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or foreign OIDs, plus ingest, verification,
/// store and transport failures.
pub fn serve_receive_pack<R: Read, W: Write>(
    reader: R,
    writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
    lfs: LfsMode,
) -> Result<(), GitError> {
    serve_receive_pack_with(ReceivePackParams {
        reader,
        writer,
        store,
        kind,
        head,
        interrupt,
        policy: &NoPolicy,
        lfs,
        limits: ReceiveLimits::default(),
        on_behalf_of: None,
    })?;
    Ok(())
}

/// Builds the capability line one `receive-pack` advertisement carries.
fn receive_caps(kind: HashKind) -> String {
    format!(
        "report-status delete-refs ofs-delta push-options object-format={} agent={}",
        object_format_value(kind),
        AGENT
    )
}

/// Writes only the `receive-pack` ref advertisement: the discovery half of
/// a stateless git-service request.
///
/// # Errors
/// [`GitError::ObjectFormat`] for store/kind mismatch, plus store failures.
pub fn advertise_receive_pack(
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
) -> Result<Vec<u8>, GitError> {
    if store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "serving store uses another object format".to_owned(),
        });
    }
    advertisement(store, kind, head, &receive_caps(kind))
}

/// Computes the daemon-side digest of one git-service request: SHA-256 over
/// a domain tag, the service name, the parsed command lines, and the
/// canonical effective limits. Client values never feed it.
#[must_use]
pub fn git_service_digest(service: &str, commands: &[Vec<u8>], limits: &[u8]) -> String {
    let mut hasher = gix_hash::hasher(HashKind::Sha256.gix());
    hasher.update(b"ruk-git-service-v1\0");
    hasher.update(service.as_bytes());
    hasher.update(b"\0");
    for command in commands {
        hasher.update(command);
        hasher.update(b"\0");
    }
    hasher.update(limits);
    let digest = hasher
        .try_finalize()
        .expect("SHA-256 has no collision refusal");
    let mut hex = String::with_capacity(digest.as_bytes().len() * 2);
    for byte in digest.as_bytes() {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("hex digit"));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("hex digit"));
    }
    hex
}

/// Bounds for one receive-pack round: pack ingest quotas plus the push
/// option cap. Envelopes without explicit quotas serve with the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveLimits {
    /// Pack ingest quotas applied to the round's pack.
    pub ingest: IngestLimits,
    /// Largest push-option count accepted when negotiated.
    pub max_push_options: u64,
}

impl Default for ReceiveLimits {
    fn default() -> Self {
        Self {
            ingest: IngestLimits::default(),
            max_push_options: MAX_PUSH_OPTIONS,
        }
    }
}

/// Parameters for one `receive-pack` round: the transport streams, the
/// store and its advertisement, the interrupt flag, the serving policy,
/// and the envelope limits and provenance.
///
/// Grouped so new envelope fields extend the struct instead of
/// lengthening the serve entry.
pub struct ReceivePackParams<'a, R: Read, W: Write> {
    /// Request bytes.
    pub reader: R,
    /// Response bytes.
    pub writer: W,
    /// Store the pack stages into and the refs publish from.
    pub store: &'a Store,
    /// Object format the round serves.
    pub kind: HashKind,
    /// Advertisement the round reports.
    pub head: &'a HeadAdvertisement,
    /// Cancellation flag the pack stages check.
    pub interrupt: &'a Interrupt,
    /// Hook policy the round answers through.
    pub policy: &'a dyn ReceivePolicy,
    /// Pointer policy for pushed blobs.
    pub lfs: LfsMode,
    /// Pack ingest quotas plus the push-option cap.
    pub limits: ReceiveLimits,
    /// Provenance the invocation declared; recorded, never authorized on.
    pub on_behalf_of: Option<&'a str>,
}

impl<R: Read, W: Write> std::fmt::Debug for ReceivePackParams<'_, R, W> {
    /// Formats the identifying parameters: streams and policy do not
    /// implement [`std::fmt::Debug`], so only the round shape renders.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivePackParams")
            .field("kind", &self.kind)
            .field("lfs", &self.lfs)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Serves one `receive-pack` session with quarantine staging and hook
/// phases (see [`super::hooks`]): the pack stages unpublished, hooks
/// observe it through the quarantine directory, staged objects publish
/// only after the refusing phases pass, `refs/for/` commands divert to
/// the `proc-receive` hook under the configured prefixes (default
/// `["refs/for"]`, so `refs/pull/` lands as a plain ref; see
/// [`super::proc_receive`]), surviving refs apply through the shared CAS
/// path, and `post-receive` runs after refs land.
///
/// A `pre-receive` refusal marks every live ref `ng` and drops the staging
/// without publishing; an `update` refusal marks only its own ref; a
/// `proc-receive` refusal marks only its diverted refs while normal refs
/// still land; a `post-receive` failure is relayed to the server's stderr
/// and never fails the push. Refusals complete the protocol with `unpack
/// ok` plus `ng` lines and return `Ok`, exactly like CAS rejections.
///
/// Returns the landed event sequences in outcome order, identifying this
/// push's operations for the caller's exit report.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or foreign OIDs, plus ingest, verification,
/// store and transport failures.
pub fn serve_receive_pack_with<R: Read, W: Write>(
    params: ReceivePackParams<'_, R, W>,
) -> Result<Vec<u64>, GitError> {
    let ReceivePackParams {
        reader,
        mut writer,
        store,
        kind,
        head,
        interrupt,
        policy,
        lfs,
        limits,
        on_behalf_of,
    } = params;
    let context = EventContext {
        on_behalf_of: on_behalf_of.map(str::to_owned),
        ..EventContext::default()
    };
    if store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "serving store uses another object format".to_owned(),
        });
    }
    send(
        &mut writer,
        &advertisement(store, kind, head, &receive_caps(kind))?,
    )?;

    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut commands: Vec<Command> = Vec::new();
    let mut atomic = false;
    let mut client_push_options = false;
    while let Some(mut line) = read_frame(&mut pkt, "update commands")? {
        if commands.is_empty() {
            if line == b"push-cert" || line.starts_with(b"push-cert\0") {
                return Err(GitError::Unsupported {
                    command: "receive-pack push-cert (not advertised)".to_owned(),
                });
            }
            if let Some(nul) = line.iter().position(|b| *b == 0) {
                let tail = line.split_off(nul);
                for token in tail[1..].split(|b| *b == b' ') {
                    if token == b"atomic" {
                        atomic = true;
                    } else if token == b"push-options" {
                        client_push_options = true;
                    }
                }
            }
        }
        commands.push(parse_command(&line, kind)?);
    }
    if commands.is_empty() {
        return Ok(Vec::new());
    }
    // Push options follow the commands flush and precede the pack, exactly
    // like the oracle's `read_push_options` before `unpack_with_sideband`.
    // Hosts advertise them on every repository
    // (`receive.advertisePushOptions`), and AGit reads `topic`,
    // `force-push`, `title` and `description` from them.
    let mut push_options: Vec<String> = Vec::new();
    if client_push_options {
        while let Some(line) = read_frame(&mut pkt, "push options")? {
            if push_options.len() as u64 >= limits.max_push_options {
                return Err(GitError::Limit {
                    detail: format!("push sent more than {} options", limits.max_push_options),
                });
            }
            let option =
                String::from_utf8(line).map_err(|_| corrupt("push option is not UTF-8"))?;
            push_options.push(option);
        }
    }
    let zero = kind.zero_oid();
    // Pre-validate names: `apply_refs` fails the whole batch on a malformed
    // name, but the wire demands per-ref verdicts.
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut live: Vec<(usize, PushUpdate)> = Vec::with_capacity(commands.len());
    let mut results: Vec<Option<Result<(), String>>> = (0..commands.len()).map(|_| None).collect();
    for (index, cmd) in commands.iter().enumerate() {
        if !seen.insert(cmd.name.as_slice()) {
            results[index] = Some(Err("duplicate command for ref".to_owned()));
        } else if RefName::new(cmd.name.clone()).is_err() {
            results[index] = Some(Err("malformed ref name".to_owned()));
        } else {
            live.push((
                index,
                PushUpdate {
                    name: cmd.name.clone(),
                    old: cmd.old,
                    new: cmd.new,
                },
            ));
        }
    }
    // The pack follows only when some ref gains objects; delete-only pushes
    // send none, mirroring the oracle's `delete_only` gate. Staging stays
    // unpublished: hooks observe it through quarantine, and publication
    // waits until the refusing phases pass.
    let mut staged: Option<StagedPack> = None;
    let mut facts: Vec<FactMutation> = Vec::new();
    if commands.iter().any(|cmd| cmd.new != zero) {
        let news: Vec<Oid> = commands
            .iter()
            .filter(|cmd| cmd.new != zero)
            .map(|cmd| cmd.new)
            .collect();
        match ingest_and_verify(pkt.get_mut(), store, kind, &news, limits.ingest, interrupt) {
            Ok((pack, commit_facts)) => {
                staged = Some(pack);
                facts = commit_facts;
            }
            Err(err) => {
                let reason = sanitize(&err.to_string());
                send_report(&mut writer, Some(&reason), &all_ng(&commands, &reason))?;
                return Err(err);
            }
        }
    }
    // LFS policy gate over what the pack introduces: under `Deny` a
    // pointer blob refuses exactly the live ref updates reaching it, with
    // the same in-band `ng` shape as hook refusals. The verdicts land
    // before quarantine staging so hooks and the CAS path skip refused
    // refs; the staged objects still publish unreachable afterwards, the
    // way hook refusals leave unreferenced objects behind.
    if let Some(staged_pack) = staged.as_ref() {
        let live_tips: Vec<(usize, Oid)> = live
            .iter()
            .map(|(index, update)| (*index, update.new))
            .collect();
        match refusals_for_live(staged_pack, kind, lfs, &live_tips, interrupt) {
            Ok(refusals) => {
                for (index, reason) in refusals {
                    results[index] = Some(Err(reason));
                }
            }
            Err(err) => {
                let reason = sanitize(&err.to_string());
                send_report(&mut writer, Some(&reason), &all_ng(&commands, &reason))?;
                return Err(err);
            }
        }
    }
    // Quarantine staging for hook inspection. A materialization failure is
    // infrastructure, not a hook verdict: every ref reports `ng` and the
    // error propagates, with the unpack line still `ok`.
    let quarantine = match stage_quarantine(policy.quarantine_parent(), staged.as_ref()) {
        Ok(quarantine) => quarantine,
        Err(err) => {
            let reason = sanitize(&err.to_string());
            send_report(&mut writer, None, &all_ng(&commands, &reason))?;
            return Err(err);
        }
    };
    interrupt.check("running receive hooks")?;
    // One policy call judges every wire command: script hooks run the
    // historical phases byte for byte (`pre-receive` observes every
    // command exactly as sent), other policies answer directly. The
    // verdicts travel in-band with `unpack ok`; only the return stays
    // `Ok`, exactly like CAS rejections below. Verdicts already recorded
    // (duplicates, malformed names) are never overwritten.
    let live_flags: Vec<bool> = {
        let mut flags = vec![false; commands.len()];
        for (index, _) in &live {
            flags[*index] = true;
        }
        flags
    };
    let policy_commands: Vec<ReceiveCommand> = commands
        .iter()
        .zip(live_flags)
        .map(|(cmd, live)| ReceiveCommand {
            name: cmd.name.clone(),
            old: cmd.old,
            new: cmd.new,
            live,
        })
        .collect();
    // Push facts for the callback: staged object bytes plus the new
    // commit tips (staged commits first, then command tips already in
    // the store), deduplicated.
    let mut pack_bytes: u64 = 0;
    let mut seen_commits: HashSet<Oid> = HashSet::new();
    let mut new_commits: Vec<Oid> = Vec::new();
    if let Some(staged_pack) = staged.as_ref() {
        for oid in staged_pack.oids() {
            if let Some((obj_kind, payload)) = staged_pack.payload(*oid) {
                pack_bytes = pack_bytes.saturating_add(payload.len() as u64);
                if obj_kind == ObjectKind::Commit && seen_commits.insert(*oid) {
                    new_commits.push(*oid);
                }
            }
        }
    }
    for cmd in &commands {
        if cmd.new != zero
            && seen_commits.insert(cmd.new)
            && let Ok(object) = store.read(cmd.new)
            && object.kind == ObjectKind::Commit
        {
            new_commits.push(cmd.new);
        }
    }
    let (new_commits, new_commits_truncated) = truncate_hook_commits(new_commits);
    let batch = ReceiveBatch {
        commands: &policy_commands,
        push_options: &push_options,
        push_options_negotiated: client_push_options,
        quarantine: quarantine.as_ref(),
        kind,
        atomic,
        interrupt,
        new_commits,
        new_commits_truncated,
        pack_bytes,
    };
    let mut alternates: Vec<(usize, AlternateRef)> = Vec::new();
    let verdicts = if atomic {
        for (index, _) in &live {
            if results[*index].is_none() {
                results[*index] = Some(Err("atomic pushes are not supported".to_owned()));
            }
        }
        Vec::new()
    } else {
        policy.pre_receive(&batch)
    };
    // A whole-push refusal drops the staging unpublished and returns
    // before promotion, mirroring the historical `pre-receive` early
    // return: refused objects must never enter the store.
    if let Some(reason) = verdicts.iter().find_map(|verdict| match verdict {
        RefVerdict::RejectPush { reason } => Some(reason.clone()),
        RefVerdict::Accept | RefVerdict::Reject { .. } | RefVerdict::Divert { .. } => None,
    }) {
        for (index, _) in &live {
            results[*index] = Some(Err(reason.clone()));
        }
        send_report(&mut writer, None, &report_rows(&commands, &results))?;
        return Ok(Vec::new());
    }
    let mut divert_writes: Vec<(usize, PushUpdate)> = Vec::new();
    for (command_index, verdict) in verdicts.into_iter().enumerate() {
        if results[command_index].is_some() {
            continue;
        }
        match verdict {
            RefVerdict::Accept => {}
            RefVerdict::Reject { reason } => results[command_index] = Some(Err(reason)),
            RefVerdict::RejectPush { reason } => results[command_index] = Some(Err(reason)),
            RefVerdict::Divert {
                alternate,
                write_through_cas,
            } => {
                if write_through_cas
                    && divert_writes
                        .iter()
                        .any(|(_, update)| update.name == alternate.refname)
                {
                    results[command_index] = Some(Err(format!(
                        "duplicate divert to review ref `{}`",
                        String::from_utf8_lossy(&alternate.refname)
                    )));
                    continue;
                }
                alternates.push((command_index, alternate.clone()));
                results[command_index] = Some(Ok(()));
                if write_through_cas {
                    // Hosted diverts land through the same CAS below:
                    // expect the review ref's current tip (or absence).
                    let cmd = &commands[command_index];
                    match RefName::new(alternate.refname.clone()) {
                        Ok(name) => match StoreRefs::new(store).get(&name) {
                            Ok(tip) => {
                                let old = match tip {
                                    Some(RefTarget::Direct(oid)) => oid,
                                    _ => kind.zero_oid(),
                                };
                                divert_writes.push((
                                    command_index,
                                    PushUpdate {
                                        name: alternate.refname.clone(),
                                        old,
                                        new: cmd.new,
                                    },
                                ));
                            }
                            Err(err) => {
                                results[command_index] = Some(Err(format!(
                                    "review ref unreadable: {}",
                                    sanitize(&err.to_string())
                                )));
                                alternates.retain(|(i, _)| *i != command_index);
                            }
                        },
                        Err(_) => {
                            results[command_index] =
                                Some(Err("review ref name is malformed".to_owned()));
                            alternates.retain(|(i, _)| *i != command_index);
                        }
                    }
                }
            }
        }
    }
    // Promote staged objects plus their commit rows in one publication.
    // This runs even when every ref was refused: the oracle migrates the
    // quarantine directory regardless of per-ref outcomes, and unreferenced
    // objects simply stay unreachable.
    if let Some(pack) = staged
        && let Err(err) = store.publish(
            pack.into_objects(),
            &facts,
            EventSource::ReceivePack,
            &context,
        )
    {
        let err = GitError::from(err);
        let reason = sanitize(&err.to_string());
        send_report(&mut writer, Some(&reason), &all_ng(&commands, &reason))?;
        return Err(err);
    }
    // Only hook-surviving refs reach the CAS path; hook verdicts already
    // recorded above are never overwritten. Fall-through refs rejoined the
    // undecided set with their `update` verdict recorded, so they apply
    // through the same path as ordinary refs. Landed refs contribute
    // their event sequences, which identify this push's operations.
    let survivors: Vec<&PushUpdate> = live
        .iter()
        .filter(|(index, _)| results[*index].is_none())
        .map(|(_, update)| update)
        .collect();
    let mut operation_ids: Vec<u64> = Vec::new();
    if !atomic && !survivors.is_empty() {
        match apply_refs(store, kind, &survivors, false, on_behalf_of) {
            Ok((outcomes, ref_events)) => {
                for outcome in &outcomes {
                    if let Some((index, _)) =
                        live.iter().find(|(_, update)| update.name == outcome.name)
                    {
                        results[*index] = Some(match &outcome.result {
                            RefResult::Ok => Ok(()),
                            RefResult::Rejected { reason } => Err(reason.clone()),
                        });
                        if matches!(outcome.result, RefResult::Ok)
                            && let Some(event) =
                                ref_events.iter().find(|event| event.name == outcome.name)
                        {
                            operation_ids.push(event.seq);
                        }
                    }
                }
            }
            Err(err) => {
                let reason = sanitize(&err.to_string());
                for result in results.iter_mut().filter(|result| result.is_none()) {
                    *result = Some(Err(format!("ref update failed: {reason}")));
                }
                for (command_index, _) in &divert_writes {
                    results[*command_index] = Some(Err(format!("ref update failed: {reason}")));
                    alternates.retain(|(i, _)| i != command_index);
                }
                send_report(&mut writer, None, &report_rows(&commands, &results))?;
                return Err(err);
            }
        }
    }
    // Hosted diverts write their review refs through the same CAS: the
    // provisional `ok` above confirms only after the review ref lands.
    if !divert_writes.is_empty() {
        let updates: Vec<&PushUpdate> = divert_writes.iter().map(|(_, update)| update).collect();
        match apply_refs(store, kind, &updates, false, on_behalf_of) {
            Ok((outcomes, ref_events)) => {
                for outcome in &outcomes {
                    if let Some(position) = divert_writes
                        .iter()
                        .position(|(_, update)| update.name == outcome.name)
                    {
                        let (command_index, _) = &divert_writes[position];
                        let command_index = *command_index;
                        match &outcome.result {
                            RefResult::Ok => {
                                if let Some(event) =
                                    ref_events.iter().find(|event| event.name == outcome.name)
                                {
                                    operation_ids.push(event.seq);
                                }
                            }
                            RefResult::Rejected { reason } => {
                                results[command_index] = Some(Err(reason.clone()));
                                alternates.retain(|(i, _)| *i != command_index);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                let reason = sanitize(&err.to_string());
                for (command_index, _) in &divert_writes {
                    results[*command_index] =
                        Some(Err(format!("review ref update failed: {reason}")));
                    alternates.retain(|(i, _)| i != command_index);
                }
                send_report(&mut writer, None, &report_rows(&commands, &results))?;
                return Err(err);
            }
        }
    }
    // `post-receive` over the landed refs, after refs are updated. Its
    // failure relays to server diagnostics and never fails the push:
    // protocol v0's report has no sideband slot for it. The hosted
    // policy only stashes the callback here; the daemon pumps it after
    // the receipt write and the report delivery, never before. Diverted
    // commands the hook accepted arrive under their review ref: the hook
    // performed the write itself, so the landed line names the
    // hook-supplied refname (with the hook-supplied OIDs when present),
    // not the original `refs/for/` name.
    let landed: String = live
        .iter()
        .filter(|(index, _)| matches!(results[*index], Some(Ok(()))))
        .map(|(index, update)| {
            if let Some((_, alternate)) = alternates.iter().find(|(i, _)| i == index) {
                return alternate_line(alternate, update.old, update.new);
            }
            let cmd = commands
                .iter()
                .find(|cmd| cmd.name == update.name)
                .expect("live update names a command");
            hook_line(cmd)
        })
        .collect();
    if !landed.is_empty() && interrupt.check("running post-receive hook").is_ok() {
        policy.post_receive(&LandedRefs {
            lines: &landed,
            push_options: &push_options,
            push_options_negotiated: client_push_options,
            quarantine: quarantine.as_ref(),
        });
    }
    send_report(&mut writer, None, &report_rows(&commands, &results))?;
    Ok(operation_ids)
}

/// Cap of commit tips listed on one hook call: the first entries travel
/// with the truncation flag instead of refusing past ~390k commits, when
/// the HookCall would pass the 16 MiB control bound. The hook judges
/// tips; full history stays readable from the store.
pub(crate) const MAX_HOOK_NEW_COMMITS: usize = 1024;

/// Keeps the first entries of a hook commit list with a truncation flag.
fn truncate_hook_commits(commits: Vec<Oid>) -> (Vec<Oid>, bool) {
    if commits.len() > MAX_HOOK_NEW_COMMITS {
        let mut commits = commits;
        commits.truncate(MAX_HOOK_NEW_COMMITS);
        (commits, true)
    } else {
        (commits, false)
    }
}

/// Collects per-ref verdicts in command order; every command has one by the
/// time any report sends.
fn report_rows(
    commands: &[Command],
    results: &[Option<Result<(), String>>],
) -> Vec<(Vec<u8>, Result<(), String>)> {
    commands
        .iter()
        .zip(results.iter())
        .map(|(cmd, result)| {
            (
                cmd.name.clone(),
                result.clone().expect("every command has a verdict"),
            )
        })
        .collect()
}

/// Routes one server-side command to its serve half (protocol v0).
///
/// `name` is the bare command (`upload-pack`, `receive-pack`,
/// `upload-archive`); the per-command grammars stay with their owners.
/// The `upload-archive` arm serves `git archive --remote` through
/// [`super::archive::serve_upload_archive`].
///
/// # Errors
/// [`GitError::Unsupported`] for an unknown command, plus each half's own
/// failures.
#[expect(
    clippy::too_many_arguments,
    reason = "row-mandated serve entry: command routing plus the receive policy"
)]
pub fn serve_command<R: Read, W: Write>(
    name: &str,
    reader: R,
    writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
    policy: &dyn ReceivePolicy,
) -> Result<(), GitError> {
    match name {
        "upload-pack" => serve_upload_pack(reader, writer, store, kind, head, interrupt),
        // No repository directory travels with a bare command dispatch, so
        // no policy file is readable: fail closed to pointer refusal.
        "receive-pack" => serve_receive_pack_with(ReceivePackParams {
            reader,
            writer,
            store,
            kind,
            head,
            interrupt,
            policy,
            lfs: LfsMode::Deny,
            limits: ReceiveLimits::default(),
            on_behalf_of: None,
        })
        .map(|_| ()),
        "upload-archive" => {
            super::archive::serve_upload_archive(reader, writer, store, kind, head, interrupt)
        }
        other => Err(GitError::Unsupported {
            command: format!("unknown serve command {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::hooks::ReceiveHooks;
    use super::super::policy::{
        LandedRefs, NoPolicy, ReceiveBatch, ReceivePolicy, RefVerdict, ScriptPolicy,
    };
    use super::super::refadv::{Initial, read_initial};
    use super::super::session::test_support::{store_with_pack, test_store};
    use super::*;
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTransaction, RefUpdate};
    use ruk_core::refs::{StoreRefs, prepare_checked_transaction};

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    const THREE: &str = "7a4943e466a7ce4f4c56d9eeb89c8909b1c43d22";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn default_divert_prefixes_are_refs_for_only() {
        assert_eq!(
            ReceiveHooks::disabled().proc_receive_prefixes(),
            &["refs/for".to_owned()],
            "the documented default diverts refs/for only; refs/pull lands plain"
        );
    }

    #[test]
    fn hook_commit_list_truncates_past_1024() {
        let commits: Vec<Oid> = (0..MAX_HOOK_NEW_COMMITS)
            .map(|n| oid(&format!("{n:040x}")))
            .collect();
        let (kept, truncated) = truncate_hook_commits(commits);
        assert_eq!(kept.len(), MAX_HOOK_NEW_COMMITS);
        assert!(!truncated);

        let commits: Vec<Oid> = (0..=MAX_HOOK_NEW_COMMITS)
            .map(|n| oid(&format!("{n:040x}")))
            .collect();
        assert_eq!(commits.len(), MAX_HOOK_NEW_COMMITS + 1);
        let (kept, truncated) = truncate_hook_commits(commits);
        assert_eq!(kept.len(), MAX_HOOK_NEW_COMMITS);
        assert!(truncated);
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
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish ref");
    }

    fn server_store() -> Store {
        let kind = HashKind::Sha1;
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        set_ref(&store, kind, b"refs/heads/main", oid(FOUR));
        store
    }

    fn framed(line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_data(&mut out, line).expect("frame");
        out
    }

    /// Skips the advertisement and NAK lines of a serve transcript,
    /// returning the pack bytes that follow.
    fn pack_of(out: &[u8], kind: HashKind) -> Vec<u8> {
        let mut pkt = PktReader::new(out, Interrupt::none());
        match read_initial(&mut pkt, kind).expect("advertisement parses") {
            Initial::Refs(_) => {}
            Initial::V2(_) => panic!("unexpected v2 advertisement"),
        }
        assert_eq!(
            pkt.read_line("first verdict").expect("NAK").to_vec(),
            b"NAK"
        );
        assert_eq!(
            pkt.read_line("second verdict").expect("NAK").to_vec(),
            b"NAK"
        );
        pkt.get_mut()[..].to_vec()
    }

    fn serve_upload(input: &[u8], store: &Store, kind: HashKind) -> Vec<u8> {
        let mut out = Vec::new();
        serve_upload_pack(input, &mut out, store, kind, &head(), &Interrupt::none())
            .expect("serve");
        out
    }

    #[test]
    fn upload_serves_wants_minus_haves() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let mut input = Vec::new();
        input.extend_from_slice(&framed(
            format!("want {FOUR} multi_ack_detailed ofs-delta agent=test\n").as_bytes(),
        ));
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&framed(format!("have {THREE}\n").as_bytes()));
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&framed(b"done\n"));

        let out = serve_upload(&input, &store, kind);

        // The advertisement round-trips through the client's own parser.
        let mut adv = PktReader::new(&out[..], Interrupt::none());
        match read_initial(&mut adv, kind).expect("advertisement") {
            Initial::Refs(adv) => {
                assert!(adv.capabilities.has("multi_ack"));
                assert!(adv.capabilities.has("ofs-delta"));
                assert!(!adv.capabilities.has("thin-pack"));
                assert!(!adv.capabilities.has("side-band-64k"));
                let main = adv
                    .refs
                    .iter()
                    .find(|r| r.name == b"refs/heads/main")
                    .expect("main advertised");
                assert_eq!(main.oid, Some(oid(FOUR)));
            }
            Initial::V2(_) => panic!("unexpected v2"),
        }
        // The client offered THREE as a have, so the pack carries FOUR
        // without its already-held parent.
        let pack = pack_of(&out, kind);
        let dest = test_store(kind);
        let staged = ingest_pack(
            &pack[..],
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("pack ingests");
        assert!(staged.contains(oid(FOUR)));
        assert!(!staged.contains(oid(THREE)));
    }

    #[test]
    fn upload_serves_the_full_closure_without_haves() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let mut input = Vec::new();
        input.extend_from_slice(&framed(
            format!("want {FOUR} multi_ack_detailed agent=test\n").as_bytes(),
        ));
        input.extend_from_slice(b"0000");
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&framed(b"done\n"));

        let out = serve_upload(&input, &store, kind);
        let pack = pack_of(&out, kind);
        let dest = test_store(kind);
        let staged = ingest_pack(
            &pack[..],
            kind,
            &dest,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("pack ingests");
        verify_closure(&dest, &staged, &[oid(FOUR)], None, &[], &Interrupt::none())
            .expect("closure verifies");
    }

    #[test]
    fn upload_rejects_unknown_want() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let unknown = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let mut input = Vec::new();
        input.extend_from_slice(&framed(format!("want {unknown}\n").as_bytes()));
        input.extend_from_slice(b"0000");
        let mut out = Vec::new();
        let err = serve_upload_pack(
            &input[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("unknown want");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn upload_rejects_protocol_v2() {
        let kind = HashKind::Sha1;
        let store = server_store();
        let mut input = Vec::new();
        input.extend_from_slice(&framed(b"version 2\n"));
        let mut out = Vec::new();
        let err = serve_upload_pack(
            &input[..],
            &mut out,
            &store,
            kind,
            &head(),
            &Interrupt::none(),
        )
        .expect_err("v2");
        assert!(matches!(err, GitError::Unsupported { .. }), "got {err:?}");
    }

    #[test]
    fn upload_advertises_empty_repository() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let head = HeadAdvertisement {
            oid: kind.zero_oid(),
            symref: Some(b"refs/heads/main".to_vec()),
        };
        let mut out = Vec::new();
        // No wants: an empty want list still answers the have round and an
        // empty pack, so an empty clone stays in sync.
        let mut input = Vec::new();
        input.extend_from_slice(b"0000");
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&framed(b"done\n"));
        serve_upload_pack(
            &input[..],
            &mut out,
            &store,
            kind,
            &head,
            &Interrupt::none(),
        )
        .expect("serve");
        let mut pkt = PktReader::new(&out[..], Interrupt::none());
        match read_initial(&mut pkt, kind).expect("advertisement") {
            Initial::Refs(adv) => {
                assert!(adv.refs.is_empty());
            }
            Initial::V2(_) => panic!("unexpected v2"),
        }
    }

    fn push_pack(src: &Store, kind: HashKind, old: Oid, new: Oid, name: &[u8]) -> Vec<u8> {
        use super::super::push::push_closure;
        let update = PushUpdate {
            name: name.to_vec(),
            old,
            new,
        };
        let live = vec![&update];
        let entries = push_closure(src, kind, &live, &Interrupt::none()).expect("closure");
        let pack_entries = entries
            .iter()
            .map(super::super::push::ClosureObject::as_entry)
            .collect::<Vec<_>>();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, &Interrupt::none()).expect("pack");
        pack
    }

    fn command(old: Oid, new: Oid, name: &[u8], caps: Option<&str>) -> Vec<u8> {
        let mut line = format!(
            "{} {} {}",
            old.to_hex(),
            new.to_hex(),
            String::from_utf8_lossy(name)
        );
        if let Some(caps) = caps {
            line.push('\0');
            line.push_str(caps);
        }
        line.push('\n');
        framed(line.as_bytes())
    }

    fn blob_oid(data: &[u8]) -> Oid {
        HashKind::Sha1
            .hash_git_object("blob", data)
            .expect("blob hashes")
    }

    fn tree_for_blob(name: &[u8], blob: Oid) -> (Vec<u8>, Oid) {
        let mut bytes = format!("100644 {}\0", String::from_utf8_lossy(name)).into_bytes();
        bytes.extend_from_slice(blob.as_bytes());
        let oid = HashKind::Sha1
            .hash_git_object("tree", &bytes)
            .expect("tree hashes");
        (bytes, oid)
    }

    fn commit_for_tree(tree: Oid) -> (Vec<u8>, Oid) {
        let body = format!(
            "tree {}\nauthor T <t@t.invalid> 0 +0000\ncommitter T <t@t.invalid> 0 +0000\n\nlimits\n",
            tree.to_hex()
        );
        let bytes = body.into_bytes();
        let oid = HashKind::Sha1
            .hash_git_object("commit", &bytes)
            .expect("commit hashes");
        (bytes, oid)
    }

    fn limit_pack() -> (Vec<u8>, Oid, usize) {
        limit_pack_with(0)
    }

    fn limit_pack_with(seed: u8) -> (Vec<u8>, Oid, usize) {
        let blob: Vec<u8> = (0..1000)
            .map(|i| ((i + usize::from(seed) * 131) % 251) as u8)
            .collect();
        let blob_id = blob_oid(&blob);
        let (tree_bytes, tree_id) = tree_for_blob(b"f", blob_id);
        let (commit_bytes, commit_id) = commit_for_tree(tree_id);
        let entries = [
            PackEntry {
                oid: commit_id,
                kind: ObjectKind::Commit,
                bytes: &commit_bytes,
                base: None,
            },
            PackEntry {
                oid: tree_id,
                kind: ObjectKind::Tree,
                bytes: &tree_bytes,
                base: None,
            },
            PackEntry {
                oid: blob_id,
                kind: ObjectKind::Blob,
                bytes: &blob,
                base: None,
            },
        ];
        let mut pack = Vec::new();
        write_pack(&mut pack, HashKind::Sha1, &entries, &Interrupt::none()).expect("pack");
        (pack, commit_id, blob.len())
    }

    fn pack_stats(pack: &[u8]) -> (u64, u64, u64) {
        use gix_pack::data::input::{BytesToEntriesIter, EntryDataMode, Mode};
        let mut stream = pack;
        let iter = BytesToEntriesIter::new_from_header(
            &mut stream,
            Mode::Verify,
            EntryDataMode::Keep,
            HashKind::Sha1.gix(),
        )
        .expect("pack parses");
        let mut count = 0u64;
        let mut largest = 0u64;
        let mut compressed = 0u64;
        for item in iter {
            let entry = item.expect("entry parses");
            count += 1;
            largest = largest.max(entry.decompressed_size);
            compressed = compressed.saturating_add(entry.compressed_size);
        }
        (count, largest, compressed)
    }

    fn serve_push_with_limits(
        dest: &Store,
        new: Oid,
        pack: &[u8],
        limits: ReceiveLimits,
    ) -> Result<Vec<u64>, GitError> {
        let kind = HashKind::Sha1;
        let mut input = command(
            kind.zero_oid(),
            new,
            b"refs/heads/main",
            Some("report-status"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(pack);
        let mut out = Vec::new();
        serve_receive_pack_with(ReceivePackParams {
            reader: &input[..],
            writer: &mut out,
            store: dest,
            kind,
            head: &head(),
            interrupt: &Interrupt::none(),
            policy: &NoPolicy,
            lfs: LfsMode::Deny,
            limits,
            on_behalf_of: None,
        })
    }

    fn with_ingest(f: impl Fn(IngestLimits) -> IngestLimits) -> ReceiveLimits {
        ReceiveLimits {
            ingest: f(IngestLimits::default()),
            ..ReceiveLimits::default()
        }
    }

    fn report_lines(mut out: &[u8]) -> Vec<Vec<u8>> {
        let mut pkt = PktReader::new(&mut out, Interrupt::none());
        match read_initial(&mut pkt, HashKind::Sha1).expect("advertisement") {
            Initial::Refs(_) => {}
            Initial::V2(_) => panic!("unexpected v2"),
        }
        let mut lines = Vec::new();
        loop {
            let packet = pkt.read_packet().expect("frame");
            match packet {
                Packet::Flush => break,
                Packet::Data(_) => lines.push(packet.line().unwrap_or_default().to_vec()),
                other => panic!("unexpected {other:?}"),
            }
        }
        lines
    }

    #[test]
    fn receive_applies_branch_create() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");
        let mut input = command(
            kind.zero_oid(),
            oid(FOUR),
            b"refs/heads/main",
            Some("report-status delete-refs ofs-delta agent=test"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&pack);

        let mut out = Vec::new();
        serve_receive_pack(
            &input[..],
            &mut out,
            &dest,
            kind,
            &head(),
            &Interrupt::none(),
            LfsMode::Deny,
        )
        .expect("serve");
        let lines = report_lines(&out);
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert!(super::super::has_object(&dest, oid(FOUR)).expect("object landed"));
    }

    #[test]
    fn receive_delete_only_skips_the_pack() {
        let kind = HashKind::Sha1;
        let dest = server_store();
        let mut input = command(
            oid(FOUR),
            kind.zero_oid(),
            b"refs/heads/main",
            Some("report-status"),
        );
        input.extend_from_slice(b"0000");
        // No pack bytes follow: the server must not try to ingest one.

        let mut out = Vec::new();
        serve_receive_pack(
            &input[..],
            &mut out,
            &dest,
            kind,
            &head(),
            &Interrupt::none(),
            LfsMode::Deny,
        )
        .expect("serve");
        let lines = report_lines(&out);
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
    }

    #[test]
    fn receive_stale_old_reports_ng_like_stock() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = server_store();
        // The client saw THREE but the server is at FOUR, which is also
        // the desired tip: stock receive-pack still answers `ng` for the
        // stale expectation. Only an exact receipt replay (same request
        // id, same digest) returns the stored report; that path never
        // reaches `apply_refs`.
        let pack = push_pack(&src, kind, oid(THREE), oid(FOUR), b"refs/heads/main");
        let mut input = command(
            oid(THREE),
            oid(FOUR),
            b"refs/heads/main",
            Some("report-status"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&pack);

        let mut out = Vec::new();
        serve_receive_pack(
            &input[..],
            &mut out,
            &dest,
            kind,
            &head(),
            &Interrupt::none(),
            LfsMode::Deny,
        )
        .expect("serve reports outcomes in-band");
        let lines = report_lines(&out);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok".to_vec());
        assert!(
            lines[1].starts_with(b"ng refs/heads/main "),
            "stale old must report ng, got {:?}",
            String::from_utf8_lossy(&lines[1])
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
    }

    /// Accepts every command, atomic included: the serve-level atomic
    /// refusal must fire before any policy verdict, so this test fails
    /// on code that leaves the refusal to the policies (both shipped
    /// policies refuse atomic themselves, which would mask a missing
    /// serve-level rule).
    struct AcceptAtomic {
        pre_receive_calls: std::sync::atomic::AtomicUsize,
    }

    impl ReceivePolicy for AcceptAtomic {
        fn needs_quarantine(&self) -> bool {
            false
        }

        fn quarantine_parent(&self) -> Option<std::path::PathBuf> {
            None
        }

        fn pre_receive(&self, batch: &ReceiveBatch<'_>) -> Vec<RefVerdict> {
            self.pre_receive_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            batch.commands.iter().map(|_| RefVerdict::Accept).collect()
        }

        fn post_receive(&self, _landed: &LandedRefs<'_>) {}
    }

    #[test]
    fn receive_refuses_atomic_without_hooks() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");
        let mut input = command(
            kind.zero_oid(),
            oid(FOUR),
            b"refs/heads/main",
            Some("report-status atomic"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&pack);

        let policy = AcceptAtomic {
            pre_receive_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let mut out = Vec::new();
        serve_receive_pack_with(ReceivePackParams {
            reader: &input[..],
            writer: &mut out,
            store: &dest,
            kind,
            head: &head(),
            interrupt: &Interrupt::none(),
            policy: &policy,
            lfs: LfsMode::Deny,
            limits: ReceiveLimits::default(),
            on_behalf_of: None,
        })
        .expect("atomic refusal stays in-band");
        assert_eq!(
            policy
                .pre_receive_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the serve-level refusal runs before any policy verdict"
        );
        let lines = report_lines(&out);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok");
        assert!(
            lines[1].starts_with(b"ng refs/heads/main atomic pushes are not supported"),
            "got {lines:?}"
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), None);
    }

    #[test]
    fn receive_rejects_a_moved_ref() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = server_store();
        // The client saw THREE and re-sets THREE, but the server already
        // moved to FOUR: the tip matches neither the expectation nor the
        // desire, so the CAS still refuses.
        let pack = push_pack(&src, kind, oid(THREE), oid(FOUR), b"refs/heads/main");
        let mut input = command(
            oid(THREE),
            oid(THREE),
            b"refs/heads/main",
            Some("report-status"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(&pack);

        let mut out = Vec::new();
        serve_receive_pack(
            &input[..],
            &mut out,
            &dest,
            kind,
            &head(),
            &Interrupt::none(),
            LfsMode::Deny,
        )
        .expect("serve reports rejections in-band");
        let lines = report_lines(&out);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok");
        assert!(
            lines[1].starts_with(b"ng refs/heads/main "),
            "got {:?}",
            lines[1]
        );
    }

    #[test]
    fn receive_reports_unpack_failures() {
        let kind = HashKind::Sha1;
        let dest = test_store(kind);
        let mut input = command(
            kind.zero_oid(),
            oid(FOUR),
            b"refs/heads/main",
            Some("report-status"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(b"NOTAPACK");

        let mut out = Vec::new();
        let err = serve_receive_pack(
            &input[..],
            &mut out,
            &dest,
            kind,
            &head(),
            &Interrupt::none(),
            LfsMode::Deny,
        )
        .expect_err("garbage pack");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
        let lines = report_lines(&out);
        assert!(lines[0].starts_with(b"unpack "), "got {:?}", lines[0]);
        assert!(
            lines[1].starts_with(b"ng refs/heads/main "),
            "got {:?}",
            lines[1]
        );
    }

    const POINTER_BLOB: &[u8] = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n";

    /// A source store holding one commit whose tree carries a Git LFS
    /// pointer blob, returning the commit tip.
    fn pointer_tip(src: &Store, kind: HashKind) -> Oid {
        use ruk_core::store::types::ObjectKind;
        let blob = src
            .prepare(
                ObjectKind::Blob,
                POINTER_BLOB.len() as u64,
                POINTER_BLOB,
                None,
            )
            .expect("pointer blob");
        let blob_oid = blob.oid();
        let mut tree = b"100644 asset.bin\0".to_vec();
        tree.extend_from_slice(blob_oid.as_bytes());
        let tree_oid = kind.hash_git_object("tree", &tree).expect("tree id");
        let tree_prepared = src
            .prepare(ObjectKind::Tree, tree.len() as u64, &tree[..], None)
            .expect("tree");
        assert_eq!(tree_prepared.oid(), tree_oid);
        let commit = format!(
            "tree {}\nauthor T <t@example.invalid> 0 +0000\ncommitter T <t@example.invalid> 0 +0000\n\npointer\n",
            tree_oid.to_hex()
        );
        let commit_prepared = src
            .prepare(
                ObjectKind::Commit,
                commit.len() as u64,
                commit.as_bytes(),
                None,
            )
            .expect("commit");
        let tip = commit_prepared.oid();
        src.publish(
            vec![blob, tree_prepared, commit_prepared],
            &[],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish pointer commit");
        tip
    }

    fn serve_push_with_mode(
        dest: &Store,
        kind: HashKind,
        pack: &[u8],
        new: Oid,
        mode: LfsMode,
    ) -> Vec<Vec<u8>> {
        let mut input = command(
            kind.zero_oid(),
            new,
            b"refs/heads/main",
            Some("report-status delete-refs ofs-delta agent=test"),
        );
        input.extend_from_slice(b"0000");
        input.extend_from_slice(pack);
        let mut out = Vec::new();
        serve_receive_pack_with(ReceivePackParams {
            reader: &input[..],
            writer: &mut out,
            store: dest,
            kind,
            head: &head(),
            interrupt: &Interrupt::none(),
            policy: &NoPolicy,
            lfs: mode,
            limits: ReceiveLimits::default(),
            on_behalf_of: None,
        })
        .expect("serve reports refusals in-band");
        report_lines(&out)
    }

    #[test]
    fn receive_refuses_pointer_push_under_deny() {
        let kind = HashKind::Sha1;
        let src = test_store(kind);
        let tip = pointer_tip(&src, kind);
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), tip, b"refs/heads/main");
        let lines = serve_push_with_mode(&dest, kind, &pack, tip, LfsMode::Deny);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok");
        assert!(
            lines[1].starts_with(b"ng refs/heads/main "),
            "got {:?}",
            lines[1]
        );
        assert!(
            String::from_utf8_lossy(&lines[1]).contains("E_UNSUPPORTED_LFS"),
            "the refusal names the policy code: got {:?}",
            lines[1]
        );
    }

    #[test]
    fn receive_records_pointer_bytes_under_pointers_mode() {
        let kind = HashKind::Sha1;
        let src = test_store(kind);
        let tip = pointer_tip(&src, kind);
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), tip, b"refs/heads/main");
        let lines = serve_push_with_mode(&dest, kind, &pack, tip, LfsMode::Pointers);
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert!(
            super::super::has_object(&dest, tip).expect("pointer commit landed"),
            "pointers mode records the bytes plainly"
        );
    }

    #[test]
    fn receive_records_pointer_bytes_under_full_mode_without_payload() {
        let kind = HashKind::Sha1;
        let src = test_store(kind);
        let tip = pointer_tip(&src, kind);
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), tip, b"refs/heads/main");
        let lines = serve_push_with_mode(&dest, kind, &pack, tip, LfsMode::Full);
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert!(
            super::super::has_object(&dest, tip).expect("pointer commit landed"),
            "full mode records the pointer with no payload present"
        );
    }

    static HOOK_TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh repository directory holding `hooks/`, unique per test.
    fn hook_repo() -> std::path::PathBuf {
        use std::sync::atomic::Ordering;
        let id = HOOK_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ruk-hook-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(dir.join("hooks")).expect("hooks dir");
        dir
    }

    /// Writes an executable `hooks/<name>` shell script.
    fn write_hook(repo: &std::path::Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = repo.join("hooks").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("hook script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("hook executable");
    }

    /// Serves one branch-create push through `hooks`, returning the report
    /// lines.
    fn serve_push_with_hooks(
        dest: &Store,
        kind: HashKind,
        updates: &[(Oid, Oid, &[u8])],
        pack: &[u8],
        policy: &dyn ReceivePolicy,
    ) -> Vec<Vec<u8>> {
        serve_push_raw(
            dest,
            kind,
            updates,
            "report-status delete-refs ofs-delta agent=test",
            &[],
            pack,
            policy,
        )
    }

    /// Serves one push whose first command carries `first_caps`, with raw
    /// `middle` bytes (push-option frames) between the commands flush and
    /// the pack, returning the report lines.
    fn pack_header_entry(type_id: u8, size: u64) -> Vec<u8> {
        let mut first = (type_id << 4) | ((size & 0x0f) as u8);
        let mut rest = size >> 4;
        if rest != 0 {
            first |= 0x80;
        }
        let mut out = vec![first];
        while rest != 0 {
            let mut byte = (rest & 0x7f) as u8;
            rest >>= 7;
            if rest != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
        out
    }

    fn pack_ofs_distance(distance: u64) -> Vec<u8> {
        let mut parts = vec![(distance & 127) as u8];
        let mut rest = distance >> 7;
        while rest > 0 {
            rest -= 1;
            parts.push(0x80 | ((rest & 127) as u8));
            rest >>= 7;
        }
        parts.reverse();
        parts
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write as _;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("deflate");
        encoder.finish().expect("finish")
    }

    fn delta_chain_pack() -> (Vec<u8>, Oid) {
        let base: Vec<u8> = (0..2000).map(|i| (i % 251) as u8).collect();
        let mut mid = base.clone();
        for byte in &mut mid[1000..1010] {
            *byte = byte.wrapping_add(1);
        }
        let mut tip = mid.clone();
        for byte in &mut tip[500..510] {
            *byte = byte.wrapping_add(2);
        }
        let tip_id = blob_oid(&tip);
        let (tree_bytes, tree_id) = tree_for_blob(b"f", tip_id);
        let (commit_bytes, commit_id) = commit_for_tree(tree_id);
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&5u32.to_be_bytes());
        let mut entry_offsets = Vec::new();
        for (type_id, bytes) in [
            (1u8, commit_bytes.as_slice()),
            (2u8, tree_bytes.as_slice()),
            (3u8, base.as_slice()),
        ] {
            entry_offsets.push(pack.len() as u64);
            pack.extend_from_slice(&pack_header_entry(type_id, bytes.len() as u64));
            pack.extend_from_slice(&zlib(bytes));
        }
        let mut base_offset = entry_offsets[2];
        for (from, to) in [(&base, &mid), (&mid, &tip)] {
            let delta = super::super::pack::encode_delta(from, to);
            let entry_offset = pack.len() as u64;
            pack.extend_from_slice(&pack_header_entry(6, delta.len() as u64));
            pack.extend_from_slice(&pack_ofs_distance(entry_offset - base_offset));
            pack.extend_from_slice(&zlib(&delta));
            base_offset = entry_offset;
        }
        let mut hasher = gix_hash::hasher(HashKind::Sha1.gix());
        hasher.update(&pack);
        let trailer = hasher.try_finalize().expect("pack hashes");
        pack.extend_from_slice(trailer.as_bytes());
        (pack, commit_id)
    }

    #[test]
    fn receive_limits_refuse_extra_objects() {
        let (pack, commit, _) = limit_pack();
        let (count, _, _) = pack_stats(&pack);
        assert_eq!(count, 3, "the limit pack holds commit, tree, and blob");
        for (limit, accepted) in [(count - 1, false), (count, true), (count + 1, true)] {
            let dest = test_store(HashKind::Sha1);
            let result = serve_push_with_limits(
                &dest,
                commit,
                &pack,
                with_ingest(|ingest| IngestLimits {
                    max_objects: limit,
                    ..ingest
                }),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "object quota {limit} decides the three-object push"
            );
            if accepted {
                assert_eq!(result.expect("accepted push lands").len(), 1);
            } else {
                assert!(
                    matches!(result, Err(GitError::Limit { .. })),
                    "over-quota push refuses with Limit"
                );
            }
        }
    }

    #[test]
    fn receive_limits_refuse_oversize_object() {
        let (pack, commit, blob_size) = limit_pack();
        let (_, largest, _) = pack_stats(&pack);
        assert_eq!(largest, blob_size as u64, "the blob is the largest entry");
        for (limit, accepted) in [(largest - 1, false), (largest, true), (largest + 1, true)] {
            let dest = test_store(HashKind::Sha1);
            let result = serve_push_with_limits(
                &dest,
                commit,
                &pack,
                with_ingest(|ingest| IngestLimits {
                    max_object_bytes: limit,
                    ..ingest
                }),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "object byte quota {limit} decides the push"
            );
            assert_eq!(
                matches!(result, Err(GitError::Limit { .. })),
                !accepted,
                "over-quota push refuses with Limit"
            );
        }
    }

    #[test]
    fn receive_limits_refuse_oversize_pack() {
        let (pack, commit, _) = limit_pack();
        let (_, _, compressed) = pack_stats(&pack);
        assert!(compressed > 0, "the pack carries compressed bytes");
        for (limit, accepted) in [
            (compressed.saturating_sub(1), false),
            (compressed, true),
            (compressed + 1, true),
        ] {
            let dest = test_store(HashKind::Sha1);
            let result = serve_push_with_limits(
                &dest,
                commit,
                &pack,
                with_ingest(|ingest| IngestLimits {
                    max_pack_bytes: limit,
                    ..ingest
                }),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "pack byte quota {limit} decides the push"
            );
            assert_eq!(
                matches!(result, Err(GitError::Limit { .. })),
                !accepted,
                "over-quota push refuses with Limit"
            );
        }
    }

    #[test]
    fn receive_limits_refuse_deep_delta_chain() {
        let (pack, commit) = delta_chain_pack();
        for (limit, accepted) in [(0, false), (1, true), (2, true)] {
            let dest = test_store(HashKind::Sha1);
            let result = serve_push_with_limits(
                &dest,
                commit,
                &pack,
                with_ingest(|ingest| IngestLimits {
                    max_delta_depth: limit,
                    ..ingest
                }),
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "delta depth quota {limit} decides the two-delta push"
            );
            if !accepted {
                let detail = format!("{}", result.expect_err("deep chain refuses"));
                assert!(
                    detail.contains("depth bound"),
                    "deep chain refuses on depth: {detail}"
                );
            }
        }
    }

    #[test]
    fn receive_limits_refuse_extra_push_options() {
        let (pack, commit, _) = limit_pack();
        let mut middle = Vec::new();
        for option in ["topic=f1", "foo=bar", "baz=qux"] {
            encode_data(&mut middle, option.as_bytes()).expect("frame");
        }
        middle.extend_from_slice(b"0000");
        for (limit, accepted) in [(2, false), (3, true), (4, true)] {
            let dest = test_store(HashKind::Sha1);
            let mut input = command(
                HashKind::Sha1.zero_oid(),
                commit,
                b"refs/heads/main",
                Some("report-status push-options"),
            );
            input.extend_from_slice(b"0000");
            input.extend_from_slice(&middle);
            input.extend_from_slice(&pack);
            let mut out = Vec::new();
            let result = serve_receive_pack_with(ReceivePackParams {
                reader: &input[..],
                writer: &mut out,
                store: &dest,
                kind: HashKind::Sha1,
                head: &head(),
                interrupt: &Interrupt::none(),
                policy: &NoPolicy,
                lfs: LfsMode::Deny,
                limits: ReceiveLimits {
                    max_push_options: limit,
                    ..ReceiveLimits::default()
                },
                on_behalf_of: None,
            });
            assert_eq!(
                result.is_ok(),
                accepted,
                "option cap {limit} decides the three-option push"
            );
            assert_eq!(
                matches!(result, Err(GitError::Limit { .. })),
                !accepted,
                "over-cap push refuses with Limit"
            );
        }
    }

    #[test]
    fn concurrent_identical_pushes_to_distinct_branches_all_land() {
        let kind = HashKind::Sha1;
        for count in [2usize, 4, 8] {
            let dest = test_store(kind);
            let (pack, commit, _) = limit_pack();
            let dest_ref = &dest;
            let pack_ref = &pack;
            let outcomes: Vec<(Vec<u64>, Vec<Vec<u8>>)> = std::thread::scope(|scope| {
                (0..count)
                    .map(|branch| {
                        scope.spawn(move || {
                            let name = format!("refs/heads/dup-{branch}");
                            let mut input = command(
                                kind.zero_oid(),
                                commit,
                                name.as_bytes(),
                                Some("report-status"),
                            );
                            input.extend_from_slice(b"0000");
                            input.extend_from_slice(pack_ref);
                            let mut out = Vec::new();
                            let seqs = serve_receive_pack_with(ReceivePackParams {
                                reader: &input[..],
                                writer: &mut out,
                                store: dest_ref,
                                kind,
                                head: &head(),
                                interrupt: &Interrupt::none(),
                                policy: &NoPolicy,
                                lfs: LfsMode::Deny,
                                limits: ReceiveLimits::default(),
                                on_behalf_of: None,
                            })
                            .expect("identical push lands");
                            (seqs, report_lines(&out))
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|handle| handle.join().expect("push thread"))
                    .collect()
            });
            assert_eq!(outcomes.len(), count);
            for (seqs, lines) in &outcomes {
                assert_eq!(seqs.len(), 1, "each push lands one ref event");
                assert!(
                    lines.iter().any(|line| line == b"unpack ok"),
                    "got {lines:?}"
                );
                assert!(
                    lines.iter().any(|line| line.starts_with(b"ok ")),
                    "got {lines:?}"
                );
            }
            for branch in 0..count {
                let name = format!("refs/heads/dup-{branch}");
                assert_eq!(
                    ref_oid(&dest, name.as_bytes()),
                    Some(commit),
                    "every branch holds the one commit"
                );
            }
        }
    }

    #[test]
    fn concurrent_same_branch_race_refuses_exactly_one() {
        let kind = HashKind::Sha1;
        let dest = test_store(kind);
        let (pack_a, commit_a, _) = limit_pack_with(1);
        let (pack_b, commit_b, _) = limit_pack_with(2);
        assert_ne!(commit_a, commit_b, "the racers carry distinct commits");
        let dest_ref = &dest;
        let push = |pack: &[u8], commit: Oid| {
            let mut input = command(
                kind.zero_oid(),
                commit,
                b"refs/heads/race",
                Some("report-status"),
            );
            input.extend_from_slice(b"0000");
            input.extend_from_slice(pack);
            let mut out = Vec::new();
            serve_receive_pack_with(ReceivePackParams {
                reader: &input[..],
                writer: &mut out,
                store: dest_ref,
                kind,
                head: &head(),
                interrupt: &Interrupt::none(),
                policy: &NoPolicy,
                lfs: LfsMode::Deny,
                limits: ReceiveLimits::default(),
                on_behalf_of: None,
            })
            .expect("race serves in-band refusals");
            report_lines(&out)
        };
        let (lines_a, lines_b) = std::thread::scope(|scope| {
            let first = scope.spawn(move || push(&pack_a, commit_a));
            let second = scope.spawn(move || push(&pack_b, commit_b));
            (
                first.join().expect("first racer"),
                second.join().expect("second racer"),
            )
        });
        let oks = [&lines_a, &lines_b]
            .iter()
            .filter(|lines| lines.iter().any(|line| line.starts_with(b"ok ")))
            .count();
        assert_eq!(
            oks, 1,
            "exactly one racer lands: {lines_a:?} vs {lines_b:?}"
        );
        let tip = ref_oid(&dest, b"refs/heads/race").expect("race lands a tip");
        assert!(
            tip == commit_a || tip == commit_b,
            "the tip is one racer: {tip}"
        );
    }

    fn serve_push_raw(
        dest: &Store,
        kind: HashKind,
        updates: &[(Oid, Oid, &[u8])],
        first_caps: &str,
        middle: &[u8],
        pack: &[u8],
        policy: &dyn ReceivePolicy,
    ) -> Vec<Vec<u8>> {
        let mut input = Vec::new();
        for (index, (old, new, name)) in updates.iter().enumerate() {
            let caps = (index == 0).then_some(first_caps);
            input.extend_from_slice(&command(*old, *new, name, caps));
        }
        input.extend_from_slice(b"0000");
        input.extend_from_slice(middle);
        input.extend_from_slice(pack);
        let mut out = Vec::new();
        serve_receive_pack_with(ReceivePackParams {
            reader: &input[..],
            writer: &mut out,
            store: dest,
            kind,
            head: &head(),
            interrupt: &Interrupt::none(),
            policy,
            lfs: LfsMode::Deny,
            limits: ReceiveLimits::default(),
            on_behalf_of: None,
        })
        .expect("serve completes refused pushes in-band");
        report_lines(&out)
    }

    /// Writes an executable `hooks/proc-receive` stub speaking the hook
    /// protocol: it records the diverted commands to `cmds_marker` and
    /// answers every command with `verdict`. Byte-exact `dd` reads keep it
    /// POSIX sh (no `head -c` over-read, no bashisms); the conversation is
    /// lock-step with the server so no phase blocks. Only the accept path
    /// needs a speaking stub — refusals use `exit 1`, and the protocol
    /// grammar itself is covered by in-memory transcript tests.
    fn write_proc_receive_stub(
        repo: &std::path::Path,
        cmds_marker: &std::path::Path,
        verdict: &str,
    ) {
        let body = format!(
            r#"
L=$(dd bs=4 count=1 2>/dev/null)
N=$(($((0x$L)) - 4))
V=$(dd bs=1 count="$N" 2>/dev/null)
F=$(dd bs=4 count=1 2>/dev/null)
printf '000eversion=1\n0000'
while :; do
  L=$(dd bs=4 count=1 2>/dev/null)
  [ "$L" = "0000" ] && break
  [ -z "$L" ] && exit 1
  N=$(($((0x$L)) - 4))
  C=$(dd bs=1 count="$N" 2>/dev/null)
  echo "$C" >> "{cmds}"
  set -- $C
  REF=$3
  NEW=$2
  {verdict}
done
printf '0000'
"#,
            cmds = cmds_marker.display(),
        );
        write_hook(repo, "proc-receive", &body);
    }

    /// Answers one diverted command with `ok` plus a review-ref option.
    fn ok_with_review_ref() -> &'static str {
        r#"
  R="ok $REF"
  printf '%04x%s' "$((${#R} + 4))" "$R"
  O="option refname refs/pull/1/head"
  printf '%04x%s' "$((${#O} + 4))" "$O"
  O2="option new-oid $NEW"
  printf '%04x%s' "$((${#O2} + 4))" "$O2"
"#
    }

    fn ref_oid(dest: &Store, name: &[u8]) -> Option<Oid> {
        let target = StoreRefs::new(dest)
            .get(&RefName::new(name.to_vec()).expect("ref name"))
            .expect("ref read");
        match target {
            Some(RefTarget::Direct(oid)) => Some(oid),
            _ => None,
        }
    }

    /// A mixed push diverts `refs/for/` to the hook while the normal ref
    /// lands: the client sees `ok` for both, the review backend saw only
    /// the diverted command, and no literal `refs/for/` ref is created.
    #[test]
    fn agit_ok_routes_for_to_review_not_literal_ref() {
        use std::time::Duration;

        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let cmds_marker = repo.join("proc-commands");
        write_proc_receive_stub(&repo, &cmds_marker, ok_with_review_ref());
        let hooks = ReceiveHooks::for_repo(repo).with_timeout(Duration::from_secs(10));
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_raw(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
                (kind.zero_oid(), oid(FOUR), b"refs/for/main"),
            ],
            "report-status delete-refs ofs-delta agent=test",
            &[],
            &pack,
            &ScriptPolicy::new(hooks.clone()),
        );
        assert_eq!(
            lines,
            vec![
                b"unpack ok".to_vec(),
                b"ok refs/heads/main".to_vec(),
                b"ok refs/for/main".to_vec(),
            ]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        assert_eq!(ref_oid(&dest, b"refs/for/main"), None);
        let seen = std::fs::read_to_string(&cmds_marker).expect("hook saw commands");
        assert!(
            seen.contains("refs/for/main"),
            "hook missed the diverted command: {seen:?}"
        );
        assert!(
            !seen.contains("refs/heads/main"),
            "hook saw a normal ref: {seen:?}"
        );
    }

    /// `pre-receive` observes every wire command exactly as sent,
    /// including duplicates: the hook stdin carries both lines even
    /// though the duplicate already carries its verdict.
    #[test]
    fn prereceive_observes_duplicate_commands() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let stdin_marker = repo.join("pre-stdin");
        write_hook(
            &repo,
            "pre-receive",
            &format!("cat > \"{}\"\n", stdin_marker.display()),
        );
        let hooks = ReceiveHooks::for_repo(repo);
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
            ],
            &pack,
            &ScriptPolicy::new(hooks),
        );
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"unpack ok");
        assert_eq!(lines[1], b"ok refs/heads/main");
        assert!(
            lines[2].starts_with(b"ng refs/heads/main "),
            "got {:?}",
            lines[2]
        );
        let seen = std::fs::read_to_string(&stdin_marker).expect("hook saw stdin");
        let expected = format!(
            "{} {} refs/heads/main\n{} {} refs/heads/main\n",
            kind.zero_oid().to_hex(),
            oid(FOUR).to_hex(),
            kind.zero_oid().to_hex(),
            oid(FOUR).to_hex(),
        );
        assert_eq!(seen, expected, "pre-receive stdin skipped a command");
    }

    /// Hooks run with a hermetic environment: the hook observes exactly
    /// `PATH=/usr/bin:/bin`, `GIT_DIR`, and the quarantine inspection
    /// variables, while inherited variables (like `HOME`, which the test
    /// process always carries) never arrive.
    #[test]
    fn hooks_run_with_hermetic_env_allowlist() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let env_marker = repo.join("hook-env");
        write_hook(
            &repo,
            "pre-receive",
            &format!("env | sort > \"{}\"\n", env_marker.display()),
        );
        let hooks = ReceiveHooks::for_repo(repo);
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(hooks),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        let seen = std::fs::read_to_string(&env_marker).expect("hook dumped env");
        assert!(
            seen.lines().any(|line| line == "PATH=/usr/bin:/bin"),
            "hook PATH is not the allowlist value: {seen:?}"
        );
        assert!(
            seen.lines().any(|line| line.starts_with("GIT_DIR=")),
            "hook missed GIT_DIR: {seen:?}"
        );
        assert!(
            seen.lines()
                .any(|line| line.starts_with("GIT_QUARANTINE_PATH=")),
            "hook missed the quarantine path: {seen:?}"
        );
        assert!(
            std::env::var_os("HOME").is_some(),
            "the test needs an inherited HOME to prove the clear"
        );
        assert!(
            !seen.lines().any(|line| line.starts_with("HOME=")),
            "inherited variables leak into hooks: {seen:?}"
        );
    }

    /// The script policy pins hook outputs byte for byte: `pre-receive`
    /// observes both commands, one `update` refusal names its exact
    /// decline line, and `post-receive` observes only the landed ref.
    #[test]
    fn script_policy_matches_existing_hook_outputs() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let pre_marker = repo.join("pre-lines");
        let post_marker = repo.join("post-lines");
        write_hook(
            &repo,
            "pre-receive",
            &format!("cat > \"{}\"\n", pre_marker.display()),
        );
        write_hook(
            &repo,
            "post-receive",
            &format!("cat > \"{}\"\n", post_marker.display()),
        );
        // Only refs/heads/b gets an update refusal: gate the hook on
        // its first argument.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let path = repo.join("hooks").join("update");
            std::fs::write(
                &path,
                "#!/bin/sh\nif [ \"$1\" = \"refs/heads/b\" ]; then echo keep-out >&2; exit 1; fi\nexit 0\n",
            )
            .expect("gate update hook");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("hook executable");
        }
        let hooks = ReceiveHooks::for_repo(repo);
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
                (kind.zero_oid(), oid(FOUR), b"refs/heads/b"),
            ],
            &pack,
            &ScriptPolicy::new(hooks),
        );
        assert_eq!(
            lines,
            vec![
                b"unpack ok".to_vec(),
                b"ok refs/heads/main".to_vec(),
                b"ng refs/heads/b update hook declined: keep-out".to_vec(),
            ]
        );
        let seen_pre = std::fs::read_to_string(&pre_marker).expect("pre-receive ran");
        assert!(seen_pre.contains("refs/heads/main"), "got {seen_pre:?}");
        assert!(seen_pre.contains("refs/heads/b"), "got {seen_pre:?}");
        let seen_post = std::fs::read_to_string(&post_marker).expect("post-receive ran");
        assert!(seen_post.contains("refs/heads/main"), "got {seen_post:?}");
        assert!(
            !seen_post.contains("refs/heads/b"),
            "refused ref leaked to post: {seen_post:?}"
        );
    }

    /// `refs/pull/` pushes no longer divert to `proc-receive`: with the
    /// default prefixes only `refs/for/` diverts, so a `refs/pull/` ref
    /// lands as a plain ref through the CAS path while the hook never
    /// sees it.
    #[test]
    fn refs_pull_no_longer_diverted() {
        use std::time::Duration;

        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let cmds_marker = repo.join("proc-commands");
        write_proc_receive_stub(&repo, &cmds_marker, ok_with_review_ref());
        let hooks = ReceiveHooks::for_repo(repo).with_timeout(Duration::from_secs(10));
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_raw(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/for/main"),
                (kind.zero_oid(), oid(FOUR), b"refs/pull/1/head"),
            ],
            "report-status delete-refs ofs-delta agent=test",
            &[],
            &pack,
            &ScriptPolicy::new(hooks),
        );
        assert_eq!(
            lines,
            vec![
                b"unpack ok".to_vec(),
                b"ok refs/for/main".to_vec(),
                b"ok refs/pull/1/head".to_vec(),
            ]
        );
        assert_eq!(ref_oid(&dest, b"refs/for/main"), None);
        assert_eq!(ref_oid(&dest, b"refs/pull/1/head"), Some(oid(FOUR)));
        let seen = std::fs::read_to_string(&cmds_marker).expect("hook saw commands");
        assert!(
            seen.contains("refs/for/main"),
            "hook missed the diverted command: {seen:?}"
        );
        assert!(
            !seen.contains("refs/pull"),
            "hook saw an undiverted ref: {seen:?}"
        );
    }

    /// `post-receive` observes the hook-supplied review ref for a diverted
    /// command the hook accepted, not the original `refs/for/` name: the
    /// hook sent `option refname` plus `option new-oid`, so the landed
    /// line carries both (with the pushed old OID, which the hook did not
    /// override).
    #[test]
    fn agit_post_receive_observes_review_ref() {
        use std::time::Duration;

        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let cmds_marker = repo.join("proc-commands");
        write_proc_receive_stub(&repo, &cmds_marker, ok_with_review_ref());
        let post_marker = repo.join("post-lines");
        write_hook(
            &repo,
            "post-receive",
            &format!("cat > \"{}\"\n", post_marker.display()),
        );
        let hooks = ReceiveHooks::for_repo(repo).with_timeout(Duration::from_secs(10));
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_raw(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/for/main")],
            "report-status delete-refs ofs-delta agent=test",
            &[],
            &pack,
            &ScriptPolicy::new(hooks.clone()),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/for/main".to_vec(),]
        );
        let seen = std::fs::read_to_string(&post_marker).expect("post-receive ran");
        assert_eq!(
            seen,
            format!(
                "{} {} refs/pull/1/head\n",
                kind.zero_oid().to_hex(),
                oid(FOUR).to_hex()
            ),
            "post-receive missed the review ref: {seen:?}"
        );
    }

    /// `GIT_PUSH_OPTION_COUNT` is exported only when the client negotiated
    /// `push-options`: this push carries no such capability, so the hook
    /// must observe neither the count nor any option.
    #[test]
    fn push_option_count_absent_without_negotiation() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let marker = repo.join("push-option-count");
        write_hook(
            &repo,
            "pre-receive",
            &format!(
                "echo \"COUNT=${{GIT_PUSH_OPTION_COUNT-unset}}\" > \"{}\"\n",
                marker.display()
            ),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        let seen = std::fs::read_to_string(&marker).expect("hook ran");
        assert!(
            seen.contains("COUNT=unset"),
            "unnegotiated push exported a count: {seen:?}"
        );
    }

    /// A failing `proc-receive` hook refuses only its diverted refs
    /// in-band; the normal refs of the same push still land.
    #[test]
    fn agit_hook_failure_keeps_normal_refs() {
        use std::time::Duration;

        let kind = HashKind::Sha1;
        let repo = hook_repo();
        write_hook(&repo, "proc-receive", "exit 1\n");
        let hooks = ReceiveHooks::for_repo(repo).with_timeout(Duration::from_secs(10));
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_raw(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
                (kind.zero_oid(), oid(FOUR), b"refs/for/main"),
            ],
            "report-status delete-refs ofs-delta agent=test",
            &[],
            &pack,
            &ScriptPolicy::new(hooks.clone()),
        );
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"unpack ok");
        assert_eq!(lines[1], b"ok refs/heads/main");
        assert!(
            lines[2].starts_with(b"ng refs/for/main "),
            "got {:?}",
            lines[2]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        assert_eq!(ref_oid(&dest, b"refs/for/main"), None);
    }

    /// With no `proc-receive` script installed there is no review backend,
    /// so `refs/for/` pushes fall through to the normal ref path.
    #[test]
    fn agit_missing_hook_falls_through_to_normal_ref() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/for/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/for/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/for/main"), Some(oid(FOUR)));
    }

    /// Push options travel before the pack on the wire and reach hooks as
    /// `GIT_PUSH_OPTION_*`: a `pre-receive` recorder observes them while
    /// the pack still ingests normally.
    #[test]
    fn push_options_reach_hooks_before_the_pack() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let marker = repo.join("push-options");
        write_hook(
            &repo,
            "pre-receive",
            &format!(
                "echo \"COUNT=$GIT_PUSH_OPTION_COUNT OPT0=$GIT_PUSH_OPTION_0\" > \"{}\"\n",
                marker.display()
            ),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");
        let mut middle = Vec::new();
        encode_data(&mut middle, b"topic=my-topic").expect("frame");
        middle.extend_from_slice(b"0000");

        let lines = serve_push_raw(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            "report-status delete-refs ofs-delta push-options agent=test",
            &middle,
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        let seen = std::fs::read_to_string(&marker).expect("hook saw options");
        assert!(
            seen.contains("COUNT=1 OPT0=topic=my-topic"),
            "options lost: {seen:?}"
        );
    }

    #[test]
    fn hook_prereceive_refusal_leaves_store_untouched() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let marker = repo.join("pre-receive-ran");
        write_hook(
            &repo,
            "pre-receive",
            &format!("echo refused > \"{}\"\nexit 1\n", marker.display()),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok");
        assert!(
            lines[1].starts_with(b"ng refs/heads/main pre-receive hook declined"),
            "got {:?}",
            lines[1]
        );
        // The hook ran, but nothing promoted: the object never published
        // and the ref never moved.
        assert!(marker.is_file(), "pre-receive hook did not run");
        assert!(
            !super::super::has_object(&dest, oid(FOUR)).expect("probe"),
            "refused object published"
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), None);
    }

    #[test]
    fn hook_prereceive_pass_publishes_and_exposes_quarantine() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let scratch = repo.join("scratch");
        std::fs::create_dir_all(&scratch).expect("scratch");
        let marker = repo.join("pre-receive-ran");
        write_hook(
            &repo,
            "pre-receive",
            &format!(
                concat!(
                    "test -n \"$GIT_QUARANTINE_PATH\" || exit 10\n",
                    "test -f \"$GIT_QUARANTINE_PATH/manifest\" || exit 11\n",
                    "test -d \"$GIT_DIR\" || exit 12\n",
                    "test -n \"$(find \"$GIT_QUARANTINE_PATH/objects\" -type f)\" || exit 13\n",
                    "echo passed > \"{}\"\n",
                    "exit 0\n",
                ),
                marker.display()
            ),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(
                ReceiveHooks::for_repo(repo.clone()).with_quarantine_parent(scratch.clone()),
            ),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert!(marker.is_file(), "passing hook did not run: {lines:?}");
        assert!(super::super::has_object(&dest, oid(FOUR)).expect("probe"));
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        // The per-push quarantine directory is removed after the session.
        let leftovers: Vec<_> = std::fs::read_dir(&scratch)
            .expect("scratch")
            .collect::<Result<_, _>>()
            .expect("entries");
        assert!(leftovers.is_empty(), "quarantine leaked: {leftovers:?}");
    }

    #[test]
    fn hook_update_refusal_is_per_ref() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        write_hook(
            &repo,
            "update",
            concat!(
                "if [ \"$1\" = \"refs/heads/feature\" ]; then\n",
                "  echo \"feature frozen\"\n",
                "  exit 1\n",
                "fi\n",
                "exit 0\n",
            ),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let main = PushUpdateForTest {
            name: b"refs/heads/main".to_vec(),
            old: kind.zero_oid(),
            new: oid(FOUR),
        };
        let feature = PushUpdateForTest {
            name: b"refs/heads/feature".to_vec(),
            old: kind.zero_oid(),
            new: oid(THREE),
        };
        let pack = push_pack_for(&src, kind, &[&main, &feature]);

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[
                (kind.zero_oid(), oid(FOUR), b"refs/heads/main"),
                (kind.zero_oid(), oid(THREE), b"refs/heads/feature"),
            ],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"unpack ok");
        assert_eq!(lines[1], b"ok refs/heads/main");
        assert!(
            lines[2].starts_with(b"ng refs/heads/feature update hook declined"),
            "got {:?}",
            lines[2]
        );
        // The surviving ref lands; the refused one stays absent. Staged
        // objects still promote, mirroring quarantine migration.
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        assert_eq!(ref_oid(&dest, b"refs/heads/feature"), None);
        assert!(super::super::has_object(&dest, oid(FOUR)).expect("probe"));
        assert!(super::super::has_object(&dest, oid(THREE)).expect("probe"));
    }

    /// Minimal update triple for multi-ref pack construction in tests.
    struct PushUpdateForTest {
        name: Vec<u8>,
        old: Oid,
        new: Oid,
    }

    /// Builds one pack covering every given update's closure.
    fn push_pack_for(src: &Store, kind: HashKind, updates: &[&PushUpdateForTest]) -> Vec<u8> {
        use super::super::push::{PushUpdate, push_closure};
        let owned: Vec<PushUpdate> = updates
            .iter()
            .map(|update| PushUpdate {
                name: update.name.clone(),
                old: update.old,
                new: update.new,
            })
            .collect();
        let live: Vec<&PushUpdate> = owned.iter().collect();
        let entries = push_closure(src, kind, &live, &Interrupt::none()).expect("closure");
        let pack_entries = entries
            .iter()
            .map(super::super::push::ClosureObject::as_entry)
            .collect::<Vec<_>>();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, &Interrupt::none()).expect("pack");
        pack
    }

    #[test]
    fn hook_prereceive_timeout_survives_grandchildren() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        // A backgrounded sleep outlives the killed hook holding stderr
        // open; the push must still fail fast on the timeout instead of
        // hanging on the pipe.
        write_hook(&repo, "pre-receive", "sleep 30 &\nexec sleep 30\n");
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let started = std::time::Instant::now();
        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(
                ReceiveHooks::for_repo(repo).with_timeout(std::time::Duration::from_secs(1)),
            ),
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "hook timeout did not bound the push"
        );
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"unpack ok");
        assert!(
            lines[1].starts_with(b"ng refs/heads/main pre-receive hook failed: io: timed out"),
            "got {:?}",
            lines[1]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), None);
    }

    #[test]
    fn hook_postreceive_runs_after_refs_land() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        let seen = repo.join("post-receive-stdin");
        let marker = repo.join("post-receive-ran");
        write_hook(
            &repo,
            "post-receive",
            &format!(
                "cat > \"{}\"\necho ran > \"{}\"\nexit 0\n",
                seen.display(),
                marker.display()
            ),
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
        assert!(marker.is_file(), "post-receive hook did not run");
        let stdin = std::fs::read_to_string(&seen).expect("hook stdin");
        assert!(
            stdin.contains("refs/heads/main"),
            "post-receive saw no update line: {stdin:?}"
        );
    }

    #[test]
    fn hook_postreceive_failure_is_not_fatal() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        write_hook(
            &repo,
            "post-receive",
            "echo \"backend exploded\" >&2\nexit 1\n",
        );
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
    }

    #[test]
    fn hook_missing_scripts_pass() {
        let kind = HashKind::Sha1;
        let repo = hook_repo();
        // No scripts under `hooks/`: every phase passes through.
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        let pack = push_pack(&src, kind, kind.zero_oid(), oid(FOUR), b"refs/heads/main");

        let lines = serve_push_with_hooks(
            &dest,
            kind,
            &[(kind.zero_oid(), oid(FOUR), b"refs/heads/main")],
            &pack,
            &ScriptPolicy::new(ReceiveHooks::for_repo(repo)),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
    }
}
