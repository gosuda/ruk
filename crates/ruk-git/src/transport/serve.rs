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
//!   ofs-delta object-format agent`, reads update commands, ingests the
//!   pack (skipped for delete-only pushes, mirroring the oracle's
//!   `delete_only` gate), verifies the closure, records commit rows, and
//!   applies refs through the shared
//!   [`apply_refs`](super::session::apply_refs) CAS path, reporting
//!   per-ref `ok`/`ng` lines. `atomic`, `push-cert` and `push-options` are
//!   not advertised; an `atomic` request that arrives anyway rejects every
//!   ref instead of desynchronizing the stream.
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

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::Store;

use super::fetch::{commit_record_facts, verify_closure};
use super::pack::{IngestLimits, PackEntry, ingest_pack, write_pack};
use super::pktline::{Packet, PktReader, encode_data, encode_flush, send};
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
    let mut caps = format!(
        "multi_ack ofs-delta object-format={} agent={}",
        object_format_value(kind),
        AGENT
    );
    if let Some(target) = head.symref.as_deref() {
        caps.push_str(&format!(" symref=HEAD:{}", String::from_utf8_lossy(target)));
    }
    send(&mut writer, &advertisement(store, kind, head, &caps)?)?;

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
/// over staged plus committed objects, records commit rows, and publishes
/// everything in one transaction.
fn ingest_verify_publish<R: Read>(
    reader: R,
    store: &Store,
    kind: HashKind,
    news: &[Oid],
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    let staged = ingest_pack(reader, kind, store, IngestLimits::default(), interrupt)?;
    verify_closure(store, &staged, news, None, &[], interrupt)?;
    let facts = commit_record_facts(store, &staged)?;
    store.publish(staged.into_objects(), &facts)?;
    Ok(())
}

/// Serves one `receive-pack` session: writes the advertisement, reads update
/// commands plus the pack, and reports per-ref outcomes.
///
/// Ingest, verification and publication failures still send a report (`unpack
/// <err>` with every ref `ng`) before returning the error, so the client
/// stays in sync; per-ref CAS rejections are outcomes, not errors.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or foreign OIDs, plus ingest, verification,
/// store and transport failures.
pub fn serve_receive_pack<R: Read, W: Write>(
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
    let caps = format!(
        "report-status delete-refs ofs-delta object-format={} agent={}",
        object_format_value(kind),
        AGENT
    );
    send(&mut writer, &advertisement(store, kind, head, &caps)?)?;

    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut commands: Vec<Command> = Vec::new();
    let mut atomic = false;
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
                    }
                }
            }
        }
        commands.push(parse_command(&line, kind)?);
    }
    if commands.is_empty() {
        return Ok(());
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
    // send none, mirroring the oracle's `delete_only` gate.
    if commands.iter().any(|cmd| cmd.new != zero) {
        let news: Vec<Oid> = commands
            .iter()
            .filter(|cmd| cmd.new != zero)
            .map(|cmd| cmd.new)
            .collect();
        if let Err(err) = ingest_verify_publish(pkt.get_mut(), store, kind, &news, interrupt) {
            let reason = sanitize(&err.to_string());
            send_report(&mut writer, Some(&reason), &all_ng(&commands, &reason))?;
            return Err(err);
        }
    }
    if atomic {
        for (index, _) in &live {
            results[*index] = Some(Err("atomic pushes are not supported".to_owned()));
        }
    } else {
        let refs: Vec<&PushUpdate> = live.iter().map(|(_, update)| update).collect();
        match apply_refs(store, kind, &refs, false) {
            Ok(outcomes) => {
                for outcome in &outcomes {
                    if let Some((index, _)) =
                        live.iter().find(|(_, update)| update.name == outcome.name)
                    {
                        results[*index] = Some(match &outcome.result {
                            RefResult::Ok => Ok(()),
                            RefResult::Rejected { reason } => Err(reason.clone()),
                        });
                    }
                }
            }
            Err(err) => {
                let reason = sanitize(&err.to_string());
                for result in results.iter_mut().filter(|result| result.is_none()) {
                    *result = Some(Err(format!("ref update failed: {reason}")));
                }
                let rows = commands
                    .iter()
                    .zip(results.iter())
                    .map(|(cmd, result)| {
                        (
                            cmd.name.clone(),
                            result.clone().expect("every command has a verdict"),
                        )
                    })
                    .collect::<Vec<_>>();
                send_report(&mut writer, None, &rows)?;
                return Err(err);
            }
        }
    }
    let rows = commands
        .iter()
        .zip(results.iter())
        .map(|(cmd, result)| {
            (
                cmd.name.clone(),
                result.clone().expect("every command has a verdict"),
            )
        })
        .collect::<Vec<_>>();
    send_report(&mut writer, None, &rows)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::refadv::{Initial, read_initial};
    use super::super::session::test_support::{store_with_pack, test_store};
    use super::*;
    use ruk_core::refdata::{RefChange, RefExpect, RefTransaction, RefUpdate};
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

    fn framed(line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_data(&mut out, line).expect("frame");
        out
    }

    /// Skips the advertisement and NAK lines of a serve transcript,
    /// returning the pack bytes that follow.
    fn pack_of(out: &[u8], kind: HashKind) -> Vec<u8> {
        let mut pkt = PktReader::new(&out[..], Interrupt::none());
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
        )
        .expect("serve");
        let lines = report_lines(&out);
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
    }

    #[test]
    fn receive_rejects_a_moved_ref() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = server_store();
        // The client saw THREE but the server is at FOUR: the CAS fails.
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
}
