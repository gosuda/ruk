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
//!   rows only when those pass, diverts `refs/for/` and `refs/pull/`
//!   commands to the `proc-receive` hook (see [`super::proc_receive`]),
//!   and applies surviving refs through the shared
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

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::{FactMutation, Store};

use super::fetch::{commit_record_facts, verify_closure};
use super::hooks::{Quarantine, ReceiveHooks, run_hook, stage_quarantine};
use super::pack::{IngestLimits, PackEntry, StagedPack, ingest_pack, write_pack};
use super::pktline::{Packet, PktReader, encode_data, encode_flush, send};
use super::proc_receive::{
    ProcReceiveCommand, ProcVerdict, PushOptions, is_proc_receive_ref, run_proc_receive,
};
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
/// unbounded pre-pack read is a memory sink, and no real client (Forgejo
/// uses at most four AGit keys) approaches this.
const MAX_PUSH_OPTIONS: usize = 256;

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
    interrupt: &Interrupt,
) -> Result<(StagedPack, Vec<FactMutation>), GitError> {
    let staged = ingest_pack(reader, kind, store, IngestLimits::default(), interrupt)?;
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

/// Runs the AGit diversion for surviving proc-receive commands: accepted
/// commands report `ok` for their original ref (the review backend wrote
/// the review ref itself), refused ones report `ng`, and fall-through
/// commands rejoin the normal path through the `update` hook, leaving
/// their verdict undecided for the CAS path below.
fn run_proc_receive_phase(
    live: &[(usize, PushUpdate)],
    results: &mut [Option<Result<(), String>>],
    hooks: &ReceiveHooks,
    quarantine: Option<&Quarantine>,
    options: &PushOptions<'_>,
    kind: HashKind,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    let mut indices = Vec::new();
    let mut hook_commands = Vec::new();
    for (index, update) in live {
        if results[*index].is_none() && is_proc_receive_ref(&update.name) {
            indices.push(*index);
            hook_commands.push(ProcReceiveCommand {
                old: update.old,
                new: update.new,
                name: update.name.clone(),
            });
        }
    }
    if hook_commands.is_empty() {
        return Ok(());
    }
    interrupt.check("running proc-receive hook")?;
    let verdicts = run_proc_receive(hooks, quarantine, &hook_commands, options, kind, interrupt);
    for (position, verdict) in verdicts.into_iter().enumerate() {
        let index = indices[position];
        match verdict {
            ProcVerdict::Accepted { .. } => results[index] = Some(Ok(())),
            ProcVerdict::Rejected { reason } => results[index] = Some(Err(reason)),
            ProcVerdict::FallThrough => {}
        }
    }
    for (index, update) in live {
        if !indices.contains(index) || results[*index].is_some() {
            continue;
        }
        interrupt.check("running update hooks")?;
        let args = [
            String::from_utf8_lossy(&update.name).into_owned(),
            update.old.to_hex(),
            update.new.to_hex(),
        ];
        if let Some(reason) = run_hook(hooks, quarantine, "update", &args, None, options.values) {
            results[*index] = Some(Err(reason));
        }
    }
    Ok(())
}

/// Serves one `receive-pack` session: writes the advertisement, reads update
/// commands plus the pack, and reports per-ref outcomes.
///
/// Ingest, verification and publication failures still send a report (`unpack
/// <err>` with every ref `ng`) before returning the error, so the client
/// stays in sync; per-ref CAS rejections are outcomes, not errors.
///
/// Hook phases are disabled: this is the historical entry point preserved
/// for callers without a repository directory. Pass [`ReceiveHooks`] to
/// [`serve_receive_pack_with`] to enable quarantine staging with
/// `pre-receive`/`update`/`post-receive` execution.
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
) -> Result<(), GitError> {
    serve_receive_pack_with(
        reader,
        writer,
        store,
        kind,
        head,
        interrupt,
        &ReceiveHooks::disabled(),
    )
}

/// Serves one `receive-pack` session with quarantine staging and hook
/// phases (see [`super::hooks`]): the pack stages unpublished, hooks
/// observe it through the quarantine directory, staged objects publish
/// only after the refusing phases pass, `refs/for/` and `refs/pull/`
/// commands divert to the `proc-receive` hook (see
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
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::ObjectFormat`]
/// for store/kind mismatch or foreign OIDs, plus ingest, verification,
/// store and transport failures.
pub fn serve_receive_pack_with<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
    hooks: &ReceiveHooks,
) -> Result<(), GitError> {
    if store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "serving store uses another object format".to_owned(),
        });
    }
    let caps = format!(
        "report-status delete-refs ofs-delta push-options object-format={} agent={}",
        object_format_value(kind),
        AGENT
    );
    send(&mut writer, &advertisement(store, kind, head, &caps)?)?;

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
        return Ok(());
    }
    // Push options follow the commands flush and precede the pack, exactly
    // like the oracle's `read_push_options` before `unpack_with_sideband`.
    // Forgejo advertises them on every repository
    // (`receive.advertisePushOptions`), and AGit reads `topic`,
    // `force-push`, `title` and `description` from them.
    let mut push_options: Vec<String> = Vec::new();
    if client_push_options {
        while let Some(line) = read_frame(&mut pkt, "push options")? {
            if push_options.len() >= MAX_PUSH_OPTIONS {
                return Err(GitError::Limit {
                    detail: format!("push sent more than {MAX_PUSH_OPTIONS} options"),
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
        match ingest_and_verify(pkt.get_mut(), store, kind, &news, interrupt) {
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
    // Quarantine staging for hook inspection. A materialization failure is
    // infrastructure, not a hook verdict: every ref reports `ng` and the
    // error propagates, with the unpack line still `ok`.
    let quarantine = match stage_quarantine(hooks, staged.as_ref()) {
        Ok(quarantine) => quarantine,
        Err(err) => {
            let reason = sanitize(&err.to_string());
            send_report(&mut writer, None, &all_ng(&commands, &reason))?;
            return Err(err);
        }
    };
    interrupt.check("running receive hooks")?;
    // `pre-receive` over every command: a refusal fails the whole push and
    // drops the staging unpublished, mirroring the oracle's quarantine
    // removal. The verdicts travel in-band with `unpack ok`; only the
    // return stays `Ok`, exactly like CAS rejections below.
    let all_lines: String = commands.iter().map(hook_line).collect();
    if let Some(reason) = run_hook(
        hooks,
        quarantine.as_ref(),
        "pre-receive",
        &[],
        Some(all_lines.as_bytes()),
        &push_options,
    ) {
        for (index, _) in &live {
            results[*index] = Some(Err(reason.clone()));
        }
        send_report(&mut writer, None, &report_rows(&commands, &results))?;
        return Ok(());
    }
    // `update` per live ref over argv (`<ref> <old> <new>`, mirroring the
    // oracle and Forgejo's dispatcher): a refusal marks only its own ref.
    // Proc-receive refs skip this phase: the oracle's `update()` runs only
    // for commands the hook did not claim, and Forgejo never sees an
    // `update` call for `refs/for/` either.
    for (index, update) in &live {
        if is_proc_receive_ref(&update.name) {
            continue;
        }
        interrupt.check("running update hooks")?;
        let args = [
            String::from_utf8_lossy(&update.name).into_owned(),
            update.old.to_hex(),
            update.new.to_hex(),
        ];
        if let Some(reason) = run_hook(
            hooks,
            quarantine.as_ref(),
            "update",
            &args,
            None,
            &push_options,
        ) {
            results[*index] = Some(Err(reason));
        }
    }
    // Promote staged objects plus their commit rows in one publication.
    // This runs even when every ref was refused: the oracle migrates the
    // quarantine directory regardless of per-ref outcomes, and unreferenced
    // objects simply stay unreachable.
    if let Some(pack) = staged {
        if let Err(err) = store.publish(pack.into_objects(), &facts) {
            let err = GitError::from(err);
            let reason = sanitize(&err.to_string());
            send_report(&mut writer, Some(&reason), &all_ng(&commands, &reason))?;
            return Err(err);
        }
    }
    // AGit diversion runs only outside `atomic`: consulting the hook could
    // create a review the client is then told failed, and atomicity across
    // a review backend is out of scope, so atomic rejects everything first.
    if atomic {
        for (index, _) in &live {
            if results[*index].is_none() {
                results[*index] = Some(Err("atomic pushes are not supported".to_owned()));
            }
        }
    } else {
        let options = PushOptions {
            values: &push_options,
            negotiated: client_push_options,
        };
        run_proc_receive_phase(
            &live,
            &mut results,
            hooks,
            quarantine.as_ref(),
            &options,
            kind,
            interrupt,
        )?;
    }
    // Only hook-surviving refs reach the CAS path; hook verdicts already
    // recorded above are never overwritten. Fall-through refs rejoined the
    // undecided set with their `update` verdict recorded, so they apply
    // through the same path as ordinary refs.
    let survivors: Vec<&PushUpdate> = live
        .iter()
        .filter(|(index, _)| results[*index].is_none())
        .map(|(_, update)| update)
        .collect();
    if !atomic && !survivors.is_empty() {
        match apply_refs(store, kind, &survivors, false) {
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
                send_report(&mut writer, None, &report_rows(&commands, &results))?;
                return Err(err);
            }
        }
    }
    // `post-receive` over the landed refs, after refs are updated. Its
    // failure relays to server diagnostics and never fails the push:
    // protocol v0's report has no sideband slot for it.
    let landed: String = live
        .iter()
        .filter(|(index, _)| matches!(results[*index], Some(Ok(()))))
        .map(|(_, update)| {
            let cmd = commands
                .iter()
                .find(|cmd| cmd.name == update.name)
                .expect("live update names a command");
            hook_line(cmd)
        })
        .collect();
    if !landed.is_empty() && interrupt.check("running post-receive hook").is_ok() {
        if let Some(reason) = run_hook(
            hooks,
            quarantine.as_ref(),
            "post-receive",
            &[],
            Some(landed.as_bytes()),
            &push_options,
        ) {
            tracing::warn!("post-receive hook failed: {reason}");
        }
    }
    send_report(&mut writer, None, &report_rows(&commands, &results))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::super::hooks::ReceiveHooks;
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
        hooks: &ReceiveHooks,
    ) -> Vec<Vec<u8>> {
        serve_push_raw(
            dest,
            kind,
            updates,
            "report-status delete-refs ofs-delta agent=test",
            &[],
            pack,
            hooks,
        )
    }

    /// Serves one push whose first command carries `first_caps`, with raw
    /// `middle` bytes (push-option frames) between the commands flush and
    /// the pack, returning the report lines.
    fn serve_push_raw(
        dest: &Store,
        kind: HashKind,
        updates: &[(Oid, Oid, &[u8])],
        first_caps: &str,
        middle: &[u8],
        pack: &[u8],
        hooks: &ReceiveHooks,
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
        serve_receive_pack_with(
            &input[..],
            &mut out,
            dest,
            kind,
            &head(),
            &Interrupt::none(),
            hooks,
        )
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
            &hooks,
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
            &hooks,
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo.clone()).with_quarantine_parent(scratch.clone()),
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo).with_timeout(std::time::Duration::from_secs(1)),
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo),
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
            &ReceiveHooks::for_repo(repo),
        );
        assert_eq!(
            lines,
            vec![b"unpack ok".to_vec(), b"ok refs/heads/main".to_vec(),]
        );
        assert_eq!(ref_oid(&dest, b"refs/heads/main"), Some(oid(FOUR)));
    }
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
pub fn serve_command<R: Read, W: Write>(
    name: &str,
    reader: R,
    writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    match name {
        "upload-pack" => serve_upload_pack(reader, writer, store, kind, head, interrupt),
        "receive-pack" => serve_receive_pack(reader, writer, store, kind, head, interrupt),
        "upload-archive" => {
            super::archive::serve_upload_archive(reader, writer, store, kind, head, interrupt)
        }
        other => Err(GitError::Unsupported {
            command: format!("unknown serve command {other:?}"),
        }),
    }
}
