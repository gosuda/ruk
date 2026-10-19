//! AGit review routing: diverting `refs/for/` and `refs/pull/` pushes to
//! the `proc-receive` hook.
//!
//! Forgejo implements AGit ("push to `refs/for/<branch>` opens a pull
//! request") through git's `proc-receive` hook, not through ref updates:
//! every repository gets `receive.procReceiveRefs` values `refs/for` and
//! `refs/pull/` (`forgejo/modules/git/git.go`) plus a generated
//! `hooks/proc-receive` dispatcher chaining `forgejo hook proc-receive`
//! (`forgejo/modules/git/hook_generate.go`), which creates or updates the
//! pull request and its `refs/pull/<N>/head` ref itself
//! (`forgejo/services/agit/agit.go`, `forgejo/services/pull/pull.go`
//! `UpdateRef`). The review backend therefore owns the alternate-ref
//! write; this module only diverts the commands, speaks the hook
//! protocol, and translates the verdicts into per-ref outcomes.
//!
//! The diversion mirrors the oracle (`git/builtin/receive-pack.c`):
//!
//! - A ref matches when it equals a configured prefix or extends it past
//!   a `/` (`proc_receive_ref_append` strips trailing slashes, so the
//!   Forgejo values behave as `refs/for/` and `refs/pull/`), for adds,
//!   modifies and deletes alike. Matched commands skip the `update` hook
//!   and the normal ref update entirely and report the hook's verdict.
//! - With no `proc-receive` script installed the commands fall through to
//!   the normal path: Forgejo always installs the dispatcher, so a
//!   missing script means no review backend is configured and the push is
//!   an ordinary ref push. (The oracle would refuse instead, but only
//!   when its config names prefixes; Ruk carries no per-repo config, so
//!   the hook's presence is the configuration signal.)
//! - The hook conversation is the oracle's `run_proc_receive_hook`
//!   verbatim: `version=1[\0<features>]` plus flush both ways, the diverted
//!   `<old> <new> <ref>` commands plus flush, the push options plus flush
//!   when the hook asks for them, then `ok`/`ng`/`option` lines to a
//!   flush. `option fall-through` (which Forgejo sends for refs its
//!   `ProcReceive` does not match) returns the command to the normal
//!   path; `option refname/old-oid/new-oid/forced-update` records the
//!   review ref the hook created for observability.
//! - A broken conversation refuses only the diverted refs in-band, like
//!   the oracle's `"fail to run proc-receive hook"`, and never aborts the
//!   push of normal refs.
//!
//! Oracle anchors: `git/builtin/receive-pack.c` (`run_proc_receive_hook`,
//! `read_proc_receive_report`, `execute_commands`), `forgejo/cmd/hook.go`
//! (`runHookProcReceive`).

use std::io::{Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};

use ruk_core::ids::{HashKind, Oid};

use super::Interrupt;
use super::hooks::{Quarantine, ReceiveHooks, apply_hook_env};
use super::pktline::{Packet, PktReader, encode_data, encode_flush};
use crate::{GitError, parse_oid_for};

/// Refs diverted to the `proc-receive` hook: Forgejo's
/// `receive.procReceiveRefs` values with oracle-style trailing slashes
/// stripped (`forgejo/modules/git/git.go`, `proc_receive_ref_append`).
const PROC_RECEIVE_PREFIXES: [&str; 2] = ["refs/for", "refs/pull"];

/// Whether a ref name diverts to the `proc-receive` hook: equal to a
/// configured prefix or extending it past a `/`, mirroring
/// `proc_receive_ref_matches`.
#[must_use]
pub fn is_proc_receive_ref(name: &[u8]) -> bool {
    PROC_RECEIVE_PREFIXES.iter().any(|prefix| {
        let raw = prefix.as_bytes();
        name == raw || (name.starts_with(raw) && name.get(raw.len()) == Some(&b'/'))
    })
}

/// The client's push options with their negotiation flag.
///
/// The values travel to the hook over the protocol and to every other
/// phase as `GIT_PUSH_OPTION_*`; the flag mirrors the oracle's
/// server-to-hook feature bit and stays true when the client negotiated
/// `push-options` but sent no lines.
#[derive(Clone, Debug)]
pub(crate) struct PushOptions<'a> {
    /// Option lines in wire order.
    pub values: &'a [String],
    /// Whether the client negotiated `push-options`.
    pub negotiated: bool,
}

/// One diverted `<old> <new> <ref>` command.
#[derive(Clone, Debug)]
pub struct ProcReceiveCommand {
    /// Advertised old OID (zero for creates).
    pub old: Oid,
    /// Pushed new OID (zero for deletes).
    pub new: Oid,
    /// Full ref name.
    pub name: Vec<u8>,
}

/// The review ref the hook reported creating, from its `option` lines.
///
/// The hook performed the write itself (Forgejo's `UpdateRef`), so the
/// client still reports the original ref while `post-receive` observes
/// this review ref (see `run_proc_receive_phase` in `serve.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlternateRef {
    /// The review ref, e.g. `refs/pull/1/head`.
    pub refname: Vec<u8>,
    /// Previous review-ref tip, when the hook sent `option old-oid`.
    pub old_oid: Option<Oid>,
    /// New review-ref tip, from `option new-oid`.
    pub new_oid: Option<Oid>,
    /// Whether the hook sent `option forced-update`.
    pub forced: bool,
}

/// One diverted command's verdict.
#[derive(Clone, Debug)]
pub enum ProcVerdict {
    /// The hook accepted the push; the client reports `ok <original>`.
    Accepted {
        /// The review ref from the hook's `option` lines, if any.
        alternate: Option<AlternateRef>,
    },
    /// The hook sent `option fall-through`: run the normal ref update.
    FallThrough,
    /// The hook refused (`ng`) or the conversation broke.
    Rejected {
        /// In-band reason for the client's `ng` line.
        reason: String,
    },
}

/// Grace for a killed hook's pipes to drain before its conversation thread
/// is abandoned. Mirrors the stderr grace in [`super::hooks`]: only
/// grandchildren holding inherited pipes open can outlive the reap, and
/// the push must not hang on them.
const CONVERSE_GRACE: Duration = Duration::from_secs(5);

/// Poll interval watching the conversation thread for completion.
const CONVERSE_POLL: Duration = Duration::from_millis(5);

fn broken(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// Diverts `commands` to the `proc-receive` hook, returning one verdict
/// per command in order.
///
/// With no hook script installed every command falls through (see the
/// module docs). Every other failure refuses the diverted refs in-band;
/// normal refs are never affected.
pub(crate) fn run_proc_receive(
    hooks: &ReceiveHooks,
    quarantine: Option<&Quarantine>,
    commands: &[ProcReceiveCommand],
    options: &PushOptions<'_>,
    kind: HashKind,
    interrupt: &Interrupt,
) -> Vec<ProcVerdict> {
    if commands.is_empty() {
        return Vec::new();
    }
    let Some(repo_dir) = hooks.repo_dir() else {
        return fall_through_all(commands);
    };
    let Some(path) = hooks.hook_path("proc-receive") else {
        return fall_through_all(commands);
    };
    if !path.exists() {
        return fall_through_all(commands);
    }
    let mut cmd = std::process::Command::new(&path);
    cmd.current_dir(repo_dir);
    apply_hook_env(
        &mut cmd,
        repo_dir,
        quarantine,
        options.values,
        options.negotiated,
    );
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return reject_all(commands, format!("cannot execute proc-receive: {err}"));
        }
    };
    let stdin = match child.stdin.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            return reject_all(commands, "proc-receive has no stdin pipe".to_owned());
        }
    };
    let stdout = match child.stdout.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            return reject_all(commands, "proc-receive has no stdout pipe".to_owned());
        }
    };
    let stderr = child.stderr.take();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name("ruk-proc-receive-stderr".to_owned())
        .spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = stderr {
                let _ = pipe.read_to_end(&mut buf);
            }
            let _ = stderr_tx.send(buf);
        })
        .is_err()
    {
        let _ = child.kill();
        return reject_all(commands, "cannot read proc-receive stderr".to_owned());
    }
    let worker_commands: Vec<ProcReceiveCommand> = commands.to_vec();
    let worker_options: Vec<String> = options.values.to_vec();
    let worker_negotiated = options.negotiated;
    let worker_interrupt = interrupt.clone();
    let worker = std::thread::Builder::new()
        .name("ruk-proc-receive-converse".to_owned())
        .spawn(move || {
            converse(
                Box::new(stdin) as Box<dyn Write + Send>,
                Box::new(stdout) as Box<dyn Read + Send>,
                &worker_commands,
                &worker_options,
                worker_negotiated,
                kind,
                &worker_interrupt,
            )
        });
    let worker = match worker {
        Ok(handle) => handle,
        Err(_) => {
            let _ = child.kill();
            return reject_all(commands, "cannot run proc-receive conversation".to_owned());
        }
    };
    let deadline = Instant::now() + hooks.timeout();
    let mut cancelled = false;
    loop {
        if worker.is_finished() {
            break;
        }
        if interrupt.check("running proc-receive hook").is_err() {
            cancelled = true;
            let _ = child.kill();
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(CONVERSE_POLL);
    }
    reap(&mut child);
    let stderr = stderr_rx.recv_timeout(CONVERSE_GRACE).unwrap_or_default();
    let stderr_text = String::from_utf8_lossy(&stderr);
    if !stderr_text.trim().is_empty() {
        tracing::warn!(
            "proc-receive hook stderr: {}",
            stderr_text
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(512)
                .collect::<String>()
        );
    }
    if cancelled {
        return reject_all(commands, "proc-receive hook was cancelled".to_owned());
    }
    match worker.join_timeout(CONVERSE_GRACE) {
        Some(Ok(verdicts)) => verdicts,
        Some(Err(err)) => reject_all(commands, err.to_string()),
        None => reject_all(
            commands,
            format!(
                "proc-receive hook timed out after {}s",
                hooks.timeout().as_secs()
            ),
        ),
    }
}

/// Reaps a hook child, killing it first when it lingers past its report.
///
/// A hook that answered should exit on its own; the kill covers the
/// lingerer without stalling the push on an unbounded wait.
fn reap(child: &mut std::process::Child) {
    let deadline = Instant::now() + CONVERSE_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(CONVERSE_POLL);
    }
}

/// One [`ProcVerdict::FallThrough`] per command.
fn fall_through_all(commands: &[ProcReceiveCommand]) -> Vec<ProcVerdict> {
    commands.iter().map(|_| ProcVerdict::FallThrough).collect()
}

/// One [`ProcVerdict::Rejected`] per command.
fn reject_all(commands: &[ProcReceiveCommand], reason: String) -> Vec<ProcVerdict> {
    commands
        .iter()
        .map(|_| ProcVerdict::Rejected {
            reason: reason.clone(),
        })
        .collect()
}

/// Stable per-command conversation state.
struct Pending {
    accepted: bool,
    fall_through: bool,
    alternate: Option<AlternateRef>,
    reason: Option<String>,
    returned: bool,
}

/// Speaks the oracle's hook protocol: version negotiation, the diverted
/// commands, the push options when the hook asks, then the `ok`/`ng`/
/// `option` report.
///
/// Boxed pipes keep the conversation testable in-memory and movable into
/// its watchdog thread. On any protocol break every unanswered command is
/// refused, while commands the hook already answered keep their verdicts,
/// exactly like `read_proc_receive_report`.
fn converse(
    mut stdin: Box<dyn Write + Send>,
    stdout: Box<dyn Read + Send>,
    commands: &[ProcReceiveCommand],
    push_options: &[String],
    offer_push_options: bool,
    kind: HashKind,
    interrupt: &Interrupt,
) -> Result<Vec<ProcVerdict>, GitError> {
    // The version line carries its LF inside the frame; commands and
    // options travel without one, exactly like the oracle's
    // `packet_write_fmt_gently` calls. Forgejo parses the raw payloads
    // (`strings.SplitN(..., " ", 3)`, `pushoptions.Parse`), so a stray LF
    // would corrupt the ref name and option values.
    let mut out = Vec::new();
    if offer_push_options {
        encode_data(&mut out, b"version=1\0push-options\n")?;
    } else {
        encode_data(&mut out, b"version=1\n")?;
    }
    encode_flush(&mut out);
    write_phase(&mut stdin, &out, "hook version")?;

    let mut pkt = PktReader::new(stdout, interrupt.clone());
    let version_line = read_line(&mut pkt, "hook version")?;
    let hook_wants_options = parse_version(&version_line)?;
    read_flush(&mut pkt, "hook version")?;

    let mut out = Vec::new();
    for command in commands {
        encode_data(
            &mut out,
            format!(
                "{} {} {}",
                command.old.to_hex(),
                command.new.to_hex(),
                String::from_utf8_lossy(&command.name)
            )
            .as_bytes(),
        )?;
    }
    encode_flush(&mut out);
    write_phase(&mut stdin, &out, "hook commands")?;

    if hook_wants_options {
        let mut out = Vec::new();
        for option in push_options {
            encode_data(&mut out, option.as_bytes())?;
        }
        encode_flush(&mut out);
        write_phase(&mut stdin, &out, "hook options")?;
    }

    let mut pending: Vec<Pending> = commands
        .iter()
        .map(|_| Pending {
            accepted: false,
            fall_through: false,
            alternate: None,
            reason: None,
            returned: false,
        })
        .collect();
    loop {
        let packet = pkt
            .read_packet()
            .map_err(|err| broken(format!("reading the proc-receive report: {err}")))?;
        match packet {
            Packet::Flush => break,
            Packet::Delimiter | Packet::ResponseEnd => {
                return Err(broken("proc-receive sent an unexpected framing packet"));
            }
            Packet::Data(_) => {}
        }
        let line = packet.line().unwrap_or_default();
        let text =
            std::str::from_utf8(line).map_err(|_| broken("proc-receive sent a bad report line"))?;
        report_line(text, commands, &mut pending, kind)?;
    }
    Ok(pending
        .into_iter()
        .map(|state| {
            if state.fall_through {
                ProcVerdict::FallThrough
            } else if let Some(reason) = state.reason {
                ProcVerdict::Rejected { reason }
            } else if state.accepted {
                ProcVerdict::Accepted {
                    alternate: state.alternate,
                }
            } else {
                ProcVerdict::Rejected {
                    reason: "proc-receive failed to report status".to_owned(),
                }
            }
        })
        .collect())
}

/// Writes one phase and flushes the pipe so the hook's blocking read
/// observes it.
fn write_phase(pipe: &mut dyn Write, bytes: &[u8], what: &str) -> Result<(), GitError> {
    pipe.write_all(bytes).map_err(|err| GitError::Io {
        detail: format!("writing the proc-receive {what}: {err}"),
    })?;
    pipe.flush().map_err(|err| GitError::Io {
        detail: format!("flushing the proc-receive {what}: {err}"),
    })?;
    Ok(())
}

/// Reads one data line with its trailing LF removed.
fn read_line<R: Read>(pkt: &mut PktReader<R>, what: &str) -> Result<Vec<u8>, GitError> {
    match pkt.read_packet()? {
        Packet::Data(_) => Ok(pkt.last_line().unwrap_or_default().to_vec()),
        other => Err(broken(format!("expected {what}, got {other:?}"))),
    }
}

/// Reads the flush ending a hook protocol phase.
fn read_flush<R: Read>(pkt: &mut PktReader<R>, what: &str) -> Result<(), GitError> {
    match pkt.read_packet()? {
        Packet::Flush => Ok(()),
        other => Err(broken(format!("expected {what} flush, got {other:?}"))),
    }
}

/// Parses the hook's `version=1[\0<features>]` line, returning whether it
/// asked for push options. Only version 1 is supported: the oracle also
/// tolerates 0, but no hook in the wild sends it and negotiating down
/// would only mask skew.
fn parse_version(line: &[u8]) -> Result<bool, GitError> {
    let text = std::str::from_utf8(line).map_err(|_| broken("proc-receive sent a bad version"))?;
    let (version, features) = match text.split_once('\0') {
        Some((version, features)) => (version, Some(features)),
        None => (text, None),
    };
    if version != "version=1" {
        return Err(broken(format!(
            "unsupported proc-receive version {version:?}"
        )));
    }
    Ok(features.is_some_and(|list| list.split(' ').any(|token| token.trim() == "push-options")))
}

/// Folds one `ok`/`ng`/`option` report line into the pending verdicts.
///
/// Malformed lines and reports for unknown refs fail the conversation
/// without poisoning commands the hook already answered, like the oracle.
fn report_line(
    line: &str,
    commands: &[ProcReceiveCommand],
    pending: &mut [Pending],
    kind: HashKind,
) -> Result<(), GitError> {
    if let Some(body) = line.strip_prefix("option ") {
        return report_option(body, pending, kind);
    }
    let (status, rest) = line.split_once(' ').ok_or_else(|| {
        broken(format!(
            "proc-receive sent an incomplete status line: {line:?}"
        ))
    })?;
    if status != "ok" && status != "ng" {
        return Err(broken(format!("proc-receive sent bad status {status:?}")));
    }
    let (name, reason) = match rest.split_once(' ') {
        Some((name, reason)) => (name, Some(reason)),
        None => (rest, None),
    };
    let index = commands
        .iter()
        .position(|command| command.name == name.as_bytes())
        .ok_or_else(|| broken(format!("proc-receive answered unknown ref {name:?}")))?;
    let state = &mut pending[index];
    state.returned = true;
    if status == "ng" {
        state.reason = Some(reason.unwrap_or("failed").to_owned());
    } else {
        state.accepted = true;
    }
    Ok(())
}

/// Folds one `option` line into the most recent `ok`, like the oracle's
/// hint tracking. An option with no preceding `ok` fails the
/// conversation. Unparsable OIDs are ignored, matching the oracle's
/// guarded option parsing.
fn report_option(line: &str, pending: &mut [Pending], kind: HashKind) -> Result<(), GitError> {
    let state = pending
        .iter_mut()
        .rfind(|state| state.returned && state.accepted)
        .ok_or_else(|| broken("proc-receive sent 'option' without a matching 'ok'"))?;
    let (key, value) = match line.split_once(' ') {
        Some((key, value)) => (key, Some(value)),
        None => (line, None),
    };
    match key {
        "fall-through" => state.fall_through = true,
        "forced-update" => {
            if let Some(alternate) = state.alternate.as_mut() {
                alternate.forced = true;
            }
        }
        "refname" => {
            let Some(name) = value else {
                return Err(broken("proc-receive sent 'option refname' without a name"));
            };
            state.alternate = Some(AlternateRef {
                refname: name.as_bytes().to_vec(),
                old_oid: None,
                new_oid: None,
                forced: false,
            });
        }
        "old-oid" => {
            if let (Some(name), Some(alternate)) = (value, state.alternate.as_mut())
                && let Ok(oid) = parse_oid_for(name, kind)
            {
                alternate.old_oid = Some(oid);
            }
        }
        "new-oid" => {
            if let (Some(name), Some(alternate)) = (value, state.alternate.as_mut())
                && let Ok(oid) = parse_oid_for(name, kind)
            {
                alternate.new_oid = Some(oid);
            }
        }
        _ => {}
    }
    Ok(())
}

/// A [`std::thread::JoinHandle`] extension bounding the final reap: after
/// the child is dead its conversation thread can only be stuck on
/// grandchildren-held pipes, so a bounded wait replaces an unbounded one.
trait JoinTimeout<T> {
    /// Joins within `grace`, returning `None` when the thread outlives it.
    fn join_timeout(self, grace: Duration) -> Option<Result<T, GitError>>;
}

impl<T> JoinTimeout<T> for std::thread::JoinHandle<Result<T, GitError>> {
    fn join_timeout(self, grace: Duration) -> Option<Result<T, GitError>> {
        let deadline = Instant::now() + grace;
        while !self.is_finished() {
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(CONVERSE_POLL);
        }
        match self.join() {
            Ok(result) => Some(result),
            Err(_) => Some(Err(broken("the proc-receive conversation panicked"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruk_core::ids::HashKind;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static PROC_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn command(name: &str) -> ProcReceiveCommand {
        ProcReceiveCommand {
            old: oid(ZERO_SHA1),
            new: oid(FOUR),
            name: name.as_bytes().to_vec(),
        }
    }

    /// Frames transcript lines the way a hook would send them.
    fn transcript(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            if *line == "FLUSH" {
                encode_flush(&mut out);
            } else {
                encode_data(&mut out, line.as_bytes()).expect("frame");
            }
        }
        out
    }

    /// Shared in-memory sink recovering the bytes `converse` writes.
    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Sink {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().expect("sink").clone()
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Drives [`converse`] against an in-memory hook transcript, returning
    /// the verdicts plus every byte the server wrote.
    fn drive(
        hook_output: Vec<u8>,
        commands: &[ProcReceiveCommand],
        options: &[String],
        offer: bool,
    ) -> (Result<Vec<ProcVerdict>, GitError>, Vec<u8>) {
        let sink = Sink::default();
        let stdin = Box::new(sink.clone()) as Box<dyn Write + Send>;
        let stdout = Box::new(Cursor::new(hook_output)) as Box<dyn Read + Send>;
        let result = converse(
            stdin,
            stdout,
            commands,
            options,
            offer,
            HashKind::Sha1,
            &Interrupt::none(),
        );
        (result, sink.bytes())
    }

    /// Reads every frame the server wrote during a drive.
    fn written_frames(written: &[u8]) -> Vec<Vec<u8>> {
        let mut pkt = PktReader::new(written, Interrupt::none());
        let mut frames = Vec::new();
        loop {
            match pkt.read_packet().expect("frame") {
                Packet::Flush => frames.push(Vec::new()),
                Packet::Data(payload) => {
                    frames.push(payload.strip_suffix(b"\n").unwrap_or(payload).to_vec())
                }
                other => panic!("unexpected {other:?}"),
            }
            if pkt.get_mut().is_empty() {
                break;
            }
        }
        frames
    }

    /// The server speaks version, commands, then options in order, each
    /// phase flush-terminated, with no stray LFs on commands or options.
    #[test]
    fn server_phases_are_ordered_and_framed() {
        let hook = transcript(&[
            "version=1\0push-options\n",
            "FLUSH",
            "ok refs/for/main\n",
            "FLUSH",
        ]);
        let options = vec!["topic=my-topic".to_owned()];
        let (_, written) = drive(hook, &[command("refs/for/main")], &options, true);
        let frames = written_frames(&written);
        assert_eq!(
            frames,
            vec![
                b"version=1\0push-options".to_vec(),
                Vec::new(),
                format!("{ZERO_SHA1} {FOUR} refs/for/main").into_bytes(),
                Vec::new(),
                b"topic=my-topic".to_vec(),
                Vec::new(),
            ]
        );
    }

    /// A Forgejo-shaped answer (`ok` plus the review-ref options) accepts
    /// the push and records the review ref.
    #[test]
    fn hook_ok_with_review_ref_accepts() {
        let hook = transcript(&[
            "version=1\n",
            "FLUSH",
            "ok refs/for/main\n",
            "option refname refs/pull/1/head\n",
            &format!("option new-oid {FOUR}\n"),
            "FLUSH",
        ]);
        let (result, _) = drive(hook, &[command("refs/for/main")], &[], false);
        let verdicts = result.expect("conversation");
        match &verdicts[0] {
            ProcVerdict::Accepted { alternate } => {
                let alternate = alternate.as_ref().expect("review ref");
                assert_eq!(alternate.refname, b"refs/pull/1/head");
                assert_eq!(alternate.new_oid, Some(oid(FOUR)));
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    /// `ng` refuses, and commands the hook never answers are refused with
    /// the oracle's message.
    #[test]
    fn hook_ng_and_silence_refuse() {
        let hook = transcript(&[
            "version=1\n",
            "FLUSH",
            "ng refs/for/main no review for you\n",
            "FLUSH",
        ]);
        let (result, _) = drive(
            hook,
            &[command("refs/for/main"), command("refs/for/other")],
            &[],
            false,
        );
        let verdicts = result.expect("conversation");
        match &verdicts[0] {
            ProcVerdict::Rejected { reason } => assert!(reason.contains("no review")),
            other => panic!("unexpected verdict: {other:?}"),
        }
        match &verdicts[1] {
            ProcVerdict::Rejected { reason } => {
                assert_eq!(reason, "proc-receive failed to report status");
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    /// `option fall-through` returns the command to the normal path.
    #[test]
    fn hook_fall_through_returns_to_normal_path() {
        let hook = transcript(&[
            "version=1\n",
            "FLUSH",
            "ok refs/heads/main\n",
            "option fall-through\n",
            "FLUSH",
        ]);
        let (result, _) = drive(hook, &[command("refs/heads/main")], &[], false);
        let verdicts = result.expect("conversation");
        assert!(matches!(verdicts[0], ProcVerdict::FallThrough));
    }

    /// A hook that hangs up mid-report fails the conversation.
    #[test]
    fn hook_hangup_fails_the_conversation() {
        let hook = transcript(&["version=1\n", "FLUSH", "ok refs/for/main\n"]);
        let (result, _) = drive(hook, &[command("refs/for/main")], &[], false);
        assert!(result.is_err(), "hangup should fail, got {result:?}");
    }

    /// Push options travel to the hook only when it asks: the server
    /// offers the feature, the hook answers `push-options`, and the
    /// options follow before the report.
    #[test]
    fn hook_negotiated_push_options_are_forwarded() {
        let hook = transcript(&[
            "version=1\0push-options\n",
            "FLUSH",
            "ok refs/for/main\n",
            "FLUSH",
        ]);
        let options = vec!["topic=my-topic".to_owned()];
        let (result, _) = drive(hook, &[command("refs/for/main")], &options, true);
        assert!(matches!(
            result.expect("conversation")[0],
            ProcVerdict::Accepted { .. }
        ));
    }

    fn hook_repo() -> std::path::PathBuf {
        let id = PROC_TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ruk-proc-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(dir.join("hooks")).expect("hooks dir");
        dir
    }

    /// With no hook script installed every command falls through to the
    /// normal path.
    #[test]
    fn missing_hook_falls_through() {
        let repo = hook_repo();
        let options = PushOptions {
            values: &[],
            negotiated: false,
        };
        let verdicts = run_proc_receive(
            &ReceiveHooks::for_repo(repo),
            None,
            &[command("refs/for/main")],
            &options,
            HashKind::Sha1,
            &Interrupt::none(),
        );
        assert!(matches!(verdicts[0], ProcVerdict::FallThrough));
    }

    /// A hook that exits without speaking refuses the diverted refs
    /// in-band instead of aborting the push.
    #[test]
    fn crashing_hook_refuses_in_band() {
        let repo = hook_repo();
        let path = repo.join("hooks").join("proc-receive");
        std::fs::write(&path, "#!/bin/sh\nexit 1\n").expect("hook script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("hook executable");
        let options = PushOptions {
            values: &[],
            negotiated: false,
        };
        let verdicts = run_proc_receive(
            &ReceiveHooks::for_repo(repo).with_timeout(Duration::from_secs(10)),
            None,
            &[command("refs/for/main")],
            &options,
            HashKind::Sha1,
            &Interrupt::none(),
        );
        assert!(matches!(verdicts[0], ProcVerdict::Rejected { .. }));
    }

    #[test]
    fn prefix_matching_mirrors_the_oracle() {
        assert!(is_proc_receive_ref(b"refs/for/main"));
        assert!(is_proc_receive_ref(b"refs/for/main/topic"));
        assert!(is_proc_receive_ref(b"refs/pull/1/head"));
        assert!(!is_proc_receive_ref(b"refs/heads/main"));
        assert!(!is_proc_receive_ref(b"refs/forum/main"));
        // A bare prefix matches like the oracle (`!*remains`); the hook
        // then refuses it (Forgejo: empty branch name is no review).
        assert!(is_proc_receive_ref(b"refs/for"));
    }
}
