//! Receive-pack hook phases over quarantine staging.
//!
//! During `receive-pack`, pushed objects land in a quarantine directory
//! first: the pack stages into memory as [`StagedPack`](super::pack::StagedPack)
//! (invisible to every reader until publication), and
//! [`stage_quarantine`] additionally materializes those staged payloads as
//! loose objects plus a manifest under a per-push directory. Hook scripts
//! observe the push through that directory via `GIT_QUARANTINE_PATH`, and
//! the staged objects promote into the store through one
//! [`Store::publish`](ruk_core::store::Store::publish) only after every
//! refusing phase passes. Dropping the staging (and the directory, via
//! [`Quarantine`]'s `Drop`) publishes nothing.
//!
//! Hook resolution is `<repo_dir>/hooks/<name>` for `pre-receive`, `update`
//! and `post-receive`, executed directly (no shell) with the repository
//! directory as cwd. That single convention covers three layouts:
//!
//! - a Ruk repository root (hooks beside `.ruk`),
//! - a legacy bare `.git` directory served as `repo_dir` (its hooks
//!   already live at `.git/hooks/`, and Git-format endpoints are refused
//!   elsewhere, so no special case is needed),
//! - Forgejo repositories: Forgejo generates dispatcher scripts at exactly
//!   `<repo>/hooks/<name>` which chain `hooks/<name>.d/*` (including its
//!   internal `gitea` hook) — see `forgejo/modules/git/hook_generate.go`.
//!   Executing the top-level script runs the whole chain, so no separate
//!   `.d` handling exists here.
//!
//! Phase semantics mirror `git-receive-pack` (`git/builtin/receive-pack.c`):
//!
//! - `pre-receive` reads `<old> <new> <ref>` lines on stdin; a nonzero exit
//!   refuses the whole push (every live ref reports `ng`).
//! - `update` takes `<ref> <old> <new>` as argv (this is why Forgejo's own
//!   `update` dispatcher forwards `$1 $2 $3`); a nonzero exit refuses only
//!   that ref, and the remaining refs still land.
//! - `post-receive` reads the landed `<old> <new> <ref>` lines on stdin
//!   after refs are updated; failure is relayed to the server's stderr and
//!   never fails the push (protocol v0's report has no sideband slot for
//!   it, so the message goes to server logs instead of the client).
//!
//! A missing script is a pass. Hooks inherit the server's environment plus
//! `GIT_QUARANTINE_PATH`, `GIT_OBJECT_DIRECTORY` (the quarantine
//! `objects/` dir, so hook `git` commands transparently see staged
//! objects), `GIT_DIR` (the repository directory), and
//! `RUK_QUARANTINE_MANIFEST` (the manifest path). Hook stdout is discarded;
//! hook stderr supplies the refusal message. Every hook runs under
//! [`HOOK_TIMEOUT`]; expiry kills the hook and refuses fail-closed.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ruk_core::store::ObjectKind;

use super::pack::StagedPack;
use crate::GitError;

/// Wall-clock budget for one hook execution.
///
/// A daemon-level timeout is the wrong source here: the daemon's
/// handshake/frame deadlines guard IPC framing at millisecond scale, while
/// a hook may legitimately compile, lint, or scan a push for many seconds.
/// Sixty seconds matches Git hosting practice for server hooks.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(60);

/// Server-side hook configuration for one `receive-pack` session.
///
/// [`ReceiveHooks::disabled`] runs no hooks and creates no quarantine
/// directory (the staging still stays unpublished until the trivially
/// passing phases, so the no-hooks path behaves exactly as before).
/// [`ReceiveHooks::for_repo`] enables the three phases against a
/// repository directory holding `hooks/`.
#[derive(Clone, Debug)]
pub struct ReceiveHooks {
    repo_dir: Option<PathBuf>,
    timeout: Duration,
    quarantine_parent: Option<PathBuf>,
}

impl ReceiveHooks {
    /// No hooks: every phase passes without touching the filesystem.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            repo_dir: None,
            timeout: HOOK_TIMEOUT,
            quarantine_parent: None,
        }
    }

    /// Run hooks from `<repo_dir>/hooks/` with the default timeout and the
    /// system temp directory as the quarantine parent.
    #[must_use]
    pub fn for_repo(repo_dir: PathBuf) -> Self {
        Self {
            repo_dir: Some(repo_dir),
            timeout: HOOK_TIMEOUT,
            quarantine_parent: None,
        }
    }

    /// Overrides the per-hook wall-clock budget. A zero timeout falls back
    /// to [`HOOK_TIMEOUT`] rather than refusing every hook instantly.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = if timeout.is_zero() {
            HOOK_TIMEOUT
        } else {
            timeout
        };
        self
    }

    /// Overrides the directory quarantine staging is created under
    /// (defaults to the system temp directory).
    #[must_use]
    pub fn with_quarantine_parent(mut self, dir: PathBuf) -> Self {
        self.quarantine_parent = Some(dir);
        self
    }

    /// Whether any hook phase can run.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.repo_dir.is_some()
    }

    /// The per-hook wall-clock budget bounding one hook conversation.
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The repository directory hooks resolve against, if any.
    #[must_use]
    pub fn repo_dir(&self) -> Option<&Path> {
        self.repo_dir.as_deref()
    }

    /// The script path for one hook phase, if hooks are enabled.
    ///
    /// The name is always one of the three fixed phase names chosen by the
    /// caller in this module; no caller-controlled text reaches the path.
    pub(crate) fn hook_path(&self, name: &str) -> Option<PathBuf> {
        self.repo_dir
            .as_deref()
            .map(|root| root.join("hooks").join(name))
    }
}

/// One push's quarantine directory: staged objects materialized as loose
/// objects plus a manifest for hook inspection.
///
/// Removing the value deletes the directory best-effort, so every early
/// return (refusal, unpack failure, cancellation) cleans up without a
/// dedicated call.
#[derive(Debug)]
pub(crate) struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// The directory exposed as `GIT_QUARANTINE_PATH`.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The loose-object store exposed as `GIT_OBJECT_DIRECTORY`.
    pub(crate) fn objects_dir(&self) -> PathBuf {
        self.dir.join("objects")
    }

    /// The manifest listing every materialized object, exposed as
    /// `RUK_QUARANTINE_MANIFEST`.
    pub(crate) fn manifest(&self) -> PathBuf {
        self.dir.join("manifest")
    }
}

impl Drop for Quarantine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Materializes `staged` as loose objects plus a manifest under a fresh
/// per-push directory, or returns `None` when hooks are disabled.
///
/// The directory is created even with no staged objects (delete-only
/// pushes still run hooks with `GIT_QUARANTINE_PATH` set, mirroring the
/// oracle). Total bytes are bounded by the pack ingest limits that already
/// bounded the staging, so no second quota is enforced here.
pub(crate) fn stage_quarantine(
    hooks: &ReceiveHooks,
    staged: Option<&StagedPack>,
) -> Result<Option<Quarantine>, GitError> {
    if !hooks.enabled() {
        return Ok(None);
    }
    let parent: PathBuf = hooks
        .quarantine_parent
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    let id = QUARANTINE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = parent.join(format!("ruk-quarantine-{}-{id}", std::process::id()));
    let io = |what: &str, err: std::io::Error| GitError::Io {
        detail: format!("quarantine staging {what}: {err}"),
    };
    std::fs::create_dir_all(dir.join("objects"))
        .map_err(|err| io("creating the quarantine directory", err))?;
    let mut manifest = String::from("# ruk-quarantine v1\n");
    if let Some(staged) = staged {
        for oid in staged.oids() {
            let Some((kind, payload)) = staged.payload(*oid) else {
                continue;
            };
            // Packs never carry native conflicts (the pack writer refuses
            // them), so a conflict kind has nothing Git-shaped to
            // materialize; publication still carries it, only hook
            // inspection skips it.
            let Some(type_name) = git_type_name(kind) else {
                continue;
            };
            let hex = oid.to_hex();
            write_loose(&dir.join("objects"), &hex, type_name, payload)?;
            manifest.push_str(&format!("{hex} {type_name} {}\n", payload.len()));
        }
    }
    std::fs::write(dir.join("manifest"), manifest.as_bytes())
        .map_err(|err| io("writing the quarantine manifest", err))?;
    Ok(Some(Quarantine { dir }))
}

/// Git loose-object name for one staged kind; `None` has no Git spelling.
fn git_type_name(kind: ObjectKind) -> Option<&'static str> {
    match kind {
        ObjectKind::Blob => Some("blob"),
        ObjectKind::Tree => Some("tree"),
        ObjectKind::Commit => Some("commit"),
        ObjectKind::Tag => Some("tag"),
        ObjectKind::Conflict => None,
    }
}

/// Writes one loose object: `objects/xx/rest` holding the zlib of
/// `<type> <len>\0<payload>`, readable by any hook `git` command pointed
/// at the quarantine directory.
fn write_loose(objects: &Path, hex: &str, type_name: &str, payload: &[u8]) -> Result<(), GitError> {
    let io = |what: &str, err: std::io::Error| GitError::Io {
        detail: format!("quarantine staging {what}: {err}"),
    };
    let (fan, rest) = hex.split_at(2);
    std::fs::create_dir_all(objects.join(fan))
        .map_err(|err| io("creating a quarantine fanout", err))?;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    write!(encoder, "{type_name} {}\0", payload.len())
        .map_err(|err| io("framing a quarantine object", err))?;
    encoder
        .write_all(payload)
        .map_err(|err| io("framing a quarantine object", err))?;
    let bytes = encoder
        .finish()
        .map_err(|err| io("deflating a quarantine object", err))?;
    std::fs::write(objects.join(fan).join(rest), bytes)
        .map_err(|err| io("writing a quarantine object", err))?;
    Ok(())
}

/// Runs one hook phase: `None` when the hook passes or is absent,
/// `Some(reason)` when it refuses.
///
/// `push_options` reaches the hook as `GIT_PUSH_OPTION_COUNT` plus
/// `GIT_PUSH_OPTION_<i>` only when the client negotiated `push-options`,
/// mirroring the oracle's `run_receive_hook` environment (which exports
/// nothing when the capability was not negotiated, not even a zero
/// count). Spawn failures and timeouts refuse fail-closed with an
/// explanatory reason; they never pass silently and never abort the
/// protocol with an error (the refusal travels in-band as `ng` lines,
/// like any hook decline). Direct exec, never a shell: `args` cannot
/// interpolate.
pub(crate) fn run_hook(
    hooks: &ReceiveHooks,
    quarantine: Option<&Quarantine>,
    name: &str,
    args: &[String],
    stdin: Option<&[u8]>,
    push_options: &[String],
    negotiated: bool,
) -> Option<String> {
    let repo_dir = hooks.repo_dir.as_deref()?;
    let path = hooks.hook_path(name)?;
    // `exists` follows symlinks: a dangling link is no hook, an executable
    // target runs. The name is a fixed phase literal, so no traversal or
    // escape from `<repo>/hooks/` is expressible.
    if !path.exists() {
        return None;
    }
    match execute(
        &path,
        repo_dir,
        quarantine,
        args,
        stdin,
        push_options,
        negotiated,
        hooks.timeout,
    ) {
        Ok(Outcome::Pass) => None,
        Ok(Outcome::Declined { stderr }) => Some(decline_message(name, &stderr)),
        Err(err) => Some(format!("{name} hook failed: {}", shorten(&err.to_string()))),
    }
}

/// Applies the shared hook environment: quarantine inspection, the
/// repository directory, and the client's push options.
///
/// One constructor so every phase (`pre-receive`, `update`,
/// `post-receive`, `proc-receive`) exports identical variables.
/// `GIT_PUSH_OPTION_COUNT` (plus `GIT_PUSH_OPTION_<i>`) is exported only
/// when the client negotiated `push-options`, matching the oracle: an
/// unnegotiated push exports neither the count nor any option.
pub(crate) fn apply_hook_env(
    cmd: &mut Command,
    repo_dir: &Path,
    quarantine: Option<&Quarantine>,
    push_options: &[String],
    negotiated: bool,
) {
    if let Some(q) = quarantine {
        cmd.env("GIT_QUARANTINE_PATH", q.dir());
        cmd.env("GIT_OBJECT_DIRECTORY", q.objects_dir());
        cmd.env("RUK_QUARANTINE_MANIFEST", q.manifest());
    }
    cmd.env("GIT_DIR", repo_dir);
    if negotiated {
        cmd.env("GIT_PUSH_OPTION_COUNT", push_options.len().to_string());
        for (index, option) in push_options.iter().enumerate() {
            cmd.env(format!("GIT_PUSH_OPTION_{index}"), option);
        }
    }
}

enum Outcome {
    Pass,
    Declined { stderr: String },
}

/// Grace period for hook stderr to arrive once its child is reaped.
///
/// Grandchildren that outlive a killed hook can hold the pipe open; after
/// this grace their output is dropped and the reader abandoned instead of
/// hanging the push. The grace only ever binds pathological hooks: a
/// reaped child's own output is already in the pipe and arrives instantly.
const STDERR_GRACE: Duration = Duration::from_secs(5);

/// Spawns the hook script directly and waits under `timeout`, feeding
/// `stdin` (closed before waiting) and capturing stderr on a reader thread
/// so a chatty hook cannot deadlock a full pipe.
///
/// The reader is deliberately detached rather than scoped: a scoped join
/// would wait out grandchildren holding stderr open even after the timed
/// out child is killed and reaped. Here the bytes travel back over a
/// channel under [`STDERR_GRACE`]; a reader that never delivers is
/// abandoned (it exits on its own once every inheritor finally exits) and
/// the push proceeds.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the hook spawn shape: paths, quarantine, args, input, options, and timeout"
)]
fn execute(
    path: &Path,
    repo_dir: &Path,
    quarantine: Option<&Quarantine>,
    args: &[String],
    stdin_bytes: Option<&[u8]>,
    push_options: &[String],
    negotiated: bool,
    timeout: Duration,
) -> Result<Outcome, GitError> {
    let mut cmd = Command::new(path);
    cmd.args(args);
    cmd.current_dir(repo_dir);
    apply_hook_env(&mut cmd, repo_dir, quarantine, push_options, negotiated);
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    // Hook stdout has no v0 report slot (only `ok`/`ng` lines travel back),
    // so it is discarded; stderr is captured for refusal reasons and the
    // post-receive relay.
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|err| GitError::Io {
        detail: format!("cannot execute {}: {err}", path.display()),
    })?;
    let stdin_pipe = child.stdin.take();
    let stderr_pipe = child.stderr.take();
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ruk-hook-stderr".to_owned())
        .spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = stderr_pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            let _ = stderr_tx.send(buf);
        })
        .map_err(|err| GitError::Io {
            detail: format!("spawning the hook stderr reader: {err}"),
        })?;
    // The stdin write runs off-thread: a hook that stays alive without
    // reading stdin must not wedge the write past the hook timeout. The
    // input is already bounded (one line per update command); dropping
    // the pipe afterwards delivers EOF, and killing the child turns a
    // stuck write into `EPIPE` so the writer exits on its own.
    if let (Some(mut pipe), Some(input)) = (stdin_pipe, stdin_bytes) {
        let input = input.to_vec();
        std::thread::Builder::new()
            .name("ruk-hook-stdin".to_owned())
            .spawn(move || {
                let _ = pipe.write_all(&input);
            })
            .map_err(|err| GitError::Io {
                detail: format!("spawning the hook stdin writer: {err}"),
            })?;
    }
    // A timeout kill reaps the direct child; only surviving grandchildren
    // can still hold stderr open past this point, and the grace below
    // bounds that wait instead of hanging the push.
    let status = match wait_bounded(&mut child, timeout) {
        Ok(status) => status,
        Err(err) => {
            let _ = stderr_rx.recv_timeout(STDERR_GRACE);
            return Err(err);
        }
    };
    let stderr = stderr_rx.recv_timeout(STDERR_GRACE).unwrap_or_default();
    if status.success() {
        return Ok(Outcome::Pass);
    }
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    Ok(Outcome::Declined { stderr })
}

/// Waits for the hook, killing it past `timeout`. The kill is best-effort;
/// the reap after it reports the timeout either way.
fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, GitError> {
    let io = |detail: String| GitError::Io { detail };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Err(err) => return Err(io(format!("waiting for the hook: {err}"))),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io(format!("timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Refusal message from hook stderr: its first non-blank line, flattened
/// onto one short line for the `ng` report.
fn decline_message(name: &str, stderr: &str) -> String {
    match stderr.lines().map(str::trim).find(|line| !line.is_empty()) {
        Some(line) => format!("{name} hook declined: {}", shorten(line)),
        None => format!("{name} hook declined"),
    }
}

/// Flattens a message onto one short line for `ng` reasons.
fn shorten(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}
