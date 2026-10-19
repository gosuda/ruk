//! The hooks runner.
//!
//! | hook | call site | status |
//! | --- | --- | --- |
//! | `pre-commit` | `commit`, amend, merge conclude | implemented (`--no-verify` skips) |
//! | `commit-msg` | `commit`, amend, merge conclude | implemented over a message file the hook may rewrite (`--no-verify` skips) |
//! | `post-commit` | `commit`, amend, merge conclude | implemented |
//! | `pre-push` | `push` | implemented with `<remote> <url>` (`--no-verify` skips) |
//! | `post-merge` | `merge` | implemented with the squash flag |
//! | `post-checkout` | `checkout`, `switch`, orphan | implemented with `<old> <new> <flag>` |
//!
//! Lookup mirrors `find_hook`: `core.hooksPath` (relative paths resolve
//! against the repository root) beats `.ruk/hooks` beats `.git/hooks`.
//! Only existing executable files match; `.sample` files and missing hooks
//! read as absent and succeed silently. A non-zero exit blocks the
//! operation with the hook's status, and hook stderr rides `ctx.stderr`.
//!
//! Oracle anchors: `git/hook.c` (`find_hook`, `run_hooks_opt`).

use std::path::PathBuf;

use ruk_git::GitError;
use ruk_git::transport::push::PushUpdate;

use super::Ctx;

/// Hook names this runner dispatches. Anything else with a `/` or NUL is
/// refused; unknown bare names simply never match a file.
const KNOWN_HOOKS: &[&str] = &[
    "pre-commit",
    "commit-msg",
    "post-commit",
    "pre-push",
    "post-merge",
    "post-checkout",
];

/// Locates one hook file, mirroring `find_hook`: a configured
/// `core.hooksPath` replaces the defaults entirely (no fallback), else
/// `.ruk/hooks` beats `.git/hooks`.
#[must_use]
pub(crate) fn hook_path(ctx: &Ctx, name: &str) -> Option<PathBuf> {
    if !KNOWN_HOOKS.contains(&name) || name.contains('/') || name.contains('\0') {
        return None;
    }
    if let Some(dir) = ctx.config_get("core.hooksPath") {
        let base = if std::path::Path::new(&dir).is_absolute() {
            PathBuf::from(dir)
        } else {
            ctx.root.join(dir)
        };
        let candidate = base.join(name);
        return is_executable(&candidate).then_some(candidate);
    }
    for dir in [
        ctx.root.join(".ruk").join("hooks"),
        ctx.root.join(".git").join("hooks"),
    ] {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Reports whether `path` is an existing executable regular file.
fn is_executable(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Runs one hook with `args` and `stdin`, mirroring `run_hooks_opt`.
fn run_hook(ctx: &mut Ctx, name: &str, args: &[&str], stdin: &[u8]) -> Result<(), GitError> {
    let Some(path) = hook_path(ctx, name) else {
        return Ok(());
    };
    let mut child = std::process::Command::new(&path)
        .args(args)
        .current_dir(&ctx.file_base)
        .envs(ctx.env.vars.clone())
        .env("GIT_DIR", ctx.root.join(".ruk"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| GitError::Io {
            detail: format!("cannot run hook {name:?}: {err}"),
        })?;
    if !stdin.is_empty() {
        use std::io::Write as _;
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(stdin);
        }
    }
    let output = child.wait_with_output().map_err(|err| GitError::Io {
        detail: format!("cannot read hook {name:?}: {err}"),
    })?;
    if !output.stderr.is_empty() {
        ctx.emit_stderr(&output.stderr);
    }
    if output.status.success() {
        return Ok(());
    }
    Err(GitError::Invalid {
        detail: format!("hook {name:?} exited with status {}", output.status),
    })
}

/// Runs `pre-commit`. Callers skip this on `--no-verify` and dry runs.
pub(crate) fn run_pre_commit(ctx: &mut Ctx) -> Result<(), GitError> {
    run_hook(ctx, "pre-commit", &[], &[])
}

/// Runs `commit-msg` over a message file the hook may rewrite, returning
/// the file's bytes after the hook exits, mirroring the oracle's
/// file-backed hand-off. Callers skip this on `--no-verify`.
pub(crate) fn run_commit_msg(ctx: &mut Ctx, message: String) -> Result<String, GitError> {
    if hook_path(ctx, "commit-msg").is_none() {
        return Ok(message);
    }
    let path = ctx
        .root
        .join(".ruk")
        .join(format!("COMMIT_MSG_{}", std::process::id()));
    std::fs::write(&path, message.as_bytes()).map_err(|err| GitError::Io {
        detail: format!("cannot stage the commit message: {err}"),
    })?;
    let arg = path.to_string_lossy().into_owned();
    let outcome = run_hook(ctx, "commit-msg", &[&arg], &[]);
    let after = std::fs::read(&path).map_err(|err| GitError::Io {
        detail: format!("cannot re-read the commit message: {err}"),
    })?;
    let _ = std::fs::remove_file(&path);
    outcome?;
    Ok(String::from_utf8_lossy(&after).into_owned())
}

/// Runs `post-commit` after the new commit exists. A failing hook still
/// reports success: the oracle discards `post-commit` status, and the
/// commit already landed. Hook stderr still rides `ctx.stderr`.
pub(crate) fn run_post_commit(ctx: &mut Ctx) -> Result<(), GitError> {
    let _ = run_hook(ctx, "post-commit", &[], &[]);
    Ok(())
}

/// Runs `post-merge` for a regular merge. No `--squash` spelling exists,
/// so the oracle's squash flag is always `0` here. Like `post-commit`,
/// the status is discarded: the merge already landed.
pub(crate) fn run_post_merge(ctx: &mut Ctx) -> Result<(), GitError> {
    let _ = run_hook(ctx, "post-merge", &["0"], &[]);
    Ok(())
}

/// Runs `post-checkout` with `<old> <new> <flag>`: full hex on both sides
/// (the zero id when unborn). Every call site here is a branch checkout,
/// so the flag is always `1`; path-only checkouts never run the hook.
pub(crate) fn run_post_checkout(ctx: &mut Ctx, old: &str, new: &str) -> Result<(), GitError> {
    run_hook(ctx, "post-checkout", &[old, new, "1"], &[])
}

/// Builds `pre-push` stdin lines from one expanded local ref per update:
/// `<local> <new> <dst> <old>`, mirroring what `send-pack` feeds the
/// hook. Up-to-date refs (`old == new`) emit nothing, the way the oracle
/// skips them. Every other update emits a line even when `locals` runs
/// short: the destination name stands in instead of dropping the ref.
#[must_use]
pub(crate) fn pre_push_stdin(locals: &[String], updates: &[PushUpdate]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, update) in updates.iter().enumerate() {
        if update.old == update.new {
            continue;
        }
        let dst = String::from_utf8_lossy(&update.name).into_owned();
        let local = locals.get(index).map_or(dst.clone(), Clone::clone);
        out.extend_from_slice(
            format!(
                "{local} {} {dst} {}\n",
                update.new.to_hex(),
                update.old.to_hex()
            )
            .as_bytes(),
        );
    }
    out
}

/// Builds `pre-push` stdin lines for deletions: `(delete) <zero> <dst>
/// <old>` per update, the oracle's delete spelling.
#[must_use]
pub(crate) fn pre_push_delete_stdin(updates: &[PushUpdate]) -> Vec<u8> {
    let mut out = Vec::new();
    for update in updates {
        out.extend_from_slice(
            format!(
                "(delete) {} {} {}\n",
                update.new.to_hex(),
                String::from_utf8_lossy(&update.name),
                update.old.to_hex()
            )
            .as_bytes(),
        );
    }
    out
}

/// Builds `pre-push` stdin lines for mirror pushes, where each side names
/// the same ref: `<name> <new> <name> <old>` per update.
#[must_use]
pub(crate) fn pre_push_mirror_stdin(updates: &[PushUpdate]) -> Vec<u8> {
    let mut out = Vec::new();
    for update in updates {
        let name = String::from_utf8_lossy(&update.name);
        out.extend_from_slice(
            format!(
                "{name} {} {name} {}\n",
                update.new.to_hex(),
                update.old.to_hex()
            )
            .as_bytes(),
        );
    }
    out
}

/// Runs `pre-push` with `<remote> <url>` and the resolved ref lines on
/// stdin. Callers skip this on `--no-verify`.
pub(crate) fn run_pre_push(
    ctx: &mut Ctx,
    remote: &str,
    url: &str,
    lines: &[u8],
) -> Result<(), GitError> {
    run_hook(ctx, "pre-push", &[remote, url], lines)
}
