//! Sparse checkout: `sparse-checkout init`, `set`, `list`, `disable`, `reapply`.
//!
//! | subcommand | backing | status |
//! | --- | --- | --- |
//! | `init` | `core.sparseCheckout` config + `.ruk/info/sparse-checkout` | implemented (`--cone` is `Unsupported`) |
//! | `set` | patterns file replace + reapply (`--stdin`, `--no-reapply`) | implemented (`--cone` is `Unsupported`) |
//! | `list` | patterns file read | implemented |
//! | `disable` | config off + flags cleared + full worktree restore | implemented |
//! | `reapply` | current patterns applied to index flags + worktree | implemented |
//!
//! Patterns live on disk at `.ruk/info/sparse-checkout` (the oracle's
//! `$GIT_DIR/info/sparse-checkout`) with one rule per line: blank lines and
//! `#` comments are skipped, a leading `!` negates, a leading `/` anchors to
//! the root, and a trailing `/` matches the whole directory. Matching is the
//! repo glob (`*` crosses `/`, plus `?`/`[...]`); a non-glob pattern also
//! matches everything below that path, so `docs` keeps `docs/a.txt`. The
//! last matching line wins. With no rules (missing or empty file) everything
//! matches; with rules, unmatched paths are outside the cone.
//!
//! The index keeps every entry: paths outside the sparse set carry
//! `CE_SKIP_WORKTREE` (`IndexFlags::skip_worktree`) on their stage-zero row,
//! and the worktree holds only matching files. With no rules (missing or
//! empty patterns file) everything matches; otherwise only paths a rule
//! names (last match wins, `!` excludes) are in the cone. `set`/`reapply`/
//! `disable` rewrite exactly the touched worktree paths and refuse when a
//! rewrite would discard local changes; untracked files are never removed.
//!
//! Oracle anchor: `git/builtin/sparse-checkout.c`.
//!
//! Named gaps: cone mode (`--cone`, cone prefixes), `--no-cone` accepted as
//! the default; branch-switch checkouts and `status` do not consult the
//! sparse set (only this verb's own apply step filters).

use std::collections::BTreeMap;

use ruk_core::ids::Oid;
use ruk_core::index::{FileMode, IndexEntry, RepoPath, Stage};
use ruk_core::store::Store;
use ruk_git::GitError;

use super::state::{
    config_write, load_or_default, path_row_mutations, read_path_rows, scan_index,
    workspace_mutation,
};
use super::tree::{join_base, read_object_bytes};
use super::{Collected, Ctx, FlagSpec, collect, line, read_stdin_text};

/// Config key enabling the sparse filter.
const SPARSE_CONFIG: &str = "core.sparseCheckout";

/// One parsed patterns-file line.
#[derive(Clone, Debug)]
struct SparseRule {
    /// Glob (or literal prefix) matched against the full path.
    pattern: String,
    /// Negated (`!`) rules exclude instead of include.
    negate: bool,
    /// Trailing-`/` rules match the whole directory subtree.
    dir_only: bool,
}

/// Sparse checkout: enable, narrow, list, or lift the worktree filter.
///
/// Oracle: `git/builtin/sparse-checkout.c`.
pub(crate) fn sparse_checkout(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "cone",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-cone",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-reapply",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.is_set("cone") {
        return Err(GitError::Unsupported {
            command: "sparse-checkout --cone (cone mode)".to_owned(),
        });
    }
    ctx.require_worktree()?;
    match opts.positionals.first().map(String::as_str) {
        Some("init") => {
            expect_no_patterns(&opts, "init")?;
            init(ctx)
        }
        Some("set") => set(ctx, &opts),
        Some("list") => {
            expect_no_patterns(&opts, "list")?;
            list(ctx)
        }
        Some("disable") => {
            expect_no_patterns(&opts, "disable")?;
            disable(ctx)
        }
        Some("reapply") => {
            expect_no_patterns(&opts, "reapply")?;
            reapply_current(ctx)
        }
        Some(other) => Err(GitError::Invalid {
            detail: format!("unknown sparse-checkout subcommand {other:?}"),
        }),
        None => Err(GitError::Invalid {
            detail: "usage: sparse-checkout <init|set|list|disable|reapply>".to_owned(),
        }),
    }
}

/// Refuses stray patterns on subcommands that take none.
fn expect_no_patterns(opts: &Collected, sub: &str) -> Result<(), GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: format!("usage: sparse-checkout {sub}"),
        });
    }
    Ok(())
}

/// Enables sparse checkout and converges the worktree onto the stored
/// patterns (a fresh empty file matches everything, so first-time init is
/// a no-op beyond enabling).
fn init(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let path = patterns_path(ctx);
    if !path.exists() {
        write_patterns(ctx, "")?;
    }
    config_write(store, SPARSE_CONFIG, "true")?;
    apply_patterns(ctx)
}

/// Replaces the patterns and reapplies them to index flags and worktree.
fn set(ctx: &Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    let mut patterns: Vec<String> = opts.positionals[1..].to_vec();
    if opts.is_set("stdin") {
        let text = read_stdin_text(&ctx.env)?;
        patterns.extend(text.lines().map(str::to_owned));
    }
    if patterns.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: sparse-checkout set [--stdin] <pattern>...".to_owned(),
        });
    }
    let mut body = String::new();
    for pattern in &patterns {
        body.push_str(pattern);
        body.push('\n');
    }
    write_patterns(ctx, &body)?;
    let store = ctx.store()?;
    config_write(store, SPARSE_CONFIG, "true")?;
    if opts.is_set("no-reapply") {
        return Ok(Vec::new());
    }
    apply_patterns(ctx)
}

/// Prints the stored patterns, one per line.
fn list(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let path = patterns_path(ctx);
    let body = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    };
    Ok(line(body))
}

/// Lifts the filter: flags cleared, missing tracked files restored.
/// Present files are never overwritten and untracked files never touched.
fn disable(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    config_write(store, SPARSE_CONFIG, "false")?;
    clear_skip_flags(ctx)?;
    let mut writes: Vec<(Vec<u8>, SparseWrite)> = Vec::new();
    for (path, stage, entry) in scan_index(store, kind)? {
        if stage != Stage::Zero || entry.mode() == FileMode::Gitlink {
            continue;
        }
        if worktree_present(ctx, &path.as_bytes().to_vec()) {
            continue;
        }
        writes.push((
            path.as_bytes().to_vec(),
            SparseWrite::Blob {
                mode: entry.mode(),
                oid: entry.oid(),
            },
        ));
    }
    sync_sparse_worktree(ctx, &writes)?;
    Ok(Vec::new())
}

/// Reports whether a worktree path exists as a file or link.
fn worktree_present(ctx: &Ctx, path: &[u8]) -> bool {
    join_base(&ctx.file_base, path).is_ok_and(|full| full.is_symlink() || full.is_file())
}

/// Reapplies the stored patterns without changing them.
fn reapply_current(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    ctx.store()?;
    if ctx.config_get(SPARSE_CONFIG).as_deref() != Some("true") {
        return Err(GitError::Invalid {
            detail: "sparse checkout is not enabled (run `sparse-checkout init`)".to_owned(),
        });
    }
    apply_patterns(ctx)
}

/// Applies the stored patterns to index flags and the worktree.
fn apply_patterns(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let rules = load_rules(ctx);
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut mutations = Vec::new();
    let mut writes: Vec<(Vec<u8>, SparseWrite)> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();
    let mut stage_zero: BTreeMap<Vec<u8>, IndexEntry> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            stage_zero.insert(path.as_bytes().to_vec(), entry.clone());
        }
    }
    for (raw_path, entry) in &stage_zero {
        let repo_path = repo_path_of(raw_path)?;
        let before = read_path_rows(store, kind, &repo_path)?;
        let wanted = rules_match(&rules, raw_path);
        let mut next_entry = entry.clone();
        let flags = next_entry.flags();
        if flags.skip_worktree == !wanted {
            // Flag already correct; the worktree may still need the file.
            if wanted {
                plan_materialize(ctx, store, raw_path, &entry, &mut writes, &mut blocked);
            } else {
                plan_removal(ctx, store, raw_path, &entry, &mut writes, &mut blocked);
            }
            continue;
        }
        next_entry = IndexEntry::new(
            entry.oid(),
            entry.mode(),
            entry.stat(),
            ruk_core::index::IndexFlags {
                skip_worktree: !wanted,
                ..flags
            },
        )
        .map_err(core_invalid)?;
        mutations.extend(path_row_mutations(
            &repo_path,
            &before,
            &[(Stage::Zero, next_entry.clone())],
        )?);
        if wanted {
            plan_materialize(ctx, store, raw_path, &next_entry, &mut writes, &mut blocked);
        } else {
            plan_removal(ctx, store, raw_path, &next_entry, &mut writes, &mut blocked);
        }
    }
    if !blocked.is_empty() {
        blocked.sort();
        let mut detail = String::from(
            "error: Your local changes to the following files would be overwritten by sparse-checkout:\n",
        );
        for path in &blocked {
            detail.push_str(&format!("\t{path}\n"));
        }
        detail.push_str("Please commit your changes or stash them before you switch.");
        return Err(GitError::Invalid { detail });
    }
    if !mutations.is_empty() {
        let (workspace, raw) = load_or_default(store)?;
        let next = workspace
            .mutate_index(workspace.stamp)
            .map_err(core_invalid)?;
        mutations.push(workspace_mutation(raw.as_deref(), &next)?);
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    sync_sparse_worktree(ctx, &writes)?;
    Ok(Vec::new())
}

/// Clears every skip-worktree flag (for `disable`).
fn clear_skip_flags(ctx: &Ctx) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut mutations = Vec::new();
    for (path, stage, entry) in &rows {
        if *stage != Stage::Zero || !entry.flags().skip_worktree {
            continue;
        }
        let before = read_path_rows(store, kind, path)?;
        let next = IndexEntry::new(
            entry.oid(),
            entry.mode(),
            entry.stat(),
            ruk_core::index::IndexFlags {
                skip_worktree: false,
                ..entry.flags()
            },
        )
        .map_err(core_invalid)?;
        mutations.extend(path_row_mutations(path, &before, &[(Stage::Zero, next)])?);
    }
    if mutations.is_empty() {
        return Ok(());
    }
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(core_invalid)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// One scoped worktree change for the sparse apply step.
enum SparseWrite {
    /// Write the index blob.
    Blob { mode: FileMode, oid: Oid },
    /// Remove the worktree file.
    Remove,
}

/// Plans materializing one in-cone path: write when missing, block on dirty.
fn plan_materialize(
    ctx: &Ctx,
    store: &Store,
    path: &[u8],
    entry: &IndexEntry,
    writes: &mut Vec<(Vec<u8>, SparseWrite)>,
    blocked: &mut Vec<String>,
) {
    if entry.mode() == FileMode::Gitlink {
        return;
    }
    let Ok(full) = join_base(&ctx.file_base, path) else {
        return;
    };
    if entry.mode() == FileMode::Symlink {
        let target = std::fs::read_link(&full)
            .ok()
            .map(|link| link.as_os_str().as_encoded_bytes().to_vec());
        let wanted = read_object_bytes(store, entry.oid()).ok().map(|(_, body)| body);
        if target == wanted {
            return;
        }
        if full.is_symlink() || full.is_file() {
            blocked.push(String::from_utf8_lossy(path).into_owned());
            return;
        }
        writes.push((
            path.to_vec(),
            SparseWrite::Blob {
                mode: entry.mode(),
                oid: entry.oid(),
            },
        ));
        return;
    }
    let body = match std::fs::read(&full) {
        Ok(body) => Some(body),
        Err(_) => None,
    };
    let wanted = read_object_bytes(store, entry.oid())
        .ok()
        .map(|(_, body)| body);
    if body == wanted {
        return;
    }
    if body.is_some() {
        blocked.push(String::from_utf8_lossy(path).into_owned());
        return;
    }
    writes.push((
        path.to_vec(),
        SparseWrite::Blob {
            mode: entry.mode(),
            oid: entry.oid(),
        },
    ));
}

/// Plans removing one out-of-cone path: remove when clean, block on dirty.
fn plan_removal(
    ctx: &Ctx,
    store: &Store,
    path: &[u8],
    entry: &IndexEntry,
    writes: &mut Vec<(Vec<u8>, SparseWrite)>,
    blocked: &mut Vec<String>,
) {
    if entry.mode() == FileMode::Gitlink {
        return;
    }
    let Ok(full) = join_base(&ctx.file_base, path) else {
        return;
    };
    if entry.mode() == FileMode::Symlink {
        if !full.is_symlink() {
            return;
        }
        let target = std::fs::read_link(&full)
            .ok()
            .map(|link| link.as_os_str().as_encoded_bytes().to_vec());
        let wanted = read_object_bytes(store, entry.oid()).ok().map(|(_, body)| body);
        if target != wanted {
            blocked.push(String::from_utf8_lossy(path).into_owned());
            return;
        }
        writes.push((path.to_vec(), SparseWrite::Remove));
        return;
    }
    let Ok(body) = std::fs::read(&full) else {
        return;
    };
    let Ok((_, wanted)) = read_object_bytes(store, entry.oid()) else {
        return;
    };
    if body != wanted {
        blocked.push(String::from_utf8_lossy(path).into_owned());
        return;
    }
    writes.push((path.to_vec(), SparseWrite::Remove));
}

/// Writes exactly the planned sparse paths.
fn sync_sparse_worktree(ctx: &Ctx, writes: &[(Vec<u8>, SparseWrite)]) -> Result<(), GitError> {
    let store = ctx.store()?;
    for (path, write) in writes {
        let full = join_base(&ctx.file_base, path)?;
        match write {
            SparseWrite::Remove => {
                if full.is_symlink() || full.is_file() {
                    std::fs::remove_file(&full).map_err(|err| GitError::Io {
                        detail: format!("removing {}: {err}", full.display()),
                    })?;
                }
                prune_empty_parents(&full, &ctx.file_base);
            }
            SparseWrite::Blob { mode, oid } => {
                if *mode == FileMode::Symlink {
                    let (_, body) = read_object_bytes(store, *oid)?;
                    let text =
                        std::str::from_utf8(&body).map_err(|_| GitError::Invalid {
                            detail: "symlink target is not valid UTF-8".to_owned(),
                        })?;
                    if full.is_symlink() || full.exists() {
                        std::fs::remove_file(&full).map_err(|err| GitError::Io {
                            detail: format!("removing {}: {err}", full.display()),
                        })?;
                    }
                    if let Some(parent) = full.parent() {
                        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                            detail: format!("creating {}: {err}", parent.display()),
                        })?;
                    }
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(text, &full).map_err(|err| GitError::Io {
                        detail: format!("linking {}: {err}", full.display()),
                    })?;
                    #[cfg(not(unix))]
                    return Err(GitError::Unsupported {
                        command: "checkout of symlinks on this platform".to_owned(),
                    });
                    continue;
                }
                let (_, body) = read_object_bytes(store, *oid)?;
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                        detail: format!("creating {}: {err}", parent.display()),
                    })?;
                }
                if full.is_symlink() {
                    std::fs::remove_file(&full).map_err(|err| GitError::Io {
                        detail: format!("removing {}: {err}", full.display()),
                    })?;
                }
                std::fs::write(&full, body).map_err(|err| GitError::Io {
                    detail: format!("writing {}: {err}", full.display()),
                })?;
                #[cfg(unix)]
                if *mode == FileMode::Executable {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o755))
                        .map_err(|err| GitError::Io {
                            detail: format!("chmod {}: {err}", full.display()),
                        })?;
                }
            }
        }
    }
    Ok(())
}

/// Removes newly-empty parent directories up to (not including) the base.
fn prune_empty_parents(full: &std::path::Path, base: &std::path::Path) {
    let mut dir = full.parent();
    while let Some(candidate) = dir {
        if candidate == base {
            break;
        }
        if std::fs::remove_dir(candidate).is_err() {
            break;
        }
        dir = candidate.parent();
    }
}

/// Loads and parses the patterns file; missing means match-all.
fn load_rules(ctx: &Ctx) -> Vec<SparseRule> {
    let body = std::fs::read(patterns_path(ctx)).unwrap_or_default();
    parse_rules(&body)
}

/// Parses patterns-file bytes into rules in file order.
fn parse_rules(body: &[u8]) -> Vec<SparseRule> {
    let mut out = Vec::new();
    for raw in String::from_utf8_lossy(body).lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negate, pattern) = match line.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        if pattern.is_empty() {
            continue;
        }
        let (pattern, dir_only) = match pattern.strip_suffix('/') {
            Some(dir) => (dir, true),
            None => (pattern, false),
        };
        let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
        if pattern.is_empty() {
            continue;
        }
        out.push(SparseRule {
            pattern: pattern.to_owned(),
            negate,
            dir_only,
        });
    }
    out
}

/// Reports whether `path` is in the sparse cone: the last matching rule
/// wins. With no rules at all nothing filters (everything matches); with
/// rules, a path no rule names is outside the cone.
fn rules_match(rules: &[SparseRule], path: &[u8]) -> bool {
    if rules.is_empty() {
        return true;
    }
    let text = String::from_utf8_lossy(path);
    let mut matched = false;
    for rule in rules {
        if rule_matches(rule, &text) {
            matched = !rule.negate;
        }
    }
    matched
}

/// Matches one rule against a full path.
fn rule_matches(rule: &SparseRule, path: &str) -> bool {
    if has_glob(&rule.pattern) {
        return sparse_glob(&rule.pattern, path);
    }
    if rule.dir_only {
        return path == rule.pattern || path.starts_with(&format!("{}/", rule.pattern));
    }
    // A literal matches the path itself and everything below it.
    path == rule.pattern || path.starts_with(&format!("{}/", rule.pattern))
}

/// Reports whether a pattern carries glob metacharacters.
fn has_glob(pattern: &str) -> bool {
    pattern.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'[' | b'\\'))
}

/// Shell-ish glob where `*` crosses `/`, plus `?`/`[...]` and escapes.
fn sparse_glob(pattern: &str, text: &str) -> bool {
    fn go(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        match pattern[0] {
            b'*' => {
                let mut rest = &pattern[1..];
                while rest.first() == Some(&b'*') {
                    rest = &rest[1..];
                }
                (0..=text.len()).any(|index| go(rest, &text[index..]))
            }
            b'?' => !text.is_empty() && go(&pattern[1..], &text[1..]),
            b'[' => {
                let Some(end) = pattern.iter().position(|byte| *byte == b']') else {
                    return text.first() == Some(&b'[') && go(&pattern[1..], &text[1..]);
                };
                if text.is_empty() {
                    return false;
                }
                let mut class = &pattern[1..end];
                let mut negate = false;
                if class.first() == Some(&b'!') || class.first() == Some(&b'^') {
                    negate = true;
                    class = &class[1..];
                }
                let mut hit = false;
                let mut index = 0;
                while index < class.len() {
                    if index + 2 < class.len() && class[index + 1] == b'-' {
                        if (class[index]..=class[index + 2]).contains(&text[0]) {
                            hit = true;
                        }
                        index += 3;
                    } else {
                        if class[index] == text[0] {
                            hit = true;
                        }
                        index += 1;
                    }
                }
                (hit != negate) && go(&pattern[end + 1..], &text[1..])
            }
            b'\\' if pattern.len() > 1 => {
                text.first() == Some(&pattern[1]) && go(&pattern[2..], &text[1..])
            }
            byte => text.first() == Some(&byte) && go(&pattern[1..], &text[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Locates the on-disk patterns file.
fn patterns_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.root.join(".ruk").join("info").join("sparse-checkout")
}

/// Replaces the patterns file, creating `.ruk/info` as needed.
fn write_patterns(ctx: &Ctx, body: &str) -> Result<(), GitError> {
    let path = patterns_path(ctx);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    std::fs::write(&path, body).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", path.display()),
    })?;
    Ok(())
}

/// Wraps raw path bytes as a repo path.
fn repo_path_of(raw: &[u8]) -> Result<RepoPath, GitError> {
    RepoPath::new(raw.to_vec()).map_err(core_invalid)
}

/// Maps a model failure into the interpreter error space.
fn core_invalid(err: impl Into<ruk_core::error::CoreError>) -> GitError {
    GitError::from(err.into())
}
