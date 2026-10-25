//! Staging verbs: `add`, `mv`, `rm`, `update-index`, `ls-files`, `status`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `add` | `WsIndex` stage-0 rows + generation bump | implemented (explicit paths, `-u`, `-A`, `-N`) |
//! | `mv` | row rename across stages + file rename | implemented |
//! | `rm` | row delete + file delete (`--cached` keeps the file) | implemented |
//! | `update-index` | row add/remove/flag edits | implemented (`--cacheinfo`, `--stdin`, `--add`, `--remove`, `--assume-unchanged`, `--skip-worktree`, `--refresh`) |
//! | `ls-files` | row scan | implemented (`-s`, `-u`, `--others`) |
//! | `status` | `HEAD` tree vs index vs worktree | implemented (`--porcelain=v1`/`v2`, `--short`, `--long`, `--branch`, `--null`, `-u` modes, `--ignored`, `--show-stash`, `--ahead-behind`/`--no-ahead-behind`, `--renames`/`-M`/`--find-renames`/`--no-renames`, `-v` staged + `-vv` unstaged diffs, `--no-column`/`--ignore-submodules` no-op, `--column` unsupported) |
//!
//! Oracle anchors: `git/builtin/add.c`, `git/builtin/mv.c`,
//! `git/builtin/rm.c`, `git/builtin/update-index.c`,
//! `git/builtin/ls-files.c`, `git/builtin/commit.c` (`cmd_status`).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ruk_core::ids::HashKind;
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage, StatData};
use ruk_core::store::{EventContext, EventSource, Store};
use ruk_git::GitError;

use super::state::{
    MAX_OBJECT_BYTES, head_oid, load_or_default, path_row_mutations, read_path_rows, read_ref,
    scan_index, stash_high_water, stash_read, unmerged_paths, walk_history, workspace_mutation,
};
use super::tree::{
    TreeMode, WorktreeEntry, WorktreeType, commit_tree_oid, flatten_tree, join_base,
    read_object_bytes, read_worktree_file, walk_worktree,
};
use super::{Ctx, FlagSpec, collect, line};

/// `(path, staged code, index/head identity)` in path order.
type StagedEntry = (Vec<u8>, char, Option<(TreeMode, ruk_core::ids::Oid)>);
/// `(old path, new path, score)` staged rename.
type StagedRename = (Vec<u8>, Vec<u8>, u8);
/// Split status-only spellings: kept args, formats, untracked modes.
type StatusArgsSplit = (Vec<String>, Vec<StatusFormat>, Vec<UntrackedMode>);

/// How `add` fills new rows. A named type, never a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddFill {
    /// Hash the file bytes.
    Content,
    /// Reserve with the empty blob (`add -N`).
    Intent,
}

/// Adds worktree files to stage-zero index rows.
///
/// Oracle: `git/builtin/add.c`.
pub(crate) fn add(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "update",
            short: Some('u'),
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: Some('A'),
            takes_value: false,
        },
        FlagSpec {
            long: "intent-to-add",
            short: Some('N'),
            takes_value: false,
        },
        FlagSpec {
            long: "refresh",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let fill = if opts.is_set("intent-to-add") {
        AddFill::Intent
    } else {
        AddFill::Content
    };
    let targets = collect_add_targets(ctx, store, &opts)?;
    if targets.is_empty() {
        return Err(GitError::Invalid {
            detail: "add needs at least one path".to_owned(),
        });
    }
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    for path in &targets {
        let before = read_path_rows(store, kind, path)?;
        if opts.is_set("update") && before.is_empty() {
            return Err(GitError::NotFound {
                detail: format!("pathspec is not tracked: {}", shown(path)),
            });
        }
        let (entry, staged) = stage_file(ctx, kind, path, fill)?;
        objects.extend(staged);
        mutations.extend(path_row_mutations(path, &before, &[(Stage::Zero, entry)])?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    store
        .publish(
            objects,
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    Ok(Vec::new())
}

/// Resolves the path list for `add` from flags and positionals.
fn collect_add_targets(
    ctx: &Ctx,
    store: &Store,
    opts: &super::Collected,
) -> Result<Vec<RepoPath>, GitError> {
    if opts.is_set("all") {
        let mut out = Vec::new();
        for entry in walk_worktree(&ctx.file_base)? {
            out.push(repo_path_of(ctx, &entry.path)?);
        }
        for positional in &opts.positionals {
            let path = repo_path_of(ctx, positional.as_bytes())?;
            if !out.contains(&path) {
                out.push(path);
            }
        }
        return Ok(out);
    }
    if opts.is_set("update") && opts.positionals.is_empty() {
        let mut out = Vec::new();
        for (path, _, _) in scan_index(store, ctx.kind()?)? {
            out.push(path);
        }
        return Ok(out);
    }
    opts.positionals
        .iter()
        .map(|positional| repo_path_of(ctx, positional.as_bytes()))
        .collect()
}

/// Stages one worktree file's current bytes for verbs outside staging.
pub(crate) fn stage_worktree_file(
    ctx: &Ctx,
    kind: HashKind,
    path: &RepoPath,
) -> Result<(IndexEntry, Vec<ruk_core::store::PreparedObject>), GitError> {
    stage_file(ctx, kind, path, AddFill::Content)
}

/// Stages one file's bytes (or its intent reservation) as an index entry.
fn stage_file(
    ctx: &Ctx,
    kind: HashKind,
    path: &RepoPath,
    fill: AddFill,
) -> Result<(IndexEntry, Vec<ruk_core::store::PreparedObject>), GitError> {
    let full = join_base(&ctx.file_base, path.as_bytes())?;
    let meta = std::fs::symlink_metadata(&full).map_err(|err| GitError::Io {
        detail: format!("statting {}: {err}", full.display()),
    })?;
    if meta.file_type().is_dir() {
        return Err(GitError::Invalid {
            detail: format!("{} is a directory", shown(path)),
        });
    }
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&full).map_err(|err| GitError::Io {
            detail: format!("reading link {}: {err}", full.display()),
        })?;
        let bytes = target.as_os_str().as_encoded_bytes().to_vec();
        let stat = super::state::stat_from_meta(&meta).ok();
        return stage_bytes(ctx, kind, FileMode::Symlink, &bytes, fill, stat);
    }
    let mode = file_mode_of(&meta);
    let bytes = read_worktree_file(&ctx.file_base, path.as_bytes())?;
    let byte_len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
        detail: format!("file {} exceeds the length range", shown(path)),
    })?;
    if byte_len > MAX_OBJECT_BYTES {
        return Err(GitError::Limit {
            detail: format!("file {} exceeds the object bound", shown(path)),
        });
    }
    // The tuple is captured before the content read: a concurrent edit can
    // only stale it (the next scan rehashes), never validate foreign bytes.
    let stat = super::state::stat_from_meta(&meta).ok();
    stage_bytes(ctx, kind, mode, &bytes, fill, stat)
}

/// Builds the entry for staged bytes under one fill discipline and prepares
/// the blob object for publication. Content fills always emit the object:
/// the store deduplicates by OID at publish, so a known blob costs one
/// prepared frame, never a second record. The worktree lstat tuple travels
/// with the entry so dirty scans can trust it; an unstattable file leaves
/// the row stat-less and scans rehash, exactly as before.
fn stage_bytes(
    ctx: &Ctx,
    kind: HashKind,
    mode: FileMode,
    bytes: &[u8],
    fill: AddFill,
    stat: Option<StatData>,
) -> Result<(IndexEntry, Vec<ruk_core::store::PreparedObject>), GitError> {
    let entry = match fill {
        AddFill::Content => IndexEntry::for_blob(kind, mode, bytes, stat),
        AddFill::Intent => IndexEntry::intent_to_add(kind, FileMode::Regular, stat),
    }
    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    match fill {
        AddFill::Content => {
            let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
                detail: "blob payload exceeds the length range".to_owned(),
            })?;
            let prepared = ctx
                .store()?
                .prepare(
                    ruk_core::store::types::ObjectKind::Blob,
                    len,
                    std::io::Cursor::new(bytes.to_vec()),
                    None,
                )
                .map_err(GitError::from)?;
            Ok((entry, vec![prepared]))
        }
        AddFill::Intent => Ok((entry, Vec::new())),
    }
}

/// Derives the index mode from worktree metadata.
#[cfg(unix)]
pub(crate) fn file_mode_of(meta: &std::fs::Metadata) -> FileMode {
    use std::os::unix::fs::PermissionsExt as _;
    if meta.permissions().mode() & 0o100 != 0 {
        FileMode::Executable
    } else {
        FileMode::Regular
    }
}

#[cfg(not(unix))]
pub(crate) fn file_mode_of(_meta: &std::fs::Metadata) -> FileMode {
    FileMode::Regular
}

/// Maps CLI bytes to a validated repository path under the file base.
pub(crate) fn repo_path_of(ctx: &Ctx, raw: &[u8]) -> Result<RepoPath, GitError> {
    let text = std::str::from_utf8(raw).map_err(|_| GitError::Invalid {
        detail: "pathspec is not valid UTF-8".to_owned(),
    })?;
    let joined = if std::path::Path::new(text).is_absolute() {
        std::path::PathBuf::from(text)
    } else {
        ctx.env.cwd.join(text)
    };
    let relative = joined
        .strip_prefix(&ctx.file_base)
        .map_err(|_| GitError::Invalid {
            detail: format!("pathspec {text:?} is outside the repository"),
        })?;
    let mut parts: Vec<u8> = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => {
                if !parts.is_empty() {
                    parts.push(b'/');
                }
                parts.extend_from_slice(part.as_encoded_bytes());
            }
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad pathspec {text:?}"),
                });
            }
        }
    }
    RepoPath::new(parts).map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))
}

/// Renders a path for diagnostics.
fn shown(path: &RepoPath) -> String {
    path.to_utf8()
        .map_or_else(|| format!("{:?}", path.as_bytes()), str::to_owned)
}

/// Renames index rows across stages and renames the worktree file.
///
/// Oracle: `git/builtin/mv.c`.
pub(crate) fn mv(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "force",
        short: Some('f'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.positionals.len() != 2 {
        return Err(GitError::Invalid {
            detail: "usage: mv [--force] <source> <destination>".to_owned(),
        });
    }
    let src = repo_path_of(ctx, opts.positionals[0].as_bytes())?;
    let dst = repo_path_of(ctx, opts.positionals[1].as_bytes())?;
    let before_src = read_path_rows(store, kind, &src)?;
    if before_src.is_empty() {
        return Err(GitError::NotFound {
            detail: format!("source is not tracked: {}", shown(&src)),
        });
    }
    let before_dst = read_path_rows(store, kind, &dst)?;
    if !before_dst.is_empty() && !opts.is_set("force") {
        return Err(GitError::Invalid {
            detail: format!("destination exists: {}", shown(&dst)),
        });
    }
    let after: Vec<(Stage, IndexEntry)> = before_src
        .iter()
        .map(|(stage, entry, _)| (*stage, entry.clone()))
        .collect();
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = path_row_mutations(&src, &before_src, &[])?;
    mutations.extend(path_row_mutations(&dst, &before_dst, &after)?);
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    let src_file = join_base(&ctx.file_base, src.as_bytes())?;
    let dst_file = join_base(&ctx.file_base, dst.as_bytes())?;
    if let Some(parent) = dst_file.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    store
        .publish(
            Vec::new(),
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    std::fs::rename(&src_file, &dst_file).map_err(|err| GitError::Io {
        detail: format!("renaming {}: {err}", src_file.display()),
    })?;
    Ok(Vec::new())
}

/// Removes paths from the index and, without `--cached`, from the worktree.
///
/// Oracle: `git/builtin/rm.c`.
pub(crate) fn rm(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "cached",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "recursive",
            short: Some('r'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: rm [--cached] [-r] <path>...".to_owned(),
        });
    }
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    for positional in &opts.positionals {
        let path = repo_path_of(ctx, positional.as_bytes())?;
        let before = read_path_rows(store, kind, &path)?;
        if before.is_empty() {
            if !opts.is_set("recursive") {
                return Err(GitError::NotFound {
                    detail: format!("pathspec is not tracked: {}", shown(&path)),
                });
            }
            let nested = remove_nested(store, kind, &path)?;
            if nested.is_empty() {
                return Err(GitError::NotFound {
                    detail: format!("pathspec is not tracked: {}", shown(&path)),
                });
            }
            for nested_path in nested {
                let nested_before = read_path_rows(store, kind, &nested_path)?;
                mutations.extend(path_row_mutations(&nested_path, &nested_before, &[])?);
                files.push(join_base(&ctx.file_base, nested_path.as_bytes())?);
                removed.push(String::from_utf8_lossy(nested_path.as_bytes()).into_owned());
            }
            continue;
        }
        mutations.extend(path_row_mutations(&path, &before, &[])?);
        files.push(join_base(&ctx.file_base, path.as_bytes())?);
        removed.push(String::from_utf8_lossy(path.as_bytes()).into_owned());
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    store
        .publish(
            Vec::new(),
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    if !opts.is_set("cached") {
        for file in files {
            if file.is_dir() {
                std::fs::remove_dir_all(&file).map_err(|err| GitError::Io {
                    detail: format!("removing {}: {err}", file.display()),
                })?;
            } else if file.is_symlink() || file.exists() {
                std::fs::remove_file(&file).map_err(|err| GitError::Io {
                    detail: format!("removing {}: {err}", file.display()),
                })?;
            }
        }
    }
    let mut out = Vec::new();
    for path in removed {
        out.extend_from_slice(format!("rm '{path}'\n").as_bytes());
    }
    Ok(out)
}

/// Collects every tracked path below a directory prefix. Callers re-read
/// each path's rows so deletions carry the true compare-and-swap bytes.
fn remove_nested(store: &Store, kind: HashKind, dir: &RepoPath) -> Result<Vec<RepoPath>, GitError> {
    let mut prefix = dir.as_bytes().to_vec();
    prefix.push(b'/');
    let mut out = Vec::new();
    for (path, _, _) in scan_index(store, kind)? {
        if path.as_bytes().starts_with(&prefix) && !out.contains(&path) {
            out.push(path);
        }
    }
    out.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(out)
}

/// Registers worktree contents in the index at a lower level than `add`.
///
/// Oracle: `git/builtin/update-index.c`.
pub(crate) fn update_index(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "cacheinfo",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "add",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "remove",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "force-remove",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "refresh",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "really-refresh",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "assume-unchanged",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-assume-unchanged",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "skip-worktree",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-skip-worktree",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("refresh") || opts.is_set("really-refresh") {
        return Ok(Vec::new());
    }
    let mut cacheinfos = opts.all("cacheinfo")?;
    if opts.is_set("stdin") {
        let stdin = super::read_stdin_text(&ctx.env)?;
        for stdin_line in stdin.lines() {
            if !stdin_line.is_empty() {
                cacheinfos.push(stdin_line.to_owned());
            }
        }
    }
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    for info in &cacheinfos {
        mutations.extend(apply_cacheinfo(ctx, store, kind, info, opts.is_set("add"))?);
    }
    for positional in &opts.positionals {
        let path = repo_path_of(ctx, positional.as_bytes())?;
        let before = read_path_rows(store, kind, &path)?;
        if before.is_empty() {
            if opts.is_set("add") {
                let (entry, staged) = stage_file(ctx, kind, &path, AddFill::Content)?;
                objects.extend(staged);
                mutations.extend(path_row_mutations(&path, &before, &[(Stage::Zero, entry)])?);
            } else if opts.is_set("remove") || opts.is_set("force-remove") {
                continue;
            } else {
                return Err(GitError::NotFound {
                    detail: format!("pathspec is not tracked: {}", shown(&path)),
                });
            }
            continue;
        }
        if opts.is_set("remove") || opts.is_set("force-remove") {
            mutations.extend(path_row_mutations(&path, &before, &[])?);
            continue;
        }
        if let Some(flag_ops) = row_flag_ops(&opts) {
            mutations.extend(apply_row_flags(&path, &before, &flag_ops)?);
            continue;
        }
        let (entry, staged) = stage_file(ctx, kind, &path, AddFill::Content)?;
        objects.extend(staged);
        let after: Vec<(Stage, IndexEntry)> = before
            .iter()
            .map(|(stage, _, _)| (*stage, entry.clone()))
            .collect();
        mutations.extend(path_row_mutations(&path, &before, &after)?);
    }
    if mutations.is_empty() {
        return Ok(Vec::new());
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    store
        .publish(
            objects,
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    Ok(Vec::new())
}

/// Applies one `mode,oid,path` cacheinfo record.
fn apply_cacheinfo(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    info: &str,
    allow_add: bool,
) -> Result<Vec<ruk_core::store::FactMutation>, GitError> {
    let (mode_text, rest) = info.split_once(',').ok_or_else(|| GitError::Invalid {
        detail: format!("bad --cacheinfo {info:?}: want mode,oid,path"),
    })?;
    let (oid_text, path_text) = rest.split_once(',').ok_or_else(|| GitError::Invalid {
        detail: format!("bad --cacheinfo {info:?}: want mode,oid,path"),
    })?;
    let mode_value = u32::from_str_radix(mode_text, 8).map_err(|_| GitError::Invalid {
        detail: format!("bad --cacheinfo mode {mode_text:?}"),
    })?;
    let mode = FileMode::from_octal(mode_value).map_err(|err| GitError::Invalid {
        detail: format!("bad --cacheinfo mode: {err}"),
    })?;
    let oid = ruk_git::parse_oid_for(oid_text.trim(), kind)?;
    let path = repo_path_of(ctx, path_text.trim().as_bytes())?;
    let entry = IndexEntry::new(oid, mode, None, IndexFlags::default())
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    let before = read_path_rows(store, kind, &path)?;
    if before.is_empty() && !allow_add {
        return Err(GitError::NotFound {
            detail: format!("pathspec is not tracked (pass --add): {}", shown(&path)),
        });
    }
    path_row_mutations(&path, &before, &[(Stage::Zero, entry)])
}

/// One row-flag edit from `update-index` flag options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowFlagOp {
    /// Set `assume-unchanged`.
    Assume,
    /// Clear `assume-unchanged`.
    NoAssume,
    /// Set `skip-worktree`.
    Skip,
    /// Clear `skip-worktree`.
    NoSkip,
}

/// Collects the row-flag edits named by the parsed options, if any.
fn row_flag_ops(opts: &super::Collected) -> Option<Vec<RowFlagOp>> {
    let mut ops = Vec::new();
    if opts.is_set("assume-unchanged") {
        ops.push(RowFlagOp::Assume);
    }
    if opts.is_set("no-assume-unchanged") {
        ops.push(RowFlagOp::NoAssume);
    }
    if opts.is_set("skip-worktree") {
        ops.push(RowFlagOp::Skip);
    }
    if opts.is_set("no-skip-worktree") {
        ops.push(RowFlagOp::NoSkip);
    }
    if ops.is_empty() { None } else { Some(ops) }
}

/// Flips row flags on every stored stage of one path.
fn apply_row_flags(
    path: &RepoPath,
    before: &[(Stage, IndexEntry, Vec<u8>)],
    ops: &[RowFlagOp],
) -> Result<Vec<ruk_core::store::FactMutation>, GitError> {
    let mut after = Vec::new();
    for (stage, entry, _) in before {
        let mut flags = entry.flags();
        for op in ops {
            match op {
                RowFlagOp::Assume => flags.assume_unchanged = true,
                RowFlagOp::NoAssume => flags.assume_unchanged = false,
                RowFlagOp::Skip => flags.skip_worktree = true,
                RowFlagOp::NoSkip => flags.skip_worktree = false,
            }
        }
        let replaced = IndexEntry::new(entry.oid(), entry.mode(), entry.stat(), flags)
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
        after.push((*stage, replaced));
    }
    path_row_mutations(path, before, &after)
}

/// Shows index rows, unmerged rows, or untracked files.
///
/// Oracle: `git/builtin/ls-files.c`.
pub(crate) fn ls_files(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "stage",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "unmerged",
            short: Some('u'),
            takes_value: false,
        },
        FlagSpec {
            long: "others",
            short: Some('o'),
            takes_value: false,
        },
        FlagSpec {
            long: "error-unmatch",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut out = Vec::new();
    if opts.is_set("others") {
        let tracked: HashSet<Vec<u8>> = rows
            .iter()
            .map(|(path, _, _)| path.as_bytes().to_vec())
            .collect();
        for entry in walk_worktree(&ctx.file_base)? {
            if !tracked.contains(&entry.path) {
                out.extend_from_slice(entry.path.as_slice());
                out.push(b'\n');
            }
        }
        return Ok(out);
    }
    let only_unmerged = opts.is_set("unmerged");
    for (path, stage, entry) in &rows {
        if only_unmerged && *stage == Stage::Zero {
            continue;
        }
        if opts.is_set("stage") || only_unmerged {
            out.extend_from_slice(
                format!(
                    "{} {} {}\t{}\n",
                    super::state::mode_text(entry.mode()),
                    entry.oid().to_hex(),
                    stage.as_u8(),
                    shown(path)
                )
                .as_bytes(),
            );
        } else if *stage == Stage::Zero {
            out.extend_from_slice(format!("{}\n", shown(path)).as_bytes());
        }
    }
    if opts.is_set("error-unmatch") {
        for positional in &opts.positionals {
            let path = repo_path_of(ctx, positional.as_bytes())?;
            if !rows.iter().any(|(known, _, _)| *known == path) {
                return Err(GitError::NotFound {
                    detail: format!("pathspec did not match: {}", shown(&path)),
                });
            }
        }
    }
    Ok(out)
}

/// Untracked-file display for `-u`/`--untracked-files`: hidden, collapsed
/// to `dir/`, or listed file by file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UntrackedMode {
    /// `-uno`: hide untracked files entirely.
    No,
    /// Default: collapse untracked directories holding no tracked file.
    Normal,
    /// `-uall`: list every untracked file.
    All,
}

/// Porcelain machine formats: v1 (`XY <path>`) or v2 (`1`/`2`/`u`/`?`/`!`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PorcelainVersion {
    V1,
    V2,
}

/// Output shape: the last of `--porcelain`/`--short`/`--long` wins, the
/// way the oracle's single `status_format` variable resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusFormat {
    Long,
    Short,
    Porcelain(PorcelainVersion),
}

/// Ahead/behind detail: exact counts by default and `--ahead-behind`,
/// suppressed by `--no-ahead-behind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AheadBehind {
    Full,
    Off,
}

/// Parses one `-u<mode>`/`--untracked-files[=<mode>]` value. The oracle's
/// `defval` is `all`, so a bare `-u` lists every file; `normal` (collapse)
/// is only the default when the flag is absent.
fn parse_untracked_mode(value: Option<&str>) -> Result<UntrackedMode, GitError> {
    match value {
        None | Some("all") => Ok(UntrackedMode::All),
        Some("normal") => Ok(UntrackedMode::Normal),
        Some("no") => Ok(UntrackedMode::No),
        Some(other) => Err(GitError::Invalid {
            detail: format!("bad --untracked-files={other:?}: want no|normal|all"),
        }),
    }
}

/// Validates `--ignore-submodules[=<when>]`: accepted so scripts pass
/// through, inert because no submodule summary engine exists to tune.
fn check_ignore_submodules(arg: &str) -> Result<(), GitError> {
    let value = arg.strip_prefix("--ignore-submodules=").unwrap_or("all");
    match value {
        "all" | "untracked" | "dirty" | "none" => Ok(()),
        _ => Err(GitError::Invalid {
            detail: format!("bad {arg:?}: want --ignore-submodules[=all|untracked|dirty|none]"),
        }),
    }
}

/// Splits status-only spellings `collect` cannot express, stopping at `--`
/// so paths survive: `--porcelain[=v1|v2]`, `--short`, `--long` (kept in
/// command-line order so the last format wins), `-u<mode>` and
/// `--untracked-files[=<mode>]` (bare means `normal`), and
/// `--ignore-submodules[=<when>]` (validated, inert).
fn split_status_args(args: &[String]) -> Result<StatusArgsSplit, GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut formats = Vec::new();
    let mut untracked = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            kept.extend(args[index..].iter().cloned());
            break;
        }
        if arg == "--porcelain" {
            formats.push(StatusFormat::Porcelain(PorcelainVersion::V1));
        } else if let Some(value) = arg.strip_prefix("--porcelain=") {
            match value {
                "v1" | "1" => formats.push(StatusFormat::Porcelain(PorcelainVersion::V1)),
                "v2" | "2" => formats.push(StatusFormat::Porcelain(PorcelainVersion::V2)),
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!("bad --porcelain={value:?}: want v1|v2"),
                    });
                }
            }
        } else if arg == "--short" || arg == "-s" {
            formats.push(StatusFormat::Short);
        } else if arg == "--long" {
            formats.push(StatusFormat::Long);
        } else if arg == "--untracked-files" || arg == "-u" {
            untracked.push(UntrackedMode::All);
        } else if arg == "-vv" {
            // The shared collector rejects grouped shorts, so the one
            // documented group spells out to two verbose hits here.
            kept.push("-v".to_owned());
            kept.push("-v".to_owned());
        } else if let Some(value) = arg.strip_prefix("--untracked-files=") {
            untracked.push(parse_untracked_mode(Some(value))?);
        } else if let Some(rest) = arg.strip_prefix("-u") {
            untracked.push(parse_untracked_mode(Some(rest))?);
        } else if arg == "--ignore-submodules" || arg.starts_with("--ignore-submodules=") {
            check_ignore_submodules(arg)?;
        } else {
            kept.push(arg.clone());
        }
        index += 1;
    }
    Ok((kept, formats, untracked))
}

/// Shows the working tree status against the index and `HEAD`.
///
/// Oracle: `git/builtin/commit.c` (`cmd_status`).
pub(crate) fn status(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "branch",
            short: Some('b'),
            takes_value: false,
        },
        // NUL-terminate entries; implies porcelain v1 with no format flag.
        FlagSpec {
            long: "null",
            short: Some('z'),
            takes_value: false,
        },
        FlagSpec {
            long: "show-stash",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "ahead-behind",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-ahead-behind",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "ignored",
            short: None,
            takes_value: false,
        },
        // The machine never paginates a column layout: `--no-column` (the
        // default) parses while `--column` names its TTY reason.
        FlagSpec {
            long: "no-column",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "column",
            short: None,
            takes_value: false,
        },
        // Appends the staged diff to a long report (`-vv` adds the
        // unstaged diff too), rendered by the diff lane itself.
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
    ];
    let (args, formats, untracked_opts) = split_status_args(args)?;
    let (args, rename_mode) = super::rename::split_rename_args(&args)?;
    let opts = collect(&args, &specs)?;
    if opts.is_set("column") {
        return Err(GitError::Unsupported {
            command: "status --column needs a terminal column layout".to_owned(),
        });
    }
    ctx.require_worktree()?;
    let mut format = StatusFormat::Long;
    for next in formats {
        format = next;
    }
    // Verbose diffs render before the store is borrowed: the diff lane
    // needs `&mut Ctx`. Porcelain formats ignore `-v` like the oracle.
    let verbose = opts.count("verbose");
    let staged_diff = (verbose >= 1 && format == StatusFormat::Long)
        .then(|| super::verbs_history::diff(ctx, &["--cached".to_owned()]))
        .transpose()?;
    let unstaged_diff = (verbose >= 2 && format == StatusFormat::Long)
        .then(|| super::verbs_history::diff(ctx, &[]))
        .transpose()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let null = opts.is_set("null");
    if null && format == StatusFormat::Long {
        format = StatusFormat::Porcelain(PorcelainVersion::V1);
    }
    let untracked_mode = untracked_opts
        .last()
        .copied()
        .unwrap_or(UntrackedMode::Normal);
    let ahead_behind = if opts.is_set("no-ahead-behind") {
        AheadBehind::Off
    } else {
        AheadBehind::Full
    };
    let show_stash = opts.is_set("show-stash");
    let eol = if null { b'\0' } else { b'\n' };
    let plan = status_plan_with_mode(ctx, store, kind, rename_mode, untracked_mode)?;
    match format {
        StatusFormat::Porcelain(PorcelainVersion::V2) => {
            let ignored = opts.is_set("ignored").then(|| plan.ignored.clone());
            let input = V2Input {
                plan: &plan,
                show_branch: opts.is_set("branch"),
                ignored: ignored.as_deref(),
                ahead_behind,
                show_stash,
                eol,
            };
            render_porcelain_v2(ctx, store, kind, &input)
        }
        StatusFormat::Short | StatusFormat::Porcelain(PorcelainVersion::V1) => {
            let branch = opts
                .is_set("branch")
                .then(|| porcelain_v1_branch(ctx, store, ahead_behind))
                .transpose()?;
            let ignored = opts.is_set("ignored").then(|| plan.ignored.clone());
            Ok(render_porcelain(
                &plan,
                branch.as_deref(),
                ignored.as_deref(),
                eol,
            ))
        }
        StatusFormat::Long => {
            let tracking = match current_short_branch(store)? {
                Some(name) if ahead_behind == AheadBehind::Full => {
                    tracking_sentence(ctx, store, &name)?
                }
                _ => None,
            };
            let stash = if show_stash { stash_count(store)? } else { 0 };
            let ignored = opts.is_set("ignored").then(|| plan.ignored.clone());
            let branch = long_branch_label(store)?;
            let mut out = render_long_full(
                store,
                &branch,
                &plan,
                tracking.as_deref(),
                stash,
                ignored.as_deref(),
            );
            // `-vv` heads each diff the way the oracle does; a single `-v`
            // appends the bare staged diff. Prefixes stay the diff lane's
            // `a/`/`b/` (the oracle uses `c/`/`i/`/`w/` here).
            if verbose >= 2 {
                if let Some(diff) = staged_diff
                    && !diff.is_empty()
                {
                    out.extend_from_slice(b"Changes to be committed:\n");
                    out.extend_from_slice(&diff);
                }
                if let Some(diff) = unstaged_diff
                    && !diff.is_empty()
                {
                    out.extend_from_slice(
                            b"--------------------------------------------------\nChanges not staged for commit:\n",
                        );
                    out.extend_from_slice(&diff);
                }
            } else if let Some(diff) = staged_diff
                && !diff.is_empty()
            {
                if out.last() != Some(&b'\n') {
                    out.push(b'\n');
                }
                out.extend_from_slice(&diff);
            }
            Ok(out)
        }
    }
}

/// One computed status: staged, unstaged, unmerged, untracked, and ignored
/// paths.
pub(crate) struct StatusPlan {
    /// `(path, staged code, index/head identity)` in path order. The
    /// identity backs exact-rename pairing; `None` for modified/unmerged.
    pub(crate) staged: Vec<StagedEntry>,
    /// `(old path, new path, score)` staged renames; exact pairs score 100.
    pub(crate) renames: Vec<(Vec<u8>, Vec<u8>, u8)>,
    /// `(old path, new path, score)` worktree deletions paired with
    /// untracked files (`-M` only; the oracle never reports these, so the
    /// default plan leaves them as delete plus untracked).
    pub(crate) renames_unstaged: Vec<(Vec<u8>, Vec<u8>, u8)>,
    /// `(path, worktree code)` in path order.
    pub(crate) unstaged: Vec<(Vec<u8>, char)>,
    /// Unmerged paths in path order.
    pub(crate) unmerged: Vec<Vec<u8>>,
    /// Untracked paths in path order, shaped by the untracked mode.
    pub(crate) untracked: Vec<Vec<u8>>,
    /// Ignored paths (collapsed to `dir/`), shown only with `--ignored`.
    pub(crate) ignored: Vec<Vec<u8>>,
}

/// Compares `HEAD` tree, index rows, and worktree files with the default
/// exact-only rename pairing and uncollapsed untracked files.
pub(crate) fn status_plan(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
) -> Result<StatusPlan, GitError> {
    status_plan_with_mode(
        ctx,
        store,
        kind,
        super::rename::RenameMode::ExactOnly,
        UntrackedMode::All,
    )
}

/// Compares `HEAD` tree, index rows, and worktree files, pairing renames
/// per `mode`: staged additions/deletions always pair when identical
/// (unless disabled), and `-M` additionally pairs by similarity both
/// staged and worktree (deleted tracked plus untracked). Ignored files
/// split out of the untracked list per `.rukignore` (tracked files never
/// count as ignored); the remainder collapses per `untracked_mode`.
pub(crate) fn status_plan_with_mode(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    mode: super::rename::RenameMode,
    untracked_mode: UntrackedMode,
) -> Result<StatusPlan, GitError> {
    let head_tree = head_tree_map(ctx, store)?;
    let rows = scan_index(store, kind)?;
    let mut index_merged: BTreeMap<Vec<u8>, (TreeMode, ruk_core::ids::Oid)> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            index_merged.insert(
                path.as_bytes().to_vec(),
                (TreeMode::from(entry.mode()), entry.oid()),
            );
        }
    }
    let unmerged = unmerged_paths(&rows);
    let mut staged = Vec::new();
    let mut known: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    for path in unmerged.keys() {
        staged.push((path.clone(), 'U', None));
        known.insert(path.clone(), true);
    }
    for (path, mode_oid) in &index_merged {
        known.insert(path.clone(), true);
        match head_tree.get(path) {
            None => staged.push((path.clone(), 'A', Some(*mode_oid))),
            Some(head_mode_oid) => {
                if head_mode_oid != mode_oid {
                    staged.push((path.clone(), 'M', None));
                }
            }
        }
    }
    for (path, mode_oid) in &head_tree {
        if !known.contains_key(path) {
            staged.push((path.clone(), 'D', Some(*mode_oid)));
        }
    }
    staged.sort();
    let renames = pair_staged_renames(ctx, store, &mut staged, mode)?;
    let mut blobs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();
    let stamp = super::state::read_index_stamp(store);
    let mut index_entries: BTreeMap<Vec<u8>, &IndexEntry> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            index_entries.insert(path.as_bytes().to_vec(), entry);
        }
    }
    let mut present: HashSet<Vec<u8>> = HashSet::new();
    for entry in walk_worktree(&ctx.file_base)? {
        present.insert(entry.path.clone());
        let clean = index_entries
            .get(&entry.path)
            .is_some_and(|cached| is_stat_clean(ctx, cached, &entry.path, stamp));
        if clean {
            continue;
        }
        let bytes = read_entry_bytes(ctx, &entry)?;
        blobs.insert(entry.path.clone(), bytes);
    }
    for (path, bytes) in &blobs {
        match index_merged.get(path) {
            None => {
                if !unmerged.contains_key(path) {
                    untracked.push(path.clone());
                }
            }
            Some((_, oid)) => {
                let (_, current) = read_object_bytes(store, *oid)?;
                if current.as_slice() != bytes.as_slice() {
                    unstaged.push((path.clone(), 'M'));
                }
            }
        }
    }
    for (path, _, _) in &rows {
        let key = path.as_bytes().to_vec();
        if !present.contains(&key) && !unmerged.contains_key(&key) {
            unstaged.push((key, 'D'));
        }
    }
    unstaged.sort();
    untracked.sort();
    // Worktree renames pair only under `-M`: the default plan keeps the
    // oracle's delete-plus-untracked output.
    let renames_unstaged = match mode {
        super::rename::RenameMode::Similar(threshold) => pair_unstaged_renames(
            store,
            &index_merged,
            &blobs,
            &mut unstaged,
            &mut untracked,
            threshold,
        )?,
        super::rename::RenameMode::Disabled | super::rename::RenameMode::ExactOnly => Vec::new(),
    };
    let mut tracked: HashSet<Vec<u8>> = HashSet::new();
    for path in index_merged.keys().chain(head_tree.keys()) {
        tracked.insert(path.clone());
    }
    // Ignored files hide from the untracked list (tracked files never do);
    // the survivors collapse per the untracked mode while ignored sides
    // always collapse to `dir/`.
    let ignore_rules = super::verbs_misc::load_ignore_rules(&ctx.file_base)?;
    let mut shown = Vec::new();
    let mut ignored_files = Vec::new();
    for path in untracked {
        let text = String::from_utf8_lossy(&path);
        if super::verbs_misc::path_is_ignored(&ignore_rules, &text).is_some() {
            ignored_files.push(path);
        } else {
            shown.push(path);
        }
    }
    let ignored = collapse_untracked(ignored_files, &tracked);
    let untracked = match untracked_mode {
        UntrackedMode::No => Vec::new(),
        UntrackedMode::Normal => collapse_untracked(shown, &tracked),
        UntrackedMode::All => shown,
    };
    let mut unmerged_paths_sorted: Vec<Vec<u8>> = unmerged.into_keys().collect();
    unmerged_paths_sorted.sort();
    Ok(StatusPlan {
        staged,
        renames,
        renames_unstaged,
        unstaged,
        unmerged: unmerged_paths_sorted,
        untracked,
        ignored,
    })
}

/// Collapses paths under directories holding no tracked file to `dir/`,
/// the oracle's `normal` display: the shortest clean ancestor wins, so
/// `a/b/c` under a clean `a/` reports `a/`.
fn collapse_untracked(paths: Vec<Vec<u8>>, tracked: &HashSet<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut live: HashSet<Vec<u8>> = HashSet::new();
    for path in tracked {
        let mut rest = path.as_slice();
        while let Some(pos) = rest.iter().rposition(|byte| *byte == b'/') {
            live.insert(rest[..pos].to_vec());
            rest = &rest[..pos];
        }
    }
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        let mut collapsed: Option<Vec<u8>> = None;
        let mut start = 0;
        while let Some(rel) = path[start..].iter().position(|byte| *byte == b'/') {
            let dir = &path[..start + rel];
            if !live.contains(dir) {
                let mut entry = dir.to_vec();
                entry.push(b'/');
                collapsed = Some(entry);
                break;
            }
            start += rel + 1;
        }
        let entry = collapsed.unwrap_or(path);
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    out.sort();
    out
}

/// Pairs staged additions with staged deletions per `mode`, removing both
/// sides from `staged`. `Disabled` pairs nothing; `ExactOnly` pairs
/// identical blobs (the historical behavior); `Similar` additionally pairs
/// edited blobs at or above the threshold.
fn pair_staged_renames(
    ctx: &Ctx,
    store: &Store,
    staged: &mut Vec<StagedEntry>,
    mode: super::rename::RenameMode,
) -> Result<Vec<StagedRename>, GitError> {
    if mode == super::rename::RenameMode::Disabled {
        return Ok(Vec::new());
    }
    if mode == super::rename::RenameMode::ExactOnly {
        return Ok(pair_exact_renames(staged));
    }
    let super::rename::RenameMode::Similar(threshold) = mode else {
        return Ok(pair_exact_renames(staged));
    };
    pair_similar_staged(ctx, store, staged, threshold)
}

/// Pairs staged additions with staged deletions of identical blobs into
/// `(old, new, 100)` renames, removing both sides from `staged`. The
/// oracle reports similarity-100% moves as `R  old -> new`; content-exact
/// pairing reproduces that without a similarity engine.
fn pair_exact_renames(staged: &mut Vec<StagedEntry>) -> Vec<(Vec<u8>, Vec<u8>, u8)> {
    let mut renames = Vec::new();
    let mut kept = Vec::new();
    let mut unmatched_adds: Vec<(Vec<u8>, TreeMode, ruk_core::ids::Oid)> = Vec::new();
    for (path, code, identity) in staged.drain(..) {
        if code == 'A'
            && let Some((mode, oid)) = identity
        {
            unmatched_adds.push((path, mode, oid));
            continue;
        }
        kept.push((path, code, identity));
    }
    let mut taken = vec![false; unmatched_adds.len()];
    let mut restaged = Vec::new();
    for (path, code, identity) in kept {
        if code != 'D' {
            restaged.push((path, code, identity));
            continue;
        }
        let Some((mode, oid)) = identity else {
            restaged.push((path, code, identity));
            continue;
        };
        let mut paired = None;
        for (index, (new_path, new_mode, new_oid)) in unmatched_adds.iter().enumerate() {
            if !taken[index] && *new_mode == mode && *new_oid == oid {
                paired = Some((index, new_path.clone()));
                break;
            }
        }
        match paired {
            Some((index, new_path)) => {
                taken[index] = true;
                renames.push((path, new_path, 100));
            }
            None => restaged.push((path, code, Some((mode, oid)))),
        }
    }
    for (index, (path, mode, oid)) in unmatched_adds.into_iter().enumerate() {
        if !taken[index] {
            restaged.push((path, 'A', Some((mode, oid))));
        }
    }
    restaged.sort();
    renames.sort();
    *staged = restaged;
    renames
}

/// Pairs staged additions with staged deletions by blob similarity at or
/// above `threshold`, after exact-oid pairing. Blob bodies read once per
/// side; oversized sides only pair when their oids already match.
fn pair_similar_staged(
    _ctx: &Ctx,
    store: &Store,
    staged: &mut Vec<StagedEntry>,
    threshold: u8,
) -> Result<Vec<StagedRename>, GitError> {
    use super::rename::{RenameSide, pair_renames, similarity};
    let mut renames = Vec::new();
    let mut keep: Vec<StagedEntry> = Vec::new();
    let mut dels: Vec<(Vec<u8>, TreeMode, ruk_core::ids::Oid)> = Vec::new();
    let mut adds: Vec<(Vec<u8>, TreeMode, ruk_core::ids::Oid)> = Vec::new();
    for (path, code, identity) in staged.drain(..) {
        match (code, identity) {
            ('D', Some((mode, oid))) => dels.push((path, mode, oid)),
            ('A', Some((mode, oid))) => adds.push((path, mode, oid)),
            _ => keep.push((path, code, identity)),
        }
    }
    // Exact oids pair regardless of mode, in path order.
    let mut taken = vec![false; adds.len()];
    let mut live_dels: Vec<(Vec<u8>, TreeMode, ruk_core::ids::Oid)> = Vec::new();
    for (old_path, old_mode, old_oid) in dels {
        let mut paired = None;
        for (index, (new_path, _, new_oid)) in adds.iter().enumerate() {
            if !taken[index] && *new_oid == old_oid {
                paired = Some(index);
                renames.push((old_path.clone(), new_path.clone(), 100));
                break;
            }
        }
        match paired {
            Some(index) => taken[index] = true,
            None => live_dels.push((old_path, old_mode, old_oid)),
        }
    }
    let live_adds: Vec<(Vec<u8>, TreeMode, ruk_core::ids::Oid)> = adds
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !taken[*index])
        .map(|(_, triple)| triple)
        .collect();
    // Similarity over the leftovers; mode plays no role here.
    const MAX_SCORE_BYTES: usize = 1 << 20;
    let mut del_side = Vec::with_capacity(live_dels.len());
    let mut del_body: Vec<Option<Vec<u8>>> = Vec::with_capacity(live_dels.len());
    for (path, _, oid) in &live_dels {
        let (_, body) = read_object_bytes(store, *oid)?;
        del_side.push(RenameSide {
            path: path.clone(),
            size: body.len(),
        });
        del_body.push(if body.len() > MAX_SCORE_BYTES {
            None
        } else {
            Some(body)
        });
    }
    let mut add_side = Vec::with_capacity(live_adds.len());
    let mut add_body: Vec<Option<Vec<u8>>> = Vec::with_capacity(live_adds.len());
    for (path, _, oid) in &live_adds {
        let (_, body) = read_object_bytes(store, *oid)?;
        add_side.push(RenameSide {
            path: path.clone(),
            size: body.len(),
        });
        add_body.push(if body.len() > MAX_SCORE_BYTES {
            None
        } else {
            Some(body)
        });
    }
    let mut used_del = vec![false; live_dels.len()];
    let mut used_add = vec![false; live_adds.len()];
    for win in pair_renames(&del_side, &add_side, threshold, |oi, ni| {
        if live_dels[oi].2 == live_adds[ni].2 {
            return 100;
        }
        match (&del_body[oi], &add_body[ni]) {
            (Some(old), Some(new)) => similarity(old, new),
            _ => 0,
        }
    }) {
        if used_del[win.old] || used_add[win.new] {
            continue;
        }
        used_del[win.old] = true;
        used_add[win.new] = true;
        renames.push((
            live_dels[win.old].0.clone(),
            live_adds[win.new].0.clone(),
            win.score,
        ));
    }
    // Rebuild: survivors are the kept rows plus unpaired leftovers.
    let mut restaged = keep;
    for (index, (path, mode, oid)) in live_dels.into_iter().enumerate() {
        if !used_del[index] {
            restaged.push((path, 'D', Some((mode, oid))));
        }
    }
    for (index, (path, mode, oid)) in live_adds.into_iter().enumerate() {
        if !used_add[index] {
            restaged.push((path, 'A', Some((mode, oid))));
        }
    }
    restaged.sort();
    *staged = restaged;
    renames.sort();
    Ok(renames)
}

/// Pairs worktree deletions of tracked files with untracked files by blob
/// similarity at or above `threshold`, removing both sides from `unstaged`
/// and `untracked`. Runs only under `-M`; the default plan keeps the
/// oracle's delete-plus-untracked output.
fn pair_unstaged_renames(
    store: &Store,
    index: &BTreeMap<Vec<u8>, (TreeMode, ruk_core::ids::Oid)>,
    worktree: &BTreeMap<Vec<u8>, Vec<u8>>,
    unstaged: &mut Vec<(Vec<u8>, char)>,
    untracked: &mut Vec<Vec<u8>>,
    threshold: u8,
) -> Result<Vec<StagedRename>, GitError> {
    use super::rename::{RenameSide, pair_renames, similarity};
    let mut dels: Vec<(Vec<u8>, ruk_core::ids::Oid)> = Vec::new();
    let mut keep: Vec<(Vec<u8>, char)> = Vec::new();
    for (path, code) in unstaged.drain(..) {
        match code {
            'D' => match index.get(&path) {
                Some((_, oid)) => dels.push((path, *oid)),
                None => keep.push((path, code)),
            },
            _ => keep.push((path, code)),
        }
    }
    if dels.is_empty() || untracked.is_empty() {
        *unstaged = keep;
        return Ok(Vec::new());
    }
    const MAX_SCORE_BYTES: usize = 1 << 20;
    let mut del_side = Vec::with_capacity(dels.len());
    let mut del_body: Vec<Option<Vec<u8>>> = Vec::with_capacity(dels.len());
    for (path, oid) in &dels {
        let (_, body) = read_object_bytes(store, *oid)?;
        del_side.push(RenameSide {
            path: path.clone(),
            size: body.len(),
        });
        del_body.push(if body.len() > MAX_SCORE_BYTES {
            None
        } else {
            Some(body)
        });
    }
    let mut add_side = Vec::with_capacity(untracked.len());
    for path in untracked.iter() {
        let bytes = worktree.get(path).cloned().unwrap_or_default();
        add_side.push(RenameSide {
            path: path.clone(),
            size: bytes.len(),
        });
    }
    let mut used_untracked = vec![false; untracked.len()];
    let mut renames = Vec::new();
    for win in pair_renames(&del_side, &add_side, threshold, |oi, ni| {
        let bytes = worktree
            .get(&add_side[ni].path)
            .map(Vec::as_slice)
            .unwrap_or_default();
        match &del_body[oi] {
            Some(old) => similarity(old, bytes),
            None => 0,
        }
    }) {
        used_untracked[win.new] = true;
        renames.push((
            dels[win.old].0.clone(),
            add_side[win.new].path.clone(),
            win.score,
        ));
    }
    let mut used_del = vec![false; dels.len()];
    for win in renames.iter() {
        if let Some(index) = dels.iter().position(|(path, _)| path == &win.0) {
            used_del[index] = true;
        }
    }
    let mut restaged = keep;
    for (index, (path, _)) in dels.into_iter().enumerate() {
        if !used_del[index] {
            restaged.push((path, 'D'));
        }
    }
    restaged.sort();
    *unstaged = restaged;
    let mut kept_untracked = Vec::with_capacity(untracked.len());
    for (index, path) in untracked.drain(..).enumerate() {
        if !used_untracked[index] {
            kept_untracked.push(path);
        }
    }
    *untracked = kept_untracked;
    renames.sort();
    Ok(renames)
}

/// Maps every path of the `HEAD` tree to its mode and oid. Unborn `HEAD`
/// (no commit yet) maps to the empty tree.
fn head_tree_map(
    ctx: &Ctx,
    store: &Store,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, ruk_core::ids::Oid)>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    let resolved = super::state::resolve_head(store, &workspace.head)?;
    let oid = match resolved {
        super::state::ResolvedHead::Detached(oid) => Some(oid),
        super::state::ResolvedHead::Symbolic(resolved) => resolved.oid,
    };
    let Some(commit_oid) = oid else {
        return Ok(BTreeMap::new());
    };
    let records = ruk_core::records::Records::new(store);
    let record = records
        .get_commit(&ruk_core::heads::Head::Git { oid: commit_oid })
        .map_err(GitError::from)?
        .ok_or_else(|| GitError::NotFound {
            detail: format!("HEAD points at missing commit {}", commit_oid.to_hex()),
        })?;
    let tree = commit_tree_oid(&record)?;
    let mut map = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, ctx.kind()?, tree)? {
        map.insert(path, (mode, oid));
    }
    Ok(map)
}

/// Reads one walked entry's bytes for comparison.
fn read_entry_bytes(ctx: &Ctx, entry: &WorktreeEntry) -> Result<Vec<u8>, GitError> {
    match entry.file_type {
        WorktreeType::File => read_worktree_file(&ctx.file_base, &entry.path),
        WorktreeType::Symlink => {
            let full = join_base(&ctx.file_base, &entry.path)?;
            std::fs::read_link(&full)
                .map(|target| target.as_os_str().as_encoded_bytes().to_vec())
                .map_err(|err| GitError::Io {
                    detail: format!("reading link {}: {err}", full.display()),
                })
        }
    }
}
/// Reports whether the worktree file at `path` is proven unchanged by its
/// index row: the cached tuple matches a fresh lstat and the file's mtime
/// predates the index write stamp. Never fails: any lookup or stat error
/// answers false and the caller hashes, exactly as without the cache.
pub(crate) fn is_stat_clean(
    ctx: &Ctx,
    entry: &IndexEntry,
    path: &[u8],
    stamp: Option<i64>,
) -> bool {
    let Ok(full) = join_base(&ctx.file_base, path) else {
        return false;
    };
    let Ok(meta) = std::fs::symlink_metadata(&full) else {
        return false;
    };
    let mode = if meta.file_type().is_symlink() {
        FileMode::Symlink
    } else {
        file_mode_of(&meta)
    };
    let Ok(fresh) = super::state::stat_from_meta(&meta) else {
        return false;
    };
    matches!(
        super::state::trust_index_entry(entry, &fresh, mode, stamp),
        super::state::StatTrust::Clean
    )
}

/// Renders porcelain v1 lines (`## <branch>`, `XY <path>`,
/// `R  <old> -> <new>`, `?? <path>`, `!! <path>`), terminated by `eol`
/// (`--null` uses NUL).
fn render_porcelain(
    plan: &StatusPlan,
    branch: Option<&str>,
    ignored: Option<&[Vec<u8>]>,
    eol: u8,
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(branch) = branch {
        out.extend_from_slice(format!("## {branch}").as_bytes());
        out.push(eol);
    }
    let mut staged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code, _) in &plan.staged {
        staged_map.insert(path, *code);
    }
    let mut unstaged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code) in &plan.unstaged {
        unstaged_map.insert(path, *code);
    }
    let mut rename_new: BTreeMap<&Vec<u8>, &Vec<u8>> = BTreeMap::new();
    for (old, new, _) in &plan.renames {
        rename_new.insert(new, old);
    }
    let mut lines: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for path in staged_map.keys().chain(unstaged_map.keys()) {
        if plan.renames.iter().any(|(old, _, _)| old == *path)
            || plan.renames_unstaged.iter().any(|(old, _, _)| old == *path)
        {
            continue;
        }
        let staged_code = staged_map.get(path).copied().unwrap_or(' ');
        let unstaged_code = unstaged_map.get(path).copied().unwrap_or(' ');
        if staged_code == ' ' && unstaged_code == ' ' {
            continue;
        }
        match rename_new.get(path) {
            Some(old) => {
                lines.insert(
                    (*path).clone(),
                    v1_rename_line(&format!("R{unstaged_code}"), path, old, eol),
                );
            }
            None => {
                let line = format!(
                    "{staged_code}{unstaged_code} {}",
                    String::from_utf8_lossy(path)
                );
                lines.insert((*path).clone(), line.into_bytes());
            }
        }
    }
    for (new, old) in &rename_new {
        if lines.contains_key(*new) {
            continue;
        }
        lines.insert((*new).clone(), v1_rename_line("R ", new, old, eol));
    }
    for (old, new, _) in &plan.renames_unstaged {
        lines.insert(new.clone(), v1_rename_line(" R", new, old, eol));
    }
    // `-z` rename records self-terminate (`XY new\0old\0`); every other
    // line still takes the entry terminator. A path can never end in NUL,
    // so the terminator test is exact.
    for line in lines.into_values() {
        out.extend_from_slice(&line);
        if line.last() != Some(&b'\0') {
            out.push(eol);
        }
    }
    for path in &plan.unmerged {
        if !staged_map.contains_key(&path) {
            out.extend_from_slice(b"UU ");
            out.extend_from_slice(path);
            out.push(eol);
        }
    }
    for path in &plan.untracked {
        out.extend_from_slice(b"?? ");
        out.extend_from_slice(path);
        out.push(eol);
    }
    if let Some(ignored) = ignored {
        for path in ignored {
            out.extend_from_slice(b"!! ");
            out.extend_from_slice(path);
            out.push(eol);
        }
    }
    out
}

/// Renders one v1 rename line: `XY old -> new` normally, but
/// `XY new\0old\0` (self-terminated, raw paths) under `-z`, the way the
/// oracle reverses and NUL-splits rename records without C-quoting.
fn v1_rename_line(key: &str, new: &[u8], old: &[u8], eol: u8) -> Vec<u8> {
    let mut line = format!("{key} ").into_bytes();
    if eol == b'\0' {
        line.extend_from_slice(new);
        line.push(b'\0');
        line.extend_from_slice(old);
        line.push(b'\0');
    } else {
        line.extend_from_slice(String::from_utf8_lossy(old).as_bytes());
        line.extend_from_slice(b" -> ");
        line.extend_from_slice(String::from_utf8_lossy(new).as_bytes());
    }
    line
}

/// Pushes one `eol`-terminated header line.
fn push_v2_line(out: &mut Vec<u8>, text: &str, eol: u8) {
    out.extend_from_slice(text.as_bytes());
    out.push(eol);
}

/// Porcelain v2 selections that travel together: the plan, display flags,
/// and the line terminator.
struct V2Input<'a> {
    plan: &'a StatusPlan,
    show_branch: bool,
    ignored: Option<&'a [Vec<u8>]>,
    ahead_behind: AheadBehind,
    show_stash: bool,
    eol: u8,
}

/// Writes the `# branch.*` (plus `# stash`) headers for porcelain v2;
/// nothing without `--branch`, tracking only with a live upstream.
fn v2_branch_headers(
    ctx: &Ctx,
    store: &Store,
    input: &V2Input<'_>,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    if !input.show_branch {
        return Ok(());
    }
    match head_oid(store) {
        Ok(tip) => push_v2_line(out, &format!("# branch.oid {}", tip.to_hex()), input.eol),
        Err(_) => push_v2_line(out, "# branch.oid (initial)", input.eol),
    }
    let Some(name) = current_short_branch(store)? else {
        push_v2_line(out, "# branch.head (detached)", input.eol);
        return Ok(());
    };
    push_v2_line(out, &format!("# branch.head {name}"), input.eol);
    if let Some(upstream) = branch_upstream(ctx, store, &name) {
        let Some(target) = upstream.oid else {
            return Ok(());
        };
        push_v2_line(
            out,
            &format!("# branch.upstream {}", upstream.display),
            input.eol,
        );
        if input.ahead_behind == AheadBehind::Full
            && let Ok(head) = head_oid(store)
        {
            let (ahead, behind) = ahead_behind_counts(store, head, target)?;
            push_v2_line(out, &format!("# branch.ab +{ahead} -{behind}"), input.eol);
        }
    }
    Ok(())
}

/// Writes the `# stash N` line for porcelain v2; unlike the branch
/// headers this needs only `--show-stash`, never `--branch`.
fn v2_stash_line(store: &Store, eol: u8, out: &mut Vec<u8>) -> Result<(), GitError> {
    let entries = stash_count(store)?;
    if entries > 0 {
        push_v2_line(out, &format!("# stash {entries}"), eol);
    }
    Ok(())
}

/// Renders porcelain v2: `# branch.*` headers (with `--branch`), `1`
/// changed lines with head/index/worktree modes and oids, `2` rename
/// lines with scores, `u` unmerged lines with stage modes and oids, `?`
/// untracked, `!` ignored. The lane is stat-less, so the worktree mode
/// column reuses the indexed mode; missing sides print `000000` and the
/// zero oid. Submodules report `N...`: no submodule state is tracked.
fn render_porcelain_v2(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    input: &V2Input<'_>,
) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    v2_branch_headers(ctx, store, input, &mut out)?;
    if input.show_stash {
        v2_stash_line(store, input.eol, &mut out)?;
    }
    let plan = input.plan;
    let eol = input.eol;
    let head_tree = head_tree_map(ctx, store)?;
    let rows = scan_index(store, kind)?;
    let mut index: BTreeMap<Vec<u8>, (TreeMode, ruk_core::ids::Oid)> = BTreeMap::new();
    let mut stages: BTreeMap<Vec<u8>, Vec<(u8, TreeMode, ruk_core::ids::Oid)>> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        let key = path.as_bytes().to_vec();
        let value = (TreeMode::from(entry.mode()), entry.oid());
        if *stage == Stage::Zero {
            index.insert(key, value);
        } else {
            stages
                .entry(key)
                .or_default()
                .push((stage.as_u8(), value.0, value.1));
        }
    }
    let zero = "0".repeat(kind.hex_len());
    let head_side = |path: &[u8]| -> (u32, String) {
        match head_tree.get(path) {
            Some((mode, oid)) => (mode.octal(), oid.to_hex()),
            None => (0, zero.clone()),
        }
    };
    let index_side = |path: &[u8]| -> (u32, String) {
        match index.get(path) {
            Some((mode, oid)) => (mode.octal(), oid.to_hex()),
            None => (0, zero.clone()),
        }
    };
    let mut staged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code, _) in &plan.staged {
        staged_map.insert(path, *code);
    }
    let mut unstaged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code) in &plan.unstaged {
        unstaged_map.insert(path, *code);
    }
    let mut rename_new: BTreeMap<&Vec<u8>, (&Vec<u8>, u8)> = BTreeMap::new();
    for (old, new, score) in plan.renames.iter().chain(plan.renames_unstaged.iter()) {
        rename_new.insert(new, (old, *score));
    }
    let mut paths: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (path, _, _) in &plan.staged {
        paths.insert(path.clone());
    }
    for (path, _) in &plan.unstaged {
        paths.insert(path.clone());
    }
    for (old, new, _) in plan.renames.iter().chain(plan.renames_unstaged.iter()) {
        paths.remove(old);
        paths.insert(new.clone());
    }
    let unmerged: HashSet<&Vec<u8>> = plan.unmerged.iter().collect();
    // `-z` separates rename sides with NUL instead of TAB, like the oracle.
    let sep = if eol == b'\0' { b'\0' } else { b'\t' };
    for path in &paths {
        if unmerged.contains(&path) {
            continue;
        }
        let worktree = unstaged_map.get(&path).copied().unwrap_or('.');
        if let Some((old, score)) = rename_new.get(&path) {
            let (mode_head, oid_head) = head_side(old);
            let (mode_index, oid_index) = index_side(path);
            let mode_worktree = if worktree == 'D' {
                0
            } else if mode_index != 0 {
                mode_index
            } else {
                index_side(old).0
            };
            let mut line = format!(
                "2 R{worktree} N... {mode_head:06o} {mode_index:06o} {mode_worktree:06o} {oid_head} {oid_index} R{score} ",
            )
            .into_bytes();
            line.extend_from_slice(path);
            line.push(sep);
            line.extend_from_slice(old);
            line.push(eol);
            out.extend_from_slice(&line);
            continue;
        }
        let staged = staged_map.get(&path).copied().unwrap_or('.');
        let (mode_head, oid_head) = head_side(path);
        let (mode_index, oid_index) = index_side(path);
        let mode_worktree = if worktree == 'D' {
            0
        } else if mode_index != 0 {
            mode_index
        } else {
            mode_head
        };
        let mut line = format!(
            "1 {staged}{worktree} N... {mode_head:06o} {mode_index:06o} {mode_worktree:06o} {oid_head} {oid_index} ",
        )
        .into_bytes();
        line.extend_from_slice(path);
        line.push(eol);
        out.extend_from_slice(&line);
    }
    for path in &plan.unmerged {
        let mut mode = [0u32; 3];
        let mut oid = [zero.clone(), zero.clone(), zero.clone()];
        let mut mask = 0u8;
        if let Some(entries) = stages.get(path) {
            for (stage, entry_mode, entry_oid) in entries {
                if (1..=3).contains(stage) {
                    let slot = usize::from(*stage - 1);
                    mode[slot] = entry_mode.octal();
                    oid[slot] = entry_oid.to_hex();
                    mask |= 1 << (*stage - 1);
                }
            }
        }
        let key = match mask {
            1 => "DD",
            2 => "AU",
            3 => "UD",
            4 => "UA",
            5 => "DU",
            6 => "AA",
            _ => "UU",
        };
        let mut line = format!(
            "u {key} N... {:06o} {:06o} {:06o} {:06o} {} {} {} ",
            mode[0], mode[1], mode[2], mode[1], oid[0], oid[1], oid[2],
        )
        .into_bytes();
        line.extend_from_slice(path);
        line.push(eol);
        out.extend_from_slice(&line);
    }
    for path in &plan.untracked {
        out.extend_from_slice(b"? ");
        out.extend_from_slice(path);
        out.push(eol);
    }
    if let Some(ignored) = input.ignored {
        for path in ignored {
            out.extend_from_slice(b"! ");
            out.extend_from_slice(path);
            out.push(eol);
        }
    }
    Ok(out)
}

/// One configured upstream: the display short name plus the ref target
/// (`None` when the upstream is gone).
struct Upstream {
    display: String,
    oid: Option<ruk_core::ids::Oid>,
}

/// Resolves the upstream of one local branch from
/// `branch.<name>.remote`/`.merge` (the pair `branch -u` records): remote
/// `.` means the merge ref itself, otherwise the remote-tracking ref under
/// `refs/remotes/<remote>/`. `None` means no upstream is configured.
fn branch_upstream(ctx: &Ctx, store: &Store, branch: &str) -> Option<Upstream> {
    let remote = ctx.config_get(&format!("branch.{branch}.remote"))?;
    let merge = ctx.config_get(&format!("branch.{branch}.merge"))?;
    let full = if remote == "." {
        merge.clone()
    } else {
        let leaf = merge.strip_prefix("refs/heads/").unwrap_or(&merge);
        format!("refs/remotes/{remote}/{leaf}")
    };
    let display = full
        .strip_prefix("refs/remotes/")
        .or_else(|| full.strip_prefix("refs/heads/"))
        .unwrap_or(&full)
        .to_owned();
    let name = ruk_core::refdata::RefName::new(full).ok()?;
    // A configured upstream with no ref is gone, not unconfigured: report
    // it so the `[gone]` and gone sentences stay reachable.
    let gone = || {
        Some(Upstream {
            display: display.clone(),
            oid: None,
        })
    };
    let mut target = match read_ref(store, &name).ok()? {
        Some(target) => target,
        None => return gone(),
    };
    for _ in 0..16 {
        match target {
            ruk_core::refdata::RefTarget::Direct(oid) => {
                return Some(Upstream {
                    display,
                    oid: Some(oid),
                });
            }
            ruk_core::refdata::RefTarget::Symbolic(next) => {
                target = match read_ref(store, &next).ok()? {
                    Some(target) => target,
                    None => return gone(),
                };
            }
        }
    }
    None
}

/// Counts commits reachable from `head` but not `upstream` (ahead) and
/// vice versa (behind) by ancestry-set difference.
fn ahead_behind_counts(
    store: &Store,
    head: ruk_core::ids::Oid,
    upstream: ruk_core::ids::Oid,
) -> Result<(usize, usize), GitError> {
    if head == upstream {
        return Ok((0, 0));
    }
    let head_set: HashSet<ruk_core::ids::Oid> = walk_history(store, &[head], None)?
        .into_iter()
        .map(|(oid, _)| oid)
        .collect();
    let upstream_set: HashSet<ruk_core::ids::Oid> = walk_history(store, &[upstream], None)?
        .into_iter()
        .map(|(oid, _)| oid)
        .collect();
    Ok((
        head_set.difference(&upstream_set).count(),
        upstream_set.difference(&head_set).count(),
    ))
}

/// Renders the oracle's long-format tracking sentence for one branch, or
/// `None` without a configured upstream (or before the first commit).
fn tracking_sentence(ctx: &Ctx, store: &Store, branch: &str) -> Result<Option<String>, GitError> {
    let Some(upstream) = branch_upstream(ctx, store, branch) else {
        return Ok(None);
    };
    let Some(target) = upstream.oid else {
        return Ok(Some(format!(
            "Your branch is based on '{}', but the upstream is gone.",
            upstream.display
        )));
    };
    let Ok(head) = head_oid(store) else {
        return Ok(None);
    };
    let (ahead, behind) = ahead_behind_counts(store, head, target)?;
    let noun = |count: usize| {
        if count == 1 {
            "commit".to_owned()
        } else {
            "commits".to_owned()
        }
    };
    Ok(Some(match (ahead, behind) {
        (0, 0) => format!("Your branch is up to date with '{}'.", upstream.display),
        (ahead, 0) => format!(
            "Your branch is ahead of '{}' by {ahead} {}.",
            upstream.display,
            noun(ahead)
        ),
        (0, behind) => format!(
            "Your branch is behind '{}' by {behind} {}.",
            upstream.display,
            noun(behind)
        ),
        (ahead, behind) => format!(
            "Your branch and '{}' have diverged,\nand have {ahead} and {behind} different commits each, respectively.",
            upstream.display
        ),
    }))
}

/// Renders the porcelain v1 `##` header: the short branch (or
/// `HEAD (no branch)` detached) with `...<upstream> [ahead N, behind M]`
/// tracking, or `[gone]` when the upstream ref is missing.
fn porcelain_v1_branch(
    ctx: &Ctx,
    store: &Store,
    ahead_behind: AheadBehind,
) -> Result<String, GitError> {
    let Some(name) = current_short_branch(store)? else {
        return Ok("HEAD (no branch)".to_owned());
    };
    let mut line = name.clone();
    if let Some(upstream) = branch_upstream(ctx, store, &name) {
        line.push_str("...");
        line.push_str(&upstream.display);
        match upstream.oid {
            None => line.push_str(" [gone]"),
            Some(target) => {
                if ahead_behind == AheadBehind::Full
                    && let Ok(head) = head_oid(store)
                {
                    let (ahead, behind) = ahead_behind_counts(store, head, target)?;
                    match (ahead, behind) {
                        (0, 0) => {}
                        (ahead, 0) => line.push_str(&format!(" [ahead {ahead}]")),
                        (0, behind) => line.push_str(&format!(" [behind {behind}]")),
                        (ahead, behind) => {
                            line.push_str(&format!(" [ahead {ahead}, behind {behind}]"))
                        }
                    }
                }
            }
        }
    }
    Ok(line)
}

/// Counts live stash entries across numbering gaps left by drops.
fn stash_count(store: &Store) -> Result<usize, GitError> {
    let high = stash_high_water(store)?;
    let mut entries = 0;
    for slot in 0..high {
        if stash_read(store, slot)?.is_some() {
            entries += 1;
        }
    }
    Ok(entries)
}

/// Names the checked-out branch for long status, shortened like the
/// oracle (`HEAD detached at <short>` when detached).
pub(crate) fn long_branch_label(store: &Store) -> Result<String, GitError> {
    match current_short_branch(store)? {
        Some(name) => Ok(name),
        None => {
            let tip = super::state::head_oid(store)?;
            Ok(format!("HEAD detached at {}", short_oid(&tip)))
        }
    }
}

/// Reads the checked-out branch shortened, or `None` when detached.
fn current_short_branch(store: &Store) -> Result<Option<String>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match &workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => Ok(Some(
            name.to_utf8()
                .map_or_else(|| format!("{name}"), str::to_owned)
                .trim_start_matches("refs/heads/")
                .to_owned(),
        )),
        ruk_core::workspace::HeadRef::Detached(_) => Ok(None),
    }
}

/// Shortens one object id for status output.
fn short_oid(oid: &ruk_core::ids::Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

/// Reports whether `HEAD` is unborn (a branch with no commit yet), which
/// selects the `No commits yet` status block and the `rm --cached` hint.
fn head_unborn(store: &Store) -> Result<bool, GitError> {
    let (workspace, _) = load_or_default(store)?;
    Ok(match super::state::resolve_head(store, &workspace.head)? {
        super::state::ResolvedHead::Detached(_) => false,
        super::state::ResolvedHead::Symbolic(resolved) => resolved.oid.is_none(),
    })
}

/// Renders the default long status from one plan with no tracking, stash,
/// or ignored extras: the historical three-argument entry point.
pub(crate) fn render_long(store: &Store, branch: &str, plan: &StatusPlan) -> Vec<u8> {
    render_long_full(store, branch, plan, None, 0, None)
}

/// Renders the default long status from one plan, matching the oracle's
/// section order, hint text, blank lines, and footers exactly. `tracking`
/// is the upstream sentence (or `None`), `stash` the stash entry count
/// (`--show-stash`, 0 hides), and `ignored` the `--ignored` list.
pub(crate) fn render_long_full(
    store: &Store,
    branch: &str,
    plan: &StatusPlan,
    tracking: Option<&str>,
    stash: usize,
    ignored: Option<&[Vec<u8>]>,
) -> Vec<u8> {
    let unborn = head_unborn(store).unwrap_or(false);
    let mut out = Vec::new();
    out.extend_from_slice(format!("On branch {branch}\n").as_bytes());
    if let Some(sentence) = tracking {
        out.extend_from_slice(sentence.as_bytes());
        out.push(b'\n');
    }
    if unborn {
        out.extend_from_slice(b"\nNo commits yet\n");
    }
    let ignored = ignored.unwrap_or(&[]);
    if plan.staged.is_empty()
        && plan.renames.is_empty()
        && plan.renames_unstaged.is_empty()
        && plan.unstaged.is_empty()
        && plan.untracked.is_empty()
        && ignored.is_empty()
    {
        if unborn {
            out.extend_from_slice(
                b"\nnothing to commit (create/copy files and use \"git add\" to track)\n",
            );
        } else {
            out.extend_from_slice(b"nothing to commit, working tree clean\n");
        }
        out.extend_from_slice(&stash_summary(stash));
        return line(out);
    }
    let mut sections: Vec<Vec<u8>> = Vec::new();
    let staged_lines = staged_status_lines(plan);
    if !staged_lines.is_empty() {
        let mut section = Vec::from(b"Changes to be committed:\n".as_slice());
        if unborn {
            section.extend_from_slice(b"  (use \"git rm --cached <file>...\" to unstage)\n");
        } else {
            section.extend_from_slice(b"  (use \"git restore --staged <file>...\" to unstage)\n");
        }
        for entry in staged_lines {
            section.extend_from_slice(&entry);
        }
        sections.push(section);
    }
    if !plan.unstaged.is_empty() || !plan.renames_unstaged.is_empty() {
        let mut section = Vec::from(b"Changes not staged for commit:\n".as_slice());
        if plan.unstaged.iter().any(|(_, code)| *code == 'D') {
            section.extend_from_slice(
                b"  (use \"git add/rm <file>...\" to update what will be committed)\n",
            );
        } else {
            section.extend_from_slice(
                b"  (use \"git add <file>...\" to update what will be committed)\n",
            );
        }
        section.extend_from_slice(
            b"  (use \"git restore <file>...\" to discard changes in working directory)\n",
        );
        for (path, code) in &plan.unstaged {
            let word = if *code == 'D' { "deleted" } else { "modified" };
            section.extend_from_slice(&status_entry(word, path));
        }
        let mut renamed: Vec<&(Vec<u8>, Vec<u8>, u8)> = plan.renames_unstaged.iter().collect();
        renamed.sort_by(|left, right| left.1.cmp(&right.1));
        for (old, new, _) in renamed {
            let display = format!(
                "{} -> {}",
                String::from_utf8_lossy(old),
                String::from_utf8_lossy(new)
            );
            section.extend_from_slice(&format!("\t{:11} {}\n", "renamed:", display).into_bytes());
        }
        sections.push(section);
    }
    if !plan.untracked.is_empty() {
        let mut section = Vec::from(b"Untracked files:\n".as_slice());
        section.extend_from_slice(
            b"  (use \"git add <file>...\" to include in what will be committed)\n",
        );
        for path in &plan.untracked {
            section.extend_from_slice(format!("\t{}\n", String::from_utf8_lossy(path)).as_bytes());
        }
        sections.push(section);
    }
    if !ignored.is_empty() {
        let mut section = Vec::from(b"Ignored files:\n".as_slice());
        section.extend_from_slice(
            b"  (use \"git add -f <file>...\" to include in what will be committed)\n",
        );
        for path in ignored {
            section.extend_from_slice(format!("\t{}\n", String::from_utf8_lossy(path)).as_bytes());
        }
        sections.push(section);
    }
    let footer: &[u8] = if !plan.staged.is_empty() || !plan.renames.is_empty() {
        b""
    } else if !plan.unstaged.is_empty() || !plan.renames_unstaged.is_empty() {
        b"\nno changes added to commit (use \"git add\" and/or \"git commit -a\")\n"
    } else if !plan.untracked.is_empty() {
        b"\nnothing added to commit but untracked files present (use \"git add\" to track)\n"
    } else {
        b""
    };
    if unborn {
        out.push(b'\n');
    }
    for (index, section) in sections.iter().enumerate() {
        if index > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(section);
    }
    if footer.is_empty() {
        out.push(b'\n');
    } else {
        out.extend_from_slice(footer);
    }
    out.extend_from_slice(&stash_summary(stash));
    line(out)
}
/// Renders `Your stash currently has N entr(y|ies)` for `--show-stash`,
/// empty when no entries are stashed.
fn stash_summary(entries: usize) -> Vec<u8> {
    if entries == 0 {
        return Vec::new();
    }
    let noun = if entries == 1 { "entry" } else { "entries" };
    format!("Your stash currently has {entries} {noun}\n").into_bytes()
}

/// Renders staged entries plus exact renames as aligned `\t<word>:  <path>`
/// lines, sorted by display path.
fn staged_status_lines(plan: &StatusPlan) -> Vec<Vec<u8>> {
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (path, code, _) in &plan.staged {
        let word = match code {
            'A' => "new file",
            'D' => "deleted",
            'U' => "unmerged",
            _ => "modified",
        };
        rows.push((path.clone(), status_entry(word, path)));
    }
    for (old, new, _) in &plan.renames {
        let display = format!(
            "{} -> {}",
            String::from_utf8_lossy(old),
            String::from_utf8_lossy(new)
        );
        rows.push((
            new.clone(),
            format!("\t{:11} {}\n", "renamed:", display).into_bytes(),
        ));
    }
    rows.sort();
    rows.into_iter().map(|(_, entry)| entry).collect()
}

/// Renders one aligned status entry: the `word:` label padded so the path
/// always starts in the same column (`modified:   `, `deleted:    `).
fn status_entry(word: &str, path: &[u8]) -> Vec<u8> {
    format!(
        "\t{:11} {}\n",
        format!("{word}:"),
        String::from_utf8_lossy(path)
    )
    .into_bytes()
}
