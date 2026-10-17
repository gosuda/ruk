//! Staging verbs: `add`, `mv`, `rm`, `update-index`, `ls-files`, `status`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `add` | `WsIndex` stage-0 rows + generation bump | implemented (explicit paths, `-u`, `-A`, `-N`) |
//! | `mv` | row rename across stages + file rename | implemented |
//! | `rm` | row delete + file delete (`--cached` keeps the file) | implemented |
//! | `update-index` | row add/remove/flag edits | implemented (`--cacheinfo`, `--stdin`, `--add`, `--remove`, `--assume-unchanged`, `--skip-worktree`, `--refresh`) |
//! | `ls-files` | row scan | implemented (`-s`, `-u`, `--others`) |
//! | `status` | `HEAD` tree vs index vs worktree | implemented (`--porcelain`, `--short`, long) |
//!
//! Oracle anchors: `git/builtin/add.c`, `git/builtin/mv.c`,
//! `git/builtin/rm.c`, `git/builtin/update-index.c`,
//! `git/builtin/ls-files.c`, `git/builtin/commit.c` (`cmd_status`).

use std::collections::{BTreeMap, HashSet};

use ruk_core::ids::HashKind;
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage};
use ruk_core::store::Store;
use ruk_git::GitError;

use super::state::{
    MAX_OBJECT_BYTES, load_or_default, path_row_mutations, read_path_rows, scan_index,
    unmerged_paths, workspace_mutation,
};
use super::tree::{
    WorktreeEntry, WorktreeType, commit_tree_oid, flatten_tree, join_base, read_object_bytes,
    read_worktree_file, walk_worktree,
};
use super::{Ctx, FlagSpec, collect, line};

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
    store.publish(objects, &mutations).map_err(GitError::from)?;
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
        return stage_bytes(ctx, kind, FileMode::Symlink, &bytes, fill);
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
    stage_bytes(ctx, kind, mode, &bytes, fill)
}

/// Builds the entry for staged bytes under one fill discipline and prepares
/// the blob object for publication. Content fills always emit the object:
/// the store deduplicates by OID at publish, so a known blob costs one
/// prepared frame, never a second record.
fn stage_bytes(
    ctx: &Ctx,
    kind: HashKind,
    mode: FileMode,
    bytes: &[u8],
    fill: AddFill,
) -> Result<(IndexEntry, Vec<ruk_core::store::PreparedObject>), GitError> {
    let entry = match fill {
        AddFill::Content => IndexEntry::for_blob(kind, mode, bytes, None),
        AddFill::Intent => IndexEntry::intent_to_add(kind, FileMode::Regular, None),
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
fn file_mode_of(meta: &std::fs::Metadata) -> FileMode {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o100 != 0 {
            return FileMode::Executable;
        }
    }
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
    let src_file = join_base(&ctx.file_base, src.as_bytes())?;
    let dst_file = join_base(&ctx.file_base, dst.as_bytes())?;
    if let Some(parent) = dst_file.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    store
        .publish(Vec::new(), &mutations)
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
            }
            continue;
        }
        mutations.extend(path_row_mutations(&path, &before, &[])?);
        files.push(join_base(&ctx.file_base, path.as_bytes())?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
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
    Ok(Vec::new())
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
        let stdin = std::io::read_to_string(std::io::stdin()).map_err(|err| GitError::Io {
            detail: format!("reading stdin: {err}"),
        })?;
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
    store.publish(objects, &mutations).map_err(GitError::from)?;
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

/// Shows the working tree status against the index and `HEAD`.
///
/// Oracle: `git/builtin/commit.c` (`cmd_status`).
pub(crate) fn status(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "porcelain",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "short",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "branch",
            short: Some('b'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let plan = status_plan(ctx, store, kind)?;
    if opts.is_set("porcelain") || opts.is_set("short") {
        let branch = opts
            .is_set("branch")
            .then(|| branch_label(store))
            .transpose()?;
        return Ok(render_porcelain(&plan, branch.as_deref()));
    }
    let branch = branch_label(store)?;
    Ok(render_long(&branch, &plan))
}

/// One computed status: staged, unstaged, unmerged, and untracked paths.
struct StatusPlan {
    /// `(path, staged code)` in path order.
    staged: Vec<(Vec<u8>, char)>,
    /// `(path, worktree code)` in path order.
    unstaged: Vec<(Vec<u8>, char)>,
    /// Unmerged paths in path order.
    unmerged: Vec<Vec<u8>>,
    /// Untracked paths in path order.
    untracked: Vec<Vec<u8>>,
}

/// Compares `HEAD` tree, index rows, and worktree files.
fn status_plan(ctx: &Ctx, store: &Store, kind: HashKind) -> Result<StatusPlan, GitError> {
    let head_tree = head_tree_map(ctx, store)?;
    let rows = scan_index(store, kind)?;
    let mut index_merged: BTreeMap<Vec<u8>, (FileMode, ruk_core::ids::Oid)> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            index_merged.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    let unmerged = unmerged_paths(&rows);
    let mut staged = Vec::new();
    let mut known: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    for (path, _) in unmerged.iter() {
        staged.push((path.clone(), 'U'));
        known.insert(path.clone(), true);
    }
    for (path, mode_oid) in &index_merged {
        known.insert(path.clone(), true);
        match head_tree.get(path) {
            None => staged.push((path.clone(), 'A')),
            Some(head_mode_oid) => {
                if head_mode_oid != mode_oid {
                    staged.push((path.clone(), 'M'));
                }
            }
        }
    }
    for (path, _) in &head_tree {
        if !known.contains_key(path) {
            staged.push((path.clone(), 'D'));
        }
    }
    staged.sort();
    let mut blobs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();
    for entry in walk_worktree(&ctx.file_base)? {
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
        if !blobs.contains_key(&key) && !unmerged.contains_key(&key) {
            unstaged.push((key, 'D'));
        }
    }
    unstaged.sort();
    untracked.sort();
    let mut unmerged_paths_sorted: Vec<Vec<u8>> = unmerged.into_keys().collect();
    unmerged_paths_sorted.sort();
    Ok(StatusPlan {
        staged,
        unstaged,
        unmerged: unmerged_paths_sorted,
        untracked,
    })
}

/// Maps every path of the `HEAD` tree to its mode and oid. Unborn `HEAD`
/// (no commit yet) maps to the empty tree.
fn head_tree_map(
    ctx: &Ctx,
    store: &Store,
) -> Result<BTreeMap<Vec<u8>, (FileMode, ruk_core::ids::Oid)>, GitError> {
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

/// Renders porcelain v1 lines (`XY <path>`, `?? <path>`).
fn render_porcelain(plan: &StatusPlan, branch: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(branch) = branch {
        out.extend_from_slice(format!("## {branch}\n").as_bytes());
    }
    let mut staged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code) in &plan.staged {
        staged_map.insert(path, *code);
    }
    let mut unstaged_map: BTreeMap<&Vec<u8>, char> = BTreeMap::new();
    for (path, code) in &plan.unstaged {
        unstaged_map.insert(path, *code);
    }
    let mut paths: Vec<&Vec<u8>> = staged_map
        .keys()
        .chain(unstaged_map.keys())
        .copied()
        .collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        let staged_code = staged_map.get(path).copied().unwrap_or(' ');
        let unstaged_code = unstaged_map.get(path).copied().unwrap_or(' ');
        if staged_code == ' ' && unstaged_code == ' ' {
            continue;
        }
        out.extend_from_slice(format!("{staged_code}{unstaged_code} ").as_bytes());
        out.extend_from_slice(path);
        out.push(b'\n');
    }
    for path in &plan.unmerged {
        if !staged_map.contains_key(&path) {
            out.extend_from_slice(b"UU ");
            out.extend_from_slice(path);
            out.push(b'\n');
        }
    }
    for path in &plan.untracked {
        out.extend_from_slice(b"?? ");
        out.extend_from_slice(path);
        out.push(b'\n');
    }
    out
}

/// Names the checked-out branch, or the detached oid, for long status.
fn branch_label(store: &Store) -> Result<String, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match &workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => Ok(name
            .to_utf8()
            .map_or_else(|| format!("{name}"), str::to_owned)),
        ruk_core::workspace::HeadRef::Detached(oid) => Ok(format!("detached at {}", oid.to_hex())),
    }
}

/// Renders the default long status from one plan.
fn render_long(branch: &str, plan: &StatusPlan) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("On branch {branch}\n").as_bytes());
    if plan.staged.is_empty() && plan.unstaged.is_empty() && plan.untracked.is_empty() {
        out.extend_from_slice(b"nothing to commit, working tree clean\n");
        return line(out);
    }
    if !plan.staged.is_empty() {
        out.extend_from_slice(b"Changes to be committed:\n");
        for (path, code) in &plan.staged {
            let word = match code {
                'A' => "new file",
                'D' => "deleted",
                'U' => "unmerged",
                _ => "modified",
            };
            out.extend_from_slice(
                format!("\t{word}: {}\n", String::from_utf8_lossy(path)).as_bytes(),
            );
        }
    }
    if !plan.unstaged.is_empty() {
        out.extend_from_slice(b"Changes not staged for commit:\n");
        for (path, code) in &plan.unstaged {
            let word = if *code == 'D' { "deleted" } else { "modified" };
            out.extend_from_slice(
                format!("\t{word}: {}\n", String::from_utf8_lossy(path)).as_bytes(),
            );
        }
    }
    if !plan.untracked.is_empty() {
        out.extend_from_slice(b"Untracked files:\n");
        for path in &plan.untracked {
            out.extend_from_slice(format!("\t{}\n", String::from_utf8_lossy(path)).as_bytes());
        }
    }
    line(out)
}
