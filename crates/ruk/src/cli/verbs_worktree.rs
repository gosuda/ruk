//! Secondary working trees: `worktree add`, `list`, `remove`, `prune`.
//!
//! | subcommand | backing | status |
//! | --- | --- | --- |
//! | `add` | commit-tree file materialization + `Pins` row under `cli/worktrees/` | implemented (branches, detach, `-b`/`-B`, `--force`) |
//! | `list` | main workspace row + `cli/worktrees/` scan | implemented (`--porcelain`) |
//! | `remove` | dirty-target guard + directory drop + row delete | implemented (`--force`) |
//! | `prune` | drops rows whose directory is gone | implemented (`--dry-run`/`-n`) |
//!
//! A secondary worktree is a real second directory on disk holding the
//! checked-out files of one commit, linked to the same `.ruk` by a `rukdir:`
//! pointer file and tracked in the store so `list` and `prune` can find it.
//! It is a snapshot checkout, not a second `HEAD`: the CLI workspace row and
//! the index still belong to the main worktree, so commands run inside a
//! secondary directory do not resolve to this repository. Adding inside the
//! repository root is refused, since the main worktree scan has no
//! worktree-boundary concept and would read the nested files as untracked.
//!
//! Oracle anchor: `git/builtin/worktree.c`.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{FactExpectation, FactMutation, FactPageBudget, FactTable, Store};
use ruk_core::workspace::{HeadRef, ResolvedHead};
use ruk_git::GitError;
use serde::{Deserialize, Serialize};

use super::state::{
    apply_refs, branch_name, commit_record, head_oid, load_or_default, read_ref, resolve_head,
    resolve_rev,
};
use super::tree::{
    TreeMode, WorktreeType, commit_tree_oid, flatten_tree, join_base, read_object_bytes,
    walk_worktree,
};
use super::{Collected, Ctx, FlagSpec, collect, line};

/// Tracking-row prefix; the canonical absolute path follows.
const WORKTREE_PREFIX: &[u8] = b"cli/worktrees/";

/// One tracked secondary worktree: where it lives, what it holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WorktreeRecord {
    /// Canonical absolute path of the secondary directory.
    path: String,
    /// Checked-out commit, lowercase hex.
    commit: String,
    /// Checked-out branch as a full ref name, or `None` when detached.
    branch: Option<String>,
}

/// Whether checkout may overwrite divergent files already on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overwrite {
    Refuse,
    Allow,
}

/// Manages secondary working trees.
///
/// Oracle: `git/builtin/worktree.c`.
pub(crate) fn worktree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "porcelain",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "detach",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "branch",
            short: Some('b'),
            takes_value: true,
        },
        FlagSpec {
            long: "force-branch",
            short: Some('B'),
            takes_value: true,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "dry-run",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    match opts.positionals.first().map(String::as_str) {
        None => list(ctx, &opts),
        Some("list") => {
            if opts.positionals.len() != 1 {
                return Err(GitError::Invalid {
                    detail: "usage: worktree list [--porcelain]".to_owned(),
                });
            }
            list(ctx, &opts)
        }
        Some("add") => add(ctx, &opts),
        Some("remove") | Some("rm") => remove(ctx, &opts),
        Some("prune") => prune(ctx, &opts),
        Some(other) => Err(GitError::Invalid {
            detail: format!("unknown worktree subcommand {other:?}"),
        }),
    }
}

/// Adds a secondary checkout of one commit into a new directory.
fn add(ctx: &mut Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let new_branch = opts.single("branch")?;
    let force_branch = opts.single("force-branch")?;
    if new_branch.is_some() && force_branch.is_some() {
        return Err(GitError::Invalid {
            detail: "usage: worktree add [--detach] [-b <new> | -B <new>] [--force] <path> [<commit-ish>]"
                .to_owned(),
        });
    }
    let tail: &[String] = opts.positionals.get(1..).unwrap_or(&[]);
    let (path_arg, rev_arg) = match tail {
        [path] => (path.as_str(), None),
        [path, rev] => (path.as_str(), Some(rev.as_str())),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: worktree add [--detach] [-b <new> | -B <new>] [--force] <path> [<commit-ish>]"
                    .to_owned(),
            });
        }
    };
    let overwrite = if opts.is_set("force") {
        Overwrite::Allow
    } else {
        Overwrite::Refuse
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target = canonical_path(&ctx.env.cwd, path_arg)?;
    if target.starts_with(&ctx.root) {
        return Err(GitError::Invalid {
            detail: format!(
                "cannot add a worktree inside the repository at {}",
                ctx.root.display()
            ),
        });
    }
    if target.join(".ruk").is_dir() {
        return Err(GitError::Invalid {
            detail: format!(
                "cannot add a worktree at {}: it already holds a repository",
                target.display()
            ),
        });
    }
    if dir_non_empty(&target)? && overwrite == Overwrite::Refuse {
        return Err(GitError::Invalid {
            detail: format!(
                "directory {} is not empty; use --force to check out into it",
                target.display()
            ),
        });
    }

    let path_text = display_path(&target)?;
    if store
        .fact(FactTable::Pins, &record_key(&path_text))?
        .is_some()
    {
        return Err(GitError::Invalid {
            detail: format!("{} is already a registered worktree", target.display()),
        });
    }
    let (oid, branch, created, pending) = if let Some(name) = new_branch {
        let (start, refname) = plan_new_branch(store, kind, &name, rev_arg)?;
        (
            start,
            Some(refname.to_string()),
            true,
            Some((refname, start, RefExpect::Absent)),
        )
    } else if let Some(name) = force_branch {
        let (start, refname) = plan_branch_reset(store, kind, &name, rev_arg)?;
        (
            start,
            Some(refname.to_string()),
            true,
            Some((refname, start, RefExpect::Any)),
        )
    } else if opts.is_set("detach") {
        (
            resolve_detached_head(store, kind, rev_arg)?,
            None,
            false,
            None,
        )
    } else {
        let (oid, branch) = resolve_attached_head(store, kind, rev_arg)?;
        (oid, branch, false, None)
    };
    if let Some(name) = &branch
        && let Some(holder) = holder_of(store, &ctx.root, name)?
    {
        return Err(GitError::Invalid {
            detail: format!("{name:?} is already used by worktree at {holder:?}"),
        });
    }
    if let Some((refname, start, expected)) = pending {
        write_add_branch(store, kind, refname, start, expected)?;
    }
    let record = commit_record(store, oid)?;
    let tree = commit_tree_oid(&record)?;
    std::fs::create_dir_all(&target).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", target.display()),
    })?;
    if overwrite == Overwrite::Allow {
        materialize_tree_overwrite(store, kind, tree, &target)?;
    } else {
        materialize_tree(store, kind, tree, &target)?;
    }
    write_link_file(&target, &ctx.root.join(".ruk"))?;
    let value = sonic_rs::to_vec(&WorktreeRecord {
        path: path_text.clone(),
        commit: oid.to_hex(),
        branch: branch.clone(),
    })
    .map_err(|err| GitError::Io {
        detail: format!("worktree record encode: {err}"),
    })?;
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key: record_key(&path_text),
                expected: FactExpectation::Absent,
                value: Some(value),
            }],
        )
        .map_err(GitError::from)?;

    if opts.is_set("quiet") {
        return Ok(Vec::new());
    }
    let summary = match &branch {
        Some(name) if created => format!("new branch '{}'", short_branch(name)),
        Some(name) => format!("checking out '{}'", short_branch(name)),
        None => format!("detached HEAD {}", short_oid(&oid)),
    };
    Ok(line(format!("Preparing worktree ({summary})").into_bytes()))
}

/// Resolves a detached checkout: the named revision, defaulting to `HEAD`.
fn resolve_detached_head(
    store: &Store,
    kind: HashKind,
    rev: Option<&str>,
) -> Result<Oid, GitError> {
    let oid = match rev {
        Some(rev) => resolve_rev(store, kind, rev)?,
        None => head_oid(store)?,
    };
    commit_record(store, oid)?;
    Ok(oid)
}

/// Resolves a branch checkout: the named branch, defaulting to `HEAD`.
///
/// A revision that names a branch attaches to it; any other revision (or a
/// detached `HEAD` with no revision) detaches.
fn resolve_attached_head(
    store: &Store,
    kind: HashKind,
    rev: Option<&str>,
) -> Result<(Oid, Option<String>), GitError> {
    match rev {
        None => {
            let (workspace, _) = load_or_default(store)?;
            match &workspace.head {
                HeadRef::Symbolic(name) => {
                    let oid = head_oid(store)?;
                    Ok((oid, Some(name.to_string())))
                }
                HeadRef::Detached(oid) => Ok((*oid, None)),
            }
        }
        Some(rev) => {
            let oid = resolve_rev(store, kind, rev)?;
            commit_record(store, oid)?;
            Ok((
                oid,
                attach_candidate(store, rev)?.map(|name| name.to_string()),
            ))
        }
    }
}

/// Names the branch `rev` designates, when it designates a local branch.
fn attach_candidate(store: &Store, rev: &str) -> Result<Option<RefName>, GitError> {
    if let Ok(short) = branch_name(rev)
        && read_ref(store, &short)?.is_some()
    {
        return Ok(Some(short));
    }
    if let Ok(full) = RefName::new(rev)
        && rev.starts_with("refs/heads/")
        && read_ref(store, &full)?.is_some()
    {
        return Ok(Some(full));
    }
    Ok(None)
}

/// Plans the `-b` branch of a new worktree without writing it.
fn plan_new_branch(
    store: &Store,
    kind: HashKind,
    name: &str,
    rev: Option<&str>,
) -> Result<(Oid, RefName), GitError> {
    let (start, refname) = resolve_branch_start(store, kind, name, rev)?;
    if read_ref(store, &refname)?.is_some() {
        return Err(GitError::Invalid {
            detail: format!("branch {name:?} already exists"),
        });
    }
    Ok((start, refname))
}

/// Plans the `-B` branch reset of a new worktree without writing it.
fn plan_branch_reset(
    store: &Store,
    kind: HashKind,
    name: &str,
    rev: Option<&str>,
) -> Result<(Oid, RefName), GitError> {
    resolve_branch_start(store, kind, name, rev)
}

/// Resolves one worktree branch name to its start commit.
fn resolve_branch_start(
    store: &Store,
    kind: HashKind,
    name: &str,
    rev: Option<&str>,
) -> Result<(Oid, RefName), GitError> {
    let refname = branch_name(name)?;
    let start = match rev {
        Some(rev) => resolve_rev(store, kind, rev)?,
        None => head_oid(store)?,
    };
    commit_record(store, start)?;
    Ok((start, refname))
}

/// Writes one worktree branch ref under its creation expectation.
fn write_add_branch(
    store: &Store,
    kind: HashKind,
    refname: RefName,
    start: Oid,
    expected: RefExpect,
) -> Result<(), GitError> {
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected,
            change: RefChange::Set(RefTarget::Direct(start)),
        }],
    )?;
    Ok(())
}

/// Lists the main worktree followed by every tracked secondary.
fn list(ctx: &mut Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let porcelain = opts.is_set("porcelain");
    let mut entries: Vec<(String, String, Option<String>)> = Vec::new();
    let (workspace, _) = load_or_default(store)?;
    let (main_sha, main_branch) = match resolve_head(store, &workspace.head)? {
        ResolvedHead::Detached(oid) => (oid.to_hex(), None),
        ResolvedHead::Symbolic(resolved) => {
            let sha = resolved
                .oid
                .map(|oid| oid.to_hex())
                .unwrap_or_else(|| kind.zero_oid().to_hex());
            (sha, Some(resolved.terminal.to_string()))
        }
    };
    entries.push((display_path(&ctx.root)?, main_sha, main_branch));
    for (record, _) in scan_records(store)? {
        entries.push((record.path, record.commit, record.branch));
    }
    let mut out = Vec::new();
    for (index, (path, sha, branch)) in entries.iter().enumerate() {
        if porcelain {
            if index > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(format!("worktree {path}\nHEAD {sha}\n").as_bytes());
            match branch {
                Some(name) => out.extend_from_slice(format!("branch {name}\n").as_bytes()),
                None => out.extend_from_slice(b"detached\n"),
            }
            continue;
        }
        let shown = match branch {
            Some(name) => short_branch(name).to_owned(),
            None => "(detached)".to_owned(),
        };
        out.extend_from_slice(format!("{path}  {sha}  [{shown}]\n").as_bytes());
    }
    Ok(out)
}

/// Removes a secondary worktree, refusing dirty checkouts without `--force`.
fn remove(ctx: &mut Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let tail: &[String] = opts.positionals.get(1..).unwrap_or(&[]);
    let [path] = tail else {
        return Err(GitError::Invalid {
            detail: "usage: worktree remove [--force] <path>".to_owned(),
        });
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target = canonical_path(&ctx.env.cwd, path)?;
    if target == ctx.root {
        return Err(GitError::Invalid {
            detail: "cannot remove the main worktree".to_owned(),
        });
    }
    let path_text = display_path(&target)?;
    let key = record_key(&path_text);
    let Some(raw) = store.fact(FactTable::Pins, &key)? else {
        return Err(GitError::NotFound {
            detail: format!("{} is not a registered worktree", target.display()),
        });
    };
    let record: WorktreeRecord = sonic_rs::from_slice(&raw).map_err(|err| GitError::Corrupt {
        detail: format!("worktree record does not decode: {err}"),
    })?;
    let base = PathBuf::from(&record.path);
    if !base.exists() {
        return Err(GitError::Invalid {
            detail: format!(
                "worktree at {} is gone; use `worktree prune` to drop it",
                record.path
            ),
        });
    }
    if !opts.is_set("force") && worktree_dirty(store, kind, &record, &base)? {
        return Err(GitError::Invalid {
            detail: format!(
                "worktree at {} has modified or untracked files; use --force",
                record.path
            ),
        });
    }
    std::fs::remove_dir_all(&base).map_err(|err| GitError::Io {
        detail: format!("removing {}: {err}", base.display()),
    })?;
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Value(raw),
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(Vec::new())
}

/// Drops tracking rows whose directory no longer exists.
fn prune(ctx: &mut Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    let tail: &[String] = opts.positionals.get(1..).unwrap_or(&[]);
    if !tail.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: worktree prune [--dry-run]".to_owned(),
        });
    }
    let dry = opts.is_set("dry-run");
    let store = ctx.store()?;
    let mut out = Vec::new();
    for (record, raw) in scan_records(store)? {
        if Path::new(&record.path).exists() {
            continue;
        }
        out.extend_from_slice(
            format!("Removing {}: directory no longer exists\n", record.path).as_bytes(),
        );
        if dry {
            continue;
        }
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Pins,
                    key: record_key(&record.path),
                    expected: FactExpectation::Value(raw),
                    value: None,
                }],
            )
            .map_err(GitError::from)?;
    }
    Ok(out)
}

/// Names the holder already checking out `branch`, if any.
fn holder_of(store: &Store, main_root: &Path, branch: &str) -> Result<Option<String>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    if let HeadRef::Symbolic(name) = &workspace.head
        && name.to_string() == branch
    {
        return Ok(Some(display_path(main_root)?));
    }
    for (record, _) in scan_records(store)? {
        if record.branch.as_deref() == Some(branch) {
            return Ok(Some(record.path));
        }
    }
    Ok(None)
}

/// Canonicalizes a CLI path against `cwd` without touching the filesystem.
fn canonical_path(cwd: &Path, input: &str) -> Result<PathBuf, GitError> {
    if input.is_empty() {
        return Err(GitError::Invalid {
            detail: "worktree path is empty".to_owned(),
        });
    }
    let joined = if Path::new(input).is_absolute() {
        PathBuf::from(input)
    } else {
        cwd.join(input)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    Ok(out)
}

/// Reports whether `dir` exists and holds any entry.
fn dir_non_empty(dir: &Path) -> Result<bool, GitError> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(GitError::Io {
            detail: format!("listing {}: {err}", dir.display()),
        }),
    }
}

/// Writes one commit's tree into `base`, refusing divergent files.
fn materialize_tree(store: &Store, kind: HashKind, tree: Oid, base: &Path) -> Result<(), GitError> {
    materialize_impl(store, kind, tree, base, Overwrite::Refuse)
}

/// Writes one commit's tree into `base`, overwriting divergent files.
fn materialize_tree_overwrite(
    store: &Store,
    kind: HashKind,
    tree: Oid,
    base: &Path,
) -> Result<(), GitError> {
    materialize_impl(store, kind, tree, base, Overwrite::Allow)
}

/// Writes one commit's tree into `base` under one overwrite policy.
fn materialize_impl(
    store: &Store,
    kind: HashKind,
    tree: Oid,
    base: &Path,
    overwrite: Overwrite,
) -> Result<(), GitError> {
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        if mode == TreeMode::Gitlink {
            continue;
        }
        let full = join_base(base, &path)?;
        let (_, body) = read_object_bytes(store, oid)?;
        if mode == TreeMode::Symlink {
            write_worktree_link(&full, &body, &path, overwrite)?;
        } else {
            write_worktree_file(&full, &body, mode == TreeMode::Executable, &path, overwrite)?;
        }
    }
    Ok(())
}

/// Writes one regular file under one overwrite policy.
fn write_worktree_file(
    full: &Path,
    body: &[u8],
    executable: bool,
    path: &[u8],
    overwrite: Overwrite,
) -> Result<(), GitError> {
    if let Some(current) = read_existing(full)? {
        if current == body {
            return Ok(());
        }
        if overwrite == Overwrite::Refuse {
            return Err(GitError::Invalid {
                detail: format!(
                    "would overwrite '{}'; use --force",
                    String::from_utf8_lossy(path)
                ),
            });
        }
        std::fs::remove_file(full).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", full.display()),
        })?;
    }
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    std::fs::write(full, body).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", full.display()),
    })?;
    set_executable(full, executable)
}

/// Writes one symlink under one overwrite policy.
#[cfg(unix)]
fn write_worktree_link(
    full: &Path,
    body: &[u8],
    path: &[u8],
    overwrite: Overwrite,
) -> Result<(), GitError> {
    if let Some(current) = read_existing(full)? {
        if current == body {
            return Ok(());
        }
        if overwrite == Overwrite::Refuse {
            return Err(GitError::Invalid {
                detail: format!(
                    "would overwrite '{}'; use --force",
                    String::from_utf8_lossy(path)
                ),
            });
        }
        std::fs::remove_file(full).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", full.display()),
        })?;
    }
    let text = std::str::from_utf8(body).map_err(|_| GitError::Invalid {
        detail: "symlink target is not valid UTF-8".to_owned(),
    })?;
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    std::os::unix::fs::symlink(text, full).map_err(|err| GitError::Io {
        detail: format!("linking {}: {err}", full.display()),
    })
}

/// Refuses symlink checkouts where the platform cannot make them.
#[cfg(not(unix))]
fn write_worktree_link(
    _full: &Path,
    _body: &[u8],
    _path: &[u8],
    _overwrite: Overwrite,
) -> Result<(), GitError> {
    Err(GitError::Unsupported {
        command: "checkout of symlinks on this platform".to_owned(),
    })
}

/// Marks one checked-out file executable when the tree says so.
#[cfg(unix)]
fn set_executable(full: &Path, executable: bool) -> Result<(), GitError> {
    if !executable {
        return Ok(());
    }
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(full, std::fs::Permissions::from_mode(0o755)).map_err(|err| {
        GitError::Io {
            detail: format!("chmod {}: {err}", full.display()),
        }
    })
}

/// File modes need no fixup where the platform has no executable bit.
#[cfg(not(unix))]
fn set_executable(_full: &Path, _executable: bool) -> Result<(), GitError> {
    Ok(())
}

/// Reads existing bytes at `full`: link targets for links, content for files.
fn read_existing(full: &Path) -> Result<Option<Vec<u8>>, GitError> {
    let meta = match std::fs::symlink_metadata(full) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(GitError::Io {
                detail: format!("statting {}: {err}", full.display()),
            });
        }
    };
    if meta.is_symlink() {
        let target = std::fs::read_link(full).map_err(|err| GitError::Io {
            detail: format!("reading {}: {err}", full.display()),
        })?;
        return Ok(Some(target.as_os_str().as_encoded_bytes().to_vec()));
    }
    if meta.is_file() {
        let bytes = std::fs::read(full).map_err(|err| GitError::Io {
            detail: format!("reading {}: {err}", full.display()),
        })?;
        return Ok(Some(bytes));
    }
    Err(GitError::Invalid {
        detail: format!("cannot overwrite directory {}", full.display()),
    })
}

/// Reports whether a secondary checkout differs from its recorded commit.
fn worktree_dirty(
    store: &Store,
    kind: HashKind,
    record: &WorktreeRecord,
    base: &Path,
) -> Result<bool, GitError> {
    let commit = Oid::from_hex(&record.commit).map_err(|err| GitError::Corrupt {
        detail: format!("worktree commit does not parse: {err}"),
    })?;
    let commit_record = commit_record(store, commit)?;
    let tree = commit_tree_oid(&commit_record)?;
    let mut wanted: BTreeMap<Vec<u8>, (TreeMode, Oid)> = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        if mode == TreeMode::Gitlink {
            continue;
        }
        wanted.insert(path, (mode, oid));
    }
    let walked = walk_worktree(base)?;
    for entry in &walked {
        let Some((mode, oid)) = wanted.get(&entry.path) else {
            return Ok(true);
        };
        let link_wanted = *mode == TreeMode::Symlink;
        let link_found = entry.file_type == WorktreeType::Symlink;
        if link_wanted != link_found {
            return Ok(true);
        }
        let (_, body) = read_object_bytes(store, *oid)?;
        let full = join_base(base, &entry.path)?;
        let current = if link_found {
            std::fs::read_link(&full)
                .map_err(|err| GitError::Io {
                    detail: format!("reading {}: {err}", full.display()),
                })?
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            std::fs::read(&full).map_err(|err| GitError::Io {
                detail: format!("reading {}: {err}", full.display()),
            })?
        };
        if current != body {
            return Ok(true);
        }
    }
    for path in wanted.keys() {
        if !walked.iter().any(|entry| &entry.path == path) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Writes the `rukdir:` pointer linking a secondary back to its store.
fn write_link_file(target: &Path, ruk_dir: &Path) -> Result<(), GitError> {
    let marker = target.join(".ruk");
    std::fs::write(&marker, format!("rukdir: {}\n", ruk_dir.display())).map_err(|err| {
        GitError::Io {
            detail: format!("writing {}: {err}", marker.display()),
        }
    })
}

/// Tracking-row key for one canonical path.
fn record_key(path: &str) -> Vec<u8> {
    let mut key = WORKTREE_PREFIX.to_vec();
    key.extend_from_slice(path.as_bytes());
    key
}

/// Renders a path as UTF-8 for keys and records.
fn display_path(path: &Path) -> Result<String, GitError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| GitError::Invalid {
            detail: "worktree path is not valid UTF-8".to_owned(),
        })
}

/// Shortens `refs/heads/<name>` to `<name>` for display.
fn short_branch(name: &str) -> &str {
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// Short hex for one-line summaries.
fn short_oid(oid: &Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

/// Scans every tracked secondary in key order.
fn scan_records(store: &Store) -> Result<Vec<(WorktreeRecord, Vec<u8>)>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = Some(WORKTREE_PREFIX.to_vec());
    loop {
        let page = store.fact_page(
            FactTable::Pins,
            after.as_deref(),
            FactPageBudget::new(1024, 1 << 20),
        )?;
        if page.rows.is_empty() {
            return Ok(out);
        }
        for row in &page.rows {
            if !row.key.starts_with(WORKTREE_PREFIX) {
                return Ok(out);
            }
            let record: WorktreeRecord =
                sonic_rs::from_slice(&row.value).map_err(|err| GitError::Corrupt {
                    detail: format!("worktree record does not decode: {err}"),
                })?;
            out.push((record, row.value.clone()));
        }
        if !page.more {
            return Ok(out);
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
}
