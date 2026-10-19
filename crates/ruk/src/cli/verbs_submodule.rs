//! Submodules: `submodule add/status/init/deinit/update/summary/foreach`.
//!
//! | subcommand | backing | status |
//! | --- | --- | --- |
//! | `add` | local clone into `<path>/.ruk` + gitlink row + `.rukmodules` row | implemented (local paths only; `--name`, `--branch/-b`, `--force`, `--depth`) |
//! | `status` | index gitlink vs child `HEAD`, `--cached` index-vs-`HEAD` | implemented (`--recursive`, `--cached`) |
//! | `init` | copies `.rukmodules` urls into `submodule.<name>.url` config | implemented |
//! | `deinit` | drops the child directory, keeps the gitlink + `.rukmodules` | implemented (refuses dirty trees without `--force`) |
//! | `update` | `--init` clones, then checks the child out at the gitlink oid | implemented (`--init`/`--recursive`/`--remote`/`--depth`; `--merge`/`--rebase` are `Unsupported`) |
//! | `summary` | index gitlink vs `HEAD` gitlink per submodule | implemented (commit subjects omitted) |
//! | `foreach` | runs `sh -c` in each initialized child | implemented (`--recursive`) |
//! | `absorbgitdirs` | nothing to absorb: children keep `.ruk/` in place | `Unsupported` named gap |
//!
//! A submodule is a nested repository whose worktree lives at
//! `<root>/<path>` with its store at `<root>/<path>/.ruk` (a `gitdir:`
//! pointer file is followed when present, so an absorbed-style layout
//! keeps working). The superproject records the binding two ways, exactly
//! like the oracle: a gitlink index row (`160000`, an [`IndexEntry`] with
//! [`FileMode::Gitlink`] holding the child commit id, written through the
//! same `path_row_mutations` path as `update-index --cacheinfo`) and a
//! `.rukmodules` file (worktree bytes plus a stage-zero blob row) with one
//! `[submodule "<name>"]` section per entry (`path`, `url`, optional
//! `branch`). `update` checks the child out detached at the recorded oid
//! the way the oracle does; nested recursion follows `--recursive`.
//!
//! Module data is read from the worktree `.rukmodules` first, then the
//! index blob, then the `HEAD` tree, so freshly added (uncommitted) entries
//! work without a commit round-trip.
//!
//! Oracle anchor: `git/builtin/submodule--helper.c`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{PreparationBudget, Store};
use ruk_core::workspace::{GitCompatWorkspace, HeadRef, Scope};
use ruk_git::GitError;
use ruk_git::transport::session::{LocalFetchRequest, advertise, local_fetch};

use super::state::{
    DEFAULT_BRANCH, apply_refs, commit_record, config_unset, config_write, head_oid,
    load_or_default, load_workspace, path_row_mutations, read_path_rows, remote_root, scan_index,
    unmerged_paths, workspace_mutation,
};
use super::tree::{TreeMode, commit_tree_oid, flatten_tree, join_base, read_object_bytes};
use super::{Collected, Ctx, FlagSpec, collect};

/// One `.rukmodules` entry: the superproject-side binding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SubmoduleEntry {
    /// Section name (`[submodule "<name>"]`).
    name: String,
    /// Worktree-relative path of the child.
    path: String,
    /// Clone/fetch source recorded at `add` time.
    url: String,
    /// Upstream branch for `update --remote`, when recorded.
    branch: Option<String>,
}

/// Flags shared across the update walk (top level and `--recursive`).
#[derive(Clone, Debug, Default)]
struct UpdateFlags {
    init: bool,
    recursive: bool,
    remote: bool,
    depth: Option<u32>,
}

/// Manages nested repositories bound by gitlink rows.
///
/// Oracle: `git/builtin/submodule--helper.c`.
pub(crate) fn submodule(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "cached",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "recursive",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "init",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "remote",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "checkout",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "merge",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "rebase",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "branch",
            short: Some('b'),
            takes_value: true,
        },
        FlagSpec {
            long: "name",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "depth",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let (cmd, rest) = opts
        .positionals
        .split_first()
        .ok_or_else(|| GitError::Invalid {
            detail:
                "usage: submodule <add|status|init|deinit|update|summary|foreach|absorbgitdirs>"
                    .to_owned(),
        })?;
    match cmd.as_str() {
        "add" => cmd_add(ctx, &opts, rest),
        "status" => cmd_status(ctx, &opts, rest),
        "init" => cmd_init(ctx, rest),
        "deinit" => cmd_deinit(ctx, &opts, rest),
        "update" => cmd_update(ctx, &opts, rest),
        "summary" => cmd_summary(ctx, &opts, rest),
        "foreach" => cmd_foreach(ctx, &opts, rest),
        "absorbgitdirs" => Err(GitError::Unsupported {
            command: "submodule absorbgitdirs: child stores live at <path>/.ruk and need no gitdir absorption"
                .to_owned(),
        }),
        other => Err(GitError::Invalid {
            detail: format!("unknown submodule subcommand {other:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// `.rukmodules` codec
// ---------------------------------------------------------------------------

/// Parses `.rukmodules` bytes into entries in file order.
///
/// Only `path`, `url`, and `branch` keys are kept; anything else (update
/// strategies, fetch-recursion flags) is ignored so hand-written files keep
/// working. Sections without both a path and a url are skipped.
fn parse_gitmodules(bytes: &[u8]) -> Vec<SubmoduleEntry> {
    let text = String::from_utf8_lossy(bytes);
    let mut entries = Vec::new();
    let mut current: Option<SubmoduleEntry> = None;
    for raw in text.lines() {
        let stripped = raw.trim();
        if let Some(name) = stripped
            .strip_prefix("[submodule \"")
            .and_then(|tail| tail.strip_suffix("\"]"))
        {
            if let Some(entry) = current.take() {
                push_complete(&mut entries, entry);
            }
            current = Some(SubmoduleEntry {
                name: name.to_owned(),
                path: String::new(),
                url: String::new(),
                branch: None,
            });
        } else if let Some((key, value)) = stripped.split_once('=') {
            let Some(entry) = current.as_mut() else {
                continue;
            };
            let value = unquote(value.trim());
            match key.trim() {
                "path" => entry.path = value,
                "url" => entry.url = value,
                "branch" if !value.is_empty() => {
                    entry.branch = Some(value);
                }
                _ => {}
            }
        }
    }
    if let Some(entry) = current {
        push_complete(&mut entries, entry);
    }
    entries
}

/// Keeps entries that name both a path and a url.
fn push_complete(out: &mut Vec<SubmoduleEntry>, entry: SubmoduleEntry) {
    if !entry.path.is_empty() && !entry.url.is_empty() {
        out.push(entry);
    }
}

/// Strips one layer of matching single or double quotes.
fn unquote(value: &str) -> String {
    if value.len() >= 2 {
        if let Some(inner) = value
            .strip_prefix('"')
            .and_then(|tail| tail.strip_suffix('"'))
        {
            return inner.to_owned();
        }
        if let Some(inner) = value
            .strip_prefix('\'')
            .and_then(|tail| tail.strip_suffix('\''))
        {
            return inner.to_owned();
        }
    }
    value.to_owned()
}

/// Renders entries in the canonical section form.
fn render_gitmodules(entries: &[SubmoduleEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(format!("[submodule \"{}\"]\n", entry.name).as_bytes());
        out.extend_from_slice(format!("\tpath = {}\n", entry.path).as_bytes());
        out.extend_from_slice(format!("\turl = {}\n", entry.url).as_bytes());
        if let Some(branch) = &entry.branch {
            out.extend_from_slice(format!("\tbranch = {branch}\n").as_bytes());
        }
    }
    out
}

/// Loads the module bindings: worktree file first, then the index blob,
/// then the `HEAD` tree, so uncommitted `add` output works immediately.
fn load_modules(ctx: &Ctx, store: &Store, kind: HashKind) -> Result<Vec<SubmoduleEntry>, GitError> {
    let file = ctx.file_base.join(".rukmodules");
    if let Ok(bytes) = std::fs::read(&file) {
        return Ok(parse_gitmodules(&bytes));
    }
    let path = RepoPath::new(b".rukmodules".to_vec()).map_err(to_core)?;
    for (stage, entry, _) in read_path_rows(store, kind, &path)? {
        if stage == Stage::Zero {
            let (_, body) = read_object_bytes(store, entry.oid())?;
            return Ok(parse_gitmodules(&body));
        }
    }
    if let Ok(tree) = head_tree_map(store, kind)
        && let Some((_, oid)) = tree.get(b".rukmodules".as_slice())
    {
        let (_, body) = read_object_bytes(store, *oid)?;
        return Ok(parse_gitmodules(&body));
    }
    Ok(Vec::new())
}

/// Maps one CLI path argument to a validated repository path.
fn cli_path(ctx: &Ctx, raw: &str) -> Result<RepoPath, GitError> {
    super::verbs_stage::repo_path_of(ctx, raw.as_bytes())
}

/// Reads the gitlink oid staged at `path`, if the row is a gitlink.
fn index_gitlink(store: &Store, kind: HashKind, path: &RepoPath) -> Result<Option<Oid>, GitError> {
    for (stage, entry, _) in read_path_rows(store, kind, path)? {
        if stage == Stage::Zero {
            return Ok(if entry.mode() == FileMode::Gitlink {
                Some(entry.oid())
            } else {
                None
            });
        }
    }
    Ok(None)
}

/// Flattens the `HEAD` tree into a path map; unborn `HEAD` maps to empty.
fn head_tree_map(
    store: &Store,
    kind: HashKind,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, GitError> {
    let head = match head_oid(store) {
        Ok(oid) => oid,
        Err(GitError::NotFound { .. }) => return Ok(BTreeMap::new()),
        Err(err) => return Err(err),
    };
    let record = commit_record(store, head)?;
    let tree = commit_tree_oid(&record)?;
    let mut map = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        map.insert(path, (mode, oid));
    }
    Ok(map)
}

/// Maps a model failure into the interpreter error space.
fn to_core(err: ruk_core::error::CoreModelError) -> GitError {
    GitError::from(ruk_core::error::CoreError::from(err))
}

// ---------------------------------------------------------------------------
// child stores
// ---------------------------------------------------------------------------

/// Opens the child store at `child_root`, following a `gitdir:` pointer
/// file when `.ruk` is a file rather than a directory. `None` means the
/// submodule was never initialized here.
fn open_child_store(child_root: &Path) -> Result<Option<Store>, GitError> {
    let dot = child_root.join(".ruk");
    if dot.is_dir() {
        return Ok(Some(open_store(&dot)?));
    }
    if dot.is_file() {
        let text = std::fs::read_to_string(&dot).map_err(|err| GitError::Io {
            detail: format!("reading {}: {err}", dot.display()),
        })?;
        let Some(target) = text.strip_prefix("gitdir:").map(str::trim) else {
            return Err(GitError::Invalid {
                detail: format!("{} is not a gitdir pointer", dot.display()),
            });
        };
        let resolved = if Path::new(target).is_absolute() {
            PathBuf::from(target)
        } else {
            dot.parent().unwrap_or(child_root).join(target)
        };
        return Ok(Some(open_store(&resolved)?));
    }
    Ok(None)
}

/// Opens a store directory with the reference budget.
fn open_store(dir: &Path) -> Result<Store, GitError> {
    Store::open(
        dir,
        std::sync::Arc::new(PreparationBudget::reference_defaults()),
    )
    .map_err(GitError::from)
}

/// Short branch name for display (`refs/heads/main` renders as `main`).
fn short_branch(name: &str) -> &str {
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// Short object prefix for display.
fn short_oid(oid: &Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

// ---------------------------------------------------------------------------
// `add`
// ---------------------------------------------------------------------------

/// Clones a local repository as a submodule and records the binding.
///
/// The child is a full local clone (objects, branch refs, remote-tracking
/// refs, `HEAD`, `remote.origin.url`) checked out on the source branch;
/// the superproject stages the gitlink row plus the `.rukmodules` row in
/// one transaction. Network urls are `Offline`, like `clone`.
fn cmd_add(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let url = rest.first().ok_or_else(|| GitError::Invalid {
        detail: "usage: submodule add [--name <name>] [-b <branch>] [--force] <url> [<path>]"
            .to_owned(),
    })?;
    if rest.len() > 2 {
        return Err(GitError::Invalid {
            detail: "usage: submodule add [--name <name>] [-b <branch>] [--force] <url> [<path>]"
                .to_owned(),
        });
    }
    let depth = match opts.single("depth")? {
        None => None,
        Some(value) => Some(value.parse::<u32>().map_err(|_| GitError::Invalid {
            detail: format!("bad depth {value:?}"),
        })?),
    };
    let src_root = remote_root(ctx, url)?;
    let src_store = open_store(&src_root.join(".ruk"))?;
    let kind = ctx.kind()?;
    if src_store.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "submodule object format disagrees with the superproject".to_owned(),
        });
    }
    let default_path = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("submodule")
        .trim_end_matches(".git");
    let path_text = rest.get(1).map_or(default_path, String::as_str);
    if path_text.is_empty() || path_text == ".rukmodules" {
        return Err(GitError::Invalid {
            detail: format!("bad submodule path {path_text:?}"),
        });
    }
    let repo_path = cli_path(ctx, path_text)?;
    let name = opts.single("name")?.unwrap_or_else(|| path_text.to_owned());
    if name.is_empty() || name.contains('"') || name.contains('\n') {
        return Err(GitError::Invalid {
            detail: format!("bad submodule name {name:?}"),
        });
    }
    let store = ctx.store()?;
    let mut entries = load_modules(ctx, store, kind)?;
    if !opts.is_set("force")
        && entries
            .iter()
            .any(|entry| entry.path == path_text || entry.name == name)
    {
        return Err(GitError::Invalid {
            detail: format!("{path_text:?} is already a submodule; use --force to replace it"),
        });
    }
    let child_root = ctx.root.join(path_text);
    if !opts.is_set("force") {
        if child_root.join(".ruk").exists() {
            return Err(GitError::Invalid {
                detail: format!(
                    "{} already holds a repository; use --force to replace it",
                    child_root.display()
                ),
            });
        }
        if child_root.is_dir() && dir_non_empty(&child_root)? {
            return Err(GitError::Invalid {
                detail: format!(
                    "{} is not empty; use --force to add into it",
                    child_root.display()
                ),
            });
        }
    }
    if let Some(want) = opts.single("branch")? {
        let probe = format!("refs/heads/{want}");
        RefName::new(probe.as_str()).map_err(|err| GitError::Invalid {
            detail: format!("branch refused: {err}"),
        })?;
    }
    std::fs::create_dir_all(&child_root).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", child_root.display()),
    })?;
    if opts.is_set("force") && child_root.join(".ruk").is_dir() {
        std::fs::remove_dir_all(child_root.join(".ruk")).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", child_root.join(".ruk").display()),
        })?;
    }
    let head_oid = clone_local_into(&src_store, &child_root, kind, url, depth)?;
    let child_store = open_child_store(&child_root)?.ok_or_else(|| GitError::Corrupt {
        detail: format!("submodule {path_text:?} has no store after clone"),
    })?;
    checkout_child_attached(&child_store, &child_root, kind, head_oid)?;
    entries.retain(|entry| entry.path != path_text && entry.name != name);
    entries.push(SubmoduleEntry {
        name: name.clone(),
        path: path_text.to_owned(),
        url: url.clone(),
        branch: opts.single("branch")?,
    });
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    let gitlink = IndexEntry::new(head_oid, FileMode::Gitlink, None, IndexFlags::default())
        .map_err(to_core)?;
    let before_link = read_path_rows(store, kind, &repo_path)?;
    mutations.extend(path_row_mutations(
        &repo_path,
        &before_link,
        &[(Stage::Zero, gitlink)],
    )?);
    let body = render_gitmodules(&entries);
    std::fs::write(ctx.file_base.join(".rukmodules"), &body).map_err(|err| GitError::Io {
        detail: format!("writing .rukmodules: {err}"),
    })?;
    let modules_path = RepoPath::new(b".rukmodules".to_vec()).map_err(to_core)?;
    let blob = IndexEntry::for_blob(kind, FileMode::Regular, &body, None).map_err(to_core)?;
    let blob_len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "rukmodules body exceeds the length range".to_owned(),
    })?;
    let prepared = store
        .prepare(
            ruk_core::store::types::ObjectKind::Blob,
            blob_len,
            std::io::Cursor::new(body),
            None,
        )
        .map_err(GitError::from)?;
    objects.push(prepared);
    let before_modules = read_path_rows(store, kind, &modules_path)?;
    mutations.extend(path_row_mutations(
        &modules_path,
        &before_modules,
        &[(Stage::Zero, blob)],
    )?);
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store.publish(objects, &mutations).map_err(GitError::from)?;
    ctx.emit_stderr(format!("Cloning into {path_text:?}...\n").as_bytes());
    Ok(Vec::new())
}

/// Clones every advertised ref from `src` into a fresh store at
/// `dst_root/.ruk`, attaches `HEAD` to the source branch, and returns the
/// checked-out commit. Mirrors the local lane of `clone`.
fn clone_local_into(
    src: &Store,
    dst_root: &Path,
    kind: HashKind,
    url: &str,
    depth: Option<u32>,
) -> Result<Oid, GitError> {
    let budget = std::sync::Arc::new(PreparationBudget::reference_defaults());
    let dst = Store::create(&dst_root.join(".ruk"), kind, budget).map_err(GitError::from)?;
    let advertised = advertise(src)?;
    if advertised.is_empty() {
        return Err(GitError::NotFound {
            detail: "source repository has no refs to clone".to_owned(),
        });
    }
    let wants: Vec<Oid> = advertised
        .iter()
        .filter_map(|entry| match &entry.target {
            RefTarget::Direct(oid) => Some(*oid),
            RefTarget::Symbolic(name) => advertised
                .iter()
                .find(|other| other.name == name.as_bytes())
                .and_then(|other| match &other.target {
                    RefTarget::Direct(oid) => Some(*oid),
                    RefTarget::Symbolic(_) => None,
                }),
        })
        .collect();
    let request = LocalFetchRequest {
        wants,
        haves: Vec::new(),
        filter: None,
        depth,
    };
    local_fetch(
        &dst,
        src,
        b"origin",
        &request,
        &[],
        &[],
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    let mut updates = Vec::new();
    for entry in &advertised {
        if entry.name.starts_with(b"refs/heads/") {
            let name = RefName::new(entry.name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("source ref refused: {err}"),
            })?;
            updates.push(RefUpdate {
                name,
                expected: RefExpect::Absent,
                change: RefChange::Set(entry.target.clone()),
            });
            let short = String::from_utf8_lossy(&entry.name)
                .strip_prefix("refs/heads/")
                .unwrap_or("")
                .to_owned();
            let remote_name =
                RefName::new(format!("refs/remotes/origin/{short}")).map_err(|err| {
                    GitError::Invalid {
                        detail: format!("remote-tracking ref refused: {err}"),
                    }
                })?;
            updates.push(RefUpdate {
                name: remote_name,
                expected: RefExpect::Absent,
                change: RefChange::Set(entry.target.clone()),
            });
        } else if entry.name.starts_with(b"refs/tags/") {
            let name = RefName::new(entry.name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("source ref refused: {err}"),
            })?;
            updates.push(RefUpdate {
                name,
                expected: RefExpect::Absent,
                change: RefChange::Set(entry.target.clone()),
            });
        }
    }
    apply_refs(&dst, kind, updates)?;
    let head_branch = match load_workspace(src)? {
        Some((workspace, _)) => match &workspace.head {
            HeadRef::Symbolic(name) => name.to_string(),
            HeadRef::Detached(_) => DEFAULT_BRANCH.to_owned(),
        },
        None => DEFAULT_BRANCH.to_owned(),
    };
    let head_name = RefName::new(head_branch.as_str()).map_err(|err| GitError::Invalid {
        detail: format!("branch refused: {err}"),
    })?;
    let workspace = GitCompatWorkspace::new(HeadRef::Symbolic(head_name), Scope::Full);
    let mutation = workspace_mutation(None, &workspace)?;
    dst.publish(Vec::new(), &[mutation])
        .map_err(GitError::from)?;
    config_write(&dst, "remote.origin.url", url)?;
    config_write(
        &dst,
        "remote.origin.fetch",
        "+refs/heads/*:refs/remotes/origin/*",
    )?;
    head_oid(&dst)
}

/// Checks a child worktree out at `oid`: files, index rows, and `HEAD`.
///
/// Takes the already-open child `Store`: reopening the same `.ruk` while
/// the caller holds it would self-conflict on the redb OFD lock
/// (`DatabaseAlreadyOpen`), so the handle is threaded through.
fn checkout_child_inner(
    child: &Store,
    child_root: &Path,
    kind: HashKind,
    oid: Oid,
    detach: bool,
) -> Result<(), GitError> {
    let record = commit_record(child, oid)?;
    let tree = commit_tree_oid(&record)?;
    let flat = flatten_tree(child, kind, tree)?;
    materialize_flat(child, kind, &flat, child_root)?;
    write_flat_index(child, kind, &flat)?;
    if detach {
        let (mut workspace, raw) = load_or_default(child)?;
        workspace.head = HeadRef::Detached(oid);
        let next = workspace.mutate_index(workspace.stamp)?;
        child
            .publish(Vec::new(), &[workspace_mutation(raw.as_deref(), &next)?])
            .map_err(GitError::from)?;
    }
    Ok(())
}

/// Checks a fresh clone out on its branch, keeping the attached `HEAD`.
fn checkout_child_attached(
    child: &Store,
    child_root: &Path,
    kind: HashKind,
    oid: Oid,
) -> Result<(), GitError> {
    checkout_child_inner(child, child_root, kind, oid, false)
}

/// Checks a submodule out detached at its recorded oid: the `update` posture.
fn checkout_child_detached(
    child: &Store,
    child_root: &Path,
    kind: HashKind,
    oid: Oid,
) -> Result<(), GitError> {
    checkout_child_inner(child, child_root, kind, oid, true)
}

/// Creates one child symlink from its recorded target blob, mirroring the
/// checkout lane: targets are UTF-8 text, never raw bytes.
#[cfg(unix)]
fn create_child_link(child: &Store, oid: Oid, full: &Path) -> Result<(), GitError> {
    let (_, body) = read_object_bytes(child, oid)?;
    let text = std::str::from_utf8(&body).map_err(|_| GitError::Invalid {
        detail: "symlink target is not valid UTF-8".to_owned(),
    })?;
    if full.is_symlink() || full.is_file() {
        std::fs::remove_file(full).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", full.display()),
        })?;
    }
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    std::os::unix::fs::symlink(text, full).map_err(|err| GitError::Io {
        detail: format!("linking {}: {err}", full.display()),
    })
}

/// Refuses child links where the platform cannot make them.
#[cfg(not(unix))]
fn create_child_link(_child: &Store, _oid: Oid, _full: &Path) -> Result<(), GitError> {
    Err(GitError::Unsupported {
        command: "submodule checkout of symlinks needs a Unix worktree".to_owned(),
    })
}

/// Writes every flattened tree entry under `base`, removing files the old
/// child index named but the new tree drops. Gitlink entries materialize
/// as empty directories (nested checkouts arrive via `--recursive`).
fn materialize_flat(
    child: &Store,
    kind: HashKind,
    flat: &[(Vec<u8>, TreeMode, Oid)],
    base: &Path,
) -> Result<(), GitError> {
    let mut wanted: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    for (path, mode, oid) in flat {
        wanted.insert(path.clone(), true);
        let full = join_base(base, path)?;
        if *mode == TreeMode::Gitlink {
            std::fs::create_dir_all(&full).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", full.display()),
            })?;
            continue;
        }
        if *mode == TreeMode::Symlink {
            create_child_link(child, *oid, &full)?;
            continue;
        }
        let (_, body) = read_object_bytes(child, *oid)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&full, body).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
        #[cfg(unix)]
        if *mode == TreeMode::Executable {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o755)).map_err(
                |err| GitError::Io {
                    detail: format!("chmod {}: {err}", full.display()),
                },
            )?;
        }
    }
    for (path, _, _) in scan_index(child, kind)? {
        let key = path.as_bytes().to_vec();
        if wanted.contains_key(&key) {
            continue;
        }
        let Ok(full) = join_base(base, &key) else {
            continue;
        };
        if full.is_symlink() || full.is_file() {
            std::fs::remove_file(&full).map_err(|err| GitError::Io {
                detail: format!("removing {}: {err}", full.display()),
            })?;
        }
    }
    Ok(())
}

/// Replaces the child stage-zero rows with the flattened tree: new rows
/// for tree members, deletions for dropped paths, one generation bump.
fn write_flat_index(
    child: &Store,
    kind: HashKind,
    flat: &[(Vec<u8>, TreeMode, Oid)],
) -> Result<(), GitError> {
    let (workspace, raw) = load_or_default(child)?;
    let mut mutations = Vec::new();
    let mut seen: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    for (path, mode, oid) in flat {
        let repo_path = RepoPath::new(path.clone()).map_err(to_core)?;
        let file_mode = mode.as_index_mode()?;
        let entry =
            IndexEntry::new(*oid, file_mode, None, IndexFlags::default()).map_err(to_core)?;
        let before = read_path_rows(child, kind, &repo_path)?;
        mutations.extend(path_row_mutations(
            &repo_path,
            &before,
            &[(Stage::Zero, entry)],
        )?);
        seen.insert(path.clone(), true);
    }
    for (path, _, _) in scan_index(child, kind)? {
        if seen.contains_key(path.as_bytes()) {
            continue;
        }
        let before = read_path_rows(child, kind, &path)?;
        mutations.extend(path_row_mutations(&path, &before, &[])?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    child
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Reports whether `dir` holds any entry.
fn dir_non_empty(dir: &Path) -> Result<bool, GitError> {
    let mut entries = std::fs::read_dir(dir).map_err(|err| GitError::Io {
        detail: format!("reading {}: {err}", dir.display()),
    })?;
    Ok(entries.next().is_some())
}

// ---------------------------------------------------------------------------
// `status`
// ---------------------------------------------------------------------------

/// Lists one line per submodule: `<flag><oid> <path> (<branch>)`.
///
/// The flag mirrors the oracle: ` ` in sync, `+` checked out elsewhere,
/// `-` uninitialized, `U` merged-conflicted. `--cached` compares the index
/// gitlink against `HEAD` instead of the child checkout.
fn cmd_status(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = select_entries(&load_modules(ctx, store, kind)?, rest)?;
    let mut out = Vec::new();
    let view = RepoView {
        root: &ctx.root,
        store,
        kind,
    };
    status_into(view, &entries, opts, "", &mut out)?;
    Ok(out)
}

/// One worktree-plus-store pair a submodule walk operates on.
///
/// Top-level walks borrow the interpreter roots; recursive walks borrow one
/// initialized child. Grouping the trio keeps every walk signature short.
#[derive(Clone, Copy)]
struct RepoView<'a> {
    /// Worktree root files are read and written under.
    root: &'a Path,
    /// Open store backing the worktree.
    store: &'a Store,
    /// Object format of the store.
    kind: HashKind,
}

/// Appends status lines for `entries`, prefixing nested paths with `prefix`.
fn status_into(
    view: RepoView<'_>,
    entries: &[SubmoduleEntry],
    opts: &Collected,
    prefix: &str,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    let head_tree = head_tree_map(view.store, view.kind)?;
    let rows = scan_index(view.store, view.kind)?;
    let unmerged = unmerged_paths(&rows);
    let mut index_map: BTreeMap<Vec<u8>, Oid> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero && entry.mode() == FileMode::Gitlink {
            index_map.insert(path.as_bytes().to_vec(), entry.oid());
        }
    }
    for entry in entries {
        let display = format!("{prefix}{}", entry.path);
        let index_oid = index_map.get(entry.path.as_bytes());
        let head_oid_opt = match head_tree.get(entry.path.as_bytes()) {
            Some((TreeMode::Gitlink, oid)) => Some(*oid),
            _ => None,
        };
        if unmerged.contains_key(entry.path.as_bytes()) {
            let oid = index_oid
                .copied()
                .or(head_oid_opt)
                .ok_or_else(|| GitError::NotFound {
                    detail: format!("no gitlink recorded for {:?}", entry.path),
                })?;
            out.extend_from_slice(
                format!("U{} {display} (missing gitlink)\n", oid.to_hex()).as_bytes(),
            );
            continue;
        }
        let child_root = view.root.join(&entry.path);
        let child = open_child_store(&child_root)?;
        if opts.is_set("cached") {
            let (flag, oid) = match (index_oid, head_oid_opt) {
                (Some(index), Some(head)) if index != &head => ('+', *index),
                (Some(index), _) => (' ', *index),
                (None, Some(head)) => ('+', head),
                (None, None) => {
                    return Err(GitError::NotFound {
                        detail: format!("no gitlink recorded for {:?}", entry.path),
                    });
                }
            };
            let describe = describe_child(child.as_ref())?;
            out.extend_from_slice(
                format!("{flag}{} {display} ({describe})\n", oid.to_hex()).as_bytes(),
            );
        } else {
            match (child, index_oid) {
                (None, Some(index)) => {
                    out.extend_from_slice(
                        format!("-{} {display} (uninitialized)\n", index.to_hex()).as_bytes(),
                    );
                }
                (None, None) => {
                    if let Some(head) = head_oid_opt {
                        out.extend_from_slice(
                            format!("-{head} {display} (uninitialized)\n", head = head.to_hex())
                                .as_bytes(),
                        );
                    } else {
                        return Err(GitError::NotFound {
                            detail: format!("no gitlink recorded for {:?}", entry.path),
                        });
                    }
                }
                (Some(child_store), index_opt) => {
                    let child_head = head_oid(&child_store)?;
                    let flag = match index_opt {
                        Some(index) if index != &child_head => '+',
                        _ => ' ',
                    };
                    let shown = index_opt.unwrap_or(&child_head);
                    let describe = describe_child(Some(&child_store))?;
                    out.extend_from_slice(
                        format!("{flag}{} {display} ({describe})\n", shown.to_hex()).as_bytes(),
                    );
                    if opts.is_set("recursive") {
                        let nested = load_modules_at(&child_root, &child_store, view.kind)?;
                        if !nested.is_empty() {
                            let child_view = RepoView {
                                root: &child_root,
                                store: &child_store,
                                kind: view.kind,
                            };
                            status_into_nested(
                                child_view,
                                &nested,
                                opts,
                                &format!("{display}/"),
                                &mut *out,
                            )?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Recursive status inside an initialized child.
fn status_into_nested(
    view: RepoView<'_>,
    entries: &[SubmoduleEntry],
    opts: &Collected,
    prefix: &str,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    let head_tree = head_tree_map(view.store, view.kind)?;
    let rows = scan_index(view.store, view.kind)?;
    let mut index_map: BTreeMap<Vec<u8>, Oid> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero && entry.mode() == FileMode::Gitlink {
            index_map.insert(path.as_bytes().to_vec(), entry.oid());
        }
    }
    for entry in entries {
        let display = format!("{prefix}{}", entry.path);
        let index_oid = index_map.get(entry.path.as_bytes());
        let nested_root = view.root.join(&entry.path);
        match (open_child_store(&nested_root)?, index_oid) {
            (None, Some(index)) => {
                out.extend_from_slice(
                    format!("-{} {display} (uninitialized)\n", index.to_hex()).as_bytes(),
                );
            }
            (None, None) => {
                if let Some((_, head)) = head_tree.get(entry.path.as_bytes()) {
                    out.extend_from_slice(
                        format!("-{} {display} (uninitialized)\n", head.to_hex()).as_bytes(),
                    );
                }
            }
            (Some(nested_store), index_opt) => {
                let nested_head = head_oid(&nested_store)?;
                let flag = match index_opt {
                    Some(index) if index != &nested_head => '+',
                    _ => ' ',
                };
                let shown = index_opt.unwrap_or(&nested_head);
                let describe = match load_workspace(&nested_store)? {
                    Some((workspace, _)) => match &workspace.head {
                        HeadRef::Symbolic(name) => short_branch(&name.to_string()).to_owned(),
                        HeadRef::Detached(oid) => short_oid(oid),
                    },
                    None => short_oid(&nested_head),
                };
                out.extend_from_slice(
                    format!("{flag}{} {display} ({describe})\n", shown.to_hex()).as_bytes(),
                );
                if opts.is_set("recursive") {
                    let deeper = load_modules_at(&nested_root, &nested_store, view.kind)?;
                    if !deeper.is_empty() {
                        let deeper_view = RepoView {
                            root: &nested_root,
                            store: &nested_store,
                            kind: view.kind,
                        };
                        status_into_nested(
                            deeper_view,
                            &deeper,
                            opts,
                            &format!("{display}/"),
                            &mut *out,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Names the child branch (or short oid when detached) for status lines.
fn describe_child(child: Option<&Store>) -> Result<String, GitError> {
    match child {
        None => Ok("uninitialized".to_owned()),
        Some(child_store) => match load_workspace(child_store)? {
            Some((workspace, _)) => Ok(match &workspace.head {
                HeadRef::Symbolic(name) => short_branch(&name.to_string()).to_owned(),
                HeadRef::Detached(oid) => short_oid(oid),
            }),
            None => Ok("(no HEAD)".to_owned()),
        },
    }
}

/// Loads module bindings rooted at `root` (worktree file, else the store).
fn load_modules_at(
    root: &Path,
    store: &Store,
    kind: HashKind,
) -> Result<Vec<SubmoduleEntry>, GitError> {
    let file = root.join(".rukmodules");
    if let Ok(bytes) = std::fs::read(&file) {
        return Ok(parse_gitmodules(&bytes));
    }
    let path = RepoPath::new(b".rukmodules".to_vec()).map_err(to_core)?;
    for (stage, entry, _) in read_path_rows(store, kind, &path)? {
        if stage == Stage::Zero {
            let (_, body) = read_object_bytes(store, entry.oid())?;
            return Ok(parse_gitmodules(&body));
        }
    }
    Ok(Vec::new())
}

/// Narrows entries to the requested paths; unknown paths fail.
fn select_entries(
    entries: &[SubmoduleEntry],
    rest: &[String],
) -> Result<Vec<SubmoduleEntry>, GitError> {
    if rest.is_empty() {
        return Ok(entries.to_vec());
    }
    let mut out = Vec::new();
    for wanted in rest {
        let trimmed = wanted.trim_end_matches('/');
        match entries.iter().find(|entry| entry.path == trimmed) {
            Some(entry) => out.push(entry.clone()),
            None => {
                return Err(GitError::NotFound {
                    detail: format!("no submodule mapping found for {wanted:?}"),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `init`, `deinit`
// ---------------------------------------------------------------------------

/// Registers `.rukmodules` urls as `submodule.<name>.url` config records.
fn cmd_init(ctx: &mut Ctx, rest: &[String]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = select_entries(&load_modules(ctx, store, kind)?, rest)?;
    let mut out = Vec::new();
    for entry in &entries {
        config_write(store, &format!("submodule.{}.url", entry.name), &entry.url)?;
        if let Some(branch) = &entry.branch {
            config_write(store, &format!("submodule.{}.branch", entry.name), branch)?;
        }
        out.extend_from_slice(
            format!(
                "Submodule '{}' ({}) registered for path '{}'\n",
                entry.name, entry.url, entry.path
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

/// Clears submodule worktrees, keeping the gitlink and `.rukmodules` rows
/// so a later `update --init` restores them. Needs at least one path, like
/// the oracle.
fn cmd_deinit(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    if rest.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: submodule deinit [--force] <path>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = select_entries(&load_modules(ctx, store, kind)?, rest)?;
    let force = opts.is_set("force");
    let mut out = Vec::new();
    for entry in &entries {
        let child_root = ctx.root.join(&entry.path);
        refuse_dirty_child(entry, &child_root, kind, force)?;
        if child_root.is_dir() {
            std::fs::remove_dir_all(&child_root).map_err(|err| GitError::Io {
                detail: format!("removing {}: {err}", child_root.display()),
            })?;
            out.extend_from_slice(format!("Cleared directory '{}'\n", entry.path).as_bytes());
        }
        let _ = config_unset(store, &format!("submodule.{}.url", entry.name));
        let _ = config_unset(store, &format!("submodule.{}.branch", entry.name));
    }
    Ok(out)
}

/// Refuses to clear a dirty child worktree unless `force` discards it.
fn refuse_dirty_child(
    entry: &SubmoduleEntry,
    child_root: &Path,
    kind: HashKind,
    force: bool,
) -> Result<(), GitError> {
    if force || !child_root.is_dir() {
        return Ok(());
    }
    let Some(child_store) = open_child_store(child_root)? else {
        return Ok(());
    };
    if child_is_dirty(&child_store, kind, child_root)? {
        return Err(GitError::Invalid {
            detail: format!(
                "submodule {:?} has local changes; use --force to discard them",
                entry.path
            ),
        });
    }
    Ok(())
}

/// Reports whether the child worktree differs from its `HEAD`.
///
/// Staged drift compares index rows against the `HEAD` tree; worktree drift
/// re-hashes tracked file bytes (symlinks read as their target). Untracked
/// files never block, matching the oracle's tracked-changes refusal.
fn child_is_dirty(child: &Store, kind: HashKind, root: &Path) -> Result<bool, GitError> {
    let rows = scan_index(child, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Ok(true);
    }
    let head_tree = head_tree_map(child, kind)?;
    let mut indexed: BTreeMap<Vec<u8>, (TreeMode, Oid)> = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            indexed.insert(
                path.as_bytes().to_vec(),
                (TreeMode::from(entry.mode()), entry.oid()),
            );
        }
    }
    if indexed.len() != head_tree.len() {
        return Ok(true);
    }
    for (path, mode_oid) in &indexed {
        if head_tree.get(path) != Some(mode_oid) {
            return Ok(true);
        }
    }
    for (path, stage, entry) in &rows {
        if *stage != Stage::Zero || entry.mode() == FileMode::Gitlink {
            continue;
        }
        let full = join_base(root, path.as_bytes())?;
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(err) => {
                return Err(GitError::Io {
                    detail: format!("statting {}: {err}", full.display()),
                });
            }
        };
        if meta.file_type().is_dir() {
            return Ok(true);
        }
        let bytes = if meta.file_type().is_symlink() {
            std::fs::read_link(&full)
                .map_err(|err| GitError::Io {
                    detail: format!("reading link {}: {err}", full.display()),
                })?
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            std::fs::read(&full).map_err(|err| GitError::Io {
                detail: format!("reading {}: {err}", full.display()),
            })?
        };
        let oid = kind.hash_git_object("blob", &bytes).map_err(to_core)?;
        if oid != entry.oid() {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// `update`
// ---------------------------------------------------------------------------

/// Checks initialized submodules out at their recorded gitlink oids.
///
/// Uninitialized entries are skipped unless `--init` clones them first;
/// `--remote` moves the target to the recorded branch's remote tip (after
/// fetching it); `--recursive` descends into nested submodules.
fn cmd_update(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    if opts.is_set("merge") || opts.is_set("rebase") {
        return Err(GitError::Unsupported {
            command:
                "submodule update --merge/--rebase: only the checkout update mode is implemented"
                    .to_owned(),
        });
    }
    let depth = match opts.single("depth")? {
        None => None,
        Some(value) => Some(value.parse::<u32>().map_err(|_| GitError::Invalid {
            detail: format!("bad depth {value:?}"),
        })?),
    };
    let flags = UpdateFlags {
        init: opts.is_set("init"),
        recursive: opts.is_set("recursive"),
        remote: opts.is_set("remote"),
        depth,
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = select_entries(&load_modules(ctx, store, kind)?, rest)?;
    let mut out = Vec::new();
    let view = RepoView {
        root: &ctx.root,
        store,
        kind,
    };
    update_into(view, &entries, &flags, &mut out)?;
    Ok(out)
}

/// Runs the update walk for `entries` bound at `view`'s worktree.
fn update_into(
    view: RepoView<'_>,
    entries: &[SubmoduleEntry],
    flags: &UpdateFlags,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    for entry in entries {
        let child_root = view.root.join(&entry.path);
        let mut child_opt = open_child_store(&child_root)?;
        if child_opt.is_none() {
            if !flags.init {
                continue;
            }
            let src_root = remote_root_at(view.root, &entry.url)?;
            let src_store = open_store(&src_root.join(".ruk"))?;
            if src_store.hash_kind() != view.kind {
                return Err(GitError::ObjectFormat {
                    detail: format!(
                        "submodule {:?} object format disagrees with the superproject",
                        entry.path
                    ),
                });
            }
            std::fs::create_dir_all(&child_root).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", child_root.display()),
            })?;
            clone_local_into(&src_store, &child_root, view.kind, &entry.url, flags.depth)?;
            child_opt = open_child_store(&child_root)?;
        }
        let child_store = child_opt.ok_or_else(|| GitError::Corrupt {
            detail: format!("submodule {:?} has no store after init", entry.path),
        })?;
        let repo_path = RepoPath::new(entry.path.as_bytes().to_vec()).map_err(to_core)?;
        let want = if flags.remote {
            fetch_remote_tip(&child_store, view.kind, entry)?
        } else {
            index_gitlink(view.store, view.kind, &repo_path)?
                .or_else(|| head_gitlink(view.store, view.kind, entry.path.as_bytes()))
                .ok_or_else(|| GitError::NotFound {
                    detail: format!("no gitlink recorded for {:?}", entry.path),
                })?
        };
        ensure_present(&child_store, view.kind, entry, want, flags.depth)?;
        checkout_child_detached(&child_store, &child_root, view.kind, want)?;
        out.extend_from_slice(
            format!(
                "Submodule path '{}': checked out '{}'\n",
                entry.path,
                want.to_hex()
            )
            .as_bytes(),
        );
        if flags.recursive {
            let nested = load_modules_at(&child_root, &child_store, view.kind)?;
            if !nested.is_empty() {
                let child_view = RepoView {
                    root: &child_root,
                    store: &child_store,
                    kind: view.kind,
                };
                update_into(child_view, &nested, flags, &mut *out)?;
            }
        }
    }
    Ok(())
}

/// Reads the gitlink recorded for `path` in the `HEAD` tree, if any.
fn head_gitlink(store: &Store, kind: HashKind, path: &[u8]) -> Option<Oid> {
    match head_tree_map(store, kind) {
        Ok(map) => match map.get(path) {
            Some((TreeMode::Gitlink, oid)) => Some(*oid),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Fetches the recorded branch tip from the submodule url into the child
/// and returns it. Without a recorded branch the child `HEAD` is kept.
fn fetch_remote_tip(
    child: &Store,
    kind: HashKind,
    entry: &SubmoduleEntry,
) -> Result<Oid, GitError> {
    let Some(branch) = entry.branch.as_deref().filter(|branch| !branch.is_empty()) else {
        return head_oid(child);
    };
    let url = config_read_opt(child, "remote.origin.url")?.unwrap_or_else(|| entry.url.clone());
    let src_root = PathBuf::from(&url);
    let src_root = if src_root.is_absolute() {
        src_root
    } else {
        // Urls recorded by `add` are used verbatim; only absolute local
        // paths resolve for `--remote` fetches.
        return Err(GitError::Offline {
            detail: format!(
                "cannot fetch remote tip for {:?}: {url:?} is not local",
                entry.path
            ),
        });
    };
    let src_store = open_store(&src_root.join(".ruk"))?;
    let advertised = advertise(&src_store)?;
    let target = format!("refs/heads/{branch}");
    let oid = advertised
        .iter()
        .find(|item| item.name == target.as_bytes())
        .and_then(|item| match &item.target {
            RefTarget::Direct(oid) => Some(*oid),
            RefTarget::Symbolic(_) => None,
        })
        .ok_or_else(|| GitError::NotFound {
            detail: format!("branch {branch:?} not advertised by {:?}", entry.url),
        })?;
    let request = LocalFetchRequest {
        wants: vec![oid],
        haves: Vec::new(),
        filter: None,
        depth: None,
    };
    local_fetch(
        child,
        &src_store,
        b"origin",
        &request,
        &[],
        &[],
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    let name =
        RefName::new(format!("refs/remotes/origin/{branch}")).map_err(|err| GitError::Invalid {
            detail: format!("remote-tracking ref refused: {err}"),
        })?;
    apply_refs(
        child,
        kind,
        vec![RefUpdate {
            name,
            expected: RefExpect::Any,
            change: RefChange::Set(RefTarget::Direct(oid)),
        }],
    )?;
    Ok(oid)
}

/// Reads one config value without failing on storage errors.
fn config_read_opt(store: &Store, name: &str) -> Result<Option<String>, GitError> {
    super::state::config_read(store, name)
}

/// Fetches `want` from the submodule url when the child lacks it.
fn ensure_present(
    child: &Store,
    _kind: HashKind,
    entry: &SubmoduleEntry,
    want: Oid,
    depth: Option<u32>,
) -> Result<(), GitError> {
    if commit_record(child, want).is_ok() {
        return Ok(());
    }
    let url = config_read_opt(child, "remote.origin.url")?.unwrap_or_else(|| entry.url.clone());
    let src_root = PathBuf::from(&url);
    if !src_root.is_absolute() {
        return Err(GitError::NotFound {
            detail: format!(
                "submodule {:?} commit {} is not present and {:?} is not fetchable",
                entry.path,
                want.to_hex(),
                entry.url
            ),
        });
    }
    let src_store = open_store(&src_root.join(".ruk"))?;
    let request = LocalFetchRequest {
        wants: vec![want],
        haves: Vec::new(),
        filter: None,
        depth,
    };
    local_fetch(
        child,
        &src_store,
        b"origin",
        &request,
        &[],
        &[],
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    commit_record(child, want).map(|_| ())
}

/// Resolves a submodule url against `root` the way `remote_root` resolves
/// against the process context (local paths only).
fn remote_root_at(root: &Path, url: &str) -> Result<PathBuf, GitError> {
    let base = if Path::new(url).is_absolute() {
        PathBuf::from(url)
    } else {
        root.join(url)
    };
    if base.join(".ruk").is_dir() {
        return Ok(base);
    }
    Err(GitError::Offline {
        detail: format!("submodule url {url:?} is not a local repository path"),
    })
}

// ---------------------------------------------------------------------------
// `summary`, `foreach`
// ---------------------------------------------------------------------------

/// Summarizes gitlink drift: index vs `HEAD` per submodule.
///
/// In sync when both agree (or the entry is uninitialized on both sides);
/// otherwise one `* <path> <old>...<new>` line. Commit subjects are
/// omitted: this is the shape `summary` keeps without a log renderer.
fn cmd_summary(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = select_entries(&load_modules(ctx, store, kind)?, rest)?;
    let head_tree = head_tree_map(store, kind)?;
    let _ = opts;
    let mut out = Vec::new();
    for entry in &entries {
        let repo_path = RepoPath::new(entry.path.as_bytes().to_vec()).map_err(to_core)?;
        let index_oid = index_gitlink(store, kind, &repo_path)?;
        let head_oid_opt = match head_tree.get(entry.path.as_bytes()) {
            Some((TreeMode::Gitlink, oid)) => Some(*oid),
            _ => None,
        };
        match (head_oid_opt, index_oid) {
            (Some(head), Some(index)) if head != index => {
                out.extend_from_slice(
                    format!(
                        "* {} {}...{}\n",
                        entry.path,
                        short_oid(&head),
                        short_oid(&index)
                    )
                    .as_bytes(),
                );
            }
            (None, Some(index)) => {
                out.extend_from_slice(
                    format!("* {} (added {})\n", entry.path, short_oid(&index)).as_bytes(),
                );
            }
            (Some(head), None) => {
                out.extend_from_slice(
                    format!("* {} (removed {})\n", entry.path, short_oid(&head)).as_bytes(),
                );
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Runs one shell command in each initialized submodule worktree.
///
/// The command (positionals joined by a blank) runs under `sh -c` with
/// `name`, `sm_path`, `displaypath`, `sha1`, and `toplevel` set, after an
/// `Entering '<path>'` line. A failing child fails the verb.
fn cmd_foreach(ctx: &mut Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: submodule foreach [--recursive] <command>".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = load_modules(ctx, store, kind)?;
    let mut out = Vec::new();
    let view = RepoView {
        root: &ctx.root,
        store,
        kind,
    };
    let cmd = ForeachCmd {
        opts,
        command: rest,
    };
    foreach_into(view, &entries, &cmd, "", &mut out)?;
    Ok(out)
}

/// The foreach command plus its options, traveling as one argument.
struct ForeachCmd<'a> {
    /// Parsed flags (`--recursive`, `--quiet`).
    opts: &'a Collected,
    /// Command words joined with blanks under `sh -c`.
    command: &'a [String],
}

/// Runs the foreach walk for `entries` bound at `view`'s worktree.
fn foreach_into(
    view: RepoView<'_>,
    entries: &[SubmoduleEntry],
    cmd: &ForeachCmd<'_>,
    prefix: &str,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    let script = cmd.command.join(" ");
    for entry in entries {
        let child_root = view.root.join(&entry.path);
        let Some(child_store) = open_child_store(&child_root)? else {
            continue;
        };
        let display = format!("{prefix}{}", entry.path);
        let sha1 = head_oid(&child_store)
            .map(|oid| oid.to_hex())
            .unwrap_or_default();
        out.extend_from_slice(format!("Entering '{display}'\n").as_bytes());
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .current_dir(&child_root)
            .env("name", &entry.name)
            .env("sm_path", &entry.path)
            .env("displaypath", &display)
            .env("sha1", &sha1)
            .env("toplevel", view.root)
            .output()
            .map_err(|err| GitError::Io {
                detail: format!("running foreach in {display:?}: {err}"),
            })?;
        out.extend_from_slice(&output.stdout);
        out.extend_from_slice(&output.stderr);
        if !output.status.success() {
            return Err(GitError::Invalid {
                detail: format!(
                    "foreach in {display:?} failed with {}",
                    output.status.code().unwrap_or(-1)
                ),
            });
        }
        if cmd.opts.is_set("recursive") {
            let nested = load_modules_at(&child_root, &child_store, view.kind)?;
            if !nested.is_empty() {
                let child_view = RepoView {
                    root: &child_root,
                    store: &child_store,
                    kind: view.kind,
                };
                foreach_into(child_view, &nested, cmd, &format!("{display}/"), &mut *out)?;
            }
        }
    }
    Ok(())
}
