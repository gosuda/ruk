//! Repository lifecycle verbs: `init`, `clone`, `migrate`, `config`, `remote`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `init` | `Store::create` + workspace row + unborn `HEAD` | implemented |
//! | `clone` | `Store::create` + `session::local_fetch` + ref copy | implemented for local paths; network sources are `Offline` |
//! | `migrate` | `Store::create` + `import::import_repository` + workspace row | implemented; worktree checkout, config conversion, and hooks are out of scope |
//! | `config` | `Pins` records under `cli/config/` | implemented, `--local` scope only |
//! | `remote` | `remote.<name>.*` config records | implemented |
//! | `worktree` | absent workcopy lane | unsupported |
//!
//! Oracle anchors: `git/builtin/init-db.c`, `git/builtin/clone.c`,
//! `git/builtin/config.c`, `git/builtin/remote.c`, `git/builtin/worktree.c`.

use std::sync::Arc;

use ruk_core::change::OperationId;
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::ids::HashKind;
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTarget, RefUpdate};
use ruk_core::refs::StoreRefs;
use ruk_core::store::{PreparationBudget, Store};
use ruk_core::workspace::{GitCompatWorkspace, HeadRef, Scope};
use ruk_git::GitError;
use ruk_git::import::objects::source_hash_kind;
use ruk_git::import::{
    DirectPublish, ImportLimits, ImportProgress, ImportRequest, SourceHead, import_repository,
};
use ruk_git::transport::Interrupt;
use ruk_git::transport::session::{LocalFetchRequest, advertise, local_fetch};

use super::state::{
    DEFAULT_BRANCH, apply_refs, config_list, config_read, config_unset, config_write,
    load_workspace, open_store_at, remote_fetch_specs, remote_root, remote_url, workspace_mutation,
};
use super::{Collected, Ctx, FlagSpec, collect, line};

/// Creates an empty repository: the store, the workspace row, and an unborn
/// `HEAD` on the default branch.
///
/// Oracle: `git/builtin/init-db.c`.
pub(crate) fn init(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "object-format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "bare",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        // Accepted: names the unborn `HEAD` branch, defaulting to `main`.
        FlagSpec {
            long: "initial-branch",
            short: Some('b'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let initial = match opts.single("initial-branch")? {
        None => DEFAULT_BRANCH.to_owned(),
        Some(name) => {
            let full = format!("refs/heads/{name}");
            RefName::new(full.as_str()).map_err(|err| GitError::Invalid {
                detail: format!("initial branch refused: {err}"),
            })?;
            full
        }
    };
    let kind = match opts.single("object-format")? {
        None => HashKind::Sha1,
        Some(value) => match value.as_str() {
            "sha1" => HashKind::Sha1,
            "sha256" => HashKind::Sha256,
            other => {
                return Err(GitError::Invalid {
                    detail: format!("unknown object format {other:?}"),
                });
            }
        },
    };
    let dir = opts.positionals.first().map_or(".", String::as_str);
    let path = if std::path::Path::new(dir).is_absolute() {
        std::path::PathBuf::from(dir)
    } else {
        ctx.env.cwd.join(dir)
    };
    std::fs::create_dir_all(&path).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", path.display()),
    })?;
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store_dir = path.join(".ruk");
    let reinit = store_dir.is_dir();
    let store = if reinit {
        Store::open(&store_dir, budget).map_err(GitError::from)?
    } else {
        Store::create(&store_dir, kind, budget).map_err(GitError::from)?
    };
    if load_workspace(&store)?.is_none() {
        let name = RefName::new(initial.as_str()).map_err(|err| GitError::Invalid {
            detail: format!("default branch refused: {err}"),
        })?;
        let workspace = GitCompatWorkspace::new(HeadRef::Symbolic(name), Scope::Full);
        let mutation = workspace_mutation(None, &workspace)?;
        store
            .publish(Vec::new(), &[mutation])
            .map_err(GitError::from)?;
    }
    if opts.is_set("quiet") {
        return Ok(Vec::new());
    }
    let display = if dir == "." {
        ctx.env.cwd.clone()
    } else {
        path
    };
    let message = if reinit {
        format!(
            "Reinitialized existing Ruk repository in {}/.ruk/\n",
            display.display()
        )
    } else {
        format!(
            "Initialized empty Ruk repository in {}/.ruk/\n",
            display.display()
        )
    };
    Ok(message.into_bytes())
}

/// Clones a local repository: fresh store, fetched tips, copied branches.
///
/// Oracle: `git/builtin/clone.c`. Only local paths are routable in this
/// slice; anything else is `Offline`, the way an unreachable remote fails.
pub(crate) fn clone(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "bare",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "depth",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "origin",
            short: Some('o'),
            takes_value: true,
        },
        FlagSpec {
            long: "branch",
            short: Some('b'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let src = opts.positionals.first().ok_or_else(|| GitError::Invalid {
        detail: "clone needs a source repository".to_owned(),
    })?;
    let origin = opts
        .single("origin")?
        .unwrap_or_else(|| "origin".to_owned());
    let depth = opts
        .single("depth")?
        .map(|value| {
            value.parse::<u32>().map_err(|_| GitError::Invalid {
                detail: format!("bad depth {value:?}"),
            })
        })
        .transpose()?;
    let src_root = remote_root(ctx, src)?;
    let src_store = open_store_at(&src_root)?;
    let dst_name = opts
        .positionals
        .get(1)
        .map_or_else(|| default_clone_name(src), |name| name.clone());
    let dst = if std::path::Path::new(&dst_name).is_absolute() {
        std::path::PathBuf::from(&dst_name)
    } else {
        ctx.env.cwd.join(&dst_name)
    };
    if dst.exists() {
        return Err(GitError::Invalid {
            detail: format!("destination {} already exists", dst.display()),
        });
    }
    std::fs::create_dir_all(&dst).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", dst.display()),
    })?;
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let kind = src_store.hash_kind();
    let dst_store = Store::create(&dst.join(".ruk"), kind, budget).map_err(GitError::from)?;
    let advertised = advertise(&src_store)?;
    if advertised.is_empty() {
        return Err(GitError::NotFound {
            detail: "source repository has no refs to clone".to_owned(),
        });
    }
    let wants: Vec<ruk_core::ids::Oid> = advertised
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
        &dst_store,
        &src_store,
        origin.as_bytes(),
        &request,
        &[],
        &[],
        ruk_git::transport::pack::IngestLimits::default(),
        &Interrupt::none(),
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
            let remote_name =
                RefName::new(remote_tracking_name(&origin, &entry.name)?).map_err(|err| {
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
    apply_refs(&dst_store, kind, updates)?;
    let head_branch = src_head_branch(&src_store)?.unwrap_or_else(|| DEFAULT_BRANCH.to_owned());
    let checkout_branch = match opts.single("branch")? {
        Some(short) => format!("refs/heads/{short}"),
        None => head_branch,
    };
    let head_name = RefName::new(checkout_branch.clone()).map_err(|err| GitError::Invalid {
        detail: format!("branch refused: {err}"),
    })?;
    if StoreRefs::new(&dst_store)
        .get(&head_name)
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?
        .is_none()
    {
        return Err(GitError::NotFound {
            detail: format!("branch {checkout_branch:?} does not exist in the source"),
        });
    }
    let workspace = GitCompatWorkspace::new(HeadRef::Symbolic(head_name), Scope::Full);
    let mutation = workspace_mutation(None, &workspace)?;
    dst_store
        .publish(Vec::new(), &[mutation])
        .map_err(GitError::from)?;
    config_write(&dst_store, &format!("remote.{origin}.url"), src)?;
    config_write(
        &dst_store,
        &format!("remote.{origin}.fetch"),
        &format!("+refs/heads/*:refs/remotes/{origin}/*"),
    )?;
    Ok(format!("Cloned into {}\n", dst.display()).into_bytes())
}

/// Imports an existing Git repository into a fresh `.ruk` store.
///
/// Git has no `migrate` builtin; the object and ref motion reuses the
/// exact-import lane (`ruk_git::import::import_repository`), which reads
/// loose zlib objects, pack v2/v3 with idx v1/v2, and alternates, verifying
/// every OID by re-hashing.
///
/// `<git-dir>` is a worktree root (holding `.git/`) or a bare repository /
/// `.git` directory; `<dest-dir>` defaults to `<git-dir>` itself and the
/// store lands at `<dest>/.ruk`. `--bare` is accepted for `git clone`
/// familiarity and changes nothing (no checkout lane exists either way).
/// `<dest>/.ruk` must not exist unless `--force` replaces it.
///
/// Objects publish in bounded batches and refs only in the final batch, so
/// a mid-import failure may leave a partial `.ruk`: retry with `--force`.
/// Worktree checkout, config conversion, and hooks are out of scope.
pub(crate) fn migrate(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "bare",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let src_arg = opts.positionals.first().ok_or_else(|| GitError::Invalid {
        detail: "usage: migrate [--bare] [--force] <git-dir> [<dest-dir>]".to_owned(),
    })?;
    let resolve = |arg: &str| -> std::path::PathBuf {
        let path = std::path::Path::new(arg);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            ctx.env.cwd.join(path)
        }
    };
    let src = resolve(src_arg);
    let git_dir = resolve_source_git_dir(&src)?;
    let dest = opts
        .positionals
        .get(1)
        .map_or_else(|| src.clone(), |arg| resolve(arg));
    std::fs::create_dir_all(&dest).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", dest.display()),
    })?;
    let store_dir = dest.join(".ruk");
    if store_dir.exists() {
        if !opts.is_set("force") {
            return Err(GitError::Invalid {
                detail: format!(
                    "{} already exists; pass --force to replace it",
                    store_dir.display()
                ),
            });
        }
        std::fs::remove_dir_all(&store_dir).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", store_dir.display()),
        })?;
    }
    let kind = source_hash_kind(&git_dir)?;
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store = Store::create(&store_dir, kind, budget).map_err(GitError::from)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| i64::try_from(span.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let request = ImportRequest {
        git_dir: &git_dir,
        observation_source: b"migrate",
        operation: OperationId(1),
        committer: Signature {
            name: "ruk migrate".into(),
            email: "migrate@example.com".into(),
            timestamp: now,
            offset: TzOffset::UTC,
        },
        message: "migrate".into(),
        limits: ImportLimits::default(),
    };
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let report = import_repository(&store, &request, &progress, &mut sink)?;
    let head = match &report.head {
        Some(SourceHead::Symbolic { name, .. }) => HeadRef::Symbolic(name.clone()),
        Some(SourceHead::Detached(oid)) => HeadRef::Detached(*oid),
        None => {
            let name = RefName::new(DEFAULT_BRANCH).map_err(|err| GitError::Invalid {
                detail: format!("default branch refused: {err}"),
            })?;
            HeadRef::Symbolic(name)
        }
    };
    let workspace = GitCompatWorkspace::new(head, Scope::Full);
    let mutation = workspace_mutation(None, &workspace)?;
    store
        .publish(Vec::new(), &[mutation])
        .map_err(GitError::from)?;
    Ok(format!(
        "Migrated {} objects and {} refs from {} [{kind}]\n",
        report.objects,
        report.refs_seen,
        git_dir.display(),
    )
    .into_bytes())
}

/// Maps a migrate source argument to the Git directory it names: a
/// worktree root through its `.git/`, else the directory itself when it
/// holds `objects/`.
fn resolve_source_git_dir(src: &std::path::Path) -> Result<std::path::PathBuf, GitError> {
    let dotted = src.join(".git");
    if dotted.is_dir() {
        return Ok(dotted);
    }
    if src.join("objects").is_dir() {
        return Ok(src.to_path_buf());
    }
    Err(GitError::Invalid {
        detail: format!(
            "{} is not a git repository (no .git/ or objects/)",
            src.display()
        ),
    })
}

/// Derives the destination directory name from the source path.
fn default_clone_name(src: &str) -> String {
    let trimmed = src.trim_end_matches('/');
    let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
    base.strip_suffix(".ruk")
        .or_else(|| base.strip_suffix(".git"))
        .unwrap_or(base)
        .to_owned()
}

/// Maps `refs/heads/<branch>` to its remote-tracking name.
fn remote_tracking_name(origin: &str, source: &[u8]) -> Result<Vec<u8>, GitError> {
    let suffix = source
        .strip_prefix(b"refs/heads/")
        .ok_or_else(|| GitError::Invalid {
            detail: "only branch heads map to remote-tracking refs".to_owned(),
        })?;
    let mut out = format!("refs/remotes/{origin}/").into_bytes();
    out.extend_from_slice(suffix);
    Ok(out)
}

/// Reads the source repository's checked-out branch name, if it has one.
fn src_head_branch(src: &Store) -> Result<Option<String>, GitError> {
    let raw = src.fact(
        ruk_core::store::types::FactTable::Workspaces,
        b"cli/workspaces/git-compat",
    )?;
    let Some(bytes) = raw else {
        return Ok(None);
    };
    let workspace: GitCompatWorkspace =
        sonic_rs::from_slice(&bytes).map_err(|err| GitError::Corrupt {
            detail: format!("source workspace row does not decode: {err}"),
        })?;
    match workspace.head {
        HeadRef::Symbolic(name) => Ok(name.to_utf8().map(str::to_owned)),
        HeadRef::Detached(_) => Ok(None),
    }
}

/// Gets and sets repository options in the `cli/config/` record space.
///
/// Oracle: `git/builtin/config.c`. Only the local scope exists here;
/// `--global`, `--system`, and `--worktree` are `Unsupported`.
pub(crate) fn config(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "list",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "get",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "unset",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "local",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "global",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "system",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "worktree",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "bool",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.is_set("global") || opts.is_set("system") || opts.is_set("worktree") {
        return Err(GitError::Unsupported {
            command: "config --global/--system/--worktree".to_owned(),
        });
    }
    let store = ctx.store()?;
    if opts.is_set("list") {
        reject_positionals(&opts, "config --list")?;
        let mut out = Vec::new();
        for (name, value) in config_list(store)? {
            out.extend_from_slice(format!("{name}={value}\n").as_bytes());
        }
        return Ok(out);
    }
    if opts.is_set("unset") {
        let [name] = opts.positionals.as_slice() else {
            return Err(GitError::Invalid {
                detail: "usage: config --unset <name>".to_owned(),
            });
        };
        config_unset(store, name)?;
        return Ok(Vec::new());
    }
    match opts.positionals.as_slice() {
        [] => {
            if opts.is_set("get") {
                return Err(GitError::Invalid {
                    detail: "config --get needs a name".to_owned(),
                });
            }
            let mut out = Vec::new();
            for (name, value) in config_list(store)? {
                out.extend_from_slice(format!("{name}={value}\n").as_bytes());
            }
            Ok(out)
        }
        [name] => {
            let stored = config_read(store, name)?;
            match stored {
                Some(value) => Ok(line(value.into_bytes())),
                None => Err(GitError::NotFound {
                    detail: format!("config {name} is not set"),
                }),
            }
        }
        [name, value] => {
            if opts.is_set("get") {
                return Err(GitError::Invalid {
                    detail: "config --get takes exactly one name".to_owned(),
                });
            }
            if opts.is_set("bool") {
                parse_bool_flag(value)?;
            }
            config_write(store, name, value)?;
            Ok(Vec::new())
        }
        _ => Err(GitError::Invalid {
            detail: "config takes at most <name> [<value>]".to_owned(),
        }),
    }
}

/// Validates a `--bool` value without changing its stored spelling.
fn parse_bool_flag(value: &str) -> Result<(), GitError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0" => Ok(()),
        _ => Err(GitError::Invalid {
            detail: format!("bad boolean config value {value:?}"),
        }),
    }
}

/// Manages tracked repositories through `remote.<name>.*` config records.
///
/// Oracle: `git/builtin/remote.c`.
pub(crate) fn remote(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "verbose",
        short: Some('v'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let sub = opts.positionals.first().map(String::as_str);
    match sub {
        None => {
            if opts.is_set("verbose") {
                list_remote_urls(store)
            } else {
                list_remote_names(store)
            }
        }
        Some("-v") => list_remote_urls(store),
        Some("add") => {
            let tail = sub_tail(&opts);
            let [name, url] = tail else {
                return Err(GitError::Invalid {
                    detail: "usage: remote add <name> <url>".to_owned(),
                });
            };
            if config_read(store, &format!("remote.{name}.url"))?.is_some() {
                return Err(GitError::Invalid {
                    detail: format!("remote {name:?} already exists"),
                });
            }
            config_write(store, &format!("remote.{name}.url"), &url)?;
            config_write(
                store,
                &format!("remote.{name}.fetch"),
                &format!("+refs/heads/*:refs/remotes/{name}/*"),
            )?;
            Ok(Vec::new())
        }
        Some("remove") | Some("rm") => {
            let tail = sub_tail(&opts);
            let [name] = tail else {
                return Err(GitError::Invalid {
                    detail: "usage: remote remove <name>".to_owned(),
                });
            };
            remote_url(ctx, name)?;
            for suffix in ["url", "fetch"] {
                let key = format!("remote.{name}.{suffix}");
                if config_read(store, &key)?.is_some() {
                    config_unset(store, &key)?;
                }
            }
            Ok(Vec::new())
        }
        Some("get-url") => {
            let tail = sub_tail(&opts);
            let [name] = tail else {
                return Err(GitError::Invalid {
                    detail: "usage: remote get-url <name>".to_owned(),
                });
            };
            Ok(line(remote_url(ctx, name)?.into_bytes()))
        }
        Some("set-url") => {
            let tail = sub_tail(&opts);
            let [name, url] = tail else {
                return Err(GitError::Invalid {
                    detail: "usage: remote set-url <name> <url>".to_owned(),
                });
            };
            remote_url(ctx, name)?;
            config_write(store, &format!("remote.{name}.url"), url)?;
            Ok(Vec::new())
        }
        Some("show") => {
            let names = if opts.positionals.len() == 1 {
                all_remote_names(store)?
            } else {
                sub_tail(&opts).to_vec()
            };
            let mut out = Vec::new();
            for name in names {
                let url = remote_url(ctx, &name)?;
                out.extend_from_slice(format!("{name}\n  URL: {url}\n").as_bytes());
                for spec in remote_fetch_specs(ctx, &name) {
                    out.extend_from_slice(format!("  fetch: {spec}\n").as_bytes());
                }
            }
            Ok(out)
        }
        Some(other) => Err(GitError::Invalid {
            detail: format!("unknown remote subcommand {other:?}"),
        }),
    }
}

/// Lists remote names, one per line.
fn list_remote_names(store: &Store) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    for name in all_remote_names(store)? {
        out.extend_from_slice(format!("{name}\n").as_bytes());
    }
    Ok(out)
}

/// Lists remotes with their URLs, like `remote -v`.
fn list_remote_urls(store: &Store) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    for name in all_remote_names(store)? {
        let url = config_read(store, &format!("remote.{name}.url"))?.unwrap_or_default();
        out.extend_from_slice(format!("{name}\t{url} (fetch)\n").as_bytes());
        out.extend_from_slice(format!("{name}\t{url} (push)\n").as_bytes());
    }
    Ok(out)
}

/// Collects every configured remote name in order.
fn all_remote_names(store: &Store) -> Result<Vec<String>, GitError> {
    let mut names = Vec::new();
    for (key, _) in config_list(store)? {
        if let Some(rest) = key.strip_prefix("remote.") {
            if let Some((name, _)) = rest.split_once('.') {
                if !names.contains(&name.to_owned()) {
                    names.push(name.to_owned());
                }
            }
        }
    }
    Ok(names)
}

/// Manages multiple working trees. Unsupported: no workcopy lane exists.
///
/// Oracle: `git/builtin/worktree.c`.
pub(crate) fn worktree(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "worktree: multiple working trees need the workcopy lane".to_owned(),
    })
}

/// Rejects positionals for verbs that take none.
fn reject_positionals(opts: &Collected, usage: &str) -> Result<(), GitError> {
    if opts.positionals.is_empty() {
        return Ok(());
    }
    Err(GitError::Invalid {
        detail: format!("{usage} takes no arguments"),
    })
}

/// Takes the positionals after the subcommand word.
fn sub_tail(opts: &Collected) -> &[String] {
    opts.positionals.get(1..).unwrap_or(&[])
}
