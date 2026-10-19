//! Branch and ref verbs: `branch`, `checkout`, `switch`, `restore`,
//! `reset`, `update-ref`, `symbolic-ref`, `show-ref`, `for-each-ref`, `tag`,
//! `stash`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `branch` | ref transactions + ancestry checks | implemented (list/create/delete/rename) |
//! | `checkout` | workspace `checkout` transition + index reset | implemented (branches, detach, `-b`, paths) |
//! | `switch` | same transition, no path form | implemented (with remote guess) |
//! | `restore` | index/worktree row sync | implemented |
//! | `reset` | branch move + index/worktree sync | implemented (`--soft`, `--mixed`, `--hard`, paths) |
//! | `update-ref` | checked ref transaction + reflog row | implemented |
//! | `symbolic-ref` | workspace `HEAD` move or ref symref | implemented |
//! | `show-ref` | ref scan | implemented |
//! | `for-each-ref` | ref scan + object reads | implemented (`%(refname)`, `%(objectname)`, `%(objecttype)`) |
//! | `tag` | ref rows + tag payloads | implemented (lightweight, annotated, list, delete) |
//! | `stash` | stash commits + slot records + index snapshots | implemented (`push`, `list`, `show`, `drop`, `pop`, `apply`, `clear`) |
//!
//! Oracle anchors: `git/builtin/branch.c`, `git/builtin/checkout.c`,
//! `git/builtin/switch.c`, `git/builtin/restore.c`, `git/builtin/reset.c`,
//! `git/builtin/update-ref.c`, `git/builtin/symbolic-ref.c`,
//! `git/builtin/show-ref.c`, `git/builtin/for-each-ref.c`,
//! `git/builtin/tag.c`, `git/builtin/stash.c`.

use ruk_core::commit::CommitRecord;
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage};
use ruk_core::ops::{NewRequest, prepare_new as ops_prepare_new};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::refs::{ReflogKey, ReflogRecord, StoreRefs, prepare_append_reflog};
use ruk_core::store::{FactMutation, Store};
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    AppliedRef, StashSlot, apply_refs, branch_name, config_read, config_unset, config_write,
    create_branch, head_oid, is_ancestor, list_refs, load_or_default, merged_rows,
    path_row_mutations, read_path_rows, reflog_alloc, replace_redirect, resolve_branch_target,
    resolve_rev, scan_index, stash_alloc, stash_drop, stash_read, stash_write, workspace_mutation,
};
use super::tree::{
    TreeMode, WorktreeType, build_index_tree, commit_tree_oid, flatten_tree, join_base,
    peel_to_tree, read_object_bytes, store_object, tag_payload,
};
use super::{Ctx, FlagSpec, collect, line};

/// Lists, creates, renames, or deletes branches.
///
/// Oracle: `git/builtin/branch.c`.
pub(crate) fn branch(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "force-delete",
            short: Some('D'),
            takes_value: false,
        },
        FlagSpec {
            long: "move",
            short: Some('m'),
            takes_value: false,
        },
        FlagSpec {
            long: "force-move",
            short: Some('M'),
            takes_value: false,
        },
        FlagSpec {
            long: "copy",
            short: Some('c'),
            takes_value: false,
        },
        FlagSpec {
            long: "force-copy",
            short: Some('C'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "show-current",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "list",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "remotes",
            short: Some('r'),
            takes_value: false,
        },
        FlagSpec {
            long: "set-upstream-to",
            short: Some('u'),
            takes_value: true,
        },
        FlagSpec {
            long: "unset-upstream",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "sort",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "points-at",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "track",
            short: Some('t'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-track",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "create-reflog",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "edit-description",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "abbrev",
            short: None,
            takes_value: true,
        },
        // Accepted and inert: piped output is already one-per-line with no
        // color, which is what `--column`/`--color` select for non-TTY
        // output in the oracle; `--no-column`/`--no-color` are the default.
        FlagSpec {
            long: "column",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-column",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "color",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-color",
            short: None,
            takes_value: false,
        },
        // Accepted for script compatibility: branch output is already quiet
        // except for the delete notice, which this suppresses.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    // `--merged`/`--no-merged`/`--contains`/`--no-contains` take an optional
    // commit (default `HEAD`, oracle `LASTARG_DEFAULT`): pull them out before
    // `collect`, which cannot express optional values. `--with`/`--without`
    // are the oracle's hidden aliases for `--contains`/`--no-contains`.
    // `-vv` and other combined no-value shorts are expanded here too, since
    // `collect` only accepts one short per token.
    let mut merged: Vec<String> = Vec::new();
    let mut no_merged: Vec<String> = Vec::new();
    let mut contains: Vec<String> = Vec::new();
    let mut no_contains: Vec<String> = Vec::new();
    let mut pre = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let mut inline: Option<String> = None;
        let mut bare_name: Option<&str> = None;
        for name in [
            "--merged",
            "--no-merged",
            "--contains",
            "--no-contains",
            "--with",
            "--without",
        ] {
            if arg == name {
                bare_name = Some(name);
                break;
            }
            if let Some(rest) = arg.strip_prefix(&format!("{name}=")) {
                inline = Some(rest.to_owned());
                bare_name = Some(name);
                break;
            }
        }
        if let Some(name) = bare_name {
            let value = if let Some(v) = inline {
                v
            } else if index + 1 < args.len()
                && args[index + 1] != "--"
                && !args[index + 1].starts_with('-')
            {
                index += 1;
                args[index].clone()
            } else {
                "HEAD".to_owned()
            };
            match name {
                "--merged" => merged.push(value),
                "--no-merged" => no_merged.push(value),
                "--contains" | "--with" => contains.push(value),
                _ => no_contains.push(value),
            }
            index += 1;
            continue;
        }
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && !arg.contains('=')
            && arg[1..].chars().all(|ch| {
                specs
                    .iter()
                    .any(|spec| spec.short == Some(ch) && !spec.takes_value)
            })
        {
            for ch in arg[1..].chars() {
                pre.push(format!("-{ch}"));
            }
            index += 1;
            continue;
        }
        pre.push(arg.clone());
        index += 1;
    }
    let mut opts = collect(&pre, &specs)?;
    for value in merged {
        opts.present
            .entry("merged".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in no_merged {
        opts.present
            .entry("no-merged".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in contains {
        opts.present
            .entry("contains".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in no_contains {
        opts.present
            .entry("no-contains".to_owned())
            .or_default()
            .push(Some(value));
    }
    let store = ctx.store()?;
    if opts.is_set("show-current") {
        let current = current_branch_name(store)?.unwrap_or_default();
        return Ok(line(shorten_refname(&current).as_bytes().to_vec()));
    }
    if opts.single("set-upstream-to")?.is_some() {
        return set_branch_upstream(ctx, &opts);
    }
    if opts.is_set("unset-upstream") {
        return unset_branch_upstream(ctx, &opts);
    }
    if opts.is_set("delete") || opts.is_set("force-delete") {
        return delete_branches(ctx, &opts);
    }
    if opts.is_set("move") || opts.is_set("force-move") {
        return rename_branch(ctx, &opts);
    }
    if opts.is_set("copy") || opts.is_set("force-copy") {
        return copy_branch(ctx, &opts);
    }
    if opts.is_set("edit-description") {
        if opts.is_set("delete")
            || opts.is_set("force-delete")
            || opts.is_set("move")
            || opts.is_set("force-move")
            || opts.is_set("copy")
            || opts.is_set("force-copy")
        {
            return Err(GitError::Invalid {
                detail: "cannot combine --edit-description with another action".to_owned(),
            });
        }
        return edit_branch_description(ctx, &opts);
    }
    if opts.is_set("track") && opts.is_set("no-track") {
        return Err(GitError::Invalid {
            detail: "cannot combine --track and --no-track".to_owned(),
        });
    }
    // Any list-shaping flag implies `--list`: positionals are patterns, not a
    // branch to create, the way the oracle's `filter`/`format` options do.
    let list_mode = opts.is_set("list")
        || opts.count("verbose") > 0
        || opts.is_set("merged")
        || opts.is_set("no-merged")
        || opts.is_set("contains")
        || opts.is_set("no-contains")
        || opts.all("sort").is_ok_and(|v| !v.is_empty())
        || opts.single("format").is_ok_and(|v| v.is_some())
        || opts.all("points-at").is_ok_and(|v| !v.is_empty());
    match opts.positionals.as_slice() {
        [] => list_branches(ctx, &opts),
        _ if list_mode => list_branches(ctx, &opts),
        _ if opts.is_set("remotes") || opts.is_set("all") => Err(GitError::Invalid {
            detail: "the -a, and -r, options to 'git branch' do not take a branch name.\nDid you mean to use: -a|-r --list <pattern>?".to_owned(),
        }),
        [name] => {
            if opts.is_set("track") {
                return Err(GitError::Invalid {
                    detail: "cannot set up tracking information; starting point is HEAD"
                        .to_owned(),
                });
            }
            let refname = branch_name(name)?;
            if super::state::read_ref(store, &refname)?.is_some() {
                if !opts.is_set("force") {
                    return Err(GitError::Invalid {
                        detail: format!("branch {name:?} already exists"),
                    });
                }
                refuse_checked_out_branch(store, name)?;
                let before = super::state::read_ref(store, &refname)?;
                let target = resolve_branch_target(store, ctx.kind()?, None)?;
                force_branch(store, ctx.kind()?, name, target)?;
                if opts.is_set("create-reflog") {
                    let skipped = maybe_create_reflog(
                        ctx,
                        &refname,
                        before,
                        target,
                        "branch: Created from HEAD".to_owned(),
                    )?;
                    if skipped {
                        ctx.emit_stderr(
                            b"warning: no identity configured; skipping reflog creation\n",
                        );
                    }
                }
                return Ok(Vec::new());
            }
            let target = resolve_branch_target(store, ctx.kind()?, None)?;
            create_branch(store, ctx.kind()?, name, target)?;
            if opts.is_set("create-reflog") {
                let skipped = maybe_create_reflog(
                    ctx,
                    &refname,
                    None,
                    target,
                    "branch: Created from HEAD".to_owned(),
                )?;
                if skipped {
                    ctx.emit_stderr(
                        b"warning: no identity configured; skipping reflog creation\n",
                    );
                }
            }
            Ok(Vec::new())
        }
        [name, start] => {
            let target = resolve_branch_target(store, ctx.kind()?, Some(start))?;
            let refname = branch_name(name)?;
            let before = super::state::read_ref(store, &refname)?;
            if !opts.is_set("force") {
                if before.is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("branch {name:?} already exists"),
                    });
                }
            } else {
                refuse_checked_out_branch(store, name)?;
            }
            force_branch(store, ctx.kind()?, name, target)?;
            let skipped = if opts.is_set("create-reflog") {
                maybe_create_reflog(
                    ctx,
                    &refname,
                    before,
                    target,
                    format!("branch: Created from {start}"),
                )?
            } else {
                false
            };
            if opts.is_set("track") {
                record_tracking(store, name, start)?;
            }
            if skipped {
                ctx.emit_stderr(
                    b"warning: no identity configured; skipping reflog creation\n",
                );
            }
            Ok(Vec::new())
        }
        _ => Err(GitError::Invalid {
            detail: "usage: branch [<name> [<start>]]".to_owned(),
        }),
    }
}

/// Refuses to force-move the checked-out branch, the way the oracle
/// protects the worktree's branch from `branch -f`.
fn refuse_checked_out_branch(store: &Store, name: &str) -> Result<(), GitError> {
    let current = current_branch_name(store)?;
    let wanted = format!("refs/heads/{name}");
    if current.as_deref() == Some(wanted.as_str()) || current.as_deref() == Some(name) {
        return Err(GitError::Invalid {
            detail: format!("cannot force update the checked-out branch {name:?}"),
        });
    }
    Ok(())
}

/// Resolves `<remote>/<branch>` or a local branch into the
/// `(remote, merge)` config pair `git branch -u` records.
fn parse_upstream(store: &Store, upstream: &str) -> Result<(String, String), GitError> {
    if let Some(local) = upstream.strip_prefix("refs/heads/") {
        let name = branch_name(local)?;
        if super::state::read_ref(store, &name)?.is_some() {
            return Ok((".".to_owned(), format!("refs/heads/{local}")));
        }
    } else {
        let short = upstream.strip_prefix("refs/remotes/").unwrap_or(upstream);
        if let Some((remote, rest)) = short.split_once('/') {
            let full = format!("refs/remotes/{remote}/{rest}");
            let name = RefName::new(full).map_err(|err| GitError::Invalid {
                detail: format!("bad upstream name: {err}"),
            })?;
            if super::state::read_ref(store, &name)?.is_some() {
                return Ok((remote.to_owned(), format!("refs/heads/{rest}")));
            }
        } else {
            let name = branch_name(short)?;
            if super::state::read_ref(store, &name)?.is_some() {
                return Ok((".".to_owned(), format!("refs/heads/{short}")));
            }
        }
    }
    Err(GitError::NotFound {
        detail: format!("upstream {upstream:?} does not exist"),
    })
}

/// Resolves the branch `-u`/`--unset-upstream` acts on: the positional or
/// the checked-out branch, as a full ref name plus its config short name.
fn upstream_branch(ctx: &Ctx, opts: &super::Collected) -> Result<(String, String), GitError> {
    let store = ctx.store()?;
    let full = match opts.positionals.as_slice() {
        [] => current_branch_name(store)?.ok_or_else(|| GitError::Invalid {
            detail: "not on a branch".to_owned(),
        })?,
        [name] => {
            if name.starts_with("refs/") {
                name.clone()
            } else {
                format!("refs/heads/{name}")
            }
        }
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: branch [-u <upstream> | --unset-upstream] [<branch>]".to_owned(),
            });
        }
    };
    let short = full
        .strip_prefix("refs/heads/")
        .ok_or_else(|| GitError::Invalid {
            detail: "can only track a local branch".to_owned(),
        })?
        .to_owned();
    Ok((full, short))
}

/// Records `branch.<name>.remote`/`branch.<name>.merge` for one branch.
///
/// Oracle: `git/builtin/branch.c` (`setup_tracking`).
fn set_branch_upstream(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let upstream = opts
        .single("set-upstream-to")?
        .ok_or_else(|| GitError::Invalid {
            detail: "option --set-upstream-to requires a value".to_owned(),
        })?;
    let (full, short) = upstream_branch(ctx, opts)?;
    let target = RefName::new(full).map_err(|err| GitError::Invalid {
        detail: format!("bad branch name: {err}"),
    })?;
    if super::state::read_ref(store, &target)?.is_none() {
        return Err(GitError::NotFound {
            detail: format!("branch {short:?} does not exist"),
        });
    }
    let (remote, merge) = parse_upstream(store, &upstream)?;
    config_write(store, &format!("branch.{short}.remote"), &remote)?;
    config_write(store, &format!("branch.{short}.merge"), &merge)?;
    Ok(Vec::new())
}

/// Drops `branch.<name>.remote`/`branch.<name>.merge` for one branch.
fn unset_branch_upstream(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let (_, short) = upstream_branch(ctx, opts)?;
    let remote_key = format!("branch.{short}.remote");
    let merge_key = format!("branch.{short}.merge");
    if config_read(store, &remote_key)?.is_none() && config_read(store, &merge_key)?.is_none() {
        return Err(GitError::Invalid {
            detail: format!("branch {short:?} has no upstream configured"),
        });
    }
    if config_read(store, &remote_key)?.is_some() {
        config_unset(store, &remote_key)?;
    }
    if config_read(store, &merge_key)?.is_some() {
        config_unset(store, &merge_key)?;
    }
    Ok(Vec::new())
}

static EDIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Resolves the editor the way `var GIT_EDITOR` does: `GIT_EDITOR`, then
/// `core.editor`, then `VISUAL`, then `EDITOR`.
fn resolve_editor(ctx: &Ctx) -> Option<String> {
    ctx.env
        .get("GIT_EDITOR")
        .map(str::to_owned)
        .or_else(|| ctx.config_get("core.editor"))
        .or_else(|| ctx.env.get("VISUAL").map(str::to_owned))
        .or_else(|| ctx.env.get("EDITOR").map(str::to_owned))
}

/// Edits `initial` in the configured editor, returning the saved bytes.
///
/// Headless callers (tests, the IPC daemon) never reach the spawn: without
/// a terminal on stdin the verb fails exactly where the oracle fails
/// instead of hanging. A missing editor or a failing editor is an `Invalid`
/// configuration error, not an unimplemented path.
fn run_editor(ctx: &Ctx, initial: &[u8], suffix: &str) -> Result<Vec<u8>, GitError> {
    let editor = resolve_editor(ctx).ok_or_else(|| GitError::Invalid {
        detail: "no editor configured (set GIT_EDITOR or core.editor)".to_owned(),
    })?;
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(GitError::Invalid {
            detail: "cannot run an interactive editor without a terminal".to_owned(),
        });
    }
    let nonce = EDIT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "ruk-edit-{}-{}{suffix}",
        std::process::id(),
        nonce
    ));
    std::fs::write(&path, initial).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", path.display()),
    })?;
    let mut parts = editor.split_whitespace();
    let program = parts.next().unwrap_or("false");
    let status = std::process::Command::new(program)
        .args(parts.collect::<Vec<_>>())
        .arg(&path)
        .status()
        .map_err(|err| GitError::Io {
            detail: format!("starting editor {editor:?}: {err}"),
        })?;
    if !status.success() {
        let _ = std::fs::remove_file(&path);
        return Err(GitError::Invalid {
            detail: format!("editor {editor:?} exited with {status}"),
        });
    }
    let edited = std::fs::read(&path).map_err(|err| GitError::Io {
        detail: format!("reading {}: {err}", path.display()),
    })?;
    let _ = std::fs::remove_file(&path);
    Ok(edited)
}

/// Edits a branch's `branch.<name>.description` in the configured editor.
///
/// Oracle: `git/builtin/branch.c` (`edit_branch_description`). With no
/// positional the current branch is edited; the branch must exist.
fn edit_branch_description(ctx: &mut Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let short = match opts.positionals.as_slice() {
        [] => current_branch_name(store)?
            .and_then(|full| {
                full.strip_prefix("refs/heads/")
                    .map(str::to_owned)
                    .or(Some(full))
            })
            .ok_or_else(|| GitError::Invalid {
                detail: "not on a branch".to_owned(),
            })?,
        [name] => name
            .strip_prefix("refs/heads/")
            .unwrap_or(name)
            .to_owned(),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: branch --edit-description [<branch>]".to_owned(),
            });
        }
    };
    if super::state::read_ref(store, &branch_name(&short)?)?.is_none() {
        return Err(GitError::NotFound {
            detail: format!("branch {short:?} does not exist"),
        });
    }
    let key = format!("branch.{short}.description");
    let initial = config_read(store, &key)?.unwrap_or_default();
    let edited = run_editor(ctx, initial.as_bytes(), ".md")?;
    config_write(store, &key, &String::from_utf8_lossy(&edited))?;
    Ok(Vec::new())
}

/// Writes a reflog creation entry for a new branch when `--create-reflog`
/// is given. Returns whether the write was skipped: without configured
/// identity there is no committer to record, so the caller names the skip
/// on stderr itself (this helper only holds `&Ctx`, keeping `Store`
/// borrows alive across the call).
fn maybe_create_reflog(
    ctx: &Ctx,
    name: &RefName,
    before: Option<RefTarget>,
    oid: Oid,
    message: String,
) -> Result<bool, GitError> {
    if super::state::identity(ctx, super::state::IdentityRole::Committer).is_err() {
        return Ok(true);
    }
    append_reflog(
        ctx,
        &[AppliedRef {
            name: name.clone(),
            before,
            after: Some(RefTarget::Direct(oid)),
        }],
        Some(message),
    )?;
    Ok(false)
}

/// Copies a branch ref, the way `git branch -c/-C` duplicates the ref and
/// its upstream config.
///
/// Oracle: `git/builtin/branch.c` (`copy_branch`).
fn copy_branch(ctx: &mut Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (old, new) = match opts.positionals.as_slice() {
        [new] => {
            let current = current_branch_name(store)?.ok_or_else(|| GitError::Invalid {
                detail: "not on a branch".to_owned(),
            })?;
            (current, new.clone())
        }
        [old, new] => {
            let full = if old.starts_with("refs/") {
                old.clone()
            } else {
                format!("refs/heads/{old}")
            };
            (full, new.clone())
        }
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: branch -c [<old>] <new>".to_owned(),
            });
        }
    };
    let old_name = RefName::new(old.clone()).map_err(|err| GitError::Invalid {
        detail: format!("bad branch name: {err}"),
    })?;
    let new_name = branch_name(&new)?;
    let target = super::state::read_ref(store, &old_name)?.ok_or_else(|| GitError::NotFound {
        detail: format!("branch {old:?} does not exist"),
    })?;
    if super::state::read_ref(store, &new_name)?.is_some() && !opts.is_set("force-copy") {
        return Err(GitError::Invalid {
            detail: format!("branch {new:?} already exists"),
        });
    }
    let force = opts.is_set("force-copy");
    let before = super::state::read_ref(store, &new_name)?;
    // Resolve symbolic targets so the creation log names an object even
    // when the copied ref itself is symbolic; unresolvable targets skip
    // the log rather than failing the copy.
    let copied_oid = peel_target_oid(ctx, &target)?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: new_name.clone(),
            expected: if force {
                RefExpect::Any
            } else {
                RefExpect::Absent
            },
            change: match target.clone() {
                RefTarget::Direct(oid) => RefChange::Set(RefTarget::Direct(oid)),
                RefTarget::Symbolic(name) => RefChange::Set(RefTarget::Symbolic(name)),
            },
        }],
    )?;
    // Copy the upstream config the way the oracle copies the branch config.
    let old_short = old
        .strip_prefix("refs/heads/")
        .unwrap_or(old.as_str())
        .to_owned();
    let new_short = new
        .strip_prefix("refs/heads/")
        .unwrap_or(new.as_str())
        .to_owned();
    for key in ["remote", "merge"] {
        let from = format!("branch.{old_short}.{key}");
        if let Some(value) = config_read(store, &from)? {
            config_write(store, &format!("branch.{new_short}.{key}"), &value)?;
        }
    }
    if opts.is_set("create-reflog") {
        if let Some(oid) = copied_oid {
            let skipped = maybe_create_reflog(
                ctx,
                &new_name,
                before,
                oid,
                format!("branch: Copied from {old}"),
            )?;
            if skipped {
                ctx.emit_stderr(b"warning: no identity configured; skipping reflog creation\n");
            }
        }
    }
    Ok(Vec::new())
}

/// Counts commits reachable from `tip` but not `base` and vice versa, the
/// `ahead`/`behind` pair `branch -vv` prints.
fn branch_ahead_behind(store: &Store, tip: Oid, base: Oid) -> Result<(usize, usize), GitError> {
    fn reachable(store: &Store, start: Oid) -> Result<std::collections::HashSet<Oid>, GitError> {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![start];
        while let Some(oid) = stack.pop() {
            if !seen.insert(oid) {
                continue;
            }
            let record = match super::state::commit_record(store, oid) {
                Ok(record) => record,
                Err(GitError::NotFound { .. }) => continue,
                Err(other) => return Err(other),
            };
            for parent in record.parents() {
                if let ruk_core::heads::Head::Git { oid } = parent {
                    stack.push(*oid);
                }
            }
        }
        Ok(seen)
    }
    let from_tip = reachable(store, tip)?;
    let from_base = reachable(store, base)?;
    Ok((
        from_tip.difference(&from_base).count(),
        from_base.difference(&from_tip).count(),
    ))
}

/// Names the upstream tracking ref for a local branch short name, if its
/// `branch.<name>.remote`/`branch.<name>.merge` config exists.
fn branch_upstream_ref(store: &Store, short: &str) -> Result<Option<(String, String)>, GitError> {
    let remote = config_read(store, &format!("branch.{short}.remote"))?;
    let merge = config_read(store, &format!("branch.{short}.merge"))?;
    match (remote, merge) {
        (Some(remote), Some(merge)) => {
            let branch_part = merge.strip_prefix("refs/heads/").unwrap_or(&merge);
            let full = if remote == "." {
                merge.clone()
            } else {
                format!("refs/remotes/{remote}/{branch_part}")
            };
            Ok(Some((full, remote)))
        }
        _ => Ok(None),
    }
}

/// Lists local branches, current marked, with optional remotes and oids.
fn list_branches(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let current = current_branch_name(store)?;
    let remotes_only = opts.is_set("remotes");
    let mut out = Vec::new();
    let mut branch_rows: Vec<(String, String, char, RefTarget)> = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        let is_branch = text.starts_with("refs/heads/");
        let is_remote = text.starts_with("refs/remotes/");
        let visible = if remotes_only {
            is_remote
        } else {
            is_branch || (opts.is_set("all") && is_remote)
        };
        if !visible {
            continue;
        }
        let short = text
            .trim_start_matches("refs/heads/")
            .trim_start_matches("refs/remotes/");
        if !opts.positionals.is_empty()
            && !opts
                .positionals
                .iter()
                .any(|want| glob_match(want, &text) || glob_match(want, short))
        {
            continue;
        }
        let mark = if Some(text.clone()) == current {
            '*'
        } else {
            ' '
        };
        // Defer rendering until filters/sort apply; collect first.
        branch_rows.push((text.clone(), short.to_owned(), mark, target.clone()));
    }
    // `--merged`/`--contains` family: resolve each commit once, then keep
    // only rows whose tip stands in the required ancestry relation.
    let resolve_filter = |values: Vec<String>| -> Result<Vec<Oid>, GitError> {
        let mut oids = Vec::with_capacity(values.len());
        for value in values {
            oids.push(resolve_rev(store, ctx.kind()?, &value)?);
        }
        Ok(oids)
    };
    let merged = resolve_filter(opts.all("merged")?)?;
    let no_merged = resolve_filter(opts.all("no-merged")?)?;
    let contains = resolve_filter(opts.all("contains")?)?;
    let no_contains = resolve_filter(opts.all("no-contains")?)?;
    let mut points_at: Vec<Oid> = Vec::new();
    for value in opts.all("points-at")? {
        points_at.push(resolve_rev(store, ctx.kind()?, &value)?);
    }
    let mut kept: Vec<(String, String, char, RefTarget)> = Vec::new();
    for (text, short, mark, target) in branch_rows {
        let tip = peel_direct(&target);
        if !points_at.is_empty() {
            let mut hit = false;
            if let Some(tip) = tip {
                if points_at.contains(&tip) {
                    hit = true;
                }
                // Annotated tags point at tag objects but read as commits.
                if !hit
                    && peel_target_oid(ctx, &target)?
                        .is_some_and(|peeled| points_at.contains(&peeled))
                {
                    hit = true;
                }
                if !hit
                    && peel_tag_target(ctx, &target)?
                        .is_some_and(|peeled| points_at.contains(&peeled))
                {
                    hit = true;
                }
            }
            if !hit {
                continue;
            }
        }
        // Ancestry filters need a concrete tip; symbolic/unborn rows cannot
        // satisfy them, so they drop out when any such filter is present.
        if !merged.is_empty()
            || !no_merged.is_empty()
            || !contains.is_empty()
            || !no_contains.is_empty()
        {
            let Some(tip) = tip else { continue };
            let mut ok = true;
            for base in &merged {
                if !is_ancestor(store, tip, *base).unwrap_or(false) && tip != *base {
                    ok = false;
                    break;
                }
            }
            for base in &no_merged {
                if is_ancestor(store, tip, *base).unwrap_or(false) || tip == *base {
                    ok = false;
                    break;
                }
            }
            for commit in &contains {
                if !is_ancestor(store, *commit, tip).unwrap_or(false) && tip != *commit {
                    ok = false;
                    break;
                }
            }
            for commit in &no_contains {
                if is_ancestor(store, *commit, tip).unwrap_or(false) || tip == *commit {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
        }
        kept.push((text, short, mark, target));
    }
    sort_branch_rows(ctx, &mut kept, &opts.all("sort")?)?;
    let abbrev = match opts.single("abbrev")? {
        Some(text) => Some(text.parse::<usize>().map_err(|_| GitError::Invalid {
            detail: format!("bad --abbrev value {text:?}"),
        })?),
        None => None,
    };
    let verbose = opts.count("verbose");
    if let Some(format) = opts.single("format")? {
        for (text, short, mark, target) in &kept {
            let row = BranchRow {
                full: text,
                short: short,
                mark: *mark,
                target,
            };
            out.extend_from_slice(&render_branch_format(ctx, &format, &row, abbrev)?);
        }
        return Ok(out);
    }
    for (text, short, mark, target) in &kept {
        if verbose == 0 {
            out.extend_from_slice(format!("{mark} {short}\n").as_bytes());
            continue;
        }
        let mut detail = ref_detail_abbrev(ctx, target, abbrev)?;
        if verbose >= 2 && text.starts_with("refs/heads/") {
            let local = text.trim_start_matches("refs/heads/");
            if let Some((upstream_full, _)) = branch_upstream_ref(store, local)? {
                let upstream_short = shorten_refname(&upstream_full);
                match super::state::read_ref(
                    store,
                    &RefName::new(upstream_full.clone()).map_err(|err| GitError::Invalid {
                        detail: format!("bad upstream ref: {err}"),
                    })?,
                )? {
                    None => {
                        detail.push_str(&format!(" [{upstream_short}: gone]"));
                    }
                    Some(upstream_target) => {
                        if let (Some(tip), Some(base)) =
                            (peel_direct(target), peel_direct(&upstream_target))
                        {
                            let (ahead, behind) =
                                branch_ahead_behind(store, tip, base).unwrap_or((0, 0));
                            let tracking = match (ahead, behind) {
                                (0, 0) => String::new(),
                                (a, 0) => format!(" [{upstream_short}: ahead {a}]"),
                                (0, b) => format!(" [{upstream_short}: behind {b}]"),
                                (a, b) => {
                                    format!(" [{upstream_short}: ahead {a}, behind {b}]")
                                }
                            };
                            detail.push_str(&tracking);
                        } else {
                            detail.push_str(&format!(" [{upstream_short}]"));
                        }
                    }
                }
            }
        }
        out.extend_from_slice(format!("{mark} {short} {detail}\n").as_bytes());
    }
    Ok(out)
}

/// Renders the oid and subject behind one listed ref target.
fn ref_detail(ctx: &Ctx, target: &RefTarget) -> Result<String, GitError> {
    let store = ctx.store()?;
    let oid = match target {
        RefTarget::Direct(oid) => *oid,
        RefTarget::Symbolic(name) => {
            let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), name)
                .map_err(|err| GitError::from(CoreError::from(err)))?;
            resolved.oid.ok_or_else(|| GitError::NotFound {
                detail: "symbolic ref points at an unborn branch".to_owned(),
            })?
        }
    };
    let records = ruk_core::records::Records::new(store);
    let subject = records
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .map(|record| first_message_line(record.message()))
        .unwrap_or_default();
    Ok(format!("{} {subject}", oid.to_hex()))
}

/// Renders the oid (abbreviated to `width` hex digits when given) and
/// subject behind one listed ref target.
fn ref_detail_abbrev(
    ctx: &Ctx,
    target: &RefTarget,
    width: Option<usize>,
) -> Result<String, GitError> {
    let store = ctx.store()?;
    let oid = match target {
        RefTarget::Direct(oid) => *oid,
        RefTarget::Symbolic(name) => {
            let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), name)
                .map_err(|err| GitError::from(CoreError::from(err)))?;
            resolved.oid.ok_or_else(|| GitError::NotFound {
                detail: "symbolic ref points at an unborn branch".to_owned(),
            })?
        }
    };
    let hex = oid.to_hex();
    let shown = match width {
        Some(n) => hex.chars().take(n).collect::<String>(),
        None => hex,
    };
    let records = ruk_core::records::Records::new(store);
    let subject = records
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .map(|record| first_message_line(record.message()))
        .unwrap_or_default();
    Ok(format!("{shown} {subject}"))
}

/// Sorts branch rows by `--sort` keys (`-` prefixes reverse), matching the
/// `for-each-ref` key set (`refname`, `objectname`, `objecttype`,
/// `authordate`, `committerdate`, `creatordate`).
fn sort_branch_rows(
    ctx: &Ctx,
    rows: &mut [(String, String, char, RefTarget)],
    keys: &[String],
) -> Result<(), GitError> {
    let mut parsed = Vec::with_capacity(keys.len());
    for key in keys {
        let (name, reverse) = key
            .strip_prefix('-')
            .map_or((key.as_str(), false), |rest| (rest, true));
        match name {
            "refname" | "objectname" | "objecttype" | "authordate" | "committerdate"
            | "creatordate" => parsed.push((name, reverse)),
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("unknown --sort key {key:?}"),
                });
            }
        }
    }
    if parsed.is_empty() {
        return Ok(());
    }
    let mut decorated = Vec::with_capacity(rows.len());
    for (text, _, _, target) in rows.iter() {
        let info = ref_commit_info(ctx, target)?;
        let oid = peel_target_oid(ctx, target)?
            .map(|oid| oid.to_hex())
            .unwrap_or_default();
        decorated.push((
            text.clone(),
            ref_object_type_or_empty(ctx, target)?,
            oid,
            info.as_ref().map(|info| info.author_ts).unwrap_or(0),
            info.as_ref().map(|info| info.committer_ts).unwrap_or(0),
        ));
    }
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&left, &right| {
        let (lname, ltype, loid, lauthor, lcommitter) = &decorated[left];
        let (rname, rtype, roid, rauthor, rcommitter) = &decorated[right];
        let mut verdict = std::cmp::Ordering::Equal;
        for (name, reverse) in &parsed {
            let next = match *name {
                "refname" => lname.cmp(rname),
                "objectname" => loid.cmp(roid),
                "objecttype" => ltype.cmp(rtype),
                "authordate" => lauthor.cmp(rauthor),
                _ => lcommitter.cmp(rcommitter),
            };
            if next != std::cmp::Ordering::Equal {
                verdict = if *reverse { next.reverse() } else { next };
                break;
            }
        }
        verdict
    });
    rows.sort_by(|_, _| std::cmp::Ordering::Equal);
    let mut sorted: Vec<(String, String, char, RefTarget)> = Vec::with_capacity(rows.len());
    for index in order {
        let (text, short, mark, target) = &rows[index];
        sorted.push((text.clone(), short.clone(), *mark, target.clone()));
    }
    rows.iter_mut().enumerate().for_each(|(i, row)| {
        let (text, short, mark, target) = &sorted[i];
        *row = (text.clone(), short.clone(), *mark, target.clone());
    });
    Ok(())
}

/// One branch row for `--format` rendering.
struct BranchRow<'a> {
    full: &'a str,
    short: &'a str,
    mark: char,
    target: &'a RefTarget,
}

/// Renders one branch row with `--format`: the `for-each-ref` atoms plus
/// `%(upstream)`, `%(upstream:short)`, and `%(HEAD)` (`*` on current).
fn render_branch_format(
    ctx: &Ctx,
    format: &str,
    row: &BranchRow<'_>,
    abbrev: Option<usize>,
) -> Result<Vec<u8>, GitError> {
    let full = row.full;
    let short = row.short;
    let mark = row.mark;
    let target = row.target;
    let store = ctx.store()?;
    let mut rendered = String::new();
    let mut rest = format;
    while let Some(start) = rest.find("%(") {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find(')').ok_or_else(|| GitError::Invalid {
            detail: "bad --format: missing )".to_owned(),
        })?;
        match &after[..end] {
            "refname" => rendered.push_str(full),
            "refname:short" => rendered.push_str(short),
            "objectname" => {
                let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("ref {full} is unborn"),
                })?;
                rendered.push_str(&oid.to_hex());
            }
            "objectname:short" => {
                let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("ref {full} is unborn"),
                })?;
                let hex = oid.to_hex();
                let width = abbrev.unwrap_or(7);
                rendered.push_str(&hex.chars().take(width).collect::<String>());
            }
            "objecttype" => rendered.push_str(&ref_object_type(ctx, target)?),
            "subject" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.subject).unwrap_or_default());
            }
            "authorname" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.author_name).unwrap_or_default());
            }
            "committername" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.committer_name).unwrap_or_default());
            }
            "creatordate" | "creatordate:iso" => {
                let info = ref_commit_info(ctx, target)?;
                if let Some(known) = info {
                    rendered.push_str(&iso_datetime(known.committer_ts, known.committer_offset));
                }
            }
            "upstream" => {
                if full.starts_with("refs/heads/") {
                    let local = full.trim_start_matches("refs/heads/");
                    if let Some((upstream_full, _)) = branch_upstream_ref(store, local)? {
                        rendered.push_str(&upstream_full);
                    }
                }
            }
            "upstream:short" => {
                if full.starts_with("refs/heads/") {
                    let local = full.trim_start_matches("refs/heads/");
                    if let Some((upstream_full, _)) = branch_upstream_ref(store, local)? {
                        rendered.push_str(shorten_refname(&upstream_full));
                    }
                }
            }
            "HEAD" => rendered.push(mark),
            other => {
                return Err(GitError::Invalid {
                    detail: format!("unsupported --format field %({other})"),
                });
            }
        }
        rest = &after[end + 1..];
    }
    rendered.push_str(rest);
    rendered.push('\n');
    Ok(rendered.into_bytes())
}

/// Takes the first message line for branch listings.
fn first_message_line(message: &[u8]) -> String {
    let end = message
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(message.len());
    String::from_utf8_lossy(&message[..end]).into_owned()
}

/// Matches `*` globs for branch and tag patterns.
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => {
            text.starts_with(head) && text.ends_with(tail) && head.len() + tail.len() <= text.len()
        }
    }
}

/// Reads the full ref name of the checked-out branch, if on one.
fn current_branch_name(store: &Store) -> Result<Option<String>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(name) => Ok(name.to_utf8().map(str::to_owned)),
        HeadRef::Detached(_) => Ok(None),
    }
}

/// Deletes branches, refusing unmerged work without force.
///
/// Oracle: `git/builtin/branch.c` (`delete_branches`).
fn delete_branches(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: branch -d <name>...".to_owned(),
        });
    }
    let current = current_branch_name(store)?;
    let head = head_oid(store).ok();
    let remote = opts.is_set("remotes");
    let mut out = Vec::new();
    for name in &opts.positionals {
        let refname = if remote {
            RefName::new(format!("refs/remotes/{name}")).map_err(|err| GitError::Invalid {
                detail: format!("bad branch name: {err}"),
            })?
        } else {
            branch_name(name)?
        };
        if !remote && Some(refname.to_utf8().unwrap_or_default().to_owned()) == current {
            return Err(GitError::Invalid {
                detail: format!("cannot delete the checked-out branch {name:?}"),
            });
        }
        let target =
            super::state::read_ref(store, &refname)?.ok_or_else(|| GitError::NotFound {
                detail: format!("branch {name:?} does not exist"),
            })?;
        if !opts.is_set("force-delete") {
            let target_oid = peel_direct(&target).ok_or_else(|| GitError::Invalid {
                detail: format!("branch {name:?} does not point at an object"),
            })?;
            let merged = head
                .map(|tip| is_ancestor(store, target_oid, tip))
                .transpose()?
                .unwrap_or(false);
            if !merged {
                return Err(GitError::Invalid {
                    detail: format!("branch {name:?} is not merged (use -D to force)"),
                });
            }
        }
        apply_refs(
            store,
            kind,
            vec![RefUpdate {
                name: refname,
                expected: RefExpect::Present(target),
                change: RefChange::Delete,
            }],
        )?;
        // Deleting a branch drops its config section the way the oracle
        // prunes `branch.<name>.*` with the ref.
        let short = name
            .trim_start_matches("refs/heads/")
            .trim_start_matches("refs/remotes/");
        for key in [
            format!("branch.{short}.remote"),
            format!("branch.{short}.merge"),
        ] {
            if config_read(store, &key)?.is_some() {
                config_unset(store, &key)?;
            }
        }
        if !opts.is_set("quiet") {
            out.extend_from_slice(format!("Deleted branch {name}\n").as_bytes());
        }
    }
    Ok(out)
}

/// Extracts the direct oid behind a ref target, if any.
fn peel_direct(target: &RefTarget) -> Option<Oid> {
    match target {
        RefTarget::Direct(oid) => Some(*oid),
        RefTarget::Symbolic(_) => None,
    }
}

/// Renames a branch, moving `HEAD` with it when current.
///
/// Oracle: `git/builtin/branch.c` (`rename_branch`).
fn rename_branch(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (old, rename_new) = match opts.positionals.as_slice() {
        [rename_new] => {
            let current = current_branch_name(store)?.ok_or_else(|| GitError::Invalid {
                detail: "not on a branch".to_owned(),
            })?;
            (current, rename_new.clone())
        }
        [old, rename_new] => {
            let full = if old.starts_with("refs/") {
                old.clone()
            } else {
                format!("refs/heads/{old}")
            };
            (full, rename_new.clone())
        }
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: branch -m [<old>] <new>".to_owned(),
            });
        }
    };
    let old_name = RefName::new(old.clone()).map_err(|err| GitError::Invalid {
        detail: format!("bad branch name: {err}"),
    })?;
    let new_name = branch_name(&rename_new)?;
    let target = super::state::read_ref(store, &old_name)?.ok_or_else(|| GitError::NotFound {
        detail: format!("branch {old:?} does not exist"),
    })?;
    if super::state::read_ref(store, &new_name)?.is_some() && !opts.is_set("force-move") {
        return Err(GitError::Invalid {
            detail: format!("branch {rename_new:?} already exists"),
        });
    }
    let force = opts.is_set("force-move");
    let mut updates = vec![RefUpdate {
        name: old_name.clone(),
        expected: RefExpect::Present(target.clone()),
        change: RefChange::Delete,
    }];
    updates.push(RefUpdate {
        name: new_name.clone(),
        expected: if force {
            RefExpect::Any
        } else {
            RefExpect::Absent
        },
        change: match target {
            RefTarget::Direct(oid) => RefChange::Set(RefTarget::Direct(oid)),
            RefTarget::Symbolic(name) => RefChange::Set(RefTarget::Symbolic(name)),
        },
    });
    apply_refs(store, kind, updates)?;
    let (workspace, raw) = load_or_default(store)?;
    if let HeadRef::Symbolic(current) = &workspace.head {
        if current == &old_name {
            let next = workspace.move_head(workspace.stamp, HeadRef::Symbolic(new_name))?;
            let mutation = workspace_mutation(raw.as_deref(), &next)?;
            store
                .publish(Vec::new(), &[mutation])
                .map_err(GitError::from)?;
        }
    }
    Ok(Vec::new())
}

/// Forces a branch to a target, creating or moving it.
fn force_branch(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    name: &str,
    target: Oid,
) -> Result<(), GitError> {
    let refname = branch_name(name)?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected: RefExpect::Any,
            change: RefChange::Set(RefTarget::Direct(target)),
        }],
    )?;
    Ok(())
}

/// Switches branches, detaches `HEAD`, or restores worktree paths.
///
/// Oracle: `git/builtin/checkout.c`.
pub(crate) fn checkout(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
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
            long: "detach",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        // Accepted for script compatibility: switches never print progress,
        // and worktree updates already overwrite, so both are satisfied.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "track",
            short: Some('t'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-track",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "orphan",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "merge",
            short: Some('m'),
            takes_value: false,
        },
        FlagSpec {
            long: "conflict",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "guess",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-guess",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "ours",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "theirs",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "source",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "staged",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "worktree",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "ignore-skip-worktree-bits",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "pathspec-from-file",
            short: None,
            takes_value: true,
        },
        // Accepted and inert: checkouts never report progress.
        FlagSpec {
            long: "progress",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-progress",
            short: None,
            takes_value: false,
        },
        // Accepted and inert: this store never refuses a checkout for
        // another worktree holding the branch.
        FlagSpec {
            long: "ignore-other-worktrees",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("patch") {
        return Err(GitError::Unsupported {
            command: "checkout --patch needs interactive hunk selection".to_owned(),
        });
    }
    if opts.single("pathspec-from-file")?.is_some() {
        return Err(GitError::Unsupported {
            command: "checkout --pathspec-from-file needs the pathspec-file lane".to_owned(),
        });
    }
    if opts.is_set("ignore-skip-worktree-bits") {
        return Err(GitError::Unsupported {
            command: "checkout --ignore-skip-worktree-bits needs skip-worktree handling".to_owned(),
        });
    }
    if let Some(style) = opts.single("conflict")? {
        match style.as_str() {
            "merge" | "diff3" | "zdiff3" => {}
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad --conflict value {style:?}"),
                });
            }
        }
        if !opts.is_set("merge") {
            return Err(GitError::Invalid {
                detail: "option --conflict requires --merge".to_owned(),
            });
        }
    }
    if let Some(orphan) = opts.single("orphan")? {
        if opts.single("branch")?.is_some() || opts.single("force-branch")?.is_some() {
            return Err(GitError::Invalid {
                detail: "cannot combine --orphan with -b/-B".to_owned(),
            });
        }
        if opts.is_set("track") {
            return Err(GitError::Invalid {
                detail: "'--orphan' cannot be used with '-t'".to_owned(),
            });
        }
        let start = opts.positionals.first().map(String::as_str);
        return checkout_orphan(ctx, &orphan, start, opts.is_set("quiet"));
    }
    if opts.is_set("track") && opts.is_set("no-track") {
        return Err(GitError::Invalid {
            detail: "cannot combine --track and --no-track".to_owned(),
        });
    }
    if opts.is_set("track") {
        return checkout_new_branch_tracked(ctx, &opts);
    }
    if opts.is_set("merge")
        && (opts.single("branch")?.is_some() || opts.single("force-branch")?.is_some())
    {
        let start = opts.positionals.first().map(String::as_str);
        switch_merge_guard(ctx, guard_tree_for(ctx, start)?)?;
    }
    if let Some(name) = opts.single("branch")? {
        let start = opts.positionals.first().map(String::as_str);
        let out = checkout_new_branch(ctx, &name, start, false, opts.is_set("quiet"))?;
        if start.is_some_and(|s| is_remote_start(s)) && !opts.is_set("no-track") {
            let Some(start) = start else {
                return Ok(out);
            };
            record_tracking(ctx.store()?, &name, start)?;
        }
        return Ok(out);
    }
    if let Some(name) = opts.single("force-branch")? {
        let start = opts.positionals.first().map(String::as_str);
        let out = checkout_new_branch(ctx, &name, start, true, opts.is_set("quiet"))?;
        if start.is_some_and(|s| is_remote_start(s)) && !opts.is_set("no-track") {
            let Some(start) = start else {
                return Ok(out);
            };
            record_tracking(ctx.store()?, &name, start)?;
        }
        return Ok(out);
    }
    if opts.is_set("ours") && opts.is_set("theirs") {
        return Err(GitError::Invalid {
            detail: "cannot combine --ours and --theirs".to_owned(),
        });
    }
    if (opts.is_set("ours") || opts.is_set("theirs"))
        && (opts.single("source")?.is_some()
            || opts.positionals.first().is_some_and(|first| {
                ctx.store()
                    .and_then(|store| ctx.kind().map(|kind| (store, kind)))
                    .is_ok_and(|(store, kind)| {
                        super::state::resolve_rev(store, kind, first).is_ok()
                    })
            }))
    {
        return Err(GitError::Invalid {
            detail: "cannot combine --ours/--theirs with a tree".to_owned(),
        });
    }
    // `collect` strips `--`, so a lone positional after `--` must read as a
    // path, not a revision to switch to.
    let saw_dashdash = args.iter().any(|arg| arg == "--");
    match opts.positionals.as_slice() {
        [] => {
            if opts.is_set("detach") {
                let tip = head_oid(ctx.store()?)?;
                return detach_at(ctx, tip);
            }
            Err(GitError::Invalid {
                detail: "usage: checkout [-b <new>] [<rev>]".to_owned(),
            })
        }
        [rev] => {
            if opts.is_set("detach") {
                let store = ctx.store()?;
                let tip = resolve_rev(store, ctx.kind()?, rev)?;
                return detach_at(ctx, tip);
            }
            if saw_dashdash {
                return checkout_paths(ctx, &opts);
            }
            if opts.is_set("staged")
                || opts.is_set("worktree")
                || opts.is_set("ours")
                || opts.is_set("theirs")
                || opts.single("source")?.is_some()
            {
                return checkout_paths(ctx, &opts);
            }
            // `--guess` is the default: a lone name matching one
            // remote-tracking branch creates it locally, like `switch`.
            // With `--merge` the guessed target is guarded inside
            // `switch_guessing`; a local branch is guarded here.
            if !opts.is_set("no-guess") {
                let store = ctx.store()?;
                if branch_name(rev).is_ok()
                    && super::state::read_ref(store, &branch_name(rev)?)?.is_none()
                    && guess_remote_branch(store, rev)?.is_some()
                {
                    return switch_guessing(
                        ctx,
                        rev,
                        true,
                        opts.is_set("quiet"),
                        !opts.is_set("no-track"),
                        opts.is_set("merge"),
                    );
                }
            }
            if opts.is_set("merge") {
                if let Ok(name) = branch_name(rev) {
                    let store = ctx.store()?;
                    if let Some(target) = super::state::read_ref(store, &name)? {
                        if let Some(tip) = peel_direct(&target) {
                            switch_merge_guard(ctx, tree_for_tip(ctx, tip)?)?;
                        }
                    }
                }
            }
            switch_to_rev(ctx, rev, opts.is_set("quiet"))
        }
        _ => checkout_paths(ctx, &opts),
    }
}

/// Checks out a new unborn branch: `HEAD` moves to it, the index keeps its
/// rows without a start point or takes the start tree with one, matching
/// `checkout --orphan [<start-point>]`.
fn checkout_orphan(
    ctx: &mut Ctx,
    name: &str,
    start: Option<&str>,
    quiet: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if super::state::read_ref(store, &branch_name(name)?)?.is_some() {
        return Err(GitError::Invalid {
            detail: format!("branch {name:?} already exists"),
        });
    }
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace.checkout(workspace.stamp, HeadRef::Symbolic(branch_name(name)?))?;
    let mut mutations = Vec::new();
    if let Some(start) = start {
        let oid = resolve_rev(store, kind, start)?;
        let tree = peel_to_tree(store, kind, oid)?;
        mutations.extend(reset_index_to(store, kind, tree)?);
    }
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    if start.is_some() {
        sync_worktree_to_index(ctx)?;
    }
    if !quiet {
        ctx.emit_stderr(format!("Switched to a new branch '{name}'\n").as_bytes());
    }
    Ok(Vec::new())
}

/// Creates and checks out a branch that tracks its start point, recording
/// `branch.<name>.remote`/`branch.<name>.merge` the way `--track` does.
fn checkout_new_branch_tracked(
    ctx: &mut Ctx,
    opts: &super::Collected,
) -> Result<Vec<u8>, GitError> {
    let branch = opts.single("branch")?;
    let force_branch = opts.single("force-branch")?;
    let (name, start, force) = match (branch, force_branch) {
        (Some(name), None) => (name, opts.positionals.first().map(String::as_str), false),
        (None, Some(name)) => (name, opts.positionals.first().map(String::as_str), true),
        (None, None) => {
            let [guess] = opts.positionals.as_slice() else {
                return Err(GitError::Invalid {
                    detail: "usage: checkout --track (-b <new> [<start>] | <remote>/<branch>)"
                        .to_owned(),
                });
            };
            let bare = guess.strip_prefix("refs/remotes/").unwrap_or(guess);
            let (_, short) = bare.split_once('/').ok_or_else(|| GitError::Invalid {
                detail: format!("cannot guess a local name from {guess:?}; pass -b <name>"),
            })?;
            (short.to_owned(), Some(guess.as_str()), false)
        }
        (Some(_), Some(_)) => {
            return Err(GitError::Invalid {
                detail: "cannot combine -b and -B".to_owned(),
            });
        }
    };
    let start = start.ok_or_else(|| GitError::Invalid {
        detail: "cannot set up tracking information; starting point is HEAD".to_owned(),
    })?;
    // Validate the upstream before creating anything, so a bad start point
    // leaves no half-made branch behind. Each store borrow ends before the
    // mutable branch creation below.
    parse_upstream(ctx.store()?, start)?;
    let quiet = opts.is_set("quiet");
    let out = checkout_new_branch(ctx, &name, Some(start), force, quiet)?;
    record_tracking(ctx.store()?, &name, start)?;
    Ok(out)
}

/// Records `branch.<name>.remote`/`branch.<name>.merge` for a start point.
fn record_tracking(store: &Store, name: &str, start: &str) -> Result<(), GitError> {
    let (remote, merge) = parse_upstream(store, start)?;
    config_write(store, &format!("branch.{name}.remote"), &remote)?;
    config_write(store, &format!("branch.{name}.merge"), &merge)?;
    Ok(())
}

/// Creates and checks out a branch from a start point, reporting the
/// switch on stderr like the oracle (`-q` hushes it).
fn checkout_new_branch(
    ctx: &mut Ctx,
    name: &str,
    start: Option<&str>,
    force: bool,
    quiet: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target = resolve_branch_target(store, kind, start)?;
    let refname = branch_name(name)?;
    let exists = super::state::read_ref(store, &refname)?.is_some();
    if exists && !force {
        return Err(GitError::Invalid {
            detail: format!("branch {name:?} already exists"),
        });
    }
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname.clone(),
            expected: if exists {
                RefExpect::Any
            } else {
                RefExpect::Absent
            },
            change: RefChange::Set(RefTarget::Direct(target)),
        }],
    )?;
    switch_head_to(ctx, HeadRef::Symbolic(refname))?;
    if !quiet {
        ctx.emit_stderr(format!("Switched to a new branch '{name}'\n").as_bytes());
    }
    Ok(Vec::new())
}

/// Switches `HEAD` to a branch or detaches at an object, reporting branch
/// switches on stderr like the oracle.
fn switch_to_rev(ctx: &mut Ctx, rev: &str, quiet: bool) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if let Ok(name) = branch_name(rev) {
        if super::state::read_ref(store, &name)?.is_some() {
            switch_head_to(ctx, HeadRef::Symbolic(name))?;
            if !quiet {
                ctx.emit_stderr(format!("Switched to branch '{rev}'\n").as_bytes());
            }
            return Ok(Vec::new());
        }
    }
    let oid = resolve_rev(store, kind, rev)?;
    detach_at(ctx, oid)
}

/// Moves `HEAD` to `head` and resets the index to its tree.
fn switch_head_to(ctx: &Ctx, head: HeadRef) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let tree = head_tree_of(store, &head)?;
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace.checkout(workspace.stamp, head)?;
    let mut mutations = reset_index_to(store, ctx.kind()?, tree)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    sync_worktree_to_index(ctx)?;
    Ok(Vec::new())
}

/// Detaches `HEAD` at one commit and resets the index to its tree.
fn detach_at(ctx: &Ctx, oid: Oid) -> Result<Vec<u8>, GitError> {
    super::state::commit_record(ctx.store()?, oid)?;
    switch_head_to(ctx, HeadRef::Detached(oid))
}

/// Reads the tree behind a `HEAD` value: born branches resolve, detached
/// heads read directly, unborn branches are the empty tree.
fn head_tree_of(store: &Store, head: &HeadRef) -> Result<Oid, GitError> {
    let kind = store.hash_kind();
    match super::state::resolve_head(store, head)? {
        super::state::ResolvedHead::Detached(oid) => {
            let record = super::state::commit_record(store, oid)?;
            commit_tree_oid(&record)
        }
        super::state::ResolvedHead::Symbolic(resolved) => match resolved.oid {
            Some(oid) => {
                let record = super::state::commit_record(store, oid)?;
                commit_tree_oid(&record)
            }
            None => kind
                .hash_git_object("tree", b"")
                .map_err(|err| GitError::from(CoreError::from(err))),
        },
    }
}

/// Restores paths from the index, a revision tree, or a conflict stage.
///
/// `--ours`/`--theirs` select stage 2/3 for unmerged paths; `--source`
/// names the tree explicitly; `--staged`/`--worktree` scope the restore to
/// the index and/or worktree (default: index and worktree from a tree,
/// worktree from the index).
fn checkout_paths(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut positionals = opts.positionals.as_slice();
    if positionals.first().is_some_and(|first| *first == "--") {
        positionals = &positionals[1..];
    }
    if positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "checkout needs paths".to_owned(),
        });
    }
    if let Some(want) = positionals.first() {
        if want == "--" {
            positionals = &positionals[1..];
        }
    }
    if positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "checkout needs paths".to_owned(),
        });
    }
    let conflict_stage = opts
        .is_set("ours")
        .then_some(Stage::Ours)
        .or(opts.is_set("theirs").then_some(Stage::Theirs));
    let explicit_source = opts.single("source")?;
    // With an explicit `--source` every positional is a path; otherwise a
    // leading revision followed by paths selects the tree, as before.
    let (tree_paths, source_tree) = if let Some(rev) = explicit_source {
        let oid = replace_redirect(store, resolve_rev(store, kind, &rev)?);
        (positionals, Some(peel_to_tree(store, kind, oid)?))
    } else if conflict_stage.is_some() {
        (positionals, None)
    } else {
        match positionals {
            [] => {
                return Err(GitError::Invalid {
                    detail: "checkout needs paths".to_owned(),
                });
            }
            [_single] => (positionals, None),
            [rev, rest @ ..] => match resolve_rev(store, kind, rev) {
                Ok(oid) => {
                    let oid = replace_redirect(store, oid);
                    (rest, Some(peel_to_tree(store, kind, oid)?))
                }
                Err(_) => (positionals, None),
            },
        }
    };
    if tree_paths.is_empty() {
        return Err(GitError::Invalid {
            detail: "checkout needs paths".to_owned(),
        });
    }
    // `--staged` without a tree restores the index from `HEAD`, not from
    // itself: without this the index write below would copy rows onto
    // themselves and change nothing.
    let source_tree = match (source_tree, conflict_stage) {
        (None, None) if opts.is_set("staged") => Some(head_tree_committed(ctx)?),
        (tree, _) => tree,
    };
    let staged_only = opts.is_set("staged") && !opts.is_set("worktree");
    let worktree_only = opts.is_set("worktree") && !opts.is_set("staged");
    if let Some(stage) = conflict_stage {
        return checkout_conflict_paths(ctx, tree_paths, stage, staged_only, worktree_only);
    }
    // `-m` on clean paths is vacuous: the restore below already carries
    // local state. Unmerged paths need real conflict recreation.
    if opts.is_set("merge") {
        for wanted in tree_paths {
            let path = super::verbs_stage::repo_path_of(ctx, wanted.as_bytes())?;
            let rows = read_path_rows(store, kind, &path)?;
            if rows.iter().any(|(stage, _, _)| *stage != Stage::Zero) {
                return Err(GitError::Unsupported {
                    command: "checkout -m with unmerged paths needs the merge lane".to_owned(),
                });
            }
        }
    }
    // Tree entries carry their own modes; index entries already hold
    // `FileMode`. The index map is built lazily: tree-sourced restores
    // never read it.
    let mut tree_entries = std::collections::BTreeMap::new();
    if let Some(tree) = source_tree {
        for (path, mode, oid) in flatten_tree(store, kind, tree)? {
            tree_entries.insert(path, (mode, oid));
        }
    }
    let index_entries = if source_tree.is_some() {
        std::collections::BTreeMap::new()
    } else {
        index_entry_map(ctx)?
    };
    // From a tree the oracle refreshes both index and worktree; from the
    // index only the worktree. Explicit `--staged`/`--worktree` narrow it.
    let update_index = source_tree.is_some() && !worktree_only || staged_only;
    let update_worktree = !staged_only;
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut worktree_writes: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    for wanted in tree_paths {
        let path = super::verbs_stage::repo_path_of(ctx, wanted.as_bytes())?;
        let (mode, oid) = match tree_entries.get(path.as_bytes()) {
            Some((mode, oid)) => (
                mode.as_index_mode()
                    .map_err(|err| GitError::from(CoreError::from(err)))?,
                *oid,
            ),
            None if source_tree.is_some() => {
                return Err(GitError::NotFound {
                    detail: format!("pathspec did not match: {wanted:?}"),
                });
            }
            None => {
                let (mode, oid) =
                    index_entries
                        .get(path.as_bytes())
                        .ok_or_else(|| GitError::NotFound {
                            detail: format!("pathspec did not match: {wanted:?}"),
                        })?;
                (*mode, *oid)
            }
        };
        let (_, body) = read_object_bytes(store, oid)?;
        if update_worktree {
            let full = super::tree::join_base(&ctx.file_base, path.as_bytes())?;
            worktree_writes.push((full, body.clone()));
        }
        if update_index {
            let before = read_path_rows(store, kind, &path)?;
            let entry = IndexEntry::new(oid, mode, None, IndexFlags::default())
                .map_err(|err| GitError::from(CoreError::from(err)))?;
            mutations.extend(path_row_mutations(&path, &before, &[(Stage::Zero, entry)])?);
        }
    }
    if !mutations.is_empty() {
        let next = workspace.mutate_index(workspace.stamp)?;
        mutations.push(workspace_mutation(raw.as_deref(), &next)?);
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    for (full, body) in worktree_writes {
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&full, body).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
    }
    Ok(Vec::new())
}

/// Restores unmerged paths from stage 2 (`--ours`) or stage 3 (`--theirs`),
/// writing stage zero plus the worktree unless scoped otherwise.
fn checkout_conflict_paths(
    ctx: &Ctx,
    paths: &[String],
    stage: Stage,
    staged_only: bool,
    worktree_only: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut worktree_writes: Vec<(std::path::PathBuf, Vec<u8>)> = Vec::new();
    for wanted in paths {
        let path = super::verbs_stage::repo_path_of(ctx, wanted.as_bytes())?;
        let rows = read_path_rows(store, kind, &path)?;
        let (_, entry, _) = rows
            .iter()
            .find(|(s, _, _)| *s == stage)
            .ok_or_else(|| GitError::Invalid {
                detail: format!("path {wanted:?} is not unmerged"),
            })?
            .clone();
        let (_, body) = read_object_bytes(store, entry.oid())?;
        if !staged_only {
            let full = super::tree::join_base(&ctx.file_base, path.as_bytes())?;
            worktree_writes.push((full, body));
        }
        if !worktree_only {
            let before = read_path_rows(store, kind, &path)?;
            let resolved = IndexEntry::new(entry.oid(), entry.mode(), None, IndexFlags::default())
                .map_err(|err| GitError::from(CoreError::from(err)))?;
            mutations.extend(path_row_mutations(
                &path,
                &before,
                &[(Stage::Zero, resolved)],
            )?);
        }
    }
    if !mutations.is_empty() {
        let next = workspace.mutate_index(workspace.stamp)?;
        mutations.push(workspace_mutation(raw.as_deref(), &next)?);
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    for (full, body) in worktree_writes {
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&full, body).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
    }
    Ok(Vec::new())
}

/// Maps every stage-zero index path to its mode and oid.
fn index_entry_map(
    ctx: &Ctx,
) -> Result<std::collections::BTreeMap<Vec<u8>, (ruk_core::index::FileMode, Oid)>, GitError> {
    let store = ctx.store()?;
    let mut map = std::collections::BTreeMap::new();
    for (path, stage, entry) in scan_index(store, ctx.kind()?)? {
        if stage == Stage::Zero {
            map.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    Ok(map)
}

/// Switches branches without the path form.
///
/// Oracle: `git/builtin/switch.c`.
pub(crate) fn switch(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "create",
            short: Some('c'),
            takes_value: true,
        },
        FlagSpec {
            long: "force-create",
            short: Some('C'),
            takes_value: true,
        },
        FlagSpec {
            long: "detach",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "guess",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-guess",
            short: None,
            takes_value: false,
        },
        // Accepted for script compatibility: switches never print progress,
        // and worktree updates already overwrite, so both are satisfied.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "discard-changes",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "orphan",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "track",
            short: Some('t'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-track",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "merge",
            short: Some('m'),
            takes_value: false,
        },
        FlagSpec {
            long: "conflict",
            short: None,
            takes_value: true,
        },
        // Accepted and inert: switches never report progress.
        FlagSpec {
            long: "progress",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-progress",
            short: None,
            takes_value: false,
        },
        // Accepted and inert: this store never refuses a switch for another
        // worktree holding the branch, so the override is already satisfied.
        FlagSpec {
            long: "ignore-other-worktrees",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if let Some(style) = opts.single("conflict")? {
        match style.as_str() {
            "merge" | "diff3" | "zdiff3" => {}
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad --conflict value {style:?}"),
                });
            }
        }
        if !opts.is_set("merge") {
            return Err(GitError::Invalid {
                detail: "option --conflict requires --merge".to_owned(),
            });
        }
    }
    if opts.is_set("track") && opts.is_set("no-track") {
        return Err(GitError::Invalid {
            detail: "cannot combine --track and --no-track".to_owned(),
        });
    }
    if let Some(orphan) = opts.single("orphan")? {
        if opts.single("create")?.is_some() || opts.single("force-create")?.is_some() {
            return Err(GitError::Invalid {
                detail: "cannot combine --orphan with -c/-C".to_owned(),
            });
        }
        if opts.is_set("track") {
            return Err(GitError::Invalid {
                detail: "'--orphan' cannot be used with '-t'".to_owned(),
            });
        }
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "switch --orphan takes no start point".to_owned(),
            });
        }
        return switch_orphan(ctx, &orphan, opts.is_set("quiet"));
    }
    // `--merge` refuses clobbering local work before any ref or file moves;
    // clean trees take the normal switch, whose result matches a true merge.
    if opts.is_set("merge")
        && (opts.single("create")?.is_some() || opts.single("force-create")?.is_some())
    {
        let start = opts.positionals.first().map(String::as_str);
        switch_merge_guard(ctx, guard_tree_for(ctx, start)?)?;
    }
    if let Some(name) = opts.single("create")? {
        let start = opts.positionals.first().map(String::as_str);
        let out = checkout_new_branch(ctx, &name, start, false, opts.is_set("quiet"))?;
        if opts.is_set("track") || (start.is_some_and(|s| is_remote_start(s)) && !opts.is_set("no-track")) {
            let Some(start) = start else {
                return Err(GitError::Invalid {
                    detail: "cannot set up tracking information; starting point is HEAD"
                        .to_owned(),
                });
            };
            record_tracking(ctx.store()?, &name, start)?;
        }
        return Ok(out);
    }
    if let Some(name) = opts.single("force-create")? {
        let start = opts.positionals.first().map(String::as_str);
        let out = checkout_new_branch(ctx, &name, start, true, opts.is_set("quiet"))?;
        if opts.is_set("track") || (start.is_some_and(|s| is_remote_start(s)) && !opts.is_set("no-track")) {
            let Some(start) = start else {
                return Err(GitError::Invalid {
                    detail: "cannot set up tracking information; starting point is HEAD"
                        .to_owned(),
                });
            };
            record_tracking(ctx.store()?, &name, start)?;
        }
        return Ok(out);
    }
    match opts.positionals.as_slice() {
        [] => {
            if opts.is_set("detach") {
                let tip = head_oid(ctx.store()?)?;
                return detach_at(ctx, tip);
            }
            Err(GitError::Invalid {
                detail: "usage: switch [-c <new>] [<branch>]".to_owned(),
            })
        }
        [branch] => {
            if opts.is_set("detach") {
                let store = ctx.store()?;
                let tip = resolve_rev(store, ctx.kind()?, branch)?;
                if opts.is_set("merge") {
                    let tree = peel_to_tree(store, ctx.kind()?, tip)?;
                    switch_merge_guard(ctx, tree)?;
                }
                return detach_at(ctx, tip);
            }
            switch_guessing(
                ctx,
                branch,
                !opts.is_set("no-guess"),
                opts.is_set("quiet"),
                !opts.is_set("no-track"),
                opts.is_set("merge"),
            )
        }
        _ => Err(GitError::Invalid {
            detail: "usage: switch [-c <new>] [<branch>]".to_owned(),
        }),
    }
}

/// Reports whether a start point names a remote-tracking branch, for
/// automatic `--track` setup.
fn is_remote_start(start: &str) -> bool {
    let bare = start.strip_prefix("refs/remotes/").unwrap_or(start);
    bare.contains('/')
}

/// Switches to a new unborn branch, clearing the index and tracked files
/// the way `switch --orphan` starts from the empty tree.
fn switch_orphan(ctx: &mut Ctx, name: &str, quiet: bool) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if super::state::read_ref(store, &branch_name(name)?)?.is_some() {
        return Err(GitError::Invalid {
            detail: format!("branch {name:?} already exists"),
        });
    }
    // The empty tree hashes without existing: store it so the index reset
    // below can read it back.
    let empty = store_object(store, ruk_core::store::ObjectKind::Tree, Vec::new())?;
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace.checkout(workspace.stamp, HeadRef::Symbolic(branch_name(name)?))?;
    let mut mutations = reset_index_to(store, kind, empty)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    sync_worktree_to_index(ctx)?;
    if !quiet {
        ctx.emit_stderr(format!("Switched to a new branch '{name}'\n").as_bytes());
    }
    Ok(Vec::new())
}

/// Resolves one commit oid to its tree for switch guards.
fn tree_for_tip(ctx: &Ctx, tip: Oid) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    match super::state::commit_record(store, tip) {
        Ok(record) => commit_tree_oid(&record),
        Err(_) => peel_to_tree(store, ctx.kind()?, tip),
    }
}

/// Switches to a branch, guessing a remote-tracking start when missing,
/// reporting the switch on stderr like the oracle.
fn switch_guessing(
    ctx: &mut Ctx,
    branch: &str,
    guess: bool,
    quiet: bool,
    track: bool,
    merge: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if let Ok(name) = branch_name(branch) {
        if super::state::read_ref(store, &name)?.is_some() {
            if merge {
                let tip = super::state::read_ref(store, &name)?
                    .and_then(|target| peel_direct(&target));
                if let Some(tip) = tip {
                    switch_merge_guard(ctx, tree_for_tip(ctx, tip)?)?;
                }
            }
            switch_head_to(ctx, HeadRef::Symbolic(name))?;
            if !quiet {
                ctx.emit_stderr(format!("Switched to branch '{branch}'\n").as_bytes());
            }
            return Ok(Vec::new());
        }
    }
    if guess {
        if let Some(tracked) = guess_remote_branch(store, branch)? {
            let target = super::state::read_ref(store, &tracked)?.and_then(|target| match target {
                RefTarget::Direct(oid) => Some(oid),
                RefTarget::Symbolic(_) => None,
            });
            if let Some(target) = target {
                if merge {
                    switch_merge_guard(ctx, tree_for_tip(ctx, target)?)?;
                }
                create_branch(store, kind, branch, target)?;
                if track {
                    let remote = tracked.to_utf8().unwrap_or_default().to_owned();
                    record_tracking(store, branch, &remote)?;
                }
                switch_head_to(ctx, HeadRef::Symbolic(branch_name(branch)?))?;
                if !quiet {
                    ctx.emit_stderr(format!("Switched to branch '{branch}'\n").as_bytes());
                }
                return Ok(Vec::new());
            }
        }
    }
    Err(GitError::NotFound {
        detail: format!("branch {branch:?} does not exist"),
    })
}

/// Finds the unique remote-tracking branch for a guessed switch.
fn guess_remote_branch(store: &Store, branch: &str) -> Result<Option<RefName>, GitError> {
    let suffix = format!("/{branch}").into_bytes();
    let mut found = None;
    for (name, _) in list_refs(store)? {
        if name.as_bytes().starts_with(b"refs/remotes/") && name.as_bytes().ends_with(&suffix) {
            if found.is_some() {
                return Ok(None);
            }
            found = Some(name);
        }
    }
    Ok(found)
}

/// Restores worktree files and staged entries.
///
/// Oracle: `git/builtin/restore.c`.
pub(crate) fn restore(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "staged",
            short: Some('S'),
            takes_value: false,
        },
        FlagSpec {
            long: "worktree",
            short: Some('W'),
            takes_value: false,
        },
        FlagSpec {
            long: "source",
            short: Some('s'),
            takes_value: true,
        },
        // Accepted for script compatibility: restores print nothing already.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: restore [--staged] [--worktree] [--source=<rev>] <path>...".to_owned(),
        });
    }
    let staged = opts.is_set("staged");
    let worktree = opts.is_set("worktree") || !staged;
    if staged {
        let tree = match opts.single("source")? {
            Some(rev) => {
                let oid = resolve_rev(store, kind, &rev)?;
                peel_to_tree(store, kind, oid)?
            }
            None => head_tree_committed(ctx)?,
        };
        restore_staged(ctx, &opts, tree)?;
    }
    if worktree {
        restore_worktree(ctx, &opts)?;
    }
    Ok(Vec::new())
}

/// Reads the committed `HEAD` tree, refusing an unborn branch for staged
/// restores the way Git refuses a missing source.
fn head_tree_committed(ctx: &Ctx) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let tip = head_oid(store)?;
    let record = super::state::commit_record(store, tip)?;
    commit_tree_oid(&record)
}

/// Resets staged rows for the named paths to one tree.
fn restore_staged(ctx: &Ctx, opts: &super::Collected, tree: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut target = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        target.insert(path, (mode, oid));
    }
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    for positional in &opts.positionals {
        let path = super::verbs_stage::repo_path_of(ctx, positional.as_bytes())?;
        let before = read_path_rows(store, kind, &path)?;
        let after = target
            .get(path.as_bytes())
            .map(|(mode, oid)| {
                IndexEntry::new(*oid, mode.as_index_mode()?, None, IndexFlags::default())
                    .map_err(|err| GitError::from(CoreError::from(err)))
            })
            .transpose()?
            .map(|entry| vec![(Stage::Zero, entry)])
            .unwrap_or_default();
        mutations.extend(path_row_mutations(&path, &before, &after)?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Rewrites worktree files for the named paths from the index or a source.
fn restore_worktree(ctx: &Ctx, opts: &super::Collected) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entries = match opts.single("source")? {
        Some(rev) => {
            let oid = resolve_rev(store, kind, &rev)?;
            let tree = peel_to_tree(store, kind, oid)?;
            let mut map = std::collections::BTreeMap::new();
            for (path, _, oid) in flatten_tree(store, kind, tree)? {
                map.insert(path, oid);
            }
            map
        }
        None => {
            let mut map = std::collections::BTreeMap::new();
            for (path, (_, oid)) in index_entry_map(ctx)? {
                map.insert(path, oid);
            }
            map
        }
    };
    for positional in &opts.positionals {
        let path = super::verbs_stage::repo_path_of(ctx, positional.as_bytes())?;
        let oid = entries
            .get(path.as_bytes())
            .ok_or_else(|| GitError::NotFound {
                detail: format!("pathspec did not match: {positional:?}"),
            })?;
        let (_, body) = read_object_bytes(store, *oid)?;
        let full = join_base(&ctx.file_base, path.as_bytes())?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&full, body).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
    }
    Ok(())
}

/// Resets `HEAD`, the index, and optionally the worktree.
///
/// Oracle: `git/builtin/reset.c`.
pub(crate) fn reset(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "soft",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "mixed",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "hard",
            short: None,
            takes_value: false,
        },
        // Accepted for script compatibility: resets print nothing already.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "merge",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "keep",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "intent-to-add",
            short: Some('N'),
            takes_value: false,
        },
        // Accepted and inert: this store keeps no stat cache, so there is no
        // index refresh to skip after a mixed reset.
        FlagSpec {
            long: "no-refresh",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "pathspec-from-file",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("patch") {
        return Err(GitError::Unsupported {
            command: "reset --patch needs interactive hunk selection".to_owned(),
        });
    }
    if opts.single("pathspec-from-file")?.is_some() {
        return Err(GitError::Unsupported {
            command: "reset --pathspec-from-file needs the pathspec-file lane".to_owned(),
        });
    }
    if opts.is_set("merge") {
        return Err(GitError::Unsupported {
            command: "reset --merge needs the three-way merge lane".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    // `collect` strips `--`, so count the raw argv tokens after it: when
    // every positional follows `--` the whole list is paths, and a revision
    // is only taken when a positional precedes the separator.
    let paths_after = args
        .iter()
        .position(|arg| arg == "--")
        .map_or(0, |at| args.len() - at - 1);
    let positionals = opts.positionals.as_slice();
    let (rev, paths): (Option<String>, &[String]) = match positionals {
        [] => (None, &[]),
        _ if paths_after == positionals.len() => (None, positionals),
        [single] => (Some(single.clone()), &[]),
        [first, rest @ ..] => (Some(first.clone()), rest),
    };
    if !paths.is_empty() {
        if opts.is_set("soft") || opts.is_set("hard") {
            return Err(GitError::Invalid {
                detail: "Cannot do soft or hard reset with paths.".to_owned(),
            });
        }
        let tree = match rev {
            Some(rev) => {
                let oid = resolve_rev(store, kind, &rev)?;
                peel_to_tree(store, kind, oid)?
            }
            None => head_tree_committed(ctx)?,
        };
        if opts.is_set("intent-to-add") {
            return reset_paths_intent(ctx, paths, tree).map(|()| Vec::new());
        }
        let pseudo = super::Collected {
            present: Default::default(),
            positionals: paths.to_vec(),
        };
        return restore_staged(ctx, &pseudo, tree).map(|()| Vec::new());
    }
    if opts.is_set("intent-to-add") && (opts.is_set("soft") || opts.is_set("hard")) {
        return Err(GitError::Invalid {
            detail: "the option '-N' requires '--mixed'".to_owned(),
        });
    }
    let target = match rev {
        Some(rev) => resolve_rev(store, kind, &rev)?,
        None => head_oid(store)?,
    };
    let modes = [
        opts.is_set("soft"),
        opts.is_set("mixed"),
        opts.is_set("hard"),
        opts.is_set("keep"),
    ];
    if modes.iter().filter(|set| **set).count() > 1 {
        return Err(GitError::Invalid {
            detail: "reset takes at most one of --soft, --mixed, --hard, --keep".to_owned(),
        });
    }
    // `--keep` guards before moving anything: differing paths with staged
    // or worktree changes refuse instead of clobbering.
    if opts.is_set("keep") {
        let quiet = opts.is_set("quiet");
        return reset_keep(ctx, target, quiet);
    }
    move_branch_to(ctx, target)?;
    let quiet = opts.is_set("quiet");
    if opts.is_set("soft") {
        return Ok(Vec::new());
    }
    let record = super::state::commit_record(store, target)?;
    let tree = commit_tree_oid(&record)?;
    reset_index_tree(ctx, tree)?;
    if opts.is_set("hard") {
        sync_worktree_to_index(ctx)?;
        if quiet {
            return Ok(Vec::new());
        }
        return Ok(reset_head_line(&record, target));
    }
    if quiet {
        return Ok(Vec::new());
    }
    reset_unstaged_report(ctx, store, kind)
}

/// Resets named paths to `tree`, recording intent-to-add entries where the
/// tree lacks the path instead of deleting the row.
fn reset_paths_intent(ctx: &Ctx, paths: &[String], tree: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut target = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        target.insert(path, (mode, oid));
    }
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    for wanted in paths {
        let path = super::verbs_stage::repo_path_of(ctx, wanted.as_bytes())?;
        let before = read_path_rows(store, kind, &path)?;
        let after = match target.get(path.as_bytes()) {
            Some((mode, oid)) => {
                let entry =
                    IndexEntry::new(*oid, mode.as_index_mode()?, None, IndexFlags::default())
                        .map_err(|err| GitError::from(CoreError::from(err)))?;
                vec![(Stage::Zero, entry)]
            }
            None => {
                let entry = IndexEntry::intent_to_add(kind, FileMode::Regular, None)
                    .map_err(|err| GitError::from(CoreError::from(err)))?;
                vec![(Stage::Zero, entry)]
            }
        };
        mutations.extend(path_row_mutations(&path, &before, &after)?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Names every differing path whose staged rows or worktree bytes diverge
/// from the old tree: staged deletions/additions, non-zero stages, and
/// edited or newly present worktree files. Callers refuse these instead of
/// clobbering local work.
fn merge_blocked_paths(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    old_map: &std::collections::BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    differing: &[Vec<u8>],
) -> Result<Vec<String>, GitError> {
    let rows = scan_index(store, kind)?;
    let mut staged_by_path: std::collections::BTreeMap<Vec<u8>, Vec<(Stage, IndexEntry)>> =
        std::collections::BTreeMap::new();
    for (path, stage, entry) in &rows {
        staged_by_path
            .entry(path.as_bytes().to_vec())
            .or_default()
            .push((*stage, entry.clone()));
    }
    let mut blocked: Vec<String> = Vec::new();
    for path in differing {
        let clean_staged = match (old_map.get(path), staged_by_path.get(path)) {
            (Some((mode, oid)), Some(stages)) => {
                stages.len() == 1
                    && stages[0].0 == Stage::Zero
                    && stages[0].1.oid() == *oid
                    && stages[0].1.mode() == mode.as_index_mode().unwrap_or(FileMode::Regular)
            }
            // A missing index row where the old tree names one is a staged
            // deletion; a present row where it names none is a staged
            // addition. Both refuse instead of clobbering.
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
        };
        if !clean_staged {
            blocked.push(String::from_utf8_lossy(path).into_owned());
            continue;
        }
        // Worktree check: differing paths must still hold old bytes.
        let full = super::tree::join_base(&ctx.file_base, path)?;
        let worktree_bytes = std::fs::read(&full).ok();
        match old_map.get(path) {
            Some((_, oid)) => {
                let (_, old_body) = read_object_bytes(store, *oid)?;
                match worktree_bytes {
                    Some(have) if have == old_body => {}
                    _ => blocked.push(String::from_utf8_lossy(path).into_owned()),
                }
            }
            None => {
                if worktree_bytes.is_some() {
                    blocked.push(String::from_utf8_lossy(path).into_owned());
                }
            }
        }
    }
    Ok(blocked)
}

/// Guards a merging branch switch (`switch -m`, `checkout -m <rev>`): paths
/// differing between the current `HEAD` tree and `new_tree` that carry
/// staged or worktree edits refuse before anything moves. Clean trees pass
/// through to the normal switch, whose result then matches a true merge.
fn switch_merge_guard(ctx: &Ctx, new_tree: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let old_map = match head_oid(store) {
        Ok(tip) => {
            let record = super::state::commit_record(store, tip)?;
            let old_tree = commit_tree_oid(&record)?;
            let mut map = std::collections::BTreeMap::new();
            for (path, mode, oid) in flatten_tree(store, kind, old_tree)? {
                map.insert(path, (mode, oid));
            }
            map
        }
        // Unborn `HEAD` has no old blobs: every new path is differing.
        Err(_) => std::collections::BTreeMap::new(),
    };
    let mut new_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, new_tree)? {
        new_map.insert(path, (mode, oid));
    }
    let mut differing: Vec<Vec<u8>> = Vec::new();
    for path in old_map.keys().chain(new_map.keys()) {
        if old_map.get(path) != new_map.get(path) && !differing.contains(path) {
            differing.push(path.clone());
        }
    }
    let mut blocked = merge_blocked_paths(ctx, store, kind, &old_map, &differing)?;
    if blocked.is_empty() {
        return Ok(());
    }
    blocked.sort();
    Err(GitError::Invalid {
        detail: format!(
            "local changes would be overwritten by switch: {}",
            blocked.join(", ")
        ),
    })
}

/// Resolves a start point to its tree for merge-guard purposes, peeling
/// non-commit targets the way path restores do.
fn guard_tree_for(ctx: &Ctx, rev: Option<&str>) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = resolve_branch_target(store, kind, rev)?;
    match super::state::commit_record(store, oid) {
        Ok(record) => commit_tree_oid(&record),
        Err(_) => peel_to_tree(store, kind, oid),
    }
}

/// Resets `HEAD` and the index to `target` while keeping local changes:
/// paths differing between old and new trees with staged or worktree edits
/// refuse before anything moves; otherwise only differing paths touch the
/// worktree so unrelated edits stay.
fn reset_keep(ctx: &Ctx, target: Oid, quiet: bool) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let old_tip = head_oid(store)?;
    let old_record = super::state::commit_record(store, old_tip)?;
    let old_tree = commit_tree_oid(&old_record)?;
    let new_record = super::state::commit_record(store, target)?;
    let new_tree = commit_tree_oid(&new_record)?;
    let mut old_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, old_tree)? {
        old_map.insert(path, (mode, oid));
    }
    let mut new_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, new_tree)? {
        new_map.insert(path, (mode, oid));
    }
    let mut union: Vec<Vec<u8>> = old_map.keys().cloned().collect();
    for path in new_map.keys() {
        if !union.contains(path) {
            union.push(path.clone());
        }
    }
    let mut differing: Vec<Vec<u8>> = Vec::new();
    for path in &union {
        if old_map.get(path) != new_map.get(path) {
            differing.push(path.clone());
        }
    }
    let mut blocked = merge_blocked_paths(ctx, store, kind, &old_map, &differing)?;
    if !blocked.is_empty() {
        blocked.sort();
        return Err(GitError::Invalid {
            detail: format!(
                "local changes would be overwritten by reset --keep: {}",
                blocked.join(", ")
            ),
        });
    }
    move_branch_to(ctx, target)?;
    // Scoped index reset: only differing paths take the new tree's rows, so
    // staged edits on unrelated paths stay exactly as they were.
    let (workspace, raw) = load_or_default(store)?;
    let mut index_mutations = Vec::new();
    for path in &differing {
        let repo_path =
            RepoPath::new(path.clone()).map_err(|err| GitError::from(CoreError::from(err)))?;
        let before = read_path_rows(store, kind, &repo_path)?;
        let after = match new_map.get(path) {
            Some((mode, oid)) => {
                let entry =
                    IndexEntry::new(*oid, mode.as_index_mode()?, None, IndexFlags::default())
                        .map_err(|err| GitError::from(CoreError::from(err)))?;
                vec![(Stage::Zero, entry)]
            }
            None => Vec::new(),
        };
        index_mutations.extend(path_row_mutations(&repo_path, &before, &after)?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    index_mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &index_mutations)
        .map_err(GitError::from)?;
    // Scoped worktree sync: only differing paths are rewritten.
    for path in &differing {
        match new_map.get(path) {
            Some((_, oid)) => {
                let (_, body) = read_object_bytes(store, *oid)?;
                let full = super::tree::join_base(&ctx.file_base, path)?;
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                        detail: format!("creating {}: {err}", parent.display()),
                    })?;
                }
                std::fs::write(&full, body).map_err(|err| GitError::Io {
                    detail: format!("writing {}: {err}", full.display()),
                })?;
            }
            None => {
                let full = super::tree::join_base(&ctx.file_base, path)?;
                if full.is_file() {
                    std::fs::remove_file(&full).map_err(|err| GitError::Io {
                        detail: format!("removing {}: {err}", full.display()),
                    })?;
                }
            }
        }
    }
    if quiet {
        return Ok(Vec::new());
    }
    Ok(reset_head_line(&new_record, target))
}

/// Renders `HEAD is now at <short> <subject>` after a hard reset.
fn reset_head_line(record: &CommitRecord, target: Oid) -> Vec<u8> {
    let message = record.message();
    let end = message
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(message.len());
    format!(
        "HEAD is now at {} {}\n",
        target.to_hex().chars().take(7).collect::<String>(),
        String::from_utf8_lossy(&message[..end])
    )
    .into_bytes()
}

/// Renders `Unstaged changes after reset:` plus worktree differences when
/// a mixed reset leaves any, silent otherwise like the oracle.
fn reset_unstaged_report(ctx: &Ctx, store: &Store, kind: HashKind) -> Result<Vec<u8>, GitError> {
    let plan = super::verbs_stage::status_plan(ctx, store, kind)?;
    if plan.unstaged.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::from(b"Unstaged changes after reset:\n".as_slice());
    for (path, code) in &plan.unstaged {
        out.extend_from_slice(format!("{code}\t{}\n", String::from_utf8_lossy(path)).as_bytes());
    }
    Ok(out)
}

/// Moves the current branch tip (or detaches state) to `target`.
pub(crate) fn move_branch_to(ctx: &Ctx, target: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (workspace, raw) = load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => {
            let before = super::state::read_ref(store, name)?;
            let expected = before.map(RefExpect::Present).unwrap_or(RefExpect::Absent);
            apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: name.clone(),
                    expected,
                    change: RefChange::Set(RefTarget::Direct(target)),
                }],
            )?;
            let _ = raw;
            Ok(())
        }
        HeadRef::Detached(_) => {
            let next = workspace.move_head(workspace.stamp, HeadRef::Detached(target))?;
            let mutation = workspace_mutation(raw.as_deref(), &next)?;
            store
                .publish(Vec::new(), &[mutation])
                .map_err(GitError::from)?;
            Ok(())
        }
    }
}

/// Resets the whole index to one tree without moving `HEAD`.
pub(crate) fn reset_index_tree(ctx: &Ctx, tree: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = reset_index_to(store, kind, tree)?;
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Builds index-reset mutations toward one tree for checkout-style verbs.
pub(crate) fn reset_index_to(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    tree: Oid,
) -> Result<Vec<FactMutation>, GitError> {
    let mut target = std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        target.insert(path, (mode, oid));
    }
    let rows = scan_index(store, kind)?;
    let mut union: Vec<RepoPath> = Vec::new();
    for (path, _, _) in &rows {
        if !union.contains(path) {
            union.push(path.clone());
        }
    }
    for path in target.keys() {
        let candidate =
            RepoPath::new(path.clone()).map_err(|err| GitError::from(CoreError::from(err)))?;
        if !union.contains(&candidate) {
            union.push(candidate);
        }
    }
    let mut mutations = Vec::new();
    for path in union {
        let before_real = read_path_rows(store, kind, &path)?;
        let after = target
            .get(path.as_bytes())
            .map(|(mode, oid)| {
                IndexEntry::new(*oid, mode.as_index_mode()?, None, IndexFlags::default())
                    .map_err(|err| GitError::from(CoreError::from(err)))
            })
            .transpose()?
            .map(|entry| vec![(Stage::Zero, entry)])
            .unwrap_or_default();
        mutations.extend(path_row_mutations(&path, &before_real, &after)?);
    }
    Ok(mutations)
}

/// Rewrites worktree files to match the current index, deleting tracked
/// files the index no longer names. Untracked files are never touched.
pub(crate) fn sync_worktree_to_index(ctx: &Ctx) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut wanted: std::collections::BTreeMap<Vec<u8>, (ruk_core::index::FileMode, Oid)> =
        std::collections::BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            wanted.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    for (path, (mode, oid)) in &wanted {
        let full = join_base(&ctx.file_base, path)?;
        if *mode == ruk_core::index::FileMode::Gitlink {
            continue;
        }
        if *mode == ruk_core::index::FileMode::Symlink {
            create_worktree_link(store, *oid, &full)?;
            continue;
        }
        let (_, body) = read_object_bytes(store, *oid)?;
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                detail: format!("creating {}: {err}", parent.display()),
            })?;
        }
        std::fs::write(&full, body).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
        #[cfg(unix)]
        if *mode == ruk_core::index::FileMode::Executable {
            use std::os::unix::fs::PermissionsExt as _;
            let permissions = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&full, permissions).map_err(|err| GitError::Io {
                detail: format!("chmod {}: {err}", full.display()),
            })?;
        }
    }
    let walked = super::tree::walk_worktree(&ctx.file_base)?;
    for entry in walked {
        if entry.file_type == WorktreeType::Symlink {
            continue;
        }
        if !wanted.contains_key(&entry.path) {
            let full = join_base(&ctx.file_base, &entry.path)?;
            std::fs::remove_file(&full).map_err(|err| GitError::Io {
                detail: format!("removing {}: {err}", full.display()),
            })?;
        }
    }
    Ok(())
}

/// Creates one worktree symlink from its recorded target blob.
#[cfg(unix)]
fn create_worktree_link(store: &Store, oid: Oid, full: &std::path::Path) -> Result<(), GitError> {
    let (_, body) = read_object_bytes(store, oid)?;
    let text = std::str::from_utf8(&body).map_err(|_| GitError::Invalid {
        detail: "symlink target is not valid UTF-8".to_owned(),
    })?;
    if full.is_symlink() || full.exists() {
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

/// Refuses worktree links where the platform cannot make them.
#[cfg(not(unix))]
fn create_worktree_link(
    _store: &Store,
    _oid: Oid,
    _full: &std::path::Path,
) -> Result<(), GitError> {
    Err(GitError::Unsupported {
        command: "checkout of symlinks on this platform".to_owned(),
    })
}

/// Updates one ref through a checked transaction, with an optional reflog.
///
/// Oracle: `git/builtin/update-ref.c`.
pub(crate) fn update_ref(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-deref",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "z",
            short: Some('z'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let _ = opts.is_set("no-deref");
    if opts.is_set("stdin") {
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: update-ref --stdin [-z] [-m <msg>]".to_owned(),
            });
        }
        return update_ref_stdin(ctx, &opts);
    }
    if opts.is_set("delete") {
        let (name, old) = match opts.positionals.as_slice() {
            [name] => (name.clone(), None),
            [name, old] => (name.clone(), Some(old.clone())),
            _ => {
                return Err(GitError::Invalid {
                    detail: "usage: update-ref -d <ref> [<old>]".to_owned(),
                });
            }
        };
        return delete_ref_logged(ctx, &name, old, opts.single("message")?);
    }
    let (name, value, old) = match opts.positionals.as_slice() {
        [name, value] => (name.clone(), value.clone(), None),
        [name, value, old] => (name.clone(), value.clone(), Some(old.clone())),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: update-ref [-m <msg>] <ref> <new> [<old>]".to_owned(),
            });
        }
    };
    let refname = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })?;
    let zero = kind.zero_oid().to_hex();
    let new_oid = ruk_git::parse_oid_for(&value, kind)?;
    // A zero new value deletes the ref, and a zero old value means the ref
    // must not exist, the way the oracle treats the all-zero object id.
    let change = if value == zero {
        RefChange::Delete
    } else {
        RefChange::Set(RefTarget::Direct(new_oid))
    };
    let expected = match old {
        Some(hex) if hex == zero => RefExpect::Absent,
        Some(hex) => {
            let oid = ruk_git::parse_oid_for(&hex, kind)?;
            RefExpect::Present(RefTarget::Direct(oid))
        }
        None => RefExpect::Any,
    };
    let applied = apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected,
            change,
        }],
    )?;
    append_reflog(ctx, &applied, opts.single("message")?)?;
    Ok(Vec::new())
}

/// Applies a batch of `update`/`create`/`delete`/`verify` lines from stdin.
///
/// Oracle: `git/builtin/update-ref.c` (`update_refs_stdin`).
fn update_ref_stdin(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let raw = super::read_stdin_bytes(&ctx.env)?;
    let zero = kind.zero_oid().to_hex();
    let mut updates = Vec::new();
    let split_nul = opts.is_set("z");
    let chunks: Vec<String> = if split_nul {
        raw.split(|byte| *byte == 0)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect()
    } else {
        String::from_utf8_lossy(&raw)
            .lines()
            .map(str::to_owned)
            .collect()
    };
    for chunk in &chunks {
        let text = chunk.trim();
        if text.is_empty() {
            continue;
        }
        let mut parts = text.split(' ');
        let verb = parts.next().unwrap_or_default();
        if verb == "option" {
            let name = parts.next().unwrap_or_default();
            if name != "no-deref" {
                return Err(GitError::Invalid {
                    detail: format!("unknown update-ref option {name:?}"),
                });
            }
            if parts.next().is_some() {
                return Err(GitError::Invalid {
                    detail: format!("bad update-ref line {text:?}"),
                });
            }
            continue;
        }
        let name = parts.next().ok_or_else(|| GitError::Invalid {
            detail: format!("bad update-ref line {text:?}"),
        })?;
        let refname = RefName::new(name.to_owned()).map_err(|err| GitError::Invalid {
            detail: format!("bad ref name: {err}"),
        })?;
        let expect_old = |old: Option<&str>| -> Result<RefExpect, GitError> {
            match old {
                None => Ok(RefExpect::Any),
                Some(hex) if hex == zero => Ok(RefExpect::Absent),
                Some(hex) => Ok(RefExpect::Present(RefTarget::Direct(
                    ruk_git::parse_oid_for(hex, kind)?,
                ))),
            }
        };
        match verb {
            "update" | "create" => {
                let hex = parts.next().ok_or_else(|| GitError::Invalid {
                    detail: format!("bad update-ref line {text:?}"),
                })?;
                if hex == zero {
                    return Err(GitError::Invalid {
                        detail: format!("{verb} refuses the zero object id (use delete)"),
                    });
                }
                let oid = ruk_git::parse_oid_for(hex, kind)?;
                let old = parts.next();
                if verb == "create" && old.is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("bad update-ref line {text:?}"),
                    });
                }
                if parts.next().is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("bad update-ref line {text:?}"),
                    });
                }
                updates.push(RefUpdate {
                    name: refname,
                    expected: if verb == "create" {
                        RefExpect::Absent
                    } else {
                        expect_old(old)?
                    },
                    change: RefChange::Set(RefTarget::Direct(oid)),
                });
            }
            "delete" => {
                let old = parts.next();
                let expected = expect_old(old)?;
                if parts.next().is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("bad update-ref line {text:?}"),
                    });
                }
                updates.push(RefUpdate {
                    name: refname,
                    expected,
                    change: RefChange::Delete,
                });
            }
            "verify" => {
                let held = super::state::read_ref(store, &refname)?;
                let wanted = expect_old(parts.next())?;
                if parts.next().is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("bad update-ref line {text:?}"),
                    });
                }
                let good = match wanted {
                    RefExpect::Any => held.is_some(),
                    RefExpect::Absent => held.is_none(),
                    RefExpect::Present(target) => held.as_ref() == Some(&target),
                };
                if !good {
                    return Err(GitError::Invalid {
                        detail: format!("cannot verify {name:?}"),
                    });
                }
            }
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("unknown update-ref command {verb:?}"),
                });
            }
        }
    }
    if updates.is_empty() {
        return Ok(Vec::new());
    }
    let applied = apply_refs(store, kind, updates)?;
    append_reflog(ctx, &applied, opts.single("message")?)?;
    Ok(Vec::new())
}

/// Deletes one ref with an optional expected value and reflog message.
fn delete_ref_logged(
    ctx: &Ctx,
    name: &str,
    old: Option<String>,
    message: Option<String>,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let refname = RefName::new(name.to_owned()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })?;
    let expected = match old {
        Some(hex) if hex == kind.zero_oid().to_hex() => RefExpect::Absent,
        Some(hex) => {
            let oid = ruk_git::parse_oid_for(&hex, kind)?;
            RefExpect::Present(RefTarget::Direct(oid))
        }
        None => RefExpect::Any,
    };
    let applied = apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected,
            change: RefChange::Delete,
        }],
    )?;
    append_reflog(ctx, &applied, message)?;
    Ok(Vec::new())
}

/// Appends reflog rows for applied ref changes when a message was given.
fn append_reflog(
    ctx: &Ctx,
    applied: &[AppliedRef],
    message: Option<String>,
) -> Result<(), GitError> {
    let Some(message) = message else {
        return Ok(());
    };
    let store = ctx.store()?;
    let committer = super::state::identity(ctx, super::state::IdentityRole::Committer)?;
    let mut mutations = Vec::new();
    for change in applied {
        let old_oid = change.before.as_ref().and_then(underlying_oid);
        let new_oid = change.after.as_ref().and_then(underlying_oid);
        if old_oid.is_none() && new_oid.is_none() {
            continue;
        }
        let operation = ruk_core::change::OperationId(reflog_alloc(store)?);
        let key = ReflogKey::new(change.name.clone(), operation, operation.0);
        let record = ReflogRecord {
            operation,
            old_oid,
            new_oid,
            committer: committer.clone(),
            message: ruk_core::ByteString::from(message.as_str()),
        };
        mutations.push(prepare_append_reflog(store, &key, &record).map_err(GitError::from)?);
    }
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Reads the direct oid behind a ref target for reflog rows.
fn underlying_oid(target: &RefTarget) -> Option<Oid> {
    match target {
        RefTarget::Direct(oid) => Some(*oid),
        RefTarget::Symbolic(_) => None,
    }
}

/// Reads, sets, or deletes symbolic refs; `HEAD` moves the workspace.
///
/// Oracle: `git/builtin/symbolic-ref.c`.
pub(crate) fn symbolic_ref(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        // Accepted for script compatibility: reads print only the target,
        // and the exit status already signals a non-symbolic ref.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "short",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-recurse",
            short: None,
            takes_value: false,
        },
        // The default: accepted so scripts can spell it out.
        FlagSpec {
            long: "recurse",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    // `-m` is the reflog reason for an update. Deletes ignore it, as the
    // oracle does; a set on a symref has no reflog lane here, so it is refused
    // rather than dropped (see the `[name, target]` arm).
    let message = opts.single("message")?;
    match opts.positionals.as_slice() {
        [] => Err(GitError::Invalid {
            detail: "usage: symbolic-ref [-d] <name> [<target>]".to_owned(),
        }),
        [name] => {
            if opts.is_set("delete") {
                return delete_symbolic(ctx, name);
            }
            let target = if opts.is_set("no-recurse") {
                ref_text(&immediate_symbolic_target(ctx, name)?)
            } else {
                terminal_symbolic_target(ctx, name)?
            };
            if opts.is_set("short") {
                return Ok(line(shorten_refname(&target).as_bytes().to_vec()));
            }
            Ok(line(target.into_bytes()))
        }
        [name, target] => {
            if opts.is_set("delete") {
                return Err(GitError::Invalid {
                    detail: "symbolic-ref -d takes only a name".to_owned(),
                });
            }
            if message.is_some() {
                return Err(GitError::Unsupported {
                    command: "symbolic-ref -m on a set: symref reflog rows are not recorded"
                        .to_owned(),
                });
            }
            write_symbolic(ctx, name, target)
        }
        _ => Err(GitError::Invalid {
            detail: "usage: symbolic-ref [-d] <name> [<target>]".to_owned(),
        }),
    }
}

/// Shortens `refs/heads/main` to `main` for `--short` listings.
fn shorten_refname(name: &str) -> &str {
    name.strip_prefix("refs/heads/")
        .or_else(|| name.strip_prefix("refs/tags/"))
        .or_else(|| name.strip_prefix("refs/remotes/"))
        .unwrap_or_else(|| name.strip_prefix("refs/").unwrap_or(name))
}

/// The one-level target of a symbolic ref, `HEAD` included (`--no-recurse`).
fn immediate_symbolic_target(ctx: &Ctx, name: &str) -> Result<RefName, GitError> {
    let store = ctx.store()?;
    if name == "HEAD" {
        let (workspace, _) = load_or_default(store)?;
        return match workspace.head {
            HeadRef::Symbolic(target) => Ok(target),
            HeadRef::Detached(_) => Err(not_symbolic("HEAD")),
        };
    }
    let refname = symref_name(name)?;
    match super::state::read_ref(store, &refname)? {
        Some(RefTarget::Symbolic(target)) => Ok(target),
        Some(RefTarget::Direct(_)) => Err(not_symbolic(name)),
        None => Err(GitError::NotFound {
            detail: format!("ref {name} does not exist"),
        }),
    }
}

/// The terminal of a symbolic ref's chain: the oracle's default. It prints
/// even when unborn, and a broken chain is reported by name.
fn terminal_symbolic_target(ctx: &Ctx, name: &str) -> Result<String, GitError> {
    let store = ctx.store()?;
    let refs = StoreRefs::new(store);
    if name == "HEAD" {
        let (workspace, _) = load_or_default(store)?;
        let resolved = match workspace.head.resolve(&refs).map_err(ref_error)? {
            ruk_core::workspace::ResolvedHead::Symbolic(resolved) => resolved,
            ruk_core::workspace::ResolvedHead::Detached(_) => {
                return Err(not_symbolic("HEAD"));
            }
        };
        return Ok(ref_text(&resolved.terminal));
    }
    // Reject a direct or absent ref before resolving through it.
    immediate_symbolic_target(ctx, name)?;
    let refname = symref_name(name)?;
    let resolved = ruk_core::refdata::resolve(&refs, &refname).map_err(ref_error)?;
    Ok(ref_text(&resolved.terminal))
}

/// Parses a stored ref name from the command line.
fn symref_name(name: &str) -> Result<RefName, GitError> {
    RefName::new(name.to_owned()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })
}

/// The text of a ref name as the symref verbs print it.
fn ref_text(name: &RefName) -> String {
    name.to_utf8().unwrap_or_default().to_owned()
}

/// The refusal for a ref that is not symbolic.
fn not_symbolic(name: &str) -> GitError {
    GitError::Invalid {
        detail: format!("ref {name} is not a symbolic ref"),
    }
}

/// Maps a ref-contract failure: a store read keeps its error, while a broken
/// chain (cycle or too deep) is reported by name.
fn ref_error(err: ruk_core::refdata::RefError) -> GitError {
    match err {
        ruk_core::refdata::RefError::Read(core) => GitError::from(core),
        other => GitError::Invalid {
            detail: other.to_string(),
        },
    }
}

/// Points one symbolic ref at a target; `HEAD` moves the workspace row.
fn write_symbolic(ctx: &Ctx, name: &str, target: &str) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target_name = RefName::new(target.to_owned()).map_err(|err| GitError::Invalid {
        detail: format!("bad symref target: {err}"),
    })?;
    if name == "HEAD" {
        if !target.starts_with("refs/") {
            return Err(GitError::Invalid {
                detail: "Refusing to point HEAD outside of refs/".to_owned(),
            });
        }
        let (workspace, raw) = load_or_default(store)?;
        let next = workspace.move_head(workspace.stamp, HeadRef::Symbolic(target_name))?;
        let mutation = workspace_mutation(raw.as_deref(), &next)?;
        store
            .publish(Vec::new(), &[mutation])
            .map_err(GitError::from)?;
        return Ok(Vec::new());
    }
    let refname = RefName::new(name.to_owned()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected: RefExpect::Any,
            change: RefChange::Set(RefTarget::Symbolic(target_name)),
        }],
    )?;
    Ok(Vec::new())
}

/// Deletes one symbolic ref, refusing `HEAD` and any ref that is not symbolic.
///
/// The delete is a compare-and-swap on the symbolic value just read: a ref that
/// turned direct in between fails the expectation instead of being removed.
/// Like the oracle's delete, no reflog message is recorded.
fn delete_symbolic(ctx: &Ctx, name: &str) -> Result<Vec<u8>, GitError> {
    if name == "HEAD" {
        return Err(GitError::Invalid {
            detail: "deleting HEAD is not allowed".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let refname = symref_name(name)?;
    let expected = match super::state::read_ref(store, &refname)? {
        Some(target @ RefTarget::Symbolic(_)) => target,
        _ => {
            return Err(GitError::Invalid {
                detail: format!("Cannot delete {name}, not a symbolic ref"),
            });
        }
    };
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected: RefExpect::Present(expected),
            change: RefChange::Delete,
        }],
    )?;
    Ok(Vec::new())
}

/// Lists local references.
///
/// Oracle: `git/builtin/show-ref.c`.
pub(crate) fn show_ref(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "head",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "verify",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "tags",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "heads",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "branches",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dereference",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "hash",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "abbrev",
            short: None,
            takes_value: false,
        },
        // Accepted for `--verify`: the exit status already carries the
        // answer, so nothing is printed.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "exclude-existing",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "exists",
            short: None,
            takes_value: false,
        },
    ];
    // `--abbrev[=<n>]` and `--hash[=<n>]` take an optional value, which the
    // shared parser cannot express: normalize the valued form to the bare
    // flag and remember the width.
    let mut abbrev_digits: Option<usize> = None;
    let mut rewritten = Vec::with_capacity(args.len());
    for arg in args {
        if let Some(width) = arg.strip_prefix("--abbrev=") {
            abbrev_digits = Some(parse_oid_width(width)?);
            rewritten.push("--abbrev".to_owned());
        } else if let Some(width) = arg.strip_prefix("--hash=") {
            abbrev_digits = Some(parse_oid_width(width)?);
            rewritten.push("--hash".to_owned());
        } else {
            rewritten.push(arg.clone());
        }
    }
    let opts = collect(&rewritten, &specs)?;
    let store = ctx.store()?;
    let mut out = Vec::new();
    if opts.is_set("exists") {
        for name in &opts.positionals {
            let refname = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("bad ref name: {err}"),
            })?;
            if super::state::read_ref(store, &refname)?.is_none() {
                return Err(GitError::NotFound {
                    detail: format!("reference does not exist: {name}"),
                });
            }
        }
        return Ok(out);
    }
    if opts.is_set("exclude-existing") {
        return show_ref_exclude_existing(ctx);
    }
    if opts.is_set("verify") {
        if opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: show-ref --verify <ref>".to_owned(),
            });
        }
        let quiet = opts.is_set("quiet");
        for name in &opts.positionals {
            let refname = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("bad ref name: {err}"),
            })?;
            let target =
                super::state::read_ref(store, &refname)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("ref {name} does not exist"),
                })?;
            let oid = peel_target_oid(ctx, &target)?.ok_or_else(|| GitError::NotFound {
                detail: format!("ref {name} is unborn"),
            })?;
            if !quiet {
                out.extend_from_slice(format!("{} {}\n", oid.to_hex(), name).as_bytes());
            }
        }
        return Ok(out);
    }
    let digits = abbrev_digits.or(opts.is_set("abbrev").then_some(7));
    let hash_only = opts.is_set("hash");
    let render_oid = |oid: &Oid| {
        let hex = oid.to_hex();
        match digits {
            Some(width) => hex[..width.min(hex.len())].to_owned(),
            None => hex,
        }
    };
    if opts.is_set("head") {
        if let Ok(tip) = head_oid(store) {
            let shown = render_oid(&tip);
            if hash_only {
                out.extend_from_slice(format!("{shown}\n").as_bytes());
            } else {
                out.extend_from_slice(format!("{shown} HEAD\n").as_bytes());
            }
        }
    }
    let heads_only = opts.is_set("heads") || opts.is_set("branches");
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        if opts.is_set("tags") && !text.starts_with("refs/tags/") {
            continue;
        }
        if heads_only && !text.starts_with("refs/heads/") {
            continue;
        }
        if !opts.positionals.is_empty()
            && !opts
                .positionals
                .iter()
                .any(|pattern| glob_match(pattern, &text))
        {
            continue;
        }
        let Some(oid) = peel_target_oid(ctx, &target)? else {
            continue;
        };
        let shown = render_oid(&oid);
        if hash_only {
            out.extend_from_slice(format!("{shown}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{shown} {text}\n").as_bytes());
        }
        if opts.is_set("dereference") {
            let peeled = peel_tag_target(ctx, &target)?;
            if peeled.is_some_and(|peeled| peeled != oid) {
                let shown = render_oid(&peeled.unwrap_or(oid));
                if hash_only {
                    out.extend_from_slice(format!("{shown}\n").as_bytes());
                } else {
                    out.extend_from_slice(format!("{shown} {text}^{{}}\n").as_bytes());
                }
            }
        }
    }
    Ok(out)
}

/// Parses an `--abbrev=<n>` / `--hash=<n>` width.
fn parse_oid_width(text: &str) -> Result<usize, GitError> {
    let width: usize = text.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad object width {text:?}"),
    })?;
    if width == 0 {
        return Err(GitError::Invalid {
            detail: format!("bad object width {text:?}"),
        });
    }
    Ok(width)
}

/// Prints stdin `<oid> <ref>` lines whose ref is absent locally.
///
/// Oracle: `git/builtin/show-ref.c` (`--exclude-existing`).
fn show_ref_exclude_existing(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let stdin = super::read_stdin_text(&ctx.env)?;
    let mut out = Vec::new();
    for raw in stdin.lines() {
        let text = raw.trim_end();
        if text.is_empty() {
            continue;
        }
        let refpart = text.split_once(' ').map_or(text, |(_, name)| name);
        let missing = match RefName::new(refpart.to_owned()) {
            Err(_) => true,
            Ok(refname) => super::state::read_ref(store, &refname)?.is_none(),
        };
        if missing {
            out.extend_from_slice(text.as_bytes());
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// Follows an annotated tag object to the object it points at.
fn peel_tag_target(ctx: &Ctx, target: &RefTarget) -> Result<Option<Oid>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let RefTarget::Direct(oid) = target else {
        return Ok(peel_target_oid(ctx, target)?);
    };
    let (object_kind, body) = read_object_bytes(store, *oid)?;
    if object_kind != ruk_core::store::ObjectKind::Tag {
        return Ok(Some(*oid));
    }
    let first = body.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let hex = first
        .strip_prefix(b"object ")
        .ok_or_else(|| GitError::Invalid {
            detail: format!("tag {} has no object header", oid.to_hex()),
        })?;
    let text = std::str::from_utf8(hex).map_err(|_| GitError::Invalid {
        detail: format!("tag {} has a non-UTF-8 object header", oid.to_hex()),
    })?;
    ruk_git::parse_oid_for(text, kind).map(Some)
}

/// Peels one ref target to its object id for listings.
fn peel_target_oid(ctx: &Ctx, target: &RefTarget) -> Result<Option<Oid>, GitError> {
    let store = ctx.store()?;
    match target {
        RefTarget::Direct(oid) => Ok(Some(*oid)),
        RefTarget::Symbolic(name) => {
            let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), name)
                .map_err(|err| GitError::from(CoreError::from(err)))?;
            Ok(resolved.oid)
        }
    }
}

/// Prints one line per ref with caller-chosen fields.
///
/// Oracle: `git/builtin/for-each-ref.c`. The implemented fields are
/// `%(refname)`, `%(refname:short)`, `%(objectname)`, `%(objectname:short)`,
/// `%(objecttype)`, `%(subject)`, `%(authorname)`, `%(committername)`, and
/// `%(creatordate)` / `%(creatordate:iso)`; anything else fails instead of
/// printing a blank.
pub(crate) fn for_each_ref(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "count",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "sort",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "points-at",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let format = opts
        .single("format")?
        .unwrap_or_else(|| "%(objectname) %(refname)".to_owned());
    let fields = parse_format(&format)?;
    let mut points = Vec::new();
    for hex in opts.all("points-at")? {
        points.push(ruk_git::parse_oid_for(&hex, kind)?);
    }
    let mut refs: Vec<(String, RefTarget)> = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        if !opts.positionals.is_empty()
            && !opts
                .positionals
                .iter()
                .any(|pattern| glob_match(pattern, &text))
        {
            continue;
        }
        if !points.is_empty() {
            let direct = matches!(&target, RefTarget::Direct(oid) if points.contains(oid));
            let peeled = peel_target_oid(ctx, &target)?.is_some_and(|oid| points.contains(&oid));
            // Annotated tags point at tag objects but read as their commit,
            // so `--points-at` matches the peeled target too.
            let tag_peeled =
                peel_tag_target(ctx, &target)?.is_some_and(|oid| points.contains(&oid));
            if !direct && !peeled && !tag_peeled {
                continue;
            }
        }
        refs.push((text, target));
    }
    sort_refs(ctx, &mut refs, &opts.all("sort")?)?;
    if let Some(count) = opts.single("count")? {
        let count: usize = count.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad --count value {count:?}"),
        })?;
        refs.truncate(count);
    }
    let mut out = Vec::new();
    for (text, target) in &refs {
        let info = ref_commit_info(ctx, target)?;
        let mut rendered_line = Vec::new();
        for field in &fields {
            match field {
                FormatField::Text(literal) => {
                    rendered_line.extend_from_slice(literal.as_bytes());
                }
                FormatField::RefName => rendered_line.extend_from_slice(text.as_bytes()),
                FormatField::RefNameShort => {
                    rendered_line.extend_from_slice(shorten_refname(text).as_bytes());
                }
                FormatField::ObjectName => {
                    let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                        detail: format!("ref {text} is unborn"),
                    })?;
                    rendered_line.extend_from_slice(oid.to_hex().as_bytes());
                }
                FormatField::ObjectNameShort => {
                    let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                        detail: format!("ref {text} is unborn"),
                    })?;
                    let hex = oid.to_hex();
                    rendered_line.extend_from_slice(hex[..7.min(hex.len())].as_bytes());
                }
                FormatField::ObjectType => {
                    let kind_name = ref_object_type(ctx, target)?;
                    rendered_line.extend_from_slice(kind_name.as_bytes());
                }
                FormatField::Subject => {
                    let subject = info.as_ref().map(|known| known.subject.clone());
                    rendered_line.extend_from_slice(subject.unwrap_or_default().as_bytes());
                }
                FormatField::AuthorName => {
                    let name = info.as_ref().map(|known| known.author_name.clone());
                    rendered_line.extend_from_slice(name.unwrap_or_default().as_bytes());
                }
                FormatField::CommitterName => {
                    let name = info.as_ref().map(|known| known.committer_name.clone());
                    rendered_line.extend_from_slice(name.unwrap_or_default().as_bytes());
                }
                FormatField::CreatorDate => {
                    let date = info
                        .as_ref()
                        .map(|known| iso_datetime(known.committer_ts, known.committer_offset));
                    rendered_line.extend_from_slice(date.unwrap_or_default().as_bytes());
                }
            }
        }
        rendered_line.push(b'\n');
        out.extend_from_slice(&rendered_line);
    }
    Ok(out)
}

/// Sorts ref rows by `--sort` keys (`-` prefixes reverse), the way
/// `git/builtin/for-each-ref.c` orders its ref array.
fn sort_refs(ctx: &Ctx, refs: &mut [(String, RefTarget)], keys: &[String]) -> Result<(), GitError> {
    let mut parsed = Vec::with_capacity(keys.len());
    for key in keys {
        let (name, reverse) = key
            .strip_prefix('-')
            .map_or((key.as_str(), false), |rest| (rest, true));
        match name {
            "refname" | "objectname" | "objecttype" | "authordate" | "committerdate"
            | "creatordate" => parsed.push((name, reverse)),
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("unknown --sort key {key:?}"),
                });
            }
        }
    }
    if parsed.is_empty() {
        return Ok(());
    }
    let mut decorated = Vec::with_capacity(refs.len());
    for (text, target) in refs.iter() {
        let info = ref_commit_info(ctx, target)?;
        let oid = peel_target_oid(ctx, target)?
            .map(|oid| oid.to_hex())
            .unwrap_or_default();
        decorated.push((
            text.clone(),
            ref_object_type_or_empty(ctx, target)?,
            oid,
            info.as_ref().map(|info| info.author_ts).unwrap_or(0),
            info.as_ref().map(|info| info.committer_ts).unwrap_or(0),
        ));
    }
    let mut order: Vec<usize> = (0..refs.len()).collect();
    order.sort_by(|&left, &right| {
        let (lname, ltype, loid, lauthor, lcommitter) = &decorated[left];
        let (rname, rtype, roid, rauthor, rcommitter) = &decorated[right];
        let mut verdict = std::cmp::Ordering::Equal;
        for (name, reverse) in &parsed {
            let next = match *name {
                "refname" => lname.cmp(rname),
                "objectname" => loid.cmp(roid),
                "objecttype" => ltype.cmp(rtype),
                "authordate" => lauthor.cmp(rauthor),
                _ => lcommitter.cmp(rcommitter),
            };
            if next != std::cmp::Ordering::Equal {
                verdict = if *reverse { next.reverse() } else { next };
                break;
            }
        }
        verdict
    });
    let mut sorted = Vec::with_capacity(refs.len());
    for index in order {
        let (text, target) = &refs[index];
        sorted.push((text.clone(), target.clone()));
    }
    refs.clone_from_slice(&sorted);
    Ok(())
}

/// Names the peeled object type behind one ref target, or empty when unborn.
fn ref_object_type_or_empty(ctx: &Ctx, target: &RefTarget) -> Result<String, GitError> {
    if peel_target_oid(ctx, target)?.is_none() {
        return Ok(String::new());
    }
    ref_object_type(ctx, target)
}

/// One parsed `--format` piece.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FormatField {
    /// Literal text between fields.
    Text(String),
    /// The full ref name.
    RefName,
    /// The ref name without its `refs/*/` prefix.
    RefNameShort,
    /// The peeled object id in hex.
    ObjectName,
    /// The first seven digits of the peeled object id.
    ObjectNameShort,
    /// The peeled object type name.
    ObjectType,
    /// The first line of the peeled commit message.
    Subject,
    /// The peeled commit author name.
    AuthorName,
    /// The peeled commit committer name.
    CommitterName,
    /// The peeled commit committer date in `iso` mode.
    CreatorDate,
}

/// Parses a `--format` string into literal and field pieces.
fn parse_format(format: &str) -> Result<Vec<FormatField>, GitError> {
    let mut fields = Vec::new();
    let mut literal = String::new();
    let mut rest = format;
    while let Some(start) = rest.find("%(") {
        literal.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find(')').ok_or_else(|| GitError::Invalid {
            detail: "bad --format: missing )".to_owned(),
        })?;
        if !literal.is_empty() {
            fields.push(FormatField::Text(literal.clone()));
            literal.clear();
        }
        match &after[..end] {
            "refname" => fields.push(FormatField::RefName),
            "refname:short" => fields.push(FormatField::RefNameShort),
            "objectname" => fields.push(FormatField::ObjectName),
            "objectname:short" => fields.push(FormatField::ObjectNameShort),
            "objecttype" => fields.push(FormatField::ObjectType),
            "subject" => fields.push(FormatField::Subject),
            "authorname" => fields.push(FormatField::AuthorName),
            "committername" => fields.push(FormatField::CommitterName),
            "creatordate" | "creatordate:iso" => fields.push(FormatField::CreatorDate),
            other => {
                return Err(GitError::Invalid {
                    detail: format!("unsupported --format field %({other})"),
                });
            }
        }
        rest = &after[end + 1..];
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        fields.push(FormatField::Text(literal));
    }
    Ok(fields)
}

/// Commit facts behind one ref for `%(subject)` and name/date fields.
struct PeeledCommit {
    author_name: String,
    committer_name: String,
    author_ts: i64,
    committer_ts: i64,
    committer_offset: ruk_core::conflict::TzOffset,
    subject: String,
}

/// Peels a ref to its commit record for informational format fields.
/// Non-commit targets read as absent, the way the oracle prints blanks.
fn ref_commit_info(ctx: &Ctx, target: &RefTarget) -> Result<Option<PeeledCommit>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let Some(peeled) = peel_target_oid(ctx, target)? else {
        return Ok(None);
    };
    let (object_kind, body) = read_object_bytes(store, peeled)?;
    let commit_oid = if object_kind == ruk_core::store::ObjectKind::Tag {
        let Some(first) = body.split(|byte| *byte == b'\n').next() else {
            return Ok(None);
        };
        let Some(hex) = first.strip_prefix(b"object ") else {
            return Ok(None);
        };
        let text = std::str::from_utf8(hex).map_err(|_| GitError::Invalid {
            detail: "tag object header is not valid UTF-8".to_owned(),
        })?;
        ruk_git::parse_oid_for(text, kind)?
    } else {
        peeled
    };
    let record = match super::state::commit_record(store, commit_oid) {
        Ok(record) => record,
        Err(GitError::NotFound { .. }) => return Ok(None),
        Err(other) => return Err(other),
    };
    let author = record
        .author()
        .map_err(|err| GitError::from(CoreError::from(err)))?;
    let committer = record
        .committer()
        .map_err(|err| GitError::from(CoreError::from(err)))?;
    Ok(Some(PeeledCommit {
        author_name: String::from_utf8_lossy(author.name.as_bytes()).into_owned(),
        committer_name: String::from_utf8_lossy(committer.name.as_bytes()).into_owned(),
        author_ts: author.timestamp,
        committer_ts: committer.timestamp,
        committer_offset: committer.offset,
        subject: first_message_line(record.message()),
    }))
}

/// Renders `YYYY-MM-DD HH:MM:SS +HH:MM` in the committer's zone for
/// `%(creatordate:iso)`, matching the oracle's `iso` date mode.
fn iso_datetime(timestamp: i64, offset: ruk_core::conflict::TzOffset) -> String {
    let digits = u32::from(offset.hhmm());
    let minutes = i64::from(digits / 100) * 60 + i64::from(digits % 100);
    let shift = minutes * 60;
    let local = timestamp + if offset.is_negative() { -shift } else { shift };
    let days = local.div_euclid(86_400);
    let clock = local.rem_euclid(86_400) as u64;
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let display_year = if month <= 2 { year + 1 } else { year };
    format!(
        "{display_year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} {}{:02}:{:02}",
        clock / 3_600,
        (clock % 3_600) / 60,
        clock % 60,
        if offset.is_negative() { '-' } else { '+' },
        minutes / 60,
        minutes % 60,
    )
}

/// Names the peeled object type behind one ref target.
fn ref_object_type(ctx: &Ctx, target: &RefTarget) -> Result<String, GitError> {
    let store = ctx.store()?;
    let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
        detail: "ref is unborn".to_owned(),
    })?;
    let (kind, _) = read_object_bytes(store, oid)?;
    Ok(match kind {
        ruk_core::store::ObjectKind::Blob => "blob".to_owned(),
        ruk_core::store::ObjectKind::Tree => "tree".to_owned(),
        ruk_core::store::ObjectKind::Commit => "commit".to_owned(),
        ruk_core::store::ObjectKind::Tag => "tag".to_owned(),
        ruk_core::store::ObjectKind::Conflict => "conflict".to_owned(),
    })
}

/// Creates, lists, and deletes tags; annotated tags store tag payloads.
///
/// Oracle: `git/builtin/tag.c`.
pub(crate) fn tag(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "list",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "annotate",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "verify",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "sign",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "local-user",
            short: Some('u'),
            takes_value: true,
        },
        FlagSpec {
            long: "file",
            short: Some('F'),
            takes_value: true,
        },
        FlagSpec {
            long: "sort",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "points-at",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "edit",
            short: Some('e'),
            takes_value: false,
        },
        FlagSpec {
            long: "cleanup",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "create-reflog",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "column",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-column",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "color",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-color",
            short: None,
            takes_value: false,
        },
    ];
    // `-n[<num>]` takes an optional attached value, which the shared parser
    // cannot express: normalize to a remembered line count.
    // `--merged`/`--contains` take an optional commit (default `HEAD`).
    let mut annotation_lines: Option<usize> = None;
    let mut merged: Vec<String> = Vec::new();
    let mut no_merged: Vec<String> = Vec::new();
    let mut contains: Vec<String> = Vec::new();
    let mut no_contains: Vec<String> = Vec::new();
    let mut rewritten = Vec::with_capacity(args.len());
    let mut tag_index = 0;
    while tag_index < args.len() {
        let arg = &args[tag_index];
        if arg == "-n" {
            annotation_lines = Some(1);
            tag_index += 1;
            continue;
        }
        if let Some(digits) = arg.strip_prefix("-n") {
            if !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit()) {
                annotation_lines = Some(digits.parse().map_err(|_| GitError::Invalid {
                    detail: format!("bad -n value {arg:?}"),
                })?);
                tag_index += 1;
                continue;
            }
        }
        let mut matched: Option<&str> = None;
        let mut inline: Option<String> = None;
        for name in [
            "--merged",
            "--no-merged",
            "--contains",
            "--no-contains",
            "--with",
            "--without",
        ] {
            if arg == name {
                matched = Some(name);
                break;
            }
            if let Some(rest) = arg.strip_prefix(&format!("{name}=")) {
                matched = Some(name);
                inline = Some(rest.to_owned());
                break;
            }
        }
        if let Some(name) = matched {
            let value = if let Some(v) = inline {
                v
            } else if tag_index + 1 < args.len()
                && args[tag_index + 1] != "--"
                && !args[tag_index + 1].starts_with('-')
            {
                tag_index += 1;
                args[tag_index].clone()
            } else {
                "HEAD".to_owned()
            };
            match name {
                "--merged" => merged.push(value),
                "--no-merged" => no_merged.push(value),
                "--contains" | "--with" => contains.push(value),
                _ => no_contains.push(value),
            }
            tag_index += 1;
            continue;
        }
        rewritten.push(arg.clone());
        tag_index += 1;
    }
    let mut opts = collect(&rewritten, &specs)?;
    for value in merged {
        opts.present
            .entry("merged".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in no_merged {
        opts.present
            .entry("no-merged".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in contains {
        opts.present
            .entry("contains".to_owned())
            .or_default()
            .push(Some(value));
    }
    for value in no_contains {
        opts.present
            .entry("no-contains".to_owned())
            .or_default()
            .push(Some(value));
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("sign") || opts.single("local-user")?.is_some() {
        return Err(GitError::Unsupported {
            command: "tag signing needs GPG, which this store does not implement".to_owned(),
        });
    }
    if opts.is_set("verify") {
        return verify_tags(ctx, &opts);
    }
    if opts.is_set("delete") {
        if opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: tag -d <name>...".to_owned(),
            });
        }
        let mut out = Vec::new();
        for name in &opts.positionals {
            let refname = tag_name(name)?;
            if super::state::read_ref(store, &refname)?.is_none() {
                return Err(GitError::NotFound {
                    detail: format!("tag {name:?} does not exist"),
                });
            }
            apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: refname,
                    expected: RefExpect::Any,
                    change: RefChange::Delete,
                }],
            )?;
            out.extend_from_slice(format!("Deleted tag '{name}'\n").as_bytes());
        }
        return Ok(out);
    }
    if opts.is_set("edit") && opts.is_set("list") {
        return Err(GitError::Invalid {
            detail: "cannot combine --edit and --list".to_owned(),
        });
    }
    if let Some(mode) = opts.single("cleanup")? {
        match mode.as_str() {
            "verbatim" | "whitespace" | "strip" | "scissors" | "default" => {}
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad --cleanup value {mode:?}"),
                });
            }
        }
    }
    // `-n` implies `-l` in the oracle, and the no-arg form already lists.
    // Any list-shaping flag also implies list mode so filters never fall
    // into tag creation.
    let lines = annotation_lines.unwrap_or(0);
    let tag_list_mode = opts.is_set("list")
        || annotation_lines.is_some()
        || opts.is_set("merged")
        || opts.is_set("no-merged")
        || opts.is_set("contains")
        || opts.is_set("no-contains")
        || opts.all("sort").is_ok_and(|v| !v.is_empty())
        || opts.single("format").is_ok_and(|v| v.is_some())
        || opts.all("points-at").is_ok_and(|v| !v.is_empty());
    match opts.positionals.as_slice() {
        [] => list_tags(ctx, &opts, None, lines),
        [pattern] if tag_list_mode => list_tags(ctx, &opts, Some(pattern), lines),
        _ if tag_list_mode => list_tags(ctx, &opts, None, lines),
        [name] => create_tag(ctx, name, None, &opts),
        [name, target] => create_tag(ctx, name, Some(target), &opts),
        _ => Err(GitError::Invalid {
            detail: "usage: tag [-a] [-m <msg>] <name> [<target>]".to_owned(),
        }),
    }
}

/// Verifies annotated tags structurally: the tag object must exist and its
/// target must resolve. The store holds no GPG signatures to check.
fn verify_tags(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: tag -v <name>...".to_owned(),
        });
    }
    let mut out = Vec::new();
    for name in &opts.positionals {
        let refname = tag_name(name)?;
        let target =
            super::state::read_ref(ctx.store()?, &refname)?.ok_or_else(|| GitError::NotFound {
                detail: format!("tag {name:?} does not exist"),
            })?;
        let RefTarget::Direct(oid) = target else {
            return Err(GitError::Invalid {
                detail: format!("tag {name:?} is not a tag object"),
            });
        };
        let (object_kind, body) = read_object_bytes(ctx.store()?, oid)?;
        if object_kind != ruk_core::store::ObjectKind::Tag {
            return Err(GitError::Invalid {
                detail: format!("tag {name:?} is lightweight: cannot verify"),
            });
        }
        out.extend_from_slice(&line(body));
    }
    Ok(out)
}

/// Lists tags, optionally filtered by a glob.
fn list_tags(
    ctx: &Ctx,
    opts: &super::Collected,
    extra: Option<&str>,
    lines: usize,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let patterns: Vec<String> = opts
        .positionals
        .iter()
        .cloned()
        .chain(extra.map(str::to_owned))
        .collect();
    let kind = ctx.kind()?;
    let resolve_commit = |values: Vec<String>| -> Result<Vec<Oid>, GitError> {
        let mut oids = Vec::with_capacity(values.len());
        for value in values {
            oids.push(resolve_rev(store, kind, &value)?);
        }
        Ok(oids)
    };
    let merged = resolve_commit(opts.all("merged")?)?;
    let no_merged = resolve_commit(opts.all("no-merged")?)?;
    let contains = resolve_commit(opts.all("contains")?)?;
    let no_contains = resolve_commit(opts.all("no-contains")?)?;
    let mut points_at: Vec<Oid> = Vec::new();
    for value in opts.all("points-at")? {
        points_at.push(resolve_rev(store, kind, &value)?);
    }
    let mut rows: Vec<(String, String, RefTarget)> = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        if !text.starts_with("refs/tags/") {
            continue;
        }
        let short = text.trim_start_matches("refs/tags/").to_owned();
        if !patterns.is_empty() && !patterns.iter().any(|pattern| glob_match(pattern, &short)) {
            continue;
        }
        // Peel once: lightweight tags read as their commit, annotated tags
        // as the tag object with a commit behind it.
        let peeled = peel_tag_target(ctx, &target)?.or(peel_target_oid(ctx, &target)?);
        if !points_at.is_empty() {
            let direct = matches!(&target, RefTarget::Direct(oid) if points_at.contains(oid));
            let matches_peeled = peeled.is_some_and(|oid| points_at.contains(&oid));
            if !direct && !matches_peeled {
                continue;
            }
        }
        if !merged.is_empty()
            || !no_merged.is_empty()
            || !contains.is_empty()
            || !no_contains.is_empty()
        {
            let Some(tip) = peeled else { continue };
            // Tags resolve to commits, blobs, or trees; ancestry filters only
            // apply to commit tips, so non-commit tags drop out when such a
            // filter is present.
            let tip_is_commit = super::state::commit_record(store, tip).is_ok();
            if !tip_is_commit {
                continue;
            }
            let mut ok = true;
            for base in &merged {
                if tip != *base && !is_ancestor(store, tip, *base).unwrap_or(false) {
                    ok = false;
                    break;
                }
            }
            for base in &no_merged {
                if tip == *base || is_ancestor(store, tip, *base).unwrap_or(false) {
                    ok = false;
                    break;
                }
            }
            for commit in &contains {
                if tip != *commit && !is_ancestor(store, *commit, tip).unwrap_or(false) {
                    ok = false;
                    break;
                }
            }
            for commit in &no_contains {
                if tip == *commit || is_ancestor(store, *commit, tip).unwrap_or(false) {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }
        }
        rows.push((text, short, target.clone()));
    }
    sort_tag_rows(ctx, &mut rows, &opts.all("sort")?)?;
    let mut out = Vec::new();
    if let Some(format) = opts.single("format")? {
        for (text, short, target) in &rows {
            out.extend_from_slice(&render_tag_format(ctx, &format, text, short, target)?);
        }
        return Ok(out);
    }
    for (_, short, target) in &rows {
        if lines == 0 {
            out.extend_from_slice(format!("{short}\n").as_bytes());
            continue;
        }
        let shown = tag_message_lines(ctx, target, lines)?;
        if shown.is_empty() {
            out.extend_from_slice(format!("{short}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{short:<16}{}\n", shown[0]).as_bytes());
            for extra in &shown[1..] {
                out.extend_from_slice(format!("    {extra}\n").as_bytes());
            }
        }
    }
    Ok(out)
}

/// Sorts tag rows by `--sort` keys, the `for-each-ref` key set.
fn sort_tag_rows(
    ctx: &Ctx,
    rows: &mut [(String, String, RefTarget)],
    keys: &[String],
) -> Result<(), GitError> {
    let mut parsed = Vec::with_capacity(keys.len());
    for key in keys {
        let (name, reverse) = key
            .strip_prefix('-')
            .map_or((key.as_str(), false), |rest| (rest, true));
        match name {
            "refname" | "objectname" | "objecttype" | "authordate" | "committerdate"
            | "creatordate" => parsed.push((name, reverse)),
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("unknown --sort key {key:?}"),
                });
            }
        }
    }
    if parsed.is_empty() {
        return Ok(());
    }
    let mut decorated = Vec::with_capacity(rows.len());
    for (text, _, target) in rows.iter() {
        let info = ref_commit_info(ctx, target)?;
        let oid = peel_target_oid(ctx, target)?
            .map(|oid| oid.to_hex())
            .unwrap_or_default();
        decorated.push((
            text.clone(),
            ref_object_type_or_empty(ctx, target)?,
            oid,
            info.as_ref().map(|info| info.author_ts).unwrap_or(0),
            info.as_ref().map(|info| info.committer_ts).unwrap_or(0),
        ));
    }
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&left, &right| {
        let (lname, ltype, loid, lauthor, lcommitter) = &decorated[left];
        let (rname, rtype, roid, rauthor, rcommitter) = &decorated[right];
        let mut verdict = std::cmp::Ordering::Equal;
        for (name, reverse) in &parsed {
            let next = match *name {
                "refname" => lname.cmp(rname),
                "objectname" => loid.cmp(roid),
                "objecttype" => ltype.cmp(rtype),
                "authordate" => lauthor.cmp(rauthor),
                _ => lcommitter.cmp(rcommitter),
            };
            if next != std::cmp::Ordering::Equal {
                verdict = if *reverse { next.reverse() } else { next };
                break;
            }
        }
        verdict
    });
    let mut sorted = Vec::with_capacity(rows.len());
    for index in order {
        let (text, short, target) = &rows[index];
        sorted.push((text.clone(), short.clone(), target.clone()));
    }
    rows.iter_mut().enumerate().for_each(|(i, row)| {
        let (text, short, target) = &sorted[i];
        *row = (text.clone(), short.clone(), target.clone());
    });
    Ok(())
}

/// Renders one tag row with `--format`, the `for-each-ref` atoms.
fn render_tag_format(
    ctx: &Ctx,
    format: &str,
    full: &str,
    short: &str,
    target: &RefTarget,
) -> Result<Vec<u8>, GitError> {
    let mut rendered = String::new();
    let mut rest = format;
    while let Some(start) = rest.find("%(") {
        rendered.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find(')').ok_or_else(|| GitError::Invalid {
            detail: "bad --format: missing )".to_owned(),
        })?;
        match &after[..end] {
            "refname" => rendered.push_str(full),
            "refname:short" => rendered.push_str(short),
            "objectname" => {
                let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("ref {full} is unborn"),
                })?;
                rendered.push_str(&oid.to_hex());
            }
            "objectname:short" => {
                let oid = peel_target_oid(ctx, target)?.ok_or_else(|| GitError::NotFound {
                    detail: format!("ref {full} is unborn"),
                })?;
                let hex = oid.to_hex();
                rendered.push_str(&hex.chars().take(7).collect::<String>());
            }
            "objecttype" => rendered.push_str(&ref_object_type(ctx, target)?),
            "subject" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.subject).unwrap_or_default());
            }
            "authorname" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.author_name).unwrap_or_default());
            }
            "committername" => {
                let info = ref_commit_info(ctx, target)?;
                rendered.push_str(&info.map(|i| i.committer_name).unwrap_or_default());
            }
            "creatordate" | "creatordate:iso" => {
                let info = ref_commit_info(ctx, target)?;
                if let Some(known) = info {
                    rendered.push_str(&iso_datetime(known.committer_ts, known.committer_offset));
                }
            }
            other => {
                return Err(GitError::Invalid {
                    detail: format!("unsupported --format field %({other})"),
                });
            }
        }
        rest = &after[end + 1..];
    }
    rendered.push_str(rest);
    rendered.push('\n');
    Ok(rendered.into_bytes())
}

/// Reads up to `lines` annotation lines: the tag message for annotated
/// tags, the target commit message for lightweight ones.
fn tag_message_lines(ctx: &Ctx, target: &RefTarget, lines: usize) -> Result<Vec<String>, GitError> {
    let store = ctx.store()?;
    let Some(oid) = peel_target_oid(ctx, target)? else {
        return Ok(Vec::new());
    };
    let (object_kind, body) = read_object_bytes(store, oid)?;
    if object_kind == ruk_core::store::ObjectKind::Tag {
        let message = body
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .map(|at| body[at + 2..].to_vec())
            .unwrap_or_default();
        return Ok(String::from_utf8_lossy(&message)
            .lines()
            .take(lines)
            .map(str::to_owned)
            .collect());
    }
    let record = match super::state::commit_record(store, oid) {
        Ok(record) => record,
        Err(GitError::NotFound { .. }) => return Ok(Vec::new()),
        Err(other) => return Err(other),
    };
    Ok(String::from_utf8_lossy(record.message())
        .lines()
        .take(lines)
        .map(str::to_owned)
        .collect())
}

/// Creates a lightweight or annotated tag at a target revision.
fn create_tag(
    ctx: &Ctx,
    name: &str,
    target: Option<&str>,
    opts: &super::Collected,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let refname = tag_name(name)?;
    if super::state::read_ref(store, &refname)?.is_some() && !opts.is_set("force") {
        return Err(GitError::Invalid {
            detail: format!("tag {name:?} already exists"),
        });
    }
    let oid = match target {
        Some(rev) => resolve_rev(store, kind, rev)?,
        None => head_oid(store)?,
    };
    let cleanup = opts
        .single("cleanup")?
        .unwrap_or_else(|| "strip".to_owned());
    let pointed = if opts.is_set("annotate")
        || opts.single("message")?.is_some()
        || opts.single("file")?.is_some()
        || opts.is_set("edit")
    {
        let raw = match opts.single("message")? {
            Some(text) => text.into_bytes(),
            None => match opts.single("file")? {
                Some(path) => {
                    let full = ctx.env.cwd.join(&path);
                    std::fs::read(&full).map_err(|err| GitError::Io {
                        detail: format!("reading {}: {err}", full.display()),
                    })?
                }
                None => format!("tag {name}\n").into_bytes(),
            },
        };
        // `-e` opens the message above in the editor; an empty result
        // aborts the tag the way the oracle refuses empty messages.
        let raw = if opts.is_set("edit") {
            let edited = run_editor(ctx, &raw, ".md")?;
            if edited.iter().all(|byte| byte.is_ascii_whitespace()) {
                return Err(GitError::Invalid {
                    detail: "empty tag message".to_owned(),
                });
            }
            edited
        } else {
            raw
        };
        let message = apply_tag_cleanup(&raw, &cleanup);
        let (object_kind, _) = read_object_bytes(store, oid)?;
        let type_name = match object_kind {
            ruk_core::store::ObjectKind::Blob => "blob",
            ruk_core::store::ObjectKind::Tree => "tree",
            ruk_core::store::ObjectKind::Commit => "commit",
            ruk_core::store::ObjectKind::Tag => "tag",
            ruk_core::store::ObjectKind::Conflict => "conflict",
        };
        let tagger = super::state::identity(ctx, super::state::IdentityRole::Committer).ok();
        let payload = tag_payload(&oid.to_hex(), type_name, name, tagger.as_ref(), &message);
        store_object(store, ruk_core::store::ObjectKind::Tag, payload)?
    } else {
        oid
    };
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected: if opts.is_set("force") {
                RefExpect::Any
            } else {
                RefExpect::Absent
            },
            change: RefChange::Set(RefTarget::Direct(pointed)),
        }],
    )?;
    Ok(Vec::new())
}

/// Applies `--cleanup=<mode>` to a tag message: `verbatim` keeps bytes,
/// `whitespace` strips trailing whitespace, `strip`/`default` also drop
/// `#` comment lines and leading/trailing blank lines, `scissors` cuts at
/// the scissors marker first.
fn apply_tag_cleanup(raw: &[u8], mode: &str) -> Vec<u8> {
    if mode == "verbatim" {
        return raw.to_vec();
    }
    let text = String::from_utf8_lossy(raw);
    let mut lines: Vec<&str> = text.lines().collect();
    if mode == "scissors" {
        if let Some(at) = lines
            .iter()
            .position(|line| line.contains("------------------------ >8 ------------------------"))
        {
            lines.truncate(at);
        }
    }
    let mut kept: Vec<String> = Vec::new();
    for line in lines {
        let no_trailing = line.trim_end();
        if (mode == "strip" || mode == "default" || mode == "scissors")
            && (no_trailing.starts_with('#') || no_trailing.is_empty() && kept.is_empty())
        {
            if no_trailing.starts_with('#') {
                continue;
            }
        }
        if mode == "whitespace" {
            kept.push(no_trailing.to_owned());
        } else if no_trailing.starts_with('#') {
            continue;
        } else {
            kept.push(no_trailing.to_owned());
        }
    }
    while kept.first().is_some_and(|line| line.is_empty()) {
        kept.remove(0);
    }
    while kept.last().is_some_and(|line| line.is_empty()) {
        kept.pop();
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out.into_bytes()
}

/// Validates a tag short name into its full ref name.
fn tag_name(name: &str) -> Result<RefName, GitError> {
    RefName::new(format!("refs/tags/{name}")).map_err(|err| GitError::Invalid {
        detail: format!("bad tag name: {err}"),
    })
}

/// Stashes worktree and index state in a stash commit plus a slot record.
///
/// Oracle: `git/builtin/stash.c`.
pub(crate) fn stash(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        // `--keep-index` leaves the index alone; the rest need lanes this
        // store does not have, so they fail loudly instead of half-working.
        FlagSpec {
            long: "keep-index",
            short: Some('k'),
            takes_value: false,
        },
        FlagSpec {
            long: "include-untracked",
            short: Some('u'),
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "staged",
            short: Some('S'),
            takes_value: false,
        },
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        // Accepted for script compatibility: output is the only effect.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        // Accepted: `apply`/`pop` restore the index rows only with `--index`;
        // without it the worktree alone comes back, like the oracle.
        FlagSpec {
            long: "index",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let sub = opts.positionals.first().map(String::as_str);
    let pushing = sub.is_none_or(|word| word == "push" || word == "save");
    if pushing {
        for flag in ["include-untracked", "all", "staged", "patch"] {
            if opts.is_set(flag) {
                return Err(GitError::Unsupported {
                    command: format!("stash --{flag} needs the worktree snapshot lane"),
                });
            }
        }
    } else {
        for flag in ["keep-index", "include-untracked", "all", "staged", "patch"] {
            if !opts.is_set(flag) {
                continue;
            }
            if flag == "patch" && sub == Some("show") {
                return Err(GitError::Unsupported {
                    command: "stash show --patch needs the diff lane".to_owned(),
                });
            }
            // `show -u` is valid in the oracle; stashes here never record
            // untracked files, so the plain listing already is the answer.
            if flag == "include-untracked" && sub == Some("show") {
                continue;
            }
            return Err(GitError::Invalid {
                detail: format!(
                    "option --{flag} does not apply to stash {}",
                    sub.unwrap_or("push")
                ),
            });
        }
    }
    let quiet = opts.is_set("quiet");
    match opts.positionals.as_slice() {
        [] => hush_result(stash_push(ctx, &opts), quiet),
        [sub] if sub == "push" => hush_result(stash_push(ctx, &opts), quiet),
        [sub] if sub == "save" => hush_result(stash_push(ctx, &opts), quiet),
        [sub, first, rest @ ..] if sub == "save" => {
            if opts.is_set("message") {
                return Err(GitError::Invalid {
                    detail: "cannot combine -m with a save message".to_owned(),
                });
            }
            let mut saved = opts.clone();
            let mut message = first.clone();
            for extra in rest {
                message.push(' ');
                message.push_str(extra);
            }
            saved
                .present
                .insert("message".to_owned(), vec![Some(message)]);
            hush_result(stash_push(ctx, &saved), quiet)
        }
        [sub] if sub == "list" => stash_list(ctx),
        [sub] if sub == "show" => stash_show(ctx, Some(default_slot(ctx)?)),
        [sub, slot] if sub == "show" => stash_show(ctx, Some(parse_slot(slot)?)),
        [sub] if sub == "drop" => hush_result(stash_drop_slot(ctx, default_slot(ctx)?), quiet),
        [sub, slot] if sub == "drop" => hush_result(stash_drop_slot(ctx, parse_slot(slot)?), quiet),
        [sub] if sub == "pop" => {
            hush_result(stash_pop_scoped(ctx, default_slot(ctx)?, &opts), quiet)
        }
        [sub, slot] if sub == "pop" => {
            hush_result(stash_pop_scoped(ctx, parse_slot(slot)?, &opts), quiet)
        }
        [sub] if sub == "apply" => {
            hush_result(stash_apply_scoped(ctx, default_slot(ctx)?, &opts), quiet)
        }
        [sub, slot] if sub == "apply" => {
            hush_result(stash_apply_scoped(ctx, parse_slot(slot)?, &opts), quiet)
        }
        [sub] if sub == "clear" => stash_clear(ctx),
        [sub, name] if sub == "branch" => {
            hush_result(stash_branch(ctx, name, default_slot(ctx)?), quiet)
        }
        [sub, name, slot] if sub == "branch" => {
            hush_result(stash_branch(ctx, name, parse_slot(slot)?), quiet)
        }
        [other] => Err(GitError::Invalid {
            detail: format!("unknown stash subcommand {other:?}"),
        }),
        _ => Err(GitError::Invalid {
            detail: "usage: stash [push|list|show|drop|pop|apply|clear]".to_owned(),
        }),
    }
}

/// Drops verb output for `--quiet`, keeping the exit status as the signal.
fn hush_result(result: Result<Vec<u8>, GitError>, quiet: bool) -> Result<Vec<u8>, GitError> {
    result.map(|out| if quiet { Vec::new() } else { out })
}

/// Parses a stash slot number, accepting `stash@{n}` like the oracle.
fn parse_slot(text: &str) -> Result<u64, GitError> {
    let inner = text
        .strip_prefix("stash@{")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(text);
    inner.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad stash slot {text:?}"),
    })
}

/// Resolves a bare stash subcommand (no slot argument) to the newest live
/// slot, the way the oracle defaults to `stash@{0}`. Falls back to slot
/// zero when empty so the usual not-found error fires.
fn default_slot(ctx: &Ctx) -> Result<u64, GitError> {
    let store = ctx.store()?;
    Ok(live_slots(store)?.last().copied().unwrap_or(0))
}

/// Creates a branch at a stash's base commit, checks it out, and applies
/// the stash there, dropping the slot on success.
///
/// Oracle: `git/builtin/stash.c` (`do_branch`).
fn stash_branch(ctx: &Ctx, name: &str, slot: u64) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entry = stash_read(store, slot)?.ok_or_else(|| GitError::NotFound {
        detail: format!("no such stash slot: stash@{{{slot}}}"),
    })?;
    if entry.base_hex.is_empty() {
        return Err(GitError::Invalid {
            detail: "cannot branch a stash created on an unborn branch".to_owned(),
        });
    }
    let base = ruk_git::parse_oid_for(&entry.base_hex, kind)?;
    if super::state::read_ref(store, &branch_name(name)?)?.is_some() {
        return Err(GitError::Invalid {
            detail: format!("branch {name:?} already exists"),
        });
    }
    create_branch(store, kind, name, base)?;
    switch_head_to(ctx, HeadRef::Symbolic(branch_name(name)?))?;
    stash_apply_with_index(ctx, slot)?;
    stash_drop(store, slot)?;
    repoint_stash_ref(ctx)?;
    Ok(format!("Switched to a new branch '{name}'\n").into_bytes())
}

/// Derives the one-line subject the oracle prints in stash messages:
/// `pp_commit_easy(CMIT_FMT_ONELINE, ...)` (`git/pretty.c`
/// `format_subject` with `" "`). Leading blank lines are skipped and the
/// first paragraph's lines are joined with single spaces, so a multi-line
/// first paragraph reads as one line instead of truncating at the first
/// `\n`.
fn stash_subject(message: &[u8]) -> String {
    let text = String::from_utf8_lossy(message);
    let mut paragraph = Vec::new();
    let mut started = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            if started {
                break;
            }
            continue;
        }
        started = true;
        paragraph.push(line);
    }
    paragraph.join(" ")
}

/// Shortest unambiguous hex prefix of `oid` over stored commits, minimum 7:
/// git's `repo_find_unique_abbrev` (`DEFAULT_ABBREV`) extends the prefix
/// while another object shares it. Only the `Commits` table is enumerable
/// here, so a hypothetical collision against an unindexed blob or tree
/// still reads at 7; the commit set, where real collisions live, is exact.
fn unique_short_oid(store: &Store, oid: Oid) -> Result<String, GitError> {
    let hex = oid.to_hex();
    let records = ruk_core::records::Records::new(store);
    let budget = ruk_core::records::RecordPageBudget::new(4096, 1 << 26);
    let mut peers = Vec::new();
    let mut after = None;
    loop {
        let page = records
            .page_commits(after.as_ref(), budget)
            .map_err(GitError::from)?;
        for (head, _) in &page.items {
            if let Head::Git { oid: peer } = head {
                if *peer != oid {
                    peers.push(peer.to_hex());
                }
            }
        }
        after = page.next_cursor;
        if !page.more {
            break;
        }
    }
    let mut width = 7.min(hex.len());
    while width < hex.len() && peers.iter().any(|peer| peer.starts_with(&hex[..width])) {
        width += 1;
    }
    Ok(hex[..width].to_owned())
}

/// Records the index and worktree in oracle-shaped stash commits, then
/// resets both to `HEAD`.
///
/// Oracle: `git/builtin/stash.c` (`do_push_stash`). A push mints two
/// commits: an index commit (`tree` = index state, parent = `HEAD`,
/// subject `index on <branch>: <short> <subject>`) and a worktree commit
/// (`tree` = worktree state, parents = [`HEAD`, index commit], subject
/// `On <branch>: <msg>` or `WIP on ...`). `refs/stash` points at the
/// worktree commit, whose oid the later `Dropped` line names.
fn stash_push(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    for (_, stage, _) in &rows {
        if *stage != Stage::Zero {
            return Err(GitError::Invalid {
                detail: "cannot stash unmerged paths".to_owned(),
            });
        }
    }
    let Some(tip) = head_oid(store).ok() else {
        return Err(GitError::Invalid {
            detail: "You do not have the initial commit yet".to_owned(),
        });
    };
    let head_record = super::state::commit_record(store, tip)?;
    let head_tree = commit_tree_oid(&head_record)?;
    let head_subject = stash_subject(head_record.message());
    let head_short = unique_short_oid(store, tip)?;
    let index_tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let (worktree_rows, blobs) = worktree_overlay_rows(ctx, store, kind, &rows)?;
    if !blobs.is_empty() {
        store.publish(blobs, &[]).map_err(GitError::from)?;
    }
    let worktree_tree = build_index_tree(store, kind, &worktree_rows)?;
    if index_tree == head_tree && worktree_tree == head_tree {
        return Ok(b"No local changes to save\n".to_vec());
    }
    let branch = stash_branch_label(store)?;
    // The slot subject doubles as the worktree commit message, the way the
    // oracle records `On <branch>: <msg>` (or `WIP on ...` without `-m`).
    let message = match opts.single("message")? {
        Some(given) => format!("On {branch}: {given}"),
        None => format!("WIP on {branch}: {head_short} {head_subject}"),
    };
    let index_message = format!("index on {branch}: {head_short} {head_subject}");
    let author = super::state::identity(ctx, super::state::IdentityRole::Author)?;
    let committer = super::state::identity(ctx, super::state::IdentityRole::Committer)?;
    let base_heads = vec![Head::Git { oid: tip }];
    // Commit payloads carry the message verbatim. The oracle ends its index
    // message with a newline but leaves the worktree subject bare; the slot
    // subject matches the latter for `list` and the `Saved` line.
    let index_oid = mint_stash_commit(
        store,
        NewRequest {
            tree: index_tree,
            parents: base_heads.clone(),
            author: author.clone(),
            committer: committer.clone(),
            message: ruk_core::ByteString::from(format!("{index_message}\n").as_str()),
            change_id: None,
            predecessor: None,
            provenance: None,
        },
    )?;
    let mut wip_parents = base_heads;
    wip_parents.push(Head::Git { oid: index_oid });
    let commit_oid = mint_stash_commit(
        store,
        NewRequest {
            tree: worktree_tree,
            parents: wip_parents,
            author,
            committer,
            message: ruk_core::ByteString::from(message.as_str()),
            change_id: None,
            predecessor: None,
            provenance: None,
        },
    )?;
    let slot = stash_alloc(store)?;
    let slot_rows: Vec<(Vec<u8>, Stage, IndexEntry)> = rows
        .iter()
        .map(|(path, stage, entry)| (path.as_bytes().to_vec(), *stage, entry.clone()))
        .collect();
    stash_write(
        store,
        slot,
        &StashSlot {
            message: message.clone(),
            base_hex: tip.to_hex(),
            commit_hex: commit_oid.to_hex(),
            rows: slot_rows,
        },
    )?;
    let stash_ref = RefName::new("refs/stash").map_err(|err| GitError::Invalid {
        detail: format!("stash ref refused: {err}"),
    })?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: stash_ref,
            expected: RefExpect::Any,
            change: RefChange::Set(RefTarget::Direct(commit_oid)),
        }],
    )?;
    // `--keep-index` records the slot without resetting, leaving the
    // stashed changes staged the way the oracle does.
    if !opts.is_set("keep-index") {
        reset_index_tree(ctx, head_tree)?;
        let indexed: Vec<Vec<u8>> = rows
            .iter()
            .map(|(path, _, _)| path.as_bytes().to_vec())
            .collect();
        checkout_tree_files(ctx, store, kind, head_tree, &indexed)?;
    }
    Ok(format!("Saved working directory and index state {message}\n").into_bytes())
}

/// Mints one stash commit through the shared exportable path (no
/// `change-id` header, so oids match the oracle byte-for-byte) and returns
/// its object id. A byte-identical commit (same tree, parents, message,
/// and identity, as a repeated push of unchanged state produces) already
/// lives in the store, so only a missing commit is published — the oracle
/// likewise deduplicates by oid.
fn mint_stash_commit(store: &Store, request: NewRequest) -> Result<Oid, GitError> {
    let prepared = ops_prepare_new(store, request).map_err(GitError::from)?;
    let oid = prepared
        .output
        .oid
        .or_else(|| prepared.output.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "stash commit has no git identity".to_owned(),
        })?;
    let missing = match super::state::commit_record(store, oid) {
        Ok(_) => false,
        Err(GitError::NotFound { .. }) => true,
        Err(err) => return Err(err),
    };
    if missing {
        store
            .publish(prepared.objects, &prepared.facts)
            .map_err(GitError::from)?;
    }
    Ok(oid)
}

/// Builds `(path, entry)` rows for the stash worktree tree: the tracked
/// index rows with every on-disk file's bytes re-hashed, so unstaged edits
/// land in the `WIP` commit the way the oracle records them. Files missing
/// from disk drop out (staged deletions); gitlinks keep their index entry;
/// untracked files are never read. Returns the rows plus the newly staged
/// blob objects for the caller to publish.
fn worktree_overlay_rows(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    rows: &[(RepoPath, Stage, IndexEntry)],
) -> Result<
    (
        Vec<(Vec<u8>, IndexEntry)>,
        Vec<ruk_core::store::PreparedObject>,
    ),
    GitError,
> {
    let mut out = Vec::new();
    let mut objects = Vec::new();
    for (path, stage, entry) in rows {
        if *stage != Stage::Zero {
            continue;
        }
        if entry.mode() == FileMode::Gitlink {
            out.push((path.as_bytes().to_vec(), entry.clone()));
            continue;
        }
        let full = join_base(&ctx.file_base, path.as_bytes())?;
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(GitError::Io {
                    detail: format!("statting {}: {err}", full.display()),
                });
            }
        };
        if meta.file_type().is_dir() {
            continue;
        }
        let (mode, bytes) = if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&full).map_err(|err| GitError::Io {
                detail: format!("reading link {}: {err}", full.display()),
            })?;
            (
                FileMode::Symlink,
                target.as_os_str().as_encoded_bytes().to_vec(),
            )
        } else {
            let bytes = std::fs::read(&full).map_err(|err| GitError::Io {
                detail: format!("reading {}: {err}", full.display()),
            })?;
            (super::verbs_stage::file_mode_of(&meta), bytes)
        };
        let hashed = IndexEntry::for_blob(kind, mode, &bytes, None)
            .map_err(|err| GitError::from(CoreError::from(err)))?;
        let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
            detail: format!(
                "file {} exceeds the length range",
                String::from_utf8_lossy(path.as_bytes())
            ),
        })?;
        let prepared = store
            .prepare(
                ruk_core::store::types::ObjectKind::Blob,
                len,
                std::io::Cursor::new(bytes),
                None,
            )
            .map_err(GitError::from)?;
        objects.push(prepared);
        out.push((path.as_bytes().to_vec(), hashed));
    }
    Ok((out, objects))
}

/// Names every path the stash changes: entries whose `(mode, oid)` differ
/// between the `WIP` tree and the base tree, including additions and
/// deletions. The restore guards and rewrites only these paths; anything
/// else keeps its worktree and index state, the way the oracle's merge
/// only touches stash-changed paths.
fn stash_touched_paths(
    wip: &[(Vec<u8>, TreeMode, Oid)],
    base: &[(Vec<u8>, TreeMode, Oid)],
) -> Vec<Vec<u8>> {
    let mut wip_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in wip {
        wip_map.insert(path.clone(), (*mode, *oid));
    }
    let mut base_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in base {
        base_map.insert(path.clone(), (*mode, *oid));
    }
    let mut touched = Vec::new();
    for (path, entry) in &wip_map {
        if base_map.get(path) != Some(entry) {
            touched.push(path.clone());
        }
    }
    for path in base_map.keys() {
        if !wip_map.contains_key(path.as_slice()) {
            touched.push(path.clone());
        }
    }
    touched.sort();
    touched
}

/// Refuses a restore whose `WIP` tree would overwrite unsaved worktree
/// edits on stash-touched paths. A touched path passes when it is missing
/// on disk, already holds the `WIP` bytes (re-apply), or still holds the
/// base bytes (clean restore); anything else — including an untracked file
/// where the stash adds one — errors instead of clobbering, the way the
/// oracle refuses an overwriting merge. Untouched paths are never read:
/// unrelated worktree edits stay.
fn refuse_worktree_overwrite(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    tree: Oid,
    base_paths: &[(Vec<u8>, TreeMode, Oid)],
) -> Result<(), GitError> {
    let mut wip: std::collections::BTreeMap<Vec<u8>, (TreeMode, Oid)> =
        std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        wip.insert(path, (mode, oid));
    }
    let mut base: std::collections::BTreeMap<Vec<u8>, (TreeMode, Oid)> =
        std::collections::BTreeMap::new();
    for (path, mode, oid) in base_paths {
        base.insert(path.clone(), (*mode, *oid));
    }
    let mut union: Vec<&Vec<u8>> = wip.keys().collect();
    for path in base.keys() {
        if !wip.contains_key(path.as_slice()) {
            union.push(path);
        }
    }
    let mut blocked = Vec::new();
    for path in union {
        // Only stash-touched paths can collide with the restore: an
        // untouched path keeps its worktree bytes whatever they are, so
        // unrelated edits never block. The `(mode, oid)` comparison keeps
        // this in step with `stash_touched_paths`, so even a pure mode
        // change is checked (its bytes match either side and pass).
        if wip.get(path) == base.get(path) {
            continue;
        }
        let full = join_base(&ctx.file_base, path)?;
        let disk = match std::fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_dir() => None,
            Ok(meta) if meta.file_type().is_symlink() => std::fs::read_link(&full)
                .ok()
                .map(|target| target.as_os_str().as_encoded_bytes().to_vec()),
            Ok(_) => std::fs::read(&full).ok(),
            Err(_) => None,
        };
        let Some(disk) = disk else {
            // Missing on disk, or a directory where the stash names a file:
            // the checkout recreates the first and fails loudly on the
            // second, so neither silently loses edits.
            if std::fs::symlink_metadata(&full).is_ok() {
                blocked.push(String::from_utf8_lossy(path).into_owned());
            }
            continue;
        };
        let matches = |entry: Option<&(TreeMode, Oid)>| {
            entry.is_some_and(|(_, want)| {
                read_object_bytes(store, *want)
                    .ok()
                    .is_some_and(|(_, body)| body == disk)
            })
        };
        if !matches(wip.get(path)) && !matches(base.get(path)) {
            blocked.push(String::from_utf8_lossy(path).into_owned());
        }
    }
    if blocked.is_empty() {
        return Ok(());
    }
    blocked.sort();
    Err(GitError::Invalid {
        detail: format!(
            "worktree has changes; stash apply needs a clean worktree: {}",
            blocked.join(", ")
        ),
    })
}

/// Writes every path of `tree` into the worktree and deletes the `extra`
/// paths missing from it. Only `tree` members and `extra` entries are ever
/// touched: untracked files stay. Callers pass the paths the old index or
/// `HEAD` named, so a push resets the worktree to `HEAD` and an apply
/// restores the `WIP` tree including its deletions.
fn checkout_tree_files(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    tree: Oid,
    extra: &[Vec<u8>],
) -> Result<(), GitError> {
    let mut wanted: std::collections::BTreeMap<Vec<u8>, (TreeMode, Oid)> =
        std::collections::BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        wanted.insert(path, (mode, oid));
    }
    for (path, (mode, oid)) in &wanted {
        let full = join_base(&ctx.file_base, path)?;
        if *mode == TreeMode::Gitlink {
            continue;
        }
        if *mode == TreeMode::Symlink {
            create_worktree_link(store, *oid, &full)?;
            continue;
        }
        let (_, body) = read_object_bytes(store, *oid)?;
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
            let permissions = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&full, permissions).map_err(|err| GitError::Io {
                detail: format!("chmod {}: {err}", full.display()),
            })?;
        }
    }
    for raw in extra {
        if wanted.contains_key(raw) {
            continue;
        }
        let Ok(full) = join_base(&ctx.file_base, raw) else {
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

/// Names the stashed branch shortened, `(no branch)` when detached, for
/// the `On <branch>: <msg>` stash subject.
fn stash_branch_label(store: &Store) -> Result<String, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => Ok(name
            .to_utf8()
            .unwrap_or_default()
            .trim_start_matches("refs/heads/")
            .to_owned()),
        HeadRef::Detached(_) => Ok("(no branch)".to_owned()),
    }
}

/// Lists every live stash slot in number order.
fn stash_list(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let mut out = Vec::new();
    for slot in live_slots(store)? {
        let Some(entry) = stash_read(store, slot)? else {
            continue;
        };
        out.extend_from_slice(format!("stash@{{{slot}}}: {}\n", entry.message).as_bytes());
    }
    Ok(out)
}

/// Shows the files one stash slot holds.
fn stash_show(ctx: &Ctx, slot: Option<u64>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entry = stash_read(store, slot.unwrap_or(0))?.ok_or_else(|| GitError::NotFound {
        detail: "no such stash slot".to_owned(),
    })?;
    let commit_oid = ruk_git::parse_oid_for(&entry.commit_hex, kind)?;
    let record = super::state::commit_record(store, commit_oid)?;
    let tree = commit_tree_oid(&record)?;
    let mut out = Vec::new();
    for (path, _, _) in flatten_tree(store, kind, tree)? {
        out.extend_from_slice(format!(" {}\n", String::from_utf8_lossy(&path)).as_bytes());
    }
    Ok(out)
}

/// Drops one stash slot and repoints `refs/stash` at the newest survivor.
fn stash_drop_slot(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entry = stash_read(store, slot)?.ok_or_else(|| GitError::NotFound {
        detail: format!("no such stash slot: stash@{{{slot}}}"),
    })?;
    let commit_hex = entry.commit_hex.clone();
    stash_drop(store, slot)?;
    repoint_stash_ref(ctx)?;
    Ok(format!("Dropped refs/stash@{{{slot}}} ({commit_hex})\n").into_bytes())
}

/// Points `refs/stash` at the newest live slot, deleting it when empty.
fn repoint_stash_ref(ctx: &Ctx) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let stash_ref = RefName::new("refs/stash").map_err(|err| GitError::Invalid {
        detail: format!("stash ref refused: {err}"),
    })?;
    let newest = live_slots(store)?.last().copied();
    match newest {
        Some(slot) => {
            let entry = stash_read(store, slot)?.ok_or_else(|| GitError::Corrupt {
                detail: format!("stash slot {slot} vanished"),
            })?;
            let commit_oid = ruk_git::parse_oid_for(&entry.commit_hex, kind)?;
            apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: stash_ref,
                    expected: RefExpect::Any,
                    change: RefChange::Set(RefTarget::Direct(commit_oid)),
                }],
            )?;
        }
        None => {
            if super::state::read_ref(store, &stash_ref)?.is_some() {
                apply_refs(
                    store,
                    kind,
                    vec![RefUpdate {
                        name: stash_ref,
                        expected: RefExpect::Any,
                        change: RefChange::Delete,
                    }],
                )?;
            }
        }
    }
    Ok(())
}

/// Collects every live stash slot number in order.
fn live_slots(store: &Store) -> Result<Vec<u64>, GitError> {
    let mut out = Vec::new();
    for slot in 0..super::state::stash_high_water(store)? {
        if stash_read(store, slot)?.is_some() {
            out.push(slot);
        }
    }
    Ok(out)
}

/// Whether a stash restore also brings back the stashed index rows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexRestore {
    /// Worktree files only, like `apply`/`pop` without `--index`: a stashed
    /// staged change comes back unstaged.
    Worktree,
    /// Worktree files plus index rows (`--index`, `stash branch`).
    WorktreeAndIndex,
}

/// Dispatches `apply` on the parsed `--index` flag to its named entry point.
fn stash_apply_scoped(ctx: &Ctx, slot: u64, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.is_set("index") {
        stash_apply_with_index(ctx, slot)
    } else {
        stash_apply(ctx, slot)
    }
}

/// Dispatches `pop` on the parsed `--index` flag to its named entry point.
fn stash_pop_scoped(ctx: &Ctx, slot: u64, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.is_set("index") {
        stash_pop_with_index(ctx, slot)
    } else {
        stash_pop(ctx, slot)
    }
}

/// Restores one slot's worktree files, requiring `HEAD` and refusing only
/// staged changes on paths the stash touches.
fn stash_apply(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_restore(ctx, slot, IndexRestore::Worktree)
}

/// Restores one slot's worktree files and its index rows, requiring `HEAD`
/// and refusing only staged changes on paths the stash touches.
fn stash_apply_with_index(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_restore(ctx, slot, IndexRestore::WorktreeAndIndex)
}

/// Refuses a restore whose index holds staged changes on stash-touched
/// paths: unmerged stages always, and stage-zero rows matching neither the
/// base nor the `WIP` entry. Anything else — including staged changes on
/// paths the stash never names — restores cleanly, the way the oracle only
/// refuses overlapping local changes. A row already holding the base entry
/// is an unstaged-only change governed by the worktree guard; a row
/// already holding the `WIP` entry is consistent with the restore.
fn refuse_index_overlap(
    current: &[(RepoPath, Stage, IndexEntry)],
    wip: &[(Vec<u8>, TreeMode, Oid)],
    base: &[(Vec<u8>, TreeMode, Oid)],
    touched: &[Vec<u8>],
) -> Result<(), GitError> {
    let entry_matches = |rows: &[(Vec<u8>, TreeMode, Oid)], path: &[u8], row: &IndexEntry| {
        rows.iter().any(|(known, mode, oid)| {
            known.as_slice() == path
                && mode
                    .as_index_mode()
                    .is_ok_and(|index_mode| index_mode == row.mode())
                && *oid == row.oid()
        })
    };
    let mut blocked = Vec::new();
    for (path, stage, row) in current {
        if *stage != Stage::Zero {
            blocked.push(format!(
                "{} (unmerged)",
                String::from_utf8_lossy(path.as_bytes())
            ));
            continue;
        }
        let raw = path.as_bytes();
        if !touched.iter().any(|known| known.as_slice() == raw) {
            continue;
        }
        if !entry_matches(base, raw, row) && !entry_matches(wip, raw, row) {
            blocked.push(String::from_utf8_lossy(raw).into_owned());
        }
    }
    if blocked.is_empty() {
        return Ok(());
    }
    blocked.sort();
    Err(GitError::Invalid {
        detail: format!(
            "index has changes; stash apply needs a clean index on: {}",
            blocked.join(", ")
        ),
    })
}

/// Whether validated index rows for one path match the base tree entry:
/// the stash staged nothing there (or the path never existed), so an
/// `--index` restore must leave the current rows alone instead of
/// restoring over them.
fn stash_recorded_is_base(stashed: &[(Stage, IndexEntry)], base: Option<(TreeMode, Oid)>) -> bool {
    match (stashed, base) {
        ([], None) => true,
        ([(Stage::Zero, row)], Some((mode, oid))) => {
            mode.as_index_mode()
                .is_ok_and(|index_mode| index_mode == row.mode())
                && oid == row.oid()
        }
        _ => false,
    }
}

/// Refuses `--index` when the current index holds staged changes the
/// recorded rows cannot absorb. On paths where the stash staged something
/// (recorded rows differ from the base entry) the current rows must match
/// the recorded rows or the base entry; anything else would silently
/// clobber staged work the oracle would merge-or-refuse instead. Paths
/// where the stash staged nothing keep their current rows unconditionally,
/// the way the oracle merges the stashed index state alongside unrelated
/// staged changes.
fn refuse_index_restore_conflict(
    current: &[(RepoPath, Stage, IndexEntry)],
    entry: &StashSlot,
    base: &[(Vec<u8>, TreeMode, Oid)],
    kind: HashKind,
) -> Result<(), GitError> {
    let mut base_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in base {
        base_map.insert(path.as_slice(), (*mode, *oid));
    }
    let mut recorded: std::collections::BTreeMap<&[u8], Vec<(Stage, IndexEntry)>> =
        std::collections::BTreeMap::new();
    for (raw, stage, row) in &entry.rows {
        if row.validate(kind).is_err() {
            continue;
        }
        recorded
            .entry(raw.as_slice())
            .or_default()
            .push((*stage, row.clone()));
    }
    let mut union: std::collections::BTreeSet<&[u8]> = recorded.keys().copied().collect();
    for (path, _, _) in current {
        union.insert(path.as_bytes());
    }
    let mut blocked = Vec::new();
    for raw in union {
        let base_entry = base_map.get(raw).copied();
        let rec: &[(Stage, IndexEntry)] = recorded.get(raw).map_or(&[], Vec::as_slice);
        if stash_recorded_is_base(rec, base_entry) {
            continue;
        }
        let cur: Vec<(Stage, IndexEntry)> = current
            .iter()
            .filter(|(path, _, _)| path.as_bytes() == raw)
            .map(|(_, stage, row)| (*stage, row.clone()))
            .collect();
        if cur.as_slice() == rec || stash_recorded_is_base(&cur, base_entry) {
            continue;
        }
        blocked.push(String::from_utf8_lossy(raw).into_owned());
    }
    if blocked.is_empty() {
        return Ok(());
    }
    blocked.sort();
    Err(GitError::Invalid {
        detail: format!(
            "index has changes; stash apply --index cannot restore over: {}",
            blocked.join(", ")
        ),
    })
}

/// Writes only the stash-touched paths of the `WIP` tree into the worktree
/// and deletes the touched paths the stash drops. Untouched paths keep
/// whatever the worktree holds — including unrelated staged or unstaged
/// edits — because the restore never names them; anything else on disk
/// (untracked files) stays.
fn checkout_stash_files(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    wip: &[(Vec<u8>, TreeMode, Oid)],
    touched: &[Vec<u8>],
) -> Result<(), GitError> {
    let mut wanted: std::collections::BTreeMap<Vec<u8>, (TreeMode, Oid)> =
        std::collections::BTreeMap::new();
    for (path, mode, oid) in wip {
        if touched
            .iter()
            .any(|known| known.as_slice() == path.as_slice())
        {
            wanted.insert(path.clone(), (*mode, *oid));
        }
    }
    for (path, (mode, oid)) in &wanted {
        let full = join_base(&ctx.file_base, path)?;
        if *mode == TreeMode::Gitlink {
            continue;
        }
        if *mode == TreeMode::Symlink {
            create_worktree_link(store, *oid, &full)?;
            continue;
        }
        let (_, body) = read_object_bytes(store, *oid)?;
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
            let permissions = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&full, permissions).map_err(|err| GitError::Io {
                detail: format!("chmod {}: {err}", full.display()),
            })?;
        }
    }
    for raw in touched {
        if wanted.contains_key(raw) {
            continue;
        }
        let Ok(full) = join_base(&ctx.file_base, raw) else {
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

/// Restores one slot's worktree files from its `WIP` commit, and its index
/// rows too under [`IndexRestore::WorktreeAndIndex`].
///
/// Oracle: `git/builtin/stash.c` (`do_apply_stash`). Without `--index` the
/// oracle leaves the index on the base, so a stashed staged change comes
/// back unstaged; `stash branch` always restores the index. Only
/// stash-touched paths are guarded and rewritten: staged or worktree edits
/// elsewhere restore cleanly instead of demanding a fully clean tree.
fn stash_restore(ctx: &Ctx, slot: u64, scope: IndexRestore) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entry = stash_read(store, slot)?.ok_or_else(|| GitError::NotFound {
        detail: format!("no such stash slot: stash@{{{slot}}}"),
    })?;
    let base = head_oid(store)
        .ok()
        .map(|tip| tip.to_hex())
        .unwrap_or_default();
    if entry.base_hex != base {
        return Err(GitError::Unsupported {
            command: "stash restore with a moved HEAD needs the merge lane".to_owned(),
        });
    }
    let commit_oid = ruk_git::parse_oid_for(&entry.commit_hex, kind)?;
    let record = super::state::commit_record(store, commit_oid)?;
    let tree = commit_tree_oid(&record)?;
    let wip_paths = flatten_tree(store, kind, tree)?;
    let base_paths = if entry.base_hex.is_empty() {
        Vec::new()
    } else {
        let base_oid = ruk_git::parse_oid_for(&entry.base_hex, kind)?;
        let base_record = super::state::commit_record(store, base_oid)?;
        flatten_tree(store, kind, commit_tree_oid(&base_record)?)?
    };
    let touched = stash_touched_paths(&wip_paths, &base_paths);
    let current = scan_index(store, kind)?;
    refuse_index_overlap(&current, &wip_paths, &base_paths, &touched)?;
    if scope == IndexRestore::WorktreeAndIndex {
        refuse_index_restore_conflict(&current, &entry, &base_paths, kind)?;
    }
    refuse_worktree_overwrite(ctx, store, kind, tree, &base_paths)?;
    checkout_stash_files(ctx, store, kind, &wip_paths, &touched)?;
    if scope == IndexRestore::WorktreeAndIndex {
        restore_stash_index(store, kind, &current, &entry, &base_paths)?;
    }
    let plan = super::verbs_stage::status_plan(ctx, store, kind)?;
    let branch = super::verbs_stage::long_branch_label(store)?;
    Ok(super::verbs_stage::render_long(store, &branch, &plan))
}

/// Writes one slot's recorded index rows back into the index. Paths where
/// the stash staged nothing keep their current rows, so `--index` restores
/// alongside unrelated staged changes instead of deleting them; paths
/// where it staged something take the recorded rows authoritatively, the
/// way the oracle reinstates the stashed index. The conflict guard runs
/// first, so a recorded path never overwrites divergent staged work here.
fn restore_stash_index(
    store: &Store,
    kind: HashKind,
    current: &[(RepoPath, Stage, IndexEntry)],
    entry: &StashSlot,
    base: &[(Vec<u8>, TreeMode, Oid)],
) -> Result<(), GitError> {
    let (workspace, raw) = load_or_default(store)?;
    let mut base_map = std::collections::BTreeMap::new();
    for (path, mode, oid) in base {
        base_map.insert(path.as_slice(), (*mode, *oid));
    }
    let mut mutations = Vec::new();
    let mut union: Vec<RepoPath> = current.iter().map(|(path, _, _)| path.clone()).collect();
    for (path_bytes, _, _) in &entry.rows {
        let path = RepoPath::new(path_bytes.clone())
            .map_err(|err| GitError::from(CoreError::from(err)))?;
        if !union.contains(&path) {
            union.push(path);
        }
    }
    for path in union {
        let stashed: Vec<(Stage, IndexEntry)> = entry
            .rows
            .iter()
            .filter(|(known, _, _)| *known == path.as_bytes())
            .filter_map(|(_, stage, row)| row.validate(kind).ok().map(|()| (*stage, row.clone())))
            .collect();
        if stash_recorded_is_base(&stashed, base_map.get(path.as_bytes()).copied()) {
            continue;
        }
        let before = read_path_rows(store, kind, &path)?;
        mutations.extend(path_row_mutations(&path, &before, &stashed)?);
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Applies one slot and drops it, reporting the worktree status plus the
/// `Dropped refs/stash@{n} (<oid>)` line like the oracle.
fn stash_pop(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_pop_inner(ctx, slot, IndexRestore::Worktree)
}

/// Applies one slot with its index rows and drops it, reporting the
/// worktree status plus the `Dropped` line like `pop --index`.
fn stash_pop_with_index(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_pop_inner(ctx, slot, IndexRestore::WorktreeAndIndex)
}

/// Applies one slot under `scope` and drops it, reporting the worktree
/// status plus the `Dropped refs/stash@{n} (<oid>)` line like the oracle.
fn stash_pop_inner(ctx: &Ctx, slot: u64, scope: IndexRestore) -> Result<Vec<u8>, GitError> {
    stash_restore(ctx, slot, scope)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let entry = stash_read(store, slot)?.ok_or_else(|| GitError::NotFound {
        detail: format!("no such stash slot: stash@{{{slot}}}"),
    })?;
    let commit_hex = entry.commit_hex.clone();
    stash_drop(store, slot)?;
    repoint_stash_ref(ctx)?;
    let plan = super::verbs_stage::status_plan(ctx, store, kind)?;
    let branch = super::verbs_stage::long_branch_label(store)?;
    let mut out = super::verbs_stage::render_long(store, &branch, &plan);
    out.extend_from_slice(format!("Dropped refs/stash@{{{slot}}} ({commit_hex})\n").as_bytes());
    Ok(out)
}

/// Deletes every stash slot and the stash ref.
fn stash_clear(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for slot in live_slots(store)? {
        stash_drop(store, slot)?;
    }
    let stash_ref = RefName::new("refs/stash").map_err(|err| GitError::Invalid {
        detail: format!("stash ref refused: {err}"),
    })?;
    if super::state::read_ref(store, &stash_ref)?.is_some() {
        apply_refs(
            store,
            kind,
            vec![RefUpdate {
                name: stash_ref,
                expected: RefExpect::Any,
                change: RefChange::Delete,
            }],
        )?;
    }
    Ok(Vec::new())
}
