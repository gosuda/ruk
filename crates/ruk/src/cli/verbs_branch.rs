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
    path_row_mutations, read_path_rows, reflog_alloc, resolve_branch_target, resolve_rev,
    scan_index, stash_alloc, stash_drop, stash_read, stash_write, workspace_mutation,
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
            short: None,
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
        // Accepted for script compatibility: branch output is already quiet
        // except for the delete notice, which this suppresses.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
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
    match opts.positionals.as_slice() {
        [] => list_branches(ctx, &opts),
        _ if opts.is_set("list") => list_branches(ctx, &opts),
        _ if opts.is_set("remotes") || opts.is_set("all") => Err(GitError::Invalid {
            detail: "the -a, and -r, options to 'git branch' do not take a branch name.\nDid you mean to use: -a|-r --list <pattern>?".to_owned(),
        }),
        [name] => {
            let refname = branch_name(name)?;
            if super::state::read_ref(store, &refname)?.is_some() {
                if !opts.is_set("force") {
                    return Err(GitError::Invalid {
                        detail: format!("branch {name:?} already exists"),
                    });
                }
                refuse_checked_out_branch(store, name)?;
                let target = resolve_branch_target(store, ctx.kind()?, None)?;
                force_branch(store, ctx.kind()?, name, target)?;
                return Ok(Vec::new());
            }
            let target = resolve_branch_target(store, ctx.kind()?, None)?;
            create_branch(store, ctx.kind()?, name, target)?;
            Ok(Vec::new())
        }
        [name, start] => {
            let target = resolve_branch_target(store, ctx.kind()?, Some(start))?;
            if !opts.is_set("force") {
                let refname = branch_name(name)?;
                if super::state::read_ref(store, &refname)?.is_some() {
                    return Err(GitError::Invalid {
                        detail: format!("branch {name:?} already exists"),
                    });
                }
            } else {
                refuse_checked_out_branch(store, name)?;
            }
            force_branch(store, ctx.kind()?, name, target)?;
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

/// Lists local branches, current marked, with optional remotes and oids.
fn list_branches(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let current = current_branch_name(store)?;
    let remotes_only = opts.is_set("remotes");
    let mut out = Vec::new();
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
        if opts.is_set("verbose") {
            let detail = ref_detail(ctx, &target)?;
            out.extend_from_slice(format!("{mark} {short} {detail}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{mark} {short}\n").as_bytes());
        }
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
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("track") {
        return checkout_new_branch_tracked(ctx, &opts);
    }
    if let Some(name) = opts.single("branch")? {
        let start = opts.positionals.first().map(String::as_str);
        return checkout_new_branch(ctx, &name, start, false, opts.is_set("quiet"));
    }
    if let Some(name) = opts.single("force-branch")? {
        let start = opts.positionals.first().map(String::as_str);
        return checkout_new_branch(ctx, &name, start, true, opts.is_set("quiet"));
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
            switch_to_rev(ctx, rev, opts.is_set("quiet"))
        }
        _ => checkout_paths(ctx, &opts),
    }
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

/// Restores worktree paths from the index or one revision's tree.
fn checkout_paths(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut positionals = opts.positionals.as_slice();
    if positionals.first().is_some_and(|first| *first == "--") {
        positionals = &positionals[1..];
    }
    let (tree_paths, source_tree) = match positionals {
        [] => {
            return Err(GitError::Invalid {
                detail: "checkout needs paths".to_owned(),
            });
        }
        [single] => (std::slice::from_ref(single), None),
        [rev, rest @ ..] => {
            let oid = resolve_rev(store, kind, rev)?;
            (rest, Some(peel_to_tree(store, kind, oid)?))
        }
    };
    let entries = match source_tree {
        Some(tree) => {
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
    for wanted in tree_paths {
        let path = super::verbs_stage::repo_path_of(ctx, wanted.as_bytes())?;
        let oid = entries
            .get(path.as_bytes())
            .ok_or_else(|| GitError::NotFound {
                detail: format!("pathspec did not match: {wanted:?}"),
            })?;
        let (_, body) = read_object_bytes(store, *oid)?;
        let full = super::tree::join_base(&ctx.file_base, path.as_bytes())?;
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
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if let Some(name) = opts.single("create")? {
        let start = opts.positionals.first().map(String::as_str);
        return checkout_new_branch(ctx, &name, start, false, opts.is_set("quiet"));
    }
    if let Some(name) = opts.single("force-create")? {
        let start = opts.positionals.first().map(String::as_str);
        return checkout_new_branch(ctx, &name, start, true, opts.is_set("quiet"));
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
                return detach_at(ctx, tip);
            }
            switch_guessing(ctx, branch, !opts.is_set("no-guess"), opts.is_set("quiet"))
        }
        _ => Err(GitError::Invalid {
            detail: "usage: switch [-c <new>] [<branch>]".to_owned(),
        }),
    }
}

/// Switches to a branch, guessing a remote-tracking start when missing,
/// reporting the switch on stderr like the oracle.
fn switch_guessing(
    ctx: &mut Ctx,
    branch: &str,
    guess: bool,
    quiet: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if let Ok(name) = branch_name(branch) {
        if super::state::read_ref(store, &name)?.is_some() {
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
                create_branch(store, kind, branch, target)?;
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
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("merge") || opts.is_set("keep") {
        return Err(GitError::Unsupported {
            command: "reset --merge and --keep need the merge lane".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (rev, paths) = match opts.positionals.as_slice() {
        [] => (None, &[][..]),
        [single] if single == "--" => (None, &[][..]),
        [single] => (Some(single.clone()), &[][..]),
        [first, rest @ ..] if *first == *"--" => (None, rest),
        [first, rest @ ..] => (Some(first.clone()), rest),
    };
    if !paths.is_empty() {
        let tree = match rev {
            Some(rev) => {
                let oid = resolve_rev(store, kind, &rev)?;
                peel_to_tree(store, kind, oid)?
            }
            None => head_tree_committed(ctx)?,
        };
        let pseudo = super::Collected {
            present: Default::default(),
            positionals: paths.to_vec(),
        };
        return restore_staged(ctx, &pseudo, tree).map(|()| Vec::new());
    }
    let target = match rev {
        Some(rev) => resolve_rev(store, kind, &rev)?,
        None => head_oid(store)?,
    };
    let modes = [
        opts.is_set("soft"),
        opts.is_set("mixed"),
        opts.is_set("hard"),
    ];
    if modes.iter().filter(|set| **set).count() > 1 {
        return Err(GitError::Invalid {
            detail: "reset takes at most one of --soft, --mixed, --hard".to_owned(),
        });
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
    ];
    // `-n[<num>]` takes an optional attached value, which the shared parser
    // cannot express: normalize to a remembered line count.
    let mut annotation_lines: Option<usize> = None;
    let mut rewritten = Vec::with_capacity(args.len());
    for arg in args {
        if arg == "-n" {
            annotation_lines = Some(1);
        } else if let Some(digits) = arg.strip_prefix("-n") {
            annotation_lines = Some(digits.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad -n value {arg:?}"),
            })?);
        } else {
            rewritten.push(arg.clone());
        }
    }
    let opts = collect(&rewritten, &specs)?;
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
    // `-n` implies `-l` in the oracle, and the no-arg form already lists.
    let lines = annotation_lines.unwrap_or(0);
    match opts.positionals.as_slice() {
        [] => list_tags(ctx, &opts, None, lines),
        [pattern] if opts.is_set("list") || annotation_lines.is_some() => {
            list_tags(ctx, &opts, Some(pattern), lines)
        }
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
    let mut out = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        if !text.starts_with("refs/tags/") {
            continue;
        }
        let short = text.trim_start_matches("refs/tags/");
        if !patterns.is_empty() && !patterns.iter().any(|pattern| glob_match(pattern, short)) {
            continue;
        }
        if lines == 0 {
            out.extend_from_slice(format!("{short}\n").as_bytes());
            continue;
        }
        let shown = tag_message_lines(ctx, &target, lines)?;
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
    let pointed = if opts.is_set("annotate")
        || opts.single("message")?.is_some()
        || opts.single("file")?.is_some()
    {
        let message = match opts.single("message")? {
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

/// Refuses a restore whose `WIP` tree would overwrite unsaved worktree
/// edits. A path passes when it is missing on disk, already holds the
/// `WIP` bytes (re-apply), or still holds the base bytes (clean restore);
/// anything else — including an untracked file where the stash adds one —
/// errors instead of clobbering, the way the oracle refuses an overwriting
/// merge.
fn refuse_worktree_overwrite(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    tree: Oid,
    base_paths: &[(Vec<u8>, TreeMode, Oid)],
) -> Result<(), GitError> {
    let mut wip: std::collections::BTreeMap<Vec<u8>, Oid> = std::collections::BTreeMap::new();
    for (path, _, oid) in flatten_tree(store, kind, tree)? {
        wip.insert(path, oid);
    }
    let mut base: std::collections::BTreeMap<Vec<u8>, Oid> = std::collections::BTreeMap::new();
    for (path, _, oid) in base_paths {
        base.insert(path.clone(), *oid);
    }
    let mut union: Vec<&Vec<u8>> = wip.keys().collect();
    for path in base.keys() {
        if !wip.contains_key(path.as_slice()) {
            union.push(path);
        }
    }
    let mut blocked = Vec::new();
    for path in union {
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
        let matches = |oid: Option<&Oid>| {
            oid.is_some_and(|want| {
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

/// Restores one slot's worktree files, requiring `HEAD` and a clean index
/// on the stashed base.
fn stash_apply(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_restore(ctx, slot, IndexRestore::Worktree)
}

/// Restores one slot's worktree files and its index rows, requiring `HEAD`
/// and a clean index on the stashed base.
fn stash_apply_with_index(ctx: &Ctx, slot: u64) -> Result<Vec<u8>, GitError> {
    stash_restore(ctx, slot, IndexRestore::WorktreeAndIndex)
}

/// Restores one slot's worktree files from its `WIP` commit, and its index
/// rows too under [`IndexRestore::WorktreeAndIndex`].
///
/// Oracle: `git/builtin/stash.c` (`do_apply_stash`). Without `--index` the
/// oracle leaves the index on the base, so a stashed staged change comes
/// back unstaged; `stash branch` always restores the index.
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
    let current = scan_index(store, kind)?;
    if !current.is_empty() {
        let base_tree = if entry.base_hex.is_empty() {
            None
        } else {
            let base_oid = ruk_git::parse_oid_for(&entry.base_hex, kind)?;
            let record = super::state::commit_record(store, base_oid)?;
            Some(commit_tree_oid(&record)?)
        };
        let clean = match base_tree {
            None => false,
            Some(tree) => {
                let mut target = std::collections::BTreeMap::new();
                for (path, mode, oid) in flatten_tree(store, kind, tree)? {
                    target.insert(path, (mode, oid));
                }
                current.len() == target.len()
                    && current.iter().all(|(path, stage, row)| {
                        *stage == Stage::Zero
                            && target.get(path.as_bytes()).is_some_and(|(mode, oid)| {
                                mode.as_index_mode()
                                    .map_or(false, |index_mode| index_mode == row.mode())
                                    && *oid == row.oid()
                            })
                    })
            }
        };
        if !clean {
            return Err(GitError::Invalid {
                detail: "index has changes; stash apply needs a clean index".to_owned(),
            });
        }
    }
    let commit_oid = ruk_git::parse_oid_for(&entry.commit_hex, kind)?;
    let record = super::state::commit_record(store, commit_oid)?;
    let tree = commit_tree_oid(&record)?;
    let base_paths = if entry.base_hex.is_empty() {
        Vec::new()
    } else {
        let base_oid = ruk_git::parse_oid_for(&entry.base_hex, kind)?;
        let base_record = super::state::commit_record(store, base_oid)?;
        flatten_tree(store, kind, commit_tree_oid(&base_record)?)?
    };
    // Restore the worktree from the `WIP` tree. Paths the stash deletes come
    // back out through the base-tree and current-index extras; anything else
    // on disk (untracked files) stays.
    let mut extra: Vec<Vec<u8>> = Vec::new();
    for (path, _, _) in &base_paths {
        if !extra
            .iter()
            .any(|known| known.as_slice() == path.as_slice())
        {
            extra.push(path.clone());
        }
    }
    for (path, stage, _) in &current {
        if *stage == Stage::Zero
            && !extra
                .iter()
                .any(|known| known.as_slice() == path.as_bytes())
        {
            extra.push(path.as_bytes().to_vec());
        }
    }
    refuse_worktree_overwrite(ctx, store, kind, tree, &base_paths)?;
    checkout_tree_files(ctx, store, kind, tree, &extra)?;
    if scope == IndexRestore::WorktreeAndIndex {
        restore_stash_index(store, kind, &current, &entry)?;
    }
    let plan = super::verbs_stage::status_plan(ctx, store, kind)?;
    let branch = super::verbs_stage::long_branch_label(store)?;
    Ok(super::verbs_stage::render_long(store, &branch, &plan))
}

/// Writes one slot's recorded index rows back into the index.
fn restore_stash_index(
    store: &Store,
    kind: HashKind,
    current: &[(RepoPath, Stage, IndexEntry)],
    entry: &StashSlot,
) -> Result<(), GitError> {
    let (workspace, raw) = load_or_default(store)?;
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
        let before = read_path_rows(store, kind, &path)?;
        let after: Vec<(Stage, IndexEntry)> = entry
            .rows
            .iter()
            .filter(|(known, _, _)| *known == path.as_bytes())
            .filter_map(|(_, stage, row)| row.validate(kind).ok().map(|()| (*stage, row.clone())))
            .collect();
        mutations.extend(path_row_mutations(&path, &before, &after)?);
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
