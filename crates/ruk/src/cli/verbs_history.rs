//! History verbs: `commit`, `merge`, `rebase`, `cherry-pick`, `revert`,
//! `log`, `show`, `diff`, `merge-base`, `rev-list`, `rev-parse`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `commit` | tree build + `ops::new`/`ops::edit` + branch move | implemented (`-m`, `-a`, `--amend`) |
//! | `merge` | ancestor check + fast-forward | implemented (fast-forward only; content merge is `Unsupported`) |
//! | `rebase` | no-op detection | partial (up-to-date succeeds; replay is `Unsupported`) |
//! | `cherry-pick` | revision resolution | partial (sequencer readers real; content application is `Unsupported`) |
//! | `revert` | revision resolution | partial (same shape as `cherry-pick`) |
//! | `log` | commit ancestry walk | implemented (`--oneline`, `-n`) |
//! | `show` | commit read + tree diff | implemented (`--oneline`, `-s`, `--stat`, `--name-only`) |
//! | `diff` | tree/index/worktree compare + line differ | implemented (`--cached`, `--stat`, `--name-only`, paths) |
//! | `merge-base` | breadth-first paint-down | implemented |
//! | `rev-list` | ancestry walk | implemented (`--count`, `-n`) |
//! | `rev-parse` | revision resolution + repo facts | implemented (subset of flags) |
//!
//! Oracle anchors: `git/builtin/commit.c`, `git/builtin/merge.c`,
//! `git/builtin/rebase.c`, `git/builtin/revert.c` (`cmd_cherry_pick`,
//! `cmd_revert`), `git/builtin/log.c` (`cmd_log`, `cmd_show`),
//! `git/builtin/diff.c`, `git/builtin/merge-base.c`,
//! `git/builtin/rev-list.c`, `git/builtin/rev-parse.c`.

use std::collections::BTreeMap;

use ruk_core::conflict::Signature;
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::Oid;
use ruk_core::index::{RepoPath, Stage};
use ruk_core::ops::{EditRequest, NewRequest, edit as ops_edit, new as ops_new};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    IdentityRole, commit_record, head_oid, identity, is_ancestor, load_or_default,
    merge_base as state_merge_base, merged_rows, now_seconds, read_path_rows, resolve_rev,
    scan_index, sequencer_read, walk_history, workspace_mutation,
};
use super::tree::{
    WorktreeEntry, build_index_tree, commit_tree_oid, flatten_tree, peel_to_tree, read_object_bytes,
};
use super::{Ctx, FlagSpec, collect, line};

/// Records staged changes as a commit, or rewrites `HEAD` with `--amend`.
///
/// Oracle: `git/builtin/commit.c`.
pub(crate) fn commit(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "amend",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "author",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "commit takes no paths (use -a or stage first)".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    for (_, stage, _) in &rows {
        if *stage != Stage::Zero {
            return Err(GitError::Invalid {
                detail: "unmerged paths must be resolved first".to_owned(),
            });
        }
    }
    if opts.is_set("all") {
        refresh_tracked(ctx)?;
    }
    let rows = scan_index(store, kind)?;
    let tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let message = commit_message(&opts)?;
    let author_text = opts.single("author")?;
    let author_from_flag = author_text.is_some();
    let author = match author_text {
        Some(text) => parse_author_flag(&text)?,
        None => identity(ctx, IdentityRole::Author)?,
    };
    let committer = identity(ctx, IdentityRole::Committer)?;
    if opts.is_set("amend") {
        return commit_amend(ctx, tree, message, author, committer, author_from_flag);
    }
    let parents = match head_oid(store) {
        Ok(tip) => vec![Head::Git { oid: tip }],
        Err(_) => Vec::new(),
    };
    if let Some(tip) = parents.first().and_then(|head| head.as_git().copied()) {
        let record = commit_record(store, tip)?;
        if commit_tree_oid(&record)? == tree {
            return Err(GitError::Invalid {
                detail: "nothing to commit, working tree clean".to_owned(),
            });
        }
    }
    let request = NewRequest {
        tree,
        parents,
        author,
        committer,
        message: ruk_core::ByteString::from(message.as_str()),
        change_id: None,
        predecessor: None,
        provenance: None,
    };
    let result = ops_new(store, request).map_err(GitError::from)?;
    let new_oid = result
        .oid
        .or_else(|| result.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "new commit has no git identity".to_owned(),
        })?;
    advance_head_to(ctx, new_oid)?;
    let label = branch_label_of(ctx)?;
    let subject = message.lines().next().unwrap_or_default().to_owned();
    Ok(format!("[{label} {}] {subject}\n", short_hex(&new_oid)).into_bytes())
}

/// Refreshes every tracked stage-zero row from its worktree file.
fn refresh_tracked(ctx: &Ctx) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    for (path, stage, _) in scan_index(store, kind)? {
        if stage != Stage::Zero {
            continue;
        }
        let before = read_path_rows(store, kind, &path)?;
        match super::verbs_stage::stage_worktree_file(ctx, kind, &path) {
            Ok((entry, staged)) => {
                objects.extend(staged);
                mutations.extend(super::state::path_row_mutations(
                    &path,
                    &before,
                    &[(Stage::Zero, entry)],
                )?);
            }
            Err(GitError::Io { .. }) => {
                mutations.extend(super::state::path_row_mutations(&path, &before, &[])?);
            }
            Err(other) => return Err(other),
        }
    }
    if mutations.is_empty() {
        return Ok(());
    }
    let next = workspace.mutate_index(workspace.stamp)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store.publish(objects, &mutations).map_err(GitError::from)?;
    Ok(())
}

/// Reads the required `-m` message.
fn commit_message(opts: &super::Collected) -> Result<String, GitError> {
    opts.single("message")?.ok_or_else(|| GitError::Invalid {
        detail: "commit needs -m <message> (no editor is implemented)".to_owned(),
    })
}

/// Parses `--author "Name <email>"` into a signature stamped now.
fn parse_author_flag(text: &str) -> Result<Signature, GitError> {
    let (name, email) = text
        .rsplit_once('<')
        .and_then(|(name, rest)| {
            rest.strip_suffix('>')
                .map(|email| (name.trim(), email.trim()))
        })
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad --author {text:?}: want \"Name <email>\""),
        })?;
    let timestamp = now_seconds()?;
    Signature::parse(format!("{name} <{email}> {timestamp} +0000").as_bytes()).map_err(|err| {
        GitError::Invalid {
            detail: format!("bad --author: {err}"),
        }
    })
}

/// Rewrites the current commit keeping its parents and change.
fn commit_amend(
    ctx: &Ctx,
    tree: Oid,
    message: String,
    author: Signature,
    committer: Signature,
    replace_author: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let tip = head_oid(store)?;
    let result = ops_edit(
        store,
        EditRequest {
            head: Head::Git { oid: tip },
            tree: Some(tree),
            message: Some(ruk_core::ByteString::from(message.as_str())),
            author: replace_author.then_some(author),
            committer: Some(committer),
        },
    )
    .map_err(GitError::from)?;
    let new_oid = result
        .head
        .as_git()
        .copied()
        .ok_or_else(|| GitError::Invalid {
            detail: "rewritten commit has no git identity".to_owned(),
        })?;
    advance_head_to(ctx, new_oid)?;
    let label = branch_label_of(ctx)?;
    Ok(format!("[{label} {}] {message}\n", short_hex(&new_oid)).into_bytes())
}

/// Moves the current branch tip, or a detached `HEAD`, to a new commit.
fn advance_head_to(ctx: &Ctx, new_oid: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (workspace, raw) = load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => {
            let before = super::state::read_ref(store, name)?;
            let expected = before.map(RefExpect::Present).unwrap_or(RefExpect::Absent);
            super::state::apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: name.clone(),
                    expected,
                    change: RefChange::Set(RefTarget::Direct(new_oid)),
                }],
            )?;
            Ok(())
        }
        HeadRef::Detached(_) => {
            let next = workspace.move_head(workspace.stamp, HeadRef::Detached(new_oid))?;
            let mutation = workspace_mutation(raw.as_deref(), &next)?;
            store
                .publish(Vec::new(), &[mutation])
                .map_err(GitError::from)?;
            Ok(())
        }
    }
}

/// Names the current branch for commit output, or `HEAD` when detached.
fn branch_label_of(ctx: &Ctx) -> Result<String, GitError> {
    let store = ctx.store()?;
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(name) => Ok(name
            .to_utf8()
            .map_or_else(|| format!("{name}"), str::to_owned)),
        HeadRef::Detached(_) => Ok("HEAD".to_owned()),
    }
}

/// Shortens one object id for one-line output.
fn short_hex(oid: &Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

/// Joins history lines with the fast-forward merge of one branch.
///
/// Oracle: `git/builtin/merge.c`. Only fast-forwards complete here; a merge
/// that needs content resolution fails before touching any state.
pub(crate) fn merge(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "abort",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "continue",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "ff-only",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-ff",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("merge", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("merge", "continue");
    }
    if opts.is_set("no-ff") {
        return Err(GitError::Unsupported {
            command: "merge --no-ff needs the merge lane".to_owned(),
        });
    }
    let rev = opts.positionals.first().ok_or_else(|| GitError::Invalid {
        detail: "usage: merge <rev>".to_owned(),
    })?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tip = resolve_rev(store, kind, rev)?;
    let _ = opts.single("message")?;
    let current = match head_oid(store) {
        Ok(tip) => tip,
        Err(_) => return merge_into_unborn(ctx, rev, tip),
    };
    if current == tip {
        return Ok(b"Already up to date.\n".to_vec());
    }
    if is_ancestor(store, current, tip)? {
        return merge_fast_forward(ctx, rev, tip);
    }
    if is_ancestor(store, tip, current)? {
        return Ok(b"Already up to date.\n".to_vec());
    }
    Err(GitError::Unsupported {
        command: "non-fast-forward merge needs the merge lane".to_owned(),
    })
}

/// Reports the absence of sequencer state for `--abort` and friends.
fn no_sequencer(verb: &str, action: &str) -> Result<Vec<u8>, GitError> {
    Err(GitError::Invalid {
        detail: format!("there is no {verb} in progress to {action}"),
    })
}

/// Points the current branch at a tip when `HEAD` is still unborn.
fn merge_into_unborn(ctx: &Ctx, rev: &str, tip: Oid) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let (workspace, raw) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(name) => {
            super::state::apply_refs(
                store,
                ctx.kind()?,
                vec![RefUpdate {
                    name: name.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Direct(tip)),
                }],
            )?;
            fast_forward_to(ctx, tip)?;
            Ok(format!("Fast-forwarded to {rev}\n").into_bytes())
        }
        HeadRef::Detached(_) => Err(GitError::Invalid {
            detail: "cannot merge into a detached HEAD with no commits".to_owned(),
        }),
    }
}

/// Resets the index and worktree to one commit's tree after a branch move.
fn fast_forward_to(ctx: &Ctx, tip: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let record = commit_record(store, tip)?;
    let tree = commit_tree_oid(&record)?;
    super::verbs_branch::reset_index_tree(ctx, tree)?;
    super::verbs_branch::sync_worktree_to_index(ctx)
}

/// Fast-forwards the current branch to a descendant tip.
pub(crate) fn merge_fast_forward(ctx: &Ctx, rev: &str, tip: Oid) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(_) => {
            super::verbs_branch::move_branch_to(ctx, tip)?;
            fast_forward_to(ctx, tip)?;
            Ok(format!("Fast-forwarded to {rev}\n").into_bytes())
        }
        HeadRef::Detached(_) => Err(GitError::Unsupported {
            command: "merge into a detached HEAD needs the merge lane".to_owned(),
        }),
    }
}

/// Reapplies commits on another base. Only the trivial case completes.
///
/// Oracle: `git/builtin/rebase.c`.
pub(crate) fn rebase(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "abort",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "continue",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "onto",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("rebase", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("rebase", "continue");
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let onto = match opts.single("onto")? {
        Some(rev) => resolve_rev(store, kind, &rev)?,
        None => {
            let rev = opts.positionals.first().ok_or_else(|| GitError::Invalid {
                detail: "usage: rebase <upstream>".to_owned(),
            })?;
            resolve_rev(store, kind, rev)?
        }
    };
    let current = head_oid(store)?;
    if current == onto {
        let label = branch_label_of(ctx)?;
        return Ok(format!("Current branch {label} is up to date.\n").into_bytes());
    }
    Err(GitError::Unsupported {
        command: "rebase replay needs the merge lane".to_owned(),
    })
}

/// Applies existing commits elsewhere. Sequencer readers are real; content
/// application needs the absent merge lane.
///
/// Oracle: `git/builtin/revert.c` (`cmd_cherry_pick`).
pub(crate) fn cherry_pick(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "abort",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "continue",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-commit",
            short: Some('n'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("cherry-pick", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("cherry-pick", "continue");
    }
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: cherry-pick <commit>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for rev in &opts.positionals {
        resolve_rev(store, kind, rev)?;
    }
    let _ = sequencer_read(store, "cherry-pick")?;
    Err(GitError::Unsupported {
        command: "cherry-pick needs the merge lane".to_owned(),
    })
}

/// Reverts existing commits. Same backing shape as `cherry-pick`.
///
/// Oracle: `git/builtin/revert.c` (`cmd_revert`).
pub(crate) fn revert(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "abort",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "continue",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-commit",
            short: Some('n'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("revert", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("revert", "continue");
    }
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: revert <commit>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for rev in &opts.positionals {
        resolve_rev(store, kind, rev)?;
    }
    let _ = sequencer_read(store, "revert")?;
    Err(GitError::Unsupported {
        command: "revert needs the merge lane".to_owned(),
    })
}

/// Shows commit logs from one tip.
///
/// Oracle: `git/builtin/log.c` (`cmd_log`).
pub(crate) fn log(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "oneline",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "max-count",
            short: Some('n'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit = opts
        .single("max-count")?
        .map(|value| {
            value.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad --max-count {value:?}"),
            })
        })
        .transpose()?;
    let rev = opts.positionals.first().map_or("HEAD", String::as_str);
    let tip = resolve_rev(store, kind, rev)?;
    let mut out = Vec::new();
    for (oid, record) in walk_history(store, &[tip], limit)? {
        if opts.is_set("oneline") {
            let subject = first_subject_line(record.message());
            out.extend_from_slice(format!("{} {subject}\n", short_hex(&oid)).as_bytes());
        } else {
            out.extend_from_slice(&super::state::render_commit_header(oid, &record));
        }
    }
    Ok(out)
}

/// Takes the first message line for one-line logs.
fn first_subject_line(message: &[u8]) -> String {
    let end = message
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(message.len());
    String::from_utf8_lossy(&message[..end]).into_owned()
}

/// Shows one commit with its diff against its first parent.
///
/// Oracle: `git/builtin/log.c` (`cmd_show`).
pub(crate) fn show(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "oneline",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-patch",
            short: Some('s'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rev = opts.positionals.first().map_or("HEAD", String::as_str);
    let (oid, record) = super::state::read_commit(store, kind, rev)?;
    let mut out = Vec::new();
    if opts.is_set("oneline") {
        out.extend_from_slice(
            format!(
                "{} {}\n",
                short_hex(&oid),
                first_subject_line(record.message())
            )
            .as_bytes(),
        );
    } else {
        out.extend_from_slice(&super::state::render_commit_header(oid, &record));
    }
    if opts.is_set("no-patch") {
        return Ok(out);
    }
    let tree = commit_tree_oid(&record)?;
    let parent_tree = record
        .parents()
        .first()
        .and_then(|head| head.as_git().copied())
        .map(|parent| {
            super::state::read_commit(store, kind, &parent.to_hex())
                .and_then(|(_, parent_record)| commit_tree_oid(&parent_record))
        })
        .transpose()?;
    let pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
    out.extend_from_slice(&render_pairs(ctx, &pairs, &opts)?);
    Ok(out)
}

/// Shows worktree, index, and tree differences with hunks.
///
/// Oracle: `git/builtin/diff.c`.
pub(crate) fn diff(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "cached",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut positionals = opts.positionals.as_slice();
    if positionals.first().is_some_and(|first| *first == "--") {
        positionals = &positionals[1..];
    }
    let try_rev = |text: &str| match resolve_rev(store, kind, text) {
        Ok(_) => Ok(Some(text.to_owned())),
        Err(GitError::NotFound { .. }) => Ok(None),
        Err(other) => Err(other),
    };
    let (rev, rev_b, paths) = match positionals {
        [] => (None, None, &[][..]),
        [single] => match try_rev(single)? {
            Some(rev) => (Some(rev), None, &[][..]),
            None => (None, None, positionals),
        },
        [first, second, rest @ ..] => match try_rev(first)? {
            Some(one) => match try_rev(second)? {
                Some(two) => (Some(one), Some(two), rest),
                None => (Some(one), None, &positionals[1..]),
            },
            None => (None, None, positionals),
        },
    };
    let paths: Vec<RepoPath> = paths
        .iter()
        .map(|text| super::verbs_stage::repo_path_of(ctx, text.as_bytes()))
        .collect::<Result<_, _>>()?;
    let pairs = match (rev, rev_b) {
        (Some(one), Some(two)) => {
            let old_tree = peel_to_tree(store, kind, resolve_rev(store, kind, &one)?)?;
            let new_tree = peel_to_tree(store, kind, resolve_rev(store, kind, &two)?)?;
            tree_pairs(ctx, Some(old_tree), Some(new_tree))?
        }
        (rev, None) => match (rev, opts.is_set("cached")) {
            (None, false) => worktree_pairs(ctx)?,
            (None, true) => staged_pairs(ctx)?,
            (Some(one), false) => rev_worktree_pairs(ctx, &one)?,
            (Some(one), true) => rev_staged_pairs(ctx, &one)?,
        },
        (None, Some(_)) => unreachable!("a second rev never outlives a missing first"),
    };
    let pairs: Vec<TreePair> = pairs
        .into_iter()
        .filter(|pair| {
            paths.is_empty()
                || paths
                    .iter()
                    .any(|want| want.as_bytes() == pair.path.as_slice())
        })
        .collect();
    render_pairs(ctx, &pairs, &opts)
}

/// One compared path: the old and new side, either absent.
struct TreePair {
    /// Full path bytes.
    path: Vec<u8>,
    /// Old mode and oid, when present before.
    old: Option<(ruk_core::index::FileMode, Oid)>,
    /// New mode and oid, when present after.
    new: Option<(ruk_core::index::FileMode, Oid)>,
    /// New-side bytes when the content has no stored object (worktree
    /// edits). Overrides the object read keyed by `new`'s oid.
    new_bytes: Option<Vec<u8>>,
}

/// Pairs two optional trees path by path.
fn tree_pairs(ctx: &Ctx, old: Option<Oid>, new: Option<Oid>) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut old_map = BTreeMap::new();
    if let Some(tree) = old {
        for (path, mode, oid) in flatten_tree(store, kind, tree)? {
            old_map.insert(path, (mode, oid));
        }
    }
    let mut new_map = BTreeMap::new();
    if let Some(tree) = new {
        for (path, mode, oid) in flatten_tree(store, kind, tree)? {
            new_map.insert(path, (mode, oid));
        }
    }
    let mut union: Vec<Vec<u8>> = old_map.keys().cloned().collect();
    for path in new_map.keys() {
        if !union.contains(path) {
            union.push(path.clone());
        }
    }
    union.sort();
    let mut pairs = Vec::new();
    for path in union {
        let old_entry = old_map.remove(&path);
        let new_entry = new_map.remove(&path);
        if old_entry == new_entry {
            continue;
        }
        pairs.push(TreePair {
            path,
            old: old_entry,
            new: new_entry,
            new_bytes: None,
        });
    }
    Ok(pairs)
}

/// Pairs worktree files against index blobs.
///
/// Worktree content is carried as inline bytes: unstaged edits have no
/// stored object, so a hash-only side would read as `not found`.
fn worktree_pairs(ctx: &Ctx) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut index_map = BTreeMap::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            index_map.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    let mut pairs = Vec::new();
    for entry in super::tree::walk_worktree(&ctx.file_base)? {
        let bytes = entry_bytes(ctx, &entry)?;
        match index_map.remove(&entry.path) {
            None => {
                let oid = kind
                    .hash_git_object("blob", &bytes)
                    .map_err(|err| GitError::from(CoreError::from(err)))?;
                let mode = entry_mode_of(&entry);
                pairs.push(TreePair {
                    path: entry.path,
                    old: None,
                    new: Some((mode, oid)),
                    new_bytes: Some(bytes),
                });
            }
            Some((mode, oid)) => {
                let (_, current) = read_object_bytes(store, oid)?;
                if current != bytes {
                    let fresh = kind
                        .hash_git_object("blob", &bytes)
                        .map_err(|err| GitError::from(CoreError::from(err)))?;
                    pairs.push(TreePair {
                        path: entry.path,
                        old: Some((mode, oid)),
                        new: Some((mode, fresh)),
                        new_bytes: Some(bytes),
                    });
                }
            }
        }
    }
    for (path, (mode, oid)) in index_map {
        pairs.push(TreePair {
            path,
            old: Some((mode, oid)),
            new: None,
            new_bytes: None,
        });
    }
    pairs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(pairs)
}

/// Reads one walked entry's bytes for comparison.
fn entry_bytes(ctx: &Ctx, entry: &WorktreeEntry) -> Result<Vec<u8>, GitError> {
    match entry.file_type {
        super::tree::WorktreeType::File => {
            super::tree::read_worktree_file(&ctx.file_base, &entry.path)
        }
        super::tree::WorktreeType::Symlink => {
            let full = super::tree::join_base(&ctx.file_base, &entry.path)?;
            std::fs::read_link(&full)
                .map(|target| target.as_os_str().as_encoded_bytes().to_vec())
                .map_err(|err| GitError::Io {
                    detail: format!("reading link {}: {err}", full.display()),
                })
        }
    }
}

/// Guesses the index mode for a walked entry.
fn entry_mode_of(entry: &super::tree::WorktreeEntry) -> ruk_core::index::FileMode {
    match entry.file_type {
        super::tree::WorktreeType::Symlink => ruk_core::index::FileMode::Symlink,
        super::tree::WorktreeType::File => ruk_core::index::FileMode::Regular,
    }
}

/// Pairs the `HEAD` tree against index blobs.
fn staged_pairs(ctx: &Ctx) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let tip = head_oid(store)?;
    let record = commit_record(store, tip)?;
    let tree = commit_tree_oid(&record)?;
    let mut index_map = BTreeMap::new();
    for (path, stage, entry) in scan_index(store, ctx.kind()?)? {
        if stage == Stage::Zero {
            index_map.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    tree_pairs_index(ctx, Some(tree), index_map)
}

/// Pairs one revision's tree against worktree files.
fn rev_worktree_pairs(ctx: &Ctx, rev: &str) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = resolve_rev(store, kind, rev)?;
    let tree = peel_to_tree(store, kind, oid)?;
    let mut tree_map = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        tree_map.insert(path, (mode, oid));
    }
    let mut pairs = Vec::new();
    for entry in super::tree::walk_worktree(&ctx.file_base)? {
        let bytes = entry_bytes(ctx, &entry)?;
        match tree_map.remove(&entry.path) {
            None => {
                let fresh = kind
                    .hash_git_object("blob", &bytes)
                    .map_err(|err| GitError::from(CoreError::from(err)))?;
                let mode = entry_mode_of(&entry);
                pairs.push(TreePair {
                    path: entry.path,
                    old: None,
                    new: Some((mode, fresh)),
                    new_bytes: Some(bytes),
                });
            }
            Some((mode, oid)) => {
                let (_, current) = read_object_bytes(store, oid)?;
                if current != bytes {
                    let fresh = kind
                        .hash_git_object("blob", &bytes)
                        .map_err(|err| GitError::from(CoreError::from(err)))?;
                    pairs.push(TreePair {
                        path: entry.path,
                        old: Some((mode, oid)),
                        new: Some((mode, fresh)),
                        new_bytes: Some(bytes),
                    });
                }
            }
        }
    }
    for (path, (mode, oid)) in tree_map {
        pairs.push(TreePair {
            path,
            old: Some((mode, oid)),
            new: None,
            new_bytes: None,
        });
    }
    pairs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(pairs)
}

/// Pairs one revision's tree against index blobs.
fn rev_staged_pairs(ctx: &Ctx, rev: &str) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = resolve_rev(store, kind, rev)?;
    let tree = peel_to_tree(store, kind, oid)?;
    let mut index_map = BTreeMap::new();
    for (path, stage, entry) in scan_index(store, kind)? {
        if stage == Stage::Zero {
            index_map.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    tree_pairs_index(ctx, Some(tree), index_map)
}

/// Pairs one tree against a ready index map.
fn tree_pairs_index(
    ctx: &Ctx,
    tree: Option<Oid>,
    mut index_map: BTreeMap<Vec<u8>, (ruk_core::index::FileMode, Oid)>,
) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut tree_map = BTreeMap::new();
    if let Some(tree) = tree {
        for (path, mode, oid) in flatten_tree(store, kind, tree)? {
            tree_map.insert(path, (mode, oid));
        }
    }
    let mut union: Vec<Vec<u8>> = tree_map.keys().cloned().collect();
    for path in index_map.keys() {
        if !union.contains(path) {
            union.push(path.clone());
        }
    }
    union.sort();
    let mut pairs = Vec::new();
    for path in union {
        let old_entry = tree_map.remove(&path);
        let new_entry = index_map.remove(&path);
        if old_entry == new_entry {
            continue;
        }
        pairs.push(TreePair {
            path,
            old: old_entry,
            new: new_entry,
            new_bytes: None,
        });
    }
    Ok(pairs)
}

/// One rendered pair with its line counts for `--stat`.
struct CountedHunk {
    /// Full path bytes.
    path: Vec<u8>,
    /// Unified text for the patch form.
    text: Vec<u8>,
    /// Added lines.
    added: usize,
    /// Removed lines.
    removed: usize,
}

/// Renders pairs as patch, stat, or names per the parsed options.
fn render_pairs(
    ctx: &Ctx,
    pairs: &[TreePair],
    opts: &super::Collected,
) -> Result<Vec<u8>, GitError> {
    if opts.is_set("name-only") {
        let mut out = Vec::new();
        for pair in pairs {
            out.extend_from_slice(String::from_utf8_lossy(&pair.path).as_bytes());
            out.push(b'\n');
        }
        return Ok(out);
    }
    let mut hunks: Vec<CountedHunk> = Vec::new();
    for pair in pairs {
        let (old_body, new_body) = pair_bodies(ctx, pair)?;
        let (text, added, removed) =
            unified_pair(&pair.path, old_body.as_deref(), new_body.as_deref())?;
        hunks.push(CountedHunk {
            path: pair.path.clone(),
            text,
            added,
            removed,
        });
    }
    if opts.is_set("stat") {
        return Ok(render_stat(&hunks));
    }
    let mut out = Vec::new();
    for hunk in &hunks {
        out.extend_from_slice(&hunk.text);
    }
    Ok(out)
}

/// Renders `--stat` from counted hunks.
fn render_stat(hunks: &[CountedHunk]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut added_total = 0;
    let mut removed_total = 0;
    for hunk in hunks {
        added_total += hunk.added;
        removed_total += hunk.removed;
        out.extend_from_slice(
            format!(
                " {} | {}{}{}\n",
                String::from_utf8_lossy(&hunk.path),
                hunk.added + hunk.removed,
                "+".repeat(hunk.added),
                "-".repeat(hunk.removed)
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(
        format!(
            " {} files changed, {added_total} insertions(+), {removed_total} deletions(-)\n",
            hunks.len()
        )
        .as_bytes(),
    );
    out
}

/// Reads both blob bodies behind one pair for the differ.
fn pair_bodies(ctx: &Ctx, pair: &TreePair) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), GitError> {
    let store = ctx.store()?;
    let old_body = pair
        .old
        .map(|(_, oid)| read_object_bytes(store, oid).map(|(_, body)| body))
        .transpose()?;
    let new_body = match &pair.new_bytes {
        Some(bytes) => Some(bytes.clone()),
        None => pair
            .new
            .map(|(_, oid)| read_object_bytes(store, oid).map(|(_, body)| body))
            .transpose()?,
    };
    Ok((old_body, new_body))
}

/// Diffs one path pair into unified text with added/removed counts.
fn unified_pair(
    path: &[u8],
    old: Option<&[u8]>,
    new: Option<&[u8]>,
) -> Result<(Vec<u8>, usize, usize), GitError> {
    let name = String::from_utf8_lossy(path);
    let mut out = format!("diff --git a/{name} b/{name}\n").into_bytes();
    match (old, new) {
        (None, Some(_)) => out.extend_from_slice(b"new file\n"),
        (Some(_), None) => out.extend_from_slice(b"deleted file\n"),
        _ => {}
    }
    let old_lines = old.map(split_lines).unwrap_or_default();
    let new_lines = new.map(split_lines).unwrap_or_default();
    if old_lines.iter().any(|line| line.contains(&b'\0'))
        || new_lines.iter().any(|line| line.contains(&b'\0'))
    {
        out.extend_from_slice(b"Binary files differ\n");
        return Ok((out, 0, 0));
    }
    let product = old_lines.len().saturating_mul(new_lines.len());
    if product > 4_000_000 {
        out.extend_from_slice(
            format!(
                "(diff too large: {} against {} lines omitted)\n",
                old_lines.len(),
                new_lines.len()
            )
            .as_bytes(),
        );
        return Ok((out, new_lines.len(), old_lines.len()));
    }
    let script = lcs_script(&old_lines, &new_lines);
    let mut added = 0;
    let mut removed = 0;
    out.extend_from_slice(format!("--- a/{name}\n+++ b/{name}\n").as_bytes());
    let mut hunk_start = 0;
    let mut old_line_number = 1;
    let mut new_line_number = 1;
    while hunk_start < script.len() {
        let hunk_end = script.len().min(hunk_start + 20);
        let hunk_old_start = old_line_number;
        let hunk_new_start = new_line_number;
        let mut old_count = 0;
        let mut new_count = 0;
        for op in &script[hunk_start..hunk_end] {
            match op {
                DiffOp::Keep(_) => {
                    old_count += 1;
                    new_count += 1;
                    old_line_number += 1;
                    new_line_number += 1;
                }
                DiffOp::Delete(_) => {
                    old_count += 1;
                    old_line_number += 1;
                }
                DiffOp::Insert(_) => {
                    new_count += 1;
                    new_line_number += 1;
                }
            }
        }
        out.extend_from_slice(
            format!("@@ -{hunk_old_start},{old_count} +{hunk_new_start},{new_count} @@\n")
                .as_bytes(),
        );
        for op in &script[hunk_start..hunk_end] {
            match op {
                DiffOp::Keep(line) => {
                    out.push(b' ');
                    out.extend_from_slice(line);
                    out.push(b'\n');
                }
                DiffOp::Delete(line) => {
                    removed += 1;
                    out.push(b'-');
                    out.extend_from_slice(line);
                    out.push(b'\n');
                }
                DiffOp::Insert(line) => {
                    added += 1;
                    out.push(b'+');
                    out.extend_from_slice(line);
                    out.push(b'\n');
                }
            }
        }
        hunk_start = hunk_end;
    }
    Ok((out, added, removed))
}

/// One line-diff operation over borrowed line bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DiffOp<'a> {
    /// Present on both sides.
    Keep(&'a [u8]),
    /// Present only before.
    Delete(&'a [u8]),
    /// Present only after.
    Insert(&'a [u8]),
}

/// Splits bytes into lines without terminators. Empty input is no lines;
/// a trailing newline never invents a phantom empty line.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if lines.last() == Some(&b"".as_slice()) {
        lines.pop();
    }
    lines
}

/// Aligns two line lists with a classic LCS table.
fn lcs_script<'a>(old: &[&'a [u8]], new: &[&'a [u8]]) -> Vec<DiffOp<'a>> {
    let rows = old.len() + 1;
    let cols = new.len() + 1;
    let mut table = vec![0u32; rows * cols];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i * cols + j] = if old[i] == new[j] {
                table[(i + 1) * cols + j + 1] + 1
            } else {
                table[(i + 1) * cols + j].max(table[i * cols + j + 1])
            };
        }
    }
    let mut script = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            script.push(DiffOp::Keep(old[i]));
            i += 1;
            j += 1;
        } else if table[(i + 1) * cols + j] >= table[i * cols + j + 1] {
            script.push(DiffOp::Delete(old[i]));
            i += 1;
        } else {
            script.push(DiffOp::Insert(new[j]));
            j += 1;
        }
    }
    for line in &old[i..] {
        script.push(DiffOp::Delete(line));
    }
    for line in &new[j..] {
        script.push(DiffOp::Insert(line));
    }
    script
}

/// Shortens one branch revision for `--abbrev-ref`, including `HEAD`.
fn abbrev_branch(ctx: &Ctx, rev: &str) -> Result<Option<String>, GitError> {
    let store = ctx.store()?;
    if rev == "HEAD" {
        let (workspace, _) = load_or_default(store)?;
        return Ok(Some(match workspace.head {
            HeadRef::Symbolic(name) => name
                .to_utf8()
                .unwrap_or_default()
                .trim_start_matches("refs/heads/")
                .to_owned(),
            HeadRef::Detached(_) => "HEAD".to_owned(),
        }));
    }
    for candidate in [rev.to_owned(), format!("refs/heads/{rev}")] {
        let Ok(name) = RefName::new(candidate.clone()) else {
            continue;
        };
        if super::state::read_ref(store, &name)?.is_some() {
            return Ok(Some(candidate.trim_start_matches("refs/heads/").to_owned()));
        }
    }
    Ok(None)
}

/// Finds one common ancestor for the given tips.
///
/// Oracle: `git/builtin/merge-base.c`.
pub(crate) fn merge_base(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "is-ancestor",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("is-ancestor") {
        let [first, second] = opts.positionals.as_slice() else {
            return Err(GitError::Invalid {
                detail: "usage: merge-base --is-ancestor <a> <b>".to_owned(),
            });
        };
        let ancestor = resolve_rev(store, kind, first)?;
        let descendant = resolve_rev(store, kind, second)?;
        if is_ancestor(store, ancestor, descendant)? {
            return Ok(Vec::new());
        }
        return Err(GitError::NotFound {
            detail: format!("{first} is not an ancestor of {second}"),
        });
    }
    if opts.positionals.len() < 2 {
        return Err(GitError::Invalid {
            detail: "usage: merge-base <a> <b>...".to_owned(),
        });
    }
    let mut tips = Vec::new();
    for rev in &opts.positionals {
        tips.push(resolve_rev(store, kind, rev)?);
    }
    let mut base = tips[0];
    for tip in tips.iter().skip(1) {
        base = state_merge_base(store, base, *tip)?;
    }
    Ok(line(base.to_hex().into_bytes()))
}

/// Lists ancestry from tips, newest discovered first.
///
/// Oracle: `git/builtin/rev-list.c`.
pub(crate) fn rev_list(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "count",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "max-count",
            short: Some('n'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit = opts
        .single("max-count")?
        .map(|value| {
            value.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad --max-count {value:?}"),
            })
        })
        .transpose()?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: rev-list [--count] <rev>...".to_owned(),
        });
    }
    let mut tips = Vec::new();
    for rev in &opts.positionals {
        tips.push(resolve_rev(store, kind, rev)?);
    }
    let history = walk_history(store, &tips, limit)?;
    if opts.is_set("count") {
        return Ok(line(history.len().to_string().into_bytes()));
    }
    let mut out = Vec::new();
    for (oid, _) in history {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

/// Resolves revisions and prints repository facts.
///
/// Oracle: `git/builtin/rev-parse.c`.
pub(crate) fn rev_parse(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "verify",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "git-dir",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "show-toplevel",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "is-inside-work-tree",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "abbrev-ref",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "short",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut out = Vec::new();
    if opts.is_set("git-dir") {
        out.extend_from_slice(format!("{}/.ruk\n", ctx.root.display()).as_bytes());
    }
    if opts.is_set("show-toplevel") {
        out.extend_from_slice(format!("{}\n", ctx.root.display()).as_bytes());
    }
    if opts.is_set("is-inside-work-tree") {
        out.extend_from_slice(if ctx.bare { b"false\n" } else { b"true\n" });
    }
    for rev in &opts.positionals {
        if *rev == "--" {
            continue;
        }
        if opts.is_set("abbrev-ref") {
            if let Some(short) = abbrev_branch(ctx, rev)? {
                out.extend_from_slice(format!("{short}\n").as_bytes());
                continue;
            }
        }
        let oid = resolve_rev(store, kind, rev)?;
        if opts.is_set("short") {
            out.extend_from_slice(format!("{}\n", short_hex(&oid)).as_bytes());
        } else {
            out.extend_from_slice(format!("{}\n", oid.to_hex()).as_bytes());
        }
    }
    Ok(out)
}
