//! History verbs: `commit`, `merge`, `rebase`, `cherry-pick`, `revert`,
//! `log`, `show`, `diff`, `merge-base`, `rev-list`, `rev-parse`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `commit` | tree build + `ops::new`/`ops::edit` + branch move | implemented (multi `-m`, `-a`, `--amend`, `--allow-empty`, `-q`, `-C`/`-c`, `--author`, `--date`, `--dry-run`, `--no-verify` no-op) |
//! | `merge` | fast-forward fast-path + three-way lane | implemented (syntax lane first, bounded text fallback; `--no-ff`, `--ff-only`, `--continue`/`--abort`/`--quit`, `MERGE_HEAD` + stages 1/2/3 on conflict) |
//! | `rebase` | range replay over the lane | implemented (`<upstream>` and `--onto`, `--continue`/`--skip`/`--abort`; drops merge commits, no branch switching) |
//! | `cherry-pick` | per-commit replay over the lane | implemented (`-n`, `-m`, `-x`, `--continue`/`--skip`/`--abort`, `CHERRY_PICK_HEAD`) |
//! | `revert` | inverse replay over the lane | implemented (`-n`, `-m`, `--continue`/`--skip`/`--abort`, `REVERT_HEAD`) |
//! | `log` | commit ancestry walk | implemented (oneline, format/pretty incl. full/fuller/email/raw, ranges, paths, stat/patch/summary/shortstat/numstat/dirstat, filters incl. follow/pickaxe/merges, first-parent, left-right/cherry-pick, topo/date order, date shapes, abbrev, notes, decorate, source, simplify-by-decoration, branch/tag/remote/exclude tips, boundary, graph) |
//! | `show` | commit read + tree diff, or blob bytes | implemented (format/pretty, stat/patch, `rev:path` blob form) |
//! | `diff` | tree/index/worktree compare + line differ | implemented (`--cached`/`--staged`, ranges, stat/patch, `-U`, name-status, paths) |
//! | `merge-base` | breadth-first paint-down | implemented (`--is-ancestor`, `-a`/`--all`) |
//! | `rev-list` | ancestry walk | implemented (`--count`, `-n`, `--all`, `--objects`, `--parents`, `--reverse`, ranges) |
//! | `rev-parse` | revision resolution + repo facts | implemented (`--verify` arity, `--short[=N]`, `--abbrev-ref`, `--git-dir`, `--show-toplevel`, `--is-inside-work-tree`, `--is-bare-repository`, `@`/`:path`) |
//!
//! Oracle anchors: `git/builtin/commit.c`, `git/builtin/merge.c`,
//! `git/builtin/rebase.c`, `git/builtin/revert.c` (`cmd_cherry_pick`,
//! `cmd_revert`), `git/builtin/log.c` (`cmd_log`, `cmd_show`),
//! `git/builtin/diff.c`, `git/builtin/merge-base.c`,
//! `git/builtin/rev-list.c`, `git/builtin/rev-parse.c`.

use std::collections::{BTreeMap, HashMap, HashSet};

use ruk_core::commit::CommitRecord;
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage};
use ruk_core::merge::composed::MergeMode;
use ruk_core::merge::composed::host::ComposedRequest;
use ruk_core::merge::composed::route::{MergeOutcome, merge_file};
use ruk_core::merge::syntax::grammar::{Cancel, GrammarRegistry, dispatch};
use ruk_core::merge::syntax::registry_providers;
use ruk_core::ops::{EditRequest, NewRequest, edit as ops_edit, new as ops_new};
use regex::bytes::Regex;
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::ObjectKind as MergeLaneObjectKind;
use ruk_core::store::Store as MergeLaneStore;
use ruk_core::store::Store;
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    IdentityRole, SequencerState, WalkQueue, commit_record, head_oid, identity, is_ancestor,
    list_refs, load_or_default, merge_base as state_merge_base, merged_rows, now_seconds,
    pseudo_delete,
    pseudo_read, pseudo_read_oid, pseudo_write, read_path_rows, read_ref, replace_redirect,
    resolve_rev, scan_index, sequencer_delete, sequencer_read, sequencer_write, walk_history,
    walk_record, workspace_mutation,
};
use super::tree::{
    TreeMode, WorktreeEntry, build_index_tree, commit_tree_oid, flatten_tree, peel_to_tree,
    read_object_bytes,
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
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "allow-empty",
            short: None,
            takes_value: false,
        },
        // Accepted and ignored: no hooks exist in this store, so there is
        // nothing to skip; parsing it keeps `commit --no-verify` working.
        FlagSpec {
            long: "no-verify",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "dry-run",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "date",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "reuse-message",
            short: Some('C'),
            takes_value: true,
        },
        // No editor is implemented, so `-c` reuses the message as-is like
        // `-C`; the spelling is still accepted for script compatibility.
        FlagSpec {
            long: "reedit-message",
            short: Some('c'),
            takes_value: true,
        },
    ];
    let opts = collect_expanded(args, &specs)?;
    ctx.require_worktree()?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "commit takes no paths (use -a or stage first)".to_owned(),
        });
    }
    let quiet = opts.is_set("quiet");
    let finish = |body: Vec<u8>| -> Result<Vec<u8>, GitError> {
        if quiet { Ok(Vec::new()) } else { Ok(body) }
    };
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
    // An explicit `commit` over a conflicted merge concludes it the way the
    // oracle does: two parents and the pending merge message.
    if pseudo_read_oid(store, "MERGE_HEAD")?.is_some() {
        if opts.is_set("amend") {
            return Err(GitError::Invalid {
                detail: "cannot amend while merging".to_owned(),
            });
        }
        let message = if opts.is_set("message")
            || opts.is_set("reuse-message")
            || opts.is_set("reedit-message")
        {
            Some(commit_message(&opts, store, kind)?)
        } else {
            None
        };
        return conclude_merge(ctx, message);
    }
    let tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let message = commit_message(&opts, store, kind)?;
    let author_text = opts.single("author")?;
    let author_from_flag = author_text.is_some();
    let author = match author_text {
        Some(text) => parse_author_flag(&text)?,
        None => identity(ctx, IdentityRole::Author)?,
    };
    // `git commit --date` overrides the author date only.
    let author = match opts.single("date")? {
        None => author,
        Some(text) => {
            let stamp = parse_date_arg(&text)?;
            let Signature {
                name,
                email,
                offset,
                ..
            } = author;
            Signature {
                name,
                email,
                timestamp: stamp,
                offset,
            }
        }
    };
    let committer = identity(ctx, IdentityRole::Committer)?;
    if opts.is_set("amend") {
        let out = commit_amend(ctx, tree, message, author, committer, author_from_flag)?;
        return finish(out);
    }
    let parents = match head_oid(store) {
        Ok(tip) => vec![Head::Git { oid: tip }],
        Err(_) => Vec::new(),
    };
    let tree_unchanged = match parents.first().and_then(|head| head.as_git().copied()) {
        None => false,
        Some(tip) => commit_tree_oid(&commit_record(store, tip)?)? == tree,
    };
    if tree_unchanged && !opts.is_set("allow-empty") {
        return Err(GitError::Invalid {
            detail: "nothing to commit, working tree clean".to_owned(),
        });
    }
    if opts.is_set("dry-run") {
        let label = branch_label_of(ctx)?;
        let subject = message.lines().next().unwrap_or_default().to_owned();
        return finish(format!("Would commit on {label}: {subject}\n").into_bytes());
    }
    let old_tree = parents_tree(ctx, &parents)?;
    let root = parents.is_empty();
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
    let summary = if root {
        root_commit_summary(ctx, old_tree, tree, &new_oid, &label, &subject)?
    } else {
        commit_summary(ctx, old_tree, tree, &new_oid, &label, &subject)?
    };
    finish(summary)
}

/// Reads the tree behind `parents`: the first parent's tree, or `None`
/// for a root commit, the way the oracle diffs against the empty tree.
fn parents_tree(ctx: &Ctx, parents: &[Head]) -> Result<Option<Oid>, GitError> {
    let Some(first) = parents.first().and_then(|head| head.as_git().copied()) else {
        return Ok(None);
    };
    let store = ctx.store()?;
    Ok(Some(commit_tree_oid(&commit_record(store, first)?)?))
}

/// Renders `[branch short] subject` plus the diffstat block for a
/// non-root commit.
fn commit_summary(
    ctx: &Ctx,
    old_tree: Option<Oid>,
    new_tree: Oid,
    new_oid: &Oid,
    label: &str,
    subject: &str,
) -> Result<Vec<u8>, GitError> {
    summary_with_header(
        ctx,
        old_tree,
        new_tree,
        format!("[{label} {}] {subject}\n", short_hex(new_oid)),
    )
}

/// Renders `[branch (root-commit) short] subject` plus the diffstat block
/// for the first commit on a branch.
fn root_commit_summary(
    ctx: &Ctx,
    old_tree: Option<Oid>,
    new_tree: Oid,
    new_oid: &Oid,
    label: &str,
    subject: &str,
) -> Result<Vec<u8>, GitError> {
    summary_with_header(
        ctx,
        old_tree,
        new_tree,
        format!("[{label} (root-commit) {}] {subject}\n", short_hex(new_oid)),
    )
}

/// Renders one header line plus the commit diffstat block: the `N files
/// changed` summary with git's singular/plural rules, then `create mode`/
/// `delete mode`/`rename ... (100%)` lines per file. Unlike `--stat`, the
/// short commit report has no per-file lines.
fn summary_with_header(
    ctx: &Ctx,
    old_tree: Option<Oid>,
    new_tree: Oid,
    header: String,
) -> Result<Vec<u8>, GitError> {
    let mut out = header.into_bytes();
    let changes = tree_file_changes(ctx, old_tree, new_tree)?;
    let (added, removed) = stat_totals(&changes);
    out.extend_from_slice(&stat_summary(changes.len(), added, removed));
    out.extend_from_slice(&render_mode_lines(&changes));
    Ok(out)
}

/// Totals added/removed lines across file changes for summary lines.
fn stat_totals(changes: &[FileChange]) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    for change in changes {
        added += change.added;
        removed += change.removed;
    }
    (added, removed)
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

/// Reads the commit message: repeated `-m` paragraphs joined with a blank
/// line (as in git), else the message reused from `-C`/`-c`.
fn commit_message(
    opts: &super::Collected,
    store: &Store,
    kind: HashKind,
) -> Result<String, GitError> {
    let reuse = match (
        opts.single("reuse-message")?,
        opts.single("reedit-message")?,
    ) {
        (Some(_), Some(_)) => {
            return Err(GitError::Invalid {
                detail: "cannot combine -C and -c".to_owned(),
            });
        }
        (Some(rev), None) | (None, Some(rev)) => Some(reused_message(store, kind, &rev)?),
        (None, None) => None,
    };
    let parts = opts.all("message")?;
    match (reuse, parts.as_slice()) {
        (Some(_), [_, ..]) => Err(GitError::Invalid {
            detail: "option -m cannot be combined with -C/-c".to_owned(),
        }),
        (Some(text), _) => Ok(text),
        (None, []) => Err(GitError::Invalid {
            detail: "commit needs -m <message> (no editor is implemented)".to_owned(),
        }),
        // Git terminates the joined `-m` paragraphs with a newline (`-m one`
        // stores `one\n`), so the stored bytes match the oracle exactly.
        (None, _) => {
            let mut message = parts.join("\n\n");
            if !message.ends_with('\n') {
                message.push('\n');
            }
            Ok(message)
        }
    }
}

/// Reads the message of one existing commit for `-C`/`-c`.
fn reused_message(store: &Store, kind: HashKind, rev: &str) -> Result<String, GitError> {
    let oid = resolve_rev(store, kind, rev)?;
    let record = commit_record(store, oid)?;
    Ok(String::from_utf8_lossy(record.message()).into_owned())
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
    let old_tree = commit_tree_oid(&commit_record(store, tip)?)?;
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
    let subject = message.lines().next().unwrap_or_default().to_owned();
    commit_summary(ctx, Some(old_tree), tree, &new_oid, &label, &subject)
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

/// Names the current branch for commit output, shortened the way the
/// oracle prints `main` instead of `refs/heads/main`, or `detached HEAD`
/// when detached.
fn branch_label_of(ctx: &Ctx) -> Result<String, GitError> {
    let store = ctx.store()?;
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(name) => Ok(name
            .to_utf8()
            .map_or_else(|| format!("{name}"), str::to_owned)
            .trim_start_matches("refs/heads/")
            .to_owned()),
        HeadRef::Detached(_) => Ok("detached HEAD".to_owned()),
    }
}

/// Shortens one object id for one-line output.
fn short_hex(oid: &Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

/// Collects `args` after expanding grouped short flags (`-am` reads as
/// `-a -m`). The shared [`collect`] only takes one short per token, so each
/// history verb expands first; unknown letters are left for `collect` to
/// reject with its clear `unknown option` error.
fn collect_expanded(args: &[String], specs: &[FlagSpec]) -> Result<super::Collected, GitError> {
    collect(&expand_combined_shorts(args, specs), specs)
}

/// Expands one token of grouped boolean shorts into long flags.
fn expand_combined_shorts(args: &[String], specs: &[FlagSpec]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        match split_short_group(arg, specs) {
            Some(expanded) => out.extend(expanded),
            None => out.push(arg.clone()),
        }
    }
    out
}

/// Splits `-xyz` into `--long-x --long-y --long-z` when every letter is a
/// known short and all but the last take no value. Anything else (`-U5`,
/// `-n`, unknown letters) is left alone for [`collect`].
fn split_short_group(arg: &str, specs: &[FlagSpec]) -> Option<Vec<String>> {
    let body = arg.strip_prefix('-')?;
    if body.starts_with('-') || body.len() < 2 {
        return None;
    }
    let mut found = Vec::new();
    for letter in body.chars() {
        if !letter.is_ascii_alphanumeric() {
            return None;
        }
        found.push(specs.iter().find(|spec| spec.short == Some(letter))?);
    }
    if found[..found.len() - 1].iter().any(|spec| spec.takes_value) {
        return None;
    }
    Some(
        found
            .iter()
            .map(|spec| format!("--{}", spec.long))
            .collect(),
    )
}

/// Rewrites bare `-<N>` tokens to `--max-count=<N>`, the way `git log -5`
/// limits output. Only all-digit bodies match, so `-U5` and paths pass
/// through untouched.
fn rewrite_dash_number(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| match arg.strip_prefix('-') {
            Some(body)
                if !arg.starts_with("--")
                    && !body.is_empty()
                    && body.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                format!("--max-count={body}")
            }
            _ => arg.clone(),
        })
        .collect()
}

/// Splits raw args at the first `--`: everything after is a path even when
/// it looks like a revision. [`collect`] erases the marker, so verbs that
/// take paths pre-split before collecting.
fn split_double_dash(args: &[String]) -> (Vec<String>, Vec<String>) {
    match args.iter().position(|arg| arg == "--") {
        None => (args.to_vec(), Vec::new()),
        Some(index) => (args[..index].to_vec(), args[index + 1..].to_vec()),
    }
}

/// Extracts `--decorate=<mode>` before collecting: the flag takes an
/// optional value, which [`collect`] cannot spell. Bare `--decorate` stays
/// for `collect` and means `short`.
fn extract_decorate_arg(args: &[String]) -> Result<(Vec<String>, Option<String>), GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut mode = None;
    for arg in args {
        match arg.strip_prefix("--decorate=") {
            None => kept.push(arg.clone()),
            Some(value) => match value {
                "short" | "full" | "auto" | "no" => mode = Some(value.to_owned()),
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!("bad --decorate={value:?}: want short|full|auto|no"),
                    });
                }
            },
        }
    }
    Ok((kept, mode))
}

/// Extracts `--short=<N>` before collecting, for the same optional-value
/// reason as [`extract_decorate_arg`]. Bare `--short` stays and means 7.
fn extract_short_len(args: &[String]) -> Result<(Vec<String>, Option<usize>), GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut len = None;
    for arg in args {
        match arg.strip_prefix("--short=") {
            None => kept.push(arg.clone()),
            Some(value) => {
                kept.push("--short".to_owned());
                let parsed: usize = value.parse().map_err(|_| GitError::Invalid {
                    detail: format!("bad --short={value:?}: want a prefix length"),
                })?;
                if parsed == 0 {
                    return Err(GitError::Invalid {
                        detail: format!("bad --short={value:?}: want a prefix length"),
                    });
                }
                len = Some(parsed);
            }
        }
    }
    Ok((kept, len))
}

/// Resolves one revision with the spellings [`resolve_rev`] lacks: `@` for
/// `HEAD` (plus `@~`/`@^` suffixes) and `<rev>:<path>` / `:<path>` blob
/// paths. Reflog `@{...}` fails closed with a clear message.
pub(crate) fn resolve_local(store: &Store, kind: HashKind, rev: &str) -> Result<Oid, GitError> {
    if rev == "@" {
        return head_oid(store);
    }
    if let Some(rest) = rev.strip_prefix('@') {
        if rest.starts_with('{') {
            return Err(GitError::Unsupported {
                command: format!("reflog lookup {rev:?} is not supported"),
            });
        }
        if rest.starts_with('~') || rest.starts_with('^') {
            return resolve_rev(store, kind, &format!("HEAD{rest}"));
        }
        return Err(GitError::NotFound {
            detail: format!("unknown revision {rev:?}"),
        });
    }
    match rev.split_once(':') {
        None => resolve_rev(store, kind, rev),
        Some((rev_part, path_part)) => blob_oid_for_path(store, kind, rev_part, path_part),
    }
}

/// Reads the blob oid behind `<rev>:<path>`, or the staged blob for
/// `:<path>`.
fn blob_oid_for_path(
    store: &Store,
    kind: HashKind,
    rev_part: &str,
    path_part: &str,
) -> Result<Oid, GitError> {
    if path_part.is_empty() {
        return Err(GitError::Invalid {
            detail: "bad revision: a path must follow ':'".to_owned(),
        });
    }
    if rev_part.is_empty() {
        for (path, stage, entry) in scan_index(store, kind)? {
            if stage == Stage::Zero && path.as_bytes() == path_part.as_bytes() {
                return Ok(entry.oid());
            }
        }
        return Err(GitError::NotFound {
            detail: format!("no staged blob for {path_part:?}"),
        });
    }
    let oid = resolve_local(store, kind, rev_part)?;
    let tree = peel_to_tree(store, kind, replace_redirect(store, oid))?;
    for (path, _, blob) in flatten_tree(store, kind, tree)? {
        if path == path_part.as_bytes() {
            return Ok(blob);
        }
    }
    Err(GitError::NotFound {
        detail: format!("{path_part:?} is not in {rev_part}"),
    })
}

/// Resolves one ref target through symbolic links, giving up after a short
/// chain instead of looping forever.
fn resolve_ref_target(store: &Store, target: Option<RefTarget>) -> Result<Option<Oid>, GitError> {
    let mut current = target;
    for _ in 0..16 {
        match current {
            None => return Ok(None),
            Some(RefTarget::Direct(oid)) => return Ok(Some(oid)),
            Some(RefTarget::Symbolic(name)) => current = read_ref(store, &name)?,
        }
    }
    Ok(None)
}

/// Tries to resolve one revision, mapping absence to `None` so callers can
/// tell paths from revs the way `diff` must.
fn try_resolve_rev(store: &Store, kind: HashKind, text: &str) -> Result<Option<Oid>, GitError> {
    match resolve_local(store, kind, text) {
        Ok(oid) => Ok(Some(oid)),
        Err(GitError::NotFound { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// One `A..B` / `A...B` range token split from its operator. Empty sides
/// mean `HEAD`, as in git.
struct Range {
    /// Excluded side (`A`).
    from: String,
    /// Included side (`B`).
    to: String,
    /// `true` for the `...` symmetric difference.
    symmetric: bool,
}

/// Splits a range token on `...` before `..`; anything else is not a range.
fn split_range(text: &str) -> Option<Range> {
    if let Some((from, to)) = text.split_once("...") {
        return Some(Range {
            from: from.to_owned(),
            to: to.to_owned(),
            symmetric: true,
        });
    }
    text.split_once("..").map(|(from, to)| Range {
        from: from.to_owned(),
        to: to.to_owned(),
        symmetric: false,
    })
}

/// Resolves one range side, defaulting empty sides to `HEAD`.
fn resolve_range_side(store: &Store, kind: HashKind, side: &str) -> Result<Oid, GitError> {
    if side.is_empty() {
        head_oid(store)
    } else {
        resolve_local(store, kind, side)
    }
}

/// Splits revision positionals into included tips and excluded commits,
/// honoring `A..B` (exclude `A`), `A...B` (exclude merge bases), `^A`, and
/// `A^!` (include `A`, exclude its parents). Plain revs are included.
/// `default` fills the tips when nothing was included.
pub(crate) fn parse_log_revs(
    store: &Store,
    kind: HashKind,
    positionals: &[String],
    default: Option<Oid>,
) -> Result<(Vec<Oid>, Vec<Oid>), GitError> {
    let mut tips = Vec::new();
    let mut exclude = Vec::new();
    for item in positionals {
        if let Some(range) = split_range(item) {
            let from = resolve_range_side(store, kind, &range.from)?;
            let to = resolve_range_side(store, kind, &range.to)?;
            if range.symmetric {
                tips.push(from);
                tips.push(to);
                exclude.extend(merge_bases_all(store, from, to)?);
            } else {
                tips.push(to);
                exclude.push(from);
            }
            continue;
        }
        if let Some(rest) = item.strip_prefix('^') {
            exclude.push(resolve_local(store, kind, rest)?);
            continue;
        }
        if let Some(base) = item.strip_suffix("^!") {
            let oid = resolve_local(store, kind, base)?;
            tips.push(oid);
            exclude.extend(commit_parents(store, oid)?);
            continue;
        }
        tips.push(resolve_local(store, kind, item)?);
    }
    if tips.is_empty() {
        tips.extend(default);
    }
    Ok((tips, exclude))
}

/// Lists the parent oids of one commit.
fn commit_parents(store: &Store, oid: Oid) -> Result<Vec<Oid>, GitError> {
    Ok(commit_record(store, oid)?
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .collect())
}

/// Walks `tips` in `git log` order while skipping `exclude` and everything
/// reachable from it, mirroring [`walk_history`] otherwise.
pub(crate) fn walk_history_excluding(
    store: &Store,
    tips: &[Oid],
    exclude: &[Oid],
    limit: Option<usize>,
) -> Result<Vec<(Oid, CommitRecord)>, GitError> {
    use ruk_core::records::Records;
    let records = Records::new(store);
    let mut seen: HashSet<Oid> = HashSet::new();
    let mut stack: Vec<Oid> = exclude.to_vec();
    while let Some(oid) = stack.pop() {
        let oid = super::state::replace_redirect(store, oid);
        if !seen.insert(oid) {
            continue;
        }
        let Ok(record) = super::state::walk_record(store, &records, oid) else {
            continue;
        };
        for parent in record.parents() {
            if let Some(parent_oid) = parent.as_git().copied() {
                stack.push(parent_oid);
            }
        }
    }
    let mut queue = super::state::WalkQueue::new();
    for oid in &seen {
        queue.mark_seen(*oid);
    }
    for tip in tips {
        queue.enqueue(store, &records, *tip)?;
    }
    let mut out = Vec::new();
    while let Some((oid, record)) = queue.pop() {
        for parent in record.parents() {
            let Some(parent_oid) = parent.as_git().copied() else {
                continue;
            };
            queue.enqueue(store, &records, parent_oid)?;
        }
        out.push((oid, record));
        if limit.is_some_and(|max| out.len() >= max) {
            return Ok(out);
        }
    }
    Ok(out)
}

/// Finds every merge base of two tips: common ancestors that are not
/// themselves ancestors of another common ancestor.
fn merge_bases_all(store: &Store, left: Oid, right: Oid) -> Result<Vec<Oid>, GitError> {
    if left == right {
        return Ok(vec![left]);
    }
    let left_set: HashSet<Oid> = walk_history(store, &[left], None)?
        .into_iter()
        .map(|(oid, _)| oid)
        .collect();
    let mut common = Vec::new();
    for (oid, _) in walk_history(store, &[right], None)? {
        if left_set.contains(&oid) {
            common.push(oid);
        }
    }
    minimize_bases(store, common)
}

/// Drops duplicate and ancestor-dominated candidates, keeping the minimal
/// base set in discovery order.
fn minimize_bases(store: &Store, candidates: Vec<Oid>) -> Result<Vec<Oid>, GitError> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for oid in candidates {
        if seen.insert(oid) {
            unique.push(oid);
        }
    }
    let mut bases = Vec::new();
    for cand in &unique {
        let mut dominated = false;
        for other in &unique {
            if cand != other && is_ancestor(store, *cand, *other)? {
                dominated = true;
                break;
            }
        }
        if !dominated {
            bases.push(*cand);
        }
    }
    Ok(bases)
}

/// Collects every commit oid behind any ref, for `--all`. Non-commit
/// targets (tag objects pointing elsewhere) are skipped.
fn all_ref_tips(store: &Store) -> Result<Vec<Oid>, GitError> {
    let mut tips = Vec::new();
    let mut seen = HashSet::new();
    for (_, target) in list_refs(store)? {
        if let Some(oid) = resolve_ref_target(store, Some(target))? {
            if commit_record(store, oid).is_ok() && seen.insert(oid) {
                tips.push(oid);
            }
        }
    }
    Ok(tips)
}

/// Validates `--mainline <n>` as a positive parent number. The sequencer
/// lane is absent, so callers check this before failing closed.
fn check_mainline(opts: &super::Collected) -> Result<(), GitError> {
    let Some(text) = opts.single("mainline")? else {
        return Ok(());
    };
    match text.parse::<usize>() {
        Ok(num) if num > 0 => Ok(()),
        _ => Err(GitError::Invalid {
            detail: format!("bad --mainline {text:?}: want a parent number"),
        }),
    }
}

/// Parses a date argument: `@<epoch>`, a bare `<epoch>`, or `YYYY-MM-DD`
/// (midnight UTC). Anything else names the accepted shapes.
fn parse_date_arg(text: &str) -> Result<i64, GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad date {text:?}: want @<epoch>, <epoch>, or YYYY-MM-DD"),
    };
    let digits = text.strip_prefix('@').unwrap_or(text);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return digits.parse().map_err(|_| bad());
    }
    let mut parts = text.split('-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(year), Some(month), Some(day), None) => {
            let year: i64 = year.parse().map_err(|_| bad())?;
            let month: i64 = month.parse().map_err(|_| bad())?;
            let day: i64 = day.parse().map_err(|_| bad())?;
            if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
                return Err(bad());
            }
            Ok(days_from_civil(year, month, day) * 86_400)
        }
        _ => Err(bad()),
    }
}

/// Counts days from 1970-01-01 to a civil date (Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted = if month <= 2 { year - 1 } else { year };
    let era = if adjusted >= 0 {
        adjusted
    } else {
        adjusted - 399
    } / 400;
    let yoe = adjusted - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Renders a timestamp the way git's `%ad` does: `Sun Oct 18 05:50:17 2026
/// +0900`, in the ident's own offset.
fn format_git_date(stamp: i64, offset: ruk_core::conflict::TzOffset) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let civil = civil_of(stamp, offset);
    format!(
        "{} {} {} {:02}:{:02}:{:02} {} {offset}",
        WEEKDAYS[civil.weekday],
        MONTHS[civil.month_index],
        civil.day,
        civil.hour,
        civil.minute,
        civil.second,
        civil.year,
    )
}

/// One parsed `--format`/`--pretty` placeholder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FormatField {
    /// `%H`: full commit oid.
    FullOid,
    /// `%h`: abbreviated commit oid.
    ShortOid,
    /// `%s`: subject (first message line).
    Subject,
    /// `%an`, `%ae`, `%ad`: author name, email, date.
    AuthorName,
    /// Author email.
    AuthorEmail,
    /// Author date.
    AuthorDate,
    /// `%cn`, `%ce`, `%cd`: committer name, email, date.
    CommitterName,
    /// Committer email.
    CommitterEmail,
    /// Committer date.
    CommitterDate,
    /// `%d`: decorations like ` (HEAD -> main)`, empty when none.
    Decoration,
    /// `%P`: parent oids, space-separated.
    Parents,
    /// `%T`: the commit's tree oid.
    Tree,
    /// `%S`: the `--source` ref name, empty when none.
    Source,
    /// `%n`: newline.
    Newline,
    /// `%%`: a literal percent.
    Percent,
}

/// One `--format` piece: literal bytes or a placeholder.
enum FormatPart {
    /// Raw bytes copied through.
    Text(Vec<u8>),
    /// Placeholder to expand per commit.
    Field(FormatField),
}

/// Parses a `--format`/`--pretty` string. Unknown placeholders fail closed
/// naming the supported set, instead of printing them through silently.
fn parse_log_format(text: &str) -> Result<Vec<FormatPart>, GitError> {
    let unknown = |letter: char| GitError::Invalid {
        detail: format!(
            "unknown placeholder %{letter} (supported: %H %h %s %an %ae %ad %cn %ce %cd %d %P %T %S %% %n)"
        ),
    };
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut literal = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            literal.push(bytes[index]);
            index += 1;
            continue;
        }
        index += 1;
        let field = match bytes.get(index) {
            Some(b'H') => FormatField::FullOid,
            Some(b'h') => FormatField::ShortOid,
            Some(b's') => FormatField::Subject,
            Some(b'd') => FormatField::Decoration,
            Some(b'P') => FormatField::Parents,
            Some(b'T') => FormatField::Tree,
            Some(b'S') => FormatField::Source,
            Some(b'n') => FormatField::Newline,
            Some(b'%') => FormatField::Percent,
            Some(b'a') => match bytes.get(index + 1) {
                Some(b'n') => {
                    index += 1;
                    FormatField::AuthorName
                }
                Some(b'e') => {
                    index += 1;
                    FormatField::AuthorEmail
                }
                Some(b'd') => {
                    index += 1;
                    FormatField::AuthorDate
                }
                Some(letter) => return Err(unknown(char::from(*letter))),
                None => return Err(unknown(' ')),
            },
            Some(b'c') => match bytes.get(index + 1) {
                Some(b'n') => {
                    index += 1;
                    FormatField::CommitterName
                }
                Some(b'e') => {
                    index += 1;
                    FormatField::CommitterEmail
                }
                Some(b'd') => {
                    index += 1;
                    FormatField::CommitterDate
                }
                Some(letter) => return Err(unknown(char::from(*letter))),
                None => return Err(unknown(' ')),
            },
            Some(letter) => return Err(unknown(char::from(*letter))),
            None => {
                return Err(GitError::Invalid {
                    detail: "dangling % at the end of --format".to_owned(),
                });
            }
        };
        if !literal.is_empty() {
            parts.push(FormatPart::Text(std::mem::take(&mut literal)));
        }
        parts.push(FormatPart::Field(field));
        index += 1;
    }
    if !literal.is_empty() {
        parts.push(FormatPart::Text(literal));
    }
    Ok(parts)
}

/// Parses a `--pretty <name>` shorthand: `oneline` shortens, the other
/// stock names keep the default header, and anything with a placeholder
/// (after an optional `format:`/`tformat:` prefix) is a format string.
fn parse_pretty_arg(text: &str) -> Result<Option<Vec<FormatPart>>, GitError> {
    match text {
        "oneline" => Ok(None),
        "short" | "medium" | "full" | "fuller" => Ok(None),
        _ => {
            let body = text
                .strip_prefix("format:")
                .or_else(|| text.strip_prefix("tformat:"))
                .unwrap_or(text);
            if body.contains('%') {
                parse_log_format(body).map(Some)
            } else {
                Err(GitError::Invalid {
                    detail: format!(
                        "unsupported --pretty {text:?} (supported: oneline, short, medium, full, fuller, format:...)"
                    ),
                })
            }
        }
    }
}

/// How `--date` renders `%ad`/`%cd` and the `Date:` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DateMode {
    /// `Sun Oct 18 05:50:17 2026 +0900`, in the ident's own offset.
    Default,
    /// `3 days ago` against the invocation time.
    Relative,
    /// `2026-10-18`.
    Short,
    /// `2026-10-18 05:50:17 +0900`.
    Iso,
    /// `<epoch> <±HHMM>`.
    Raw,
    /// `<epoch>`.
    Unix,
}

/// Parses `--date=<fmt>`. `local` and `format:...` need timezone conversion
/// and strftime shaping this tool does not implement, so they fail
/// `Unsupported` loudly instead of rendering a neighboring format.
fn parse_date_mode(text: &str) -> Result<DateMode, GitError> {
    match text {
        "default" => Ok(DateMode::Default),
        "relative" => Ok(DateMode::Relative),
        "short" => Ok(DateMode::Short),
        "iso" | "iso-strict" => Ok(DateMode::Iso),
        "raw" => Ok(DateMode::Raw),
        "unix" => Ok(DateMode::Unix),
        "local" | "rfc" | "rfc2822" | "email" => Err(GitError::Unsupported {
            command: format!("--date={text} is not supported"),
        }),
        _ if text.starts_with("format:") => Err(GitError::Unsupported {
            command: "--date=format:... is not supported".to_owned(),
        }),
        _ => Err(GitError::Invalid {
            detail: format!(
                "bad --date {text:?}: want default|relative|short|iso|raw|unix"
            ),
        }),
    }
}

/// One civil date in the ident's own offset, backing every `--date` shape.
struct CivilDate {
    /// Full year.
    year: i64,
    /// Month 1..=12.
    month: i64,
    /// Day 1..=31.
    day: i64,
    /// Hour, minute, second.
    hour: i64,
    /// Minute.
    minute: i64,
    /// Second.
    second: i64,
    /// Weekday index into the git `Thu..Wed` table.
    weekday: usize,
    /// Month index 0..=11.
    month_index: usize,
}

/// Splits a timestamp into civil fields in the ident's own offset, the same
/// arithmetic [`format_git_date`] prints.
fn civil_of(stamp: i64, offset: TzOffset) -> CivilDate {
    let hhmm = i64::from(offset.hhmm());
    let shift = (hhmm / 100) * 3_600 + (hhmm % 100) * 60;
    let local = stamp + if offset.is_negative() { -shift } else { shift };
    let days = local.div_euclid(86_400);
    let clock = local.rem_euclid(86_400);
    let civil = days + 719_468;
    let era = if civil >= 0 { civil } else { civil - 146_096 } / 146_097;
    let doe = civil - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let full_year = if month <= 2 { year + 1 } else { year };
    let weekday = usize::try_from(days.rem_euclid(7)).expect("weekday remainder fits in seven");
    let month_index =
        usize::try_from(month - 1).expect("parsed month 1..=12 gives index 0..=11");
    CivilDate {
        year: full_year,
        month,
        day,
        hour: clock / 3_600,
        minute: (clock % 3_600) / 60,
        second: clock % 60,
        weekday,
        month_index,
    }
}

/// Renders `2 hours ago` style relative dates against `now`, with git's
/// unit ladder (seconds, minutes, hours, days, weeks, months, years).
fn relative_date(now: i64, stamp: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;
    const WEEK: i64 = 7 * DAY;
    const MONTH: i64 = 30 * DAY;
    const YEAR: i64 = 365 * DAY;
    let diff = now.saturating_sub(stamp).max(0);
    let (count, unit) = if diff < MINUTE {
        (diff, "second")
    } else if diff < HOUR {
        (diff / MINUTE, "minute")
    } else if diff < DAY {
        (diff / HOUR, "hour")
    } else if diff < WEEK {
        (diff / DAY, "day")
    } else if diff < 5 * WEEK {
        (diff / WEEK, "week")
    } else if diff < YEAR {
        (diff / MONTH, "month")
    } else {
        (diff / YEAR, "year")
    };
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

/// Renders one ident timestamp in a `--date` shape.
fn render_date(stamp: i64, offset: TzOffset, mode: DateMode, now: i64) -> String {
    match mode {
        DateMode::Default => format_git_date(stamp, offset),
        DateMode::Relative => relative_date(now, stamp),
        DateMode::Short => {
            let civil = civil_of(stamp, offset);
            format!("{:04}-{:02}-{:02}", civil.year, civil.month, civil.day)
        }
        DateMode::Iso => {
            let civil = civil_of(stamp, offset);
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {offset}",
                civil.year, civil.month, civil.day, civil.hour, civil.minute, civil.second,
            )
        }
        DateMode::Raw => format!("{stamp} {offset}"),
        DateMode::Unix => format!("{stamp}"),
    }
}

/// Named `--pretty` shapes beyond the default header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrettyKind {
    /// `short`/`medium`: the default header.
    Default,
    /// `Author:` plus `Commit:` identity lines.
    Full,
    /// `Full` plus `AuthorDate:`/`CommitDate:` lines.
    Fuller,
    /// Mbox headers plus subject and body.
    Email,
    /// Raw `tree`/`parent`/`author`/`committer` header plus message.
    Raw,
}

/// Strips an optional `format:`/`tformat:` prefix, which both `--pretty`
/// and `--format` accept around a placeholder string.
fn strip_format_prefix(text: &str) -> &str {
    text.strip_prefix("format:")
        .or_else(|| text.strip_prefix("tformat:"))
        .unwrap_or(text)
}

/// Shortens one object id to `len` hex chars (saturating at the full hex).
fn short_hex_len(oid: &Oid, len: usize) -> String {
    oid.to_hex().chars().take(len.max(1)).collect()
}

/// Renders parsed format parts for one commit. `decoration` is the `%d`
/// text including its leading space, or empty when undecorated; `source`
/// is the `--source` ref name (`%S`), empty when none.
fn render_log_format(
    parts: &[FormatPart],
    line: &CommitLine,
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
    source: &str,
) -> Result<Vec<u8>, GitError> {
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    let author = record.author().map_err(|_| broken("author"))?;
    let committer = record.committer().map_err(|_| broken("committer"))?;
    let mut out = Vec::new();
    for part in parts {
        match part {
            FormatPart::Text(bytes) => out.extend_from_slice(bytes),
            FormatPart::Field(field) => match field {
                FormatField::FullOid => out.extend_from_slice(oid.to_hex().as_bytes()),
                FormatField::ShortOid => {
                    out.extend_from_slice(short_hex_len(oid, line.abbrev_len).as_bytes());
                }
                FormatField::Subject => {
                    out.extend_from_slice(first_subject_line(record.message()).as_bytes());
                }
                FormatField::AuthorName => out.extend_from_slice(author.name.as_bytes()),
                FormatField::AuthorEmail => out.extend_from_slice(author.email.as_bytes()),
                FormatField::AuthorDate => {
                    out.extend_from_slice(
                        render_date(author.timestamp, author.offset, line.date, line.now)
                            .as_bytes(),
                    );
                }
                FormatField::CommitterName => out.extend_from_slice(committer.name.as_bytes()),
                FormatField::CommitterEmail => out.extend_from_slice(committer.email.as_bytes()),
                FormatField::CommitterDate => {
                    out.extend_from_slice(
                        render_date(committer.timestamp, committer.offset, line.date, line.now)
                            .as_bytes(),
                    );
                }
                FormatField::Decoration => out.extend_from_slice(decoration.as_bytes()),
                FormatField::Parents => {
                    let parents: Vec<String> = record
                        .parents()
                        .iter()
                        .filter_map(|head| head.as_git().map(|oid| oid.to_hex()))
                        .collect();
                    out.extend_from_slice(parents.join(" ").as_bytes());
                }
                FormatField::Tree => {
                    out.extend_from_slice(commit_tree_oid(record)?.to_hex().as_bytes());
                }
                FormatField::Source => out.extend_from_slice(source.as_bytes()),
                FormatField::Newline => out.push(b'\n'),
                FormatField::Percent => out.push(b'%'),
            },
        }
    }
    Ok(out)
}

/// How one commit's identity line renders: short header, full header, or a
/// caller-supplied format.
struct CommitLine {
    /// Shorten to `--oneline` form.
    oneline: bool,
    /// Parsed `--format`/`--pretty`, when given.
    format: Option<Vec<FormatPart>>,
    /// Shorten the header oid (`--abbrev-commit`).
    abbrev: bool,
    /// Abbreviated oid width (`--abbrev=<n>`, default 7).
    abbrev_len: usize,
    /// Named `--pretty` shape beyond the default header.
    pretty: PrettyKind,
    /// `--date` shape for `%ad`/`%cd` and `Date:` lines.
    date: DateMode,
    /// Invocation time for relative dates.
    now: i64,
}

/// Renders one commit's identity line for `log` and `show`.
fn render_commit_line(
    line: &CommitLine,
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
) -> Result<Vec<u8>, GitError> {
    render_commit_line_full(line, oid, record, decoration, "")
}

/// Renders one commit's identity line with `--source` text: `source` is
/// the reaching ref name, empty when `--source` is off or the tip is
/// unnamed. Oneline form is `<short> <source> <subject>`; the header form
/// appends the source after the oid, before decorations.
fn render_commit_line_full(
    line: &CommitLine,
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
    source: &str,
) -> Result<Vec<u8>, GitError> {
    if let Some(parts) = &line.format {
        let mut out = render_log_format(parts, line, oid, record, decoration, source)?;
        out.push(b'\n');
        return Ok(out);
    }
    if line.oneline {
        let subject = first_subject_line(record.message());
        let short = short_hex_len(oid, line.abbrev_len);
        if source.is_empty() {
            return Ok(format!("{short} {subject}\n").into_bytes());
        }
        return Ok(format!("{short} {source} {subject}\n").into_bytes());
    }
    if line.pretty != PrettyKind::Default {
        return render_pretty_shape(line, oid, record, decoration);
    }
    let id = if line.abbrev {
        short_hex_len(oid, line.abbrev_len)
    } else {
        oid.to_hex()
    };
    let source_text = if source.is_empty() {
        String::new()
    } else {
        format!(" {source}")
    };
    let mut out = format!("commit {id}{source_text}{decoration}\n").into_bytes();
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    let author = record.author().map_err(|_| broken("author"))?;
    out.extend_from_slice(b"Author: ");
    out.extend_from_slice(author.name.as_bytes());
    out.extend_from_slice(b" <");
    out.extend_from_slice(author.email.as_bytes());
    out.extend_from_slice(b">\n");
    out.extend_from_slice(
        format!(
            "Date:   {}\n",
            render_date(author.timestamp, author.offset, line.date, line.now)
        )
        .as_bytes(),
    );
    out.push(b'\n');
    out.extend_from_slice(&indented_message(record.message()));
    out.push(b'\n');
    Ok(out)
}

/// Renders the `--pretty=full`/`fuller`/`email`/`raw` shapes: full adds the
/// committer line, fuller adds both date lines, email renders mbox
/// headers, and raw renders the stored header lines verbatim.
fn render_pretty_shape(
    line: &CommitLine,
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
) -> Result<Vec<u8>, GitError> {
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    let author = record.author().map_err(|_| broken("author"))?;
    let committer = record.committer().map_err(|_| broken("committer"))?;
    let id = if line.abbrev {
        short_hex_len(oid, line.abbrev_len)
    } else {
        oid.to_hex()
    };
    let mut out = Vec::new();
    match line.pretty {
        PrettyKind::Default => {
            out.extend_from_slice(format!("commit {id}{decoration}\n").as_bytes());
            out.extend_from_slice(&indented_message(record.message()));
            out.push(b'\n');
            return Ok(out);
        }
        PrettyKind::Full => {
            out.extend_from_slice(format!("commit {id}{decoration}\n").as_bytes());
            push_ident(&mut out, "Author: ", &author);
            push_ident(&mut out, "Commit: ", &committer);
        }
        PrettyKind::Fuller => {
            out.extend_from_slice(format!("commit {id}{decoration}\n").as_bytes());
            push_ident(&mut out, "Author:     ", &author);
            out.extend_from_slice(
                format!(
                    "AuthorDate: {}\n",
                    render_date(author.timestamp, author.offset, line.date, line.now)
                )
                .as_bytes(),
            );
            push_ident(&mut out, "Commit:     ", &committer);
            out.extend_from_slice(
                format!(
                    "CommitDate: {}\n",
                    render_date(committer.timestamp, committer.offset, line.date, line.now)
                )
                .as_bytes(),
            );
        }
        PrettyKind::Email => {
            let subject = first_subject_line(record.message());
            out.extend_from_slice(
                format!(
                    "From {} {}\n",
                    oid.to_hex(),
                    format_git_date(author.timestamp, author.offset)
                )
                .as_bytes(),
            );
            out.extend_from_slice(b"From: ");
            out.extend_from_slice(author.name.as_bytes());
            out.extend_from_slice(b" <");
            out.extend_from_slice(author.email.as_bytes());
            out.extend_from_slice(b">\n");
            out.extend_from_slice(
                format!(
                    "Date: {}\n",
                    render_date(author.timestamp, author.offset, line.date, line.now)
                )
                .as_bytes(),
            );
            out.extend_from_slice(format!("Subject: [PATCH] {subject}\n").as_bytes());
            out.push(b'\n');
            out.extend_from_slice(&message_body(record.message()));
            if !out.ends_with(b"\n") {
                out.push(b'\n');
            }
            return Ok(out);
        }
        PrettyKind::Raw => {
            out.extend_from_slice(format!("commit {}\n", oid.to_hex()).as_bytes());
            out.extend_from_slice(
                format!("tree {}\n", commit_tree_oid(record)?.to_hex()).as_bytes(),
            );
            for parent in record
                .parents()
                .iter()
                .filter_map(|head| head.as_git().copied())
            {
                out.extend_from_slice(format!("parent {}\n", parent.to_hex()).as_bytes());
            }
            push_raw_ident(&mut out, "author", &author);
            push_raw_ident(&mut out, "committer", &committer);
            out.push(b'\n');
            let mut message = record.message().to_vec();
            if !message.ends_with(b"\n") {
                message.push(b'\n');
            }
            out.extend_from_slice(&message);
            return Ok(out);
        }
    }
    out.push(b'\n');
    out.extend_from_slice(&indented_message(record.message()));
    out.push(b'\n');
    Ok(out)
}

/// Pushes one identity line behind its full label (`Author: ` or the
/// padded `Author:     ` fuller shape).
fn push_ident(out: &mut Vec<u8>, label: &str, ident: &Signature) {
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(ident.name.as_bytes());
    out.extend_from_slice(b" <");
    out.extend_from_slice(ident.email.as_bytes());
    out.extend_from_slice(b">\n");
}

/// Pushes one raw `author <name> <email> <epoch> <±HHMM>` header line.
fn push_raw_ident(out: &mut Vec<u8>, role: &str, ident: &Signature) {
    out.extend_from_slice(
        format!(
            "{role} {} <{}> {} {}\n",
            String::from_utf8_lossy(ident.name.as_bytes()),
            String::from_utf8_lossy(ident.email.as_bytes()),
            ident.timestamp,
            ident.offset,
        )
        .as_bytes(),
    );
}

/// Indents a message body four spaces the way the pretty printer does,
/// chomping trailing newlines first so `one\n` renders as `    one\n`.
fn indented_message(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut body = message;
    while body.last() == Some(&b'\n') {
        body = &body[..body.len() - 1];
    }
    for message_line in body.split(|byte| *byte == b'\n') {
        out.extend_from_slice(b"    ");
        out.extend_from_slice(message_line);
        out.push(b'\n');
    }
    out
}

/// Takes the message after its subject line, dropping the blank separator,
/// for `--pretty=email` bodies.
fn message_body(message: &[u8]) -> Vec<u8> {
    let mut lines = message.split(|byte| *byte == b'\n').peekable();
    lines.next();
    let rest: Vec<&[u8]> = lines.collect();
    let mut start = 0;
    while start < rest.len() && rest[start].is_empty() {
        start += 1;
    }
    let mut out = Vec::new();
    for line in &rest[start..] {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Builds the oid-to-decoration map from every ref, marking the checked-out
/// branch `HEAD -> <branch>` the way git does.
fn decoration_map(store: &Store) -> Result<HashMap<Oid, Vec<String>>, GitError> {
    let mut map: HashMap<Oid, Vec<String>> = HashMap::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        if let Some(oid) = resolve_ref_target(store, Some(target))? {
            map.entry(oid).or_default().push(text);
        }
    }
    for names in map.values_mut() {
        names.sort();
        names.dedup();
    }
    let (workspace, _) = load_or_default(store)?;
    if let HeadRef::Symbolic(name) = &workspace.head {
        let branch = name
            .to_utf8()
            .unwrap_or_default()
            .trim_start_matches("refs/heads/")
            .to_owned();
        if let Some(oid) = resolve_ref_target(store, read_ref(store, name)?)? {
            let full = name.to_utf8().unwrap_or_default().to_owned();
            let entry = map.entry(oid).or_default();
            entry.retain(|existing| existing != &full);
            entry.insert(0, format!("HEAD -> {branch}"));
        }
    }
    Ok(map)
}

/// Shortens one ref name for `short` decorations, keeping other names full.
fn short_ref_name(text: &str) -> &str {
    text.strip_prefix("refs/heads/")
        .or_else(|| text.strip_prefix("refs/tags/"))
        .or_else(|| text.strip_prefix("refs/remotes/"))
        .unwrap_or(text)
}

/// Renders the `%d` text for one commit: ` (HEAD -> main, v1)` with its
/// leading space, or empty when undecorated.
fn decoration_text(map: &HashMap<Oid, Vec<String>>, oid: &Oid, full: bool) -> String {
    match map.get(oid) {
        Some(names) if !names.is_empty() => {
            let list: Vec<&str> = names
                .iter()
                .map(|name| {
                    if full {
                        name.as_str()
                    } else {
                        short_ref_name(name)
                    }
                })
                .collect();
            format!(" ({})", list.join(", "))
        }
        _ => String::new(),
    }
}

/// Reports whether `path` equals `want` or lives under it, so `log --
/// <dir>` matches everything beneath the directory like git.
fn path_wanted(path: &[u8], want: &[u8]) -> bool {
    path == want || (path.starts_with(want) && path.get(want.len()) == Some(&b'/'))
}

/// Reports whether a commit changes any wanted path against any parent (or
/// introduces it, for a root commit).
fn commit_touches_path(
    store: &Store,
    kind: HashKind,
    record: &CommitRecord,
    wants: &[Vec<u8>],
) -> Result<bool, GitError> {
    let tree = commit_tree_oid(record)?;
    let mut current = BTreeMap::new();
    for (path, _, blob) in flatten_tree(store, kind, tree)? {
        current.insert(path, blob);
    }
    let parents = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .collect::<Vec<_>>();
    if parents.is_empty() {
        return Ok(current
            .keys()
            .any(|path| wants.iter().any(|want| path_wanted(path, want))));
    }
    for parent in parents {
        let parent_tree = commit_tree_oid(&commit_record(store, parent)?)?;
        let mut before = BTreeMap::new();
        for (path, _, blob) in flatten_tree(store, kind, parent_tree)? {
            before.insert(path, blob);
        }
        let mut keys: Vec<&Vec<u8>> = current.keys().chain(before.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            if !wants.iter().any(|want| path_wanted(key, want)) {
                continue;
            }
            if current.get(key) != before.get(key) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Prefixes one commit's output block with graph markers: `* ` on the
/// commit line, `| ` on every following line, as `git log --graph` draws a
/// linear strand.
fn graph_block(block: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, raw_line) in block.split_inclusive(|byte| *byte == b'\n').enumerate() {
        out.extend_from_slice(if index == 0 { b"* " } else { b"| " });
        out.extend_from_slice(raw_line);
    }
    if !block.ends_with(b"\n") && !block.is_empty() {
        out.push(b'\n');
    }
    out
}

/// Joins history lines with the fast-forward merge of one branch, or a real
/// three-way merge through the lane when both sides moved.
///
/// Oracle: `git/builtin/merge.c`. Fast-forwards keep their path; anything
/// else plans `{base, ours, theirs}` over the syntax lane with the bounded
/// text merge as the `Declined` fallback.
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
        // Accepted: fast-forward is the only merge this slice performs, so
        // `--ff` (the oracle default) is already the behavior.
        FlagSpec {
            long: "ff",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
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
    if opts.is_set("abort") {
        return merge_abort(ctx);
    }
    if opts.is_set("quit") {
        return merge_quit(ctx);
    }
    if opts.is_set("continue") {
        return merge_continue(ctx);
    }
    if opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: merge <rev>".to_owned(),
        });
    }
    let rev = opts.positionals.first().ok_or_else(|| GitError::Invalid {
        detail: "usage: merge <rev>".to_owned(),
    })?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tip = resolve_rev(store, kind, rev)?;
    let message = opts.single("message")?;
    let quiet = opts.is_set("quiet");
    let no_ff = opts.is_set("no-ff");
    let current = match head_oid(store) {
        Ok(tip) => tip,
        Err(_) => {
            let out = merge_into_unborn(ctx, rev, tip)?;
            return Ok(hush_merge(out, quiet));
        }
    };
    if current == tip {
        return Ok(hush_merge(b"Already up to date.\n".to_vec(), quiet));
    }
    let ff = is_ancestor(store, current, tip)?;
    if opts.is_set("ff-only") && !ff {
        return Err(GitError::Invalid {
            detail: "Not possible to fast-forward, aborting.".to_owned(),
        });
    }
    if ff && !no_ff {
        let (workspace, _) = load_or_default(store)?;
        if matches!(workspace.head, HeadRef::Detached(_)) {
            let out = merge_fast_forward_detached(ctx, current, tip)?;
            return Ok(hush_merge(out, quiet));
        }
        let out = merge_fast_forward(ctx, rev, current, tip)?;
        return Ok(hush_merge(out, quiet));
    }
    if is_ancestor(store, tip, current)? {
        return Ok(hush_merge(b"Already up to date.\n".to_vec(), quiet));
    }
    let out = merge_content(ctx, rev, current, tip, message)?;
    Ok(hush_merge(out, quiet))
}

/// Merges one tip through the three-way lane: plans, guards, applies, and
/// either commits the merge or leaves conflict state behind.
fn merge_content(
    ctx: &Ctx,
    rev: &str,
    current: Oid,
    tip: Oid,
    message: Option<String>,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = require_clean_index(store, kind)?;
    let base = state_merge_base(store, current, tip).map_err(|err| match err {
        GitError::NotFound { .. } => GitError::Invalid {
            detail: "refusing to merge unrelated histories".to_owned(),
        },
        other => other,
    })?;
    let label = branch_label_of(ctx)?;
    let default_message = format!("Merge {rev} into {label}");
    // A `--no-ff` fast-forward has an empty ours side: take theirs wholesale.
    if base == current {
        snapshot_abort_index(ctx, "merge")?;
        let ours_tree = commit_tree_oid(&commit_record(store, current)?)?;
        let theirs_tree = commit_tree_oid(&commit_record(store, tip)?)?;
        let staged = take_tree_state(ctx, ours_tree, theirs_tree)?;
        let new_oid = lane_commit(
            ctx,
            build_index_tree(store, kind, &staged)?,
            vec![current, tip],
            message.unwrap_or(default_message),
        )?;
        pseudo_write(store, "ORIG_HEAD", current.to_hex().into_bytes())?;
        pseudo_delete(store, "abort-index/merge")?;
        let subject = message_subject(ctx, &new_oid)?;
        return commit_summary(
            ctx,
            Some(commit_tree_oid(&commit_record(store, current)?)?),
            commit_tree_oid(&commit_record(store, new_oid)?)?,
            &new_oid,
            &label,
            &subject,
        );
    }
    let base_tree = commit_tree_oid(&commit_record(store, base)?)?;
    let ours_tree = commit_tree_oid(&commit_record(store, current)?)?;
    let theirs_tree = commit_tree_oid(&commit_record(store, tip)?)?;
    let plan = plan_merge_trees(ctx, base_tree, ours_tree, theirs_tree, "HEAD", rev)?;
    let ours_map = lane_tree_map(store, kind, ours_tree)?;
    guard_lane_worktree(ctx, &rows, &ours_map, &plan, "merge")?;
    snapshot_abort_index(ctx, "merge")?;
    let staged = apply_merge_plan(ctx, &plan)?;
    if !plan.conflicted.is_empty() {
        let text = message.unwrap_or(default_message);
        write_merge_state(ctx, &current, &tip, &text)?;
        return Err(merge_conflict_error(&plan));
    }
    let new_oid = lane_commit(
        ctx,
        build_index_tree(store, kind, &staged)?,
        vec![current, tip],
        message.unwrap_or(default_message),
    )?;
    pseudo_write(store, "ORIG_HEAD", current.to_hex().into_bytes())?;
    pseudo_delete(store, "abort-index/merge")?;
    let mut out = b"Merge made by the 'ort' strategy.\n".to_vec();
    let changes = tree_file_changes(
        ctx,
        Some(ours_tree),
        commit_tree_oid(&commit_record(store, new_oid)?)?,
    )?;
    out.extend_from_slice(&render_file_stat(&changes));
    Ok(out)
}

/// Plans one tree staged wholesale over another: paths the target holds
/// resolve to `Take`, paths only the old tree holds resolve to `Deleted`.
fn plan_take_tree(
    target: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    ours: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
) -> Result<MergePlan, GitError> {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(target.keys().cloned());
    keys.extend(ours.keys().cloned());
    let mut resolutions = Vec::with_capacity(keys.len());
    for path in keys {
        match target.get(&path) {
            Some((mode, oid)) => resolutions.push((
                path,
                PathResolution::Take {
                    mode: mode.as_index_mode()?,
                    oid: *oid,
                },
            )),
            None => resolutions.push((path, PathResolution::Deleted)),
        }
    }
    Ok(MergePlan {
        resolutions,
        auto_merged: Vec::new(),
        conflicted: Vec::new(),
    })
}

/// Stages one tree wholesale over another through the guarded lane.
fn take_tree_state(
    ctx: &Ctx,
    ours_tree: Oid,
    target_tree: Oid,
) -> Result<Vec<(Vec<u8>, IndexEntry)>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = require_clean_index(store, kind)?;
    let target = lane_tree_map(store, kind, target_tree)?;
    let ours_map = lane_tree_map(store, kind, ours_tree)?;
    let plan = plan_take_tree(&target, &ours_map)?;
    guard_lane_worktree(ctx, &rows, &ours_map, &plan, "merge")?;
    apply_merge_plan(ctx, &plan)
}

/// Writes `ORIG_HEAD`, `MERGE_HEAD`, `MERGE_MSG`, and the sequencer record.
fn write_merge_state(ctx: &Ctx, current: &Oid, tip: &Oid, message: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    pseudo_write(store, "ORIG_HEAD", current.to_hex().into_bytes())?;
    pseudo_write(store, "MERGE_HEAD", tip.to_hex().into_bytes())?;
    pseudo_write(store, "MERGE_MSG", message.as_bytes().to_vec())?;
    sequencer_write(
        store,
        "merge",
        &SequencerState {
            verb: "merge".to_owned(),
            head_hex: current.to_hex(),
            target_hex: tip.to_hex(),
            message: message.to_owned(),
        },
    )
}

/// Renders the oracle-style conflict report for a stopped merge.
fn merge_conflict_error(plan: &MergePlan) -> GitError {
    let mut detail = String::new();
    for path in &plan.auto_merged {
        detail.push_str(&format!("Auto-merging {path}\n"));
    }
    for path in &plan.conflicted {
        detail.push_str(&format!("CONFLICT (content): Merge conflict in {path}\n"));
    }
    detail.push_str("Automatic merge failed; fix conflicts and then commit the result.");
    GitError::Invalid { detail }
}

/// Concludes a conflicted merge from the resolved index: the shared body of
/// `merge --continue` and an explicit `commit` over `MERGE_HEAD`.
fn conclude_merge(ctx: &mut Ctx, message: Option<String>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "you have not concluded your merge (MERGE_HEAD exists)".to_owned(),
        });
    }
    let merge_head = pseudo_read_oid(store, "MERGE_HEAD")?.ok_or_else(|| GitError::Corrupt {
        detail: "MERGE_HEAD is missing".to_owned(),
    })?;
    let text = match message {
        Some(text) => text,
        None => pseudo_read(store, "MERGE_MSG")?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| {
                format!(
                    "Merge {} into {}",
                    merge_head.to_hex(),
                    branch_label_of(ctx).unwrap_or_default()
                )
            }),
    };
    let head = head_oid(store)?;
    let old_tree = commit_tree_oid(&commit_record(store, head)?)?;
    let tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let new_oid = lane_commit(ctx, tree, vec![head, merge_head], text)?;
    sequencer_delete(store, "merge")?;
    pseudo_delete(store, "MERGE_HEAD")?;
    pseudo_delete(store, "MERGE_MSG")?;
    pseudo_delete(store, "abort-index/merge")?;
    let label = branch_label_of(ctx)?;
    let subject = message_subject(ctx, &new_oid)?;
    commit_summary(ctx, Some(old_tree), tree, &new_oid, &label, &subject)
}

/// Reads the subject line of one commit message.
fn message_subject(ctx: &Ctx, oid: &Oid) -> Result<String, GitError> {
    let store = ctx.store()?;
    let record = commit_record(store, *oid)?;
    let message = record.message();
    Ok(String::from_utf8_lossy(&message)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned())
}

/// Resumes a conflicted merge from the resolved index.
fn merge_continue(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    if sequencer_read(store, "merge")?.is_none() {
        return no_sequencer("merge", "continue");
    }
    conclude_merge(ctx, None)
}

/// Abandons a conflicted merge, restoring the pre-merge index and worktree.
fn merge_abort(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let Some(seq) = sequencer_read(store, "merge")? else {
        return no_sequencer("merge", "abort");
    };
    let orig = Oid::from_hex(&seq.head_hex).map_err(|_| GitError::Corrupt {
        detail: "merge sequencer head does not decode".to_owned(),
    })?;
    if head_oid(store)? != orig {
        super::verbs_branch::move_branch_to(ctx, orig)?;
    }
    restore_abort_index(ctx, "merge")?;
    sequencer_delete(store, "merge")?;
    pseudo_delete(store, "MERGE_HEAD")?;
    pseudo_delete(store, "MERGE_MSG")?;
    Ok(Vec::new())
}

/// Drops merge state while keeping the index and worktree as they are.
fn merge_quit(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    if sequencer_read(store, "merge")?.is_none() {
        return no_sequencer("merge", "quit");
    }
    sequencer_delete(store, "merge")?;
    pseudo_delete(store, "MERGE_HEAD")?;
    pseudo_delete(store, "MERGE_MSG")?;
    pseudo_delete(store, "abort-index/merge")?;
    Ok(Vec::new())
}

/// Drops merge output for `--quiet`, keeping the exit status as the signal.
fn hush_merge(out: Vec<u8>, quiet: bool) -> Vec<u8> {
    if quiet { Vec::new() } else { out }
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
            fast_forward_to(ctx, None, tip)?;
            Ok(format!("Fast-forwarded to {rev}\n").into_bytes())
        }
        HeadRef::Detached(_) => Err(GitError::Invalid {
            detail: "cannot merge into a detached HEAD with no commits".to_owned(),
        }),
    }
}

/// Resets the index and worktree to one commit's tree after a branch move,
/// touching only paths the two trees disagree on: untracked files and staged
/// extras elsewhere are never listed, read, or removed.
fn fast_forward_to(ctx: &Ctx, old_tree: Option<Oid>, tip: Oid) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let new_tree = commit_tree_oid(&commit_record(store, tip)?)?;
    let new_map = lane_tree_map(store, kind, new_tree)?;
    let old_map = match old_tree {
        Some(tree) => lane_tree_map(store, kind, tree)?,
        None => BTreeMap::new(),
    };
    let rows = require_clean_index(store, kind)?;
    let plan = plan_take_tree(&new_map, &old_map)?;
    guard_lane_worktree(ctx, &rows, &old_map, &plan, "merge")?;
    apply_merge_plan(ctx, &plan)?;
    Ok(())
}

/// Fast-forwards a detached `HEAD` through the guarded lane: no new commit,
/// only the scoped index and worktree move.
fn merge_fast_forward_detached(ctx: &Ctx, before: Oid, tip: Oid) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let old_tree = commit_tree_oid(&commit_record(store, before)?)?;
    let new_tree = commit_tree_oid(&commit_record(store, tip)?)?;
    let changes = tree_file_changes(ctx, Some(old_tree), new_tree)?;
    take_tree_state(ctx, old_tree, new_tree)?;
    advance_head_to(ctx, tip)?;
    let mut out = format!(
        "Updating {}..{}\nFast-forward\n",
        short_hex(&before),
        short_hex(&tip)
    )
    .into_bytes();
    out.extend_from_slice(&render_file_stat(&changes));
    out.extend_from_slice(&render_mode_lines(&changes));
    Ok(out)
}

/// Fast-forwards the current branch to a descendant tip, reporting
/// `Updating <old>..<new>` plus the file stat the way the oracle does.
pub(crate) fn merge_fast_forward(
    ctx: &Ctx,
    rev: &str,
    before: Oid,
    tip: Oid,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        HeadRef::Symbolic(_) => {
            let old_tree = commit_tree_oid(&commit_record(store, before)?)?;
            let new_tree = commit_tree_oid(&commit_record(store, tip)?)?;
            let changes = tree_file_changes(ctx, Some(old_tree), new_tree)?;
            super::verbs_branch::move_branch_to(ctx, tip)?;
            fast_forward_to(ctx, Some(old_tree), tip)?;
            let _ = rev;
            let mut out = format!(
                "Updating {}..{}\nFast-forward\n",
                short_hex(&before),
                short_hex(&tip)
            )
            .into_bytes();
            out.extend_from_slice(&render_file_stat(&changes));
            out.extend_from_slice(&render_mode_lines(&changes));
            Ok(out)
        }
        HeadRef::Detached(_) => Err(GitError::Unsupported {
            command: "merge into a detached HEAD needs the merge lane".to_owned(),
        }),
    }
}

/// Reapplies commits on another base, one three-way replay per commit.
///
/// Oracle: `git/builtin/rebase.c`. Supports `rebase <upstream>` and
/// `rebase --onto <new> <upstream>`; switching branches mid-rebase stays
/// `Unsupported`, and merge commits in the replayed range are dropped the
/// way the oracle drops them without `--rebase-merges`.
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
            long: "skip",
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
    if opts.is_set("abort") {
        return pick_abort(ctx, "rebase", None);
    }
    if opts.is_set("quit") {
        return pick_quit(ctx, "rebase", None);
    }
    if opts.is_set("continue") {
        return rebase_continue(ctx);
    }
    if opts.is_set("skip") {
        return rebase_skip(ctx);
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (onto, upstream) = match opts.single("onto")? {
        Some(rev) => {
            let onto = resolve_rev(store, kind, &rev)?;
            let upstream = match opts.positionals.first() {
                Some(rev) => resolve_rev(store, kind, rev)?,
                None => {
                    return Err(GitError::Invalid {
                        detail: "usage: rebase --onto <newbase> <upstream>".to_owned(),
                    });
                }
            };
            if opts.positionals.len() > 1 {
                return Err(GitError::Unsupported {
                    command: "rebase with a branch to check out".to_owned(),
                });
            }
            (onto, upstream)
        }
        None => {
            if opts.positionals.len() != 1 {
                return Err(GitError::Invalid {
                    detail: "usage: rebase <upstream>".to_owned(),
                });
            }
            let upstream = resolve_rev(store, kind, &opts.positionals[0])?;
            (upstream, upstream)
        }
    };
    let current = head_oid(store)?;
    let label = branch_label_of(ctx)?;
    if current == onto {
        return Ok(format!("Current branch {label} is up to date.\n").into_bytes());
    }
    let range = rev_range(store, current, upstream)?;
    if range.is_empty() {
        return Ok(format!("Current branch {label} is up to date.\n").into_bytes());
    }
    // A rebase moves the branch even before replaying, so it needs a
    // pristine index; staged changes would be silently re-homed otherwise.
    let rows = require_clean_index(store, kind)?;
    let index_tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let current_tree = commit_tree_oid(&commit_record(store, current)?)?;
    if index_tree != current_tree {
        return Err(GitError::Invalid {
            detail: "cannot rebase: Your index contains uncommitted changes.".to_owned(),
        });
    }
    if is_ancestor(store, current, onto)? {
        super::verbs_branch::move_branch_to(ctx, onto)?;
        take_tree_state(
            ctx,
            current_tree,
            commit_tree_oid(&commit_record(store, onto)?)?,
        )?;
        return Ok(format!("Successfully rebased and updated {label}.\n").into_bytes());
    }
    snapshot_abort_index(ctx, "rebase")?;
    pseudo_write(store, "ORIG_HEAD", current.to_hex().into_bytes())?;
    super::verbs_branch::move_branch_to(ctx, onto)?;
    take_tree_state(
        ctx,
        current_tree,
        commit_tree_oid(&commit_record(store, onto)?)?,
    )?;
    let mut todos = Vec::with_capacity(range.len());
    for oid in &range {
        let parents = commit_parents(store, *oid)?;
        if parents.len() > 1 {
            continue;
        }
        let record = commit_record(store, *oid)?;
        todos.push(PickTodo {
            oid: oid.to_hex(),
            base: parents
                .first()
                .map_or_else(String::new, |parent| parent.to_hex()),
            theirs: oid.to_hex(),
            message: String::from_utf8_lossy(record.message()).into_owned(),
            label: short_hex(oid),
        });
    }
    let orig_hex = current.to_hex();
    let mut out = apply_pick_todos(ctx, "rebase", None, &orig_hex, todos, false)?;
    let done = format!("Successfully rebased and updated {label}.\n").into_bytes();
    out.extend_from_slice(&done);
    Ok(out)
}

/// Lists `head..exclude` oldest-first: reachable from `head`, unreachable
/// from `exclude`, parents before children.
fn rev_range(store: &MergeLaneStore, head: Oid, exclude: Oid) -> Result<Vec<Oid>, GitError> {
    let from_head = walk_history(store, &[head], None)?;
    let excluded: HashSet<Oid> = walk_history(store, &[exclude], None)?
        .into_iter()
        .map(|(oid, _)| oid)
        .collect();
    let mut keep = HashSet::new();
    let mut parents: HashMap<Oid, Vec<Oid>> = HashMap::new();
    for (oid, record) in &from_head {
        if excluded.contains(oid) {
            continue;
        }
        keep.insert(*oid);
        let mut list = Vec::new();
        for parent in record.parents() {
            if let Some(parent_oid) = parent.as_git().copied() {
                list.push(parent_oid);
            }
        }
        parents.insert(*oid, list);
    }
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![(head, false)];
    while let Some((oid, expanded)) = stack.pop() {
        if expanded {
            order.push(oid);
            continue;
        }
        if !keep.contains(&oid) || !visited.insert(oid) {
            continue;
        }
        stack.push((oid, true));
        if let Some(list) = parents.get(&oid) {
            for parent in list {
                stack.push((*parent, false));
            }
        }
    }
    Ok(order)
}

/// Resumes a stopped rebase replay from the resolved index.
fn rebase_continue(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let mut out = pick_continue(ctx, "rebase", None)?;
    let label = branch_label_of(ctx)?;
    out.extend_from_slice(format!("Successfully rebased and updated {label}.\n").as_bytes());
    Ok(out)
}

/// Skips the stopped rebase pick and replays the rest of the range.
fn rebase_skip(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let mut out = pick_skip(ctx, "rebase", None)?;
    // Skipping the last pick finishes the rebase without further output
    // from the lane; the success line still applies when state cleared.
    let store = ctx.store()?;
    if sequencer_read(store, "rebase")?.is_none() {
        let label = branch_label_of(ctx)?;
        out.extend_from_slice(format!("Successfully rebased and updated {label}.\n").as_bytes());
    }
    Ok(out)
}

/// Builds pick todos for `cherry-pick`: each commit replays parent→commit.
fn cherry_pick_todos(
    ctx: &Ctx,
    oids: &[Oid],
    mainline: Option<usize>,
    with_reference: bool,
) -> Result<Vec<PickTodo>, GitError> {
    let store = ctx.store()?;
    let mut todos = Vec::with_capacity(oids.len());
    for oid in oids {
        let parents = commit_parents(store, *oid)?;
        let base = match parents.len() {
            0 => None,
            1 => Some(parents[0]),
            _ => match mainline {
                Some(n) if n >= 1 && n <= parents.len() => Some(parents[n - 1]),
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!(
                            "commit {} is a merge but no -m option was given",
                            short_hex(oid)
                        ),
                    });
                }
            },
        };
        let record = commit_record(store, *oid)?;
        let mut message = String::from_utf8_lossy(record.message()).into_owned();
        if with_reference {
            message = format!(
                "{}\n(cherry picked from commit {})",
                message.trim_end(),
                oid.to_hex()
            );
            message.push('\n');
        }
        todos.push(PickTodo {
            oid: oid.to_hex(),
            base: base.map_or_else(String::new, |parent| parent.to_hex()),
            theirs: oid.to_hex(),
            message,
            label: short_hex(oid),
        });
    }
    Ok(todos)
}

/// Builds pick todos for `revert`: each commit replays commit→parent, the
/// inverse of a cherry-pick.
fn revert_todos(
    ctx: &Ctx,
    oids: &[Oid],
    mainline: Option<usize>,
) -> Result<Vec<PickTodo>, GitError> {
    let store = ctx.store()?;
    let mut todos = Vec::with_capacity(oids.len());
    for oid in oids {
        let parents = commit_parents(store, *oid)?;
        let parent = match parents.len() {
            0 => {
                return Err(GitError::Invalid {
                    detail: format!("commit {} is a root commit", short_hex(oid)),
                });
            }
            1 => parents[0],
            _ => match mainline {
                Some(n) if n >= 1 && n <= parents.len() => parents[n - 1],
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!(
                            "commit {} is a merge but no -m option was given",
                            short_hex(oid)
                        ),
                    });
                }
            },
        };
        let record = commit_record(store, *oid)?;
        let subject = String::from_utf8_lossy(record.message())
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        todos.push(PickTodo {
            oid: oid.to_hex(),
            base: oid.to_hex(),
            theirs: parent.to_hex(),
            message: format!(
                "Revert \"{subject}\"\n\nThis reverts commit {}.\n",
                oid.to_hex()
            ),
            label: format!("revert of {}", short_hex(oid)),
        });
    }
    Ok(todos)
}

/// Applies pending picks in order, committing each clean one and stopping
/// with sequencer state at the first conflict.
fn apply_pick_todos(
    ctx: &mut Ctx,
    verb: &str,
    head_key: Option<&str>,
    orig_hex: &str,
    todos: Vec<PickTodo>,
    no_commit: bool,
) -> Result<Vec<u8>, GitError> {
    let mut remaining = todos;
    let mut out = Vec::new();
    while let Some(todo) = remaining.first().cloned() {
        let store = ctx.store()?;
        let kind = ctx.kind()?;
        let head = head_oid(store)?;
        let head_tree = commit_tree_oid(&commit_record(store, head)?)?;
        let empty = build_index_tree(store, kind, &[])?;
        let base_tree = if todo.base.is_empty() {
            empty
        } else {
            let base_oid = Oid::from_hex(&todo.base).map_err(|_| GitError::Corrupt {
                detail: format!("sequencer todo for {verb} does not decode"),
            })?;
            commit_tree_oid(&commit_record(store, base_oid)?)?
        };
        let theirs_oid = Oid::from_hex(&todo.theirs).map_err(|_| GitError::Corrupt {
            detail: format!("sequencer todo for {verb} does not decode"),
        })?;
        let theirs_tree = commit_tree_oid(&commit_record(store, theirs_oid)?)?;
        let rows = require_clean_index(store, kind)?;
        let plan = plan_merge_trees(ctx, base_tree, head_tree, theirs_tree, "HEAD", &todo.label)?;
        let head_map = lane_tree_map(store, kind, head_tree)?;
        guard_lane_worktree(ctx, &rows, &head_map, &plan, verb)?;
        let staged = apply_merge_plan(ctx, &plan)?;
        if plan.conflicted.is_empty() {
            if !no_commit {
                let new_oid = lane_commit(
                    ctx,
                    build_index_tree(store, kind, &staged)?,
                    vec![head],
                    todo.message.clone(),
                )?;
                out.extend_from_slice(&pick_summary(ctx, head_tree, new_oid)?);
            }
            remaining.remove(0);
        } else {
            write_lane_state(
                ctx,
                verb,
                head_key,
                orig_hex,
                &todo.oid,
                &todo.message,
                &remaining,
            )?;
            return Err(pick_conflict_error(verb, &todo, &plan));
        }
    }
    clear_lane_state(ctx, verb, head_key)?;
    Ok(out)
}

/// Renders `[branch short] subject` for one applied pick.
fn pick_summary(ctx: &Ctx, old_tree: Oid, new_oid: Oid) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let new_tree = commit_tree_oid(&commit_record(store, new_oid)?)?;
    let label = branch_label_of(ctx)?;
    let subject = message_subject(ctx, &new_oid)?;
    commit_summary(ctx, Some(old_tree), new_tree, &new_oid, &label, &subject)
}

/// Renders the oracle-style conflict report for a stopped pick.
fn pick_conflict_error(verb: &str, todo: &PickTodo, plan: &MergePlan) -> GitError {
    let subject = todo.message.lines().next().unwrap_or_default().to_owned();
    let short = &todo.oid[..todo.oid.len().min(7)];
    let mut detail = String::new();
    for path in &plan.auto_merged {
        detail.push_str(&format!("Auto-merging {path}\n"));
    }
    for path in &plan.conflicted {
        detail.push_str(&format!("CONFLICT (content): Merge conflict in {path}\n"));
    }
    detail.push_str(&format!("error: could not apply {short}... {subject}\n"));
    detail.push_str(&format!(
        "hint: after resolving the conflicts, run `{verb} --continue`\n"
    ));
    detail.push_str(&format!("hint: use `{verb} --skip` to skip this patch\n"));
    detail.push_str(&format!("hint: use `{verb} --abort` to cancel"));
    GitError::Invalid { detail }
}

/// Resumes a stopped pick sequence from the resolved index.
fn pick_continue(ctx: &mut Ctx, verb: &str, head_key: Option<&str>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let Some(seq) = sequencer_read(store, verb)? else {
        return no_sequencer(verb, "continue");
    };
    let todos = read_lane_todos(store, verb)?.ok_or_else(|| GitError::Corrupt {
        detail: format!("sequencer todo for {verb} does not decode"),
    })?;
    let Some(current) = todos.first().cloned() else {
        return Err(GitError::Corrupt {
            detail: format!("sequencer todo for {verb} is empty"),
        });
    };
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "unmerged paths must be resolved first".to_owned(),
        });
    }
    let head = head_oid(store)?;
    let head_tree = commit_tree_oid(&commit_record(store, head)?)?;
    let tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    let new_oid = lane_commit(ctx, tree, vec![head], current.message.clone())?;
    let mut out = pick_summary(ctx, head_tree, new_oid)?;
    let rest = todos[1..].to_vec();
    if rest.is_empty() {
        clear_lane_state(ctx, verb, head_key)?;
        return Ok(out);
    }
    out.extend_from_slice(&apply_pick_todos(
        ctx,
        verb,
        head_key,
        &seq.head_hex,
        rest,
        false,
    )?);
    Ok(out)
}

/// Skips the stopped pick, resets the whole index and worktree to `HEAD`
/// (the skipped pick's clean-resolved paths must not leak into the next
/// pick's commit, which is built from the index), and applies the rest.
fn pick_skip(ctx: &mut Ctx, verb: &str, head_key: Option<&str>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let Some(seq) = sequencer_read(store, verb)? else {
        return no_sequencer(verb, "skip");
    };
    let todos = read_lane_todos(store, verb)?.ok_or_else(|| GitError::Corrupt {
        detail: format!("sequencer todo for {verb} does not decode"),
    })?;
    let head = head_oid(store)?;
    let head_tree = commit_tree_oid(&commit_record(store, head)?)?;
    let head_map = lane_tree_map(store, kind, head_tree)?;
    // No dirty guard here: in-progress user resolutions are exactly what a
    // skip discards. Untracked files stay untouched by construction.
    apply_merge_plan(ctx, &plan_take_tree(&head_map, &head_map)?)?;
    if todos.len() <= 1 {
        clear_lane_state(ctx, verb, head_key)?;
        return Ok(Vec::new());
    }
    let rest = todos[1..].to_vec();
    apply_pick_todos(ctx, verb, head_key, &seq.head_hex, rest, false)
}

/// Abandons a pick sequence, restoring the pre-operation index and branch.
fn pick_abort(ctx: &mut Ctx, verb: &str, head_key: Option<&str>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let Some(seq) = sequencer_read(store, verb)? else {
        return no_sequencer(verb, "abort");
    };
    let orig = Oid::from_hex(&seq.head_hex).map_err(|_| GitError::Corrupt {
        detail: format!("{verb} sequencer head does not decode"),
    })?;
    if head_oid(store)? != orig {
        super::verbs_branch::move_branch_to(ctx, orig)?;
    }
    restore_abort_index(ctx, verb)?;
    clear_lane_state(ctx, verb, head_key)?;
    Ok(Vec::new())
}

/// Drops pick state while keeping the index and worktree as they are.
fn pick_quit(ctx: &mut Ctx, verb: &str, head_key: Option<&str>) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    if sequencer_read(store, verb)?.is_none() {
        return no_sequencer(verb, "quit");
    }
    clear_lane_state(ctx, verb, head_key)?;
    Ok(Vec::new())
}

/// Applies existing commits elsewhere, one three-way merge per commit.
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
            long: "skip",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-commit",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "mainline",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "edit",
            short: Some('e'),
            takes_value: false,
        },
        // Real git spells this `-x` with no long form; `--x` is accepted
        // here as the same flag for parser uniformity.
        FlagSpec {
            long: "x",
            short: Some('x'),
            takes_value: false,
        },
    ];
    let opts = collect_expanded(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") {
        return pick_abort(ctx, "cherry-pick", Some("CHERRY_PICK_HEAD"));
    }
    if opts.is_set("quit") {
        return pick_quit(ctx, "cherry-pick", Some("CHERRY_PICK_HEAD"));
    }
    if opts.is_set("continue") {
        return pick_continue(ctx, "cherry-pick", Some("CHERRY_PICK_HEAD"));
    }
    if opts.is_set("skip") {
        return pick_skip(ctx, "cherry-pick", Some("CHERRY_PICK_HEAD"));
    }
    check_mainline(&opts)?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: cherry-pick <commit>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut oids = Vec::with_capacity(opts.positionals.len());
    for rev in &opts.positionals {
        oids.push(resolve_rev(store, kind, rev)?);
    }
    let mainline = opts
        .single("mainline")?
        .map(|text| {
            text.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad --mainline {text:?}: want a parent number"),
            })
        })
        .transpose()?;
    let todos = cherry_pick_todos(ctx, &oids, mainline, opts.is_set("x"))?;
    let orig_hex = head_oid(store)?.to_hex();
    snapshot_abort_index(ctx, "cherry-pick")?;
    apply_pick_todos(
        ctx,
        "cherry-pick",
        Some("CHERRY_PICK_HEAD"),
        &orig_hex,
        todos,
        opts.is_set("no-commit"),
    )
}

/// Reverts existing commits, one inverse three-way merge per commit.
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
            long: "skip",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-commit",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "mainline",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "edit",
            short: Some('e'),
            takes_value: false,
        },
    ];
    let opts = collect_expanded(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("abort") {
        return pick_abort(ctx, "revert", Some("REVERT_HEAD"));
    }
    if opts.is_set("quit") {
        return pick_quit(ctx, "revert", Some("REVERT_HEAD"));
    }
    if opts.is_set("continue") {
        return pick_continue(ctx, "revert", Some("REVERT_HEAD"));
    }
    if opts.is_set("skip") {
        return pick_skip(ctx, "revert", Some("REVERT_HEAD"));
    }
    check_mainline(&opts)?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: revert <commit>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut oids = Vec::with_capacity(opts.positionals.len());
    for rev in &opts.positionals {
        oids.push(resolve_rev(store, kind, rev)?);
    }
    let mainline = opts
        .single("mainline")?
        .map(|text| {
            text.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad --mainline {text:?}: want a parent number"),
            })
        })
        .transpose()?;
    let todos = revert_todos(ctx, &oids, mainline)?;
    let orig_hex = head_oid(store)?.to_hex();
    snapshot_abort_index(ctx, "revert")?;
    apply_pick_todos(
        ctx,
        "revert",
        Some("REVERT_HEAD"),
        &orig_hex,
        todos,
        opts.is_set("no-commit"),
    )
}

// ===========================================================================
// Merge lane: three-way content merge over the syntax/conflict machinery.
// ===========================================================================
//
// One engine serves `merge`, `cherry-pick`, `revert`, and `rebase` replay:
// the caller supplies `{base, ours, theirs}` trees plus worktree labels and
// gets per-path resolutions. Each content path goes through
// `merge::composed::route::merge_file` (syntax/plain/composed engines over
// the pinned tree-sitter grammars) first; the bounded line-based diff3 below
// runs only when the syntax stage answers `Declined` (or no language claims
// the path). Conflicted paths land in the index at stages 1/2/3 with
// `MERGE_HEAD`-family state left behind, the way the oracle leaves the
// sequencer; clean merges produce a real commit with the right parents.
//
// The worktree sync here is deliberately scoped: only paths the operation
// touches are written or removed, and removals cover only paths the
// pre-operation index tracked. The generic `sync_worktree_to_index` walks
// the whole worktree and would delete untracked files, so the lane never
// calls it.

/// How one path resolves in a three-way merge.
enum PathResolution {
    /// Keep the stored blob at stage zero.
    Take { mode: FileMode, oid: Oid },
    /// New content: publish the bytes as a blob, then stage zero.
    NewBlob { mode: FileMode, bytes: Vec<u8> },
    /// No rows for this path.
    Deleted,
    /// Stage 1/2/3 rows plus worktree bytes (`None` leaves the worktree).
    Conflict {
        stages: Vec<(Stage, IndexEntry)>,
        worktree: Option<Vec<u8>>,
    },
}

/// Per-path plan for one `{base, ours, theirs}` merge.
struct MergePlan {
    /// One entry per touched path, in index order.
    resolutions: Vec<(Vec<u8>, PathResolution)>,
    /// Display paths both sides changed (clean or not), for `Auto-merging`.
    auto_merged: Vec<String>,
    /// Display paths left conflicted.
    conflicted: Vec<String>,
}

/// One pending pick for the sequencer verbs: everything `--continue` needs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PickTodo {
    /// Picked commit hex.
    oid: String,
    /// Base tree side hex (`""` for a root pick).
    base: String,
    /// Theirs tree side hex.
    theirs: String,
    /// Commit message to record when this pick lands.
    message: String,
    /// Theirs worktree label for conflict markers.
    label: String,
}

/// Builds a stage row entry for one blob oid.
fn lane_entry(mode: FileMode, oid: Oid) -> Result<IndexEntry, GitError> {
    IndexEntry::new(oid, mode, None, IndexFlags::default())
        .map_err(|err| GitError::from(CoreError::from(err)))
}

/// Reads one blob body through a small oid-keyed cache.
fn lane_blob(
    store: &MergeLaneStore,
    cache: &mut HashMap<Oid, Vec<u8>>,
    oid: Oid,
) -> Result<Vec<u8>, GitError> {
    if let Some(hit) = cache.get(&oid) {
        return Ok(hit.clone());
    }
    let (kind, body) = read_object_bytes(store, oid)?;
    if kind != MergeLaneObjectKind::Blob {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a blob", oid.to_hex()),
        });
    }
    cache.insert(oid, body.clone());
    Ok(body)
}

/// Flattens one tree to a path map for the lane.
fn lane_tree_map(
    store: &MergeLaneStore,
    kind: HashKind,
    tree: Oid,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, GitError> {
    let mut out = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        out.insert(path, (mode, oid));
    }
    Ok(out)
}

/// Splits bytes into lines keeping terminators; empty input has no lines.
/// (The existing `split_lines` strips terminators for display; the merge
/// lane needs them to reproduce file bytes exactly.)
fn lane_split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            out.push(&bytes[start..index + 1]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        out.push(&bytes[start..]);
    }
    out
}

/// One replaced block: `a[a_start..a_end]` becomes `b[b_start..b_end]`.
#[derive(Clone, Copy, Debug)]
struct Hunk {
    a_start: usize,
    a_end: usize,
    b_start: usize,
    b_end: usize,
}

/// Myers O(ND) hunks between two line slices, or `None` past the bounds.
///
/// The trace cap keeps memory under ~16 MiB; giving up means the caller
/// reports a whole-file conflict, never a wrong merge.
fn myers_hunks(a: &[&[u8]], b: &[&[u8]]) -> Option<Vec<Hunk>> {
    // Every index below fits `i32`: inputs past 40,000 lines decline up
    // front, so each `try_into` below is infallible in practice and `None`
    // stays the honest answer for anything unexpected.
    let total = a.len().checked_add(b.len())?;
    if total == 0 {
        return Some(Vec::new());
    }
    if total > 40_000 {
        return None;
    }
    let n = i32::try_from(a.len()).ok()?;
    let m = i32::try_from(b.len()).ok()?;
    let max = i32::try_from(total).ok()?;
    let width = usize::try_from(max).ok()?.checked_mul(2)?.checked_add(1)?;
    let off = i64::from(max);
    let cell = |v: &[i32], k: i64| -> Option<i32> {
        let idx = usize::try_from(off + k).ok()?;
        Some(*v.get(idx)?)
    };
    let mut v = vec![0i32; width];
    let mut trace: Vec<Vec<i32>> = Vec::new();
    let row_cap = (4_000_000 / width).max(64);
    let mut done: Option<i32> = None;
    for d in 0..=max {
        let dd = i64::from(d);
        for k in (-dd..=dd).step_by(2) {
            let down = k == -dd
                || (k != dd && cell(&v, k - 1).unwrap_or(0) < cell(&v, k + 1).unwrap_or(0));
            let mut x = if down {
                cell(&v, k + 1)?
            } else {
                cell(&v, k - 1)? + 1
            };
            let mut y = x - i32::try_from(k).ok()?;
            while x < n
                && y >= 0
                && y < m
                && a[usize::try_from(x).ok()?] == b[usize::try_from(y).ok()?]
            {
                x += 1;
                y += 1;
            }
            let idx = usize::try_from(off + k).ok()?;
            *v.get_mut(idx)? = x;
            if x >= n && y >= m {
                done = Some(d);
                break;
            }
        }
        trace.push(v.clone());
        if trace.len() > row_cap {
            return None;
        }
        if done.is_some() {
            break;
        }
    }
    let depth = done?;
    if depth == 0 {
        return Some(Vec::new());
    }
    enum Op {
        Ins { pos: usize, b0: usize, b1: usize },
        Del { a0: usize, a1: usize },
    }
    let depth_usize = usize::try_from(depth).ok()?;
    let mut ops = Vec::new();
    let (mut x, mut y) = (i64::from(n), i64::from(m));
    for dd in (1..=depth_usize).rev() {
        let prev = trace.get(dd - 1)?;
        let k = x - y;
        let di = i64::try_from(dd).ok()?;
        let go_down = k == -di
            || (k != di && cell(prev, k - 1).unwrap_or(0) < cell(prev, k + 1).unwrap_or(0));
        let k_prev = if go_down { k + 1 } else { k - 1 };
        let x_prev = i64::from(cell(prev, k_prev)?);
        let y_prev = x_prev - k_prev;
        while x > x_prev && y > y_prev {
            x -= 1;
            y -= 1;
        }
        if x == x_prev {
            ops.push(Op::Ins {
                pos: usize::try_from(x).ok()?,
                b0: usize::try_from(y_prev).ok()?,
                b1: usize::try_from(y).ok()?,
            });
        } else {
            ops.push(Op::Del {
                a0: usize::try_from(x_prev).ok()?,
                a1: usize::try_from(x).ok()?,
            });
        }
        x = x_prev;
        y = y_prev;
    }
    ops.reverse();
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut bpos = 0;
    for op in ops {
        let next = match op {
            Op::Ins { pos, b0, b1 } => {
                bpos = b1;
                Hunk {
                    a_start: pos,
                    a_end: pos,
                    b_start: b0,
                    b_end: b1,
                }
            }
            Op::Del { a0, a1 } => Hunk {
                a_start: a0,
                a_end: a1,
                b_start: bpos,
                b_end: bpos,
            },
        };
        if let Some(last) = hunks.last_mut() {
            if last.a_end == next.a_start && last.b_end == next.b_start {
                last.a_end = next.a_end;
                last.b_end = next.b_end;
                continue;
            }
        }
        hunks.push(next);
    }
    Some(hunks)
}

/// Splices one side's hunks over a base range into borrowed lines.
fn splice_lines<'a>(
    base: &'a [&[u8]],
    hunks: &[Hunk],
    start: usize,
    end: usize,
    side: &'a [&[u8]],
) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut pos = start;
    for hunk in hunks {
        if hunk.a_start < start || hunk.a_end > end {
            continue;
        }
        out.extend_from_slice(&base[pos..hunk.a_start]);
        out.extend_from_slice(&side[hunk.b_start..hunk.b_end]);
        pos = hunk.a_end;
    }
    out.extend_from_slice(&base[pos..end]);
    out
}

/// Appends lines, adding a missing trailing newline per line.
fn push_lines(out: &mut Vec<u8>, lines: &[&[u8]]) {
    for line in lines {
        out.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
}

/// Appends one `<<<<<<<`/`=======`/`>>>>>>>` block.
fn push_conflict(
    out: &mut Vec<u8>,
    ours_label: &str,
    ours: &[&[u8]],
    theirs_label: &str,
    theirs: &[&[u8]],
) {
    out.extend_from_slice(format!("<<<<<<< {ours_label}\n").as_bytes());
    push_lines(out, ours);
    out.extend_from_slice(b"=======\n");
    push_lines(out, theirs);
    out.extend_from_slice(format!(">>>>>>> {theirs_label}\n").as_bytes());
}

/// Bounded line-based three-way merge: the lane's fallback when the syntax
/// stage declines a path. Returns the merged bytes plus whether any hunk
/// conflicted, or `None` when the input is past the bounds (the caller then
/// reports a whole-file conflict).
fn diff3_merge(
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    ours_label: &str,
    theirs_label: &str,
) -> Option<(Vec<u8>, bool)> {
    const MAX_TEXT_TRIPLET: usize = 8 << 20;
    if base.len() + ours.len() + theirs.len() > MAX_TEXT_TRIPLET {
        return None;
    }
    let a = lane_split_lines(base);
    let o = lane_split_lines(ours);
    let t = lane_split_lines(theirs);
    let hunks_o = myers_hunks(&a, &o)?;
    let hunks_t = myers_hunks(&a, &t)?;
    let mut bounds: Vec<(usize, usize)> = hunks_o
        .iter()
        .map(|h| (h.a_start, h.a_end))
        .chain(hunks_t.iter().map(|h| (h.a_start, h.a_end)))
        .collect();
    bounds.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(bounds.len());
    for bound in bounds {
        if let Some(last) = merged.last_mut() {
            if bound.0 <= last.1 {
                last.1 = last.1.max(bound.1);
                continue;
            }
        }
        merged.push(bound);
    }
    let mut out = Vec::new();
    let mut conflicted = false;
    let mut pos = 0;
    for (start, end) in merged {
        for line in &a[pos..start] {
            out.extend_from_slice(line);
        }
        let in_o: Vec<&Hunk> = hunks_o
            .iter()
            .filter(|h| h.a_start >= start && h.a_end <= end)
            .collect();
        let in_t: Vec<&Hunk> = hunks_t
            .iter()
            .filter(|h| h.a_start >= start && h.a_end <= end)
            .collect();
        match (in_o.is_empty(), in_t.is_empty()) {
            (false, false) => {
                let ours_lines = splice_lines(&a, &hunks_o, start, end, &o);
                let theirs_lines = splice_lines(&a, &hunks_t, start, end, &t);
                if ours_lines == theirs_lines {
                    push_lines(&mut out, &ours_lines);
                } else {
                    conflicted = true;
                    push_conflict(
                        &mut out,
                        ours_label,
                        &ours_lines,
                        theirs_label,
                        &theirs_lines,
                    );
                }
            }
            (true, false) => {
                push_lines(&mut out, &splice_lines(&a, &hunks_t, start, end, &t));
            }
            (false, true) => {
                push_lines(&mut out, &splice_lines(&a, &hunks_o, start, end, &o));
            }
            (true, true) => {}
        }
        pos = end;
    }
    for line in &a[pos..] {
        out.extend_from_slice(line);
    }
    Some((out, conflicted))
}

/// One path's three side views: tree mode plus blob/commit oid each.
#[derive(Clone, Copy, Debug)]
struct PathSides {
    base: Option<(TreeMode, Oid)>,
    ours: Option<(TreeMode, Oid)>,
    theirs: Option<(TreeMode, Oid)>,
}

/// The per-operation merge scope: blob cache, syntax registry, labels.
struct LaneScope<'a> {
    blobs: HashMap<Oid, Vec<u8>>,
    registry: GrammarRegistry<'a>,
    cancel: Cancel,
    ours_label: String,
    theirs_label: String,
}

impl LaneScope<'_> {
    /// Stages for whichever sides are present, in stage order.
    fn stages(&self, sides: &PathSides) -> Result<Vec<(Stage, IndexEntry)>, GitError> {
        let mut out = Vec::new();
        for (side, stage) in [
            (sides.base, Stage::Base),
            (sides.ours, Stage::Ours),
            (sides.theirs, Stage::Theirs),
        ] {
            if let Some((mode, oid)) = side {
                out.push((stage, lane_entry(mode.as_index_mode()?, oid)?));
            }
        }
        Ok(out)
    }

    /// File modes for all three present sides.
    fn modes(&self, sides: &PathSides) -> Result<(FileMode, FileMode, FileMode), GitError> {
        let one = |side: Option<(TreeMode, Oid)>| -> Result<FileMode, GitError> {
            side.map(|(mode, _)| mode.as_index_mode())
                .transpose()
                .map(|mode| mode.unwrap_or(FileMode::Regular))
        };
        Ok((one(sides.base)?, one(sides.ours)?, one(sides.theirs)?))
    }
}

/// Resolves one path both sides changed, syntax lane first and the bounded
/// text merge only on `Declined`.
fn resolve_content(
    ctx: &Ctx,
    scope: &mut LaneScope<'_>,
    path: &[u8],
    sides: &PathSides,
) -> Result<PathResolution, GitError> {
    let store = ctx.store()?;
    // A side can be absent on genuinely conflicting shapes (add/add has no
    // base, modify/delete misses a side); those degrade to conflict stages
    // instead of failing the whole operation.
    let (Some(base), Some(ours), Some(theirs)) = (sides.base, sides.ours, sides.theirs) else {
        let survivor = sides.ours.or(sides.theirs);
        let worktree = survivor
            .map(|(_, oid)| lane_blob(store, &mut scope.blobs, oid))
            .transpose()?;
        return Ok(PathResolution::Conflict {
            stages: scope.stages(sides)?,
            worktree,
        });
    };
    let (base_mode, ours_mode, theirs_mode) = scope.modes(sides)?;
    let mode = if ours_mode != base_mode {
        ours_mode
    } else {
        theirs_mode
    };
    if base_mode == FileMode::Gitlink
        || ours_mode == FileMode::Gitlink
        || theirs_mode == FileMode::Gitlink
    {
        return Ok(PathResolution::Conflict {
            stages: scope.stages(sides)?,
            worktree: None,
        });
    }
    let base_bytes = lane_blob(store, &mut scope.blobs, base.1)?;
    let ours_bytes = lane_blob(store, &mut scope.blobs, ours.1)?;
    let theirs_bytes = lane_blob(store, &mut scope.blobs, theirs.1)?;
    if base_bytes.contains(&0) || ours_bytes.contains(&0) || theirs_bytes.contains(&0) {
        return Ok(PathResolution::Conflict {
            stages: scope.stages(sides)?,
            worktree: Some(ours_bytes),
        });
    }
    let first_line = base_bytes.split(|byte| *byte == b'\n').next();
    let language =
        dispatch(path, first_line, None).map_err(|err| GitError::from(CoreError::from(err)))?;
    if let Some(language) = language {
        let request = ComposedRequest {
            path: ruk_core::ByteString::from(path.to_vec()),
            language,
            base: &base_bytes,
            ours: &ours_bytes,
            theirs: &theirs_bytes,
            mode: MergeMode::Syntax,
        };
        match merge_file(request, &scope.registry, &scope.cancel) {
            Ok(MergeOutcome::Merged { bytes, .. }) => {
                return Ok(PathResolution::NewBlob { mode, bytes });
            }
            Ok(MergeOutcome::Declined { .. }) => {}
            Err(ruk_core::merge::syntax::grammar::SyntaxError::Cancelled(detail)) => {
                return Err(GitError::Cancelled { detail });
            }
            Err(_) => {}
        }
    }
    match diff3_merge(
        &base_bytes,
        &ours_bytes,
        &theirs_bytes,
        &scope.ours_label,
        &scope.theirs_label,
    ) {
        Some((bytes, false)) => Ok(PathResolution::NewBlob { mode, bytes }),
        Some((bytes, true)) => Ok(PathResolution::Conflict {
            stages: scope.stages(sides)?,
            worktree: Some(bytes),
        }),
        None => {
            let mut markers = Vec::new();
            push_conflict(
                &mut markers,
                &scope.ours_label,
                &lane_split_lines(&ours_bytes),
                &scope.theirs_label,
                &lane_split_lines(&theirs_bytes),
            );
            Ok(PathResolution::Conflict {
                stages: scope.stages(sides)?,
                worktree: Some(markers),
            })
        }
    }
}

/// One union path plus its merge context for resolution.
struct PathInput<'a> {
    path: &'a [u8],
    /// The path is a directory prefix of another union path: any file side
    /// here is a file/directory conflict.
    dir_clash: bool,
    sides: PathSides,
}

/// Converts one tree side to its index file mode.
fn side_file_mode(side: (TreeMode, Oid)) -> Result<(FileMode, Oid), GitError> {
    Ok((side.0.as_index_mode()?, side.1))
}

/// Resolves one union path from its three side views.
fn resolve_path(
    ctx: &Ctx,
    scope: &mut LaneScope<'_>,
    input: &PathInput,
    auto_merged: &mut Vec<String>,
) -> Result<PathResolution, GitError> {
    let store = ctx.store()?;
    let shown = String::from_utf8_lossy(input.path).into_owned();
    let sides = &input.sides;
    // A file in any side colliding with a directory prefix elsewhere in the
    // union is a file/directory conflict; every present side (including the
    // base) keeps its stage, and the worktree keeps whichever side is a file.
    if input.dir_clash {
        let survivor = sides.ours.or(sides.theirs);
        let worktree = survivor
            .map(|(_, oid)| lane_blob(store, &mut scope.blobs, oid))
            .transpose()?;
        return Ok(PathResolution::Conflict {
            stages: scope.stages(sides)?,
            worktree,
        });
    }
    match (sides.base, sides.ours, sides.theirs) {
        (None, None, None) => Ok(PathResolution::Deleted),
        (None, Some(side), None) | (None, None, Some(side)) => {
            let (mode, oid) = side_file_mode(side)?;
            Ok(PathResolution::Take { mode, oid })
        }
        (None, Some(one), Some(other)) => {
            auto_merged.push(shown);
            if one == other {
                let (mode, oid) = side_file_mode(one)?;
                return Ok(PathResolution::Take { mode, oid });
            }
            // Add/add with different bodies always conflicts: no base exists
            // to reconcile the two additions against.
            let ours_bytes = lane_blob(store, &mut scope.blobs, one.1)?;
            let theirs_bytes = lane_blob(store, &mut scope.blobs, other.1)?;
            let worktree = if ours_bytes.contains(&0) || theirs_bytes.contains(&0) {
                ours_bytes
            } else {
                let mut markers = Vec::new();
                push_conflict(
                    &mut markers,
                    &scope.ours_label,
                    &lane_split_lines(&ours_bytes),
                    &scope.theirs_label,
                    &lane_split_lines(&theirs_bytes),
                );
                markers
            };
            Ok(PathResolution::Conflict {
                stages: scope.stages(sides)?,
                worktree: Some(worktree),
            })
        }
        (Some(_), None, None) => Ok(PathResolution::Deleted),
        (Some(base_side), Some(ours_side), None) => {
            // Theirs deleted: clean when ours is untouched, a modify/delete
            // conflict otherwise.
            if base_side == ours_side {
                return Ok(PathResolution::Deleted);
            }
            auto_merged.push(shown);
            let (_, oid) = side_file_mode(ours_side)?;
            Ok(PathResolution::Conflict {
                stages: scope.stages(sides)?,
                worktree: Some(lane_blob(store, &mut scope.blobs, oid)?),
            })
        }
        (Some(base_side), None, Some(theirs_side)) => {
            // Ours deleted: clean when theirs is untouched, a
            // modify/delete conflict otherwise.
            if base_side == theirs_side {
                return Ok(PathResolution::Deleted);
            }
            auto_merged.push(shown);
            let (_, oid) = side_file_mode(theirs_side)?;
            Ok(PathResolution::Conflict {
                stages: scope.stages(sides)?,
                worktree: Some(lane_blob(store, &mut scope.blobs, oid)?),
            })
        }
        (Some(base_side), Some(ours_side), Some(theirs_side)) => {
            if ours_side == base_side {
                let (mode, oid) = side_file_mode(theirs_side)?;
                return Ok(PathResolution::Take { mode, oid });
            }
            if theirs_side == base_side {
                let (mode, oid) = side_file_mode(ours_side)?;
                return Ok(PathResolution::Take { mode, oid });
            }
            if ours_side == theirs_side {
                auto_merged.push(shown);
                let (mode, oid) = side_file_mode(ours_side)?;
                return Ok(PathResolution::Take { mode, oid });
            }
            auto_merged.push(shown);
            resolve_content(ctx, scope, input.path, sides)
        }
    }
}

/// Plans one `{base, ours, theirs}` tree merge over every union path.
fn plan_merge_trees(
    ctx: &Ctx,
    base_tree: Oid,
    ours_tree: Oid,
    theirs_tree: Oid,
    ours_label: &str,
    theirs_label: &str,
) -> Result<MergePlan, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let base_map = lane_tree_map(store, kind, base_tree)?;
    let ours_map = lane_tree_map(store, kind, ours_tree)?;
    let theirs_map = lane_tree_map(store, kind, theirs_tree)?;
    let providers = registry_providers()
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    let mut registry = GrammarRegistry::new();
    for provider in &providers {
        registry.insert(provider);
    }
    let mut scope = LaneScope {
        blobs: HashMap::new(),
        registry,
        cancel: Cancel::never(),
        ours_label: ours_label.to_owned(),
        theirs_label: theirs_label.to_owned(),
    };
    let mut keys = std::collections::BTreeSet::new();
    for map in [&base_map, &ours_map, &theirs_map] {
        keys.extend(map.keys().cloned());
    }
    let mut dir_prefixes = std::collections::HashSet::new();
    for key in &keys {
        for (index, byte) in key.iter().enumerate() {
            if *byte == b'/' {
                dir_prefixes.insert(key[..index].to_vec());
            }
        }
    }
    // Rename tracking: a rename on one side plus content edits on the other
    // merges the edit into the renamed path instead of conflicting as
    // delete plus add. Detection runs at the oracle's 50% threshold.
    let theirs_ren = detect_lane_renames(ctx, &mut scope.blobs, &base_map, &theirs_map)?;
    let ours_ren = detect_lane_renames(ctx, &mut scope.blobs, &base_map, &ours_map)?;
    // `old -> (new, theirs_renamed)` for consumed rename sources, and the
    // reverse for redirect targets.
    let mut redirect_old: HashMap<Vec<u8>, (Vec<u8>, bool)> = HashMap::new();
    let mut redirect_new: HashMap<Vec<u8>, (Vec<u8>, bool)> = HashMap::new();
    for (old, new, _) in &theirs_ren {
        if ours_ren.iter().any(|(other, _, _)| other == old) || dir_prefixes.contains(new) {
            continue;
        }
        match (base_map.get(old), ours_map.get(old), ours_map.get(new)) {
            (Some(base_side), Some(ours_side), None) if ours_side != base_side => {
                redirect_old.insert(old.clone(), (new.clone(), true));
                redirect_new.insert(new.clone(), (old.clone(), true));
            }
            _ => {}
        }
    }
    for (old, new, _) in &ours_ren {
        if theirs_ren.iter().any(|(other, _, _)| other == old)
            || redirect_old.contains_key(old)
            || dir_prefixes.contains(new)
        {
            continue;
        }
        match (base_map.get(old), theirs_map.get(old), theirs_map.get(new)) {
            (Some(base_side), Some(theirs_side), None) if theirs_side != base_side => {
                redirect_old.insert(old.clone(), (new.clone(), false));
                redirect_new.insert(new.clone(), (old.clone(), false));
            }
            _ => {}
        }
    }
    let mut plan = MergePlan {
        resolutions: Vec::new(),
        auto_merged: Vec::new(),
        conflicted: Vec::new(),
    };
    for path in keys {
        // A consumed rename source simply deletes: its content merged at
        // the redirect target below.
        if redirect_old.contains_key(&path) {
            plan.resolutions.push((path, PathResolution::Deleted));
            continue;
        }
        if let Some((old_path, theirs_side)) = redirect_new.get(&path) {
            let shown = String::from_utf8_lossy(&path).into_owned();
            let synthetic = PathSides {
                base: base_map.get(old_path).copied(),
                ours: if *theirs_side {
                    ours_map.get(old_path).copied()
                } else {
                    ours_map.get(&path).copied()
                },
                theirs: if *theirs_side {
                    theirs_map.get(&path).copied()
                } else {
                    theirs_map.get(old_path).copied()
                },
            };
            let resolution = match (synthetic.base, synthetic.ours, synthetic.theirs) {
                (Some(_), Some(_), Some(_)) => {
                    plan.auto_merged.push(shown);
                    resolve_content(ctx, &mut scope, &path, &synthetic)?
                }
                _ => {
                    let input = PathInput {
                        path: &path,
                        dir_clash: dir_prefixes.contains(&path),
                        sides: PathSides {
                            base: base_map.get(&path).copied(),
                            ours: ours_map.get(&path).copied(),
                            theirs: theirs_map.get(&path).copied(),
                        },
                    };
                    resolve_path(ctx, &mut scope, &input, &mut plan.auto_merged)?
                }
            };
            if matches!(resolution, PathResolution::Conflict { .. }) {
                plan.conflicted
                    .push(String::from_utf8_lossy(&path).into_owned());
            }
            plan.resolutions.push((path, resolution));
            continue;
        }
        let input = PathInput {
            path: &path,
            dir_clash: dir_prefixes.contains(&path),
            sides: PathSides {
                base: base_map.get(&path).copied(),
                ours: ours_map.get(&path).copied(),
                theirs: theirs_map.get(&path).copied(),
            },
        };
        let resolution = resolve_path(ctx, &mut scope, &input, &mut plan.auto_merged)?;
        if matches!(resolution, PathResolution::Conflict { .. }) {
            plan.conflicted
                .push(String::from_utf8_lossy(&path).into_owned());
        }
        plan.resolutions.push((path, resolution));
    }
    Ok(plan)
}

/// Detects base-to-side renames: deleted base paths paired with added side
/// paths by blob identity, then by 50% content similarity. Blob bodies come
/// through the lane cache; gitlink sides only pair when identical.
fn detect_lane_renames(
    ctx: &Ctx,
    cache: &mut HashMap<Oid, Vec<u8>>,
    base: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    side: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
) -> Result<Vec<(Vec<u8>, Vec<u8>, u8)>, GitError> {
    use super::rename::{RenameSide, pair_renames, similarity};
    let store = ctx.store()?;
    let mut dels: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    let mut adds: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    for (path, (mode, oid)) in base {
        if !side.contains_key(path) {
            dels.push((path.clone(), *mode, *oid));
        }
    }
    for (path, (mode, oid)) in side {
        if !base.contains_key(path) {
            adds.push((path.clone(), *mode, *oid));
        }
    }
    let mut taken = vec![false; adds.len()];
    let mut out: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    let mut rest: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    for (old_path, old_mode, old_oid) in dels {
        let mut hit = None;
        for (index, (new_path, _, new_oid)) in adds.iter().enumerate() {
            if !taken[index] && *new_oid == old_oid {
                hit = Some(index);
                out.push((old_path.clone(), new_path.clone(), 100));
                break;
            }
        }
        match hit {
            Some(index) => taken[index] = true,
            None => rest.push((old_path, old_mode, old_oid)),
        }
    }
    let live_adds: Vec<(Vec<u8>, TreeMode, Oid)> = adds
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !taken[*index])
        .map(|(_, triple)| triple)
        .collect();
    const MAX_SCORE_BYTES: usize = 1 << 20;
    let mut lane_body = |mode: TreeMode, oid: Oid| -> Result<Option<Vec<u8>>, GitError> {
        if mode == TreeMode::Gitlink {
            return Ok(None);
        }
        let body = lane_blob(store, cache, oid)?;
        if body.len() > MAX_SCORE_BYTES {
            return Ok(None);
        }
        Ok(Some(body))
    };
    let mut del_side = Vec::with_capacity(rest.len());
    let mut del_body = Vec::with_capacity(rest.len());
    for (path, mode, oid) in &rest {
        let body = lane_body(*mode, *oid)?;
        del_side.push(RenameSide {
            path: path.clone(),
            size: body.as_ref().map_or(0, Vec::len),
        });
        del_body.push(body);
    }
    let mut add_side = Vec::with_capacity(live_adds.len());
    let mut add_body = Vec::with_capacity(live_adds.len());
    for (path, mode, oid) in &live_adds {
        let body = lane_body(*mode, *oid)?;
        add_side.push(RenameSide {
            path: path.clone(),
            size: body.as_ref().map_or(0, Vec::len),
        });
        add_body.push(body);
    }
    let rest_oid: Vec<Oid> = rest.iter().map(|(_, _, oid)| *oid).collect();
    let live_oid: Vec<Oid> = live_adds.iter().map(|(_, _, oid)| *oid).collect();
    for win in pair_renames(&del_side, &add_side, 50, |oi, ni| {
        if rest_oid[oi] == live_oid[ni] {
            return 100;
        }
        match (&del_body[oi], &add_body[ni]) {
            (Some(old), Some(new)) => similarity(old, new),
            _ => 0,
        }
    }) {
        out.push((
            del_side[win.old].path.clone(),
            add_side[win.new].path.clone(),
            win.score,
        ));
    }
    out.sort();
    Ok(out)
}

/// One scoped worktree write: only merge-touched paths are ever addressed.
enum LaneWrite {
    /// Materialize a stored blob.
    Blob { mode: FileMode, oid: Oid },
    /// Write marker or survivor bytes as a regular file.
    Bytes(Vec<u8>),
    /// Remove a tracked path the merge dropped.
    Remove,
}

/// Applies one plan: publishes new blobs, swaps index rows per touched path,
/// and syncs exactly those worktree paths. Returns the merged stage-zero
/// rows for tree building.
fn apply_merge_plan(ctx: &Ctx, plan: &MergePlan) -> Result<Vec<(Vec<u8>, IndexEntry)>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut prepared = Vec::new();
    let mut staged: Vec<(Vec<u8>, IndexEntry)> = Vec::new();
    let mut mutations = Vec::new();
    let mut writes: Vec<(Vec<u8>, LaneWrite)> = Vec::new();
    for (path, resolution) in &plan.resolutions {
        let repo_path =
            RepoPath::new(path.clone()).map_err(|err| GitError::from(CoreError::from(err)))?;
        let before = read_path_rows(store, kind, &repo_path)?;
        let after: Vec<(Stage, IndexEntry)> = match resolution {
            PathResolution::Take { mode, oid } => {
                let entry = lane_entry(*mode, *oid)?;
                staged.push((path.clone(), entry.clone()));
                writes.push((
                    path.clone(),
                    LaneWrite::Blob {
                        mode: *mode,
                        oid: *oid,
                    },
                ));
                vec![(Stage::Zero, entry)]
            }
            PathResolution::NewBlob { mode, bytes } => {
                let entry = IndexEntry::for_blob(kind, *mode, bytes, None)
                    .map_err(|err| GitError::from(CoreError::from(err)))?;
                let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
                    detail: "merged blob exceeds the length range".to_owned(),
                })?;
                prepared.push(
                    store
                        .prepare(
                            MergeLaneObjectKind::Blob,
                            len,
                            std::io::Cursor::new(bytes.clone()),
                            None,
                        )
                        .map_err(GitError::from)?,
                );
                staged.push((path.clone(), entry.clone()));
                writes.push((
                    path.clone(),
                    LaneWrite::Blob {
                        mode: *mode,
                        oid: entry.oid(),
                    },
                ));
                vec![(Stage::Zero, entry)]
            }
            PathResolution::Deleted => {
                writes.push((path.clone(), LaneWrite::Remove));
                Vec::new()
            }
            PathResolution::Conflict { stages, worktree } => {
                if let Some(bytes) = worktree {
                    writes.push((path.clone(), LaneWrite::Bytes(bytes.clone())));
                }
                stages.clone()
            }
        };
        mutations.extend(super::state::path_row_mutations(
            &repo_path, &before, &after,
        )?);
    }
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(|err| GitError::from(CoreError::from(err)))?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(prepared, &mutations)
        .map_err(GitError::from)?;
    sync_lane_worktree(ctx, &writes)?;
    Ok(staged)
}

/// Writes exactly the addressed worktree paths: files, links, removals.
/// Nothing outside `writes` is listed, read, or touched.
fn sync_lane_worktree(ctx: &Ctx, writes: &[(Vec<u8>, LaneWrite)]) -> Result<(), GitError> {
    let store = ctx.store()?;
    for (path, write) in writes {
        let full = super::tree::join_base(&ctx.file_base, path)?;
        match write {
            LaneWrite::Remove => {
                if full.is_symlink() || full.is_file() {
                    std::fs::remove_file(&full).map_err(|err| GitError::Io {
                        detail: format!("removing {}: {err}", full.display()),
                    })?;
                }
                prune_empty_parents(&full, &ctx.file_base);
            }
            LaneWrite::Blob { mode, oid } => {
                if *mode == FileMode::Gitlink {
                    continue;
                }
                if *mode == FileMode::Symlink {
                    write_lane_link(store, *oid, &full)?;
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
            LaneWrite::Bytes(bytes) => {
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
                std::fs::write(&full, bytes).map_err(|err| GitError::Io {
                    detail: format!("writing {}: {err}", full.display()),
                })?;
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

/// Materializes one symlink worktree path from its target blob.
fn write_lane_link(
    store: &MergeLaneStore,
    oid: Oid,
    full: &std::path::Path,
) -> Result<(), GitError> {
    let (_, body) = read_object_bytes(store, oid)?;
    #[cfg(unix)]
    {
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
        })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (text_placeholder(&body), full);
        Err(GitError::Unsupported {
            command: "checkout of symlinks on this platform".to_owned(),
        })
    }
}

#[cfg(not(unix))]
fn text_placeholder(body: &[u8]) -> &[u8] {
    body
}

/// Refuses to start a merge-like operation over unmerged index rows.
fn require_clean_index(
    store: &MergeLaneStore,
    kind: HashKind,
) -> Result<Vec<(RepoPath, Stage, IndexEntry)>, GitError> {
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "unmerged paths must be resolved first".to_owned(),
        });
    }
    Ok(rows)
}

/// Refuses when the worktree disagrees with the index on a path the plan
/// rewrites, so a merge never silently discards local changes. Paths the
/// plan leaves alone are never inspected.
fn guard_lane_worktree(
    ctx: &Ctx,
    rows: &[(RepoPath, Stage, IndexEntry)],
    ours_map: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    plan: &MergePlan,
    verb: &str,
) -> Result<(), GitError> {
    let store = ctx.store()?;
    let mut stage_zero: HashMap<&[u8], &IndexEntry> = HashMap::new();
    for (path, stage, entry) in rows {
        if *stage == Stage::Zero {
            stage_zero.insert(path.as_bytes(), entry);
        }
    }
    let mut cache: HashMap<Oid, Vec<u8>> = HashMap::new();
    let mut blocked: Vec<String> = Vec::new();
    for (path, resolution) in &plan.resolutions {
        let touched = match resolution {
            PathResolution::Take { mode, oid } => {
                ours_map.get(path).is_none_or(|(head_mode, head_oid)| {
                    head_mode.as_index_mode().ok() != Some(*mode) || head_oid != oid
                })
            }
            PathResolution::NewBlob { mode, bytes } => match ours_map.get(path) {
                None => true,
                Some((head_mode, head_oid)) => {
                    head_mode.as_index_mode().ok() != Some(*mode)
                        || lane_blob(store, &mut cache, *head_oid)
                            .ok()
                            .is_none_or(|head_bytes| head_bytes != *bytes)
                }
            },
            PathResolution::Deleted => ours_map.contains_key(path),
            PathResolution::Conflict { .. } => true,
        };
        if !touched {
            continue;
        }
        // A staged change on a merge-touched path would be silently re-homed
        // by the apply step, so the index must match the ours head there.
        // Untracked files and staged extras on untouched paths never enter
        // the plan and are never inspected.
        let head_side: Option<(FileMode, Oid)> = ours_map
            .get(path)
            .and_then(|(mode, oid)| mode.as_index_mode().ok().map(|file| (file, *oid)));
        // Gitlinks carry commit ids the worktree cannot materialize, so both
        // checks below are meaningless for them; every other path must show
        // an index that matches the ours head.
        let gitlink = matches!(
            stage_zero.get(path.as_slice()),
            Some(entry) if entry.mode() == FileMode::Gitlink
        );
        if !gitlink {
            let staged_side: Option<(FileMode, Oid)> = match stage_zero.get(path.as_slice()) {
                Some(entry) => Some((entry.mode(), entry.oid())),
                None => None,
            };
            if staged_side != head_side {
                blocked.push(String::from_utf8_lossy(path).into_owned());
                continue;
            }
        }
        let dirty = match stage_zero.get(path.as_slice()) {
            Some(entry) if entry.mode() == FileMode::Gitlink => false,
            Some(entry) => {
                let full = super::tree::join_base(&ctx.file_base, path)?;
                if entry.mode() == FileMode::Symlink {
                    let target = std::fs::read_link(&full)
                        .ok()
                        .map(|link| link.as_os_str().as_encoded_bytes().to_vec());
                    let wanted = lane_blob(store, &mut cache, entry.oid()).ok();
                    target != wanted
                } else {
                    let body = std::fs::read(&full).ok();
                    let wanted = lane_blob(store, &mut cache, entry.oid()).ok();
                    body != wanted
                }
            }
            None => {
                let full = super::tree::join_base(&ctx.file_base, path).ok();
                full.is_some_and(|path| path.is_symlink() || path.is_file())
            }
        };
        if dirty {
            blocked.push(String::from_utf8_lossy(path).into_owned());
        }
    }
    if blocked.is_empty() {
        return Ok(());
    }
    blocked.sort();
    let mut detail = format!(
        "error: Your local changes to the following files would be overwritten by {verb}:\n"
    );
    for path in &blocked {
        detail.push_str(&format!("\t{path}\n"));
    }
    detail.push_str("Please commit your changes or stash them before you merge.");
    Err(GitError::Invalid { detail })
}

/// Records one commit on the current branch (or detached `HEAD`) and moves
/// it forward, returning the new tip.
fn lane_commit(ctx: &Ctx, tree: Oid, parents: Vec<Oid>, message: String) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let author = identity(ctx, IdentityRole::Author)?;
    let committer = identity(ctx, IdentityRole::Committer)?;
    let request = NewRequest {
        tree,
        parents: parents.into_iter().map(|oid| Head::Git { oid }).collect(),
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
    Ok(new_oid)
}

/// Snapshots the merged index rows for a future `--abort` restore.
fn snapshot_abort_index(ctx: &Ctx, verb: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut serial: Vec<(Vec<u8>, u8, Vec<u8>)> = Vec::with_capacity(rows.len());
    for (path, stage, entry) in &rows {
        let bytes = sonic_rs::to_vec(entry).map_err(|err| GitError::Io {
            detail: format!("abort snapshot encode: {err}"),
        })?;
        serial.push((path.as_bytes().to_vec(), stage.as_u8(), bytes));
    }
    let value = sonic_rs::to_vec(&serial).map_err(|err| GitError::Io {
        detail: format!("abort snapshot encode: {err}"),
    })?;
    pseudo_write(store, &format!("abort-index/{verb}"), value)
}

/// Restores the `--abort` snapshot: index rows return exactly, worktree
/// files for snapshot paths are rewritten, and anything staged meanwhile
/// leaves the index (its worktree files stay, never deleted here).
fn restore_abort_index(ctx: &Ctx, verb: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let key = format!("abort-index/{verb}");
    let Some(raw) = pseudo_read(store, &key)? else {
        return Ok(());
    };
    let serial: Vec<(Vec<u8>, u8, Vec<u8>)> =
        sonic_rs::from_slice(&raw).map_err(|_| GitError::Corrupt {
            detail: format!("abort snapshot for {verb} does not decode"),
        })?;
    let mut wanted: BTreeMap<Vec<u8>, Vec<(Stage, IndexEntry)>> = BTreeMap::new();
    for (path, stage_num, bytes) in &serial {
        let stage =
            Stage::from_u8(*stage_num).map_err(|err| GitError::from(CoreError::from(err)))?;
        let entry: IndexEntry = sonic_rs::from_slice(bytes).map_err(|_| GitError::Corrupt {
            detail: format!("abort snapshot for {verb} does not decode"),
        })?;
        entry
            .validate(kind)
            .map_err(|err| GitError::from(CoreError::from(err)))?;
        wanted.entry(path.clone()).or_default().push((stage, entry));
    }
    let mut present: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for (path, _, _) in scan_index(store, kind)? {
        present.insert(path.as_bytes().to_vec());
    }
    let mut mutations = Vec::new();
    let mut writes: Vec<(Vec<u8>, LaneWrite)> = Vec::new();
    let mut keys: std::collections::BTreeSet<Vec<u8>> = wanted.keys().cloned().collect();
    keys.extend(present.iter().cloned());
    for path in keys {
        let repo_path =
            RepoPath::new(path.clone()).map_err(|err| GitError::from(CoreError::from(err)))?;
        let before = read_path_rows(store, kind, &repo_path)?;
        let after = wanted.get(&path).cloned().unwrap_or_default();
        mutations.extend(super::state::path_row_mutations(
            &repo_path, &before, &after,
        )?);
        if let Some(rows) = wanted.get(&path) {
            if let Some((_, entry)) = rows.iter().find(|(stage, _)| *stage == Stage::Zero) {
                writes.push((
                    path.clone(),
                    LaneWrite::Blob {
                        mode: entry.mode(),
                        oid: entry.oid(),
                    },
                ));
            } else {
                writes.push((path.clone(), LaneWrite::Remove));
            }
        }
    }
    let (workspace, raw_ws) = load_or_default(store)?;
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(|err| GitError::from(CoreError::from(err)))?;
    mutations.push(workspace_mutation(raw_ws.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    // Restoring the pre-operation worktree must not delete files the user
    // created meanwhile: filter removals to snapshot paths only when the
    // worktree file is tracked there... snapshot removals only address paths
    // the snapshot knew, which is exactly right.
    sync_lane_worktree(ctx, &writes)?;
    pseudo_delete(store, &key)?;
    Ok(())
}

/// Writes sequencer + todo + head state for a stopped pick/merge/rebase.
fn write_lane_state(
    ctx: &Ctx,
    verb: &str,
    head_key: Option<&str>,
    orig_hex: &str,
    current_hex: &str,
    message: &str,
    todos: &[PickTodo],
) -> Result<(), GitError> {
    let store = ctx.store()?;
    sequencer_write(
        store,
        verb,
        &SequencerState {
            verb: verb.to_owned(),
            head_hex: orig_hex.to_owned(),
            target_hex: current_hex.to_owned(),
            message: message.to_owned(),
        },
    )?;
    if let Some(key) = head_key {
        pseudo_write(store, key, current_hex.as_bytes().to_vec())?;
    }
    let value = sonic_rs::to_vec(todos).map_err(|err| GitError::Io {
        detail: format!("sequencer todo encode: {err}"),
    })?;
    pseudo_write(store, &format!("todo/{verb}"), value)?;
    Ok(())
}

/// Reads the pending todo list for a sequencer verb.
fn read_lane_todos(store: &MergeLaneStore, verb: &str) -> Result<Option<Vec<PickTodo>>, GitError> {
    let Some(raw) = pseudo_read(store, &format!("todo/{verb}"))? else {
        return Ok(None);
    };
    sonic_rs::from_slice(&raw)
        .map_err(|_| GitError::Corrupt {
            detail: format!("sequencer todo for {verb} does not decode"),
        })
        .map(Some)
}

/// Deletes every lane record for a finished or aborted verb.
fn clear_lane_state(ctx: &Ctx, verb: &str, head_key: Option<&str>) -> Result<(), GitError> {
    let store = ctx.store()?;
    sequencer_delete(store, verb)?;
    if let Some(key) = head_key {
        pseudo_delete(store, key)?;
    }
    pseudo_delete(store, &format!("todo/{verb}"))?;
    pseudo_delete(store, &format!("abort-index/{verb}"))?;
    Ok(())
}

/// Shows commit logs from tips, newest committer-date first.
///
/// Oracle: `git/builtin/log.c` (`cmd_log`). Decorations stay off unless
/// `--decorate` is given: git's `auto` default shows them only on a
/// terminal, and this interpreter never renders to one.
///
/// Accepted history flags beyond the identity line: `--follow`, `-S`, `-G`,
/// `--merges`/`--no-merges` (later `--no-merges` wins when both are given),
/// `--first-parent`, `--left-right`/`--cherry-pick` (sides come from the
/// first `A...B` range; without one every commit reads as right-side `>`),
/// `--topo-order`, `--date-order` (the walk already pops newest
/// committer-date first, so this is accepted as the default order),
/// `--date=<fmt>`/`--relative-date`, `--abbrev[=<n>]`, `--summary`,
/// `--shortstat`, `--numstat`, `--dirstat`, `--show-notes[=<ref>]`/
/// `--no-notes`, `--decorate=<short|full|auto|no>`, `--source`,
/// `--simplify-by-decoration`, `--branches[=<glob>]`/`--tags[=<glob>]`/
/// `--remotes[=<glob>]`/`--exclude=<glob>`, and `--boundary`. A positional
/// that names no revision falls back to a path when it exists in the
/// worktree or the `HEAD` tree, the way the oracle DWIMs `log <path>`;
/// otherwise it still fails as an unknown revision. `-n` stays
/// `--max-count`, as in git: notes are `--show-notes` only.
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
        FlagSpec {
            long: "stat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "name-status",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "pretty",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "graph",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "reverse",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "since",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "until",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "author",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "abbrev-commit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "decorate",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-decorate",
            short: None,
            takes_value: false,
        },
        // `-q` suppresses the per-commit diffs, as in git; the commit list
        // itself still prints.
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "unified",
            short: Some('U'),
            takes_value: true,
        },
        FlagSpec {
            long: "follow",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "merges",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-merges",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "first-parent",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "left-right",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "cherry-pick",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "topo-order",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "date-order",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "date",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "relative-date",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "summary",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "shortstat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "numstat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dirstat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "show-notes",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-notes",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "source",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "simplify-by-decoration",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "boundary",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "exclude",
            short: None,
            takes_value: true,
        },
        // Pickaxe `-S<string>`: commits changing the occurrence count.
        FlagSpec {
            long: "pickaxe",
            short: Some('S'),
            takes_value: true,
        },
        // Pickaxe `-G<regex>`: commits with a matching added/removed line.
        FlagSpec {
            long: "pickaxe-regex",
            short: Some('G'),
            takes_value: true,
        },
    ];
    let (rev_args, path_args) = split_double_dash(args);
    let rev_args = rewrite_format_colon(&rev_args);
    let (rev_args, decorate_mode) = extract_decorate_arg(&rev_args)?;
    let (rev_args, abbrev_len) = extract_abbrev_arg(&rev_args)?;
    let (rev_args, ref_filters) = extract_ref_filter_args(&rev_args)?;
    let (rev_args, notes_ref) = extract_show_notes_arg(&rev_args)?;
    let (rev_args, rename_mode) = super::rename::split_rename_args(&rev_args)?;
    let opts = collect_expanded(&rewrite_dash_number(&rev_args), &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit = parse_max_count(&opts)?;
    let default_tip = head_oid(store).ok();
    // DWIM positionals that name no revision into paths when they exist in
    // the worktree or the `HEAD` tree; anything else stays a revision so
    // typos still fail loudly in `parse_log_revs`.
    let mut rev_positionals: Vec<String> = Vec::new();
    let mut dwim_paths: Vec<Vec<u8>> = Vec::new();
    for item in &opts.positionals {
        if split_range(item).is_some() || item.starts_with('^') || item.ends_with("^!") {
            rev_positionals.push(item.clone());
            continue;
        }
        match try_resolve_rev(store, kind, item)? {
            Some(_) => rev_positionals.push(item.clone()),
            None => {
                if dwim_path_exists(ctx, store, kind, item)? {
                    dwim_paths.push(item.as_bytes().to_vec());
                } else {
                    rev_positionals.push(item.clone());
                }
            }
        }
    }
    let (mut tips, exclude) = parse_log_revs(store, kind, &rev_positionals, default_tip)?;
    let excludes = opts.all("exclude")?;
    // Tip labels feed `--source` text and `--left-right` sides; the first
    // symmetric range fixes left vs right.
    let mut tip_names: HashMap<Oid, String> = HashMap::new();
    for (oid, name) in log_ref_tips(store, opts.is_set("all"), &ref_filters, &excludes)? {
        if !tips.contains(&oid) {
            tips.push(oid);
        }
        tip_names.entry(oid).or_insert(name);
    }
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: log [<options>] [<revision-range>] [[--] <path>...]".to_owned(),
        });
    }
    let mut sym_sides: Option<(Oid, Oid)> = None;
    for item in &rev_positionals {
        if let Some(range) = split_range(item) {
            let from = resolve_range_side(store, kind, &range.from)?;
            let to = resolve_range_side(store, kind, &range.to)?;
            tip_names.entry(from).or_insert_with(|| {
                if range.from.is_empty() {
                    "HEAD".to_owned()
                } else {
                    range.from.clone()
                }
            });
            tip_names.entry(to).or_insert_with(|| {
                if range.to.is_empty() {
                    "HEAD".to_owned()
                } else {
                    range.to.clone()
                }
            });
            if range.symmetric && sym_sides.is_none() {
                sym_sides = Some((from, to));
            }
        } else if item.starts_with('^') {
            // Excluded side: no label.
        } else if let Some(base) = item.strip_suffix("^!") {
            let oid = resolve_local(store, kind, base)?;
            tip_names.entry(oid).or_insert(base.to_owned());
        } else {
            let oid = resolve_local(store, kind, item)?;
            tip_names.entry(oid).or_insert(item.clone());
        }
    }
    if rev_positionals.is_empty()
        && let Some(tip) = default_tip
    {
        tip_names.entry(tip).or_insert("HEAD".to_owned());
    }
    let since = parse_since_until(&opts, "since")?;
    let until = parse_since_until(&opts, "until")?;
    let author_want = opts.single("author")?;
    let mut wants: Vec<Vec<u8>> = path_args
        .iter()
        .map(|path| path.as_bytes().to_vec())
        .collect();
    wants.extend(dwim_paths);
    let follow = opts.is_set("follow");
    if follow {
        wants.sort();
        wants.dedup();
        if wants.len() != 1 {
            return Err(GitError::Invalid {
                detail: "option --follow requires exactly one path".to_owned(),
            });
        }
    }
    let needle = opts.single("pickaxe")?;
    if needle.as_deref() == Some("") {
        return Err(GitError::Invalid {
            detail: "option -S requires a non-empty string".to_owned(),
        });
    }
    let pickaxe_regex = opts
        .single("pickaxe-regex")?
        .map(|pattern| {
            Regex::new(&pattern).map_err(|_| GitError::Invalid {
                detail: format!("bad -G regex {pattern:?}"),
            })
        })
        .transpose()?;
    let merges_only = opts.is_set("merges");
    let no_merges = opts.is_set("no-merges");
    let first_parent = opts.is_set("first-parent");
    let left_right = opts.is_set("left-right");
    let cherry_pick = opts.is_set("cherry-pick");
    let topo_order = opts.is_set("topo-order");
    let mut line = commit_line_of(&opts)?;
    if let Some(len) = abbrev_len {
        line.abbrev_len = len;
        line.abbrev = true;
    }
    let decorate = !opts.is_set("no-decorate")
        && (opts.is_set("decorate") || decorate_mode.as_deref().is_some_and(|mode| mode != "no"));
    let full_names = decorate_mode.as_deref() == Some("full");
    let simplify = opts.is_set("simplify-by-decoration");
    let decorations = if decorate || line.format.is_some() || simplify {
        decoration_map(store)?
    } else {
        HashMap::new()
    };
    let extra_stats = opts.is_set("summary")
        || opts.is_set("shortstat")
        || opts.is_set("numstat")
        || opts.is_set("dirstat");
    let show_diffs = !opts.is_set("quiet")
        && (opts.is_set("patch")
            || opts.is_set("stat")
            || opts.is_set("name-only")
            || opts.is_set("name-status")
            || extra_stats);
    let show_notes = opts.is_set("show-notes") && !opts.is_set("no-notes");
    let notes_default = notes_ref.flatten();
    let follow_mode = match rename_mode {
        super::rename::RenameMode::Similar(_) => rename_mode,
        super::rename::RenameMode::Disabled | super::rename::RenameMode::ExactOnly => {
            super::rename::RenameMode::Similar(50)
        }
    };
    let mut shown: Vec<ShownCommit> = Vec::new();
    let mut follow_path: Option<Vec<u8>> = if follow { wants.first().cloned() } else { None };
    for entry in walk_log(store, &tips, &exclude, first_parent)? {
        let path_wants: &[Vec<u8>] = if follow { &[] } else { &wants };
        if !commit_passes_filters(
            store,
            kind,
            &entry.record,
            since,
            until,
            author_want.as_deref(),
            path_wants,
        )? {
            continue;
        }
        if merges_only || no_merges {
            let parents: Vec<Oid> = entry
                .record
                .parents()
                .iter()
                .filter_map(|head| head.as_git().copied())
                .collect();
            if merges_only && parents.len() < 2 {
                continue;
            }
            if no_merges && parents.len() > 1 {
                continue;
            }
        }
        if (needle.is_some() || pickaxe_regex.is_some())
            && !commit_passes_pickaxe(
                ctx,
                store,
                &entry.record,
                &wants,
                needle.as_deref().map(str::as_bytes),
                pickaxe_regex.as_ref(),
            )?
        {
            continue;
        }
        if follow {
            let Some(current) = follow_path.clone() else {
                continue;
            };
            match follow_step(ctx, store, &entry.record, &current, follow_mode)? {
                None => continue,
                Some(next) => follow_path = Some(next),
            }
        }
        let origin = entry.origin;
        shown.push(ShownCommit {
            oid: entry.oid,
            record: entry.record,
            origin,
        });
    }
    if simplify {
        shown.retain(|shown| decorations.contains_key(&shown.oid));
    }
    if cherry_pick
        && let Some((left, right)) = sym_sides
    {
        shown = cherry_pick_filter(ctx, store, &shown, left, right)?;
    }
    if topo_order {
        shown = topo_reorder(shown, &tips);
    }
    if let Some(max) = limit {
        shown.truncate(max);
    }
    if opts.is_set("reverse") {
        shown.reverse();
    }
    // Boundary commits render after the list in committer-date order (they
    // flip along with `--reverse`), each prefixed with `-`.
    let mut boundary: Vec<(i64, Oid, CommitRecord)> = Vec::new();
    if opts.is_set("boundary") {
        let mut seen_boundary = HashSet::new();
        for oid in &exclude {
            let oid = replace_redirect(store, *oid);
            if !seen_boundary.insert(oid) {
                continue;
            }
            let Ok(record) = commit_record(store, oid) else {
                continue;
            };
            boundary.push((super::state::commit_stamp(&record), oid, record));
        }
        boundary.sort_by(|left, right| right.0.cmp(&left.0));
    }
    let graph = opts.is_set("graph");
    let source = opts.is_set("source");
    let mut out = Vec::new();
    for shown in &shown {
        let decoration = decoration_text(&decorations, &shown.oid, full_names);
        let source_text =
            source.then(|| tip_names.get(&shown.origin).cloned().unwrap_or_default());
        let mut block = render_commit_line_full(
            &line,
            &shown.oid,
            &shown.record,
            &decoration,
            source_text.as_deref().unwrap_or(""),
        )?;
        if show_notes
            && let Some(note) = super::verbs_notes::note_for_commit(
                store,
                kind,
                notes_default.as_deref(),
                &shown.oid,
            )?
        {
            block.extend_from_slice(&render_note(&note));
        }
        if show_diffs {
            block.extend_from_slice(&log_commit_diff(
                ctx,
                store,
                &shown.oid,
                &shown.record,
                &opts,
                rename_mode,
            )?);
            if extra_stats {
                block.extend_from_slice(&log_commit_extra(
                    ctx,
                    store,
                    &shown.oid,
                    &shown.record,
                    &opts,
                )?);
            }
        }
        if left_right {
            let marker = match sym_sides {
                Some((left, _)) if shown.origin == left => b'<',
                _ => b'>',
            };
            block.insert(0, marker);
        }
        if graph {
            block = graph_block(&block);
        }
        out.extend_from_slice(&block);
    }
    for (_, oid, record) in &boundary {
        let decoration = decoration_text(&decorations, oid, full_names);
        let mut block = render_commit_line_full(&line, oid, record, &decoration, "")?;
        block.insert(0, b'-');
        if graph {
            block = graph_block(&block);
        }
        out.extend_from_slice(&block);
    }
    // Boundary rows stay trailing after `--reverse`: they were the excluded
    // tail before the flip, not part of the reversed walk.
    Ok(out)
}

/// One walked commit plus the tip it was first reached from, backing
/// `--source` text and `--left-right` sides.
struct ShownCommit {
    /// Commit oid.
    oid: Oid,
    /// Parsed commit record.
    record: CommitRecord,
    /// Tip whose walk first reached this commit.
    origin: Oid,
}

/// One walk step for [`walk_log`]: the commit plus its reaching tip.
struct LogWalkEntry {
    /// Commit oid.
    oid: Oid,
    /// Parsed commit record.
    record: CommitRecord,
    /// Tip whose walk first reached this commit.
    origin: Oid,
}

/// Rewrites `--format:<value>` to `--format=<value>` before collecting.
/// The wave contract spells the flag `--format:%H ...`, so the colon form
/// is accepted as an alias of the oracle's `--format=` spelling.
fn rewrite_format_colon(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| match arg.strip_prefix("--format:") {
            Some(value) => format!("--format={value}"),
            None => arg.clone(),
        })
        .collect()
}

/// Extracts `--abbrev`/`--abbrev=<n>` before collecting: the flag takes an
/// Extracts `--abbrev`/`--abbrev=<n>` before collecting: the flag takes an
/// optional value, which [`collect`] cannot spell. Both spellings imply
/// `--abbrev-commit`; the returned length defaults to 7 for the bare form.
fn extract_abbrev_arg(args: &[String]) -> Result<(Vec<String>, Option<usize>), GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut len = None;
    for arg in args {
        if arg == "--abbrev" {
            kept.push("--abbrev-commit".to_owned());
            len = Some(7);
        } else if let Some(value) = arg.strip_prefix("--abbrev=") {
            let parsed: usize = value.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad --abbrev={value:?}: want a prefix length"),
            })?;
            if parsed == 0 {
                return Err(GitError::Invalid {
                    detail: format!("bad --abbrev={value:?}: want a prefix length"),
                });
            }
            kept.push("--abbrev-commit".to_owned());
            len = Some(parsed);
        } else {
            kept.push(arg.clone());
        }
    }
    Ok((kept, len))
}

/// Which ref namespace a `--branches`/`--tags`/`--remotes` filter covers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefScope {
    /// `refs/heads/`.
    Branches,
    /// `refs/tags/`.
    Tags,
    /// `refs/remotes/`.
    Remotes,
}

/// One `--branches[=<glob>]`/`--tags[=<glob>]`/`--remotes[=<glob>]` filter.
/// A bare flag means `*`, the way the oracle lists the whole namespace.
struct RefFilter {
    /// Namespace to scan.
    scope: RefScope,
    /// Shell glob over the short (prefix-stripped) ref name.
    pattern: String,
}

/// Extracts ref-listing filters before collecting: each takes an optional
/// glob, which [`collect`] cannot spell. Unknown `--branch...` lookalikes
/// stay for `collect` to reject.
fn extract_ref_filter_args(args: &[String]) -> Result<(Vec<String>, Vec<RefFilter>), GitError> {
    fn split(name: &str, arg: &str) -> Option<Option<String>> {
        let rest = arg.strip_prefix(name)?;
        if rest.is_empty() {
            Some(None)
        } else {
            rest.strip_prefix('=').map(str::to_owned).map(Some)
        }
    }
    let mut kept = Vec::with_capacity(args.len());
    let mut filters = Vec::new();
    for arg in args {
        if let Some(pattern) = split("--branches", arg) {
            filters.push(RefFilter {
                scope: RefScope::Branches,
                pattern: pattern.unwrap_or_else(|| "*".to_owned()),
            });
        } else if let Some(pattern) = split("--tags", arg) {
            filters.push(RefFilter {
                scope: RefScope::Tags,
                pattern: pattern.unwrap_or_else(|| "*".to_owned()),
            });
        } else if let Some(pattern) = split("--remotes", arg) {
            filters.push(RefFilter {
                scope: RefScope::Remotes,
                pattern: pattern.unwrap_or_else(|| "*".to_owned()),
            });
        } else {
            kept.push(arg.clone());
        }
    }
    for filter in &filters {
        if filter.pattern.is_empty() {
            return Err(GitError::Invalid {
                detail: "empty ref pattern: want a shell glob".to_owned(),
            });
        }
    }
    Ok((kept, filters))
}

/// Extracts `--show-notes[=<ref>]` before collecting: the flag takes an
/// optional notes ref, which [`collect`] cannot spell. `None` means the
/// flag is absent, `Some(None)` the bare form (default notes ref).
fn extract_show_notes_arg(
    args: &[String],
) -> Result<(Vec<String>, Option<Option<String>>), GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut notes: Option<Option<String>> = None;
    for arg in args {
        if arg == "--show-notes" {
            kept.push(arg.clone());
            notes = Some(None);
        } else if let Some(value) = arg.strip_prefix("--show-notes=") {
            kept.push("--show-notes".to_owned());
            notes = Some(if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            });
        } else {
            kept.push(arg.clone());
        }
    }
    Ok((kept, notes))
}

/// Matches a shell glob over ref names: `*` spans any run, `?` one byte,
/// everything else literal.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(saved) = star {
            pi = saved + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Collects commit tips from `--all` plus every ref-listing filter,
/// skipping `--exclude` globs (matched against the full and short ref
/// names) and non-commit targets, the way the oracle expands revisions.
/// Each tip carries its short ref name for `--source`.
fn log_ref_tips(
    store: &Store,
    all: bool,
    filters: &[RefFilter],
    excludes: &[String],
) -> Result<Vec<(Oid, String)>, GitError> {
    if !all && filters.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (name, target) in list_refs(store)? {
        let full = name.to_utf8().unwrap_or_default().to_owned();
        let (scope, short) = if let Some(short) = full.strip_prefix("refs/heads/") {
            (RefScope::Branches, short)
        } else if let Some(short) = full.strip_prefix("refs/tags/") {
            (RefScope::Tags, short)
        } else if let Some(short) = full.strip_prefix("refs/remotes/") {
            (RefScope::Remotes, short)
        } else {
            continue;
        };
        if !all
            && !filters
                .iter()
                .any(|filter| filter.scope == scope && glob_match(&filter.pattern, short))
        {
            continue;
        }
        if excludes
            .iter()
            .any(|glob| glob_match(glob, &full) || glob_match(glob, short))
        {
            continue;
        }
        if let Some(oid) = resolve_ref_target(store, Some(target))? {
            if commit_record(store, oid).is_ok() && seen.insert(oid) {
                out.push((oid, short_ref_name(&full).to_owned()));
            }
        }
    }
    Ok(out)
}

/// Reports whether a positional names a path for DWIM fallback: it exists
/// in the worktree, or equals (or contains) a path in the `HEAD` tree.
fn dwim_path_exists(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    item: &str,
) -> Result<bool, GitError> {
    if ctx.file_base.join(item).exists() {
        return Ok(true);
    }
    let Ok(head) = head_oid(store) else {
        return Ok(false);
    };
    let Ok(record) = commit_record(store, head) else {
        return Ok(false);
    };
    let Ok(tree) = commit_tree_oid(&record) else {
        return Ok(false);
    };
    let Ok(entries) = flatten_tree(store, kind, tree) else {
        return Ok(false);
    };
    let want = item.as_bytes();
    Ok(entries
        .iter()
        .any(|(path, _, _)| path_wanted(path, want) || path_wanted(want, path)))
}

/// Walks `tips` in `git log` order (newest committer-date first, discovery
/// order breaking ties) while skipping `exclude` and everything reachable
/// from it, mirroring [`walk_history_excluding`]. When `first_parent` is
/// set only the first parent is followed out of each merge. Every entry
/// records the tip whose walk first reached it (first reach wins), backing
/// `--source` and `--left-right`.
fn walk_log(
    store: &Store,
    tips: &[Oid],
    exclude: &[Oid],
    first_parent: bool,
) -> Result<Vec<LogWalkEntry>, GitError> {
    use ruk_core::records::Records;
    let records = Records::new(store);
    let mut seen: HashSet<Oid> = HashSet::new();
    let mut stack: Vec<Oid> = exclude.to_vec();
    while let Some(oid) = stack.pop() {
        let oid = replace_redirect(store, oid);
        if !seen.insert(oid) {
            continue;
        }
        let Ok(record) = walk_record(store, &records, oid) else {
            continue;
        };
        for parent in record.parents() {
            if let Some(parent_oid) = parent.as_git().copied() {
                stack.push(parent_oid);
            }
        }
    }
    let mut queue = WalkQueue::new();
    for oid in &seen {
        queue.mark_seen(*oid);
    }
    let mut origins: HashMap<Oid, Oid> = HashMap::new();
    for tip in tips {
        origins.entry(*tip).or_insert(*tip);
        queue.enqueue(store, &records, *tip)?;
    }
    let mut out = Vec::new();
    while let Some((oid, record)) = queue.pop() {
        let origin = origins.get(&oid).copied().unwrap_or(oid);
        let parents: Vec<Oid> = record
            .parents()
            .iter()
            .filter_map(|head| head.as_git().copied())
            .collect();
        let first: &[Oid] = match parents.first() {
            Some(one) => std::slice::from_ref(one),
            None => &[],
        };
        let next: &[Oid] = if first_parent { first } else { &parents };
        for parent in next {
            origins.entry(*parent).or_insert(origin);
            queue.enqueue(store, &records, *parent)?;
        }
        out.push(LogWalkEntry {
            oid,
            record,
            origin,
        });
    }
    Ok(out)
}

/// Advances `--follow` one commit back: reports whether the commit touches
/// `current`, plus the path to keep tracking (the pre-rename path when the
/// commit renames it away). Rename pairing runs at 50% similarity when the
/// caller's mode would pair nothing, the way the oracle implies rename
/// detection for `--follow`.
fn follow_step(
    ctx: &Ctx,
    store: &Store,
    record: &CommitRecord,
    current: &[u8],
    mode: super::rename::RenameMode,
) -> Result<Option<Vec<u8>>, GitError> {
    let tree = commit_tree_oid(record)?;
    let mut parent_tree = None;
    if let Some(parent) = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .next()
    {
        parent_tree = Some(commit_tree_oid(&commit_record(store, parent)?)?);
    }
    let mut pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
    let effective = match mode {
        super::rename::RenameMode::Similar(_) => mode,
        super::rename::RenameMode::Disabled | super::rename::RenameMode::ExactOnly => {
            super::rename::RenameMode::Similar(50)
        }
    };
    apply_pair_renames(ctx, &mut pairs, effective)?;
    for pair in &pairs {
        if pair.path == current {
            if let Some(old) = &pair.old_path {
                if old != current {
                    return Ok(Some(old.clone()));
                }
            }
            return Ok(Some(current.to_vec()));
        }
    }
    Ok(None)
}

/// Counts non-empty needle occurrences in one blob body.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Reports whether a commit passes the pickaxe filters against its first
/// parent: `-S` keeps commits changing the needle's occurrence count across
/// the diff, `-G` keeps commits with an added/removed line matching the
/// regex (binary sides are skipped for `-G`, counted raw for `-S`, as in
/// git). Non-empty `wants` limits both to matching paths.
fn commit_passes_pickaxe(
    ctx: &Ctx,
    store: &Store,
    record: &CommitRecord,
    wants: &[Vec<u8>],
    needle: Option<&[u8]>,
    pattern: Option<&Regex>,
) -> Result<bool, GitError> {
    let tree = commit_tree_oid(record)?;
    let mut parent_tree = None;
    if let Some(parent) = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .next()
    {
        parent_tree = Some(commit_tree_oid(&commit_record(store, parent)?)?);
    }
    for pair in &tree_pairs(ctx, parent_tree, Some(tree))? {
        if !wants.is_empty() && !wants.iter().any(|want| path_wanted(&pair.path, want)) {
            continue;
        }
        let (old_body, new_body) = pair_bodies(ctx, pair)?;
        if let Some(needle) = needle {
            let old_count =
                count_occurrences(old_body.as_deref().unwrap_or_default(), needle);
            let new_count =
                count_occurrences(new_body.as_deref().unwrap_or_default(), needle);
            if old_count != new_count {
                return Ok(true);
            }
            continue;
        }
        if let Some(regex) = pattern {
            let old = old_body.unwrap_or_default();
            let new = new_body.unwrap_or_default();
            if old.contains(&0) || new.contains(&0) {
                continue;
            }
            let old_lines = split_lines(&old);
            let new_lines = split_lines(&new);
            for op in lcs_script(&old_lines, &new_lines) {
                let changed = match op {
                    DiffOp::Delete(line) | DiffOp::Insert(line) => line,
                    DiffOp::Keep(_) => continue,
                };
                if regex.is_match(changed) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Fingerprints one commit's first-parent change for `--cherry-pick`: the
/// sorted multiset of added/removed lines (binary sides contribute their
/// path, the way a patch-id still distinguishes them), joined on NUL.
fn patch_fingerprint(
    ctx: &Ctx,
    store: &Store,
    record: &CommitRecord,
) -> Result<Vec<u8>, GitError> {
    let tree = commit_tree_oid(record)?;
    let mut parent_tree = None;
    if let Some(parent) = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .next()
    {
        parent_tree = Some(commit_tree_oid(&commit_record(store, parent)?)?);
    }
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for pair in &tree_pairs(ctx, parent_tree, Some(tree))? {
        let (old_body, new_body) = pair_bodies(ctx, pair)?;
        let old = old_body.unwrap_or_default();
        let new = new_body.unwrap_or_default();
        if old.contains(&0) || new.contains(&0) {
            lines.push(pair.path.clone());
            continue;
        }
        let old_lines = split_lines(&old);
        let new_lines = split_lines(&new);
        for op in lcs_script(&old_lines, &new_lines) {
            match op {
                DiffOp::Delete(line) | DiffOp::Insert(line) => lines.push(line.to_vec()),
                DiffOp::Keep(_) => {}
            }
        }
    }
    lines.sort();
    let mut out = Vec::new();
    for line in &lines {
        out.extend_from_slice(line);
        out.push(0);
    }
    Ok(out)
}

/// Drops `--cherry-pick` commits for one `A...B` range: a commit whose
/// change fingerprint also occurs on the other side is omitted on both
/// sides, as in git. Commits reached via any other tip are always kept.
fn cherry_pick_filter(
    ctx: &Ctx,
    store: &Store,
    shown: &[ShownCommit],
    left: Oid,
    right: Oid,
) -> Result<Vec<ShownCommit>, GitError> {
    let mut prints: Vec<Vec<u8>> = Vec::with_capacity(shown.len());
    for shown in shown {
        prints.push(patch_fingerprint(ctx, store, &shown.record)?);
    }
    let mut left_counts: HashMap<&Vec<u8>, usize> = HashMap::new();
    let mut right_counts: HashMap<&Vec<u8>, usize> = HashMap::new();
    for (shown, print) in shown.iter().zip(prints.iter()) {
        if shown.origin == left {
            *left_counts.entry(print).or_default() += 1;
        } else if shown.origin == right {
            *right_counts.entry(print).or_default() += 1;
        }
    }
    let mut out = Vec::with_capacity(shown.len());
    for (shown, print) in shown.into_iter().zip(prints.iter()) {
        let duplicate = if shown.origin == left {
            right_counts.contains_key(print)
        } else if shown.origin == right {
            left_counts.contains_key(print)
        } else {
            false
        };
        if !duplicate {
            out.push(ShownCommit {
                oid: shown.oid,
                record: shown.record.clone(),
                origin: shown.origin,
            });
        }
    }
    Ok(out)
}

/// Reorders walked commits into `--topo-order`: children before parents,
/// with each branch kept contiguous. Iterative pre-order depth-first search
/// from the tips (first parent first); commits unreachable from the tips
/// cannot occur from [`walk_log`] and sweep last in oid order.
fn topo_reorder(shown: Vec<ShownCommit>, tips: &[Oid]) -> Vec<ShownCommit> {
    let mut slots: HashMap<Oid, ShownCommit> =
        shown.into_iter().map(|shown| (shown.oid, shown)).collect();
    let mut visited: HashSet<Oid> = HashSet::new();
    let mut out = Vec::with_capacity(slots.len());
    let mut stack: Vec<Oid> = Vec::new();
    for tip in tips.iter().rev() {
        if slots.contains_key(tip) {
            stack.push(*tip);
        }
    }
    while let Some(oid) = stack.pop() {
        if !visited.insert(oid) {
            continue;
        }
        let Some(entry) = slots.remove(&oid) else {
            continue;
        };
        let parents: Vec<Oid> = entry
            .record
            .parents()
            .iter()
            .filter_map(|head| head.as_git().copied())
            .collect();
        for parent in parents.iter().rev() {
            if slots.contains_key(parent) {
                stack.push(*parent);
            }
        }
        out.push(entry);
    }
    if !slots.is_empty() {
        let mut rest: Vec<Oid> = slots.keys().copied().collect();
        rest.sort();
        for oid in rest {
            if visited.insert(oid) {
                out.push(slots.remove(&oid).expect("leftover topo slot"));
            }
        }
    }
    out
}

/// Renders one commit's first-parent change in the extra stat shapes:
/// `--summary` mode lines, `--numstat` added/deleted/path rows, `--shortstat`
/// one-line totals, and `--dirstat` per-directory percentages. `--stat`
/// itself still renders through the shared pair renderer in
/// [`log_commit_diff`] so its bytes never depend on which extra shapes are
/// also requested.
fn log_commit_extra(
    ctx: &Ctx,
    store: &Store,
    oid: &Oid,
    record: &CommitRecord,
    opts: &super::Collected,
) -> Result<Vec<u8>, GitError> {
    let tree = commit_tree_oid(record)?;
    let mut parent_tree = None;
    if let Some(parent) = commit_parents(store, *oid)?.first() {
        parent_tree = Some(commit_tree_oid(&commit_record(store, *parent)?)?);
    }
    let changes = tree_file_changes(ctx, parent_tree, tree)?;
    let mut out = Vec::new();
    if opts.is_set("summary") {
        out.extend_from_slice(&render_mode_lines(&changes));
    }
    if opts.is_set("numstat") {
        out.extend_from_slice(&render_numstat(&changes));
    }
    if opts.is_set("shortstat") {
        let (added, removed) = stat_totals(&changes);
        out.extend_from_slice(&stat_summary(changes.len(), added, removed));
    }
    if opts.is_set("dirstat") {
        out.extend_from_slice(&render_dirstat(&changes));
    }
    Ok(out)
}

/// Renders `--numstat` rows: `added<TAB>deleted<TAB>path`, `-` counts for
/// binaries, `old => new` for renames, in display-path order.
fn render_numstat(changes: &[FileChange]) -> Vec<u8> {
    let mut out = Vec::new();
    for change in changes {
        let name = stat_name(change);
        if change.binary {
            out.extend_from_slice(format!("-\t-\t{name}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{}\t{}\t{name}\n", change.added, change.removed).as_bytes());
        }
    }
    out
}

/// Renders `--dirstat` rows: changed lines per top-level directory as a
/// percentage of the commit's changed lines, hottest first. Root-level
/// files group under their own name.
fn render_dirstat(changes: &[FileChange]) -> Vec<u8> {
    let mut per_dir: HashMap<String, usize> = HashMap::new();
    let mut total = 0;
    for change in changes {
        let lines = change.added + change.removed;
        total += lines;
        let path = String::from_utf8_lossy(&display_path(change)).into_owned();
        let dir = match path.find('/') {
            Some(index) => format!("{}/", &path[..index]),
            None => path,
        };
        *per_dir.entry(dir).or_default() += lines;
    }
    if total == 0 {
        return Vec::new();
    }
    let mut rows: Vec<(String, usize)> = per_dir.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let mut out = Vec::new();
    for (dir, lines) in &rows {
        let percent = 100.0 * *lines as f64 / total as f64;
        out.extend_from_slice(format!("{percent:5.1}%  {dir}\n").as_bytes());
    }
    out
}

/// Renders one note for `--show-notes` the way the oracle appends it after
/// the message: a `Notes:` header with the body indented four spaces.
fn render_note(note: &[u8]) -> Vec<u8> {
    let mut out = b"Notes:\n".to_vec();
    let mut text = note;
    while text.last() == Some(&b'\n') {
        text = &text[..text.len() - 1];
    }
    for line in text.split(|byte| *byte == b'\n') {
        out.extend_from_slice(b"    ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// Parses `--max-count` once for the verbs that limit history output.
fn parse_max_count(opts: &super::Collected) -> Result<Option<usize>, GitError> {
    opts.single("max-count")?
        .map(|value| {
            value.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad --max-count {value:?}"),
            })
        })
        .transpose()
}

/// Parses one `--since`/`--until` bound into a committer timestamp.
fn parse_since_until(opts: &super::Collected, name: &str) -> Result<Option<i64>, GitError> {
    opts.single(name)?
        .map(|text| parse_date_arg(&text))
        .transpose()
}

/// Builds the shared identity-line rendering for `log` and `show` from
/// `--oneline`/`--pretty`/`--format`/`--abbrev-commit`, plus the
/// log-only `--date`/`--relative-date` shapes (`show` never declares those
/// flags, so it always renders the default shape).
fn commit_line_of(opts: &super::Collected) -> Result<CommitLine, GitError> {
    let mut oneline = opts.is_set("oneline");
    let mut pretty = PrettyKind::Default;
    let mut format = match opts.single("format")? {
        Some(text) => Some(parse_log_format(strip_format_prefix(&text))?),
        None => None,
    };
    if format.is_none() {
        if let Some(text) = opts.single("pretty")? {
            match text.as_str() {
                "oneline" => oneline = true,
                "short" | "medium" => oneline = false,
                "full" => pretty = PrettyKind::Full,
                "fuller" => pretty = PrettyKind::Fuller,
                "email" => pretty = PrettyKind::Email,
                "raw" => pretty = PrettyKind::Raw,
                _ => format = parse_pretty_arg(&text)?,
            }
        }
    }
    let mut date = match opts.single("date")? {
        Some(text) => parse_date_mode(&text)?,
        None => DateMode::Default,
    };
    if date == DateMode::Default && opts.is_set("relative-date") {
        date = DateMode::Relative;
    }
    Ok(CommitLine {
        oneline,
        format,
        abbrev: opts.is_set("abbrev-commit"),
        abbrev_len: 7,
        pretty,
        date,
        now: now_seconds()?,
    })
}

/// Reports whether one commit passes the `--since`/`--until`/`--author` and
/// path filters. Bounds compare against the committer timestamp, as in git.
fn commit_passes_filters(
    store: &Store,
    kind: HashKind,
    record: &CommitRecord,
    since: Option<i64>,
    until: Option<i64>,
    author_want: Option<&str>,
    wants: &[Vec<u8>],
) -> Result<bool, GitError> {
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    if since.is_some() || until.is_some() {
        let stamp = record
            .committer()
            .map_err(|_| broken("committer"))?
            .timestamp;
        if since.is_some_and(|bound| stamp < bound) || until.is_some_and(|bound| stamp > bound) {
            return Ok(false);
        }
    }
    if let Some(want) = author_want {
        let author = record.author().map_err(|_| broken("author"))?;
        let name = String::from_utf8_lossy(author.name.as_bytes());
        let email = String::from_utf8_lossy(author.email.as_bytes());
        if !name.contains(want) && !email.contains(want) {
            return Ok(false);
        }
    }
    if !wants.is_empty() && !commit_touches_path(store, kind, record, wants)? {
        return Ok(false);
    }
    Ok(true)
}

/// Renders one log commit's change against its first parent, reusing the
/// shared pair renderer so `--stat`/`-p` spellings match `diff` and `show`.
/// When only the extra stat shapes (`--summary`/`--shortstat`/`--numstat`/
/// `--dirstat`) are requested, no patch prints: those render separately in
/// [`log_commit_extra`].
fn log_commit_diff(
    ctx: &Ctx,
    store: &Store,
    oid: &Oid,
    record: &CommitRecord,
    opts: &super::Collected,
    rename_mode: super::rename::RenameMode,
) -> Result<Vec<u8>, GitError> {
    let extra_only = (opts.is_set("summary")
        || opts.is_set("shortstat")
        || opts.is_set("numstat")
        || opts.is_set("dirstat"))
        && !(opts.is_set("patch")
            || opts.is_set("stat")
            || opts.is_set("name-only")
            || opts.is_set("name-status"));
    if extra_only {
        return Ok(Vec::new());
    }
    let tree = commit_tree_oid(record)?;
    let mut parent_tree = None;
    if let Some(parent) = commit_parents(store, *oid)?.first() {
        parent_tree = Some(commit_tree_oid(&commit_record(store, *parent)?)?);
    }
    let mut pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
    apply_pair_renames(ctx, &mut pairs, rename_mode)?;
    render_pairs(ctx, &pairs, opts)
}

/// Takes the first message line for one-line logs.
fn first_subject_line(message: &[u8]) -> String {
    let end = message
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(message.len());
    String::from_utf8_lossy(&message[..end]).into_owned()
}

/// Shows one commit with its diff against its first parent, or one blob
/// with `show <rev>:<path>`.
///
/// Oracle: `git/builtin/log.c` (`cmd_show`). Explicit `-p`/`--patch` is the
/// default patch behavior and only matters next to `--stat`, where the two
/// combine into stat-then-patch.
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
            long: "name-status",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-patch",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "pretty",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "abbrev-commit",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "decorate",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-decorate",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "unified",
            short: Some('U'),
            takes_value: true,
        },
    ];
    let (args, decorate_mode) = extract_decorate_arg(args)?;
    let (args, rename_mode) = super::rename::split_rename_args(&args)?;
    let opts = collect_expanded(&args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rev = opts.positionals.first().map_or("HEAD", String::as_str);
    if rev.contains(':') {
        let oid = resolve_local(store, kind, rev)?;
        let (_, body) = read_object_bytes(store, oid)?;
        return Ok(body);
    }
    let oid = resolve_local(store, kind, rev)?;
    let record = commit_record(store, oid)?;
    let line = commit_line_of(&opts)?;
    let decorate = !opts.is_set("no-decorate")
        && (opts.is_set("decorate") || decorate_mode.as_deref().is_some_and(|mode| mode != "no"));
    let full_names = decorate_mode.as_deref() == Some("full");
    let decoration = if decorate || line.format.is_some() {
        decoration_text(&decoration_map(store)?, &oid, full_names)
    } else {
        String::new()
    };
    let mut out = render_commit_line(&line, &oid, &record, &decoration)?;
    if opts.is_set("no-patch") || opts.is_set("quiet") {
        return Ok(out);
    }
    let tree = commit_tree_oid(&record)?;
    let mut parent_tree = None;
    if let Some(parent) = commit_parents(store, oid)?.first() {
        parent_tree = Some(commit_tree_oid(&commit_record(store, *parent)?)?);
    }
    let mut pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
    apply_pair_renames(ctx, &mut pairs, rename_mode)?;
    out.extend_from_slice(&render_pairs(ctx, &pairs, &opts)?);
    Ok(out)
}

/// Shows worktree, index, and tree differences with hunks.
///
/// Oracle: `git/builtin/diff.c`. `A..B` compares the two trees directly
/// (the `diff A B` form); `A...B` diffs the merge base against `B`, showing
/// `B` since it forked, as in git. `--no-color` is accepted because output
/// is never colorized. `--exit-code` is deliberately absent: the verb
/// return carries stdout or failure, never both, so a differing diff with
/// exit 1 needs plumbing owned outside this file.
pub(crate) fn diff(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "cached",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "staged",
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
            long: "name-status",
            short: None,
            takes_value: false,
        },
        // Accepted: patch is the default output, so the flag only matters
        // next to `--stat` (stat-then-patch in the shared renderer).
        FlagSpec {
            long: "patch",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "unified",
            short: Some('U'),
            takes_value: true,
        },
        // Accepted and ignored: output is never colorized.
        FlagSpec {
            long: "no-color",
            short: None,
            takes_value: false,
        },
    ];
    let (rev_args, dash_paths) = split_double_dash(args);
    let (rev_args, rename_mode) = super::rename::split_rename_args(&rev_args)?;
    let opts = collect_expanded(&rev_args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut rev_zone: Vec<String> = Vec::new();
    for item in &opts.positionals {
        match split_range(item) {
            Some(range) if !range.from.is_empty() && !range.to.is_empty() => {
                let from = try_resolve_rev(store, kind, &range.from)?;
                let to = try_resolve_rev(store, kind, &range.to)?;
                match (from, to) {
                    (Some(from_oid), Some(to_oid)) => {
                        if range.symmetric {
                            let base = state_merge_base(store, from_oid, to_oid)?;
                            rev_zone.push(base.to_hex());
                        } else {
                            rev_zone.push(range.from);
                        }
                        rev_zone.push(range.to);
                    }
                    _ => rev_zone.push(item.clone()),
                }
            }
            _ => rev_zone.push(item.clone()),
        }
    }
    let (rev, rev_b, mut path_texts) = match rev_zone.as_slice() {
        [] => (None, None, Vec::new()),
        [single] => match try_resolve_rev(store, kind, single)? {
            Some(_) => (Some(single.clone()), None, Vec::new()),
            None => (None, None, vec![single.clone()]),
        },
        [first, second, rest @ ..] => match try_resolve_rev(store, kind, first)? {
            Some(_) => match try_resolve_rev(store, kind, second)? {
                Some(_) => (Some(first.clone()), Some(second.clone()), rest.to_vec()),
                None => (
                    Some(first.clone()),
                    None,
                    std::iter::once(second.clone())
                        .chain(rest.iter().cloned())
                        .collect(),
                ),
            },
            None => (None, None, rev_zone.clone()),
        },
    };
    path_texts.extend(dash_paths);
    let paths: Vec<RepoPath> = path_texts
        .iter()
        .map(|text| super::verbs_stage::repo_path_of(ctx, text.as_bytes()))
        .collect::<Result<_, _>>()?;
    let staged = opts.is_set("cached") || opts.is_set("staged");
    // Only tree/tree and tree/index pairs rename-pair: worktree additions
    // include untracked files, which the oracle never pairs.
    let track_renames = rev_b.is_some() || staged;
    let pairs = match (rev, rev_b) {
        (Some(one), Some(two)) => {
            let old_oid = replace_redirect(store, resolve_local(store, kind, &one)?);
            let new_oid = replace_redirect(store, resolve_local(store, kind, &two)?);
            let old_tree = peel_to_tree(store, kind, old_oid)?;
            let new_tree = peel_to_tree(store, kind, new_oid)?;
            tree_pairs(ctx, Some(old_tree), Some(new_tree))?
        }
        (rev, None) => match (rev, staged) {
            (None, false) => worktree_pairs(ctx)?,
            (None, true) => staged_pairs(ctx)?,
            (Some(one), false) => rev_worktree_pairs(ctx, &one)?,
            (Some(one), true) => rev_staged_pairs(ctx, &one)?,
        },
        (None, Some(_)) => unreachable!("a second rev never outlives a missing first"),
    };
    let mut pairs = pairs;
    if !paths.is_empty() {
        // The oracle applies the pathspec before rename detection: sides
        // outside it stay add or delete, never half of a rename.
        pairs.retain(|pair| {
            paths
                .iter()
                .any(|want| want.as_bytes() == pair.path.as_slice())
        });
    }
    if track_renames {
        apply_pair_renames(ctx, &mut pairs, rename_mode)?;
    }
    render_pairs(ctx, &pairs, &opts)
}

/// One compared path: the old and new side, either absent.
struct TreePair {
    /// Full path bytes (the new path for renames).
    path: Vec<u8>,
    /// Old path for renames, set by the pairing pass.
    old_path: Option<Vec<u8>>,
    /// Old mode and oid, when present before.
    old: Option<(TreeMode, Oid)>,
    /// New mode and oid, when present after.
    new: Option<(TreeMode, Oid)>,
    /// New-side bytes when the content has no stored object (worktree
    /// edits). Overrides the object read keyed by `new`'s oid.
    new_bytes: Option<Vec<u8>>,
    /// Rename similarity score, set by the pairing pass.
    similarity: Option<u8>,
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
            old_path: None,
            old: old_entry,
            new: new_entry,
            new_bytes: None,
            similarity: None,
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
            index_map.insert(
                path.as_bytes().to_vec(),
                (TreeMode::from(entry.mode()), entry.oid()),
            );
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
                let mode = TreeMode::from(entry_mode_of(&entry));
                pairs.push(TreePair {
                    path: entry.path,
                    old_path: None,
                    old: None,
                    new: Some((mode, oid)),
                    new_bytes: Some(bytes),
                    similarity: None,
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
                        old_path: None,
                        old: Some((mode, oid)),
                        new: Some((mode, fresh)),
                        new_bytes: Some(bytes),
                        similarity: None,
                    });
                }
            }
        }
    }
    for (path, (mode, oid)) in index_map {
        pairs.push(TreePair {
            path,
            old_path: None,
            old: Some((mode, oid)),
            new: None,
            new_bytes: None,
            similarity: None,
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
            index_map.insert(
                path.as_bytes().to_vec(),
                (TreeMode::from(entry.mode()), entry.oid()),
            );
        }
    }
    tree_pairs_index(ctx, Some(tree), index_map)
}

/// Pairs one revision's tree against worktree files.
fn rev_worktree_pairs(ctx: &Ctx, rev: &str) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = replace_redirect(store, resolve_rev(store, kind, rev)?);
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
                let mode = TreeMode::from(entry_mode_of(&entry));
                pairs.push(TreePair {
                    path: entry.path,
                    old_path: None,
                    old: None,
                    new: Some((mode, fresh)),
                    new_bytes: Some(bytes),
                    similarity: None,
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
                        old_path: None,
                        old: Some((mode, oid)),
                        new: Some((mode, fresh)),
                        new_bytes: Some(bytes),
                        similarity: None,
                    });
                }
            }
        }
    }
    for (path, (mode, oid)) in tree_map {
        pairs.push(TreePair {
            path,
            old_path: None,
            old: Some((mode, oid)),
            new: None,
            new_bytes: None,
            similarity: None,
        });
    }
    pairs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(pairs)
}

/// Pairs one revision's tree against index blobs.
fn rev_staged_pairs(ctx: &Ctx, rev: &str) -> Result<Vec<TreePair>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = replace_redirect(store, resolve_rev(store, kind, rev)?);
    let tree = peel_to_tree(store, kind, oid)?;
    let mut index_map = BTreeMap::new();
    for (path, stage, entry) in scan_index(store, kind)? {
        if stage == Stage::Zero {
            index_map.insert(
                path.as_bytes().to_vec(),
                (TreeMode::from(entry.mode()), entry.oid()),
            );
        }
    }
    tree_pairs_index(ctx, Some(tree), index_map)
}

/// Pairs one tree against a ready index map.
fn tree_pairs_index(
    ctx: &Ctx,
    tree: Option<Oid>,
    mut index_map: BTreeMap<Vec<u8>, (TreeMode, Oid)>,
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
            old_path: None,
            old: old_entry,
            new: new_entry,
            new_bytes: None,
            similarity: None,
        });
    }
    Ok(pairs)
}

/// Pairs deletions with additions into renames when `mode` enables
/// similarity (`-M`). Worktree pairs never reach this pass: their additions
/// include untracked files, which the oracle never rename-pairs, so the
/// callers only invoke it for tree/tree and tree/index pairs.
fn apply_pair_renames(
    ctx: &Ctx,
    pairs: &mut Vec<TreePair>,
    mode: super::rename::RenameMode,
) -> Result<(), GitError> {
    use super::rename::{RenameSide, pair_renames, similarity};
    let threshold = match mode {
        super::rename::RenameMode::Similar(value) => value,
        super::rename::RenameMode::Disabled | super::rename::RenameMode::ExactOnly => {
            return Ok(());
        }
    };
    let store = ctx.store()?;
    // Index positions of pure deletions and pure additions.
    let mut dels: Vec<usize> = Vec::new();
    let mut adds: Vec<usize> = Vec::new();
    for (index, pair) in pairs.iter().enumerate() {
        match (&pair.old, &pair.new) {
            (Some(_), None) => dels.push(index),
            (None, Some(_)) => adds.push(index),
            _ => {}
        }
    }
    if dels.is_empty() || adds.is_empty() {
        return Ok(());
    }
    const MAX_SCORE_BYTES: usize = 1 << 20;
    // Blob bodies on each side, read once; oversized sides only pair when
    // their oids already match.
    let mut del_body: Vec<Option<Vec<u8>>> = Vec::with_capacity(dels.len());
    let mut del_side: Vec<RenameSide> = Vec::with_capacity(dels.len());
    for index in &dels {
        let pair = &pairs[*index];
        let (mode, oid) = pair.old.expect("deletion has an old side");
        let (_, body) = read_object_bytes(store, oid)?;
        del_side.push(RenameSide {
            path: pair.path.clone(),
            size: body.len(),
        });
        del_body.push(if body.len() > MAX_SCORE_BYTES {
            None
        } else {
            Some(body)
        });
    }
    let mut add_body: Vec<Option<Vec<u8>>> = Vec::with_capacity(adds.len());
    let mut add_side: Vec<RenameSide> = Vec::with_capacity(adds.len());
    for index in &adds {
        let pair = &pairs[*index];
        let (_, oid) = pair.new.expect("addition has a new side");
        let body = match &pair.new_bytes {
            Some(bytes) => bytes.clone(),
            None => read_object_bytes(store, oid)?.1,
        };
        add_side.push(RenameSide {
            path: pair.path.clone(),
            size: body.len(),
        });
        add_body.push(if body.len() > MAX_SCORE_BYTES {
            None
        } else {
            Some(body)
        });
    }
    let del_oid: Vec<Oid> = dels
        .iter()
        .map(|index| pairs[*index].old.expect("deletion old").1)
        .collect();
    let add_oid: Vec<Oid> = adds
        .iter()
        .map(|index| pairs[*index].new.expect("addition new").1)
        .collect();
    let del_link: Vec<bool> = dels
        .iter()
        .map(|index| {
            matches!(
                pairs[*index].old.expect("deletion old").0,
                TreeMode::Gitlink
            )
        })
        .collect();
    let add_link: Vec<bool> = adds
        .iter()
        .map(|index| {
            matches!(
                pairs[*index].new.expect("addition new").0,
                TreeMode::Gitlink
            )
        })
        .collect();
    let winners = pair_renames(&del_side, &add_side, threshold, |oi, ni| {
        if del_oid[oi] == add_oid[ni] {
            return 100;
        }
        if del_link[oi] || add_link[ni] {
            return 0;
        }
        match (&del_body[oi], &add_body[ni]) {
            (Some(old), Some(new)) => similarity(old, new),
            _ => 0,
        }
    });
    if winners.is_empty() {
        return Ok(());
    }
    let mut dead = vec![false; pairs.len()];
    let mut merged: Vec<(usize, Vec<u8>, (TreeMode, Oid), u8)> = Vec::new();
    for win in &winners {
        let del_index = dels[win.old];
        let add_index = adds[win.new];
        dead[del_index] = true;
        merged.push((
            add_index,
            pairs[del_index].path.clone(),
            pairs[del_index].old.expect("deletion old"),
            win.score,
        ));
    }
    for (add_index, old_path, old_entry, score) in merged {
        let pair = &mut pairs[add_index];
        pair.old = Some(old_entry);
        pair.old_path = Some(old_path);
        pair.similarity = Some(score);
    }
    let mut kept = Vec::with_capacity(pairs.len());
    for (index, pair) in pairs.drain(..).enumerate() {
        if !dead[index] {
            kept.push(pair);
        }
    }
    kept.sort_by(|left, right| left.path.cmp(&right.path));
    *pairs = kept;
    Ok(())
}

/// One rendered pair with its line counts for `--stat`.
struct CountedHunk {
    /// Full path bytes (the new path for renames).
    path: Vec<u8>,
    /// Old path for renames.
    old_path: Option<Vec<u8>>,
    /// Unified text for the patch form.
    text: Vec<u8>,
    /// Added lines.
    added: usize,
    /// Removed lines.
    removed: usize,
}

/// Renders pairs as patch, stat, or names per the parsed options. An
/// explicit `-p`/`--patch` next to `--stat` prints stat-then-patch, as in
/// git; without it `--stat` prints the stat alone.
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
    if opts.is_set("name-status") {
        let mut out = Vec::new();
        for pair in pairs {
            if let (Some(old_path), Some(score)) = (&pair.old_path, pair.similarity) {
                out.extend_from_slice(
                    format!(
                        "R{score:03}\t{}\t{}\n",
                        String::from_utf8_lossy(old_path),
                        String::from_utf8_lossy(&pair.path)
                    )
                    .as_bytes(),
                );
                continue;
            }
            let status = match (&pair.old, &pair.new) {
                (None, Some(_)) => 'A',
                (Some(_), None) => 'D',
                _ => 'M',
            };
            out.extend_from_slice(
                format!("{status}\t{}\n", String::from_utf8_lossy(&pair.path)).as_bytes(),
            );
        }
        return Ok(out);
    }
    let context = parse_unified_arg(opts)?;
    let mut hunks: Vec<CountedHunk> = Vec::new();
    for pair in pairs {
        let (old_body, new_body) = pair_bodies(ctx, pair)?;
        let (text, added, removed) =
            unified_pair(pair, old_body.as_deref(), new_body.as_deref(), context)?;
        hunks.push(CountedHunk {
            path: pair.path.clone(),
            old_path: pair.old_path.clone(),
            text,
            added,
            removed,
        });
    }
    if opts.is_set("stat") {
        let stat = render_stat(&hunks);
        if !opts.is_set("patch") {
            return Ok(stat);
        }
        let mut out = stat;
        for hunk in &hunks {
            out.extend_from_slice(&hunk.text);
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    for hunk in &hunks {
        out.extend_from_slice(&hunk.text);
    }
    Ok(out)
}

/// Parses `-U<n>`/`--unified=<n>` into a context radius, if given.
fn parse_unified_arg(opts: &super::Collected) -> Result<Option<usize>, GitError> {
    opts.single("unified")?
        .map(|text| {
            text.parse::<usize>().map_err(|_| GitError::Invalid {
                detail: format!("bad -U {text:?}: want context lines"),
            })
        })
        .transpose()
}

/// One changed file between two stored trees, with line counts for the
/// stat block. Exact-blob renames pair into one entry, the way the oracle
/// reports `rename a.txt => aa.txt (100%)` for identical content.
pub(crate) struct FileChange {
    /// Old path, mode, and blob; absent for additions.
    pub(crate) old: Option<(Vec<u8>, TreeMode, Oid)>,
    /// New path, mode, and blob; absent for deletions.
    pub(crate) new: Option<(Vec<u8>, TreeMode, Oid)>,
    /// Added lines (zero for renames, binaries, and mode-only changes).
    pub(crate) added: usize,
    /// Removed lines.
    pub(crate) removed: usize,
    /// Either side holds NUL bytes.
    pub(crate) binary: bool,
    /// Old and new blob sizes for `Bin` stat lines.
    pub(crate) sizes: (usize, usize),
}

/// Diffs two stored trees path by path with line counts, pairing
/// additions and deletions of identical blobs into renames.
pub(crate) fn tree_file_changes(
    ctx: &Ctx,
    old_tree: Option<Oid>,
    new_tree: Oid,
) -> Result<Vec<FileChange>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut old_map = BTreeMap::new();
    if let Some(tree) = old_tree {
        for (path, mode, oid) in flatten_tree(store, kind, tree)? {
            old_map.insert(path, (mode, oid));
        }
    }
    let mut new_map = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, new_tree)? {
        new_map.insert(path, (mode, oid));
    }
    let mut union: Vec<Vec<u8>> = old_map.keys().cloned().collect();
    for path in new_map.keys() {
        if !union.contains(path) {
            union.push(path.clone());
        }
    }
    union.sort();
    let mut added_paths: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    let mut removed_paths: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    let mut changes: Vec<FileChange> = Vec::new();
    for path in union {
        let old_entry = old_map.remove(&path);
        let new_entry = new_map.remove(&path);
        match (old_entry, new_entry) {
            (None, None) => {}
            (Some(old), Some(new)) if old == new => {}
            (Some((old_mode, old_oid)), Some((new_mode, new_oid))) => {
                let (old_body, new_body) =
                    stored_pair(store, (old_mode, old_oid), (new_mode, new_oid))?;
                let (added, removed, binary) = count_diff(&old_body, &new_body);
                changes.push(FileChange {
                    old: Some((path.clone(), old_mode, old_oid)),
                    new: Some((path, new_mode, new_oid)),
                    added,
                    removed,
                    binary,
                    sizes: (old_body.len(), new_body.len()),
                });
            }
            (None, Some((mode, oid))) => added_paths.push((path, mode, oid)),
            (Some((mode, oid)), None) => removed_paths.push((path, mode, oid)),
        }
    }
    // Pair identical blobs first, the way similarity-100% renames collapse.
    let mut taken_new = vec![false; added_paths.len()];
    let mut orphans: Vec<(Vec<u8>, TreeMode, Oid)> = Vec::new();
    for (old_path, old_mode, old_oid) in removed_paths {
        let mut paired = None;
        for (index, (new_path, new_mode, new_oid)) in added_paths.iter().enumerate() {
            if !taken_new[index] && *new_oid == old_oid {
                paired = Some((index, new_path.clone(), *new_mode, *new_oid));
                break;
            }
        }
        match paired {
            Some((index, new_path, new_mode, new_oid)) => {
                taken_new[index] = true;
                let body = stat_body(store, old_mode, old_oid)?;
                changes.push(FileChange {
                    old: Some((old_path, old_mode, old_oid)),
                    new: Some((new_path, new_mode, new_oid)),
                    added: 0,
                    removed: 0,
                    binary: body.contains(&0),
                    sizes: (body.len(), body.len()),
                });
            }
            None => orphans.push((old_path, old_mode, old_oid)),
        }
    }
    for (path, mode, oid) in orphans {
        let body = stat_body(store, mode, oid)?;
        changes.push(FileChange {
            old: Some((path, mode, oid)),
            new: None,
            added: 0,
            removed: split_lines(&body).len(),
            binary: body.contains(&0),
            sizes: (body.len(), 0),
        });
    }
    for (index, (path, mode, oid)) in added_paths.into_iter().enumerate() {
        if taken_new[index] {
            continue;
        }
        let body = stat_body(store, mode, oid)?;
        changes.push(FileChange {
            old: None,
            new: Some((path, mode, oid)),
            added: split_lines(&body).len(),
            removed: 0,
            binary: body.contains(&0),
            sizes: (0, body.len()),
        });
    }
    changes.sort_by(|left, right| display_path(left).cmp(&display_path(right)));
    Ok(changes)
}

/// Reads both blobs behind one stored pair.
fn stored_pair(
    store: &Store,
    old: (TreeMode, Oid),
    new: (TreeMode, Oid),
) -> Result<(Vec<u8>, Vec<u8>), GitError> {
    Ok((
        stat_body(store, old.0, old.1)?,
        stat_body(store, new.0, new.1)?,
    ))
}

/// Reads one blob for stat line counts.
///
/// A gitlink row names a commit in the child store, never a blob here, so
/// its side reads as empty: the change still counts as a file, with no
/// lines, and the mode line keeps the `160000` spelling.
fn stat_body(store: &Store, mode: TreeMode, oid: Oid) -> Result<Vec<u8>, GitError> {
    if mode == TreeMode::Gitlink {
        return Ok(Vec::new());
    }
    read_object_bytes(store, oid).map(|(_, body)| body)
}

/// Counts added/removed lines between two bodies with the shared LCS
/// differ. Either side holding NUL bytes is binary: no line counts.
fn count_diff(old_body: &[u8], new_body: &[u8]) -> (usize, usize, bool) {
    if old_body.contains(&0) || new_body.contains(&0) {
        return (0, 0, true);
    }
    let old_lines = split_lines(old_body);
    let new_lines = split_lines(new_body);
    let mut added = 0;
    let mut removed = 0;
    for op in lcs_script(&old_lines, &new_lines) {
        match op {
            DiffOp::Keep(_) => {}
            DiffOp::Delete(_) => removed += 1,
            DiffOp::Insert(_) => added += 1,
        }
    }
    (added, removed, false)
}

/// Sorts and displays one change under its new path, old path for deletes.
fn display_path(change: &FileChange) -> Vec<u8> {
    match (&change.old, &change.new) {
        (_, Some((path, _, _))) => path.clone(),
        (Some((path, _, _)), None) => path.clone(),
        (None, None) => Vec::new(),
    }
}

/// Renders the per-file stat lines plus the summary, the block `commit`,
/// `show --stat`, and fast-forward merges share.
pub(crate) fn render_file_stat(changes: &[FileChange]) -> Vec<u8> {
    let mut out = Vec::new();
    let width = changes
        .iter()
        .map(|change| stat_name(change).len())
        .max()
        .unwrap_or(0);
    let (added_total, removed_total) = stat_totals(changes);
    for change in changes {
        let name = stat_name(change);
        let padded = format!("{name:<width$}");
        if change.binary {
            out.extend_from_slice(
                format!(
                    " {padded} | Bin {} -> {} bytes\n",
                    change.sizes.0, change.sizes.1
                )
                .as_bytes(),
            );
        } else if change.added == 0 && change.removed == 0 {
            out.extend_from_slice(format!(" {padded} | 0\n").as_bytes());
        } else {
            out.extend_from_slice(
                format!(
                    " {padded} | {} {}{}\n",
                    change.added + change.removed,
                    "+".repeat(change.added),
                    "-".repeat(change.removed)
                )
                .as_bytes(),
            );
        }
    }
    out.extend_from_slice(&stat_summary(changes.len(), added_total, removed_total));
    out
}

/// Names one change for stat lines: `old => new` for renames.
fn stat_name(change: &FileChange) -> String {
    match (&change.old, &change.new) {
        (Some((old_path, _, _)), Some((new_path, _, _))) if old_path != new_path => format!(
            "{} => {}",
            String::from_utf8_lossy(old_path),
            String::from_utf8_lossy(new_path)
        ),
        _ => String::from_utf8_lossy(&display_path(change)).into_owned(),
    }
}

/// Renders the `N files changed, ...` summary with git's rules: singular
/// `file`/`insertion`/`deletion`, and both zero counters shown only when
/// nothing changed at all.
pub(crate) fn stat_summary(files: usize, added: usize, removed: usize) -> Vec<u8> {
    let mut line = format!(
        " {files} {} changed",
        if files == 1 { "file" } else { "files" }
    );
    if added > 0 || removed == 0 {
        line.push_str(&format!(
            ", {added} {}",
            if added == 1 {
                "insertion(+)"
            } else {
                "insertions(+)"
            }
        ));
    }
    if removed > 0 || added == 0 {
        line.push_str(&format!(
            ", {removed} {}",
            if removed == 1 {
                "deletion(-)"
            } else {
                "deletions(-)"
            }
        ));
    }
    line.push('\n');
    line.into_bytes()
}

/// Renders `create mode`/`delete mode`/`rename ... (100%)` lines plus pure
/// mode changes, in display-path order.
pub(crate) fn render_mode_lines(changes: &[FileChange]) -> Vec<u8> {
    let mut out = Vec::new();
    for change in changes {
        match (&change.old, &change.new) {
            (None, Some((path, mode, _))) => {
                out.extend_from_slice(
                    format!(
                        " create mode {:o} {}\n",
                        mode.octal(),
                        String::from_utf8_lossy(path)
                    )
                    .as_bytes(),
                );
            }
            (Some((path, mode, _)), None) => {
                out.extend_from_slice(
                    format!(
                        " delete mode {:o} {}\n",
                        mode.octal(),
                        String::from_utf8_lossy(path)
                    )
                    .as_bytes(),
                );
            }
            (Some((old_path, old_mode, _)), Some((new_path, new_mode, _))) => {
                if old_path != new_path {
                    out.extend_from_slice(
                        format!(
                            " rename {} => {} (100%)\n",
                            String::from_utf8_lossy(old_path),
                            String::from_utf8_lossy(new_path)
                        )
                        .as_bytes(),
                    );
                }
                if old_mode != new_mode {
                    out.extend_from_slice(
                        format!(
                            " mode change {:o} => {:o} {}\n",
                            old_mode.octal(),
                            new_mode.octal(),
                            String::from_utf8_lossy(new_path)
                        )
                        .as_bytes(),
                    );
                }
            }
            (None, None) => {}
        }
    }
    out
}

/// Renders `--stat` from counted hunks.
fn render_stat(hunks: &[CountedHunk]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut added_total = 0;
    let mut removed_total = 0;
    for hunk in hunks {
        added_total += hunk.added;
        removed_total += hunk.removed;
        let name = match &hunk.old_path {
            Some(old) => format!(
                "{} => {}",
                String::from_utf8_lossy(old),
                String::from_utf8_lossy(&hunk.path)
            ),
            None => String::from_utf8_lossy(&hunk.path).into_owned(),
        };
        out.extend_from_slice(
            format!(
                " {name} | {} {}{}\n",
                hunk.added + hunk.removed,
                "+".repeat(hunk.added),
                "-".repeat(hunk.removed)
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(&stat_summary(hunks.len(), added_total, removed_total));
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

/// Formats one hunk range the way the oracle does: the `,count` suffix is
/// omitted for single-line hunks (`@@ -1 +1 @@`), kept otherwise.
fn hunk_range(start: usize, count: usize) -> String {
    if count == 1 {
        format!("{start}")
    } else {
        format!("{start},{count}")
    }
}

/// Diffs one path pair into unified text with added/removed counts,
/// collapsing unchanged runs to `context` lines around each change when
/// set. `None` keeps the historical show-everything form. The extended
/// header (`new file mode`, `index <old>..<new>`, `/dev/null` sides)
/// follows the oracle's `diff.c` layout exactly.
fn unified_pair(
    pair: &TreePair,
    old: Option<&[u8]>,
    new: Option<&[u8]>,
    context: Option<usize>,
) -> Result<(Vec<u8>, usize, usize), GitError> {
    let new_name = String::from_utf8_lossy(&pair.path);
    let old_name = pair
        .old_path
        .as_ref()
        .map_or_else(|| new_name.clone(), |old| String::from_utf8_lossy(old));
    let mut out = format!("diff --git a/{old_name} b/{new_name}\n").into_bytes();
    let old_mode = pair.old.map(|(mode, _)| mode);
    let new_mode = pair.new.map(|(mode, _)| mode);
    match (old_mode, new_mode) {
        (None, Some(mode)) => {
            out.extend_from_slice(format!("new file mode {:o}\n", mode.octal()).as_bytes());
        }
        (Some(mode), None) => {
            out.extend_from_slice(format!("deleted file mode {:o}\n", mode.octal()).as_bytes());
        }
        (Some(before), Some(after)) if before != after => {
            out.extend_from_slice(
                format!(
                    "old mode {:o}\nnew mode {:o}\n",
                    before.octal(),
                    after.octal()
                )
                .as_bytes(),
            );
        }
        _ => {}
    }
    if let Some(score) = pair.similarity {
        out.extend_from_slice(
            format!("similarity index {score}%\nrename from {old_name}\nrename to {new_name}\n")
                .as_bytes(),
        );
    }
    let old_oid = pair.old.map(|(_, oid)| oid);
    let new_oid = pair.new.map(|(_, oid)| oid);
    let content_changed = old_oid != new_oid;
    if pair.old_path.is_some() && !content_changed {
        return Ok((out, 0, 0));
    }
    if content_changed {
        let old_short = old_oid.map_or_else(|| "0000000".to_owned(), |oid| short_hex(&oid));
        let new_short = new_oid.map_or_else(|| "0000000".to_owned(), |oid| short_hex(&oid));
        match (old_mode, new_mode) {
            (Some(before), Some(after)) if before == after => {
                out.extend_from_slice(
                    format!("index {old_short}..{new_short} {:o}\n", before.octal()).as_bytes(),
                );
            }
            _ => {
                out.extend_from_slice(format!("index {old_short}..{new_short}\n").as_bytes());
            }
        }
    }
    let old_lines = old.map(split_lines).unwrap_or_default();
    let new_lines = new.map(split_lines).unwrap_or_default();
    if old_lines.iter().any(|line| line.contains(&b'\0'))
        || new_lines.iter().any(|line| line.contains(&b'\0'))
    {
        let old_side = pair
            .old
            .map_or_else(|| "/dev/null".to_owned(), |_| format!("a/{old_name}"));
        let new_side = pair
            .new
            .map_or_else(|| "/dev/null".to_owned(), |_| format!("b/{new_name}"));
        out.extend_from_slice(
            format!("Binary files {old_side} and {new_side} differ\n").as_bytes(),
        );
        return Ok((out, 0, 0));
    }
    if pair.old.is_none() {
        out.extend_from_slice(b"--- /dev/null\n");
    } else {
        out.extend_from_slice(format!("--- a/{old_name}\n").as_bytes());
    }
    if pair.new.is_none() {
        out.extend_from_slice(b"+++ /dev/null\n");
    } else {
        out.extend_from_slice(format!("+++ b/{new_name}\n").as_bytes());
    }
    if !content_changed {
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
    if let Some(radius) = context {
        let (added, removed) = emit_context_hunks(&mut out, &script, radius);
        return Ok((out, added, removed));
    }
    let mut hunk_start = 0;
    let mut old_line_number: usize = 1;
    let mut new_line_number: usize = 1;
    while hunk_start < script.len() {
        let hunk_end = script.len().min(hunk_start + 20);
        let range_old_start = old_line_number;
        let range_new_start = new_line_number;
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
        // Git numbers an empty side at the line before the hunk.
        let hunk_old_start = range_old_start.saturating_sub(usize::from(old_count == 0));
        let hunk_new_start = range_new_start.saturating_sub(usize::from(new_count == 0));
        out.extend_from_slice(
            format!(
                "@@ -{} +{} @@\n",
                hunk_range(hunk_old_start, old_count),
                hunk_range(hunk_new_start, new_count)
            )
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

/// Emits one window per change run with `radius` context lines, merging
/// windows whose gaps hold at most `2 * radius` unchanged lines, as git
/// does. Returns added/removed counts for `--stat`.
fn emit_context_hunks(out: &mut Vec<u8>, script: &[DiffOp<'_>], radius: usize) -> (usize, usize) {
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for (index, op) in script.iter().enumerate() {
        if matches!(op, DiffOp::Keep(_)) {
            continue;
        }
        let start = index.saturating_sub(radius);
        let end = (index + 1 + radius).min(script.len());
        match windows.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => windows.push((start, end)),
        }
    }
    let mut added = 0;
    let mut removed = 0;
    let mut old_number: usize = 1;
    let mut new_number: usize = 1;
    let mut cursor = 0;
    for (start, end) in windows {
        for op in &script[cursor..start] {
            match op {
                DiffOp::Keep(_) => {
                    old_number += 1;
                    new_number += 1;
                }
                DiffOp::Delete(_) => old_number += 1,
                DiffOp::Insert(_) => new_number += 1,
            }
        }
        let (mut old_count, mut new_count) = (0, 0);
        for op in &script[start..end] {
            match op {
                DiffOp::Keep(_) => {
                    old_count += 1;
                    new_count += 1;
                }
                DiffOp::Delete(_) => old_count += 1,
                DiffOp::Insert(_) => new_count += 1,
            }
        }
        // Git numbers an empty side at the line before the hunk (`-1,0`
        // for an insertion after line 1), not at the next live line.
        let old_start = if old_count == 0 {
            old_number.saturating_sub(1)
        } else {
            old_number
        };
        let new_start = if new_count == 0 {
            new_number.saturating_sub(1)
        } else {
            new_number
        };
        out.extend_from_slice(
            format!(
                "@@ -{} +{} @@\n",
                hunk_range(old_start, old_count),
                hunk_range(new_start, new_count)
            )
            .as_bytes(),
        );
        for op in &script[start..end] {
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
        old_number += old_count;
        new_number += new_count;
        cursor = end;
    }
    (added, removed)
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
    let specs = [
        FlagSpec {
            long: "is-ancestor",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
    ];
    let opts = collect_expanded(args, &specs)?;
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
        tips.push(resolve_local(store, kind, rev)?);
    }
    if opts.is_set("all") {
        let mut bases = vec![tips[0]];
        for tip in tips.iter().skip(1) {
            let mut next = Vec::new();
            for base in &bases {
                next.extend(merge_bases_all(store, *base, *tip)?);
            }
            bases = minimize_bases(store, next)?;
        }
        let mut out = Vec::new();
        for base in &bases {
            out.extend_from_slice(&line(base.to_hex().into_bytes()));
        }
        return Ok(out);
    }
    let mut base = tips[0];
    for tip in tips.iter().skip(1) {
        base = state_merge_base(store, base, *tip)?;
    }
    Ok(line(base.to_hex().into_bytes()))
}

/// Lists ancestry from tips, newest discovered first.
///
/// Oracle: `git/builtin/rev-list.c`. `--objects` prints each commit oid
/// plus every unseen blob as `<oid> <path>`; bare tree oids are omitted.
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
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "objects",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "parents",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "reverse",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "abbrev-commit",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect_expanded(&rewrite_dash_number(args), &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit = parse_max_count(&opts)?;
    let (mut tips, exclude) = parse_log_revs(store, kind, &opts.positionals, None)?;
    if opts.is_set("all") {
        tips.extend(all_ref_tips(store)?);
    }
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: rev-list [--count] <rev>...".to_owned(),
        });
    }
    let mut history = walk_history_excluding(store, &tips, &exclude, None)?;
    if let Some(max) = limit {
        history.truncate(max);
    }
    if opts.is_set("reverse") {
        history.reverse();
    }
    if opts.is_set("count") {
        return Ok(line(history.len().to_string().into_bytes()));
    }
    let abbrev = opts.is_set("abbrev-commit");
    let show_parents = opts.is_set("parents");
    let show_objects = opts.is_set("objects");
    let mut out = Vec::new();
    let mut seen_objects: HashSet<Oid> = HashSet::new();
    for (oid, record) in &history {
        let mut head_line = if abbrev { short_hex(oid) } else { oid.to_hex() };
        if show_parents {
            head_line.push_str(&parent_suffix(store, *oid, abbrev)?);
        }
        out.extend_from_slice(head_line.as_bytes());
        out.push(b'\n');
        if show_objects {
            let tree = commit_tree_oid(record)?;
            let mut blobs = flatten_tree(store, kind, tree)?;
            blobs.sort();
            for (path, _, blob) in blobs {
                if seen_objects.insert(blob) {
                    out.extend_from_slice(blob.to_hex().as_bytes());
                    out.push(b' ');
                    out.extend_from_slice(&path);
                    out.push(b'\n');
                }
            }
        }
    }
    Ok(out)
}

/// Renders the ` --parents` suffix: one leading space per parent oid,
/// shortened with `--abbrev-commit`.
fn parent_suffix(store: &Store, oid: Oid, abbrev: bool) -> Result<String, GitError> {
    let mut suffix = String::new();
    for parent in commit_parents(store, oid)? {
        suffix.push(' ');
        suffix.push_str(&if abbrev {
            short_hex(&parent)
        } else {
            parent.to_hex()
        });
    }
    Ok(suffix)
}

/// Resolves revisions and prints repository facts.
///
/// Oracle: `git/builtin/rev-parse.c`. `--git-dir` prints this store's
/// `.ruk` directory the way git prints `.git`: the documented analog, not
/// a relative path.
pub(crate) fn rev_parse(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "verify",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
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
            long: "is-bare-repository",
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
    let (args, short_len) = extract_short_len(args)?;
    let opts = collect_expanded(&args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("verify") && opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rev-parse --verify <rev>".to_owned(),
        });
    }
    let mut out = Vec::new();
    if opts.is_set("git-dir") {
        out.extend_from_slice(format!("{}/.ruk\n", ctx.root.display()).as_bytes());
    }
    if opts.is_set("show-toplevel") {
        if ctx.bare {
            return Err(GitError::Invalid {
                detail: "this operation must be run in a work tree".to_owned(),
            });
        }
        out.extend_from_slice(format!("{}\n", ctx.root.display()).as_bytes());
    }
    if opts.is_set("is-inside-work-tree") {
        out.extend_from_slice(if ctx.bare { b"false\n" } else { b"true\n" });
    }
    if opts.is_set("is-bare-repository") {
        out.extend_from_slice(if ctx.bare { b"true\n" } else { b"false\n" });
    }
    let short_len = short_len.or(opts.is_set("short").then_some(7));
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
        let oid = resolve_local(store, kind, rev)?;
        match short_len {
            None => out.extend_from_slice(format!("{}\n", oid.to_hex()).as_bytes()),
            Some(len) => {
                let hex = oid.to_hex();
                let end = len.min(hex.len());
                out.extend_from_slice(hex[..end].as_bytes());
                out.push(b'\n');
            }
        }
    }
    Ok(out)
}
