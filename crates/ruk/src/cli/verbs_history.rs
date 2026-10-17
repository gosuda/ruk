//! History verbs: `commit`, `merge`, `rebase`, `cherry-pick`, `revert`,
//! `log`, `show`, `diff`, `merge-base`, `rev-list`, `rev-parse`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `commit` | tree build + `ops::new`/`ops::edit` + branch move | implemented (multi `-m`, `-a`, `--amend`, `--allow-empty`, `-q`, `-C`/`-c`, `--author`, `--date`, `--dry-run`, `--no-verify` no-op) |
//! | `merge` | ancestor check + fast-forward | implemented (fast-forward only; content merge is `Unsupported`) |
//! | `rebase` | no-op detection | partial (up-to-date succeeds; replay is `Unsupported`) |
//! | `cherry-pick` | revision resolution | partial (sequencer readers real; content application is `Unsupported`; parses `-n`, `-m`, `-e`, `-x`, `--skip`) |
//! | `revert` | revision resolution | partial (same shape as `cherry-pick`; parses `-n`, `-m`, `-e`, `--skip`) |
//! | `log` | commit ancestry walk | implemented (oneline, format/pretty, ranges, paths, stat/patch, filters, decorate, graph) |
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
use ruk_core::conflict::Signature;
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{RepoPath, Stage};
use ruk_core::ops::{EditRequest, NewRequest, edit as ops_edit, new as ops_new};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::Store;
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    IdentityRole, commit_record, head_oid, identity, is_ancestor, list_refs, load_or_default,
    merge_base as state_merge_base, merged_rows, now_seconds, read_path_rows, read_ref,
    resolve_rev, scan_index, sequencer_read, walk_history, workspace_mutation,
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
    finish(format!("[{label} {}] {subject}\n", short_hex(&new_oid)).into_bytes())
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
        (None, _) => Ok(parts.join("\n\n")),
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
fn resolve_local(store: &Store, kind: HashKind, rev: &str) -> Result<Oid, GitError> {
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
    let tree = peel_to_tree(store, kind, oid)?;
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
fn parse_log_revs(
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

/// Walks `tips` newest-first while skipping `exclude` and everything
/// reachable from it, mirroring [`walk_history`] otherwise.
fn walk_history_excluding(
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
        if !seen.insert(oid) {
            continue;
        }
        let record = match records.get_commit(&Head::Git { oid }) {
            Ok(Some(record)) => record,
            _ => continue,
        };
        for parent in record.parents() {
            if let Some(parent_oid) = parent.as_git().copied() {
                stack.push(parent_oid);
            }
        }
    }
    let mut queue: Vec<Oid> = tips.to_vec();
    let mut out = Vec::new();
    while let Some(oid) = queue.pop() {
        if !seen.insert(oid) {
            continue;
        }
        let record = records
            .get_commit(&Head::Git { oid })
            .map_err(GitError::from)?
            .ok_or_else(|| GitError::NotFound {
                detail: format!("object {} is not a stored commit", oid.to_hex()),
            })?;
        for parent in record.parents() {
            if let Some(parent_oid) = parent.as_git().copied() {
                if !seen.contains(&parent_oid) {
                    queue.push(parent_oid);
                }
            }
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
    let month_index = usize::try_from(month - 1).expect("parsed month 1..=12 gives index 0..=11");
    format!(
        "{} {} {:02} {:02}:{:02}:{:02} {full_year} {offset}",
        WEEKDAYS[weekday],
        MONTHS[month_index],
        day,
        clock / 3_600,
        (clock % 3_600) / 60,
        clock % 60,
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
            "unknown placeholder %{letter} (supported: %H %h %s %an %ae %ad %cn %ce %cd %d %% %n)"
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

/// Renders parsed format parts for one commit. `decoration` is the `%d`
/// text including its leading space, or empty when undecorated.
fn render_log_format(
    parts: &[FormatPart],
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
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
                FormatField::ShortOid => out.extend_from_slice(short_hex(oid).as_bytes()),
                FormatField::Subject => {
                    out.extend_from_slice(first_subject_line(record.message()).as_bytes());
                }
                FormatField::AuthorName => out.extend_from_slice(author.name.as_bytes()),
                FormatField::AuthorEmail => out.extend_from_slice(author.email.as_bytes()),
                FormatField::AuthorDate => {
                    out.extend_from_slice(
                        format_git_date(author.timestamp, author.offset).as_bytes(),
                    );
                }
                FormatField::CommitterName => out.extend_from_slice(committer.name.as_bytes()),
                FormatField::CommitterEmail => out.extend_from_slice(committer.email.as_bytes()),
                FormatField::CommitterDate => {
                    out.extend_from_slice(
                        format_git_date(committer.timestamp, committer.offset).as_bytes(),
                    );
                }
                FormatField::Decoration => out.extend_from_slice(decoration.as_bytes()),
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
}

/// Renders one commit's identity line for `log` and `show`.
fn render_commit_line(
    line: &CommitLine,
    oid: &Oid,
    record: &CommitRecord,
    decoration: &str,
) -> Result<Vec<u8>, GitError> {
    if let Some(parts) = &line.format {
        let mut out = render_log_format(parts, oid, record, decoration)?;
        out.push(b'\n');
        return Ok(out);
    }
    if line.oneline {
        let subject = first_subject_line(record.message());
        return Ok(format!("{}{decoration} {subject}\n", short_hex(oid)).into_bytes());
    }
    let id = if line.abbrev {
        short_hex(oid)
    } else {
        oid.to_hex()
    };
    let mut out = format!("commit {id}{decoration}\n").into_bytes();
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    let author = record.author().map_err(|_| broken("author"))?;
    let committer = record.committer().map_err(|_| broken("committer"))?;
    out.extend_from_slice(b"Author: ");
    out.extend_from_slice(&author.render());
    out.push(b'\n');
    out.extend_from_slice(b"Commit: ");
    out.extend_from_slice(&committer.render());
    out.push(b'\n');
    out.push(b'\n');
    for message_line in record.message().split(|byte| *byte == b'\n') {
        out.extend_from_slice(b"    ");
        out.extend_from_slice(message_line);
        out.push(b'\n');
    }
    out.push(b'\n');
    Ok(out)
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
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("cherry-pick", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("cherry-pick", "continue");
    }
    if opts.is_set("skip") {
        return no_sequencer("cherry-pick", "skip");
    }
    check_mainline(&opts)?;
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
    if opts.is_set("abort") || opts.is_set("quit") {
        return no_sequencer("revert", "abort");
    }
    if opts.is_set("continue") {
        return no_sequencer("revert", "continue");
    }
    if opts.is_set("skip") {
        return no_sequencer("revert", "skip");
    }
    check_mainline(&opts)?;
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

/// Shows commit logs from tips, newest discovered first.
///
/// Oracle: `git/builtin/log.c` (`cmd_log`). Decorations stay off unless
/// `--decorate` is given: git's `auto` default shows them only on a
/// terminal, and this interpreter never renders to one.
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
    ];
    let (rev_args, path_args) = split_double_dash(args);
    let (rev_args, decorate_mode) = extract_decorate_arg(&rev_args)?;
    let opts = collect_expanded(&rewrite_dash_number(&rev_args), &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit = parse_max_count(&opts)?;
    let default_tip = head_oid(store).ok();
    let (mut tips, exclude) = parse_log_revs(store, kind, &opts.positionals, default_tip)?;
    if opts.is_set("all") {
        tips.extend(all_ref_tips(store)?);
    }
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: log [<options>] [<revision-range>] [[--] <path>...]".to_owned(),
        });
    }
    let since = parse_since_until(&opts, "since")?;
    let until = parse_since_until(&opts, "until")?;
    let author_want = opts.single("author")?;
    let wants: Vec<Vec<u8>> = path_args
        .iter()
        .map(|path| path.as_bytes().to_vec())
        .collect();
    let line = commit_line_of(&opts)?;
    let decorate = !opts.is_set("no-decorate")
        && (opts.is_set("decorate") || decorate_mode.as_deref().is_some_and(|mode| mode != "no"));
    let full_names = decorate_mode.as_deref() == Some("full");
    let decorations = if decorate || line.format.is_some() {
        decoration_map(store)?
    } else {
        HashMap::new()
    };
    let show_diffs = !opts.is_set("quiet")
        && (opts.is_set("patch")
            || opts.is_set("stat")
            || opts.is_set("name-only")
            || opts.is_set("name-status"));
    let mut shown: Vec<(Oid, CommitRecord)> = Vec::new();
    for (oid, record) in walk_history_excluding(store, &tips, &exclude, None)? {
        if !commit_passes_filters(
            store,
            kind,
            &record,
            since,
            until,
            author_want.as_deref(),
            &wants,
        )? {
            continue;
        }
        shown.push((oid, record));
        if limit.is_some_and(|max| shown.len() >= max) {
            break;
        }
    }
    if opts.is_set("reverse") {
        shown.reverse();
    }
    let graph = opts.is_set("graph");
    let mut out = Vec::new();
    for (oid, record) in &shown {
        let decoration = decoration_text(&decorations, oid, full_names);
        let mut block = render_commit_line(&line, oid, record, &decoration)?;
        if show_diffs {
            block.extend_from_slice(&log_commit_diff(ctx, store, oid, record, &opts)?);
        }
        if graph {
            block = graph_block(&block);
        }
        out.extend_from_slice(&block);
    }
    Ok(out)
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
/// `--oneline`/`--pretty`/`--format`/`--abbrev-commit`.
fn commit_line_of(opts: &super::Collected) -> Result<CommitLine, GitError> {
    let mut oneline = opts.is_set("oneline");
    let mut format = match opts.single("format")? {
        Some(text) => Some(parse_log_format(&text)?),
        None => None,
    };
    if format.is_none() {
        if let Some(text) = opts.single("pretty")? {
            if text == "oneline" {
                oneline = true;
            } else if ["short", "medium", "full", "fuller"].contains(&text.as_str()) {
                oneline = false;
            } else {
                format = parse_pretty_arg(&text)?;
            }
        }
    }
    Ok(CommitLine {
        oneline,
        format,
        abbrev: opts.is_set("abbrev-commit"),
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
fn log_commit_diff(
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
    let pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
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
    let pairs = tree_pairs(ctx, parent_tree, Some(tree))?;
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
    let pairs = match (rev, rev_b) {
        (Some(one), Some(two)) => {
            let old_tree = peel_to_tree(store, kind, resolve_local(store, kind, &one)?)?;
            let new_tree = peel_to_tree(store, kind, resolve_local(store, kind, &two)?)?;
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
        let (text, added, removed) = unified_pair(
            &pair.path,
            old_body.as_deref(),
            new_body.as_deref(),
            context,
        )?;
        hunks.push(CountedHunk {
            path: pair.path.clone(),
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

/// Diffs one path pair into unified text with added/removed counts,
/// collapsing unchanged runs to `context` lines around each change when
/// set. `None` keeps the historical show-everything form.
fn unified_pair(
    path: &[u8],
    old: Option<&[u8]>,
    new: Option<&[u8]>,
    context: Option<usize>,
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
    if let Some(radius) = context {
        let (added, removed) = emit_context_hunks(&mut out, &script, radius);
        return Ok((out, added, removed));
    }
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
            format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@\n").as_bytes(),
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
