//! Misc plumbing and user verbs: `clean`, `describe`, `reflog`, `shortlog`,
//! `check-mailmap`, `cherry`, `name-rev`, `check-ignore`, `check-attr`, `stripspace`,
//! `interpret-trailers`, `var`, `get-tar-commit-id`, `fmt-merge-msg`,
//! `verify-tag`, `verify-commit`, plus the leftover surface: `stage` and
//! `whatchanged` aliases, `show-index`, `unpack-objects`, `unpack-file`,
//! `mktag`, `bugreport`, `diagnose`, `for-each-repo`, `last-modified`,
//! the `filter-branch` refusal, and the named-gap stubs (`pack-redundant`,
//! `web--browse`, `mergetool`, `difftool`, `instaweb`, `imap-send`,
//! `send-email`, `send-pack`, `quiltimport`, `remote-http`/`https`/`ftp`/
//! `ftps`/`ext`/`fd`).
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `clean` | index scan vs worktree walk | implemented (`-f`/`-d`/`-n`/`-e`; `.rukignore` skipped by default, `-x` includes ignored, `-X` only ignored) |
//! | `describe` | breadth-first walk to the nearest tag | implemented (`--tags`/`--exact-match`/`--long`/`--abbrev`/`--always`) |
//! | `reflog` | `Reflogs` rows `update-ref -m` writes | implemented (`show`/`list`/`expire --expire=now|never|<N>.days.ago`/`delete <ref>@{n}`) |
//! | `shortlog` | ancestry walk grouped by author | implemented (`-s`/`-n`/`-e`, ranges; names and emails mapped through the mailmap) |
//! | `check-mailmap` | mailmap lookup | implemented (`<contact>...`, `--stdin`, `--mailmap-file`; `--mailmap-blob` is `Unsupported`) |
//! | `cherry` | tree-diff content patch-ids | implemented (`-v`, `upstream [head [base]]`; no whitespace normalization) |
//! | `name-rev` | multi-source breadth-first naming | implemented (`--tags`/`--name-only`/`--refs`) |
//! | `check-ignore` | `.rukignore` glob scan | implemented (no file means nothing ignored, exit 1) |
//! | `check-attr` | `.rukattributes` scan | implemented (absent file means every attr unspecified) |
//! | `stripspace` | stdin byte filter | implemented (`--strip-comments`) |
//! | `interpret-trailers` | trailer-block parse | implemented (`--only-trailers`/`--only-input`/`--unfold`/`--trailer`/`--where`) |
//! | `var` | identity/config facts | implemented (`GIT_AUTHOR_IDENT`, `GIT_COMMITTER_IDENT` through the mailmap, `GIT_DEFAULT_BRANCH`, `GIT_EDITOR`, `GIT_PAGER`, `-l`) |
//! | `get-tar-commit-id` | tar `comment` pax scan | implemented (stdin tar only) |
//! | `fmt-merge-msg` | `FETCH_HEAD` pseudo record | implemented (`-m`, `--log[=n]`/`--no-log`, `--stdin`/file) |
//! | `verify-tag` | structural check, honest refusal | partial (no signatures: always refuses after validating) |
//! | `verify-commit` | existence check, honest refusal | partial (no signatures: always refuses after validating) |
//! | `stage` | `add` forward | implemented (alias, same flags and errors) |
//! | `whatchanged` | `log` ranges walked, `show --raw` per non-merge tip | implemented (`-n`, ranges; no pathspecs) |
//! | `show-index` | v2 `.idx` parse from stdin/file | implemented (`<offset> <hex> <crc>` lines) |
//! | `unpack-objects` | pack ingest plus publication | implemented (`-n`/`--dry-run` verifies only) |
//! | `unpack-file` | blob spilled to `tmp-unpack-*` | implemented (blobs only) |
//! | `mktag` | stdin tag body validated and stored | implemented (`type` must name a kind) |
//! | `bugreport` | version/platform/config/refs/head dump | implemented (`-o`) |
//! | `diagnose` | bug report plus object census | implemented (`-o`) |
//! | `for-each-repo` | in-process dispatch per listed repo | implemented (repeatable `--config`, aborts on first failure) |
//! | `last-modified` | first-parent walk for the touching commit | implemented (`<oid>\t<path>` per path) |
//! | `filter-branch` | deprecated upstream | unsupported (loud refusal with alternatives) |
//! | `pack-redundant`, `web--browse`, `mergetool`, `difftool`, `instaweb`, `imap-send`, `send-email`, `send-pack`, `quiltimport`, `remote-http`, `remote-https`, `remote-ftp`, `remote-ftps`, `remote-ext`, `remote-fd` | no backing | unsupported (named gaps) |
//!
//! Oracle anchors: `git/builtin/clean.c`, `git/builtin/describe.c`,
//! `git/builtin/reflog.c`, `git/builtin/shortlog.c`, `git/mailmap.c`,
//! `git/builtin/check-mailmap.c`, `git/builtin/cherry.c`,
//! `git/builtin/name-rev.c`, `git/builtin/check-ignore.c`,
//! `git/builtin/check-attr.c`, `git/builtin/stripspace.c`,
//! `git/builtin/interpret-trailers.c`, `git/builtin/var.c`,
//! `git/builtin/get-tar-commit-id.c`, `git/builtin/fmt-merge-msg.c`,
//! `git/builtin/verify-tag.c`, `git/builtin/verify-commit.c`,
//! `git/builtin/add.c` (`stage`), `git/builtin/log.c` (`whatchanged`),
//! `git/builtin/show-index.c`, `git/builtin/unpack-objects.c`,
//! `git/builtin/unpack-file.c`, `git/builtin/mktag.c`,
//! `git/builtin/bugreport.c`, `git/builtin/diagnose.c`,
//! `git/builtin/for-each-repo.c`, `git/git-filter-branch.sh`,
//! `git/builtin/pack-redundant.c`, `git/git-web--browse.sh`,
//! `git/git-mergetool.sh`, `git/builtin/difftool.c`, `git/git-instaweb.sh`,
//! `git/builtin/imap-send.c`, `git/git-send-email.pl`,
//! `git/builtin/send-pack.c`, `git/git-quiltimport.sh`,
//! `git/remote-curl.c`, `git/builtin/remote-ext.c`,
//! `git/builtin/remote-fd.c`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use ruk_core::commit::CommitRecord;
use ruk_core::conflict::Signature;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::refs::{ReflogKey, StoreRefs, page_reflogs};
use ruk_core::store::{
    FactExpectation, FactMutation, FactPageBudget, FactTable, ObjectKind, Store,
};
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    IdentityRole, commit_record, head_oid, identity, list_refs, load_or_default,
    merge_base as state_merge_base, now_seconds, pseudo_read, read_ref, resolve_rev, scan_index,
};
use super::tree::{TreeMode, commit_tree_oid, flatten_tree, read_object_bytes, walk_worktree};
use super::verbs_history::{parse_log_revs, walk_history_excluding};
use super::{Ctx, FlagSpec, collect, line};

/// Expands grouped boolean shorts (`-sn` reads as `--summary --numbered`).
///
/// The shared [`collect`] takes one short per token, so verbs with several
/// boolean shorts expand first; tokens with unknown or valued letters pass
/// through for `collect` to reject or fill with its clearer errors.
fn expand_groups(args: &[String], specs: &[FlagSpec]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let expandable = match arg.strip_prefix('-') {
            Some(body)
                if !body.starts_with('-')
                    && body.len() > 1
                    && body.bytes().all(|byte| byte.is_ascii_alphanumeric()) =>
            {
                body.chars()
                    .map(|letter| specs.iter().find(|spec| spec.short == Some(letter)))
                    .collect::<Option<Vec<_>>>()
                    .is_some_and(|found| found.iter().all(|spec| !spec.takes_value))
            }
            _ => false,
        };
        if expandable {
            let body = &arg[1..];
            for letter in body.chars() {
                let spec = specs
                    .iter()
                    .find(|spec| spec.short == Some(letter))
                    .expect("checked above");
                out.push(format!("--{}", spec.long));
            }
            continue;
        }
        out.push(arg.clone());
    }
    out
}

/// Rewrites bare `-<N>` tokens to `--max-count=<N>`, the way the oracle's
/// shortlog/log limit reads a digit flag.
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

/// Shell-ish glob over UTF-8 text: `*`, `?`, `[...]` (with `a-z` ranges and
/// `!`/`^` negation), backslash escape. No `**` semantics: `*` crosses `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        match pattern[0] {
            b'*' => {
                let mut rest = &pattern[1..];
                while rest.first() == Some(&b'*') {
                    rest = &rest[1..];
                }
                (0..=text.len()).any(|index| go(rest, &text[index..]))
            }
            b'?' => !text.is_empty() && go(&pattern[1..], &text[1..]),
            b'[' => {
                let Some(end) = pattern.iter().position(|byte| *byte == b']') else {
                    return text.first() == Some(&b'[') && go(&pattern[1..], &text[1..]);
                };
                if text.is_empty() {
                    return false;
                }
                let mut class = &pattern[1..end];
                let mut negate = false;
                if class.first() == Some(&b'!') || class.first() == Some(&b'^') {
                    negate = true;
                    class = &class[1..];
                }
                let mut hit = false;
                let mut index = 0;
                while index < class.len() {
                    if index + 2 < class.len() && class[index + 1] == b'-' {
                        if (class[index]..=class[index + 2]).contains(&text[0]) {
                            hit = true;
                        }
                        index += 3;
                    } else {
                        if class[index] == text[0] {
                            hit = true;
                        }
                        index += 1;
                    }
                }
                (hit != negate) && go(&pattern[end + 1..], &text[1..])
            }
            b'\\' if pattern.len() > 1 => {
                text.first() == Some(&pattern[1]) && go(&pattern[2..], &text[1..])
            }
            byte => text.first() == Some(&byte) && go(&pattern[1..], &text[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Peels `oid` through tag objects to its commit, passing commits through.
fn peel_to_commit(store: &Store, mut oid: Oid) -> Result<Oid, GitError> {
    for _ in 0..32 {
        let (kind, body) = read_object_bytes(store, oid)?;
        match kind {
            ObjectKind::Commit => return Ok(oid),
            ObjectKind::Tag => {
                oid = tag_target_oid(&body)?;
            }
            _ => {
                return Err(GitError::NotFound {
                    detail: format!("object {} is not a commit", oid.to_hex()),
                });
            }
        }
    }
    Err(GitError::Invalid {
        detail: format!("tag chain past {} is too deep", oid.to_hex()),
    })
}

/// Reads the `object <hex>` line of one tag body.
fn tag_target_oid(body: &[u8]) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(body).map_err(|_| GitError::Corrupt {
        detail: "tag body is not utf-8".to_owned(),
    })?;
    for text_line in text.lines() {
        if let Some(hex) = text_line.strip_prefix("object ") {
            return Oid::from_hex(hex.trim()).map_err(|_| GitError::Corrupt {
                detail: "tag object line is not an object id".to_owned(),
            });
        }
    }
    Err(GitError::Corrupt {
        detail: "tag body has no object line".to_owned(),
    })
}

/// Resolves one revision and peels tags to the commit, for verbs that only
/// name commits (`describe`, `cherry`, `name-rev` inputs).
fn resolve_commit(store: &Store, kind: HashKind, rev: &str) -> Result<Oid, GitError> {
    let oid = resolve_rev(store, kind, rev)?;
    // `resolve_rev` already fails closed on non-commit suffix walks; a tag
    // object id still needs one peel step to its commit.
    match read_object_bytes(store, oid) {
        Ok((ObjectKind::Commit, _)) => Ok(oid),
        Ok((ObjectKind::Tag, _)) => peel_to_commit(store, oid),
        Ok(_) => Err(GitError::NotFound {
            detail: format!("{rev:?} is not a commit"),
        }),
        Err(err) => Err(err),
    }
}

/// Parent oids of one commit, in stored order.
fn parents_of(store: &Store, oid: Oid) -> Result<Vec<Oid>, GitError> {
    Ok(commit_record(store, oid)?
        .parents()
        .iter()
        .filter_map(Head::as_git)
        .copied()
        .collect())
}

// ---------------------------------------------------------------------------
// clean
// ---------------------------------------------------------------------------

/// Removes untracked worktree files.
///
/// Oracle: `git/builtin/clean.c`. Candidates skip `.rukignore` matches
/// unless `-x` widens the run to ignored paths too; `-X` keeps only
/// ignored paths. Without `-d`, files inside wholly-untracked directories
/// stay, the way the oracle refuses to descend into them.
pub(crate) fn clean(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "dir",
            short: Some('d'),
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
        FlagSpec {
            long: "ignored",
            short: Some('x'),
            takes_value: false,
        },
        FlagSpec {
            long: "only-ignored",
            short: Some('X'),
            takes_value: false,
        },
        FlagSpec {
            long: "exclude",
            short: Some('e'),
            takes_value: true,
        },
    ];
    let opts = collect(&expand_groups(args, &specs), &specs)?;
    ctx.require_worktree()?;
    let dry = opts.is_set("dry-run");
    let force = opts.is_set("force");
    if !force && !dry {
        return Err(GitError::Invalid {
            detail: "clean requires -f (use -n to preview)".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tracked: HashSet<Vec<u8>> = scan_index(store, kind)?
        .into_iter()
        .map(|(path, _, _)| path.as_bytes().to_vec())
        .collect();
    // Directories holding a tracked file are tracked; anything else is an
    // untracked directory the default run must not descend into.
    let mut tracked_dirs: HashSet<Vec<u8>> = HashSet::new();
    tracked_dirs.insert(Vec::new());
    for path in tracked.iter() {
        let mut dir = path.as_slice();
        while let Some(index) = dir.iter().rposition(|byte| *byte == b'/') {
            dir = &dir[..index];
            tracked_dirs.insert(dir.to_vec());
        }
    }
    let excludes = opts.all("exclude")?;
    let ignore_rules = load_ignore_rules(&ctx.file_base)?;
    let limits: Vec<Vec<u8>> = opts
        .positionals
        .iter()
        .map(|limit| limit.as_bytes().to_vec())
        .collect();
    let mut candidates: Vec<(Vec<u8>, bool)> = Vec::new();
    for entry in walk_worktree(&ctx.file_base)? {
        if tracked.contains(&entry.path) {
            continue;
        }
        if !under_limits(&entry.path, &limits) {
            continue;
        }
        if !opts.is_set("dir") && inside_untracked_dir(&entry.path, &tracked_dirs) {
            continue;
        }
        let text = String::from_utf8_lossy(&entry.path).into_owned();
        let base = text.rsplit('/').next().unwrap_or_default();
        if excludes
            .iter()
            .any(|pattern| glob_match(pattern, &text) || glob_match(pattern, base))
        {
            continue;
        }
        let ignored = path_is_ignored(&ignore_rules, &text).is_some();
        if ignored && !opts.is_set("ignored") && !opts.is_set("only-ignored") {
            continue;
        }
        candidates.push((entry.path, ignored));
    }
    // `-X` keeps only ignored paths.
    if opts.is_set("only-ignored") {
        candidates.retain(|(_, ignored)| *ignored);
    }
    candidates.sort();
    if dry {
        if opts.is_set("quiet") {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (path, _) in &candidates {
            out.extend_from_slice(b"Would remove ");
            out.extend_from_slice(path);
            out.push(b'\n');
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    let mut emptied: Vec<PathBuf> = Vec::new();
    for (path, _) in &candidates {
        let full = ctx.file_base.join(String::from_utf8_lossy(path).as_ref());
        match std::fs::remove_file(&full) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(GitError::Io {
                    detail: format!("removing {}: {err}", full.display()),
                });
            }
        }
        if let Some(parent) = full.parent() {
            emptied.push(parent.to_path_buf());
        }
        if !opts.is_set("quiet") {
            out.extend_from_slice(b"Removing ");
            out.extend_from_slice(path);
            out.push(b'\n');
        }
    }
    if opts.is_set("dir") {
        // Deepest first so newly-emptied parents cascade.
        emptied.sort_by(|left, right| right.components().count().cmp(&left.components().count()));
        emptied.dedup();
        for dir in emptied {
            if dir == ctx.file_base {
                continue;
            }
            let _ = std::fs::remove_dir(dir);
        }
    }
    Ok(out)
}

/// Reports whether `path` equals or lives under one of `limits` (empty
/// limits match everything).
fn under_limits(path: &[u8], limits: &[Vec<u8>]) -> bool {
    limits.is_empty()
        || limits.iter().any(|limit| {
            path == limit.as_slice()
                || (path.starts_with(limit.as_slice()) && path.get(limit.len()) == Some(&b'/'))
        })
}

/// Reports whether `path` lives under a directory holding no tracked file.
fn inside_untracked_dir(path: &[u8], tracked_dirs: &HashSet<Vec<u8>>) -> bool {
    match path.iter().rposition(|byte| *byte == b'/') {
        None => false,
        Some(index) => !tracked_dirs.contains(&path[..index]),
    }
}

// ---------------------------------------------------------------------------
// describe
// ---------------------------------------------------------------------------

/// One tag peeled to its commit. Only annotated tags are collected unless
/// `--tags` widens the set to lightweight ones.
struct TagTip {
    name: String,
    commit: Oid,
}

/// Describes a commit by its nearest reachable tag.
///
/// Oracle: `git/builtin/describe.c`. Distance is the breadth-first parent
/// depth, the same count the oracle's suffix prints; ties break by tag
/// name so repeated runs agree.
pub(crate) fn describe(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut abbrev: Option<usize> = None;
    for arg in args {
        if arg == "--abbrev" {
            abbrev = Some(7);
        } else if let Some(value) = arg.strip_prefix("--abbrev=") {
            abbrev = Some(value.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad --abbrev={value:?}: want a prefix length"),
            })?);
        } else {
            rewritten.push(arg.clone());
        }
    }
    let specs = [
        FlagSpec {
            long: "tags",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "exact-match",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "long",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "always",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(&rewritten, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rev = opts
        .positionals
        .first()
        .map(String::as_str)
        .unwrap_or("HEAD");
    if opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: describe [--tags] [--exact-match] [--long] [<rev>]".to_owned(),
        });
    }
    let tip = resolve_commit(store, kind, rev)?;
    let mut tags: Vec<TagTip> = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default().to_owned();
        let Some(short) = text.strip_prefix("refs/tags/") else {
            continue;
        };
        let RefTarget::Direct(oid) = target else {
            continue;
        };
        let (object_kind, _) = read_object_bytes(store, oid)?;
        if object_kind == ObjectKind::Tag {
            if let Ok(commit) = peel_to_commit(store, oid) {
                tags.push(TagTip {
                    name: short.to_owned(),
                    commit,
                });
            }
        } else if opts.is_set("tags") && commit_record(store, oid).is_ok() {
            tags.push(TagTip {
                name: short.to_owned(),
                commit: oid,
            });
        }
    }
    let by_commit: HashMap<Oid, Vec<&TagTip>> = {
        let mut map: HashMap<Oid, Vec<&TagTip>> = HashMap::new();
        for tag in &tags {
            map.entry(tag.commit).or_default().push(tag);
        }
        map
    };
    // Breadth-first parent walk from the tip: the first depth holding a
    // tag is the nearest, whatever the date order says.
    let mut depth_of: HashMap<Oid, usize> = HashMap::new();
    let mut queue: VecDeque<Oid> = VecDeque::new();
    depth_of.insert(tip, 0);
    queue.push_back(tip);
    let mut found: Option<(usize, Vec<String>)> = None;
    while let Some(oid) = queue.pop_front() {
        let depth = depth_of[&oid];
        if found.as_ref().is_some_and(|(best, _)| depth > *best) {
            break;
        }
        if let Some(tips) = by_commit.get(&oid) {
            let mut names: Vec<String> = tips.iter().map(|tag| tag.name.clone()).collect();
            names.sort();
            names.dedup();
            match &mut found {
                Some((_, acc)) => {
                    for name in names {
                        if !acc.contains(&name) {
                            acc.push(name);
                        }
                    }
                    acc.sort();
                }
                None => found = Some((depth, names)),
            }
        }
        if found.as_ref().is_some_and(|(best, _)| depth >= *best) {
            continue;
        }
        for parent in parents_of(store, oid)? {
            if !depth_of.contains_key(&parent) {
                depth_of.insert(parent, depth + 1);
                queue.push_back(parent);
            }
        }
    }
    let abbrev_len = abbrev.unwrap_or(7);
    if abbrev_len == 0 {
        return Err(GitError::Invalid {
            detail: "bad --abbrev=0: want a prefix length".to_owned(),
        });
    }
    let short_of = |oid: &Oid| {
        let hex = oid.to_hex();
        hex[..abbrev_len.min(hex.len())].to_owned()
    };
    match found {
        None => {
            if opts.is_set("always") {
                return Ok(line(short_of(&tip).into_bytes()));
            }
            Err(GitError::NotFound {
                detail: format!("no tag describes {}", tip.to_hex()),
            })
        }
        Some((depth, mut names)) => {
            names.sort();
            let name = names.remove(0);
            if opts.is_set("exact-match") && depth != 0 {
                return Err(GitError::NotFound {
                    detail: format!("no tag exactly matches {}", tip.to_hex()),
                });
            }
            if depth == 0 && !opts.is_set("long") {
                return Ok(line(name.into_bytes()));
            }
            Ok(line(
                format!("{name}-{depth}-g{}", short_of(&tip)).into_bytes(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// reflog
// ---------------------------------------------------------------------------

/// Resolves a reflog ref spelling: full names, `HEAD`, and branch shorts.
fn reflog_name(store: &Store, spelling: &str) -> Result<RefName, GitError> {
    if spelling == "HEAD" {
        let (workspace, _) = load_or_default(store)?;
        return match workspace.head {
            HeadRef::Symbolic(name) => Ok(name),
            HeadRef::Detached(_) => Err(GitError::Invalid {
                detail: "HEAD is detached: name the ref explicitly".to_owned(),
            }),
        };
    }
    if let Ok(name) = RefName::new(spelling.to_owned()) {
        if super::state::read_ref(store, &name)?.is_some() || has_reflogs(store, &name)? {
            return Ok(name);
        }
    }
    let full = format!("refs/heads/{spelling}");
    RefName::new(full.clone()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })
}

/// Reports whether any reflog row exists for `name`.
fn has_reflogs(store: &Store, name: &RefName) -> Result<bool, GitError> {
    let page = page_reflogs(store, name, None, 1).map_err(GitError::from)?;
    Ok(!page.entries.is_empty())
}

/// Reads every reflog entry for `name`, oldest first.
fn read_reflog_all(
    store: &Store,
    name: &RefName,
) -> Result<Vec<ruk_core::refs::ReflogEntry>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<ReflogKey> = None;
    loop {
        let page = page_reflogs(store, name, after.as_ref(), 256).map_err(GitError::from)?;
        let more = page.more;
        out.extend(page.entries);
        if !more {
            return Ok(out);
        }
        after = out.last().map(|entry| entry.key.clone());
    }
}

/// Deletes one reflog row by key.
fn delete_reflog_key(store: &Store, key: &ReflogKey) -> Result<(), GitError> {
    let bytes = key.encode();
    let Some(raw) = store.fact(FactTable::Reflogs, &bytes)? else {
        return Err(GitError::NotFound {
            detail: "reflog entry is already gone".to_owned(),
        });
    };
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Reflogs,
                key: bytes,
                expected: FactExpectation::Value(raw),
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Shows, lists, expires, and deletes reflog rows.
///
/// Oracle: `git/builtin/reflog.c`. Only the rows `update-ref -m` writes
/// exist: branch moves from other verbs record none, so a ref with no
/// `-m` history shows empty instead of a synthesized past.
pub(crate) fn reflog(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let (sub, rest) = match args.first().map(String::as_str) {
        Some(word @ ("show" | "list" | "expire" | "delete")) => (word, &args[1..]),
        Some(word) if !word.starts_with('-') => {
            return Err(GitError::Invalid {
                detail: format!("unknown reflog subcommand {word:?}: want show|list|expire|delete"),
            });
        }
        _ => ("show", &args[..]),
    };
    match sub {
        "show" => reflog_show(ctx, rest),
        "list" => reflog_list(ctx, rest),
        "expire" => reflog_expire(ctx, rest),
        "delete" => reflog_delete(ctx, rest),
        _ => unreachable!(),
    }
}

/// Prints one ref's reflog, newest first: `<new> <ref>@{<n>}: <message>`.
fn reflog_show(ctx: &Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "max-count",
        short: Some('n'),
        takes_value: true,
    }];
    let opts = collect(&rewrite_dash_number(args), &specs)?;
    let store = ctx.store()?;
    let spelling = opts
        .positionals
        .first()
        .map(String::as_str)
        .unwrap_or("HEAD");
    if opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: reflog show [-n <n>] [<ref>]".to_owned(),
        });
    }
    let name = reflog_name(store, spelling)?;
    let limit: Option<usize> = match opts.single("max-count")? {
        None => None,
        Some(text) => Some(text.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad -n value {text:?}"),
        })?),
    };
    let mut entries = read_reflog_all(store, &name)?;
    if entries.is_empty() {
        return Err(GitError::NotFound {
            detail: format!("no reflog for {}", name.to_utf8().unwrap_or_default()),
        });
    }
    entries.reverse();
    if let Some(max) = limit {
        entries.truncate(max);
    }
    let shown = name.to_utf8().unwrap_or_default();
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let new_hex = entry
            .record
            .new_oid
            .map(|oid| oid.to_hex())
            .unwrap_or_else(|| "(deleted)".to_owned());
        let short: String = if new_hex == "(deleted)" {
            new_hex.clone()
        } else {
            new_hex.chars().take(7).collect()
        };
        let message = String::from_utf8_lossy(entry.record.message.as_bytes());
        out.extend_from_slice(format!("{short} {shown}@{{{index}}}: {message}\n").as_bytes());
    }
    Ok(out)
}

/// Lists every ref holding at least one reflog row.
fn reflog_list(ctx: &Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if !args.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: reflog list".to_owned(),
        });
    }
    let store = ctx.store()?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = store.fact_page(
            FactTable::Reflogs,
            after.as_deref(),
            FactPageBudget::new(1024, 1 << 20),
        )?;
        if page.rows.is_empty() {
            break;
        }
        for row in &page.rows {
            let key = ReflogKey::decode(&row.key).map_err(|err| GitError::Corrupt {
                detail: format!("reflog key does not decode: {err}"),
            })?;
            *counts
                .entry(key.name.to_utf8().unwrap_or_default().to_owned())
                .or_default() += 1;
        }
        if !page.more {
            break;
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
    let mut out = Vec::new();
    for (name, count) in &counts {
        out.extend_from_slice(format!("{name} ({count})\n").as_bytes());
    }
    Ok(out)
}

/// Expires reflog rows by committer age.
///
/// Oracle: `git/builtin/reflog.c` (`cmd_reflog_expire`). Supported
/// `--expire` values are `now`/`all` (drop everything), `never` (drop
/// nothing), and `<N>.days|weeks|hours.ago`; a bare `expire` drops rows
/// older than 90 days. Reachability is not consulted: the store keeps no
/// per-entry reachability flag, so age alone decides.
fn reflog_expire(ctx: &Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "expire",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dry-run",
            short: Some('n'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let cutoff = match opts.single("expire")?.as_deref() {
        None => now_seconds()? - 90 * 86_400,
        Some("now") | Some("all") => i64::MAX,
        Some("never") => return Ok(Vec::new()),
        Some(value) => parse_expire_ago(value)?,
    };
    let mut names: Vec<RefName> = Vec::new();
    if opts.is_set("all") {
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: reflog expire [--expire=<when>] [--all | <ref>]".to_owned(),
            });
        }
        let mut seen: HashSet<String> = HashSet::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = store.fact_page(
                FactTable::Reflogs,
                after.as_deref(),
                FactPageBudget::new(1024, 1 << 20),
            )?;
            if page.rows.is_empty() {
                break;
            }
            for row in &page.rows {
                let key = ReflogKey::decode(&row.key).map_err(|err| GitError::Corrupt {
                    detail: format!("reflog key does not decode: {err}"),
                })?;
                let text = key.name.to_utf8().unwrap_or_default().to_owned();
                if seen.insert(text) {
                    names.push(key.name.clone());
                }
            }
            if !page.more {
                break;
            }
            after = page.rows.last().map(|row| row.key.clone());
        }
    } else {
        let spelling = opts
            .positionals
            .first()
            .map(String::as_str)
            .unwrap_or("HEAD");
        if opts.positionals.len() > 1 {
            return Err(GitError::Invalid {
                detail: "usage: reflog expire [--expire=<when>] [--all | <ref>]".to_owned(),
            });
        }
        names.push(reflog_name(store, spelling)?);
    }
    for name in &names {
        for entry in read_reflog_all(store, name)? {
            if entry.record.committer.timestamp < cutoff {
                if opts.is_set("dry-run") {
                    continue;
                }
                delete_reflog_key(store, &entry.key)?;
            }
        }
    }
    Ok(Vec::new())
}

/// Parses `<N>.days|weeks|hours.ago` into a cutoff timestamp.
fn parse_expire_ago(value: &str) -> Result<i64, GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad --expire={value:?}: want now|never|all|<N>.days.ago"),
    };
    let (count_text, unit) = value
        .strip_suffix(".ago")
        .and_then(|bare| bare.rsplit_once('.'))
        .ok_or_else(bad)?;
    let count: i64 = count_text.parse().map_err(|_| bad())?;
    let span = match unit {
        "day" | "days" => 86_400,
        "week" | "weeks" => 7 * 86_400,
        "hour" | "hours" => 3_600,
        _ => return Err(bad()),
    };
    Ok(now_seconds()? - count.saturating_mul(span))
}

/// Deletes one reflog entry by `ref@{n}` selector, newest first.
fn reflog_delete(ctx: &Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if args.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: reflog delete <ref>@{<n>}".to_owned(),
        });
    }
    let store = ctx.store()?;
    let (spelling, index) = args[0]
        .rsplit_once("@{")
        .and_then(|(name, tail)| {
            tail.strip_suffix('}')
                .and_then(|digits| digits.parse::<usize>().ok().map(|n| (name, n)))
        })
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad selector {:?}: want <ref>@{{<n>}}", args[0]),
        })?;
    let name = reflog_name(store, spelling)?;
    let mut entries = read_reflog_all(store, &name)?;
    entries.reverse();
    let entry = entries.get(index).ok_or_else(|| GitError::NotFound {
        detail: format!("{} has no entry @{{{index}}}", args[0]),
    })?;
    delete_reflog_key(store, &entry.key)?;
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// shortlog
// ---------------------------------------------------------------------------

/// Groups history by author.
///
/// Oracle: `git/builtin/shortlog.c`. Reads revisions only (no stdin mode):
/// the default tip is `HEAD`, with the same range spellings as `log`.
pub(crate) fn shortlog(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "summary",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "numbered",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "email",
            short: Some('e'),
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "max-count",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(&expand_groups(&rewrite_dash_number(args), &specs), &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit: Option<usize> = match opts.single("max-count")? {
        None => None,
        Some(text) => Some(text.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad --max-count={text:?}"),
        })?),
    };
    let default_tip = head_oid(store).ok();
    let (mut tips, exclude) = parse_log_revs(store, kind, &opts.positionals, default_tip)?;
    if opts.is_set("all") {
        for (_, target) in list_refs(store)? {
            if let Some(oid) = peel_target_commit(store, Some(target))? {
                if commit_record(store, oid).is_ok() {
                    tips.push(oid);
                }
            }
        }
    }
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: shortlog [-s] [-n] [-e] [<revision-range>]".to_owned(),
        });
    }
    let history = walk_history_excluding(store, &tips, &exclude, limit)?;
    let mailmap = load_mailmap(ctx);
    // Groups in first-seen order; `-n` re-sorts by count, else by key.
    let mut order: Vec<String> = Vec::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut subjects: HashMap<String, Vec<String>> = HashMap::new();
    for (_, record) in &history {
        let author = record.author().map_err(|err| GitError::Corrupt {
            detail: format!("commit author does not decode: {err}"),
        })?;
        let stored_name = String::from_utf8_lossy(author.name.as_bytes());
        let stored_email = String::from_utf8_lossy(author.email.as_bytes());
        let (name, email) = mailmap
            .map_ident(&stored_name, &stored_email)
            .unwrap_or((stored_name.into_owned(), stored_email.into_owned()));
        let key = if opts.is_set("email") {
            format!("{name} <{email}>")
        } else {
            name
        };
        if !counts.contains_key(&key) {
            order.push(key.clone());
        }
        *counts.entry(key.clone()).or_default() += 1;
        let subject = String::from_utf8_lossy(record.message())
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        subjects.entry(key).or_default().push(subject);
    }
    if opts.is_set("numbered") {
        order.sort_by(|left, right| {
            counts[right]
                .cmp(&counts[left])
                .then_with(|| left.cmp(right))
        });
    } else {
        order.sort();
    }
    let mut out = Vec::new();
    for key in &order {
        let count = counts[key];
        if opts.is_set("summary") {
            out.extend_from_slice(format!("{count:>7}\t{key}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{key} ({count}):\n").as_bytes());
            for subject in &subjects[key] {
                out.extend_from_slice(format!("      {subject}\n").as_bytes());
            }
            out.push(b'\n');
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// mailmap
// ---------------------------------------------------------------------------

/// One email-keyed mailmap entry: the simple mapping plus the
/// name-qualified sub-entries, mirroring `struct mailmap_entry` in
/// `git/mailmap.c`.
#[derive(Clone, Debug, Default)]
pub(crate) struct MailmapEntry {
    /// Simple-entry replacement name.
    name: Option<String>,
    /// Simple-entry replacement email.
    email: Option<String>,
    /// `(lowercased old name, replacement name, replacement email)` rows.
    names: Vec<(String, Option<String>, Option<String>)>,
}

/// The parsed mailmap: `(lowercased old email, entry)` rows in file order.
/// Later files override earlier ones through [`Mailmap::merge`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Mailmap {
    entries: Vec<(String, MailmapEntry)>,
}

impl Mailmap {
    /// Parses mailmap text the way `read_mailmap_string` does: `#`
    /// comments and lines without a `<...>` pair contribute nothing.
    #[must_use]
    pub(crate) fn parse(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            out.add_line(line);
        }
        out
    }

    /// Folds one line into the map, mirroring `read_mailmap_line` plus
    /// `add_mapping`: `Proper <proper> Commit <commit>` maps the pair,
    /// `Proper <proper> <commit>` and `<proper> <commit>` map the email,
    /// and a lone `Proper <proper>` canonicalizes that email's name.
    fn add_line(&mut self, line: &str) {
        if line.starts_with('#') {
            return;
        }
        let Some((name1, email1, rest)) = split_mailmap_pair(line) else {
            return;
        };
        if email1.is_empty() {
            return;
        }
        let (name2, email2) = match rest {
            None => (None, None),
            Some(tail) => match split_mailmap_pair(tail) {
                Some((name, email, _)) if !email.is_empty() => (name, Some(email)),
                _ => return,
            },
        };
        let (new_name, new_email, old_name, old_email) = match email2 {
            Some(old) => (name1, Some(email1), name2, old),
            None => (name1, None, None, email1),
        };
        let key = old_email.to_lowercase();
        let entry = match self.entries.iter_mut().find(|(email, _)| *email == key) {
            Some((_, entry)) => entry,
            None => {
                self.entries.push((key, MailmapEntry::default()));
                &mut self.entries.last_mut().expect("mailmap entry just pushed").1
            }
        };
        match old_name {
            Some(old) if !old.is_empty() => {
                let lower = old.to_lowercase();
                match entry.names.iter_mut().find(|(name, _, _)| *name == lower) {
                    Some(row) => *row = (lower, new_name, new_email),
                    None => entry.names.push((lower, new_name, new_email)),
                }
            }
            _ => {
                if new_name.is_some() {
                    entry.name = new_name;
                }
                if new_email.is_some() {
                    entry.email = new_email;
                }
            }
        }
    }

    /// Folds another mailmap's rows in, later rows winning per key.
    fn merge(&mut self, other: &Self) {
        for (key, entry) in &other.entries {
            match self.entries.iter_mut().find(|(email, _)| email == key) {
                Some((_, slot)) => {
                    if entry.name.is_some() {
                        slot.name.clone_from(&entry.name);
                    }
                    if entry.email.is_some() {
                        slot.email.clone_from(&entry.email);
                    }
                    for row in &entry.names {
                        match slot.names.iter_mut().find(|(name, _, _)| *name == row.0) {
                            Some(slot_row) => *slot_row = row.clone(),
                            None => slot.names.push(row.clone()),
                        }
                    }
                }
                None => self.entries.push((key.clone(), entry.clone())),
            }
        }
    }

    /// Maps one `(name, email)` pair, mirroring `map_user`: the email
    /// matches case-insensitively, then a name-qualified row wins when the
    /// name matches too, else the simple row applies. Returns `None` when
    /// no row maps the pair. Display-only: callers never store the result.
    #[must_use]
    pub(crate) fn map_ident(&self, name: &str, email: &str) -> Option<(String, String)> {
        let entry = self
            .entries
            .iter()
            .find(|(key, _)| *key == email.to_lowercase())
            .map(|(_, entry)| entry)?;
        if !entry.names.is_empty() {
            if let Some((_, new_name, new_email)) = entry
                .names
                .iter()
                .find(|(old, _, _)| *old == name.to_lowercase())
            {
                if new_name.is_none() && new_email.is_none() {
                    return None;
                }
                return Some((
                    new_name.clone().unwrap_or_else(|| name.to_owned()),
                    new_email.clone().unwrap_or_else(|| email.to_owned()),
                ));
            }
        }
        if entry.name.is_none() && entry.email.is_none() {
            return None;
        }
        Some((
            entry.name.clone().unwrap_or_else(|| name.to_owned()),
            entry.email.clone().unwrap_or_else(|| email.to_owned()),
        ))
    }
}

/// Splits one `Name <email>` pair: the name is the trimmed text before
/// `<` (`None` when empty), the email is the text to the first `>`, and
/// the rest is the trailing text when non-empty.
fn split_mailmap_pair(text: &str) -> Option<(Option<String>, String, Option<&str>)> {
    let left = text.find('<')?;
    let after = &text[left + 1..];
    let right = after.find('>')?;
    let name = text[..left].trim();
    let email = after[..right].trim().to_owned();
    let rest = after[right + 1..].trim_start();
    Some((
        (!name.is_empty()).then(|| name.to_owned()),
        email,
        (!rest.is_empty()).then_some(rest),
    ))
}

/// Splits a `check-mailmap` contact into `(name, email)`: `Name <email>`
/// pairs split on the brackets, anything else is a bare email with no
/// name, mirroring the oracle's `split_ident_line` fallback.
#[must_use]
pub(crate) fn split_contact(text: &str) -> (String, String) {
    let trimmed = text.trim();
    match split_mailmap_pair(trimmed) {
        Some((name, email, _)) if !email.is_empty() => (name.unwrap_or_default(), email),
        _ => (String::new(), trimmed.to_owned()),
    }
}

/// Renders one mapped contact the way `check_mailmap` prints: the name
/// and a space only when a name is present.
#[must_use]
pub(crate) fn render_contact(name: &str, email: &str) -> Vec<u8> {
    if name.is_empty() {
        format!("<{email}>\n").into_bytes()
    } else {
        format!("{name} <{email}>\n").into_bytes()
    }
}

/// Loads the mailmap for one command: `.mailmap` at the root, then
/// `.ruk/mailmap`, then the `mailmap.file` config path, later files
/// overriding earlier ones. Missing or unreadable files read as empty
/// instead of failing the command they annotate.
#[must_use]
pub(crate) fn load_mailmap(ctx: &Ctx) -> Mailmap {
    let mut out = Mailmap::default();
    for candidate in [
        ctx.root.join(".mailmap"),
        ctx.root.join(".ruk").join("mailmap"),
    ] {
        if let Ok(bytes) = std::fs::read(&candidate) {
            out.merge(&Mailmap::parse(&String::from_utf8_lossy(&bytes)));
        }
    }
    if let Some(path) = ctx.config_get("mailmap.file") {
        let candidate = if std::path::Path::new(&path).is_absolute() {
            PathBuf::from(path)
        } else {
            ctx.root.join(path)
        };
        if let Ok(bytes) = std::fs::read(&candidate) {
            out.merge(&Mailmap::parse(&String::from_utf8_lossy(&bytes)));
        }
    }
    out
}

/// Prints the canonical form of each contact through the mailmap.
///
/// Oracle: `git/builtin/check-mailmap.c`. Contacts are `Name <email>`
/// pairs or bare emails, from argv plus `--stdin` lines; `--mailmap-file`
/// appends one more mailmap layer, while `--mailmap-blob` is `Unsupported`.
pub(crate) fn check_mailmap(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "mailmap-file",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "mailmap-blob",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.is_set("mailmap-blob") {
        return Err(GitError::Unsupported {
            command: "check-mailmap --mailmap-blob is not supported".to_owned(),
        });
    }
    let mut mailmap = load_mailmap(ctx);
    if let Some(path) = opts.single("mailmap-file")? {
        let bytes = std::fs::read(&path).map_err(|err| GitError::Io {
            detail: format!("cannot read mailmap file {path:?}: {err}"),
        })?;
        mailmap.merge(&Mailmap::parse(&String::from_utf8_lossy(&bytes)));
    }
    let mut contacts: Vec<String> = opts.positionals.clone();
    if opts.is_set("stdin") {
        let input = super::read_stdin_bytes(&ctx.env)?;
        contacts.extend(
            String::from_utf8_lossy(&input)
                .lines()
                .map(str::to_owned),
        );
    }
    if contacts.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: check-mailmap [--stdin] [--mailmap-file=<file>] <contact>...".to_owned(),
        });
    }
    let mut out = Vec::new();
    for contact in &contacts {
        let (name, email) = split_contact(contact);
        let (name, email) = mailmap
            .map_ident(&name, &email)
            .unwrap_or((name, email));
        out.extend_from_slice(&render_contact(&name, &email));
    }
    Ok(out)
}

/// Follows one optional ref target to its commit, peeling tag objects.
fn peel_target_commit(store: &Store, target: Option<RefTarget>) -> Result<Option<Oid>, GitError> {
    let mut current = target;
    for _ in 0..16 {
        match current {
            None => return Ok(None),
            Some(RefTarget::Direct(oid)) => match read_object_bytes(store, oid) {
                Ok((ObjectKind::Commit, _)) => return Ok(Some(oid)),
                Ok((ObjectKind::Tag, body)) => match tag_target_oid(&body) {
                    Ok(next) => {
                        current = Some(RefTarget::Direct(next));
                    }
                    Err(_) => return Ok(None),
                },
                _ => return Ok(None),
            },
            Some(RefTarget::Symbolic(name)) => {
                let resolved =
                    ruk_core::refdata::resolve(&StoreRefs::new(store), &name).map_err(|err| {
                        GitError::Invalid {
                            detail: format!("bad ref chain: {err}"),
                        }
                    })?;
                match resolved.oid {
                    None => return Ok(None),
                    Some(oid) => current = Some(RefTarget::Direct(oid)),
                }
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// cherry
// ---------------------------------------------------------------------------

/// The content patch-id of one commit: a stable hash of its tree diff.
///
/// Both sides of each changed path contribute their full bytes, so the
/// same textual change from the same base hashes the same; rebased or
/// whitespace-mangled equivalents do not. Documented subset of the
/// oracle's whitespace-normalized `patch-id`.
fn patch_id(store: &Store, kind: HashKind, record: &CommitRecord) -> Result<String, GitError> {
    let new_tree = commit_tree_oid(record)?;
    let new_map: BTreeMap<Vec<u8>, (TreeMode, Oid)> = flatten_tree(store, kind, new_tree)?
        .into_iter()
        .map(|(path, mode, oid)| (path, (mode, oid)))
        .collect();
    let old_map: BTreeMap<Vec<u8>, (TreeMode, Oid)> = match record
        .parents()
        .iter()
        .filter_map(Head::as_git)
        .copied()
        .next()
    {
        None => BTreeMap::new(),
        Some(parent) => flatten_tree(
            store,
            kind,
            commit_tree_oid(&commit_record(store, parent)?)?,
        )?
        .into_iter()
        .map(|(path, mode, oid)| (path, (mode, oid)))
        .collect(),
    };
    let mut keys: Vec<&Vec<u8>> = new_map.keys().chain(old_map.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut canonical = Vec::new();
    for key in keys {
        let old = old_map.get(key);
        let new = new_map.get(key);
        if old == new {
            continue;
        }
        canonical.extend_from_slice(b"path:");
        canonical.extend_from_slice(key);
        canonical.push(0);
        for side in [old, new] {
            match side {
                None => canonical.extend_from_slice(b"absent\0"),
                Some((mode, oid)) => {
                    let bytes = if *mode == TreeMode::Gitlink {
                        oid.to_hex().into_bytes()
                    } else {
                        read_object_bytes(store, *oid)?.1
                    };
                    canonical.extend_from_slice(bytes.as_slice());
                    canonical.push(0);
                }
            }
        }
    }
    kind.hash_git_object("blob", &canonical)
        .map(|oid| oid.to_hex())
        .map_err(|err| GitError::Invalid {
            detail: format!("patch-id hash failed: {err}"),
        })
}

/// Compares upstream against head by patch-id.
///
/// Oracle: `git/builtin/cherry.c`. `+` marks head-only changes, `-` marks
/// changes the upstream side already carries. Merge commits compare
/// against their first parent.
pub(crate) fn cherry(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut abbrev: Option<usize> = None;
    for arg in args {
        if arg == "--abbrev" {
            abbrev = Some(7);
        } else if let Some(value) = arg.strip_prefix("--abbrev=") {
            abbrev = Some(value.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad --abbrev={value:?}: want a prefix length"),
            })?);
        } else {
            rewritten.push(arg.clone());
        }
    }
    let specs = [FlagSpec {
        long: "verbose",
        short: Some('v'),
        takes_value: false,
    }];
    let opts = collect(&rewritten, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (upstream_rev, head_rev, base_rev) = match opts.positionals.as_slice() {
        [upstream] => (upstream.as_str(), "HEAD", None),
        [upstream, head] => (upstream.as_str(), head.as_str(), None),
        [upstream, head, base] => (upstream.as_str(), head.as_str(), Some(base.as_str())),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: cherry [-v] <upstream> [<head> [<base>]]".to_owned(),
            });
        }
    };
    let upstream = resolve_commit(store, kind, upstream_rev)?;
    let head = resolve_commit(store, kind, head_rev)?;
    let base = match base_rev {
        Some(rev) => Some(resolve_commit(store, kind, rev)?),
        None => state_merge_base(store, upstream, head).ok(),
    };
    let (head_only, up_only) = match base {
        Some(root) => (
            walk_history_excluding(store, &[head], &[root], None)?,
            walk_history_excluding(store, &[upstream], &[root], None)?,
        ),
        // Disjoint histories: compare each tip's full past, the way the
        // oracle falls back when no merge base exists.
        None => (
            walk_history_excluding(store, &[head], &[upstream], None)?,
            walk_history_excluding(store, &[upstream], &[head], None)?,
        ),
    };
    let mut up_ids: HashSet<String> = HashSet::new();
    for (_, record) in &up_only {
        up_ids.insert(patch_id(store, kind, record)?);
    }
    let abbrev_len = abbrev.unwrap_or(40);
    if abbrev_len == 0 {
        return Err(GitError::Invalid {
            detail: "bad --abbrev=0: want a prefix length".to_owned(),
        });
    }
    // Oldest first, the oracle's print order.
    let mut ordered = head_only;
    ordered.reverse();
    let mut out = Vec::new();
    for (oid, record) in &ordered {
        let mark = if up_ids.contains(&patch_id(store, kind, record)?) {
            '-'
        } else {
            '+'
        };
        let hex = oid.to_hex();
        let shown = &hex[..abbrev_len.min(hex.len())];
        if opts.is_set("verbose") {
            let subject = String::from_utf8_lossy(record.message())
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            out.extend_from_slice(format!("{mark} {shown} {subject}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{mark} {shown}\n").as_bytes());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// name-rev
// ---------------------------------------------------------------------------

/// Names commits by the nearest ref containing them.
///
/// Oracle: `git/builtin/name-rev.c`. Every tip starts at distance zero and
/// parents cost one, so the first name to reach a commit is its nearest;
/// exact ties break by ref name. Branches print short, tags as `tags/<t>`.
pub(crate) fn name_rev(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "tags",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "refs",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: name-rev [--tags] [--name-only] <rev>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let patterns = opts.all("refs")?;
    let mut tips: Vec<(String, Oid)> = Vec::new();
    for (name, target) in list_refs(store)? {
        let text = name.to_utf8().unwrap_or_default();
        let shown = match text.strip_prefix("refs/heads/") {
            Some(short) => short.to_owned(),
            None => match text.strip_prefix("refs/tags/") {
                Some(short) => format!("tags/{short}"),
                None => continue,
            },
        };
        if opts.is_set("tags") && !text.starts_with("refs/tags/") {
            continue;
        }
        if !patterns.is_empty() && !patterns.iter().any(|p| glob_match(p, &text)) {
            continue;
        }
        if let Some(commit) = peel_target_commit(store, Some(target))? {
            tips.push((shown, commit));
        }
    }
    if tips.is_empty() {
        return Err(GitError::NotFound {
            detail: "no refs to name from".to_owned(),
        });
    }
    tips.sort();
    let mut found: HashMap<Oid, (String, usize)> = HashMap::new();
    let mut queue: VecDeque<Oid> = VecDeque::new();
    for (shown, tip) in &tips {
        if !found.contains_key(tip) {
            found.insert(*tip, (shown.clone(), 0));
            queue.push_back(*tip);
        }
    }
    while let Some(oid) = queue.pop_front() {
        let (name, depth) = found[&oid].clone();
        for parent in parents_of(store, oid)? {
            if !found.contains_key(&parent) {
                found.insert(parent, (name.clone(), depth + 1));
                queue.push_back(parent);
            }
        }
    }
    let mut out = Vec::new();
    for rev in &opts.positionals {
        let oid = resolve_commit(store, kind, rev)?;
        let Some((name, depth)) = found.get(&oid) else {
            return Err(GitError::NotFound {
                detail: format!("{} is not named by any ref", oid.to_hex()),
            });
        };
        let label = match *depth {
            0 => name.clone(),
            _ => format!("{name}~{depth}"),
        };
        if opts.is_set("name-only") {
            out.extend_from_slice(format!("{label}\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{} {label}\n", oid.to_hex()).as_bytes());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// check-ignore / check-attr ignore-file helpers
// ---------------------------------------------------------------------------

/// One parsed ignore line, with its file line number for `-v` output.
pub(crate) struct IgnoreRule {
    lineno: usize,
    pattern: String,
    dir_only: bool,
    negate: bool,
}

/// Loads `.rukignore` lines: blanks and `#` comments drop, `!` negates, a
/// trailing `/` pins a directory. Absent file means no rules.
pub(crate) fn load_ignore_rules(base: &Path) -> Result<Vec<IgnoreRule>, GitError> {
    let path = base.join(".rukignore");
    let body = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(GitError::Io {
                detail: format!("reading {}: {err}", path.display()),
            });
        }
    };
    let text = String::from_utf8_lossy(&body);
    let mut rules = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.strip_suffix('\r').unwrap_or(raw).trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (negate, pattern) = match trimmed.strip_prefix('!') {
            Some(rest) => (true, rest.to_owned()),
            None => (false, trimmed.to_owned()),
        };
        if pattern.is_empty() {
            continue;
        }
        let dir_only = pattern.ends_with('/');
        rules.push(IgnoreRule {
            lineno: index + 1,
            pattern: pattern.trim_end_matches('/').to_owned(),
            dir_only,
            negate,
        });
    }
    Ok(rules)
}

/// Matches one rule against a worktree-relative path.
fn ignore_rule_hits(rule: &IgnoreRule, path: &str) -> bool {
    if rule.dir_only {
        return path == rule.pattern || path.starts_with(&format!("{}/", rule.pattern));
    }
    if rule.pattern.contains('/') {
        let anchored = rule.pattern.trim_start_matches('/');
        return glob_match(anchored, path);
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    glob_match(&rule.pattern, base)
}

/// The last matching rule decides: ignored unless it negates.
pub(crate) fn path_is_ignored(rules: &[IgnoreRule], path: &str) -> Option<usize> {
    let mut hit = None;
    for (index, rule) in rules.iter().enumerate() {
        if ignore_rule_hits(rule, path) {
            hit = Some(index);
        }
    }
    hit.filter(|index| !rules[*index].negate)
}

/// Tests worktree paths against `.rukignore`.
///
/// Oracle: `git/builtin/check-ignore.c`. Exit 0 prints the ignored paths;
/// exit 1 (through `NotFound`, the way `grep` reports no hit) prints
/// nothing when no path is ignored.
pub(crate) fn check_ignore(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "non-matching",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let mut paths: Vec<String> = opts.positionals.clone();
    if opts.is_set("stdin") {
        let raw = super::read_stdin_bytes(&ctx.env)?;
        paths.extend(
            String::from_utf8_lossy(&raw)
                .lines()
                .map(|text_line| text_line.strip_suffix('\r').unwrap_or(text_line).to_owned())
                .filter(|text_line| !text_line.is_empty()),
        );
    }
    if paths.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: check-ignore [-q] [-v] [--stdin] <path>...".to_owned(),
        });
    }
    // Outside a repository there is no ignore file to read; every path is
    // non-ignored, the honest exit-1 case.
    let rules = ctx
        .store
        .as_ref()
        .map(|_| load_ignore_rules(&ctx.file_base))
        .transpose()?
        .unwrap_or_default();
    let flip = opts.is_set("non-matching");
    let mut out = Vec::new();
    let mut printed = 0;
    for path in &paths {
        let ignored = path_is_ignored(&rules, path);
        if ignored.is_some() == flip {
            continue;
        }
        printed += 1;
        if opts.is_set("quiet") {
            continue;
        }
        if opts.is_set("verbose") {
            match ignored {
                Some(index) => out.extend_from_slice(
                    format!(
                        ".rukignore:{}:{}:{path}\n",
                        rules[index].lineno, rules[index].pattern
                    )
                    .as_bytes(),
                ),
                None => out.extend_from_slice(format!("::{path}\n").as_bytes()),
            }
        } else {
            out.extend_from_slice(format!("{path}\n").as_bytes());
        }
    }
    if printed == 0 {
        return Err(GitError::NotFound {
            detail: "no paths are ignored".to_owned(),
        });
    }
    Ok(out)
}

/// One attribute assignment on a `.rukattributes` line.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AttrValue {
    Set,
    Unset,
    Unspecified,
    Valued(String),
}

impl AttrValue {
    fn info(&self) -> String {
        match self {
            Self::Set => "set".to_owned(),
            Self::Unset => "unset".to_owned(),
            Self::Unspecified => "unspecified".to_owned(),
            Self::Valued(value) => value.clone(),
        }
    }
}

/// One parsed `.rukattributes` line.
struct AttrRule {
    pattern: String,
    assigns: Vec<(String, AttrValue)>,
}

/// Loads `.rukattributes`: `pattern attr...` with `name` (set), `-name`
/// (unset), `name!` (unspecified), `name=value`. Absent file means no rules.
fn load_attr_rules(base: &Path) -> Result<Vec<AttrRule>, GitError> {
    let path = base.join(".rukattributes");
    let body = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(GitError::Io {
                detail: format!("reading {}: {err}", path.display()),
            });
        }
    };
    let mut rules = Vec::new();
    for raw in String::from_utf8_lossy(&body).lines() {
        let text_line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if text_line.is_empty() || text_line.starts_with('#') {
            continue;
        }
        let mut words = text_line.split_whitespace();
        let Some(pattern) = words.next() else {
            continue;
        };
        let mut assigns = Vec::new();
        for word in words {
            let (name, value) = if let Some(bare) = word.strip_prefix('-') {
                (bare.to_owned(), AttrValue::Unset)
            } else if let Some((name, val)) = word.split_once('=') {
                (name.to_owned(), AttrValue::Valued(val.to_owned()))
            } else if let Some(bare) = word.strip_suffix('!') {
                (bare.to_owned(), AttrValue::Unspecified)
            } else {
                (word.to_owned(), AttrValue::Set)
            };
            if !name.is_empty() {
                assigns.push((name, value));
            }
        }
        rules.push(AttrRule {
            pattern: pattern.to_owned(),
            assigns,
        });
    }
    Ok(rules)
}

/// Matches an attribute pattern: anchored on `/`, else basename.
fn attr_rule_hits(pattern: &str, path: &str) -> bool {
    if pattern.contains('/') {
        return glob_match(pattern.trim_start_matches('/'), path);
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    glob_match(pattern, base)
}

/// Resolves one attribute for a path: the last matching line wins.
fn resolve_attr(rules: &[AttrRule], path: &str, attr: &str) -> AttrValue {
    let mut value = AttrValue::Unspecified;
    for rule in rules {
        if !attr_rule_hits(&rule.pattern, path) {
            continue;
        }
        for (name, assigned) in &rule.assigns {
            if name == attr {
                value = assigned.clone();
            }
        }
    }
    value
}

/// Reports attributes for paths.
///
/// Oracle: `git/builtin/check-attr.c`. With no `.rukattributes` file every
/// attribute is `unspecified`; the exit status stays zero either way.
pub(crate) fn check_attr(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
    ];
    // Paths live after `--`; everything before names attributes.
    let (head, mut paths) = match args.iter().position(|arg| arg == "--") {
        None => (args.to_vec(), Vec::new()),
        Some(index) => (
            args[..index].to_vec(),
            args[index + 1..]
                .iter()
                .map(|s| s.to_owned())
                .collect::<Vec<String>>(),
        ),
    };
    // `collect` erases the marker, so pre-`--` positionals are the names.
    let opts = collect(&expand_groups(&head, &specs), &specs)?;
    let attrs = opts.positionals.clone();
    if opts.is_set("stdin") {
        let raw = super::read_stdin_bytes(&ctx.env)?;
        paths.extend(
            String::from_utf8_lossy(&raw)
                .lines()
                .map(|text_line| text_line.strip_suffix('\r').unwrap_or(text_line).to_owned())
                .filter(|text_line| !text_line.is_empty()),
        );
    }
    if opts.is_set("all") && !attrs.is_empty() {
        return Err(GitError::Invalid {
            detail: "check-attr -a takes no attribute names".to_owned(),
        });
    }
    if (!opts.is_set("all") && attrs.is_empty()) || paths.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: check-attr [-a | <attr>...] [--] <path>...".to_owned(),
        });
    }
    let rules = ctx
        .store
        .as_ref()
        .map(|_| load_attr_rules(&ctx.file_base))
        .transpose()?
        .unwrap_or_default();
    let mut out = Vec::new();
    for path in &paths {
        if opts.is_set("all") {
            let mut names: Vec<String> = Vec::new();
            for rule in &rules {
                if !attr_rule_hits(&rule.pattern, path) {
                    continue;
                }
                for (name, _) in &rule.assigns {
                    if !names.contains(name) {
                        names.push(name.clone());
                    }
                }
            }
            names.sort();
            for name in &names {
                let value = resolve_attr(&rules, path, name);
                out.extend_from_slice(format!("{path}: {name}: {}\n", value.info()).as_bytes());
            }
            continue;
        }
        for attr in &attrs {
            let value = resolve_attr(&rules, path, attr);
            out.extend_from_slice(format!("{path}: {attr}: {}\n", value.info()).as_bytes());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// stripspace
// ---------------------------------------------------------------------------

/// Cleans whitespace from stdin.
///
/// Oracle: `git/builtin/stripspace.c`: trailing whitespace drops, blank
/// runs collapse to one, leading/trailing blanks drop, and non-empty
/// output ends in exactly one newline.
pub(crate) fn stripspace(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "strip-comments",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "comment-lines",
            short: Some('c'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: stripspace [--strip-comments] < input".to_owned(),
        });
    }
    let raw = super::read_stdin_bytes(&ctx.env)?;
    let strip_comments = opts.is_set("strip-comments") || opts.is_set("comment-lines");
    let mut kept: Vec<Vec<u8>> = Vec::new();
    for text_line in raw.split(|byte| *byte == b'\n') {
        let mut text_line = text_line.to_vec();
        while text_line
            .last()
            .is_some_and(|b| *b == b' ' || *b == b'\t' || *b == b'\r')
        {
            text_line.pop();
        }
        if strip_comments && text_line.iter().find(|b| **b != b' ' && **b != b'\t') == Some(&b'#') {
            continue;
        }
        kept.push(text_line);
    }
    // The split leaves a phantom tail after a trailing newline; it rejoins
    // below through the single enforced terminator.
    if raw.ends_with(b"\n") {
        kept.pop();
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    for text_line in kept {
        if text_line.is_empty() && out.last().is_some_and(Vec::is_empty) {
            continue;
        }
        out.push(text_line);
    }
    while out.first().is_some_and(Vec::is_empty) {
        out.remove(0);
    }
    while out.last().is_some_and(Vec::is_empty) {
        out.pop();
    }
    if out.is_empty() {
        return Ok(Vec::new());
    }
    let mut bytes = out.join(&b'\n');
    bytes.push(b'\n');
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// interpret-trailers
// ---------------------------------------------------------------------------

/// One parsed trailer: `token: value`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Trailer {
    token: String,
    value: String,
}

/// Reports whether a line opens a trailer (`token: value` with a
/// Git-shaped token).
fn is_trailer_line(text_line: &str) -> bool {
    let Some(colon) = text_line.find(':') else {
        return false;
    };
    let (token, _) = text_line.split_at(colon);
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Splits a message into body lines and trailing trailer lines.
/// Continuation lines (leading space) fold into the trailer above them.
fn split_trailers(text: &str) -> (Vec<String>, Vec<Trailer>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut end = lines.len();
    while end > 0 && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let text_line = lines[start - 1];
        if text_line.starts_with(' ') || text_line.starts_with('\t') || is_trailer_line(text_line) {
            start -= 1;
        } else {
            break;
        }
    }
    // A block of only continuations is body text, not trailers.
    if start < end && !lines[start..end].iter().any(|l| is_trailer_line(l)) {
        start = end;
    }
    let mut trailers: Vec<Trailer> = Vec::new();
    let mut index = start;
    while index < end {
        let text_line = lines[index];
        if !is_trailer_line(text_line) {
            index += 1;
            continue;
        }
        let Some(colon) = text_line.find(':') else {
            index += 1;
            continue;
        };
        let token = text_line[..colon].trim().to_owned();
        let mut value = text_line[colon + 1..].trim().to_owned();
        index += 1;
        while index < end && (lines[index].starts_with(' ') || lines[index].starts_with('\t')) {
            value.push(' ');
            value.push_str(lines[index].trim());
            index += 1;
        }
        trailers.push(Trailer { token, value });
    }
    (
        lines[..start].iter().map(|s| (*s).to_owned()).collect(),
        trailers,
    )
}

/// Parses one `--trailer` argument in `key=value` or `key: value` form,
/// splitting at the earliest separator the way the oracle accepts both.
/// A bare `key` carries an empty value.
fn parse_trailer_arg(extra: &str) -> Result<Trailer, GitError> {
    let equals = extra.find('=');
    let colon = extra.find(':');
    let cut = match (equals, colon) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };
    match cut {
        Some(index) => Ok(Trailer {
            token: extra[..index].trim().to_owned(),
            value: extra[index + 1..].trim().to_owned(),
        }),
        None => Ok(Trailer {
            token: extra.trim().to_owned(),
            value: String::new(),
        }),
    }
}

/// Parses and formats commit-message trailers.
///
/// Oracle: `git/builtin/interpret-trailers.c`. Supported subset: the
/// default prints the message with `--trailer` lines appended, while
/// `--only-trailers`, `--only-input`, `--parse`, `--unfold`, and
/// `--where=before|after` select and shape the parts.
pub(crate) fn interpret_trailers(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "only-trailers",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "only-input",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "unfold",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "parse",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "trailer",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "where",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "key",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail:
                "usage: interpret-trailers [--only-trailers] [--trailer=<key[=: ]value>] < input"
                    .to_owned(),
        });
    }
    if opts.is_set("only-trailers") && opts.is_set("only-input") {
        return Err(GitError::Invalid {
            detail: "--only-trailers and --only-input exclude each other".to_owned(),
        });
    }
    let placement = opts.single("where")?.unwrap_or_else(|| "after".to_owned());
    let before = match placement.as_str() {
        "after" | "end" => false,
        "before" | "start" => true,
        _ => {
            return Err(GitError::Invalid {
                detail: format!("bad --where={placement:?}: want after|before|end|start"),
            });
        }
    };
    let raw = super::read_stdin_bytes(&ctx.env)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (mut body, mut trailers) = split_trailers(&text);
    for extra in opts.all("trailer")? {
        trailers.push(parse_trailer_arg(&extra)?);
    }
    if trailers.iter().any(|t| {
        t.token.is_empty()
            || !t
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return Err(GitError::Invalid {
            detail: "trailer token must be non-empty [A-Za-z0-9-_]+".to_owned(),
        });
    }
    if let Some(key) = opts.single("key")? {
        trailers.retain(|t| t.token == key);
    }
    if opts.is_set("parse") || opts.is_set("only-trailers") {
        let mut out = Vec::new();
        for t in &trailers {
            if t.value.is_empty() {
                out.extend_from_slice(format!("{}\n", t.token).as_bytes());
            } else {
                out.extend_from_slice(format!("{}: {}\n", t.token, t.value).as_bytes());
            }
        }
        return Ok(out);
    }
    if opts.is_set("only-input") {
        while body.last().is_some_and(|l| l.trim().is_empty()) {
            body.pop();
        }
        if body.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(line(body.join("\n").into_bytes()));
    }
    // Default: the message with trailers appended in place.
    let mut lines = body;
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    let rendered: Vec<String> = trailers
        .iter()
        .map(|t| {
            if t.value.is_empty() {
                t.token.clone()
            } else {
                format!("{}: {}", t.token, t.value)
            }
        })
        .collect();
    if !lines.is_empty() && !rendered.is_empty() {
        if before {
            let mut combined = rendered;
            combined.push(String::new());
            combined.extend(lines);
            lines = combined;
        } else {
            lines.push(String::new());
            lines.extend(rendered);
        }
    } else {
        lines.extend(rendered);
    }
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    Ok(line(lines.join("\n").into_bytes()))
}

// ---------------------------------------------------------------------------
// var
// ---------------------------------------------------------------------------

/// Prints one runtime variable.
///
/// Oracle: `git/builtin/var.c`. The idents come from the same identity the
/// commit verb uses, so `var` and `commit` never disagree; the rest fall
/// back through env, config, and the oracle's compiled defaults.
pub(crate) fn var(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "list",
        short: Some('l'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.is_set("list") {
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: var [-l | <variable>]".to_owned(),
            });
        }
        let mut out = Vec::new();
        for name in [
            "GIT_AUTHOR_IDENT",
            "GIT_COMMITTER_IDENT",
            "GIT_DEFAULT_BRANCH",
            "GIT_EDITOR",
            "GIT_PAGER",
        ] {
            let value = String::from_utf8_lossy(&var_value(ctx, name)?).into_owned();
            out.extend_from_slice(format!("{name}={value}\n").as_bytes());
        }
        return Ok(out);
    }
    let [name] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: var [-l | <variable>]".to_owned(),
        });
    };
    Ok(line(var_value(ctx, name)?))
}

/// Reads one ident through the mailmap for `var`, mirroring how the `%aN`
/// display shapes map the stored ident without rewriting it. A mapped
/// ident that fails the canonical grammar falls back to the stored one
/// instead of failing the lookup.
fn mapped_ident(ctx: &Ctx, role: IdentityRole) -> Result<Signature, GitError> {
    let ident = identity(ctx, role)?;
    let mailmap = load_mailmap(ctx);
    let stored_name = String::from_utf8_lossy(ident.name.as_bytes());
    let stored_email = String::from_utf8_lossy(ident.email.as_bytes());
    let mapped = mailmap.map_ident(&stored_name, &stored_email);
    let Some((name, email)) = mapped else {
        return Ok(ident);
    };
    let rendered = format!("{name} <{email}> {} {}", ident.timestamp, ident.offset);
    Ok(Signature::parse(rendered.as_bytes()).unwrap_or(ident))
}

/// Reads one variable's value without the trailing newline.
fn var_value(ctx: &Ctx, name: &str) -> Result<Vec<u8>, GitError> {
    match name {
        "GIT_AUTHOR_IDENT" => Ok(mapped_ident(ctx, IdentityRole::Author)?.render()),
        "GIT_COMMITTER_IDENT" => Ok(mapped_ident(ctx, IdentityRole::Committer)?.render()),
        "GIT_DEFAULT_BRANCH" => Ok(ctx
            .config_get("init.defaultBranch")
            .unwrap_or_else(|| "main".to_owned())
            .into_bytes()),
        "GIT_EDITOR" => Ok(var_chain(
            ctx,
            "GIT_EDITOR",
            "core.editor",
            &["VISUAL", "EDITOR"],
            "vi",
        )),
        "GIT_PAGER" => Ok(var_chain(
            ctx,
            "GIT_PAGER",
            "core.pager",
            &["PAGER"],
            "less",
        )),
        _ => Err(GitError::Invalid {
            detail: format!("unknown variable {name:?}"),
        }),
    }
}

/// Resolves an editor-style variable: dedicated env, config, fallbacks,
/// then the oracle's compiled default.
fn var_chain(
    ctx: &Ctx,
    env_key: &str,
    config_key: &str,
    fallbacks: &[&str],
    default: &str,
) -> Vec<u8> {
    if let Some(value) = ctx.env.get(env_key) {
        return value.as_bytes().to_vec();
    }
    if let Some(value) = ctx.config_get(config_key) {
        return value.into_bytes();
    }
    for key in fallbacks {
        if let Some(value) = ctx.env.get(key) {
            return value.as_bytes().to_vec();
        }
    }
    default.as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// get-tar-commit-id
// ---------------------------------------------------------------------------

/// Prints the commit id stored in a tar archive's global pax header.
///
/// Oracle: `git/builtin/get-tar-commit-id.c`. The archive verb writes the
/// same `comment=<hex>` record the oracle writes, so this round-trips;
/// anything else exits 1 instead of inventing an id.
pub(crate) fn get_tar_commit_id(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if !args.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: get-tar-commit-id < archive.tar".to_owned(),
        });
    }
    let raw = super::read_stdin_bytes(&ctx.env)?;
    match scan_tar_comment(&raw)? {
        Some(hex) => Ok(line(hex.into_bytes())),
        None => Err(GitError::NotFound {
            detail: "archive carries no commit id".to_owned(),
        }),
    }
}

/// Scans tar headers for a global/extended `comment` pax record holding a
/// 40- or 64-hex object id.
fn scan_tar_comment(raw: &[u8]) -> Result<Option<String>, GitError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() < 512 || raw[257..262] != *b"ustar" {
        return Err(GitError::Corrupt {
            detail: "input is not a ustar archive".to_owned(),
        });
    }
    let mut offset = 0;
    while offset + 512 <= raw.len() {
        let header = &raw[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        if header[257..262] != *b"ustar" {
            return Err(GitError::Corrupt {
                detail: "archive header is not ustar".to_owned(),
            });
        }
        let size = parse_tar_size(&header[124..136])?;
        let size = usize::try_from(size).map_err(|_| GitError::Corrupt {
            detail: "tar size exceeds the address range".to_owned(),
        })?;
        offset += 512;
        let kind = header[156];
        if kind == b'g' || kind == b'x' {
            let end = offset.saturating_add(size).min(raw.len());
            if let Some(hex) = scan_pax_comment(&raw[offset..end]) {
                return Ok(Some(hex));
            }
        }
        offset = offset.saturating_add(((size + 511) / 512) * 512);
    }
    Ok(None)
}

/// Parses a 12-byte octal tar size field.
fn parse_tar_size(field: &[u8]) -> Result<u64, GitError> {
    let text: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect();
    let digits = String::from_utf8(text).map_err(|_| GitError::Corrupt {
        detail: "tar size is not ascii".to_owned(),
    })?;
    let trimmed = digits.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 8).map_err(|_| GitError::Corrupt {
        detail: "tar size is not octal".to_owned(),
    })
}

/// Finds `comment=<hex>` in pax extended-header data.
fn scan_pax_comment(data: &[u8]) -> Option<String> {
    for record in data.split(|byte| *byte == b'\n') {
        let mut parts = record.splitn(2, |byte| *byte == b' ');
        parts.next()?;
        let assignment = parts.next()?;
        let equals = assignment.iter().position(|byte| *byte == b'=')?;
        if &assignment[..equals] != b"comment" {
            continue;
        }
        let value = String::from_utf8_lossy(&assignment[equals + 1..]).into_owned();
        if (value.len() == 40 || value.len() == 64)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Some(value.to_ascii_lowercase());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// fmt-merge-msg
// ---------------------------------------------------------------------------

/// One fetched tip from the `FETCH_HEAD` pseudo record.
struct FetchedTip {
    oid: Oid,
    name: String,
}

/// Parses the `FETCH_HEAD` pseudo record (`<hex>\t<ref>` per line).
fn read_fetch_head(store: &Store, kind: HashKind) -> Result<Vec<FetchedTip>, GitError> {
    let Some(raw) = pseudo_read(store, "FETCH_HEAD")? else {
        return Err(GitError::NotFound {
            detail: "no FETCH_HEAD: run fetch first".to_owned(),
        });
    };
    let mut tips = Vec::new();
    for text_line in String::from_utf8_lossy(&raw).lines() {
        let text_line = text_line.strip_suffix('\r').unwrap_or(text_line);
        if text_line.trim().is_empty() {
            continue;
        }
        let (hex, name) = text_line
            .split_once('\t')
            .or_else(|| text_line.split_once(' '))
            .ok_or_else(|| GitError::Corrupt {
                detail: "FETCH_HEAD line has no ref".to_owned(),
            })?;
        let oid = ruk_git::parse_oid_for(hex.trim(), kind)?;
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(GitError::Corrupt {
                detail: "FETCH_HEAD line has an empty ref".to_owned(),
            });
        }
        tips.push(FetchedTip { oid, name });
    }
    if tips.is_empty() {
        return Err(GitError::NotFound {
            detail: "FETCH_HEAD is empty".to_owned(),
        });
    }
    Ok(tips)
}

/// Short merge label for one fetched ref.
fn merge_label(name: &str) -> String {
    if let Some(short) = name.strip_prefix("refs/heads/") {
        return format!("branch '{short}'");
    }
    if let Some(short) = name.strip_prefix("refs/remotes/") {
        return format!("remote-tracking branch '{short}'");
    }
    if let Some(short) = name.strip_prefix("refs/tags/") {
        return format!("tag '{short}'");
    }
    format!("ref '{name}'")
}

/// Formats a merge message from fetched tips.
///
/// Oracle: `git/builtin/fmt-merge-msg.c`. Reads the `FETCH_HEAD` pseudo
/// record the fetch verb writes (or `--stdin`/a file in the same shape);
/// `-m` overrides the subject, `--log[=n]` appends new-commit subjects
/// (default 20 per tip), `--no-log` suppresses them.
pub(crate) fn fmt_merge_msg(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut log_limit: Option<usize> = None;
    let mut log_seen = false;
    for arg in args {
        if arg == "--log" {
            log_seen = true;
        } else if let Some(value) = arg.strip_prefix("--log=") {
            log_seen = true;
            log_limit = Some(value.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad --log={value:?}: want a count"),
            })?);
        } else {
            rewritten.push(arg.clone());
        }
    }
    let specs = [
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "log",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-log",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(&rewritten, &specs)?;
    if opts.is_set("log") || log_seen {
        log_limit = log_limit.or(Some(20));
    }
    if opts.is_set("no-log") {
        log_limit = None;
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tips = if opts.is_set("stdin") {
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "usage: fmt-merge-msg [--log[=n]] [-m <msg>] [--stdin | <file>]".to_owned(),
            });
        }
        parse_fetch_bytes(&super::read_stdin_bytes(&ctx.env)?, kind)?
    } else if let Some(path) = opts.positionals.first() {
        if opts.positionals.len() > 1 {
            return Err(GitError::Invalid {
                detail: "usage: fmt-merge-msg [--log[=n]] [-m <msg>] [--stdin | <file>]".to_owned(),
            });
        }
        let full = ctx.env.cwd.join(path);
        let raw = std::fs::read(&full).map_err(|err| GitError::Io {
            detail: format!("reading {}: {err}", full.display()),
        })?;
        parse_fetch_bytes(&raw, kind)?
    } else {
        read_fetch_head(store, kind)?
    };
    let subject = match opts.single("message")? {
        Some(text) => text,
        None => {
            let labels: Vec<String> = tips.iter().map(|tip| merge_label(&tip.name)).collect();
            if labels.len() == 1 {
                format!("Merge {}", labels[0])
            } else {
                format!("Merge {}", labels.join(", "))
            }
        }
    };
    let mut out = line(subject.into_bytes());
    if let Some(max) = log_limit {
        let head = head_oid(store).ok();
        for tip in &tips {
            let exclude: Vec<Oid> = head.into_iter().collect();
            let mut fresh = walk_history_excluding(store, &[tip.oid], &exclude, Some(max))?;
            fresh.reverse();
            if fresh.is_empty() {
                continue;
            }
            out.extend_from_slice(format!("* {}:\n", merge_label(&tip.name)).as_bytes());
            for (_, record) in &fresh {
                let subject = String::from_utf8_lossy(record.message())
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                out.extend_from_slice(format!("  {subject}\n").as_bytes());
            }
        }
    }
    Ok(out)
}

/// Parses `FETCH_HEAD`-shaped bytes from `--stdin` or a file.
fn parse_fetch_bytes(raw: &[u8], kind: HashKind) -> Result<Vec<FetchedTip>, GitError> {
    let mut tips = Vec::new();
    for text_line in String::from_utf8_lossy(raw).lines() {
        let text_line = text_line.strip_suffix('\r').unwrap_or(text_line);
        if text_line.trim().is_empty() {
            continue;
        }
        let (hex, name) = text_line
            .split_once('\t')
            .or_else(|| text_line.split_once(' '))
            .ok_or_else(|| GitError::Invalid {
                detail: "fetch input line has no ref".to_owned(),
            })?;
        tips.push(FetchedTip {
            oid: ruk_git::parse_oid_for(hex.trim(), kind)?,
            name: name.trim().to_owned(),
        });
    }
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch input is empty".to_owned(),
        });
    }
    Ok(tips)
}

// ---------------------------------------------------------------------------
// verify-tag / verify-commit
// ---------------------------------------------------------------------------

/// Checks one tag object body for its three header lines and a live target.
fn check_tag_body(store: &Store, body: &[u8]) -> Result<(), GitError> {
    let text = std::str::from_utf8(body).map_err(|_| GitError::Corrupt {
        detail: "tag body is not utf-8".to_owned(),
    })?;
    let mut has_object = false;
    let mut has_type = false;
    let mut has_tag = false;
    for text_line in text.lines() {
        if text_line.is_empty() {
            break;
        }
        has_object |= text_line.starts_with("object ");
        has_type |= text_line.starts_with("type ");
        has_tag |= text_line.starts_with("tag ");
    }
    if !(has_object && has_type && has_tag) {
        return Err(GitError::Corrupt {
            detail: "tag body misses object/type/tag headers".to_owned(),
        });
    }
    let target = tag_target_oid(body)?;
    read_object_bytes(store, target).map(|_| ())
}

/// Verifies tag objects structurally, then refuses honestly.
///
/// Oracle: `git/builtin/verify-tag.c`. The store holds no GPG signatures,
/// so after the structural check passes the verb exits nonzero instead of
/// claiming a verification it cannot perform.
pub(crate) fn verify_tag(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "verbose",
        short: Some('v'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: verify-tag <tag>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    for name in &opts.positionals {
        let refname =
            RefName::new(format!("refs/tags/{name}")).map_err(|err| GitError::Invalid {
                detail: format!("bad tag name: {err}"),
            })?;
        let target = read_ref(store, &refname)?.ok_or_else(|| GitError::NotFound {
            detail: format!("tag {name:?} does not exist"),
        })?;
        let RefTarget::Direct(oid) = target else {
            return Err(GitError::Invalid {
                detail: format!("tag {name:?} is symbolic"),
            });
        };
        let (object_kind, body) = read_object_bytes(store, oid)?;
        if object_kind == ObjectKind::Tag {
            check_tag_body(store, &body)?;
        }
    }
    let first = &opts.positionals[0];
    Err(GitError::Unsupported {
        command: format!("tag {first:?} carries no GPG signature: this store cannot verify tags"),
    })
}

/// Verifies commits structurally, then refuses honestly.
///
/// Oracle: `git/builtin/verify-commit.c`. Same shape as `verify-tag`:
/// existence and commit shape check first, then a nonzero refusal, since
/// no signatures exist to verify.
pub(crate) fn verify_commit(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "verbose",
        short: Some('v'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: verify-commit <commit>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for rev in &opts.positionals {
        let oid = resolve_commit(store, kind, rev)?;
        commit_record(store, oid)?;
    }
    Err(GitError::Unsupported {
        command: "commits carry no GPG signatures: this store cannot verify commits".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// stage / whatchanged (aliases)
// ---------------------------------------------------------------------------

/// Stages paths exactly like `add`.
///
/// Oracle: `git/builtin/add.c`. `stage` is the historical synonym git keeps
/// as its own builtin entry; here it forwards byte-for-byte, so every
/// `add` flag and error reads identically.
pub(crate) fn stage(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    super::verbs_stage::add(ctx, args)
}

/// Shows commits with raw per-file lines, skipping merges.
///
/// Oracle: `git/builtin/log.c` (`cmd_whatchanged`, hard-wired to
/// `log --raw --no-merges`). `log` renders no `--raw` section, but `show`
/// does, so each walked non-merge tip renders through `show --raw`.
/// Ranges use the same revision grammar as `log`; `-n` caps the walk.
pub(crate) fn whatchanged(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "max-count",
        short: Some('n'),
        takes_value: true,
    }];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let limit: Option<usize> = match opts.single("max-count")? {
        None => None,
        Some(text) => Some(text.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad --max-count={text:?}"),
        })?),
    };
    let default_tip = head_oid(store).ok();
    let (tips, exclude) = parse_log_revs(store, kind, &opts.positionals, default_tip)?;
    if tips.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: whatchanged [-n <n>] [<revision-range>]".to_owned(),
        });
    }
    let history = walk_history_excluding(store, &tips, &exclude, None)?;
    let mut out = Vec::new();
    let mut shown = 0usize;
    for (oid, record) in &history {
        let parents: Vec<Oid> = record
            .parents()
            .iter()
            .filter_map(|head| head.as_git().copied())
            .collect();
        if parents.len() > 1 {
            continue;
        }
        if limit.is_some_and(|max| shown >= max) {
            break;
        }
        shown += 1;
        out.extend_from_slice(
            &super::verbs_history::show(&mut *ctx, &["--raw".to_owned(), oid.to_hex()])?,
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// show-index
// ---------------------------------------------------------------------------

/// Lists the objects named by a pack index.
///
/// Oracle: `git/builtin/show-index.c`. Reads a v2 `.idx` from stdin (or
/// the one `<idx-file>` positional) and prints
/// `<offset> <hex> <crc>` per entry. Only v2 indexes parse: anything else
/// is `Corrupt`, since guessing an object list would invent history.
pub(crate) fn show_index(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    let bytes = match opts.positionals.as_slice() {
        [] => super::read_stdin_bytes(&ctx.env)?,
        [path] => std::fs::read(path).map_err(|err| GitError::Io {
            detail: format!("reading {path}: {err}"),
        })?,
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: show-index [<idx-file>] < pack.idx".to_owned(),
            });
        }
    };
    let kind = ctx.kind().unwrap_or(HashKind::Sha1);
    let width = kind.oid_len();
    if bytes.len() < 8 + 1024
        || &bytes[..4] != b"\xfftOc"
        || u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != 2
    {
        return Err(GitError::Corrupt {
            detail: "not a v2 pack index".to_owned(),
        });
    }
    let mut fanout = [0u32; 256];
    for (slot, cell) in fanout.iter_mut().enumerate() {
        let base = 8 + 4 * slot;
        *cell = u32::from_be_bytes([
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
        ]);
    }
    if fanout.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(GitError::Corrupt {
            detail: "pack index fanout decreases".to_owned(),
        });
    }
    // Every offset below is attacker-controlled input: checked arithmetic
    // turns overflow into `Corrupt`, and every read goes through `get`,
    // so a hostile index errors instead of panicking.
    let corrupt = |detail: &str| GitError::Corrupt {
        detail: detail.to_owned(),
    };
    let count = usize::try_from(fanout[255])
        .map_err(|_| corrupt("pack index entry count exceeds address space"))?;
    let oids_len = count
        .checked_mul(width)
        .ok_or_else(|| corrupt("pack index entry table overflows"))?;
    let crc_len = count
        .checked_mul(4)
        .ok_or_else(|| corrupt("pack index crc table overflows"))?;
    let oids_base = 8usize.checked_add(1024).ok_or_else(|| corrupt("pack index header overflows"))?;
    let crc_base = oids_base
        .checked_add(oids_len)
        .ok_or_else(|| corrupt("pack index entry table overflows"))?;
    let off_base = crc_base
        .checked_add(crc_len)
        .ok_or_else(|| corrupt("pack index crc table overflows"))?;
    let off_end = off_base
        .checked_add(crc_len)
        .ok_or_else(|| corrupt("pack index offset table overflows"))?;
    // Offsets with the high bit set index the 8-byte large-offset table
    // that follows the 4-byte table; count them before sizing the tail.
    let mut large = 0usize;
    for index in 0..count {
        let base = off_base.checked_add(
            index
                .checked_mul(4)
                .ok_or_else(|| corrupt("pack index offset entry overflows"))?,
        );
        let base = base.ok_or_else(|| corrupt("pack index offset table overflows"))?;
        let Some(entry) = bytes.get(base..base.saturating_add(4)) else {
            return Err(corrupt("pack index truncates its offset table"));
        };
        let entry: [u8; 4] = entry
            .try_into()
            .map_err(|_| corrupt("pack index truncates its offset table"))?;
        if u32::from_be_bytes(entry) & 0x8000_0000 != 0 {
            large = large
                .checked_add(1)
                .ok_or_else(|| corrupt("pack index large-offset count overflows"))?;
        }
    }
    let large_len = large
        .checked_mul(8)
        .ok_or_else(|| corrupt("pack index large-offset table overflows"))?;
    let trailer = off_end
        .checked_add(large_len)
        .ok_or_else(|| corrupt("pack index large-offset table overflows"))?;
    let expected = trailer
        .checked_add(width)
        .and_then(|end| end.checked_add(width))
        .ok_or_else(|| corrupt("pack index trailer overflows"))?;
    if bytes.len() != expected {
        return Err(corrupt(
            "pack index length disagrees with its entry count",
        ));
    }
    let mut out = Vec::new();
    for index in 0..count {
        let oid = &bytes[oids_base + index * width..oids_base + (index + 1) * width];
        let crc = u32::from_be_bytes([
            bytes[crc_base + 4 * index],
            bytes[crc_base + 4 * index + 1],
            bytes[crc_base + 4 * index + 2],
            bytes[crc_base + 4 * index + 3],
        ]);
        let raw = u32::from_be_bytes([
            bytes[off_base + 4 * index],
            bytes[off_base + 4 * index + 1],
            bytes[off_base + 4 * index + 2],
            bytes[off_base + 4 * index + 3],
        ]);
        let offset = if raw & 0x8000_0000 == 0 {
            u64::from(raw)
        } else {
            let slot = usize::try_from(raw & 0x7fff_ffff)
                .map_err(|_| corrupt("pack index large-offset slot exceeds address space"))?;
            if slot >= large {
                return Err(corrupt("pack index large-offset slot escapes its table"));
            }
            let base = off_end.checked_add(
                slot
                    .checked_mul(8)
                    .ok_or_else(|| corrupt("pack index large-offset slot overflows"))?,
            );
            let base = base.ok_or_else(|| corrupt("pack index large-offset table overflows"))?;
            let Some(entry) = bytes.get(base..base.saturating_add(8)) else {
                return Err(corrupt("pack index truncates its large-offset table"));
            };
            let entry: [u8; 8] = entry
                .try_into()
                .map_err(|_| corrupt("pack index truncates its large-offset table"))?;
            u64::from_be_bytes(entry)
        };
        out.extend_from_slice(
            format!(
                "{offset} {} {crc:08x}\n",
                oid.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// unpack-objects / unpack-file
// ---------------------------------------------------------------------------

/// Unpacks a pack stream from stdin into the store.
///
/// Oracle: `git/builtin/unpack-objects.c`. The store keeps no loose/pack
/// split, so the pack ingests and publishes exactly the way `index-pack`
/// publishes it (commit-record facts included); `-n`/`--dry-run` verifies
/// without publishing.
pub(crate) fn unpack_objects(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "dry-run",
        short: Some('n'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: unpack-objects [-n] < pack".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let bytes = super::read_stdin_bytes(&ctx.env)?;
    let staged = ruk_git::transport::pack::ingest_pack(
        &bytes[..],
        kind,
        store,
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    let count = staged.oids().len();
    if opts.is_set("dry-run") {
        return Ok(line(
            format!("stdin: ok ({count} objects, dry run, nothing stored)").into_bytes(),
        ));
    }
    let facts = ruk_git::transport::fetch::commit_record_facts(store, &staged)?;
    store
        .publish(staged.into_objects(), &facts)
        .map_err(GitError::from)?;
    Ok(line(
        format!("stdin: ok ({count} objects unpacked)").into_bytes(),
    ))
}

/// Writes one blob to a file and prints its name.
///
/// Oracle: `git/builtin/unpack-file.c`. The file lands in the worktree
/// root as `tmp-unpack-<12hex>-<pid>` (suffixed when the name is taken;
/// the oracle mints its own temp name the same way); non-blobs are
/// `Invalid`, since only blobs have file bytes to spill.
pub(crate) fn unpack_file(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    let [rev] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: unpack-file <blob>".to_owned(),
        });
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = resolve_rev(store, kind, rev).or_else(|_| ruk_git::parse_oid_for(rev, kind))?;
    let (object_kind, body) = read_object_bytes(store, oid)?;
    if object_kind != ObjectKind::Blob {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a blob", oid.to_hex()),
        });
    }
    // The oracle mints a fresh temp file per call, so a second unpack of
    // the same blob must not clobber the first: suffix on collision.
    let stem = format!("tmp-unpack-{}-{}", &oid.to_hex()[..12], std::process::id());
    let mut name = stem.clone();
    let mut attempt = 0u32;
    let path = loop {
        let candidate = ctx.file_base.join(&name);
        if !candidate.exists() {
            break candidate;
        }
        attempt = attempt.saturating_add(1);
        name = format!("{stem}-{attempt}");
    };
    std::fs::write(&path, &body).map_err(|err| GitError::Io {
        detail: format!("writing {name}: {err}"),
    })?;
    Ok(line(name.into_bytes()))
}

// ---------------------------------------------------------------------------
// mktag
// ---------------------------------------------------------------------------

/// Creates a tag object from a stdin body.
///
/// Oracle: `git/builtin/mktag.c`. The body must carry `object`/`type`/`tag`
/// headers over a live target (the same structural check `verify-tag`
/// runs), and `type` must name a real object kind; the stored tag's id
/// prints on success.
pub(crate) fn mktag(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: mktag < tag-body".to_owned(),
        });
    }
    let store = ctx.store()?;
    let body = super::read_stdin_bytes(&ctx.env)?;
    check_tag_body(store, &body)?;
    let text = std::str::from_utf8(&body).map_err(|_| GitError::Corrupt {
        detail: "tag body is not utf-8".to_owned(),
    })?;
    let mut object_type = None::<&str>;
    for text_line in text.lines() {
        if text_line.is_empty() {
            break;
        }
        if let Some(value) = text_line.strip_prefix("type ") {
            object_type = Some(value);
        }
    }
    match object_type {
        Some("blob") | Some("tree") | Some("commit") | Some("tag") => {}
        _ => {
            return Err(GitError::Invalid {
                detail: "tag body needs `type blob|tree|commit|tag`".to_owned(),
            });
        }
    }
    let oid = super::tree::store_object(store, ObjectKind::Tag, body)?;
    Ok(line(oid.to_hex().into_bytes()))
}

// ---------------------------------------------------------------------------
// bugreport / diagnose
// ---------------------------------------------------------------------------

/// Shared report body: version, platform, config, refs, and head.
///
/// Store sections degrade to an explicit marker outside a repository
/// instead of failing, the way the oracle still reports what it can.
fn report_bytes(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let mut out = super::dispatch::version_text();
    out.extend_from_slice(
        format!(
            "os: {} arch: {}\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .as_bytes(),
    );
    let Ok(store) = ctx.store() else {
        out.extend_from_slice(b"(no repository: store sections omitted)\n");
        return Ok(out);
    };
    let format_name = match ctx.kind() {
        Ok(HashKind::Sha256) => "sha256",
        _ => "sha1",
    };
    out.extend_from_slice(format!("object-format: {format_name}\n").as_bytes());
    out.extend_from_slice(b"[config]\n");
    match super::state::config_list(store) {
        Ok(pairs) => {
            for (name, value) in pairs {
                out.extend_from_slice(format!("{name}={value}\n").as_bytes());
            }
        }
        Err(err) => out.extend_from_slice(format!("(config unreadable: {err})\n").as_bytes()),
    }
    out.extend_from_slice(b"[refs]\n");
    match list_refs(store) {
        Ok(refs) => {
            for (name, target) in refs {
                let text = name.to_utf8().unwrap_or_default();
                match target {
                    RefTarget::Direct(oid) => out.extend_from_slice(
                        format!("{text} {}\n", oid.to_hex()).as_bytes(),
                    ),
                    RefTarget::Symbolic(dest) => out.extend_from_slice(
                        format!("{text} ref: {}\n", dest.to_utf8().unwrap_or_default()).as_bytes(),
                    ),
                }
            }
        }
        Err(err) => out.extend_from_slice(format!("(refs unreadable: {err})\n").as_bytes()),
    }
    match head_oid(store) {
        Ok(oid) => out.extend_from_slice(format!("head: {}\n", oid.to_hex()).as_bytes()),
        Err(_) => out.extend_from_slice(b"head: unborn\n"),
    }
    Ok(out)
}

/// Dumps a bug report: version, platform, config, refs, and head.
///
/// Oracle: `git/builtin/bugreport.c`. The oracle mails its report through
/// the user's mailer; here it goes to stdout, or to `-o`/`--output-file`.
pub(crate) fn bugreport(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "output-file",
        short: Some('o'),
        takes_value: true,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: bugreport [-o <file>]".to_owned(),
        });
    }
    let report = report_bytes(ctx)?;
    if let Some(path) = opts.single("output-file")? {
        std::fs::write(&path, &report).map_err(|err| GitError::Io {
            detail: format!("writing {path}: {err}"),
        })?;
        return Ok(line(format!("wrote {path}").into_bytes()));
    }
    Ok(report)
}

/// Dumps diagnostics: the bug report plus the object census.
///
/// Oracle: `git/builtin/diagnose.c`. The oracle zips diagnostics with
/// loose-object stats; the store keeps no loose split, so this prints the
/// same report plus the census line (`diagnose` with `-o`/`--output`
/// writes the file and prints its path).
pub(crate) fn diagnose(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "output",
        short: Some('o'),
        takes_value: true,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: diagnose [-o <file>]".to_owned(),
        });
    }
    let mut report = report_bytes(ctx)?;
    if ctx.store().is_ok() {
        let store = ctx.store()?;
        let mut count: u64 = 0;
        let mut bytes: u64 = 0;
        for (_, _, len) in store.iter_objects().map_err(GitError::from)? {
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(len);
        }
        report.extend_from_slice(format!("objects: {count} total, {bytes} bytes\n").as_bytes());
    }
    if let Some(path) = opts.single("output")? {
        std::fs::write(&path, &report).map_err(|err| GitError::Io {
            detail: format!("writing {path}: {err}"),
        })?;
        return Ok(line(format!("wrote {path}").into_bytes()));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// for-each-repo
// ---------------------------------------------------------------------------

/// Runs one command in every listed repository.
///
/// Oracle: `git/builtin/for-each-repo.c`. Each `--config=<key>` value
/// names one repository per line (config records hold one value each, so
/// repeat `--config` for more keys); the command dispatches in-process
/// against each store in turn, and the first failure aborts with its own
/// error after naming the repository on stderr.
pub(crate) fn for_each_repo(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    // Leading `--config` options name the repositories; the first
    // non-option token (or anything after `--`) starts the child command,
    // whose own flags pass through untouched. Routing the whole argv
    // through `collect` would reject the child's flags as unknown options,
    // so the split is manual, mirroring how the oracle stops option
    // parsing at the command.
    const USAGE: &str = "usage: for-each-repo --config=<key>... <command> [<args>...]";
    let mut keys = Vec::new();
    let mut command: &[String] = &[];
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            command = &args[index + 1..];
            break;
        }
        if let Some(key) = arg.strip_prefix("--config=") {
            keys.push(key.to_owned());
        } else if arg == "--config" {
            index += 1;
            keys.push(args.get(index).cloned().ok_or_else(|| GitError::Invalid {
                detail: "option --config requires a value".to_owned(),
            })?);
        } else if let Some(name) = arg.strip_prefix("--") {
            let name = name.split('=').next().unwrap_or_default();
            return Err(GitError::Invalid {
                detail: format!("unknown option --{name} ({USAGE})"),
            });
        } else {
            command = &args[index..];
            break;
        }
        index += 1;
    }
    if keys.is_empty() || command.is_empty() {
        return Err(GitError::Invalid {
            detail: USAGE.to_owned(),
        });
    }
    let mut repos = Vec::new();
    for key in &keys {
        let value = ctx.config_get(key).ok_or_else(|| GitError::NotFound {
            detail: format!("config {key} is not set"),
        })?;
        for text_line in value.lines() {
            let trimmed = text_line.trim();
            if !trimmed.is_empty() {
                repos.push(trimmed.to_owned());
            }
        }
    }
    if repos.is_empty() {
        return Err(GitError::NotFound {
            detail: "no repositories listed by --config".to_owned(),
        });
    }
    let verb_name = &command[0];
    let verb_args = &command[1..];
    let verb = super::dispatch::lookup(verb_name).ok_or_else(|| GitError::Unsupported {
        command: verb_name.clone(),
    })?;
    // The store serializes opens against live handles (reads included),
    // so a listed repository that is already open here cannot be opened
    // again: when the listed root is this context's root, the open store
    // moves into the sub-context for the run and moves back after, the
    // way the oracle's per-repository processes each own exactly one
    // handle. Anything else opens (and drops) its own handle per run.
    let here = std::fs::canonicalize(&ctx.root).ok();
    let mut out = Vec::new();
    let mut result = Ok(());
    for repo in &repos {
        if result.is_err() {
            break;
        }
        let root = std::path::PathBuf::from(repo);
        let dot = if root.file_name().is_some_and(|name| name == ".ruk") {
            root.clone()
        } else {
            root.join(".ruk")
        };
        let same_root = here.as_ref().is_some_and(|here| {
            std::fs::canonicalize(&root)
                .ok()
                .is_some_and(|there| there == *here)
        });
        let reused = if same_root {
            ctx.store.take()
        } else {
            None
        };
        let mut sub = if let Some(store) = reused {
            let kind = store.hash_kind();
            Ctx {
                store: Some(store),
                root: ctx.root.clone(),
                file_base: ctx.file_base.clone(),
                kind: Some(kind),
                env: ctx.env.clone(),
                bare: false,
                cli_config: Vec::new(),
                stderr: Vec::new(),
            }
        } else {
            let store = match ruk_core::store::Store::open(
                &dot,
                std::sync::Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
            ) {
                Ok(store) => store,
                Err(err) => {
                    result = Err(GitError::Io {
                        detail: format!("opening {repo}: {err}"),
                    });
                    break;
                }
            };
            let kind = store.hash_kind();
            Ctx {
                store: Some(store),
                root: root.clone(),
                file_base: root.clone(),
                kind: Some(kind),
                env: ctx.env.clone(),
                bare: false,
                cli_config: Vec::new(),
                stderr: Vec::new(),
            }
        };
        match (verb.run)(&mut sub, verb_args) {
            Ok(bytes) => {
                ctx.stderr.extend_from_slice(&sub.stderr);
                out.extend_from_slice(&bytes);
            }
            Err(err) => {
                ctx.emit_stderr(format!("for-each-repo: {repo}: {err}\n").as_bytes());
                result = Err(err);
            }
        }
        if let Some(store) = sub.store.take() {
            if ctx.store.is_none() {
                ctx.store = Some(store);
            }
        }
    }
    result.map(|()| out)
}

// ---------------------------------------------------------------------------
// last-modified
// ---------------------------------------------------------------------------

/// Finds the blob id at `path` in one commit's tree, if the path exists.
fn blob_at_path(
    store: &Store,
    kind: HashKind,
    oid: Oid,
    path: &[u8],
) -> Result<Option<Oid>, GitError> {
    let tree = super::tree::peel_to_tree(store, kind, oid)?;
    for (name, _, blob) in super::tree::flatten_tree(store, kind, tree)? {
        if name == path {
            return Ok(Some(blob));
        }
    }
    Ok(None)
}

/// Prints the newest commit that last touched each path.
///
/// New in git 2.49 as a last-touch blame answering `<oid>\t<path>` per
/// input. The walk follows first parents from `HEAD`: the first commit
/// whose path blob differs from its parent's (creation, change, and
/// deletion all differ) is the touch. Paths history never carries are
/// `NotFound`.
pub(crate) fn last_modified(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: last-modified [--] <path>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tip = head_oid(store)?;
    let mut chain = Vec::new();
    let mut current = Some(tip);
    while let Some(oid) = current {
        chain.push(oid);
        current = commit_record(store, oid)?
            .parents()
            .iter()
            .filter_map(|head| head.as_git().copied())
            .next();
    }
    let mut out = Vec::new();
    for path in &opts.positionals {
        let bytes = path.as_bytes();
        let mut blobs = Vec::with_capacity(chain.len());
        for oid in &chain {
            blobs.push(blob_at_path(store, kind, *oid, bytes)?);
        }
        let mut found = None;
        for (index, oid) in chain.iter().enumerate() {
            let parent = if index + 1 < chain.len() {
                blobs[index + 1]
            } else {
                None
            };
            if blobs[index] != parent {
                found = Some(*oid);
                break;
            }
        }
        match found {
            Some(oid) => {
                out.extend_from_slice(format!("{}\t{path}\n", oid.to_hex()).as_bytes());
            }
            None => {
                return Err(GitError::NotFound {
                    detail: format!("path {path:?} never appears in HEAD history"),
                });
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// filter-branch (deprecated upstream) and named gaps
// ---------------------------------------------------------------------------

/// Rejects one command family with its reason.
fn gap(command: &str) -> Result<Vec<u8>, GitError> {
    Err(GitError::Unsupported {
        command: command.to_owned(),
    })
}

/// Refuses history rewrites loudly.
///
/// Oracle: `git/git-filter-branch.sh`. Git itself deprecates this script
/// with a warning baked in; here it is a typed refusal pointing at the
/// supported rewrites (`rebase`, `fast-export`/`fast-import`).
pub(crate) fn filter_branch(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("filter-branch is deprecated upstream and unimplemented: use rebase or fast-export/fast-import")
}

/// The store keeps no loose/pack split for redundancy to prune.
///
/// Oracle: `git/builtin/pack-redundant.c`.
pub(crate) fn pack_redundant(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("pack-redundant needs the loose/pack split this store does not keep")
}

/// No browser launcher ships with this interpreter.
///
/// Oracle: `git/git-web--browse.sh`.
pub(crate) fn web_browse(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("web--browse needs a browser launcher: open the URL yourself")
}

/// No interactive merge tool ships with this interpreter.
///
/// Oracle: `git/git-mergetool.sh`.
pub(crate) fn mergetool(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("mergetool needs an interactive merge tool: resolve conflicts, then commit")
}

/// No interactive diff viewer ships with this interpreter.
///
/// Oracle: `git/builtin/difftool.c`.
pub(crate) fn difftool(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("difftool needs an interactive diff viewer: use diff")
}

/// No web server backend ships with this interpreter.
///
/// Oracle: `git/git-instaweb.sh`.
pub(crate) fn instaweb(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("instaweb needs gitweb-style serving this store does not provide")
}

/// No IMAP upload path ships with this interpreter.
///
/// Oracle: `git/builtin/imap-send.c`.
pub(crate) fn imap_send(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("imap-send needs an IMAP upload path this store does not provide")
}

/// No SMTP submit path ships with this interpreter.
///
/// Oracle: `git/git-send-email.pl`.
pub(crate) fn send_email(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("send-email needs an SMTP submit path: use format-patch files")
}

/// Live-connection pack sending is unimplemented; `push` owns delivery.
///
/// Oracle: `git/builtin/send-pack.c`.
pub(crate) fn send_pack(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("send-pack over a live connection is unimplemented: use push")
}

/// No quilt series importer ships with this interpreter.
///
/// Oracle: `git/git-quiltimport.sh`.
pub(crate) fn quiltimport(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("quiltimport needs a quilt series: apply patches with apply/am")
}

/// Network transports stay offline; local paths only.
///
/// Oracle: `git/remote-curl.c`.
pub(crate) fn remote_http(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-http network transport is offline: clone/fetch/push route local paths only")
}

/// Network transports stay offline; local paths only.
///
/// Oracle: `git/remote-curl.c`.
pub(crate) fn remote_https(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-https network transport is offline: clone/fetch/push route local paths only")
}

/// Network transports stay offline; local paths only.
///
/// Oracle: `git/remote-curl.c`.
pub(crate) fn remote_ftp(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-ftp network transport is offline: clone/fetch/push route local paths only")
}

/// Network transports stay offline; local paths only.
///
/// Oracle: `git/remote-curl.c`.
pub(crate) fn remote_ftps(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-ftps network transport is offline: clone/fetch/push route local paths only")
}

/// No subprocess remote transport ships with this interpreter.
///
/// Oracle: `git/builtin/remote-ext.c`.
pub(crate) fn remote_ext(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-ext subprocess transport is unimplemented")
}

/// The file-descriptor test helper ships with no tests to serve.
///
/// Oracle: `git/builtin/remote-fd.c`.
pub(crate) fn remote_fd(_ctx: &mut Ctx, _args: &[String]) -> Result<Vec<u8>, GitError> {
    gap("remote-fd is a test helper and is unimplemented")
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ruk_core::store::{PreparationBudget, Store};
    use ruk_git::GitError;

    use super::super::state::{head_oid, pseudo_write};
    use super::super::{
        CliEnv, Ctx, verbs_branch, verbs_history, verbs_repo, verbs_stage, verbs_transport,
    };
    use super::{
        check_attr, check_ignore, cherry, clean, describe, fmt_merge_msg, get_tar_commit_id,
        interpret_trailers, name_rev, reflog, shortlog, stripspace, var, verify_commit, verify_tag,
    };

    static NEXT: AtomicU64 = AtomicU64::new(50_000);

    fn tmp(case: &str) -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("ruk-misc-{}-{id}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("temp base");
        base
    }

    fn test_env(cwd: &PathBuf) -> CliEnv {
        let vars = [
            ("GIT_AUTHOR_NAME", "Ada"),
            ("GIT_AUTHOR_EMAIL", "ada@example.invalid"),
            ("GIT_COMMITTER_NAME", "Ada"),
            ("GIT_COMMITTER_EMAIL", "ada@example.invalid"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect::<HashMap<String, String>>();
        CliEnv {
            vars,
            cwd: cwd.clone(),
            stdin: None,
        }
    }

    fn open_store(root: &PathBuf) -> Store {
        Store::open(
            &root.join(".ruk"),
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("open store")
    }

    fn mkctx(root: &PathBuf, env: CliEnv) -> Ctx {
        let store = open_store(root);
        let kind = store.hash_kind();
        Ctx {
            store: Some(store),
            root: root.clone(),
            file_base: root.clone(),
            kind: Some(kind),
            env,
            bare: false,
            cli_config: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn fresh(case: &str) -> (PathBuf, Ctx) {
        let base = tmp(case);
        let env = test_env(&base);
        let mut boot = Ctx {
            store: None,
            root: base.clone(),
            file_base: base.clone(),
            kind: None,
            env,
            bare: false,
            cli_config: Vec::new(),
            stderr: Vec::new(),
        };
        verbs_repo::init(&mut boot, &["repo".to_owned()]).expect("init");
        let root = base.join("repo");
        let ctx = mkctx(&root, test_env(&root));
        (root, ctx)
    }

    fn call(
        verb: fn(&mut Ctx, &[String]) -> Result<Vec<u8>, GitError>,
        ctx: &mut Ctx,
        args: &[&str],
    ) -> Result<Vec<u8>, GitError> {
        verb(
            ctx,
            &args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>(),
        )
    }

    fn commit_file(ctx: &mut Ctx, root: &PathBuf, file: &str, body: &[u8], message: &str) {
        std::fs::write(root.join(file), body).expect("write file");
        call(verbs_stage::add, ctx, &[file]).expect("add");
        call(verbs_history::commit, ctx, &["-m", message]).expect("commit");
    }

    fn head_hex(ctx: &Ctx) -> String {
        head_oid(ctx.store().expect("store"))
            .expect("head")
            .to_hex()
    }

    fn stdin_of(ctx: &mut Ctx, input: &[u8]) {
        ctx.env.stdin = Some(input.to_vec());
    }

    #[test]
    fn clean_dry_run_then_force() {
        let (root, mut ctx) = fresh("clean");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        std::fs::write(root.join("untracked.txt"), b"u\n").expect("write");
        std::fs::create_dir_all(root.join("sub/dir")).expect("mkdir");
        std::fs::write(root.join("sub/dir/u.txt"), b"u\n").expect("write");
        let preview =
            String::from_utf8(call(clean, &mut ctx, &["-n"]).expect("dry run")).expect("utf8");
        assert!(
            preview.contains("Would remove untracked.txt"),
            "got {preview:?}"
        );
        assert!(!preview.contains("sub/dir/u.txt"), "got {preview:?}");
        assert!(root.join("untracked.txt").exists());
        call(clean, &mut ctx, &["-f"]).expect("clean");
        assert!(!root.join("untracked.txt").exists());
        assert!(
            root.join("sub/dir/u.txt").exists(),
            "no -d keeps nested files"
        );
        call(clean, &mut ctx, &["-f", "-d"]).expect("clean -d");
        assert!(!root.join("sub/dir/u.txt").exists());
        assert!(call(clean, &mut ctx, &[]).is_err(), "clean needs -f");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn clean_respects_rukignore() {
        let (root, mut ctx) = fresh("clean-ignore");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        std::fs::write(root.join("keep.txt"), b"k\n").expect("write");
        std::fs::write(root.join("skip.log"), b"s\n").expect("write");
        std::fs::write(root.join(".rukignore"), b"*.log\n").expect("write");
        let preview =
            String::from_utf8(call(clean, &mut ctx, &["-n"]).expect("dry run")).expect("utf8");
        assert!(preview.contains("keep.txt"), "got {preview:?}");
        assert!(!preview.contains("skip.log"), "got {preview:?}");
        let preview = String::from_utf8(call(clean, &mut ctx, &["-n", "-x"]).expect("with -x"))
            .expect("utf8");
        assert!(preview.contains("skip.log"), "got {preview:?}");
        let preview = String::from_utf8(call(clean, &mut ctx, &["-n", "-X"]).expect("only -X"))
            .expect("utf8");
        assert!(!preview.contains("keep.txt"), "got {preview:?}");
        assert!(preview.contains("skip.log"), "got {preview:?}");
        call(clean, &mut ctx, &["-f", "-X"]).expect("clean -X");
        assert!(root.join("keep.txt").exists());
        assert!(!root.join("skip.log").exists());
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn describe_nearest_tag() {
        let (root, mut ctx) = fresh("describe");
        commit_file(&mut ctx, &root, "a.txt", b"1\n", "one");
        call(verbs_branch::tag, &mut ctx, &["-a", "-m", "v1", "v1"]).expect("tag");
        commit_file(&mut ctx, &root, "b.txt", b"2\n", "two");
        commit_file(&mut ctx, &root, "c.txt", b"3\n", "three");
        let head = head_hex(&ctx);
        let out =
            String::from_utf8(call(describe, &mut ctx, &[]).expect("describe")).expect("utf8");
        assert_eq!(out.trim(), format!("v1-2-g{}", &head[..7]));
        let exact = String::from_utf8(
            call(describe, &mut ctx, &["--exact-match", "HEAD~2"]).expect("exact"),
        )
        .expect("utf8");
        assert_eq!(exact.trim(), "v1");
        assert!(call(describe, &mut ctx, &["--exact-match"]).is_err());
        let long =
            String::from_utf8(call(describe, &mut ctx, &["--long", "HEAD~2"]).expect("long"))
                .expect("utf8");
        assert!(long.trim().starts_with("v1-0-g"), "got {long:?}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn reflog_show_and_expire() {
        let (root, mut ctx) = fresh("reflog");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        let tip = head_hex(&ctx);
        call(
            verbs_branch::update_ref,
            &mut ctx,
            &["-m", "first", "refs/heads/main", &tip],
        )
        .expect("update-ref");
        call(
            verbs_branch::update_ref,
            &mut ctx,
            &["-m", "second", "refs/heads/main", &tip],
        )
        .expect("update-ref");
        let out = String::from_utf8(call(reflog, &mut ctx, &["show", "main"]).expect("show"))
            .expect("utf8");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "got {out:?}");
        assert!(lines[0].contains("main@{0}: second"), "got {out:?}");
        assert!(lines[1].contains("main@{1}: first"), "got {out:?}");
        call(reflog, &mut ctx, &["delete", "main@{1}"]).expect("delete");
        let out =
            String::from_utf8(call(reflog, &mut ctx, &[]).expect("default show")).expect("utf8");
        assert_eq!(out.lines().count(), 1, "got {out:?}");
        call(reflog, &mut ctx, &["expire", "--expire=now", "main"]).expect("expire");
        assert!(call(reflog, &mut ctx, &["show", "main"]).is_err());
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn shortlog_summary_counts() {
        let (root, mut ctx) = fresh("shortlog");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed it");
        commit_file(&mut ctx, &root, "b.txt", b"b\n", "second it");
        ctx.env
            .vars
            .insert("GIT_AUTHOR_NAME".to_owned(), "Bo".to_owned());
        ctx.env.vars.insert(
            "GIT_AUTHOR_EMAIL".to_owned(),
            "bo@example.invalid".to_owned(),
        );
        commit_file(&mut ctx, &root, "c.txt", b"c\n", "third it");
        let summary =
            String::from_utf8(call(shortlog, &mut ctx, &["-s"]).expect("summary")).expect("utf8");
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(lines.len(), 2, "got {summary:?}");
        assert!(
            lines[0].ends_with("\tAda") && lines[0].contains('2'),
            "got {summary:?}"
        );
        assert!(
            lines[1].ends_with("\tBo") && lines[1].contains('1'),
            "got {summary:?}"
        );
        let full = String::from_utf8(call(shortlog, &mut ctx, &[]).expect("full")).expect("utf8");
        assert!(full.contains("Ada (2):"), "got {full:?}");
        assert!(full.contains("seed it"), "got {full:?}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn cherry_marks_equivalent() {
        let (root, mut ctx) = fresh("cherry");
        commit_file(&mut ctx, &root, "a.txt", b"1\n", "base");
        call(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
        commit_file(&mut ctx, &root, "a.txt", b"2\n", "change a");
        call(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
        commit_file(&mut ctx, &root, "a.txt", b"2\n", "change a again");
        call(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
        commit_file(&mut ctx, &root, "b.txt", b"x\n", "extra");
        let out =
            String::from_utf8(call(cherry, &mut ctx, &["main"]).expect("cherry")).expect("utf8");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "got {out:?}");
        assert!(lines[0].starts_with("- "), "got {out:?}");
        assert!(lines[1].starts_with("+ "), "got {out:?}");
        let verbose = String::from_utf8(call(cherry, &mut ctx, &["-v", "main"]).expect("verbose"))
            .expect("utf8");
        assert!(
            verbose.contains("change a") && verbose.contains("extra"),
            "got {verbose:?}"
        );
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn name_rev_branch_distance() {
        let (root, mut ctx) = fresh("name-rev");
        commit_file(&mut ctx, &root, "a.txt", b"1\n", "one");
        let first = head_hex(&ctx);
        call(verbs_branch::tag, &mut ctx, &["v1"]).expect("tag");
        commit_file(&mut ctx, &root, "b.txt", b"2\n", "two");
        let second = head_hex(&ctx);
        commit_file(&mut ctx, &root, "c.txt", b"3\n", "three");
        let head = head_hex(&ctx);
        let out =
            String::from_utf8(call(name_rev, &mut ctx, &["HEAD"]).expect("head")).expect("utf8");
        assert_eq!(out.trim(), format!("{head} main"));
        // The tagged commit names exactly; the untagged middle commit
        // names by distance back from the branch tip.
        let out =
            String::from_utf8(call(name_rev, &mut ctx, &[&first]).expect("first")).expect("utf8");
        assert_eq!(out.trim(), format!("{first} tags/v1"));
        let out =
            String::from_utf8(call(name_rev, &mut ctx, &[&second]).expect("second")).expect("utf8");
        assert_eq!(out.trim(), format!("{second} main~1"));
        let out = String::from_utf8(call(name_rev, &mut ctx, &["--tags", &first]).expect("tags"))
            .expect("utf8");
        assert_eq!(out.trim(), format!("{first} tags/v1"));
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn check_ignore_with_file() {
        let (root, mut ctx) = fresh("check-ignore");
        assert!(call(check_ignore, &mut ctx, &["a.txt"]).is_err());
        std::fs::write(root.join(".rukignore"), b"*.log\n!keep.log\n").expect("write");
        let out = String::from_utf8(call(check_ignore, &mut ctx, &["a.log"]).expect("hit"))
            .expect("utf8");
        assert_eq!(out, "a.log\n");
        assert!(call(check_ignore, &mut ctx, &["keep.log"]).is_err());
        assert!(call(check_ignore, &mut ctx, &["a.txt"]).is_err());
        let verbose =
            String::from_utf8(call(check_ignore, &mut ctx, &["-v", "a.log"]).expect("verbose"))
                .expect("utf8");
        assert_eq!(verbose, ".rukignore:1:*.log:a.log\n");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn check_attr_values() {
        let (root, mut ctx) = fresh("check-attr");
        std::fs::write(root.join(".rukattributes"), b"*.txt text\n*.bin -text\n").expect("write");
        let out =
            String::from_utf8(call(check_attr, &mut ctx, &["text", "--", "f.txt"]).expect("set"))
                .expect("utf8");
        assert_eq!(out, "f.txt: text: set\n");
        let out =
            String::from_utf8(call(check_attr, &mut ctx, &["text", "--", "f.bin"]).expect("unset"))
                .expect("utf8");
        assert_eq!(out, "f.bin: text: unset\n");
        let out = String::from_utf8(
            call(check_attr, &mut ctx, &["binary", "--", "f.txt"]).expect("unspecified"),
        )
        .expect("utf8");
        assert_eq!(out, "f.txt: binary: unspecified\n");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn stripspace_collapses() {
        let (root, mut ctx) = fresh("stripspace");
        stdin_of(&mut ctx, b"  a  \n\n\nb   \n\n");
        let out = call(stripspace, &mut ctx, &[]).expect("stripspace");
        assert_eq!(out, b"  a\n\nb\n");
        stdin_of(&mut ctx, b"# comment\n  # indented\na\n");
        let out = call(stripspace, &mut ctx, &["--strip-comments"]).expect("comments");
        assert_eq!(out, b"a\n");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn trailers_parse_and_append() {
        let (root, mut ctx) = fresh("trailers");
        stdin_of(&mut ctx, b"subject\n\nbody\n\nSigned-off-by: Ada <a@x>\n");
        let out = call(interpret_trailers, &mut ctx, &["--only-trailers"]).expect("only");
        assert_eq!(out, b"Signed-off-by: Ada <a@x>\n");
        stdin_of(&mut ctx, b"subject\n");
        let out = call(
            interpret_trailers,
            &mut ctx,
            &["--trailer", "Reviewed-by: Bo <b@x>"],
        )
        .expect("append");
        assert_eq!(out, b"subject\n\nReviewed-by: Bo <b@x>\n");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn var_idents() {
        let (root, ctx) = fresh("var");
        let mut ctx = ctx;
        let out = String::from_utf8(call(var, &mut ctx, &["GIT_AUTHOR_IDENT"]).expect("author"))
            .expect("utf8");
        assert!(out.starts_with("Ada <ada@example.invalid> "), "got {out:?}");
        let out = String::from_utf8(call(var, &mut ctx, &["-l"]).expect("list")).expect("utf8");
        assert!(out.contains("GIT_AUTHOR_IDENT="), "got {out:?}");
        assert!(call(var, &mut ctx, &["NOPE"]).is_err());
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn tar_commit_round_trip() {
        let (root, mut ctx) = fresh("tar");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        let head = head_hex(&ctx);
        let tar = call(verbs_transport::archive, &mut ctx, &["HEAD"]).expect("archive");
        assert!(!tar.is_empty());
        stdin_of(&mut ctx, &tar);
        let out = String::from_utf8(call(get_tar_commit_id, &mut ctx, &[]).expect("commit id"))
            .expect("utf8");
        assert_eq!(out.trim(), head);
        stdin_of(&mut ctx, b"nope");
        assert!(call(get_tar_commit_id, &mut ctx, &[]).is_err());
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn merge_msg_from_fetch_head() {
        let (root, mut ctx) = fresh("fmt-merge-msg");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        call(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
        commit_file(&mut ctx, &root, "b.txt", b"b\n", "side work");
        let tip = head_hex(&ctx);
        call(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
        let store = ctx.store().expect("store").clone();
        pseudo_write(
            &store,
            "FETCH_HEAD",
            format!("{tip}\trefs/heads/feature\n").into_bytes(),
        )
        .expect("fetch head");
        let out =
            String::from_utf8(call(fmt_merge_msg, &mut ctx, &[]).expect("message")).expect("utf8");
        assert_eq!(out, "Merge branch 'feature'\n");
        let out = String::from_utf8(call(fmt_merge_msg, &mut ctx, &["--log"]).expect("log"))
            .expect("utf8");
        assert!(out.contains("side work"), "got {out:?}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn verify_tag_refuses_without_signature() {
        let (root, mut ctx) = fresh("verify-tag");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        call(verbs_branch::tag, &mut ctx, &["-a", "-m", "v1", "v1"]).expect("tag");
        let err = call(verify_tag, &mut ctx, &["v1"]).expect_err("no signatures");
        assert!(err.to_string().contains("signature"), "got {err:?}");
        assert!(call(verify_tag, &mut ctx, &["missing"]).is_err());
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn verify_commit_refuses_without_signature() {
        let (root, mut ctx) = fresh("verify-commit");
        commit_file(&mut ctx, &root, "a.txt", b"a\n", "seed");
        let err = call(verify_commit, &mut ctx, &["HEAD"]).expect_err("no signatures");
        assert!(err.to_string().contains("signature"), "got {err:?}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }
}
