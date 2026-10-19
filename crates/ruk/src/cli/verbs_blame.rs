//! `blame` and `annotate`: line-level attribution.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `blame` | first-parent history walk + per-commit LCS alignment | implemented (default `<oid> (<author> <date> <line>) <content>`, `-L`, `-p`/`--porcelain`, `--line-porcelain`, `-l`, worktree overlay with `Not Committed Yet`) |
//! | `annotate` | same entry point as `blame` | implemented (alias row) |
//!
//! The walk follows first parents from the blamed tip, the way the oracle
//! does without `--no-first-parent`: merges attribute through their first
//! parent only. At each step the parent file and the current file align
//! through the classic LCS table (the same alignment `diff` renders), and
//! every surviving line carries its tip index down into the parent while
//! only parent-absent lines take the current commit as their origin. The
//! advisory on this verb is that single-hop attribution loses ownership;
//! the queue below exists so no line is ever assigned without surviving
//! every intermediate alignment.
//!
//! Oracle anchor: `git/builtin/blame.c` (`cmd_blame`, `cmd_annotate`).
//!
//! Named gaps: `-C`/`-M` parse but do not enable cross-file copy/move
//! detection (lines are attributed within the blamed path's own history);
//! `--first-parent` is accepted and inert because first-parent is the only
//! walk; `-L :<funcname>` and `/regex/` ranges are rejected with the
//! accepted shapes named.

use std::collections::{HashMap, HashSet};

use ruk_core::commit::CommitRecord;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;

use super::state::{commit_record, head_oid, now_seconds, replace_redirect};
use super::tree::{commit_tree_oid, flatten_tree, read_object_bytes};
use super::{Ctx, FlagSpec, collect};

/// LCS cell cap: `diff` omits hunks past four million cells instead of
/// truncating silently; blame attributes the surviving lines to the newer
/// commit and stops, for the same reason.
const LCS_CELL_CAP: usize = 4_000_000;

/// Abbreviation width for the default format, matching the oracle's blame
/// column (not the seven-char log convention elsewhere in this tool).
const BLAME_ABBREV: usize = 8;

/// One attributed final line: the introducing commit plus its line number
/// there, or `None` for an uncommitted worktree line.
type Origin = Option<(Oid, usize)>;

/// Annotates one path with its introducing commits.
///
/// Oracle: `git/builtin/blame.c`. With no `<rev>` the worktree file is
/// blamed and worktree-only lines report `Not Committed Yet`; with an
/// explicit revision only committed history is read.
pub(crate) fn blame(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let args = normalize_copy_flags(args);
    let specs = [
        FlagSpec {
            long: "line-range",
            short: Some('L'),
            takes_value: true,
        },
        FlagSpec {
            long: "porcelain",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "line-porcelain",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "long",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "first-parent",
            short: None,
            takes_value: false,
        },
        // Parsed and inert: no cross-file copy/move detection (see the
        // module header). Bare flags only; `-C<num>` is normalized away in
        // [`normalize_copy_flags`] because `collect` cannot spell an
        // optional value.
        FlagSpec {
            long: "find-copies",
            short: Some('C'),
            takes_value: false,
        },
        FlagSpec {
            long: "find-moves",
            short: Some('M'),
            takes_value: false,
        },
    ];
    let (rev_args, dash_path) = split_blame_dash(&args);
    let opts = collect(&rev_args, &specs)?;
    let (rev_text, path_text) = blame_rev_and_path(&opts.positionals, &dash_path)?;
    if path_text.is_empty() {
        return Err(GitError::Usage {
            detail: "usage: blame [<options>] [<rev> [--] <path>]".to_owned(),
        });
    }
    let path = path_text.as_bytes().to_vec();
    let store = ctx.store()?;
    let kind = ctx.kind()?;

    let porcelain = opts.is_set("porcelain") || opts.is_set("line-porcelain");
    let per_line = opts.is_set("line-porcelain");
    let long = opts.is_set("long");

    // Resolve the blamed tip. No revision means the worktree file overlaid
    // on `HEAD`, the way the oracle blames the working tree by default.
    let (tip, worktree) = match rev_text {
        Some(rev) => {
            let oid = replace_redirect(
                store,
                super::verbs_history::resolve_local(store, kind, &rev)?,
            );
            commit_record(store, oid)?;
            (oid, None)
        }
        None => {
            let tip = head_oid(store)?;
            if ctx.bare {
                (tip, None)
            } else {
                let bytes = read_worktree_path(ctx, &path)?;
                (tip, Some(bytes))
            }
        }
    };

    let blamed = blame_committed(store, kind, tip, &path)?;
    // Overlay the worktree when no revision was named: lines the worktree
    // added take the uncommitted origin, surviving lines keep the committed
    // attribution they carried through the whole walk.
    let viewed = match worktree {
        None => BlamedFile {
            lines: blamed.lines,
            origins: blamed.origins,
        },
        Some(bytes) => {
            if bytes == blamed.tip_bytes {
                BlamedFile {
                    lines: blamed.lines,
                    origins: blamed.origins,
                }
            } else {
                let (lines, origins) = overlay_worktree(&blamed.lines, &blamed.origins, &bytes)?;
                BlamedFile { lines, origins }
            }
        }
    };

    let total = viewed.lines.len();
    let range = match opts.single("line-range")? {
        Some(spec) => parse_line_range(&spec, total)?,
        None => (1, total),
    };
    let facts = load_commit_facts(store, &viewed.origins)?;

    let mut out = Vec::new();
    if porcelain {
        let mut view = Porcelain {
            store,
            kind,
            path: &path,
            file: &viewed,
            facts: &facts,
            range,
            out: &mut out,
            previous_cache: HashMap::new(),
        };
        if per_line {
            view.run_per_line()?;
        } else {
            view.run_grouped()?;
        }
    } else {
        render_default(&mut out, &viewed, &facts, range, long)?;
    }
    Ok(out)
}

/// One blamed file: final lines plus one origin per line.
struct BlamedFile {
    /// Final file lines without terminators.
    lines: Vec<Vec<u8>>,
    /// One origin per final line.
    origins: Vec<Origin>,
}

/// Splits blame positionals and the `--` path into the optional revision
/// and the single blamed path.
fn blame_rev_and_path(
    positionals: &[String],
    dash_path: &[String],
) -> Result<(Option<String>, String), GitError> {
    let usage = || GitError::Usage {
        detail: "usage: blame [<options>] [<rev> [--] <path>]".to_owned(),
    };
    if dash_path.len() > 1 {
        return Err(usage());
    }
    if let Some(path) = dash_path.first() {
        if positionals.len() > 1 {
            return Err(usage());
        }
        return Ok((positionals.first().cloned(), path.clone()));
    }
    match positionals {
        [] => Err(usage()),
        [path] => Ok((None, path.clone())),
        [rev, path] => Ok((Some(rev.clone()), path.clone())),
        _ => Err(usage()),
    }
}

/// Splits blame args at the first `--`: everything after names the path
/// even when it looks like a revision. [`collect`] erases the marker, so
/// the split happens first.
fn split_blame_dash(args: &[String]) -> (Vec<String>, Vec<String>) {
    match args.iter().position(|arg| arg == "--") {
        None => (args.to_vec(), Vec::new()),
        Some(at) => (args[..at].to_vec(), args[at + 1..].to_vec()),
    }
}

/// Rewrites attached `-C<num>`/`-M<num>` to their bare flags before
/// collecting: the options take an optional value, which [`collect`]
/// cannot spell, and the values are inert here in any case.
fn normalize_copy_flags(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| {
            if arg.len() > 2
                && (arg.starts_with("-C") || arg.starts_with("-M"))
                && arg[2..].bytes().all(|byte| byte.is_ascii_digit())
            {
                arg[..2].to_owned()
            } else {
                arg.clone()
            }
        })
        .collect()
}

/// Reads one worktree path under the context base, refusing escapes the
/// way the tree helpers do.
fn read_worktree_path(ctx: &Ctx, path: &[u8]) -> Result<Vec<u8>, GitError> {
    let text = std::str::from_utf8(path).map_err(|_| GitError::Invalid {
        detail: format!(
            "bad path {:?}: not valid UTF-8",
            String::from_utf8_lossy(path)
        ),
    })?;
    if text.is_empty() || text.starts_with('/') || text.split('/').any(|part| part == "..") {
        return Err(GitError::Invalid {
            detail: format!("bad path {text:?}"),
        });
    }
    std::fs::read(ctx.file_base.join(text)).map_err(|err| GitError::NotFound {
        detail: format!("cannot read worktree path {text:?}: {err}"),
    })
}

/// The committed blame of one path at one tip: tip bytes, tip lines, and
/// one origin per tip line.
struct CommittedBlame {
    /// Raw tip bytes, for the worktree-equality fast path.
    tip_bytes: Vec<u8>,
    /// Tip file lines without terminators.
    lines: Vec<Vec<u8>>,
    /// One origin per tip line.
    origins: Vec<Origin>,
}

/// Walks the first-parent chain from `tip`, attributing each tip line to
/// the commit that introduced it.
fn blame_committed(
    store: &Store,
    kind: HashKind,
    tip: Oid,
    path: &[u8],
) -> Result<CommittedBlame, GitError> {
    let tip_bytes = read_path_at(store, kind, tip, path)?.ok_or_else(|| GitError::NotFound {
        detail: format!(
            "{:?} is not in {}",
            String::from_utf8_lossy(path),
            tip.to_hex(),
        ),
    })?;
    let tip_lines = split_owned(&tip_bytes);
    let mut origins: Vec<Origin> = vec![None; tip_lines.len()];
    // `queue[i]` is the tip line index that current-file line `i` carries,
    // or [`NO_DESCENDANT`] when no tip line descends from it (a parent-only
    // line the child deleted). The queue spans the whole current file at
    // every step — not just the kept lines — because the next alignment
    // indexes the full parent file. A line takes an origin only when its
    // own level introduces it, and every surviving line keeps its exact
    // index in the introducing commit.
    let mut queue: Vec<usize> = (0..tip_lines.len()).collect();
    let mut current_lines = tip_lines.clone();
    let mut commit = tip;
    // Replace refs redirect every read (`commit_record` maps the replaced
    // oid to its replacement) while the walk advances through raw parent
    // oids. When a replacement's own history reaches back to the replaced
    // oid (first replaced by its child second, whose parent is first), the
    // raw parent re-redirects to the replacement and the same commits
    // revisit forever. Stop on the second visit and attribute leftovers to
    // the effective (redirected) commit.
    let mut visited: HashSet<Oid> = HashSet::new();

    loop {
        if !visited.insert(commit) {
            assign_remaining(&mut origins, &queue, replace_redirect(store, commit));
            break;
        }
        let record = commit_record(store, commit)?;
        let Some(parent) = first_parent_oid(&record) else {
            // Root commit: everything still unassigned entered here, at
            // its position in this file.
            assign_remaining(&mut origins, &queue, commit);
            break;
        };
        let Some(parent_bytes) = read_path_at(store, kind, parent, path)? else {
            // The path enters in `commit`: everything left is its own.
            assign_remaining(&mut origins, &queue, commit);
            break;
        };
        let parent_lines: Vec<Vec<u8>> = split_owned(&parent_bytes);
        let Some(script) = lcs_script_checked(&parent_lines, &current_lines) else {
            // Past the alignment bound: attribute the rest here and stop
            // rather than misattributing older lines.
            assign_remaining(&mut origins, &queue, commit);
            break;
        };
        let mut next_queue: Vec<usize> = Vec::with_capacity(parent_lines.len());
        let mut current_index = 0;
        for op in &script {
            match op {
                BlameOp::Keep => {
                    next_queue.push(queue[current_index]);
                    current_index += 1;
                }
                BlameOp::Delete => {
                    // A parent-only line: no tip line descends from it,
                    // but the slot keeps the queue full-width for the
                    // next alignment.
                    next_queue.push(NO_DESCENDANT);
                }
                BlameOp::Insert => {
                    let carried = queue[current_index];
                    if carried != NO_DESCENDANT && origins[carried].is_none() {
                        origins[carried] = Some((commit, current_index));
                    }
                    current_index += 1;
                }
            }
        }
        current_lines = parent_lines;
        queue = next_queue;
        commit = parent;
        if queue.is_empty() || origins.iter().all(|origin| origin.is_some()) {
            break;
        }
    }

    Ok(CommittedBlame {
        tip_bytes,
        lines: tip_lines,
        origins,
    })
}

/// No tip line descends from this queue slot (a parent-only line).
const NO_DESCENDANT: usize = usize::MAX;

/// Attributes every still-unassigned carried line to `commit`. The queue
/// position is the line's index in `commit`'s file, so boundary and
/// oversize fallbacks keep exact origin line numbers. Slots with no tip
/// descendant are skipped.
fn assign_remaining(origins: &mut [Origin], queue: &[usize], commit: Oid) {
    for (at, carried) in queue.iter().enumerate() {
        if *carried != NO_DESCENDANT && origins[*carried].is_none() {
            origins[*carried] = Some((commit, at));
        }
    }
}

/// Reads the blob behind `path` in one commit's tree, or `None` when the
/// path is absent there.
fn read_path_at(
    store: &Store,
    kind: HashKind,
    commit: Oid,
    path: &[u8],
) -> Result<Option<Vec<u8>>, GitError> {
    let record = commit_record(store, commit)?;
    let tree = commit_tree_oid(&record)?;
    for (entry_path, _, blob) in flatten_tree(store, kind, tree)? {
        if entry_path == path {
            let (object_kind, body) = read_object_bytes(store, blob)?;
            if object_kind != ObjectKind::Blob {
                return Err(GitError::Invalid {
                    detail: format!(
                        "{:?} in {} is not a blob",
                        String::from_utf8_lossy(path),
                        commit.to_hex(),
                    ),
                });
            }
            return Ok(Some(body));
        }
    }
    Ok(None)
}

/// Lists the first parent oid of one commit, if any.
fn first_parent_oid(record: &CommitRecord) -> Option<Oid> {
    record.parents().iter().find_map(|parent| match parent {
        Head::Git { oid } => Some(*oid),
        Head::Conflicted { .. } => None,
    })
}

/// Splits bytes into owned lines without terminators. Empty input is no
/// lines; a trailing newline never invents a phantom empty line.
fn split_owned(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<Vec<u8>> = bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.to_vec())
        .collect();
    if lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    lines
}

/// One line-diff operation between two owned line lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlameOp {
    /// Present on both sides.
    Keep,
    /// Present only before.
    Delete,
    /// Present only after.
    Insert,
}

/// Aligns two line lists with the classic LCS table, or `None` past the
/// cell bound.
fn lcs_script_checked(old: &[Vec<u8>], new: &[Vec<u8>]) -> Option<Vec<BlameOp>> {
    if old.len().saturating_mul(new.len()) > LCS_CELL_CAP {
        return None;
    }
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
            script.push(BlameOp::Keep);
            i += 1;
            j += 1;
        } else if table[(i + 1) * cols + j] >= table[i * cols + j + 1] {
            script.push(BlameOp::Delete);
            i += 1;
        } else {
            script.push(BlameOp::Insert);
            j += 1;
        }
    }
    for _ in &old[i..] {
        script.push(BlameOp::Delete);
    }
    for _ in &new[j..] {
        script.push(BlameOp::Insert);
    }
    Some(script)
}

/// Overlays worktree bytes on a committed blame: surviving lines keep
/// their committed origins, worktree-added lines take the uncommitted
/// origin.
fn overlay_worktree(
    committed_lines: &[Vec<u8>],
    committed_origins: &[Origin],
    worktree_bytes: &[u8],
) -> Result<(Vec<Vec<u8>>, Vec<Origin>), GitError> {
    let worktree_lines = split_owned(worktree_bytes);
    // An empty committed file needs no special case: aligning nothing
    // against the worktree yields one `Insert` per worktree line, so the
    // general path below attributes every line as uncommitted.
    let Some(script) = lcs_script_checked(committed_lines, &worktree_lines) else {
        let origins = vec![None; worktree_lines.len()];
        return Ok((worktree_lines, origins));
    };
    let mut lines = Vec::with_capacity(worktree_lines.len());
    let mut origins = Vec::with_capacity(worktree_lines.len());
    let (mut committed_index, mut worktree_index) = (0, 0);
    for op in &script {
        match op {
            BlameOp::Keep => {
                lines.push(worktree_lines[worktree_index].clone());
                origins.push(committed_origins[committed_index]);
                committed_index += 1;
                worktree_index += 1;
            }
            BlameOp::Delete => {
                committed_index += 1;
            }
            BlameOp::Insert => {
                lines.push(worktree_lines[worktree_index].clone());
                origins.push(None);
                worktree_index += 1;
            }
        }
    }
    Ok((lines, origins))
}

/// Facts for rendering one origin commit: signatures plus subject.
struct OriginFacts {
    /// Full hex of the origin commit.
    hex: String,
    /// Author name bytes.
    author: Vec<u8>,
    /// Author email bytes.
    email: Vec<u8>,
    /// Author timestamp and offset text.
    author_time: i64,
    author_tz: String,
    /// Committer name, email, timestamp, offset text.
    committer: Vec<u8>,
    committer_email: Vec<u8>,
    committer_time: i64,
    committer_tz: String,
    /// First message line.
    summary: Vec<u8>,
    /// Whether the origin commit is a root (boundary marker).
    boundary: bool,
    /// First-parent hex for the porcelain `previous` line, when the
    /// origin commit has a parent at all.
    previous: Option<String>,
}

/// Loads facts for every distinct origin commit.
fn load_commit_facts(
    store: &Store,
    origins: &[Origin],
) -> Result<HashMap<Oid, OriginFacts>, GitError> {
    let mut out = HashMap::new();
    for origin in origins.iter().flatten() {
        if out.contains_key(&origin.0) {
            continue;
        }
        let record = commit_record(store, origin.0)?;
        let author = record.author().map_err(|err| GitError::Corrupt {
            detail: format!("bad author ident in {}: {err}", origin.0.to_hex()),
        })?;
        let committer = record.committer().map_err(|err| GitError::Corrupt {
            detail: format!("bad committer ident in {}: {err}", origin.0.to_hex()),
        })?;
        let summary = record
            .message()
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default()
            .to_vec();
        out.insert(
            origin.0,
            OriginFacts {
                hex: origin.0.to_hex(),
                author: author.name.as_bytes().to_vec(),
                email: author.email.as_bytes().to_vec(),
                author_time: author.timestamp,
                author_tz: author.offset.to_string(),
                committer: committer.name.as_bytes().to_vec(),
                committer_email: committer.email.as_bytes().to_vec(),
                committer_time: committer.timestamp,
                committer_tz: committer.offset.to_string(),
                summary,
                boundary: first_parent_oid(&record).is_none(),
                previous: first_parent_oid(&record).map(|parent| parent.to_hex()),
            },
        );
    }
    Ok(out)
}

/// Parses `-L <start>[,<end>]`: 1-based inclusive bounds where a negative
/// bound counts back from the last line (`-1` is the last line),
/// `start,+count` names `count` lines from `start`, a bare `<start>` names
/// one line, and an empty end runs to the last line. `/regex/` and
/// `:<funcname>` ranges fail closed naming these shapes.
fn parse_line_range(spec: &str, total: usize) -> Result<(usize, usize), GitError> {
    let shapes = || GitError::Invalid {
        detail: format!("bad -L {spec:?}: want <start>[,<end>] with 1-based line numbers"),
    };
    if spec.starts_with('/') || spec.starts_with(':') {
        return Err(shapes());
    }
    let (start_text, end_text) = match spec.split_once(',') {
        Some((start, end)) => (start, Some(end)),
        None => (spec, None),
    };
    let absolute = |text: &str| -> Result<usize, GitError> {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(shapes());
        }
        text.parse().map_err(|_| shapes())
    };
    let bound = |text: &str| -> Result<usize, GitError> {
        if let Some(back) = text.strip_prefix('-') {
            if back.is_empty() || !back.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(shapes());
            }
            let back: usize = back.parse().map_err(|_| shapes())?;
            if back == 0 || back > total {
                return Err(out_of_lines(spec, total));
            }
            return Ok(total - back + 1);
        }
        if text.strip_prefix('+').is_some() {
            return Err(shapes());
        }
        absolute(text)
    };
    let start = bound(start_text)?;
    let end = match end_text {
        None => start,
        Some("") => total,
        Some(text) => {
            if let Some(count_text) = text.strip_prefix('+') {
                let count: usize = absolute(count_text)?;
                if count == 0 {
                    return Err(shapes());
                }
                start.saturating_add(count - 1)
            } else {
                bound(text)?
            }
        }
    };
    if start == 0 || start > total {
        return Err(out_of_lines(spec, total));
    }
    if end < start {
        return Err(GitError::Invalid {
            detail: format!("bad -L {spec:?}: end line {end} is before start line {start}"),
        });
    }
    Ok((start, end.min(total)))
}

/// Reports a `-L` bound outside the blamed file.
fn out_of_lines(spec: &str, total: usize) -> GitError {
    GitError::Invalid {
        detail: format!("-L {spec:?}: file has only {total} lines"),
    }
}

/// The origin identity shared by one porcelain group: the origin commit,
/// or uncommitted.
type GroupKey = Option<Oid>;

/// Renders the default format: `<oid> (<author> <date> <line>) <content>`,
/// with a `^` prefix on boundary-commit lines.
fn render_default(
    out: &mut Vec<u8>,
    file: &BlamedFile,
    facts: &HashMap<Oid, OriginFacts>,
    range: (usize, usize),
    long: bool,
) -> Result<(), GitError> {
    let now = now_seconds()?;
    for (index, line) in file.lines.iter().enumerate() {
        let lineno = index + 1;
        if lineno < range.0 || lineno > range.1 {
            continue;
        }
        match file.origins[index] {
            Some((oid, _)) => {
                let row = blame_facts(facts, &oid)?;
                let id = if long {
                    row.hex.clone()
                } else {
                    row.hex.chars().take(BLAME_ABBREV).collect()
                };
                let prefix = if row.boundary { "^" } else { "" };
                out.extend_from_slice(
                    format!(
                        "{prefix}{id} ({} {} {lineno}) ",
                        String::from_utf8_lossy(&row.author),
                        blame_date(row.author_time, &row.author_tz)?,
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(line);
                out.push(b'\n');
            }
            None => {
                out.extend_from_slice(
                    format!(
                        "00000000 (Not Committed Yet {} {lineno}) ",
                        blame_date(now, "+0000")?,
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(line);
                out.push(b'\n');
            }
        }
    }
    Ok(())
}

/// Looks up one origin commit's facts, naming the missing commit instead
/// of panicking.
fn blame_facts<'a>(
    facts: &'a HashMap<Oid, OriginFacts>,
    oid: &Oid,
) -> Result<&'a OriginFacts, GitError> {
    facts.get(oid).ok_or_else(|| GitError::Corrupt {
        detail: format!("missing blame facts for {}", oid.to_hex()),
    })
}

/// One porcelain render: the blamed file plus its facts and the output it
/// fills. Grouping the travelling state keeps every method within the
/// parameter budget.
struct Porcelain<'a> {
    /// The open native store, for `previous`-path checks.
    store: &'a Store,
    /// Object format of the open repository.
    kind: HashKind,
    /// Blamed path bytes.
    path: &'a [u8],
    /// Blamed lines and origins.
    file: &'a BlamedFile,
    /// Facts per distinct origin commit.
    facts: &'a HashMap<Oid, OriginFacts>,
    /// In-range line bounds, 1-based inclusive.
    range: (usize, usize),
    /// Output being filled.
    out: &'a mut Vec<u8>,
    /// Memoized `previous`-path checks per origin commit.
    previous_cache: HashMap<Oid, bool>,
}

impl Porcelain<'_> {
    /// Renders porcelain (`-p`): one header group per origin run, then
    /// `\t<content>` lines.
    fn run_grouped(&mut self) -> Result<(), GitError> {
        self.run_impl(false)
    }

    /// Renders per-line porcelain (`--line-porcelain`): every line gets
    /// its own header.
    fn run_per_line(&mut self) -> Result<(), GitError> {
        self.run_impl(true)
    }

    /// Shared porcelain engine behind [`Porcelain::run_grouped`] and
    /// [`Porcelain::run_per_line`].
    fn run_impl(&mut self, per_line: bool) -> Result<(), GitError> {
        let mut group: Vec<usize> = Vec::new();
        for (index, _) in self.file.lines.iter().enumerate() {
            let lineno = index + 1;
            if lineno < self.range.0 || lineno > self.range.1 {
                continue;
            }
            let same = !per_line
                && group
                    .last()
                    .is_some_and(|last| self.key(*last) == self.key(index));
            if group.is_empty() || same {
                group.push(index);
            } else {
                let pending = std::mem::take(&mut group);
                self.flush(&pending)?;
                group.push(index);
            }
        }
        let pending = std::mem::take(&mut group);
        self.flush(&pending)?;
        Ok(())
    }

    /// The grouping identity of one line: origin commit or uncommitted.
    /// Origin line numbers within a commit never split a group.
    fn key(&self, index: usize) -> GroupKey {
        self.file.origins[index].map(|(oid, _)| oid)
    }

    /// Emits one group's header plus its `\t<content>` lines.
    fn flush(&mut self, group: &[usize]) -> Result<(), GitError> {
        if group.is_empty() {
            return Ok(());
        }
        let first = group[0];
        match self.file.origins[first] {
            Some((oid, at)) => self.flush_committed(group, first, &oid, at)?,
            None => self.flush_uncommitted(group, first)?,
        }
        for index in group {
            self.out.push(b'\t');
            let line = self.file.lines[*index].clone();
            self.out.extend_from_slice(&line);
            self.out.push(b'\n');
        }
        Ok(())
    }

    /// Emits one committed group's header.
    fn flush_committed(
        &mut self,
        group: &[usize],
        first: usize,
        oid: &Oid,
        at: usize,
    ) -> Result<(), GitError> {
        let hex;
        let author;
        let email;
        let author_time;
        let author_tz;
        let committer;
        let committer_email;
        let committer_time;
        let committer_tz;
        let summary;
        let boundary;
        let previous;
        {
            let row = blame_facts(self.facts, oid)?;
            hex = row.hex.clone();
            author = row.author.clone();
            email = row.email.clone();
            author_time = row.author_time;
            author_tz = row.author_tz.clone();
            committer = row.committer.clone();
            committer_email = row.committer_email.clone();
            committer_time = row.committer_time;
            committer_tz = row.committer_tz.clone();
            summary = row.summary.clone();
            boundary = row.boundary;
            previous = row.previous.clone();
        }
        let path_text = String::from_utf8_lossy(self.path).into_owned();
        self.out.extend_from_slice(
            format!("{} {} {} {}\n", hex, at + 1, first + 1, group.len()).as_bytes(),
        );
        Self::field(self.out, "author", &author);
        self.out.extend_from_slice(
            format!("author-mail <{}>\n", String::from_utf8_lossy(&email)).as_bytes(),
        );
        self.out.extend_from_slice(
            format!("author-time {author_time}\nauthor-tz {author_tz}\n").as_bytes(),
        );
        Self::field(self.out, "committer", &committer);
        self.out.extend_from_slice(
            format!(
                "committer-mail <{}>\n",
                String::from_utf8_lossy(&committer_email)
            )
            .as_bytes(),
        );
        self.out.extend_from_slice(
            format!("committer-time {committer_time}\ncommitter-tz {committer_tz}\n").as_bytes(),
        );
        Self::field(self.out, "summary", &summary);
        if let Some(parent_hex) = previous {
            if self.previous_holds(*oid)? {
                self.out
                    .extend_from_slice(format!("previous {parent_hex} {path_text}\n").as_bytes());
            }
        }
        if boundary {
            self.out.extend_from_slice(b"boundary\n");
        }
        self.out
            .extend_from_slice(format!("filename {path_text}\n").as_bytes());
        Ok(())
    }

    /// Emits one uncommitted group's header.
    fn flush_uncommitted(&mut self, group: &[usize], first: usize) -> Result<(), GitError> {
        let now = now_seconds()?;
        let zeros = "0".repeat(self.hex_width());
        let path_text = String::from_utf8_lossy(self.path).into_owned();
        self.out.extend_from_slice(
            format!("{zeros} {} {} {}\n", first + 1, first + 1, group.len()).as_bytes(),
        );
        self.out.extend_from_slice(b"author Not Committed Yet\n");
        self.out
            .extend_from_slice(b"author-mail <not.committed.yet>\n");
        self.out
            .extend_from_slice(format!("author-time {now}\nauthor-tz +0000\n").as_bytes());
        self.out.extend_from_slice(b"committer Not Committed Yet\n");
        self.out
            .extend_from_slice(b"committer-mail <not.committed.yet>\n");
        self.out
            .extend_from_slice(format!("committer-time {now}\ncommitter-tz +0000\n").as_bytes());
        self.out.extend_from_slice(b"summary Not Committed Yet\n");
        self.out
            .extend_from_slice(format!("filename {path_text}\n").as_bytes());
        Ok(())
    }

    /// Reports whether the origin commit's parent still holds the blamed
    /// path, qualifying the porcelain `previous` line. Checked once per
    /// distinct commit.
    fn previous_holds(&mut self, commit: Oid) -> Result<bool, GitError> {
        if let Some(hit) = self.previous_cache.get(&commit) {
            return Ok(*hit);
        }
        let parent = self.facts.get(&commit).and_then(|row| row.previous.clone());
        let holds = match parent {
            None => false,
            Some(hex) => {
                let parent = Oid::from_hex(&hex).map_err(|err| GitError::Corrupt {
                    detail: format!("bad parent id {hex:?}: {err}"),
                })?;
                read_path_at(self.store, self.kind, parent, self.path)?.is_some()
            }
        };
        self.previous_cache.insert(commit, holds);
        Ok(holds)
    }

    /// Width of the zero oid for the uncommitted porcelain header: the
    /// store's hash width in hex.
    fn hex_width(&self) -> usize {
        match self.store.hash_kind() {
            HashKind::Sha1 => 40,
            HashKind::Sha256 => 64,
        }
    }

    /// Emits one `name <lossy-bytes>` porcelain field line.
    fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
        out.extend_from_slice(name.as_bytes());
        out.push(b' ');
        out.extend_from_slice(String::from_utf8_lossy(value).as_bytes());
        out.push(b'\n');
    }
}

/// Formats `(timestamp, +HHMM)` as `YYYY-MM-DD HH:MM:SS +HHMM` in the
/// ident's own offset, the oracle blame column (not the `%ad` spelling
/// `log` renders).
fn blame_date(stamp: i64, zone: &str) -> Result<String, GitError> {
    let offset_seconds = parse_zone(zone)?;
    let civil = stamp + i64::from(offset_seconds);
    let days = civil.div_euclid(86_400);
    let seconds = civil.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} {zone}",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60,
    ))
}

/// Parses `+HHMM`/`-HHMM` into seconds east of UTC.
fn parse_zone(zone: &str) -> Result<i32, GitError> {
    let bad = || GitError::Corrupt {
        detail: format!("bad timezone {zone:?}"),
    };
    let bytes = zone.as_bytes();
    if bytes.len() != 5 || (bytes[0] != b'+' && bytes[0] != b'-') {
        return Err(bad());
    }
    let digits = |start: usize, end: usize| -> Result<i32, GitError> {
        std::str::from_utf8(&bytes[start..end])
            .map_err(|_| bad())?
            .parse()
            .map_err(|_| bad())
    };
    let hours: i32 = digits(1, 3)?;
    let minutes: i32 = digits(3, 5)?;
    if hours > 14 || minutes > 59 {
        return Err(bad());
    }
    let seconds = hours * 3_600 + minutes * 60;
    Ok(if bytes[0] == b'-' { -seconds } else { seconds })
}

/// Converts days since 1970-01-01 to a civil date (Hinnant's algorithm).
/// The `u32` bounds below are proven by construction (day-of-year under
/// 366, month-prime under 12), so the conversions expect rather than wrap.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1)
        .expect("day-of-year fits in u32");
    let prime = u32::try_from(month_prime).expect("month-prime fits in u32");
    let month = if prime < 10 { prime + 3 } else { prime - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
