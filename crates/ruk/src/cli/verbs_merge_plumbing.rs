//! Low-level merge and index plumbing: `merge-file`, `merge-tree`,
//! `read-tree`, `checkout-index`, and `rerere`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `merge-file` | bounded line three-way merge over worktree files | implemented (`-p`, `-q`, `-L`, `--ours`/`--theirs`/`--union`, `--diff3`, `--marker-size`; no `--stdout` alias gap: `--stdout` accepted) |
//! | `merge-tree` | tree-level three-way merge, index/worktree untouched | implemented (prints the new tree plus `CONFLICT` lines, exit 0; no `--write-tree`/`--name-only` forms) |
//! | `read-tree` | index population from one tree, `--empty`, `-m` two/three-tree, `--reset`, `-u` | implemented (`--prefix`, `--index-output`, `--trivial`, `--aggressive`, `--dry-run` refused) |
//! | `checkout-index` | index-to-worktree materialization | implemented (`-a`, `-f`, `-u`, `-q`, `--prefix`, `--stage=1/2/3`, `--stdin`; `--stage=all`, `--temp`, `-z` without `--stdin` refused) |
//! | `rerere` | recorded-resolution replay under `cli/rerere/` | implemented (record/replay/`status`/`diff`/`remaining`/`forget`/`clear`/`gc`; no `rerere.enabled`/`autoupdate` config) |
//!
//! The three-way text merge is this module's own bounded line differ
//! (dynamic-programming LCS capped at four million cells, eight-megabyte
//! triplet cap): markers spell `<<<<<<< <ours>` / `=======` / `>>>>>>>`
//! `<theirs>`, with `||||||| <base>` between when `--diff3` (or
//! `merge-tree`'s recorded form) asks. Inputs past the caps merge as one
//! whole-file conflict, never a wrong merge. NUL bytes refuse the textual
//! merge; `--ours`/`--theirs`/`--union` still resolve them by selection.
//!
//! `merge-tree` never touches the index or worktree: it publishes the
//! merged (marker-bearing on conflict) blobs and root tree, then prints the
//! tree id. Conflicts are `CONFLICT (content)` report lines on stdout with a
//! zero exit, since the interpreter cannot carry stdout alongside a failure.
//!
//! `rerere` keys records by the conflict-hunk bytes (marker lines excluded,
//! so branch labels never perturb the id) hashed as a blob id. A bare run
//! replays recorded resolutions onto current conflicts and records fresh
//! preimages; newly resolved paths graduate their active preimage into a
//! postimage.
//!
//! Consistency: every index mutation publishes with the workspace-row bump
//! in one store transaction (snapshot isolation per verb); `rerere` replay
//! is idempotent per path, so a partial run converges by re-running.
//!
//! Oracle anchors: `git/builtin/merge-file.c`, `git/builtin/merge-tree.c`,
//! `git/builtin/read-tree.c`, `git/builtin/checkout-index.c`,
//! `git/builtin/rerere.c`.

use std::collections::{BTreeMap, HashMap};

use ruk_core::ids::Oid;
use ruk_core::index::{FileMode, IndexEntry, IndexFlags, RepoPath, Stage};
use ruk_core::store::{
    FactExpectation, FactMutation, FactPageBudget, FactTable, ObjectKind, Store,
};
use ruk_git::GitError;
use serde::{Deserialize, Serialize};

use super::state::{
    commit_record, head_oid, load_or_default, now_seconds, path_row_mutations, read_path_rows,
    resolve_rev, scan_index, workspace_mutation,
};
use super::tree::{
    TreeMode, build_index_tree, commit_tree_oid, flatten_tree, join_base, peel_to_tree,
    read_object_bytes, store_object,
};
use super::{Ctx, FlagSpec, collect, line, read_stdin_text};

// ---------------------------------------------------------------------------
// Bounded line three-way merge (shared by merge-file and merge-tree)
// ---------------------------------------------------------------------------

/// Largest base+ours+theirs triplet merged line-wise; past it the whole
/// file conflicts.
const MAX_MERGE_TRIPLET: usize = 8 << 20;
/// Largest LCS cell count; past it the whole file conflicts.
const MAX_DIFF_CELLS: usize = 4_000_000;
/// Largest single file `rerere` records inline.
const MAX_RERERE_BYTES: usize = 1 << 20;

/// Splits bytes into lines keeping terminators; empty input has no lines.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
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
struct TextHunk {
    a_start: usize,
    a_end: usize,
    b_start: usize,
    b_end: usize,
}

/// LCS hunks between two line slices, or `None` past the cell cap.
fn lcs_hunks(a: &[&[u8]], b: &[&[u8]]) -> Option<Vec<TextHunk>> {
    if a.is_empty() && b.is_empty() {
        return Some(Vec::new());
    }
    let (rows, cols) = (a.len(), b.len());
    let cells = rows.checked_add(1)?.checked_mul(cols.checked_add(1)?)?;
    if cells > MAX_DIFF_CELLS {
        return None;
    }
    let stride = cols + 1;
    let mut table = vec![0u32; cells];
    for i in 1..=rows {
        for j in 1..=cols {
            table[i * stride + j] = if a[i - 1] == b[j - 1] {
                table[(i - 1) * stride + (j - 1)] + 1
            } else {
                table[(i - 1) * stride + j].max(table[i * stride + (j - 1)])
            };
        }
    }
    // Backtrack the LCS as match runs, then invert to hunks.
    let mut matches: Vec<(usize, usize)> = Vec::new();
    let (mut i, mut j) = (rows, cols);
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            matches.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if table[(i - 1) * stride + j] >= table[i * stride + (j - 1)] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    matches.reverse();
    let mut hunks = Vec::new();
    let (mut ai, mut bi) = (0, 0);
    for (mi, mj) in matches {
        if ai != mi || bi != mj {
            hunks.push(TextHunk {
                a_start: ai,
                a_end: mi,
                b_start: bi,
                b_end: mj,
            });
        }
        ai = mi + 1;
        bi = mj + 1;
    }
    if ai != rows || bi != cols {
        hunks.push(TextHunk {
            a_start: ai,
            a_end: rows,
            b_start: bi,
            b_end: cols,
        });
    }
    Some(hunks)
}

/// Splices `side` lines over `base[start..end]` through `hunks`.
fn splice<'a>(
    base: &'a [&[u8]],
    hunks: &[TextHunk],
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
fn push_text_lines(out: &mut Vec<u8>, lines: &[&[u8]]) {
    for text_line in lines {
        out.extend_from_slice(text_line);
        if !text_line.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
}

/// How conflict markers spell their sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerStyle {
    /// `<<<<<<<` / `=======` / `>>>>>>>`.
    Normal,
    /// Plus a `||||||| base` section.
    Diff3,
}

/// One conflict block: every marker line travels together.
struct ConflictBlock<'a> {
    marker: &'a [u8],
    ours_label: &'a str,
    ours: &'a [&'a [u8]],
    base_label: &'a str,
    base: Option<&'a [&'a [u8]]>,
    theirs_label: &'a str,
    theirs: &'a [&'a [u8]],
    style: MarkerStyle,
}

/// Appends one fence row of `glyph` repeated to the marker width.
fn push_fence(out: &mut Vec<u8>, glyph: u8, width: usize) {
    out.extend(std::iter::repeat_n(glyph, width));
}

/// Appends one conflict block.
fn push_text_conflict(out: &mut Vec<u8>, block: &ConflictBlock<'_>) {
    let width = block.marker.len();
    push_fence(out, b'<', width);
    out.extend_from_slice(format!(" {}\n", block.ours_label).as_bytes());
    push_text_lines(out, block.ours);
    if block.style == MarkerStyle::Diff3 {
        push_fence(out, b'|', width);
        out.extend_from_slice(format!(" {}\n", block.base_label).as_bytes());
        push_text_lines(out, block.base.unwrap_or(&[]));
    }
    out.extend_from_slice(b"=======\n");
    push_text_lines(out, block.theirs);
    push_fence(out, b'>', width);
    out.extend_from_slice(format!(" {}\n", block.theirs_label).as_bytes());
}

/// One three-way text merge request: the sides travel together.
struct TextMerge<'a> {
    base: &'a [u8],
    ours: &'a [u8],
    theirs: &'a [u8],
    labels: (&'a str, &'a str, &'a str),
    style: MarkerStyle,
    marker: &'a [u8],
    mode: ResolveMode,
}

/// How an auto-resolve mode settles conflicting regions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolveMode {
    /// Mark conflicts (exit nonzero when any conflict).
    Markers,
    /// Take the ours side everywhere.
    Ours,
    /// Take the theirs side everywhere.
    Theirs,
    /// Concatenate both sides over conflicting regions.
    Union,
}

/// Bounded line three-way merge. Returns the merged bytes plus whether any
/// region conflicted, or `None` past the bounds (the caller then reports a
/// whole-file conflict).
fn text_merge(request: &TextMerge<'_>) -> Option<(Vec<u8>, bool)> {
    let &TextMerge {
        base,
        ours,
        theirs,
        labels,
        style,
        marker,
        mode,
    } = request;
    if base.len() + ours.len() + theirs.len() > MAX_MERGE_TRIPLET {
        return None;
    }
    let (ours_label, base_label, theirs_label) = labels;
    let a = split_lines(base);
    let o = split_lines(ours);
    let t = split_lines(theirs);
    let hunks_o = lcs_hunks(&a, &o)?;
    let hunks_t = lcs_hunks(&a, &t)?;
    let mut bounds: Vec<(usize, usize)> = hunks_o
        .iter()
        .map(|hunk| (hunk.a_start, hunk.a_end))
        .chain(hunks_t.iter().map(|hunk| (hunk.a_start, hunk.a_end)))
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
        for text_line in &a[pos..start] {
            out.extend_from_slice(text_line);
        }
        let in_o: Vec<&TextHunk> = hunks_o
            .iter()
            .filter(|hunk| hunk.a_start >= start && hunk.a_end <= end)
            .collect();
        let in_t: Vec<&TextHunk> = hunks_t
            .iter()
            .filter(|hunk| hunk.a_start >= start && hunk.a_end <= end)
            .collect();
        match (in_o.is_empty(), in_t.is_empty()) {
            (false, false) => {
                let ours_lines = splice(&a, &hunks_o, start, end, &o);
                let theirs_lines = splice(&a, &hunks_t, start, end, &t);
                if ours_lines == theirs_lines {
                    push_text_lines(&mut out, &ours_lines);
                } else {
                    conflicted = true;
                    match mode {
                        ResolveMode::Markers => {
                            let base_lines = splice(&a, &[], start, end, &[]);
                            push_text_conflict(
                                &mut out,
                                &ConflictBlock {
                                    marker,
                                    ours_label,
                                    ours: &ours_lines,
                                    base_label,
                                    base: Some(&base_lines),
                                    theirs_label,
                                    theirs: &theirs_lines,
                                    style,
                                },
                            );
                        }
                        ResolveMode::Ours => push_text_lines(&mut out, &ours_lines),
                        ResolveMode::Theirs => push_text_lines(&mut out, &theirs_lines),
                        ResolveMode::Union => {
                            push_text_lines(&mut out, &ours_lines);
                            // Theirs lines already present through ours are
                            // not repeated; ordering stays ours-first.
                            let mut seen: std::collections::HashSet<&[u8]> =
                                ours_lines.iter().copied().collect();
                            for text_line in &theirs_lines {
                                if seen.insert(text_line) {
                                    out.extend_from_slice(text_line);
                                    if !text_line.ends_with(b"\n") {
                                        out.push(b'\n');
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (true, false) => {
                push_text_lines(&mut out, &splice(&a, &hunks_t, start, end, &t));
            }
            (false, true) => {
                push_text_lines(&mut out, &splice(&a, &hunks_o, start, end, &o));
            }
            (true, true) => {}
        }
        pos = end;
    }
    for text_line in &a[pos..] {
        out.extend_from_slice(text_line);
    }
    Some((out, conflicted && mode == ResolveMode::Markers))
}

/// Whole-file conflict block used past the merge bounds.
fn whole_file_conflict(
    ours: &[u8],
    theirs: &[u8],
    labels: (&str, &str, &str),
    style: MarkerStyle,
    marker: &[u8],
    base: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let base_lines = split_lines(base);
    push_text_conflict(
        &mut out,
        &ConflictBlock {
            marker,
            ours_label: labels.0,
            ours: &split_lines(ours),
            base_label: labels.1,
            base: Some(&base_lines),
            theirs_label: labels.2,
            theirs: &split_lines(theirs),
            style,
        },
    );
    out
}

// ---------------------------------------------------------------------------
// merge-file
// ---------------------------------------------------------------------------

/// Merges three worktree files, writing markers into `<current>`.
///
/// Oracle: `git/builtin/merge-file.c`.
pub(crate) fn merge_file_cmd(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "stdout",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "label",
            short: Some('L'),
            takes_value: true,
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
            long: "union",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "diff3",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "marker-size",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let mode = match (
        opts.is_set("ours"),
        opts.is_set("theirs"),
        opts.is_set("union"),
    ) {
        (false, false, false) => ResolveMode::Markers,
        (true, false, false) => ResolveMode::Ours,
        (false, true, false) => ResolveMode::Theirs,
        (false, false, true) => ResolveMode::Union,
        _ => {
            return Err(GitError::Invalid {
                detail: "merge-file takes at most one of --ours/--theirs/--union".to_owned(),
            });
        }
    };
    let marker_len = match opts.single("marker-size")? {
        None => 7,
        Some(text) => text.parse::<usize>().map_err(|_| GitError::Invalid {
            detail: format!("bad --marker-size {text:?}"),
        })?,
    };
    if marker_len < 7 {
        return Err(GitError::Invalid {
            detail: format!("--marker-size must be at least 7, got {marker_len}"),
        });
    }
    let labels = opts.all("label")?;
    if labels.len() > 3 {
        return Err(GitError::Invalid {
            detail: "merge-file takes at most three -L labels".to_owned(),
        });
    }
    if opts.positionals.len() != 3 {
        return Err(GitError::Usage {
            detail: "usage: merge-file [-p] [-q] [-L <label>]... [--ours|--theirs|--union] [--diff3] <current> <base> <other>".to_owned(),
        });
    }
    let (current, base, other) = (
        opts.positionals[0].clone(),
        opts.positionals[1].clone(),
        opts.positionals[2].clone(),
    );
    let current_bytes = read_lane_file(&ctx.file_base, &current)?;
    let base_bytes = read_lane_file(&ctx.file_base, &base)?;
    let other_bytes = read_lane_file(&ctx.file_base, &other)?;
    let style = if opts.is_set("diff3") {
        MarkerStyle::Diff3
    } else {
        MarkerStyle::Normal
    };
    let marker = vec![b'<'; marker_len];
    let triple = (
        labels.first().map_or(current.as_str(), String::as_str),
        labels.get(1).map_or(base.as_str(), String::as_str),
        labels.get(2).map_or(other.as_str(), String::as_str),
    );
    let binary = [&current_bytes, &base_bytes, &other_bytes]
        .iter()
        .any(|bytes| bytes.contains(&0));
    let (merged, conflicted) = if binary {
        match mode {
            ResolveMode::Ours => (current_bytes.clone(), false),
            ResolveMode::Theirs => (other_bytes.clone(), false),
            ResolveMode::Union => {
                let mut both = current_bytes.clone();
                both.extend_from_slice(&other_bytes);
                (both, false)
            }
            ResolveMode::Markers => {
                return Err(GitError::Invalid {
                    detail: format!("cannot merge binary files {current:?} and {other:?}"),
                });
            }
        }
    } else {
        match text_merge(&TextMerge {
            base: &base_bytes,
            ours: &current_bytes,
            theirs: &other_bytes,
            labels: triple,
            style,
            marker: &marker,
            mode,
        }) {
            Some(done) => done,
            // Past the bounds the resolve modes still settle by
            // selection; only marker mode reports a whole-file conflict.
            None => match mode {
                ResolveMode::Markers => (
                    whole_file_conflict(
                        &current_bytes,
                        &other_bytes,
                        triple,
                        style,
                        &marker,
                        &base_bytes,
                    ),
                    true,
                ),
                ResolveMode::Ours => (current_bytes.clone(), false),
                ResolveMode::Theirs => (other_bytes.clone(), false),
                ResolveMode::Union => {
                    let mut both = current_bytes.clone();
                    both.extend_from_slice(&other_bytes);
                    (both, false)
                }
            },
        }
    };
    if opts.is_set("stdout") {
        // The interpreter drops stdout on failure, so conflict bytes ride
        // in the error detail (truncated past 1 MiB) with status 1; the
        // file on disk is untouched.
        return if conflicted {
            Err(stdout_conflict_error(&merged, &current))
        } else {
            Ok(merged)
        };
    }
    let full = join_base(&ctx.file_base, current.as_bytes())?;
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    std::fs::write(&full, &merged).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", full.display()),
    })?;
    if conflicted {
        return Err(conflict_error(&merged, &current));
    }
    Ok(Vec::new())
}

/// Builds the exit-1 conflict report with the merged bytes inline (the
/// interpreter drops stdout on failure, so markers ride in the detail).
fn conflict_error(merged: &[u8], path: &str) -> GitError {
    let mut detail = format!("merge-file: {path}: merged with conflicts\n");
    if merged.len() > MAX_ERROR_MERGED {
        detail.push_str(&String::from_utf8_lossy(&merged[..MAX_ERROR_MERGED]));
        detail.push_str("\n[merge-file: output truncated]\n");
    } else {
        detail.push_str(&String::from_utf8_lossy(merged));
    }
    GitError::Invalid { detail }
}

/// Largest conflict output embedded in an error detail.
const MAX_ERROR_MERGED: usize = 1 << 20;

/// Builds the exit-1 `-p` conflict report with the merged bytes inline.
fn stdout_conflict_error(merged: &[u8], path: &str) -> GitError {
    let mut detail = format!("merge-file: {path}: merged with conflicts\n");
    if merged.len() > MAX_ERROR_MERGED {
        detail.push_str(&String::from_utf8_lossy(&merged[..MAX_ERROR_MERGED]));
        detail.push_str("\n[merge-file: output truncated]\n");
    } else {
        detail.push_str(&String::from_utf8_lossy(merged));
    }
    GitError::Invalid { detail }
}

/// Reads one lane file relative to the worktree base.
fn read_lane_file(base: &std::path::Path, name: &str) -> Result<Vec<u8>, GitError> {
    let full = join_base(base, name.as_bytes())?;
    std::fs::read(&full).map_err(|err| GitError::NotFound {
        detail: format!("cannot read {name:?}: {err}"),
    })
}

// ---------------------------------------------------------------------------
// merge-tree
// ---------------------------------------------------------------------------

/// Merges three trees without touching the index or worktree.
///
/// Oracle: `git/builtin/merge-tree.c`. Prints the merged tree id; conflict
/// report lines follow on stdout with a zero exit (see module docs).
pub(crate) fn merge_tree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "write-tree",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.is_set("write-tree") || opts.is_set("name-only") {
        return Err(GitError::Unsupported {
            command: "merge-tree --write-tree/--name-only output forms".to_owned(),
        });
    }
    if opts.positionals.len() != 3 {
        return Err(GitError::Usage {
            detail: "usage: merge-tree <base-tree> <ours> <theirs>".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let base_tree = peel_to_tree(store, kind, resolve_rev(store, kind, &opts.positionals[0])?)?;
    let ours_tree = peel_to_tree(store, kind, resolve_rev(store, kind, &opts.positionals[1])?)?;
    let theirs_tree = peel_to_tree(store, kind, resolve_rev(store, kind, &opts.positionals[2])?)?;
    let base_map = tree_path_map(store, kind, base_tree)?;
    let ours_map = tree_path_map(store, kind, ours_tree)?;
    let theirs_map = tree_path_map(store, kind, theirs_tree)?;
    let mut keys = std::collections::BTreeSet::new();
    for map in [&base_map, &ours_map, &theirs_map] {
        keys.extend(map.keys().cloned());
    }
    let mut rows: Vec<(Vec<u8>, IndexEntry)> = Vec::with_capacity(keys.len());
    let mut conflicted: Vec<String> = Vec::new();
    let mut blobs: HashMap<Oid, Vec<u8>> = HashMap::new();
    for path in keys {
        let sides = (
            base_map.get(&path).copied(),
            ours_map.get(&path).copied(),
            theirs_map.get(&path).copied(),
        );
        match merge_tree_path(store, &mut blobs, sides)? {
            TreePathOutcome::Take(mode, oid) => {
                rows.push((path, lane_index_entry(kind, mode, oid)?));
            }
            TreePathOutcome::Merged(mode, bytes) => {
                let oid = store_object(store, ObjectKind::Blob, bytes)?;
                rows.push((path, lane_index_entry(kind, mode, oid)?));
            }
            TreePathOutcome::Conflict(mode, bytes) => {
                conflicted.push(String::from_utf8_lossy(&path).into_owned());
                let oid = store_object(store, ObjectKind::Blob, bytes)?;
                // A mode conflict keeps the ours blob mode when the bytes
                // came from a side; marker blobs are regular files.
                rows.push((path, lane_index_entry(kind, mode, oid)?));
            }
            TreePathOutcome::Deleted => {}
        }
    }
    let tree = build_index_tree(store, kind, &rows)?;
    let mut out = format!("{}\n", tree.to_hex()).into_bytes();
    conflicted.sort();
    for path in &conflicted {
        out.extend_from_slice(format!("CONFLICT (content): Merge conflict in {path}\n").as_bytes());
    }
    if !conflicted.is_empty() && !opts.is_set("quiet") {
        ctx.emit_stderr(format!("merge-tree: {} conflict(s)\n", conflicted.len()).as_bytes());
    }
    Ok(line(out))
}

/// One merged tree path.
enum TreePathOutcome {
    /// Keep the stored blob.
    Take(FileMode, Oid),
    /// Merged bytes as a regular blob.
    Merged(FileMode, Vec<u8>),
    /// Conflict bytes (markers or surviving side) with their tree mode.
    Conflict(FileMode, Vec<u8>),
    /// No entry for this path.
    Deleted,
}

/// Flattens one tree to a path map.
fn tree_path_map(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    tree: Oid,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, GitError> {
    let mut out = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        out.insert(path, (mode, oid));
    }
    Ok(out)
}

/// Builds a stage-zero row for merged-tree output.
fn lane_index_entry(
    kind: ruk_core::ids::HashKind,
    mode: FileMode,
    oid: Oid,
) -> Result<IndexEntry, GitError> {
    let entry = IndexEntry::new(oid, mode, None, IndexFlags::default()).map_err(core_err)?;
    entry.validate(kind).map_err(core_err)?;
    Ok(entry)
}

/// Reads one blob body through a small oid-keyed cache.
fn lane_blob(
    store: &Store,
    cache: &mut HashMap<Oid, Vec<u8>>,
    oid: Oid,
) -> Result<Vec<u8>, GitError> {
    if let Some(hit) = cache.get(&oid) {
        return Ok(hit.clone());
    }
    let (kind, body) = read_object_bytes(store, oid)?;
    if kind != ObjectKind::Blob {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a blob", oid.to_hex()),
        });
    }
    cache.insert(oid, body.clone());
    Ok(body)
}

/// Merges one union path at tree level (no syntax lane: plumbing).
fn merge_tree_path(
    store: &Store,
    blobs: &mut HashMap<Oid, Vec<u8>>,
    sides: (
        Option<(TreeMode, Oid)>,
        Option<(TreeMode, Oid)>,
        Option<(TreeMode, Oid)>,
    ),
) -> Result<TreePathOutcome, GitError> {
    let (base, ours, theirs) = sides;
    // Directory/file clashes cannot happen here: tree paths never prefix
    // one another.
    match (base, ours, theirs) {
        (None, None, None) => Ok(TreePathOutcome::Deleted),
        (None, Some(side), None) | (None, None, Some(side)) => {
            Ok(TreePathOutcome::Take(index_side(side)?, side.1))
        }
        (None, Some(one), Some(other)) => {
            if one == other {
                return Ok(TreePathOutcome::Take(index_side(one)?, one.1));
            }
            // Add/add: merge textually when both are text blobs.
            tree_content_merge(store, blobs, None, one, other)
        }
        (Some(_), None, None) => Ok(TreePathOutcome::Deleted),
        (Some(base_side), Some(ours_side), None) => {
            if base_side == ours_side {
                return Ok(TreePathOutcome::Deleted);
            }
            // Modified on ours, deleted on theirs: keep the ours blob.
            Ok(TreePathOutcome::Conflict(
                index_side(ours_side)?,
                lane_blob(store, blobs, ours_side.1)?,
            ))
        }
        (Some(base_side), None, Some(theirs_side)) => {
            if base_side == theirs_side {
                return Ok(TreePathOutcome::Deleted);
            }
            Ok(TreePathOutcome::Conflict(
                index_side(theirs_side)?,
                lane_blob(store, blobs, theirs_side.1)?,
            ))
        }
        (Some(base_side), Some(ours_side), Some(theirs_side)) => {
            if ours_side == base_side {
                return Ok(TreePathOutcome::Take(
                    index_side(theirs_side)?,
                    theirs_side.1,
                ));
            }
            if theirs_side == base_side {
                return Ok(TreePathOutcome::Take(index_side(ours_side)?, ours_side.1));
            }
            if ours_side == theirs_side {
                return Ok(TreePathOutcome::Take(index_side(ours_side)?, ours_side.1));
            }
            tree_content_merge(store, blobs, Some(base_side), ours_side, theirs_side)
        }
    }
}

/// Converts a tree side to its index file mode.
fn index_side(side: (TreeMode, Oid)) -> Result<FileMode, GitError> {
    side.0.as_index_mode().map_err(core_err)
}

/// Merges both-changed blob sides textually; anything unmergeable keeps the
/// ours bytes as the conflict blob.
fn tree_content_merge(
    store: &Store,
    blobs: &mut HashMap<Oid, Vec<u8>>,
    base: Option<(TreeMode, Oid)>,
    ours: (TreeMode, Oid),
    theirs: (TreeMode, Oid),
) -> Result<TreePathOutcome, GitError> {
    let ours_mode = index_side(ours).unwrap_or(FileMode::Regular);
    let theirs_mode = index_side(theirs).unwrap_or(FileMode::Regular);
    // The side that moved off the base wins the mode, as in the content
    // lane; add/add with equal modes takes either.
    let mode = match base {
        Some((base_tree_mode, _)) => {
            let base_file = base_tree_mode.as_index_mode().unwrap_or(FileMode::Regular);
            if ours_mode != base_file {
                ours_mode
            } else {
                theirs_mode
            }
        }
        None => ours_mode,
    };
    let gitlink = [base, Some(ours), Some(theirs)]
        .iter()
        .flatten()
        .any(|(tree_mode, _)| *tree_mode == TreeMode::Gitlink);
    if gitlink {
        // Gitlinks name commits: keep ours, conflicted.
        return Ok(TreePathOutcome::Conflict(
            ours_mode,
            lane_blob(store, blobs, ours.1)?,
        ));
    }
    if ours_mode != theirs_mode {
        return Ok(TreePathOutcome::Conflict(
            ours_mode,
            lane_blob(store, blobs, ours.1)?,
        ));
    }
    let base_bytes = match base {
        Some((_, oid)) => lane_blob(store, blobs, oid)?,
        None => Vec::new(),
    };
    let ours_bytes = lane_blob(store, blobs, ours.1)?;
    let theirs_bytes = lane_blob(store, blobs, theirs.1)?;
    if [&base_bytes, &ours_bytes, &theirs_bytes]
        .iter()
        .any(|bytes| bytes.contains(&0))
    {
        return Ok(TreePathOutcome::Conflict(ours_mode, ours_bytes));
    }
    let labels = ("ours", "base", "theirs");
    match text_merge(&TextMerge {
        base: &base_bytes,
        ours: &ours_bytes,
        theirs: &theirs_bytes,
        labels,
        style: MarkerStyle::Normal,
        marker: b"<<<<<<<",
        mode: ResolveMode::Markers,
    }) {
        Some((bytes, false)) => Ok(TreePathOutcome::Merged(mode, bytes)),
        Some((bytes, true)) => Ok(TreePathOutcome::Conflict(FileMode::Regular, bytes)),
        None => Ok(TreePathOutcome::Conflict(
            FileMode::Regular,
            whole_file_conflict(
                &ours_bytes,
                &theirs_bytes,
                labels,
                MarkerStyle::Normal,
                b"<<<<<<<",
                &base_bytes,
            ),
        )),
    }
}

/// Maps a model failure into the interpreter error space.
fn core_err(err: impl Into<ruk_core::error::CoreError>) -> GitError {
    GitError::from(err.into())
}

// ---------------------------------------------------------------------------
// read-tree
// ---------------------------------------------------------------------------

/// Populates the index from trees: `read-tree [--empty] [-m] [--reset] [-u]`.
///
/// Oracle: `git/builtin/read-tree.c`.
pub(crate) fn read_tree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "m",
            short: Some('m'),
            takes_value: false,
        },
        FlagSpec {
            long: "reset",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "u",
            short: Some('u'),
            takes_value: false,
        },
        FlagSpec {
            long: "empty",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "prefix",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "index-output",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "trivial",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "aggressive",
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
    for refused in ["prefix", "index-output", "trivial", "aggressive", "dry-run"] {
        if opts.is_set(refused) {
            return Err(GitError::Unsupported {
                command: format!("read-tree --{refused}"),
            });
        }
    }
    if opts.is_set("empty") {
        if !opts.positionals.is_empty() || opts.is_set("m") || opts.is_set("reset") {
            return Err(GitError::Invalid {
                detail: "usage: read-tree --empty [-u]".to_owned(),
            });
        }
        return read_tree_empty(ctx, &opts);
    }
    if opts.is_set("m") {
        return read_tree_merge(ctx, &opts);
    }
    if opts.positionals.len() != 1 {
        return Err(GitError::Usage {
            detail: "usage: read-tree [--reset] [-u] <tree-ish>".to_owned(),
        });
    }
    read_tree_single(ctx, &opts, &opts.positionals[0].clone())
}

/// Replaces the whole index with one tree. Plain replacement refuses
/// unmerged rows; `--reset` discards them. Branch tips never move (that is
/// `reset`'s job).
fn read_tree_single(ctx: &Ctx, opts: &super::Collected, rev: &str) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let tree = peel_to_tree(store, kind, resolve_rev(store, kind, rev)?)?;
    // Plain replacement refuses unmerged rows; `--reset` discards them.
    if !opts.is_set("reset") {
        let rows = scan_index(store, kind)?;
        if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
            return Err(GitError::Invalid {
                detail: "unmerged paths must be resolved first".to_owned(),
            });
        }
    }
    if opts.is_set("u") {
        ctx.require_worktree()?;
        let before = stage_zero_map(store, kind)?;
        super::verbs_branch::reset_index_tree(ctx, tree)?;
        checkout_touched(ctx, &before, &stage_zero_map(store, kind)?)?;
        return Ok(Vec::new());
    }
    super::verbs_branch::reset_index_tree(ctx, tree)?;
    Ok(Vec::new())
}

/// Empties the index; with `-u` the tracked worktree files go too.
fn read_tree_empty(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let before = stage_zero_map(store, kind)?;
    let rows = scan_index(store, kind)?;
    let mut mutations = Vec::new();
    // One mutation set per path to keep expectations exact.
    let mut done: Vec<RepoPath> = Vec::new();
    for (path, _, _) in &rows {
        if done.contains(path) {
            continue;
        }
        done.push(path.clone());
        let seen = read_path_rows(store, kind, path)?;
        mutations.extend(path_row_mutations(path, &seen, &[])?);
    }
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace.mutate_index(workspace.stamp).map_err(core_err)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    if opts.is_set("u") {
        ctx.require_worktree()?;
        checkout_touched(ctx, &before, &stage_zero_map(store, kind)?)?;
    }
    Ok(Vec::new())
}

/// Two/three-tree `-m` merge into the index with stages 1/2/3 on conflict.
fn read_tree_merge(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let revs = opts.positionals.clone();
    let (base_tree, ours_tree, theirs_tree) = match revs.len() {
        1 => {
            // One-tree `-m` only fast-forwards an unchanged index: anything
            // else is a real merge the two/three-tree form performs.
            let tree = peel_to_tree(store, kind, resolve_rev(store, kind, &revs[0])?)?;
            let head_tree = head_tree_of(ctx)?;
            if head_tree == tree {
                return Ok(Vec::new());
            }
            return Err(GitError::Invalid {
                detail: format!(
                    "refusing to merge {:?} into the current index (use two trees)",
                    revs[0]
                ),
            });
        }
        2 => {
            let head_tree = head_tree_of(ctx)?;
            (
                head_tree,
                peel_to_tree(store, kind, resolve_rev(store, kind, &revs[0])?)?,
                peel_to_tree(store, kind, resolve_rev(store, kind, &revs[1])?)?,
            )
        }
        3 => (
            peel_to_tree(store, kind, resolve_rev(store, kind, &revs[0])?)?,
            peel_to_tree(store, kind, resolve_rev(store, kind, &revs[1])?)?,
            peel_to_tree(store, kind, resolve_rev(store, kind, &revs[2])?)?,
        ),
        _ => {
            return Err(GitError::Usage {
                detail: "usage: read-tree -m <tree1> [<tree2> [<tree3>]] [-u]".to_owned(),
            });
        }
    };
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "unmerged paths must be resolved first".to_owned(),
        });
    }
    let base_map = tree_path_map(store, kind, base_tree)?;
    let ours_map = tree_path_map(store, kind, ours_tree)?;
    let theirs_map = tree_path_map(store, kind, theirs_tree)?;
    let mut keys = std::collections::BTreeSet::new();
    for map in [&base_map, &ours_map, &theirs_map] {
        keys.extend(map.keys().cloned());
    }
    let before = stage_zero_map(store, kind)?;
    let mut mutations = Vec::new();
    for path in &keys {
        let repo_path = RepoPath::new(path.clone()).map_err(core_err)?;
        let seen = read_path_rows(store, kind, &repo_path)?;
        let after = read_merge_resolution(
            base_map.get(path).copied(),
            ours_map.get(path).copied(),
            theirs_map.get(path).copied(),
        )?;
        mutations.extend(path_row_mutations(
            &repo_path,
            &seen,
            &after
                .iter()
                .map(|(stage, entry)| (*stage, entry.clone()))
                .collect::<Vec<_>>(),
        )?);
    }
    let (workspace, raw) = load_or_default(store)?;
    let next = workspace.mutate_index(workspace.stamp).map_err(core_err)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    if opts.is_set("u") {
        ctx.require_worktree()?;
        checkout_touched(ctx, &before, &stage_zero_map(store, kind)?)?;
    }
    Ok(Vec::new())
}

/// Resolves one union path to index stages: clean takes resolve to stage 0,
/// both-changed to stages 1/2/3, never to worktree markers.
fn read_merge_resolution(
    base: Option<(TreeMode, Oid)>,
    ours: Option<(TreeMode, Oid)>,
    theirs: Option<(TreeMode, Oid)>,
) -> Result<Vec<(Stage, IndexEntry)>, GitError> {
    let entry = |side: (TreeMode, Oid)| -> Result<IndexEntry, GitError> {
        IndexEntry::new(
            side.1,
            side.0.as_index_mode().map_err(core_err)?,
            None,
            IndexFlags::default(),
        )
        .map_err(core_err)
    };
    let stages = |sides: (
        Option<(TreeMode, Oid)>,
        Option<(TreeMode, Oid)>,
        Option<(TreeMode, Oid)>,
    )|
     -> Result<Vec<(Stage, IndexEntry)>, GitError> {
        let mut out = Vec::new();
        for (side, stage) in [
            (sides.0, Stage::Base),
            (sides.1, Stage::Ours),
            (sides.2, Stage::Theirs),
        ] {
            if let Some(present) = side {
                out.push((stage, entry(present)?));
            }
        }
        Ok(out)
    };
    match (base, ours, theirs) {
        (None, None, None) => Ok(Vec::new()),
        (None, Some(side), None) | (None, None, Some(side)) => {
            Ok(vec![(Stage::Zero, entry(side)?)])
        }
        (None, Some(one), Some(other)) => {
            if one == other {
                return Ok(vec![(Stage::Zero, entry(one)?)]);
            }
            stages((None, Some(one), Some(other)))
        }
        (Some(_), None, None) => Ok(Vec::new()),
        (Some(base_side), Some(ours_side), None) => {
            if base_side == ours_side {
                return Ok(Vec::new());
            }
            stages((Some(base_side), Some(ours_side), None))
        }
        (Some(base_side), None, Some(theirs_side)) => {
            if base_side == theirs_side {
                return Ok(Vec::new());
            }
            stages((Some(base_side), None, Some(theirs_side)))
        }
        (Some(base_side), Some(ours_side), Some(theirs_side)) => {
            if ours_side == base_side {
                return Ok(vec![(Stage::Zero, entry(theirs_side)?)]);
            }
            if theirs_side == base_side {
                return Ok(vec![(Stage::Zero, entry(ours_side)?)]);
            }
            if ours_side == theirs_side {
                return Ok(vec![(Stage::Zero, entry(ours_side)?)]);
            }
            stages((Some(base_side), Some(ours_side), Some(theirs_side)))
        }
    }
}

/// Stage-zero index map for worktree sync diffing.
fn stage_zero_map(
    store: &Store,
    kind: ruk_core::ids::HashKind,
) -> Result<BTreeMap<Vec<u8>, (FileMode, Oid)>, GitError> {
    let mut out = BTreeMap::new();
    for (path, stage, entry) in scan_index(store, kind)? {
        if stage == Stage::Zero {
            out.insert(path.as_bytes().to_vec(), (entry.mode(), entry.oid()));
        }
    }
    Ok(out)
}

/// Tree of the current `HEAD` commit.
fn head_tree_of(ctx: &Ctx) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let oid = head_oid(store)?;
    commit_tree_oid(&commit_record(store, oid)?)
}

/// Checks out exactly the paths two stage-zero maps disagree on: new blobs
/// are written, dropped paths removed when clean, dirty paths refused.
/// Untracked files never enter either map and are never touched.
fn checkout_touched(
    ctx: &Ctx,
    before: &BTreeMap<Vec<u8>, (FileMode, Oid)>,
    after: &BTreeMap<Vec<u8>, (FileMode, Oid)>,
) -> Result<(), GitError> {
    let store = ctx.store()?;
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(before.keys().cloned());
    keys.extend(after.keys().cloned());
    let mut blocked: Vec<String> = Vec::new();
    let mut writes: Vec<(Vec<u8>, TouchedWrite)> = Vec::new();
    let mut cache: HashMap<Oid, Vec<u8>> = HashMap::new();
    for path in &keys {
        let old = before.get(path);
        let new = after.get(path);
        if old == new {
            continue;
        }
        match (old, new) {
            (_, Some((mode, oid))) => {
                if *mode == FileMode::Gitlink {
                    continue;
                }
                let wanted = lane_blob(store, &mut cache, *oid).ok();
                let full = join_base(&ctx.file_base, path).map_err(|_| GitError::Invalid {
                    detail: format!("bad path {}", String::from_utf8_lossy(path)),
                })?;
                let current = read_lane_worktree(&full, mode);
                match (current, wanted) {
                    (Some(current), Some(wanted)) if current != wanted => {
                        // Overwrite only when the worktree still shows the
                        // old index bytes (or nothing does).
                        let old_bytes =
                            old.and_then(|(_, oid)| lane_blob(store, &mut cache, *oid).ok());
                        if Some(current) != old_bytes {
                            blocked.push(String::from_utf8_lossy(path).into_owned());
                            continue;
                        }
                        writes.push((
                            path.clone(),
                            TouchedWrite::Blob {
                                mode: *mode,
                                oid: *oid,
                            },
                        ));
                    }
                    _ => writes.push((
                        path.clone(),
                        TouchedWrite::Blob {
                            mode: *mode,
                            oid: *oid,
                        },
                    )),
                }
            }
            (Some(_), None) => {
                let full = join_base(&ctx.file_base, path).map_err(|_| GitError::Invalid {
                    detail: format!("bad path {}", String::from_utf8_lossy(path)),
                })?;
                if !full.is_symlink() && !full.is_file() {
                    continue;
                }
                let old_bytes = old.and_then(|(_, oid)| lane_blob(store, &mut cache, *oid).ok());
                let current = std::fs::read(&full).ok();
                if current != old_bytes {
                    blocked.push(String::from_utf8_lossy(path).into_owned());
                    continue;
                }
                writes.push((path.clone(), TouchedWrite::Remove));
            }
            (None, None) => {}
        }
    }
    if !blocked.is_empty() {
        blocked.sort();
        let mut detail = String::from(
            "error: Your local changes to the following files would be overwritten by checkout:\n",
        );
        for path in &blocked {
            detail.push_str(&format!("\t{path}\n"));
        }
        detail.push_str("Please commit your changes or stash them before you switch.");
        return Err(GitError::Invalid { detail });
    }
    for (path, write) in &writes {
        let full = join_base(&ctx.file_base, path)?;
        match write {
            TouchedWrite::Remove => {
                if full.is_symlink() || full.is_file() {
                    std::fs::remove_file(&full).map_err(|err| GitError::Io {
                        detail: format!("removing {}: {err}", full.display()),
                    })?;
                }
            }
            TouchedWrite::Blob { mode, oid } => {
                write_lane_blob(ctx, *mode, *oid, &full)?;
            }
        }
    }
    Ok(())
}

/// One scoped checkout write.
enum TouchedWrite {
    Blob { mode: FileMode, oid: Oid },
    Remove,
}

/// Reads one worktree file for dirty-checking (`None` when absent).
fn read_lane_worktree(full: &std::path::Path, mode: &FileMode) -> Option<Vec<u8>> {
    if *mode == FileMode::Symlink {
        return std::fs::read_link(full)
            .ok()
            .map(|link| link.as_os_str().as_encoded_bytes().to_vec());
    }
    std::fs::read(full).ok()
}

/// Writes one blob to a worktree path.
fn write_lane_blob(
    ctx: &Ctx,
    mode: FileMode,
    oid: Oid,
    full: &std::path::Path,
) -> Result<(), GitError> {
    let store = ctx.store()?;
    if mode == FileMode::Symlink {
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
        #[cfg(unix)]
        std::os::unix::fs::symlink(text, full).map_err(|err| GitError::Io {
            detail: format!("linking {}: {err}", full.display()),
        })?;
        #[cfg(not(unix))]
        return Err(GitError::Unsupported {
            command: "checkout of symlinks on this platform".to_owned(),
        });
        return Ok(());
    }
    let (_, body) = read_object_bytes(store, oid)?;
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    if full.is_symlink() {
        std::fs::remove_file(full).map_err(|err| GitError::Io {
            detail: format!("removing {}: {err}", full.display()),
        })?;
    }
    std::fs::write(full, body).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", full.display()),
    })?;
    #[cfg(unix)]
    if mode == FileMode::Executable {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(full, std::fs::Permissions::from_mode(0o755)).map_err(|err| {
            GitError::Io {
                detail: format!("chmod {}: {err}", full.display()),
            }
        })?;
    }
    let _ = ctx;
    Ok(())
}

// ---------------------------------------------------------------------------
// checkout-index
// ---------------------------------------------------------------------------

/// Materializes index entries into the worktree.
///
/// Oracle: `git/builtin/checkout-index.c`.
pub(crate) fn checkout_index(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "index",
            short: Some('u'),
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "prefix",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "stage",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "temp",
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
    if opts.is_set("temp") {
        return Err(GitError::Unsupported {
            command: "checkout-index --temp".to_owned(),
        });
    }
    if opts.is_set("z") && !opts.is_set("stdin") {
        return Err(GitError::Invalid {
            detail: "checkout-index -z needs --stdin".to_owned(),
        });
    }
    if let Some(stage) = opts.single("stage")? {
        if !["1", "2", "3"].contains(&stage.as_str()) {
            return Err(GitError::Unsupported {
                command: "checkout-index --stage=all".to_owned(),
            });
        }
    }
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut wanted: Vec<String> = opts.positionals.clone();
    if opts.is_set("stdin") {
        let text = read_stdin_text(&ctx.env)?;
        if opts.is_set("z") {
            wanted.extend(
                text.split('\0')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned),
            );
        } else {
            wanted.extend(
                text.lines()
                    .filter(|text_line| !text_line.is_empty())
                    .map(str::to_owned),
            );
        }
    }
    if wanted.iter().any(|path| *path == "--") {
        wanted.retain(|path| *path != "--");
    }
    let prefix = opts.single("prefix")?.unwrap_or_default();
    if !prefix.is_empty() && (prefix.starts_with('/') || prefix.contains("..")) {
        return Err(GitError::Invalid {
            detail: format!("bad --prefix {prefix:?}"),
        });
    }
    let stage = match opts.single("stage")?.as_deref() {
        None => None,
        Some("1") => Some(Stage::Base),
        Some("2") => Some(Stage::Ours),
        Some("3") => Some(Stage::Theirs),
        Some(_) => unreachable!("stage validated above"),
    };
    let rows = scan_index(store, kind)?;
    let mut by_path: BTreeMap<Vec<u8>, Vec<(Stage, IndexEntry)>> = BTreeMap::new();
    for (path, path_stage, entry) in &rows {
        by_path
            .entry(path.as_bytes().to_vec())
            .or_default()
            .push((*path_stage, entry.clone()));
    }
    let targets: Vec<Vec<u8>> = if opts.is_set("all") {
        if !wanted.is_empty() {
            return Err(GitError::Invalid {
                detail: "checkout-index -a takes no path arguments".to_owned(),
            });
        }
        by_path.keys().cloned().collect()
    } else {
        if wanted.is_empty() {
            return Err(GitError::Usage {
                detail: "usage: checkout-index [-a] [-f] [-u] [-q] [--prefix=<dir>] [--stage=<n>] [--] <path>...".to_owned(),
            });
        }
        let mut out = Vec::with_capacity(wanted.len());
        for name in &wanted {
            let repo_path = super::verbs_stage::repo_path_of(ctx, name.as_bytes())?;
            out.push(repo_path.as_bytes().to_vec());
        }
        out
    };
    let force = opts.is_set("force");
    let mut out = Vec::new();
    for path in targets {
        let Some(stages) = by_path.get(&path) else {
            return Err(GitError::NotFound {
                detail: format!(
                    "path is not in the index: {:?}",
                    String::from_utf8_lossy(&path)
                ),
            });
        };
        let entry = match stage {
            None => stages
                .iter()
                .find(|(path_stage, _)| *path_stage == Stage::Zero)
                .map(|(_, entry)| entry.clone()),
            Some(wanted_stage) => stages
                .iter()
                .find(|(path_stage, _)| *path_stage == wanted_stage)
                .map(|(_, entry)| entry.clone()),
        };
        let Some(entry) = entry else {
            let detail = match stage {
                None => format!(
                    "path has no stage-zero entry: {:?}",
                    String::from_utf8_lossy(&path)
                ),
                Some(_) => format!(
                    "path is not in the index at that stage: {:?}",
                    String::from_utf8_lossy(&path)
                ),
            };
            return Err(GitError::NotFound { detail });
        };
        if entry.mode() == FileMode::Gitlink {
            continue;
        }
        let shown = String::from_utf8_lossy(&path).into_owned();
        let rel = if prefix.is_empty() {
            shown.clone()
        } else {
            format!("{}/{}", prefix.trim_end_matches('/'), shown)
        };
        let full = join_base(&ctx.file_base, rel.as_bytes())?;
        checkout_one(ctx, &entry, &full, force)?;
        if !opts.is_set("quiet") {
            out.extend_from_slice(rel.as_bytes());
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// Writes one index entry to its worktree path, refusing dirty overwrites
/// without `--force`.
fn checkout_one(
    ctx: &Ctx,
    entry: &IndexEntry,
    full: &std::path::Path,
    force: bool,
) -> Result<(), GitError> {
    let store = ctx.store()?;
    if !force {
        let current = read_lane_worktree(full, &entry.mode());
        let wanted = lane_blob_uncached(store, entry.oid()).ok();
        if let Some(current) = current {
            if Some(current) != wanted {
                return Err(GitError::Invalid {
                    detail: format!("already exists, no checkout: {}", full.display()),
                });
            }
            return Ok(());
        }
    }
    write_lane_blob(ctx, entry.mode(), entry.oid(), full)
}

/// Reads one blob body without a cache.
fn lane_blob_uncached(store: &Store, oid: Oid) -> Result<Vec<u8>, GitError> {
    let (kind, body) = read_object_bytes(store, oid)?;
    if kind != ObjectKind::Blob {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a blob", oid.to_hex()),
        });
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// rerere
// ---------------------------------------------------------------------------

/// Record prefix for conflict-resolution records keyed by conflict id hex.
const RERERE_PREFIX: &[u8] = b"cli/rerere/";
/// Active-preimage map: conflicted path bytes to conflict id hex.
const RERERE_ACTIVE_PREFIX: &[u8] = b"cli/rerere-active/";
/// Preimage-only records older than this are `gc` candidates (15 days).
const RERERE_GC_PREIMAGE_SECS: i64 = 15 * 24 * 60 * 60;
/// Resolved records older than this are `gc` candidates (60 days).
const RERERE_GC_RESOLVED_SECS: i64 = 60 * 24 * 60 * 60;

/// One recorded conflict and its known resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RerereRecord {
    /// Lossy display path that produced the conflict.
    path: String,
    /// Unix seconds when the preimage was recorded.
    created: i64,
    /// Conflict-hunk bytes the id hashes.
    preimage: Vec<u8>,
    /// Resolved worktree bytes, once the user resolved them.
    postimage: Option<Vec<u8>>,
}

/// Reuses recorded conflict resolutions.
///
/// Oracle: `git/builtin/rerere.c`. A bare run replays resolutions with
/// matching preimages onto current conflicts (staging stage zero) and
/// records fresh preimages; newly resolved paths graduate to postimages.
pub(crate) fn rerere(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "rerere-autoupdate",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    match opts.positionals.first().map(String::as_str) {
        None => rerere_replay(ctx),
        Some("status") => rerere_status(ctx, &opts),
        Some("diff") => rerere_diff(ctx, &opts),
        Some("remaining") => rerere_remaining(ctx, &opts),
        Some("forget") => rerere_forget(ctx, &opts),
        Some("clear") => rerere_clear(ctx, &opts),
        Some("gc") => rerere_gc(ctx, &opts),
        Some(other) => Err(GitError::Invalid {
            detail: format!("unknown rerere subcommand {other:?}"),
        }),
    }
}

/// Bare run: replay resolutions, record preimages, graduate resolutions.
fn rerere_replay(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    let mut conflicted: BTreeMap<Vec<u8>, Vec<(Stage, IndexEntry)>> = BTreeMap::new();
    let mut resolved_paths: Vec<Vec<u8>> = Vec::new();
    for (path, stage, entry) in &rows {
        if *stage == Stage::Zero {
            if !resolved_paths.iter().any(|known| known == path.as_bytes()) {
                resolved_paths.push(path.as_bytes().to_vec());
            }
            continue;
        }
        conflicted
            .entry(path.as_bytes().to_vec())
            .or_default()
            .push((*stage, entry.clone()));
    }
    let mut out = Vec::new();
    // Replay recorded resolutions onto current conflicts first.
    for (path, stages) in &conflicted {
        let full = join_base(&ctx.file_base, path)?;
        let body = match std::fs::read(&full) {
            Ok(body) => body,
            Err(_) => continue,
        };
        if body.len() > MAX_RERERE_BYTES {
            continue;
        }
        let Some(hunks) = conflict_hunks(&body) else {
            continue;
        };
        let id = rerere_id(kind, &hunks)?;
        let Some(record) = rerere_read(store, &id)? else {
            rerere_store_preimage(ctx, path, &hunks, &id)?;
            continue;
        };
        let Some(postimage) = record.postimage else {
            // Refresh the active map so a later resolution graduates.
            rerere_mark_active(ctx, path, &id)?;
            continue;
        };
        std::fs::write(&full, &postimage).map_err(|err| GitError::Io {
            detail: format!("writing {}: {err}", full.display()),
        })?;
        let mode = stages
            .iter()
            .find(|(stage, _)| *stage == Stage::Ours)
            .or_else(|| stages.first())
            .map(|(_, entry)| entry.mode())
            .unwrap_or(FileMode::Regular);
        if mode == FileMode::Gitlink {
            continue;
        }
        let repo_path = RepoPath::new(path.clone()).map_err(core_err)?;
        let before = read_path_rows(store, kind, &repo_path)?;
        let entry = IndexEntry::for_blob(kind, mode, &postimage, None).map_err(core_err)?;
        let mutations = path_row_mutations(&repo_path, &before, &[(Stage::Zero, entry)])?;
        let (workspace, raw) = load_or_default(store)?;
        let next = workspace.mutate_index(workspace.stamp).map_err(core_err)?;
        let mut all = mutations;
        all.push(workspace_mutation(raw.as_deref(), &next)?);
        store.publish(Vec::new(), &all).map_err(GitError::from)?;
        out.extend_from_slice(
            format!(
                "Resolved '{}' using previous resolution.\n",
                String::from_utf8_lossy(path)
            )
            .as_bytes(),
        );
    }
    // Graduate newly resolved paths: an active preimage whose path no
    // longer carries higher stages becomes a postimage.
    let actives = rerere_scan_active(store)?;
    for (path, id) in actives {
        if conflicted.contains_key(&path) {
            continue;
        }
        let full = match join_base(&ctx.file_base, &path) {
            Ok(full) => full,
            Err(_) => continue,
        };
        let body = match std::fs::read(&full) {
            Ok(body) => body,
            Err(_) => {
                rerere_unmark_active(ctx, &path)?;
                continue;
            }
        };
        if body.len() > MAX_RERERE_BYTES || conflict_hunks(&body).is_some() {
            continue;
        }
        let mut record = match rerere_read(store, &id)? {
            Some(record) => record,
            None => {
                rerere_unmark_active(ctx, &path)?;
                continue;
            }
        };
        record.postimage = Some(body);
        rerere_write(ctx, &id, &record)?;
        rerere_unmark_active(ctx, &path)?;
        out.extend_from_slice(
            format!(
                "Recorded resolution for '{}'.\n",
                String::from_utf8_lossy(&path)
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

/// Lists conflicted paths, one per line.
fn rerere_status(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rerere status".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut out = Vec::new();
    for (path, stage, _) in scan_index(store, kind)? {
        if stage != Stage::Zero {
            out.extend_from_slice(path.as_bytes());
            out.push(b'\n');
            // Deduplicate repeat stages of the same path below.
            let _ = &mut out;
        }
    }
    // Collapse repeat stages to one line per path.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut dedup = Vec::new();
    for text_line in out.split_inclusive(|byte| *byte == b'\n') {
        if !seen.contains(&text_line.to_vec()) {
            seen.push(text_line.to_vec());
            dedup.extend_from_slice(text_line);
        }
    }
    Ok(dedup)
}

/// Shows recorded resolutions as labeled preimage/postimage sections.
fn rerere_diff(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rerere diff".to_owned(),
        });
    }
    let store = ctx.store()?;
    let mut out = Vec::new();
    for (id, record) in rerere_scan(store)? {
        let Some(postimage) = &record.postimage else {
            continue;
        };
        out.extend_from_slice(format!("--- a/{}\n", record.path).as_bytes());
        out.extend_from_slice(format!("+++ b/{}\n", record.path).as_bytes());
        out.extend_from_slice(format!("@@ recorded {id} @@\n").as_bytes());
        out.extend_from_slice(b"--- preimage\n");
        out.extend_from_slice(&record.preimage);
        if !record.preimage.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(b"+++ resolution\n");
        out.extend_from_slice(postimage);
        if !postimage.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// Lists conflicted paths with no recorded resolution.
fn rerere_remaining(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rerere remaining".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for (path, stage, _) in scan_index(store, kind)? {
        if stage != Stage::Zero && !seen.contains(&path.as_bytes().to_vec()) {
            seen.push(path.as_bytes().to_vec());
        }
    }
    let mut out = Vec::new();
    for path in seen {
        let full = join_base(&ctx.file_base, &path)?;
        let body = std::fs::read(&full).unwrap_or_default();
        let resolved = match conflict_hunks(&body) {
            Some(hunks) => rerere_read(store, &rerere_id(kind, &hunks)?)?
                .is_some_and(|record| record.postimage.is_some()),
            None => true,
        };
        if !resolved {
            out.extend_from_slice(&path);
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// Drops records and active preimages for paths.
fn rerere_forget(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() < 2 {
        return Err(GitError::Invalid {
            detail: "usage: rerere forget [--] <path>...".to_owned(),
        });
    }
    let store = ctx.store()?;
    let mut mutations = Vec::new();
    for name in opts.positionals.iter().skip(1) {
        if name == "--" {
            continue;
        }
        let repo_path = super::verbs_stage::repo_path_of(ctx, name.as_bytes())?;
        let raw = repo_path.as_bytes().to_vec();
        let mut active_key = RERERE_ACTIVE_PREFIX.to_vec();
        active_key.extend_from_slice(&raw);
        mutations.push(FactMutation {
            table: FactTable::Pins,
            key: active_key,
            expected: FactExpectation::Any,
            value: None,
        });
        // Drop records whose display path matches.
        for (id, record) in rerere_scan(store)? {
            if record.path.as_bytes() == raw.as_slice() {
                let mut key = RERERE_PREFIX.to_vec();
                key.extend_from_slice(id.as_bytes());
                mutations.push(FactMutation {
                    table: FactTable::Pins,
                    key,
                    expected: FactExpectation::Any,
                    value: None,
                });
            }
        }
    }
    if !mutations.is_empty() {
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    Ok(Vec::new())
}

/// Drops every record and active preimage.
fn rerere_clear(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rerere clear".to_owned(),
        });
    }
    let store = ctx.store()?;
    let mut mutations = Vec::new();
    for (id, _) in rerere_scan(store)? {
        let mut key = RERERE_PREFIX.to_vec();
        key.extend_from_slice(id.as_bytes());
        mutations.push(FactMutation {
            table: FactTable::Pins,
            key,
            expected: FactExpectation::Any,
            value: None,
        });
    }
    for (path, _) in rerere_scan_active(store)? {
        let mut key = RERERE_ACTIVE_PREFIX.to_vec();
        key.extend_from_slice(&path);
        mutations.push(FactMutation {
            table: FactTable::Pins,
            key,
            expected: FactExpectation::Any,
            value: None,
        });
    }
    if !mutations.is_empty() {
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    Ok(Vec::new())
}

/// Prunes stale records: preimage-only past 15 days, resolved past 60.
fn rerere_gc(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    if opts.positionals.len() != 1 {
        return Err(GitError::Invalid {
            detail: "usage: rerere gc".to_owned(),
        });
    }
    let store = ctx.store()?;
    let now = now_seconds()?;
    let mut mutations = Vec::new();
    let mut pruned = 0u64;
    for (id, record) in rerere_scan(store)? {
        let age = now.saturating_sub(record.created);
        let stale = match &record.postimage {
            None => age > RERERE_GC_PREIMAGE_SECS,
            Some(_) => age > RERERE_GC_RESOLVED_SECS,
        };
        if stale {
            let mut key = RERERE_PREFIX.to_vec();
            key.extend_from_slice(id.as_bytes());
            mutations.push(FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: None,
            });
            pruned += 1;
        }
    }
    if !mutations.is_empty() {
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    Ok(line(
        format!("pruned {pruned} rerere record(s)").into_bytes(),
    ))
}

/// Extracts conflict-hunk content (marker lines excluded) from worktree
/// bytes, or `None` when the file carries no markers.
fn conflict_hunks(body: &[u8]) -> Option<Vec<u8>> {
    let mut hunks = Vec::new();
    let mut in_conflict = false;
    let mut found = false;
    for text_line in split_lines(body) {
        if text_line.starts_with(b"<<<<<<< ") {
            in_conflict = true;
            found = true;
            continue;
        }
        if text_line.starts_with(b">>>>>>> ") {
            in_conflict = false;
            continue;
        }
        if in_conflict {
            if text_line.starts_with(b"||||||| ")
                || text_line == b"=======\n"
                || text_line == b"======="
            {
                continue;
            }
            hunks.extend_from_slice(text_line);
        }
    }
    found.then_some(hunks)
}

/// Hashes conflict hunks to the record id.
fn rerere_id(kind: ruk_core::ids::HashKind, hunks: &[u8]) -> Result<String, GitError> {
    kind.hash_git_object("blob", hunks)
        .map(|oid| oid.to_hex())
        .map_err(core_err)
}

/// Reads one record by id hex.
fn rerere_read(store: &Store, id: &str) -> Result<Option<RerereRecord>, GitError> {
    let mut key = RERERE_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    let raw = store.fact(FactTable::Pins, &key).map_err(GitError::from)?;
    raw.map(|bytes| {
        sonic_rs::from_slice(&bytes).map_err(|err| GitError::Corrupt {
            detail: format!("rerere record {id} does not decode: {err}"),
        })
    })
    .transpose()
}

/// Writes one record by id hex.
fn rerere_write(ctx: &Ctx, id: &str, record: &RerereRecord) -> Result<(), GitError> {
    let store = ctx.store()?;
    let value = sonic_rs::to_vec(record).map_err(|err| GitError::Io {
        detail: format!("rerere record encode: {err}"),
    })?;
    let mut key = RERERE_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: Some(value),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Scans every record in key order.
fn rerere_scan(store: &Store) -> Result<Vec<(String, RerereRecord)>, GitError> {
    scan_prefix(store, RERERE_PREFIX, |key, value| {
        let id = String::from_utf8_lossy(&key[RERERE_PREFIX.len()..]).into_owned();
        let record: RerereRecord =
            sonic_rs::from_slice(value).map_err(|err| GitError::Corrupt {
                detail: format!("rerere record {id} does not decode: {err}"),
            })?;
        Ok((id, record))
    })
}

/// Stores a fresh preimage and marks the path active.
fn rerere_store_preimage(ctx: &Ctx, path: &[u8], hunks: &[u8], id: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    if rerere_read(store, id)?.is_some() {
        rerere_mark_active(ctx, path, id)?;
        return Ok(());
    }
    rerere_write(
        ctx,
        id,
        &RerereRecord {
            path: String::from_utf8_lossy(path).into_owned(),
            created: now_seconds()?,
            preimage: hunks.to_vec(),
            postimage: None,
        },
    )?;
    rerere_mark_active(ctx, path, id)?;
    Ok(())
}

/// Marks a path's active preimage id.
fn rerere_mark_active(ctx: &Ctx, path: &[u8], id: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    let mut key = RERERE_ACTIVE_PREFIX.to_vec();
    key.extend_from_slice(path);
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: Some(id.as_bytes().to_vec()),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Clears a path's active preimage.
fn rerere_unmark_active(ctx: &Ctx, path: &[u8]) -> Result<(), GitError> {
    let store = ctx.store()?;
    let mut key = RERERE_ACTIVE_PREFIX.to_vec();
    key.extend_from_slice(path);
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Scans the active-preimage map in key order.
fn rerere_scan_active(store: &Store) -> Result<Vec<(Vec<u8>, String)>, GitError> {
    scan_prefix(store, RERERE_ACTIVE_PREFIX, |key, value| {
        Ok((
            key[RERERE_ACTIVE_PREFIX.len()..].to_vec(),
            String::from_utf8_lossy(value).into_owned(),
        ))
    })
}

/// Scans one `Pins` prefix in key order, decoding each row.
fn scan_prefix<T>(
    store: &Store,
    prefix: &[u8],
    mut decode: impl FnMut(&[u8], &[u8]) -> Result<T, GitError>,
) -> Result<Vec<T>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = Some(prefix.to_vec());
    loop {
        let page = store
            .fact_page(
                FactTable::Pins,
                after.as_deref(),
                FactPageBudget::new(1024, 1 << 20),
            )
            .map_err(GitError::from)?;
        if page.rows.is_empty() {
            return Ok(out);
        }
        for row in &page.rows {
            if !row.key.starts_with(prefix) {
                return Ok(out);
            }
            out.push(decode(&row.key, &row.value)?);
        }
        if !page.more {
            return Ok(out);
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
}
