//! Content search: `grep`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `grep` | worktree walk / tree flatten, `regex::bytes` matcher | implemented (subset) |
//!
//! Oracle anchor: `git/builtin/grep.c`.
//!
//! Subset: one positional pattern or repeatable `-e`, `-l`/`--name-only`
//! (`--files-with-matches` alias), `-c`/`--count`, `-n`/`--line-number`,
//! `-i`, `-w`/`--word-regexp`, `-F`/`--fixed-strings`,
//! `-E`/`--extended-regexp` (last of `-F`/`-E` on argv wins, as in the
//! oracle), `-H`/`--with-filename`/`--no-filename`, and one optional
//! `<commit>` positional that searches the named tree instead of the
//! worktree. `-l` stops each file at its first hit. Exit contract: 0 on a
//! hit, 1 (`NotFound`) on no hit, 128 (`Usage`) on bad invocation.
//!
//! Deliberate divergences: patterns always use Rust regex syntax (the
//! oracle's BRE-vs-ERE distinction is collapsed, so BRE-only escapes like
//! `\(...\)` match literally); there is no `.rukignore`/pathspec support
//! (no ignore matcher exists anywhere in this tree yet), so a second
//! positional is a usage error, never a path filter; binary hits render
//! `Binary file <path> matches` and count as one; symlinks are skipped
//! rather than followed out of the worktree.

use std::borrow::Cow;

use regex::bytes::{Regex, RegexBuilder};
use ruk_core::store::ObjectKind;
use ruk_git::GitError;

use super::state::resolve_rev;
use super::tree::{
    WorktreeType, flatten_tree, peel_to_tree, read_object_bytes, read_worktree_file, walk_worktree,
};
use super::{Ctx, FlagSpec, collect};

/// Searches worktree files, or one named tree, for pattern matches.
///
/// Oracle: `git/builtin/grep.c`.
pub(crate) fn grep(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "name-only",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "files-with-matches",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "count",
            short: Some('c'),
            takes_value: false,
        },
        FlagSpec {
            long: "line-number",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "extended-regexp",
            short: Some('E'),
            takes_value: false,
        },
        FlagSpec {
            long: "fixed-strings",
            short: Some('F'),
            takes_value: false,
        },
        FlagSpec {
            long: "ignore-case",
            short: Some('i'),
            takes_value: false,
        },
        FlagSpec {
            long: "word-regexp",
            short: Some('w'),
            takes_value: false,
        },
        FlagSpec {
            long: "with-filename",
            short: Some('H'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-filename",
            short: Some('h'),
            takes_value: false,
        },
        FlagSpec {
            long: "regexp",
            short: Some('e'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs).map_err(|err| match err {
        GitError::Invalid { detail } => GitError::Usage { detail },
        other => other,
    })?;

    let mut patterns = opts.all("regexp")?;
    let mut positionals = opts.positionals.iter();
    if patterns.is_empty() {
        let first = positionals.next().ok_or_else(|| GitError::Usage {
            detail: "no pattern given".to_owned(),
        })?;
        patterns.push(first.clone());
    }
    let rev_arg: Option<&str> = match positionals.as_slice() {
        [] => None,
        [one] => Some(one),
        _ => {
            return Err(GitError::Usage {
                detail: "pathspecs are not supported; give at most one <commit>".to_owned(),
            });
        }
    };

    let options = MatchOptions {
        ignore_case: opts.is_set("ignore-case"),
        word: opts.is_set("word-regexp"),
    };
    let matcher = build_matcher(&patterns, last_engine(args), &options)?;
    let files_only = opts.is_set("name-only") || opts.is_set("files-with-matches");
    let show_count = opts.is_set("count");
    let show_lineno = opts.is_set("line-number");
    let force_name = opts.is_set("with-filename");
    let hide_name = opts.is_set("no-filename");

    let (rev_label, files) = load_sources(ctx, rev_arg)?;
    // Tree hits always carry their `<rev>:` label, as in the oracle; in the
    // worktree, filenames print when more than one file was searched.
    // Explicit flags always win.
    let show_name = !hide_name && (force_name || rev_label.is_some() || files.len() > 1);

    let mut out = Vec::new();
    let mut any = false;
    for (path, bytes) in &files {
        let mut label: Vec<u8> = Vec::new();
        if let Some(rev) = &rev_label {
            label.extend_from_slice(rev.as_bytes());
            label.push(b':');
        }
        label.extend_from_slice(path);
        let scan = if files_only {
            scan_first_hit(&matcher, bytes)
        } else {
            scan_all_matches(&matcher, bytes)
        };
        if scan.matched_lines.is_empty() {
            continue;
        }
        any = true;
        if files_only {
            out.extend_from_slice(&label);
            out.push(b'\n');
            continue;
        }
        if scan.binary {
            if show_count {
                if show_name {
                    push_count_named(&mut out, &label, 1);
                } else {
                    push_count_bare(&mut out, 1);
                }
            } else {
                out.extend_from_slice(b"Binary file ");
                out.extend_from_slice(&label);
                out.extend_from_slice(b" matches\n");
            }
            continue;
        }
        if show_count {
            if show_name {
                push_count_named(&mut out, &label, scan.matched_lines.len());
            } else {
                push_count_bare(&mut out, scan.matched_lines.len());
            }
            continue;
        }
        for (lineno, line) in &scan.matched_lines {
            if show_name {
                out.extend_from_slice(&label);
                out.push(b':');
            }
            if show_lineno {
                out.extend_from_slice(lineno.to_string().as_bytes());
                out.push(b':');
            }
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    if !any {
        return Err(GitError::NotFound {
            detail: "no matches found".to_owned(),
        });
    }
    Ok(out)
}

/// Pattern options shared by both engines.
struct MatchOptions {
    /// Fold ASCII case before comparing.
    ignore_case: bool,
    /// Match only at word boundaries.
    word: bool,
}

/// Which pattern engine the last of `-F`/`-E` on raw argv selects.
///
/// The scan skips `-e` values so a pattern spelled like a flag cannot flip
/// the engine; combined shorts never reach here (`collect` refuses them).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    /// Rust regex syntax (covers the oracle's basic and extended modes).
    Regex,
    /// Literal byte search.
    Fixed,
}

/// Reads the winning engine off raw argv, defaulting to regex.
fn last_engine(args: &[String]) -> Engine {
    let mut engine = Engine::Regex;
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "-e" || arg == "--regexp" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--regexp=") {
            continue;
        }
        let bytes = arg.as_bytes();
        if bytes.len() > 2 && bytes[0] == b'-' && bytes[1] == b'e' && !arg.starts_with("--") {
            // Attached `-e<pattern>` value.
            continue;
        }
        if arg == "-F" || arg == "--fixed-strings" {
            engine = Engine::Fixed;
        } else if arg == "-E" || arg == "--extended-regexp" {
            engine = Engine::Regex;
        }
    }
    engine
}

/// Compiled multi-pattern matcher: any pattern matching is a hit.
///
/// Word limits (`-w`) are checked per hit against the raw neighbor bytes,
/// the same rule for both engines, so neither engine depends on regex
/// look-around support.
enum Matcher {
    /// Literal byte needles, lowercased up front when ignoring case.
    Fixed {
        needles: Vec<Vec<u8>>,
        ignore_case: bool,
        word: bool,
    },
    /// One compiled regex per pattern: each pattern searches the line
    /// independently, so a short alternative can never shadow a longer one
    /// sharing its prefix (leftmost-first alternation would).
    Re { regexes: Vec<Regex>, word: bool },
}

/// Compiles the patterns for one engine; regex failures are usage errors.
fn build_matcher(
    patterns: &[String],
    engine: Engine,
    options: &MatchOptions,
) -> Result<Matcher, GitError> {
    match engine {
        Engine::Fixed => Ok(Matcher::Fixed {
            needles: patterns
                .iter()
                .map(|pattern| {
                    if options.ignore_case {
                        pattern.as_bytes().to_ascii_lowercase()
                    } else {
                        pattern.as_bytes().to_vec()
                    }
                })
                .collect(),
            ignore_case: options.ignore_case,
            word: options.word,
        }),
        Engine::Regex => {
            let mut regexes = Vec::with_capacity(patterns.len());
            for pattern in patterns {
                let regex = RegexBuilder::new(pattern)
                    .case_insensitive(options.ignore_case)
                    .build()
                    .map_err(|err| GitError::Usage {
                        detail: format!("bad pattern {pattern:?}: {err}"),
                    })?;
                regexes.push(regex);
            }
            Ok(Matcher::Re {
                regexes,
                word: options.word,
            })
        }
    }
}

/// One file's scan: the matching lines plus whether the file is binary.
///
/// Binary detection is whole-file (any NUL byte), as in the oracle; an
/// empty needle matches every line of a non-empty file.
struct FileScan<'a> {
    /// One `(1-based lineno, raw line)` pair per matching line.
    matched_lines: Vec<(usize, &'a [u8])>,
    /// The file holds a NUL byte.
    binary: bool,
}

/// Scans every line of one file's bytes.
fn scan_all_matches<'bytes>(matcher: &Matcher, bytes: &'bytes [u8]) -> FileScan<'bytes> {
    scan_impl(matcher, bytes, CountMatches::All)
}

/// Scans one file's bytes, stopping at its first hit (for `-l`).
fn scan_first_hit<'bytes>(matcher: &Matcher, bytes: &'bytes [u8]) -> FileScan<'bytes> {
    scan_impl(matcher, bytes, CountMatches::FirstHit)
}

/// How many hits one file scan reports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CountMatches {
    /// Every matching line.
    All,
    /// Stop after the first matching line.
    FirstHit,
}

/// Splits one file into lines and records the wanted hits.
///
/// A single trailing newline does not add a phantom line; an empty file
/// has no lines at all.
fn scan_impl<'bytes>(
    matcher: &Matcher,
    bytes: &'bytes [u8],
    want: CountMatches,
) -> FileScan<'bytes> {
    let binary = bytes.contains(&0);
    let mut lines: Vec<&[u8]> = Vec::new();
    if !bytes.is_empty() {
        lines.extend(bytes.split(|byte| *byte == b'\n'));
        if bytes.ends_with(b"\n") {
            lines.pop();
        }
    }
    let mut matched_lines = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line_matches(matcher, line) {
            matched_lines.push((index + 1, *line));
            if want == CountMatches::FirstHit {
                break;
            }
        }
    }
    FileScan {
        matched_lines,
        binary,
    }
}

/// Reports whether one raw line matches any pattern.
fn line_matches(matcher: &Matcher, line: &[u8]) -> bool {
    match matcher {
        Matcher::Re { regexes, word } => regexes.iter().any(|regex| {
            if !word {
                return regex.is_match(line);
            }
            regex.find_iter(line).any(|hit| {
                let (start, end) = (hit.start(), hit.end());
                let left_ok = start == 0 || !is_word_byte(line[start - 1]);
                let right_ok = end == line.len() || !is_word_byte(line[end]);
                left_ok && right_ok
            })
        }),
        Matcher::Fixed {
            needles,
            ignore_case,
            word,
        } => {
            let hay: Cow<'_, [u8]> = if *ignore_case {
                Cow::Owned(line.to_ascii_lowercase())
            } else {
                Cow::Borrowed(line)
            };
            needles.iter().any(|needle| {
                if needle.is_empty() {
                    return true;
                }
                if hay.len() < needle.len() {
                    return false;
                }
                hay.windows(needle.len()).enumerate().any(|(at, window)| {
                    if window != needle.as_slice() {
                        return false;
                    }
                    if !word {
                        return true;
                    }
                    let left_ok = at == 0 || !is_word_byte(hay[at - 1]);
                    let right_ok =
                        at + needle.len() == hay.len() || !is_word_byte(hay[at + needle.len()]);
                    left_ok && right_ok
                })
            })
        }
    }
}

/// Oracle word characters for `-w`: ASCII alphanumerics plus underscore.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Loaded grep sources: `(rev label, [(path, bytes)])`.
type GrepSources = (Option<String>, Vec<(Vec<u8>, Vec<u8>)>);

/// Loads `(rev label, [(path, bytes)])` for the worktree or one tree.
///
/// Tree entries that are not blobs (gitlinks, submodules) are skipped, as
/// the oracle skips what it cannot read as text.
fn load_sources(ctx: &mut Ctx, rev_arg: Option<&str>) -> Result<GrepSources, GitError> {
    match rev_arg {
        None => load_worktree(ctx),
        Some(rev_text) => load_tree(ctx, rev_text),
    }
}

/// Reads every regular worktree file under the context base.
///
/// Symlinks are skipped: following them could read outside the worktree,
/// and the oracle never reports link bytes as matches.
fn load_worktree(ctx: &Ctx) -> Result<GrepSources, GitError> {
    ctx.require_worktree()?;
    let mut files = Vec::new();
    for entry in walk_worktree(&ctx.file_base)? {
        if entry.file_type != WorktreeType::File {
            continue;
        }
        let bytes = read_worktree_file(&ctx.file_base, &entry.path)?;
        files.push((entry.path, bytes));
    }
    Ok((None, files))
}

/// Reads every blob under the tree one revision names.
fn load_tree(ctx: &Ctx, rev_text: &str) -> Result<GrepSources, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let oid = resolve_rev(store, kind, rev_text).map_err(|err| GitError::Usage {
        detail: format!("unknown revision {rev_text:?}: {err}"),
    })?;
    let tree = peel_to_tree(store, kind, oid).map_err(|err| GitError::Usage {
        detail: format!("{rev_text:?} is not a tree or commit: {err}"),
    })?;
    let mut files = Vec::new();
    for (path, _mode, blob) in flatten_tree(store, kind, tree)? {
        let (object_kind, bytes) = read_object_bytes(store, blob)?;
        if object_kind != ObjectKind::Blob {
            continue;
        }
        files.push((path, bytes));
    }
    Ok((Some(rev_text.to_owned()), files))
}

/// Pushes a `-c` count line with its filename.
fn push_count_named(out: &mut Vec<u8>, label: &[u8], count: usize) {
    push_count_impl(out, Some(label), count);
}

/// Pushes a bare `-c` count line with no filename.
fn push_count_bare(out: &mut Vec<u8>, count: usize) {
    push_count_impl(out, None, count);
}

/// Renders one count line with an optional filename prefix.
fn push_count_impl(out: &mut Vec<u8>, label: Option<&[u8]>, count: usize) {
    if let Some(label) = label {
        out.extend_from_slice(label);
        out.push(b':');
    }
    out.extend_from_slice(count.to_string().as_bytes());
    out.push(b'\n');
}
