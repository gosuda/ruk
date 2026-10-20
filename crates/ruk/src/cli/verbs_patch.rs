//! Email-patch verbs: `apply`, `format-patch`, `am`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `apply` | unified-diff parse + hunk match + worktree/index write | implemented (context matching with offset search, `--index`/`--cached`/`--check`/`--stat`/`--numstat`/`--reverse`/`-p`; no binary patches, no gitlinks) |
//! | `format-patch` | range walk + mbox render | implemented (stdout unless `-o`, `-n`, `--numbered`/`--no-numbered`, `-U`; merge commits refused; subjects stay raw UTF-8) |
//! | `am` | mbox parse + apply + commit | implemented (files or stdin, `--signoff`, `-k`, `-p`, `--continue`/`--skip`/`--abort`/`--quit` over `AM_STATE`; dirty index refused; no `-3`) |
//!
//! Oracle anchors: `git/builtin/apply.c`, `git/builtin/log.c`
//! (`cmd_format_patch`), `git/builtin/am.c`.
//!
//! Divergences from Git:
//! - `format-patch` writes concatenated mbox to stdout unless `-o` names a
//!   directory (git writes one file per commit unless `--stdout`); the mbox
//!   bytes follow the same layout either way.
//! - Subjects stay raw UTF-8; non-ASCII subjects are never RFC2047-encoded.
//! - Binary diffs render as `Binary files ... differ` and `apply` refuses
//!   them instead of applying delta payloads.
//! - `am` validates every hunk of a message before touching the worktree or
//!   the index, so a failed patch leaves no partial state behind;
//!   `--continue` then stages the patch's paths from the resolved worktree
//!   and commits with the saved author and message.

use std::collections::BTreeMap;

use ruk_core::change::RequestId;
use ruk_core::commit::CommitRecord;
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{FileMode, IndexEntry, RepoPath, Stage, StatData};
use ruk_core::ops::NewRequest;
use ruk_core::store::{EventContext, EventSource};
use ruk_git::GitError;

use super::state::{
    IdentityRole, commit_record, head_oid, identity, load_or_default, merged_rows, now_seconds,
    path_row_mutations, pseudo_delete, pseudo_read, pseudo_write, read_path_rows, scan_index,
    workspace_mutation,
};
use super::tree::{
    TreeMode, build_index_tree, commit_tree_oid, flatten_tree, join_base, read_object_bytes,
    read_worktree_file,
};
use super::verbs_branch::reset;
use super::verbs_history::{
    parse_log_revs, render_file_stat, stat_summary, tree_file_changes, walk_history_excluding,
};
use super::{Ctx, FlagSpec, collect, read_stdin_bytes};

/// Path-to-content seed map from the `HEAD` tree.
type SeedFileMap = BTreeMap<Vec<u8>, (TreeMode, Option<Vec<u8>>)>;
/// `(old path, new path, result bytes, result mode, deleted)` apply result.
type AmApplyResult = (Vec<u8>, Vec<u8>, Vec<u8>, FileMode, bool);
/// `(index row, staged content plus lstat tuple)` touched entry.
type TouchedEntry = (RepoPath, Option<(FileMode, Vec<u8>, Option<StatData>)>);

// ---------------------------------------------------------------------------
// shared text model
// ---------------------------------------------------------------------------

/// One file line with its newline flag, so `\ No newline at end of file`
/// round-trips byte-identically.
#[derive(Clone, Debug)]
struct TextLine {
    /// Line bytes without the terminator.
    body: Vec<u8>,
    /// Whether a `\n` followed the line.
    newline: bool,
}

/// Splits file bytes into lines, remembering a missing final newline.
fn split_text(bytes: &[u8]) -> Vec<TextLine> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let trailing = bytes.ends_with(b"\n");
    let body = if trailing {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    };
    let mut out: Vec<TextLine> = body
        .split(|byte| *byte == b'\n')
        .map(|part| TextLine {
            body: part.to_vec(),
            newline: true,
        })
        .collect();
    if !trailing && let Some(last) = out.last_mut() {
        last.newline = false;
    }
    out
}

/// Joins lines back into file bytes.
fn join_text(lines: &[TextLine]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(&line.body);
        if line.newline {
            out.push(b'\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// unified-diff rendering (format-patch)
// ---------------------------------------------------------------------------

/// One LCS operation between an old and a new body, by line index.
#[derive(Clone, Copy, Debug)]
enum DiffOp {
    /// Unchanged on both sides.
    Keep(usize, usize),
    /// Old-only line.
    Del(usize),
    /// New-only line.
    Ins(usize),
}

/// Bounded LCS table over line bodies; `None` when the product exceeds the
/// same 4M bound the `diff` renderer uses, so huge files degrade to a
/// whole-file replacement instead of an allocation blowup.
fn lcs_ops(old: &[Vec<u8>], new: &[Vec<u8>]) -> Option<Vec<DiffOp>> {
    if old.len().saturating_mul(new.len()) > 4_000_000 {
        return None;
    }
    let (m, n) = (old.len(), new.len());
    let mut table = vec![0_u32; (m + 1) * (n + 1)];
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            table[i * (n + 1) + j] = if old[i] == new[j] {
                table[(i + 1) * (n + 1) + j + 1] + 1
            } else {
                table[(i + 1) * (n + 1) + j].max(table[i * (n + 1) + j + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < m && j < n {
        if old[i] == new[j] {
            ops.push(DiffOp::Keep(i, j));
            i += 1;
            j += 1;
        } else if table[(i + 1) * (n + 1) + j] >= table[i * (n + 1) + j + 1] {
            ops.push(DiffOp::Del(i));
            i += 1;
        } else {
            ops.push(DiffOp::Ins(j));
            j += 1;
        }
    }
    while i < m {
        ops.push(DiffOp::Del(i));
        i += 1;
    }
    while j < n {
        ops.push(DiffOp::Ins(j));
        j += 1;
    }
    Some(ops)
}

/// Emits hunks with `radius` context lines, merging windows whose gap holds
/// at most `2 * radius` unchanged lines, the way the oracle groups hunks.
fn emit_patch_hunks(out: &mut Vec<u8>, old: &[TextLine], new: &[TextLine], radius: usize) {
    let old_bodies: Vec<Vec<u8>> = old.iter().map(|line| line.body.clone()).collect();
    let new_bodies: Vec<Vec<u8>> = new.iter().map(|line| line.body.clone()).collect();
    let Some(ops) = lcs_ops(&old_bodies, &new_bodies) else {
        emit_whole_replace(out, old, new);
        return;
    };
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for (index, op) in ops.iter().enumerate() {
        if matches!(op, DiffOp::Keep(_, _)) {
            continue;
        }
        let start = index.saturating_sub(radius);
        let end = (index + 1 + radius).min(ops.len());
        match windows.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => windows.push((start, end)),
        }
    }
    if windows.is_empty() {
        // Bodies match line-wise but newline flags differ: the change is
        // real (the blobs differ) and needs one replacing hunk.
        let same = old.len() == new.len()
            && old
                .iter()
                .zip(new.iter())
                .all(|(a, b)| a.body == b.body && a.newline == b.newline);
        if !same {
            emit_whole_replace(out, old, new);
        }
        return;
    }
    let (mut old_seen, mut new_seen) = (0_usize, 0_usize);
    let mut cursor = 0;
    for (start, end) in windows {
        for op in &ops[cursor..start] {
            match op {
                DiffOp::Keep(_, _) => {
                    old_seen += 1;
                    new_seen += 1;
                }
                DiffOp::Del(_) => old_seen += 1,
                DiffOp::Ins(_) => new_seen += 1,
            }
        }
        let (mut old_count, mut new_count) = (0_usize, 0_usize);
        for op in &ops[start..end] {
            match op {
                DiffOp::Keep(_, _) => {
                    old_count += 1;
                    new_count += 1;
                }
                DiffOp::Del(_) => old_count += 1,
                DiffOp::Ins(_) => new_count += 1,
            }
        }
        // An empty side numbers at the line before the hunk, as git does.
        let old_start = if old_count == 0 {
            old_seen
        } else {
            old_seen + 1
        };
        let new_start = if new_count == 0 {
            new_seen
        } else {
            new_seen + 1
        };
        out.extend_from_slice(
            format!(
                "@@ -{} +{} @@\n",
                hunk_range(old_start, old_count),
                hunk_range(new_start, new_count)
            )
            .as_bytes(),
        );
        for op in &ops[start..end] {
            match op {
                DiffOp::Keep(oi, ni) => {
                    out.push(b' ');
                    out.extend_from_slice(&old[*oi].body);
                    out.push(b'\n');
                    emit_context_no_newline(out, old, *oi, new, *ni);
                    old_seen += 1;
                    new_seen += 1;
                }
                DiffOp::Del(oi) => {
                    out.push(b'-');
                    out.extend_from_slice(&old[*oi].body);
                    out.push(b'\n');
                    emit_side_no_newline(out, old, *oi);
                    old_seen += 1;
                }
                DiffOp::Ins(ni) => {
                    out.push(b'+');
                    out.extend_from_slice(&new[*ni].body);
                    out.push(b'\n');
                    emit_side_no_newline(out, new, *ni);
                    new_seen += 1;
                }
            }
        }
        cursor = end;
    }
}

/// Formats one hunk range: the `,count` suffix is omitted for single-line
/// hunks, kept otherwise (including `0,0` for empty sides).
fn hunk_range(start: usize, count: usize) -> String {
    if count == 1 {
        format!("{start}")
    } else {
        format!("{start},{count}")
    }
}

/// Emits `\ No newline at end of file` after a context line that ends
/// either side's file without a terminator; one marker covers both.
fn emit_context_no_newline(
    out: &mut Vec<u8>,
    old: &[TextLine],
    oi: usize,
    new: &[TextLine],
    ni: usize,
) {
    let old_missing = oi + 1 == old.len() && old.get(oi).is_some_and(|line| !line.newline);
    let new_missing = ni + 1 == new.len() && new.get(ni).is_some_and(|line| !line.newline);
    if old_missing || new_missing {
        out.extend_from_slice(b"\\ No newline at end of file\n");
    }
}

/// Emits the marker after a deletion or addition ending its side's file
/// without a terminator.
fn emit_side_no_newline(out: &mut Vec<u8>, side: &[TextLine], si: usize) {
    if si + 1 == side.len() && side.get(si).is_some_and(|line| !line.newline) {
        out.extend_from_slice(b"\\ No newline at end of file\n");
    }
}

/// Emits one hunk replacing the whole file, the fallback for inputs past
/// the LCS bound (and for newline-only changes, which group no window).
fn emit_whole_replace(out: &mut Vec<u8>, old: &[TextLine], new: &[TextLine]) {
    let old_start = if old.is_empty() { 0 } else { 1 };
    let new_start = if new.is_empty() { 0 } else { 1 };
    out.extend_from_slice(
        format!(
            "@@ -{} +{} @@\n",
            hunk_range(old_start, old.len()),
            hunk_range(new_start, new.len())
        )
        .as_bytes(),
    );
    for line in old {
        out.push(b'-');
        out.extend_from_slice(&line.body);
        out.push(b'\n');
    }
    if old.last().is_some_and(|line| !line.newline) {
        out.extend_from_slice(b"\\ No newline at end of file\n");
    }
    for line in new {
        out.push(b'+');
        out.extend_from_slice(&line.body);
        out.push(b'\n');
    }
    if new.last().is_some_and(|line| !line.newline) {
        out.extend_from_slice(b"\\ No newline at end of file\n");
    }
}

// ---------------------------------------------------------------------------
// mbox dates
// ---------------------------------------------------------------------------

const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// One civil date in an ident's own offset, with its weekday and month
/// index for rendering. Shares the oracle's arithmetic so mbox dates agree
/// with `log` dates.
struct CivilDate {
    /// Full year.
    year: i64,
    /// Day of month.
    day: i64,
    /// Hour, minute, second of the shifted clock.
    hour: i64,
    /// Minute of the shifted clock.
    minute: i64,
    /// Second of the shifted clock.
    second: i64,
    /// Weekday index into [`WEEKDAYS`].
    weekday: usize,
    /// Month index into [`MONTHS`].
    month_index: usize,
}

/// Splits a stamp into civil fields in the ident's own offset.
fn civil_in_offset(stamp: i64, offset: TzOffset) -> CivilDate {
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
    let month_index = usize::try_from(month - 1).expect("month 1..=12 gives index 0..=11");
    CivilDate {
        year: full_year,
        day,
        hour: clock / 3_600,
        minute: (clock % 3_600) / 60,
        second: clock % 60,
        weekday,
        month_index,
    }
}

/// Formats an RFC2822 mbox `Date:` header (`Thu, 19 Oct 2026 12:34:56
/// +0000`), the shape `am` parses back.
fn format_mbox_date(stamp: i64, offset: TzOffset) -> String {
    let civil = civil_in_offset(stamp, offset);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} {offset}",
        WEEKDAYS[civil.weekday],
        civil.day,
        MONTHS[civil.month_index],
        civil.year,
        civil.hour,
        civil.minute,
        civil.second
    )
}

/// Formats the `From <oid> <date>` separator's ctime-style date.
fn format_from_date(stamp: i64, offset: TzOffset) -> String {
    let civil = civil_in_offset(stamp, offset);
    format!(
        "{} {} {} {:02}:{:02}:{:02} {}",
        WEEKDAYS[civil.weekday],
        MONTHS[civil.month_index],
        civil.day,
        civil.hour,
        civil.minute,
        civil.second,
        civil.year
    )
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's
/// algorithm), the inverse of the rendering above.
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

/// Parses an mbox `Date:` value: RFC2822 (`Thu, 19 Oct 2026 12:34:56
/// +0000`, weekday optional), the raw `@<stamp> <tz>` form, or a bare
/// `<stamp> <tz>` pair. Anything else fails naming the value.
fn parse_mbox_date(text: &str) -> Result<(i64, TzOffset), GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad mbox Date: {text:?}"),
    };
    let trimmed = text.trim();
    // Raw `@<stamp> <tz>` or bare `<stamp> <tz>`.
    let bare = trimmed.strip_prefix('@').map_or(trimmed, str::trim);
    let mut parts = bare.split_whitespace();
    if let (Some(first), second) = (parts.next(), parts.next())
        && parts.next().is_none()
    {
        let numeric = first.len() > 4
            && first
                .bytes()
                .enumerate()
                .all(|(i, b)| b.is_ascii_digit() || (i == 0 && b == b'-'));
        if numeric && let Ok(stamp) = first.parse::<i64>() {
            let offset = match second {
                None => TzOffset::UTC,
                Some(tz) => parse_tz_token(tz).ok_or_else(bad)?,
            };
            return Ok((stamp, offset));
        }
    }
    // RFC2822: `[Wday, ]DD Mon YYYY HH:MM:SS TZ`.
    let no_weekday = trimmed
        .split_once(',')
        .map_or(trimmed, |(_, rest)| rest.trim());
    let fields: Vec<&str> = no_weekday.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(bad());
    }
    let Some(day) = fields.first().and_then(|text| text.parse::<i64>().ok()) else {
        return Err(bad());
    };
    let Some(month) = MONTHS
        .iter()
        .position(|name| fields.get(1).is_some_and(|field| *field == *name))
        .map(|index| i64::try_from(index).map(|i| i + 1))
    else {
        return Err(bad());
    };
    let month = month.map_err(|_| bad())?;
    let year: i64 = fields
        .get(2)
        .and_then(|text| text.parse().ok())
        .ok_or_else(bad)?;
    let clock: Vec<&str> = fields
        .get(3)
        .map_or_else(Vec::new, |text| text.split(':').collect());
    if clock.len() != 3 {
        return Err(bad());
    }
    let parse_clock = |index: usize| {
        clock
            .get(index)
            .and_then(|text| text.parse::<i64>().ok())
            .ok_or_else(bad)
    };
    let (hour, minute, second) = (parse_clock(0)?, parse_clock(1)?, parse_clock(2)?);
    if !(1..=31).contains(&day)
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(bad());
    }
    let offset = fields
        .get(4)
        .and_then(|token| parse_tz_token(token))
        .ok_or_else(bad)?;
    let digits = i64::from(offset.hhmm());
    let shift = digits / 100 * 3_600 + digits % 100 * 60;
    let shift = if offset.is_negative() { -shift } else { shift };
    Ok((
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - shift,
        offset,
    ))
}

/// Parses one numeric `+HHMM` token (or the `GMT`/`UT`/`UTC`/`Z`
/// synonyms).
fn parse_tz_token(token: &str) -> Option<TzOffset> {
    if matches!(token, "GMT" | "UT" | "UTC" | "Z") {
        return Some(TzOffset::UTC);
    }
    let bytes = token.as_bytes();
    let sign = bytes.first()?;
    let digits = bytes.get(1..)?;
    if digits.len() != 4 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let hhmm = digits
        .iter()
        .fold(0_u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    match sign {
        b'+' => TzOffset::new(false, hhmm).ok(),
        b'-' => TzOffset::new(true, hhmm).ok(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// format-patch
// ---------------------------------------------------------------------------

/// Prepares mbox patches for a revision range.
///
/// Oracle: `git/builtin/log.c` (`cmd_format_patch`).
pub(crate) fn format_patch(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "stdout",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "output-directory",
            short: Some('o'),
            takes_value: true,
        },
        FlagSpec {
            long: "numbered",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-numbered",
            short: Some('N'),
            takes_value: false,
        },
        FlagSpec {
            long: "unified",
            short: Some('U'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let out_dir = opts.single("output-directory")?;
    if opts.is_set("stdout") && out_dir.is_some() {
        return Err(GitError::Invalid {
            detail: "--stdout and -o/--output-directory do not combine".to_owned(),
        });
    }
    if opts.positionals.is_empty() {
        return Err(GitError::Usage {
            detail: "format-patch needs a revision range (e.g. HEAD~2..HEAD)".to_owned(),
        });
    }
    let context = match opts.single("unified")? {
        None => 3,
        Some(text) => text.parse::<usize>().map_err(|_| GitError::Invalid {
            detail: format!("bad -U {text:?}: want context lines"),
        })?,
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (tips, exclude) = parse_log_revs(store, kind, &opts.positionals, None)?;
    let mut commits = walk_history_excluding(store, &tips, &exclude, None)?;
    commits.reverse();
    for (oid, record) in &commits {
        let parents = record
            .parents()
            .iter()
            .filter_map(|head| head.as_git().copied())
            .count();
        if parents > 1 {
            return Err(GitError::Invalid {
                detail: format!(
                    "commit {} is a merge and cannot be formatted (no -m support)",
                    oid.to_hex()
                ),
            });
        }
    }
    let total = commits.len();
    let numbered = !opts.is_set("no-numbered") && (opts.is_set("numbered") || total > 1);
    let mut out = Vec::new();
    for (index, (oid, record)) in commits.iter().enumerate() {
        let num = numbered.then_some((index + 1, total));
        let mbox = mbox_for_commit(ctx, *oid, record, num, context)?;
        match &out_dir {
            None => out.extend_from_slice(&mbox),
            Some(dir) => {
                let subject = first_subject(record);
                let file = format!("{:04}-{}.patch", index + 1, slug_subject(&subject));
                let target = ctx.env.cwd.join(dir).join(&file);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                        detail: format!("creating {}: {err}", parent.display()),
                    })?;
                }
                std::fs::write(&target, &mbox).map_err(|err| GitError::Io {
                    detail: format!("writing {}: {err}", target.display()),
                })?;
                out.extend_from_slice(format!("{dir}/{file}\n").as_bytes());
            }
        }
    }
    Ok(out)
}

/// Renders one commit as a single mbox message.
fn mbox_for_commit(
    ctx: &Ctx,
    oid: Oid,
    record: &CommitRecord,
    num: Option<(usize, usize)>,
    context: usize,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let parents: Vec<Oid> = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .collect();
    let parent_tree = match parents.first() {
        None => None,
        Some(parent) => Some(commit_tree_oid(&commit_record(store, *parent)?)?),
    };
    let tree = commit_tree_oid(record)?;
    let changes = tree_file_changes(ctx, parent_tree, tree)?;
    let broken = |role: &str| GitError::Corrupt {
        detail: format!("bad {role} ident"),
    };
    let author = record.author().map_err(|_| broken("author"))?;
    let message = String::from_utf8_lossy(record.message()).into_owned();
    let subject = first_subject(record);
    let body = message_body(&message);
    let subject_line = match num {
        None => subject.clone(),
        Some((index, total)) => format!("[PATCH {index}/{total}] {subject}"),
    };
    let name = String::from_utf8_lossy(author.name.as_bytes());
    let email = String::from_utf8_lossy(author.email.as_bytes());
    let mut mbox = format!(
        "From {} {}\nFrom: {name} <{email}>\nDate: {}\nSubject: {subject_line}\n\n",
        oid.to_hex(),
        format_from_date(author.timestamp, author.offset),
        format_mbox_date(author.timestamp, author.offset)
    )
    .into_bytes();
    if !body.is_empty() {
        for line in body.lines() {
            if line.starts_with("From ") {
                mbox.extend_from_slice(b">");
            }
            mbox.extend_from_slice(line.as_bytes());
            mbox.push(b'\n');
        }
    }
    mbox.extend_from_slice(b"\n---\n");
    if !changes.is_empty() {
        mbox.extend_from_slice(&render_file_stat(&changes));
        mbox.extend_from_slice(b"\n");
        mbox.extend_from_slice(&render_patch_diff(ctx, &changes, context));
    }
    mbox.extend_from_slice(format!("-- \nruk {}\n", env!("CARGO_PKG_VERSION")).as_bytes());
    Ok(mbox)
}

/// First message line: the mbox `Subject:` without its prefix.
fn first_subject(record: &CommitRecord) -> String {
    String::from_utf8_lossy(record.message())
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Message body after the subject: leading blank lines skipped, trailing
/// newlines trimmed.
fn message_body(message: &str) -> String {
    let mut parts = message.split('\n');
    parts.next();
    let rest: Vec<&str> = parts.collect();
    let mut start = 0;
    while start < rest.len() && rest[start].trim().is_empty() {
        start += 1;
    }
    rest[start..].join("\n").trim_end().to_owned()
}

/// Slugifies a subject for `-o` file names: runs outside
/// `[A-Za-z0-9._-]` collapse to one `-`, truncated to 60 bytes.
fn slug_subject(subject: &str) -> String {
    let mut slug = String::new();
    let mut dash = false;
    for byte in subject.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            slug.push(char::from(byte));
            dash = false;
        } else if !dash {
            slug.push('-');
            dash = true;
        }
        if slug.len() >= 60 {
            break;
        }
    }
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "patch".to_owned()
    } else {
        slug
    }
}

/// Renders the unified diff for one commit's file changes.
fn render_patch_diff(
    ctx: &Ctx,
    changes: &[super::verbs_history::FileChange],
    context: usize,
) -> Vec<u8> {
    // Bodies come from stored blobs, so rendering cannot fail: a missing
    // object would already have failed the stat pass above.
    let store = match ctx.store() {
        Ok(store) => store,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for change in changes {
        let old_name = change
            .old
            .as_ref()
            .map(|(path, _, _)| String::from_utf8_lossy(path).into_owned());
        let new_name = change
            .new
            .as_ref()
            .map(|(path, _, _)| String::from_utf8_lossy(path).into_owned());
        let display = new_name
            .clone()
            .or_else(|| old_name.clone())
            .unwrap_or_default();
        let old_display = old_name.clone().unwrap_or_else(|| display.clone());
        out.extend_from_slice(format!("diff --git a/{old_display} b/{display}\n").as_bytes());
        let old_mode = change.old.as_ref().map(|(_, mode, _)| *mode);
        let new_mode = change.new.as_ref().map(|(_, mode, _)| *mode);
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
        let renamed = match (&change.old, &change.new) {
            (Some((old_path, _, _)), Some((new_path, _, _))) => old_path != new_path,
            _ => false,
        };
        if renamed {
            out.extend_from_slice(
                format!("similarity index 100%\nrename from {old_display}\nrename to {display}\n")
                    .as_bytes(),
            );
        }
        let old_oid = change.old.as_ref().map(|(_, _, oid)| *oid);
        let new_oid = change.new.as_ref().map(|(_, _, oid)| *oid);
        let content_changed = old_oid != new_oid;
        if content_changed {
            let old_short =
                old_oid.map_or_else(|| "0000000".to_owned(), |oid| oid.to_hex()[..7].to_owned());
            let new_short =
                new_oid.map_or_else(|| "0000000".to_owned(), |oid| oid.to_hex()[..7].to_owned());
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
        let old_body = old_oid.and_then(|oid| read_object_bytes(store, oid).ok());
        let new_body = new_oid.and_then(|oid| read_object_bytes(store, oid).ok());
        if old_body.as_ref().is_some_and(|(_, body)| body.contains(&0))
            || new_body.as_ref().is_some_and(|(_, body)| body.contains(&0))
        {
            let old_side = if change.old.is_some() {
                format!("a/{old_display}")
            } else {
                "/dev/null".to_owned()
            };
            let new_side = if change.new.is_some() {
                format!("b/{display}")
            } else {
                "/dev/null".to_owned()
            };
            out.extend_from_slice(
                format!("Binary files {old_side} and {new_side} differ\n").as_bytes(),
            );
            continue;
        }
        if change.old.is_none() {
            out.extend_from_slice(b"--- /dev/null\n");
        } else {
            out.extend_from_slice(format!("--- a/{old_display}\n").as_bytes());
        }
        if change.new.is_none() {
            out.extend_from_slice(b"+++ /dev/null\n");
        } else {
            out.extend_from_slice(format!("+++ b/{display}\n").as_bytes());
        }
        if !content_changed {
            continue;
        }
        emit_patch_hunks(
            &mut out,
            &split_text(&present_or_empty(old_body)),
            &split_text(&present_or_empty(new_body)),
            context,
        );
    }
    out
}

/// Present blob bytes, or empty for an absent side: an empty body renders
/// whole-file add/remove hunks against the present side.
fn present_or_empty(body: Option<(ruk_core::store::ObjectKind, Vec<u8>)>) -> Vec<u8> {
    body.map_or_else(Vec::new, |(_, bytes)| bytes)
}

// ---------------------------------------------------------------------------
// unified-diff parsing (apply, am)
// ---------------------------------------------------------------------------

/// One hunk line: its ` `/`-`/`+` kind, content, and newline flag.
#[derive(Clone, Debug)]
struct HunkLine {
    /// `b' '`, `b'-'`, or `b'+'`.
    kind: u8,
    /// Line bytes without the terminator.
    body: Vec<u8>,
    /// False after `\ No newline at end of file`.
    newline: bool,
}

/// One parsed `@@` hunk with header counts.
#[derive(Clone, Debug)]
struct PatchHunk {
    /// Old start line (1-based; 0-based position when `old_count` is 0).
    old_start: usize,
    /// Old line count from the header.
    old_count: usize,
    /// New start line (same convention).
    new_start: usize,
    /// New line count from the header.
    new_count: usize,
    /// Body lines in order.
    lines: Vec<HunkLine>,
    /// The old side's last line lacks its newline.
    no_newline_old: bool,
    /// The new side's last line lacks its newline.
    no_newline_new: bool,
}

/// One parsed file patch.
#[derive(Clone, Debug)]
struct PatchFile {
    /// Old name from `---` (or `diff --git`); `/dev/null` for new files.
    old_path: Vec<u8>,
    /// New name from `+++` (or `diff --git`); `/dev/null` for deletions.
    new_path: Vec<u8>,
    /// Octal mode from `old mode`, when given.
    old_mode: Option<u32>,
    /// Octal mode from `new mode`/`new file mode`, when given.
    new_mode: Option<u32>,
    /// Old side is `/dev/null`.
    is_new: bool,
    /// New side is `/dev/null`.
    is_delete: bool,
    /// `rename from`/`rename to` headers were present.
    renamed: bool,
    /// `Binary files ... differ` was present; refused downstream.
    binary: bool,
    /// Content hunks in order.
    hunks: Vec<PatchHunk>,
}

/// Parses unified-diff bytes into per-file patches, accepting both `diff
/// --git` headers and traditional `---`/`+++` openings. Unknown leading
/// lines fail naming the line instead of guessing.
fn parse_patch(bytes: &[u8]) -> Result<Vec<PatchFile>, GitError> {
    let mut lines: Vec<Vec<u8>> = bytes
        .split(|byte| *byte == b'\n')
        .map(|line| {
            line.strip_suffix(b"\r")
                .map_or_else(|| line.to_vec(), <[u8]>::to_vec)
        })
        .collect();
    // The split leaves one artifact empty string after a trailing newline;
    // drop it so it is never read as a context line. A genuine trailing
    // blank context line still parses: its `" "` line precedes this one.
    if bytes.ends_with(b"\n") {
        lines.pop();
    }
    let mut files = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        while index < lines.len()
            && lines
                .get(index)
                .is_some_and(|line| line.is_empty() || line.starts_with(b"Index: "))
        {
            index += 1;
        }
        if index >= lines.len() {
            break;
        }
        let Some(line) = lines.get(index) else {
            break;
        };
        if line.starts_with(b"diff --git ") {
            index = parse_git_file(&lines, index, &mut files)?;
        } else if line.starts_with(b"--- ") {
            index = parse_plain_file(&lines, index, &mut files)?;
        } else {
            return Err(GitError::Invalid {
                detail: format!(
                    "expected 'diff --git' or '---' but found {:?}",
                    preview(line)
                ),
            });
        }
    }
    if files.is_empty() {
        return Err(GitError::Invalid {
            detail: "patch carries no file diffs".to_owned(),
        });
    }
    Ok(files)
}

/// First 60 bytes of a line for diagnostics.
fn preview(line: &[u8]) -> String {
    String::from_utf8_lossy(line.get(..line.len().min(60)).unwrap_or_default()).into_owned()
}

/// Parses one `diff --git` file block starting at `index`; returns the
/// index of the next unconsumed line.
fn parse_git_file(
    lines: &[Vec<u8>],
    mut index: usize,
    files: &mut Vec<PatchFile>,
) -> Result<usize, GitError> {
    let Some(header) = lines.get(index) else {
        return Err(GitError::Invalid {
            detail: "patch ends inside a 'diff --git' header".to_owned(),
        });
    };
    let (git_old, git_new) = parse_git_header(header)?;
    let mut file = PatchFile {
        old_path: git_old,
        new_path: git_new,
        old_mode: None,
        new_mode: None,
        is_new: false,
        is_delete: false,
        renamed: false,
        binary: false,
        hunks: Vec::new(),
    };
    index += 1;
    while index < lines.len() {
        let Some(line) = lines.get(index) else {
            break;
        };
        if line.starts_with(b"diff --git ") {
            break;
        }
        if let Some(rest) = line.strip_prefix(b"old mode ") {
            file.old_mode = Some(parse_mode(rest)?);
        } else if let Some(rest) = line.strip_prefix(b"new mode ") {
            file.new_mode = Some(parse_mode(rest)?);
        } else if let Some(rest) = line.strip_prefix(b"new file mode ") {
            file.new_mode = Some(parse_mode(rest)?);
        } else if let Some(rest) = line.strip_prefix(b"deleted file mode ") {
            file.old_mode = Some(parse_mode(rest)?);
        } else if let Some(rest) = line.strip_prefix(b"rename from ") {
            file.old_path = unquote_path(rest);
            file.renamed = true;
        } else if let Some(rest) = line.strip_prefix(b"rename to ") {
            file.new_path = unquote_path(rest);
            file.renamed = true;
        } else if line.starts_with(b"similarity index ")
            || line.starts_with(b"dissimilarity index ")
            || line.starts_with(b"index ")
        {
            // Informational only.
        } else if line.starts_with(b"Binary files ") && line.ends_with(b" differ") {
            file.binary = true;
            index += 1;
            break;
        } else if let Some(rest) = line.strip_prefix(b"--- ") {
            file.old_path = unquote_path(cut_tab(rest));
        } else if let Some(rest) = line.strip_prefix(b"+++ ") {
            file.new_path = unquote_path(cut_tab(rest));
        } else if line.starts_with(b"@@ ") {
            // `---`/`+++` order is not enforced: a hunk ends the header.
            index = parse_hunks(lines, index, &mut file)?;
            continue;
        } else if line.is_empty() {
            // Blank separators between blocks.
        } else {
            break;
        }
        index += 1;
    }
    finish_file(&mut file);
    files.push(file);
    Ok(index)
}

/// Parses one traditional (`---`/`+++` without `diff --git`) file block.
fn parse_plain_file(
    lines: &[Vec<u8>],
    mut index: usize,
    files: &mut Vec<PatchFile>,
) -> Result<usize, GitError> {
    let Some(first) = lines.get(index) else {
        return Err(GitError::Invalid {
            detail: "patch ends inside a '---' header".to_owned(),
        });
    };
    let Some(old) = first.strip_prefix(b"--- ") else {
        return Err(GitError::Invalid {
            detail: "patch ends inside a '---' header".to_owned(),
        });
    };
    let mut file = PatchFile {
        old_path: unquote_path(cut_tab(old)),
        new_path: Vec::new(),
        old_mode: None,
        new_mode: None,
        is_new: false,
        is_delete: false,
        renamed: false,
        binary: false,
        hunks: Vec::new(),
    };
    index += 1;
    if lines
        .get(index)
        .is_some_and(|line| line.starts_with(b"+++ "))
    {
        let plus = lines.get(index).expect("bounds checked above");
        let Some(new) = plus.strip_prefix(b"+++ ") else {
            return Err(GitError::Corrupt {
                detail: "patch '+++' header does not decode".to_owned(),
            });
        };
        file.new_path = unquote_path(cut_tab(new));
        index += 1;
    }
    index = parse_hunks(lines, index, &mut file)?;
    finish_file(&mut file);
    files.push(file);
    Ok(index)
}

/// Parses consecutive `@@` hunks into `file`; returns the first
/// unconsumed index.
fn parse_hunks(
    lines: &[Vec<u8>],
    mut index: usize,
    file: &mut PatchFile,
) -> Result<usize, GitError> {
    while index < lines.len()
        && lines
            .get(index)
            .is_some_and(|line| line.starts_with(b"@@ "))
    {
        let header = lines.get(index).expect("bounds checked above");
        if header.starts_with(b"@@@ ") {
            return Err(GitError::Invalid {
                detail: "combined diffs are not supported".to_owned(),
            });
        }
        let (old_start, old_count, new_start, new_count) = parse_hunk_header(header)?;
        index += 1;
        let mut hunk = PatchHunk {
            old_start,
            old_count,
            new_start,
            new_count,
            lines: Vec::new(),
            no_newline_old: false,
            no_newline_new: false,
        };
        let mut old_seen = 0usize;
        let mut new_seen = 0usize;
        while index < lines.len() {
            let Some(line) = lines.get(index) else {
                break;
            };
            // A hunk ends when both side counts are met; a trailing `\`
            // marker still binds to the last body line.
            if old_seen >= old_count && new_seen >= new_count {
                break;
            }
            if line.is_empty() {
                // An empty line is a context empty line, as git reads it.
                hunk.lines.push(HunkLine {
                    kind: b' ',
                    body: Vec::new(),
                    newline: true,
                });
                old_seen += 1;
                new_seen += 1;
                index += 1;
            } else {
                match line.first() {
                    Some(b' ') | Some(b'-') | Some(b'+') => {
                        hunk.lines.push(HunkLine {
                            kind: *line.first().expect("matched above"),
                            body: line.get(1..).unwrap_or_default().to_vec(),
                            newline: true,
                        });
                        index += 1;
                    }
                    Some(b'\\') => {
                        let Some(last) = hunk.lines.last_mut() else {
                            return Err(GitError::Invalid {
                                detail: "stray '\\ No newline at end of file'".to_owned(),
                            });
                        };
                        last.newline = false;
                        match last.kind {
                            b'-' => hunk.no_newline_old = true,
                            b'+' => hunk.no_newline_new = true,
                            _ => {
                                hunk.no_newline_old = true;
                                hunk.no_newline_new = true;
                            }
                        }
                        index += 1;
                    }
                    _ => break,
                }
            }
        }
        check_hunk_counts(&hunk)?;
        file.hunks.push(hunk);
    }
    Ok(index)
}

/// Parses `@@ -<o>[,<oc>] +<n>[,<nc>] @@`: counts default to 1.
fn parse_hunk_header(line: &[u8]) -> Result<(usize, usize, usize, usize), GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad hunk header {:?}", preview(line)),
    };
    let text = std::str::from_utf8(line).map_err(|_| bad())?;
    let inner = text
        .strip_prefix("@@ ")
        .and_then(|rest| rest.split(" @@").next())
        .ok_or_else(bad)?;
    let mut parts = inner.split(' ');
    let old = parts.next().ok_or_else(bad)?;
    let new = parts.next().ok_or_else(bad)?;
    let (old_start, old_count) = parse_range(old.strip_prefix('-').ok_or_else(bad)?)?;
    let (new_start, new_count) = parse_range(new.strip_prefix('+').ok_or_else(bad)?)?;
    Ok((old_start, old_count, new_start, new_count))
}

/// Parses one `<start>[,<count>]` hunk range.
fn parse_range(text: &str) -> Result<(usize, usize), GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad hunk range {text:?}"),
    };
    match text.split_once(',') {
        Some((start, count)) => Ok((
            start.parse().map_err(|_| bad())?,
            count.parse().map_err(|_| bad())?,
        )),
        None => Ok((text.parse().map_err(|_| bad())?, 1)),
    }
}

/// Rejects hunks whose header counts disagree with their body lines.
fn check_hunk_counts(hunk: &PatchHunk) -> Result<(), GitError> {
    let mut old_count = 0;
    let mut new_count = 0;
    for line in &hunk.lines {
        match line.kind {
            b' ' => {
                old_count += 1;
                new_count += 1;
            }
            b'-' => old_count += 1,
            b'+' => new_count += 1,
            _ => {}
        }
    }
    if old_count != hunk.old_count || new_count != hunk.new_count {
        return Err(GitError::Invalid {
            detail: format!(
                "hunk @@ -{} +{} @@ body holds {old_count}/{new_count} lines",
                hunk_range(hunk.old_start, hunk.old_count),
                hunk_range(hunk.new_start, hunk.new_count),
            ),
        });
    }
    check_newline_marks(hunk)
}

/// Rejects patches where a non-final line of either side lacks its
/// newline: only the last old-side line (`-`/context) and the last
/// new-side line (`+`/context) may carry the marker.
fn check_newline_marks(hunk: &PatchHunk) -> Result<(), GitError> {
    let last_old = hunk.lines.iter().rposition(|line| line.kind != b'+');
    let last_new = hunk.lines.iter().rposition(|line| line.kind != b'-');
    for (index, line) in hunk.lines.iter().enumerate() {
        if line.newline {
            continue;
        }
        let ends_old = Some(index) == last_old && line.kind != b'+';
        let ends_new = Some(index) == last_new && line.kind != b'-';
        if !ends_old && !ends_new {
            return Err(GitError::Invalid {
                detail: "misplaced '\\ No newline at end of file'".to_owned(),
            });
        }
    }
    Ok(())
}

/// Fills `is_new`/`is_delete` from `/dev/null` sides and defaults an
/// unset name from the other side.
fn finish_file(file: &mut PatchFile) {
    if file.old_path == b"/dev/null" {
        file.is_new = true;
    }
    if file.new_path == b"/dev/null" {
        file.is_delete = true;
    }
    if file.new_path.is_empty() && !file.is_delete {
        file.new_path = file.old_path.clone();
    }
    if file.old_path.is_empty() && !file.is_new {
        file.old_path = file.new_path.clone();
    }
}

/// Splits `diff --git <old> <new>`, honoring double-quoted names.
fn parse_git_header(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>), GitError> {
    let Some(rest) = line.strip_prefix(b"diff --git ") else {
        return Err(GitError::Corrupt {
            detail: "patch 'diff --git' header does not decode".to_owned(),
        });
    };
    let (first, after) = split_git_name(rest)?;
    let second = after.strip_prefix(b" ").unwrap_or(after);
    Ok((unquote_path(first), unquote_path(second)))
}

/// Splits the first name off a `diff --git` tail.
fn split_git_name(rest: &[u8]) -> Result<(&[u8], &[u8]), GitError> {
    if rest.first() == Some(&b'"') {
        let mut index = 1;
        while index < rest.len() {
            if rest.get(index) == Some(&b'\\') {
                index += 2;
                continue;
            }
            if rest.get(index) == Some(&b'"') {
                let (first, after) = rest.split_at(index + 1);
                return Ok((first, after));
            }
            index += 1;
        }
        return Err(GitError::Invalid {
            detail: "unterminated quoted name in 'diff --git'".to_owned(),
        });
    }
    match rest.iter().position(|byte| *byte == b' ') {
        Some(at) => Ok((
            rest.get(..at).unwrap_or_default(),
            rest.get(at..).unwrap_or_default(),
        )),
        None => Err(GitError::Invalid {
            detail: "malformed 'diff --git' header".to_owned(),
        }),
    }
}

/// Unquotes a `"..."` name, unescaping backslash pairs; other names pass
/// through untouched.
fn unquote_path(text: &[u8]) -> Vec<u8> {
    if text.len() >= 2 && text.first() == Some(&b'"') && text.last() == Some(&b'"') {
        let mut out = Vec::with_capacity(text.len());
        let mut index = 1;
        while index < text.len() - 1 {
            if text.get(index) == Some(&b'\\') && index + 1 < text.len() - 1 {
                if let Some(next) = text.get(index + 1) {
                    out.push(*next);
                }
                index += 2;
            } else if let Some(byte) = text.get(index) {
                out.push(*byte);
                index += 1;
            } else {
                break;
            }
        }
        out
    } else {
        text.to_vec()
    }
}

/// Cuts a trailing tab-separated timestamp off a `---`/`+++` name.
fn cut_tab(name: &[u8]) -> &[u8] {
    match name.iter().position(|byte| *byte == b'\t') {
        Some(at) => name.get(..at).unwrap_or_default(),
        None => name,
    }
}

/// Parses an octal file mode.
fn parse_mode(text: &[u8]) -> Result<u32, GitError> {
    let text = std::str::from_utf8(text).map_err(|_| GitError::Invalid {
        detail: format!("bad file mode {:?}", preview(text)),
    })?;
    u32::from_str_radix(text.trim(), 8).map_err(|_| GitError::Invalid {
        detail: format!("bad file mode {text:?}"),
    })
}

/// Strips `depth` leading components (`-p`, default 1); `/dev/null`
/// passes through for side detection.
fn strip_path(path: &[u8], depth: usize) -> Result<Vec<u8>, GitError> {
    if path == b"/dev/null" {
        return Ok(path.to_vec());
    }
    let parts: Vec<&[u8]> = path.split(|byte| *byte == b'/').collect();
    if parts.len() <= depth {
        return Err(GitError::Invalid {
            detail: format!("cannot strip {depth} from {:?}", preview(path)),
        });
    }
    Ok(parts[depth..].join(&b'/'))
}

// ---------------------------------------------------------------------------
// hunk application
// ---------------------------------------------------------------------------

/// Old-side bodies of one hunk: context plus deletions, in order.
fn hunk_old_seq(hunk: &PatchHunk) -> Vec<&[u8]> {
    hunk.lines
        .iter()
        .filter(|line| line.kind != b'+')
        .map(|line| line.body.as_slice())
        .collect()
}

/// Builds the replacement lines for a hunk matched at `pos`: context
/// lines keep the file's bytes, additions come from the patch, and every
/// line but the last terminates (the last follows the patch's marker).
fn hunk_new_lines(hunk: &PatchHunk, file: &[TextLine], pos: usize) -> Vec<TextLine> {
    let mut out = Vec::new();
    let mut cursor = pos;
    for line in &hunk.lines {
        match line.kind {
            b'-' => cursor += 1,
            b' ' => {
                if let Some(current) = file.get(cursor) {
                    out.push(TextLine {
                        body: current.body.clone(),
                        newline: true,
                    });
                }
                cursor += 1;
            }
            _ => {
                out.push(TextLine {
                    body: line.body.clone(),
                    newline: true,
                });
            }
        }
    }
    if let Some(last) = out.last_mut() {
        last.newline = !hunk.no_newline_new;
    }
    out
}

/// Reports whether a hunk's old side matches `file` at `pos`, bodies only.
/// A claimed missing trailing newline is enforced only when the match ends
/// at the file's last line; mid-file lines always terminate.
fn matches_at(file: &[TextLine], pos: usize, hunk: &PatchHunk) -> bool {
    let seq = hunk_old_seq(hunk);
    if pos + seq.len() > file.len() {
        return false;
    }
    for (offset, want) in seq.iter().enumerate() {
        if file.get(pos + offset).is_none_or(|line| line.body != *want) {
            return false;
        }
    }
    if hunk.no_newline_old
        && let Some(last) = seq.len().checked_sub(1)
        && pos + last + 1 == file.len()
        && file.get(pos + last).is_some_and(|line| line.newline)
    {
        return false;
    }
    true
}

/// Applies one hunk to `lines`, trying the expected position first and
/// then scanning the whole file; returns the line-count delta.
fn apply_one_hunk(
    lines: &mut Vec<TextLine>,
    hunk: &PatchHunk,
    want: usize,
) -> Result<isize, GitError> {
    let old_len = hunk_old_seq(hunk).len();
    let mut found = None;
    if matches_at(lines, want.min(lines.len()), hunk) {
        found = Some(want.min(lines.len()));
    } else {
        let limit = lines.len().saturating_sub(old_len);
        for pos in 0..=limit {
            if matches_at(lines, pos, hunk) {
                found = Some(pos);
                break;
            }
        }
    }
    let Some(pos) = found else {
        return Err(GitError::Invalid {
            detail: format!(
                "patch does not apply: hunk @@ -{} +{} @@ has no match",
                hunk_range(hunk.old_start, hunk.old_count),
                hunk_range(hunk.new_start, hunk.new_count),
            ),
        });
    };
    let replacement = hunk_new_lines(hunk, lines, pos);
    let new_len = replacement.len();
    lines.splice(pos..pos + old_len, replacement);
    let new_delta = isize::try_from(new_len).map_err(|_| GitError::Limit {
        detail: "patched file exceeds the line range".to_owned(),
    })?;
    let old_delta = isize::try_from(old_len).map_err(|_| GitError::Limit {
        detail: "patched file exceeds the line range".to_owned(),
    })?;
    Ok(new_delta - old_delta)
}

/// Applies every hunk of one file patch to `base`, tracking the running
/// offset from the hunk headers.
fn apply_hunks_to(base: &[TextLine], hunks: &[PatchHunk]) -> Result<Vec<TextLine>, GitError> {
    let mut lines = base.to_vec();
    let mut delta: isize = 0;
    for hunk in hunks {
        let header_pos = isize::try_from(if hunk.old_count == 0 {
            hunk.old_start
        } else {
            hunk.old_start.saturating_sub(1)
        })
        .map_err(|_| GitError::Limit {
            detail: "hunk offset exceeds the range".to_owned(),
        })?;
        let want = usize::try_from((header_pos + delta).max(0)).map_err(|_| GitError::Limit {
            detail: "hunk offset exceeds the range".to_owned(),
        })?;
        delta += apply_one_hunk(&mut lines, hunk, want)?;
    }
    Ok(lines)
}

/// Swaps a file patch's sides for `--reverse`.
fn reverse_file(file: &mut PatchFile) {
    std::mem::swap(&mut file.old_path, &mut file.new_path);
    std::mem::swap(&mut file.old_mode, &mut file.new_mode);
    std::mem::swap(&mut file.is_new, &mut file.is_delete);
    for hunk in &mut file.hunks {
        std::mem::swap(&mut hunk.old_start, &mut hunk.new_start);
        std::mem::swap(&mut hunk.old_count, &mut hunk.new_count);
        std::mem::swap(&mut hunk.no_newline_old, &mut hunk.no_newline_new);
        for line in &mut hunk.lines {
            line.kind = match line.kind {
                b'-' => b'+',
                b'+' => b'-',
                other => other,
            };
        }
    }
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

/// Where `apply` reads bases from and writes results to. A named type,
/// never a flag triple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyTarget {
    /// Worktree files only.
    Worktree,
    /// Index rows only.
    IndexOnly,
    /// Index rows plus worktree files.
    IndexAndWorktree,
}

/// One validated file application: stripped paths and result bytes.
struct ApplyPlan {
    /// Pre-image path (old side, stripped).
    old_path: Vec<u8>,
    /// Post-image path (new side, stripped).
    new_path: Vec<u8>,
    /// Result bytes after the hunks.
    result: Vec<u8>,
    /// Result index mode.
    result_mode: FileMode,
    /// Create the path.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    is_new: bool,
    /// Remove the path.
    is_delete: bool,
    /// Pre-image path differs (rename).
    renamed: bool,
}

/// Applies a unified diff to the worktree and/or index.
///
/// Oracle: `git/builtin/apply.c`.
pub(crate) fn apply(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "index",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "cached",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "check",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "stat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "numstat",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "reverse",
            short: Some('R'),
            takes_value: false,
        },
        FlagSpec {
            long: "strip",
            short: Some('p'),
            takes_value: true,
        },
        // Accepted: a successful apply prints nothing either way.
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    if opts.is_set("stat") && opts.is_set("numstat") {
        return Err(GitError::Invalid {
            detail: "--stat and --numstat do not combine".to_owned(),
        });
    }
    let strip = parse_strip(&opts)?;
    let patch = if opts.positionals.is_empty() {
        read_stdin_bytes(&ctx.env)?
    } else {
        let mut all = Vec::new();
        for name in &opts.positionals {
            let path = ctx.env.cwd.join(name);
            all.extend_from_slice(&std::fs::read(&path).map_err(|err| GitError::Io {
                detail: format!("reading {}: {err}", path.display()),
            })?);
        }
        all
    };
    let mut files = parse_patch(&patch)?;
    if opts.is_set("reverse") {
        for file in &mut files {
            reverse_file(file);
        }
    }
    if opts.is_set("stat") {
        return Ok(render_apply_stat(&files, strip));
    }
    if opts.is_set("numstat") {
        return Ok(render_apply_numstat(&files, strip));
    }
    let target = if opts.is_set("cached") {
        ApplyTarget::IndexOnly
    } else if opts.is_set("index") {
        ApplyTarget::IndexAndWorktree
    } else {
        ApplyTarget::Worktree
    };
    let plans = plan_apply(ctx, &files, strip, target)?;
    if opts.is_set("check") {
        return Ok(Vec::new());
    }
    execute_apply(ctx, &plans, target)?;
    Ok(Vec::new())
}

/// Validates every file patch against its base without mutating anything.
fn plan_apply(
    ctx: &Ctx,
    files: &[PatchFile],
    strip: usize,
    target: ApplyTarget,
) -> Result<Vec<ApplyPlan>, GitError> {
    let mut plans = Vec::with_capacity(files.len());
    for file in files {
        if file.binary {
            return Err(GitError::Invalid {
                detail: "binary patches are not supported".to_owned(),
            });
        }
        plans.push(plan_one_file(ctx, file, strip, target)?);
    }
    Ok(plans)
}

/// Validates one file patch: resolves paths, reads the base, applies the
/// hunks in memory, and derives the result mode.
fn plan_one_file(
    ctx: &Ctx,
    file: &PatchFile,
    strip: usize,
    target: ApplyTarget,
) -> Result<ApplyPlan, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let old_path = strip_path(&file.old_path, strip)?;
    // Deletions name `/dev/null` on the new side: every row mutation and
    // worktree write must address the real pre-image path instead.
    let new_path = if file.is_delete {
        old_path.clone()
    } else {
        strip_path(&file.new_path, strip)?
    };
    let (base, base_mode) = if file.is_new {
        ensure_absent_for_create(ctx, &new_path, target, store, kind)
            .map_err(|err| wrap_path(&new_path, err))?;
        (Vec::new(), FileMode::Regular)
    } else if target == ApplyTarget::Worktree {
        read_worktree_existing(ctx, &old_path).map_err(|err| wrap_path(&new_path, err))?
    } else {
        read_index_existing(store, kind, &old_path).map_err(|err| wrap_path(&new_path, err))?
    };
    if target == ApplyTarget::IndexAndWorktree && !file.is_new {
        check_worktree_matches(ctx, &old_path, &base).map_err(|err| wrap_path(&new_path, err))?;
    }
    let result_lines =
        apply_hunks_to(&split_text(&base), &file.hunks).map_err(|err| wrap_path(&new_path, err))?;
    let result = join_text(&result_lines);
    let result_mode =
        patch_result_mode(file, base_mode).map_err(|err| wrap_path(&new_path, err))?;
    // Operational rename: the stripped paths differ on a modified file, so
    // the pre-image rows and file must go. New files keep the `/dev/null`
    // side, which is never a repository path; deletes already normalized
    // the new side onto the old one above.
    let renamed = !file.is_new && old_path != new_path;
    Ok(ApplyPlan {
        old_path,
        new_path,
        result,
        result_mode,
        is_new: file.is_new,
        is_delete: file.is_delete,
        renamed,
    })
}

/// Refuses a new-file patch when its path already exists on the side it
/// would create: the worktree for worktree targets, the index otherwise.
fn ensure_absent_for_create(
    ctx: &Ctx,
    new_path: &[u8],
    target: ApplyTarget,
    store: &ruk_core::store::Store,
    kind: HashKind,
) -> Result<(), GitError> {
    if target != ApplyTarget::Worktree {
        let repo = RepoPath::new(new_path.to_vec()).map_err(to_core_invalid)?;
        let rows = read_path_rows(store, kind, &repo)?;
        if rows.iter().any(|(stage, _, _)| *stage == Stage::Zero) {
            return Err(GitError::Invalid {
                detail: format!(
                    "path {} is already in the index",
                    String::from_utf8_lossy(new_path)
                ),
            });
        }
    }
    if target != ApplyTarget::IndexOnly {
        let full = join_base(&ctx.file_base, new_path)?;
        if full.is_symlink() || full.exists() {
            return Err(GitError::Invalid {
                detail: format!(
                    "path {} already exists in the worktree",
                    String::from_utf8_lossy(new_path)
                ),
            });
        }
    }
    Ok(())
}

/// Reads an existing worktree file's bytes and mode for a patch base.
fn read_worktree_existing(ctx: &Ctx, path: &[u8]) -> Result<(Vec<u8>, FileMode), GitError> {
    let full = join_base(&ctx.file_base, path)?;
    let meta = std::fs::symlink_metadata(&full).map_err(|_| GitError::Invalid {
        detail: format!(
            "path {} does not exist in the worktree",
            String::from_utf8_lossy(path)
        ),
    })?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&full).map_err(|err| GitError::Io {
            detail: format!("reading link {}: {err}", full.display()),
        })?;
        return Ok((
            target.as_os_str().as_encoded_bytes().to_vec(),
            FileMode::Symlink,
        ));
    }
    if meta.file_type().is_dir() {
        return Err(GitError::Invalid {
            detail: format!("path {} is a directory", String::from_utf8_lossy(path)),
        });
    }
    let mode = super::verbs_stage::file_mode_of(&meta);
    let bytes = read_worktree_file(&ctx.file_base, path)?;
    Ok((bytes, mode))
}

/// Reads an existing stage-zero index row's bytes and mode.
fn read_index_existing(
    store: &ruk_core::store::Store,
    kind: HashKind,
    path: &[u8],
) -> Result<(Vec<u8>, FileMode), GitError> {
    let repo = RepoPath::new(path.to_vec()).map_err(to_core_invalid)?;
    let rows = read_path_rows(store, kind, &repo)?;
    let Some((_, entry, _)) = rows.iter().find(|(stage, _, _)| *stage == Stage::Zero) else {
        return Err(GitError::Invalid {
            detail: format!("path {} is not in the index", String::from_utf8_lossy(path)),
        });
    };
    if entry.mode() == FileMode::Gitlink {
        return Err(GitError::Invalid {
            detail: "gitlink patches are not supported".to_owned(),
        });
    }
    let (_, body) = read_object_bytes(store, entry.oid())?;
    Ok((body, entry.mode()))
}

/// Refuses an `--index` application when the worktree copy of a touched
/// path already differs from the index base it would overwrite.
fn check_worktree_matches(ctx: &Ctx, old_path: &[u8], base: &[u8]) -> Result<(), GitError> {
    let full = join_base(&ctx.file_base, old_path)?;
    if !full.is_symlink() && !full.is_file() {
        return Err(GitError::Invalid {
            detail: format!(
                "worktree {} is missing for --index",
                String::from_utf8_lossy(old_path)
            ),
        });
    }
    let (current, _) = read_worktree_existing(ctx, old_path)?;
    if current != *base {
        return Err(GitError::Invalid {
            detail: format!(
                "worktree {} does not match the index base",
                String::from_utf8_lossy(old_path)
            ),
        });
    }
    Ok(())
}

/// Derives the result mode: the patch's new mode wins, then its old mode,
/// then the base mode. Gitlinks are refused, never carried.
fn patch_result_mode(file: &PatchFile, base_mode: FileMode) -> Result<FileMode, GitError> {
    let Some(octal) = file.new_mode.or(file.old_mode) else {
        return Ok(base_mode);
    };
    let mode = FileMode::from_octal(octal).map_err(to_core_invalid)?;
    if mode == FileMode::Gitlink {
        return Err(GitError::Invalid {
            detail: "gitlink patches are not supported".to_owned(),
        });
    }
    Ok(mode)
}

/// Maps a model failure into the interpreter error space.
fn to_core_invalid(err: impl Into<CoreError>) -> GitError {
    GitError::from(err.into())
}

/// Prefixes an `Invalid` failure with the patch path it came from; other
/// errors pass through untouched.
fn wrap_path(path: &[u8], err: GitError) -> GitError {
    match err {
        GitError::Invalid { detail } => GitError::Invalid {
            detail: format!("{}: {detail}", String::from_utf8_lossy(path)),
        },
        other => other,
    }
}

/// Writes validated plans to the index and/or worktree. Index rows publish
/// in one transaction with a single generation bump; worktree files follow.
fn execute_apply(ctx: &Ctx, plans: &[ApplyPlan], target: ApplyTarget) -> Result<(), GitError> {
    if target != ApplyTarget::Worktree {
        let store = ctx.store()?;
        let kind = ctx.kind()?;
        let (workspace, raw) = load_or_default(store)?;
        let mut mutations = Vec::new();
        let mut objects = Vec::new();
        for plan in plans {
            stage_plan_result(store, kind, plan, &mut objects, &mut mutations)?;
        }
        let next = workspace
            .mutate_index(workspace.stamp)
            .map_err(to_core_invalid)?;
        mutations.push(workspace_mutation(raw.as_deref(), &next)?);
        mutations.push(super::state::index_stamp_mutation()?);
        store
            .publish(
                objects,
                &mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .map_err(GitError::from)?;
    }
    if target != ApplyTarget::IndexOnly {
        for plan in plans {
            write_plan_worktree(ctx, plan)?;
        }
        // Worktree-only applies leave the rows naming old bytes: only
        // refresh when the index transaction above staged the same results.
        // Deletes name `/dev/null`, never a repository path.
        if target != ApplyTarget::Worktree {
            let store = ctx.store()?;
            let kind = ctx.kind()?;
            let written: Vec<Vec<u8>> = plans
                .iter()
                .filter(|plan| !plan.is_delete)
                .map(|plan| plan.new_path.clone())
                .collect();
            super::state::refresh_stats_after_write(ctx, store, kind, &written)?;
        }
    }
    Ok(())
}

/// Stages one plan's result rows (or row deletions) into the pending
/// index transaction.
fn stage_plan_result(
    store: &ruk_core::store::Store,
    kind: HashKind,
    plan: &ApplyPlan,
    objects: &mut Vec<ruk_core::store::PreparedObject>,
    mutations: &mut Vec<ruk_core::store::FactMutation>,
) -> Result<(), GitError> {
    if plan.renamed && plan.old_path != plan.new_path {
        let old_repo = RepoPath::new(plan.old_path.clone()).map_err(to_core_invalid)?;
        let before = read_path_rows(store, kind, &old_repo)?;
        mutations.extend(path_row_mutations(&old_repo, &before, &[])?);
    }
    let new_repo = RepoPath::new(plan.new_path.clone()).map_err(to_core_invalid)?;
    let before = read_path_rows(store, kind, &new_repo)?;
    if plan.is_delete {
        mutations.extend(path_row_mutations(&new_repo, &before, &[])?);
        return Ok(());
    }
    let entry = IndexEntry::for_blob(kind, plan.result_mode, &plan.result, None)
        .map_err(to_core_invalid)?;
    let len = u64::try_from(plan.result.len()).map_err(|_| GitError::Limit {
        detail: "patched blob exceeds the length range".to_owned(),
    })?;
    objects.push(
        store
            .prepare(
                ruk_core::store::types::ObjectKind::Blob,
                len,
                std::io::Cursor::new(plan.result.clone()),
                None,
            )
            .map_err(GitError::from)?,
    );
    mutations.extend(path_row_mutations(
        &new_repo,
        &before,
        &[(Stage::Zero, entry)],
    )?);
    Ok(())
}

/// Writes one plan's result to the worktree: files, symlinks, removals.
fn write_plan_worktree(ctx: &Ctx, plan: &ApplyPlan) -> Result<(), GitError> {
    if plan.is_delete {
        let full = join_base(&ctx.file_base, &plan.new_path)?;
        if full.is_symlink() || full.is_file() {
            std::fs::remove_file(&full).map_err(|err| GitError::Io {
                detail: format!("removing {}: {err}", full.display()),
            })?;
        }
        return Ok(());
    }
    if plan.renamed && plan.old_path != plan.new_path {
        let old_full = join_base(&ctx.file_base, &plan.old_path)?;
        if old_full.is_symlink() || old_full.is_file() {
            std::fs::remove_file(&old_full).map_err(|err| GitError::Io {
                detail: format!("removing {}: {err}", old_full.display()),
            })?;
        }
    }
    write_worktree_bytes(ctx, &plan.new_path, plan.result_mode, &plan.result)
}

/// Writes bytes to one worktree path, creating parents and honoring the
/// executable bit and symlinks.
fn write_worktree_bytes(
    ctx: &Ctx,
    path: &[u8],
    mode: FileMode,
    bytes: &[u8],
) -> Result<(), GitError> {
    let full = join_base(&ctx.file_base, path)?;
    if mode == FileMode::Symlink {
        let text = std::str::from_utf8(bytes).map_err(|_| GitError::Invalid {
            detail: "symlink target is not valid UTF-8".to_owned(),
        })?;
        #[cfg(unix)]
        {
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
                    detail: format!("creating {}: {err}", parent.display()),
                })?;
            }
            if full.is_symlink() || full.exists() {
                std::fs::remove_file(&full).map_err(|err| GitError::Io {
                    detail: format!("removing {}: {err}", full.display()),
                })?;
            }
            std::os::unix::fs::symlink(text, &full).map_err(|err| GitError::Io {
                detail: format!("linking {}: {err}", full.display()),
            })?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let _ = text;
            return Err(GitError::Unsupported {
                command: "symlink patches need a Unix worktree".to_owned(),
            });
        }
    }
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
    // The patch names the exact mode, so both directions apply: dropping
    // the executable bit is as much a result as setting it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let bits = if mode == FileMode::Executable {
            0o755
        } else {
            0o644
        };
        std::fs::set_permissions(&full, std::fs::Permissions::from_mode(bits)).map_err(|err| {
            GitError::Io {
                detail: format!("chmod {}: {err}", full.display()),
            }
        })?;
    }
    Ok(())
}

/// One stat row: display name with added/removed counts.
struct ApplyStatRow {
    /// Display name (`old => new` for renames).
    name: String,
    /// Added lines.
    added: usize,
    /// Removed lines.
    removed: usize,
}

/// Collects per-file counts for `--stat`/`--numstat`.
fn apply_stat_rows(files: &[PatchFile], strip: usize) -> Vec<ApplyStatRow> {
    let mut rows = Vec::with_capacity(files.len());
    for file in files {
        let (mut added, mut removed) = (0, 0);
        for hunk in &file.hunks {
            for line in &hunk.lines {
                match line.kind {
                    b'+' => added += 1,
                    b'-' => removed += 1,
                    _ => {}
                }
            }
        }
        rows.push(ApplyStatRow {
            name: stat_name(file, strip),
            added,
            removed,
        });
    }
    rows
}

/// Renders `--stat` for parsed patches without touching anything.
fn render_apply_stat(files: &[PatchFile], strip: usize) -> Vec<u8> {
    let rows = apply_stat_rows(files, strip);
    let mut out = Vec::new();
    let (mut added_total, mut removed_total) = (0, 0);
    for row in &rows {
        added_total += row.added;
        removed_total += row.removed;
        out.extend_from_slice(
            format!(
                " {} | {} {}{}\n",
                row.name,
                row.added + row.removed,
                "+".repeat(row.added),
                "-".repeat(row.removed)
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(&stat_summary(rows.len(), added_total, removed_total));
    out
}

/// Renders `--numstat` for parsed patches without touching anything.
fn render_apply_numstat(files: &[PatchFile], strip: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for row in apply_stat_rows(files, strip) {
        out.extend_from_slice(format!("{}\t{}\t{}\n", row.added, row.removed, row.name).as_bytes());
    }
    out
}

/// Names a patch file for stat output: `old => new` for renames, the new
/// path otherwise (the old path for deletions).
fn stat_name(file: &PatchFile, strip: usize) -> String {
    let old = strip_path(&file.old_path, strip).unwrap_or_else(|_| file.old_path.clone());
    let new = strip_path(&file.new_path, strip).unwrap_or_else(|_| file.new_path.clone());
    if file.renamed && old != new {
        return format!(
            "{} => {}",
            String::from_utf8_lossy(&old),
            String::from_utf8_lossy(&new)
        );
    }
    if file.is_delete {
        String::from_utf8_lossy(&old).into_owned()
    } else {
        String::from_utf8_lossy(&new).into_owned()
    }
}

// ---------------------------------------------------------------------------
// am
// ---------------------------------------------------------------------------

/// Pseudo-head holding the in-progress `am` session: the abort head plus
/// framed remaining mbox messages.
const AM_STATE: &str = "AM_STATE";

/// One parsed mbox message: envelope plus content patches.
#[derive(Clone, Debug)]
struct AmMessage {
    /// Commit author from `From:` with the stamp from `Date:`.
    author: Signature,
    /// Commit subject (`[PATCH n/m]` prefixes stripped unless kept).
    subject: String,
    /// Commit body after the subject.
    body: String,
    /// Content patches from the message's diff section.
    patches: Vec<PatchFile>,
}

/// Applies mbox patches as commits.
///
/// Oracle: `git/builtin/am.c`.
pub(crate) fn am(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "signoff",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "keep",
            short: Some('k'),
            takes_value: false,
        },
        FlagSpec {
            long: "strip",
            short: Some('p'),
            takes_value: true,
        },
        FlagSpec {
            long: "continue",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "skip",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "abort",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quit",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let store = ctx.store()?;
    let state = pseudo_read(store, AM_STATE)?;
    let controls = ["continue", "skip", "abort", "quit"]
        .into_iter()
        .filter(|name| opts.is_set(name))
        .collect::<Vec<_>>();
    if controls.len() > 1 {
        return Err(GitError::Invalid {
            detail: "am takes at most one of --continue, --skip, --abort, --quit".to_owned(),
        });
    }
    if let Some(control) = controls.first() {
        let Some(raw) = state else {
            return Err(GitError::Invalid {
                detail: format!("no am in progress for --{control}"),
            });
        };
        let (abort, pending) = decode_am_state(&raw)?;
        return match *control {
            "abort" => am_abort(ctx, &abort),
            "quit" => {
                pseudo_delete(store, AM_STATE)?;
                Ok(Vec::new())
            }
            "skip" => {
                let rest = pending.into_iter().skip(1).collect::<Vec<_>>();
                am_resume(ctx, &abort, rest, &opts, None)
            }
            _ => am_continue(ctx, &abort, pending, &opts),
        };
    }
    if state.is_some() {
        return Err(GitError::Invalid {
            detail: "am already in progress (use --continue, --skip, or --abort)".to_owned(),
        });
    }
    let raws = read_mbox_inputs(ctx, &opts.positionals)?;
    if raws.is_empty() {
        return Err(GitError::Invalid {
            detail: "no mbox patches found (missing From lines?)".to_owned(),
        });
    }
    require_clean_for_am(ctx)?;
    let abort = head_oid(store)?.to_hex();
    am_resume(ctx, &abort, raws, &opts, None)
}

/// Reads mbox inputs from files, or stdin when no files are named.
fn read_mbox_inputs(ctx: &Ctx, names: &[String]) -> Result<Vec<Vec<u8>>, GitError> {
    let mut out = Vec::new();
    if names.is_empty() {
        let bytes = read_stdin_bytes(&ctx.env)?;
        out.extend(split_mbox(&bytes));
        return Ok(out);
    }
    for name in names {
        let path = ctx.env.cwd.join(name);
        let bytes = std::fs::read(&path).map_err(|err| GitError::Io {
            detail: format!("reading {}: {err}", path.display()),
        })?;
        out.extend(split_mbox(&bytes));
    }
    Ok(out)
}

/// Splits mbox bytes into per-message raws on `From ` envelope lines.
/// Bodies escaping `From ` as `>From ` survive the split; every raw is
/// normalized to `\n` endings with one trailing newline.
fn split_mbox(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut current: Vec<Vec<u8>> = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line
            .strip_suffix(b"\r")
            .map_or_else(|| line.to_vec(), <[u8]>::to_vec);
        if line.starts_with(b"From ") && !current.is_empty() {
            out.push(join_raw(&current));
            current = Vec::new();
        }
        current.push(line);
    }
    if current.iter().any(|line| !line.is_empty()) {
        out.push(join_raw(&current));
    }
    out
}

/// Joins split lines into one normalized message raw: trailing blank
/// lines collapse so the raw ends in exactly one newline. Without this,
/// the split artifact after a trailing newline would double it and push
/// the mbox signature out of the strip window below.
fn join_raw(lines: &[Vec<u8>]) -> Vec<u8> {
    let mut end = lines.len();
    while end > 0 && lines[end - 1].is_empty() {
        end -= 1;
    }
    let mut out = Vec::new();
    for line in &lines[..end] {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Refuses `am` over unmerged paths or a dirty index, which the per-patch
/// commits would otherwise sweep into the new trees.
fn require_clean_for_am(ctx: &Ctx) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "unmerged paths must be resolved before am".to_owned(),
        });
    }
    let head = head_oid(store)?;
    let head_tree = commit_tree_oid(&commit_record(store, head)?)?;
    let index_tree = build_index_tree(store, kind, &merged_rows(&rows))?;
    if index_tree != head_tree {
        return Err(GitError::Invalid {
            detail: "staged changes would be overwritten by am (commit or stash them)".to_owned(),
        });
    }
    Ok(())
}

/// Applies the remaining messages, seeding the file map from `HEAD`.
/// `continued` carries the already-committed current message for
/// `--continue`, whose remaining messages apply after it.
fn am_resume(
    ctx: &mut Ctx,
    abort: &str,
    pending: Vec<Vec<u8>>,
    opts: &super::Collected,
    continued: Option<String>,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let strip = parse_strip(opts)?;
    let head = head_oid(store)?;
    let head_tree = commit_tree_oid(&commit_record(store, head)?)?;
    let mut map = seed_file_map(store, kind, head_tree)?;
    let mut pending = pending;
    let mut out = Vec::new();
    if let Some(summary) = continued {
        out.extend_from_slice(summary.as_bytes());
    }
    while let Some(raw) = pending.first() {
        let parsed = if opts.is_set("keep") {
            parse_message_keep(raw)
        } else {
            parse_message(raw)
        };
        let message = match parsed {
            Ok(message) => message,
            Err(err) => {
                let store = ctx.store()?;
                save_am_state(store, abort, &pending)?;
                return Err(with_am_hint(err));
            }
        };
        match am_apply_message(ctx, &message, &mut map, opts, strip) {
            Ok(summary) => {
                out.extend_from_slice(&summary);
                pending.remove(0);
            }
            Err(err) => {
                let store = ctx.store()?;
                save_am_state(store, abort, &pending)?;
                return Err(with_am_hint(err));
            }
        }
    }
    let store = ctx.store()?;
    pseudo_delete(store, AM_STATE)?;
    Ok(out)
}

/// Points a stopped `am` at its resumption verbs. Every stoppage leaves
/// the session behind, so every failure carries the same hint.
fn with_am_hint(err: GitError) -> GitError {
    let mut detail = err.to_string();
    detail.push_str(
        "\nhint: resolve the failure and run `am --continue`, `am --skip`, or `am --abort`",
    );
    GitError::Invalid { detail }
}

/// Parses `-p/--strip` (default 1) for `apply` and `am`.
fn parse_strip(opts: &super::Collected) -> Result<usize, GitError> {
    match opts.single("strip")? {
        None => Ok(1),
        Some(text) => text.parse::<usize>().map_err(|_| GitError::Invalid {
            detail: format!("bad -p {text:?}: want strip components"),
        }),
    }
}

/// Seeds the path-to-content map from the `HEAD` tree. Gitlink and tree
/// entries seed without bytes; touching them fails closed downstream.
fn seed_file_map(
    store: &ruk_core::store::Store,
    kind: HashKind,
    tree: Oid,
) -> Result<SeedFileMap, GitError> {
    let mut map = BTreeMap::new();
    for (path, mode, oid) in flatten_tree(store, kind, tree)? {
        let body = match mode {
            TreeMode::Gitlink | TreeMode::Tree => None,
            _ => Some(read_object_bytes(store, oid).map(|(_, body)| body)?),
        };
        map.insert(path, (mode, body));
    }
    Ok(map)
}

/// Applies one message: in-memory hunk validation, worktree guards,
/// worktree plus index writes, then the commit.
fn am_apply_message(
    ctx: &mut Ctx,
    message: &AmMessage,
    map: &mut BTreeMap<Vec<u8>, (TreeMode, Option<Vec<u8>>)>,
    opts: &super::Collected,
    strip: usize,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for file in &message.patches {
        if file.binary {
            return Err(GitError::Invalid {
                detail: format!(
                    "binary patch for {} is not supported",
                    preview(&file.new_path)
                ),
            });
        }
    }
    // Phase 1: every hunk applies to the in-memory map before anything is
    // written, so a failure leaves no partial state.
    // Each entry: pre-image path, post-image path, result bytes, result
    // mode, whether the path is deleted.
    let mut results: Vec<AmApplyResult> = Vec::new();
    for file in &message.patches {
        let old_path = strip_path(&file.old_path, strip)?;
        // Deletions name `/dev/null` on the new side: every row mutation
        // and worktree write must address the real pre-image path instead.
        let new_path = if file.is_delete {
            old_path.clone()
        } else {
            strip_path(&file.new_path, strip)?
        };
        let wrap = |detail: String| GitError::Invalid {
            detail: format!("{}: {detail}", String::from_utf8_lossy(&new_path)),
        };
        if file.is_new && map.contains_key(&old_path) {
            return Err(wrap(format!(
                "path {} already exists",
                String::from_utf8_lossy(&old_path)
            )));
        }
        let base = if file.is_new {
            (TreeMode::Regular, Vec::new())
        } else {
            let Some((mode, body)) = map.get(&old_path) else {
                return Err(wrap(format!(
                    "path {} does not match any HEAD file",
                    String::from_utf8_lossy(&old_path)
                )));
            };
            let Some(body) = body else {
                return Err(GitError::Invalid {
                    detail: "gitlink patches are not supported".to_owned(),
                });
            };
            (*mode, body.clone())
        };
        let result_mode =
            patch_result_mode(file, tree_mode_of(base.0)).map_err(|err| match err {
                GitError::Invalid { detail } => wrap(detail),
                other => other,
            })?;
        let applied =
            apply_hunks_to(&split_text(&base.1), &file.hunks).map_err(|err| match err {
                GitError::Invalid { detail } => wrap(detail),
                other => other,
            })?;
        results.push((
            old_path,
            new_path,
            join_text(&applied),
            result_mode,
            file.is_delete,
        ));
    }
    // Phase 2: the worktree copies of touched paths must still match the
    // bases, so user edits are never silently overwritten.
    for (old_path, new_path, _, _, is_delete) in &results {
        guard_worktree_untouched(ctx, map, old_path, new_path, *is_delete)?;
    }
    // Phase 3: stage, commit, write the worktree, advance the map.
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    for (old_path, new_path, result, result_mode, is_delete) in &results {
        if old_path != new_path && old_path != b"/dev/null" {
            let old_repo = RepoPath::new(old_path.clone()).map_err(to_core_invalid)?;
            let before = read_path_rows(store, kind, &old_repo)?;
            mutations.extend(path_row_mutations(&old_repo, &before, &[])?);
        }
        let new_repo = RepoPath::new(new_path.clone()).map_err(to_core_invalid)?;
        let before = read_path_rows(store, kind, &new_repo)?;
        if *is_delete {
            mutations.extend(path_row_mutations(&new_repo, &before, &[])?);
            continue;
        }
        let entry =
            IndexEntry::for_blob(kind, *result_mode, result, None).map_err(to_core_invalid)?;
        let len = u64::try_from(result.len()).map_err(|_| GitError::Limit {
            detail: "patched blob exceeds the length range".to_owned(),
        })?;
        objects.push(
            store
                .prepare(
                    ruk_core::store::types::ObjectKind::Blob,
                    len,
                    std::io::Cursor::new(result.clone()),
                    None,
                )
                .map_err(GitError::from)?,
        );
        mutations.extend(path_row_mutations(
            &new_repo,
            &before,
            &[(Stage::Zero, entry)],
        )?);
    }
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(to_core_invalid)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    store
        .publish(
            objects,
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    let staged = scan_index(store, kind)?;
    let tree = build_index_tree(store, kind, &merged_rows(&staged))?;
    let committer = identity(ctx, IdentityRole::Committer)?;
    let commit_message = am_commit_text(message, opts, &committer)?;
    let head = head_oid(store)?;
    let request = NewRequest {
        tree,
        parents: vec![Head::Git { oid: head }],
        author: message.author.clone(),
        committer,
        message: ruk_core::ByteString::from(commit_message.as_str()),
        change_id: None,
        predecessor: None,
        provenance: None,
    };
    let applied = super::coordinator::commit_new(ctx, request, RequestId::generate())?;
    let _new_oid = applied
        .oid
        .or_else(|| applied.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "new commit has no git identity".to_owned(),
        })?;
    let store = ctx.store()?;
    for (old_path, new_path, result, result_mode, is_delete) in &results {
        if *is_delete {
            let full = join_base(&ctx.file_base, new_path)?;
            if full.is_symlink() || full.is_file() {
                std::fs::remove_file(&full).map_err(|err| GitError::Io {
                    detail: format!("removing {}: {err}", full.display()),
                })?;
            }
            map.remove(old_path);
            continue;
        }
        if old_path != new_path && old_path != b"/dev/null" {
            let old_full = join_base(&ctx.file_base, old_path)?;
            if old_full.is_symlink() || old_full.is_file() {
                std::fs::remove_file(&old_full).map_err(|err| GitError::Io {
                    detail: format!("removing {}: {err}", old_full.display()),
                })?;
            }
            map.remove(old_path);
        }
        write_worktree_bytes(ctx, new_path, *result_mode, result)?;
        map.insert(
            new_path.clone(),
            (TreeMode::from(*result_mode), Some(result.clone())),
        );
    }
    let written: Vec<Vec<u8>> = results
        .iter()
        .filter(|entry| !entry.4)
        .map(|entry| entry.1.clone())
        .collect();
    super::state::refresh_stats_after_write(ctx, store, kind, &written)?;
    Ok(format!("Applying: {}\n", message.subject).into_bytes())
}

/// Refuses one message's worktree writes when a touched path already
/// differs from the base the patch validated against.
fn guard_worktree_untouched(
    ctx: &Ctx,
    map: &BTreeMap<Vec<u8>, (TreeMode, Option<Vec<u8>>)>,
    old_path: &[u8],
    new_path: &[u8],
    is_delete: bool,
) -> Result<(), GitError> {
    let full = join_base(&ctx.file_base, if is_delete { old_path } else { new_path })?;
    let base_present = map.contains_key(old_path);
    if !base_present {
        if full.is_symlink() || full.is_file() {
            return Err(GitError::Invalid {
                detail: format!(
                    "worktree {} already exists",
                    String::from_utf8_lossy(new_path)
                ),
            });
        }
        return Ok(());
    }
    if !full.is_symlink() && !full.is_file() {
        return Err(GitError::Invalid {
            detail: format!("worktree {} is missing", String::from_utf8_lossy(old_path)),
        });
    }
    let base = map
        .get(old_path)
        .and_then(|(_, body)| body.clone())
        .unwrap_or_default();
    let (current, _) = read_worktree_existing(ctx, old_path)?;
    if current != base {
        return Err(GitError::Invalid {
            detail: format!(
                "local changes to {} would be overwritten",
                String::from_utf8_lossy(old_path)
            ),
        });
    }
    Ok(())
}

/// Maps our tree mode back to an index mode for patch carries.
fn tree_mode_of(mode: TreeMode) -> FileMode {
    match mode {
        TreeMode::Regular => FileMode::Regular,
        TreeMode::Executable => FileMode::Executable,
        TreeMode::Symlink => FileMode::Symlink,
        TreeMode::Gitlink => FileMode::Gitlink,
        TreeMode::Tree => FileMode::Regular,
    }
}

/// Builds the commit text: subject plus body, with an appended
/// `Signed-off-by` trailer under `--signoff`.
fn am_commit_text(
    message: &AmMessage,
    opts: &super::Collected,
    committer: &Signature,
) -> Result<String, GitError> {
    let mut text = if message.body.is_empty() {
        format!("{}\n", message.subject)
    } else {
        format!("{}\n\n{}\n", message.subject, message.body)
    };
    if opts.is_set("signoff") {
        let name = String::from_utf8_lossy(committer.name.as_bytes());
        let email = String::from_utf8_lossy(committer.email.as_bytes());
        text.pop();
        text.push_str(&format!("\nSigned-off-by: {name} <{email}>\n"));
    }
    Ok(text)
}

/// Implements `am --continue`: stages the current message's paths from
/// the resolved worktree, commits with its saved author and message, then
/// applies the rest.
fn am_continue(
    ctx: &mut Ctx,
    abort: &str,
    pending: Vec<Vec<u8>>,
    opts: &super::Collected,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let strip = parse_strip(opts)?;
    let Some(raw) = pending.first() else {
        pseudo_delete(store, AM_STATE)?;
        return Ok(Vec::new());
    };
    let message = if opts.is_set("keep") {
        parse_message_keep(raw)
    } else {
        parse_message(raw)
    }?;
    let rows = scan_index(store, kind)?;
    if rows.iter().any(|(_, stage, _)| *stage != Stage::Zero) {
        return Err(GitError::Invalid {
            detail: "unmerged paths must be resolved before am --continue".to_owned(),
        });
    }
    let (workspace, workspace_raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    let mut objects = Vec::new();
    // Each entry: the index row plus staged content and its lstat tuple
    // (`None` removes it). The tuple is captured before the content read so
    // a concurrent edit can only stale it, never validate foreign bytes.
    let mut touched: Vec<TouchedEntry> = Vec::new();
    for file in &message.patches {
        let old_path = strip_path(&file.old_path, strip)?;
        let new_path = strip_path(&file.new_path, strip)?;
        // New files keep the `/dev/null` side, which is never a repository
        // path and has no rows to remove.
        if file.is_delete || (new_path != old_path && old_path != b"/dev/null") {
            let old_repo = RepoPath::new(old_path.clone()).map_err(to_core_invalid)?;
            touched.push((old_repo, None));
        }
        if file.is_delete {
            continue;
        }
        let full = join_base(&ctx.file_base, &new_path)?;
        let meta = std::fs::symlink_metadata(&full).map_err(|_| GitError::Invalid {
            detail: format!(
                "resolved file {} is missing for am --continue",
                String::from_utf8_lossy(&new_path)
            ),
        })?;
        let stat = super::state::stat_from_meta(&meta).ok();
        let (mode, bytes) = if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&full).map_err(|err| GitError::Io {
                detail: format!("reading link {}: {err}", full.display()),
            })?;
            (
                FileMode::Symlink,
                target.as_os_str().as_encoded_bytes().to_vec(),
            )
        } else if meta.file_type().is_dir() {
            return Err(GitError::Invalid {
                detail: format!(
                    "resolved path {} is a directory",
                    String::from_utf8_lossy(&new_path)
                ),
            });
        } else {
            let mode = file
                .new_mode
                .or(file.old_mode)
                .map(FileMode::from_octal)
                .transpose()
                .map_err(to_core_invalid)?
                .unwrap_or_else(|| super::verbs_stage::file_mode_of(&meta));
            (mode, read_worktree_file(&ctx.file_base, &new_path)?)
        };
        let new_repo = RepoPath::new(new_path).map_err(to_core_invalid)?;
        touched.push((new_repo, Some((mode, bytes, stat))));
    }
    for (repo, staged) in &touched {
        let before = read_path_rows(store, kind, repo)?;
        match staged {
            None => mutations.extend(path_row_mutations(repo, &before, &[])?),
            Some((mode, bytes, stat)) => {
                let entry =
                    IndexEntry::for_blob(kind, *mode, bytes, *stat).map_err(to_core_invalid)?;
                let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
                    detail: "resolved blob exceeds the length range".to_owned(),
                })?;
                objects.push(
                    store
                        .prepare(
                            ruk_core::store::types::ObjectKind::Blob,
                            len,
                            std::io::Cursor::new(bytes.clone()),
                            None,
                        )
                        .map_err(GitError::from)?,
                );
                mutations.extend(path_row_mutations(repo, &before, &[(Stage::Zero, entry)])?);
            }
        }
    }
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(to_core_invalid)?;
    mutations.push(workspace_mutation(workspace_raw.as_deref(), &next)?);
    mutations.push(super::state::index_stamp_mutation()?);
    store
        .publish(
            objects,
            &mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    let staged = scan_index(store, kind)?;
    let tree = build_index_tree(store, kind, &merged_rows(&staged))?;
    let committer = identity(ctx, IdentityRole::Committer)?;
    let commit_message = am_commit_text(&message, opts, &committer)?;
    let head = head_oid(store)?;
    let request = NewRequest {
        tree,
        parents: vec![Head::Git { oid: head }],
        author: message.author.clone(),
        committer,
        message: ruk_core::ByteString::from(commit_message.as_str()),
        change_id: None,
        predecessor: None,
        provenance: None,
    };
    let applied = super::coordinator::commit_new(ctx, request, RequestId::generate())?;
    let _new_oid = applied
        .oid
        .or_else(|| applied.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "new commit has no git identity".to_owned(),
        })?;
    let summary = format!("Applying: {}\n", message.subject);
    let rest = pending.into_iter().skip(1).collect::<Vec<_>>();
    am_resume(ctx, abort, rest, opts, Some(summary))
}

/// Implements `am --abort`: hard-resets to the pre-`am` head and drops
/// the session state.
fn am_abort(ctx: &mut Ctx, abort: &str) -> Result<Vec<u8>, GitError> {
    reset(ctx, &["--hard".to_owned(), abort.to_owned()])?;
    pseudo_delete(ctx.store()?, AM_STATE)?;
    Ok(Vec::new())
}

/// Encodes the `am` session: the abort head plus framed message raws.
fn save_am_state(
    store: &ruk_core::store::Store,
    abort: &str,
    pending: &[Vec<u8>],
) -> Result<(), GitError> {
    let mut out = format!("AMv1 {abort}\n").into_bytes();
    for raw in pending {
        out.extend_from_slice(format!("### {}\n", raw.len()).as_bytes());
        out.extend_from_slice(raw);
    }
    pseudo_write(store, AM_STATE, out)
}

/// Decodes the `am` session state.
fn decode_am_state(raw: &[u8]) -> Result<(String, Vec<Vec<u8>>), GitError> {
    let corrupt = || GitError::Corrupt {
        detail: "am state does not decode".to_owned(),
    };
    let header_end = raw
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(corrupt)?;
    let header =
        std::str::from_utf8(raw.get(..header_end).unwrap_or_default()).map_err(|_| corrupt())?;
    let abort = header.strip_prefix("AMv1 ").ok_or_else(corrupt)?.to_owned();
    let mut pending = Vec::new();
    let mut cursor = header_end + 1;
    while cursor < raw.len() {
        let end = raw[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(corrupt)?;
        let frame = std::str::from_utf8(raw.get(cursor..cursor + end).ok_or_else(corrupt)?)
            .map_err(|_| corrupt())?;
        let len: usize = frame
            .strip_prefix("### ")
            .ok_or_else(corrupt)?
            .parse()
            .map_err(|_| corrupt())?;
        cursor += end + 1;
        let body = raw.get(cursor..cursor + len).ok_or_else(corrupt)?.to_vec();
        cursor += len;
        pending.push(body);
    }
    Ok((abort, pending))
}

// ---------------------------------------------------------------------------
// mbox parsing
// ---------------------------------------------------------------------------

/// Parses one mbox message raw, stripping `[PATCH n/m]` subject prefixes
/// so committed subjects match the original commits.
fn parse_message(raw: &[u8]) -> Result<AmMessage, GitError> {
    parse_message_impl(raw, false)
}

/// Parses one mbox message raw, preserving `[PATCH n/m]` subject prefixes
/// (`am -k`).
fn parse_message_keep(raw: &[u8]) -> Result<AmMessage, GitError> {
    parse_message_impl(raw, true)
}

/// Shared envelope, body, and diff parsing behind both subject policies.
fn parse_message_impl(raw: &[u8], keep_subject: bool) -> Result<AmMessage, GitError> {
    let lines: Vec<Vec<u8>> = raw
        .split(|byte| *byte == b'\n')
        .map(|line| {
            line.strip_suffix(b"\r")
                .map_or_else(|| line.to_vec(), <[u8]>::to_vec)
        })
        .collect();
    if lines.first().is_none_or(|line| !line.starts_with(b"From ")) {
        return Err(GitError::Invalid {
            detail: "message is not an mbox message (missing From line)".to_owned(),
        });
    }
    // Headers until the first blank line, with folded continuations.
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut index = 1;
    while index < lines.len() && lines.get(index).is_some_and(|line| !line.is_empty()) {
        let line = lines.get(index).expect("bounds checked above");
        if (line.first() == Some(&b' ') || line.first() == Some(&b'\t')) && !headers.is_empty() {
            let last = headers.last_mut().expect("headers non-empty");
            last.1.push(b' ');
            last.1.extend_from_slice(line.trim_ascii_start());
        } else if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            headers.push((line[..colon].to_vec(), line[colon + 1..].to_vec()));
        }
        index += 1;
    }
    index += 1; // Skip the blank line.
    let header = |name: &[u8]| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| String::from_utf8_lossy(value.trim_ascii()).into_owned())
    };
    let from = header(b"From").ok_or_else(|| GitError::Invalid {
        detail: "mbox message has no From: header".to_owned(),
    })?;
    let subject_raw = header(b"Subject").ok_or_else(|| GitError::Invalid {
        detail: "mbox message has no Subject: header".to_owned(),
    })?;
    let (author_name, author_email) = parse_from_header(&from)?;
    let (stamp, offset) = match header(b"Date") {
        None => (now_seconds()?, TzOffset::UTC),
        Some(date) => parse_mbox_date(&date)?,
    };
    let author =
        Signature::parse(format!("{author_name} <{author_email}> {stamp} {offset}").as_bytes())
            .map_err(|_| GitError::Invalid {
                detail: format!("bad mbox From: header {from:?}"),
            })?;
    let payload = lines.get(index..).unwrap_or_default();
    let diff_at = payload
        .iter()
        .position(|line| line.starts_with(b"diff --git "));
    let (body_lines, diff_lines) = match diff_at {
        Some(at) => (&payload[..at], &payload[at..]),
        None => (payload, &[][..]),
    };
    // The message ends at the last `---` separator (stat lines between it
    // and the diff are discarded); a message with neither diff nor
    // separator carries no patch at all.
    let mut end = body_lines.len();
    while end > 0 && body_lines.get(end - 1).is_some_and(|line| line.is_empty()) {
        end -= 1;
    }
    let mut body = body_lines.get(..end).unwrap_or_default();
    match body.iter().rposition(|line| line == b"---") {
        Some(sep) => {
            body = body.get(..sep).unwrap_or_default();
            while body.last().is_some_and(|line| line.is_empty()) {
                body = body.get(..body.len() - 1).unwrap_or_default();
            }
        }
        None if diff_lines.is_empty() => {
            return Err(GitError::Invalid {
                detail: "mbox message carries no diff".to_owned(),
            });
        }
        None => {}
    }
    let mut body_text = Vec::new();
    for line in body {
        // `>From ` unescapes to `From ` exactly once; other quoted lines
        // pass through untouched.
        if let Some(unescaped) = line.strip_prefix(b">From ") {
            body_text.extend_from_slice(unescaped);
        } else {
            body_text.extend_from_slice(line);
        }
        body_text.push(b'\n');
    }
    let body_text = String::from_utf8_lossy(&body_text);
    let body_text = body_text.trim_end().to_owned();
    let diff_bytes = strip_signature(diff_lines);
    let patches = if diff_bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
        Vec::new()
    } else {
        parse_patch(&diff_bytes)?
    };
    let subject = if keep_subject {
        subject_raw.trim().to_owned()
    } else {
        strip_bracket_prefix(subject_raw.trim())
    };
    Ok(AmMessage {
        author,
        subject,
        body: body_text,
        patches,
    })
}

/// Parses `Name <email>` (email required, the way `Signature` needs it).
fn parse_from_header(from: &str) -> Result<(String, String), GitError> {
    let bad = || GitError::Invalid {
        detail: format!("bad mbox From: header {from:?}"),
    };
    let open = from.rfind('<').ok_or_else(bad)?;
    let close = from
        .get(open..)
        .and_then(|rest| rest.find('>'))
        .ok_or_else(bad)?;
    let name = from
        .get(..open)
        .map_or_else(String::new, |text| text.trim().to_owned());
    let email = from
        .get(open + 1..open + close)
        .map_or_else(String::new, |text| text.trim().to_owned());
    if name.is_empty() || email.is_empty() {
        return Err(bad());
    }
    Ok((name, email))
}

/// Strips leading `[PATCH ...]` (or `[patch ...]`) subject prefixes.
fn strip_bracket_prefix(subject: &str) -> String {
    let mut rest = subject;
    loop {
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('[') {
            return trimmed.to_owned();
        }
        let Some(close) = trimmed.find(']') else {
            return trimmed.to_owned();
        };
        let tag = trimmed.get(1..close).unwrap_or_default();
        if tag.eq_ignore_ascii_case("patch") || tag.to_ascii_uppercase().starts_with("PATCH ") {
            rest = trimmed.get(close + 1..).unwrap_or_default();
        } else {
            return trimmed.to_owned();
        }
    }
}

/// Cuts the trailing `-- ` signature block (`-- \n<version>`) off diff
/// lines: the last `-- ` line with at most two short lines after it, none
/// of which open a new diff section.
fn strip_signature(lines: &[Vec<u8>]) -> Vec<u8> {
    // Trailing blank lines are padding, not content: ignore them when
    // locating the signature block, so padded mboxes strip like clean ones.
    let mut end = lines.len();
    while end > 0 && lines.get(end - 1).is_some_and(|line| line.is_empty()) {
        end -= 1;
    }
    let mut cut = end;
    for (index, line) in lines.iter().enumerate().take(end) {
        if line == b"-- " {
            let tail = lines.get(index + 1..end).unwrap_or_default();
            if tail.len() <= 2
                && tail.iter().all(|line| {
                    !(line.starts_with(b"diff --git ")
                        || line.starts_with(b"@@ ")
                        || line.starts_with(b"--- ")
                        || line.starts_with(b"+++ "))
                })
            {
                cut = index;
            }
        }
    }
    let mut out = Vec::new();
    for line in lines.get(..cut).unwrap_or_default() {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}
