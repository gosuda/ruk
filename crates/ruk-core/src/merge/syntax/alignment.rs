//! Conservative structural alignment and byte-preserving splice.
//!
//! The driver aligns candidate units through unchanged base ranges and
//! exact parent/sibling position first, using unique structural keys only as
//! supporting identity. One-sided changes become exact byte replacements;
//! opposite changes to distinct unambiguous units coexist only when their
//! edits do not overlap and order is intact. Everything else declines with a
//! truthful reason so the caller can run bounded text merge and report the
//! single existing notice schema.
//!
//! Shape of the algorithm (all work bounded by the triplet byte bound):
//!
//! * units are extracted per input and indexed by structural key; duplicate
//!   keys with differing bytes decline immediately;
//! * a base key missing on one side whose `(kind, name)` appears elsewhere
//!   on that side is a cross-boundary move and declines;
//! * doubly-present units classify by exact byte equality; a unit changed on
//!   both sides descends once through [`Adapter::children`] or declines;
//! * deletions must occupy whole lines and every gap byte around them must
//!   match; insertions land in the base gap between consecutive base units
//!   and must reproduce the gap bytes around the new units, modulo
//!   whitespace and adapter-declared separators;
//! * collected edits are validated (sorted, non-overlapping, in-bounds),
//!   spliced from the end of the base buffer in one pass, and the candidate
//!   is re-parsed with the same grammar before publication.

use std::collections::{HashMap, HashSet};

use crate::merge::composed::{MergeNotices, NoticeCode};

use super::adapters::{
    Decline, DeclineReason, SourceUnit, UnitKey, adapter_for, index_units, offset, slice_range,
};
use super::grammar::{Cancel, GrammarRegistry, Language, MAX_TRIPLET_BYTES, ParsedTree, SyntaxError};
use super::{
    ByteEdit, EditProvenance, EditSource, SyntaxOutcome, SyntaxProvenance, SyntaxRequest,
    decline_notices,
};

/// One parsed input of a triplet; units are filled after extraction.
/// Sources travel on the request and the level, never duplicated here.
struct ParsedInput {
    tree: super::grammar::ParsedTree,
    units: Vec<SourceUnit>,
}

/// Why parsing stopped: cancellation propagates as an error, everything else
/// becomes a parse decline with a notice.
enum ParseHalt {
    Cancel(SyntaxError),
    Decline(DeclineReason, String),
}

/// Why classification stopped: cancellation propagates as `E_CANCELLED`
/// without text fallback; declines carry the truthful reason for bounded
/// text merge. Every `?` on a `Decline` converts automatically.
enum MergeHalt {
    Cancel(SyntaxError),
    Decline(Decline),
}

impl From<Decline> for MergeHalt {
    fn from(decline: Decline) -> Self {
        Self::Decline(decline)
    }
}

/// One validated base-relative replacement with provenance.
struct RawEdit {
    base_start: u32,
    base_end: u32,
    replacement: Vec<u8>,
    provenance: EditSource,
    unit: String,
    side_start: u32,
    side_end: u32,
}

/// Converts a byte length to `u32`.
#[must_use]
fn to_u32(len: usize) -> Option<u32> {
    u32::try_from(len).ok()
}

/// Converts a byte length to `u64` without a truncating cast.
#[must_use]
fn to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Parses one input. Only cancellation propagates as an error; every other
/// failure becomes a parse decline.
fn parse_input<'a>(
    req: &SyntaxRequest<'a>,
    grammars: &GrammarRegistry<'_>,
    cancel: &Cancel,
    source: &'a [u8],
    which: &str,
) -> Result<ParsedInput, ParseHalt> {
    cancel.check().map_err(ParseHalt::Cancel)?;
    let Some(grammar) = grammars.get(req.language) else {
        return Err(ParseHalt::Decline(
            DeclineReason::GrammarUnavailable,
            format!("no provider registered for {}", req.language.id()),
        ));
    };
    let tree = grammar.parse(source, cancel).map_err(|err| match err {
        SyntaxError::Cancelled(_) => ParseHalt::Cancel(err),
        SyntaxError::Invalid { detail, .. } => {
            ParseHalt::Decline(DeclineReason::ParseFailed, format!("{which}: {detail}"))
        }
    })?;
    if tree.has_error() {
        return Err(ParseHalt::Decline(
            DeclineReason::ParseFailed,
            format!("{which} holds ERROR or missing nodes"),
        ));
    }
    Ok(ParsedInput {
        tree,
        units: Vec::new(),
    })
}

/// Validates that units are sorted and non-overlapping.
fn check_coverage(units: &[SourceUnit], which: &str) -> Option<Decline> {
    let mut cursor = 0_u32;
    for unit in units {
        if unit.start < cursor || unit.end < unit.start {
            return Some(Decline::new(
                DeclineReason::UnsupportedConstruct,
                format!("{which} units overlap or invert order near `{}`", unit.key),
            ));
        }
        cursor = unit.end;
    }
    None
}

/// Short `(kind, name)` occurrence counts for move detection.
fn short_counts(units: &[SourceUnit]) -> HashMap<(&str, &[u8]), usize> {
    let mut map = HashMap::new();
    for unit in units {
        let (kind, name) = unit.key.short();
        *map.entry((kind, name)).or_insert(0) += 1;
    }
    map
}

/// Line span covering `start..end`: back over same-line whitespace to the
/// previous newline, forward over same-line whitespace through one newline.
/// Returns `None` when the span would swallow non-whitespace outside the
/// unit, so a unit sharing its lines can never be line-deleted.
#[must_use]
fn whole_lines(source: &[u8], start: u32, end: u32) -> Option<(u32, u32)> {
    let start = offset(start)?;
    let end = offset(end)?;
    if start > end || end > source.len() {
        return None;
    }
    let mut line_start = start;
    while line_start > 0 && source[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    if source[line_start..start].iter().any(|b| !b.is_ascii_whitespace()) {
        return None;
    }
    let mut line_end = end;
    while line_end < source.len() && source[line_end] != b'\n' {
        line_end += 1;
    }
    if line_end < source.len() {
        line_end += 1;
    }
    if source[end..line_end].iter().any(|b| !b.is_ascii_whitespace()) {
        return None;
    }
    Some((to_u32(line_start)?, to_u32(line_end)?))
}

/// Collects the gap bytes of `span`, skipping every range in `skip` (unit
/// bodies and new-unit spans, each verified independently). Ranges in `skip`
/// must be sorted and non-overlapping.
#[must_use]
fn gap_bytes(source: &[u8], span: (u32, u32), skip: &[(u32, u32)]) -> Option<Vec<u8>> {
    let (mut cursor, span_end) = (offset(span.0)?, offset(span.1)?);
    if cursor > span_end || span_end > source.len() {
        return None;
    }
    let mut out = Vec::new();
    for (skip_start, skip_end) in skip {
        let (skip_start, skip_end) = (offset(*skip_start)?, offset(*skip_end)?);
        if skip_start < cursor || skip_end < skip_start || skip_end > span_end {
            return None;
        }
        out.extend_from_slice(&source[cursor..skip_start]);
        cursor = skip_end;
    }
    out.extend_from_slice(&source[cursor..span_end]);
    Some(out)
}

/// Normalized gap comparison: ASCII whitespace and adapter-declared
/// separators are ignored, so a member insertion that adds a comma or
/// semicolon beside its new unit still proves the surrounding gap bytes.
/// Anything else must match exactly.
#[must_use]
fn gaps_match(separators: &[u8], left: &[u8], right: &[u8]) -> bool {
    let normalized = |bytes: &[u8]| {
        bytes
            .iter()
            .filter(|b| !b.is_ascii_whitespace() && !separators.contains(b))
            .copied()
            .collect::<Vec<u8>>()
    };
    normalized(left) == normalized(right)
}

/// Working state of one merge level: a whole file or one unit body. Trees,
/// sources, and unit lists are borrowed separately so a child level can
/// reuse its parent trees without cloning them.
struct Level<'a> {
    adapter: &'a dyn super::adapters::Adapter,
    base_tree: &'a ParsedTree,
    base_source: &'a [u8],
    base_units: &'a [SourceUnit],
    base_span: (u32, u32),
    ours_tree: &'a ParsedTree,
    ours_source: &'a [u8],
    ours_units: &'a [SourceUnit],
    ours_span: (u32, u32),
    theirs_tree: &'a ParsedTree,
    theirs_source: &'a [u8],
    theirs_units: &'a [SourceUnit],
    theirs_span: (u32, u32),
    cancel: &'a Cancel,
}

/// Per-side resolution of the base units at one level.
struct Side<'a> {
    /// Key to side-unit index for units present on this side.
    map: HashMap<&'a UnitKey, usize>,
    /// Short-key occurrence counts for move detection.
    shorts: HashMap<(&'a str, &'a [u8]), usize>,
    /// Base-relative spans verified by deletion checks on this side.
    verified: Vec<(u32, u32)>,
    /// Base gaps covered by insertion edits on this side.
    inserted_gaps: HashSet<(u32, u32)>,
    provenance: EditSource,
}

impl<'a> Side<'a> {
    /// Counterpart unit for `key`, borrowed from `units` (not from `self`),
    /// so lookups never hold a map borrow across an edit push.
    fn counterpart<'u>(&self, units: &'u [SourceUnit], key: &UnitKey) -> Option<&'u SourceUnit> {
        self.map.get(key).map(|index| &units[*index])
    }
}

/// Counterpart positions of the base units bracketing a gap on one side.
/// Both bounding units must be present; the caller guarantees spans around
/// deletions were verified separately.
fn side_gap_span(
    base_units: &[SourceUnit],
    side_units: &[SourceUnit],
    side: &Side<'_>,
    prev: Option<usize>,
    next: Option<usize>,
    side_span: (u32, u32),
) -> Option<(u32, u32)> {
    let start = match prev {
        Some(index) => side.counterpart(side_units, &base_units[index].key)?.end,
        None => side_span.0,
    };
    let end = match next {
        Some(index) => side.counterpart(side_units, &base_units[index].key)?.start,
        None => side_span.1,
    };
    (start <= end).then_some((start, end))
}

/// Side-only units between one pair of base neighbours.
struct InsertionGroup {
    prev: Option<usize>,
    next: Option<usize>,
    units: Vec<usize>,
}

/// Groups side-only units by nearest base neighbours in side order.
fn insertion_groups(base_units: &[SourceUnit], side_units: &[SourceUnit]) -> Vec<InsertionGroup> {
    let base_positions: HashMap<&UnitKey, usize> = base_units
        .iter()
        .enumerate()
        .map(|(index, unit)| (&unit.key, index))
        .collect();
    let mut groups: Vec<InsertionGroup> = Vec::new();
    for (unit_index, unit) in side_units.iter().enumerate() {
        if base_positions.contains_key(&unit.key) {
            continue;
        }
        let prev = (0..unit_index)
            .rev()
            .find_map(|i| base_positions.get(&side_units[i].key).copied());
        let next = ((unit_index + 1)..side_units.len())
            .find_map(|i| base_positions.get(&side_units[i].key).copied());
        match groups
            .iter_mut()
            .find(|group| group.prev == prev && group.next == next)
        {
            Some(group) => group.units.push(unit_index),
            None => groups.push(InsertionGroup {
                prev,
                next,
                units: vec![unit_index],
            }),
        }
    }
    groups
}

/// Classifies a unit present in all three inputs by exact byte equality.
/// Ranges and node ids arrive as copied tuples so no map borrow outlives
/// the lookup.
fn present(
    level: &Level<'_>,
    unit: &SourceUnit,
    ours: (u32, u32, u32),
    theirs: (u32, u32, u32),
    edits: &mut Vec<RawEdit>,
) -> Result<(), MergeHalt> {
    let base_bytes = unit_bytes(level.base_source, unit, "base")?;
    let ours_bytes = slice_range(level.ours_source, ours.0, ours.1).ok_or_else(|| {
        Decline::new(
            DeclineReason::UnsupportedConstruct,
            format!("ours unit `{}` is out of range", unit.key),
        )
    })?;
    let theirs_bytes = slice_range(level.theirs_source, theirs.0, theirs.1).ok_or_else(|| {
        Decline::new(
            DeclineReason::UnsupportedConstruct,
            format!("theirs unit `{}` is out of range", unit.key),
        )
    })?;
    if ours_bytes == base_bytes && theirs_bytes == base_bytes {
        return Ok(());
    }
    if theirs_bytes == base_bytes {
        edits.push(replace_range(unit, ours.0, ours.1, ours_bytes, EditSource::Ours));
        return Ok(());
    }
    if ours_bytes == base_bytes {
        edits.push(replace_range(unit, theirs.0, theirs.1, theirs_bytes, EditSource::Theirs));
        return Ok(());
    }
    descend(level, unit, ours, theirs, edits)
}

/// Validates one child list: sorted, non-overlapping, inside `span`, and
/// every child range addressable in `source`.
fn check_children(
    children: &mut [SourceUnit],
    source: &[u8],
    span: (u32, u32),
    which: &str,
    parent_key: &UnitKey,
) -> Result<(), Decline> {
    children.sort_by_key(|child| (child.start, child.end));
    if let Some(decline) = check_coverage(children, which) {
        return Err(decline);
    }
    for child in children.iter() {
        if child.start < span.0
            || child.end > span.1
            || slice_range(source, child.start, child.end).is_none()
        {
            return Err(Decline::new(
                DeclineReason::UnsupportedConstruct,
                format!("{which} child of `{parent_key}` escapes its unit"),
            ));
        }
    }
    Ok(())
}

/// Descends once into a doubly-changed unit's child units, else declines.
/// Child edits are absolute base ranges and extend the parent edit list.
fn descend(
    level: &Level<'_>,
    unit: &SourceUnit,
    ours: (u32, u32, u32),
    theirs: (u32, u32, u32),
    edits: &mut Vec<RawEdit>,
) -> Result<(), MergeHalt> {
    let mut base_children = level.adapter.children(level.base_tree, level.base_source, unit.node);
    let mut ours_children = level.adapter.children(level.ours_tree, level.ours_source, ours.2);
    let mut theirs_children =
        level.adapter.children(level.theirs_tree, level.theirs_source, theirs.2);
    if base_children.is_empty() && ours_children.is_empty() && theirs_children.is_empty() {
        return Err(Decline::new(
            DeclineReason::SameUnitChanged,
            format!("`{}` changed on both sides", unit.key),
        )
        .into());
    }
    check_children(
        &mut base_children,
        level.base_source,
        (unit.start, unit.end),
        "base",
        &unit.key,
    )?;
    check_children(
        &mut ours_children,
        level.ours_source,
        (ours.0, ours.1),
        "ours",
        &unit.key,
    )?;
    check_children(
        &mut theirs_children,
        level.theirs_source,
        (theirs.0, theirs.1),
        "theirs",
        &unit.key,
    )?;
    let nested = Level {
        adapter: level.adapter,
        base_tree: level.base_tree,
        base_source: level.base_source,
        base_units: &base_children,
        base_span: (unit.start, unit.end),
        ours_tree: level.ours_tree,
        ours_source: level.ours_source,
        ours_units: &ours_children,
        ours_span: (ours.0, ours.1),
        theirs_tree: level.theirs_tree,
        theirs_source: level.theirs_source,
        theirs_units: &theirs_children,
        theirs_span: (theirs.0, theirs.1),
        cancel: level.cancel,
    };
    let child_edits = classify_level(&nested).map_err(|halt| match halt {
        MergeHalt::Cancel(err) => MergeHalt::Cancel(err),
        MergeHalt::Decline(decline) => MergeHalt::Decline(Decline::new(
            decline.reason,
            format!("inside `{}`: {}", unit.key, decline.detail),
        )),
    })?;
    edits.extend(child_edits);
    Ok(())
}

/// Inputs to one deletion classification, bundled so the function takes a
/// single argument. Lifetimes stay split: the two mutable borrows (`'s`,
/// `'e`) are independent of each other and of the shared inputs (`'l`), so
/// each borrow ends at the call instead of unifying across the loop.
struct DeleteArgs<'l, 's, 'e> {
    level: &'l Level<'l>,
    base_units: &'l [SourceUnit],
    keeper_units: &'l [SourceUnit],
    keeper_source: &'l [u8],
    deleter_units: &'l [SourceUnit],
    deleter_side: &'s mut Side<'l>,
    unit: &'l SourceUnit,
    index: usize,
    edits: &'e mut Vec<RawEdit>,
}

/// Classifies a unit missing on the deleting side: a `(kind, name)` match
/// elsewhere is a cross-boundary move and declines, a keeper-side edit is
/// delete-versus-edit and declines, otherwise the deletion must be clean
/// whole lines with matching gap bytes.
fn deleted(args: DeleteArgs<'_, '_, '_>) -> Result<(), Decline> {
    let DeleteArgs {
        level,
        base_units,
        keeper_units,
        keeper_source,
        deleter_units,
        deleter_side,
        unit,
        index,
        edits,
    } = args;
    let (kind, name) = unit.key.short();
    if deleter_side.shorts.contains_key(&(kind, name)) {
        return Err(Decline::new(
            DeclineReason::ChangedKey,
            format!("`{}` moved to a different parent on one side", unit.key),
        ));
    }
    let keeper_hit = keeper_units
        .iter()
        .find(|other| other.key == unit.key)
        .ok_or_else(|| {
            Decline::new(
                DeclineReason::AmbiguousRename,
                format!("`{}` vanished inconsistently", unit.key),
            )
        })?;
    let base_bytes = unit_bytes(level.base_source, unit, "base")?;
    let keeper_bytes = unit_bytes(keeper_source, keeper_hit, "keeper")?;
    if keeper_bytes != base_bytes {
        return Err(Decline::new(
            DeclineReason::AmbiguousRename,
            format!("`{}` deleted on one side and edited on the other", unit.key),
        ));
    }
    verify_deletion(
        level,
        base_units,
        deleter_units,
        deleter_side,
        unit,
        index,
        edits,
    )
}

/// Inputs to a both-sides deletion classification, bundled so the function
/// takes a single argument. Each mutable borrow carries its own lifetime so
/// no borrow outlives its call.
struct DeleteBothArgs<'l, 's1, 's2, 'e> {
    level: &'l Level<'l>,
    base_units: &'l [SourceUnit],
    ours_units: &'l [SourceUnit],
    theirs_units: &'l [SourceUnit],
    ours_side: &'s1 mut Side<'l>,
    theirs_side: &'s2 mut Side<'l>,
    unit: &'l SourceUnit,
    index: usize,
    edits: &'e mut Vec<RawEdit>,
}

/// Classifies a unit missing on both sides: each side must delete it
/// cleanly; the second verified deletion emits no duplicate edit.
fn deleted_both(args: DeleteBothArgs<'_, '_, '_, '_>) -> Result<(), Decline> {
    let DeleteBothArgs {
        level,
        base_units,
        ours_units,
        theirs_units,
        ours_side,
        theirs_side,
        unit,
        index,
        edits,
    } = args;
    for side_units in [ours_units, theirs_units] {
        let (kind, name) = unit.key.short();
        if short_counts(side_units).contains_key(&(kind, name)) {
            return Err(Decline::new(
                DeclineReason::ChangedKey,
                format!("`{}` moved to a different parent on one side", unit.key),
            ));
        }
    }
    verify_deletion(level, base_units, ours_units, ours_side, unit, index, edits)?;
    let anchor = edits.len();
    verify_deletion(level, base_units, theirs_units, theirs_side, unit, index, edits)?;
    if edits.len() > anchor {
        edits.pop();
    }
    Ok(())
}

/// Exact bytes of one unit's range.
fn unit_bytes<'s>(
    source: &'s [u8],
    unit: &SourceUnit,
    which: &str,
) -> Result<&'s [u8], Decline> {
    slice_range(source, unit.start, unit.end).ok_or_else(|| {
        Decline::new(
            DeclineReason::UnsupportedConstruct,
            format!("{which} unit `{}` is out of range", unit.key),
        )
    })
}

/// A one-sided whole-unit replacement edit over copied ranges.
fn replace_range(
    unit: &SourceUnit,
    side_start: u32,
    side_end: u32,
    side_bytes: &[u8],
    provenance: EditSource,
) -> RawEdit {
    RawEdit {
        base_start: unit.start,
        base_end: unit.end,
        replacement: side_bytes.to_vec(),
        provenance,
        unit: unit.key.to_string(),
        side_start,
        side_end,
    }
}

/// Verifies a deletion: the unit occupies whole lines, and every gap byte of
/// the enclosing present-unit span matches on the deleting side once unit
/// bodies (verified separately) and new units (verified by insertion
/// checks) are skipped.
fn verify_deletion(
    level: &Level<'_>,
    base_units: &[SourceUnit],
    deleter_units: &[SourceUnit],
    deleter_side: &mut Side<'_>,
    unit: &SourceUnit,
    index: usize,
    edits: &mut Vec<RawEdit>,
) -> Result<(), Decline> {
    let (deleter_source, deleter_span) = match deleter_side.provenance {
        EditSource::Ours => (level.ours_source, level.ours_span),
        EditSource::Theirs => (level.theirs_source, level.theirs_span),
    };
    let (line_start, line_end) =
        whole_lines(level.base_source, unit.start, unit.end).ok_or_else(|| {
            Decline::new(
                DeclineReason::AmbiguousRename,
                format!("`{}` shares its lines; cannot delete cleanly", unit.key),
            )
        })?;
    let prev = (0..index)
        .rev()
        .find(|i| deleter_side.map.contains_key(&base_units[*i].key));
    let next = ((index + 1)..base_units.len())
        .find(|i| deleter_side.map.contains_key(&base_units[*i].key));
    let base_span = (
        prev.map_or(level.base_span.0, |i| base_units[i].end),
        next.map_or(level.base_span.1, |i| base_units[i].start),
    );
    let side_span = side_gap_span(
        base_units,
        deleter_units,
        deleter_side,
        prev,
        next,
        deleter_span,
    )
    .ok_or_else(|| {
        Decline::new(
            DeclineReason::AmbiguousRename,
            format!("cannot resolve the span around deleted `{}`", unit.key),
        )
    })?;
    let mut base_skip: Vec<(u32, u32)> = Vec::new();
    for (i, other) in base_units.iter().enumerate() {
        if other.end <= base_span.0 || other.start >= base_span.1 {
            continue;
        }
        base_skip.push(if i == index {
            (line_start, line_end)
        } else {
            (other.start, other.end)
        });
    }
    base_skip.sort();
    let base_gaps = gap_bytes(level.base_source, base_span, &base_skip).ok_or_else(|| {
        Decline::new(
            DeclineReason::AmbiguousRename,
            format!("base span arithmetic failed near `{}`", unit.key),
        )
    })?;
    let mut side_skip: Vec<(u32, u32)> = deleter_units
        .iter()
        .filter(|other| other.end > side_span.0 && other.start < side_span.1)
        .map(|other| (other.start, other.end))
        .collect();
    side_skip.sort();
    let side_gaps = gap_bytes(deleter_source, side_span, &side_skip).ok_or_else(|| {
        Decline::new(
            DeclineReason::AmbiguousRename,
            format!("side span arithmetic failed near `{}`", unit.key),
        )
    })?;
    if !gaps_match(level.adapter.separators(), &base_gaps, &side_gaps) {
        return Err(Decline::new(
            DeclineReason::AmbiguousRename,
            format!("`{}` deletion carries adjacent bytes; declining", unit.key),
        ));
    }
    deleter_side.verified.push(base_span);
    edits.push(RawEdit {
        base_start: line_start,
        base_end: line_end,
        replacement: Vec::new(),
        provenance: deleter_side.provenance,
        unit: unit.key.to_string(),
        side_start: side_span.0,
        side_end: side_span.0,
    });
    Ok(())
}

/// Applies one insertion group: neighbours must be consecutive in base
/// order, and the side span with new-unit bodies removed must reproduce the
/// base gap, modulo whitespace and adapter separators.
fn apply_insertion_group(
    level: &Level<'_>,
    base_units: &[SourceUnit],
    side_units: &[SourceUnit],
    side: &mut Side<'_>,
    group: &InsertionGroup,
    competing: bool,
    edits: &mut Vec<RawEdit>,
) -> Result<(), Decline> {
    // Two insertions in the same gap are ambiguous and conflict even when
    // byte-identical: equal newly inserted spans alone never prove shared
    // identity, and accepting them would be a lossy same-change collapse.
    if competing {
        return Err(Decline::new(
            DeclineReason::CompetingInsertion,
            "both sides inserted into the same gap".to_owned(),
        ));
    }
    let consecutive = match (group.prev, group.next) {
        (Some(prev), Some(next)) => next == prev + 1,
        (None, Some(next)) => next == 0,
        (Some(prev), None) => prev + 1 == base_units.len(),
        (None, None) => base_units.is_empty(),
    };
    if !consecutive {
        return Err(Decline::new(
            DeclineReason::UnsupportedConstruct,
            "an insertion spans a deletion on the same side".to_owned(),
        ));
    }
    let (side_source, side_span) = match side.provenance {
        EditSource::Ours => (level.ours_source, level.ours_span),
        EditSource::Theirs => (level.theirs_source, level.theirs_span),
    };
    let base_gap = (
        group.prev.map_or(level.base_span.0, |i| base_units[i].end),
        group.next.map_or(level.base_span.1, |i| base_units[i].start),
    );
    let side_gap = side_gap_span(
        base_units,
        side_units,
        side,
        group.prev,
        group.next,
        side_span,
    )
    .ok_or_else(|| {
        Decline::new(
            DeclineReason::CompetingInsertion,
            "cannot resolve an insertion gap".to_owned(),
        )
    })?;
    let mut new_spans: Vec<(u32, u32)> = group
        .units
        .iter()
        .map(|i| (side_units[*i].start, side_units[*i].end))
        .collect();
    new_spans.sort();
    if new_spans
        .iter()
        .any(|(start, end)| *start < side_gap.0 || *end > side_gap.1)
    {
        return Err(Decline::new(
            DeclineReason::CompetingInsertion,
            "a new unit escapes its insertion gap".to_owned(),
        ));
    }
    let base_gaps = gap_bytes(level.base_source, base_gap, &[]).ok_or_else(|| {
        Decline::new(
            DeclineReason::CompetingInsertion,
            "base gap arithmetic failed".to_owned(),
        )
    })?;
    let side_gaps = gap_bytes(side_source, side_gap, &new_spans).ok_or_else(|| {
        Decline::new(
            DeclineReason::CompetingInsertion,
            "side gap arithmetic failed".to_owned(),
        )
    })?;
    if !gaps_match(level.adapter.separators(), &base_gaps, &side_gaps) {
        let reason = if competing {
            DeclineReason::CompetingInsertion
        } else {
            DeclineReason::UnsupportedConstruct
        };
        return Err(Decline::new(
            reason,
            "an insertion does not reproduce the base gap bytes".to_owned(),
        ));
    }
    let replacement = slice_range(side_source, side_gap.0, side_gap.1)
        .unwrap_or(b"")
        .to_vec();
    let names = group
        .units
        .iter()
        .map(|i| side_units[*i].key.to_string())
        .collect::<Vec<_>>()
        .join("+");
    side.inserted_gaps.insert(base_gap);
    edits.push(RawEdit {
        base_start: base_gap.0,
        base_end: base_gap.1,
        replacement,
        provenance: side.provenance,
        unit: format!("insert:{names}"),
        side_start: side_gap.0,
        side_end: side_gap.1,
    });
    Ok(())
}

/// Verifies every base gap not covered by an insertion or deletion check is
/// byte-identical on one side.
fn verify_gaps(
    level: &Level<'_>,
    base_units: &[SourceUnit],
    side_units: &[SourceUnit],
    side: &Side<'_>,
) -> Result<(), Decline> {
    let (side_source, side_span) = match side.provenance {
        EditSource::Ours => (level.ours_source, level.ours_span),
        EditSource::Theirs => (level.theirs_source, level.theirs_span),
    };
    for index in 0..=base_units.len() {
        let prev = if index == 0 { None } else { Some(index - 1) };
        let next = (index < base_units.len()).then_some(index);
        let gap = (
            prev.map_or(level.base_span.0, |i| base_units[i].end),
            next.map_or(level.base_span.1, |i| base_units[i].start),
        );
        if gap.0 > gap.1 {
            return Err(Decline::new(
                DeclineReason::UnsupportedConstruct,
                "base gap inverts order".to_owned(),
            ));
        }
        if side.inserted_gaps.contains(&gap) {
            continue;
        }
        if side
            .verified
            .iter()
            .any(|span| span.0 <= gap.0 && gap.1 <= span.1)
        {
            continue;
        }
        let side_gap =
            side_gap_span(base_units, side_units, side, prev, next, side_span).ok_or_else(|| {
                Decline::new(
                    DeclineReason::UnsupportedConstruct,
                    "cannot resolve an unchanged gap".to_owned(),
                )
            })?;
        let base_bytes = slice_range(level.base_source, gap.0, gap.1).unwrap_or(b"");
        let side_bytes = slice_range(side_source, side_gap.0, side_gap.1).unwrap_or(b"");
        if base_bytes != side_bytes {
            return Err(Decline::new(
                DeclineReason::UnsupportedConstruct,
                "a non-unit region changed; no structural unit covers it".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Classifies pre-extracted unit lists: the shared body of whole-file and
/// child-level merges. Cancellation halts with `E_CANCELLED`; declines halt
/// with the truthful reason.
fn classify_level(level: &Level<'_>) -> Result<Vec<RawEdit>, MergeHalt> {
    let base_units = level.base_units;
    let ours_units = level.ours_units;
    let theirs_units = level.theirs_units;
    // Units must be sorted and non-overlapping; adapters guarantee this and
    // the driver enforces it before indexing.
    for (units, which) in [
        (base_units, "base"),
        (ours_units, "ours"),
        (theirs_units, "theirs"),
    ] {
        if let Some(decline) = check_coverage(units, which) {
            return Err(decline.into());
        }
    }
    let (base_map, decline) = index_units(
        base_units,
        level.base_source,
        &[
            (ours_units, level.ours_source),
            (theirs_units, level.theirs_source),
        ],
    );
    if let Some(decline) = decline {
        return Err(decline.into());
    }
    let (ours_map, decline) =
        index_units(ours_units, level.ours_source, &[(base_units, level.base_source)]);
    if let Some(decline) = decline {
        return Err(decline.into());
    }
    let (theirs_map, decline) = index_units(
        theirs_units,
        level.theirs_source,
        &[(base_units, level.base_source)],
    );
    if let Some(decline) = decline {
        return Err(decline.into());
    }
    let _ = base_map;
    let mut ours_side = Side {
        map: ours_map,
        shorts: short_counts(ours_units),
        verified: Vec::new(),
        inserted_gaps: HashSet::new(),
        provenance: EditSource::Ours,
    };
    let mut theirs_side = Side {
        map: theirs_map,
        shorts: short_counts(theirs_units),
        verified: Vec::new(),
        inserted_gaps: HashSet::new(),
        provenance: EditSource::Theirs,
    };
    let mut edits = Vec::new();
    for (index, unit) in base_units.iter().enumerate() {
        level.cancel.check().map_err(MergeHalt::Cancel)?;
        let ours_hit = ours_side
            .counterpart(ours_units, &unit.key)
            .map(|hit| (hit.start, hit.end, hit.node));
        let theirs_hit = theirs_side
            .counterpart(theirs_units, &unit.key)
            .map(|hit| (hit.start, hit.end, hit.node));
        match (ours_hit, theirs_hit) {
            (Some(ours_range), Some(theirs_range)) => {
                present(level, unit, ours_range, theirs_range, &mut edits)?;
            }
            (Some(_), None) => deleted(DeleteArgs {
                level,
                base_units,
                keeper_units: ours_units,
                keeper_source: level.ours_source,
                deleter_units: theirs_units,
                deleter_side: &mut theirs_side,
                unit,
                index,
                edits: &mut edits,
            })?,
            (None, Some(_)) => deleted(DeleteArgs {
                level,
                base_units,
                keeper_units: theirs_units,
                keeper_source: level.theirs_source,
                deleter_units: ours_units,
                deleter_side: &mut ours_side,
                unit,
                index,
                edits: &mut edits,
            })?,
            (None, None) => deleted_both(DeleteBothArgs {
                level,
                base_units,
                ours_units,
                theirs_units,
                ours_side: &mut ours_side,
                theirs_side: &mut theirs_side,
                unit,
                index,
                edits: &mut edits,
            })?,
        }
    }
    let ours_groups = insertion_groups(base_units, ours_units);
    let theirs_groups = insertion_groups(base_units, theirs_units);
    for group in &ours_groups {
        let competing = theirs_groups
            .iter()
            .any(|other| other.prev == group.prev && other.next == group.next);
        apply_insertion_group(
            level,
            base_units,
            ours_units,
            &mut ours_side,
            group,
            competing,
            &mut edits,
        )?;
    }
    for group in &theirs_groups {
        let competing = ours_groups
            .iter()
            .any(|other| other.prev == group.prev && other.next == group.next);
        apply_insertion_group(
            level,
            base_units,
            theirs_units,
            &mut theirs_side,
            group,
            competing,
            &mut edits,
        )?;
    }
    verify_gaps(level, base_units, ours_units, &ours_side)?;
    verify_gaps(level, base_units, theirs_units, &theirs_side)?;
    Ok(edits)
}

/// Three-way content merge of one plain-language triplet.
///
/// Cancellation (`E_CANCELLED`) and invalid caller input (`E_INVALID`) are
/// errors; every other outcome is a typed [`SyntaxOutcome`]: verified
/// `Merged` bytes with provenance, or a `Declined` reason with the single
/// existing notice so the caller can run bounded text merge.
pub fn merge_triplet(
    req: &SyntaxRequest<'_>,
    grammars: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<SyntaxOutcome, SyntaxError> {
    cancel.check()?;
    if req.path.is_empty() || req.path.as_bytes().contains(&0) {
        return Err(SyntaxError::Invalid {
            what: "merge path",
            detail: "must be non-empty and contain no NUL".to_owned(),
        });
    }
    if !req.language.is_plain() {
        return Ok(declined(
            req,
            DeclineReason::ComposedLanguage,
            format!(
                "{} files merge in the composed-file owner, not the plain engine",
                req.language.id()
            ),
            None,
        ));
    }
    for (which, bytes) in [("base", req.base), ("ours", req.ours), ("theirs", req.theirs)] {
        if bytes.contains(&0) {
            return Ok(declined(
                req,
                DeclineReason::BinaryContent,
                format!("{which} input holds NUL bytes; binary content is not parsed"),
                None,
            ));
        }
        if core::str::from_utf8(bytes).is_err() {
            return Ok(declined(
                req,
                DeclineReason::ParseFailed,
                format!("{which} input is not valid UTF-8"),
                None,
            ));
        }
    }
    // Unchanged-side fast paths yield the changed side byte-for-byte,
    // including line endings and the final newline — but only after the
    // returned side parses without ERROR or missing nodes. An unparseable
    // side never ships as a syntax-clean claim.
    if req.ours == req.base {
        return clean_checked(req, grammars, cancel, req.theirs, "theirs");
    }
    if req.theirs == req.base {
        return clean_checked(req, grammars, cancel, req.ours, "ours");
    }
    if req.ours == req.theirs {
        return clean_checked(req, grammars, cancel, req.ours, "ours");
    }
    let total = to_u64(req.base.len())
        .saturating_add(to_u64(req.ours.len()))
        .saturating_add(to_u64(req.theirs.len()));
    if total > MAX_TRIPLET_BYTES {
        return Ok(declined(
            req,
            DeclineReason::SizeLimit,
            format!("triplet holds {total} bytes over the {MAX_TRIPLET_BYTES} bound"),
            None,
        ));
    }
    let mut base = match parse_input(req, grammars, cancel, req.base, "base") {
        Ok(input) => input,
        Err(ParseHalt::Cancel(err)) => return Err(err),
        Err(ParseHalt::Decline(reason, detail)) => return Ok(declined(req, reason, detail, None)),
    };
    let mut ours = match parse_input(req, grammars, cancel, req.ours, "ours") {
        Ok(input) => input,
        Err(ParseHalt::Cancel(err)) => return Err(err),
        Err(ParseHalt::Decline(reason, detail)) => return Ok(declined(req, reason, detail, None)),
    };
    let mut theirs = match parse_input(req, grammars, cancel, req.theirs, "theirs") {
        Ok(input) => input,
        Err(ParseHalt::Cancel(err)) => return Err(err),
        Err(ParseHalt::Decline(reason, detail)) => return Ok(declined(req, reason, detail, None)),
    };
    let Some(adapter) = adapter_for(req.language) else {
        return Ok(declined(
            req,
            DeclineReason::ComposedLanguage,
            format!("{} has no plain adapter", req.language.id()),
            None,
        ));
    };
    if let Some(decline) = adapter.veto(
        &base.tree,
        req.base,
        &ours.tree,
        req.ours,
        &theirs.tree,
        req.theirs,
    ) {
        return Ok(declined(req, decline.reason, decline.detail, None));
    }
    base.units = adapter.units(&base.tree, req.base);
    ours.units = adapter.units(&ours.tree, req.ours);
    theirs.units = adapter.units(&theirs.tree, req.theirs);
    let base_len = to_u32(req.base.len()).ok_or(SyntaxError::Invalid {
        what: "merge input",
        detail: "base exceeds addressable range".to_owned(),
    })?;
    let ours_len = to_u32(req.ours.len()).ok_or(SyntaxError::Invalid {
        what: "merge input",
        detail: "ours exceeds addressable range".to_owned(),
    })?;
    let theirs_len = to_u32(req.theirs.len()).ok_or(SyntaxError::Invalid {
        what: "merge input",
        detail: "theirs exceeds addressable range".to_owned(),
    })?;
    let level = Level {
        adapter,
        base_tree: &base.tree,
        base_source: req.base,
        base_units: &base.units,
        base_span: (0, base_len),
        ours_tree: &ours.tree,
        ours_source: req.ours,
        ours_units: &ours.units,
        ours_span: (0, ours_len),
        theirs_tree: &theirs.tree,
        theirs_source: req.theirs,
        theirs_units: &theirs.units,
        theirs_span: (0, theirs_len),
        cancel,
    };
    let edits = match classify_level(&level) {
        Ok(edits) => edits,
        Err(MergeHalt::Cancel(err)) => return Err(err),
        Err(MergeHalt::Decline(decline)) => {
            return Ok(declined(req, decline.reason, decline.detail, None));
        }
    };
    let (bytes, public, provenance) = match splice_edits(req.base, edits) {
        Ok(out) => out,
        Err(decline) => return Ok(declined(req, decline.reason, decline.detail, None)),
    };
    cancel.check()?;
    let grammar = grammars.get(req.language).ok_or(SyntaxError::Invalid {
        what: "merge input",
        detail: "grammar vanished mid-merge".to_owned(),
    })?;
    let candidate = match grammar.parse(&bytes, cancel) {
        Ok(tree) => tree,
        Err(SyntaxError::Cancelled(err)) => return Err(SyntaxError::Cancelled(err)),
        Err(SyntaxError::Invalid { detail, .. }) => {
            return Ok(declined(
                req,
                DeclineReason::ParseFailed,
                format!("merged candidate: {detail}"),
                None,
            ));
        }
    };
    if candidate.has_error() {
        return Ok(declined(
            req,
            DeclineReason::ParseFailed,
            "the merged candidate does not parse; declining".to_owned(),
            None,
        ));
    }
    Ok(SyntaxOutcome::Merged {
        bytes,
        edits: public,
        provenance: SyntaxProvenance::new(req, provenance),
        notices: MergeNotices::default(),
    })
}

/// Builds a decline outcome with the single existing notice.
fn declined(
    req: &SyntaxRequest<'_>,
    reason: DeclineReason,
    detail: String,
    region: Option<crate::merge::composed::NoticeRegion>,
) -> SyntaxOutcome {
    let notices = decline_notices(req, reason, &detail, region);
    SyntaxOutcome::Declined {
        reason,
        detail,
        notices,
    }
}

/// Builds a clean outcome with no structural edits (fast path) after the
/// returned side parses without ERROR or missing nodes. Parse failure
/// declines; cancellation propagates as an error and never falls back.
fn clean_checked(
    req: &SyntaxRequest<'_>,
    grammars: &GrammarRegistry<'_>,
    cancel: &Cancel,
    bytes: &[u8],
    which: &str,
) -> Result<SyntaxOutcome, SyntaxError> {
    cancel.check()?;
    let Some(grammar) = grammars.get(req.language) else {
        return Ok(declined(
            req,
            DeclineReason::GrammarUnavailable,
            format!("no provider registered for {}", req.language.id()),
            None,
        ));
    };
    let tree = match grammar.parse(bytes, cancel) {
        Ok(tree) => tree,
        Err(SyntaxError::Cancelled(err)) => return Err(SyntaxError::Cancelled(err)),
        Err(SyntaxError::Invalid { detail, .. }) => {
            return Ok(declined(
                req,
                DeclineReason::ParseFailed,
                format!("{which}: {detail}"),
                None,
            ));
        }
    };
    if tree.has_error() {
        return Ok(declined(
            req,
            DeclineReason::ParseFailed,
            format!("{which} holds ERROR or missing nodes"),
            None,
        ));
    }
    Ok(SyntaxOutcome::Merged {
        bytes: bytes.to_vec(),
        edits: Vec::new(),
        provenance: SyntaxProvenance::new(req, Vec::new()),
        notices: MergeNotices::default(),
    })
}

/// Validates collected edits (sorted, non-overlapping, in-bounds) and
/// splices them into `base` from the end in one pass.
fn splice_edits(
    base: &[u8],
    mut edits: Vec<RawEdit>,
) -> Result<(Vec<u8>, Vec<ByteEdit>, Vec<EditProvenance>), Decline> {
    edits.sort_by_key(|edit| (edit.base_start, edit.base_end));
    let base_len = to_u32(base.len()).ok_or_else(|| {
        Decline::new(DeclineReason::SizeLimit, "base exceeds addressable range".to_owned())
    })?;
    let mut cursor = 0_u32;
    for edit in &edits {
        if edit.base_start < cursor || edit.base_end < edit.base_start || edit.base_end > base_len
        {
            return Err(Decline::new(
                DeclineReason::OverlappingEdits,
                format!("edits overlap or leave base near `{}`", edit.unit),
            ));
        }
        cursor = edit.base_end;
    }
    let mut bytes = base.to_vec();
    let mut provenance = Vec::with_capacity(edits.len());
    let mut public = Vec::with_capacity(edits.len());
    for edit in edits.into_iter().rev() {
        let RawEdit {
            base_start,
            base_end,
            replacement,
            provenance: source,
            unit,
            side_start,
            side_end,
        } = edit;
        let start = offset(base_start).ok_or_else(|| {
            Decline::new(
                DeclineReason::OverlappingEdits,
                "edit offset out of range".to_owned(),
            )
        })?;
        let end = offset(base_end).ok_or_else(|| {
            Decline::new(
                DeclineReason::OverlappingEdits,
                "edit offset out of range".to_owned(),
            )
        })?;
        bytes.splice(start..end, replacement.iter().copied());
        provenance.push(EditProvenance {
            source,
            unit,
            base_start,
            base_end,
            side_start,
            side_end,
        });
        public.push(ByteEdit {
            start: base_start,
            end: base_end,
            replacement,
            provenance: source,
        });
    }
    provenance.reverse();
    public.reverse();
    Ok((bytes, public, provenance))
}

/// Notebook catalogue entries report the notebook structure code, never the
/// generic embedded-language code.
#[must_use]
pub fn notice_code_for(reason: DeclineReason, language: Language) -> NoticeCode {
    if language == Language::Notebook && reason == DeclineReason::ComposedLanguage {
        NoticeCode::NotebookStructureDeclined
    } else {
        reason.notice_code()
    }
}
