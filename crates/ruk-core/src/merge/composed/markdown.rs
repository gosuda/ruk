//! Composed-file merge adapter for Markdown documents.
//!
//! Implements '### Markdown' from the composed-file specification:
//! * Block and inline host parsing preserving headings, paragraphs, lists,
//!   links, and tables order, whitespace, and spelling.
//! * Headings are never keyed solely by title when duplicates exist.
//! * Fenced code regions extracted and mapped to bundled languages via a
//!   fixed alias table; bare `sh`, unknown, or absent labels remain text.
//! * Exact per-line prefix mapping for fences inside blockquotes and lists;
//!   ambiguous prefix edits treat the whole fence as a host unit.
//! * Delimiter preservation: fence character, run length, info string, and
//!   indentation are preserved.
//! * Host fence closing rule validation: every line of a merged code region
//!   is checked against the closing rule before publication; a newly
//!   introduced closing line makes that candidate conflict.

use std::collections::HashMap;

use super::host::{ComposedOutcome, ComposedRequest};
use crate::merge::composed::{MergeMode, MergeNotice, MergeNotices, NoticeCode, NoticeCollector};
use crate::merge::syntax::{
    Cancel, DeclineReason, GrammarRegistry, Language, MAX_TRIPLET_BYTES, SyntaxError,
    SyntaxOutcome, SyntaxRequest, merge_triplet,
};

/// Maximum embedded fenced code regions considered per file before text fallback.
pub const MAX_FENCED_REGIONS: usize = 256;

/// Maps a code fence info string to a supported bundled language, if recognized.
///
/// Returns `None` for absent, unknown, or bare `sh` labels without sniffing.
#[must_use]
pub fn language_for_fence_info(info: &str) -> Option<Language> {
    let label = info.split_whitespace().next()?;
    let lower = label.to_ascii_lowercase();
    match lower.as_str() {
        "js" | "javascript" | "jsx" => Some(Language::Javascript),
        "ts" | "typescript" => Some(Language::Typescript),
        "tsx" => Some(Language::Tsx),
        "py" | "python" => Some(Language::Python),
        "bash" => Some(Language::Bash),
        "c" => Some(Language::C),
        "cpp" | "c++" => Some(Language::Cpp),
        "cs" | "csharp" => Some(Language::CSharp),
        "java" => Some(Language::Java),
        "kotlin" | "kt" => Some(Language::Kotlin),
        "swift" => Some(Language::Swift),
        "ruby" | "rb" => Some(Language::Ruby),
        "php" => Some(Language::Php),
        "ocaml" | "ml" => Some(Language::Ocaml),
        "lua" => Some(Language::Lua),
        "rust" | "rs" => Some(Language::Rust),
        "go" => Some(Language::Go),
        "json" => Some(Language::Json),
        "yaml" | "yml" => Some(Language::Yaml),
        "toml" => Some(Language::Toml),
        "html" => Some(Language::Html),
        "css" => Some(Language::Css),
        // Bare "sh", unknown, or absent labels stay text.
        _ => None,
    }
}

/// Validates whether a line of code would close the enclosing code fence.
///
/// Under CommonMark rules, a closing code fence line has 0..=3 spaces of
/// indentation, followed by a run of `fence_char` of length at least `min_len`,
/// followed only by trailing whitespace.
#[must_use]
pub fn is_closing_fence_line(line: &[u8], fence_char: char, min_len: usize) -> bool {
    let mut idx = 0;
    let mut spaces = 0;
    while idx < line.len() && line[idx] == b' ' && spaces < 3 {
        spaces += 1;
        idx += 1;
    }
    let target = match fence_char {
        '`' => b'`',
        '~' => b'~',
        _ => return false,
    };
    let mut run = 0;
    while idx < line.len() && line[idx] == target {
        run += 1;
        idx += 1;
    }
    if run < min_len {
        return false;
    }
    while idx < line.len() {
        let b = line[idx];
        if b != b' ' && b != b'\t' && b != b'\r' && b != b'\n' {
            return false;
        }
        idx += 1;
    }
    true
}

fn line_triggers_closing_rule(line: &[u8], prefix: &str, fence_char: char, min_len: usize) -> bool {
    if is_closing_fence_line(line, fence_char, min_len) {
        return true;
    }
    if !prefix.is_empty() {
        let mut prefixed = Vec::with_capacity(prefix.len() + line.len());
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(line);
        if is_fence_close(&prefixed, prefix, fence_char, min_len) {
            return true;
        }
        if is_fence_close(line, prefix, fence_char, min_len) {
            return true;
        }
    }
    false
}

/// Checks whether any line in `code` satisfies the host fence's actual closing rule,
/// including mapped list/quote prefixes, allowed indentation, fence character/run length,
/// and trailing whitespace.
fn has_closing_line(code: &[u8], prefix: &str, fence_char: char, min_len: usize) -> bool {
    for line in code.split(|&b| b == b'\n') {
        if line_triggers_closing_rule(line, prefix, fence_char, min_len) {
            return true;
        }
    }
    false
}

/// Re-attaches `prefix` to each line of `code`.
fn attach_prefix(code: &[u8], prefix: &str) -> Vec<u8> {
    if prefix.is_empty() {
        return code.to_vec();
    }
    let prefix_bytes = prefix.as_bytes();
    let mut out = Vec::new();
    for line in code.split_inclusive(|&b| b == b'\n') {
        out.extend_from_slice(prefix_bytes);
        out.extend_from_slice(line);
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct LineSpan {
    start: usize,
    end: usize,
}

fn split_lines(source: &[u8]) -> Vec<LineSpan> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < source.len() {
        let mut end = start;
        while end < source.len() && source[end] != b'\n' {
            end += 1;
        }
        if end < source.len() && source[end] == b'\n' {
            end += 1;
        }
        lines.push(LineSpan { start, end });
        start = end;
    }
    lines
}

struct FenceOpenHeader {
    prefix: String,
    indent: usize,
    fence_char: char,
    fence_len: usize,
    info_string: String,
    language: Option<Language>,
}

fn parse_fence_open(line: &[u8]) -> Option<FenceOpenHeader> {
    let mut idx = 0;
    let mut spaces_before_quote = 0;
    while idx < line.len() && line[idx] == b' ' && spaces_before_quote < 3 {
        spaces_before_quote += 1;
        idx += 1;
    }
    let mut prefix_end = 0;
    let mut has_quote = false;
    if idx < line.len() && line[idx] == b'>' {
        has_quote = true;
        idx += 1;
        if idx < line.len() && line[idx] == b' ' {
            idx += 1;
        }
        prefix_end = idx;
    } else {
        idx = 0;
    }

    let prefix = if has_quote {
        core::str::from_utf8(&line[..prefix_end]).ok()?.to_owned()
    } else {
        String::new()
    };

    let mut indent = 0;
    while idx < line.len() && line[idx] == b' ' && indent < 3 {
        indent += 1;
        idx += 1;
    }

    if idx >= line.len() {
        return None;
    }

    let ch = line[idx];
    let fence_char = match ch {
        b'`' => '`',
        b'~' => '~',
        _ => return None,
    };

    let mut fence_len = 0;
    while idx < line.len() && line[idx] == ch {
        fence_len += 1;
        idx += 1;
    }
    if fence_len < 3 {
        return None;
    }

    let rest = &line[idx..];
    let rest_str = core::str::from_utf8(rest).ok()?;
    let trimmed = rest_str.trim_matches(|c| c == '\r' || c == '\n').trim();

    if fence_char == '`' && trimmed.contains('`') {
        return None;
    }

    let language = language_for_fence_info(trimmed);

    Some(FenceOpenHeader {
        prefix,
        indent,
        fence_char,
        fence_len,
        info_string: trimmed.to_owned(),
        language,
    })
}

fn is_fence_close(line: &[u8], prefix: &str, fence_char: char, min_len: usize) -> bool {
    let mut idx = 0;
    if !prefix.is_empty() {
        let prefix_bytes = prefix.as_bytes();
        if line.starts_with(prefix_bytes) {
            idx += prefix_bytes.len();
        } else {
            let trimmed = prefix.trim_end().as_bytes();
            if !line.starts_with(trimmed) {
                return false;
            }
            idx += trimmed.len();
        }
    }

    let mut spaces = 0;
    while idx < line.len() && line[idx] == b' ' && spaces < 3 {
        spaces += 1;
        idx += 1;
    }

    let target = match fence_char {
        '`' => b'`',
        '~' => b'~',
        _ => return false,
    };
    let mut run = 0;
    while idx < line.len() && line[idx] == target {
        run += 1;
        idx += 1;
    }
    if run < min_len {
        return false;
    }

    while idx < line.len() {
        let b = line[idx];
        if b != b' ' && b != b'\t' && b != b'\r' && b != b'\n' {
            return false;
        }
        idx += 1;
    }
    true
}

fn parse_heading(line: &[u8]) -> Option<(u8, String)> {
    let mut idx = 0;
    while idx < line.len() && line[idx] == b' ' && idx < 3 {
        idx += 1;
    }
    let mut level: usize = 0;
    while idx < line.len() && line[idx] == b'#' && level < 6 {
        level += 1;
        idx += 1;
    }
    if level == 0 {
        return None;
    }
    if idx < line.len()
        && line[idx] != b' '
        && line[idx] != b'\t'
        && line[idx] != b'\r'
        && line[idx] != b'\n'
    {
        return None;
    }
    let rest = &line[idx..];
    let rest_str = core::str::from_utf8(rest).ok()?;
    let trimmed = rest_str.trim_matches(|c| c == '\r' || c == '\n').trim();
    let title = trimmed.trim_end_matches('#').trim();
    let level_u8 = u8::try_from(level).ok()?;
    Some((level_u8, title.to_owned()))
}

fn is_blank_line(line: &[u8]) -> bool {
    line.iter()
        .all(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n')
}

fn classify_block(first_line: &[u8]) -> &'static str {
    let trimmed = first_line.trim_ascii_start();
    if trimmed.starts_with(b">") {
        "quote"
    } else if trimmed.starts_with(b"- ") || trimmed.starts_with(b"* ") || trimmed.starts_with(b"+ ")
    {
        "list"
    } else if trimmed.starts_with(b"|") {
        "table"
    } else if trimmed.starts_with(b"---")
        || trimmed.starts_with(b"***")
        || trimmed.starts_with(b"___")
    {
        "hr"
    } else {
        "para"
    }
}

fn current_section_key(active: &[(u8, String, usize)]) -> String {
    if active.is_empty() {
        return "root".to_owned();
    }
    active
        .iter()
        .map(|(lvl, title, occ)| format!("h{lvl}:{title}:{occ}"))
        .collect::<Vec<_>>()
        .join("/")
}

/// Structural properties of one fenced code block.
#[derive(Clone, Debug)]
pub struct FenceBlock {
    pub key: String,
    pub section_key: String,
    pub indent: usize,
    pub fence_char: char,
    pub fence_len: usize,
    pub info_string: String,
    pub language: Option<Language>,
    pub prefix: String,
    pub uniform_prefix: bool,
    pub code_bytes: Vec<u8>,
    pub open_line: Vec<u8>,
    pub close_line: Vec<u8>,
    pub raw_bytes: Vec<u8>,
}

/// Structural properties of one host prose block.
#[derive(Clone, Debug)]
pub struct HostBlock {
    pub key: String,
    pub raw_bytes: Vec<u8>,
}

/// One top-level unit in a Markdown document.
#[derive(Clone, Debug)]
pub enum MdUnit {
    Host(HostBlock),
    Fence(FenceBlock),
}

impl MdUnit {
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Host(d) => &d.key,
            Self::Fence(d) => &d.key,
        }
    }

    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Host(d) => &d.raw_bytes,
            Self::Fence(d) => &d.raw_bytes,
        }
    }
}

fn parse_markdown_units(source: &[u8]) -> Result<Vec<MdUnit>, SyntaxError> {
    let lines = split_lines(source);
    let mut units = Vec::new();
    let mut active_headings: Vec<(u8, String, usize)> = Vec::new();
    let mut heading_counts: HashMap<(u8, String), usize> = HashMap::new();
    let mut unit_counts: HashMap<(String, &'static str), usize> = HashMap::new();
    let mut fence_counts: HashMap<(String, String), usize> = HashMap::new();

    let mut i = 0;
    while i < lines.len() {
        let line_bytes = &source[lines[i].start..lines[i].end];

        if let Some(header) = parse_fence_open(line_bytes) {
            let mut close_idx = None;
            for j in (i + 1)..lines.len() {
                let candidate = &source[lines[j].start..lines[j].end];
                if is_fence_close(
                    candidate,
                    &header.prefix,
                    header.fence_char,
                    header.fence_len,
                ) {
                    close_idx = Some(j);
                    break;
                }
            }

            let (body_end, fence_end, close_line) = match close_idx {
                Some(j) => (
                    j,
                    lines[j].end,
                    source[lines[j].start..lines[j].end].to_vec(),
                ),
                None => (lines.len(), source.len(), Vec::new()),
            };

            let mut code_bytes = Vec::new();
            let mut uniform_prefix = true;
            let prefix_bytes = header.prefix.as_bytes();
            let prefix_len = prefix_bytes.len();
            let trimmed_prefix = header.prefix.trim_end().as_bytes();

            for k in (i + 1)..body_end {
                let body_line = &source[lines[k].start..lines[k].end];
                if header.prefix.is_empty() {
                    code_bytes.extend_from_slice(body_line);
                } else if body_line.starts_with(prefix_bytes) {
                    code_bytes.extend_from_slice(&body_line[prefix_len..]);
                } else if body_line.starts_with(trimmed_prefix) {
                    let rest = &body_line[trimmed_prefix.len()..];
                    if rest.starts_with(b" ") {
                        code_bytes.extend_from_slice(&rest[1..]);
                    } else {
                        code_bytes.extend_from_slice(rest);
                    }
                } else {
                    uniform_prefix = false;
                    code_bytes.extend_from_slice(body_line);
                }
            }

            let sec_key = current_section_key(&active_headings);
            let lang_tag = header.language.map_or("text", |l| l.id()).to_owned();
            let occ = fence_counts
                .entry((sec_key.clone(), lang_tag.clone()))
                .or_insert(0);
            let this_occ = *occ;
            *occ += 1;
            let key = format!("{sec_key}/fence:{lang_tag}:{this_occ}");

            let open_line = line_bytes.to_vec();
            let raw_bytes = source[lines[i].start..fence_end].to_vec();

            units.push(MdUnit::Fence(FenceBlock {
                key,
                section_key: sec_key,
                indent: header.indent,
                fence_char: header.fence_char,
                fence_len: header.fence_len,
                info_string: header.info_string,
                language: header.language,
                prefix: header.prefix,
                uniform_prefix,
                code_bytes,
                open_line,
                close_line,
                raw_bytes,
            }));

            i = match close_idx {
                Some(j) => j + 1,
                None => lines.len(),
            };
            continue;
        }

        if let Some((level, title)) = parse_heading(line_bytes) {
            let occ = heading_counts.entry((level, title.clone())).or_insert(0);
            let this_occ = *occ;
            *occ += 1;

            while active_headings
                .last()
                .is_some_and(|(lvl, _, _)| *lvl >= level)
            {
                active_headings.pop();
            }
            active_headings.push((level, title.clone(), this_occ));

            let key = format!("heading:{level}:{title}:{this_occ}");
            let raw_bytes = line_bytes.to_vec();
            units.push(MdUnit::Host(HostBlock { key, raw_bytes }));
            i += 1;
            continue;
        }

        if is_blank_line(line_bytes) {
            let mut j = i + 1;
            while j < lines.len() && is_blank_line(&source[lines[j].start..lines[j].end]) {
                j += 1;
            }
            let sec_key = current_section_key(&active_headings);
            let occ = unit_counts.entry((sec_key.clone(), "blank")).or_insert(0);
            let this_occ = *occ;
            *occ += 1;
            let key = format!("{sec_key}/blank:{this_occ}");
            let raw_bytes = source[lines[i].start..lines[j - 1].end].to_vec();
            units.push(MdUnit::Host(HostBlock { key, raw_bytes }));
            i = j;
            continue;
        }

        let start_idx = i;
        let mut j = i + 1;
        while j < lines.len() {
            let next_bytes = &source[lines[j].start..lines[j].end];
            if is_blank_line(next_bytes)
                || parse_fence_open(next_bytes).is_some()
                || parse_heading(next_bytes).is_some()
            {
                break;
            }
            j += 1;
        }
        let sec_key = current_section_key(&active_headings);
        let kind_tag = classify_block(&source[lines[start_idx].start..lines[start_idx].end]);
        let occ = unit_counts.entry((sec_key.clone(), kind_tag)).or_insert(0);
        let this_occ = *occ;
        *occ += 1;
        let key = format!("{sec_key}/{kind_tag}:{this_occ}");
        let raw_bytes = source[lines[start_idx].start..lines[j - 1].end].to_vec();
        units.push(MdUnit::Host(HostBlock { key, raw_bytes }));
        i = j;
    }

    Ok(units)
}

fn collect_fences_by_sec_and_lang(units: &[MdUnit]) -> HashMap<(String, String), Vec<&FenceBlock>> {
    let mut map: HashMap<(String, String), Vec<&FenceBlock>> = HashMap::new();
    for u in units {
        if let MdUnit::Fence(d) = u {
            let lang_tag = d.language.map_or("text", |l| l.id()).to_owned();
            map.entry((d.section_key.clone(), lang_tag))
                .or_default()
                .push(d);
        }
    }
    map
}

fn has_duplicate_content(list: &[&FenceBlock]) -> bool {
    for (i, first) in list.iter().enumerate() {
        for second in &list[(i + 1)..] {
            if first.code_bytes == second.code_bytes {
                return true;
            }
        }
    }
    false
}

fn check_fence_correspondence(
    base_units: &[MdUnit],
    ours_units: &[MdUnit],
    theirs_units: &[MdUnit],
) -> bool {
    let base_fences = collect_fences_by_sec_and_lang(base_units);
    let ours_fences = collect_fences_by_sec_and_lang(ours_units);
    let theirs_fences = collect_fences_by_sec_and_lang(theirs_units);

    for (key, b_list) in &base_fences {
        if b_list.len() <= 1 {
            continue;
        }
        let Some(o_list) = ours_fences.get(key) else {
            return false;
        };
        let Some(t_list) = theirs_fences.get(key) else {
            return false;
        };
        if o_list.len() != b_list.len() || t_list.len() != b_list.len() {
            return false;
        }
        if has_duplicate_content(b_list) {
            return false;
        }
    }
    true
}

enum FenceMergeResult {
    Merged(Vec<u8>),
    Declined(DeclineReason),
    Conflict,
}

fn merge_fence_block(
    request: &ComposedRequest<'_>,
    base_f: &FenceBlock,
    ours_f: &FenceBlock,
    theirs_f: &FenceBlock,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    collector: &mut NoticeCollector,
) -> Result<FenceMergeResult, SyntaxError> {
    let Some(lang) = base_f.language else {
        return Ok(FenceMergeResult::Conflict);
    };
    if ours_f.language != Some(lang) || theirs_f.language != Some(lang) {
        return Ok(FenceMergeResult::Conflict);
    }
    if base_f.fence_char != ours_f.fence_char || base_f.fence_char != theirs_f.fence_char {
        return Ok(FenceMergeResult::Conflict);
    }
    if base_f.fence_len != ours_f.fence_len || base_f.fence_len != theirs_f.fence_len {
        return Ok(FenceMergeResult::Conflict);
    }
    if base_f.indent != ours_f.indent || base_f.indent != theirs_f.indent {
        return Ok(FenceMergeResult::Conflict);
    }
    if base_f.prefix != ours_f.prefix || base_f.prefix != theirs_f.prefix {
        return Ok(FenceMergeResult::Conflict);
    }
    if !base_f.prefix.is_empty()
        && (!base_f.uniform_prefix || !ours_f.uniform_prefix || !theirs_f.uniform_prefix)
    {
        return Ok(FenceMergeResult::Conflict);
    }

    let syn_req = SyntaxRequest {
        path: request.path.clone(),
        language: lang,
        base: &base_f.code_bytes,
        ours: &ours_f.code_bytes,
        theirs: &theirs_f.code_bytes,
    };
    let outcome = merge_triplet(&syn_req, registry, cancel)?;
    let merged_code = match outcome {
        SyntaxOutcome::Merged { bytes, notices, .. } => {
            collector.absorb(notices);
            bytes
        }
        SyntaxOutcome::Declined {
            reason, notices, ..
        } => {
            collector.absorb(notices);
            return Ok(FenceMergeResult::Declined(reason));
        }
    };

    if has_closing_line(
        &merged_code,
        &base_f.prefix,
        base_f.fence_char,
        base_f.fence_len,
    ) {
        if let Ok(notice) = MergeNotice::new(
            request.path.clone(),
            None,
            "markdown",
            NoticeCode::SyntaxAmbiguous,
            "merged code introduces premature closing fence line",
        ) {
            collector.record(notice);
        }
        return Ok(FenceMergeResult::Conflict);
    }

    let final_code = attach_prefix(&merged_code, &base_f.prefix);
    let mut assembled =
        Vec::with_capacity(base_f.open_line.len() + final_code.len() + base_f.close_line.len());
    assembled.extend_from_slice(&base_f.open_line);
    assembled.extend_from_slice(&final_code);
    assembled.extend_from_slice(&base_f.close_line);
    Ok(FenceMergeResult::Merged(assembled))
}

enum UnitMergeResult {
    Merged(Vec<u8>),
    Declined(DeclineReason),
    Conflict,
}

fn merge_single_unit(
    request: &ComposedRequest<'_>,
    base_unit: &MdUnit,
    ours_unit: &MdUnit,
    theirs_unit: &MdUnit,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    collector: &mut NoticeCollector,
) -> Result<UnitMergeResult, SyntaxError> {
    let b_raw = base_unit.raw_bytes();
    let o_raw = ours_unit.raw_bytes();
    let t_raw = theirs_unit.raw_bytes();

    if o_raw == b_raw && t_raw == b_raw {
        return Ok(UnitMergeResult::Merged(b_raw.to_vec()));
    }
    if o_raw != b_raw && t_raw == b_raw {
        return Ok(UnitMergeResult::Merged(o_raw.to_vec()));
    }
    if o_raw == b_raw && t_raw != b_raw {
        return Ok(UnitMergeResult::Merged(t_raw.to_vec()));
    }
    if o_raw == t_raw {
        return Ok(UnitMergeResult::Merged(o_raw.to_vec()));
    }

    match (base_unit, ours_unit, theirs_unit) {
        (MdUnit::Fence(b_f), MdUnit::Fence(o_f), MdUnit::Fence(t_f)) => {
            let res = merge_fence_block(request, b_f, o_f, t_f, registry, cancel, collector)?;
            match res {
                FenceMergeResult::Merged(bytes) => Ok(UnitMergeResult::Merged(bytes)),
                FenceMergeResult::Declined(reason) => Ok(UnitMergeResult::Declined(reason)),
                FenceMergeResult::Conflict => Ok(UnitMergeResult::Conflict),
            }
        }
        _ => Ok(UnitMergeResult::Conflict),
    }
}

fn gap_insertions_match(ours_gap: &[MdUnit], theirs_gap: &[MdUnit]) -> bool {
    if ours_gap.is_empty() || theirs_gap.is_empty() {
        return true;
    }
    if ours_gap.len() != theirs_gap.len() {
        return false;
    }
    for (o, t) in ours_gap.iter().zip(theirs_gap.iter()) {
        if o.raw_bytes() != t.raw_bytes() {
            return false;
        }
    }
    true
}

/// One side's document positioned at its match for a base unit, for
/// fence-span checks.
struct SideSpan<'u, 'm> {
    units: &'u [MdUnit],
    match_pos: usize,
    map: &'m HashMap<&'u str, usize>,
}

/// End of the span owned by the side unit at `match_pos`: the position of the
/// next matched base unit in the same side document, or the document end.
fn fence_span_end(
    side_map: &HashMap<&str, usize>,
    base_units: &[MdUnit],
    base_idx: usize,
    match_pos: usize,
    side_len: usize,
) -> usize {
    for next_base in &base_units[(base_idx + 1)..] {
        if let Some(pos) = side_map.get(next_base.key()).copied()
            && pos > match_pos
        {
            return pos;
        }
    }
    side_len
}

/// Whether the side's span (matched fence plus following spill up to the next
/// matched base unit) holds a closing-rule line outside the matched fence
/// itself. Only prose and label-less fence fragments count, so a genuinely
/// appended fenced block is not mistaken for a broken boundary.
fn span_holds_new_close(
    base_fence: &FenceBlock,
    side: SideSpan<'_, '_>,
    base_units: &[MdUnit],
    base_idx: usize,
) -> bool {
    let end = fence_span_end(
        side.map,
        base_units,
        base_idx,
        side.match_pos,
        side.units.len(),
    );
    let Some(span) = side.units.get(side.match_pos..end) else {
        return false;
    };
    let Some((_, spill)) = span.split_first() else {
        return false;
    };
    spill
        .iter()
        .filter(|unit| match unit {
            MdUnit::Host(_) => true,
            MdUnit::Fence(fragment) => fragment.info_string.is_empty(),
        })
        .flat_map(|unit| unit.raw_bytes().split(|&byte| byte == b'\n'))
        .any(|line| {
            is_fence_close(
                line,
                &base_fence.prefix,
                base_fence.fence_char,
                base_fence.fence_len,
            )
        })
}

/// Whether both sides changed the fence differently and either side's span
/// proves a newly introduced closing line. Host parsing consumes the new
/// delimiter as a boundary, so the child slices no longer carry it and only a
/// span-level check can still see the break before publication.
fn fence_close_introduced(
    base_unit: &MdUnit,
    base_units: &[MdUnit],
    base_idx: usize,
    ours: SideSpan<'_, '_>,
    theirs: SideSpan<'_, '_>,
) -> bool {
    let MdUnit::Fence(base_fence) = base_unit else {
        return false;
    };
    let Some(o_unit) = ours.units.get(ours.match_pos) else {
        return false;
    };
    let Some(t_unit) = theirs.units.get(theirs.match_pos) else {
        return false;
    };
    if o_unit.raw_bytes() == base_unit.raw_bytes() {
        return false;
    }
    if t_unit.raw_bytes() == base_unit.raw_bytes() {
        return false;
    }
    if o_unit.raw_bytes() == t_unit.raw_bytes() {
        return false;
    }
    span_holds_new_close(base_fence, ours, base_units, base_idx)
        || span_holds_new_close(base_fence, theirs, base_units, base_idx)
}

fn merge_units(
    request: &ComposedRequest<'_>,
    base_units: &[MdUnit],
    ours_units: &[MdUnit],
    theirs_units: &[MdUnit],
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<ComposedOutcome, SyntaxError> {
    let mut collector = NoticeCollector::new();

    if !check_fence_correspondence(base_units, ours_units, theirs_units) {
        if let Ok(notice) = MergeNotice::new(
            request.path.clone(),
            None,
            "markdown",
            NoticeCode::SyntaxAmbiguous,
            "duplicate same-language code fences without unique correspondence",
        ) {
            collector.record(notice);
        }
        return Ok(ComposedOutcome::Conflict {
            notices: collector.finish(),
        });
    }

    let ours_map: HashMap<&str, usize> = ours_units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.key(), i))
        .collect();
    let theirs_map: HashMap<&str, usize> = theirs_units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.key(), i))
        .collect();

    let mut merged_bytes = Vec::new();
    let mut ours_idx = 0;
    let mut theirs_idx = 0;

    for (bi, base_unit) in base_units.iter().enumerate() {
        cancel.check()?;

        let ours_match = ours_map.get(base_unit.key()).copied();
        let theirs_match = theirs_map.get(base_unit.key()).copied();

        let ours_gap_end = match ours_match {
            Some(pos) if pos >= ours_idx => pos,
            _ => ours_idx,
        };
        let theirs_gap_end = match theirs_match {
            Some(pos) if pos >= theirs_idx => pos,
            _ => theirs_idx,
        };

        let ours_gap = &ours_units[ours_idx..ours_gap_end];
        let theirs_gap = &theirs_units[theirs_idx..theirs_gap_end];

        if !gap_insertions_match(ours_gap, theirs_gap) {
            if let Ok(notice) = MergeNotice::new(
                request.path.clone(),
                None,
                "markdown",
                NoticeCode::SyntaxAmbiguous,
                "competing insertions into the same gap",
            ) {
                collector.record(notice);
            }
            return Ok(ComposedOutcome::Conflict {
                notices: collector.finish(),
            });
        }

        let inserted = if !ours_gap.is_empty() {
            ours_gap
        } else {
            theirs_gap
        };
        for ins in inserted {
            merged_bytes.extend_from_slice(ins.raw_bytes());
        }

        ours_idx = match ours_match {
            Some(pos) if pos >= ours_idx => pos + 1,
            _ => ours_idx,
        };
        theirs_idx = match theirs_match {
            Some(pos) if pos >= theirs_idx => pos + 1,
            _ => theirs_idx,
        };

        match (ours_match, theirs_match) {
            (None, None) => continue,
            (None, Some(t_pos)) => {
                let t_unit = &theirs_units[t_pos];
                if t_unit.raw_bytes() != base_unit.raw_bytes() {
                    return Ok(ComposedOutcome::Conflict {
                        notices: collector.finish(),
                    });
                }
                continue;
            }
            (Some(o_pos), None) => {
                let o_unit = &ours_units[o_pos];
                if o_unit.raw_bytes() != base_unit.raw_bytes() {
                    return Ok(ComposedOutcome::Conflict {
                        notices: collector.finish(),
                    });
                }
                continue;
            }
            (Some(o_pos), Some(t_pos)) => {
                let o_unit = &ours_units[o_pos];
                let t_unit = &theirs_units[t_pos];
                let broken = fence_close_introduced(
                    base_unit,
                    base_units,
                    bi,
                    SideSpan {
                        units: ours_units,
                        match_pos: o_pos,
                        map: &ours_map,
                    },
                    SideSpan {
                        units: theirs_units,
                        match_pos: t_pos,
                        map: &theirs_map,
                    },
                );
                if broken {
                    if let Ok(notice) = MergeNotice::new(
                        request.path.clone(),
                        None,
                        "markdown",
                        NoticeCode::SyntaxAmbiguous,
                        format!(
                            "fence {} gains a closing line concurrent with code edits; treating as conflict",
                            base_unit.key(),
                        ),
                    ) {
                        collector.record(notice);
                    }
                    return Ok(ComposedOutcome::Conflict {
                        notices: collector.finish(),
                    });
                }
                let merged_res = merge_single_unit(
                    request,
                    base_unit,
                    o_unit,
                    t_unit,
                    registry,
                    cancel,
                    &mut collector,
                )?;
                match merged_res {
                    UnitMergeResult::Merged(bytes) => {
                        merged_bytes.extend_from_slice(&bytes);
                    }
                    UnitMergeResult::Declined(reason) => {
                        return Ok(ComposedOutcome::Declined {
                            reason,
                            notices: collector.finish(),
                        });
                    }
                    UnitMergeResult::Conflict => {
                        return Ok(ComposedOutcome::Conflict {
                            notices: collector.finish(),
                        });
                    }
                }
            }
        }
    }

    let trailing_ours = &ours_units[ours_idx..];
    let trailing_theirs = &theirs_units[theirs_idx..];
    if !gap_insertions_match(trailing_ours, trailing_theirs) {
        return Ok(ComposedOutcome::Conflict {
            notices: collector.finish(),
        });
    }
    let trailing = if !trailing_ours.is_empty() {
        trailing_ours
    } else {
        trailing_theirs
    };
    for ins in trailing {
        merged_bytes.extend_from_slice(ins.raw_bytes());
    }

    Ok(ComposedOutcome::Clean {
        bytes: merged_bytes,
        notices: collector.finish(),
    })
}

/// Merges one Markdown composed request.
///
/// Dispatches fenced code blocks through their mapped bundled language grammar
/// while preserving headings, paragraphs, lists, links, tables, and block delimiters.
///
/// # Errors
/// Returns [`SyntaxError::Cancelled`] if `cancel` trips, or [`SyntaxError::Invalid`]
/// on malformed paths.
pub fn merge_markdown(
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<ComposedOutcome, SyntaxError> {
    cancel.check()?;

    if request.path.is_empty() || request.path.as_bytes().contains(&0) {
        return Err(SyntaxError::Invalid {
            what: "merge path",
            detail: "must be non-empty and contain no NUL".to_owned(),
        });
    }

    if request.mode == MergeMode::Git {
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::UnsupportedConstruct,
            notices: MergeNotices::default(),
        });
    }

    for (which, bytes) in [
        ("base", request.base),
        ("ours", request.ours),
        ("theirs", request.theirs),
    ] {
        if bytes.contains(&0) {
            let mut collector = NoticeCollector::new();
            if let Ok(notice) = MergeNotice::new(
                request.path.clone(),
                None,
                "markdown",
                NoticeCode::SyntaxParseDeclined,
                format!("{which} input holds NUL bytes; binary content is not parsed"),
            ) {
                collector.record(notice);
            }
            return Ok(ComposedOutcome::Declined {
                reason: DeclineReason::BinaryContent,
                notices: collector.finish(),
            });
        }
        if core::str::from_utf8(bytes).is_err() {
            let mut collector = NoticeCollector::new();
            if let Ok(notice) = MergeNotice::new(
                request.path.clone(),
                None,
                "markdown",
                NoticeCode::SyntaxParseDeclined,
                format!("{which} input is not valid UTF-8"),
            ) {
                collector.record(notice);
            }
            return Ok(ComposedOutcome::Declined {
                reason: DeclineReason::ParseFailed,
                notices: collector.finish(),
            });
        }
    }

    if request.ours == request.base {
        return Ok(ComposedOutcome::Clean {
            bytes: request.theirs.to_vec(),
            notices: MergeNotices::default(),
        });
    }
    if request.theirs == request.base {
        return Ok(ComposedOutcome::Clean {
            bytes: request.ours.to_vec(),
            notices: MergeNotices::default(),
        });
    }
    if request.ours == request.theirs {
        return Ok(ComposedOutcome::Clean {
            bytes: request.ours.to_vec(),
            notices: MergeNotices::default(),
        });
    }

    let total = u64::try_from(request.base.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(request.ours.len()).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(request.theirs.len()).unwrap_or(u64::MAX));
    if total > MAX_TRIPLET_BYTES {
        let mut collector = NoticeCollector::new();
        if let Ok(notice) = MergeNotice::new(
            request.path.clone(),
            None,
            "markdown",
            NoticeCode::SyntaxLimit,
            format!("triplet holds {total} bytes over the {MAX_TRIPLET_BYTES} bound"),
        ) {
            collector.record(notice);
        }
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::SizeLimit,
            notices: collector.finish(),
        });
    }

    if let Some(grammar) = registry.get(Language::Markdown) {
        cancel.check()?;
        let _ = grammar.parse(request.base, cancel);
        let _ = grammar.parse(request.ours, cancel);
        let _ = grammar.parse(request.theirs, cancel);
    }

    let base_units = parse_markdown_units(request.base)?;
    let ours_units = parse_markdown_units(request.ours)?;
    let theirs_units = parse_markdown_units(request.theirs)?;

    let count_fences = |units: &[MdUnit]| -> usize {
        units
            .iter()
            .filter(|u| matches!(u, MdUnit::Fence(_)))
            .count()
    };
    if count_fences(&base_units) > MAX_FENCED_REGIONS
        || count_fences(&ours_units) > MAX_FENCED_REGIONS
        || count_fences(&theirs_units) > MAX_FENCED_REGIONS
    {
        let mut collector = NoticeCollector::new();
        if let Ok(notice) = MergeNotice::new(
            request.path.clone(),
            None,
            "markdown",
            NoticeCode::SyntaxLimit,
            format!("fenced code regions exceed maximum bound of {MAX_FENCED_REGIONS}"),
        ) {
            collector.record(notice);
        }
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::SizeLimit,
            notices: collector.finish(),
        });
    }

    merge_units(
        request,
        &base_units,
        &ours_units,
        &theirs_units,
        registry,
        cancel,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::ByteString;
    use crate::merge::syntax::treesitter::registry_providers;

    fn setup_test_registry<'a>(
        providers: &'a [Result<crate::merge::syntax::TsGrammar, SyntaxError>],
    ) -> GrammarRegistry<'a> {
        let mut registry = GrammarRegistry::new();
        for p in providers.iter().flatten() {
            registry.insert(p);
        }
        registry
    }

    #[test]
    fn test_independent_prose_and_fenced_rust_edits_combine() {
        let base = "# Title\n\nInitial prose.\n\n```rust\nfn compute() -> u32 {\n    1\n}\n```\n\nNotes.\n";
        let ours = "# Title\n\nUpdated introductory prose.\n\n```rust\nfn compute() -> u32 {\n    1\n}\n```\n\nNotes.\n";
        let theirs = "# Title\n\nInitial prose.\n\n```rust\nfn compute() -> u32 {\n    1\n}\n\nfn extra() -> u32 {\n    2\n}\n```\n\nNotes.\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("README.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        match outcome {
            ComposedOutcome::Clean { bytes, .. } => {
                let merged = core::str::from_utf8(&bytes).expect("valid utf-8");
                assert!(merged.contains("Updated introductory prose."));
                assert!(merged.contains("fn extra()"));
            }
            other => panic!("expected clean merge, got {:?}", other),
        }
    }

    #[test]
    fn test_duplicate_same_language_fences_without_unique_correspondence_conflict() {
        let base =
            "# Section\n\n```rust\nfn duplicate() {}\n```\n\n```rust\nfn duplicate() {}\n```\n";
        let ours = "# Section\n\n```rust\nfn duplicate() { let x = 1; }\n```\n\n```rust\nfn duplicate() {}\n```\n";
        let theirs = "# Section\n\n```rust\nfn duplicate() {}\n```\n\n```rust\nfn duplicate() { let y = 2; }\n```\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("README.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_prefix_change_cannot_corrupt_code_offsets() {
        let base = "> ```rust\n> fn helper() {\n>     do_work();\n> }\n> ```\n";
        let ours = ">> ```rust\n>> fn helper() {\n>>     do_work();\n>> }\n>> ```\n";
        let theirs =
            "> ```rust\n> fn helper() {\n>     do_work();\n>     log_work();\n> }\n> ```\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("README.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_closing_fence_rule_prevents_premature_close() {
        let base = "```rust\nfn example() {\n    let a = 1;\n}\n```\n";
        let ours = "```rust\nfn example() {\n    let a = 10;\n}\n```\n";
        let theirs = "```rust\nfn example() {\n```\n    let a = 1;\n}\n```\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("README.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_unrecognized_info_string_stays_text() {
        let base = "```custom_tool\nconfig: default\n```\n";
        let ours = "```custom_tool\nconfig: ours\n```\n";
        let theirs = "```custom_tool\nconfig: theirs\n```\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("tool.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_fenced_code_concurrent_clean_rust_merge() {
        let base = "# Header\n\n```rust\nfn first() -> u32 {\n    1\n}\n\nfn second() -> u32 {\n    2\n}\n```\n";
        let ours = "# Header\n\n```rust\nfn first() -> u32 {\n    10\n}\n\nfn second() -> u32 {\n    2\n}\n```\n";
        let theirs = "# Header\n\n```rust\nfn first() -> u32 {\n    1\n}\n\nfn second() -> u32 {\n    20\n}\n```\n";

        let providers = registry_providers();
        let registry = setup_test_registry(&providers);
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("math.md"),
            language: Language::Markdown,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_markdown(&req, &registry, &cancel).expect("merge_markdown");
        match outcome {
            ComposedOutcome::Clean { bytes, .. } => {
                let merged = core::str::from_utf8(&bytes).expect("valid utf-8");
                assert!(merged.contains("10"));
                assert!(merged.contains("20"));
            }
            other => panic!("expected clean merge, got {:?}", other),
        }
    }
}
