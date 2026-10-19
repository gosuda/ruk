//! Composed-file merge adapter for Jupyter notebooks (`.ipynb`).
//!
//! Implements '## Jupyter notebooks' from the composed-file specification:
//! * Own document and cell structure; supports nbformat major 4, minors 0 through 5
//!   with no upgrade or normalization.
//! * Minor 5 requires unique ASCII IDs of 1–64 letters/digits/hyphens/underscores.
//!   Non-v4 or newer minor declines with [`NoticeCode::NotebookStructureDeclined`].
//! * Rejects duplicate decoded JSON object keys before map conversion.
//! * Locates members/arrays with the bundled `tree-sitter-json` grammar through
//!   the registry and slices original bytes for unchanged values.
//! * Decodes slices with `crate::protocol::decode_json` or borrowed slices.
//! * Never rebuilds the document through a pretty-printer; preserves key order,
//!   whitespace, unknown fields, metadata, attachments byte-identically when
//!   carried from one side.
//! * Cell identity: valid unique IDs align independently with each side; absent
//!   side is a deletion. New-ID collisions conflict unless byte-identical and in
//!   the same gap. Without IDs, anchors exact unchanged cells by `cell_type` plus
//!   source content and unambiguous surrounding base matches; outputs and
//!   execution counts are never identity evidence.
//! * Content: code-cell language from `language_info.name` then kernelspec `language`;
//!   unsupported selects text with [`NoticeCode::EmbeddedLanguageUnsupported`].
//!   Markdown cells use the Markdown composed adapter; raw cells use text;
//!   code-cell source uses the selected syntax adapter.
//! * Metadata, attachments, and unknown fields use conservative JSON three-way
//!   value merging.
//! * Output clearing: a base code cell whose final decoded source differs from base
//!   sets `outputs` to `[]` and `execution_count` to `null`, even when the final
//!   source equals one side; a new code cell clears too; an unchanged code cell
//!   keeps them through value merging; a cell-type change into code clears.
//!   Emits [`NoticeCode::NotebookOutputsCleared`].

use std::collections::{HashMap, HashSet};

use super::host::{ComposedOutcome, ComposedRequest};
use crate::bytes::ByteString;
use crate::merge::composed::{
    MergeMode, MergeNotice, MergeNotices, NoticeCode, NoticeCollector, NoticeInput, NoticeRegion,
};
use crate::merge::syntax::SyntaxRequest;
use crate::merge::syntax::adapters::DeclineReason;
use crate::merge::syntax::alignment::merge_triplet;
use crate::merge::syntax::grammar::{
    Cancel, GrammarRegistry, Language, MAX_TRIPLET_BYTES, ParsedTree, SyntaxError,
};
use crate::protocol::decode_json;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};

/// Maximum number of cells accepted in a notebook to bound memory and recursion.
pub const MAX_NOTEBOOK_CELLS: usize = 16_384;

/// Merges Jupyter notebook documents (`.ipynb`) according to the composed-file specification.
///
/// # Errors
/// Returns [`SyntaxError::Cancelled`] if `cancel` fires, or [`SyntaxError::Invalid`]
/// if caller arguments are invalid.
pub fn merge_notebook(
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
            reason: DeclineReason::ComposedLanguage,
            notices: MergeNotices::default(),
        });
    }

    if let Err(outcome) = validate_inputs(request) {
        return Ok(outcome);
    }

    let Some(grammar) = registry.get(Language::Json) else {
        return Ok(notebook_decline(
            &request.path,
            NoticeCode::SyntaxWorkerFailed,
            DeclineReason::GrammarUnavailable,
            "tree-sitter-json grammar unavailable in registry",
        ));
    };

    let (base_tree, ours_tree, theirs_tree) = match parse_input_trees(grammar, request, cancel) {
        Ok(trees) => trees,
        Err(Ok(outcome)) => return Ok(outcome),
        Err(Err(err)) => return Err(err),
    };

    let base_doc = match parse_notebook(&base_tree, request.base, &request.path) {
        Ok(doc) => doc,
        Err(outcome) => return Ok(outcome),
    };
    let ours_doc = match parse_notebook(&ours_tree, request.ours, &request.path) {
        Ok(doc) => doc,
        Err(outcome) => return Ok(outcome),
    };
    let theirs_doc = match parse_notebook(&theirs_tree, request.theirs, &request.path) {
        Ok(doc) => doc,
        Err(outcome) => return Ok(outcome),
    };

    let mut collector = NoticeCollector::new();

    let (target_major, target_minor) = match resolve_version(
        &base_doc,
        &ours_doc,
        &theirs_doc,
        request.ours,
        request.theirs,
        request.base,
    ) {
        VersionResolution::Resolved(maj, min) => (maj, min),
        VersionResolution::Conflict => return Ok(conflict_outcome()),
    };

    let code_language = match resolve_code_language(
        &base_doc.metadata_value,
        &ours_doc.metadata_value,
        &theirs_doc.metadata_value,
        request,
        &mut collector,
    ) {
        LanguageDecision::Selected(l) => l,
        LanguageDecision::Conflict => return Ok(conflict_outcome()),
    };

    let Some(merged_metadata_val) = merge_json_values(
        &base_doc.metadata_value,
        &ours_doc.metadata_value,
        &theirs_doc.metadata_value,
    ) else {
        return Ok(conflict_outcome());
    };

    let aligned_cells = match align_cells(&base_doc, &ours_doc, &theirs_doc, request) {
        Ok(cells) => cells,
        Err(outcome) => return Ok(outcome),
    };

    cancel.check()?;

    let mut merged_cells_bytes = Vec::new();

    for (pos, candidate) in aligned_cells.iter().enumerate() {
        cancel.check()?;
        let cell_merge = merge_candidate_cell(
            candidate,
            pos,
            code_language,
            request,
            registry,
            cancel,
            &mut collector,
        )?;

        let cell_bytes = match cell_merge {
            CellMergeOutcome::Merged { bytes, .. } => bytes,
            CellMergeOutcome::Conflict => return Ok(conflict_outcome()),
        };
        merged_cells_bytes.push(cell_bytes);
    }

    let (donor_bytes, donor_doc) = select_root_donor(request, &base_doc, &ours_doc, &theirs_doc);

    let cells_array_bytes = format_cells_array(
        donor_bytes,
        donor_doc.cells_val_range,
        &donor_doc.cells,
        &merged_cells_bytes,
    );

    let final_bytes = splice_root_document(
        donor_bytes,
        donor_doc,
        cells_array_bytes,
        &merged_metadata_val,
        target_major,
        target_minor,
    );

    let final_tree = grammar.parse(&final_bytes, cancel)?;
    if final_tree.has_error() {
        return Ok(notebook_decline(
            &request.path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            "assembled notebook JSON failed syntax verification",
        ));
    }

    Ok(ComposedOutcome::Clean {
        bytes: final_bytes,
        notices: collector.finish(),
    })
}

fn conflict_outcome() -> ComposedOutcome {
    ComposedOutcome::Conflict {
        notices: MergeNotices::default(),
    }
}

fn validate_inputs(request: &ComposedRequest<'_>) -> Result<(), ComposedOutcome> {
    check_triplet_size(request)?;
    check_input_bytes("base", request.base, &request.path)?;
    check_input_bytes("ours", request.ours, &request.path)?;
    check_input_bytes("theirs", request.theirs, &request.path)?;
    Ok(())
}

fn check_triplet_size(request: &ComposedRequest<'_>) -> Result<(), ComposedOutcome> {
    let total_len = request
        .base
        .len()
        .saturating_add(request.ours.len())
        .saturating_add(request.theirs.len());
    let max_bytes = usize::try_from(MAX_TRIPLET_BYTES).unwrap_or(usize::MAX);
    if total_len <= max_bytes {
        return Ok(());
    }
    Err(notebook_decline(
        &request.path,
        NoticeCode::SyntaxLimit,
        DeclineReason::SizeLimit,
        "triplet size exceeds MAX_TRIPLET_BYTES",
    ))
}

fn check_input_bytes(which: &str, bytes: &[u8], path: &ByteString) -> Result<(), ComposedOutcome> {
    if bytes.contains(&0) {
        let msg = format!("{which} input holds NUL bytes; binary content is not parsed");
        return Err(notebook_decline(
            path,
            NoticeCode::SyntaxParseDeclined,
            DeclineReason::BinaryContent,
            &msg,
        ));
    }
    if core::str::from_utf8(bytes).is_err() {
        let msg = format!("{which} input is not valid UTF-8");
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            &msg,
        ));
    }
    Ok(())
}

fn parse_input_trees<'a>(
    grammar: &'a dyn crate::merge::syntax::Grammar,
    request: &'a ComposedRequest<'_>,
    cancel: &Cancel,
) -> Result<(ParsedTree, ParsedTree, ParsedTree), Result<ComposedOutcome, SyntaxError>> {
    let base_tree = grammar.parse(request.base, cancel).map_err(Err)?;
    let ours_tree = grammar.parse(request.ours, cancel).map_err(Err)?;
    let theirs_tree = grammar.parse(request.theirs, cancel).map_err(Err)?;

    check_tree_clean("base", &base_tree, &request.path).map_err(Ok)?;
    check_tree_clean("ours", &ours_tree, &request.path).map_err(Ok)?;
    check_tree_clean("theirs", &theirs_tree, &request.path).map_err(Ok)?;

    Ok((base_tree, ours_tree, theirs_tree))
}

fn check_tree_clean(
    which: &str,
    tree: &ParsedTree,
    path: &ByteString,
) -> Result<(), ComposedOutcome> {
    if !tree.has_error() && !tree.is_empty() {
        return Ok(());
    }
    let msg = format!("{which} input holds syntax errors");
    Err(notebook_decline(
        path,
        NoticeCode::NotebookStructureDeclined,
        DeclineReason::ParseFailed,
        &msg,
    ))
}

enum LanguageDecision {
    Selected(Option<Language>),
    Conflict,
}

fn resolve_code_language(
    base_meta: &sonic_rs::Value,
    ours_meta: &sonic_rs::Value,
    theirs_meta: &sonic_rs::Value,
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> LanguageDecision {
    let base_raw = raw_language_name(base_meta);
    let ours_raw = raw_language_name(ours_meta);
    let theirs_raw = raw_language_name(theirs_meta);

    if ours_raw != theirs_raw && ours_raw != base_raw && theirs_raw != base_raw {
        return LanguageDecision::Conflict;
    }

    let effective_lang_name = if ours_raw != base_raw {
        ours_raw
    } else if theirs_raw != base_raw {
        theirs_raw
    } else {
        base_raw
    };

    let code_language = effective_lang_name.as_deref().and_then(Language::from_id);

    if code_language.is_none() {
        let detail = if let Some(name) = &effective_lang_name {
            format!("declared language '{name}' is unsupported; code cells merge as text")
        } else {
            "notebook declares no supported code language; code cells merge as text".to_owned()
        };
        if let Ok(notice) = MergeNotice::new(
            request.path.clone(),
            None,
            Language::Notebook.id(),
            NoticeCode::EmbeddedLanguageUnsupported,
            detail,
        ) {
            collector.record(notice);
        }
    }

    LanguageDecision::Selected(code_language)
}

fn select_root_donor<'a>(
    request: &'a ComposedRequest<'_>,
    base: &'a ParsedNotebook,
    ours: &'a ParsedNotebook,
    theirs: &'a ParsedNotebook,
) -> (&'a [u8], &'a ParsedNotebook) {
    if request.ours != request.base {
        (request.ours, ours)
    } else if request.theirs != request.base {
        (request.theirs, theirs)
    } else {
        (request.base, base)
    }
}

fn splice_root_document(
    donor_bytes: &[u8],
    donor_doc: &ParsedNotebook,
    cells_array_bytes: Vec<u8>,
    merged_metadata_val: &sonic_rs::Value,
    target_major: i64,
    target_minor: i64,
) -> Vec<u8> {
    let mut root_replacements = Vec::new();

    root_replacements.push((
        donor_doc.cells_val_range.0,
        donor_doc.cells_val_range.1,
        cells_array_bytes,
    ));

    if *merged_metadata_val != donor_doc.metadata_value {
        let meta_bytes = sonic_rs::to_vec(merged_metadata_val).unwrap_or_else(|_| b"{}".to_vec());
        root_replacements.push((
            donor_doc.metadata_val_range.0,
            donor_doc.metadata_val_range.1,
            meta_bytes,
        ));
    }

    if target_major != donor_doc.nbformat {
        root_replacements.push((
            donor_doc.nbformat_val_range.0,
            donor_doc.nbformat_val_range.1,
            target_major.to_string().into_bytes(),
        ));
    }

    if target_minor != donor_doc.nbformat_minor {
        root_replacements.push((
            donor_doc.nbformat_minor_val_range.0,
            donor_doc.nbformat_minor_val_range.1,
            target_minor.to_string().into_bytes(),
        ));
    }

    root_replacements.sort_by_key(|r| r.0);

    let mut final_bytes = Vec::new();
    let mut cursor = 0;
    for (start, end, repl) in root_replacements {
        if start >= cursor && end <= donor_bytes.len() {
            final_bytes.extend_from_slice(&donor_bytes[cursor..start]);
            final_bytes.extend_from_slice(&repl);
            cursor = end;
        }
    }
    final_bytes.extend_from_slice(&donor_bytes[cursor..]);
    final_bytes
}

enum VersionResolution {
    Resolved(i64, i64),
    Conflict,
}

fn resolve_version(
    base: &ParsedNotebook,
    ours: &ParsedNotebook,
    theirs: &ParsedNotebook,
    ours_bytes: &[u8],
    theirs_bytes: &[u8],
    base_bytes: &[u8],
) -> VersionResolution {
    let base_v = (base.nbformat, base.nbformat_minor);
    let ours_v = (ours.nbformat, ours.nbformat_minor);
    let theirs_v = (theirs.nbformat, theirs.nbformat_minor);

    if ours_v == base_v && theirs_v == base_v {
        return VersionResolution::Resolved(base_v.0, base_v.1);
    }
    if ours_v == theirs_v {
        return VersionResolution::Resolved(ours_v.0, ours_v.1);
    }
    if ours_v != base_v && theirs_v == base_v {
        if theirs_bytes == base_bytes {
            return VersionResolution::Resolved(ours_v.0, ours_v.1);
        }
        return VersionResolution::Conflict;
    }
    if theirs_v != base_v && ours_v == base_v {
        if ours_bytes == base_bytes {
            return VersionResolution::Resolved(theirs_v.0, theirs_v.1);
        }
        return VersionResolution::Conflict;
    }
    VersionResolution::Conflict
}

struct ParsedNotebook {
    nbformat: i64,
    nbformat_val_range: (usize, usize),
    nbformat_minor: i64,
    nbformat_minor_val_range: (usize, usize),
    metadata_val_range: (usize, usize),
    metadata_value: sonic_rs::Value,
    cells_val_range: (usize, usize),
    cells: Vec<ParsedCell>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SourceKind {
    String,
    List,
}

struct DecodedSource {
    text: String,
    kind: SourceKind,
}

struct ParsedCell {
    byte_range: (usize, usize),
    cell_type: String,
    id: Option<String>,
    metadata_val_range: (usize, usize),
    metadata_value: sonic_rs::Value,
    source: DecodedSource,
    source_val_range: (usize, usize),
    outputs_val_range: Option<(usize, usize)>,
    outputs_value: Option<sonic_rs::Value>,
    execution_count_val_range: Option<(usize, usize)>,
    execution_count_value: Option<sonic_rs::Value>,
}

fn parse_notebook(
    tree: &ParsedTree,
    source: &[u8],
    path: &ByteString,
) -> Result<ParsedNotebook, ComposedOutcome> {
    let root_node = find_root_object(tree).ok_or_else(|| {
        notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            "root JSON value is not an object",
        )
    })?;

    let root_pairs = parse_object_pairs(tree, root_node, source).map_err(|r| {
        notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            r,
            "root object parse failed",
        )
    })?;

    let mut fields = RootFields::default();
    for p in &root_pairs {
        extract_root_field(tree, p, source, &mut fields);
    }

    let (major, minor, meta_val, cells_node) = validate_root_fields(fields, path)?;
    let cells = extract_all_cells(tree, cells_node.0, source, minor.0, path)?;

    Ok(ParsedNotebook {
        nbformat: major.0,
        nbformat_val_range: major.1,
        nbformat_minor: minor.0,
        nbformat_minor_val_range: minor.1,
        metadata_val_range: meta_val.0,
        metadata_value: meta_val.1,
        cells_val_range: cells_node.1,
        cells,
    })
}

#[derive(Default)]
struct RootFields {
    nbformat: Option<(i64, (usize, usize))>,
    nbformat_minor: Option<(i64, (usize, usize))>,
    metadata: Option<((usize, usize), sonic_rs::Value)>,
    cells: Option<(u32, (usize, usize))>,
}

fn extract_root_field(tree: &ParsedTree, p: &ParsedPair, source: &[u8], fields: &mut RootFields) {
    let bytes = &source[p.val_range.0..p.val_range.1];
    match p.key.as_str() {
        "nbformat" => fields.nbformat = decode_json::<i64>(bytes).ok().map(|v| (v, p.val_range)),
        "nbformat_minor" => {
            fields.nbformat_minor = decode_json::<i64>(bytes).ok().map(|v| (v, p.val_range))
        }
        "metadata" => {
            fields.metadata = decode_json::<sonic_rs::Value>(bytes)
                .ok()
                .map(|v| (p.val_range, v))
        }
        "cells" if tree.kind_of(p.val_node) == "array" => {
            fields.cells = Some((p.val_node, p.val_range))
        }
        _ => {}
    }
}

type RootExtracted = (
    (i64, (usize, usize)),
    (i64, (usize, usize)),
    ((usize, usize), sonic_rs::Value),
    (u32, (usize, usize)),
);

fn validate_root_fields(
    fields: RootFields,
    path: &ByteString,
) -> Result<RootExtracted, ComposedOutcome> {
    let (Some(major), Some(minor), Some(meta_val), Some(cells_node)) = (
        fields.nbformat,
        fields.nbformat_minor,
        fields.metadata,
        fields.cells,
    ) else {
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            "notebook missing required root fields (nbformat, nbformat_minor, metadata, cells)",
        ));
    };

    if major.0 != 4 || !(0..=5).contains(&minor.0) {
        let msg = format!(
            "unsupported nbformat version {}.{}; expected 4.0 through 4.5",
            major.0, minor.0
        );
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ComposedLanguage,
            &msg,
        ));
    }

    Ok((major, minor, meta_val, cells_node))
}

fn extract_all_cells(
    tree: &ParsedTree,
    c_node: u32,
    source: &[u8],
    minor: i64,
    path: &ByteString,
) -> Result<Vec<ParsedCell>, ComposedOutcome> {
    let cell_nodes = tree
        .children(c_node)
        .into_iter()
        .filter(|&c| tree.kind_of(c) == "object")
        .collect::<Vec<_>>();

    if cell_nodes.len() > MAX_NOTEBOOK_CELLS {
        return Err(notebook_decline(
            path,
            NoticeCode::SyntaxLimit,
            DeclineReason::SizeLimit,
            "cell count exceeds MAX_NOTEBOOK_CELLS",
        ));
    }

    let mut cells = Vec::new();
    let mut seen_ids = HashSet::new();

    for (pos, node) in cell_nodes.into_iter().enumerate() {
        let cell = parse_indexed_cell(tree, node, source, pos, minor, path)?;
        if let Some(id) = &cell.id {
            validate_cell_id(id, pos, &mut seen_ids, path)?;
        }
        cells.push(cell);
    }

    Ok(cells)
}

fn parse_indexed_cell(
    tree: &ParsedTree,
    node: u32,
    source: &[u8],
    pos: usize,
    minor: i64,
    path: &ByteString,
) -> Result<ParsedCell, ComposedOutcome> {
    let cell = parse_cell(tree, node, source).map_err(|r| {
        let msg = format!("cell at position {pos} invalid or holds duplicate keys");
        notebook_decline(path, NoticeCode::NotebookStructureDeclined, r, &msg)
    })?;

    if minor == 5 && cell.id.is_none() {
        let msg = format!("cell at position {pos} missing required id in nbformat v4.5");
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            &msg,
        ));
    }

    Ok(cell)
}

fn validate_cell_id(
    id: &str,
    pos: usize,
    seen_ids: &mut HashSet<String>,
    path: &ByteString,
) -> Result<(), ComposedOutcome> {
    if !is_valid_cell_id(id) {
        let msg = format!("cell at position {pos} has invalid id '{id}'");
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::ParseFailed,
            &msg,
        ));
    }
    if !seen_ids.insert(id.to_owned()) {
        let msg = format!("duplicate cell id '{id}' at position {pos}");
        return Err(notebook_decline(
            path,
            NoticeCode::NotebookStructureDeclined,
            DeclineReason::DuplicateKey,
            &msg,
        ));
    }
    Ok(())
}

fn notebook_decline(
    path: &ByteString,
    code: NoticeCode,
    reason: DeclineReason,
    detail: &str,
) -> ComposedOutcome {
    let mut collector = NoticeCollector::new();
    if let Ok(notice) = MergeNotice::new(path.clone(), None, Language::Notebook.id(), code, detail)
    {
        collector.record(notice);
    }
    ComposedOutcome::Declined {
        reason,
        notices: collector.finish(),
    }
}

#[derive(Default)]
struct CellFields {
    cell_type: Option<String>,
    id: Option<String>,
    metadata: Option<(usize, usize, sonic_rs::Value)>,
    source: Option<(usize, usize, DecodedSource)>,
    outputs: Option<(usize, usize, sonic_rs::Value)>,
    execution_count: Option<(usize, usize, sonic_rs::Value)>,
}

impl CellFields {
    fn into_cell(self, byte_range: (usize, usize)) -> Result<ParsedCell, DeclineReason> {
        let (Some(ctype), Some(meta), Some(src)) = (self.cell_type, self.metadata, self.source)
        else {
            return Err(DeclineReason::ParseFailed);
        };
        Ok(ParsedCell {
            byte_range,
            cell_type: ctype,
            id: self.id,
            metadata_val_range: (meta.0, meta.1),
            metadata_value: meta.2,
            source: src.2,
            source_val_range: (src.0, src.1),
            outputs_val_range: self.outputs.as_ref().map(|o| (o.0, o.1)),
            outputs_value: self.outputs.map(|o| o.2),
            execution_count_val_range: self.execution_count.as_ref().map(|e| (e.0, e.1)),
            execution_count_value: self.execution_count.map(|e| e.2),
        })
    }
}

fn parse_cell(
    tree: &ParsedTree,
    cell_node: u32,
    source: &[u8],
) -> Result<ParsedCell, DeclineReason> {
    let cell_rec = tree.get(cell_node).ok_or(DeclineReason::ParseFailed)?;
    let byte_range = (
        usize::try_from(cell_rec.start).map_err(|_| DeclineReason::ParseFailed)?,
        usize::try_from(cell_rec.end).map_err(|_| DeclineReason::ParseFailed)?,
    );

    let pairs = parse_object_pairs(tree, cell_node, source)?;
    let mut fields = CellFields::default();

    for p in pairs {
        extract_cell_field(tree, &p, source, &mut fields)?;
    }

    fields.into_cell(byte_range)
}

fn extract_cell_field(
    tree: &ParsedTree,
    p: &ParsedPair,
    source: &[u8],
    fields: &mut CellFields,
) -> Result<(), DeclineReason> {
    let bytes = &source[p.val_range.0..p.val_range.1];
    match p.key.as_str() {
        "cell_type" => {
            fields.cell_type = decode_json::<String>(bytes).ok();
        }
        "id" => {
            fields.id = decode_json::<String>(bytes).ok();
        }
        "metadata" => {
            let val =
                decode_json::<sonic_rs::Value>(bytes).map_err(|_| DeclineReason::ParseFailed)?;
            fields.metadata = Some((p.val_range.0, p.val_range.1, val));
        }
        "source" => {
            let decoded = decode_cell_source(tree, p.val_node, bytes)?;
            fields.source = Some((p.val_range.0, p.val_range.1, decoded));
        }
        "outputs" => {
            let val = decode_json::<sonic_rs::Value>(bytes).ok();
            fields.outputs = val.map(|v| (p.val_range.0, p.val_range.1, v));
        }
        "execution_count" => {
            let val = decode_json::<sonic_rs::Value>(bytes).ok();
            fields.execution_count = val.map(|v| (p.val_range.0, p.val_range.1, v));
        }
        _ => {}
    }
    Ok(())
}

fn decode_cell_source(
    tree: &ParsedTree,
    val_node: u32,
    bytes: &[u8],
) -> Result<DecodedSource, DeclineReason> {
    match tree.kind_of(val_node) {
        "string" => {
            let text = decode_json::<String>(bytes).map_err(|_| DeclineReason::ParseFailed)?;
            Ok(DecodedSource {
                text,
                kind: SourceKind::String,
            })
        }
        "array" => {
            let list = decode_json::<Vec<String>>(bytes).map_err(|_| DeclineReason::ParseFailed)?;
            Ok(DecodedSource {
                text: list.join(""),
                kind: SourceKind::List,
            })
        }
        _ => Err(DeclineReason::ParseFailed),
    }
}

struct ParsedPair {
    key: String,
    val_node: u32,
    val_range: (usize, usize),
}

fn parse_object_pairs(
    tree: &ParsedTree,
    obj_node: u32,
    source: &[u8],
) -> Result<Vec<ParsedPair>, DeclineReason> {
    let mut pairs = Vec::new();
    let mut seen_keys = HashSet::new();

    for child in tree.children(obj_node) {
        if tree.kind_of(child) != "pair" {
            continue;
        }
        let pair = parse_single_pair(tree, child, source)?;
        if !seen_keys.insert(pair.key.clone()) {
            return Err(DeclineReason::DuplicateKey);
        }
        pairs.push(pair);
    }

    Ok(pairs)
}

fn parse_single_pair(
    tree: &ParsedTree,
    pair_node: u32,
    source: &[u8],
) -> Result<ParsedPair, DeclineReason> {
    let key_node = tree
        .child_with_field(pair_node, "key")
        .or_else(|| tree.named_children(pair_node).first().copied())
        .ok_or(DeclineReason::ParseFailed)?;
    let val_node = tree
        .child_with_field(pair_node, "value")
        .or_else(|| tree.named_children(pair_node).get(1).copied())
        .ok_or(DeclineReason::ParseFailed)?;

    let key_rec = tree.get(key_node).ok_or(DeclineReason::ParseFailed)?;
    let val_rec = tree.get(val_node).ok_or(DeclineReason::ParseFailed)?;

    let key_start = usize::try_from(key_rec.start).map_err(|_| DeclineReason::ParseFailed)?;
    let key_end = usize::try_from(key_rec.end).map_err(|_| DeclineReason::ParseFailed)?;
    let val_start = usize::try_from(val_rec.start).map_err(|_| DeclineReason::ParseFailed)?;
    let val_end = usize::try_from(val_rec.end).map_err(|_| DeclineReason::ParseFailed)?;

    let key_bytes = &source[key_start..key_end];
    let key_str = decode_json::<String>(key_bytes).map_err(|_| DeclineReason::ParseFailed)?;

    Ok(ParsedPair {
        key: key_str,
        val_node,
        val_range: (val_start, val_end),
    })
}

fn find_root_object(tree: &ParsedTree) -> Option<u32> {
    if tree.is_empty() {
        return None;
    }
    if tree.kind_of(0) == "object" {
        return Some(0);
    }
    tree.named_children(0)
        .into_iter()
        .find(|&c| tree.kind_of(c) == "object")
}

fn is_valid_cell_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn raw_language_name(metadata: &sonic_rs::Value) -> Option<String> {
    if let Some(name) = metadata
        .get("language_info")
        .and_then(|v| v.get("name"))
        .and_then(|n| n.as_str())
    {
        return Some(name.to_owned());
    }
    metadata
        .get("kernelspec")
        .and_then(|v| v.get("language"))
        .and_then(|l| l.as_str())
        .map(ToOwned::to_owned)
}

enum AlignedCandidate<'a> {
    InsertedOurs(&'a ParsedCell),
    InsertedTheirs(&'a ParsedCell),
    CoalescedInsert(&'a ParsedCell),
    Matched {
        base: &'a ParsedCell,
        ours: &'a ParsedCell,
        theirs: &'a ParsedCell,
    },
}

fn align_cells<'a>(
    base: &'a ParsedNotebook,
    ours: &'a ParsedNotebook,
    theirs: &'a ParsedNotebook,
    request: &ComposedRequest<'_>,
) -> Result<Vec<AlignedCandidate<'a>>, ComposedOutcome> {
    let all_have_ids = base.cells.iter().all(|c| c.id.is_some())
        && ours.cells.iter().all(|c| c.id.is_some())
        && theirs.cells.iter().all(|c| c.id.is_some());

    if all_have_ids {
        align_by_id(base, ours, theirs, request)
    } else {
        align_by_anchors(base, ours, theirs, request)
    }
}

fn align_by_id<'a>(
    base: &'a ParsedNotebook,
    ours: &'a ParsedNotebook,
    theirs: &'a ParsedNotebook,
    request: &ComposedRequest<'_>,
) -> Result<Vec<AlignedCandidate<'a>>, ComposedOutcome> {
    let mut base_id_map = HashMap::new();
    for (i, c) in base.cells.iter().enumerate() {
        if let Some(id) = &c.id {
            base_id_map.insert(id.as_str(), i);
        }
    }

    let mut ours_id_map = HashMap::new();
    for (i, c) in ours.cells.iter().enumerate() {
        if let Some(id) = &c.id {
            ours_id_map.insert(id.as_str(), i);
        }
    }

    let mut theirs_id_map = HashMap::new();
    for (i, c) in theirs.cells.iter().enumerate() {
        if let Some(id) = &c.id {
            theirs_id_map.insert(id.as_str(), i);
        }
    }

    check_new_id_collisions(
        &ours.cells,
        &base_id_map,
        &theirs_id_map,
        &theirs.cells,
        request,
    )?;

    let ours_base_indices: Vec<usize> = ours
        .cells
        .iter()
        .filter_map(|c| c.id.as_deref().and_then(|id| base_id_map.get(id)))
        .copied()
        .collect();
    if !is_strictly_increasing(&ours_base_indices) {
        return Err(conflict_outcome());
    }

    let theirs_base_indices: Vec<usize> = theirs
        .cells
        .iter()
        .filter_map(|c| c.id.as_deref().and_then(|id| base_id_map.get(id)))
        .copied()
        .collect();
    if !is_strictly_increasing(&theirs_base_indices) {
        return Err(conflict_outcome());
    }

    let n = base.cells.len();
    let ours_gaps = partition_into_gaps(&ours.cells, &base_id_map, n);
    let theirs_gaps = partition_into_gaps(&theirs.cells, &base_id_map, n);

    check_gap_collisions(&ours_gaps, &theirs_gaps, request)?;

    assemble_id_aligned_candidates(
        base,
        &ours.cells,
        &theirs.cells,
        &ours_id_map,
        &theirs_id_map,
        &ours_gaps,
        &theirs_gaps,
    )
}

fn check_new_id_collisions(
    ours_cells: &[ParsedCell],
    base_id_map: &HashMap<&str, usize>,
    theirs_id_map: &HashMap<&str, usize>,
    theirs_cells: &[ParsedCell],
    request: &ComposedRequest<'_>,
) -> Result<(), ComposedOutcome> {
    for cell in ours_cells {
        let Some(id) = &cell.id else { continue };
        let has_base = base_id_map.contains_key(id.as_str());
        let Some(&theirs_idx) = theirs_id_map.get(id.as_str()) else {
            continue;
        };
        if !has_base && !cells_byte_equal(cell, &theirs_cells[theirs_idx], request) {
            return Err(conflict_outcome());
        }
    }
    Ok(())
}

fn cells_byte_equal(a: &ParsedCell, b: &ParsedCell, req: &ComposedRequest<'_>) -> bool {
    req.ours[a.byte_range.0..a.byte_range.1] == req.theirs[b.byte_range.0..b.byte_range.1]
}

fn partition_into_gaps<'a>(
    cells: &'a [ParsedCell],
    base_id_map: &HashMap<&str, usize>,
    n: usize,
) -> Vec<Vec<&'a ParsedCell>> {
    let mut gaps = vec![Vec::new(); n + 1];
    let mut current_gap = 0;
    for cell in cells {
        let Some(id) = &cell.id else { continue };
        match base_id_map.get(id.as_str()) {
            Some(&base_idx) => current_gap = base_idx + 1,
            None => gaps[current_gap].push(cell),
        }
    }
    gaps
}

fn check_gap_collisions(
    ours_gaps: &[Vec<&ParsedCell>],
    theirs_gaps: &[Vec<&ParsedCell>],
    request: &ComposedRequest<'_>,
) -> Result<(), ComposedOutcome> {
    for (og, tg) in ours_gaps.iter().zip(theirs_gaps) {
        if og.is_empty() || tg.is_empty() {
            continue;
        }
        if og.len() != tg.len() || !gaps_byte_identical(og, tg, request) {
            return Err(conflict_outcome());
        }
    }
    Ok(())
}

fn gaps_byte_identical(
    og: &[&ParsedCell],
    tg: &[&ParsedCell],
    request: &ComposedRequest<'_>,
) -> bool {
    og.iter().zip(tg.iter()).all(|(o, t)| {
        request.ours[o.byte_range.0..o.byte_range.1]
            == request.theirs[t.byte_range.0..t.byte_range.1]
    })
}

fn assemble_id_aligned_candidates<'a>(
    base: &'a ParsedNotebook,
    ours_cells: &'a [ParsedCell],
    theirs_cells: &'a [ParsedCell],
    ours_id_map: &HashMap<&str, usize>,
    theirs_id_map: &HashMap<&str, usize>,
    ours_gaps: &[Vec<&'a ParsedCell>],
    theirs_gaps: &[Vec<&'a ParsedCell>],
) -> Result<Vec<AlignedCandidate<'a>>, ComposedOutcome> {
    let mut candidates = Vec::new();
    for g in 0..=base.cells.len() {
        collect_gap_insertions(
            ours_gaps[g].as_slice(),
            theirs_gaps[g].as_slice(),
            &mut candidates,
        );
        if g < base.cells.len() {
            let b = &base.cells[g];
            let bid = b.id.as_deref().unwrap_or("");
            let in_ours = ours_id_map.get(bid).map(|&i| &ours_cells[i]);
            let in_theirs = theirs_id_map.get(bid).map(|&i| &theirs_cells[i]);
            candidates.extend(resolve_single_base_cell(b, in_ours, in_theirs)?);
        }
    }
    Ok(candidates)
}

fn collect_gap_insertions<'a>(
    og: &[&'a ParsedCell],
    tg: &[&'a ParsedCell],
    candidates: &mut Vec<AlignedCandidate<'a>>,
) {
    if !og.is_empty() && !tg.is_empty() {
        for o in og {
            candidates.push(AlignedCandidate::CoalescedInsert(o));
        }
    } else if !og.is_empty() {
        for o in og {
            candidates.push(AlignedCandidate::InsertedOurs(o));
        }
    } else if !tg.is_empty() {
        for t in tg {
            candidates.push(AlignedCandidate::InsertedTheirs(t));
        }
    }
}

fn resolve_single_base_cell<'a>(
    b: &'a ParsedCell,
    in_ours: Option<&'a ParsedCell>,
    in_theirs: Option<&'a ParsedCell>,
) -> Result<Option<AlignedCandidate<'a>>, ComposedOutcome> {
    match (in_ours, in_theirs) {
        (None, None) => Ok(None),
        (Some(o), None) => check_deleted_on_theirs(o, b),
        (None, Some(t)) => check_deleted_on_ours(t, b),
        (Some(o), Some(t)) => check_both_kept(b, o, t),
    }
}

fn check_deleted_on_theirs<'a>(
    o: &'a ParsedCell,
    b: &'a ParsedCell,
) -> Result<Option<AlignedCandidate<'a>>, ComposedOutcome> {
    if cell_differs_from_base(o, b) {
        Err(conflict_outcome())
    } else {
        Ok(None)
    }
}

fn check_deleted_on_ours<'a>(
    t: &'a ParsedCell,
    b: &'a ParsedCell,
) -> Result<Option<AlignedCandidate<'a>>, ComposedOutcome> {
    if cell_differs_from_base(t, b) {
        Err(conflict_outcome())
    } else {
        Ok(None)
    }
}

fn check_both_kept<'a>(
    b: &'a ParsedCell,
    o: &'a ParsedCell,
    t: &'a ParsedCell,
) -> Result<Option<AlignedCandidate<'a>>, ComposedOutcome> {
    if o.cell_type != t.cell_type && o.cell_type != b.cell_type && t.cell_type != b.cell_type {
        return Err(conflict_outcome());
    }
    Ok(Some(AlignedCandidate::Matched {
        base: b,
        ours: o,
        theirs: t,
    }))
}

fn align_by_anchors<'a>(
    base: &'a ParsedNotebook,
    ours: &'a ParsedNotebook,
    theirs: &'a ParsedNotebook,
    request: &ComposedRequest<'_>,
) -> Result<Vec<AlignedCandidate<'a>>, ComposedOutcome> {
    let candidate_anchors = find_unique_anchors(&base.cells, &ours.cells, &theirs.cells);

    let ours_anchor_order: Vec<usize> = candidate_anchors.iter().map(|a| a.1).collect();
    let theirs_anchor_order: Vec<usize> = candidate_anchors.iter().map(|a| a.2).collect();
    if !is_strictly_increasing(&ours_anchor_order) || !is_strictly_increasing(&theirs_anchor_order)
    {
        return Err(conflict_outcome());
    }

    let mut candidates = Vec::new();
    let mut prev_b = 0;
    let mut prev_o = 0;
    let mut prev_t = 0;

    for &(b_idx, o_idx, t_idx) in &candidate_anchors {
        let b_slice = &base.cells[prev_b..b_idx];
        let o_slice = &ours.cells[prev_o..o_idx];
        let t_slice = &theirs.cells[prev_t..t_idx];

        process_anchor_interval(b_slice, o_slice, t_slice, request, &mut candidates)?;

        candidates.push(matched_anchor(base, ours, theirs, b_idx, o_idx, t_idx));
        prev_b = b_idx + 1;
        prev_o = o_idx + 1;
        prev_t = t_idx + 1;
    }

    let b_slice = &base.cells[prev_b..];
    let o_slice = &ours.cells[prev_o..];
    let t_slice = &theirs.cells[prev_t..];

    process_anchor_interval(b_slice, o_slice, t_slice, request, &mut candidates)?;

    Ok(candidates)
}

fn matched_anchor<'a>(
    base: &'a ParsedNotebook,
    ours: &'a ParsedNotebook,
    theirs: &'a ParsedNotebook,
    b: usize,
    o: usize,
    t: usize,
) -> AlignedCandidate<'a> {
    AlignedCandidate::Matched {
        base: &base.cells[b],
        ours: &ours.cells[o],
        theirs: &theirs.cells[t],
    }
}
fn matched_slice<'a>(
    b: &'a [ParsedCell],
    o: &'a [ParsedCell],
    t: &'a [ParsedCell],
) -> AlignedCandidate<'a> {
    AlignedCandidate::Matched {
        base: &b[0],
        ours: &o[0],
        theirs: &t[0],
    }
}
fn find_unique_anchors(
    base: &[ParsedCell],
    ours: &[ParsedCell],
    theirs: &[ParsedCell],
) -> Vec<(usize, usize, usize)> {
    let mut base_counts = HashMap::new();
    for c in base {
        let key = (&c.cell_type, c.source.text.as_str());
        *base_counts.entry(key).or_insert(0_usize) += 1;
    }

    let mut ours_counts = HashMap::new();
    for c in ours {
        let key = (&c.cell_type, c.source.text.as_str());
        *ours_counts.entry(key).or_insert(0_usize) += 1;
    }

    let mut theirs_counts = HashMap::new();
    for c in theirs {
        let key = (&c.cell_type, c.source.text.as_str());
        *theirs_counts.entry(key).or_insert(0_usize) += 1;
    }

    let mut candidate_anchors = Vec::new();
    for (b_idx, c) in base.iter().enumerate() {
        let key = (&c.cell_type, c.source.text.as_str());
        if base_counts.get(&key) != Some(&1)
            || ours_counts.get(&key) != Some(&1)
            || theirs_counts.get(&key) != Some(&1)
        {
            continue;
        }
        let o_idx = ours
            .iter()
            .position(|oc| (&oc.cell_type, oc.source.text.as_str()) == key)
            .unwrap_or(0);
        let t_idx = theirs
            .iter()
            .position(|tc| (&tc.cell_type, tc.source.text.as_str()) == key)
            .unwrap_or(0);
        candidate_anchors.push((b_idx, o_idx, t_idx));
    }
    candidate_anchors
}

fn process_anchor_interval<'a>(
    b_slice: &'a [ParsedCell],
    o_slice: &'a [ParsedCell],
    t_slice: &'a [ParsedCell],
    request: &ComposedRequest<'_>,
    candidates: &mut Vec<AlignedCandidate<'a>>,
) -> Result<(), ComposedOutcome> {
    match (b_slice.len(), o_slice.len(), t_slice.len()) {
        (0, 0, 0) => Ok(()),
        (1, 1, 1) => {
            candidates.push(matched_slice(b_slice, o_slice, t_slice));
            Ok(())
        }
        (1, 0, 1) => handle_interval_deleted_on_ours(&b_slice[0], &t_slice[0]),
        (1, 1, 0) => handle_interval_deleted_on_theirs(&b_slice[0], &o_slice[0]),
        (1, 0, 0) => Ok(()),
        (0, n_o, 0) if n_o > 0 => {
            candidates.extend(o_slice.iter().map(AlignedCandidate::InsertedOurs));
            Ok(())
        }
        (0, 0, n_t) if n_t > 0 => {
            candidates.extend(t_slice.iter().map(AlignedCandidate::InsertedTheirs));
            Ok(())
        }
        (0, n_o, n_t) if n_o > 0 && n_t > 0 => {
            handle_interval_coalesce(o_slice, t_slice, request, candidates)
        }
        _ => Err(conflict_outcome()),
    }
}

fn handle_interval_deleted_on_ours(b: &ParsedCell, t: &ParsedCell) -> Result<(), ComposedOutcome> {
    if cell_differs_from_base(t, b) {
        Err(conflict_outcome())
    } else {
        Ok(())
    }
}

fn handle_interval_deleted_on_theirs(
    b: &ParsedCell,
    o: &ParsedCell,
) -> Result<(), ComposedOutcome> {
    if cell_differs_from_base(o, b) {
        Err(conflict_outcome())
    } else {
        Ok(())
    }
}

fn handle_interval_coalesce<'a>(
    o_slice: &'a [ParsedCell],
    t_slice: &'a [ParsedCell],
    request: &ComposedRequest<'_>,
    candidates: &mut Vec<AlignedCandidate<'a>>,
) -> Result<(), ComposedOutcome> {
    if o_slice.len() != t_slice.len() {
        return Err(conflict_outcome());
    }
    let all_identical = o_slice.iter().zip(t_slice.iter()).all(|(o, t)| {
        request.ours[o.byte_range.0..o.byte_range.1]
            == request.theirs[t.byte_range.0..t.byte_range.1]
    });
    if !all_identical {
        return Err(conflict_outcome());
    }
    candidates.extend(o_slice.iter().map(AlignedCandidate::CoalescedInsert));
    Ok(())
}

fn cell_differs_from_base(cell: &ParsedCell, base: &ParsedCell) -> bool {
    cell.cell_type != base.cell_type
        || cell.source.text != base.source.text
        || cell.metadata_value != base.metadata_value
}

fn is_strictly_increasing(slice: &[usize]) -> bool {
    for i in 1..slice.len() {
        if slice[i] <= slice[i - 1] {
            return false;
        }
    }
    true
}

enum CellMergeOutcome {
    Merged {
        bytes: Vec<u8>,
        #[expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )]
        cleared: bool,
    },
    Conflict,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OutputPolicy {
    Preserve,
    Clear,
}

fn merge_candidate_cell(
    candidate: &AlignedCandidate<'_>,
    position: usize,
    code_lang: Option<Language>,
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    collector: &mut NoticeCollector,
) -> Result<CellMergeOutcome, SyntaxError> {
    cancel.check()?;
    match candidate {
        AlignedCandidate::InsertedOurs(cell) => Ok(merge_inserted_cell(
            request.ours,
            cell,
            position,
            request,
            collector,
            NoticeInput::Ours,
        )),
        AlignedCandidate::InsertedTheirs(cell) => Ok(merge_inserted_cell(
            request.theirs,
            cell,
            position,
            request,
            collector,
            NoticeInput::Theirs,
        )),
        AlignedCandidate::CoalescedInsert(cell) => Ok(merge_inserted_cell(
            request.ours,
            cell,
            position,
            request,
            collector,
            NoticeInput::Ours,
        )),
        AlignedCandidate::Matched { base, ours, theirs } => {
            let cells = MatchedCells { base, ours, theirs };
            let ctx = CellMergeCtx {
                request,
                registry,
                cancel,
                collector,
            };
            merge_matched_cell(&cells, position, code_lang, ctx)
        }
    }
}

fn merge_inserted_cell(
    source: &[u8],
    cell: &ParsedCell,
    position: usize,
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
    input: NoticeInput,
) -> CellMergeOutcome {
    let policy = if cell.cell_type == "code" {
        OutputPolicy::Clear
    } else {
        OutputPolicy::Preserve
    };
    if policy == OutputPolicy::Clear {
        record_output_cleared_notice(cell, None, position, request, collector, input);
    }
    let bytes = emit_patched_cell(source, cell, None, None, policy);
    CellMergeOutcome::Merged {
        bytes,
        cleared: policy == OutputPolicy::Clear,
    }
}

/// The three sides of one matched notebook cell.
#[derive(Clone, Copy)]
struct MatchedCells<'c> {
    base: &'c ParsedCell,
    ours: &'c ParsedCell,
    theirs: &'c ParsedCell,
}

/// Shared driver context for one matched-cell merge.
struct CellMergeCtx<'a> {
    request: &'a ComposedRequest<'a>,
    registry: &'a GrammarRegistry<'a>,
    cancel: &'a Cancel,
    collector: &'a mut NoticeCollector,
}

fn merge_matched_cell(
    cells: &MatchedCells<'_>,
    position: usize,
    code_lang: Option<Language>,
    ctx: CellMergeCtx<'_>,
) -> Result<CellMergeOutcome, SyntaxError> {
    let MatchedCells { base, ours, theirs } = *cells;
    let CellMergeCtx {
        request,
        registry,
        cancel,
        collector,
    } = ctx;
    let Some(cell_type) = resolve_cell_type(base, ours, theirs) else {
        return Ok(CellMergeOutcome::Conflict);
    };

    let Some(merged_source_text) =
        resolve_cell_source_text(cells, &cell_type, code_lang, request, registry, cancel)?
    else {
        return Ok(CellMergeOutcome::Conflict);
    };

    let Some(merged_meta_val) = resolve_cell_metadata_val(base, ours, theirs) else {
        return Ok(CellMergeOutcome::Conflict);
    };

    let policy = determine_output_policy(base, &cell_type, &merged_source_text);
    if policy == OutputPolicy::Clear {
        record_output_cleared_notice(
            ours,
            Some(base),
            position,
            request,
            collector,
            NoticeInput::Base,
        );
    } else if cell_type == "code" && !outputs_compatible(base, ours, theirs) {
        return Ok(CellMergeOutcome::Conflict);
    }

    let (donor_bytes, donor_cell) = select_donor_cell(base, ours, theirs, request);

    let new_source_bytes = determine_replacement_source_bytes(
        &merged_source_text,
        donor_cell,
        ours,
        theirs,
        base,
        request,
    );

    let new_meta_bytes =
        determine_replacement_metadata_bytes(&merged_meta_val, donor_cell, ours, theirs, request);

    let bytes = emit_patched_cell(
        donor_bytes,
        donor_cell,
        new_source_bytes.as_deref(),
        new_meta_bytes.as_deref(),
        policy,
    );

    Ok(CellMergeOutcome::Merged {
        bytes,
        cleared: policy == OutputPolicy::Clear,
    })
}

fn determine_replacement_source_bytes(
    merged_src: &str,
    donor: &ParsedCell,
    ours: &ParsedCell,
    theirs: &ParsedCell,
    base: &ParsedCell,
    request: &ComposedRequest<'_>,
) -> Option<Vec<u8>> {
    if donor.source.text == merged_src {
        return None;
    }
    if merged_src == ours.source.text {
        return Some(request.ours[ours.source_val_range.0..ours.source_val_range.1].to_vec());
    }
    if merged_src == theirs.source.text {
        return Some(request.theirs[theirs.source_val_range.0..theirs.source_val_range.1].to_vec());
    }
    Some(format_source_json(merged_src, base.source.kind))
}

fn determine_replacement_metadata_bytes(
    merged_meta: &sonic_rs::Value,
    donor: &ParsedCell,
    ours: &ParsedCell,
    theirs: &ParsedCell,
    request: &ComposedRequest<'_>,
) -> Option<Vec<u8>> {
    if donor.metadata_value == *merged_meta {
        return None;
    }
    if *merged_meta == ours.metadata_value {
        return Some(request.ours[ours.metadata_val_range.0..ours.metadata_val_range.1].to_vec());
    }
    if *merged_meta == theirs.metadata_value {
        return Some(
            request.theirs[theirs.metadata_val_range.0..theirs.metadata_val_range.1].to_vec(),
        );
    }
    sonic_rs::to_vec(merged_meta).ok()
}

fn resolve_cell_type(base: &ParsedCell, ours: &ParsedCell, theirs: &ParsedCell) -> Option<String> {
    if ours.cell_type == theirs.cell_type {
        return Some(ours.cell_type.clone());
    }
    if ours.cell_type == base.cell_type {
        return Some(theirs.cell_type.clone());
    }
    if theirs.cell_type == base.cell_type {
        return Some(ours.cell_type.clone());
    }
    None
}

fn determine_output_policy(base: &ParsedCell, cell_type: &str, merged_src: &str) -> OutputPolicy {
    if cell_type != "code" {
        return OutputPolicy::Preserve;
    }
    if base.cell_type != "code" || merged_src != base.source.text {
        OutputPolicy::Clear
    } else {
        OutputPolicy::Preserve
    }
}

fn outputs_compatible(base: &ParsedCell, ours: &ParsedCell, theirs: &ParsedCell) -> bool {
    three_way_json_compatible(
        &base.outputs_value,
        &ours.outputs_value,
        &theirs.outputs_value,
    ) && three_way_json_compatible(
        &base.execution_count_value,
        &ours.execution_count_value,
        &theirs.execution_count_value,
    )
}

fn select_donor_cell<'a>(
    base: &'a ParsedCell,
    ours: &'a ParsedCell,
    theirs: &'a ParsedCell,
    request: &'a ComposedRequest<'_>,
) -> (&'a [u8], &'a ParsedCell) {
    if cell_differs_from_base(theirs, base) && !cell_differs_from_base(ours, base) {
        (request.theirs, theirs)
    } else {
        (request.ours, ours)
    }
}

fn resolve_cell_source_text(
    cells: &MatchedCells<'_>,
    cell_type: &str,
    code_lang: Option<Language>,
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<Option<String>, SyntaxError> {
    let MatchedCells { base, ours, theirs } = *cells;
    if ours.source.text == base.source.text && theirs.source.text == base.source.text {
        return Ok(Some(base.source.text.clone()));
    }
    if ours.source.text == base.source.text {
        return Ok(Some(theirs.source.text.clone()));
    }
    if theirs.source.text == base.source.text {
        return Ok(Some(ours.source.text.clone()));
    }
    if ours.source.text == theirs.source.text {
        return Ok(Some(ours.source.text.clone()));
    }

    match cell_type {
        "markdown" => merge_markdown_source(
            request,
            &base.source.text,
            &ours.source.text,
            &theirs.source.text,
            registry,
            cancel,
        ),
        "code" => merge_code_source(
            request,
            &base.source.text,
            &ours.source.text,
            &theirs.source.text,
            code_lang,
            registry,
            cancel,
        ),
        _ => Ok(merge_lines(
            &base.source.text,
            &ours.source.text,
            &theirs.source.text,
        )),
    }
}

fn resolve_cell_metadata_val(
    base: &ParsedCell,
    ours: &ParsedCell,
    theirs: &ParsedCell,
) -> Option<sonic_rs::Value> {
    if ours.metadata_value == base.metadata_value && theirs.metadata_value == base.metadata_value {
        return Some(base.metadata_value.clone());
    }
    if ours.metadata_value == base.metadata_value {
        return Some(theirs.metadata_value.clone());
    }
    if theirs.metadata_value == base.metadata_value {
        return Some(ours.metadata_value.clone());
    }
    if ours.metadata_value == theirs.metadata_value {
        return Some(ours.metadata_value.clone());
    }
    merge_json_values(
        &base.metadata_value,
        &ours.metadata_value,
        &theirs.metadata_value,
    )
}

fn three_way_json_compatible(
    base: &Option<sonic_rs::Value>,
    ours: &Option<sonic_rs::Value>,
    theirs: &Option<sonic_rs::Value>,
) -> bool {
    if ours == base || theirs == base || ours == theirs {
        return true;
    }
    match (base, ours, theirs) {
        (Some(b), Some(o), Some(t)) => merge_json_values(b, o, t).is_some(),
        _ => false,
    }
}

fn record_output_cleared_notice(
    cell: &ParsedCell,
    base: Option<&ParsedCell>,
    position: usize,
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
    input: NoticeInput,
) {
    let detail = if let Some(id) = &cell.id {
        format!("cell '{id}': outputs cleared and execution_count set to null")
    } else {
        format!("cell at position {position}: outputs cleared and execution_count set to null")
    };

    let region = if let Some(b) = base {
        let start = u64::try_from(b.byte_range.0).unwrap_or(0);
        let end = u64::try_from(b.byte_range.1).unwrap_or(0);
        NoticeRegion::new(NoticeInput::Base, start, end).ok()
    } else {
        let start = u64::try_from(cell.byte_range.0).unwrap_or(0);
        let end = u64::try_from(cell.byte_range.1).unwrap_or(0);
        NoticeRegion::new(input, start, end).ok()
    };

    if let Ok(notice) = MergeNotice::new(
        request.path.clone(),
        region,
        Language::Notebook.id(),
        NoticeCode::NotebookOutputsCleared,
        detail,
    ) {
        collector.record(notice);
    }
}

fn emit_patched_cell(
    donor_source: &[u8],
    cell: &ParsedCell,
    new_source_bytes: Option<&[u8]>,
    new_metadata_bytes: Option<&[u8]>,
    policy: OutputPolicy,
) -> Vec<u8> {
    if new_source_bytes.is_none()
        && new_metadata_bytes.is_none()
        && policy == OutputPolicy::Preserve
    {
        return donor_source[cell.byte_range.0..cell.byte_range.1].to_vec();
    }

    let mut replacements = Vec::new();

    if let Some(src_bytes) = new_source_bytes {
        replacements.push((
            cell.source_val_range.0,
            cell.source_val_range.1,
            src_bytes.to_vec(),
        ));
    }

    if let Some(meta_bytes) = new_metadata_bytes {
        replacements.push((
            cell.metadata_val_range.0,
            cell.metadata_val_range.1,
            meta_bytes.to_vec(),
        ));
    }

    if policy == OutputPolicy::Clear {
        if let Some(out_range) = cell.outputs_val_range {
            replacements.push((out_range.0, out_range.1, b"[]".to_vec()));
        }
        if let Some(exec_range) = cell.execution_count_val_range {
            replacements.push((exec_range.0, exec_range.1, b"null".to_vec()));
        }
    }

    replacements.sort_by_key(|r| r.0);

    let mut out = Vec::new();
    let mut cursor = cell.byte_range.0;

    for (start, end, repl) in replacements {
        if start >= cursor && end <= cell.byte_range.1 {
            out.extend_from_slice(&donor_source[cursor..start]);
            out.extend_from_slice(&repl);
            cursor = end;
        }
    }
    out.extend_from_slice(&donor_source[cursor..cell.byte_range.1]);

    if policy == OutputPolicy::Clear
        && cell.outputs_val_range.is_none()
        && let Some(closing_brace) = out.iter().rposition(|&b| b == b'}')
    {
        let mut inserted = Vec::new();
        inserted.extend_from_slice(&out[..closing_brace]);
        inserted.extend_from_slice(
            b",\n      \"outputs\": [],\n      \"execution_count\": null\n    }",
        );
        inserted.extend_from_slice(&out[closing_brace + 1..]);
        out = inserted;
    }

    out
}

fn format_source_json(text: &str, kind: SourceKind) -> Vec<u8> {
    match kind {
        SourceKind::String => sonic_rs::to_vec(text).unwrap_or_else(|_| b"\"\"".to_vec()),
        SourceKind::List => format_source_as_list(text),
    }
}

fn format_source_as_list(text: &str) -> Vec<u8> {
    let lines = split_lines_retained(text);
    if lines.is_empty() {
        return b"[]".to_vec();
    }
    let mut out = Vec::new();
    out.push(b'[');
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.push(b'\n');
        out.extend_from_slice(b"        ");
        let encoded = sonic_rs::to_vec(line).unwrap_or_else(|_| b"\"\"".to_vec());
        out.extend_from_slice(&encoded);
    }
    out.push(b'\n');
    out.extend_from_slice(b"      ]");
    out
}

fn split_lines_retained(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            lines.push(text[start..=i].to_owned());
            start = i + 1;
        }
    }
    if start < text.len() {
        lines.push(text[start..].to_owned());
    }
    lines
}

fn format_cells_array(
    donor_bytes: &[u8],
    cells_val_range: (usize, usize),
    donor_cells: &[ParsedCell],
    merged_cells_bytes: &[Vec<u8>],
) -> Vec<u8> {
    if merged_cells_bytes.is_empty() {
        return b"[]".to_vec();
    }

    let indent = if !donor_cells.is_empty() {
        let first_start = donor_cells[0].byte_range.0;
        if first_start > cells_val_range.0 + 1 {
            &donor_bytes[cells_val_range.0 + 1..first_start]
        } else {
            b"\n    "
        }
    } else {
        b"\n    "
    };

    let mut out = Vec::new();
    out.push(b'[');
    for (i, cell_bytes) in merged_cells_bytes.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(indent);
        out.extend_from_slice(cell_bytes);
    }
    out.push(b'\n');
    out.extend_from_slice(b"  ]");
    out
}

fn merge_markdown_source(
    req: &ComposedRequest<'_>,
    base_src: &str,
    ours_src: &str,
    theirs_src: &str,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<Option<String>, SyntaxError> {
    cancel.check()?;
    if ours_src == base_src {
        return Ok(Some(theirs_src.to_owned()));
    }
    if theirs_src == base_src {
        return Ok(Some(ours_src.to_owned()));
    }
    if ours_src == theirs_src {
        return Ok(Some(ours_src.to_owned()));
    }

    let md_req = ComposedRequest {
        path: req.path.clone(),
        language: Language::Markdown,
        base: base_src.as_bytes(),
        ours: ours_src.as_bytes(),
        theirs: theirs_src.as_bytes(),
        mode: req.mode,
    };
    let Ok(ComposedOutcome::Clean { bytes, .. }) =
        super::markdown::merge_markdown(&md_req, registry, cancel)
    else {
        return Ok(merge_lines(base_src, ours_src, theirs_src));
    };
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(text)),
        Err(_) => Ok(merge_lines(base_src, ours_src, theirs_src)),
    }
}

fn syntax_merged_text(
    syn_req: &SyntaxRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<Option<String>, SyntaxError> {
    let outcome = merge_triplet(syn_req, registry, cancel)?;
    let crate::merge::syntax::SyntaxOutcome::Merged { bytes, .. } = outcome else {
        return Ok(None);
    };
    Ok(String::from_utf8(bytes).ok())
}
fn merge_code_source(
    req: &ComposedRequest<'_>,
    base_src: &str,
    ours_src: &str,
    theirs_src: &str,
    lang: Option<Language>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<Option<String>, SyntaxError> {
    cancel.check()?;
    if ours_src == base_src {
        return Ok(Some(theirs_src.to_owned()));
    }
    if theirs_src == base_src {
        return Ok(Some(ours_src.to_owned()));
    }
    if ours_src == theirs_src {
        return Ok(Some(ours_src.to_owned()));
    }

    if let Some(language) = lang {
        let syn_req = SyntaxRequest {
            path: req.path.clone(),
            language,
            base: base_src.as_bytes(),
            ours: ours_src.as_bytes(),
            theirs: theirs_src.as_bytes(),
        };
        if let Some(text) = syntax_merged_text(&syn_req, registry, cancel)? {
            return Ok(Some(text));
        }
    }
    Ok(merge_lines(base_src, ours_src, theirs_src))
}

fn merge_lines(base: &str, ours: &str, theirs: &str) -> Option<String> {
    if ours == base {
        return Some(theirs.to_owned());
    }
    if theirs == base {
        return Some(ours.to_owned());
    }
    if ours == theirs {
        return Some(ours.to_owned());
    }

    let base_lines = split_lines_retained(base);
    let ours_lines = split_lines_retained(ours);
    let theirs_lines = split_lines_retained(theirs);

    let lcs_bo = compute_lcs(&base_lines, &ours_lines);
    let lcs_bt = compute_lcs(&base_lines, &theirs_lines);

    let diff_bo = lcs_to_chunks(&base_lines, &ours_lines, &lcs_bo);
    let diff_bt = lcs_to_chunks(&base_lines, &theirs_lines, &lcs_bt);

    merge_line_chunks(&base_lines, &diff_bo, &diff_bt)
}

fn compute_lcs(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return Vec::new();
    }
    let mut dp = vec![vec![0_u32; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            let cost = if a[i] == b[j] {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
            dp[i + 1][j + 1] = cost;
        }
    }
    let mut i = n;
    let mut j = m;
    let mut matches = Vec::new();
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            matches.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    matches.reverse();
    matches
}

struct LineChunk {
    base_start: usize,
    base_end: usize,
    repl: Vec<String>,
}

fn lcs_to_chunks(base: &[String], other: &[String], matches: &[(usize, usize)]) -> Vec<LineChunk> {
    let mut chunks = Vec::new();
    let mut cur_b = 0;
    let mut cur_o = 0;

    for &(m_b, m_o) in matches {
        if m_b > cur_b || m_o > cur_o {
            chunks.push(new_chunk(cur_b, m_b, &other[cur_o..m_o]));
        }
        cur_b = m_b + 1;
        cur_o = m_o + 1;
    }
    if cur_b < base.len() || cur_o < other.len() {
        chunks.push(new_chunk(cur_b, base.len(), &other[cur_o..other.len()]));
    }
    chunks
}

fn new_chunk(start: usize, end: usize, repl: &[String]) -> LineChunk {
    LineChunk {
        base_start: start,
        base_end: end,
        repl: repl.to_vec(),
    }
}
fn finish_line_merge(base: &[String], cursor: usize) -> MergeStep {
    let emitted = if cursor < base.len() {
        base[cursor..].to_vec()
    } else {
        Vec::new()
    };
    MergeStep {
        emitted,
        new_cursor: base.len(),
        advance_o: 0,
        advance_t: 0,
    }
}
struct MergeStep {
    emitted: Vec<String>,
    new_cursor: usize,
    advance_o: usize,
    advance_t: usize,
}

fn step_chunk(
    base: &[String],
    b_cursor: usize,
    start: usize,
    end: usize,
    repl: &[String],
    advance_o: usize,
    advance_t: usize,
) -> MergeStep {
    let mut emitted = Vec::new();
    if start > b_cursor {
        emitted.extend_from_slice(&base[b_cursor..start]);
    }
    emitted.extend_from_slice(repl);
    MergeStep {
        emitted,
        new_cursor: end,
        advance_o,
        advance_t,
    }
}

fn advance_line_merge(
    base: &[String],
    b_cursor: usize,
    next_o: Option<&LineChunk>,
    next_t: Option<&LineChunk>,
) -> Option<MergeStep> {
    match (next_o, next_t) {
        (Some(co), Some(ct))
            if co.base_start == ct.base_start
                && co.base_end == ct.base_end
                && co.repl != ct.repl =>
        {
            None
        }
        (Some(co), Some(ct)) if co.base_start == ct.base_start && co.base_end == ct.base_end => {
            Some(step_chunk(
                base,
                b_cursor,
                co.base_start,
                co.base_end,
                &co.repl,
                1,
                1,
            ))
        }
        (Some(co), Some(ct)) if co.base_end <= ct.base_start => Some(step_chunk(
            base,
            b_cursor,
            co.base_start,
            co.base_end,
            &co.repl,
            1,
            0,
        )),
        (Some(co), Some(ct)) if ct.base_end <= co.base_start => Some(step_chunk(
            base,
            b_cursor,
            ct.base_start,
            ct.base_end,
            &ct.repl,
            0,
            1,
        )),
        (Some(co), None) => Some(step_chunk(
            base,
            b_cursor,
            co.base_start,
            co.base_end,
            &co.repl,
            1,
            0,
        )),
        (None, Some(ct)) => Some(step_chunk(
            base,
            b_cursor,
            ct.base_start,
            ct.base_end,
            &ct.repl,
            0,
            1,
        )),
        (None, None) => Some(finish_line_merge(base, b_cursor)),
        _ => None,
    }
}

fn merge_line_chunks(
    base: &[String],
    chunks_o: &[LineChunk],
    chunks_t: &[LineChunk],
) -> Option<String> {
    let mut out = Vec::new();
    let mut b_cursor = 0;
    let mut idx_o = 0;
    let mut idx_t = 0;

    while b_cursor < base.len() || idx_o < chunks_o.len() || idx_t < chunks_t.len() {
        let step = advance_line_merge(base, b_cursor, chunks_o.get(idx_o), chunks_t.get(idx_t))?;
        out.extend_from_slice(&step.emitted);
        b_cursor = step.new_cursor;
        idx_o += step.advance_o;
        idx_t += step.advance_t;
    }
    Some(out.concat())
}

fn merge_json_values(
    base: &sonic_rs::Value,
    ours: &sonic_rs::Value,
    theirs: &sonic_rs::Value,
) -> Option<sonic_rs::Value> {
    if ours == base {
        return Some(theirs.clone());
    }
    if theirs == base {
        return Some(ours.clone());
    }
    if ours == theirs {
        return Some(ours.clone());
    }

    match (base.as_object(), ours.as_object(), theirs.as_object()) {
        (Some(b_obj), Some(o_obj), Some(t_obj)) => merge_json_objects(b_obj, o_obj, t_obj),
        _ => None,
    }
}

fn merge_json_objects(
    b_obj: &sonic_rs::Object,
    o_obj: &sonic_rs::Object,
    t_obj: &sonic_rs::Object,
) -> Option<sonic_rs::Value> {
    let mut keys_in_order = Vec::new();
    let mut seen = HashSet::new();

    for (k, _) in b_obj.iter().chain(o_obj.iter()).chain(t_obj.iter()) {
        if seen.insert(k) {
            keys_in_order.push(k);
        }
    }

    let mut merged_map = sonic_rs::Object::new();
    for key in keys_in_order {
        let entry = merge_object_entry(b_obj.get(&key), o_obj.get(&key), t_obj.get(&key))?;
        if let Some(val) = entry {
            merged_map.insert(key, val);
        }
    }
    Some(sonic_rs::Value::from(merged_map))
}

fn merge_object_entry(
    b_val: Option<&sonic_rs::Value>,
    o_val: Option<&sonic_rs::Value>,
    t_val: Option<&sonic_rs::Value>,
) -> Option<Option<sonic_rs::Value>> {
    match (b_val, o_val, t_val) {
        (Some(bv), Some(ov), Some(tv)) => merge_json_values(bv, ov, tv).map(Some),
        (None, Some(ov), Some(tv)) if ov == tv => Some(Some(ov.clone())),
        (None, Some(ov), None) => Some(Some(ov.clone())),
        (None, None, Some(tv)) => Some(Some(tv.clone())),
        (Some(bv), None, Some(tv)) if tv == bv => Some(None),
        (Some(bv), Some(ov), None) if ov == bv => Some(None),
        (Some(_), None, None) | (None, None, None) => Some(None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::syntax::treesitter::registry_providers;

    struct TestEnv {
        providers: Vec<Result<crate::merge::syntax::TsGrammar, SyntaxError>>,
    }

    impl TestEnv {
        fn new() -> Self {
            Self {
                providers: registry_providers(),
            }
        }

        fn registry(&self) -> GrammarRegistry<'_> {
            let mut reg = GrammarRegistry::new();
            self.providers.iter().flatten().for_each(|p| reg.insert(p));
            reg
        }
    }

    #[test]
    fn test_edit_source_and_metadata_clears_only_edited_cell() {
        let base = r#"{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 1,
      "id": "c-0",
      "metadata": {},
      "outputs": [
        {
          "output_type": "stream",
          "text": ["base 0\n"]
        }
      ],
      "source": [
        "print('base 0')\n"
      ]
    },
    {
      "cell_type": "code",
      "execution_count": 2,
      "id": "c-1",
      "metadata": {},
      "outputs": [
        {
          "output_type": "stream",
          "text": ["untouched output bytes\n"]
        }
      ],
      "source": [
        "print('base 1')\n"
      ]
    }
  ],
  "metadata": {
    "language_info": {
      "name": "python"
    }
  },
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let ours = r#"{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 5,
      "id": "c-0",
      "metadata": {},
      "outputs": [
        {
          "output_type": "stream",
          "text": ["ours 0\n"]
        }
      ],
      "source": [
        "print('ours 0')\n"
      ]
    },
    {
      "cell_type": "code",
      "execution_count": 2,
      "id": "c-1",
      "metadata": {},
      "outputs": [
        {
          "output_type": "stream",
          "text": ["untouched output bytes\n"]
        }
      ],
      "source": [
        "print('base 1')\n"
      ]
    }
  ],
  "metadata": {
    "language_info": {
      "name": "python"
    }
  },
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let theirs = r#"{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 1,
      "id": "c-0",
      "metadata": {},
      "outputs": [
        {
          "output_type": "stream",
          "text": ["base 0\n"]
        }
      ],
      "source": [
        "print('base 0')\n"
      ]
    },
    {
      "cell_type": "code",
      "execution_count": 2,
      "id": "c-1",
      "metadata": {
        "tags": ["keep"]
      },
      "outputs": [
        {
          "output_type": "stream",
          "text": ["untouched output bytes\n"]
        }
      ],
      "source": [
        "print('base 1')\n"
      ]
    }
  ],
  "metadata": {
    "language_info": {
      "name": "python"
    }
  },
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("test.ipynb"),
            language: Language::Notebook,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        let ComposedOutcome::Clean { bytes, notices } = outcome else {
            panic!("expected clean outcome, got {outcome:?}");
        };

        let parsed: sonic_rs::Value = decode_json(&bytes).expect("parse json");
        let cells = parsed["cells"].as_array().expect("cells array");
        assert_eq!(cells.len(), 2);

        // Cell 0: source was edited, so outputs cleared to [] and execution_count set to null
        let c0 = &cells[0];
        let c0_src = c0["source"].as_array().expect("c0 source array");
        assert_eq!(c0_src[0].as_str(), Some("print('ours 0')\n"));
        assert_eq!(c0["outputs"].as_array().map(sonic_rs::Array::len), Some(0));
        assert!(c0["execution_count"].is_null());

        // Cell 1: metadata was edited, outputs UNTOUCHED
        let c1 = &cells[1];
        assert_eq!(c1["metadata"]["tags"][0].as_str(), Some("keep"));
        assert_eq!(c1["execution_count"].as_i64(), Some(2));
        let c1_out = c1["outputs"].as_array().expect("c1 outputs array");
        assert_eq!(
            c1_out[0]["text"][0].as_str(),
            Some("untouched output bytes\n")
        );

        // Verify untouched output bytes preserved byte-for-byte
        assert!(
            bytes
                .windows(b"untouched output bytes".len())
                .any(|w| w == b"untouched output bytes")
        );

        // Notice emitted for Cell 0
        assert_eq!(notices.entries().len(), 1);
        assert_eq!(
            notices.entries()[0].code(),
            NoticeCode::NotebookOutputsCleared
        );
        assert!(notices.entries()[0].detail().contains("c-0"));
    }

    #[test]
    fn test_idless_unique_neighbour_alignment() {
        let base = r###"{
  "cells": [
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": "# Title\n"
    },
    {
      "cell_type": "code",
      "execution_count": 1,
      "metadata": {},
      "outputs": [{"text": ["1\n"]}],
      "source": "x = 1\n"
    },
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": "## Footer\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 2
}"###;

        let ours = r###"{
  "cells": [
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": "# Title\n"
    },
    {
      "cell_type": "code",
      "execution_count": 2,
      "metadata": {},
      "outputs": [{"text": ["2\n"]}],
      "source": "x = 2\n"
    },
    {
      "cell_type": "markdown",
      "metadata": {},
      "source": "## Footer\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 2
}"###;

        let theirs = base;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("idless.ipynb"),
            language: Language::Notebook,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        let ComposedOutcome::Clean { bytes, notices } = outcome else {
            panic!("expected clean outcome, got {outcome:?}");
        };

        let parsed: sonic_rs::Value = decode_json(&bytes).expect("parse json");
        let cells = parsed["cells"].as_array().expect("cells array");
        assert_eq!(cells.len(), 3);
        assert_eq!(cells[1]["source"].as_str(), Some("x = 2\n"));
        assert_eq!(
            cells[1]["outputs"].as_array().map(sonic_rs::Array::len),
            Some(0)
        );
        assert!(cells[1]["execution_count"].is_null());

        assert_eq!(notices.entries().len(), 2); // EmbeddedLanguageUnsupported + NotebookOutputsCleared
        assert!(
            notices
                .entries()
                .iter()
                .any(|n| n.code() == NoticeCode::NotebookOutputsCleared
                    && n.detail().contains("cell at position 1"))
        );
    }

    #[test]
    fn test_duplicate_cells_conflict() {
        let base = r#"{
  "cells": [
    {
      "cell_type": "code",
      "metadata": {},
      "source": "print(1)\n"
    },
    {
      "cell_type": "code",
      "metadata": {},
      "source": "print(1)\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 2
}"#;

        let ours = r#"{
  "cells": [
    {
      "cell_type": "code",
      "metadata": {},
      "source": "print(2)\n"
    },
    {
      "cell_type": "code",
      "metadata": {},
      "source": "print(1)\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 2
}"#;

        let theirs = base;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("dup.ipynb"),
            language: Language::Notebook,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_new_id_collision_conflicts() {
        let base = r#"{
  "cells": [
    {
      "cell_type": "code",
      "id": "c-0",
      "metadata": {},
      "source": "print(0)\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let ours = r#"{
  "cells": [
    {
      "cell_type": "code",
      "id": "c-0",
      "metadata": {},
      "source": "print(0)\n"
    },
    {
      "cell_type": "code",
      "id": "c-new",
      "metadata": {},
      "source": "print('ours')\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let theirs = r#"{
  "cells": [
    {
      "cell_type": "code",
      "id": "c-0",
      "metadata": {},
      "source": "print(0)\n"
    },
    {
      "cell_type": "code",
      "id": "c-new",
      "metadata": {},
      "source": "print('theirs')\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("collision.ipynb"),
            language: Language::Notebook,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        assert!(matches!(outcome, ComposedOutcome::Conflict { .. }));
    }

    #[test]
    fn test_unknown_fields_survive() {
        let base = r#"{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 1,
      "id": "c-0",
      "metadata": {},
      "my_custom_tag": 42,
      "outputs": [],
      "source": "a = 1\n"
    }
  ],
  "custom_kernel_info": {
    "engine": "v1"
  },
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let ours = r#"{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 2,
      "id": "c-0",
      "metadata": {},
      "my_custom_tag": 42,
      "outputs": [],
      "source": "a = 2\n"
    }
  ],
  "custom_kernel_info": {
    "engine": "v1"
  },
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let theirs = base;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("unknown_fields.ipynb"),
            language: Language::Notebook,
            base: base.as_bytes(),
            ours: ours.as_bytes(),
            theirs: theirs.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        let ComposedOutcome::Clean { bytes, .. } = outcome else {
            panic!("expected clean outcome, got {outcome:?}");
        };

        let parsed: sonic_rs::Value = decode_json(&bytes).expect("parse json");
        assert_eq!(parsed["custom_kernel_info"]["engine"].as_str(), Some("v1"));
        assert_eq!(parsed["cells"][0]["my_custom_tag"].as_i64(), Some(42));
        assert_eq!(parsed["cells"][0]["source"].as_str(), Some("a = 2\n"));
    }

    #[test]
    fn test_unsupported_version_declines() {
        let bad_nb = r#"{
  "cells": [],
  "metadata": {},
  "nbformat": 5,
  "nbformat_minor": 0
}"#;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("bad_ver.ipynb"),
            language: Language::Notebook,
            base: bad_nb.as_bytes(),
            ours: bad_nb.as_bytes(),
            theirs: bad_nb.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        let ComposedOutcome::Declined { reason, notices } = outcome else {
            panic!("expected declined outcome, got {outcome:?}");
        };
        assert_eq!(reason, DeclineReason::ComposedLanguage);
        assert_eq!(
            notices.entries()[0].code(),
            NoticeCode::NotebookStructureDeclined
        );
    }

    #[test]
    fn test_minor_5_missing_id_declines() {
        let no_id = r#"{
  "cells": [
    {
      "cell_type": "code",
      "metadata": {},
      "source": "x = 1\n"
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}"#;

        let env = TestEnv::new();
        let registry = env.registry();
        let cancel = Cancel::never();
        let req = ComposedRequest {
            path: ByteString::from("missing_id.ipynb"),
            language: Language::Notebook,
            base: no_id.as_bytes(),
            ours: no_id.as_bytes(),
            theirs: no_id.as_bytes(),
            mode: MergeMode::Syntax,
        };

        let outcome = merge_notebook(&req, &registry, &cancel).expect("merge_notebook");
        let ComposedOutcome::Declined { reason, notices } = outcome else {
            panic!("expected declined outcome, got {outcome:?}");
        };
        assert_eq!(reason, DeclineReason::ParseFailed);
        assert_eq!(
            notices.entries()[0].code(),
            NoticeCode::NotebookStructureDeclined
        );
    }
}
