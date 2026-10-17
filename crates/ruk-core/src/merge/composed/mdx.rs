//! MDX composed-file merge adapter.
//!
//! Handles `.mdx` files by combining CommonMark/GFM markdown with embedded
//! JSX elements, ESM import/export statements, and JavaScript brace expressions.
//! Document structure and boundaries are parsed via `mdxjs = "=1.0.4"` and
//! `markdown = "=1.0.0"`.

use crate::bytes::ByteString;
use crate::merge::composed::{
    MergeNotice, MergeNotices, NoticeCode, NoticeCollector, NoticeInput, NoticeRegion,
};
use crate::merge::syntax::adapters::DeclineReason;
use crate::merge::syntax::grammar::{
    Cancel, GrammarRegistry, Language, MAX_TRIPLET_BYTES, SyntaxError,
};
use markdown::mdast::Node;
use markdown::unist::Position;

use super::host::{ComposedOutcome, ComposedRequest};

/// Maximum injection depth for nested MDX constructs.
pub const MAX_MDX_DEPTH: usize = 4;

/// Maximum number of structural units considered in one file.
pub const MAX_MDX_UNITS: usize = 256;

/// Kind of structural unit recognized in an MDX document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdxUnitKind {
    /// ESM import or export declaration block.
    Esm,
    /// Flow or text JSX element with opening/closing delimiters.
    JsxElement,
    /// Embedded JavaScript expression enclosed in braces (`{...}`).
    BraceExpression,
    /// Markdown block (heading, paragraph, code fence, list, etc.).
    Markdown,
}

/// A structural span identified by the MDX host parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdxUnit {
    /// High-level kind of unit.
    pub kind: MdxUnitKind,
    /// Half-open start byte offset in source.
    pub start: usize,
    /// Half-open end byte offset in source.
    pub end: usize,
    /// Optional opening delimiter boundary `(start, end)`.
    pub open_boundary: Option<(usize, usize)>,
    /// Optional closing delimiter boundary `(start, end)`.
    pub close_boundary: Option<(usize, usize)>,
}

/// Verifies that a half-open byte span `start..end` is within buffer bounds
/// and aligns exactly with UTF-8 character boundaries.
///
/// # Errors
/// Returns `DeclineReason::ParseFailed` if bounds or char boundaries are invalid.
pub fn verify_span(source: &str, start: usize, end: usize) -> Result<(), DeclineReason> {
    if start > end || end > source.len() {
        return Err(DeclineReason::ParseFailed);
    }
    if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return Err(DeclineReason::ParseFailed);
    }
    Ok(())
}

/// Recursively verifies every unist `Position` in the AST against `source`.
///
/// # Errors
/// Returns `DeclineReason::ParseFailed` if any node's start or end byte offset
/// is out of bounds or not on a UTF-8 character boundary.
pub fn verify_ast_offsets(node: &Node, source: &str) -> Result<(), DeclineReason> {
    if let Some(pos) = node.position() {
        verify_span(source, pos.start.offset, pos.end.offset)?;
    }
    if let Some(children) = node.children() {
        for child in children {
            verify_ast_offsets(child, source)?;
        }
    }
    Ok(())
}

/// Extracts top-level structural units from an MDX AST root.
fn extract_top_units(root: &Node, source: &str) -> Result<Vec<MdxUnit>, DeclineReason> {
    let mut units = Vec::new();
    let Some(children) = root.children() else {
        return Ok(units);
    };

    for child in children {
        if units.len() >= MAX_MDX_UNITS {
            return Err(DeclineReason::SizeLimit);
        }
        let Some(pos) = child.position() else {
            continue;
        };
        verify_span(source, pos.start.offset, pos.end.offset)?;
        let start = pos.start.offset;
        let end = pos.end.offset;

        let unit = match child {
            Node::MdxjsEsm(_) => MdxUnit {
                kind: MdxUnitKind::Esm,
                start,
                end,
                open_boundary: None,
                close_boundary: None,
            },
            Node::MdxJsxFlowElement(elem) => {
                let (open_b, close_b) = compute_jsx_boundaries(elem, start, end);
                MdxUnit {
                    kind: MdxUnitKind::JsxElement,
                    start,
                    end,
                    open_boundary: open_b,
                    close_boundary: close_b,
                }
            }
            Node::MdxFlowExpression(_) => {
                let open_b = if end > start {
                    Some((start, start.saturating_add(1)))
                } else {
                    None
                };
                let close_b = if end > start.saturating_add(1) {
                    Some((end.saturating_sub(1), end))
                } else {
                    None
                };
                MdxUnit {
                    kind: MdxUnitKind::BraceExpression,
                    start,
                    end,
                    open_boundary: open_b,
                    close_boundary: close_b,
                }
            }
            _ => MdxUnit {
                kind: MdxUnitKind::Markdown,
                start,
                end,
                open_boundary: None,
                close_boundary: None,
            },
        };
        units.push(unit);
    }
    Ok(units)
}

fn compute_jsx_boundaries(
    elem: &markdown::mdast::MdxJsxFlowElement,
    start: usize,
    end: usize,
) -> (Option<(usize, usize)>, Option<(usize, usize)>) {
    if elem.children.is_empty() {
        return (Some((start, end)), None);
    }
    let first_start = elem
        .children
        .first()
        .and_then(|c| c.position())
        .map(|p| p.start.offset)
        .unwrap_or(start);
    let last_end = elem
        .children
        .last()
        .and_then(|c| c.position())
        .map(|p| p.end.offset)
        .unwrap_or(end);
    let open_b = Some((start, first_start));
    let close_b = if last_end < end {
        Some((last_end, end))
    } else {
        None
    };
    (open_b, close_b)
}

/// Synthesizes a notice and returns a typed `ComposedOutcome::Declined`.
fn decline_parse(
    path: &ByteString,
    language: Language,
    reason: DeclineReason,
    detail: &str,
) -> ComposedOutcome {
    let mut collector = NoticeCollector::new();
    let code = match reason {
        DeclineReason::SizeLimit => NoticeCode::SyntaxLimit,
        DeclineReason::ParseFailed | DeclineReason::BinaryContent => {
            NoticeCode::SyntaxParseDeclined
        }
        _ => NoticeCode::SyntaxAmbiguous,
    };
    if let Ok(notice) = MergeNotice::new(path.clone(), None, language.id(), code, detail) {
        collector.record(notice);
    }
    ComposedOutcome::Declined {
        reason,
        notices: collector.finish(),
    }
}

/// One planned replacement of a base byte range.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PlannedEdit {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
}

/// Three-way merge entry point for MDX documents.
///
/// Distinguishes Markdown text, JSX elements, ESM declarations, and brace
/// expressions using `mdxjs = "=1.0.4"`. Never executes imports, evaluates
/// expressions, or renders JavaScript.
///
/// # Errors
/// Returns `SyntaxError::Cancelled` if cancelled, or `SyntaxError::Invalid`
/// if path is invalid.
pub fn merge_mdx(
    request: &ComposedRequest<'_>,
    _registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<ComposedOutcome, SyntaxError> {
    cancel.check()?;

    if request.path.is_empty() || request.path.as_bytes().contains(&0) {
        return Err(SyntaxError::Invalid {
            what: "merge path",
            detail: "must be non-empty and contain no NUL".to_owned(),
        });
    }

    let total_len = request
        .base
        .len()
        .saturating_add(request.ours.len())
        .saturating_add(request.theirs.len());
    let max_budget = usize::try_from(MAX_TRIPLET_BYTES).unwrap_or(usize::MAX);
    if total_len > max_budget {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::SizeLimit,
            "triplet exceeds maximum size limit",
        ));
    }

    if request.base.contains(&0) || request.ours.contains(&0) || request.theirs.contains(&0) {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::BinaryContent,
            "input contains NUL bytes; binary content is not supported",
        ));
    }

    let base_str = match core::str::from_utf8(request.base) {
        Ok(s) => s,
        Err(_) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                "base input is not valid UTF-8",
            ));
        }
    };
    let ours_str = match core::str::from_utf8(request.ours) {
        Ok(s) => s,
        Err(_) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                "ours input is not valid UTF-8",
            ));
        }
    };
    let theirs_str = match core::str::from_utf8(request.theirs) {
        Ok(s) => s,
        Err(_) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                "theirs input is not valid UTF-8",
            ));
        }
    };

    if request.ours == request.base && request.theirs == request.base {
        return Ok(ComposedOutcome::Clean {
            bytes: request.base.to_vec(),
            notices: MergeNotices::default(),
        });
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

    let options = mdxjs::Options::default();
    let base_ast = match mdxjs::mdast_util_from_mdx(base_str, &options) {
        Ok(ast) => ast,
        Err(err) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                &format!("base MDX parse error: {err}"),
            ));
        }
    };
    let ours_ast = match mdxjs::mdast_util_from_mdx(ours_str, &options) {
        Ok(ast) => ast,
        Err(err) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                &format!("ours MDX parse error: {err}"),
            ));
        }
    };
    let theirs_ast = match mdxjs::mdast_util_from_mdx(theirs_str, &options) {
        Ok(ast) => ast,
        Err(err) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                &format!("theirs MDX parse error: {err}"),
            ));
        }
    };

    if verify_ast_offsets(&base_ast, base_str).is_err() {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::ParseFailed,
            "base AST offsets violate UTF-8 character boundaries",
        ));
    }
    if verify_ast_offsets(&ours_ast, ours_str).is_err() {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::ParseFailed,
            "ours AST offsets violate UTF-8 character boundaries",
        ));
    }
    if verify_ast_offsets(&theirs_ast, theirs_str).is_err() {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::ParseFailed,
            "theirs AST offsets violate UTF-8 character boundaries",
        ));
    }

    let base_units = match extract_top_units(&base_ast, base_str) {
        Ok(u) => u,
        Err(r) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                r,
                "failed extracting base MDX units",
            ));
        }
    };
    let ours_units = match extract_top_units(&ours_ast, ours_str) {
        Ok(u) => u,
        Err(r) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                r,
                "failed extracting ours MDX units",
            ));
        }
    };
    let theirs_units = match extract_top_units(&theirs_ast, theirs_str) {
        Ok(u) => u,
        Err(r) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                r,
                "failed extracting theirs MDX units",
            ));
        }
    };

    if base_units.len() != ours_units.len() || base_units.len() != theirs_units.len() {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::UnsupportedConstruct,
            "structural unit count changed across inputs",
        ));
    }

    let mut edits = Vec::new();

    for i in 0..base_units.len() {
        let b = &base_units[i];
        let o = &ours_units[i];
        let t = &theirs_units[i];

        if b.kind != o.kind || b.kind != t.kind {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ChangedKey,
                "host unit kind mismatch between sides",
            ));
        }

        let b_bytes = &request.base[b.start..b.end];
        let o_bytes = &request.ours[o.start..o.end];
        let t_bytes = &request.theirs[t.start..t.end];

        let ours_changed = o_bytes != b_bytes;
        let theirs_changed = t_bytes != b_bytes;

        if !ours_changed && !theirs_changed {
            continue;
        }

        if ours_changed && !theirs_changed {
            edits.push(PlannedEdit {
                start: b.start,
                end: b.end,
                replacement: o_bytes.to_vec(),
            });
            continue;
        }

        if !ours_changed && theirs_changed {
            edits.push(PlannedEdit {
                start: b.start,
                end: b.end,
                replacement: t_bytes.to_vec(),
            });
            continue;
        }

        if o_bytes == t_bytes {
            edits.push(PlannedEdit {
                start: b.start,
                end: b.end,
                replacement: o_bytes.to_vec(),
            });
            continue;
        }

        if matches!(
            b.kind,
            MdxUnitKind::JsxElement | MdxUnitKind::BraceExpression | MdxUnitKind::Esm
        ) {
            let mut collector = NoticeCollector::new();
            let start_u64 = u64::try_from(b.start).unwrap_or(0);
            let end_u64 = u64::try_from(b.end).unwrap_or(0);
            let region = NoticeRegion::new(NoticeInput::Base, start_u64, end_u64).ok();
            if let Ok(notice) = MergeNotice::new(
                request.path.clone(),
                region,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                "boundary/structure overlap conflict in indivisible MDX host unit",
            ) {
                collector.record(notice);
            }
            return Ok(ComposedOutcome::Conflict {
                notices: collector.finish(),
            });
        }

        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::SameUnitChanged,
            "both sides concurrently edited markdown unit",
        ));
    }

    edits.sort_by_key(|e| e.start);
    let mut cursor = 0;
    for e in &edits {
        if e.start < cursor || e.end < e.start || e.end > request.base.len() {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::OverlappingEdits,
                "collected MDX edits overlap",
            ));
        }
        cursor = e.end;
    }

    let mut merged = request.base.to_vec();
    for edit in edits.into_iter().rev() {
        merged.splice(edit.start..edit.end, edit.replacement);
    }

    let merged_str = match core::str::from_utf8(&merged) {
        Ok(s) => s,
        Err(_) => {
            return Ok(decline_parse(
                &request.path,
                request.language,
                DeclineReason::ParseFailed,
                "merged MDX candidate is not valid UTF-8",
            ));
        }
    };
    if let Err(err) = mdxjs::mdast_util_from_mdx(merged_str, &options) {
        return Ok(decline_parse(
            &request.path,
            request.language,
            DeclineReason::ParseFailed,
            &format!("merged MDX verification parse failed: {err}"),
        ));
    }

    Ok(ComposedOutcome::Clean {
        bytes: merged,
        notices: MergeNotices::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::composed::MergeMode;

    fn make_req<'a>(
        path: &'a str,
        base: &'a [u8],
        ours: &'a [u8],
        theirs: &'a [u8],
    ) -> ComposedRequest<'a> {
        ComposedRequest {
            path: ByteString::from(path),
            language: Language::Mdx,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        }
    }

    #[test]
    fn test_offset_verification() {
        let source = "# Hello 😊 World\n";
        assert!(verify_span(source, 0, 7).is_ok());
        // Emoji 😊 is 4 bytes: 8..12. Index 9 is not a char boundary.
        assert_eq!(verify_span(source, 8, 9), Err(DeclineReason::ParseFailed));
        // Out of buffer bounds.
        assert_eq!(verify_span(source, 0, 500), Err(DeclineReason::ParseFailed));

        let reg = GrammarRegistry::new();
        let cancel = Cancel::never();
        let req = make_req("test.mdx", b"# Hi \xff\xfe\n", b"# Hi\n", b"# Hi\n");
        let outcome = merge_mdx(&req, &reg, &cancel).unwrap();
        assert!(matches!(
            outcome,
            ComposedOutcome::Declined {
                reason: DeclineReason::ParseFailed,
                ..
            }
        ));
    }

    #[test]
    fn test_prose_only() {
        let base = b"# Title\n\nParagraph one.\n\nParagraph two.\n";
        let ours = b"# Title\n\nParagraph one edited by ours.\n\nParagraph two.\n";
        let theirs = b"# Title\n\nParagraph one.\n\nParagraph two edited by theirs.\n";

        let reg = GrammarRegistry::new();
        let cancel = Cancel::never();
        let req = make_req("docs/guide.mdx", base, ours, theirs);
        let outcome = merge_mdx(&req, &reg, &cancel).unwrap();

        match outcome {
            ComposedOutcome::Clean { bytes, .. } => {
                let text = core::str::from_utf8(&bytes).unwrap();
                assert!(text.contains("Paragraph one edited by ours."));
                assert!(text.contains("Paragraph two edited by theirs."));
            }
            other => panic!("expected clean merge, got: {:?}", other),
        }
    }

    #[test]
    fn test_esm_edit() {
        let base = b"import { a } from './a';\n\n# Welcome\n\nSome prose text here.\n";
        let ours = b"import { a } from './a';\n\n# Welcome\n\nUpdated prose text here.\n";
        let theirs = b"import { a, b } from './a';\n\n# Welcome\n\nSome prose text here.\n";

        let reg = GrammarRegistry::new();
        let cancel = Cancel::never();
        let req = make_req("page.mdx", base, ours, theirs);
        let outcome = merge_mdx(&req, &reg, &cancel).unwrap();

        match outcome {
            ComposedOutcome::Clean { bytes, .. } => {
                let text = core::str::from_utf8(&bytes).unwrap();
                assert!(text.contains("import { a, b } from './a';"));
                assert!(text.contains("Updated prose text here."));
            }
            other => panic!("expected clean merge, got: {:?}", other),
        }
    }

    #[test]
    fn test_boundary_overlap() {
        let base = b"<Button variant=\"outline\">\n  Click me\n</Button>\n";
        let ours = b"<IconButton variant=\"outline\">\n  Click me\n</IconButton>\n";
        let theirs = b"<Button variant=\"outline\">\n  Press here\n</Button>\n";

        let reg = GrammarRegistry::new();
        let cancel = Cancel::never();
        let req = make_req("component.mdx", base, ours, theirs);
        let outcome = merge_mdx(&req, &reg, &cancel).unwrap();

        match outcome {
            ComposedOutcome::Conflict { notices } => {
                assert!(!notices.is_empty());
                let notice = &notices.entries()[0];
                assert_eq!(notice.code(), NoticeCode::SyntaxAmbiguous);
            }
            other => panic!("expected conflict on boundary overlap, got: {:?}", other),
        }
    }
}
