//! Host and embedded-region composition engine for HTML, Vue, and Svelte.
//!
//! This module implements syntax-assisted three-way content merge for mixed
//! host documents containing embedded language regions (scripts, styles,
//! templates). The host grammar owns the document structure and delimiter
//! boundaries, while plain language adapters ([`crate::merge::syntax::adapter_for`])
//! and [`crate::merge::syntax::alignment::merge_triplet`] merge matched child
//! regions when delimiters, roles, and declared languages are intact.
//!
//! All new schema and component versions are v1. Structured notices use the
//! single canonical notice schema defined by [`crate::merge::composed`].
//! Resource bounds enforce a maximum injection depth of 4, a maximum of 256
//! regions per file, and an overall 8 MiB triplet budget.

use std::collections::HashMap;

use crate::bytes::ByteString;
use crate::merge::composed::{
    MergeMode, MergeNotice, MergeNotices, NoticeCode, NoticeCollector, NoticeInput, NoticeRegion,
};
use crate::merge::syntax::adapters::{DeclineReason, adapter_for};
use crate::merge::syntax::alignment::merge_triplet;
use crate::merge::syntax::grammar::{
    Cancel, Grammar, GrammarRegistry, Language, MAX_TRIPLET_BYTES, ParsedTree, SyntaxError,
};
use crate::merge::syntax::{SyntaxOutcome, SyntaxRequest};

/// Maximum nesting depth of container elements enclosing an embedded region.
pub const MAX_INJECTION_DEPTH: usize = 4;

/// Maximum number of embedded regions considered in one file.
pub const MAX_REGIONS_PER_FILE: usize = 256;

/// A bounded composed-file merge request for one host document triplet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedRequest<'a> {
    /// Byte-exact repository path, carried into merge notices.
    pub path: ByteString,
    /// Host language (HTML, Vue, Svelte).
    pub language: Language,
    /// Common ancestor source bytes.
    pub base: &'a [u8],
    /// First side source bytes.
    pub ours: &'a [u8],
    /// Second side source bytes.
    pub theirs: &'a [u8],
    /// Effective merge mode (Syntax or Git).
    pub mode: MergeMode,
}

/// The typed outcome of one composed-file merge operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComposedOutcome {
    /// Merged cleanly with byte-preserved host structure and verified regions.
    Clean {
        /// Merged file bytes.
        bytes: Vec<u8>,
        /// Bounded structured notices recorded during merge.
        notices: MergeNotices,
    },
    /// Structural conflict that cannot be resolved automatically.
    Conflict {
        /// Bounded structured notices recording conflict evidence.
        notices: MergeNotices,
    },
    /// The syntax stage declined to ordinary bounded text merge.
    Declined {
        /// Truthful machine-readable decline reason.
        reason: DeclineReason,
        /// Bounded structured notices explaining the decline.
        notices: MergeNotices,
    },
}

impl ComposedOutcome {
    /// Whether the outcome represents a clean merge.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    /// Whether the outcome represents a structural conflict.
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }

    /// Whether the outcome represents a decline to text merge.
    #[must_use]
    pub const fn is_declined(&self) -> bool {
        matches!(self, Self::Declined { .. })
    }

    /// Structured notices accompanying this outcome.
    #[must_use]
    pub fn notices(&self) -> &MergeNotices {
        match self {
            Self::Clean { notices, .. }
            | Self::Conflict { notices }
            | Self::Declined { notices, .. } => notices,
        }
    }
}

/// Semantic role of an embedded region within its host document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionRole {
    /// HTML `<script>` element.
    HtmlScript,
    /// HTML `<style>` element.
    HtmlStyle,
    /// Vue `<script setup>` block.
    VueScriptSetup,
    /// Vue ordinary `<script>` block.
    VueScriptOrdinary,
    /// Vue `<style>` block.
    VueStyle,
    /// Vue `<template>` block.
    VueTemplate,
    /// Svelte `<script module>` or `<script context="module">` block.
    SvelteScriptModule,
    /// Svelte instance `<script>` block.
    SvelteScriptInstance,
    /// Svelte `<style>` block.
    SvelteStyle,
    /// Other embedded or fallback host element.
    Other,
}

/// Unique structural identity of an embedded region within a host document.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RegionKey {
    host_kind: String,
    role: RegionRole,
    context: Vec<u8>,
}

/// One located embedded region in a parsed host input.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EmbeddedRegion {
    key: RegionKey,
    declared_language: Option<Language>,
    declared_lang_str: String,
    start_delim: Vec<u8>,
    end_delim: Vec<u8>,
    content_start: usize,
    content_end: usize,
    depth: usize,
}

/// A pending byte replacement for an altered embedded region.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegionEdit<'a> {
    start: usize,
    end: usize,
    role: RegionRole,
    context: &'a [u8],
    declared_language: Option<Language>,
    replacement: Vec<u8>,
}

/// Records a notice safely without failing or unwrapping.
fn add_notice(
    collector: &mut NoticeCollector,
    path: &ByteString,
    region: Option<(NoticeInput, u64, u64)>,
    language: &str,
    code: NoticeCode,
    detail: impl Into<String>,
) {
    let reg = region.and_then(|(inp, s, e)| NoticeRegion::new(inp, s, e).ok());
    let lang = if language.is_empty() {
        "text"
    } else {
        language
    };
    if let Ok(notice) = MergeNotice::new(path.clone(), reg, lang, code, detail) {
        collector.record(notice);
    }
}

/// Finds the `tag_name` child of a start tag node.
fn find_tag_name_child(tree: &ParsedTree, source: &[u8], tag_node: u32) -> Option<Vec<u8>> {
    tree.named_children(tag_node)
        .into_iter()
        .find(|&g| tree.kind_of(g) == "tag_name")
        .map(|g| tree.text_of(g, source).to_vec())
}

/// Extracts tag name bytes from an element node's start tag or self-closing tag.
fn get_tag_name(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
    for child in tree.named_children(node) {
        let kind = tree.kind_of(child);
        let is_tag = kind == "start_tag" || kind == "self_closing_tag";
        if is_tag && let Some(name) = find_tag_name_child(tree, source, child) {
            return name;
        }
    }
    Vec::new()
}

/// Checks whether an element node matches any of the target tag names.
fn is_tag_name(tree: &ParsedTree, source: &[u8], node: u32, targets: &[&[u8]]) -> bool {
    let tag = get_tag_name(tree, source, node);
    targets.iter().any(|&t| t.eq_ignore_ascii_case(&tag))
}

/// Strips optional surrounding quotes from an attribute value.
fn parse_attr_value(tree: &ParsedTree, source: &[u8], part: u32) -> Option<Vec<u8>> {
    let mut raw = tree.text_of(part, source);
    let is_quoted = (raw.starts_with(b"\"") && raw.ends_with(b"\""))
        || (raw.starts_with(b"'") && raw.ends_with(b"'"));
    if is_quoted && raw.len() >= 2 {
        raw = &raw[1..raw.len() - 1];
    }
    Some(raw.to_vec())
}

/// Parses a single attribute node into `(name, optional_value)`.
fn parse_attribute(
    tree: &ParsedTree,
    source: &[u8],
    attr_node: u32,
) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let mut name = Vec::new();
    let mut value = None;
    for part in tree.named_children(attr_node) {
        let part_kind = tree.kind_of(part);
        if part_kind == "attribute_name" || part_kind == "directive_name" {
            name = tree.text_of(part, source).to_vec();
        } else if part_kind == "attribute_value"
            || part_kind == "quoted_attribute_value"
            || part_kind == "directive_value"
        {
            value = parse_attr_value(tree, source, part);
        }
    }
    if name.is_empty() {
        return None;
    }
    Some((name, value))
}

/// Extracts attributes as `(name, optional_unquoted_value)` pairs from a start tag.
fn get_attributes(
    tree: &ParsedTree,
    source: &[u8],
    start_tag: u32,
) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut attrs = Vec::new();
    for child in tree.named_children(start_tag) {
        let kind = tree.kind_of(child);
        if kind != "attribute" && kind != "directive_attribute" {
            continue;
        }
        if let Some(attr) = parse_attribute(tree, source, child) {
            attrs.push(attr);
        }
    }
    attrs
}

/// Checks whether an attribute name is present.
fn has_attr(attrs: &[(Vec<u8>, Option<Vec<u8>>)], name: &[u8]) -> bool {
    attrs
        .iter()
        .any(|(n, _)| n.as_slice().eq_ignore_ascii_case(name))
}

/// Returns the value slice of a named attribute, if present.
fn attr_value<'a>(attrs: &'a [(Vec<u8>, Option<Vec<u8>>)], name: &[u8]) -> Option<&'a [u8]> {
    attrs
        .iter()
        .find(|(n, _)| n.as_slice().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_deref())
}

/// Maps a script lang attribute string to a catalogued language.
fn parse_script_lang(lang_str: &str) -> (Option<Language>, String) {
    let declared = match lang_str {
        "ts" | "typescript" => Some(Language::Typescript),
        "js" | "javascript" => Some(Language::Javascript),
        _ => None,
    };
    (declared, lang_str.to_owned())
}

/// Maps a script MIME type string to a catalogued language.
fn parse_script_type(type_str: &str) -> (Option<Language>, String) {
    let declared = match type_str {
        "text/javascript" | "application/javascript" | "module" | "text/ecmascript" => {
            Some(Language::Javascript)
        }
        "text/typescript" | "application/typescript" | "ts" => Some(Language::Typescript),
        _ => None,
    };
    (declared, type_str.to_owned())
}

/// Maps a style lang attribute string to a catalogued language.
fn parse_style_lang(lang_str: &str) -> (Option<Language>, String) {
    let declared = match lang_str {
        "css" => Some(Language::Css),
        _ => None,
    };
    (declared, lang_str.to_owned())
}

/// Determines role and language for HTML elements.
fn determine_html_role_and_lang(
    tag: &[u8],
    attrs: &[(Vec<u8>, Option<Vec<u8>>)],
) -> (RegionRole, Option<Language>, String) {
    if tag.eq_ignore_ascii_case(b"script") {
        if has_attr(attrs, b"src") {
            return (RegionRole::HtmlScript, None, "src".to_owned());
        }
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_script_lang(&s);
            return (RegionRole::HtmlScript, declared, desc);
        }
        if let Some(typ) = attr_value(attrs, b"type") {
            let s = String::from_utf8_lossy(typ).to_ascii_lowercase();
            let (declared, desc) = parse_script_type(&s);
            return (RegionRole::HtmlScript, declared, desc);
        }
        return (
            RegionRole::HtmlScript,
            Some(Language::Javascript),
            "javascript".to_owned(),
        );
    }
    if tag.eq_ignore_ascii_case(b"style") {
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_style_lang(&s);
            return (RegionRole::HtmlStyle, declared, desc);
        }
        if let Some(typ) = attr_value(attrs, b"type") {
            let s = String::from_utf8_lossy(typ).to_ascii_lowercase();
            let (declared, desc) = parse_style_lang(&s);
            return (RegionRole::HtmlStyle, declared, desc);
        }
        return (RegionRole::HtmlStyle, Some(Language::Css), "css".to_owned());
    }
    (RegionRole::Other, None, "text".to_owned())
}

/// Determines role and language for Vue elements.
fn determine_vue_role_and_lang(
    tag: &[u8],
    attrs: &[(Vec<u8>, Option<Vec<u8>>)],
) -> (RegionRole, Option<Language>, String) {
    if tag.eq_ignore_ascii_case(b"script") {
        let is_setup = has_attr(attrs, b"setup");
        let role = if is_setup {
            RegionRole::VueScriptSetup
        } else {
            RegionRole::VueScriptOrdinary
        };
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_script_lang(&s);
            return (role, declared, desc);
        }
        return (role, Some(Language::Javascript), "javascript".to_owned());
    }
    if tag.eq_ignore_ascii_case(b"style") {
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_style_lang(&s);
            return (RegionRole::VueStyle, declared, desc);
        }
        return (RegionRole::VueStyle, Some(Language::Css), "css".to_owned());
    }
    if tag.eq_ignore_ascii_case(b"template") {
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let declared = (s == "html").then_some(Language::Html);
            return (RegionRole::VueTemplate, declared, s);
        }
        return (
            RegionRole::VueTemplate,
            Some(Language::Html),
            "html".to_owned(),
        );
    }
    (RegionRole::Other, None, "text".to_owned())
}

/// Determines role and language for Svelte elements.
fn determine_svelte_role_and_lang(
    tag: &[u8],
    attrs: &[(Vec<u8>, Option<Vec<u8>>)],
) -> (RegionRole, Option<Language>, String) {
    if tag.eq_ignore_ascii_case(b"script") {
        let is_module = has_attr(attrs, b"module")
            || attr_value(attrs, b"context").is_some_and(|v| v.eq_ignore_ascii_case(b"module"));
        let role = if is_module {
            RegionRole::SvelteScriptModule
        } else {
            RegionRole::SvelteScriptInstance
        };
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_script_lang(&s);
            return (role, declared, desc);
        }
        return (role, Some(Language::Javascript), "javascript".to_owned());
    }
    if tag.eq_ignore_ascii_case(b"style") {
        if let Some(lang) = attr_value(attrs, b"lang") {
            let s = String::from_utf8_lossy(lang).to_ascii_lowercase();
            let (declared, desc) = parse_style_lang(&s);
            return (RegionRole::SvelteStyle, declared, desc);
        }
        return (
            RegionRole::SvelteStyle,
            Some(Language::Css),
            "css".to_owned(),
        );
    }
    (RegionRole::Other, None, "text".to_owned())
}

/// Determines role, optional supported child language, and raw language descriptor.
fn determine_role_and_lang(
    tag: &[u8],
    host_lang: Language,
    attrs: &[(Vec<u8>, Option<Vec<u8>>)],
) -> (RegionRole, Option<Language>, String) {
    match host_lang {
        Language::Html => determine_html_role_and_lang(tag, attrs),
        Language::Vue => determine_vue_role_and_lang(tag, attrs),
        Language::Svelte => determine_svelte_role_and_lang(tag, attrs),
        _ => (RegionRole::Other, None, "text".to_owned()),
    }
}

/// Checks whether an AST node represents a candidate host embedded element.
fn is_host_embedded(
    kind: &str,
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    host_lang: Language,
) -> bool {
    if kind == "script_element" || kind == "style_element" {
        return true;
    }
    if host_lang == Language::Vue && kind == "template_element" {
        return true;
    }
    if kind == "element" {
        let targets: &[&[u8]] = if host_lang == Language::Vue {
            &[b"script", b"style", b"template"]
        } else {
            &[b"script", b"style"]
        };
        return is_tag_name(tree, source, node, targets);
    }
    false
}

/// Formats a unique structural context string for an embedded region.
fn build_context(
    ancestors: &[Vec<u8>],
    id_attr: &[u8],
    scoped: bool,
    module_attr: bool,
    setup_attr: bool,
    context_attr: &[u8],
) -> Vec<u8> {
    let mut ctx = Vec::new();
    for (i, anc) in ancestors.iter().enumerate() {
        if i > 0 {
            ctx.push(b'/');
        }
        ctx.extend_from_slice(anc);
    }
    ctx.push(b'#');
    ctx.extend_from_slice(id_attr);
    ctx.push(b';');
    if scoped {
        ctx.extend_from_slice(b"scoped;");
    }
    if module_attr {
        ctx.extend_from_slice(b"module;");
    }
    if setup_attr {
        ctx.extend_from_slice(b"setup;");
    }
    if !context_attr.is_empty() {
        ctx.extend_from_slice(b"context=");
        ctx.extend_from_slice(context_attr);
        ctx.push(b';');
    }
    ctx
}

/// Shared read-only context for the recursive host-tree walk.
#[derive(Clone, Copy)]
struct HostWalk<'a> {
    tree: &'a ParsedTree,
    source: &'a [u8],
    host_lang: Language,
    path: &'a ByteString,
    input_which: NoticeInput,
}

/// The three region-key sets compared when checking insertions and deletions.
struct RegionKeySets<'a> {
    base_keys: &'a HashMap<&'a RegionKey, usize>,
    ours_keys: &'a HashMap<&'a RegionKey, usize>,
    theirs_keys: &'a HashMap<&'a RegionKey, usize>,
}

/// The four inputs merged when both sides change one embedded region.
/// Two lifetimes: `r_base` outlives the returned edit while the contents
/// only need to live through the call (they borrow the request sides).
#[derive(Clone, Copy)]
struct CompetingInputs<'b, 'c> {
    r_base: &'b EmbeddedRegion,
    base_content: &'c [u8],
    ours_content: &'c [u8],
    theirs_content: &'c [u8],
}

/// Shared request context for final host verification.
struct HostVerify<'a> {
    host_grammar: &'a dyn Grammar,
    registry: &'a GrammarRegistry<'a>,
    cancel: &'a Cancel,
    req_lang: Language,
    path: &'a ByteString,
}

/// Processes an embedded element node and extracts its region descriptor.
fn process_embedded_node(
    ctx: HostWalk<'_>,
    node: u32,
    ancestors: &[Vec<u8>],
    container_depth: usize,
    regions: &mut Vec<EmbeddedRegion>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let HostWalk {
        tree,
        source,
        host_lang,
        path,
        input_which,
    } = ctx;
    if container_depth > MAX_INJECTION_DEPTH {
        let msg = format!("exceeded maximum injection depth {MAX_INJECTION_DEPTH}");
        add_notice(
            collector,
            path,
            None,
            host_lang.id(),
            NoticeCode::SyntaxLimit,
            msg,
        );
        return Err(DeclineReason::SizeLimit);
    }

    let start_tag = tree
        .named_children(node)
        .into_iter()
        .find(|c| ["start_tag", "self_closing_tag"].contains(&tree.kind_of(*c)));
    let Some(start_tag) = start_tag else {
        return Ok(());
    };
    if tree.kind_of(start_tag) == "self_closing_tag" {
        return Ok(());
    }

    let end_tag = tree
        .named_children(node)
        .into_iter()
        .find(|c| tree.kind_of(*c) == "end_tag");
    let Some(end_tag) = end_tag else {
        return Ok(());
    };

    let Some(st_node) = tree.get(start_tag) else {
        return Ok(());
    };
    let Some(et_node) = tree.get(end_tag) else {
        return Ok(());
    };

    let content_start = usize::try_from(st_node.end).unwrap_or(source.len());
    let content_end = usize::try_from(et_node.start).unwrap_or(source.len());
    if content_start > content_end {
        return Err(DeclineReason::ParseFailed);
    }

    let tag = get_tag_name(tree, source, node);
    let attrs = get_attributes(tree, source, start_tag);
    let (role, declared_language, declared_lang_str) =
        determine_role_and_lang(&tag, host_lang, &attrs);

    let id_attr = attr_value(&attrs, b"id").unwrap_or(&[]);
    let scoped = has_attr(&attrs, b"scoped");
    let module_attr = has_attr(&attrs, b"module");
    let setup_attr = has_attr(&attrs, b"setup");
    let context_attr = attr_value(&attrs, b"context").unwrap_or(&[]);
    let context = build_context(
        ancestors,
        id_attr,
        scoped,
        module_attr,
        setup_attr,
        context_attr,
    );

    if declared_language.is_none() {
        let s_u64 = u64::try_from(content_start).unwrap_or(0);
        let e_u64 = u64::try_from(content_end).unwrap_or(0);
        let msg = format!("unsupported embedded preprocessor or MIME type: {declared_lang_str}");
        add_notice(
            collector,
            path,
            Some((input_which, s_u64, e_u64)),
            &declared_lang_str,
            NoticeCode::EmbeddedLanguageUnsupported,
            msg,
        );
    }

    regions.push(EmbeddedRegion {
        key: RegionKey {
            host_kind: tree.kind_of(node).to_owned(),
            role,
            context,
        },
        declared_language,
        declared_lang_str,
        start_delim: tree.text_of(start_tag, source).to_vec(),
        end_delim: tree.text_of(end_tag, source).to_vec(),
        content_start,
        content_end,
        depth: container_depth,
    });

    if regions.len() > MAX_REGIONS_PER_FILE {
        let msg = format!("exceeded maximum {MAX_REGIONS_PER_FILE} regions per file");
        add_notice(
            collector,
            path,
            None,
            host_lang.id(),
            NoticeCode::SyntaxLimit,
            msg,
        );
        return Err(DeclineReason::SizeLimit);
    }

    Ok(())
}

/// Recursively processes container nodes and traverses children.
fn process_container_node(
    ctx: HostWalk<'_>,
    node: u32,
    ancestors: &mut Vec<Vec<u8>>,
    container_depth: usize,
    regions: &mut Vec<EmbeddedRegion>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let HostWalk { tree, source, .. } = ctx;
    let tag = get_tag_name(tree, source, node);
    let is_elem = !tag.is_empty();
    if is_elem {
        ancestors.push(tag);
    }
    let next_depth = if is_elem {
        container_depth + 1
    } else {
        container_depth
    };
    for child in tree.named_children(node) {
        walk_tree(ctx, child, ancestors, next_depth, regions, collector)?;
    }
    if is_elem {
        ancestors.pop();
    }
    Ok(())
}

/// Walks the parsed host tree to discover embedded regions.
fn walk_tree(
    ctx: HostWalk<'_>,
    node: u32,
    ancestors: &mut Vec<Vec<u8>>,
    container_depth: usize,
    regions: &mut Vec<EmbeddedRegion>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let HostWalk {
        tree,
        source,
        host_lang,
        ..
    } = ctx;
    let kind = tree.kind_of(node);
    if is_host_embedded(kind, tree, source, node, host_lang) {
        return process_embedded_node(ctx, node, ancestors, container_depth, regions, collector);
    }
    process_container_node(ctx, node, ancestors, container_depth, regions, collector)
}

/// Extracts all embedded regions from a parsed host input.
fn extract_regions(
    tree: &ParsedTree,
    source: &[u8],
    host_lang: Language,
    path: &ByteString,
    input_which: NoticeInput,
    collector: &mut NoticeCollector,
) -> Result<Vec<EmbeddedRegion>, DeclineReason> {
    let mut regions = Vec::new();
    if tree.is_empty() {
        return Ok(regions);
    }
    let mut ancestors = Vec::new();
    let ctx = HostWalk {
        tree,
        source,
        host_lang,
        path,
        input_which,
    };
    walk_tree(ctx, 0, &mut ancestors, 0, &mut regions, collector)?;
    Ok(regions)
}

/// Parses a host input and checks for syntax errors.
fn parse_host(
    grammar: &dyn Grammar,
    source: &[u8],
    cancel: &Cancel,
    lang: Language,
    path: &ByteString,
    which: &str,
    collector: &mut NoticeCollector,
) -> Result<Result<ParsedTree, DeclineReason>, SyntaxError> {
    cancel.check()?;
    let tree = match grammar.parse(source, cancel) {
        Ok(t) => t,
        Err(SyntaxError::Cancelled(msg)) => return Err(SyntaxError::Cancelled(msg)),
        Err(err) => {
            let msg = format!("{which} input failed to parse: {err}");
            add_notice(
                collector,
                path,
                None,
                lang.id(),
                NoticeCode::SyntaxParseDeclined,
                msg,
            );
            return Ok(Err(DeclineReason::ParseFailed));
        }
    };
    if tree.has_error() {
        let msg = format!("{which} input holds ERROR or missing nodes");
        add_notice(
            collector,
            path,
            None,
            lang.id(),
            NoticeCode::SyntaxParseDeclined,
            msg,
        );
        return Ok(Err(DeclineReason::ParseFailed));
    }
    Ok(Ok(tree))
}

/// Validates binary content and UTF-8 encoding of one input.
fn check_input_bytes(
    which: &str,
    bytes: &[u8],
    path: &ByteString,
    lang: Language,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    if bytes.contains(&0) {
        let msg = format!("{which} input contains NUL bytes");
        add_notice(
            collector,
            path,
            None,
            lang.id(),
            NoticeCode::SyntaxParseDeclined,
            msg,
        );
        return Err(DeclineReason::BinaryContent);
    }
    if core::str::from_utf8(bytes).is_err() {
        let msg = format!("{which} input is not valid UTF-8");
        add_notice(
            collector,
            path,
            None,
            lang.id(),
            NoticeCode::SyntaxParseDeclined,
            msg,
        );
        return Err(DeclineReason::ParseFailed);
    }
    Ok(())
}

/// Validates triplet size, binary content, and UTF-8 encoding.
fn validate_request(
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let total_bytes = u64::try_from(request.base.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(request.ours.len()).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(request.theirs.len()).unwrap_or(u64::MAX));

    if total_bytes > MAX_TRIPLET_BYTES {
        let msg = format!("triplet size {total_bytes} exceeds maximum {MAX_TRIPLET_BYTES} bytes");
        add_notice(
            collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::SyntaxLimit,
            msg,
        );
        return Err(DeclineReason::SizeLimit);
    }

    check_input_bytes(
        "base",
        request.base,
        &request.path,
        request.language,
        collector,
    )?;
    check_input_bytes(
        "ours",
        request.ours,
        &request.path,
        request.language,
        collector,
    )?;
    check_input_bytes(
        "theirs",
        request.theirs,
        &request.path,
        request.language,
        collector,
    )?;
    Ok(())
}

/// Checks that region keys occur at most once within a single input.
fn check_key_uniqueness(
    keys: &HashMap<&RegionKey, usize>,
    which: &str,
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    for (key, count) in keys {
        if *count > 1 {
            let msg = format!("duplicate embedded region key in {which}: {:?}", key.role);
            add_notice(
                collector,
                &request.path,
                None,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                msg,
            );
            return Err(DeclineReason::DuplicateKey);
        }
    }
    Ok(())
}

/// Verifies that no embedded regions were added or removed on one side.
fn check_insertions_and_deletions(
    keys: RegionKeySets<'_>,
    ours_regions: &[EmbeddedRegion],
    theirs_regions: &[EmbeddedRegion],
    base_regions: &[EmbeddedRegion],
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let RegionKeySets {
        base_keys,
        ours_keys,
        theirs_keys,
    } = keys;
    for r_ours in ours_regions {
        if base_keys.contains_key(&r_ours.key) {
            continue;
        }
        if theirs_keys.contains_key(&r_ours.key) {
            let msg = format!(
                "competing same-gap insertion of region {:?}",
                r_ours.key.role
            );
            add_notice(
                collector,
                &request.path,
                None,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                msg,
            );
            return Err(DeclineReason::CompetingInsertion);
        }
        let msg = format!(
            "embedded region {:?} present on only one side",
            r_ours.key.role
        );
        add_notice(
            collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Err(DeclineReason::UnsupportedConstruct);
    }

    for r_theirs in theirs_regions {
        if base_keys.contains_key(&r_theirs.key) {
            continue;
        }
        let msg = format!(
            "embedded region {:?} present on only one side",
            r_theirs.key.role
        );
        add_notice(
            collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Err(DeclineReason::UnsupportedConstruct);
    }

    for r_base in base_regions {
        let in_ours = ours_keys.contains_key(&r_base.key);
        let in_theirs = theirs_keys.contains_key(&r_base.key);
        if !in_ours || !in_theirs {
            let msg = format!("embedded region {:?} deleted on one side", r_base.key.role);
            add_notice(
                collector,
                &request.path,
                None,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                msg,
            );
            return Err(DeclineReason::UnsupportedConstruct);
        }
    }

    Ok(())
}

/// Checks that delimiters, roles, and languages match across the triplet.
fn check_region_integrity(
    r_base: &EmbeddedRegion,
    r_ours: &EmbeddedRegion,
    r_theirs: &EmbeddedRegion,
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<(), DeclineReason> {
    let delim_changed = r_ours.start_delim != r_base.start_delim
        || r_theirs.start_delim != r_base.start_delim
        || r_ours.end_delim != r_base.end_delim
        || r_theirs.end_delim != r_base.end_delim;

    if delim_changed {
        let msg = format!("delimiters changed for region {:?}", r_base.key.role);
        add_notice(
            collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Err(DeclineReason::ChangedKey);
    }

    let role_changed = r_ours.key.role != r_base.key.role || r_theirs.key.role != r_base.key.role;
    let lang_changed = r_ours.declared_language != r_base.declared_language
        || r_theirs.declared_language != r_base.declared_language
        || r_ours.declared_lang_str != r_base.declared_lang_str
        || r_theirs.declared_lang_str != r_base.declared_lang_str;

    if role_changed || lang_changed {
        let msg = format!(
            "role or declared language changed for region {:?}",
            r_base.key.role
        );
        add_notice(
            collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Err(DeclineReason::ChangedKey);
    }

    Ok(())
}

/// Validates structural matching, uniqueness, and unchanged boundaries between inputs.
fn validate_matching<'a>(
    base_regions: &'a [EmbeddedRegion],
    ours_regions: &'a [EmbeddedRegion],
    theirs_regions: &'a [EmbeddedRegion],
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<Vec<(&'a EmbeddedRegion, &'a EmbeddedRegion, &'a EmbeddedRegion)>, DeclineReason> {
    let mut base_keys: HashMap<&RegionKey, usize> = HashMap::new();
    for r in base_regions {
        *base_keys.entry(&r.key).or_default() += 1;
    }
    let mut ours_keys: HashMap<&RegionKey, usize> = HashMap::new();
    for r in ours_regions {
        *ours_keys.entry(&r.key).or_default() += 1;
    }
    let mut theirs_keys: HashMap<&RegionKey, usize> = HashMap::new();
    for r in theirs_regions {
        *theirs_keys.entry(&r.key).or_default() += 1;
    }

    check_key_uniqueness(&base_keys, "base", request, collector)?;
    check_key_uniqueness(&ours_keys, "ours", request, collector)?;
    check_key_uniqueness(&theirs_keys, "theirs", request, collector)?;

    let keys = RegionKeySets {
        base_keys: &base_keys,
        ours_keys: &ours_keys,
        theirs_keys: &theirs_keys,
    };
    check_insertions_and_deletions(
        keys,
        ours_regions,
        theirs_regions,
        base_regions,
        request,
        collector,
    )?;

    let mut matched = Vec::with_capacity(base_regions.len());
    for r_base in base_regions {
        let Some(r_ours) = ours_regions.iter().find(|r| r.key == r_base.key) else {
            add_notice(
                collector,
                &request.path,
                None,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                "missing region in ours",
            );
            return Err(DeclineReason::UnsupportedConstruct);
        };
        let Some(r_theirs) = theirs_regions.iter().find(|r| r.key == r_base.key) else {
            add_notice(
                collector,
                &request.path,
                None,
                request.language.id(),
                NoticeCode::SyntaxAmbiguous,
                "missing region in theirs",
            );
            return Err(DeclineReason::UnsupportedConstruct);
        };

        check_region_integrity(r_base, r_ours, r_theirs, request, collector)?;
        matched.push((r_base, r_ours, r_theirs));
    }

    Ok(matched)
}

/// Merges a region changed on both sides using plain syntax adapter.
fn merge_competing_region<'a, 'c>(
    inputs: CompetingInputs<'a, 'c>,
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    collector: &mut NoticeCollector,
) -> Result<Result<Option<RegionEdit<'a>>, DeclineReason>, SyntaxError> {
    let CompetingInputs {
        r_base,
        base_content,
        ours_content,
        theirs_content,
    } = inputs;
    let Some(child_lang) = r_base.declared_language else {
        let msg = format!(
            "both sides changed unsupported preprocessor region {}",
            r_base.declared_lang_str
        );
        add_notice(
            collector,
            &request.path,
            None,
            &r_base.declared_lang_str,
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Ok(Err(DeclineReason::SameUnitChanged));
    };

    if adapter_for(child_lang).is_none() {
        let msg = format!("no plain adapter for child language {}", child_lang.id());
        add_notice(
            collector,
            &request.path,
            None,
            child_lang.id(),
            NoticeCode::EmbeddedLanguageUnsupported,
            msg,
        );
        return Ok(Err(DeclineReason::ComposedLanguage));
    }

    let child_req = SyntaxRequest {
        path: request.path.clone(),
        language: child_lang,
        base: base_content,
        ours: ours_content,
        theirs: theirs_content,
    };

    cancel.check()?;
    let child_outcome = merge_triplet(&child_req, registry, cancel)?;
    match child_outcome {
        SyntaxOutcome::Merged {
            bytes: child_bytes,
            notices: child_notices,
            ..
        } => {
            collector.absorb(child_notices);
            Ok(Ok(Some(RegionEdit {
                start: r_base.content_start,
                end: r_base.content_end,
                role: r_base.key.role,
                context: &r_base.key.context,
                declared_language: r_base.declared_language,
                replacement: child_bytes,
            })))
        }
        SyntaxOutcome::Declined {
            reason,
            detail: _,
            notices: child_notices,
        } => {
            collector.absorb(child_notices);
            Ok(Err(reason))
        }
    }
}

/// Merges a single embedded region or delegates to plain syntax engine.
fn merge_single_region<'a>(
    r_base: &'a EmbeddedRegion,
    r_ours: &'a EmbeddedRegion,
    r_theirs: &'a EmbeddedRegion,
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    collector: &mut NoticeCollector,
) -> Result<Result<Option<RegionEdit<'a>>, DeclineReason>, SyntaxError> {
    let base_content = &request.base[r_base.content_start..r_base.content_end];
    let ours_content = &request.ours[r_ours.content_start..r_ours.content_end];
    let theirs_content = &request.theirs[r_theirs.content_start..r_theirs.content_end];

    if ours_content == base_content && theirs_content == base_content {
        return Ok(Ok(None));
    }

    if ours_content != base_content && theirs_content == base_content {
        return Ok(Ok(Some(RegionEdit {
            start: r_base.content_start,
            end: r_base.content_end,
            role: r_base.key.role,
            context: &r_base.key.context,
            declared_language: r_base.declared_language,
            replacement: ours_content.to_vec(),
        })));
    }

    if ours_content == base_content && theirs_content != base_content {
        return Ok(Ok(Some(RegionEdit {
            start: r_base.content_start,
            end: r_base.content_end,
            role: r_base.key.role,
            context: &r_base.key.context,
            declared_language: r_base.declared_language,
            replacement: theirs_content.to_vec(),
        })));
    }

    if ours_content == theirs_content {
        return Ok(Ok(Some(RegionEdit {
            start: r_base.content_start,
            end: r_base.content_end,
            role: r_base.key.role,
            context: &r_base.key.context,
            declared_language: r_base.declared_language,
            replacement: ours_content.to_vec(),
        })));
    }

    let inputs = CompetingInputs {
        r_base,
        base_content,
        ours_content,
        theirs_content,
    };
    merge_competing_region(inputs, request, registry, cancel, collector)
}

/// Performs a single-pass streaming splice of sorted, non-overlapping replacements.
fn splice_edits(base: &[u8], edits: &[RegionEdit<'_>]) -> Result<Vec<u8>, DeclineReason> {
    for edit in edits {
        if edit.start > edit.end || edit.end > base.len() {
            return Err(DeclineReason::OverlappingEdits);
        }
    }
    for window in edits.windows(2) {
        if window[0].end > window[1].start {
            return Err(DeclineReason::OverlappingEdits);
        }
    }

    let mut merged = Vec::with_capacity(base.len());
    let mut cursor = 0;
    for edit in edits {
        merged.extend_from_slice(&base[cursor..edit.start]);
        merged.extend_from_slice(&edit.replacement);
        cursor = edit.end;
    }
    merged.extend_from_slice(&base[cursor..]);
    Ok(merged)
}

/// Verifies that a single altered region mapped bounds and byte coverage match.
fn verify_single_edit_boundary(
    edit: &RegionEdit<'_>,
    final_regions: &[EmbeddedRegion],
    merged_bytes: &[u8],
    shift: isize,
    req_lang: Language,
    path: &ByteString,
    collector: &mut NoticeCollector,
) -> Result<isize, DeclineReason> {
    let old_len =
        isize::try_from(edit.end - edit.start).map_err(|_| DeclineReason::UnsupportedConstruct)?;
    let new_len =
        isize::try_from(edit.replacement.len()).map_err(|_| DeclineReason::UnsupportedConstruct)?;
    let exp_start = match isize::try_from(edit.start)
        .ok()
        .and_then(|s| s.checked_add(shift))
        .and_then(|s| usize::try_from(s).ok())
    {
        Some(s) => s,
        None => return Err(DeclineReason::UnsupportedConstruct),
    };
    let exp_end = exp_start + edit.replacement.len();

    let matching = final_regions.iter().find(|fr| {
        fr.key.role == edit.role
            && fr.key.context.as_slice() == edit.context
            && fr.content_start == exp_start
            && fr.content_end == exp_end
    });

    let Some(fr) = matching else {
        let msg = format!(
            "altered region {:?} boundary changed in final parse",
            edit.role
        );
        add_notice(
            collector,
            path,
            None,
            req_lang.id(),
            NoticeCode::SyntaxAmbiguous,
            msg,
        );
        return Err(DeclineReason::UnsupportedConstruct);
    };

    if &merged_bytes[fr.content_start..fr.content_end] != edit.replacement.as_slice() {
        add_notice(
            collector,
            path,
            None,
            req_lang.id(),
            NoticeCode::SyntaxAmbiguous,
            "altered region byte coverage does not match replacement",
        );
        return Err(DeclineReason::UnsupportedConstruct);
    }

    Ok(new_len - old_len)
}

/// Verifies that an altered child region parses without ERROR nodes.
fn verify_child_syntax(
    edit: &RegionEdit<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    path: &ByteString,
    collector: &mut NoticeCollector,
) -> Result<Result<(), DeclineReason>, SyntaxError> {
    let Some(child_lang) = edit.declared_language else {
        return Ok(Ok(()));
    };
    let Some(cg) = registry.get(child_lang) else {
        return Ok(Ok(()));
    };
    let child_tree = cg.parse(&edit.replacement, cancel)?;
    if child_tree.has_error() {
        add_notice(
            collector,
            path,
            None,
            child_lang.id(),
            NoticeCode::SyntaxParseDeclined,
            "altered child region holds ERROR or missing nodes",
        );
        return Ok(Err(DeclineReason::ParseFailed));
    }
    Ok(Ok(()))
}

/// Verifies that the re-parsed host and child regions match expected boundaries.
fn verify_final(
    ctx: HostVerify<'_>,
    merged_bytes: &[u8],
    edits: &[RegionEdit<'_>],
    collector: &mut NoticeCollector,
) -> Result<Result<(), DeclineReason>, SyntaxError> {
    let HostVerify {
        host_grammar,
        registry,
        cancel,
        req_lang,
        path,
    } = ctx;
    cancel.check()?;
    let final_tree = match parse_host(
        host_grammar,
        merged_bytes,
        cancel,
        req_lang,
        path,
        "final",
        collector,
    )? {
        Ok(t) => t,
        Err(reason) => return Ok(Err(reason)),
    };

    let final_regions = match extract_regions(
        &final_tree,
        merged_bytes,
        req_lang,
        path,
        NoticeInput::Result,
        collector,
    ) {
        Ok(r) => r,
        Err(reason) => return Ok(Err(reason)),
    };

    let mut shift: isize = 0;
    for edit in edits {
        let delta = match verify_single_edit_boundary(
            edit,
            &final_regions,
            merged_bytes,
            shift,
            req_lang,
            path,
            collector,
        ) {
            Ok(d) => d,
            Err(reason) => return Ok(Err(reason)),
        };
        shift += delta;

        if let Err(reason) = verify_child_syntax(edit, registry, cancel, path, collector)? {
            return Ok(Err(reason));
        }
    }

    Ok(Ok(()))
}

/// Resolves trivial cases where no embedded region edits were produced.
fn resolve_unaltered_host(
    request: &ComposedRequest<'_>,
    collector: &mut NoticeCollector,
) -> Result<Vec<u8>, DeclineReason> {
    if request.ours == request.base && request.theirs == request.base {
        return Ok(request.base.to_vec());
    }
    if request.ours == request.theirs {
        return Ok(request.ours.to_vec());
    }
    if request.ours != request.base && request.theirs == request.base {
        return Ok(request.ours.to_vec());
    }
    if request.ours == request.base && request.theirs != request.base {
        return Ok(request.theirs.to_vec());
    }
    add_notice(
        collector,
        &request.path,
        None,
        request.language.id(),
        NoticeCode::SyntaxAmbiguous,
        "concurrent host changes outside embedded regions",
    );
    Err(DeclineReason::SameUnitChanged)
}

/// Merges one composed host file (HTML, Vue, Svelte) with syntax assistance.
///
/// # Errors
/// Cancellation returns [`SyntaxError::Cancelled`]. Boundary caller errors
/// return [`SyntaxError::Invalid`]. Host/embedded declines return
/// [`ComposedOutcome::Declined`].
pub fn merge_host(
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<ComposedOutcome, SyntaxError> {
    cancel.check()?;

    if request.path.is_empty() || request.path.as_bytes().contains(&0) {
        return Err(SyntaxError::Invalid {
            what: "merge path",
            detail: "path must be non-empty and contain no NUL".to_owned(),
        });
    }

    if request.mode == MergeMode::Git {
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::ComposedLanguage,
            notices: MergeNotices::default(),
        });
    }

    let mut collector = NoticeCollector::new();

    if let Err(reason) = validate_request(request, &mut collector) {
        return Ok(ComposedOutcome::Declined {
            reason,
            notices: collector.finish(),
        });
    }

    if !matches!(
        request.language,
        Language::Html | Language::Vue | Language::Svelte
    ) {
        let msg = format!("{} is not a supported host language", request.language.id());
        add_notice(
            &mut collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::EmbeddedLanguageUnsupported,
            msg,
        );
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::ComposedLanguage,
            notices: collector.finish(),
        });
    }

    let Some(host_grammar) = registry.get(request.language) else {
        let msg = format!("no host grammar registered for {}", request.language.id());
        add_notice(
            &mut collector,
            &request.path,
            None,
            request.language.id(),
            NoticeCode::EmbeddedLanguageUnsupported,
            msg,
        );
        return Ok(ComposedOutcome::Declined {
            reason: DeclineReason::ComposedLanguage,
            notices: collector.finish(),
        });
    };

    let base_tree = match parse_host(
        host_grammar,
        request.base,
        cancel,
        request.language,
        &request.path,
        "base",
        &mut collector,
    )? {
        Ok(tree) => tree,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };
    let ours_tree = match parse_host(
        host_grammar,
        request.ours,
        cancel,
        request.language,
        &request.path,
        "ours",
        &mut collector,
    )? {
        Ok(tree) => tree,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };
    let theirs_tree = match parse_host(
        host_grammar,
        request.theirs,
        cancel,
        request.language,
        &request.path,
        "theirs",
        &mut collector,
    )? {
        Ok(tree) => tree,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };

    let base_regions = match extract_regions(
        &base_tree,
        request.base,
        request.language,
        &request.path,
        NoticeInput::Base,
        &mut collector,
    ) {
        Ok(r) => r,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };
    let ours_regions = match extract_regions(
        &ours_tree,
        request.ours,
        request.language,
        &request.path,
        NoticeInput::Ours,
        &mut collector,
    ) {
        Ok(r) => r,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };
    let theirs_regions = match extract_regions(
        &theirs_tree,
        request.theirs,
        request.language,
        &request.path,
        NoticeInput::Theirs,
        &mut collector,
    ) {
        Ok(r) => r,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };

    let matched = match validate_matching(
        &base_regions,
        &ours_regions,
        &theirs_regions,
        request,
        &mut collector,
    ) {
        Ok(m) => m,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };

    let mut edits = Vec::new();
    for (r_base, r_ours, r_theirs) in matched {
        match merge_single_region(
            r_base,
            r_ours,
            r_theirs,
            request,
            registry,
            cancel,
            &mut collector,
        )? {
            Ok(Some(edit)) => edits.push(edit),
            Ok(None) => {}
            Err(reason) => {
                return Ok(ComposedOutcome::Declined {
                    reason,
                    notices: collector.finish(),
                });
            }
        }
    }

    if edits.is_empty() {
        return match resolve_unaltered_host(request, &mut collector) {
            Ok(bytes) => Ok(ComposedOutcome::Clean {
                bytes,
                notices: collector.finish(),
            }),
            Err(reason) => Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            }),
        };
    }

    edits.sort_by_key(|e| e.start);
    let merged_bytes = match splice_edits(request.base, &edits) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return Ok(ComposedOutcome::Declined {
                reason,
                notices: collector.finish(),
            });
        }
    };

    let ctx = HostVerify {
        host_grammar,
        registry,
        cancel,
        req_lang: request.language,
        path: &request.path,
    };
    if let Err(reason) = verify_final(ctx, &merged_bytes, &edits, &mut collector)? {
        return Ok(ComposedOutcome::Declined {
            reason,
            notices: collector.finish(),
        });
    }

    Ok(ComposedOutcome::Clean {
        bytes: merged_bytes,
        notices: collector.finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::syntax::treesitter::TsGrammar;

    struct DelegatedGrammar(TsGrammar, Language);

    impl Grammar for DelegatedGrammar {
        fn language(&self) -> Language {
            self.1
        }

        fn parse(&self, source: &[u8], cancel: &Cancel) -> Result<ParsedTree, SyntaxError> {
            self.0.parse(source, cancel)
        }
    }

    fn test_registry<'a>(
        html: &'a TsGrammar,
        js: &'a TsGrammar,
        css: &'a TsGrammar,
        vue: Option<&'a TsGrammar>,
        svelte: Option<&'a dyn Grammar>,
    ) -> GrammarRegistry<'a> {
        let mut reg = GrammarRegistry::new();
        reg.insert(html);
        reg.insert(js);
        reg.insert(css);
        if let Some(v) = vue {
            reg.insert(v);
        }
        if let Some(s) = svelte {
            reg.insert(s);
        }
        reg
    }

    #[test]
    fn test_two_independent_edits_clean() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");
        let reg = test_registry(&html_g, &js_g, &css_g, None, None);

        let base = b"<!doctype html>\n<html>\n<head>\n<script>\nconsole.log(\"base\");\n</script>\n<style>\nbody { color: black; }\n</style>\n</head>\n<body><p>ready</p></body>\n</html>\n";
        let ours = b"<!doctype html>\n<html>\n<head>\n<script>\nconsole.log(\"ours\");\n</script>\n<style>\nbody { color: black; }\n</style>\n</head>\n<body><p>ready</p></body>\n</html>\n";
        let theirs = b"<!doctype html>\n<html>\n<head>\n<script>\nconsole.log(\"base\");\n</script>\n<style>\nbody { color: blue; }\n</style>\n</head>\n<body><p>ready</p></body>\n</html>\n";

        let req = ComposedRequest {
            path: ByteString::from("index.html"),
            language: Language::Html,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Clean { bytes, notices: _ } = outcome else {
            panic!("expected Clean, got {outcome:?}");
        };
        let merged_str = String::from_utf8(bytes).expect("valid utf-8");
        assert!(merged_str.contains("console.log(\"ours\");"));
        assert!(merged_str.contains("body { color: blue; }"));
        assert!(merged_str.starts_with("<!doctype html>\n<html>\n<head>\n<script>"));
        assert!(merged_str.ends_with("</style>\n</head>\n<body><p>ready</p></body>\n</html>\n"));
    }

    #[test]
    fn test_changed_lang_attribute_declines() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");
        let reg = test_registry(&html_g, &js_g, &css_g, None, None);

        let base = b"<script lang=\"ts\">\nlet x: number = 1;\n</script>\n";
        let ours = b"<script lang=\"js\">\nlet x = 1;\n</script>\n";
        let theirs = b"<script lang=\"ts\">\nlet x: number = 2;\n</script>\n";

        let req = ComposedRequest {
            path: ByteString::from("index.html"),
            language: Language::Html,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Declined { reason, notices } = outcome else {
            panic!("expected Declined, got {outcome:?}");
        };
        assert_eq!(reason, DeclineReason::ChangedKey);
        assert!(!notices.is_empty());
        assert_eq!(notices.entries()[0].code(), NoticeCode::SyntaxAmbiguous);
    }

    #[test]
    fn test_region_present_on_only_one_side_declines() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");
        let reg = test_registry(&html_g, &js_g, &css_g, None, None);

        let base = b"<div>\n<script>\nconsole.log(1);\n</script>\n</div>\n";
        let ours = b"<div>\n<p>deleted script</p>\n</div>\n";
        let theirs = b"<div>\n<script>\nconsole.log(1);\n</script>\n</div>\n";

        let req = ComposedRequest {
            path: ByteString::from("index.html"),
            language: Language::Html,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Declined { reason, notices } = outcome else {
            panic!("expected Declined, got {outcome:?}");
        };
        assert_eq!(reason, DeclineReason::UnsupportedConstruct);
        assert!(!notices.is_empty());
    }

    #[test]
    fn test_competing_same_gap_insertion_declines() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");
        let reg = test_registry(&html_g, &js_g, &css_g, None, None);

        let base = b"<div>\n<p>base</p>\n</div>\n";
        let ours = b"<div>\n<p>base</p>\n<script>\nconsole.log(\"ours\");\n</script>\n</div>\n";
        let theirs = b"<div>\n<p>base</p>\n<script>\nconsole.log(\"theirs\");\n</script>\n</div>\n";

        let req = ComposedRequest {
            path: ByteString::from("index.html"),
            language: Language::Html,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Declined { reason, notices } = outcome else {
            panic!("expected Declined, got {outcome:?}");
        };
        assert_eq!(reason, DeclineReason::CompetingInsertion);
        assert!(!notices.is_empty());
        assert_eq!(notices.entries()[0].code(), NoticeCode::SyntaxAmbiguous);
    }

    #[test]
    fn test_vue_script_vs_script_setup_roles() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");
        let vue_g = TsGrammar::vue().expect("tree-sitter vue loads");
        let reg = test_registry(&html_g, &js_g, &css_g, Some(&vue_g), None);

        let base = b"<template>\n  <p>{{ msg }}</p>\n</template>\n<script setup>\nconst msg = \"base-setup\";\n</script>\n<script>\nexport default { name: \"AppBase\" };\n</script>\n";
        let ours = b"<template>\n  <p>{{ msg }}</p>\n</template>\n<script setup>\nconst msg = \"ours-setup\";\n</script>\n<script>\nexport default { name: \"AppBase\" };\n</script>\n";
        let theirs = b"<template>\n  <p>{{ msg }}</p>\n</template>\n<script setup>\nconst msg = \"base-setup\";\n</script>\n<script>\nexport default { name: \"AppTheirs\" };\n</script>\n";

        let req = ComposedRequest {
            path: ByteString::from("App.vue"),
            language: Language::Vue,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Clean { bytes, notices: _ } = outcome else {
            panic!("expected Clean, got {outcome:?}");
        };
        let merged_str = String::from_utf8(bytes).expect("valid utf-8");
        assert!(merged_str.contains("const msg = \"ours-setup\";"));
        assert!(merged_str.contains("export default { name: \"AppTheirs\" };"));
    }

    #[test]
    fn test_svelte_module_vs_instance_roles() {
        let html_g = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let js_g = TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE)
            .expect("tree-sitter js loads");
        let css_g = TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE)
            .expect("tree-sitter css loads");

        let svelte_inner = TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE)
            .expect("tree-sitter html loads");
        let svelte_g = DelegatedGrammar(svelte_inner, Language::Svelte);
        let reg = test_registry(&html_g, &js_g, &css_g, None, Some(&svelte_g));

        let base = b"<script module>\nlet total = 0;\n</script>\n<script>\nlet count = 1;\n</script>\n<p>{count}</p>\n";
        let ours = b"<script module>\nlet total = 100;\n</script>\n<script>\nlet count = 1;\n</script>\n<p>{count}</p>\n";
        let theirs = b"<script module>\nlet total = 0;\n</script>\n<script>\nlet count = 42;\n</script>\n<p>{count}</p>\n";

        let req = ComposedRequest {
            path: ByteString::from("Counter.svelte"),
            language: Language::Svelte,
            base,
            ours,
            theirs,
            mode: MergeMode::Syntax,
        };

        let outcome = merge_host(&req, &reg, &Cancel::never()).expect("merge succeeds");
        let ComposedOutcome::Clean { bytes, notices: _ } = outcome else {
            panic!("expected Clean, got {outcome:?}");
        };
        let merged_str = String::from_utf8(bytes).expect("valid utf-8");
        assert!(merged_str.contains("let total = 100;"));
        assert!(merged_str.contains("let count = 42;"));
    }
}
