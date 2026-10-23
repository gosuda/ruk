//! Structural source-unit adapters for every plain language.
//!
//! Each adapter recognizes the safe source units of one language family,
//! preserves byte trivia and ordering, and declines cases whose identity or
//! placement is ambiguous. Adapters work only with [`ParsedTree`] indices:
//! the parser is a byte index, never a printer, and no adapter reformats,
//! sorts, or copies whole ASTs.
//!
//! Grouping mirrors the language plan: `code` (Rust, Go, C, C++, Java, C#,
//! Kotlin, Swift), `web` (JavaScript, TypeScript, TSX), `script` (Python,
//! Ruby, PHP, Bash, Lua), `ml` (OCaml implementation and interface), `data`
//! (JSON, TOML, YAML, CSS, HTML). Composed languages (Vue, Svelte,
//! Markdown, MDX, notebooks) have catalogue entries in [`super::grammar`]
//! but no adapter here; the plain merger declines them before dispatching.

pub mod code;
pub mod data;
pub mod ml;
pub mod script;
pub mod web;

use std::collections::HashMap;

use crate::merge::syntax::grammar::{Language, ParsedTree};

/// Maximum container-descent depth in adapter extraction. Deeper subtrees
/// stay gaps and decline when touched rather than risking stack exhaustion
/// on adversarial input.
pub const MAX_WALK_DEPTH: usize = 256;

/// Adapter-rule revision covered by the manifest digest. Bump whenever unit
/// recognition, key construction, dispatch-adjacent adapter behavior, or
/// structural decline rules change; the digest then forces a
/// `language_set_version` revision instead of a cache-compatible build.
pub const ADAPTER_RULES_REVISION: u32 = 1;

/// Why the syntax stage declines a triplet to bounded text merge. Every
/// variant maps to exactly one existing [`NoticeCode`](crate::merge::composed::NoticeCode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeclineReason {
    /// The same unit changed on both sides.
    SameUnitChanged,
    /// A structural key occurs more than once with differing bytes.
    DuplicateKey,
    /// A unit's key matches by name but its parent context moved.
    ChangedKey,
    /// A rename or attachment is ambiguous.
    AmbiguousRename,
    /// Both sides inserted into the same gap.
    CompetingInsertion,
    /// Collected edits overlap or invert order.
    OverlappingEdits,
    /// A language-specific unsupported construct (macro boundary, anchor,
    /// heredoc scope, mixed-language crossing, multiline string).
    UnsupportedConstruct,
    /// A side failed to parse or holds ERROR/missing nodes.
    ParseFailed,
    /// The triplet exceeds [`MAX_TRIPLET_BYTES`](super::grammar::MAX_TRIPLET_BYTES).
    SizeLimit,
    /// An input is not scannable source (NUL bytes, invalid UTF-8).
    BinaryContent,
    /// A composed language reached the plain merger.
    ComposedLanguage,
    /// The selected grammar has no registered provider.
    GrammarUnavailable,
}

impl DeclineReason {
    /// Stable machine spelling for fixtures and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameUnitChanged => "same-unit-changed",
            Self::DuplicateKey => "duplicate-key",
            Self::ChangedKey => "changed-key",
            Self::AmbiguousRename => "ambiguous-rename",
            Self::CompetingInsertion => "competing-insertion",
            Self::OverlappingEdits => "overlapping-edits",
            Self::UnsupportedConstruct => "unsupported-construct",
            Self::ParseFailed => "parse-failed",
            Self::SizeLimit => "size-limit",
            Self::BinaryContent => "binary-content",
            Self::ComposedLanguage => "composed-language",
            Self::GrammarUnavailable => "grammar-unavailable",
        }
    }

    /// The single existing notice code reporting this decline.
    #[must_use]
    pub const fn notice_code(self) -> crate::merge::composed::NoticeCode {
        use crate::merge::composed::NoticeCode;
        match self {
            Self::SameUnitChanged
            | Self::DuplicateKey
            | Self::ChangedKey
            | Self::AmbiguousRename
            | Self::CompetingInsertion
            | Self::OverlappingEdits
            | Self::UnsupportedConstruct => NoticeCode::SyntaxAmbiguous,
            Self::ParseFailed | Self::BinaryContent => NoticeCode::SyntaxParseDeclined,
            Self::SizeLimit => NoticeCode::SyntaxLimit,
            Self::ComposedLanguage => NoticeCode::EmbeddedLanguageUnsupported,
            Self::GrammarUnavailable => NoticeCode::SyntaxWorkerFailed,
        }
    }
}

/// A decline with caller-facing diagnostic detail. Detail is diagnostic
/// text, never a parser contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decline {
    /// Machine-readable reason.
    pub reason: DeclineReason,
    /// One-line diagnostic naming the unit, key, or range involved.
    pub detail: String,
}

impl Decline {
    #[must_use]
    pub fn new(reason: DeclineReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

/// Structural identity of one source unit: node kind, declared name, the
/// language-specific discriminator (signature, receiver, key path), and the
/// flattened lexical-parent chain. Keys never consist of a global name
/// alone; the parent context and discriminator are always part of equality.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnitKey {
    /// Tree-sitter node kind of the unit.
    pub kind: String,
    /// Declared name bytes (empty for units that decline unnamed matching).
    pub name: Vec<u8>,
    /// Language discriminator: signature, receiver, key path, selector.
    pub discriminator: Vec<u8>,
    /// Lexical-parent names from outermost to innermost, joined by NUL.
    pub parent: Vec<u8>,
}

impl UnitKey {
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        name: Vec<u8>,
        discriminator: Vec<u8>,
        parent: Vec<u8>,
    ) -> Self {
        Self {
            kind: kind.into(),
            name,
            discriminator,
            parent,
        }
    }

    /// Short `(kind, name)` pair used only to detect parent moves
    /// ([`DeclineReason::ChangedKey`]); never used for pairing.
    #[must_use]
    pub fn short(&self) -> (&str, &[u8]) {
        (self.kind.as_str(), self.name.as_slice())
    }
}

impl core::fmt::Display for UnitKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}:{}:{}@{}",
            self.kind,
            String::from_utf8_lossy(&self.name),
            String::from_utf8_lossy(&self.discriminator),
            String::from_utf8_lossy(&self.parent),
        )
    }
}

/// One candidate merge unit: an unambiguous named declaration with its exact
/// byte range (including conservatively attached trivia) and its defining
/// node in the parsed tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUnit {
    /// Structural identity.
    pub key: UnitKey,
    /// Half-open byte range in the parsed source, trivia included.
    pub start: u32,
    /// Half-open byte end in the parsed source, trivia included.
    pub end: u32,
    /// Defining node index in the parsed tree.
    pub node: u32,
}

/// One language's structural rules: which nodes are safe units, how their
/// keys are built, when a whole tree is vetoed, and how a doubly-changed
/// unit decomposes into child units for one recursive descent step.
pub trait Adapter {
    /// The catalogued language this adapter implements.
    fn language(&self) -> Language;

    /// Extracts candidate merge units in source order. Units must be
    /// non-overlapping; empty-name units are allowed only when the adapter
    /// documents them as byte-identical-or-decline (the driver enforces
    /// that). Spans the adapter cannot attribute stay uncovered and become
    /// gaps, which the driver treats conservatively.
    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit>;

    /// Whole-tree conservative veto over all three parsed inputs. Returns a
    /// decline when the file uses a construct this adapter never merges
    /// structurally (YAML anchors, TOML multiline edits, PHP template
    /// crossings, notebook-scale embedded delegation). `None` passes.
    fn veto(
        &self,
        _base: &ParsedTree,
        _base_src: &[u8],
        _ours: &ParsedTree,
        _ours_src: &[u8],
        _theirs: &ParsedTree,
        _theirs_src: &[u8],
    ) -> Option<Decline> {
        None
    }

    /// Decomposes a doubly-changed unit into child units for one recursive
    /// descent step (class members, object entries, rule declarations). The
    /// default is no descent: the unit is atomic and any double change
    /// declines. Implementations read the defining `node` from the parsed
    /// tree; child ranges must lie strictly inside the unit range.
    fn children(&self, _tree: &ParsedTree, _source: &[u8], _node: u32) -> Vec<SourceUnit> {
        Vec::new()
    }

    /// Separator bytes the insertion check ignores alongside whitespace, so
    /// a member insertion that adds a comma or semicolon beside its new unit
    /// still proves the surrounding gap bytes. The default is none: most
    /// languages separate units with whitespace alone.
    fn separators(&self) -> &[u8] {
        &[]
    }
}

/// Returns the adapter for a plain language, or `None` for composed
/// languages (which the driver declines before consulting adapters).
#[must_use]
pub fn adapter_for(language: Language) -> Option<&'static dyn Adapter> {
    Some(match language {
        Language::Rust => &code::RustAdapter as &dyn Adapter,
        Language::Go => &code::GoAdapter as &dyn Adapter,
        Language::C => &code::CAdapter as &dyn Adapter,
        Language::Cpp => &code::CppAdapter as &dyn Adapter,
        Language::Java => &code::JavaAdapter as &dyn Adapter,
        Language::CSharp => &code::CSharpAdapter as &dyn Adapter,
        Language::Kotlin => &code::KotlinAdapter as &dyn Adapter,
        Language::Swift => &code::SwiftAdapter as &dyn Adapter,
        Language::Javascript => &web::JavascriptAdapter as &dyn Adapter,
        Language::Typescript => &web::TypescriptAdapter as &dyn Adapter,
        Language::Tsx => &web::TsxAdapter as &dyn Adapter,
        Language::Python => &script::PythonAdapter as &dyn Adapter,
        Language::Ruby => &script::RubyAdapter as &dyn Adapter,
        Language::Php => &script::PhpAdapter as &dyn Adapter,
        Language::Bash => &script::BashAdapter as &dyn Adapter,
        Language::Lua => &script::LuaAdapter as &dyn Adapter,
        Language::Ocaml => &ml::OcamlAdapter as &dyn Adapter,
        Language::OcamlInterface => &ml::OcamlInterfaceAdapter as &dyn Adapter,
        Language::Json => &data::JsonAdapter as &dyn Adapter,
        Language::Toml => &data::TomlAdapter as &dyn Adapter,
        Language::Yaml => &data::YamlAdapter as &dyn Adapter,
        Language::Css => &data::CssAdapter as &dyn Adapter,
        Language::Html => &data::HtmlAdapter as &dyn Adapter,
        Language::Vue
        | Language::Svelte
        | Language::Markdown
        | Language::Mdx
        | Language::Notebook => return None,
    })
}

/// Converts a `u32` byte offset to `usize` for slicing.
pub fn offset(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

/// Slices `source` to `start..end`, clamped. Returns `None` on inverted or
/// out-of-range spans.
#[must_use]
pub fn slice_range(source: &[u8], start: u32, end: u32) -> Option<&[u8]> {
    let start = offset(start)?;
    let end = offset(end)?;
    if start > end || end > source.len() {
        return None;
    }
    Some(&source[start..end])
}

/// Declared-name bytes of `node`: the text of the child on the `name` field
/// edge, or — for grammars that put the declarator on a differently named
/// edge — the first candidate in `alt_fields`. Returns an empty vector when
/// no name edge exists; callers treat empty names as unnamed units.
pub fn declared_name(tree: &ParsedTree, source: &[u8], node: u32, alt_fields: &[&str]) -> Vec<u8> {
    if let Some(name) = tree.child_with_field(node, "name") {
        return tree.text_of(name, source).to_vec();
    }
    for field in alt_fields {
        if let Some(name) = tree.child_with_field(node, field) {
            return tree.text_of(name, source).to_vec();
        }
    }
    Vec::new()
}

/// Discriminator bytes: the exact source text of the first child matching
/// one of `kinds` (parameter lists, receivers, key paths), normalized only
/// by taking the raw bytes. Empty when absent.
pub fn discriminator_by_kind(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    kinds: &[&str],
) -> Vec<u8> {
    tree.named_children(node)
        .into_iter()
        .find(|child| kinds.contains(&tree.kind_of(*child)))
        .map_or_else(Vec::new, |child| tree.text_of(child, source).to_vec())
}

/// Whether `bytes` hold a blank line (two line breaks with only whitespace
/// between), which breaks comment attachment.
fn has_blank_line(bytes: &[u8]) -> bool {
    let mut breaks = 0_u32;
    for byte in bytes {
        if *byte == b'\n' {
            breaks += 1;
            if breaks >= 2 {
                return true;
            }
        } else if !byte.is_ascii_whitespace() {
            return false;
        }
    }
    false
}

/// Extends `start` backwards over attached leading comment lines. A comment
/// sibling attaches only when it is a comment-kind node on the lines
/// immediately above with no blank line and no other code between. Attribute
/// nodes listed in `attr_kinds` attach the same way. Grammars that nest
/// decorators/annotations inside the declaration node need no trivia walk;
/// this helper covers grammars where they are preceding siblings.
pub fn attach_leading_trivia(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    comment_kinds: &[&str],
    attr_kinds: &[&str],
) -> u32 {
    let Some(record) = tree.get(node) else {
        return tree.get(node).map_or(0, |n| n.start);
    };
    let mut start = record.start;
    let mut cursor = tree.prev_sibling(node);
    while cursor != super::grammar::NODE_NONE {
        let Some(prev) = tree.get(cursor) else {
            break;
        };
        let kind = tree.kind_of(cursor);
        if !comment_kinds.contains(&kind) && !attr_kinds.contains(&kind) {
            break;
        }
        let between = slice_range(source, prev.end, start).unwrap_or(b"");
        if between.iter().any(|b| !b.is_ascii_whitespace()) || has_blank_line(between) {
            break;
        }
        start = prev.start;
        cursor = tree.prev_sibling(cursor);
    }
    start
}

/// Indexes units by key, reporting the first duplicated key whose units
/// differ in bytes. Returns the map plus an optional duplicate decline when
/// `strict_if_differ` finds differing duplicates. Code families pass
/// `strict_if_differ = true` semantics through the driver (overloads and
/// reopenings decline only when touched); data families pre-veto duplicates
/// in their `veto`.
pub fn index_units<'u>(
    units: &'u [SourceUnit],
    source: &[u8],
    others: &[(&[SourceUnit], &[u8])],
) -> (HashMap<&'u UnitKey, usize>, Option<Decline>) {
    let mut map: HashMap<&'u UnitKey, usize> = HashMap::new();
    let mut dups: HashMap<&'u UnitKey, Vec<usize>> = HashMap::new();
    for (index, unit) in units.iter().enumerate() {
        if map.insert(&unit.key, index).is_some() {
            dups.entry(&unit.key).or_default().push(index);
        }
    }
    // Include the first occurrence in each duplicate group.
    for (index, unit) in units.iter().enumerate() {
        if let Some(group) = dups.get_mut(&unit.key)
            && !group.contains(&index)
        {
            group.push(index);
        }
    }
    for (key, group) in &dups {
        let mut texts: Vec<&[u8]> = group
            .iter()
            .filter_map(|i| slice_range(source, units[*i].start, units[*i].end))
            .collect();
        for (other_units, other_src) in others {
            for other in other_units.iter().filter(|u| &u.key == *key) {
                if let Some(text) = slice_range(other_src, other.start, other.end) {
                    texts.push(text);
                }
            }
        }
        let first = texts.first().copied().unwrap_or(b"");
        if texts.iter().any(|text| *text != first) {
            return (
                map,
                Some(Decline::new(
                    DeclineReason::DuplicateKey,
                    format!("duplicate unit key `{key}` with differing bytes"),
                )),
            );
        }
    }
    (map, None)
}
