//! Revset expression syntax and Pratt parser.
//!
//! # Revset Grammar & Precedence
//!
//! The grammar conforms to `local://ruk-graph-implementation-contract.md`
//! and `local://ruk-core-contract-plan.md`, with operator precedence grounded
//! in Jujutsu (`jj`):
//!
//! 1. Primary / Atoms (tightest):
//!    - Working copy head `@`
//!    - Parents of working copy head `@-`
//!    - Symbol / identifier / branch / tag / commit / change name
//!    - Quoted string literal (`"..."` or `'...'`)
//!    - Contracted functions:
//!      - `heads(x)`, `roots(x)`, `ancestors(x)`, `descendants(x)`
//!      - `bookmarks([pattern])`, `remote_bookmarks([pattern])`, `tags([pattern])`
//!      - `conflicted()`, `divergent()`, `mine()`
//!      - `session(id)`, `change(prefix)`, `description(text)`, `files(glob)`
//!      - `attested(kind, result)`
//!    - Parenthesized grouping (`( expr )`)
//! 2. Binary Infix Ranges:
//!    - `x::y` (DAG range) and `x..y` (ancestors(rhs) ~ ancestors(lhs)) (`BP = 40, 41`)
//!    - Range chaining without parentheses (`a::b::c` or `a..b..c`) is explicitly rejected.
//! 3. Unary Prefix Negation `~`:
//!    - `~x` (complement, `BP = 30`)
//! 4. Binary Infix Intersection `&` and Difference `~`:
//!    - `x & y` and `x ~ y` (left-associative, equal precedence, `BP = 20, 21`)
//! 5. Binary Infix Union `|`:
//!    - `x | y` (left-associative, lowest precedence, `BP = 10, 11`)
//!
//! # Stack Safety & Flat Arena Architecture
//!
//! - **Zero recursive drop**: The AST is represented as a typed flat arena
//!   ([`AstArena`]), where nodes refer to children using opaque 32-bit indices
//!   ([`NodeId`]). Dropping a [`RevsetAst`] performs a single flat loop over
//!   `Vec<Node>` and `Vec<String>` with zero call stack frames, preventing stack
//!   overflows on large or deeply chained expressions.
//! - **Bounded parser recursion**: Recursive expression parsing is strictly
//!   bounded by [`MAX_PARSE_DEPTH`] (128). Inputs exceeding this depth are
//!   rejected with `ErrorCode::EInvalid`.
//! - **Bounded arena allocation**: Total node count is bounded by
//!   [`MAX_AST_NODES`] (65,536, identical to [`crate::protocol::MAX_REVSET_BYTES`]).

use core::fmt;

use logos::Logos;

use crate::error::{CoreError, ErrorCode};
use crate::protocol::{RevsetText, MAX_REVSET_BYTES};

/// Maximum nesting depth allowed during recursive Pratt parsing.
pub const MAX_PARSE_DEPTH: usize = 128;

/// Maximum number of AST nodes permitted in one revset arena.
pub const MAX_AST_NODES: usize = MAX_REVSET_BYTES; // 65,536

/// Byte range within UTF-8 revset source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn empty(pos: usize) -> Self {
        Self {
            start: pos,
            end: pos,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    #[must_use]
    pub fn join(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl From<core::ops::Range<usize>> for Span {
    fn from(r: core::ops::Range<usize>) -> Self {
        Self::new(r.start, r.end)
    }
}

impl From<Span> for core::ops::Range<usize> {
    fn from(s: Span) -> Self {
        s.start..s.end
    }
}

/// Opaque index into the flat node arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub(crate) u32);

impl NodeId {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// Opaque index into the string arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StringId(pub(crate) u32);

impl StringId {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// Kind of an AST node in the flat arena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    // --- Primaries / Atoms ---
    /// Working copy head (`@`).
    At,
    /// Parents of working copy head (`@-`).
    AtMinus,
    /// Unresolved symbol / ref name.
    Symbol(StringId),
    /// Quoted string literal.
    StringLiteral(StringId),

    // --- Contracted Functions with Plain String Arguments ---
    /// `session(id)`: Filter by session ID.
    Session(StringId),
    /// `change(prefix)`: Filter by change prefix.
    Change(StringId),
    /// `description(text)`: Filter by commit description text.
    Description(StringId),
    /// `files(glob)`: Filter by changed file glob pattern.
    Files(StringId),
    /// `attested(kind, result)`: Filter by attestation kind and result.
    Attested {
        kind: StringId,
        result: StringId,
    },

    // --- Contracted Functions with Expression Arguments ---
    /// `heads(x)`: Commits in `x` that are not ancestors of other commits in `x`.
    Heads(NodeId),
    /// `roots(x)`: Commits in `x` that are not descendants of other commits in `x`.
    Roots(NodeId),
    /// `ancestors(x)`: Commits that are ancestors of `x` (including `x`).
    Ancestors(NodeId),
    /// `descendants(x)`: Commits that are descendants of `x` (including `x`).
    Descendants(NodeId),

    // --- Contracted Functions with Optional String Pattern Filter ---
    /// `bookmarks([pattern])`: Bookmark targets matching optional pattern.
    Bookmarks(Option<NodeId>),
    /// `remote_bookmarks([pattern])`: Remote bookmark targets matching optional pattern.
    RemoteBookmarks(Option<NodeId>),
    /// `tags([pattern])`: Tag targets matching optional pattern.
    Tags(Option<NodeId>),

    // --- Contracted Nullary Functions ---
    /// `conflicted()`: Commits with conflicts.
    Conflicted,
    /// `divergent()`: Commits in a divergent state.
    Divergent,
    /// `mine()`: Commits authored by the current user/session.
    Mine,

    // --- Unary Prefix Operator ---
    /// Negation / complement (`~rhs`).
    Negate(NodeId),

    // --- Binary Infix Operators ---
    /// Intersection (`lhs & rhs`).
    Intersection(NodeId, NodeId),
    /// Union (`lhs | rhs`).
    Union(NodeId, NodeId),
    /// Set difference (`lhs ~ rhs`).
    Difference(NodeId, NodeId),
    /// DAG range (`lhs::rhs`: descendants of lhs that are ancestors of rhs).
    DagRange(NodeId, NodeId),
    /// Range (`lhs..rhs` = `ancestors(rhs) ~ ancestors(lhs)`).
    Range(NodeId, NodeId),

    // --- Grouping ---
    /// Explicit parenthesized grouping (`( expr )`).
    Group(NodeId),
}

/// AST Node containing node kind and source span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: NodeKind,
    pub span: Span,
}

/// Flat arena storing all AST nodes and string payloads.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AstArena {
    pub(crate) nodes: Vec<Node>,
    pub(crate) strings: Vec<String>,
}

impl AstArena {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[must_use]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.as_usize()]
    }

    #[must_use]
    pub fn string(&self, id: StringId) -> &str {
        &self.strings[id.as_usize()]
    }

    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    #[must_use]
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    pub fn alloc_node(&mut self, kind: NodeKind, span: Span) -> Result<NodeId, RevsetParseError> {
        let Ok(index) = u32::try_from(self.nodes.len()) else {
            return Err(RevsetParseError::invalid(
                format!("revset expression node count exceeded limit of {MAX_AST_NODES}"),
                span,
            ));
        };
        if self.nodes.len() >= MAX_AST_NODES {
            return Err(RevsetParseError::invalid(
                format!("revset expression node count exceeded limit of {MAX_AST_NODES}"),
                span,
            ));
        }
        let id = NodeId(index);
        self.nodes.push(Node { kind, span });
        Ok(id)
    }

    pub fn alloc_string(&mut self, s: String) -> Result<StringId, RevsetParseError> {
        let Ok(index) = u32::try_from(self.strings.len()) else {
            return Err(RevsetParseError::invalid(
                format!("revset expression string count exceeded limit of {MAX_AST_NODES}"),
                Span::empty(0),
            ));
        };
        if self.strings.len() >= MAX_AST_NODES {
            return Err(RevsetParseError::invalid(
                format!("revset expression string count exceeded limit of {MAX_AST_NODES}"),
                Span::empty(0),
            ));
        }
        let id = StringId(index);
        self.strings.push(s);
        Ok(id)
    }

    /// Returns the immediate children of the node identified by `id`.
    #[must_use]
    pub fn children(&self, id: NodeId) -> smallvec::SmallVec<[NodeId; 2]> {
        let node = self.node(id);
        match &node.kind {
            NodeKind::At
            | NodeKind::AtMinus
            | NodeKind::Symbol(_)
            | NodeKind::StringLiteral(_)
            | NodeKind::Session(_)
            | NodeKind::Change(_)
            | NodeKind::Description(_)
            | NodeKind::Files(_)
            | NodeKind::Attested { .. }
            | NodeKind::Conflicted
            | NodeKind::Divergent
            | NodeKind::Mine => smallvec::SmallVec::new(),

            NodeKind::Bookmarks(opt)
            | NodeKind::RemoteBookmarks(opt)
            | NodeKind::Tags(opt) => {
                if let Some(child) = opt {
                    smallvec::smallvec![*child]
                } else {
                    smallvec::SmallVec::new()
                }
            }

            NodeKind::Heads(c)
            | NodeKind::Roots(c)
            | NodeKind::Ancestors(c)
            | NodeKind::Descendants(c)
            | NodeKind::Negate(c)
            | NodeKind::Group(c) => smallvec::smallvec![*c],

            NodeKind::Intersection(l, r)
            | NodeKind::Union(l, r)
            | NodeKind::Difference(l, r)
            | NodeKind::DagRange(l, r)
            | NodeKind::Range(l, r) => smallvec::smallvec![*l, *r],
        }
    }
}

/// Complete parsed revset expression with root node and flat arena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevsetAst {
    pub(crate) arena: AstArena,
    pub(crate) root: NodeId,
    pub(crate) text: String,
}

impl RevsetAst {
    #[must_use]
    pub fn root(&self) -> &Node {
        self.arena.node(self.root)
    }

    #[must_use]
    pub fn root_id(&self) -> NodeId {
        self.root
    }

    #[must_use]
    pub fn node(&self, id: NodeId) -> &Node {
        self.arena.node(id)
    }

    #[must_use]
    pub fn string(&self, id: StringId) -> &str {
        self.arena.string(id)
    }

    #[must_use]
    pub fn arena(&self) -> &AstArena {
        &self.arena
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.arena.len()
    }

    #[must_use]
    pub fn children(&self, id: NodeId) -> smallvec::SmallVec<[NodeId; 2]> {
        self.arena.children(id)
    }
}

impl fmt::Display for RevsetAst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Actionable revset parse error returning E_INVALID with span context.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("revset parse error at {span}: {message}")]
pub struct RevsetParseError {
    pub code: ErrorCode, // Always ErrorCode::EInvalid
    pub message: String,
    pub span: Span,
    pub hints: Vec<String>,
}

impl RevsetParseError {
    #[must_use]
    pub fn invalid(message: impl Into<String>, span: Span) -> Self {
        Self {
            code: ErrorCode::EInvalid,
            message: message.into(),
            span,
            hints: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }
}

impl From<RevsetParseError> for CoreError {
    fn from(err: RevsetParseError) -> Self {
        let mut core = CoreError::new(err.code, err.to_string());
        core.hints = err.hints;
        core
    }
}

// ---------------------------------------------------------------------------
// Logos Token Definitions & Lexer
// ---------------------------------------------------------------------------

#[derive(Logos, Clone, Copy, Debug, PartialEq, Eq)]
#[logos(skip r"[ \t\r\n\x0c]+")]
pub(crate) enum RawToken<'a> {
    #[token("@-")]
    AtMinus,

    #[token("@")]
    At,

    #[token("::")]
    ColonColon,

    #[token("..")]
    DotDot,

    #[token("&")]
    Ampersand,

    #[token("|")]
    Pipe,

    #[token("~")]
    Tilde,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token(",")]
    Comma,

    #[regex(r#""([^"\\\x00-\x1F]|\\.)*""#)]
    DoubleQuoted(&'a str),

    #[regex(r#"'[^'\x00]*'"#)]
    SingleQuoted(&'a str),

    #[regex(r"[a-zA-Z0-9_/*?]+([.-][a-zA-Z0-9_/*?]+)*")]
    Ident(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpannedToken<'a> {
    pub token: RawToken<'a>,
    pub span: Span,
}

fn unescape_double_quoted(raw: &str, span: Span) -> Result<String, RevsetParseError> {
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        return Err(RevsetParseError::invalid(
            "unterminated double-quoted string literal",
            span,
        ));
    }
    let inner = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.char_indices().peekable();
    let base_offset = span.start + 1;

    while let Some((idx, ch)) = chars.next() {
        if ch == '\0' {
            return Err(RevsetParseError::invalid(
                "NUL byte is not permitted in revset expressions",
                Span::new(base_offset + idx, base_offset + idx + 1),
            ));
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let esc_start = base_offset + idx;
        let Some((_, next_ch)) = chars.next() else {
            return Err(RevsetParseError::invalid(
                "incomplete escape sequence at end of string literal",
                Span::new(esc_start, esc_start + 1),
            ));
        };

        match next_ch {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0C'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => {
                return Err(RevsetParseError::invalid(
                    "NUL byte is not permitted in revset expressions",
                    Span::new(esc_start, esc_start + 2),
                ));
            }
            'x' => {
                let mut hex_str = String::with_capacity(2);
                for _ in 0..2 {
                    let Some((_, h)) = chars.next() else {
                        return Err(RevsetParseError::invalid(
                            "incomplete \\x escape sequence (expected 2 hex digits)",
                            Span::new(esc_start, span.end - 1),
                        ));
                    };
                    hex_str.push(h);
                }
                let val = u8::from_str_radix(&hex_str, 16).map_err(|_| {
                    RevsetParseError::invalid(
                        format!("invalid \\x escape sequence '\\x{hex_str}'"),
                        Span::new(esc_start, esc_start + 4),
                    )
                })?;
                if val == 0 {
                    return Err(RevsetParseError::invalid(
                        "NUL byte is not permitted in revset expressions",
                        Span::new(esc_start, esc_start + 4),
                    ));
                }
                out.push(char::from(val));
            }
            'u' => {
                if chars.peek().map(|&(_, c)| c) == Some('{') {
                    chars.next(); // consume '{'
                    let mut hex_str = String::new();
                    let mut closed = false;
                    while let Some((_, h)) = chars.next() {
                        if h == '}' {
                            closed = true;
                            break;
                        }
                        hex_str.push(h);
                        if hex_str.len() > 6 {
                            break;
                        }
                    }
                    if !closed {
                        return Err(RevsetParseError::invalid(
                            "unclosed unicode escape sequence (missing '}')",
                            Span::new(esc_start, span.end - 1),
                        ));
                    }
                    let code_point = u32::from_str_radix(&hex_str, 16).map_err(|_| {
                        RevsetParseError::invalid(
                            format!("invalid unicode escape '\\u{{{hex_str}}}'"),
                            Span::new(esc_start, esc_start + 3 + hex_str.len()),
                        )
                    })?;
                    if code_point == 0 {
                        return Err(RevsetParseError::invalid(
                            "NUL byte is not permitted in revset expressions",
                            Span::new(esc_start, esc_start + 3 + hex_str.len()),
                        ));
                    }
                    let unicode_char = char::from_u32(code_point).ok_or_else(|| {
                        RevsetParseError::invalid(
                            format!("unicode escape '\\u{{{hex_str}}}' is out of range"),
                            Span::new(esc_start, esc_start + 3 + hex_str.len()),
                        )
                    })?;
                    out.push(unicode_char);
                } else {
                    let mut hex_str = String::with_capacity(4);
                    for _ in 0..4 {
                        let Some((_, h)) = chars.next() else {
                            return Err(RevsetParseError::invalid(
                                "incomplete \\u escape sequence (expected 4 hex digits)",
                                Span::new(esc_start, span.end - 1),
                            ));
                        };
                        hex_str.push(h);
                    }
                    let code_point = u32::from_str_radix(&hex_str, 16).map_err(|_| {
                        RevsetParseError::invalid(
                            format!("invalid unicode escape '\\u{hex_str}'"),
                            Span::new(esc_start, esc_start + 6),
                        )
                    })?;
                    if code_point == 0 {
                        return Err(RevsetParseError::invalid(
                            "NUL byte is not permitted in revset expressions",
                            Span::new(esc_start, esc_start + 6),
                        ));
                    }
                    let unicode_char = char::from_u32(code_point).ok_or_else(|| {
                        RevsetParseError::invalid(
                            format!("unicode escape '\\u{hex_str}' is out of range"),
                            Span::new(esc_start, esc_start + 6),
                        )
                    })?;
                    out.push(unicode_char);
                }
            }
            other => {
                return Err(RevsetParseError::invalid(
                    format!("invalid escape sequence '\\{other}' in string literal"),
                    Span::new(esc_start, esc_start + 1 + other.len_utf8()),
                ));
            }
        }
    }
    Ok(out)
}

fn unescape_single_quoted(raw: &str, span: Span) -> Result<String, RevsetParseError> {
    if raw.len() < 2 || !raw.starts_with('\'') || !raw.ends_with('\'') {
        return Err(RevsetParseError::invalid(
            "unterminated single-quoted string literal",
            span,
        ));
    }
    let inner = &raw[1..raw.len() - 1];
    if let Some(nul_idx) = inner.bytes().position(|b| b == 0) {
        return Err(RevsetParseError::invalid(
            "NUL byte is not permitted in revset expressions",
            Span::new(span.start + 1 + nul_idx, span.start + 1 + nul_idx + 1),
        ));
    }
    Ok(inner.to_owned())
}

fn tokenize<'a>(input: &'a str) -> Result<Vec<SpannedToken<'a>>, RevsetParseError> {
    if input.len() > MAX_REVSET_BYTES {
        return Err(RevsetParseError::invalid(
            format!("revset expression length exceeds limit of {MAX_REVSET_BYTES} bytes"),
            Span::new(0, input.len()),
        ));
    }
    if let Some(nul_pos) = input.bytes().position(|b| b == 0) {
        return Err(RevsetParseError::invalid(
            "NUL byte is not permitted in revset expressions",
            Span::new(nul_pos, nul_pos + 1),
        ));
    }

    let mut lexer = RawToken::lexer(input);
    let mut tokens = Vec::new();

    while let Some(res) = lexer.next() {
        let range = lexer.span();
        let span = Span::new(range.start, range.end);
        match res {
            Ok(tok) => tokens.push(SpannedToken { token: tok, span }),
            Err(()) => {
                let tail = &input[range.start..];
                let Some(ch) = tail.chars().next() else {
                    return Err(RevsetParseError::invalid(
                        "unexpected end of input in token",
                        span,
                    ));
                };
                if ch == '+' {
                    return Err(RevsetParseError::invalid(
                        "unrecognized operator '+': Ruk revsets do not support '+' (use '|' for union; '+' children alias is not supported)",
                        span,
                    ).with_hint("use '|' for set union; to traverse children use descendants()"));
                }
                if ch == '^' {
                    return Err(RevsetParseError::invalid(
                        "unrecognized operator '^': use '@-' for parents of '@'",
                        span,
                    ).with_hint("use '@-' for working copy parents or ancestors()"));
                }
                if ch == '-' {
                    return Err(RevsetParseError::invalid(
                        "unrecognized operator '-': revsets support '@-' for working copy parents; use '~' for set difference",
                        span,
                    ).with_hint("use '@-' for working copy parents or '~' for difference ('x ~ y')"));
                }
                if ch == '"' {
                    return Err(RevsetParseError::invalid(
                        "unterminated double-quoted string literal",
                        Span::new(range.start, input.len()),
                    ).with_hint("add a closing '\"' at the end of the string"));
                }
                if ch == '\'' {
                    return Err(RevsetParseError::invalid(
                        "unterminated single-quoted string literal",
                        Span::new(range.start, input.len()),
                    ).with_hint("add a closing '\'' at the end of the raw string"));
                }
                if ch == '\0' {
                    return Err(RevsetParseError::invalid(
                        "NUL byte is not permitted in revset expressions",
                        span,
                    ));
                }
                return Err(RevsetParseError::invalid(
                    format!("unexpected character '{ch}' in revset expression"),
                    span,
                ).with_hint("valid revset tokens are identifiers, strings, operators (@, @-, ::, .., &, |, ~), and parentheses"));
            }
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Pratt Parser
// ---------------------------------------------------------------------------

const BP_LOWEST: u8 = 0;
const BP_UNION: u8 = 10;
const BP_INTERSECT: u8 = 20;
const BP_NEGATE: u8 = 30;
const BP_RANGE_INFIX: u8 = 40;

struct Parser<'a> {
    tokens: Vec<SpannedToken<'a>>,
    pos: usize,
    arena: AstArena,
    depth: usize,
    text: &'a str,
}

impl<'a> Parser<'a> {
    fn new(tokens: Vec<SpannedToken<'a>>, text: &'a str) -> Self {
        Self {
            tokens,
            pos: 0,
            arena: AstArena::new(),
            depth: 0,
            text,
        }
    }

    fn peek(&self) -> Option<RawToken<'a>> {
        self.tokens.get(self.pos).map(|st| st.token)
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.pos)
            .map(|st| st.span)
            .unwrap_or_else(|| Span::empty(self.text.len()))
    }

    fn advance(&mut self) -> Option<SpannedToken<'a>> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos];
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn next_token(&mut self) -> Result<SpannedToken<'a>, RevsetParseError> {
        self.advance().ok_or_else(|| {
            RevsetParseError::invalid(
                "unexpected end of revset expression",
                Span::empty(self.text.len()),
            )
        })
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<NodeId, RevsetParseError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            self.depth -= 1;
            return Err(RevsetParseError::invalid(
                format!("revset expression nesting depth exceeded limit of {MAX_PARSE_DEPTH}"),
                self.current_span(),
            ));
        }

        let mut lhs = match self.parse_prefix() {
            Ok(node) => node,
            Err(err) => {
                self.depth -= 1;
                return Err(err);
            }
        };

        loop {
            let Some(peek_tok) = self.peek() else {
                break;
            };

            match peek_tok {
                RawToken::ColonColon => {
                    // Binary Infix DAG range: x::y
                    if BP_RANGE_INFIX < min_bp {
                        break;
                    }
                    if matches!(
                        self.arena.node(lhs).kind,
                        NodeKind::DagRange(..) | NodeKind::Range(..)
                    ) {
                        self.depth -= 1;
                        return Err(RevsetParseError::invalid(
                            "cannot chain range operators without parentheses",
                            self.current_span(),
                        )
                        .with_hint(
                            "use parentheses to clarify precedence: '(x::y)::z' or 'x::(y::z)'",
                        ));
                    }
                    let op_st = self.next_token()?;
                    let rhs = self.parse_expr(BP_RANGE_INFIX + 1)?;
                    let lhs_span = self.arena.node(lhs).span;
                    let rhs_span = self.arena.node(rhs).span;
                    let span = lhs_span.join(op_st.span).join(rhs_span);
                    lhs = self.arena.alloc_node(NodeKind::DagRange(lhs, rhs), span)?;
                }

                RawToken::DotDot => {
                    // Binary Infix range: x..y
                    if BP_RANGE_INFIX < min_bp {
                        break;
                    }
                    if matches!(
                        self.arena.node(lhs).kind,
                        NodeKind::DagRange(..) | NodeKind::Range(..)
                    ) {
                        self.depth -= 1;
                        return Err(RevsetParseError::invalid(
                            "cannot chain range operators without parentheses",
                            self.current_span(),
                        )
                        .with_hint(
                            "use parentheses to clarify precedence: '(x..y)..z' or 'x..(y..z)'",
                        ));
                    }
                    let op_st = self.next_token()?;
                    let rhs = self.parse_expr(BP_RANGE_INFIX + 1)?;
                    let lhs_span = self.arena.node(lhs).span;
                    let rhs_span = self.arena.node(rhs).span;
                    let span = lhs_span.join(op_st.span).join(rhs_span);
                    lhs = self.arena.alloc_node(NodeKind::Range(lhs, rhs), span)?;
                }

                RawToken::Ampersand => {
                    // Infix intersection: lhs & rhs
                    if BP_INTERSECT < min_bp {
                        break;
                    }
                    let op_st = self.next_token()?;
                    let rhs = self.parse_expr(BP_INTERSECT + 1)?;
                    let lhs_span = self.arena.node(lhs).span;
                    let rhs_span = self.arena.node(rhs).span;
                    let span = lhs_span.join(op_st.span).join(rhs_span);
                    lhs = self
                        .arena
                        .alloc_node(NodeKind::Intersection(lhs, rhs), span)?;
                }

                RawToken::Tilde => {
                    // Infix difference: lhs ~ rhs
                    if BP_INTERSECT < min_bp {
                        break;
                    }
                    let op_st = self.next_token()?;
                    let rhs = self.parse_expr(BP_INTERSECT + 1)?;
                    let lhs_span = self.arena.node(lhs).span;
                    let rhs_span = self.arena.node(rhs).span;
                    let span = lhs_span.join(op_st.span).join(rhs_span);
                    lhs = self
                        .arena
                        .alloc_node(NodeKind::Difference(lhs, rhs), span)?;
                }

                RawToken::Pipe => {
                    // Infix union: lhs | rhs
                    if BP_UNION < min_bp {
                        break;
                    }
                    let op_st = self.next_token()?;
                    let rhs = self.parse_expr(BP_UNION + 1)?;
                    let lhs_span = self.arena.node(lhs).span;
                    let rhs_span = self.arena.node(rhs).span;
                    let span = lhs_span.join(op_st.span).join(rhs_span);
                    lhs = self.arena.alloc_node(NodeKind::Union(lhs, rhs), span)?;
                }

                _ => break,
            }
        }

        self.depth -= 1;
        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<NodeId, RevsetParseError> {
        let st = self.next_token()?;

        match st.token {
            RawToken::AtMinus => self.arena.alloc_node(NodeKind::AtMinus, st.span),

            RawToken::At => self.arena.alloc_node(NodeKind::At, st.span),

            RawToken::Tilde => {
                let rhs = self.parse_expr(BP_NEGATE)?;
                let rhs_span = self.arena.node(rhs).span;
                let span = st.span.join(rhs_span);
                self.arena.alloc_node(NodeKind::Negate(rhs), span)
            }

            RawToken::ColonColon => Err(RevsetParseError::invalid(
                "unexpected '::' in prefix position; '::' is a binary DAG range operator ('x::y')",
                st.span,
            ).with_hint("use 'x::y' for DAG range or ancestors(y)/descendants(x)")),

            RawToken::DotDot => Err(RevsetParseError::invalid(
                "unexpected '..' in prefix position; '..' is a binary range operator ('x..y')",
                st.span,
            ).with_hint("use 'x..y' for range or ancestors(y) ~ ancestors(x)")),

            RawToken::LParen => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_span = self.current_span();
                    return Err(RevsetParseError::invalid(
                        "expected revset expression inside parentheses, found ')'",
                        st.span.join(r_span),
                    ));
                }
                let inner = self.parse_expr(BP_LOWEST)?;
                let next = self.advance();
                match next {
                    Some(SpannedToken {
                        token: RawToken::RParen,
                        span: r_span,
                    }) => {
                        let span = st.span.join(r_span);
                        self.arena.alloc_node(NodeKind::Group(inner), span)
                    }
                    _ => Err(RevsetParseError::invalid(
                        "expected closing ')'",
                        self.current_span(),
                    )),
                }
            }

            RawToken::DoubleQuoted(raw) => {
                let unescaped = unescape_double_quoted(raw, st.span)?;
                let sid = self.arena.alloc_string(unescaped)?;
                self.arena.alloc_node(NodeKind::StringLiteral(sid), st.span)
            }

            RawToken::SingleQuoted(raw) => {
                let unescaped = unescape_single_quoted(raw, st.span)?;
                let sid = self.arena.alloc_string(unescaped)?;
                self.arena.alloc_node(NodeKind::StringLiteral(sid), st.span)
            }

            RawToken::Ident(name) => {
                if self.peek() == Some(RawToken::LParen) {
                    self.parse_function_call(name, st.span)
                } else {
                    let sid = self.arena.alloc_string(name.to_owned())?;
                    self.arena.alloc_node(NodeKind::Symbol(sid), st.span)
                }
            }

            RawToken::RParen => Err(RevsetParseError::invalid(
                "unexpected closing ')'",
                st.span,
            )),

            RawToken::Comma => Err(RevsetParseError::invalid("unexpected comma ','", st.span)),

            RawToken::Ampersand => Err(RevsetParseError::invalid(
                "unexpected '&' in prefix position; expected revset expression before '&'",
                st.span,
            )),

            RawToken::Pipe => Err(RevsetParseError::invalid(
                "unexpected '|' in prefix position; expected revset expression before '|'",
                st.span,
            )),
        }
    }

    fn parse_string_arg(&mut self, func_name: &str) -> Result<StringId, RevsetParseError> {
        let st = self.next_token()?;
        match st.token {
            RawToken::DoubleQuoted(raw) => {
                let unescaped = unescape_double_quoted(raw, st.span)?;
                self.arena.alloc_string(unescaped)
            }
            RawToken::SingleQuoted(raw) => {
                let unescaped = unescape_single_quoted(raw, st.span)?;
                self.arena.alloc_string(unescaped)
            }
            RawToken::Ident(name) => self.arena.alloc_string(name.to_owned()),
            _ => Err(RevsetParseError::invalid(
                format!("expected string or identifier argument for function '{func_name}'"),
                st.span,
            )),
        }
    }

    fn parse_function_call(
        &mut self,
        name: &str,
        name_span: Span,
    ) -> Result<NodeId, RevsetParseError> {
        let lparen_st = self.next_token()?; // consume '('

        // 1. Plain string functions: session, change, description, files, attested
        match name {
            "session" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'session' takes exactly 1 argument (id), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let sid = self.parse_string_arg("session")?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'session' takes exactly 1 argument (id), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("session")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                return self.arena.alloc_node(NodeKind::Session(sid), call_span);
            }

            "change" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'change' takes exactly 1 argument (prefix), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let sid = self.parse_string_arg("change")?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'change' takes exactly 1 argument (prefix), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("change")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                return self.arena.alloc_node(NodeKind::Change(sid), call_span);
            }

            "description" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'description' takes exactly 1 argument (text), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let sid = self.parse_string_arg("description")?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'description' takes exactly 1 argument (text), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("description")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                return self.arena.alloc_node(NodeKind::Description(sid), call_span);
            }

            "files" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'files' takes exactly 1 argument (glob), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let sid = self.parse_string_arg("files")?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'files' takes exactly 1 argument (glob), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("files")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                return self.arena.alloc_node(NodeKind::Files(sid), call_span);
            }

            "attested" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'attested' takes exactly 2 arguments (kind, result), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let kind_id = self.parse_string_arg("attested")?;
                if self.peek() != Some(RawToken::Comma) {
                    return Err(RevsetParseError::invalid(
                        "function 'attested' takes exactly 2 arguments (kind, result), got 1",
                        self.current_span(),
                    ));
                }
                self.next_token()?; // consume ','
                let result_id = self.parse_string_arg("attested")?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'attested' takes exactly 2 arguments (kind, result), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("attested")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                return self.arena.alloc_node(
                    NodeKind::Attested {
                        kind: kind_id,
                        result: result_id,
                    },
                    call_span,
                );
            }

            _ => {}
        }

        // 2. Functions with strict arity
        match name {
            // Nullary functions: conflicted(), divergent(), mine()
            "conflicted" => {
                if self.peek() != Some(RawToken::RParen) {
                    let span = self.current_span();
                    return Err(RevsetParseError::invalid(
                        "function 'conflicted' takes 0 arguments",
                        name_span.join(span),
                    ));
                }
                let rparen_st = self.expect_rparen("conflicted")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Conflicted, call_span)
            }

            "divergent" => {
                if self.peek() != Some(RawToken::RParen) {
                    let span = self.current_span();
                    return Err(RevsetParseError::invalid(
                        "function 'divergent' takes 0 arguments",
                        name_span.join(span),
                    ));
                }
                let rparen_st = self.expect_rparen("divergent")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Divergent, call_span)
            }

            "mine" => {
                if self.peek() != Some(RawToken::RParen) {
                    let span = self.current_span();
                    return Err(RevsetParseError::invalid(
                        "function 'mine' takes 0 arguments",
                        name_span.join(span),
                    ));
                }
                let rparen_st = self.expect_rparen("mine")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Mine, call_span)
            }

            // Exactly 1 argument: heads(x), roots(x), ancestors(x), descendants(x)
            "heads" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'heads' takes exactly 1 argument (x), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let expr_id = self.parse_expr(BP_LOWEST)?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'heads' takes exactly 1 argument (x), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("heads")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Heads(expr_id), call_span)
            }

            "roots" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'roots' takes exactly 1 argument (x), got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let expr_id = self.parse_expr(BP_LOWEST)?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'roots' takes exactly 1 argument (x), got multiple",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("roots")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Roots(expr_id), call_span)
            }

            "ancestors" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'ancestors' takes exactly 1 argument, got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let expr_id = self.parse_expr(BP_LOWEST)?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'ancestors' takes exactly 1 argument (depth-argument overload is not supported)",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("ancestors")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Ancestors(expr_id), call_span)
            }

            "descendants" => {
                if self.peek() == Some(RawToken::RParen) {
                    let r_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'descendants' takes exactly 1 argument, got 0",
                        name_span.join(r_st.span),
                    ));
                }
                let expr_id = self.parse_expr(BP_LOWEST)?;
                if self.peek() == Some(RawToken::Comma) {
                    let c_st = self.next_token()?;
                    return Err(RevsetParseError::invalid(
                        "function 'descendants' takes exactly 1 argument (depth-argument overload is not supported)",
                        name_span.join(c_st.span),
                    ));
                }
                let rparen_st = self.expect_rparen("descendants")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Descendants(expr_id), call_span)
            }

            // 0 or 1 argument: bookmarks([p]), remote_bookmarks([p]), tags([p])
            "bookmarks" => {
                let arg = if self.peek() == Some(RawToken::RParen) {
                    None
                } else {
                    let expr_id = self.parse_expr(BP_LOWEST)?;
                    if self.peek() == Some(RawToken::Comma) {
                        let c_st = self.next_token()?;
                        return Err(RevsetParseError::invalid(
                            "function 'bookmarks' takes 0 or 1 arguments, got multiple",
                            name_span.join(c_st.span),
                        ));
                    }
                    Some(expr_id)
                };
                let rparen_st = self.expect_rparen("bookmarks")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Bookmarks(arg), call_span)
            }

            "remote_bookmarks" => {
                let arg = if self.peek() == Some(RawToken::RParen) {
                    None
                } else {
                    let expr_id = self.parse_expr(BP_LOWEST)?;
                    if self.peek() == Some(RawToken::Comma) {
                        let c_st = self.next_token()?;
                        return Err(RevsetParseError::invalid(
                            "function 'remote_bookmarks' takes 0 or 1 arguments, got multiple",
                            name_span.join(c_st.span),
                        ));
                    }
                    Some(expr_id)
                };
                let rparen_st = self.expect_rparen("remote_bookmarks")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::RemoteBookmarks(arg), call_span)
            }

            "tags" => {
                let arg = if self.peek() == Some(RawToken::RParen) {
                    None
                } else {
                    let expr_id = self.parse_expr(BP_LOWEST)?;
                    if self.peek() == Some(RawToken::Comma) {
                        let c_st = self.next_token()?;
                        return Err(RevsetParseError::invalid(
                            "function 'tags' takes 0 or 1 arguments, got multiple",
                            name_span.join(c_st.span),
                        ));
                    }
                    Some(expr_id)
                };
                let rparen_st = self.expect_rparen("tags")?;
                let call_span = name_span.join(lparen_st.span).join(rparen_st.span);
                self.arena.alloc_node(NodeKind::Tags(arg), call_span)
            }

            _ => {
                let mut err = RevsetParseError::invalid(
                    format!("unknown revset function '{name}'"),
                    name_span,
                );
                match name {
                    "parents" => err = err.with_hint("use '@-' or 'ancestors()'"),
                    "children" => err = err.with_hint("use 'descendants()'"),
                    "conflicts" => err = err.with_hint("did you mean 'conflicted()' ?"),
                    "tag" => err = err.with_hint("did you mean 'tags()' ?"),
                    "bookmark" => err = err.with_hint("did you mean 'bookmarks()' ?"),
                    _ => {
                        err = err.with_hint(
                            "supported functions: heads, roots, ancestors, descendants, bookmarks, remote_bookmarks, tags, conflicted, divergent, mine, session(id), change(prefix), description(text), files(glob), attested(kind,result)",
                        );
                    }
                }
                Err(err)
            }
        }
    }

    fn expect_rparen(&mut self, func_name: &str) -> Result<SpannedToken<'a>, RevsetParseError> {
        let rparen_st = self.next_token()?;
        if rparen_st.token != RawToken::RParen {
            return Err(RevsetParseError::invalid(
                format!("expected closing ')' for function '{func_name}'"),
                self.current_span(),
            ));
        }
        Ok(rparen_st)
    }

    fn token_text(&self, tok: RawToken<'a>, span: Span) -> &'a str {
        if span.start <= self.text.len() && span.end <= self.text.len() && span.start <= span.end {
            &self.text[span.start..span.end]
        } else {
            match tok {
                RawToken::At => "@",
                RawToken::AtMinus => "@-",
                RawToken::ColonColon => "::",
                RawToken::DotDot => "..",
                RawToken::Ampersand => "&",
                RawToken::Pipe => "|",
                RawToken::Tilde => "~",
                RawToken::LParen => "(",
                RawToken::RParen => ")",
                RawToken::Comma => ",",
                RawToken::DoubleQuoted(s) | RawToken::SingleQuoted(s) | RawToken::Ident(s) => s,
            }
        }
    }
}

/// Parse a validated [`RevsetText`] into a typed flat arena AST.
///
/// Returns [`CoreError`] with `ErrorCode::EInvalid` and actionable span
/// information on malformed syntax, invalid characters, function arity errors,
/// depth limit exceedance, or trailing tokens.
pub fn parse(revset: &RevsetText) -> Result<RevsetAst, CoreError> {
    parse_internal(revset.as_str()).map_err(CoreError::from)
}

/// Crate-internal entry point from string slice for callers/tests.
pub(crate) fn parse_str(input: &str) -> Result<RevsetAst, CoreError> {
    parse_internal(input).map_err(CoreError::from)
}

fn parse_internal(input: &str) -> Result<RevsetAst, RevsetParseError> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(RevsetParseError::invalid(
            "expected revset expression, found empty input",
            Span::empty(0),
        ));
    }

    let mut parser = Parser::new(tokens, input);
    let root = parser.parse_expr(BP_LOWEST)?;

    if !parser.is_eof() {
        let st = parser.tokens[parser.pos];
        let tok_text = parser.token_text(st.token, st.span);
        return Err(RevsetParseError::invalid(
            format!("unexpected trailing token: '{tok_text}'"),
            st.span,
        )
        .with_hint("expected operator or end of revset expression"));
    }

    Ok(RevsetAst {
        arena: parser.arena,
        root,
        text: input.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_arena_drop_does_not_overflow_stack_on_deep_structure() {
        let mut arena = AstArena::new();
        let mut current = arena.alloc_node(NodeKind::At, Span::empty(0)).expect("alloc");
        // Build a 20,000 deep chain in the flat arena
        for i in 0..20_000 {
            current = arena
                .alloc_node(NodeKind::Negate(current), Span::empty(i))
                .expect("alloc");
        }
        let ast = RevsetAst {
            root: current,
            arena,
            text: String::new(),
        };
        // Dropping ast here must be completely non-recursive over the flat Vec
        drop(ast);
    }

    #[test]
    fn parser_rejects_malicious_nesting_depth() {
        let open = "(".repeat(200);
        let close = ")".repeat(200);
        let deep_expr = format!("{open}@{close}");
        let err = parse_str(&deep_expr).expect_err("should reject nesting depth");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("nesting depth"));
    }

    #[test]
    fn parser_rejects_malicious_negation_nesting() {
        let mut deep_expr = String::new();
        for _ in 0..200 {
            deep_expr.push('~');
        }
        deep_expr.push('@');
        let err = parse_str(&deep_expr).expect_err("should reject nesting depth");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("nesting depth"));
    }

    #[test]
    fn large_chain_of_unions_parses_and_drops() {
        let mut chain = String::new();
        for i in 0..1000 {
            if i > 0 {
                chain.push_str(" | ");
            }
            chain.push_str(&format!("c{i}"));
        }
        let ast = parse_str(&chain).expect("parse large chain");
        assert_eq!(ast.node_count(), 1999);
        drop(ast);
    }

    #[test]
    fn large_chain_of_intersections_parses_and_drops() {
        let mut chain = String::new();
        for i in 0..1000 {
            if i > 0 {
                chain.push_str(" & ");
            }
            chain.push_str(&format!("c{i}"));
        }
        let ast = parse_str(&chain).expect("parse large chain");
        assert_eq!(ast.node_count(), 1999);
        drop(ast);
    }

    #[test]
    fn precedence_union_and_intersection() {
        // a | b & c => a | (b & c)
        let ast = parse_str("a | b & c").expect("parse");
        match &ast.root().kind {
            NodeKind::Union(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Symbol(_)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Intersection(_, _)));
            }
            other => panic!("expected union at root, got {other:?}"),
        }

        // a & b | c => (a & b) | c
        let ast = parse_str("a & b | c").expect("parse");
        match &ast.root().kind {
            NodeKind::Union(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Intersection(_, _)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected union at root, got {other:?}"),
        }
    }

    #[test]
    fn precedence_intersection_and_difference_left_associative() {
        // a & b ~ c => (a & b) ~ c
        let ast = parse_str("a & b ~ c").expect("parse");
        match &ast.root().kind {
            NodeKind::Difference(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Intersection(_, _)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected difference at root, got {other:?}"),
        }

        // a ~ b & c => (a ~ b) & c
        let ast = parse_str("a ~ b & c").expect("parse");
        match &ast.root().kind {
            NodeKind::Intersection(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Difference(_, _)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected intersection at root, got {other:?}"),
        }
    }

    #[test]
    fn precedence_negate_and_intersection() {
        // ~a & b => (~a) & b
        let ast = parse_str("~a & b").expect("parse");
        match &ast.root().kind {
            NodeKind::Intersection(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Negate(_)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected intersection at root, got {other:?}"),
        }

        // a & ~b => a & (~b)
        let ast = parse_str("a & ~b").expect("parse");
        match &ast.root().kind {
            NodeKind::Intersection(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Symbol(_)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Negate(_)));
            }
            other => panic!("expected intersection at root, got {other:?}"),
        }
    }

    #[test]
    fn precedence_ranges_bind_tighter_than_negate() {
        // ~x::y => ~(x::y)
        let ast = parse_str("~x::y").expect("parse");
        match &ast.root().kind {
            NodeKind::Negate(child) => {
                assert!(matches!(ast.node(*child).kind, NodeKind::DagRange(_, _)));
            }
            other => panic!("expected negate at root, got {other:?}"),
        }

        // ~x..y => ~(x..y)
        let ast = parse_str("~x..y").expect("parse");
        match &ast.root().kind {
            NodeKind::Negate(child) => {
                assert!(matches!(ast.node(*child).kind, NodeKind::Range(_, _)));
            }
            other => panic!("expected negate at root, got {other:?}"),
        }
    }

    #[test]
    fn precedence_at_minus_binds_as_atom() {
        // @-::main => (@-)::main
        let ast = parse_str("@-::main").expect("parse");
        match &ast.root().kind {
            NodeKind::DagRange(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::AtMinus));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected DagRange at root, got {other:?}"),
        }
    }

    #[test]
    fn precedence_ranges_and_logical_operators() {
        // x::y | z => (x::y) | z
        let ast = parse_str("x::y | z").expect("parse");
        match &ast.root().kind {
            NodeKind::Union(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::DagRange(_, _)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::Symbol(_)));
            }
            other => panic!("expected union at root, got {other:?}"),
        }

        // z | x::y => z | (x::y)
        let ast = parse_str("z | x::y").expect("parse");
        match &ast.root().kind {
            NodeKind::Union(lhs, rhs) => {
                assert!(matches!(ast.node(*lhs).kind, NodeKind::Symbol(_)));
                assert!(matches!(ast.node(*rhs).kind, NodeKind::DagRange(_, _)));
            }
            other => panic!("expected union at root, got {other:?}"),
        }
    }

    #[test]
    fn test_range_operators_and_chain_rejection() {
        // x::y (infix)
        let ast = parse_str("a::b").expect("parse");
        assert!(matches!(ast.root().kind, NodeKind::DagRange(_, _)));

        // x..y (infix)
        let ast = parse_str("a..b").expect("parse");
        assert!(matches!(ast.root().kind, NodeKind::Range(_, _)));

        // Chained ranges without parens must be rejected
        let err = parse_str("a::b::c").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("cannot chain range"));

        let err = parse_str("a..b..c").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("cannot chain range"));
    }

    #[test]
    fn test_symbols_and_at_variants() {
        // @
        let ast = parse_str("@").expect("parse");
        assert!(matches!(ast.root().kind, NodeKind::At));

        // @-
        let ast = parse_str("@-").expect("parse");
        assert!(matches!(ast.root().kind, NodeKind::AtMinus));

        // main
        let ast = parse_str("main").expect("parse");
        match &ast.root().kind {
            NodeKind::Symbol(s) => assert_eq!(ast.string(*s), "main"),
            other => panic!("expected Symbol, got {other:?}"),
        }

        // quoted string
        let ast = parse_str("\"my-branch\"").expect("parse");
        match &ast.root().kind {
            NodeKind::StringLiteral(s) => assert_eq!(ast.string(*s), "my-branch"),
            other => panic!("expected StringLiteral, got {other:?}"),
        }
    }

    #[test]
    fn test_function_arity_validation() {
        // session(id): exactly 1 string
        let ast = parse_str("session(\"s1\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Session(sid) => assert_eq!(ast.string(*sid), "s1"),
            other => panic!("expected Session, got {other:?}"),
        }
        assert!(parse_str("session(s1)").is_ok());
        assert_eq!(parse_str("session()").unwrap_err().code, ErrorCode::EInvalid);
        assert_eq!(
            parse_str("session(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // change(prefix): exactly 1 string
        let ast = parse_str("change(\"abc\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Change(sid) => assert_eq!(ast.string(*sid), "abc"),
            other => panic!("expected Change, got {other:?}"),
        }
        assert_eq!(parse_str("change()").unwrap_err().code, ErrorCode::EInvalid);
        assert_eq!(
            parse_str("change(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // description(text): exactly 1 string
        let ast = parse_str("description(\"fix\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Description(sid) => assert_eq!(ast.string(*sid), "fix"),
            other => panic!("expected Description, got {other:?}"),
        }
        assert_eq!(
            parse_str("description()").unwrap_err().code,
            ErrorCode::EInvalid
        );
        assert_eq!(
            parse_str("description(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // files(glob): exactly 1 string
        let ast = parse_str("files(\"*.rs\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Files(sid) => assert_eq!(ast.string(*sid), "*.rs"),
            other => panic!("expected Files, got {other:?}"),
        }
        assert_eq!(parse_str("files()").unwrap_err().code, ErrorCode::EInvalid);
        assert_eq!(
            parse_str("files(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // attested(kind, result): exactly 2 strings
        let ast = parse_str("attested(\"test\", \"pass\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Attested { kind, result } => {
                assert_eq!(ast.string(*kind), "test");
                assert_eq!(ast.string(*result), "pass");
            }
            other => panic!("expected Attested, got {other:?}"),
        }
        assert_eq!(
            parse_str("attested(\"test\")").unwrap_err().code,
            ErrorCode::EInvalid
        );
        assert_eq!(
            parse_str("attested(\"test\", \"pass\", \"extra\")")
                .unwrap_err()
                .code,
            ErrorCode::EInvalid
        );

        // heads(x): exactly 1 argument
        assert!(parse_str("heads(main)").is_ok());
        assert_eq!(parse_str("heads()").unwrap_err().code, ErrorCode::EInvalid);
        assert_eq!(parse_str("heads(a, b)").unwrap_err().code, ErrorCode::EInvalid);

        // roots(x): exactly 1 argument
        assert!(parse_str("roots(main)").is_ok());
        assert_eq!(parse_str("roots()").unwrap_err().code, ErrorCode::EInvalid);
        assert_eq!(parse_str("roots(a, b)").unwrap_err().code, ErrorCode::EInvalid);

        // ancestors(x): exactly 1 argument (NO depth overload!)
        assert!(parse_str("ancestors(@)").is_ok());
        assert_eq!(parse_str("ancestors()").unwrap_err().code, ErrorCode::EInvalid);
        let err = parse_str("ancestors(@, 2)").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("depth"));

        // descendants(x): exactly 1 argument (NO depth overload!)
        assert!(parse_str("descendants(@)").is_ok());
        assert_eq!(parse_str("descendants()").unwrap_err().code, ErrorCode::EInvalid);
        let err = parse_str("descendants(@, 2)").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("depth"));

        // conflicted(): exactly 0 arguments
        assert!(parse_str("conflicted()").is_ok());
        assert_eq!(
            parse_str("conflicted(main)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // divergent(): exactly 0 arguments
        assert!(parse_str("divergent()").is_ok());
        assert_eq!(
            parse_str("divergent(main)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // mine(): exactly 0 arguments
        assert!(parse_str("mine()").is_ok());
        assert_eq!(parse_str("mine(extra)").unwrap_err().code, ErrorCode::EInvalid);

        // bookmarks([p]): 0 or 1 argument
        assert!(parse_str("bookmarks()").is_ok());
        assert!(parse_str("bookmarks(\"main*\")").is_ok());
        assert_eq!(
            parse_str("bookmarks(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // remote_bookmarks([p]): 0 or 1 argument
        assert!(parse_str("remote_bookmarks()").is_ok());
        assert!(parse_str("remote_bookmarks(\"main*\")").is_ok());
        assert_eq!(
            parse_str("remote_bookmarks(a, b)").unwrap_err().code,
            ErrorCode::EInvalid
        );

        // tags([p]): 0 or 1 argument
        assert!(parse_str("tags()").is_ok());
        assert!(parse_str("tags(\"v*\")").is_ok());
        assert_eq!(parse_str("tags(a, b)").unwrap_err().code, ErrorCode::EInvalid);

        // unknown function
        let err = parse_str("unknown_func()").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("unknown revset function"));
    }

    #[test]
    fn test_forbidden_operators_produce_actionable_errors() {
        let err = parse_str("a + b").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("'+'"));

        let err = parse_str("a+").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("'+'"));

        let err = parse_str("a^").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("'^'"));

        let err = parse_str("a - b").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("'-'"));

        // Nullary or prefix ranges forbidden
        let err = parse_str("::").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("::main").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("..").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("..main").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn test_string_literal_escapes_and_errors() {
        let ast = parse_str("description(\"hello \\\"world\\\" \\n\\t\\r\")").expect("parse");
        match &ast.root().kind {
            NodeKind::Description(sid) => {
                assert_eq!(ast.string(*sid), "hello \"world\" \n\t\r");
            }
            other => panic!("expected Description, got {other:?}"),
        }

        let ast = parse_str("files('src/*.rs')").expect("parse");
        match &ast.root().kind {
            NodeKind::Files(sid) => {
                assert_eq!(ast.string(*sid), "src/*.rs");
            }
            other => panic!("expected Files, got {other:?}"),
        }

        let err = parse_str("\"unclosed").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("unterminated"));

        let err = parse_str("'unclosed").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("unterminated"));

        let err = parse_str("\"hello \\q world\"").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("invalid escape sequence"));

        let err = parse_str("\"hello \\0 world\"").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("NUL"));

        let err = parse_str("hello \0 world").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("NUL"));
    }

    #[test]
    fn test_malformed_inputs() {
        let err = parse_str("").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("   \t\n  ").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("main feature").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("unexpected trailing token"));

        let err = parse_str("main &").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("main |").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("main ~").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str("(main").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);

        let err = parse_str(")").unwrap_err();
        assert_eq!(err.code, ErrorCode::EInvalid);
    }
}
