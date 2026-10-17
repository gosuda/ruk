//! Grammar catalogue, dispatch, parse-tree seam, and resource bounds.
//!
//! This module owns the closed [`Language`] inventory (28 parser variants),
//! the exact grammar pins with ABI/source evidence, deterministic dispatch
//! (extension, basename, shebang, validated override), the fixed 8 MiB
//! triplet bound, cancellation, the [`SyntaxError`] surface, the
//! provider-neutral [`ParsedTree`]/[`Grammar`] seam the merge driver runs
//! against, and the deterministic manifest-digest input that pins
//! `language_set_version = 1`.
//!
//! The seam is deliberate: registry [`Cargo.toml`] manifests and the
//! `build.rs` that compiles the vendored Vue C sources belong to the parent
//! integration owner (Slice 0), so this file names the exact crates, exports,
//! and entry points the parent must wire and defines the checked conversion
//! every provider must satisfy. No grammar is downloaded, compiled, or
//! selected at runtime; every [`Grammar`] implementation is constructed from
//! the pinned dependencies listed here. Grammar crate availability is
//! necessary but never sufficient: each language additionally needs its
//! adapter in `super::adapters` and its readiness sample below to parse.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, ErrorCode};

/// Grammar/adapter set version carried on every mergeability and merge
/// result. Starts at 1; changes whenever grammar pins, dispatch,
/// composition, or structural merge rules change.
pub const LANGUAGE_SET_VERSION: u32 = 1;

/// Maximum combined `base + ours + theirs` source bytes accepted for one
/// syntax triplet. The same fixed bound applies to every parser call.
pub const MAX_TRIPLET_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum byte length of a validated `ruk-language` override identifier.
pub const MAX_OVERRIDE_BYTES: usize = 64;

/// Sentinel for "no node" in [`ParsedTree`] link fields.
pub const NODE_NONE: u32 = u32::MAX;

/// Sentinel for "no field" on a [`ParsedNode::field`] edge.
pub const FIELD_NONE: u32 = u32::MAX;

/// Every parser variant the syntax engine catalogues. The spelling of
/// [`Language::id`] is the validated `ruk-language` attribute value and the
/// notice `language` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    Rust,
    Python,
    Go,
    Yaml,
    Javascript,
    Typescript,
    Tsx,
    C,
    Cpp,
    Java,
    CSharp,
    Kotlin,
    Swift,
    Ruby,
    Php,
    Bash,
    Ocaml,
    OcamlInterface,
    Lua,
    Html,
    Css,
    Json,
    Toml,
    Vue,
    Svelte,
    Markdown,
    Mdx,
    Notebook,
}

impl Language {
    /// All catalogued languages in canonical order.
    pub const ALL: [Self; 28] = [
        Self::Rust,
        Self::Python,
        Self::Go,
        Self::Yaml,
        Self::Javascript,
        Self::Typescript,
        Self::Tsx,
        Self::C,
        Self::Cpp,
        Self::Java,
        Self::CSharp,
        Self::Kotlin,
        Self::Swift,
        Self::Ruby,
        Self::Php,
        Self::Bash,
        Self::Ocaml,
        Self::OcamlInterface,
        Self::Lua,
        Self::Html,
        Self::Css,
        Self::Json,
        Self::Toml,
        Self::Vue,
        Self::Svelte,
        Self::Markdown,
        Self::Mdx,
        Self::Notebook,
    ];

    /// Canonical identifier: attribute value, dispatch key, notice language.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Python => "python",
            Self::Go => "go",
            Self::Yaml => "yaml",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
            Self::Tsx => "tsx",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Java => "java",
            Self::CSharp => "c-sharp",
            Self::Kotlin => "kotlin",
            Self::Swift => "swift",
            Self::Ruby => "ruby",
            Self::Php => "php",
            Self::Bash => "bash",
            Self::Ocaml => "ocaml",
            Self::OcamlInterface => "ocaml-interface",
            Self::Lua => "lua",
            Self::Html => "html",
            Self::Css => "css",
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Vue => "vue",
            Self::Svelte => "svelte",
            Self::Markdown => "markdown",
            Self::Mdx => "mdx",
            Self::Notebook => "notebook",
        }
    }

    /// Parses a validated language identifier. Returns `None` for unknown
    /// identifiers; the caller maps that to `E_INVALID`.
    #[must_use]
    pub fn from_id(text: &str) -> Option<Self> {
        Some(match text {
            "rust" => Self::Rust,
            "python" => Self::Python,
            "go" => Self::Go,
            "yaml" => Self::Yaml,
            "javascript" => Self::Javascript,
            "typescript" => Self::Typescript,
            "tsx" => Self::Tsx,
            "c" => Self::C,
            "cpp" => Self::Cpp,
            "java" => Self::Java,
            "c-sharp" => Self::CSharp,
            "kotlin" => Self::Kotlin,
            "swift" => Self::Swift,
            "ruby" => Self::Ruby,
            "php" => Self::Php,
            "bash" => Self::Bash,
            "ocaml" => Self::Ocaml,
            "ocaml-interface" => Self::OcamlInterface,
            "lua" => Self::Lua,
            "html" => Self::Html,
            "css" => Self::Css,
            "json" => Self::Json,
            "toml" => Self::Toml,
            "vue" => Self::Vue,
            "svelte" => Self::Svelte,
            "markdown" => Self::Markdown,
            "mdx" => Self::Mdx,
            "notebook" => Self::Notebook,
            _ => return None,
        })
    }

    /// Whether the plain in-process structural merger may handle this
    /// language. Vue, Svelte, Markdown, MDX, and notebooks are catalogue
    /// entries for the composed-file owner; the plain merger declines them
    /// with a typed composed-language decline instead of parsing them with a
    /// generic grammar.
    #[must_use]
    pub const fn is_plain(self) -> bool {
        !matches!(
            self,
            Self::Vue | Self::Svelte | Self::Markdown | Self::Mdx | Self::Notebook
        )
    }

    /// Exact grammar pin, selected export, generated ABI, published source,
    /// and license for this language. ABI values are source inspections
    /// against tree-sitter core 0.27.1's accepted interval 13 through 15.
    #[must_use]
    pub const fn grammar_pin(self) -> GrammarPin {
        match self {
            Self::Rust => GrammarPin::crate_pin(
                "tree-sitter-rust",
                "0.24.2",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-rust/0.24.2/source/",
            ),
            Self::Python => GrammarPin::crate_pin(
                "tree-sitter-python",
                "0.25.0",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-python/0.25.0/source/",
            ),
            Self::Go => GrammarPin::crate_pin(
                "tree-sitter-go",
                "0.25.0",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-go/0.25.0/source/",
            ),
            Self::Yaml => GrammarPin::crate_pin(
                "tree-sitter-yaml",
                "0.7.2",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-yaml/0.7.2/source/",
            ),
            Self::Javascript => GrammarPin::crate_pin(
                "tree-sitter-javascript",
                "0.25.0",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-javascript/0.25.0/source/",
            ),
            Self::Typescript => GrammarPin::crate_pin(
                "tree-sitter-typescript",
                "0.23.2",
                "LANGUAGE_TYPESCRIPT",
                14,
                "https://docs.rs/crate/tree-sitter-typescript/0.23.2/source/",
            ),
            Self::Tsx => GrammarPin::crate_pin(
                "tree-sitter-typescript",
                "0.23.2",
                "LANGUAGE_TSX",
                14,
                "https://docs.rs/crate/tree-sitter-typescript/0.23.2/source/",
            ),
            Self::C => GrammarPin::crate_pin(
                "tree-sitter-c",
                "0.24.2",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-c/0.24.2/source/",
            ),
            Self::Cpp => GrammarPin::crate_pin(
                "tree-sitter-cpp",
                "0.23.4",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-cpp/0.23.4/source/",
            ),
            Self::Java => GrammarPin::crate_pin(
                "tree-sitter-java",
                "0.23.5",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-java/0.23.5/source/",
            ),
            Self::CSharp => GrammarPin::crate_pin(
                "tree-sitter-c-sharp",
                "0.23.5",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-c-sharp/0.23.5/source/",
            ),
            Self::Kotlin => GrammarPin::crate_pin(
                "tree-sitter-kotlin-ng",
                "1.1.0",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-kotlin-ng/1.1.0/source/",
            ),
            Self::Swift => GrammarPin::crate_pin(
                "tree-sitter-swift",
                "0.7.4",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-swift/0.7.4/source/",
            ),
            Self::Ruby => GrammarPin::crate_pin(
                "tree-sitter-ruby",
                "0.23.1",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-ruby/0.23.1/source/",
            ),
            Self::Php => GrammarPin::crate_pin(
                "tree-sitter-php",
                "0.25.1",
                "LANGUAGE_PHP",
                15,
                "https://docs.rs/crate/tree-sitter-php/0.25.1/source/",
            ),
            Self::Bash => GrammarPin::crate_pin(
                "tree-sitter-bash",
                "0.25.1",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-bash/0.25.1/source/",
            ),
            Self::Ocaml => GrammarPin::crate_pin(
                "tree-sitter-ocaml",
                "0.26.0",
                "LANGUAGE_OCAML",
                15,
                "https://docs.rs/crate/tree-sitter-ocaml/0.26.0/source/",
            ),
            Self::OcamlInterface => GrammarPin::crate_pin(
                "tree-sitter-ocaml",
                "0.26.0",
                "LANGUAGE_OCAML_INTERFACE",
                15,
                "https://docs.rs/crate/tree-sitter-ocaml/0.26.0/source/",
            ),
            Self::Lua => GrammarPin::crate_pin(
                "tree-sitter-lua",
                "0.5.0",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-lua/0.5.0/source/",
            ),
            Self::Html => GrammarPin::crate_pin(
                "tree-sitter-html",
                "0.23.2",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-html/0.23.2/source/",
            ),
            Self::Css => GrammarPin::crate_pin(
                "tree-sitter-css",
                "0.25.0",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-css/0.25.0/source/",
            ),
            Self::Json => GrammarPin::crate_pin(
                "tree-sitter-json",
                "0.24.8",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-json/0.24.8/source/",
            ),
            Self::Toml => GrammarPin::crate_pin(
                "tree-sitter-toml-ng",
                "0.7.0",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-toml-ng/0.7.0/source/",
            ),
            Self::Vue => GrammarPin::vendored(
                "tree-sitter-grammars/tree-sitter-vue",
                "ce8011a414fdf8091f4e4071752efc376f4afb08",
                "tree_sitter_vue",
                15,
                "https://github.com/tree-sitter-grammars/tree-sitter-vue/blob/ce8011a414fdf8091f4e4071752efc376f4afb08/src/parser.c",
            ),
            Self::Svelte => GrammarPin::crate_pin(
                "tree-sitter-svelte-ng",
                "1.0.2",
                "LANGUAGE",
                14,
                "https://docs.rs/crate/tree-sitter-svelte-ng/1.0.2/source/",
            ),
            Self::Markdown => GrammarPin::crate_pin(
                "tree-sitter-md",
                "0.5.3",
                "LANGUAGE",
                15,
                "https://docs.rs/crate/tree-sitter-md/0.5.3/source/",
            ),
            Self::Mdx => GrammarPin::host_library(
                "mdxjs",
                "1.0.4",
                "mdxjs::mdast_util_from_mdx",
                "https://docs.rs/mdxjs/1.0.4/mdxjs/fn.mdast_util_from_mdx.html",
            ),
            Self::Notebook => GrammarPin::host_library(
                "tree-sitter-json + serde_json",
                "0.24.8",
                "JSON byte spans and typed cell adapter",
                "https://docs.rs/crate/tree-sitter-json/0.24.8/source/",
            ),
        }
    }

    /// Minimal valid sample the readiness gate parses with this language's
    /// pinned grammar. Each sample exercises the external scanner where the
    /// grammar has one (heredoc, raw strings, inline HTML, front-matter
    /// adjacency) and the adapter's primary named unit.
    #[must_use]
    pub const fn readiness_sample(self) -> &'static str {
        match self {
            Self::Rust => "fn ready() -> u32 {\n    1\n}\n",
            Self::Python => "def ready():\n    return 1\n",
            Self::Go => "package ready\n\nfunc Ready() int {\n\treturn 1\n}\n",
            Self::Yaml => "ready:\n  enabled: true\n",
            Self::Javascript => "export function ready() {\n  return 1;\n}\n",
            Self::Typescript => "export function ready(): number {\n  return 1;\n}\n",
            Self::Tsx => "export function Ready(): number {\n  return 1;\n}\n",
            Self::C => "int ready(void) {\n  return 1;\n}\n",
            Self::Cpp => "int ready() {\n  return 1;\n}\n",
            Self::Java => "class Ready {\n  int ready() {\n    return 1;\n  }\n}\n",
            Self::CSharp => "class Ready {\n  int Get() {\n    return 1;\n  }\n}\n",
            Self::Kotlin => "fun ready(): Int {\n  return 1\n}\n",
            Self::Swift => "func ready() -> Int {\n  return 1\n}\n",
            Self::Ruby => "def ready\n  1\nend\n",
            Self::Php => "<?php\nfunction ready(): int {\n  return 1;\n}\n",
            Self::Bash => "#!/usr/bin/env bash\nready() {\n  echo 1\n}\n",
            Self::Ocaml => "let ready () = 1\n",
            Self::OcamlInterface => "val ready : unit -> int\n",
            Self::Lua => "local function ready()\n  return 1\nend\n",
            Self::Html => "<!doctype html>\n<html><body><p>ready</p></body></html>\n",
            Self::Css => ".ready {\n  color: green;\n}\n",
            Self::Json => "{\"ready\": true}\n",
            Self::Toml => "[ready]\nenabled = true\n",
            Self::Vue => "<template>\n  <p>{{ msg }}</p>\n</template>\n",
            Self::Svelte => "<script>\n  let msg = 1;\n</script>\n<p>{msg}</p>\n",
            Self::Markdown => "# Ready\n\nSome text.\n",
            Self::Mdx => "# Ready\n\nSome text.\n",
            Self::Notebook => {
                "{\"cells\": [], \"metadata\": {}, \"nbformat\": 4, \"nbformat_minor\": 5}\n"
            }
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Exact dependency/source pin behind one [`Language`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrammarPin {
    /// Registry crate name, vendored repository, or host-library description.
    pub origin: &'static str,
    /// Exact crate version, commit SHA, or host version.
    pub version: &'static str,
    /// Selected Rust export (`LANGUAGE`, `LANGUAGE_TSX`, `tree_sitter_vue`,
    /// or the host entry point).
    pub export: &'static str,
    /// Generated parser ABI, or 0 when the entry is a host library rather
    /// than a generated parser (MDX, notebook).
    pub abi: u8,
    /// Published package/commit source evidence URL.
    pub source: &'static str,
    /// License of the grammar package. All registry grammars and the
    /// vendored Vue parser are MIT; auxiliary build/parser dependencies keep
    /// their own package licenses.
    pub license: &'static str,
    /// Whether the parser is vendored C (Vue) rather than a registry crate.
    pub vendored: bool,
}

impl GrammarPin {
    const fn crate_pin(
        origin: &'static str,
        version: &'static str,
        export: &'static str,
        abi: u8,
        source: &'static str,
    ) -> Self {
        Self {
            origin,
            version,
            export,
            abi,
            source,
            license: "MIT",
            vendored: false,
        }
    }

    const fn vendored(
        origin: &'static str,
        version: &'static str,
        export: &'static str,
        abi: u8,
        source: &'static str,
    ) -> Self {
        Self {
            origin,
            version,
            export,
            abi,
            source,
            license: "MIT",
            vendored: true,
        }
    }

    const fn host_library(
        origin: &'static str,
        version: &'static str,
        export: &'static str,
        source: &'static str,
    ) -> Self {
        Self {
            origin,
            version,
            export,
            abi: 0,
            source,
            license: "MIT",
            vendored: false,
        }
    }
}

/// Errors of the syntax stage that abort merging instead of declining to
/// text fallback. Parse failures, size overruns, and unavailable grammars
/// are *declines* (see `DeclineReason` in `super`); only cancellation and
/// invalid caller input surface here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyntaxError {
    /// The caller cancelled. Never falls back to text merge.
    #[error("cancelled: {0}")]
    Cancelled(String),
    /// Caller input rejected at the boundary (unknown language override,
    /// empty path, oversized override).
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
}

impl SyntaxError {
    /// The closed error code this failure reports.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Cancelled(_) => ErrorCode::ECancelled,
            Self::Invalid { .. } => ErrorCode::EInvalid,
        }
    }
}

impl From<SyntaxError> for CoreError {
    fn from(err: SyntaxError) -> Self {
        let message = err.to_string();
        Self::new(err.code(), message)
    }
}

/// Cooperative cancellation checked at triplet, parse, per-unit, splice, and
/// re-parse boundaries. Backed by an optional shared atomic flag so a
/// coordinator can cancel in-flight syntax work; [`Cancel::never`] disables
/// checks for contexts without a flag.
#[derive(Debug, Clone, Default)]
pub struct Cancel {
    flag: Option<std::sync::Arc<AtomicBool>>,
}

impl Cancel {
    /// A token that never fires.
    #[must_use]
    pub fn never() -> Self {
        Self::default()
    }

    /// A token firing when `flag` is set.
    #[must_use]
    pub fn from_flag(flag: std::sync::Arc<AtomicBool>) -> Self {
        Self { flag: Some(flag) }
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
    }

    /// Returns `E_CANCELLED` when cancellation was requested.
    ///
    /// # Errors
    /// The caller requested cancellation.
    pub fn check(&self) -> Result<(), SyntaxError> {
        if self.is_cancelled() {
            return Err(SyntaxError::Cancelled(
                "syntax merge cancelled before publication".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One node of a provider-neutral parse tree. Links are indices into
/// [`ParsedTree::nodes`]; [`NODE_NONE`] terminates child/sibling chains and
/// marks the root's parent. `field` names the tree-sitter field of the edge
/// from the parent ([`FIELD_NONE`] when the edge has no field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedNode {
    /// Index into [`ParsedTree::kinds`].
    pub kind: u32,
    /// Index into [`ParsedTree::fields`], or [`FIELD_NONE`].
    pub field: u32,
    /// Half-open byte range in the parsed source.
    pub start: u32,
    /// Half-open byte range in the parsed source.
    pub end: u32,
    /// Parent node index, or [`NODE_NONE`] for the root.
    pub parent: u32,
    /// First child index, or [`NODE_NONE`].
    pub first_child: u32,
    /// Next sibling index, or [`NODE_NONE`].
    pub next_sibling: u32,
    /// Whether the node is named (not anonymous punctuation/trivia).
    pub is_named: bool,
    /// Whether the node is an ERROR node.
    pub is_error: bool,
    /// Whether the node is a missing (inserted) node.
    pub is_missing: bool,
}

/// A bounded, engine-owned parse tree. The provider walks its native
/// tree-sitter tree once and fills these flat tables; the merge driver then
/// works only with indices, never with parser pointers. Table sizes are
/// bounded by the parsed input size, which is itself bounded by
/// [`MAX_TRIPLET_BYTES`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedTree {
    /// Interned node-kind names.
    pub kinds: Vec<Box<str>>,
    /// Interned field names.
    pub fields: Vec<Box<str>>,
    /// Flat node table in tree order; index 0 is the root.
    pub nodes: Vec<ParsedNode>,
    /// Length of the parsed source in bytes.
    pub source_len: u32,
}

impl ParsedTree {
    /// Converts a node index to `usize` without a truncating cast.
    fn index(node: u32) -> Option<usize> {
        usize::try_from(node).ok()
    }

    /// Kind name of `node`, or `"<absent>"` for an unknown index.
    #[must_use]
    pub fn kind_of(&self, node: u32) -> &str {
        Self::index(node)
            .and_then(|index| self.nodes.get(index))
            .and_then(|n| Self::index(n.kind).and_then(|k| self.kinds.get(k)))
            .map_or("<absent>", |kind| kind.as_ref())
    }

    /// Field name of the edge from the parent, if any.
    #[must_use]
    pub fn field_of(&self, node: u32) -> Option<&str> {
        let node = Self::index(node).and_then(|index| self.nodes.get(index))?;
        if node.field == FIELD_NONE {
            return None;
        }
        Self::index(node.field).and_then(|index| self.fields.get(index).map(|f| f.as_ref()))
    }

    /// Raw node record, if present.
    #[must_use]
    pub fn get(&self, node: u32) -> Option<&ParsedNode> {
        Self::index(node).and_then(|index| self.nodes.get(index))
    }

    /// Child indices of `node` in source order.
    pub fn children(&self, node: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cursor = self.get(node).map_or(NODE_NONE, |n| n.first_child);
        while cursor != NODE_NONE {
            out.push(cursor);
            cursor = self.get(cursor).map_or(NODE_NONE, |n| n.next_sibling);
        }
        out
    }

    /// Named child indices of `node` in source order.
    pub fn named_children(&self, node: u32) -> Vec<u32> {
        self.children(node)
            .into_iter()
            .filter(|child| self.get(*child).is_some_and(|n| n.is_named))
            .collect()
    }

    /// Previous sibling of `node`, or [`NODE_NONE`].
    #[must_use]
    pub fn prev_sibling(&self, node: u32) -> u32 {
        let parent = self.get(node).map_or(NODE_NONE, |n| n.parent);
        if parent == NODE_NONE {
            return NODE_NONE;
        }
        let mut prev = NODE_NONE;
        for child in self.children(parent) {
            if child == node {
                return prev;
            }
            prev = child;
        }
        NODE_NONE
    }

    /// First child of `node` whose edge field is `field`.
    #[must_use]
    pub fn child_with_field(&self, node: u32, field: &str) -> Option<u32> {
        self.children(node)
            .into_iter()
            .find(|child| self.field_of(*child) == Some(field))
    }

    /// First named child of `node` with kind `kind`.
    #[must_use]
    pub fn child_with_kind(&self, node: u32, kind: &str) -> Option<u32> {
        self.named_children(node)
            .into_iter()
            .find(|child| self.kind_of(*child) == kind)
    }

    /// Source bytes covered by `node`, clamped to `source`.
    #[must_use]
    pub fn text_of<'a>(&self, node: u32, source: &'a [u8]) -> &'a [u8] {
        let Some(n) = self.get(node) else {
            return &[];
        };
        let Ok(start) = usize::try_from(n.start) else {
            return &[];
        };
        let Ok(end) = usize::try_from(n.end) else {
            return &[];
        };
        let start = start.min(source.len());
        let end = end.min(source.len());
        if start <= end {
            &source[start..end]
        } else {
            &[]
        }
    }

    /// Whether any node is an ERROR or missing node.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.nodes.iter().any(|n| n.is_error || n.is_missing)
    }

    /// Whether the tree holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// A checked grammar provider: converts one pinned grammar's
/// `tree-sitter-language::LanguageFn` export through this seam. The parent
/// integration implements this trait once per grammar crate (plus the
/// vendored Vue bridge); the merge driver is generic over it and never names
/// a grammar crate.
///
/// Provider obligations: enforce the same [`MAX_TRIPLET_BYTES`] bound,
/// check `cancel` while parsing, reject sources the grammar cannot scan
/// with a descriptive error, and fill [`ParsedTree`] faithfully (exact byte
/// ranges, named flags, field edges, error/missing markers).
pub trait Grammar {
    /// The catalogued language this provider parses.
    fn language(&self) -> Language;

    /// Parses `source`, returning a provider-neutral tree.
    ///
    /// # Errors
    /// `E_CANCELLED` when `cancel` fires; `E_INVALID` when the source cannot
    /// be scanned (the driver converts this to a parse decline, never a
    /// claim). Providers MUST NOT fall back to another grammar.
    fn parse(&self, source: &[u8], cancel: &Cancel) -> Result<ParsedTree, SyntaxError>;
}

/// Registry mapping each plain language to its checked provider. Composed
/// languages ([`Language::is_plain`] false) have no entry: the plain merger
/// declines them before consulting the registry.
#[derive(Default)]
pub struct GrammarRegistry<'a> {
    entries: Vec<(Language, &'a dyn Grammar)>,
}

impl core::fmt::Debug for GrammarRegistry<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GrammarRegistry")
            .field("languages", &self.languages())
            .finish()
    }
}

impl<'a> GrammarRegistry<'a> {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `grammar` for its language, replacing any prior entry.
    pub fn insert(&mut self, grammar: &'a dyn Grammar) {
        let language = grammar.language();
        if let Some(slot) = self.entries.iter_mut().find(|(lang, _)| *lang == language) {
            slot.1 = grammar;
        } else {
            self.entries.push((language, grammar));
        }
    }

    /// Returns the provider for `language`, if registered.
    #[must_use]
    pub fn get(&self, language: Language) -> Option<&'a dyn Grammar> {
        self.entries
            .iter()
            .find(|(lang, _)| *lang == language)
            .map(|(_, grammar)| *grammar)
    }

    /// Languages with a registered provider.
    #[must_use]
    pub fn languages(&self) -> Vec<Language> {
        self.entries.iter().map(|(lang, _)| *lang).collect()
    }
}

/// Splits `path` into basename bytes (after the final `/`).
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
}

/// Splits a basename into stem and lowercase-ASCII extension at the final
/// dot. Returns `None` when there is no dot or the dot leads the name.
fn extension(basename: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let dot = basename.iter().rposition(|byte| *byte == b'.')?;
    if dot == 0 {
        return None;
    }
    let stem = basename[..dot].to_vec();
    let ext = basename[dot + 1..].to_ascii_lowercase();
    if ext.is_empty() {
        return None;
    }
    Some((stem, ext))
}

/// Validates a `ruk-language` attribute override. `"text"` explicitly
/// disables syntax for the path (`Ok(None)`); a known identifier selects
/// that language; anything else fails `E_INVALID` before mutation.
fn resolve_override(override_id: &str) -> Result<Option<Language>, SyntaxError> {
    if override_id == "text" {
        return Ok(None);
    }
    if override_id.len() > MAX_OVERRIDE_BYTES {
        return Err(SyntaxError::Invalid {
            what: "ruk-language override",
            detail: format!("{override_id:?} exceeds {MAX_OVERRIDE_BYTES} bytes"),
        });
    }
    Language::from_id(override_id).map_or_else(
        || {
            Err(SyntaxError::Invalid {
                what: "ruk-language override",
                detail: format!("unknown language {override_id:?}"),
            })
        },
        |language| Ok(Some(language)),
    )
}

/// Recognizes a Bash shebang on an extensionless script or `.sh` file.
/// Parses direct interpreter paths and `/usr/bin/env` with optional `-S`
/// without executing anything. Only the fixed executable basenames
/// `python`/`python3`, `ruby`, `bash`, and `lua` select a language; unknown
/// versions and names select text.
fn shebang_language(first_line: &[u8]) -> Option<Language> {
    let line = first_line.strip_prefix(b"#!")?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|part| !part.is_empty());
    let interpreter = parts.next()?;
    let executable: &[u8] = if interpreter == b"/usr/bin/env" {
        let mut next = parts.next()?;
        if next == b"-S" {
            next = parts.next()?;
        }
        next
    } else {
        interpreter
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or(interpreter)
    };
    // A version suffix (python3.12) or flag bundle still names the same
    // interpreter only for the fixed basenames below.
    match executable {
        b"python" | b"python3" => Some(Language::Python),
        b"ruby" => Some(Language::Ruby),
        b"bash" => Some(Language::Bash),
        b"lua" => Some(Language::Lua),
        _ => None,
    }
}

/// Deterministic language dispatch for one path.
///
/// Precedence: a validated `ruk-language` attribute override first, then
/// exact basename/extension mapping, then a recognized shebang for
/// extensionless scripts and `.sh`, otherwise ordinary text (`Ok(None)`).
/// Explicit `merge=binary|union|text` attributes are resolved by the content
/// driver before this function is consulted and never reach it.
///
/// Ambiguous `.h`, `.inc`, and `.sh` files default to text: `.h`/`.inc`
/// never guess C versus C++, and `.sh` selects Bash only for a Bash shebang
/// or an explicit `bash` override. POSIX sh, fish, and PowerShell are not
/// relabelled Bash. No Objective-C selection from `.m`/`.mm`; JSONC,
/// SCSS/Sass, and SQL dialects are not relabelled.
///
/// # Errors
/// An unknown or oversized override identifier (`E_INVALID`).
pub fn dispatch(
    path: &[u8],
    first_line: Option<&[u8]>,
    override_id: Option<&str>,
) -> Result<Option<Language>, SyntaxError> {
    if let Some(override_id) = override_id {
        return resolve_override(override_id);
    }
    if path.is_empty() {
        return Err(SyntaxError::Invalid {
            what: "merge path",
            detail: "empty path".to_owned(),
        });
    }
    let base = basename(path);
    // Exact basenames first (extensionless configuration files).
    if base == b"Rakefile" || base == b"Gemfile" {
        return Ok(Some(Language::Ruby));
    }
    if base == b"Cargo.lock" {
        return Ok(Some(Language::Toml));
    }
    let Some((_, ext)) = extension(base) else {
        // Extensionless: shebang only.
        return Ok(first_line.and_then(shebang_language));
    };
    dispatch_extension(&ext, first_line)
}

/// Maps a lowercase file extension to its language. `.h`/`.inc` never guess
/// C versus C++; `.sh` selects Bash only for a Bash shebang.
fn dispatch_extension(
    ext: &[u8],
    first_line: Option<&[u8]>,
) -> Result<Option<Language>, SyntaxError> {
    let language = match ext {
        b"rs" => Some(Language::Rust),
        b"py" | b"pyi" => Some(Language::Python),
        b"go" => Some(Language::Go),
        b"yaml" | b"yml" => Some(Language::Yaml),
        b"js" | b"mjs" | b"cjs" | b"jsx" => Some(Language::Javascript),
        b"ts" | b"mts" | b"cts" => Some(Language::Typescript),
        b"tsx" => Some(Language::Tsx),
        b"c" => Some(Language::C),
        b"cc" | b"cpp" | b"cxx" | b"hpp" | b"hh" | b"hxx" => Some(Language::Cpp),
        b"java" => Some(Language::Java),
        b"cs" => Some(Language::CSharp),
        b"kt" | b"kts" => Some(Language::Kotlin),
        b"swift" => Some(Language::Swift),
        b"rb" => Some(Language::Ruby),
        b"php" | b"phtml" => Some(Language::Php),
        b"bash" => Some(Language::Bash),
        b"ml" => Some(Language::Ocaml),
        b"mli" => Some(Language::OcamlInterface),
        b"lua" => Some(Language::Lua),
        b"html" | b"htm" => Some(Language::Html),
        b"css" => Some(Language::Css),
        b"json" => Some(Language::Json),
        b"toml" => Some(Language::Toml),
        b"vue" => Some(Language::Vue),
        b"svelte" => Some(Language::Svelte),
        b"md" | b"markdown" => Some(Language::Markdown),
        b"mdx" => Some(Language::Mdx),
        b"ipynb" => Some(Language::Notebook),
        // Ambiguous headers and unknown extensions stay text.
        b"h" | b"inc" => None,
        b"sh" => {
            let shebang = first_line.and_then(shebang_language);
            return Ok(if shebang == Some(Language::Bash) {
                shebang
            } else {
                None
            });
        }
        _ => None,
    };
    Ok(language)
}

/// SHA-256 hex digest binding a merge input. Digests travel in
/// [`SyntaxProvenance`](super::SyntaxProvenance) so the coordinator can
/// validate returned byte-range edits against the exact sources.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// The build-generated manifest digest: SHA-256 over
/// [`manifest_digest_input`]. Reported beside `language_set_version` on
/// mergeability and merge results so callers distinguish catalogue
/// revisions; same version with a different digest is a build-contract
/// error, not a cache-compatible revision.
#[must_use]
pub fn manifest_digest() -> String {
    sha256_hex(&manifest_digest_input())
}

/// Deterministic manifest-digest input pinning `language_set_version = 1`.
///
/// The returned bytes are the exact, stable input the parent build hashes
/// (SHA-256) into the build-generated manifest digest stored beside
/// `language_set_version`: one header line, one line per catalogued language
/// in canonical order (`id|origin|version|export|abi|license`), one adapter
/// rule line, and the triplet bound. Same version with a different digest is
/// a build-contract error, not a cache-compatible revision.
#[must_use]
pub fn manifest_digest_input() -> Vec<u8> {
    let mut out = String::from("ruk-syntax-manifest/v1\nlanguage_set_version=1\n");
    for language in Language::ALL {
        let pin = language.grammar_pin();
        out.push_str(&format!(
            "{}|{}|{}|{}|{}|{}|{}\n",
            language.id(),
            pin.origin,
            pin.version,
            pin.export,
            pin.abi,
            pin.license,
            if pin.vendored { "vendored" } else { "registry" },
        ));
    }
    out.push_str(&format!(
        "adapter-rules/v1 plain={} composed=vue,svelte,markdown,mdx,notebook\n",
        Language::ALL
            .iter()
            .filter(|lang| lang.is_plain())
            .map(|lang| lang.id())
            .collect::<Vec<_>>()
            .join(","),
    ));
    out.push_str(&format!(
        "adapter-rules-rev/{}\n",
        super::adapters::ADAPTER_RULES_REVISION,
    ));
    out.push_str(&format!("triplet-bound-bytes/{MAX_TRIPLET_BYTES}\n"));
    out.into_bytes()
}
