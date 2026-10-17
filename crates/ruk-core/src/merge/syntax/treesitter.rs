//! The `Grammar` provider bridge: one checked conversion per pinned
//! grammar crate's `tree-sitter-language::LanguageFn` export into the
//! engine's provider-neutral [`ParsedTree`].
//!
//! Each [`TsGrammar`] wraps one `LanguageFn`, converted through the
//! checked `Parser::set_language` gate (ABI interval 13..=15 under
//! tree-sitter 0.27.1) at construction: a grammar that rejects the
//! interval fails then, never mid-merge. Parse fills the flat node table
//! in a single non-recursive walk so deep syntax trees cannot overflow
//! the stack.
//!
//! The vendored Vue bridge ([`super::vue_ffi`]) is the only non-registry
//! grammar; it produces its `LanguageFn` from the audited extern symbol.

use std::collections::HashMap;
use std::fmt;
use std::ops::ControlFlow;
use std::sync::Mutex;

use tree_sitter::{Language as TsLanguage, Node, Parser};
use tree_sitter_language::LanguageFn;

use super::grammar::{
    Cancel, FIELD_NONE, Grammar, Language, MAX_TRIPLET_BYTES, NODE_NONE, ParsedNode, ParsedTree,
    SyntaxError,
};

/// A checked provider for one catalogued language over its pinned
/// `LanguageFn` export.
pub struct TsGrammar {
    language: Language,
    parser: Mutex<Parser>,
}

impl fmt::Debug for TsGrammar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsGrammar")
            .field("language", &self.language)
            .finish_non_exhaustive()
    }
}

impl TsGrammar {
    /// Builds the provider and checks the grammar against this runtime's
    /// accepted ABI interval. Failure is an `E_INVALID` construction error;
    /// `new` never marks the language unavailable, so callers must refuse
    /// to register a rejected grammar.
    ///
    /// # Errors
    /// [`SyntaxError::Invalid`] when `set_language` rejects the ABI.
    pub fn new(language: Language, export: LanguageFn) -> Result<Self, SyntaxError> {
        let mut parser = Parser::new();
        parser
            .set_language(&TsLanguage::from(export))
            .map_err(|err| SyntaxError::Invalid {
                what: "grammar",
                detail: format!("tree-sitter rejected pinned grammar for {language}: {err}"),
            })?;
        Ok(Self {
            language,
            parser: Mutex::new(parser),
        })
    }

    /// The provider over the vendored Vue parser. Lives here so composed
    /// hosts and readiness checks share the one audited bridge.
    ///
    /// # Errors
    /// [`SyntaxError::Invalid`] when the linked grammar rejects the ABI.
    pub fn vue() -> Result<Self, SyntaxError> {
        Self::new(Language::Vue, super::vue_ffi::vue_language_fn())
    }
}

/// Interns `name` and returns its table index.
fn intern<'a>(table: &mut Vec<Box<str>>, map: &mut HashMap<&'a str, u32>, name: &'a str) -> u32 {
    if let Some(index) = map.get(name) {
        return *index;
    }
    let index = u32::try_from(table.len()).expect("intern table bounded by node count");
    table.push(name.into());
    map.insert(name, index);
    index
}

/// Fills the flat node table with one iterative cursor walk; the parser
/// tree shape is trusted for structure only, never for depth.
fn fill_nodes(root: Node<'_>, source_len: u32, cancel: &Cancel) -> Result<ParsedTree, SyntaxError> {
    let mut kinds: Vec<Box<str>> = Vec::new();
    let mut fields: Vec<Box<str>> = Vec::new();
    let mut kind_map: HashMap<&str, u32> = HashMap::new();
    let mut field_map: HashMap<&str, u32> = HashMap::new();
    let mut nodes: Vec<ParsedNode> = Vec::new();
    // Parallel to `nodes`: the most recent child index assigned per node.
    let mut last_child: Vec<u32> = Vec::new();
    // Stack of ancestor node indices, innermost last.
    let mut ancestors: Vec<u32> = Vec::new();

    let mut cursor = root.walk();
    loop {
        cancel.check()?;
        let node = cursor.node();
        let index = u32::try_from(nodes.len()).expect("node table bounded by source size");
        let parent = ancestors.last().copied().unwrap_or(NODE_NONE);

        let field = cursor
            .field_name()
            .map_or(FIELD_NONE, |name| intern(&mut fields, &mut field_map, name));
        let kind = intern(&mut kinds, &mut kind_map, node.kind());

        nodes.push(ParsedNode {
            kind,
            field,
            start: u32::try_from(node.start_byte()).unwrap_or(source_len),
            end: u32::try_from(node.end_byte()).unwrap_or(source_len),
            parent,
            first_child: NODE_NONE,
            next_sibling: NODE_NONE,
            is_named: node.is_named(),
            is_error: node.is_error(),
            is_missing: node.is_missing(),
        });
        last_child.push(NODE_NONE);

        if parent != NODE_NONE {
            let parent_index = usize::try_from(parent).expect("u32 index");
            let prev = last_child[parent_index];
            if prev == NODE_NONE {
                nodes[parent_index].first_child = index;
            } else {
                nodes[usize::try_from(prev).expect("u32 index")].next_sibling = index;
            }
            last_child[parent_index] = index;
        }

        if cursor.goto_first_child() {
            ancestors.push(index);
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return Ok(ParsedTree {
                    kinds,
                    fields,
                    nodes,
                    source_len,
                });
            }
            ancestors.pop();
        }
    }
}

impl Grammar for TsGrammar {
    fn language(&self) -> Language {
        self.language
    }

    fn parse(&self, source: &[u8], cancel: &Cancel) -> Result<ParsedTree, SyntaxError> {
        cancel.check()?;
        if u64::try_from(source.len()).unwrap_or(u64::MAX) > MAX_TRIPLET_BYTES {
            return Err(SyntaxError::Invalid {
                what: "source",
                detail: format!(
                    "source of {} bytes exceeds the {}-byte triplet bound",
                    source.len(),
                    MAX_TRIPLET_BYTES,
                ),
            });
        }
        let source_len = u32::try_from(source.len()).expect("source bounded to MAX_TRIPLET_BYTES");

        let mut parser = self.parser.lock().expect("parser mutex poisoned");
        let mut feed = |offset: usize, _point: tree_sitter::Point| -> &[u8] {
            source.get(offset..).unwrap_or(&[])
        };
        let mut progress = |_state: &tree_sitter::ParseState| {
            if cancel.is_cancelled() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let options = tree_sitter::ParseOptions::new().progress_callback(&mut progress);
        let tree = match parser.parse_with_options(&mut feed, None, Some(options)) {
            Some(tree) => tree,
            None if cancel.is_cancelled() => {
                return Err(SyntaxError::Cancelled(
                    "syntax parse cancelled inside the grammar".to_owned(),
                ));
            }
            None => {
                return Err(SyntaxError::Invalid {
                    what: "source",
                    detail: format!("tree-sitter produced no tree for {}", self.language),
                });
            }
        };

        let mut parsed = fill_nodes(tree.root_node(), source_len, cancel)?;
        // A cancelled parse can still yield a tree when the callback raced;
        // an incomplete tree must not merge.
        parsed.source_len = source_len;
        Ok(parsed)
    }
}

/// Registers a provider for every plain language against its pinned
/// registry export. Callers keep `providers` alive for the registry's
/// lifetime and check readiness before serving merges.
#[must_use]
pub fn registry_providers() -> Vec<Result<TsGrammar, SyntaxError>> {
    vec![
        TsGrammar::new(Language::Rust, tree_sitter_rust::LANGUAGE),
        TsGrammar::new(Language::Python, tree_sitter_python::LANGUAGE),
        TsGrammar::new(Language::Go, tree_sitter_go::LANGUAGE),
        TsGrammar::new(Language::Yaml, tree_sitter_yaml::LANGUAGE),
        TsGrammar::new(Language::Javascript, tree_sitter_javascript::LANGUAGE),
        TsGrammar::new(
            Language::Typescript,
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        ),
        TsGrammar::new(Language::Tsx, tree_sitter_typescript::LANGUAGE_TSX),
        TsGrammar::new(Language::C, tree_sitter_c::LANGUAGE),
        TsGrammar::new(Language::Cpp, tree_sitter_cpp::LANGUAGE),
        TsGrammar::new(Language::Java, tree_sitter_java::LANGUAGE),
        TsGrammar::new(Language::CSharp, tree_sitter_c_sharp::LANGUAGE),
        TsGrammar::new(Language::Kotlin, tree_sitter_kotlin_ng::LANGUAGE),
        TsGrammar::new(Language::Swift, tree_sitter_swift::LANGUAGE),
        TsGrammar::new(Language::Ruby, tree_sitter_ruby::LANGUAGE),
        TsGrammar::new(Language::Php, tree_sitter_php::LANGUAGE_PHP),
        TsGrammar::new(Language::Bash, tree_sitter_bash::LANGUAGE),
        TsGrammar::new(Language::Ocaml, tree_sitter_ocaml::LANGUAGE_OCAML),
        TsGrammar::new(
            Language::OcamlInterface,
            tree_sitter_ocaml::LANGUAGE_OCAML_INTERFACE,
        ),
        TsGrammar::new(Language::Lua, tree_sitter_lua::LANGUAGE),
        TsGrammar::new(Language::Html, tree_sitter_html::LANGUAGE),
        TsGrammar::new(Language::Css, tree_sitter_css::LANGUAGE),
        TsGrammar::new(Language::Json, tree_sitter_json::LANGUAGE),
        TsGrammar::new(Language::Toml, tree_sitter_toml_ng::LANGUAGE),
    ]
}
