//! Web-language adapters: JavaScript (with JSX), TypeScript, TSX.
//!
//! Named functions, classes, and whole import/export statements are units.
//! Class and interface bodies decompose into uniquely named members.
//! Overload signatures share keys by construction and fall under the
//! duplicate-key rule. Anonymous callbacks, JSX sibling lists, and computed
//! property names keep their exact bytes as keys: unique ones merge when the
//! surrounding context proves the unit, duplicates decline. `export`
//! wrappers are transparent; only bare re-exports (`export { … }`,
//! `export *`, `export default <expression>`) are whole-statement units.

use super::{
    Adapter, SourceUnit, UnitKey, attach_leading_trivia, declared_name, discriminator_by_kind,
    offset,
};
use crate::merge::syntax::grammar::{Language, NODE_NONE, ParsedTree};

/// Node kinds that declare members inside a class or interface body.
/// Verified against the pinned grammars' `node-types.json`.
const MEMBER_KINDS: &[&str] = &[
    "method_definition",
    "field_definition",
    "public_field_definition",
    "method_signature",
    "property_signature",
    "call_signature",
    "construct_signature",
    "index_signature",
    "abstract_method_signature",
];

/// Body wrappers traversed transparently: class bodies, TypeScript
/// `interface_body`, and `object_type` everywhere. Statement blocks and
/// function bodies are never listed, so nested functions never leak out as
/// member units. (`object_type` also occurs in type positions, but those
/// parents are units or gaps that return before descent, so only
/// member-position object types ever unwrap.)
const BODY_WRAPPER_KINDS: &[&str] = &["class_body", "interface_body", "object_type"];

/// Node kinds that declare a value or type at statement level.
const DECL_KINDS: &[&str] = &[
    "function_declaration",
    "generator_function_declaration",
    "class_declaration",
    "abstract_class_declaration",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "namespace_declaration",
    "module_declaration",
    "ambient_declaration",
];

/// Whether a declaration node is a single declarator holding a function
/// value (`const f = () => …`): the only variable shape that becomes a
/// unit. Multi-declarator lists and non-function values stay gaps.
fn single_function_value(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if tree.kind_of(node) != "lexical_declaration" && tree.kind_of(node) != "variable_declaration" {
        return None;
    }
    let declarators: Vec<u32> = tree
        .named_children(node)
        .into_iter()
        .filter(|child| tree.kind_of(*child) == "variable_declarator")
        .collect();
    if declarators.len() != 1 {
        return None;
    }
    let declarator = declarators[0];
    let name = tree
        .child_with_field(declarator, "name")
        .map_or_else(Vec::new, |name| tree.text_of(name, source).to_vec());
    if name.is_empty() {
        return None;
    }
    let value = tree.child_with_field(declarator, "value")?;
    let value_kind = tree.kind_of(value);
    if ![
        "function_expression",
        "arrow_function",
        "generator_function",
        "async_function",
    ]
    .contains(&value_kind)
    {
        return None;
    }
    let params = tree
        .named_children(value)
        .into_iter()
        .find(|child| ["formal_parameters", "parameters"].contains(&tree.kind_of(*child)))
        .map_or_else(Vec::new, |params| tree.text_of(params, source).to_vec());
    Some((name, params))
}

/// Declared name of an export statement's inner declaration, if it wraps
/// one. Bare re-exports have no inner declaration.
fn export_inner_name(tree: &ParsedTree, source: &[u8], node: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    for child in tree.named_children(node) {
        let kind = tree.kind_of(child);
        if DECL_KINDS.contains(&kind)
            || kind == "lexical_declaration"
            || kind == "variable_declaration"
        {
            if kind == "lexical_declaration" || kind == "variable_declaration" {
                return single_function_value(tree, source, child);
            }
            let name = declared_name(tree, source, child, &[]);
            if name.is_empty() {
                return None;
            }
            let discriminator = discriminator_by_kind(
                tree,
                source,
                child,
                &[
                    "formal_parameters",
                    "type_parameters",
                    "return_type",
                    "heritage",
                ],
            );
            return Some((name, discriminator));
        }
    }
    None
}

fn push_unit(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    kind: String,
    name: Vec<u8>,
    discriminator: Vec<u8>,
    parent: &[u8],
    out: &mut Vec<SourceUnit>,
) {
    let Some(record) = tree.get(node) else {
        return;
    };
    let start = attach_leading_trivia(tree, source, node, &["comment"], &["decorator"]);
    if offset(start).is_none() || offset(record.end).is_none() {
        return;
    }
    out.push(SourceUnit {
        key: UnitKey::new(kind, name, discriminator, parent.to_vec()),
        start,
        end: record.end,
        node,
    });
}

/// Extracts units under `node`, threading class/interface parent names.
/// Descent stops at [`MAX_WALK_DEPTH`](super::MAX_WALK_DEPTH); deeper
/// subtrees stay gaps.
fn collect(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    parents: &mut Vec<Vec<u8>>,
    out: &mut Vec<SourceUnit>,
    depth: usize,
) {
    if depth > super::MAX_WALK_DEPTH {
        return;
    }
    let kind = tree.kind_of(node).to_owned();
    if kind == "import_statement" {
        // Whole import statements are units keyed by their exact text:
        // order and trivia are preserved by the splice, never sorted.
        let text = tree.text_of(node, source).to_vec();
        push_unit(
            tree,
            source,
            node,
            kind,
            text,
            Vec::new(),
            &parents.concat(),
            out,
        );
        return;
    }
    if kind == "export_statement" {
        match export_inner_name(tree, source, node) {
            Some((name, discriminator)) => {
                push_unit(
                    tree,
                    source,
                    node,
                    kind,
                    name,
                    discriminator,
                    &parents.concat(),
                    out,
                );
            }
            None => {
                let text = tree.text_of(node, source).to_vec();
                push_unit(
                    tree,
                    source,
                    node,
                    kind,
                    text,
                    Vec::new(),
                    &parents.concat(),
                    out,
                );
            }
        }
        return;
    }
    if DECL_KINDS.contains(&kind.as_str()) {
        let name = declared_name(tree, source, node, &[]);
        if kind == "class_declaration"
            || kind == "abstract_class_declaration"
            || kind == "interface_declaration"
        {
            // Classes and interfaces contribute parent context; their
            // headers stay gaps so heritage changes decline. Members are
            // reached through the body wrapper only.
            if !name.is_empty() {
                let mut qualified = name;
                qualified.push(0);
                parents.push(qualified);
                for child in tree.named_children(node) {
                    let body = BODY_WRAPPER_KINDS.contains(&tree.kind_of(child))
                        || tree.field_of(child) == Some("body");
                    if body || MEMBER_KINDS.contains(&tree.kind_of(child)) {
                        collect(tree, source, child, parents, out, depth + 1);
                    }
                }
                parents.pop();
            }
            return;
        }
        let discriminator = discriminator_by_kind(
            tree,
            source,
            node,
            &[
                "formal_parameters",
                "type_parameters",
                "return_type",
                "heritage",
            ],
        );
        push_unit(
            tree,
            source,
            node,
            kind,
            name,
            discriminator,
            &parents.concat(),
            out,
        );
        return;
    }
    if kind == "lexical_declaration" || kind == "variable_declaration" {
        if let Some((name, discriminator)) = single_function_value(tree, source, node) {
            push_unit(
                tree,
                source,
                node,
                kind,
                name,
                discriminator,
                &parents.concat(),
                out,
            );
        }
        return;
    }
    if MEMBER_KINDS.contains(&kind.as_str()) {
        let name = declared_name(tree, source, node, &[]);
        let discriminator = discriminator_by_kind(
            tree,
            source,
            node,
            &["formal_parameters", "type_parameters", "return_type"],
        );
        push_unit(
            tree,
            source,
            node,
            kind,
            name,
            discriminator,
            &parents.concat(),
            out,
        );
        return;
    }
    let is_root = tree.get(node).is_some_and(|n| n.parent == NODE_NONE);
    if BODY_WRAPPER_KINDS.contains(&kind.as_str()) {
        // Transparent wrapper reached directly (nested case): unwrap one
        // level into member position.
        for child in tree.named_children(node) {
            collect(tree, source, child, parents, out, depth + 1);
        }
        return;
    }
    if !is_root {
        return;
    }
    for child in tree.named_children(node) {
        collect(tree, source, child, parents, out, depth + 1);
    }
}

fn extract(tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
    let mut out = Vec::new();
    if tree.is_empty() {
        return out;
    }
    let mut parents = Vec::new();
    collect(tree, source, 0, &mut parents, &mut out, 0);
    out.sort_by_key(|unit| (unit.start, unit.end));
    out
}

macro_rules! web_adapter {
    ($name:ident, $lang:expr) => {
        /// Structural adapter; see the module documentation.
        #[derive(Debug)]
        pub struct $name;

        impl Adapter for $name {
            fn language(&self) -> Language {
                $lang
            }

            fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
                extract(tree, source)
            }
        }
    };
}

web_adapter!(JavascriptAdapter, Language::Javascript);
web_adapter!(TypescriptAdapter, Language::Typescript);
web_adapter!(TsxAdapter, Language::Tsx);
