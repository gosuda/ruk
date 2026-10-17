//! OCaml adapters: implementation (`.ml`) and interface (`.mli`).
//!
//! Whole mutually recursive groups are single units keyed by their joined
//! bound names. Shadowed names fall under the duplicate-key rule. Functors,
//! local opens, operators bound to symbol names, and ordered bindings
//! without an attributable name stay gaps or decline when touched.
//!
//! The `tree-sitter-ocaml` 0.26.0 node-kind table below is best-effort from
//! the pinned grammar: kinds that fail to match only shrink coverage to
//! conservative gaps, and the readiness gate plus fixture suite verify the
//! table before release.

use super::{Adapter, SourceUnit, UnitKey, attach_leading_trivia, declared_name, offset};
use crate::merge::syntax::grammar::{Language, NODE_NONE, ParsedTree};

/// Node kinds that form merge units (whole `and`-groups, never fragments).
const IMPL_UNIT_KINDS: &[&str] = &[
    "value_definition",
    "module_definition",
    "type_definition",
    "external_definition",
    "exception_definition",
    "class_definition",
];

/// Node kinds that form merge units in signatures.
const SIG_UNIT_KINDS: &[&str] = &[
    "value_specification",
    "module_definition",
    "type_definition",
    "exception_definition",
    "class_definition",
    "external_definition",
];

/// Transparent bodies: their members extract with parent context.
const BODY_KINDS: &[&str] = &["structure", "signature", "functor_body"];

/// Module/type/class/exception/value name leaves for non-binding
/// definitions. `value_name` is safe here: inside `value_definition` the
/// bound names ride `pattern` edges under `let_binding`, never as direct
/// children, while interface `value_specification` carries its name as a
/// direct `value_name` child.
const DECL_NAME_KINDS: &[&str] = &[
    "module_name",
    "type_constructor",
    "class_name",
    "exception_name",
    "value_name",
];

/// Maximum joined group-name bytes kept in a key.
const MAX_GROUP_NAME_BYTES: usize = 128;

/// Bound name of one `let_binding`: the `pattern`-edge child outside
/// `parameter` subtrees, whose own patterns must not leak into the key.
/// Empty when the binding carries no attributable pattern.
fn binding_pattern_name(tree: &ParsedTree, source: &[u8], binding: u32) -> Vec<u8> {
    for grandchild in tree.named_children(binding) {
        if tree.kind_of(grandchild) == "parameter" {
            continue;
        }
        if tree.field_of(grandchild) != Some("pattern") {
            continue;
        }
        let text = tree.text_of(grandchild, source).to_vec();
        if !text.is_empty() {
            return text;
        }
    }
    Vec::new()
}

/// Collects bound names of a mutually recursive group: the `name`-edge
/// child first, then one `pattern`-edge name per `let_binding`, joined by
/// `&`. Only binding-position names are read, so editing a body cannot
/// change the unit's identity. Empty when nothing attributable is found.
fn group_name(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
    if let Some(name) = tree.child_with_field(node, "name") {
        let text = tree.text_of(name, source).to_vec();
        if !text.is_empty() {
            return text;
        }
    }
    let mut names: Vec<Vec<u8>> = Vec::new();
    for child in tree.named_children(node) {
        if names.join("&".as_bytes()).len() >= MAX_GROUP_NAME_BYTES {
            break;
        }
        if tree.kind_of(child).ends_with("binding") {
            let name = binding_pattern_name(tree, source, child);
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
            continue;
        }
        if DECL_NAME_KINDS.contains(&tree.kind_of(child)) {
            let text = tree.text_of(child, source).to_vec();
            if !text.is_empty() && !names.contains(&text) {
                names.push(text);
            }
        }
    }
    let joined = names.join(b"&".as_slice());
    joined[..joined.len().min(MAX_GROUP_NAME_BYTES)].to_vec()
}

/// Discriminator: functor parameter and return-signature text, so applied
/// functors with the same name but different parameters do not pair.
fn group_discriminator(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
    tree.named_children(node)
        .into_iter()
        .filter(|child| {
            let kind = tree.kind_of(*child);
            kind.contains("functor") || kind.contains("parameter")
        })
        .map(|child| tree.text_of(child, source).to_vec())
        .collect::<Vec<_>>()
        .join(b"|".as_slice())
}

fn collect(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    unit_kinds: &[&str],
    parents: &mut Vec<Vec<u8>>,
    out: &mut Vec<SourceUnit>,
    depth: usize,
) {
    if depth > super::MAX_WALK_DEPTH {
        return;
    }
    let kind = tree.kind_of(node).to_owned();
    if unit_kinds.contains(&kind.as_str()) {
        // A module with a decomposable body is a container only: its
        // members extract with the module name as parent while the header
        // stays a gap, so a renamed module cannot pair its old members by
        // name alone. A module without a body is a leaf unit. Never both:
        // units must not overlap.
        if kind == "module_definition"
            && tree
                .named_children(node)
                .iter()
                .any(|child| BODY_KINDS.contains(&tree.kind_of(*child)))
        {
            let inner = group_name(tree, source, node);
            if inner.is_empty() {
                return;
            }
            let mut qualified = inner;
            qualified.push(0);
            parents.push(qualified);
            for child in tree.named_children(node) {
                if BODY_KINDS.contains(&tree.kind_of(child)) {
                    for member in tree.named_children(child) {
                        collect(tree, source, member, unit_kinds, parents, out, depth + 1);
                    }
                }
            }
            parents.pop();
            return;
        }
        let mut name = group_name(tree, source, node);
        if name.is_empty() {
            // Local opens (`open M`) carry no name and stay gaps.
            name = declared_name(tree, source, node, &[]);
            if name.is_empty() {
                return;
            }
        }
        let discriminator = group_discriminator(tree, source, node);
        let parent = parents.concat();
        let Some(record) = tree.get(node) else {
            return;
        };
        let start = attach_leading_trivia(tree, source, node, &["comment", "attribute"], &[]);
        if offset(start).is_none() || offset(record.end).is_none() {
            return;
        }
        out.push(SourceUnit {
            key: UnitKey::new(kind, name, discriminator, parent),
            start,
            end: record.end,
            node,
        });
        return;
    }
    let is_root = tree.get(node).is_some_and(|n| n.parent == NODE_NONE);
    if BODY_KINDS.contains(&kind.as_str()) || is_root {
        for child in tree.named_children(node) {
            collect(tree, source, child, unit_kinds, parents, out, depth + 1);
        }
    }
}

fn extract(tree: &ParsedTree, source: &[u8], unit_kinds: &[&str]) -> Vec<SourceUnit> {
    let mut out = Vec::new();
    if tree.is_empty() {
        return out;
    }
    let mut parents = Vec::new();
    collect(tree, source, 0, unit_kinds, &mut parents, &mut out, 0);
    out.sort_by_key(|unit| (unit.start, unit.end));
    out
}

/// OCaml implementation files (`.ml`, `LANGUAGE_OCAML`).
#[derive(Debug)]
pub struct OcamlAdapter;

impl Adapter for OcamlAdapter {
    fn language(&self) -> Language {
        Language::Ocaml
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        extract(tree, source, IMPL_UNIT_KINDS)
    }
}

/// OCaml interface files (`.mli`, `LANGUAGE_OCAML_INTERFACE`).
#[derive(Debug)]
pub struct OcamlInterfaceAdapter;

impl Adapter for OcamlInterfaceAdapter {
    fn language(&self) -> Language {
        Language::OcamlInterface
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        extract(tree, source, SIG_UNIT_KINDS)
    }
}
