//! Script-language adapters: Python, Ruby, PHP, Bash, Lua.
//!
//! Top-level definitions are units; top-level statements, commands, imports,
//! and blocks stay ordered gaps. Decorated definitions and global namespaces
//! are transparent: they contribute no key of their own. PHP inline-HTML
//! (`text`) nodes are never units, and any unit crossing a PHP/template
//! boundary is dropped to a gap.

use std::collections::HashSet;

use super::{
    Adapter, SourceUnit, UnitKey, attach_leading_trivia, declared_name, discriminator_by_kind,
    offset,
};
use crate::merge::syntax::grammar::{Language, NODE_NONE, ParsedTree};

/// Declarative rules for one script language. Kind tables are verified
/// against each pinned grammar's `node-types.json`.
struct ScriptRules {
    /// Node kinds that are merge units. Containers are never units.
    unit_kinds: &'static [&'static str],
    /// Named containers descended with parent context.
    container_kinds: &'static [&'static str],
    /// Body wrappers traversed transparently at any depth (Python class
    /// suites, PHP declaration lists). Function bodies are never listed.
    body_kinds: &'static [&'static str],
    /// Transparent wrappers (decorated definitions, global namespaces).
    passthrough_kinds: &'static [&'static str],
    name_alts: &'static [&'static str],
    disc_kinds: &'static [&'static str],
    comment_kinds: &'static [&'static str],
    /// When true, drop units containing an inline-template child kind.
    boundary_kind: Option<&'static str>,
}

/// Marks every `kind` node plus all of its ancestors, in one iterative
/// pass. Units on a marked node cross a template boundary and are dropped
/// to gaps after extraction.
fn mark_ancestors(tree: &ParsedTree, kind: &str) -> HashSet<u32> {
    let mut marked = HashSet::new();
    let mut stack = vec![0_u32];
    while let Some(node) = stack.pop() {
        if tree.kind_of(node) == kind {
            let mut cursor = node;
            loop {
                marked.insert(cursor);
                cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
                if cursor == NODE_NONE {
                    break;
                }
            }
        }
        stack.extend(tree.children(node));
    }
    marked
}

fn collect(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    rules: &ScriptRules,
    language: Language,
    parents: &mut Vec<Vec<u8>>,
    out: &mut Vec<SourceUnit>,
    depth: usize,
    floor: u32,
) {
    if depth > super::MAX_WALK_DEPTH {
        return;
    }
    let kind = tree.kind_of(node).to_owned();
    if rules.unit_kinds.contains(&kind.as_str()) {
        let name = declared_name(tree, source, node, rules.name_alts);
        let discriminator = discriminator_by_kind(tree, source, node, rules.disc_kinds);
        let parent = parents.concat();
        let Some(record) = tree.get(node) else {
            return;
        };
        let start = attach_leading_trivia(tree, source, node, rules.comment_kinds, &[]).min(floor);
        if offset(start).is_none() || offset(record.end).is_none() || start > record.end {
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
    let mut pushed = false;
    if rules.container_kinds.contains(&kind.as_str()) {
        let name = declared_name(tree, source, node, rules.name_alts);
        if !name.is_empty() {
            let mut qualified = name;
            qualified.push(0);
            parents.push(qualified);
            pushed = true;
        }
    } else if !rules.passthrough_kinds.contains(&kind.as_str()) {
        if tree.get(node).is_some_and(|n| n.parent != NODE_NONE)
            && !rules.body_kinds.contains(&kind.as_str())
        {
            return;
        }
    }
    // Transparent wrappers (decorated definitions) extend the floor so the
    // wrapped definition owns its decorators: decorators belong to their
    // definition and travel with the unit.
    let floor = if rules.passthrough_kinds.contains(&kind.as_str()) {
        floor.min(tree.get(node).map_or(floor, |n| n.start))
    } else {
        floor
    };
    for child in tree.named_children(node) {
        collect(
            tree,
            source,
            child,
            rules,
            language,
            parents,
            out,
            depth + 1,
            floor,
        );
    }
    if pushed {
        parents.pop();
    }
}

fn extract(
    tree: &ParsedTree,
    source: &[u8],
    rules: &ScriptRules,
    language: Language,
) -> Vec<SourceUnit> {
    let mut out = Vec::new();
    if tree.is_empty() {
        return out;
    }
    let mut parents = Vec::new();
    collect(
        tree,
        source,
        0,
        rules,
        language,
        &mut parents,
        &mut out,
        0,
        u32::MAX,
    );
    if let Some(boundary) = rules.boundary_kind {
        let marked = mark_ancestors(tree, boundary);
        out.retain(|unit| !marked.contains(&unit.node));
    }
    out.sort_by_key(|unit| (unit.start, unit.end));
    out
}

macro_rules! script_adapter {
    ($name:ident, $lang:expr, $rules:expr) => {
        /// Structural adapter; see the module documentation.
        #[derive(Debug)]
        pub struct $name;

        impl Adapter for $name {
            fn language(&self) -> Language {
                $lang
            }

            fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
                extract(tree, source, &$rules, $lang)
            }
        }
    };
}

const PYTHON_RULES: ScriptRules = ScriptRules {
    // Imports, assignments, and expression statements (including dynamic
    // execution) stay ordered gaps, never name-paired units. Classes are
    // containers only; their suites traverse transparently while function
    // suites stay opaque (functions return as units before descent).
    unit_kinds: &["function_definition"],
    container_kinds: &["class_definition"],
    body_kinds: &["block"],
    passthrough_kinds: &["decorated_definition"],
    name_alts: &[],
    // Parameter lists pin the declared form; decorators live inside the
    // wrapped node so they travel with the unit.
    disc_kinds: &[
        "parameters",
        "type_parameters",
        "return_type",
        "superclasses",
    ],
    comment_kinds: &["comment"],
    boundary_kind: None,
};

const RUBY_RULES: ScriptRules = ScriptRules {
    // Classes and modules are containers only: members wrap in
    // `body_statement`, so direct-child traversal would miss them.
    // Reopenings share keys by construction and fall under the
    // duplicate-key rule. Top-level calls and blocks stay ordered gaps.
    unit_kinds: &["method", "singleton_method"],
    container_kinds: &["class", "module"],
    body_kinds: &["body_statement"],
    passthrough_kinds: &[],
    name_alts: &["constant", "name"],
    disc_kinds: &["parameters", "receiver", "superclass"],
    comment_kinds: &["comment"],
    boundary_kind: None,
};

const PHP_RULES: ScriptRules = ScriptRules {
    // Anonymous classes, traits adaptations, and attributes outside
    // declarations are gaps; units crossing into inline HTML are dropped.
    // Type declarations are containers only.
    unit_kinds: &[
        "function_definition",
        "method_declaration",
        "property_declaration",
        "const_declaration",
    ],
    container_kinds: &[
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
        "namespace_definition",
    ],
    // Member bodies wrap in `declaration_list`.
    body_kinds: &["declaration_list"],
    passthrough_kinds: &[],
    name_alts: &[],
    disc_kinds: &[
        "parameters",
        "return_type",
        "base_clause",
        "class_interface_clause",
    ],
    comment_kinds: &["comment"],
    boundary_kind: Some("text"),
};

const BASH_RULES: ScriptRules = ScriptRules {
    // Only complete function definitions are units (the `name` field
    // edge). Commands, assignments, redirections, traps, heredocs at top
    // level, and compound lists stay ordered gaps and are never reordered
    // or split.
    unit_kinds: &["function_definition"],
    container_kinds: &[],
    body_kinds: &[],
    passthrough_kinds: &[],
    name_alts: &[],
    disc_kinds: &[],
    comment_kinds: &["comment", "heredoc_start"],
    boundary_kind: None,
};

const LUA_RULES: ScriptRules = ScriptRules {
    // Named function declarations only (the `name` field edge; there is no
    // `local_function` or `function_name` node in this grammar). Table
    // constructors, assignments, and bare statements stay ordered gaps:
    // repeated, computed, and positional table keys never pair by name.
    unit_kinds: &["function_declaration"],
    container_kinds: &[],
    body_kinds: &[],
    passthrough_kinds: &[],
    name_alts: &[],
    disc_kinds: &["parameters", "return_type"],
    comment_kinds: &["comment"],
    boundary_kind: None,
};

script_adapter!(PythonAdapter, Language::Python, PYTHON_RULES);
script_adapter!(RubyAdapter, Language::Ruby, RUBY_RULES);
script_adapter!(PhpAdapter, Language::Php, PHP_RULES);
script_adapter!(BashAdapter, Language::Bash, BASH_RULES);
script_adapter!(LuaAdapter, Language::Lua, LUA_RULES);
