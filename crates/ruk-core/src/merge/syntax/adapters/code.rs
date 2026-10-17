//! Compiled-language adapters: Rust, Go, C, C++, Java, C#, Kotlin, Swift.
//!
//! Shared extraction engine over per-language rule tables. Rule tables name
//! tree-sitter node kinds pinned to the grammar versions in
//! [`grammar`](super::super::grammar); kind names that fail to match only
//! shrink coverage to conservative gaps, never misattribute units.
//!
//! Containers (modules, classes, namespaces, impl blocks) are transparent:
//! they contribute parent context, never units of their own, so a renamed
//! container cannot pair its old members with new ones by name alone.
//! Preprocessor branches, macro bodies, template declarations, and import
//! groups stay opaque gaps: any change inside them declines.

use super::{
    Adapter, SourceUnit, UnitKey, attach_leading_trivia, declared_name, discriminator_by_kind,
    offset, slice_range,
};
use crate::merge::syntax::grammar::{Language, NODE_NONE, ParsedTree};

/// Declarative unit rules for one compiled language. All kind tables are
/// verified against the pinned grammar's `node-types.json`; see the module
/// documentation for the per-language evidence.
struct CodeRules {
    /// Node kinds that are merge units. Containers are never units: a type
    /// that also appears here would turn its whole body atomic and hide
    /// its members.
    unit_kinds: &'static [&'static str],
    /// Node kinds descended with their declared name as parent context.
    /// Unnamed containers traverse purely.
    container_kinds: &'static [&'static str],
    /// Body wrappers traversed without parent context of their own
    /// (`class_body`, `declaration_list`): members are reached only through
    /// these, never through function bodies (units return before descent).
    body_kinds: &'static [&'static str],
    /// Node kinds never descended (preprocessor, templates, directives).
    opaque_kinds: &'static [&'static str],
    /// Extra field names holding the declared name after `"name"`.
    name_alts: &'static [&'static str],
    /// Child kinds whose raw text discriminates overloads and receivers.
    disc_kinds: &'static [&'static str],
    /// Optional field edge prepended to the discriminator (Go receivers).
    disc_field: Option<&'static str>,
    /// When true, concatenate every matching discriminator child in order
    /// (Swift's unwrapped parameter lists) instead of taking the first.
    disc_all: bool,
    /// Comment node kinds for trivia attachment.
    comment_kinds: &'static [&'static str],
    /// Attribute node kinds for trivia attachment.
    attr_kinds: &'static [&'static str],
    /// When true, a `declaration`-shaped unit is valid only with exactly one
    /// declarator edge (C/C++ declarator lists stay gaps).
    single_declarator: bool,
}

/// Counts children of `node` on the `field` edge.
fn field_count(tree: &ParsedTree, node: u32, field: &str) -> usize {
    tree.children(node)
        .into_iter()
        .filter(|child| tree.field_of(*child) == Some(field))
        .count()
}

/// Declared name for C/C++ declarator shapes: unwraps
/// `function`/`array`/`pointer` declarators to the inner identifier.
fn c_declarator_name(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
    let Some(mut cursor) = tree.child_with_field(node, "declarator") else {
        return Vec::new();
    };
    // Single-declarator shapes only; lists stay gaps (checked by caller).
    for _ in 0..16 {
        let kind = tree.kind_of(cursor);
        if kind == "identifier" || kind == "type_identifier" {
            return tree.text_of(cursor, source).to_vec();
        }
        if kind == "parenthesized_declarator" {
            cursor = tree.named_children(cursor).first().copied().unwrap_or(NODE_NONE);
            if cursor == NODE_NONE {
                return Vec::new();
            }
        } else if let Some(inner) = tree.child_with_field(cursor, "declarator") {
            cursor = inner;
        } else {
            return Vec::new();
        }
    }
    Vec::new()
}

/// Discriminator bytes for one unit: the optional field edge (receivers)
/// followed by the kind-based signature children (first match, or every
/// match in order when `disc_all`).
fn unit_discriminator(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    rules: &CodeRules,
) -> Vec<u8> {
    let mut discriminator = Vec::new();
    if let Some(field) = rules.disc_field {
        if let Some(edge) = tree.child_with_field(node, field) {
            discriminator.extend_from_slice(tree.text_of(edge, source));
            discriminator.push(0);
        }
    }
    if rules.disc_all {
        for child in tree.named_children(node) {
            if rules.disc_kinds.contains(&tree.kind_of(child)) {
                discriminator.extend_from_slice(tree.text_of(child, source));
                discriminator.push(0);
            }
        }
    } else {
        discriminator.extend_from_slice(&discriminator_by_kind(
            tree,
            source,
            node,
            rules.disc_kinds,
        ));
    }
    discriminator
}

/// Parameter-list text from inside a C/C++ declarator: kind-based lookup
/// cannot see it because the list nests under `function_declarator`.
fn c_signature(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
    let mut cursor = tree.child_with_field(node, "declarator");
    for _ in 0..16 {
        let Some(current) = cursor else {
            return Vec::new();
        };
        if tree.kind_of(current) == "function_declarator" {
            return tree
                .named_children(current)
                .into_iter()
                .filter(|child| {
                    ["parameter_list", "parameters"].contains(&tree.kind_of(*child))
                })
                .map(|child| tree.text_of(child, source).to_vec())
                .collect::<Vec<_>>()
                .concat();
        }
        cursor = tree.child_with_field(current, "declarator");
    }
    Vec::new()
}

/// Extracts units under `node`, threading lexical-parent names. Descent
/// stops at [`MAX_WALK_DEPTH`](super::MAX_WALK_DEPTH); deeper subtrees stay
/// gaps. Members are reached through containers and their transparent body
/// wrappers only; any other unknown node stops the walk, so function bodies
/// (units return before descent, and their body kinds are never listed as
/// wrappers) never leak nested declarations as member units.
fn collect(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    rules: &CodeRules,
    language: Language,
    parents: &mut Vec<Vec<u8>>,
    out: &mut Vec<SourceUnit>,
    depth: usize,
) {
    if depth > super::MAX_WALK_DEPTH {
        return;
    }
    let kind = tree.kind_of(node).to_owned();
    if rules.opaque_kinds.contains(&kind.as_str())
        || (language == Language::CSharp && kind.ends_with("directive"))
    {
        return;
    }
    if rules.unit_kinds.contains(&kind.as_str()) {
        if rules.single_declarator && field_count(tree, node, "declarator") != 1 {
            return;
        }
        let name = if matches!(language, Language::C | Language::Cpp)
            && (kind.as_str() == "function_definition" || kind.as_str() == "declaration")
        {
            c_declarator_name(tree, source, node)
        } else {
            declared_name(tree, source, node, rules.name_alts)
        };
        let mut discriminator = unit_discriminator(tree, source, node, rules);
        if matches!(language, Language::C | Language::Cpp)
            && (kind.as_str() == "function_definition" || kind.as_str() == "declaration")
        {
            discriminator.extend_from_slice(&c_signature(tree, source, node));
        }
        let parent = parents.concat();
        let Some(record) = tree.get(node) else {
            return;
        };
        let start = attach_leading_trivia(tree, source, node, rules.comment_kinds, rules.attr_kinds);
        let (Some(_s), Some(_e)) = (offset(start), offset(record.end)) else {
            return;
        };
        out.push(SourceUnit {
            key: UnitKey::new(kind, name, discriminator, parent),
            start,
            end: record.end,
            node,
        });
        return;
    }
    // Containers contribute parent context; the root contributes none.
    // Body wrappers are transparent at any depth so nested containers keep
    // resolving their members.
    let is_root = tree.get(node).is_some_and(|n| n.parent == NODE_NONE);
    let mut pushed = false;
    if rules.container_kinds.contains(&kind.as_str()) {
        let name = declared_name(tree, source, node, rules.name_alts);
        if !name.is_empty() {
            let mut qualified = name;
            qualified.push(0);
            parents.push(qualified);
            pushed = true;
        }
    } else if !is_root && !rules.body_kinds.contains(&kind.as_str()) {
        return;
    }
    for child in tree.named_children(node) {
        collect(tree, source, child, rules, language, parents, out, depth + 1);
    }
    if pushed {
        parents.pop();
    }
}

/// Runs `rules` from the root of `tree`.
fn extract(
    tree: &ParsedTree,
    source: &[u8],
    rules: &CodeRules,
    language: Language,
) -> Vec<SourceUnit> {
    let mut out = Vec::new();
    if tree.is_empty() {
        return out;
    }
    let mut parents = Vec::new();
    collect(tree, source, 0, rules, language, &mut parents, &mut out, 0);
    out.sort_by_key(|unit| (unit.start, unit.end));
    out
}

const RUST_COMMENTS: &[&str] = &["line_comment", "block_comment"];
const C_COMMENTS: &[&str] = &["comment"];
const CPP_ATTRS: &[&str] = &["attribute_declaration"];
const JAVA_ATTRS: &[&str] = &["modifiers"];
const CS_ATTRS: &[&str] = &["attribute_list"];

macro_rules! plain_adapter {
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

const RUST_RULES: CodeRules = CodeRules {
    // Macro invocations and definitions are opaque gaps, never units.
    unit_kinds: &[
        "function_item",
        "struct_item",
        "enum_item",
        "union_item",
        "trait_item",
        "type_item",
        "const_item",
        "static_item",
    ],
    container_kinds: &["mod_item", "impl_item"],
    // Module and impl members wrap in `declaration_list`; function bodies
    // use `block`, which stays opaque.
    body_kinds: &["declaration_list"],
    opaque_kinds: &["macro_invocation", "macro_definition", "macro_rule", "use_declaration"],
    name_alts: &["type", "trait"],
    // Parameters (and return types they textually contain) separate overloads;
    // impl headers separate same-name methods across impl blocks.
    disc_kinds: &["parameters", "return_type", "type_parameters"],
    disc_field: None,
    disc_all: false,
    comment_kinds: RUST_COMMENTS,
    attr_kinds: &["attribute_item", "inner_attribute_item"],
    single_declarator: false,
};

const GO_RULES: CodeRules = CodeRules {
    unit_kinds: &[
        "function_declaration",
        "method_declaration",
        "type_spec",
        "const_spec",
        "var_spec",
    ],
    // Grouped declarations wrap each spec; the wrappers are unnamed, so
    // they traverse purely without contributing parent context.
    container_kinds: &["type_declaration", "const_declaration", "var_declaration"],
    body_kinds: &[],
    // Import groups and grouped parens stay ordered gaps.
    opaque_kinds: &["import_declaration", "import_spec_list"],
    name_alts: &[],
    // The receiver is a field edge, not a child kind: methods on different
    // receivers are distinct units. Signatures pin the declared form.
    disc_kinds: &["parameters", "result"],
    disc_field: Some("receiver"),
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: &[],
    single_declarator: false,
};

const C_RULES: CodeRules = CodeRules {
    unit_kinds: &["function_definition", "declaration", "type_definition"],
    container_kinds: &[],
    body_kinds: &[],
    // Every preprocessor branch is opaque: units inside conditional
    // compilation have ambiguous context.
    opaque_kinds: &[
        "preproc_include",
        "preproc_def",
        "preproc_function_def",
        "preproc_call",
        "preproc_if",
        "preproc_ifdef",
        "preproc_ifdef_plus",
        "preproc_elif",
        "preproc_else",
        "preproc_directive",
    ],
    name_alts: &[],
    // Parameter lists nest inside declarators; `c_signature` reads them.
    // The kind list stays for declarator-level fallbacks.
    disc_kinds: &["parameter_list", "parameters"],
    disc_field: None,
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: &["attribute_specifier"],
    single_declarator: true,
};

const CPP_RULES: CodeRules = CodeRules {
    // Class and struct specifiers are containers only: listing them as
    // units would turn whole bodies atomic and hide their members.
    unit_kinds: &[
        "function_definition",
        "declaration",
        "type_definition",
        "enum_specifier",
        "field_declaration",
    ],
    container_kinds: &["namespace_definition", "class_specifier", "struct_specifier"],
    // Class bodies wrap in `field_declaration_list`; namespaces in
    // `declaration_list`.
    body_kinds: &["field_declaration_list", "declaration_list"],
    // Templates and specializations have ambiguous identity; preprocessor
    // branches are opaque for the same reason as in C.
    opaque_kinds: &[
        "template_declaration",
        "template_instantiation",
        "preproc_include",
        "preproc_def",
        "preproc_function_def",
        "preproc_call",
        "preproc_if",
        "preproc_ifdef",
        "preproc_ifdef_plus",
        "preproc_elif",
        "preproc_else",
        "preproc_directive",
        "access_specifier",
    ],
    name_alts: &["name", "type_name"],
    // Full parameter spellings separate overloads; destructors carry `~`.
    // Lists nest inside declarators; `c_signature` reads them.
    disc_kinds: &["parameter_list", "parameters", "type_parameter_list"],
    disc_field: None,
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: CPP_ATTRS,
    single_declarator: true,
};

const JAVA_RULES: CodeRules = CodeRules {
    // Type declarations are containers only; their members extract with
    // the enclosing type as parent context.
    unit_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "field_declaration",
        "compact_constructor_declaration",
    ],
    container_kinds: &[
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
    ],
    // Member bodies wrap per enclosing kind; method bodies use `block`.
    body_kinds: &["class_body", "interface_body", "enum_body"],
    opaque_kinds: &["import_declaration", "package_declaration", "module_declaration"],
    name_alts: &[],
    // Full syntactic signatures: parameters, type parameters, return type,
    // and throws clause text. Never method name alone.
    disc_kinds: &[
        "formal_parameters",
        "type_parameters",
        "throws",
        "type",
        "return_type",
    ],
    disc_field: None,
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: JAVA_ATTRS,
    single_declarator: false,
};

const CSHARP_RULES: CodeRules = CodeRules {
    // Type declarations are containers only; members extract with the
    // enclosing type as parent context.
    unit_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "field_declaration",
        "property_declaration",
        "event_declaration",
        "operator_declaration",
        "conversion_operator_declaration",
    ],
    container_kinds: &[
        "namespace_declaration",
        "class_declaration",
        "interface_declaration",
        "struct_declaration",
        "record_declaration",
    ],
    // Member bodies wrap in `declaration_list`; there is no `class_body`
    // in this grammar. Method bodies use `block`.
    body_kinds: &["declaration_list"],
    opaque_kinds: &["using_directive"],
    name_alts: &[],
    disc_kinds: &["parameter_list", "type_parameter_list", "return_type"],
    disc_field: None,
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: CS_ATTRS,
    single_declarator: false,
};

const KOTLIN_RULES: CodeRules = CodeRules {
    // Type declarations are containers only; members extract with the
    // enclosing type as parent context.
    unit_kinds: &[
        "function_declaration",
        "property_declaration",
        "type_alias",
        "secondary_constructor",
        "primary_constructor",
    ],
    container_kinds: &["class_declaration", "object_declaration", "companion_object"],
    // Member bodies wrap in `class_body`; function bodies use `block`.
    body_kinds: &["class_body"],
    // Imports use the `import` node (there is no `import_header`).
    opaque_kinds: &["import", "package_header"],
    name_alts: &[],
    // Receivers are a field edge; value parameters wrap in
    // `function_value_parameters` (there is no `value_parameters` node).
    disc_kinds: &[
        "function_value_parameters",
        "type_parameters",
        "return_type",
    ],
    disc_field: Some("receiver"),
    disc_all: false,
    comment_kinds: C_COMMENTS,
    attr_kinds: &["annotations", "annotation"],
    single_declarator: false,
};

const SWIFT_RULES: CodeRules = CodeRules {
    // This grammar (0.7.4) has no struct, enum, or extension declarations:
    // only classes, protocols, and members below. Type declarations are
    // containers only; members extract with parent context.
    unit_kinds: &[
        "function_declaration",
        "init_declaration",
        "deinit_declaration",
        "property_declaration",
        "typealias_declaration",
        "subscript_declaration",
        "protocol_function_declaration",
        "protocol_property_declaration",
    ],
    container_kinds: &["class_declaration", "protocol_declaration"],
    // Member bodies wrap in `class_body` / `protocol_body`; function
    // bodies use `function_body`.
    body_kinds: &["class_body", "protocol_body"],
    opaque_kinds: &["import_declaration"],
    name_alts: &[],
    // Parameters are direct `parameter` children with no list wrapper, so
    // every matching child concatenates in order; return and type
    // parameters join them. (There is no `parameter_clause` node.)
    disc_kinds: &["parameter", "return_type", "type_parameters"],
    disc_field: None,
    disc_all: true,
    comment_kinds: C_COMMENTS,
    attr_kinds: &["attributes", "attribute"],
    single_declarator: false,
};

plain_adapter!(RustAdapter, Language::Rust, RUST_RULES);
plain_adapter!(GoAdapter, Language::Go, GO_RULES);
plain_adapter!(CAdapter, Language::C, C_RULES);
plain_adapter!(CppAdapter, Language::Cpp, CPP_RULES);
plain_adapter!(JavaAdapter, Language::Java, JAVA_RULES);
plain_adapter!(CSharpAdapter, Language::CSharp, CSHARP_RULES);
plain_adapter!(KotlinAdapter, Language::Kotlin, KOTLIN_RULES);
plain_adapter!(SwiftAdapter, Language::Swift, SWIFT_RULES);

/// Byte spans of units that changed on exactly one side, for tests and
/// diagnostics. Returns `None` when a span is out of range.
#[must_use]
pub fn changed_span<'a>(source: &'a [u8], unit: &SourceUnit) -> Option<&'a [u8]> {
    slice_range(source, unit.start, unit.end)
}
