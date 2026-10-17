//! Data and document adapters: JSON, TOML, YAML, CSS, HTML.
//!
//! Object members, table entries, mapping pairs, declarations, and elements
//! are units keyed by literal key, selector, or tag with full lexical
//! context. Arrays and sequences are positional and atomic: one-sided whole
//! value carries, double changes decline. Duplicate keys, anchors, merge
//! keys, tags, and block scalars veto the whole file to text fallback.
//! HTML script/style interiors are opaque host units; the plain engine never
//! delegates them to another language.
//!
//! Grammar node-kind tables are best-effort from the pinned versions and
//! verified by the readiness gate plus fixtures; unknown shapes shrink to
//! conservative gaps. Tree walks are iterative except for shallow
//! container descent, which carries an explicit depth cap.

use std::collections::HashSet;

use super::{
    Adapter, Decline, DeclineReason, SourceUnit, UnitKey, attach_leading_trivia, offset,
};
use crate::merge::syntax::grammar::{Language, NODE_NONE, ParsedTree};

use super::MAX_WALK_DEPTH;

/// Next sibling of `node`, or [`NODE_NONE`].
fn next_sibling(tree: &ParsedTree, node: u32) -> u32 {
    let parent = tree.get(node).map_or(NODE_NONE, |n| n.parent);
    if parent == NODE_NONE {
        return NODE_NONE;
    }
    let children = tree.children(parent);
    let mut take_next = false;
    for child in children {
        if take_next {
            return child;
        }
        if child == node {
            take_next = true;
        }
    }
    NODE_NONE
}

/// End of `node` extended over an immediately following anonymous sibling
/// with exact text `punct` (`,` or `;`), so trailing separators travel with
/// their declaration instead of stranding in gaps.
fn extend_over(tree: &ParsedTree, node: u32, punct: &str) -> u32 {
    let end = tree.get(node).map_or(0, |n| n.end);
    let sibling = next_sibling(tree, node);
    if sibling == NODE_NONE {
        return end;
    }
    let anonymous = tree.get(sibling).is_some_and(|n| !n.is_named);
    if anonymous && tree.kind_of(sibling) == punct {
        return tree.get(sibling).map_or(end, |n| n.end);
    }
    end
}

/// Iterative descendant collection by kind (explicit stack, no recursion).
fn descendants_by_kind(tree: &ParsedTree, root: u32, kinds: &[&str]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if kinds.contains(&tree.kind_of(node)) {
            out.push(node);
        }
        stack.extend(tree.children(node));
    }
    out
}

/// Raw text of the `key`-edge child, or empty when absent.
fn key_text(tree: &ParsedTree, source: &[u8], pair: u32) -> Vec<u8> {
    tree.child_with_field(pair, "key")
        .map_or_else(Vec::new, |key| tree.text_of(key, source).to_vec())
}

/// The `value`-edge child of a pair, if any.
fn value_child(tree: &ParsedTree, pair: u32) -> Option<u32> {
    tree.child_with_field(pair, "value")
}

/// Whether `node` is a TOML key node (`bare_key`, `dotted_key`,
/// `quoted_key`): the toml-ng grammar puts no field edges on pairs.
fn is_toml_key(tree: &ParsedTree, node: u32) -> bool {
    ["dotted_key", "bare_key", "quoted_key"].contains(&tree.kind_of(node))
}

/// Raw text of a TOML pair's key: its first key-kind named child.
fn toml_key_text(tree: &ParsedTree, source: &[u8], pair: u32) -> Vec<u8> {
    tree.named_children(pair)
        .into_iter()
        .find(|child| is_toml_key(tree, *child))
        .map_or_else(Vec::new, |key| tree.text_of(key, source).to_vec())
}

/// A TOML pair's value: its last named child that is not the key.
fn toml_value_child(tree: &ParsedTree, pair: u32) -> Option<u32> {
    tree.named_children(pair).into_iter().rev().find(|child| {
        !is_toml_key(tree, *child) && tree.kind_of(*child) != "comment"
    })
}

fn push(
    tree: &ParsedTree,
    source: &[u8],
    node: u32,
    end: u32,
    key: UnitKey,
    out: &mut Vec<SourceUnit>,
) {
    if tree.get(node).is_none() {
        return;
    }
    let start = attach_leading_trivia(tree, source, node, &["comment", "block_comment"], &[]);
    if offset(start).is_none() || offset(end).is_none() || start > end {
        return;
    }
    out.push(SourceUnit {
        key,
        start,
        end,
        node,
    });
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// JSON object member units with comma-extended ranges and object descent.
#[derive(Debug)]
pub struct JsonAdapter;

impl JsonAdapter {
    fn walk(
        tree: &ParsedTree,
        source: &[u8],
        value: u32,
        parent: &mut Vec<Vec<u8>>,
        out: &mut Vec<SourceUnit>,
        depth: usize,
    ) {
        if depth > MAX_WALK_DEPTH {
            return;
        }
        if tree.kind_of(value) != "object" {
            return;
        }
        for pair in tree
            .named_children(value)
            .into_iter()
            .filter(|child| tree.kind_of(*child) == "pair")
        {
            let key = key_text(tree, source, pair);
            if key.is_empty() {
                continue;
            }
            match value_child(tree, pair) {
                Some(nested) if tree.kind_of(nested) == "object" => {
                    let mut qualified = key;
                    qualified.push(0);
                    parents_push(parent, qualified, |parent| {
                        Self::walk(tree, source, nested, parent, out, depth + 1);
                    });
                }
                _ => {
                    let end = extend_over(tree, pair, ",");
                    push(
                        tree,
                        source,
                        pair,
                        end,
                        UnitKey::new("pair", key, Vec::new(), parent.concat()),
                        out,
                    );
                }
            }
        }
    }

    /// Parent key path of `pair` by walking up through enclosing pairs.
    fn parent_path(tree: &ParsedTree, source: &[u8], pair: u32) -> Vec<u8> {
        let mut segments = Vec::new();
        let mut cursor = tree.get(pair).map_or(NODE_NONE, |n| n.parent);
        while cursor != NODE_NONE {
            let parent = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
            if tree.kind_of(cursor) == "pair" {
                let key = key_text(tree, source, cursor);
                if !key.is_empty() {
                    segments.push(key);
                }
            }
            cursor = parent;
        }
        segments.reverse();
        segments.join(&0)
    }

    /// Duplicate literal keys inside one object, if any.
    fn duplicate_key(tree: &ParsedTree, source: &[u8]) -> Option<Vec<u8>> {
        for object in descendants_by_kind(tree, 0, &["object"]) {
            let mut seen = HashSet::new();
            for pair in tree
                .named_children(object)
                .into_iter()
                .filter(|child| tree.kind_of(*child) == "pair")
            {
                let key = key_text(tree, source, pair);
                if key.is_empty() {
                    continue;
                }
                if seen.contains(&key) {
                    return Some(key);
                }
                seen.insert(key);
            }
        }
        None
    }
}

/// Pushes `qualified` as parent context for `body`, then pops it.
fn parents_push(parent: &mut Vec<Vec<u8>>, qualified: Vec<u8>, body: impl FnOnce(&mut Vec<Vec<u8>>)) {
    parent.push(qualified);
    body(parent);
    parent.pop();
}

impl Adapter for JsonAdapter {
    fn language(&self) -> Language {
        Language::Json
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        let mut out = Vec::new();
        if tree.is_empty() {
            return out;
        }
        let root_value = tree.named_children(0).into_iter().next();
        match root_value {
            Some(value) if tree.kind_of(value) == "object" => {
                let mut parent = Vec::new();
                Self::walk(tree, source, value, &mut parent, &mut out, 0);
            }
            Some(value) => {
                // Top-level arrays and scalars are one atomic unit:
                // one-sided whole-value carries, double changes decline.
                let end = tree.get(value).map_or(0, |n| n.end);
                push(
                    tree,
                    source,
                    value,
                    end,
                    UnitKey::new(tree.kind_of(value), Vec::new(), Vec::new(), Vec::new()),
                    &mut out,
                );
            }
            None => {}
        }
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn veto(
        &self,
        base: &ParsedTree,
        base_src: &[u8],
        ours: &ParsedTree,
        ours_src: &[u8],
        theirs: &ParsedTree,
        theirs_src: &[u8],
    ) -> Option<Decline> {
        for (tree, source) in [(base, base_src), (ours, ours_src), (theirs, theirs_src)] {
            if tree.is_empty() {
                continue;
            }
            if let Some(key) = Self::duplicate_key(tree, source) {
                return Some(Decline::new(
                    DeclineReason::DuplicateKey,
                    format!(
                        "duplicate JSON key `{}`; declining",
                        String::from_utf8_lossy(&key)
                    ),
                ));
            }
        }
        None
    }

    fn children(&self, tree: &ParsedTree, source: &[u8], node: u32) -> Vec<SourceUnit> {
        if tree.kind_of(node) != "pair" {
            return Vec::new();
        }
        let nested = value_child(tree, node).filter(|value| tree.kind_of(*value) == "object");
        let Some(nested) = nested else {
            return Vec::new();
        };
        let mut parent: Vec<Vec<u8>> = Vec::new();
        let path = Self::parent_path(tree, source, node);
        if !path.is_empty() {
            parent.push(path);
        }
        let key = key_text(tree, source, node);
        if !key.is_empty() {
            let mut qualified = key;
            qualified.push(0);
            parent.push(qualified);
        }
        let mut out = Vec::new();
        Self::walk(tree, source, nested, &mut parent, &mut out, 0);
        out
    }

    fn separators(&self) -> &[u8] {
        &[b',']
    }
}

// ---------------------------------------------------------------------------
// TOML
// ---------------------------------------------------------------------------

/// TOML table entries with dotted-key flattening and inline-table descent.
#[derive(Debug)]
pub struct TomlAdapter;

impl TomlAdapter {
    /// Header path text of a `table` node: its first non-pair named child.
    fn table_path(tree: &ParsedTree, source: &[u8], table: u32) -> Vec<u8> {
        tree.named_children(table)
            .into_iter()
            .find(|child| tree.kind_of(*child) != "pair")
            .map_or_else(Vec::new, |header| tree.text_of(header, source).to_vec())
    }

    /// Whether `node` sits inside an array-of-table section: such subtrees
    /// are opaque gaps in both sweeps, so repeated `[[x]]` sections and
    /// same-named keys across sections never veto each other. The toml-ng
    /// grammar names the section node `table_array_element`.
    fn inside_table_array(tree: &ParsedTree, node: u32) -> bool {
        let mut cursor = tree.get(node).map_or(NODE_NONE, |n| n.parent);
        while cursor != NODE_NONE {
            if tree.kind_of(cursor) == "table_array_element" {
                return true;
            }
            cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
        }
        false
    }

    /// Collects `(table_path, pair_key)` entries and table paths, skipping
    /// array-of-table subtrees entirely.
    fn entries(
        tree: &ParsedTree,
        source: &[u8],
    ) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut pairs = Vec::new();
        let mut tables = Vec::new();
        let mut multiline = Vec::new();
        for node in descendants_by_kind(tree, 0, &["table", "table_array_element", "pair"]) {
            if tree.kind_of(node) == "table_array_element"
                || Self::inside_table_array(tree, node)
            {
                continue;
            }
            match tree.kind_of(node) {
                "table" => tables.push(Self::table_path(tree, source, node)),
                _ => {
                    let key = toml_key_text(tree, source, node);
                    // Enclosing table path by walking up.
                    let mut cursor = tree.get(node).map_or(NODE_NONE, |n| n.parent);
                    let mut path = Vec::new();
                    while cursor != NODE_NONE {
                        if tree.kind_of(cursor) == "table" {
                            path = Self::table_path(tree, source, cursor);
                            break;
                        }
                        cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
                    }
                    pairs.push((path, key));
                }
            }
        }
        for node in descendants_by_kind(tree, 0, &["string"]) {
            let text = tree.text_of(node, source);
            if text.contains(&b'\n') {
                multiline.push(text.to_vec());
            }
        }
        // Broader string-kind sweep for grammars with split string nodes.
        for kind in [
            "basic_string",
            "literal_string",
            "multiline_basic_string",
            "multiline_literal_string",
        ] {
            for node in descendants_by_kind(tree, 0, &[kind]) {
                let text = tree.text_of(node, source);
                if text.contains(&b'\n') {
                    multiline.push(text.to_vec());
                }
            }
        }
        (pairs, tables, multiline)
    }
}

impl Adapter for TomlAdapter {
    fn language(&self) -> Language {
        Language::Toml
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        let mut out = Vec::new();
        if tree.is_empty() {
            return out;
        }
        Self::tables_into(tree, source, 0, &mut Vec::new(), &mut out, 0);
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn veto(
        &self,
        base: &ParsedTree,
        base_src: &[u8],
        ours: &ParsedTree,
        ours_src: &[u8],
        theirs: &ParsedTree,
        theirs_src: &[u8],
    ) -> Option<Decline> {
        let inputs = [(base, base_src), (ours, ours_src), (theirs, theirs_src)];
        let mut multiline_sets = Vec::new();
        for (tree, source) in inputs {
            if tree.is_empty() {
                continue;
            }
            let (pairs, tables, multiline) = Self::entries(tree, source);
            let mut seen_pairs = HashSet::new();
            for (path, key) in &pairs {
                // Dotted full path for collision checks: `[a]` plus `b.c`
                // under it claims `a.b.c`, exactly like a `[a.b.c]` table.
                // A table path that merely prefixes a dotted key is normal
                // nesting, not a collision.
                let mut full = Vec::with_capacity(path.len() + key.len() + 1);
                full.extend_from_slice(path);
                if !full.is_empty() {
                    full.push(b'.');
                }
                full.extend_from_slice(key);
                if seen_pairs.contains(&full) {
                    return Some(Decline::new(
                        DeclineReason::DuplicateKey,
                        format!(
                            "duplicate TOML key `{}`; declining",
                            String::from_utf8_lossy(&full)
                        ),
                    ));
                }
                for table in &tables {
                    if *table == full {
                        return Some(Decline::new(
                            DeclineReason::UnsupportedConstruct,
                            "TOML dotted-key/table collision; declining".to_owned(),
                        ));
                    }
                    if table.len() > full.len()
                        && table.starts_with(&full)
                        && table[full.len()..].starts_with(b".")
                    {
                        return Some(Decline::new(
                            DeclineReason::UnsupportedConstruct,
                            "TOML scalar where a table is expected; declining".to_owned(),
                        ));
                    }
                }
                seen_pairs.insert(full);
            }
            let mut seen_tables = HashSet::new();
            for table in &tables {
                if !seen_tables.insert(table.as_slice()) {
                    return Some(Decline::new(
                        DeclineReason::DuplicateKey,
                        format!(
                            "duplicate TOML table `{}`; declining",
                            String::from_utf8_lossy(table)
                        ),
                    ));
                }
            }
            multiline_sets.push(multiline);
        }
        // Multiline string contents decline when edited.
        if multiline_sets.len() == 3
            && (multiline_sets[1] != multiline_sets[0]
                || multiline_sets[2] != multiline_sets[0])
        {
            return Some(Decline::new(
                DeclineReason::UnsupportedConstruct,
                "TOML multiline string contents changed; declining".to_owned(),
            ));
        }
        None
    }

    fn children(&self, tree: &ParsedTree, source: &[u8], node: u32) -> Vec<SourceUnit> {
        if tree.kind_of(node) != "pair" {
            return Vec::new();
        }
        let inline = toml_value_child(tree, node)
            .filter(|value| tree.kind_of(*value) == "inline_table");
        let Some(inline) = inline else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for pair in tree
            .named_children(inline)
            .into_iter()
            .filter(|child| tree.kind_of(*child) == "pair")
        {
            let key = toml_key_text(tree, source, pair);
            if key.is_empty() {
                continue;
            }
            let end = extend_over(tree, pair, ",");
            push(
                tree,
                source,
                pair,
                end,
                UnitKey::new("pair", key, Vec::new(), Vec::new()),
                &mut out,
            );
        }
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn separators(&self) -> &[u8] {
        &[b',']
    }
}

impl TomlAdapter {
    fn tables_into(
        tree: &ParsedTree,
        source: &[u8],
        node: u32,
        tables: &mut Vec<Vec<u8>>,
        out: &mut Vec<SourceUnit>,
        depth: usize,
    ) {
        if depth > MAX_WALK_DEPTH {
            return;
        }
        let kind = tree.kind_of(node);
        // Array-of-table elements have no stable identity: opaque gaps.
        if kind == "table_array_element" {
            return;
        }
        if kind == "table" {
            tables.push(Self::table_path(tree, source, node));
        }
        for child in tree.named_children(node) {
            let child_kind = tree.kind_of(child);
            if child_kind == "table" || child_kind == "document" {
                Self::tables_into(tree, source, child, tables, out, depth + 1);
            } else if child_kind == "pair" {
                let key = toml_key_text(tree, source, child);
                if key.is_empty() {
                    continue;
                }
                let parent = tables.last().cloned().unwrap_or_default();
                let end = tree.get(child).map_or(0, |n| n.end);
                push(
                    tree,
                    source,
                    child,
                    end,
                    UnitKey::new("pair", key, Vec::new(), parent),
                    out,
                );
            }
        }
        if kind == "table" {
            tables.pop();
        }
    }
}

// ---------------------------------------------------------------------------
// YAML
// ---------------------------------------------------------------------------

/// YAML mapping pairs with nested-mapping descent and atomic sequences.
#[derive(Debug)]
pub struct YamlAdapter;

impl YamlAdapter {
    fn walk(
        tree: &ParsedTree,
        source: &[u8],
        mapping: u32,
        parent: &mut Vec<Vec<u8>>,
        out: &mut Vec<SourceUnit>,
        depth: usize,
    ) {
        if depth > MAX_WALK_DEPTH {
            return;
        }
        for pair in tree
            .named_children(mapping)
            .into_iter()
            .filter(|child| tree.kind_of(*child) == "block_mapping_pair")
        {
            let key = key_text(tree, source, pair);
            if key.is_empty() {
                continue;
            }
            match value_child(tree, pair) {
                Some(nested)
                    if ["block_mapping", "block_node", "mapping"].contains(&tree.kind_of(nested)) =>
                {
                    let mut qualified = key;
                    qualified.push(0);
                    parents_push(parent, qualified, |parent| {
                        Self::walk(tree, source, nested, parent, out, depth + 1);
                    });
                }
                _ => {
                    let end = tree.get(pair).map_or(0, |n| n.end);
                    push(
                        tree,
                        source,
                        pair,
                        end,
                        UnitKey::new("block_mapping_pair", key, Vec::new(), parent.concat()),
                        out,
                    );
                }
            }
        }
    }

    /// Feature veto: anchors, aliases, tags, block scalars, merge keys, and
    /// duplicate sibling keys decline the whole file. Anchor/alias kinds
    /// also match by substring so a renamed grammar node cannot slip an
    /// alias past the veto; block merge keys additionally match line text
    /// so a grammar that folds them into plain scalars still declines.
    fn veto_tree(tree: &ParsedTree, source: &[u8]) -> Option<Decline> {
        if !descendants_by_kind(tree, 0, &["anchor", "alias", "tag", "block_scalar"]).is_empty()
            || Self::has_anchor_alias_kind(tree)
        {
            return Some(Decline::new(
                DeclineReason::UnsupportedConstruct,
                "YAML anchors, aliases, tags, or block scalars; declining".to_owned(),
            ));
        }
        if Self::has_block_merge_key(source) {
            return Some(Decline::new(
                DeclineReason::UnsupportedConstruct,
                "YAML merge key; declining".to_owned(),
            ));
        }
        for mapping in descendants_by_kind(tree, 0, &["block_mapping", "flow_mapping"]) {
            let mut seen = HashSet::new();
            for pair in tree.named_children(mapping).into_iter().filter(|child| {
                ["block_mapping_pair", "flow_pair"].contains(&tree.kind_of(*child))
            }) {
                let key = key_text(tree, source, pair);
                if key == b"<<" {
                    return Some(Decline::new(
                        DeclineReason::UnsupportedConstruct,
                        "YAML merge key; declining".to_owned(),
                    ));
                }
                if key.is_empty() {
                    continue;
                }
                if seen.contains(&key) {
                    return Some(Decline::new(
                        DeclineReason::DuplicateKey,
                        format!(
                            "duplicate YAML key `{}`; declining",
                            String::from_utf8_lossy(&key)
                        ),
                    ));
                }
                seen.insert(key);
            }
        }
        None
    }

    /// Whether any node kind mentions anchors or aliases.
    fn has_anchor_alias_kind(tree: &ParsedTree) -> bool {
        let mut stack = vec![0_u32];
        while let Some(node) = stack.pop() {
            let kind = tree.kind_of(node);
            if kind.contains("anchor") || kind.contains("alias") {
                return true;
            }
            stack.extend(tree.children(node));
        }
        false
    }

    /// Whether any line opens a block merge key (`<<:`). Comment lines and
    /// quoted scalars never match: the former start with `#`, the latter
    /// with a quote.
    fn has_block_merge_key(source: &[u8]) -> bool {
        source.split(|b| *b == b'\n').any(|line| {
            let stripped = line
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .map_or(&line[..0], |start| &line[start..]);
            stripped.starts_with(b"<<:")
                || stripped.starts_with(b"<< ")
                || stripped == b"<<"
        })
    }
}

impl Adapter for YamlAdapter {
    fn language(&self) -> Language {
        Language::Yaml
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        let mut out = Vec::new();
        if tree.is_empty() {
            return out;
        }
        for mapping in descendants_by_kind(tree, 0, &["block_mapping"]) {
            // Only top-level mappings seed the walk; nested ones are
            // reached through their pairs.
            let mut cursor = tree.get(mapping).map_or(NODE_NONE, |n| n.parent);
            let mut nested = false;
            while cursor != NODE_NONE {
                if ["block_mapping_pair", "flow_pair"].contains(&tree.kind_of(cursor)) {
                    nested = true;
                    break;
                }
                cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
            }
            if nested {
                continue;
            }
            Self::walk(tree, source, mapping, &mut Vec::new(), &mut out, 0);
        }
        // Flow mappings at top level without a block mapping.
        if out.is_empty() {
            for mapping in descendants_by_kind(tree, 0, &["flow_mapping"]) {
                Self::walk_flow(tree, source, mapping, &mut Vec::new(), &mut out, 0);
            }
        }
        // A document without mappings is one atomic unit.
        if out.is_empty() {
            let value = tree.named_children(0).into_iter().next();
            if let Some(value) = value {
                let end = tree.get(value).map_or(0, |n| n.end);
                push(
                    tree,
                    source,
                    value,
                    end,
                    UnitKey::new(tree.kind_of(value), Vec::new(), Vec::new(), Vec::new()),
                    &mut out,
                );
            }
        }
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn veto(
        &self,
        base: &ParsedTree,
        base_src: &[u8],
        ours: &ParsedTree,
        ours_src: &[u8],
        theirs: &ParsedTree,
        theirs_src: &[u8],
    ) -> Option<Decline> {
        for (tree, source) in [(base, base_src), (ours, ours_src), (theirs, theirs_src)] {
            if tree.is_empty() {
                continue;
            }
            if let Some(decline) = Self::veto_tree(tree, source) {
                return Some(decline);
            }
        }
        None
    }

    fn children(&self, tree: &ParsedTree, source: &[u8], node: u32) -> Vec<SourceUnit> {
        if tree.kind_of(node) != "block_mapping_pair" {
            return Vec::new();
        }
        let nested = value_child(tree, node)
            .filter(|value| ["block_mapping", "block_node", "mapping"].contains(&tree.kind_of(*value)));
        let Some(nested) = nested else {
            return Vec::new();
        };
        let mut parent = Vec::new();
        let key = key_text(tree, source, node);
        if !key.is_empty() {
            let mut qualified = key;
            qualified.push(0);
            parent.push(qualified);
        }
        let mut out = Vec::new();
        Self::walk(tree, source, nested, &mut parent, &mut out, 0);
        out
    }

    fn separators(&self) -> &[u8] {
        &[b',']
    }
}

impl YamlAdapter {
    fn walk_flow(
        tree: &ParsedTree,
        source: &[u8],
        mapping: u32,
        parent: &mut Vec<Vec<u8>>,
        out: &mut Vec<SourceUnit>,
        depth: usize,
    ) {
        if depth > MAX_WALK_DEPTH {
            return;
        }
        for pair in tree
            .named_children(mapping)
            .into_iter()
            .filter(|child| tree.kind_of(*child) == "flow_pair")
        {
            let key = key_text(tree, source, pair);
            if key.is_empty() {
                continue;
            }
            let end = extend_over(tree, pair, ",");
            push(
                tree,
                source,
                pair,
                end,
                UnitKey::new("flow_pair", key, Vec::new(), parent.concat()),
                out,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

/// CSS rule sets with declaration descent and at-rule context.
#[derive(Debug)]
pub struct CssAdapter;

impl CssAdapter {
    /// At-rule prelude text: keyword plus parameters, excluding the body.
    fn at_prelude(tree: &ParsedTree, source: &[u8], node: u32) -> Vec<u8> {
        tree.named_children(node)
            .into_iter()
            .filter(|child| !["block", "rule_set", "declaration"].contains(&tree.kind_of(*child)))
            .map(|child| tree.text_of(child, source).to_vec())
            .collect::<Vec<_>>()
            .join(b" ".as_slice())
    }

    /// Property name of a declaration: bytes before the first colon.
    fn property_name(tree: &ParsedTree, source: &[u8], declaration: u32) -> Vec<u8> {
        if let Some(property) = tree.child_with_field(declaration, "property") {
            return tree.text_of(property, source).to_vec();
        }
        let text = tree.text_of(declaration, source);
        text.iter()
            .position(|b| *b == b':')
            .map_or_else(Vec::new, |colon| text[..colon].to_vec())
    }

    /// Extracts one rule member (a declaration or a nested rule set) into
    /// `out`, skipping anything unattributable.
    fn member_into(tree: &ParsedTree, source: &[u8], child: u32, out: &mut Vec<SourceUnit>) {
        match tree.kind_of(child) {
            "declaration" => {
                let name = Self::property_name(tree, source, child);
                if name.is_empty() {
                    return;
                }
                let end = extend_over(tree, child, ";");
                push(
                    tree,
                    source,
                    child,
                    end,
                    UnitKey::new("declaration", name, Vec::new(), Vec::new()),
                    out,
                );
            }
            "rule_set" => {
                let selectors = tree
                    .named_children(child)
                    .into_iter()
                    .find(|grand| ["selectors", "selector"].contains(&tree.kind_of(*grand)))
                    .map_or_else(Vec::new, |grand| tree.text_of(grand, source).to_vec());
                let end = tree.get(child).map_or(0, |n| n.end);
                push(
                    tree,
                    source,
                    child,
                    end,
                    UnitKey::new("rule_set", selectors, Vec::new(), Vec::new()),
                    out,
                );
            }
            _ => {}
        }
    }

    /// Extracts the members of a rule `block` into `out`.
    fn block_into(tree: &ParsedTree, source: &[u8], block: u32, out: &mut Vec<SourceUnit>) {
        for child in tree.named_children(block) {
            Self::member_into(tree, source, child, out);
        }
    }

    fn rule_path(tree: &ParsedTree, source: &[u8], rule: u32, parent: &[Vec<u8>]) -> Vec<u8> {
        let mut path = parent.concat();
        let selectors = tree
            .named_children(rule)
            .into_iter()
            .find(|child| {
                ["selectors", "selector", "keyframe_selectors"].contains(&tree.kind_of(*child))
            })
            .map_or_else(Vec::new, |child| tree.text_of(child, source).to_vec());
        path.extend_from_slice(&selectors);
        path
    }
}

impl Adapter for CssAdapter {
    fn language(&self) -> Language {
        Language::Css
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        let mut out = Vec::new();
        if tree.is_empty() {
            return out;
        }
        Self::rules_into(tree, source, 0, &mut Vec::new(), &mut out, 0);
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn children(&self, tree: &ParsedTree, source: &[u8], node: u32) -> Vec<SourceUnit> {
        if tree.kind_of(node) != "rule_set" {
            return Vec::new();
        }
        // Declarations nest inside the rule's `block`, not beside the
        // selectors: descend one level before matching members.
        let mut out = Vec::new();
        for child in tree.named_children(node) {
            if tree.kind_of(child) == "block" {
                Self::block_into(tree, source, child, &mut out);
            } else {
                Self::member_into(tree, source, child, &mut out);
            }
        }
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn separators(&self) -> &[u8] {
        &[b';', b',']
    }
}

impl CssAdapter {
    fn rules_into(
        tree: &ParsedTree,
        source: &[u8],
        node: u32,
        parents: &mut Vec<Vec<u8>>,
        out: &mut Vec<SourceUnit>,
        depth: usize,
    ) {
        if depth > MAX_WALK_DEPTH {
            return;
        }
        let kind = tree.kind_of(node);
        if kind == "rule_set" {
            let path = Self::rule_path(tree, source, node, parents);
            let end = tree.get(node).map_or(0, |n| n.end);
            push(
                tree,
                source,
                node,
                end,
                UnitKey::new("rule_set", path, Vec::new(), Vec::new()),
                out,
            );
            return;
        }
        // Body-less at-rules (@import, @charset) are whole-text units;
        // at-rules with bodies contribute prelude context.
        if ["charset_statement", "import_statement", "namespace_statement"]
            .contains(&kind)
        {
            let text = tree.text_of(node, source).to_vec();
            let end = tree.get(node).map_or(0, |n| n.end);
            push(
                tree,
                source,
                node,
                end,
                UnitKey::new(kind, text, Vec::new(), parents.concat()),
                out,
            );
            return;
        }
        let mut pushed = false;
        if kind.ends_with("_statement") || kind == "at_rule" || kind == "media_query" {
            let mut prelude = Self::at_prelude(tree, source, node);
            if !prelude.is_empty() {
                prelude.push(0);
                parents.push(prelude);
                pushed = true;
            }
        } else if tree.get(node).is_some_and(|n| n.parent != NODE_NONE) {
            return;
        }
        for child in tree.named_children(node) {
            Self::rules_into(tree, source, child, parents, out, depth + 1);
        }
        if pushed {
            parents.pop();
        }
    }
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/// HTML elements aligned by tag, id, and ancestor chain. No descent: a
/// doubly-changed element declines, and script/style interiors are opaque
/// host units the plain engine never delegates.
#[derive(Debug)]
pub struct HtmlAdapter;

impl HtmlAdapter {
    /// Tag name of an element through its start tag.
    fn tag_name(tree: &ParsedTree, source: &[u8], element: u32) -> Vec<u8> {
        tree.named_children(element)
            .into_iter()
            .find(|child| {
                ["start_tag", "self_closing_tag"].contains(&tree.kind_of(*child))
            })
            .and_then(|tag| {
                tree.named_children(tag)
                    .into_iter()
                    .find(|grand| tree.kind_of(*grand) == "tag_name")
            })
            .map_or_else(Vec::new, |name| tree.text_of(name, source).to_vec())
    }

    /// Literal `id` attribute value of an element, or empty.
    fn id_value(tree: &ParsedTree, source: &[u8], element: u32) -> Vec<u8> {
        let start_tag = tree.named_children(element).into_iter().find(|child| {
            ["start_tag", "self_closing_tag"].contains(&tree.kind_of(*child))
        });
        let Some(start_tag) = start_tag else {
            return Vec::new();
        };
        for attribute in tree
            .named_children(start_tag)
            .into_iter()
            .filter(|child| tree.kind_of(*child) == "attribute")
        {
            let is_id = tree
                .named_children(attribute)
                .into_iter()
                .any(|part| {
                    tree.kind_of(part) == "attribute_name"
                        && tree.text_of(part, source) == b"id"
                });
            if is_id {
                return tree
                    .named_children(attribute)
                    .into_iter()
                    .filter(|part| tree.kind_of(*part) != "attribute_name")
                    .map(|part| tree.text_of(part, source).to_vec())
                    .collect::<Vec<_>>()
                    .concat();
            }
        }
        Vec::new()
    }

    /// Ancestor identity chain of `element`, outermost first: each ancestor
    /// contributes `tag` plus `#id` when it carries a literal id. Tag names
    /// alone are too weak (every `<p>` under a `<div>` would collide), while
    /// a bare global id would permit cross-tree moves; the chain keeps both
    /// local and supporting.
    fn ancestors(tree: &ParsedTree, source: &[u8], element: u32) -> Vec<u8> {
        let mut tags = Vec::new();
        let mut cursor = tree.get(element).map_or(NODE_NONE, |n| n.parent);
        while cursor != NODE_NONE {
            if ["element", "script_element", "style_element"].contains(&tree.kind_of(cursor)) {
                let tag = Self::tag_name(tree, source, cursor);
                if !tag.is_empty() {
                    let mut segment = tag;
                    let id = Self::id_value(tree, source, cursor);
                    if !id.is_empty() {
                        segment.push(b'#');
                        segment.extend_from_slice(&id);
                    }
                    tags.push(segment);
                }
            }
            cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
        }
        tags.reverse();
        tags.join(&0)
    }
}

impl Adapter for HtmlAdapter {
    fn language(&self) -> Language {
        Language::Html
    }

    fn units(&self, tree: &ParsedTree, source: &[u8]) -> Vec<SourceUnit> {
        let mut out = Vec::new();
        if tree.is_empty() {
            return out;
        }
        let elements = descendants_by_kind(tree, 0, &["element", "script_element", "style_element"]);
        let element_set: HashSet<u32> = elements.iter().copied().collect();
        // Only innermost elements are units: an ancestor that contains
        // another element stays a gap, so unit ranges never overlap. A tag
        // edit on an outer element declines through its gap; member edits
        // carry through the inner units.
        let mut has_element_descendant = HashSet::new();
        for element in &elements {
            let mut cursor = tree.get(*element).map_or(NODE_NONE, |n| n.parent);
            while cursor != NODE_NONE {
                if element_set.contains(&cursor) {
                    has_element_descendant.insert(cursor);
                }
                cursor = tree.get(cursor).map_or(NODE_NONE, |n| n.parent);
            }
        }
        for element in elements {
            if has_element_descendant.contains(&element) {
                continue;
            }
            let tag = Self::tag_name(tree, source, element);
            if tag.is_empty() {
                continue;
            }
            let id = Self::id_value(tree, source, element);
            let parent = Self::ancestors(tree, source, element);
            let end = tree.get(element).map_or(0, |n| n.end);
            push(
                tree,
                source,
                element,
                end,
                UnitKey::new(tree.kind_of(element), tag, id, parent),
                &mut out,
            );
        }
        out.sort_by_key(|unit| (unit.start, unit.end));
        out
    }

    fn separators(&self) -> &[u8] {
        &[]
    }
}
