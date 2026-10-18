//! Path-level tree edits over stored Git trees.
//!
//! The one primitive is [`apply_delta`]: it applies the change `from -> to`,
//! restricted to a [`Selection`] of paths, onto `base`. A selected path whose
//! `base` entry matches `from` takes the `to` entry; one whose `base` already
//! matches `to` is left alone; any other selected path has diverged on both
//! sides and refuses with [`ErrorCode::EConflicted`] naming it. Nothing merges
//! content: a conflict is reported, never resolved.
//!
//! Split (`selected` = parent plus the selection taken from the source,
//! `remainder` = source with the selection reverted to the parent), squash
//! (moving a selection of the source delta into the destination), and revert
//! (reversing a delta onto a new parent) all reduce to this primitive. Only
//! directories on a path to a changed entry are rewritten; every other subtree
//! is copied by id.
//!
//! [`set_entry`] and [`lookup`] address one path inside one tree, and
//! [`conflicted_paths`] enumerates the paths a list of tree terms still
//! disagrees on. Together they resolve conflicted trees path by path.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::RepoPath;
use crate::merge::Merge;
use crate::store::Store;
use crate::store::types::{ObjectKind, PreparedObject};
use crate::workcopy::tree::{TreeItem, TreeMode, encode_tree, git_order, parse_tree};

/// The paths a tree edit touches.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Selection<'a> {
    /// Every path.
    All,
    /// Each listed path and everything below it.
    Paths(&'a [RepoPath]),
}

/// One tree entry: its mode and object id.
pub(crate) type Entry = (TreeMode, Oid);

/// An entry that may be absent. An absent directory is the empty directory.
pub(crate) type Node = Option<Entry>;

/// The result of one tree edit: the new root and the tree objects it staged.
#[derive(Debug)]
pub(crate) struct TreeEdit {
    /// The new root tree. Always a tree, even when empty.
    pub(crate) root: Oid,
    /// Newly staged tree objects; absent from the store until published.
    pub(crate) objects: Vec<PreparedObject>,
}

/// The id of the empty tree for `kind`. It need not be stored.
///
/// # Errors
/// Hashing failures for the hash kind.
pub(crate) fn empty_tree(kind: HashKind) -> Result<Oid, CoreError> {
    kind.hash_git_object("tree", b"").map_err(CoreError::from)
}

/// Applies the change `from -> to`, restricted to `selection`, onto `base`.
///
/// Selected paths that `base` already holds at `to` are unchanged; selected
/// paths that `base` holds at `from` take their `to` entry (absence included).
/// Unselected paths keep their `base` entry.
///
/// # Errors
/// - [`ErrorCode::EConflicted`] naming every selected path that diverged in
///   `base` and in the delta, and any path where a file and a directory would
///   have to share a name.
/// - [`ErrorCode::ENotFound`] for a tree that is not stored (except the empty
///   tree), [`ErrorCode::ECorrupt`] for a malformed tree, and store failures.
pub(crate) fn apply_delta(
    store: &Store,
    base: Oid,
    from: Oid,
    to: Oid,
    selection: Selection<'_>,
) -> Result<TreeEdit, CoreError> {
    let mut editor = Editor::new(store, selection)?;
    let root = editor.apply_at(
        &[],
        Some((TreeMode::Tree, base)),
        Some((TreeMode::Tree, from)),
        Some((TreeMode::Tree, to)),
    )?;
    if !editor.conflicts.is_empty() {
        return Err(editor.conflict_error());
    }
    let root = root_oid(&mut editor, root)?;
    Ok(TreeEdit {
        root,
        objects: editor.objects,
    })
}

/// The entry at `path` inside tree `root`, or `None` when absent. A file
/// standing where the path needs a directory also reads as absent.
///
/// # Errors
/// [`ErrorCode::ENotFound`] for an unstored tree, [`ErrorCode::ECorrupt`] for a
/// malformed one, and store failures.
pub(crate) fn lookup(store: &Store, root: Oid, path: &RepoPath) -> Result<Node, CoreError> {
    let editor = Editor::new(store, Selection::All)?;
    let comps: Vec<&[u8]> = path.components().collect();
    let Some((name, dirs)) = comps.split_last() else {
        return Ok(Some((TreeMode::Tree, root)));
    };
    let mut dir: Node = Some((TreeMode::Tree, root));
    for component in dirs {
        dir = match editor.items(dir)?.get(*component).copied() {
            Some((TreeMode::Tree, oid)) => Some((TreeMode::Tree, oid)),
            _ => return Ok(None),
        };
    }
    Ok(editor.items(dir)?.get(*name).copied())
}

/// Replaces (or with `None` removes) the entry at `path` inside tree `root`,
/// creating intermediate directories and pruning directories that empty out.
///
/// # Errors
/// [`ErrorCode::EConflicted`] when an ancestor of `path` is a file in `root`;
/// otherwise as [`apply_delta`].
pub(crate) fn set_entry(
    store: &Store,
    root: Oid,
    path: &RepoPath,
    entry: Node,
) -> Result<TreeEdit, CoreError> {
    let mut editor = Editor::new(store, Selection::All)?;
    let comps: Vec<&[u8]> = path.components().collect();
    let node = editor.set_at(Some((TreeMode::Tree, root)), &comps, entry, path)?;
    let root = root_oid(&mut editor, node)?;
    Ok(TreeEdit {
        root,
        objects: editor.objects,
    })
}

/// Every path whose entries differ across the tree `terms`, paired with the
/// number of terms its simplified conflict keeps (odd, at least three).
///
/// Directories whose ids agree are skipped without reading them.
///
/// # Errors
/// As [`apply_delta`].
pub(crate) fn conflicted_paths(
    store: &Store,
    terms: &[Oid],
) -> Result<Vec<(RepoPath, usize)>, CoreError> {
    let editor = Editor::new(store, Selection::All)?;
    let nodes: Vec<Node> = terms.iter().map(|oid| Some((TreeMode::Tree, *oid))).collect();
    let mut out = Vec::new();
    editor.walk_conflicts(&[], &nodes, &mut out)?;
    Ok(out)
}

/// Returns the root id, writing an empty directory when the edit removed
/// every entry.
fn root_oid(editor: &mut Editor<'_>, node: Node) -> Result<Oid, CoreError> {
    match node {
        Some((TreeMode::Tree, oid)) => Ok(oid),
        _ => editor.write(BTreeMap::new()),
    }
}

/// Whether an entry is a directory.
fn is_dir(node: Node) -> bool {
    matches!(node, Some((TreeMode::Tree, _)))
}

/// Whether an entry is a directory or absent: the only shapes a directory
/// merge can recurse through.
fn dir_or_absent(node: Node) -> bool {
    node.is_none_or(|(mode, _)| mode == TreeMode::Tree)
}

/// `dir/name`, or `name` at the root.
fn child(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(dir.len() + 1 + name.len());
    if !dir.is_empty() {
        path.extend_from_slice(dir);
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// Whether the selected `path` lies inside a selected path, itself included.
pub(crate) fn covered_by(path: &[u8], selected: &RepoPath) -> bool {
    let selected = selected.as_bytes();
    path == selected
        || (path.len() > selected.len()
            && path.starts_with(selected)
            && path[selected.len()] == b'/')
}

/// Whether some selected path lies strictly below directory `path`.
fn selects_below(path: &[u8], selected: &RepoPath) -> bool {
    let selected = selected.as_bytes();
    selected.len() > path.len()
        && selected.starts_with(path)
        && (path.is_empty() || selected[path.len()] == b'/')
}

struct Editor<'a> {
    store: &'a Store,
    kind: HashKind,
    empty: Oid,
    selection: Selection<'a>,
    /// Selected paths that diverged in both base and delta.
    conflicts: Vec<Vec<u8>>,
    objects: Vec<PreparedObject>,
    /// Tree ids already staged by this edit.
    staged: BTreeSet<Oid>,
}

impl<'a> Editor<'a> {
    fn new(store: &'a Store, selection: Selection<'a>) -> Result<Self, CoreError> {
        let kind = store.hash_kind();
        Ok(Self {
            store,
            kind,
            empty: empty_tree(kind)?,
            selection,
            conflicts: Vec::new(),
            objects: Vec::new(),
            staged: BTreeSet::new(),
        })
    }

    fn covers(&self, path: &[u8]) -> bool {
        match self.selection {
            Selection::All => true,
            Selection::Paths(paths) => paths.iter().any(|selected| covered_by(path, selected)),
        }
    }

    fn selects_below(&self, path: &[u8]) -> bool {
        match self.selection {
            Selection::All => false,
            Selection::Paths(paths) => paths.iter().any(|selected| selects_below(path, selected)),
        }
    }

    fn conflict_error(&self) -> CoreError {
        let shown: Vec<String> = self
            .conflicts
            .iter()
            .take(8)
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect();
        let more = self.conflicts.len().saturating_sub(shown.len());
        let suffix = if more == 0 {
            String::new()
        } else {
            format!(" and {more} more")
        };
        CoreError::new(
            ErrorCode::EConflicted,
            format!(
                "the change conflicts with the base at {}{suffix}; resolve those paths first",
                shown.join(", ")
            ),
        )
    }

    /// The entries of a directory node, keyed by name. Absent and non-directory
    /// nodes have no entries.
    fn items(&self, node: Node) -> Result<BTreeMap<Vec<u8>, Entry>, CoreError> {
        let Some((TreeMode::Tree, oid)) = node else {
            return Ok(BTreeMap::new());
        };
        if oid == self.empty {
            return Ok(BTreeMap::new());
        }
        let mut object = self.store.read(oid)?;
        if object.kind != ObjectKind::Tree {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                format!("object {} is not a tree", oid.to_hex()),
            ));
        }
        let mut bytes = Vec::new();
        object.bytes.read_to_end(&mut bytes).map_err(|err| {
            CoreError::new(ErrorCode::EIo, format!("reading tree {}: {err}", oid.to_hex()))
        })?;
        let items = parse_tree(self.kind, &bytes)?;
        Ok(items
            .into_iter()
            .map(|item| (item.name, (item.mode, item.oid)))
            .collect())
    }

    /// Encodes and stages one directory, or returns the existing id when the
    /// store already holds it. An empty directory is the empty tree.
    fn write(&mut self, items: BTreeMap<Vec<u8>, Entry>) -> Result<Oid, CoreError> {
        let mut items: Vec<TreeItem> = items
            .into_iter()
            .map(|(name, (mode, oid))| TreeItem { name, mode, oid })
            .collect();
        items.sort_by(git_order);
        let bytes = encode_tree(&items);
        let oid = self.kind.hash_git_object("tree", &bytes)?;
        if self.staged.contains(&oid) || self.store.object_len(oid)?.is_some() {
            return Ok(oid);
        }
        let len = u64::try_from(bytes.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "tree exceeds u64 bytes"))?;
        let object = self
            .store
            .prepare(ObjectKind::Tree, len, bytes.as_slice(), None)?;
        if object.oid() != oid {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "prepared tree id disagrees with its encoded bytes",
            ));
        }
        self.staged.insert(oid);
        self.objects.push(object);
        Ok(oid)
    }

    /// Applies the delta to one path. `base`, `from`, and `to` are the entry at
    /// `path` in each tree; the result is the entry `base` becomes.
    fn apply_at(
        &mut self,
        path: &[u8],
        base: Node,
        from: Node,
        to: Node,
    ) -> Result<Node, CoreError> {
        if base == to || from == to {
            return Ok(base);
        }
        let covered = self.covers(path);
        if !covered && !self.selects_below(path) {
            return Ok(base);
        }
        if covered && base == from {
            return Ok(to);
        }
        if !covered && !is_dir(from) && !is_dir(to) {
            // No selected path lies beneath a file on either side of the delta.
            return Ok(base);
        }
        if covered && !(dir_or_absent(base) && dir_or_absent(from) && dir_or_absent(to)) {
            self.conflicts.push(path.to_vec());
            return Ok(base);
        }

        let base_items = self.items(base)?;
        let from_items = self.items(from)?;
        let to_items = self.items(to)?;
        let names: BTreeSet<&Vec<u8>> = base_items
            .keys()
            .chain(from_items.keys())
            .chain(to_items.keys())
            .collect();
        let mut updates: Vec<(Vec<u8>, Node)> = Vec::new();
        for name in names {
            let entry_base = base_items.get(name).copied();
            let entry_from = from_items.get(name).copied();
            let entry_to = to_items.get(name).copied();
            let child_path = child(path, name);
            let next = self.apply_at(&child_path, entry_base, entry_from, entry_to)?;
            if next != entry_base {
                updates.push((name.clone(), next));
            }
        }
        if updates.is_empty() {
            return Ok(base);
        }
        if base.is_some_and(|(mode, _)| mode != TreeMode::Tree) {
            // A file in the base cannot become a directory the delta fills.
            self.conflicts.push(path.to_vec());
            return Ok(base);
        }
        let mut out = base_items;
        for (name, next) in updates {
            match next {
                Some(entry) => out.insert(name, entry),
                None => out.remove(&name),
            };
        }
        if out.is_empty() && !path.is_empty() {
            return Ok(None);
        }
        Ok(Some((TreeMode::Tree, self.write(out)?)))
    }

    /// Writes `entry` at the path `comps` below directory node `dir`.
    fn set_at(
        &mut self,
        dir: Node,
        comps: &[&[u8]],
        entry: Node,
        path: &RepoPath,
    ) -> Result<Node, CoreError> {
        let Some((name, rest)) = comps.split_first() else {
            return Ok(entry);
        };
        let mut items = self.items(dir)?;
        if rest.is_empty() {
            match entry {
                Some(entry) => items.insert(name.to_vec(), entry),
                None => items.remove(*name),
            };
        } else {
            let existing = items.get(*name).copied();
            if !dir_or_absent(existing) {
                return Err(CoreError::new(
                    ErrorCode::EConflicted,
                    format!(
                        "{} cannot be set: an ancestor is a file in this tree",
                        String::from_utf8_lossy(path.as_bytes())
                    ),
                ));
            }
            let next = self.set_at(existing, rest, entry, path)?;
            match next {
                Some(next) => items.insert(name.to_vec(), next),
                None => items.remove(*name),
            };
        }
        if items.is_empty() {
            return Ok(None);
        }
        Ok(Some((TreeMode::Tree, self.write(items)?)))
    }

    /// Collects the paths under directory `dir` whose entries differ across
    /// `nodes`, one node per tree term.
    fn walk_conflicts(
        &self,
        dir: &[u8],
        nodes: &[Node],
        out: &mut Vec<(RepoPath, usize)>,
    ) -> Result<(), CoreError> {
        let maps = nodes
            .iter()
            .map(|node| self.items(*node))
            .collect::<Result<Vec<_>, _>>()?;
        let names: BTreeSet<&Vec<u8>> = maps.iter().flat_map(|map| map.keys()).collect();
        for name in names {
            let entries: Vec<Node> = maps.iter().map(|map| map.get(name).copied()).collect();
            let Some(first) = entries.first() else {
                continue;
            };
            if entries.iter().all(|entry| entry == first) {
                continue;
            }
            let path = child(dir, name);
            let all_dirs = entries.iter().all(|entry| dir_or_absent(*entry));
            if all_dirs && entries.iter().any(|entry| is_dir(*entry)) {
                self.walk_conflicts(&path, &entries, out)?;
                continue;
            }
            let simplified = Merge::try_from_vec(entries)
                .map_err(CoreError::from)?
                .simplify();
            if simplified.is_resolved() {
                continue;
            }
            let terms = 2 * simplified.num_sides() - 1;
            out.push((RepoPath::new(path).map_err(CoreError::from)?, terms));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::store::PreparationBudget;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ruk-tree-edit-test-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&root);
            let store = Store::create(
                &root,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create test store");
            Self { root, store }
        }

        /// Publishes `object` and returns its id.
        fn publish(&self, kind: ObjectKind, bytes: &[u8]) -> Oid {
            let len = u64::try_from(bytes.len()).expect("len");
            let prepared = self
                .store
                .prepare(kind, len, Cursor::new(bytes), None)
                .expect("prepare");
            let oid = prepared.oid();
            self.store.publish(vec![prepared], &[]).expect("publish");
            oid
        }

        fn blob(&self, text: &str) -> Oid {
            self.publish(ObjectKind::Blob, text.as_bytes())
        }

        /// Builds a tree from `(path, blob text)` pairs.
        fn tree(&self, files: &[(&str, &str)]) -> Oid {
            let mut root = self.publish(ObjectKind::Tree, b"");
            for (path, text) in files {
                let blob = self.blob(text);
                let entry = Some((TreeMode::File(crate::index::FileMode::Regular), blob));
                root = write_all(self, root, path, entry);
            }
            root
        }

        fn read(&self, root: Oid, path: &str) -> Option<String> {
            let path = RepoPath::new(path.as_bytes().to_vec()).expect("path");
            let entry = lookup(&self.store, root, &path).expect("lookup")?;
            let (mode, oid) = entry;
            assert!(mode != TreeMode::Tree, "{path:?} names a directory");
            let mut object = self.store.read(oid).expect("read blob");
            let mut bytes = Vec::new();
            object.bytes.read_to_end(&mut bytes).expect("read bytes");
            Some(String::from_utf8(bytes).expect("utf8"))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn write_all(fixture: &Fixture, root: Oid, path: &str, entry: Node) -> Oid {
        let path = RepoPath::new(path.as_bytes().to_vec()).expect("path");
        let edit = set_entry(&fixture.store, root, &path, entry).expect("set entry");
        publish_edit(fixture, edit)
    }

    fn publish_edit(fixture: &Fixture, edit: TreeEdit) -> Oid {
        fixture
            .store
            .publish(edit.objects, &[])
            .expect("publish tree edit");
        edit.root
    }

    fn paths(list: &[&str]) -> Vec<RepoPath> {
        list.iter()
            .map(|p| RepoPath::new(p.as_bytes().to_vec()).expect("path"))
            .collect()
    }

    fn apply(
        fixture: &Fixture,
        base: Oid,
        from: Oid,
        to: Oid,
        selection: Selection<'_>,
    ) -> Result<Oid, CoreError> {
        let edit = apply_delta(&fixture.store, base, from, to, selection)?;
        Ok(publish_edit(fixture, edit))
    }

    #[test]
    fn selected_delta_lands_and_unselected_stays() {
        let fixture = Fixture::new("select");
        let parent = fixture.tree(&[("a", "a0"), ("b", "b0")]);
        let source = fixture.tree(&[("a", "a1"), ("b", "b1")]);
        let selected = paths(&["a"]);

        let selected_tree = apply(
            &fixture,
            parent,
            parent,
            source,
            Selection::Paths(&selected),
        )
        .expect("selected tree");
        assert_eq!(fixture.read(selected_tree, "a").as_deref(), Some("a1"));
        assert_eq!(fixture.read(selected_tree, "b").as_deref(), Some("b0"));

        let remainder = apply(
            &fixture,
            source,
            source,
            parent,
            Selection::Paths(&selected),
        )
        .expect("remainder tree");
        assert_eq!(fixture.read(remainder, "a").as_deref(), Some("a0"));
        assert_eq!(fixture.read(remainder, "b").as_deref(), Some("b1"));
    }

    #[test]
    fn whole_directory_selection_takes_every_leaf_below_it() {
        let fixture = Fixture::new("dir");
        let base = fixture.tree(&[("d/x", "x0"), ("d/y", "y0"), ("e", "e0")]);
        let to = fixture.tree(&[("d/x", "x1"), ("d/z", "z1"), ("e", "e1")]);
        let selected = paths(&["d"]);
        let merged = apply(&fixture, base, base, to, Selection::Paths(&selected)).expect("merge");
        assert_eq!(fixture.read(merged, "d/x").as_deref(), Some("x1"));
        assert_eq!(fixture.read(merged, "d/z").as_deref(), Some("z1"));
        assert_eq!(fixture.read(merged, "d/y"), None, "deletion below d applies");
        assert_eq!(fixture.read(merged, "e").as_deref(), Some("e0"));
    }

    #[test]
    fn reverse_delta_keeps_unrelated_base_content() {
        let fixture = Fixture::new("revert");
        // target introduced `t` and changed `a`; its parent has neither.
        let parent = fixture.tree(&[("a", "a0")]);
        let target = fixture.tree(&[("a", "a1"), ("t", "t")]);
        // onto carries an unrelated file the reversal must keep.
        let onto = fixture.tree(&[("a", "a1"), ("t", "t"), ("keep", "k")]);
        let edit = apply_delta(&fixture.store, onto, target, parent, Selection::All)
            .expect("reverse delta");
        let reverted = publish_edit(&fixture, edit);
        assert_eq!(fixture.read(reverted, "a").as_deref(), Some("a0"));
        assert_eq!(fixture.read(reverted, "t"), None);
        assert_eq!(fixture.read(reverted, "keep").as_deref(), Some("k"));
    }

    #[test]
    fn diverged_selected_path_refuses_naming_it() {
        let fixture = Fixture::new("conflict");
        let from = fixture.tree(&[("a", "a0"), ("b", "b0")]);
        let to = fixture.tree(&[("a", "a1"), ("b", "b1")]);
        let base = fixture.tree(&[("a", "a-other"), ("b", "b0")]);
        let selected = paths(&["a"]);
        let err = apply(&fixture, base, from, to, Selection::Paths(&selected))
            .expect_err("diverged path must conflict");
        assert_eq!(err.code, ErrorCode::EConflicted);
        assert!(err.message.contains("a"), "names the path: {}", err.message);

        // An unselected divergence is not this edit's business.
        let unselected = paths(&["b"]);
        let ok = apply(&fixture, base, from, to, Selection::Paths(&unselected))
            .expect("b is not diverged");
        assert_eq!(fixture.read(ok, "b").as_deref(), Some("b1"));
    }

    #[test]
    fn set_entry_round_trips_and_prunes_emptied_directories() {
        let fixture = Fixture::new("set");
        let tree = fixture.tree(&[("d/x", "x"), ("top", "t")]);
        let path = RepoPath::new(b"d/x".to_vec()).expect("path");
        let removed = set_entry(&fixture.store, tree, &path, None).expect("remove");
        let removed_root = publish_edit(&fixture, removed);
        assert_eq!(lookup(&fixture.store, removed_root, &path).expect("lookup"), None);
        let dir = RepoPath::new(b"d".to_vec()).expect("path");
        assert_eq!(
            lookup(&fixture.store, removed_root, &dir).expect("lookup"),
            None,
            "an emptied directory is pruned"
        );
        assert_eq!(fixture.read(removed_root, "top").as_deref(), Some("t"));
    }

    #[test]
    fn conflicted_paths_lists_only_disagreeing_leaves() {
        let fixture = Fixture::new("terms");
        let t1 = fixture.tree(&[("same", "s"), ("clash", "1"), ("d/x", "x1")]);
        let t2 = fixture.tree(&[("same", "s"), ("clash", "2"), ("d/x", "x2")]);
        let t3 = fixture.tree(&[("same", "s"), ("clash", "3"), ("d/x", "x1")]);
        let found = conflicted_paths(&fixture.store, &[t1, t2, t3]).expect("walk");
        let names: Vec<String> = found
            .iter()
            .map(|(path, _)| String::from_utf8_lossy(path.as_bytes()).into_owned())
            .collect();
        assert_eq!(names, vec!["clash".to_string(), "d/x".to_string()]);
        assert!(found.iter().all(|(_, terms)| *terms == 3));
    }

    #[test]
    fn a_file_in_the_base_blocks_a_selected_directory_change() {
        let fixture = Fixture::new("file-blocks-dir");
        let base = fixture.tree(&[("a", "file")]);
        let from = fixture.tree(&[]);
        let to = fixture.tree(&[("a/x", "v")]);
        let selected = paths(&["a/x"]);
        let err = apply(&fixture, base, from, to, Selection::Paths(&selected))
            .expect_err("a file cannot become a directory the delta fills");
        assert_eq!(err.code, ErrorCode::EConflicted);
        assert!(err.message.contains("at a"), "names the path: {}", err.message);
    }

    #[test]
    fn removing_the_last_selected_entry_writes_the_empty_root() {
        let fixture = Fixture::new("empty-root");
        let base = fixture.tree(&[("x", "x0")]);
        let empty = fixture.tree(&[]);
        let selected = paths(&["x"]);
        let emptied = apply(&fixture, base, base, empty, Selection::Paths(&selected))
            .expect("removing the only entry applies");
        assert_eq!(emptied, empty, "an emptied root is the empty tree");
    }
}
