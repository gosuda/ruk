//! Git tree codec, the directory cache, and dirty-ancestor tree rebuild.
//!
//! Rebuild visits only directories that contain a changed path. Every other
//! entry, including whole out-of-scope subtrees and gitlinks, is copied from
//! the base tree by id. Only directories whose encoded bytes change produce
//! new tree objects and `ws_dirs` rows.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::statcache::{corrupt, decode_row, encode_row};
use super::{cache_key, join};
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath};
use crate::store::{FactExpectation, FactMutation, FactTable, ObjectKind, PreparedObject, Store};
use crate::workspace::Scope;
use crate::{CoreError, ErrorCode, WorkspaceId};

/// The mode of one tree entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum TreeMode {
    File(FileMode),
    Tree,
}

impl TreeMode {
    fn spelling(self) -> &'static [u8] {
        match self {
            Self::File(FileMode::Regular) => b"100644",
            Self::File(FileMode::Executable) => b"100755",
            Self::File(FileMode::Symlink) => b"120000",
            Self::File(FileMode::Gitlink) => b"160000",
            Self::Tree => b"40000",
        }
    }

    /// Parses a stored mode. The historical group-writable `100664` reads
    /// as regular and a zero-padded `040000` as a tree, as Git reads them.
    fn parse(text: &[u8]) -> Option<Self> {
        Some(match text {
            b"100644" | b"100664" => Self::File(FileMode::Regular),
            b"100755" => Self::File(FileMode::Executable),
            b"120000" => Self::File(FileMode::Symlink),
            b"160000" => Self::File(FileMode::Gitlink),
            b"40000" | b"040000" => Self::Tree,
            _ => return None,
        })
    }

    /// A blob-backed entry: regular, executable, or symlink.
    #[must_use]
    pub(crate) fn is_blob(self) -> bool {
        matches!(
            self,
            Self::File(FileMode::Regular | FileMode::Executable | FileMode::Symlink)
        )
    }
}

/// One tree entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TreeItem {
    pub(crate) name: Vec<u8>,
    pub(crate) mode: TreeMode,
    pub(crate) oid: Oid,
}

/// Git's tree order: bytewise by name, a tree compared as if its name ended
/// in `/`.
pub(crate) fn git_order(left: &TreeItem, right: &TreeItem) -> Ordering {
    let suffix = |item: &TreeItem| (item.mode == TreeMode::Tree).then_some(b'/');
    let left_bytes = left.name.iter().copied().chain(suffix(left));
    let right_bytes = right.name.iter().copied().chain(suffix(right));
    left_bytes.cmp(right_bytes)
}

/// Encodes entries already in [`git_order`].
#[must_use]
pub(crate) fn encode_tree(items: &[TreeItem]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.mode.spelling());
        out.push(b' ');
        out.extend_from_slice(&item.name);
        out.push(0);
        out.extend_from_slice(item.oid.as_bytes());
    }
    out
}

/// Parses a tree payload of the repository's hash width.
///
/// # Errors
/// `E_CORRUPT` for a malformed payload.
pub(crate) fn parse_tree(kind: HashKind, mut bytes: &[u8]) -> Result<Vec<TreeItem>, CoreError> {
    let corrupt = |detail: &str| CoreError::new(ErrorCode::ECorrupt, format!("tree: {detail}"));
    let width = kind.oid_len();
    let mut items = Vec::new();
    while !bytes.is_empty() {
        let space = bytes
            .iter()
            .position(|&byte| byte == b' ')
            .ok_or_else(|| corrupt("entry without a mode"))?;
        let mode = TreeMode::parse(&bytes[..space]).ok_or_else(|| corrupt("unknown mode"))?;
        let rest = &bytes[space + 1..];
        let nul = rest
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| corrupt("unterminated name"))?;
        let name = &rest[..nul];
        if name.is_empty() || name.contains(&b'/') {
            return Err(corrupt("invalid entry name"));
        }
        let id = rest
            .get(nul + 1..nul + 1 + width)
            .ok_or_else(|| corrupt("truncated object id"))?;
        items.push(TreeItem {
            name: name.to_vec(),
            mode,
            oid: Oid::from_bytes(id).map_err(CoreError::from)?,
        });
        bytes = &rest[nul + 1 + width..];
    }
    Ok(items)
}

/// One `ws_dirs` row: a directory's tree id and its entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirRow {
    pub(crate) tree: Oid,
    pub(crate) items: Vec<TreeItem>,
}

/// Reads directory listings through the `ws_dirs` cache, falling back to
/// verified store reads. A cache row is used only when its tree id equals
/// the id being read.
#[derive(Debug)]
pub(crate) struct Dirs<'s> {
    store: &'s Store,
    workspace: WorkspaceId,
    loaded: HashMap<Oid, Arc<[TreeItem]>>,
}

impl<'s> Dirs<'s> {
    #[must_use]
    pub(crate) fn new(store: &'s Store, workspace: WorkspaceId) -> Self {
        Self {
            store,
            workspace,
            loaded: HashMap::new(),
        }
    }

    /// The entries of tree `oid`, found at directory `dir`.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unpublished tree, `E_CORRUPT` for a non-tree or
    /// malformed object, and store failures.
    pub(crate) fn items(&mut self, dir: &[u8], oid: Oid) -> Result<Arc<[TreeItem]>, CoreError> {
        if let Some(items) = self.loaded.get(&oid) {
            return Ok(Arc::clone(items));
        }
        let key = cache_key(self.workspace, dir);
        let cached = match self.store.fact(FactTable::WsDirs, &key)? {
            Some(bytes) => Some(decode_row::<DirRow>(self.store, "ws_dirs row", &bytes)?),
            None => None,
        };
        let items: Arc<[TreeItem]> = match cached {
            Some(row) if row.tree == oid => row.items.into(),
            _ => self.read_tree(oid)?.into(),
        };
        self.loaded.insert(oid, Arc::clone(&items));
        Ok(items)
    }

    fn read_tree(&self, oid: Oid) -> Result<Vec<TreeItem>, CoreError> {
        let mut object = self.store.read(oid)?;
        if object.kind != ObjectKind::Tree {
            return Err(corrupt(
                self.store,
                format!("object {} is not a tree", oid.to_hex()),
            ));
        }
        let mut bytes = Vec::new();
        object
            .bytes
            .read_to_end(&mut bytes)
            .map_err(|err| super::io_error("reading a tree object", &err))?;
        parse_tree(self.store.hash_kind(), &bytes).map_err(|err| {
            corrupt(
                self.store,
                format!(
                    "tree object {} does not parse: {}",
                    oid.to_hex(),
                    err.message
                ),
            )
        })
    }

    /// The entry at `path` in the tree rooted at `root`.
    ///
    /// # Errors
    /// As [`Self::items`].
    pub(crate) fn lookup(
        &mut self,
        root: Oid,
        path: &[u8],
    ) -> Result<Option<(TreeMode, Oid)>, CoreError> {
        let mut current = (TreeMode::Tree, root);
        let mut dir_len = 0;
        for name in path.split(|&byte| byte == b'/') {
            if current.0 != TreeMode::Tree {
                return Ok(None);
            }
            let items = self.items(&path[..dir_len], current.1)?;
            let Some(item) = items.iter().find(|item| item.name == name) else {
                return Ok(None);
            };
            current = (item.mode, item.oid);
            dir_len = if dir_len == 0 {
                name.len()
            } else {
                dir_len + 1 + name.len()
            };
        }
        Ok(Some(current))
    }

    /// Every blob-backed entry under directory `start` (empty for the root)
    /// that the scope covers, descending only into visited directories.
    /// Names that cannot be repository paths are skipped: snapshot never
    /// touches them.
    ///
    /// # Errors
    /// As [`Self::items`].
    pub(crate) fn tracked_files(
        &mut self,
        root: Oid,
        start: &[u8],
        scope: &Scope,
    ) -> Result<BTreeMap<RepoPath, (FileMode, Oid)>, CoreError> {
        let mut out = BTreeMap::new();
        let start_tree = if start.is_empty() {
            Some(root)
        } else {
            match self.lookup(root, start)? {
                Some((TreeMode::Tree, oid)) => Some(oid),
                _ => None,
            }
        };
        let Some(start_tree) = start_tree else {
            return Ok(out);
        };
        let mut pending = vec![(start.to_vec(), start_tree)];
        while let Some((dir, oid)) = pending.pop() {
            for item in self.items(&dir, oid)?.iter() {
                let Ok(path) = join(&dir, &item.name) else {
                    continue;
                };
                match item.mode {
                    TreeMode::Tree if scope.includes_dir(&path) => {
                        pending.push((path.as_bytes().to_vec(), item.oid));
                    }
                    TreeMode::File(mode) if item.mode.is_blob() => {
                        out.insert(path, (mode, item.oid));
                    }
                    _ => {}
                }
            }
        }
        Ok(out)
    }
}

/// The new state of one changed path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Leaf {
    File { mode: FileMode, blob: Oid },
    Absent,
}

#[derive(Default)]
struct Node {
    leaf: Option<Leaf>,
    children: BTreeMap<Vec<u8>, Node>,
}

impl Node {
    /// Inserts a leaf. A file leaf replaces everything below it, and a path
    /// below a file leaf is dropped: nothing can exist beneath a file. An
    /// absent leaf keeps its children: the old entry is gone and, if
    /// anything lies below, a new directory replaces it.
    fn insert(&mut self, path: &RepoPath, leaf: Leaf) {
        let mut node = self;
        for name in path.components() {
            if matches!(node.leaf, Some(Leaf::File { .. })) {
                return;
            }
            node = node.children.entry(name.to_vec()).or_default();
        }
        if matches!(leaf, Leaf::File { .. }) {
            node.children.clear();
        }
        node.leaf = Some(leaf);
    }
}

/// The result of one rebuild.
#[derive(Debug)]
pub(crate) struct Rebuilt {
    pub(crate) root: Oid,
    /// New tree objects, deduplicated by id.
    pub(crate) objects: Vec<PreparedObject>,
    /// `ws_dirs` rows to put (rebuilt directories) and remove (directories
    /// that vanished or became files).
    pub(crate) dirs: Vec<FactMutation>,
    /// Directories present in the base whose subtree was dropped or
    /// replaced; their `ws_status` and `ws_dirs` descendants are stale.
    pub(crate) removed_dirs: Vec<Vec<u8>>,
}

/// Rebuilds the tree rooted at `base` with `leaves` applied, along their
/// ancestors only.
///
/// # Errors
/// Tree read failures, `E_CAPACITY`/`E_LIMIT` from preparation, and
/// `E_OBJECT_FORMAT` for a leaf of the wrong hash width.
pub(crate) fn rebuild(
    dirs: &mut Dirs<'_>,
    base: Oid,
    leaves: &BTreeMap<RepoPath, Leaf>,
) -> Result<Rebuilt, CoreError> {
    let mut trie = Node::default();
    for (path, leaf) in leaves {
        trie.insert(path, *leaf);
    }
    let mut out = Rebuilt {
        root: base,
        objects: Vec::new(),
        dirs: Vec::new(),
        removed_dirs: Vec::new(),
    };
    let mut seen = HashSet::new();
    // The root is never collapsed: an empty worktree is the empty tree.
    let Some(root) = rebuild_dir(
        dirs,
        &trie,
        &mut Vec::new(),
        Some(base),
        &mut out,
        &mut seen,
    )?
    else {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "root rebuild produced no tree",
        ));
    };
    out.root = root;
    Ok(out)
}

fn rebuild_dir(
    dirs: &mut Dirs<'_>,
    node: &Node,
    dir: &mut Vec<u8>,
    base: Option<Oid>,
    out: &mut Rebuilt,
    seen: &mut HashSet<Oid>,
) -> Result<Option<Oid>, CoreError> {
    let mut entries: BTreeMap<Vec<u8>, (TreeMode, Oid)> = match base {
        Some(oid) => dirs
            .items(dir, oid)?
            .iter()
            .map(|item| (item.name.clone(), (item.mode, item.oid)))
            .collect(),
        None => BTreeMap::new(),
    };
    for (name, child) in &node.children {
        let previous = entries.get(name).copied();
        if child.leaf.is_none() && matches!(previous, Some((TreeMode::File(FileMode::Gitlink), _)))
        {
            continue;
        }
        let next = match child.leaf {
            Some(Leaf::File { mode, blob }) => Some((TreeMode::File(mode), blob)),
            Some(Leaf::Absent) if child.children.is_empty() => None,
            Some(Leaf::Absent) => rebuild_child(dirs, child, dir, name, None, out, seen)?,
            None => rebuild_child(dirs, child, dir, name, previous, out, seen)?,
        };
        if let Some((TreeMode::Tree, _)) = previous
            && !matches!(next, Some((TreeMode::Tree, _)))
        {
            out.removed_dirs.push(child_path(dir, name));
        }
        match next {
            Some(entry) => entries.insert(name.clone(), entry),
            None => entries.remove(name),
        };
    }

    if entries.is_empty() && !dir.is_empty() {
        return Ok(None);
    }
    let items: Vec<TreeItem> = entries
        .into_iter()
        .map(|(name, (mode, oid))| TreeItem { name, mode, oid })
        .collect();
    write_tree(dirs, dir, items, base, out, seen).map(Some)
}

/// Rebuilds the subdirectory `name` of `dir` from its base entry: a tree is
/// the base, anything else (a file being replaced, nothing) starts empty.
fn rebuild_child(
    dirs: &mut Dirs<'_>,
    child: &Node,
    dir: &mut Vec<u8>,
    name: &[u8],
    previous: Option<(TreeMode, Oid)>,
    out: &mut Rebuilt,
    seen: &mut HashSet<Oid>,
) -> Result<Option<(TreeMode, Oid)>, CoreError> {
    let sub_base = match previous {
        Some((TreeMode::Tree, oid)) => Some(oid),
        _ => None,
    };
    let mark = dir.len();
    if !dir.is_empty() {
        dir.push(b'/');
    }
    dir.extend_from_slice(name);
    let sub = rebuild_dir(dirs, child, dir, sub_base, out, seen);
    dir.truncate(mark);
    Ok(sub?.map(|oid| (TreeMode::Tree, oid)))
}

fn child_path(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = dir.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// Encodes one directory; prepares the object and records its `ws_dirs` row
/// only when the id differs from `base`.
fn write_tree(
    dirs: &mut Dirs<'_>,
    dir: &[u8],
    mut items: Vec<TreeItem>,
    base: Option<Oid>,
    out: &mut Rebuilt,
    seen: &mut HashSet<Oid>,
) -> Result<Oid, CoreError> {
    let kind = dirs.store.hash_kind();
    for item in &items {
        item.oid.expect_kind(kind, "tree entry")?;
    }
    items.sort_by(git_order);
    let bytes = encode_tree(&items);
    let oid = kind.hash_git_object("tree", &bytes)?;
    if Some(oid) == base {
        return Ok(oid);
    }
    if seen.insert(oid) {
        let len = u64::try_from(bytes.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "tree exceeds u64 bytes"))?;
        let object = dirs
            .store
            .prepare(ObjectKind::Tree, len, bytes.as_slice(), None)?;
        if object.oid() != oid {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "prepared tree id disagrees with its encoded bytes",
            ));
        }
        out.objects.push(object);
    }
    let row = DirRow { tree: oid, items };
    let encoded = encode_row("ws_dirs row", &row)?;
    out.dirs.push(FactMutation {
        table: FactTable::WsDirs,
        key: cache_key(dirs.workspace, dir),
        expected: FactExpectation::Any,
        value: Some(encoded),
    });
    dirs.loaded.insert(oid, row.items.into());
    Ok(oid)
}
