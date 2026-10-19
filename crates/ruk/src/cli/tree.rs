//! Canonical Git tree codec and commit/tag payload builders.
//!
//! Trees are the exact `git mktree` byte form: entries sorted with
//! directories ordered as `name + "/"`, each spelled `<octal> <name>\0<raw
//! id>`. The parser accepts exactly that form; anything else is `E_INVALID`,
//! never a silent repair. Payload builders spell the canonical commit and
//! tag headers the store's Git import path already accepts.

use std::collections::BTreeMap;
use std::io::Read as _;

use ruk_core::conflict::Signature;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{FileMode, IndexEntry};
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;
use std::io::Read;

/// The mode of one tree entry: the four blob/commit modes plus the
/// directory mode. The index [`FileMode`] deliberately refuses `040000`
/// (index rows are never directories), so trees carry this wider type and
/// map back through [`TreeMode::as_index_mode`] only for blob/commit rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum TreeMode {
    Regular,
    Executable,
    Symlink,
    Gitlink,
    Tree,
}

impl TreeMode {
    /// Canonical octal value, the way `ls-tree` spells it.
    #[must_use]
    pub(crate) const fn octal(self) -> u32 {
        match self {
            Self::Regular => 0o100_644,
            Self::Executable => 0o100_755,
            Self::Symlink => 0o120_000,
            Self::Gitlink => 0o160_000,
            Self::Tree => 0o040_000,
        }
    }

    /// Canonical spelling for tree bodies.
    fn spelling(self) -> &'static str {
        match self {
            Self::Regular => "100644",
            Self::Executable => "100755",
            Self::Symlink => "120000",
            Self::Gitlink => "160000",
            Self::Tree => "40000",
        }
    }

    /// Parses a stored mode. The historical group-writable `100664` reads
    /// as regular and a zero-padded `040000` as a tree, as Git reads them.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        Some(match bytes {
            b"100644" | b"100664" => Self::Regular,
            b"100755" => Self::Executable,
            b"120000" => Self::Symlink,
            b"160000" => Self::Gitlink,
            b"40000" | b"040000" => Self::Tree,
            _ => return None,
        })
    }

    /// Whether this entry names a subtree.
    #[must_use]
    pub(crate) const fn is_tree(self) -> bool {
        matches!(self, Self::Tree)
    }

    /// The index mode for a blob/commit entry. Directories never reach
    /// index rows; calling this on `Tree` is an internal error.
    pub(crate) fn as_index_mode(self) -> Result<FileMode, GitError> {
        match self {
            Self::Regular => Ok(FileMode::Regular),
            Self::Executable => Ok(FileMode::Executable),
            Self::Symlink => Ok(FileMode::Symlink),
            Self::Gitlink => Ok(FileMode::Gitlink),
            Self::Tree => Err(GitError::Invalid {
                detail: "tree directory has no index mode".to_owned(),
            }),
        }
    }
}

impl From<FileMode> for TreeMode {
    fn from(mode: FileMode) -> Self {
        match mode {
            FileMode::Regular => Self::Regular,
            FileMode::Executable => Self::Executable,
            FileMode::Symlink => Self::Symlink,
            FileMode::Gitlink => Self::Gitlink,
        }
    }
}

/// One parsed tree entry in stored order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeEntry {
    /// Entry mode.
    pub(crate) mode: TreeMode,
    /// Entry name bytes (no `/`, no NUL).
    pub(crate) name: Vec<u8>,
    /// Entry target: blob/tree oid, or a commit oid for a gitlink.
    pub(crate) oid: Oid,
}

/// Parses one canonical tree body of this repository's hash kind.
pub(crate) fn parse_tree(kind: HashKind, bytes: &[u8]) -> Result<Vec<TreeEntry>, GitError> {
    let width = kind_width(kind);
    let mut entries = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let space =
            rest.iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(|| GitError::Invalid {
                    detail: "tree entry has no mode terminator".to_owned(),
                })?;
        let mode_text = rest[..space]
            .iter()
            .map(|byte| *byte as char)
            .collect::<String>();
        let mode = TreeMode::parse(&rest[..space]).ok_or_else(|| GitError::Invalid {
            detail: format!("tree entry has bad mode {mode_text:?}"),
        })?;
        rest = &rest[space + 1..];
        let nul = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| GitError::Invalid {
                detail: "tree entry has no name terminator".to_owned(),
            })?;
        let name = rest[..nul].to_vec();
        if name.is_empty() || name.contains(&b'/') {
            return Err(GitError::Invalid {
                detail: "tree entry has an empty or nested name".to_owned(),
            });
        }
        rest = &rest[nul + 1..];
        if rest.len() < width {
            return Err(GitError::Invalid {
                detail: "tree entry is truncated".to_owned(),
            });
        }
        let oid = Oid::from_bytes(&rest[..width]).map_err(|err| GitError::Invalid {
            detail: format!("tree entry has a bad object id: {err}"),
        })?;
        if oid.kind() != kind {
            return Err(GitError::ObjectFormat {
                detail: "tree entry id width disagrees with the repository".to_owned(),
            });
        }
        rest = &rest[width..];
        entries.push(TreeEntry { mode, name, oid });
    }
    Ok(entries)
}

/// Raw id width in bytes for one hash kind.
fn kind_width(kind: HashKind) -> usize {
    match kind {
        HashKind::Sha1 => 20,
        HashKind::Sha256 => 32,
    }
}

/// Builds the canonical body for already-sorted entries.
pub(crate) fn encode_tree(entries: &[TreeEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(entry.mode.spelling().as_bytes());
        out.push(b' ');
        out.extend_from_slice(&entry.name);
        out.push(0);
        out.extend_from_slice(entry.oid.as_bytes());
    }
    out
}

/// Builds and publishes the tree for stage-zero `rows`, bottom-up.
///
/// `rows` holds `(full path bytes, entry)` pairs; intermediate subtrees are
/// published in the one transaction with the root, so a tree never names a
/// missing subtree.
pub(crate) fn build_index_tree(
    store: &Store,
    kind: HashKind,
    rows: &[(Vec<u8>, IndexEntry)],
) -> Result<Oid, GitError> {
    let mut by_dir: BTreeMap<Vec<u8>, Vec<(Vec<u8>, FileMode, Oid)>> = BTreeMap::new();
    for (path, entry) in rows {
        entry
            .validate(kind)
            .map_err(|err| GitError::from(core_error_of(err)))?;
        let (dir, file) = split_parent(path);
        by_dir
            .entry(dir)
            .or_default()
            .push((file, entry.mode(), entry.oid()));
    }
    let mut published = Vec::new();
    let root = build_dir(store, kind, &by_dir, &[], &mut published)?;
    store.publish(published, &[]).map_err(GitError::from)?;
    Ok(root)
}

/// Builds one directory level, recursing into subdirectories first.
fn build_dir(
    store: &Store,
    kind: HashKind,
    by_dir: &BTreeMap<Vec<u8>, Vec<(Vec<u8>, FileMode, Oid)>>,
    dir: &[u8],
    published: &mut Vec<ruk_core::store::PreparedObject>,
) -> Result<Oid, GitError> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut subdirs: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    if let Some(files) = by_dir.get(dir) {
        for (file, mode, oid) in files {
            entries.push(TreeEntry {
                mode: TreeMode::from(*mode),
                name: file.clone(),
                oid: *oid,
            });
        }
    }
    for key in by_dir.keys() {
        if let Some(child) = direct_child(dir, key) {
            subdirs.insert(child, true);
        }
    }
    for entry in entries.iter() {
        if subdirs.contains_key(&entry.name) {
            return Err(GitError::Invalid {
                detail: "path is both a file and a directory".to_owned(),
            });
        }
    }
    for child in subdirs.keys() {
        let mut full = dir.to_vec();
        if !full.is_empty() {
            full.push(b'/');
        }
        full.extend_from_slice(child);
        let oid = build_dir(store, kind, by_dir, &full, published)?;
        entries.push(TreeEntry {
            mode: TreeMode::Tree,
            name: child.clone(),
            oid,
        });
    }
    entries.sort_by(tree_order);
    let body = encode_tree(&entries);
    let body_len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "tree body exceeds the length range".to_owned(),
    })?;
    let prepared = store
        .prepare(ObjectKind::Tree, body_len, std::io::Cursor::new(body), None)
        .map_err(GitError::from)?;
    let oid = prepared.oid();
    published.push(prepared);
    Ok(oid)
}

/// Git tree order: names compared bytewise with directories as `name/`.
fn tree_order(left: &TreeEntry, right: &TreeEntry) -> std::cmp::Ordering {
    let mut left_key = left.name.clone();
    let mut right_key = right.name.clone();
    if left.mode.is_tree() {
        left_key.push(b'/');
    }
    if right.mode.is_tree() {
        right_key.push(b'/');
    }
    left_key.cmp(&right_key)
}

/// Splits a full path into its parent directory and file name.
fn split_parent(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => (path[..index].to_vec(), path[index + 1..].to_vec()),
        None => (Vec::new(), path.to_vec()),
    }
}

/// Names the direct child of `dir` that `key` names or lives under.
///
/// Every `by_dir` key is a directory: the key itself is a child when it sits
/// directly below `dir`, and a longer key contributes its first component.
fn direct_child(dir: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if key == dir {
        return None;
    }
    let rest = if dir.is_empty() {
        key
    } else {
        key.strip_prefix(dir)?.strip_prefix(b"/")?
    };
    if rest.is_empty() {
        return None;
    }
    match rest.iter().position(|byte| *byte == b'/') {
        Some(index) => Some(rest[..index].to_vec()),
        None => Some(rest.to_vec()),
    }
}

/// Maps a model failure into the interpreter error space.
fn core_error_of(err: ruk_core::error::CoreModelError) -> ruk_core::error::CoreError {
    ruk_core::error::CoreError::from(err)
}

/// Builds the canonical commit payload `commit-tree` and `commit` store.
pub(crate) fn commit_payload(
    tree_hex: &str,
    parents: &[String],
    author: &Signature,
    committer: &Signature,
    message: &[u8],
) -> Vec<u8> {
    let mut out = format!("tree {tree_hex}\n").into_bytes();
    for parent in parents {
        out.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    out.extend_from_slice(b"author ");
    out.extend_from_slice(&author.render());
    out.push(b'\n');
    out.extend_from_slice(b"committer ");
    out.extend_from_slice(&committer.render());
    out.push(b'\n');
    out.push(b'\n');
    out.extend_from_slice(message);
    out
}

/// Builds the canonical annotated-tag payload `tag` stores.
pub(crate) fn tag_payload(
    object_hex: &str,
    object_type: &str,
    tag: &str,
    tagger: Option<&Signature>,
    message: &[u8],
) -> Vec<u8> {
    let mut out = format!("object {object_hex}\ntype {object_type}\ntag {tag}\n").into_bytes();
    if let Some(tagger) = tagger {
        out.extend_from_slice(b"tagger ");
        out.extend_from_slice(&tagger.render());
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(message);
    out
}

/// Stores one prepared Git object body and publishes it alone.
pub(crate) fn store_object(
    store: &Store,
    kind: ObjectKind,
    body: Vec<u8>,
) -> Result<Oid, GitError> {
    let body_len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "object body exceeds the length range".to_owned(),
    })?;
    let prepared = store
        .prepare(kind, body_len, std::io::Cursor::new(body), None)
        .map_err(GitError::from)?;
    let oid = prepared.oid();
    store.publish(vec![prepared], &[]).map_err(GitError::from)?;
    Ok(oid)
}

/// Reads one object body through the transport's bounded reader.
pub(crate) fn read_object_bytes(
    store: &Store,
    oid: Oid,
) -> Result<(ObjectKind, Vec<u8>), GitError> {
    ruk_git::transport::read_object(store, oid, super::state::MAX_OBJECT_BYTES)
}

/// Reads every byte of a worktree path relative to a base.
///
/// Rejects absolute paths and escapes above the base before touching disk.
pub(crate) fn read_worktree_file(base: &std::path::Path, path: &[u8]) -> Result<Vec<u8>, GitError> {
    let relative = join_base(base, path)?;
    std::fs::read(&relative).map_err(|err| GitError::Io {
        detail: format!("reading {}: {err}", relative.display()),
    })
}

/// Joins untrusted path bytes onto `base`, refusing escapes.
pub(crate) fn join_base(
    base: &std::path::Path,
    path: &[u8],
) -> Result<std::path::PathBuf, GitError> {
    let text = std::str::from_utf8(path).map_err(|_| GitError::Invalid {
        detail: "path is not valid UTF-8 for worktree access".to_owned(),
    })?;
    let candidate = std::path::Path::new(text);
    if candidate.is_absolute() || text.is_empty() {
        return Err(GitError::Invalid {
            detail: format!("bad worktree path {text:?}"),
        });
    }
    let mut joined = base.to_path_buf();
    for component in candidate.components() {
        match component {
            std::path::Component::Normal(part) => joined.push(part),
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad worktree path {text:?}"),
                });
            }
        }
    }
    Ok(joined)
}

/// One worktree entry found by a recursive walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorktreeEntry {
    /// Bytes relative to the walk base, `/`-separated.
    pub(crate) path: Vec<u8>,
    /// File or symlink; directories recurse and are never returned.
    pub(crate) file_type: WorktreeType,
}

/// Whether a walked entry is a file or a symlink. A named type, never a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorktreeType {
    /// Regular content bytes.
    File,
    /// Link target bytes.
    Symlink,
}

/// Walks `base` recursively, skipping the `.ruk` metadata directory.
pub(crate) fn walk_worktree(base: &std::path::Path) -> Result<Vec<WorktreeEntry>, GitError> {
    let mut out = Vec::new();
    walk_dir(base, base, &mut out)?;
    out.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(out)
}

/// Recurses one directory level of a worktree walk.
fn walk_dir(
    base: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<WorktreeEntry>,
) -> Result<(), GitError> {
    let entries = std::fs::read_dir(dir).map_err(|err| GitError::Io {
        detail: format!("listing {}: {err}", dir.display()),
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| GitError::Io {
            detail: format!("listing {}: {err}", dir.display()),
        })?;
        let name = entry.file_name();
        if dir == base && name == ".ruk" {
            continue;
        }
        let file_type = entry.file_type().map_err(|err| GitError::Io {
            detail: format!("statting {}: {err}", entry.path().display()),
        })?;
        if file_type.is_dir() {
            walk_dir(base, &entry.path(), out)?;
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(base)
            .map_err(|_| GitError::Io {
                detail: "worktree path escapes its base".to_owned(),
            })?
            .to_path_buf();
        let path = relative
            .to_str()
            .ok_or_else(|| GitError::Invalid {
                detail: "worktree path is not valid UTF-8".to_owned(),
            })?
            .as_bytes()
            .to_vec();
        if file_type.is_symlink() {
            out.push(WorktreeEntry {
                path,
                file_type: WorktreeType::Symlink,
            });
        } else if file_type.is_file() {
            out.push(WorktreeEntry {
                path,
                file_type: WorktreeType::File,
            });
        }
    }
    Ok(())
}

/// Flattens one stored tree to `(path, mode, oid)` rows, recursing.
///
/// Gitlinks stay as commit entries without existence checks, as `ls-tree`
/// reports them.
pub(crate) fn flatten_tree(
    store: &Store,
    kind: HashKind,
    oid: Oid,
) -> Result<Vec<(Vec<u8>, TreeMode, Oid)>, GitError> {
    let mut out = Vec::new();
    flatten_dir(store, kind, oid, &[], &mut out)?;
    Ok(out)
}

/// Flattens one directory level of a stored tree.
fn flatten_dir(
    store: &Store,
    kind: HashKind,
    oid: Oid,
    prefix: &[u8],
    out: &mut Vec<(Vec<u8>, TreeMode, Oid)>,
) -> Result<(), GitError> {
    let (object_kind, body) = read_object_bytes(store, oid)?;
    if object_kind != ObjectKind::Tree {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a tree", oid.to_hex()),
        });
    }
    for entry in parse_tree(kind, &body)? {
        let mut full = prefix.to_vec();
        if !full.is_empty() {
            full.push(b'/');
        }
        full.extend_from_slice(&entry.name);
        if entry.mode.is_tree() {
            flatten_dir(store, kind, entry.oid, &full, out)?;
        } else {
            out.push((full, entry.mode, entry.oid));
        }
    }
    Ok(())
}

/// Peels any tree-ish object id to its tree: trees pass through, commits
/// resolve to their recorded tree.
pub(crate) fn peel_to_tree(store: &Store, kind: HashKind, oid: Oid) -> Result<Oid, GitError> {
    let (object_kind, body) = read_object_bytes(store, oid)?;
    match object_kind {
        ObjectKind::Tree => Ok(oid),
        ObjectKind::Commit => {
            let line_end = body
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(body.len());
            let first = &body[..line_end];
            let hex = first
                .strip_prefix(b"tree ")
                .ok_or_else(|| GitError::Invalid {
                    detail: format!("commit {} has no tree line", oid.to_hex()),
                })?;
            let hex_text = std::str::from_utf8(hex).map_err(|_| GitError::Invalid {
                detail: format!("commit {} has a non-UTF-8 tree line", oid.to_hex()),
            })?;
            let tree = Oid::from_hex(hex_text).map_err(|err| GitError::Invalid {
                detail: format!("commit {} has a bad tree id: {err}", oid.to_hex()),
            })?;
            if tree.kind() != kind {
                return Err(GitError::ObjectFormat {
                    detail: "commit tree width disagrees with the repository".to_owned(),
                });
            }
            Ok(tree)
        }
        _ => Err(GitError::Invalid {
            detail: format!("object {} is not a tree-ish object", oid.to_hex()),
        }),
    }
}

/// Reads the tree recorded by one commit: the `tree` header of a Git
/// payload, else the native record's resolved tree.
pub(crate) fn commit_tree_oid(record: &ruk_core::commit::CommitRecord) -> Result<Oid, GitError> {
    if let Some(payload) = record.git_payload() {
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len());
        let first = &payload[..line_end];
        let hex = first
            .strip_prefix(b"tree ")
            .ok_or_else(|| GitError::Invalid {
                detail: "commit payload has no tree line".to_owned(),
            })?;
        let hex_text = std::str::from_utf8(hex).map_err(|_| GitError::Invalid {
            detail: "commit tree line is not valid UTF-8".to_owned(),
        })?;
        return Oid::from_hex(hex_text).map_err(|err| GitError::Invalid {
            detail: format!("commit tree id is bad: {err}"),
        });
    }
    record
        .tree()
        .as_resolved()
        .copied()
        .ok_or_else(|| GitError::Invalid {
            detail: "conflicted commit has no single tree".to_owned(),
        })
}

/// Streams one reader into a bounded buffer for hash-object and friends.
pub(crate) fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>, GitError> {
    let mut limited = reader.take(limit + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).map_err(|err| GitError::Io {
        detail: format!("reading input: {err}"),
    })?;
    if u64::try_from(buf.len()).map_or(true, |len| len > limit) {
        return Err(GitError::Limit {
            detail: format!("input exceeds {limit} bytes"),
        });
    }
    Ok(buf)
}
