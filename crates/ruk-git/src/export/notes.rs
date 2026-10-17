//! Typed Git notes on the export side: `refs/notes/*` as commit-to-note edges.
//!
//! The export packer already carries every notes ref and object through the
//! generic closure, so notes bytes and OIDs arrive intact. This module is
//! the typed check on that path: it reads a stored notes commit's fanout
//! tree and reports the same edges the import side records. Path shards of
//! two characters are encoding detail; the walk concatenates every
//! component before parsing the annotated identity, and the note tree
//! itself is the contract. Byte-identical to the sibling
//! `crate::import::notes` in prefix, edge shape, and walk semantics.

use std::collections::BTreeMap;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::Store;
use ruk_core::store::types::ObjectKind;

use crate::GitError;

/// The ref prefix that marks a notes namespace, with its trailing slash.
///
/// Byte-identical to the sibling `crate::import::notes::NOTES_PREFIX`.
pub const NOTES_PREFIX: &[u8] = b"refs/notes/";

/// Whether `name` lives under the notes prefix.
#[must_use]
pub fn is_notes_ref(name: &RefName) -> bool {
    starts_with(name.as_bytes(), NOTES_PREFIX)
}

/// One annotated object and the blob that annotates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoteEdge {
    /// The annotated object's identity.
    pub target: Oid,
    /// The note blob's identity.
    pub note: Oid,
}

/// One notes namespace: its ref, its notes commit, and its edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotesNamespace {
    /// The full notes ref name, such as `refs/notes/commits`.
    pub name: RefName,
    /// The notes commit the ref points to.
    pub commit: Oid,
    /// Every commit-to-note edge, ordered by target.
    pub edges: Vec<NoteEdge>,
}

impl NotesNamespace {
    /// The notes ref name.
    #[must_use]
    pub fn name(&self) -> &RefName {
        &self.name
    }

    /// The notes commit.
    #[must_use]
    pub fn commit(&self) -> Oid {
        self.commit
    }

    /// Every edge, ordered by target.
    #[must_use]
    pub fn edges(&self) -> &[NoteEdge] {
        &self.edges
    }

    /// How many notes the namespace holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the namespace holds no notes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// The note blob for `target`, when the namespace annotates it.
    #[must_use]
    pub fn find(&self, target: Oid) -> Option<Oid> {
        self.edges
            .iter()
            .find(|edge| edge.target == target)
            .map(|edge| edge.note)
    }
}

/// Every direct notes ref in `entries` with its commit OID.
#[must_use]
pub fn notes_targets(entries: &[(RefName, RefTarget)]) -> Vec<(RefName, Oid)> {
    let mut out = Vec::new();
    for (name, target) in entries {
        if !is_notes_ref(name) {
            continue;
        }
        if let RefTarget::Direct(oid) = target {
            out.push((name.clone(), *oid));
        }
    }
    out
}

/// Loads one notes namespace from the store.
///
/// # Errors
/// [`GitError::NotFound`] for a promisor-omitted object,
/// [`GitError::Corrupt`] for a non-commit ref target, a malformed commit or
/// tree, a non-hex note path, or a duplicate target.
pub fn load_notes_namespace(
    store: &Store,
    name: &RefName,
    commit: Oid,
) -> Result<NotesNamespace, GitError> {
    let tree = commit_tree(store, commit)?;
    let table = walk_notes_tree(store, tree)?;
    Ok(NotesNamespace {
        name: name.clone(),
        commit,
        edges: table
            .into_iter()
            .map(|(target, note)| NoteEdge { target, note })
            .collect(),
    })
}

/// Loads every namespace in `pairs`, which the caller filtered.
///
/// # Errors
/// As [`load_notes_namespace`].
pub fn load_all_notes(
    store: &Store,
    pairs: &[(RefName, Oid)],
) -> Result<Vec<NotesNamespace>, GitError> {
    let mut out = Vec::with_capacity(pairs.len());
    for (name, commit) in pairs {
        out.push(load_notes_namespace(store, name, *commit)?);
    }
    Ok(out)
}

/// Largest object pulled through a notes walk.
const WALK_OBJECT_BYTES: u64 = 512 << 20;

/// Reads the tree a stored notes commit names.
fn commit_tree(store: &Store, commit: Oid) -> Result<Oid, GitError> {
    let (kind, bytes) = super::super::transport::read_object(store, commit, WALK_OBJECT_BYTES)?;
    if kind != ObjectKind::Commit {
        return Err(GitError::Corrupt {
            detail: format!("notes ref targets non-commit object {commit}"),
        });
    }
    let header = super::objects::parse_commit(commit, &bytes, store.hash_kind())?;
    Ok(header.tree)
}

/// Walks one stored notes tree iteratively, joining every path component.
fn walk_notes_tree(store: &Store, root: Oid) -> Result<BTreeMap<Oid, Oid>, GitError> {
    let kind = store.hash_kind();
    let mut edges = BTreeMap::new();
    let mut stack: Vec<(Oid, Vec<u8>)> = vec![(root, Vec::new())];
    while let Some((tree, prefix)) = stack.pop() {
        for (name, oid, entry_kind) in read_tree_entries(store, tree, kind)? {
            if entry_kind == ObjectKind::Tree {
                let mut child = prefix.clone();
                child.extend_from_slice(&name);
                stack.push((oid, child));
                continue;
            }
            if entry_kind != ObjectKind::Blob {
                return Err(GitError::Corrupt {
                    detail: format!("notes tree {tree} holds a non-blob note entry"),
                });
            }
            let mut full = prefix.clone();
            full.extend_from_slice(&name);
            let target = parse_target_hex(&full, tree, kind)?;
            if edges.insert(target, oid).is_some() {
                return Err(GitError::Corrupt {
                    detail: format!("notes tree {tree} annotates {target} twice"),
                });
            }
        }
    }
    Ok(edges)
}

/// Reads one stored tree's named entries, skipping gitlinks.
fn read_tree_entries(
    store: &Store,
    tree: Oid,
    kind: HashKind,
) -> Result<Vec<(Vec<u8>, Oid, ObjectKind)>, GitError> {
    let (found, bytes) = super::super::transport::read_object(store, tree, WALK_OBJECT_BYTES)?;
    if found != ObjectKind::Tree {
        return Err(GitError::Corrupt {
            detail: format!("notes path reaches non-tree object {tree}"),
        });
    }
    parse_entries(&bytes, tree, kind)
}

/// Parses raw tree bytes into named entries.
fn parse_entries(
    bytes: &[u8],
    tree: Oid,
    kind: HashKind,
) -> Result<Vec<(Vec<u8>, Oid, ObjectKind)>, GitError> {
    let hash_len = kind.oid_len();
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let entry = parse_entry(rest, tree, kind, hash_len)?;
        rest = entry.rest;
        if let Some(named) = entry.named {
            out.push(named);
        }
    }
    Ok(out)
}

/// One parsed tree entry with its remainder.
struct ParsedEntry<'a> {
    /// Bytes after this entry.
    rest: &'a [u8],
    /// The entry, absent for a skipped gitlink.
    named: Option<(Vec<u8>, Oid, ObjectKind)>,
}

/// Parses the first entry of `rest`.
fn parse_entry(
    rest: &[u8],
    tree: Oid,
    kind: HashKind,
    hash_len: usize,
) -> Result<ParsedEntry<'_>, GitError> {
    let space = rest
        .iter()
        .position(|b| *b == b' ')
        .ok_or_else(|| GitError::Corrupt {
            detail: format!("notes tree {tree} holds a malformed entry"),
        })?;
    let mode = parse_mode(&rest[..space], tree)?;
    let after_mode = rest.get(space + 1..).ok_or_else(|| GitError::Corrupt {
        detail: format!("notes tree {tree} holds a malformed entry"),
    })?;
    let nul = after_mode
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| GitError::Corrupt {
            detail: format!("notes tree {tree} holds a nameless entry"),
        })?;
    let after_name = after_mode.get(nul + 1..).ok_or_else(|| GitError::Corrupt {
        detail: format!("notes tree {tree} holds a truncated entry"),
    })?;
    if after_name.len() < hash_len {
        return Err(GitError::Corrupt {
            detail: format!("notes tree {tree} holds a truncated entry"),
        });
    }
    let oid = Oid::from_bytes(&after_name[..hash_len]).map_err(|_| GitError::Corrupt {
        detail: format!("notes tree {tree} holds an entry with a bad OID"),
    })?;
    if oid.kind() != kind {
        return Err(GitError::Corrupt {
            detail: format!("notes tree {tree} holds an entry of the wrong width"),
        });
    }
    let next = after_name
        .get(hash_len..)
        .ok_or_else(|| GitError::Corrupt {
            detail: format!("notes tree {tree} holds a truncated entry"),
        })?;
    if mode == 0o160000 {
        return Ok(ParsedEntry {
            rest: next,
            named: None,
        });
    }
    let entry_kind = if mode == 0o040000 {
        ObjectKind::Tree
    } else {
        ObjectKind::Blob
    };
    Ok(ParsedEntry {
        rest: next,
        named: Some((after_mode[..nul].to_vec(), oid, entry_kind)),
    })
}

/// Parses an octal tree-entry mode.
fn parse_mode(digits: &[u8], tree: Oid) -> Result<u32, GitError> {
    if digits.is_empty() || digits.iter().any(|b| !b.is_ascii_digit() || *b > b'7') {
        return Err(GitError::Corrupt {
            detail: format!("notes tree {tree} holds a non-octal mode"),
        });
    }
    Ok(digits.iter().fold(0u32, |acc, b| {
        acc.saturating_mul(8).saturating_add(u32::from(b - b'0'))
    }))
}

/// Parses one concatenated notes path as the annotated identity.
fn parse_target_hex(path: &[u8], tree: Oid, kind: HashKind) -> Result<Oid, GitError> {
    let text = core::str::from_utf8(path).map_err(|_| GitError::Corrupt {
        detail: format!("notes tree {tree} holds a non-UTF-8 note path"),
    })?;
    crate::parse_oid_for(text, kind).map_err(|_| GitError::Corrupt {
        detail: format!("notes tree {tree} holds a non-hex note path"),
    })
}

/// Byte-prefix comparison without allocating.
fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()] == *prefix
}
