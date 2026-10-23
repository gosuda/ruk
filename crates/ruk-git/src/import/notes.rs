//! Typed Git notes: `refs/notes/*` as commit-to-note edges.
//!
//! Notes refs already flow through the generic ref and object path, so every
//! notes byte and OID is preserved exactly. This module adds the typed view:
//! a notes namespace is the direct ref plus the fanout tree its commit
//! names. Each note is one blob entry whose full path is the annotated
//! object's hex identity; the 2-character shard directories are encoding
//! detail, so the walk concatenates every path component before parsing the
//! target. The note tree itself is the contract: import records the edges
//! without rewriting any OID, and export must emit the identical tree.

use std::collections::BTreeMap;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::ObjectKind;

use super::objects::SourceObjects;
use super::refs::SourceRefs;
use crate::GitError;

/// The ref prefix that marks a notes namespace, with its trailing slash.
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

/// Every direct notes ref in `refs` with its commit OID.
#[must_use]
pub fn notes_refs(refs: &SourceRefs) -> Vec<(RefName, Oid)> {
    let mut out = Vec::new();
    for candidate in &refs.refs {
        if !is_notes_ref(&candidate.name) {
            continue;
        }
        if let RefTarget::Direct(oid) = candidate.target {
            out.push((candidate.name.clone(), oid));
        }
    }
    out
}

/// Loads one notes namespace from the source object database.
///
/// # Errors
/// [`GitError::NotFound`] for a missing notes commit or tree,
/// [`GitError::Corrupt`] for a non-commit ref target, a malformed commit or
/// tree, a non-hex note path, or a duplicate target.
pub fn load_notes_namespace(
    source: &SourceObjects,
    name: &RefName,
    commit: Oid,
) -> Result<NotesNamespace, GitError> {
    let kind = source.hash_kind();
    let tree = commit_tree(source, commit, kind)?;
    let table = walk_notes_tree(source, tree, kind)?;
    Ok(NotesNamespace {
        name: name.clone(),
        commit,
        edges: table
            .into_iter()
            .map(|(target, note)| NoteEdge { target, note })
            .collect(),
    })
}

/// Loads every direct notes namespace in `refs`.
///
/// # Errors
/// As [`load_notes_namespace`].
pub fn load_all_notes(
    source: &SourceObjects,
    refs: &SourceRefs,
) -> Result<Vec<NotesNamespace>, GitError> {
    let mut out = Vec::with_capacity(refs.refs.len());
    for (name, commit) in notes_refs(refs) {
        out.push(load_notes_namespace(source, &name, commit)?);
    }
    Ok(out)
}

/// Reads the tree a notes commit names.
fn commit_tree(source: &SourceObjects, commit: Oid, kind: HashKind) -> Result<Oid, GitError> {
    let object = source.read_in_memory(commit)?;
    if object.kind != ObjectKind::Commit {
        return Err(GitError::Corrupt {
            detail: format!("notes ref targets non-commit object {commit}"),
        });
    }
    let parsed = gix_object::CommitRef::from_bytes(&object.payload, kind.gix()).map_err(|err| {
        GitError::Corrupt {
            detail: format!("notes commit {commit} does not parse: {err}"),
        }
    })?;
    let hex = parsed.tree().to_hex().to_string();
    crate::parse_oid_for(hex.as_str(), kind)
}

/// Walks one notes tree iteratively, joining every path component.
fn walk_notes_tree(
    source: &SourceObjects,
    root: Oid,
    kind: HashKind,
) -> Result<BTreeMap<Oid, Oid>, GitError> {
    let mut edges = BTreeMap::new();
    let mut stack: Vec<(Oid, Vec<u8>)> = vec![(root, Vec::new())];
    while let Some((tree, prefix)) = stack.pop() {
        for (name, oid, entry_kind) in read_tree_entries(source, tree, kind)? {
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

/// Reads one tree's named entries, skipping gitlinks like every other walk.
fn read_tree_entries(
    source: &SourceObjects,
    tree: Oid,
    kind: HashKind,
) -> Result<Vec<(Vec<u8>, Oid, ObjectKind)>, GitError> {
    let object = source.read_in_memory(tree)?;
    if object.kind != ObjectKind::Tree {
        return Err(GitError::Corrupt {
            detail: format!("notes path reaches non-tree object {tree}"),
        });
    }
    parse_entries(&object.payload, tree, kind)
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
        rest = after_name
            .get(hash_len..)
            .ok_or_else(|| GitError::Corrupt {
                detail: format!("notes tree {tree} holds a truncated entry"),
            })?;
        if mode == 0o160000 {
            continue;
        }
        let entry_kind = if mode == 0o040000 {
            ObjectKind::Tree
        } else {
            ObjectKind::Blob
        };
        out.push((after_mode[..nul].to_vec(), oid, entry_kind));
    }
    Ok(out)
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

/// Parses one concatenated notes path as the annotated object's identity.
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

#[cfg(test)]
mod tests {
    use super::super::fixtures::Fixture;
    use super::*;

    fn notes_fixture() -> (Fixture, Oid, Oid, Oid) {
        let fixture = Fixture::sha1();
        let blob = fixture.blob(b"note body\n");
        let target_tree = fixture.loose("tree", b"");
        let (target_payload, target) = fixture.commit(target_tree, &[], b"", b"annotated\n");
        let _ = target_payload;
        let hex = target.to_hex();
        let (inner_payload, inner) = fixture.tree(&[(false, &hex.as_bytes()[2..], blob)]);
        let _ = inner_payload;
        let (root_payload, root) = fixture.tree(&[(true, &hex.as_bytes()[..2], inner)]);
        let _ = root_payload;
        let (notes_payload, notes) = fixture.commit(root, &[], b"", b"notes\n");
        let _ = notes_payload;
        fixture.write_ref("refs/notes/commits", notes);
        fixture.write_head("ref: refs/heads/main\n");
        (fixture, target, blob, notes)
    }

    #[test]
    fn notes_prefix_matches_namespaces_only() {
        let name = RefName::new(b"refs/notes/commits".to_vec()).expect("name");
        assert!(is_notes_ref(&name));
        let other = RefName::new(b"refs/heads/main".to_vec()).expect("name");
        assert!(!is_notes_ref(&other));
    }

    #[test]
    fn notes_namespace_loads_one_fanout_edge() {
        let (fixture, target, blob, notes) = notes_fixture();
        let source = SourceObjects::open(&fixture.git_dir, fixture.hash, 1 << 20).expect("source");
        let name = RefName::new(b"refs/notes/commits".to_vec()).expect("name");
        let namespace = load_notes_namespace(&source, &name, notes).expect("notes");
        assert_eq!(namespace.commit(), notes);
        assert_eq!(namespace.len(), 1);
        assert_eq!(namespace.find(target), Some(blob));
    }
}
