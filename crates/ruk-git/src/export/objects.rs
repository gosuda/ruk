//! The export closure: every object reachable from the exported roots,
//! read through [`Store::read`].
//!
//! Roots are walked one at a time into a tentative set that joins the
//! export only when the whole closure is Git: a root whose object is a
//! native `conflict-v1` record, or whose closure reaches one, is classified
//! native and contributes nothing, so a refused root never leaks part of
//! its closure into the pack. Objects already in the export are complete
//! closures and stop the walk.
//!
//! Commits stop at stored shallow boundaries (a `Shallow` row keyed by the
//! raw commit OID), which are then written to the export's `shallow` file.
//! Gitlinks name commits of another repository and are not followed. Blobs
//! are not read during the walk; the pack writer reads each one and checks
//! its kind.
//!
//! A missing object is never skipped: one with a `Promisor` row (keyed by
//! the raw OID) was omitted by a partial clone and fails with
//! [`GitError::NotFound`] so the caller fetches it first; any other missing
//! object is [`GitError::Corrupt`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::{FactTable, ObjectKind, Store, StoreError};
use serde::Serialize;

use crate::GitError;

/// Why a root is not exported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReason {
    /// The root itself is a native `conflict-v1` record.
    NativeRecord,
    /// The root is Git, but its closure reaches a native record (a native
    /// parent, or a tag whose target is native).
    NativeInClosure,
}

/// The kind a referencing object requires of an object it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// A ref or detached HEAD may name any Git object.
    Any,
    Kind(ObjectKind),
}

/// What walking one root decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootOutcome {
    /// The closure is in the export. `peeled` is the first non-tag object
    /// when the root is an annotated tag.
    Exported { peeled: Option<Oid> },
    /// Nothing of this root was exported; `oid` is the native object found.
    Native { reason: NativeReason, oid: Oid },
}

/// The accumulated export closure.
#[derive(Debug)]
pub(crate) struct Closure<'s> {
    store: &'s Store,
    kind: HashKind,
    included: BTreeMap<Oid, ObjectKind>,
    shallow: BTreeSet<Oid>,
}

impl<'s> Closure<'s> {
    pub(crate) fn new(store: &'s Store) -> Self {
        Self {
            store,
            kind: store.hash_kind(),
            included: BTreeMap::new(),
            shallow: BTreeSet::new(),
        }
    }

    /// Every exported object and its kind, sorted by id.
    pub(crate) fn objects(&self) -> &BTreeMap<Oid, ObjectKind> {
        &self.included
    }

    /// Shallow boundary commits inside the closure.
    pub(crate) fn shallow(&self) -> &BTreeSet<Oid> {
        &self.shallow
    }

    /// Adds `root`'s closure when it is entirely Git.
    ///
    /// # Errors
    /// [`GitError::NotFound`] for a promisor-omitted object,
    /// [`GitError::Corrupt`] for a missing or malformed object or a kind
    /// that contradicts its referrer, and store failures.
    pub(crate) fn add_root(&mut self, root: Oid) -> Result<RootOutcome, GitError> {
        crate::require_kind(root, self.kind)?;
        if !self.included.contains_key(&root)
            && let Some(native) = self.walk(root)?
        {
            let reason = if native == root {
                NativeReason::NativeRecord
            } else {
                NativeReason::NativeInClosure
            };
            return Ok(RootOutcome::Native {
                reason,
                oid: native,
            });
        }
        Ok(RootOutcome::Exported {
            peeled: self.peel(root)?,
        })
    }

    /// Walks `root` into a tentative set and merges it on success. Returns
    /// the first native record found instead, merging nothing. Every kind
    /// comes from the object metadata, so blobs are classified without
    /// reading their payload; only commit, tree, and tag payloads are read.
    fn walk(&mut self, root: Oid) -> Result<Option<Oid>, GitError> {
        let mut tentative: BTreeMap<Oid, ObjectKind> = BTreeMap::new();
        let mut boundaries = Vec::new();
        let mut pending = vec![(root, Expect::Any)];
        while let Some((oid, expect)) = pending.pop() {
            if let Some(&known) = self.included.get(&oid).or_else(|| tentative.get(&oid)) {
                check_expect(oid, known, expect)?;
                continue;
            }
            let object = read_object(self.store, oid)?;
            let kind = object.kind;
            if kind == ObjectKind::Conflict {
                return Ok(Some(oid));
            }
            check_expect(oid, kind, expect)?;
            match kind {
                ObjectKind::Blob => {}
                ObjectKind::Commit => {
                    let bytes = drain(object.bytes)?;
                    let header = parse_commit(oid, &bytes, self.kind)?;
                    pending.push((header.tree, Expect::Kind(ObjectKind::Tree)));
                    if self
                        .store
                        .fact(FactTable::Shallow, oid.as_bytes())?
                        .is_some()
                    {
                        boundaries.push(oid);
                    } else {
                        pending.extend(
                            header
                                .parents
                                .into_iter()
                                .map(|parent| (parent, Expect::Kind(ObjectKind::Commit))),
                        );
                    }
                }
                ObjectKind::Tree => {
                    let bytes = drain(object.bytes)?;

                    pending.extend(parse_tree(oid, &bytes, self.kind)?);
                }
                ObjectKind::Tag => {
                    let bytes = drain(object.bytes)?;
                    let (target, target_kind) = parse_tag(oid, &bytes, self.kind)?;
                    pending.push((target, Expect::Kind(target_kind)));
                }
                ObjectKind::Conflict => {}
            }
            tentative.insert(oid, kind);
        }

        self.included.append(&mut tentative);
        self.shallow.extend(boundaries);
        Ok(None)
    }

    /// The first non-tag object behind an annotated tag root. Every tag in
    /// the chain is in the closure, so the chain is at most that long.
    fn peel(&self, root: Oid) -> Result<Option<Oid>, GitError> {
        let mut current = root;
        let mut peeled = None;
        for _ in 0..self.included.len() {
            if self.included.get(&current) != Some(&ObjectKind::Tag) {
                return Ok(peeled);
            }
            let bytes = self.read_tag(current)?;
            let (target, _) = parse_tag(current, &bytes, self.kind)?;
            current = target;
            peeled = Some(target);
        }
        Err(GitError::Corrupt {
            detail: format!("tag chain from {root} does not end"),
        })
    }

    /// Reads a tag payload for peeling.
    fn read_tag(&self, oid: Oid) -> Result<Vec<u8>, GitError> {
        let object = read_object(self.store, oid)?;
        drain(object.bytes)
    }
}

/// Reads one object, classifying a missing one as promisor-omitted or
/// corrupt.
///
/// # Errors
/// See the module docs.
pub(crate) fn read_object(
    store: &Store,
    oid: Oid,
) -> Result<ruk_core::store::ReadObject, GitError> {
    match store.read(oid) {
        Ok(object) => Ok(object),
        Err(StoreError::NotFound(_)) => Err(missing(store, oid)?),
        Err(err) => Err(err.into()),
    }
}

/// Reads a spool fully into memory. Structural payloads (commits, trees,
/// tags) are bounded by the store's own admission; blobs never come here.
fn drain(mut spool: ruk_core::store::Spool) -> Result<Vec<u8>, GitError> {
    let mut bytes = Vec::new();
    spool
        .read_to_end(&mut bytes)
        .map_err(super::pack::io_error)?;
    Ok(bytes)
}

fn missing(store: &Store, oid: Oid) -> Result<GitError, GitError> {
    if store.fact(FactTable::Promisor, oid.as_bytes())?.is_some() {
        return Ok(GitError::NotFound {
            detail: format!(
                "object {oid} was omitted by a partial clone; fetch the missing closure before export"
            ),
        });
    }
    Ok(GitError::Corrupt {
        detail: format!("reachable object {oid} is missing from the store"),
    })
}

fn check_expect(oid: Oid, actual: ObjectKind, expect: Expect) -> Result<(), GitError> {
    match expect {
        Expect::Kind(wanted) if wanted != actual => Err(GitError::Corrupt {
            detail: format!("object {oid} is a {actual:?} where a {wanted:?} is referenced"),
        }),
        Expect::Any | Expect::Kind(_) => Ok(()),
    }
}

/// The structural part of a commit header.
#[derive(Debug)]
pub(crate) struct CommitHeader {
    pub(crate) tree: Oid,
    pub(crate) parents: Vec<Oid>,
}

/// Reads `tree` then every `parent` line; the rest of the commit is opaque
/// and preserved byte-for-byte by the pack.
pub(crate) fn parse_commit(
    oid: Oid,
    bytes: &[u8],
    kind: HashKind,
) -> Result<CommitHeader, GitError> {
    let mut lines = bytes.split(|&b| b == b'\n');
    let tree = lines
        .next()
        .and_then(|line| line.strip_prefix(b"tree "))
        .ok_or_else(|| malformed(oid, "commit does not start with a tree line"))?;
    let tree = header_oid(oid, tree, kind)?;
    let mut parents = Vec::new();
    for line in lines {
        let Some(hex) = line.strip_prefix(b"parent ") else {
            break;
        };
        parents.push(header_oid(oid, hex, kind)?);
    }
    Ok(CommitHeader { tree, parents })
}

/// Reads a tag's `object` and `type` lines.
pub(crate) fn parse_tag(
    oid: Oid,
    bytes: &[u8],
    kind: HashKind,
) -> Result<(Oid, ObjectKind), GitError> {
    let mut lines = bytes.split(|&b| b == b'\n');
    let target = lines
        .next()
        .and_then(|line| line.strip_prefix(b"object "))
        .ok_or_else(|| malformed(oid, "tag does not start with an object line"))?;
    let target = header_oid(oid, target, kind)?;
    let type_name = lines
        .next()
        .and_then(|line| line.strip_prefix(b"type "))
        .ok_or_else(|| malformed(oid, "tag has no type line"))?;
    let target_kind = match type_name {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => return Err(malformed(oid, "tag names an unknown object type")),
    };
    Ok((target, target_kind))
}

/// Tree entries to follow: subtrees and blobs. Gitlinks are skipped.
fn parse_tree(oid: Oid, bytes: &[u8], kind: HashKind) -> Result<Vec<(Oid, Expect)>, GitError> {
    let width = kind.oid_len();
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| malformed(oid, "tree entry has no mode"))?;
        let mode = parse_mode(rest.get(..space).unwrap_or_default())
            .ok_or_else(|| malformed(oid, "tree entry mode is not octal"))?;
        let after_mode = rest.get(space + 1..).unwrap_or_default();
        let nul = after_mode
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| malformed(oid, "tree entry name is not terminated"))?;
        let id_start = nul + 1;
        let raw = after_mode
            .get(id_start..id_start + width)
            .ok_or_else(|| malformed(oid, "tree entry id is truncated"))?;
        let entry = Oid::from_bytes(raw).map_err(|err| malformed(oid, &err.to_string()))?;
        rest = after_mode.get(id_start + width..).unwrap_or_default();
        match mode & 0o170_000 {
            0o040_000 => out.push((entry, Expect::Kind(ObjectKind::Tree))),
            0o160_000 => {}
            _ => out.push((entry, Expect::Kind(ObjectKind::Blob))),
        }
    }
    Ok(out)
}

fn parse_mode(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 7 {
        return None;
    }
    digits.iter().try_fold(0u32, |acc, &digit| {
        (b'0'..=b'7')
            .contains(&digit)
            .then(|| acc * 8 + u32::from(digit - b'0'))
    })
}

fn header_oid(oid: Oid, hex: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(hex).map_err(|_| malformed(oid, "header id is not hex"))?;
    crate::parse_oid_for(text, kind).map_err(|err| malformed(oid, &err.to_string()))
}

fn malformed(oid: Oid, detail: &str) -> GitError {
    GitError::Corrupt {
        detail: format!("object {oid}: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_header_reads_tree_and_ordered_parents() {
        let kind = HashKind::Sha1;
        let id = kind.hash_git_object("blob", b"c").unwrap();
        let tree = kind.hash_git_object("tree", b"").unwrap();
        let p1 = kind.hash_git_object("blob", b"p1").unwrap();
        let p2 = kind.hash_git_object("blob", b"p2").unwrap();
        let text = format!(
            "tree {tree}\nparent {p1}\nparent {p2}\nauthor a <a> 1 +0000\ncommitter a <a> 1 +0000\nx-unknown v\n\nmsg\nparent {tree}\n"
        );
        let header = parse_commit(id, text.as_bytes(), kind).unwrap();
        assert_eq!(header.tree, tree);
        assert_eq!(header.parents, vec![p1, p2]);
    }

    #[test]
    fn wrong_width_ids_are_corrupt() {
        let id = HashKind::Sha1.hash_git_object("blob", b"c").unwrap();
        let tree = HashKind::Sha256.hash_git_object("tree", b"").unwrap();
        let text = format!("tree {tree}\n\n");
        assert!(matches!(
            parse_commit(id, text.as_bytes(), HashKind::Sha1),
            Err(GitError::Corrupt { .. })
        ));
    }

    #[test]
    fn tree_entries_skip_gitlinks_and_classify_modes() {
        let kind = HashKind::Sha1;
        let id = kind.hash_git_object("blob", b"t").unwrap();
        let blob = kind.hash_git_object("blob", b"b").unwrap();
        let sub = kind.hash_git_object("tree", b"").unwrap();
        let link = kind.hash_git_object("blob", b"l").unwrap();
        let mut bytes = Vec::new();
        for (mode, name, oid) in [
            (&b"100644"[..], &b"a\xff"[..], blob),
            (b"40000", b"d", sub),
            (b"160000", b"m", link),
            (b"120000", b"s", blob),
        ] {
            bytes.extend_from_slice(mode);
            bytes.push(b' ');
            bytes.extend_from_slice(name);
            bytes.push(0);
            bytes.extend_from_slice(oid.as_bytes());
        }
        let entries = parse_tree(id, &bytes, kind).unwrap();
        assert_eq!(
            entries,
            vec![
                (blob, Expect::Kind(ObjectKind::Blob)),
                (sub, Expect::Kind(ObjectKind::Tree)),
                (blob, Expect::Kind(ObjectKind::Blob)),
            ]
        );
        assert!(matches!(
            parse_tree(id, &bytes[..bytes.len() - 1], kind),
            Err(GitError::Corrupt { .. })
        ));
    }

    #[test]
    fn tag_header_reads_target_and_type() {
        let kind = HashKind::Sha256;
        let id = kind.hash_git_object("blob", b"t").unwrap();
        let target = kind.hash_git_object("blob", b"x").unwrap();
        let text = format!("object {target}\ntype blob\ntag v1\ntagger a <a> 1 +0000\n\nm\n");
        assert_eq!(
            parse_tag(id, text.as_bytes(), kind).unwrap(),
            (target, ObjectKind::Blob)
        );
    }
}
