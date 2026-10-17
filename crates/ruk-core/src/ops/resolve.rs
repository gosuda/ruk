//! `resolve`: record a resolution of a conflicted commit by publishing a new
//! commit whose tree is the caller's resolved tree.
//!
//! When resolving a conflicted commit, the newly published commit records the
//! resolved tree, keeps the existing commit as predecessor, shares its change
//! identity and parents, and preserves the original message unless overridden.

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::{NativeCommitInput, Provenance};
use crate::conflict::ExtraHeader;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::ops::PreparedOp;
use crate::records::Records;
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// Header name carrying the native change ID.
const CHANGE_ID_HEADER: &[u8] = b"change-id";

/// One conflict resolution to execute.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    /// The conflicted commit to resolve.
    pub head: Head,
    /// The resolved tree to record.
    pub resolved_tree: Oid,
    /// Optional override for the commit message. When absent, the existing
    /// commit message is preserved.
    pub message: Option<ByteString>,
}

/// What resolution produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResolveResult {
    /// The stored head of the newly created resolved commit.
    pub head: Head,
    /// The change the commit belongs to.
    pub change_id: ChangeId,
}

/// Resolves a conflicted commit by creating and publishing a rewrite with the
/// resolved tree.
///
/// # Preconditions
/// - `head` names a stored commit in this repository.
/// - `resolved_tree` names a stored tree object in this repository.
/// - `head` is a current head of its change.
/// - `resolved_tree` does not match the singleton tree `head` already has.
///
/// # Errors
/// `E_OBJECT_FORMAT` for a digest of the wrong width, `E_NOT_FOUND` when
/// `head` or `resolved_tree` is not stored, `E_INVALID` when `resolved_tree`
/// is not a tree or is the same singleton the record already has, or when the
/// message contains a NUL byte, and `E_STALE` when `head` is not a current
/// head of the change. Store failures map by their own code.
pub fn resolve(store: &Store, request: ResolveRequest) -> Result<ResolveResult, CoreError> {
    let prepared = prepare_resolve(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one conflict resolution and stages its publication parts
/// without publishing.
///
/// Runs every check [`resolve`] runs and returns the staged objects,
/// exact-expectation facts, and the output publication will produce.
pub fn prepare_resolve(
    store: &Store,
    request: ResolveRequest,
) -> Result<PreparedOp<ResolveResult>, CoreError> {
    let kind = store.hash_kind();
    request.head.validate(kind)?;
    request.resolved_tree.expect_kind(kind, "tree")?;
    require_tree(store, request.resolved_tree)?;

    let records = Records::new(store);
    let record = records.get_commit(&request.head)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("commit {} is not stored", describe_head(&request.head)),
        )
    })?;

    if record.tree().as_resolved() == Some(&request.resolved_tree) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "commit {} already has singleton tree {}",
                describe_head(&request.head),
                request.resolved_tree,
            ),
        ));
    }

    if request
        .message
        .as_ref()
        .is_some_and(|m| m.as_bytes().contains(&0))
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "commit message contains a NUL byte",
        ));
    }

    let message = request
        .message
        .unwrap_or_else(|| ByteString::from(record.message()));
    let author = record.author()?;
    let committer = record.committer()?;
    let extra_headers: Vec<ExtraHeader> = record
        .extra_headers()
        .iter()
        .filter(|h| h.name.as_bytes() != CHANGE_ID_HEADER)
        .cloned()
        .collect();
    let provenance: Option<Provenance> = record.provenance().cloned();

    let input = NativeCommitInput {
        change_id: record.change_id(),
        tree: Merge::resolved(request.resolved_tree),
        parents: record.parents().to_vec(),
        predecessor: Some(request.head),
        author,
        committer,
        extra_headers,
        message,
        provenance,
    };

    let prepared = records.prepare_native_commit(input)?;
    let head = prepared.head;
    let change_id = prepared.record.change_id();
    Ok(PreparedOp {
        objects: vec![prepared.prepared_object],
        facts: prepared.mutations,
        output: ResolveResult { head, change_id },
    })
}

/// Refuses a tree that is not a stored tree of this repository.
fn require_tree(store: &Store, tree: Oid) -> Result<(), CoreError> {
    let Some(len) = store.object_len(tree)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("tree {tree} is not stored"),
        ));
    };
    let read = store.read(tree)?;
    if read.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "{tree} is a {:?} object of {len} bytes, not a tree",
                read.kind
            ),
        ));
    }
    Ok(())
}

fn describe_head(head: &Head) -> String {
    match head {
        Head::Git { oid } => oid.to_string(),
        Head::Conflicted { key } => format!("{key:?}"),
    }
}

fn store_error(error: StoreError) -> CoreError {
    CoreError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::bytes::ByteString;
    use crate::conflict::{Signature, TzOffset};
    use crate::ids::HashKind;
    use crate::ops::{NewRequest, new as create_commit};
    use crate::store::PreparationBudget;
    use crate::store::types::ObjectKind;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ruk-resolve-test-{}-{}-{tag}",
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

        fn tree(&self, marker: &[u8]) -> Oid {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"100644 x");
            bytes.push(*marker.first().expect("marker"));
            bytes.push(0);
            bytes.extend_from_slice(&[0x11; 20]);
            let len = u64::try_from(bytes.len()).expect("len fits u64");
            let prepared = self
                .store
                .prepare(ObjectKind::Tree, len, Cursor::new(&bytes), None)
                .expect("prepare tree");
            let oid = prepared.oid();
            self.store
                .publish(vec![prepared], &[])
                .expect("publish tree");
            oid
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn signature(name: &str, timestamp: i64) -> Signature {
        Signature {
            name: ByteString::from(name),
            email: ByteString::from(format!("{name}@example.invalid")),
            timestamp,
            offset: TzOffset::UTC,
        }
    }

    #[test]
    fn resolve_conflicted_commit_replaces_head_and_sets_tree() {
        let fixture = Fixture::new("conflicted");
        let tree_1 = fixture.tree(b"1");
        let tree_2 = fixture.tree(b"2");
        let tree_3 = fixture.tree(b"3");
        let resolved_tree = fixture.tree(b"r");

        let records = Records::new(&fixture.store);
        let change_id = ChangeId::generate();
        let input = NativeCommitInput {
            change_id,
            tree: Merge::from_vec(vec![tree_1, tree_2, tree_3]),
            parents: Vec::new(),
            predecessor: None,
            author: signature("Alice", 1_700_000_000),
            committer: signature("Alice", 1_700_000_000),
            extra_headers: Vec::new(),
            message: ByteString::from("Conflicted commit"),
            provenance: None,
        };
        let prepared = records
            .prepare_native_commit(input)
            .expect("prepare conflicted");
        fixture
            .store
            .publish(vec![prepared.prepared_object], &prepared.mutations)
            .expect("publish conflicted");
        let conflicted_head = prepared.head;

        let result = resolve(
            &fixture.store,
            ResolveRequest {
                head: conflicted_head,
                resolved_tree,
                message: None,
            },
        )
        .expect("resolve conflicted commit");

        assert_eq!(result.change_id, change_id);
        assert_ne!(result.head, conflicted_head);

        let records = Records::new(&fixture.store);
        let commit = records
            .get_commit(&result.head)
            .expect("get commit")
            .expect("commit exists");
        assert_eq!(commit.tree().as_resolved(), Some(&resolved_tree));
        assert_eq!(commit.predecessor(), Some(conflicted_head));
        assert_eq!(commit.message(), b"Conflicted commit");

        let change = records
            .get_change(&change_id)
            .expect("get change")
            .expect("change exists");
        assert_eq!(change.heads, vec![result.head]);
    }

    #[test]
    fn resolve_with_overridden_message() {
        let fixture = Fixture::new("message");
        let tree_1 = fixture.tree(b"1");
        let tree_2 = fixture.tree(b"2");
        let tree_3 = fixture.tree(b"3");
        let resolved_tree = fixture.tree(b"r");

        let records = Records::new(&fixture.store);
        let change_id = ChangeId::generate();
        let input = NativeCommitInput {
            change_id,
            tree: Merge::from_vec(vec![tree_1, tree_2, tree_3]),
            parents: Vec::new(),
            predecessor: None,
            author: signature("Alice", 1_700_000_000),
            committer: signature("Alice", 1_700_000_000),
            extra_headers: Vec::new(),
            message: ByteString::from("Original message"),
            provenance: None,
        };
        let prepared = records
            .prepare_native_commit(input)
            .expect("prepare conflicted");
        fixture
            .store
            .publish(vec![prepared.prepared_object], &prepared.mutations)
            .expect("publish conflicted");

        let result = resolve(
            &fixture.store,
            ResolveRequest {
                head: prepared.head,
                resolved_tree,
                message: Some(ByteString::from("Resolved cleanly")),
            },
        )
        .expect("resolve with message");

        let records = Records::new(&fixture.store);
        let commit = records
            .get_commit(&result.head)
            .expect("get commit")
            .expect("commit exists");
        assert_eq!(commit.message(), b"Resolved cleanly");
    }

    #[test]
    fn resolve_refuses_same_singleton_tree_with_einvalid() {
        let fixture = Fixture::new("same-singleton");
        let tree_1 = fixture.tree(b"1");
        let created = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_1,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_000),
                committer: signature("Alice", 1_700_000_000),
                message: ByteString::from("Singleton commit"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create commit");

        let err = resolve(
            &fixture.store,
            ResolveRequest {
                head: created.head,
                resolved_tree: tree_1,
                message: None,
            },
        )
        .expect_err("same singleton tree must be refused");

        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn resolve_refuses_unstored_tree_and_unstored_commit() {
        let fixture = Fixture::new("unstored");
        let tree_1 = fixture.tree(b"1");
        let unstored_tree = Oid::from_bytes(&[0xee; 20]).expect("oid");
        let unstored_head = Head::Git {
            oid: Oid::from_bytes(&[0xff; 20]).expect("oid"),
        };

        let err_head = resolve(
            &fixture.store,
            ResolveRequest {
                head: unstored_head,
                resolved_tree: tree_1,
                message: None,
            },
        )
        .expect_err("unstored head must fail");
        assert_eq!(err_head.code, ErrorCode::ENotFound);

        let created = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_1,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_000),
                committer: signature("Alice", 1_700_000_000),
                message: ByteString::from("Root commit"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create commit");

        let err_tree = resolve(
            &fixture.store,
            ResolveRequest {
                head: created.head,
                resolved_tree: unstored_tree,
                message: None,
            },
        )
        .expect_err("unstored tree must fail");
        assert_eq!(err_tree.code, ErrorCode::ENotFound);
    }
}
