//! `squash`: squash N consecutive commits into one and publish it atomically.
//!
//! The request names an ordered list of heads forming a linear chain, the
//! squashed tree, and the squashed message. The squashed commit takes the
//! first commit's parents and change ID, the caller's tree and message, and
//! the last head as its predecessor. Earlier heads are not deleted; they
//! remain in the store as unreachable history.

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::{CommitRecord, NativeCommitInput};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::ops::PreparedOp;
use crate::records::Records;
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// What to squash: an ordered linear chain of commits, a tree, and a message.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SquashRequest {
    /// Ordered heads to squash, oldest first. Must form a linear chain.
    pub heads: Vec<Head>,
    /// The tree this squashed commit records.
    pub tree: Oid,
    /// Raw message bytes for the squashed commit.
    pub message: ByteString,
}

/// What publication produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SquashResult {
    /// The stored head of the newly created squashed commit.
    pub head: Head,
    /// The change the squashed commit belongs to (from the first commit).
    pub change_id: ChangeId,
    /// The heads absorbed by the squash, in their original order.
    pub absorbed: Vec<Head>,
}

/// Squashes N consecutive commits into one native commit and publishes it.
///
/// # Preconditions
/// - At least 2 heads are provided.
/// - `tree` names a stored tree object of this repository's hash kind.
/// - Every head in `heads` is a stored commit of this repository.
/// - `heads` forms a linear chain where each next commit's parents contain
///   the previous head.
///
/// # Errors
/// `E_INVALID` when fewer than 2 heads are provided, or when two adjacent
/// heads do not form a linear chain (naming both offending heads).
/// `E_OBJECT_FORMAT` for an object ID or head of the wrong width.
/// `E_NOT_FOUND` when the tree or any head is not stored in the repository.
/// Store failures map by their own code. Nothing is published unless every
/// check passes.
pub fn squash(store: &Store, request: SquashRequest) -> Result<SquashResult, CoreError> {
    let prepared = prepare_squash(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one squash and stages its publication parts without publishing.
///
/// Runs every check [`squash`] runs and returns the staged objects,
/// exact-expectation facts, and the output publication will produce.
pub fn prepare_squash(
    store: &Store,
    request: SquashRequest,
) -> Result<PreparedOp<SquashResult>, CoreError> {
    if request.heads.len() < 2 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "squash requires at least 2 heads, got {}",
                request.heads.len()
            ),
        ));
    }

    let kind = store.hash_kind();
    request.tree.expect_kind(kind, "tree")?;
    require_tree(store, request.tree)?;

    let records = Records::new(store);
    let mut commit_records = Vec::with_capacity(request.heads.len());
    for head in &request.heads {
        head.validate(kind)?;
        let record = records.get_commit(head)?.ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("commit {} is not stored", describe_head(head)),
            )
        })?;
        commit_records.push(record);
    }

    validate_chain(&request.heads, &commit_records)?;

    let first_record = commit_records
        .first()
        .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "squash requires at least 2 heads"))?;
    let last_record = commit_records
        .last()
        .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "squash requires at least 2 heads"))?;
    let last_head = *request
        .heads
        .last()
        .ok_or_else(|| CoreError::new(ErrorCode::EInvalid, "squash requires at least 2 heads"))?;

    let change_id = first_record.change_id();
    let parents = first_record.parents().to_vec();
    let author = first_record.author()?;
    let committer = last_record.committer()?;

    let input = NativeCommitInput {
        change_id,
        tree: Merge::from_vec(vec![request.tree]),
        parents,
        predecessor: Some(last_head),
        author,
        committer,
        extra_headers: Vec::new(),
        message: request.message,
        provenance: None,
    };

    let prepared = records.prepare_native_commit(input)?;
    let head = prepared.head;
    Ok(PreparedOp {
        objects: vec![prepared.prepared_object],
        facts: prepared.mutations,
        output: SquashResult {
            head,
            change_id,
            absorbed: request.heads,
        },
    })
}

/// Verifies that each next commit's parents contain the previous head.
fn validate_chain(heads: &[Head], records: &[CommitRecord]) -> Result<(), CoreError> {
    for i in 1..heads.len() {
        let prev = heads[i - 1];
        let curr = heads[i];
        if !records[i].parents().contains(&prev) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "commits {} and {} do not form a linear chain: {} is not a parent of {}",
                    describe_head(&prev),
                    describe_head(&curr),
                    describe_head(&prev),
                    describe_head(&curr),
                ),
            ));
        }
    }
    Ok(())
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

    use super::*;
    use crate::conflict::{Signature, TzOffset};
    use crate::ids::HashKind;
    use crate::ops::new::{NewRequest, new as new_commit};
    use crate::store::PreparationBudget;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("ruk-ops-squash-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let store = Store::create(
                &root,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create test store");
            Self { root, store }
        }

        fn publish(&self, kind: ObjectKind, bytes: &[u8]) -> Oid {
            let prepared = self
                .store
                .prepare(
                    kind,
                    u64::try_from(bytes.len()).expect("test object fits u64"),
                    Cursor::new(bytes),
                    None,
                )
                .expect("prepare object");
            let oid = prepared.oid();
            self.store
                .publish(vec![prepared], &[])
                .expect("publish object");
            oid
        }

        fn tree(&self, marker: &[u8]) -> Oid {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"100644 x");
            bytes.push(*marker.first().expect("marker"));
            bytes.push(0);
            bytes.extend_from_slice(&[0x11; 20]);
            self.publish(ObjectKind::Tree, &bytes)
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

    fn new_request(
        tree: Oid,
        parents: Vec<Head>,
        message: &str,
        change_id: Option<ChangeId>,
        predecessor: Option<Head>,
    ) -> NewRequest {
        NewRequest {
            tree,
            parents,
            author: signature("Ada", 1_700_000_000),
            committer: signature("Ada", 1_700_000_000),
            message: ByteString::from(message),
            change_id,
            predecessor,
            provenance: None,
        }
    }

    #[test]
    fn squash_combines_linear_chain_into_single_commit() {
        let fixture = Fixture::new("success");
        let tree_root = fixture.tree(b"0");
        let tree_a = fixture.tree(b"a");
        let tree_b = fixture.tree(b"b");
        let tree_c = fixture.tree(b"c");
        let squashed_tree = fixture.tree(b"s");

        // Base commit before the chain
        let root = new_commit(
            &fixture.store,
            new_request(tree_root, Vec::new(), "root\n", None, None),
        )
        .expect("create root");

        let change_id = ChangeId::generate();

        // Commit 1: child of root, starts change_id
        let c1 = new_commit(
            &fixture.store,
            new_request(tree_a, vec![root.head], "first\n", Some(change_id), None),
        )
        .expect("create c1");

        // Commit 2: child and rewrite of c1
        let c2 = new_commit(
            &fixture.store,
            new_request(
                tree_b,
                vec![c1.head],
                "second\n",
                Some(change_id),
                Some(c1.head),
            ),
        )
        .expect("create c2");

        // Commit 3: child and rewrite of c2
        let c3 = new_commit(
            &fixture.store,
            new_request(
                tree_c,
                vec![c2.head],
                "third\n",
                Some(change_id),
                Some(c2.head),
            ),
        )
        .expect("create c3");

        // Squash c1..c3 into one
        let squashed = squash(
            &fixture.store,
            SquashRequest {
                heads: vec![c1.head, c2.head, c3.head],
                tree: squashed_tree,
                message: ByteString::from("squashed 1-3\n"),
            },
        )
        .expect("squash succeeds");

        assert_eq!(squashed.change_id, change_id);
        assert_eq!(squashed.absorbed, vec![c1.head, c2.head, c3.head]);
        assert_ne!(squashed.head, c1.head);
        assert_ne!(squashed.head, c2.head);
        assert_ne!(squashed.head, c3.head);

        // Verify commit record
        let records = Records::new(&fixture.store);
        let record = records
            .get_commit(&squashed.head)
            .expect("read record")
            .expect("commit stored");
        assert_eq!(record.change_id(), change_id);
        assert_eq!(record.parents(), &[root.head]);
        assert_eq!(record.predecessor(), Some(c3.head));
        assert_eq!(record.message(), b"squashed 1-3\n");
        assert_eq!(record.tree().as_resolved(), Some(&squashed_tree));

        // Verify change heads: squashed head replaced c3.head
        let change = records
            .get_change(&change_id)
            .expect("read change")
            .expect("change stored");
        assert_eq!(change.heads, vec![squashed.head]);

        // Earlier heads are still stored (unreachable history, not deleted)
        assert!(records.get_commit(&c1.head).unwrap().is_some());
        assert!(records.get_commit(&c2.head).unwrap().is_some());
        assert!(records.get_commit(&c3.head).unwrap().is_some());
    }

    #[test]
    fn single_head_is_refused() {
        let fixture = Fixture::new("single");
        let tree = fixture.tree(b"a");
        let c1 = new_commit(
            &fixture.store,
            new_request(tree, Vec::new(), "root\n", None, None),
        )
        .expect("create c1");

        let err = squash(
            &fixture.store,
            SquashRequest {
                heads: vec![c1.head],
                tree,
                message: ByteString::from("single\n"),
            },
        )
        .expect_err("refuses single head");

        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn unstored_head_is_refused() {
        let fixture = Fixture::new("unstored");
        let tree = fixture.tree(b"a");
        let c1 = new_commit(
            &fixture.store,
            new_request(tree, Vec::new(), "root\n", None, None),
        )
        .expect("create c1");

        let missing_head = Head::Git {
            oid: Oid::from_bytes(&[0x33; 20]).expect("oid"),
        };

        let err = squash(
            &fixture.store,
            SquashRequest {
                heads: vec![c1.head, missing_head],
                tree,
                message: ByteString::from("unstored\n"),
            },
        )
        .expect_err("refuses unstored head");

        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn broken_chain_is_refused_naming_offending_pair() {
        let fixture = Fixture::new("broken");
        let tree_a = fixture.tree(b"a");
        let tree_b = fixture.tree(b"b");
        let c1 = new_commit(
            &fixture.store,
            new_request(tree_a, Vec::new(), "root1\n", None, None),
        )
        .expect("create c1");

        // c2 is an independent root commit, not a child of c1
        let c2 = new_commit(
            &fixture.store,
            new_request(tree_b, Vec::new(), "root2\n", None, None),
        )
        .expect("create c2");

        let err = squash(
            &fixture.store,
            SquashRequest {
                heads: vec![c1.head, c2.head],
                tree: tree_a,
                message: ByteString::from("broken\n"),
            },
        )
        .expect_err("refuses broken chain");

        assert_eq!(err.code, ErrorCode::EInvalid);
        let msg = err.to_string();
        let h1_str = describe_head(&c1.head);
        let h2_str = describe_head(&c2.head);
        assert!(
            msg.contains(&h1_str),
            "error message should name offending head 1"
        );
        assert!(
            msg.contains(&h2_str),
            "error message should name offending head 2"
        );
    }
}
