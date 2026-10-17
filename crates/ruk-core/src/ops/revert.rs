//! `revert`: create a commit that undoes a prior commit's tree change.
//!
//! The operation creates a commit with the caller's resolved tree, parented on
//! the reverted commit, and publishes it in a fresh change. It never joins the
//! reverted commit's change.
//!
//! # Oplog Gap
//! Operation inversion (`invert`) requires touched-key before and after values
//! to restore the prior repository fact state. In the current coordinator
//! architecture, `FactTable::Ops` and its internal stream codec (`OpHeader`,
//! `OpDelta`, `OpDeltaReader`) are private to `crate::coord`. No public or
//! crate-visible API exposes touched-key prior values (`OpDelta.before`) to
//! change operations in `crate::ops`. Per the operations contract, `invert`
//! refuses to invent a parallel log and reports `E_UNSUPPORTED_OPERATION`
//! (using [`ErrorCode::EInvalid`]).

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::{ChangeId, OperationId};
use crate::commit::{CommitRecord, NativeCommitInput};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::ops::PreparedOp;
use crate::records::{RecordBatchPreparer, Records};
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// Request to revert a stored commit.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevertRequest {
    /// The commit to revert.
    pub head: Head,
    /// The tree that undoes the reverted commit's tree change.
    ///
    /// The caller resolves content; this operation refuses to compute a merge
    /// and requires a mandatory tree.
    pub tree: Oid,
    /// Raw message bytes. Defaults to `Revert "<original first line>"` when omitted.
    pub message: Option<ByteString>,
}

/// What revert publication produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RevertResult {
    /// The stored head of the newly created revert commit.
    pub head: Head,
    /// The change the revert commit belongs to (distinct from the reverted commit's change).
    pub change_id: ChangeId,
    /// The head that was reverted.
    pub reverted: Head,
}

/// Result of an operation inversion.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct InvertResult {
    /// Keys whose prior values were restored.
    pub restored: Vec<Vec<u8>>,
    /// Keys whose prior values were absent and thus deleted.
    pub deleted: Vec<Vec<u8>>,
}

/// Creates and publishes one revert commit.
///
/// Undoes the tree change of `request.head` by publishing a commit with
/// `request.tree` and `[request.head]` as parent. The revert commit is
/// published in a fresh change and never joins the reverted commit's change.
///
/// # Preconditions
/// - `head` names a stored commit in this repository.
/// - `tree` names a stored tree object in this repository.
/// - `message` contains no NUL bytes.
///
/// # Errors
/// - `E_NOT_FOUND` if `head` is not a stored commit or `tree` is not stored.
/// - `E_OBJECT_FORMAT` if `head` or `tree` digest width disagrees with the repository.
/// - `E_INVALID` if `tree` is not a tree object, or if `message` contains a NUL byte.
/// - Store failures map by their own error code.
pub fn revert(store: &Store, request: RevertRequest) -> Result<RevertResult, CoreError> {
    let prepared = prepare_revert(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one revert and stages its publication parts without publishing.
///
/// Runs every check [`revert`] runs and returns the staged objects,
/// exact-expectation facts, and the output publication will produce.
pub fn prepare_revert(
    store: &Store,
    request: RevertRequest,
) -> Result<PreparedOp<RevertResult>, CoreError> {
    let kind = store.hash_kind();
    request.head.validate(kind)?;
    request.tree.expect_kind(kind, "tree")?;
    let original = require_stored_commit(store, &request.head)?;
    require_tree(store, request.tree)?;

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

    let author = original.author()?;
    let committer = original.committer()?;

    let message = match request.message {
        Some(msg) => msg,
        None => default_revert_message(original.message()),
    };

    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let change_id = resolve_revert_change_id(&mut preparer, request.head, original.change_id())?;

    let input = NativeCommitInput {
        change_id,
        tree: Merge::from_vec(vec![request.tree]),
        parents: vec![request.head],
        predecessor: None,
        author,
        committer,
        extra_headers: Vec::new(),
        message,
        provenance: None,
    };

    let prepared = records.prepare_native_commit(input)?;
    let head = prepared.head;
    Ok(PreparedOp {
        objects: vec![prepared.prepared_object],
        facts: prepared.mutations,
        output: RevertResult {
            head,
            change_id: prepared.record.change_id(),
            reverted: request.head,
        },
    })
}

/// Inverts a prior operation by restoring touched keys to their prior values.
///
/// # Errors
/// Returns `E_UNSUPPORTED_OPERATION` (using [`ErrorCode::EInvalid`]) because the
/// coordinator oplog API is private to `crate::coord` and does not expose
/// touched-key prior values (`OpDelta.before`) to operations in `crate::ops`.
pub fn invert(store: &Store, operation: OperationId) -> Result<InvertResult, CoreError> {
    let _ = store;
    Err(CoreError::new(
        ErrorCode::EInvalid,
        format!(
            "E_UNSUPPORTED_OPERATION: coordinator oplog is private and does not expose prior values per key (OpDelta.before) to change operations for operation {}",
            operation.0
        ),
    ))
}

/// Resolves a fresh change ID for the revert commit.
///
/// Ensures the revert commit never joins the reverted commit's change.
fn resolve_revert_change_id(
    preparer: &mut RecordBatchPreparer<'_>,
    head: Head,
    original_change_id: ChangeId,
) -> Result<ChangeId, CoreError> {
    let Head::Git { oid } = head else {
        return Ok(ChangeId::generate());
    };
    let candidate = preparer.resolve_or_mint_change_id(&oid)?;
    if candidate == original_change_id {
        return Ok(ChangeId::generate());
    }
    Ok(candidate)
}

/// Refuses a head that is not a stored commit of this repository.
fn require_stored_commit(store: &Store, head: &Head) -> Result<CommitRecord, CoreError> {
    let records = Records::new(store);
    if let Some(record) = records.get_commit(head)? {
        return Ok(record);
    }
    Err(CoreError::new(
        ErrorCode::ENotFound,
        format!("commit {} is not stored", describe_head(head)),
    ))
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

fn default_revert_message(original_message: &[u8]) -> ByteString {
    let first_line = match original_message.split(|&b| b == b'\n').next() {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => b"",
    };
    let mut msg = Vec::with_capacity(first_line.len() + 10);
    msg.extend_from_slice(b"Revert \"");
    msg.extend_from_slice(first_line);
    msg.push(b'"');
    ByteString::from(msg)
}

fn store_error(error: StoreError) -> CoreError {
    CoreError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    use crate::bytes::ByteString;
    use crate::conflict::{Signature, TzOffset};
    use crate::error::ErrorCode;
    use crate::ids::HashKind;
    use crate::ops::new::{NewRequest, new};
    use crate::records::Records;
    use crate::store::types::ObjectKind;
    use crate::store::{PreparationBudget, Store};

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("ruk-revert-test-{}-{tag}", std::process::id()));
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

    fn signature(name: &str, email: &str, timestamp: i64) -> Signature {
        Signature {
            name: ByteString::from(name),
            email: ByteString::from(email),
            timestamp,
            offset: TzOffset::UTC,
        }
    }

    fn create_commit(fixture: &Fixture, tree: Oid, message: &str) -> Head {
        let req = NewRequest {
            tree,
            parents: Vec::new(),
            author: signature("Dev", "dev@example.invalid", 1_700_000_000),
            committer: signature("Dev", "dev@example.invalid", 1_700_000_000),
            message: ByteString::from(message),
            change_id: None,
            predecessor: None,
            provenance: None,
        };
        new(&fixture.store, req).expect("create commit").head
    }

    #[test]
    fn revert_creates_commit_in_fresh_change_with_default_message() {
        let fixture = Fixture::new("fresh-change");
        let tree_base = fixture.tree(b"1");
        let tree_feature = fixture.tree(b"2");
        let orig_head = create_commit(&fixture, tree_feature, "Add feature\n\nFull description");

        let revert_req = RevertRequest {
            head: orig_head,
            tree: tree_base,
            message: None,
        };
        let result = revert(&fixture.store, revert_req).expect("revert succeeds");

        assert_eq!(result.reverted, orig_head);
        assert_ne!(result.head, orig_head);

        let records = Records::new(&fixture.store);
        let orig_commit = records
            .get_commit(&orig_head)
            .expect("read orig")
            .expect("orig exists");
        assert_ne!(result.change_id, orig_commit.change_id());

        let revert_commit = records
            .get_commit(&result.head)
            .expect("read revert")
            .expect("revert exists");
        assert_eq!(revert_commit.parents(), &[orig_head]);
        assert_eq!(revert_commit.tree().as_resolved(), Some(&tree_base));
        assert_eq!(revert_commit.message(), b"Revert \"Add feature\"");
        assert_eq!(revert_commit.change_id(), result.change_id);

        let orig_change = records
            .get_change(&orig_commit.change_id())
            .expect("read change")
            .expect("orig change exists");
        assert_eq!(orig_change.heads, vec![orig_head]);

        let revert_change = records
            .get_change(&result.change_id)
            .expect("read change")
            .expect("revert change exists");
        assert_eq!(revert_change.heads, vec![result.head]);
    }

    #[test]
    fn revert_with_custom_message() {
        let fixture = Fixture::new("custom-msg");
        let tree_base = fixture.tree(b"1");
        let tree_feature = fixture.tree(b"2");
        let orig_head = create_commit(&fixture, tree_feature, "Initial commit");

        let revert_req = RevertRequest {
            head: orig_head,
            tree: tree_base,
            message: Some(ByteString::from("Explicit revert message")),
        };
        let result = revert(&fixture.store, revert_req).expect("revert succeeds");

        let records = Records::new(&fixture.store);
        let revert_commit = records
            .get_commit(&result.head)
            .expect("read revert")
            .expect("revert exists");
        assert_eq!(revert_commit.message(), b"Explicit revert message");

        let orig_commit = records
            .get_commit(&orig_head)
            .expect("read orig")
            .expect("orig exists");
        assert_ne!(result.change_id, orig_commit.change_id());
    }

    #[test]
    fn revert_refuses_unstored_commit_or_tree() {
        let fixture = Fixture::new("not-found");
        let tree = fixture.tree(b"1");
        let dummy_head = Head::Git {
            oid: Oid::from_bytes(&[0x22; 20]).expect("valid sha1 oid"),
        };

        let req_missing_commit = RevertRequest {
            head: dummy_head,
            tree,
            message: None,
        };
        let err_commit =
            revert(&fixture.store, req_missing_commit).expect_err("unstored commit fails");
        assert_eq!(err_commit.code, ErrorCode::ENotFound);

        let orig_head = create_commit(&fixture, tree, "Message");
        let dummy_tree = Oid::from_bytes(&[0x33; 20]).expect("valid sha1 oid");
        let req_missing_tree = RevertRequest {
            head: orig_head,
            tree: dummy_tree,
            message: None,
        };
        let err_tree = revert(&fixture.store, req_missing_tree).expect_err("unstored tree fails");
        assert_eq!(err_tree.code, ErrorCode::ENotFound);
    }

    #[test]
    fn revert_refuses_message_with_nul_byte() {
        let fixture = Fixture::new("nul-byte");
        let tree = fixture.tree(b"1");
        let orig_head = create_commit(&fixture, tree, "Clean commit");

        let req = RevertRequest {
            head: orig_head,
            tree,
            message: Some(ByteString::from("Bad\0message")),
        };
        let err = revert(&fixture.store, req).expect_err("NUL message rejected");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn revert_refuses_non_tree_object() {
        let fixture = Fixture::new("non-tree");
        let tree = fixture.tree(b"1");
        let orig_head = create_commit(&fixture, tree, "Clean commit");

        let blob = fixture.publish(ObjectKind::Blob, b"plain blob content");
        let req = RevertRequest {
            head: orig_head,
            tree: blob,
            message: None,
        };
        let err = revert(&fixture.store, req).expect_err("blob as tree rejected");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn invert_reports_unsupported_operation() {
        let fixture = Fixture::new("invert-unsupported");
        let err = invert(&fixture.store, OperationId(42)).expect_err("invert unsupported");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("E_UNSUPPORTED_OPERATION"));
    }
}
