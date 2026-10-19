//! `split`: split one commit into two consecutive commits within the same change.
//!
//! The first commit receives the caller-supplied intermediate tree, the original
//! commit's parents, and `predecessor: Some(head)`. The second commit retains the
//! original commit's tree, takes the first commit as its sole parent, and sets
//! `predecessor: Some(first)`. Both commits are staged in a single atomic batch.

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

/// One commit split to execute.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SplitRequest {
    /// The commit to split.
    pub head: Head,
    /// Intermediate tree for the first commit.
    pub first_tree: Oid,
    /// Commit message for the first commit.
    pub message: ByteString,
    /// Commit message for the second commit. When absent, defaults to the original message.
    pub second_message: Option<ByteString>,
}

/// What splitting produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SplitResult {
    /// Head of the first created commit.
    pub first: Head,
    /// Head of the second created commit.
    pub second: Head,
    /// The change both commits belong to.
    pub change_id: ChangeId,
}

/// Splits one commit into two commits published in a single atomic transaction.
///
/// # Preconditions
/// - `head` names an existing stored commit.
/// - `first_tree` names a stored tree object of this repository's hash kind.
/// - `first_tree` differs from the original commit's tree.
/// - Neither message contains a NUL byte.
///
/// # Errors
/// - `E_INVALID` if `first_tree` equals the original commit tree or a message contains NUL.
/// - `E_NOT_FOUND` if `head` or `first_tree` is not stored.
/// - `E_STALE` if `head` is not a current head of its change.
/// - Store failures propagate their respective error code.
pub fn split(store: &Store, request: SplitRequest) -> Result<SplitResult, CoreError> {
    let prepared = prepare_split(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one commit split and stages its publication parts without
/// publishing.
///
/// Runs every check [`split`] runs — both commits are staged in memory —
/// and returns the staged objects, exact-expectation facts, and the output
/// publication will produce.
pub fn prepare_split(
    store: &Store,
    request: SplitRequest,
) -> Result<PreparedOp<SplitResult>, CoreError> {
    let kind = store.hash_kind();
    request.head.validate(kind)?;
    request.first_tree.expect_kind(kind, "tree")?;
    require_tree(store, request.first_tree)?;

    if request.message.as_bytes().contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "first commit message contains a NUL byte",
        ));
    }
    if let Some(msg) = &request.second_message
        && msg.as_bytes().contains(&0)
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "second commit message contains a NUL byte",
        ));
    }

    let records = Records::new(store);
    let Some(existing) = records.get_commit(&request.head)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("commit {} is not stored", describe_head(&request.head)),
        ));
    };

    if existing.tree().as_resolved() == Some(&request.first_tree) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "first_tree cannot be equal to the original commit tree",
        ));
    }

    let change_id = existing.change_id();
    let author = existing.author()?;
    let committer = existing.committer()?;
    let extra_headers: Vec<ExtraHeader> = existing
        .extra_headers()
        .iter()
        .filter(|h| h.name.as_bytes() != CHANGE_ID_HEADER)
        .cloned()
        .collect();
    let provenance: Option<Provenance> = existing.provenance().cloned();

    let second_message = match request.second_message {
        Some(msg) => msg,
        None => ByteString::from(existing.message()),
    };

    let input_first = NativeCommitInput {
        change_id,
        tree: Merge::from_vec(vec![request.first_tree]),
        parents: existing.parents().to_vec(),
        predecessor: Some(request.head),
        author: author.clone(),
        committer: committer.clone(),
        extra_headers: extra_headers.clone(),
        message: request.message,
        provenance: provenance.clone(),
    };

    let mut preparer = records.batch_preparer();
    let first = preparer.add_native_commit(input_first)?;

    let input_second = NativeCommitInput {
        change_id,
        tree: existing.tree().clone(),
        parents: vec![first],
        predecessor: Some(first),
        author,
        committer,
        extra_headers,
        message: second_message,
        provenance,
    };

    let second = preparer.add_native_commit(input_second)?;
    let batch = preparer.finish()?;

    Ok(PreparedOp {
        objects: batch.prepared_objects,
        facts: batch.mutations,
        output: SplitResult {
            first,
            second,
            change_id,
        },
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
    use crate::conflict::{Signature, TzOffset};
    use crate::ids::HashKind;
    use crate::ops::{NewRequest, new};
    use crate::store::PreparationBudget;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ruk-split-test-{}-{}-{tag}",
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

        fn initial_commit(&self, marker: &[u8], msg: &str) -> (Head, ChangeId, Oid) {
            let tree = self.tree(marker);
            let author = sample_sig("Author", 1700000000);
            let committer = sample_sig("Committer", 1700000000);
            let result = new(
                &self.store,
                NewRequest {
                    tree,
                    parents: Vec::new(),
                    author,
                    committer,
                    message: ByteString::from(msg),
                    change_id: None,
                    predecessor: None,
                    provenance: None,
                },
            )
            .expect("create initial commit");
            (result.head, result.change_id, tree)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn sample_sig(name: &str, stamp: i64) -> Signature {
        Signature {
            name: ByteString::from(name),
            email: ByteString::from(format!("{name}@example.com")),
            timestamp: stamp,
            offset: TzOffset::new(false, 0).expect("tz offset"),
        }
    }

    #[test]
    fn test_split_happy_path_chained_commits() {
        let fixture = Fixture::new("happy");
        let (head, change_id, original_tree) = fixture.initial_commit(b"B", "Full original commit");
        let first_tree = fixture.tree(b"A");

        let result = split(
            &fixture.store,
            SplitRequest {
                head,
                first_tree,
                message: ByteString::from("Part 1 message"),
                second_message: Some(ByteString::from("Part 2 message")),
            },
        )
        .expect("split commit");

        assert_eq!(result.change_id, change_id);
        assert_ne!(result.first, head);
        assert_ne!(result.second, head);
        assert_ne!(result.first, result.second);

        let records = Records::new(&fixture.store);
        let commit_1 = records
            .get_commit(&result.first)
            .expect("read 1")
            .expect("commit 1 exists");
        let commit_2 = records
            .get_commit(&result.second)
            .expect("read 2")
            .expect("commit 2 exists");

        // Verify first commit properties
        assert_eq!(commit_1.change_id(), change_id);
        assert_eq!(commit_1.tree().as_resolved(), Some(&first_tree));
        assert_eq!(commit_1.message(), b"Part 1 message");
        assert_eq!(commit_1.predecessor(), Some(head));
        assert!(commit_1.parents().is_empty());

        // Verify second commit properties
        assert_eq!(commit_2.change_id(), change_id);
        assert_eq!(commit_2.tree().as_resolved(), Some(&original_tree));
        assert_eq!(commit_2.message(), b"Part 2 message");
        assert_eq!(commit_2.predecessor(), Some(result.first));
        assert_eq!(commit_2.parents(), &[result.first]);

        // Change entry should have second commit as active head
        let change = records
            .get_change(&change_id)
            .expect("read change")
            .expect("change exists");
        assert_eq!(change.heads, vec![result.second]);
    }

    #[test]
    fn test_split_default_second_message() {
        let fixture = Fixture::new("default-msg");
        let (head, change_id, _original_tree) =
            fixture.initial_commit(b"B", "Original preserved message");
        let first_tree = fixture.tree(b"A");

        let result = split(
            &fixture.store,
            SplitRequest {
                head,
                first_tree,
                message: ByteString::from("First message"),
                second_message: None,
            },
        )
        .expect("split with default second message");

        assert_eq!(result.change_id, change_id);

        let records = Records::new(&fixture.store);
        let commit_2 = records
            .get_commit(&result.second)
            .expect("read 2")
            .expect("commit 2 exists");

        assert_eq!(commit_2.message(), b"Original preserved message");
    }

    #[test]
    fn test_split_identical_tree_refused() {
        let fixture = Fixture::new("identical");
        let (head, _change_id, original_tree) = fixture.initial_commit(b"X", "Message");

        let err = split(
            &fixture.store,
            SplitRequest {
                head,
                first_tree: original_tree,
                message: ByteString::from("Part 1"),
                second_message: None,
            },
        )
        .expect_err("should refuse identical tree");

        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn test_split_missing_head_refused() {
        let fixture = Fixture::new("missing");
        let first_tree = fixture.tree(b"A");
        let missing_head = Head::Git { oid: first_tree };

        let err = split(
            &fixture.store,
            SplitRequest {
                head: missing_head,
                first_tree,
                message: ByteString::from("Part 1"),
                second_message: None,
            },
        )
        .expect_err("should refuse missing head");

        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
