//! `edit`: rewrite one commit's message and/or author/committer and/or tree while keeping its change ID.
//!
//! The operation loads an existing commit record, updates any combination of its
//! message, author, committer, or tree, and publishes the replacement commit with
//! `predecessor: Some(request.head)` under the original change ID.

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::{NativeCommitInput, Provenance};
use crate::conflict::{ExtraHeader, Signature};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::records::Records;
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// Header name carrying the native change ID.
const CHANGE_ID_HEADER: &[u8] = b"change-id";

/// One commit rewrite to execute.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EditRequest {
    /// The commit to rewrite.
    pub head: Head,
    /// New tree object, when replacing the tree.
    pub tree: Option<Oid>,
    /// New raw message bytes, when replacing the message.
    pub message: Option<ByteString>,
    /// New author identity, when replacing the author.
    pub author: Option<Signature>,
    /// New committer identity, when replacing the committer.
    pub committer: Option<Signature>,
}

/// What rewriting produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct EditResult {
    /// The stored head, which is the rewritten commit's identity.
    pub head: Head,
    /// The change the commit belongs to (preserved from original).
    pub change_id: ChangeId,
}

/// Rewrites one commit's message, identities, and/or tree while preserving its change identity.
///
/// # Preconditions
/// - At least one of `tree`, `message`, `author`, or `committer` is provided.
/// - `head` names a stored commit.
/// - When provided, `tree` names a stored tree object of this repository's hash kind.
///
/// # Errors
/// - `E_INVALID` when no fields to edit are provided, or message contains a NUL byte.
/// - `E_NOT_FOUND` when `head` or `tree` is not stored in the repository.
/// - `E_STALE` when `head` is not a current head of its change.
/// - Store failures propagate their respective error code.
pub fn edit(store: &Store, request: EditRequest) -> Result<EditResult, CoreError> {
    if request.tree.is_none()
        && request.message.is_none()
        && request.author.is_none()
        && request.committer.is_none()
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "edit request must specify at least one field to change",
        ));
    }

    let kind = store.hash_kind();
    request.head.validate(kind)?;
    if let Some(tree) = request.tree {
        tree.expect_kind(kind, "tree")?;
        require_tree(store, tree)?;
    }
    if let Some(msg) = &request.message {
        if msg.as_bytes().contains(&0) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "commit message contains a NUL byte",
            ));
        }
    }

    let records = Records::new(store);
    let Some(existing) = records.get_commit(&request.head)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("commit {} is not stored", describe_head(&request.head)),
        ));
    };

    let tree = match request.tree {
        Some(t) => Merge::from_vec(vec![t]),
        None => existing.tree().clone(),
    };
    let message = match request.message {
        Some(m) => m,
        None => ByteString::from(existing.message()),
    };
    let author = match request.author {
        Some(a) => a,
        None => existing.author()?,
    };
    let committer = match request.committer {
        Some(c) => c,
        None => existing.committer()?,
    };
    let parents = existing.parents().to_vec();
    let extra_headers: Vec<ExtraHeader> = existing
        .extra_headers()
        .iter()
        .filter(|h| h.name.as_bytes() != CHANGE_ID_HEADER)
        .cloned()
        .collect();
    let provenance: Option<Provenance> = existing.provenance().cloned();

    let input = NativeCommitInput {
        change_id: existing.change_id(),
        tree,
        parents,
        predecessor: Some(request.head),
        author,
        committer,
        extra_headers,
        message,
        provenance,
    };

    let prepared = records.prepare_native_commit(input)?;
    let head = prepared.head;
    store
        .publish(vec![prepared.prepared_object], &prepared.mutations)
        .map_err(store_error)?;

    Ok(EditResult {
        head,
        change_id: prepared.record.change_id(),
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
    use crate::conflict::TzOffset;
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
                "ruk-edit-test-{}-{}-{tag}",
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
    fn test_edit_message_preserves_change_id_and_tree() {
        let fixture = Fixture::new("msg");
        let (head, change_id, tree) = fixture.initial_commit(b"1", "Initial message");

        let result = edit(
            &fixture.store,
            EditRequest {
                head,
                tree: None,
                message: Some(ByteString::from("Updated message")),
                author: None,
                committer: None,
            },
        )
        .expect("edit commit message");

        assert_eq!(result.change_id, change_id);
        assert_ne!(result.head, head);

        let records = Records::new(&fixture.store);
        let commit = records
            .get_commit(&result.head)
            .expect("read")
            .expect("commit exists");

        assert_eq!(commit.change_id(), change_id);
        assert_eq!(commit.message(), b"Updated message");
        assert_eq!(commit.tree().as_resolved(), Some(&tree));
        assert_eq!(commit.predecessor(), Some(head));
    }

    #[test]
    fn test_edit_tree_author_and_committer() {
        let fixture = Fixture::new("fields");
        let (head, change_id, _old_tree) = fixture.initial_commit(b"1", "Static message");
        let new_tree = fixture.tree(b"2");
        let new_author = sample_sig("New Author", 1700000100);
        let new_committer = sample_sig("New Committer", 1700000200);

        let result = edit(
            &fixture.store,
            EditRequest {
                head,
                tree: Some(new_tree),
                message: None,
                author: Some(new_author.clone()),
                committer: Some(new_committer.clone()),
            },
        )
        .expect("edit tree and signatures");

        assert_eq!(result.change_id, change_id);
        assert_ne!(result.head, head);

        let records = Records::new(&fixture.store);
        let commit = records
            .get_commit(&result.head)
            .expect("read")
            .expect("commit exists");

        assert_eq!(commit.tree().as_resolved(), Some(&new_tree));
        assert_eq!(commit.author().expect("author"), new_author);
        assert_eq!(commit.committer().expect("committer"), new_committer);
        assert_eq!(commit.message(), b"Static message");
    }

    #[test]
    fn test_edit_no_fields_refused() {
        let fixture = Fixture::new("empty");
        let (head, _change_id, _tree) = fixture.initial_commit(b"1", "Message");

        let err = edit(
            &fixture.store,
            EditRequest {
                head,
                tree: None,
                message: None,
                author: None,
                committer: None,
            },
        )
        .expect_err("should refuse empty edit");

        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn test_edit_missing_head_refused() {
        let fixture = Fixture::new("missing");
        let missing_head = Head::Git {
            oid: fixture.tree(b"x"),
        };

        let err = edit(
            &fixture.store,
            EditRequest {
                head: missing_head,
                tree: None,
                message: Some(ByteString::from("New")),
                author: None,
                committer: None,
            },
        )
        .expect_err("should refuse missing head");

        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
