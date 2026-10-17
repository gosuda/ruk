//! `abandon`: remove commits from their changes and mark a change abandoned
//! when it has no heads left.
//!
//! An abandoned commit remains stored as an object, but its change drops
//! it from its current heads. When a change has no heads left, its state
//! transitions to abandoned.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::change::ChangeId;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::records::Records;
use crate::records::codec::{decode_change_entry, encode_change_entry};
use crate::records::keys::change_key;
use crate::records::types::{ChangeEntry, ChangeState};
use crate::store::types::{FactExpectation, FactMutation, FactTable};
use crate::store::{Store, StoreError};

/// One request to abandon commit heads.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbandonRequest {
    /// Commit heads to remove from their changes.
    pub heads: Vec<Head>,
}

/// What abandoning produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AbandonResult {
    /// Changes that were marked abandoned because no heads remained.
    pub abandoned: Vec<ChangeId>,
    /// Active changes that retain heads, paired with their remaining head count.
    pub remaining: Vec<(ChangeId, usize)>,
}

/// Removes commits from their changes and marks changes abandoned when no
/// heads remain.
///
/// # Preconditions
/// - Every head in `request.heads` is a stored commit in this repository.
/// - Every head's change entry is stored in the repository.
///
/// # Errors
/// `E_OBJECT_FORMAT` for a head digest of the wrong width, `E_NOT_FOUND` when
/// a named commit or its change is not stored. Store failures map by their
/// own code. CAS mismatch (`E_STALE`) is returned if any change was concurrently
/// modified.
pub fn abandon(store: &Store, request: AbandonRequest) -> Result<AbandonResult, CoreError> {
    let kind = store.hash_kind();
    for head in &request.heads {
        head.validate(kind)?;
    }

    let records = Records::new(store);

    let mut pending: BTreeMap<ChangeId, PendingChangeUpdate> = BTreeMap::new();
    let mut order: Vec<ChangeId> = Vec::new();

    for head in &request.heads {
        let record = records.get_commit(head)?.ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("commit {} is not stored", describe_head(head)),
            )
        })?;
        let change_id = record.change_id();

        if !pending.contains_key(&change_id) {
            let update = load_change_update(store, &change_id)?;
            pending.insert(change_id, update);
            order.push(change_id);
        }

        let update = pending
            .get_mut(&change_id)
            .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "pending change update missing"))?;
        update.entry.heads.retain(|h| *h != *head);
        if update.entry.heads.is_empty() {
            update.entry.state = ChangeState::Abandoned;
        }
    }

    let mut mutations = Vec::with_capacity(pending.len());
    let mut abandoned = Vec::new();
    let mut remaining = Vec::new();

    for change_id in order {
        let update = pending
            .remove(&change_id)
            .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "pending change update missing"))?;
        let encoded = encode_change_entry(&update.entry)?;
        mutations.push(FactMutation {
            table: FactTable::Changes,
            key: change_key(&change_id).to_vec(),
            expected: FactExpectation::Value(update.initial_bytes),
            value: Some(encoded),
        });

        if update.entry.heads.is_empty() {
            abandoned.push(change_id);
        } else {
            remaining.push((change_id, update.entry.heads.len()));
        }
    }

    store.publish(Vec::new(), &mutations).map_err(store_error)?;

    Ok(AbandonResult {
        abandoned,
        remaining,
    })
}

struct PendingChangeUpdate {
    initial_bytes: Vec<u8>,
    entry: ChangeEntry,
}

fn load_change_update(
    store: &Store,
    change_id: &ChangeId,
) -> Result<PendingChangeUpdate, CoreError> {
    let key = change_key(change_id);
    let initial_bytes = store.fact(FactTable::Changes, &key)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("change {change_id} is not stored"),
        )
    })?;
    let entry = decode_change_entry(store, change_id, &initial_bytes)?;
    Ok(PendingChangeUpdate {
        initial_bytes,
        entry,
    })
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
    use crate::ids::{HashKind, Oid};
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
                "ruk-abandon-test-{}-{}-{tag}",
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
    fn abandon_single_head_marks_change_abandoned() {
        let fixture = Fixture::new("single");
        let tree_a = fixture.tree(b"a");
        let created = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_a,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_000),
                committer: signature("Alice", 1_700_000_000),
                message: ByteString::from("Commit 1"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create commit");

        let result = abandon(
            &fixture.store,
            AbandonRequest {
                heads: vec![created.head],
            },
        )
        .expect("abandon head");

        assert_eq!(result.abandoned, vec![created.change_id]);
        assert!(result.remaining.is_empty());

        let key = change_key(&created.change_id);
        let raw = fixture
            .store
            .fact(FactTable::Changes, &key)
            .expect("fact read")
            .expect("change row exists");
        let entry: ChangeEntry = crate::store::decode("change entry", &raw).expect("decode");
        assert_eq!(entry.state, ChangeState::Abandoned);
        assert!(entry.heads.is_empty());

        let records = Records::new(&fixture.store);
        assert!(
            records
                .get_commit(&created.head)
                .expect("get commit")
                .is_some()
        );
        let oid = created.head.as_git().copied().expect("git oid");
        assert!(fixture.store.object_len(oid).expect("object len").is_some());
    }

    #[test]
    fn abandon_one_head_of_divergent_change_leaves_other_head_active() {
        let fixture = Fixture::new("divergent");
        let tree_a = fixture.tree(b"a");
        let tree_b = fixture.tree(b"b");

        let c1 = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_a,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_000),
                committer: signature("Alice", 1_700_000_000),
                message: ByteString::from("Commit 1"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create commit 1");

        let c2 = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_b,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_001),
                committer: signature("Alice", 1_700_000_001),
                message: ByteString::from("Commit 2"),
                change_id: Some(c1.change_id),
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create commit 2");

        let result = abandon(
            &fixture.store,
            AbandonRequest {
                heads: vec![c1.head],
            },
        )
        .expect("abandon c1");

        assert!(result.abandoned.is_empty());
        assert_eq!(result.remaining, vec![(c1.change_id, 1)]);

        let records = Records::new(&fixture.store);
        let entry = records
            .get_change(&c1.change_id)
            .expect("get change")
            .expect("change exists");
        assert_eq!(entry.state, ChangeState::Active);
        assert_eq!(entry.heads, vec![c2.head]);
    }

    #[test]
    fn abandon_multiple_heads_across_changes() {
        let fixture = Fixture::new("multi");
        let tree_a = fixture.tree(b"a");
        let tree_b = fixture.tree(b"b");
        let tree_c = fixture.tree(b"c");

        let ca = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_a,
                parents: Vec::new(),
                author: signature("Alice", 1_700_000_000),
                committer: signature("Alice", 1_700_000_000),
                message: ByteString::from("Commit A"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create ca");

        let cb1 = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_b,
                parents: Vec::new(),
                author: signature("Bob", 1_700_000_000),
                committer: signature("Bob", 1_700_000_000),
                message: ByteString::from("Commit B1"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create cb1");

        let cb2 = create_commit(
            &fixture.store,
            NewRequest {
                tree: tree_c,
                parents: Vec::new(),
                author: signature("Bob", 1_700_000_001),
                committer: signature("Bob", 1_700_000_001),
                message: ByteString::from("Commit B2"),
                change_id: Some(cb1.change_id),
                predecessor: None,
                provenance: None,
            },
        )
        .expect("create cb2");

        let result = abandon(
            &fixture.store,
            AbandonRequest {
                heads: vec![ca.head, cb1.head],
            },
        )
        .expect("abandon ca and cb1");

        assert_eq!(result.abandoned, vec![ca.change_id]);
        assert_eq!(result.remaining, vec![(cb1.change_id, 1)]);

        let records = Records::new(&fixture.store);
        let entry_b = records
            .get_change(&cb1.change_id)
            .expect("get change")
            .expect("change exists");
        assert_eq!(entry_b.state, ChangeState::Active);
        assert_eq!(entry_b.heads, vec![cb2.head]);
    }

    #[test]
    fn abandon_refuses_unstored_commit() {
        let fixture = Fixture::new("unstored");
        let unstored = Head::Git {
            oid: Oid::from_bytes(&[0xaa; 20]).expect("oid"),
        };
        let err = abandon(
            &fixture.store,
            AbandonRequest {
                heads: vec![unstored],
            },
        )
        .expect_err("unstored commit must fail");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
