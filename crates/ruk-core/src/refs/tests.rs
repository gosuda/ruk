//! Real-store adversarial tests for store-backed refs, transaction preparation,
//! native ref conflicts, and append-only reflogs.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::bytes::ByteString;
use crate::conflict::{Signature, TzOffset};
use crate::ids::{HashKind, Oid};
use crate::merge::Merge;
use crate::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use crate::store::{
    EventContext, EventSource, FactExpectation, FactMutation, FactTable, PreparationBudget, Store,
};

struct TestStore {
    root: PathBuf,
    store: Store,
}

impl TestStore {
    fn new(tag: &str, kind: HashKind) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ruk-refs-test-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::create(&root, kind, budget).expect("create test store");
        Self { root, store }
    }

    fn store(&self) -> &Store {
        &self.store
    }

    fn publish_mutations(&self, facts: &[FactMutation]) {
        self.store
            .publish(
                Vec::new(),
                facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish test mutations");
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn test_oid(kind: HashKind, seed: &[u8]) -> Oid {
    kind.hash_git_object("blob", seed).expect("valid oid")
}

fn test_signature(name: &str, email: &str, stamp: i64) -> Signature {
    Signature {
        name: ByteString::from(name),
        email: ByteString::from(email),
        timestamp: stamp,
        offset: TzOffset::new(false, 0).expect("canonical +0000 tz offset"),
    }
}

fn check_and_prepare(
    store: &Store,
    transaction: &RefTransaction,
) -> Result<PreparedRefTransaction, CoreError> {
    transaction.check(&StoreRefs::new(store))?;
    prepare_checked_transaction(store, transaction)
}

#[test]
fn test_exact_lookup_and_ordered_seek_with_distractor_refs() {
    let ts = TestStore::new("seek-distractors", HashKind::Sha1);
    let store = ts.store();

    let names = [
        "refs/heads/a",
        "refs/heads/alpha",
        "refs/heads/b",
        "refs/heads/beta",
        "refs/heads/feature/one",
        "refs/heads/feature/two",
        "refs/heads/main",
        "refs/heads/master",
        "refs/heads/z",
        "refs/remotes/origin/feature",
        "refs/remotes/origin/main",
        "refs/tags/v0.1",
        "refs/tags/v1.0",
        "refs/tags/v2.0",
    ];

    let mut expected_refs = Vec::new();
    let mut mutations = Vec::new();

    for (i, name_str) in names.iter().enumerate() {
        let name = RefName::new(name_str.as_bytes()).expect("valid name");
        let oid = test_oid(HashKind::Sha1, format!("blob-{i}").as_bytes());
        let target = RefTarget::Direct(oid);
        let encoded = crate::store::encode("ref target", &target).expect("encode target");
        mutations.push(FactMutation {
            table: FactTable::Refs,
            key: name.as_bytes().to_vec(),
            expected: FactExpectation::Absent,
            value: Some(encoded),
        });
        expected_refs.push((name, target));
    }

    ts.publish_mutations(&mutations);

    let reader = StoreRefs::new(store);

    // Exact lookups
    for (name, expected_target) in &expected_refs {
        let found = reader.get(name).expect("get ref");
        assert_eq!(found.as_ref(), Some(expected_target));
    }

    // Missing ref returns None
    let missing = RefName::new(b"refs/heads/missing").expect("valid name");
    assert_eq!(reader.get(&missing).expect("get missing"), None);

    // Inclusive seek: exact matches
    for (name, expected_target) in &expected_refs {
        let seek_res = reader.seek(name.as_bytes()).expect("seek exact");
        assert_eq!(seek_res, Some((name.clone(), expected_target.clone())));
    }

    // Inclusive seek: prefix / between items
    let seek_alpha = reader.seek(b"refs/heads/al").expect("seek al");
    assert_eq!(
        seek_alpha.map(|(n, _)| n),
        Some(RefName::new(b"refs/heads/alpha").unwrap())
    );

    let seek_m = reader.seek(b"refs/heads/m").expect("seek m");
    assert_eq!(
        seek_m.map(|(n, _)| n),
        Some(RefName::new(b"refs/heads/main").unwrap())
    );

    let seek_empty = reader.seek(b"").expect("seek empty");
    assert_eq!(
        seek_empty.map(|(n, _)| n),
        Some(RefName::new(b"refs/heads/a").unwrap())
    );

    let seek_past = reader.seek(b"refs/zzz").expect("seek past end");
    assert_eq!(seek_past, None);

    // Bounded paging: page in chunks of 4
    let mut paged = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let page = page_refs(store, cursor.as_deref(), 4).expect("page refs");
        assert!(page.entries.len() <= 4);
        for entry in page.entries {
            cursor = Some(entry.name.as_bytes().to_vec());
            paged.push((entry.name, entry.target));
        }
        if !page.more {
            break;
        }
    }
    assert_eq!(paged, expected_refs);
}

#[test]
fn test_stale_expected_target() {
    let ts = TestStore::new("stale-target", HashKind::Sha1);
    let store = ts.store();

    let name = RefName::new(b"refs/heads/main").expect("name");
    let oid1 = test_oid(HashKind::Sha1, b"oid1");
    let oid2 = test_oid(HashKind::Sha1, b"oid2");
    let oid3 = test_oid(HashKind::Sha1, b"oid3");

    // Initially create refs/heads/main -> oid1
    let prep1 = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: name.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid1)),
            }],
        )
        .unwrap(),
    )
    .expect("prep1");
    ts.publish_mutations(prep1.mutations());

    // Expecting Absent when Present -> Stale
    let stale_absent = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: name.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid2)),
            }],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            stale_absent,
            Err(CoreError {
                code: ErrorCode::EStale,
                ..
            })
        ),
        "expected EStale, got {stale_absent:?}"
    );

    // Expecting oid3 when current is oid1 -> Stale
    let stale_present = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: name.clone(),
                expected: RefExpect::Present(RefTarget::Direct(oid3)),
                change: RefChange::Set(RefTarget::Direct(oid2)),
            }],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            stale_present,
            Err(CoreError {
                code: ErrorCode::EStale,
                ..
            })
        ),
        "expected EStale, got {stale_present:?}"
    );

    // Store state remains oid1
    assert_eq!(
        StoreRefs::new(store).get(&name).unwrap(),
        Some(RefTarget::Direct(oid1))
    );
}

#[test]
fn test_symbolic_loop_and_directory_file_collisions() {
    let ts = TestStore::new("collisions-and-loops", HashKind::Sha1);
    let store = ts.store();

    let oid = test_oid(HashKind::Sha1, b"blob");

    // 1. Directory/file collision: parent exists, cannot create child
    let parent = RefName::new(b"refs/heads/dir").expect("name");
    let child = RefName::new(b"refs/heads/dir/child").expect("name");

    let prep_parent = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: parent.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid)),
            }],
        )
        .unwrap(),
    )
    .expect("prep parent");
    ts.publish_mutations(prep_parent.mutations());

    let collide_child = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: child.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid)),
            }],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            collide_child,
            Err(CoreError {
                code: ErrorCode::EInvalid,
                ..
            })
        ),
        "expected collision error, got {collide_child:?}"
    );

    // 2. Directory/file collision: child exists, cannot create parent
    let child2 = RefName::new(b"refs/heads/tree/leaf").expect("name");
    let parent2 = RefName::new(b"refs/heads/tree").expect("name");

    let prep_child2 = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: child2.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid)),
            }],
        )
        .unwrap(),
    )
    .expect("prep child2");
    ts.publish_mutations(prep_child2.mutations());

    let collide_parent2 = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: parent2.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid)),
            }],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            collide_parent2,
            Err(CoreError {
                code: ErrorCode::EInvalid,
                ..
            })
        ),
        "expected collision error, got {collide_parent2:?}"
    );

    // 3. Symbolic loop: a -> b, b -> a in same transaction
    let sym_a = RefName::new(b"refs/heads/sym-a").expect("name");
    let sym_b = RefName::new(b"refs/heads/sym-b").expect("name");

    let loop_tx = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![
                RefUpdate {
                    name: sym_a.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(sym_b.clone())),
                },
                RefUpdate {
                    name: sym_b.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(sym_a.clone())),
                },
            ],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            loop_tx,
            Err(CoreError {
                code: ErrorCode::EInvalid,
                ..
            })
        ),
        "expected cycle error, got {loop_tx:?}"
    );

    // 4. Symbolic chain > MAX_SYMREF_LINKS (4)
    let s0 = RefName::new(b"refs/heads/s0").unwrap();
    let s1 = RefName::new(b"refs/heads/s1").unwrap();
    let s2 = RefName::new(b"refs/heads/s2").unwrap();
    let s3 = RefName::new(b"refs/heads/s3").unwrap();
    let s4 = RefName::new(b"refs/heads/s4").unwrap();
    let s5 = RefName::new(b"refs/heads/s5").unwrap();

    let deep_tx = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![
                RefUpdate {
                    name: s0.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(s1.clone())),
                },
                RefUpdate {
                    name: s1.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(s2.clone())),
                },
                RefUpdate {
                    name: s2.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(s3.clone())),
                },
                RefUpdate {
                    name: s3.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(s4.clone())),
                },
                RefUpdate {
                    name: s4.clone(),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(RefTarget::Symbolic(s5.clone())),
                },
            ],
        )
        .unwrap(),
    );
    assert!(
        matches!(
            deep_tx,
            Err(CoreError {
                code: ErrorCode::EInvalid,
                ..
            })
        ),
        "expected too-deep error, got {deep_tx:?}"
    );
}

#[test]
fn test_same_transaction_deleting_conflicting_path_before_creation() {
    let ts = TestStore::new("delete-before-create", HashKind::Sha1);
    let store = ts.store();

    let old_name = RefName::new(b"refs/heads/sub").expect("name");
    let new_name = RefName::new(b"refs/heads/sub/nested").expect("name");
    let oid1 = test_oid(HashKind::Sha1, b"oid1");
    let oid2 = test_oid(HashKind::Sha1, b"oid2");

    // Create initial refs/heads/sub
    let prep_init = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: old_name.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid1)),
            }],
        )
        .unwrap(),
    )
    .expect("prep init");
    ts.publish_mutations(prep_init.mutations());

    // Single transaction: delete refs/heads/sub AND create refs/heads/sub/nested
    let tx = RefTransaction::new(
        HashKind::Sha1,
        vec![
            RefUpdate {
                name: old_name.clone(),
                expected: RefExpect::Present(RefTarget::Direct(oid1)),
                change: RefChange::Delete,
            },
            RefUpdate {
                name: new_name.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid2)),
            },
        ],
    )
    .unwrap();

    let prep_rename = check_and_prepare(store, &tx).expect("rename tx must succeed");
    assert_eq!(prep_rename.mutations().len(), 2);

    // Verify mutations capture exact expected values
    assert!(matches!(
        prep_rename.mutations()[0].expected,
        FactExpectation::Value(_)
    ));
    assert_eq!(prep_rename.mutations()[0].value, None);
    assert_eq!(prep_rename.mutations()[1].expected, FactExpectation::Absent);
    assert!(prep_rename.mutations()[1].value.is_some());

    ts.publish_mutations(prep_rename.mutations());

    // Verify post-publication state
    let reader = StoreRefs::new(store);
    assert_eq!(reader.get(&old_name).unwrap(), None);
    assert_eq!(
        reader.get(&new_name).unwrap(),
        Some(RefTarget::Direct(oid2))
    );
}

#[test]
fn test_no_effects_on_rejected_preparation() {
    let ts = TestStore::new("no-effects", HashKind::Sha1);
    let store = ts.store();

    let name = RefName::new(b"refs/heads/main").expect("name");
    let oid1 = test_oid(HashKind::Sha1, b"oid1");
    let oid2 = test_oid(HashKind::Sha1, b"oid2");

    // Establish baseline
    let prep_init = check_and_prepare(
        store,
        &RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: name.clone(),
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(oid1)),
            }],
        )
        .unwrap(),
    )
    .expect("init");
    ts.publish_mutations(prep_init.mutations());

    // Run rejected transaction (stale expectation)
    let rejected_tx = RefTransaction::new(
        HashKind::Sha1,
        vec![RefUpdate {
            name: name.clone(),
            expected: RefExpect::Present(RefTarget::Direct(oid2)),
            change: RefChange::Set(RefTarget::Direct(oid2)),
        }],
    )
    .unwrap();
    let res = check_and_prepare(store, &rejected_tx);
    assert!(res.is_err());

    // Assert store is completely untouched
    let reader = StoreRefs::new(store);
    assert_eq!(reader.get(&name).unwrap(), Some(RefTarget::Direct(oid1)));
}

#[test]
fn test_malformed_stored_rows_quarantine() {
    let ts = TestStore::new("quarantine", HashKind::Sha1);
    let store = ts.store();

    // 1. Corrupt postcard bytes in FactTable::Refs
    let corrupt_name = RefName::new(b"refs/heads/corrupted").expect("name");
    let bad_bytes = b"garbage_not_postcard".to_vec();
    ts.publish_mutations(&[FactMutation {
        table: FactTable::Refs,
        key: corrupt_name.as_bytes().to_vec(),
        expected: FactExpectation::Absent,
        value: Some(bad_bytes),
    }]);

    assert!(!store.quarantine(), "store not quarantined yet");

    // Reading the corrupted ref triggers quarantine
    let reader = StoreRefs::new(store);
    let err = reader.get(&corrupt_name).unwrap_err();
    assert_eq!(err.code, ErrorCode::ECorrupt);

    // Store is now quarantined!
    assert!(store.quarantine());

    // Subsequent operations refuse
    let valid_name = RefName::new(b"refs/heads/other").unwrap();
    let refused = reader.get(&valid_name).unwrap_err();
    assert_eq!(refused.code, ErrorCode::ECorrupt);
}

#[test]
fn test_wrong_hash_kind_quarantine() {
    let ts = TestStore::new("hash-kind-quarantine", HashKind::Sha1);
    let store = ts.store();

    // A Sha256 Oid stored in a Sha1 store
    let sha256_oid = test_oid(HashKind::Sha256, b"sha256-payload");
    let target = RefTarget::Direct(sha256_oid);
    let encoded = crate::store::encode("ref target", &target).expect("encode");

    let name = RefName::new(b"refs/heads/bad-hash").expect("name");
    ts.publish_mutations(&[FactMutation {
        table: FactTable::Refs,
        key: name.as_bytes().to_vec(),
        expected: FactExpectation::Absent,
        value: Some(encoded),
    }]);

    let reader = StoreRefs::new(store);
    let err = reader.get(&name).unwrap_err();
    assert_eq!(err.code, ErrorCode::ECorrupt);
    assert!(store.quarantine());
}

#[test]
fn test_byte_exact_conflict_recovery_and_bounded_continuation() {
    let ts = TestStore::new("conflicts", HashKind::Sha1);
    let store = ts.store();

    let name1 = RefName::new(b"refs/heads/c1").expect("name");
    let name2 = RefName::new(b"refs/heads/c2").expect("name");

    let oid_a = test_oid(HashKind::Sha1, b"term-a");
    let oid_b = test_oid(HashKind::Sha1, b"term-b");
    let oid_base = test_oid(HashKind::Sha1, b"term-base");

    let conflict1 = Merge::from_vec(vec![Some(oid_a), Some(oid_base), Some(oid_b)]);
    let conflict2 = Merge::from_vec(vec![Some(oid_b), Some(oid_base), None]);

    // Prepare set ref conflicts
    let m1 = prepare_set_ref_conflict(store, &name1, &conflict1).expect("set c1");
    let m2 = prepare_set_ref_conflict(store, &name2, &conflict2).expect("set c2");
    ts.publish_mutations(&[m1, m2]);

    // Read back exact conflicts
    let read1 = get_ref_conflict(store, &name1)
        .expect("read c1")
        .expect("present");
    assert_eq!(read1, conflict1);

    let read2 = get_ref_conflict(store, &name2)
        .expect("read c2")
        .expect("present");
    assert_eq!(read2, conflict2);

    // Bounded paging: page 1 entry at a time
    let page1 = page_ref_conflicts(store, None, 1).expect("page 1");
    assert_eq!(page1.entries.len(), 1);
    assert!(page1.more);
    assert_eq!(page1.entries[0].name, name1);
    assert_eq!(page1.entries[0].conflict, conflict1);

    let page2 = page_ref_conflicts(store, Some(name1.as_bytes()), 1).expect("page 2");
    assert_eq!(page2.entries.len(), 1);
    assert!(!page2.more);
    assert_eq!(page2.entries[0].name, name2);
    assert_eq!(page2.entries[0].conflict, conflict2);

    // Clear conflict
    let clear_m1 = prepare_clear_ref_conflict(store, &name1).expect("clear c1");
    ts.publish_mutations(&[clear_m1]);

    assert_eq!(get_ref_conflict(store, &name1).unwrap(), None);
    assert_eq!(get_ref_conflict(store, &name2).unwrap(), Some(conflict2));
}

#[test]
fn test_byte_exact_reflog_recovery_and_bounded_continuation() {
    let ts = TestStore::new("reflogs", HashKind::Sha1);
    let store = ts.store();

    let main = RefName::new(b"refs/heads/main").expect("name");
    let main_extra = RefName::new(b"refs/heads/main-extra").expect("name");
    let feat = RefName::new(b"refs/heads/feature").expect("name");

    let oid1 = test_oid(HashKind::Sha1, b"oid1");
    let oid2 = test_oid(HashKind::Sha1, b"oid2");
    let oid3 = test_oid(HashKind::Sha1, b"oid3");

    let committer = test_signature("Alice Committer", "alice@example.com", 1700000000);

    // 1. Initial creation of main (unborn old_oid: None)
    let k1 = ReflogKey::new(main.clone(), OperationId(10), 0);
    let r1 = ReflogRecord {
        operation: OperationId(10),
        old_oid: None,
        new_oid: Some(oid1),
        committer: committer.clone(),
        message: ByteString::from("branch: created from HEAD"),
    };

    // 2. Fast-forward main
    let k2 = ReflogKey::new(main.clone(), OperationId(11), 0);
    let r2 = ReflogRecord {
        operation: OperationId(11),
        old_oid: Some(oid1),
        new_oid: Some(oid2),
        committer: committer.clone(),
        message: ByteString::from("commit: update core logic"),
    };

    // 3. Rebase step on main (same op, ord 0 and 1)
    let k3 = ReflogKey::new(main.clone(), OperationId(12), 0);
    let r3 = ReflogRecord {
        operation: OperationId(12),
        old_oid: Some(oid2),
        new_oid: Some(oid3),
        committer: committer.clone(),
        message: ByteString::from("rebase: step 1"),
    };

    let k4 = ReflogKey::new(main.clone(), OperationId(12), 1);
    let r4 = ReflogRecord {
        operation: OperationId(12),
        old_oid: Some(oid3),
        new_oid: Some(oid1),
        committer: committer.clone(),
        message: ByteString::from("rebase: step 2"),
    };

    // 4. Branch deletion of main (deleted new_oid: None)
    let k5 = ReflogKey::new(main.clone(), OperationId(13), 0);
    let r5 = ReflogRecord {
        operation: OperationId(13),
        old_oid: Some(oid1),
        new_oid: None,
        committer: committer.clone(),
        message: ByteString::from("branch: deleted"),
    };

    // Distractor reflogs
    let k_dist1 = ReflogKey::new(main_extra.clone(), OperationId(10), 0);
    let r_dist1 = ReflogRecord {
        operation: OperationId(10),
        old_oid: None,
        new_oid: Some(oid2),
        committer: committer.clone(),
        message: ByteString::from("distractor main-extra"),
    };

    let k_dist2 = ReflogKey::new(feat.clone(), OperationId(10), 0);
    let r_dist2 = ReflogRecord {
        operation: OperationId(10),
        old_oid: None,
        new_oid: Some(oid3),
        committer: committer.clone(),
        message: ByteString::from("distractor feature"),
    };

    let mut mutations = Vec::new();
    for (k, r) in [
        (&k1, &r1),
        (&k2, &r2),
        (&k3, &r3),
        (&k4, &r4),
        (&k5, &r5),
        (&k_dist1, &r_dist1),
        (&k_dist2, &r_dist2),
    ] {
        mutations.push(prepare_append_reflog(store, k, r).expect("append reflog"));
    }
    ts.publish_mutations(&mutations);

    // Exact read verification
    let read_r1 = get_reflog(store, &k1).expect("get k1").expect("present");
    assert_eq!(read_r1, r1);
    let read_r5 = get_reflog(store, &k5).expect("get k5").expect("present");
    assert_eq!(read_r5, r5);

    // Bounded per-ref iteration: page refs/heads/main in limits of 2
    let page1 = page_reflogs(store, &main, None, 2).expect("page 1");
    assert_eq!(page1.entries.len(), 2);
    assert!(page1.more);
    assert_eq!(page1.entries[0].key, k1);
    assert_eq!(page1.entries[0].record, r1);
    assert_eq!(page1.entries[1].key, k2);
    assert_eq!(page1.entries[1].record, r2);

    let page2 = page_reflogs(store, &main, Some(&k2), 2).expect("page 2");
    assert_eq!(page2.entries.len(), 2);
    assert!(page2.more);
    assert_eq!(page2.entries[0].key, k3);
    assert_eq!(page2.entries[0].record, r3);
    assert_eq!(page2.entries[1].key, k4);
    assert_eq!(page2.entries[1].record, r4);

    let page3 = page_reflogs(store, &main, Some(&k4), 2).expect("page 3");
    assert_eq!(page3.entries.len(), 1);
    assert!(!page3.more);
    assert_eq!(page3.entries[0].key, k5);
    assert_eq!(page3.entries[0].record, r5);

    // Verify it did NOT bleed into main-extra!
    let page_empty = page_reflogs(store, &main, Some(&k5), 2).expect("page after end");
    assert_eq!(page_empty.entries.len(), 0);
    assert!(!page_empty.more);

    // Row pair bound check (> 16 MiB)
    let huge_msg = vec![b'x'; MAX_CONTROL_FRAME_BYTES];
    let huge_record = ReflogRecord {
        operation: OperationId(99),
        old_oid: None,
        new_oid: Some(oid1),
        committer: committer.clone(),
        message: ByteString::from(huge_msg),
    };
    let huge_key = ReflogKey::new(main.clone(), OperationId(99), 0);
    let err = prepare_append_reflog(store, &huge_key, &huge_record).unwrap_err();
    assert_eq!(err.code, ErrorCode::ELimit);
}

#[test]
fn released_tag_marker_round_trips_through_postcard() {
    use crate::protocol::Timestamp;
    let marker = ReleasedTagMarker {
        owner_release_id: "rel-1".to_string(),
        target_oid: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
        frozen_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
    };
    let bytes = crate::store::encode("released_tags", &marker).expect("encode marker");
    let decoded: ReleasedTagMarker =
        crate::store::decode("released_tags", &bytes).expect("decode marker");
    assert_eq!(decoded, marker);
}

fn released_marker(owner: &str, target: Oid) -> ReleasedTagMarker {
    ReleasedTagMarker {
        owner_release_id: owner.to_owned(),
        target_oid: target,
        frozen_at: crate::protocol::Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
    }
}

fn freeze_tag(ts: &TestStore, name: &RefName, marker: &ReleasedTagMarker) {
    let freeze = prepare_release_freeze(ts.store(), name, marker).expect("prepare freeze");
    ts.publish_mutations(&[freeze]);
}

#[test]
fn released_tag_freeze_is_create_if_absent_and_idempotent_per_owner_and_target() {
    let ts = TestStore::new("released-freeze-create", HashKind::Sha1);
    let store = ts.store();
    let name = RefName::new("refs/tags/v1").expect("tag name");
    let target = test_oid(HashKind::Sha1, b"release target");
    let marker = released_marker("rel-1", target);

    let freeze = prepare_release_freeze(store, &name, &marker).expect("prepare freeze");
    assert_eq!(freeze.table, FactTable::ReleasedTags);
    assert!(matches!(freeze.expected, FactExpectation::Absent));
    ts.publish_mutations(&[freeze]);
    assert_eq!(
        released_tag_marker(store, &name).expect("read marker"),
        Some(marker.clone())
    );

    let retry = prepare_release_freeze(store, &name, &marker).expect("retry prepare");
    assert!(
        matches!(retry.expected, FactExpectation::Value(_)),
        "same owner and target is an idempotent, row-guarded write"
    );
}

#[test]
fn released_tag_freeze_refuses_another_owner_or_another_target() {
    let ts = TestStore::new("released-freeze-refuse", HashKind::Sha1);
    let store = ts.store();
    let name = RefName::new("refs/tags/v1").expect("tag name");
    let target = test_oid(HashKind::Sha1, b"release target");
    freeze_tag(&ts, &name, &released_marker("rel-1", target));

    let other_owner = prepare_release_freeze(store, &name, &released_marker("rel-2", target))
        .expect_err("another owner is refused");
    assert_eq!(other_owner.code, ErrorCode::EForbidden);
    assert!(
        other_owner.message.contains("rel-1"),
        "{}",
        other_owner.message
    );

    let moved = test_oid(HashKind::Sha1, b"moved target");
    let other_target = prepare_release_freeze(store, &name, &released_marker("rel-1", moved))
        .expect_err("same owner at another target is refused");
    assert_eq!(other_target.code, ErrorCode::EForbidden);
    assert!(
        other_target.message.contains("rel-1"),
        "{}",
        other_target.message
    );
}

#[test]
fn released_tag_clear_is_owner_checked_and_removes_the_row() {
    let ts = TestStore::new("released-freeze-clear", HashKind::Sha1);
    let store = ts.store();
    let name = RefName::new("refs/tags/v1").expect("tag name");
    let target = test_oid(HashKind::Sha1, b"release target");
    freeze_tag(&ts, &name, &released_marker("rel-1", target));

    let refused =
        prepare_release_unfreeze(store, &name, "rel-2").expect_err("another owner cannot clear");
    assert_eq!(refused.code, ErrorCode::EForbidden);
    assert!(refused.message.contains("rel-1"), "{}", refused.message);

    let clear = prepare_release_unfreeze(store, &name, "rel-1").expect("owner clear prepares");
    ts.publish_mutations(&[clear]);
    assert_eq!(
        released_tag_marker(store, &name).expect("read marker"),
        None
    );
    let absent =
        prepare_release_unfreeze(store, &name, "rel-1").expect("clear without a row prepares");
    assert!(
        matches!(absent.expected, FactExpectation::Absent) && absent.value.is_none(),
        "no row is a no-op guarded by absence"
    );
}

#[test]
fn check_tag_unfrozen_refuses_only_while_a_marker_is_live() {
    let ts = TestStore::new("released-freeze-check", HashKind::Sha1);
    let store = ts.store();
    let name = RefName::new("refs/tags/v1").expect("tag name");
    let branch = RefName::new("refs/heads/main").expect("branch name");
    let target = test_oid(HashKind::Sha1, b"release target");

    check_tag_unfrozen(store, &name).expect("no marker passes");
    assert!(
        tag_freeze_guards(store, &[&branch])
            .expect("guards for a branch")
            .is_empty(),
        "names outside refs/tags/ carry no guard"
    );

    freeze_tag(&ts, &name, &released_marker("rel-1", target));
    let err = check_tag_unfrozen(store, &name).expect_err("frozen tag refuses");
    assert_eq!(err.code, ErrorCode::EForbidden);
    assert_eq!(
        err.message,
        "tag `refs/tags/v1` is frozen by release `rel-1`"
    );
    let refused = tag_freeze_guards(store, &[&name]).expect_err("guard refuses a frozen tag");
    assert_eq!(refused.code, ErrorCode::EForbidden);
}

#[test]
fn tag_freeze_guard_fails_a_publish_that_raced_a_freeze() {
    let ts = TestStore::new("released-freeze-race", HashKind::Sha1);
    let store = ts.store();
    let name = RefName::new("refs/tags/v1").expect("tag name");
    let target = test_oid(HashKind::Sha1, b"tag commit");

    let guards = tag_freeze_guards(store, &[&name]).expect("guard while unfrozen");
    assert_eq!(guards.len(), 1);
    let transaction = RefTransaction::new(
        HashKind::Sha1,
        vec![RefUpdate {
            name: name.clone(),
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(target)),
        }],
    )
    .expect("tag transaction");
    let facts = check_and_prepare(store, &transaction)
        .expect("prepare tag ref")
        .into_mutations();
    freeze_tag(&ts, &name, &released_marker("rel-1", target));
    let err = store
        .publish(
            Vec::new(),
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect_err("the stale guard fails the publish");
    assert_eq!(err.code(), ErrorCode::EStale);
    assert_eq!(
        StoreRefs::new(store).get(&name).expect("read ref"),
        None,
        "a refused publish creates no ref"
    );
}
