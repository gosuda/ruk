//! Behavioral and adversarial real-Store tests for records.
//!
//! Covers all required evidence items from `local://ruk-native-records-contract.md`:
//! 1. Exact imported-byte preservation
//! 2. Git vs native conflict eligibility
//! 3. SHA-1 native-key fixed 32-byte identity
//! 4. Imported divergence versus trusted local supersession
//! 5. Stable absent-change-id reimport
//! 6. Wrong expected head / CAS failure
//! 7. All-or-nothing batch conflict
//! 8. Bounded high-history paging and corrupt row quarantine

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::codec::encode_change_entry;
use super::import::ImportBatch;
use super::keys::{change_key, decode_head_key, head_key, history_key};
use super::reader::Records;
use super::types::{ChangeEntry, ChangeState, ImportOutcome, RecordPageBudget};
use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::NativeCommitInput;
use crate::conflict::{Signature, TzOffset};
use crate::error::ErrorCode;
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};
use crate::merge::Merge;
use crate::store::types::{FactExpectation, FactMutation, FactTable};
use crate::store::{PreparationBudget, Store, StoreError};

struct TestFixture {
    root: std::path::PathBuf,
    store: Store,
}

impl TestFixture {
    fn new(tag: &str, kind: HashKind) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ruk-records-test-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::create(&root, kind, budget).expect("create test store");
        Self { root, store }
    }

    fn store(&self) -> &Store {
        &self.store
    }

    fn publish(&self, mutations: &[FactMutation]) {
        self.store
            .publish(Vec::new(), mutations)
            .expect("publish mutations");
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn sample_signature(name: &str, stamp: i64) -> Signature {
    Signature {
        name: ByteString::from(name),
        email: ByteString::from(format!("{name}@example.com")),
        timestamp: stamp,
        offset: TzOffset::new(false, 0).expect("canonical +0000 tz offset"),
    }
}

fn sample_oid(kind: HashKind, seed: &[u8]) -> Oid {
    kind.hash_git_object("blob", seed).expect("valid oid")
}

// ---------------------------------------------------------------------------
// 1. Exact Imported-Byte Preservation
// ---------------------------------------------------------------------------

#[test]
fn test_exact_imported_byte_preservation() {
    let fixture = TestFixture::new("byte-preservation", HashKind::Sha1);
    let records = Records::new(fixture.store());

    // Construct a raw Git commit payload with preserved header ordering,
    // multi-line headers, and non-UTF-8 characters.
    let tree_oid = sample_oid(HashKind::Sha1, b"tree-1");
    let parent_oid = sample_oid(HashKind::Sha1, b"parent-1");
    let change_id = ChangeId::generate();

    let mut payload = Vec::new();
    payload.extend_from_slice(b"tree ");
    payload.extend_from_slice(tree_oid.to_hex().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"parent ");
    payload.extend_from_slice(parent_oid.to_hex().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"author Arbitrary Name <author@example.com> 1700000000 +0000\n");
    payload.extend_from_slice(b"committer Arbitrary Name <author@example.com> 1700000000 +0000\n");
    // Non-alphabetical header order: z-custom before a-custom
    payload.extend_from_slice(b"z-custom preserved first\n");
    payload.extend_from_slice(b"change-id ");
    payload.extend_from_slice(change_id.to_reverse_hex().as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"a-custom preserved second\n");
    payload.extend_from_slice(b"gpgsig -----BEGIN SIGNATURE-----\n");
    payload.extend_from_slice(b" multi-line sig line 1\n");
    payload.extend_from_slice(b" multi-line sig line 2\n");
    payload.extend_from_slice(b" -----END SIGNATURE-----\n");
    payload.push(b'\n');
    payload.extend_from_slice(b"Preserved commit message with \xFF non-utf8 byte\n");

    let prepared = records
        .prepare_import_git(payload.clone(), None)
        .expect("prepare git import");

    assert_eq!(prepared.change_id, change_id);
    assert!(!prepared.is_divergent);

    // Publish to the store
    fixture
        .store()
        .publish(vec![prepared.prepared_object], &prepared.mutations)
        .expect("publish import");

    // Read back and assert verbatim byte preservation
    let read_back = records
        .get_commit(&prepared.head)
        .expect("read commit")
        .expect("commit exists");

    let stored_payload = read_back.git_payload().expect("git payload exists");
    assert_eq!(stored_payload, payload.as_slice());
}

// ---------------------------------------------------------------------------
// 2. Git vs Native Conflict Eligibility
// ---------------------------------------------------------------------------

#[test]
fn test_git_native_eligibility() {
    let fixture = TestFixture::new("eligibility", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let tree_1 = sample_oid(HashKind::Sha1, b"tree-1");
    let tree_2 = sample_oid(HashKind::Sha1, b"tree-2");
    let tree_3 = sample_oid(HashKind::Sha1, b"tree-3");
    let parent_git = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"parent-git"),
    };

    // Case A: Singleton tree + all Git parents => Git object
    let input_git = NativeCommitInput {
        change_id: ChangeId::generate(),
        tree: Merge::resolved(tree_1),
        parents: vec![parent_git],
        predecessor: None,
        author: sample_signature("Alice", 1700000000),
        committer: sample_signature("Alice", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("Git eligible"),
        provenance: None,
    };
    let prep_git = records
        .prepare_native_commit(input_git)
        .expect("prepare git eligible");
    assert!(prep_git.record.is_exportable());
    assert!(prep_git.head.is_git());

    // Case B: Conflicted tree (3 terms) + Git parent => Native conflict record
    let conflicted_tree = Merge::from_vec(vec![tree_1, tree_2, tree_3]);
    let input_conflicted_tree = NativeCommitInput {
        change_id: ChangeId::generate(),
        tree: conflicted_tree,
        parents: vec![parent_git],
        predecessor: None,
        author: sample_signature("Alice", 1700000000),
        committer: sample_signature("Alice", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("Conflicted tree"),
        provenance: None,
    };
    let prep_conflicted_tree = records
        .prepare_native_commit(input_conflicted_tree)
        .expect("prepare conflicted tree");
    assert!(!prep_conflicted_tree.record.is_exportable());
    assert!(!prep_conflicted_tree.head.is_git());

    // Case C: Singleton tree + Conflicted parent => Native conflict record
    let parent_conflicted = prep_conflicted_tree.head;
    let input_native_parent = NativeCommitInput {
        change_id: ChangeId::generate(),
        tree: Merge::resolved(tree_1),
        parents: vec![parent_conflicted],
        predecessor: None,
        author: sample_signature("Alice", 1700000000),
        committer: sample_signature("Alice", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("Native parent descendant"),
        provenance: None,
    };
    let prep_native_parent = records
        .prepare_native_commit(input_native_parent)
        .expect("prepare native parent descendant");
    assert!(!prep_native_parent.record.is_exportable());
    assert!(!prep_native_parent.head.is_git());
}

// ---------------------------------------------------------------------------
// 3. SHA-1 Native-Key Fixed 32-Byte Identity
// ---------------------------------------------------------------------------

#[test]
fn test_sha1_native_key_fixed32_identity() {
    let fixture = TestFixture::new("fixed32-sha1", HashKind::Sha1);
    let records = Records::new(fixture.store());

    // Native CommitKey with fixed 32 bytes
    let raw_32_bytes = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    let commit_key = CommitKey::from_bytes(&raw_32_bytes).expect("valid 32-byte commit key");
    assert_eq!(commit_key.as_bytes().len(), 32);

    let head = Head::Conflicted { key: commit_key };

    // Key encoding in SHA-1 must preserve all 32 bytes (tag 1 + 32 bytes = 33 bytes)
    let encoded_key = head_key(&head);
    assert_eq!(encoded_key.len(), 33);
    assert_eq!(encoded_key[0], 1);
    assert_eq!(&encoded_key[1..], &raw_32_bytes);

    // Decode back
    let decoded_head = decode_head_key(&encoded_key).expect("decode head key");
    match decoded_head {
        Head::Conflicted { key: decoded_key } => {
            assert_eq!(decoded_key.as_bytes().len(), 32);
            assert_eq!(decoded_key.as_bytes(), &raw_32_bytes);
        }
        Head::Git { .. } => panic!("expected conflicted head"),
    }

    // Verify history key also preserves 32 bytes under SHA-1
    let change_id = ChangeId::generate();
    let hkey = history_key(&change_id, &head);
    assert_eq!(hkey.len(), 16 + 1 + 32);
    let (dec_cid, dec_head) = super::keys::decode_history_key(&hkey).expect("decode history key");
    assert_eq!(dec_cid, change_id);
    assert_eq!(dec_head, head);
}

// ---------------------------------------------------------------------------
// 4. Imported Divergence vs Trusted Local Supersession
// ---------------------------------------------------------------------------

#[test]
fn test_divergence_vs_trusted_supersession() {
    let fixture = TestFixture::new("divergence-vs-supersession", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let tree_1 = sample_oid(HashKind::Sha1, b"tree-1");
    let tree_2 = sample_oid(HashKind::Sha1, b"tree-2");
    let change_id = ChangeId::generate();

    // Step 1: Initial native commit creation for change_id
    let input_1 = NativeCommitInput {
        change_id,
        tree: Merge::resolved(tree_1),
        parents: Vec::new(),
        predecessor: None,
        author: sample_signature("Alice", 1700000000),
        committer: sample_signature("Alice", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("Initial commit"),
        provenance: None,
    };
    let prep_1 = records.prepare_native_commit(input_1).expect("prep 1");
    fixture
        .store()
        .publish(vec![prep_1.prepared_object], &prep_1.mutations)
        .expect("publish 1");

    let entry_1 = records
        .get_change(&change_id)
        .expect("read change")
        .expect("exists");
    assert_eq!(entry_1.heads, vec![prep_1.head]);
    assert!(!entry_1.is_divergent());

    // Step 2: Trusted local rewrite specifying predecessor prep_1.head
    let input_2 = NativeCommitInput {
        change_id,
        tree: Merge::resolved(tree_2),
        parents: Vec::new(),
        predecessor: Some(prep_1.head),
        author: sample_signature("Alice", 1700000001),
        committer: sample_signature("Alice", 1700000001),
        extra_headers: Vec::new(),
        message: ByteString::from("Rewritten commit"),
        provenance: None,
    };
    let prep_2 = records.prepare_native_commit(input_2).expect("prep 2");
    fixture
        .store()
        .publish(vec![prep_2.prepared_object], &prep_2.mutations)
        .expect("publish 2");

    let entry_2 = records
        .get_change(&change_id)
        .expect("read change")
        .expect("exists");
    // Supersession: prep_1.head was replaced by prep_2.head
    assert_eq!(entry_2.heads, vec![prep_2.head]);
    assert!(!entry_2.is_divergent());

    // Step 3: Imported commit with same change_id but different OID -> Divergence!
    let mut import_payload = Vec::new();
    import_payload.extend_from_slice(b"tree ");
    import_payload.extend_from_slice(
        sample_oid(HashKind::Sha1, b"import-tree")
            .to_hex()
            .as_bytes(),
    );
    import_payload.push(b'\n');
    import_payload.extend_from_slice(b"author Bob <bob@example.com> 1700000002 +0000\n");
    import_payload.extend_from_slice(b"committer Bob <bob@example.com> 1700000002 +0000\n");
    import_payload.extend_from_slice(b"change-id ");
    import_payload.extend_from_slice(change_id.to_reverse_hex().as_bytes());
    import_payload.extend_from_slice(b"\n\nImported external work\n");

    let prep_import = records
        .prepare_import_git(import_payload, None)
        .expect("prep import");
    assert!(prep_import.is_divergent);

    fixture
        .store()
        .publish(vec![prep_import.prepared_object], &prep_import.mutations)
        .expect("publish import");

    let entry_3 = records
        .get_change(&change_id)
        .expect("read change")
        .expect("exists");
    assert!(entry_3.is_divergent());
    assert_eq!(entry_3.heads.len(), 2);
    assert!(entry_3.contains_head(&prep_2.head));
    assert!(entry_3.contains_head(&prep_import.head));
}

// ---------------------------------------------------------------------------
// 5. Stable Absent-Change-Id Reimport
// ---------------------------------------------------------------------------

#[test]
fn test_stable_absent_change_id_reimport() {
    let fixture = TestFixture::new("stable-reimport", HashKind::Sha1);
    let records = Records::new(fixture.store());

    // Commit payload without any change-id header
    let mut payload = Vec::new();
    payload.extend_from_slice(b"tree ");
    payload.extend_from_slice(
        sample_oid(HashKind::Sha1, b"plain-tree")
            .to_hex()
            .as_bytes(),
    );
    payload.extend_from_slice(b"\nauthor Carol <carol@example.com> 1700000000 +0000\n");
    payload.extend_from_slice(b"committer Carol <carol@example.com> 1700000000 +0000\n\n");
    payload.extend_from_slice(b"No change-id header in this commit\n");

    // First import: derives a stable change ID from the commit OID.
    let prep_1 = records
        .prepare_import_git(payload.clone(), None)
        .expect("first import");
    let minted_id = prep_1.change_id;
    assert_eq!(
        minted_id,
        ChangeId::from_oid(prep_1.head.as_git().expect("git head")),
        "headerless import derives its change ID from the OID",
    );

    fixture
        .store()
        .publish(vec![prep_1.prepared_object], &prep_1.mutations)
        .expect("publish 1");

    // Verify mapping in FactTable::ImportedChanges
    let mapped_id = records
        .get_imported_change(prep_1.head.as_git().expect("git head"))
        .expect("read imported change")
        .expect("mapping exists");
    assert_eq!(mapped_id, minted_id);

    // Second import of the identical payload: must resolve the exact same ChangeId
    let mut batch = ImportBatch::new(fixture.store());
    let outcome = batch
        .observe_git_payload(payload, None)
        .expect("second import");

    match outcome {
        ImportOutcome::Known { head, change_id } => {
            assert_eq!(head, prep_1.head);
            assert_eq!(change_id, minted_id);
        }
        other => panic!("expected Known outcome on reimport, got {other:?}"),
    }

    let (objects, mutations) = batch.into_parts().expect("finish batch");
    assert!(objects.is_empty(), "known import should stage no objects");
    assert!(
        mutations.is_empty(),
        "known import should emit no mutations"
    );
}

// ---------------------------------------------------------------------------
// 6. Wrong Expected Head / CAS Failure
// ---------------------------------------------------------------------------

#[test]
fn test_wrong_expected_head_and_cas_failure() {
    let fixture = TestFixture::new("wrong-expected-head", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let change_id = ChangeId::generate();
    let tree_1 = sample_oid(HashKind::Sha1, b"t1");
    let wrong_head = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"wrong-head-oid"),
    };

    // Case A: Predecessor head not in change heads fails with E_STALE before publishing
    let input = NativeCommitInput {
        change_id,
        tree: Merge::resolved(tree_1),
        parents: Vec::new(),
        predecessor: Some(wrong_head),
        author: sample_signature("Dan", 1700000000),
        committer: sample_signature("Dan", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("Stale rewrite"),
        provenance: None,
    };

    let err = records
        .prepare_native_commit(input)
        .err()
        .expect("should fail with E_NOT_FOUND or E_STALE");
    assert!(
        err.code == ErrorCode::ENotFound || err.code == ErrorCode::EStale,
        "expected ENotFound or EStale, got {err:?}"
    );

    // Case B: CAS expectation violation in Store
    let key = change_key(&change_id);
    let initial_entry = ChangeEntry::new(ChangeState::Active, wrong_head);
    let initial_bytes = encode_change_entry(&initial_entry).expect("encode");

    // Publish initial entry
    fixture.publish(&[FactMutation {
        table: FactTable::Changes,
        key: key.to_vec(),
        expected: FactExpectation::Absent,
        value: Some(initial_bytes.clone()),
    }]);

    // Mutation with stale expected value must fail in redb transaction
    let stale_mutation = FactMutation {
        table: FactTable::Changes,
        key: key.to_vec(),
        expected: FactExpectation::Value(b"completely-wrong-bytes".to_vec()),
        value: Some(b"new-bytes".to_vec()),
    };
    let result = fixture.store().publish(Vec::new(), &[stale_mutation]);
    assert!(matches!(result, Err(StoreError::StaleFact { .. })));
}

// ---------------------------------------------------------------------------
// 7. All-or-Nothing Batch Conflict
// ---------------------------------------------------------------------------

#[test]
fn test_all_or_nothing_batch_conflict() {
    let fixture = TestFixture::new("all-or-nothing-batch", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let change_id = ChangeId::generate();
    let tree_1 = sample_oid(HashKind::Sha1, b"tree-batch-1");
    let tree_2 = sample_oid(HashKind::Sha1, b"tree-batch-2");

    let mut preparer = records.batch_preparer();

    // 1. Add valid commit
    let input_1 = NativeCommitInput {
        change_id,
        tree: Merge::resolved(tree_1),
        parents: Vec::new(),
        predecessor: None,
        author: sample_signature("Eve", 1700000000),
        committer: sample_signature("Eve", 1700000000),
        extra_headers: Vec::new(),
        message: ByteString::from("First commit in batch"),
        provenance: None,
    };
    let head_1 = preparer.add_native_commit(input_1).expect("add first");

    // 2. Add second commit with conflicting/invalid predecessor
    let wrong_head = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"non-existent-predecessor"),
    };
    let input_2 = NativeCommitInput {
        change_id,
        tree: Merge::resolved(tree_2),
        parents: Vec::new(),
        predecessor: Some(wrong_head),
        author: sample_signature("Eve", 1700000001),
        committer: sample_signature("Eve", 1700000001),
        extra_headers: Vec::new(),
        message: ByteString::from("Conflicting second commit"),
        provenance: None,
    };
    let err = preparer.add_native_commit(input_2).expect_err("must fail");
    assert_eq!(err.code, ErrorCode::EStale);

    // Dropping preparer without publishing leaves Store completely pristine
    drop(preparer);

    let change = records.get_change(&change_id).expect("read");
    assert!(
        change.is_none(),
        "store must not contain any changes from dropped batch"
    );

    let commit = records.get_commit(&head_1).expect("read");
    assert!(
        commit.is_none(),
        "store must not contain commits from dropped batch"
    );
}

// ---------------------------------------------------------------------------
// 8. Bounded High-History Paging and Corrupt Row Quarantine
// ---------------------------------------------------------------------------

#[test]
fn test_bounded_high_history_paging() {
    let fixture = TestFixture::new("history-paging", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let target_change = ChangeId::generate();
    let other_change_1 = ChangeId::from_bytes([0x00; 16]);
    let other_change_2 = ChangeId::from_bytes([0xff; 16]);

    let mut mutations = Vec::new();

    // Populate other change 1
    let other_head_1 = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"other-head-1"),
    };
    mutations.push(FactMutation {
        table: FactTable::ChangeHistory,
        key: history_key(&other_change_1, &other_head_1),
        expected: FactExpectation::Absent,
        value: Some(super::codec::encode_change_history().expect("encode")),
    });

    // Populate 35 history heads for target_change
    let mut expected_heads = Vec::new();
    for i in 0..35_u8 {
        let oid = sample_oid(HashKind::Sha1, &[b'h', i]);
        let head = Head::Git { oid };
        expected_heads.push(head);
        mutations.push(FactMutation {
            table: FactTable::ChangeHistory,
            key: history_key(&target_change, &head),
            expected: FactExpectation::Absent,
            value: Some(super::codec::encode_change_history().expect("encode")),
        });
    }
    expected_heads.sort_unstable();

    // Populate other change 2
    let other_head_2 = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"other-head-2"),
    };
    mutations.push(FactMutation {
        table: FactTable::ChangeHistory,
        key: history_key(&other_change_2, &other_head_2),
        expected: FactExpectation::Absent,
        value: Some(super::codec::encode_change_history().expect("encode")),
    });

    fixture.publish(&mutations);

    // Page target_change with page size 10
    let mut collected = Vec::new();
    let mut cursor: Option<Head> = None;
    let budget = RecordPageBudget::new(10, 4096);

    loop {
        let page = records
            .page_change_history(&target_change, cursor.as_ref(), budget)
            .expect("read history page");

        assert!(page.heads.len() <= 10);
        collected.extend(page.heads);

        if !page.more {
            assert!(page.next_cursor.is_none());
            break;
        }
        assert!(page.next_cursor.is_some());
        cursor = page.next_cursor;
    }

    assert_eq!(collected.len(), 35);
    assert_eq!(collected, expected_heads);
}

#[test]
fn test_corrupt_row_quarantine() {
    let fixture = TestFixture::new("quarantine", HashKind::Sha1);
    let records = Records::new(fixture.store());

    let target_head = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"corrupt-target"),
    };

    // Inject corrupted postcard bytes directly into FactTable::Commits
    fixture.publish(&[FactMutation {
        table: FactTable::Commits,
        key: head_key(&target_head),
        expected: FactExpectation::Absent,
        value: Some(vec![0xff, 0xff, 0xff, 0xff]), // Corrupt postcard payload
    }]);

    // Reading the corrupt row must fail with E_CORRUPT
    let err = records.get_commit(&target_head).expect_err("must fail");
    assert_eq!(err.code, ErrorCode::ECorrupt);

    // Store must now be quarantined; subsequent operations are refused
    let probe_head = Head::Git {
        oid: sample_oid(HashKind::Sha1, b"probe"),
    };
    let quarantine_err = records.get_commit(&probe_head).expect_err("quarantined");
    assert_eq!(quarantine_err.code, ErrorCode::ECorrupt);

    let store_fact_err = fixture
        .store()
        .fact(FactTable::Changes, b"")
        .expect_err("quarantine refuses");
    assert_eq!(store_fact_err.code(), ErrorCode::ECorrupt);
}
#[test]
fn test_headless_abandoned_change_reads_back_while_headless_active_is_corrupt() {
    // A headless `Abandoned` entry is the legal stored state `abandon` writes
    // when it drains the last head: it must read back instead of failing.
    let fixture = TestFixture::new("headless-abandoned", HashKind::Sha1);
    let records = Records::new(fixture.store());
    let change_id = ChangeId::generate();
    let entry = ChangeEntry {
        state: ChangeState::Abandoned,
        heads: Vec::new(),
    };
    fixture.publish(&[FactMutation {
        table: FactTable::Changes,
        key: change_key(&change_id).to_vec(),
        expected: FactExpectation::Absent,
        value: Some(encode_change_entry(&entry).expect("encode")),
    }]);
    let read = records
        .get_change(&change_id)
        .expect("headless abandoned reads back")
        .expect("change present");
    assert_eq!(read.state, ChangeState::Abandoned);
    assert!(read.heads.is_empty());

    // A headless `Active` entry stays corruption: same shape, other state.
    let bad_fixture = TestFixture::new("headless-active", HashKind::Sha1);
    let bad_records = Records::new(bad_fixture.store());
    let bad_id = ChangeId::generate();
    let bad = ChangeEntry {
        state: ChangeState::Active,
        heads: Vec::new(),
    };
    bad_fixture.publish(&[FactMutation {
        table: FactTable::Changes,
        key: change_key(&bad_id).to_vec(),
        expected: FactExpectation::Absent,
        value: Some(encode_change_entry(&bad).expect("encode")),
    }]);
    let err = bad_records
        .get_change(&bad_id)
        .expect_err("headless active must fail");
    assert_eq!(err.code, ErrorCode::ECorrupt);
    let quarantined = bad_records
        .get_change(&ChangeId::generate())
        .expect_err("quarantined");
    assert_eq!(quarantined.code, ErrorCode::ECorrupt);
}
