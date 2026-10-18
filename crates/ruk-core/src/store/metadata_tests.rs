//! Behavioral tests for the metadata authority: the table census, the
//! initialize-versus-open split, exact-key reads, conditional fact
//! publication, the owned publication transaction, and refusal of damaged
//! rows. Damage is injected with raw redb handles on the closed database,
//! the way a damaged or foreign file would actually arrive.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, TableDefinition,
    TableHandle,
};

use std::sync::Arc;

use super::error::StoreError;
use super::metadata::{FactPage, FactPageBudget, FactRow, Metadata, PublicationTxn};
use super::types::{
    FactExpectation, FactMutation, FactTable, ObjectKind, ObjectLocation, SegmentManifest,
};
use super::{PreparationBudget, Store};
use crate::ids::{HashKind, Oid};

const RAW_OBJECTS: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("objects");
const RAW_SEGMENTS: TableDefinition<'static, u64, &'static [u8]> = TableDefinition::new("segments");
const RAW_GENERATION: TableDefinition<'static, (), u64> = TableDefinition::new("generation");
const RAW_VERIFIED: TableDefinition<'static, (), u64> = TableDefinition::new("verified_generation");

/// The census of the core contract, spelled independently of the code under
/// test: every table a store must contain, and no other.
const CENSUS: [&str; 30] = [
    "objects",
    "commits",
    "changes",
    "imported_changes",
    "change_history",
    "ops",
    "op_head",
    "refs",
    "ref_conflicts",
    "remote_observations",
    "workspaces",
    "claims",
    "ws_index",
    "ws_status",
    "ws_dirs",
    "receipts",
    "sessions",
    "attestations",
    "push_plans",
    "land_plans",
    "published_heads",
    "leases",
    "ws_apply",
    "segments",
    "generation",
    "verified_generation",
    "promisor",
    "shallow",
    "pins",
    "reflogs",
];

fn every_fact_table() -> Vec<FactTable> {
    let all = vec![
        FactTable::Refs,
        FactTable::RefConflicts,
        FactTable::RemoteObservations,
        FactTable::Changes,
        FactTable::ImportedChanges,
        FactTable::ChangeHistory,
        FactTable::Commits,
        FactTable::Ops,
        FactTable::OpHead,
        FactTable::Workspaces,
        FactTable::Claims,
        FactTable::WsIndex,
        FactTable::WsStatus,
        FactTable::WsDirs,
        FactTable::Receipts,
        FactTable::Sessions,
        FactTable::Attestations,
        FactTable::PushPlans,
        FactTable::LandPlans,
        FactTable::PublishedHeads,
        FactTable::Leases,
        FactTable::WsApply,
        FactTable::Reflogs,
        FactTable::Promisor,
        FactTable::Shallow,
        FactTable::Pins,
        FactTable::LfsObjects,
    ];
    // A new variant fails to compile here until it is listed above.
    for table in &all {
        match table {
            FactTable::Refs
            | FactTable::RefConflicts
            | FactTable::RemoteObservations
            | FactTable::Changes
            | FactTable::ImportedChanges
            | FactTable::ChangeHistory
            | FactTable::Commits
            | FactTable::Ops
            | FactTable::OpHead
            | FactTable::Workspaces
            | FactTable::Claims
            | FactTable::WsIndex
            | FactTable::WsStatus
            | FactTable::WsDirs
            | FactTable::Receipts
            | FactTable::Sessions
            | FactTable::Attestations
            | FactTable::PushPlans
            | FactTable::LandPlans
            | FactTable::PublishedHeads
            | FactTable::Leases
            | FactTable::WsApply
            | FactTable::Reflogs
            | FactTable::Promisor
            | FactTable::Shallow
            | FactTable::Pins
            | FactTable::LfsObjects => {}
        }
    }
    all
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ruk-metadata-test-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test directory");
        Self(dir)
    }

    fn meta_path(&self) -> PathBuf {
        self.0.join("meta.redb")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn empty_file(path: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create empty file")
}

fn create(dir: &TestDir) -> Metadata {
    Metadata::create_in_file(empty_file(&dir.meta_path())).expect("initialize metadata")
}

fn reopen(dir: &TestDir) -> Metadata {
    Metadata::open(&dir.meta_path()).expect("open metadata")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn some(value: &[u8]) -> Option<Vec<u8>> {
    Some(value.to_vec())
}

fn put(table: FactTable, key: &[u8], value: &[u8]) -> FactMutation {
    cas(table, key, FactExpectation::Any, some(value))
}

fn cas(
    table: FactTable,
    key: &[u8],
    expected: FactExpectation,
    value: Option<Vec<u8>>,
) -> FactMutation {
    FactMutation {
        table,
        key: key.to_vec(),
        expected,
        value,
    }
}

/// Commits `facts` as one publication at the next generation.
fn publish(meta: &Metadata, facts: &[FactMutation]) {
    let next = meta.generation().expect("generation") + 1;
    let txn = meta.begin_publication(facts).expect("begin publication");
    txn.set_generation(next).expect("advance generation");
    txn.commit().expect("commit publication");
}

fn read_fact(meta: &Metadata, table: FactTable, key: &[u8]) -> Option<Vec<u8>> {
    meta.fact(table, key).expect("read fact")
}

fn expect_stale(result: Result<PublicationTxn, StoreError>, table: &str, key: &[u8]) {
    match result {
        Err(StoreError::StaleFact {
            table: found,
            key: text,
        }) => {
            assert_eq!(found, table);
            assert_eq!(text, hex(key));
        }
        other => panic!("expected a stale fact on {table}, got {other:?}"),
    }
}

fn oid_of(digest: &[u8]) -> Oid {
    Oid::from_bytes(digest).expect("digest of a known width")
}

fn sha1_oid(seed: u8) -> Oid {
    oid_of(&[seed; 20])
}

fn location(segment: u64, offset: u64) -> ObjectLocation {
    ObjectLocation {
        kind: ObjectKind::Blob,
        decoded_len: 11,
        segment,
        offset,
        record_len: 40,
        generation: 1,
        base: None,
        depth: 0,
    }
}

fn manifest(id: u64, records_end: u64, sealed: bool) -> SegmentManifest {
    SegmentManifest {
        id,
        committed_end: records_end + if sealed { 24 } else { 0 },
        records_end,
        sealed,
        retired: false,
        generation: 1,
    }
}

fn raw_table_names(path: &Path) -> Vec<String> {
    let db = Database::open(path).expect("raw open");
    let txn = db.begin_read().expect("raw read");
    let mut names: Vec<String> = txn
        .list_tables()
        .expect("list tables")
        .map(|handle| handle.name().to_owned())
        .collect();
    names.sort();
    names
}

pub(super) fn raw_put_object(path: &Path, key: &[u8], value: &[u8]) {
    let db = Database::open(path).expect("raw open");
    let txn = db.begin_write().expect("raw write");
    {
        let mut table = txn.open_table(RAW_OBJECTS).expect("raw objects");
        table.insert(key, value).expect("raw insert");
    }
    txn.commit().expect("raw commit");
}

pub(super) fn raw_put_segment(path: &Path, key: u64, value: &[u8]) {
    let db = Database::open(path).expect("raw open");
    let txn = db.begin_write().expect("raw write");
    {
        let mut table = txn.open_table(RAW_SEGMENTS).expect("raw segments");
        table.insert(key, value).expect("raw insert");
    }
    txn.commit().expect("raw commit");
}

/// Advances the stored locator generation by one without recording it as
/// verified, so the next recovery treats the generation as unverified.
/// Tests use this alongside row surgery to model committed-state damage a
/// cached open must still detect.
pub(super) fn raw_bump_generation(path: &Path) {
    let db = Database::open(path).expect("raw open");
    let txn = db.begin_write().expect("raw write");
    {
        let mut table = txn.open_table(RAW_GENERATION).expect("raw generation");
        let current: u64 = table
            .get(())
            .expect("raw get")
            .map(|guard| guard.value())
            .unwrap_or(0);
        table.insert((), current + 1).expect("raw insert");
    }
    txn.commit().expect("raw commit");
}

fn encoded<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).expect("encode")
}

// ---------------------------------------------------------------------
// Initialization versus opening
// ---------------------------------------------------------------------

#[test]
fn create_initializes_the_complete_census_and_generation_zero() {
    let dir = TestDir::new("census");
    let meta = create(&dir);
    assert_eq!(meta.generation().expect("generation"), 0);
    assert_eq!(
        meta.verified_generation().expect("verified generation"),
        Some(0)
    );
    assert!(meta.all_manifests().expect("manifests").is_empty());
    drop(meta);

    let mut expected: Vec<String> = CENSUS.iter().map(|name| (*name).to_owned()).collect();
    expected.sort();
    assert_eq!(raw_table_names(&dir.meta_path()), expected);

    let reopened = reopen(&dir);
    let tables = every_fact_table();
    assert_eq!(tables.len(), 27);
    assert_eq!(tables, FactTable::ALL.to_vec(), "FactTable::ALL drifted");
    for table in tables {
        assert!(CENSUS.contains(&table.table_name()), "{table:?}");
        assert_eq!(read_fact(&reopened, table, b"k"), None, "{table:?}");
    }
}

#[test]
fn create_refuses_a_non_empty_file_and_leaves_its_bytes_alone() {
    let dir = TestDir::new("create-nonempty");
    std::fs::write(dir.meta_path(), b"not empty").expect("seed file");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.meta_path())
        .expect("open seed");
    let result = Metadata::create_in_file(file);
    assert!(matches!(result, Err(StoreError::Invalid(_))), "{result:?}");
    assert_eq!(std::fs::read(dir.meta_path()).expect("read"), b"not empty");
}

#[test]
fn create_refuses_an_existing_database_and_keeps_its_facts() {
    let dir = TestDir::new("create-existing");
    let meta = create(&dir);
    publish(&meta, &[put(FactTable::Refs, b"main", b"v1")]);
    drop(meta);

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.meta_path())
        .expect("open existing");
    let result = Metadata::create_in_file(file);
    assert!(matches!(result, Err(StoreError::Invalid(_))), "{result:?}");

    let reopened = reopen(&dir);
    assert_eq!(read_fact(&reopened, FactTable::Refs, b"main"), some(b"v1"));
    assert_eq!(reopened.generation().expect("generation"), 1);
}

#[test]
fn open_refuses_a_missing_file_without_creating_it() {
    let dir = TestDir::new("open-missing");
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
    assert!(!dir.meta_path().exists());
}

#[test]
fn open_refuses_an_empty_file_without_initializing_it() {
    let dir = TestDir::new("open-empty");
    drop(empty_file(&dir.meta_path()));
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
    assert_eq!(std::fs::metadata(dir.meta_path()).expect("stat").len(), 0);
}

#[test]
fn open_refuses_a_foreign_file() {
    let dir = TestDir::new("open-foreign");
    std::fs::write(dir.meta_path(), vec![0xAB_u8; 8192]).expect("seed file");
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
    assert_eq!(
        std::fs::read(dir.meta_path()).expect("read"),
        vec![0xAB_u8; 8192]
    );
}

#[test]
fn open_refuses_a_database_missing_a_census_table() {
    let dir = TestDir::new("open-missing-table");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        let pins: TableDefinition<'static, &'static [u8], &'static [u8]> =
            TableDefinition::new("pins");
        assert!(txn.delete_table(pins).expect("delete table"));
        txn.commit().expect("raw commit");
    }
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
}

#[test]
fn open_refuses_a_census_table_with_the_wrong_types() {
    let dir = TestDir::new("open-retyped-table");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        assert!(txn.delete_table(RAW_OBJECTS).expect("delete table"));
        let retyped: TableDefinition<'static, u64, u64> = TableDefinition::new("objects");
        drop(txn.open_table(retyped).expect("recreate table"));
        txn.commit().expect("raw commit");
    }
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
}

#[test]
fn open_refuses_an_unknown_table_as_an_unknown_format() {
    let dir = TestDir::new("open-unknown-table");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        let future: TableDefinition<'static, u64, u64> = TableDefinition::new("future_table");
        drop(txn.open_table(future).expect("create table"));
        txn.commit().expect("raw commit");
    }
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Version(_))), "{result:?}");
}

#[test]
fn open_accepts_a_store_predating_the_verified_generation_table_as_unverified() {
    let dir = TestDir::new("open-no-verified-table");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        assert!(txn.delete_table(RAW_VERIFIED).expect("delete table"));
        txn.commit().expect("raw commit");
    }
    let meta = reopen(&dir);
    assert_eq!(
        meta.verified_generation().expect("verified generation"),
        None
    );
    meta.set_verified_generation(4)
        .expect("record verification");
    assert_eq!(
        meta.verified_generation().expect("verified generation"),
        Some(4)
    );
    meta.set_verified_generation(7)
        .expect("record verification");
    assert_eq!(
        meta.verified_generation().expect("verified generation"),
        Some(7)
    );
}

#[test]
fn open_refuses_an_unexpected_multimap_table() {
    let dir = TestDir::new("open-multimap");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        let multi: MultimapTableDefinition<'static, u64, u64> =
            MultimapTableDefinition::new("multi");
        drop(txn.open_multimap_table(multi).expect("create multimap"));
        txn.commit().expect("raw commit");
    }
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Version(_))), "{result:?}");
}

#[test]
fn open_refuses_a_missing_generation_row() {
    let dir = TestDir::new("open-no-generation");
    drop(create(&dir));
    {
        let db = Database::open(dir.meta_path()).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        {
            let mut table = txn.open_table(RAW_GENERATION).expect("raw generation");
            assert!(table.remove(()).expect("remove row").is_some());
        }
        txn.commit().expect("raw commit");
    }
    let result = Metadata::open(&dir.meta_path());
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
}

// ---------------------------------------------------------------------
// Publication: atomicity, durability across reopen, visibility
// ---------------------------------------------------------------------

#[test]
fn a_committed_publication_survives_reopen_in_every_table() {
    let dir = TestDir::new("reopen");
    let meta = create(&dir);
    let first = sha1_oid(1);
    let second = sha1_oid(2);

    let txn = meta
        .begin_publication(&[
            put(FactTable::Refs, b"refs/heads/main", b"tip"),
            put(FactTable::Changes, b"change-1", b"entry"),
        ])
        .expect("begin");
    txn.set_generation(1).expect("generation");
    txn.insert_object(&first, &location(0, 0)).expect("object");
    txn.insert_object(&second, &location(0, 40))
        .expect("object");
    txn.upsert_manifest(&manifest(0, 80, false))
        .expect("manifest");
    txn.commit().expect("commit");
    drop(meta);

    let meta = reopen(&dir);
    assert_eq!(meta.generation().expect("generation"), 1);
    assert_eq!(
        read_fact(&meta, FactTable::Refs, b"refs/heads/main"),
        some(b"tip")
    );
    assert_eq!(
        read_fact(&meta, FactTable::Changes, b"change-1"),
        some(b"entry")
    );
    assert_eq!(
        meta.get_object(&first).expect("object"),
        Some(location(0, 0))
    );
    assert_eq!(
        meta.get_object(&second).expect("object"),
        Some(location(0, 40))
    );
    assert_eq!(
        meta.manifest(0).expect("manifest"),
        Some(manifest(0, 80, false))
    );
    assert_eq!(
        meta.all_manifests().expect("manifests"),
        vec![manifest(0, 80, false)]
    );
}

#[test]
fn an_abandoned_publication_makes_nothing_visible() {
    let dir = TestDir::new("abandon");
    let meta = create(&dir);
    let oid = sha1_oid(9);
    {
        let txn = meta
            .begin_publication(&[put(FactTable::Refs, b"main", b"new")])
            .expect("begin");
        txn.set_generation(5).expect("generation");
        txn.insert_object(&oid, &location(0, 0)).expect("object");
        txn.upsert_manifest(&manifest(0, 40, false))
            .expect("manifest");
    }
    assert_eq!(read_fact(&meta, FactTable::Refs, b"main"), None);
    assert_eq!(meta.get_object(&oid).expect("object"), None);
    assert_eq!(meta.manifest(0).expect("manifest"), None);
    assert_eq!(meta.generation().expect("generation"), 0);
    drop(meta);

    let meta = reopen(&dir);
    assert_eq!(read_fact(&meta, FactTable::Refs, b"main"), None);
    assert_eq!(meta.generation().expect("generation"), 0);
}

#[test]
fn readers_see_only_committed_state_while_a_publication_is_open() {
    let dir = TestDir::new("snapshot");
    let meta = create(&dir);
    publish(&meta, &[put(FactTable::Refs, b"main", b"old")]);
    let oid = sha1_oid(3);

    let txn = meta
        .begin_publication(&[put(FactTable::Refs, b"main", b"new")])
        .expect("begin");
    txn.set_generation(2).expect("generation");
    txn.insert_object(&oid, &location(0, 0)).expect("object");

    assert_eq!(read_fact(&meta, FactTable::Refs, b"main"), some(b"old"));
    assert_eq!(meta.get_object(&oid).expect("object"), None);
    assert_eq!(meta.generation().expect("generation"), 1);
    assert_eq!(txn.get_object(&oid).expect("object"), Some(location(0, 0)));

    txn.commit().expect("commit");
    assert_eq!(read_fact(&meta, FactTable::Refs, b"main"), some(b"new"));
    assert_eq!(meta.get_object(&oid).expect("object"), Some(location(0, 0)));
    assert_eq!(meta.generation().expect("generation"), 2);
}

#[test]
fn a_second_publication_waits_for_the_first_and_checks_against_its_commit() {
    let dir = TestDir::new("serial");
    let meta = create(&dir);
    let first = meta
        .begin_publication(&[cas(
            FactTable::Refs,
            b"k",
            FactExpectation::Absent,
            some(b"1"),
        )])
        .expect("first");
    first.set_generation(1).expect("generation");

    let stale = std::thread::scope(|scope| {
        let second = scope.spawn(|| {
            let outcome = meta.begin_publication(&[cas(
                FactTable::Refs,
                b"k",
                FactExpectation::Absent,
                some(b"2"),
            )]);
            match outcome {
                Err(StoreError::StaleFact { table, key }) => Some((table, key)),
                _ => None,
            }
        });
        first.commit().expect("commit first");
        second.join().expect("second publication thread")
    });
    assert_eq!(stale, Some(("refs", hex(b"k"))));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"k"), some(b"1"));
}

// ---------------------------------------------------------------------
// Conditional facts
// ---------------------------------------------------------------------

#[test]
fn any_stale_expectation_leaves_every_fact_and_the_generation_untouched() {
    let dir = TestDir::new("cas-stale");
    let meta = create(&dir);
    publish(&meta, &[put(FactTable::Refs, b"a", b"abc")]);

    let offenders: [(&str, FactMutation); 6] = [
        (
            "absent on an existing key",
            cas(FactTable::Refs, b"a", FactExpectation::Absent, some(b"x")),
        ),
        (
            "value on a missing key",
            cas(
                FactTable::Refs,
                b"missing",
                FactExpectation::Value(b"v".to_vec()),
                some(b"x"),
            ),
        ),
        (
            "different value",
            cas(
                FactTable::Refs,
                b"a",
                FactExpectation::Value(b"abd".to_vec()),
                some(b"x"),
            ),
        ),
        (
            "proper prefix of the stored value",
            cas(
                FactTable::Refs,
                b"a",
                FactExpectation::Value(b"ab".to_vec()),
                some(b"x"),
            ),
        ),
        (
            "proper extension of the stored value",
            cas(
                FactTable::Refs,
                b"a",
                FactExpectation::Value(b"abcd".to_vec()),
                None,
            ),
        ),
        (
            "empty value against a stored value",
            cas(
                FactTable::Refs,
                b"a",
                FactExpectation::Value(Vec::new()),
                some(b"x"),
            ),
        ),
    ];

    for (name, offender) in offenders {
        for position in 0..=3 {
            let mut batch = vec![
                put(FactTable::Changes, b"before", b"1"),
                cas(FactTable::Pins, b"p", FactExpectation::Absent, some(b"p")),
                put(FactTable::Claims, b"after", b"2"),
            ];
            batch.insert(position, offender.clone());

            expect_stale(
                meta.begin_publication(&batch),
                offender.table.table_name(),
                &offender.key,
            );

            assert_eq!(
                read_fact(&meta, FactTable::Refs, b"a"),
                some(b"abc"),
                "{name}"
            );
            assert_eq!(
                read_fact(&meta, FactTable::Changes, b"before"),
                None,
                "{name}"
            );
            assert_eq!(read_fact(&meta, FactTable::Pins, b"p"), None, "{name}");
            assert_eq!(
                read_fact(&meta, FactTable::Claims, b"after"),
                None,
                "{name}"
            );
            assert_eq!(meta.generation().expect("generation"), 1, "{name}");
        }
    }
}

#[test]
fn satisfied_expectations_apply_together() {
    let dir = TestDir::new("cas-ok");
    let meta = create(&dir);
    publish(
        &meta,
        &[
            put(FactTable::Refs, b"keep", b"k1"),
            put(FactTable::Refs, b"swap", b"s1"),
            put(FactTable::Refs, b"drop", b"d1"),
            put(FactTable::Refs, b"force", b"f1"),
        ],
    );

    publish(
        &meta,
        &[
            cas(
                FactTable::Refs,
                b"swap",
                FactExpectation::Value(b"s1".to_vec()),
                some(b"s2"),
            ),
            cas(
                FactTable::Refs,
                b"drop",
                FactExpectation::Value(b"d1".to_vec()),
                None,
            ),
            cas(FactTable::Refs, b"force", FactExpectation::Any, some(b"f2")),
            cas(
                FactTable::Refs,
                b"fresh",
                FactExpectation::Absent,
                some(b"n1"),
            ),
            cas(
                FactTable::Refs,
                b"never-existed",
                FactExpectation::Any,
                None,
            ),
        ],
    );

    assert_eq!(read_fact(&meta, FactTable::Refs, b"keep"), some(b"k1"));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"swap"), some(b"s2"));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"drop"), None);
    assert_eq!(read_fact(&meta, FactTable::Refs, b"force"), some(b"f2"));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"fresh"), some(b"n1"));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"never-existed"), None);
    assert_eq!(meta.generation().expect("generation"), 2);
}

#[test]
fn duplicate_fact_keys_are_refused_before_any_write() {
    let dir = TestDir::new("duplicates");
    let meta = create(&dir);

    let same_value = [
        put(FactTable::Refs, b"k", b"v"),
        put(FactTable::Refs, b"k", b"v"),
    ];
    let contradictory = [
        cas(FactTable::Refs, b"k", FactExpectation::Absent, some(b"v1")),
        cas(FactTable::Claims, b"x", FactExpectation::Any, some(b"y")),
        cas(FactTable::Refs, b"k", FactExpectation::Any, some(b"v2")),
    ];
    for batch in [&same_value[..], &contradictory[..]] {
        let result = meta.begin_publication(batch);
        assert!(matches!(result, Err(StoreError::Invalid(_))), "{result:?}");
    }
    assert_eq!(read_fact(&meta, FactTable::Refs, b"k"), None);
    assert_eq!(read_fact(&meta, FactTable::Claims, b"x"), None);

    // The same key in another table, and other keys in one table, are
    // independent mutations.
    publish(
        &meta,
        &[
            put(FactTable::Refs, b"k", b"in-refs"),
            put(FactTable::Claims, b"k", b"in-claims"),
            put(FactTable::Refs, b"k2", b"other-key"),
        ],
    );
    assert_eq!(read_fact(&meta, FactTable::Refs, b"k"), some(b"in-refs"));
    assert_eq!(
        read_fact(&meta, FactTable::Claims, b"k"),
        some(b"in-claims")
    );
    assert_eq!(read_fact(&meta, FactTable::Refs, b"k2"), some(b"other-key"));
}

#[test]
fn fact_reads_match_exact_keys_only() {
    let dir = TestDir::new("exact-keys");
    let meta = create(&dir);
    publish(
        &meta,
        &[
            put(FactTable::Refs, b"refs/heads/main", b"main"),
            put(FactTable::Refs, b"", b"empty-key"),
            put(FactTable::Refs, b"bin\0key\xff", b"binary"),
        ],
    );

    assert_eq!(
        read_fact(&meta, FactTable::Refs, b"refs/heads/main"),
        some(b"main")
    );
    assert_eq!(read_fact(&meta, FactTable::Refs, b"refs/heads/mai"), None);
    assert_eq!(read_fact(&meta, FactTable::Refs, b"refs/heads/main2"), None);
    assert_eq!(read_fact(&meta, FactTable::Refs, b"refs/heads/main/"), None);
    assert_eq!(
        read_fact(&meta, FactTable::Refs, b"refs/heads/main\0"),
        None
    );
    assert_eq!(
        read_fact(&meta, FactTable::Changes, b"refs/heads/main"),
        None
    );
    assert_eq!(read_fact(&meta, FactTable::Refs, b""), some(b"empty-key"));
    assert_eq!(read_fact(&meta, FactTable::Refs, b"\0"), None);
    assert_eq!(
        read_fact(&meta, FactTable::Refs, b"bin\0key\xff"),
        some(b"binary")
    );
    assert_eq!(read_fact(&meta, FactTable::Refs, b"bin\0key"), None);
}

#[test]
fn large_values_round_trip_byte_for_byte() {
    let dir = TestDir::new("large-value");
    let meta = create(&dir);
    let value: Vec<u8> = (0..1_500_000_u32)
        .map(|n| u8::try_from(n % 251).expect("remainder below 251 fits a byte"))
        .collect();
    publish(&meta, &[put(FactTable::Receipts, b"big", &value)]);
    drop(meta);
    let meta = reopen(&dir);
    assert_eq!(read_fact(&meta, FactTable::Receipts, b"big"), Some(value));
}

// ---------------------------------------------------------------------
// Object rows
// ---------------------------------------------------------------------

#[test]
fn object_reads_match_exact_digests_only() {
    let dir = TestDir::new("exact-oids");
    let meta = create(&dir);
    let stored = sha1_oid(7);
    let mut neighbour_digest = [7_u8; 20];
    neighbour_digest[19] = 8;
    let neighbour = oid_of(&neighbour_digest);
    let wider = oid_of(&[7_u8; 32]);

    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    txn.insert_object(&stored, &location(0, 0)).expect("object");
    txn.commit().expect("commit");

    assert_eq!(
        meta.get_object(&stored).expect("object"),
        Some(location(0, 0))
    );
    assert_eq!(meta.get_object(&neighbour).expect("object"), None);
    assert_eq!(meta.get_object(&wider).expect("object"), None);
}

#[test]
fn objects_are_insert_only_and_reject_inconsistent_locations() {
    let dir = TestDir::new("object-guards");
    let meta = create(&dir);
    let oid = sha1_oid(4);
    let base = sha1_oid(5);

    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    txn.insert_object(&oid, &location(0, 0)).expect("object");
    txn.commit().expect("commit");

    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(2).expect("generation");
    let mut moved = location(3, 4096);
    assert!(matches!(
        txn.insert_object(&oid, &moved),
        Err(StoreError::Invalid(_))
    ));

    let fresh = sha1_oid(6);
    txn.insert_object(&fresh, &location(0, 40))
        .expect("fresh object");
    assert!(matches!(
        txn.insert_object(&fresh, &location(0, 80)),
        Err(StoreError::Invalid(_))
    ));

    let invalid = sha1_oid(10);
    let mut cases: Vec<(&str, ObjectLocation)> = Vec::new();
    moved.base = None;
    moved.depth = 2;
    cases.push(("depth without a base", moved.clone()));
    moved.base = Some(base);
    moved.depth = 0;
    cases.push(("base without depth", moved.clone()));
    moved.depth = 51;
    cases.push(("depth past the chain cap", moved.clone()));
    moved.depth = 1;
    moved.base = Some(invalid);
    cases.push(("self-referential base", moved.clone()));
    moved.base = Some(oid_of(&[5_u8; 32]));
    cases.push(("base of a different width", moved.clone()));
    moved.base = None;
    moved.depth = 0;
    moved.record_len = 9;
    cases.push(("record shorter than its header", moved.clone()));
    moved.record_len = 40;
    moved.offset = u64::MAX;
    cases.push(("extent overflowing u64", moved.clone()));
    for (name, case) in cases {
        let result = txn.insert_object(&invalid, &case);
        assert!(
            matches!(result, Err(StoreError::Invalid(_))),
            "{name}: {result:?}"
        );
    }
    txn.commit().expect("commit");

    assert_eq!(meta.get_object(&oid).expect("object"), Some(location(0, 0)));
    assert_eq!(
        meta.get_object(&fresh).expect("object"),
        Some(location(0, 40))
    );
    assert_eq!(meta.get_object(&invalid).expect("object"), None);

    let delta = ObjectLocation {
        base: Some(base),
        depth: 1,
        ..location(1, 0)
    };
    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(3).expect("generation");
    txn.insert_object(&sha1_oid(11), &delta)
        .expect("delta object");
    txn.commit().expect("commit");
    assert_eq!(meta.get_object(&sha1_oid(11)).expect("object"), Some(delta));
}

#[test]
fn object_pages_follow_key_order_and_resume_after_the_cursor() {
    let dir = TestDir::new("object-pages");
    let meta = create(&dir);
    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    for seed in [5_u8, 1, 4, 2, 3] {
        txn.insert_object(&sha1_oid(seed), &location(0, u64::from(seed) * 40))
            .expect("object");
    }
    txn.commit().expect("commit");

    let mut seen = Vec::new();
    let mut cursor: Option<Oid> = None;
    loop {
        let page = meta.object_page(cursor.as_ref(), 2).expect("page");
        assert!(page.len() <= 2);
        let Some((last, _)) = page.last() else { break };
        cursor = Some(*last);
        seen.extend(page);
    }
    let expected: Vec<(Oid, ObjectLocation)> = (1_u8..=5)
        .map(|seed| (sha1_oid(seed), location(0, u64::from(seed) * 40)))
        .collect();
    assert_eq!(seen, expected);

    assert!(meta.object_page(None, 0).expect("page").is_empty());
    let past_end = sha1_oid(5);
    assert!(
        meta.object_page(Some(&past_end), 10)
            .expect("page")
            .is_empty()
    );
}

#[test]
fn damaged_object_rows_are_refused_and_do_not_poison_neighbours() {
    let dir = TestDir::new("damaged-objects");
    let meta = create(&dir);
    let healthy = sha1_oid(1);
    let victim = sha1_oid(2);
    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    txn.insert_object(&healthy, &location(0, 0))
        .expect("object");
    txn.commit().expect("commit");
    drop(meta);

    let valid = encoded(&location(0, 40));
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = valid[..valid.len() - 1].to_vec();
    let no_base_with_depth = encoded(&ObjectLocation {
        depth: 3,
        ..location(0, 40)
    });
    let width_mismatch = encoded(&ObjectLocation {
        base: Some(oid_of(&[9_u8; 32])),
        depth: 1,
        ..location(0, 40)
    });
    let short_record = encoded(&ObjectLocation {
        record_len: 3,
        ..location(0, 40)
    });
    let cases: [(&str, Vec<u8>); 7] = [
        ("garbage", vec![0xFF; 3]),
        ("empty", Vec::new()),
        ("trailing byte", trailing),
        ("truncated", truncated),
        ("depth without base", no_base_with_depth),
        ("base width mismatch", width_mismatch),
        ("record shorter than header", short_record),
    ];

    for (name, bytes) in cases {
        raw_put_object(&dir.meta_path(), victim.as_bytes(), &bytes);
        let meta = reopen(&dir);
        let result = meta.get_object(&victim);
        assert!(
            matches!(result, Err(StoreError::Corrupt(_))),
            "{name}: {result:?}"
        );
        let paged = meta.object_page(None, 10);
        assert!(
            matches!(paged, Err(StoreError::Corrupt(_))),
            "{name}: {paged:?}"
        );
        assert_eq!(
            meta.get_object(&healthy).expect("healthy object"),
            Some(location(0, 0)),
            "{name}"
        );
    }
}

#[test]
fn an_object_row_keyed_by_a_non_digest_is_refused_by_enumeration() {
    let dir = TestDir::new("bad-object-key");
    drop(create(&dir));
    raw_put_object(&dir.meta_path(), b"short", &encoded(&location(0, 0)));
    let meta = reopen(&dir);
    let result = meta.object_page(None, 10);
    assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
}

// ---------------------------------------------------------------------
// Segment manifests and generation
// ---------------------------------------------------------------------

#[test]
fn manifests_list_in_id_order() {
    let dir = TestDir::new("manifest-order");
    let meta = create(&dir);
    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    for id in [5_u64, 1, 3] {
        txn.upsert_manifest(&manifest(id, id * 100, false))
            .expect("manifest");
    }
    txn.commit().expect("commit");

    let ids: Vec<u64> = meta
        .all_manifests()
        .expect("manifests")
        .into_iter()
        .map(|found| found.id)
        .collect();
    assert_eq!(ids, vec![1, 3, 5]);
    assert_eq!(meta.manifest(2).expect("manifest"), None);
    assert_eq!(
        meta.manifest(3).expect("manifest"),
        Some(manifest(3, 300, false))
    );
}

#[test]
fn manifests_only_move_forward() {
    let dir = TestDir::new("manifest-forward");
    let meta = create(&dir);

    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    txn.upsert_manifest(&manifest(0, 100, false))
        .expect("create");
    txn.upsert_manifest(&manifest(0, 200, false)).expect("grow");
    assert!(matches!(
        txn.upsert_manifest(&manifest(0, 150, false)),
        Err(StoreError::Invalid(_))
    ));
    txn.upsert_manifest(&manifest(0, 200, true)).expect("seal");
    txn.commit().expect("commit");
    assert_eq!(
        meta.manifest(0).expect("manifest"),
        Some(manifest(0, 200, true))
    );

    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(2).expect("generation");
    let refused: [(&str, SegmentManifest); 6] = [
        ("unseal", manifest(0, 224, false)),
        ("extend a sealed segment", manifest(0, 210, true)),
        ("shrink a sealed segment", manifest(0, 190, true)),
        (
            "records past committed end",
            SegmentManifest {
                records_end: 300,
                ..manifest(1, 200, false)
            },
        ),
        (
            "sealed without a whole footer",
            SegmentManifest {
                committed_end: 223,
                ..manifest(1, 200, true)
            },
        ),
        (
            "unsealed with trailing bytes",
            SegmentManifest {
                committed_end: 210,
                ..manifest(1, 200, false)
            },
        ),
    ];
    for (name, change) in refused {
        let result = txn.upsert_manifest(&change);
        assert!(
            matches!(result, Err(StoreError::Invalid(_))),
            "{name}: {result:?}"
        );
    }
    let retired = SegmentManifest {
        retired: true,
        ..manifest(0, 200, true)
    };
    txn.upsert_manifest(&retired).expect("retire");
    assert!(matches!(
        txn.upsert_manifest(&manifest(0, 200, true)),
        Err(StoreError::Invalid(_))
    ));
    txn.commit().expect("commit");

    assert_eq!(meta.manifest(0).expect("manifest"), Some(retired));
    assert_eq!(meta.manifest(1).expect("manifest"), None);
}

#[test]
fn damaged_manifest_rows_are_refused() {
    let dir = TestDir::new("damaged-manifests");
    let meta = create(&dir);
    let txn = meta.begin_publication(&[]).expect("begin");
    txn.set_generation(1).expect("generation");
    txn.upsert_manifest(&manifest(1, 100, false))
        .expect("manifest");
    txn.commit().expect("commit");
    drop(meta);

    let valid = encoded(&manifest(7, 100, false));
    let mut trailing = valid.clone();
    trailing.push(0);
    let cases: [(&str, u64, Vec<u8>); 5] = [
        ("garbage", 7, vec![0xFF; 2]),
        ("trailing byte", 7, trailing),
        ("stored under another id", 8, valid),
        (
            "sealed without a footer",
            7,
            encoded(&SegmentManifest {
                sealed: true,
                ..manifest(7, 100, false)
            }),
        ),
        (
            "records past committed end",
            7,
            encoded(&SegmentManifest {
                records_end: 101,
                ..manifest(7, 100, false)
            }),
        ),
    ];

    for (name, key, bytes) in cases {
        raw_put_segment(&dir.meta_path(), key, &bytes);
        let meta = reopen(&dir);
        let single = meta.manifest(key);
        assert!(
            matches!(single, Err(StoreError::Corrupt(_))),
            "{name}: {single:?}"
        );
        let all = meta.all_manifests();
        assert!(
            matches!(all, Err(StoreError::Corrupt(_))),
            "{name}: {all:?}"
        );
        assert_eq!(
            meta.manifest(1).expect("healthy manifest"),
            Some(manifest(1, 100, false)),
            "{name}"
        );
        drop(meta);
        raw_put_segment(&dir.meta_path(), key, &encoded(&manifest(key, 100, false)));
    }
}

#[test]
fn generation_must_strictly_advance() {
    let dir = TestDir::new("generation");
    let meta = create(&dir);

    let txn = meta.begin_publication(&[]).expect("begin");
    assert!(matches!(txn.set_generation(0), Err(StoreError::Invalid(_))));
    txn.set_generation(1).expect("advance");
    assert!(matches!(txn.set_generation(1), Err(StoreError::Invalid(_))));
    txn.commit().expect("commit");
    drop(meta);

    let meta = reopen(&dir);
    assert_eq!(meta.generation().expect("generation"), 1);
    let txn = meta.begin_publication(&[]).expect("begin");
    assert!(matches!(txn.set_generation(1), Err(StoreError::Invalid(_))));
    txn.set_generation(7).expect("advance");
    txn.commit().expect("commit");
    assert_eq!(meta.generation().expect("generation"), 7);
}

// ---------------------------------------------------------------------
// Fact paging
// ---------------------------------------------------------------------

#[test]
fn fact_page_rejects_zero_budget_as_invalid() {
    let dir = TestDir::new("fact-page-zero-budget");
    let meta = create(&dir);

    for (rows, bytes) in [(0, 100), (10, 0), (0, 0)] {
        let result = meta.fact_page(FactTable::Refs, None, FactPageBudget::new(rows, bytes));
        assert!(
            matches!(result, Err(StoreError::Invalid(_))),
            "rows={rows}, bytes={bytes}: expected Invalid, got {result:?}"
        );
    }
}

#[test]
fn fact_page_empty_table_returns_empty_and_not_more() {
    let dir = TestDir::new("fact-page-empty");
    let meta = create(&dir);

    let page = meta
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 1024))
        .expect("empty page");
    assert!(page.rows.is_empty());
    assert!(!page.more);

    let after_page = meta
        .fact_page(
            FactTable::Refs,
            Some(b"nonexistent"),
            FactPageBudget::new(10, 1024),
        )
        .expect("after page");
    assert!(after_page.rows.is_empty());
    assert!(!after_page.more);
}

#[test]
fn fact_page_first_oversized_row_returns_limit_never_empty_eof() {
    let dir = TestDir::new("fact-page-oversized-first");
    let meta = create(&dir);

    // key: 8 bytes, value: 12 bytes => 20 bytes total
    publish(
        &meta,
        &[
            put(FactTable::Refs, b"refs/h/1", b"target-one-!"),
            put(FactTable::Refs, b"refs/h/2", b"target-two-!"),
        ],
    );

    // First row alone (20 bytes) exceeds budget of 19 bytes.
    let result = meta.fact_page(FactTable::Refs, None, FactPageBudget::new(10, 19));
    assert!(
        matches!(result, Err(StoreError::Limit(_))),
        "expected Limit, got {result:?}"
    );

    // First row fits in 20 bytes.
    let page1 = meta
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 20))
        .expect("page1");
    assert_eq!(page1.rows.len(), 1);
    assert_eq!(page1.rows[0].key, b"refs/h/1");
    assert!(page1.more);

    // Second row as first row of the continuation page exceeds budget of 19 bytes.
    let after_key = &page1.rows[0].key;
    let result2 = meta.fact_page(
        FactTable::Refs,
        Some(after_key),
        FactPageBudget::new(10, 19),
    );
    assert!(
        matches!(result2, Err(StoreError::Limit(_))),
        "expected Limit on resumed first row, got {result2:?}"
    );
}

#[test]
fn fact_page_exact_budget_eof_versus_another_row() {
    let dir = TestDir::new("fact-page-exact-budget");
    let meta = create(&dir);

    // Each row is 4 bytes key + 6 bytes value = 10 bytes total.
    publish(
        &meta,
        &[
            put(FactTable::Refs, b"ref1", b"val001"),
            put(FactTable::Refs, b"ref2", b"val002"),
        ],
    );

    // Page 1 with budget 10 bytes: exactly fits row 1 (10 bytes).
    // Because row 2 exists in the table, more MUST be true.
    let page1 = meta
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 10))
        .expect("page 1");
    assert_eq!(page1.rows.len(), 1);
    assert_eq!(page1.rows[0].key, b"ref1");
    assert_eq!(page1.rows[0].value, b"val001");
    assert!(page1.more, "more must be true when another row exists");

    // Page 2 with budget 10 bytes: exactly fits row 2 (10 bytes).
    // Because no more rows exist (iterator exhausted), more MUST be false.
    let page2 = meta
        .fact_page(FactTable::Refs, Some(b"ref1"), FactPageBudget::new(10, 10))
        .expect("page 2");
    assert_eq!(page2.rows.len(), 1);
    assert_eq!(page2.rows[0].key, b"ref2");
    assert_eq!(page2.rows[0].value, b"val002");
    assert!(
        !page2.more,
        "more must be false when iterator is exhausted at exact budget"
    );

    // Case B: Table with only ONE row. Budget is exact match (10 bytes).
    let dir_single = TestDir::new("fact-page-exact-single");
    let meta_single = create(&dir_single);
    publish(&meta_single, &[put(FactTable::Refs, b"ref1", b"val001")]);

    let single_page = meta_single
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 10))
        .expect("single page");
    assert_eq!(single_page.rows.len(), 1);
    assert_eq!(single_page.rows[0].key, b"ref1");
    assert_eq!(single_page.rows[0].value, b"val001");
    assert!(
        !single_page.more,
        "more must be false on EOF at exact budget"
    );
}

#[test]
fn fact_page_counts_both_key_and_value_bytes() {
    let dir = TestDir::new("fact-page-key-bytes");
    let meta = create(&dir);

    // key is 40 bytes, value is 10 bytes => 50 bytes total.
    let long_key = vec![b'k'; 40];
    let value = vec![b'v'; 10];
    publish(&meta, &[put(FactTable::Changes, &long_key, &value)]);

    // If only value bytes (10) were counted, budget of 25 would mistakenly accept it.
    // Key byte accounting requires 50 bytes, so 49 must return Limit.
    let err = meta
        .fact_page(FactTable::Changes, None, FactPageBudget::new(10, 49))
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Limit(_)),
        "expected Limit, got {err:?}"
    );

    // Budget of 50 bytes accepts it exactly.
    let page = meta
        .fact_page(FactTable::Changes, None, FactPageBudget::new(10, 50))
        .expect("exact page");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].key, long_key);
    assert_eq!(page.rows[0].value, value);
    assert!(!page.more);
}

#[test]
fn fact_page_exact_sequence_across_row_boundaries() {
    let dir = TestDir::new("fact-page-row-boundaries");
    let meta = create(&dir);

    // Insert 20 rows in unordered sequence.
    let mut expected = Vec::new();
    let mut mutations = Vec::new();
    for i in [
        13_u8, 5, 19, 2, 8, 1, 17, 10, 4, 16, 7, 0, 14, 6, 18, 3, 9, 11, 15, 12,
    ] {
        let key = format!("ref/{i:02}").into_bytes();
        let value = format!("target-for-{i:02}").into_bytes();
        expected.push((key.clone(), value.clone()));
        mutations.push(put(FactTable::Refs, &key, &value));
    }
    expected.sort();
    publish(&meta, &mutations);

    // Page with row limit 3 and large byte budget.
    let mut seen = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let page = meta
            .fact_page(
                FactTable::Refs,
                cursor.as_deref(),
                FactPageBudget::new(3, 100_000),
            )
            .expect("page");
        assert!(page.rows.len() <= 3);
        assert_eq!(
            page.more,
            seen.len() + page.rows.len() < expected.len(),
            "more must match remaining rows"
        );
        for row in &page.rows {
            seen.push((row.key.clone(), row.value.clone()));
        }
        match page.rows.last() {
            Some(last) => cursor = Some(last.key.clone()),
            None => break,
        }
        if !page.more {
            break;
        }
    }

    assert_eq!(seen.len(), expected.len());
    assert_eq!(
        seen, expected,
        "every record must appear exactly once in raw key order"
    );

    // Reading again after the last key returns empty and more=false.
    let final_page = meta
        .fact_page(
            FactTable::Refs,
            cursor.as_deref(),
            FactPageBudget::new(3, 100_000),
        )
        .expect("final page");
    assert!(final_page.rows.is_empty());
    assert!(!final_page.more);
}

#[test]
fn fact_page_exact_sequence_across_byte_boundaries() {
    let dir = TestDir::new("fact-page-byte-boundaries");
    let meta = create(&dir);

    // 15 rows with varied key and value lengths.
    let mut expected = Vec::new();
    let mut mutations = Vec::new();
    for i in 0..15_u8 {
        let key = format!("k{:02}_{}", i, "x".repeat(usize::from(i % 5))).into_bytes();
        let value = format!("v{:02}_{}", i, "y".repeat(usize::from(i % 7))).into_bytes();
        expected.push((key.clone(), value.clone()));
        mutations.push(put(FactTable::Changes, &key, &value));
    }
    expected.sort();
    publish(&meta, &mutations);

    // Page with tight byte budget: 35 bytes (each row is ~10-25 bytes).
    let byte_budget = 35;
    let mut seen = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    let mut page_count = 0;

    loop {
        page_count += 1;
        let page = meta
            .fact_page(
                FactTable::Changes,
                cursor.as_deref(),
                FactPageBudget::new(100, byte_budget),
            )
            .expect("byte page");

        let page_bytes: usize = page.rows.iter().map(|r| r.key.len() + r.value.len()).sum();
        assert!(
            page_bytes <= byte_budget,
            "page bytes {page_bytes} exceeded budget {byte_budget}"
        );
        assert!(!page.rows.is_empty(), "non-empty table should yield rows");

        for row in &page.rows {
            seen.push((row.key.clone(), row.value.clone()));
        }

        assert_eq!(
            page.more,
            seen.len() < expected.len(),
            "more must be true iff there are remaining records"
        );

        cursor = Some(page.rows.last().unwrap().key.clone());
        if !page.more {
            break;
        }
    }

    assert!(
        page_count > 1,
        "must require multiple pages to exercise byte boundaries"
    );
    assert_eq!(seen.len(), expected.len());
    assert_eq!(
        seen, expected,
        "no skipped or duplicated records across byte splits"
    );
}

#[test]
fn fact_page_clamps_rows_at_1024() {
    let dir = TestDir::new("fact-page-clamp-1024");
    let meta = create(&dir);

    let total = 1100_usize;
    let mut expected = Vec::with_capacity(total);
    let mut mutations = Vec::with_capacity(total);
    for i in 0..total {
        let key = format!("ref/{i:04}").into_bytes();
        let value = format!("val/{i:04}").into_bytes();
        expected.push((key.clone(), value.clone()));
        mutations.push(put(FactTable::Refs, &key, &value));
    }
    expected.sort();
    publish(&meta, &mutations);

    // Request 2000 rows (exceeds clamp of 1024) with generous byte budget.
    let page1 = meta
        .fact_page(FactTable::Refs, None, FactPageBudget::new(2000, 10_000_000))
        .expect("page 1");
    assert_eq!(page1.rows.len(), 1024, "page must be clamped to 1024 rows");
    assert!(page1.more, "more must be true when rows remain");

    let page2 = meta
        .fact_page(
            FactTable::Refs,
            Some(&page1.rows.last().unwrap().key),
            FactPageBudget::new(2000, 10_000_000),
        )
        .expect("page 2");
    assert_eq!(page2.rows.len(), total - 1024);
    assert!(!page2.more);

    let mut combined = page1.rows;
    combined.extend(page2.rows);
    let seen: Vec<(Vec<u8>, Vec<u8>)> = combined.into_iter().map(|r| (r.key, r.value)).collect();
    assert_eq!(seen, expected);
}

#[test]
fn fact_page_refuses_when_store_is_quarantined() {
    let dir = TestDir::new("fact-page-quarantine");
    let store_root = dir.0.join("store");
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store = Store::create(&store_root, HashKind::Sha1, budget).expect("create store");

    // Publish one fact.
    let facts = [cas(
        FactTable::Refs,
        b"refs/heads/main",
        FactExpectation::Absent,
        some(b"hash1"),
    )];
    store.publish(vec![], &facts).expect("publish fact");

    // Verify healthy fact_page works through Store.
    let page = store
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 1024))
        .expect("healthy fact page");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].key, b"refs/heads/main");
    assert!(!store.quarantine());

    // Inject corruption observation into store to latch quarantine.
    let observed_err = StoreError::Corrupt("metadata sector damaged".to_owned());
    let _ = store.observe(Err::<(), _>(observed_err));
    assert!(
        store.quarantine(),
        "store must be quarantined after observing Corrupt"
    );

    // Store::fact_page must now refuse due to quarantine.
    let err = store
        .fact_page(FactTable::Refs, None, FactPageBudget::new(10, 1024))
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Corrupt(_)),
        "quarantined store must return Corrupt, got {err:?}"
    );
}
