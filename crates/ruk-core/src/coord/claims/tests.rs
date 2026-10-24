use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::capability::{Capabilities, ReadIntents};
use crate::coord::leases::{AcquireArgs, CursorWant, LeaseKind, LeaseRegistry};
use crate::ids::HashKind;
use crate::protocol::{
    ClaimHolderFilter, ClaimListArgs, EditAction, Mutation, PageCursor, QueryDigest, Request,
    WriteArgs, WriteEdit,
};
use crate::protocol::{ClaimSubject, ClaimTtl, TaskKey};
use crate::store::{EventContext, EventSource, PreparationBudget};
use crate::{ByteString, OperationId, RequestId, StoreId, WorkspaceId};

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    store: Store,
    clock: Clock,
    claims: ClaimClock,
    _root: Root,
}

impl Fixture {
    fn new() -> Self {
        let root =
            Root(std::env::temp_dir().join(format!("ruk-claim-test-{}", ClaimId::generate())));
        let store = Store::create(
            &root.0,
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        let wall = "2026-10-17T12:00:00Z".parse().expect("wall time");
        let clock = Clock::injected(wall, Instant::now());
        let claims = ClaimClock::open(&store, clock.clone()).expect("claim clock");
        Self {
            store,
            clock,
            claims,
            _root: root,
        }
    }

    fn acquire(
        &self,
        holder: SessionId,
        id: ClaimId,
        paths: &[&str],
        mode: ClaimMode,
    ) -> ClaimRecord {
        let change = seal_acquire(
            &self.store,
            &self.claims,
            holder,
            id,
            args(paths, mode),
            None,
        )
        .expect("acquire");
        self.store
            .publish(
                Vec::new(),
                &change.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish claim");
        change.record
    }
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text.as_bytes()).expect("valid path")
}
fn holder(value: u8) -> SessionId {
    SessionId::from_bytes([value; 16])
}
fn claim(value: u8) -> ClaimId {
    ClaimId::from_bytes([value; 16])
}
fn args(paths: &[&str], mode: ClaimMode) -> ClaimAcquireArgs {
    ClaimAcquireArgs {
        paths: paths.iter().map(|text| path(text)).collect(),
        ttl: ClaimTtl::new(60).expect("ttl"),
        mode,
        subject: None,
    }
}
fn write_error(result: Result<ClaimCheck, CoreError>) -> ErrorCode {
    match result {
        Ok(_) => panic!("write unexpectedly permitted"),
        Err(error) => error.code,
    }
}
fn acquire_error(result: Result<ClaimChange, CoreError>) -> ErrorCode {
    match result {
        Ok(_) => panic!("acquisition unexpectedly permitted"),
        Err(error) => error.code,
    }
}
fn renew_error(result: Result<ClaimChange, CoreError>) -> ErrorCode {
    match result {
        Ok(_) => panic!("renewal unexpectedly permitted"),
        Err(error) => error.code,
    }
}
fn task_subject() -> ClaimSubject {
    ClaimSubject::Task(TaskKey::new("01JATASKKEYEXAMPLE000000001").expect("task key"))
}
fn task_args(paths: &[&str], seconds: u32) -> ClaimAcquireArgs {
    ClaimAcquireArgs {
        paths: paths.iter().map(|text| path(text)).collect(),
        ttl: ClaimTtl::new(seconds).expect("ttl"),
        mode: ClaimMode::Enforce,
        subject: Some(task_subject()),
    }
}
fn publish(change: &ClaimChange, fixture: &Fixture) {
    fixture
        .store
        .publish(
            Vec::new(),
            &change.facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish claim");
}

#[test]
fn task_claim_acquire_carries_subject_and_allows_longer_ttl() {
    let fixture = Fixture::new();
    let change = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(1),
        task_args(&["src"], 24 * 3600),
        None,
    )
    .expect("task acquire");
    publish(&change, &fixture);
    let stored = read_record(&fixture.store, claim(1))
        .expect("read")
        .expect("record");
    assert_eq!(stored.subject, Some(task_subject()));
    assert_eq!(stored.holder, holder(1));
    // A subject-less claim cannot take a task-lease lifetime.
    assert_eq!(
        acquire_error(seal_acquire(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(2),
            ClaimAcquireArgs {
                paths: vec![path("other")],
                ttl: ClaimTtl::new(3601).expect("ttl"),
                mode: ClaimMode::Enforce,
                subject: None,
            },
            None,
        )),
        ErrorCode::EInvalid
    );
}

#[test]
fn claim_renew_extends_window_and_preserves_subject() {
    let fixture = Fixture::new();
    let original = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(1),
        task_args(&["src"], 60),
        None,
    )
    .expect("task acquire");
    publish(&original, &fixture);
    fixture
        .clock
        .advance_injected(Duration::from_secs(30), None)
        .expect("advance");
    let renewed =
        seal_renew(&fixture.store, &fixture.claims, holder(1), claim(1), 120).expect("renew");
    assert!(renewed.record.expires_at > original.record.expires_at);
    assert_eq!(renewed.record.subject, Some(task_subject()));
    assert_eq!(renewed.record.paths, original.record.paths);
    assert_eq!(renewed.record.mode, original.record.mode);
    assert_eq!(renewed.record.holder, original.record.holder);
    assert_eq!(renewed.record.claim, original.record.claim);
    publish(&renewed, &fixture);
    let stored = read_record(&fixture.store, claim(1))
        .expect("read")
        .expect("record");
    assert_eq!(stored.expires_at, renewed.record.expires_at);
    assert_eq!(stored.subject, Some(task_subject()));
}

#[test]
fn claim_renew_refuses_expired_and_foreign_claims() {
    let fixture = Fixture::new();
    let change = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(1),
        task_args(&["src"], 60),
        None,
    )
    .expect("task acquire");
    publish(&change, &fixture);
    assert_eq!(
        renew_error(seal_renew(
            &fixture.store,
            &fixture.claims,
            holder(2),
            claim(1),
            60
        )),
        ErrorCode::EForbidden
    );
    fixture
        .clock
        .advance_injected(Duration::from_secs(60), None)
        .expect("expire");
    assert_eq!(
        renew_error(seal_renew(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(1),
            60
        )),
        ErrorCode::EStale
    );
    assert_eq!(
        renew_error(seal_renew(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(9),
            60
        )),
        ErrorCode::ENotFound
    );
}

#[test]
fn claim_sweep_removes_only_expired_records() {
    let fixture = Fixture::new();
    let first = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(1),
        task_args(&["old"], 60),
        None,
    )
    .expect("first acquire");
    publish(&first, &fixture);
    fixture
        .clock
        .advance_injected(Duration::from_secs(59), None)
        .expect("advance");
    let second = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(2),
        task_args(&["new"], 60),
        None,
    )
    .expect("second acquire");
    publish(&second, &fixture);
    fixture
        .clock
        .advance_injected(Duration::from_secs(2), None)
        .expect("expire first");
    let sweep = sweep_page(
        &fixture.store,
        &fixture.claims,
        None,
        FactPageBudget::new(10, 4096),
    )
    .expect("select sweep");
    assert!(!sweep.facts.is_empty(), "expired claim must sweep");
    fixture
        .store
        .publish(
            Vec::new(),
            &sweep.facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish sweep");
    assert!(
        read_record(&fixture.store, claim(1))
            .expect("read")
            .is_none(),
        "expired claim must delete"
    );
    assert!(
        read_record(&fixture.store, claim(2))
            .expect("read")
            .is_some(),
        "live claim must survive"
    );
    let idle = sweep_page(
        &fixture.store,
        &fixture.claims,
        None,
        FactPageBudget::new(10, 4096),
    )
    .expect("reselect sweep");
    assert!(
        idle.facts.is_empty(),
        "a clean table sweeps nothing, not even the fence"
    );
}

#[test]
fn pre_subject_claim_decodes_with_empty_subject() {
    let fixture = Fixture::new();
    let now = fixture.claims.now().expect("now");
    let then = Timestamp::new(
        now.instant()
            .checked_add(jiff::SignedDuration::from_secs(60))
            .expect("expiry"),
    );
    let old = super::ClaimRowV2 {
        version: 2,
        created: now,
        record: super::ClaimRecordV2 {
            claim: claim(8),
            holder: holder(1),
            paths: vec![path("v2")],
            mode: ClaimMode::Enforce,
            expires_at: then,
            on_behalf_of: Some("hook".to_owned()),
        },
    };
    let raw = crate::store::encode("claim", &old).expect("encode v2 row");
    let row = decode_claim(&fixture.store, &record_key(claim(8)), &raw).expect("v2 decodes");
    assert_eq!(row.version, super::CLAIM_ROW_VERSION);
    assert_eq!(row.record.claim, claim(8));
    assert_eq!(row.record.on_behalf_of, Some("hook".to_owned()));
    assert_eq!(row.record.subject, None);
}

#[test]
fn live_holders_exports_only_live_holders() {
    let fixture = Fixture::new();
    for (holder_id, claim_id, paths) in [(1, 1, &["a"][..]), (2, 2, &["b"][..])] {
        let change = seal_acquire(
            &fixture.store,
            &fixture.claims,
            holder(holder_id),
            claim(claim_id),
            task_args(paths, 60),
            None,
        )
        .expect("acquire");
        publish(&change, &fixture);
    }
    fixture
        .clock
        .advance_injected(Duration::from_secs(60), None)
        .expect("expire");
    let change = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(2),
        claim(3),
        task_args(&["c"], 60),
        None,
    )
    .expect("reacquire");
    publish(&change, &fixture);
    assert_eq!(
        live_holders(&fixture.store, &fixture.claims, &[holder(1), holder(2)]).expect("holders"),
        vec![holder(2)]
    );
}

#[test]
fn retention_holder_check_is_bounded_to_selected_sessions() {
    let fixture = Fixture::new();
    for i in 10..60u8 {
        let p = format!("seeded-path-{i}");
        let change = seal_acquire(
            &fixture.store,
            &fixture.claims,
            holder(i),
            claim(i),
            task_args(&[&p], 60),
            None,
        )
        .expect("acquire background claim");
        publish(&change, &fixture);
    }

    let live_change = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(1),
        claim(1),
        task_args(&["live-path"], 60),
        None,
    )
    .expect("acquire live claim");
    publish(&live_change, &fixture);

    let expired_change = seal_acquire(
        &fixture.store,
        &fixture.claims,
        holder(2),
        claim(2),
        task_args(&["expired-path"], 10),
        None,
    )
    .expect("acquire expired claim");
    publish(&expired_change, &fixture);

    fixture
        .clock
        .advance_injected(Duration::from_secs(20), None)
        .expect("advance clock past expired claim");

    let empty_before = fixture.store.io_stats();
    let empty_holders =
        live_holders(&fixture.store, &fixture.claims, &[]).expect("empty candidates");
    assert!(empty_holders.is_empty());
    let empty_after = fixture.store.io_stats();
    assert_eq!(empty_after.fact_page_calls, empty_before.fact_page_calls);
    assert_eq!(empty_after.fact_rows, empty_before.fact_rows);

    let before = fixture.store.io_stats();
    let protected = live_holders(
        &fixture.store,
        &fixture.claims,
        &[holder(1), holder(2), holder(3)],
    )
    .expect("bounded holders lookup");
    assert_eq!(protected, vec![holder(1)]);

    let after = fixture.store.io_stats();
    let page_calls = after.fact_page_calls - before.fact_page_calls;
    let fact_rows = after.fact_rows - before.fact_rows;
    assert!(page_calls <= 3);
    assert!(
        fact_rows <= 6,
        "holder lookups must read at most a couple of rows per candidate, got {fact_rows}"
    );
}

#[test]
fn components_block_ancestors_and_descendants_but_not_byte_prefixes() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["a/b"], ClaimMode::Enforce);
    for blocked in ["a", "a/b", "a/b/c"] {
        assert_eq!(
            write_error(seal_write(
                &fixture.store,
                &fixture.claims,
                holder(2),
                &[path(blocked)]
            )),
            ErrorCode::EClaimed
        );
    }
    for permitted in ["ab", "a/bb", "a/c"] {
        let check = seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path(permitted)],
        )
        .expect("unrelated component");
        assert!(check.warnings.items.is_empty());
    }
    seal_write(&fixture.store, &fixture.claims, holder(1), &[path("a/b/c")]).expect("same holder");
}

#[test]
fn canonicalization_finds_ancestors_separated_by_lexical_neighbors() {
    let fixture = Fixture::new();
    let record = fixture.acquire(
        holder(1),
        claim(1),
        &["a/b", "a-else", "a", "z/c", "z"],
        ClaimMode::Enforce,
    );
    assert_eq!(record.paths, vec![path("a"), path("a-else"), path("z")]);
    assert!(
        fixture
            .store
            .fact(
                FactTable::Claims,
                &[b"Pa/b\0".as_slice(), claim(1).as_bytes()].concat()
            )
            .expect("lookup")
            .is_none()
    );
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("z/c/d")]
        )),
        ErrorCode::EClaimed
    );
}

#[test]
fn advisory_claims_warn_only_other_holders_without_duplicate_warnings() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["a"], ClaimMode::Advise);
    fixture.acquire(holder(1), claim(2), &["a/b"], ClaimMode::Advise);
    let check = seal_write(&fixture.store, &fixture.claims, holder(2), &[path("a/b/c")])
        .expect("advisory write");
    assert_eq!(
        check.warnings.items,
        vec![Warning::ClaimAdvisory {
            path: path("a/b/c"),
            holder: holder(1)
        }]
    );
    assert_eq!(check.warnings.total, 1);
    let own = seal_write(&fixture.store, &fixture.claims, holder(1), &[path("a/b/c")])
        .expect("own write");
    assert!(own.warnings.items.is_empty());
}

#[test]
fn concurrent_acquisitions_under_the_writer_lane_cannot_both_succeed() {
    let fixture = Fixture::new();
    let lane = Mutex::new(());
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            let _guard = lane.lock().expect("lane");
            match seal_acquire(
                &fixture.store,
                &fixture.claims,
                holder(1),
                claim(1),
                args(&["src"], ClaimMode::Enforce),
                None,
            ) {
                Ok(change) => {
                    fixture
                        .store
                        .publish(
                            Vec::new(),
                            &change.facts,
                            EventSource::LocalPush,
                            &EventContext::default(),
                        )
                        .expect("first publication");
                    Ok(())
                }
                Err(error) => Err(error.code),
            }
        });
        let second = scope.spawn(|| {
            let _guard = lane.lock().expect("lane");
            match seal_acquire(
                &fixture.store,
                &fixture.claims,
                holder(2),
                claim(2),
                args(&["src/lib.rs"], ClaimMode::Enforce),
                None,
            ) {
                Ok(change) => {
                    fixture
                        .store
                        .publish(
                            Vec::new(),
                            &change.facts,
                            EventSource::LocalPush,
                            &EventContext::default(),
                        )
                        .expect("second publication");
                    Ok(())
                }
                Err(error) => Err(error.code),
            }
        });
        [
            first.join().expect("first worker"),
            second.join().expect("second worker"),
        ]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ErrorCode::EClaimed))
            .count(),
        1
    );
}

#[test]
fn release_rejects_another_holder_and_removes_every_index_atomically() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["src", "docs"], ClaimMode::Enforce);
    assert_eq!(
        acquire_error(seal_release(
            &fixture.store,
            &fixture.claims,
            holder(2),
            claim(1)
        )),
        ErrorCode::EForbidden
    );
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("docs/a")]
        )),
        ErrorCode::EClaimed
    );
    let release =
        seal_release(&fixture.store, &fixture.claims, holder(1), claim(1)).expect("release");
    fixture
        .store
        .publish(
            Vec::new(),
            &release.facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish release");
    for key in row_keys(&release.record).expect("keys") {
        assert!(
            fixture
                .store
                .fact(FactTable::Claims, &key)
                .expect("lookup")
                .is_none()
        );
    }
    seal_write(&fixture.store, &fixture.claims, holder(2), &[path("src/a")])
        .expect("released write");
}

#[test]
fn exact_expiry_and_persisted_clock_prevent_rollback_revival() {
    let fixture = Fixture::new();
    let original = fixture.acquire(holder(1), claim(1), &["src"], ClaimMode::Enforce);
    fixture
        .clock
        .advance_injected(Duration::from_secs(59), None)
        .expect("advance");
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("src/a")]
        )),
        ErrorCode::EClaimed
    );
    let old_wall = "2026-10-17T11:00:00Z".parse().expect("old wall");
    fixture
        .clock
        .advance_injected(Duration::from_secs(1), Some(old_wall))
        .expect("rollback");
    let check = seal_write(&fixture.store, &fixture.claims, holder(2), &[path("src/a")])
        .expect("exact expiration");
    fixture
        .store
        .publish(
            Vec::new(),
            &check.facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("persist permitted mutation's clock");
    let restarted = ClaimClock::open(&fixture.store, Clock::injected(old_wall, Instant::now()))
        .expect("restart clock");
    seal_write(&fixture.store, &restarted, holder(2), &[path("src/a")])
        .expect("expired claim cannot revive");
    let (_, retained) = read_claim(&fixture.store, claim(1))
        .expect("read")
        .expect("retained row");
    assert_eq!(retained.record.expires_at, original.expires_at);
}

#[test]
fn filtered_claim_page_preserves_continuation_to_live_records() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["old"], ClaimMode::Enforce);
    fixture
        .clock
        .advance_injected(Duration::from_secs(60), None)
        .expect("expire first");
    fixture.acquire(holder(1), claim(2), &["new"], ClaimMode::Enforce);
    let scratch =
        std::env::temp_dir().join(format!("ruk-claim-lease-filtered-{}", ClaimId::generate()));
    let leases = LeaseRegistry::new(fixture.clock.clone(), scratch.clone());
    let start = fixture.clock.sample().expect("sample").mono;
    let store_id = StoreId::from_bytes([1; 16]);
    let view = OperationId(7);
    let query = QueryDigest::from_bytes([3; 32]);
    let (lease, _cancel, _guard) = leases
        .acquire(
            AcquireArgs {
                kind: LeaseKind::Interactive,
                store: store_id,
                session: holder(1),
                view,
                query,
                roots: Vec::new(),
                op_floor: None,
                position_bytes: 64,
                view_retained: true,
            },
            start,
        )
        .expect("acquire");
    let cursor = PageCursor {
        store: store_id,
        view,
        query,
        lease,
        position: ByteString::from(Vec::new()),
    };
    let want = CursorWant {
        store: store_id,
        session: holder(1),
        view,
        query,
    };
    let page = |cursor: &PageCursor, listing: ClaimListing, now: Instant| {
        list_page(LeasedClaimPage {
            store: &fixture.store,
            clock: &fixture.claims,
            leases: &leases,
            listing,
            cursor,
            want: &want,
            now,
            budget: FactPageBudget::new(1, 4096),
        })
    };
    let (first, _) = page(&cursor, ClaimListing::Mine(holder(1)), start).expect("first page");
    assert!(first.records.is_empty());
    let resume =
        next_claim_cursor(&cursor, first.next).expect("filtered row must not end the listing");
    let (second, _) = page(&resume, ClaimListing::Mine(holder(1)), start).expect("second page");
    assert_eq!(
        second
            .records
            .iter()
            .map(|row| row.claim)
            .collect::<Vec<_>>(),
        vec![claim(2)]
    );
    assert!(page(&resume, ClaimListing::Mine(holder(2)), start).is_err());
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn orphaned_path_index_quarantines_instead_of_allowing_a_write() {
    let fixture = Fixture::new();
    let key = [b"Psrc\0".as_slice(), claim(1).as_bytes()].concat();
    fixture
        .store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Claims,
                key,
                expected: FactExpectation::Absent,
                value: Some(Vec::new()),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("insert damaged index");
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("src/a")]
        )),
        ErrorCode::ECorrupt
    );
    assert!(fixture.store.quarantine());
}

#[test]
fn stale_expired_cleanup_cannot_remove_a_replaced_record() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["src"], ClaimMode::Enforce);
    fixture
        .clock
        .advance_injected(Duration::from_secs(60), None)
        .expect("expire");
    let cleanup = sweep_page(
        &fixture.store,
        &fixture.claims,
        None,
        FactPageBudget::new(10, 4096),
    )
    .expect("prepare cleanup");
    let (old, mut row) = read_claim(&fixture.store, claim(1))
        .expect("read")
        .expect("record");
    row.created = fixture.claims.now().expect("now");
    row.record.expires_at = Timestamp::new(
        row.created
            .instant()
            .checked_add(jiff::SignedDuration::from_secs(60))
            .expect("expiry"),
    );
    let replacement = crate::store::encode("claim", &row).expect("encode");
    fixture
        .store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Claims,
                key: record_key(claim(1)),
                expected: FactExpectation::Value(old),
                value: Some(replacement),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("replace under lane");
    assert!(matches!(
        fixture.store.publish(
            Vec::new(),
            &cleanup.facts,
            EventSource::LocalPush,
            &EventContext::default()
        ),
        Err(StoreError::StaleFact { .. })
    ));
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("src/a")]
        )),
        ErrorCode::EClaimed
    );
}

fn list_args(filter: ClaimHolderFilter) -> ClaimListArgs {
    ClaimListArgs {
        holder: filter,
        page: crate::protocol::PageRequest::default(),
    }
}

fn grant_claims() -> Capabilities {
    Capabilities {
        read_intents: ReadIntents {
            claims: true,
            ..ReadIntents::default()
        },
        ..Capabilities::default()
    }
}

fn grant_provenance() -> Capabilities {
    Capabilities {
        read_intents: ReadIntents {
            provenance: true,
            ..ReadIntents::default()
        },
        ..Capabilities::default()
    }
}

fn write_request(paths: &[&str]) -> Request {
    Request::Write(Box::new(Mutation {
        request_id: RequestId::generate(),
        args: WriteArgs {
            binding: crate::protocol::WorkspaceBinding {
                workspace: WorkspaceId::generate(),
                expected: crate::workspace::WorkspaceStamp::INITIAL,
            },
            edits: paths
                .iter()
                .map(|text| WriteEdit {
                    path: path(text),
                    action: EditAction::Delete,
                })
                .collect(),
        },
    }))
}

#[test]
fn claim_list_authorization_denies_and_grants() {
    let viewer = holder(1);
    let bare = Capabilities::default();
    assert_eq!(
        authorize_claim_list_args(&bare, viewer, &list_args(ClaimHolderFilter::Any))
            .err()
            .expect("any without intent")
            .code,
        ErrorCode::EForbidden
    );
    match authorize_claim_list_args(&bare, viewer, &list_args(ClaimHolderFilter::Mine))
        .expect("own listing")
    {
        ClaimListing::Mine(seen) => assert_eq!(seen, viewer),
        ClaimListing::AllAuthorized => panic!("mine resolved to all"),
    }
    match authorize_claim_list_args(&grant_claims(), viewer, &list_args(ClaimHolderFilter::Any))
        .expect("granted listing")
    {
        ClaimListing::AllAuthorized => (),
        ClaimListing::Mine(_) => panic!("any resolved to mine"),
    }
    assert_eq!(
        authorize_claim_listing(&bare, viewer, &ClaimListing::Mine(holder(2)))
            .expect_err("another holder without intent")
            .code,
        ErrorCode::EForbidden
    );
}

#[test]
fn provenance_read_authorization_denies_and_grants() {
    let viewer = holder(1);
    let bare = Capabilities::default();
    authorize_provenance_read(&bare, viewer, viewer).expect("own provenance");
    assert_eq!(
        authorize_provenance_read(&bare, viewer, holder(2))
            .expect_err("other without intent")
            .code,
        ErrorCode::EForbidden
    );
    authorize_provenance_read(&grant_provenance(), viewer, holder(2)).expect("granted provenance");
}

#[test]
fn seal_envelope_settles_on_publish_and_aborts_on_drop() {
    let fixture = Fixture::new();
    let guard = ClaimSealGuard::new(
        ClaimSealEnvelope::for_acquire(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(1),
            args(&["src"], ClaimMode::Enforce),
            None,
        )
        .expect("seal acquire"),
    );
    assert!(guard.envelope().is_some());
    let (facts, _, record) = guard.settle().expect("settle");
    assert!(record.is_some());
    fixture
        .store
        .publish(
            Vec::new(),
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish seal");
    assert_eq!(
        write_error(seal_write(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &[path("src/a")]
        )),
        ErrorCode::EClaimed
    );
    let aborted = ClaimSealGuard::new(
        ClaimSealEnvelope::for_acquire(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(9),
            args(&["aborted"], ClaimMode::Enforce),
            None,
        )
        .expect("seal aborted"),
    );
    aborted.abort();
    seal_write(
        &fixture.store,
        &fixture.claims,
        holder(2),
        &[path("aborted/x")],
    )
    .expect("aborted seal leaves no claim");
    let dropped = ClaimSealGuard::new(
        ClaimSealEnvelope::for_acquire(
            &fixture.store,
            &fixture.claims,
            holder(1),
            claim(8),
            args(&["dropped"], ClaimMode::Enforce),
            None,
        )
        .expect("seal dropped"),
    );
    drop(dropped);
    seal_write(
        &fixture.store,
        &fixture.claims,
        holder(2),
        &[path("dropped/x")],
    )
    .expect("dropped seal leaves no claim");
    let released =
        ClaimSealEnvelope::for_release(&fixture.store, &fixture.claims, holder(1), claim(1))
            .expect("seal release");
    let (facts, _, _) = released.settle();
    fixture
        .store
        .publish(
            Vec::new(),
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish release");
    seal_write(&fixture.store, &fixture.claims, holder(2), &[path("src/a")])
        .expect("released write");
}

#[test]
fn mutation_seal_covers_declared_write_paths() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["src"], ClaimMode::Enforce);
    assert_eq!(
        ClaimSealEnvelope::mutation_paths(&write_request(&["src/lib.rs"])),
        vec![path("src/lib.rs")]
    );
    assert!(ClaimSealEnvelope::mutation_paths(&write_request(&[])).is_empty());
    assert_eq!(
        ClaimSealEnvelope::for_mutation(
            &fixture.store,
            &fixture.claims,
            holder(2),
            &write_request(&["src/lib.rs"]),
            None,
            None,
        )
        .expect_err("blocked write")
        .code,
        ErrorCode::EClaimed
    );
    let envelope = ClaimSealEnvelope::for_mutation(
        &fixture.store,
        &fixture.claims,
        holder(2),
        &write_request(&["docs/a"]),
        None,
        None,
    )
    .expect("free write");
    let (facts, _, _) = envelope.settle();
    fixture
        .store
        .publish(
            Vec::new(),
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish fence");
}

#[test]
fn leased_claim_pages_refuse_stale_views() {
    let fixture = Fixture::new();
    fixture.acquire(holder(1), claim(1), &["a"], ClaimMode::Enforce);
    fixture.acquire(holder(1), claim(2), &["b"], ClaimMode::Enforce);
    let scratch = std::env::temp_dir().join(format!("ruk-claim-lease-{}", ClaimId::generate()));
    let leases = LeaseRegistry::new(fixture.clock.clone(), scratch.clone());
    let start = fixture.clock.sample().expect("sample").mono;
    let store_id = StoreId::from_bytes([1; 16]);
    let view = OperationId(7);
    let query = QueryDigest::from_bytes([3; 32]);
    let (lease, _cancel, _guard) = leases
        .acquire(
            AcquireArgs {
                kind: LeaseKind::Interactive,
                store: store_id,
                session: holder(1),
                view,
                query,
                roots: Vec::new(),
                op_floor: None,
                position_bytes: 64,
                view_retained: true,
            },
            start,
        )
        .expect("acquire");
    let cursor = PageCursor {
        store: store_id,
        view,
        query,
        lease,
        position: ByteString::from(Vec::new()),
    };
    let want = CursorWant {
        store: store_id,
        session: holder(1),
        view,
        query,
    };
    let page = |cursor: &PageCursor, want: &CursorWant, now: Instant| {
        list_page(LeasedClaimPage {
            store: &fixture.store,
            clock: &fixture.claims,
            leases: &leases,
            listing: listing_for_filter(ClaimHolderFilter::Mine, holder(1)),
            cursor,
            want,
            now,
            budget: FactPageBudget::new(1, 4096),
        })
    };
    let (first, binding) = page(&cursor, &want, start).expect("first page");
    assert_eq!(binding.lease, lease);
    assert_eq!(binding.kind, LeaseKind::Interactive);
    assert_eq!(first.records.len(), 1);
    let resume = next_claim_cursor(&cursor, first.next).expect("continuation");
    assert_eq!(resume.store, store_id);
    assert_eq!(resume.view, view);
    assert_eq!(resume.query, query);
    assert_eq!(resume.lease, lease);
    let (second, _) = page(&resume, &want, start).expect("second page");
    assert_eq!(second.records.len(), 1);
    assert_ne!(first.records, second.records);
    let stale = CursorWant {
        store: store_id,
        session: holder(1),
        view: OperationId(8),
        query,
    };
    assert_eq!(
        page(&resume, &stale, start).err().expect("stale view").code,
        ErrorCode::EForbidden
    );
    assert_eq!(
        page(
            &resume,
            &want,
            start + crate::coord::leases::INTERACTIVE_TTL
        )
        .err()
        .expect("expired lease")
        .code,
        ErrorCode::ELeaseLost
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn version_one_claim_decodes_without_provenance() {
    let fixture = Fixture::new();
    let now = fixture.claims.now().expect("now");
    let then = Timestamp::new(
        now.instant()
            .checked_add(jiff::SignedDuration::from_secs(60))
            .expect("expiry"),
    );
    let old = super::ClaimRowV1 {
        version: 1,
        created: now,
        record: super::ClaimRecordV1 {
            claim: claim(7),
            holder: holder(1),
            paths: vec![path("v1")],
            mode: ClaimMode::Enforce,
            expires_at: then,
        },
    };
    let raw = crate::store::encode("claim", &old).expect("encode v1 row");
    let row = decode_claim(&fixture.store, &record_key(claim(7)), &raw).expect("v1 decodes");
    assert_eq!(row.version, super::CLAIM_ROW_VERSION);
    assert_eq!(row.record.claim, claim(7));
    assert_eq!(row.record.on_behalf_of, None);
}
