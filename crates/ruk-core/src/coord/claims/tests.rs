use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::ids::HashKind;
use crate::protocol::ClaimTtl;
use crate::store::PreparationBudget;

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
        let change = seal_acquire(&self.store, &self.claims, holder, id, args(paths, mode))
            .expect("acquire");
        self.store
            .publish(Vec::new(), &change.facts)
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
            ) {
                Ok(change) => {
                    fixture
                        .store
                        .publish(Vec::new(), &change.facts)
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
            ) {
                Ok(change) => {
                    fixture
                        .store
                        .publish(Vec::new(), &change.facts)
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
        .publish(Vec::new(), &release.facts)
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
        .publish(Vec::new(), &check.facts)
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
    let first = list_page(
        &fixture.store,
        &fixture.claims,
        ClaimListing::Mine(holder(1)),
        None,
        FactPageBudget::new(1, 4096),
    )
    .expect("first page");
    assert!(first.records.is_empty());
    let next = first.next.expect("filtered row must not end the listing");
    let second = list_page(
        &fixture.store,
        &fixture.claims,
        ClaimListing::Mine(holder(1)),
        Some(&next),
        FactPageBudget::new(1, 4096),
    )
    .expect("second page");
    assert_eq!(
        second
            .records
            .iter()
            .map(|row| row.claim)
            .collect::<Vec<_>>(),
        vec![claim(2)]
    );
    assert!(
        list_page(
            &fixture.store,
            &fixture.claims,
            ClaimListing::Mine(holder(2)),
            Some(&next),
            FactPageBudget::new(1, 4096)
        )
        .is_err()
    );
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
        )
        .expect("replace under lane");
    assert!(matches!(
        fixture.store.publish(Vec::new(), &cleanup.facts),
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
