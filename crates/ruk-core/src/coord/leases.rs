//! Bounded logical-lease registry and raw-root collection barrier.
//!
//! [`LeaseRegistry`] is the only entry point. It pairs a [`LeaseTable`]
//! (session/repository/query/view-bound leases with frozen lifetimes) with a
//! [`RootBarrier`] (Idle/Mark/SweepPending/Sweep/Closed with checked epochs)
//! behind one mutex held only for short critical sections. Disk I/O, scans,
//! and closure traversal always run outside the lock on detached snapshots
//! and handles, revalidating `(phase, cycle)` afterward.
//!
//! Safe handoff: expiry fires cancellation on the registry-held authority
//! handle, while the [`OwnerGuard`] retains the slot, roots, and charges
//! until the owned task actually terminates. Scope end or disconnect drops
//! the guard; cross-request durable plans and journals are never made
//! ephemeral here — the parent keeps those as durable roots outside this
//! registry.
//!
//! Budgets: one [`ByteBudget`] sized at [`LEASE_BOOKS_LIMIT`], restated from
//! the frozen [`crate::MAX_CONTROL_FRAME_BYTES`] as `u64`. Every lease,
//! gray entry, and condemned byte is reserved before it exists; refusal is
//! `E_LIMIT`. There is no separate lease-count knob: each entry carries a
//! nonzero measured charge, so the byte budget bounds the table. Scratch
//! files live under the parent-supplied `scratch_dir`; their bytes are
//! conservatively covered by the same budget charges.

pub(crate) mod barrier;
pub(crate) mod condemned;
pub(crate) mod table;
pub(crate) mod timing;

pub(crate) use barrier::{CollectionPhase, Dedupe, RootBarrier, SealedCycle, SweepOutcome};
pub(crate) use condemned::{BLOCK_LEN, BLOCK_RECORDS, CondemnedBuilder, CondemnedSet, RECORD_LEN};
pub(crate) use table::{
    AcquireArgs, BulkProgress, CursorWant, LeaseBinding, LeaseKind, RootOrigin,
};
pub(crate) use timing::{
    BULK_INTERVAL, BULK_NO_PROGRESS, BULK_TOTAL, GRAY_ALLOWANCE_BYTES, INTERACTIVE_TTL,
};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use crate::budget::{ByteBudget, ByteReservation};
use crate::coord::cancel::Cancel;
use crate::coord::clock::Clock;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::protocol::PageCursor;
use crate::{LeaseId, OperationId};

/// In-memory bookkeeping budget, restated from the frozen control-frame bound
/// ([`crate::MAX_CONTROL_FRAME_BYTES`]) as `u64`.
pub(crate) const LEASE_BOOKS_LIMIT: u64 = 16 * 1024 * 1024;

/// RAII protection for an admitted owner. Dropping the guard releases the
/// lease slot, its staged roots, and its charges even across disconnects.
/// Expiry cancels authority first but never releases early: the guard keeps
/// in-flight physical/logical protection until the owned task terminates.
#[must_use = "dropping the OwnerGuard releases the lease protection"]
pub(crate) struct OwnerGuard {
    lease: Option<LeaseId>,
    registry: Weak<LeaseRegistry>,
}

impl OwnerGuard {
    /// The protected lease, if still held.
    #[must_use]
    pub(crate) fn lease(&self) -> Option<LeaseId> {
        self.lease
    }

    /// Releases protection early; otherwise drop releases it.
    pub(crate) fn release(mut self) {
        if let Some(lease) = self.lease.take() {
            if let Some(registry) = self.registry.upgrade() {
                registry.release_owner(&lease);
            }
        }
    }
}

impl Drop for OwnerGuard {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            if let Some(registry) = self.registry.upgrade() {
                registry.release_owner(&lease);
            }
        }
    }
}

impl std::fmt::Debug for OwnerGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerGuard")
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

/// Detached frontier snapshot carrying its own budget reservation. The charge
/// lives exactly as long as the snapshot, so enumerated roots are accounted
/// while any collector holds them outside the registry lock.
#[derive(Debug)]
pub(crate) struct FrontierSnapshot {
    roots: Arc<Vec<Head>>,
    _charge: ByteReservation,
}

impl FrontierSnapshot {
    /// The protected roots enumerated under the lock.
    #[must_use]
    pub(crate) fn roots(&self) -> &Arc<Vec<Head>> {
        &self.roots
    }

    /// Number of protected roots in the snapshot.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the snapshot holds no roots.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// Locked registry state. All lock holds are short: no I/O, scans, fsync, or
/// traversal under the mutex.
struct State {
    table: table::LeaseTable,
    barrier: RootBarrier,
    live_roots: HashMap<Head, u32>,
    lease_roots: HashMap<LeaseId, Vec<Head>>,
}

/// Bounded lease registry plus collection barrier. Shared as
/// `Arc<LeaseRegistry>`; owner guards hold a [`Weak`] back-reference so a
/// leaked guard can never keep the registry alive.
pub(crate) struct LeaseRegistry {
    clock: Clock,
    books: Arc<ByteBudget>,
    scratch_dir: PathBuf,
    inner: Mutex<State>,
}

impl LeaseRegistry {
    /// Empty registry charging `LEASE_BOOKS_LIMIT` and spilling condemned
    /// files under `scratch_dir`. Performs no I/O.
    #[must_use]
    pub(crate) fn new(clock: Clock, scratch_dir: PathBuf) -> Arc<Self> {
        let books = ByteBudget::new(LEASE_BOOKS_LIMIT);
        Arc::new(Self {
            clock,
            books: Arc::clone(&books),
            scratch_dir,
            inner: Mutex::new(State {
                table: table::LeaseTable::new(&books),
                barrier: RootBarrier::new(),
                live_roots: HashMap::new(),
                lease_roots: HashMap::new(),
            }),
        })
    }

    /// The coordinator clock for parent sampling.
    #[must_use]
    pub(crate) fn clock(&self) -> &Clock {
        &self.clock
    }

    /// Locks the state or fails closed on poisoning.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, CoreError> {
        self.inner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "lease registry lock poisoned"))
    }

    /// Acquires one lease. `args` carries binding, roots, floor, and the
    /// retained-view proof; `now` is the parent-sampled monotonic instant.
    pub(crate) fn acquire(
        self: &Arc<Self>,
        args: AcquireArgs,
        now: Instant,
    ) -> Result<(LeaseId, Cancel, OwnerGuard), CoreError> {
        // Phase one, under lock: refuse closed work and snapshot the
        // condemned handle when a sweep-phase check will be required.
        let snapshot = {
            let state = self.lock()?;
            if state.barrier.phase() == CollectionPhase::Closed {
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    "coordinator closed after ambiguous sweep-record failure",
                ));
            }
            let sweep = matches!(
                state.barrier.phase(),
                CollectionPhase::SweepPending | CollectionPhase::Sweep
            );
            let needs_lookup = sweep
                && args
                    .roots
                    .iter()
                    .any(|(_, origin)| *origin == RootOrigin::PrePivot);
            needs_lookup.then(|| (state.barrier.cycle(), state.barrier.condemned()))
        };
        // Phase two, outside the lock: real condemned membership lookups.
        let mut condemned_hits = Vec::new();
        if let Some((cycle, condemned)) = &snapshot {
            let Some(set) = condemned else {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "sweep phase without a condemned set",
                ));
            };
            for (root, origin) in &args.roots {
                if *origin != RootOrigin::PrePivot {
                    continue;
                }
                if set.contains(root)? {
                    condemned_hits.push((*root, *cycle));
                }
            }
        }
        // Phase three, under lock: revalidate the cycle, insert the lease,
        // stage roots, and record Mark-time gray work.
        let mut state = self.lock()?;
        for (_, cycle) in &condemned_hits {
            // A hit revalidates like a dedupe refusal: rollover goes stale,
            // a confirmed member rejects before any effect.
            state.barrier.confirm_dedupe(*cycle, true)?;
        }
        if let Some((cycle, _)) = &snapshot {
            state.barrier.confirm_dedupe(*cycle, false)?;
        }
        let root_list: Vec<Head> = args.roots.iter().map(|(root, _)| *root).collect();
        let in_mark = state.barrier.phase() == CollectionPhase::Mark;
        let (id, observer) = state.table.acquire(args, now)?;
        for root in &root_list {
            state
                .live_roots
                .entry(*root)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
        if in_mark {
            for root in &root_list {
                if let Err(err) = state.barrier.note_gray(*root) {
                    // Gray overflow aborts the cycle; roll the acquisition
                    // back so the caller retries cleanly in Idle.
                    for staged in &root_list {
                        unstage_root(&mut state.live_roots, staged);
                    }
                    state.table.remove(&id);
                    return Err(err);
                }
            }
        }
        state.lease_roots.insert(id, root_list);
        Ok((
            id,
            observer,
            OwnerGuard {
                lease: Some(id),
                registry: Arc::downgrade(self),
            },
        ))
    }

    /// Stages a late raw root under a live owning lease, before its first
    /// locator/object lookup. Derived references reuse the owning lease and
    /// never escape its lifetime: dropping the owner unstages them.
    pub(crate) fn stage_raw_root(
        &self,
        head: Head,
        origin: RootOrigin,
        owner: LeaseId,
    ) -> Result<(), CoreError> {
        let snapshot = {
            let state = self.lock()?;
            if state.barrier.phase() == CollectionPhase::Closed {
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    "coordinator closed after ambiguous sweep-record failure",
                ));
            }
            if !state.table.owner_live(&owner) {
                return Err(CoreError::new(
                    ErrorCode::ELeaseLost,
                    "staging owner holds no live lease",
                ));
            }
            let sweep = matches!(
                state.barrier.phase(),
                CollectionPhase::SweepPending | CollectionPhase::Sweep
            );
            (sweep && origin == RootOrigin::PrePivot)
                .then(|| (state.barrier.cycle(), state.barrier.condemned()))
        };
        if let Some((cycle, condemned)) = snapshot {
            let Some(set) = condemned else {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "sweep phase without a condemned set",
                ));
            };
            let member = set.contains(&head)?;
            let state = self.lock()?;
            state.barrier.confirm_dedupe(cycle, member)?;
        }
        let mut state = self.lock()?;
        if !state.table.owner_live(&owner) {
            return Err(CoreError::new(
                ErrorCode::ELeaseLost,
                "staging owner holds no live lease",
            ));
        }
        state
            .live_roots
            .entry(head)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        state.lease_roots.entry(owner).or_default().push(head);
        if state.barrier.phase() == CollectionPhase::Mark {
            state.barrier.note_gray(head)?;
        }
        Ok(())
    }

    /// Reports a deletion of a not-yet-enumerated untracked root row during
    /// Mark: bounded gray work plus a root-epoch increment.
    pub(crate) fn note_untracked_deletion(&self, head: Head) -> Result<(), CoreError> {
        let mut state = self.lock()?;
        state.barrier.note_gray(head)
    }

    /// Verifies a cursor against the calling request's binding. Mismatch is
    /// `E_FORBIDDEN`; correct binding on expired authority is `E_LEASE_LOST`.
    pub(crate) fn check_cursor(
        &self,
        cursor: &PageCursor,
        want: &CursorWant,
        now: Instant,
    ) -> Result<LeaseBinding, CoreError> {
        let mut state = self.lock()?;
        state.table.sweep_expiry(now);
        state.table.check_cursor(cursor, want, now)
    }

    /// Records owner progress. Heartbeats never move deadlines; admitted work
    /// re-arms only the interval, never the two-hour total.
    pub(crate) fn report_progress(
        &self,
        lease: &LeaseId,
        progress: BulkProgress,
        now: Instant,
    ) -> Result<(), CoreError> {
        let mut state = self.lock()?;
        // The arriving report is itself progress: renew first, then sweep.
        // Cancellation belongs to the sweeper acting on observed silence
        // between calls; a lease only dies when the sweep, not the owner,
        // finds it lapsed — once marked expired it never revives.
        let result = state.table.report_progress(lease, progress, now);
        state.table.sweep_expiry(now);
        result
    }

    /// Accounts one page's exact rows and copied bytes, reserving first.
    pub(crate) fn account_page(
        &self,
        lease: &LeaseId,
        rows: usize,
        bytes: u64,
        position_len: usize,
        now: Instant,
    ) -> Result<(), CoreError> {
        let mut state = self.lock()?;
        // A completed page is admitted work: stamp the renewal before the
        // sweep may judge silence, matching report_progress ordering.
        let result = state
            .table
            .account_page(lease, rows, bytes, position_len, now);
        state.table.sweep_expiry(now);
        result
    }

    /// Sweeps expired authority with the registry clock. Fires cancellation;
    /// RAII guards keep their protection until their tasks terminate.
    pub(crate) fn sweep_expiry(&self) -> Result<(), CoreError> {
        let now = self.clock.sample()?.mono;
        self.lock()?.table.sweep_expiry(now);
        Ok(())
    }

    /// Detached frontier snapshot of currently protected roots for
    /// enumeration outside the lock. Reserved from the books budget first;
    /// the returned handle carries its reservation for as long as the
    /// snapshot lives, per the budget's RAII rule.
    pub(crate) fn frontier_snapshot(&self) -> Result<FrontierSnapshot, CoreError> {
        let state = self.lock()?;
        let record = u64::try_from(RECORD_LEN)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "record size overflows u64"))?;
        let bytes = u64::try_from(state.live_roots.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "frontier size overflows u64"))?
            .checked_mul(record)
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "frontier charge overflows u64"))?;
        let charge = self.books.reserve(bytes).map_err(|refused| {
            CoreError::new(
                ErrorCode::ELimit,
                format!("frontier budget refused: {refused}"),
            )
        })?;
        let snapshot: Vec<Head> = state.live_roots.keys().copied().collect();
        Ok(FrontierSnapshot {
            roots: Arc::new(snapshot),
            _charge: charge,
        })
    }

    /// Begins `Mark` under sole lane ownership at the pivot generation.
    pub(crate) fn begin_mark(
        &self,
        pivot: u64,
        op_window: Option<(u64, u64)>,
    ) -> Result<(), CoreError> {
        self.lock()?.barrier.begin_mark(pivot, op_window)
    }

    /// Brackets large-frontier publication to scratch.
    pub(crate) fn begin_frontier_publish(&self) -> Result<(), CoreError> {
        self.lock()?.barrier.begin_frontier_publish()
    }

    /// Closes the frontier publication bracket.
    pub(crate) fn end_frontier_publish(&self) -> Result<(), CoreError> {
        self.lock()?.barrier.end_frontier_publish()
    }

    /// Marks root enumeration finished for `cycle`.
    pub(crate) fn finish_enumeration(&self, cycle: u64) -> Result<(), CoreError> {
        self.lock()?.barrier.finish_enumeration(cycle)
    }

    /// Acknowledges gray entries incorporated into the candidate.
    pub(crate) fn drain_gray(&self, through_epoch: u64) -> Result<(), CoreError> {
        self.lock()?.barrier.drain_gray(through_epoch)
    }

    /// Current cycle, for collectors correlating enumeration with seal.
    pub(crate) fn cycle(&self) -> Result<u64, CoreError> {
        Ok(self.lock()?.barrier.cycle())
    }

    /// Current root epoch, for collectors stamping candidates.
    pub(crate) fn root_epoch(&self) -> Result<u64, CoreError> {
        Ok(self.lock()?.barrier.root_epoch())
    }

    /// Current phase, for parent orchestration and tests.
    pub(crate) fn phase(&self) -> Result<CollectionPhase, CoreError> {
        Ok(self.lock()?.barrier.phase())
    }

    /// Seals the candidate, minting the token the parent carries through the
    /// durable sweep-record commit.
    pub(crate) fn seal_candidate(
        &self,
        cycle: u64,
        candidate_epoch: u64,
        condemned: Arc<CondemnedSet>,
    ) -> Result<SealedCycle, CoreError> {
        self.lock()?
            .barrier
            .seal_candidate(cycle, candidate_epoch, condemned)
    }

    /// Applies the parent's sweep-record commit outcome.
    pub(crate) fn sweep_record_outcome(
        &self,
        token: &SealedCycle,
        outcome: SweepOutcome,
    ) -> Result<(), CoreError> {
        self.lock()?.barrier.sweep_record_outcome(token, outcome)
    }

    /// Completes `Sweep` after the lane's final durable cursor/retirement
    /// transaction. The registry deletes nothing itself.
    pub(crate) fn complete_sweep(&self, token: &SealedCycle) -> Result<(), CoreError> {
        self.lock()?.barrier.complete_sweep(token)
    }

    /// Dedupe guidance for an existing object: condemned lookup outside the
    /// lock during sweep phases with cycle revalidation after; condemned
    /// members reject `E_LIMIT` before effects, everything else retains its
    /// original locator, delta base, and depth.
    pub(crate) fn check_dedupe(&self, head: &Head) -> Result<Dedupe, CoreError> {
        let snapshot = {
            let state = self.lock()?;
            if !state.barrier.dedupe_needs_lookup()? {
                return Ok(Dedupe::RetainOriginal);
            }
            (state.barrier.cycle(), state.barrier.condemned())
        };
        let (cycle, condemned) = snapshot;
        let Some(set) = condemned else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "sweep phase without a condemned set",
            ));
        };
        let member = set.contains(head)?;
        self.lock()?.barrier.confirm_dedupe(cycle, member)
    }

    /// Minimum retained-operation floor over live lease pins and the running
    /// collection window. The parent validates actual retained operations
    /// against this pin under sole lane ownership before pruning.
    pub(crate) fn min_retained_floor(&self) -> Result<Option<OperationId>, CoreError> {
        let state = self.lock()?;
        Ok(
            match (state.table.min_lease_floor(), state.barrier.cycle_floor()) {
                (Some(lease), Some(cycle)) => Some(OperationId(lease.0.min(cycle.0))),
                (Some(lease), None) => Some(lease),
                (None, Some(cycle)) => Some(cycle),
                (None, None) => None,
            },
        )
    }

    /// Copied rows and bytes recorded for `lease`.
    pub(crate) fn page_stats(&self, lease: &LeaseId) -> Result<(u64, u64), CoreError> {
        self.lock()?.table.page_stats(lease)
    }

    /// Live lease count, including expired-but-protected entries.
    pub(crate) fn lease_count(&self) -> Result<usize, CoreError> {
        Ok(self.lock()?.table.len())
    }

    /// Builds a condemned candidate builder charging this registry's books
    /// and spilling under its scratch directory.
    #[must_use]
    pub(crate) fn condemned_builder(self: &Arc<Self>) -> CondemnedBuilder {
        CondemnedBuilder::new(&self.books, &self.scratch_dir)
    }

    /// Releases owner protection for `lease`, unstaging its roots.
    pub(crate) fn release_owner(&self, lease: &LeaseId) {
        let Ok(mut state) = self.lock() else {
            return;
        };
        state.table.release_owner(lease);
        if let Some(roots) = state.lease_roots.remove(lease) {
            for root in roots {
                unstage_root(&mut state.live_roots, &root);
            }
        }
    }
}

/// Decrements a live-root owner count, removing the root at zero.
fn unstage_root(live: &mut HashMap<Head, u32>, root: &Head) {
    if let Some(count) = live.get_mut(root) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            live.remove(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Oid;
    use crate::protocol::QueryDigest;
    use crate::{SessionId, StoreId};
    use std::time::Duration;

    fn test_clock() -> Clock {
        Clock::injected(jiff::Timestamp::now(), Instant::now())
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ruk-leases-reg-{tag}"))
    }

    fn head(byte: u8) -> Head {
        Head::Git {
            oid: Oid::from_bytes(&[byte; 20]).expect("20-byte digest"),
        }
    }

    fn args(kind: LeaseKind, roots: Vec<(Head, RootOrigin)>) -> AcquireArgs {
        AcquireArgs {
            kind,
            store: StoreId::from_bytes([1; 16]),
            session: SessionId::from_bytes([2; 16]),
            view: OperationId(7),
            query: QueryDigest::from_bytes([3; 32]),
            roots,
            op_floor: Some(OperationId(5)),
            position_bytes: 16,
            view_retained: true,
        }
    }

    fn now(clock: &Clock) -> Instant {
        clock.sample().expect("sample").mono
    }

    #[test]
    fn expiry_cancels_authority_but_guard_retains_until_drop() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("expiry"));
        let start = now(&clock);
        let (id, observer, guard) = registry
            .acquire(
                args(
                    LeaseKind::Interactive,
                    vec![(head(1), RootOrigin::PostPivot)],
                ),
                start,
            )
            .expect("acquire");
        assert_eq!(guard.lease(), Some(id));
        let _ = registry.clock().sample().expect("clock samples");
        let late = start + INTERACTIVE_TTL;
        // Sweep with an explicit late sample: authority lapses and fires.
        registry.lock().expect("lock").table.sweep_expiry(late);
        assert_eq!(
            observer.check().expect_err("cancelled").code,
            ErrorCode::ECancelled
        );
        // Held work keeps slot, roots, and prune floor: expired but protected.
        assert_eq!(registry.lease_count().expect("count"), 1);
        assert_eq!(
            registry.min_retained_floor().expect("floor"),
            Some(OperationId(5))
        );
        assert!(!registry.frontier_snapshot().expect("snapshot").is_empty());
        drop(guard);
        registry.release_owner(&id);
        assert_eq!(registry.lease_count().expect("count"), 0);
        assert_eq!(registry.min_retained_floor().expect("floor"), None);
        assert!(registry.frontier_snapshot().expect("snapshot").is_empty());
        let _ = std::fs::remove_dir_all(scratch_dir("expiry"));
    }

    #[test]
    fn wrong_bindings_forbid_without_adopting() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("binding"));
        let start = now(&clock);
        let (id, _observer, _guard) = registry
            .acquire(args(LeaseKind::Interactive, Vec::new()), start)
            .expect("acquire");
        let cursor = PageCursor {
            store: StoreId::from_bytes([1; 16]),
            view: OperationId(7),
            query: QueryDigest::from_bytes([3; 32]),
            lease: id,
            position: crate::ByteString::from(vec![0_u8; 4]),
        };
        for (store, session, view, query) in [
            ([9; 16], [2; 16], 7, [3; 32]),
            ([1; 16], [9; 16], 7, [3; 32]),
            ([1; 16], [2; 16], 8, [3; 32]),
            ([1; 16], [2; 16], 7, [4; 32]),
        ] {
            let want = CursorWant {
                store: StoreId::from_bytes(store),
                session: SessionId::from_bytes(session),
                view: OperationId(view),
                query: QueryDigest::from_bytes(query),
            };
            let err = registry
                .check_cursor(&cursor, &want, start)
                .expect_err("mismatch forbids");
            assert_eq!(err.code, ErrorCode::EForbidden);
        }
        let _ = std::fs::remove_dir_all(scratch_dir("binding"));
    }

    #[test]
    fn bulk_total_lifetime_never_renews() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("bulk"));
        let start = now(&clock);
        let (id, _observer, _guard) = registry
            .acquire(args(LeaseKind::Bulk, Vec::new()), start)
            .expect("acquire");
        // Admitted progress every minute for the full lifetime still dies at 2h.
        // After the first admitted work stamps progress, the silence window
        // is 30 seconds, so admitted-work reports must arrive faster than that
        // to renew to the two-hour cap.
        let mut at = start;
        let mut step = Duration::from_secs(60);
        while at + step < start + BULK_TOTAL {
            at += step;
            registry
                .report_progress(&id, BulkProgress::AdmittedWork, at)
                .expect("renew");
            step = BULK_NO_PROGRESS - Duration::from_secs(5);
        }
        let err = registry
            .report_progress(&id, BulkProgress::AdmittedWork, start + BULK_TOTAL)
            .expect_err("total cap");
        assert_eq!(err.code, ErrorCode::ELeaseLost);
        let _ = std::fs::remove_dir_all(scratch_dir("bulk"));
    }

    #[test]
    fn prune_floor_held_until_owner_drops() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("floor"));
        let start = now(&clock);
        let (id, _observer, guard) = registry
            .acquire(args(LeaseKind::Bulk, Vec::new()), start)
            .expect("acquire");
        assert_eq!(
            registry.min_retained_floor().expect("floor"),
            Some(OperationId(5))
        );
        // Early release retires the lease at once with its floor pin.
        guard.release();
        assert_eq!(registry.lease_count().expect("count"), 0);
        assert_eq!(registry.min_retained_floor().expect("floor"), None);
        let _ = std::fs::remove_dir_all(scratch_dir("floor"));
    }

    #[test]
    fn insertion_before_closure_seals_after_drain() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("closure"));
        let start = now(&clock);
        registry.begin_mark(100, Some((3, 9))).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        // Raw insertion racing mark closure lands in gray and moves the epoch.
        let epoch_before = registry.root_epoch().expect("epoch");
        let (_id, _observer, _guard) = registry
            .acquire(
                args(LeaseKind::Bulk, vec![(head(4), RootOrigin::PrePivot)]),
                start,
            )
            .expect("acquire");
        assert!(registry.root_epoch().expect("epoch") > epoch_before);
        registry.finish_enumeration(cycle).expect("finish");
        let err = registry
            .seal_candidate(cycle, epoch_before, Arc::new(CondemnedSet::empty(cycle)))
            .expect_err("stale candidate epoch");
        assert_eq!(err.code, ErrorCode::EStale);
        registry
            .drain_gray(registry.root_epoch().expect("epoch"))
            .expect("drain");
        let token = registry
            .seal_candidate(
                cycle,
                registry.root_epoch().expect("epoch"),
                Arc::new(CondemnedSet::empty(cycle)),
            )
            .expect("seal after drain");
        assert_eq!(token.pivot(), 100);
        assert_eq!(
            registry.phase().expect("phase"),
            CollectionPhase::SweepPending
        );
        let _ = std::fs::remove_dir_all(scratch_dir("closure"));
    }

    #[test]
    fn gray_overflow_aborts_before_any_removal() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("overflow"));
        registry.begin_mark(1, None).expect("begin");
        // Exhaust the 16 MiB gray allowance with 34-byte records.
        let mut pushed = 0_u64;
        let overflow = loop {
            let byte = u8::try_from(pushed % 251).expect("modulo 251 fits u8");
            if registry.note_untracked_deletion(head(byte)).is_err() {
                break pushed;
            }
            pushed += 1;
            if pushed > 600_000 {
                break pushed;
            }
        };
        assert!(overflow > 0, "gray must fill before aborting");
        assert_eq!(registry.phase().expect("phase"), CollectionPhase::Idle);
        // Publication is unblocked: a fresh cycle begins immediately.
        registry.begin_mark(2, None).expect("begin after abort");
        let _ = std::fs::remove_dir_all(scratch_dir("overflow"));
    }

    #[test]
    fn condemned_member_rejects_before_effects_post_pivot_stays_live() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("condemned"));
        let start = now(&clock);
        registry.begin_mark(50, None).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        registry.finish_enumeration(cycle).expect("finish");
        let mut builder = registry.condemned_builder();
        builder.push(&head(6)).expect("push");
        let set = Arc::new(builder.seal(cycle).expect("seal"));
        let epoch = registry.root_epoch().expect("epoch");
        let token = registry.seal_candidate(cycle, epoch, set).expect("seal");
        registry
            .sweep_record_outcome(&token, SweepOutcome::Committed)
            .expect("sweep");
        // Pre-pivot condemned root: E_LIMIT before any lease exists.
        let err = registry
            .acquire(
                args(LeaseKind::Bulk, vec![(head(6), RootOrigin::PrePivot)]),
                start,
            )
            .expect_err("condemned reuse");
        assert_eq!(err.code, ErrorCode::ELimit);
        assert_eq!(registry.lease_count().expect("count"), 0);
        // Post-pivot root stays live in the same phase.
        registry
            .acquire(
                args(LeaseKind::Bulk, vec![(head(6), RootOrigin::PostPivot)]),
                start,
            )
            .expect("post-pivot live");
        // Dedupe agrees: member rejects, fresh root retains its locator.
        assert_eq!(
            registry.check_dedupe(&head(6)).expect_err("member").code,
            ErrorCode::ELimit
        );
        assert_eq!(
            registry.check_dedupe(&head(9)).expect("fresh"),
            Dedupe::RetainOriginal
        );
        let _ = std::fs::remove_dir_all(scratch_dir("condemned"));
    }

    #[test]
    fn completed_condemnation_does_not_haunt_next_cycle() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("rollover"));
        registry.begin_mark(7, None).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        registry.finish_enumeration(cycle).expect("finish");
        let mut builder = registry.condemned_builder();
        builder.push(&head(1)).expect("push");
        let set = Arc::new(builder.seal(cycle).expect("seal"));
        let token = registry
            .seal_candidate(cycle, registry.root_epoch().expect("epoch"), set)
            .expect("seal");
        registry
            .sweep_record_outcome(&token, SweepOutcome::Committed)
            .expect("sweep");
        assert_eq!(
            registry.check_dedupe(&head(1)).expect_err("member").code,
            ErrorCode::ELimit
        );
        registry.complete_sweep(&token).expect("complete");
        // The old cycle's verdict never leaks into the new one: the same
        // object retains its original locator once the sweep closes.
        assert_eq!(
            registry.check_dedupe(&head(1)).expect("fresh cycle"),
            Dedupe::RetainOriginal
        );
        let _ = std::fs::remove_dir_all(scratch_dir("rollover"));
    }

    #[test]
    fn candidate_failure_transitions_close_or_restore() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock.clone(), scratch_dir("failure"));
        registry.begin_mark(3, None).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        registry.finish_enumeration(cycle).expect("finish");
        let token = registry
            .seal_candidate(
                cycle,
                registry.root_epoch().expect("epoch"),
                Arc::new(CondemnedSet::empty(cycle)),
            )
            .expect("seal");
        registry
            .sweep_record_outcome(&token, SweepOutcome::DefiniteFailure)
            .expect("restore");
        assert_eq!(registry.phase().expect("phase"), CollectionPhase::Mark);

        let clock2 = test_clock();
        let registry2 = LeaseRegistry::new(clock2, scratch_dir("failure2"));
        registry2.begin_mark(3, None).expect("begin");
        let cycle2 = registry2.cycle().expect("cycle");
        registry2.finish_enumeration(cycle2).expect("finish");
        let token2 = registry2
            .seal_candidate(
                cycle2,
                registry2.root_epoch().expect("epoch"),
                Arc::new(CondemnedSet::empty(cycle2)),
            )
            .expect("seal");
        registry2
            .sweep_record_outcome(&token2, SweepOutcome::Ambiguous)
            .expect("close");
        assert_eq!(registry2.phase().expect("phase"), CollectionPhase::Closed);
        let err = registry2.begin_mark(4, None).expect_err("closed refuses");
        assert_eq!(err.code, ErrorCode::EIo);
        let _ = std::fs::remove_dir_all(scratch_dir("failure"));
        let _ = std::fs::remove_dir_all(scratch_dir("failure2"));
    }

    #[test]
    fn staging_threads_racing_closure_leave_valid_state() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock, scratch_dir("race"));
        let start = Instant::now();
        registry.begin_mark(9, None).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        std::thread::scope(|scope| {
            let stop = Arc::new(AtomicBool::new(false));
            let mut handles = Vec::new();
            for worker in 0..4_u8 {
                let stop = Arc::clone(&stop);
                let registry = Arc::clone(&registry);
                handles.push(scope.spawn(move || {
                    let mut n = 0_u8;
                    while !stop.load(Ordering::SeqCst) {
                        let stamp = head(worker.wrapping_mul(64).wrapping_add(n));
                        let acquired = registry.acquire(
                            args(LeaseKind::Bulk, vec![(stamp, RootOrigin::PrePivot)]),
                            start,
                        );
                        if let Ok((id, _observer, guard)) = acquired {
                            drop(guard);
                            registry.release_owner(&id);
                        }
                        n = n.wrapping_add(1);
                    }
                }));
            }
            // The main lane enumerates and seals while staging hammers gray:
            // either no racer landed between drain and seal (valid seal) or
            // one did (stale, retryable) — never an unchecked grant.
            registry.finish_enumeration(cycle).expect("finish");
            let _ = registry.drain_gray(registry.root_epoch().expect("epoch"));
            let seal = registry.seal_candidate(
                cycle,
                registry.root_epoch().expect("epoch"),
                Arc::new(CondemnedSet::empty(cycle)),
            );
            stop.store(true, Ordering::SeqCst);
            for handle in handles {
                handle.join().expect("worker");
            }
            match seal {
                Ok(token) => {
                    registry
                        .sweep_record_outcome(&token, SweepOutcome::Committed)
                        .expect("commit");
                    registry.complete_sweep(&token).expect("complete");
                    assert_eq!(registry.phase().expect("phase"), CollectionPhase::Idle);
                }
                Err(err) => {
                    assert_eq!(err.code, ErrorCode::EStale);
                    assert_eq!(registry.phase().expect("phase"), CollectionPhase::Mark);
                }
            }
        });
        let _ = std::fs::remove_dir_all(scratch_dir("race"));
    }

    #[test]
    fn sweep_phase_serves_concurrent_lookups_without_lock() {
        use std::sync::Barrier;
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock, scratch_dir("lookups"));
        registry.begin_mark(11, None).expect("begin");
        let cycle = registry.cycle().expect("cycle");
        registry.finish_enumeration(cycle).expect("finish");
        let mut builder = registry.condemned_builder();
        builder.push(&head(6)).expect("push");
        let token = registry
            .seal_candidate(
                cycle,
                registry.root_epoch().expect("epoch"),
                Arc::new(builder.seal(cycle).expect("seal")),
            )
            .expect("seal");
        registry
            .sweep_record_outcome(&token, SweepOutcome::Committed)
            .expect("sweep");
        let gate = Arc::new(Barrier::new(5));
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let gate = Arc::clone(&gate);
                let registry = Arc::clone(&registry);
                handles.push(scope.spawn(move || {
                    gate.wait();
                    // Throughout Sweep every lookup is cycle-checked: members
                    // reject, fresh roots retain, with real file I/O and no
                    // registry lock held by any thread here.
                    for _ in 0..25 {
                        assert_eq!(
                            registry.check_dedupe(&head(6)).expect_err("member").code,
                            ErrorCode::ELimit
                        );
                        assert_eq!(
                            registry.check_dedupe(&head(9)).expect("fresh"),
                            Dedupe::RetainOriginal
                        );
                    }
                    gate.wait();
                }));
            }
            gate.wait();
            gate.wait();
            for handle in handles {
                handle.join().expect("worker");
            }
        });
        registry.complete_sweep(&token).expect("complete");
        assert_eq!(registry.phase().expect("phase"), CollectionPhase::Idle);
        let _ = std::fs::remove_dir_all(scratch_dir("lookups"));
    }

    #[test]
    fn concurrent_acquires_and_stages_keep_invariants() {
        let clock = test_clock();
        let registry = LeaseRegistry::new(clock, scratch_dir("concurrent"));
        let start = Instant::now();
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for worker in 0..8_u8 {
                let registry = Arc::clone(&registry);
                handles.push(scope.spawn(move || {
                    for round in 0..25_u8 {
                        let root = head(worker.wrapping_mul(32).wrapping_add(round));
                        let (id, _observer, guard) = registry
                            .acquire(
                                args(LeaseKind::Interactive, vec![(root, RootOrigin::PostPivot)]),
                                start,
                            )
                            .expect("concurrent acquire");
                        registry
                            .stage_raw_root(head(200), RootOrigin::PostPivot, id)
                            .expect("concurrent stage");
                        registry
                            .account_page(&id, 10, 512, 8, start)
                            .expect("concurrent page");
                        // Each round acquires a fresh lease and copies exactly
                        // one page: per-lease accounting never accumulates
                        // across leases.
                        let (rows, bytes) = registry.page_stats(&id).expect("stats");
                        assert_eq!((rows, bytes), (10, 520));
                        drop(guard);
                        registry.release_owner(&id);
                    }
                }));
            }
            for handle in handles {
                handle.join().expect("worker");
            }
        });
        // Every owner released: no slot, root, or binding may leak.
        assert_eq!(registry.lease_count().expect("count"), 0);
        assert_eq!(registry.min_retained_floor().expect("floor"), None);
        assert!(registry.frontier_snapshot().expect("snapshot").is_empty());
        let _ = std::fs::remove_dir_all(scratch_dir("concurrent"));
    }
}

impl LeaseRegistry {
    /// Checks a claim-list page cursor against its leased view.
    ///
    /// Claim paging entry over [`LeaseRegistry::check_cursor`]: binding
    /// mismatch is `E_FORBIDDEN`, correct binding on expired authority is
    /// `E_LEASE_LOST`. The caller lists from the cursor position only after
    /// this check succeeds, so paged claim lists stay bound to the immutable
    /// leased view.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when the cursor binding differs from the request;
    /// `E_LEASE_LOST` when the lease is unknown, retired, or expired.
    pub(crate) fn check_claim_page_cursor(
        &self,
        cursor: &PageCursor,
        want: &CursorWant,
        now: Instant,
    ) -> Result<LeaseBinding, CoreError> {
        self.check_cursor(cursor, want, now)
    }
}
