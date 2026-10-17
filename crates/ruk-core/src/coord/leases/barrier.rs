//! Raw-root collection barrier: Idle/Mark/SweepPending/Sweep/Closed.
//!
//! [`RootBarrier`] is pure state behind the registry mutex: short critical
//! sections, no I/O. It tracks checked `cycle`/`root_epoch` counters, the
//! bounded gray set of Mark-time additions, the enumeration and frontier
//! completion flags, and the sealed condemned handle. The collector builds
//! candidates and performs durable commits outside the lock; every re-entry
//! revalidates `(phase, cycle)` so a stale candidate can never seal and a
//! stale lookup can never grant.
//!
//! Linearizability note: each transition is a single mutex critical section,
//! so the barrier state is linearizable across lane and reader threads. The
//! condemned membership check itself is snapshot-consistent per cycle, not
//! linearizable with concurrent marks: callers revalidate the cycle after
//! the lookup and treat rollover as `E_STALE`.

use std::sync::Arc;

use crate::OperationId;
use crate::budget::{ByteBudget, ByteReservation};
use crate::coord::leases::condemned::CondemnedSet;
use crate::coord::leases::timing::GRAY_ALLOWANCE_BYTES;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;

/// Barrier phase. `Closed` is terminal after an ambiguous sweep-record
/// failure: the coordinator refuses further collection work instead of
/// resetting to `Idle` and continuing on uncertain durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CollectionPhase {
    Idle,
    Mark,
    SweepPending,
    Sweep,
    Closed,
}

/// Outcome of the parent's durable sweep-record commit, reported back under
/// the sole writer lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SweepOutcome {
    /// The sweep record committed: enter `Sweep`.
    Committed,
    /// Definite prepublication failure: restore `Mark` with a fresh cycle so
    /// in-flight lookups revalidate instead of granting against stale state.
    DefiniteFailure,
    /// Ambiguous failure: close the coordinator terminally.
    Ambiguous,
}

/// Dedupe guidance for an existing object. The registry never re-encodes:
/// the only honest answers are retention of the original locator or rejection
/// of condemned reuse before any effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dedupe {
    /// Keep the original locator, delta base, and depth untouched.
    RetainOriginal,
}

/// Minimal sealed-cycle token. Fields are private and there is no public
/// constructor: only [`RootBarrier::seal_candidate`] mints one, after
/// verifying epoch equality, an empty gray set, finished enumeration, and no
/// in-flight frontier publication. Every later transition rechecks the token
/// against live state.
#[derive(Debug)]
pub(crate) struct SealedCycle {
    cycle: u64,
    root_epoch: u64,
    pivot: u64,
}

impl SealedCycle {
    /// The sealed collection cycle.
    #[must_use]
    pub(crate) fn cycle(&self) -> u64 {
        self.cycle
    }

    /// The root epoch the candidate was built against.
    #[must_use]
    pub(crate) fn root_epoch(&self) -> u64 {
        self.root_epoch
    }

    /// The pivot generation separating condemned from live roots.
    #[must_use]
    pub(crate) fn pivot(&self) -> u64 {
        self.pivot
    }
}

/// Pure barrier state machine.
pub(crate) struct RootBarrier {
    phase: CollectionPhase,
    cycle: u64,
    root_epoch: u64,
    pivot: u64,
    gray: Vec<Head>,
    gray_books: Option<Arc<ByteBudget>>,
    gray_charges: Vec<ByteReservation>,
    enumeration_done: bool,
    frontier_in_flight: bool,
    op_window: Option<(u64, u64)>,
    condemned: Option<Arc<CondemnedSet>>,
}

impl RootBarrier {
    /// Fresh barrier: `Idle`, cycle zero.
    pub(crate) fn new() -> Self {
        Self {
            phase: CollectionPhase::Idle,
            cycle: 0,
            root_epoch: 0,
            pivot: 0,
            gray: Vec::new(),
            gray_books: None,
            gray_charges: Vec::new(),
            enumeration_done: false,
            frontier_in_flight: false,
            op_window: None,
            condemned: None,
        }
    }

    /// Current phase.
    #[must_use]
    pub(crate) fn phase(&self) -> CollectionPhase {
        self.phase
    }

    /// Current collection cycle.
    #[must_use]
    pub(crate) fn cycle(&self) -> u64 {
        self.cycle
    }

    /// Current root epoch.
    #[must_use]
    pub(crate) fn root_epoch(&self) -> u64 {
        self.root_epoch
    }

    /// Condemned handle of the running cycle, if sealed.
    #[must_use]
    pub(crate) fn condemned(&self) -> Option<Arc<CondemnedSet>> {
        self.condemned.clone()
    }

    /// Operation window pinned by the running collection cycle.
    #[must_use]
    pub(crate) fn cycle_floor(&self) -> Option<OperationId> {
        self.op_window.map(|(low, _)| OperationId(low))
    }

    /// Rejects all work once closed.
    fn refuse_if_closed(&self) -> Result<(), CoreError> {
        if self.phase == CollectionPhase::Closed {
            return Err(CoreError::new(
                ErrorCode::EIo,
                "coordinator closed after ambiguous sweep-record failure",
            ));
        }
        Ok(())
    }

    /// Checked cycle advance; overflow fails `E_CAPACITY`, never wraps.
    fn next_cycle(&mut self) -> Result<(), CoreError> {
        self.cycle = self.cycle.checked_add(1).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "collection cycle counter exhausted")
        })?;
        Ok(())
    }

    /// Checked root-epoch advance.
    fn bump_root_epoch(&mut self) -> Result<(), CoreError> {
        self.root_epoch = self.root_epoch.checked_add(1).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "collection root epoch exhausted")
        })?;
        Ok(())
    }

    /// Begins `Mark` under sole lane ownership at the pivot generation,
    /// opening a fresh per-cycle gray budget of [`GRAY_ALLOWANCE_BYTES`].
    pub(crate) fn begin_mark(
        &mut self,
        pivot: u64,
        op_window: Option<(u64, u64)>,
    ) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Idle {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "collection cycle already in progress",
            ));
        }
        if let Some((low, high)) = op_window {
            if low > high {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "collection op window inverted",
                ));
            }
        }
        self.phase = CollectionPhase::Mark;
        self.pivot = pivot;
        self.op_window = op_window;
        self.gray.clear();
        self.gray_charges.clear();
        self.gray_books = Some(ByteBudget::new(GRAY_ALLOWANCE_BYTES));
        self.enumeration_done = false;
        self.frontier_in_flight = false;
        Ok(())
    }

    /// Records one Mark-time addition: a raw root inserted after the snapshot
    /// or a deletion of a not-yet-enumerated untracked root row. Bounded by
    /// the per-cycle gray budget; overflow aborts the cycle to `Idle` with a
    /// fresh cycle **before any removal**, reporting `E_LIMIT`.
    pub(crate) fn note_gray(&mut self, head: Head) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Mark {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "gray work outside Mark",
            ));
        }
        let Some(books) = self.gray_books.clone() else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "mark cycle lost its gray budget",
            ));
        };
        let bytes = u64::try_from(crate::coord::leases::condemned::RECORD_LEN)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "gray record size overflows u64"))?;
        let charge = match books.reserve(bytes) {
            Ok(charge) => charge,
            Err(_) => {
                self.abort_mark();
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    "gray budget full; mark cycle aborted before any removal",
                ));
            }
        };
        self.gray.push(head);
        self.gray_charges.push(charge);
        if let Err(err) = self.bump_root_epoch() {
            self.abort_mark();
            return Err(err);
        }
        Ok(())
    }

    /// Aborts the running Mark back to `Idle` with a fresh cycle. In-flight
    /// lookups revalidate and observe `E_STALE`, never a stale grant.
    fn abort_mark(&mut self) {
        let _ = self.next_cycle();
        self.phase = CollectionPhase::Idle;
        self.gray.clear();
        self.gray_charges.clear();
        self.gray_books = None;
        self.enumeration_done = false;
        self.frontier_in_flight = false;
        self.op_window = None;
    }

    /// Brackets large-frontier publication to scratch. Seal fails while a
    /// publication is in flight.
    pub(crate) fn begin_frontier_publish(&mut self) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Mark {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "frontier publish outside Mark",
            ));
        }
        if self.frontier_in_flight {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "frontier publish already in flight",
            ));
        }
        self.frontier_in_flight = true;
        Ok(())
    }

    /// Closes the frontier publication bracket.
    pub(crate) fn end_frontier_publish(&mut self) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if !self.frontier_in_flight {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "no frontier publish in flight",
            ));
        }
        self.frontier_in_flight = false;
        Ok(())
    }

    /// Marks root enumeration finished for `cycle`.
    pub(crate) fn finish_enumeration(&mut self, cycle: u64) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Mark || cycle != self.cycle {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "enumeration for a stale cycle",
            ));
        }
        self.enumeration_done = true;
        Ok(())
    }

    /// Acknowledges gray entries incorporated into the candidate through
    /// `through_epoch`, draining them. Seal still requires the gray set to be
    /// fully empty.
    pub(crate) fn drain_gray(&mut self, through_epoch: u64) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Mark {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "gray drain outside Mark",
            ));
        }
        let total = u64::try_from(self.gray.len())
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "gray set size overflows u64"))?;
        let base = self.root_epoch.saturating_sub(total);
        if through_epoch < base {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "gray drain epoch predates the gray set",
            ));
        }
        // Entries carry no per-entry epoch; the collector drains in order, so
        // the acknowledged prefix length is the epoch delta from the gray
        // base, derived without new bookkeeping.
        let acknowledged = through_epoch.saturating_sub(base);
        let acknowledged = usize::try_from(acknowledged).unwrap_or(usize::MAX);
        let drain = acknowledged.min(self.gray.len());
        self.gray.drain(..drain);
        self.gray_charges.truncate(self.gray.len());
        Ok(())
    }

    /// Seals the candidate, minting the token the parent must carry through
    /// the durable sweep-record commit. Verifies the candidate epoch equals
    /// the current epoch, the gray set is empty, enumeration finished, and no
    /// frontier publication is in flight.
    pub(crate) fn seal_candidate(
        &mut self,
        cycle: u64,
        candidate_epoch: u64,
        condemned: Arc<CondemnedSet>,
    ) -> Result<SealedCycle, CoreError> {
        self.refuse_if_closed()?;
        if self.phase != CollectionPhase::Mark {
            return Err(CoreError::new(ErrorCode::EInvalid, "seal outside Mark"));
        }
        if cycle != self.cycle {
            return Err(CoreError::new(ErrorCode::EStale, "seal for a stale cycle"));
        }
        if candidate_epoch != self.root_epoch {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "candidate epoch moved under the collector",
            ));
        }
        if !self.gray.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "gray work outstanding at seal",
            ));
        }
        if !self.enumeration_done {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "root enumeration unfinished at seal",
            ));
        }
        if self.frontier_in_flight {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "frontier publication in flight at seal",
            ));
        }
        if condemned.cycle() != self.cycle {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "condemned set bound to another cycle",
            ));
        }
        self.phase = CollectionPhase::SweepPending;
        self.condemned = Some(condemned);
        Ok(SealedCycle {
            cycle: self.cycle,
            root_epoch: self.root_epoch,
            pivot: self.pivot,
        })
    }

    /// Checks a sealed token against live state.
    fn check_token(&self, token: &SealedCycle) -> Result<(), CoreError> {
        self.refuse_if_closed()?;
        if token.cycle != self.cycle || token.root_epoch != self.root_epoch {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "sealed cycle moved under the lane",
            ));
        }
        Ok(())
    }

    /// Applies the parent's sweep-record commit outcome. Ambiguous failure
    /// closes the coordinator terminally; definite failure restores `Mark`
    /// with a fresh cycle.
    pub(crate) fn sweep_record_outcome(
        &mut self,
        token: &SealedCycle,
        outcome: SweepOutcome,
    ) -> Result<(), CoreError> {
        if self.phase != CollectionPhase::SweepPending {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "sweep outcome outside SweepPending",
            ));
        }
        self.check_token(token)?;
        match outcome {
            SweepOutcome::Committed => {
                self.phase = CollectionPhase::Sweep;
            }
            SweepOutcome::DefiniteFailure => {
                self.phase = CollectionPhase::Mark;
                self.condemned = None;
                self.enumeration_done = false;
                self.next_cycle()?;
            }
            SweepOutcome::Ambiguous => {
                self.phase = CollectionPhase::Closed;
                self.condemned = None;
                self.gray.clear();
                self.gray_charges.clear();
                self.gray_books = None;
            }
        }
        Ok(())
    }

    /// Completes `Sweep` after the lane's final durable cursor/retirement
    /// transaction, returning to `Idle` with a fresh cycle and dropping the
    /// condemned handle. The registry deletes nothing itself.
    pub(crate) fn complete_sweep(&mut self, token: &SealedCycle) -> Result<(), CoreError> {
        if self.phase != CollectionPhase::Sweep {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "sweep completion outside Sweep",
            ));
        }
        self.check_token(token)?;
        self.next_cycle()?;
        self.phase = CollectionPhase::Idle;
        self.condemned = None;
        self.gray.clear();
        self.gray_charges.clear();
        self.gray_books = None;
        self.enumeration_done = false;
        self.op_window = None;
        Ok(())
    }

    /// Dedupe guidance for an existing object. During `SweepPending`/`Sweep`
    /// the caller must consult the condemned handle outside the lock and pass
    /// the result back through [`RootBarrier::confirm_dedupe`]; this method
    /// only reports whether a lookup is required. Outside sweep phases the
    /// original locator is always retained.
    pub(crate) fn dedupe_needs_lookup(&self) -> Result<bool, CoreError> {
        self.refuse_if_closed()?;
        Ok(matches!(
            self.phase,
            CollectionPhase::SweepPending | CollectionPhase::Sweep
        ))
    }

    /// Confirms a condemned lookup performed outside the lock. `observed`
    /// carries the `(phase, cycle)` sampled before the I/O; mismatch is
    /// `E_STALE`, never a grant. Condemned members reject `E_LIMIT` before
    /// any effect; anything else retains its original locator.
    pub(crate) fn confirm_dedupe(
        &self,
        observed_cycle: u64,
        member: bool,
    ) -> Result<Dedupe, CoreError> {
        self.refuse_if_closed()?;
        if observed_cycle != self.cycle
            || !matches!(
                self.phase,
                CollectionPhase::SweepPending | CollectionPhase::Sweep
            )
        {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "dedupe lookup raced a cycle rollover",
            ));
        }
        if member {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "condemned object reuse rejected",
            ));
        }
        Ok(Dedupe::RetainOriginal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Oid;

    fn head(byte: u8) -> Head {
        Head::Git {
            oid: Oid::from_bytes(&[byte; 20]).expect("20-byte digest"),
        }
    }

    fn sealed_through_mark(barrier: &mut RootBarrier) -> SealedCycle {
        barrier.begin_mark(42, Some((3, 9))).expect("begin");
        let cycle = barrier.cycle();
        barrier.finish_enumeration(cycle).expect("finish");
        barrier
            .seal_candidate(
                cycle,
                barrier.root_epoch(),
                Arc::new(CondemnedSet::empty(cycle)),
            )
            .expect("seal")
    }

    #[test]
    fn gray_addition_blocks_seal_until_drained() {
        let mut barrier = RootBarrier::new();
        barrier.begin_mark(1, None).expect("begin");
        let cycle = barrier.cycle();
        barrier.note_gray(head(1)).expect("gray");
        barrier.finish_enumeration(cycle).expect("finish");
        let err = barrier
            .seal_candidate(
                cycle,
                barrier.root_epoch(),
                Arc::new(CondemnedSet::empty(cycle)),
            )
            .expect_err("gray outstanding");
        assert_eq!(err.code, ErrorCode::EStale);
        barrier.drain_gray(barrier.root_epoch()).expect("drain");
        barrier
            .seal_candidate(
                cycle,
                barrier.root_epoch(),
                Arc::new(CondemnedSet::empty(cycle)),
            )
            .expect("seal");
    }

    #[test]
    fn seal_rejects_stale_candidate_epoch() {
        let mut barrier = RootBarrier::new();
        barrier.begin_mark(1, None).expect("begin");
        let cycle = barrier.cycle();
        barrier.finish_enumeration(cycle).expect("finish");
        barrier.note_gray(head(2)).expect("late gray");
        // Candidate built before the late gray carries the old epoch.
        let err = barrier
            .seal_candidate(cycle, cycle, Arc::new(CondemnedSet::empty(cycle)))
            .expect_err("stale epoch");
        assert_eq!(err.code, ErrorCode::EStale);
    }

    #[test]
    fn definite_failure_restores_mark_ambiguous_closes() {
        let mut barrier = RootBarrier::new();
        let token = sealed_through_mark(&mut barrier);
        barrier
            .sweep_record_outcome(&token, SweepOutcome::DefiniteFailure)
            .expect("restore");
        assert_eq!(barrier.phase(), CollectionPhase::Mark);

        let mut barrier = RootBarrier::new();
        let token = sealed_through_mark(&mut barrier);
        barrier
            .sweep_record_outcome(&token, SweepOutcome::Ambiguous)
            .expect("close");
        assert_eq!(barrier.phase(), CollectionPhase::Closed);
        let err = barrier.begin_mark(2, None).expect_err("closed");
        assert_eq!(err.code, ErrorCode::EIo);
    }

    #[test]
    fn dedupe_rollover_never_grants() {
        let mut barrier = RootBarrier::new();
        let token = sealed_through_mark(&mut barrier);
        let observed = token.cycle();
        barrier
            .sweep_record_outcome(&token, SweepOutcome::Committed)
            .expect("sweep");
        barrier.complete_sweep(&token).expect("complete");
        // Lookup sampled the old cycle: confirmation must go stale.
        let err = barrier
            .confirm_dedupe(observed, false)
            .expect_err("rollover");
        assert_eq!(err.code, ErrorCode::EStale);
    }
}
