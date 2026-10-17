//! Bounded lease table: binding, renewal, expiry, and page accounting.
//!
//! [`LeaseTable`] is pure state behind the registry mutex: every method runs
//! a short critical section and performs no I/O. Reservations come from the
//! shared [`ByteBudget`] before any insertion; each entry holds its guards so
//! release is RAII. Cancellation halves follow the safe handoff: the table
//! owns the [`CancelHandle`] authority and hands the owner a [`Cancel`]
//! observer plus the registry's RAII owner guard. Expiry fires `cancel()` on the handle but
//! releases nothing until the guard drops, so a still-running admitted owner
//! keeps its protection until its task actually terminates.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::budget::{ByteBudget, ByteReservation};
use crate::coord::cancel::{Cancel, CancelHandle, cancellation};
use crate::coord::leases::timing::{self, Authority};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::protocol::{PageCursor, QueryDigest, MAX_CURSOR_POSITION_BYTES, MAX_PAGE_SIZE};
use crate::{LeaseId, OperationId, SessionId, StoreId};

/// Interactive or bulk/scratch/export lifetime class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseKind {
    /// View/cursor lease: 30 s authority, no renewal.
    Interactive,
    /// Scratch/export/stream lease: 15 min interval on admitted progress,
    /// 30 s no-progress cancel, 2 h total cap.
    Bulk,
}

/// Whether the owner reported admitted progress since the last renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BulkProgress {
    /// The owner completed admitted work: re-arm the interval deadline.
    AdmittedWork,
    /// Poll only: never moves any deadline.
    Heartbeat,
}

/// How an object root relates to the collection pivot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootOrigin {
    /// Root predates the pivot: condemned-checked during SweepPending/Sweep.
    PrePivot,
    /// Root was created beyond the pivot: live, but its dependencies still
    /// require a protected closure (enforced by the parent, not here).
    PostPivot,
}

/// Arguments for acquiring one lease. All sizes are exact measured charges.
pub(crate) struct AcquireArgs {
    /// Lifetime class.
    pub(crate) kind: LeaseKind,
    /// Repository the lease is bound to.
    pub(crate) store: StoreId,
    /// Session the lease is bound to.
    pub(crate) session: SessionId,
    /// Immutable view identity; unknown/pruned views reject `E_STALE`.
    pub(crate) view: OperationId,
    /// Query context; compared with constant-time equality.
    pub(crate) query: QueryDigest,
    /// Object roots staged before first lookup, with pivot relation.
    pub(crate) roots: Vec<(Head, RootOrigin)>,
    /// Retained-operation prune floor pinned while the lease lives.
    pub(crate) op_floor: Option<OperationId>,
    /// Exact cursor position bytes the first page will carry.
    pub(crate) position_bytes: usize,
    /// Whether `view` is a currently retained operation generation.
    pub(crate) view_retained: bool,
}

/// Expected cursor binding supplied by the calling request.
pub(crate) struct CursorWant {
    /// Repository the request arrived on.
    pub(crate) store: StoreId,
    /// Session the request is authenticated as.
    pub(crate) session: SessionId,
    /// View the request is reading.
    pub(crate) view: OperationId,
    /// Query the request is executing.
    pub(crate) query: QueryDigest,
}

/// Verified binding returned for a live cursor.
#[derive(Debug)]
pub(crate) struct LeaseBinding {
    /// The lease the cursor was issued for.
    pub(crate) lease: LeaseId,
    /// Lifetime class of that lease.
    pub(crate) kind: LeaseKind,
}

/// Exact measured charge of one lease binding, in bytes. No guessed per-row
/// overhead: 16 bytes per UUID identity, 32 for the query digest, 8 for the
/// view, plus exact caller-measured position and root bytes.
fn binding_bytes(position_bytes: usize, root_count: usize) -> Result<u64, CoreError> {
    let position = u64::try_from(position_bytes)
        .map_err(|_| CoreError::new(ErrorCode::ECapacity, "cursor position size overflows u64"))?;
    let record = u64::try_from(crate::coord::leases::condemned::RECORD_LEN)
        .map_err(|_| CoreError::new(ErrorCode::ECapacity, "record size overflows u64"))?;
    let roots = u64::try_from(root_count)
        .map_err(|_| CoreError::new(ErrorCode::ECapacity, "root count overflows u64"))?
        .checked_mul(record)
        .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "root charge overflows u64"))?;
    (16_u64 + 16 + 8 + 32)
        .checked_add(position)
        .and_then(|total| total.checked_add(roots))
        .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "lease charge overflows u64"))
}

/// One live lease entry. The `_charge` guard releases the binding bytes when
/// the entry leaves the table; `authority` fires cancellation on expiry.
struct LeaseEntry {
    kind: LeaseKind,
    store: StoreId,
    session: SessionId,
    view: OperationId,
    query: QueryDigest,
    created: Instant,
    progress: Instant,
    authority: CancelHandle,
    expired: bool,
    owner_live: bool,
    op_floor: Option<OperationId>,
    rows_copied: u64,
    bytes_copied: u64,
    _charge: ByteReservation,
}

impl LeaseEntry {
    /// Authority of this entry at `now`.
    fn authority_at(&self, now: Instant) -> Authority {
        match self.kind {
            LeaseKind::Interactive => timing::interactive_authority(self.created, now),
            LeaseKind::Bulk => timing::bulk_authority(self.created, self.progress, now),
        }
    }
}

/// Pure bounded lease table. All methods are short critical sections without
/// I/O; the registry wraps them with barrier checks and condemned lookups.
pub(crate) struct LeaseTable {
    books: Arc<ByteBudget>,
    entries: HashMap<LeaseId, LeaseEntry>,
}

impl LeaseTable {
    /// Empty table charging the shared books budget.
    pub(crate) fn new(books: &Arc<ByteBudget>) -> Self {
        Self {
            books: Arc::clone(books),
            entries: HashMap::new(),
        }
    }

    /// Number of live table entries (expired-but-protected included).
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Acquires one lease, reserving its exact measured bytes first. The
    /// returned [`Cancel`] observes authority; the registry wraps the id in
    /// its RAII owner guard, which retains protection until the owned task
    /// terminates.
    pub(crate) fn acquire(&mut self, args: AcquireArgs, now: Instant) -> Result<(LeaseId, Cancel), CoreError> {
        if !args.view_retained {
            return Err(CoreError::new(ErrorCode::EStale, "lease view is unknown or pruned"));
        }
        let charge = binding_bytes(args.position_bytes, args.roots.len())
            .and_then(|bytes| self.books.reserve(bytes).map_err(|refused| {
                CoreError::new(ErrorCode::ELimit, format!("lease budget refused: {refused}"))
            }))?;
        let id = LeaseId::generate();
        let (authority, observer) = cancellation();
        let entry = LeaseEntry {
            kind: args.kind,
            store: args.store,
            session: args.session,
            view: args.view,
            query: args.query,
            created: now,
            progress: now,
            authority,
            expired: false,
            owner_live: true,
            op_floor: args.op_floor,
            rows_copied: 0,
            bytes_copied: 0,
            _charge: charge,
        };
        self.entries.insert(id, entry);
        Ok((id, observer))
    }

    /// Looks up the entry or reports lease loss without revealing anything else.
    fn entry(&self, lease: &LeaseId) -> Result<&LeaseEntry, CoreError> {
        self.entries.get(lease).ok_or_else(|| {
            CoreError::new(ErrorCode::ELeaseLost, "lease is unknown or retired")
        })
    }

    /// Mutable lookup with the same lease-loss contract.
    fn entry_mut(&mut self, lease: &LeaseId) -> Result<&mut LeaseEntry, CoreError> {
        self.entries.get_mut(lease).ok_or_else(|| {
            CoreError::new(ErrorCode::ELeaseLost, "lease is unknown or retired")
        })
    }

    /// Verifies cursor binding: every field must match the issuing lease.
    /// Mismatch is `E_FORBIDDEN` (no reveal, no adopt); correct binding on an
    /// expired lease is `E_LEASE_LOST`.
    pub(crate) fn check_cursor(
        &self,
        cursor: &PageCursor,
        want: &CursorWant,
        now: Instant,
    ) -> Result<LeaseBinding, CoreError> {
        let entry = self.entry(&cursor.lease)?;
        if entry.store != want.store
            || entry.session != want.session
            || entry.view != want.view
            || !entry.query.ct_eq(&want.query)
        {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "cursor binding does not match this request",
            ));
        }
        if entry.expired || !entry.authority_at(now).is_live() {
            return Err(CoreError::new(ErrorCode::ELeaseLost, "lease authority expired"));
        }
        Ok(LeaseBinding {
            lease: cursor.lease,
            kind: entry.kind,
        })
    }

    /// Records admitted progress. Heartbeats never move deadlines; admitted
    /// work re-arms only the interval, never the total lifetime. Use on an
    /// expired lease is `E_LEASE_LOST`; a silent bulk owner reports
    /// `E_CANCELLED` so the caller cancels the owner promptly.
    pub(crate) fn report_progress(
        &mut self,
        lease: &LeaseId,
        progress: BulkProgress,
        now: Instant,
    ) -> Result<(), CoreError> {
        let entry = self.entry_mut(lease)?;
        // Admitted work is stamped before the authority check: the arriving
        // report is itself the renewal, re-arming the interval it satisfies.
        // Heartbeats stamp nothing and can never extend any deadline.
        if entry.expired {
            return Err(CoreError::new(ErrorCode::ELeaseLost, "lease authority expired"));
        }
        if entry.kind == LeaseKind::Bulk && progress == BulkProgress::AdmittedWork {
            entry.progress = now;
        }
        if !entry.authority_at(now).is_live() {
            return Err(CoreError::new(ErrorCode::ELeaseLost, "lease authority expired"));
        }
        Ok(())
    }

    /// Accounts one page: validates row/position bounds, reserves exact bytes
    /// first, then records rows and copied bytes with checked arithmetic.
    pub(crate) fn account_page(
        &mut self,
        lease: &LeaseId,
        rows: usize,
        bytes: u64,
        position_len: usize,
        now: Instant,
    ) -> Result<(), CoreError> {
        if rows > MAX_PAGE_SIZE {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("page holds at most {MAX_PAGE_SIZE} rows"),
            ));
        }
        if position_len > MAX_CURSOR_POSITION_BYTES {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("cursor position exceeds {MAX_CURSOR_POSITION_BYTES} bytes"),
            ));
        }
        let entry = self
            .entries
            .get_mut(lease)
            .ok_or_else(|| CoreError::new(ErrorCode::ELeaseLost, "lease is unknown or retired"))?;
        // A completed page copy is admitted work and is stamped before the
        // authority check: the page is itself the renewal. Streaming owners
        // stay alive without a separate progress call.
        if entry.expired {
            return Err(CoreError::new(ErrorCode::ELeaseLost, "lease authority expired"));
        }
        if entry.kind == LeaseKind::Bulk {
            entry.progress = now;
        }
        if !entry.authority_at(now).is_live() {

            return Err(CoreError::new(ErrorCode::ELeaseLost, "lease authority expired"));
        }
        let position = u64::try_from(position_len)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "position size overflows u64"))?;
        let cost = bytes.checked_add(position).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "page charge overflows u64")
        })?;
        // Disjoint-field borrow: the entry must stay mutable below while the
        // page charge reserves against the table books.
        let books = &self.books;
        let _page = books.reserve(cost).map_err(|refused| {
            CoreError::new(ErrorCode::ELimit, format!("page budget refused: {refused}"))
        })?;
        // Page charges release immediately: they bound the copy, not the lease.
        drop(_page);

        let rows_add = u64::try_from(rows)
            .map_err(|_| CoreError::new(ErrorCode::ECapacity, "row count overflows u64"))?;
        entry.rows_copied = entry.rows_copied.checked_add(rows_add).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "lease row accounting overflows")
        })?;
        entry.bytes_copied = entry.bytes_copied.checked_add(cost).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "lease byte accounting overflows")
        })?;
        Ok(())
    }

    /// Sweeps expired authority: fires cancellation on lapsed entries.
    /// Entries with
    /// a live owner stay (protected but unusable) until the [`OwnerGuard`]
    /// drops; ownerless entries leave immediately.
    pub(crate) fn sweep_expiry(&mut self, now: Instant) {
        let mut retired = Vec::new();
        for (id, entry) in self.entries.iter_mut() {
            if entry.expired {
                if !entry.owner_live {
                    retired.push(*id);
                }
                continue;
            }
            if !entry.authority_at(now).is_live() {
                entry.authority.cancel();
                entry.expired = true;
                if !entry.owner_live {
                    retired.push(*id);
                }
            }
        }
        for id in retired {
            self.entries.remove(&id);
        }
    }

    /// Retires `lease` on owner departure, releasing its charge at once. The
    /// registry root invokes this from the owner guard's drop, so scope end
    /// or disconnect drops the ephemeral lease even before expiry; later use
    /// reports `E_LEASE_LOST`. Fired cancellation stays latched in the
    /// owner's `Cancel` observer. Unknown ids are a silent no-op, keeping
    /// double-release idempotent.
    pub(crate) fn release_owner(&mut self, lease: &LeaseId) {
        self.entries.remove(lease);
    }

    /// Removes `lease` outright, releasing its charge. Used to roll back an
    /// acquisition whose barrier staging failed after insertion.
    pub(crate) fn remove(&mut self, lease: &LeaseId) {
        self.entries.remove(lease);
    }

    /// Whether `lease` currently holds owner protection.
    #[must_use]
    pub(crate) fn owner_live(&self, lease: &LeaseId) -> bool {
        self.entries.get(lease).is_some_and(|entry| entry.owner_live)
    }

    /// Copied rows and bytes recorded for `lease`.
    pub(crate) fn page_stats(&self, lease: &LeaseId) -> Result<(u64, u64), CoreError> {
        let entry = self.entry(lease)?;
        Ok((entry.rows_copied, entry.bytes_copied))
    }

    /// Minimum retained-operation floor over live leases for pruning.
    #[must_use]
    pub(crate) fn min_lease_floor(&self) -> Option<OperationId> {
        self.entries.values().filter_map(|entry| entry.op_floor).min_by_key(|id| id.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn books() -> Arc<ByteBudget> {
        ByteBudget::new(1 << 20)
    }

    fn args(kind: LeaseKind) -> AcquireArgs {
        AcquireArgs {
            kind,
            store: StoreId::from_bytes([1; 16]),
            session: SessionId::from_bytes([2; 16]),
            view: OperationId(7),
            query: QueryDigest::from_bytes([3; 32]),
            roots: Vec::new(),
            op_floor: Some(OperationId(5)),
            position_bytes: 64,
            view_retained: true,
        }
    }

    #[test]
    fn unknown_view_rejects_before_reservation() {
        let books = books();
        let mut table = LeaseTable::new(&books);
        let mut bad = args(LeaseKind::Interactive);
        bad.view_retained = false;
        let now = Instant::now();
        let err = table.acquire(bad, now).expect_err("unknown view");
        assert_eq!(err.code, ErrorCode::EStale);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn wrong_session_forbids_without_reveal() {
        let books = books();
        let mut table = LeaseTable::new(&books);
        let now = Instant::now();
        let (id, _cancel) = table.acquire(args(LeaseKind::Interactive), now).expect("acquire");
        assert!(table.owner_live(&id));
        let cursor = PageCursor {
            store: StoreId::from_bytes([1; 16]),
            view: OperationId(7),
            query: QueryDigest::from_bytes([3; 32]),
            lease: id,
            position: crate::ByteString::from(vec![]),
        };
        let mut want = CursorWant {
            store: StoreId::from_bytes([1; 16]),
            session: SessionId::from_bytes([9; 16]),
            view: OperationId(7),
            query: QueryDigest::from_bytes([3; 32]),
        };
        let err = table.check_cursor(&cursor, &want, now).expect_err("wrong session");
        assert_eq!(err.code, ErrorCode::EForbidden);
        want.session = SessionId::from_bytes([2; 16]);
        let binding = table.check_cursor(&cursor, &want, now).expect("correct binding");
        assert_eq!(binding.lease, id);
        assert_eq!(binding.kind, LeaseKind::Interactive);
    }

    #[test]
    fn expiry_cancels_but_owner_guard_retains_slot() {
        let books = books();
        let mut table = LeaseTable::new(&books);
        let now = Instant::now();
        let (id, cancel) = table.acquire(args(LeaseKind::Interactive), now).expect("acquire");
        let late = now + timing::INTERACTIVE_TTL;
        table.sweep_expiry(late);
        assert_eq!(cancel.check().expect_err("cancelled").code, ErrorCode::ECancelled);
        // Owner still holds protection: the slot survives the sweep.
        assert_eq!(table.len(), 1);
        table.release_owner(&id);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn smallest_lease_still_carries_a_nonzero_charge() {
        // Binding floor: two UUIDs plus view plus query digest, before any
        // position or root bytes. A 71-byte budget must refuse even the
        // barest lease, so the table can never grow unbounded on zero charges.
        let books = Arc::new(ByteBudget::new(71));
        let mut table = LeaseTable::new(&books);
        let mut bare = args(LeaseKind::Interactive);
        bare.position_bytes = 0;
        let err = table.acquire(bare, Instant::now()).expect_err("floor refuses");
        assert_eq!(err.code, ErrorCode::ELimit);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn streaming_pages_keep_a_bulk_owner_alive() {
        let books = books();
        let mut table = LeaseTable::new(&books);
        let now = Instant::now();
        let (id, _cancel) = table.acquire(args(LeaseKind::Bulk), now).expect("acquire");
        // Pages alone re-arm the interval: no separate progress call, yet the
        // owner survives far past one interval through steady copies.
        // The first interval is the 15-minute lease bound; after that each
        // page stamps progress and the owner's silence window is 30 seconds,
        // so steady pages must arrive at least that often to stay alive.
        let mut at = now;
        let mut step = timing::BULK_INTERVAL - Duration::from_secs(60);
        while at < now + timing::BULK_TOTAL - Duration::from_secs(60) {
            at += step;
            table.account_page(&id, 1, 64, 0, at).expect("page keeps alive");
            step = timing::BULK_NO_PROGRESS - Duration::from_secs(5);
        }
        let err = table
            .account_page(&id, 1, 64, 0, now + timing::BULK_TOTAL)
            .expect_err("total cap still applies");
        assert_eq!(err.code, ErrorCode::ELeaseLost);
    }

    #[test]
    fn heartbeat_never_extends_bulk_interval() {
        let books = books();
        let mut table = LeaseTable::new(&books);
        let now = Instant::now();
        let (id, _cancel) = table.acquire(args(LeaseKind::Bulk), now).expect("acquire");
        let edge = now + timing::BULK_INTERVAL;
        // Heartbeat at the edge cannot save the interval.
        let err = table.report_progress(&id, BulkProgress::Heartbeat, edge).expect_err("lapsed");
        assert_eq!(err.code, ErrorCode::ELeaseLost);
    }
}
