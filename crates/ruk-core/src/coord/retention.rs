//! Logical retention ledger accounting, bounded expiry sweeps, and conservative pruning time.
//!
//! # Invariants
//! - **Logical Retention Ledger ([`apply_facts`])**:
//!   Tracks row and byte conservation for [`FactTable::Receipts`], [`FactTable::Sessions`], and [`FactTable::Ops`].
//!   All other tables are classified as untracked through an exhaustive match and ignored.
//!   For tracked tables, [`FactExpectation::Any`] is invalid. Mutations are evaluated in a local copy
//!   and installed into [`Retained`] only after all facts succeed. Arithmetic is checked; underflow, overflow,
//!   or contradiction is committed corruption and always latches store quarantine.
//! - **Bounded Expiry Sweeps ([`sweep_page`])**:
//!   Scans a bounded page from [`SweepTable::Receipts`] or [`SweepTable::Sessions`] using [`Store::fact_page`]
//!   with exclusive cursor continuation. Page limits are clamped to at most [`SWEEP_PAGE_MAX_ROWS`] (1000)
//!   and [`SWEEP_PAGE_MAX_BYTES`] (`MAX_CONTROL_FRAME_BYTES + 32` bytes), permitting the single largest valid row.
//!   Rows are evaluated one at a time: Receipts expire at `retained_until <= now`; Sessions expire at
//!   `receipts_until <= now` (ReceiptsOnly) or `idle_expires_at + RECEIPT_HORIZON <= now` (Active).
//!   Expired rows produce exact [`FactExpectation::Value`] deletion mutations. Unexpired rows are never selected.
//!   The cursor advances to the last row seen when more rows remain, and reaches `None` strictly at table end.
//!   First-row oversize is a real error, never EOF. No direct [`Store::publish`] production calls.
//! - **Conservative Process-Local Pruning Clock ([`RetentionClock`])**:
//!   Evaluates `min(current_effective_wall, initial_wall + monotonic_elapsed)` checked, ensuring forward
//!   clock jumps during process execution cannot hasten in-process pruning. Across process restarts, only
//!   durable wall time is stored; monotonic time is strictly process-local.
//! - **Non-Preemptible Execution**:
//!   A bounded redb page scan in [`sweep_page`] is a non-preemptible library call requiring the caller's
//!   reserved maintenance execution slice; no measured 10ms execution time bound is claimed. Paced laps
//!   do not promise complete table drain within one pass under concurrent writes.

use std::time::{Duration, Instant};

use jiff::SignedDuration;

use crate::coord::clock::Times;
use crate::coord::rows::{RECEIPT_HORIZON, Retained, SweepCursors, decode_receipt, decode_session};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::SessionAuthority;
use crate::protocol::Timestamp;
use crate::store::types::{FactExpectation, FactMutation, FactTable};
use crate::store::{FactPageBudget, FactRow, Store, StoreError};

/// Maximum number of rows scanned in a single bounded expiry sweep page.
pub(crate) const SWEEP_PAGE_MAX_ROWS: usize = 1000;

/// The largest coordinator key width across sweepable tables (32 bytes for receipt keys).
pub(crate) const LARGEST_KEY_WIDTH: usize = 32;

/// Maximum byte budget for a single bounded expiry sweep page: `MAX_CONTROL_FRAME_BYTES + 32`.
/// This budget guarantees that one largest valid row can always be read and decoded.
pub(crate) const SWEEP_PAGE_MAX_BYTES: usize = crate::MAX_CONTROL_FRAME_BYTES + LARGEST_KEY_WIDTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrackedTable {
    Receipts,
    Sessions,
    Ops,
}

impl TrackedTable {
    /// Exhaustively matches [`FactTable`]. Returns `Some` for the three tables
    /// tracked by the logical retention ledger, and `None` for all untracked tables.
    #[must_use]
    const fn classify(table: FactTable) -> Option<Self> {
        match table {
            FactTable::Receipts => Some(Self::Receipts),
            FactTable::Sessions => Some(Self::Sessions),
            FactTable::Ops => Some(Self::Ops),
            FactTable::Refs
            | FactTable::RefConflicts
            | FactTable::RemoteObservations
            | FactTable::Changes
            | FactTable::ImportedChanges
            | FactTable::ChangeHistory
            | FactTable::Commits
            | FactTable::OpHead
            | FactTable::Workspaces
            | FactTable::Claims
            | FactTable::WsIndex
            | FactTable::WsStatus
            | FactTable::WsDirs
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
            | FactTable::LfsObjects => None,
        }
    }
}

/// Adjusts the logical retention ledger for a batch of fact mutations, observing
/// corruption through `store` unconditionally.
///
/// Only [`FactTable::Receipts`], [`FactTable::Sessions`], and [`FactTable::Ops`] are tracked.
/// All other tables are ignored.
///
/// For tracked tables:
/// - [`FactExpectation::Any`] is invalid.
/// - [`FactExpectation::Absent`] -> `Some(new)`: adds 1 row and `key.len() + new.len()` stored bytes.
/// - [`FactExpectation::Value(old)`] -> `Some(new)`: adjusts exact value bytes (`new.len() - old.len()`);
///   key bytes are unchanged. A guard with identical value changes nothing.
/// - [`FactExpectation::Value(old)`] -> `None`: removes 1 row and `key.len() + old.len()` stored bytes.
/// - [`FactExpectation::Absent`] -> `None`: changes nothing.
///
/// Arithmetic is checked; underflow of an existing ledger is committed corruption, not wraparound.
/// All modifications are computed into a local copy and installed into `*retained` only after
/// all facts succeed (ensuring ledger errors cannot partially update caller state).
///
/// Committed corruption (underflow, overflow, or mathematical contradiction) always latches store quarantine.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] on invalid expectation for tracked tables.
/// - [`ErrorCode::ECorrupt`] on ledger underflow, overflow, or mathematical contradiction.
pub(crate) fn apply_facts(
    store: &Store,
    retained: &mut Retained,
    facts: &[FactMutation],
) -> Result<(), CoreError> {
    let mut working = *retained;

    for fact in facts {
        let Some(tracked) = TrackedTable::classify(fact.table) else {
            // Untracked table: ignore.
            continue;
        };

        if fact.expected == FactExpectation::Any {
            let msg = format!(
                "tracked table {:?} mutation cannot use FactExpectation::Any in retention ledger adjustment",
                fact.table
            );
            return store
                .observe(Err(StoreError::Invalid(msg)))
                .map_err(CoreError::from);
        }

        let usage = match tracked {
            TrackedTable::Receipts => &mut working.receipts,
            TrackedTable::Sessions => &mut working.sessions,
            TrackedTable::Ops => &mut working.ops,
        };

        apply_mutation_to_usage(
            store,
            fact.table,
            usage,
            &fact.key,
            &fact.expected,
            fact.value.as_deref(),
        )?;

        // Ledger contradiction check: rows == 0 must imply stored_bytes == 0.
        if usage.rows == 0 && usage.stored_bytes != 0 {
            return Err(underflow_or_overflow_corrupt(
                store,
                fact.table,
                format!(
                    "ledger contradiction: row count reached 0 but stored bytes is {}",
                    usage.stored_bytes
                ),
            ));
        }
    }

    *retained = working;
    Ok(())
}

fn apply_mutation_to_usage(
    store: &Store,
    table: FactTable,
    usage: &mut crate::coord::rows::Usage,
    key: &[u8],
    expected: &FactExpectation,
    value: Option<&[u8]>,
) -> Result<(), CoreError> {
    let k_len = u64::try_from(key.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "key length exceeds u64 limit"))?;

    match (expected, value) {
        (FactExpectation::Absent, Some(new_val)) => {
            let v_len = u64::try_from(new_val.len())
                .map_err(|_| CoreError::new(ErrorCode::ELimit, "value length exceeds u64 limit"))?;
            usage.rows = usage
                .rows
                .checked_add(1)
                .ok_or_else(|| underflow_or_overflow_corrupt(store, table, "row count overflow"))?;
            let row_bytes = k_len.checked_add(v_len).ok_or_else(|| {
                underflow_or_overflow_corrupt(
                    store,
                    table,
                    "key length + value length overflow u64",
                )
            })?;
            usage.stored_bytes = usage.stored_bytes.checked_add(row_bytes).ok_or_else(|| {
                underflow_or_overflow_corrupt(store, table, "stored bytes overflow")
            })?;
        }
        (FactExpectation::Value(old_val), Some(new_val)) => {
            if old_val == new_val {
                return Ok(());
            }
            let old_len = u64::try_from(old_val.len()).map_err(|_| {
                CoreError::new(ErrorCode::ELimit, "old value length exceeds u64 limit")
            })?;
            let new_len = u64::try_from(new_val.len()).map_err(|_| {
                CoreError::new(ErrorCode::ELimit, "new value length exceeds u64 limit")
            })?;
            if new_len >= old_len {
                let diff = new_len - old_len;
                usage.stored_bytes = usage.stored_bytes.checked_add(diff).ok_or_else(|| {
                    underflow_or_overflow_corrupt(store, table, "stored bytes overflow on replace")
                })?;
            } else {
                let diff = old_len - new_len;
                usage.stored_bytes = usage.stored_bytes.checked_sub(diff).ok_or_else(|| {
                    underflow_or_overflow_corrupt(
                        store,
                        table,
                        format!(
                            "stored bytes underflow on replace: current {}, needed -{diff}",
                            usage.stored_bytes
                        ),
                    )
                })?;
            }
        }
        (FactExpectation::Value(old_val), None) => {
            let old_len = u64::try_from(old_val.len()).map_err(|_| {
                CoreError::new(ErrorCode::ELimit, "old value length exceeds u64 limit")
            })?;
            usage.rows = usage.rows.checked_sub(1).ok_or_else(|| {
                underflow_or_overflow_corrupt(
                    store,
                    table,
                    format!("row count underflow on delete: current rows {}", usage.rows),
                )
            })?;
            let old_bytes = k_len.checked_add(old_len).ok_or_else(|| {
                underflow_or_overflow_corrupt(
                    store,
                    table,
                    "key length + old value length overflow u64",
                )
            })?;
            usage.stored_bytes = usage.stored_bytes.checked_sub(old_bytes).ok_or_else(|| {
                underflow_or_overflow_corrupt(
                    store,
                    table,
                    format!(
                        "stored bytes underflow on delete: current {}, needed -{old_bytes}",
                        usage.stored_bytes
                    ),
                )
            })?;
        }
        (FactExpectation::Absent, None) => {}
        (FactExpectation::Any, _) => unreachable!("checked prior to mutation application"),
    }

    Ok(())
}

fn underflow_or_overflow_corrupt(
    store: &Store,
    table: FactTable,
    detail: impl Into<String>,
) -> CoreError {
    let msg = format!(
        "retention ledger corruption on {:?}: {}",
        table,
        detail.into()
    );
    let _ = store.observe::<()>(Err(StoreError::Corrupt(msg.clone())));
    CoreError::new(ErrorCode::ECorrupt, msg)
}

/// Sweepable coordinator metadata tables subject to bounded expiry sweeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SweepTable {
    /// Mutation idempotency receipts ([`FactTable::Receipts`]).
    Receipts,
    /// Coordinator sessions ([`FactTable::Sessions`]).
    Sessions,
}

/// The result of a single bounded expiry sweep page.
#[derive(Clone, Debug)]
pub(crate) struct SweepPage {
    /// Exact Value-expected deletion mutations for all expired rows in this page.
    pub(crate) deletions: Vec<FactMutation>,
    /// Updated sweep cursors for subsequent pages.
    pub(crate) cursors: SweepCursors,
    /// Number of rows examined in this page.
    pub(crate) examined_rows: usize,
    /// Total bytes (keys + values) examined across all rows in this page.
    pub(crate) examined_bytes: u64,
}

/// Scans a bounded page of rows from a sweepable coordinator table and generates
/// exact deletion mutations for any expired entries.
///
/// Uses [`Store::fact_page`] with exclusive continuation and bounded limits:
/// at most [`SWEEP_PAGE_MAX_ROWS`] (1000) rows and [`SWEEP_PAGE_MAX_BYTES`]
/// (`ROW_MAX_BYTES + 32`) bytes, permitting one largest valid row.
///
/// Rows are decoded one at a time:
/// - Receipts: expired when `receipt.retained_until <= now`.
/// - Sessions: `ReceiptsOnly` expired when `receipts_until <= now`;
///   `Active` deletion eligible only after `idle_expires_at + RECEIPT_HORIZON <= now`.
///
/// Arithmetic or format errors report committed corruption and latch store quarantine.
/// No unexpired receipt or session is selected for deletion.
///
/// A row's exact original bytes become the deletion expectation (`FactExpectation::Value`).
/// The cursor reaches `None` strictly at table end; first-row oversize is a real error, never EOF.
///
/// This function does not call [`Store::publish`] directly; the caller publishes deletions
/// atomically within its reserved maintenance lane.
///
/// # Errors
/// - [`ErrorCode::ECorrupt`] on malformed keys, invalid row bytes, or timestamp arithmetic overflow.
/// - [`ErrorCode::ELimit`] if the first row exceeds the byte budget.
pub(crate) fn sweep_page(
    store: &Store,
    table: SweepTable,
    cursors: SweepCursors,
    now: Timestamp,
) -> Result<SweepPage, CoreError> {
    let (fact_table, after, key_width) = match table {
        SweepTable::Receipts => (
            FactTable::Receipts,
            cursors.receipts.as_ref().map(|k| k.as_slice()),
            32_usize,
        ),
        SweepTable::Sessions => (
            FactTable::Sessions,
            cursors.sessions.as_ref().map(|k| k.as_slice()),
            16_usize,
        ),
    };

    let budget = FactPageBudget::new(SWEEP_PAGE_MAX_ROWS, SWEEP_PAGE_MAX_BYTES);
    let page = store
        .fact_page(fact_table, after, budget)
        .map_err(CoreError::from)?;

    let mut deletions = Vec::new();
    let mut examined_rows: usize = 0;
    let mut examined_bytes: u64 = 0;

    for row in &page.rows {
        examined_rows = examined_rows.saturating_add(1);
        let row_len = match (u64::try_from(row.key.len()), u64::try_from(row.value.len())) {
            (Ok(k), Ok(v)) => k.saturating_add(v),
            _ => u64::MAX,
        };
        examined_bytes = examined_bytes.saturating_add(row_len);

        if row.key.len() != key_width {
            return store
                .observe(Err(StoreError::Corrupt(format!(
                    "invalid key width for {:?}: expected {key_width} bytes, found {}",
                    fact_table,
                    row.key.len()
                ))))
                .map_err(CoreError::from);
        }

        let is_expired = match table {
            SweepTable::Receipts => is_receipt_expired(store, &row.key, &row.value, now)?,
            SweepTable::Sessions => is_session_expired(store, &row.key, &row.value, now)?,
        };

        if is_expired {
            deletions.push(FactMutation {
                table: fact_table,
                key: row.key.clone(),
                expected: FactExpectation::Value(row.value.clone()),
                value: None,
            });
        }
    }

    let mut next_cursors = cursors;
    if page.more {
        next_cursors = advance_cursor_to_last_row(store, table, next_cursors, page.rows.last())?;
    } else {
        match table {
            SweepTable::Receipts => next_cursors.receipts = None,
            SweepTable::Sessions => next_cursors.sessions = None,
        }
    }

    Ok(SweepPage {
        deletions,
        cursors: next_cursors,
        examined_rows,
        examined_bytes,
    })
}

fn advance_cursor_to_last_row(
    store: &Store,
    table: SweepTable,
    mut cursors: SweepCursors,
    last_row: Option<&FactRow>,
) -> Result<SweepCursors, CoreError> {
    let Some(last) = last_row else {
        return store
            .observe(Err(StoreError::Corrupt(
                "fact page returned more=true with empty row set".to_owned(),
            )))
            .map_err(CoreError::from);
    };

    match table {
        SweepTable::Receipts => {
            if last.key.len() != 32 {
                return store
                    .observe(Err(StoreError::Corrupt(format!(
                        "cursor receipt key length is {} bytes, expected 32",
                        last.key.len()
                    ))))
                    .map_err(CoreError::from);
            }
            let mut k = [0_u8; 32];
            key_slice_to_32(&mut k, &last.key);
            cursors.receipts = Some(k);
        }
        SweepTable::Sessions => {
            if last.key.len() != 16 {
                return store
                    .observe(Err(StoreError::Corrupt(format!(
                        "cursor session key length is {} bytes, expected 16",
                        last.key.len()
                    ))))
                    .map_err(CoreError::from);
            }
            let mut k = [0_u8; 16];
            key_slice_to_16(&mut k, &last.key);
            cursors.sessions = Some(k);
        }
    }

    Ok(cursors)
}

fn key_slice_to_32(dst: &mut [u8; 32], src: &[u8]) {
    dst.copy_from_slice(src);
}

fn key_slice_to_16(dst: &mut [u8; 16], src: &[u8]) {
    dst.copy_from_slice(src);
}

fn is_receipt_expired(
    store: &Store,
    key: &[u8],
    value: &[u8],
    now: Timestamp,
) -> Result<bool, CoreError> {
    let mut key_arr = [0_u8; 32];
    key_arr.copy_from_slice(key);
    let receipt_row = decode_receipt(store, &key_arr, value)?;
    Ok(receipt_row.receipt().retained_until <= now)
}

fn is_session_expired(
    store: &Store,
    key: &[u8],
    value: &[u8],
    now: Timestamp,
) -> Result<bool, CoreError> {
    let mut key_arr = [0_u8; 16];
    key_arr.copy_from_slice(key);
    let session_row = decode_session(store, &key_arr, value)?;
    match session_row.authority {
        SessionAuthority::ReceiptsOnly { receipts_until } => Ok(receipts_until <= now),
        SessionAuthority::Active { idle_expires_at } => {
            let eligible_instant = idle_expires_at
                .instant()
                .checked_add(RECEIPT_HORIZON)
                .map_err(|err| {
                    let _ = store.observe::<()>(Err(StoreError::Corrupt(format!(
                        "session active expiry + RECEIPT_HORIZON arithmetic overflow: {err}"
                    ))));
                    CoreError::new(
                        ErrorCode::ECorrupt,
                        format!(
                            "session active expiry + RECEIPT_HORIZON arithmetic overflow: {err}"
                        ),
                    )
                })?;
            Ok(Timestamp::new(eligible_instant) <= now)
        }
    }
}

/// Conservative process-local pruning clock.
///
/// Within a single coordinator process lifetime, this clock guards against
/// forward wall-clock jumps (e.g. NTP step adjustments, VM resumption, or manual
/// clock steps) that would otherwise cause unexpired promises (mutation receipts
/// and session retention horizons) to be pruned prematurely.
///
/// Exposes [`RetentionClock::now`] which computes:
/// `min(current_effective_wall, initial_wall + monotonic_elapsed)` checked.
///
/// # Process Boundary and Restart
/// Monotonic instants (`std::time::Instant`) cannot be persisted across process
/// restarts. Across coordinator restarts, only durable wall time is available in
/// stored records; this is a fundamental OS limit and this type does not pretend
/// a monotonic clock persists across crashes or restarts. On process restart,
/// the coordinator initializes a new [`RetentionClock`] from its initial [`Times`] sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetentionClock {
    initial_wall: jiff::Timestamp,
    initial_mono: Instant,
}

impl RetentionClock {
    /// Initializes a conservative pruning clock from a single coordinator [`Times`] sample.
    #[must_use]
    pub(crate) const fn new(init: Times) -> Self {
        Self {
            initial_wall: init.wall,
            initial_mono: init.mono,
        }
    }

    /// Evaluates conservative pruning time at the given `current` sample.
    ///
    /// Computes `min(current.wall, initial_wall + monotonic_elapsed)` checked.
    ///
    /// # Errors
    /// [`ErrorCode::EIo`] if monotonic duration conversion or timestamp addition overflows.
    pub(crate) fn now(&self, current: &Times) -> Result<Timestamp, CoreError> {
        let elapsed_duration = match current.mono.checked_duration_since(self.initial_mono) {
            Some(d) => d,
            None => Duration::ZERO,
        };

        let signed_elapsed = SignedDuration::try_from(elapsed_duration).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("elapsed monotonic duration overflow in retention clock: {err}"),
            )
        })?;

        let monotonic_bound = self
            .initial_wall
            .checked_add(signed_elapsed)
            .map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("retention clock monotonic bound overflow: {err}"),
                )
            })?;

        let safe_wall = std::cmp::min(current.wall, monotonic_bound);
        Ok(Timestamp::new(safe_wall))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::capability::Capabilities;
    use crate::change::{ChangeId, OperationId, RequestId, SessionId};
    use crate::commit::ProvenanceClaims;
    use crate::coord::policy::Principal;
    use crate::coord::rows::{ReceiptRow, SessionRow, Usage, encode, receipt_key, session_key};
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::protocol::{
        BoundedList, MutationOutcome, ReceiptRef, Reply, RequestDigest, WsTakeReply,
    };
    use crate::store::PreparationBudget;
    use crate::workspace::{NativeWorkspace, Scope, WorkspaceState};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-coord-retention-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create test directory");
            Self(dir)
        }

        fn store_dir(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_store(tag: &str) -> (TempRoot, Store) {
        let temp = TempRoot::new(tag);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store =
            Store::create(&temp.store_dir(), HashKind::Sha1, budget).expect("create test store");
        (temp, store)
    }

    fn sample_workspace_state() -> WorkspaceState {
        WorkspaceState::Native(NativeWorkspace::new(
            ChangeId::from_bytes([7; 16]),
            Head::Git {
                oid: Oid::from_hex("0123456789abcdef0123456789abcdef01234567").expect("valid oid"),
            },
            Scope::Full,
        ))
    }

    fn sample_mutation_reply(
        session: SessionId,
        request_id: RequestId,
        retained_until: Timestamp,
    ) -> Reply {
        let outcome = MutationOutcome {
            receipt: ReceiptRef {
                session,
                request_id,
                digest: RequestDigest::from_bytes([0x42; 32]),
                replayed: false,
                retained_until,
            },
            operation: Some(OperationId(1)),
            heads: BoundedList::complete(Vec::new()).expect("empty"),
            stamps: BoundedList::complete(Vec::new()).expect("empty"),
            warnings: BoundedList::complete(Vec::new()).expect("empty"),
            merge: None,
            provenance: BoundedList::complete(Vec::new()).expect("empty"),
            identity: None,
        };
        Reply::WsTake(Box::new(WsTakeReply {
            outcome,
            state: sample_workspace_state(),
        }))
    }

    fn sample_session_row(authority: SessionAuthority) -> SessionRow {
        SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity: None,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0x55; 32],
            authority,
        }
    }

    #[test]
    fn ledger_exact_conservation_insert_replace_delete() {
        let (_temp, store) = test_store("ledger-exact");
        let mut retained = Retained::default();

        let key_r = receipt_key(
            SessionId::from_bytes([1; 16]),
            RequestId::from_bytes([2; 16]),
        );
        let val1 = vec![1, 2, 3, 4, 5]; // 5 bytes
        let val2 = vec![1, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes (grow by 3)
        let val3 = vec![9, 10]; // 2 bytes (shrink by 6)

        // 1. Insert receipt: Absent -> Some(val1)
        let f1 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Absent,
            value: Some(val1.clone()),
        };
        apply_facts(&store, &mut retained, &[f1]).expect("insert receipt");
        assert_eq!(retained.receipts.rows, 1);
        assert_eq!(retained.receipts.stored_bytes, 32 + 5);

        // 2. Replace receipt: Value(val1) -> Some(val2) (grow)
        let f2 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Value(val1.clone()),
            value: Some(val2.clone()),
        };
        apply_facts(&store, &mut retained, &[f2]).expect("replace grow");
        assert_eq!(retained.receipts.rows, 1);
        assert_eq!(retained.receipts.stored_bytes, 32 + 8);

        // 3. Replace receipt with unchanged value (guard): Value(val2) -> Some(val2)
        let f3 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Value(val2.clone()),
            value: Some(val2.clone()),
        };
        apply_facts(&store, &mut retained, &[f3]).expect("replace unchanged guard");
        assert_eq!(retained.receipts.rows, 1);
        assert_eq!(retained.receipts.stored_bytes, 32 + 8);

        // 4. Replace receipt: Value(val2) -> Some(val3) (shrink)
        let f4 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Value(val2),
            value: Some(val3.clone()),
        };
        apply_facts(&store, &mut retained, &[f4]).expect("replace shrink");
        assert_eq!(retained.receipts.rows, 1);
        assert_eq!(retained.receipts.stored_bytes, 32 + 2);

        // 5. Delete receipt: Value(val3) -> None
        let f5 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Value(val3),
            value: None,
        };
        apply_facts(&store, &mut retained, &[f5]).expect("delete receipt");
        assert_eq!(retained.receipts.rows, 0);
        assert_eq!(retained.receipts.stored_bytes, 0);

        // 6. Absent -> None changes nothing
        let f6 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Absent,
            value: None,
        };
        apply_facts(&store, &mut retained, &[f6]).expect("absent-none no-op");
        assert_eq!(retained.receipts.rows, 0);
        assert_eq!(retained.receipts.stored_bytes, 0);

        // 7. Untracked tables change nothing
        let f_untracked = FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/main".to_vec(),
            expected: FactExpectation::Absent,
            value: Some(b"some_oid".to_vec()),
        };
        apply_facts(&store, &mut retained, &[f_untracked]).expect("untracked fact ignored");
        assert_eq!(retained, Retained::default());
    }

    #[test]
    fn ledger_no_partial_update_on_failure() {
        let (_temp, store) = test_store("ledger-no-partial");
        let initial = Retained {
            receipts: Usage {
                rows: 10,
                stored_bytes: 500,
            },
            sessions: Usage {
                rows: 2,
                stored_bytes: 80,
            },
            ops: Usage {
                rows: 5,
                stored_bytes: 200,
            },
        };
        let mut retained = initial;

        // Batch with 1 valid mutation followed by FactExpectation::Any on tracked table
        let key_r = receipt_key(
            SessionId::from_bytes([9; 16]),
            RequestId::from_bytes([9; 16]),
        );
        let valid_fact = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Absent,
            value: Some(vec![1, 2, 3]),
        };
        let invalid_any = FactMutation {
            table: FactTable::Sessions,
            key: session_key(SessionId::from_bytes([1; 16])).to_vec(),
            expected: FactExpectation::Any,
            value: Some(vec![1, 2, 3]),
        };

        let err = apply_facts(&store, &mut retained, &[valid_fact, invalid_any])
            .expect_err("any must fail");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert_eq!(
            retained, initial,
            "retained ledger must be unchanged after failure"
        );

        // Batch with 1 valid mutation followed by underflow delete
        let underflow_delete = FactMutation {
            table: FactTable::Ops,
            key: vec![0; 12],
            expected: FactExpectation::Value(vec![0; 1000]), // 1000 bytes > 200 bytes
            value: None,
        };
        let valid_fact2 = FactMutation {
            table: FactTable::Receipts,
            key: key_r.to_vec(),
            expected: FactExpectation::Absent,
            value: Some(vec![1, 2, 3]),
        };

        let err2 = apply_facts(&store, &mut retained, &[valid_fact2, underflow_delete])
            .expect_err("underflow must fail");
        assert_eq!(err2.code, ErrorCode::ECorrupt);
        assert_eq!(
            retained, initial,
            "retained ledger must be unchanged after underflow failure"
        );
    }

    #[test]
    fn ledger_underflow_latches_store_quarantine() {
        let (_temp, store) = test_store("underflow-quarantine");
        assert!(!store.quarantine());

        let mut retained = Retained::default();

        let underflow_delete = FactMutation {
            table: FactTable::Receipts,
            key: vec![0; 32],
            expected: FactExpectation::Value(vec![1, 2, 3]),
            value: None,
        };

        let err = apply_facts(&store, &mut retained, &[underflow_delete])
            .expect_err("underflow must error");
        assert_eq!(err.code, ErrorCode::ECorrupt);

        // Store must now be quarantined
        assert!(
            store.quarantine(),
            "store must be quarantined after committed underflow"
        );
        assert_eq!(
            store
                .fact(FactTable::OpHead, b"")
                .expect_err("quarantined")
                .code(),
            ErrorCode::ECorrupt
        );
    }

    #[test]
    fn ledger_contradiction_zero_rows_non_zero_bytes_corrupt() {
        let (_temp, store) = test_store("ledger-contradiction");
        let mut retained = Retained {
            receipts: Usage {
                rows: 1,
                stored_bytes: 100,
            },
            sessions: Usage::default(),
            ops: Usage::default(),
        };

        // Deleting 1 row with 40 bytes leaves 0 rows but 60 stored bytes
        let delete_mutation = FactMutation {
            table: FactTable::Receipts,
            key: vec![0; 32],
            expected: FactExpectation::Value(vec![0; 8]), // 32 + 8 = 40 bytes
            value: None,
        };

        let err = apply_facts(&store, &mut retained, &[delete_mutation])
            .expect_err("zero rows with non-zero bytes must be corrupt");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert!(store.quarantine());
    }

    #[test]
    fn sweep_page_expired_vs_live_receipts_mixed() {
        let (_temp, store) = test_store("sweep-receipts-mixed");
        let now_instant = jiff::Timestamp::now();
        let now = Timestamp::new(now_instant);

        let s = SessionId::from_bytes([1; 16]);
        let r_expired1 = RequestId::from_bytes([10; 16]);
        let r_live = RequestId::from_bytes([11; 16]);
        let r_expired2 = RequestId::from_bytes([12; 16]);

        let past_time = Timestamp::new(
            now_instant
                .checked_sub(jiff::SignedDuration::from_hours(2))
                .expect("sub"),
        );
        let future_time = Timestamp::new(
            now_instant
                .checked_add(jiff::SignedDuration::from_hours(2))
                .expect("add"),
        );

        let reply_exp1 = sample_mutation_reply(s, r_expired1, past_time);
        let row_exp1 = ReceiptRow::new(s, r_expired1, reply_exp1).expect("row");
        let enc_exp1 = encode("receipt", &row_exp1).expect("enc");
        let key_exp1 = receipt_key(s, r_expired1);

        let reply_live = sample_mutation_reply(s, r_live, future_time);
        let row_live = ReceiptRow::new(s, r_live, reply_live).expect("row");
        let enc_live = encode("receipt", &row_live).expect("enc");
        let key_live = receipt_key(s, r_live);

        let reply_exp2 = sample_mutation_reply(s, r_expired2, past_time);
        let row_exp2 = ReceiptRow::new(s, r_expired2, reply_exp2).expect("row");
        let enc_exp2 = encode("receipt", &row_exp2).expect("enc");
        let key_exp2 = receipt_key(s, r_expired2);

        // Populate store with 3 receipts
        store
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::Receipts,
                        key: key_exp1.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc_exp1.clone()),
                    },
                    FactMutation {
                        table: FactTable::Receipts,
                        key: key_live.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc_live.clone()),
                    },
                    FactMutation {
                        table: FactTable::Receipts,
                        key: key_exp2.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc_exp2.clone()),
                    },
                ],
            )
            .expect("publish test receipts");

        let sweep = sweep_page(&store, SweepTable::Receipts, SweepCursors::default(), now)
            .expect("sweep receipts");

        assert_eq!(sweep.examined_rows, 3);
        let total_bytes = (32 + enc_exp1.len() as u64)
            + (32 + enc_live.len() as u64)
            + (32 + enc_exp2.len() as u64);
        assert_eq!(sweep.examined_bytes, total_bytes);

        // Only the 2 expired receipts must be selected for deletion
        assert_eq!(sweep.deletions.len(), 2);
        assert_eq!(sweep.deletions[0].key, key_exp1);
        assert_eq!(
            sweep.deletions[0].expected,
            FactExpectation::Value(enc_exp1)
        );
        assert_eq!(sweep.deletions[0].value, None);

        assert_eq!(sweep.deletions[1].key, key_exp2);
        assert_eq!(
            sweep.deletions[1].expected,
            FactExpectation::Value(enc_exp2)
        );
        assert_eq!(sweep.deletions[1].value, None);

        // Table end reached
        assert_eq!(sweep.cursors.receipts, None);
    }

    #[test]
    fn sweep_page_sessions_active_vs_receipts_only_horizons() {
        let (_temp, store) = test_store("sweep-sessions");
        let now_instant = jiff::Timestamp::now();
        let now = Timestamp::new(now_instant);

        let s1 = SessionId::from_bytes([1; 16]); // ReceiptsOnly, expired
        let s2 = SessionId::from_bytes([2; 16]); // ReceiptsOnly, live
        let s3 = SessionId::from_bytes([3; 16]); // Active, expired (>7d past idle)
        let s4 = SessionId::from_bytes([4; 16]); // Active, live (<7d past idle)

        let past_1h = Timestamp::new(
            now_instant
                .checked_sub(jiff::SignedDuration::from_hours(1))
                .expect("sub"),
        );
        let future_1h = Timestamp::new(
            now_instant
                .checked_add(jiff::SignedDuration::from_hours(1))
                .expect("add"),
        );
        let past_8d = Timestamp::new(
            now_instant
                .checked_sub(jiff::SignedDuration::from_hours(192))
                .expect("sub"),
        );
        let past_2d = Timestamp::new(
            now_instant
                .checked_sub(jiff::SignedDuration::from_hours(48))
                .expect("sub"),
        );

        let row_s1 = sample_session_row(SessionAuthority::ReceiptsOnly {
            receipts_until: past_1h,
        });
        let row_s2 = sample_session_row(SessionAuthority::ReceiptsOnly {
            receipts_until: future_1h,
        });
        let row_s3 = sample_session_row(SessionAuthority::Active {
            idle_expires_at: past_8d,
        });
        let row_s4 = sample_session_row(SessionAuthority::Active {
            idle_expires_at: past_2d,
        });

        let enc1 = encode("session", &row_s1).expect("enc");
        let enc2 = encode("session", &row_s2).expect("enc");
        let enc3 = encode("session", &row_s3).expect("enc");
        let enc4 = encode("session", &row_s4).expect("enc");

        store
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::Sessions,
                        key: session_key(s1).to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc1.clone()),
                    },
                    FactMutation {
                        table: FactTable::Sessions,
                        key: session_key(s2).to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc2.clone()),
                    },
                    FactMutation {
                        table: FactTable::Sessions,
                        key: session_key(s3).to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc3.clone()),
                    },
                    FactMutation {
                        table: FactTable::Sessions,
                        key: session_key(s4).to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc4.clone()),
                    },
                ],
            )
            .expect("publish sessions");

        let sweep = sweep_page(&store, SweepTable::Sessions, SweepCursors::default(), now)
            .expect("sweep sessions");

        assert_eq!(sweep.examined_rows, 4);
        // Only s1 (ReceiptsOnly past) and s3 (Active 8d past idle > 7d horizon) are expired
        assert_eq!(sweep.deletions.len(), 2);
        assert_eq!(sweep.deletions[0].key, session_key(s1));
        assert_eq!(sweep.deletions[0].expected, FactExpectation::Value(enc1));
        assert_eq!(sweep.deletions[0].value, None);

        assert_eq!(sweep.deletions[1].key, session_key(s3));
        assert_eq!(sweep.deletions[1].expected, FactExpectation::Value(enc3));
        assert_eq!(sweep.deletions[1].value, None);

        assert_eq!(sweep.cursors.sessions, None);
    }

    #[test]
    fn sweep_page_exclusive_cursor_continuation_and_table_end() {
        let (_temp, store) = test_store("sweep-continuation");
        let now_instant = jiff::Timestamp::now();
        let now = Timestamp::new(now_instant);

        let s = SessionId::from_bytes([1; 16]);
        let r1 = RequestId::from_bytes([1; 16]);
        let r2 = RequestId::from_bytes([2; 16]);

        let past_time = Timestamp::new(
            now_instant
                .checked_sub(jiff::SignedDuration::from_hours(1))
                .expect("sub"),
        );

        let reply1 = sample_mutation_reply(s, r1, past_time);
        let row1 = ReceiptRow::new(s, r1, reply1).expect("row");
        let enc1 = encode("receipt", &row1).expect("enc");
        let key1 = receipt_key(s, r1);

        let reply2 = sample_mutation_reply(s, r2, past_time);
        let row2 = ReceiptRow::new(s, r2, reply2).expect("row");
        let enc2 = encode("receipt", &row2).expect("enc");
        let key2 = receipt_key(s, r2);

        store
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::Receipts,
                        key: key1.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc1.clone()),
                    },
                    FactMutation {
                        table: FactTable::Receipts,
                        key: key2.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(enc2.clone()),
                    },
                ],
            )
            .expect("publish 2 receipts");

        // Sweep continuation with cursor pointing to key1:
        // Exclusive range means key1 must be skipped and only key2 examined!
        let initial_cursor = SweepCursors {
            receipts: Some(key1),
            sessions: None,
        };

        let sweep = sweep_page(&store, SweepTable::Receipts, initial_cursor, now)
            .expect("sweep continuation");

        assert_eq!(sweep.examined_rows, 1, "must examine strictly after key1");
        assert_eq!(sweep.deletions.len(), 1);
        assert_eq!(sweep.deletions[0].key, key2);
        // Table end reached on key2
        assert_eq!(sweep.cursors.receipts, None);
    }

    #[test]
    fn sweep_page_empty_table_returns_none_cursor_and_zero_examined() {
        let (_temp, store) = test_store("sweep-empty");
        let now = Timestamp::new(jiff::Timestamp::now());

        let sweep = sweep_page(&store, SweepTable::Receipts, SweepCursors::default(), now)
            .expect("sweep empty");
        assert!(sweep.deletions.is_empty());
        assert_eq!(sweep.cursors.receipts, None);
        assert_eq!(sweep.examined_rows, 0);
        assert_eq!(sweep.examined_bytes, 0);
    }

    #[test]
    fn sweep_page_corrupt_receipt_bytes_quarantines_store() {
        let (_temp, store) = test_store("corrupt-receipt");
        let s = SessionId::from_bytes([1; 16]);
        let r = RequestId::from_bytes([1; 16]);
        let key = receipt_key(s, r);

        // Put invalid postcard bytes into Receipts
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(vec![0xff, 0xfe, 0xfd]),
                }],
            )
            .expect("publish");

        let now = Timestamp::new(jiff::Timestamp::now());
        let err = sweep_page(&store, SweepTable::Receipts, SweepCursors::default(), now)
            .expect_err("corrupt receipt must fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert!(store.quarantine(), "store must be quarantined");
    }

    #[test]
    fn sweep_page_invalid_receipt_key_width_quarantines_store() {
        let (_temp, store) = test_store("invalid-receipt-key-width");

        // Put a row with a 16-byte key into Receipts (must be 32 bytes)
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: vec![0x11; 16],
                    expected: FactExpectation::Absent,
                    value: Some(vec![1, 2, 3]),
                }],
            )
            .expect("publish");

        let now = Timestamp::new(jiff::Timestamp::now());
        let err = sweep_page(&store, SweepTable::Receipts, SweepCursors::default(), now)
            .expect_err("invalid key width must fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert!(
            store.quarantine(),
            "store must be quarantined on invalid key width"
        );
    }

    #[test]
    fn sweep_page_invalid_session_key_width_quarantines_store() {
        let (_temp, store) = test_store("invalid-session-key-width");

        // Put a row with a 32-byte key into Sessions (must be 16 bytes)
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Sessions,
                    key: vec![0x22; 32],
                    expected: FactExpectation::Absent,
                    value: Some(vec![1, 2, 3]),
                }],
            )
            .expect("publish");

        let now = Timestamp::new(jiff::Timestamp::now());
        let err = sweep_page(&store, SweepTable::Sessions, SweepCursors::default(), now)
            .expect_err("invalid session key width must fail");
        assert_eq!(err.code, ErrorCode::ECorrupt);
        assert!(
            store.quarantine(),
            "store must be quarantined on invalid key width"
        );
    }

    #[test]
    fn retention_clock_forward_clock_jump_safety() {
        let base_wall = jiff::Timestamp::from_second(1_700_000_000).expect("valid base wall");
        let base_mono = Instant::now();
        let init_times = Times::new(base_wall, base_mono);

        let clock = RetentionClock::new(init_times);

        // Simulate massive forward wall jump (+30 days) while monotonic advances by only 50ms
        let jumped_wall = base_wall
            .checked_add(jiff::SignedDuration::from_hours(720))
            .expect("30 days jump");
        let elapsed_mono = Duration::from_millis(50);
        let sample_times = Times::new(jumped_wall, base_mono + elapsed_mono);

        let safe_now = clock.now(&sample_times).expect("now");
        let expected_safe_wall = base_wall
            .checked_add(SignedDuration::try_from(elapsed_mono).expect("signed"))
            .expect("add");

        assert_eq!(safe_now.instant(), expected_safe_wall);
        assert!(
            safe_now.instant() < jumped_wall,
            "pruning time must not follow forward OS wall jump"
        );
    }

    #[test]
    fn retention_clock_normal_advance_and_backward_jump() {
        let base_wall = jiff::Timestamp::from_second(1_700_000_000).expect("valid base wall");
        let base_mono = Instant::now();
        let init_times = Times::new(base_wall, base_mono);

        let clock = RetentionClock::new(init_times);

        // 1. Normal advance: wall and mono advance by exactly 10 seconds
        let elapsed = Duration::from_secs(10);
        let wall_normal = base_wall
            .checked_add(SignedDuration::try_from(elapsed).expect("signed"))
            .expect("add");
        let sample_normal = Times::new(wall_normal, base_mono + elapsed);

        let now_normal = clock.now(&sample_normal).expect("now");
        assert_eq!(now_normal.instant(), wall_normal);

        // 2. Backward wall jump: wall clock moved backward by 5 seconds
        let wall_backward = base_wall
            .checked_sub(jiff::SignedDuration::from_secs(5))
            .expect("sub");
        let sample_backward = Times::new(wall_backward, base_mono + elapsed);

        let now_backward = clock.now(&sample_backward).expect("now");
        // min(wall_backward, base_wall + 10s) must be wall_backward
        assert_eq!(now_backward.instant(), wall_backward);

        // 3. Monotonic before initial (saturating safety)
        let sample_prior_mono = Times::new(
            base_wall,
            base_mono
                .checked_sub(Duration::from_secs(1))
                .unwrap_or(base_mono),
        );
        let now_prior = clock.now(&sample_prior_mono).expect("prior mono");
        assert_eq!(now_prior.instant(), base_wall);
    }
}
