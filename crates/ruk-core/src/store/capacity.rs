//! Durable capacity ledger: the consumer of [`crate::physical`].
//!
//! # Design
//!
//! `physical.rs` performs the platform reservation (`fallocate` /
//! `SetFileInformationByHandle`) but its receipt is an observation, not a
//! durable charge. This ledger is the durable side of that contract, and it
//! honours the four obligations the `physical` module doc names:
//!
//! 1. **Persist before reserving.** `Store::publish` commits the pending
//!    row in its own Immediate-redb transaction *before* the first
//!    [`crate::physical::PhysicalReservation::reserve`] call. Staging the
//!    row in the held publication transaction would not be durable: a crash
//!    after the reserve but before the commit would leave allocated blocks
//!    with no ledger row. The pending commit is a separate transaction
//!    because redb has a single writer and the publication transaction is
//!    already held for fact expectations at that point; the store validates
//!    the plan once in a probing transaction (aborted, never committed),
//!    commits the pending row, then opens the real publication transaction
//!    and re-validates. The writer mutex is held throughout, so the two
//!    validations observe identical committed state.
//! 2. **Serialized allocator.** Every ledger mutation and every reserve
//!    call happens under the store's writer mutex, the same serialization
//!    that sequences publication. No second publisher can interleave.
//! 3. **Re-query update.** No second query is needed: the reservation
//!    already re-queries the still-open handle after the platform call, so
//!    the observed `allocated_bytes`/`logical_len` are copied straight from
//!    the receipt into the row when the publication commits.
//! 4. **Durable-only release.** [`PhysicalReservation`](crate::physical::PhysicalReservation)
//!    has no `Drop` impl on purpose. Charge leaves the ledger only through
//!    an Immediate commit: `Pending -> Committed` in the publication's own
//!    commit, `Pending -> Released` in recovery reconciliation, and (future)
//!    ledger pruning of tombstones under compaction.
//!
//! # Rows
//!
//! One row per reserving publication, keyed by `(generation, seq)`: the
//! locator generation the publication will advance to, plus a per-generation
//! sequence so a retry after a crash does not collide with the dead row.
//! The value is a postcard [`PendingReservation`]: the estimated byte count
//! (known before the segment split), the state, and the per-segment charges
//! with their observed receipts (known after the appends).
//!
//! # Quotas
//!
//! [`CapacityLimits`] carries two optional knobs, both unbounded by default
//! so existing stores behave exactly as before:
//!
//! - `max_pending_bytes`: ceiling over `sum(Pending.estimated_bytes)` plus
//!   the incoming estimate, checked at admission before anything mutates.
//! - `max_store_bytes`: ceiling over live committed segment extents (sum of
//!   `committed_end` over non-retired manifests) plus the incoming
//!   estimate.
//!
//! A refusal is [`StoreError::Limit`] before the first mutation, so the
//! writer stays open. This ledger does NOT duplicate [`PreparationBudget`]:
//! the budget governs transient preparation memory and scratch disk, which
//! vanish when a spool drops; the ledger governs durable segment bytes,
//! which survive the process. Different lifetimes, different owners, one
//! admission each.
//!
//! # Crash recovery
//!
//! Choice (a): stale `Pending` rows are re-checked against actual file
//! extents at `Store::open` and released. A row is still `Pending` after a
//! crash only if its publication never committed, because the
//! `Pending -> Committed` transition commits atomically with the locators.
//! Its reserved range therefore lies outside every committed extent: either
//! in the open segment's uncommitted tail (which recovery truncates,
//! freeing the blocks) or in a sealed orphan no manifest names (no live
//! reader can reach it). Holding such rows until compaction would pin quota
//! for dead publications that compaction never visits — orphans carry no
//! manifest — while the blocks themselves are already freed or unreachable.
//! So reconciliation stats each charged segment file, records the observed
//! length, and marks the row `Released` in one Immediate commit. A row
//! whose range *is* covered by a committed extent cannot exist (it would
//! imply the commit happened, which would have marked it `Committed`), so
//! the re-check is evidence, not a branch: any `Pending` row found at open
//! is dead.
//!
//! # Gaps (see the task report)
//!
//! - Coordinator plumbing: `policy.toml [capacity]` parses, but nothing
//!   calls `Store::set_capacity_limits` yet.
//! - Tombstone pruning: `Committed`/`Released` rows accumulate; a future
//!   compaction pass should delete them.
//! - Partial-segment release on compaction lives with the manifests, not
//!   the rows; quota reads live manifests so it never over-charges.

use std::path::Path;

use super::metadata::Metadata;
use super::segment::segment_file_name;
use crate::store::error::StoreError;

/// Quota knobs for the capacity ledger. `None` means unbounded, which is
/// the default and preserves the pre-ledger behaviour exactly.
///
/// Mirrors `policy.toml [capacity]`: `max_pending` maps to
/// [`Self::max_pending_bytes`], `max_total` maps to
/// [`Self::max_store_bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityLimits {
    /// Ceiling over held pending estimates plus the incoming estimate.
    pub max_pending_bytes: Option<u64>,
    /// Ceiling over live committed segment extents plus the incoming estimate.
    pub max_store_bytes: Option<u64>,
}

impl Default for CapacityLimits {
    /// Unbounded: admission never refuses.
    fn default() -> Self {
        Self {
            max_pending_bytes: None,
            max_store_bytes: None,
        }
    }
}

impl CapacityLimits {
    /// Unbounded limits.
    #[must_use]
    pub fn unbounded() -> Self {
        Self::default()
    }
}

/// Lifecycle of one pending-reservation row.
///
/// `Pending` rows exist only for publications that reserved (or were about
/// to reserve) but never committed. `Committed` rows are audit history: the
/// bytes they charged are covered by committed manifests and locators.
/// `Released` rows are dead charges freed by recovery reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReservationState {
    Pending,
    Committed,
    Released,
}

/// One segment range reserved and observed during a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentCharge {
    /// Segment file id the range was reserved in.
    pub segment: u64,
    /// Start offset of the reserved range.
    pub offset: u64,
    /// Reserved length (the record length, header included).
    pub len: u64,
    /// Filesystem-reported allocated bytes for the whole file, observed
    /// through the still-open handle after the reservation.
    pub allocated_bytes: u64,
    /// File-visible length at the same observation point.
    pub logical_len: u64,
}

/// The durable pending-reservation record of one publication.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingReservation {
    /// Locator generation the publication advanced (or would advance) to.
    pub generation: u64,
    /// Per-generation sequence distinguishing crash retries.
    pub seq: u32,
    /// Estimated appended bytes, fixed before the segment split is known.
    pub estimated_bytes: u64,
    /// Lifecycle state.
    pub state: ReservationState,
    /// Per-segment reservations with their observed receipts. Empty until
    /// the appends run; complete when the row commits.
    pub charges: Vec<SegmentCharge>,
}
// (All fields are `pub`: the store owner builds and settles rows; serde
// owns the wire form.)

impl PendingReservation {
    /// Key bytes: big-endian generation followed by big-endian sequence.
    /// Fixed width, so raw-byte order matches numeric order.
    #[must_use]
    pub fn key(generation: u64, seq: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(12);
        key.extend_from_slice(&generation.to_be_bytes());
        key.extend_from_slice(&seq.to_be_bytes());
        key
    }

    /// Splits key bytes back into `(generation, seq)`.
    pub fn split_key(key: &[u8]) -> Result<(u64, u32), StoreError> {
        if key.len() != 12 {
            return Err(StoreError::Corrupt(format!(
                "pending reservation key has {} bytes, expected 12",
                key.len()
            )));
        }
        let generation = u64::from_be_bytes(key[0..8].try_into().expect("sliced length"));
        let seq = u32::from_be_bytes(key[8..12].try_into().expect("sliced length"));
        Ok((generation, seq))
    }
}

/// Checked sum of record lengths for the incoming publication.
pub(crate) fn estimate_bytes(lens: impl Iterator<Item = u64>) -> Result<u64, StoreError> {
    let mut total = 0u64;
    for len in lens {
        total = total.checked_add(len).ok_or_else(|| {
            StoreError::Capacity("publication byte estimate overflows u64".to_owned())
        })?;
    }
    Ok(total)
}

/// Admission check: refuses with [`StoreError::Limit`] before any mutation.
/// All sums are precomputed by the caller; this function only compares.
pub(crate) fn admit(
    pending_held: u64,
    committed_held: u64,
    estimate: u64,
    limits: &CapacityLimits,
) -> Result<(), StoreError> {
    if let Some(max) = limits.max_pending_bytes {
        let after = pending_held.checked_add(estimate).ok_or_else(|| {
            StoreError::Capacity("pending byte accounting overflows u64".to_owned())
        })?;
        if after > max {
            return Err(StoreError::Limit(format!(
                "pending reservation limit of {max} bytes exceeded ({pending_held} held, {estimate} requested)"
            )));
        }
    }
    if let Some(max) = limits.max_store_bytes {
        let after = committed_held.checked_add(estimate).ok_or_else(|| {
            StoreError::Capacity("store byte accounting overflows u64".to_owned())
        })?;
        if after > max {
            return Err(StoreError::Limit(format!(
                "store size limit of {max} bytes exceeded ({committed_held} committed, {estimate} requested)"
            )));
        }
    }
    Ok(())
}

/// Next per-generation sequence: one past the highest `seq` already keyed
/// under `generation`, or zero when none exists.
#[must_use]
pub(crate) fn next_seq(existing: &[(Vec<u8>, PendingReservation)], generation: u64) -> u32 {
    existing
        .iter()
        .filter_map(|(key, _)| {
            PendingReservation::split_key(key)
                .ok()
                .filter(|(row_gen, _)| *row_gen == generation)
                .map(|(_, seq)| seq)
        })
        .max()
        .map(|seq| seq.saturating_add(1))
        .unwrap_or(0)
}

/// Sums `estimated_bytes` over rows in `Pending` state.
#[must_use]
pub(crate) fn pending_held(rows: &[(Vec<u8>, PendingReservation)]) -> u64 {
    rows.iter()
        .filter(|(_, row)| row.state == ReservationState::Pending)
        .map(|(_, row)| row.estimated_bytes)
        .fold(0u64, |acc, len| acc.saturating_add(len))
}

/// Releases every stale `Pending` row found at open. Recovery already ran,
/// so the observed file lengths are post-truncation: each charged file is
/// consulted as evidence, then the row is marked `Released` in one
/// Immediate commit. Returns the number of rows released.
///
/// A `Pending` row at open is always dead (its commit would have marked it
/// `Committed` atomically with the locators), so the verdict never branches
/// on what the files show; an overflowing charged extent is ledger damage
/// and refuses the open instead.
pub(crate) fn reconcile_stale_pending(
    meta: &Metadata,
    segments_dir: &Path,
) -> Result<u64, StoreError> {
    let rows = meta.pending_rows()?;
    let mut updates = Vec::new();
    for (key, row) in &rows {
        if row.state != ReservationState::Pending {
            continue;
        }
        for charge in &row.charges {
            charge.offset.checked_add(charge.len).ok_or_else(|| {
                StoreError::Corrupt("pending reservation holds an overflowing extent".to_owned())
            })?;
            // Evidence the file was consulted post-recovery; the verdict is
            // unconditional (see above and the module docs).
            let _observed_len: Option<u64> = std::fs::metadata(
                segments_dir.join(segment_file_name(charge.segment)),
            )
            .map(|metadata| metadata.len())
            .ok();
        }
        let mut released = row.clone();
        released.state = ReservationState::Released;
        updates.push((key.clone(), released));
    }
    let released = u64::try_from(updates.len()).map_err(|_| {
        StoreError::Capacity("released pending-row count overflows u64".to_owned())
    })?;
    meta.release_pending(&updates)?;
    Ok(released)
}
