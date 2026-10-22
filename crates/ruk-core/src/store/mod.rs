//! The durable object and fact store.
//!
//! [`Store`] is the one public surface: objects are prepared into bounded
//! spools, then published together with conditional fact mutations in a
//! single durable transaction. Segments hold object bytes, redb holds every
//! mutable fact, and one serialized writer sequences publication.
//!
//! # Publication order
//!
//! 1. Open the one redb write transaction and verify and apply every fact
//!    expectation in it, before any byte is appended.
//! 2. Validate every prepared object against the target store: hash width,
//!    committed duplicate compatibility, and every delta base committed in
//!    this store with the same kind and the right chain depth.
//! 3. Append complete records, rolling segments at the target size. New
//!    segment files are created exclusively; the id advances past any
//!    unknown file instead of overwriting or unlinking it.
//! 4. Flush every touched segment, then publish new directory entries
//!    (POSIX flushes the directory; Windows published each entry when it
//!    was created).
//! 5. Commit the held transaction: locators, segment manifests, the
//!    generation, and facts become visible together.
//!
//! A failed append or an ambiguous commit closes the writer: the bytes stay
//! for recovery and nothing publishes around damage in this session. A
//! failed commit may already be durable, so nothing rolls back. Committed
//! corruption latches quarantine and refuses all later service, whether a
//! read, a fact lookup, or a publication's own reads of committed metadata
//! observed it. Corruption found in the staged bytes of a publication (a
//! payload checksum mismatch while appending) is not committed corruption:
//! it closes the writer and latches nothing.
//!
//! This slice stores objects and facts. Repository operations, coordination
//! transport, retention and collection are later slices.

pub mod error;
pub mod lfs;
pub mod types;

mod capacity;
mod compact;
mod delta;
pub mod durability;
mod group;
mod guards;
mod metadata;
pub(crate) mod pinned;
mod prepare;
mod recovery;
mod segment;
mod spool;
mod stream;

#[cfg(test)]
mod crash_tests;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod prepare_tests;
#[cfg(test)]
mod segment_tests;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

pub use capacity::CapacityLimits;
pub(crate) use capacity::{PendingReservation, ReservationState, SegmentCharge};
pub use compact::{CompactionBacklog, CompactionStats, PruneStats};
pub use error::StoreError;
pub(crate) use guards::{GenerationGuard, GenerationRegistry};
pub use metadata::{FactPage, FactPageBudget, FactRow};
pub(crate) use metadata::{decode, encode};
pub use spool::{BudgetLimits, PreparationBudget, Spool};
pub use stream::{ChunkDecision, StreamMeta};
pub use types::{
    EVENT_HEAD_KEY, Encoding, EventContext, EventHeadRow, EventSource, FactExpectation,
    FactMutation, FactTable, ObjectKind, ObjectLocation, PreparedObject, Publication,
    REPO_META_KEY, ReadObject, RefEvent, RepoMetaRow, SegmentManifest, StoreEvent, StoreFormat,
};

use crate::change::StoreId;
use crate::error::ErrorCode;
use crate::ids::{HashKind, Oid};
use crate::physical::{AllocationError as PhysicalAllocationError, PhysicalReservation};
use crate::refdata::RefName;
use metadata::{Metadata, PublicationTxn};
use pinned::{PinnedRoot, segment_rel};
use recovery::{Committed, OpenSegment, Recovered, SegmentFileCache};
use segment::SegmentWriter;
use types::{RepoMetaRowV0, decode_store_event};

/// Longest delta chain accepted on write and read.
pub(crate) const MAX_DELTA_DEPTH: u8 = 50;

const FORMAT_FILE: &str = "format";
const META_FILE: &str = "meta.redb";
const SEGMENTS_DIR: &str = "segments";
/// The format file is three short lines; anything longer is foreign.
const MAX_FORMAT_BYTES: u64 = 128;

/// A durable object store rooted at a `.ruk/store` directory.
///
/// `Store` is `Sync`: reads and fact lookups run concurrently with each
/// other and with publication, and publications serialize on one writer.
/// Reads release every metadata transaction before payload I/O.
/// Lock-free counters of observable I/O work issued through [`Store`].
///
/// Diagnostic only: a snapshot is not transactional, and callers must not
/// branch on these numbers. Capacity verification and measurements read
/// them; nothing else does.
#[derive(Debug, Default)]
struct IoCounters {
    /// Completed [`Store::read`] object decodes.
    object_reads: AtomicU64,
    /// Decoded bytes those reads produced.
    object_decoded_bytes: AtomicU64,
    /// [`Store::object_len`] locator lookups.
    locator_lookups: AtomicU64,
    /// [`Store::fact`] lookups.
    fact_lookups: AtomicU64,
    /// Rows returned by fact lookups and pages.
    fact_rows: AtomicU64,
    /// [`Store::fact_page`] calls.
    fact_page_calls: AtomicU64,
    /// Payload reads that reached the metadata chain.
    metadata_calls: AtomicU64,
    /// Publications that committed, one per [`Store::publish`] call.
    publications: AtomicU64,
    /// Publication transactions committed. A group shares one, so this is at
    /// most `publications`.
    publication_commits: AtomicU64,
    /// Segment files synced by publications.
    segment_syncs: AtomicU64,
    /// Pending-reservation commits (one Immediate metadata commit each).
    pending_commits: AtomicU64,
    /// Directory syncs for newly created segment files.
    directory_syncs: AtomicU64,
}

/// A copy of [`Store`]'s I/O counters at one instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoStats {
    pub object_reads: u64,
    pub object_decoded_bytes: u64,
    pub locator_lookups: u64,
    pub fact_lookups: u64,
    pub fact_rows: u64,
    pub fact_page_calls: u64,
    pub metadata_calls: u64,
    /// Publications that committed.
    pub publications: u64,
    /// Publication transactions committed; a group of publications shares one.
    pub publication_commits: u64,
    /// Segment files synced by publications.
    pub segment_syncs: u64,
    /// Pending-reservation commits. Each is an Immediate metadata commit.
    pub pending_commits: u64,
    /// Directory syncs for newly created segment files.
    pub directory_syncs: u64,
}

pub struct Store {
    root: PathBuf,
    format: StoreFormat,
    meta: Metadata,
    io: IoCounters,
    budget: Arc<PreparationBudget>,
    capacity: Mutex<CapacityLimits>,
    guards: Arc<GenerationRegistry>,
    writer: Mutex<WriterState>,
    /// Read-only descriptors for committed segments, opened once per id and
    /// shared by every read through positional I/O. Dropped with the store.
    segment_fds: SegmentFileCache,
    /// The held store-root directory. Every later segment-file open,
    /// create, probe, unlink, and directory sync travels this descriptor
    /// instead of the recorded path, so a symlink swapped into the path
    /// after open cannot redirect them.
    pin: PinnedRoot,
    /// Serializes whole compaction passes against each other. Publications
    /// never take it; the swap takes the writer lock beneath it.
    compaction_lock: Mutex<()>,
    quarantine: Mutex<Option<String>>,
    quarantined: AtomicBool,
    /// Submissions waiting for the writer, drained by the next writer holder.
    queue: group::Queue,
    /// The commit linger window in nanoseconds (`RUK_COMMIT_LINGER_MS`).
    commit_linger_nanos: AtomicU64,
}

/// One held reader pin against segment retirement for the duration of a
/// fork photograph and copy.
///
/// Dropping the pin releases the registration; release is unconditional on
/// every path.
#[derive(Debug)]
pub struct ForkPin {
    _guard: GenerationGuard,
}

/// State owned by the serialized publication writer.
struct WriterState {
    /// The open segment currently appended to.
    active: Option<ActiveSegment>,
    /// The recovered open segment, reopened lazily by the first append.
    resume: Option<OpenSegment>,
    /// Next segment id to try; only advances.
    next_segment_id: u64,
    /// Set once a publication failed after durable work began.
    closed: Option<String>,
    /// Test-only segment roll target in bytes; zero means the production
    /// [`segment::SEGMENT_TARGET_BYTES`]. Lets compaction tests build
    /// multi-segment stores without 256 MiB payloads.
    #[cfg(test)]
    segment_target_override: u64,
}

impl WriterState {
    /// The segment roll target in effect: the test override when set, the
    /// production target otherwise.
    fn target_bytes(&self) -> u64 {
        #[cfg(test)]
        if self.segment_target_override > 0 {
            return self.segment_target_override;
        }
        segment::SEGMENT_TARGET_BYTES
    }
}

struct ActiveSegment {
    id: u64,
    writer: SegmentWriter<File>,
}

/// What one publication appended before its transaction commits.
#[derive(Default)]
struct Batch {
    /// Segments sealed during this publication, kept until flushed.
    sealed: Vec<ActiveSegment>,
    /// Whether the writer's current active segment received bytes.
    active_touched: bool,
    /// Whether a segment file was created (its entry needs publishing).
    new_entries: bool,
    locations: Vec<(Oid, ObjectLocation)>,
    /// Platform reservations performed by this publication, in order, with
    /// their observed receipts. Settled into the pending row at stage time.
    charges: Vec<SegmentCharge>,
}

/// Durable proof that the pending row committed before the first reserve
/// call of a publication. Carried from the pending commit to the stage step
/// of the same publication, under the same writer lock.
struct PendingHandle {
    key: Vec<u8>,
    row: PendingReservation,
}

/// A validated publication: identities in request order and the objects
/// that still need bytes.
struct Plan<'a> {
    order: Vec<Oid>,
    fresh: Vec<&'a PreparedObject>,
    generation: u64,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.root)
            .field("kind", &self.format.kind)
            .field("quarantined", &self.quarantined.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Creates a new store at `root`, the `.ruk/store` directory itself.
    ///
    /// Every element is created exclusively: an existing `format`,
    /// `meta.redb` or `segments` makes creation fail and nothing is
    /// overwritten. `segments` is created by this call or not at all: a
    /// directory that a racing creator made visible is never adopted, so of
    /// several concurrent creators of one root at most one proceeds.
    ///
    /// The `format` file is the last write: every earlier publication (root,
    /// `segments`, `meta.redb` and its first commit) has returned before the
    /// first format byte is written, and the format is flushed before this
    /// call returns. A valid format proves that the earlier publications
    /// completed. An opener flushes that format before recovery. An absent,
    /// incomplete, or rejected format prevents opening; creation never
    /// adopts or deletes an incomplete store.
    ///
    /// The store identity is fixed once, before any filesystem change, and
    /// recorded in the format file: reopening or moving the same store keeps
    /// it, and every new store has a distinct identity.
    ///
    /// # Platforms
    /// POSIX creates `root` and any missing ancestors, flushing the existing
    /// ancestor chain first, and accepts an existing directory as `root`.
    ///
    /// Windows requires an existing, already durable parent and an absent
    /// `root`. Nothing proves that an ancestor some other actor created is
    /// durable, so none is created here and none is trusted: the caller
    /// (standalone setup, a hosting process) provisions the parent and makes
    /// it durable before this call. A missing parent fails before any change,
    /// an existing `root` of any kind is never adopted, and only the call
    /// whose exclusive publication of `root` succeeds builds inside it.
    ///
    /// A relative `root` is resolved against the current directory once,
    /// here, and the store keeps the absolute path: a later change of the
    /// process working directory cannot redirect its file I/O.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when the layout already exists, and on Windows
    /// when `root` already exists; [`StoreError::Io`] (`NotFound` on Windows
    /// for a missing parent) and [`StoreError::Database`] on creation
    /// failure, and [`StoreError::Io`] when `root` cannot be made absolute.
    ///
    /// An I/O error reported by a flush fails the call and is final: the
    /// storage layer reported that durability is not established. Reopening
    /// does not repair a failed writeback, and no retry is attempted; the
    /// directory is left for an operator, who may need to recover the
    /// storage first.
    pub fn create(
        root: &Path,
        kind: HashKind,
        budget: Arc<PreparationBudget>,
    ) -> Result<Self, StoreError> {
        let format = StoreFormat {
            kind,
            id: StoreId::generate(),
        };
        let root = std::path::absolute(root)?;
        let root = root.as_path();
        create_root(root)?;
        for name in [FORMAT_FILE, META_FILE, SEGMENTS_DIR] {
            require_absent(&root.join(name))?;
        }
        create_owned_dir(&root.join(SEGMENTS_DIR))?;
        let meta_file = durability::create_file_published(&root.join(META_FILE))?;
        durability::sync_file(&meta_file)?;
        let meta = Metadata::create_in_file(meta_file)?;
        sync_entries(root)?;

        let mut format_file = durability::create_file_published(&root.join(FORMAT_FILE))?;
        format_file.write_all(&format.to_bytes())?;
        durability::sync_file(&format_file)?;
        sync_entries(root)?;

        let guards = Arc::new(GenerationRegistry::new(0));
        let mut store = Self::assemble(
            root,
            format,
            meta,
            budget,
            guards,
            Recovered {
                next_segment_id: 0,
                open: None,
            },
        );
        store.pin = PinnedRoot::open(root)?;
        Ok(store)
    }

    /// Opens an existing store after verifying all committed bytes.
    ///
    /// Recovery validates every committed segment extent, truncates only an
    /// open segment's uncommitted tail, and verifies every committed object
    /// identity unless the stored verified generation already covers the
    /// current one (see the recovery module docs for the caching contract).
    /// Missing or damaged committed bytes found by the passes that run
    /// refuse the open.
    ///
    /// Once the metadata database is owned, and before recovery or any
    /// return, the validated format file is flushed again, and on POSIX the
    /// root's entries too. A creator that died before its own flush may have
    /// left a format that is visible only in the cache; this makes what was
    /// validated durable before any operation can be acknowledged on top of
    /// it. The file is only flushed, never rewritten, and opening needs
    /// write access to it. A flush that reports an I/O error fails the open;
    /// a successful flush after an earlier reported failure does not prove
    /// the earlier writeback, so such a store needs operator storage
    /// recovery rather than a reopen.
    ///
    /// A relative `root` is resolved against the current directory once,
    /// here, and the store keeps the absolute path (see [`Store::create`]).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] without a format file;
    /// [`StoreError::Version`] for an unknown format, including an empty or
    /// partly written one left by an interrupted creation and the rejected
    /// earlier two-line marker;
    /// [`StoreError::Corrupt`] for committed damage; I/O and database
    /// failures propagate, including a `root` that cannot be made absolute.
    ///
    /// Cross-process concurrency: redb opens in `ExclusiveWriter` mode, so
    /// the whole-file lock is held for the `Database` lifetime — two
    /// processes' open stores serialize against each other, reads included
    /// (a read-only redb handle could share, but the store opens
    /// read-write). The wait below only bounds the queue at open; once open,
    /// a peer holds the lock until its store drops, which is what `git`
    /// effectively does for writers while reads go lock-free. The lock is an
    /// OS-advisory byte range released by the kernel when the holder's
    /// descriptors close, so a killed peer never leaves a stale lock: the
    /// waiter's retry then succeeds.
    pub fn open(root: &Path, budget: Arc<PreparationBudget>) -> Result<Self, StoreError> {
        Self::open_with_timeout(root, budget, metadata::open_wait_timeout())
    }

    /// Opens the store, waiting up to `timeout` for a lock-busy peer at the
    /// metadata open; corruption still refuses on the first attempt. A
    /// `timeout` of zero means a single attempt. The budget defaults to
    /// `RUK_OPEN_TIMEOUT_MS` milliseconds (10 s when unset or unparsable)
    /// through [`Store::open`]; the CLI needs no extra flag.
    pub fn open_with_timeout(
        root: &Path,
        budget: Arc<PreparationBudget>,
        timeout: Duration,
    ) -> Result<Self, StoreError> {
        Self::open_with_timeout_inner(root, root, budget, timeout)
    }

    /// Opens the store at `open_root` while recording `record_root`: every
    /// file access during the open travels `open_root`, so callers holding
    /// a containment descriptor open through `/proc/self/fd` and keep the
    /// recorded root free of process-local file descriptor numbers. The
    /// recorded root must name the same directory.
    ///
    /// # Errors
    /// As for [`Store::open`].
    pub fn open_pinned(
        open_root: &Path,
        record_root: &Path,
        budget: Arc<PreparationBudget>,
    ) -> Result<Self, StoreError> {
        Self::open_with_timeout_inner(
            open_root,
            record_root,
            budget,
            metadata::open_wait_timeout(),
        )
    }

    fn open_with_timeout_inner(
        open_root: &Path,
        record_root: &Path,
        budget: Arc<PreparationBudget>,
        timeout: Duration,
    ) -> Result<Self, StoreError> {
        let profiling = profile_enabled();
        let total = ProfileClock::now(profiling);
        let mut clock = ProfileClock::now(profiling);
        let root = std::path::absolute(open_root)?;
        let root = root.as_path();
        let record_root = std::path::absolute(record_root)?;
        let record_root = record_root.as_path();
        // Hold the opened directory before any file access: every later
        // segment open travels this descriptor, so flips of the recorded
        // path after this point cannot redirect them.
        let pin = PinnedRoot::open(root)?;
        // The format and metadata opens travel the held descriptor when
        // pinned, so no later segment, metadata, or format access follows
        // the recorded path by name.
        let format_path = pin
            .proc_subpath(FORMAT_FILE)
            .unwrap_or_else(|| root.join(FORMAT_FILE));
        let (format, format_file) = read_format_file(&format_path)?;
        let format_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        let meta_path = pin
            .proc_subpath(META_FILE)
            .unwrap_or_else(|| root.join(META_FILE));
        let meta = Metadata::open_with_timeout(&meta_path, timeout)?;
        let meta_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        durability::sync_file(&format_file)?;
        sync_entries(root)?;
        drop(format_file);
        let sync_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        budget.register_scratch(&pin, root)?;
        let scratch_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        let generation = meta.generation()?;
        let guards = Arc::new(GenerationRegistry::new(generation));
        let segment_fds = SegmentFileCache::default();
        let committed = Committed {
            root,
            kind: format.kind,
            meta: &meta,
            budget: &budget,
            guards: &guards,
            files: &segment_fds,
            pin: &pin,
        };
        let setup_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        let recovered = match recovery::run(&committed) {
            Ok(recovered) => recovered,
            Err(err) => {
                #[cfg(test)]
                {
                    if err.code() == ErrorCode::ECorrupt {
                        crash_tests::crash_at("recovery_after_detect_corrupt");
                    }
                }
                return Err(err);
            }
        };
        // Reconcile capacity-ledger rows left Pending by publications that
        // never committed, after recovery truncated the tails they may have
        // reserved in: re-check them against the file extents as found and
        // release them (see store::capacity).
        capacity::reconcile_stale_pending(&meta, &root.join(SEGMENTS_DIR))?;
        // The recovery pass above warmed `segment_fds` (one open per sealed
        // segment); the assembled store keeps warming it instead of
        // reopening those segments on first serve.
        let recovery_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        let mut store = Self::assemble(record_root, format, meta, budget, guards, recovered);
        store.segment_fds = segment_fds;
        store.pin = pin;
        let assemble_ms = clock.elapsed_ms();
        if profiling {
            eprintln!(
                "[ruk-profile] open total={:.2}ms format={:.2}ms meta={:.2}ms sync={:.2}ms scratch={:.2}ms setup={:.2}ms recovery={:.2}ms assemble={:.2}ms",
                total.elapsed_ms(),
                format_ms,
                meta_ms,
                sync_ms,
                scratch_ms,
                setup_ms,
                recovery_ms,
                assemble_ms,
            );
        }
        Ok(store)
    }

    fn assemble(
        root: &Path,
        format: StoreFormat,
        meta: Metadata,
        budget: Arc<PreparationBudget>,
        guards: Arc<GenerationRegistry>,
        recovered: Recovered,
    ) -> Self {
        Self {
            root: root.to_path_buf(),
            format,
            meta,
            io: IoCounters::default(),
            budget,
            capacity: Mutex::new(CapacityLimits::unbounded()),
            guards,
            segment_fds: SegmentFileCache::default(),
            pin: PinnedRoot::default(),
            writer: Mutex::new(WriterState {
                active: None,
                resume: recovered.open,
                next_segment_id: recovered.next_segment_id,
                closed: None,
                #[cfg(test)]
                segment_target_override: 0,
            }),
            compaction_lock: Mutex::new(()),
            quarantine: Mutex::new(None),
            quarantined: AtomicBool::new(false),
            queue: group::Queue::default(),
            commit_linger_nanos: AtomicU64::new(group::nanos(group::linger_from_env())),
        }
    }

    /// The store root directory: the directory holding `format`, the segment
    /// files, and `policy.toml`. Absolute for stores opened through
    /// [`Store::open`], as given for stores from [`Store::create`].
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of segment `id` under this store's root.
    #[must_use]
    pub fn segment_path(&self, id: u64) -> PathBuf {
        self.root
            .join(SEGMENTS_DIR)
            .join(segment::segment_file_name(id))
    }

    /// The fixed hash kind of this store.
    #[must_use]
    pub fn hash_kind(&self) -> HashKind {
        self.format.kind
    }

    /// The immutable identity of this store, fixed by the format file at
    /// creation and preserved by reopen and rename.
    #[must_use]
    pub fn store_id(&self) -> StoreId {
        self.format.id
    }

    /// Whether committed corruption latched quarantine in this session.
    #[must_use]
    pub fn quarantine(&self) -> bool {
        self.quarantined.load(Ordering::SeqCst)
    }

    /// Why the store is quarantined, if it is.
    #[must_use]
    pub fn quarantine_reason(&self) -> Option<String> {
        self.quarantine.lock().ok()?.clone()
    }

    fn committed(&self) -> Committed<'_> {
        Committed {
            root: &self.root,
            kind: self.format.kind,
            meta: &self.meta,
            budget: &self.budget,
            guards: &self.guards,
            files: &self.segment_fds,
            pin: &self.pin,
        }
    }

    /// Checks whether a segment retired at or before `retired_generation` is ready for physical unlink.
    ///
    /// # Precondition
    /// The caller MUST have already durably removed every locator referencing this segment
    /// and committed the retirement manifest at or before `retired_generation`.
    ///
    /// No filesystem I/O is performed under this registry mutex.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn is_segment_retired_ready_for_unlink(&self, retired_generation: u64) -> bool {
        self.guards
            .is_segment_retired_ready_for_unlink(retired_generation)
    }

    /// Accessor for the store's generation registry.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn generation_registry(&self) -> &Arc<GenerationRegistry> {
        &self.guards
    }

    /// Builds a corruption error and latches quarantine, mirroring
    /// committed reads: callers that detect committed damage report it
    /// through here instead of constructing it inline.
    pub(crate) fn latch_corrupt(&self, detail: String) -> StoreError {
        let err = StoreError::Corrupt(detail);
        self.latch(&err.to_string());
        err
    }

    /// Latches quarantine. The first reason stays.
    fn latch(&self, reason: &str) {
        if let Ok(mut slot) = self.quarantine.lock() {
            slot.get_or_insert_with(|| reason.to_owned());
        }
        self.quarantined.store(true, Ordering::SeqCst);
    }

    fn refuse_if_quarantined(&self) -> Result<(), StoreError> {
        if !self.quarantined.load(Ordering::SeqCst) {
            return Ok(());
        }
        let reason = self
            .quarantine_reason()
            .unwrap_or_else(|| "committed corruption was observed".to_owned());
        Err(StoreError::Corrupt(format!(
            "store is quarantined: {reason}"
        )))
    }

    /// Latches quarantine when a read of committed state reports corruption.
    pub(crate) fn observe<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if let Err(err) = &result
            && err.code() == ErrorCode::ECorrupt
        {
            self.latch(&err.to_string());
        }
        result
    }

    fn lock_writer(&self) -> Result<MutexGuard<'_, WriterState>, StoreError> {
        self.writer
            .lock()
            .map_err(|_| StoreError::WriterClosed("writer state poisoned by a panic".to_owned()))
    }

    /// Flushes the writer's open segment file and retires the handle.
    ///
    /// Every committed byte was already synced by its publication before the
    /// metadata commit, so this only forces out whatever the OS still holds
    /// back, then drops the open `File` so the descriptor does not linger
    /// until the store itself drops. The retirement is terminal for
    /// publication: dropping the handle without sealing leaves the committed
    /// manifest naming one unsealed segment, so minting a fresh segment
    /// afterwards would record two open segments and fail recovery. The
    /// writer latches closed instead, and later publications fail with
    /// [`StoreError::WriterClosed`] until the store reopens (recovery then
    /// resumes the single open segment). Reads are unaffected. Dropping the
    /// store without closing is still safe: the next open truncates any
    /// uncommitted tail during recovery. Closing is idempotent; a store
    /// with no open segment returns immediately.
    ///
    /// The publication lane runner calls this once its drain commits the
    /// final batch (see [`crate::coord`]), so the handle always retires
    /// after the last write rather than before it.
    ///
    /// # Errors
    /// [`StoreError::WriterClosed`] when the writer state is poisoned;
    /// [`StoreError::Io`] when the final flush fails.
    pub fn close(&self) -> Result<(), StoreError> {
        let mut writer = self.lock_writer()?;
        // Latch before the fallible flush: a sync failure still returns
        // `Io`, but the writer must already refuse further publication,
        // otherwise the dropped handle plus a freshly minted segment would
        // record two open segments and fail the next recovery.
        if writer.closed.is_none() {
            writer.closed = Some("store closed; reopen the store to publish again".to_owned());
        }
        if let Some(mut active) = writer.active.take() {
            // Normally empty: every publication flushed after its append
            // loop. Flush anyway so no staged byte is left behind the sync.
            active.writer.flush_staged()?;
            durability::sync_file(active.writer.get_ref())?;
        }
        Ok(())
    }

    /// Replaces the capacity quota knobs (default unbounded). The
    /// coordinator applies the `policy.toml [capacity]` values here; the
    /// ledger reads them at each publication admission.
    pub fn set_capacity_limits(&self, limits: CapacityLimits) {
        *self
            .capacity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = limits;
    }

    fn capacity_limits(&self) -> CapacityLimits {
        *self
            .capacity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every capacity-ledger row. Test-only: lets crash tests assert the
    /// reconciliation outcome without reopening the metadata database.
    #[cfg(test)]
    pub(crate) fn capacity_pending_rows_for_tests(
        &self,
    ) -> Result<Vec<(Vec<u8>, PendingReservation)>, StoreError> {
        self.meta.pending_rows()
    }

    /// Shrinks the segment roll target for this store. Test-only: lets
    /// compaction tests build multi-segment stores without 256 MiB
    /// payloads. The floor keeps one small record plus its header and seal
    /// footer representable.
    #[cfg(test)]
    pub(crate) fn set_segment_target_for_tests(&self, bytes: u64) {
        if let Ok(mut writer) = self.writer.lock() {
            writer.segment_target_override = bytes.max(1024);
        }
    }

    /// Prepares one object for publication.
    ///
    /// `input` must yield exactly `decoded_len` bytes. A `predecessor` must
    /// be committed in this store; it is read back verified and offered to
    /// the delta encoder. Ordinary preparation emits zstd; a delta is kept
    /// only when its whole stored payload is below half the raw length.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown predecessor,
    /// [`StoreError::Limit`] and [`StoreError::Capacity`] for admission,
    /// [`StoreError::Invalid`] for a length mismatch, and quarantine.
    pub fn prepare(
        &self,
        kind: ObjectKind,
        decoded_len: u64,
        input: impl Read,
        predecessor: Option<Oid>,
    ) -> Result<PreparedObject, StoreError> {
        self.refuse_if_quarantined()?;
        let base = match predecessor {
            Some(oid) => Some((oid, self.read(oid)?)),
            None => None,
        };
        prepare::prepare_object(
            self.format.kind,
            kind,
            decoded_len,
            input,
            base.as_ref().map(|(oid, read)| (*oid, read)),
            &self.budget,
            &self.root,
            &self.pin,
        )
    }

    /// Reads one object: verified frames, decoded delta chain, recomputed
    /// identity. No metadata transaction spans payload I/O.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unpublished id; [`StoreError::Corrupt`]
    /// for any damage, which also latches quarantine.
    pub fn read(&self, oid: Oid) -> Result<ReadObject, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.metadata_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.observe(self.committed().read(oid));
        if let Ok(object) = &result {
            self.io.object_reads.fetch_add(1, Ordering::Relaxed);
            self.io
                .object_decoded_bytes
                .fetch_add(object.bytes.len(), Ordering::Relaxed);
        }
        result
    }

    /// The committed decoded length of `oid`, or `None` when it was never
    /// published. No payload I/O.
    ///
    /// # Errors
    /// [`StoreError::ObjectFormat`] for a digest of the wrong width;
    /// [`StoreError::Corrupt`] for storage damage, which also latches
    /// quarantine; quarantine refuses.
    pub fn object_len(&self, oid: Oid) -> Result<Option<u64>, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.locator_lookups.fetch_add(1, Ordering::Relaxed);
        self.committed().check_width(oid)?;
        self.observe(
            self.meta
                .get_object(&oid)
                .map(|location| location.map(|location| location.decoded_len)),
        )
    }
    /// Every committed object: identity, kind, and decoded length, in
    /// raw-digest order. The object census behind `cat-file
    /// --batch-all-objects --batch-check` and unreachable-object sweeps:
    /// kinds and lengths come straight from the locator rows, so the scan
    /// does no payload I/O. Each page is its own read transaction; the
    /// returned snapshot is not transactional with later reads.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for storage damage, which also latches
    /// quarantine; quarantine refuses.
    pub fn iter_objects(&self) -> Result<Vec<(Oid, ObjectKind, u64)>, StoreError> {
        self.refuse_if_quarantined()?;
        let mut out = Vec::new();
        let mut after: Option<Oid> = None;
        loop {
            let page = self.observe(self.meta.object_page(after.as_ref(), 1024))?;
            if page.is_empty() {
                return Ok(out);
            }
            after = page.last().map(|(oid, _)| *oid);
            out.extend(
                page.into_iter()
                    .map(|(oid, location)| (oid, location.kind, location.decoded_len)),
            );
        }
    }

    /// Decodes a prepared, not yet committed object and verifies its
    /// identity, the same proof publication and readers get later. A delta
    /// decodes over its committed base.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for a delta whose base is not committed;
    /// [`StoreError::Corrupt`] when the payload does not round-trip to the
    /// object identity; preparation budget limits and quarantine.
    pub(crate) fn decode_prepared(&self, object: &PreparedObject) -> Result<Spool, StoreError> {
        self.refuse_if_quarantined()?;
        let base = match (object.encoding(), object.base()) {
            (Encoding::Delta, Some(base)) => Some((base, self.read(base)?.bytes)),
            _ => None,
        };
        prepare::decode_record(
            self.format.kind,
            object.kind(),
            &object.oid(),
            object.encoding(),
            object.payload.view(),
            object.payload.len(),
            object.decoded_len(),
            base.as_ref().map(|(oid, spool)| (*oid, spool.view())),
            &self.budget,
            &self.root,
            &self.pin,
        )
    }

    /// A snapshot of the I/O work counters. Relaxed ordering: these numbers
    /// are diagnostics and never publish or gate anything, so no acquire
    /// ordering is needed.
    #[must_use]
    pub fn io_stats(&self) -> IoStats {
        IoStats {
            object_reads: self.io.object_reads.load(Ordering::Relaxed),
            object_decoded_bytes: self.io.object_decoded_bytes.load(Ordering::Relaxed),
            locator_lookups: self.io.locator_lookups.load(Ordering::Relaxed),
            fact_lookups: self.io.fact_lookups.load(Ordering::Relaxed),
            fact_rows: self.io.fact_rows.load(Ordering::Relaxed),
            fact_page_calls: self.io.fact_page_calls.load(Ordering::Relaxed),
            metadata_calls: self.io.metadata_calls.load(Ordering::Relaxed),
            publications: self.io.publications.load(Ordering::Relaxed),
            publication_commits: self.io.publication_commits.load(Ordering::Relaxed),
            segment_syncs: self.io.segment_syncs.load(Ordering::Relaxed),
            pending_commits: self.io.pending_commits.load(Ordering::Relaxed),
            directory_syncs: self.io.directory_syncs.load(Ordering::Relaxed),
        }
    }
    /// A bounded page of raw fact rows strictly after `after` in key order.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for zero rows or bytes in `budget`;
    /// [`StoreError::Limit`] if the first row alone exceeds the byte budget;
    /// [`StoreError::Corrupt`] for storage damage, which also latches quarantine;
    /// quarantine refuses.
    pub fn fact_page(
        &self,
        table: FactTable,
        after: Option<&[u8]>,
        budget: FactPageBudget,
    ) -> Result<FactPage, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.fact_page_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.observe(self.meta.fact_page(table, after, budget));
        if let Ok(page) = &result {
            self.io
                .fact_rows
                .fetch_add(page.rows.len() as u64, Ordering::Relaxed);
        }
        result
    }

    /// A bounded page of raw fact rows under `prefix`, seeking inclusively
    /// at the prefix when `after` is absent and exclusively after `after`
    /// otherwise. Stops at the first key outside `prefix`.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for zero rows or bytes in `budget`;
    /// [`StoreError::Limit`] if the first row alone exceeds the byte budget;
    /// [`StoreError::Corrupt`] for storage damage, which also latches quarantine;
    /// quarantine refuses.
    pub fn fact_page_prefixed(
        &self,
        table: FactTable,
        after: Option<&[u8]>,
        prefix: &[u8],
        budget: FactPageBudget,
    ) -> Result<FactPage, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.fact_page_calls.fetch_add(1, Ordering::Relaxed);
        let result = self.observe(self.meta.fact_page_prefixed(table, after, prefix, budget));
        if let Ok(page) = &result {
            self.io
                .fact_rows
                .fetch_add(page.rows.len() as u64, Ordering::Relaxed);
        }
        result
    }

    /// Reads one fact value.
    ///
    /// # Errors
    /// Database failures propagate; [`StoreError::Corrupt`] for damage, which
    /// also latches quarantine; quarantine refuses.
    pub fn fact(&self, table: FactTable, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.refuse_if_quarantined()?;
        self.io.fact_lookups.fetch_add(1, Ordering::Relaxed);
        let result = self.observe(self.meta.fact(table, key));
        if let Ok(Some(_)) = &result {
            self.io.fact_rows.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Publishes prepared objects and conditional fact mutations atomically.
    ///
    /// Duplicates of committed objects are accepted when kind and length
    /// agree, keep their original immutable bytes, and still appear in
    /// [`Publication::objects`]. An empty object list publishes facts only;
    /// the generation advances only when new locators publish.
    ///
    /// # Errors
    /// The phase of the failure decides the effect, not its error kind.
    ///
    /// Before the first byte is appended (fact verification and object
    /// planning) a failure leaves the store and the writer untouched. That
    /// covers [`StoreError::StaleFact`], [`StoreError::Invalid`],
    /// [`StoreError::ObjectFormat`], [`StoreError::Capacity`] and a failed
    /// read of committed metadata. [`StoreError::Corrupt`] from such a read
    /// is committed corruption: it latches quarantine, and every later call
    /// on this store refuses.
    ///
    /// From the first append on, any failure, including
    /// [`StoreError::Capacity`] from segment allocation, closes the writer
    /// for this session ([`StoreError::WriterClosed`] on the next call) and
    /// leaves recovery to decide; a failed commit is never rolled back. A
    /// payload checksum mismatch while appending concerns staged bytes and
    /// latches nothing; corruption reported by the metadata reads and writes
    /// of the commit step latches quarantine as well.
    ///
    /// A quarantined store refuses before it reports a closed writer.
    ///
    /// Concurrent calls group: each publication waits in a queue, and the
    /// caller holding the writer commits the queue in as few transactions as
    /// the keys allow (see the `group` module). Every caller still receives
    /// the outcome its publication would have had alone.
    pub fn publish(
        &self,
        objects: Vec<PreparedObject>,
        facts: &[FactMutation],
        source: EventSource,
        context: &EventContext,
    ) -> Result<Publication, StoreError> {
        self.refuse_if_quarantined()?;
        if objects.is_empty() && facts.is_empty() {
            return Ok(Publication {
                objects: Vec::new(),
                generation: self.observe(self.meta.generation())?,
                ref_events: Vec::new(),
            });
        }
        let attribution = vec![(source, context.clone()); facts.len()];
        let outcome = self.publish_grouped(objects, facts, attribution);
        if outcome.is_ok() {
            self.io.publications.fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    /// Commits one publication with one source and per-fact contexts: the
    /// lane's multi-candidate batches attribute each fact to its own
    /// candidate. `contexts` aligns 1:1 with `facts`.
    pub(crate) fn publish_detailed(
        &self,
        objects: Vec<PreparedObject>,
        facts: &[FactMutation],
        source: EventSource,
        contexts: &[EventContext],
    ) -> Result<Publication, StoreError> {
        self.refuse_if_quarantined()?;
        if objects.is_empty() && facts.is_empty() {
            return Ok(Publication {
                objects: Vec::new(),
                generation: self.observe(self.meta.generation())?,
                ref_events: Vec::new(),
            });
        }
        if contexts.len() != facts.len() {
            return Err(StoreError::Invalid(
                "event attribution must align 1:1 with facts".to_owned(),
            ));
        }
        let attribution: Vec<(EventSource, EventContext)> = contexts
            .iter()
            .map(|context| (source, context.clone()))
            .collect();
        let outcome = self.publish_grouped(objects, facts, attribution);
        if outcome.is_ok() {
            self.io.publications.fetch_add(1, Ordering::Relaxed);
        }
        outcome
    }

    /// Largest events rows one retention sweep prunes per call. Sweeps run
    /// periodically, so a backlog drains over rounds instead of one giant
    /// transaction.
    pub(crate) const SWEEP_EVENTS_PAGE_ROWS: usize = 10_000;

    /// Builds the event rows plus head bump for one publication: one event
    /// per `FactTable::Refs` mutation, sequenced past the stored head, with
    /// `oldest` carried forward. Empty when the batch moves no refs. The
    /// writer lock is held, so sequences stay strictly increasing across
    /// lane and receive-pack publications.
    fn emit_ref_events(
        &self,
        facts: &[FactMutation],
        attribution: &[(EventSource, EventContext)],
    ) -> Result<(Vec<FactMutation>, Vec<RefEvent>), StoreError> {
        let mut ref_facts = Vec::new();
        for (fact, attr) in facts.iter().zip(attribution.iter()) {
            if fact.table == FactTable::Refs {
                ref_facts.push((fact, attr));
            }
        }
        if ref_facts.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let (mut head, oldest, head_raw) = self.read_event_head()?;
        let at = Self::unix_millis()?;
        let mut out = Vec::with_capacity(ref_facts.len() + 1);
        let mut ref_events = Vec::with_capacity(ref_facts.len());
        for (fact, (source, context)) in ref_facts {
            head = head
                .checked_add(1)
                .ok_or_else(|| StoreError::Capacity("event sequence exhausted".to_owned()))?;
            let event = StoreEvent {
                name: fact.key.clone(),
                old: match &fact.expected {
                    FactExpectation::Value(before) => Some(before.clone()),
                    _ => None,
                },
                new: fact.value.clone(),
                at,
                source: *source,
                operation: context.operation,
                request_id: context.request_id.clone(),
                session: context.session,
                on_behalf_of: context.on_behalf_of.clone(),
            };
            out.push(FactMutation {
                table: FactTable::Events,
                key: head.to_be_bytes().to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("event", &event)?),
            });
            ref_events.push(RefEvent {
                name: fact.key.clone(),
                seq: head,
            });
        }
        let row = EventHeadRow { head, oldest };
        out.push(FactMutation {
            table: FactTable::EventHead,
            key: EVENT_HEAD_KEY.to_vec(),
            expected: head_raw.map_or(FactExpectation::Absent, FactExpectation::Value),
            value: Some(encode("event head", &row)?),
        });
        Ok((out, ref_events))
    }

    /// The event horizon: the last assigned sequence and the oldest
    /// retained sequence. Absent rows mean no event ever committed.
    ///
    /// # Errors
    /// Database failures propagate; quarantine refuses.
    pub fn event_head(&self) -> Result<(u64, u64), StoreError> {
        let (head, oldest, _) = self.read_event_head()?;
        Ok((head, oldest))
    }

    /// Reads the repository metadata row written at init. Absent rows mean
    /// the store predates `repo.init` metadata and carries no default
    /// branch.
    ///
    /// # Errors
    /// Database failures propagate; quarantine refuses.
    pub fn repo_meta(&self) -> Result<Option<RepoMetaRow>, StoreError> {
        Ok(self.repo_meta_raw()?.map(|(row, _)| row))
    }

    /// Reads the repository metadata row with its exact stored bytes.
    /// Absent rows mean the store predates `repo.init` metadata.
    pub(crate) fn repo_meta_raw(&self) -> Result<Option<(RepoMetaRow, Vec<u8>)>, StoreError> {
        match self.fact(FactTable::RepoMeta, REPO_META_KEY)? {
            None => Ok(None),
            Some(raw) => decode_repo_meta(&raw).map(|row| Some((row, raw))),
        }
    }

    /// Persists the repository metadata row written once at init.
    ///
    /// Refuses when the row is already present: init runs once per store.
    ///
    /// # Errors
    /// Database failures propagate; quarantine refuses.
    pub fn write_repo_meta(&self, default_branch: RefName) -> Result<(), StoreError> {
        let row = RepoMetaRow {
            default_branch,
            land_requirements: Vec::new(),
            trusted_signers: Vec::new(),
            policy_generation: 0,
        };
        let bytes = metadata::encode("repo meta", &row)?;
        self.publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::RepoMeta,
                key: REPO_META_KEY.to_vec(),
                expected: FactExpectation::Absent,
                value: Some(bytes),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )?;
        Ok(())
    }

    /// The current locator generation of this store.
    ///
    /// # Errors
    /// Database failures propagate; quarantine refuses.
    pub fn generation(&self) -> Result<u64, StoreError> {
        self.refuse_if_quarantined()?;
        self.observe(self.meta.generation())
    }

    /// The default branch recorded at init, or `None` when the store
    /// predates `repo.init` metadata.
    ///
    /// # Errors
    /// Database failures propagate; quarantine refuses.
    pub fn default_branch(&self) -> Result<Option<RefName>, StoreError> {
        Ok(self.repo_meta()?.map(|row| row.default_branch))
    }

    /// Every committed segment manifest in id order.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for storage damage, which also latches
    /// quarantine; quarantine refuses.
    pub fn all_manifests(&self) -> Result<Vec<SegmentManifest>, StoreError> {
        self.refuse_if_quarantined()?;
        self.observe(self.meta.all_manifests())
    }

    /// Every committed object locator in raw-digest order.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for storage damage, which also latches
    /// quarantine; quarantine refuses.
    pub fn all_object_locations(&self) -> Result<Vec<(Oid, ObjectLocation)>, StoreError> {
        self.refuse_if_quarantined()?;
        let mut out = Vec::new();
        let mut after: Option<Oid> = None;
        loop {
            let page = self.observe(self.meta.object_page(after.as_ref(), 1024))?;
            if page.is_empty() {
                return Ok(out);
            }
            after = page.last().map(|(oid, _)| *oid);
            out.extend(page);
        }
    }

    /// Installs one photographed sealed snapshot into this fresh staging
    /// store: the hardlinked sealed-segment manifests plus their verbatim
    /// sealed locators, with the destination generation set to the forked
    /// source generation in both the metadata and the in-memory generation
    /// registry. The destination generation reaches the forked generation
    /// even when the sealed set is empty, so a tail-only fork still
    /// carries the source generation. Tail-resident objects are never
    /// installed here; the caller re-creates them by content copy
    /// afterwards, so the two sets must be disjoint and the call fails
    /// closed on any overlap. Each linked segment file is re-verified
    /// against its photographed committed extent before install. Runs
    /// before the destination's first open, so recovery validates the
    /// installed state like any committed store.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for an overlap between the sealed and tail
    /// sets, a locator generation above `generation`, an unsealed or
    /// retired manifest, a linked file shorter than its committed extent,
    /// or a generation that regresses the fresh store; database failures
    /// propagate; quarantine refuses.
    pub fn import_sealed_snapshot(
        &self,
        manifests: &[SegmentManifest],
        sealed: &[(Oid, ObjectLocation)],
        tail_oids: &[Oid],
        generation: u64,
    ) -> Result<(), StoreError> {
        self.refuse_if_quarantined()?;
        let mut staged: std::collections::HashSet<Oid> =
            std::collections::HashSet::with_capacity(sealed.len());
        for (oid, _) in sealed {
            if !staged.insert(*oid) {
                return Err(StoreError::Invalid(format!(
                    "sealed snapshot repeats object {oid}"
                )));
            }
        }
        for oid in tail_oids {
            if staged.contains(oid) {
                return Err(StoreError::Invalid(format!(
                    "fork snapshot overlaps sealed and tail on {oid}"
                )));
            }
        }
        let mut by_id: std::collections::HashMap<u64, &SegmentManifest> =
            std::collections::HashMap::with_capacity(manifests.len());
        for manifest in manifests {
            if !manifest.sealed {
                return Err(StoreError::Invalid(format!(
                    "fork snapshot links unsealed segment {}",
                    manifest.id
                )));
            }
            if manifest.retired {
                return Err(StoreError::Invalid(format!(
                    "fork snapshot links retired segment {}",
                    manifest.id
                )));
            }
            let path = self
                .root
                .join(SEGMENTS_DIR)
                .join(segment::segment_file_name(manifest.id));
            let len = std::fs::metadata(&path)
                .map(|meta| meta.len())
                .map_err(|err| {
                    StoreError::Invalid(format!(
                        "linked segment {} is not readable: {err}",
                        manifest.id
                    ))
                })?;
            if len < manifest.committed_end {
                return Err(StoreError::Invalid(format!(
                    "linked segment {} holds {len} bytes below its committed end {}",
                    manifest.id, manifest.committed_end
                )));
            }
            if by_id.insert(manifest.id, manifest).is_some() {
                return Err(StoreError::Invalid(format!(
                    "sealed snapshot repeats segment {}",
                    manifest.id
                )));
            }
        }
        for (oid, location) in sealed {
            if !by_id.contains_key(&location.segment) {
                return Err(StoreError::Invalid(format!(
                    "sealed object {oid} names unlinked segment {}",
                    location.segment
                )));
            }
            if location.generation > generation {
                return Err(StoreError::Invalid(format!(
                    "sealed object {oid} is newer than the forked generation {generation}"
                )));
            }
        }
        let current = self.observe(self.meta.generation())?;
        if generation < current {
            return Err(StoreError::Invalid(format!(
                "forked generation {generation} regresses past {current}"
            )));
        }
        let _writer = self.lock_writer()?;
        let txn = self.observe(self.meta.begin_publication(&[]))?;
        for (oid, location) in sealed {
            self.observe(txn.insert_object(oid, location))?;
        }
        for manifest in manifests {
            self.observe(txn.upsert_manifest(manifest))?;
        }
        if generation > current {
            self.observe(txn.set_generation(generation))?;
        }
        self.observe(txn.commit())?;
        drop(_writer);
        self.guards.advance_published_generation(generation);
        Ok(())
    }

    /// Registers one reader pin on this store for a fork photograph and
    /// copy: the pin registers before any snapshot read and releases on
    /// drop, so compaction cannot retire and unlink a linked sealed
    /// segment under the fork.
    #[must_use]
    pub fn pin_for_fork(&self) -> ForkPin {
        ForkPin {
            _guard: self.guards.register(),
        }
    }

    /// Reads the event horizon: the last assigned sequence, the oldest
    /// retained sequence, and the raw head row for CAS updates. Absent rows
    /// mean no event ever committed.
    fn read_event_head(&self) -> Result<(u64, u64, Option<Vec<u8>>), StoreError> {
        match self.fact(FactTable::EventHead, EVENT_HEAD_KEY)? {
            None => Ok((0, 1, None)),
            Some(raw) => {
                let row: EventHeadRow = decode("event head", &raw)?;
                Ok((row.head, row.oldest, Some(raw)))
            }
        }
    }

    /// Builds deletion facts pruning `Events` rows older than
    /// `cutoff_millis`, keeping the head row's `oldest` current. Reads at
    /// most one oldest-first page per call; later sweeps drain the rest.
    /// Empty when nothing is old enough.
    pub(crate) fn sweep_events_page(
        &self,
        cutoff_millis: u64,
        limit: usize,
    ) -> Result<Vec<FactMutation>, StoreError> {
        let page = self.fact_page(
            FactTable::Events,
            None,
            FactPageBudget::new(limit, usize::MAX),
        )?;
        if page.rows.is_empty() {
            return Ok(Vec::new());
        }
        let (head, oldest, head_raw) = self.read_event_head()?;
        let mut out = Vec::new();
        let mut kept: Option<u64> = None;
        for row in &page.rows {
            let event: StoreEvent = decode_store_event(&row.value)?;
            if event.at < cutoff_millis {
                out.push(FactMutation {
                    table: FactTable::Events,
                    key: row.key.clone(),
                    expected: FactExpectation::Value(row.value.clone()),
                    value: None,
                });
            } else if kept.is_none() {
                kept = Some(Self::seq_from_event_key(&row.key)?);
            }
        }
        if out.is_empty() {
            return Ok(Vec::new());
        }
        let new_oldest = match (kept, page.more) {
            (Some(seq), _) => oldest.max(seq),
            (None, false) => head.saturating_add(1),
            (None, true) => {
                // Every row in this page is pruned but more rows remain:
                // oldest must advance past the page's final deleted
                // sequence, or a cursor inside the hole would skip the
                // pruned rows without the expired signal.
                let last = page
                    .rows
                    .last()
                    .map(|row| Self::seq_from_event_key(&row.key))
                    .transpose()?
                    .unwrap_or(oldest);
                oldest.max(last.saturating_add(1))
            }
        };
        if new_oldest != oldest || head_raw.is_none() {
            let row = EventHeadRow {
                head,
                oldest: new_oldest,
            };
            out.push(FactMutation {
                table: FactTable::EventHead,
                key: EVENT_HEAD_KEY.to_vec(),
                expected: head_raw.map_or(FactExpectation::Absent, FactExpectation::Value),
                value: Some(encode("event head", &row)?),
            });
        }
        Ok(out)
    }

    /// Decodes one big-endian event sequence key.
    ///
    /// # Errors
    /// `Invalid` for a short key.
    fn seq_from_event_key(key: &[u8]) -> Result<u64, StoreError> {
        let bytes: [u8; 8] = key
            .try_into()
            .map_err(|_| StoreError::Invalid("event key is not an 8-byte sequence".to_owned()))?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Unix millis of the system clock, for event timestamps.
    ///
    /// # Errors
    /// `E_IO` when the clock predates the epoch.
    fn unix_millis() -> Result<u64, StoreError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Io(std::io::Error::other("clock predates the epoch")))?;
        u64::try_from(elapsed.as_millis())
            .map_err(|_| StoreError::Io(std::io::Error::other("clock millis overflow u64")))
    }

    /// Commits one publication with the writer held: the probe, the pending
    /// reservation, the real transaction, the ref events, then append and
    /// commit. Ref events and the head bump join the real transaction, so a
    /// batch and its events commit atomically under the writer lock.
    fn publish_locked(
        &self,
        writer: &mut WriterState,
        objects: &[&PreparedObject],
        facts: &[FactMutation],
        attribution: &[(EventSource, EventContext)],
    ) -> Result<Publication, StoreError> {
        // A read may have latched quarantine while this call waited for the
        // writer; nothing commits on a store already known to be corrupt.
        self.refuse_if_quarantined()?;
        if let Some(reason) = &writer.closed {
            return Err(StoreError::WriterClosed(reason.clone()));
        }
        let profile = profile_enabled();
        // Probe first: the pending row must commit before the first
        // reservation call, but redb holds a single writer, so the real
        // publication transaction opens only after the pending commit. The
        // probe validates facts and objects and is aborted without
        // committing; the writer lock held throughout keeps the
        // re-validation below identical.
        let staged = (|| {
            let probe_txn = self.observe(self.meta.begin_publication(facts))?;
            let probe_plan = self.observe(self.plan(&probe_txn, objects))?;
            drop(probe_txn);
            let pending = self.persist_pending(&probe_plan)?;
            let txn = self.observe(self.meta.begin_publication(facts))?;
            let (event_facts, ref_events) =
                self.observe(self.emit_ref_events(facts, attribution))?;
            self.observe(txn.apply_more(&event_facts))?;
            let plan = self.observe(self.plan(&txn, objects))?;
            Ok::<_, StoreError>((pending, txn, plan, ref_events))
        })();
        let (pending, txn, plan, ref_events) = match staged {
            Ok(prepared) => prepared,
            Err(err) => {
                // Committed corruption met before the first append still
                // ends this session's publications: the bytes the writer
                // may hold queued against now-known-bad state cannot run.
                if self.quarantine() {
                    writer.closed = Some(format!(
                        "publication observed committed corruption before writing; reopen the store to run recovery ({err})"
                    ));
                }
                return Err(err);
            }
        };
        let begin_start = ProfileClock::now(profile);
        let begin_ms = begin_start.elapsed_ms();
        let plan_start = ProfileClock::now(profile);
        let plan_ms = plan_start.elapsed_ms();
        if let Some(handle) = &pending
            && handle.row.generation != plan.generation
        {
            // Unreachable while the writer lock is held; fail closed and
            // release the row rather than stranding it until the next open.
            let released = PendingReservation {
                state: ReservationState::Released,
                ..handle.row.clone()
            };
            let _ = self.meta.release_pending(&[(handle.key.clone(), released)]);
            return Err(StoreError::Invalid(
                "publication generation moved under the writer lock".to_owned(),
            ));
        }
        if profile {
            eprintln!(
                "[ruk-profile] publish begin={begin_ms:.1}ms plan={plan_ms:.1}ms objects={} fresh={}",
                objects.len(),
                plan.fresh.len(),
            );
        }
        match self.write_and_commit(writer, txn, plan, profile, pending) {
            Ok(mut publication) => {
                publication.ref_events = ref_events;
                Ok(publication)
            }
            Err(err) => {
                writer.closed = Some(format!(
                    "publication failed after durable work began; reopen the store to run recovery ({err})"
                ));
                Err(err)
            }
        }
    }

    /// Validates every object against this store before any byte is
    /// appended.
    fn plan<'a>(
        &self,
        txn: &PublicationTxn,
        objects: &[&'a PreparedObject],
    ) -> Result<Plan<'a>, StoreError> {
        let mut order = Vec::with_capacity(objects.len());
        let mut fresh = Vec::new();
        let mut seen: HashMap<Oid, (ObjectKind, u64)> = HashMap::with_capacity(objects.len());
        for &object in objects {
            let oid = object.oid();
            self.check_prepared(object)?;
            order.push(oid);
            if let Some(&identity) = seen.get(&oid) {
                ensure_same_identity(oid, identity, object)?;
                continue;
            }
            seen.insert(oid, (object.kind(), object.decoded_len()));
            let Some(existing) = txn.get_object(&oid)? else {
                self.check_delta_base(txn, object)?;
                segment::record_len_for(object.payload.len())?;
                fresh.push(object);
                continue;
            };
            ensure_same_identity(oid, (existing.kind, existing.decoded_len), object)?;
        }
        let current = self.meta.generation()?;
        let generation = if fresh.is_empty() {
            current
        } else {
            current
                .checked_add(1)
                .ok_or_else(|| StoreError::Capacity("locator generation exhausted".to_owned()))?
        };
        Ok(Plan {
            order,
            fresh,
            generation,
        })
    }

    /// Rejects a prepared object that cannot belong to this store: wrong
    /// hash width, or encoding, base and depth that disagree.
    fn check_prepared(&self, object: &PreparedObject) -> Result<(), StoreError> {
        let oid = object.oid();
        if oid.kind() != self.format.kind {
            return Err(StoreError::ObjectFormat(format!(
                "prepared object {oid} is not a {} digest",
                self.format.kind
            )));
        }
        let (delta, base) = (object.encoding() == Encoding::Delta, object.base());
        let Some(base) = base.filter(|_| delta) else {
            if delta || object.base().is_some() || object.depth() != 0 {
                return Err(StoreError::Invalid(format!(
                    "prepared object {oid} has an inconsistent encoding, base or depth"
                )));
            }
            return Ok(());
        };
        if base.kind() != self.format.kind {
            return Err(StoreError::ObjectFormat(format!(
                "delta base {base} of {oid} is not a {} digest",
                self.format.kind
            )));
        }
        if object.depth() == 0 || object.depth() > MAX_DELTA_DEPTH {
            return Err(StoreError::Invalid(format!(
                "delta object {oid} has chain depth {} outside 1..={MAX_DELTA_DEPTH}",
                object.depth()
            )));
        }
        Ok(())
    }

    /// A delta base must already be committed in this store, with the same
    /// kind and one level shallower than the delta. A prepared object moved
    /// from another store, or one naming a same-batch base, fails here.
    fn check_delta_base(
        &self,
        txn: &PublicationTxn,
        object: &PreparedObject,
    ) -> Result<(), StoreError> {
        let Some(base) = object.base() else {
            return Ok(());
        };
        let oid = object.oid();
        let committed = txn.get_object(&base)?.ok_or_else(|| {
            StoreError::Invalid(format!(
                "delta base {base} of {oid} is not committed in this store"
            ))
        })?;
        if committed.kind != object.kind() {
            return Err(StoreError::Invalid(format!(
                "delta base {base} has kind {:?} but {oid} has kind {:?}",
                committed.kind,
                object.kind()
            )));
        }
        if committed.depth.checked_add(1) != Some(object.depth()) {
            return Err(StoreError::Invalid(format!(
                "delta {oid} claims depth {} over base {base} at depth {}",
                object.depth(),
                committed.depth
            )));
        }
        Ok(())
    }
}

/// Decodes one repository metadata row, accepting the pre-policy shape.
/// Rows written before `policy.set` existed read back with an empty
/// landing policy at generation zero.
fn decode_repo_meta(bytes: &[u8]) -> Result<RepoMetaRow, StoreError> {
    if let Ok(row) = decode::<RepoMetaRow>("repo meta", bytes) {
        return Ok(row);
    }
    let old: RepoMetaRowV0 = decode("repo meta", bytes)
        .map_err(|_| StoreError::Corrupt("repo meta: malformed row".to_owned()))?;
    Ok(RepoMetaRow {
        default_branch: old.default_branch,
        land_requirements: Vec::new(),
        trusted_signers: Vec::new(),
        policy_generation: 0,
    })
}

/// A committed duplicate is compatible when kind and decoded length agree.
fn ensure_same_identity(
    oid: Oid,
    (kind, decoded_len): (ObjectKind, u64),
    object: &PreparedObject,
) -> Result<(), StoreError> {
    if kind == object.kind() && decoded_len == object.decoded_len() {
        return Ok(());
    }
    Err(StoreError::Invalid(format!(
        "object {oid} is already known as {kind:?} of {decoded_len} bytes, not {:?} of {}",
        object.kind(),
        object.decoded_len()
    )))
}

impl Store {
    /// Appends, flushes, publishes entries, and commits. The transaction
    /// holds every fact mutation already applied and is committed last.
    ///
    /// Only the metadata steps are observed: they read committed rows, so
    /// corruption they report is committed corruption. The appending and
    /// flushing steps handle staged bytes, where a payload checksum
    /// mismatch is not committed corruption and must not latch quarantine;
    /// the caller closes the writer for either.
    /// Checks the probe plan against the capacity quotas and commits the
    /// pending row with Immediate durability. Returns `None` for
    /// publications that append nothing. A quota refusal is
    /// [`StoreError::Limit`] before the first mutation, so the writer stays
    /// open; anything later closes it and the row reconciles at next open.
    fn persist_pending(&self, plan: &Plan<'_>) -> Result<Option<PendingHandle>, StoreError> {
        if plan.fresh.is_empty() {
            return Ok(None);
        }
        let mut estimate = 0u64;
        for object in &plan.fresh {
            let record_len = segment::record_len_for(object.payload.len())?;
            estimate = estimate.checked_add(record_len).ok_or_else(|| {
                StoreError::Capacity("publication byte estimate overflows u64".to_owned())
            })?;
        }
        let rows = self.observe(self.meta.pending_rows())?;
        let mut committed_held = 0u64;
        for manifest in self.observe(self.meta.all_manifests())? {
            if manifest.retired {
                continue;
            }
            committed_held = committed_held
                .checked_add(manifest.committed_end)
                .ok_or_else(|| {
                    StoreError::Capacity("committed byte accounting overflows u64".to_owned())
                })?;
        }
        capacity::admit(
            capacity::pending_held(&rows),
            committed_held,
            estimate,
            &self.capacity_limits(),
        )?;
        let seq = capacity::next_seq(&rows, plan.generation);
        let key = PendingReservation::key(plan.generation, seq);
        let row = PendingReservation {
            generation: plan.generation,
            seq,
            estimated_bytes: estimate,
            state: ReservationState::Pending,
            charges: Vec::new(),
        };
        self.observe(self.meta.commit_pending(&key, &row))?;
        self.io.pending_commits.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        crash_tests::crash_at("capacity_pending_persisted");
        Ok(Some(PendingHandle { key, row }))
    }

    fn write_and_commit(
        &self,
        writer: &mut WriterState,
        txn: PublicationTxn,
        plan: Plan<'_>,
        profile: bool,
        pending: Option<PendingHandle>,
    ) -> Result<Publication, StoreError> {
        let Plan {
            order,
            fresh,
            generation,
        } = plan;
        let mut batch = Batch::default();
        let total_start = ProfileClock::now(profile);
        let append_start = ProfileClock::now(profile);
        let mut append_bytes = 0u64;
        let mut probe = if profile {
            AppendProbe::live()
        } else {
            AppendProbe::idle()
        };
        for object in &fresh {
            append(
                writer, &mut batch, &self.pin, object, generation, &mut probe,
            )?;
            if profile {
                append_bytes += segment::record_len_for(object.payload.len()).unwrap_or(0);
            }
        }
        // Staged record bytes reach the stream here, in one write per
        // segment: the `after_append` hook promises the last record byte
        // (and any seal footer the batch wrote) is on the file, and the
        // fsync below must cover every staged byte. Seal already flushed
        // the parked segments; only the active one can hold staging.
        if let Some(active) = writer.active.as_mut() {
            active.writer.flush_staged()?;
        }
        let append_ms = append_start.elapsed_ms();
        #[cfg(test)]
        crash_tests::crash_at("after_append");

        let sync_start = ProfileClock::now(profile);
        let synced = batch.sync_files(writer)?;
        self.io.segment_syncs.fetch_add(synced, Ordering::Relaxed);
        let sync_files_ms = sync_start.elapsed_ms();
        #[cfg(test)]
        crash_tests::crash_at("after_segment_sync");

        let dir_start = ProfileClock::now(profile);
        if batch.new_entries {
            self.pin.sync_segments_dir().map_err(StoreError::from)?;
            self.io.directory_syncs.fetch_add(1, Ordering::Relaxed);
        }
        let sync_dir_ms = dir_start.elapsed_ms();
        #[cfg(test)]
        crash_tests::crash_at("after_directory_sync");

        let stage_start = ProfileClock::now(profile);
        self.observe(batch.stage(
            &txn,
            writer,
            generation,
            !fresh.is_empty(),
            pending.as_ref(),
        ))?;
        let stage_ms = stage_start.elapsed_ms();
        let commit_start = ProfileClock::now(profile);
        self.observe(txn.commit())?;
        self.io.publication_commits.fetch_add(1, Ordering::Relaxed);
        let commit_ms = commit_start.elapsed_ms();
        if profile {
            eprintln!(
                "[ruk-profile] write_and_commit fresh={} append={append_ms:.1}ms append_bytes={append_bytes} loop_pick={:.1}ms loop_write={:.1}ms loop_book={:.1}ms sync_files={sync_files_ms:.1}ms sync_dir={sync_dir_ms:.1}ms stage={stage_ms:.1}ms commit={commit_ms:.1}ms total={:.1}ms",
                fresh.len(),
                probe.pick_ms,
                probe.write_ms,
                probe.book_ms,
                total_start.elapsed_ms(),
            );
        }
        #[cfg(test)]
        crash_tests::crash_at("after_metadata_commit");

        self.guards.advance_published_generation(generation);

        #[cfg(test)]
        crash_tests::crash_at("before_ack");
        Ok(Publication {
            objects: order,
            generation,
            ref_events: Vec::new(),
        })
    }
}

impl Batch {
    /// Records the generation, every new locator, and the final manifest of
    /// every touched segment in the publication transaction, and settles
    /// the pending row: `Committed` with the observed charges, proving the
    /// persistence-before-reservation order in the same commit that makes
    /// the bytes visible.
    fn stage(
        &self,
        txn: &PublicationTxn,
        writer: &WriterState,
        generation: u64,
        advance_generation: bool,
        pending: Option<&PendingHandle>,
    ) -> Result<(), StoreError> {
        if advance_generation {
            txn.set_generation(generation)?;
        }
        for (oid, location) in &self.locations {
            txn.insert_object(oid, location)?;
        }
        for manifest in self.manifests(writer, generation) {
            txn.upsert_manifest(&manifest)?;
        }
        match pending {
            Some(handle) => {
                if handle.row.generation != generation {
                    return Err(StoreError::Invalid(
                        "pending reservation names a different generation".to_owned(),
                    ));
                }
                txn.replace_pending(
                    &handle.key,
                    &PendingReservation {
                        generation: handle.row.generation,
                        seq: handle.row.seq,
                        estimated_bytes: handle.row.estimated_bytes,
                        state: ReservationState::Committed,
                        charges: self.charges.clone(),
                    },
                )?;
            }
            None if !self.charges.is_empty() => {
                return Err(StoreError::Invalid(
                    "segment charges without a pending reservation".to_owned(),
                ));
            }
            None => {}
        }
        Ok(())
    }

    /// Flushes every segment this publication touched.
    fn sync_files(&self, writer: &WriterState) -> Result<u64, StoreError> {
        let mut synced = 0;
        for segment in &self.sealed {
            durability::sync_file(segment.writer.get_ref())?;
            synced += 1;
        }
        match writer.active.as_ref() {
            Some(active) if self.active_touched => {
                durability::sync_file(active.writer.get_ref())?;
                synced += 1;
            }
            _ => {}
        }
        Ok(synced)
    }

    /// The final manifest rows of every touched segment.
    fn manifests(&self, writer: &WriterState, generation: u64) -> Vec<SegmentManifest> {
        let active = writer
            .active
            .as_ref()
            .filter(|_| self.active_touched)
            .into_iter();
        self.sealed
            .iter()
            .chain(active)
            .map(|segment| SegmentManifest {
                id: segment.id,
                committed_end: segment.writer.committed_end(),
                records_end: segment.writer.records_end(),
                sealed: segment.writer.is_sealed(),
                retired: false,
                generation,
            })
            .collect()
    }
}

/// Per-phase accumulators for the append loop, reported on the
/// `RUK_PROFILE=1` line. `pick` covers segment selection (and the rare
/// open/roll), `write` the [`segment::SegmentWriter::append`] call
/// (framing, payload CRC, staging), and `book` the locator push and the
/// oversized check. Clocks only run when profiling; disabled probes cost
/// three dead branches per record.
#[derive(Default)]
struct AppendProbe {
    enabled: bool,
    pick_ms: f64,
    write_ms: f64,
    book_ms: f64,
}

impl AppendProbe {
    fn live() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    fn idle() -> Self {
        Self::default()
    }

    fn clock(&self) -> ProfileClock {
        ProfileClock::now(self.enabled)
    }
}

/// Appends one prepared object to the active segment, rolling to a new
/// segment first when it does not fit, and sealing a dedicated segment
/// when a single record exceeds the target.
fn append(
    writer: &mut WriterState,
    batch: &mut Batch,
    pin: &PinnedRoot,
    object: &PreparedObject,
    generation: u64,
    probe: &mut AppendProbe,
) -> Result<(), StoreError> {
    let payload_len = object.payload.len();
    let record_len = segment::record_len_for(payload_len)?;
    let pick_start = probe.clock();
    let active = active_segment(writer, batch, pin, record_len)?;
    probe.pick_ms += pick_start.elapsed_ms();
    // Pre-publication reservation of exactly the range about to be
    // appended, on the still-open segment file. The receipt carries the
    // post-operation re-query; the charge joins the batch for the stage
    // step. A refusal fails the publication closed here, before the bytes.
    let reserve_offset = active.writer.records_end();
    let reservation =
        PhysicalReservation::reserve(active.writer.get_ref(), reserve_offset, record_len)
            .map_err(map_allocation_error)?;
    let receipt = reservation.receipt();
    batch.charges.push(SegmentCharge {
        segment: active.id,
        offset: reserve_offset,
        len: record_len,
        allocated_bytes: receipt.allocated_bytes,
        logical_len: receipt.logical_len,
    });
    let write_start = probe.clock();
    // Resident payloads skip the streaming path's per-record combine and
    // scratch bounce: the slice path stages the same bytes with hardware
    // checksum passes. File-backed payloads keep the streaming path and
    // its re-verification against the prepared checksum.
    let appended = match object.payload.memory_bytes() {
        Some(bytes) => active.writer.append_slice(
            object.kind(),
            object.encoding(),
            bytes,
            object.payload_crc,
        )?,
        None => active.writer.append(
            object.kind(),
            object.encoding(),
            payload_len,
            object.payload_crc,
            object.payload.view(),
        )?,
    };
    probe.write_ms += write_start.elapsed_ms();
    let book_start = probe.clock();
    let segment = active.id;
    let oversized = active.writer.records_end() > writer.target_bytes();
    batch.active_touched = true;
    batch.locations.push((
        object.oid(),
        ObjectLocation {
            kind: object.kind(),
            decoded_len: object.decoded_len(),
            segment,
            offset: appended.offset,
            record_len: appended.record_len,
            generation,
            base: object.base(),
            depth: object.depth(),
        },
    ));
    if oversized {
        seal_active(writer, batch)?;
    }
    probe.book_ms += book_start.elapsed_ms();
    Ok(())
}

/// The segment the next record goes to: the recovered or current open
/// segment, a fresh one when none is open, or a rolled one when the record
/// would overflow a non-empty segment.
fn active_segment<'w>(
    writer: &'w mut WriterState,
    batch: &mut Batch,
    pin: &PinnedRoot,
    record_len: u64,
) -> Result<&'w mut ActiveSegment, StoreError> {
    if writer.active.is_none() {
        let opened = open_segment(writer, batch, pin)?;
        writer.active = Some(opened);
    }
    let target = writer.target_bytes();
    let overflows = writer.active.as_ref().is_some_and(|active| {
        active.writer.records_end() > 0 && !active.writer.fits_sized(record_len, target)
    });
    if overflows {
        seal_active(writer, batch)?;
        let opened = open_segment(writer, batch, pin)?;
        writer.active = Some(opened);
    }
    writer
        .active
        .as_mut()
        .ok_or_else(|| StoreError::WriterClosed("no open segment after allocation".to_owned()))
}

/// Seals the active segment's footer and parks it until the batch flushes.
fn seal_active(writer: &mut WriterState, batch: &mut Batch) -> Result<(), StoreError> {
    let Some(mut active) = writer.active.take() else {
        return Ok(());
    };
    // Pre-reserve the 24-byte seal footer at the current records end before
    // it is written, so the seal itself cannot hit a late allocation.
    let footer_offset = active.writer.records_end();
    let footer_len = spool::to_u64(segment::FOOTER_LEN);
    let reservation =
        PhysicalReservation::reserve(active.writer.get_ref(), footer_offset, footer_len)
            .map_err(map_allocation_error)?;
    let receipt = reservation.receipt();
    batch.charges.push(SegmentCharge {
        segment: active.id,
        offset: footer_offset,
        len: footer_len,
        allocated_bytes: receipt.allocated_bytes,
        logical_len: receipt.logical_len,
    });
    active.writer.seal()?;
    batch.sealed.push(active);
    Ok(())
}

/// Maps a platform reservation refusal onto the store's typed errors. `Io`
/// (including `ENOSPC`) stays I/O; a filesystem that cannot honour the
/// strict contract fails closed as invalid input to this publication.
fn map_allocation_error(err: PhysicalAllocationError) -> StoreError {
    match err {
        PhysicalAllocationError::Io(inner) => StoreError::Io(inner),
        PhysicalAllocationError::Overflow => {
            StoreError::Invalid("reservation range overflows u64".to_owned())
        }
        PhysicalAllocationError::NotRegularFile => {
            StoreError::Invalid("segment handle is not a regular file".to_owned())
        }
        PhysicalAllocationError::Unsupported | PhysicalAllocationError::UnverifiedFilesystem => {
            StoreError::Invalid(
                "strict platform reservation refused: segment filesystem fails the pre-publication contract".to_owned(),
            )
        }
    }
}

/// Reopens the recovered open segment once, otherwise creates the next
/// segment exclusively. Existing files are never overwritten or unlinked:
/// the id advances past each unknown name, and exhausting the id space is
/// a capacity error.
fn open_segment(
    writer: &mut WriterState,
    batch: &mut Batch,
    pin: &PinnedRoot,
) -> Result<ActiveSegment, StoreError> {
    if let Some(resume) = writer.resume.take() {
        let file = pin
            .open_read_write(&segment_rel(resume.id))
            .map_err(StoreError::from)?;
        return Ok(ActiveSegment {
            id: resume.id,
            writer: SegmentWriter::resumed(file, resume.records_end, resume.records_crc)?,
        });
    }
    loop {
        let id = writer.next_segment_id;
        let next = id
            .checked_add(1)
            .ok_or_else(|| StoreError::Capacity("segment id space exhausted".to_owned()))?;
        match pin.create_new(&segment_rel(id)) {
            Ok(file) => {
                writer.next_segment_id = next;
                batch.new_entries = true;
                return Ok(ActiveSegment {
                    id,
                    writer: SegmentWriter::fresh(file)?,
                });
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                writer.next_segment_id = next;
            }
            Err(err) => return Err(StoreError::from(err)),
        }
    }
}

/// Coarse publish-stage timing for the clone-probe floor hunt. `RUK_PROFILE=1`
/// prints one stderr line per publication stage; any other value (or unset)
/// compiles to a dead clock with zero behavior change. Stderr, not tracing:
/// `ruk-core` has no tracing dependency and the probe reads raw stderr.
fn profile_enabled() -> bool {
    std::env::var_os("RUK_PROFILE").is_some_and(|value| value == "1")
}

/// A clock that only runs when profiling. `elapsed_ms` on a disabled clock
/// returns 0.0 without touching the system clock.
struct ProfileClock {
    start: Option<std::time::Instant>,
}

impl ProfileClock {
    fn now(enabled: bool) -> Self {
        Self {
            start: enabled.then(std::time::Instant::now),
        }
    }

    fn elapsed_ms(&self) -> f64 {
        self.start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    }
}

/// Publishes directory entries created by `create_file_published`. POSIX
/// flushes the directory; Windows published every entry when it was
/// created, so there is nothing left to flush.
#[cfg(unix)]
fn sync_entries(dir: &Path) -> Result<(), StoreError> {
    durability::sync_dir(dir)
}

#[cfg(not(unix))]
fn sync_entries(_dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Creates the store root. POSIX creates missing ancestors and flushes the
/// existing chain, and accepts an existing directory.
#[cfg(unix)]
fn create_root(root: &Path) -> Result<(), StoreError> {
    durability::create_dir_all_synced(root)
}

/// Creates the store root. Windows requires an existing, durable parent and
/// an absent root; see [`Store::create`].
#[cfg(not(unix))]
fn create_root(root: &Path) -> Result<(), StoreError> {
    create_owned_dir(root)
}

/// Creates one directory that this call must own. Any existing name, such as
/// a directory a racing creator just made visible, is refused instead of
/// adopted.
fn create_owned_dir(path: &Path) -> Result<(), StoreError> {
    match durability::create_dir_published(path) {
        Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
            Err(StoreError::Invalid(format!(
                "{} already exists; refusing to adopt it",
                path.display()
            )))
        }
        result => result,
    }
}

/// Fails unless `path` does not exist, without following symlinks.
fn require_absent(path: &Path) -> Result<(), StoreError> {
    match path.symlink_metadata() {
        Ok(_) => Err(StoreError::Invalid(format!(
            "{} already exists; refusing to overwrite a store",
            path.display()
        ))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Reads and parses the bounded format file, returning the handle it was
/// read through. The handle can write because flushing a file needs a
/// write-capable handle on Windows; it is never written.
pub(crate) fn read_format(root: &Path) -> Result<(StoreFormat, File), StoreError> {
    read_format_file(&root.join(FORMAT_FILE))
}

fn read_format_file(path: &Path) -> Result<(StoreFormat, File), StoreError> {
    let mut file = match durability::open_existing(path) {
        Ok(file) => file,
        Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound(format!(
                "no store format file under {}",
                path.display()
            )));
        }
        Err(err) => return Err(err),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_FORMAT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if !u64::try_from(bytes.len()).is_ok_and(|len| len <= MAX_FORMAT_BYTES) {
        return Err(StoreError::Version(
            "format file is longer than any known format".to_owned(),
        ));
    }
    Ok((StoreFormat::from_bytes(&bytes)?, file))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::metadata_tests::{raw_bump_generation, raw_put_object, raw_put_segment};
    use super::*;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// A unique temporary directory removed on drop. The directory exists
    /// from the start: it is the store root's parent, which Windows creation
    /// requires the caller to provide.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-store-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create the test parent directory");
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

    fn budget() -> Arc<PreparationBudget> {
        Arc::new(PreparationBudget::reference_defaults())
    }

    fn create(temp: &TempRoot, kind: HashKind) -> Store {
        Store::create(&temp.store_dir(), kind, budget()).expect("create store")
    }

    fn reopen(temp: &TempRoot) -> Store {
        Store::open(&temp.store_dir(), budget()).expect("open store")
    }

    #[test]
    fn repo_meta_reads_pre_policy_rows_with_empty_policy() {
        #[derive(serde::Serialize)]
        struct OldRepoMetaRow {
            default_branch: crate::refdata::RefName,
        }
        let temp = TempRoot::new("repo-meta-v0");
        let store = create(&temp, HashKind::Sha1);
        let old = OldRepoMetaRow {
            default_branch: crate::refdata::RefName::new("refs/heads/main").expect("branch"),
        };
        let bytes = postcard::to_allocvec(&old).expect("encode old row");
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::RepoMeta,
                    key: REPO_META_KEY.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(bytes),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish old row");
        let row = store.repo_meta().expect("read meta").expect("row present");
        assert_eq!(row.default_branch.as_bytes(), b"refs/heads/main");
        assert!(row.land_requirements.is_empty());
        assert!(row.trusted_signers.is_empty());
        assert_eq!(row.policy_generation, 0);
    }

    #[test]
    fn open_waits_for_a_live_store_instead_of_refusing() {
        use std::time::{Duration, Instant};

        let temp = TempRoot::new("open-lock-wait");
        let holder = create(&temp, HashKind::Sha1);
        let root = temp.store_dir();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let store = Store::open_with_timeout(&root, budget(), Duration::from_secs(30))
                .expect("the second open waits for the live store");
            assert_eq!(store.hash_kind(), HashKind::Sha1);
            done_tx
                .send(Instant::now())
                .expect("report the waiter completion");
        });
        // The waiter must still be queued behind the live store here: it
        // neither refuses with already-open nor slips through early.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            done_rx.try_recv().is_err(),
            "the second Store::open must queue behind the live store"
        );
        let released = Instant::now();
        drop(holder);
        let completed = done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the second open completes after the drop");
        assert!(
            completed >= released,
            "the second open completes after the first store drops, not before"
        );
        waiter.join().expect("join the waiter");
    }

    fn len_of(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("length fits u64")
    }

    fn blob(store: &Store, bytes: &[u8]) -> PreparedObject {
        store
            .prepare(ObjectKind::Blob, len_of(bytes), bytes, None)
            .expect("prepare blob")
    }

    fn blob_oid(kind: HashKind, bytes: &[u8]) -> Oid {
        kind.hash_git_object("blob", bytes).expect("hash blob")
    }

    fn read_all(store: &Store, oid: Oid) -> Vec<u8> {
        let mut object = store.read(oid).expect("read object");
        let mut bytes = Vec::new();
        object.bytes.read_to_end(&mut bytes).expect("read spool");
        bytes
    }

    fn pseudo(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_be_bytes()[0]
            })
            .collect()
    }

    fn mutation(
        table: FactTable,
        key: &[u8],
        expected: FactExpectation,
        value: Option<&[u8]>,
    ) -> FactMutation {
        FactMutation {
            table,
            key: key.to_vec(),
            expected,
            value: value.map(<[u8]>::to_vec),
        }
    }

    fn segment_file(temp: &TempRoot, id: u64) -> PathBuf {
        temp.store_dir()
            .join(SEGMENTS_DIR)
            .join(segment::segment_file_name(id))
    }

    fn meta_file(temp: &TempRoot) -> PathBuf {
        temp.store_dir().join(META_FILE)
    }

    fn segment_names(temp: &TempRoot) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(temp.store_dir().join(SEGMENTS_DIR))
            .expect("segments dir")
            .map(|entry| {
                entry
                    .expect("segment entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// Objects and a delta prepared while a store was still healthy, for the
    /// tests that damage committed metadata afterwards. Preparation is
    /// refused once a store is quarantined, so everything a later call needs
    /// exists before the damage.
    struct Seeded {
        healthy: Oid,
        victim: Oid,
        /// The victim's bytes prepared again, as a client re-publishing it.
        victim_again: PreparedObject,
        /// A delta whose committed base is the victim.
        delta_over_victim: PreparedObject,
        unrelated: PreparedObject,
        spare: PreparedObject,
    }

    /// Commits a healthy and a victim blob plus one fact in a fresh store,
    /// then closes it.
    fn seed(temp: &TempRoot) -> Seeded {
        let store = create(temp, HashKind::Sha1);
        let healthy = blob(&store, &pseudo(2000, 21));
        let victim_bytes = pseudo(32 * 1024, 22);
        let victim = blob(&store, &victim_bytes);
        let (healthy_oid, victim_oid) = (healthy.oid(), victim.oid());
        let main = [mutation(
            FactTable::Refs,
            b"refs/heads/main",
            FactExpectation::Absent,
            Some(healthy_oid.as_bytes()),
        )];
        store
            .publish(
                vec![healthy, victim],
                &main,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish committed objects");
        let mut changed = victim_bytes.clone();
        changed[16_000..16_008].copy_from_slice(b"EDITED!!");
        let delta_over_victim = store
            .prepare(
                ObjectKind::Blob,
                len_of(&changed),
                &changed[..],
                Some(victim_oid),
            )
            .expect("prepare delta");
        assert_eq!(delta_over_victim.encoding(), Encoding::Delta);
        let seeded = Seeded {
            healthy: healthy_oid,
            victim: victim_oid,
            victim_again: blob(&store, &victim_bytes),
            delta_over_victim,
            unrelated: blob(&store, &pseudo(2000, 23)),
            spare: blob(&store, &pseudo(2000, 24)),
        };
        drop(store);
        seeded
    }

    /// A live store over committed metadata damaged after a clean open.
    ///
    /// Recovery first runs for real over the healthy files and its result is
    /// kept. `damage` then edits the closed metadata file with raw redb, and
    /// the store is assembled over `Metadata::open`, which checks only the
    /// table census. This bypasses startup verification of the damaged
    /// state: `Store::open` on the same files refuses, and redb's exclusive
    /// lock forbids writing under a live store. It is a real `Store` over
    /// real redb and segments, not a public runtime corruption injection.
    fn reopen_over_damage(temp: &TempRoot, damage: impl FnOnce(&Path)) -> Store {
        let root = temp.store_dir();
        let (format, format_file) = read_format(&root).expect("format file");
        drop(format_file);
        let shared = budget();
        let recovered = {
            let meta = Metadata::open(&meta_file(temp)).expect("healthy metadata");
            let generation = meta.generation().expect("healthy generation");
            let guards = Arc::new(GenerationRegistry::new(generation));
            let pin = PinnedRoot::open(&root).expect("pin test store");
            shared
                .register_scratch(&pin, &root)
                .expect("scratch accounting");
            let files = SegmentFileCache::default();
            let committed = Committed {
                root: &root,
                kind: format.kind,
                meta: &meta,
                budget: &shared,
                guards: &guards,
                files: &files,
                pin: &pin,
            };
            recovery::run(&committed).expect("healthy store recovers")
        };
        damage(&meta_file(temp));
        let meta = Metadata::open(&meta_file(temp)).expect("metadata census");
        let generation = meta.generation().unwrap_or(0);
        let guards = Arc::new(GenerationRegistry::new(generation));
        Store::assemble(&root, format, meta, shared, guards, recovered)
    }

    /// A refusal is typed corruption from a call whose ordinary execution
    /// would succeed. Callers pair it with `Store::quarantine`, so state and
    /// behavior together identify the latch without reading message text.
    fn assert_refused<T: std::fmt::Debug>(what: &str, result: Result<T, StoreError>) {
        match result {
            Err(StoreError::Corrupt(_)) => {}
            other => panic!("{what}: expected a refusal as Corrupt, got {other:?}"),
        }
    }

    /// Every live method refuses once corruption latched quarantine. Each
    /// call below targets undamaged state and would succeed on a healthy
    /// store: a read of an intact object, a lookup of a committed fact,
    /// preparation of fresh bytes, an absent-key fact write, an empty
    /// publication, and a fresh object publication.
    fn assert_refuses_all_service(store: &Store, healthy: Oid, spare: PreparedObject) {
        assert!(store.quarantine());
        assert!(store.quarantine_reason().is_some());
        assert_refused("read of an undamaged object", store.read(healthy));
        assert_refused(
            "fact lookup",
            store.fact(FactTable::Refs, b"refs/heads/main"),
        );
        assert_refused(
            "prepare",
            store.prepare(ObjectKind::Blob, 1, &b"x"[..], None),
        );
        let facts = [mutation(
            FactTable::Refs,
            b"refs/heads/other",
            FactExpectation::Absent,
            Some(b"v"),
        )];
        assert_refused(
            "fact-only publish",
            store.publish(
                vec![],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            ),
        );
        assert_refused(
            "empty publish",
            store.publish(
                vec![],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            ),
        );
        assert_refused(
            "unrelated object publish",
            store.publish(
                vec![spare],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            ),
        );
    }

    #[test]
    fn objects_and_facts_survive_reopen_for_both_hash_kinds() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let temp = TempRoot::new("roundtrip");
            let store = create(&temp, kind);
            let identity = store.store_id();
            assert_ne!(identity, StoreId::nil(), "creation fixes a real identity");
            let payload = pseudo(5000, 1);
            let prepared = blob(&store, &payload);
            let oid = prepared.oid();
            assert_eq!(oid, blob_oid(kind, &payload));
            let facts = [mutation(
                FactTable::Refs,
                b"refs/heads/main",
                FactExpectation::Absent,
                Some(oid.as_bytes()),
            )];
            let published = store
                .publish(
                    vec![prepared],
                    &facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish");
            assert_eq!(published.objects, vec![oid]);
            assert_eq!(published.generation, 1);
            drop(store);

            let store = reopen(&temp);
            assert_eq!(store.hash_kind(), kind);
            assert_eq!(store.store_id(), identity, "reopen keeps the identity");
            assert_eq!(read_all(&store, oid), payload);
            assert_eq!(
                store
                    .fact(FactTable::Refs, b"refs/heads/main")
                    .expect("fact"),
                Some(oid.as_bytes().to_vec())
            );
        }
    }

    /// Renaming a store directory changes no identity: reopening the moved
    /// store reports the identity fixed at creation, for both kinds.
    #[test]
    fn renaming_a_store_keeps_its_identity_for_both_hash_kinds() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let temp = TempRoot::new("identity-rename");
            let identity = create(&temp, kind).store_id();
            let moved = temp.0.join("moved-store");
            std::fs::rename(temp.store_dir(), &moved).expect("rename the store directory");
            let store = Store::open(&moved, budget()).expect("open the renamed store");
            assert_eq!(store.store_id(), identity, "{kind:?}: rename");
            assert_eq!(store.hash_kind(), kind);
        }
    }

    /// Independently created stores have distinct identities, across both
    /// object formats.
    #[test]
    fn independently_created_stores_have_distinct_identities() {
        let first = TempRoot::new("distinct-a");
        let second = TempRoot::new("distinct-b");
        let sha1 = create(&first, HashKind::Sha1).store_id();
        let sha256 = create(&second, HashKind::Sha256).store_id();
        assert_ne!(sha1, StoreId::nil());
        assert_ne!(sha256, StoreId::nil());
        assert_ne!(sha1, sha256);
    }

    #[test]
    fn create_refuses_to_overwrite_any_existing_layout_element() {
        let temp = TempRoot::new("create-refuse");
        std::fs::create_dir_all(temp.store_dir()).expect("mkdir");
        let meta = temp.store_dir().join(META_FILE);
        std::fs::write(&meta, b"not a database").expect("seed meta");
        let err = Store::create(&temp.store_dir(), HashKind::Sha1, budget())
            .expect_err("partial layout must refuse");
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(std::fs::read(&meta).expect("meta"), b"not a database");

        let temp = TempRoot::new("create-twice");
        drop(create(&temp, HashKind::Sha1));
        assert!(Store::create(&temp.store_dir(), HashKind::Sha1, budget()).is_err());
    }

    #[test]
    fn create_refuses_an_existing_segments_directory_and_leaves_it_alone() {
        let temp = TempRoot::new("create-segments");
        let segments = temp.store_dir().join(SEGMENTS_DIR);
        std::fs::create_dir_all(&segments).expect("seed segments");
        let keep = segments.join("keep");
        std::fs::write(&keep, b"payload").expect("seed content");
        let err = Store::create(&temp.store_dir(), HashKind::Sha1, budget())
            .expect_err("an existing segments directory must refuse");
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(std::fs::read(&keep).expect("content"), b"payload");
        assert!(!meta_file(&temp).exists(), "nothing is built inside it");
        assert!(!temp.store_dir().join(FORMAT_FILE).exists());
    }

    /// Exactly one of several concurrent creators of one root proceeds; every
    /// loser fails, and the winner's store opens and serves.
    #[test]
    fn exactly_one_concurrent_creator_wins_a_store_root() {
        const RACERS: usize = 6;
        for round in 0..8 {
            let temp = TempRoot::new("create-race");
            let barrier = std::sync::Barrier::new(RACERS);
            // The winner's store is dropped inside its thread, releasing the
            // database for the reopen below.
            let outcomes: Vec<Result<(), String>> = std::thread::scope(|scope| {
                let racers: Vec<_> = (0..RACERS)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            Store::create(&temp.store_dir(), HashKind::Sha1, budget())
                                .map(drop)
                                .map_err(|err| format!("{err:?}"))
                        })
                    })
                    .collect();
                racers
                    .into_iter()
                    .map(|racer| racer.join().expect("creator panicked"))
                    .collect()
            });
            let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
            assert_eq!(winners, 1, "round {round}: {outcomes:?}");

            // The one store that came out is whole and serves.
            let store = reopen(&temp);
            let winner = store.store_id();
            let payload = pseudo(2000, 61);
            let oid = store
                .publish(
                    vec![blob(&store, &payload)],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("the winner's store publishes")
                .objects[0];
            drop(store);
            let store = reopen(&temp);
            assert_eq!(store.store_id(), winner, "round {round}");
            assert_eq!(read_all(&store, oid), payload, "round {round}");
        }
    }

    /// A creation that stopped before the format was complete is neither
    /// opened nor completed by a later call, and its files are untouched.
    /// Every rejected marker shape, including the earlier two-line marker,
    /// leaves the marker and the metadata bytes unchanged.
    #[test]
    fn an_incomplete_format_is_neither_opened_nor_adopted() {
        let identity = StoreId::generate();
        let canonical = StoreFormat {
            kind: HashKind::Sha1,
            id: identity,
        }
        .to_bytes();
        let canonical_text = String::from_utf8(canonical.clone()).expect("marker is UTF-8");
        let mut with_extra = canonical.clone();
        with_extra.extend_from_slice(b"extra fourth line\n");
        let upper = identity.to_string().to_ascii_uppercase();
        let torn: [(&str, Vec<u8>); 9] = [
            ("empty", Vec::new()),
            ("prefix", canonical[..canonical.len() / 2].to_vec()),
            ("zeros", vec![0; canonical.len()]),
            (
                "earlier two-line marker",
                b"ruk-store 1\nobject-format sha1\n".to_vec(),
            ),
            (
                "nil identity",
                format!(
                    "ruk-store 1\nobject-format sha1\nstore-id {}\n",
                    StoreId::nil()
                )
                .into_bytes(),
            ),
            (
                "carriage return",
                canonical_text.replace('\n', "\r\n").into_bytes(),
            ),
            (
                "missing final newline",
                canonical[..canonical.len() - 1].to_vec(),
            ),
            (
                "uppercase identity",
                format!("ruk-store 1\nobject-format sha1\nstore-id {upper}\n").into_bytes(),
            ),
            ("extra line", with_extra),
        ];
        for (name, bytes) in torn {
            let temp = TempRoot::new("incomplete-format");
            let healthy = create(&temp, HashKind::Sha1);
            let payload = pseudo(2000, 62);
            let oid = healthy
                .publish(
                    vec![blob(&healthy, &payload)],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish")
                .objects[0];
            drop(healthy);
            let format = temp.store_dir().join(FORMAT_FILE);
            std::fs::write(&format, &bytes).expect("leave an interrupted format");
            let meta_before = std::fs::read(meta_file(&temp)).expect("meta");

            let err = Store::open(&temp.store_dir(), budget()).expect_err("must not open");
            assert!(matches!(err, StoreError::Version(_)), "{name}: {err:?}");
            let err = Store::create(&temp.store_dir(), HashKind::Sha1, budget())
                .expect_err("must not adopt or recreate");
            assert!(matches!(err, StoreError::Invalid(_)), "{name}: {err:?}");
            assert_eq!(std::fs::read(&format).expect("format"), bytes, "{name}");
            assert_eq!(
                std::fs::read(meta_file(&temp)).expect("meta"),
                meta_before,
                "{name}"
            );

            std::fs::write(&format, &canonical).expect("restore the complete format");
            let store = reopen(&temp);
            assert_eq!(read_all(&store, oid), payload, "{name}");
        }
    }

    /// Opening flushes the root's entries (the format entry on POSIX) before
    /// it returns, and a refusal leaves the database openable.
    #[cfg(unix)]
    #[test]
    fn open_flushes_the_root_entries_before_returning() {
        let temp = TempRoot::new("open-flush");
        drop(create(&temp, HashKind::Sha1));
        let inject = durability::fault::fail_sync_of(&temp.store_dir());
        let err = Store::open(&temp.store_dir(), budget())
            .expect_err("entries that cannot be flushed must refuse the open");
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == durability::fault::INJECTED_KIND),
            "{err:?}"
        );
        drop(inject);
        let store = reopen(&temp);
        assert_eq!(store.hash_kind(), HashKind::Sha1);
    }

    /// POSIX builds the missing ancestors of a store root.
    #[cfg(unix)]
    #[test]
    fn posix_create_builds_missing_ancestors() {
        let temp = TempRoot::new("create-nested");
        let root = temp.0.join("a/b/store");
        let store = Store::create(&root, HashKind::Sha1, budget()).expect("create nested");
        drop(store);
        assert_eq!(
            Store::open(&root, budget())
                .expect("open nested")
                .hash_kind(),
            HashKind::Sha1
        );
    }

    /// Windows creates no ancestor and adopts no root; the store tree is the
    /// caller's to provision durably.
    #[cfg(windows)]
    #[test]
    fn windows_create_needs_a_present_parent_and_an_absent_root() {
        let temp = TempRoot::new("create-windows");
        let missing = temp.0.join("absent");
        let err = Store::create(&missing.join("store"), HashKind::Sha1, budget())
            .expect_err("a missing parent must fail");
        assert!(
            matches!(&err, StoreError::Io(e) if e.kind() == io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert!(!missing.exists(), "no ancestor may be created");
        assert_eq!(
            std::fs::read_dir(&temp.0).expect("list parent").count(),
            0,
            "a failed creation leaves nothing behind"
        );

        std::fs::create_dir(temp.store_dir()).expect("existing empty root");
        let err = Store::create(&temp.store_dir(), HashKind::Sha1, budget())
            .expect_err("an existing root must never be adopted");
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(
            std::fs::read_dir(temp.store_dir())
                .expect("list root")
                .count(),
            0,
            "an existing root is left untouched"
        );
        assert_eq!(
            std::fs::read_dir(&temp.0).expect("list parent").count(),
            1,
            "no temporary name is left in the parent"
        );
    }

    #[test]
    fn duplicate_of_a_committed_object_keeps_its_bytes_and_generation() {
        let temp = TempRoot::new("duplicate");
        let store = create(&temp, HashKind::Sha1);
        let payload = pseudo(3000, 2);
        let first = store
            .publish(
                vec![blob(&store, &payload)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("first publish");
        let before = std::fs::metadata(segment_file(&temp, 0))
            .expect("segment")
            .len();
        let again = store
            .publish(
                vec![blob(&store, &payload)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("duplicate publish");
        assert_eq!(again.objects, first.objects);
        assert_eq!(again.generation, first.generation);
        let after = std::fs::metadata(segment_file(&temp, 0))
            .expect("segment")
            .len();
        assert_eq!(before, after);
    }

    #[test]
    fn prepared_object_of_another_hash_kind_is_refused() {
        let sha1 = TempRoot::new("kind-a");
        let sha256 = TempRoot::new("kind-b");
        let source = create(&sha1, HashKind::Sha1);
        let target = create(&sha256, HashKind::Sha256);
        let foreign = blob(&source, b"foreign width");
        let err = target
            .publish(
                vec![foreign],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("width mismatch");
        assert!(matches!(err, StoreError::ObjectFormat(_)), "{err:?}");
    }

    #[test]
    fn delta_whose_base_is_not_committed_here_is_refused_before_any_append() {
        let a = TempRoot::new("base-a");
        let b = TempRoot::new("base-b");
        let source = create(&a, HashKind::Sha1);
        let target = create(&b, HashKind::Sha1);
        let base_bytes = pseudo(32 * 1024, 3);
        let base = blob(&source, &base_bytes);
        let base_oid = base.oid();
        source
            .publish(
                vec![base],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish base");
        let mut changed = base_bytes.clone();
        changed[16_000..16_008].copy_from_slice(b"EDITED!!");
        let delta = source
            .prepare(
                ObjectKind::Blob,
                len_of(&changed),
                &changed[..],
                Some(base_oid),
            )
            .expect("prepare delta");
        assert_eq!(delta.encoding(), Encoding::Delta);
        let facts = [mutation(
            FactTable::Refs,
            b"refs/heads/x",
            FactExpectation::Absent,
            Some(b"v"),
        )];
        let err = target
            .publish(
                vec![delta],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("dangling base");
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(
            target.fact(FactTable::Refs, b"refs/heads/x").expect("fact"),
            None
        );
        let entries = std::fs::read_dir(b.store_dir().join(SEGMENTS_DIR))
            .expect("segments dir")
            .count();
        assert_eq!(entries, 0, "validation must precede any segment creation");
        target
            .publish(
                vec![],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("writer stays open after a validation failure");
    }

    #[test]
    fn delta_chain_reads_back_exactly_after_reopen() {
        let temp = TempRoot::new("delta-read");
        let store = create(&temp, HashKind::Sha1);
        let base_bytes = pseudo(32 * 1024, 4);
        let base = blob(&store, &base_bytes);
        let base_oid = base.oid();
        store
            .publish(
                vec![base],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish base");
        let mut changed = base_bytes.clone();
        changed[100..108].copy_from_slice(b"CHANGED!");
        let delta = store
            .prepare(
                ObjectKind::Blob,
                len_of(&changed),
                &changed[..],
                Some(base_oid),
            )
            .expect("prepare delta");
        assert_eq!(delta.encoding(), Encoding::Delta);
        assert_eq!(delta.depth(), 1);
        let delta_oid = delta.oid();
        store
            .publish(
                vec![delta],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish delta");
        drop(store);

        let store = reopen(&temp);
        assert_eq!(read_all(&store, delta_oid), changed);
        assert_eq!(store.read(delta_oid).expect("read").depth, 1);
        assert_eq!(read_all(&store, base_oid), base_bytes);
    }

    #[test]
    fn identical_record_replay_converges_while_conflicts_stay_stale() {
        let temp = TempRoot::new("record-replay");
        let store = create(&temp, HashKind::Sha1);
        for table in [
            FactTable::Commits,
            FactTable::Changes,
            FactTable::ImportedChanges,
            FactTable::ChangeHistory,
        ] {
            let first = [mutation(
                table,
                b"row",
                FactExpectation::Absent,
                Some(b"v1"),
            )];
            store
                .publish(
                    vec![],
                    &first,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("first record write");
            store
                .publish(
                    vec![],
                    &first,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("identical record replay converges");
            let changed = [mutation(
                table,
                b"row",
                FactExpectation::Absent,
                Some(b"v2"),
            )];
            let err = store
                .publish(
                    vec![],
                    &changed,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect_err("a differing record still refuses");
            assert!(matches!(err, StoreError::StaleFact { .. }), "{err:?}");
        }
    }

    #[test]
    fn unknown_predecessor_is_not_found() {
        let temp = TempRoot::new("predecessor");
        let store = create(&temp, HashKind::Sha1);
        let unknown = blob_oid(HashKind::Sha1, b"never published");
        let err = store
            .prepare(ObjectKind::Blob, 3, &b"abc"[..], Some(unknown))
            .expect_err("unknown predecessor");
        assert!(matches!(err, StoreError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn stale_and_duplicate_fact_batches_change_nothing() {
        let temp = TempRoot::new("facts");
        let store = create(&temp, HashKind::Sha1);
        let set = [mutation(
            FactTable::Claims,
            b"claim",
            FactExpectation::Absent,
            Some(b"one"),
        )];
        store
            .publish(
                vec![],
                &set,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("first set");
        let err = store
            .publish(
                vec![],
                &set,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("claim already present");
        assert!(matches!(err, StoreError::StaleFact { .. }), "{err:?}");

        let twice = [
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"a")),
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"b")),
        ];
        let err = store
            .publish(
                vec![],
                &twice,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("duplicate key");
        assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
        assert_eq!(store.fact(FactTable::Claims, b"dup").expect("fact"), None);
        assert_eq!(
            store.fact(FactTable::Claims, b"claim").expect("fact"),
            Some(b"one".to_vec())
        );
        let remove = [mutation(
            FactTable::Claims,
            b"claim",
            FactExpectation::Value(b"one".to_vec()),
            None,
        )];
        store
            .publish(
                vec![],
                &remove,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("conditional remove");
        assert_eq!(store.fact(FactTable::Claims, b"claim").expect("fact"), None);
    }

    #[test]
    fn unknown_segment_file_is_skipped_never_overwritten() {
        let temp = TempRoot::new("orphan");
        let store = create(&temp, HashKind::Sha1);
        let orphan = segment_file(&temp, 0);
        std::fs::write(&orphan, b"unknown orphan bytes").expect("seed orphan");
        let payload = pseudo(2000, 5);
        let prepared = blob(&store, &payload);
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish past orphan");
        assert_eq!(
            std::fs::read(&orphan).expect("orphan"),
            b"unknown orphan bytes"
        );
        assert!(segment_file(&temp, 1).exists());
        assert_eq!(read_all(&store, oid), payload);
        drop(store);

        let store = reopen(&temp);
        assert_eq!(read_all(&store, oid), payload);
        assert_eq!(
            std::fs::read(&orphan).expect("orphan"),
            b"unknown orphan bytes"
        );
    }

    #[test]
    fn reopened_store_resumes_the_open_segment() {
        let temp = TempRoot::new("resume");
        let store = create(&temp, HashKind::Sha1);
        let first = pseudo(2000, 6);
        let first_oid = store
            .publish(
                vec![blob(&store, &first)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("first")
            .objects[0];
        drop(store);

        let store = reopen(&temp);
        let second = pseudo(2000, 7);
        let second_oid = store
            .publish(
                vec![blob(&store, &second)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("second")
            .objects[0];
        assert!(!segment_file(&temp, 1).exists());
        drop(store);

        let store = reopen(&temp);
        assert_eq!(read_all(&store, first_oid), first);
        assert_eq!(read_all(&store, second_oid), second);
    }

    #[test]
    fn close_retires_the_handle_and_reopen_resumes() {
        let temp = TempRoot::new("close");
        let store = create(&temp, HashKind::Sha1);
        let first = pseudo(2000, 60);
        let first_oid = store
            .publish(
                vec![blob(&store, &first)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("first")
            .objects[0];
        store.close().expect("close");
        // Idempotent: closing twice retires nothing new.
        store.close().expect("second close");
        // Terminal for publication: the dropped handle stays the single
        // committed open segment, so a fresh segment here would strand two
        // opens and fail the next recovery.
        let refused = pseudo(2000, 61);
        let err = store
            .publish(
                vec![blob(&store, &refused)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("publish after close is refused");
        assert!(
            matches!(err, StoreError::WriterClosed(_)),
            "expected WriterClosed, got {err:?}"
        );
        // Reads still serve after close.
        assert_eq!(read_all(&store, first_oid), first);
        drop(store);

        // Recovery resumes the single open segment, not a second one.
        let store = reopen(&temp);
        assert_eq!(read_all(&store, first_oid), first);
        let second = pseudo(2000, 62);
        let second_oid = store
            .publish(
                vec![blob(&store, &second)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("post-reopen publish resumes the open segment")
            .objects[0];
        assert!(!segment_file(&temp, 1).exists());
        drop(store);

        let store = reopen(&temp);
        assert_eq!(read_all(&store, first_oid), first);
        assert_eq!(read_all(&store, second_oid), second);
    }

    #[test]
    fn open_truncates_only_the_uncommitted_tail() {
        let temp = TempRoot::new("tail");
        let store = create(&temp, HashKind::Sha1);
        let payload = pseudo(2000, 8);
        let oid = store
            .publish(
                vec![blob(&store, &payload)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish")
            .objects[0];
        drop(store);
        let path = segment_file(&temp, 0);
        let committed = std::fs::metadata(&path).expect("segment").len();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open segment");
        file.write_all(&[0xAA; 100]).expect("append junk");
        drop(file);

        let store = reopen(&temp);
        assert_eq!(std::fs::metadata(&path).expect("segment").len(), committed);
        assert_eq!(read_all(&store, oid), payload);
        let more = pseudo(500, 9);
        let more_oid = store
            .publish(
                vec![blob(&store, &more)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish after truncation")
            .objects[0];
        assert_eq!(read_all(&store, more_oid), more);
    }

    #[test]
    fn open_verifies_every_object_across_batch_boundaries() {
        // More committed objects than one verification batch holds
        // (recovery batches 4096 locators), so the reopening pass must
        // carry its page cursor across at least one batch boundary. Keep
        // this count above the batch size if that constant ever moves.
        const OBJECTS: usize = 4100;
        const CHUNK: usize = 512;
        let temp = TempRoot::new("verify-batches");
        let store = create(&temp, HashKind::Sha1);
        let mut oids = Vec::with_capacity(OBJECTS);
        let indices: Vec<usize> = (0..OBJECTS).collect();
        for group in indices.chunks(CHUNK) {
            let batch: Vec<PreparedObject> = group
                .iter()
                .map(|i| {
                    blob(
                        &store,
                        &pseudo(16, u64::try_from(*i).expect("object index fits u64")),
                    )
                })
                .collect();
            oids.extend(
                store
                    .publish(batch, &[], EventSource::LocalPush, &EventContext::default())
                    .expect("publish")
                    .objects,
            );
        }
        assert_eq!(oids.len(), OBJECTS);
        drop(store);
        let store = reopen(&temp);
        for i in [0, OBJECTS / 2, OBJECTS - 1] {
            assert_eq!(read_all(&store, oids[i]), pseudo(16, i as u64));
        }
        drop(store);
        // Damage the last row in digest order: a reopen must reach the
        // final batch to refuse it.
        let mut ordered = oids.clone();
        ordered.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let tail = *ordered.last().expect("committed objects");
        let meta = meta_file(&temp);
        raw_put_object(&meta, tail.as_bytes(), &[0xFF; 3]);
        raw_bump_generation(&meta);
        let err = Store::open(&temp.store_dir(), budget()).expect_err("damaged tail row");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    }

    #[test]
    fn open_refuses_missing_committed_bytes() {
        let temp = TempRoot::new("short");
        let store = create(&temp, HashKind::Sha1);
        store
            .publish(
                vec![blob(&store, &pseudo(2000, 10))],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");
        drop(store);
        let path = segment_file(&temp, 0);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open segment");
        let len = file.metadata().expect("metadata").len();
        file.set_len(len - 1).expect("shorten");
        drop(file);
        let err = Store::open(&temp.store_dir(), budget()).expect_err("short committed file");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert_eq!(std::fs::metadata(&path).expect("segment").len(), len - 1);
    }

    #[test]
    fn corruption_seen_by_a_read_latches_quarantine() {
        let temp = TempRoot::new("quarantine");
        let store = create(&temp, HashKind::Sha1);
        let payload = pseudo(2000, 11);
        let prepared = blob(&store, &payload);
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        let path = segment_file(&temp, 0);
        let mut bytes = std::fs::read(&path).expect("segment bytes");
        bytes[segment::HEADER_LEN + 2] ^= 0xFF;
        std::fs::write(&path, bytes).expect("corrupt segment");

        let err = store.read(oid).expect_err("corrupt record");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert!(store.quarantine());
        assert!(store.quarantine_reason().is_some());
        let facts = [mutation(
            FactTable::Refs,
            b"r",
            FactExpectation::Any,
            Some(b"v"),
        )];
        assert!(matches!(
            store.publish(
                vec![],
                &facts,
                EventSource::LocalPush,
                &EventContext::default()
            ),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            store.fact_page(FactTable::Refs, None, FactPageBudget::new(10, 1024)),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            store.fact(FactTable::Refs, b"r"),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            store.prepare(ObjectKind::Blob, 1, &b"x"[..], None),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn publishing_an_object_with_a_malformed_committed_locator_quarantines_the_store() {
        let temp = TempRoot::new("publish-malformed-locator");
        let seeded = seed(&temp);
        let acknowledged = std::fs::read(segment_file(&temp, 0)).expect("segment bytes");
        let store = reopen_over_damage(&temp, |meta| {
            raw_put_object(meta, seeded.victim.as_bytes(), &[0xFF; 3]);
            // Row surgery alone leaves the verified generation covering the
            // store, which a cached open would skip; the bump models damage
            // from an unverified generation, which recovery must refuse.
            raw_bump_generation(meta);
        });

        let err = store
            .publish(
                vec![seeded.victim_again],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("malformed locator");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert!(
            store.quarantine(),
            "committed corruption observed by publish must latch quarantine"
        );
        assert_refuses_all_service(&store, seeded.healthy, seeded.spare);

        assert_eq!(
            std::fs::read(segment_file(&temp, 0)).expect("segment bytes"),
            acknowledged
        );
        assert_eq!(segment_names(&temp), [segment::segment_file_name(0)]);
        drop(store);
        let err = Store::open(&temp.store_dir(), budget())
            .expect_err("recovery must refuse the damaged row too");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert_eq!(
            std::fs::read(segment_file(&temp, 0)).expect("segment bytes"),
            acknowledged
        );
    }

    #[test]
    fn publishing_a_delta_over_a_base_with_a_malformed_locator_quarantines_the_store() {
        let temp = TempRoot::new("publish-malformed-base");
        let seeded = seed(&temp);
        let store = reopen_over_damage(&temp, |meta| {
            raw_put_object(meta, seeded.victim.as_bytes(), &[0xFF; 3]);
        });

        let err = store
            .publish(
                vec![seeded.delta_over_victim],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("malformed base locator");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert!(
            store.quarantine(),
            "a corrupt delta base seen while planning must latch quarantine"
        );
        assert_refuses_all_service(&store, seeded.healthy, seeded.spare);
        assert_eq!(segment_names(&temp), [segment::segment_file_name(0)]);
    }

    #[test]
    fn a_malformed_committed_manifest_met_while_committing_closes_the_writer_and_quarantines() {
        let temp = TempRoot::new("publish-malformed-manifest");
        let seeded = seed(&temp);
        let acknowledged = std::fs::read(segment_file(&temp, 0)).expect("segment bytes");
        // Recovery resumes segment 0, so this publication appends to it and
        // then reads its manifest row to record the new extent.
        let store = reopen_over_damage(&temp, |meta| raw_put_segment(meta, 0, &[0xFF; 3]));

        let err = store
            .publish(
                vec![seeded.unrelated],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect_err("manifest row of the segment being appended is malformed");
        assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
        assert!(
            store.lock_writer().expect("writer").closed.is_some(),
            "a failure after the first append must close the writer"
        );
        assert!(
            store.quarantine(),
            "a committed manifest row that fails decoding is committed corruption"
        );
        assert_refuses_all_service(&store, seeded.healthy, seeded.spare);
        let after = std::fs::read(segment_file(&temp, 0)).expect("segment bytes");
        assert!(
            after.starts_with(&acknowledged),
            "acknowledged bytes must stay a prefix of the segment"
        );
        assert_eq!(segment_names(&temp), [segment::segment_file_name(0)]);
    }

    #[test]
    fn caller_mistakes_never_quarantine_the_store() {
        let temp = TempRoot::new("caller-mistakes");
        let source_dir = TempRoot::new("caller-mistakes-source");
        let foreign_dir = TempRoot::new("caller-mistakes-foreign");
        let store = create(&temp, HashKind::Sha1);
        let source = create(&source_dir, HashKind::Sha1);
        let foreign = create(&foreign_dir, HashKind::Sha256);

        let claim = [mutation(
            FactTable::Claims,
            b"claim",
            FactExpectation::Absent,
            Some(b"one"),
        )];
        store
            .publish(
                vec![],
                &claim,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("first claim");
        assert!(matches!(
            store.publish(
                vec![],
                &claim,
                EventSource::LocalPush,
                &EventContext::default()
            ),
            Err(StoreError::StaleFact { .. })
        ));
        let twice = [
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"a")),
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"b")),
        ];
        assert!(matches!(
            store.publish(
                vec![],
                &twice,
                EventSource::LocalPush,
                &EventContext::default()
            ),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.publish(
                vec![blob(&foreign, b"wide")],
                &[],
                EventSource::LocalPush,
                &EventContext::default()
            ),
            Err(StoreError::ObjectFormat(_))
        ));

        let base_bytes = pseudo(32 * 1024, 31);
        let base = blob(&source, &base_bytes);
        let base_oid = base.oid();
        source
            .publish(
                vec![base],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish base");
        let mut changed = base_bytes;
        changed[100..108].copy_from_slice(b"CHANGED!");
        let dangling = source
            .prepare(
                ObjectKind::Blob,
                len_of(&changed),
                &changed[..],
                Some(base_oid),
            )
            .expect("prepare delta");
        assert_eq!(dangling.encoding(), Encoding::Delta);
        assert!(matches!(
            store.publish(
                vec![dangling],
                &[],
                EventSource::LocalPush,
                &EventContext::default()
            ),
            Err(StoreError::Invalid(_))
        ));

        let unknown = blob_oid(HashKind::Sha1, b"never published");
        assert!(matches!(store.read(unknown), Err(StoreError::NotFound(_))));
        assert!(matches!(
            store.read(blob_oid(HashKind::Sha256, b"wide")),
            Err(StoreError::ObjectFormat(_))
        ));
        assert!(matches!(
            store.prepare(ObjectKind::Blob, 3, &b"abc"[..], Some(unknown)),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.prepare(ObjectKind::Blob, 5, &b"abc"[..], None),
            Err(StoreError::Invalid(_))
        ));

        assert!(!store.quarantine());
        assert_eq!(store.quarantine_reason(), None);
        assert!(store.lock_writer().expect("writer").closed.is_none());
        let payload = pseudo(2000, 32);
        let prepared = blob(&store, &payload);
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("the store still serves");
        assert_eq!(read_all(&store, oid), payload);
    }

    /// Names the directory the child moves its own working directory to.
    /// Set only on the spawned child, never on the parent suite.
    const RELATIVE_ROOT_MOVE_ENV: &str = "RUK_STORE_RELATIVE_ROOT_MOVE_TO";

    #[test]
    fn a_relative_root_keeps_its_directory_when_the_working_directory_changes() {
        let temp = TempRoot::new("relative-root");
        let first = temp.0.join("first");
        let second = temp.0.join("second");
        std::fs::create_dir_all(&first).expect("first directory");
        std::fs::create_dir_all(&second).expect("second directory");

        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "store::tests::relative_root_child",
                "--ignored",
                "--nocapture",
            ])
            .env(RELATIVE_ROOT_MOVE_ENV, &second)
            .current_dir(&first)
            .output()
            .expect("spawn child");
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        // The store the child wrote is the evidence that the child ran: an
        // exact-name filter that matched nothing would leave no store here.
        let store = Store::open(&first.join("relative").join("store"), budget())
            .expect("reopen the store the child wrote");
        for seed in [41, 42] {
            let payload = pseudo(2000, seed);
            let oid = blob_oid(HashKind::Sha1, &payload);
            assert_eq!(read_all(&store, oid), payload, "object of seed {seed}");
        }
        assert_eq!(
            std::fs::read_dir(&second)
                .expect("second directory")
                .count(),
            0,
            "payload I/O must not follow the working directory"
        );
    }

    /// Child of the test above: creates and reopens a store by a relative
    /// root, moves its own working directory, then reads and publishes
    /// through the same handle. Only the spawned child's process is moved.
    #[test]
    #[ignore = "child of a_relative_root_keeps_its_directory_when_the_working_directory_changes; the parent test spawns it"]
    fn relative_root_child() {
        let Some(second) = std::env::var_os(RELATIVE_ROOT_MOVE_ENV) else {
            panic!("this child requires {RELATIVE_ROOT_MOVE_ENV} from its parent test");
        };
        let root = Path::new("relative").join("store");
        // Windows creation requires the root's parent to exist.
        #[cfg(not(unix))]
        std::fs::create_dir("relative").expect("provision the parent");
        let first_payload = pseudo(2000, 41);
        let store =
            Store::create(&root, HashKind::Sha1, budget()).expect("create by relative root");
        let first = store
            .publish(
                vec![blob(&store, &first_payload)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish before the move")
            .objects[0];
        drop(store);
        let store = Store::open(&root, budget()).expect("open by the same relative root");

        std::env::set_current_dir(&second).expect("move this child's working directory");

        assert_eq!(read_all(&store, first), first_payload);
        let later_payload = pseudo(2000, 42);
        let later = store
            .publish(
                vec![blob(&store, &later_payload)],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish after the move")
            .objects[0];
        assert_eq!(read_all(&store, later), later_payload);
    }

    #[test]
    fn sequential_publications_commit_one_at_a_time() {
        use std::time::Duration;

        let temp = TempRoot::new("group-sequential");
        let store = create(&temp, HashKind::Sha1);
        store.set_commit_linger(Duration::ZERO);
        let before = store.io_stats();
        for seed in 0..5 {
            store
                .publish(
                    vec![blob(&store, &pseudo(256, seed))],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("sequential publish");
        }
        let after = store.io_stats();
        assert_eq!(after.publications - before.publications, 5);
        assert_eq!(after.publication_commits - before.publication_commits, 5);
    }

    #[test]
    fn concurrent_publications_share_commits_and_land_intact() {
        use std::time::Duration;

        const WRITERS: usize = 4;
        const COMMITS: usize = 20;
        const SOLO: u64 = 5;
        fn barriers(stats: IoStats) -> u64 {
            stats.pending_commits
                + stats.publication_commits
                + stats.segment_syncs
                + stats.directory_syncs
        }
        let seed_of = |writer: usize, seq: usize| {
            u64::try_from(writer * COMMITS + seq).expect("seed fits u64") + 1
        };
        let temp = TempRoot::new("group-commit");
        let store = Arc::new(create(&temp, HashKind::Sha1));
        // Solo baseline on this store: no linger, one publication at a time.
        store.set_commit_linger(Duration::ZERO);
        store
            .publish(
                vec![blob(&store, &pseudo(64, 9_999))],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("warm-up publish");
        let solo_before = store.io_stats();
        for seed in 0..SOLO {
            store
                .publish(
                    vec![blob(&store, &pseudo(512, 20_000 + seed))],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("solo publish");
        }
        let solo = barriers(store.io_stats()) - barriers(solo_before);
        store.set_commit_linger(Duration::from_millis(10));
        let before = store.io_stats();
        std::thread::scope(|scope| {
            for writer in 0..WRITERS {
                let store = Arc::clone(&store);
                scope.spawn(move || {
                    for seq in 0..COMMITS {
                        let payload = pseudo(512, seed_of(writer, seq));
                        let expected = blob_oid(HashKind::Sha1, &payload);
                        let key = format!("refs/heads/w{writer}-{seq}");
                        let tip = format!("tip-{writer}-{seq}");
                        let fact = mutation(
                            FactTable::Refs,
                            key.as_bytes(),
                            FactExpectation::Absent,
                            Some(tip.as_bytes()),
                        );
                        let publication = store
                            .publish(
                                vec![blob(&store, &payload)],
                                &[fact],
                                EventSource::LocalPush,
                                &EventContext::default(),
                            )
                            .expect("grouped publication commits");
                        assert_eq!(publication.objects, vec![expected]);
                    }
                });
            }
        });
        let after = store.io_stats();
        let total = u64::try_from(WRITERS * COMMITS).expect("publication count fits u64");
        let publications = after.publications - before.publications;
        let commits = after.publication_commits - before.publication_commits;
        let syncs = after.segment_syncs - before.segment_syncs;
        assert_eq!(publications, total);
        assert!(
            commits < total,
            "{commits} metadata commits for {total} publications: nothing grouped"
        );
        assert!(
            syncs < total,
            "{syncs} segment syncs for {total} publications: nothing grouped"
        );
        let grouped = barriers(after) - barriers(before);
        let solo_projection = solo * total / SOLO;
        assert!(
            grouped < solo_projection,
            "{grouped} grouped durability barriers for {total} publications; solo projection {solo_projection}"
        );
        drop(store);

        let reopened = reopen(&temp);
        for writer in 0..WRITERS {
            for seq in 0..COMMITS {
                let payload = pseudo(512, seed_of(writer, seq));
                assert_eq!(
                    read_all(&reopened, blob_oid(HashKind::Sha1, &payload)),
                    payload
                );
                let key = format!("refs/heads/w{writer}-{seq}");
                assert_eq!(
                    reopened
                        .fact(FactTable::Refs, key.as_bytes())
                        .expect("read grouped fact"),
                    Some(format!("tip-{writer}-{seq}").into_bytes())
                );
            }
        }
    }

    #[test]
    fn concurrent_claims_on_one_fact_admit_exactly_one_publisher() {
        use std::time::Duration;

        let temp = TempRoot::new("group-conflict");
        let store = Arc::new(create(&temp, HashKind::Sha1));
        store.set_commit_linger(Duration::from_millis(5));
        let outcomes: Vec<Result<Publication, StoreError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4u8)
                .map(|n| {
                    let store = Arc::clone(&store);
                    scope.spawn(move || {
                        let payload = vec![n; 64];
                        let tip = [n];
                        let fact = mutation(
                            FactTable::Refs,
                            b"refs/heads/contested",
                            FactExpectation::Absent,
                            Some(&tip[..]),
                        );
                        store.publish(
                            vec![blob(&store, &payload)],
                            &[fact],
                            EventSource::LocalPush,
                            &EventContext::default(),
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("publisher thread"))
                .collect()
        });
        let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(
            winners, 1,
            "exactly one absent-expectation claim may commit"
        );
        for loser in outcomes.iter().filter_map(|outcome| outcome.as_ref().err()) {
            assert!(
                matches!(loser, StoreError::StaleFact { .. }),
                "a losing claim must fail as stale, got: {loser}"
            );
        }
    }

    fn read_events(store: &Store) -> Vec<(u64, StoreEvent)> {
        let page = store
            .fact_page(
                FactTable::Events,
                None,
                FactPageBudget::new(10_000, usize::MAX),
            )
            .expect("read events");
        assert!(!page.more, "the test writes fewer rows than one page");
        page.rows
            .iter()
            .map(|row| {
                let seq =
                    u64::from_be_bytes(row.key.as_slice().try_into().expect("8-byte event key"));
                let event: StoreEvent = decode_store_event(&row.value).expect("decode event");
                (seq, event)
            })
            .collect()
    }

    fn read_head(store: &Store) -> EventHeadRow {
        let raw = store
            .fact(FactTable::EventHead, EVENT_HEAD_KEY)
            .expect("read head")
            .expect("the head row exists once an event commits");
        decode("event head", &raw).expect("decode head")
    }

    #[test]
    fn events_survive_restart() {
        let temp = TempRoot::new("events-restart");
        let store = create(&temp, HashKind::Sha1);
        let set = [mutation(
            FactTable::Refs,
            b"refs/heads/main",
            FactExpectation::Absent,
            Some(b"v1"),
        )];
        store
            .publish(
                Vec::new(),
                &set,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("publish ref");
        let before = read_events(&store);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].0, 1);
        assert_eq!(before[0].1.name, b"refs/heads/main");
        assert_eq!(before[0].1.old, None);
        assert_eq!(before[0].1.new, Some(b"v1".to_vec()));
        assert_eq!(read_head(&store), EventHeadRow { head: 1, oldest: 1 });
        drop(store);
        let store = reopen(&temp);
        let after = read_events(&store);
        assert_eq!(after, before, "events persist across reopen");
        assert_eq!(read_head(&store), EventHeadRow { head: 1, oldest: 1 });
    }

    #[test]
    fn events_increase_strictly_across_sources_with_attribution() {
        use crate::change::{OperationId, SessionId};
        let temp = TempRoot::new("events-order");
        let store = create(&temp, HashKind::Sha1);
        let lane_context = EventContext {
            operation: Some(OperationId(7)),
            request_id: Some("req-lane".to_string()),
            session: Some(SessionId::from_bytes([3; 16])),
            on_behalf_of: Some("agent-lane".to_string()),
        };
        let lane = [mutation(
            FactTable::Refs,
            b"refs/heads/main",
            FactExpectation::Absent,
            Some(b"v1"),
        )];
        store
            .publish(Vec::new(), &lane, EventSource::Lane, &lane_context)
            .expect("publish lane batch");
        let receive = [mutation(
            FactTable::Refs,
            b"refs/heads/scratch",
            FactExpectation::Absent,
            Some(b"v2"),
        )];
        store
            .publish(
                Vec::new(),
                &receive,
                EventSource::ReceivePack,
                &EventContext::default(),
            )
            .expect("publish receive batch");
        let events = read_events(&store);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert_eq!(events[1].0, 2);
        assert_eq!(events[0].1.source, EventSource::Lane);
        assert_eq!(events[1].1.source, EventSource::ReceivePack);
        assert_eq!(events[0].1.operation, Some(OperationId(7)));
        assert_eq!(events[0].1.request_id.as_deref(), Some("req-lane"));
        assert_eq!(events[0].1.session, Some(SessionId::from_bytes([3; 16])));
        assert_eq!(events[0].1.on_behalf_of.as_deref(), Some("agent-lane"));
        assert_eq!(events[1].1.operation, None);
        assert_eq!(events[1].1.on_behalf_of, None);
        assert_eq!(read_head(&store), EventHeadRow { head: 2, oldest: 1 });
    }

    #[test]
    fn events_sweep_prunes_to_retention_keeping_oldest_current() {
        let temp = TempRoot::new("events-sweep");
        let store = create(&temp, HashKind::Sha1);
        let old_event = StoreEvent {
            name: b"refs/heads/old".to_vec(),
            old: None,
            new: Some(b"v1".to_vec()),
            at: 1_000,
            source: EventSource::Lane,
            operation: None,
            request_id: None,
            session: None,
            on_behalf_of: None,
        };
        let new_event = StoreEvent {
            name: b"refs/heads/new".to_vec(),
            old: None,
            new: Some(b"v2".to_vec()),
            at: 9_000,
            source: EventSource::ReceivePack,
            operation: None,
            request_id: None,
            session: None,
            on_behalf_of: None,
        };
        let facts = [
            FactMutation {
                table: FactTable::Events,
                key: 1_u64.to_be_bytes().to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("event", &old_event).expect("encode")),
            },
            FactMutation {
                table: FactTable::Events,
                key: 2_u64.to_be_bytes().to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("event", &new_event).expect("encode")),
            },
            FactMutation {
                table: FactTable::EventHead,
                key: EVENT_HEAD_KEY.to_vec(),
                expected: FactExpectation::Absent,
                value: Some(
                    encode("event head", &EventHeadRow { head: 2, oldest: 1 }).expect("encode"),
                ),
            },
        ];
        store
            .publish(
                Vec::new(),
                &facts,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("seed events");
        let deletions = store.sweep_events_page(5_000, 10_000).expect("sweep");
        assert_eq!(deletions.len(), 2, "one event row plus the head bump");
        store
            .publish(
                Vec::new(),
                &deletions,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("publish sweep");
        let remaining = read_events(&store);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 2);
        assert_eq!(read_head(&store), EventHeadRow { head: 2, oldest: 2 });
    }

    #[test]
    fn events_sweep_full_page_advances_oldest_past_pruned() {
        let temp = TempRoot::new("events-sweep-full-page");
        let store = create(&temp, HashKind::Sha1);
        let mut facts = Vec::new();
        for seq in 1_u64..=3 {
            let event = StoreEvent {
                name: format!("refs/heads/e{seq}").into_bytes(),
                old: None,
                new: Some(b"v1".to_vec()),
                at: 1_000,
                source: EventSource::Lane,
                operation: None,
                request_id: None,
                session: None,
                on_behalf_of: None,
            };
            facts.push(FactMutation {
                table: FactTable::Events,
                key: seq.to_be_bytes().to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encode("event", &event).expect("encode")),
            });
        }
        facts.push(FactMutation {
            table: FactTable::EventHead,
            key: EVENT_HEAD_KEY.to_vec(),
            expected: FactExpectation::Absent,
            value: Some(
                encode("event head", &EventHeadRow { head: 3, oldest: 1 }).expect("encode"),
            ),
        });
        store
            .publish(
                Vec::new(),
                &facts,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("seed events");
        // The first page prunes every row it holds while more rows
        // remain: oldest must jump past the page, not stay behind it.
        let deletions = store.sweep_events_page(5_000, 2).expect("sweep");
        assert_eq!(deletions.len(), 3, "two event rows plus the head bump");
        store
            .publish(
                Vec::new(),
                &deletions,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("publish sweep");
        assert_eq!(read_head(&store), EventHeadRow { head: 3, oldest: 3 });
        let remaining = read_events(&store);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 3);
    }
}
