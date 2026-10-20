//! Committed-state verification: verified object reads and fail-closed
//! recovery.
//!
//! Both consumers trust only what committed metadata names. A locator is
//! resolved into a delta chain; every record on the chain is streamed from
//! its segment through a bounded checksum reader, decoded, and identity
//! verified by the preparation decoder before any byte reaches a caller.
//! No redb transaction is held across payload I/O: every metadata lookup
//! opens and drops its own read transaction.
//!
//! Recovery runs once in `Store::open`, before the store serves anything:
//!
//! 1. every non-retired manifest's segment file must exist, hold at least
//!    its committed extent, and contain only valid records (and, when
//!    sealed, an intact footer and exactly its committed length). This
//!    manifest pass runs on every open;
//! 2. an open segment's uncommitted tail, and only that, is truncated, after
//!    the committed prefix verified;
//! 3. every committed locator is resolved and its object identity verified
//!    with bounded memory, paged so no metadata read spans payload I/O —
//!    but only when the stored verified generation does not already cover
//!    the current one (see below).
//!
//! Step 3 is cached, steps 1 and 2 are not. Recovery compares the committed
//! locator generation against the `verified_generation` recorded in
//! metadata by the last successful verification pass. When they match, the
//! object identities were already proven for exactly this committed state
//! and the pass is skipped; after a verification pass succeeds, recovery
//! commits `verified_generation = generation` before returning, so the next
//! open with no intervening publication skips it. Publication advances the
//! generation without marking it verified, so the first open after a
//! publish always pays the full verification: the cost lands on the
//! writer's next open, amortized across the reads that follow.
//!
//! The trade-off is explicit: silent corruption that lands after a
//! generation was verified, and leaves every segment record checksum
//! intact (for example locator-row surgery in the metadata database),
//! evades a cached open. Segment-file damage is still caught on every open
//! by the manifest pass, every served read still verifies the chain it
//! touches, and any generation the cache has not covered is fully
//! verified. Setting `RUK_VERIFY=full` in the environment forces the full
//! object pass on every open, bypassing the cache: the escape hatch for
//! the paranoid and for crash tests that surgically damage committed
//! state after it was verified.
//!
//! Any missing or damaged committed byte found by the passes that run is
//! [`StoreError::Corrupt`]; the store does not open. Unknown files in the
//! segment directory are never read, repaired, or deleted: a crash can
//! orphan a created segment file and the append owner skips its name
//! instead.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::durability;
use super::guards::{CapturedLink, GenerationRegistry, ObjectSnapshot};
use super::metadata::Metadata;
use super::prepare;
use super::segment::{self, PreadReader, RecordPayload};
use super::spool::{PreparationBudget, Spool};
use super::types::{ObjectLocation, ReadObject, SegmentManifest};
use super::{ProfileClock, SEGMENTS_DIR, StoreError, profile_enabled};
use crate::ids::{HashKind, Oid};

/// Locators verified per metadata page during recovery.
const VERIFY_PAGE: usize = 256;
/// Locators collected per parallel verification batch. The batch vector
/// stays near half a megabyte no matter how many objects the store holds,
/// so the parallel pass keeps the old paged pass's bounded memory.
const VERIFY_BATCH: usize = 4096;
/// Largest object-verification fan-out. Sixteen workers use a workstation
/// without spawning a thread per core on large machines; each worker holds
/// at most one transient decode against the shared preparation budget, so
/// the extra residency stays far below the reference 2 GiB ceiling.
const VERIFY_THREADS: usize = 16;
/// Buffer in front of segment reads.
const READ_BUFFER: usize = 64 * 1024;
/// Environment variable forcing the full object identity pass on every
/// open, bypassing the verified-generation cache.
const VERIFY_ENV: &str = "RUK_VERIFY";
/// [`VERIFY_ENV`] value selecting the full pass.
const VERIFY_FULL: &str = "full";

/// Read-only descriptors for committed segments, opened once per segment id.
///
/// `Store::read` used to `File::open` the same segment once per object;
/// this keeps one canonical read-only `File` per segment and hands out
/// clones of its `Arc` instead. Callers must read through [`PreadReader`]
/// (positional reads), never by seeking the shared `File`: its cursor is
/// process-wide and concurrent readers would move it under each other.
///
/// Retirement safety: segment ids are allocated monotonically and never
/// reused, so a cached descriptor can never alias a newer segment; fresh
/// reads reject retired manifests before touching payload I/O, so a cached
/// descriptor for a retired segment is unreachable (a pre-retirement
/// snapshot keeps its own pin through the generation registry, and its
/// `Arc` keeps reading even after eviction). Compaction still evicts on
/// unlink so a cached handle never pins a retired file on platforms where
/// open files cannot be unlinked.
#[derive(Debug, Default)]
pub(super) struct SegmentFileCache {
    files: Mutex<HashMap<u64, Arc<File>>>,
}

impl SegmentFileCache {
    /// The canonical read-only handle for `id`, opening `path` once. A
    /// missing file is missing committed bytes, hence corruption.
    pub(super) fn get_or_open(
        &self,
        id: u64,
        open: impl FnOnce() -> Result<File, StoreError>,
    ) -> Result<Arc<File>, StoreError> {
        let mut files = match self.files.lock() {
            Ok(guard) => guard,
            Err(_) => {
                // A poisoned cache must not refuse reads: serve this one
                // uncached. Correctness never depends on the cache.
                return open().map(Arc::new);
            }
        };
        if let Some(cached) = files.get(&id) {
            return Ok(Arc::clone(cached));
        }
        let file = Arc::new(open()?);
        files.insert(id, Arc::clone(&file));
        Ok(file)
    }

    /// Forgets the cached handle for `id`, if any. Compaction calls this
    /// before unlinking a retired segment file.
    pub(super) fn evict(&self, id: u64) {
        if let Ok(mut files) = self.files.lock() {
            files.remove(&id);
        }
    }
}

/// A read-side view of one store's committed state.
#[derive(Clone, Copy)]
pub(super) struct Committed<'a> {
    pub(super) root: &'a Path,
    pub(super) kind: HashKind,
    pub(super) meta: &'a Metadata,
    pub(super) budget: &'a Arc<PreparationBudget>,
    pub(super) guards: &'a Arc<GenerationRegistry>,
    pub(super) files: &'a SegmentFileCache,
    pub(super) pin: &'a super::pinned::PinnedRoot,
}

/// The open (unsealed) segment recovery verified, ready to resume appends.
#[derive(Clone, Copy, Debug)]
pub(super) struct OpenSegment {
    pub(super) id: u64,
    pub(super) records_end: u64,
    pub(super) records_crc: u32,
}

/// What the append owner needs after a successful recovery.
#[derive(Debug)]
pub(super) struct Recovered {
    /// First segment id above every manifest id; the allocator advances
    /// past unknown orphan files from here.
    pub(super) next_segment_id: u64,
    pub(super) open: Option<OpenSegment>,
}

fn corrupt(detail: String) -> StoreError {
    StoreError::Corrupt(detail)
}

impl Committed<'_> {
    pub(super) fn segment_path(&self, id: u64) -> PathBuf {
        self.root
            .join(SEGMENTS_DIR)
            .join(segment::segment_file_name(id))
    }

    /// The cached read-only handle for a committed segment, opened through
    /// the store pin so a swapped symlink cannot redirect it. A missing
    /// file is missing committed bytes, hence corruption. Callers read
    /// through [`PreadReader`]: the shared cursor is never moved.
    pub(super) fn open_committed(&self, id: u64) -> Result<Arc<File>, StoreError> {
        let rel = super::pinned::segment_rel(id);
        self.files.get_or_open(id, || {
            self.pin
                .open_read(&rel)
                .map_err(|err| missing_is_corrupt(err, id))
        })
    }

    pub(super) fn check_width(&self, oid: Oid) -> Result<(), StoreError> {
        if oid.kind() == self.kind {
            return Ok(());
        }
        Err(StoreError::ObjectFormat(format!(
            "object id {oid} is not a {} digest",
            self.kind
        )))
    }

    /// Reads one committed object: registers a physical reader guard, captures
    /// a complete delta chain and required manifests in ONE metadata transaction,
    /// drops the transaction, and decodes the payload while holding the guard.
    pub(super) fn read(&self, oid: Oid) -> Result<ReadObject, StoreError> {
        self.check_width(oid)?;
        let guard = self.guards.register();
        let snapshot = self.meta.snapshot_object_chain(self.kind, &oid)?;
        let bytes = self.load_snapshot(&snapshot)?;
        drop(guard);
        Ok(ReadObject {
            kind: snapshot.target_kind(),
            bytes,
            depth: snapshot.target_depth(),
        })
    }

    /// Decodes the whole chain of a captured snapshot, root first, and returns
    /// the target's decoded bytes.
    pub(super) fn load_snapshot(&self, snapshot: &ObjectSnapshot) -> Result<Spool, StoreError> {
        let mut previous: Option<Spool> = None;
        for link in snapshot.links.iter().rev() {
            let base = match (previous.as_ref(), link.location.base) {
                (Some(spool), Some(base_oid)) => Some((base_oid, spool.view())),
                (None, None) => None,
                _ => {
                    return Err(corrupt(format!(
                        "delta chain of {} is inconsistent with its base",
                        link.oid
                    )));
                }
            };
            let decoded = self.decode_link_from_snapshot(link, base)?;
            previous = Some(decoded);
        }
        previous.ok_or_else(|| corrupt(format!("delta chain of {} is empty", snapshot.target_oid)))
    }

    /// Streams one record, verifies its framing and checksum against the captured
    /// manifest, and decodes it.
    fn decode_link_from_snapshot(
        &self,
        link: &CapturedLink,
        base: Option<(Oid, super::spool::SpoolView<'_>)>,
    ) -> Result<Spool, StoreError> {
        let location = &link.location;
        let manifest = &link.manifest;
        let oid = &link.oid;

        let end = location
            .offset
            .checked_add(location.record_len)
            .filter(|end| *end <= manifest.records_end)
            .ok_or_else(|| {
                corrupt(format!(
                    "object {oid} record [{}, +{}) leaves segment {} record extent {}",
                    location.offset, location.record_len, manifest.id, manifest.records_end
                ))
            })?;
        let file = self.open_committed(location.segment)?;
        let mut payload = RecordPayload::open(
            BufReader::with_capacity(READ_BUFFER, PreadReader::new(&file)),
            location.offset,
            manifest.records_end,
        )?;
        let header = *payload.header();
        if header.kind != location.kind
            || header.record_len() != location.record_len
            || (header.encoding == super::types::Encoding::Delta) != location.base.is_some()
        {
            return Err(corrupt(format!(
                "record at {} (ending {end}) in segment {} disagrees with the locator of {oid}",
                location.offset, manifest.id
            )));
        }
        let decoded = prepare::decode_record(
            self.kind,
            location.kind,
            oid,
            header.encoding,
            &mut payload,
            u64::from(header.payload_len),
            location.decoded_len,
            base,
            self.budget,
            self.root,
        )?;
        payload.finish()?;
        Ok(decoded)
    }

    /// Verifies one committed object end to end and drops the bytes.
    fn verify_object(
        &self,
        oid: Oid,
        location: &ObjectLocation,
        generation: u64,
    ) -> Result<(), StoreError> {
        self.check_width(oid)
            .map_err(|err| corrupt(err.to_string()))?;
        if location.generation > generation {
            return Err(corrupt(format!(
                "object {oid} was published at generation {} above the store generation {generation}",
                location.generation
            )));
        }
        self.read(oid).map(drop)
    }
}

/// Whether the environment demands the full object identity pass on this
/// open regardless of the verification cache.
fn full_verify_forced() -> bool {
    std::env::var(VERIFY_ENV).is_ok_and(|value| value == VERIFY_FULL)
}

fn missing_is_corrupt(err: io::Error, id: u64) -> StoreError {
    if err.kind() == io::ErrorKind::NotFound {
        return corrupt(format!("committed segment {id} is missing"));
    }
    StoreError::Io(err)
}

/// Verifies every committed segment, truncates uncommitted open-segment
/// tails, then verifies every committed object identity.
pub(super) fn run(committed: &Committed<'_>) -> Result<Recovered, StoreError> {
    let profiling = profile_enabled();
    let mut clock = ProfileClock::now(profiling);
    let manifests = committed.meta.all_manifests()?;
    let manifests_ms = clock.elapsed_ms();
    clock = ProfileClock::now(profiling);
    let mut next_segment_id = 0_u64;
    let mut open: Option<OpenSegment> = None;
    for manifest in &manifests {
        next_segment_id = next_segment_id.max(
            manifest
                .id
                .checked_add(1)
                .ok_or_else(|| StoreError::Capacity("segment id space exhausted".to_owned()))?,
        );
        if manifest.retired {
            continue;
        }
        let verified = verify_segment(committed, manifest)?;
        if manifest.sealed {
            continue;
        }
        let resumed = OpenSegment {
            id: manifest.id,
            records_end: manifest.records_end,
            records_crc: verified.records_crc,
        };
        if open.replace(resumed).is_some() {
            return Err(corrupt(
                "more than one open segment is recorded in the manifest".to_owned(),
            ));
        }
    }
    let segments_ms = clock.elapsed_ms();
    clock = ProfileClock::now(profiling);
    let generation = committed.meta.generation()?;
    let cached = committed.meta.verified_generation()?;
    let gen_ms = clock.elapsed_ms();
    clock = ProfileClock::now(profiling);
    let mut verify_ms = 0.0;
    let mut stamp_ms = 0.0;
    let skipped = !full_verify_forced() && cached == Some(generation);
    if !skipped {
        verify_objects(committed, generation)?;
        verify_ms = clock.elapsed_ms();
        clock = ProfileClock::now(profiling);
        committed.meta.set_verified_generation(generation)?;
        stamp_ms = clock.elapsed_ms();
    }
    if profiling {
        eprintln!(
            "[ruk-profile] recovery manifests={:.2}ms segments={:.2}ms gen={:.2}ms verify={:.2}ms stamp={:.2}ms skipped={} nmanifests={}",
            manifests_ms,
            segments_ms,
            gen_ms,
            verify_ms,
            stamp_ms,
            skipped,
            manifests.len(),
        );
    }
    Ok(Recovered {
        next_segment_id,
        open,
    })
}

/// Verifies one segment file against its manifest. An open segment's
/// uncommitted tail is truncated only after its committed prefix verified;
/// sealed and short files are never altered.
fn verify_segment(
    committed: &Committed<'_>,
    manifest: &SegmentManifest,
) -> Result<segment::VerifiedSegment, StoreError> {
    let path = committed.segment_path(manifest.id);
    if manifest.sealed {
        // Sealed segments never change, so the cached read-only handle is
        // exact; workers read through their own positional readers, keeping
        // the shared cursor untouched.
        let cached = committed.open_committed(manifest.id)?;
        return segment::validate_segment_file_concurrent(
            &cached,
            manifest.committed_end,
            manifest.records_end,
            manifest.sealed,
        )
        .map_err(StoreError::from);
    }
    // The open segment needs a read-write handle for tail truncation; it
    // must never come from the read-only cache.
    let file = durability::open_existing(&path).map_err(|err| match err {
        StoreError::Io(io_err) => missing_is_corrupt(io_err, manifest.id),
        other => other,
    })?;
    let verified = segment::validate_segment_file_concurrent(
        &file,
        manifest.committed_end,
        manifest.records_end,
        manifest.sealed,
    )?;
    if verified.file_len > manifest.committed_end {
        file.set_len(manifest.committed_end)?;
        durability::sync_file(&file)?;
        #[cfg(test)]
        super::crash_tests::crash_at("recovery_after_tail_truncate");
    }
    Ok(verified)
}

/// Verifies every committed object identity. Callers invoke this only for
/// generations the verification cache does not cover; on success they
/// record the generation as verified.
///
/// Locators are collected with the same fast redb scan as before, so still
/// no metadata read spans payload I/O, in batches of at most
/// [`VERIFY_BATCH`] rows whose verification fans out across at most
/// [`VERIFY_THREADS`] scoped workers. Sharing `committed` is safe: every
/// metadata lookup opens and drops its own read transaction, guard
/// registration is a short mutex critical section, and each worker holds at
/// most one transient decode. Workers that observe another worker's failure
/// stop early; the first failure decides the result.
fn verify_objects(committed: &Committed<'_>, generation: u64) -> Result<(), StoreError> {
    let mut after: Option<Oid> = None;
    loop {
        let mut batch = Vec::new();
        loop {
            let page = committed.meta.object_page(after.as_ref(), VERIFY_PAGE)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            after = Some(*last);
            batch.extend(page);
            if batch.len() >= VERIFY_BATCH {
                break;
            }
        }
        if batch.is_empty() {
            return Ok(());
        }
        verify_batch(committed, &batch, generation)?;
    }
}

/// Verifies one bounded batch of collected locators across at most
/// [`VERIFY_THREADS`] scoped workers.
fn verify_batch(
    committed: &Committed<'_>,
    locators: &[(Oid, ObjectLocation)],
    generation: u64,
) -> Result<(), StoreError> {
    let threads = std::thread::available_parallelism()
        .map(|width| width.get())
        .unwrap_or(1)
        .min(VERIFY_THREADS)
        .min(locators.len().max(1));
    if threads <= 1 {
        for (oid, location) in locators {
            committed.verify_object(*oid, location, generation)?;
        }
        return Ok(());
    }
    let cancel = AtomicBool::new(false);
    let cancelled = &cancel;
    let chunk = locators.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for batch in locators.chunks(chunk) {
            handles.push(scope.spawn(move || {
                for (oid, location) in batch {
                    if cancelled.load(Ordering::SeqCst) {
                        return None;
                    }
                    if let Err(err) = committed.verify_object(*oid, location, generation) {
                        cancelled.store(true, Ordering::SeqCst);
                        return Some(err);
                    }
                }
                None
            }));
        }
        let mut first: Option<StoreError> = None;
        for handle in handles {
            match handle.join() {
                Ok(result) => {
                    if first.is_none() {
                        first = result;
                    }
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        first.map_or(Ok(()), Err)
    })
}
