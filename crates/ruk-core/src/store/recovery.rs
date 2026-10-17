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
//!    sealed, an intact footer and exactly its committed length);
//! 2. an open segment's uncommitted tail, and only that, is truncated, after
//!    the committed prefix verified;
//! 3. every committed locator is resolved and its object identity verified
//!    with bounded memory, paged so no metadata read spans payload I/O.
//!
//! Any missing or damaged committed byte is [`StoreError::Corrupt`]; the
//! store does not open. Unknown files in the segment directory are never
//! read, repaired, or deleted: a crash can orphan a created segment file and
//! the append owner skips its name instead.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::durability;
use super::guards::{CapturedLink, GenerationRegistry, ObjectSnapshot};
use super::metadata::Metadata;
use super::prepare;
use super::segment::{self, RecordPayload};
use super::spool::{PreparationBudget, Spool};
use super::types::{ObjectLocation, ReadObject, SegmentManifest};
use super::{SEGMENTS_DIR, StoreError};
use crate::ids::{HashKind, Oid};

/// Locators verified per metadata page during recovery.
const VERIFY_PAGE: usize = 256;
/// Buffer in front of segment reads.
const READ_BUFFER: usize = 64 * 1024;

/// A read-side view of one store's committed state.
#[derive(Clone, Copy)]
pub(super) struct Committed<'a> {
    pub(super) root: &'a Path,
    pub(super) kind: HashKind,
    pub(super) meta: &'a Metadata,
    pub(super) budget: &'a Arc<PreparationBudget>,
    pub(super) guards: &'a Arc<GenerationRegistry>,
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

    /// Opens a committed segment file read-only. A missing file is missing
    /// committed bytes, hence corruption.
    fn open_committed(&self, id: u64) -> Result<File, StoreError> {
        File::open(self.segment_path(id)).map_err(|err| missing_is_corrupt(err, id))
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
            BufReader::with_capacity(READ_BUFFER, file),
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

fn missing_is_corrupt(err: io::Error, id: u64) -> StoreError {
    if err.kind() == io::ErrorKind::NotFound {
        return corrupt(format!("committed segment {id} is missing"));
    }
    StoreError::Io(err)
}

/// Verifies every committed segment, truncates uncommitted open-segment
/// tails, then verifies every committed object identity.
pub(super) fn run(committed: &Committed<'_>) -> Result<Recovered, StoreError> {
    let manifests = committed.meta.all_manifests()?;
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
    verify_objects(committed)?;
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
    let mut file = if manifest.sealed {
        committed.open_committed(manifest.id)?
    } else {
        durability::open_existing(&path).map_err(|err| match err {
            StoreError::Io(io_err) => missing_is_corrupt(io_err, manifest.id),
            other => other,
        })?
    };
    let verified = segment::validate_segment_file(
        &mut file,
        manifest.committed_end,
        manifest.records_end,
        manifest.sealed,
    )?;
    if !manifest.sealed && verified.file_len > manifest.committed_end {
        file.set_len(manifest.committed_end)?;
        durability::sync_file(&file)?;
        #[cfg(test)]
        super::crash_tests::crash_at("recovery_after_tail_truncate");
    }
    Ok(verified)
}

/// Verifies every committed object identity, one metadata page at a time.
fn verify_objects(committed: &Committed<'_>) -> Result<(), StoreError> {
    let generation = committed.meta.generation()?;
    let mut after: Option<Oid> = None;
    loop {
        let page = committed.meta.object_page(after.as_ref(), VERIFY_PAGE)?;
        let Some((last, _)) = page.last() else {
            return Ok(());
        };
        after = Some(*last);
        for (oid, location) in &page {
            committed.verify_object(*oid, location, generation)?;
        }
    }
}
