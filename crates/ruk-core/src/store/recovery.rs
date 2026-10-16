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
use super::metadata::Metadata;
use super::prepare;
use super::segment::{self, RecordPayload};
use super::spool::{PreparationBudget, Spool};
use super::types::{ObjectLocation, ReadObject, SegmentManifest};
use super::{MAX_DELTA_DEPTH, SEGMENTS_DIR, StoreError};
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

    fn check_width(&self, oid: Oid) -> Result<(), StoreError> {
        if oid.kind() == self.kind {
            return Ok(());
        }
        Err(StoreError::ObjectFormat(format!(
            "object id {oid} is not a {} digest",
            self.kind
        )))
    }

    /// Reads one committed object: locator lookup, then verified decode of
    /// its delta chain.
    pub(super) fn read(&self, oid: Oid) -> Result<ReadObject, StoreError> {
        self.check_width(oid)?;
        let location = self
            .meta
            .get_object(&oid)?
            .ok_or_else(|| StoreError::NotFound(oid.to_hex()))?;
        let bytes = self.load(oid, &location)?;
        Ok(ReadObject {
            kind: location.kind,
            bytes,
            depth: location.depth,
        })
    }

    /// Resolves the base chain of `location`, target first, root last.
    ///
    /// Each base must exist, share the kind, and sit exactly one level
    /// shallower; depth therefore strictly decreases, which rules out cycles
    /// and bounds the walk by [`MAX_DELTA_DEPTH`].
    fn chain(
        &self,
        oid: Oid,
        location: &ObjectLocation,
    ) -> Result<Vec<(Oid, ObjectLocation)>, StoreError> {
        let mut chain = vec![(oid, location.clone())];
        let mut cursor = (oid, location.base, location.depth, location.kind);
        loop {
            let (child, base, depth, kind) = cursor;
            let Some(base_oid) = base else {
                if depth != 0 {
                    return Err(corrupt(format!(
                        "non-delta object {child} records chain depth {depth}"
                    )));
                }
                return Ok(chain);
            };
            if depth == 0 || depth > MAX_DELTA_DEPTH {
                return Err(corrupt(format!(
                    "delta object {child} records chain depth {depth} outside 1..={MAX_DELTA_DEPTH}"
                )));
            }
            let base_location = self.meta.get_object(&base_oid)?.ok_or_else(|| {
                corrupt(format!(
                    "committed delta {child} references missing base {base_oid}"
                ))
            })?;
            if base_location.kind != kind || base_location.depth.checked_add(1) != Some(depth) {
                return Err(corrupt(format!(
                    "delta {child} (depth {depth}) disagrees with its base {base_oid} (depth {}, kind {:?})",
                    base_location.depth, base_location.kind
                )));
            }
            cursor = (
                base_oid,
                base_location.base,
                base_location.depth,
                base_location.kind,
            );
            chain.push((base_oid, base_location));
        }
    }

    /// Decodes and verifies the whole chain, root first, and returns the
    /// target's decoded bytes.
    fn load(&self, oid: Oid, location: &ObjectLocation) -> Result<Spool, StoreError> {
        let chain = self.chain(oid, location)?;
        let mut previous: Option<Spool> = None;
        for (link_oid, link) in chain.iter().rev() {
            let base = match (previous.as_ref(), link.base) {
                (Some(spool), Some(base_oid)) => Some((base_oid, spool.view())),
                (None, None) => None,
                _ => {
                    return Err(corrupt(format!(
                        "delta chain of {link_oid} is inconsistent with its base"
                    )));
                }
            };
            let decoded = self.decode_link(link_oid, link, base)?;
            previous = Some(decoded);
        }
        previous.ok_or_else(|| corrupt(format!("delta chain of {oid} is empty")))
    }

    /// Streams one record, verifies its framing and checksum, and decodes
    /// it. The decoder verifies the identity; the full-record checksum is
    /// verified last because a decoder may stop before the payload ends.
    fn decode_link(
        &self,
        oid: &Oid,
        location: &ObjectLocation,
        base: Option<(Oid, super::spool::SpoolView<'_>)>,
    ) -> Result<Spool, StoreError> {
        let manifest = self.meta.manifest(location.segment)?.ok_or_else(|| {
            corrupt(format!(
                "object {oid} locates unmanifested segment {}",
                location.segment
            ))
        })?;
        if manifest.retired {
            return Err(corrupt(format!(
                "object {oid} locates retired segment {}",
                manifest.id
            )));
        }
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
        self.load(oid, location).map(drop)
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
