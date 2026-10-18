//! Copying compaction: live-object rewrite into fresh segments.
//!
//! Every committed object is live: no object-deletion path exists (retention
//! sweeps delete only fact rows), so the reachable set is the whole objects
//! table and compaction merges sealed segments into few while reclaiming
//! retired files. One redb transaction swaps every locator, retires every
//! source manifest, and advances the generation, so the commit is the single
//! linearization point: readers snapshot locators either fully before or
//! fully after the swap, never mixed.
//!
//! Concurrency (steady-state consistency via locks): bulk copying runs
//! without the writer lock against immutable committed prefixes, so
//! publications proceed; the swap takes the writer lock, which linearizes
//! compaction against [`Store::publish`]. The session-open segment (active
//! or recovered) is excluded from the retire set, so publications always
//! land outside the rewrite and no root insertion is ever lost or left
//! pointing at a retired segment. A rescan under the final lock copies any
//! straggler before the swap as defense in depth. Whole-run serialization
//! across concurrent compactions comes from a dedicated compaction mutex,
//! keeping two rewrites from retiring each other's fresh segments.

use std::collections::{HashMap, HashSet};
use std::fs::File;

use super::durability;
use super::metadata::PublicationTxn;
use super::segment::{self, RecordPayload, SegmentWriter};
use super::types::{Encoding, ObjectLocation, SegmentManifest};
use super::{Store, SEGMENTS_DIR, StoreError};
use crate::ids::Oid;

/// What one [`Store::compact`] pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactionStats {
    /// Live objects copied into fresh segments.
    pub objects_copied: usize,
    /// Record bytes (header plus payload) copied.
    pub bytes_copied: u64,
    /// Fresh segments created.
    pub segments_created: usize,
    /// Source segments retired in the swap transaction.
    pub segments_retired: usize,
    /// Retired segment files physically unlinked.
    pub segments_unlinked: usize,
    /// Bytes of unlinked segment files.
    pub bytes_freed: u64,
}

impl CompactionStats {
    /// True when the pass created segments or unlinked files. A false value
    /// means the caller should skip any follow-up lane publication.
    #[must_use]
    pub fn did_work(&self) -> bool {
        self.segments_created > 0 || self.segments_unlinked > 0
    }
}

/// One fresh segment being filled.
struct FreshSegment {
    id: u64,
    writer: SegmentWriter<File>,
}

/// Copied bytes staged for the swap transaction.
#[derive(Default)]
struct Staged {
    segments: Vec<FreshSegment>,
    current: Option<FreshSegment>,
    copied: HashMap<Oid, ObjectLocation>,
    bytes_copied: u64,
}

impl Store {
    /// Merges sealed segments' objects into fresh segments and reclaims
    /// retired files.
    ///
    /// Objects are copied verbatim (kind, encoding, delta base, and depth
    /// preserved); only segment ids and offsets change. A single redb
    /// transaction replaces every locator, retires every source manifest,
    /// and advances the generation. Retired files unlink only when no live
    /// reader pins them; the rest stay retired-but-present for a later pass.
    ///
    /// The session-open segment is never rewritten, so an empty retire set
    /// takes only the reclaim path. Orphaned fresh files from a failed pass
    /// carry no manifest row: recovery skips them and the id allocator moves
    /// past their names.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for committed damage (which latches
    /// quarantine, like any committed read); [`StoreError::Io`] for staged
    /// file failures, which leave the writer usable; an ambiguous swap
    /// failure closes the writer exactly like publication.
    pub fn compact(&self) -> Result<CompactionStats, StoreError> {
        self.refuse_if_quarantined()?;
        let _serial = self.compaction_lock.lock().map_err(|_| {
            StoreError::WriterClosed("compaction lock poisoned by a panic".to_owned())
        })?;
        // No reader pin is needed here: this pass is the only unlinker and
        // whole passes serialize on the compaction lock, so no retired
        // file this pass copies from can vanish under it. Live external
        // readers still defer each unlink through the generation registry.
        self.compact_guarded()
    }

    fn compact_guarded(&self) -> Result<CompactionStats, StoreError> {
        let manifests = self.observe(self.meta.all_manifests())?;
        let generation = self.observe(self.meta.generation())?;
        // The session-open segment stays writable for the whole pass, so it
        // can never join the retire set: publications land there or on ids
        // minted after this snapshot, both outside the rewrite.
        let (target, open) = {
            let writer = self.lock_writer()?;
            if let Some(reason) = writer.closed.as_ref() {
                return Err(StoreError::WriterClosed(reason.clone()));
            }
            let mut open = HashSet::new();
            open.extend(writer.active.as_ref().map(|active| active.id));
            open.extend(writer.resume.as_ref().map(|resume| resume.id));
            (writer.target_bytes(), open)
        };
        let mut live: HashMap<u64, SegmentManifest> = HashMap::new();
        let mut previously_retired: Vec<SegmentManifest> = Vec::new();
        for manifest in manifests {
            if manifest.retired {
                previously_retired.push(manifest);
            } else if !open.contains(&manifest.id) {
                live.insert(manifest.id, manifest);
            }
        }
        let mut stats = self.reclaim_files(&previously_retired, generation)?;
        let retire: HashSet<u64> = live.keys().copied().collect();
        // One sealed segment rewrites to itself: no garbage exists inside
        // a segment (objects are never deleted), so merging needs at
        // least two sources to free anything.
        if retire.len() < 2 {
            return Ok(stats);
        }
        let segments_dir = self.root.join(SEGMENTS_DIR);
        let mut staged = Staged::default();
        let mut candidates: Vec<(Oid, ObjectLocation, u64)> = Vec::new();
        let mut candidate_bytes: u64 = 0;
        for (oid, location) in self.page_all_objects()? {
            if !retire.contains(&location.segment) {
                continue;
            }
            let records_end = live
                .get(&location.segment)
                .map(|manifest| manifest.records_end)
                .unwrap_or(0);
            stats_add(&mut candidate_bytes, location.record_len)?;
            candidates.push((oid, location, records_end));
        }
        // Rewriting N segments into N or more fresh ones frees nothing and
        // never converges, so only merge when packing estimates fewer
        // fresh segments than sources. Reclaim still runs below.
        let retire_len = u64::try_from(retire.len())
            .map_err(|_| StoreError::Capacity("segment count overflows u64".to_owned()))?;
        let fresh_needed = candidate_bytes.div_ceil(target).max(1);
        if candidates.is_empty() || fresh_needed >= retire_len {
            return Ok(stats);
        }
        for (oid, location, records_end) in &candidates {
            let mut alloc = || self.create_segment_file(&segments_dir);
            self.copy_object(
                &segments_dir,
                target,
                &mut staged,
                &mut alloc,
                *oid,
                location,
                *records_end,
            )?;
        }

        let new_generation = self.swap_segments(&segments_dir, target, &mut staged, &retire)?;
        stats.objects_copied = staged.copied.len();
        stats.bytes_copied = staged.bytes_copied;
        stats.segments_created = staged.segments.len();
        stats.segments_retired = retire.len();

        let retired_manifests: Vec<SegmentManifest> = retire
            .iter()
            .filter_map(|id| live.get(id))
            .map(|manifest| SegmentManifest {
                retired: true,
                generation: new_generation,
                ..manifest.clone()
            })
            .collect();
        let freed = self.reclaim_files(&retired_manifests, new_generation)?;
        stats.segments_unlinked += freed.segments_unlinked;
        stats.bytes_freed += freed.bytes_freed;
        Ok(stats)
    }

    /// Every committed object in raw-digest order, paged so no read
    /// transaction spans payload I/O.
    fn page_all_objects(&self) -> Result<Vec<(Oid, ObjectLocation)>, StoreError> {
        let mut objects = Vec::new();
        let mut after: Option<Oid> = None;
        loop {
            let page = self.observe(self.meta.object_page(after.as_ref(), 1024))?;
            if page.is_empty() {
                return Ok(objects);
            }
            after = page.last().map(|(oid, _)| *oid);
            objects.extend(page);
        }
    }

    /// Copies one committed record into the staged fresh segments,
    /// verifying framing and checksum against its locator. Staged-file
    /// failures are plain I/O errors: nothing committed, writer untouched.
    fn copy_object(
        &self,
        segments_dir: &std::path::Path,
        target: u64,
        staged: &mut Staged,
        alloc: &mut impl FnMut() -> Result<FreshSegment, StoreError>,
        oid: Oid,
        location: &ObjectLocation,
        records_end: u64,
    ) -> Result<(), StoreError> {
        if staged.copied.contains_key(&oid) {
            return Ok(());
        }
        let path = segments_dir.join(segment::segment_file_name(location.segment));
        let opened = File::open(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                StoreError::Corrupt(format!(
                    "segment {} file is missing committed bytes of object {oid}",
                    location.segment
                ))
            } else {
                StoreError::Io(err)
            }
        })?;
        let header = RecordPayload::open(opened, location.offset, records_end)
            .map(|payload| *payload.header())
            .map_err(|err| self.compact_record_error(err, location.segment, &oid))?;
        if header.kind != location.kind
            || header.record_len() != location.record_len
            || (header.encoding == Encoding::Delta) != location.base.is_some()
        {
            return Err(self.latch_corrupt(format!(
                "record at offset {} in segment {} disagrees with the locator of {oid}",
                location.offset, location.segment
            )));
        }
        // First pass: verify the checksum and learn the payload-only CRC
        // the fresh framing needs. Second pass streams the verified bytes.
        let verify = File::open(&path).map_err(StoreError::Io)?;
        let payload_crc = RecordPayload::open(verify, location.offset, records_end)
            .and_then(|payload| payload.finish_with_payload_crc())
            .map_err(|err| self.compact_record_error(err, location.segment, &oid))?;
        let record_len = header.record_len();
        let needs_roll = staged.current.as_ref().is_some_and(|current| {
            current.writer.records_end() > 0 && !current.writer.fits_sized(record_len, target)
        });
        if needs_roll {
            self.seal_current(staged)?;
        }
        if staged.current.is_none() {
            staged.current = Some(alloc()?);
        }
        let current = staged.current.as_mut().ok_or_else(|| {
            StoreError::Capacity("compaction could not allocate a fresh segment".to_owned())
        })?;
        let source = File::open(&path).map_err(StoreError::Io)?;
        let mut payload = RecordPayload::open(source, location.offset, records_end)
            .map_err(|err| self.compact_record_error(err, location.segment, &oid))?;
        let appended = current
            .writer
            .append(
                header.kind,
                header.encoding,
                u64::from(header.payload_len),
                payload_crc,
                &mut payload,
            )
            .map_err(StoreError::from)?;
        payload
            .finish()
            .map_err(|err| self.compact_record_error(err, location.segment, &oid))?;
        let placed = (current.id, appended.offset, appended.record_len);
        let seal_after = current.writer.records_end() > target;
        if seal_after {
            self.seal_current(staged)?;
        }
        staged.copied.insert(
            oid,
            ObjectLocation {
                kind: location.kind,
                decoded_len: location.decoded_len,
                segment: placed.0,
                offset: placed.1,
                record_len: placed.2,
                generation: 0,
                base: location.base,
                depth: location.depth,
            },
        );
        stats_add(&mut staged.bytes_copied, appended.record_len)?;
        Ok(())
    }

    /// Maps a segment error to quarantine-latching corruption or plain
    /// storage failure. Committed framing damage latches like any committed
    /// read; staged I/O trouble stays local.
    fn compact_record_error(
        &self,
        err: segment::SegmentError,
        segment_id: u64,
        oid: &Oid,
    ) -> StoreError {
        match err {
            segment::SegmentError::Corrupt(detail) => self.latch_corrupt(format!(
                "segment {segment_id} record of object {oid} is damaged: {detail}"
            )),
            other => StoreError::from(other),
        }
    }

    fn seal_current(&self, staged: &mut Staged) -> Result<(), StoreError> {
        let Some(mut current) = staged.current.take() else {
            return Ok(());
        };
        current.writer.seal().map_err(StoreError::from)?;
        staged.segments.push(current);
        Ok(())
    }

    /// Creates one fresh segment file exclusively, advancing past names a
    /// racing publication won. Ids reserve under brief locks.
    fn create_segment_file(
        &self,
        segments_dir: &std::path::Path,
    ) -> Result<FreshSegment, StoreError> {
        let mut take_id = || self.alloc_segment_id();
        self.create_segment_file_lockfree(segments_dir, &mut take_id)
    }

    /// Reserves one segment id under a brief writer lock.
    fn alloc_segment_id(&self) -> Result<u64, StoreError> {
        let mut writer = self.lock_writer()?;
        if let Some(reason) = writer.closed.as_ref() {
            return Err(StoreError::WriterClosed(reason.clone()));
        }
        let id = writer.next_segment_id;
        writer.next_segment_id = id
            .checked_add(1)
            .ok_or_else(|| StoreError::Capacity("segment id space exhausted".to_owned()))?;
        Ok(id)
    }

    /// Creates one fresh segment file exclusively from caller-supplied ids,
    /// skipping names an orphaned file already owns. Never touches the
    /// writer lock, so the locked swap can allocate without deadlock;
    /// skipped orphans stay unknown files recovery ignores.
    fn create_segment_file_lockfree(
        &self,
        segments_dir: &std::path::Path,
        take_id: &mut impl FnMut() -> Result<u64, StoreError>,
    ) -> Result<FreshSegment, StoreError> {
        loop {
            let id = take_id()?;
            let path = segments_dir.join(segment::segment_file_name(id));
            match durability::create_file_published(&path) {
                Ok(file) => {
                    let writer = SegmentWriter::fresh(file).map_err(StoreError::from)?;
                    return Ok(FreshSegment { id, writer });
                }
                Err(StoreError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Under the writer lock: copies stragglers published during the
    /// unlocked copy, seals and syncs every fresh segment, then commits
    /// the locator swap, source retirements, and generation advance in one
    /// transaction. Returns the new generation. Any failure after the lock
    /// closes the writer, mirroring publication.
    fn swap_segments(
        &self,
        segments_dir: &std::path::Path,
        target: u64,
        staged: &mut Staged,
        retire: &HashSet<u64>,
    ) -> Result<u64, StoreError> {
        let mut writer = self.lock_writer()?;
        self.refuse_if_quarantined()?;
        if let Some(reason) = writer.closed.as_ref() {
            return Err(StoreError::WriterClosed(reason.clone()));
        }
        let outcome = self.swap_inner(segments_dir, target, staged, retire, &mut writer);
        match outcome {
            Ok(generation) => Ok(generation),
            Err(err) => {
                writer.closed = Some(format!(
                    "compaction failed after durable work began; reopen the store to run recovery ({err})"
                ));
                Err(err)
            }
        }
    }

    /// The locked swap body. Straggler copies stay under the lock so no
    /// publication slips between the final rescan and the commit; the bulk
    /// copy already ran unlocked, so only racing publications are copied
    /// here. Fresh ids allocate from the held lock, never re-locking.
    fn swap_inner(
        &self,
        segments_dir: &std::path::Path,
        target: u64,
        staged: &mut Staged,
        retire: &HashSet<u64>,
        writer: &mut super::WriterState,
    ) -> Result<u64, StoreError> {
        let mut next_id = writer.next_segment_id;
        let mut take_id = || {
            let id = next_id;
            next_id = id
                .checked_add(1)
                .ok_or_else(|| StoreError::Capacity("segment id space exhausted".to_owned()))?;
            Ok(id)
        };
        for (oid, location) in self.page_all_objects()? {
            if !retire.contains(&location.segment) || staged.copied.contains_key(&oid) {
                continue;
            }
            let stored = self
                .observe(self.meta.manifest(location.segment))?
                .ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "object {oid} locates unmanifested segment {}",
                        location.segment
                    ))
                })?;
            let mut alloc = || self.create_segment_file_lockfree(segments_dir, &mut take_id);
            self.copy_object(
                segments_dir,
                target,
                staged,
                &mut alloc,
                oid,
                &location,
                stored.records_end,
            )?;
        }
        writer.next_segment_id = next_id.max(writer.next_segment_id);
        self.seal_current(staged)?;
        if let Some(current) = staged.current.take() {
            let mut current = current;
            current.writer.seal().map_err(StoreError::from)?;
            staged.segments.push(current);
        }
        for fresh in &staged.segments {
            durability::sync_file(fresh.writer.get_ref())?;
        }
        if !staged.segments.is_empty() {
            super::sync_entries(segments_dir)?;
        }
        let new_generation = self.observe(self.meta.generation())?.checked_add(1).ok_or_else(|| {
            StoreError::Capacity("locator generation exhausted".to_owned())
        })?;
        let txn = self.observe(self.meta.begin_publication(&[]))?;
        self.stage_swap(&txn, staged, retire, new_generation)?;
        self.observe(txn.commit())?;
        self.guards.advance_published_generation(new_generation);
        Ok(new_generation)
    }

    /// Records the swap in the open transaction: moved locators, fresh
    /// manifests, and retired source manifests.
    fn stage_swap(
        &self,
        txn: &PublicationTxn,
        staged: &Staged,
        retire: &HashSet<u64>,
        new_generation: u64,
    ) -> Result<(), StoreError> {
        txn.set_generation(new_generation)?;
        for (oid, location) in &staged.copied {
            txn.replace_object(
                oid,
                &ObjectLocation {
                    generation: new_generation,
                    ..location.clone()
                },
            )?;
        }
        for fresh in &staged.segments {
            txn.upsert_manifest(&SegmentManifest {
                id: fresh.id,
                committed_end: fresh.writer.committed_end(),
                records_end: fresh.writer.records_end(),
                sealed: true,
                retired: false,
                generation: new_generation,
            })?;
        }
        for id in retire {
            let Some(stored) = self.observe(self.meta.manifest(*id))? else {
                continue;
            };
            txn.upsert_manifest(&SegmentManifest {
                retired: true,
                generation: new_generation,
                ..stored
            })?;
        }
        Ok(())
    }

    /// Unlinks retired segment files no live reader pins, summing freed
    /// bytes. Best effort per file: an unlink failure leaves the
    /// retired-but-present row for a later pass, never an error.
    fn reclaim_files(
        &self,
        retired: &[SegmentManifest],
        retired_generation: u64,
    ) -> Result<CompactionStats, StoreError> {
        let mut stats = CompactionStats::default();
        for manifest in retired {
            if !self
                .guards
                .is_segment_retired_ready_for_unlink(retired_generation.max(manifest.generation))
            {
                continue;
            }
            let path = self
                .root
                .join(SEGMENTS_DIR)
                .join(segment::segment_file_name(manifest.id));
            let len = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                stats.segments_unlinked += 1;
                stats_add(&mut stats.bytes_freed, len)?;
            }
        }
        Ok(stats)
    }
}

fn stats_add(total: &mut u64, amount: u64) -> Result<(), StoreError> {
    *total = total.checked_add(amount).ok_or_else(|| {
        StoreError::Capacity("compaction byte accounting overflows u64".to_owned())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::ids::HashKind;
    use crate::store::types::ObjectKind;
    use crate::store::{PreparationBudget, Store};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-compact-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create the test parent directory");
            Self(dir)
        }

        fn store_dir(&self) -> std::path::PathBuf {
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

    fn create(temp: &TempRoot) -> Store {
        Store::create(&temp.store_dir(), HashKind::Sha1, budget()).expect("create store")
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

    fn publish_blob(store: &Store, bytes: &[u8]) -> Oid {
        let len = u64::try_from(bytes.len()).expect("length fits u64");
        let prepared = store
            .prepare(ObjectKind::Blob, len, bytes, None)
            .expect("prepare blob");
        let oid = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish blob");
        oid
    }

    fn read_all(store: &Store, oid: Oid) -> Vec<u8> {
        let mut object = store.read(oid).expect("read object");
        let mut bytes = Vec::new();
        object
            .bytes
            .read_to_end(&mut bytes)
            .expect("read spool");
        bytes
    }

    fn segment_count(store: &Store) -> usize {
        store
            .meta
            .all_manifests()
            .expect("list manifests")
            .iter()
            .filter(|manifest| !manifest.retired)
            .count()
    }

    #[test]
    fn single_segment_compact_is_a_reclaim_only_no_op() {
        let temp = TempRoot::new("noop");
        let store = create(&temp);
        let bytes = pseudo(64, 7);
        let oid = publish_blob(&store, &bytes);
        let stats = store.compact().expect("compact");
        assert!(!stats.did_work(), "one segment has nothing to merge");
        assert_eq!(read_all(&store, oid), bytes);
    }

    #[test]
    fn merge_preserves_every_object_and_retires_sources() {
        let temp = TempRoot::new("merge");
        let store = create(&temp);
        store.set_segment_target_for_tests(1024);
        let mut expected: HashMap<Oid, Vec<u8>> = HashMap::new();
        for index in 0..12_u64 {
            let bytes = pseudo(300, 1000 + index);
            let oid = publish_blob(&store, &bytes);
            expected.insert(oid, bytes);
        }
        let before = segment_count(&store);
        assert!(before >= 2, "tiny target must build segments, saw {before}");
        let generation_before = store.meta.generation().expect("generation");
        let open_id = store
            .meta
            .all_manifests()
            .expect("list manifests")
            .into_iter()
            .find(|manifest| !manifest.sealed && !manifest.retired)
            .map(|manifest| manifest.id);
        let retired_objects = expected
            .keys()
            .filter(|oid| {
                store
                    .meta
                    .get_object(oid)
                    .expect("locator")
                    .is_some_and(|location| Some(location.segment) != open_id)
            })
            .count();
        assert!(retired_objects >= 2, "test needs sealed sources to merge");

        // Dense sealed segments cannot repack smaller: the gate must hold.
        let idle_gate = store.compact().expect("gated compact");
        assert!(
            !idle_gate.did_work(),
            "repacking {before} dense segments frees nothing"
        );

        // Raising the target underfills the sealed sources, so the merge
        // must fire and collapse them.
        store.set_segment_target_for_tests(16384);
        let stats = store.compact().expect("compact");
        assert!(stats.did_work(), "merging {before} segments must do work");
        assert_eq!(stats.objects_copied, retired_objects);
        assert_eq!(stats.segments_retired, before - usize::from(open_id.is_some()));
        assert!(stats.bytes_freed > 0, "retired files must unlink");
        assert_eq!(stats.segments_unlinked, stats.segments_retired);

        for (oid, bytes) in &expected {
            assert_eq!(read_all(&store, *oid), *bytes, "object {oid} survives");
        }
        let generation_after = store.meta.generation().expect("generation");
        assert!(generation_after > generation_before);
        assert!(
            segment_count(&store) < before,
            "segments must merge down"
        );

        drop(store);
        let reopened = Store::open(&temp.store_dir(), budget()).expect("reopen");
        for (oid, bytes) in &expected {
            assert_eq!(read_all(&reopened, *oid), *bytes, "object {oid} after reopen");
        }
        let idle = reopened.compact().expect("second compact");
        assert!(!idle.did_work(), "merged store has nothing left to do");
    }

    #[test]
    fn concurrent_publishes_during_compact_lose_no_object() {
        let temp = TempRoot::new("racing");
        let store = create(&temp);
        store.set_segment_target_for_tests(2048);
        let mut expected: HashMap<Oid, Vec<u8>> = HashMap::new();
        for index in 0..8_u64 {
            let bytes = pseudo(300, 2000 + index);
            let oid = publish_blob(&store, &bytes);
            expected.insert(oid, bytes);
        }
        let expected = Arc::new(Mutex::new(expected));
        std::thread::scope(|scope| {
            for worker in 0..4_u64 {
                let store_ref = &store;
                let expected_ref = Arc::clone(&expected);
                scope.spawn(move || {
                    for index in 0..8_u64 {
                        let bytes = pseudo(300, 10_000 + worker * 100 + index);
                        let oid = publish_blob(store_ref, &bytes);
                        expected_ref.lock().expect("poisoned").insert(oid, bytes);
                        if index == 3 {
                            let _ = store_ref.compact();
                        }
                    }
                });
            }
            let _ = store.compact();
            let _ = store.compact();
        });
        let guard = expected.lock().expect("poisoned");
        assert_eq!(guard.len(), 8 + 4 * 8);
        for (oid, bytes) in guard.iter() {
            assert_eq!(read_all(&store, *oid), *bytes, "object {oid} survives");
        }
        drop(guard);
        drop(store);
        let reopened = Store::open(&temp.store_dir(), budget()).expect("reopen");
        let guard = expected.lock().expect("poisoned");
        for (oid, bytes) in guard.iter() {
            assert_eq!(read_all(&reopened, *oid), *bytes, "object {oid} after reopen");
        }
    }
}
