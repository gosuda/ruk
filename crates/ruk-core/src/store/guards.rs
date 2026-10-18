//! Physical reader guards and locator-chain snapshots.
//!
//! A reader registers a [`GenerationGuard`] before opening the redb read
//! transaction used for locator lookup. In ONE short read transaction, the
//! reader captures a complete, bounded delta chain and all required segment
//! manifests as an [`ObjectSnapshot`].
//!
//! The metadata read transaction is released before any payload disk I/O.
//! Payload decoding uses only the captured snapshot facts while holding the
//! guard. Once the target's detached [`Spool`](super::Spool) is produced, the
//! guard drops.
//!
//! # Epochs and Retirement
//!
//! The [`GenerationRegistry`] records the last durably published Store
//! generation `P`. A reader registers at epoch `u128::from(P) + 1`, representing
//! the next publication boundary and preventing `u64::MAX` overflow.
//!
//! When a segment is retired at generation `R`, its locators are durably removed
//! and its retirement manifest committed at or before generation `R`. Physical
//! unlink readiness requires that no active reader has epoch `<= u128::from(R)`.
//! Any reader registered after publication will receive epoch `R + 1 > R` and
//! cannot obtain locators to the retired segment; therefore, new readers do not
//! starve retirement of old segment files.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::ids::Oid;
use crate::store::types::{ObjectKind, ObjectLocation, SegmentManifest};

/// Registry tracking the durably published Store generation and active reader epochs.
#[derive(Debug)]
pub(crate) struct GenerationRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug)]
struct RegistryInner {
    published_generation: u64,
    active_readers: BTreeMap<u128, usize>,
}

/// An active physical reader registration.
///
/// Owns its registration by RAII. Deregisters from [`GenerationRegistry`] on drop.
/// Reader I/O failure and panic release the pin automatically.
/// Not cloneable: cannot be duplicated into uncounted readers.
#[derive(Debug)]
#[must_use = "dropping a GenerationGuard releases the physical reader pin"]
pub(crate) struct GenerationGuard {
    registry: Arc<GenerationRegistry>,
    epoch: u128,
}

impl GenerationRegistry {
    /// Creates a new registry initialized with the store's current published generation.
    #[must_use]
    pub(crate) fn new(published_generation: u64) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                published_generation,
                active_readers: BTreeMap::new(),
            }),
        }
    }

    /// Registers a new active physical reader.
    ///
    /// Must be called BEFORE opening the redb read transaction for locator lookup.
    /// The reader is assigned epoch `u128::from(published_generation) + 1`.
    #[must_use]
    pub(crate) fn register(self: &Arc<Self>) -> GenerationGuard {
        let mut inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        let epoch = u128::from(inner.published_generation)
            .checked_add(1)
            .expect("reader epoch overflow u128");
        let count = inner.active_readers.entry(epoch).or_insert(0);
        *count = count.checked_add(1).expect("active reader count overflow");
        GenerationGuard {
            registry: Arc::clone(self),
            epoch,
        }
    }

    /// Deregisters an active reader epoch. Called by `GenerationGuard::drop`.
    fn deregister(&self, epoch: u128) {
        let mut inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        let Some(count) = inner.active_readers.get_mut(&epoch) else {
            panic!("deregistering unknown reader epoch {epoch}");
        };
        *count = count.checked_sub(1).expect("active reader count underflow");
        if *count == 0 {
            inner.active_readers.remove(&epoch);
        }
    }

    /// Advances the durably published generation after a successful publication commit.
    /// Readers admitted after this call register with an epoch strictly greater than `generation`.
    pub(crate) fn advance_published_generation(&self, generation: u64) {
        let mut inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        if generation > inner.published_generation {
            inner.published_generation = generation;
        }
    }

    /// The oldest active reader epoch, or `None` if no readers are active.
    #[must_use]
    pub(crate) fn oldest_active_reader_epoch(&self) -> Option<u128> {
        let inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        inner.active_readers.keys().next().copied()
    }

    /// Returns whether a segment retired at or before `retired_generation` is ready for physical unlink.
    ///
    /// # Precondition
    /// The caller MUST have already durably removed every locator referencing this segment
    /// and committed the retirement manifest at or before `retired_generation`.
    ///
    /// No filesystem I/O is performed under this registry mutex.
    #[must_use]
    pub(crate) fn is_segment_retired_ready_for_unlink(&self, retired_generation: u64) -> bool {
        let inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        match inner.active_readers.keys().next().copied() {
            Some(oldest) => oldest > u128::from(retired_generation),
            None => true,
        }
    }

    /// Total number of active registered readers.
    #[must_use]
    pub(crate) fn active_reader_count(&self) -> usize {
        let inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        inner.active_readers.values().sum()
    }

    /// The current published generation recorded in the registry.
    #[must_use]
    pub(crate) fn published_generation(&self) -> u64 {
        let inner = self
            .inner
            .lock()
            .expect("generation registry lock poisoned");
        inner.published_generation
    }
}

impl GenerationGuard {
    /// The reader epoch assigned at registration.
    #[must_use]
    pub(crate) fn epoch(&self) -> u128 {
        self.epoch
    }
}

impl Drop for GenerationGuard {
    fn drop(&mut self) {
        self.registry.deregister(self.epoch);
    }
}

/// One verified link in a captured delta chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CapturedLink {
    pub(crate) oid: Oid,
    pub(crate) location: ObjectLocation,
    pub(crate) manifest: SegmentManifest,
}

/// Coherent snapshot of an object's complete locator and manifest chain,
/// captured in one redb read transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObjectSnapshot {
    pub(crate) target_oid: Oid,
    pub(crate) target_kind: ObjectKind,
    pub(crate) target_depth: u8,
    /// Chain links ordered from target (index 0) down to root base (last index).
    pub(crate) links: Vec<CapturedLink>,
}

impl ObjectSnapshot {
    pub(crate) fn target_oid(&self) -> Oid {
        self.target_oid
    }

    pub(crate) fn target_kind(&self) -> ObjectKind {
        self.target_kind
    }

    pub(crate) fn target_depth(&self) -> u8 {
        self.target_depth
    }

    pub(crate) fn links(&self) -> &[CapturedLink] {
        &self.links
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::ids::HashKind;
    use crate::store::metadata_tests::{raw_put_object, raw_put_segment};
    use crate::store::types::PreparedObject;
    use crate::store::{
        BudgetLimits, MAX_DELTA_DEPTH, META_FILE, PreparationBudget, Store, StoreError, encode,
    };

    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    struct GuardTestDir(PathBuf);

    impl GuardTestDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ruk-guard-test-{tag}-{}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::SeqCst),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn store_dir(&self) -> PathBuf {
            self.0.join("store")
        }

        fn meta_path(&self) -> PathBuf {
            self.store_dir().join(META_FILE)
        }
    }

    impl Drop for GuardTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_store(dir: &GuardTestDir) -> Store {
        let budget = Arc::new(PreparationBudget::new(BudgetLimits {
            max_object_bytes: Some(16 * 1024 * 1024),
            // Fits one large-encode reservation (IO + ENCODE_ALLOWANCE_LARGE)
            // plus the delta path's second reservation.
            max_prepared_memory: 16 * 1024 * 1024,
            max_scratch_total: 64 * 1024 * 1024,
            max_scratch_per_store: 64 * 1024 * 1024,
            memory_spool_threshold: 256 * 1024,
        }));
        Store::create(&dir.store_dir(), HashKind::Sha1, budget).expect("create store")
    }

    fn prep_blob(store: &Store, bytes: &[u8]) -> PreparedObject {
        store
            .prepare(
                ObjectKind::Blob,
                u64::try_from(bytes.len()).expect("len fits u64"),
                bytes,
                None,
            )
            .expect("prepare blob")
    }

    fn prep_delta(store: &Store, base: Oid, bytes: &[u8]) -> PreparedObject {
        store
            .prepare(
                ObjectKind::Blob,
                u64::try_from(bytes.len()).expect("len fits u64"),
                bytes,
                Some(base),
            )
            .expect("prepare delta")
    }

    #[test]
    fn registry_lifecycle_and_generation_advance() {
        let reg = Arc::new(GenerationRegistry::new(0));
        assert_eq!(reg.published_generation(), 0);
        assert_eq!(reg.active_reader_count(), 0);
        assert_eq!(reg.oldest_active_reader_epoch(), None);

        // Advance generation
        reg.advance_published_generation(10);
        assert_eq!(reg.published_generation(), 10);

        // Regressing generation is ignored
        reg.advance_published_generation(5);
        assert_eq!(reg.published_generation(), 10);

        // Advancing to higher works
        reg.advance_published_generation(15);
        assert_eq!(reg.published_generation(), 15);
    }

    #[test]
    fn reader_registration_assigns_next_boundary_epoch() {
        let reg = Arc::new(GenerationRegistry::new(42));
        assert_eq!(reg.published_generation(), 42);

        let guard = reg.register();
        // Epoch must be published_generation + 1
        assert_eq!(guard.epoch(), 43);
        assert_eq!(reg.active_reader_count(), 1);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(43));

        drop(guard);
        assert_eq!(reg.active_reader_count(), 0);
        assert_eq!(reg.oldest_active_reader_epoch(), None);
    }

    #[test]
    fn multiple_readers_at_same_and_different_epochs() {
        let reg = Arc::new(GenerationRegistry::new(5));

        // Two readers at epoch 6
        let r1 = reg.register();
        let r2 = reg.register();
        assert_eq!(r1.epoch(), 6);
        assert_eq!(r2.epoch(), 6);
        assert_eq!(reg.active_reader_count(), 2);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(6));

        // Advance published generation to 8
        reg.advance_published_generation(8);

        // One reader at epoch 9
        let r3 = reg.register();
        assert_eq!(r3.epoch(), 9);
        assert_eq!(reg.active_reader_count(), 3);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(6));

        // Drop one reader at epoch 6
        drop(r1);
        assert_eq!(reg.active_reader_count(), 2);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(6));

        // Drop second reader at epoch 6
        drop(r2);
        assert_eq!(reg.active_reader_count(), 1);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(9));

        // Drop r3
        drop(r3);
        assert_eq!(reg.active_reader_count(), 0);
        assert_eq!(reg.oldest_active_reader_epoch(), None);
    }

    #[test]
    fn u64_max_generation_does_not_overflow_u128() {
        let reg = Arc::new(GenerationRegistry::new(u64::MAX));
        let guard = reg.register();
        let expected_epoch = u128::from(u64::MAX) + 1;
        assert_eq!(guard.epoch(), expected_epoch);
        assert_eq!(reg.oldest_active_reader_epoch(), Some(expected_epoch));

        // Unlink readiness check at u64::MAX
        // The reader registered at u128::from(u64::MAX) + 1 > u128::from(u64::MAX)
        assert!(reg.is_segment_retired_ready_for_unlink(u64::MAX));

        // But for retirement at u64::MAX with reader at an older epoch, it would be false
        drop(guard);
        assert_eq!(reg.active_reader_count(), 0);
    }

    #[test]
    fn retirement_unlink_readiness_logic() {
        let reg = Arc::new(GenerationRegistry::new(2));

        // Reader A registered at published generation 2 -> epoch 3
        let reader_a = reg.register();
        assert_eq!(reader_a.epoch(), 3);

        // Segment 1 was retired at generation 1.
        // Reader A's epoch is 3. 3 > 1, so segment 1 is ready for unlink!
        assert!(reg.is_segment_retired_ready_for_unlink(1));

        // Segment 3 was retired at generation 3.
        // Reader A's epoch is 3 <= 3, so segment 3 is NOT ready for unlink!
        assert!(!reg.is_segment_retired_ready_for_unlink(3));

        // Advance to generation 3
        reg.advance_published_generation(3);

        // Reader B registered at published generation 3 -> epoch 4
        let reader_b = reg.register();
        assert_eq!(reader_b.epoch(), 4);

        // Still not ready because reader_a (epoch 3) is alive
        assert!(!reg.is_segment_retired_ready_for_unlink(3));

        // Drop reader A
        drop(reader_a);

        // Now only reader_b (epoch 4) is alive. 4 > 3, so segment 3 IS ready for unlink!
        assert!(reg.is_segment_retired_ready_for_unlink(3));

        // New Reader C registered at generation 4 -> epoch 5
        reg.advance_published_generation(4);
        let reader_c = reg.register();
        assert_eq!(reader_c.epoch(), 5);

        // New readers do NOT starve retirement of segment 3
        assert!(reg.is_segment_retired_ready_for_unlink(3));

        drop(reader_b);
        drop(reader_c);
    }

    #[test]
    fn guard_drops_and_releases_pin_on_panic_unwind() {
        let reg = Arc::new(GenerationRegistry::new(10));
        assert_eq!(reg.active_reader_count(), 0);

        let result = std::panic::catch_unwind({
            let reg_clone = Arc::clone(&reg);
            move || {
                let _guard = reg_clone.register();
                assert_eq!(reg_clone.active_reader_count(), 1);
                panic!("simulated reader panic during payload decode");
            }
        });
        assert!(result.is_err());
        assert_eq!(reg.active_reader_count(), 0);
        assert_eq!(reg.oldest_active_reader_epoch(), None);
    }

    #[test]
    fn captured_snapshot_survives_later_locator_removal() {
        let dir = GuardTestDir::new("snapshot-locator-removal");
        let store = test_store(&dir);

        let data = b"payload to be read via captured snapshot";
        let blob = prep_blob(&store, data);
        let oid = blob.oid();
        store.publish(vec![blob], &[]).expect("publish blob");

        // Register guard and capture snapshot
        let guard = store.generation_registry().register();
        let snapshot = store
            .committed()
            .meta
            .snapshot_object_chain(store.hash_kind(), &oid)
            .expect("snapshot object chain");

        // Release the open store so raw redb write can modify meta.redb
        let reg = Arc::clone(store.generation_registry());
        let store_dir = dir.store_dir();
        let meta_path = dir.meta_path();
        let budget = Arc::new(PreparationBudget::reference_defaults());
        drop(store);

        // Durably remove locator from metadata
        raw_put_object(&meta_path, oid.as_bytes(), &[]);

        let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
        let files = crate::store::recovery::SegmentFileCache::default();
        let committed = crate::store::recovery::Committed {
            root: &store_dir,
            kind: HashKind::Sha1,
            meta: &meta,
            budget: &budget,
            guards: &reg,
            files: &files,
        };

        // Decode using captured snapshot
        let decoded = committed.load_snapshot(&snapshot).expect("load snapshot");
        let mut got = Vec::new();
        decoded.view().read_to_end(&mut got).expect("read spool");
        assert_eq!(got, data);

        drop(guard);
        assert_eq!(reg.active_reader_count(), 0);
    }

    #[test]
    fn captured_snapshot_survives_segment_retirement_no_false_quarantine() {
        let dir = GuardTestDir::new("snapshot-segment-retirement");
        let store = test_store(&dir);

        let data = b"payload preserved across retirement";
        let blob = prep_blob(&store, data);
        let oid = blob.oid();
        store.publish(vec![blob], &[]).expect("publish blob");

        // Capture snapshot while holding guard
        let guard = store.generation_registry().register();
        let snapshot = store
            .committed()
            .meta
            .snapshot_object_chain(store.hash_kind(), &oid)
            .expect("snapshot object chain");

        let seg_id = snapshot.links[0].manifest.id;

        // Simulate collector marking the segment retired in metadata
        let retired_manifest = SegmentManifest {
            id: seg_id,
            committed_end: snapshot.links[0].manifest.committed_end,
            records_end: snapshot.links[0].manifest.records_end,
            sealed: snapshot.links[0].manifest.sealed,
            retired: true,
            generation: snapshot.links[0].manifest.generation,
        };
        let encoded_manifest =
            encode("segment manifest", &retired_manifest).expect("encode manifest");

        let reg = Arc::clone(store.generation_registry());
        let store_dir = dir.store_dir();
        let meta_path = dir.meta_path();
        let budget = Arc::new(PreparationBudget::reference_defaults());
        drop(store);

        // Raw put to retired manifest with store closed
        raw_put_segment(&meta_path, seg_id, &encoded_manifest);

        let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
        let files = crate::store::recovery::SegmentFileCache::default();
        let committed = crate::store::recovery::Committed {
            root: &store_dir,
            kind: HashKind::Sha1,
            meta: &meta,
            budget: &budget,
            guards: &reg,
            files: &files,
        };

        // Decode using captured snapshot: uses captured non-retired manifest!
        let decoded = committed.load_snapshot(&snapshot).expect("load snapshot");
        let mut got = Vec::new();
        decoded.view().read_to_end(&mut got).expect("read spool");
        assert_eq!(got, data);

        // A new read starting after retirement sees the retired manifest and refuses as Corrupt
        let new_read = committed.read(oid);
        assert!(
            matches!(new_read, Err(StoreError::Corrupt(_))),
            "new read must reject retired segment: {new_read:?}"
        );

        drop(guard);
    }

    #[test]
    fn retired_segment_stays_protected_until_old_guard_drops() {
        let dir = GuardTestDir::new("retire-protect");
        let store = test_store(&dir);

        let data1 = b"object in segment 0";
        let blob1 = prep_blob(&store, data1);
        store.publish(vec![blob1], &[]).expect("publish 1");
        // Published at generation 1

        // Reader registers at generation 1 (epoch 2)
        let guard = store.generation_registry().register();
        assert_eq!(guard.epoch(), 2);

        // Generation 2: publish another object
        let data2 = b"object in segment 1";
        let blob2 = prep_blob(&store, data2);
        store.publish(vec![blob2], &[]).expect("publish 2");
        // Published at generation 2

        // Segment 0 is retired at generation 2.
        // Check unlink readiness for generation 2:
        // Reader is still active at epoch 2 <= 2.
        assert!(!store.is_segment_retired_ready_for_unlink(2));

        // Reader drops
        drop(guard);

        // Now segment retired at generation 2 is ready for unlink!
        assert!(store.is_segment_retired_ready_for_unlink(2));
    }

    #[test]
    fn later_generation_readers_do_not_starve_old_segment_retirement() {
        let dir = GuardTestDir::new("no-starve");
        let store = test_store(&dir);

        let b1 = prep_blob(&store, b"gen 1 blob");
        store.publish(vec![b1], &[]).expect("gen 1");

        let b2 = prep_blob(&store, b"gen 2 blob");
        store.publish(vec![b2], &[]).expect("gen 2");

        // Segment retired at generation 2
        // A horde of new readers register at generation 2 -> all receive epoch 3
        let r1 = store.generation_registry().register();
        let r2 = store.generation_registry().register();
        let r3 = store.generation_registry().register();
        assert_eq!(r1.epoch(), 3);
        assert_eq!(r2.epoch(), 3);
        assert_eq!(r3.epoch(), 3);

        // Unlink readiness for segment retired at generation 2 must be TRUE
        // because all active readers have epoch 3 > 2!
        assert!(store.is_segment_retired_ready_for_unlink(2));

        drop(r1);
        drop(r2);
        drop(r3);
    }

    #[test]
    fn depth_corruption_variants_rejected_by_snapshot_reader() {
        let dir = GuardTestDir::new("depth-corruption");
        let store = test_store(&dir);

        let base_data = b"base payload";
        let base_blob = prep_blob(&store, base_data);
        let base_oid = base_blob.oid();
        store.publish(vec![base_blob], &[]).expect("publish base");

        let delta_data = b"delta payload";
        let delta_blob = prep_delta(&store, base_oid, delta_data);
        let delta_oid = delta_blob.oid();
        store.publish(vec![delta_blob], &[]).expect("publish delta");

        let meta_path = dir.meta_path();
        drop(store);

        // Case 1: Non-delta object with depth > 0
        let bad_non_delta = ObjectLocation {
            segment: 0,
            offset: 0,
            record_len: 40,
            decoded_len: 12,
            kind: ObjectKind::Blob,
            depth: 1, // Invalid! Non-delta must have depth 0
            base: None,
            generation: 1,
        };
        let bad_non_delta_oid = HashKind::Sha1
            .hash_git_object("blob", b"bad-non-delta")
            .unwrap();
        raw_put_object(
            &meta_path,
            bad_non_delta_oid.as_bytes(),
            &encode("loc", &bad_non_delta).unwrap(),
        );
        {
            let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
            let res = meta.snapshot_object_chain(HashKind::Sha1, &bad_non_delta_oid);
            assert!(
                matches!(res, Err(StoreError::Corrupt(_))),
                "expected corrupt for non-delta with depth 1, got {res:?}"
            );
        }

        // Case 2: Delta object with depth == 0
        let bad_delta_zero = ObjectLocation {
            segment: 0,
            offset: 0,
            record_len: 40,
            decoded_len: 12,
            kind: ObjectKind::Blob,
            depth: 0, // Invalid! Delta must have depth >= 1
            base: Some(base_oid),
            generation: 1,
        };
        let bad_delta_zero_oid = HashKind::Sha1
            .hash_git_object("blob", b"bad-delta-zero")
            .unwrap();
        raw_put_object(
            &meta_path,
            bad_delta_zero_oid.as_bytes(),
            &encode("loc", &bad_delta_zero).unwrap(),
        );
        {
            let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
            let res = meta.snapshot_object_chain(HashKind::Sha1, &bad_delta_zero_oid);
            assert!(
                matches!(res, Err(StoreError::Corrupt(_))),
                "expected corrupt for delta with depth 0, got {res:?}"
            );
        }

        // Case 3: Delta object with depth > MAX_DELTA_DEPTH
        let bad_depth = ObjectLocation {
            segment: 0,
            offset: 0,
            record_len: 40,
            decoded_len: 12,
            kind: ObjectKind::Blob,
            depth: MAX_DELTA_DEPTH + 1, // Invalid!
            base: Some(base_oid),
            generation: 1,
        };
        let bad_depth_oid = HashKind::Sha1
            .hash_git_object("blob", b"bad-depth")
            .unwrap();
        raw_put_object(
            &meta_path,
            bad_depth_oid.as_bytes(),
            &encode("loc", &bad_depth).unwrap(),
        );
        {
            let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
            let res = meta.snapshot_object_chain(HashKind::Sha1, &bad_depth_oid);
            assert!(
                matches!(res, Err(StoreError::Corrupt(_))),
                "expected corrupt for depth > MAX, got {res:?}"
            );
        }

        // Case 4: Delta object referencing missing base
        let missing_base_oid = HashKind::Sha1
            .hash_git_object("blob", b"missing-base")
            .unwrap();
        let bad_missing_base = ObjectLocation {
            segment: 0,
            offset: 0,
            record_len: 40,
            decoded_len: 12,
            kind: ObjectKind::Blob,
            depth: 1,
            base: Some(missing_base_oid),
            generation: 1,
        };
        let bad_missing_base_oid = HashKind::Sha1
            .hash_git_object("blob", b"bad-missing-base")
            .unwrap();
        raw_put_object(
            &meta_path,
            bad_missing_base_oid.as_bytes(),
            &encode("loc", &bad_missing_base).unwrap(),
        );
        {
            let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
            let res = meta.snapshot_object_chain(HashKind::Sha1, &bad_missing_base_oid);
            assert!(
                matches!(res, Err(StoreError::Corrupt(_))),
                "expected corrupt for missing base, got {res:?}"
            );
        }

        // Case 5: Base depth disagreeing with child depth (base depth is 0, child claims depth 2)
        let bad_depth_mismatch = ObjectLocation {
            segment: 0,
            offset: 0,
            record_len: 40,
            decoded_len: 12,
            kind: ObjectKind::Blob,
            depth: 2, // Base has depth 0, so child should have depth 1
            base: Some(base_oid),
            generation: 1,
        };
        let bad_mismatch_oid = HashKind::Sha1
            .hash_git_object("blob", b"bad-mismatch")
            .unwrap();
        raw_put_object(
            &meta_path,
            bad_mismatch_oid.as_bytes(),
            &encode("loc", &bad_depth_mismatch).unwrap(),
        );
        {
            let meta = crate::store::Metadata::open(&meta_path).expect("open meta");
            let res = meta.snapshot_object_chain(HashKind::Sha1, &bad_mismatch_oid);
            assert!(
                matches!(res, Err(StoreError::Corrupt(_))),
                "expected corrupt for base depth mismatch, got {res:?}"
            );
        }
    }
}
