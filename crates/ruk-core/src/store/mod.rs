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
pub mod types;

mod delta;
mod durability;
mod metadata;
mod prepare;
mod recovery;
mod segment;
mod spool;

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub use error::StoreError;
pub use spool::{BudgetLimits, PreparationBudget, Spool};
pub use types::{
    Encoding, FactExpectation, FactMutation, FactTable, ObjectKind, ObjectLocation, PreparedObject,
    Publication, ReadObject, SegmentManifest, StoreFormat,
};

use crate::error::ErrorCode;
use crate::ids::{HashKind, Oid};
use metadata::{Metadata, PublicationTxn};
use recovery::{Committed, OpenSegment, Recovered};
use segment::SegmentWriter;

/// Longest delta chain accepted on write and read.
pub(crate) const MAX_DELTA_DEPTH: u8 = 50;

const FORMAT_FILE: &str = "format";
const META_FILE: &str = "meta.redb";
const SEGMENTS_DIR: &str = "segments";
/// The format file is two short lines; anything longer is foreign.
const MAX_FORMAT_BYTES: u64 = 128;

/// A durable object store rooted at a `.ruk/store` directory.
///
/// `Store` is `Sync`: reads and fact lookups run concurrently with each
/// other and with publication, and publications serialize on one writer.
/// Reads release every metadata transaction before payload I/O.
pub struct Store {
    root: PathBuf,
    kind: HashKind,
    meta: Metadata,
    budget: Arc<PreparationBudget>,
    writer: Mutex<WriterState>,
    quarantine: Mutex<Option<String>>,
    quarantined: AtomicBool,
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
            .field("kind", &self.kind)
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
    /// completed. An opener flushes that format before recovery. An absent
    /// or incomplete format prevents opening; creation never adopts or
    /// deletes an incomplete store.
    ///
    /// # Platforms
    /// POSIX creates `root` and any missing ancestors, flushing the existing
    /// ancestor chain first, and accepts an existing directory as `root`.
    ///
    /// Windows requires an existing, already durable parent and an absent
    /// `root`. Nothing proves that an ancestor some other actor created is
    /// durable, so none is created here and none is trusted: the caller
    /// (standalone setup, the Forgejo patch) provisions the parent and makes
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
        format_file.write_all(&StoreFormat { kind }.to_bytes())?;
        durability::sync_file(&format_file)?;
        sync_entries(root)?;

        Ok(Self::assemble(
            root,
            kind,
            meta,
            budget,
            Recovered {
                next_segment_id: 0,
                open: None,
            },
        ))
    }

    /// Opens an existing store after verifying all committed bytes.
    ///
    /// Recovery validates every committed segment extent, truncates only an
    /// open segment's uncommitted tail, and verifies every committed object
    /// identity. Missing or damaged committed bytes refuse the open.
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
    /// partly written one left by an interrupted creation;
    /// [`StoreError::Corrupt`] for committed damage; I/O and database
    /// failures propagate, including a `root` that cannot be made absolute.
    pub fn open(root: &Path, budget: Arc<PreparationBudget>) -> Result<Self, StoreError> {
        let root = std::path::absolute(root)?;
        let root = root.as_path();
        let (format, format_file) = read_format(root)?;
        let meta = Metadata::open(&root.join(META_FILE))?;
        durability::sync_file(&format_file)?;
        sync_entries(root)?;
        drop(format_file);
        budget.register_scratch(root)?;
        let committed = Committed {
            root,
            kind: format.kind,
            meta: &meta,
            budget: &budget,
        };
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
        Ok(Self::assemble(root, format.kind, meta, budget, recovered))
    }

    fn assemble(
        root: &Path,
        kind: HashKind,
        meta: Metadata,
        budget: Arc<PreparationBudget>,
        recovered: Recovered,
    ) -> Self {
        Self {
            root: root.to_path_buf(),
            kind,
            meta,
            budget,
            writer: Mutex::new(WriterState {
                active: None,
                resume: recovered.open,
                next_segment_id: recovered.next_segment_id,
                closed: None,
            }),
            quarantine: Mutex::new(None),
            quarantined: AtomicBool::new(false),
        }
    }

    /// The fixed hash kind of this store.
    #[must_use]
    pub fn hash_kind(&self) -> HashKind {
        self.kind
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
            kind: self.kind,
            meta: &self.meta,
            budget: &self.budget,
        }
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
    fn observe<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
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
            self.kind,
            kind,
            decoded_len,
            input,
            base.as_ref().map(|(oid, read)| (*oid, read)),
            &self.budget,
            &self.root,
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
        self.observe(self.committed().read(oid))
    }

    /// Reads one fact value.
    ///
    /// # Errors
    /// Database failures propagate; [`StoreError::Corrupt`] for damage, which
    /// also latches quarantine; quarantine refuses.
    pub fn fact(&self, table: FactTable, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.refuse_if_quarantined()?;
        self.observe(self.meta.fact(table, key))
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
    pub fn publish(
        &self,
        objects: Vec<PreparedObject>,
        facts: &[FactMutation],
    ) -> Result<Publication, StoreError> {
        self.refuse_if_quarantined()?;
        if objects.is_empty() && facts.is_empty() {
            return Ok(Publication {
                objects: Vec::new(),
                generation: self.observe(self.meta.generation())?,
            });
        }
        let mut writer = self.lock_writer()?;
        // A read may have latched quarantine while this call waited for the
        // writer; nothing commits on a store already known to be corrupt.
        self.refuse_if_quarantined()?;
        if let Some(reason) = &writer.closed {
            return Err(StoreError::WriterClosed(reason.clone()));
        }
        let txn = self.observe(self.meta.begin_publication(facts))?;
        let plan = self.observe(self.plan(&txn, &objects))?;
        match self.write_and_commit(&mut writer, txn, plan) {
            Ok(publication) => Ok(publication),
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
        objects: &'a [PreparedObject],
    ) -> Result<Plan<'a>, StoreError> {
        let mut order = Vec::with_capacity(objects.len());
        let mut fresh = Vec::new();
        let mut seen: HashMap<Oid, (ObjectKind, u64)> = HashMap::with_capacity(objects.len());
        for object in objects {
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
        if oid.kind() != self.kind {
            return Err(StoreError::ObjectFormat(format!(
                "prepared object {oid} is not a {} digest",
                self.kind
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
        if base.kind() != self.kind {
            return Err(StoreError::ObjectFormat(format!(
                "delta base {base} of {oid} is not a {} digest",
                self.kind
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
    fn write_and_commit(
        &self,
        writer: &mut WriterState,
        txn: PublicationTxn,
        plan: Plan<'_>,
    ) -> Result<Publication, StoreError> {
        let Plan {
            order,
            fresh,
            generation,
        } = plan;
        let segments_dir = self.root.join(SEGMENTS_DIR);
        let mut batch = Batch::default();
        for object in &fresh {
            append(writer, &mut batch, &segments_dir, object, generation)?;
        }
        #[cfg(test)]
        crash_tests::crash_at("after_append");

        batch.sync_files(writer)?;
        #[cfg(test)]
        crash_tests::crash_at("after_segment_sync");

        if batch.new_entries {
            sync_entries(&segments_dir)?;
        }
        #[cfg(test)]
        crash_tests::crash_at("after_directory_sync");

        self.observe(batch.stage(&txn, writer, generation, !fresh.is_empty()))?;
        self.observe(txn.commit())?;
        #[cfg(test)]
        crash_tests::crash_at("after_metadata_commit");

        #[cfg(test)]
        crash_tests::crash_at("before_ack");
        Ok(Publication {
            objects: order,
            generation,
        })
    }
}

impl Batch {
    /// Records the generation, every new locator, and the final manifest of
    /// every touched segment in the publication transaction.
    fn stage(
        &self,
        txn: &PublicationTxn,
        writer: &WriterState,
        generation: u64,
        advance_generation: bool,
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
        Ok(())
    }

    /// Flushes every segment this publication touched.
    fn sync_files(&self, writer: &WriterState) -> Result<(), StoreError> {
        for segment in &self.sealed {
            durability::sync_file(segment.writer.get_ref())?;
        }
        match writer.active.as_ref() {
            Some(active) if self.active_touched => durability::sync_file(active.writer.get_ref()),
            _ => Ok(()),
        }
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

/// Appends one prepared object to the active segment, rolling to a new
/// segment first when it does not fit, and sealing a dedicated segment
/// when a single record exceeds the target.
fn append(
    writer: &mut WriterState,
    batch: &mut Batch,
    segments_dir: &Path,
    object: &PreparedObject,
    generation: u64,
) -> Result<(), StoreError> {
    let payload_len = object.payload.len();
    let record_len = segment::record_len_for(payload_len)?;
    let active = active_segment(writer, batch, segments_dir, record_len)?;
    let appended = active.writer.append(
        object.kind(),
        object.encoding(),
        payload_len,
        object.payload_crc,
        object.payload.view(),
    )?;
    let segment = active.id;
    let oversized = active.writer.records_end() > segment::SEGMENT_TARGET_BYTES;
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
    Ok(())
}

/// The segment the next record goes to: the recovered or current open
/// segment, a fresh one when none is open, or a rolled one when the record
/// would overflow a non-empty segment.
fn active_segment<'w>(
    writer: &'w mut WriterState,
    batch: &mut Batch,
    segments_dir: &Path,
    record_len: u64,
) -> Result<&'w mut ActiveSegment, StoreError> {
    if writer.active.is_none() {
        let opened = open_segment(writer, batch, segments_dir)?;
        writer.active = Some(opened);
    }
    let overflows = writer.active.as_ref().is_some_and(|active| {
        active.writer.records_end() > 0 && !active.writer.fits_target(record_len)
    });
    if overflows {
        seal_active(writer, batch)?;
        let opened = open_segment(writer, batch, segments_dir)?;
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
    active.writer.seal()?;
    batch.sealed.push(active);
    Ok(())
}

/// Reopens the recovered open segment once, otherwise creates the next
/// segment exclusively. Existing files are never overwritten or unlinked:
/// the id advances past each unknown name, and exhausting the id space is
/// a capacity error.
fn open_segment(
    writer: &mut WriterState,
    batch: &mut Batch,
    segments_dir: &Path,
) -> Result<ActiveSegment, StoreError> {
    if let Some(resume) = writer.resume.take() {
        let path = segments_dir.join(segment::segment_file_name(resume.id));
        let file = durability::open_existing(&path)?;
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
        let path = segments_dir.join(segment::segment_file_name(id));
        match durability::create_file_published(&path) {
            Ok(file) => {
                writer.next_segment_id = next;
                batch.new_entries = true;
                return Ok(ActiveSegment {
                    id,
                    writer: SegmentWriter::fresh(file)?,
                });
            }
            Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
                writer.next_segment_id = next;
            }
            Err(err) => return Err(err),
        }
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
fn read_format(root: &Path) -> Result<(StoreFormat, File), StoreError> {
    let mut file = match durability::open_existing(&root.join(FORMAT_FILE)) {
        Ok(file) => file,
        Err(StoreError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound(format!(
                "no store format file under {}",
                root.display()
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

    use super::metadata_tests::{raw_put_object, raw_put_segment};
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
            .publish(vec![healthy, victim], &main)
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
            shared.register_scratch(&root).expect("scratch accounting");
            let committed = Committed {
                root: &root,
                kind: format.kind,
                meta: &meta,
                budget: &shared,
            };
            recovery::run(&committed).expect("healthy store recovers")
        };
        damage(&meta_file(temp));
        let meta = Metadata::open(&meta_file(temp)).expect("metadata census");
        Store::assemble(&root, format.kind, meta, shared, recovered)
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
        assert_refused("fact-only publish", store.publish(vec![], &facts));
        assert_refused("empty publish", store.publish(vec![], &[]));
        assert_refused(
            "unrelated object publish",
            store.publish(vec![spare], &facts),
        );
    }

    #[test]
    fn objects_and_facts_survive_reopen_for_both_hash_kinds() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let temp = TempRoot::new("roundtrip");
            let store = create(&temp, kind);
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
            let published = store.publish(vec![prepared], &facts).expect("publish");
            assert_eq!(published.objects, vec![oid]);
            assert_eq!(published.generation, 1);
            drop(store);

            let store = reopen(&temp);
            assert_eq!(store.hash_kind(), kind);
            assert_eq!(read_all(&store, oid), payload);
            assert_eq!(
                store
                    .fact(FactTable::Refs, b"refs/heads/main")
                    .expect("fact"),
                Some(oid.as_bytes().to_vec())
            );
        }
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
            let payload = pseudo(2000, 61);
            let oid = store
                .publish(vec![blob(&store, &payload)], &[])
                .expect("the winner's store publishes")
                .objects[0];
            drop(store);
            assert_eq!(read_all(&reopen(&temp), oid), payload, "round {round}");
        }
    }

    /// A creation that stopped before the format was complete is neither
    /// opened nor completed by a later call, and its files are untouched.
    #[test]
    fn an_incomplete_format_is_neither_opened_nor_adopted() {
        let canonical = StoreFormat {
            kind: HashKind::Sha1,
        }
        .to_bytes();
        let torn: [(&str, Vec<u8>); 3] = [
            ("empty", Vec::new()),
            ("prefix", canonical[..canonical.len() / 2].to_vec()),
            ("zeros", vec![0; canonical.len()]),
        ];
        for (name, bytes) in torn {
            let temp = TempRoot::new("incomplete-format");
            let healthy = create(&temp, HashKind::Sha1);
            let payload = pseudo(2000, 62);
            let oid = healthy
                .publish(vec![blob(&healthy, &payload)], &[])
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
            .publish(vec![blob(&store, &payload)], &[])
            .expect("first publish");
        let before = std::fs::metadata(segment_file(&temp, 0))
            .expect("segment")
            .len();
        let again = store
            .publish(vec![blob(&store, &payload)], &[])
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
            .publish(vec![foreign], &[])
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
        source.publish(vec![base], &[]).expect("publish base");
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
            .publish(vec![delta], &facts)
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
            .publish(vec![], &facts)
            .expect("writer stays open after a validation failure");
    }

    #[test]
    fn delta_chain_reads_back_exactly_after_reopen() {
        let temp = TempRoot::new("delta-read");
        let store = create(&temp, HashKind::Sha1);
        let base_bytes = pseudo(32 * 1024, 4);
        let base = blob(&store, &base_bytes);
        let base_oid = base.oid();
        store.publish(vec![base], &[]).expect("publish base");
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
        store.publish(vec![delta], &[]).expect("publish delta");
        drop(store);

        let store = reopen(&temp);
        assert_eq!(read_all(&store, delta_oid), changed);
        assert_eq!(store.read(delta_oid).expect("read").depth, 1);
        assert_eq!(read_all(&store, base_oid), base_bytes);
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
        store.publish(vec![], &set).expect("first set");
        let err = store
            .publish(vec![], &set)
            .expect_err("claim already present");
        assert!(matches!(err, StoreError::StaleFact { .. }), "{err:?}");

        let twice = [
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"a")),
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"b")),
        ];
        let err = store.publish(vec![], &twice).expect_err("duplicate key");
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
        store.publish(vec![], &remove).expect("conditional remove");
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
            .publish(vec![prepared], &[])
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
            .publish(vec![blob(&store, &first)], &[])
            .expect("first")
            .objects[0];
        drop(store);

        let store = reopen(&temp);
        let second = pseudo(2000, 7);
        let second_oid = store
            .publish(vec![blob(&store, &second)], &[])
            .expect("second")
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
            .publish(vec![blob(&store, &payload)], &[])
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
            .publish(vec![blob(&store, &more)], &[])
            .expect("publish after truncation")
            .objects[0];
        assert_eq!(read_all(&store, more_oid), more);
    }

    #[test]
    fn open_refuses_missing_committed_bytes() {
        let temp = TempRoot::new("short");
        let store = create(&temp, HashKind::Sha1);
        store
            .publish(vec![blob(&store, &pseudo(2000, 10))], &[])
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
        store.publish(vec![prepared], &[]).expect("publish");

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
            store.publish(vec![], &facts),
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
        });

        let err = store
            .publish(vec![seeded.victim_again], &[])
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
            .publish(vec![seeded.delta_over_victim], &[])
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
            .publish(vec![seeded.unrelated], &[])
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
        store.publish(vec![], &claim).expect("first claim");
        assert!(matches!(
            store.publish(vec![], &claim),
            Err(StoreError::StaleFact { .. })
        ));
        let twice = [
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"a")),
            mutation(FactTable::Claims, b"dup", FactExpectation::Any, Some(b"b")),
        ];
        assert!(matches!(
            store.publish(vec![], &twice),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.publish(vec![blob(&foreign, b"wide")], &[]),
            Err(StoreError::ObjectFormat(_))
        ));

        let base_bytes = pseudo(32 * 1024, 31);
        let base = blob(&source, &base_bytes);
        let base_oid = base.oid();
        source.publish(vec![base], &[]).expect("publish base");
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
            store.publish(vec![dangling], &[]),
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
            .publish(vec![prepared], &[])
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
            .publish(vec![blob(&store, &first_payload)], &[])
            .expect("publish before the move")
            .objects[0];
        drop(store);
        let store = Store::open(&root, budget()).expect("open by the same relative root");

        std::env::set_current_dir(&second).expect("move this child's working directory");

        assert_eq!(read_all(&store, first), first_payload);
        let later_payload = pseudo(2000, 42);
        let later = store
            .publish(vec![blob(&store, &later_payload)], &[])
            .expect("publish after the move")
            .objects[0];
        assert_eq!(read_all(&store, later), later_payload);
    }
}
