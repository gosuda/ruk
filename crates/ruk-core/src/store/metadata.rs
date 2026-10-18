//! The metadata authority of the durable store: one redb database holding
//! object locators, segment manifests, the locator generation, and every
//! mutable fact table of the core census.
//!
//! # Tables
//!
//! Thirty named tables are created together, once, by
//! [`Metadata::create_in_file`]:
//!
//! - `objects`: raw object digest -> postcard [`ObjectLocation`];
//! - `segments`: segment id -> postcard [`SegmentManifest`];
//! - `generation`: `()` -> the current locator generation;
//! - `verified_generation`: `()` -> the locator generation whose objects
//!   recovery last fully identity-verified, written only by recovery on a
//!   successful open;
//! - one `&[u8] -> &[u8]` table per [`FactTable`] variant, named by
//!   [`FactTable::table_name`]. Fact values are opaque here; their owners
//!   postcard-encode them.
//!
//! `objects`, `segments` and `generation` are publication-owned: they are
//! written only through [`PublicationTxn`], never through a
//! [`FactMutation`].
//!
//! A store written before `verified_generation` existed opens normally: the
//! missing table reads as unverified, so the next open verifies every
//! object and then records the table. A binary that predates the table
//! refuses a store holding it as [`StoreError::Version`], the same unknown
//! census signal as any other format drift.
//!
//! # Initialization versus opening
//!
//! [`Metadata::create_in_file`] initializes a zero-length file and nothing
//! else. [`Metadata::open`] never creates anything: a missing, empty,
//! foreign or truncated file, a missing or mistyped census table, an
//! unknown table, or a missing generation row is refused instead of being
//! repaired by initialization. Format drift is [`StoreError::Version`];
//! every other inconsistency is [`StoreError::Corrupt`].
//!
//! # Transactions
//!
//! Every read opens its own redb read transaction and drops it before it
//! returns, so no MVCC snapshot is held across payload I/O. The only
//! long-lived transaction is the [`PublicationTxn`], which the publisher
//! holds from fact validation through byte sync until [`PublicationTxn::commit`]
//! (Immediate durability, one commit). redb has a single writer, so holding
//! it also serializes publication and makes the checked expectations the
//! state the commit applies to.
//!
//! A commit error may already be durable. It surfaces as
//! [`StoreError::Commit`] and callers must never truncate bytes or assume
//! rollback in response.

use std::fmt;
use std::io;
use std::ops::Bound;
use std::path::Path;

use redb::{
    Builder, Database, DatabaseError, Durability, ReadableDatabase, ReadableTable, StorageError,
    TableDefinition, TableError, TableHandle, TransactionError, WriteTransaction,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ids::{HashKind, Oid};
use crate::store::MAX_DELTA_DEPTH;
use crate::store::error::StoreError;
use crate::store::guards::{CapturedLink, ObjectSnapshot};
use crate::store::segment;
use crate::store::types::{
    FactExpectation, FactMutation, FactTable, ObjectLocation, SegmentManifest,
};

/// Maximum persisted byte length of a single fact row's key plus value (16 MiB).
/// Persisted rows exceeding this cap are committed corruption.
pub(crate) const MAX_FACT_ROW_BYTES: usize = 16 * 1024 * 1024;

/// Length of a segment record header; no stored record is shorter. The one
/// layout value lives in `segment`; this is its lossless `u64` view
/// (`usize` is at most 64 bits on every supported target).
const RECORD_HEADER_LEN: u64 = segment::HEADER_LEN as u64;
/// Length of a segment seal footer, included in a sealed segment's
/// committed end (same single source as [`RECORD_HEADER_LEN`]).
const SEAL_FOOTER_LEN: u64 = segment::FOOTER_LEN as u64;

/// redb's read and write cache budget for one open store.
///
/// The reference profile allows 8 GiB of metadata/block cache across all
/// open stores and at most 128 simultaneously open stores, so each store
/// gets the fixed share `8 GiB / 128 = 64 MiB`; the sum can never exceed the
/// profile even with every handle open. redb's own default is 1 GiB per
/// database, which 128 open stores would multiply past the whole budget.
/// A coordinator that budgets caches globally replaces this constant later.
const CACHE_BYTES_PER_STORE: usize = 64 * 1024 * 1024;

/// A redb builder carrying the store's explicit cache limit.
fn builder() -> Builder {
    let mut builder = Database::builder();
    builder.set_cache_size(CACHE_BYTES_PER_STORE);
    builder
}

type BytesTable = TableDefinition<'static, &'static [u8], &'static [u8]>;

const OBJECTS: BytesTable = TableDefinition::new("objects");
const SEGMENTS: TableDefinition<'static, u64, &'static [u8]> = TableDefinition::new("segments");
const GENERATION: TableDefinition<'static, (), u64> = TableDefinition::new("generation");
const VERIFIED_GENERATION: TableDefinition<'static, (), u64> =
    TableDefinition::new("verified_generation");

const fn fact_definition(table: FactTable) -> BytesTable {
    TableDefinition::new(table.table_name())
}

/// Bounded resource limits for a fact table page request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactPageBudget {
    pub rows: usize,
    pub bytes: usize,
}

impl FactPageBudget {
    #[must_use]
    pub const fn new(rows: usize, bytes: usize) -> Self {
        Self { rows, bytes }
    }
}

/// One raw key and value pair from a fact table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A bounded page of fact rows with continuation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactPage {
    pub rows: Vec<FactRow>,
    pub more: bool,
}

fn is_census_name(name: &str) -> bool {
    name == OBJECTS.name()
        || name == SEGMENTS.name()
        || name == GENERATION.name()
        || name == VERIFIED_GENERATION.name()
        || FactTable::ALL
            .iter()
            .any(|table| table.table_name() == name)
}

/// The redb database behind one store.
#[derive(Debug)]
pub(crate) struct Metadata {
    db: Database,
}

impl Metadata {
    /// Initializes `file`, which must be zero-length, as a new metadata
    /// database: all census tables and generation 0 in one Immediate
    /// commit. The handle is the one the caller created exclusively and
    /// published durably; redb takes its lock on this very handle, so the
    /// database cannot be opened by a second owner while the store lives.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if the file already holds bytes (nothing is
    /// truncated or overwritten); redb failures otherwise.
    pub(crate) fn create_in_file(file: std::fs::File) -> Result<Self, StoreError> {
        let len = file.metadata()?.len();
        if len != 0 {
            return Err(StoreError::Invalid(format!(
                "metadata database must be created in an empty file, found {len} bytes"
            )));
        }
        let db = builder().create_file(file).map_err(database_error)?;
        let mut txn = db.begin_write().map_err(txn_error)?;
        txn.set_durability(Durability::Immediate)?;
        drop(txn.open_table(OBJECTS).map_err(table_error)?);
        drop(txn.open_table(SEGMENTS).map_err(table_error)?);
        for table in FactTable::ALL {
            drop(
                txn.open_table(fact_definition(table))
                    .map_err(table_error)?,
            );
        }
        {
            let mut generation = txn.open_table(GENERATION).map_err(table_error)?;
            generation.insert((), 0_u64).map_err(storage)?;
        }
        {
            let mut verified = txn.open_table(VERIFIED_GENERATION).map_err(table_error)?;
            verified.insert((), 0_u64).map_err(storage)?;
        }
        txn.commit()?;
        Ok(Self { db })
    }

    /// Opens an existing metadata database and verifies the census.
    ///
    /// Schema revision: census tables the file predates (a store written
    /// before a [`FactTable`] variant existed) are created empty before
    /// verification, the same tolerance [`Metadata::verified_generation`]
    /// shows a missing verification cache: absence means an older schema,
    /// not damage. Unknown tables still refuse with [`StoreError::Version`].
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a missing, empty, foreign or damaged
    /// file, a mistyped census table, or a missing generation row;
    /// [`StoreError::Version`] for an unknown table or a file format
    /// that needs an offline upgrade.
    pub(crate) fn open(path: &Path) -> Result<Self, StoreError> {
        let db = builder().open(path).map_err(database_error)?;
        ensure_census(&db)?;
        verify_census(&db)?;
        Ok(Self { db })
    }

    /// The current locator generation.
    pub(crate) fn generation(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        lookup_generation(&txn.open_table(GENERATION).map_err(table_error)?)
    }

    /// The locator generation recovery last fully identity-verified, or
    /// `None` when no verified generation is recorded.
    ///
    /// A missing table means the store predates the verification cache, not
    /// damage: the caller must verify every object and then record the
    /// result with [`Metadata::set_verified_generation`]. Any other table
    /// failure keeps the existing census meaning.
    pub(crate) fn verified_generation(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        let table = match txn.open_table(VERIFIED_GENERATION) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(err) => return Err(table_error(err)),
        };
        Ok(table.get(()).map_err(storage)?.map(|guard| guard.value()))
    }

    /// Records `generation` as fully identity-verified in one Immediate
    /// commit. Recovery calls this after a successful verification pass and
    /// before serving anything; the commit may already be durable on
    /// failure, so callers treat it like any other metadata commit.
    pub(crate) fn set_verified_generation(&self, generation: u64) -> Result<(), StoreError> {
        let mut txn = self.db.begin_write().map_err(txn_error)?;
        txn.set_durability(Durability::Immediate)?;
        {
            let mut table = txn.open_table(VERIFIED_GENERATION).map_err(table_error)?;
            table.insert((), generation).map_err(storage)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The locator for `oid`, or `None` if it was never published.
    pub(crate) fn get_object(&self, oid: &Oid) -> Result<Option<ObjectLocation>, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        lookup_object(&txn.open_table(OBJECTS).map_err(table_error)?, oid)
    }

    /// Resolves the complete bounded delta chain and all required segment manifests
    /// for `oid` within ONE single read transaction.
    ///
    /// The read transaction is dropped before this method returns.
    /// Validates hash width, chain depth bounds (1..=MAX_DELTA_DEPTH for deltas, 0
    /// for non-deltas), kind consistency, strict base depth (`base.depth + 1 == child.depth`),
    /// manifest existence, non-retired manifest state, and record extents.
    ///
    /// # Errors
    /// - [`StoreError::ObjectFormat`] if `oid` or any base in the chain does not match `expected_kind`.
    /// - [`StoreError::NotFound`] if `oid` is not committed.
    /// - [`StoreError::Corrupt`] if a base is missing, depth or kind is inconsistent,
    ///   a manifest is missing or retired, record extents exceed manifest records_end,
    ///   or locator generation exceeds store generation.
    pub(crate) fn snapshot_object_chain(
        &self,
        expected_kind: HashKind,
        oid: &Oid,
    ) -> Result<ObjectSnapshot, StoreError> {
        if oid.kind() != expected_kind {
            return Err(StoreError::ObjectFormat(format!(
                "object id {oid} is not a {expected_kind} digest"
            )));
        }

        let txn = self.db.begin_read().map_err(txn_error)?;
        let objects_table = txn.open_table(OBJECTS).map_err(table_error)?;
        let segments_table = txn.open_table(SEGMENTS).map_err(table_error)?;
        let generation_table = txn.open_table(GENERATION).map_err(table_error)?;
        let current_generation = lookup_generation(&generation_table)?;

        let target_location = lookup_object(&objects_table, oid)?
            .ok_or_else(|| StoreError::NotFound(oid.to_hex()))?;

        let target_kind = target_location.kind;
        let target_depth = target_location.depth;

        let mut links = Vec::new();
        let mut cursor_oid = *oid;
        let mut cursor_location = target_location;

        loop {
            if cursor_oid.kind() != expected_kind {
                return Err(StoreError::ObjectFormat(format!(
                    "object id {cursor_oid} is not a {expected_kind} digest"
                )));
            }

            if cursor_location.generation > current_generation {
                return Err(StoreError::Corrupt(format!(
                    "object {cursor_oid} was published at generation {} above the store generation {current_generation}",
                    cursor_location.generation
                )));
            }

            let manifest =
                lookup_manifest(&segments_table, cursor_location.segment)?.ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "object {cursor_oid} locates unmanifested segment {}",
                        cursor_location.segment
                    ))
                })?;

            if manifest.retired {
                return Err(StoreError::Corrupt(format!(
                    "object {cursor_oid} locates retired segment {}",
                    manifest.id
                )));
            }

            let _end = cursor_location
                .offset
                .checked_add(cursor_location.record_len)
                .filter(|end| *end <= manifest.records_end)
                .ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "object {cursor_oid} record [{}, +{}) leaves segment {} record extent {}",
                        cursor_location.offset,
                        cursor_location.record_len,
                        manifest.id,
                        manifest.records_end
                    ))
                })?;

            let (child_oid, base_opt, depth, kind) = (
                cursor_oid,
                cursor_location.base,
                cursor_location.depth,
                cursor_location.kind,
            );

            links.push(CapturedLink {
                oid: cursor_oid,
                location: cursor_location,
                manifest,
            });

            let Some(base_oid) = base_opt else {
                if depth != 0 {
                    return Err(StoreError::Corrupt(format!(
                        "non-delta object {child_oid} records chain depth {depth}"
                    )));
                }
                break;
            };

            if depth == 0 || depth > MAX_DELTA_DEPTH {
                return Err(StoreError::Corrupt(format!(
                    "delta object {child_oid} records chain depth {depth} outside 1..={MAX_DELTA_DEPTH}"
                )));
            }

            if base_oid.kind() != expected_kind {
                return Err(StoreError::ObjectFormat(format!(
                    "delta base {base_oid} of {child_oid} is not a {expected_kind} digest"
                )));
            }

            let base_location = lookup_object(&objects_table, &base_oid)?.ok_or_else(|| {
                StoreError::Corrupt(format!(
                    "committed delta {child_oid} references missing base {base_oid}"
                ))
            })?;

            if base_location.kind != kind || base_location.depth.checked_add(1) != Some(depth) {
                return Err(StoreError::Corrupt(format!(
                    "delta {child_oid} (depth {depth}) disagrees with its base {base_oid} (depth {}, kind {:?})",
                    base_location.depth, base_location.kind
                )));
            }

            cursor_oid = base_oid;
            cursor_location = base_location;
        }

        drop(txn);

        Ok(ObjectSnapshot {
            target_oid: *oid,
            target_kind,
            target_depth,
            links,
        })
    }

    /// At most `limit` object rows in raw-digest order whose key is
    /// strictly greater than `after`. Each call is its own read
    /// transaction, so a recovery pass pages through the table without
    /// holding any snapshot across payload I/O.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a key that is not a valid object id or
    /// a row that fails decoding or consistency checks.
    pub(crate) fn object_page(
        &self,
        after: Option<&Oid>,
        limit: usize,
    ) -> Result<Vec<(Oid, ObjectLocation)>, StoreError> {
        let mut page = Vec::with_capacity(limit.min(1024));
        if limit == 0 {
            return Ok(page);
        }
        let txn = self.db.begin_read().map_err(txn_error)?;
        let table = txn.open_table(OBJECTS).map_err(table_error)?;
        let lower: Bound<&[u8]> =
            after.map_or(Bound::Unbounded, |oid| Bound::Excluded(oid.as_bytes()));
        let rows = table
            .range::<&[u8]>((lower, Bound::Unbounded))
            .map_err(storage)?;
        for row in rows.take(limit) {
            let (key, value) = row.map_err(storage)?;
            let oid = Oid::from_bytes(key.value()).map_err(|err| {
                StoreError::Corrupt(format!("objects table holds an invalid object id: {err}"))
            })?;
            let location = decode_location(&oid, value.value())?;
            page.push((oid, location));
        }
        Ok(page)
    }

    /// The manifest of segment `id`, or `None` if no such row exists.
    pub(crate) fn manifest(&self, id: u64) -> Result<Option<SegmentManifest>, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        lookup_manifest(&txn.open_table(SEGMENTS).map_err(table_error)?, id)
    }

    /// Every segment manifest in id order. Recovery needs the whole set;
    /// there is one small row per segment (about 40 bytes per 256 MiB of
    /// payload), so the collected vector stays far below the preparation
    /// budget, and collecting lets the read transaction end before any
    /// segment file is touched.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] when a row fails decoding, its stored key
    /// differs from its id, or its extents are inconsistent.
    pub(crate) fn all_manifests(&self) -> Result<Vec<SegmentManifest>, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        let table = txn.open_table(SEGMENTS).map_err(table_error)?;
        let mut manifests = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            manifests.push(decode_manifest(key.value(), value.value())?);
        }
        Ok(manifests)
    }

    /// Returns at most `budget.rows` (clamped to 1024) fact rows strictly
    /// after `after` in raw key order, totaling at most `budget.bytes` of
    /// copied key and value bytes.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for zero rows or bytes in `budget`;
    /// [`StoreError::Limit`] if the first row alone exceeds `budget.bytes`;
    /// [`StoreError::Corrupt`] or [`StoreError::Storage`] for redb failures.
    pub(crate) fn fact_page(
        &self,
        table: FactTable,
        after: Option<&[u8]>,
        budget: FactPageBudget,
    ) -> Result<FactPage, StoreError> {
        if budget.rows == 0 || budget.bytes == 0 {
            return Err(StoreError::Invalid(format!(
                "fact page budget must specify non-zero rows and bytes, found rows={} bytes={}",
                budget.rows, budget.bytes
            )));
        }

        let max_rows = budget.rows.min(1024);
        let mut rows = Vec::with_capacity(max_rows.min(64));
        let mut accumulated_bytes: usize = 0;
        let mut more = false;

        let txn = self.db.begin_read().map_err(txn_error)?;
        let fact_table = txn
            .open_table(fact_definition(table))
            .map_err(table_error)?;
        let lower: Bound<&[u8]> = after.map_or(Bound::Unbounded, |key| Bound::Excluded(key));
        let mut iter = fact_table
            .range::<&[u8]>((lower, Bound::Unbounded))
            .map_err(storage)?;

        while let Some(item) = iter.next() {
            let (key_guard, value_guard) = item.map_err(storage)?;
            let key = key_guard.value();
            let value = value_guard.value();

            let row_bytes = key.len().checked_add(value.len()).ok_or_else(|| {
                StoreError::Capacity("fact row key + value bytes overflow usize".to_owned())
            })?;

            let new_total = accumulated_bytes.checked_add(row_bytes).ok_or_else(|| {
                StoreError::Capacity("fact page accumulated bytes overflow usize".to_owned())
            })?;

            if new_total > budget.bytes {
                if rows.is_empty() {
                    return Err(StoreError::Limit(format!(
                        "first fact row in table {} requires {row_bytes} bytes, exceeding budget {}",
                        table.table_name(),
                        budget.bytes
                    )));
                }
                more = true;
                break;
            }

            rows.push(FactRow {
                key: key.to_vec(),
                value: value.to_vec(),
            });
            accumulated_bytes = new_total;

            if rows.len() == max_rows || accumulated_bytes == budget.bytes {
                if iter.next().transpose().map_err(storage)?.is_some() {
                    more = true;
                }
                break;
            }
        }

        Ok(FactPage { rows, more })
    }

    /// The exact value stored under `key` in `table`, if any.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if the stored row's key + value bytes exceed
    /// [`MAX_FACT_ROW_BYTES`] (16 MiB).
    pub(crate) fn fact(&self, table: FactTable, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_read().map_err(txn_error)?;
        let rows = txn
            .open_table(fact_definition(table))
            .map_err(table_error)?;
        let found = rows.get(key).map_err(storage)?;
        let Some(guard) = found else {
            return Ok(None);
        };
        let value = guard.value();
        let total_bytes = key.len().checked_add(value.len()).ok_or_else(|| {
            StoreError::Capacity("fact row key + value bytes overflow usize".to_owned())
        })?;
        if total_bytes > MAX_FACT_ROW_BYTES {
            return Err(StoreError::Corrupt(format!(
                "fact row in table {} has key + value size {total_bytes} bytes exceeding maximum {MAX_FACT_ROW_BYTES}",
                table.table_name()
            )));
        }
        Ok(Some(value.to_vec()))
    }

    /// Begins the one write transaction of a publication, and inside it
    /// verifies every expectation of `facts` and applies the mutations.
    ///
    /// Nothing is visible until [`PublicationTxn::commit`]. Dropping the
    /// transaction on any path aborts it and leaves every fact, object,
    /// manifest and the generation exactly as before.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when two mutations name the same
    /// `(table, key)`, before a transaction opens; [`StoreError::StaleFact`]
    /// naming the first mutation whose expectation failed; redb failures.
    pub(crate) fn begin_publication(
        &self,
        facts: &[FactMutation],
    ) -> Result<PublicationTxn, StoreError> {
        reject_duplicate_facts(facts)?;
        let mut txn = self.db.begin_write().map_err(txn_error)?;
        txn.set_durability(Durability::Immediate)?;
        for fact in facts {
            apply_fact(&txn, fact)?;
        }
        Ok(PublicationTxn { txn })
    }
}

/// The owned write transaction of one publication.
///
/// Created by [`Metadata::begin_publication`] with the fact mutations
/// already applied. Methods validate before they write, so a rejected call
/// leaves the transaction exactly as it was; the owner still drops it on
/// any error. [`Self::commit`] consumes it.
pub(crate) struct PublicationTxn {
    txn: WriteTransaction,
}

impl fmt::Debug for PublicationTxn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicationTxn").finish_non_exhaustive()
    }
}

impl PublicationTxn {
    /// The locator for `oid` as of this transaction.
    pub(crate) fn get_object(&self, oid: &Oid) -> Result<Option<ObjectLocation>, StoreError> {
        lookup_object(&self.txn.open_table(OBJECTS).map_err(table_error)?, oid)
    }

    /// Publishes a new locator. The key must not exist: published bytes
    /// are immutable and a second row would orphan the first.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for an existing key or a location whose
    /// extent, base or depth is inconsistent.
    pub(crate) fn insert_object(
        &self,
        oid: &Oid,
        location: &ObjectLocation,
    ) -> Result<(), StoreError> {
        if let Some(defect) = location_defect(oid, location) {
            return Err(StoreError::Invalid(format!("object {oid}: {defect}")));
        }
        let encoded = encode("object location", location)?;
        let mut table = self.txn.open_table(OBJECTS).map_err(table_error)?;
        if table.get(oid.as_bytes()).map_err(storage)?.is_some() {
            return Err(StoreError::Invalid(format!(
                "object {oid} is already published"
            )));
        }
        table
            .insert(oid.as_bytes(), encoded.as_slice())
            .map_err(storage)?;
        Ok(())
    }

    /// Moves a committed locator to its compacted position. The key must
    /// already exist: compaction rewrites positions, never identities, so a
    /// missing row means the swap set raced its own snapshot and the swap
    /// must abort rather than invent a locator.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for a missing key or a location whose
    /// extent, base or depth is inconsistent.
    pub(crate) fn replace_object(
        &self,
        oid: &Oid,
        location: &ObjectLocation,
    ) -> Result<(), StoreError> {
        if let Some(defect) = location_defect(oid, location) {
            return Err(StoreError::Invalid(format!("object {oid}: {defect}")));
        }
        let encoded = encode("object location", location)?;
        let mut table = self.txn.open_table(OBJECTS).map_err(table_error)?;
        if table.get(oid.as_bytes()).map_err(storage)?.is_none() {
            return Err(StoreError::Invalid(format!(
                "object {oid} has no committed locator to replace"
            )));
        }
        table
            .insert(oid.as_bytes(), encoded.as_slice())
            .map_err(storage)?;
        Ok(())
    }

    /// Records the committed state of one segment.
    ///
    /// Extents must be consistent (`committed_end` is `records_end`, plus
    /// the 24-byte footer exactly when sealed) and must only move forward
    /// from the stored row: a committed end never shrinks, a seal is never
    /// undone, a sealed segment's extents never change, retirement is never
    /// undone.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for an inconsistent or regressing manifest.
    pub(crate) fn upsert_manifest(&self, manifest: &SegmentManifest) -> Result<(), StoreError> {
        if let Some(defect) = manifest_defect(manifest) {
            return Err(StoreError::Invalid(format!(
                "segment {}: {defect}",
                manifest.id
            )));
        }
        let encoded = encode("segment manifest", manifest)?;
        let mut table = self.txn.open_table(SEGMENTS).map_err(table_error)?;
        if let Some(stored) = lookup_manifest(&table, manifest.id)?
            && let Some(defect) = manifest_transition_defect(&stored, manifest)
        {
            return Err(StoreError::Invalid(format!(
                "segment {}: {defect}",
                manifest.id
            )));
        }
        table
            .insert(manifest.id, encoded.as_slice())
            .map_err(storage)?;
        Ok(())
    }

    /// Advances the locator generation, which must exceed the stored one.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when `generation` does not advance.
    pub(crate) fn set_generation(&self, generation: u64) -> Result<(), StoreError> {
        let mut table = self.txn.open_table(GENERATION).map_err(table_error)?;
        let current = lookup_generation(&table)?;
        if generation <= current {
            return Err(StoreError::Invalid(format!(
                "generation {generation} does not advance past {current}"
            )));
        }
        table.insert((), generation).map_err(storage)?;
        Ok(())
    }

    /// Commits every change in one transaction with Immediate durability.
    ///
    /// # Errors
    /// [`StoreError::Commit`]. The failure may already be durable: the
    /// caller must stop publishing and let recovery decide, never truncate
    /// bytes or assume rollback.
    pub(crate) fn commit(self) -> Result<(), StoreError> {
        self.txn.commit()?;
        Ok(())
    }
}

fn reject_duplicate_facts(facts: &[FactMutation]) -> Result<(), StoreError> {
    let mut keys: Vec<(FactTable, &[u8])> = facts
        .iter()
        .map(|fact| (fact.table, fact.key.as_slice()))
        .collect();
    keys.sort_unstable();
    if let Some(pair) = keys.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(StoreError::Invalid(format!(
            "two mutations of {} key {} in one publication",
            pair[0].0.table_name(),
            key_text(pair[0].1)
        )));
    }
    Ok(())
}

/// Verifies one expectation against the transaction's own view and applies
/// the mutation. The publisher holds the only write transaction, so what is
/// verified here is what the commit applies to.
fn apply_fact(txn: &WriteTransaction, fact: &FactMutation) -> Result<(), StoreError> {
    let mut table = txn
        .open_table(fact_definition(fact.table))
        .map_err(table_error)?;
    let stale = match &fact.expected {
        FactExpectation::Any => false,
        FactExpectation::Absent => table.get(fact.key.as_slice()).map_err(storage)?.is_some(),
        FactExpectation::Value(want) => table
            .get(fact.key.as_slice())
            .map_err(storage)?
            .is_none_or(|stored| stored.value() != want.as_slice()),
    };
    if stale {
        return Err(StoreError::StaleFact {
            table: fact.table.table_name(),
            key: key_text(&fact.key),
        });
    }
    match &fact.value {
        Some(value) => {
            table
                .insert(fact.key.as_slice(), value.as_slice())
                .map_err(storage)?;
        }
        None => {
            table.remove(fact.key.as_slice()).map_err(storage)?;
        }
    }
    Ok(())
}

/// Creates only the `lfs_objects` table when the database predates that
/// schema revision, so an older store opens with the new table empty
/// instead of refusing. Every other census table keeps its existing
/// meaning: a missing one is still damage, never silently recreated —
/// recreating `objects` would orphan segment bytes behind vanished
/// locators and turn damage into silent missing-object reads. A write
/// transaction's `open_table` creates the table only when absent;
/// existing tables and rows are untouched.
fn ensure_census(db: &Database) -> Result<(), StoreError> {
    let mut txn = db.begin_write().map_err(txn_error)?;
    txn.open_table(fact_definition(FactTable::LfsObjects))
        .map_err(table_error)?;
    txn.commit()?;
    Ok(())
}

fn verify_census(db: &Database) -> Result<(), StoreError> {
    let txn = db.begin_read().map_err(txn_error)?;
    for handle in txn.list_tables().map_err(storage)? {
        if !is_census_name(handle.name()) {
            return Err(StoreError::Version(format!(
                "metadata database holds unknown table {}",
                handle.name()
            )));
        }
    }
    if txn
        .list_multimap_tables()
        .map_err(storage)?
        .next()
        .is_some()
    {
        return Err(StoreError::Version(
            "metadata database holds an unexpected multimap table".to_owned(),
        ));
    }
    txn.open_table(OBJECTS).map_err(table_error)?;
    txn.open_table(SEGMENTS).map_err(table_error)?;
    for table in FactTable::ALL {
        txn.open_table(fact_definition(table))
            .map_err(table_error)?;
    }
    lookup_generation(&txn.open_table(GENERATION).map_err(table_error)?)?;
    Ok(())
}

fn lookup_generation(table: &impl ReadableTable<(), u64>) -> Result<u64, StoreError> {
    table
        .get(())
        .map_err(storage)?
        .map(|guard| guard.value())
        .ok_or_else(|| StoreError::Corrupt("metadata database has no generation row".to_owned()))
}

fn lookup_object(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    oid: &Oid,
) -> Result<Option<ObjectLocation>, StoreError> {
    let found = table.get(oid.as_bytes()).map_err(storage)?;
    found
        .map(|guard| decode_location(oid, guard.value()))
        .transpose()
}

fn lookup_manifest(
    table: &impl ReadableTable<u64, &'static [u8]>,
    id: u64,
) -> Result<Option<SegmentManifest>, StoreError> {
    let found = table.get(id).map_err(storage)?;
    found
        .map(|guard| decode_manifest(id, guard.value()))
        .transpose()
}

fn decode_location(oid: &Oid, bytes: &[u8]) -> Result<ObjectLocation, StoreError> {
    let location: ObjectLocation = decode("object location", bytes)?;
    match location_defect(oid, &location) {
        None => Ok(location),
        Some(defect) => Err(StoreError::Corrupt(format!("object {oid}: {defect}"))),
    }
}

fn decode_manifest(id: u64, bytes: &[u8]) -> Result<SegmentManifest, StoreError> {
    let manifest: SegmentManifest = decode("segment manifest", bytes)?;
    if manifest.id != id {
        return Err(StoreError::Corrupt(format!(
            "segment row {id} holds a manifest for segment {}",
            manifest.id
        )));
    }
    match manifest_defect(&manifest) {
        None => Ok(manifest),
        Some(defect) => Err(StoreError::Corrupt(format!("segment {id}: {defect}"))),
    }
}

/// Decodes exactly one postcard value: truncation, an out-of-range
/// discriminant or length, and bytes left over are all corruption.
pub(crate) fn decode<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> Result<T, StoreError> {
    let (value, rest) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|err| StoreError::Corrupt(format!("{what}: malformed postcard row: {err}")))?;
    if !rest.is_empty() {
        return Err(StoreError::Corrupt(format!(
            "{what}: {} bytes follow the postcard row",
            rest.len()
        )));
    }
    Ok(value)
}

pub(crate) fn encode<T: Serialize>(what: &str, value: &T) -> Result<Vec<u8>, StoreError> {
    postcard::to_allocvec(value)
        .map_err(|err| StoreError::Invalid(format!("{what} cannot be encoded: {err}")))
}

fn location_defect(oid: &Oid, location: &ObjectLocation) -> Option<String> {
    if location.record_len < RECORD_HEADER_LEN {
        return Some(format!(
            "record length {} is shorter than the {RECORD_HEADER_LEN}-byte header",
            location.record_len
        ));
    }
    if location.offset.checked_add(location.record_len).is_none() {
        return Some("record extent overflows u64".to_owned());
    }
    match location.base {
        None if location.depth != 0 => Some(format!(
            "record without a delta base has depth {}",
            location.depth
        )),
        None => None,
        Some(base) => {
            if location.depth == 0 || location.depth > MAX_DELTA_DEPTH {
                Some(format!(
                    "delta record has depth {}, outside 1..={MAX_DELTA_DEPTH}",
                    location.depth
                ))
            } else if base.as_bytes().len() != oid.as_bytes().len() {
                Some(format!("delta base {base} has a different digest width"))
            } else if base == *oid {
                Some("delta base is the object itself".to_owned())
            } else {
                None
            }
        }
    }
}

fn manifest_defect(manifest: &SegmentManifest) -> Option<String> {
    let Some(footer) = manifest.committed_end.checked_sub(manifest.records_end) else {
        return Some(format!(
            "records end {} lies past committed end {}",
            manifest.records_end, manifest.committed_end
        ));
    };
    let expected = if manifest.sealed { SEAL_FOOTER_LEN } else { 0 };
    (footer != expected).then(|| {
        format!(
            "{} segment has {footer} bytes between records end and committed end, expected {expected}",
            if manifest.sealed { "sealed" } else { "unsealed" }
        )
    })
}

fn manifest_transition_defect(stored: &SegmentManifest, next: &SegmentManifest) -> Option<String> {
    if next.committed_end < stored.committed_end {
        Some(format!(
            "committed end would shrink from {} to {}",
            stored.committed_end, next.committed_end
        ))
    } else if stored.sealed && !next.sealed {
        Some("a seal would be undone".to_owned())
    } else if stored.sealed
        && (next.records_end != stored.records_end || next.committed_end != stored.committed_end)
    {
        Some("a sealed segment's extents would change".to_owned())
    } else if stored.retired && !next.retired {
        Some("a retirement would be undone".to_owned())
    } else {
        None
    }
}

fn key_text(key: &[u8]) -> String {
    const SHOWN: usize = 64;
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(key.len().min(SHOWN) * 2 + 3);
    for &byte in key.iter().take(SHOWN) {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    if key.len() > SHOWN {
        text.push_str("...");
    }
    text
}

fn storage(err: StorageError) -> StoreError {
    match err {
        StorageError::Corrupted(message) => {
            StoreError::Corrupt(format!("metadata database: {message}"))
        }
        other => StoreError::Storage(other),
    }
}

fn txn_error(err: TransactionError) -> StoreError {
    match err {
        TransactionError::Storage(inner) => storage(inner),
        other => StoreError::Transaction(other),
    }
}

/// A census table that is absent, mistyped or redefined is damaged
/// authority; only a live double-open is the caller's own defect.
fn table_error(err: TableError) -> StoreError {
    match err {
        TableError::Storage(inner) => storage(inner),
        other @ TableError::TableAlreadyOpen(..) => StoreError::Table(other),
        other => StoreError::Corrupt(format!("metadata table census: {other}")),
    }
}

fn database_error(err: DatabaseError) -> StoreError {
    match err {
        DatabaseError::Storage(StorageError::Io(err)) => match err.kind() {
            io::ErrorKind::InvalidData => StoreError::Corrupt(format!("metadata database: {err}")),
            io::ErrorKind::NotFound => {
                StoreError::Corrupt(format!("metadata database is missing: {err}"))
            }
            _ => StoreError::Io(err),
        },
        DatabaseError::Storage(inner) => storage(inner),
        DatabaseError::UpgradeRequired(version) => StoreError::Version(format!(
            "metadata database file format {version} needs an offline upgrade"
        )),
        other => StoreError::Database(other),
    }
}
