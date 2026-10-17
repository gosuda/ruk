//! Preparation of native commit creations, local rewrites, and batch imports.
//!
//! Provides [`RecordBatchPreparer`] with an in-memory pending overlay to prevent
//! stale store reads across multi-step transactions, and single-record convenience
//! methods on [`Records`].
//!
//! Returns precise CAS [`FactMutation`]s and [`PreparedObject`]s for the coordinator's
//! single publication lane. Performs no production [`Store::publish`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use super::codec::{
    decode_change_entry, decode_imported_change, encode_change_entry, encode_change_history,
    encode_commit_record, encode_imported_change,
};
use super::keys::{change_key, head_key, history_key, imported_change_key};
use super::reader::Records;
use super::types::{
    ChangeEntry, ChangeState, PreparedImport, PreparedNativeCommit, PreparedRecordBatch,
};
use crate::change::ChangeId;
use crate::commit::{CommitRecord, NativeCommitInput, Provenance};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::store::types::{FactExpectation, FactMutation, FactTable, ObjectKind};
use crate::store::{PreparedObject, Store};

/// Tracks pending state of a change entry within a batch.
pub(crate) struct PendingChange {
    pub(crate) initial_bytes: Option<Vec<u8>>,
    pub(crate) current_entry: ChangeEntry,
    pub(crate) touched: bool,
}

/// Tracks pending state of an imported OID -> ChangeId mapping.
pub(crate) struct PendingImported {
    pub(crate) change_id: ChangeId,
    pub(crate) is_new: bool,
}

/// In-memory overlay batch preparer for record mutations.
pub struct RecordBatchPreparer<'a> {
    pub(crate) store: &'a Store,
    pub(crate) prepared_objects: Vec<PreparedObject>,
    pub(crate) pending_commits: BTreeMap<Head, CommitRecord>,
    pub(crate) pending_changes: BTreeMap<ChangeId, PendingChange>,
    pub(crate) pending_imported: BTreeMap<Oid, PendingImported>,
    pub(crate) pending_history: BTreeSet<(ChangeId, Head)>,
}

impl<'a> RecordBatchPreparer<'a> {
    /// Creates a new batch preparer backed by `store`.
    #[must_use]
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
            prepared_objects: Vec::new(),
            pending_commits: BTreeMap::new(),
            pending_changes: BTreeMap::new(),
            pending_imported: BTreeMap::new(),
            pending_history: BTreeSet::new(),
        }
    }

    /// Resolves an existing imported OID mapping or mints a fresh local ChangeId.
    ///
    /// Checks the pending overlay first, then the Store. If absent from both,
    /// mints a fresh random ChangeId and records a pending mapping with CAS
    /// expectation [`FactExpectation::Absent`].
    pub fn resolve_or_mint_change_id(&mut self, oid: &Oid) -> Result<ChangeId, CoreError> {
        if let Some(pending) = self.pending_imported.get(oid) {
            return Ok(pending.change_id);
        }

        let key = imported_change_key(oid);
        let raw = self.store.fact(FactTable::ImportedChanges, &key)?;

        let (change_id, is_new) = match raw {
            Some(bytes) => {
                let cid = decode_imported_change(self.store, oid, &bytes)?;
                (cid, false)
            }
            None => {
                let cid = ChangeId::generate();
                (cid, true)
            }
        };

        self.pending_imported
            .insert(*oid, PendingImported { change_id, is_new });
        Ok(change_id)
    }

    /// Adds a native commit creation or trusted local rewrite to the batch.
    ///
    /// If `input.predecessor` is `Some(old_head)`, verifies `old_head` is currently
    /// present in the change's heads (returning `E_STALE` on mismatch) and replaces
    /// it with the new head. If `input.predecessor` is `None` and the change already
    /// exists, adds a divergent head.
    pub fn add_native_commit(&mut self, input: NativeCommitInput) -> Result<Head, CoreError> {
        let kind = self.store.hash_kind();
        let predecessor_head = input.predecessor;
        let change_id = input.change_id;

        let record = CommitRecord::create(input, kind)?;
        let head = record.head()?;

        // Predecessor membership is validated before object staging: a stale
        // head names the CAS condition the caller violated, while the staged
        // delta base is an implementation detail that must never leak a
        // NotFound ahead of the authoritative E_STALE.
        self.apply_change_transition(change_id, head, predecessor_head.as_ref())?;
        let prepared = self.stage_commit_object(&record, predecessor_head.as_ref())?;

        self.prepared_objects.push(prepared);
        self.pending_commits.insert(head, record);
        self.pending_history.insert((change_id, head));

        Ok(head)
    }

    /// Adds an imported Git commit payload to the batch.
    ///
    /// Preserves raw Git payload bytes and header order. Matching change IDs
    /// add divergent heads unless the exact OID is already known.
    pub fn add_import_git(
        &mut self,
        payload: Vec<u8>,
        provenance: Option<Provenance>,
    ) -> Result<Head, CoreError> {
        let kind = self.store.hash_kind();
        let oid = kind.hash_git_object("commit", &payload)?;
        let head = Head::Git { oid };

        let declared_header = CommitRecord::git_header_change_id(&payload);
        let was_present = self.pending_imported.contains_key(&oid);
        let change_id = match declared_header {
            Some(declared) => declared,
            None => self.resolve_or_mint_change_id(&oid)?,
        };
        let minted_in_this_call = declared_header.is_none()
            && !was_present
            && self
                .pending_imported
                .get(&oid)
                .is_some_and(|pending| pending.is_new);

        let payload_len = u64::try_from(payload.len()).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "commit payload length overflows u64")
        })?;
        let prepared = self.store.prepare(
            ObjectKind::Commit,
            payload_len,
            Cursor::new(payload.as_slice()),
            None,
        )?;

        let record = match CommitRecord::import_git(payload, kind, change_id, provenance) {
            Ok(record) => record,
            Err(err) => {
                if minted_in_this_call {
                    self.pending_imported.remove(&oid);
                }
                return Err(CoreError::from(err));
            }
        };

        if let Err(err) = self.apply_import_transition(change_id, head) {
            if minted_in_this_call {
                self.pending_imported.remove(&oid);
            }
            return Err(err);
        }

        self.prepared_objects.push(prepared);
        self.pending_commits.insert(head, record);
        self.pending_history.insert((change_id, head));

        Ok(head)
    }

    /// Stages a commit object (Git commit or native conflict) through Store preparation.
    fn stage_commit_object(
        &self,
        record: &CommitRecord,
        predecessor: Option<&Head>,
    ) -> Result<PreparedObject, CoreError> {
        if record.is_exportable() {
            let payload = record.git_payload().ok_or_else(|| {
                CoreError::new(ErrorCode::EInvalid, "exportable record missing git payload")
            })?;
            let delta_base = match predecessor {
                Some(Head::Git { oid }) => Some(*oid),
                _ => None,
            };
            let payload_len = u64::try_from(payload.len()).map_err(|_| {
                CoreError::new(ErrorCode::ECapacity, "git payload length overflows u64")
            })?;
            let prepared = self.store.prepare(
                ObjectKind::Commit,
                payload_len,
                Cursor::new(payload),
                delta_base,
            )?;
            return Ok(prepared);
        }

        let native = record.native_record().ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "unexportable record missing native frame",
            )
        })?;
        let frame = native.encode();
        let frame_len = u64::try_from(frame.len()).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "conflict frame length overflows u64")
        })?;
        let prepared =
            self.store
                .prepare(ObjectKind::Conflict, frame_len, Cursor::new(frame), None)?;
        Ok(prepared)
    }

    /// Ensures a change entry exists in the overlay, loading from Store if needed.
    fn load_or_init_change(
        &mut self,
        change_id: ChangeId,
        initial_head: Option<Head>,
    ) -> Result<(), CoreError> {
        if self.pending_changes.contains_key(&change_id) {
            return Ok(());
        }

        let key = change_key(&change_id);
        let raw = self.store.fact(FactTable::Changes, &key)?;

        match raw {
            Some(bytes) => {
                let entry = decode_change_entry(self.store, &change_id, &bytes)?;
                self.pending_changes.insert(
                    change_id,
                    PendingChange {
                        initial_bytes: Some(bytes),
                        current_entry: entry,
                        touched: false,
                    },
                );
            }
            None => {
                let Some(h) = initial_head else {
                    return Err(CoreError::new(
                        ErrorCode::ENotFound,
                        format!("change {change_id} does not exist"),
                    ));
                };
                self.pending_changes.insert(
                    change_id,
                    PendingChange {
                        initial_bytes: None,
                        current_entry: ChangeEntry::new(ChangeState::Active, h),
                        touched: true,
                    },
                );
            }
        }
        Ok(())
    }

    /// Applies state transition for a native commit or local rewrite.
    fn apply_change_transition(
        &mut self,
        change_id: ChangeId,
        new_head: Head,
        predecessor: Option<&Head>,
    ) -> Result<(), CoreError> {
        // If predecessor specified, change must already exist
        let initial_head = match predecessor {
            Some(_) => None,
            None => Some(new_head),
        };

        self.load_or_init_change(change_id, initial_head)?;
        let pending = self.pending_changes.get_mut(&change_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "change entry missing in pending overlay",
            )
        })?;

        match predecessor {
            Some(old_head) => {
                pending.current_entry.replace_head(old_head, new_head)?;
                pending.touched = true;
            }
            None => {
                if pending.current_entry.add_head(new_head)? {
                    pending.touched = true;
                }
            }
        }
        Ok(())
    }

    /// Applies state transition for an imported Git commit.
    pub(crate) fn apply_import_transition(
        &mut self,
        change_id: ChangeId,
        head: Head,
    ) -> Result<(), CoreError> {
        self.load_or_init_change(change_id, Some(head))?;
        let pending = self.pending_changes.get_mut(&change_id).ok_or_else(|| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "change entry missing in pending overlay",
            )
        })?;

        if pending.current_entry.add_head(head)? {
            pending.touched = true;
        }
        Ok(())
    }

    /// Finishes the batch preparation, compiling pending state into exact CAS FactMutations.
    pub fn finish(self) -> Result<PreparedRecordBatch, CoreError> {
        let mut mutations = Vec::new();

        // 1. Commits
        for (head, record) in self.pending_commits {
            mutations.push(FactMutation {
                table: FactTable::Commits,
                key: head_key(&head),
                expected: FactExpectation::Absent,
                value: Some(encode_commit_record(&record)?),
            });
        }

        // 2. Changes
        for (change_id, pending) in self.pending_changes {
            if !pending.touched {
                continue;
            }
            let key = change_key(&change_id).to_vec();
            let expected = match pending.initial_bytes {
                Some(bytes) => FactExpectation::Value(bytes),
                None => FactExpectation::Absent,
            };
            mutations.push(FactMutation {
                table: FactTable::Changes,
                key,
                expected,
                value: Some(encode_change_entry(&pending.current_entry)?),
            });
        }

        // 3. ImportedChanges
        for (oid, pending) in self.pending_imported {
            if !pending.is_new {
                continue;
            }
            mutations.push(FactMutation {
                table: FactTable::ImportedChanges,
                key: imported_change_key(&oid),
                expected: FactExpectation::Absent,
                value: Some(encode_imported_change(pending.change_id)?),
            });
        }

        // 4. ChangeHistory
        for (change_id, head) in self.pending_history {
            mutations.push(FactMutation {
                table: FactTable::ChangeHistory,
                key: history_key(&change_id, &head),
                expected: FactExpectation::Absent,
                value: Some(encode_change_history()?),
            });
        }

        Ok(PreparedRecordBatch {
            prepared_objects: self.prepared_objects,
            mutations,
        })
    }
}

// ---------------------------------------------------------------------------
// Convenience Methods on Records
// ---------------------------------------------------------------------------

impl<'a> Records<'a> {
    /// Creates a batch preparer for multi-record operations.
    #[must_use]
    pub fn batch_preparer(&self) -> RecordBatchPreparer<'a> {
        RecordBatchPreparer::new(self.store())
    }

    /// Prepares a single native commit creation or trusted local rewrite.
    pub fn prepare_native_commit(
        &self,
        input: NativeCommitInput,
    ) -> Result<PreparedNativeCommit, CoreError> {
        let mut preparer = self.batch_preparer();
        let head = preparer.add_native_commit(input)?;
        let record = preparer
            .pending_commits
            .get(&head)
            .cloned()
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "prepared commit record missing in pending overlay",
                )
            })?;
        let batch = preparer.finish()?;

        let mut objects = batch.prepared_objects;
        let prepared_object = if objects.is_empty() {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "no prepared object emitted for native commit",
            ));
        } else {
            objects.remove(0)
        };

        Ok(PreparedNativeCommit {
            head,
            record,
            prepared_object,
            mutations: batch.mutations,
        })
    }

    /// Prepares a single imported Git commit payload.
    pub fn prepare_import_git(
        &self,
        payload: Vec<u8>,
        provenance: Option<Provenance>,
    ) -> Result<PreparedImport, CoreError> {
        let mut preparer = self.batch_preparer();
        let head = preparer.add_import_git(payload, provenance)?;
        let record = preparer
            .pending_commits
            .get(&head)
            .cloned()
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "prepared commit record missing in pending overlay",
                )
            })?;
        let change_id = record.change_id();

        let is_divergent = preparer
            .pending_changes
            .get(&change_id)
            .is_some_and(|p| p.current_entry.is_divergent());

        let batch = preparer.finish()?;
        let mut objects = batch.prepared_objects;
        let prepared_object = if objects.is_empty() {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "no prepared object emitted for git import",
            ));
        } else {
            objects.remove(0)
        };

        Ok(PreparedImport {
            head,
            change_id,
            record,
            is_divergent,
            prepared_object,
            mutations: batch.mutations,
        })
    }
}
