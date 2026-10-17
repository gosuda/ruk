//! Git commit import bridge with in-memory pending overlay.
//!
//! Provides [`ImportBatch`] to process imported Git commits from `ruk-git`.
//! Staged objects and CAS mutations are generated without repeated stale Store reads.
//!
//! Preserves:
//! - Exact Git commit payload bytes and original header order
//! - Stable by-OID mapping in `FactTable::ImportedChanges` for commits lacking a `change-id` header
//! - Divergent head tracking when a known `change-id` is observed with a new OID
//! - Idempotent no-op for already-known commit OIDs

use std::io::Cursor;

use super::codec::{decode_change_entry, decode_commit_record};
use super::keys::{change_key, head_key};
use super::preparer::RecordBatchPreparer;
use super::types::ImportOutcome;
use crate::change::ChangeId;
use crate::commit::{CommitRecord, Provenance};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::store::types::{FactMutation, FactTable, ObjectKind};
use crate::store::{PreparedObject, Store};

/// A batch of Git commit observations with an in-memory pending overlay.
pub struct ImportBatch<'a> {
    preparer: RecordBatchPreparer<'a>,
    outcomes: Vec<ImportOutcome>,
}

impl<'a> ImportBatch<'a> {
    /// Creates a new import batch backed by `store`.
    #[must_use]
    pub fn new(store: &'a Store) -> Self {
        Self {
            preparer: RecordBatchPreparer::new(store),
            outcomes: Vec::new(),
        }
    }

    /// Resolves an existing imported OID mapping or mints a fresh local ChangeId.
    pub fn resolve_or_mint_change_id(&mut self, oid: &Oid) -> Result<ChangeId, CoreError> {
        self.preparer.resolve_or_mint_change_id(oid)
    }

    /// Observes an already-parsed [`CommitRecord`] from an imported Git commit.
    ///
    /// If the head is already known for this change, returns [`ImportOutcome::Known`]
    /// and emits no new mutations. Otherwise adds a new change or divergent head.
    pub fn observe_git(&mut self, record: &CommitRecord) -> Result<ImportOutcome, CoreError> {
        let kind = self.preparer.store.hash_kind();
        if record.kind() != kind {
            return Err(CoreError::new(
                ErrorCode::EObjectFormat,
                format!(
                    "commit record kind {:?} does not match store format kind {:?}",
                    record.kind(),
                    kind
                ),
            ));
        }

        let head = record.head()?;
        let change_id = record.change_id();

        // 1. Check if head is already known for this change
        if self.is_head_known(&change_id, &head)? {
            let outcome = ImportOutcome::Known { head, change_id };
            self.outcomes.push(outcome);
            return Ok(outcome);
        }

        // 2. Stage object via Store::prepare
        let payload = record.git_payload().ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "imported commit must contain a Git payload",
            )
        })?;
        let payload_len = u64::try_from(payload.len()).map_err(|_| {
            CoreError::new(ErrorCode::ECapacity, "commit payload length overflows u64")
        })?;
        let prepared = self.preparer.store.prepare(
            ObjectKind::Commit,
            payload_len,
            Cursor::new(payload),
            None,
        )?;

        // 3. Classify outcome before updating overlay
        let is_existing_change = self.change_exists(&change_id)?;
        let outcome = if is_existing_change {
            ImportOutcome::Divergent { head, change_id }
        } else {
            ImportOutcome::NewChange { head, change_id }
        };

        // 4. Update overlay state
        self.preparer.apply_import_transition(change_id, head)?;
        self.preparer.prepared_objects.push(prepared);
        self.preparer.pending_commits.insert(head, record.clone());
        self.preparer.pending_history.insert((change_id, head));
        self.outcomes.push(outcome);

        Ok(outcome)
    }

    /// Observes a raw Git commit payload.
    ///
    /// Preserves exact bytes and header order. Checks for a declared `change-id`
    /// header; if absent, uses [`Self::resolve_or_mint_change_id`] for stable by-OID mapping.
    pub fn observe_git_payload(
        &mut self,
        payload: Vec<u8>,
        provenance: Option<Provenance>,
    ) -> Result<ImportOutcome, CoreError> {
        let kind = self.preparer.store.hash_kind();
        let oid = kind.hash_git_object("commit", &payload)?;
        let head = Head::Git { oid };

        // Fast path: if exact head already known in pending commits or Store
        if let Some(record) = self.lookup_commit(&head)? {
            let outcome = ImportOutcome::Known {
                head,
                change_id: record.change_id(),
            };
            self.outcomes.push(outcome);
            return Ok(outcome);
        }

        let change_id = match CommitRecord::git_header_change_id(&payload) {
            Some(declared) => declared,
            None => self.resolve_or_mint_change_id(&oid)?,
        };

        let record = CommitRecord::import_git(payload, kind, change_id, provenance)?;
        self.observe_git(&record)
    }

    /// Checks if a head is already known for `change_id` in the pending overlay or store.
    fn is_head_known(&self, change_id: &ChangeId, head: &Head) -> Result<bool, CoreError> {
        if let Some(pending) = self.preparer.pending_changes.get(change_id) {
            return Ok(pending.current_entry.contains_head(head));
        }

        let key = change_key(change_id);
        let raw = self.preparer.store.fact(FactTable::Changes, &key)?;
        let Some(bytes) = raw else {
            return Ok(false);
        };

        let entry = decode_change_entry(self.preparer.store, change_id, &bytes)?;
        Ok(entry.contains_head(head))
    }

    /// Checks if `change_id` exists in the pending overlay or store.
    fn change_exists(&self, change_id: &ChangeId) -> Result<bool, CoreError> {
        if self.preparer.pending_changes.contains_key(change_id) {
            return Ok(true);
        }
        let key = change_key(change_id);
        let raw = self.preparer.store.fact(FactTable::Changes, &key)?;
        Ok(raw.is_some())
    }

    /// Looks up a commit record in pending commits or store.
    fn lookup_commit(&self, head: &Head) -> Result<Option<CommitRecord>, CoreError> {
        if let Some(record) = self.preparer.pending_commits.get(head) {
            return Ok(Some(record.clone()));
        }
        let key = head_key(head);
        let raw = self.preparer.store.fact(FactTable::Commits, &key)?;
        let Some(bytes) = raw else {
            return Ok(None);
        };
        let record = decode_commit_record(self.preparer.store, head, &bytes)?;
        Ok(Some(record))
    }

    /// Recorded outcomes in this batch.
    #[must_use]
    pub fn outcomes(&self) -> &[ImportOutcome] {
        &self.outcomes
    }

    /// Finishes the batch, returning all compiled CAS mutations.
    pub fn into_mutations(self) -> Result<Vec<FactMutation>, CoreError> {
        let batch = self.preparer.finish()?;
        Ok(batch.mutations)
    }

    /// Finishes the batch, returning prepared objects and compiled CAS mutations.
    pub fn into_parts(self) -> Result<(Vec<PreparedObject>, Vec<FactMutation>), CoreError> {
        let batch = self.preparer.finish()?;
        Ok((batch.prepared_objects, batch.mutations))
    }
}
