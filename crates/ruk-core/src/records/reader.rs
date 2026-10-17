//! Typed point lookups and bounded range paging for records tables.
//!
//! Owns [`Records`], which provides typed read access to:
//! - `FactTable::Commits`
//! - `FactTable::Changes`
//! - `FactTable::ImportedChanges`
//! - `FactTable::ChangeHistory`
//!
//! Enforces semantic validation and latches quarantine on committed corruption.

use super::codec::{
    decode_change_entry, decode_change_history, decode_commit_record, decode_imported_change,
};
use super::keys::{
    change_key, decode_change_key, decode_head_key, decode_history_key,
    decode_imported_change_key, head_key, history_key, imported_change_key,
};
use super::types::{ChangeEntry, HistoryPage, RecordPage, RecordPageBudget};
use crate::change::ChangeId;
use crate::commit::CommitRecord;
use crate::error::CoreError;
use crate::heads::Head;
use crate::ids::Oid;
use crate::store::types::FactTable;
use crate::store::{FactPageBudget, Store};

/// Typed Store-backed reader for commits, changes, and history.
pub struct Records<'a> {
    store: &'a Store,
}

impl<'a> Records<'a> {
    /// Creates a reader backed by `store`.
    #[must_use]
    pub const fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// The underlying store handle.
    #[must_use]
    pub const fn store(&self) -> &'a Store {
        self.store
    }

    // -----------------------------------------------------------------------
    // Commits (FactTable::Commits)
    // -----------------------------------------------------------------------

    /// Reads one commit record by head.
    ///
    /// # Errors
    /// [`ErrorCode::ECorrupt`] on corrupt or semantically invalid bytes (latches quarantine);
    /// store read errors propagate.
    pub fn get_commit(&self, head: &Head) -> Result<Option<CommitRecord>, CoreError> {
        let key = head_key(head);
        let raw = self.store.fact(FactTable::Commits, &key)?;
        match raw {
            Some(bytes) => decode_commit_record(self.store, head, &bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Bounded range paging of commit records strictly after `after` in key order.
    pub fn page_commits(
        &self,
        after: Option<&Head>,
        budget: RecordPageBudget,
    ) -> Result<RecordPage<Head, CommitRecord>, CoreError> {
        let after_key = after.map(head_key);
        let fact_budget = FactPageBudget::new(budget.rows, budget.bytes);
        let page = self
            .store
            .fact_page(FactTable::Commits, after_key.as_deref(), fact_budget)?;

        let mut items = Vec::with_capacity(page.rows.len());
        for row in &page.rows {
            let head = decode_head_key(&row.key)?;
            let record = decode_commit_record(self.store, &head, &row.value)?;
            items.push((head, record));
        }

        let next_cursor = if page.more {
            items.last().map(|(h, _)| *h)
        } else {
            None
        };

        Ok(RecordPage {
            items,
            more: page.more,
            next_cursor,
        })
    }

    // -----------------------------------------------------------------------
    // Changes (FactTable::Changes)
    // -----------------------------------------------------------------------

    /// Reads one change entry by change ID.
    ///
    /// # Errors
    /// [`ErrorCode::ECorrupt`] on corrupt or semantically invalid bytes (latches quarantine);
    /// store read errors propagate.
    pub fn get_change(&self, change_id: &ChangeId) -> Result<Option<ChangeEntry>, CoreError> {
        let key = change_key(change_id);
        let raw = self.store.fact(FactTable::Changes, &key)?;
        match raw {
            Some(bytes) => decode_change_entry(self.store, change_id, &bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Bounded range paging of change entries strictly after `after` in key order.
    pub fn page_changes(
        &self,
        after: Option<&ChangeId>,
        budget: RecordPageBudget,
    ) -> Result<RecordPage<ChangeId, ChangeEntry>, CoreError> {
        let after_key = after.map(change_key);
        let fact_budget = FactPageBudget::new(budget.rows, budget.bytes);
        let page = self.store.fact_page(
            FactTable::Changes,
            after_key.as_ref().map(|k| k.as_slice()),
            fact_budget,
        )?;

        let mut items = Vec::with_capacity(page.rows.len());
        for row in &page.rows {
            let change_id = decode_change_key(&row.key)?;
            let entry = decode_change_entry(self.store, &change_id, &row.value)?;
            items.push((change_id, entry));
        }

        let next_cursor = if page.more {
            items.last().map(|(cid, _)| *cid)
        } else {
            None
        };

        Ok(RecordPage {
            items,
            more: page.more,
            next_cursor,
        })
    }

    // -----------------------------------------------------------------------
    // Imported Changes (FactTable::ImportedChanges)
    // -----------------------------------------------------------------------

    /// Reads the local change ID mapped to an imported Git commit OID.
    pub fn get_imported_change(&self, oid: &Oid) -> Result<Option<ChangeId>, CoreError> {
        let key = imported_change_key(oid);
        let raw = self.store.fact(FactTable::ImportedChanges, &key)?;
        match raw {
            Some(bytes) => decode_imported_change(self.store, oid, &bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Bounded range paging of imported change mappings strictly after `after` in key order.
    pub fn page_imported_changes(
        &self,
        after: Option<&Oid>,
        budget: RecordPageBudget,
    ) -> Result<RecordPage<Oid, ChangeId>, CoreError> {
        let after_key = after.map(imported_change_key);
        let fact_budget = FactPageBudget::new(budget.rows, budget.bytes);
        let page = self.store.fact_page(
            FactTable::ImportedChanges,
            after_key.as_deref(),
            fact_budget,
        )?;

        let mut items = Vec::with_capacity(page.rows.len());
        for row in &page.rows {
            let oid = decode_imported_change_key(&row.key, self.store.hash_kind())?;
            let change_id = decode_imported_change(self.store, &oid, &row.value)?;
            items.push((oid, change_id));
        }

        let next_cursor = if page.more {
            items.last().map(|(o, _)| *o)
        } else {
            None
        };

        Ok(RecordPage {
            items,
            more: page.more,
            next_cursor,
        })
    }

    // -----------------------------------------------------------------------
    // Change History (FactTable::ChangeHistory)
    // -----------------------------------------------------------------------

    /// Checks if `head` is recorded in `change_id`'s history.
    pub fn has_change_history(
        &self,
        change_id: &ChangeId,
        head: &Head,
    ) -> Result<bool, CoreError> {
        let key = history_key(change_id, head);
        let raw = self.store.fact(FactTable::ChangeHistory, &key)?;
        match raw {
            Some(bytes) => {
                decode_change_history(self.store, change_id, head, &bytes)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Bounded range paging of history heads for a specific `change_id`.
    ///
    /// Jumps directly to `change_id`'s contiguous range and stops immediately
    /// once keys depart from `change_id`'s 16-byte prefix.
    pub fn page_change_history(
        &self,
        change_id: &ChangeId,
        after: Option<&Head>,
        budget: RecordPageBudget,
    ) -> Result<HistoryPage, CoreError> {
        let prefix = change_id.as_bytes();
        let after_key = match after {
            Some(h) => history_key(change_id, h),
            None => prefix.to_vec(),
        };

        let fact_budget = FactPageBudget::new(budget.rows, budget.bytes);
        let page = self.store.fact_page(
            FactTable::ChangeHistory,
            Some(&after_key),
            fact_budget,
        )?;

        let mut heads = Vec::with_capacity(page.rows.len());
        let mut more = false;

        for row in &page.rows {
            if !row.key.starts_with(prefix) {
                // Departed from this change's contiguous range
                break;
            }
            let (cid, head) = decode_history_key(&row.key)?;
            if cid != *change_id {
                break;
            }
            decode_change_history(self.store, change_id, &head, &row.value)?;
            heads.push(head);
        }

        // If all returned rows matched this change and the store reported more,
        // then this change has more history rows.
        if heads.len() == page.rows.len() && page.more {
            more = true;
        }

        let next_cursor = if more {
            heads.last().copied()
        } else {
            None
        };

        Ok(HistoryPage {
            heads,
            more,
            next_cursor,
        })
    }
}
