//! Admitted work accounting and bounded, resumable row scans.
//!
//! [`Work`] carries the caller's checkpoint and the per-call verification budget.
//! [`RowScan`] reads the attestations table one store page at a time, so no call
//! holds more than one page of rows, and no metadata transaction spans the
//! caller's processing.

use crate::error::{CoreError, ErrorCode};
use crate::store::{FactPageBudget, FactRow, FactTable, Store};

use super::{Checkpoint, Progress};

/// Rows per store page during scans.
const SCAN_PAGE_ROWS: usize = 256;
/// Bytes per store page during scans.
const SCAN_PAGE_BYTES: usize = 1024 * 1024;
/// Stored rows one call may decode and verify before it refuses with `E_LIMIT`.
pub(super) const VERIFY_BUDGET_ROWS: usize = 32_768;

/// The caller's checkpoint and the call's bounded budget.
pub(super) struct Work<'a> {
    gate: &'a Checkpoint<'a>,
    progress: Progress,
    verify_left: usize,
}

impl<'a> Work<'a> {
    pub(super) fn new(gate: &'a Checkpoint<'a>) -> Self {
        Self {
            gate,
            progress: Progress::default(),
            verify_left: VERIFY_BUDGET_ROWS,
        }
    }

    /// A budget for a full-table walk that holds one row at a time. The checkpoint
    /// bounds such a walk, not a row count.
    pub(super) fn streaming(gate: &'a Checkpoint<'a>) -> Self {
        Self {
            gate,
            progress: Progress::default(),
            verify_left: usize::MAX,
        }
    }

    /// Counts one examined unit and lets the checkpoint stop the call.
    pub(super) fn step(&mut self) -> Result<(), CoreError> {
        self.progress.examined = self.progress.examined.saturating_add(1);
        (self.gate)(self.progress)
    }

    /// Counts produced units and lets the checkpoint stop the call.
    pub(super) fn produced(&mut self, units: u64) -> Result<(), CoreError> {
        self.progress.produced = self.progress.produced.saturating_add(units);
        (self.gate)(self.progress)
    }

    /// Charges one stored-row decode against the call's budget.
    pub(super) fn verify(&mut self) -> Result<(), CoreError> {
        if self.verify_left == 0 {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!(
                    "attestation work exceeds {VERIFY_BUDGET_ROWS} verified rows in one call; \
                     narrow the filter or page the result"
                ),
            ));
        }
        self.verify_left -= 1;
        Ok(())
    }
}

/// A resumable scan of the attestations table over one key prefix.
pub(super) struct RowScan<'s> {
    store: &'s Store,
    prefix: Vec<u8>,
    last: Vec<u8>,
    page: std::vec::IntoIter<FactRow>,
    more: bool,
}

impl<'s> RowScan<'s> {
    /// Scans rows under `prefix` strictly after `after`, or from the start of the
    /// prefix when `after` is `None`.
    pub(super) fn new(store: &'s Store, prefix: &[u8], after: Option<&[u8]>) -> Self {
        let last = match after {
            Some(position) => position.to_vec(),
            None => prefix.to_vec(),
        };
        Self {
            store,
            prefix: prefix.to_vec(),
            last,
            page: Vec::new().into_iter(),
            more: true,
        }
    }

    /// The next row under the prefix, or `None` at the end of the prefix.
    pub(super) fn next_row(&mut self) -> Result<Option<FactRow>, CoreError> {
        while self.page.as_slice().is_empty() && self.more {
            self.refill()?;
        }
        let Some(row) = self.page.next() else {
            return Ok(None);
        };
        if !row.key.starts_with(&self.prefix) {
            self.finish();
            return Ok(None);
        }
        self.last.clear();
        self.last.extend_from_slice(&row.key);
        Ok(Some(row))
    }

    fn refill(&mut self) -> Result<(), CoreError> {
        let page = self.store.fact_page(
            FactTable::Attestations,
            Some(&self.last),
            FactPageBudget::new(SCAN_PAGE_ROWS, SCAN_PAGE_BYTES),
        )?;
        self.more = page.more && !page.rows.is_empty();
        self.page = page.rows.into_iter();
        Ok(())
    }

    fn finish(&mut self) {
        self.more = false;
        self.page = Vec::new().into_iter();
    }

    /// The key of the last row yielded, or the start position before any row.
    pub(super) fn position(&self) -> &[u8] {
        &self.last
    }
}
