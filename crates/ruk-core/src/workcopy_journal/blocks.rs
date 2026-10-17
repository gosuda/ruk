//! The journal side of the snapshot-blocking seam
//! ([`crate::workcopy::journal_state`]).
//!
//! [`JournalReader`] decodes and validates the `ws_apply` row instead of
//! only testing its presence, so a damaged row latches quarantine rather
//! than being reported as an ordinary open journal. An open journal is
//! always reported as [`ApplyPhase::Applying`]: whether its paths hold
//! external edits is a physical question answered by
//! [`super::recover::inspect`], not by the row.

use crate::change::WorkspaceId;
use crate::error::CoreError;
use crate::store::Store;
use crate::workcopy::journal_state::{ApplyObservation, ApplyPhase, JournalState, guard_for};

use super::journal::{self, ApplyJournal};

/// The validating [`JournalState`] implementation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct JournalReader;

impl JournalState for JournalReader {
    fn observe(&self, store: &Store, workspace: WorkspaceId) -> Result<ApplyObservation, CoreError> {
        let loaded = journal::load(store, workspace)?;
        let phase = if loaded.is_some() {
            ApplyPhase::Applying
        } else {
            ApplyPhase::Idle
        };
        Ok(ApplyObservation {
            phase,
            guard: guard_for(workspace, loaded.map(|(_, bytes)| bytes)),
        })
    }
}

/// Whether `workspace` has an open journal.
///
/// # Errors
/// Store failures; `E_CORRUPT` for an invalid row.
pub(crate) fn is_applying(store: &Store, workspace: WorkspaceId) -> Result<bool, CoreError> {
    Ok(journal::load(store, workspace)?.is_some())
}

/// The open journal of `workspace`, for status reporting.
///
/// # Errors
/// Store failures; `E_CORRUPT` for an invalid row.
pub(crate) fn current_journal(
    store: &Store,
    workspace: WorkspaceId,
) -> Result<Option<ApplyJournal>, CoreError> {
    Ok(journal::load(store, workspace)?.map(|(journal, _)| journal))
}
