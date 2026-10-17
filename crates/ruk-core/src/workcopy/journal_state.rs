//! The seam between snapshot/write and the materialization journal.
//!
//! While a workspace's journal is open, snapshots and every workspace
//! mutation are refused: the directory may hold a hybrid of preimage and
//! target, and snapshotting it would record a state no operation produced.
//!
//! Row convention, shared with the journal owner: the `ws_apply` row of a
//! workspace (key: the 16 raw workspace id bytes) exists exactly while a
//! journal is open. Beginning an apply inserts it with
//! [`FactExpectation::Absent`]; finishing or aborting removes it.
//!
//! Checking the phase once is not enough, because an apply may begin after
//! the check. [`ApplyObservation::guard`] is a no-op mutation pinning what
//! was observed; snapshot and write publish it in their own transaction, so
//! a journal opened in between makes that publication fail `E_STALE`.
//!
//! [`NoJournal`] reads the row directly and treats any row as an open
//! journal. The journal owner replaces it by implementing [`JournalState`]
//! for its reader, which decodes and validates the row.

use std::fmt;

use crate::store::{FactExpectation, FactMutation, FactTable, Store};
use crate::{CoreError, ErrorCode, WorkspaceId};

/// The `ws_apply` key of a workspace.
#[must_use]
pub(crate) fn ws_apply_key(workspace: WorkspaceId) -> Vec<u8> {
    workspace.as_bytes().to_vec()
}

/// A workspace's materialization phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplyPhase {
    /// No journal is open; the worktree may be snapshotted.
    Idle,
    /// A journal is open and its writes may be in progress.
    Applying,
    /// A journal is open and recovery found paths matching neither
    /// preimage nor target.
    Recovery,
}

/// One observation of the phase and the guard that pins it.
#[derive(Clone, Debug)]
pub(crate) struct ApplyObservation {
    pub(crate) phase: ApplyPhase,
    /// A mutation of the `ws_apply` row that changes nothing and fails
    /// unless the row still holds what was observed.
    pub(crate) guard: FactMutation,
}

/// Reads a workspace's materialization phase.
pub(crate) trait JournalState: Send + Sync + fmt::Debug {
    /// # Errors
    /// Store failures; `E_CORRUPT` for an undecodable journal row.
    fn observe(&self, store: &Store, workspace: WorkspaceId) -> Result<ApplyObservation, CoreError>;
}

/// The guard for an observed row: absent stays absent, present bytes are
/// rewritten unchanged under a value expectation.
#[must_use]
pub(crate) fn guard_for(workspace: WorkspaceId, observed: Option<Vec<u8>>) -> FactMutation {
    let key = ws_apply_key(workspace);
    match observed {
        None => FactMutation {
            table: FactTable::WsApply,
            key,
            expected: FactExpectation::Absent,
            value: None,
        },
        Some(bytes) => FactMutation {
            table: FactTable::WsApply,
            key,
            expected: FactExpectation::Value(bytes.clone()),
            value: Some(bytes),
        },
    }
}

/// Reads the `ws_apply` row without decoding it: absent is idle, any row is
/// an open journal reported as applying.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoJournal;

impl JournalState for NoJournal {
    fn observe(&self, store: &Store, workspace: WorkspaceId) -> Result<ApplyObservation, CoreError> {
        let row = store.fact(FactTable::WsApply, &ws_apply_key(workspace))?;
        let phase = if row.is_some() {
            ApplyPhase::Applying
        } else {
            ApplyPhase::Idle
        };
        Ok(ApplyObservation {
            phase,
            guard: guard_for(workspace, row),
        })
    }
}

/// Refuses unless the workspace is idle, returning the guard to publish.
///
/// # Errors
/// `E_WORKSPACE_APPLYING` while a journal applies, `E_WORKSPACE_RECOVERY`
/// while it awaits recovery, and store failures.
pub(crate) fn ensure_idle(
    journal: &dyn JournalState,
    store: &Store,
    workspace: WorkspaceId,
) -> Result<FactMutation, CoreError> {
    let observation = journal.observe(store, workspace)?;
    match observation.phase {
        ApplyPhase::Idle => Ok(observation.guard),
        ApplyPhase::Applying => Err(CoreError::new(
            ErrorCode::EWorkspaceApplying,
            "a materialization is in progress in this workspace",
        )
        .with_hint("wait for it to finish or run `ws.recover`")),
        ApplyPhase::Recovery => Err(CoreError::new(
            ErrorCode::EWorkspaceRecovery,
            "an interrupted materialization needs recovery in this workspace",
        )
        .with_hint("run `ws.recover abort` or `ws.recover discard`")),
    }
}
