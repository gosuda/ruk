//! Recovery of an interrupted materialization (`ws.recover`, and the scan
//! run after a store opens).
//!
//! Every journaled path is compared with both recorded sides:
//! - equal to the target: complete, skipped;
//! - equal to the preimage (or removed between the two halves of a
//!   directory/non-directory swap): safe to redo;
//! - anything else: an external edit. `Resume` refuses with
//!   `E_WORKSPACE_RECOVERY` naming every such path before writing anything;
//!   `Discard` overwrites exactly the listed ones; `Abort` restores only the
//!   paths still matching target or preimage and leaves external edits in
//!   place, reporting them.
//!
//! Start and finish are fenced by lease epoch: recovery first rebinds the
//! journal to the caller's epoch (which must not be older than the
//! journal's) in one compare-and-swap with the workspace row, so a
//! displaced holder still executing fails its next fenced step, and the
//! completing batch compare-and-swaps the same row again. The journal is
//! cleared only after the complete side it converged to verifies, so a
//! hybrid checkout never stops being Applying and is never snapshotted.

use std::collections::BTreeSet;
use std::path::Path;

use crate::change::WorkspaceId;
use crate::error::{CoreError, ErrorCode};
use crate::index::RepoPath;
use crate::store::{FactPageBudget, FactTable, Store, StoreError};

use super::apply::{
    ApplyOutcome, Executor, FinishBatch, Foreign, PathState, Toward, WorkspaceFence, recovery_error,
};
use super::journal::{self, ApplyStep, MAX_JOURNAL_ROW_BYTES, StepCursor};
use super::safety::WorkRoot;

/// How to resolve an open journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    /// Finish toward the target; refuse if any path was edited externally.
    Resume,
    /// Finish toward the target, overwriting exactly these external edits.
    Discard(BTreeSet<RepoPath>),
    /// Return to the preimage where safe; keep external edits.
    Abort,
}

/// The outcome of a completed recovery. The journal row is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryReport {
    /// Paths that already matched the side recovery converged to.
    pub(crate) already: Vec<RepoPath>,
    /// Paths recovery wrote.
    pub(crate) converged: Vec<RepoPath>,
    /// External edits left in place (abort only).
    pub(crate) unresolved: Vec<RepoPath>,
}

/// Per-path classification, for `ws.status` while Applying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathReport {
    pub(crate) path: RepoPath,
    pub(crate) at_target: bool,
    pub(crate) at_preimage: bool,
    pub(crate) external_edit: bool,
}

/// Workspaces with an open journal. The coordinator calls this after
/// [`Store::open`] and refuses snapshots for each until recovered.
///
/// # Errors
/// Store failures; an undecodable key is `E_CORRUPT`.
pub(crate) fn open_journals(store: &Store) -> Result<Vec<WorkspaceId>, CoreError> {
    let mut after: Option<Vec<u8>> = None;
    let mut open = Vec::new();
    loop {
        let budget = FactPageBudget::new(16, MAX_JOURNAL_ROW_BYTES.saturating_add(16));
        let page = store.fact_page(FactTable::WsApply, after.as_deref(), budget)?;
        for row in &page.rows {
            let Ok(key) = <[u8; 16]>::try_from(row.key.as_slice()) else {
                let corrupt = StoreError::Corrupt("ws_apply key is not 16 bytes".to_owned());
                return store.observe(Err(corrupt)).map_err(CoreError::from);
            };
            open.push(WorkspaceId::from_bytes(key));
        }
        after = page.rows.last().map(|row| row.key.clone());
        if page.rows.is_empty() || !page.more {
            return Ok(open);
        }
    }
}

/// Classifies every journaled path without changing anything. `None` when
/// no journal is open.
///
/// # Errors
/// Store and I/O failures.
pub(crate) fn inspect(
    store: &Store,
    root: &Path,
    workspace: WorkspaceId,
) -> Result<Option<Vec<PathReport>>, CoreError> {
    let Some((journal, row)) = journal::load(store, workspace)? else {
        return Ok(None);
    };
    let workspace_row = store
        .fact(FactTable::Workspaces, workspace.as_bytes())?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "workspace is not registered"))?;
    let stamp = crate::workspace::WorkspaceStamp {
        sequence: 0,
        lease_epoch: journal.lease_epoch,
    };
    let fence = WorkspaceFence::new(workspace, workspace_row, stamp);
    let exec = Executor::new(store, WorkRoot::open(root)?, fence, journal, row);
    let mut reports = Vec::with_capacity(exec.journal.entries.len());
    for (index, entry) in exec.journal.entries.iter().enumerate() {
        let state = exec.classify(index)?;
        reports.push(PathReport {
            path: entry.path.clone(),
            at_target: state == PathState::AtTarget,
            at_preimage: state == PathState::AtPreimage,
            external_edit: state == PathState::Foreign,
        });
    }
    Ok(Some(reports))
}

/// Resolves the open journal of `fence.workspace()`.
///
/// # Errors
/// `E_NOT_FOUND` without an open journal; `E_LEASE_LOST` when the fence is
/// stale or older than the journal's owner; `E_WORKSPACE_RECOVERY` naming
/// external edits (`Resume`, or `Discard` paths not listed); `E_INVALID`
/// when abort is given a successor workspace row; `E_IO`.
pub(crate) fn recover(
    store: &Store,
    root: &Path,
    fence: WorkspaceFence,
    action: RecoveryAction,
    finish: FinishBatch,
) -> Result<RecoveryReport, CoreError> {
    let workspace = fence.workspace();
    if action == RecoveryAction::Abort && finish.next_row.is_some() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "abort keeps the workspace at its preimage; it takes no successor row",
        ));
    }
    let (journal, row) = journal::load(store, workspace)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            "workspace has no open materialization journal",
        )
    })?;
    fence.check(store, ErrorCode::ELeaseLost)?;
    if fence.lease_epoch() < journal.lease_epoch {
        return Err(CoreError::new(
            ErrorCode::ELeaseLost,
            "journal belongs to a newer lease epoch",
        ));
    }
    let mut rebound = journal.clone();
    rebound.lease_epoch = fence.lease_epoch();
    rebound.cursor = StepCursor {
        pass: journal.cursor.pass.checked_add(1).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "journal recovery pass exhausted")
        })?,
        step: ApplyStep::Journaled,
        done: 0,
    };
    let mut exec = Executor::new(store, WorkRoot::open(root)?, fence, journal, row);
    exec.republish(rebound)?;
    for index in 0..exec.journal.entries.len() {
        exec.clean_temp(index)?;
    }
    let mut states = Vec::with_capacity(exec.journal.entries.len());
    for index in 0..exec.journal.entries.len() {
        states.push(exec.classify(index)?);
    }

    let (toward, discard, foreign) = match action {
        RecoveryAction::Resume => (Toward::Target, BTreeSet::new(), Foreign::Fail),
        RecoveryAction::Discard(paths) => (Toward::Target, paths, Foreign::Fail),
        RecoveryAction::Abort => (Toward::Preimage, BTreeSet::new(), Foreign::Skip),
    };
    if toward == Toward::Target {
        let refused: Vec<RepoPath> = exec
            .journal
            .entries
            .iter()
            .zip(&states)
            .filter(|(entry, state)| {
                **state == PathState::Foreign && !discard.contains(&entry.path)
            })
            .map(|(entry, _)| entry.path.clone())
            .collect();
        if !refused.is_empty() {
            return Err(recovery_error(&refused));
        }
    }
    let settled = match toward {
        Toward::Target => PathState::AtTarget,
        Toward::Preimage => PathState::AtPreimage,
    };
    let already: BTreeSet<RepoPath> = exec
        .journal
        .entries
        .iter()
        .zip(&states)
        .filter(|(_, state)| **state == settled)
        .map(|(entry, _)| entry.path.clone())
        .collect();

    let unresolved = exec.converge(toward, &discard, foreign)?;
    exec.verify(toward, &unresolved)?;
    let unresolved_paths: Vec<RepoPath> = unresolved
        .iter()
        .filter_map(|index| {
            exec.journal
                .entries
                .get(*index)
                .map(|entry| entry.path.clone())
        })
        .collect();
    let ApplyOutcome {
        changed,
        unresolved,
    } = exec.complete(finish, unresolved_paths)?;
    let left: BTreeSet<&RepoPath> = unresolved.iter().collect();
    let converged = changed
        .into_iter()
        .filter(|path| !already.contains(path) && !left.contains(path))
        .collect();
    Ok(RecoveryReport {
        already: already.into_iter().collect(),
        converged,
        unresolved,
    })
}
