//! `undo`: the inverse of a retained operation, as exact facts.
//!
//! Every delta an operation recorded names one tracked key with its value
//! before and after the operation. Undo emits, per delta, a fact that expects
//! the `after` value and writes the `before` value back. The facts are
//! exact-compare-and-swap, so the lane refuses the whole undo with `E_STALE`
//! when any touched key has moved since the operation committed: undo never
//! overwrites a later write it did not observe.
//!
//! Operations whose effects reach outside the tracked tables cannot be
//! inverted from their deltas alone. Those methods are refused with
//! `E_UNSUPPORTED_OPERATION` rather than guessed at.

use crate::change::OperationId;
use crate::coord::oplog::{OpDeltaReader, read_header, tracked};
use crate::coord::rows::{OpDelta, OpHeader, fact_table_from_name};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Method, UndoSummary};
use crate::store::Store;
use crate::store::types::{FactExpectation, FactMutation, FactTable};

/// The inverse of one operation, ready to lane as a mutation.
#[derive(Debug)]
pub(crate) struct UndoPlan {
    /// Exact facts restoring every touched key to its pre-operation value.
    pub(crate) facts: Vec<FactMutation>,
    /// Keys restored, counted by table.
    pub(crate) summary: UndoSummary,
}

/// Builds the inverse of `operation` from its stored deltas.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] when the operation is not retained (never
///   committed, or pruned).
/// - [`ErrorCode::EUndoConflict`] for methods whose effects lie outside the
///   tracked tables, naming the effect.
/// - [`ErrorCode::ECorrupt`] for a delta naming an unknown or untracked table.
/// - Store and stream decoding failures.
pub(crate) fn prepare_undo(store: &Store, operation: OperationId) -> Result<UndoPlan, CoreError> {
    let header = read_header(store, operation)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("operation {} is not retained", operation.0),
        )
    })?;
    refuse_non_invertible(&header)?;
    let mut reader = OpDeltaReader::new(store, operation, header);
    let mut plan = UndoPlan {
        facts: Vec::new(),
        summary: UndoSummary {
            refs: 0,
            changes: 0,
            workspaces: 0,
        },
    };
    while let Some(delta) = reader.next_delta()? {
        plan.facts.push(inverse_fact(&mut plan.summary, delta)?);
    }
    Ok(plan)
}

/// Refuses operations whose effects the tracked deltas cannot restore.
fn refuse_non_invertible(header: &OpHeader) -> Result<(), CoreError> {
    let reason = match header.entry.method {
        Method::Fetch => "fetch writes remote-tracking and shallow state outside the tracked tables",
        Method::Push | Method::PushReconcile => {
            "push sends to a remote and records plans and observations outside the tracked tables"
        }
        Method::LandPrepare | Method::LandExecute => {
            "landing consumes land plans and moves a remote outside the tracked tables"
        }
        _ => return Ok(()),
    };
    Err(CoreError::new(
        ErrorCode::EUndoConflict,
        format!(
            "operation {} cannot be undone: {reason}",
            header.entry.id.0
        ),
    ))
}

/// The exact inverse fact of one delta, counting it into `summary`.
fn inverse_fact(summary: &mut UndoSummary, delta: OpDelta) -> Result<FactMutation, CoreError> {
    let table = fact_table_from_name(&delta.table).ok_or_else(|| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("operation names unknown table `{}`", delta.table),
        )
    })?;
    if !tracked(table) {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!("operation names untracked table `{}`", delta.table),
        ));
    }
    count(summary, table);
    let expected = match delta.after {
        Some(after) => FactExpectation::Value(after),
        None => FactExpectation::Absent,
    };
    Ok(FactMutation {
        table,
        key: delta.key,
        expected,
        value: delta.before,
    })
}

fn count(summary: &mut UndoSummary, table: FactTable) {
    match table {
        FactTable::Refs => summary.refs += 1,
        FactTable::Changes => summary.changes += 1,
        FactTable::Workspaces => summary.workspaces += 1,
        _ => {}
    }
}
