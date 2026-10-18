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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::change::{CheckedOperationId, SessionId};
    use crate::coord::oplog::{self, OpMeta};
    use crate::ids::HashKind;
    use crate::protocol::Timestamp;
    use crate::store::PreparationBudget;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ruk-undo-test-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&root);
            let store = Store::create(
                &root,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create test store");
            Self { root, store }
        }

        /// Records one operation over `changes` and publishes its log entry.
        fn record(&self, method: Method, changes: &[FactMutation]) -> OperationId {
            let mut ops = CheckedOperationId::new(0, u64::MAX);
            let meta = OpMeta {
                session: SessionId::generate(),
                method,
                committed_at: Timestamp::new(jiff::Timestamp::UNIX_EPOCH),
                undoes: None,
            };
            let (id, mutations) = oplog::record(&mut ops, None, meta, changes)
                .expect("record operation")
                .expect("tracked change recorded");
            self.store
                .publish(Vec::new(), &mutations)
                .expect("publish operation");
            id
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn ref_set(key: &[u8], value: &[u8]) -> FactMutation {
        FactMutation {
            table: FactTable::Refs,
            key: key.to_vec(),
            expected: FactExpectation::Absent,
            value: Some(value.to_vec()),
        }
    }

    #[test]
    fn undo_expects_each_after_value_and_writes_the_before_value() {
        let fixture = Fixture::new("inverse");
        let id = fixture.record(Method::BookmarkSet, &[ref_set(b"refs/heads/main", b"new")]);
        let plan = prepare_undo(&fixture.store, id).expect("undo prepares");
        assert_eq!(plan.facts.len(), 1);
        let fact = &plan.facts[0];
        assert_eq!(fact.table, FactTable::Refs);
        assert_eq!(fact.key, b"refs/heads/main".to_vec());
        assert!(
            matches!(&fact.expected, FactExpectation::Value(after) if after == b"new"),
            "expects the operation's after value"
        );
        assert_eq!(fact.value, None, "a created key is removed again");
        assert_eq!(plan.summary.refs, 1);
    }

    #[test]
    fn undo_refuses_operations_with_effects_outside_tracked_tables() {
        let fixture = Fixture::new("fetch");
        let id = fixture.record(Method::Fetch, &[ref_set(b"refs/remotes/origin/main", b"x")]);
        let err = prepare_undo(&fixture.store, id).expect_err("fetch cannot be inverted");
        assert_eq!(err.code, ErrorCode::EUndoConflict);
        assert!(err.message.contains("fetch"), "names the effect: {}", err.message);
    }

    #[test]
    fn undo_of_an_unretained_operation_is_not_found() {
        let fixture = Fixture::new("missing");
        let err = prepare_undo(&fixture.store, OperationId(7)).expect_err("no such operation");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
