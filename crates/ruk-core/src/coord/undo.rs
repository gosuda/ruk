//! `undo`: the inverse of a retained operation, as exact facts.
//!
//! An operation's deltas name each tracked key it changed, with the value
//! before and after. Undo emits, per key, a fact that expects the value the
//! operation left (`after`) and writes the value it found (`before`). A key
//! that has since moved is refused up front with `E_UNDO_CONFLICT`; the lane
//! re-checks the same expectations at publication, so a concurrent commit
//! surfaces as `E_STALE`. Undo never overwrites a later write it did not
//! observe.
//!
//! Operations whose effects reach outside the tracked tables cannot be inverted
//! from their deltas alone. Those methods are refused with `E_UNDO_CONFLICT`
//! rather than guessed at. Every [`Method`] is named in [`refuse_non_invertible`],
//! so a new method must be classified before it can be undone.

use std::collections::BTreeMap;

use crate::change::OperationId;
use crate::coord::oplog::{OpDeltaReader, read_header, tracked};
use crate::coord::rows::{OpHeader, fact_table_from_name};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Method, Request, UndoSummary};
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

/// The operation an `undo` request inverts; every other request inverts none.
pub(crate) fn undone_operation(request: &Request) -> Option<OperationId> {
    match request {
        Request::Undo(undo) => Some(undo.args.operation),
        _ => None,
    }
}

/// Builds the inverse of `operation` from its stored deltas.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] when the operation is not retained (never
///   committed, or pruned).
/// - [`ErrorCode::EUndoConflict`] for methods whose effects lie outside the
///   tracked tables, and for a key that no longer holds the value the operation
///   left.
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
    // Keyed by table name and key, each entry keeps the value before the first
    // delta and the value after the last: the net change to that key.
    let mut net: BTreeMap<(String, Vec<u8>), (Option<Vec<u8>>, Option<Vec<u8>>)> =
        BTreeMap::new();
    while let Some(delta) = reader.next_delta()? {
        let slot = net
            .entry((delta.table, delta.key))
            .or_insert((delta.before, None));
        slot.1 = delta.after;
    }
    let mut plan = UndoPlan {
        facts: Vec::new(),
        summary: UndoSummary {
            refs: 0,
            changes: 0,
            workspaces: 0,
        },
    };
    for ((table_name, key), (before, after)) in net {
        if before == after {
            continue;
        }
        let table = inverse_table(&table_name)?;
        count(&mut plan.summary, table);
        let expected = match after {
            Some(after) => FactExpectation::Value(after),
            None => FactExpectation::Absent,
        };
        plan.facts.push(FactMutation {
            table,
            key,
            expected,
            value: before,
        });
    }
    refuse_diverged(store, operation, &plan.facts)?;
    Ok(plan)
}

/// Classifies every method. Methods whose effects reach outside the tracked
/// tables are refused; the rest change only tracked state (or none).
fn refuse_non_invertible(header: &OpHeader) -> Result<(), CoreError> {
    let reason = match header.entry.method {
        Method::Fetch => {
            "fetch writes remote-tracking and shallow state outside the tracked tables"
        }
        Method::Push | Method::PushReconcile => {
            "push sends to a remote and records plans and observations outside the tracked tables"
        }
        Method::LandPrepare | Method::LandExecute => {
            "landing consumes land plans and moves a remote outside the tracked tables"
        }
        Method::Edit | Method::New => {
            "a workspace checkout is materialized on disk outside the tracked tables and undo cannot restore it"
        }
        Method::SessionOpen
        | Method::SessionResume
        | Method::Schema
        | Method::WsNew
        | Method::WsScope
        | Method::WsTake
        | Method::WsDrop
        | Method::WsRecover
        | Method::Snapshot
        | Method::Write
        | Method::Describe
        | Method::Rebase
        | Method::Squash
        | Method::Split
        | Method::Abandon
        | Method::Resolve
        | Method::Revert
        | Method::BookmarkSet
        | Method::BookmarkDelete
        | Method::BookmarkResolve
        | Method::TagSet
        | Method::TagDelete
        | Method::ClaimAcquire
        | Method::ClaimRelease
        | Method::ClaimList
        | Method::AttestAdd
        | Method::AttestList
        | Method::OpLog
        | Method::OpPrune
        | Method::Pin
        | Method::Unpin
        | Method::Undo
        | Method::Status
        | Method::Log
        | Method::Diff
        | Method::Show
        | Method::File
        | Method::Blame
        | Method::Query => return Ok(()),
    };
    Err(CoreError::new(
        ErrorCode::EUndoConflict,
        format!(
            "operation {} cannot be undone: {reason}",
            header.entry.id.0
        ),
    ))
}

/// Resolves a stored table name to a tracked table, refusing anything else.
fn inverse_table(name: &str) -> Result<FactTable, CoreError> {
    let table = fact_table_from_name(name).ok_or_else(|| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("operation names unknown table `{name}`"),
        )
    })?;
    if !tracked(table) {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!("operation names untracked table `{name}`"),
        ));
    }
    Ok(table)
}

/// Refuses the undo when any key no longer holds the value the operation left.
fn refuse_diverged(
    store: &Store,
    operation: OperationId,
    facts: &[FactMutation],
) -> Result<(), CoreError> {
    for fact in facts {
        let current = store.fact(fact.table, &fact.key)?;
        let holds = match &fact.expected {
            FactExpectation::Value(after) => current.as_deref() == Some(after.as_slice()),
            FactExpectation::Absent => current.is_none(),
            FactExpectation::Any => true,
        };
        if !holds {
            return Err(CoreError::new(
                ErrorCode::EUndoConflict,
                format!(
                    "operation {} cannot be undone: a key in table {} has moved since the operation",
                    operation.0,
                    fact.table.table_name()
                ),
            ));
        }
    }
    Ok(())
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

        /// Publishes the state `changes` make and the operation log entry that
        /// records them, as the lane would.
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
            let mut facts = changes.to_vec();
            facts.extend(mutations);
            self.store
                .publish(Vec::new(), &facts)
                .expect("publish operation and its state");
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
    fn undo_refuses_a_key_that_moved_since_the_operation() {
        let fixture = Fixture::new("diverged");
        let id = fixture.record(Method::BookmarkSet, &[ref_set(b"refs/heads/main", b"new")]);
        let moved = FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/main".to_vec(),
            expected: FactExpectation::Value(b"new".to_vec()),
            value: Some(b"later".to_vec()),
        };
        fixture
            .store
            .publish(Vec::new(), &[moved])
            .expect("a later write lands");
        let err = prepare_undo(&fixture.store, id).expect_err("the key has moved");
        assert_eq!(err.code, ErrorCode::EUndoConflict);
    }

    #[test]
    fn undo_of_an_unretained_operation_is_not_found() {
        let fixture = Fixture::new("missing");
        let err = prepare_undo(&fixture.store, OperationId(7)).expect_err("no such operation");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
