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
//!
//! The boundary has three layers: the method allowlist below refuses effects
//! outside every tracked table (remotes, and materialized workcopy checkouts);
//! [`refuse_restoring_workspaces`] refuses the tracked-but-fencing-monotonic
//! workspace rows a rewrite may advance; and [`refuse_diverged`] refuses keys
//! that moved since the operation, with the lane re-checking the same
//! expectations at publication.

use std::collections::BTreeMap;

use crate::change::OperationId;
use crate::coord::oplog::{OpDeltaReader, journaled, read_header, undoable};
use crate::coord::rows::{OpHeader, fact_table_from_name};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Method, Request, UndoSummary};
use crate::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};

use crate::refs::StoreRefs;
use crate::store::Store;
use crate::store::types::{FactExpectation, FactMutation, FactTable};

/// Net undo change per key: the value before the first delta and after the last.
type NetChanges = BTreeMap<(String, Vec<u8>), (Option<Vec<u8>>, Option<Vec<u8>>)>;

/// The inverse of one operation, ready to lane as a mutation.
#[derive(Debug)]
pub(crate) struct UndoPlan {
    /// Exact facts restoring every touched key to its pre-operation value.
    pub(crate) facts: Vec<FactMutation>,
    /// Keys restored, counted by table.
    pub(crate) summary: UndoSummary,
    /// The checked ref transaction when the inverse moves refs, re-checked by
    /// the lane at publication like every live ref mutation.
    pub(crate) ref_transaction: Option<RefTransaction>,
    /// Ref names the transaction was validated against.
    pub(crate) ref_dependencies: Vec<RefName>,
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
/// Deltas, expectations, and the ref transaction all derive from the
/// committed operation stream; current keys are re-checked before
/// anything inverts, so a moved key refuses instead of restoring stale
/// bytes.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] when the operation is not retained (never
///   committed, or pruned).
/// - [`ErrorCode::EUndoConflict`] for methods whose effects lie outside the
///   undoable tables, for a journaled-but-not-undoable delta, and for a key
///   that no longer holds the value the operation left.
/// - [`ErrorCode::ECorrupt`] for a delta naming an unknown or unjournaled table.
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
    let mut net: NetChanges = BTreeMap::new();
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
        ref_transaction: None,
        ref_dependencies: Vec::new(),
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
    refuse_restoring_workspaces(operation, &plan.facts)?;
    refuse_diverged(store, operation, &plan.facts)?;
    let (transaction, dependencies) = undo_ref_transaction(store, &plan.facts)?;
    plan.ref_transaction = transaction;
    plan.ref_dependencies = dependencies;
    Ok(plan)
}

/// Lowers the inverse's Refs facts to a checked [`RefTransaction`] with its
/// dependency names: the same namespace checks (directory/file collisions,
/// symbolic-ref cycles and depth, judged against current state) live ref
/// mutations run. The lane re-checks the transaction at publication, so a ref
/// created beside the restored name after prepare still refuses. Returns
/// `(None, [])` when the inverse moves no ref.
///
/// # Errors
/// - [`ErrorCode::ECorrupt`] for a ref key or target that fails to decode.
/// - The [`RefTransaction`] check failures, as for live ref mutations.
fn undo_ref_transaction(
    store: &Store,
    facts: &[FactMutation],
) -> Result<(Option<RefTransaction>, Vec<RefName>), CoreError> {
    let mut updates = Vec::new();
    for fact in facts {
        if fact.table != FactTable::Refs {
            continue;
        }
        let name = RefName::new(fact.key.as_slice()).map_err(|err| {
            CoreError::new(
                ErrorCode::ECorrupt,
                format!("undone operation names an invalid ref key: {err}"),
            )
        })?;
        let expected = match &fact.expected {
            FactExpectation::Value(after) => RefExpect::Present(decode_ref_target(after)?),
            FactExpectation::Absent => RefExpect::Absent,
            FactExpectation::Any => RefExpect::Any,
        };
        let change = match &fact.value {
            Some(before) => RefChange::Set(decode_ref_target(before)?),
            None => RefChange::Delete,
        };
        updates.push(RefUpdate {
            name,
            expected,
            change,
        });
    }
    if updates.is_empty() {
        return Ok((None, Vec::new()));
    }
    let dependencies = updates.iter().map(|update| update.name.clone()).collect();
    let transaction = RefTransaction::new(store.hash_kind(), updates).map_err(CoreError::from)?;
    transaction
        .check(&StoreRefs::new(store))
        .map_err(CoreError::from)?;
    Ok((Some(transaction), dependencies))
}

/// Decodes one stored ref target from an operation delta.
///
/// # Errors
/// [`ErrorCode::ECorrupt`] for bytes that are not an encoded [`RefTarget`].
fn decode_ref_target(bytes: &[u8]) -> Result<RefTarget, CoreError> {
    crate::store::decode("ref target", bytes).map_err(CoreError::from)
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
        Method::PolicySet => "policy.set rewrites the landing policy outside the tracked tables",
        Method::RepoInit | Method::RepoDelete | Method::RepoRename | Method::RepoFork => {
            "repository lifecycle moves stores on disk outside the tracked tables"
        }
        Method::Edit
        | Method::New
        | Method::WsNew
        | Method::WsScope
        | Method::WsTake
        | Method::WsDrop => {
            "a workspace checkout is materialized on disk outside the tracked tables and undo cannot restore it"
        }
        Method::SessionOpen
        | Method::SessionResume
        | Method::Schema
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
        | Method::Query
        | Method::GitCommit
        | Method::ClaimRenew
        | Method::RepoStat
        | Method::Tree
        | Method::RefsList
        | Method::Compare
        | Method::Search
        | Method::Archive
        | Method::EventsTail
        | Method::RemoteRefs => return Ok(()),
    };
    Err(CoreError::new(
        ErrorCode::EUndoConflict,
        format!("operation {} cannot be undone: {reason}", header.entry.id.0),
    ))
}

/// Resolves a stored table name to an undoable table, refusing anything else.
///
/// Journaled-but-not-undoable tables (`Claims`, `Attestations`, `PushPlans`,
/// `LandPlans`) refuse with `E_UNDO_CONFLICT`: their rows name real operation
/// state, so failing to invert them is a policy refusal, never corruption.
/// Anything outside the journaled set is committed damage.
fn inverse_table(name: &str) -> Result<FactTable, CoreError> {
    let table = fact_table_from_name(name).ok_or_else(|| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("operation names unknown table `{name}`"),
        )
    })?;
    if undoable(table) {
        return Ok(table);
    }
    if journaled(table) {
        return Err(CoreError::new(
            ErrorCode::EUndoConflict,
            format!("operation names journaled table `{name}` that undo cannot invert"),
        ));
    }
    Err(CoreError::new(
        ErrorCode::ECorrupt,
        format!("operation names unjournaled table `{name}`"),
    ))
}

/// Refuses the undo when it would restore a workspace row.
///
/// Workspace stamps and lease epochs never move backward: fencing tokens are
/// issued against the current stamp, so writing the pre-operation bytes would
/// reissue an old stamp for different state (ABA) or hand the workspace to a
/// displaced holder at a lower lease epoch, reviving its fencing tokens.
/// Every other table restores exact bytes safely.
fn refuse_restoring_workspaces(
    operation: OperationId,
    facts: &[FactMutation],
) -> Result<(), CoreError> {
    if facts.iter().any(|fact| fact.table == FactTable::Workspaces) {
        return Err(CoreError::new(
            ErrorCode::EUndoConflict,
            format!(
                "operation {} cannot be undone: it moves a workspace, and restoring the row would move its stamp or lease epoch backward",
                operation.0
            ),
        ));
    }
    Ok(())
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
    use crate::ids::{HashKind, Oid};
    use crate::protocol::Timestamp;
    use crate::refdata::RefTarget;
    use crate::store::{EventContext, EventSource, PreparationBudget};

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
                on_behalf_of: None,
            };
            let (id, mutations) = oplog::record(&mut ops, None, meta, changes)
                .expect("record operation")
                .expect("tracked change recorded");
            let mut facts = changes.to_vec();
            facts.extend(mutations);
            self.store
                .publish(
                    Vec::new(),
                    &facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
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

    fn ref_target(n: u8) -> Vec<u8> {
        let oid = Oid::from_hex(&format!("{n:040x}")).expect("test oid");
        crate::store::encode("ref target", &RefTarget::Direct(oid)).expect("encode test target")
    }

    #[test]
    fn undo_expects_each_after_value_and_writes_the_before_value() {
        let fixture = Fixture::new("inverse");
        let created = ref_target(1);
        let id = fixture.record(
            Method::BookmarkSet,
            &[ref_set(b"refs/heads/main", &created)],
        );
        let plan = prepare_undo(&fixture.store, id).expect("undo prepares");
        assert_eq!(plan.facts.len(), 1);
        let fact = &plan.facts[0];
        assert_eq!(fact.table, FactTable::Refs);
        assert_eq!(fact.key, b"refs/heads/main".to_vec());
        assert!(
            matches!(&fact.expected, FactExpectation::Value(after) if after == &created),
            "expects the operation's after value"
        );
        assert_eq!(fact.value, None, "a created key is removed again");
        assert_eq!(plan.summary.refs, 1);
        let transaction = plan
            .ref_transaction
            .as_ref()
            .expect("undo carries a ref transaction");
        assert_eq!(transaction.updates().len(), 1);
        assert_eq!(
            plan.ref_dependencies,
            vec![RefName::new(b"refs/heads/main").expect("test name")],
            "the lane re-checks the restored name at publication"
        );
    }

    #[test]
    fn undo_refuses_a_restored_ref_beside_a_live_child() {
        let fixture = Fixture::new("ref-clash");
        let deleted = ref_target(1);
        fixture
            .store
            .publish(
                Vec::new(),
                &[ref_set(b"refs/heads/a", &deleted)],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("seed the ref the operation deletes");
        let id = fixture.record(
            Method::BookmarkDelete,
            &[FactMutation {
                table: FactTable::Refs,
                key: b"refs/heads/a".to_vec(),
                expected: FactExpectation::Value(deleted.clone()),
                value: None,
            }],
        );
        fixture
            .store
            .publish(
                Vec::new(),
                &[ref_set(b"refs/heads/a/b", &ref_target(2))],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("a sibling ref lands");
        let err = prepare_undo(&fixture.store, id).expect_err("directory/file clash refuses");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(
            err.message.contains("refs/heads/a"),
            "names the clashing ref: {}",
            err.message
        );
    }

    #[test]
    fn undo_refuses_operations_with_effects_outside_tracked_tables() {
        let fixture = Fixture::new("fetch");
        let id = fixture.record(
            Method::Fetch,
            &[ref_set(b"refs/remotes/origin/main", &ref_target(4))],
        );
        let err = prepare_undo(&fixture.store, id).expect_err("fetch cannot be inverted");
        assert_eq!(err.code, ErrorCode::EUndoConflict);
        assert!(
            err.message.contains("fetch"),
            "names the effect: {}",
            err.message
        );
    }

    #[test]
    fn undo_refuses_a_key_that_moved_since_the_operation() {
        let fixture = Fixture::new("diverged");
        let created = ref_target(5);
        let id = fixture.record(
            Method::BookmarkSet,
            &[ref_set(b"refs/heads/main", &created)],
        );
        let moved = FactMutation {
            table: FactTable::Refs,
            key: b"refs/heads/main".to_vec(),
            expected: FactExpectation::Value(created),
            value: Some(ref_target(6)),
        };
        fixture
            .store
            .publish(
                Vec::new(),
                &[moved],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("a later write lands");
        let err = prepare_undo(&fixture.store, id).expect_err("the key has moved");
        assert_eq!(err.code, ErrorCode::EUndoConflict);
    }

    #[test]
    fn undo_refuses_to_restore_a_workspace_row() {
        let fixture = Fixture::new("workspace");
        let id = fixture.record(
            Method::Describe,
            &[FactMutation {
                table: FactTable::Workspaces,
                key: vec![7; 16],
                expected: FactExpectation::Absent,
                value: Some(b"row".to_vec()),
            }],
        );
        let err = prepare_undo(&fixture.store, id).expect_err("workspace rows never restore");
        assert_eq!(err.code, ErrorCode::EUndoConflict);
        assert!(
            err.message.contains("workspace"),
            "names the hazard: {}",
            err.message
        );
    }

    #[test]
    fn undo_refuses_every_workspace_moving_method() {
        // The allowlist boundary: any method that moves a materialized
        // checkout is refused up front, not merely at its workspace delta.
        for method in [
            Method::Edit,
            Method::New,
            Method::WsNew,
            Method::WsScope,
            Method::WsTake,
            Method::WsDrop,
        ] {
            let fixture = Fixture::new("ws-methods");
            let id = fixture.record(method, &[ref_set(b"refs/heads/main", &ref_target(9))]);
            let err = prepare_undo(&fixture.store, id).expect_err("workspace movers stay refused");
            assert_eq!(err.code, ErrorCode::EUndoConflict);
            assert!(
                err.message.contains("materialized"),
                "{method:?} names the checkout hazard: {}",
                err.message
            );
        }
    }

    #[test]
    fn undo_of_an_unretained_operation_is_not_found() {
        let fixture = Fixture::new("missing");
        let err = prepare_undo(&fixture.store, OperationId(7)).expect_err("no such operation");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }
}
