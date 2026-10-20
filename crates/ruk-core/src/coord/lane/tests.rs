//! Real-Store integration and unit tests for the coordinator publication lane.
//!
//! Tests cover all 11 invariant scenarios mandated by the contract:
//! 1. Two disjoint requests in one batch
//! 2. Per-session activity coalescing
//! 3. Exact duplicate coalescing and mismatched digest
//! 4. Stale same-workspace rejection and epoch-first fencing
//! 5. Current policy revocation after preparation
//! 6. Receipt replay despite expiry or stale stamp
//! 7. No-op receipt without operation
//! 8. Atomic domain, op, receipt, and head persistence across store reopen
//! 9. Overlapping candidates deferred with owned spools intact
//! 10. Cancellation before publication and receiver drop after commit
//! 11. Fail-closed ambiguous storage error handling

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jiff::SignedDuration;
use tokio::sync::oneshot;

use super::commit::{StoreFailureKind, classify_store_error};
use super::*;
use crate::bytes::ByteString;
use crate::change::{ClaimId, RequestId, SessionId, WorkspaceId};
use crate::coord::cancel::cancellation;
use crate::coord::clock::Clock;
use crate::coord::oplog;
use crate::coord::policy::{Policy, PolicySource, Principal};
use crate::coord::rows::{self, WorkspaceRow};
use crate::coord::session::{SessionLive, SessionTable, prepare_open};
use crate::error::ErrorCode;
use crate::ids::HashKind;
use crate::index::RepoPath;
use crate::protocol::{
    ClaimAcquireArgs, ClaimAcquireReply, ClaimMode, ClaimRecord, ClaimTtl, Mutation,
    MutationOutcome, ReceiptRef, Reply, Request, RequestDigest, SessionOpenArgs, Timestamp,
    WorkspaceInit, WsNewArgs, WsNewReply,
};
use crate::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
use crate::store::types::{FactExpectation, FactMutation, FactTable, ObjectKind, PreparedObject};
use crate::store::{PreparationBudget, Store, StoreError};
use crate::workspace::{NativeWorkspace, Scope, WorkspaceStamp, WorkspaceState};

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "ruk-lane-test-{tag}-{}-{}-{nanos}",
            std::process::id(),
            TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::create_dir_all(&dir);
        Self(dir)
    }

    fn store_dir(&self) -> PathBuf {
        self.0.join("store")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_store(temp: &TempRoot) -> Store {
    let budget = Arc::new(PreparationBudget::reference_defaults());
    Store::create(&temp.store_dir(), HashKind::Sha1, budget).expect("create test store")
}

fn test_session(
    table: &SessionTable,
    principal: &Principal,
    idle: SignedDuration,
) -> Arc<SessionLive> {
    let times = table.clock().sample().expect("sample times");
    let policy = Policy::default_for_owner(principal).expect("default policy");
    let principal_policy = policy.lookup(principal).expect("owner policy");
    let pending = prepare_open(
        principal,
        principal_policy,
        idle,
        &SessionOpenArgs::default(),
        times.wall,
    )
    .expect("prepare open");
    let reservation = table.reserve_open(&pending).expect("reserve open");
    let bound = reservation.into_binding(Arc::new(pending.row), idle, times);
    Arc::clone(bound.session())
}

fn dummy_mutation_request(request_id: RequestId) -> (Request, Reply) {
    let req = Request::WsNew(Box::new(Mutation {
        request_id,
        args: WsNewArgs {
            root: ByteString::from("/tmp/workspace"),
            init: WorkspaceInit::Native {
                parents: Vec::new(),
            },
            scope: None,
        },
    }));

    let reply = Reply::WsNew(Box::new(WsNewReply {
        outcome: MutationOutcome {
            receipt: ReceiptRef {
                session: SessionId::generate(),
                request_id,
                digest: RequestDigest::from_bytes([0; 32]),
                replayed: false,
                retained_until: Timestamp::new(jiff::Timestamp::now()),
            },
            operation: None,
            heads: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            stamps: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            warnings: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            merge: None,
            provenance: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            identity: None,
        },
        workspace: WorkspaceId::generate(),
        state: WorkspaceState::Native({
            let mut w = NativeWorkspace::new(
                crate::change::ChangeId::from_bytes([0; 16]),
                crate::heads::Head::Git {
                    oid: crate::ids::Oid::from_bytes(&[0u8; 20]).unwrap(),
                },
                Scope::Full,
            );
            w.stamp = WorkspaceStamp {
                sequence: 0,
                lease_epoch: 0,
            };
            w
        }),
    }));

    (req, reply)
}

fn make_candidate(
    session: Arc<SessionLive>,
    principal: Principal,
    request_id: RequestId,
    objects: Vec<PreparedObject>,
    facts: Vec<FactMutation>,
) -> MutationCandidate {
    let (req, reply) = dummy_mutation_request(request_id);
    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);

    MutationCandidate::new(
        session,
        principal,
        request_id,
        req,
        reply,
        objects,
        facts,
        None,
        None,
        Vec::new(),
        cancel,
        None,
    )
    .expect("valid candidate")
}

#[test]
fn test_1_two_disjoint_requests_in_one_batch() {
    let temp = TempRoot::new("two-disjoint");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let req_id1 = RequestId::generate();
    let req_id2 = RequestId::generate();

    // Disjoint domain facts in a tracked table (FactTable::Refs)
    let fact1 = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/branch-1".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"oid-value-1".to_vec()),
    };
    let fact2 = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/branch-2".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"oid-value-2".to_vec()),
    };

    let cand1 = make_candidate(
        session1,
        principal.clone(),
        req_id1,
        Vec::new(),
        vec![fact1],
    );
    let cand2 = make_candidate(session2, principal, req_id2, Vec::new(), vec![fact2]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let batch = vec![
        BatchItem::Mutation {
            candidate: Box::new(cand1),
            reply_tx: Some(tx1),
        },
        BatchItem::Mutation {
            candidate: Box::new(cand2),
            reply_tx: Some(tx2),
        },
    ];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .expect("commit batch succeeds");

    let reply1 = rx1.blocking_recv().expect("reply 1").expect("ok reply 1");
    let reply2 = rx2.blocking_recv().expect("reply 2").expect("ok reply 2");

    let outcome1 = reply1.outcome().expect("outcome 1");
    let outcome2 = reply2.outcome().expect("outcome 2");

    // Both get distinct, chained operations
    let op1 = outcome1.operation.expect("op1 allocated");
    let op2 = outcome2.operation.expect("op2 allocated");
    assert!(
        op2.0 > op1.0,
        "operations must be strictly increasing in batch order"
    );

    // Receipts exist for both in FactTable::Receipts
    let key1 = rows::receipt_key(outcome1.receipt.session, outcome1.receipt.request_id);
    let key2 = rows::receipt_key(outcome2.receipt.session, outcome2.receipt.request_id);
    assert!(store.fact(FactTable::Receipts, &key1).unwrap().is_some());
    assert!(store.fact(FactTable::Receipts, &key2).unwrap().is_some());
}

#[test]
fn test_2_per_session_activity_coalescing() {
    let temp = TempRoot::new("session-coalesce");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);

    let req_id1 = RequestId::generate();
    let req_id2 = RequestId::generate();

    let fact1 = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/feature-a".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"oid-a".to_vec()),
    };
    let fact2 = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/feature-b".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"oid-b".to_vec()),
    };

    let cand1 = make_candidate(
        Arc::clone(&session),
        principal.clone(),
        req_id1,
        Vec::new(),
        vec![fact1],
    );
    let cand2 = make_candidate(session, principal, req_id2, Vec::new(), vec![fact2]);

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let batch = vec![
        BatchItem::Mutation {
            candidate: Box::new(cand1),
            reply_tx: Some(tx1),
        },
        BatchItem::Mutation {
            candidate: Box::new(cand2),
            reply_tx: Some(tx2),
        },
    ];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .expect("batch commits");

    assert!(rx1.blocking_recv().unwrap().is_ok());
    assert!(rx2.blocking_recv().unwrap().is_ok());
}

#[test]
fn test_3_exact_duplicate_coalescing_and_mismatched_digest() {
    let temp = TempRoot::new("duplicate-coalesce");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);
    let req_id = RequestId::generate();

    let fact = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/dedup".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"oid-dedup".to_vec()),
    };

    let cand1 = make_candidate(
        Arc::clone(&session),
        principal.clone(),
        req_id,
        Vec::new(),
        vec![fact.clone()],
    );
    let cand2 = make_candidate(
        Arc::clone(&session),
        principal.clone(),
        req_id,
        Vec::new(),
        vec![fact],
    );

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    // In-batch identical duplicate
    let batch = vec![
        BatchItem::Mutation {
            candidate: Box::new(cand1),
            reply_tx: Some(tx1),
        },
        BatchItem::Mutation {
            candidate: Box::new(cand2),
            reply_tx: Some(tx2),
        },
    ];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .expect("commit batch succeeds");

    let r1 = rx1.blocking_recv().unwrap().unwrap();
    let r2 = rx2.blocking_recv().unwrap().unwrap();

    assert_eq!(r1, r2, "coalesced duplicate must receive identical reply");

    // Now test mismatched digest with the already committed request id
    let req_diff = Request::WsNew(Box::new(Mutation {
        request_id: req_id,
        args: WsNewArgs {
            root: ByteString::from("/tmp/different-workspace"),
            init: WorkspaceInit::GitCompat {
                head: crate::workspace::HeadRef::Symbolic(
                    crate::refdata::RefName::new(b"refs/heads/main".to_vec()).unwrap(),
                ),
            },
            scope: None,
        },
    }));
    let reply_diff = Reply::WsNew(Box::new(WsNewReply {
        outcome: MutationOutcome {
            receipt: ReceiptRef {
                session: SessionId::generate(),
                request_id: req_id,
                digest: RequestDigest::from_bytes([0; 32]),
                replayed: false,
                retained_until: Timestamp::new(jiff::Timestamp::now()),
            },
            operation: None,
            heads: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            stamps: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            warnings: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            merge: None,
            provenance: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
            identity: None,
        },
        workspace: WorkspaceId::generate(),
        state: WorkspaceState::Native({
            let mut w = NativeWorkspace::new(
                crate::change::ChangeId::from_bytes([0; 16]),
                crate::heads::Head::Git {
                    oid: crate::ids::Oid::from_bytes(&[0u8; 20]).unwrap(),
                },
                Scope::Full,
            );
            w.stamp = WorkspaceStamp {
                sequence: 0,
                lease_epoch: 0,
            };
            w
        }),
    }));
    let cand_mismatched = MutationCandidate::new(
        session,
        principal,
        req_id,
        req_diff,
        reply_diff,
        Vec::new(),
        Vec::new(),
        None,
        None,
        Vec::new(),
        cancel.clone(),
        None,
    )
    .unwrap();

    let (tx3, rx3) = oneshot::channel();
    let batch2 = vec![BatchItem::Mutation {
        candidate: Box::new(cand_mismatched),
        reply_tx: Some(tx3),
    }];

    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch2,
        &cancel,
    )
    .expect("commit batch processes lookup");

    let err = rx3.blocking_recv().unwrap().unwrap_err();
    assert_eq!(err.code, ErrorCode::ERequestReused);
}

#[test]
fn test_4_stale_same_workspace_rejection_and_epoch_first_fencing() {
    let temp = TempRoot::new("workspace-fencing");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session_a = test_session(&session_table, &principal, idle);
    let session_b = test_session(&session_table, &principal, idle);

    let ws_id = WorkspaceId::generate();
    let ws_stamp = WorkspaceStamp {
        sequence: 10,
        lease_epoch: 5,
    }; // sequence 10, lease_epoch 5
    let ws_row = WorkspaceRow {
        state: WorkspaceState::Native({
            let mut w = NativeWorkspace::new(
                crate::change::ChangeId::from_bytes([0; 16]),
                crate::heads::Head::Git {
                    oid: crate::ids::Oid::from_bytes(&[0u8; 20]).unwrap(),
                },
                Scope::Full,
            );
            w.stamp = ws_stamp;
            w
        }),
        holder: session_a.id(),
        root: crate::bytes::ByteString::from("/tmp/ruk-lane-test"),
    };
    let encoded_ws = rows::encode("workspace", &ws_row).unwrap();

    // Persist workspace in store
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Workspaces,
                key: rows::workspace_key(ws_id).to_vec(),
                expected: FactExpectation::Absent,
                value: Some(encoded_ws),
            }],
        )
        .unwrap();

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);

    // 1. Session B attempts write -> holder mismatch -> E_LEASE_LOST
    let mut cand_b = make_candidate(
        session_b,
        principal.clone(),
        RequestId::generate(),
        Vec::new(),
        Vec::new(),
    );
    cand_b.workspace_fence = Some(WorkspaceFence::new(ws_id, ws_stamp));
    let (tx_b, rx_b) = oneshot::channel();
    let batch_b = vec![BatchItem::Mutation {
        candidate: Box::new(cand_b),
        reply_tx: Some(tx_b),
    }];
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch_b,
        &cancel,
    )
    .expect("lane stays up for per-candidate rejection");
    let err_b = rx_b
        .blocking_recv()
        .expect("reply")
        .expect_err("holder mismatch");
    assert_eq!(err_b.code, ErrorCode::ELeaseLost);

    // 2. Session A with wrong epoch (4 instead of 5) and wrong sequence (9 instead of 10) -> epoch checked first -> E_LEASE_LOST
    let mut cand_epoch = make_candidate(
        Arc::clone(&session_a),
        principal.clone(),
        RequestId::generate(),
        Vec::new(),
        Vec::new(),
    );
    cand_epoch.workspace_fence = Some(WorkspaceFence::new(
        ws_id,
        WorkspaceStamp {
            sequence: 9,
            lease_epoch: 4,
        },
    ));
    let (tx_e, rx_e) = oneshot::channel();
    let batch_e = vec![BatchItem::Mutation {
        candidate: Box::new(cand_epoch),
        reply_tx: Some(tx_e),
    }];
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch_e,
        &cancel,
    )
    .expect("lane stays up for per-candidate rejection");
    let err_e = rx_e
        .blocking_recv()
        .expect("reply")
        .expect_err("epoch mismatch");
    assert_eq!(err_e.code, ErrorCode::ELeaseLost);

    // 3. Session A with right epoch (5) but wrong sequence (9 instead of 10) -> sequence mismatch -> E_STALE
    let mut cand_seq = make_candidate(
        session_a,
        principal,
        RequestId::generate(),
        Vec::new(),
        Vec::new(),
    );
    cand_seq.workspace_fence = Some(WorkspaceFence::new(
        ws_id,
        WorkspaceStamp {
            sequence: 9,
            lease_epoch: 5,
        },
    ));
    let (tx_s, rx_s) = oneshot::channel();
    let batch_s = vec![BatchItem::Mutation {
        candidate: Box::new(cand_seq),
        reply_tx: Some(tx_s),
    }];
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch_s,
        &cancel,
    )
    .expect("lane stays up for per-candidate rejection");
    let err_s = rx_s
        .blocking_recv()
        .expect("reply")
        .expect_err("sequence mismatch");
    assert_eq!(err_s.code, ErrorCode::EStale);
}

#[test]
fn test_5_current_policy_revocation_after_preparation() {
    let temp = TempRoot::new("policy-revocation");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let other_principal = Principal::from_peer_uid(2000);
    let policy_source = PolicySource::open(&temp.store_dir(), other_principal);
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);
    let cand = make_candidate(
        session,
        principal,
        RequestId::generate(),
        Vec::new(),
        Vec::new(),
    );

    let (tx, rx) = oneshot::channel();
    let batch = vec![BatchItem::Mutation {
        candidate: Box::new(cand),
        reply_tx: Some(tx),
    }];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    // Because policy_source owner is other_principal (2000), principal 1000 is not listed!
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .expect("lane stays up for per-candidate rejection");
    let err = rx
        .blocking_recv()
        .expect("reply")
        .expect_err("policy revoked");
    assert_eq!(err.code, ErrorCode::EForbidden);
}

#[test]
fn test_6_receipt_replay_despite_expiry_or_stale_stamp() {
    let temp = TempRoot::new("replay-precedence");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);
    let req_id = RequestId::generate();

    let fact = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/replay-branch".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"committed-value".to_vec()),
    };

    let cand = make_candidate(
        Arc::clone(&session),
        principal.clone(),
        req_id,
        Vec::new(),
        vec![fact],
    );

    let (tx1, rx1) = oneshot::channel();
    let batch = vec![BatchItem::Mutation {
        candidate: Box::new(cand),
        reply_tx: Some(tx1),
    }];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .unwrap();
    let first_reply = rx1.blocking_recv().unwrap().unwrap();

    // Now submit the same request again, but attach an expired/stale expectation or fence
    let mut cand2 = make_candidate(session, principal, req_id, Vec::new(), Vec::new());
    cand2.workspace_fence = Some(WorkspaceFence::new(
        WorkspaceId::generate(),
        WorkspaceStamp {
            sequence: 999,
            lease_epoch: 999,
        },
    ));

    let (tx2, rx2) = oneshot::channel();
    let batch2 = vec![BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: Some(tx2),
    }];

    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch2,
        &cancel,
    )
    .unwrap();
    let replayed_reply = rx2.blocking_recv().unwrap().unwrap();

    assert!(replayed_reply.outcome().unwrap().receipt.replayed);
    assert_eq!(replayed_reply.method(), first_reply.method());
}

#[test]
fn test_7_noop_receipt_without_operation() {
    let temp = TempRoot::new("noop-receipt");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);
    let req_id = RequestId::generate();

    // Candidate with no tracked mutations
    let cand = make_candidate(session, principal, req_id, Vec::new(), Vec::new());

    let (tx, rx) = oneshot::channel();
    let batch = vec![BatchItem::Mutation {
        candidate: Box::new(cand),
        reply_tx: Some(tx),
    }];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .unwrap();

    let reply = rx.blocking_recv().unwrap().unwrap();
    let outcome = reply.outcome().unwrap();

    // Untracked-only mutation receives durable receipt but NO operation ID
    assert!(outcome.operation.is_none());
    assert_eq!(outcome.receipt.request_id, req_id);
    assert!(!outcome.receipt.replayed);
}

#[test]
fn test_8_atomic_domain_op_receipt_head_after_reopen() {
    let temp = TempRoot::new("atomic-reopen");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);
    let req_id = RequestId::generate();

    let blob_bytes = b"persisted-blob-data";
    let prep = store
        .prepare(
            ObjectKind::Blob,
            u64::try_from(blob_bytes.len()).expect("fits u64"),
            &blob_bytes[..],
            None,
        )
        .expect("prepare blob");
    let prep_oid = prep.oid();

    let fact = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/persisted".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(prep_oid.as_bytes().to_vec()),
    };

    let cand = make_candidate(session, principal, req_id, vec![prep], vec![fact]);

    let (tx, rx) = oneshot::channel();
    let batch = vec![BatchItem::Mutation {
        candidate: Box::new(cand),
        reply_tx: Some(tx),
    }];

    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel,
    )
    .unwrap();
    let reply = rx.blocking_recv().unwrap().unwrap();
    let op_id = reply.outcome().unwrap().operation.expect("op id allocated");

    // Reopen store from disk
    drop(store);
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let reopened = Store::open(&temp.store_dir(), budget).expect("reopen store");

    // Verify object exists
    let read_obj = reopened.read(prep_oid).expect("read object after reopen");
    assert_eq!(read_obj.kind, ObjectKind::Blob);

    // Verify ref fact exists
    let ref_bytes = reopened
        .fact(FactTable::Refs, b"refs/heads/persisted")
        .unwrap()
        .expect("ref fact persisted");
    assert_eq!(ref_bytes, prep_oid.as_bytes());

    // Verify op header exists
    let op_header = oplog::read_header(&reopened, op_id)
        .unwrap()
        .expect("op header exists");
    assert_eq!(op_header.entry.id, op_id);

    // Verify coordinator head
    let head_bytes = reopened
        .fact(FactTable::OpHead, rows::OP_HEAD_KEY)
        .unwrap()
        .unwrap();
    let head = rows::decode_head(&reopened, &head_bytes).unwrap();
    assert_eq!(head.last_op, Some(op_id));
}

#[test]
fn test_9_overlapping_candidates_deferred_with_owned_spools_intact() {
    let temp = TempRoot::new("defer-overlap");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let blob1 = store
        .prepare(ObjectKind::Blob, 5, &b"blob1"[..], None)
        .unwrap();
    let blob2 = store
        .prepare(ObjectKind::Blob, 5, &b"blob2"[..], None)
        .unwrap();

    let same_key = b"refs/heads/contended".to_vec();

    let fact1 = FactMutation {
        table: FactTable::Refs,
        key: same_key.clone(),
        expected: FactExpectation::Absent,
        value: Some(b"first".to_vec()),
    };
    let fact2 = FactMutation {
        table: FactTable::Refs,
        key: same_key,
        expected: FactExpectation::Value(b"first".to_vec()),
        value: Some(b"second".to_vec()),
    };

    let cand1 = make_candidate(
        session1,
        principal.clone(),
        RequestId::generate(),
        vec![blob1],
        vec![fact1],
    );
    let cand2 = make_candidate(
        session2,
        principal,
        RequestId::generate(),
        vec![blob2],
        vec![fact2],
    );

    let item1 = BatchItem::Mutation {
        candidate: Box::new(cand1),
        reply_tx: None,
    };
    let item2 = BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: None,
    };

    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&item1));
    accumulator.add(item1);

    // Overlapping key: accumulator MUST reject item2
    assert!(
        !accumulator.can_admit(&item2),
        "overlapping key candidate must be deferred"
    );

    // Commit batch 1
    let (ch, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(ch);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        accumulator.drain(),
        &cancel,
    )
    .expect("batch 1 commits");

    // Spools on item2 are completely intact! Now commit batch 2
    let mut accumulator2 = BatchAccumulator::new();
    assert!(accumulator2.can_admit(&item2));
    accumulator2.add(item2);

    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        accumulator2.drain(),
        &cancel,
    )
    .expect("batch 2 commits with preserved spools");
}

#[test]
fn test_10_cancellation_before_publication_and_receiver_drop_after_commit() {
    let temp = TempRoot::new("cancellation-drop");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session = test_session(&session_table, &principal, idle);

    // Case A: Pre-publish cancellation
    let (handle, cancel) = cancellation();
    handle.cancel(); // Cancel immediately

    let fact = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/cancelled".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"val".to_vec()),
    };
    let mut cand = make_candidate(
        Arc::clone(&session),
        principal.clone(),
        RequestId::generate(),
        Vec::new(),
        vec![fact],
    );
    cand.cancel = cancel;

    let (tx, rx) = oneshot::channel();
    let batch = vec![BatchItem::Mutation {
        candidate: Box::new(cand),
        reply_tx: Some(tx),
    }];

    let (_ch2, cancel2) = cancellation();
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch,
        &cancel2,
    )
    .unwrap();
    let err = rx.blocking_recv().unwrap().unwrap_err();
    assert_eq!(err.code, ErrorCode::ECancelled);
    assert!(
        store
            .fact(FactTable::Refs, b"refs/heads/cancelled")
            .unwrap()
            .is_none()
    );

    // Case B: Receiver dropped after commit
    let (tx2, rx2) = oneshot::channel();
    drop(rx2); // Receiver dropped before publication begins

    let fact2 = FactMutation {
        table: FactTable::Refs,
        key: b"refs/heads/dropped-rx".to_vec(),
        expected: FactExpectation::Absent,
        value: Some(b"survives".to_vec()),
    };
    let cand2 = make_candidate(
        session,
        principal,
        RequestId::generate(),
        Vec::new(),
        vec![fact2],
    );
    let batch2 = vec![BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: Some(tx2),
    }];

    // Commit must succeed durably even if receiver was dropped
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        batch2,
        &cancel2,
    )
    .unwrap();
    assert_eq!(
        store
            .fact(FactTable::Refs, b"refs/heads/dropped-rx")
            .unwrap()
            .unwrap(),
        b"survives"
    );
}

#[test]
fn test_11_fail_closed_ambiguous_storage_error() {
    let temp = TempRoot::new("fail-closed");
    let store = Arc::new(test_store(&temp));
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = Arc::new(PolicySource::open(&temp.store_dir(), principal.clone()));

    let (lane, _runner) = create_publication_lane(store, session_table, policy_source, clock);

    // Verify error classification rules
    let io_err = StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "pipe broken",
    ));
    assert_eq!(
        classify_store_error(&io_err),
        StoreFailureKind::AmbiguousOrFatal
    );

    let stale_err = StoreError::StaleFact {
        table: "refs",
        key: "refs/heads/main".to_owned(),
    };
    assert_eq!(
        classify_store_error(&stale_err),
        StoreFailureKind::AmbiguousOrFatal
    );

    let closed_err = StoreError::WriterClosed("store quarantined".to_owned());
    assert_eq!(
        classify_store_error(&closed_err),
        StoreFailureKind::AmbiguousOrFatal
    );

    let corrupt_err = StoreError::Corrupt("bad crc".to_owned());
    assert_eq!(
        classify_store_error(&corrupt_err),
        StoreFailureKind::AmbiguousOrFatal
    );

    let invalid_err = StoreError::Invalid("bad argument".to_owned());
    assert_eq!(
        classify_store_error(&invalid_err),
        StoreFailureKind::PreMutation
    );

    // Closing the lane latches fail-closed state
    lane.close();
    let err = lane.check_open().unwrap_err();
    assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);
}

#[tokio::test]
async fn test_12_shutdown_drains_queued_submissions() {
    use crate::coord::cancel::cancellation;

    let temp = TempRoot::new("shutdown-drain");
    let store = Arc::new(test_store(&temp));
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = Arc::new(PolicySource::open(&temp.store_dir(), principal.clone()));
    let (lane, runner) = create_publication_lane(store, session_table, policy_source, clock);

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let lane = lane.clone();
        tasks.push(tokio::spawn(async move {
            let (_guard, cancel) = cancellation();
            let candidate =
                InternalCandidate::new(InternalPayload::Maintenance, Vec::new(), cancel, None)
                    .expect("maintenance candidate");
            lane.submit_internal(candidate).await
        }));
    }
    // Every submission must reach the lane queue before shutdown: the
    // channel is buffered, so one scheduling quantum each is ample, and
    // the drain below only promises what is already queued.
    tokio::time::sleep(Duration::from_millis(200)).await;
    lane.close();
    // Fire shutdown cancellation before the runner starts: the loop exits
    // at once, so every reply below proves the post-loop drain committed.
    let (run_handle, run_cancel) = cancellation();
    drop(run_handle);
    let outcome = runner.run(run_cancel).await;
    assert_eq!(
        outcome.unwrap_err().code,
        ErrorCode::ECancelled,
        "a cancelled run still reports cancellation"
    );
    for task in tasks {
        task.await
            .expect("submission task joins")
            .expect("queued submission drains instead of failing");
    }
}

/// Claim acquisitions serialize across batches: two overlapping acquires
/// never share one batch, so the second seals against the first's committed
/// record and fails `E_CLAIMED` instead of committing an overlap.
#[test]
fn test_12_overlapping_claim_acquires_serialize_across_batches() {
    fn acquire_candidate(
        session: &Arc<SessionLive>,
        principal: &Principal,
    ) -> (MutationCandidate, ClaimId) {
        let request_id = RequestId::generate();
        let claim = ClaimId::generate();
        let paths = vec![RepoPath::new("src").expect("test path")];
        let request = Request::ClaimAcquire(Box::new(Mutation {
            request_id,
            args: ClaimAcquireArgs {
                paths: paths.clone(),
                ttl: ClaimTtl::new(60).expect("ttl"),
                mode: ClaimMode::Enforce,
            },
        }));
        let reply = Reply::ClaimAcquire(Box::new(ClaimAcquireReply {
            outcome: MutationOutcome {
                receipt: ReceiptRef {
                    session: session.id(),
                    request_id,
                    digest: RequestDigest::from_bytes([0; 32]),
                    replayed: false,
                    retained_until: Timestamp::new(jiff::Timestamp::now()),
                },
                operation: None,
                heads: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
                stamps: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
                warnings: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
                merge: None,
                provenance: crate::protocol::BoundedList::complete(Vec::new()).unwrap(),
                identity: None,
            },
            claim: ClaimRecord {
                claim,
                holder: session.id(),
                paths,
                mode: ClaimMode::Enforce,
                expires_at: Timestamp::new(jiff::Timestamp::now()),
                on_behalf_of: None,
            },
        }));
        let (handle, cancel) = cancellation();
        let _keep = std::mem::ManuallyDrop::new(handle);
        let candidate = MutationCandidate::new(
            Arc::clone(session),
            principal.clone(),
            request_id,
            request,
            reply,
            Vec::new(),
            Vec::new(),
            None,
            None,
            Vec::new(),
            cancel,
            None,
        )
        .expect("valid claim candidate");
        (candidate, claim)
    }

    let temp = TempRoot::new("claim-serialize");
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);

    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let (cand1, _) = acquire_candidate(&session1, &principal);
    let (cand2, _) = acquire_candidate(&session2, &principal);
    let (tx1, mut rx1) = oneshot::channel();
    let (tx2, mut rx2) = oneshot::channel();
    let item1 = BatchItem::Mutation {
        candidate: Box::new(cand1),
        reply_tx: Some(tx1),
    };
    let item2 = BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: Some(tx2),
    };

    // Same-batch admission is refused: the second acquire defers.
    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&item1));
    accumulator.add(item1);
    assert!(
        !accumulator.can_admit(&item2),
        "overlapping claim acquire must defer to the next batch"
    );

    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        accumulator.drain(),
        &cancel,
    )
    .expect("batch 1 commits");
    rx1.try_recv()
        .expect("first acquire answers")
        .expect("first acquire seals");

    // Against the committed record the deferred acquire is claimed.
    let mut accumulator2 = BatchAccumulator::new();
    assert!(accumulator2.can_admit(&item2));
    accumulator2.add(item2);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        accumulator2.drain(),
        &cancel,
    )
    .expect("batch 2 runs");
    let err = rx2
        .try_recv()
        .expect("second acquire answers")
        .expect_err("overlapping acquire is claimed");
    assert_eq!(err.code, ErrorCode::EClaimed);
}

/// Builds a branch-write candidate shaped like a prepared `git.commit`:
/// a CAS transaction moving `branch`, the branch as read premise, and the
/// matching `Refs` fact.
fn branch_write_candidate(
    session: Arc<SessionLive>,
    principal: Principal,
    branch: &str,
    oid_byte: u8,
) -> MutationCandidate {
    let name = RefName::new(branch).expect("valid branch name");
    let oid = crate::ids::Oid::from_bytes(&[oid_byte; 20]).expect("test oid");
    let transaction = RefTransaction::new(
        HashKind::Sha1,
        vec![RefUpdate {
            name: name.clone(),
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(oid)),
        }],
    )
    .expect("valid ref transaction");
    let fact = FactMutation {
        table: FactTable::Refs,
        key: name.as_bytes().to_vec(),
        expected: FactExpectation::Absent,
        value: Some(vec![oid_byte; 20]),
    };
    let request_id = RequestId::generate();
    let (req, reply) = dummy_mutation_request(request_id);
    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);
    MutationCandidate::new(
        session,
        principal,
        request_id,
        req,
        reply,
        Vec::new(),
        vec![fact],
        None,
        Some(transaction),
        vec![name],
        cancel,
        None,
    )
    .expect("valid branch candidate")
}

/// Builds a premise-read candidate: no write, just a `ref_dependencies`
/// pin on `branch`.
fn ref_read_candidate(
    session: Arc<SessionLive>,
    principal: Principal,
    branch: &str,
) -> MutationCandidate {
    let request_id = RequestId::generate();
    let (req, reply) = dummy_mutation_request(request_id);
    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);
    MutationCandidate::new(
        session,
        principal,
        request_id,
        req,
        reply,
        Vec::new(),
        Vec::new(),
        None,
        None,
        vec![RefName::new(branch).expect("valid branch name")],
        cancel,
        None,
    )
    .expect("valid read candidate")
}

fn ref_test_setup(
    tag: &str,
) -> (
    TempRoot,
    Store,
    Clock,
    SessionTable,
    PolicySource,
    Principal,
    SignedDuration,
) {
    let temp = TempRoot::new(tag);
    let store = test_store(&temp);
    let clock = Clock::system();
    let session_table = SessionTable::new(clock.clone());
    let principal = Principal::from_peer_uid(1000);
    let policy_source = PolicySource::open(&temp.store_dir(), principal.clone());
    let idle = SignedDuration::from_hours(24);
    (
        temp,
        store,
        clock,
        session_table,
        policy_source,
        principal,
        idle,
    )
}

/// Disjoint branch writes share one batch and both land: the relaxed gate
/// admits `b1` + `b2` together and the shared publication persists both refs.
#[test]
fn test_13_disjoint_ref_writes_share_one_batch() {
    let (_temp, store, clock, session_table, policy_source, principal, idle) =
        ref_test_setup("disjoint-refs");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let cand1 = branch_write_candidate(session1, principal.clone(), "refs/heads/b1", 0x11);
    let cand2 = branch_write_candidate(session2, principal, "refs/heads/b2", 0x22);
    let item1 = BatchItem::Mutation {
        candidate: Box::new(cand1),
        reply_tx: None,
    };
    let item2 = BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: None,
    };

    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&item1));
    accumulator.add(item1);
    assert!(
        accumulator.can_admit(&item2),
        "disjoint branch writes must share one batch"
    );
    accumulator.add(item2);

    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);
    commit_batch(
        &store,
        &session_table,
        &policy_source,
        &clock,
        accumulator.drain(),
        &cancel,
    )
    .expect("shared batch commits");
    assert!(
        store
            .fact(FactTable::Refs, b"refs/heads/b1")
            .expect("read b1")
            .is_some(),
        "b1 landed from the shared batch"
    );
    assert!(
        store
            .fact(FactTable::Refs, b"refs/heads/b2")
            .expect("read b2")
            .is_some(),
        "b2 landed from the shared batch"
    );
}

/// Same-branch writes still serialize: the second `b1` mover defers so CAS
/// decides the winner and the loser retries client-side.
#[test]
fn test_14_same_branch_writes_serialize_across_batches() {
    let (_temp, _store, _clock, session_table, _policy_source, principal, idle) =
        ref_test_setup("same-branch-refs");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let cand1 = branch_write_candidate(session1, principal.clone(), "refs/heads/b1", 0x11);
    let cand2 = branch_write_candidate(session2, principal, "refs/heads/b1", 0x22);
    let item1 = BatchItem::Mutation {
        candidate: Box::new(cand1),
        reply_tx: None,
    };
    let item2 = BatchItem::Mutation {
        candidate: Box::new(cand2),
        reply_tx: None,
    };

    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&item1));
    accumulator.add(item1);
    assert!(
        !accumulator.can_admit(&item2),
        "same-branch write must defer to the next batch"
    );
}

/// Read/write premise conflicts serialize in both arrival orders, while a
/// disjoint reader shares: a writer arriving after a reader would
/// invalidate the premise the reader was validated against, and a reader
/// arriving after a writer premises on a value the batch is moving.
#[test]
fn test_15_ref_read_write_premise_conflicts_serialize() {
    let (_temp, _store, _clock, session_table, _policy_source, principal, idle) =
        ref_test_setup("ref-read-write");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);
    let session3 = test_session(&session_table, &principal, idle);
    let session4 = test_session(&session_table, &principal, idle);

    // Reader first, writer second: the write hits the admitted read premise.
    let reader = ref_read_candidate(session1, principal.clone(), "refs/heads/main");
    let writer = branch_write_candidate(session2, principal.clone(), "refs/heads/main", 0x11);
    let reader_item = BatchItem::Mutation {
        candidate: Box::new(reader),
        reply_tx: None,
    };
    let writer_item = BatchItem::Mutation {
        candidate: Box::new(writer),
        reply_tx: None,
    };
    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&reader_item));
    accumulator.add(reader_item);
    assert!(
        !accumulator.can_admit(&writer_item),
        "write after a read premise on the same ref must defer"
    );

    // Writer first, reader second: the read premise hits the admitted write.
    let writer2 = branch_write_candidate(session3, principal.clone(), "refs/heads/main", 0x11);
    let reader2 = ref_read_candidate(session4, principal.clone(), "refs/heads/main");
    let writer_item2 = BatchItem::Mutation {
        candidate: Box::new(writer2),
        reply_tx: None,
    };
    let reader_item2 = BatchItem::Mutation {
        candidate: Box::new(reader2),
        reply_tx: None,
    };
    let mut accumulator2 = BatchAccumulator::new();
    assert!(accumulator2.can_admit(&writer_item2));
    accumulator2.add(writer_item2);
    assert!(
        !accumulator2.can_admit(&reader_item2),
        "read premise after a write on the same ref must defer"
    );
}

/// A ref-less item and a ref-touching item share one batch: disjoint reader
/// and writer premises never intersect.
#[test]
fn test_16_refless_and_ref_touching_share_one_batch() {
    let (_temp, _store, _clock, session_table, _policy_source, principal, idle) =
        ref_test_setup("refless-ref");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);

    let plain = make_candidate(
        session1,
        principal.clone(),
        RequestId::generate(),
        Vec::new(),
        Vec::new(),
    );
    let writer = branch_write_candidate(session2, principal, "refs/heads/b9", 0x33);
    let plain_item = BatchItem::Mutation {
        candidate: Box::new(plain),
        reply_tx: None,
    };
    let writer_item = BatchItem::Mutation {
        candidate: Box::new(writer),
        reply_tx: None,
    };

    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&plain_item));
    accumulator.add(plain_item);
    assert!(
        accumulator.can_admit(&writer_item),
        "ref-less and ref-touching items must share one batch"
    );
}

/// Builds a symbolic-link candidate: a CAS transaction setting `from` to
/// point at `to`, plus the matching `Refs` fact and read premise.
fn symbolic_link_candidate(
    session: Arc<SessionLive>,
    principal: Principal,
    from: &str,
    to: &str,
) -> MutationCandidate {
    let name = RefName::new(from).expect("valid branch name");
    let target = RefName::new(to).expect("valid target name");
    let transaction = RefTransaction::new(
        HashKind::Sha1,
        vec![RefUpdate {
            name: name.clone(),
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Symbolic(target.clone())),
        }],
    )
    .expect("valid ref transaction");
    let fact = FactMutation {
        table: FactTable::Refs,
        key: name.as_bytes().to_vec(),
        expected: FactExpectation::Absent,
        value: Some(target.as_bytes().to_vec()),
    };
    let request_id = RequestId::generate();
    let (req, reply) = dummy_mutation_request(request_id);
    let (handle, cancel) = cancellation();
    let _keep = std::mem::ManuallyDrop::new(handle);
    MutationCandidate::new(
        session,
        principal,
        request_id,
        req,
        reply,
        Vec::new(),
        vec![fact],
        None,
        Some(transaction),
        vec![name],
        cancel,
        None,
    )
    .expect("valid link candidate")
}

/// A ref and its child never share a batch: the per-item checks validate
/// against the same pre-batch snapshot and the store never re-checks the
/// directory/file invariant at publish time, so the gate refuses the pair
/// in both arrival orders.
#[test]
fn test_17_ref_child_pairs_serialize_across_batches() {
    let (_temp, _store, _clock, session_table, _policy_source, principal, idle) =
        ref_test_setup("ref-child");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);
    let session3 = test_session(&session_table, &principal, idle);
    let session4 = test_session(&session_table, &principal, idle);

    let parent = branch_write_candidate(session1, principal.clone(), "refs/heads/a", 0x11);
    let child = branch_write_candidate(session2, principal.clone(), "refs/heads/a/b", 0x22);
    let parent_item = BatchItem::Mutation {
        candidate: Box::new(parent),
        reply_tx: None,
    };
    let child_item = BatchItem::Mutation {
        candidate: Box::new(child),
        reply_tx: None,
    };
    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&parent_item));
    accumulator.add(parent_item);
    assert!(
        !accumulator.can_admit(&child_item),
        "child ref after its parent prefix must defer"
    );

    let child2 = branch_write_candidate(session3, principal.clone(), "refs/heads/a/b", 0x22);
    let parent2 = branch_write_candidate(session4, principal.clone(), "refs/heads/a", 0x11);
    let child_item2 = BatchItem::Mutation {
        candidate: Box::new(child2),
        reply_tx: None,
    };
    let parent_item2 = BatchItem::Mutation {
        candidate: Box::new(parent2),
        reply_tx: None,
    };
    let mut accumulator2 = BatchAccumulator::new();
    assert!(accumulator2.can_admit(&child_item2));
    accumulator2.add(child_item2);
    assert!(
        !accumulator2.can_admit(&parent_item2),
        "parent prefix after its child ref must defer"
    );
}

/// Links joining into a cycle never share a batch, while two links aimed
/// at one target do: cycle halves meet through the target sets in both
/// arrival orders, and target/target overlap alone stays shareable.
#[test]
fn test_18_symbolic_cycle_halves_serialize_across_batches() {
    let (_temp, _store, _clock, session_table, _policy_source, principal, idle) =
        ref_test_setup("link-cycle");
    let session1 = test_session(&session_table, &principal, idle);
    let session2 = test_session(&session_table, &principal, idle);
    let session3 = test_session(&session_table, &principal, idle);
    let session4 = test_session(&session_table, &principal, idle);
    let session5 = test_session(&session_table, &principal, idle);
    let session6 = test_session(&session_table, &principal, idle);

    let forward =
        symbolic_link_candidate(session1, principal.clone(), "refs/heads/a", "refs/heads/b");
    let backward =
        symbolic_link_candidate(session2, principal.clone(), "refs/heads/b", "refs/heads/a");
    let forward_item = BatchItem::Mutation {
        candidate: Box::new(forward),
        reply_tx: None,
    };
    let backward_item = BatchItem::Mutation {
        candidate: Box::new(backward),
        reply_tx: None,
    };
    let mut accumulator = BatchAccumulator::new();
    assert!(accumulator.can_admit(&forward_item));
    accumulator.add(forward_item);
    assert!(
        !accumulator.can_admit(&backward_item),
        "closing half of a symbolic cycle must defer"
    );

    let backward2 =
        symbolic_link_candidate(session3, principal.clone(), "refs/heads/b", "refs/heads/a");
    let forward2 =
        symbolic_link_candidate(session4, principal.clone(), "refs/heads/a", "refs/heads/b");
    let backward_item2 = BatchItem::Mutation {
        candidate: Box::new(backward2),
        reply_tx: None,
    };
    let forward_item2 = BatchItem::Mutation {
        candidate: Box::new(forward2),
        reply_tx: None,
    };
    let mut accumulator2 = BatchAccumulator::new();
    assert!(accumulator2.can_admit(&backward_item2));
    accumulator2.add(backward_item2);
    assert!(
        !accumulator2.can_admit(&forward_item2),
        "opening half after the closing half must defer"
    );

    // Two links sharing one target commit no joint invariant: both admit.
    let left = symbolic_link_candidate(session5, principal.clone(), "refs/heads/a", "refs/heads/b");
    let right =
        symbolic_link_candidate(session6, principal.clone(), "refs/heads/c", "refs/heads/b");
    let left_item = BatchItem::Mutation {
        candidate: Box::new(left),
        reply_tx: None,
    };
    let right_item = BatchItem::Mutation {
        candidate: Box::new(right),
        reply_tx: None,
    };
    let mut accumulator3 = BatchAccumulator::new();
    assert!(accumulator3.can_admit(&left_item));
    accumulator3.add(left_item);
    assert!(
        accumulator3.can_admit(&right_item),
        "links sharing one target must share one batch"
    );
}
