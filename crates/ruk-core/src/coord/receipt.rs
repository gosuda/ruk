//! Receipt helpers: idempotency hashing, lookup, replay, and rejection settlement.
//!
//! Mutations in Ruk are idempotent: every committed mutation records a receipt
//! in [`FactTable::Receipts`] containing the byte-identical [`Reply`]. When a request
//! repeats an existing `(session, request_id)` with the same idempotency digest,
//! the coordinator replays the stored reply with `replayed = true` and avoids
//! re-executing the operation.

use sha2::{Digest, Sha256};

use crate::change::{RequestId, SessionId};
use crate::coord::rows::{decode_receipt, receipt_key};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Reply, Request, RequestDigest};
use crate::store::Store;
use crate::store::types::FactTable;

/// Computes the v1 idempotency digest for a request using SHA-256.
///
/// Returns `Ok(None)` for read and bootstrap requests that have no receipt.
///
/// # Errors
/// [`ErrorCode::EInvalid`] if the request arguments cannot be postcard-encoded.
pub(crate) fn digest_v1(req: &Request) -> Result<Option<RequestDigest>, CoreError> {
    let Some(input) = req.digest_input_v1()? else {
        return Ok(None);
    };
    let hash = Sha256::digest(&input);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&hash);
    Ok(Some(RequestDigest::from_bytes(bytes)))
}

/// The result of an idempotency lookup in [`FactTable::Receipts`].
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Lookup {
    /// No receipt exists for `(session, request_id)`, or its retention horizon has expired.
    Miss,
    /// An identical request previously committed; the stored reply is replayed.
    Replay(Reply),
    /// A receipt exists for `(session, request_id)` but with a different digest (`E_REQUEST_REUSED`).
    Reused,
}

/// Performs an exact point read of [`FactTable::Receipts`] for `(session, request)`.
///
/// If a receipt exists:
/// - Verifies semantic invariants and quarantine latches via [`decode_receipt`].
/// - If `retained_until <= wall`, treats the receipt as expired ([`Lookup::Miss`]).
/// - If the stored digest matches `digest`, returns [`Lookup::Replay`] with `replayed = true`.
/// - If the digest differs, returns [`Lookup::Reused`].
///
/// # Errors
/// [`ErrorCode::ECorrupt`] if committed receipt bytes fail decode or invariant validation.
pub(crate) fn lookup(
    store: &Store,
    session: SessionId,
    request: RequestId,
    digest: &RequestDigest,
    wall: jiff::Timestamp,
) -> Result<Lookup, CoreError> {
    let key = receipt_key(session, request);
    let raw = store.fact(FactTable::Receipts, &key)?;
    let Some(bytes) = raw else {
        return Ok(Lookup::Miss);
    };

    let receipt_row = decode_receipt(store, &key, &bytes)?;
    let retained_until = receipt_row.receipt().retained_until.instant();
    if retained_until <= wall {
        return Ok(Lookup::Miss);
    }

    if receipt_row.receipt().digest == *digest {
        Ok(Lookup::Replay(receipt_row.into_replay()))
    } else {
        Ok(Lookup::Reused)
    }
}

/// Returns the stored reply when `(session, request)` committed before, so a
/// retried request replays instead of re-executing.
///
/// The lane's receipt lookup runs after preparation, but preparation
/// re-runs translation against current state — which already reflects the
/// committed attempt — so a retry would fail `E_STALE`/`E_INVALID` before
/// ever reaching the lane. The dispatch path calls this before preparing.
///
/// The hosted push transport jobs (`push`, `push.reconcile`) also call this
/// before touching the network: a retried push must return the stored reply
/// instead of re-sending bytes to the remote.
///
/// # Errors
/// - [`ErrorCode::ERequestReused`] if the request id was used with a different digest.
/// - [`ErrorCode::ECorrupt`] if committed receipt bytes fail decode or invariant validation.
pub fn replay_if_committed(
    store: &Store,
    session: SessionId,
    request: &Request,
    wall: jiff::Timestamp,
) -> Result<Option<Reply>, CoreError> {
    let Some(request_id) = request.request_id() else {
        return Ok(None);
    };
    let Some(digest) = digest_v1(request)? else {
        return Ok(None);
    };
    match lookup(store, session, request_id, &digest, wall)? {
        Lookup::Replay(reply) => Ok(Some(reply)),
        Lookup::Reused => Err(CoreError::new(
            ErrorCode::ERequestReused,
            "request id already used with different digest",
        )),
        Lookup::Miss => Ok(None),
    }
}

/// Rechecks the receipt table before returning a pre-lane rejection (e.g. `E_STALE` or `E_LEASE_LOST`).
///
/// If the request actually committed previously (e.g. connection dropped after commit but before
/// reply delivery), replay takes precedence over the rejection error.
///
/// # Errors
/// - [`ErrorCode::ERequestReused`] if the request id was used with a different digest.
/// - `err` if no receipt exists.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )
)]
pub(crate) fn settle_rejection(
    store: &Store,
    session: SessionId,
    request: RequestId,
    digest: &RequestDigest,
    wall: jiff::Timestamp,
    err: CoreError,
) -> Result<Reply, CoreError> {
    match lookup(store, session, request, digest, wall)? {
        Lookup::Replay(reply) => Ok(reply),
        Lookup::Reused => Err(CoreError::new(
            ErrorCode::ERequestReused,
            "request id already used with different digest",
        )),
        Lookup::Miss => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::change::{ChangeId, OperationId, WorkspaceId};
    use crate::coord::rows::{ReceiptRow, encode};
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::protocol::{
        BoundedList, Method, MutationOutcome, ReceiptRef, Timestamp, WsTakeArgs, WsTakeReply,
    };
    use crate::store::types::{FactExpectation, FactMutation};
    use crate::store::{EventContext, EventSource, PreparationBudget};
    use crate::workspace::{NativeWorkspace, Scope, WorkspaceState};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-coord-receipt-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                TEST_DIR_SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create test directory");
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

    fn test_store(tag: &str) -> (TempRoot, Store) {
        let temp = TempRoot::new(tag);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store =
            Store::create(&temp.store_dir(), HashKind::Sha1, budget).expect("create test store");
        (temp, store)
    }

    fn sample_workspace_state() -> WorkspaceState {
        WorkspaceState::Native(NativeWorkspace::new(
            ChangeId::from_bytes([7; 16]),
            Head::Git {
                oid: Oid::from_hex("0123456789abcdef0123456789abcdef01234567").expect("valid oid"),
            },
            Scope::Full,
        ))
    }

    fn sample_mutation_reply(
        session: SessionId,
        request: RequestId,
        digest: RequestDigest,
        replayed: bool,
        retained_until: Timestamp,
    ) -> Reply {
        let receipt = ReceiptRef {
            session,
            request_id: request,
            digest,
            replayed,
            retained_until,
        };
        let outcome = MutationOutcome {
            receipt,
            operation: Some(OperationId(42)),
            heads: BoundedList::complete(Vec::new()).expect("empty"),
            stamps: BoundedList::complete(Vec::new()).expect("empty"),
            warnings: BoundedList::complete(Vec::new()).expect("empty"),
            merge: None,
            provenance: BoundedList::complete(Vec::new()).expect("empty"),
            identity: None,
        };
        let ws_state = sample_workspace_state();
        Reply::WsTake(Box::new(WsTakeReply {
            outcome,
            state: ws_state,
        }))
    }

    fn sample_take_request(request_id: RequestId) -> Request {
        Request::WsTake(Box::new(crate::protocol::Mutation {
            request_id,
            args: WsTakeArgs {
                workspace: WorkspaceId::generate(),
                expected: None,
            },
        }))
    }

    #[test]
    fn digest_v1_computes_sha256_of_mutation_arguments() {
        let req_id = RequestId::generate();
        let req = sample_take_request(req_id);

        let digest_opt = digest_v1(&req).expect("digest computation");
        assert!(digest_opt.is_some());
        let digest = digest_opt.unwrap();

        let raw_input = req.digest_input_v1().expect("input").expect("some input");
        let expected_hash = Sha256::digest(&raw_input);
        assert_eq!(digest.as_bytes(), expected_hash.as_slice());

        // Anonymous / read requests return None
        let schema_req = Request::Schema(Box::new(crate::protocol::SchemaArgs { method: None }));
        assert_eq!(digest_v1(&schema_req).expect("schema digest"), None);
    }

    #[test]
    fn lookup_miss_when_no_receipt_in_store() {
        let (_dir, store) = test_store("lookup-miss");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let digest = RequestDigest::from_bytes([0xaa; 32]);
        let wall = jiff::Timestamp::now();

        let res = lookup(&store, session, req_id, &digest, wall).expect("lookup");
        assert_eq!(res, Lookup::Miss);
    }

    #[test]
    fn lookup_replay_exact_match_and_reused_mismatch() {
        let (_dir, store) = test_store("lookup-replay");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let digest = RequestDigest::from_bytes([0x42; 32]);
        let future_wall = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(24))
            .expect("future wall");
        let retained_until = Timestamp::new(future_wall);

        let reply = sample_mutation_reply(session, req_id, digest, false, retained_until);
        let receipt_row = ReceiptRow::new(session, req_id, reply.clone()).expect("new receipt row");
        let encoded = encode("receipt", &receipt_row).expect("encode");

        let key = receipt_key(session, req_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        let current_wall = jiff::Timestamp::now();

        // Matching digest -> Lookup::Replay
        let lookup_match = lookup(&store, session, req_id, &digest, current_wall).expect("lookup");
        match lookup_match {
            Lookup::Replay(replayed_reply) => {
                let outcome = replayed_reply.outcome().expect("outcome");
                assert!(outcome.receipt.replayed, "replayed flag must be true");
                assert_eq!(outcome.receipt.session, session);
                assert_eq!(outcome.receipt.request_id, req_id);
                assert_eq!(outcome.receipt.digest, digest);
                assert_eq!(outcome.operation, Some(OperationId(42)));
            }
            other => panic!("expected Replay, got {other:?}"),
        }

        // Differing digest -> Lookup::Reused
        let different_digest = RequestDigest::from_bytes([0x99; 32]);
        let lookup_diff =
            lookup(&store, session, req_id, &different_digest, current_wall).expect("lookup");
        assert_eq!(lookup_diff, Lookup::Reused);
    }

    #[test]
    fn lookup_miss_after_expiration() {
        let (_dir, store) = test_store("lookup-expired");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let digest = RequestDigest::from_bytes([0x11; 32]);

        let past_time = jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .expect("past time");
        let retained_until = Timestamp::new(past_time);

        let reply = sample_mutation_reply(session, req_id, digest, false, retained_until);
        let receipt_row = ReceiptRow::new(session, req_id, reply).expect("new receipt row");
        let encoded = encode("receipt", &receipt_row).expect("encode");

        let key = receipt_key(session, req_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        let current_wall = jiff::Timestamp::now();
        let res = lookup(&store, session, req_id, &digest, current_wall).expect("lookup");
        assert_eq!(res, Lookup::Miss, "expired receipt must return Miss");
    }

    #[test]
    fn retried_request_replays_instead_of_re_executing() {
        let (_dir, store) = test_store("replay-first");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let request = sample_take_request(req_id);
        let digest = digest_v1(&request)
            .expect("digest computation")
            .expect("mutation has a digest");
        let retained_until = Timestamp::new(
            jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_hours(24))
                .expect("future"),
        );
        let reply = sample_mutation_reply(session, req_id, digest, false, retained_until);
        let encoded = encode(
            "receipt",
            &ReceiptRow::new(session, req_id, reply).expect("row"),
        )
        .expect("encode");
        let key = receipt_key(session, req_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");
        let wall = jiff::Timestamp::now();
        // The same session and request id retried replays the stored reply.
        let replayed = replay_if_committed(&store, session, &request, wall)
            .expect("replay lookup")
            .expect("a committed request replays");
        assert!(replayed.outcome().expect("outcome").receipt.replayed);
        // The same id with different arguments refuses instead of executing.
        let different = sample_take_request(req_id);
        assert_ne!(
            digest_v1(&different).expect("digest").expect("digest"),
            digest,
            "the test needs arguments that actually differ"
        );
        let reused = replay_if_committed(&store, session, &different, wall).expect_err("reused id");
        assert_eq!(reused.code, ErrorCode::ERequestReused);
        // An uncommitted id prepares normally.
        let fresh = sample_take_request(RequestId::generate());
        assert_eq!(
            replay_if_committed(&store, session, &fresh, wall).expect("miss"),
            None
        );
    }

    #[test]
    fn settle_rejection_prefers_replay_over_stale_or_lease_lost() {
        let (_dir, store) = test_store("settle-rejection");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let digest = RequestDigest::from_bytes([0x55; 32]);
        let future_wall = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(24))
            .expect("future");
        let retained_until = Timestamp::new(future_wall);

        let original_reply = sample_mutation_reply(session, req_id, digest, false, retained_until);
        let receipt_row =
            ReceiptRow::new(session, req_id, original_reply.clone()).expect("new receipt row");
        let encoded = encode("receipt", &receipt_row).expect("encode");

        let key = receipt_key(session, req_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        let current_wall = jiff::Timestamp::now();
        let stale_err = CoreError::new(ErrorCode::EStale, "workspace stamp changed concurrently");

        // Receipt exists with matching digest -> replay takes precedence!
        let settled = settle_rejection(
            &store,
            session,
            req_id,
            &digest,
            current_wall,
            stale_err.clone(),
        )
        .expect("settle should replay");
        assert!(settled.outcome().expect("outcome").receipt.replayed);

        // Receipt exists with differing digest -> fails E_REQUEST_REUSED
        let wrong_digest = RequestDigest::from_bytes([0x77; 32]);
        let reused_err = settle_rejection(
            &store,
            session,
            req_id,
            &wrong_digest,
            current_wall,
            stale_err.clone(),
        )
        .unwrap_err();
        assert_eq!(reused_err.code, ErrorCode::ERequestReused);

        // No receipt for unknown request -> returns the original error
        let unknown_req = RequestId::generate();
        let miss_err = settle_rejection(
            &store,
            session,
            unknown_req,
            &digest,
            current_wall,
            stale_err.clone(),
        )
        .unwrap_err();
        assert_eq!(miss_err.code, ErrorCode::EStale);
    }

    #[test]
    fn replay_survives_operation_deletion_and_preserves_payload() {
        let (_dir, store) = test_store("replay-survives-op-del");
        let session = SessionId::generate();
        let req_id = RequestId::generate();
        let digest = RequestDigest::from_bytes([0x88; 32]);
        let future_wall = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_hours(48))
            .expect("future");
        let retained_until = Timestamp::new(future_wall);

        let reply = sample_mutation_reply(session, req_id, digest, false, retained_until);
        let receipt_row = ReceiptRow::new(session, req_id, reply.clone()).expect("new row");
        let encoded = encode("receipt", &receipt_row).expect("encode");

        let key = receipt_key(session, req_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");

        // The Ops table is completely empty; no operation exists.
        // Replay must succeed without inspecting or depending on Ops!
        let current_wall = jiff::Timestamp::now();
        let res = lookup(&store, session, req_id, &digest, current_wall).expect("lookup");
        match res {
            Lookup::Replay(replayed) => {
                let out = replayed.outcome().expect("outcome");
                assert!(out.receipt.replayed);
                assert_eq!(out.operation, Some(OperationId(42)));
                // Method and state match original
                assert_eq!(replayed.method(), Method::WsTake);
            }
            other => panic!("expected Replay, got {other:?}"),
        }
    }
}
