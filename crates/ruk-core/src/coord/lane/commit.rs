//! Sole publication owner commit pipeline.
//!
//! Executes exact CAS fact validation, idempotency replay lookup, duplicate
//! coalescing, current policy rechecks, workspace fencing, semantic ref checks,
//! oplog generation, 7-day receipt creation, retention preflight, CoordinatorHead
//! updates, and consumed-spool `Store::publish` execution.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::oneshot;

use crate::change::{CheckedOperationId, OperationId, RequestId, SessionId};
use crate::coord::cancel::Cancel;
use crate::coord::claims;
use crate::coord::clock::{Clock, Times};
use crate::coord::lane::batch::BatchItem;
use crate::coord::lane::candidate::{InternalPayload, MutationCandidate};
use crate::coord::oplog::{self, OpMeta};
use crate::coord::policy::{Policy, PolicySource};
use crate::coord::receipt::{self, Lookup};
use crate::coord::retention;
use crate::coord::rows::{self, CoordinatorHead, RECEIPT_HORIZON, ReceiptRow, SessionRow};
use crate::coord::session::Authority;
use crate::coord::session::SessionTable;
use crate::coord::workspace;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{ReceiptRef, Reply, RequestDigest, SessionAuthority, Timestamp};
use crate::refs::StoreRefs;
use crate::store::types::{FactExpectation, FactMutation, FactTable, PreparedObject};
use crate::store::{Store, StoreError};

/// Classification of a `StoreError` during lane publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreFailureKind {
    /// Definitive pre-mutation rejection before durable work began.
    PreMutation,
    /// Ambiguous or allocator-latched failure: durable work may have partially
    /// committed, or the redb writer/quarantine is closed. The lane must latch closed.
    AmbiguousOrFatal,
}

/// Classifies a `StoreError` to determine whether the lane must fail closed.
#[must_use]
pub(crate) fn classify_store_error(err: &StoreError) -> StoreFailureKind {
    match err {
        StoreError::Commit(_)
        | StoreError::WriterClosed(_)
        | StoreError::Corrupt(_)
        | StoreError::Storage(_)
        | StoreError::Database(_)
        | StoreError::Transaction(_)
        | StoreError::Table(_)
        | StoreError::SetDurability(_) => StoreFailureKind::AmbiguousOrFatal,
        StoreError::Io(_) => {
            // An I/O error during publish may have partially modified segments on disk.
            StoreFailureKind::AmbiguousOrFatal
        }
        StoreError::StaleFact { .. } => {
            // An unexpected StaleFact after sole-owner pre-validation means an invariant
            // was violated. Per contract: "An unexpected StaleFact after lane validation
            // closes the lane as an invariant failure."
            StoreFailureKind::AmbiguousOrFatal
        }
        StoreError::Invalid(_)
        | StoreError::Capacity(_)
        | StoreError::Limit(_)
        | StoreError::NotFound(_)
        | StoreError::Version(_)
        | StoreError::ObjectFormat(_)
        | StoreError::Model(_) => StoreFailureKind::PreMutation,
    }
}

/// One active mutation candidate being committed in the current batch.
struct ActiveMutation {
    candidate: Box<MutationCandidate>,
    reply_tx: Option<oneshot::Sender<Result<Reply, CoreError>>>,
    allocated_op: Option<OperationId>,
}

/// One active internal candidate being committed in the current batch.
struct ActiveInternal {
    payload: InternalPayload,
    facts: Vec<FactMutation>,
    reply_tx: Option<oneshot::Sender<Result<(), CoreError>>>,
}

/// Commits a batch of items under sole publication owner ownership.
///
/// Pre-mutation validation errors fail the affected candidate individually without
/// aborting surviving valid items. Ambiguous or fatal store failures latch the lane closed.
///
/// # Errors
/// Returns `CoreError` on pre-publication failure, cancellation, or store error.
pub(crate) fn commit_batch(
    store: &Store,
    session_table: &SessionTable,
    policy_source: &PolicySource,
    clock: &Clock,
    batch: Vec<BatchItem>,
    cancel: &Cancel,
) -> Result<(), CoreError> {
    if batch.is_empty() {
        return Ok(());
    }

    let times = clock.sample()?;

    // 1. Separate cancelled items before starting preparation.
    let mut pending_items = Vec::with_capacity(batch.len());
    for item in batch {
        if item.cancel().check().is_err() {
            item.fail(CoreError::new(ErrorCode::ECancelled, "operation cancelled"));
            continue;
        }
        pending_items.push(item);
    }

    if pending_items.is_empty() {
        return Ok(());
    }

    // 2. Separate mutations and internal items; resolve idempotency replays and in-batch duplicates.
    let mut candidate_mutations: Vec<ActiveMutation> = Vec::new();
    let mut active_internals: Vec<ActiveInternal> = Vec::new();
    let mut coalesced_duplicates: HashMap<
        (SessionId, RequestId),
        Vec<oneshot::Sender<Result<Reply, CoreError>>>,
    > = HashMap::new();
    let mut seen_batch_mutations: HashMap<(SessionId, RequestId), RequestDigest> = HashMap::new();

    for item in pending_items {
        match item {
            BatchItem::Internal {
                candidate,
                reply_tx,
            } => {
                active_internals.push(ActiveInternal {
                    payload: candidate.payload,
                    facts: candidate.facts,
                    reply_tx,
                });
            }
            BatchItem::Mutation {
                candidate,
                reply_tx,
            } => {
                let session_id = candidate.session.id();
                let request_id = candidate.request_id;
                let digest = candidate.digest;

                // Check stored receipts first.
                match receipt::lookup(store, session_id, request_id, &digest, times.wall)? {
                    Lookup::Replay(reply) => {
                        if let Some(tx) = reply_tx {
                            let _ = tx.send(Ok(reply));
                        }
                        continue;
                    }
                    Lookup::Reused => {
                        if let Some(tx) = reply_tx {
                            let _ = tx.send(Err(CoreError::new(
                                ErrorCode::ERequestReused,
                                "request id already used with different digest",
                            )));
                        }
                        continue;
                    }
                    Lookup::Miss => {}
                }

                // Check in-batch duplicates.
                if let Some(&first_digest) = seen_batch_mutations.get(&(session_id, request_id)) {
                    if first_digest != digest {
                        if let Some(tx) = reply_tx {
                            let _ = tx.send(Err(CoreError::new(
                                ErrorCode::ERequestReused,
                                "request id already used with different digest",
                            )));
                        }
                    } else if let Some(tx) = reply_tx {
                        coalesced_duplicates
                            .entry((session_id, request_id))
                            .or_default()
                            .push(tx);
                    }
                    continue;
                }

                seen_batch_mutations.insert((session_id, request_id), digest);
                candidate_mutations.push(ActiveMutation {
                    candidate,
                    reply_tx,
                    allocated_op: None,
                });
            }
        }
    }

    // 3. Pre-validate each candidate individually; fail the one candidate on error without aborting survivors.
    let policy = policy_source.load()?;
    let claim_clock = claims::ClaimClock::open(store, clock.clone())?;
    // The claim-clock fence fact is one row per publication; every seal in
    // the batch emits it, so only the first candidate may carry it.
    let mut claim_clock_fenced = false;
    let mut active_mutations: Vec<ActiveMutation> = Vec::with_capacity(candidate_mutations.len());

    for mut m in candidate_mutations {
        let validation_res =
            validate_candidate(store, &policy, &m.candidate, &times).and_then(|()| {
                claims::ClaimSealEnvelope::for_mutation(
                    store,
                    &claim_clock,
                    m.candidate.session.id(),
                    &m.candidate.request,
                )
                .map(|envelope| {
                    let (facts, _warnings, _record) = envelope.settle();
                    for fact in facts {
                        let is_clock =
                            fact.table == FactTable::Claims && fact.key == claims::CLOCK_KEY;
                        if is_clock && claim_clock_fenced {
                            continue;
                        }
                        claim_clock_fenced |= is_clock;
                        m.candidate.facts.push(fact);
                    }
                })
            });
        if let Err(err) = validation_res {
            if let Some(duplicates) =
                coalesced_duplicates.remove(&(m.candidate.session.id(), m.candidate.request_id))
            {
                for tx in duplicates {
                    let _ = tx.send(Err(err.clone()));
                }
            }
            if let Some(tx) = m.reply_tx.take() {
                let _ = tx.send(Err(err));
            }
            continue;
        }
        active_mutations.push(m);
    }

    // Validate internal candidates.
    let mut valid_internals: Vec<ActiveInternal> = Vec::with_capacity(active_internals.len());
    for mut internal in active_internals {
        let mut internal_err = None;
        for fact in &internal.facts {
            if let Err(err) = validate_fact_expectation(store, fact) {
                internal_err = Some(err);
                break;
            }
        }
        if let Some(err) = internal_err {
            if let Some(tx) = internal.reply_tx.take() {
                let _ = tx.send(Err(err));
            }
            continue;
        }
        valid_internals.push(internal);
    }

    if active_mutations.is_empty() && valid_internals.is_empty() {
        return Ok(());
    }

    // 4. Oplog recording and OperationId allocation for surviving mutations.
    let current_head_bytes = store.fact(FactTable::OpHead, rows::OP_HEAD_KEY)?;
    let mut head = match &current_head_bytes {
        Some(bytes) => rows::decode_head(store, bytes)?,
        None => CoordinatorHead::default(),
    };

    let initial_last_op = head.last_op;
    let mut ops = CheckedOperationId::new(initial_last_op.map_or(0, |id| id.0), u64::MAX);
    let mut parent_op = initial_last_op;
    let mut all_facts: Vec<FactMutation> = Vec::new();

    for m in &mut active_mutations {
        let meta = OpMeta {
            session: m.candidate.session.id(),
            method: m.candidate.request.method(),
            committed_at: times.timestamp(),
            undoes: None,
        };

        let op_record = oplog::record(&mut ops, parent_op, meta, &m.candidate.facts)?;
        if let Some((op_id, op_mutations)) = op_record {
            parent_op = Some(op_id);
            all_facts.extend(op_mutations);
            m.allocated_op = Some(op_id);
        }
    }

    // 5. Receipt generation for every surviving mutation candidate.
    let retained_until = times.checked_add_signed(RECEIPT_HORIZON)?;
    for m in &mut active_mutations {
        let receipt_ref = ReceiptRef {
            session: m.candidate.session.id(),
            request_id: m.candidate.request_id,
            digest: m.candidate.digest,
            replayed: false,
            retained_until: Timestamp::new(retained_until),
        };

        if let Some(outcome) = m.candidate.mut_reply.outcome_mut() {
            outcome.receipt = receipt_ref;
            outcome.operation = m.allocated_op;
        }

        let receipt_row = rows::ReceiptRow::new(
            m.candidate.session.id(),
            m.candidate.request_id,
            m.candidate.mut_reply.clone(),
        )?;
        let encoded_receipt = rows::encode("receipt row", &receipt_row)?;
        let receipt_key =
            rows::receipt_key(m.candidate.session.id(), m.candidate.request_id).to_vec();

        all_facts.push(FactMutation {
            table: FactTable::Receipts,
            key: receipt_key,
            expected: FactExpectation::Absent,
            value: Some(encoded_receipt),
        });
    }

    // 6. Collect domain mutations and internal transaction mutations.
    for m in &active_mutations {
        all_facts.extend(m.candidate.facts.iter().cloned());
    }

    let mut internal_updated_sessions: HashMap<SessionId, Arc<SessionRow>> = HashMap::new();
    for internal in &valid_internals {
        all_facts.extend(internal.facts.iter().cloned());
        match &internal.payload {
            InternalPayload::SessionOpen { id, row, .. } => {
                let encoded = rows::encode("session row", &**row)?;
                all_facts.push(FactMutation {
                    table: FactTable::Sessions,
                    key: rows::session_key(*id).to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                });
                internal_updated_sessions.insert(*id, Arc::clone(row));
            }
            InternalPayload::SessionExpireLatch { id, row, .. } => {
                let encoded = rows::encode("session row", &**row)?;
                let old_bytes = store.fact(FactTable::Sessions, &rows::session_key(*id))?;
                let expected = old_bytes.map_or(FactExpectation::Absent, FactExpectation::Value);
                all_facts.push(FactMutation {
                    table: FactTable::Sessions,
                    key: rows::session_key(*id).to_vec(),
                    expected,
                    value: Some(encoded),
                });
                internal_updated_sessions.insert(*id, Arc::clone(row));
            }
            InternalPayload::Sweep { cursors } => {
                head.sweep = *cursors;
            }
            InternalPayload::Maintenance => {}
        }
    }

    // 7. Emit one durable Sessions CAS fact per distinct session for activity refresh.
    let default_idle = policy.session_idle();
    let mut updated_session_rows: HashMap<SessionId, Arc<SessionRow>> = HashMap::new();

    for m in &active_mutations {
        let session_id = m.candidate.session.id();
        if internal_updated_sessions.contains_key(&session_id)
            || updated_session_rows.contains_key(&session_id)
        {
            continue;
        }

        let key = rows::session_key(session_id);
        let Some(old_bytes) = store.fact(FactTable::Sessions, &key)? else {
            continue;
        };

        let mut row = rows::decode_session(store, &key, &old_bytes)?;
        let new_expires_instant = times.checked_add_signed(default_idle)?;
        let new_expires_ts = Timestamp::new(new_expires_instant);

        let modified = match row.authority {
            SessionAuthority::Active { idle_expires_at } => {
                if new_expires_ts >= idle_expires_at {
                    row.authority = SessionAuthority::Active {
                        idle_expires_at: new_expires_ts,
                    };
                    true
                } else {
                    false
                }
            }
            _ => false,
        };

        if modified {
            let encoded = rows::encode("session row", &row)?;
            all_facts.push(FactMutation {
                table: FactTable::Sessions,
                key: key.to_vec(),
                expected: FactExpectation::Value(old_bytes),
                value: Some(encoded),
            });
            updated_session_rows.insert(session_id, Arc::new(row));
        }
    }

    // 8. Retention ledger update and CoordinatorHead publication.
    retention::apply_facts(store, &mut head.retained, &all_facts)?;
    head.last_op = ops.last();
    let encoded_head = rows::encode("coordinator head", &head)?;
    all_facts.push(FactMutation {
        table: FactTable::OpHead,
        key: rows::OP_HEAD_KEY.to_vec(),
        expected: current_head_bytes.map_or(FactExpectation::Absent, FactExpectation::Value),
        value: Some(encoded_head),
    });

    // 9. Final cancellation check immediately before irreversible store publish.
    cancel.check()?;

    // 10. Irreversible store publication.
    let mut all_objects = Vec::new();
    for m in &mut active_mutations {
        all_objects.append(&mut m.candidate.objects);
    }

    let publish_result = store.publish(all_objects, &all_facts);
    if let Err(store_err) = publish_result {
        let failure_kind = classify_store_error(&store_err);
        let core_err = CoreError::from(store_err);

        for m in active_mutations {
            if let Some(tx) = m.reply_tx {
                let _ = tx.send(Err(core_err.clone()));
            }
        }
        for internal in valid_internals {
            if let Some(tx) = internal.reply_tx {
                let _ = tx.send(Err(core_err.clone()));
            }
        }
        for duplicates in coalesced_duplicates.into_values() {
            for tx in duplicates {
                let _ = tx.send(Err(core_err.clone()));
            }
        }

        if failure_kind == StoreFailureKind::AmbiguousOrFatal {
            return Err(CoreError::new(
                ErrorCode::ECoordinatorUnresponsive,
                format!("publication lane closed due to storage failure: {core_err}"),
            ));
        }

        return Err(core_err);
    }

    // 11. Post-commit state updates and waiter notifications.
    for m in &active_mutations {
        let session_id = m.candidate.session.id();
        let session_row = updated_session_rows
            .get(&session_id)
            .cloned()
            .unwrap_or_else(|| m.candidate.session.row());

        session_table.apply_committed(session_id, Some(session_row), default_idle, times);
    }

    for internal in &valid_internals {
        match &internal.payload {
            InternalPayload::SessionOpen { id, row, idle } => {
                session_table.apply_committed(*id, Some(Arc::clone(row)), *idle, times);
            }
            InternalPayload::SessionExpireLatch { id, row, idle } => {
                session_table.apply_committed(*id, Some(Arc::clone(row)), *idle, times);
            }
            InternalPayload::Sweep { .. } | InternalPayload::Maintenance => {}
        }
    }

    for m in active_mutations {
        let reply = m.candidate.mut_reply;
        let session_id = m.candidate.session.id();
        let request_id = m.candidate.request_id;

        if let Some(duplicates) = coalesced_duplicates.remove(&(session_id, request_id)) {
            for tx in duplicates {
                let _ = tx.send(Ok(reply.clone()));
            }
        }

        if let Some(tx) = m.reply_tx {
            let _ = tx.send(Ok(reply));
        }
    }

    for internal in valid_internals {
        if let Some(tx) = internal.reply_tx {
            let _ = tx.send(Ok(()));
        }
    }

    Ok(())
}

fn validate_candidate(
    store: &Store,
    policy: &Policy,
    candidate: &MutationCandidate,
    times: &Times,
) -> Result<(), CoreError> {
    // Check policy ceiling and claims.
    let principal_policy = policy.lookup(&candidate.principal)?;
    principal_policy.admit_claims(
        candidate.session.row().identity.as_ref(),
        &candidate.session.row().claims,
    )?;

    // Check session authority.
    let auth = candidate.session.current_authority(times);
    if auth != Authority::Active {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            "session write authority has expired",
        ));
    }

    // Validate workspace fence if present.
    if let Some(fence) = candidate.workspace_fence {
        let observed = workspace::observe(store, fence.id)?;
        observed.fence(candidate.session.id(), fence.expected)?;
    }

    // Validate ref transaction if present.
    if let Some(tx) = &candidate.ref_transaction {
        tx.check(&StoreRefs::new(store))?;
    }

    // Pre-validate all fact expectations.
    for fact in &candidate.facts {
        validate_fact_expectation(store, fact)?;
    }

    Ok(())
}

fn validate_fact_expectation(store: &Store, fact: &FactMutation) -> Result<(), CoreError> {
    if fact.expected == FactExpectation::Any {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "FactExpectation::Any is forbidden for lane mutations",
        ));
    }

    let current = store.fact(fact.table, &fact.key)?;

    match &fact.expected {
        FactExpectation::Absent => {
            if current.is_some() {
                return Err(CoreError::new(
                    ErrorCode::EStale,
                    format!(
                        "fact in table {:?} was expected absent but exists",
                        fact.table
                    ),
                ));
            }
        }
        FactExpectation::Value(expected_bytes) => {
            let Some(bytes) = &current else {
                return Err(CoreError::new(
                    ErrorCode::EStale,
                    format!(
                        "fact in table {:?} was expected present but is absent",
                        fact.table
                    ),
                ));
            };
            if bytes != expected_bytes {
                return Err(CoreError::new(
                    ErrorCode::EStale,
                    format!(
                        "fact in table {:?} did not match expected value",
                        fact.table
                    ),
                ));
            }
        }
        FactExpectation::Any => unreachable!(),
    }

    Ok(())
}
