//! Candidate definitions for the coordinator publication lane.
//!
//! Every client mutation or internal coordinator transaction submitted to the
//! sole publication owner is represented as a typed, bounded candidate.
//! No arbitrary JSON mutation engines or unbounded closure captures are used.

use std::sync::Arc;

use crate::change::{RequestId, SessionId, WorkspaceId};
use crate::coord::admission::Admitted;
use crate::coord::cancel::Cancel;
use crate::coord::policy::Principal;
use crate::coord::receipt;
use crate::coord::rows::SweepCursors;
use crate::coord::rows::{ROW_MAX_BYTES, SessionRow};
use crate::coord::session::SessionLive;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Reply, Request, RequestDigest};
use crate::refdata::{RefName, RefTransaction};
use crate::store::types::{FactExpectation, FactMutation, PreparedObject};
use crate::workspace::WorkspaceStamp;
use jiff::SignedDuration;

/// Fencing requirement for a workspace mutation candidate.
///
/// Under sole writer ownership, the held workspace row is rechecked before
/// effects: holder session and lease epoch must match before sequence comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkspaceFence {
    pub(crate) id: WorkspaceId,
    pub(crate) expected: WorkspaceStamp,
}

impl WorkspaceFence {
    /// Creates a new workspace fence.
    #[must_use]
    pub(crate) const fn new(id: WorkspaceId, expected: WorkspaceStamp) -> Self {
        Self { id, expected }
    }
}

/// Validates that facts contain no `FactExpectation::Any`, conform to `ROW_MAX_BYTES`,
/// and returns the total accounted byte size.
fn account_and_validate_facts(facts: &[FactMutation]) -> Result<u64, CoreError> {
    let mut total_bytes: u64 = 0;
    for fact in facts {
        if fact.expected == FactExpectation::Any {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "FactExpectation::Any is forbidden for lane facts",
            ));
        }

        let key_len = u64::try_from(fact.key.len())
            .map_err(|_| CoreError::new(ErrorCode::ELimit, "key len overflow"))?;
        let val_len = match &fact.value {
            Some(v) => u64::try_from(v.len())
                .map_err(|_| CoreError::new(ErrorCode::ELimit, "val len overflow"))?,
            None => 0,
        };
        let exp_len = match &fact.expected {
            FactExpectation::Value(v) => u64::try_from(v.len())
                .map_err(|_| CoreError::new(ErrorCode::ELimit, "expected len overflow"))?,
            _ => 0,
        };

        let row_bytes = key_len
            .checked_add(val_len)
            .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "fact row size overflow"))?;
        let exp_row_bytes = key_len
            .checked_add(exp_len)
            .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "fact expectation size overflow"))?;

        if row_bytes > ROW_MAX_BYTES || exp_row_bytes > ROW_MAX_BYTES {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!(
                    "fact row for table {:?} exceeds maximum limit of {} bytes",
                    fact.table, ROW_MAX_BYTES
                ),
            ));
        }

        total_bytes = total_bytes
            .checked_add(row_bytes)
            .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "prepared bytes overflow"))?;
    }
    Ok(total_bytes)
}

/// A client mutation request prepared for atomic publication.
///
/// Owns its prepared object spools, exact fact expectations, typed outcome reply,
/// canonical digest, session/principal binding, cancellation observer, and optional
/// workspace fencing / ref transactions.
pub(crate) struct MutationCandidate {
    pub(crate) session: Arc<SessionLive>,
    pub(crate) principal: Principal,
    pub(crate) request_id: RequestId,
    pub(crate) digest: RequestDigest,
    pub(crate) request: Request,
    pub(crate) mut_reply: Reply,
    pub(crate) objects: Vec<PreparedObject>,
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) workspace_fence: Option<WorkspaceFence>,
    pub(crate) ref_transaction: Option<RefTransaction>,
    pub(crate) ref_dependencies: Vec<RefName>,
    pub(crate) cancel: Cancel,
    pub(crate) admitted: Option<Admitted>,
    pub(crate) prepared_bytes: u64,
}

impl MutationCandidate {
    /// Creates and validates a new `MutationCandidate`.
    ///
    /// Computes the canonical request digest from `request` and validates the reply
    /// outcome header against `request.method()`.
    ///
    /// # Errors
    /// - `E_INVALID` if the request method is not a mutation, the reply method does not
    ///   match the request, the reply has no mutable outcome, or any fact uses `FactExpectation::Any`.
    /// - `E_LIMIT` if any fact row exceeds `ROW_MAX_BYTES`.
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor takes 12 validated fields; production caller is hosted.rs, tests in lane/tests.rs"
    )]
    pub(crate) fn new(
        session: Arc<SessionLive>,
        principal: Principal,
        request_id: RequestId,
        request: Request,
        mut mut_reply: Reply,
        objects: Vec<PreparedObject>,
        facts: Vec<FactMutation>,
        workspace_fence: Option<WorkspaceFence>,
        ref_transaction: Option<RefTransaction>,
        ref_dependencies: Vec<RefName>,
        cancel: Cancel,
        admitted: Option<Admitted>,
    ) -> Result<Self, CoreError> {
        if !request.method().is_mutation() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("method `{}` is not a mutation", request.method().as_str()),
            ));
        }

        if mut_reply.method() != request.method() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "reply method `{}` does not match request method `{}`",
                    mut_reply.method().as_str(),
                    request.method().as_str()
                ),
            ));
        }

        if mut_reply.outcome_mut().is_none() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "mutation reply must contain a mutable MutationOutcome header",
            ));
        }

        let digest = receipt::digest_v1(&request)?.ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "failed to compute request digest")
        })?;

        let mut prepared_bytes: u64 = 0;
        for obj in &objects {
            prepared_bytes = prepared_bytes
                .checked_add(obj.payload.len())
                .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "prepared bytes overflow"))?;
        }

        let fact_bytes = account_and_validate_facts(&facts)?;
        prepared_bytes = prepared_bytes
            .checked_add(fact_bytes)
            .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "prepared bytes overflow"))?;

        Ok(Self {
            session,
            principal,
            request_id,
            digest,
            request,
            mut_reply,
            objects,
            facts,
            workspace_fence,
            ref_transaction,
            ref_dependencies,
            cancel,
            admitted,
            prepared_bytes,
        })
    }
}

/// Payload discriminator for internal / control transactions that share the sole publication lane.
#[derive(Debug)]
pub(crate) enum InternalPayload {
    /// Persists a `SessionRow` after `SessionTable::reserve_open` but before binding.
    SessionOpen {
        id: SessionId,
        row: Arc<SessionRow>,
        idle: SignedDuration,
    },
    /// Persists irreversible expiry (`ReceiptsOnly`) upon session resumption latch.
    SessionExpireLatch {
        id: SessionId,
        row: Arc<SessionRow>,
        idle: SignedDuration,
    },
    /// Bounded expiry sweep: deletes expired receipts or sessions and advances sweep cursors.
    Sweep { cursors: SweepCursors },
    /// Maintenance or pruning: general exact-CAS facts with optional retention head adjustment.
    Maintenance,
}

/// A coordinator-internal transaction submitted to the publication lane.
///
/// Internal transactions do not create receipt rows or allocate operation IDs, but
/// run through the same sole publication owner and atomic redb commit pipeline.
pub(crate) struct InternalCandidate {
    pub(crate) payload: InternalPayload,
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) cancel: Cancel,
    pub(crate) admitted: Option<Admitted>,
    pub(crate) prepared_bytes: u64,
}

impl InternalCandidate {
    /// Creates and validates a new `InternalCandidate`.
    ///
    /// # Errors
    /// - `E_INVALID` if any fact uses `FactExpectation::Any`.
    /// - `E_LIMIT` if any fact row exceeds `ROW_MAX_BYTES`.
    pub(crate) fn new(
        payload: InternalPayload,
        facts: Vec<FactMutation>,
        cancel: Cancel,
        admitted: Option<Admitted>,
    ) -> Result<Self, CoreError> {
        let prepared_bytes = account_and_validate_facts(&facts)?;
        Ok(Self {
            payload,
            facts,
            cancel,
            admitted,
            prepared_bytes,
        })
    }
}
