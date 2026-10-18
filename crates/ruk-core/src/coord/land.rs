//! Exact-candidate land plans and drift-refusing execution.
//!
//! A land plan freezes one immutable landing: the target ref, the exact
//! candidate commit set, the required base tip, the attestation predicates,
//! and the execution deadline. [`land_prepare`] computes the plan and stores
//! it in [`FactTable::LandPlans`](crate::store::types::FactTable::LandPlans).
//! [`land_execute`] validates the stored plan against live state and
//! publishes the target move in one store commit. Any drift refuses with a
//! typed decline. Execution never re-plans silently.
//!
//! # Exactness contract
//! - The candidate set is frozen sorted and deduplicated. Execution publishes
//!   the primary candidate (the first set member) as the new target tip.
//! - The base is the resolved target tip at prepare time, or absent for an
//!   unborn target. Execution requires the live tip to equal the base
//!   exactly. This is an equality check, not a fast-forward check.
//! - Attestation predicates are frozen inputs. Prepare snapshots their
//!   outcome; execution re-evaluates them live and refuses when any
//!   candidate misses a requirement.
//! - Plans expire one hour after creation. Expired plans refuse.
//! - Execution consumes the stored plan row in the same commit as the ref
//!   move, so a second execution refuses as not found.
//!
//! # Protocol binding
//! - [`LandPrepareRequest`] carries [`LandPrepareArgs`](crate::protocol::LandPrepareArgs)
//!   plus the exact candidates, the attestation policy, and the creation time.
//! - [`LandPlan`] maps to [`LandPrepareReply`](crate::protocol::LandPrepareReply):
//!   `plan`, `candidate` (the primary candidate), `base` (the zero OID of the
//!   store hash kind when the target is unborn), `expires_at`,
//!   `policy_generation`, and `requirements`.
//! - [`land_execute`] takes the stored plan. A daemon serving
//!   [`LandExecuteArgs`](crate::protocol::LandExecuteArgs) loads the plan
//!   with [`load_plan`], refuses `E_STALE` when `args.candidate` differs from
//!   the primary candidate, then calls [`land_execute`].
//! - [`LandOutcome`] is the local publish leg. The remote push leg and the
//!   [`LandExecuteReply`](crate::protocol::LandExecuteReply) assembly stay
//!   with the transport owner.
//!
//! # Preconditions
//! Both entry points run under sole publication-lane ownership. Ref
//! preparation reads the target tip through a range seek that concurrent
//! writers can invalidate. The execute commit is one atomic publication;
//! its exact fact expectations give linearizable single-writer semantics,
//! and a second executor loses the plan-row expectation instead of
//! double-landing.

use jiff::SignedDuration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::attestation::{
    Checkpoint, MAX_LAND_REQUIREMENTS, MAX_TRUSTED_SIGNERS, evaluate_requirements,
};
use crate::change::PlanId;
use crate::error::{CoreError, ErrorCode};
use crate::ids::Oid;
use crate::protocol::{AttestRequirement, ChangeRef, MergeSelection, SignerFingerprint, Timestamp};
use crate::refdata::{
    RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate, resolve,
};
use crate::refs::{StoreRefs, prepare_checked_transaction};
use crate::store::types::{FactExpectation, FactMutation, FactTable};
use crate::store::{Store, decode, encode};

/// How long a land plan stays executable after creation.
pub const LAND_PLAN_TTL: SignedDuration = SignedDuration::from_hours(1);

/// Most candidate commits one land plan freezes.
pub const MAX_LAND_CANDIDATES: usize = 1024;

/// The frozen inputs [`land_prepare`] turns into a [`LandPlan`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandPrepareRequest {
    /// The change under land, with its selected head.
    pub change: ChangeRef,
    /// The target ref to land onto, e.g. `refs/heads/main`.
    pub target: RefName,
    /// The exact candidate commits to freeze, before deduplication.
    pub candidates: Vec<Oid>,
    /// The attestations the candidate set must carry at execution.
    pub requirements: Vec<AttestRequirement>,
    /// The signers trusted to meet the requirements.
    pub trusted: Vec<SignerFingerprint>,
    /// The merge selection in force for the landing.
    pub merge: MergeSelection,
    /// The policy version that produced the requirements.
    pub policy_generation: u64,
    /// The creation time; the deadline is one hour later.
    pub now: Timestamp,
}

/// An immutable land plan, stored as one [`FactTable::LandPlans`](crate::store::types::FactTable::LandPlans) row.
///
/// All durable row formats declared here are v1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandPlan {
    /// The durable identity of this plan.
    pub plan: PlanId,
    /// The change under land, with its selected head.
    pub change: ChangeRef,
    /// The requested target ref.
    pub target: RefName,
    /// The frozen candidate set, sorted and deduplicated.
    pub candidates: Vec<Oid>,
    /// The resolved target tip at prepare time, or absent when unborn.
    pub base: Option<Oid>,
    /// The frozen attestation predicates.
    pub requirements: Vec<AttestRequirement>,
    /// The frozen trusted signers.
    pub trusted: Vec<SignerFingerprint>,
    /// The merge selection in force for the landing.
    pub merge: MergeSelection,
    /// The policy version that produced the requirements.
    pub policy_generation: u64,
    /// The creation time.
    pub created_at: Timestamp,
    /// The last executable instant, one hour after creation.
    pub expires_at: Timestamp,
    /// Whether every candidate met every requirement at prepare time.
    pub satisfied_at_prepare: bool,
}

impl LandPlan {
    /// Returns the primary candidate: the first member of the frozen set.
    ///
    /// [`land_prepare`] refuses empty candidate sets, so a stored plan
    /// carries at least one member. An empty set decodes only from a
    /// hand-built row and reports as absent here.
    #[must_use]
    pub fn candidate(&self) -> Option<Oid> {
        self.candidates.first().copied()
    }

    /// Returns true when `now` is past the execution deadline.
    ///
    /// The plan stays valid at exactly `expires_at` and refuses after it.
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now.instant() > self.expires_at.instant()
    }
}

/// The local publish leg of one executed land plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandOutcome {
    /// The executed plan.
    pub plan: PlanId,
    /// The target ref that moved.
    pub target: RefName,
    /// The required base tip, or absent for an unborn target.
    pub base: Option<Oid>,
    /// The published tip: the primary candidate.
    pub candidate: Oid,
    /// The full frozen candidate set.
    pub candidates: Vec<Oid>,
    /// The deadline the execution met.
    pub expires_at: Timestamp,
}

/// Returns the [`FactTable::LandPlans`](crate::store::types::FactTable::LandPlans) key for `plan`.
#[must_use]
pub fn plan_key(plan: PlanId) -> [u8; 16] {
    *plan.as_bytes()
}

/// Loads the stored plan for `plan`.
///
/// Returns `Ok(None)` when no plan row exists.
///
/// # Errors
/// `E_CORRUPT` for a stored row that fails decoding; I/O failures propagate.
pub fn load_plan(store: &Store, plan: PlanId) -> Result<Option<LandPlan>, CoreError> {
    let raw = store.fact(FactTable::LandPlans, &plan_key(plan))?;
    let Some(bytes) = raw else {
        return Ok(None);
    };
    let stored: LandPlan = store.observe(decode("land plan", &bytes))?;
    Ok(Some(stored))
}

/// Stages an exact-candidate land plan without publishing it.
///
/// Runs every check [`land_prepare`] runs — candidate width and stored
/// existence, target resolution, attestation snapshot, deadline, row-size
/// bound — and returns the frozen plan plus its `LandPlans` row mutation
/// (absent-key expectation), so the hosted lane can publish the row through
/// its own commit path. A generated plan id that collides with a stored row
/// refuses `E_STALE` here instead of failing at publication time.
///
/// # Errors
/// Same as [`land_prepare`], without publishing.
pub fn prepare_land_plan(
    store: &Store,
    request: LandPrepareRequest,
    checkpoint: &Checkpoint<'_>,
) -> Result<(LandPlan, FactMutation), CoreError> {
    if request.candidates.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "land plan needs at least one candidate",
        ));
    }
    if request.candidates.len() > MAX_LAND_CANDIDATES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("land plan holds at most {MAX_LAND_CANDIDATES} candidates"),
        ));
    }
    if request.requirements.len() > MAX_LAND_REQUIREMENTS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("a land policy names at most {MAX_LAND_REQUIREMENTS} requirements"),
        ));
    }
    if request.trusted.len() > MAX_TRUSTED_SIGNERS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("a land policy trusts at most {MAX_TRUSTED_SIGNERS} signers"),
        ));
    }
    let kind = store.hash_kind();
    for candidate in &request.candidates {
        candidate
            .expect_kind(kind, "land candidate")
            .map_err(CoreError::from)?;
    }
    if let Some(head) = request.change.head {
        head.validate(kind).map_err(CoreError::from)?;
    }
    let refs = StoreRefs::new(store);
    let resolved = resolve(&refs, &request.target).map_err(CoreError::from)?;
    if resolved.terminal != request.target {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "land target must be a direct ref, not a symbolic link",
        ));
    }
    let mut candidates = request.candidates;
    candidates.sort();
    candidates.dedup();
    for candidate in &candidates {
        let present = store.object_len(*candidate)?;
        if present.is_none() {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                format!("land candidate {candidate} is not stored"),
            ));
        }
    }
    let mut satisfied_at_prepare = true;
    for candidate in &candidates {
        let evaluation = evaluate_requirements(
            store,
            candidate,
            &request.requirements,
            &request.trusted,
            checkpoint,
        )?;
        satisfied_at_prepare = satisfied_at_prepare && evaluation.satisfied;
    }
    let expires = request
        .now
        .instant()
        .checked_add(LAND_PLAN_TTL)
        .map_err(|err| {
            CoreError::new(
                ErrorCode::EInvalid,
                format!("land plan expiry overflows: {err}"),
            )
        })?;
    let plan = LandPlan {
        plan: PlanId::generate(),
        change: request.change,
        target: request.target,
        candidates,
        base: resolved.oid,
        requirements: request.requirements,
        trusted: request.trusted,
        merge: request.merge,
        policy_generation: request.policy_generation,
        created_at: request.now,
        expires_at: Timestamp::new(expires),
        satisfied_at_prepare,
    };
    let bytes: Vec<u8> = store.observe(encode("land plan", &plan))?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "encoded land plan exceeds one control frame",
        ));
    }
    let key = plan_key(plan.plan).to_vec();
    if store.fact(FactTable::LandPlans, &key)?.is_some() {
        return Err(CoreError::new(
            ErrorCode::EStale,
            "land plan identity collision; re-prepare",
        ));
    }
    let mutation = FactMutation {
        table: FactTable::LandPlans,
        key,
        expected: FactExpectation::Absent,
        value: Some(bytes),
    };
    Ok((plan, mutation))
}

/// Freezes an exact-candidate land plan and stores it.
///
/// Reads the resolved target tip as the required base, validates every
/// candidate width and stored existence, snapshots the attestation predicate
/// outcome, sets the one-hour deadline, and publishes the plan row with an
/// absent-key expectation. The call moves no ref.
///
/// # Errors
/// `E_INVALID` for an empty candidate set, a symbolic target, or an
/// overflowing deadline; `E_LIMIT` for too many candidates, requirements,
/// trusted signers, or an oversized row; `E_OBJECT_FORMAT` for a candidate
/// of the wrong hash width; `E_NOT_FOUND` for a candidate with no stored
/// object; `E_POLICY` for requirements with no trusted signer; `E_STALE`
/// for a plan identity collision; `E_CORRUPT` or `E_IO` from the store.
pub fn land_prepare(
    store: &Store,
    request: LandPrepareRequest,
    checkpoint: &Checkpoint<'_>,
) -> Result<LandPlan, CoreError> {
    let (plan, mutation) = prepare_land_plan(store, request, checkpoint)?;
    store.publish(Vec::new(), &[mutation])?;
    Ok(plan)
}

/// Executes a land plan after validating it against live state.
///
/// The stored plan row must equal `plan` exactly, the plan must be
/// unexpired, the live target tip must still equal the frozen base, and
/// every candidate must meet every requirement under the frozen trust set.
/// The commit moves the target to the primary candidate and consumes the
/// plan row in one atomic publication.
///
/// # Errors
/// `E_NOT_FOUND` for an unknown plan; `E_STALE` for an expired plan, a
/// stored plan that differs from `plan`, a moved target tip, or a lost
/// commit race; `E_POLICY` for a candidate that misses a requirement;
/// `E_CORRUPT` or `E_IO` from the store.
pub fn land_execute(
    store: &Store,
    plan: &LandPlan,
    now: Timestamp,
    checkpoint: &Checkpoint<'_>,
) -> Result<LandOutcome, CoreError> {
    let raw = store.fact(FactTable::LandPlans, &plan_key(plan.plan))?;
    let Some(stored_bytes) = raw else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("unknown land plan {}", plan.plan),
        ));
    };
    let stored: LandPlan = store.observe(decode("land plan", &stored_bytes))?;
    if stored != *plan {
        return Err(CoreError::new(
            ErrorCode::EStale,
            "stored land plan differs from the presented plan; re-prepare",
        ));
    }
    if plan.is_expired(now) {
        return Err(CoreError::new(
            ErrorCode::EStale,
            "land plan expired; re-prepare",
        ));
    }
    let refs = StoreRefs::new(store);
    let resolved = resolve(&refs, &plan.target).map_err(CoreError::from)?;
    if resolved.terminal != plan.target {
        return Err(CoreError::new(
            ErrorCode::EStale,
            "land target no longer resolves directly; re-prepare",
        ));
    }
    if resolved.oid != plan.base {
        return Err(CoreError::new(
            ErrorCode::EStale,
            "land target tip moved since prepare; re-prepare",
        ));
    }
    for candidate in &plan.candidates {
        let evaluation = evaluate_requirements(
            store,
            candidate,
            &plan.requirements,
            &plan.trusted,
            checkpoint,
        )?;
        if !evaluation.satisfied {
            return Err(CoreError::new(
                ErrorCode::EPolicy,
                format!("land candidate {candidate} misses a required attestation"),
            ));
        }
    }
    let Some(primary) = plan.candidate() else {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "stored land plan has an empty candidate set",
        ));
    };
    let ref_expected = match plan.base {
        Some(base) => RefExpect::Present(RefTarget::Direct(base)),
        None => RefExpect::Absent,
    };
    let transaction = RefTransaction::new(
        store.hash_kind(),
        vec![RefUpdate {
            name: plan.target.clone(),
            expected: ref_expected,
            change: RefChange::Set(RefTarget::Direct(primary)),
        }],
    )
    .map_err(CoreError::from)?;
    let prepared = prepare_checked_transaction(store, &transaction).map_err(CoreError::from)?;
    let mut mutations = prepared.into_mutations();
    mutations.push(FactMutation {
        table: FactTable::LandPlans,
        key: plan_key(plan.plan).to_vec(),
        expected: FactExpectation::Value(stored_bytes),
        value: None,
    });
    store.publish(Vec::new(), &mutations)?;
    Ok(LandOutcome {
        plan: plan.plan,
        target: plan.target.clone(),
        base: plan.base,
        candidate: primary,
        candidates: plan.candidates.clone(),
        expires_at: plan.expires_at,
    })
}
