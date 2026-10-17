//! Host-facing coordinator facade for external adapters.
//!
//! [`HostedCoordinator`] owns one repository's coordinator state (store,
//! session table, policy source, admission handle, and publication lane) and
//! exposes the minimal surface the daemon, CLI, and MCP adapters need:
//! session open, resume, and close, plus admitted mutation submission. No
//! table, lock, policy, or lane internals leak through the public types.
//!
//! The lane runner needs a Tokio runtime the core must not own, so
//! [`HostedCoordinator::spawn_on`] borrows a host [`tokio::runtime::Handle`] and spawns the
//! single publication owner there exactly once. [`HostedCoordinator::shutdown`]
//! drains the lane and releases the runner.
//!
//! A bare [`Request`] carries no prepared objects or facts, and no in-tree
//! producer translates an arbitrary method into lane parts, so
//! [`HostedCoordinator::submit_prepared`] accepts caller-prepared parts in a
//! [`PreparedMutation`]. A future per-method dispatch layer supplies them;
//! until it exists a bare request has no honest lane path and callers refuse
//! it with [`ErrorCode::EHosted`] at their own boundary.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::admission::{
    Admission, AdmissionLimits, AdmissionRequest, Admitted, RepoAdmission, RequestClass,
    WorkResources,
};
pub use super::cancel::{Cancel, CancelHandle, cancellation};
use super::clock::Clock;
use super::lane::{
    InternalCandidate, InternalPayload, MutationCandidate, PublicationLane, PublicationLaneRunner,
    WorkspaceFence, create_publication_lane,
};
use super::policy::PolicySource;
pub use super::policy::Principal;
use super::rows::{RECEIPT_HORIZON, SessionRow, decode_session, session_key};
use super::session::{Authority, ResumeOutcome, SessionTable, prepare_open};
use crate::capability::Capabilities;
use crate::change::{RequestId, SessionId, WorkspaceId};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    ReconnectSecret, Reply, Request, SessionAuthority, SessionOpenArgs, SessionResumeArgs,
    SessionResumeReply, Timestamp,
};
use crate::refdata::{RefName, RefTransaction};
use crate::store::Store;
use crate::store::types::{FactMutation, FactTable, PreparedObject};
use crate::workspace::WorkspaceStamp;

/// Caller-prepared parts of one mutation submission.
///
/// The per-method dispatch layer prepares `objects` through [`Store::prepare`],
/// builds `facts` with exact expectations, and precomputes `reply` carrying the
/// mutable outcome header for `request.method()`. [`HostedCoordinator`] admits
/// the submission, validates the candidate, and publishes it on the lane.
#[derive(Debug)]
pub struct PreparedMutation {
    /// Target session of the mutation.
    pub session: SessionId,
    /// Idempotency key of the mutation.
    pub request_id: RequestId,
    /// Mutation method and parameters.
    pub request: Request,
    /// Precomputed reply carrying the mutable outcome header.
    pub reply: Reply,
    /// Prepared object spools owned by the candidate.
    pub objects: Vec<PreparedObject>,
    /// Exact-expectation fact mutations.
    pub facts: Vec<FactMutation>,
    /// Workspace fencing as an identifier plus its expected stamp.
    pub workspace_fence: Option<(WorkspaceId, WorkspaceStamp)>,
    /// Semantic ref transaction of the mutation.
    pub ref_transaction: Option<RefTransaction>,
    /// Ref names the transaction was validated against.
    pub ref_dependencies: Vec<RefName>,
}

impl PreparedMutation {
    fn payload_bytes(&self) -> Result<usize, CoreError> {
        let overflow = || CoreError::new(ErrorCode::ELimit, "mutation payload size overflow");
        let mut total: u64 = 0;
        for object in &self.objects {
            total = total
                .checked_add(object.decoded_len())
                .ok_or_else(overflow)?;
        }
        for fact in &self.facts {
            let key_len = u64::try_from(fact.key.len()).map_err(|_| overflow())?;
            total = total.checked_add(key_len).ok_or_else(overflow)?;
            if let Some(value) = fact.value.as_ref() {
                let value_len = u64::try_from(value.len()).map_err(|_| overflow())?;
                total = total.checked_add(value_len).ok_or_else(overflow)?;
            }
        }
        usize::try_from(total).map_err(|_| overflow())
    }
}

/// One repository's hosted coordinator.
///
/// Owns the store handle, live session table, policy source, admission
/// registration, and publication lane. Shares across threads through [`Arc`];
/// the lane runner leaves through [`HostedCoordinator::spawn_on`] once.
pub struct HostedCoordinator {
    store: Arc<Store>,
    sessions: SessionTable,
    policies: Arc<PolicySource>,
    admission: Arc<Admission>,
    repo: RepoAdmission,
    lane: PublicationLane,
    runner: Mutex<Option<PublicationLaneRunner>>,
    clock: Clock,
    shutdown_handle: CancelHandle,
    shutdown: Cancel,
}

impl HostedCoordinator {
    /// Opens one repository coordinator over `store`.
    ///
    /// Binds the policy source to `store_root/policy.toml` for `owner`,
    /// registers one repository with the reference admission profile, and
    /// creates the publication lane. The runner stays held until
    /// [`HostedCoordinator::spawn_on`].
    ///
    /// # Errors
    /// - [`ErrorCode::EInvalid`] when the admission profile is inconsistent.
    /// - [`ErrorCode::ELimit`] when the repository registration bound is full.
    pub fn open(
        store: Arc<Store>,
        owner: Principal,
        store_root: PathBuf,
    ) -> Result<Self, CoreError> {
        let policies = Arc::new(PolicySource::open(&store_root, owner));
        let clock = Clock::system();
        let sessions = SessionTable::new(clock.clone());
        let admission = Admission::new(AdmissionLimits::reference_profile())?;
        let repo = admission.repo()?;
        let (lane, runner) = create_publication_lane(
            Arc::clone(&store),
            sessions.clone(),
            Arc::clone(&policies),
            clock.clone(),
        );
        let (shutdown_handle, shutdown) = cancellation();
        Ok(Self {
            store,
            sessions,
            policies,
            admission,
            repo,
            lane,
            runner: Mutex::new(Some(runner)),
            clock,
            shutdown_handle,
            shutdown,
        })
    }

    /// Returns the owned store for request preparation reads.
    ///
    /// The future per-method dispatch layer reads session rows, refs, and
    /// workspace state here before building a [`PreparedMutation`].
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Spawns the publication lane runner on `handle`.
    ///
    /// The runner is single ownership: the first call takes it and the host
    /// runtime drives it to completion or to a fatal store failure.
    ///
    /// # Errors
    /// - [`ErrorCode::EInvalid`] when the runner already spawned.
    /// - [`ErrorCode::EIo`] when the runner slot is poisoned.
    pub fn spawn_on(
        &self,
        handle: &tokio::runtime::Handle,
    ) -> Result<JoinHandle<Result<(), CoreError>>, CoreError> {
        let runner = self
            .runner
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "coordinator runner lock poisoned"))?
            .take()
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    "publication lane runner already spawned",
                )
            })?;
        let cancel = self.shutdown.clone();
        Ok(handle.spawn(async move { runner.run(cancel).await }))
    }

    /// Orders lane drain and runner return.
    ///
    /// Closes the lane to new submissions and cancels the runner's blocking
    /// waits. In-flight batches still settle under sole publication ownership.
    pub fn shutdown(&self) {
        self.lane.close();
        self.shutdown_handle.cancel();
    }

    /// Opens one session for `principal` and publishes its durable row.
    ///
    /// Composes policy lookup, open preparation, capacity reservation, control
    /// admission, internal lane publication of the session row, and binding.
    /// Durability comes from the committed session row; the binding releases
    /// on return and later calls reload the row on demand.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] when the principal is unlisted or its claims
    ///   exceed the policy ceiling.
    /// - [`ErrorCode::ECapacity`] when the live session table is full.
    /// - [`ErrorCode::ELimit`] when admission sheds the publication.
    /// - [`ErrorCode::EIo`] on secret generation or clock failure.
    /// - [`ErrorCode::EInvalid`] on timestamp overflow or candidate rejection.
    pub async fn open_session(
        &self,
        principal: &Principal,
        args: &SessionOpenArgs,
        cancel: &Cancel,
    ) -> Result<(SessionId, ReconnectSecret), CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let policy = self.policies.load()?;
        let principal_policy = policy.lookup(principal)?;
        let idle = policy.session_idle();
        let times = self.clock.sample()?;
        let pending = prepare_open(principal, principal_policy, idle, args, times.wall)?;
        let reservation = self.sessions.reserve_open(&pending)?;
        let row = Arc::new(pending.row);
        let admitted = self.admit_control(cancel).await?;
        let candidate = InternalCandidate::new(
            InternalPayload::SessionOpen {
                id: pending.session_id,
                row: Arc::clone(&row),
                idle,
            },
            Vec::new(),
            cancel.clone(),
            Some(admitted),
        )?;
        self.lane.submit_internal(candidate).await?;
        let _ = reservation.into_binding(row, idle, times);
        Ok((pending.session_id, pending.reply.reconnect_secret))
    }

    /// Resumes one session under `principal` and latches expiry durably.
    ///
    /// An expired but unlatched session publishes its `ReceiptsOnly` row on
    /// the lane before replying, so the irreversible transition commits under
    /// sole publication ownership exactly once.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] on unknown session, wrong principal, bad
    ///   secret, or a passed receipt horizon, with one shared error.
    /// - [`ErrorCode::ECapacity`] when loading the session needs a slot and
    ///   the live table is full.
    /// - [`ErrorCode::ELimit`] when admission sheds the latch publication.
    pub async fn resume_session(
        &self,
        principal: &Principal,
        args: &SessionResumeArgs,
        cancel: &Cancel,
    ) -> Result<SessionResumeReply, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let policy = self.policies.load()?;
        let idle = policy.session_idle();
        let times = self.clock.sample()?;
        let admitted = self.admit_control(cancel).await?;
        match self
            .sessions
            .resume(&self.store, args, principal, idle, times)?
        {
            ResumeOutcome::Active(_bound, reply) => Ok(reply),
            ResumeOutcome::ReceiptsOnly(_bound, reply) => Ok(reply),
            ResumeOutcome::NeedsLatch {
                session_id,
                current_row: _,
                latched_row,
                receipts_until,
            } => {
                let candidate = InternalCandidate::new(
                    InternalPayload::SessionExpireLatch {
                        id: session_id,
                        row: Arc::new(latched_row),
                        idle,
                    },
                    Vec::new(),
                    cancel.clone(),
                    Some(admitted),
                )?;
                self.lane.submit_internal(candidate).await?;
                Ok(SessionResumeReply {
                    session: session_id,
                    authority: SessionAuthority::ReceiptsOnly { receipts_until },
                    capabilities: Capabilities::default(),
                })
            }
        }
    }

    /// Submits one prepared mutation through admission and the lane.
    ///
    /// Loads the session, requires active authority, holds an in-flight guard
    /// across publication, admits the payload under the interactive storage
    /// class, validates the candidate digest and reply header, and publishes
    /// on the sole publication owner. Cancellation applies to admission, the
    /// candidate observer, and the lane wait alike.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EInvalid`] when the method is not a mutation or the
    ///   reply header mismatches the request.
    /// - [`ErrorCode::EForbidden`] on unknown session or expired authority.
    /// - [`ErrorCode::ELimit`] when admission sheds the submission or a fact
    ///   row exceeds the row bound.
    pub async fn submit_prepared(
        &self,
        prepared: PreparedMutation,
        cancel: &Cancel,
    ) -> Result<Reply, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        if !prepared.request.method().is_mutation() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "method `{}` is not a mutation",
                    prepared.request.method().as_str()
                ),
            ));
        }
        let policy = self.policies.load()?;
        let idle = policy.session_idle();
        let times = self.clock.sample()?;
        let live = self
            .sessions
            .get_or_load(&self.store, prepared.session, idle, times)?
            .ok_or_else(|| CoreError::new(ErrorCode::EForbidden, "unknown session"))?;
        if live.current_authority(&times) != Authority::Active {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session lacks active authority",
            ));
        }
        let bound = self.sessions.bind(&live)?;
        let _in_flight = bound.start_in_flight()?;
        let admitted = self
            .admission
            .admit(
                &self.repo,
                AdmissionRequest {
                    class: RequestClass::Interactive,
                    resources: WorkResources::Storage,
                    payload_bytes: prepared.payload_bytes()?,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
                cancel,
            )
            .await?;
        let fence = prepared
            .workspace_fence
            .map(|(id, stamp)| WorkspaceFence::new(id, stamp));
        let candidate = MutationCandidate::new(
            live,
            bound.row().principal.clone(),
            prepared.request_id,
            prepared.request,
            prepared.reply,
            prepared.objects,
            prepared.facts,
            fence,
            prepared.ref_transaction,
            prepared.ref_dependencies,
            cancel.clone(),
            Some(admitted),
        )?;
        self.lane.submit_mutation(candidate).await
    }

    /// Closes one session by latching it to receipts-only authority.
    ///
    /// A missing row or an already latched session succeeds without
    /// publication. An active session publishes the exact
    /// `expiry + 7d` transition the row lifecycle requires.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::ECorrupt`] when the stored session row is damaged.
    /// - [`ErrorCode::EInvalid`] on horizon arithmetic overflow.
    /// - [`ErrorCode::ELimit`] when admission sheds the latch publication.
    pub async fn close_session(
        &self,
        session: SessionId,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let key = session_key(session);
        let Some(bytes) = self.store.fact(FactTable::Sessions, &key)? else {
            return Ok(());
        };
        let row = decode_session(&self.store, &key, &bytes)?;
        let idle_expires_at = match row.authority {
            SessionAuthority::Active { idle_expires_at } => idle_expires_at,
            SessionAuthority::ReceiptsOnly { .. } => return Ok(()),
        };
        let horizon = idle_expires_at
            .instant()
            .checked_add(RECEIPT_HORIZON)
            .map_err(|err| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    format!("session receipts horizon overflow: {err}"),
                )
            })?;
        let receipts_until = Timestamp::new(horizon);
        let policy = self.policies.load()?;
        let idle = policy.session_idle();
        let latched = SessionRow {
            principal: row.principal,
            identity: row.identity,
            claims: row.claims,
            capabilities: row.capabilities,
            secret_hash: row.secret_hash,
            authority: SessionAuthority::ReceiptsOnly { receipts_until },
        };
        let admitted = self.admit_control(cancel).await?;
        let candidate = InternalCandidate::new(
            InternalPayload::SessionExpireLatch {
                id: session,
                row: Arc::new(latched),
                idle,
            },
            Vec::new(),
            cancel.clone(),
            Some(admitted),
        )?;
        self.lane.submit_internal(candidate).await?;
        Ok(())
    }

    async fn admit_control(&self, cancel: &Cancel) -> Result<Admitted, CoreError> {
        self.admission
            .admit(
                &self.repo,
                AdmissionRequest {
                    class: RequestClass::Control,
                    resources: WorkResources::Compute,
                    payload_bytes: 0,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
                cancel,
            )
            .await
    }
}
