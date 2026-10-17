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
use super::claims::{ClaimClock, authorize_claim_list_args, list_page_raw};
use super::clock::Clock;
use super::lane::{
    InternalCandidate, InternalPayload, MutationCandidate, PublicationLane, PublicationLaneRunner,
    WorkspaceFence, create_publication_lane,
};
use super::oplog::read_header;
use super::policy::PolicySource;
pub use super::policy::Principal;
use super::retention::{RetentionClock, SweepTable, sweep_page};
use super::rows::{
    CoordinatorHead, OP_HEAD_KEY, RECEIPT_HORIZON, SessionRow, decode_head, decode_session,
    session_key,
};
use super::session::{Authority, ResumeOutcome, SessionTable, prepare_open};
use crate::capability::{Capabilities, ReadAccess};
use crate::change::{OperationId, RequestId, SessionId, WorkspaceId};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    AttestListArgs, AttestListReply, ClaimListArgs, ClaimListReply, MAX_PAGE_SIZE, Method,
    OpLogArgs, OpLogReply, Page, PageLimit, ReconnectSecret, Reply, Request, SessionAuthority,
    SessionOpenArgs, SessionResumeArgs, SessionResumeReply, Timestamp, ViewInfo,
};
use crate::refdata::{RefName, RefTransaction};
use crate::store::FactPageBudget;
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
    retention_clock: RetentionClock,
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
        // The conservative pruning clock is process-local: one instance per
        // coordinator, anchored at the initial clock sample of this process.
        // A restart samples a fresh anchor; monotonic time never crosses it.
        let retention_clock = RetentionClock::new(clock.sample()?);
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
            retention_clock,
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
    /// - [`ErrorCode::EForbidden`] on unknown session, expired authority,
    ///   or a caller principal that is not the session holder.
    /// - [`ErrorCode::ELimit`] when admission sheds the submission or a fact
    ///   row exceeds the row bound.
    pub async fn submit_prepared(
        &self,
        caller: &Principal,
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
        if live.row().principal != *caller {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "caller is not the session holder",
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

    /// Serves one session-bound read without publishing anything.
    ///
    /// Loads the session, requires active authority, holds an in-flight guard
    /// across the read, admits it under the interactive class with compute
    /// resources, authorizes it against the session's negotiated capabilities,
    /// and runs the read implementation. `op.log`, `claim.list`, and
    /// `attest.list` have implementations; every other read runs the same
    /// session checks and then names its missing implementation with
    /// [`ErrorCode::EHosted`], so an unknown session still reports
    /// `E_FORBIDDEN` rather than a missing-impl error.
    ///
    /// Capability mapping follows the existing handlers rather than a
    /// blanket table: ordinary reads authorize as [`ReadAccess::Objects`],
    /// which always succeeds. `claim.list` additionally uses the claims
    /// module's listing authorization (a session always reads its own
    /// claims; anything wider needs `read_intents.claims`), and the
    /// attestation queries carry no capability gate of their own. Receipts
    /// of an expired session have no read path either: without one, expired
    /// authority is uniformly forbidden here instead of inventing a
    /// receipts-only read.
    ///
    /// `claim.list` and `attest.list` serve cursor-free first pages only.
    /// Page continuations arrive as lease-bound cursor values whose binding
    /// the coordinator cannot verify without a lease registry, and the
    /// coordinator holds none, so a presented cursor refuses with
    /// [`ErrorCode::EHosted`] naming the lease gap instead of inventing
    /// lease internals. A first page that does not exhaust its listing
    /// refuses with [`ErrorCode::ELimit`] rather than truncating, mirroring
    /// the single-page bound of [`read_oplog`].
    ///
    /// The caller principal must match the session holder, mirroring the
    /// resume path: `op.log` entries name session identities, so the
    /// session identity alone cannot be the credential or any reader could
    /// step into another holder's session. [`HostedCoordinator::submit_prepared`]
    /// enforces the same holder check at publication.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] on unknown session, expired authority,
    ///   or a caller principal that is not the session holder.
    /// - [`ErrorCode::EHosted`] when the method has no read implementation.
    /// - [`ErrorCode::ELimit`] when admission sheds the read or the log
    ///   exceeds its single-page bound.
    pub async fn read(
        &self,
        principal: &Principal,
        session: SessionId,
        request: Request,
        cancel: &Cancel,
    ) -> Result<Reply, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let policy = self.policies.load()?;
        let idle = policy.session_idle();
        let times = self.clock.sample()?;
        let live = self
            .sessions
            .get_or_load(&self.store, session, idle, times)?
            .ok_or_else(|| CoreError::new(ErrorCode::EForbidden, "unknown session"))?;
        if live.current_authority(&times) != Authority::Active {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session lacks active authority",
            ));
        }
        if live.row().principal != *principal {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "caller is not the session holder",
            ));
        }
        let bound = self.sessions.bind(&live)?;
        let _in_flight = bound.start_in_flight()?;
        let _admitted = self
            .admission
            .admit(
                &self.repo,
                AdmissionRequest {
                    class: RequestClass::Interactive,
                    resources: WorkResources::Compute,
                    payload_bytes: 0,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
                cancel,
            )
            .await?;
        bound.authorize_read(ReadAccess::Objects)?;
        match request {
            Request::OpLog(args) => Ok(Reply::OpLog(Box::new(read_oplog(&self.store, &args)?))),
            Request::ClaimList(args) => {
                let row = bound.row();
                let reply =
                    read_claims(&self.store, &self.clock, session, &row.capabilities, &args)?;
                Ok(Reply::ClaimList(Box::new(reply)))
            }
            Request::AttestList(args) => Ok(Reply::AttestList(Box::new(read_attestations(
                &self.store,
                &args,
            )?))),
            other => Err(CoreError::new(
                ErrorCode::EHosted,
                format!(
                    "method `{}` has no read implementation on the coordinator: {}",
                    other.method().as_str(),
                    read_gap(other.method()),
                ),
            )),
        }
    }

    /// Verifies one session for a caller before unauthenticated work.
    ///
    /// Loads the session, requires active authority, and requires the
    /// caller to hold it. The typed mutation path runs this before
    /// preparation so store-dependent preparation errors cannot answer
    /// callers with no session standing — any session-looking string
    /// parses, so preparation must not run on unknown or foreign
    /// sessions. [`HostedCoordinator::submit_prepared`] re-checks
    /// authoritatively at publication, so expiry between the two checks
    /// fails closed there.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] on unknown session, expired authority,
    ///   or a caller principal that is not the session holder.
    pub async fn check_session(
        &self,
        caller: &Principal,
        session: SessionId,
        cancel: &Cancel,
    ) -> Result<(), CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let policy = self.policies.load()?;
        let idle = policy.session_idle();
        let times = self.clock.sample()?;
        let live = self
            .sessions
            .get_or_load(&self.store, session, idle, times)?
            .ok_or_else(|| CoreError::new(ErrorCode::EForbidden, "unknown session"))?;
        if live.current_authority(&times) != Authority::Active {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session lacks active authority",
            ));
        }
        if live.row().principal != *caller {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "caller is not the session holder",
            ));
        }
        Ok(())
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

    async fn admit_maintenance(
        &self,
        payload_bytes: usize,
        cancel: &Cancel,
    ) -> Result<Admitted, CoreError> {
        self.admission
            .admit(
                &self.repo,
                AdmissionRequest {
                    class: RequestClass::Maintenance,
                    resources: WorkResources::Storage,
                    payload_bytes,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
                cancel,
            )
            .await
    }
}

/// Rows examined and rows deleted per sweepable table by one
/// [`HostedCoordinator::retention_sweep`] pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Receipt rows scanned in this pass.
    pub receipts_examined: usize,
    /// Expired receipt rows deleted through the lane in this pass.
    pub receipts_deleted: usize,
    /// Session rows scanned in this pass.
    pub sessions_examined: usize,
    /// Expired session rows deleted through the lane in this pass.
    pub sessions_deleted: usize,
}

impl RetentionReport {
    /// True when the pass deleted nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts_deleted == 0 && self.sessions_deleted == 0
    }
}

impl HostedCoordinator {
    /// Sweeps one bounded expiry page per sweepable table through the lane.
    ///
    /// Loads the persisted `head.sweep` cursors from the `OpHead` singleton
    /// (the same `decode_head` load path `read_oplog` uses; no second cursor
    /// store exists), evaluates `sweep_page` for receipts then sessions under
    /// the coordinator's conservative [`RetentionClock`], and publishes the
    /// exact-CAS deletions plus the merged next cursors as one
    /// `InternalPayload::Sweep` candidate admitted under
    /// [`RequestClass::Maintenance`]. The lane commit installs the cursors
    /// into `head.sweep` under sole publication ownership and adjusts the
    /// retention ledger through `apply_facts`.
    ///
    /// Idle passes (no deletions and cursors unchanged) skip lane publication
    /// entirely so the head row is not rewritten every interval.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EIo`] on clock sampling or pruning-time overflow.
    /// - [`ErrorCode::ECorrupt`] on malformed rows or ledger contradiction.
    /// - [`ErrorCode::ELimit`] when admission sheds the sweep or the first
    ///   row exceeds the sweep page byte budget.
    pub async fn retention_sweep(&self, cancel: &Cancel) -> Result<RetentionReport, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        let current = self.clock.sample()?;
        let now = self.retention_clock.now(&current)?;
        let loaded = match self.store.fact(FactTable::OpHead, OP_HEAD_KEY)? {
            Some(bytes) => decode_head(&self.store, &bytes)?,
            None => CoordinatorHead::default(),
        };
        let receipts_page = sweep_page(&self.store, SweepTable::Receipts, loaded.sweep, now)?;
        let sessions_page = sweep_page(
            &self.store,
            SweepTable::Sessions,
            receipts_page.cursors,
            now,
        )?;
        let report = RetentionReport {
            receipts_examined: receipts_page.examined_rows,
            receipts_deleted: receipts_page.deletions.len(),
            sessions_examined: sessions_page.examined_rows,
            sessions_deleted: sessions_page.deletions.len(),
        };
        if report.is_empty() && sessions_page.cursors == loaded.sweep {
            return Ok(report);
        }
        let mut facts = receipts_page.deletions;
        facts.extend(sessions_page.deletions);
        let mut payload_bytes: usize = 0;
        for fact in &facts {
            payload_bytes = payload_bytes.saturating_add(fact.key.len());
            payload_bytes = payload_bytes.saturating_add(fact.value.as_ref().map_or(0, Vec::len));
        }
        let admitted = self.admit_maintenance(payload_bytes, cancel).await?;
        let candidate = InternalCandidate::new(
            InternalPayload::Sweep {
                cursors: sessions_page.cursors,
            },
            facts,
            cancel.clone(),
            Some(admitted),
        )?;
        self.lane.submit_internal(candidate).await?;
        Ok(report)
    }
}

/// Names the missing read path of one uncovered method for its refusal.
///
/// Every arm names the absent producer rather than gesturing at coverage,
/// so a caller learns which machinery would serve the method.
fn read_gap(method: Method) -> &'static str {
    match method {
        Method::Status => {
            "status needs a workspace autosnapshot plus a workcopy crawl, and the read path publishes nothing"
        }
        Method::Log | Method::Query => {
            "log and query need a production graph index over store segments, and revset evaluation builds its graph only in tests"
        }
        Method::Diff | Method::Show | Method::File | Method::Blame => {
            "diff, show, file, and blame need tree and object readers over resolved revisions with no pure producer on the coordinator"
        }
        _ => "only `op.log`, `claim.list`, and `attest.list` first pages are served",
    }
}

/// Loads the store and operation snapshot one read is served from.
///
/// Mirrors the head load of [`read_oplog`] so every read reports the same
/// view of the same head.
///
/// # Errors
/// `E_CORRUPT` for a damaged head row.
fn current_view(store: &Store) -> Result<ViewInfo, CoreError> {
    let head = match store.fact(FactTable::OpHead, OP_HEAD_KEY)? {
        Some(bytes) => decode_head(store, &bytes)?,
        None => CoordinatorHead::default(),
    };
    Ok(ViewInfo {
        store: store.store_id(),
        view: head.last_op.unwrap_or(OperationId(0)),
    })
}

/// Reads the first page of one authorized claim listing.
///
/// The caller authorizes `args` first with [`authorize_claim_list_args`];
/// this runs the raw store scan without minting or verifying any
/// lease-bound cursor. A presented cursor refuses with `E_HOSTED`
/// naming the lease gap, and a first page that does not exhaust its listing
/// refuses with `E_LIMIT` rather than truncating.
///
/// # Errors
/// `E_HOSTED` for a presented cursor (no lease registry verifies its
/// binding); `E_LIMIT` past the single-page bound; `E_CORRUPT` for a claim
/// row disagreeing with its index.
fn read_claims(
    store: &Store,
    clock: &Clock,
    viewer: SessionId,
    caps: &Capabilities,
    args: &ClaimListArgs,
) -> Result<ClaimListReply, CoreError> {
    if args.page.cursor.is_some() {
        return Err(CoreError::new(
            ErrorCode::EHosted,
            "claim.list continuation needs a lease-bound cursor and the hosted coordinator holds no lease registry: open a fresh first page instead",
        ));
    }
    let listing = authorize_claim_list_args(caps, viewer, args)?;
    let claim_clock = ClaimClock::open(store, clock.clone())?;
    let limit = args.page.effective_limit();
    let page = list_page_raw(
        store,
        &claim_clock,
        listing,
        None,
        FactPageBudget::new(limit, 1024 * 1024),
    )?;
    if page.next.is_some() {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "claim.list exceeds its single-page bound and continuations need a lease-bound cursor the hosted coordinator does not mint",
        ));
    }
    // The view loads after the scan, never before: a concurrent publication
    // may then date the reply newer than its rows (ordinary staleness), but
    // the rows can never come from a snapshot newer than the reported view.
    let view = current_view(store)?;
    Ok(ClaimListReply {
        view,
        claims: Page::new(page.records, None)?,
    })
}

/// Reads the first page of attestation statements matching `args`.
///
/// Runs the bounded attestation query with an open checkpoint: the read
/// already passed admission, so no progress gate applies. Cursor and
/// exhaustion handling mirror [`read_claims`]: no lease registry verifies a
/// presented cursor, and a non-exhausting first page refuses rather than
/// truncating.
///
/// # Errors
/// `E_HOSTED` for a presented cursor (no lease registry verifies its
/// binding); `E_LIMIT` past the single-page bound or the verification
/// budget; `E_CORRUPT` for a row that fails re-verification.
fn read_attestations(store: &Store, args: &AttestListArgs) -> Result<AttestListReply, CoreError> {
    if args.page.cursor.is_some() {
        return Err(CoreError::new(
            ErrorCode::EHosted,
            "attest.list continuation needs a lease-bound cursor and the hosted coordinator holds no lease registry: open a fresh first page instead",
        ));
    }
    let filter = crate::attestation::StatementFilter {
        subject: args.subject,
        kind: args.kind.clone(),
        signer: args.signer.clone(),
        include_superseded: args.include_superseded,
    };
    let limit_rows = u32::try_from(args.page.effective_limit())
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "page limit exceeds its bound"))?;
    let limit = PageLimit::new(limit_rows).map_err(CoreError::from)?;
    let open = |_: crate::attestation::Progress| Ok::<(), CoreError>(());
    let page = crate::attestation::list(store, &filter, limit, None, &open)?;
    if page.next.is_some() {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "attest.list exceeds its single-page bound and continuations need a lease-bound cursor the hosted coordinator does not mint",
        ));
    }
    // The view loads after the scan, never before: see `read_claims` for why
    // this order keeps rows committed at or before the reported view.
    let view = current_view(store)?;
    Ok(AttestListReply {
        view,
        records: Page::new(page.records, None)?,
    })
}

/// Reads the operation log newest-first from the coordinator head.
///
/// Walks the parent chain from the last operation, keeping every entry whose
/// session matches the filter. The walk ends at a missing header, which
/// marks the retention boundary. There is no paging on this path, so a log
/// longer than one page is refused rather than truncated.
///
/// # Errors
/// `E_CORRUPT` for a damaged head or header row; `E_LIMIT` past the
/// single-page bound.
fn read_oplog(store: &Store, args: &OpLogArgs) -> Result<OpLogReply, CoreError> {
    let head = match store.fact(FactTable::OpHead, OP_HEAD_KEY)? {
        Some(bytes) => decode_head(store, &bytes)?,
        None => CoordinatorHead::default(),
    };
    let mut entries = Vec::new();
    let mut oldest = None;
    let mut cursor = head.last_op;
    let mut visited = 0usize;
    while let Some(id) = cursor {
        visited += 1;
        if visited > MAX_PAGE_SIZE {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "operation log exceeds its single-page bound and has no paging on this path",
            ));
        }
        let Some(header) = read_header(store, id)? else {
            break;
        };
        let entry = header.entry;
        oldest = Some(id);
        cursor = entry.parent;
        if args.session.is_none_or(|want| entry.session == Some(want)) {
            entries.push(entry);
        }
    }
    Ok(OpLogReply {
        view: ViewInfo {
            store: store.store_id(),
            view: head.last_op.unwrap_or(OperationId(0)),
        },
        oldest_retained: oldest,
        entries: Page::new(entries, None)?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::ByteString;
    use crate::change::{LeaseId, RequestId, StoreId};
    use crate::commit::ProvenanceClaims;
    use crate::coord::rows::{Retained, SweepCursors, Usage, encode};
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::protocol::{
        AttestListArgs, ClaimHolderFilter, ClaimListArgs, Method, Mutation as WireMutation,
        OpLogArgs, PageCursor, PageRequest, PinArgs, QueryDigest, StatusArgs, TagSetArgs,
    };
    use crate::refdata::{RefExpect, RefName};
    use crate::store::PreparationBudget;
    use crate::store::types::FactExpectation;

    static SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |e| e.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-hosted-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn coordinator() -> (TempRoot, HostedCoordinator, Principal) {
        let temp = TempRoot::new("read");
        let store = Arc::new(
            Store::create(
                &temp.0,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create store"),
        );
        let owner = Principal::from_peer_uid(1000);
        let coord = HostedCoordinator::open(store, owner.clone(), temp.0.clone())
            .expect("open coordinator");
        (temp, coord, owner)
    }

    fn stranger() -> Principal {
        Principal::from_peer_uid(2000)
    }

    fn presented_cursor() -> PageCursor {
        PageCursor {
            store: StoreId::generate(),
            view: OperationId(0),
            query: QueryDigest::from_bytes([0x11; 32]),
            lease: LeaseId::generate(),
            position: ByteString::from(Vec::new()),
        }
    }

    #[tokio::test]
    async fn session_bound_read_serves_covered_first_pages_and_refuses_the_rest() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");

        let reply = coord
            .read(
                &owner,
                session,
                Request::OpLog(Box::new(OpLogArgs::default())),
                &cancel,
            )
            .await
            .expect("op.log reads");
        let Reply::OpLog(page) = reply else {
            panic!("op.log must answer its own reply");
        };
        assert!(page.entries.items.is_empty());

        let err = coord
            .read(
                &owner,
                SessionId::generate(),
                Request::OpLog(Box::new(OpLogArgs::default())),
                &cancel,
            )
            .await
            .expect_err("unknown session is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);

        let err = coord
            .read(
                &stranger(),
                session,
                Request::OpLog(Box::new(OpLogArgs::default())),
                &cancel,
            )
            .await
            .expect_err("foreign principal is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);

        coord
            .check_session(&owner, session, &cancel)
            .await
            .expect("holder session verifies");
        let err = coord
            .check_session(&stranger(), session, &cancel)
            .await
            .expect_err("foreign holder fails verification");
        assert_eq!(err.code, ErrorCode::EForbidden);
        let err = coord
            .check_session(&owner, SessionId::generate(), &cancel)
            .await
            .expect_err("unknown session fails verification");
        assert_eq!(err.code, ErrorCode::EForbidden);

        let reply = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs::default())),
                &cancel,
            )
            .await
            .expect("claim.list serves its first page");
        let Reply::ClaimList(list) = reply else {
            panic!("claim.list must answer its own reply");
        };
        assert!(list.claims.items.is_empty());
        assert!(list.claims.next.is_none());
        assert_eq!(list.view, page.view);

        let reply = coord
            .read(
                &owner,
                session,
                Request::AttestList(Box::new(AttestListArgs::default())),
                &cancel,
            )
            .await
            .expect("attest.list serves its first page");
        let Reply::AttestList(attest) = reply else {
            panic!("attest.list must answer its own reply");
        };
        assert!(attest.records.items.is_empty());
        assert!(attest.records.next.is_none());
        assert_eq!(attest.view, page.view);

        // The owner session carries the full ceiling, so `Any` answers here;
        // the forbidden path needs a session that negotiated the flag away.
        let (restricted, _) = coord
            .open_session(
                &owner,
                &SessionOpenArgs {
                    capabilities: Some(Capabilities {
                        read_intents: crate::capability::ReadIntents {
                            provenance: false,
                            claims: false,
                        },
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                &cancel,
            )
            .await
            .expect("open restricted session");

        let err = coord
            .read(
                &owner,
                restricted,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Any,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("claim.list for every holder needs read_intents.claims");
        assert_eq!(err.code, ErrorCode::EForbidden);

        coord
            .read(
                &owner,
                restricted,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect("a session always lists its own claims");

        let err = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: None,
                        cursor: Some(presented_cursor()),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("claim.list continuation names the lease gap");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("lease"),
            "unexpected message: {}",
            err.message
        );

        let err = coord
            .read(
                &owner,
                session,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: None,
                        cursor: Some(presented_cursor()),
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect_err("attest.list continuation names the lease gap");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("lease"),
            "unexpected message: {}",
            err.message
        );

        let err = coord
            .read(
                &owner,
                session,
                Request::Status(Box::new(StatusArgs::default())),
                &cancel,
            )
            .await
            .expect_err("status names its missing implementation");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("autosnapshot"),
            "unexpected message: {}",
            err.message
        );

        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn retention_sweep_deletes_expired_session_through_the_lane() {
        let (_temp, coord, _) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();

        // Fabricate one ReceiptsOnly session row already past its horizon.
        // The fixed id sorts after the stale cursor below, so the sweep page
        // must examine it rather than skip past it.
        let session = SessionId::from_bytes([0xAA; 16]);
        let past = Timestamp::new(
            jiff::Timestamp::now()
                .checked_sub(jiff::SignedDuration::from_hours(1))
                .expect("past horizon"),
        );
        let row = SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity: None,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0x55; 32],
            authority: SessionAuthority::ReceiptsOnly {
                receipts_until: past,
            },
        };
        let key = session_key(session);
        let encoded = encode("session row", &row).expect("encode session");
        // The direct store seeding below bypasses the lane, so the seeded
        // head must carry the matching ledger: one session row of
        // `key.len() + encoded.len()` stored bytes. Otherwise the lane's
        // `apply_facts` would report the sweep deletion as ledger underflow.
        // 16-byte key plus one small row: far below u64 range on any target.
        let stored_bytes =
            u64::try_from(key.len() + encoded.len()).expect("session row size fits u64");
        let seeded = CoordinatorHead {
            last_op: None,
            retained: Retained {
                receipts: Usage::default(),
                sessions: Usage {
                    rows: 1,
                    stored_bytes,
                },
                ops: Usage::default(),
            },
            sweep: SweepCursors {
                receipts: None,
                sessions: Some([0x00; 16]),
            },
        };
        let encoded_head = encode("coordinator head", &seeded).expect("encode head");
        coord
            .store()
            .publish(
                Vec::new(),
                &[
                    FactMutation {
                        table: FactTable::Sessions,
                        key: key.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(encoded.clone()),
                    },
                    FactMutation {
                        table: FactTable::OpHead,
                        key: OP_HEAD_KEY.to_vec(),
                        expected: FactExpectation::Absent,
                        value: Some(encoded_head),
                    },
                ],
            )
            .expect("seed expired session and ledger");

        let report = coord
            .retention_sweep(&cancel)
            .await
            .expect("sweep publishes through the lane");
        assert_eq!(report.receipts_examined, 0);
        assert_eq!(report.receipts_deleted, 0);
        assert_eq!(report.sessions_examined, 1);
        assert_eq!(report.sessions_deleted, 1);

        assert!(
            coord
                .store()
                .fact(FactTable::Sessions, &key)
                .expect("read session")
                .is_none(),
            "expired session row must delete through the lane, not a direct publish"
        );
        let head_bytes = coord
            .store()
            .fact(FactTable::OpHead, OP_HEAD_KEY)
            .expect("read head")
            .expect("head row");
        let head = decode_head(coord.store(), &head_bytes).expect("decode head");
        assert_eq!(
            head.sweep.sessions, None,
            "stale cursor must persist as drained through the lane"
        );
        assert_eq!(
            head.retained.sessions,
            Usage::default(),
            "ledger must return to empty after the sweep deletion"
        );

        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn prepared_ref_mutation_publishes_and_logs() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");

        let request_id = RequestId::generate();
        let prepared = super::super::prepare_mutation(
            coord.store(),
            session,
            Request::TagSet(Box::new(WireMutation {
                request_id,
                args: TagSetArgs {
                    name: RefName::new("refs/tags/v1").expect("tag name"),
                    target: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
                    annotation: None,
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("tag.set prepares");
        let reply = coord
            .submit_prepared(&owner, prepared, &cancel)
            .await
            .expect("tag.set publishes");
        assert_eq!(reply.method(), Method::TagSet);

        let pin = Request::Pin(Box::new(WireMutation {
            request_id: RequestId::generate(),
            args: PinArgs {
                head: Head::Git {
                    oid: Oid::from_bytes(&[0x11; 20]).expect("pin target"),
                },
            },
        }));
        let err = super::super::prepare_mutation(coord.store(), session, pin)
            .expect_err("pin stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);

        let foreign = super::super::prepare_mutation(
            coord.store(),
            session,
            Request::TagSet(Box::new(WireMutation {
                request_id: RequestId::generate(),
                args: TagSetArgs {
                    name: RefName::new("refs/tags/v2").expect("tag name"),
                    target: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
                    annotation: None,
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("second tag prepares");
        let err = coord
            .submit_prepared(&stranger(), foreign, &cancel)
            .await
            .expect_err("foreign submitter is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);

        let reply = coord
            .read(
                &owner,
                session,
                Request::OpLog(Box::new(OpLogArgs::default())),
                &cancel,
            )
            .await
            .expect("op.log reads after mutation");
        let Reply::OpLog(page) = reply else {
            panic!("op.log must answer its own reply");
        };
        assert_eq!(page.entries.items.len(), 1);
        assert_eq!(page.entries.items[0].method, Method::TagSet);
        assert_eq!(page.oldest_retained, Some(page.entries.items[0].id));

        coord.shutdown();
        let _ = runner.abort();
    }
}
