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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant as StdInstant;

use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::admission::{
    Admission, AdmissionLimits, AdmissionRequest, Admitted, RepoAdmission, RequestClass,
    WorkResources, run_blocking,
};
pub use super::cancel::{Cancel, CancelHandle, cancellation};
use super::claims::{
    ClaimClock, LeasedClaimPage, authorize_claim_list_args, list_page, list_page_raw,
    next_claim_cursor,
};
use super::clock::Clock;
use super::lane::{
    InternalCandidate, InternalPayload, MutationCandidate, PublicationLane, PublicationLaneRunner,
    WorkspaceFence, create_publication_lane,
};
use super::leases::{
    AcquireArgs, CursorWant, INTERACTIVE_TTL, LeaseKind, LeaseRegistry, OwnerGuard,
};
use super::oplog::read_header;
use super::policy::PolicySource;
pub use super::policy::Principal;
use super::prepare::{PrepareContext, prepare_mutation_with};
use super::receipt;
use super::retention::{RetentionClock, SweepTable, sweep_page};
use super::rows::{
    CoordinatorHead, OP_HEAD_KEY, RECEIPT_HORIZON, SessionRow, decode_head, decode_session,
    session_key,
};
use super::session::{Authority, ResumeOutcome, SessionTable, prepare_open};
use crate::ByteString;
use crate::attestation::Checkpoint;
use crate::capability::{Capabilities, ReadAccess};
use crate::change::{LeaseId, OperationId, RequestId, SessionId, WorkspaceId};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    AttestListArgs, AttestListReply, ClaimHolderFilter, ClaimListArgs, ClaimListReply,
    MAX_PAGE_SIZE, Method, OpLogArgs, OpLogReply, Page, PageCursor, PageLimit, QueryDigest,
    ReconnectSecret, Reply, Request, SessionAuthority, SessionOpenArgs, SessionResumeArgs,
    SessionResumeReply, Timestamp, ViewInfo,
};
use crate::refdata::{RefName, RefTransaction};
use crate::store::CompactionStats;
use crate::store::FactPageBudget;
use crate::store::Store;
use crate::store::types::{FactMutation, FactTable, PreparedObject};
use crate::workspace::WorkspaceStamp;

/// What [`HostedCoordinator::prepare_for_dispatch`] returns: either the stored
/// reply for a request that committed before, or fresh lane parts for a new one.
#[derive(Debug)]
pub enum DispatchReady {
    /// The `(session, request_id)` committed before; serve the stored reply
    /// without preparing or publishing anything.
    Replay(Reply),
    /// A new request, translated into lane parts for submission.
    Prepared(PreparedMutation),
}

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
    leases: Arc<LeaseRegistry>,
    page_guards: Mutex<HashMap<LeaseId, (OwnerGuard, StdInstant)>>,
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
        // Read leases live in memory only: the registry pairs a bounded lease
        // table with the collection barrier, spilling condemned scratch under
        // the repository root. Interactive read leases carry no object roots,
        // so the scratch directory is only a path until collection runs.
        let leases = LeaseRegistry::new(clock.clone(), store_root.join("leases-scratch"));
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
            leases,
            page_guards: Mutex::new(HashMap::new()),
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

    /// Prepares one mutation with the full coordinator context, replaying a
    /// stored reply when the request committed before.
    ///
    /// Consults the receipt ledger before translating: a client retrying the
    /// same `(session, request_id)` after a lost reply gets the stored reply,
    /// because preparation re-runs translation against current state — which
    /// already reflects the committed attempt — and would otherwise fail the
    /// retry with `E_STALE` or `E_INVALID` before the lane's own receipt
    /// lookup runs. A reused id with different arguments refuses with
    /// `E_REQUEST_REUSED` here as well.
    ///
    /// Loads the session row and runs the per-method translation with the
    /// coordinator clock and the caller's attestation gate, so ref/data
    /// methods that need identity, time, or verification can prepare. The
    /// socket dispatch path calls this with a cancellation-aware
    /// `checkpoint`; arms whose required input is absent (an unknown
    /// session has no row) refuse honestly, and
    /// [`HostedCoordinator::submit_prepared`] still enforces session
    /// authority and holder binding afterwards.
    ///
    /// Policy and the claim clock stay out of this path until a prepared
    /// arm consumes them: loading them here would fail long-covered
    /// mutations on policy or clock rows those arms never read.
    ///
    /// # Errors
    /// - [`ErrorCode::ERequestReused`] when the request id committed before
    ///   with different arguments.
    /// - [`ErrorCode::EInvalid`] when the request is not a mutation.
    /// - [`ErrorCode::EHosted`] when the method has no preparation on this
    ///   path, or its required context input is absent.
    /// - [`ErrorCode::EStale`], [`ErrorCode::ENotFound`],
    ///   [`ErrorCode::EDivergent`], or [`ErrorCode::EForbidden`] from the
    ///   per-method translation.
    /// - Store errors from the session-row read.
    pub fn prepare_for_dispatch(
        &self,
        session: SessionId,
        request: Request,
        checkpoint: &Checkpoint<'_>,
    ) -> Result<DispatchReady, CoreError> {
        let wall = self.clock.sample()?.wall;
        if let Some(reply) = receipt::replay_if_committed(&self.store, session, &request, wall)? {
            return Ok(DispatchReady::Replay(reply));
        }
        let key = session_key(session);
        let session_row = self
            .store
            .fact(FactTable::Sessions, &key)?
            .map(|bytes| decode_session(&self.store, &key, &bytes))
            .transpose()?;
        let ctx = PrepareContext {
            store: &self.store,
            session,
            session_row: session_row.as_ref(),
            clock: Some(&self.clock),
            claim_clock: None,
            policy: None,
            checkpoint: Some(checkpoint),
        };
        prepare_mutation_with(&ctx, request).map(DispatchReady::Prepared)
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
    /// waits. In-flight batches still settle under sole publication ownership
    /// (each batch commits under its own uncancelled token), and queued
    /// submissions drain before the runner returns. The store handle retires
    /// when the runner exits (the runner closes it after the drain commits
    /// the final batch), never here: closing before the drain would retire
    /// the handle while drained batches can still append. Every committed
    /// byte was already synced by its publication, so the retirement flush
    /// reports nothing new and the next open truncates any uncommitted tail
    /// during recovery.
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
    /// `claim.list`, `attest.list`, and `op.log` page through interactive
    /// read leases. A first page that does not exhaust its listing mints a
    /// 30-second lease-bound cursor instead of truncating; a presented
    /// cursor resumes at its opaque position only when the lease exists, is
    /// held by the requesting session, and matches the store, the current
    /// view, and the query digest. Binding mismatch is `E_FORBIDDEN`;
    /// unknown, retired, or expired authority is `E_LEASE_LOST`. A head that
    /// advanced since the first page makes the continuation stale
    /// (`E_FORBIDDEN`): the client restarts from a fresh first page.
    ///
    /// The caller principal must match the session holder, mirroring the
    /// resume path: `op.log` entries name session identities, so the
    /// session identity alone cannot be the credential or any reader could
    /// step into another holder's session. [`HostedCoordinator::submit_prepared`]
    /// enforces the same holder check at publication.
    ///
    /// # Errors
    /// - [`ErrorCode::EInvalid`] when the request shape is invalid; checked
    ///   before any session or lease work so malformed paging beats
    ///   `E_FORBIDDEN` and `E_LEASE_LOST`.
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] on unknown session, expired authority,
    ///   a caller principal that is not the session holder, a cursor binding
    ///   mismatch, or a stale view.
    /// - [`ErrorCode::ELeaseLost`] when the cursor names an unknown,
    ///   retired, or expired lease.
    /// - [`ErrorCode::EHosted`] when the method has no read implementation.
    /// - [`ErrorCode::ELimit`] when admission sheds the read.
    pub async fn read(
        &self,
        principal: &Principal,
        session: SessionId,
        request: Request,
        cancel: &Cancel,
    ) -> Result<Reply, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        // Protocol shape first: an oversized cursor position or an illegal
        // limit reports E_INVALID before any session or lease verdict.
        request.validate()?;
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
        // Expire read leases at entry: fire cancellation on lapsed authority
        // and drop the guards whose 30-second interactive lifetime ended so
        // the bounded table cannot fill with dead slots.
        self.leases.sweep_expiry()?;
        self.prune_expired_read_leases(times.mono)?;
        match request {
            Request::OpLog(args) => {
                let reply = self.read_oplog_page(session, &args, times.mono)?;
                Ok(Reply::OpLog(Box::new(reply)))
            }
            Request::ClaimList(args) => {
                let row = bound.row();
                let reply = self.read_claims_page(session, &row.capabilities, &args, times.mono)?;
                Ok(Reply::ClaimList(Box::new(reply)))
            }
            Request::AttestList(args) => {
                let reply = self.read_attestations_page(session, &args, times.mono)?;
                Ok(Reply::AttestList(Box::new(reply)))
            }
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

    /// Mints one interactive read lease and retains its owner guard.
    ///
    /// The guard lives in `page_guards` until its 30-second authority lapses
    /// and a read entry or retention sweep prunes it. Dropping the guard
    /// retires the slot, so continuations stay usable across requests until
    /// expiry instead of dying with the first reply.
    fn mint_read_lease(
        &self,
        session: SessionId,
        view: OperationId,
        query: QueryDigest,
        position: &[u8],
        now: StdInstant,
    ) -> Result<PageCursor, CoreError> {
        let store_id = self.store.store_id();
        let op_floor = (view.0 != 0).then_some(view);
        let args = AcquireArgs {
            kind: LeaseKind::Interactive,
            store: store_id,
            session,
            view,
            query,
            roots: Vec::new(),
            op_floor,
            position_bytes: position.len(),
            view_retained: true,
        };
        let (lease, _cancel, guard) = self.leases.acquire(args, now)?;
        let cursor = PageCursor {
            store: store_id,
            view,
            query,
            lease,
            position: ByteString::from(position.to_vec()),
        };
        self.page_guards
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "read lease guard lock poisoned"))?
            .insert(lease, (guard, now));
        Ok(cursor)
    }

    /// Drops read guards whose interactive authority lapsed.
    ///
    /// Returns live guards inspected and guards dropped. The registry sweep
    /// fires cancellation first; this only retires the slots so the bounded
    /// table cannot fill with dead entries. There is no durable leases
    /// table to publish through.
    fn prune_expired_read_leases(&self, now: StdInstant) -> Result<(usize, usize), CoreError> {
        let mut guards = self
            .page_guards
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "read lease guard lock poisoned"))?;
        let examined = guards.len();
        if examined == 0 {
            return Ok((0, 0));
        }
        let mut lapsed = Vec::new();
        for (id, (_, created)) in guards.iter() {
            let elapsed = now.checked_duration_since(*created);
            if elapsed.is_some_and(|held| held >= INTERACTIVE_TTL) {
                lapsed.push(*id);
            }
        }
        let count = lapsed.len();
        for id in lapsed {
            guards.remove(&id);
        }
        Ok((examined, count))
    }

    /// Reads one claim page, minting a lease-bound cursor when more remains.
    fn read_claims_page(
        &self,
        viewer: SessionId,
        caps: &Capabilities,
        args: &ClaimListArgs,
        now: StdInstant,
    ) -> Result<ClaimListReply, CoreError> {
        let listing = authorize_claim_list_args(caps, viewer, args)?;
        let query = claim_query_digest(args.holder);
        let limit = args.page.effective_limit();
        let budget = FactPageBudget::new(limit, 1024 * 1024);
        let Some(cursor) = args.page.cursor.as_ref() else {
            let claim_clock = ClaimClock::open(&self.store, self.clock.clone())?;
            let page = list_page_raw(&self.store, &claim_clock, listing, None, budget)?;
            let view = current_view(&self.store)?;
            let Some(position) = page.next else {
                return Ok(ClaimListReply {
                    view,
                    claims: Page::new(page.records, None)?,
                });
            };
            let next = self.mint_read_lease(viewer, view.view, query, &position, now)?;
            return Ok(ClaimListReply {
                view,
                claims: Page::new(page.records, Some(next))?,
            });
        };
        let view_before = current_view(&self.store)?;
        let want = CursorWant {
            store: self.store.store_id(),
            session: viewer,
            view: view_before.view,
            query,
        };
        let claim_clock = ClaimClock::open(&self.store, self.clock.clone())?;
        let (page, _binding) = list_page(LeasedClaimPage {
            store: &self.store,
            clock: &claim_clock,
            leases: &self.leases,
            listing,
            cursor,
            want: &want,
            now,
            budget,
        })?;
        let view_after = current_view(&self.store)?;
        if view_after.view != cursor.view {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "claim.list cursor names a stale view: open a fresh first page",
            ));
        }
        let next = next_claim_cursor(cursor, page.next);
        Ok(ClaimListReply {
            view: view_after,
            claims: Page::new(page.records, next)?,
        })
    }

    /// Reads one attestation page, minting a lease-bound cursor when more remains.
    fn read_attestations_page(
        &self,
        viewer: SessionId,
        args: &AttestListArgs,
        now: StdInstant,
    ) -> Result<AttestListReply, CoreError> {
        let query = attest_query_digest(args);
        let limit = args.page.effective_limit();
        let limit_rows = u32::try_from(limit)
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "page limit exceeds its bound"))?;
        let limit_page = PageLimit::new(limit_rows).map_err(CoreError::from)?;
        let filter = crate::attestation::StatementFilter {
            subject: args.subject,
            kind: args.kind.clone(),
            signer: args.signer.clone(),
            include_superseded: args.include_superseded,
        };
        let open = |_: crate::attestation::Progress| Ok::<(), CoreError>(());
        let Some(cursor) = args.page.cursor.as_ref() else {
            let page = crate::attestation::list(&self.store, &filter, limit_page, None, &open)?;
            let view = current_view(&self.store)?;
            let Some(position) = page.next else {
                return Ok(AttestListReply {
                    view,
                    records: Page::new(page.records, None)?,
                });
            };
            let next = self.mint_read_lease(viewer, view.view, query, &position, now)?;
            return Ok(AttestListReply {
                view,
                records: Page::new(page.records, Some(next))?,
            });
        };
        let view_before = current_view(&self.store)?;
        let want = CursorWant {
            store: self.store.store_id(),
            session: viewer,
            view: view_before.view,
            query,
        };
        self.leases.check_cursor(cursor, &want, now)?;
        let page = crate::attestation::list(
            &self.store,
            &filter,
            limit_page,
            Some(cursor.position.as_bytes()),
            &open,
        )?;
        let view_after = current_view(&self.store)?;
        if view_after.view != cursor.view {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "attest.list cursor names a stale view: open a fresh first page",
            ));
        }
        let Some(position) = page.next else {
            return Ok(AttestListReply {
                view: view_after,
                records: Page::new(page.records, None)?,
            });
        };
        let next = PageCursor {
            store: cursor.store,
            view: cursor.view,
            query: cursor.query,
            lease: cursor.lease,
            position: ByteString::from(position),
        };
        Ok(AttestListReply {
            view: view_after,
            records: Page::new(page.records, Some(next))?,
        })
    }

    /// Reads one operation-log page newest-first, paging through a lease.
    fn read_oplog_page(
        &self,
        viewer: SessionId,
        args: &OpLogArgs,
        now: StdInstant,
    ) -> Result<OpLogReply, CoreError> {
        let query = oplog_query_digest(args.session);
        let limit = args.page.effective_limit();
        let Some(cursor) = args.page.cursor.as_ref() else {
            let head = match self.store.fact(FactTable::OpHead, OP_HEAD_KEY)? {
                Some(bytes) => decode_head(&self.store, &bytes)?,
                None => CoordinatorHead::default(),
            };
            let view = ViewInfo {
                store: self.store.store_id(),
                view: head.last_op.unwrap_or(OperationId(0)),
            };
            let (entries, next_id, oldest, exhausted) =
                walk_oplog_page(&self.store, head.last_op, args.session, limit)?;
            if exhausted {
                return Ok(OpLogReply {
                    view,
                    oldest_retained: oldest,
                    entries: Page::new(entries, None)?,
                });
            }
            let position =
                encode_oplog_position(next_id.expect("non-exhausted page has a resume id"));
            let next = self.mint_read_lease(viewer, view.view, query, &position, now)?;
            return Ok(OpLogReply {
                view,
                oldest_retained: None,
                entries: Page::new(entries, Some(next))?,
            });
        };
        // Malformed positions stay E_INVALID even against a dead lease.
        if cursor.position.len() != 8 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "op.log continuation position must be 8 bytes",
            ));
        }
        let start = decode_oplog_position(cursor.position.as_bytes())?;
        let view_before = current_view(&self.store)?;
        let want = CursorWant {
            store: self.store.store_id(),
            session: viewer,
            view: view_before.view,
            query,
        };
        self.leases.check_cursor(cursor, &want, now)?;
        let (entries, next_id, oldest, exhausted) =
            walk_oplog_page(&self.store, Some(start), args.session, limit)?;
        if exhausted && entries.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "op.log continuation position was pruned: open a fresh first page",
            ));
        }
        let view_after = current_view(&self.store)?;
        if view_after.view != cursor.view {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "op.log cursor names a stale view: open a fresh first page",
            ));
        }
        if exhausted {
            return Ok(OpLogReply {
                view: view_after,
                oldest_retained: oldest,
                entries: Page::new(entries, None)?,
            });
        }
        let position = encode_oplog_position(next_id.expect("non-exhausted page has a resume id"));
        let next = PageCursor {
            store: cursor.store,
            view: cursor.view,
            query: cursor.query,
            lease: cursor.lease,
            position: ByteString::from(position),
        };
        Ok(OpLogReply {
            view: view_after,
            oldest_retained: None,
            entries: Page::new(entries, Some(next))?,
        })
    }
}

fn claim_query_digest(holder: ClaimHolderFilter) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ruk.claim.list/v1\x00");
    match holder {
        ClaimHolderFilter::Mine => hasher.update([0x00]),
        ClaimHolderFilter::Any => hasher.update([0x01]),
    }
    QueryDigest::from_bytes(hasher.finalize().into())
}

fn attest_query_digest(args: &AttestListArgs) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ruk.attest.list/v1\x00");
    match args.subject {
        None => hasher.update([0x00]),
        Some(oid) => {
            hasher.update([0x01]);
            let width = u8::try_from(oid.as_bytes().len()).unwrap_or(0xFF);
            hasher.update([width]);
            hasher.update(oid.as_bytes());
        }
    }
    match args.kind.as_ref() {
        None => hasher.update([0x00]),
        Some(kind) => {
            hasher.update([0x01]);
            hasher.update(kind.as_str().as_bytes());
            hasher.update([0x00]);
        }
    }
    match args.signer.as_ref() {
        None => hasher.update([0x00]),
        Some(signer) => {
            hasher.update([0x01]);
            hasher.update(signer.as_str().as_bytes());
            hasher.update([0x00]);
        }
    }
    hasher.update([u8::from(args.include_superseded)]);
    QueryDigest::from_bytes(hasher.finalize().into())
}

fn oplog_query_digest(session: Option<SessionId>) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ruk.op.log/v1\x00");
    match session {
        None => hasher.update([0x00]),
        Some(id) => {
            hasher.update([0x01]);
            hasher.update(id.as_bytes());
        }
    }
    QueryDigest::from_bytes(hasher.finalize().into())
}

fn encode_oplog_position(id: OperationId) -> Vec<u8> {
    id.0.to_be_bytes().to_vec()
}

fn decode_oplog_position(bytes: &[u8]) -> Result<OperationId, CoreError> {
    let raw: [u8; 8] = bytes.try_into().map_err(|_| {
        CoreError::new(
            ErrorCode::EInvalid,
            "op.log continuation position must be 8 bytes",
        )
    })?;
    Ok(OperationId(u64::from_be_bytes(raw)))
}

/// Walks one bounded `op.log` page from `start` newest-first.
///
/// Collects at most `limit` matching entries while visiting at most
/// `MAX_PAGE_SIZE` headers, so a heavily filtered page stays bounded and
/// returns short with a resume id. Returns the entries, the next operation
/// to visit, the oldest retained id when the chain is exhausted, and whether
/// the chain ended at the retention boundary.
fn walk_oplog_page(
    store: &Store,
    start: Option<OperationId>,
    filter: Option<SessionId>,
    limit: usize,
) -> Result<
    (
        Vec<crate::protocol::OperationEntry>,
        Option<OperationId>,
        Option<OperationId>,
        bool,
    ),
    CoreError,
> {
    let mut entries = Vec::new();
    let mut cursor = start;
    let mut oldest = None;
    let mut visited = 0usize;
    while let Some(id) = cursor {
        if entries.len() >= limit || visited >= MAX_PAGE_SIZE {
            return Ok((entries, Some(id), None, false));
        }
        visited += 1;
        let Some(header) = read_header(store, id)? else {
            return Ok((entries, None, oldest, true));
        };
        let entry = header.entry;
        oldest = Some(id);
        cursor = entry.parent;
        if filter.is_none_or(|want| entry.session == Some(want)) {
            entries.push(entry);
        }
    }
    Ok((entries, None, oldest, true))
}

impl HostedCoordinator {
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
/// [`HostedCoordinator::retention_sweep`] pass, plus in-memory read-lease
/// expiry. Leases hold no durable rows: `leases_examined` counts live read
/// guards inspected and `leases_expired` counts guards dropped after their
/// 30-second interactive authority lapsed. There is no leases fact table.
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
    /// Live read leases inspected for expiry in this pass.
    pub leases_examined: usize,
    /// Expired read leases dropped in this pass.
    pub leases_expired: usize,
}

impl RetentionReport {
    /// True when the pass deleted nothing durable and expired no leases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts_deleted == 0 && self.sessions_deleted == 0 && self.leases_expired == 0
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
        // In-memory read leases expire here as well as at read entry. The
        // sweep fires cancellation on lapsed authority; dropping the expired
        // owner guards retires the slots without touching any fact table.
        self.leases.sweep_expiry()?;
        let (leases_examined, leases_expired) = self.prune_expired_read_leases(current.mono)?;
        let report = RetentionReport {
            receipts_examined: receipts_page.examined_rows,
            receipts_deleted: receipts_page.deletions.len(),
            sessions_examined: sessions_page.examined_rows,
            sessions_deleted: sessions_page.deletions.len(),
            leases_examined,
            leases_expired,
        };
        // Lease expiry never publishes: it frees in-memory guards only. The
        // lane commit runs only when durable receipts/sessions need it.
        let durable_empty = report.receipts_deleted == 0 && report.sessions_deleted == 0;
        if durable_empty && sessions_page.cursors == loaded.sweep {
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

    /// Compacts the store's segments and orders the swap in the lane.
    ///
    /// Runs [`Store::compact`] on the blocking pool (bulk copy outside the
    /// lane, atomic locator swap inside the store) and, when the pass did
    /// work, publishes one empty [`InternalPayload::Maintenance`] candidate
    /// admitted under [`RequestClass::Maintenance`]. The lane commit
    /// serializes the swap against concurrent publications and exercises
    /// the retention ledger path, which the swap itself leaves untouched:
    /// compaction moves object bytes, never fact rows, so the ledger has
    /// no row to adjust and the freed bytes report here, not in the
    /// ledger. Idle passes skip the lane exactly like idle sweeps.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EIo`] on store failures; [`ErrorCode::ECorrupt`] on
    ///   committed damage, which quarantines the store.
    /// - [`ErrorCode::ELimit`] when admission sheds the maintenance work.
    pub async fn compact(&self, cancel: &Cancel) -> Result<CompactionStats, CoreError> {
        cancel.check()?;
        self.shutdown.check()?;
        // The maintenance slot releases before the lane submission below
        // admits again: the class may hold a single slot, and holding one
        // permit across a second admission would shed itself.
        let stats = {
            let admitted = self.admit_maintenance(0, cancel).await?;
            let store = Arc::clone(&self.store);
            let (_admitted, compacted) =
                run_blocking(admitted, cancel.clone(), move |_| store.compact()).await?;
            compacted.map_err(CoreError::from)?
        };
        if !stats.did_work() {
            return Ok(stats);
        }
        let admitted = self.admit_maintenance(0, cancel).await?;
        let candidate = InternalCandidate::new(
            InternalPayload::Maintenance,
            Vec::new(),
            cancel.clone(),
            Some(admitted),
        )?;
        self.lane.submit_internal(candidate).await?;
        Ok(stats)
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
        _ => "only `op.log`, `claim.list`, and `attest.list` are served, with lease-bound paging",
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::ByteString;
    use crate::capability::{AttestKind, AttestResult};
    use crate::change::{ClaimId, LeaseId, RequestId, StoreId};
    use crate::commit::ProvenanceClaims;
    use crate::coord::claims::{ClaimClock, seal_acquire};
    use crate::attestation::Progress;
    use crate::coord::receipt;
    use crate::coord::rows::{ReceiptRow, Retained, SweepCursors, Usage, encode, receipt_key};
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::index::RepoPath;
    use crate::protocol::{
        AttestAddArgs, AttestListArgs, AttestSignature, AttestStatement, BoundedList,
        ClaimHolderFilter, ClaimListArgs, ClaimMode, ClaimTtl, Method, Mutation as WireMutation,
        MutationOutcome, OpLogArgs, PageCursor, PageLimit, PageRequest, PinArgs, QueryDigest,
        ReceiptRef, StatusArgs, TagSetArgs, Timestamp, UndoArgs, UndoReply, UndoSummary,
    };
    use crate::store::types::{FactMutation, FactTable};
    use crate::refdata::{RefExpect, RefName};
    use crate::store::PreparationBudget;
    use crate::store::types::FactExpectation;
    use crate::store::{ObjectKind, Store};

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

    #[test]
    fn retried_mutation_replays_its_receipt_before_preparing() {
        let (_temp, coord, _owner) = coordinator();
        let session = SessionId::generate();
        let request_id = RequestId::generate();
        let request = Request::Undo(Box::new(WireMutation {
            request_id,
            args: UndoArgs {
                operation: OperationId(999),
            },
        }));
        // Without the receipt this request would fail preparation: operation
        // 999 is not retained. The receipt proves it committed before.
        let digest = receipt::digest_v1(&request)
            .expect("digest computation")
            .expect("a mutation has a digest");
        let retained_until = Timestamp::new(
            jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_hours(24))
                .expect("future"),
        );
        let reply = Reply::Undo(Box::new(UndoReply {
            outcome: MutationOutcome {
                receipt: ReceiptRef {
                    session,
                    request_id,
                    digest,
                    replayed: false,
                    retained_until,
                },
                operation: Some(OperationId(7)),
                heads: BoundedList::complete(Vec::new()).expect("empty"),
                stamps: BoundedList::complete(Vec::new()).expect("empty"),
                warnings: BoundedList::complete(Vec::new()).expect("empty"),
                merge: None,
                provenance: BoundedList::complete(Vec::new()).expect("empty"),
                identity: None,
            },
            undone: OperationId(7),
            restored: UndoSummary {
                refs: 0,
                changes: 0,
                workspaces: 0,
            },
        }));
        let row = ReceiptRow::new(session, request_id, reply).expect("receipt row");
        let encoded = encode("receipt", &row).expect("encode receipt");
        coord
            .store()
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Receipts,
                    key: receipt_key(session, request_id).to_vec(),
                    expected: crate::store::types::FactExpectation::Absent,
                    value: Some(encoded),
                }],
            )
            .expect("publish receipt");
        let checkpoint = |_: Progress| Ok::<(), CoreError>(());
        match coord
            .prepare_for_dispatch(session, request, &checkpoint)
            .expect("dispatch serves the retry")
        {
            DispatchReady::Replay(replayed) => {
                assert!(
                    replayed.outcome().expect("outcome").receipt.replayed,
                    "the retry replays the stored reply instead of re-executing"
                );
            }
            DispatchReady::Prepared(_) => panic!("a committed request must replay, not prepare"),
        }
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
            .expect_err("unknown claim.list lease is lost");
        assert_eq!(err.code, ErrorCode::ELeaseLost);

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
            .expect_err("unknown attest.list lease is lost");
        assert_eq!(err.code, ErrorCode::ELeaseLost);

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
    async fn compact_merges_segments_orders_swap_in_lane_and_preserves_ledger() {
        let (_temp, coord, _) = coordinator();
        coord.store().set_segment_target_for_tests(1024);
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();

        let mut blobs: Vec<(crate::ids::Oid, Vec<u8>)> = Vec::new();
        for index in 0..12_u64 {
            let mut state = 3000 + index;
            let bytes: Vec<u8> = (0..300)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state.to_be_bytes()[0]
                })
                .collect();
            let len = u64::try_from(bytes.len()).expect("blob fits u64");
            let prepared = coord
                .store()
                .prepare(ObjectKind::Blob, len, bytes.as_slice(), None)
                .expect("prepare blob");
            let oid = prepared.oid();
            coord
                .store()
                .publish(vec![prepared], &[])
                .expect("publish blob");
            blobs.push((oid, bytes));
        }
        // Underfill the sealed sources so the pack-estimate gate fires.
        coord.store().set_segment_target_for_tests(16384);
        let stats = coord.compact(&cancel).await.expect("compact through lane");
        assert!(stats.did_work(), "underfilled segments must merge");
        assert!(stats.bytes_freed > 0, "retired sources must unlink");

        for (oid, bytes) in &blobs {
            let object = coord.store().read(*oid).expect("read compacted blob");
            let mut actual = Vec::new();
            use std::io::Read as _;
            let mut spooled = object.bytes;
            spooled.read_to_end(&mut actual).expect("read spool");
            assert_eq!(&actual, bytes, "blob {oid} survives compaction");
        }
        // The maintenance lane commit ran (head exists) but moved no fact
        // row, so the retention ledger is exactly untouched.
        let head_bytes = coord
            .store()
            .fact(FactTable::OpHead, OP_HEAD_KEY)
            .expect("read head")
            .expect("maintenance commit publishes the head");
        let head = decode_head(coord.store(), &head_bytes).expect("decode head");
        assert_eq!(
            head.retained,
            Retained {
                receipts: Usage::default(),
                sessions: Usage::default(),
                ops: Usage::default(),
            },
            "compaction moves object bytes, never fact rows"
        );

        coord.shutdown();
        runner.abort();
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
        // Pinning now prepares; the fixture head was never stored, so the
        // existence check reports it instead of a refusal.
        let err = super::super::prepare_mutation(coord.store(), session, pin)
            .expect_err("unstored pin target is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

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

    fn seed_claims(coord: &HostedCoordinator, holder: SessionId, specs: &[(u8, &str)]) {
        let clock = ClaimClock::open(coord.store(), coord.clock.clone()).expect("claim clock");
        for (id_byte, path_text) in specs {
            let id = ClaimId::from_bytes([*id_byte; 16]);
            let path = RepoPath::new(path_text.as_bytes()).expect("valid path");
            let change = seal_acquire(
                coord.store(),
                &clock,
                holder,
                id,
                crate::protocol::ClaimAcquireArgs {
                    paths: vec![path],
                    ttl: ClaimTtl::new(60).expect("ttl"),
                    mode: ClaimMode::Enforce,
                },
            )
            .expect("acquire claim");
            coord
                .store()
                .publish(Vec::new(), &change.facts)
                .expect("publish claim");
        }
    }

    fn attest_key() -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[0x11; 32]))
    }

    fn sign_statement(key: &ssh_key::PrivateKey, statement: AttestStatement) -> AttestAddArgs {
        let payload = statement
            .canonical_payload_v1(HashKind::Sha1)
            .expect("canonical payload");
        let signature = key
            .sign(
                crate::attestation::ATTEST_NAMESPACE,
                ssh_key::HashAlg::Sha256,
                &payload,
            )
            .expect("sign");
        let armor = signature.to_pem(ssh_key::LineEnding::LF).expect("armor");
        AttestAddArgs {
            statement,
            signature: AttestSignature::new(armor).expect("armored signature"),
        }
    }

    fn publish_commit(store: &Store, body: &[u8]) -> Oid {
        let length = u64::try_from(body.len()).expect("object length");
        let prepared = store
            .prepare(ObjectKind::Commit, length, body, None)
            .expect("prepare commit");
        let oid = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish commit");
        oid
    }

    fn seed_attestations(coord: &HostedCoordinator, count: u8) {
        let key = attest_key();
        for index in 0..count {
            let body = format!(
                "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nattest subject {index}\n"
            );
            let subject = publish_commit(coord.store(), body.as_bytes());
            let statement = AttestStatement {
                subject,
                kind: AttestKind::new("review").expect("kind"),
                result: AttestResult::new("pass").expect("result"),
                signed_at: Timestamp::parse("2026-10-17T12:00:00Z").expect("timestamp"),
                supersedes: None,
            };
            let args = sign_statement(&key, statement);
            let open = |_: crate::attestation::Progress| Ok::<(), CoreError>(());
            let prepared =
                crate::attestation::prepare_add(coord.store(), &args, &open).expect("prepare");
            if !prepared.mutations.is_empty() {
                coord
                    .store()
                    .publish(Vec::new(), &prepared.mutations)
                    .expect("publish attestation");
            }
        }
    }

    async fn publish_tag(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        name: &str,
        cancel: &Cancel,
    ) {
        let prepared = super::super::prepare_mutation(
            coord.store(),
            session,
            Request::TagSet(Box::new(WireMutation {
                request_id: RequestId::generate(),
                args: TagSetArgs {
                    name: RefName::new(name).expect("tag name"),
                    target: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
                    annotation: None,
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("tag prepares");
        coord
            .submit_prepared(owner, prepared, cancel)
            .await
            .expect("tag publishes");
    }

    fn page_limit_1() -> PageLimit {
        PageLimit::new(1).expect("page limit 1")
    }

    #[tokio::test]
    async fn claim_list_pages_through_its_lease() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_claims(&coord, session, &[(1, "alpha"), (2, "beta"), (3, "gamma")]);
        let limit = page_limit_1();
        let args = ClaimListArgs {
            holder: ClaimHolderFilter::Mine,
            page: PageRequest {
                limit: Some(limit),
                cursor: None,
            },
        };
        let reply = coord
            .read(&owner, session, Request::ClaimList(Box::new(args)), &cancel)
            .await
            .expect("first page");
        let Reply::ClaimList(first) = reply else {
            panic!("claim.list must answer its own reply");
        };
        assert_eq!(first.claims.items.len(), 1);
        let cursor1 = first.claims.next.clone().expect("first page continues");
        let args = ClaimListArgs {
            holder: ClaimHolderFilter::Mine,
            page: PageRequest {
                limit: Some(limit),
                cursor: Some(cursor1.clone()),
            },
        };
        let reply = coord
            .read(&owner, session, Request::ClaimList(Box::new(args)), &cancel)
            .await
            .expect("second page");
        let Reply::ClaimList(second) = reply else {
            panic!("claim.list must answer its own reply");
        };
        assert_eq!(second.claims.items.len(), 1);
        assert_ne!(first.claims.items, second.claims.items);
        assert_eq!(second.view, first.view);
        let cursor2 = second.claims.next.clone().expect("second page continues");
        assert_eq!(cursor2.lease, cursor1.lease);
        assert_eq!(cursor2.view, cursor1.view);
        assert_eq!(cursor2.query, cursor1.query);
        let args = ClaimListArgs {
            holder: ClaimHolderFilter::Mine,
            page: PageRequest {
                limit: Some(limit),
                cursor: Some(cursor2),
            },
        };
        let reply = coord
            .read(&owner, session, Request::ClaimList(Box::new(args)), &cancel)
            .await
            .expect("third page");
        let Reply::ClaimList(third) = reply else {
            panic!("claim.list must answer its own reply");
        };
        assert_eq!(third.claims.items.len(), 1);
        assert!(third.claims.next.is_none());
        assert_eq!(third.view, first.view);
        assert_ne!(third.claims.items, first.claims.items);
        assert_ne!(third.claims.items, second.claims.items);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn attest_list_pages_through_its_lease() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_attestations(&coord, 3);
        let limit = page_limit_1();
        // Attestation pages may return short with a continuation when the
        // scan ends exactly at the limit, so follow `next` until it ends
        // like any client must, including a possible empty tail page.
        let mut collected = Vec::new();
        let mut cursor: Option<PageCursor> = None;
        let mut leases = Vec::new();
        let mut views = Vec::new();
        loop {
            let args = AttestListArgs {
                page: PageRequest {
                    limit: Some(limit),
                    cursor: cursor.clone(),
                },
                ..Default::default()
            };
            let reply = coord
                .read(
                    &owner,
                    session,
                    Request::AttestList(Box::new(args)),
                    &cancel,
                )
                .await
                .expect("attest page");
            let Reply::AttestList(page) = reply else {
                panic!("attest.list must answer its own reply");
            };
            views.push(page.view);
            collected.extend(page.records.items);
            match page.records.next {
                Some(next) => {
                    leases.push(next.lease);
                    cursor = Some(next);
                }
                None => break,
            }
        }
        assert_eq!(collected.len(), 3);
        assert!(views.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(leases.windows(2).all(|pair| pair[0] == pair[1]));
        let mut subjects: Vec<_> = collected.iter().map(|record| record.subject).collect();
        subjects.sort();
        subjects.dedup();
        assert_eq!(subjects.len(), 3);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn oplog_pages_through_its_lease_newest_first() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        publish_tag(&coord, &owner, session, "refs/tags/p1", &cancel).await;
        publish_tag(&coord, &owner, session, "refs/tags/p2", &cancel).await;
        publish_tag(&coord, &owner, session, "refs/tags/p3", &cancel).await;
        let limit = PageLimit::new(2).expect("page limit 2");
        let args = OpLogArgs {
            session: None,
            page: PageRequest {
                limit: Some(limit),
                cursor: None,
            },
        };
        let reply = coord
            .read(&owner, session, Request::OpLog(Box::new(args)), &cancel)
            .await
            .expect("first page");
        let Reply::OpLog(first) = reply else {
            panic!("op.log must answer its own reply");
        };
        assert_eq!(first.entries.items.len(), 2);
        assert!(first.entries.next.is_some());
        assert_eq!(first.oldest_retained, None);
        let cursor = first.entries.next.clone().expect("first page continues");
        let args = OpLogArgs {
            session: None,
            page: PageRequest {
                limit: Some(limit),
                cursor: Some(cursor),
            },
        };
        let reply = coord
            .read(&owner, session, Request::OpLog(Box::new(args)), &cancel)
            .await
            .expect("second page");
        let Reply::OpLog(second) = reply else {
            panic!("op.log must answer its own reply");
        };
        assert_eq!(second.entries.items.len(), 1);
        assert!(second.entries.next.is_none());
        assert!(second.oldest_retained.is_some());
        assert_ne!(second.entries.items[0].id, first.entries.items[0].id);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn continuations_refuse_wrong_session_leases() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (first, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open first session");
        let (second, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open second session");
        seed_claims(&coord, first, &[(11, "one"), (12, "two")]);
        seed_attestations(&coord, 2);
        publish_tag(&coord, &owner, first, "refs/tags/w1", &cancel).await;
        publish_tag(&coord, &owner, first, "refs/tags/w2", &cancel).await;
        let limit = page_limit_1();
        let reply = coord
            .read(
                &owner,
                first,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                })),
                &cancel,
            )
            .await
            .expect("claim first page");
        let Reply::ClaimList(list) = reply else {
            panic!("claim.list must answer its own reply");
        };
        let claim_cursor = list.claims.next.clone().expect("claim continues");
        let err = coord
            .read(
                &owner,
                second,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(claim_cursor),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("foreign session lease is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        let reply = coord
            .read(
                &owner,
                first,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect("attest first page");
        let Reply::AttestList(list) = reply else {
            panic!("attest.list must answer its own reply");
        };
        let attest_cursor = list.records.next.clone().expect("attest continues");
        let err = coord
            .read(
                &owner,
                second,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(attest_cursor),
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect_err("foreign session lease is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        let reply = coord
            .read(
                &owner,
                first,
                Request::OpLog(Box::new(OpLogArgs {
                    session: None,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                })),
                &cancel,
            )
            .await
            .expect("op.log first page");
        let Reply::OpLog(log) = reply else {
            panic!("op.log must answer its own reply");
        };
        let log_cursor = log.entries.next.clone().expect("op.log continues");
        let err = coord
            .read(
                &owner,
                second,
                Request::OpLog(Box::new(OpLogArgs {
                    session: None,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(log_cursor),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("foreign session lease is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn continuations_refuse_stale_views() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_claims(&coord, session, &[(21, "red"), (22, "blue")]);
        seed_attestations(&coord, 2);
        publish_tag(&coord, &owner, session, "refs/tags/s1", &cancel).await;
        publish_tag(&coord, &owner, session, "refs/tags/s2", &cancel).await;
        let limit = page_limit_1();
        let reply = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                })),
                &cancel,
            )
            .await
            .expect("claim first page");
        let Reply::ClaimList(list) = reply else {
            panic!("claim.list must answer its own reply");
        };
        let claim_cursor = list.claims.next.clone().expect("claim continues");
        let reply = coord
            .read(
                &owner,
                session,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect("attest first page");
        let Reply::AttestList(list) = reply else {
            panic!("attest.list must answer its own reply");
        };
        let attest_cursor = list.records.next.clone().expect("attest continues");
        let reply = coord
            .read(
                &owner,
                session,
                Request::OpLog(Box::new(OpLogArgs {
                    session: None,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: None,
                    },
                })),
                &cancel,
            )
            .await
            .expect("op.log first page");
        let Reply::OpLog(log) = reply else {
            panic!("op.log must answer its own reply");
        };
        let log_cursor = log.entries.next.clone().expect("op.log continues");
        publish_tag(&coord, &owner, session, "refs/tags/s3", &cancel).await;
        let err = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(claim_cursor),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("stale claim view is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        let err = coord
            .read(
                &owner,
                session,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(attest_cursor),
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect_err("stale attest view is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        let err = coord
            .read(
                &owner,
                session,
                Request::OpLog(Box::new(OpLogArgs {
                    session: None,
                    page: PageRequest {
                        limit: Some(limit),
                        cursor: Some(log_cursor),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("stale op.log view is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn expired_read_leases_are_lost_and_swept() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let view = current_view(coord.store()).expect("current view");
        let query = claim_query_digest(ClaimHolderFilter::Mine);
        let old = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(31))
            .expect("old instant");
        let store_id = coord.store().store_id();
        let (lease, _cancel, guard) = coord
            .leases
            .acquire(
                AcquireArgs {
                    kind: LeaseKind::Interactive,
                    store: store_id,
                    session,
                    view: view.view,
                    query,
                    roots: Vec::new(),
                    op_floor: None,
                    position_bytes: 0,
                    view_retained: true,
                },
                old,
            )
            .expect("acquire aged lease");
        coord
            .page_guards
            .lock()
            .expect("guard lock")
            .insert(lease, (guard, old));
        let report = coord
            .retention_sweep(&cancel)
            .await
            .expect("sweep expires the aged lease");
        assert_eq!(report.leases_examined, 1);
        assert_eq!(report.leases_expired, 1);
        let cursor = PageCursor {
            store: store_id,
            view: view.view,
            query,
            lease,
            position: ByteString::from(Vec::new()),
        };
        let err = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: None,
                        cursor: Some(cursor),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("expired lease is lost");
        assert_eq!(err.code, ErrorCode::ELeaseLost);
        coord.shutdown();
        let _ = runner.abort();
    }

    #[tokio::test]
    async fn invalid_paging_beats_lease_verdicts() {
        let (_temp, coord, owner) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let oversized = ByteString::from(vec![0x61; 5000]);
        let bad = PageCursor {
            store: StoreId::generate(),
            view: OperationId(0),
            query: QueryDigest::from_bytes([0x77; 32]),
            lease: LeaseId::generate(),
            position: oversized,
        };
        let err = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs {
                    holder: ClaimHolderFilter::Mine,
                    page: PageRequest {
                        limit: None,
                        cursor: Some(bad.clone()),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("oversized claim cursor is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
        let err = coord
            .read(
                &owner,
                session,
                Request::AttestList(Box::new(AttestListArgs {
                    page: PageRequest {
                        limit: None,
                        cursor: Some(bad.clone()),
                    },
                    ..Default::default()
                })),
                &cancel,
            )
            .await
            .expect_err("oversized attest cursor is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
        let err = coord
            .read(
                &owner,
                session,
                Request::OpLog(Box::new(OpLogArgs {
                    session: None,
                    page: PageRequest {
                        limit: None,
                        cursor: Some(bad),
                    },
                })),
                &cancel,
            )
            .await
            .expect_err("oversized op.log cursor is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
        let err = coord
            .read(
                &owner,
                SessionId::generate(),
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
            .expect_err("unknown session with valid shape stays forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
        coord.shutdown();
        let _ = runner.abort();
    }
}
