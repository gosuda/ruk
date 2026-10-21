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
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
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
use super::service_receipts::sweep_service_receipts_page;
use super::session::{Authority, BoundSession, ResumeOutcome, SessionTable, prepare_open};
use crate::ByteString;
use crate::MAX_CONTROL_FRAME_BYTES;
use crate::attestation::Checkpoint;
use crate::capability::{Capabilities, ReadAccess};
use crate::change::{LeaseId, OperationId, RequestId, SessionId, WorkspaceId};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::protocol::{
    AttestListArgs, AttestListReply, BlameArgs, BlameHunk, BlameReply, ChangeHead,
    ClaimHolderFilter, ClaimListArgs, ClaimListReply, CommitRev, CommitSummary, DEFAULT_PAGE_SIZE,
    DiffArgs, DiffBlob, DiffBody, DiffKind, DiffReply, EventsTailArgs, EventsTailReply, FileArgs,
    FileBody, FileDiff, FileReply, KeysetPage, LogArgs, LogReply, MAX_PAGE_SIZE, Method, OpLogArgs,
    OpLogReply, Page, PageCursor, PageLimit, PathChangeKind, PathSelection, PathStatus, QueryArgs,
    QueryDigest, QueryMatch, QueryReply, ReconnectSecret, RefsListArgs, RefsListReply, Reply,
    RepoStatReply, Request, RevisionRef, SessionAuthority, SessionOpenArgs, SessionResumeArgs,
    SessionResumeReply, ShowArgs, ShowBody, ShowReply, ShowTarget, SnapshotPolicy, StatusArgs,
    StatusReply, TailedEvent, Timestamp, TreeArgs, TreeEntry, TreeReply, ViewInfo,
};
use crate::refdata::{RefName, RefTransaction};
use crate::refs::page_refs_prefixed;
use crate::store::CompactionStats;
use crate::store::FactPageBudget;
use crate::store::Store;
use crate::store::types::{FactMutation, FactTable, PreparedObject, StoreEvent};
use crate::workspace::WorkspaceStamp;

/// What [`HostedCoordinator::prepare_for_dispatch`] returns: either the stored
/// reply for a request that committed before, or fresh lane parts for a new one.
#[derive(Debug)]
pub enum DispatchReady {
    /// The `(session, request_id)` committed before; serve the stored reply
    /// without preparing or publishing anything.
    Replay(Reply),
    /// A new request, translated into lane parts for submission. Boxed: the
    /// parts dwarf the replayed reply.
    Prepared(Box<PreparedMutation>),
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
    /// Provenance the invoking call declared; recorded in the operation
    /// entry and any sealed claim, never an authorization input.
    pub on_behalf_of: Option<String>,
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

/// Default horizon keeping event rows, in seconds (seven days).
pub const DEFAULT_EVENT_RETENTION_SECONDS: u64 = 604_800;

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
    event_retention_seconds: AtomicU64,
    /// Resume key for the service-receipt sweep rotation. In memory
    /// only: a restart re-scans from the first key, which delays but
    /// never breaks convergence, and no head-schema change is needed.
    receipt_sweep_cursor: Mutex<Option<Vec<u8>>>,
}

impl core::fmt::Debug for HostedCoordinator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostedCoordinator").finish_non_exhaustive()
    }
}

/// One directory listing target: the tree, its format, and the path
/// that selected it.
#[derive(Clone, Debug)]
struct DirTarget {
    root: Oid,
    kind: crate::ids::HashKind,
    path: Option<crate::index::RepoPath>,
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
        Self::open_with_limits(
            store,
            owner,
            store_root,
            AdmissionLimits::reference_profile(),
        )
    }

    /// Opens the coordinator under an explicit admission profile.
    /// [`Self::open`] passes the reference profile; tests pass tighter ones.
    ///
    /// # Errors
    /// The same refusals as [`Self::open`].
    pub(crate) fn open_with_limits(
        store: Arc<Store>,
        owner: Principal,
        store_root: PathBuf,
        limits: AdmissionLimits,
    ) -> Result<Self, CoreError> {
        let policies = Arc::new(PolicySource::open(&store_root, owner));
        let clock = Clock::system();
        let sessions = SessionTable::new(clock.clone());
        let admission = Admission::new(limits)?;
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
            event_retention_seconds: AtomicU64::new(DEFAULT_EVENT_RETENTION_SECONDS),
            receipt_sweep_cursor: Mutex::new(None),
        })
    }

    /// Sets the horizon pruning event rows, in seconds.
    pub fn set_event_retention_seconds(&self, seconds: u64) {
        self.event_retention_seconds
            .store(seconds, Ordering::Relaxed);
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
        on_behalf_of: Option<String>,
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
            on_behalf_of,
        };
        prepare_mutation_with(&ctx, request)
            .map(Box::new)
            .map(DispatchReady::Prepared)
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
        let on_behalf_of = prepared.on_behalf_of.clone();
        let mut candidate = MutationCandidate::new(
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
        candidate.on_behalf_of = on_behalf_of;
        self.lane.submit_mutation(candidate).await
    }

    /// Serves one session-bound read without publishing anything.
    ///
    /// Loads the session, requires active authority, holds an in-flight guard
    /// across the read, admits it under the interactive class with compute
    /// resources, authorizes it against the session's negotiated capabilities,
    /// and runs the read implementation. `op.log`, `claim.list`,
    /// `attest.list`, `refs.list`, `events.tail`, `file`, `show`, `log`,
    /// `diff`, `blame`, `query`, and `status` have implementations; every
    /// other read runs the same session checks and then names its missing
    /// implementation with [`ErrorCode::EHosted`], so an unknown session
    /// still reports `E_FORBIDDEN` rather than a missing-impl error.
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
        // A long poll admits and rechecks authority once per scan inside
        // `read_events_tail`, never across its wait: a parked poll holds no
        // interactive slot, and a session that lost authority cannot finish.
        let tails = matches!(request, Request::EventsTail(_));
        let _admitted = if tails {
            None
        } else {
            Some(self.admit_read(cancel).await?)
        };
        if !tails {
            bound.authorize_read(ReadAccess::Objects)?;
        }
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
            Request::RefsList(args) => {
                let reply = self.read_refs_page(&args)?;
                Ok(Reply::RefsList(Box::new(reply)))
            }
            Request::EventsTail(args) => {
                let reply = self.read_events_tail(&args, cancel, &bound).await?;
                Ok(Reply::EventsTail(Box::new(reply)))
            }
            Request::File(args) => {
                let reply = self.read_file(session, &args, times.mono)?;
                Ok(Reply::File(Box::new(reply)))
            }
            Request::Show(args) => {
                let reply = self.read_show(&args)?;
                Ok(Reply::Show(Box::new(reply)))
            }
            Request::Log(args) => {
                let reply = self.read_log(session, &args, times.mono)?;
                Ok(Reply::Log(Box::new(reply)))
            }
            Request::Diff(args) => {
                let reply = self.read_diff(session, &args, times.mono)?;
                Ok(Reply::Diff(Box::new(reply)))
            }
            Request::Blame(args) => {
                let reply = self.read_blame(session, &args, times.mono)?;
                Ok(Reply::Blame(Box::new(reply)))
            }
            Request::Query(args) => {
                let reply = self.read_query(session, &args, times.mono)?;
                Ok(Reply::Query(Box::new(reply)))
            }
            Request::Status(args) => {
                let reply = self.read_status(session, &args, times.mono)?;
                Ok(Reply::Status(Box::new(reply)))
            }
            Request::RepoStat(_) => {
                let reply = self.read_repo_stat()?;
                Ok(Reply::RepoStat(Box::new(reply)))
            }
            Request::Tree(args) => {
                let reply = self.read_tree(&args)?;
                Ok(Reply::Tree(Box::new(reply)))
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

    /// Returns the store and operation snapshot reads are served from.
    ///
    /// Mirrors the head load of [`read_oplog`] so adapters report the same
    /// view of the same head without opening a session.
    ///
    /// # Errors
    /// `E_CORRUPT` for a damaged head row.
    pub fn view(&self) -> Result<ViewInfo, CoreError> {
        current_view(&self.store)
    }

    /// Serves one `repo.stat` read: store identity, object format, default
    /// branch, quarantine latch, and the event horizon.
    ///
    /// The default branch comes from the `RepoMeta` row `repo.init` writes;
    /// stores predating that metadata report no default branch. Whole-ref
    /// counts are never computed. Reads hold no lane and publish nothing.
    fn read_repo_stat(&self) -> Result<RepoStatReply, CoreError> {
        let default_branch = self
            .store
            .repo_meta()
            .map_err(CoreError::from)?
            .map(|row| row.default_branch);
        let (head, oldest) = self.store.event_head().map_err(CoreError::from)?;
        Ok(RepoStatReply {
            view: current_view(&self.store)?,
            store_id: self.store.store_id(),
            object_format: self.store.hash_kind(),
            default_branch,
            quarantined: self.store.quarantine(),
            oldest,
            head,
        })
    }

    /// Resolves one tree revision to its root tree.
    ///
    /// A ref name follows symbolic targets (at most 16 hops) to a direct
    /// commit and reads its recorded tree; a literal object id reads its
    /// commit directly. Conflicted commits refuse [`ErrorCode::EConflicted`],
    /// unknown refs and commits refuse `E_NOT_FOUND`.
    fn resolve_tree_rev(&self, rev: &CommitRev) -> Result<Oid, CoreError> {
        use crate::records::Records;
        let oid = match rev {
            CommitRev::Ref(name) => {
                let mut target = self
                    .store
                    .fact(crate::store::types::FactTable::Refs, name.as_bytes())?
                    .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown ref"))
                    .and_then(|raw| {
                        crate::store::decode("ref target", &raw).map_err(CoreError::from)
                    })?;
                let mut oid = None;
                for _ in 0..16 {
                    match target {
                        crate::refdata::RefTarget::Direct(found) => {
                            oid = Some(found);
                            break;
                        }
                        crate::refdata::RefTarget::Symbolic(next) => {
                            target = self
                                .store
                                .fact(crate::store::types::FactTable::Refs, next.as_bytes())?
                                .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown ref"))
                                .and_then(|raw| {
                                    crate::store::decode("ref target", &raw)
                                        .map_err(CoreError::from)
                                })?;
                        }
                    }
                }
                oid.ok_or_else(|| {
                    CoreError::new(ErrorCode::EInvalid, "ref is too deeply symbolic")
                })?
            }
            CommitRev::Commit(oid) => *oid,
        };
        let record = Records::new(&self.store)
            .get_commit(&Head::Git { oid })?
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown commit"))?;
        record
            .tree()
            .as_resolved()
            .copied()
            .ok_or_else(|| CoreError::new(ErrorCode::EConflicted, "head is conflicted"))
    }

    /// Serves one `tree` read: one git-order directory listing with
    /// stateless keyset paging.
    ///
    /// Reads hold no lane and publish nothing. Blob paths refuse
    /// [`ErrorCode::EInvalid`], unknown cursors refuse it too, and
    /// conflicted heads refuse [`ErrorCode::EConflicted`].
    fn read_tree(&self, args: &TreeArgs) -> Result<TreeReply, CoreError> {
        let root = self.resolve_tree_rev(&args.rev)?;
        let limit = args.limit.map_or(DEFAULT_PAGE_SIZE, PageLimit::get);
        let entries = crate::tree::list_directory(
            &self.store,
            self.store.hash_kind(),
            root,
            args.path.as_ref(),
            limit,
            args.after.as_ref().map(|name| name.as_bytes()),
        )?;
        Ok(TreeReply {
            view: current_view(&self.store)?,
            entries,
        })
    }

    /// Serves one `refs.list` page with prefix and inclusive-start seek.
    /// Reads the event head before the page so `as_of` never runs ahead
    /// of the events the page reflects. The page binds no lease: the
    /// caller resumes from the stateless `next_after` cursor.
    fn read_refs_page(&self, args: &RefsListArgs) -> Result<RefsListReply, CoreError> {
        let limit = args.limit.map_or(DEFAULT_PAGE_SIZE, PageLimit::get);
        let prefix = args
            .prefix
            .as_ref()
            .map(ByteString::as_bytes)
            .unwrap_or_default();
        let (head, _) = self.store.event_head().map_err(CoreError::from)?;
        let page = page_refs_prefixed(&self.store, prefix, args.after.as_ref(), limit)?;
        let next_after = page.more.then(|| {
            page.entries
                .last()
                .map(|entry| ByteString::from(entry.name.as_bytes().to_vec()))
        });
        let next_after = next_after.flatten();
        Ok(RefsListReply {
            view: current_view(&self.store)?,
            refs: KeysetPage::new(page.entries, next_after)?,
            as_of: head,
        })
    }

    /// Serves one `file` read: a blob, symlink, gitlink, directory
    /// listing, or conflict at a path under the resolved root tree.
    /// Directory listings page by entry index through a read lease.
    /// Reads hold no lane and publish nothing.
    fn read_file(
        &self,
        viewer: SessionId,
        args: &FileArgs,
        now: StdInstant,
    ) -> Result<FileReply, CoreError> {
        use super::reads::{blob_bytes, inline_body};
        use crate::ops::tree_edit::lookup;
        let (view, root) = resolve_search_root(&self.store, &args.at)?;
        let kind = self.store.hash_kind();
        let body = match args.path.as_ref() {
            None => FileBody::Directory {
                entries: self.page_directory(
                    viewer,
                    &view,
                    &DirTarget {
                        root,
                        kind,
                        path: None,
                    },
                    &args.page,
                    now,
                )?,
            },
            Some(path) => {
                let node = lookup(&self.store, root, path)?
                    .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "no entry at path"))?;
                match node.0 {
                    crate::workcopy::tree::TreeMode::Tree => FileBody::Directory {
                        entries: self.page_directory(
                            viewer,
                            &view,
                            &DirTarget {
                                root: node.1,
                                kind,
                                path: Some(path.clone()),
                            },
                            &args.page,
                            now,
                        )?,
                    },
                    crate::workcopy::tree::TreeMode::File(mode) => {
                        use crate::index::FileMode;
                        match mode {
                            FileMode::Regular | FileMode::Executable => {
                                let bytes = blob_bytes(&self.store, node.1)?;
                                let size = u64::try_from(bytes.len()).map_err(|_| {
                                    CoreError::new(ErrorCode::EInvalid, "blob size overflows u64")
                                })?;
                                FileBody::Blob {
                                    oid: node.1,
                                    executable: mode == FileMode::Executable,
                                    size,
                                    content: inline_body(bytes)?,
                                }
                            }
                            FileMode::Symlink => {
                                let bytes = blob_bytes(&self.store, node.1)?;
                                FileBody::Symlink {
                                    target: ByteString::from(bytes),
                                }
                            }
                            FileMode::Gitlink => FileBody::Gitlink { commit: node.1 },
                        }
                    }
                }
            }
        };
        Ok(FileReply { view, body })
    }

    /// Pages one directory in git order by entry index.
    fn page_directory(
        &self,
        viewer: SessionId,
        view: &ViewInfo,
        target: &DirTarget,
        page: &crate::protocol::PageRequest,
        now: StdInstant,
    ) -> Result<Page<TreeEntry>, CoreError> {
        use super::reads::{file_query_digest, sized_tree_entry, tree_items};
        let limit = page.effective_limit();
        let items = tree_items(&self.store, target.kind, target.root)?;
        let start: usize = match page.cursor.as_ref() {
            None => 0,
            Some(cursor) => {
                if cursor.position.len() != 8 {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        "file continuation position must be 8 bytes",
                    ));
                }
                let want = CursorWant {
                    store: self.store.store_id(),
                    session: viewer,
                    view: current_view(&self.store)?.view,
                    query: file_query_digest(target.root, target.path.as_ref()),
                };
                self.leases.check_cursor(cursor, &want, now)?;
                usize::from_be_bytes(cursor.position.as_bytes().try_into().map_err(|_| {
                    CoreError::new(ErrorCode::EInvalid, "file continuation is not an index")
                })?)
            }
        };
        let end = start.saturating_add(limit).min(items.len());
        let mut entries = Vec::new();
        for item in items.get(start..end).unwrap_or_default() {
            entries.push(sized_tree_entry(
                &self.store,
                item.name.clone(),
                item.mode,
                item.oid,
            )?);
        }
        if end >= items.len() {
            return Page::new(entries, None);
        }
        let query = file_query_digest(target.root, target.path.as_ref());
        let position = u64::try_from(end)
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "directory index overflows u64"))?;
        let next = self.mint_read_lease(viewer, view.view, query, &position.to_be_bytes(), now)?;
        Page::new(entries, Some(next))
    }

    /// Serves one `show` read: a commit with its record, or one object.
    /// Reads hold no lane and publish nothing.
    fn read_show(&self, args: &ShowArgs) -> Result<ShowReply, CoreError> {
        use super::reads::{change_head, head_commit, inline_body};
        use crate::store::types::ObjectKind as StoreKind;
        let view = current_view(&self.store)?;
        let body = match &args.target {
            ShowTarget::Head { head } => {
                let record = head_commit(&self.store, head)?;
                ShowBody::Commit {
                    change: Some(record.change_id()),
                    head: *head,
                    record: Box::new(record),
                }
            }
            ShowTarget::Change { change } => {
                let head = change_head(&self.store, change)?;
                let record = head_commit(&self.store, &head)?;
                ShowBody::Commit {
                    change: Some(record.change_id()),
                    head,
                    record: Box::new(record),
                }
            }
            ShowTarget::Object { oid } => {
                let mut object = self.store.read(*oid).map_err(CoreError::from)?;
                let kind = match object.kind {
                    StoreKind::Blob => crate::protocol::ObjectKind::Blob,
                    StoreKind::Tree => crate::protocol::ObjectKind::Tree,
                    StoreKind::Commit => crate::protocol::ObjectKind::Commit,
                    StoreKind::Tag => crate::protocol::ObjectKind::Tag,
                    StoreKind::Conflict => {
                        return Err(CoreError::new(
                            ErrorCode::EConflicted,
                            "conflict objects have no object view",
                        ));
                    }
                };
                let mut bytes = Vec::new();
                use std::io::Read as _;
                object
                    .bytes
                    .read_to_end(&mut bytes)
                    .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
                let size = u64::try_from(bytes.len()).map_err(|_| {
                    CoreError::new(ErrorCode::EInvalid, "object size overflows u64")
                })?;
                ShowBody::Object {
                    oid: *oid,
                    kind,
                    size,
                    content: inline_body(bytes)?,
                }
            }
        };
        Ok(ShowReply { view, body })
    }

    /// Serves one `log` read: the newest-first page of one revset's matches.
    ///
    /// Parses the revset, builds the production graph index, evaluates with
    /// the stored-statement attestation lookup, and pages through an engine
    /// offset bound to a 30-second read lease. Reads hold no lane and
    /// publish nothing.
    fn read_log(
        &self,
        viewer: SessionId,
        args: &LogArgs,
        now: StdInstant,
    ) -> Result<LogReply, CoreError> {
        use super::reads::{eval_revset_page, revset_query_digest};
        use crate::revset::eval::RevsetCursor;
        let limit = args.page.effective_limit();
        let query = revset_query_digest(b"ruk.log/v1", &args.revset);
        if let Some(cursor) = args.page.cursor.as_ref() {
            let view_before = current_view(&self.store)?;
            let want = CursorWant {
                store: self.store.store_id(),
                session: viewer,
                view: view_before.view,
                query,
            };
            self.leases.check_cursor(cursor, &want, now)?;
            let offset = RevsetCursor::from_opaque(cursor.position.as_bytes())?;
            let page = eval_revset_page(&self.store, &args.revset, Some(limit), Some(&offset))?;
            let view_after = current_view(&self.store)?;
            if view_after.view != cursor.view {
                return Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "log cursor names a stale view: open a fresh first page",
                ));
            }
            self.log_reply(viewer, query, page, now)
        } else {
            let page = eval_revset_page(&self.store, &args.revset, Some(limit), None)?;
            self.log_reply(viewer, query, page, now)
        }
    }

    /// Renders one evaluated log page with its lease-bound continuation.
    fn log_reply(
        &self,
        viewer: SessionId,
        query: QueryDigest,
        page: crate::revset::eval::RevsetPage,
        now: StdInstant,
    ) -> Result<LogReply, CoreError> {
        use crate::records::Records;
        let view = current_view(&self.store)?;
        let records = Records::new(&self.store);
        let mut entries = Vec::with_capacity(page.heads.len());
        for head in &page.heads {
            let record = records.get_commit(head)?.ok_or_else(|| {
                CoreError::new(ErrorCode::ECorrupt, "log commit is missing from the store")
            })?;
            let divergent = records
                .get_change(&record.change_id())?
                .is_some_and(|entry| entry.heads.len() > 1);
            let message = record.message();
            let subject = match message.iter().position(|byte| *byte == b'\n') {
                Some(index) => &message[..index],
                None => message,
            };
            entries.push(CommitSummary {
                change: Some(record.change_id()),
                head: *head,
                parents: record.parents().to_vec(),
                author: record
                    .author()
                    .map_err(|err| CoreError::new(ErrorCode::ECorrupt, err.to_string()))?,
                committer: record
                    .committer()
                    .map_err(|err| CoreError::new(ErrorCode::ECorrupt, err.to_string()))?,
                subject: ByteString::from(subject.to_vec()),
                conflicted: matches!(head, crate::heads::Head::Conflicted { .. }),
                divergent,
            });
        }
        let next = match page.next_cursor {
            None => None,
            Some(offset) => {
                Some(self.mint_read_lease(viewer, view.view, query, &offset.to_opaque(), now)?)
            }
        };
        Ok(LogReply {
            view,
            entries: Page::new(entries, next)?,
        })
    }

    /// Serves one `query` read: the changes one revset's matches belong to.
    ///
    /// Heads sharing a change group into one match carrying every current
    /// head of the change, so divergence stays visible even when the revset
    /// names a single head. Paging mirrors [`HostedCoordinator::read_log`].
    fn read_query(
        &self,
        viewer: SessionId,
        args: &QueryArgs,
        now: StdInstant,
    ) -> Result<QueryReply, CoreError> {
        use super::reads::{eval_revset_page, revset_query_digest};
        use crate::records::Records;
        use crate::revset::eval::RevsetCursor;
        let limit = args.page.effective_limit();
        let query = revset_query_digest(b"ruk.query/v1", &args.revset);
        let page = match args.page.cursor.as_ref() {
            None => eval_revset_page(&self.store, &args.revset, Some(limit), None)?,
            Some(cursor) => {
                let view_before = current_view(&self.store)?;
                let want = CursorWant {
                    store: self.store.store_id(),
                    session: viewer,
                    view: view_before.view,
                    query,
                };
                self.leases.check_cursor(cursor, &want, now)?;
                let offset = RevsetCursor::from_opaque(cursor.position.as_bytes())?;
                let page = eval_revset_page(&self.store, &args.revset, Some(limit), Some(&offset))?;
                let view_after = current_view(&self.store)?;
                if view_after.view != cursor.view {
                    return Err(CoreError::new(
                        ErrorCode::EForbidden,
                        "query cursor names a stale view: open a fresh first page",
                    ));
                }
                page
            }
        };
        let view = current_view(&self.store)?;
        let records = Records::new(&self.store);
        let mut order: Vec<crate::change::ChangeId> = Vec::new();
        let mut grouped: std::collections::HashMap<crate::change::ChangeId, Vec<Head>> =
            std::collections::HashMap::new();
        for head in &page.heads {
            let record = records.get_commit(head)?.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "query commit is missing from the store",
                )
            })?;
            let change = record.change_id();
            if !grouped.contains_key(&change) {
                order.push(change);
            }
            grouped.entry(change).or_default().push(*head);
        }
        let mut matches = Vec::with_capacity(order.len());
        for change in order {
            let matched = grouped.remove(&change).unwrap_or_default();
            let heads = match records.get_change(&change)? {
                Some(entry) => entry.heads.clone(),
                None => matched,
            };
            matches.push(QueryMatch { change, heads });
        }
        let next = match page.next_cursor {
            None => None,
            Some(offset) => {
                Some(self.mint_read_lease(viewer, view.view, query, &offset.to_opaque(), now)?)
            }
        };
        Ok(QueryReply {
            view,
            matches: Page::new(matches, next)?,
        })
    }

    /// Serves one `diff` read: the file changes between two revisions.
    ///
    /// Both trees flatten through [`crate::coord::reads::diff_trees`] and
    /// merge-join over path bytes; every changed blob pair renders a
    /// unified patch through the cell-capped [`crate::coord::reads::lcs_align`],
    /// and anything else reports [`DiffBody::Binary`]. Reads hold no lane
    /// and publish nothing.
    fn read_diff(
        &self,
        viewer: SessionId,
        args: &DiffArgs,
        now: StdInstant,
    ) -> Result<DiffReply, CoreError> {
        use super::reads::diff_trees;
        use crate::index::{FileMode, RepoPath};
        use crate::workcopy::tree::TreeMode;
        let kind = self.store.hash_kind();
        let (_, left_root) = resolve_search_root(&self.store, &args.left)?;
        let (_, right_root) = resolve_search_root(&self.store, &args.right)?;
        let changes = diff_trees(&self.store, kind, left_root, right_root)?;
        let mut files = Vec::with_capacity(changes.len().min(args.page.effective_limit()));
        for change in &changes {
            let selected = match &args.paths {
                PathSelection::All => true,
                PathSelection::Paths(wanted) => wanted.iter().any(|prefix| {
                    let bytes = prefix.as_bytes();
                    change.path.as_slice() == bytes
                        || change.path.starts_with(bytes)
                            && change.path.get(bytes.len()) == Some(&b'/')
                }),
            };
            if !selected {
                continue;
            }
            let path = RepoPath::new(change.path.clone()).map_err(|err| {
                CoreError::new(ErrorCode::ECorrupt, format!("diff path is invalid: {err}"))
            })?;
            let is_blob = |entry: &(TreeMode, crate::ids::Oid)| {
                matches!(
                    entry.0,
                    TreeMode::File(FileMode::Regular | FileMode::Executable)
                )
            };
            let (kind, old, new, body) = match (&change.old, &change.new) {
                (None, Some(entry)) => {
                    let blob = is_blob(entry).then_some(DiffBlob {
                        oid: entry.1,
                        executable: matches!(entry.0, TreeMode::File(FileMode::Executable)),
                    });
                    let body = self.diff_body(None, Some(entry), &path)?;
                    (DiffKind::Added, None, blob, body)
                }
                (Some(entry), None) => {
                    let blob = is_blob(entry).then_some(DiffBlob {
                        oid: entry.1,
                        executable: matches!(entry.0, TreeMode::File(FileMode::Executable)),
                    });
                    let body = self.diff_body(Some(entry), None, &path)?;
                    (DiffKind::Deleted, blob, None, body)
                }
                (Some(old_entry), Some(new_entry)) => {
                    let old_blob = is_blob(old_entry).then_some(DiffBlob {
                        oid: old_entry.1,
                        executable: matches!(old_entry.0, TreeMode::File(FileMode::Executable)),
                    });
                    let new_blob = is_blob(new_entry).then_some(DiffBlob {
                        oid: new_entry.1,
                        executable: matches!(new_entry.0, TreeMode::File(FileMode::Executable)),
                    });
                    let body = self.diff_body(Some(old_entry), Some(new_entry), &path)?;
                    (DiffKind::Modified, old_blob, new_blob, body)
                }
                (None, None) => {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        "diff change has neither side",
                    ));
                }
            };
            files.push(FileDiff {
                path,
                old_path: None,
                kind,
                old,
                new,
                conflicted: false,
                body,
            });
        }
        let query = self.diff_query_digest(args);
        let total = files.len();
        let start = match args.page.cursor.as_ref() {
            None => 0,
            Some(cursor) => {
                let want = CursorWant {
                    store: self.store.store_id(),
                    session: viewer,
                    view: current_view(&self.store)?.view,
                    query,
                };
                self.leases.check_cursor(cursor, &want, now)?;
                usize::from_be_bytes(cursor.position.as_bytes().try_into().map_err(|_| {
                    CoreError::new(ErrorCode::EInvalid, "diff continuation is not an index")
                })?)
            }
        };
        let limit = args.page.effective_limit();
        let end = start.saturating_add(limit).min(total);
        let items = files.get(start..end).unwrap_or_default().to_vec();
        let view = current_view(&self.store)?;
        let next = if end >= total {
            None
        } else {
            let position = u64::try_from(end)
                .map_err(|_| CoreError::new(ErrorCode::EInvalid, "diff index overflows u64"))?;
            Some(self.mint_read_lease(viewer, view.view, query, &position.to_be_bytes(), now)?)
        };
        Ok(DiffReply {
            view,
            files: Page::new(items, next)?,
        })
    }

    /// Renders one changed file's body: a unified patch for two text blobs,
    /// [`DiffBody::Binary`] for anything else.
    fn diff_body(
        &self,
        old: Option<&(crate::workcopy::tree::TreeMode, crate::ids::Oid)>,
        new: Option<&(crate::workcopy::tree::TreeMode, crate::ids::Oid)>,
        path: &crate::index::RepoPath,
    ) -> Result<DiffBody, CoreError> {
        use super::reads::{blob_bytes, lcs_align, split_lines, unified_patch};
        use crate::index::FileMode;
        use crate::workcopy::tree::TreeMode;
        let is_text_blob = |entry: &(TreeMode, crate::ids::Oid)| {
            matches!(
                entry.0,
                TreeMode::File(FileMode::Regular | FileMode::Executable)
            )
        };
        let (Some(old_entry), Some(new_entry)) = (old, new) else {
            let present = match (old, new) {
                (Some(entry), None) | (None, Some(entry)) => entry,
                (None, None) => {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        "diff body has neither side",
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        "diff body sides are ambiguous",
                    ));
                }
            };
            if !is_text_blob(present) {
                return Ok(DiffBody::Binary);
            }
            let bytes = blob_bytes(&self.store, present.1)?;
            if bytes.contains(&0) {
                return Ok(DiffBody::Binary);
            }
            let empty: Vec<&[u8]> = Vec::new();
            let lines = split_lines(&bytes);
            let (old_lines, new_lines, old_label, new_label) = match old {
                Some(_) => (
                    lines.as_slice(),
                    empty.as_slice(),
                    format!("a/{}", String::from_utf8_lossy(path.as_bytes())),
                    String::from("/dev/null"),
                ),
                None => (
                    empty.as_slice(),
                    lines.as_slice(),
                    String::from("/dev/null"),
                    format!("b/{}", String::from_utf8_lossy(path.as_bytes())),
                ),
            };
            let ops = lcs_align(old_lines, new_lines)?;
            let patch = unified_patch(&old_label, &new_label, old_lines, new_lines, &ops);
            let inline = super::reads::inline_body(patch)?;
            return Ok(DiffBody::Unified { patch: inline });
        };
        if !is_text_blob(old_entry) || !is_text_blob(new_entry) {
            return Ok(DiffBody::Binary);
        }
        let old_bytes = blob_bytes(&self.store, old_entry.1)?;
        let new_bytes = blob_bytes(&self.store, new_entry.1)?;
        if old_bytes.contains(&0) || new_bytes.contains(&0) {
            return Ok(DiffBody::Binary);
        }
        let old_lines = split_lines(&old_bytes);
        let new_lines = split_lines(&new_bytes);
        let ops = lcs_align(&old_lines, &new_lines)?;
        let label = String::from_utf8_lossy(path.as_bytes()).into_owned();
        let patch = unified_patch(
            &format!("a/{label}"),
            &format!("b/{label}"),
            &old_lines,
            &new_lines,
            &ops,
        );
        let inline = super::reads::inline_body(patch)?;
        Ok(DiffBody::Unified { patch: inline })
    }

    /// Hashes one diff's revisions and path selection into its lease digest.
    fn diff_query_digest(&self, args: &DiffArgs) -> QueryDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"ruk.diff/v1\x00");
        hasher
            .update(format!("{:?}\x00{:?}\x00{:?}", args.left, args.right, args.paths).as_bytes());
        QueryDigest::from_bytes(hasher.finalize().into())
    }

    /// Serves one `blame` read: the per-line commit attribution of a file.
    ///
    /// Resolves the revision, attributes every line through
    /// [`crate::coord::reads::blame_attribute`], folds consecutive lines
    /// from one commit into hunks, applies the optional line window, and
    /// pages through an index offset bound to a 30-second read lease. Reads
    /// hold no lane and publish nothing.
    fn read_blame(
        &self,
        viewer: SessionId,
        args: &BlameArgs,
        now: StdInstant,
    ) -> Result<BlameReply, CoreError> {
        use super::reads::{blame_attribute, head_tree};
        use crate::records::Records;
        let (view, _) = resolve_search_root(&self.store, &args.at)?;
        let start = match &args.at {
            RevisionRef::Head { head } => *head,
            RevisionRef::Change { change } => super::reads::change_head(&self.store, change)?,
            RevisionRef::Workspace { .. } => {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "blame over a workspace needs a workcopy crawl",
                ));
            }
        };
        let _root = head_tree(&self.store, &start)?;
        let (lines, heads) = blame_attribute(&self.store, &start, &args.path)?;
        let records = Records::new(&self.store);
        let mut hunks: Vec<BlameHunk> = Vec::new();
        for (index, head) in heads.iter().enumerate() {
            let record = records.get_commit(head)?.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "blame commit is missing from the store",
                )
            })?;
            let author = record
                .author()
                .map_err(|err| CoreError::new(ErrorCode::ECorrupt, err.to_string()))?;
            let start_line = u32::try_from(index + 1).map_err(|_| {
                CoreError::new(ErrorCode::EInvalid, "blame line number overflows u32")
            })?;
            match hunks.last_mut() {
                Some(open)
                    if open.head == *head && open.start_line + open.line_count == start_line =>
                {
                    open.line_count += 1;
                }
                _ => {
                    hunks.push(BlameHunk {
                        start_line,
                        line_count: 1,
                        head: *head,
                        change: Some(record.change_id()),
                        original_path: args.path.clone(),
                        author,
                    });
                }
            }
        }
        let _ = lines;
        if let Some(window) = args.lines {
            hunks.retain(|hunk| {
                let last = hunk
                    .start_line
                    .saturating_add(hunk.line_count)
                    .saturating_sub(1);
                hunk.start_line <= window.end && last >= window.start
            });
        }
        let query = self.blame_query_digest(args);
        let total = hunks.len();
        let start_at = match args.page.cursor.as_ref() {
            None => 0,
            Some(cursor) => {
                let want = CursorWant {
                    store: self.store.store_id(),
                    session: viewer,
                    view: current_view(&self.store)?.view,
                    query,
                };
                self.leases.check_cursor(cursor, &want, now)?;
                usize::from_be_bytes(cursor.position.as_bytes().try_into().map_err(|_| {
                    CoreError::new(ErrorCode::EInvalid, "blame continuation is not an index")
                })?)
            }
        };
        let limit = args.page.effective_limit();
        let end = start_at.saturating_add(limit).min(total);
        let items = hunks.get(start_at..end).unwrap_or_default().to_vec();
        let next = if end >= total {
            None
        } else {
            let position = u64::try_from(end)
                .map_err(|_| CoreError::new(ErrorCode::EInvalid, "blame index overflows u64"))?;
            Some(self.mint_read_lease(viewer, view.view, query, &position.to_be_bytes(), now)?)
        };
        Ok(BlameReply {
            view,
            hunks: Page::new(items, next)?,
        })
    }

    /// Hashes one blame's revision, path, and line window into its lease digest.
    fn blame_query_digest(&self, args: &BlameArgs) -> QueryDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"ruk.blame/v1\x00");
        hasher.update(format!("{:?}\x00{:?}\x00{:?}", args.at, args.path, args.lines).as_bytes());
        QueryDigest::from_bytes(hasher.finalize().into())
    }

    /// Serves one `status` read: how the worktree differs from its base tree
    /// without snapshotting.
    ///
    /// Only [`SnapshotPolicy::Skip`] over a native workspace serves: `Auto`
    /// would snapshot (a publication, not a read), `GitCompat` has no
    /// workcopy crawl on this path, and a missing workspace names nothing
    /// to crawl. Each refuses with a named [`ErrorCode::EInvalid`].
    fn read_status(
        &self,
        viewer: SessionId,
        args: &StatusArgs,
        now: StdInstant,
    ) -> Result<StatusReply, CoreError> {
        use super::reads::head_tree;
        use crate::coord::rows::{decode_workspace, workspace_key};
        use crate::store::types::FactTable;
        use crate::workcopy::NoIgnore;
        use crate::workcopy::crawl::CrawlLimits;
        use crate::workcopy::journal_state::NoJournal;
        use crate::workcopy::snapshot::{SnapshotInput, StatusReport, status as snapshot_status};
        use crate::workcopy::statcache::StatClock;
        let workspace = args.workspace.ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "status needs an explicit native workspace",
            )
        })?;
        if !matches!(args.snapshot, SnapshotPolicy::Skip) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "status serves snapshot skip only: auto-snapshot publishes",
            ));
        }
        let key = workspace_key(workspace);
        let row_bytes = self
            .store
            .fact(FactTable::Workspaces, &key)?
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown workspace"))?;
        let row = decode_workspace(&self.store, &key, &row_bytes)?;
        let native = row.state.require_native().map_err(|err| {
            CoreError::new(
                ErrorCode::EInvalid,
                format!("status needs a native workspace: {err}"),
            )
        })?;
        let root = std::str::from_utf8(row.root.as_bytes())
            .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "workspace root is not UTF-8"))?;
        if root.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "status needs a workspace with a materialization root",
            ));
        }
        let base_tree = head_tree(&self.store, &native.head)?;
        let ignore = NoIgnore;
        let journal = NoJournal;
        let clock = StatClock::system(StatClock::COARSE_RESOLUTION_NS)?;
        let input = SnapshotInput {
            workspace,
            state: &row.state,
            root: std::path::Path::new(root),
            base_tree,
            watch: None,
            clock,
            limits: CrawlLimits::reference(),
            ignore: &ignore,
            journal: &journal,
        };
        let view = current_view(&self.store)?;
        let change = Some(ChangeHead {
            change: native.change,
            head: native.head,
        });
        match snapshot_status(&self.store, &input)? {
            StatusReport::Materializing(_) => Ok(StatusReply {
                view,
                workspace: Some(row.state.clone()),
                change,
                applying: true,
                snapshot_operation: None,
                paths: Page::new(Vec::new(), None)?,
            }),
            StatusReport::Clean => Ok(StatusReply {
                view,
                workspace: Some(row.state.clone()),
                change,
                applying: false,
                snapshot_operation: None,
                paths: Page::new(Vec::new(), None)?,
            }),
            StatusReport::Dirty {
                changed,
                removed,
                conflict_edits,
            } => {
                use crate::ops::tree_edit::lookup;
                use crate::workcopy::tree::TreeMode;
                let conflicts: std::collections::HashSet<&[u8]> = conflict_edits
                    .iter()
                    .map(|edit| edit.path.as_bytes())
                    .collect();
                let mut paths: Vec<PathStatus> = Vec::new();
                for path in changed {
                    let entry = lookup(&self.store, base_tree, &path)?;
                    let change = match entry {
                        None => PathChangeKind::Added,
                        Some((TreeMode::Tree, _)) => PathChangeKind::TypeChanged,
                        Some(_) => PathChangeKind::Modified,
                    };
                    paths.push(PathStatus {
                        conflicted: conflicts.contains(path.as_bytes()),
                        path,
                        change,
                    });
                }
                for path in removed {
                    paths.push(PathStatus {
                        conflicted: conflicts.contains(path.as_bytes()),
                        path,
                        change: PathChangeKind::Deleted,
                    });
                }
                paths.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                let query = self.status_query_digest(workspace);
                let total = paths.len();
                let start = match args.page.cursor.as_ref() {
                    None => 0,
                    Some(cursor) => {
                        let want = CursorWant {
                            store: self.store.store_id(),
                            session: viewer,
                            view: current_view(&self.store)?.view,
                            query,
                        };
                        self.leases.check_cursor(cursor, &want, now)?;
                        usize::from_be_bytes(cursor.position.as_bytes().try_into().map_err(
                            |_| {
                                CoreError::new(
                                    ErrorCode::EInvalid,
                                    "status continuation is not an index",
                                )
                            },
                        )?)
                    }
                };
                let limit = args.page.effective_limit();
                let end = start.saturating_add(limit).min(total);
                let items = paths.get(start..end).unwrap_or_default().to_vec();
                let next = if end >= total {
                    None
                } else {
                    let position = u64::try_from(end).map_err(|_| {
                        CoreError::new(ErrorCode::EInvalid, "status index overflows u64")
                    })?;
                    Some(self.mint_read_lease(
                        viewer,
                        view.view,
                        query,
                        &position.to_be_bytes(),
                        now,
                    )?)
                };
                Ok(StatusReply {
                    view,
                    workspace: Some(row.state.clone()),
                    change,
                    applying: false,
                    snapshot_operation: None,
                    paths: Page::new(items, next)?,
                })
            }
        }
    }

    /// Hashes one status workspace into its lease digest.
    fn status_query_digest(&self, workspace: WorkspaceId) -> QueryDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"ruk.status/v1\x00");
        hasher.update(workspace.as_bytes());
        QueryDigest::from_bytes(hasher.finalize().into())
    }

    /// One interactive compute admission for one scan of a read.
    async fn admit_read(&self, cancel: &Cancel) -> Result<Admitted, CoreError> {
        self.admission
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
            .await
    }

    /// Rechecks that a bound session still holds active authority to read.
    fn check_read_authority(&self, bound: &BoundSession) -> Result<(), CoreError> {
        let times = self.clock.sample()?;
        if bound.current_authority(&times) != Authority::Active {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session lacks active authority",
            ));
        }
        bound.authorize_read(ReadAccess::Objects)
    }

    /// Serves one `events.tail` read: ref events strictly after `after`,
    /// long-polled up to `wait_ms`. Reports `expired` when `after + 1`
    /// predates the oldest retained sequence; the caller then resnapshots
    /// from `refs.list` with `as_of`. The only ref feed. The poll holds
    /// no lane and no writer lock: it sleeps between head checks, and a
    /// repeated call replays the same rows, so delivery stays idempotent.
    /// Whether the follower has missed events: its next row, `after + 1`,
    /// predates the oldest retained row, so a resume would skip pruned
    /// rows silently and the follower must resnapshot. The saturating add
    /// holds the caught-up edge: `after` at `u64::MAX` never expires.
    fn tail_expired(after: u64, oldest: u64) -> bool {
        after.saturating_add(1) < oldest
    }

    /// The head and oldest are re-read after the page: a retention sweep
    /// between the two reads can prune rows the follower never saw, and
    /// a publish in between can leave events above the returned head.
    /// The re-check reports `expired` instead of silently skipping the
    /// pruned rows, and the reply head always covers the returned events.
    async fn read_events_tail(
        &self,
        args: &EventsTailArgs,
        cancel: &Cancel,
        bound: &BoundSession,
    ) -> Result<EventsTailReply, CoreError> {
        let limit = args.limit.map_or(DEFAULT_PAGE_SIZE, PageLimit::get);
        let wait_ms = u64::from(args.wait_ms.unwrap_or(0));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
        // Where the scan stands inside this call. Past the first pass the
        // scan resumes past everything already examined, so a waiting poll
        // re-reads only new rows instead of the table from `after`.
        let mut scanned = args.after;
        loop {
            cancel.check()?;
            let grant = self.admit_read(cancel).await?;
            self.check_read_authority(bound)?;
            let (head, oldest) = self.store.event_head().map_err(CoreError::from)?;
            if Self::tail_expired(args.after, oldest) {
                return Ok(EventsTailReply {
                    view: current_view(&self.store)?,
                    events: Vec::new(),
                    head,
                    oldest,
                    expired: true,
                });
            }
            let (events, end) = self.tail_page(scanned, limit, args.prefix.as_ref())?;
            let (head, oldest) = self.store.event_head().map_err(CoreError::from)?;
            if Self::tail_expired(args.after, oldest) {
                return Ok(EventsTailReply {
                    view: current_view(&self.store)?,
                    events: Vec::new(),
                    head,
                    oldest,
                    expired: true,
                });
            }
            // The grant ends with the scan: the wait below holds no slot.
            drop(grant);
            if !events.is_empty() || tokio::time::Instant::now() >= deadline {
                return Ok(EventsTailReply {
                    view: current_view(&self.store)?,
                    events,
                    head,
                    oldest,
                    expired: false,
                });
            }
            scanned = end;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Encoded-byte budget for one served tail page, held below the
    /// control frame bound with room for the reply envelope (view, head,
    /// oldest, expiry flag) around the events array.
    const TAIL_PAGE_ENCODE_BUDGET: usize = MAX_CONTROL_FRAME_BYTES - 65_536;

    /// Scans forward from `after`, oldest first, collecting up to `limit`
    /// events whose names fall under `prefix`, and returns them with the
    /// last examined sequence. The scan pages internally to the end of
    /// the table: a filtered page never hides matching rows past its
    /// window, and the caller resumes from the last seen sequence, so no
    /// event is missed or repeated. The accumulated page also stops at
    /// an encoded-size budget below the control frame bound: names and
    /// request ids have no length bound, so a row-count limit alone
    /// cannot keep the reply encodable. A partial page resumes from its
    /// last event, so the follower still advances.
    fn tail_page(
        &self,
        after: u64,
        limit: usize,
        prefix: Option<&ByteString>,
    ) -> Result<(Vec<TailedEvent>, u64), CoreError> {
        let mut events = Vec::new();
        let mut encoded: usize = 0;
        let mut cursor = after;
        loop {
            let budget = FactPageBudget::new(limit, MAX_CONTROL_FRAME_BYTES);
            let page = self
                .store
                .fact_page(FactTable::Events, Some(&cursor.to_be_bytes()), budget)
                .map_err(CoreError::from)?;
            if page.rows.is_empty() {
                break;
            }
            for row in &page.rows {
                if events.len() == limit {
                    break;
                }
                cursor = u64::from_be_bytes(row.key.as_slice().try_into().map_err(|_| {
                    CoreError::new(
                        ErrorCode::ECorrupt,
                        format!("event key is {} bytes, not a sequence", row.key.len()),
                    )
                })?);
                let stored: StoreEvent =
                    crate::store::types::decode_store_event(&row.value).map_err(CoreError::from)?;
                if let Some(want) = prefix
                    && !stored.name.starts_with(want.as_bytes())
                {
                    continue;
                }
                let event = TailedEvent {
                    seq: cursor,
                    name: ByteString::from(stored.name),
                    old: stored
                        .old
                        .map(|bytes| crate::store::types::decode_event_target(&bytes))
                        .transpose()
                        .map_err(CoreError::from)?,
                    new: stored
                        .new
                        .map(|bytes| crate::store::types::decode_event_target(&bytes))
                        .transpose()
                        .map_err(CoreError::from)?,
                    at: stored.at,
                    source: stored.source,
                    operation: stored.operation,
                    request_id: stored.request_id,
                    session: stored.session,
                };
                let width = sonic_rs::to_string(&event)
                    .map(|text| text.len())
                    .unwrap_or(usize::MAX);
                // A lone oversize event still goes out alone: the transport
                // refuses it the way it would have before, instead of the
                // scan wedging on an undeliverable row.
                if !events.is_empty()
                    && encoded.saturating_add(width) > Self::TAIL_PAGE_ENCODE_BUDGET
                {
                    let end = events
                        .last()
                        .map(|event: &TailedEvent| event.seq)
                        .unwrap_or(cursor);
                    return Ok((events, end));
                }
                encoded = encoded.saturating_add(width);
                events.push(event);
            }
            if events.len() == limit || !page.more {
                break;
            }
        }
        Ok((events, cursor))
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

/// One bounded newest-first `op.log` page: entries, resume id, oldest retained id, and end flag.
type OplogPage = (
    Vec<crate::protocol::OperationEntry>,
    Option<OperationId>,
    Option<OperationId>,
    bool,
);

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
) -> Result<OplogPage, CoreError> {
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
    /// Reads one session's push capabilities for git-service
    /// authorization. Requires active authority and holder identity like
    /// [`HostedCoordinator::check_session`], then returns the cloned
    /// capability set so the receive path can flag each command without
    /// holding session state.
    ///
    /// # Errors
    /// - [`ErrorCode::ECancelled`] when `cancel` or shutdown fired.
    /// - [`ErrorCode::EForbidden`] on unknown session, expired authority,
    ///   or a caller principal that is not the session holder.
    pub async fn git_push_capabilities(
        &self,
        caller: &Principal,
        session: SessionId,
        cancel: &Cancel,
    ) -> Result<Capabilities, CoreError> {
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
        Ok(live.row().capabilities.clone())
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
    /// Expired event rows deleted through the lane in this pass.
    pub events_deleted: usize,
    /// Live read leases inspected for expiry in this pass.
    pub leases_examined: usize,
    /// Expired read leases dropped in this pass.
    pub leases_expired: usize,
    /// Service receipt rows scanned in this pass.
    pub service_receipts_examined: usize,
    /// Expired service receipt rows deleted through the lane in this pass.
    pub service_receipts_deleted: usize,
}

impl RetentionReport {
    /// True when the pass deleted nothing durable and expired no leases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts_deleted == 0
            && self.sessions_deleted == 0
            && self.events_deleted == 0
            && self.service_receipts_deleted == 0
            && self.leases_expired == 0
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
        let horizon = self.event_retention_seconds.load(Ordering::Relaxed);
        let receipt_cutoff_millis = u64::try_from(
            current
                .wall
                .duration_since(jiff::Timestamp::UNIX_EPOCH)
                .as_millis(),
        )
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "retention clock millis overflow u64"))?
        .saturating_sub(horizon.saturating_mul(1_000));
        let receipt_after = self
            .receipt_sweep_cursor
            .lock()
            .map_err(|_| CoreError::new(ErrorCode::EIo, "receipt sweep cursor is poisoned"))?
            .clone();
        let receipt_sweep = sweep_service_receipts_page(
            &self.store,
            receipt_cutoff_millis,
            Store::SWEEP_EVENTS_PAGE_ROWS,
            receipt_after.as_deref(),
        )?;
        let cutoff = current.wall.duration_since(jiff::Timestamp::UNIX_EPOCH);
        let cutoff_millis = u64::try_from(cutoff.as_millis()).map_err(|_| {
            CoreError::new(ErrorCode::ELimit, "retention clock millis overflow u64")
        })?;
        let cutoff_millis = cutoff_millis.saturating_sub(horizon.saturating_mul(1_000));
        let event_deletions = self
            .store
            .sweep_events_page(cutoff_millis, Store::SWEEP_EVENTS_PAGE_ROWS)?;
        fn advance_receipt_cursor(
            coordinator: &HostedCoordinator,
            next_after: Option<Vec<u8>>,
        ) -> Result<(), CoreError> {
            *coordinator.receipt_sweep_cursor.lock().map_err(|_| {
                CoreError::new(ErrorCode::EIo, "receipt sweep cursor is poisoned")
            })? = next_after;
            Ok(())
        }
        let report = RetentionReport {
            receipts_examined: receipts_page.examined_rows,
            receipts_deleted: receipts_page.deletions.len(),
            sessions_examined: sessions_page.examined_rows,
            sessions_deleted: sessions_page.deletions.len(),
            events_deleted: event_deletions.len(),
            leases_examined,
            leases_expired,
            service_receipts_examined: receipt_sweep.examined,
            service_receipts_deleted: receipt_sweep.deletions.len(),
        };
        // Lease expiry never publishes: it frees in-memory guards only. The
        // lane commit runs only when durable receipts/sessions/events need it.
        let durable_empty = report.receipts_deleted == 0
            && report.sessions_deleted == 0
            && report.events_deleted == 0
            && report.service_receipts_deleted == 0;
        if durable_empty && sessions_page.cursors == loaded.sweep {
            advance_receipt_cursor(self, receipt_sweep.next_after)?;
            return Ok(report);
        }
        let mut facts = receipts_page.deletions;
        facts.extend(sessions_page.deletions);
        facts.extend(event_deletions);
        facts.extend(receipt_sweep.deletions);
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
        advance_receipt_cursor(self, receipt_sweep.next_after)?;
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
        Method::Compare => "compare needs a merge-base walk with bounded ahead and behind counts",
        Method::Search => {
            "search needs the core-owned search pool plus lease cursors over bounded parallel scans"
        }
        Method::Archive => "archive needs a streaming body writer under the reply credit window",
        Method::RemoteRefs => {
            "remote.refs needs an ls-refs round-trip against an explicit remote URL"
        }
        _ => "only compare, search, archive, and remote.refs lack hosted read arms",
    }
}

/// Resolves one revision to its root tree: the shared root every
/// browsing read serves from. Workspaces name a workcopy, not a tree.
/// `resolve_search_root` is the helper `search` reuses.
fn resolve_search_root(store: &Store, at: &RevisionRef) -> Result<(ViewInfo, Oid), CoreError> {
    let view = current_view(store)?;
    let root = super::reads::revision_tree(store, at)?;
    Ok((view, root))
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
    use crate::attestation::Progress;
    use crate::capability::{AttestKind, AttestResult};
    use crate::change::{ClaimId, LeaseId, RequestId, StoreId};
    use crate::commit::ProvenanceClaims;
    use crate::conflict::{Signature, TzOffset};
    use crate::coord::claims::{ClaimClock, seal_acquire};
    use crate::coord::receipt;
    use crate::coord::rows::{ReceiptRow, Retained, SweepCursors, Usage, encode, receipt_key};
    use crate::coord::service_receipts::{
        SERVICE_RECEIPT_VERSION, ServiceReceipt, lookup_service_receipt, store_service_receipt,
    };
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::index::RepoPath;
    use crate::protocol::{
        AttestAddArgs, AttestListArgs, AttestSignature, AttestStatement, BoundedList,
        ClaimHolderFilter, ClaimListArgs, ClaimMode, ClaimTtl, GitCommitArgs, Method,
        Mutation as WireMutation, MutationOutcome, OpLogArgs, PageCursor, PageLimit, PageRequest,
        PinArgs, QueryDigest, ReceiptRef, TagSetArgs, Timestamp, UndoArgs, UndoReply, UndoSummary,
    };
    use crate::refdata::{RefExpect, RefName};
    use crate::store::PreparationBudget;
    use crate::store::types::FactExpectation;
    use crate::store::types::{FactMutation, FactTable};
    use crate::store::{EventContext, EventSource, ObjectKind, Store};

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

    /// One interactive slot, so a second interactive read of the repository
    /// can only be admitted while the first has released its slot.
    fn one_interactive_slot() -> AdmissionLimits {
        let mut limits = AdmissionLimits::reference_profile();
        limits.interactive.slots = 1;
        limits.storage.interactive = 1;
        limits.repo.ordinary = 7;
        limits
    }

    fn coordinator_with_limits(
        limits: AdmissionLimits,
    ) -> (TempRoot, HostedCoordinator, Principal) {
        let temp = TempRoot::new("read-limits");
        let store = Arc::new(
            Store::create(
                &temp.0,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create store"),
        );
        let owner = Principal::from_peer_uid(1000);
        let coord =
            HostedCoordinator::open_with_limits(store, owner.clone(), temp.0.clone(), limits)
                .expect("open coordinator");
        (temp, coord, owner)
    }

    fn poll_args(wait_ms: u32) -> crate::protocol::EventsTailArgs {
        tail_query(0, None, Some(wait_ms))
    }

    /// A parked long poll must not hold its interactive slot across the
    /// wait: with one slot, a `refs.list` of the same repository is admitted
    /// during the poll instead of refused after its admission wait.
    #[tokio::test]
    async fn parked_poll_releases_its_admission_slot_between_scans() {
        let (_temp, coord, owner) = coordinator_with_limits(one_interactive_slot());
        let coord = Arc::new(coord);
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let poll = tokio::spawn({
            let coord = Arc::clone(&coord);
            let owner = owner.clone();
            let cancel = cancel.clone();
            async move {
                coord
                    .read(
                        &owner,
                        session,
                        Request::EventsTail(Box::new(poll_args(1500))),
                        &cancel,
                    )
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let _listed = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            crate::protocol::RefsListArgs {
                prefix: None,
                after: None,
                limit: None,
            },
        )
        .await;
        let parked = poll.await.expect("poll joins").expect("poll serves");
        assert!(
            matches!(parked, Reply::EventsTail(_)),
            "poll answers its own reply"
        );
    }

    /// A parked long poll rechecks its session when the wait ends: a session
    /// closed during the wait cannot finish a poll it was parked on.
    #[tokio::test]
    async fn parked_poll_refuses_a_session_that_lost_authority() {
        let (_temp, coord, owner) = coordinator();
        let coord = Arc::new(coord);
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let poll = tokio::spawn({
            let coord = Arc::clone(&coord);
            let owner = owner.clone();
            let cancel = cancel.clone();
            async move {
                coord
                    .read(
                        &owner,
                        session,
                        Request::EventsTail(Box::new(poll_args(1500))),
                        &cancel,
                    )
                    .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        coord
            .close_session(session, &cancel)
            .await
            .expect("close session");
        let outcome = poll.await.expect("poll joins");
        let err = outcome.expect_err("a closed session must not finish the poll");
        assert_eq!(err.code, ErrorCode::EForbidden);
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
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish receipt");
        let checkpoint = |_: Progress| Ok::<(), CoreError>(());
        match coord
            .prepare_for_dispatch(session, request, &checkpoint, None)
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

    fn seed_refs(coord: &HostedCoordinator, updates: &[(&str, u8)]) {
        use crate::refdata::{RefChange, RefExpect, RefTransaction, RefUpdate};
        use crate::refs::prepare_checked_transaction;

        let oid = |n: u8| Oid::from_hex(&format!("{n:02x}").repeat(20)).expect("oid");
        let transaction = RefTransaction::new(
            HashKind::Sha1,
            updates
                .iter()
                .map(|(name, n)| RefUpdate {
                    name: RefName::new(*name).expect("ref name"),
                    expected: RefExpect::Absent,
                    change: RefChange::Set(crate::refdata::RefTarget::Direct(oid(*n))),
                })
                .collect(),
        )
        .expect("ref transaction");
        let prepared =
            prepare_checked_transaction(coord.store(), &transaction).expect("prepare refs");
        coord
            .store()
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::ReceivePack,
                &EventContext::default(),
            )
            .expect("publish refs");
    }

    fn seed_branch_refs(coord: &HostedCoordinator) {
        seed_refs(
            coord,
            &[
                ("refs/heads/feat", 2),
                ("refs/heads/main", 1),
                ("refs/tags/v1", 3),
            ],
        );
    }

    async fn refs_list(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::RefsListArgs,
    ) -> crate::protocol::RefsListReply {
        let reply = coord
            .read(owner, session, Request::RefsList(Box::new(args)), cancel)
            .await
            .expect("refs.list serves");
        let Reply::RefsList(page) = reply else {
            panic!("refs.list must answer its own reply");
        };
        *page
    }

    fn read_fixtures(store: &Store) -> (Head, Head, Head) {
        use crate::workcopy::tree::{TreeItem, TreeMode, encode_tree};
        let put_blob = |bytes: &[u8]| {
            let length = u64::try_from(bytes.len()).expect("object length");
            let prepared = store
                .prepare(crate::store::types::ObjectKind::Blob, length, bytes, None)
                .expect("prepare blob");
            let oid = prepared.oid();
            store
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish blob");
            oid
        };
        let put_tree = |items: &[(&str, TreeMode, Oid)]| {
            let encoded = encode_tree(
                &items
                    .iter()
                    .map(|(name, mode, oid)| TreeItem {
                        name: name.as_bytes().to_vec(),
                        mode: *mode,
                        oid: *oid,
                    })
                    .collect::<Vec<_>>(),
            );
            let length = u64::try_from(encoded.len()).expect("object length");
            let prepared = store
                .prepare(
                    crate::store::types::ObjectKind::Tree,
                    length,
                    encoded.as_slice(),
                    None,
                )
                .expect("prepare tree");
            let oid = prepared.oid();
            store
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish tree");
            oid
        };
        let signature = || crate::conflict::Signature {
            name: ByteString::from("ada"),
            email: ByteString::from("ada@example.com"),
            timestamp: 1_700_000_000,
            offset: crate::conflict::TzOffset::new(false, 0).expect("tz offset"),
        };
        let new_commit = |tree: Oid,
                          parents: Vec<Head>,
                          message: &str,
                          change: Option<crate::change::ChangeId>| {
            crate::ops::new(
                store,
                crate::ops::NewRequest {
                    tree,
                    parents,
                    author: signature(),
                    committer: signature(),
                    message: ByteString::from(message),
                    change_id: change,
                    predecessor: None,
                    provenance: None,
                },
            )
            .expect("new commit")
            .head
        };
        let file = crate::index::FileMode::Regular;
        let blob_a = put_blob(b"one\ntwo\n");
        let tree_a = put_tree(&[("f.txt", TreeMode::File(file), blob_a)]);
        let head_a = new_commit(tree_a, Vec::new(), "first", None);
        let blob_b = put_blob(b"one\nTWO\n");
        let blob_g = put_blob(b"new\n");
        let tree_b = put_tree(&[
            ("f.txt", TreeMode::File(file), blob_b),
            ("g.txt", TreeMode::File(file), blob_g),
        ]);
        let change_b = crate::change::ChangeId::from_bytes([7; 16]);
        let head_b = new_commit(tree_b, vec![head_a], "second", Some(change_b));
        let head_b2 = new_commit(tree_b, vec![head_a], "second rewrite", Some(change_b));
        (head_a, head_b, head_b2)
    }

    fn seed_ref_oid(coord: &HostedCoordinator, name: &str, oid: Oid) {
        use crate::refdata::{RefChange, RefExpect, RefTransaction, RefUpdate};
        let transaction = RefTransaction::new(
            HashKind::Sha1,
            vec![RefUpdate {
                name: RefName::new(name).expect("ref name"),
                expected: RefExpect::Absent,
                change: RefChange::Set(crate::refdata::RefTarget::Direct(oid)),
            }],
        )
        .expect("ref transaction");
        let prepared = crate::refs::prepare_checked_transaction(coord.store(), &transaction)
            .expect("prepare refs");
        coord
            .store()
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::ReceivePack,
                &EventContext::default(),
            )
            .expect("publish refs");
    }

    async fn log_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::LogArgs,
    ) -> crate::protocol::LogReply {
        let reply = coord
            .read(owner, session, Request::Log(Box::new(args)), cancel)
            .await
            .expect("log serves");
        let Reply::Log(page) = reply else {
            panic!("log must answer its own reply");
        };
        *page
    }

    async fn query_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::QueryArgs,
    ) -> crate::protocol::QueryReply {
        let reply = coord
            .read(owner, session, Request::Query(Box::new(args)), cancel)
            .await
            .expect("query serves");
        let Reply::Query(page) = reply else {
            panic!("query must answer its own reply");
        };
        *page
    }

    async fn diff_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::DiffArgs,
    ) -> crate::protocol::DiffReply {
        let reply = coord
            .read(owner, session, Request::Diff(Box::new(args)), cancel)
            .await
            .expect("diff serves");
        let Reply::Diff(page) = reply else {
            panic!("diff must answer its own reply");
        };
        *page
    }

    async fn blame_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::BlameArgs,
    ) -> crate::protocol::BlameReply {
        let reply = coord
            .read(owner, session, Request::Blame(Box::new(args)), cancel)
            .await
            .expect("blame serves");
        let Reply::Blame(page) = reply else {
            panic!("blame must answer its own reply");
        };
        *page
    }

    async fn status_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::StatusArgs,
    ) -> crate::protocol::StatusReply {
        let reply = coord
            .read(owner, session, Request::Status(Box::new(args)), cancel)
            .await
            .expect("status serves");
        let Reply::Status(page) = reply else {
            panic!("status must answer its own reply");
        };
        *page
    }

    #[tokio::test]
    async fn log_serves_newest_first_with_lease_continuation() {
        use crate::protocol::{LogArgs, PageRequest, RevsetText};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (head_a, head_b, _) = read_fixtures(coord.store());
        let oid_b = match head_b {
            Head::Git { oid } => oid,
            Head::Conflicted { .. } => panic!("fixture head is git"),
        };
        seed_ref_oid(&coord, "refs/heads/main", oid_b);
        let first = log_of(
            &coord,
            &owner,
            session,
            &cancel,
            LogArgs {
                revset: RevsetText::new("ancestors(main)").expect("revset"),
                page: PageRequest {
                    limit: Some(page_limit_1()),
                    cursor: None,
                },
            },
        )
        .await;
        assert_eq!(first.entries.items.len(), 1);
        assert_eq!(first.entries.items[0].head, head_b);
        assert_eq!(first.entries.items[0].subject.as_bytes(), b"second");
        let cursor = first.entries.next.clone().expect("continuation");
        let second = log_of(
            &coord,
            &owner,
            session,
            &cancel,
            LogArgs {
                revset: RevsetText::new("ancestors(main)").expect("revset"),
                page: PageRequest {
                    limit: Some(page_limit_1()),
                    cursor: Some(cursor),
                },
            },
        )
        .await;
        assert_eq!(second.entries.items.len(), 1);
        assert_eq!(second.entries.items[0].head, head_a);
        assert_eq!(second.entries.next, None);
        let bad = coord
            .read(
                &owner,
                session,
                Request::Log(Box::new(LogArgs {
                    revset: RevsetText::new("main |%%").expect("revset"),
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("malformed revset refuses");
        assert_eq!(bad.code, ErrorCode::EInvalid);
    }

    #[tokio::test]
    async fn query_groups_divergent_heads() {
        use crate::protocol::{PageRequest, QueryArgs, RevsetText};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (_, head_b, head_b2) = read_fixtures(coord.store());
        let oid_of = |head: Head| match head {
            Head::Git { oid } => oid,
            Head::Conflicted { .. } => panic!("fixture head is git"),
        };
        seed_ref_oid(&coord, "refs/heads/main", oid_of(head_b));
        seed_ref_oid(&coord, "refs/heads/feat", oid_of(head_b2));
        let reply = query_of(
            &coord,
            &owner,
            session,
            &cancel,
            QueryArgs {
                revset: RevsetText::new("main | feat").expect("revset"),
                page: PageRequest::default(),
            },
        )
        .await;
        assert_eq!(reply.matches.items.len(), 1);
        let matched = &reply.matches.items[0];
        assert!(matched.heads.contains(&head_b), "first head present");
        assert!(matched.heads.contains(&head_b2), "second head present");
        assert_eq!(reply.matches.next, None);
    }

    #[tokio::test]
    async fn diff_renders_unified_patch_and_pages() {
        use crate::protocol::{DiffArgs, PageRequest, PathSelection, RevisionRef};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (head_a, head_b, _) = read_fixtures(coord.store());
        let args = |cursor: Option<PageCursor>| DiffArgs {
            left: RevisionRef::Head { head: head_a },
            right: RevisionRef::Head { head: head_b },
            paths: PathSelection::All,
            page: PageRequest {
                limit: Some(page_limit_1()),
                cursor,
            },
        };
        let first = diff_of(&coord, &owner, session, &cancel, args(None)).await;
        assert_eq!(first.files.items.len(), 1);
        let changed = &first.files.items[0];
        assert_eq!(changed.path.as_bytes(), b"f.txt");
        assert_eq!(changed.kind, crate::protocol::DiffKind::Modified);
        let crate::protocol::DiffBody::Unified { patch } = &changed.body else {
            panic!("text change renders unified");
        };
        let crate::protocol::ByteSource::Inline { data } = patch else {
            panic!("small patch inlines");
        };
        let text = String::from_utf8(data.as_bytes().to_vec()).expect("patch is UTF-8");
        assert!(text.contains("-two\n"), "deletion renders: {text}");
        assert!(text.contains("+TWO\n"), "insertion renders: {text}");
        let cursor = first.files.next.clone().expect("continuation");
        let second = diff_of(&coord, &owner, session, &cancel, args(Some(cursor))).await;
        assert_eq!(second.files.items.len(), 1);
        assert_eq!(second.files.items[0].path.as_bytes(), b"g.txt");
        assert_eq!(second.files.items[0].kind, crate::protocol::DiffKind::Added);
        assert_eq!(second.files.next, None);
    }

    #[tokio::test]
    async fn blame_attributes_each_line() {
        use crate::index::RepoPath;
        use crate::protocol::{BlameArgs, LineRange, PageRequest, RevisionRef};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (head_a, head_b, _) = read_fixtures(coord.store());
        let reply = blame_of(
            &coord,
            &owner,
            session,
            &cancel,
            BlameArgs {
                at: RevisionRef::Head { head: head_b },
                path: RepoPath::new("f.txt").expect("path"),
                lines: None,
                page: PageRequest::default(),
            },
        )
        .await;
        assert_eq!(reply.hunks.items.len(), 2);
        assert_eq!(reply.hunks.items[0].head, head_a);
        assert_eq!(reply.hunks.items[0].start_line, 1);
        assert_eq!(reply.hunks.items[1].head, head_b);
        assert_eq!(reply.hunks.items[1].start_line, 2);
        let windowed = blame_of(
            &coord,
            &owner,
            session,
            &cancel,
            BlameArgs {
                at: RevisionRef::Head { head: head_b },
                path: RepoPath::new("f.txt").expect("path"),
                lines: Some(LineRange { start: 2, end: 2 }),
                page: PageRequest::default(),
            },
        )
        .await;
        assert_eq!(windowed.hunks.items.len(), 1);
        assert_eq!(windowed.hunks.items[0].head, head_b);
        let missing = coord
            .read(
                &owner,
                session,
                Request::Blame(Box::new(BlameArgs {
                    at: RevisionRef::Head { head: head_b },
                    path: RepoPath::new("absent.txt").expect("path"),
                    lines: None,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("missing path refuses");
        assert_eq!(missing.code, ErrorCode::ENotFound);
    }

    fn publish_workspace_row(
        coord: &HostedCoordinator,
        id: WorkspaceId,
        state: crate::workspace::WorkspaceState,
        holder: SessionId,
        root: &str,
    ) {
        use crate::store::types::{FactExpectation, FactMutation, FactTable};
        let row = crate::coord::rows::WorkspaceRow {
            state,
            holder,
            root: ByteString::from(root),
        };
        let bytes = postcard::to_allocvec(&row).expect("workspace row encodes");
        coord
            .store()
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Workspaces,
                    key: crate::coord::rows::workspace_key(id).to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(bytes),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish workspace row");
    }

    #[tokio::test]
    async fn status_reports_skip_crawl_and_refuses_auto() {
        use crate::index::RepoPath;
        use crate::protocol::{PageRequest, SnapshotPolicy, StatusArgs};
        use crate::workspace::{NativeWorkspace, Scope, WorkspaceState};
        let (temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (head_a, head_b, _) = read_fixtures(coord.store());
        let _ = head_a;
        let change_b = crate::change::ChangeId::from_bytes([7; 16]);
        let wt = temp.0.join("wt");
        std::fs::create_dir_all(&wt).expect("worktree dir");
        std::fs::write(wt.join("f.txt"), b"one\nTWO\nthird\n").expect("write file");
        std::fs::write(wt.join("h.txt"), b"added\n").expect("write file");
        let id = WorkspaceId::generate();
        publish_workspace_row(
            &coord,
            id,
            WorkspaceState::Native(NativeWorkspace::new(change_b, head_b, Scope::Full)),
            session,
            wt.to_str().expect("utf8 root"),
        );
        let reply = status_of(
            &coord,
            &owner,
            session,
            &cancel,
            StatusArgs {
                workspace: Some(id),
                snapshot: SnapshotPolicy::Skip,
                page: PageRequest::default(),
            },
        )
        .await;
        assert!(!reply.applying);
        assert_eq!(
            reply.change,
            Some(ChangeHead {
                change: change_b,
                head: head_b
            })
        );
        let kinds: Vec<(&[u8], crate::protocol::PathChangeKind)> = reply
            .paths
            .items
            .iter()
            .map(|status| (status.path.as_bytes(), status.change))
            .collect();
        assert!(
            kinds.contains(&(
                b"f.txt".as_slice(),
                crate::protocol::PathChangeKind::Modified
            )),
            "modified reports: {kinds:?}"
        );
        assert!(
            kinds.contains(&(
                b"g.txt".as_slice(),
                crate::protocol::PathChangeKind::Deleted
            )),
            "deleted reports: {kinds:?}"
        );
        assert!(
            kinds.contains(&(b"h.txt".as_slice(), crate::protocol::PathChangeKind::Added)),
            "added reports: {kinds:?}"
        );
        let auto = coord
            .read(
                &owner,
                session,
                Request::Status(Box::new(StatusArgs {
                    workspace: Some(id),
                    snapshot: SnapshotPolicy::Auto,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("auto snapshot refuses");
        assert_eq!(auto.code, ErrorCode::EInvalid);
        let missing = coord
            .read(
                &owner,
                session,
                Request::Status(Box::new(StatusArgs {
                    workspace: None,
                    snapshot: SnapshotPolicy::Skip,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("missing workspace refuses");
        assert_eq!(missing.code, ErrorCode::EInvalid);
        let unknown = coord
            .read(
                &owner,
                session,
                Request::Status(Box::new(StatusArgs {
                    workspace: Some(WorkspaceId::generate()),
                    snapshot: SnapshotPolicy::Skip,
                    page: PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("unknown workspace refuses");
        assert_eq!(unknown.code, ErrorCode::ENotFound);
        let _ = RepoPath::new("f.txt").expect("path");
    }

    fn publish_repo_meta(coord: &HostedCoordinator, branch: &str) {
        use crate::store::types::{FactExpectation, FactMutation, FactTable, RepoMetaRow};
        let row = RepoMetaRow {
            default_branch: RefName::new(branch).expect("branch name"),
        };
        let bytes = postcard::to_allocvec(&row).expect("repo meta encodes");
        coord
            .store()
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::RepoMeta,
                    key: crate::store::types::REPO_META_KEY.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(bytes),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish repo meta");
    }

    async fn stat_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
    ) -> crate::protocol::RepoStatReply {
        let reply = coord
            .read(owner, session, Request::RepoStat(Box::default()), cancel)
            .await
            .expect("repo.stat serves");
        let Reply::RepoStat(page) = reply else {
            panic!("repo.stat must answer its own reply");
        };
        *page
    }

    #[tokio::test]
    async fn repo_stat_serves_store_snapshot() {
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let bare = stat_of(&coord, &owner, session, &cancel).await;
        assert_eq!(bare.store_id, coord.store().store_id());
        assert_eq!(bare.object_format, coord.store().hash_kind());
        assert_eq!(bare.default_branch, None);
        assert!(!bare.quarantined);
        assert_eq!(bare.view, coord.view().expect("coordinator view"));
        let (head, oldest) = coord.store().event_head().expect("event head");
        assert_eq!((bare.head, bare.oldest), (head, oldest));
        publish_repo_meta(&coord, "refs/heads/main");
        let meta = stat_of(&coord, &owner, session, &cancel).await;
        assert_eq!(
            meta.default_branch
                .as_ref()
                .map(|name| name.as_bytes().to_vec()),
            Some(b"refs/heads/main".to_vec())
        );
        assert_eq!(meta.view, coord.view().expect("coordinator view"));
    }

    async fn tree_of(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::TreeArgs,
    ) -> crate::protocol::TreeReply {
        let reply = coord
            .read(owner, session, Request::Tree(Box::new(args)), cancel)
            .await
            .expect("tree serves");
        let Reply::Tree(page) = reply else {
            panic!("tree must answer its own reply");
        };
        *page
    }

    #[tokio::test]
    async fn tree_lists_root_with_keyset_paging() {
        use crate::protocol::{CommitRev, PageLimit, TreeArgs};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (_, head_b, _) = read_fixtures(coord.store());
        let commit = match head_b {
            Head::Git { oid } => oid,
            Head::Conflicted { .. } => panic!("fixture head is git"),
        };
        let args = |limit: u32, after: Option<&[u8]>| TreeArgs {
            rev: CommitRev::Commit(commit),
            path: None,
            limit: PageLimit::new(limit).ok(),
            after: after.map(ByteString::from),
        };
        let first = tree_of(&coord, &owner, session, &cancel, args(1, None)).await;
        assert_eq!(first.entries.items.len(), 1);
        assert_eq!(first.entries.items[0].name.as_bytes(), b"f.txt");
        assert_eq!(first.entries.items[0].size, Some(8));
        let next = first.entries.next_after.clone().expect("continuation");
        let second = tree_of(
            &coord,
            &owner,
            session,
            &cancel,
            args(1, Some(next.as_bytes())),
        )
        .await;
        assert_eq!(second.entries.items.len(), 1);
        assert_eq!(second.entries.items[0].name.as_bytes(), b"g.txt");
        assert_eq!(second.entries.items[0].size, Some(4));
        assert_eq!(second.entries.next_after, None);
        let bad = coord
            .read(
                &owner,
                session,
                Request::Tree(Box::new(args(1, Some(b"nope")))),
                &cancel,
            )
            .await
            .expect_err("unknown tree cursor refuses");
        assert_eq!(bad.code, ErrorCode::EInvalid);
        let blob_path = coord
            .read(
                &owner,
                session,
                Request::Tree(Box::new(TreeArgs {
                    rev: CommitRev::Commit(commit),
                    path: Some(crate::index::RepoPath::new("f.txt").expect("path")),
                    limit: None,
                    after: None,
                })),
                &cancel,
            )
            .await
            .expect_err("blob path refuses");
        assert_eq!(blob_path.code, ErrorCode::EInvalid);
    }

    #[tokio::test]
    async fn tree_resolves_ref_revisions() {
        use crate::protocol::{CommitRev, TreeArgs};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (_, head_b, _) = read_fixtures(coord.store());
        let commit = match head_b {
            Head::Git { oid } => oid,
            Head::Conflicted { .. } => panic!("fixture head is git"),
        };
        seed_ref_oid(&coord, "refs/heads/main", commit);
        let reply = tree_of(
            &coord,
            &owner,
            session,
            &cancel,
            TreeArgs {
                rev: CommitRev::Ref(RefName::new("refs/heads/main").expect("ref")),
                path: None,
                limit: None,
                after: None,
            },
        )
        .await;
        assert_eq!(reply.entries.items.len(), 2);
        let unknown = coord
            .read(
                &owner,
                session,
                Request::Tree(Box::new(TreeArgs {
                    rev: CommitRev::Ref(RefName::new("refs/heads/nope").expect("ref")),
                    path: None,
                    limit: None,
                    after: None,
                })),
                &cancel,
            )
            .await
            .expect_err("unknown ref refuses");
        assert_eq!(unknown.code, ErrorCode::ENotFound);
    }

    #[tokio::test]
    async fn head_tree_refuses_conflicted_heads() {
        let (_temp, coord, _owner) = coordinator();
        let (head_a, _, _) = read_fixtures(coord.store());
        let tree_a = crate::coord::reads::head_tree(coord.store(), &head_a).expect("tree");
        let signature = || crate::conflict::Signature {
            name: ByteString::from("ada"),
            email: ByteString::from("ada@example.com"),
            timestamp: 1_700_000_000,
            offset: crate::conflict::TzOffset::new(false, 0).expect("tz offset"),
        };
        let mut preparer = crate::records::Records::new(coord.store()).batch_preparer();
        let conflicted = preparer
            .add_native_commit(crate::commit::NativeCommitInput {
                change_id: crate::change::ChangeId::generate(),
                tree: crate::merge::Merge::from_vec(vec![tree_a, tree_a, tree_a]),
                parents: Vec::new(),
                predecessor: None,
                author: signature(),
                committer: signature(),
                extra_headers: Vec::new(),
                message: ByteString::from("conflicted"),
                provenance: None,
            })
            .expect("prepare conflicted");
        let batch = preparer.finish().expect("finish batch");
        coord
            .store()
            .publish(
                batch.prepared_objects,
                &batch.mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish conflicted");
        let err = crate::coord::reads::head_tree(coord.store(), &conflicted)
            .expect_err("conflicted tree refuses");
        assert_eq!(err.code, ErrorCode::EConflicted);
    }

    #[tokio::test]
    async fn hosted_blob_read_refuses_past_bound() {
        let (_temp, coord, _owner) = coordinator();
        let big = vec![b'x'; 17_000_000];
        let length = u64::try_from(big.len()).expect("object length");
        let prepared = coord
            .store()
            .prepare(
                crate::store::types::ObjectKind::Blob,
                length,
                big.as_slice(),
                None,
            )
            .expect("prepare big blob");
        let oid = prepared.oid();
        coord
            .store()
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish big blob");
        let err = crate::coord::reads::blob_bytes(coord.store(), oid)
            .expect_err("oversize blob refuses before loading");
        assert_eq!(err.code, ErrorCode::ELimit);
    }

    #[tokio::test]
    async fn diff_added_huge_file_refuses_inline_bound() {
        use crate::protocol::{DiffArgs, PathSelection, RevisionRef};
        use crate::workcopy::tree::{TreeItem, TreeMode, encode_tree};
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let (head_a, _, _) = read_fixtures(coord.store());
        let big = vec![b'y'; 17_000_000];
        let length = u64::try_from(big.len()).expect("object length");
        let prepared = coord
            .store()
            .prepare(
                crate::store::types::ObjectKind::Blob,
                length,
                big.as_slice(),
                None,
            )
            .expect("prepare big blob");
        let blob = prepared.oid();
        coord
            .store()
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish big blob");
        let encoded = encode_tree(&[TreeItem {
            name: b"big.bin".to_vec(),
            mode: TreeMode::File(crate::index::FileMode::Regular),
            oid: blob,
        }]);
        let tree_length = u64::try_from(encoded.len()).expect("object length");
        let prepared = coord
            .store()
            .prepare(
                crate::store::types::ObjectKind::Tree,
                tree_length,
                encoded.as_slice(),
                None,
            )
            .expect("prepare big tree");
        let tree = prepared.oid();
        coord
            .store()
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish big tree");
        let signature = crate::conflict::Signature {
            name: ByteString::from("ada"),
            email: ByteString::from("ada@example.com"),
            timestamp: 1_700_000_000,
            offset: crate::conflict::TzOffset::new(false, 0).expect("tz offset"),
        };
        let head_big = crate::ops::new(
            coord.store(),
            crate::ops::NewRequest {
                tree,
                parents: vec![head_a],
                author: signature.clone(),
                committer: signature,
                message: ByteString::from("big"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("new commit")
        .head;
        let err = coord
            .read(
                &owner,
                session,
                Request::Diff(Box::new(DiffArgs {
                    left: RevisionRef::Head { head: head_a },
                    right: RevisionRef::Head { head: head_big },
                    paths: PathSelection::All,
                    page: crate::protocol::PageRequest::default(),
                })),
                &cancel,
            )
            .await
            .expect_err("huge added file refuses the inline bound");
        assert_eq!(err.code, ErrorCode::ELimit);
    }

    #[tokio::test]
    async fn refs_list_serves_prefix_seek_with_as_of() {
        use crate::protocol::RefsListArgs;

        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_branch_refs(&coord);

        let query = |prefix: Option<&str>, after: Option<&str>, limit: Option<u32>| RefsListArgs {
            prefix: prefix.map(ByteString::from),
            after: after.map(|text| RefName::new(text).expect("cursor name")),
            limit: limit.map(|rows| PageLimit::new(rows).expect("page limit")),
        };
        let names = |page: &crate::protocol::RefsListReply| {
            page.refs
                .items
                .iter()
                .map(|entry| entry.name.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };

        let full = refs_list(&coord, &owner, session, &cancel, query(None, None, None)).await;
        assert_eq!(
            names(&full),
            [
                b"refs/heads/feat".to_vec(),
                b"refs/heads/main".to_vec(),
                b"refs/tags/v1".to_vec()
            ]
        );
        assert_eq!(full.refs.next_after, None);
        assert_eq!(full.as_of, 3);

        let heads = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            query(Some("refs/heads/"), None, None),
        )
        .await;
        assert_eq!(
            names(&heads),
            [b"refs/heads/feat".to_vec(), b"refs/heads/main".to_vec()]
        );
        assert_eq!(heads.as_of, 3);

        let exact = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            query(Some("refs/heads/main"), None, None),
        )
        .await;
        assert_eq!(names(&exact), [b"refs/heads/main".to_vec()]);

        let rest = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            query(Some("refs/heads/"), Some("refs/heads/feat"), None),
        )
        .await;
        assert_eq!(names(&rest), [b"refs/heads/main".to_vec()]);
        assert_eq!(rest.refs.next_after, None);

        let first = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            query(Some("refs/heads/"), None, Some(1)),
        )
        .await;
        assert_eq!(names(&first), [b"refs/heads/feat".to_vec()]);
        let cursor = first.refs.next_after.clone().expect("more remains");
        assert_eq!(cursor.as_bytes(), b"refs/heads/feat");
        let second = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            query(Some("refs/heads/"), Some("refs/heads/feat"), Some(1)),
        )
        .await;
        assert_eq!(names(&second), [b"refs/heads/main".to_vec()]);
        assert_eq!(second.refs.next_after, None);

        let err = coord
            .read(
                &owner,
                session,
                Request::RefsList(Box::new(query(
                    Some("refs/heads/"),
                    Some("refs/tags/v1"),
                    None,
                ))),
                &cancel,
            )
            .await
            .expect_err("cursor outside the prefix is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    async fn events_tail(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: crate::protocol::EventsTailArgs,
    ) -> crate::protocol::EventsTailReply {
        let reply = coord
            .read(owner, session, Request::EventsTail(Box::new(args)), cancel)
            .await
            .expect("events.tail serves");
        let Reply::EventsTail(tail) = reply else {
            panic!("events.tail must answer its own reply");
        };
        *tail
    }

    fn tail_query(
        after: u64,
        limit: Option<u32>,
        wait_ms: Option<u32>,
    ) -> crate::protocol::EventsTailArgs {
        crate::protocol::EventsTailArgs {
            after,
            limit: limit.map(|rows| PageLimit::new(rows).expect("page limit")),
            wait_ms,
            prefix: None,
        }
    }

    #[tokio::test]
    async fn events_tail_serves_after_with_head() {
        use crate::refdata::RefTarget;

        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_branch_refs(&coord);

        let tail = events_tail(&coord, &owner, session, &cancel, tail_query(0, None, None)).await;
        assert_eq!(tail.head, 3);
        assert_eq!(tail.oldest, 1);
        assert!(!tail.expired);
        let seqs: Vec<u64> = tail.events.iter().map(|event| event.seq).collect();
        assert_eq!(seqs, [1, 2, 3]);
        let names: Vec<Vec<u8>> = tail
            .events
            .iter()
            .map(|event| event.name.as_bytes().to_vec())
            .collect();
        assert_eq!(
            names,
            [
                b"refs/heads/feat".to_vec(),
                b"refs/heads/main".to_vec(),
                b"refs/tags/v1".to_vec()
            ]
        );
        for event in &tail.events {
            assert_eq!(event.source, EventSource::ReceivePack);
            assert!(event.old.is_none());
            assert!(matches!(event.new, Some(RefTarget::Direct(_))));
        }
        let oid_main = Oid::from_hex(&"01".repeat(20)).expect("oid");
        assert_eq!(tail.events[1].new, Some(RefTarget::Direct(oid_main)));

        let tail = events_tail(&coord, &owner, session, &cancel, tail_query(2, None, None)).await;
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].seq, 3);
        assert!(!tail.expired);

        let tail = events_tail(
            &coord,
            &owner,
            session,
            &cancel,
            crate::protocol::EventsTailArgs {
                after: 0,
                limit: None,
                wait_ms: None,
                prefix: Some(ByteString::from("refs/tags/")),
            },
        )
        .await;
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].seq, 3);

        let list = refs_list(
            &coord,
            &owner,
            session,
            &cancel,
            crate::protocol::RefsListArgs {
                prefix: None,
                after: None,
                limit: None,
            },
        )
        .await;
        assert_eq!(tail.view, list.view);
        assert_eq!(list.as_of, tail.head);
    }

    #[tokio::test]
    async fn events_tail_long_poll_wakes_on_publish() {
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_branch_refs(&coord);

        let tail_fut = events_tail(
            &coord,
            &owner,
            session,
            &cancel,
            tail_query(3, None, Some(5000)),
        );
        let publish_fut = async {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            seed_refs(&coord, &[("refs/heads/next", 4)]);
        };
        let (tail, ()) = tokio::join!(tail_fut, publish_fut);
        assert_eq!(tail.events.len(), 1);
        assert_eq!(tail.events[0].seq, 4);
        assert_eq!(tail.events[0].name.as_bytes(), b"refs/heads/next");
        assert!(!tail.expired);
    }

    /// A row-count limit alone cannot keep the reply encodable: ref names
    /// and request ids have no length bound, so 300 events with 60 KiB
    /// names must come back as partial pages that still advance the
    /// follower, and the encoded page must fit the control bound.
    #[tokio::test]
    async fn events_tail_bounds_long_names_in_encoded_bytes() {
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        let names: Vec<String> = (0..300u32)
            .map(|index| format!("refs/heads/{index:05}-{}", "x".repeat(61_400)))
            .collect();
        seed_refs(
            &coord,
            &names
                .iter()
                .map(|name| (name.as_str(), 1))
                .collect::<Vec<_>>(),
        );
        let first = events_tail(
            &coord,
            &owner,
            session,
            &cancel,
            tail_query(0, Some(1000), None),
        )
        .await;
        assert!(!first.expired);
        assert!(
            first.events.len() < 300,
            "the byte budget stops the page before the row limit: {}",
            first.events.len()
        );
        assert!(
            !first.events.is_empty(),
            "a partial page still delivers events"
        );
        let encoded = sonic_rs::to_string(&first).expect("reply encodes");
        assert!(
            encoded.len() < MAX_CONTROL_FRAME_BYTES,
            "partial page uses {} of {} control bytes",
            encoded.len(),
            MAX_CONTROL_FRAME_BYTES
        );
        let resume = events_tail(
            &coord,
            &owner,
            session,
            &cancel,
            tail_query(first.events.last().expect("last seq").seq, Some(1000), None),
        )
        .await;
        assert!(
            !resume.events.is_empty(),
            "the follower resumes past the partial page"
        );
        assert!(
            resume.events[0].seq > first.events.last().expect("last seq").seq,
            "no event repeats across the resume"
        );
    }

    #[test]
    fn tail_expired_holds_the_retention_edge() {
        use super::HostedCoordinator;
        // The documented lost-event case: the follower holds `after=5`
        // and a sweep deletes rows 6 and 7, leaving `oldest=8`.
        assert!(HostedCoordinator::tail_expired(5, 8));
        // The next row survives: no gap, no expiry.
        assert!(!HostedCoordinator::tail_expired(5, 6));
        assert!(!HostedCoordinator::tail_expired(5, 5));
        assert!(!HostedCoordinator::tail_expired(5, 1));
        // A caught-up follower never expires, even at the numeric edge.
        assert!(!HostedCoordinator::tail_expired(u64::MAX, u64::MAX));
        assert!(!HostedCoordinator::tail_expired(u64::MAX - 1, u64::MAX));
    }

    #[tokio::test]
    async fn events_tail_reports_expired_for_pruned_cursor() {
        let (_temp, coord, owner) = coordinator();
        let _runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open session");
        seed_branch_refs(&coord);

        let deletions = coord
            .store()
            .sweep_events_page(u64::MAX, 1_000_000)
            .expect("sweep every event");
        assert!(!deletions.is_empty());
        coord
            .store()
            .publish(
                Vec::new(),
                &deletions,
                EventSource::Lane,
                &EventContext::default(),
            )
            .expect("publish sweep");

        let (head, oldest) = coord.store().event_head().expect("head");
        assert_eq!((head, oldest), (3, 4));
        let tail = events_tail(&coord, &owner, session, &cancel, tail_query(1, None, None)).await;
        assert!(tail.expired);
        assert!(tail.events.is_empty());
        assert_eq!((tail.head, tail.oldest), (3, 4));

        let tail = events_tail(&coord, &owner, session, &cancel, tail_query(3, None, None)).await;
        assert!(!tail.expired);
        assert!(tail.events.is_empty());
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
            .read(&owner, session, Request::OpLog(Box::default()), &cancel)
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
                Request::OpLog(Box::default()),
                &cancel,
            )
            .await
            .expect_err("unknown session is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);

        let err = coord
            .read(
                &stranger(),
                session,
                Request::OpLog(Box::default()),
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
            .read(&owner, session, Request::ClaimList(Box::default()), &cancel)
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
                Request::AttestList(Box::default()),
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
            .read(&owner, session, Request::Status(Box::default()), &cancel)
            .await
            .expect_err("status without a workspace refuses");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(
            err.message.contains("explicit native workspace"),
            "unexpected message: {}",
            err.message
        );

        coord.shutdown();
        runner.abort();
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
                EventSource::LocalPush,
                &EventContext::default(),
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
        runner.abort();
    }

    #[tokio::test]
    async fn retention_sweep_prunes_service_receipts_at_configured_horizon() {
        let (_temp, coord, _) = coordinator();
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        // One hour old: older than the 60-second test horizon, younger
        // than the seven-day default the sweep used before, so the test
        // fails on code that ignores the configured horizon.
        let now_millis = u64::try_from(
            jiff::Timestamp::now()
                .duration_since(jiff::Timestamp::UNIX_EPOCH)
                .as_millis(),
        )
        .expect("wall millis fit u64");
        let receipt = ServiceReceipt {
            version: SERVICE_RECEIPT_VERSION,
            digest: "digest".to_string(),
            exit_code: 0,
            output: Vec::new(),
            error_code: None,
            error_message: None,
            at: now_millis - 3_600_000,
        };
        store_service_receipt(coord.store(), 1000, b"/repo", "req-old", &receipt)
            .expect("seed service receipt");
        coord.set_event_retention_seconds(60);
        let report = coord
            .retention_sweep(&cancel)
            .await
            .expect("sweep prunes at the configured horizon");
        assert_eq!(report.service_receipts_examined, 1);
        assert_eq!(report.service_receipts_deleted, 1);
        assert!(
            lookup_service_receipt(coord.store(), 1000, b"/repo", "req-old")
                .expect("read receipt")
                .is_none(),
            "the aged receipt row must delete"
        );
        coord.shutdown();
        runner.abort();
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
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
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
            .read(&owner, session, Request::OpLog(Box::default()), &cancel)
            .await
            .expect("op.log reads after mutation");
        let Reply::OpLog(page) = reply else {
            panic!("op.log must answer its own reply");
        };
        assert_eq!(page.entries.items.len(), 1);
        assert_eq!(page.entries.items[0].method, Method::TagSet);
        assert_eq!(page.oldest_retained, Some(page.entries.items[0].id));

        coord.shutdown();
        runner.abort();
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
                None,
            )
            .expect("acquire claim");
            coord
                .store()
                .publish(
                    Vec::new(),
                    &change.facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
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
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish commit");
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
                    .publish(
                        Vec::new(),
                        &prepared.mutations,
                        EventSource::LocalPush,
                        &EventContext::default(),
                    )
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
        runner.abort();
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
        runner.abort();
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
        runner.abort();
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
        runner.abort();
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
        runner.abort();
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
        runner.abort();
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
        runner.abort();
    }

    fn signature() -> Signature {
        Signature {
            name: ByteString::from("Lane Test"),
            email: ByteString::from("lane@test.invalid"),
            timestamp: 1_700_000_000,
            offset: TzOffset::UTC,
        }
    }

    async fn submit(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: SessionId,
        cancel: &Cancel,
        args: GitCommitArgs,
    ) -> Oid {
        let request = Request::GitCommit(Box::new(WireMutation {
            request_id: RequestId::generate(),
            args,
        }));
        let checkpoint = |_: Progress| Ok::<(), CoreError>(());
        let prepared = match coord
            .prepare_for_dispatch(session, request, &checkpoint, None)
            .expect("prepare lane commit")
        {
            DispatchReady::Replay(reply) => {
                panic!("distinct commits must not replay: {reply:?}")
            }
            DispatchReady::Prepared(prepared) => *prepared,
        };
        let reply = coord
            .submit_prepared(owner, prepared, cancel)
            .await
            .expect("submit lane commit");
        let Reply::GitCommit(reply) = reply else {
            panic!("git.commit must answer its own reply");
        };
        reply
            .created
            .head
            .as_git()
            .copied()
            .expect("lane commit has a git identity")
    }

    /// Concurrent ref-less lane commits share one batch: without a
    /// ref_update nothing touches refs, so the batch gate admits
    /// overlapping submissions into shared store publications.
    ///
    /// This is the positive batching proof at the lane. The layered
    /// `ref_update: None` path (detached and stash commits) genuinely
    /// groups; branch commits serialize one per batch by design (see the
    /// next test). Four fits the interactive storage permits, so
    /// admission never sheds the race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_detached_commits_share_one_batch() {
        use std::time::Duration;

        use crate::change::ChangeId;

        const SUBMITS: usize = 4;

        let (_temp, coord, owner) = coordinator();
        coord.store().set_commit_linger(Duration::from_millis(10));
        let coord = Arc::new(coord);
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();

        // One shared empty tree; every commit references it.
        let tree = coord
            .store()
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("stage lane tree");
        let tree_oid = tree.oid();
        coord
            .store()
            .publish(
                vec![tree],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish lane tree");

        // Sessions open sequentially up front so the storm is pure
        // submissions.
        let mut sessions = Vec::with_capacity(SUBMITS);
        for _ in 0..SUBMITS {
            let (session, _) = coord
                .open_session(&owner, &SessionOpenArgs::default(), &cancel)
                .await
                .expect("open race session");
            sessions.push(session);
        }

        let before = coord.store().io_stats();
        // Rendezvous so all four submissions hit the lane within
        // microseconds of each other, well inside the 2 ms accumulate
        // window regardless of task-startup jitter.
        let barrier = Arc::new(tokio::sync::Barrier::new(SUBMITS));
        let mut tasks = Vec::with_capacity(SUBMITS);
        for (n, session) in sessions.into_iter().enumerate() {
            let coord = Arc::clone(&coord);
            let owner = owner.clone();
            let cancel = cancel.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                submit(
                    &coord,
                    &owner,
                    session,
                    &cancel,
                    GitCommitArgs {
                        tree: tree_oid,
                        parents: Vec::new(),
                        author: signature(),
                        committer: signature(),
                        message: ByteString::from(format!("lane detached {n}")),
                        change_id: Some(ChangeId::generate()),
                        predecessor: None,
                        ref_update: None,
                    },
                )
                .await
            }));
        }
        let mut oids = Vec::with_capacity(SUBMITS);
        tokio::time::timeout(Duration::from_secs(120), async {
            for task in tasks {
                oids.push(task.await.expect("lane task live"));
            }
        })
        .await
        .expect("lane race completes");

        // Four distinct commits minted: nothing deduplicated or replayed.
        let mut sorted = oids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), SUBMITS, "distinct detached commits");

        // The batching proof: four submissions in fewer store publications,
        // each costing at most one metadata commit.
        let after = coord.store().io_stats();
        let total = u64::try_from(SUBMITS).expect("submission count fits u64");
        let publications = after.publications - before.publications;
        let commits = after.publication_commits - before.publication_commits;
        assert!(
            publications < total,
            "lane batches concurrent submissions: {after:?} vs {before:?}"
        );
        assert!(
            commits <= publications,
            "no batch splits metadata commits: {after:?} vs {before:?}"
        );

        coord.shutdown();
        runner.abort();
    }

    /// Concurrent lane commits on distinct branches share batches: the
    /// lane admits ref-moving mutations with disjoint write-sets into one
    /// batch (`can_admit` refuses only overlapping ref writes and
    /// read/write premise conflicts), so four submissions cost fewer than
    /// four store publications. Distinct ref_updates never CAS-conflict,
    /// so all four land exactly attributed with nothing lost or retried.
    ///
    /// Same-branch pairs still serialize: they collide on the branch name
    /// and the loser retries client-side (covered by
    /// `same_branch_race_resolves` and the lane `test_14`). (CLI
    /// processes cannot reach this layer concurrently with attribution:
    /// one store holds one `HEAD`, and sequential CLI submissions arrive
    /// hundreds of milliseconds apart, far outside the 50 ms windows.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_cross_ref_commits_share_one_batch() {
        use std::time::Duration;

        use crate::change::ChangeId;
        use crate::protocol::{GitCommitArgs, GitCommitRefUpdate, SessionOpenArgs};
        use crate::refdata::resolve;
        use crate::refs::StoreRefs;

        const BRANCHES: usize = 4;

        let (_temp, coord, owner) = coordinator();
        // Widen the store group-commit window past the task-startup spread
        // so overlapping submissions land in shared groups deterministically.
        coord.store().set_commit_linger(Duration::from_millis(10));
        let coord = Arc::new(coord);
        let runner = coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();

        // One shared empty tree; every commit references it.
        let tree = coord
            .store()
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("stage lane tree");
        let tree_oid = tree.oid();
        coord
            .store()
            .publish(
                vec![tree],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish lane tree");

        // One seed commit with no ref move; every branch starts unborn and
        // every first commit parents on the seed.
        let (setup_session, _) = coord
            .open_session(&owner, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("open setup session");
        let seed_oid = submit(
            &coord,
            &owner,
            setup_session,
            &cancel,
            GitCommitArgs {
                tree: tree_oid,
                parents: Vec::new(),
                author: signature(),
                committer: signature(),
                message: ByteString::from("lane seed"),
                change_id: Some(ChangeId::generate()),
                predecessor: None,
                ref_update: None,
            },
        )
        .await;
        let seed_head = Head::Git { oid: seed_oid };

        // Sessions open sequentially up front: any session-open writes
        // stay out of the measured window, and every race task starts
        // with a live session so the storm is pure submissions.
        let mut sessions = Vec::with_capacity(BRANCHES);
        for _ in 0..BRANCHES {
            let (session, _) = coord
                .open_session(&owner, &SessionOpenArgs::default(), &cancel)
                .await
                .expect("open race session");
            sessions.push(session);
        }

        let before = coord.store().io_stats();
        // Rendezvous so all four submissions hit the lane within
        // microseconds of each other, well inside the 2 ms accumulate
        // window regardless of task-startup jitter.
        let barrier = Arc::new(tokio::sync::Barrier::new(BRANCHES));
        let mut tasks = Vec::with_capacity(BRANCHES);
        for (branch_no, session) in sessions.into_iter().enumerate() {
            let coord = Arc::clone(&coord);
            let owner = owner.clone();
            let cancel = cancel.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let branch =
                    RefName::new(format!("refs/heads/lane-{branch_no}")).expect("branch name");
                submit(
                    &coord,
                    &owner,
                    session,
                    &cancel,
                    GitCommitArgs {
                        tree: tree_oid,
                        parents: vec![seed_head],
                        author: signature(),
                        committer: signature(),
                        message: ByteString::from(format!("lane commit {branch_no}")),
                        change_id: Some(ChangeId::generate()),
                        predecessor: None,
                        ref_update: Some(GitCommitRefUpdate {
                            name: branch,
                            expected: RefExpect::Absent,
                        }),
                    },
                )
                .await
            }));
        }
        let mut finals = Vec::with_capacity(BRANCHES);
        tokio::time::timeout(Duration::from_secs(120), async {
            for task in tasks {
                finals.push(task.await.expect("lane task live"));
            }
        })
        .await
        .expect("lane race completes");

        // Every branch holds exactly its own tip; tips are distinct.
        let refs = StoreRefs::new(coord.store());
        for (branch_no, oid) in finals.iter().enumerate() {
            let name = RefName::new(format!("refs/heads/lane-{branch_no}")).expect("branch name");
            let resolved = resolve(&refs, &name).expect("resolve branch");
            assert_eq!(resolved.oid, Some(*oid), "branch holds its own tip");
        }
        let mut sorted = finals.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), BRANCHES, "distinct branch tips");

        // The batching proof: four submissions in fewer store publications,
        // each costing at most one metadata commit.
        let after = coord.store().io_stats();
        let total = u64::try_from(BRANCHES).expect("submission count fits u64");
        assert_eq!(
            u64::try_from(finals.len()).expect("final count fits u64"),
            total,
            "every submission landed"
        );
        let publications = after.publications - before.publications;
        let commits = after.publication_commits - before.publication_commits;
        assert!(
            publications < total,
            "lane batches concurrent cross-ref submissions: {after:?} vs {before:?}"
        );
        assert!(
            commits <= publications,
            "no batch splits metadata commits: {after:?} vs {before:?}"
        );

        coord.shutdown();
        runner.abort();
    }

    #[test]
    fn retention_report_is_empty_counts_every_swept_table() {
        assert!(RetentionReport::default().is_empty());
        for report in [
            RetentionReport {
                receipts_deleted: 1,
                ..RetentionReport::default()
            },
            RetentionReport {
                sessions_deleted: 1,
                ..RetentionReport::default()
            },
            RetentionReport {
                events_deleted: 1,
                ..RetentionReport::default()
            },
            RetentionReport {
                service_receipts_deleted: 1,
                ..RetentionReport::default()
            },
            RetentionReport {
                leases_expired: 1,
                ..RetentionReport::default()
            },
        ] {
            assert!(
                !report.is_empty(),
                "a pass that deleted or expired anything is not empty: {report:?}"
            );
        }
    }
}
