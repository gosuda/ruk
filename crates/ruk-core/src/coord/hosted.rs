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
use super::oplog::read_header;
use super::policy::PolicySource;
pub use super::policy::Principal;
use super::rows::{
    CoordinatorHead, OP_HEAD_KEY, RECEIPT_HORIZON, SessionRow, decode_head, decode_session,
    session_key,
};
use super::session::{Authority, ResumeOutcome, SessionTable, prepare_open};
use crate::capability::{Capabilities, ReadAccess};
use crate::change::{OperationId, RequestId, SessionId, WorkspaceId};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    MAX_PAGE_SIZE, OpLogArgs, OpLogReply, Page, ReconnectSecret, Reply, Request, SessionAuthority,
    SessionOpenArgs, SessionResumeArgs, SessionResumeReply, Timestamp, ViewInfo,
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
    /// and runs the read implementation. Only `op.log` has an implementation
    /// today; every other read runs the same session checks and then names
    /// its missing implementation with [`ErrorCode::EHosted`], so an unknown
    /// session still reports `E_FORBIDDEN` rather than a missingimpl error.
    ///
    /// Capability mapping follows the existing handlers rather than a
    /// blanket table: ordinary reads authorize as [`ReadAccess::Objects`],
    /// which always succeeds. A future `claim.list` implementation must use
    /// the claims module's listing authorization (a session always reads its
    /// own claims; anything wider needs `read_intents.claims`), and the
    /// attestation queries carry no capability gate of their own. Receipts
    /// of an expired session have no read path either: without one, expired
    /// authority is uniformly forbidden here instead of inventing a
    /// receipts-only read.
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
            other => Err(CoreError::new(
                ErrorCode::EHosted,
                format!(
                    "method `{}` has no read implementation on the coordinator: only `op.log` is served",
                    other.method().as_str(),
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
    use crate::change::RequestId;
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::protocol::{
        ClaimListArgs, Method, Mutation as WireMutation, OpLogArgs, PinArgs, TagSetArgs,
    };
    use crate::refdata::{RefExpect, RefName};
    use crate::store::PreparationBudget;

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

    #[tokio::test]
    async fn session_bound_read_serves_oplog_and_refuses_the_rest() {
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

        let err = coord
            .read(
                &owner,
                session,
                Request::ClaimList(Box::new(ClaimListArgs::default())),
                &cancel,
            )
            .await
            .expect_err("claim.list names its missing implementation");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(err.message.contains("no read implementation"));

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
