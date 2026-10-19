//! Live session table, RAII bindings, authority evaluation, and open preparation.
//!
//! The coordinator maintains a bounded in-memory table of live sessions
//! ([`SessionTable`]), capped at [`MAX_LIVE_SESSIONS`] (128) per repository.
//! Sessions hold an immutable principal, identity, claims, capabilities, and
//! secret hash, with an authority state that transitions strictly from
//! [`SessionAuthority::Active`] to [`SessionAuthority::ReceiptsOnly`].

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use jiff::SignedDuration;
use sha2::{Digest, Sha256};

use crate::capability::Capabilities;
use crate::change::SessionId;
use crate::coord::clock::{Clock, Times};
use crate::coord::policy::{Principal, PrincipalPolicy};
use crate::coord::rows::{RECEIPT_HORIZON, SessionRow, decode_session, session_key};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    ReconnectSecret, SessionAuthority, SessionOpenArgs, SessionOpenReply, SessionResumeArgs,
    SessionResumeReply, Timestamp,
};
use crate::store::Store;
use crate::store::types::FactTable;

/// Maximum number of concurrent live session registrations per repository,
/// including active connection bindings, pending opens, and detached in-flight work.
pub(crate) const MAX_LIVE_SESSIONS: usize = 128;

/// Evaluated in-process authority for a session at a sampled instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Authority {
    /// Full authority for mutations and reads until the idle expiry.
    Active,
    /// Write authority has expired; receipt lookup remains until `receipts_until`.
    /// `latched` is `true` if the row in storage is already `ReceiptsOnly`, or `false`
    /// if the active session expired in-process and requires a durable latch before reply.
    Expired {
        receipts_until: Timestamp,
        latched: bool,
    },
    /// The retention horizon has passed (`wall >= receipts_until`); session is gone.
    Gone,
}

/// Pure evaluation of session authority from row state, monotonic deadline, and times.
///
/// Invariants:
/// - An `Active` session is `Active` while both `wall < idle_expires_at` and `mono < deadline`.
/// - When expired, it transitions to `Expired` with `receipts_until = idle_expires_at + 7 d`.
/// - It becomes `Gone` once `wall >= idle_expires_at + 7 d`.
/// - A `ReceiptsOnly` session is `Expired { latched: true }` while `wall < receipts_until`,
///   and `Gone` thereafter. It never regains `Active`.
#[must_use]
pub(crate) fn authority(
    row: &SessionRow,
    deadline: Instant,
    wall: jiff::Timestamp,
    mono: Instant,
) -> Authority {
    match row.authority {
        SessionAuthority::Active { idle_expires_at } => {
            let e = idle_expires_at.instant();
            let receipts_until_instant = match e.checked_add(RECEIPT_HORIZON) {
                Ok(r) => r,
                Err(_) => return Authority::Gone,
            };
            if wall >= receipts_until_instant {
                Authority::Gone
            } else if wall < e && mono < deadline {
                Authority::Active
            } else {
                Authority::Expired {
                    receipts_until: Timestamp::new(receipts_until_instant),
                    latched: false,
                }
            }
        }
        SessionAuthority::ReceiptsOnly { receipts_until } => {
            let r = receipts_until.instant();
            if wall < r {
                Authority::Expired {
                    receipts_until,
                    latched: true,
                }
            } else {
                Authority::Gone
            }
        }
    }
}

/// Computes the monotonic in-process deadline for an active session.
///
/// Clamps remaining wall duration to at most `idle` to prevent a wall-clock
/// rollback across process restarts from extending authority.
#[must_use]
pub(crate) fn live_deadline(
    row: &SessionRow,
    idle: SignedDuration,
    wall: jiff::Timestamp,
    mono: Instant,
) -> Instant {
    match row.authority {
        SessionAuthority::Active { idle_expires_at } => {
            let e = idle_expires_at.instant();
            let remaining = e.duration_since(wall);
            let clamped = if remaining <= SignedDuration::ZERO {
                SignedDuration::ZERO
            } else if remaining >= idle {
                idle
            } else {
                remaining
            };
            let std_dur = clamped.try_into().unwrap_or(std::time::Duration::ZERO);
            mono.checked_add(std_dur).unwrap_or(mono)
        }
        SessionAuthority::ReceiptsOnly { .. } => mono,
    }
}

/// Constant-time comparison of a provided secret's SHA-256 hash against the stored hash.
///
/// Uses standard RustCrypto [`hmac::digest::CtOutput`] constant-time equality rather than a handwritten loop.
fn verify_secret_hash(provided_secret: &ReconnectSecret, stored_hash: &[u8; 32]) -> bool {
    let computed_digest = Sha256::digest(provided_secret.as_bytes());
    let expected_output = hmac::digest::Output::<Sha256>::from(*stored_hash);
    let ct_computed = hmac::digest::CtOutput::<Sha256>::new(computed_digest);
    let ct_expected = hmac::digest::CtOutput::<Sha256>::new(expected_output);
    ct_computed == ct_expected
}

/// Uniform `E_FORBIDDEN` error for session resume failures to prevent credential or timing oracles.
fn forbidden_resume() -> CoreError {
    CoreError::new(ErrorCode::EForbidden, "session resume forbidden")
}

/// Validates policy claims, negotiates capabilities, generates session ID and secret,
/// and prepares the durable row and open response.
///
/// Does not expose raw secret bytes or secret hashes in [`fmt::Debug`].
///
/// # Errors
/// - [`ErrorCode::EForbidden`] if identity or claims are disallowed or capabilities exceed ceiling.
/// - [`ErrorCode::EIo`] if OS randomness fails.
/// - [`ErrorCode::EInvalid`] on timestamp overflow.
pub(crate) fn prepare_open(
    principal: &Principal,
    policy: &PrincipalPolicy,
    idle: SignedDuration,
    args: &SessionOpenArgs,
    wall: jiff::Timestamp,
) -> Result<PendingOpen, CoreError> {
    policy.admit_claims(args.identity.as_ref(), &args.claims)?;
    let negotiated = Capabilities::negotiate(&policy.ceiling, args.capabilities.as_ref())?;

    let session_id = SessionId::generate();
    let mut secret_bytes = [0_u8; 32];
    getrandom::fill(&mut secret_bytes).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("reconnect secret generation failed: {err}"),
        )
    })?;

    let secret_hash: [u8; 32] = Sha256::digest(secret_bytes).into();
    let idle_expires_at = wall.checked_add(idle).map_err(|err| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("idle expiry timestamp overflow: {err}"),
        )
    })?;

    let row = SessionRow {
        principal: principal.clone(),
        identity: args.identity.clone(),
        claims: args.claims.clone(),
        capabilities: negotiated.clone(),
        secret_hash,
        authority: SessionAuthority::Active {
            idle_expires_at: Timestamp::new(idle_expires_at),
        },
    };

    let reply = SessionOpenReply {
        session: session_id,
        reconnect_secret: ReconnectSecret::from_bytes(secret_bytes),
        principal: principal.to_string(),
        capabilities: negotiated,
        idle_expires_at: Timestamp::new(idle_expires_at),
    };

    Ok(PendingOpen {
        session_id,
        row,
        reply,
    })
}

/// Material prepared for a pending session open prior to durable publication.
pub(crate) struct PendingOpen {
    pub(crate) session_id: SessionId,
    pub(crate) row: SessionRow,
    pub(crate) reply: SessionOpenReply,
}

impl fmt::Debug for PendingOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOpen")
            .field("session_id", &self.session_id)
            .field("row", &self.row)
            .field("reply", &self.reply)
            .finish()
    }
}

struct SessionLiveInner {
    row: Arc<SessionRow>,
    deadline: Instant,
    bindings: u32,
    in_flight: u32,
    reserved: bool,
    gone: bool,
}

/// Shared in-memory representation of an active or bound session.
pub(crate) struct SessionLive {
    id: SessionId,
    inner: Mutex<SessionLiveInner>,
}

impl fmt::Debug for SessionLive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().expect("session live lock");
        f.debug_struct("SessionLive")
            .field("id", &self.id)
            .field("row", &inner.row)
            .field("deadline", &inner.deadline)
            .field("bindings", &inner.bindings)
            .field("in_flight", &inner.in_flight)
            .field("reserved", &inner.reserved)
            .field("gone", &inner.gone)
            .finish()
    }
}

impl SessionLive {
    fn active(id: SessionId, row: Arc<SessionRow>, deadline: Instant) -> Self {
        Self {
            id,
            inner: Mutex::new(SessionLiveInner {
                row,
                deadline,
                bindings: 0,
                in_flight: 0,
                reserved: false,
                gone: false,
            }),
        }
    }

    fn reserved(id: SessionId, row: Arc<SessionRow>, deadline: Instant) -> Self {
        Self {
            id,
            inner: Mutex::new(SessionLiveInner {
                row,
                deadline,
                bindings: 0,
                in_flight: 0,
                reserved: true,
                gone: false,
            }),
        }
    }

    /// The immutable session identifier.
    #[must_use]
    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    /// Returns a cloned reference snapshot to the current session row.
    ///
    /// O(1) Arc clone; never clones the underlying identity or capabilities payloads.
    #[must_use]
    pub(crate) fn row(&self) -> Arc<SessionRow> {
        let inner = self.inner.lock().expect("session live lock");
        Arc::clone(&inner.row)
    }

    /// Returns the monotonic deadline for the session.
    #[must_use]
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    pub(crate) fn deadline(&self) -> Instant {
        let inner = self.inner.lock().expect("session live lock");
        inner.deadline
    }

    /// Evaluates current authority against explicit wall and monotonic instants.
    #[must_use]
    pub(crate) fn authority(&self, wall: jiff::Timestamp, mono: Instant) -> Authority {
        let inner = self.inner.lock().expect("session live lock");
        if inner.gone {
            return Authority::Gone;
        }
        authority(&inner.row, inner.deadline, wall, mono)
    }

    /// Evaluates current authority using sampled [`Times`].
    #[must_use]
    pub(crate) fn current_authority(&self, times: &Times) -> Authority {
        self.authority(times.wall, times.mono)
    }

    /// Convenience check whether the session is currently [`Authority::Active`].
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn is_active(&self, times: &Times) -> bool {
        self.current_authority(times) == Authority::Active
    }

    /// Authorizes a read against the session's negotiated capabilities.
    ///
    /// Ordinary object reads always succeed; another session's private
    /// provenance or claim details need the matching `read_intents` flag.
    /// Claim list and provenance handlers check this before serving.
    ///
    /// # Errors
    /// `E_FORBIDDEN` for private provenance or claim details without the
    /// matching `read_intents` flag.
    pub(crate) fn authorize_read(
        &self,
        access: crate::capability::ReadAccess,
    ) -> Result<(), CoreError> {
        self.row().capabilities.authorize_read(access)
    }

    fn start_in_flight_with_table(
        self: &Arc<Self>,
        table: &Weak<SessionTableInner>,
    ) -> Result<InFlightGuard, CoreError> {
        let mut inner = self.inner.lock().expect("session live lock");
        if inner.gone {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session has been marked gone",
            ));
        }
        inner.in_flight = inner
            .in_flight
            .checked_add(1)
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "in-flight requests overflow"))?;
        Ok(InFlightGuard {
            session: Arc::clone(self),
            table: table.clone(),
        })
    }
}

/// RAII capacity reservation holding a registration slot in [`SessionTable`]
/// prior to durable publication of a new session.
///
/// If publication fails or the reservation is dropped, the slot is immediately
/// reclaimed from the table. Upon successful commit, [`OpenReservation::into_binding`]
/// consumes the reservation into an active binding without failing capacity.
pub(crate) struct OpenReservation {
    session_id: SessionId,
    live: Arc<SessionLive>,
    table: Weak<SessionTableInner>,
    committed: bool,
}

impl OpenReservation {
    /// The session identifier reserved.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Consumes the capacity-reserved open registration into an active binding.
    ///
    /// Because capacity was already reserved in [`SessionTable::reserve_open`],
    /// this operation cannot fail capacity.
    #[must_use]
    pub(crate) fn into_binding(
        mut self,
        row: Arc<SessionRow>,
        idle: SignedDuration,
        times: Times,
    ) -> BoundSession {
        self.committed = true;
        let deadline = live_deadline(&row, idle, times.wall, times.mono);
        {
            let mut inner = self.live.inner.lock().expect("session live lock");
            inner.row = row;
            inner.deadline = deadline;
            inner.reserved = false;
            inner.bindings = 1;
            inner.gone = false;
        }
        BoundSession {
            session: Arc::clone(&self.live),
            table: self.table.clone(),
        }
    }
}

impl Drop for OpenReservation {
    fn drop(&mut self) {
        if !self.committed
            && let Some(table) = self.table.upgrade()
        {
            let mut entries = table.entries.lock().expect("session table lock");
            entries.remove(&self.session_id);
        }
    }
}

/// RAII token representing a connection binding to a session.
///
/// Releasing or dropping this token decrements the binding count on [`SessionLive`].
/// When both `bindings` and `in_flight` reach 0, the session is reclaimed from [`SessionTable`].
#[derive(Debug)]
pub(crate) struct BoundSession {
    session: Arc<SessionLive>,
    table: Weak<SessionTableInner>,
}

impl BoundSession {
    /// The shared live session.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn session(&self) -> &Arc<SessionLive> {
        &self.session
    }

    /// The session identifier.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn id(&self) -> SessionId {
        self.session.id
    }

    /// Current session row snapshot.
    #[must_use]
    pub(crate) fn row(&self) -> Arc<SessionRow> {
        self.session.row()
    }

    /// Evaluates current authority.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn current_authority(&self, times: &Times) -> Authority {
        self.session.current_authority(times)
    }

    /// Authorizes a read against the bound session's negotiated capabilities.
    ///
    /// Ordinary object reads always succeed; another session's private
    /// provenance or claim details need the matching `read_intents` flag.
    /// Claim list and provenance handlers check this before serving.
    ///
    /// # Errors
    /// `E_FORBIDDEN` for private provenance or claim details without the
    /// matching `read_intents` flag.
    pub(crate) fn authorize_read(
        &self,
        access: crate::capability::ReadAccess,
    ) -> Result<(), CoreError> {
        self.session.authorize_read(access)
    }

    /// Begins in-flight work on this session, returning an RAII guard that keeps
    /// the session live even if the connection binding drops.
    ///
    /// # Errors
    /// [`ErrorCode::EForbidden`] if the session has been marked gone.
    pub(crate) fn start_in_flight(&self) -> Result<InFlightGuard, CoreError> {
        self.session.start_in_flight_with_table(&self.table)
    }
}

impl Drop for BoundSession {
    fn drop(&mut self) {
        let should_reclaim = {
            let mut inner = self.session.inner.lock().expect("session live lock");
            inner.bindings = inner.bindings.saturating_sub(1);

            inner.bindings == 0 && inner.in_flight == 0 && !inner.reserved
        };
        if should_reclaim && let Some(table) = self.table.upgrade() {
            let mut entries = table.entries.lock().expect("session table lock");
            if let Some(entry) = entries.get(&self.session.id) {
                let inner = entry.inner.lock().expect("session live lock");
                if inner.bindings == 0 && inner.in_flight == 0 && !inner.reserved {
                    drop(inner);
                    entries.remove(&self.session.id);
                }
            }
        }
    }
}

/// RAII guard protecting detached or active in-flight request execution.
///
/// Ensures the live session remains registered in [`SessionTable`] while work
/// is processing, even across client disconnection.
#[derive(Debug)]
pub(crate) struct InFlightGuard {
    session: Arc<SessionLive>,
    table: Weak<SessionTableInner>,
}

impl InFlightGuard {
    /// The session identifier for this in-flight request.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn session_id(&self) -> SessionId {
        self.session.id
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let should_reclaim = {
            let mut inner = self.session.inner.lock().expect("session live lock");
            inner.in_flight = inner.in_flight.saturating_sub(1);
            inner.bindings == 0 && inner.in_flight == 0 && !inner.reserved
        };
        if should_reclaim && let Some(table) = self.table.upgrade() {
            let mut entries = table.entries.lock().expect("session table lock");
            if let Some(entry) = entries.get(&self.session.id) {
                let inner = entry.inner.lock().expect("session live lock");
                if inner.bindings == 0 && inner.in_flight == 0 && !inner.reserved {
                    drop(inner);
                    entries.remove(&self.session.id);
                }
            }
        }
    }
}

/// The result of an attempted session resumption.
pub(crate) enum ResumeOutcome {
    /// Resumed with active authority.
    Active(BoundSession, SessionResumeReply),
    /// Resumed with read-only/receipts-only authority.
    ReceiptsOnly(BoundSession, SessionResumeReply),
    /// The session was previously `Active` but its deadline or wall expiry has passed
    /// without a durable latch. The lane must persist `latched_row` before replying.
    NeedsLatch {
        session_id: SessionId,
        #[expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )]
        current_row: Arc<SessionRow>,
        latched_row: SessionRow,
        receipts_until: Timestamp,
    },
}

struct SessionTableInner {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    clock: Clock,
    entries: Mutex<HashMap<SessionId, Arc<SessionLive>>>,
}

/// Bounded table of live sessions for a repository.
#[derive(Clone)]
pub(crate) struct SessionTable {
    inner: Arc<SessionTableInner>,
}

impl SessionTable {
    /// Creates a new `SessionTable` sharing the coordinator's process-lifetime clock.
    #[must_use]
    pub(crate) fn new(clock: Clock) -> Self {
        Self {
            inner: Arc::new(SessionTableInner {
                clock,
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The process-lifetime clock.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn clock(&self) -> &Clock {
        &self.inner.clock
    }

    /// Returns the number of currently registered live sessions.
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn live_count(&self) -> usize {
        let entries = self.inner.entries.lock().expect("session table lock");
        entries.len()
    }

    fn reclaim_unused_locked(entries: &mut HashMap<SessionId, Arc<SessionLive>>) {
        entries.retain(|_, live| {
            let inner = live.inner.lock().expect("session live lock");
            inner.bindings > 0 || inner.in_flight > 0 || inner.reserved
        });
    }

    /// Reserves capacity and creates a live registration for a pending open.
    ///
    /// Reclaims unreferenced entries before checking capacity.
    ///
    /// # Errors
    /// [`ErrorCode::ECapacity`] if the table is at [`MAX_LIVE_SESSIONS`].
    pub(crate) fn reserve_open(&self, pending: &PendingOpen) -> Result<OpenReservation, CoreError> {
        let mut entries = self.inner.entries.lock().expect("session table lock");
        Self::reclaim_unused_locked(&mut entries);

        if entries.len() >= MAX_LIVE_SESSIONS {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("live session capacity exceeded (max {MAX_LIVE_SESSIONS})"),
            ));
        }

        let live = Arc::new(SessionLive::reserved(
            pending.session_id,
            Arc::new(pending.row.clone()),
            Instant::now(),
        ));
        entries.insert(pending.session_id, Arc::clone(&live));

        Ok(OpenReservation {
            session_id: pending.session_id,
            live,
            table: Arc::downgrade(&self.inner),
            committed: false,
        })
    }

    /// Creates an active binding to an existing live session.
    ///
    /// # Errors
    /// - [`ErrorCode::EForbidden`] if the session has been marked gone.
    /// - [`ErrorCode::ECapacity`] if bindings count overflows.
    pub(crate) fn bind(&self, live: &Arc<SessionLive>) -> Result<BoundSession, CoreError> {
        let mut inner = live.inner.lock().expect("session live lock");
        if inner.gone {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "session has been marked gone",
            ));
        }
        inner.bindings = inner
            .bindings
            .checked_add(1)
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "session bindings overflow"))?;

        Ok(BoundSession {
            session: Arc::clone(live),
            table: Arc::downgrade(&self.inner),
        })
    }

    /// Returns an existing live session from cache, or loads it from Store.
    ///
    /// # Errors
    /// - [`ErrorCode::ECapacity`] if loading requires an entry and capacity is full.
    /// - [`ErrorCode::ECorrupt`] if row bytes in Store are corrupt.
    pub(crate) fn get_or_load(
        &self,
        store: &Store,
        id: SessionId,
        idle: SignedDuration,
        times: Times,
    ) -> Result<Option<Arc<SessionLive>>, CoreError> {
        let mut entries = self.inner.entries.lock().expect("session table lock");
        if let Some(existing) = entries.get(&id) {
            return Ok(Some(Arc::clone(existing)));
        }

        let key = session_key(id);
        let raw = store.fact(FactTable::Sessions, &key)?;
        let Some(bytes) = raw else {
            return Ok(None);
        };

        let row = Arc::new(decode_session(store, &key, &bytes)?);
        Self::reclaim_unused_locked(&mut entries);
        if entries.len() >= MAX_LIVE_SESSIONS {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("live session capacity exceeded (max {MAX_LIVE_SESSIONS})"),
            ));
        }

        let deadline = live_deadline(&row, idle, times.wall, times.mono);
        let live = Arc::new(SessionLive::active(id, row, deadline));
        entries.insert(id, Arc::clone(&live));

        Ok(Some(live))
    }

    /// Resumes a session under control admission.
    ///
    /// Verifies principal and secret hash in constant time.
    /// Unknown id, wrong principal, bad secret, and expired receipt horizon (`Gone`)
    /// all share one `E_FORBIDDEN` error.
    ///
    /// # Errors
    /// - [`ErrorCode::EForbidden`] on credential or horizon failure.
    /// - [`ErrorCode::ECapacity`] if capacity is exceeded when loading the session.
    pub(crate) fn resume(
        &self,
        store: &Store,
        args: &SessionResumeArgs,
        principal: &Principal,
        idle: SignedDuration,
        times: Times,
    ) -> Result<ResumeOutcome, CoreError> {
        let (row, deadline, live_opt) = {
            let entries = self.inner.entries.lock().expect("session table lock");
            if let Some(live) = entries.get(&args.session) {
                let inner = live.inner.lock().expect("session live lock");
                (
                    Arc::clone(&inner.row),
                    inner.deadline,
                    Some(Arc::clone(live)),
                )
            } else {
                drop(entries);
                let key = session_key(args.session);
                let raw = store.fact(FactTable::Sessions, &key)?;
                let Some(bytes) = raw else {
                    return Err(forbidden_resume());
                };
                let loaded_row = Arc::new(decode_session(store, &key, &bytes)?);
                let dl = live_deadline(&loaded_row, idle, times.wall, times.mono);
                (loaded_row, dl, None)
            }
        };

        if row.principal != *principal {
            return Err(forbidden_resume());
        }

        if !verify_secret_hash(&args.reconnect_secret, &row.secret_hash) {
            return Err(forbidden_resume());
        }

        let auth = authority(&row, deadline, times.wall, times.mono);
        if auth == Authority::Gone {
            return Err(forbidden_resume());
        }

        match auth {
            Authority::Active => {
                let live = match live_opt {
                    Some(l) => l,
                    None => {
                        let mut entries = self.inner.entries.lock().expect("session table lock");
                        Self::reclaim_unused_locked(&mut entries);
                        if entries.len() >= MAX_LIVE_SESSIONS {
                            return Err(CoreError::new(
                                ErrorCode::ECapacity,
                                format!("live session capacity exceeded (max {MAX_LIVE_SESSIONS})"),
                            ));
                        }
                        let l = Arc::new(SessionLive::active(
                            args.session,
                            Arc::clone(&row),
                            deadline,
                        ));
                        entries.insert(args.session, Arc::clone(&l));
                        l
                    }
                };

                let bound = self.bind(&live)?;
                let reply = SessionResumeReply {
                    session: args.session,
                    authority: row.authority,
                    capabilities: row.capabilities.clone(),
                };
                Ok(ResumeOutcome::Active(bound, reply))
            }
            Authority::Expired {
                receipts_until,
                latched,
            } => {
                if !latched {
                    let latched_row = SessionRow {
                        principal: row.principal.clone(),
                        identity: row.identity.clone(),
                        claims: row.claims.clone(),
                        capabilities: row.capabilities.clone(),
                        secret_hash: row.secret_hash,
                        authority: SessionAuthority::ReceiptsOnly { receipts_until },
                    };
                    return Ok(ResumeOutcome::NeedsLatch {
                        session_id: args.session,
                        current_row: row,
                        latched_row,
                        receipts_until,
                    });
                }

                let live = match live_opt {
                    Some(l) => l,
                    None => {
                        let mut entries = self.inner.entries.lock().expect("session table lock");
                        Self::reclaim_unused_locked(&mut entries);
                        if entries.len() >= MAX_LIVE_SESSIONS {
                            return Err(CoreError::new(
                                ErrorCode::ECapacity,
                                format!("live session capacity exceeded (max {MAX_LIVE_SESSIONS})"),
                            ));
                        }
                        let l = Arc::new(SessionLive::active(
                            args.session,
                            Arc::clone(&row),
                            deadline,
                        ));
                        entries.insert(args.session, Arc::clone(&l));
                        l
                    }
                };

                let bound = self.bind(&live)?;
                let reply = SessionResumeReply {
                    session: args.session,
                    authority: SessionAuthority::ReceiptsOnly { receipts_until },
                    capabilities: Capabilities::default(),
                };
                Ok(ResumeOutcome::ReceiptsOnly(bound, reply))
            }
            Authority::Gone => Err(forbidden_resume()),
        }
    }

    /// Called by the parent lane after batch commit under writer ownership.
    ///
    /// Coalesces committed row updates and refreshes deadlines.
    /// Passing `None` for row marks the session gone.
    pub(crate) fn apply_committed(
        &self,
        id: SessionId,
        row: Option<Arc<SessionRow>>,
        idle: SignedDuration,
        times: Times,
    ) {
        let entries = self.inner.entries.lock().expect("session table lock");
        if let Some(live) = entries.get(&id) {
            let mut inner = live.inner.lock().expect("session live lock");
            match row {
                Some(new_row) => {
                    if inner.row.check_successor(&new_row).is_ok() {
                        inner.deadline = live_deadline(&new_row, idle, times.wall, times.mono);
                        inner.row = new_row;
                        inner.reserved = false;
                        inner.gone = false;
                    }
                }
                None => {
                    inner.gone = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::coord::policy::Principal;
    use crate::coord::rows::encode;
    use crate::ids::HashKind;
    use crate::protocol::Timestamp;
    use crate::store::PreparationBudget;
    use crate::store::types::{FactExpectation, FactMutation};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-coord-session-test-{tag}-{}-{}-{nanos}",
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

    fn sample_principal() -> Principal {
        Principal::from_peer_uid(1000)
    }

    fn sample_policy(principal: &Principal) -> PrincipalPolicy {
        crate::coord::policy::Policy::default_for_owner(principal)
            .expect("default policy")
            .lookup(principal)
            .expect("owner policy")
            .clone()
    }

    #[test]
    fn prepare_open_debug_redacts_secret_and_hash() {
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);
        let wall = jiff::Timestamp::now();
        let args = SessionOpenArgs::default();

        let pending = prepare_open(&principal, &policy, idle, &args, wall).expect("prepare open");

        let debug_str = format!("{pending:?}");
        assert!(!debug_str.contains(&pending.reply.reconnect_secret.to_hex()));
        assert!(debug_str.contains("<redacted>"));
    }

    #[test]
    fn constant_time_secret_verification() {
        let secret = ReconnectSecret::from_bytes([0x7a; 32]);
        let hash: [u8; 32] = Sha256::digest(secret.as_bytes()).into();

        assert!(verify_secret_hash(&secret, &hash));

        let wrong_secret = ReconnectSecret::from_bytes([0x7b; 32]);
        assert!(!verify_secret_hash(&wrong_secret, &hash));
    }

    #[test]
    fn authority_transitions_are_irreversible() {
        let wall0: jiff::Timestamp = "2026-10-17T12:00:00Z".parse().unwrap();
        let mono0 = Instant::now();
        let idle = SignedDuration::from_hours(1);
        let idle_expires = wall0.checked_add(idle).unwrap();

        let principal = sample_principal();
        let secret_hash = [0x12; 32];
        let mut row = SessionRow {
            principal,
            identity: None,
            claims: Default::default(),
            capabilities: Default::default(),
            secret_hash,
            authority: SessionAuthority::Active {
                idle_expires_at: Timestamp::new(idle_expires),
            },
        };

        let deadline = mono0 + Duration::from_secs(3600);

        // 1. Initially Active
        assert_eq!(authority(&row, deadline, wall0, mono0), Authority::Active);

        // 2. Wall time passes idle expiry -> Expired { latched: false }
        let wall1 = wall0.checked_add(SignedDuration::from_secs(3601)).unwrap();
        let mono1 = mono0 + Duration::from_secs(3601);
        let auth1 = authority(&row, deadline, wall1, mono1);
        let expected_receipts_until =
            Timestamp::new(idle_expires.checked_add(RECEIPT_HORIZON).unwrap());
        assert_eq!(
            auth1,
            Authority::Expired {
                receipts_until: expected_receipts_until,
                latched: false,
            }
        );

        // 3. Monotonic time rolls back in local check -> wall time still prevents Active
        assert_eq!(
            authority(&row, deadline, wall1, mono0),
            Authority::Expired {
                receipts_until: expected_receipts_until,
                latched: false,
            }
        );

        // 4. Latched to ReceiptsOnly
        row.authority = SessionAuthority::ReceiptsOnly {
            receipts_until: expected_receipts_until,
        };
        assert_eq!(
            authority(&row, deadline, wall1, mono1),
            Authority::Expired {
                receipts_until: expected_receipts_until,
                latched: true,
            }
        );

        // 5. ReceiptsOnly can never regain Active
        let new_active = SessionRow {
            authority: SessionAuthority::Active {
                idle_expires_at: Timestamp::new(
                    idle_expires
                        .checked_add(SignedDuration::from_hours(10))
                        .unwrap(),
                ),
            },
            ..row.clone()
        };
        assert!(row.check_successor(&new_active).is_err());

        // 6. Beyond 7 days -> Gone
        let wall_gone = idle_expires
            .checked_add(RECEIPT_HORIZON)
            .unwrap()
            .checked_add(SignedDuration::from_secs(1))
            .unwrap();
        assert_eq!(authority(&row, deadline, wall_gone, mono1), Authority::Gone);
    }

    #[test]
    fn resume_forbidden_for_all_unauthorized_cases() {
        let (_dir, store) = test_store("resume-forbidden");
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let times = table.clock().sample().unwrap();
        let idle = SignedDuration::from_hours(24);
        let principal = sample_principal();
        let wrong_principal = Principal::from_peer_uid(9999);

        // 1. Unknown session ID
        let resume_args = SessionResumeArgs {
            session: SessionId::generate(),
            reconnect_secret: ReconnectSecret::from_bytes([0xaa; 32]),
        };
        let err1 = table
            .resume(&store, &resume_args, &principal, idle, times)
            .err()
            .expect("unknown session must be rejected");
        assert_eq!(err1.code, ErrorCode::EForbidden);

        // Save a real session
        let open_args = SessionOpenArgs::default();
        let pending = prepare_open(
            &principal,
            &sample_policy(&principal),
            idle,
            &open_args,
            times.wall,
        )
        .unwrap();
        let encoded = encode("session", &pending.row).unwrap();
        let key = session_key(pending.session_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Sessions,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
            )
            .unwrap();

        // 2. Wrong principal
        let resume_args2 = SessionResumeArgs {
            session: pending.session_id,
            reconnect_secret: pending.reply.reconnect_secret,
        };
        let err2 = table
            .resume(&store, &resume_args2, &wrong_principal, idle, times)
            .err()
            .expect("wrong principal must be rejected");
        assert_eq!(err2.code, ErrorCode::EForbidden);
        assert_eq!(
            err1.to_string(),
            err2.to_string(),
            "uniform error message required"
        );

        // 3. Bad secret
        let resume_args3 = SessionResumeArgs {
            session: pending.session_id,
            reconnect_secret: ReconnectSecret::from_bytes([0x00; 32]),
        };
        let err3 = table
            .resume(&store, &resume_args3, &principal, idle, times)
            .err()
            .expect("bad secret must be rejected");
        assert_eq!(err3.code, ErrorCode::EForbidden);
        assert_eq!(err1.to_string(), err3.to_string());

        // 4. Correct credentials succeed
        let outcome = table
            .resume(&store, &resume_args2, &principal, idle, times)
            .unwrap();
        match outcome {
            ResumeOutcome::Active(bound, reply) => {
                assert_eq!(bound.id(), pending.session_id);
                assert_eq!(reply.session, pending.session_id);
            }
            _ => panic!("expected Active"),
        }
    }

    #[test]
    fn capacity_limit_enforced_and_reclaimed_on_drop() {
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);
        let wall = jiff::Timestamp::now();

        let mut reservations = Vec::new();
        for _ in 0..MAX_LIVE_SESSIONS {
            let pending =
                prepare_open(&principal, &policy, idle, &SessionOpenArgs::default(), wall).unwrap();
            let res = table
                .reserve_open(&pending)
                .expect("reservation should succeed");
            reservations.push(res);
        }
        assert_eq!(table.live_count(), MAX_LIVE_SESSIONS);

        // 129th reservation fails with E_CAPACITY
        let extra_pending =
            prepare_open(&principal, &policy, idle, &SessionOpenArgs::default(), wall).unwrap();
        let err = table
            .reserve_open(&extra_pending)
            .err()
            .expect("129th reservation must fail");
        assert_eq!(err.code, ErrorCode::ECapacity);

        // Drop 10 reservations -> capacity frees immediately
        for _ in 0..10 {
            reservations.pop();
        }
        // Now opening another succeeds!
        let extra_res = table
            .reserve_open(&extra_pending)
            .expect("should succeed after drop");
        assert_eq!(extra_res.session_id(), extra_pending.session_id);
    }

    #[test]
    fn open_reservation_into_binding_guarantees_capacity() {
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let times = table.clock().sample().unwrap();
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);

        let pending = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let res = table.reserve_open(&pending).unwrap();
        let session_id = res.session_id();

        // Convert to binding
        let row_arc = Arc::new(pending.row.clone());
        let bound = res.into_binding(row_arc, idle, times);
        assert_eq!(bound.id(), session_id);
        assert!(bound.current_authority(&times) == Authority::Active);

        // Detached in-flight request protects entry across connection drop
        let in_flight = bound.start_in_flight().unwrap();
        drop(bound);
        assert_eq!(table.live_count(), 1, "in-flight guard keeps entry live");

        drop(in_flight);
        // After in_flight drops and bindings == 0, entry is eligible for reclaim
        let dummy_pending = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let _dummy_res = table.reserve_open(&dummy_pending);
        // Previous unused entry was reclaimed
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn concurrent_same_session_reuse() {
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let times = table.clock().sample().unwrap();
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);

        let pending = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let res = table.reserve_open(&pending).unwrap();
        let session_id = res.session_id();
        let row_arc = Arc::new(pending.row);
        let primary_bound = res.into_binding(row_arc, idle, times);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let tbl = table.clone();
            let live_ref = Arc::clone(primary_bound.session());
            handles.push(std::thread::spawn(move || {
                let bound = tbl.bind(&live_ref).expect("concurrent bind");
                assert_eq!(bound.id(), session_id);
                let in_flight = bound.start_in_flight().expect("in-flight");
                assert_eq!(in_flight.session_id(), session_id);
                assert_eq!(tbl.live_count(), 1, "exactly one shared live entry");
            }));
        }

        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(table.live_count(), 1);
        drop(primary_bound);
        // All bindings and in-flight guards are dropped -> reclaims on next reserve
        let dummy = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let _dummy_res = table.reserve_open(&dummy);
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn binding_replacement_and_disconnect() {
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let times = table.clock().sample().unwrap();
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);

        // Open session A
        let pending_a = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let res_a = table.reserve_open(&pending_a).unwrap();
        let bound_a = res_a.into_binding(Arc::new(pending_a.row), idle, times);

        // Open session B
        let pending_b = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let res_b = table.reserve_open(&pending_b).unwrap();
        let bound_b = res_b.into_binding(Arc::new(pending_b.row), idle, times);

        assert_eq!(table.live_count(), 2);

        // Connection holds binding A
        let mut conn_binding: Option<BoundSession> = Some(bound_a);

        // Connection replaces binding A with B
        conn_binding.replace(bound_b);

        // Trigger reclamation
        let dummy = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times.wall,
        )
        .unwrap();
        let _dummy_res = table.reserve_open(&dummy);
        // Session A was unreferenced and reclaimed; B + dummy remain (count 2)
        assert_eq!(table.live_count(), 2);

        // Connection disconnects
        drop(conn_binding);
    }

    #[test]
    fn no_monotonic_rollback_extension_after_last_binding_drop_and_reload() {
        let (_dir, store) = test_store("no-rollback-extension");
        let start_wall: jiff::Timestamp = "2026-10-17T12:00:00Z".parse().unwrap();
        let start_mono = Instant::now();
        let clock = Clock::injected(start_wall, start_mono);
        let table = SessionTable::new(clock.clone());
        let times0 = table.clock().sample().unwrap();

        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(1); // 1 hour authority

        // 1. Open session with 1 hour idle (expires at 13:00:00Z)
        let pending = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times0.wall,
        )
        .unwrap();
        let res = table.reserve_open(&pending).unwrap();
        let session_id = res.session_id();
        let row_arc = Arc::new(pending.row.clone());
        let bound = res.into_binding(Arc::clone(&row_arc), idle, times0);

        // Publish session to store
        let encoded = encode("session", &row_arc).unwrap();
        let key = session_key(session_id);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: FactTable::Sessions,
                    key: key.to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encoded),
                }],
            )
            .unwrap();

        // 2. Drop last binding so session is evicted from in-memory table
        drop(bound);
        let dummy = prepare_open(
            &principal,
            &policy,
            idle,
            &SessionOpenArgs::default(),
            times0.wall,
        )
        .unwrap();
        let _dummy_res = table.reserve_open(&dummy);
        // Previous session is no longer in live cache

        // 3. Monotonic time advances 30 minutes, but OS wall rolls back by 2 hours (to 10:00:00Z!)
        let rolled_back_wall: jiff::Timestamp = "2026-10-17T10:00:00Z".parse().unwrap();
        let mono_plus_30m = start_mono + Duration::from_secs(1800);
        clock.set_injected(rolled_back_wall, mono_plus_30m);
        let times1 = clock.sample().unwrap();

        // Effective wall must be 12:30:00Z, NOT 10:00:00Z!
        let expected_effective_wall: jiff::Timestamp = "2026-10-17T12:30:00Z".parse().unwrap();
        assert_eq!(times1.wall, expected_effective_wall);

        // 4. Reload session from Store under rolled-back host OS clock
        let reloaded_live = table
            .get_or_load(&store, session_id, idle, times1)
            .unwrap()
            .expect("loaded");

        // The reloaded session must only have 30 minutes of remaining authority, NOT 3 hours!
        assert!(reloaded_live.is_active(&times1));

        // 5. Advance another 31 minutes monotonically (total 61 minutes elapsed since open)
        let mono_plus_61m = start_mono + Duration::from_secs(3660);
        clock.set_injected(rolled_back_wall, mono_plus_61m);
        let times2 = clock.sample().unwrap();

        // Effective wall is 13:01:00Z -> session must be EXPIRED!
        let auth2 = reloaded_live.current_authority(&times2);
        match auth2 {
            Authority::Expired { latched: false, .. } => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn bounded_live_state_churn_reclaims_cleanly() {
        let clock = Clock::injected("2026-10-17T12:00:00Z".parse().unwrap(), Instant::now());
        let table = SessionTable::new(clock);
        let principal = sample_principal();
        let policy = sample_policy(&principal);
        let idle = SignedDuration::from_hours(24);
        let wall = jiff::Timestamp::now();

        // Churn through 300 sessions opening and disconnecting
        for _ in 0..300 {
            let pending =
                prepare_open(&principal, &policy, idle, &SessionOpenArgs::default(), wall).unwrap();
            let res = table.reserve_open(&pending).expect("reserve succeeds");
            let times = table.clock().sample().unwrap();
            let bound = res.into_binding(Arc::new(pending.row), idle, times);
            let in_flight = bound.start_in_flight().expect("in flight");
            drop(bound);
            drop(in_flight);
        }

        // After all sessions drop, only 1 entry is left upon next reservation
        let dummy =
            prepare_open(&principal, &policy, idle, &SessionOpenArgs::default(), wall).unwrap();
        let _dummy_res = table.reserve_open(&dummy).unwrap();
        assert_eq!(
            table.live_count(),
            1,
            "churned entries must be fully reclaimed"
        );
    }
}
