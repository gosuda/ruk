//! Per-repository commit coordinator sidecar.
//!
//! One coordinator process per repository batches commit publications across
//! CLI processes through the single linearizable publication lane:
//!
//! * The server binds `<store>/coordinator.sock`, wins the store-directory
//!   ownership lock, opens [`HostedCoordinator`], and serves `git.commit`
//!   submissions until its idle TTL lapses or it is terminated. The lock is
//!   an OS-advisory file lock released by the kernel on crash, so a killed
//!   coordinator never wedges the repository: the next starter takes over.
//! * Consistency: the lane is the single publication owner, so concurrent
//!   submissions linearize; commit plus ref move publish in one batch, so a
//!   kill between them is impossible. Delivery is at-least-once (exactly-once
//!   does not exist), and every consumer is idempotent: submissions carry the
//!   caller's stable request id, the lane replays the stored reply for a
//!   repeated `(session, request_id)` from its receipt ledger, and the
//!   `git.commit` producer skips its ref transaction when the commit already
//!   landed and the ref already holds it.
//! * The store (and its coordinator) lives only while submissions are in
//!   flight. An idle server holds the socket and the ownership lock but no
//!   store handle, so read verbs and direct publishes never starve behind a
//!   retained redb lock; the next arrival opens a fresh burst.
//!
//! Authentication reuses the coordinator handshake: the client reads the
//! lock body (address plus endpoint nonce) and proves knowledge of the
//! nonce, exactly like the daemon client. Only the lock owner's uid is
//! served; anything else is refused at the handshake.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout};

use super::cancel::{Cancel, cancellation};
use super::endpoint::{self, Incoming, Outgoing};
use super::handshake;
use super::hosted::{DispatchReady, HostedCoordinator};
use super::lock::{Acquisition, EndpointAddress, EndpointNonce, LockBody, LockSnapshot, StoreLock};
use super::transport;
use crate::attestation::Progress;
use crate::change::SessionId;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    ReconnectSecret, Reply, Request, SessionAuthority, SessionOpenArgs, SessionResumeArgs,
};
use crate::store::{PreparationBudget, Store};

/// Socket leaf name inside the store directory.
pub(crate) const SOCK_NAME: &str = "coordinator.sock";

/// CLI session persistence leaf name inside the store directory.
const SESSION_NAME: &str = "cli-session";

/// Largest socket pathname, in native bytes, this sidecar binds.
const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Protocol version of the sidecar frames below.
const FRAME_VERSION: u32 = 1;

/// Absolute bound for one submission exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long past the last submission a burst keeps its store open: long
/// enough to share one lane lifetime across racing submissions, short enough
/// that clients reopening after their round trip never wait on the lock.
const BURST_LINGER: Duration = Duration::from_millis(50);

/// Concurrent submissions before the server sheds load by closing.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// One lane submission: any native request; mutations carry the caller's
/// stable idempotency key in their [`Mutation`] wrapper. The session always
/// comes from the server side.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitCall {
    /// Sidecar frame version; must be [`FRAME_VERSION`].
    pub v: u32,
    /// Lane request to prepare and submit.
    pub body: Request,
}

/// One lane answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitAnswer {
    /// Sidecar frame version; always [`FRAME_VERSION`].
    pub v: u32,
    /// The lane idempotency key this answers, hyphenated UUID text.
    pub id: String,
    /// True with `body` set, false with `code`/`message` set.
    pub ok: bool,
    /// The lane reply on success.
    pub body: Option<Reply>,
    /// Error code name on failure.
    pub code: Option<String>,
    /// Human detail on failure.
    pub message: Option<String>,
}

/// Aggregate evidence one server run reports for its proof file.
///
/// The barrier counters are store durability totals across every burst:
/// `publications` counts committed publications while
/// `publication_commits` counts the metadata transactions they shared, so
/// `publication_commits < publications` proves group commit batched work
/// that solo processes would have synced separately.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServeStats {
    /// Submissions answered, including replays and refusals.
    pub requests: u64,
    /// Submissions that committed in this run.
    pub committed: u64,
    /// Submissions answered from the receipt ledger.
    pub replayed: u64,
    /// Submissions refused with an error frame.
    pub errors: u64,
    /// Store bursts opened (one lane lifetime each).
    pub bursts: u64,
    /// Publications that committed.
    pub publications: u64,
    /// Publication transactions committed; shared by grouped publications.
    pub publication_commits: u64,
    /// Segment files synced by publications.
    pub segment_syncs: u64,
    /// Pending-reservation commits.
    pub pending_commits: u64,
    /// Directory syncs for newly created segment files.
    pub directory_syncs: u64,
}

/// How a server run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Served until the idle TTL lapsed.
    Idle,
    /// Another owner already serves this repository.
    AlreadyRunning,
}

/// What one submission settled as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubmissionOutcome {
    Committed,
    Replayed,
}

/// Socket path for the repository sidecar.
#[must_use]
pub fn socket_path(store_dir: &Path) -> PathBuf {
    store_dir.join(SOCK_NAME)
}

/// Reads the live endpoint (store id plus lock body) for a client.
///
/// # Errors
/// `E_IO` when no coordinator serves this repository (nothing published or
/// the body is not ready yet); the caller spawns one and retries.
pub fn read_cli_endpoint(store_dir: &Path) -> Result<(crate::StoreId, LockBody), CoreError> {
    let (format, file) = crate::store::read_format(store_dir)?;
    drop(file);
    match StoreLock::try_acquire(store_dir)? {
        Acquisition::Owner(_) => Err(CoreError::new(
            ErrorCode::EIo,
            "no coordinator serves this repository",
        )),
        Acquisition::Held(LockSnapshot::Ready(body)) => Ok((format.id, body)),
        Acquisition::Held(LockSnapshot::NotReady) => Err(CoreError::new(
            ErrorCode::EIo,
            "the coordinator has not published its endpoint yet",
        )),
    }
}

/// Connects to the address in a lock body under a deadline.
///
/// # Errors
/// `E_IO` when the socket refuses (a stale owner is gone; unlink and
/// respawn), `E_COORDINATOR_UNRESPONSIVE` past the deadline.
pub async fn cli_connect(body: &LockBody, deadline: Instant) -> Result<Outgoing, CoreError> {
    let wait = deadline.saturating_duration_since(Instant::now());
    match timeout(wait, endpoint::connect(&body.address)).await {
        Ok(stream) => stream,
        Err(_) => Err(CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "coordinator connect deadline expired",
        )),
    }
}

/// Runs the client handshake over a connected stream, proving knowledge of
/// the endpoint nonce from the lock body.
///
/// # Errors
/// Handshake errors when the server proof fails; the stream is unusable
/// afterwards either way.
pub async fn cli_handshake(
    stream: &mut Outgoing,
    store_id: crate::StoreId,
    body: &LockBody,
    deadline: Instant,
) -> Result<(), CoreError> {
    handshake::prove_client(stream, store_id, &body.nonce, deadline).await
}

/// Sends one length-prefixed JSON frame.
pub async fn send_frame(
    stream: &mut Outgoing,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    transport::write_body(stream, bytes, deadline).await
}

/// Receives one length-prefixed JSON frame.
pub async fn recv_frame(stream: &mut Outgoing, deadline: Instant) -> Result<Vec<u8>, CoreError> {
    let length = transport::read_length(stream, deadline).await?;
    let frame = transport::read_body(stream, length, deadline).await?;
    Ok(frame.to_vec())
}

/// Encodes one JSON frame body.
///
/// # Errors
/// `E_INVALID` when the value cannot be encoded.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    sonic_rs::to_vec(value)
        .map_err(|err| CoreError::new(ErrorCode::EInvalid, format!("frame encode: {err}")))
}

/// Decodes one JSON frame body.
///
/// # Errors
/// `E_INVALID` on malformed input; the connection is unusable afterwards.
pub fn decode_frame<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    sonic_rs::from_slice(bytes)
        .map_err(|err| CoreError::new(ErrorCode::EInvalid, format!("frame decode: {err}")))
}

/// Persistent CLI session record.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CliSession {
    session: SessionId,
    secret: ReconnectSecret,
}

fn session_path(store_dir: &Path) -> PathBuf {
    store_dir.join(SESSION_NAME)
}

fn allow(_: Progress) -> Result<(), CoreError> {
    Ok(())
}

fn answer_error(id: &str, err: &CoreError) -> CommitAnswer {
    CommitAnswer {
        v: FRAME_VERSION,
        id: id.to_owned(),
        ok: false,
        body: None,
        code: Some(format!("{:?}", err.code)),
        message: Some(err.to_string()),
    }
}

fn ok_answer(id: &str, reply: Reply) -> (CommitAnswer, SubmissionOutcome) {
    // Receipt replays mark the outcome they return; anything else committed
    // in this burst.
    let replayed = match &reply {
        Reply::GitCommit(boxed) => boxed.outcome.receipt.replayed,
        _ => false,
    };
    let answer = CommitAnswer {
        v: FRAME_VERSION,
        id: id.to_owned(),
        ok: true,
        body: Some(reply),
        code: None,
        message: None,
    };
    if replayed {
        (answer, SubmissionOutcome::Replayed)
    } else {
        (answer, SubmissionOutcome::Committed)
    }
}

/// One live store burst: the coordinator, its lane runner, the CLI session
/// every submission in the burst shares, and the durability baseline its
/// barrier evidence is measured against.
struct Burst {
    coord: Arc<HostedCoordinator>,
    session: SessionId,
    runner: tokio::task::JoinHandle<Result<(), CoreError>>,
    base: crate::store::IoStats,
}

struct Server {
    store_dir: PathBuf,
    store_id: crate::StoreId,
    nonce: EndpointNonce,
    owner: super::policy::Principal,
    idle: Duration,
    cancel: Cancel,
    conns: Arc<tokio::sync::Semaphore>,
    stats: Mutex<ServeStats>,
    active: AtomicU64,
    last_activity: Mutex<Instant>,
    burst: Mutex<Option<Burst>>,
    /// Serializes burst open/install only.
    ///
    /// Each connection runs `dispatch` on its own task, so two first
    /// submissions can otherwise race two store opens and the loser fails
    /// `E_IO: Database already open`, surfacing as a spurious Uncertain
    /// instead of a clean lost-race Stale. Prepare-plus-submit stay
    /// concurrent by design: the lane linearizes same-ref mutations
    /// itself (re-checking each against fresh state at apply), and the
    /// loser retries through the client with the fresh tip. Holding this
    /// across a full submit would only add the winner's whole publish
    /// latency to the loser's retry gap and push it out of the
    /// group-commit sharing window.
    burst_open: tokio::sync::Mutex<()>,
}

impl Server {
    fn note_activity(&self) {
        if let Ok(mut activity) = self.last_activity.lock() {
            *activity = Instant::now();
        }
    }

    fn note_committed(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.requests += 1;
            stats.committed += 1;
        }
    }

    fn note_replayed(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.requests += 1;
            stats.replayed += 1;
        }
    }

    fn note_error(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.requests += 1;
            stats.errors += 1;
        }
    }

    fn note_burst(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.bursts += 1;
        }
    }

    fn live_burst(&self) -> Option<(Arc<HostedCoordinator>, SessionId)> {
        self.burst.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .map(|burst| (Arc::clone(&burst.coord), burst.session))
        })
    }

    /// Opens (or resumes) the persistent CLI session for one burst.
    async fn ensure_session(&self, coord: &HostedCoordinator) -> Result<SessionId, CoreError> {
        let path = session_path(&self.store_dir);
        if let Ok(bytes) = std::fs::read(&path)
            && let Ok(saved) = decode_frame::<CliSession>(&bytes)
        {
            let resumed = coord
                .resume_session(
                    &self.owner,
                    &SessionResumeArgs {
                        session: saved.session,
                        reconnect_secret: saved.secret,
                    },
                    &self.cancel,
                )
                .await;
            if let Ok(reply) = resumed
                && matches!(reply.authority, SessionAuthority::Active { .. })
            {
                return Ok(saved.session);
            }
        }
        let (session, secret) = coord
            .open_session(&self.owner, &SessionOpenArgs::default(), &self.cancel)
            .await?;
        if let Ok(bytes) = encode_frame(&CliSession { session, secret }) {
            write_session_file(&path, &bytes);
        }
        Ok(session)
    }

    /// Returns the live burst, opening a fresh store burst when idle.
    ///
    /// The open/install section is serialized: concurrent first
    /// submissions must not race two store opens (the loser would fail
    /// `E_IO: Database already open`). Live-burst reuse stays cheap under
    /// the same guard.
    async fn burst(&self) -> Result<(Arc<HostedCoordinator>, SessionId), CoreError> {
        let _open_serial = self.burst_open.lock().await;
        if let Some(live) = self.live_burst() {
            return Ok(live);
        }
        let dir = self.store_dir.clone();
        let store = tokio::task::spawn_blocking(move || {
            Store::open(&dir, Arc::new(PreparationBudget::reference_defaults()))
        })
        .await
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("coordinator join: {err}")))?
        .map_err(CoreError::from)?;
        let coord = Arc::new(HostedCoordinator::open(
            Arc::new(store),
            self.owner.clone(),
            self.store_dir.clone(),
        )?);
        let runner = coord.spawn_on(&tokio::runtime::Handle::current())?;
        let session = self.ensure_session(&coord).await?;
        self.note_burst();
        // One atomic install: whoever finds a live burst keeps it and
        // retires its own just-built one, so two creators can never
        // overwrite each other and leak a runner plus its store. The guard
        // covers the pointer swap only; every await runs without it.
        let mut fresh = Some(Burst {
            coord: Arc::clone(&coord),
            session,
            runner,
            base: coord.store().io_stats(),
        });
        let raced = match self.burst.lock() {
            Ok(mut guard) => {
                if guard.is_none() {
                    if let Some(built) = fresh.take() {
                        guard.replace(built);
                    }
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    "coordinator burst lock poisoned",
                ));
            }
        };
        if raced {
            if let Some(mine) = fresh {
                mine.coord.shutdown();
                let _ = mine.runner.await;
            }
            return self.live_burst().ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EIo,
                    "coordinator burst vanished under contention",
                )
            });
        }
        Ok((coord, session))
    }

    /// Drains and retires the live burst, releasing the store lock, and
    /// folds its durability barriers into the run totals.
    async fn retire_burst(&self) {
        let burst = self
            .burst
            .lock()
            .map(|mut guard| guard.take())
            .unwrap_or(None);
        if let Some(burst) = burst {
            burst.coord.shutdown();
            let _ = burst.runner.await;
            let end = burst.coord.store().io_stats();
            if let Ok(mut stats) = self.stats.lock() {
                stats.publications += end.publications.saturating_sub(burst.base.publications);
                stats.publication_commits += end
                    .publication_commits
                    .saturating_sub(burst.base.publication_commits);
                stats.segment_syncs += end.segment_syncs.saturating_sub(burst.base.segment_syncs);
                stats.pending_commits += end
                    .pending_commits
                    .saturating_sub(burst.base.pending_commits);
                stats.directory_syncs += end
                    .directory_syncs
                    .saturating_sub(burst.base.directory_syncs);
            }
        }
    }

    async fn handle(&self, mut stream: Incoming) {
        match self.serve_one(&mut stream).await {
            Ok(SubmissionOutcome::Committed) => self.note_committed(),
            Ok(SubmissionOutcome::Replayed) => self.note_replayed(),
            Err(_) => self.note_error(),
        }
        // Timestamp before dropping the count: the idle loop retires when it
        // samples active==0 past the linger, so the stamp must already cover
        // this worker. Releasing the count first lets a descheduled task
        // retire a live burst on a stale stamp just as the loser's retry
        // arrives, forcing a second store open and breaking burst sharing.
        self.note_activity();
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    async fn serve_one(&self, stream: &mut Incoming) -> Result<SubmissionOutcome, CoreError> {
        let deadline = Instant::now() + EXCHANGE_TIMEOUT;
        handshake::prove_server(stream, self.store_id, &self.nonce, deadline).await?;
        if endpoint::principal(stream)? != self.owner {
            handshake::reject_client(stream, deadline).await?;
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "per-repo coordinators serve only the lock owner",
            ));
        }
        handshake::accept_client(stream, deadline).await?;
        let length = transport::read_length(stream, deadline).await?;
        let body = transport::read_body(stream, length, deadline).await?;
        let call = decode_frame::<CommitCall>(&body)?;
        // Lane failures travel as error frames (never a hung-up stream), so
        // the caller can tell a lost branch race (retry with a fresh tip)
        // from a transport failure (replay the same id).
        let answered = self.dispatch(&call, deadline).await;
        let id = answered
            .as_ref()
            .map(|(answer, _)| answer.id.clone())
            .unwrap_or_else(|_| "unknown".to_owned());
        let (answer, outcome) = match answered {
            Ok(ok) => ok,
            Err(err) => (answer_error(&id, &err), SubmissionOutcome::Committed),
        };
        let bytes = encode_frame(&answer)?;
        transport::write_body(stream, &bytes, deadline).await?;
        // Refusals travel in the frame above; the Err below only records
        // the refusal for stats (handle counts it once).
        if answer.ok {
            Ok(outcome)
        } else {
            Err(CoreError::new(
                ErrorCode::EIo,
                "lane refused the submission; see the error frame",
            ))
        }
    }

    async fn dispatch(
        &self,
        call: &CommitCall,
        deadline: Instant,
    ) -> Result<(CommitAnswer, SubmissionOutcome), CoreError> {
        let _ = deadline;
        if call.v != FRAME_VERSION {
            return Err(CoreError::new(
                ErrorCode::EVersion,
                format!("sidecar frame v{} is not v{FRAME_VERSION}", call.v),
            ));
        }
        let request_id = call.body.request_id().ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "the sidecar serves mutations only")
        })?;
        let id = request_id.to_string();
        call.body.validate()?;
        // The burst guard inside `burst()` covers the store open; prepare
        // and submit stay concurrent so the loser's retry gap stays small
        // enough for the group-commit sharing window.
        let (coord, session) = self.burst().await?;
        let reply = match coord.prepare_for_dispatch(session, call.body.clone(), &allow, None)? {
            DispatchReady::Replay(reply) => reply,
            DispatchReady::Prepared(prepared) => {
                coord
                    .submit_prepared(&self.owner, *prepared, &self.cancel)
                    .await?
            }
        };
        Ok(ok_answer(&id, reply))
    }
}

// Best-effort persistence: a torn write must never leave a partial secret
// behind, or the next generation opens a needlessly fresh session and loses
// receipt continuity. Write to a sibling, sync the file, rename over the
// target, then sync the directory; any failure keeps the previous record.
#[cfg(unix)]
fn write_session_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = path.with_extension(format!("session-{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let Ok(mut file) = options.open(&tmp) else {
        return;
    };
    {
        use std::io::Write as _;
        if file.write_all(bytes).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return;
        }
    }
    if file.sync_all().is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    drop(file);
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn write_session_file(path: &Path, bytes: &[u8]) {
    let _ = std::fs::write(path, bytes);
}

/// Serves the repository sidecar until the idle TTL lapses.
///
/// Binds `<store_dir>/coordinator.sock` (taking over a stale socket when
/// its owner is gone), wins the store-directory ownership lock, then serves
/// `git.commit` submissions on the publication lane. The store lives only
/// inside submission bursts; an idle server holds no store handle.
///
/// Callers run this inside a Tokio runtime with I/O and time enabled: the
/// lane runner spawns on the current handle.
///
/// # Errors
/// `E_LIMIT` when the socket path is too long, `E_IO` on bind, store, or
/// session failures. Returns [`ServeOutcome::AlreadyRunning`] (as `Ok`)
/// when another owner serves this repository.
#[cfg(unix)]
pub async fn cli_serve(
    store_dir: PathBuf,
    idle: Duration,
) -> Result<(ServeOutcome, ServeStats), CoreError> {
    let sock = socket_path(&store_dir);
    if sock.as_os_str().as_encoded_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("coordinator socket {} is too long", sock.display()),
        ));
    }
    let (format, file) = crate::store::read_format(&store_dir)?;
    drop(file);
    let mut lock = match StoreLock::try_acquire(&store_dir)? {
        Acquisition::Owner(lock) => lock,
        Acquisition::Held(_) => return Ok((ServeOutcome::AlreadyRunning, ServeStats::default())),
    };
    let listener = match tokio::net::UnixListener::bind(&sock) {
        Ok(listener) => listener,
        Err(_) => {
            if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
                return Ok((ServeOutcome::AlreadyRunning, ServeStats::default()));
            }
            let _ = std::fs::remove_file(&sock);
            tokio::net::UnixListener::bind(&sock).map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("coordinator bind {}: {err}", sock.display()),
                )
            })?
        }
    };
    let owner = endpoint::owner()?;
    let nonce = EndpointNonce::generate()?;
    let (_shutdown_handle, cancel) = cancellation();
    let server = Arc::new(Server {
        store_dir: store_dir.clone(),
        store_id: format.id,
        nonce: nonce.clone(),
        owner: owner.clone(),
        idle,
        cancel,
        conns: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        stats: Mutex::new(ServeStats::default()),
        active: AtomicU64::new(0),
        last_activity: Mutex::new(Instant::now()),
        burst: Mutex::new(None),
        burst_open: tokio::sync::Mutex::new(()),
    });
    lock.publish(&LockBody {
        pid: std::process::id(),
        address: EndpointAddress::Unix(sock.clone()),
        nonce,
    })?;
    loop {
        // An externally unlinked socket or lock file means the rendezvous is
        // gone (or a takeover is in progress): retire and exit rather than
        // serve on a dead path while still holding the ownership lock.
        if !sock.exists() || !super::lock::lock_path(&store_dir).exists() {
            server.retire_burst().await;
            break;
        }
        // Every wait is bounded by the burst linger: a finished worker must
        // wake this loop so its burst retires and the process can idle out,
        // instead of parking in `accept` until the next arrival.
        let active = server.active.load(Ordering::SeqCst);
        let elapsed = server
            .last_activity
            .lock()
            .map(|activity| activity.elapsed())
            .unwrap_or(Duration::ZERO);
        if active == 0 {
            // Release the store past the burst linger so clients reopening
            // after their round trip find a free lock; the socket, the
            // ownership lock, and the session file stay until the idle TTL.
            if elapsed >= BURST_LINGER {
                server.retire_burst().await;
            }
            if elapsed >= server.idle {
                break;
            }
            let wait = (server.idle - elapsed).min(BURST_LINGER);
            match timeout(wait, listener.accept()).await {
                Ok(Ok((stream, _))) => accept_conn(&server, stream),
                Ok(Err(_)) => {
                    if server.active.load(Ordering::SeqCst) == 0 {
                        server.retire_burst().await;
                        break;
                    }
                }
                Err(_) => {}
            }
        } else {
            match timeout(BURST_LINGER, listener.accept()).await {
                Ok(Ok((stream, _))) => accept_conn(&server, stream),
                Ok(Err(_)) => {
                    if server.active.load(Ordering::SeqCst) == 0 {
                        server.retire_burst().await;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
    }
    let stats = server
        .stats
        .lock()
        .map(|stats| stats.clone())
        .unwrap_or_default();
    let _ = write_stats_sidecar(&store_dir, &stats);
    // Unlink before releasing the lock: the next owner must find a free
    // path the moment this lock goes free, never a stale file to probe.
    let _ = std::fs::remove_file(&sock);
    drop(lock);
    Ok((ServeOutcome::Idle, stats))
}

#[cfg(unix)]
fn accept_conn(server: &Arc<Server>, stream: Incoming) {
    match server.conns.clone().try_acquire_owned() {
        Ok(permit) => {
            // Counted here, synchronously in the accept thread, so the idle
            // shutdown below can never sample zero while a worker is
            // starting: retirement only runs with no counted worker alive.
            server.active.fetch_add(1, Ordering::SeqCst);
            let worker = Arc::clone(server);
            tokio::spawn(async move {
                let _permit = permit;
                worker.handle(stream).await;
            });
        }
        Err(_) => server.note_error(),
    }
}

/// Non-Unix sidecars refuse: named-pipe rendezvous is not implemented.
#[cfg(not(unix))]
pub async fn cli_serve(
    _store_dir: PathBuf,
    _idle: Duration,
) -> Result<(ServeOutcome, ServeStats), CoreError> {
    Err(CoreError::new(
        ErrorCode::EHosted,
        "the per-repo coordinator sidecar is Unix-only",
    ))
}

fn write_stats_sidecar(store_dir: &Path, stats: &ServeStats) -> Result<(), CoreError> {
    let bytes = encode_frame(stats)?;
    std::fs::write(store_dir.join("coordinator.stats"), bytes)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("coordinator stats: {err}")))
}
