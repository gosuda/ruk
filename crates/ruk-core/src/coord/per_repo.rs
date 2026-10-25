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

use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout};

use super::endpoint::{self, Outgoing};
use super::handshake;
use super::lock::{Acquisition, LockBody, LockSnapshot, StoreLock};
use super::transport;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{Reply, Request};

#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use server::cli_serve;

/// Socket leaf name inside the store directory.
pub(crate) const SOCK_NAME: &str = "coordinator.sock";

/// Protocol version of the sidecar frames below.
pub const FRAME_VERSION: u32 = 1;

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

/// Non-Unix sidecars refuse: named-pipe rendezvous is not implemented.
#[cfg(not(unix))]
pub async fn cli_serve(
    _store_dir: PathBuf,
    _idle: std::time::Duration,
) -> Result<(ServeOutcome, ServeStats), CoreError> {
    Err(CoreError::new(
        ErrorCode::EHosted,
        "the per-repo coordinator sidecar is Unix-only",
    ))
}
