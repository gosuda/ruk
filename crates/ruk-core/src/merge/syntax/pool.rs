//! Bounded reusable syntax worker pool for tree-sitter three-way merges.
//!
//! # Architecture and Synchronization
//!
//! To protect the coordinator process from native scanner crashes, unbounded
//! memory consumption, and arbitrary third-party grammar failures, syntax
//! merges are executed within child worker processes. Each child is launched
//! by re-executing the current binary ([`std::env::current_exe`]) with the
//! internal flag [`WORKER_ARG`] (`--ruk-syntax-worker`). Workers are reused
//! across merges; a worker process is never spawned per individual file.
//!
//! While Tokio is available in the workspace dependencies, `ruk-core`'s model
//! and merge layers are synchronous today. This module therefore uses plain
//! [`std::process`] child processes together with a dedicated reader thread per
//! worker to handle stdout streaming and synchronous wall-clock deadline
//! enforcement without an asynchronous runtime.
//!
//! # Framing Protocol
//!
//! Communication between the coordinator pool and worker children travels over
//! standard input and standard output using a compact binary framing protocol:
//!
//! ```text
//! +-------------------+---------------+----------------------+------------------+
//! | Magic (4 bytes)   | Version (1 B) | Length (4 B, BE u32) | Record Kind (1B) |
//! | b"RSWF"           | 1             | N                    | e.g. 1 (Req)     |
//! +-------------------+---------------+----------------------+------------------+
//! | Payload (N bytes)                                                           |
//! +-----------------------------------------------------------------------------+
//! ```
//!
//! - **Magic**: `b"RSWF"` (Ruk Syntax Worker Frame).
//! - **Version**: `1` ([`FRAME_VERSION`]).
//! - **Record Length**: Big-endian `u32` payload byte count.
//! - **Record Kind**:
//!   - `1` ([`RECORD_KIND_MERGE_REQ`]): Length-prefixed binary request frame.
//!   - `2` ([`RECORD_KIND_MERGE_RESP`]): JSON-encoded [`WorkerResponsePayload`].
//!   - `3` ([`RECORD_KIND_SHUTDOWN`]): Clean worker shutdown instruction.
//!
//! # Resource Bounds
//!
//! - **Worker Cap**: At most two child processes are kept alive simultaneously.
//!   When replacing a crashed or cancelled worker, the dead child is reaped
//!   before any replacement process is spawned, guaranteeing that the two-worker
//!   cap is never exceeded during replacement.
//! - **Address Space**: 512 MiB limit per worker child process. On Linux and
//!   macOS, `setrlimit(RLIMIT_AS)` is applied via `rustix::process` in the
//!   child before loading any grammar. On Windows, Job Objects are required to
//!   bound worker process memory; because Job Objects are not implemented in
//!   this phase, the worker returns `E_UNSUPPORTED_OPERATION`.
//! - **Wall Deadline**: 2-second wall deadline per file enforced by the parent.
//! - **Triplet Bound**: Combined source bytes (`base + ours + theirs`) must not
//!   exceed 8 MiB ([`MAX_TRIPLET_BYTES`]). Overruns decline to bounded text merge.
//! - **Queue Bound**: At most 32 file triplets may wait in the pool's admission
//!   queue. Source bytes remain stored in the caller's buffer rather than copied.
//!
//! # Health and Failures
//!
//! - If a worker crashes or exceeds resource bounds, the request is recorded as
//!   declined and the coordinator proceeds to bounded text merge.
//! - Two crashes for the same grammar within one pool lifetime mark that grammar
//!   as [`GrammarHealth::Unhealthy`]. Subsequent merges for that grammar fail
//!   `E_IO` naming the grammar ID until operator intervention recreates the pool.
//! - Cooperative cancellation immediately aborts with `E_CANCELLED` and does
//!   NOT fall back to text merge.

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ByteString;
use crate::merge::composed::MergeNotices;
use crate::merge::syntax::adapters::DeclineReason;
use crate::merge::syntax::alignment::merge_triplet;
use crate::merge::syntax::decline_notices;
use crate::merge::syntax::grammar::{
    Cancel, GrammarRegistry, Language, MAX_TRIPLET_BYTES, SyntaxError, sha256_hex,
};
use crate::merge::syntax::{
    ByteEdit, EditProvenance, SyntaxOutcome, SyntaxProvenance, SyntaxRequest,
};

/// Internal command-line argument for the worker process entry point.
pub const WORKER_ARG: &str = "--ruk-syntax-worker";

/// Protocol magic bytes identifying a Ruk Syntax Worker Frame (`b"RSWF"`).
pub const FRAME_MAGIC: [u8; 4] = *b"RSWF";

/// Protocol format version.
pub const FRAME_VERSION: u8 = 1;

/// Record kind: merge request from coordinator to worker child.
pub const RECORD_KIND_MERGE_REQ: u8 = 1;

/// Record kind: merge response from worker child to coordinator.
pub const RECORD_KIND_MERGE_RESP: u8 = 2;

/// Record kind: graceful shutdown request from coordinator to worker child.
pub const RECORD_KIND_SHUTDOWN: u8 = 3;

/// Total byte length of a frame header (4 magic + 1 version + 4 length + 1 kind).
pub const HEADER_LEN: usize = 10;

/// Default maximum active child worker processes.
pub const DEFAULT_MAX_WORKERS: usize = 2;

/// Default per-file wall deadline enforced by coordinator.
pub const DEFAULT_FILE_DEADLINE: Duration = Duration::from_secs(2);

/// Default queue capacity for in-flight merge requests.
pub const DEFAULT_QUEUE_CAPACITY: usize = 32;

/// Default address-space limit for worker processes (512 MiB).
pub const DEFAULT_ADDRESS_SPACE_BYTES: u64 = 512 * 1024 * 1024;

/// Plain framing header encoding framing metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Magic identifier bytes (`b"RSWF"`).
    pub magic: [u8; 4],
    /// Protocol version (`1`).
    pub version: u8,
    /// Payload length in bytes (big-endian).
    pub length: u32,
    /// Record kind discriminator.
    pub kind: u8,
}

impl FrameHeader {
    /// Constructs a new frame header for the given kind and payload length.
    #[must_use]
    pub const fn new(kind: u8, length: u32) -> Self {
        Self {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            length,
            kind,
        }
    }

    /// Encodes the header into fixed 10-byte wire representation:
    /// magic (4 bytes), version (1 byte), length (4 bytes BE), kind (1 byte).
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5..9].copy_from_slice(&self.length.to_be_bytes());
        buf[9] = self.kind;
        buf
    }

    /// Decodes a header from wire bytes.
    ///
    /// # Errors
    /// Returns [`FrameError`] if magic is invalid or protocol version is unsupported.
    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self, FrameError> {
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic(magic));
        }
        let version = buf[4];
        if version != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        let length = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let kind = buf[9];
        Ok(Self {
            magic,
            version,
            length,
            kind,
        })
    }
}

/// Errors occurring while encoding, decoding, or transporting protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Magic header bytes do not match expected `b"RSWF"`.
    #[error("invalid frame magic: {0:?}")]
    InvalidMagic([u8; 4]),
    /// Frame version is not supported.
    #[error("unsupported frame version: {0}")]
    UnsupportedVersion(u8),
    /// Payload size exceeds allowable memory or buffer capacity.
    #[error("payload exceeds maximum frame size: {0}")]
    PayloadTooLarge(usize),
    /// Frame stream terminated unexpectedly.
    #[error("unexpected end of frame stream")]
    UnexpectedEof,
    /// Corrupted payload content.
    #[error("corrupted frame payload: {0}")]
    CorruptPayload(String),
    /// Standard I/O communication failure.
    #[error("frame I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Operational resource and queuing bounds for [`SyntaxPool`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolLimits {
    /// Maximum live child worker processes (capped at 2).
    pub max_workers: usize,
    /// Maximum combined triplet bytes (`base + ours + theirs`).
    pub max_triplet_bytes: u64,
    /// Per-file wall-clock timeout enforced by the coordinator.
    pub per_file_deadline: Duration,
    /// Bounded in-flight queue capacity before requests decline.
    pub queue_capacity: usize,
    /// Per-worker address space limit in bytes (512 MiB).
    pub address_space_bytes: u64,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_workers: DEFAULT_MAX_WORKERS,
            max_triplet_bytes: MAX_TRIPLET_BYTES,
            per_file_deadline: DEFAULT_FILE_DEADLINE,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            address_space_bytes: DEFAULT_ADDRESS_SPACE_BYTES,
        }
    }
}

/// Health status of a catalogued tree-sitter grammar within a pool lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrammarHealth {
    /// Grammar has suffered fewer than two crashes and is accepted for syntax merge.
    Healthy,
    /// Grammar has crashed twice; further merges fail `E_IO` until pool recreation.
    Unhealthy,
}

impl GrammarHealth {
    /// Whether the grammar is operating normally.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Whether the grammar has been marked unhealthy.
    #[must_use]
    pub const fn is_unhealthy(self) -> bool {
        matches!(self, Self::Unhealthy)
    }
}

/// Outcome of one syntax triplet merge processed through the worker pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolOutcome {
    /// Clean syntax merge producing verified replacement edits.
    Clean {
        /// Base-relative edits that produce merged bytes.
        edits: Vec<ByteEdit>,
        /// Merge notices (empty on a clean syntax outcome).
        notices: MergeNotices,
    },
    /// Syntax stage declined; caller runs bounded text merge with notices.
    Declined {
        /// Machine-readable decline reason.
        reason: DeclineReason,
        /// Merge notices describing the decline.
        notices: MergeNotices,
    },
}

impl PoolOutcome {
    /// Whether the outcome is clean.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    /// Whether the syntax merge was declined.
    #[must_use]
    pub const fn is_declined(&self) -> bool {
        matches!(self, Self::Declined { .. })
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum WirePoolOutcomeRef<'a> {
    Clean {
        edits: &'a [ByteEdit],
        notices: &'a MergeNotices,
    },
    Declined {
        reason: &'static str,
        notices: &'a MergeNotices,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum WirePoolOutcomeOwned {
    Clean {
        edits: Vec<ByteEdit>,
        notices: MergeNotices,
    },
    Declined {
        reason: String,
        notices: MergeNotices,
    },
}

impl Serialize for PoolOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Clean { edits, notices } => {
                WirePoolOutcomeRef::Clean { edits, notices }.serialize(serializer)
            }
            Self::Declined { reason, notices } => WirePoolOutcomeRef::Declined {
                reason: reason.as_str(),
                notices,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PoolOutcome {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WirePoolOutcomeOwned::deserialize(deserializer)?;
        match wire {
            WirePoolOutcomeOwned::Clean { edits, notices } => Ok(Self::Clean { edits, notices }),
            WirePoolOutcomeOwned::Declined { reason, notices } => {
                let parsed = parse_decline_reason(&reason).unwrap_or(DeclineReason::ParseFailed);
                Ok(Self::Declined {
                    reason: parsed,
                    notices,
                })
            }
        }
    }
}

/// JSON-serialized payload transmitted across worker stdout frames.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WorkerResponsePayload {
    /// Clean outcome with edits and provenance.
    Clean {
        /// Replacement byte edits.
        edits: Vec<ByteEdit>,
        /// Digest and origin provenance.
        provenance: SyntaxProvenance,
        /// Diagnostic notices.
        notices: MergeNotices,
    },
    /// Structured decline outcome.
    Declined {
        /// Wire spelling of [`DeclineReason`].
        reason: String,
        /// Detail text.
        detail: String,
        /// Diagnostic notices.
        notices: MergeNotices,
    },
    /// Worker execution error.
    Error {
        /// Machine-readable error code.
        code: String,
        /// Diagnostic error message.
        message: String,
    },
}

/// Errors encountered while spawning, driving, or communicating with a worker child.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// Failed to determine path to current executable.
    #[error("failed to discover current executable: {0}")]
    ExeDiscovery(std::io::Error),
    /// Child process spawn failure.
    #[error("failed to spawn worker process: {0}")]
    Spawn(std::io::Error),
    /// Standard pipe configuration failure.
    #[error("failed to initialize worker standard pipes")]
    PipeInit,
    /// Child process terminated unexpectedly or pipe closed.
    #[error("worker process exited unexpectedly")]
    ChildExited,
    /// Protocol frame decoding failure.
    #[error("framing error: {0}")]
    Frame(#[from] FrameError),
    /// JSON response deserialization failure.
    #[error("corrupted worker response: {0}")]
    CorruptResponse(String),
}

#[derive(Debug)]
enum AcquireError {
    Cancelled,
    QueueFull,
    Shutdown,
    Spawn(WorkerError),
}

#[derive(Debug)]
enum WorkerWaitError {
    Cancelled,
    TimedOut,
    WorkerFailed(WorkerError),
}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Result<WorkerResponsePayload, WorkerError>>,
    reader_handle: Option<std::thread::JoinHandle<()>>,
}

impl WorkerProcess {
    fn kill_and_reap(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
    }

    fn shutdown(&mut self) {
        let _ = write_frame(&mut self.stdin, RECORD_KIND_SHUTDOWN, &[]);
        let _ = self.child.wait();
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct PoolState {
    idle_workers: Vec<WorkerProcess>,
    active_worker_count: usize,
    queued_count: usize,
    crashes_by_language: HashMap<Language, u32>,
    unhealthy_languages: HashSet<Language>,
    is_shutdown: bool,
}

/// Bounded reusable syntax worker pool managing at most two worker processes.
pub struct SyntaxPool {
    limits: PoolLimits,
    state: Mutex<PoolState>,
    available: Condvar,
}

impl fmt::Debug for SyntaxPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntaxPool")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Default for SyntaxPool {
    fn default() -> Self {
        Self::new(PoolLimits::default())
    }
}

impl SyntaxPool {
    /// Creates a new syntax worker pool with specified limits.
    ///
    /// Child processes are started lazily upon first merge demand.
    #[must_use]
    pub fn new(limits: PoolLimits) -> Self {
        let max_workers = limits.max_workers.min(DEFAULT_MAX_WORKERS);
        let safe_limits = PoolLimits {
            max_workers,
            ..limits
        };
        Self {
            limits: safe_limits,
            state: Mutex::new(PoolState {
                idle_workers: Vec::with_capacity(safe_limits.max_workers),
                active_worker_count: 0,
                queued_count: 0,
                crashes_by_language: HashMap::new(),
                unhealthy_languages: HashSet::new(),
                is_shutdown: false,
            }),
            available: Condvar::new(),
        }
    }

    /// Queries the health status of `language`.
    #[must_use]
    pub fn grammar_health(&self, language: Language) -> GrammarHealth {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.unhealthy_languages.contains(&language) {
            GrammarHealth::Unhealthy
        } else {
            GrammarHealth::Healthy
        }
    }

    /// Manually records a crash for `language` within this pool lifetime.
    ///
    /// Two recorded crashes transition the grammar to [`GrammarHealth::Unhealthy`].
    pub fn record_crash(&self, language: Language) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let count = state.crashes_by_language.entry(language).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= 2 {
            state.unhealthy_languages.insert(language);
        }
    }

    /// Merges one file triplet using a pooled worker child process.
    ///
    /// # Errors
    /// - Returns [`SyntaxError::Cancelled`] if `cancel` fires before publication.
    /// - Returns [`SyntaxError::Invalid`] (`E_IO`) if the selected grammar is unhealthy.
    pub fn merge(
        &self,
        request: &SyntaxRequest<'_>,
        cancel: &Cancel,
    ) -> Result<PoolOutcome, SyntaxError> {
        cancel.check()?;

        if self.grammar_health(request.language).is_unhealthy() {
            return Err(SyntaxError::Invalid {
                what: "grammar",
                detail: format!(
                    "grammar '{}' marked unhealthy after repeated worker crashes (E_IO)",
                    request.language.id()
                ),
            });
        }

        let total_len = request.total_len();
        if total_len > self.limits.max_triplet_bytes {
            let notices = decline_notices(
                request,
                DeclineReason::SizeLimit,
                &format!(
                    "triplet bytes {} exceeds {} byte limit",
                    total_len, self.limits.max_triplet_bytes
                ),
                None,
            );
            return Ok(PoolOutcome::Declined {
                reason: DeclineReason::SizeLimit,
                notices,
            });
        }

        let mut worker = match self.acquire_worker(cancel) {
            Ok(w) => w,
            Err(err) => return self.handle_acquire_error(request, err),
        };

        let Ok(payload) = encode_request_payload(request) else {
            self.release_idle_worker(worker);
            let notices = decline_notices(
                request,
                DeclineReason::SizeLimit,
                "failed to encode request payload",
                None,
            );
            return Ok(PoolOutcome::Declined {
                reason: DeclineReason::SizeLimit,
                notices,
            });
        };

        if let Err(err) = write_frame(&mut worker.stdin, RECORD_KIND_MERGE_REQ, &payload) {
            self.handle_worker_crash(worker, request.language);
            let notices = decline_notices(
                request,
                DeclineReason::GrammarUnavailable,
                &format!("failed to write frame to syntax worker: {err}"),
                None,
            );
            return Ok(PoolOutcome::Declined {
                reason: DeclineReason::GrammarUnavailable,
                notices,
            });
        }

        let wait_res =
            self.wait_for_worker_response(&worker, cancel, self.limits.per_file_deadline);
        match wait_res {
            Ok(payload) => self.handle_worker_payload(worker, request, payload),
            Err(wait_err) => self.handle_worker_wait_error(worker, request, wait_err),
        }
    }

    /// Shuts down the worker pool, reaping all idle worker child processes.
    pub fn shutdown(self) {
        let workers = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.is_shutdown = true;
            std::mem::take(&mut state.idle_workers)
        };
        for mut worker in workers {
            worker.shutdown();
        }
    }

    fn handle_acquire_error(
        &self,
        request: &SyntaxRequest<'_>,
        err: AcquireError,
    ) -> Result<PoolOutcome, SyntaxError> {
        match err {
            AcquireError::Cancelled => Err(SyntaxError::Cancelled(
                "syntax merge cancelled before publication".to_owned(),
            )),
            AcquireError::QueueFull => {
                let notices = decline_notices(
                    request,
                    DeclineReason::SizeLimit,
                    &format!(
                        "syntax worker queue capacity of {} reached",
                        self.limits.queue_capacity
                    ),
                    None,
                );
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::SizeLimit,
                    notices,
                })
            }
            AcquireError::Shutdown => {
                let notices = decline_notices(
                    request,
                    DeclineReason::GrammarUnavailable,
                    "syntax pool is shut down",
                    None,
                );
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::GrammarUnavailable,
                    notices,
                })
            }
            AcquireError::Spawn(spawn_err) => {
                let notices = decline_notices(
                    request,
                    DeclineReason::GrammarUnavailable,
                    &format!("failed to spawn syntax worker process: {spawn_err}"),
                    None,
                );
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::GrammarUnavailable,
                    notices,
                })
            }
        }
    }

    fn handle_worker_wait_error(
        &self,
        worker: WorkerProcess,
        request: &SyntaxRequest<'_>,
        err: WorkerWaitError,
    ) -> Result<PoolOutcome, SyntaxError> {
        match err {
            WorkerWaitError::Cancelled => {
                self.kill_and_reap_cancelled(worker);
                Err(SyntaxError::Cancelled(
                    "syntax merge cancelled before publication".to_owned(),
                ))
            }
            WorkerWaitError::TimedOut => {
                self.kill_and_reap_timed_out(worker);
                let notices = decline_notices(
                    request,
                    DeclineReason::SizeLimit,
                    &format!(
                        "syntax worker exceeded {:?} wall deadline",
                        self.limits.per_file_deadline
                    ),
                    None,
                );
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::SizeLimit,
                    notices,
                })
            }
            WorkerWaitError::WorkerFailed(fail_err) => {
                self.handle_worker_crash(worker, request.language);
                let notices = decline_notices(
                    request,
                    DeclineReason::GrammarUnavailable,
                    &format!(
                        "syntax worker failed while parsing {}: {fail_err}",
                        request.language.id()
                    ),
                    None,
                );
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::GrammarUnavailable,
                    notices,
                })
            }
        }
    }

    fn acquire_worker(&self, cancel: &Cancel) -> Result<WorkerProcess, AcquireError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if cancel.is_cancelled() {
                return Err(AcquireError::Cancelled);
            }
            if state.is_shutdown {
                return Err(AcquireError::Shutdown);
            }
            if let Some(worker) = state.idle_workers.pop() {
                return Ok(worker);
            }
            if state.active_worker_count < self.limits.max_workers {
                return self.try_spawn_worker(state);
            }
            if state.queued_count >= self.limits.queue_capacity {
                return Err(AcquireError::QueueFull);
            }
            state = self.wait_in_queue(state);
        }
    }

    fn wait_in_queue<'a>(&self, mut state: MutexGuard<'a, PoolState>) -> MutexGuard<'a, PoolState> {
        state.queued_count = state.queued_count.saturating_add(1);
        let wait_res = self
            .available
            .wait_timeout(state, Duration::from_millis(20));
        let mut next_state = wait_res.unwrap_or_else(|p| p.into_inner()).0;
        next_state.queued_count = next_state.queued_count.saturating_sub(1);
        next_state
    }

    fn try_spawn_worker(
        &self,
        guard: MutexGuard<'_, PoolState>,
    ) -> Result<WorkerProcess, AcquireError> {
        let mut state = guard;
        state.active_worker_count = state.active_worker_count.saturating_add(1);
        drop(state);
        match spawn_worker() {
            Ok(worker) => Ok(worker),
            Err(err) => {
                let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
                s.active_worker_count = s.active_worker_count.saturating_sub(1);
                self.available.notify_one();
                Err(AcquireError::Spawn(err))
            }
        }
    }

    fn release_idle_worker(&self, mut worker: WorkerProcess) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.is_shutdown {
            state.active_worker_count = state.active_worker_count.saturating_sub(1);
            drop(state);
            worker.shutdown();
        } else {
            state.idle_workers.push(worker);
            self.available.notify_one();
        }
    }

    fn handle_worker_crash(&self, mut worker: WorkerProcess, language: Language) {
        worker.kill_and_reap();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let count = state.crashes_by_language.entry(language).or_insert(0);
        *count = count.saturating_add(1);
        if *count >= 2 {
            state.unhealthy_languages.insert(language);
        }
        state.active_worker_count = state.active_worker_count.saturating_sub(1);
        self.available.notify_one();
    }

    fn kill_and_reap_cancelled(&self, mut worker: WorkerProcess) {
        worker.kill_and_reap();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active_worker_count = state.active_worker_count.saturating_sub(1);
        self.available.notify_one();
    }

    fn kill_and_reap_timed_out(&self, mut worker: WorkerProcess) {
        worker.kill_and_reap();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active_worker_count = state.active_worker_count.saturating_sub(1);
        self.available.notify_one();
    }

    fn wait_for_worker_response(
        &self,
        worker: &WorkerProcess,
        cancel: &Cancel,
        deadline: Duration,
    ) -> Result<WorkerResponsePayload, WorkerWaitError> {
        let start = Instant::now();
        loop {
            if cancel.is_cancelled() {
                return Err(WorkerWaitError::Cancelled);
            }
            if start.elapsed() >= deadline {
                return Err(WorkerWaitError::TimedOut);
            }
            let step = deadline
                .saturating_sub(start.elapsed())
                .min(Duration::from_millis(10));
            if let Some(res) = poll_worker_channel(&worker.rx, step)? {
                return Ok(res);
            }
        }
    }

    fn handle_worker_payload(
        &self,
        worker: WorkerProcess,
        request: &SyntaxRequest<'_>,
        payload: WorkerResponsePayload,
    ) -> Result<PoolOutcome, SyntaxError> {
        match payload {
            WorkerResponsePayload::Clean {
                edits,
                provenance,
                notices,
            } => {
                self.release_idle_worker(worker);
                if !validate_clean_response(request, &edits, &provenance) {
                    let notices = decline_notices(
                        request,
                        DeclineReason::ParseFailed,
                        "coordinator rejected worker edits: range or digest mismatch",
                        None,
                    );
                    return Ok(PoolOutcome::Declined {
                        reason: DeclineReason::ParseFailed,
                        notices,
                    });
                }
                Ok(PoolOutcome::Clean { edits, notices })
            }
            WorkerResponsePayload::Declined {
                reason,
                detail: _,
                notices,
            } => {
                self.release_idle_worker(worker);
                let parsed = parse_decline_reason(&reason).unwrap_or(DeclineReason::ParseFailed);
                Ok(PoolOutcome::Declined {
                    reason: parsed,
                    notices,
                })
            }
            WorkerResponsePayload::Error { code, message } => {
                self.release_idle_worker(worker);
                if code == "E_CANCELLED" {
                    return Err(SyntaxError::Cancelled(message));
                }
                let notices =
                    decline_notices(request, DeclineReason::GrammarUnavailable, &message, None);
                Ok(PoolOutcome::Declined {
                    reason: DeclineReason::GrammarUnavailable,
                    notices,
                })
            }
        }
    }
}

fn poll_worker_channel(
    rx: &mpsc::Receiver<Result<WorkerResponsePayload, WorkerError>>,
    timeout: Duration,
) -> Result<Option<WorkerResponsePayload>, WorkerWaitError> {
    match rx.recv_timeout(timeout) {
        Ok(Ok(payload)) => Ok(Some(payload)),
        Ok(Err(err)) => Err(WorkerWaitError::WorkerFailed(err)),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(WorkerWaitError::WorkerFailed(WorkerError::ChildExited))
        }
    }
}

impl Drop for SyntaxPool {
    fn drop(&mut self) {
        let workers = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.is_shutdown = true;
            std::mem::take(&mut state.idle_workers)
        };
        for mut worker in workers {
            worker.kill_and_reap();
        }
    }
}

fn spawn_worker() -> Result<WorkerProcess, WorkerError> {
    let exe = std::env::current_exe().map_err(WorkerError::ExeDiscovery)?;
    let mut cmd = Command::new(exe);
    cmd.arg(WORKER_ARG);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    cmd.env_clear();
    for var in [
        "PATH",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "SYSTEMROOT",
        "TMPDIR",
    ] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    let mut child = cmd.spawn().map_err(WorkerError::Spawn)?;
    let Some(stdin) = child.stdin.take() else {
        return Err(WorkerError::PipeInit);
    };
    let Some(mut stdout) = child.stdout.take() else {
        return Err(WorkerError::PipeInit);
    };

    let (tx, rx) = mpsc::sync_channel(2);
    let reader_handle = std::thread::spawn(move || {
        read_worker_stdout_loop(&mut stdout, tx);
    });

    Ok(WorkerProcess {
        child,
        stdin,
        rx,
        reader_handle: Some(reader_handle),
    })
}

fn read_worker_stdout_loop(
    stdout: &mut std::process::ChildStdout,
    tx: mpsc::SyncSender<Result<WorkerResponsePayload, WorkerError>>,
) {
    loop {
        let Ok(frame_opt) = read_frame(stdout) else {
            let _ = tx.send(Err(WorkerError::ChildExited));
            break;
        };
        let Some((header, payload)) = frame_opt else {
            break;
        };
        if header.kind != RECORD_KIND_MERGE_RESP {
            continue;
        }
        dispatch_worker_stdout_payload(&payload, &tx);
    }
}

fn dispatch_worker_stdout_payload(
    payload: &[u8],
    tx: &mpsc::SyncSender<Result<WorkerResponsePayload, WorkerError>>,
) {
    let Ok(resp) = sonic_rs::from_slice::<WorkerResponsePayload>(payload) else {
        let _ = tx.send(Err(WorkerError::CorruptResponse(
            "corrupt JSON payload".to_owned(),
        )));
        return;
    };
    let _ = tx.send(Ok(resp));
}

/// Reads one protocol frame from `reader`.
///
/// Returns `Ok(None)` if the stream closed cleanly at a frame boundary.
///
/// # Errors
/// Returns [`FrameError`] if magic bytes, protocol version, or frame length is invalid.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<(FrameHeader, Vec<u8>)>, FrameError> {
    let mut first_byte = [0u8; 1];
    let n = reader.read(&mut first_byte)?;
    if n == 0 {
        return Ok(None);
    }
    let mut header_buf = [0u8; HEADER_LEN];
    header_buf[0] = first_byte[0];
    reader.read_exact(&mut header_buf[1..])?;

    let header = FrameHeader::decode(&header_buf)?;
    let length =
        usize::try_from(header.length).map_err(|_| FrameError::PayloadTooLarge(usize::MAX))?;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok(Some((header, payload)))
}

/// Writes one protocol frame containing `payload` to `writer` and flushes.
///
/// # Errors
/// Returns [`FrameError`] if payload length exceeds `u32::MAX` or writing fails.
pub fn write_frame<W: Write>(writer: &mut W, kind: u8, payload: &[u8]) -> Result<(), FrameError> {
    let length =
        u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge(payload.len()))?;
    let header = FrameHeader::new(kind, length);
    let encoded = header.encode();
    writer.write_all(&encoded)?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Encodes a syntax merge request into length-prefixed binary frame payload bytes.
///
/// # Errors
/// Returns [`FrameError::PayloadTooLarge`] if any field exceeds addressable wire bounds.
pub fn encode_request_payload(req: &SyntaxRequest<'_>) -> Result<Vec<u8>, FrameError> {
    let lang_id = req.language.id().as_bytes();
    let lang_len =
        u16::try_from(lang_id.len()).map_err(|_| FrameError::PayloadTooLarge(lang_id.len()))?;
    let path_bytes = req.path.as_bytes();
    let path_len = u32::try_from(path_bytes.len())
        .map_err(|_| FrameError::PayloadTooLarge(path_bytes.len()))?;
    let base_len =
        u32::try_from(req.base.len()).map_err(|_| FrameError::PayloadTooLarge(req.base.len()))?;
    let ours_len =
        u32::try_from(req.ours.len()).map_err(|_| FrameError::PayloadTooLarge(req.ours.len()))?;
    let theirs_len = u32::try_from(req.theirs.len())
        .map_err(|_| FrameError::PayloadTooLarge(req.theirs.len()))?;

    let total_len = 2
        + lang_id.len()
        + 4
        + path_bytes.len()
        + 4
        + req.base.len()
        + 4
        + req.ours.len()
        + 4
        + req.theirs.len();

    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&lang_len.to_be_bytes());
    buf.extend_from_slice(lang_id);
    buf.extend_from_slice(&path_len.to_be_bytes());
    buf.extend_from_slice(path_bytes);
    buf.extend_from_slice(&base_len.to_be_bytes());
    buf.extend_from_slice(req.base);
    buf.extend_from_slice(&ours_len.to_be_bytes());
    buf.extend_from_slice(req.ours);
    buf.extend_from_slice(&theirs_len.to_be_bytes());
    buf.extend_from_slice(req.theirs);
    Ok(buf)
}

/// Borrowed representation of a decoded merge request payload.
#[derive(Debug)]
pub struct DecodedRequest<'a> {
    /// Validated language identifier.
    pub language: Language,
    /// Path of the file being merged.
    pub path: ByteString,
    /// Base ancestor bytes borrowed from frame payload.
    pub base: &'a [u8],
    /// Ours side bytes borrowed from frame payload.
    pub ours: &'a [u8],
    /// Theirs side bytes borrowed from frame payload.
    pub theirs: &'a [u8],
}

/// Decodes binary frame payload bytes into a borrowed [`DecodedRequest`].
///
/// # Errors
/// Returns [`FrameError::CorruptPayload`] if fields are truncated, unparseable, or trailing.
pub fn decode_request_payload(payload: &[u8]) -> Result<DecodedRequest<'_>, FrameError> {
    let mut cursor = 0usize;

    if cursor + 2 > payload.len() {
        return Err(FrameError::CorruptPayload(
            "truncated language length".to_owned(),
        ));
    }
    let lang_len = usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
    cursor += 2;
    if cursor + lang_len > payload.len() {
        return Err(FrameError::CorruptPayload(
            "truncated language id".to_owned(),
        ));
    }
    let lang_str = std::str::from_utf8(&payload[cursor..cursor + lang_len])
        .map_err(|e| FrameError::CorruptPayload(format!("invalid utf8 in language: {e}")))?;
    let Some(language) = Language::from_id(lang_str) else {
        return Err(FrameError::CorruptPayload(format!(
            "unknown language id: {lang_str}"
        )));
    };
    cursor += lang_len;

    let (path_bytes, next_cursor) = read_length_prefixed_slice(payload, cursor)?;
    let path = ByteString::from(path_bytes);
    cursor = next_cursor;

    let (base, next_cursor) = read_length_prefixed_slice(payload, cursor)?;
    cursor = next_cursor;

    let (ours, next_cursor) = read_length_prefixed_slice(payload, cursor)?;
    cursor = next_cursor;

    let (theirs, next_cursor) = read_length_prefixed_slice(payload, cursor)?;
    cursor = next_cursor;

    if cursor != payload.len() {
        return Err(FrameError::CorruptPayload(
            "trailing bytes in payload".to_owned(),
        ));
    }

    Ok(DecodedRequest {
        language,
        path,
        base,
        ours,
        theirs,
    })
}

fn read_length_prefixed_slice(payload: &[u8], cursor: usize) -> Result<(&[u8], usize), FrameError> {
    if cursor + 4 > payload.len() {
        return Err(FrameError::CorruptPayload(
            "truncated field length".to_owned(),
        ));
    }
    let len = usize::try_from(u32::from_be_bytes([
        payload[cursor],
        payload[cursor + 1],
        payload[cursor + 2],
        payload[cursor + 3],
    ]))
    .map_err(|_| FrameError::PayloadTooLarge(usize::MAX))?;
    let start = cursor + 4;
    let end = start + len;
    if end > payload.len() {
        return Err(FrameError::CorruptPayload(
            "truncated field bytes".to_owned(),
        ));
    }
    Ok((&payload[start..end], end))
}

/// Parses a machine-readable decline reason string into its typed [`DeclineReason`].
#[must_use]
pub fn parse_decline_reason(text: &str) -> Option<DeclineReason> {
    match text {
        "same-unit-changed" => Some(DeclineReason::SameUnitChanged),
        "duplicate-key" => Some(DeclineReason::DuplicateKey),
        "changed-key" => Some(DeclineReason::ChangedKey),
        "ambiguous-rename" => Some(DeclineReason::AmbiguousRename),
        "competing-insertion" => Some(DeclineReason::CompetingInsertion),
        "overlapping-edits" => Some(DeclineReason::OverlappingEdits),
        "unsupported-construct" => Some(DeclineReason::UnsupportedConstruct),
        "parse-failed" => Some(DeclineReason::ParseFailed),
        "size-limit" => Some(DeclineReason::SizeLimit),
        "binary-content" => Some(DeclineReason::BinaryContent),
        "composed-language" => Some(DeclineReason::ComposedLanguage),
        "grammar-unavailable" => Some(DeclineReason::GrammarUnavailable),
        _ => None,
    }
}

fn validate_clean_response(
    req: &SyntaxRequest<'_>,
    edits: &[ByteEdit],
    provenance: &SyntaxProvenance,
) -> bool {
    if provenance.language != req.language.id() {
        return false;
    }
    if provenance.base_digest != sha256_hex(req.base) {
        return false;
    }
    if provenance.ours_digest != sha256_hex(req.ours) {
        return false;
    }
    if provenance.theirs_digest != sha256_hex(req.theirs) {
        return false;
    }
    let Ok(base_len) = u32::try_from(req.base.len()) else {
        return false;
    };
    if provenance.edits.len() != edits.len() {
        return false;
    }
    validate_edits_bounds(edits, &provenance.edits, base_len)
}

fn validate_edits_bounds(edits: &[ByteEdit], prov_edits: &[EditProvenance], base_len: u32) -> bool {
    let mut prev_end = 0_u32;
    for (edit, prov) in edits.iter().zip(prov_edits.iter()) {
        if edit.start < prev_end || edit.start > edit.end || edit.end > base_len {
            return false;
        }
        if prov.base_start != edit.start || prov.base_end != edit.end {
            return false;
        }
        prev_end = edit.end;
    }
    true
}

#[cfg(unix)]
fn apply_address_space_limit(bytes: u64) -> Result<(), SyntaxError> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let limit = Rlimit {
        current: Some(bytes),
        maximum: Some(bytes),
    };
    if let Err(err) = setrlimit(Resource::As, limit) {
        return Err(SyntaxError::Invalid {
            what: "worker address-space limit",
            detail: format!("failed to set RLIMIT_AS to {bytes} bytes: {err}"),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn apply_address_space_limit(_bytes: u64) -> Result<(), SyntaxError> {
    // Windows requires Job Objects with JOB_OBJECT_LIMIT_PROCESS_MEMORY to enforce
    // address space / process memory limits on worker child processes.
    Err(SyntaxError::Invalid {
        what: "platform",
        detail:
            "Windows Job Object required for worker address-space limit (E_UNSUPPORTED_OPERATION)"
                .to_owned(),
    })
}

#[cfg(not(any(unix, windows)))]
fn apply_address_space_limit(_bytes: u64) -> Result<(), SyntaxError> {
    Err(SyntaxError::Invalid {
        what: "platform",
        detail: "unsupported platform for worker address-space limit (E_UNSUPPORTED_OPERATION)"
            .to_owned(),
    })
}

/// Worker child process entry point.
///
/// Dispatched when the binary is re-executed with [`WORKER_ARG`]. Applies the
/// 512 MiB address-space limit, verifies grammar ABI readiness, and serves
/// merge request frames from stdin until standard input closes.
///
/// # Errors
/// Returns [`SyntaxError`] on limit enforcement failure, startup ABI mismatch,
/// or communication framing corruption.
pub fn run_worker_stdio() -> Result<(), SyntaxError> {
    apply_address_space_limit(DEFAULT_ADDRESS_SPACE_BYTES)?;

    let providers = super::treesitter::registry_providers();
    let mut registry = GrammarRegistry::new();
    for provider_res in &providers {
        match provider_res {
            Ok(grammar) => registry.insert(grammar),
            Err(err) => return Err(err.clone()),
        }
    }

    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();
    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    loop {
        let Ok(frame_opt) = read_frame(&mut stdin_lock) else {
            return Err(SyntaxError::Invalid {
                what: "worker framing",
                detail: "failed to read incoming frame".to_owned(),
            });
        };

        let Some((header, payload)) = frame_opt else {
            break;
        };

        if header.kind == RECORD_KIND_SHUTDOWN {
            break;
        }

        if header.kind != RECORD_KIND_MERGE_REQ {
            return Err(SyntaxError::Invalid {
                what: "worker framing",
                detail: format!("unexpected record kind: {}", header.kind),
            });
        }

        serve_worker_frame(&payload, &registry, &mut stdout_lock)?;
    }

    Ok(())
}

fn serve_worker_frame(
    payload: &[u8],
    registry: &GrammarRegistry<'_>,
    stdout: &mut std::io::StdoutLock<'_>,
) -> Result<(), SyntaxError> {
    let resp_payload = process_worker_request(payload, registry);
    let Ok(resp_bytes) = sonic_rs::to_vec(&resp_payload) else {
        return Err(SyntaxError::Invalid {
            what: "worker serialization",
            detail: "failed to serialize worker response".to_owned(),
        });
    };

    if let Err(err) = write_frame(stdout, RECORD_KIND_MERGE_RESP, &resp_bytes) {
        return Err(SyntaxError::Invalid {
            what: "worker io",
            detail: format!("failed to write response frame: {err}"),
        });
    }

    Ok(())
}

fn process_worker_request(payload: &[u8], registry: &GrammarRegistry<'_>) -> WorkerResponsePayload {
    let Ok(decoded) = decode_request_payload(payload) else {
        return WorkerResponsePayload::Declined {
            reason: DeclineReason::ParseFailed.as_str().to_owned(),
            detail: "request decode failed".to_owned(),
            notices: MergeNotices::default(),
        };
    };

    let req = SyntaxRequest {
        path: decoded.path,
        language: decoded.language,
        base: decoded.base,
        ours: decoded.ours,
        theirs: decoded.theirs,
    };

    let cancel = Cancel::never();
    match merge_triplet(&req, registry, &cancel) {
        Ok(SyntaxOutcome::Merged {
            bytes: _,
            edits,
            provenance,
            notices,
        }) => WorkerResponsePayload::Clean {
            edits,
            provenance,
            notices,
        },
        Ok(SyntaxOutcome::Declined {
            reason,
            detail,
            notices,
        }) => WorkerResponsePayload::Declined {
            reason: reason.as_str().to_owned(),
            detail,
            notices,
        },
        Err(err) => WorkerResponsePayload::Error {
            code: err.code().as_str().to_owned(),
            message: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::merge::composed::NoticeCode;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn test_framing_header_codec() {
        let header = FrameHeader::new(RECORD_KIND_MERGE_REQ, 1024);
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_eq!(&encoded[0..4], &FRAME_MAGIC);
        assert_eq!(encoded[4], FRAME_VERSION);
        assert_eq!(&encoded[5..9], &1024u32.to_be_bytes());
        assert_eq!(encoded[9], RECORD_KIND_MERGE_REQ);

        let decoded = FrameHeader::decode(&encoded).expect("decode valid header");
        assert_eq!(decoded, header);

        let mut bad_magic = encoded;
        bad_magic[0] = b'X';
        match FrameHeader::decode(&bad_magic) {
            Err(FrameError::InvalidMagic(m)) => assert_eq!(m[0], b'X'),
            other => panic!("expected InvalidMagic, got: {other:?}"),
        }

        let mut bad_version = encoded;
        bad_version[4] = 99;
        match FrameHeader::decode(&bad_version) {
            Err(FrameError::UnsupportedVersion(v)) => assert_eq!(v, 99),
            other => panic!("expected UnsupportedVersion, got: {other:?}"),
        }

        let mut empty_stream: &[u8] = &[];
        let read_res = read_frame(&mut empty_stream).expect("clean EOF on empty stream");
        assert!(read_res.is_none());
    }

    #[test]
    fn test_request_payload_codec_roundtrip() {
        let base = b"fn alpha() {}\n";
        let ours = b"fn alpha() { let x = 1; }\n";
        let theirs = b"fn alpha() { let y = 2; }\n";
        let path = ByteString::from("src/engine.rs");

        let req = SyntaxRequest {
            path: path.clone(),
            language: Language::Rust,
            base,
            ours,
            theirs,
        };

        let encoded = encode_request_payload(&req).expect("encode payload");
        let decoded = decode_request_payload(&encoded).expect("decode payload");

        assert_eq!(decoded.language, Language::Rust);
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.base, base);
        assert_eq!(decoded.ours, ours);
        assert_eq!(decoded.theirs, theirs);

        let truncated = &encoded[..encoded.len() - 5];
        match decode_request_payload(truncated) {
            Err(FrameError::CorruptPayload(_)) => {}
            other => panic!("expected CorruptPayload on truncated input, got: {other:?}"),
        }
    }

    #[test]
    fn test_grammar_health_state_transitions() {
        let pool = SyntaxPool::new(PoolLimits::default());
        assert_eq!(
            pool.grammar_health(Language::Python),
            GrammarHealth::Healthy
        );

        pool.record_crash(Language::Python);
        assert_eq!(
            pool.grammar_health(Language::Python),
            GrammarHealth::Healthy
        );

        pool.record_crash(Language::Python);
        assert_eq!(
            pool.grammar_health(Language::Python),
            GrammarHealth::Unhealthy
        );

        let req = SyntaxRequest {
            path: ByteString::from("script.py"),
            language: Language::Python,
            base: b"x = 1\n",
            ours: b"x = 2\n",
            theirs: b"x = 3\n",
        };

        let cancel = Cancel::never();
        let merge_res = pool.merge(&req, &cancel);
        match merge_res {
            Err(SyntaxError::Invalid { what, detail }) => {
                assert_eq!(what, "grammar");
                assert!(detail.contains("python"), "must name grammar ID: {detail}");
                assert!(detail.contains("E_IO"), "must include E_IO: {detail}");
            }
            other => panic!("expected unhealthy grammar E_IO error, got: {other:?}"),
        }
    }

    #[test]
    fn test_triplet_size_bound_declined() {
        let limits = PoolLimits {
            max_triplet_bytes: 50,
            ..PoolLimits::default()
        };
        let pool = SyntaxPool::new(limits);

        let large_base = vec![b'a'; 30];
        let large_ours = vec![b'b'; 30];
        let large_theirs = vec![b'c'; 30];

        let req = SyntaxRequest {
            path: ByteString::from("file.rs"),
            language: Language::Rust,
            base: &large_base,
            ours: &large_ours,
            theirs: &large_theirs,
        };

        let outcome = pool
            .merge(&req, &Cancel::never())
            .expect("size limit produces decline");
        match outcome {
            PoolOutcome::Declined { reason, notices } => {
                assert_eq!(reason, DeclineReason::SizeLimit);
                assert!(!notices.is_empty());
                let notice = &notices.entries()[0];
                assert_eq!(notice.code(), NoticeCode::SyntaxLimit);
            }
            PoolOutcome::Clean { .. } => panic!("expected size limit decline, got clean"),
        }
    }

    #[test]
    fn test_queue_bound_declined() {
        let limits = PoolLimits {
            queue_capacity: 0,
            max_workers: 0,
            ..PoolLimits::default()
        };
        let pool = SyntaxPool::new(limits);

        let req = SyntaxRequest {
            path: ByteString::from("file.rs"),
            language: Language::Rust,
            base: b"fn x() {}\n",
            ours: b"fn x() { 1; }\n",
            theirs: b"fn x() { 2; }\n",
        };

        let outcome = pool
            .merge(&req, &Cancel::never())
            .expect("queue bound produces decline");
        match outcome {
            PoolOutcome::Declined { reason, notices } => {
                assert_eq!(reason, DeclineReason::SizeLimit);
                assert!(!notices.is_empty());
                let notice = &notices.entries()[0];
                assert!(notice.detail().contains("queue capacity"));
            }
            PoolOutcome::Clean { .. } => panic!("expected queue bound decline, got clean"),
        }
    }

    #[test]
    fn test_cancellation_aborts_immediately() {
        let pool = SyntaxPool::new(PoolLimits::default());
        let flag = Arc::new(AtomicBool::new(true));
        let cancel = Cancel::from_flag(flag);

        let req = SyntaxRequest {
            path: ByteString::from("file.rs"),
            language: Language::Rust,
            base: b"fn x() {}\n",
            ours: b"fn x() { 1; }\n",
            theirs: b"fn x() { 2; }\n",
        };

        let err = pool
            .merge(&req, &cancel)
            .expect_err("cancellation must error");
        assert_eq!(err.code(), ErrorCode::ECancelled);
    }

    #[test]
    #[ignore = "requires built binary to execute as worker child process"]
    fn test_worker_process_integration_roundtrip() {
        let pool = SyntaxPool::new(PoolLimits::default());
        let req = SyntaxRequest {
            path: ByteString::from("file.rs"),
            language: Language::Rust,
            base: b"fn alpha() {}\n",
            ours: b"fn alpha() {}\n",
            theirs: b"fn alpha() {}\n",
        };
        let res = pool.merge(&req, &Cancel::never()).expect("merge roundtrip");
        assert!(res.is_clean());
    }
}
