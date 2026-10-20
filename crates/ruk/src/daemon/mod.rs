//! Hosted multi-repository daemon behind `ruk serve`.
//!
//! One process owns every opened repository of a hosted instance. The
//! [`Registry`] authorizes each open by canonicalized path or opaque
//! handle, each repository serializes publication on its own lane, and one
//! shared [`BoundedExecutor`] runs blocking store work. The Unix-socket IPC
//! framing, credit windows, and handshake live in [`ipc`].
//!
//! Windows named-pipe transport is out of scope for this build: [`serve`]
//! reports it as [`Error::Unsupported`] instead of binding.

pub(crate) mod executor;
pub(crate) mod ipc;
pub(crate) mod registry;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;

pub(crate) use executor::BoundedExecutor;
pub(crate) use registry::Registry;
use ruk_core::change::{RequestId, SessionId};
use ruk_core::coord::service_receipts::{
    SERVICE_RECEIPT_VERSION, ServiceReceipt, lookup_service_receipt, store_service_receipt,
};
use ruk_core::coord::{
    Cancel, CancelHandle, DEFAULT_EVENT_RETENTION_SECONDS, HostedCoordinator, Principal,
    cancellation,
};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{
    ErrorReply, Method, Mutation, ReconnectSecret, Reply, ReplyEnvelope, Request, SessionOpenArgs,
    SessionResumeArgs, decode_json,
};
use ruk_core::refdata::RefName;
use ruk_git::transport::host::{HookCall, HookReply, HostPolicy, hook_bridge};
use ruk_git::transport::pack::IngestLimits;
use ruk_git::transport::serve::ReceiveLimits;

/// Default concurrent connections of one daemon process.
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// Default blocking permits of the shared executor.
pub(crate) const DEFAULT_BLOCKING_POOL_SIZE: usize = 16;

/// Default handshake deadline in milliseconds.
pub(crate) const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

/// Default per-frame deadline in milliseconds.
pub(crate) const DEFAULT_FRAME_TIMEOUT_MS: u64 = 60_000;

/// Default interval between periodic retention sweeps in milliseconds.
pub(crate) const DEFAULT_RETENTION_INTERVAL_MS: u64 = 60_000;

/// Default bulkhead permits for long-running transport streams.
pub(crate) const DEFAULT_TRANSPORT_PERMITS: usize = 8;

/// Default pre-receive hook deadline in milliseconds.
pub(crate) const DEFAULT_HOOK_TIMEOUT_MS: u64 = 10_000;

/// Default cap of ref commands accepted per push batch.
pub(crate) const DEFAULT_HOOK_MAX_COMMANDS: usize = 1_024;

/// Ceiling of ref commands accepted per push batch.
pub(crate) const MAX_HOOK_MAX_COMMANDS: usize = 4_096;

/// Default branch recorded by `repo.init` and `repo.fork`.
pub(crate) const DEFAULT_DEFAULT_BRANCH: &str = "refs/heads/main";

/// Default cap of archive bytes served per request (1 GiB).
pub(crate) const DEFAULT_ARCHIVE_MAX_BYTES: u64 = 1_073_741_824;

/// Default walk budget for `compare` reads.
pub(crate) const DEFAULT_COMPARE_MAX_COMMITS: usize = 10_000;

/// Default per-request scan budget for `search` (64 MiB).
pub(crate) const DEFAULT_SEARCH_MAX_SCAN_BYTES: u64 = 67_108_864;

/// Default permits of the search worker pool.
pub(crate) const DEFAULT_SEARCH_POOL_SIZE: usize = 8;

/// Configuration of one `ruk serve` process.
#[derive(Clone, Debug)]
pub(crate) struct DaemonConfig {
    /// Filesystem path of the Unix socket to bind.
    socket_path: PathBuf,
    /// Repository roots; every open must land beneath one.
    repo_roots: Vec<PathBuf>,
    /// Allowed peer user identifiers; must list at least one uid, and an
    /// empty list denies every peer.
    allowed_uids: Vec<u32>,
    /// Peer user identifiers allowed to call admin methods; empty disables them.
    admin_uids: Vec<u32>,
    /// Concurrent connections before the daemon sheds accept.
    max_connections: usize,
    /// Blocking permits of the shared executor.
    blocking_pool_size: usize,
    /// Permits of the separate bulkhead for long-running transport streams.
    transport_permits: usize,
    /// Pre-receive hook deadline; fail-closed on expiry.
    hook_timeout: Duration,
    /// Cap of ref commands accepted per push batch.
    hook_max_commands: usize,
    /// Branch recorded by `repo.init` and `repo.fork`.
    default_branch: String,
    /// Horizon keeping event rows; older rows are swept.
    event_retention_seconds: u64,
    /// Cap of archive bytes served per request.
    archive_max_bytes: u64,
    /// Walk budget for `compare` reads.
    compare_max_commits: usize,
    /// Per-request scan budget for `search`.
    search_max_scan_bytes: u64,
    /// Permits of the search worker pool.
    search_pool_size: usize,
    /// Deadline for the stream-zero handshake of each connection.
    handshake_timeout: Duration,
    /// Deadline for each subsequent frame of a connection.
    frame_timeout: Duration,
    /// Starting credit window of each stream direction.
    stream_window_bytes: u64,
    /// Interval between periodic retention sweeps of every opened
    /// coordinator; zero disables them.
    retention_interval: Duration,
}

impl DaemonConfig {
    /// Builds one configuration binding `socket_path` over `repo_roots`.
    pub(crate) fn new(socket_path: PathBuf, repo_roots: Vec<PathBuf>) -> Self {
        Self {
            socket_path,
            repo_roots,
            allowed_uids: Vec::new(),
            admin_uids: Vec::new(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            blocking_pool_size: DEFAULT_BLOCKING_POOL_SIZE,
            transport_permits: DEFAULT_TRANSPORT_PERMITS,
            hook_timeout: Duration::from_millis(DEFAULT_HOOK_TIMEOUT_MS),
            hook_max_commands: DEFAULT_HOOK_MAX_COMMANDS,
            default_branch: String::from(DEFAULT_DEFAULT_BRANCH),
            event_retention_seconds: DEFAULT_EVENT_RETENTION_SECONDS,
            archive_max_bytes: DEFAULT_ARCHIVE_MAX_BYTES,
            compare_max_commits: DEFAULT_COMPARE_MAX_COMMITS,
            search_max_scan_bytes: DEFAULT_SEARCH_MAX_SCAN_BYTES,
            search_pool_size: DEFAULT_SEARCH_POOL_SIZE,
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            frame_timeout: Duration::from_millis(DEFAULT_FRAME_TIMEOUT_MS),
            stream_window_bytes: ipc::INITIAL_STREAM_WINDOW_BYTES,
            retention_interval: Duration::from_millis(DEFAULT_RETENTION_INTERVAL_MS),
        }
    }

    /// Restricts Unix-socket peers to `uids`.
    #[must_use]
    pub(crate) fn with_allowed_uids(mut self, uids: Vec<u32>) -> Self {
        self.allowed_uids = uids;
        self
    }

    /// Restricts admin methods to `uids`; empty disables them.
    #[must_use]
    pub(crate) fn with_admin_uids(mut self, uids: Vec<u32>) -> Self {
        self.admin_uids = uids;
        self
    }

    /// Sets the concurrent connection bound.
    #[must_use]
    pub(crate) fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets the permits of the separate bulkhead for long transport streams.
    #[must_use]
    pub(crate) fn with_transport_permits(mut self, permits: usize) -> Self {
        self.transport_permits = permits;
        self
    }

    /// Sets the pre-receive hook deadline.
    #[must_use]
    pub(crate) fn with_hook_timeout(mut self, timeout: Duration) -> Self {
        self.hook_timeout = timeout;
        self
    }

    /// Sets the cap of ref commands accepted per push batch.
    #[must_use]
    pub(crate) fn with_hook_max_commands(mut self, max_commands: usize) -> Self {
        self.hook_max_commands = max_commands;
        self
    }

    /// Sets the branch recorded by `repo.init` and `repo.fork`.
    #[must_use]
    pub(crate) fn with_default_branch(mut self, branch: String) -> Self {
        self.default_branch = branch;
        self
    }

    /// Sets the horizon keeping event rows.
    #[must_use]
    pub(crate) fn with_event_retention_seconds(mut self, seconds: u64) -> Self {
        self.event_retention_seconds = seconds;
        self
    }

    /// Sets the cap of archive bytes served per request.
    #[must_use]
    pub(crate) fn with_archive_max_bytes(mut self, bytes: u64) -> Self {
        self.archive_max_bytes = bytes;
        self
    }

    /// Sets the walk budget for `compare` reads.
    #[must_use]
    pub(crate) fn with_compare_max_commits(mut self, commits: usize) -> Self {
        self.compare_max_commits = commits;
        self
    }

    /// Sets the per-request scan budget for `search`.
    #[must_use]
    pub(crate) fn with_search_max_scan_bytes(mut self, bytes: u64) -> Self {
        self.search_max_scan_bytes = bytes;
        self
    }

    /// Sets the permits of the search worker pool.
    #[must_use]
    pub(crate) fn with_search_pool_size(mut self, pool_size: usize) -> Self {
        self.search_pool_size = pool_size;
        self
    }

    /// Sets the blocking permits of the shared executor.
    #[must_use]
    pub(crate) fn with_blocking_pool_size(mut self, pool_size: usize) -> Self {
        self.blocking_pool_size = pool_size;
        self
    }

    /// Sets the stream-zero handshake deadline.
    #[must_use]
    pub(crate) fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the per-frame deadline after the handshake.
    #[must_use]
    pub(crate) fn with_frame_timeout(mut self, timeout: Duration) -> Self {
        self.frame_timeout = timeout;
        self
    }

    /// Sets the starting credit window of each stream direction.
    #[must_use]
    pub(crate) fn with_stream_window_bytes(mut self, bytes: u64) -> Self {
        self.stream_window_bytes = bytes;
        self
    }

    /// Sets the interval between periodic retention sweeps of every opened
    /// coordinator. Zero disables them.
    #[must_use]
    pub(crate) fn with_retention_interval(mut self, interval: Duration) -> Self {
        self.retention_interval = interval;
        self
    }

    /// Returns the socket path.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Returns the configured repository roots.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn repo_roots(&self) -> &[PathBuf] {
        &self.repo_roots
    }

    /// Returns the interval between periodic retention sweeps; zero disables them.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn retention_interval(&self) -> Duration {
        self.retention_interval
    }

    /// Returns the peer identifiers allowed to call admin methods.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn admin_uids(&self) -> &[u32] {
        &self.admin_uids
    }

    /// Returns the cap of archive bytes served per request.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn archive_max_bytes(&self) -> u64 {
        self.archive_max_bytes
    }

    /// Returns the walk budget for `compare` reads.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn compare_max_commits(&self) -> usize {
        self.compare_max_commits
    }

    /// Returns the per-request scan budget for `search`.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn search_max_scan_bytes(&self) -> u64 {
        self.search_max_scan_bytes
    }

    /// Returns the permits of the search worker pool.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) fn search_pool_size(&self) -> usize {
        self.search_pool_size
    }

    /// Loads a TOML daemon configuration document.
    ///
    /// Keys: `socket_path`, `repo_roots`, `allowed_uids` (required),
    /// `admin_uids`, `max_connections`, `blocking_pool_size`,
    /// `transport_permits`, `handshake_timeout_ms`, `frame_timeout_ms`,
    /// `stream_window_bytes`, `retention_interval_ms` (optional; zero
    /// disables periodic retention sweeps), `hook_timeout_ms`,
    /// `hook_max_commands`, `default_branch`, `event_retention_seconds`,
    /// `archive_max_bytes`, `compare_max_commits`, `search_max_scan_bytes`,
    /// `search_pool_size`.
    ///
    /// # Errors
    /// `Error::Config` on malformed TOML, missing required keys, unknown
    /// keys, or bounds outside `validate`.
    pub(crate) fn from_toml(doc: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Doc {
            socket_path: PathBuf,
            repo_roots: Vec<PathBuf>,
            #[serde(default)]
            allowed_uids: Vec<u32>,
            #[serde(default)]
            admin_uids: Vec<u32>,
            max_connections: Option<usize>,
            blocking_pool_size: Option<usize>,
            transport_permits: Option<usize>,
            handshake_timeout_ms: Option<u64>,
            frame_timeout_ms: Option<u64>,
            stream_window_bytes: Option<u64>,
            retention_interval_ms: Option<u64>,
            hook_timeout_ms: Option<u64>,
            hook_max_commands: Option<usize>,
            default_branch: Option<String>,
            event_retention_seconds: Option<u64>,
            archive_max_bytes: Option<u64>,
            compare_max_commits: Option<usize>,
            search_max_scan_bytes: Option<u64>,
            search_pool_size: Option<usize>,
        }
        let text = std::str::from_utf8(doc)
            .map_err(|err| Error::Config(format!("config is not UTF-8: {err}")))?;
        let doc: Doc =
            toml::from_str(text).map_err(|err| Error::Config(format!("config TOML: {err}")))?;
        let mut cfg = Self::new(doc.socket_path, doc.repo_roots)
            .with_allowed_uids(doc.allowed_uids)
            .with_admin_uids(doc.admin_uids);
        if let Some(v) = doc.max_connections {
            cfg = cfg.with_max_connections(v);
        }
        if let Some(v) = doc.blocking_pool_size {
            cfg = cfg.with_blocking_pool_size(v);
        }
        if let Some(v) = doc.transport_permits {
            cfg = cfg.with_transport_permits(v);
        }
        if let Some(v) = doc.handshake_timeout_ms {
            cfg = cfg.with_handshake_timeout(Duration::from_millis(v));
        }
        if let Some(v) = doc.frame_timeout_ms {
            cfg = cfg.with_frame_timeout(Duration::from_millis(v));
        }
        if let Some(v) = doc.stream_window_bytes {
            cfg = cfg.with_stream_window_bytes(v);
        }
        if let Some(v) = doc.retention_interval_ms {
            cfg = cfg.with_retention_interval(Duration::from_millis(v));
        }
        if let Some(v) = doc.hook_timeout_ms {
            cfg = cfg.with_hook_timeout(Duration::from_millis(v));
        }
        if let Some(v) = doc.hook_max_commands {
            cfg = cfg.with_hook_max_commands(v);
        }
        if let Some(v) = doc.default_branch {
            cfg = cfg.with_default_branch(v);
        }
        if let Some(v) = doc.event_retention_seconds {
            cfg = cfg.with_event_retention_seconds(v);
        }
        if let Some(v) = doc.archive_max_bytes {
            cfg = cfg.with_archive_max_bytes(v);
        }
        if let Some(v) = doc.compare_max_commits {
            cfg = cfg.with_compare_max_commits(v);
        }
        if let Some(v) = doc.search_max_scan_bytes {
            cfg = cfg.with_search_max_scan_bytes(v);
        }
        if let Some(v) = doc.search_pool_size {
            cfg = cfg.with_search_pool_size(v);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks every bound the daemon depends on.
    ///
    /// # Errors
    /// `Config` for an empty socket path, root set, `allowed_uids`,
    /// connection bound, blocking pool, deadline, or window.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(Error::Config(String::from("socket path must not be empty")));
        }
        if self.repo_roots.is_empty() {
            return Err(Error::Config(String::from(
                "at least one repository root is required",
            )));
        }
        if self.allowed_uids.is_empty() {
            return Err(Error::Config(String::from(
                "allowed_uids must list at least one authorized peer uid",
            )));
        }
        if self.max_connections == 0 {
            return Err(Error::Config(String::from(
                "connection bound must be nonzero",
            )));
        }
        if self.blocking_pool_size == 0 {
            return Err(Error::Config(String::from(
                "blocking pool must hold at least one permit",
            )));
        }
        if self.transport_permits == 0 {
            return Err(Error::Config(String::from(
                "transport_permits must hold at least one permit",
            )));
        }
        if self.search_pool_size == 0 {
            return Err(Error::Config(String::from(
                "search_pool_size must hold at least one permit",
            )));
        }
        if self.hook_timeout.is_zero() {
            return Err(Error::Config(String::from(
                "hook_timeout_ms must be nonzero",
            )));
        }
        if self.hook_max_commands == 0 || self.hook_max_commands > MAX_HOOK_MAX_COMMANDS {
            return Err(Error::Config(format!(
                "hook_max_commands must be within 1..={MAX_HOOK_MAX_COMMANDS}"
            )));
        }
        if RefName::new(self.default_branch.clone()).is_err() {
            return Err(Error::Config(format!(
                "default_branch is not a valid ref name: {}",
                self.default_branch
            )));
        }
        if self.event_retention_seconds == 0 {
            return Err(Error::Config(String::from(
                "event_retention_seconds must be nonzero",
            )));
        }
        if self.handshake_timeout.is_zero() || self.frame_timeout.is_zero() {
            return Err(Error::Config(String::from(
                "handshake and frame deadlines must be nonzero",
            )));
        }
        if self.stream_window_bytes == 0 || self.stream_window_bytes > ipc::MAX_STREAM_WINDOW_BYTES
        {
            return Err(Error::Config(String::from(
                "stream window must fit the maximum window",
            )));
        }
        Ok(())
    }
}

/// Failure of the hosted daemon process.
#[derive(Debug)]
pub(crate) enum Error {
    /// The configuration is unusable.
    Config(String),
    /// Transport or runtime setup failed.
    Io(std::io::Error),
    /// A typed core failure ended the daemon or one handshake.
    Core(CoreError),
    /// The platform lacks the required transport.
    #[expect(
        dead_code,
        reason = "no constructor at this commit; retained for later changeset rows"
    )]
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(detail) => write!(f, "daemon config: {detail}"),
            Self::Io(err) => write!(f, "daemon I/O: {err}"),
            Self::Core(err) => write!(f, "daemon: {err}"),
            Self::Unsupported(detail) => write!(f, "daemon unsupported: {detail}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(_) | Self::Unsupported(_) => None,
            Self::Io(err) => Some(err),
            Self::Core(err) => Some(err),
        }
    }
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        Self::Core(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// The `Open` payload: one invocation against one repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InvocationOpen {
    /// Store directory path or opaque handle from a previous open: the
    /// directory holding the store format file, not the worktree root.
    pub repo: String,
    /// The protocol method name, such as `status`.
    pub method: String,
    /// The idempotency key half of a mutation, if any.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The raw JSON document of the method arguments, if any.
    #[serde(default)]
    pub args_json: Option<String>,
    /// The session reads and mutations run under, if any.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Provenance this invocation declares; recorded, never an
    /// authorization input.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

/// The `Accepted` payload answering one `Open`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InvocationAccepted {
    /// The accepted stream identifier.
    pub stream_id: u64,
    /// The dispatched method name.
    pub method: String,
    /// The opaque repository handle serving this invocation.
    pub repo_handle: String,
}

/// The `WindowUpdate` payload granting outbound credit to its stream.
///
/// Accepts both the daemon's `{credit_bytes}` form and the Go backend
/// client's `{direction, bytes}` form; an empty direction means the
/// invocation's input side. The daemon routes `stdin`/empty grants to
/// the inbound window and `stdout`/`stderr` grants to the outbound
/// window of the named stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowCredit {
    /// The credit bytes granted to the frame's stream.
    #[serde(alias = "bytes")]
    pub credit_bytes: u64,
    /// The granted direction; empty means the input side.
    #[serde(default)]
    pub direction: String,
}

/// The `Exit` payload ending one invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExitReport {
    /// The process-style exit status: zero on success.
    pub status: i32,
    /// `OK` on success, else the closed error-code spelling of the failure.
    pub code: String,
    /// The durable mutation outcome: `Completed`, `Failed`, or
    /// `CancelledBeforeCommit`.
    pub outcome: String,
    /// Unix seconds of completion, from the system clock.
    pub completed_at: u64,
}

/// Outcome of a command that ran to its terminal report.
const OUTCOME_COMPLETED: &str = "Completed";

/// Outcome of a command that failed: a refusal, a teardown, or a nonzero exit.
const OUTCOME_FAILED: &str = "Failed";

/// Outcome of a command cancelled before (or during) its run.
const OUTCOME_CANCELLED: &str = "CancelledBeforeCommit";

/// Bound of frames buffered per stream between the connection reader and
/// one stream task. The reader waits past it, so a stalled stream applies
/// backpressure to socket reads instead of growing memory.
const STREAM_CHANNEL_BOUND: usize = 32;

/// Bound of frames buffered per connection between stream tasks and the
/// single writer task owning the socket write half.
const WRITER_CHANNEL_BOUND: usize = 256;

/// Bound of stream-completion reports buffered per connection. A finished
/// task drops its report past it; the reader unregisters the stream on the
/// next frame, so the stream table stays bounded by live streams.
const COMPLETION_CHANNEL_BOUND: usize = 64;

/// One frame moving toward the socket write half, owned by the single
/// connection-writer task.
struct OutboundFrame {
    /// The frame kind.
    kind: ipc::FrameKind,
    /// The stream the frame belongs to; zero is connection control.
    stream_id: u64,
    /// The frame payload: raw bytes for data kinds, JSON for control kinds.
    payload: Vec<u8>,
}

/// The write end of one stream: its identity plus the channel to the
/// connection-writer task. Every daemon-to-client frame of the stream
/// travels through it; the writer task owns the socket write half alone.
#[derive(Clone)]
struct StreamSink {
    /// The channel to the connection-writer task.
    writer: mpsc::Sender<OutboundFrame>,
    /// The stream this sink answers for.
    stream_id: u64,
}

/// Default cap of total pack bytes accepted on one git-service stream.
const DEFAULT_MAX_PACK_BYTES: u64 = 1 << 31;

/// Default cap of objects accepted on one git-service stream.
const DEFAULT_MAX_OBJECTS: u64 = 5_000_000;

/// Default cap of one decompressed object on a git-service stream.
const DEFAULT_MAX_OBJECT_BYTES: u64 = 512 << 20;

/// Default cap of delta-chain depth followed on a git-service stream.
const DEFAULT_MAX_DELTA_DEPTH: u64 = 128;

/// Default cap of stdin bytes collected on one git-service stream.
const DEFAULT_MAX_STDIN_BYTES: u64 = 256 << 20;

/// Default cap of push options accepted on one git-service stream.
const DEFAULT_MAX_PUSH_OPTIONS: u64 = 256;

/// Per-stream ingest quotas of one git-service envelope. Absent fields take
/// the daemon defaults; the daemon-side digest covers the effective values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GitLimits {
    /// Largest total pack bytes accepted.
    #[serde(default = "default_max_pack_bytes")]
    pub max_pack_bytes: u64,
    /// Largest object count accepted.
    #[serde(default = "default_max_objects")]
    pub max_objects: u64,
    /// Largest single decompressed object accepted.
    #[serde(default = "default_max_object_bytes")]
    pub max_object_bytes: u64,
    /// Deepest delta chain followed before refusing.
    #[serde(default = "default_max_delta_depth")]
    pub max_delta_depth: u64,
    /// Largest stdin byte count collected before refusing.
    #[serde(default = "default_max_stdin_bytes")]
    pub max_stdin_bytes: u64,
    /// Largest push-option count accepted.
    #[serde(default = "default_max_push_options")]
    pub max_push_options: u64,
}

/// The default cap of total pack bytes accepted on one git-service stream.
fn default_max_pack_bytes() -> u64 {
    DEFAULT_MAX_PACK_BYTES
}

/// The default cap of objects accepted on one git-service stream.
fn default_max_objects() -> u64 {
    DEFAULT_MAX_OBJECTS
}

/// The default cap of one decompressed object on a git-service stream.
fn default_max_object_bytes() -> u64 {
    DEFAULT_MAX_OBJECT_BYTES
}

/// The default cap of delta-chain depth followed on a git-service stream.
fn default_max_delta_depth() -> u64 {
    DEFAULT_MAX_DELTA_DEPTH
}

/// The default cap of stdin bytes collected on one git-service stream.
fn default_max_stdin_bytes() -> u64 {
    DEFAULT_MAX_STDIN_BYTES
}

/// The default cap of push options accepted on one git-service stream.
fn default_max_push_options() -> u64 {
    DEFAULT_MAX_PUSH_OPTIONS
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            max_pack_bytes: default_max_pack_bytes(),
            max_objects: default_max_objects(),
            max_object_bytes: default_max_object_bytes(),
            max_delta_depth: default_max_delta_depth(),
            max_stdin_bytes: default_max_stdin_bytes(),
            max_push_options: default_max_push_options(),
        }
    }
}

impl GitLimits {
    /// Builds the receive-pack bounds from the effective envelope quotas.
    /// Operator values wider than the ingest counters saturate instead of
    /// refusing the stream.
    fn receive_limits(&self) -> ReceiveLimits {
        ReceiveLimits {
            ingest: IngestLimits {
                max_pack_bytes: self.max_pack_bytes,
                max_objects: self.max_objects,
                max_object_bytes: self.max_object_bytes,
                max_delta_depth: self.max_delta_depth,
            },
            max_push_options: self.max_push_options,
        }
    }

    /// Encodes the effective limits canonically for the daemon-side digest.
    fn encode(&self) -> Vec<u8> {
        format!(
            "max_pack_bytes={};max_objects={};max_object_bytes={};max_delta_depth={};max_stdin_bytes={};max_push_options={}",
            self.max_pack_bytes,
            self.max_objects,
            self.max_object_bytes,
            self.max_delta_depth,
            self.max_stdin_bytes,
            self.max_push_options,
        )
        .into_bytes()
    }
}

/// The `receive-pack` git service name.
const GIT_SERVICE_RECEIVE_PACK: &str = "receive-pack";

/// The `upload-pack` git service name.
const GIT_SERVICE_UPLOAD_PACK: &str = "upload-pack";

/// The `upload-archive` git service name.
const GIT_SERVICE_UPLOAD_ARCHIVE: &str = "upload-archive";

/// True for the three git services the envelope carries.
fn is_git_service(service: &str) -> bool {
    matches!(
        service,
        GIT_SERVICE_RECEIVE_PACK | GIT_SERVICE_UPLOAD_PACK | GIT_SERVICE_UPLOAD_ARCHIVE
    )
}

/// The `Open` payload of one git-service stream: `receive-pack`,
/// `upload-pack`, or `upload-archive` against one repository. An
/// `advertise` open writes the ref advertisement and ends; any other open
/// reads one request round and writes one response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandOpen {
    /// The git service: `receive-pack`, `upload-pack`, or `upload-archive`.
    pub service: String,
    /// Store directory path or opaque handle from a previous open: the
    /// directory holding the store format file, not the worktree root.
    pub repository: String,
    /// The service session; required for `receive-pack`.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The idempotency key; required for `receive-pack`.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The negotiated git protocol (`version=2` selects the v2 serve half).
    #[serde(default)]
    pub git_protocol: String,
    /// True answers only the ref advertisement and ends.
    #[serde(default)]
    pub advertise: bool,
    /// Initial outbound credit for stdout, added to the default window.
    #[serde(default)]
    pub stdout_credit: u64,
    /// Per-stream ingest quotas; absent fields take daemon defaults.
    #[serde(default)]
    pub limits: GitLimits,
    /// Provenance this invocation declares; recorded, never an
    /// authorization input.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

/// The `Accepted` payload answering one git-service `Open`.
/// `stdin_credit` carries the inbound window granted; it is always
/// positive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandAccepted {
    /// The accepted stream identifier.
    pub stream_id: u64,
    /// The stdin credit bytes granted to the client.
    pub stdin_credit: u64,
    /// The invocation identity, echoing the open's request id.
    pub invocation_id: String,
}

/// The `Exit` payload ending one git-service stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandExitReport {
    /// The native process exit status: zero on success.
    pub exit_code: i32,
    /// The terminating signal name; empty for a normal exit.
    pub signal: String,
    /// True when cancellation ended the invocation.
    pub cancelled: bool,
    /// The durable outcome: `Completed`, `Failed`, or `CancelledBeforeCommit`.
    pub outcome: String,
    /// Operation identities of the run; empty for CLI verbs.
    pub operation_ids: Vec<String>,
    /// The invocation identity, echoing the open's request id.
    pub invocation_id: String,
}

impl CommandExitReport {
    /// Builds the terminal report of a command that ran to completion.
    fn success(invocation: &str, code: u8) -> Self {
        Self {
            exit_code: i32::from(code),
            signal: String::new(),
            cancelled: false,
            outcome: OUTCOME_COMPLETED.to_string(),
            operation_ids: Vec::new(),
            invocation_id: invocation.to_string(),
        }
    }

    /// Builds the terminal report of a cancelled command.
    fn cancelled(invocation: &str) -> Self {
        Self {
            exit_code: 130,
            signal: String::new(),
            cancelled: true,
            outcome: OUTCOME_CANCELLED.to_string(),
            operation_ids: Vec::new(),
            invocation_id: invocation.to_string(),
        }
    }
}

/// One daemon-to-client stdin credit grant. The field names match the Go
/// backend's `RukWindowUpdate` exactly (`bytes`, not the daemon's
/// `credit_bytes`), so the client's credit window observes the grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StdinGrant {
    /// The granted direction: always `stdin` from the daemon.
    direction: String,
    /// The credit bytes granted.
    bytes: u64,
}

/// The `session.open` answer: the durable session identity plus the secret
/// resuming it, without invented authority.
///
/// `open_session` returns the session and its reconnect secret only. The
/// negotiated capabilities and the idle expiry live in coordinator policy
/// the daemon cannot read, so the daemon omits them instead of guessing.
/// `session.resume` reports the negotiated capabilities and authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionOpened {
    /// The opened session identity.
    pub session: SessionId,
    /// The secret resuming the session.
    pub reconnect_secret: ReconnectSecret,
    /// The authenticated principal, as determined by the server.
    pub principal: String,
}

/// Names the coordinator call site one method needs.
///
/// `schema` answers locally and the bootstrap methods run on the
/// repository coordinator. Session-bound reads run through
/// `HostedCoordinator::read` (`op.log`, `claim.list`, and `attest.list`
/// first pages are served; every other read names its missing
/// implementation), and covered mutations run through the
/// per-method preparation layer plus `submit_prepared`.
#[must_use]
pub(crate) fn coord_call_site(method: Method) -> &'static str {
    match method.kind() {
        ruk_core::protocol::MethodKind::Anonymous => "none: answer from ruk-core protocol data",
        ruk_core::protocol::MethodKind::Bootstrap => {
            "HostedCoordinator::open_session/resume_session"
        }
        ruk_core::protocol::MethodKind::Read => {
            "HostedCoordinator::read (op.log, claim.list, attest.list first pages served; other reads name their missing implementation)"
        }
        ruk_core::protocol::MethodKind::Mutation => {
            "HostedCoordinator::prepare_for_dispatch plus HostedCoordinator::submit_prepared (ref, new, claim, ws.new, pin, attest, describe, split, rebase, squash, abandon, edit, ws.scope, ws.take, ws.drop, resolve, revert, undo, land.prepare mutations covered; the rest name their missing preparation)"
        }
    }
}

/// Builds the `E_HOSTED` refusal for one session-bound method.
#[must_use]
pub(crate) fn method_error(method: Method, reason: &str) -> CoreError {
    CoreError::new(
        ErrorCode::EHosted,
        format!(
            "method `{}` needs {}: {reason}",
            method.as_str(),
            coord_call_site(method)
        ),
    )
}

/// Serves every configured repository on the configured socket until
/// interrupted.
///
/// # Errors
/// `Config` for an unusable configuration, `Io` when the socket cannot
/// bind or accept persistently fails, `Unsupported` off Unix.
pub(crate) fn serve(config: DaemonConfig) -> Result<(), Error> {
    config.validate()?;
    #[cfg(not(unix))]
    return Err(Error::Unsupported(String::from(
        "ruk serve needs a Unix socket; the Windows named-pipe transport is not implemented",
    )));
    #[cfg(unix)]
    {
        let registry = Arc::new(Registry::new(config.repo_roots.clone())?);
        registry.set_retention_interval(config.retention_interval);
        registry.set_event_retention_seconds(config.event_retention_seconds);
        registry.set_hook_timeout(config.hook_timeout);
        registry.set_hook_max_commands(config.hook_max_commands);
        let executor = BoundedExecutor::new(config.blocking_pool_size)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .max_blocking_threads(config.blocking_pool_size * 2)
            .thread_name("ruk-serve")
            .enable_io()
            .enable_time()
            .build()?;
        registry.set_runtime(runtime.handle().clone());
        runtime.block_on(serve_async(config, registry, executor))
    }
}

/// Shared handles of one connection task.
#[derive(Clone)]
struct ConnectionRefs {
    /// The authorizing registry.
    registry: Arc<Registry>,
    /// The shared blocking pool.
    executor: BoundedExecutor,
    /// The separate bulkhead for long-running transport streams: hosted
    /// hook callbacks can block a thread up to the hook deadline, so
    /// pushes never starve typed invocations.
    transport: BoundedExecutor,
    /// The starting credit window of each stream direction.
    window_bytes: u64,
    /// The stream-zero handshake deadline.
    handshake_timeout: Duration,
    /// The per-frame deadline after the handshake.
    frame_timeout: Duration,
    /// Allowed peer user identifiers; must list at least one uid, and an
    /// empty list denies every peer.
    allowed_uids: Vec<u32>,
}

#[cfg(unix)]
async fn serve_async(
    config: DaemonConfig,
    registry: Arc<Registry>,
    executor: BoundedExecutor,
) -> Result<(), Error> {
    if let Err(err) = std::fs::remove_file(&config.socket_path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(err));
    }
    let listener = tokio::net::UnixListener::bind(&config.socket_path)?;
    let transport = BoundedExecutor::new(config.transport_permits)?;
    let refs = ConnectionRefs {
        registry,
        executor,
        transport,
        window_bytes: config.stream_window_bytes,
        handshake_timeout: config.handshake_timeout,
        frame_timeout: config.frame_timeout,
        allowed_uids: config.allowed_uids.clone(),
    };
    let connections = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
    let mut consecutive_accept_errors: u32 = 0;
    loop {
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        tokio::pin!(shutdown);
        tokio::select! {
            _ = shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        consecutive_accept_errors = 0;
                        let permit = connections.clone().acquire_owned().await.map_err(|_| {
                            Error::Core(CoreError::new(
                                ErrorCode::ECancelled,
                                "connection bound closed during shutdown",
                            ))
                        })?;
                        let task_refs = refs.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            let _ = serve_connection(stream, task_refs).await;
                        });
                    }
                    Err(_) => {
                        consecutive_accept_errors += 1;
                        if consecutive_accept_errors >= 100 {
                            return Err(Error::Io(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Unix socket accept failed persistently",
                            )));
                        }
                    }
                }
            }
        }
    }
    // Orderly shutdown: first wait for live connections to release their
    // permits, so accepted work finishes with coordinator services still
    // up (frame timeouts bound every connection, so the wait ends); then
    // retire every coordinator and await each lane runner, so the drain
    // completes before the runtime drops. Spawned tasks hold registry
    // clones, so registry Drop alone would never run while a connection
    // hangs.
    if let Ok(permits) = u32::try_from(config.max_connections) {
        let _ = connections.acquire_many(permits).await;
    }
    refs.registry.shutdown_and_drain().await;
    Ok(())
}

#[cfg(unix)]
async fn serve_connection(
    mut stream: tokio::net::UnixStream,
    refs: ConnectionRefs,
) -> Result<(), Error> {
    let peer = ipc::authenticate_peer(&stream, &refs.allowed_uids).map_err(Error::Core)?;
    let deadline = tokio::time::Instant::now() + refs.handshake_timeout;
    let hello = ipc::read_frame(&mut stream, deadline).await?;
    if hello.kind != ipc::FrameKind::Open || hello.stream_id != ipc::CONTROL_STREAM_ID {
        return Err(Error::Core(CoreError::new(
            ErrorCode::EInvalid,
            "first frame must open the stream-zero handshake",
        )));
    }
    let proposal: ipc::HandshakeHello = ipc::decode_control(&hello.payload)?;
    let acceptance = ipc::negotiate(&proposal)?;
    let accept_bytes = ipc::encode_control(&acceptance)?;
    ipc::write_frame(
        &mut stream,
        ipc::FrameKind::Accepted,
        ipc::CONTROL_STREAM_ID,
        &accept_bytes,
        deadline,
    )
    .await?;
    let (mut read_half, write_half) = stream.into_split();
    let (writer_tx, writer_rx) = mpsc::channel(WRITER_CHANNEL_BOUND);
    let writer_timeout = refs.frame_timeout;
    tokio::spawn(async move {
        connection_writer(writer_rx, write_half, writer_timeout).await;
    });
    let mut streams: HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)> = HashMap::new();
    let mut generation: u64 = 0;
    let (done_tx, mut done_rx) = mpsc::channel(COMPLETION_CHANNEL_BOUND);
    loop {
        let frame_deadline = tokio::time::Instant::now() + refs.frame_timeout;
        let frame = match ipc::read_frame(&mut read_half, frame_deadline).await {
            Ok(frame) => frame,
            Err(err) => {
                drop(streams);
                drop(writer_tx);
                return Err(Error::Core(err));
            }
        };
        while let Ok((stream_id, stream_generation)) = done_rx.try_recv() {
            if let std::collections::hash_map::Entry::Occupied(entry) = streams.entry(stream_id)
                && entry.get().1 == stream_generation
            {
                entry.remove();
            }
        }
        if frame.stream_id == ipc::CONTROL_STREAM_ID {
            if handle_control_frame(&writer_tx, &frame, &mut streams).await? {
                return Ok(());
            }
            continue;
        }
        if frame.kind == ipc::FrameKind::Open {
            generation = generation.wrapping_add(1);
        }
        if route_stream_frame(
            &writer_tx,
            frame,
            &mut streams,
            &done_tx,
            generation,
            &refs,
            peer,
        )
        .await?
        {
            return Ok(());
        }
    }
}

/// Owns the socket write half of one connection: every stream task sends
/// its frames here, and this task alone writes them. A write failure ends
/// the task, which drops the channel and ends every stream task with it.
#[cfg(unix)]
async fn connection_writer(
    mut input: mpsc::Receiver<OutboundFrame>,
    mut half: tokio::net::unix::OwnedWriteHalf,
    frame_timeout: Duration,
) {
    while let Some(frame) = input.recv().await {
        let deadline = tokio::time::Instant::now() + frame_timeout;
        if ipc::write_frame(
            &mut half,
            frame.kind,
            frame.stream_id,
            &frame.payload,
            deadline,
        )
        .await
        .is_err()
        {
            break;
        }
    }
}

#[cfg(unix)]
async fn handle_control_frame(
    writer: &mpsc::Sender<OutboundFrame>,
    frame: &ipc::Frame,
    streams: &mut HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)>,
) -> Result<bool, Error> {
    match frame.kind {
        ipc::FrameKind::Cancel => {
            // Fan out without awaiting: a stream task parked inside a
            // blocking serve may hold its channel full, and awaiting one
            // stream's send would stop the reader for every sibling,
            // including their Cancel frames. A full channel declares its
            // stream dead instead.
            let mut overflowed = Vec::new();
            for (stream_id, (tx, _)) in streams.iter() {
                let cancel = ipc::Frame {
                    kind: ipc::FrameKind::Cancel,
                    stream_id: *stream_id,
                    payload: Vec::new(),
                };
                match tx.try_send(cancel) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => continue,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        overflowed.push(*stream_id);
                    }
                }
            }
            for stream_id in overflowed {
                refuse_overflowed_stream(writer, streams, stream_id).await?;
            }
            Ok(true)
        }
        ipc::FrameKind::WindowUpdate => {
            let credit: WindowCredit = ipc::decode_control(&frame.payload)?;
            let _ = credit;
            Ok(false)
        }
        ipc::FrameKind::Exit | ipc::FrameKind::Error => Ok(true),
        ipc::FrameKind::Open => {
            let err = CoreError::new(
                ErrorCode::EInvalid,
                "stream-zero carries only the handshake",
            );
            write_control_error(writer, &err).await?;
            Ok(false)
        }
        ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdin
        | ipc::FrameKind::StdinEof
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::HookCall
        | ipc::FrameKind::HookReply => {
            let report = ErrorReply::from_core(&CoreError::new(
                ErrorCode::EInvalid,
                "stream-zero carries only the handshake and control queries",
            ));
            let bytes = ipc::encode_control(&report)?;
            send_raw(
                writer,
                ipc::FrameKind::Error,
                ipc::CONTROL_STREAM_ID,
                &bytes,
            )
            .await?;
            Ok(false)
        }
    }
}

/// Queues one frame toward the connection-writer task, waiting past a full
/// channel so a slow client applies backpressure instead of losing frames.
///
/// # Errors
/// `E_IO` when the writer task is gone and the connection is dead.
async fn send_raw(
    writer: &mpsc::Sender<OutboundFrame>,
    kind: ipc::FrameKind,
    stream_id: u64,
    payload: &[u8],
) -> Result<(), Error> {
    writer
        .send(OutboundFrame {
            kind,
            stream_id,
            payload: payload.to_vec(),
        })
        .await
        .map_err(|_| Error::Core(CoreError::new(ErrorCode::EIo, "connection writer is gone")))
}

/// Writes one stream-zero `Error` frame for a rejected control query.
#[cfg(unix)]
async fn write_control_error(
    writer: &mpsc::Sender<OutboundFrame>,
    err: &CoreError,
) -> Result<(), Error> {
    let report = ErrorReply::from_core(err);
    let bytes = ipc::encode_control(&report)?;
    send_raw(
        writer,
        ipc::FrameKind::Error,
        ipc::CONTROL_STREAM_ID,
        &bytes,
    )
    .await?;
    Ok(())
}

#[cfg(unix)]
async fn route_stream_frame(
    writer: &mpsc::Sender<OutboundFrame>,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)>,
    done: &mpsc::Sender<(u64, u64)>,
    generation: u64,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<bool, Error> {
    let stream_id = frame.stream_id;
    match frame.kind {
        ipc::FrameKind::Open => {
            spawn_stream(writer, frame, streams, done, generation, refs, peer);
            Ok(false)
        }
        ipc::FrameKind::Stdin | ipc::FrameKind::StdinEof | ipc::FrameKind::HookReply => {
            route_frame_try_send(writer, streams, stream_id, frame).await?;
            Ok(false)
        }
        ipc::FrameKind::WindowUpdate => match streams.contains_key(&stream_id) {
            true => {
                route_frame_try_send(writer, streams, stream_id, frame).await?;
                Ok(false)
            }
            false => {
                let sink = StreamSink {
                    writer: writer.clone(),
                    stream_id,
                };
                send_error_exit(
                    &sink,
                    &Error::Core(CoreError::new(
                        ErrorCode::EInvalid,
                        "credit update names an unknown stream",
                    )),
                )
                .await?;
                Ok(false)
            }
        },
        ipc::FrameKind::Cancel => match streams.contains_key(&stream_id) {
            true => {
                route_frame_try_send(writer, streams, stream_id, frame).await?;
                Ok(false)
            }
            false => {
                let sink = StreamSink {
                    writer: writer.clone(),
                    stream_id,
                };
                send_exit(
                    &sink,
                    130,
                    ErrorCode::ECancelled.as_str(),
                    "CancelledBeforeCommit",
                )
                .await?;
                Ok(false)
            }
        },
        ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::HookCall
        | ipc::FrameKind::Exit
        | ipc::FrameKind::Error => {
            let sink = StreamSink {
                writer: writer.clone(),
                stream_id,
            };
            send_error_exit(
                &sink,
                &Error::Core(CoreError::new(
                    ErrorCode::EInvalid,
                    "frame kind is misplaced on this stream",
                )),
            )
            .await?;
            Ok(false)
        }
    }
}

/// Routes one frame to its stream without awaiting: `try_send` keeps a
/// parked stream task from stalling the connection reader. A closed
/// channel drops its entry; a full one declares its stream dead with an
/// overflow error exit, so the reader always returns to its socket.
#[cfg(unix)]
async fn route_frame_try_send(
    writer: &mpsc::Sender<OutboundFrame>,
    streams: &mut HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)>,
    stream_id: u64,
    frame: ipc::Frame,
) -> Result<(), Error> {
    let Some((tx, _)) = streams.get(&stream_id) else {
        return Ok(());
    };
    match tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            streams.remove(&stream_id);
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            refuse_overflowed_stream(writer, streams, stream_id).await
        }
    }
}

/// Ends an overflowed stream with an explicit error exit and drops its
/// routing entry: the reader never waits for a task that stopped
/// draining, and the client learns the stream died instead of hanging.
#[cfg(unix)]
async fn refuse_overflowed_stream(
    writer: &mpsc::Sender<OutboundFrame>,
    streams: &mut HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)>,
    stream_id: u64,
) -> Result<(), Error> {
    streams.remove(&stream_id);
    let sink = StreamSink {
        writer: writer.clone(),
        stream_id,
    };
    send_error_exit(
        &sink,
        &Error::Core(CoreError::new(
            ErrorCode::ELimit,
            "stream input overflowed its bound",
        )),
    )
    .await
}

/// Spawns one task serving the stream of one `Open` frame. The reader
/// keeps only the task's input channel: every later frame of the stream
/// routes through it, so a long invocation never blocks sibling streams
/// and `Cancel` reaches a running invocation.
#[cfg(unix)]
fn spawn_stream(
    writer: &mpsc::Sender<OutboundFrame>,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, (mpsc::Sender<ipc::Frame>, u64)>,
    done: &mpsc::Sender<(u64, u64)>,
    generation: u64,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) {
    let stream_id = frame.stream_id;
    let (tx, rx) = mpsc::channel(STREAM_CHANNEL_BOUND);
    if let Some((old, _)) = streams.insert(stream_id, (tx, generation)) {
        drop(old);
    }
    let sink = StreamSink {
        writer: writer.clone(),
        stream_id,
    };
    let task_refs = refs.clone();
    let task_done = done.clone();
    tokio::spawn(async move {
        serve_stream(rx, &sink, frame.payload, &task_refs, peer).await;
        let _ = task_done.try_send((stream_id, generation));
    });
}

/// Serves one stream to its terminal frame: an argv-style command stream
/// or a typed invocation. Every error ends the stream with an `Error`
/// plus its terminal frame; the connection stays open for other streams.
#[cfg(unix)]
async fn serve_stream(
    mut input: mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    open_payload: Vec<u8>,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) {
    if let Ok(command) = ipc::decode_control::<CommandOpen>(&open_payload) {
        serve_git_service(&mut input, sink, command, refs, peer.uid).await;
        return;
    }
    let open: InvocationOpen = match ipc::decode_control(&open_payload) {
        Ok(open) => open,
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    typed_stream(&mut input, sink, &open, refs, peer).await;
}

/// Identifiers locating one git-service round for replay dispatch.
#[derive(Clone, Copy)]
struct ReplayIds<'a> {
    invocation: &'a str,
    request_id: &'a str,
    digest: &'a str,
}

/// Sends one stored receipt as if the run just completed it: the recorded
/// output bytes plus the recorded exit, or the recorded error.
#[cfg(unix)]
async fn send_stored_outcome(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    credits: &mut ipc::StreamCredits,
    cancel_guard: &CancelHandle,
    invocation: &str,
    receipt: &ServiceReceipt,
) {
    if receipt.error_code.is_some() || receipt.error_message.is_some() {
        let code = receipt
            .error_code
            .as_deref()
            .unwrap_or("E_IO")
            .parse::<ErrorCode>()
            .unwrap_or(ErrorCode::ECorrupt);
        let message = receipt.error_message.clone().unwrap_or_default();
        let _ = send_error_exit(sink, &Error::Core(CoreError::new(code, message))).await;
        return;
    }
    let code = u8::try_from(receipt.exit_code).unwrap_or(1);
    match write_typed_chunks(sink, input, credits, cancel_guard, &receipt.output).await {
        TypedWriteFate::Done => {}
        TypedWriteFate::Cancelled | TypedWriteFate::Gone => return,
    }
    let report = CommandExitReport::success(invocation, code);
    let exit_bytes = match ipc::encode_control(&report) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
}

/// Dispatches one stored receipt against the current digest: same digest
/// replays, a different digest is `E_REQUEST_REUSED`, an unknown version
/// is corrupt and refuses rather than overwriting a newer row.
#[cfg(unix)]
async fn dispatch_stored_receipt(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    credits: &mut ipc::StreamCredits,
    cancel_guard: &CancelHandle,
    ids: ReplayIds<'_>,
    receipt: &ServiceReceipt,
) {
    if receipt.version != SERVICE_RECEIPT_VERSION {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::ECorrupt,
                format!(
                    "stored receipt for request `{}` has unknown version {}",
                    ids.request_id, receipt.version
                ),
            )),
        )
        .await;
    } else if receipt.digest == ids.digest {
        send_stored_outcome(input, sink, credits, cancel_guard, ids.invocation, receipt).await;
    } else {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::ERequestReused,
                format!(
                    "request `{}` was already used with a different digest",
                    ids.request_id
                ),
            )),
        )
        .await;
    }
}

/// Locates one service receipt: the key (peer, repository, request id)
/// plus the digest the current round computed.
struct ReceiptLocator {
    peer_uid: u32,
    repository: Vec<u8>,
    request_id: String,
    digest: String,
}

/// Persists one completed git-service outcome as a service receipt.
/// Returns the winner's receipt when a concurrent same-request execution
/// won the absence race, so the caller replays instead of publishing twice.
#[cfg(unix)]
async fn store_git_outcome(
    refs: &ConnectionRefs,
    coordinator: &Arc<HostedCoordinator>,
    locator: &ReceiptLocator,
    outcome: &Result<Vec<u8>, CoreError>,
) -> Result<Option<ServiceReceipt>, Error> {
    let (exit_code, output, error_code, error_message) = match outcome {
        Ok(output) => (0, output.clone(), None, None),
        Err(err) => (
            -1,
            Vec::new(),
            Some(err.code.to_string()),
            Some(err.message.clone()),
        ),
    };
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    let at = u64::try_from(at).unwrap_or(0);
    let receipt = ServiceReceipt {
        version: SERVICE_RECEIPT_VERSION,
        digest: locator.digest.clone(),
        exit_code,
        output,
        error_code,
        error_message,
        at,
    };
    let writer = Arc::clone(coordinator);
    let repository = locator.repository.clone();
    let request_id = locator.request_id.clone();
    let peer_uid = locator.peer_uid;
    let stored = refs
        .executor
        .run(move || {
            store_service_receipt(writer.store(), peer_uid, &repository, &request_id, &receipt)
        })
        .await
        .map_err(Error::Core)?;
    match stored {
        Ok(()) => Ok(None),
        Err(ruk_core::store::StoreError::StaleFact { .. }) => {
            let reader = Arc::clone(coordinator);
            let repository = locator.repository.clone();
            let request_id = locator.request_id.clone();
            let found = refs
                .executor
                .run(move || {
                    lookup_service_receipt(reader.store(), peer_uid, &repository, &request_id)
                })
                .await
                .map_err(Error::Core)?
                .map_err(Error::Core)?;
            match found {
                Some((receipt, _)) => Ok(Some(receipt)),
                None => Err(Error::Core(CoreError::new(
                    ErrorCode::ECorrupt,
                    "a concurrent receipt vanished mid-replay",
                ))),
            }
        }
        Err(err) => Err(Error::Core(CoreError::new(err.code(), err.to_string()))),
    }
}

/// Serves one git-service stream to its terminal frame: an `advertise`
/// open writes the ref advertisement and ends, any other open reads one
/// request round and writes one response. No digest, environment, or
/// working directory travels the wire: the digest is computed daemon-side
/// over the parsed commands and the effective limits.
#[cfg(unix)]
async fn serve_git_service(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    req: CommandOpen,
    refs: &ConnectionRefs,
    peer_uid: u32,
) {
    let stream_id = sink.stream_id;
    let mut credits = ipc::StreamCredits::new(refs.window_bytes);
    credits.open_stream(stream_id);
    let (cancel_guard, token) = cancellation();
    if !is_git_service(&req.service) {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::EInvalid,
                format!("unknown git service `{}`", req.service),
            )),
        )
        .await;
        return;
    }
    if req.service == GIT_SERVICE_RECEIVE_PACK
        && (req.session_id.as_deref().unwrap_or("").is_empty()
            || req.request_id.as_deref().unwrap_or("").is_empty())
    {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::EInvalid,
                "receive-pack needs its session and request ids",
            )),
        )
        .await;
        return;
    }
    if req.advertise && req.service == GIT_SERVICE_UPLOAD_ARCHIVE {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::EInvalid,
                "upload-archive has no ref advertisement",
            )),
        )
        .await;
        return;
    }
    let repo_ref = req.repository.clone();
    let registry = Arc::clone(&refs.registry);
    let opened = refs
        .executor
        .run(move || registry.open(&repo_ref))
        .await
        .map_err(Error::Core);
    let (_, canonical, coordinator) = match opened {
        Ok(Ok(triple)) => triple,
        Ok(Err(err)) | Err(Error::Core(err)) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
        Err(err) => {
            let _ = send_error_exit(sink, &err).await;
            return;
        }
    };
    let accepted_id = req.request_id.clone().unwrap_or_default();
    let accepted = CommandAccepted {
        stream_id,
        stdin_credit: refs.window_bytes,
        invocation_id: accepted_id,
    };
    let accepted_bytes = match ipc::encode_control(&accepted) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    if credits
        .grant_outbound(stream_id, req.stdout_credit)
        .is_err()
    {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::EInvalid,
                "git-service stream is not tracked",
            )),
        )
        .await;
        return;
    }
    if send_frame(sink, ipc::FrameKind::Accepted, &accepted_bytes)
        .await
        .is_err()
    {
        return;
    }
    let stdin_bytes = if req.advertise {
        Vec::new()
    } else {
        match collect_git_stdin(input, sink, &mut credits, &req.limits).await {
            GitStdinFate::Ready(bytes) => bytes,
            GitStdinFate::Cancelled => {
                let report = CommandExitReport::cancelled(&accepted.invocation_id);
                let exit_bytes = match ipc::encode_control(&report) {
                    Ok(bytes) => bytes,
                    Err(_) => return,
                };
                let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
                return;
            }
            GitStdinFate::Gone => {
                return;
            }
            GitStdinFate::Rejected(err) => {
                let _ = send_error_exit(sink, &Error::Core(err)).await;
                return;
            }
        }
    };
    if token.check().is_err() {
        let report = CommandExitReport::cancelled(&accepted.invocation_id);
        let exit_bytes = match ipc::encode_control(&report) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
        return;
    }
    let commands = parse_git_commands(&stdin_bytes);
    let digest = ruk_git::transport::serve::git_service_digest(
        &req.service,
        &commands,
        &req.limits.encode(),
    );
    let invocation = req
        .request_id
        .clone()
        .unwrap_or_else(|| format!("digest-{digest}"));
    // Receipts cover mutating receive-pack rounds only: advertisement and
    // upload output changes as refs move, so replaying a stored read
    // would serve stale refs.
    let receipted = req.service == GIT_SERVICE_RECEIVE_PACK && !req.advertise;
    let request_id = req.request_id.clone().unwrap_or_default();
    let repository = canonical.as_os_str().as_bytes().to_vec();
    if receipted {
        let lookup_coordinator = Arc::clone(&coordinator);
        let lookup_repository = repository.clone();
        let lookup_request = request_id.clone();
        let found = refs
            .executor
            .run(move || {
                lookup_service_receipt(
                    lookup_coordinator.store(),
                    peer_uid,
                    &lookup_repository,
                    &lookup_request,
                )
            })
            .await;
        let found = match found {
            Ok(Ok(found)) => found,
            Ok(Err(err)) => {
                let _ = send_error_exit(sink, &Error::Core(err)).await;
                return;
            }
            Err(err) => {
                let _ = send_error_exit(sink, &Error::Core(err)).await;
                return;
            }
        };
        if let Some((receipt, _)) = found {
            let ids = ReplayIds {
                invocation: &invocation,
                request_id: &request_id,
                digest: &digest,
            };
            dispatch_stored_receipt(input, sink, &mut credits, &cancel_guard, ids, &receipt).await;
            return;
        }
    }
    if req.service == GIT_SERVICE_RECEIVE_PACK && !req.advertise {
        serve_hosted_receive(HostedReceive {
            input,
            sink,
            credits: &mut credits,
            cancel_guard: &cancel_guard,
            token,
            refs,
            coordinator,
            peer_uid,
            repository,
            session_id: req.session_id.clone().unwrap_or_default(),
            request_id,
            invocation,
            digest,
            commands,
            stdin: stdin_bytes,
            limits: req.limits.receive_limits(),
        })
        .await;
        return;
    }
    let run_coordinator = Arc::clone(&coordinator);
    let outcome = refs
        .executor
        .run(move || {
            run_git_service(
                &run_coordinator,
                &req.service,
                &req.git_protocol,
                req.advertise,
                stdin_bytes,
            )
        })
        .await;
    if receipted && let Ok(inner) = &outcome {
        let locator = ReceiptLocator {
            peer_uid,
            repository: repository.clone(),
            request_id: request_id.clone(),
            digest: digest.clone(),
        };
        match store_git_outcome(refs, &coordinator, &locator, inner).await {
            Ok(None) => {}
            Ok(Some(stored)) => {
                let ids = ReplayIds {
                    invocation: &invocation,
                    request_id: &request_id,
                    digest: &digest,
                };
                dispatch_stored_receipt(input, sink, &mut credits, &cancel_guard, ids, &stored)
                    .await;
                return;
            }
            Err(store_err) => {
                let _ = send_error_exit(sink, &store_err).await;
                return;
            }
        }
    }
    let output = match outcome {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    if token.check().is_err() {
        let report = CommandExitReport::cancelled(&invocation);
        let exit_bytes = match ipc::encode_control(&report) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
        return;
    }
    match write_typed_chunks(sink, input, &mut credits, &cancel_guard, &output).await {
        TypedWriteFate::Done => {}
        TypedWriteFate::Cancelled | TypedWriteFate::Gone => return,
    }
    let report = CommandExitReport::success(&invocation, 0);
    let exit_bytes = match ipc::encode_control(&report) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
}

/// One hosted receive-pack round: everything the hook exchange needs.
/// The sync serve runs on the transport bulkhead while the pump relays
/// hook frames on the stream task; both halves meet here.
struct HostedReceive<'a> {
    input: &'a mut mpsc::Receiver<ipc::Frame>,
    sink: &'a StreamSink,
    credits: &'a mut ipc::StreamCredits,
    cancel_guard: &'a CancelHandle,
    token: Cancel,
    refs: &'a ConnectionRefs,
    coordinator: Arc<HostedCoordinator>,
    peer_uid: u32,
    repository: Vec<u8>,
    session_id: String,
    request_id: String,
    invocation: String,
    digest: String,
    commands: Vec<Vec<u8>>,
    stdin: Vec<u8>,
    limits: ReceiveLimits,
}

/// Relays one hook exchange: sends the callback, awaits its reply under
/// the call's own deadline, and fails closed to a whole-push refusal on
/// timeout, stream close, cancellation, or a malformed reply.
#[cfg(unix)]
async fn pump_one_exchange(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    call: &HookCall,
) -> HookReply {
    let bytes = match ipc::encode_control(call) {
        Ok(bytes) => bytes,
        Err(_) => return HookReply::reject_all("hook call unencodable"),
    };
    if send_frame(sink, ipc::FrameKind::HookCall, &bytes)
        .await
        .is_err()
    {
        return HookReply::reject_all("hook stream closed");
    }
    let deadline = Duration::from_millis(call.deadline_ms);
    tokio::time::timeout(deadline, async {
        loop {
            match input.recv().await {
                Some(frame) if frame.kind == ipc::FrameKind::HookReply => {
                    return ipc::decode_control::<HookReply>(&frame.payload)
                        .unwrap_or_else(|_| HookReply::reject_all("hook reply malformed"));
                }
                Some(frame) if frame.kind == ipc::FrameKind::Cancel => {
                    return HookReply::reject_all("push cancelled");
                }
                Some(_) => continue,
                None => return HookReply::reject_all("hook stream closed"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| HookReply::reject_all("hook deadline elapsed"))
}

/// Serves one hosted receive-pack round through hook callbacks: session
/// capabilities authorize each command, the sync serve judges through a
/// [`HostPolicy`] on the transport bulkhead while this task pumps hook
/// frames, and the stored receipt plus the exit report close the round.
#[cfg(unix)]
async fn serve_hosted_receive(h: HostedReceive<'_>) {
    let HostedReceive {
        input,
        sink,
        credits,
        cancel_guard,
        token,
        refs,
        coordinator,
        peer_uid,
        repository,
        session_id,
        request_id,
        invocation,
        digest,
        commands,
        stdin,
        limits,
    } = h;
    if commands.len() > refs.registry.hook_max_commands() {
        let _ = send_error_exit(
            sink,
            &Error::Core(CoreError::new(
                ErrorCode::ELimit,
                format!(
                    "push carries {} commands, more than the {} allowed",
                    commands.len(),
                    refs.registry.hook_max_commands()
                ),
            )),
        )
        .await;
        return;
    }
    let principal = Principal::from_peer_uid(peer_uid);
    let session = match session_id.parse::<SessionId>() {
        Ok(session) => session,
        Err(_) => {
            let _ = send_error_exit(
                sink,
                &Error::Core(CoreError::new(ErrorCode::EInvalid, "malformed session id")),
            )
            .await;
            return;
        }
    };
    let capabilities = match coordinator
        .git_push_capabilities(&principal, session, &token)
        .await
    {
        Ok(capabilities) => capabilities,
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    let (client, mut server) = hook_bridge();
    let deadline = refs.registry.hook_timeout();
    let policy = Arc::new(HostPolicy::new(capabilities, deadline, client));
    let lfs = ruk_core::mode_for_store(coordinator.store().root());
    let serve_policy = Arc::clone(&policy);
    let serve_coordinator = Arc::clone(&coordinator);
    let serve_limits = limits;
    let serve = refs.transport.run(move || {
        let store = serve_coordinator.store();
        let kind = store.hash_kind();
        let head = crate::cli::verbs_transport::serve_head(store)?;
        let interrupt = ruk_git::transport::Interrupt::none();
        let mut out = Vec::new();
        let seqs = ruk_git::transport::serve::serve_receive_pack_with(
            &stdin[..],
            &mut out,
            store,
            kind,
            &head,
            &interrupt,
            &*serve_policy,
            lfs,
            serve_limits,
        )?;
        Ok::<_, CoreError>((out, seqs))
    });
    drop(policy);
    tokio::pin!(serve);
    let outcome: Result<(Vec<u8>, Vec<u64>), CoreError> = loop {
        tokio::select! {
            done = &mut serve => {
                break match done {
                    Ok(inner) => inner,
                    Err(err) => Err(err),
                };
            }
            exchange = server.recv() => {
                let Some(exchange) = exchange else {
                    // The policy is gone, so the serve task owns the
                    // outcome now; await it directly.
                    break match serve.await {
                        Ok(inner) => inner,
                        Err(err) => Err(err),
                    };
                };
                let reply = pump_one_exchange(input, sink, &exchange.call).await;
                let _ = exchange.reply.send(reply);
            }
        }
    };
    let (out, seqs) = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    let out = match strip_advertisement(out) {
        Ok(out) => out,
        Err(err) => {
            let _ = send_error_exit(sink, &Error::Core(err)).await;
            return;
        }
    };
    let locator = ReceiptLocator {
        peer_uid,
        repository,
        request_id: request_id.clone(),
        digest: digest.clone(),
    };
    match store_git_outcome(refs, &coordinator, &locator, &Ok(out.clone())).await {
        Ok(None) => {}
        Ok(Some(stored)) => {
            let ids = ReplayIds {
                invocation: &invocation,
                request_id: &request_id,
                digest: &digest,
            };
            dispatch_stored_receipt(input, sink, credits, cancel_guard, ids, &stored).await;
            return;
        }
        Err(store_err) => {
            let _ = send_error_exit(sink, &store_err).await;
            return;
        }
    }
    if token.check().is_err() {
        let report = CommandExitReport::cancelled(&invocation);
        let exit_bytes = match ipc::encode_control(&report) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
        return;
    }
    match write_typed_chunks(sink, input, credits, cancel_guard, &out).await {
        TypedWriteFate::Done => {}
        TypedWriteFate::Cancelled | TypedWriteFate::Gone => return,
    }
    let mut report = CommandExitReport::success(&invocation, 0);
    report.operation_ids = seqs.iter().map(|seq| seq.to_string()).collect();
    let exit_bytes = match ipc::encode_control(&report) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    let _ = send_frame(sink, ipc::FrameKind::Exit, &exit_bytes).await;
}

/// The end of one git-service stdin collection.
#[cfg(unix)]
enum GitStdinFate {
    /// `StdinEof` arrived with the collected bytes; `advertise` opens carry
    /// no body and finish empty without waiting for it.
    Ready(Vec<u8>),
    /// A `Cancel` frame arrived for this stream.
    Cancelled,
    /// The connection reader or writer is gone.
    Gone,
    /// A protocol violation or an over-limit body; the caller already
    /// refused the stream.
    Rejected(CoreError),
}

/// Collects one request round for a git-service stream, bounded by the
/// envelope's `max_stdin_bytes`. An `advertise` open carries no body and
/// returns empty at once. Inbound bytes are credit-checked with a sliding
/// grant back per chunk, so bodies larger than one window keep flowing.
#[cfg(unix)]
async fn collect_git_stdin(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    credits: &mut ipc::StreamCredits,
    limits: &GitLimits,
) -> GitStdinFate {
    let stream_id = sink.stream_id;
    let mut stdin_bytes: Vec<u8> = Vec::new();
    loop {
        let Some(frame) = input.recv().await else {
            return GitStdinFate::Gone;
        };
        if frame.stream_id != stream_id {
            return GitStdinFate::Rejected(CoreError::new(
                ErrorCode::EInvalid,
                "stream received a frame of another stream",
            ));
        }
        match frame.kind {
            ipc::FrameKind::Stdin => {
                let grown = (stdin_bytes.len() as u64).saturating_add(frame.payload.len() as u64);
                if grown > limits.max_stdin_bytes {
                    return GitStdinFate::Rejected(CoreError::new(
                        ErrorCode::ELimit,
                        "request body exceeds its bound",
                    ));
                }
                let width = match u64::try_from(frame.payload.len()) {
                    Ok(width) => width,
                    Err(_) => {
                        return GitStdinFate::Rejected(CoreError::new(
                            ErrorCode::ELimit,
                            "stdin chunk exceeds its bound",
                        ));
                    }
                };
                if credits.consume_inbound(stream_id, width).is_err() {
                    return GitStdinFate::Rejected(CoreError::new(
                        ErrorCode::ELimit,
                        "stream credit window is exhausted",
                    ));
                }
                stdin_bytes.extend_from_slice(&frame.payload);
                if credits.grant_inbound(stream_id, width).is_err() {
                    return GitStdinFate::Rejected(CoreError::new(
                        ErrorCode::EInvalid,
                        "git-service stream is not tracked",
                    ));
                }
                let grant = StdinGrant {
                    direction: "stdin".to_string(),
                    bytes: width,
                };
                let grant_bytes = match ipc::encode_control(&grant) {
                    Ok(bytes) => bytes,
                    Err(_) => return GitStdinFate::Gone,
                };
                if send_frame(sink, ipc::FrameKind::WindowUpdate, &grant_bytes)
                    .await
                    .is_err()
                {
                    return GitStdinFate::Gone;
                }
            }
            ipc::FrameKind::StdinEof => return GitStdinFate::Ready(stdin_bytes),
            ipc::FrameKind::Cancel => return GitStdinFate::Cancelled,
            ipc::FrameKind::WindowUpdate => {
                let credit: WindowCredit = match ipc::decode_control(&frame.payload) {
                    Ok(credit) => credit,
                    Err(err) => {
                        let _ = send_error_exit(sink, &Error::Core(err.clone())).await;
                        return GitStdinFate::Rejected(err);
                    }
                };
                if let Err(err) = route_credit(credits, stream_id, &credit) {
                    let _ = send_error_exit(sink, &Error::Core(err.clone())).await;
                    return GitStdinFate::Rejected(err);
                }
            }
            ipc::FrameKind::Open
            | ipc::FrameKind::Accepted
            | ipc::FrameKind::Stdout
            | ipc::FrameKind::Stderr
            | ipc::FrameKind::HookCall
            | ipc::FrameKind::HookReply
            | ipc::FrameKind::Exit
            | ipc::FrameKind::Error => {
                return GitStdinFate::Rejected(CoreError::new(
                    ErrorCode::EInvalid,
                    "frame kind is misplaced on this stream",
                ));
            }
        }
    }
}

/// Parses the command lines of one request body: the data lines before the
/// first flush. Malformed tails stop the parse; the serve half refuses the
/// request itself.
#[cfg(unix)]
fn parse_git_commands(body: &[u8]) -> Vec<Vec<u8>> {
    use ruk_git::transport::pktline::{Packet, decode_frame};
    let mut commands = Vec::new();
    let mut rest = body;
    while let Ok(Some((packet, consumed))) = decode_frame(rest) {
        rest = &rest[consumed..];
        match packet {
            Packet::Data(_) => {
                if let Some(line) = packet.line() {
                    commands.push(line.to_vec());
                }
            }
            Packet::Flush | Packet::Delimiter | Packet::ResponseEnd => break,
        }
    }
    commands
}

/// Runs one git-service round on the blocking pool: advertisement only for
/// `advertise` opens, one full serve round otherwise.
///
/// # Errors
/// The serve half's typed failure.
#[cfg(unix)]
fn run_git_service(
    coordinator: &std::sync::Arc<ruk_core::coord::HostedCoordinator>,
    service: &str,
    git_protocol: &str,
    advertise: bool,
    stdin: Vec<u8>,
) -> Result<Vec<u8>, CoreError> {
    use ruk_git::transport::serve::{
        advertise_receive_pack, advertise_upload_pack, serve_receive_pack, serve_upload_pack,
    };
    use ruk_git::transport::serve_v2::{git_protocol_requests_v2, serve_upload_pack_v2};
    let store = coordinator.store();
    let kind = store.hash_kind();
    let head = crate::cli::verbs_transport::serve_head(store)?;
    let interrupt = ruk_git::transport::Interrupt::none();
    if advertise {
        return match service {
            GIT_SERVICE_RECEIVE_PACK => Ok(advertise_receive_pack(store, kind, &head)?),
            GIT_SERVICE_UPLOAD_PACK => {
                if git_protocol_requests_v2(Some(git_protocol)) {
                    let mut out = Vec::new();
                    serve_upload_pack_v2(&[][..], &mut out, store, kind, &head, &interrupt)?;
                    Ok(out)
                } else {
                    Ok(advertise_upload_pack(store, kind, &head)?)
                }
            }
            _ => Err(CoreError::new(
                ErrorCode::EInvalid,
                "upload-archive has no ref advertisement",
            )),
        };
    }
    let mut out = Vec::new();
    match service {
        GIT_SERVICE_RECEIVE_PACK => {
            let lfs = ruk_core::mode_for_store(store.root());
            serve_receive_pack(&stdin[..], &mut out, store, kind, &head, &interrupt, lfs)?;
            out = strip_advertisement(out)?;
        }
        GIT_SERVICE_UPLOAD_PACK => {
            if git_protocol_requests_v2(Some(git_protocol)) {
                serve_upload_pack_v2(&stdin[..], &mut out, store, kind, &head, &interrupt)?;
            } else {
                serve_upload_pack(&stdin[..], &mut out, store, kind, &head, &interrupt)?;
            }
            out = strip_advertisement(out)?;
        }
        GIT_SERVICE_UPLOAD_ARCHIVE => {
            ruk_git::transport::archive::serve_upload_archive(
                &stdin[..],
                &mut out,
                store,
                kind,
                &head,
                &interrupt,
            )?;
        }
        _ => {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("unknown git service `{service}`"),
            ));
        }
    }
    Ok(out)
}

/// Splits one full serve round into its advertisement prefix and its
/// response: a stateless request already discovered refs through an
/// `advertise` open, so only the bytes past the first flush travel back.
/// Archive rounds carry no advertisement and never pass through here.
///
/// # Errors
/// `E_INVALID` when no flush packet opens the response.
#[cfg(unix)]
fn strip_advertisement(output: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let mut offset = 0;
    while offset + 4 <= output.len() {
        let len = usize::from_str_radix(
            std::str::from_utf8(&output[offset..offset + 4]).map_err(|_| {
                CoreError::new(ErrorCode::EInvalid, "serve round is not pkt-line framed")
            })?,
            16,
        )
        .map_err(|_| CoreError::new(ErrorCode::EInvalid, "serve round is not pkt-line framed"))?;
        if len == 0 {
            return Ok(output[offset + 4..].to_vec());
        }
        if len < 4 || offset + len > output.len() {
            break;
        }
        offset += len;
    }
    Err(CoreError::new(
        ErrorCode::EInvalid,
        "serve round carries no advertisement prefix",
    ))
}

/// Routes one client credit grant to the inbound or outbound window of its
/// stream.
///
/// # Errors
/// `E_INVALID` for an unknown direction or an unknown stream.
#[cfg(unix)]
fn route_credit(
    credits: &mut ipc::StreamCredits,
    stream_id: u64,
    credit: &WindowCredit,
) -> Result<(), CoreError> {
    if credit.direction.is_empty() || credit.direction == "stdin" {
        return credits.grant_inbound(stream_id, credit.credit_bytes);
    }
    if credit.direction == "stdout" || credit.direction == "stderr" {
        return credits.grant_outbound(stream_id, credit.credit_bytes);
    }
    Err(CoreError::new(
        ErrorCode::EInvalid,
        "credit update names an unknown direction",
    ))
}

/// The end of one credit wait.
#[cfg(unix)]
enum CreditFate {
    /// A grant landed; retry the chunk.
    Granted,
    /// A `Cancel` frame arrived for this stream.
    Cancelled,
    /// The connection reader is gone.
    InputClosed,
    /// A protocol violation; the caller ends the stream.
    Rejected(CoreError),
}

/// Reads one stream channel until its client grants outbound credit,
/// shared by git-service output and typed replies. Late stdin endings are
/// ignored; a `Cancel` frame triggers the stream token.
#[cfg(unix)]
async fn wait_outbound_credit(
    input: &mut mpsc::Receiver<ipc::Frame>,
    stream_id: u64,
    credits: &mut ipc::StreamCredits,
    cancel: &CancelHandle,
) -> CreditFate {
    loop {
        let Some(frame) = input.recv().await else {
            return CreditFate::InputClosed;
        };
        if frame.stream_id != stream_id {
            return CreditFate::Rejected(CoreError::new(
                ErrorCode::EInvalid,
                "stream received a frame of another stream",
            ));
        }
        match frame.kind {
            ipc::FrameKind::WindowUpdate => {
                let credit: WindowCredit = match ipc::decode_control(&frame.payload) {
                    Ok(credit) => credit,
                    Err(err) => return CreditFate::Rejected(err),
                };
                match route_credit(credits, stream_id, &credit) {
                    Ok(()) => return CreditFate::Granted,
                    Err(err) => return CreditFate::Rejected(err),
                }
            }
            ipc::FrameKind::Cancel => {
                cancel.cancel();
                return CreditFate::Cancelled;
            }
            ipc::FrameKind::Stdin | ipc::FrameKind::StdinEof => {}
            ipc::FrameKind::Open
            | ipc::FrameKind::Accepted
            | ipc::FrameKind::Stdout
            | ipc::FrameKind::Stderr
            | ipc::FrameKind::HookCall
            | ipc::FrameKind::HookReply
            | ipc::FrameKind::Exit
            | ipc::FrameKind::Error => {
                return CreditFate::Rejected(CoreError::new(
                    ErrorCode::EInvalid,
                    "frame kind is misplaced on this stream",
                ));
            }
        }
    }
}

/// Serves one typed invocation on its stream task: opens the repository,
/// answers `Accepted`, then dispatches on the coordinator while pumping
/// the stream channel. A `Cancel` frame triggers the invocation token, so
/// cancellation reaches the running dispatch through the coordinator's
/// own checks; unexpected frames refuse the stream once dispatch ends.
#[cfg(unix)]
async fn typed_stream(
    input: &mut mpsc::Receiver<ipc::Frame>,
    sink: &StreamSink,
    open: &InvocationOpen,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) {
    let stream_id = sink.stream_id;
    let mut credits = ipc::StreamCredits::new(refs.window_bytes);
    credits.open_stream(stream_id);
    let (cancel_guard, cancel) = cancellation();
    let fail = async |err: Error| {
        let _ = send_error_exit(sink, &err).await;
    };
    let method = match Method::ALL.iter().find(|m| m.as_str() == open.method) {
        Some(method) => *method,
        None => {
            fail(Error::Core(CoreError::new(
                ErrorCode::EInvalid,
                format!("unknown method `{}`", open.method),
            )))
            .await;
            return;
        }
    };
    let repo_ref = open.repo.clone();
    let registry = Arc::clone(&refs.registry);
    let opened = refs
        .executor
        .run(move || registry.open(&repo_ref))
        .await
        .map_err(Error::Core);
    let (handle, _, coordinator) = match opened {
        Ok(Ok(triple)) => triple,
        Ok(Err(err)) | Err(Error::Core(err)) => {
            fail(Error::Core(err)).await;
            return;
        }
        Err(err) => {
            fail(err).await;
            return;
        }
    };
    let principal = Principal::from_peer_uid(peer.uid);
    let accepted = InvocationAccepted {
        stream_id,
        method: method.as_str().to_string(),
        repo_handle: handle,
    };
    let accepted_bytes = match ipc::encode_control(&accepted) {
        Ok(bytes) => bytes,
        Err(err) => {
            fail(Error::Core(err)).await;
            return;
        }
    };
    if send_frame(sink, ipc::FrameKind::Accepted, &accepted_bytes)
        .await
        .is_err()
    {
        return;
    }
    let session = match open.session_id.as_deref() {
        None => None,
        Some(text) => match text.parse::<SessionId>() {
            Ok(id) => Some(id),
            Err(err) => {
                fail(Error::Core(CoreError::new(
                    ErrorCode::EInvalid,
                    format!("invocation carries a malformed session id: {err}"),
                )))
                .await;
                return;
            }
        },
    };
    let dispatch = dispatch_method(&coordinator, &principal, open, method, session, &cancel);
    tokio::pin!(dispatch);
    let mut refused: Option<CoreError> = None;
    let result = loop {
        tokio::select! {
            output = &mut dispatch => break output,
            frame = input.recv() => {
                let Some(frame) = frame else {
                    return;
                };
                match frame.kind {
                    ipc::FrameKind::Cancel => cancel_guard.cancel(),
                    ipc::FrameKind::WindowUpdate => {
                        match ipc::decode_control::<WindowCredit>(&frame.payload) {
                            Ok(credit) => {
                                if let Err(err) = route_credit(&mut credits, stream_id, &credit) {
                                    refused = Some(err);
                                }
                            }
                            Err(err) => refused = Some(err),
                        }
                    }
                    _ => {
                        refused = Some(CoreError::new(
                            ErrorCode::EInvalid,
                            "frame kind is misplaced on this stream",
                        ));
                    }
                }
            }
        }
    };
    if let Some(err) = refused {
        fail(Error::Core(err)).await;
        return;
    }
    match result {
        Ok(stdout) => {
            match write_typed_chunks(sink, input, &mut credits, &cancel_guard, &stdout).await {
                TypedWriteFate::Done => {
                    let _ = send_exit(sink, 0, "OK", "Completed").await;
                }
                TypedWriteFate::Cancelled | TypedWriteFate::Gone => {}
            }
        }
        Err(err) => {
            if err.code == ErrorCode::ECancelled {
                let _ = send_exit(
                    sink,
                    130,
                    ErrorCode::ECancelled.as_str(),
                    "CancelledBeforeCommit",
                )
                .await;
            } else {
                fail(Error::Core(err)).await;
            }
        }
    }
}

/// Dispatches one authorized invocation on its repository coordinator.
///
/// `schema` answers locally. `session.open` opens a real session for the
/// peer principal and answers the honest subset the coordinator returns;
/// `session.resume` answers the full negotiated reply. Reads run through
/// `HostedCoordinator::read` and mutations through
/// `HostedCoordinator::prepare_for_dispatch` plus `submit_prepared`, both
/// under the invocation's session; a missing session refuses, and
/// uncovered methods name their missing path.
///
/// # Errors
/// `E_INVALID` for an unknown shape or a session-bound method without a
/// session, `E_HOSTED` where no read or preparation path exists, plus the
/// coordinator's own typed failures.
pub(crate) async fn dispatch_method(
    coordinator: &Arc<HostedCoordinator>,
    principal: &Principal,
    open: &InvocationOpen,
    method: Method,
    session: Option<SessionId>,
    cancel: &Cancel,
) -> Result<Vec<u8>, CoreError> {
    let args_json = open.args_json.as_deref();
    let request_id = open.request_id.as_deref();
    let on_behalf_of = open.on_behalf_of.clone();
    match method {
        Method::Schema => ipc::encode_control(&ruk_core::protocol::model_schema_json()),
        Method::SessionOpen => {
            let args: SessionOpenArgs = match args_json {
                None => SessionOpenArgs::default(),
                Some(text) => decode_json(text.as_bytes())?,
            };
            let request = Request::SessionOpen(Box::new(args));
            request.validate()?;
            let Request::SessionOpen(open_args) = request else {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "internal: session.open decoded to another method",
                ));
            };
            let (session, reconnect_secret) = coordinator
                .open_session(principal, &open_args, cancel)
                .await?;
            ipc::encode_control(&SessionOpened {
                session,
                reconnect_secret,
                principal: principal.to_string(),
            })
        }
        Method::SessionResume => {
            let text = args_json.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    "method `session.resume` needs its arguments",
                )
            })?;
            let args: SessionResumeArgs = decode_json(text.as_bytes())?;
            let request = Request::SessionResume(Box::new(args));
            request.validate()?;
            let Request::SessionResume(resume_args) = request else {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "internal: session.resume decoded to another method",
                ));
            };
            let reply = coordinator
                .resume_session(principal, &resume_args, cancel)
                .await?;
            ipc::encode_control(&ReplyEnvelope::success(
                None,
                Reply::SessionResume(Box::new(reply)),
            ))
        }
        _ => {
            let request = decode_request_args(method, args_json, request_id)?;
            request.validate()?;
            let Some(session) = session else {
                return Err(refuse_sessionless(method, None));
            };
            match method.kind() {
                ruk_core::protocol::MethodKind::Read => {
                    let reply = coordinator
                        .read(principal, session, request, cancel)
                        .await?;
                    ipc::encode_control(&ReplyEnvelope::success(None, reply))
                }
                ruk_core::protocol::MethodKind::Mutation => {
                    coordinator
                        .check_session(principal, session, cancel)
                        .await?;
                    // The attestation gate follows invocation cancellation:
                    // a cancelled call stops verification instead of
                    // publishing rows it no longer waits for.
                    let checkpoint = |_: ruk_core::attestation::Progress| cancel.check();
                    let typed_id = request.request_id();
                    let ready = coordinator.prepare_for_dispatch(
                        session,
                        request,
                        &checkpoint,
                        on_behalf_of,
                    )?;
                    match ready {
                        ruk_core::coord::DispatchReady::Replay(reply) => {
                            ipc::encode_control(&ReplyEnvelope::success(typed_id, reply))
                        }
                        ruk_core::coord::DispatchReady::Prepared(prepared) => {
                            let request_id = prepared.request_id;
                            let reply = coordinator
                                .submit_prepared(principal, *prepared, cancel)
                                .await?;
                            ipc::encode_control(&ReplyEnvelope::success(Some(request_id), reply))
                        }
                    }
                }
                _ => Err(refuse_sessionless(method, Some(session))),
            }
        }
    }
}

/// Builds the refusal for one read or mutation arriving without a session.
///
/// A missing session is the current refusal. A present session never
/// reaches here through dispatch: reads run on the coordinator and
/// uncovered ones name their missing implementation there, while mutations
/// prepare or name their missing preparation.
fn refuse_sessionless(method: Method, session: Option<SessionId>) -> CoreError {
    match session {
        None => CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `{}` requires a session and the invocation carries none",
                method.as_str()
            ),
        ),
        Some(_) => method_error(method, "no dispatch path serves this method with a session"),
    }
}

/// Wraps decoded mutation parameters with their idempotency key.
///
/// # Errors
/// `E_INVALID` when the invocation frame carried no request id.
fn mutation_request<Args>(
    request_id: Option<RequestId>,
    args: Args,
    wrap: fn(Box<Mutation<Args>>) -> Request,
) -> Result<Request, CoreError> {
    let request_id = request_id.ok_or_else(|| {
        CoreError::new(ErrorCode::EInvalid, "a mutation needs its idempotency key")
    })?;
    Ok(wrap(Box::new(Mutation { request_id, args })))
}

/// Decodes one argument document under the protocol JSON bound.
///
/// # Errors
/// `E_INVALID` for over-nested, malformed, or mismatched JSON.
fn decode_args<Args: DeserializeOwned>(text: &str) -> Result<Args, CoreError> {
    decode_json(text.as_bytes())
}

/// Decodes `args_json` into the typed [`Request`] of `method`.
///
/// Mutation arguments decode as bare parameters; the idempotency key comes
/// from the invocation frame. The result validates shape only: reads run on
/// the coordinator afterwards (uncovered ones name their missing
/// implementation there) and mutations prepare lane parts or name their
/// missing preparation.
///
/// # Errors
/// `E_INVALID` for missing arguments, a missing or malformed mutation
/// request id, a shape mismatch, or a violated method invariant.
fn decode_request_args(
    method: Method,
    args_json: Option<&str>,
    request_id: Option<&str>,
) -> Result<Request, CoreError> {
    let text = args_json.ok_or_else(|| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("method `{}` needs its arguments", method.as_str()),
        )
    })?;
    let id = if method.is_mutation() {
        match request_id {
            Some(text) => Some(text.parse::<RequestId>().map_err(|_| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    format!(
                        "method `{}` carries a malformed request id",
                        method.as_str()
                    ),
                )
            })?),
            None => None,
        }
    } else {
        None
    };
    match method {
        Method::WsNew => mutation_request(id, decode_args(text)?, Request::WsNew),
        Method::WsScope => mutation_request(id, decode_args(text)?, Request::WsScope),
        Method::WsTake => mutation_request(id, decode_args(text)?, Request::WsTake),
        Method::WsDrop => mutation_request(id, decode_args(text)?, Request::WsDrop),
        Method::WsRecover => mutation_request(id, decode_args(text)?, Request::WsRecover),
        Method::Snapshot => mutation_request(id, decode_args(text)?, Request::Snapshot),
        Method::Write => mutation_request(id, decode_args(text)?, Request::Write),
        Method::New => mutation_request(id, decode_args(text)?, Request::New),
        Method::GitCommit => mutation_request(id, decode_args(text)?, Request::GitCommit),
        Method::Describe => mutation_request(id, decode_args(text)?, Request::Describe),
        Method::Edit => mutation_request(id, decode_args(text)?, Request::Edit),
        Method::Split => mutation_request(id, decode_args(text)?, Request::Split),
        Method::Squash => mutation_request(id, decode_args(text)?, Request::Squash),
        Method::Rebase => mutation_request(id, decode_args(text)?, Request::Rebase),
        Method::Abandon => mutation_request(id, decode_args(text)?, Request::Abandon),
        Method::Resolve => mutation_request(id, decode_args(text)?, Request::Resolve),
        Method::Revert => mutation_request(id, decode_args(text)?, Request::Revert),
        Method::BookmarkSet => mutation_request(id, decode_args(text)?, Request::BookmarkSet),
        Method::BookmarkDelete => mutation_request(id, decode_args(text)?, Request::BookmarkDelete),
        Method::BookmarkResolve => {
            mutation_request(id, decode_args(text)?, Request::BookmarkResolve)
        }
        Method::TagSet => mutation_request(id, decode_args(text)?, Request::TagSet),
        Method::TagDelete => mutation_request(id, decode_args(text)?, Request::TagDelete),
        Method::ClaimAcquire => mutation_request(id, decode_args(text)?, Request::ClaimAcquire),
        Method::ClaimRelease => mutation_request(id, decode_args(text)?, Request::ClaimRelease),
        Method::AttestAdd => mutation_request(id, decode_args(text)?, Request::AttestAdd),
        Method::Fetch => mutation_request(id, decode_args(text)?, Request::Fetch),
        Method::Push => mutation_request(id, decode_args(text)?, Request::Push),
        Method::PushReconcile => mutation_request(id, decode_args(text)?, Request::PushReconcile),
        Method::LandPrepare => mutation_request(id, decode_args(text)?, Request::LandPrepare),
        Method::LandExecute => mutation_request(id, decode_args(text)?, Request::LandExecute),
        Method::Undo => mutation_request(id, decode_args(text)?, Request::Undo),
        Method::OpPrune => mutation_request(id, decode_args(text)?, Request::OpPrune),
        Method::Pin => mutation_request(id, decode_args(text)?, Request::Pin),
        Method::Unpin => mutation_request(id, decode_args(text)?, Request::Unpin),
        Method::ClaimList => Ok(Request::ClaimList(Box::new(decode_args(text)?))),
        Method::AttestList => Ok(Request::AttestList(Box::new(decode_args(text)?))),
        Method::OpLog => Ok(Request::OpLog(Box::new(decode_args(text)?))),
        Method::Status => Ok(Request::Status(Box::new(decode_args(text)?))),
        Method::Log => Ok(Request::Log(Box::new(decode_args(text)?))),
        Method::Diff => Ok(Request::Diff(Box::new(decode_args(text)?))),
        Method::Show => Ok(Request::Show(Box::new(decode_args(text)?))),
        Method::File => Ok(Request::File(Box::new(decode_args(text)?))),
        Method::Blame => Ok(Request::Blame(Box::new(decode_args(text)?))),
        Method::Query => Ok(Request::Query(Box::new(decode_args(text)?))),
        Method::Schema | Method::SessionOpen | Method::SessionResume => Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "internal: method `{}` takes another dispatch path",
                method.as_str()
            ),
        )),
    }
}

/// The end of one typed reply write.
#[cfg(unix)]
enum TypedWriteFate {
    /// Every byte reached the writer task.
    Done,
    /// A `Cancel` frame arrived mid-write; the cancelled exit is sent.
    Cancelled,
    /// The connection reader or writer is gone.
    Gone,
}

/// Writes one typed reply in window-sized chunks. When the outbound window
/// exhausts, the write waits for the client to grant more credit instead
/// of refusing, so large bodies stream as `Stdout` frames under the reply
/// window.
#[cfg(unix)]
async fn write_typed_chunks(
    sink: &StreamSink,
    input: &mut mpsc::Receiver<ipc::Frame>,
    credits: &mut ipc::StreamCredits,
    cancel: &CancelHandle,
    bytes: &[u8],
) -> TypedWriteFate {
    let stream_id = sink.stream_id;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + ipc::MAX_DATA_CHUNK_BYTES).min(bytes.len());
        let width = match u64::try_from(end - offset) {
            Ok(width) => width,
            Err(_) => {
                let _ = send_error_exit(
                    sink,
                    &Error::Core(CoreError::new(
                        ErrorCode::ELimit,
                        "data chunk exceeds its bound",
                    )),
                )
                .await;
                return TypedWriteFate::Gone;
            }
        };
        if credits.consume_outbound(stream_id, width).is_ok() {
            if send_frame(sink, ipc::FrameKind::Stdout, &bytes[offset..end])
                .await
                .is_err()
            {
                return TypedWriteFate::Gone;
            }
            offset = end;
            continue;
        }
        match wait_outbound_credit(input, stream_id, credits, cancel).await {
            CreditFate::Granted => {}
            CreditFate::Cancelled => {
                let _ = send_exit(
                    sink,
                    130,
                    ErrorCode::ECancelled.as_str(),
                    "CancelledBeforeCommit",
                )
                .await;
                return TypedWriteFate::Cancelled;
            }
            CreditFate::InputClosed => return TypedWriteFate::Gone,
            CreditFate::Rejected(err) => {
                let _ = send_error_exit(sink, &Error::Core(err)).await;
                return TypedWriteFate::Gone;
            }
        }
    }
    TypedWriteFate::Done
}

/// Queues one frame of `sink` toward the connection-writer task.
///
/// # Errors
/// `E_IO` when the writer task is gone and the connection is dead.
#[cfg(unix)]
async fn send_frame(sink: &StreamSink, kind: ipc::FrameKind, payload: &[u8]) -> Result<(), Error> {
    send_raw(&sink.writer, kind, sink.stream_id, payload).await
}

/// Queues the terminal `Exit` frame of `sink`.
#[cfg(unix)]
async fn send_exit(sink: &StreamSink, status: i32, code: &str, outcome: &str) -> Result<(), Error> {
    let completed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| CoreError::new(ErrorCode::EIo, "system clock predates the epoch"))?;
    let report = ExitReport {
        status,
        code: code.to_string(),
        outcome: outcome.to_string(),
        completed_at,
    };
    let bytes = ipc::encode_control(&report)?;
    send_frame(sink, ipc::FrameKind::Exit, &bytes).await
}

/// Queues an `Error` frame plus the terminal `Exit` frame of `sink`.
#[cfg(unix)]
async fn send_error_exit(sink: &StreamSink, err: &Error) -> Result<(), Error> {
    let core = match err {
        Error::Core(inner) => inner.clone(),
        Error::Config(detail) | Error::Unsupported(detail) => {
            CoreError::new(ErrorCode::EInvalid, detail.clone())
        }
        Error::Io(inner) => CoreError::new(ErrorCode::EIo, inner.to_string()),
    };
    let cancelled = core.code == ErrorCode::ECancelled;
    let status = if cancelled { 130 } else { 1 };
    let report = ErrorReply::from_core(&core);
    let bytes = ipc::encode_control(&report)?;
    send_frame(sink, ipc::FrameKind::Error, &bytes).await?;
    let outcome = if cancelled {
        OUTCOME_CANCELLED
    } else {
        OUTCOME_FAILED
    };
    send_exit(sink, status, report.code.as_str(), outcome).await
}
