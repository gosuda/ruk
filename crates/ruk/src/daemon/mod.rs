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

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(crate) use executor::BoundedExecutor;
pub(crate) use registry::Registry;
use ruk_core::change::{RequestId, SessionId};
use ruk_core::coord::{Cancel, HostedCoordinator, Principal, cancellation};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{
    Method, Mutation, ReconnectSecret, Reply, ReplyEnvelope, Request, SessionOpenArgs,
    SessionResumeArgs, decode_json,
};

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

/// Configuration of one `ruk serve` process.
#[derive(Clone, Debug)]
pub(crate) struct DaemonConfig {
    /// Filesystem path of the Unix socket to bind.
    socket_path: PathBuf,
    /// Repository roots; every open must land beneath one.
    repo_roots: Vec<PathBuf>,
    /// Allowed peer user identifiers; empty allows every local peer.
    allowed_uids: Vec<u32>,
    /// Concurrent connections before the daemon sheds accept.
    max_connections: usize,
    /// Blocking permits of the shared executor.
    blocking_pool_size: usize,
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
            max_connections: DEFAULT_MAX_CONNECTIONS,
            blocking_pool_size: DEFAULT_BLOCKING_POOL_SIZE,
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

    /// Sets the concurrent connection bound.
    #[must_use]
    pub(crate) fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
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

    /// Loads a TOML daemon configuration document.
    ///
    /// Keys: `socket_path`, `repo_roots` (required), `allowed_uids`,
    /// `max_connections`, `blocking_pool_size`, `handshake_timeout_ms`,
    /// `frame_timeout_ms`, `stream_window_bytes`, `retention_interval_ms`
    /// (optional; zero disables periodic retention sweeps).
    ///
    /// # Errors
    /// `Error::Config` on malformed TOML, missing required keys, or bounds
    /// outside `validate`.
    pub(crate) fn from_toml(doc: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct Doc {
            socket_path: PathBuf,
            repo_roots: Vec<PathBuf>,
            #[serde(default)]
            allowed_uids: Vec<u32>,
            max_connections: Option<usize>,
            blocking_pool_size: Option<usize>,
            handshake_timeout_ms: Option<u64>,
            frame_timeout_ms: Option<u64>,
            stream_window_bytes: Option<u64>,
            retention_interval_ms: Option<u64>,
        }
        let text = std::str::from_utf8(doc)
            .map_err(|err| Error::Config(format!("config is not UTF-8: {err}")))?;
        let doc: Doc =
            toml::from_str(text).map_err(|err| Error::Config(format!("config TOML: {err}")))?;
        let mut cfg =
            Self::new(doc.socket_path, doc.repo_roots).with_allowed_uids(doc.allowed_uids);
        if let Some(v) = doc.max_connections {
            cfg = cfg.with_max_connections(v);
        }
        if let Some(v) = doc.blocking_pool_size {
            cfg = cfg.with_blocking_pool_size(v);
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
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks every bound the daemon depends on.
    ///
    /// # Errors
    /// `Config` for an empty socket path, root set, connection bound,
    /// blocking pool, deadline, or window.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(Error::Config(String::from("socket path must not be empty")));
        }
        if self.repo_roots.is_empty() {
            return Err(Error::Config(String::from(
                "at least one repository root is required",
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
    /// Absolute repository path or opaque handle from a previous open.
    pub repo: String,
    /// The protocol method name, such as `status`.
    pub method: String,
    /// The idempotency key half of a mutation, if any.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The raw JSON document of the method arguments, if any.
    #[serde(default)]
    pub args_json: Option<String>,
    /// The session reads and mutations run under, if any. Go command
    /// streams never send it; typed clients do.
    #[serde(default)]
    pub session_id: Option<String>,
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
    /// The durable mutation outcome: `Completed` or `CancelledBeforeCommit`.
    pub outcome: String,
    /// Unix seconds of completion, from the system clock.
    pub completed_at: u64,
}

/// The `Error` payload reporting one invocation failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ErrorReport {
    /// The closed error-code spelling, never message text.
    pub code: String,
    /// The human diagnostic accompanying the code.
    pub message: String,
}

/// Cap of outcome records held per daemon process; older invocations evict
/// first so reconnect lookups stay bounded.
const MAX_OUTCOME_RECORDS: usize = 10_000;

/// Cap of stdin bytes collected for one command stream.
const MAX_COMMAND_STDIN_BYTES: usize = 256 * 1024 * 1024;

/// Outcome of a command that ran to its terminal report.
const OUTCOME_COMPLETED: &str = "Completed";

/// Outcome of a command cancelled before (or during) its run.
const OUTCOME_CANCELLED: &str = "CancelledBeforeCommit";

/// The `Open` payload of one argv-style command stream, mirroring the Go
/// backend's `RukOpenRequest`. `argv` holds command args without `argv[0]`
/// (for example `["rev-parse", "--git-dir"]`); the daemon prepends its own
/// program name before running the interpreter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandOpen {
    /// The service session; accepted and ignored, reserved for the
    /// day the service session becomes a coordinator session.
    pub session_id: String,
    /// The authorized repository path, canonicalized under the roots.
    pub repository: String,
    /// The idempotency key: reconnects replaying it observe the recorded
    /// terminal report instead of running the command twice.
    pub request_id: String,
    /// Command args without `argv[0]`.
    pub argv: Vec<String>,
    /// Working directory the command starts in.
    pub dir: String,
    /// Environment as `KEY=value` entries; the command sees only these.
    pub env: Vec<String>,
    /// Digest over argv, directory, and environment: a reused request id
    /// with a different digest is refused, never executed.
    pub command_digest: String,
    /// Initial outbound credit for stdout, added to the default window.
    pub stdout_credit: u64,
    /// Initial outbound credit for stderr, added to the default window.
    pub stderr_credit: u64,
}

/// The `Accepted` payload answering one command `Open`, mirroring the Go
/// backend's `RukAcceptedReply`. `stdin_credit` carries the inbound window
/// granted; it is always positive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandAccepted {
    /// The accepted stream identifier.
    pub stream_id: u64,
    /// The stdin credit bytes granted to the client.
    pub stdin_credit: u64,
    /// The invocation identity, echoing the open's request id.
    pub invocation_id: String,
}

/// The `Exit` payload ending one command stream, mirroring the Go
/// backend's `RukExitReport`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CommandExitReport {
    /// The native process exit status: zero on success.
    pub exit_code: i32,
    /// The terminating signal name; empty for a normal exit.
    pub signal: String,
    /// True when cancellation ended the invocation.
    pub cancelled: bool,
    /// The durable outcome: `Completed` or `CancelledBeforeCommit`.
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

    /// Builds the terminal report of a failed command.
    fn failure(invocation: &str) -> Self {
        Self::success(invocation, 1)
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

/// One stream-zero typed control query, mirroring the Go backend's
/// `RukControlRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ControlRequest {
    /// The query type; the daemon answers `outcome-lookup`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The invocation identity to look up.
    pub invocation_id: String,
}

/// The answer to one control query, mirroring the Go backend's
/// `RukControlReply`. It travels on an `Accepted` frame with no terminal
/// `Exit`: the connection stays open for further streams.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ControlReply {
    /// The query type echoed back.
    #[serde(rename = "type")]
    pub type_: String,
    /// True when the ledger holds the invocation's terminal report.
    pub found: bool,
    /// The recorded terminal report; absent when `found` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<CommandExitReport>,
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

/// The ledger state of one invocation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OutcomeState {
    /// The first open is still running; reconnects wait or fail loudly.
    Running {
        /// The digest the running command opened with.
        digest: String,
    },
    /// The terminal report; replays observe it without re-running.
    Done(CommandExitReport),
}

/// One ledger row: the digest that claimed the identity plus its state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OutcomeEntry {
    /// The digest of the command holding this identity.
    digest: String,
    /// Running or terminal.
    state: OutcomeState,
}

/// The process-wide outcome ledger behind reconnect lookups.
///
/// Every connection task shares one ledger through [`ConnectionRefs`], so
/// an outcome lookup arriving on a fresh connection observes commands that
/// ran on any other connection of this process.
#[derive(Debug, Default)]
struct OutcomeLedger {
    /// Invocation identity to its row.
    records: HashMap<String, OutcomeEntry>,
    /// Insertion order for oldest-first eviction; may hold stale names of
    /// removed rows, which eviction skips.
    order: VecDeque<String>,
}

impl OutcomeLedger {
    /// Claims `id` for a fresh command, evicting oldest-first past the cap.
    fn insert_running(&mut self, id: &str, digest: &str) {
        while self.records.len() >= MAX_OUTCOME_RECORDS {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.records.remove(&oldest);
        }
        self.order.push_back(id.to_string());
        self.records.insert(
            id.to_string(),
            OutcomeEntry {
                digest: digest.to_string(),
                state: OutcomeState::Running {
                    digest: digest.to_string(),
                },
            },
        );
    }

    /// Records the terminal report of `id`, keeping its digest.
    fn complete(&mut self, id: &str, report: CommandExitReport) {
        if let Some(entry) = self.records.get_mut(id) {
            entry.state = OutcomeState::Done(report);
            return;
        }
        self.order.push_back(id.to_string());
        self.records.insert(
            id.to_string(),
            OutcomeEntry {
                digest: String::new(),
                state: OutcomeState::Done(report),
            },
        );
    }

    /// Forgets `id` without a terminal report, so a retry may run fresh.
    fn remove(&mut self, id: &str) {
        self.records.remove(id);
    }
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

/// Per-stream state of one connection.
struct StreamState {
    /// Total `Stdin` bytes accepted on this stream.
    stdin_bytes: usize,
    /// True once `Cancel` arrived.
    cancelled: bool,
}

/// Shared handles of one connection task.
#[derive(Clone)]
struct ConnectionRefs {
    /// The authorizing registry.
    registry: Arc<Registry>,
    /// The shared blocking pool.
    executor: BoundedExecutor,
    /// The process-wide outcome ledger. Every connection task shares one
    /// ledger (linearizable through one mutex, held only for map
    /// probes), so an outcome lookup on a fresh connection observes
    /// commands that ran on any other connection. Consumers stay
    /// idempotent: a replayed request id observes the recorded terminal
    /// report instead of running the command twice.
    outcomes: Arc<Mutex<OutcomeLedger>>,
    /// The starting credit window of each stream direction.
    window_bytes: u64,
    /// The stream-zero handshake deadline.
    handshake_timeout: Duration,
    /// The per-frame deadline after the handshake.
    frame_timeout: Duration,
    /// Allowed peer user identifiers; empty allows every local peer.
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
    let refs = ConnectionRefs {
        registry,
        executor,
        outcomes: Arc::new(Mutex::new(OutcomeLedger::default())),
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
    let mut streams: HashMap<u64, StreamState> = HashMap::new();
    let mut credits = ipc::StreamCredits::new(refs.window_bytes);
    loop {
        let frame_deadline = tokio::time::Instant::now() + refs.frame_timeout;
        let frame = ipc::read_frame(&mut stream, frame_deadline).await?;
        if frame.stream_id == ipc::CONTROL_STREAM_ID {
            if handle_control_frame(&mut stream, &frame, &mut streams, frame_deadline, &refs)
                .await?
            {
                return Ok(());
            }
            continue;
        }
        if handle_stream_frame(&mut stream, frame, &mut streams, &mut credits, &refs, peer).await? {
            return Ok(());
        }
    }
}

#[cfg(unix)]
async fn handle_control_frame(
    stream: &mut tokio::net::UnixStream,
    frame: &ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    deadline: tokio::time::Instant,
    refs: &ConnectionRefs,
) -> Result<bool, Error> {
    match frame.kind {
        ipc::FrameKind::Cancel => {
            for state in streams.values_mut() {
                state.cancelled = true;
            }
            Ok(true)
        }
        ipc::FrameKind::WindowUpdate => {
            let credit: WindowCredit = ipc::decode_control(&frame.payload)?;
            let _ = credit;
            Ok(false)
        }
        ipc::FrameKind::Exit | ipc::FrameKind::Error => Ok(true),
        ipc::FrameKind::Open => answer_control_open(stream, frame, deadline, refs).await,
        ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdin
        | ipc::FrameKind::StdinEof
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::MergeNotices => {
            let report = ErrorReport {
                code: ErrorCode::EInvalid.as_str().to_string(),
                message: String::from("stream-zero carries only the handshake and control queries"),
            };
            let bytes = ipc::encode_control(&report)?;
            ipc::write_frame(
                stream,
                ipc::FrameKind::Error,
                ipc::CONTROL_STREAM_ID,
                &bytes,
                deadline,
            )
            .await?;
            Ok(false)
        }
    }
}

/// Answers one stream-zero `Open` control query without ending the
/// connection: `outcome-lookup` reads the shared ledger and replies on an
/// `Accepted` frame, anything else gets an `Error` frame.
#[cfg(unix)]
async fn answer_control_open(
    stream: &mut tokio::net::UnixStream,
    frame: &ipc::Frame,
    deadline: tokio::time::Instant,
    refs: &ConnectionRefs,
) -> Result<bool, Error> {
    let query: ControlRequest = match ipc::decode_control(&frame.payload) {
        Ok(query) => query,
        Err(err) => {
            write_control_error(stream, &err, deadline).await?;
            return Ok(false);
        }
    };
    if query.type_ != "outcome-lookup" {
        let err = CoreError::new(
            ErrorCode::EInvalid,
            format!("unknown control query `{}`", query.type_),
        );
        write_control_error(stream, &err, deadline).await?;
        return Ok(false);
    }
    let reply = {
        let ledger = lock_outcomes(refs)?;
        let exit = ledger
            .records
            .get(&query.invocation_id)
            .and_then(|entry| match &entry.state {
                OutcomeState::Done(report) => Some(report.clone()),
                OutcomeState::Running { .. } => None,
            });
        ControlReply {
            type_: query.type_.clone(),
            found: exit.is_some(),
            exit,
        }
    };
    let bytes = ipc::encode_control(&reply)?;
    ipc::write_frame(
        stream,
        ipc::FrameKind::Accepted,
        ipc::CONTROL_STREAM_ID,
        &bytes,
        deadline,
    )
    .await?;
    Ok(false)
}

/// Writes one stream-zero `Error` frame for a rejected control query.
#[cfg(unix)]
async fn write_control_error(
    stream: &mut tokio::net::UnixStream,
    err: &CoreError,
    deadline: tokio::time::Instant,
) -> Result<(), Error> {
    let report = ErrorReport {
        code: err.code.as_str().to_string(),
        message: err.message.clone(),
    };
    let bytes = ipc::encode_control(&report)?;
    ipc::write_frame(
        stream,
        ipc::FrameKind::Error,
        ipc::CONTROL_STREAM_ID,
        &bytes,
        deadline,
    )
    .await?;
    Ok(())
}

/// Locks the shared outcome ledger for one brief probe.
#[cfg(unix)]
fn lock_outcomes(refs: &ConnectionRefs) -> Result<std::sync::MutexGuard<'_, OutcomeLedger>, Error> {
    refs.outcomes.lock().map_err(|_| {
        Error::Core(CoreError::new(
            ErrorCode::EIo,
            "outcome ledger lock is poisoned",
        ))
    })
}

#[cfg(unix)]
async fn handle_stream_frame(
    stream: &mut tokio::net::UnixStream,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<bool, Error> {
    match frame.kind {
        ipc::FrameKind::Open => handle_open(stream, frame, streams, credits, refs, peer).await,
        ipc::FrameKind::Stdin => {
            let width = u64::try_from(frame.payload.len()).map_err(|_| {
                Error::Core(CoreError::new(
                    ErrorCode::ELimit,
                    "stdin chunk exceeds its bound",
                ))
            })?;
            if let Err(err) = credits.consume_inbound(frame.stream_id, width) {
                send_error_exit(stream, frame.stream_id, &Error::from(err), refs).await?;
                return Ok(false);
            }
            let state = streams.entry(frame.stream_id).or_insert(StreamState {
                stdin_bytes: 0,
                cancelled: false,
            });
            state.stdin_bytes += frame.payload.len();
            if state.stdin_bytes > ipc::MAX_IPC_CONTROL_BYTES {
                send_error_exit(
                    stream,
                    frame.stream_id,
                    &Error::Core(CoreError::new(ErrorCode::ELimit, "stdin exceeds its bound")),
                    refs,
                )
                .await?;
                credits.close_stream(frame.stream_id);
            }
            Ok(false)
        }
        ipc::FrameKind::StdinEof => Ok(false),
        ipc::FrameKind::WindowUpdate => {
            apply_window_update(stream, &frame, credits, refs).await?;
            Ok(false)
        }
        ipc::FrameKind::Cancel => {
            if let Some(state) = streams.get_mut(&frame.stream_id) {
                state.cancelled = true;
            }
            credits.close_stream(frame.stream_id);
            send_exit(
                stream,
                frame.stream_id,
                130,
                ErrorCode::ECancelled.as_str(),
                "CancelledBeforeCommit",
                refs,
            )
            .await?;
            Ok(false)
        }
        ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::MergeNotices
        | ipc::FrameKind::Exit
        | ipc::FrameKind::Error => {
            send_error_exit(
                stream,
                frame.stream_id,
                &Error::Core(CoreError::new(
                    ErrorCode::EInvalid,
                    "daemon never receives this frame kind from a client",
                )),
                refs,
            )
            .await?;
            Ok(false)
        }
    }
}

/// Routes one client credit grant to the inbound or outbound window of its
/// stream, refusing unknown directions and unknown streams.
#[cfg(unix)]
async fn apply_window_update(
    stream: &mut tokio::net::UnixStream,
    frame: &ipc::Frame,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
) -> Result<(), Error> {
    let credit: WindowCredit = ipc::decode_control(&frame.payload)?;
    if route_credit(credits, frame.stream_id, &credit).is_ok() {
        return Ok(());
    }
    if credit.direction.is_empty()
        || credit.direction == "stdin"
        || credit.direction == "stdout"
        || credit.direction == "stderr"
    {
        return unknown_stream_credit(stream, frame.stream_id, refs).await;
    }
    send_error_exit(
        stream,
        frame.stream_id,
        &Error::Core(CoreError::new(
            ErrorCode::EInvalid,
            "credit update names an unknown direction",
        )),
        refs,
    )
    .await
}

/// Reports a credit grant for a stream the daemon does not track.
#[cfg(unix)]
async fn unknown_stream_credit(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    refs: &ConnectionRefs,
) -> Result<(), Error> {
    send_error_exit(
        stream,
        stream_id,
        &Error::Core(CoreError::new(
            ErrorCode::EInvalid,
            "credit update names an unknown stream",
        )),
        refs,
    )
    .await
}

#[cfg(unix)]
async fn handle_open(
    stream: &mut tokio::net::UnixStream,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<bool, Error> {
    let stream_id = frame.stream_id;
    if let Ok(command) = ipc::decode_control::<CommandOpen>(&frame.payload) {
        streams.insert(
            stream_id,
            StreamState {
                stdin_bytes: 0,
                cancelled: false,
            },
        );
        credits.open_stream(stream_id);
        let close = command_inner(stream, stream_id, command, streams, credits, refs, peer).await?;
        credits.close_stream(stream_id);
        return Ok(close);
    }
    let open: InvocationOpen = match ipc::decode_control(&frame.payload) {
        Ok(open) => open,
        Err(err) => {
            send_error_exit(stream, stream_id, &Error::Core(err), refs).await?;
            return Ok(false);
        }
    };
    streams.insert(
        stream_id,
        StreamState {
            stdin_bytes: 0,
            cancelled: false,
        },
    );
    credits.open_stream(stream_id);
    let _ = open_inner(stream, stream_id, &open, credits, refs, peer).await;
    credits.close_stream(stream_id);
    Ok(false)
}

/// The claim of one invocation identity against the shared ledger.
#[cfg(unix)]
enum RequestSlot {
    /// Fresh identity, claimed as running by this open.
    Run,
    /// Terminal report recorded: replay it without running.
    Replay(CommandExitReport),
    /// Another connection is running this identity now.
    Busy,
    /// The identity is taken by a different command digest.
    DigestMismatch,
}

/// Claims one invocation identity: fresh ids become `Run`, terminal ids
/// replay, live ids and digest conflicts refuse. The ledger lock is held
/// only for this probe, never across an await.
#[cfg(unix)]
fn claim_request_slot(
    refs: &ConnectionRefs,
    request_id: &str,
    command_digest: &str,
) -> Result<RequestSlot, Error> {
    let mut ledger = lock_outcomes(refs)?;
    let Some(entry) = ledger.records.get(request_id) else {
        ledger.insert_running(request_id, command_digest);
        return Ok(RequestSlot::Run);
    };
    if entry.digest != command_digest {
        return Ok(RequestSlot::DigestMismatch);
    }
    match &entry.state {
        OutcomeState::Running { .. } => Ok(RequestSlot::Busy),
        OutcomeState::Done(report) => Ok(RequestSlot::Replay(report.clone())),
    }
}

/// The mutable serving state of one connection, threaded through command
/// handling so every helper takes a narrow slice of it.
#[cfg(unix)]
struct CommandServing<'a> {
    /// The connection socket; one command owns it while running inline.
    stream: &'a mut tokio::net::UnixStream,
    /// Per-stream bookkeeping of the connection.
    streams: &'a mut HashMap<u64, StreamState>,
    /// Directional credit windows of the connection.
    credits: &'a mut ipc::StreamCredits,
    /// Shared registry, executor, ledger, and timeouts.
    refs: &'a ConnectionRefs,
    /// The authenticated peer of the connection.
    peer: ipc::PeerIdentity,
}

/// One validated command ready to collect stdin and run.
#[cfg(unix)]
struct ReadyCommand {
    /// The invocation identity claiming the ledger row.
    invocation: String,
    /// Command args without `argv[0]`.
    argv: Vec<String>,
    /// The hermetic variable map the command runs with.
    vars: HashMap<String, String>,
    /// The canonical working directory under the roots.
    cwd: PathBuf,
}

/// Serves one argv-style command stream to its terminal frame, inline.
///
/// A long-running command blocks sibling streams on the same connection:
/// `serve_connection` cannot read the next frame while this future owns
/// the socket. That is the documented v1 limitation; frames for other
/// streams arriving mid-command are buffered and replayed after the
/// terminal frame instead of being dropped.
///
/// Returns true when the connection must close (stream-zero teardown).
#[cfg(unix)]
async fn command_inner(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    req: CommandOpen,
    streams: &mut HashMap<u64, StreamState>,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<bool, Error> {
    let CommandOpen {
        session_id: _,
        repository,
        request_id: invocation,
        argv,
        dir,
        env,
        command_digest,
        stdout_credit,
        stderr_credit,
    } = req;
    let mut serving = CommandServing {
        stream,
        streams,
        credits,
        refs,
        peer,
    };
    if invocation.is_empty() {
        refuse_unclaimed(
            &mut serving,
            stream_id,
            CoreError::new(ErrorCode::EInvalid, "command open carries no request id"),
        )
        .await?;
        return Ok(false);
    }
    match claim_request_slot(serving.refs, &invocation, &command_digest)? {
        RequestSlot::Run => {}
        RequestSlot::Replay(report) => {
            return replay_command(&mut serving, stream_id, &invocation, &report).await;
        }
        RequestSlot::Busy => {
            refuse_unclaimed(
                &mut serving,
                stream_id,
                CoreError::new(
                    ErrorCode::EInvalid,
                    "invocation is still in progress on another stream",
                ),
            )
            .await?;
            return Ok(false);
        }
        RequestSlot::DigestMismatch => {
            refuse_unclaimed(
                &mut serving,
                stream_id,
                CoreError::new(
                    ErrorCode::EInvalid,
                    "request id is taken by a different command digest",
                ),
            )
            .await?;
            return Ok(false);
        }
    }
    let validated = {
        let registry = Arc::clone(&serving.refs.registry);
        serving
            .refs
            .executor
            .run(move || validate_command_fs(&registry, &repository, &dir, &env))
            .await
    };
    let (canonical_dir, vars) = match validated {
        Ok(Ok(valid)) => valid,
        Ok(Err(err)) | Err(err) => {
            refuse_command(&mut serving, stream_id, &invocation, err).await?;
            return Ok(false);
        }
    };
    let accepted = CommandAccepted {
        stream_id,
        stdin_credit: serving.refs.window_bytes,
        invocation_id: invocation.clone(),
    };
    let accepted_bytes = ipc::encode_control(&accepted).map_err(Error::Core)?;
    if serving
        .credits
        .grant_outbound(stream_id, stdout_credit.saturating_add(stderr_credit))
        .is_err()
    {
        refuse_command(
            &mut serving,
            stream_id,
            &invocation,
            CoreError::new(ErrorCode::EInvalid, "command stream is not tracked"),
        )
        .await?;
        return Ok(false);
    }
    if send_frame(
        serving.stream,
        ipc::FrameKind::Accepted,
        stream_id,
        &accepted_bytes,
        serving.refs,
    )
    .await
    .is_err()
    {
        lock_outcomes(serving.refs)?.complete(&invocation, CommandExitReport::failure(&invocation));
        return Ok(false);
    }
    let ready = ReadyCommand {
        invocation,
        argv,
        vars,
        cwd: canonical_dir,
    };
    serve_ready_command(&mut serving, stream_id, ready).await
}

/// Collects stdin, runs the interpreter on the blocking pool, and streams
/// the captured output to the terminal frame.
///
/// Returns true when the connection must close (stream-zero teardown).
#[cfg(unix)]
async fn serve_ready_command(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    ready: ReadyCommand,
) -> Result<bool, Error> {
    let ReadyCommand {
        invocation,
        argv,
        vars,
        cwd,
    } = ready;
    let mut pending: Vec<ipc::Frame> = Vec::new();
    let stdin_bytes = match collect_command_stdin(serving, stream_id, &mut pending).await {
        Ok(CollectFate::Ready(bytes)) => bytes,
        Ok(CollectFate::Cancelled { close_connection }) => {
            return cancel_command(serving, stream_id, &invocation, pending, close_connection)
                .await;
        }
        Ok(CollectFate::Teardown) => {
            return teardown_command(serving, &invocation).await;
        }
        Ok(CollectFate::Rejected(err)) => {
            refuse_command(serving, stream_id, &invocation, err).await?;
            return Ok(false);
        }
        Err(err) => {
            lock_outcomes(serving.refs)?.remove(&invocation);
            return Err(err);
        }
    };
    let mut full_argv = Vec::with_capacity(argv.len() + 1);
    full_argv.push("git".to_string());
    full_argv.extend(argv);
    let outcome = serving
        .refs
        .executor
        .run(move || {
            crate::cli::run_captured(
                full_argv,
                crate::cli::CliEnv {
                    vars,
                    cwd,
                    stdin: Some(stdin_bytes),
                },
            )
        })
        .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            refuse_command(serving, stream_id, &invocation, err).await?;
            return Ok(false);
        }
    };
    let report = CommandExitReport::success(&invocation, outcome.code);
    lock_outcomes(serving.refs)?.complete(&invocation, report.clone());
    for (kind, bytes) in [
        (ipc::FrameKind::Stdout, outcome.stdout),
        (ipc::FrameKind::Stderr, outcome.stderr),
    ] {
        match write_cmd_data(serving, stream_id, kind, &bytes, &mut pending).await? {
            WriteFate::Done => {}
            WriteFate::Cancelled { close_connection } => {
                return cancel_command(serving, stream_id, &invocation, pending, close_connection)
                    .await;
            }
            WriteFate::Teardown => {
                return teardown_command(serving, &invocation).await;
            }
        }
    }
    let exit_bytes = ipc::encode_control(&report).map_err(Error::Core)?;
    send_frame(
        serving.stream,
        ipc::FrameKind::Exit,
        stream_id,
        &exit_bytes,
        serving.refs,
    )
    .await?;
    replay_pending(serving, pending).await
}

/// Records a stream-zero teardown failure and closes the connection.
#[cfg(unix)]
async fn teardown_command(
    serving: &mut CommandServing<'_>,
    invocation: &str,
) -> Result<bool, Error> {
    lock_outcomes(serving.refs)?.complete(invocation, CommandExitReport::failure(invocation));
    Ok(true)
}

/// Replays one recorded terminal report: `Accepted` with the invocation
/// identity, then the recorded `Exit`, without running the command again.
#[cfg(unix)]
async fn replay_command(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    invocation: &str,
    report: &CommandExitReport,
) -> Result<bool, Error> {
    let accepted = CommandAccepted {
        stream_id,
        stdin_credit: serving.refs.window_bytes,
        invocation_id: invocation.to_string(),
    };
    let accepted_bytes = ipc::encode_control(&accepted).map_err(Error::Core)?;
    send_frame(
        serving.stream,
        ipc::FrameKind::Accepted,
        stream_id,
        &accepted_bytes,
        serving.refs,
    )
    .await?;
    let exit_bytes = ipc::encode_control(report).map_err(Error::Core)?;
    send_frame(
        serving.stream,
        ipc::FrameKind::Exit,
        stream_id,
        &exit_bytes,
        serving.refs,
    )
    .await?;
    Ok(false)
}

/// Records the failure of a claimed `invocation` and reports it as `Error`
/// plus the legacy terminal frame, so a later outcome lookup observes the
/// failure instead of uncertainty.
#[cfg(unix)]
async fn refuse_command(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    invocation: &str,
    err: CoreError,
) -> Result<(), Error> {
    lock_outcomes(serving.refs)?.complete(invocation, CommandExitReport::failure(invocation));
    send_error_exit(serving.stream, stream_id, &Error::Core(err), serving.refs).await
}

/// Reports a refusal without touching the ledger: the identity is empty or
/// belongs to another command, so recording a failure would poison a row
/// this open never claimed.
#[cfg(unix)]
async fn refuse_unclaimed(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    err: CoreError,
) -> Result<(), Error> {
    send_error_exit(serving.stream, stream_id, &Error::Core(err), serving.refs).await
}

/// Ends one cancelled command with its terminal report, then replays
/// frames buffered for sibling streams. A stream-zero cancel also closes
/// the connection, since no further frame can arrive on it.
#[cfg(unix)]
async fn cancel_command(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    invocation: &str,
    pending: Vec<ipc::Frame>,
    close_connection: bool,
) -> Result<bool, Error> {
    let report = CommandExitReport::cancelled(invocation);
    lock_outcomes(serving.refs)?.complete(invocation, report.clone());
    if close_connection {
        return Ok(true);
    }
    let exit_bytes = ipc::encode_control(&report).map_err(Error::Core)?;
    send_frame(
        serving.stream,
        ipc::FrameKind::Exit,
        stream_id,
        &exit_bytes,
        serving.refs,
    )
    .await?;
    replay_pending(serving, pending).await
}

/// Replays frames buffered for other streams while a command owned the
/// socket, in arrival order.
#[cfg(unix)]
async fn replay_pending(
    serving: &mut CommandServing<'_>,
    pending: Vec<ipc::Frame>,
) -> Result<bool, Error> {
    for frame in pending {
        // Boxed: replaying may serve another command inline, which recurses
        // through `handle_stream_frame`; boxing breaks the async cycle.
        if Box::pin(handle_stream_frame(
            serving.stream,
            frame,
            serving.streams,
            serving.credits,
            serving.refs,
            serving.peer,
        ))
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Validates one command open against the filesystem, on the blocking
/// pool: resolves `dir` (and `repository` when it names another path)
/// under the configured roots and parses `env` into the hermetic variable
/// map the command runs with. The command inherits nothing from the
/// daemon's own environment.
#[cfg(unix)]
fn validate_command_fs(
    registry: &Registry,
    repository: &str,
    dir: &str,
    env: &[String],
) -> Result<(PathBuf, HashMap<String, String>), CoreError> {
    let canonical = registry.resolve(Path::new(dir))?;
    if !repository.is_empty() && repository != dir {
        let repo_path = registry.resolve(Path::new(repository))?;
        if repo_path != canonical {
            return Err(CoreError::new(
                ErrorCode::EForbidden,
                "command repository and directory disagree",
            ));
        }
    }
    let mut vars = HashMap::with_capacity(env.len());
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "command environment must be KEY=value")
        })?;
        if key.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "command environment names an empty variable",
            ));
        }
        vars.insert(key.to_string(), value.to_string());
    }
    for key in ["GIT_DIR", "GIT_WORK_TREE"] {
        if let Some(value) = vars.get(key) {
            check_env_path_under_roots(registry, &canonical, value)?;
        }
    }
    Ok((canonical, vars))
}

/// Confines one `GIT_DIR`/`GIT_WORK_TREE` value beneath the roots.
/// Absolute values resolve through the registry; relative values join the
/// command directory first. A missing path falls back to a lexical prefix
/// check so a not-yet-created directory cannot smuggle an escape.
#[cfg(unix)]
fn check_env_path_under_roots(
    registry: &Registry,
    base: &Path,
    value: &str,
) -> Result<(), CoreError> {
    let raw = Path::new(value);
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base.join(raw)
    };
    match registry.resolve(&candidate) {
        Ok(_) => Ok(()),
        Err(err) if err.code == ErrorCode::ENotFound => {
            let normalized = normalize_lexical(&candidate);
            let inside = registry
                .roots()
                .iter()
                .any(|root| normalized.starts_with(root));
            if inside {
                Ok(())
            } else {
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    "command path escapes the configured roots",
                ))
            }
        }
        Err(err) => Err(err),
    }
}

/// Collapses `.` and `..` lexically, without touching the filesystem.
#[cfg(unix)]
fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    out
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

/// The end of one stdin collection loop.
#[cfg(unix)]
enum CollectFate {
    /// `StdinEof` arrived with the collected bytes.
    Ready(Vec<u8>),
    /// Cancellation arrived; only a stream-zero cancel closes the
    /// connection.
    Cancelled {
        /// True when stream zero carried the cancel.
        close_connection: bool,
    },
    /// The client tore the connection down.
    Teardown,
    /// A protocol violation; the caller records a failure and refuses.
    Rejected(CoreError),
}

/// Collects stdin for one command stream, inline on the connection.
/// `Stdin` chunks are credit-checked and acknowledged with a `stdin`
/// grant each, so a client larger than one window keeps flowing.
/// Stream-zero teardown maps to [`CollectFate::Cancelled`] (close) or
/// [`CollectFate::Teardown`]; frames for other streams buffer into
/// `pending` for replay after the terminal frame.
#[cfg(unix)]
async fn collect_command_stdin(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    pending: &mut Vec<ipc::Frame>,
) -> Result<CollectFate, Error> {
    let mut stdin_bytes: Vec<u8> = Vec::new();
    loop {
        let deadline = tokio::time::Instant::now() + serving.refs.frame_timeout;
        let frame = ipc::read_frame(serving.stream, deadline)
            .await
            .map_err(Error::Core)?;
        if frame.stream_id != stream_id && frame.stream_id != ipc::CONTROL_STREAM_ID {
            pending.push(frame);
            continue;
        }
        if frame.stream_id == ipc::CONTROL_STREAM_ID {
            match control_during_command(serving, &frame, deadline).await? {
                ControlFate::Continue => continue,
                ControlFate::Cancelled => {
                    return Ok(CollectFate::Cancelled {
                        close_connection: true,
                    });
                }
                ControlFate::Teardown => return Ok(CollectFate::Teardown),
            }
        }
        match frame.kind {
            ipc::FrameKind::Stdin => {
                match absorb_stdin_chunk(
                    serving.credits,
                    stream_id,
                    &mut stdin_bytes,
                    &frame.payload,
                ) {
                    Ok(width) => {
                        let grant = StdinGrant {
                            direction: "stdin".to_string(),
                            bytes: width,
                        };
                        let bytes = ipc::encode_control(&grant).map_err(Error::Core)?;
                        send_frame(
                            serving.stream,
                            ipc::FrameKind::WindowUpdate,
                            stream_id,
                            &bytes,
                            serving.refs,
                        )
                        .await?;
                    }
                    Err(err) => return Ok(CollectFate::Rejected(err)),
                }
            }
            ipc::FrameKind::StdinEof => return Ok(CollectFate::Ready(stdin_bytes)),
            ipc::FrameKind::Cancel => {
                return Ok(CollectFate::Cancelled {
                    close_connection: false,
                });
            }
            ipc::FrameKind::WindowUpdate => {
                let credit: WindowCredit =
                    ipc::decode_control(&frame.payload).map_err(Error::Core)?;
                if let Err(err) = route_credit(serving.credits, stream_id, &credit) {
                    return Ok(CollectFate::Rejected(err));
                }
            }
            ipc::FrameKind::Open
            | ipc::FrameKind::Accepted
            | ipc::FrameKind::Stdout
            | ipc::FrameKind::Stderr
            | ipc::FrameKind::MergeNotices
            | ipc::FrameKind::Exit
            | ipc::FrameKind::Error => {
                return Ok(CollectFate::Rejected(CoreError::new(
                    ErrorCode::EInvalid,
                    "daemon never receives this frame kind from a client",
                )));
            }
        }
    }
}

/// Absorbs one stdin chunk under the inbound window and the stream cap,
/// returning the width the daemon grants back to the client.
///
/// # Errors
/// `E_LIMIT` past the stream cap or the inbound window.
#[cfg(unix)]
fn absorb_stdin_chunk(
    credits: &mut ipc::StreamCredits,
    stream_id: u64,
    stdin_bytes: &mut Vec<u8>,
    payload: &[u8],
) -> Result<u64, CoreError> {
    let width = u64::try_from(payload.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "stdin chunk exceeds its bound"))?;
    if stdin_bytes.len().saturating_add(payload.len()) > MAX_COMMAND_STDIN_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "command stdin exceeds its bound",
        ));
    }
    credits.consume_inbound(stream_id, width)?;
    stdin_bytes.extend_from_slice(payload);
    credits.grant_inbound(stream_id, width)?;
    Ok(width)
}

/// The end of one stream-zero frame seen while a command owns the socket.
#[cfg(unix)]
enum ControlFate {
    /// An answered query or ignored grant; keep collecting.
    Continue,
    /// Stream-zero cancel; the command ends cancelled and the connection
    /// closes.
    Cancelled,
    /// Stream-zero teardown; the command records a failure and closes.
    Teardown,
}

/// Handles one stream-zero frame arriving mid-command: global cancel and
/// teardown end the command, outcome lookups answer inline, grants are
/// ignored.
#[cfg(unix)]
async fn control_during_command(
    serving: &mut CommandServing<'_>,
    frame: &ipc::Frame,
    deadline: tokio::time::Instant,
) -> Result<ControlFate, Error> {
    match frame.kind {
        ipc::FrameKind::Cancel => Ok(ControlFate::Cancelled),
        ipc::FrameKind::Exit | ipc::FrameKind::Error => Ok(ControlFate::Teardown),
        ipc::FrameKind::WindowUpdate => {
            let credit: WindowCredit = ipc::decode_control(&frame.payload).map_err(Error::Core)?;
            let _ = credit;
            Ok(ControlFate::Continue)
        }
        ipc::FrameKind::Open => {
            answer_control_open(serving.stream, frame, deadline, serving.refs).await?;
            Ok(ControlFate::Continue)
        }
        ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdin
        | ipc::FrameKind::StdinEof
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::MergeNotices => {
            let err = CoreError::new(
                ErrorCode::EInvalid,
                "stream-zero carries only the handshake and control queries",
            );
            write_control_error(serving.stream, &err, deadline).await?;
            Ok(ControlFate::Continue)
        }
    }
}

/// The end of one output write loop.
#[cfg(unix)]
enum WriteFate {
    /// Every byte reached the socket.
    Done,
    /// Cancellation arrived mid-write; only stream-zero closes.
    Cancelled {
        /// True when stream zero carried the cancel.
        close_connection: bool,
    },
    /// The client tore the connection down.
    Teardown,
}

/// Writes one output direction in window-sized chunks. When the outbound
/// window exhausts, the loop reads frames until the client grants more
/// credit, so outputs larger than the initial window still complete as
/// long as the client keeps granting per chunk, the way the Go backend
/// does.
#[cfg(unix)]
async fn write_cmd_data(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    kind: ipc::FrameKind,
    bytes: &[u8],
    pending: &mut Vec<ipc::Frame>,
) -> Result<WriteFate, Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + ipc::MAX_DATA_CHUNK_BYTES).min(bytes.len());
        let width = u64::try_from(end - offset).map_err(|_| {
            Error::Core(CoreError::new(
                ErrorCode::ELimit,
                "data chunk exceeds its bound",
            ))
        })?;
        if serving.credits.consume_outbound(stream_id, width).is_ok() {
            send_frame(
                serving.stream,
                kind,
                stream_id,
                &bytes[offset..end],
                serving.refs,
            )
            .await?;
            offset = end;
            continue;
        }
        match await_outbound_credit(serving, stream_id, pending).await? {
            CreditFate::Granted => {}
            CreditFate::Cancelled { close_connection } => {
                return Ok(WriteFate::Cancelled { close_connection });
            }
            CreditFate::Teardown => return Ok(WriteFate::Teardown),
        }
    }
    Ok(WriteFate::Done)
}

/// The end of one credit wait.
#[cfg(unix)]
enum CreditFate {
    /// A grant landed; retry the chunk.
    Granted,
    /// Cancellation arrived; only stream-zero closes the connection.
    Cancelled {
        /// True when stream zero carried the cancel.
        close_connection: bool,
    },
    /// The client tore the connection down.
    Teardown,
}

/// Reads frames until the client grants outbound credit for `stream_id`.
/// Late stdin endings are ignored; other streams buffer into `pending`.
#[cfg(unix)]
async fn await_outbound_credit(
    serving: &mut CommandServing<'_>,
    stream_id: u64,
    pending: &mut Vec<ipc::Frame>,
) -> Result<CreditFate, Error> {
    loop {
        let deadline = tokio::time::Instant::now() + serving.refs.frame_timeout;
        let frame = ipc::read_frame(serving.stream, deadline)
            .await
            .map_err(Error::Core)?;
        if frame.stream_id != stream_id && frame.stream_id != ipc::CONTROL_STREAM_ID {
            pending.push(frame);
            continue;
        }
        if frame.stream_id == ipc::CONTROL_STREAM_ID {
            match control_during_command(serving, &frame, deadline).await? {
                ControlFate::Continue => continue,
                ControlFate::Cancelled => {
                    return Ok(CreditFate::Cancelled {
                        close_connection: true,
                    });
                }
                ControlFate::Teardown => return Ok(CreditFate::Teardown),
            }
        }
        match frame.kind {
            ipc::FrameKind::WindowUpdate => {
                let credit: WindowCredit =
                    ipc::decode_control(&frame.payload).map_err(Error::Core)?;
                route_credit(serving.credits, stream_id, &credit).map_err(Error::Core)?;
                return Ok(CreditFate::Granted);
            }
            ipc::FrameKind::Cancel => {
                return Ok(CreditFate::Cancelled {
                    close_connection: false,
                });
            }
            ipc::FrameKind::Stdin | ipc::FrameKind::StdinEof => {}
            ipc::FrameKind::Open
            | ipc::FrameKind::Accepted
            | ipc::FrameKind::Stdout
            | ipc::FrameKind::Stderr
            | ipc::FrameKind::MergeNotices
            | ipc::FrameKind::Exit
            | ipc::FrameKind::Error => {
                return Err(Error::Core(CoreError::new(
                    ErrorCode::EInvalid,
                    "daemon never receives this frame kind from a client",
                )));
            }
        }
    }
}

#[cfg(unix)]
async fn open_inner(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    open: &InvocationOpen,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<(), ()> {
    let fail = async |stream: &mut tokio::net::UnixStream, err: Error, refs: &ConnectionRefs| {
        send_error_exit(stream, stream_id, &err, refs).await
    };
    let method = match Method::ALL.iter().find(|m| m.as_str() == open.method) {
        Some(method) => *method,
        None => {
            let _ = fail(
                stream,
                Error::Core(CoreError::new(
                    ErrorCode::EInvalid,
                    format!("unknown method `{}`", open.method),
                )),
                refs,
            )
            .await;
            return Err(());
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
            let _ = fail(stream, Error::Core(err), refs).await;
            return Err(());
        }
        Err(err) => {
            let _ = fail(stream, err, refs).await;
            return Err(());
        }
    };
    let (_cancel_guard, cancel) = cancellation();
    let principal = Principal::from_peer_uid(peer.uid);
    let accepted = InvocationAccepted {
        stream_id,
        method: method.as_str().to_string(),
        repo_handle: handle,
    };
    let accepted_bytes = match ipc::encode_control(&accepted) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = fail(stream, Error::Core(err), refs).await;
            return Err(());
        }
    };
    if send_frame(
        stream,
        ipc::FrameKind::Accepted,
        stream_id,
        &accepted_bytes,
        refs,
    )
    .await
    .is_err()
    {
        return Err(());
    }
    let session = match open.session_id.as_deref() {
        None => None,
        Some(text) => match text.parse::<SessionId>() {
            Ok(id) => Some(id),
            Err(err) => {
                let _ = fail(
                    stream,
                    Error::Core(CoreError::new(
                        ErrorCode::EInvalid,
                        format!("invocation carries a malformed session id: {err}"),
                    )),
                    refs,
                )
                .await;
                return Err(());
            }
        },
    };
    match dispatch_method(
        &coordinator,
        &principal,
        method,
        open.args_json.as_deref(),
        open.request_id.as_deref(),
        session,
        &cancel,
    )
    .await
    {
        Ok(stdout) => {
            if write_data_chunks(
                stream,
                stream_id,
                ipc::FrameKind::Stdout,
                &stdout,
                credits,
                refs,
            )
            .await
            .is_err()
            {
                return Err(());
            }
            let _ = send_exit(stream, stream_id, 0, "OK", "Completed", refs).await;
            Ok(())
        }
        Err(err) => {
            let _ = fail(stream, Error::Core(err), refs).await;
            Err(())
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
    method: Method,
    args_json: Option<&str>,
    request_id: Option<&str>,
    session: Option<SessionId>,
    cancel: &Cancel,
) -> Result<Vec<u8>, CoreError> {
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
                    let ready = coordinator.prepare_for_dispatch(session, request, &checkpoint)?;
                    match ready {
                        ruk_core::coord::DispatchReady::Replay(reply) => {
                            ipc::encode_control(&ReplyEnvelope::success(typed_id, reply))
                        }
                        ruk_core::coord::DispatchReady::Prepared(prepared) => {
                            let request_id = prepared.request_id;
                            let reply = coordinator
                                .submit_prepared(principal, prepared, cancel)
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

#[cfg(unix)]
async fn write_data_chunks(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    kind: ipc::FrameKind,
    bytes: &[u8],
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
) -> Result<(), Error> {
    if bytes.is_empty() {
        return Ok(());
    }
    for chunk in bytes.chunks(ipc::MAX_DATA_CHUNK_BYTES) {
        let width = u64::try_from(chunk.len()).map_err(|_| {
            Error::Core(CoreError::new(
                ErrorCode::ELimit,
                "data chunk exceeds its bound",
            ))
        })?;
        if let Err(err) = credits.consume_outbound(stream_id, width) {
            send_error_exit(stream, stream_id, &Error::Core(err), refs).await?;
            return Err(Error::Core(CoreError::new(
                ErrorCode::ELimit,
                "stream credit window is exhausted",
            )));
        }
        send_frame(stream, kind, stream_id, chunk, refs).await?;
    }
    Ok(())
}

#[cfg(unix)]
async fn send_frame(
    stream: &mut tokio::net::UnixStream,
    kind: ipc::FrameKind,
    stream_id: u64,
    payload: &[u8],
    refs: &ConnectionRefs,
) -> Result<(), Error> {
    let deadline = tokio::time::Instant::now() + refs.frame_timeout;
    ipc::write_frame(stream, kind, stream_id, payload, deadline)
        .await
        .map_err(Error::Core)
}

#[cfg(unix)]
async fn send_exit(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    status: i32,
    code: &str,
    outcome: &str,
    refs: &ConnectionRefs,
) -> Result<(), Error> {
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
    send_frame(stream, ipc::FrameKind::Exit, stream_id, &bytes, refs).await
}

#[cfg(unix)]
async fn send_error_exit(
    stream: &mut tokio::net::UnixStream,
    stream_id: u64,
    err: &Error,
    refs: &ConnectionRefs,
) -> Result<(), Error> {
    let (code, message) = match err {
        Error::Core(inner) => (inner.code.as_str().to_string(), inner.message.clone()),
        Error::Config(detail) | Error::Unsupported(detail) => {
            (ErrorCode::EInvalid.as_str().to_string(), detail.clone())
        }
        Error::Io(inner) => (ErrorCode::EIo.as_str().to_string(), inner.to_string()),
    };
    let status = if code == ErrorCode::ECancelled.as_str() {
        130
    } else {
        1
    };
    let report = ErrorReport { code, message };
    let bytes = ipc::encode_control(&report)?;
    send_frame(stream, ipc::FrameKind::Error, stream_id, &bytes, refs).await?;
    send_exit(
        stream,
        stream_id,
        status,
        &report.code,
        "CancelledBeforeCommit",
        refs,
    )
    .await
}
