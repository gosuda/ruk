//! Hosted multi-repository daemon behind `ruk forgejo serve`.
//!
//! One process owns every opened repository of a Forgejo instance. The
//! [`Registry`] authorizes each open by canonicalized path or opaque
//! handle, each repository serializes publication on its own lane, and one
//! shared [`BoundedExecutor`] runs blocking store work. The Unix-socket IPC
//! framing, credit windows, and handshake live in [`ipc`].
//!
//! Windows named-pipe transport is out of scope for this build: [`serve`]
//! reports it as [`Error::Unsupported`] instead of binding.

pub mod executor;
pub mod ipc;
pub mod registry;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use executor::BoundedExecutor;
pub use registry::Registry;
use ruk_core::change::{RequestId, SessionId};
use ruk_core::coord::{Cancel, HostedCoordinator, Principal, cancellation};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{
    AbandonArgs, AttestAddArgs, AttestListArgs, BlameArgs, BookmarkDeleteArgs, BookmarkResolveArgs,
    BookmarkSetArgs, ClaimAcquireArgs, ClaimListArgs, ClaimReleaseArgs, DescribeArgs, DiffArgs,
    EditArgs, FetchArgs, FileArgs, LandExecuteArgs, LandPrepareArgs, LogArgs, Method, Mutation,
    NewArgs, OpLogArgs, OpPruneArgs, PinArgs, PushArgs, PushReconcileArgs, QueryArgs, RebaseArgs,
    ReconnectSecret, Reply, ReplyEnvelope, Request, ResolveArgs, RevertArgs, SessionOpenArgs,
    SessionResumeArgs, ShowArgs, SnapshotArgs, SplitArgs, SquashArgs, StatusArgs, TagDeleteArgs,
    TagSetArgs, UndoArgs, UnpinArgs, WriteArgs, WsDropArgs, WsNewArgs, WsRecoverArgs, WsScopeArgs,
    WsTakeArgs, decode_json,
};

/// Default concurrent connections of one daemon process.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// Default blocking permits of the shared executor.
pub const DEFAULT_BLOCKING_POOL_SIZE: usize = 16;

/// Default handshake deadline in milliseconds.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;

/// Default per-frame deadline in milliseconds.
pub const DEFAULT_FRAME_TIMEOUT_MS: u64 = 60_000;

/// Configuration of one `ruk forgejo serve` process.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
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
}

impl DaemonConfig {
    /// Builds one configuration binding `socket_path` over `repo_roots`.
    pub fn new(socket_path: PathBuf, repo_roots: Vec<PathBuf>) -> Self {
        Self {
            socket_path,
            repo_roots,
            allowed_uids: Vec::new(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            blocking_pool_size: DEFAULT_BLOCKING_POOL_SIZE,
            handshake_timeout: Duration::from_millis(DEFAULT_HANDSHAKE_TIMEOUT_MS),
            frame_timeout: Duration::from_millis(DEFAULT_FRAME_TIMEOUT_MS),
            stream_window_bytes: ipc::INITIAL_STREAM_WINDOW_BYTES,
        }
    }

    /// Restricts Unix-socket peers to `uids`.
    #[must_use]
    pub fn with_allowed_uids(mut self, uids: Vec<u32>) -> Self {
        self.allowed_uids = uids;
        self
    }

    /// Sets the concurrent connection bound.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets the blocking permits of the shared executor.
    #[must_use]
    pub fn with_blocking_pool_size(mut self, pool_size: usize) -> Self {
        self.blocking_pool_size = pool_size;
        self
    }

    /// Sets the stream-zero handshake deadline.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the per-frame deadline after the handshake.
    #[must_use]
    pub fn with_frame_timeout(mut self, timeout: Duration) -> Self {
        self.frame_timeout = timeout;
        self
    }

    /// Sets the starting credit window of each stream direction.
    #[must_use]
    pub fn with_stream_window_bytes(mut self, bytes: u64) -> Self {
        self.stream_window_bytes = bytes;
        self
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Returns the configured repository roots.
    #[must_use]
    pub fn repo_roots(&self) -> &[PathBuf] {
        &self.repo_roots
    }

    /// Loads a TOML daemon configuration document.
    ///
    /// Keys: `socket_path`, `repo_roots` (required), `allowed_uids`,
    /// `max_connections`, `blocking_pool_size`, `handshake_timeout_ms`,
    /// `frame_timeout_ms`, `stream_window_bytes` (optional).
    ///
    /// # Errors
    /// `Error::Config` on malformed TOML, missing required keys, or bounds
    /// outside `validate`.
    pub fn from_toml(doc: &[u8]) -> Result<Self, Error> {
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
        cfg.validate()?;
        Ok(cfg)
    }

    /// Checks every bound the daemon depends on.
    ///
    /// # Errors
    /// `Config` for an empty socket path, root set, connection bound,
    /// blocking pool, deadline, or window.
    pub fn validate(&self) -> Result<(), Error> {
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
pub enum Error {
    /// The configuration is unusable.
    Config(String),
    /// Transport or runtime setup failed.
    Io(std::io::Error),
    /// A typed core failure ended the daemon or one handshake.
    Core(CoreError),
    /// The platform lacks the required transport.
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
pub struct InvocationOpen {
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
}

/// The `Accepted` payload answering one `Open`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationAccepted {
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
pub struct WindowCredit {
    /// The credit bytes granted to the frame's stream.
    #[serde(alias = "bytes")]
    pub credit_bytes: u64,
    /// The granted direction; empty means the input side.
    #[serde(default)]
    pub direction: String,
}

/// The `Exit` payload ending one invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitReport {
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
pub struct ErrorReport {
    /// The closed error-code spelling, never message text.
    pub code: String,
    /// The human diagnostic accompanying the code.
    pub message: String,
}

/// The `session.open` answer: the durable session identity plus the secret
/// resuming it, without invented authority.
///
/// `open_session` returns the session and its reconnect secret only. The
/// negotiated capabilities and the idle expiry live in coordinator policy
/// the daemon cannot read, so the daemon omits them instead of guessing.
/// `session.resume` reports the negotiated capabilities and authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOpened {
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
/// repository coordinator. Reads still need a session-bound read path the
/// coordinator does not expose, and mutations still need the per-method
/// preparation layer translating bare arguments into lane parts.
#[must_use]
pub fn coord_call_site(method: Method) -> &'static str {
    match method.kind() {
        ruk_core::protocol::MethodKind::Anonymous => "none: answer from ruk-core protocol data",
        ruk_core::protocol::MethodKind::Bootstrap => {
            "HostedCoordinator::open_session/resume_session"
        }
        ruk_core::protocol::MethodKind::Read => {
            "a session-bound read path: BoundSession plus admission, neither exposed on HostedCoordinator"
        }
        ruk_core::protocol::MethodKind::Mutation => {
            "a per-method preparation layer: prepared objects, exact-expectation facts, a precomputed typed reply, and ref transactions for lane publication"
        }
    }
}

/// Builds the `E_HOSTED` refusal for one session-bound method.
#[must_use]
pub fn method_error(method: Method, reason: &str) -> CoreError {
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
pub fn serve(config: DaemonConfig) -> Result<(), Error> {
    config.validate()?;
    #[cfg(not(unix))]
    return Err(Error::Unsupported(String::from(
        "ruk forgejo serve needs a Unix socket; the Windows named-pipe transport is not implemented",
    )));
    #[cfg(unix)]
    {
        let registry = Arc::new(Registry::new(config.repo_roots.clone())?);
        let executor = BoundedExecutor::new(config.blocking_pool_size)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .max_blocking_threads(config.blocking_pool_size * 2)
            .thread_name("ruk-forgejo-serve")
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
    if let Err(err) = std::fs::remove_file(&config.socket_path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(Error::Io(err));
        }
    }
    let listener = tokio::net::UnixListener::bind(&config.socket_path)?;
    let refs = ConnectionRefs {
        registry,
        executor,
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
            if handle_control_frame(&mut stream, &frame, &mut streams, frame_deadline).await? {
                return Ok(());
            }
            continue;
        }
        handle_stream_frame(&mut stream, frame, &mut streams, &mut credits, &refs, peer).await?;
    }
}

#[cfg(unix)]
async fn handle_control_frame(
    stream: &mut tokio::net::UnixStream,
    frame: &ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    deadline: tokio::time::Instant,
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
        ipc::FrameKind::Open
        | ipc::FrameKind::Accepted
        | ipc::FrameKind::Stdin
        | ipc::FrameKind::StdinEof
        | ipc::FrameKind::Stdout
        | ipc::FrameKind::Stderr
        | ipc::FrameKind::WindowUpdate
        | ipc::FrameKind::MergeNotices => {
            let report = ErrorReport {
                code: ErrorCode::EInvalid.as_str().to_string(),
                message: String::from("stream-zero carries only the handshake and global cancel"),
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

#[cfg(unix)]
async fn handle_stream_frame(
    stream: &mut tokio::net::UnixStream,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<(), Error> {
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
                return Ok(());
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
            Ok(())
        }
        ipc::FrameKind::StdinEof => Ok(()),
        ipc::FrameKind::WindowUpdate => {
            let credit: WindowCredit = ipc::decode_control(&frame.payload)?;
            let granted = if credit.direction.is_empty() || credit.direction == "stdin" {
                credits.grant_inbound(frame.stream_id, credit.credit_bytes)
            } else if credit.direction == "stdout" || credit.direction == "stderr" {
                credits.grant_outbound(frame.stream_id, credit.credit_bytes)
            } else {
                send_error_exit(
                    stream,
                    frame.stream_id,
                    &Error::Core(CoreError::new(
                        ErrorCode::EInvalid,
                        "credit update names an unknown direction",
                    )),
                    refs,
                )
                .await?;
                return Ok(());
            };
            if granted.is_err() {
                send_error_exit(
                    stream,
                    frame.stream_id,
                    &Error::Core(CoreError::new(
                        ErrorCode::EInvalid,
                        "credit update names an unknown stream",
                    )),
                    refs,
                )
                .await?;
            }
            Ok(())
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
            .await
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
            .await
        }
    }
}

#[cfg(unix)]
async fn handle_open(
    stream: &mut tokio::net::UnixStream,
    frame: ipc::Frame,
    streams: &mut HashMap<u64, StreamState>,
    credits: &mut ipc::StreamCredits,
    refs: &ConnectionRefs,
    peer: ipc::PeerIdentity,
) -> Result<(), Error> {
    let stream_id = frame.stream_id;
    let open: InvocationOpen = match ipc::decode_control(&frame.payload) {
        Ok(open) => open,
        Err(err) => {
            send_error_exit(stream, stream_id, &Error::Core(err), refs).await?;
            return Ok(());
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
    Ok(())
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
    match dispatch_method(
        &coordinator,
        &principal,
        method,
        open.args_json.as_deref(),
        open.request_id.as_deref(),
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
/// `session.resume` answers the full negotiated reply. Reads and mutations
/// decode and validate, then refuse: the frame carries no session, and no
/// read or preparation path exists yet.
///
/// # Errors
/// `E_INVALID` for an unknown shape or a session-bound method without a
/// session, `E_HOSTED` where no read or preparation path exists, plus the
/// coordinator's own typed failures.
pub async fn dispatch_method(
    coordinator: &Arc<HostedCoordinator>,
    principal: &Principal,
    method: Method,
    args_json: Option<&str>,
    request_id: Option<&str>,
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
            Err(refuse_sessionless(method, None))
        }
    }
}

/// Builds the refusal for one read or mutation arriving without a session.
///
/// The invocation frame carries no session today, so the first arm always
/// fires. The second arm stays for the day the frame gains one: even with
/// a session, reads lack a coordinator read path and mutations lack their
/// per-method preparation, so both refuse through [`method_error`].
fn refuse_sessionless(method: Method, session: Option<SessionId>) -> CoreError {
    match session {
        None => CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `{}` requires a session and the invocation carries none",
                method.as_str()
            ),
        ),
        Some(_) => method_error(
            method,
            match method.kind() {
                ruk_core::protocol::MethodKind::Read => {
                    "no read path exists on the coordinator: reads need BoundSession plus admission, both crate-private to ruk-core"
                }
                _ => {
                    "no per-method preparation layer exists: bare arguments cannot supply prepared objects, exact-expectation facts, a precomputed typed reply, ref transactions, or workspace fences"
                }
            },
        ),
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
/// from the invocation frame. The result validates shape only: reads still
/// lack a coordinator read path and mutations still lack prepared lane
/// parts, so callers refuse afterwards.
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
