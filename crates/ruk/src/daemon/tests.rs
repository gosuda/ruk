//! Git-service and typed-invocation tests driving the daemon wire.
//!
//! The tests speak the daemon's field names over a socket pair
//! (`protocol_major` without `protocol_minor`, git-service envelope opens,
//! typed invocation opens) so a field rename or shape drift fails here
//! instead of against a live peer.

#![cfg(unix)]

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::ipc::{self, CONTROL_STREAM_ID, FrameKind, INITIAL_STREAM_WINDOW_BYTES};
use super::{
    BoundedExecutor, CommandAccepted, CommandExitReport, CommandOpen, ConnectionRefs, ExitReport,
    GitLimits, InvocationAccepted, InvocationOpen, Registry, SessionOpened, TransportAuth,
    serve_connection,
};
use super::{
    DEFAULT_ARCHIVE_MAX_BYTES, DEFAULT_COMPARE_MAX_COMMITS, DEFAULT_DEFAULT_BRANCH,
    DEFAULT_HOOK_MAX_COMMANDS, DEFAULT_HOOK_TIMEOUT_MS, DEFAULT_RETENTION_INTERVAL_MS,
    DEFAULT_SEARCH_MAX_SCAN_BYTES, DEFAULT_SEARCH_POOL_SIZE, DEFAULT_TRANSPORT_PERMITS,
    DaemonConfig,
};
use ruk_core::bytes::ByteString;
use ruk_core::change::{LeaseId, OperationId, PlanId, RequestId, SessionId, StoreId};
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::heads::Head;
use ruk_core::ids::Oid;
use ruk_core::index::RepoPath;
use ruk_core::ops::{NewRequest, prepare_new};
use ruk_core::protocol::{
    BookmarkSetArgs, BookmarkTarget, BoundedList, ChangeRef, ClaimAcquireArgs, ClaimMode,
    ClaimReleaseArgs, ClaimTtl, DescribeArgs, EditArgs, ErrorDetail, ErrorReply, FetchArgs,
    FetchFilter, FetchRefs, Fix, IdentityClaim, LandExecuteArgs, Method, Mutation, NewArgs,
    OpLogArgs, PageCursor, PageLimit, PageRequest, PathSelection, PinArgs, PushRefOutcome,
    PushRefStatus, PushState, QueryDigest, RemoteName, RemoteSpec, Reply, ReplyBody, ReplyEnvelope,
    Request, SessionOpenArgs, SnapshotArgs, SplitArgs, SplitPlacement, StatusArgs, TagAnnotation,
    TagSetArgs, UndoArgs, WorkspaceBinding, WorkspaceInit, WsNewArgs,
};
use ruk_core::refdata::{RefExpect, RefName, RefRead, RefTarget};
use ruk_core::store::{EventContext, EventSource, FactTable, ObjectKind, PreparationBudget, Store};
use ruk_core::store::{FactPageBudget, types::decode_store_event};
use ruk_git::transport::host::{HookCall, HookPhase, HookRefVerdict, HookReply, HookVerdict};
use ruk_git::transport::serve::ReceiveLimits;
use ruk_git::transport::{Interrupt, pack as git_pack};

/// Hands out unique temp directory names across parallel tests.
static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

/// Mints one stored commit directly in the repository store and closes the
/// handle before the daemon opens it, so dispatch-time reads see committed
/// state with only one live handle at a time.
fn seed_commit(repo_dir: &Path) -> Oid {
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store = Store::open(&repo_dir.join(".ruk"), budget).expect("open store");
    let tree = store
        .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
        .expect("prepare empty tree");
    let tree_oid = tree.oid();
    store
        .publish(
            vec![tree],
            &[],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish empty tree");
    let signature = Signature {
        name: ByteString::from("Tag"),
        email: ByteString::from("tag@example.invalid"),
        timestamp: 1_700_000_000,
        offset: TzOffset::UTC,
    };
    let prepared = prepare_new(
        &store,
        NewRequest {
            tree: tree_oid,
            parents: Vec::new(),
            author: signature.clone(),
            committer: signature,
            message: ByteString::from("seed"),
            change_id: None,
            predecessor: None,
            provenance: None,
        },
    )
    .expect("prepare seed commit");
    let oid = prepared.output.oid.expect("seed commit is a Git commit");
    store
        .publish(
            prepared.objects,
            &prepared.facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish seed commit");
    oid
}

/// Creates an empty temp directory for one test.
fn temp_root(case: &str) -> PathBuf {
    let id = NEXT_CASE.fetch_add(1, Ordering::SeqCst);
    let base =
        std::env::temp_dir().join(format!("ruk-daemon-{}-{}-{}", std::process::id(), id, case));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp root");
    base
}

/// Bounds every test frame read.
fn frame_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(15)
}

/// Builds one git-service envelope open document.
fn git_open_payload(
    service: &str,
    repository: &str,
    advertise: bool,
    session_id: Option<&str>,
    request_id: Option<&str>,
) -> Vec<u8> {
    git_open_payload_full(
        service, repository, advertise, session_id, request_id, "", None,
    )
}

/// Builds one git-service envelope open document with an explicit protocol
/// and provenance.
fn git_open_payload_full(
    service: &str,
    repository: &str,
    advertise: bool,
    session_id: Option<&str>,
    request_id: Option<&str>,
    git_protocol: &str,
    on_behalf_of: Option<&str>,
) -> Vec<u8> {
    let open = CommandOpen {
        service: service.to_string(),
        repository: repository.to_string(),
        session_id: session_id.map(str::to_string),
        request_id: request_id.map(str::to_string),
        git_protocol: git_protocol.to_string(),
        advertise,
        stdout_credit: 262_144,
        limits: GitLimits::default(),
        on_behalf_of: on_behalf_of.map(str::to_string),
    };
    sonic_rs::to_string(&open)
        .expect("git-service open encodes")
        .into_bytes()
}

/// Encodes one pkt-line data frame.
fn pkt(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Encodes one pkt-line flush.
fn flush() -> Vec<u8> {
    b"0000".to_vec()
}

/// Creates a store under the repository the way `init` does, so tests
/// seed without the deleted argv path.
fn seed_store(repo: &str) {
    let budget = Arc::new(PreparationBudget::reference_defaults());
    Store::create(
        &Path::new(repo).join(".ruk"),
        ruk_core::ids::HashKind::Sha1,
        budget,
    )
    .expect("create store");
}

/// Points `name` at `oid` in the store under `repo_dir`.
fn seed_ref(repo_dir: &Path, name: &str, oid: Oid) {
    use ruk_core::refdata::{RefChange, RefExpect, RefTarget, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store = Store::open(&repo_dir.join(".ruk"), budget).expect("open store");
    let update = RefUpdate {
        name: RefName::new(name.to_string()).expect("ref name"),
        expected: RefExpect::Absent,
        change: RefChange::Set(RefTarget::Direct(oid)),
    };
    let transaction =
        RefTransaction::new(store.hash_kind(), vec![update]).expect("ref transaction");
    let prepared = prepare_checked_transaction(&store, &transaction).expect("prepare ref");
    store
        .publish(
            Vec::new(),
            &prepared.into_mutations(),
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish ref");
}

/// One test driver end of a socket pair.
struct Driver {
    /// The client half; the daemon owns the other end.
    conn: tokio::net::UnixStream,
}

impl Driver {
    /// Sends one frame.
    async fn send(&mut self, kind: FrameKind, stream_id: u64, payload: &[u8]) {
        ipc::write_frame(&mut self.conn, kind, stream_id, payload, frame_deadline())
            .await
            .expect("send frame");
    }

    /// Reads one frame.
    async fn recv(&mut self) -> ipc::Frame {
        ipc::read_frame(&mut self.conn, frame_deadline())
            .await
            .expect("recv frame")
    }

    /// Reads data frames until the command `Exit` of `stream_id`.
    async fn recv_exit(&mut self, stream_id: u64) -> (Vec<u8>, Vec<u8>, CommandExitReport) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let frame = self.recv().await;
            assert_eq!(
                frame.stream_id, stream_id,
                "unexpected stream {}",
                frame.stream_id
            );
            match frame.kind {
                FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
                FrameKind::Stderr => stderr.extend_from_slice(&frame.payload),
                FrameKind::Exit => {
                    let report: CommandExitReport =
                        ipc::decode_control(&frame.payload).expect("exit decodes");
                    return (stdout, stderr, report);
                }
                FrameKind::Error => panic!(
                    "stream {stream_id} refused: {}",
                    String::from_utf8_lossy(&frame.payload)
                ),
                other => panic!("unexpected frame {other:?} on stream {stream_id}"),
            }
        }
    }

    /// Runs one git-service open to its terminal report: `Accepted`, the
    /// request body in one or more `Stdin` frames plus `StdinEof` (or
    /// nothing for `advertise` opens), then `Stdout` until `Exit`.
    async fn run_git(
        &mut self,
        stream_id: u64,
        payload: &[u8],
        body: &[Vec<u8>],
    ) -> (Vec<u8>, CommandExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let accepted = self.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        assert_eq!(accepted.stream_id, stream_id);
        let reply: CommandAccepted =
            ipc::decode_control(&accepted.payload).expect("accepted decodes");
        assert_eq!(reply.stream_id, stream_id);
        assert!(reply.stdin_credit > 0, "daemon grants stdin credit");
        for chunk in body {
            self.send(FrameKind::Stdin, stream_id, chunk).await;
        }
        if !body.is_empty() {
            for _ in 0..body.len() {
                let grant = self.recv().await;
                assert_eq!(grant.kind, FrameKind::WindowUpdate);
                assert_eq!(grant.stream_id, stream_id);
            }
            self.send(FrameKind::StdinEof, stream_id, &[]).await;
        }
        let (stdout, _, exit) = self.recv_exit(stream_id).await;
        (stdout, exit)
    }

    /// Sends one raw frame with an explicit kind byte, for retired kinds
    /// no enum variant names.
    async fn send_raw(&mut self, kind: u8, stream_id: u64, payload: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let total = u32::try_from(ipc::FRAME_HEADER_BYTES + payload.len()).expect("frame fits");
        let mut bytes = total.to_be_bytes().to_vec();
        bytes.push(kind);
        bytes.extend_from_slice(&stream_id.to_be_bytes());
        bytes.extend_from_slice(payload);
        self.conn.write_all(&bytes).await.expect("send raw frame");
    }

    /// Reads one frame, returning stream errors to the caller.
    async fn try_recv(&mut self) -> Result<ipc::Frame, CoreError> {
        ipc::read_frame(&mut self.conn, frame_deadline()).await
    }

    /// Runs one hosted receive-pack open to its terminal report,
    /// answering every hook callback with `answer` (`None` skips the
    /// reply, for timeout paths): `Accepted`, the request body, one
    /// `HookCall` per callback round, then `Stdout` until `Exit`.
    async fn run_git_hosted(
        &mut self,
        stream_id: u64,
        payload: &[u8],
        body: &[Vec<u8>],
        answer: impl Fn(&HookCall) -> Option<HookReply>,
    ) -> (Vec<u8>, CommandExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let accepted = self.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        assert_eq!(accepted.stream_id, stream_id);
        for chunk in body {
            self.send(FrameKind::Stdin, stream_id, chunk).await;
        }
        if !body.is_empty() {
            for _ in 0..body.len() {
                let grant = self.recv().await;
                assert_eq!(grant.kind, FrameKind::WindowUpdate);
                assert_eq!(grant.stream_id, stream_id);
            }
            self.send(FrameKind::StdinEof, stream_id, &[]).await;
        }
        let mut stdout = Vec::new();
        loop {
            let frame = self.recv().await;
            assert_eq!(
                frame.stream_id, stream_id,
                "unexpected stream {}",
                frame.stream_id
            );
            match frame.kind {
                FrameKind::HookCall => {
                    let call: HookCall =
                        ipc::decode_control(&frame.payload).expect("hook call decodes");
                    if let Some(reply) = answer(&call) {
                        let bytes = ipc::encode_control(&reply).expect("hook reply encodes");
                        self.send(FrameKind::HookReply, stream_id, &bytes).await;
                    }
                }
                FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
                FrameKind::Exit => {
                    let report: CommandExitReport =
                        ipc::decode_control(&frame.payload).expect("exit decodes");
                    return (stdout, report);
                }
                FrameKind::Error => panic!(
                    "stream {stream_id} refused: {}",
                    String::from_utf8_lossy(&frame.payload)
                ),
                other => panic!("unexpected frame {other:?} on stream {stream_id}"),
            }
        }
    }

    /// Opens one git-service stream expecting refusal: an `Error` then a
    /// nonzero `Exit`.
    async fn expect_git_refused(
        &mut self,
        stream_id: u64,
        payload: &[u8],
    ) -> (ErrorReply, ExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let err_frame = self.recv().await;
        assert_eq!(err_frame.kind, FrameKind::Error);
        assert_eq!(err_frame.stream_id, stream_id);
        let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
        let exit_frame = self.recv().await;
        assert_eq!(exit_frame.kind, FrameKind::Exit);
        assert_eq!(exit_frame.stream_id, stream_id);
        let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
        assert_eq!(exit.status, 1);
        assert_eq!(exit.outcome, "Failed");
        (report, exit)
    }

    /// Builds one typed invocation open document.
    fn typed_open(
        repo: &str,
        method: &str,
        request_id: Option<&str>,
        args_json: Option<String>,
        session_id: Option<&str>,
    ) -> Vec<u8> {
        Self::typed_open_obo(repo, method, request_id, args_json, session_id, None)
    }

    /// Builds one typed invocation open document with provenance.
    fn typed_open_obo(
        repo: &str,
        method: &str,
        request_id: Option<&str>,
        args_json: Option<String>,
        session_id: Option<&str>,
        on_behalf_of: Option<&str>,
    ) -> Vec<u8> {
        let open = InvocationOpen {
            repo: repo.to_string(),
            method: method.to_string(),
            request_id: request_id.map(str::to_string),
            args_json,
            session_id: session_id.map(str::to_string),
            on_behalf_of: on_behalf_of.map(str::to_string),
            transport_auth: TransportAuth::default(),
        };
        sonic_rs::to_string(&open)
            .expect("typed open encodes")
            .into_bytes()
    }

    /// Runs one typed invocation to its terminal `Exit`, returning stdout.
    async fn run_typed(&mut self, stream_id: u64, payload: &[u8]) -> (Vec<u8>, ExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let accepted = self.recv().await;
        assert_eq!(
            accepted.kind,
            FrameKind::Accepted,
            "typed open refused: {}",
            String::from_utf8_lossy(&accepted.payload)
        );
        let reply: InvocationAccepted =
            ipc::decode_control(&accepted.payload).expect("typed accepted decodes");
        assert_eq!(reply.stream_id, stream_id);
        let mut stdout = Vec::new();
        loop {
            let frame = self.recv().await;
            assert_eq!(frame.stream_id, stream_id);
            match frame.kind {
                FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
                FrameKind::Exit => {
                    let exit: ExitReport =
                        ipc::decode_control(&frame.payload).expect("typed exit decodes");
                    assert_eq!(exit.status, 0);
                    assert_eq!(exit.code, "OK");
                    return (stdout, exit);
                }
                FrameKind::Error => panic!(
                    "typed stream {stream_id} refused: {}",
                    String::from_utf8_lossy(&frame.payload)
                ),
                other => panic!("unexpected frame {other:?} on typed stream {stream_id}"),
            }
        }
    }

    /// Runs one typed invocation expecting refusal: an `Error` then a
    /// nonzero `Exit`.
    async fn expect_typed_refused(
        &mut self,
        stream_id: u64,
        payload: &[u8],
    ) -> (ErrorReply, ExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let accepted = self.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        let err_frame = self.recv().await;
        assert_eq!(err_frame.kind, FrameKind::Error);
        assert_eq!(err_frame.stream_id, stream_id);
        let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
        let exit_frame = self.recv().await;
        assert_eq!(exit_frame.kind, FrameKind::Exit);
        assert_eq!(exit_frame.stream_id, stream_id);
        let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
        assert_eq!(exit.status, 1);
        assert_eq!(exit.outcome, "Failed");
        (report, exit)
    }
}

/// Completes the stream-zero handshake: no `protocol_minor` field, so the
/// daemon sees zero (unknown) and still negotiates.
async fn handshake(driver: &mut Driver) {
    let hello = r#"{"protocol_major":1,"profile":"host","object_formats":["sha1"],"features":["credits","hooks.v1","events.v1","archive.v1"]}"#;
    driver
        .send(FrameKind::Open, CONTROL_STREAM_ID, hello.as_bytes())
        .await;
    let reply = driver.recv().await;
    assert_eq!(reply.kind, FrameKind::Accepted);
    assert_eq!(reply.stream_id, CONTROL_STREAM_ID);
    let accept: ipc::HandshakeAccept =
        ipc::decode_control(&reply.payload).expect("handshake decodes");
    assert_eq!(accept.protocol_major, 1);
    assert_eq!(accept.profile, "host");
    assert_eq!(
        accept.features,
        ["credits", "hooks.v1", "events.v1", "archive.v1"].map(String::from)
    );
}

/// Spawns `serve_connection` on a socket pair, returning the driver end.
fn spawn_pair(root: &Path) -> (Driver, tokio::task::JoinHandle<Result<(), super::Error>>) {
    spawn_pair_with_window(root, INITIAL_STREAM_WINDOW_BYTES)
}

/// Spawns a daemon pair keeping its registry, so hosted tests can tune
/// the hook deadline and read the store through the live coordinator.
fn spawn_hosted(
    root: &Path,
    hook_timeout_ms: u64,
) -> (
    Driver,
    Arc<Registry>,
    tokio::task::JoinHandle<Result<(), super::Error>>,
) {
    let registry = Arc::new(Registry::new(vec![root.to_path_buf()]).expect("registry"));
    registry.set_runtime(tokio::runtime::Handle::current());
    registry.set_hook_timeout(Duration::from_millis(hook_timeout_ms));
    let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
    let uid = client.peer_cred().expect("socket pair credentials").uid();
    let refs = ConnectionRefs {
        registry: Arc::clone(&registry),
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport executor"),
        window_bytes: INITIAL_STREAM_WINDOW_BYTES,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: vec![uid],
        admin_uids: Vec::new(),
    };
    let task = tokio::spawn(async move { serve_connection(server, refs).await });
    (Driver { conn: client }, registry, task)
}

/// Answers one hook callback by accepting every command.
fn accept_all(call: &HookCall) -> Option<HookReply> {
    Some(HookReply {
        reject_all: false,
        reason: None,
        verdicts: call
            .commands
            .iter()
            .map(|command| HookRefVerdict {
                name: command.name.clone(),
                verdict: HookVerdict::Accept,
            })
            .collect(),
    })
}

/// Opens one session carrying exactly these `push_refs` patterns.
async fn open_push_session(driver: &mut Driver, store_repo: &str, patterns: &[&str]) -> String {
    let mut list = String::from("[");
    for (index, pattern) in patterns.iter().enumerate() {
        if index > 0 {
            list.push(',');
        }
        list.push('"');
        list.push_str(pattern);
        list.push('"');
    }
    list.push(']');
    let args_json = format!(r#"{{"claims": {{}}, "capabilities": {{"push_refs": {list}}}}}"#);
    let payload = Driver::typed_open(
        store_repo,
        "session.open",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    opened.session.to_string()
}

/// Spawns `serve_connection` on a socket pair with one stream window size,
/// so credit tests can force the daemon to wait for grants.
fn spawn_pair_with_window(
    root: &Path,
    window_bytes: u64,
) -> (Driver, tokio::task::JoinHandle<Result<(), super::Error>>) {
    let registry = Arc::new(Registry::new(vec![root.to_path_buf()]).expect("registry"));
    registry.set_runtime(tokio::runtime::Handle::current());
    let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
    // The pair's peer is this process, so its uid is the uid the daemon
    // observes for the driver end.
    let uid = client.peer_cred().expect("socket pair credentials").uid();
    let refs = ConnectionRefs {
        registry,
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport executor"),
        window_bytes,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: vec![uid],
        admin_uids: Vec::new(),
    };
    let task = tokio::spawn(async move { serve_connection(server, refs).await });
    (Driver { conn: client }, task)
}

#[test]
fn retention_interval_defaults_to_sixty_seconds_and_parses() {
    let cfg = DaemonConfig::new(
        PathBuf::from("/tmp/ruk-retention.sock"),
        vec![PathBuf::from("/tmp")],
    );
    assert_eq!(
        cfg.retention_interval(),
        Duration::from_millis(DEFAULT_RETENTION_INTERVAL_MS)
    );
    assert_eq!(cfg.retention_interval(), Duration::from_secs(60));

    let doc = b"socket_path = \"/tmp/ruk-retention.sock\"\nrepo_roots = [\"/tmp\"]\nallowed_uids = [1000]\nretention_interval_ms = 5000\n";
    let parsed = DaemonConfig::from_toml(doc).expect("retention interval parses");
    assert_eq!(parsed.retention_interval(), Duration::from_millis(5_000));

    let disabled =
        b"socket_path = \"/tmp/ruk-retention.sock\"\nrepo_roots = [\"/tmp\"]\nallowed_uids = [1000]\nretention_interval_ms = 0\n";
    let parsed = DaemonConfig::from_toml(disabled).expect("zero disables sweeps");
    assert!(parsed.retention_interval().is_zero());
}

/// Renders one TOML document binding the scratch socket over `/tmp` plus `extra` keys.
fn config_doc(extra: &str) -> Vec<u8> {
    format!("socket_path = \"/tmp/ruk-r02.sock\"\nrepo_roots = [\"/tmp\"]\nallowed_uids = [1000]\n{extra}")
        .into_bytes()
}

#[test]
fn unknown_config_key_fails_from_toml() {
    let err = DaemonConfig::from_toml(&config_doc("no_such_key = 1\n"))
        .expect_err("unknown key must fail");
    assert!(
        matches!(err, super::Error::Config(_)),
        "unknown key must be a config error: {err}"
    );
}

#[test]
fn invalid_new_config_values_name_the_key() {
    let cases = [
        ("transport_permits", "transport_permits = 0\n"),
        ("hook_timeout_ms", "hook_timeout_ms = 0\n"),
        ("hook_max_commands", "hook_max_commands = 0\n"),
        ("hook_max_commands", "hook_max_commands = 4097\n"),
        ("default_branch", "default_branch = \"main\"\n"),
        ("event_retention_seconds", "event_retention_seconds = 0\n"),
        ("search_pool_size", "search_pool_size = 0\n"),
    ];
    for (key, extra) in cases {
        let err =
            DaemonConfig::from_toml(&config_doc(extra)).expect_err("{key} must fail validation");
        assert!(
            matches!(err, super::Error::Config(_)),
            "{key} must be a config error: {err}"
        );
        assert!(
            err.to_string().contains(key),
            "error for {key} must name it: {err}"
        );
    }
    DaemonConfig::from_toml(&config_doc("search_pool_size = 1\n"))
        .expect("one search permit starts");
}

#[test]
fn hook_max_commands_accepts_only_1_through_4096() {
    for valid in ["hook_max_commands = 1\n", "hook_max_commands = 4096\n"] {
        DaemonConfig::from_toml(&config_doc(valid)).expect("boundary must parse");
    }
}

#[test]
fn envelope_limits_convert_to_receive_bounds() {
    assert_eq!(
        GitLimits::default().receive_limits(),
        ReceiveLimits::default()
    );
    let saturated = GitLimits {
        max_pack_bytes: u64::MAX,
        max_objects: u64::MAX,
        max_object_bytes: u64::MAX,
        max_delta_depth: u64::MAX,
        max_stdin_bytes: u64::MAX,
        max_push_options: u64::MAX,
    }
    .receive_limits();
    assert_eq!(saturated.ingest.max_pack_bytes, u64::MAX);
    assert_eq!(saturated.ingest.max_objects, u64::MAX);
    assert_eq!(saturated.ingest.max_object_bytes, u64::MAX);
    assert_eq!(saturated.ingest.max_delta_depth, u64::MAX);
    assert_eq!(saturated.max_push_options, u64::MAX);
}

#[test]
fn empty_allowed_uids_refuses_start() {
    let empty = DaemonConfig::new(
        PathBuf::from("/tmp/ruk-r03.sock"),
        vec![PathBuf::from("/tmp")],
    );
    let err = empty
        .validate()
        .expect_err("empty allowed_uids must refuse startup");
    assert!(
        matches!(err, super::Error::Config(_)),
        "empty allowed_uids must be a config error: {err}"
    );
    assert!(
        err.to_string().contains("allowed_uids"),
        "refusal must name allowed_uids: {err}"
    );
    let one = DaemonConfig::new(
        PathBuf::from("/tmp/ruk-r03.sock"),
        vec![PathBuf::from("/tmp")],
    )
    .with_allowed_uids(vec![1000]);
    one.validate().expect("one listed uid starts");
}

#[test]
fn minimal_config_document_yields_new_defaults() {
    let cfg = DaemonConfig::from_toml(&config_doc("")).expect("minimal doc parses");
    assert!(cfg.admin_uids().is_empty());
    assert_eq!(cfg.transport_permits, DEFAULT_TRANSPORT_PERMITS);
    assert_eq!(
        cfg.hook_timeout,
        Duration::from_millis(DEFAULT_HOOK_TIMEOUT_MS)
    );
    assert_eq!(cfg.hook_max_commands, DEFAULT_HOOK_MAX_COMMANDS);
    assert_eq!(cfg.default_branch, DEFAULT_DEFAULT_BRANCH);
    assert_eq!(
        cfg.event_retention_seconds,
        ruk_core::coord::DEFAULT_EVENT_RETENTION_SECONDS
    );
    assert_eq!(cfg.archive_max_bytes(), DEFAULT_ARCHIVE_MAX_BYTES);
    assert_eq!(cfg.compare_max_commits(), DEFAULT_COMPARE_MAX_COMMITS);
    assert_eq!(cfg.search_max_scan_bytes(), DEFAULT_SEARCH_MAX_SCAN_BYTES);
    assert_eq!(cfg.search_pool_size(), DEFAULT_SEARCH_POOL_SIZE);
    cfg.validate().expect("defaults validate");
}

#[test]
fn explicit_new_config_values_parse() {
    let extra = "admin_uids = [1000, 1001]\ntransport_permits = 4\nhook_timeout_ms = 2500\nhook_max_commands = 64\ndefault_branch = \"refs/heads/develop\"\nevent_retention_seconds = 3600\narchive_max_bytes = 1024\ncompare_max_commits = 512\nsearch_max_scan_bytes = 2048\nsearch_pool_size = 2\n";
    let cfg = DaemonConfig::from_toml(&config_doc(extra)).expect("explicit values parse");
    assert_eq!(cfg.admin_uids(), &[1000, 1001]);
    assert_eq!(cfg.transport_permits, 4);
    assert_eq!(cfg.hook_timeout, Duration::from_millis(2_500));
    assert_eq!(cfg.hook_max_commands, 64);
    assert_eq!(cfg.default_branch, "refs/heads/develop");
    assert_eq!(cfg.event_retention_seconds, 3_600);
    assert_eq!(cfg.archive_max_bytes(), 1_024);
    assert_eq!(cfg.compare_max_commits(), 512);
    assert_eq!(cfg.search_max_scan_bytes(), 2_048);
    assert_eq!(cfg.search_pool_size(), 2);
}

#[test]
fn handshake_hello_without_minor_decodes() {
    let raw = br#"{"protocol_major":1,"profile":"host","object_formats":["sha1"],"features":[]}"#;
    let hello: ipc::HandshakeHello = ipc::decode_control(raw).expect("decodes");
    assert_eq!(hello.protocol_minor, 0);
    let accept = ipc::negotiate(&hello).expect("negotiates");
    assert_eq!(accept.protocol_major, 1);
}

#[tokio::test]
async fn git_service_advertise_matches_oracle_refs() {
    let root = temp_root("advertise");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let oracle = {
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::open(&repo_dir.join(".ruk"), budget).expect("open store");
        ruk_core::refs::StoreRefs::new(&store)
            .get(&RefName::new("refs/heads/main".to_string()).expect("ref name"))
            .expect("oracle reads the ref")
            .expect("ref exists")
    };
    assert_eq!(oracle, ruk_core::refdata::RefTarget::Direct(commit));

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    for service in ["upload-pack", "receive-pack"] {
        let ids = service == "receive-pack";
        let payload = git_open_payload(
            service,
            &store_repo,
            true,
            ids.then_some("sess-adv"),
            ids.then_some("req-adv"),
        );
        let stream_id = if service == "upload-pack" { 1 } else { 3 };
        let (stdout, exit) = driver.run_git(stream_id, &payload, &[]).await;
        assert_eq!(exit.exit_code, 0, "{service} advertise exits zero");
        assert_eq!(exit.outcome, "Completed");

        let refs = parse_advertised_refs(&stdout, service);
        assert_eq!(
            refs.len(),
            1,
            "{service} advertises exactly the seeded ref: {refs:?}"
        );
        assert_eq!(refs[0].0, "refs/heads/main");
        assert_eq!(
            refs[0].1, commit,
            "{service} advertisement names the oracle oid"
        );
    }

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_request_matches_oracle_objects() {
    let root = temp_root("request");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let mut request = pkt(format!("want {}\n", commit.to_hex()).as_bytes());
    request.extend_from_slice(&flush());
    request.extend_from_slice(&pkt(b"done\n"));

    let expected = {
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::open(&repo_dir.join(".ruk"), budget).expect("open store");
        let kind = store.hash_kind();
        let head = crate::cli::verbs_transport::serve_head(&store).expect("serve head");
        let mut oracle = Vec::new();
        ruk_git::transport::serve::serve_upload_pack(
            &request[..],
            &mut oracle,
            &store,
            kind,
            &head,
            &ruk_git::transport::Interrupt::none(),
        )
        .expect("oracle serves the same request");
        let split = find_flush(&oracle).expect("oracle output carries its advertisement");
        oracle[split..].to_vec()
    };

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = git_open_payload("upload-pack", &store_repo, false, None, None);
    let (stdout, exit) = driver.run_git(1, &payload, &[request]).await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.outcome, "Completed");
    assert!(
        stdout.starts_with(b"PACK"),
        "stateless responses carry no advertisement prefix"
    );
    assert_eq!(
        stdout, expected,
        "the daemon answers exactly the serve half past the advertisement"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_unknown_service_refused() {
    let root = temp_root("unknown-service");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = git_open_payload("piano", &store_repo, false, None, None);
    let (report, exit) = driver.expect_git_refused(1, &payload).await;
    assert_eq!(report.code, ErrorCode::EInvalid);
    assert!(report.message.contains("piano"));
    assert_eq!(exit.status, 1);

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_receive_pack_needs_session_and_request() {
    let root = temp_root("receive-ids");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = git_open_payload("receive-pack", &store_repo, false, None, Some("req-1"));
    let (report, _) = driver.expect_git_refused(1, &payload).await;
    assert_eq!(report.code, ErrorCode::EInvalid);

    let payload = git_open_payload("receive-pack", &store_repo, false, Some("sess-1"), None);
    let (report, _) = driver.expect_git_refused(3, &payload).await;
    assert_eq!(report.code, ErrorCode::EInvalid);

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_delete_only_receive_pack_round_trip() {
    let root = temp_root("receive-delete");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(1, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut request = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    request.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-del-1"),
    );
    let (stdout, exit) = driver
        .run_git_hosted(3, &payload, &[request], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.invocation_id, "req-del-1");
    let text = String::from_utf8(stdout).expect("report is text");
    assert!(text.contains("unpack ok"), "report lands: {text}");

    let advert = git_open_payload("upload-pack", &store_repo, true, None, None);
    let (stdout, exit) = driver.run_git(5, &advert, &[]).await;
    assert_eq!(exit.exit_code, 0);
    let refs = parse_advertised_refs(&stdout, "upload-pack");
    assert!(
        !refs.iter().any(|row| row.0 == "refs/heads/scratch"),
        "the delete landed: {refs:?}"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_streams_progress_while_sibling_waits() {
    let root = temp_root("git-concurrent");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = git_open_payload("upload-pack", &store_repo, false, None, None);
    driver.send(FrameKind::Open, 1, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);

    let advert = git_open_payload("upload-pack", &store_repo, true, None, None);
    let (stdout, exit) = driver.run_git(3, &advert, &[]).await;
    assert_eq!(
        exit.exit_code, 0,
        "advertise completes while stream 1 waits"
    );
    assert!(!stdout.is_empty());

    let mut request = pkt(format!("want {}\n", commit.to_hex()).as_bytes());
    request.extend_from_slice(&flush());
    request.extend_from_slice(&pkt(b"done\n"));
    driver.send(FrameKind::Stdin, 1, &request).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 1, &[]).await;
    let (pack, _, exit) = driver.recv_exit(1).await;
    assert_eq!(exit.exit_code, 0);
    assert!(pack.starts_with(b"PACK"));

    drop(driver);
    task.abort();
}

/// Parses one ref advertisement into `(name, oid)` rows, skipping the
/// `HEAD` line and the capability tail of the first row.
fn parse_advertised_refs(output: &[u8], service: &str) -> Vec<(String, Oid)> {
    let mut refs = Vec::new();
    let mut rest = output;
    while rest.len() >= 4 {
        let len = usize::from_str_radix(
            std::str::from_utf8(&rest[..4]).expect("pkt-line length is hex"),
            16,
        )
        .expect("pkt-line length parses");
        if len == 0 {
            break;
        }
        assert!(len >= 4 && rest.len() >= len, "truncated advertisement");
        let mut line = &rest[4..len];
        if let Some(nul) = line.iter().position(|b| *b == 0) {
            line = &line[..nul];
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let mut parts = line.split(|b| *b == b' ');
        let oid_hex = std::str::from_utf8(parts.next().expect("oid")).expect("oid is text");
        let name = std::str::from_utf8(parts.next().expect("name")).expect("name is text");
        if name != "HEAD" {
            let oid = Oid::from_hex(oid_hex).expect("advertised oid parses");
            refs.push((name.to_string(), oid));
        }
        rest = &rest[len..];
    }
    assert!(
        !rest.is_empty() || !refs.is_empty(),
        "{service} advertisement parses to at least the seeded ref"
    );
    refs
}

/// A stream task that stopped draining must not stall the connection
/// reader: the 33rd frame into a 32-slot channel refuses that stream
/// instead of awaiting it, and a sibling frame still routes.
#[tokio::test]
async fn reader_never_blocks_on_a_full_stream() {
    use super::{STREAM_CHANNEL_BOUND, route_stream_frame};
    use std::collections::HashMap;
    let root = temp_root("reader-overflow");
    let registry = Arc::new(Registry::new(vec![root]).expect("registry"));
    let refs = ConnectionRefs {
        registry,
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport"),
        window_bytes: INITIAL_STREAM_WINDOW_BYTES,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: Vec::new(),
        admin_uids: Vec::new(),
    };
    let peer = ipc::PeerIdentity {
        uid: 0,
        gid: 0,
        pid: None,
    };
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel(256);
    let (done_tx, _done_rx) = tokio::sync::mpsc::channel(64);
    let mut streams: HashMap<u64, super::StreamRoute> = HashMap::new();
    // Parked task: the receiver lives but never drains.
    let (tx, _parked) = tokio::sync::mpsc::channel(STREAM_CHANNEL_BOUND);
    let (_data_tx, _data_parked) = tokio::sync::mpsc::unbounded_channel();
    streams.insert(
        7,
        super::StreamRoute {
            control: tx.clone(),
            data: _data_tx,
            outstanding: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            generation: 1,
            git: true,
            task: None,
            cancel_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    );
    for _ in 0..STREAM_CHANNEL_BOUND {
        tx.try_send(ipc::Frame {
            kind: FrameKind::WindowUpdate,
            stream_id: 7,
            payload: Vec::new(),
        })
        .expect("fill the parked stream");
    }
    let overflow = ipc::Frame {
        kind: FrameKind::WindowUpdate,
        stream_id: 7,
        payload: Vec::new(),
    };
    let routed = tokio::time::timeout(
        Duration::from_secs(5),
        route_stream_frame(&writer_tx, overflow, &mut streams, &done_tx, 1, &refs, peer),
    )
    .await
    .expect("the reader never awaits a full stream");
    assert!(!routed.expect("overflow routes without error"));
    assert!(
        !streams.contains_key(&7),
        "the overflowed stream loses its routing entry"
    );
    let first = writer_rx.try_recv().expect("overflow error frame");
    assert_eq!(first.kind, FrameKind::Error);
    assert_eq!(first.stream_id, 7);
    // The refusal ends the stream with its own terminal `Exit`: the
    // aborted task must never emit a second one, and the tripped flag
    // suppresses any late send from the serve path.
    let terminal = writer_rx.try_recv().expect("overflow terminal exit");
    assert_eq!(terminal.kind, FrameKind::Exit);
    assert_eq!(terminal.stream_id, 7);
    let report: super::ExitReport =
        ipc::decode_control(&terminal.payload).expect("exit report decodes");
    assert_eq!(report.status, 1);
    // A live sibling still receives its frame promptly after the refusal.
    let (sib_tx, mut sib_rx) = tokio::sync::mpsc::channel(STREAM_CHANNEL_BOUND);
    let (sib_data_tx, _sib_data_parked) = tokio::sync::mpsc::unbounded_channel();
    streams.insert(
        9,
        super::StreamRoute {
            control: sib_tx,
            data: sib_data_tx,
            outstanding: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            generation: 1,
            git: true,
            task: None,
            cancel_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    );
    let sibling = ipc::Frame {
        kind: FrameKind::Cancel,
        stream_id: 9,
        payload: Vec::new(),
    };
    let peer = ipc::PeerIdentity {
        uid: 0,
        gid: 0,
        pid: None,
    };
    let sibling_routed = tokio::time::timeout(
        Duration::from_secs(5),
        route_stream_frame(&writer_tx, sibling, &mut streams, &done_tx, 1, &refs, peer),
    )
    .await
    .expect("a sibling frame routes after the refusal");
    assert!(!sibling_routed.expect("sibling routes without error"));
    let delivered = tokio::time::timeout(Duration::from_secs(5), sib_rx.recv())
        .await
        .expect("sibling delivery never blocks")
        .expect("sibling channel stays open");
    assert_eq!(delivered.kind, FrameKind::Cancel);
    assert_eq!(delivered.stream_id, 9);
}

/// A tripped cancel flag aborts the blocking serve instead of running
/// it to completion: the daemon threads its per-stream flag into the
/// sync serve, which polls it at every pack stage.
#[tokio::test]
async fn run_git_service_honors_a_tripped_cancel_flag() {
    use std::sync::atomic::AtomicBool;
    let root = temp_root("git-cancel-flag");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let registry = Arc::new(Registry::new(vec![root]).expect("registry"));
    registry.set_runtime(tokio::runtime::Handle::current());
    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let mut stdin = pkt(format!("want {}\n", commit.to_hex()).as_bytes());
    stdin.extend_from_slice(&flush());
    stdin.extend_from_slice(&pkt(b"done\n"));
    stdin.extend_from_slice(&flush());

    let live = Arc::new(AtomicBool::new(false));
    super::run_git_service(&coordinator, "upload-pack", "", false, stdin.clone(), live)
        .expect("an untripped flag serves the pack");
    let tripped = Arc::new(AtomicBool::new(true));
    let err = super::run_git_service(&coordinator, "upload-pack", "", false, stdin, tripped)
        .expect_err("a tripped flag aborts the serve");
    assert_eq!(
        err.code,
        ErrorCode::ECancelled,
        "abort reports cancel, got {err:?}"
    );
}

/// A `Cancel` frame ends a parked blocking wait at once: the helper
/// stops awaiting (the detached worker keeps its bulkhead permit until
/// it finishes), trips the sync flag, and reports the cancelled exit.
#[tokio::test]
async fn git_round_cancel_stops_a_parked_serve() {
    use super::{GitRound, await_git_round};
    use ruk_core::coord::cancellation;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (cancel_guard, token) = cancellation();
    let flag = Arc::new(AtomicBool::new(false));
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel(256);
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(8);
    let mut credits = ipc::StreamCredits::new(INITIAL_STREAM_WINDOW_BYTES);
    let sink = super::StreamSink {
        writer: writer_tx,
        stream_id: 1,
    };
    let parked = std::future::pending::<Result<Vec<u8>, CoreError>>();
    input_tx
        .send(ipc::Frame {
            kind: FrameKind::Cancel,
            stream_id: 1,
            payload: Vec::new(),
        })
        .await
        .expect("cancel buffers");
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        await_git_round(
            GitRound {
                input: &mut input_rx,
                sink: &sink,
                credits: &mut credits,
                cancel_guard: &cancel_guard,
                cancel_flag: Arc::clone(&flag),
                token: token.clone(),
                stream_id: 1,
                invocation: "inv-cancel-1",
            },
            parked,
        ),
    )
    .await
    .expect("cancel ends the wait");
    assert!(
        outcome.is_none(),
        "a cancelled round reports nothing further"
    );
    assert!(
        flag.load(Ordering::SeqCst),
        "cancel trips the sync flag at once"
    );
    let exit = writer_rx.try_recv().expect("cancelled exit frame");
    assert_eq!(exit.kind, FrameKind::Exit);
    assert_eq!(exit.stream_id, 1);
    let report: CommandExitReport = ipc::decode_control(&exit.payload).expect("exit decodes");
    assert_eq!(report.exit_code, 130);
    assert!(report.cancelled);
}

/// A `Cancel` frame during a hook wait refuses the push and trips the
/// sync flag at once, so the blocking serve aborts instead of running
/// to completion on its bulkhead slot.
#[tokio::test]
async fn hook_wait_cancel_trips_the_sync_flag() {
    use ruk_core::coord::cancellation;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (cancel_guard, _) = cancellation();
    let flag = Arc::new(AtomicBool::new(false));
    let (writer_tx, _writer_rx) = tokio::sync::mpsc::channel(256);
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(8);
    let sink = super::StreamSink {
        writer: writer_tx,
        stream_id: 1,
    };
    let call = HookCall {
        phase: HookPhase::PreReceive,
        commands: Vec::new(),
        push_options: Vec::new(),
        new_commits: Vec::new(),
        new_commits_truncated: false,
        pack_bytes: 0,
        deadline_ms: 5_000,
    };
    input_tx
        .send(ipc::Frame {
            kind: FrameKind::Cancel,
            stream_id: 1,
            payload: Vec::new(),
        })
        .await
        .expect("cancel buffers");
    let mut credits = super::ipc::StreamCredits::new(0);
    credits.open_stream(1);
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        super::pump_one_exchange(
            &mut input_rx,
            &sink,
            &call,
            &cancel_guard,
            &flag,
            &mut credits,
        ),
    )
    .await
    .expect("cancel ends the hook wait");
    assert!(reply.reject_all);
    assert_eq!(reply.reason.as_deref(), Some("push cancelled"));
    assert!(
        flag.load(Ordering::SeqCst),
        "hook-wait cancel trips the sync flag"
    );
}

/// A `WindowUpdate` frame during a hook wait applies to the stream
/// credits instead of dropping, so the report writer never stalls on
/// credit the client already granted.
#[tokio::test]
async fn hook_wait_applies_window_update_to_credits() {
    use ruk_core::coord::cancellation;
    use std::sync::atomic::AtomicBool;
    let (cancel_guard, _) = cancellation();
    let flag = AtomicBool::new(false);
    let (writer_tx, _writer_rx) = tokio::sync::mpsc::channel(256);
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel(8);
    let sink = super::StreamSink {
        writer: writer_tx,
        stream_id: 1,
    };
    let mut credits = super::ipc::StreamCredits::new(512);
    credits.open_stream(1);
    credits
        .consume_outbound(1, 512)
        .expect("drained window stalls without the grant");
    assert!(credits.consume_outbound(1, 1).is_err());
    let call = HookCall {
        phase: HookPhase::PreReceive,
        commands: Vec::new(),
        push_options: Vec::new(),
        new_commits: Vec::new(),
        new_commits_truncated: false,
        pack_bytes: 0,
        deadline_ms: 5_000,
    };
    let grant = super::WindowCredit {
        credit_bytes: 256,
        direction: "stdout".to_string(),
    };
    let grant_bytes = super::ipc::encode_control(&grant).expect("grant encodes");
    input_tx
        .send(ipc::Frame {
            kind: FrameKind::WindowUpdate,
            stream_id: 1,
            payload: grant_bytes,
        })
        .await
        .expect("grant buffers");
    let reply = super::HookReply {
        reject_all: false,
        reason: None,
        verdicts: Vec::new(),
    };
    let reply_bytes = ipc::encode_control(&reply).expect("reply encodes");
    input_tx
        .send(ipc::Frame {
            kind: FrameKind::HookReply,
            stream_id: 1,
            payload: reply_bytes,
        })
        .await
        .expect("reply buffers");
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        super::pump_one_exchange(
            &mut input_rx,
            &sink,
            &call,
            &cancel_guard,
            &flag,
            &mut credits,
        ),
    )
    .await
    .expect("grant plus reply ends the hook wait");
    assert!(!reply.reject_all);
    credits
        .consume_outbound(1, 256)
        .expect("the granted credit applies");
}

#[tokio::test]
async fn git_service_cancel_reports_cancelled_and_spares_siblings() {
    let root = temp_root("git-cancel");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = git_open_payload("upload-pack", &store_repo, false, None, None);
    driver.send(FrameKind::Open, 1, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Cancel, 1, &[]).await;

    let (_, _, exit) = driver.recv_exit(1).await;
    assert_eq!(exit.exit_code, 130);
    assert!(exit.cancelled);
    assert_eq!(exit.outcome, "CancelledBeforeCommit");

    let advert = git_open_payload("upload-pack", &store_repo, true, None, None);
    let (stdout, exit) = driver.run_git(3, &advert, &[]).await;
    assert_eq!(exit.exit_code, 0, "a sibling stream survives the cancel");
    assert!(!stdout.is_empty());

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn provenance_records_on_behalf_of_and_ignores_it_for_auth() {
    let root = temp_root("typed-obo");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let target = seed_commit(&repo_dir);

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let plain: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let plain_session = plain.session.to_string();

    let payload = Driver::typed_open_obo(
        &store_repo,
        "session.open",
        None,
        None,
        None,
        Some("agent-x"),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let declared: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    assert_eq!(
        declared.principal, plain.principal,
        "provenance never authorizes: the peer stays the principal"
    );
    let session = declared.session.to_string();

    let acquire_args = ClaimAcquireArgs {
        paths: vec![RepoPath::new("src").expect("test path")],
        ttl: ClaimTtl::new(60).expect("ttl"),
        mode: ClaimMode::Enforce,
    };
    let args_json = sonic_rs::to_string(&acquire_args).expect("acquire args encode");
    let payload = Driver::typed_open_obo(
        &store_repo,
        "claim.acquire",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
        Some("agent-x"),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimAcquire(acquired)) = envelope.body else {
        panic!("claim.acquire must answer its own reply");
    };
    assert_eq!(
        acquired.claim.on_behalf_of.as_deref(),
        Some("agent-x"),
        "the sealed claim carries the declared provenance"
    );

    let tag_args = TagSetArgs {
        name: RefName::new("refs/tags/v1").expect("tag name"),
        target,
        annotation: None,
        expected: RefExpect::Absent,
    };
    let args_json = sonic_rs::to_string(&tag_args).expect("tag args encode");
    let payload = Driver::typed_open_obo(
        &store_repo,
        "tag.set",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&plain_session),
        Some("agent-x"),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    assert!(
        matches!(envelope.body, ReplyBody::Success(Reply::TagSet(_))),
        "tag.set lands"
    );

    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&plain_session),
    );
    let (stdout, _) = driver.run_typed(11, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(log)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(
        log.entries.items.len(),
        2,
        "the journaled claim.acquire joins the tag op in op.log"
    );
    assert_eq!(log.entries.items[0].method.as_str(), "tag.set");
    assert_eq!(
        log.entries.items[0].on_behalf_of.as_deref(),
        Some("agent-x"),
        "the op.log entry carries the declared provenance"
    );
    assert_eq!(log.entries.items[1].method.as_str(), "claim.acquire");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_service_advertise_routes_by_protocol() {
    let root = temp_root("advertise-v2");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let v0 = git_open_payload("upload-pack", &store_repo, true, None, None);
    let (v0_out, exit) = driver.run_git(1, &v0, &[]).await;
    assert_eq!(exit.exit_code, 0);

    let v2 = git_open_payload_full(
        "upload-pack",
        &store_repo,
        true,
        None,
        None,
        "version=2",
        None,
    );
    let (v2_out, exit) = driver.run_git(3, &v2, &[]).await;
    assert_eq!(exit.exit_code, 0);
    assert_ne!(v0_out, v2_out, "v2 discovery answers its own capabilities");
    let v2_text = String::from_utf8_lossy(&v2_out);
    assert!(
        v2_text.contains("ls-refs"),
        "v2 advertisement carries v2 capabilities: {v2_text}"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn events_increase_strictly_across_lane_and_receive() {
    let root = temp_root("events-order");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let registry = Arc::new(Registry::new(vec![root.to_path_buf()]).expect("registry"));
    registry.set_runtime(tokio::runtime::Handle::current());
    let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
    let uid = client.peer_cred().expect("socket pair credentials").uid();
    let refs = ConnectionRefs {
        registry: Arc::clone(&registry),
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport executor"),
        window_bytes: INITIAL_STREAM_WINDOW_BYTES,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: vec![uid],
        admin_uids: Vec::new(),
    };
    let task = tokio::spawn(async move { serve_connection(server, refs).await });
    let mut driver = Driver { conn: client };
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let tag_args = TagSetArgs {
        name: RefName::new("refs/tags/v1").expect("tag name"),
        target: commit,
        annotation: None,
        expected: RefExpect::Absent,
    };
    let args_json = sonic_rs::to_string(&tag_args).expect("tag args encode");
    let payload = Driver::typed_open(
        &store_repo,
        "tag.set",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    assert!(
        matches!(envelope.body, ReplyBody::Success(Reply::TagSet(_))),
        "lane mutation lands"
    );

    let zero = "0".repeat(40);
    let mut request = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    request.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-del-1"),
    );
    let (_, exit) = driver
        .run_git_hosted(7, &payload, &[request], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let page = coordinator
        .store()
        .fact_page(
            ruk_core::store::FactTable::Events,
            None,
            ruk_core::store::FactPageBudget::new(100, usize::MAX),
        )
        .expect("read events");
    let seqs: Vec<u64> = page
        .rows
        .iter()
        .map(|row| u64::from_be_bytes(row.key.as_slice().try_into().expect("8-byte event key")))
        .collect();
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "the seeded ref, the lane tag, and the receive delete share one strict sequence"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn service_receipt_replays_stored_report() {
    let root = temp_root("receipt-replay");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-replay-1"),
    );
    let (first_out, first_exit) = driver
        .run_git_hosted(5, &payload, &[body.clone()], accept_all)
        .await;
    assert_eq!(first_exit.exit_code, 0);

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-replay-1"),
    );
    let (second_out, second_exit) = driver
        .run_git_hosted(7, &payload, &[body], accept_all)
        .await;
    assert_eq!(second_exit.exit_code, 0);
    assert_eq!(
        second_out, first_out,
        "the replay resends the stored report instead of re-executing"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn service_receipt_digest_mismatch_is_reused_error() {
    let root = temp_root("receipt-reuse");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let hex = commit.to_hex();
    let mut delete = pkt(format!("{hex} {zero} refs/heads/scratch\n").as_bytes());
    delete.extend_from_slice(&flush());
    let mut other = pkt(format!("{zero} {hex} refs/heads/other\n").as_bytes());
    other.extend_from_slice(&flush());

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-reuse-1"),
    );
    let (_, exit) = driver
        .run_git_hosted(5, &payload, &[delete], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-reuse-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &other).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let err_frame = driver.recv().await;
    assert_eq!(err_frame.kind, FrameKind::Error);
    let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
    assert_eq!(report.code, ErrorCode::ERequestReused);
    let exit_frame = driver.recv().await;
    assert_eq!(exit_frame.kind, FrameKind::Exit);

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_pre_receive_per_ref_accept_reject() {
    let root = temp_root("host-accept");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let hex = commit.to_hex();
    let mut body = pkt(format!("{hex} {zero} refs/heads/main\n").as_bytes());
    body.extend_from_slice(pkt(format!("{hex} {zero} refs/heads/scratch\n").as_bytes()).as_slice());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-host-1"),
    );
    let answer = |call: &HookCall| {
        Some(HookReply {
            reject_all: false,
            reason: None,
            verdicts: call
                .commands
                .iter()
                .map(|command| HookRefVerdict {
                    name: command.name.clone(),
                    verdict: if command.name == "refs/heads/main" {
                        HookVerdict::Accept
                    } else {
                        HookVerdict::Reject {
                            reason: "nope".to_owned(),
                        }
                    },
                })
                .collect(),
        })
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("ok refs/heads/main"), "got {text:?}");
    assert!(text.contains("ng refs/heads/scratch nope"), "got {text:?}");
    assert_eq!(
        exit.operation_ids,
        vec!["3".to_owned()],
        "only the landed delete names an operation"
    );

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let main = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/main")
        .expect("read main");
    let scratch = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/scratch")
        .expect("read scratch");
    assert!(main.is_none(), "accepted delete landed");
    assert!(scratch.is_some(), "refused delete stayed");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_divert_writes_review_ref_only() {
    let root = temp_root("host-divert");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let four = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    let zero = "0".repeat(40);
    let mut body = pkt(format!("{zero} {four} refs/for/main\n").as_bytes());
    body.extend_from_slice(&flush());
    body.extend_from_slice(include_bytes!(
        "../../../ruk-git/src/transport/fixtures/basic.pack"
    ));
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-divert-1"),
    );
    let answer = |call: &HookCall| {
        if call.phase == HookPhase::PostReceive {
            return accept_all(call);
        }
        Some(HookReply {
            reject_all: false,
            reason: None,
            verdicts: vec![HookRefVerdict {
                name: "refs/for/main".to_owned(),
                verdict: HookVerdict::Divert {
                    review_ref: "refs/changes/1/head".to_owned(),
                },
            }],
        })
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("ok refs/for/main"), "got {text:?}");
    assert_eq!(exit.operation_ids.len(), 1);

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let literal = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/for/main")
        .expect("read literal");
    assert!(literal.is_none(), "no literal refs/for ref lands");
    let review = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/changes/1/head")
        .expect("read review");
    assert!(review.is_some(), "the review ref lands through CAS");

    drop(driver);
    task.abort();
}

fn hosted_two_chain_pack(seed_a: u8, seed_b: u8) -> (Vec<u8>, Oid, Oid) {
    let kind = ruk_core::ids::HashKind::Sha1;
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    let mut trees: Vec<Vec<u8>> = Vec::new();
    let mut commits: Vec<Vec<u8>> = Vec::new();
    let mut blob_ids: Vec<Oid> = Vec::new();
    let mut tree_ids: Vec<Oid> = Vec::new();
    let mut commit_ids: Vec<Oid> = Vec::new();
    for seed in [seed_a, seed_b] {
        let blob: Vec<u8> = (0..1000)
            .map(|i| ((i + usize::from(seed) * 131) % 251) as u8)
            .collect();
        let blob_id = hosted_blob_oid(&blob);
        let mut tree = b"100644 f\0".to_vec();
        tree.extend_from_slice(blob_id.as_bytes());
        let tree_id = kind.hash_git_object("tree", &tree).expect("tree hashes");
        let commit = format!(
            "tree {}\nauthor T <t@t.invalid> 0 +0000\ncommitter T <t@t.invalid> 0 +0000\n\nhosted\n",
            tree_id.to_hex()
        )
        .into_bytes();
        let commit_id = kind
            .hash_git_object("commit", &commit)
            .expect("commit hashes");
        blobs.push(blob);
        trees.push(tree);
        commits.push(commit);
        blob_ids.push(blob_id);
        tree_ids.push(tree_id);
        commit_ids.push(commit_id);
    }
    let entries = [
        git_pack::PackEntry {
            oid: commit_ids[0],
            kind: ObjectKind::Commit,
            bytes: &commits[0],
            base: None,
        },
        git_pack::PackEntry {
            oid: tree_ids[0],
            kind: ObjectKind::Tree,
            bytes: &trees[0],
            base: None,
        },
        git_pack::PackEntry {
            oid: blob_ids[0],
            kind: ObjectKind::Blob,
            bytes: &blobs[0],
            base: None,
        },
        git_pack::PackEntry {
            oid: commit_ids[1],
            kind: ObjectKind::Commit,
            bytes: &commits[1],
            base: None,
        },
        git_pack::PackEntry {
            oid: tree_ids[1],
            kind: ObjectKind::Tree,
            bytes: &trees[1],
            base: None,
        },
        git_pack::PackEntry {
            oid: blob_ids[1],
            kind: ObjectKind::Blob,
            bytes: &blobs[1],
            base: None,
        },
    ];
    let mut pack = Vec::new();
    git_pack::write_pack(&mut pack, kind, &entries, &Interrupt::none()).expect("pack");
    (pack, commit_ids[0], commit_ids[1])
}

#[tokio::test]
async fn host_duplicate_divert_second_fails_first_kept() {
    let root = temp_root("host-dup-divert");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let (pack, commit_a, commit_b) = hosted_two_chain_pack(11, 12);
    assert_ne!(commit_a, commit_b, "the diverters carry distinct commits");

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let session = open_push_session(&mut driver, &store_repo, &["refs/for/**"]).await;
    let zero = "0".repeat(40);
    let mut body =
        pkt(format!("{zero} {commit} refs/for/a\n", commit = commit_a.to_hex()).as_bytes());
    body.extend_from_slice(&pkt(format!(
        "{zero} {commit} refs/for/b\n",
        commit = commit_b.to_hex()
    )
    .as_bytes()));
    body.extend_from_slice(&flush());
    body.extend_from_slice(&pack);
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-dup-divert-1"),
    );
    let answer = |call: &HookCall| {
        if call.phase == HookPhase::PostReceive {
            return accept_all(call);
        }
        Some(HookReply {
            reject_all: false,
            reason: None,
            verdicts: call
                .commands
                .iter()
                .map(|command| HookRefVerdict {
                    name: command.name.clone(),
                    verdict: HookVerdict::Divert {
                        review_ref: "refs/changes/7/head".to_owned(),
                    },
                })
                .collect(),
        })
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ok refs/for/a"),
        "the first divert keeps its report: {text:?}"
    );
    assert!(
        text.contains("ng refs/for/b"),
        "the duplicate divert fails in-band: {text:?}"
    );
    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let review = ruk_core::refs::StoreRefs::new(coordinator.store())
        .get(&RefName::new("refs/changes/7/head".to_string()).expect("ref name"))
        .expect("read review");
    assert_eq!(
        review,
        Some(RefTarget::Direct(commit_a)),
        "the first divert wins the review ref"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_post_receive_reports_only_landed_refs() {
    let root = temp_root("host-post-landed");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let session = open_push_session(&mut driver, &store_repo, &["refs/heads/**"]).await;
    let zero = "0".repeat(40);
    let bogus = "f".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&pkt(
        format!("{bogus} {zero} refs/heads/nosuch\n").as_bytes()
    ));
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-post-landed-1"),
    );
    let posted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = std::sync::Arc::clone(&posted);
    let answer = move |call: &HookCall| {
        if call.phase == HookPhase::PostReceive {
            seen.lock()
                .expect("post log")
                .extend(call.commands.iter().map(|command| command.name.clone()));
            return Some(HookReply {
                reject_all: false,
                reason: None,
                verdicts: Vec::new(),
            });
        }
        accept_all(call)
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ok refs/heads/scratch"),
        "the landed delete reports ok: {text:?}"
    );
    assert!(
        text.contains("ng refs/heads/nosuch"),
        "the refused delete reports ng: {text:?}"
    );
    let posted = posted.lock().expect("post log");
    assert_eq!(
        posted.as_slice(),
        ["refs/heads/scratch"],
        "the advisory callback names only the landed ref"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_reply_missing_ref_means_reject_all() {
    let root = temp_root("host-missing");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let hex = commit.to_hex();
    let mut body = pkt(format!("{hex} {zero} refs/heads/main\n").as_bytes());
    body.extend_from_slice(pkt(format!("{hex} {zero} refs/heads/scratch\n").as_bytes()).as_slice());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-missing-1"),
    );
    let answer = |call: &HookCall| {
        Some(HookReply {
            reject_all: false,
            reason: None,
            verdicts: call
                .commands
                .iter()
                .filter(|command| command.name == "refs/heads/main")
                .map(|command| HookRefVerdict {
                    name: command.name.clone(),
                    verdict: HookVerdict::Accept,
                })
                .collect(),
        })
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ng refs/heads/main hook left ref"),
        "got {text:?}"
    );
    assert!(
        text.contains("ng refs/heads/scratch hook left ref"),
        "got {text:?}"
    );
    assert!(exit.operation_ids.is_empty());

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    for name in [
        b"refs/heads/main".as_slice(),
        b"refs/heads/scratch".as_slice(),
    ] {
        let kept = coordinator
            .store()
            .fact(ruk_core::store::FactTable::Refs, name)
            .expect("read ref");
        assert!(kept.is_some(), "nothing lands on a partial reply");
    }

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_timeout_rejects_all_fail_closed() {
    let root = temp_root("host-timeout");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 300);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/main\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-timeout-1"),
    );
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], |_| None).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ng refs/heads/main hook deadline elapsed"),
        "got {text:?}"
    );

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let kept = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/main")
        .expect("read ref");
    assert!(kept.is_some(), "a timed-out push publishes nothing");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn host_unauthorized_ref_refused_before_callback() {
    let root = temp_root("host-unauth");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let session = open_push_session(&mut driver, &store_repo, &["refs/heads/other/**"]).await;

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/main\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-unauth-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let mut saw_hook = false;
    let mut stdout = Vec::new();
    let exit = loop {
        let frame = driver.recv().await;
        match frame.kind {
            FrameKind::HookCall => saw_hook = true,
            FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
            FrameKind::Exit => {
                break ipc::decode_control::<CommandExitReport>(&frame.payload)
                    .expect("exit decodes");
            }
            FrameKind::Error => panic!("stream refused"),
            other => panic!("unexpected frame {other:?}"),
        }
    };
    assert!(!saw_hook, "no callback fires without push authority");
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("ng refs/heads/main no push_refs capability"),
        "got {text:?}"
    );

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let kept = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/main")
        .expect("read ref");
    assert!(kept.is_some(), "an unauthorized push publishes nothing");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn hosted_atomic_push_refuses_before_pre_receive() {
    let root = temp_root("host-atomic");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let session = open_push_session(&mut driver, &store_repo, &["refs/heads/**"]).await;

    let (_, _, before) = registry.open(&store_repo).expect("open coordinator");
    let before_ref = before
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/scratch")
        .expect("read ref before the push");

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\0report-status atomic\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-atomic-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let mut saw_hook = false;
    let mut stdout = Vec::new();
    let exit = loop {
        let frame = driver.recv().await;
        match frame.kind {
            FrameKind::HookCall => saw_hook = true,
            FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
            FrameKind::Exit => {
                break ipc::decode_control::<CommandExitReport>(&frame.payload)
                    .expect("exit decodes");
            }
            FrameKind::Error => panic!("atomic refusal stays in-band"),
            other => panic!("unexpected frame {other:?}"),
        }
    };
    assert!(!saw_hook, "no callback fires for an atomic push");
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("ng refs/heads/scratch atomic pushes are not supported"),
        "got {text:?}"
    );

    let (_, _, after) = registry.open(&store_repo).expect("open coordinator");
    let after_ref = after
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/scratch")
        .expect("read ref after the push");
    assert_eq!(after_ref, before_ref, "a refused atomic push moves no ref");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn post_receive_failure_never_fails_push() {
    let root = temp_root("host-postfail");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, _registry, task) = spawn_hosted(&root, 300);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-postfail-1"),
    );
    let answer = |call: &HookCall| {
        if call.phase == HookPhase::PreReceive {
            accept_all(call)
        } else {
            None
        }
    };
    let (out, exit) = driver.run_git_hosted(5, &payload, &[body], answer).await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("ok refs/heads/scratch"), "got {text:?}");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn post_receive_follows_report_delivery() {
    let root = temp_root("host-postorder");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-postorder-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;

    let order = std::sync::Mutex::new(Vec::new());
    let mut stdout = Vec::new();
    let exit = loop {
        let frame = driver.recv().await;
        assert_eq!(frame.stream_id, 5);
        match frame.kind {
            FrameKind::HookCall => {
                let call: HookCall =
                    ipc::decode_control(&frame.payload).expect("hook call decodes");
                let mark = match call.phase {
                    HookPhase::PreReceive => "hook-pre",
                    HookPhase::PostReceive => "hook-post",
                };
                order.lock().expect("order log").push(mark);
                let reply = match call.phase {
                    HookPhase::PreReceive => accept_all(&call).expect("pre-receive answered"),
                    HookPhase::PostReceive => HookReply {
                        reject_all: false,
                        reason: None,
                        verdicts: Vec::new(),
                    },
                };
                let bytes = ipc::encode_control(&reply).expect("hook reply encodes");
                driver.send(FrameKind::HookReply, 5, &bytes).await;
            }
            FrameKind::Stdout => {
                if !frame.payload.is_empty() && stdout.is_empty() {
                    order.lock().expect("order log").push("stdout");
                }
                stdout.extend_from_slice(&frame.payload);
            }
            FrameKind::Exit => {
                order.lock().expect("order log").push("exit");
                break ipc::decode_control::<CommandExitReport>(&frame.payload)
                    .expect("exit decodes");
            }
            FrameKind::Error => panic!(
                "stream refused: {}",
                String::from_utf8_lossy(&frame.payload)
            ),
            other => panic!("unexpected frame {other:?}"),
        }
    };
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&stdout);
    assert!(text.contains("ok refs/heads/scratch"), "got {text:?}");
    let log = order.lock().expect("order log");
    let position = |mark: &str| log.iter().position(|entry| *entry == mark).expect(mark);
    assert!(
        position("hook-pre") < position("stdout"),
        "pre-receive judges first: {log:?}"
    );
    assert!(
        position("stdout") < position("hook-post"),
        "report delivers before the advisory post-receive: {log:?}"
    );
    assert!(
        position("hook-post") < position("exit"),
        "post-receive precedes exit: {log:?}"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn receive_replay_same_digest_no_second_publish() {
    let root = temp_root("host-replay");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-host-replay-1"),
    );
    let (first_out, first_exit) = driver
        .run_git_hosted(5, &payload, &[body.clone()], accept_all)
        .await;
    assert_eq!(first_exit.exit_code, 0);

    let events_before = {
        let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
        coordinator
            .store()
            .fact_page(
                ruk_core::store::FactTable::Events,
                None,
                ruk_core::store::FactPageBudget::new(100, usize::MAX),
            )
            .expect("read events")
            .rows
            .len()
    };
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-host-replay-1"),
    );
    let (second_out, second_exit) = driver
        .run_git_hosted(7, &payload, &[body], accept_all)
        .await;
    assert_eq!(second_exit.exit_code, 0);
    assert_eq!(second_out, first_out);
    let events_after = {
        let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
        coordinator
            .store()
            .fact_page(
                ruk_core::store::FactTable::Events,
                None,
                ruk_core::store::FactPageBudget::new(100, usize::MAX),
            )
            .expect("read events")
            .rows
            .len()
    };
    assert_eq!(
        events_after, events_before,
        "the replay publishes no second event"
    );
    assert!(
        !first_exit.operation_ids.is_empty(),
        "the live run names its operations"
    );
    assert_eq!(
        second_exit.operation_ids, first_exit.operation_ids,
        "the replay reports the same operations as the live run"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn receive_digest_mismatch_refused() {
    let root = temp_root("host-mismatch");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let four = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    let zero = "0".repeat(40);
    let mut create = pkt(format!("{zero} {four} refs/heads/packed\n").as_bytes());
    create.extend_from_slice(&flush());
    create.extend_from_slice(include_bytes!(
        "../../../ruk-git/src/transport/fixtures/basic.pack"
    ));
    let mut delete = pkt(format!("{four} {zero} refs/heads/packed\n").as_bytes());
    delete.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-host-mm-1"),
    );
    let (_, exit) = driver
        .run_git_hosted(5, &payload, &[create], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-host-mm-1"),
    );
    driver.send(FrameKind::Open, 7, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 7, &delete).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 7, &[]).await;
    let err_frame = driver.recv().await;
    assert_eq!(err_frame.kind, FrameKind::Error);
    let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
    assert_eq!(report.code, ErrorCode::ERequestReused);
    let exit_frame = driver.recv().await;
    assert_eq!(exit_frame.kind, FrameKind::Exit);

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn receive_ref_stale_old_without_receipt_is_rejected() {
    let root = temp_root("host-already");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-already-1"),
    );
    let (_, exit) = driver
        .run_git_hosted(5, &payload, &[body.clone()], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);

    // Same commands under a fresh request id re-execute against a ref
    // that already sits at the desired tip: stock refusal, not `ok`.
    // Tolerance lives only in the exact receipt replay (same request id,
    // same digest), which returns the stored report before the serve.
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-already-2"),
    );
    let (out, exit) = driver
        .run_git_hosted(7, &payload, &[body], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ng refs/heads/scratch destination ref moved"),
        "fresh stale push must report ng, got {text:?}"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn hosted_push_records_envelope_provenance_in_events() {
    let root = temp_root("host-provenance");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload_full(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-provenance-1"),
        "",
        Some("agent-push"),
    );
    let (out, exit) = driver
        .run_git_hosted(5, &payload, &[body], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("ok refs/heads/scratch"),
        "push must land, got {text:?}"
    );

    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let page = coordinator
        .store()
        .fact_page(
            FactTable::Events,
            None,
            FactPageBudget::new(100, usize::MAX),
        )
        .expect("read events");
    assert!(!page.rows.is_empty(), "the push emits one event");
    let event = page
        .rows
        .iter()
        .map(|row| decode_store_event(&row.value).expect("event decodes"))
        .rfind(|event| event.name == b"refs/heads/scratch")
        .expect("the push emits the scratch event");
    assert_eq!(
        event.on_behalf_of.as_deref(),
        Some("agent-push"),
        "the stored event carries the envelope provenance"
    );

    let payload = Driver::typed_open(
        &store_repo,
        "events.tail",
        None,
        Some("{\"after\":0,\"limit\":100}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope: ReplyEnvelope = ipc::decode_control(&stdout).expect("tail decodes");
    let ReplyBody::Success(Reply::EventsTail(tail)) = envelope.body else {
        panic!("events.tail must answer its own reply");
    };
    assert!(
        tail.events
            .iter()
            .any(|event| event.name.as_bytes() == b"refs/heads/scratch"),
        "provenance rows still page"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn duplicate_open_for_live_stream_is_refused() {
    let root = temp_root("host-dup-open");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    // The first receive-pack open blocks waiting for stdin, so its entry
    // stays live while the duplicate arrives.
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-dup-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    assert_eq!(accepted.stream_id, 5);

    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-dup-2"),
    );
    let (report, exit) = driver.expect_git_refused(5, &payload).await;
    assert_eq!(report.code, ErrorCode::EInvalid);
    assert_eq!(exit.status, 1);

    // The first stream survives the refused duplicate: an empty command
    // list terminated by a flush completes the push round with an empty
    // report instead of hanging on a wedged stream. WindowUpdate grants
    // for the stdin bytes drain here; only the terminal report matters.
    driver.send(FrameKind::Stdin, 5, b"0000").await;
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let completed = loop {
        let frame = driver.recv().await;
        assert_eq!(frame.stream_id, 5, "unexpected stream {}", frame.stream_id);
        match frame.kind {
            FrameKind::Stdout | FrameKind::WindowUpdate => continue,
            FrameKind::Exit => {
                break ipc::decode_control::<CommandExitReport>(&frame.payload)
                    .expect("exit decodes");
            }
            other => panic!("unexpected frame {other:?} on stream 5"),
        }
    };
    assert_eq!(
        completed.outcome, "Completed",
        "first stream completes after the refused duplicate",
    );

    drop(driver);
    task.abort();
}

/// A compliant client may split a small request body into many tiny
/// `Stdin` frames inside its credit window: the router must not refuse
/// them for frame count while every byte fits the window.
#[tokio::test]
async fn small_stdin_frames_within_window_are_not_refused() {
    let root = temp_root("small-frames");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);
    let mut request = pkt(format!("want {}\n", commit.to_hex()).as_bytes());
    request.extend_from_slice(&flush());
    request.extend_from_slice(&pkt(b"done\n"));
    let chunks: Vec<Vec<u8>> = request.chunks(1).map(<[u8]>::to_vec).collect();
    assert!(chunks.len() > 40, "{} frames", chunks.len());

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;
    let payload = git_open_payload("upload-pack", &store_repo, false, None, None);
    driver.send(FrameKind::Open, 1, &payload).await;
    assert_eq!(driver.recv().await.kind, FrameKind::Accepted);
    for chunk in &chunks {
        driver.send(FrameKind::Stdin, 1, chunk).await;
    }
    let mut grants = 0;
    while grants < chunks.len() {
        let frame = driver.recv().await;
        assert_ne!(
            frame.kind,
            FrameKind::Error,
            "compliant stream refused: {}",
            String::from_utf8_lossy(&frame.payload),
        );
        assert_eq!(frame.kind, FrameKind::WindowUpdate);
        grants += 1;
    }
    driver.send(FrameKind::StdinEof, 1, &[]).await;
    let (stdout, _, exit) = driver.recv_exit(1).await;
    assert_eq!(exit.exit_code, 0);
    assert!(stdout.starts_with(b"PACK"));
    drop(driver);
    task.abort();
}

/// A chunk past the connection's credit window ends its stream: the
/// refusal removes the routing entry and emits the terminal `Exit`, so
/// the parked task cannot later emit a second terminal frame.
#[tokio::test]
async fn credit_exhaustion_removes_the_stream() {
    use super::route_stdin_frame;
    use std::collections::HashMap;
    let root = temp_root("credit-exhaustion");
    let registry = Arc::new(Registry::new(vec![root]).expect("registry"));
    let refs = ConnectionRefs {
        registry,
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport"),
        window_bytes: 16,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: Vec::new(),
        admin_uids: Vec::new(),
    };
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel(256);
    let mut streams: HashMap<u64, super::StreamRoute> = HashMap::new();
    let (tx, _parked) = tokio::sync::mpsc::channel(super::STREAM_CHANNEL_BOUND);
    let (data_tx, _data_parked) = tokio::sync::mpsc::unbounded_channel();
    streams.insert(
        7,
        super::StreamRoute {
            control: tx,
            data: data_tx,
            outstanding: Arc::new(AtomicU64::new(0)),
            generation: 1,
            git: true,
            task: None,
            cancel_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    );
    let frame = ipc::Frame {
        kind: FrameKind::Stdin,
        stream_id: 7,
        payload: vec![0u8; 100],
    };
    let routed = tokio::time::timeout(
        Duration::from_secs(5),
        route_stdin_frame(&writer_tx, &mut streams, &refs, 7, frame),
    )
    .await
    .expect("credit refusal never blocks");
    routed.expect("credit refusal reports without error");
    assert!(
        !streams.contains_key(&7),
        "the exhausted stream loses its routing entry"
    );
    let first = writer_rx.try_recv().expect("credit error frame");
    assert_eq!(first.kind, FrameKind::Error);
    assert_eq!(first.stream_id, 7);
    let terminal = writer_rx.try_recv().expect("credit terminal exit");
    assert_eq!(terminal.kind, FrameKind::Exit);
    assert_eq!(terminal.stream_id, 7);
}

/// A cancel racing an accepted hook verdict must not report
/// `CancelledBeforeCommit` for refs that landed anyway: the stream keeps
/// awaiting the detached serve and reports what it actually did.
#[tokio::test]
async fn cancel_after_accept_reports_completed_push() {
    use std::time::Duration;
    let root = temp_root("cancel-after-accept");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/main", commit);
    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let hex = commit.to_hex();
    let mut body = pkt(format!("{hex} {zero} refs/heads/main\n").as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-probe-cancel"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    assert_eq!(driver.recv().await.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    assert_eq!(driver.recv().await.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let outcome = loop {
        let frame = driver.recv().await;
        match frame.kind {
            FrameKind::HookCall => {
                let call: HookCall = ipc::decode_control(&frame.payload).expect("call");
                if let Some(reply) = accept_all(&call) {
                    let bytes = ipc::encode_control(&reply).expect("reply");
                    driver.send(FrameKind::HookReply, 5, &bytes).await;
                    driver.send(FrameKind::Cancel, 5, &[]).await;
                }
                continue;
            }
            FrameKind::Exit => {
                let report: CommandExitReport = ipc::decode_control(&frame.payload).expect("exit");
                break report.outcome.clone();
            }
            _ => continue,
        }
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (_, _, coordinator) = registry.open(&store_repo).expect("open coordinator");
    let main = coordinator
        .store()
        .fact(ruk_core::store::FactTable::Refs, b"refs/heads/main")
        .expect("read");
    assert!(
        !(outcome == "CancelledBeforeCommit" && main.is_none()),
        "reported {outcome} but the delete landed",
    );
    assert_eq!(outcome, "Completed");
    drop(driver);
    task.abort();
}

#[tokio::test]
async fn frame_kind_9_rejected_on_any_stream() {
    let root = temp_root("kind-nine");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = git_open_payload("upload-pack", &store_repo, true, None, None);
    driver.send(FrameKind::Open, 1, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    // Drain the advertisement round first: only the retired kind may
    // kill the connection below, not in-flight traffic.
    loop {
        let frame = driver.recv().await;
        assert_eq!(frame.stream_id, 1);
        if frame.kind == FrameKind::Exit {
            break;
        }
    }
    driver.send_raw(9, 1, b"retired").await;
    let refused = driver.try_recv().await;
    assert!(
        refused.is_err(),
        "a retired frame kind tears the connection down, got {refused:?}"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn hook_frames_misplaced_on_git_stdin_are_refused() {
    let root = temp_root("hook-misplaced");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    for (stream_id, kind) in [(1u64, FrameKind::HookCall), (3u64, FrameKind::HookReply)] {
        let payload = git_open_payload("upload-pack", &store_repo, false, None, None);
        driver.send(FrameKind::Open, stream_id, &payload).await;
        let accepted = driver.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        assert_eq!(accepted.stream_id, stream_id);
        driver.send(kind, stream_id, b"misplaced").await;
        let err_frame = driver.recv().await;
        assert_eq!(err_frame.kind, FrameKind::Error);
        assert_eq!(err_frame.stream_id, stream_id);
        let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
        assert_eq!(report.code, ErrorCode::EInvalid);
        assert_eq!(report.message, "frame kind is misplaced on this stream");
        let exit_frame = driver.recv().await;
        assert_eq!(exit_frame.kind, FrameKind::Exit);
        assert_eq!(exit_frame.stream_id, stream_id);
        let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
        assert_eq!(exit.status, 1);
        assert_eq!(exit.outcome, "Failed");
    }

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn socket_round_trip_push_reports_operations() {
    let root = temp_root("host-roundtrip");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, _registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-roundtrip-1"),
    );
    let (out, exit) = driver
        .run_git_hosted(5, &payload, &[body], accept_all)
        .await;
    assert_eq!(exit.exit_code, 0);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("ok refs/heads/scratch"), "got {text:?}");
    assert_eq!(
        exit.operation_ids,
        vec!["2".to_owned()],
        "the exit report names the landed delete event"
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn git_envelope_push_option_quota_refuses_push() {
    let root = temp_root("option-quota");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let commit = seed_commit(&repo_dir);
    seed_ref(&repo_dir, "refs/heads/scratch", commit);

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;
    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{commit} {zero} refs/heads/scratch\0report-status push-options\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    body.extend_from_slice(&pkt(b"topic=quota"));
    body.extend_from_slice(&flush());

    let open = CommandOpen {
        service: "receive-pack".to_owned(),
        repository: store_repo,
        session_id: Some(session),
        request_id: Some("req-option-quota-1".to_owned()),
        git_protocol: String::new(),
        advertise: false,
        stdout_credit: 262_144,
        limits: GitLimits {
            max_push_options: 0,
            ..GitLimits::default()
        },
        on_behalf_of: None,
    };
    let payload = sonic_rs::to_string(&open)
        .expect("git-service open encodes")
        .into_bytes();
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    let err_frame = driver.recv().await;
    assert_eq!(err_frame.kind, FrameKind::Error);
    assert_eq!(err_frame.stream_id, 5);
    let report: ErrorReply = ipc::decode_control(&err_frame.payload).expect("error decodes");
    assert_eq!(report.code, ErrorCode::ELimit);
    assert!(
        report.message.contains("more than 0 options"),
        "quota names its bound: {}",
        report.message
    );
    let exit_frame = driver.recv().await;
    assert_eq!(exit_frame.kind, FrameKind::Exit);
    assert_eq!(exit_frame.stream_id, 5);
    let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
    assert_eq!(exit.status, 1);
    assert_eq!(exit.outcome, "Failed");

    drop(driver);
    task.abort();
}

fn hosted_blob_oid(data: &[u8]) -> Oid {
    ruk_core::ids::HashKind::Sha1
        .hash_git_object("blob", data)
        .expect("blob hashes")
}

fn hosted_chain_pack(seed: u8) -> (Vec<u8>, Oid) {
    let kind = ruk_core::ids::HashKind::Sha1;
    let blob: Vec<u8> = (0..1000)
        .map(|i| ((i + usize::from(seed) * 131) % 251) as u8)
        .collect();
    let blob_id = hosted_blob_oid(&blob);
    let mut tree = b"100644 f\0".to_vec();
    tree.extend_from_slice(blob_id.as_bytes());
    let tree_id = kind.hash_git_object("tree", &tree).expect("tree hashes");
    let commit = format!(
        "tree {}\nauthor T <t@t.invalid> 0 +0000\ncommitter T <t@t.invalid> 0 +0000\n\nhosted\n",
        tree_id.to_hex()
    )
    .into_bytes();
    let commit_id = kind
        .hash_git_object("commit", &commit)
        .expect("commit hashes");
    let entries = [
        git_pack::PackEntry {
            oid: commit_id,
            kind: ObjectKind::Commit,
            bytes: &commit,
            base: None,
        },
        git_pack::PackEntry {
            oid: tree_id,
            kind: ObjectKind::Tree,
            bytes: &tree,
            base: None,
        },
        git_pack::PackEntry {
            oid: blob_id,
            kind: ObjectKind::Blob,
            bytes: &blob,
            base: None,
        },
    ];
    let mut pack = Vec::new();
    git_pack::write_pack(&mut pack, kind, &entries, &Interrupt::none()).expect("pack");
    (pack, commit_id)
}

fn spawn_extra_driver(
    registry: &Arc<Registry>,
) -> (Driver, tokio::task::JoinHandle<Result<(), super::Error>>) {
    let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
    let uid = client.peer_cred().expect("socket pair credentials").uid();
    let refs = ConnectionRefs {
        registry: Arc::clone(registry),
        executor: BoundedExecutor::new(4).expect("executor"),
        transport: BoundedExecutor::new(4).expect("transport executor"),
        window_bytes: INITIAL_STREAM_WINDOW_BYTES,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: vec![uid],
        admin_uids: Vec::new(),
    };
    let task = tokio::spawn(async move { serve_connection(server, refs).await });
    (Driver { conn: client }, task)
}

#[tokio::test]
async fn concurrent_identical_hosted_pushes_all_land() {
    for count in [2usize, 4, 8] {
        let root = temp_root("hosted-dup-push");
        let repo_dir = root.join("repo");
        std::fs::create_dir_all(&repo_dir).expect("repo dir");
        let repo = repo_dir.to_str().expect("utf8 repo").to_string();
        seed_store(&repo);
        let store_repo = repo_dir
            .join(".ruk")
            .to_str()
            .expect("utf8 store repo")
            .to_string();
        let (pack, commit) = hosted_chain_pack(0);

        let (mut first, registry, first_task) = spawn_hosted(&root, 10_000);
        handshake(&mut first).await;
        let mut drivers = vec![first];
        let mut tasks = vec![first_task];
        for _ in 1..count {
            let (mut extra, task) = spawn_extra_driver(&registry);
            handshake(&mut extra).await;
            drivers.push(extra);
            tasks.push(task);
        }
        let mut pushes = Vec::new();
        for (index, mut driver) in drivers.into_iter().enumerate() {
            let repo_clone = store_repo.clone();
            let pack_clone = pack.clone();
            let session = open_push_session(&mut driver, &store_repo, &["refs/heads/**"]).await;
            pushes.push(tokio::spawn(async move {
                let zero = "0".repeat(40);
                let mut body = pkt(format!(
                    "{zero} {commit} refs/heads/dup-{index}\n",
                    commit = commit.to_hex()
                )
                .as_bytes());
                body.extend_from_slice(&flush());
                body.extend_from_slice(&pack_clone);
                let payload = git_open_payload(
                    "receive-pack",
                    &repo_clone,
                    false,
                    Some(&session),
                    Some(&format!("req-hosted-dup-{index}")),
                );
                let (out, exit) = driver
                    .run_git_hosted(1, &payload, &[body], accept_all)
                    .await;
                (index, out, exit)
            }));
        }
        for pushed in pushes {
            let (index, out, exit) = pushed.await.expect("push task");
            assert_eq!(exit.exit_code, 0, "hosted push {index} exits zero");
            let text = String::from_utf8_lossy(&out);
            assert!(
                text.contains(&format!("ok refs/heads/dup-{index}")),
                "hosted push {index} lands: {text:?}"
            );
        }
        for task in tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn concurrent_hosted_race_on_one_branch_refuses_exactly_one() {
    let root = temp_root("hosted-race");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let (pack_a, commit_a) = hosted_chain_pack(1);
    let (pack_b, commit_b) = hosted_chain_pack(2);
    assert_ne!(commit_a, commit_b, "the racers carry distinct commits");

    let (mut first, registry, first_task) = spawn_hosted(&root, 10_000);
    handshake(&mut first).await;
    let (mut second, second_task) = spawn_extra_driver(&registry);
    handshake(&mut second).await;
    let session_a = open_push_session(&mut first, &store_repo, &["refs/heads/**"]).await;
    let session_b = open_push_session(&mut second, &store_repo, &["refs/heads/**"]).await;
    let push = |mut driver: Driver,
                repo: String,
                session: String,
                request: String,
                pack: Vec<u8>,
                commit: Oid| {
        tokio::spawn(async move {
            let zero = "0".repeat(40);
            let mut body = pkt(format!(
                "{zero} {commit} refs/heads/race\n",
                commit = commit.to_hex()
            )
            .as_bytes());
            body.extend_from_slice(&flush());
            body.extend_from_slice(&pack);
            let payload =
                git_open_payload("receive-pack", &repo, false, Some(&session), Some(&request));
            let (out, exit) = driver
                .run_git_hosted(1, &payload, &[body], accept_all)
                .await;
            (out, exit)
        })
    };
    let racer_a = push(
        first,
        store_repo.clone(),
        session_a,
        "req-hosted-race-a".to_owned(),
        pack_a,
        commit_a,
    );
    let racer_b = push(
        second,
        store_repo,
        session_b,
        "req-hosted-race-b".to_owned(),
        pack_b,
        commit_b,
    );
    let (out_a, exit_a) = racer_a.await.expect("first racer");
    let (out_b, exit_b) = racer_b.await.expect("second racer");
    assert_eq!(exit_a.exit_code, 0, "refusals stay in-band");
    assert_eq!(exit_b.exit_code, 0, "refusals stay in-band");
    let text_a = String::from_utf8_lossy(&out_a);
    let text_b = String::from_utf8_lossy(&out_b);
    let oks = [&text_a, &text_b]
        .iter()
        .filter(|text| text.contains("ok refs/heads/race"))
        .count();
    assert_eq!(oks, 1, "exactly one racer lands: {text_a:?} vs {text_b:?}");
    assert!(
        [&text_a, &text_b]
            .iter()
            .any(|text| text.contains("ng refs/heads/race")),
        "the loser reports ng: {text_a:?} vs {text_b:?}"
    );
    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn concurrent_same_request_id_executes_once_and_replays() {
    let root = temp_root("host-same-req");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let (pack, commit) = hosted_chain_pack(21);

    let (mut first, registry, first_task) = spawn_hosted(&root, 10_000);
    handshake(&mut first).await;
    let (mut second, second_task) = spawn_extra_driver(&registry);
    handshake(&mut second).await;
    let session_a = open_push_session(&mut first, &store_repo, &["refs/heads/**"]).await;
    let session_b = open_push_session(&mut second, &store_repo, &["refs/heads/**"]).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let pre_count = Arc::new(AtomicU64::new(0));
    let push_same = |mut driver: Driver,
                     session: String,
                     pack: Vec<u8>,
                     barrier: Arc<tokio::sync::Barrier>,
                     pre_count: Arc<AtomicU64>| {
        let repo = store_repo.clone();
        tokio::spawn(async move {
            let zero = "0".repeat(40);
            let mut body = pkt(format!(
                "{zero} {commit} refs/heads/same\n",
                commit = commit.to_hex()
            )
            .as_bytes());
            body.extend_from_slice(&flush());
            body.extend_from_slice(&pack);
            let payload = git_open_payload(
                "receive-pack",
                &repo,
                false,
                Some(&session),
                Some("req-hosted-same-1"),
            );
            driver.send(FrameKind::Open, 1, &payload).await;
            let accepted = driver.recv().await;
            assert_eq!(accepted.kind, FrameKind::Accepted);
            driver.send(FrameKind::Stdin, 1, &body).await;
            let grant = driver.recv().await;
            assert_eq!(grant.kind, FrameKind::WindowUpdate);
            tokio::time::timeout(Duration::from_secs(10), barrier.wait())
                .await
                .expect("rendezvous");
            driver.send(FrameKind::StdinEof, 1, &[]).await;
            let mut stdout = Vec::new();
            loop {
                let frame = driver.recv().await;
                assert_eq!(frame.stream_id, 1);
                match frame.kind {
                    FrameKind::HookCall => {
                        let call: HookCall =
                            ipc::decode_control(&frame.payload).expect("hook call decodes");
                        if call.phase == HookPhase::PreReceive {
                            pre_count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        let reply = accept_all(&call).expect("hook reply answered");
                        let bytes = ipc::encode_control(&reply).expect("hook reply encodes");
                        driver.send(FrameKind::HookReply, 1, &bytes).await;
                    }
                    FrameKind::Stdout => stdout.extend_from_slice(&frame.payload),
                    FrameKind::Exit => {
                        let report: CommandExitReport =
                            ipc::decode_control(&frame.payload).expect("exit decodes");
                        return (stdout, report);
                    }
                    FrameKind::Error => panic!(
                        "stream refused: {}",
                        String::from_utf8_lossy(&frame.payload)
                    ),
                    other => panic!("unexpected frame {other:?}"),
                }
            }
        })
    };
    let racer_a = push_same(
        first,
        session_a,
        pack.clone(),
        Arc::clone(&barrier),
        Arc::clone(&pre_count),
    );
    let racer_b = push_same(second, session_b, pack, barrier, Arc::clone(&pre_count));
    let (out_a, exit_a) = racer_a.await.expect("first push");
    let (out_b, exit_b) = racer_b.await.expect("second push");
    assert_eq!(exit_a.exit_code, 0);
    assert_eq!(exit_b.exit_code, 0);
    assert_eq!(out_a, out_b, "the replay returns the stored report");
    assert_eq!(
        pre_count.load(Ordering::SeqCst),
        1,
        "exactly one same-key push executes"
    );
    assert!(
        !exit_a.operation_ids.is_empty(),
        "the live run names its operations"
    );
    assert_eq!(
        exit_a.operation_ids, exit_b.operation_ids,
        "the replay reports the same operations"
    );

    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn host_disconnect_mid_publish_still_records_receipt() {
    let root = temp_root("host-gone");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();
    seed_store(&repo);
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let (pack, commit) = hosted_chain_pack(23);

    let (mut driver, registry, task) = spawn_hosted(&root, 10_000);
    handshake(&mut driver).await;
    let peer_uid = driver.conn.peer_cred().expect("peer credentials").uid();
    let session = open_push_session(&mut driver, &store_repo, &["refs/heads/**"]).await;
    let zero = "0".repeat(40);
    let mut body = pkt(format!(
        "{zero} {commit} refs/heads/gone\n",
        commit = commit.to_hex()
    )
    .as_bytes());
    body.extend_from_slice(&flush());
    body.extend_from_slice(&pack);
    let payload = git_open_payload(
        "receive-pack",
        &store_repo,
        false,
        Some(&session),
        Some("req-hosted-gone-1"),
    );
    driver.send(FrameKind::Open, 5, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Stdin, 5, &body).await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    driver.send(FrameKind::StdinEof, 5, &[]).await;
    loop {
        let frame = driver.recv().await;
        assert_eq!(frame.stream_id, 5);
        match frame.kind {
            FrameKind::HookCall => {
                let call: HookCall =
                    ipc::decode_control(&frame.payload).expect("hook call decodes");
                assert_eq!(call.phase, HookPhase::PreReceive);
                let reply = accept_all(&call).expect("hook reply answered");
                let bytes = ipc::encode_control(&reply).expect("hook reply encodes");
                driver.send(FrameKind::HookReply, 5, &bytes).await;
                break;
            }
            FrameKind::Exit | FrameKind::Error => panic!("push ended before the hook answered"),
            _ => {}
        }
    }
    drop(driver);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (_, canonical, coordinator) = registry.open(&store_repo).expect("open coordinator");
        let landed = ruk_core::refs::StoreRefs::new(coordinator.store())
            .get(&RefName::new("refs/heads/gone".to_string()).expect("ref name"))
            .expect("read ref");
        let receipt = ruk_core::coord::service_receipts::lookup_service_receipt(
            coordinator.store(),
            peer_uid,
            canonical.as_os_str().as_bytes(),
            "req-hosted-gone-1",
        )
        .expect("read receipt");
        if landed == Some(RefTarget::Direct(commit)) && receipt.is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the publish completes and a receipt is recorded after disconnect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    task.abort();
}

#[tokio::test]
async fn typed_reply_waits_for_outbound_credit() {
    let root = temp_root("credit-wait");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair_with_window(&root, 1024);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let typed = Driver::typed_open(&store_repo, "schema", None, None, None);
    driver.send(FrameKind::Open, 3, &typed).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    assert_eq!(accepted.stream_id, 3);

    let mut body = Vec::new();
    let mut chunks = 0;
    loop {
        let grant = r#"{"credit_bytes":65536,"direction":"stdout"}"#;
        driver
            .send(FrameKind::WindowUpdate, 3, grant.as_bytes())
            .await;
        let frame = driver.recv().await;
        assert_eq!(frame.stream_id, 3);
        match frame.kind {
            FrameKind::Stdout => {
                chunks += 1;
                body.extend_from_slice(&frame.payload);
            }
            FrameKind::Exit => {
                let exit: ExitReport =
                    ipc::decode_control(&frame.payload).expect("typed exit decodes");
                assert_eq!(exit.status, 0);
                assert_eq!(exit.code, "OK");
                break;
            }
            FrameKind::Error => panic!(
                "typed stream refused instead of waiting: {}",
                String::from_utf8_lossy(&frame.payload)
            ),
            other => panic!("unexpected frame {other:?} on typed stream 3"),
        }
    }
    assert!(
        body.len() > 1024,
        "the reply exceeds the window and still completes: {} bytes in {chunks} chunks",
        body.len()
    );
    assert!(chunks > 1, "a large body streams in many chunks");

    drop(driver);
    task.abort();
}

/// Finds the end of the advertisement prefix: the first flush packet.
fn find_flush(output: &[u8]) -> Option<usize> {
    let mut rest = output;
    let mut offset = 0;
    while rest.len() >= 4 {
        let len = usize::from_str_radix(std::str::from_utf8(&rest[..4]).ok()?, 16).ok()?;
        if len == 0 {
            return Some(offset + 4);
        }
        if len < 4 || rest.len() < len {
            return None;
        }
        rest = &rest[len..];
        offset += len;
    }
    None
}

#[test]
fn error_frame_carries_full_reply_and_reads_old_payloads() {
    let reply = ErrorReply::from_core(
        &CoreError::new(ErrorCode::EStale, "stamp moved").with_hint("re-read"),
    )
    .with_fix(Fix::NewRequestId)
    .with_detail(ErrorDetail::Push {
        plan: PlanId::generate(),
        state: PushState::Uncertain,
        refs: BoundedList::complete(vec![PushRefOutcome {
            remote_ref: RefName::new("refs/heads/main").expect("ref name"),
            status: PushRefStatus::Uncertain,
        }])
        .expect("refs"),
    });
    let bytes = ipc::encode_control(&reply).expect("error encodes");
    let decoded: ErrorReply = ipc::decode_control(&bytes).expect("error decodes");
    assert_eq!(decoded, reply);
    assert_eq!(decoded.hints, vec!["re-read".to_string()]);
    assert_eq!(decoded.fixes, vec![Fix::NewRequestId]);
    assert!(matches!(decoded.detail, Some(ErrorDetail::Push { .. })));

    let old = br#"{"code":"E_INVALID","message":"bad"}"#;
    let legacy: ErrorReply = ipc::decode_control(old).expect("old error decodes");
    assert_eq!(legacy.code, ErrorCode::EInvalid);
    assert_eq!(legacy.message, "bad");
    assert!(legacy.hints.is_empty());
    assert!(legacy.fixes.is_empty());
    assert_eq!(legacy.detail, None);
}

/// Decodes typed stdout as a success [`ReplyEnvelope`].
fn typed_success(stdout: &[u8]) -> ReplyEnvelope {
    let envelope: ReplyEnvelope = ipc::decode_control(stdout).expect("reply envelope decodes");
    let ReplyBody::Success(_) = &envelope.body else {
        panic!("expected a success envelope, got {envelope:?}");
    };
    envelope
}

#[tokio::test]
async fn typed_dispatch_serves_covered_read_and_mutation() {
    let root = temp_root("typed");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    // Typed invocations name the store directory itself, where the format
    // file lives — not the worktree root around it.
    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let repo = store_repo;

    // `session.open` answers the session the later calls run under.
    let payload = Driver::typed_open(&repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    assert!(!opened.principal.is_empty());
    let session = opened.session.to_string();

    // A covered read with a live session succeeds; the fresh log is empty.
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    assert_eq!(envelope.request_id, None);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert!(reply.entries.items.is_empty());
    assert_eq!(reply.oldest_retained, None);

    // An unknown session is forbidden, not refused as sessionless.
    let unknown = SessionId::generate().to_string();
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&unknown),
    );
    let (report, _) = driver.expect_typed_refused(7, &payload).await;
    assert_eq!(report.code.as_str(), "E_FORBIDDEN");

    // A missing session keeps the sessionless refusal.
    let payload = Driver::typed_open(&repo, "op.log", None, Some("{}".to_string()), None);
    let (report, _) = driver.expect_typed_refused(9, &payload).await;
    assert_eq!(report.code.as_str(), "E_INVALID");

    // A malformed session id is invalid, never forbidden.
    let payload = Driver::typed_open(&repo, "op.log", None, Some("{}".to_string()), Some("nope"));
    let (report, _) = driver.expect_typed_refused(11, &payload).await;
    assert_eq!(report.code.as_str(), "E_INVALID");

    // A covered mutation prepares, publishes, and names its request id.
    let tag_args = TagSetArgs {
        name: RefName::new("refs/tags/v1").expect("tag name"),
        target: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
        annotation: None,
        expected: RefExpect::Absent,
    };
    let args_json = sonic_rs::to_string(&tag_args).expect("tag args encode");
    let mutation_id = RequestId::generate().to_string();
    let payload = Driver::typed_open(
        &repo,
        "tag.set",
        Some(&mutation_id),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(13, &payload).await;
    let envelope = typed_success(&stdout);
    assert_eq!(
        envelope.request_id.map(|id| id.to_string()),
        Some(mutation_id.clone())
    );
    let ReplyBody::Success(Reply::TagSet(_)) = envelope.body else {
        panic!("tag.set must answer its own reply");
    };

    // The effect landed: the log now records the mutation.
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(15, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(reply.entries.items.len(), 1);
    assert_eq!(reply.entries.items[0].method, Method::TagSet);
    assert!(reply.oldest_retained.is_some());

    // A second covered mutation lets the log prove newest-first order and
    // that oldest names the first operation, not the latest.
    let bookmark_args = BookmarkSetArgs {
        name: RefName::new("refs/heads/main").expect("bookmark name"),
        target: BookmarkTarget::Commit {
            oid: Oid::from_bytes(&[0x22; 20]).expect("bookmark target"),
        },
        expected: RefExpect::Absent,
    };
    let args_json = sonic_rs::to_string(&bookmark_args).expect("bookmark args encode");
    let payload = Driver::typed_open(
        &repo,
        "bookmark.set",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(16, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::BookmarkSet(_)) = envelope.body else {
        panic!("bookmark.set must answer its own reply");
    };
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(18, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(reply.entries.items.len(), 2);
    assert_eq!(reply.entries.items[0].method, Method::BookmarkSet);
    assert_eq!(reply.entries.items[1].method, Method::TagSet);
    assert_eq!(reply.oldest_retained, Some(reply.entries.items[1].id));

    // A newly covered read answers over the socket pair: the claim listing
    // starts empty on this store.
    let payload = Driver::typed_open(
        &repo,
        "claim.list",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(17, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimList(list)) = envelope.body else {
        panic!("claim.list must answer its own reply");
    };
    assert!(list.claims.items.is_empty());
    assert!(list.claims.next.is_none());

    // The attestation listing answers the same way.
    let payload = Driver::typed_open(
        &repo,
        "attest.list",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(19, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::AttestList(attest)) = envelope.body else {
        panic!("attest.list must answer its own reply");
    };
    assert!(attest.records.items.is_empty());
    assert!(attest.records.next.is_none());

    // `status` is now served: without a workspace it names the missing
    // workspace instead of a missing implementation.
    let payload = Driver::typed_open(
        &repo,
        "status",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(23, &payload).await;
    assert_eq!(report.code.as_str(), "E_INVALID");
    assert!(
        report.message.contains("explicit native workspace"),
        "unexpected message: {}",
        report.message
    );

    // Validation still runs before the coverage check: an uncovered read
    // with an over-long cursor position refuses as invalid, never hosted.
    let bad_cursor = PageCursor {
        store: StoreId::generate(),
        view: OperationId(0),
        query: QueryDigest::from_bytes([0x22; 32]),
        lease: LeaseId::generate(),
        position: ByteString::from(vec![b'a'; 5000]),
    };
    let bad_status = StatusArgs {
        page: PageRequest {
            limit: None,
            cursor: Some(bad_cursor),
        },
        ..Default::default()
    };
    let payload = Driver::typed_open(
        &repo,
        "status",
        None,
        Some(sonic_rs::to_string(&bad_status).expect("status args encode")),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(25, &payload).await;
    assert_eq!(report.code.as_str(), "E_INVALID");

    // A covered mutation with an unsatisfiable precondition reports it:
    // `pin` prepares, but the fixture head was never stored.
    let pin_args = PinArgs {
        head: Head::Git {
            oid: Oid::from_bytes(&[0x11; 20]).expect("pin target"),
        },
    };
    let args_json = sonic_rs::to_string(&pin_args).expect("pin args encode");
    let payload = Driver::typed_open(
        &repo,
        "pin",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(27, &payload).await;
    assert_eq!(report.code.as_str(), "E_NOT_FOUND");

    // The session check runs before preparation: an uncovered method with
    // an unknown session reports forbidden, never the missing preparation.
    let payload = Driver::typed_open(
        &repo,
        "pin",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&pin_args).expect("pin args encode")),
        Some(&SessionId::generate().to_string()),
    );
    let (report, _) = driver.expect_typed_refused(29, &payload).await;
    assert_eq!(report.code.as_str(), "E_FORBIDDEN");

    drop(driver);
    task.abort();
}

/// Socket-level proof that an annotated `tag.set` renders its tag object
/// through the dispatch context: the ref points at the tag object rather
/// than the target commit, and the log records the mutation.
#[tokio::test]
async fn typed_dispatch_serves_annotated_tag_set() {
    let root = temp_root("typed-tag");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let repo = store_repo;

    // An annotated tag renders `type commit`, so the target must be a stored
    // commit before the session opens and the daemon binds the store.
    let target = seed_commit(&repo_dir);

    let payload = Driver::typed_open(&repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let tag_args = TagSetArgs {
        name: RefName::new("refs/tags/v1").expect("tag name"),
        target,
        annotation: Some(TagAnnotation {
            tagger: Some(IdentityClaim {
                name: "Tag".to_string(),
                email: "tag@example.invalid".to_string(),
            }),
            message: ByteString::from("annotated"),
        }),
        expected: RefExpect::Absent,
    };
    let args_json = sonic_rs::to_string(&tag_args).expect("tag args encode");
    let mutation_id = RequestId::generate().to_string();
    let payload = Driver::typed_open(
        &repo,
        "tag.set",
        Some(&mutation_id),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    assert_eq!(
        envelope.request_id.map(|id| id.to_string()),
        Some(mutation_id)
    );
    let ReplyBody::Success(Reply::TagSet(reply)) = envelope.body else {
        panic!("tag.set must answer its own reply");
    };
    let RefTarget::Direct(tag_oid) = reply.target else {
        panic!("annotated tag.set must point at its tag object");
    };
    assert_ne!(tag_oid, target, "the ref moves to the tag object");

    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(log)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(log.entries.items.len(), 1);
    assert_eq!(log.entries.items[0].method, Method::TagSet);

    drop(driver);
    task.abort();
}

/// Socket-level proof that `op.log` pages through its lease: a bounded first
/// page mints a cursor and the presented cursor resumes to exhaustion.
#[tokio::test]
async fn typed_oplog_continuation_pages_through_its_lease() {
    let root = temp_root("oplog-pages");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();
    let repo = store_repo;

    let payload = Driver::typed_open(&repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    for (stream, name) in [(5, "refs/tags/c1"), (7, "refs/tags/c2")] {
        let tag_args = TagSetArgs {
            name: RefName::new(name).expect("tag name"),
            target: Oid::from_bytes(&[0x11; 20]).expect("tag target"),
            annotation: None,
            expected: RefExpect::Absent,
        };
        let args_json = sonic_rs::to_string(&tag_args).expect("tag args encode");
        let payload = Driver::typed_open(
            &repo,
            "tag.set",
            Some(&RequestId::generate().to_string()),
            Some(args_json),
            Some(&session),
        );
        let (stdout, _) = driver.run_typed(stream, &payload).await;
        let envelope = typed_success(&stdout);
        let ReplyBody::Success(Reply::TagSet(_)) = envelope.body else {
            panic!("tag.set must answer its own reply");
        };
    }

    let first_args = OpLogArgs {
        session: None,
        after: None,
        page: PageRequest {
            limit: Some(PageLimit::new(1).expect("page limit 1")),
            cursor: None,
        },
    };
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some(sonic_rs::to_string(&first_args).expect("op.log args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(first)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(first.entries.items.len(), 1);
    let cursor = first.entries.next.clone().expect("first page continues");

    let second_args = OpLogArgs {
        session: None,
        after: None,
        page: PageRequest {
            limit: Some(PageLimit::new(1).expect("page limit 1")),
            cursor: Some(cursor),
        },
    };
    let payload = Driver::typed_open(
        &repo,
        "op.log",
        None,
        Some(sonic_rs::to_string(&second_args).expect("op.log args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(11, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(second)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(second.entries.items.len(), 1);
    assert!(second.entries.next.is_none());
    assert_ne!(second.entries.items[0].id, first.entries.items[0].id);
    assert!(first.entries.items[0].id.0 > second.entries.items[0].id.0);
    assert_eq!(second.view, first.view);
    assert_eq!(second.oldest_retained, Some(second.entries.items[0].id));

    drop(driver);
    task.abort();
}

/// Socket-level proof that `new` mints an empty-tree change: the signature
/// comes from the session identity, and every call mints a fresh change.
#[tokio::test]
async fn typed_new_mints_change_with_session_identity() {
    let root = temp_root("typed-new");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let open_args = SessionOpenArgs {
        identity: Some(IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }),
        ..SessionOpenArgs::default()
    };
    let payload = Driver::typed_open(
        &store_repo,
        "session.open",
        None,
        Some(sonic_rs::to_string(&open_args).expect("open args encode")),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let submit_new = async |driver: &mut Driver,
                            stream: u64,
                            description: &str|
           -> ruk_core::protocol::NewReply {
        let new_args = NewArgs {
            parents: Vec::new(),
            description: ByteString::from(description),
            identity: None,
            workspace: None,
        };
        let args_json = sonic_rs::to_string(&new_args).expect("new args encode");
        let payload = Driver::typed_open(
            &store_repo,
            "new",
            Some(&RequestId::generate().to_string()),
            Some(args_json),
            Some(&session),
        );
        let (stdout, _) = driver.run_typed(stream, &payload).await;
        let envelope = typed_success(&stdout);
        let ReplyBody::Success(Reply::New(reply)) = envelope.body else {
            panic!("new must answer its own reply");
        };
        *reply
    };

    let first = submit_new(&mut driver, 5, "typed new").await;
    let identity = first
        .outcome
        .identity
        .expect("new reports its recorded identity");
    assert_eq!(identity.name, "Ada");
    let second = submit_new(&mut driver, 7, "typed new again").await;
    assert_ne!(
        second.created.change, first.created.change,
        "every new mints a fresh change"
    );

    // Both mints published: the log records two `new` operations.
    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(reply.entries.items.len(), 2);
    assert!(
        reply
            .entries
            .items
            .iter()
            .all(|entry| entry.method == Method::New)
    );

    drop(driver);
    task.abort();
}

/// Socket-level proof that `new` without any identity is invalid, not
/// hosted: no configuration ladder exists for the coordinator to consult.
#[tokio::test]
async fn typed_new_without_identity_is_invalid() {
    let root = temp_root("typed-new-bare");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let new_args = NewArgs {
        parents: Vec::new(),
        description: ByteString::from("nobody"),
        identity: None,
        workspace: None,
    };
    let args_json = sonic_rs::to_string(&new_args).expect("new args encode");
    let payload = Driver::typed_open(
        &store_repo,
        "new",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(5, &payload).await;
    assert_eq!(report.code.as_str(), "E_INVALID");

    // The refusal published nothing: the log stays empty.
    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert!(reply.entries.items.is_empty());

    drop(driver);
    task.abort();
}

/// Socket-level proof that `claim.acquire` seals in the lane with the
/// prepared id, and `claim.release` drops the same record.
#[tokio::test]
async fn typed_claim_acquire_and_release_round_trip() {
    let root = temp_root("typed-claim");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let acquire_args = ClaimAcquireArgs {
        paths: vec![RepoPath::new("src").expect("test path")],
        ttl: ClaimTtl::new(60).expect("ttl"),
        mode: ClaimMode::Enforce,
    };
    let args_json = sonic_rs::to_string(&acquire_args).expect("acquire args encode");
    let payload = Driver::typed_open(
        &store_repo,
        "claim.acquire",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimAcquire(acquired)) = envelope.body else {
        panic!("claim.acquire must answer its own reply");
    };

    // The acquire sealed in the lane: `claim.list` serves the sealed record.
    let payload = Driver::typed_open(
        &store_repo,
        "claim.list",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(6, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimList(listed)) = envelope.body else {
        panic!("claim.list must answer its own reply");
    };
    assert_eq!(listed.claims.items.len(), 1);
    assert_eq!(listed.claims.items[0], acquired.claim);

    let release_args = ClaimReleaseArgs {
        claim: acquired.claim.claim,
    };
    let args_json = sonic_rs::to_string(&release_args).expect("release args encode");
    let payload = Driver::typed_open(
        &store_repo,
        "claim.release",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimRelease(released)) = envelope.body else {
        panic!("claim.release must answer its own reply");
    };
    assert_eq!(released.released, acquired.claim);

    // The release sealed in the lane: the list is empty again.
    // (`op.log` stays silent by design — the Claims table is untracked.)
    let payload = Driver::typed_open(
        &store_repo,
        "claim.list",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::ClaimList(listed)) = envelope.body else {
        panic!("claim.list must answer its own reply");
    };
    assert!(listed.claims.items.is_empty(), "release dropped the claim");

    drop(driver);
    task.abort();
}

/// Socket-level proof that `ws.new` creates a native workspace row without
/// materializing a worktree.
#[tokio::test]
async fn typed_ws_new_creates_workspace() {
    let root = temp_root("typed-wsnew");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let open_args = SessionOpenArgs {
        identity: Some(IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }),
        ..SessionOpenArgs::default()
    };
    let payload = Driver::typed_open(
        &store_repo,
        "session.open",
        None,
        Some(sonic_rs::to_string(&open_args).expect("open args encode")),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let ws_args = WsNewArgs {
        root: ByteString::from("/tmp/ruk-daemon-wsnew"),
        init: WorkspaceInit::Native {
            parents: Vec::new(),
        },
        scope: None,
    };
    let args_json = sonic_rs::to_string(&ws_args).expect("ws.new args encode");
    let payload = Driver::typed_open(
        &store_repo,
        "ws.new",
        Some(&RequestId::generate().to_string()),
        Some(args_json),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::WsNew(created)) = envelope.body else {
        panic!("ws.new must answer its own reply");
    };
    assert_ne!(
        created.workspace,
        ruk_core::change::WorkspaceId::nil(),
        "ws.new mints a fresh workspace"
    );

    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(reply)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(reply.entries.items.len(), 1);
    assert_eq!(reply.entries.items[0].method, Method::WsNew);

    drop(driver);
    task.abort();
}

/// Socket-level proof that `describe` rewrites a message through the lane:
/// one rewrite, the identity reported, and the operation logged.
#[tokio::test]
async fn typed_describe_rewrites_message() {
    let root = temp_root("typed-describe");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let open_args = SessionOpenArgs {
        identity: Some(IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }),
        ..SessionOpenArgs::default()
    };
    let payload = Driver::typed_open(
        &store_repo,
        "session.open",
        None,
        Some(sonic_rs::to_string(&open_args).expect("open args encode")),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let new_args = NewArgs {
        parents: Vec::new(),
        description: ByteString::from("before"),
        identity: None,
        workspace: None,
    };
    let payload = Driver::typed_open(
        &store_repo,
        "new",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&new_args).expect("new args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::New(created)) = envelope.body else {
        panic!("new must answer its own reply");
    };

    let describe_args = DescribeArgs {
        target: ChangeRef {
            change: created.created.change,
            head: None,
        },
        description: ByteString::from("after"),
        identity: None,
        workspaces: Vec::new(),
    };
    let payload = Driver::typed_open(
        &store_repo,
        "describe",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&describe_args).expect("describe args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::Describe(rewritten)) = envelope.body else {
        panic!("describe must answer its own reply");
    };
    assert_eq!(rewritten.rewrites.items.len(), 1);
    assert_eq!(rewritten.rewrites.items[0].old, created.created.head);
    assert_ne!(rewritten.rewrites.items[0].new, created.created.head);
    assert!(rewritten.abandoned.items.is_empty());
    let identity = rewritten
        .outcome
        .identity
        .expect("describe reports the session identity");
    assert_eq!(identity.name, "Ada");

    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(log)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(log.entries.items.len(), 2);
    assert_eq!(log.entries.items[0].method, Method::Describe);
    assert_eq!(log.entries.items[1].method, Method::New);

    drop(driver);
    task.abort();
}

/// Socket-level proof that `split` reaches preparation and refuses an unstored
/// source by name: the source resolves before any tree is derived.
#[tokio::test]
async fn typed_split_of_unstored_change_refuses_not_found() {
    let root = temp_root("typed-split");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let split_args = SplitArgs {
        source: ChangeRef {
            change: ruk_core::change::ChangeId::from_bytes([0x22; 16]),
            head: None,
        },
        paths: PathSelection::Paths(vec![RepoPath::new("x").expect("test path")]),
        placement: SplitPlacement::SelectedFirst,
        description: ByteString::from("part"),
        identity: None,
        merge: ruk_core::protocol::MergeSelection::default(),
        workspaces: Vec::new(),
    };
    let payload = Driver::typed_open(
        &store_repo,
        "split",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&split_args).expect("split args encode")),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(5, &payload).await;
    assert_eq!(report.code.as_str(), "E_NOT_FOUND");
    assert!(
        report.message.contains("is not stored"),
        "split resolves its source before partitioning: {}",
        report.message
    );

    drop(driver);
    task.abort();
}

/// Socket-level proof that `edit` checks a change out into a workspace
/// through the lane: the state moves onto the new head, the stamp advances,
/// and the operation is logged.
#[tokio::test]
async fn typed_edit_checks_out_change() {
    let root = temp_root("typed-edit");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let open_args = SessionOpenArgs {
        identity: Some(IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }),
        ..SessionOpenArgs::default()
    };
    let payload = Driver::typed_open(
        &store_repo,
        "session.open",
        None,
        Some(sonic_rs::to_string(&open_args).expect("open args encode")),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let new_args = NewArgs {
        parents: Vec::new(),
        description: ByteString::from("before"),
        identity: None,
        workspace: None,
    };
    let payload = Driver::typed_open(
        &store_repo,
        "new",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&new_args).expect("new args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::New(created)) = envelope.body else {
        panic!("new must answer its own reply");
    };

    let ws_args = WsNewArgs {
        root: ByteString::from("/tmp/ruk-daemon-w4"),
        init: WorkspaceInit::Native {
            parents: Vec::new(),
        },
        scope: None,
    };
    let payload = Driver::typed_open(
        &store_repo,
        "ws.new",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&ws_args).expect("ws.new args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(7, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::WsNew(workspaced)) = envelope.body else {
        panic!("ws.new must answer its own reply");
    };

    let edit_args = EditArgs {
        binding: WorkspaceBinding {
            workspace: workspaced.workspace,
            expected: workspaced.state.stamp(),
        },
        target: ChangeRef {
            change: created.created.change,
            head: None,
        },
    };
    let payload = Driver::typed_open(
        &store_repo,
        "edit",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&edit_args).expect("edit args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(9, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::Edit(edited)) = envelope.body else {
        panic!("edit must answer its own reply");
    };
    let ruk_core::workspace::WorkspaceState::Native(next) = &edited.state else {
        panic!("edit of a native workspace stays native");
    };
    assert_eq!(next.head, created.created.head);
    assert_eq!(next.change, created.created.change);
    assert_eq!(next.stamp.sequence, workspaced.state.stamp().sequence + 1);

    let payload = Driver::typed_open(
        &store_repo,
        "op.log",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(11, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::OpLog(log)) = envelope.body else {
        panic!("op.log must answer its own reply");
    };
    assert_eq!(log.entries.items.len(), 3);
    assert_eq!(log.entries.items[0].method, Method::Edit);

    drop(driver);
    task.abort();
}

/// Socket-level proof that `snapshot` stays honestly refused: capturing the
/// worktree needs the prepare/job split with no producer on this path.
#[tokio::test]
async fn typed_snapshot_refusal_names_job_split() {
    let root = temp_root("typed-snapshot");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let open_args = SessionOpenArgs {
        identity: Some(IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }),
        ..SessionOpenArgs::default()
    };
    let payload = Driver::typed_open(
        &store_repo,
        "session.open",
        None,
        Some(sonic_rs::to_string(&open_args).expect("open args encode")),
        None,
    );
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let ws_args = WsNewArgs {
        root: ByteString::from("/tmp/ruk-daemon-w4-snapshot"),
        init: WorkspaceInit::Native {
            parents: Vec::new(),
        },
        scope: None,
    };
    let payload = Driver::typed_open(
        &store_repo,
        "ws.new",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&ws_args).expect("ws.new args encode")),
        Some(&session),
    );
    let (stdout, _) = driver.run_typed(5, &payload).await;
    let envelope = typed_success(&stdout);
    let ReplyBody::Success(Reply::WsNew(workspaced)) = envelope.body else {
        panic!("ws.new must answer its own reply");
    };

    let snapshot_args = SnapshotArgs {
        binding: WorkspaceBinding {
            workspace: workspaced.workspace,
            expected: workspaced.state.stamp(),
        },
    };
    let payload = Driver::typed_open(
        &store_repo,
        "snapshot",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&snapshot_args).expect("snapshot args encode")),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(7, &payload).await;
    assert_eq!(report.code.as_str(), "E_HOSTED");
    assert!(
        report.message.contains("workcopy::snapshot"),
        "snapshot names its missing producer: {}",
        report.message
    );

    drop(driver);
    task.abort();
}

/// Socket-level proof that `fetch` stays honestly refused: staging remote
/// objects plus the transfer runs in a transport job with no producer here.
#[tokio::test]
async fn typed_fetch_refusal_names_transport_job() {
    let root = temp_root("typed-fetch");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let fetch_args = FetchArgs {
        remote: RemoteSpec::Named {
            name: RemoteName::new("origin").expect("remote name"),
        },
        refs: FetchRefs::AllBranches,
        depth: None,
        filter: FetchFilter::default(),
    };
    let payload = Driver::typed_open(
        &store_repo,
        "fetch",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&fetch_args).expect("fetch args encode")),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(5, &payload).await;
    assert_eq!(report.code.as_str(), "E_HOSTED");
    assert!(
        report.message.contains("transport job"),
        "fetch names its missing job: {}",
        report.message
    );

    drop(driver);
    task.abort();
}

/// Socket-level proof that `land.execute` stays honestly refused: the local
/// leg publishes eagerly outside the lane and the remote leg lives in
/// transport, so no prepare/job split exists on this path.
#[tokio::test]
async fn typed_land_execute_refusal_names_plan() {
    let root = temp_root("typed-land-execute");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    seed_store(&repo);

    let store_repo = repo_dir
        .join(".ruk")
        .to_str()
        .expect("utf8 store repo")
        .to_string();

    let payload = Driver::typed_open(&store_repo, "session.open", None, None, None);
    let (stdout, _) = driver.run_typed(3, &payload).await;
    let opened: SessionOpened = ipc::decode_control(&stdout).expect("session opened decodes");
    let session = opened.session.to_string();

    let execute_args = LandExecuteArgs {
        plan: PlanId::generate(),
        candidate: Oid::from_bytes(&[0x31; 20]).expect("candidate oid"),
    };
    let payload = Driver::typed_open(
        &store_repo,
        "land.execute",
        Some(&RequestId::generate().to_string()),
        Some(sonic_rs::to_string(&execute_args).expect("land.execute args encode")),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(5, &payload).await;
    assert_eq!(report.code.as_str(), "E_NOT_FOUND");
    assert!(
        report.message.contains("unknown land plan"),
        "land.execute names the missing plan: {}",
        report.message
    );

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn admin_dispatch_serves_repo_lifecycle_before_any_coordinator_call() {
    use ruk_core::coord::{Principal, cancellation};

    use super::{Caller, InvocationOpen, dispatch_admin, registry::Registry};

    let root = temp_root("admin-dispatch");
    let registry = Registry::new(vec![root.clone()]).expect("registry opens");
    let root_str = root.to_str().expect("utf8 root").to_owned();
    let init_args = ruk_core::protocol::RepoInitArgs {
        root: root_str,
        path: "acme/hello".to_owned(),
        object_format: None,
        default_branch: None,
    };
    let open = InvocationOpen {
        repo: String::new(),
        method: "repo.init".to_string(),
        request_id: None,
        args_json: Some(sonic_rs::to_string(&init_args).expect("init args encode")),
        session_id: None,
        on_behalf_of: None,
        transport_auth: TransportAuth::default(),
    };
    let (_handle, cancel) = cancellation();
    let _ = &cancel;
    let admin = Caller {
        principal: &Principal::from_peer_uid(1000),
        admin_uids: &[1000],
    };
    let bytes = dispatch_admin(&registry, admin, &open, Method::RepoInit)
        .await
        .expect("admin repo.init serves");
    let envelope: ReplyEnvelope = ipc::decode_control(&bytes).expect("reply decodes");
    let ReplyBody::Success(Reply::RepoInit(created)) = envelope.body else {
        panic!("repo.init must answer its own reply");
    };
    assert!(created.path.ends_with("acme/hello"));
    assert_eq!(
        created.default_branch.as_bytes(),
        b"refs/heads/main",
        "daemon default branch records",
    );
    let outsider = Caller {
        principal: &Principal::from_peer_uid(2000),
        admin_uids: &[1000],
    };
    let err = dispatch_admin(&registry, outsider, &open, Method::RepoInit)
        .await
        .expect_err("non-admin refused");
    assert_eq!(err.code, ErrorCode::EForbidden);
    let forked = InvocationOpen {
        repo: String::new(),
        method: "repo.fork".to_string(),
        request_id: None,
        args_json: Some("{\"source\":\"acme/hello\",\"path\":\"acme/fork\"}".to_string()),
        session_id: None,
        on_behalf_of: None,
        transport_auth: TransportAuth::default(),
    };
    let admin = Caller {
        principal: &Principal::from_peer_uid(1000),
        admin_uids: &[1000],
    };
    let err = dispatch_admin(&registry, admin, &forked, Method::RepoFork)
        .await
        .expect_err("unserved admin refuses");
    assert_eq!(err.code, ErrorCode::EHosted);
}

#[tokio::test]
async fn largest_served_tail_page_fits_control_bound() {
    use ruk_core::coord::{HostedCoordinator, Principal, cancellation};

    use super::{Caller, InvocationOpen, dispatch_method};

    let root = temp_root("tail-bound");
    seed_store(root.to_str().expect("utf8 root"));
    let budget = Arc::new(PreparationBudget::reference_defaults());
    let store = Arc::new(Store::open(&root.join(".ruk"), budget).expect("open store"));
    let peer = Principal::from_peer_uid(1000);
    let coordinator = Arc::new(
        HostedCoordinator::open(Arc::clone(&store), peer.clone(), root.clone())
            .expect("open coordinator"),
    );
    let oid = Oid::from_bytes(&[0x31; 20]).expect("oid");
    let updates: Vec<ruk_core::refdata::RefUpdate> = (0..1000u32)
        .map(|index| ruk_core::refdata::RefUpdate {
            name: RefName::new(format!("refs/heads/b{index:04}")).expect("ref name"),
            expected: ruk_core::refdata::RefExpect::Absent,
            change: ruk_core::refdata::RefChange::Set(ruk_core::refdata::RefTarget::Direct(oid)),
        })
        .collect();
    let transaction =
        ruk_core::refdata::RefTransaction::new(ruk_core::ids::HashKind::Sha1, updates)
            .expect("ref transaction");
    let prepared =
        ruk_core::refs::prepare_checked_transaction(&store, &transaction).expect("prepare refs");
    store
        .publish(
            Vec::new(),
            &prepared.into_mutations(),
            EventSource::ReceivePack,
            &EventContext::default(),
        )
        .expect("publish refs");

    let _runner = coordinator
        .spawn_on(&tokio::runtime::Handle::current())
        .expect("spawn lane");
    let (_handle, cancel) = cancellation();
    let (session, _) = coordinator
        .open_session(&peer, &SessionOpenArgs::default(), &cancel)
        .await
        .expect("open session");
    let open = InvocationOpen {
        repo: String::new(),
        method: "events.tail".to_string(),
        request_id: None,
        args_json: Some("{\"after\":0,\"limit\":1000}".to_string()),
        session_id: Some(session.to_string()),
        on_behalf_of: None,
        transport_auth: TransportAuth::default(),
    };
    let caller = Caller {
        principal: &peer,
        admin_uids: &[],
    };
    let bytes = dispatch_method(
        &coordinator,
        caller,
        &open,
        Method::EventsTail,
        Some(session),
        &cancel,
    )
    .await
    .expect("maximal tail page encodes");
    assert!(
        bytes.len() < ipc::MAX_IPC_CONTROL_BYTES,
        "1000-event page uses {} of {} control bytes",
        bytes.len(),
        ipc::MAX_IPC_CONTROL_BYTES
    );
    let envelope: ReplyEnvelope = ipc::decode_control(&bytes).expect("reply decodes");
    let ReplyBody::Success(Reply::EventsTail(tail)) = envelope.body else {
        panic!("events.tail must answer its own reply");
    };
    assert_eq!(tail.events.len(), 1000);
}

/// Cancelling the task awaiting `run` must not free its bulkhead permit
/// while the detached worker still runs: the permit belongs to the
/// worker, not the waiter. Otherwise every aborted stream would hand its
/// permit to the next waiter while its blocking serve still occupies a
/// thread, and the bulkhead would admit more workers than it holds
/// permits for.
#[tokio::test]
async fn cancelled_run_keeps_its_permit_until_the_worker_finishes() {
    use super::executor::BoundedExecutor;
    let executor = BoundedExecutor::new(1).expect("one permit");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let waiter = tokio::spawn({
        let executor = executor.clone();
        async move {
            executor
                .run(move || {
                    started_tx.send(()).expect("test waits for start");
                    release_rx.blocking_recv().expect("test releases worker");
                    7u32
                })
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(10), started_rx)
        .await
        .expect("worker starts")
        .expect("start signal arrives");
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(
        executor.available(),
        0,
        "the detached worker keeps its permit"
    );
    release_tx.send(()).expect("release worker");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while executor.available() != 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "the permit returns after the worker finishes"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[test]
fn injected_auth_never_enters_the_service_digest() {
    use ruk_git::transport::credentials::{TransportAuth, TransportAuthKind};

    let authed = InvocationOpen {
        repo: "acme/hello".to_owned(),
        method: "push".to_owned(),
        request_id: Some("req-1".to_owned()),
        args_json: None,
        session_id: None,
        on_behalf_of: None,
        transport_auth: TransportAuth {
            kind: TransportAuthKind::Bearer,
            credential: "tok_s3cret".to_owned(),
            origin: "https://host.x:443".to_owned(),
        },
    };
    let frame = sonic_rs::to_vec(&authed).expect("authed open encodes");
    let decoded: InvocationOpen = sonic_rs::from_slice(&frame).expect("authed open decodes");
    let undo = || {
        Request::Undo(Box::new(Mutation {
            request_id: RequestId::generate(),
            args: UndoArgs {
                operation: OperationId(7),
            },
        }))
    };
    let anonymous = super::invocation_digest(&undo(), &TransportAuth::none())
        .expect("encodable")
        .expect("a mutation digests");
    assert!(
        decoded
            .transport_auth
            .header_for("https://host.x/r.git")
            .is_some()
    );
    let carried = super::invocation_digest(&undo(), &decoded.transport_auth)
        .expect("encodable")
        .expect("a mutation digests");
    assert_eq!(anonymous, carried);
    let moved = super::invocation_digest(
        &Request::Undo(Box::new(Mutation {
            request_id: RequestId::generate(),
            args: UndoArgs {
                operation: OperationId(8),
            },
        })),
        &decoded.transport_auth,
    )
    .expect("encodable")
    .expect("a mutation digests");
    assert_ne!(anonymous, moved);
    let half = TransportAuth {
        kind: TransportAuthKind::Bearer,
        credential: String::new(),
        origin: "https://host.x:443".to_owned(),
    };
    super::invocation_digest(&undo(), &half).expect_err("half-specified auth fails closed");
    let rendered = format!("{decoded:?}");
    assert!(!rendered.contains("tok_s3cret"), "{rendered:?}");
}
