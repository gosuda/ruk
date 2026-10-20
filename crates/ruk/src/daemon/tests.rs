//! Git-service and typed-invocation tests driving the daemon wire.
//!
//! The tests speak the daemon's field names over a socket pair
//! (`protocol_major` without `protocol_minor`, git-service envelope opens,
//! typed invocation opens) so a field rename or shape drift fails here
//! instead of against a live peer.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::ipc::{self, CONTROL_STREAM_ID, FrameKind, INITIAL_STREAM_WINDOW_BYTES};
use super::{
    BoundedExecutor, CommandAccepted, CommandExitReport, CommandOpen, ConnectionRefs, ExitReport,
    GitLimits, InvocationAccepted, InvocationOpen, Registry, SessionOpened, serve_connection,
};
use super::{
    DEFAULT_ARCHIVE_MAX_BYTES, DEFAULT_COMPARE_MAX_COMMITS, DEFAULT_DEFAULT_BRANCH,
    DEFAULT_EVENT_RETENTION_SECONDS, DEFAULT_HOOK_MAX_COMMANDS, DEFAULT_HOOK_TIMEOUT_MS,
    DEFAULT_RETENTION_INTERVAL_MS, DEFAULT_SEARCH_MAX_SCAN_BYTES, DEFAULT_SEARCH_POOL_SIZE,
    DEFAULT_TRANSPORT_PERMITS, DaemonConfig,
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
    FetchFilter, FetchRefs, Fix, IdentityClaim, LandExecuteArgs, Method, NewArgs, OpLogArgs,
    PageCursor, PageLimit, PageRequest, PathSelection, PinArgs, PushRefOutcome, PushRefStatus,
    PushState, QueryDigest, RemoteName, RemoteSpec, Reply, ReplyBody, ReplyEnvelope,
    SessionOpenArgs, SnapshotArgs, SplitArgs, SplitPlacement, StatusArgs, TagAnnotation,
    TagSetArgs, WorkspaceBinding, WorkspaceInit, WsNewArgs,
};
use ruk_core::refdata::{RefExpect, RefName, RefRead, RefTarget};
use ruk_core::store::{ObjectKind, PreparationBudget, Store};

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
    store.publish(vec![tree], &[]).expect("publish empty tree");
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
        .publish(prepared.objects, &prepared.facts)
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
        .publish(Vec::new(), &prepared.into_mutations())
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
        window_bytes,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: vec![uid],
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
}

#[test]
fn hook_max_commands_accepts_only_1_through_4096() {
    for valid in ["hook_max_commands = 1\n", "hook_max_commands = 4096\n"] {
        DaemonConfig::from_toml(&config_doc(valid)).expect("boundary must parse");
    }
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
    assert_eq!(cfg.event_retention_seconds, DEFAULT_EVENT_RETENTION_SECONDS);
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
        Some("sess-1"),
        Some("req-del-1"),
    );
    let (stdout, exit) = driver.run_git(1, &payload, &[request]).await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.invocation_id, "req-del-1");
    let text = String::from_utf8(stdout).expect("report is text");
    assert!(text.contains("unpack ok"), "report lands: {text}");

    let advert = git_open_payload("upload-pack", &store_repo, true, None, None);
    let (stdout, exit) = driver.run_git(3, &advert, &[]).await;
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
    assert_eq!(log.entries.items.len(), 1);
    assert_eq!(
        log.entries.items[0].on_behalf_of.as_deref(),
        Some("agent-x"),
        "the op.log entry carries the declared provenance"
    );

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

    // A read outside the covered subset names its missing implementation.
    let payload = Driver::typed_open(
        &repo,
        "status",
        None,
        Some("{}".to_string()),
        Some(&session),
    );
    let (report, _) = driver.expect_typed_refused(23, &payload).await;
    assert_eq!(report.code.as_str(), "E_HOSTED");
    assert!(
        report.message.contains("autosnapshot"),
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
    assert_eq!(report.code.as_str(), "E_HOSTED");
    assert!(
        report.message.contains("load_plan"),
        "land.execute names its plan machinery: {}",
        report.message
    );

    drop(driver);
    task.abort();
}
