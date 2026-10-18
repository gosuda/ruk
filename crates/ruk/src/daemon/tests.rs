//! Command-stream serving tests driving the exact Go wire.
//!
//! The tests speak the Forgejo backend's field names over a socket pair
//! (`protocol_major` without `protocol_minor`, `argv`/`dir`/`env` opens,
//! `outcome-lookup` on stream zero) so a field rename or shape drift fails
//! here instead of against Forgejo.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::ipc::{self, CONTROL_STREAM_ID, FrameKind, INITIAL_STREAM_WINDOW_BYTES};
use super::{
    BoundedExecutor, CommandAccepted, CommandExitReport, ConnectionRefs, ControlReply,
    DEFAULT_RETENTION_INTERVAL_MS, DaemonConfig, ErrorReport, ExitReport, InvocationAccepted,
    InvocationOpen, OutcomeLedger, Registry, SessionOpened, serve_connection,
};
use ruk_core::bytes::ByteString;
use ruk_core::change::{LeaseId, OperationId, RequestId, SessionId, StoreId};
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::heads::Head;
use ruk_core::ids::Oid;
use ruk_core::index::RepoPath;
use ruk_core::ops::{NewRequest, prepare_new};
use ruk_core::protocol::{
    BookmarkSetArgs, BookmarkTarget, ChangeRef, ClaimAcquireArgs, ClaimMode, ClaimReleaseArgs,
    ClaimTtl, DescribeArgs, EditArgs, IdentityClaim, Method, NewArgs, OpLogArgs, PageCursor,
    PageLimit, PageRequest, PathSelection, PinArgs, QueryDigest, Reply, ReplyBody, ReplyEnvelope,
    SessionOpenArgs, SnapshotArgs, SplitArgs, SplitPlacement, StatusArgs, TagAnnotation,
    TagSetArgs, WorkspaceBinding, WorkspaceInit, WsNewArgs,
};
use ruk_core::refdata::{RefExpect, RefName, RefTarget};
use ruk_core::store::{ObjectKind, PreparationBudget, Store};

/// Hands out unique temp directory names across parallel tests.
static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

/// Mints one stored commit directly in the repository store and closes the
/// handle before the daemon opens it, so dispatch-time reads see committed
/// state with only one live handle at a time.
fn seed_commit(repo_dir: &PathBuf) -> Oid {
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

/// Renders a JSON string literal for hand-built wire documents.
fn jstr(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Builds one `RukOpenRequest` document with the Go backend's field names.
fn command_open_payload(
    request_id: &str,
    argv: &str,
    dir: &str,
    repository: &str,
    digest: &str,
) -> Vec<u8> {
    format!(
        "{{\"session_id\":\"forgejo-svc\",\"repository\":{},\"request_id\":{},\"argv\":{},\"dir\":{},\"env\":[],\"command_digest\":{},\"stdout_credit\":262144,\"stderr_credit\":262144}}",
        jstr(repository),
        jstr(request_id),
        argv,
        jstr(dir),
        jstr(digest),
    )
    .into_bytes()
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

    /// Runs one command open to its terminal report, checking acceptance.
    async fn run_command(
        &mut self,
        stream_id: u64,
        request_id: &str,
        argv: &str,
        dir: &str,
        repository: &str,
        digest: &str,
    ) -> (Vec<u8>, Vec<u8>, CommandExitReport) {
        self.send(
            FrameKind::Open,
            stream_id,
            &command_open_payload(request_id, argv, dir, repository, digest),
        )
        .await;
        let accepted = self.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        let reply: CommandAccepted =
            ipc::decode_control(&accepted.payload).expect("accepted decodes");
        assert_eq!(reply.stream_id, stream_id);
        assert!(reply.stdin_credit > 0, "daemon grants stdin credit");
        assert_eq!(reply.invocation_id, request_id);
        self.send(FrameKind::StdinEof, stream_id, &[]).await;
        self.recv_exit(stream_id).await
    }

    /// Asks stream zero for one invocation outcome.
    async fn lookup(&mut self, invocation_id: &str) -> ControlReply {
        let query = format!(
            "{{\"type\":\"outcome-lookup\",\"invocation_id\":{}}}",
            jstr(invocation_id)
        );
        self.send(FrameKind::Open, CONTROL_STREAM_ID, query.as_bytes())
            .await;
        let reply = self.recv().await;
        assert_eq!(reply.kind, FrameKind::Accepted);
        assert_eq!(reply.stream_id, CONTROL_STREAM_ID);
        ipc::decode_control(&reply.payload).expect("control reply decodes")
    }

    /// Opens one command expecting refusal: an `Error` then a nonzero `Exit`.
    async fn expect_refused(
        &mut self,
        stream_id: u64,
        payload: &[u8],
    ) -> (ErrorReport, ExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let err_frame = self.recv().await;
        assert_eq!(err_frame.kind, FrameKind::Error);
        assert_eq!(err_frame.stream_id, stream_id);
        let report: ErrorReport = ipc::decode_control(&err_frame.payload).expect("error decodes");
        let exit_frame = self.recv().await;
        assert_eq!(exit_frame.kind, FrameKind::Exit);
        assert_eq!(exit_frame.stream_id, stream_id);
        let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
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
        let open = InvocationOpen {
            repo: repo.to_string(),
            method: method.to_string(),
            request_id: request_id.map(str::to_string),
            args_json,
            session_id: session_id.map(str::to_string),
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
    ) -> (ErrorReport, ExitReport) {
        self.send(FrameKind::Open, stream_id, payload).await;
        let accepted = self.recv().await;
        assert_eq!(accepted.kind, FrameKind::Accepted);
        let err_frame = self.recv().await;
        assert_eq!(err_frame.kind, FrameKind::Error);
        assert_eq!(err_frame.stream_id, stream_id);
        let report: ErrorReport = ipc::decode_control(&err_frame.payload).expect("error decodes");
        let exit_frame = self.recv().await;
        assert_eq!(exit_frame.kind, FrameKind::Exit);
        assert_eq!(exit_frame.stream_id, stream_id);
        let exit: ExitReport = ipc::decode_control(&exit_frame.payload).expect("exit decodes");
        assert_eq!(exit.status, 1);
        (report, exit)
    }
}

/// Completes the stream-zero handshake with the Go client's shape: no
/// `protocol_minor` field.
async fn handshake(driver: &mut Driver) {
    let hello = r#"{"protocol_major":1,"profile":"forgejo","object_formats":["sha1"],"features":["credits","merge-notices","outcome-lookup"]}"#;
    driver
        .send(FrameKind::Open, CONTROL_STREAM_ID, hello.as_bytes())
        .await;
    let reply = driver.recv().await;
    assert_eq!(reply.kind, FrameKind::Accepted);
    assert_eq!(reply.stream_id, CONTROL_STREAM_ID);
    let accept: ipc::HandshakeAccept =
        ipc::decode_control(&reply.payload).expect("handshake decodes");
    assert_eq!(accept.protocol_major, 1);
}

/// Spawns `serve_connection` on a socket pair, returning the driver end.
fn spawn_pair(root: &PathBuf) -> (Driver, tokio::task::JoinHandle<Result<(), super::Error>>) {
    let registry = Arc::new(Registry::new(vec![root.clone()]).expect("registry"));
    registry.set_runtime(tokio::runtime::Handle::current());
    let refs = ConnectionRefs {
        registry,
        executor: BoundedExecutor::new(4).expect("executor"),
        outcomes: Arc::new(std::sync::Mutex::new(OutcomeLedger::default())),
        window_bytes: INITIAL_STREAM_WINDOW_BYTES,
        handshake_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(15),
        allowed_uids: Vec::new(),
    };
    let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
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

    let doc = b"socket_path = \"/tmp/ruk-retention.sock\"\nrepo_roots = [\"/tmp\"]\nretention_interval_ms = 5000\n";
    let parsed = DaemonConfig::from_toml(doc).expect("retention interval parses");
    assert_eq!(parsed.retention_interval(), Duration::from_millis(5_000));

    let disabled =
        b"socket_path = \"/tmp/ruk-retention.sock\"\nrepo_roots = [\"/tmp\"]\nretention_interval_ms = 0\n";
    let parsed = DaemonConfig::from_toml(disabled).expect("zero disables sweeps");
    assert!(parsed.retention_interval().is_zero());
}

#[test]
fn handshake_hello_without_minor_decodes() {
    let raw =
        br#"{"protocol_major":1,"profile":"forgejo","object_formats":["sha1"],"features":[]}"#;
    let hello: ipc::HandshakeHello = ipc::decode_control(raw).expect("decodes");
    assert_eq!(hello.protocol_minor, 0);
    let accept = ipc::negotiate(&hello).expect("negotiates");
    assert_eq!(accept.protocol_major, 1);
}

#[tokio::test]
async fn command_stream_serves_go_wire() {
    let root = temp_root("cmd");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-1",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-1",
        )
        .await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.invocation_id, "req-init-1");
    assert!(!exit.cancelled);
    assert_eq!(exit.outcome, "Completed");
    assert!(
        repo_dir.join(".ruk").is_dir(),
        "argv init creates the store under the daemon root"
    );

    let (stdout, _, exit) = driver
        .run_command(
            3,
            "req-rev-1",
            r#"["rev-parse","--is-inside-work-tree"]"#,
            &repo,
            &repo,
            "digest-rev-1",
        )
        .await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(stdout, b"true\n");

    let reply = driver.lookup("req-rev-1").await;
    assert!(reply.found);
    let recorded = reply.exit.expect("recorded exit");
    assert_eq!(recorded.exit_code, 0);
    assert_eq!(recorded.invocation_id, "req-rev-1");

    let reply = driver.lookup("req-unknown").await;
    assert!(!reply.found);
    assert!(reply.exit.is_none());

    let payload = command_open_payload(
        "req-rev-1",
        r#"["rev-parse"]"#,
        &repo,
        &repo,
        "other-digest",
    );
    let (report, exit) = driver.expect_refused(5, &payload).await;
    assert_eq!(report.code, "E_INVALID");
    assert_eq!(exit.status, 1);

    let (_, _, replayed) = driver
        .run_command(
            7,
            "req-rev-1",
            r#"["rev-parse","--is-inside-work-tree"]"#,
            &repo,
            &repo,
            "digest-rev-1",
        )
        .await;
    assert_eq!(replayed.exit_code, 0);
    assert_eq!(replayed.invocation_id, "req-rev-1");

    let outside = std::env::temp_dir()
        .to_str()
        .expect("utf8 temp")
        .to_string();
    let payload = command_open_payload("req-bad-dir", r#"["rev-parse"]"#, &outside, &outside, "d");
    let (report, exit) = driver.expect_refused(9, &payload).await;
    assert_eq!(report.code, "E_FORBIDDEN");
    assert_eq!(exit.status, 1);

    let other_dir = root.join("other");
    std::fs::create_dir_all(&other_dir).expect("other dir");
    let other = other_dir.to_str().expect("utf8 other").to_string();
    let payload = command_open_payload("req-mismatch", r#"["rev-parse"]"#, &repo, &other, "d");
    let (report, exit) = driver.expect_refused(11, &payload).await;
    assert_eq!(report.code, "E_FORBIDDEN");
    assert_eq!(exit.status, 1);

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn command_stream_pipes_stdin_with_credit_grants() {
    let root = temp_root("stdin");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = command_open_payload(
        "req-stdin-1",
        r#"["hash-object","--stdin"]"#,
        &repo,
        &repo,
        "digest-stdin-1",
    );
    driver.send(FrameKind::Open, 1, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);

    driver.send(FrameKind::Stdin, 1, b"hello\n").await;
    let grant = driver.recv().await;
    assert_eq!(grant.kind, FrameKind::WindowUpdate);
    assert_eq!(grant.stream_id, 1);
    let grant_text = String::from_utf8(grant.payload).expect("grant is JSON");
    assert!(
        grant_text.contains("\"bytes\":6"),
        "grant uses the Go backend's field names: {grant_text}"
    );
    driver.send(FrameKind::StdinEof, 1, &[]).await;

    let (stdout, _, exit) = driver.recv_exit(1).await;
    assert_eq!(exit.exit_code, 0);
    assert_eq!(exit.invocation_id, "req-stdin-1");
    assert_eq!(stdout.len(), 41, "one hex id plus newline");
    assert_eq!(&stdout[40..], b"\n");

    drop(driver);
    task.abort();
}

#[tokio::test]
async fn command_stream_cancel_reports_cancelled() {
    let root = temp_root("cancel");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let payload = command_open_payload(
        "req-cancel-1",
        r#"["rev-parse","--is-inside-work-tree"]"#,
        &repo,
        &repo,
        "digest-cancel-1",
    );
    driver.send(FrameKind::Open, 1, &payload).await;
    let accepted = driver.recv().await;
    assert_eq!(accepted.kind, FrameKind::Accepted);
    driver.send(FrameKind::Cancel, 1, &[]).await;

    let (_, _, exit) = driver.recv_exit(1).await;
    assert_eq!(exit.exit_code, 130);
    assert!(exit.cancelled);
    assert_eq!(exit.outcome, "CancelledBeforeCommit");
    assert_eq!(exit.invocation_id, "req-cancel-1");

    let reply = driver.lookup("req-cancel-1").await;
    assert!(reply.found);
    let recorded = reply.exit.expect("recorded exit");
    assert!(recorded.cancelled);

    drop(driver);
    task.abort();
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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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
    assert_eq!(report.code, "E_FORBIDDEN");

    // A missing session keeps the sessionless refusal.
    let payload = Driver::typed_open(&repo, "op.log", None, Some("{}".to_string()), None);
    let (report, _) = driver.expect_typed_refused(9, &payload).await;
    assert_eq!(report.code, "E_INVALID");

    // A malformed session id is invalid, never forbidden.
    let payload = Driver::typed_open(&repo, "op.log", None, Some("{}".to_string()), Some("nope"));
    let (report, _) = driver.expect_typed_refused(11, &payload).await;
    assert_eq!(report.code, "E_INVALID");

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
    assert_eq!(report.code, "E_HOSTED");
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
    assert_eq!(report.code, "E_INVALID");

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
    assert_eq!(report.code, "E_NOT_FOUND");

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
    assert_eq!(report.code, "E_FORBIDDEN");

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-oplog-pages",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-oplog-pages",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-new",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-new",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-new-bare",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-new-bare",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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
    assert_eq!(report.code, "E_INVALID");

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-claim",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-claim",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-wsnew",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-wsnew",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-describe",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-describe",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

/// Socket-level proof that `split` stays honestly refused: partitioning by
/// paths needs intermediate-tree derivation with no producer on this path.
#[tokio::test]
async fn typed_split_refusal_names_tree_derivation() {
    let root = temp_root("typed-split");
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(&repo_dir).expect("repo dir");
    let repo = repo_dir.to_str().expect("utf8 repo").to_string();

    let (mut driver, task) = spawn_pair(&root);
    handshake(&mut driver).await;

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-split",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-split",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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
    assert_eq!(report.code, "E_HOSTED");
    assert!(
        report.message.contains("ops/tree_edit.rs"),
        "split names its missing producer: {}",
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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-edit",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-edit",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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

    let (_, _, exit) = driver
        .run_command(
            1,
            "req-init-typed-snapshot",
            r#"["init"]"#,
            &repo,
            &repo,
            "digest-init-typed-snapshot",
        )
        .await;
    assert_eq!(exit.exit_code, 0);

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
    assert_eq!(report.code, "E_HOSTED");
    assert!(
        report.message.contains("workcopy::snapshot"),
        "snapshot names its missing producer: {}",
        report.message
    );

    drop(driver);
    task.abort();
}
