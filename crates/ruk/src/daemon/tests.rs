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
    BoundedExecutor, CommandAccepted, CommandExitReport, ConnectionRefs, ControlReply, ErrorReport,
    ExitReport, OutcomeLedger, Registry, serve_connection,
};

/// Hands out unique temp directory names across parallel tests.
static NEXT_CASE: AtomicU64 = AtomicU64::new(0);

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
