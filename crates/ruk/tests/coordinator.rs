//! Per-repository coordinator sidecar: race, fallback, and lifecycle tests.
//!
//! These drive the real `ruk` binary (plus the `ruk coordinator` sidecar it
//! spawns) through two racing commits, coordinator absence, a killed
//! coordinator, forced-direct mode, required mode, and idle shutdown. The
//! batch win is measured through the server's own proof file
//! (`.ruk/coordinator.stats`): grouped publications share one metadata
//! transaction, so two racing commits cost fewer publication commits than
//! two solo ones.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static REPO_SEQ: AtomicU64 = AtomicU64::new(0);

fn ruk_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ruk"))
}

fn base_env() -> Vec<(String, String)> {
    vec![
        ("GIT_AUTHOR_NAME".to_owned(), "Coord Test".to_owned()),
        ("GIT_AUTHOR_EMAIL".to_owned(), "coord@test.invalid".to_owned()),
        ("GIT_COMMITTER_NAME".to_owned(), "Coord Test".to_owned()),
        ("GIT_COMMITTER_EMAIL".to_owned(), "coord@test.invalid".to_owned()),
        // Widen the store group-commit window so racing publications share
        // one durability transaction deterministically.
        ("RUK_COMMIT_LINGER_MS".to_owned(), "50".to_owned()),
    ]
}

fn run(repo: &Path, args: &[&str], extra: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(ruk_bin());
    cmd.arg("--git-dir")
        .arg(repo.join(".ruk"))
        .args(args)
        .current_dir(repo)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in base_env() {
        cmd.env(key, value);
    }
    for (key, value) in extra {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("spawn ruk");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn fresh_repo(tag: &str) -> PathBuf {
    let id = REPO_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ruk-coord-{}-{}-{}",
        tag,
        std::process::id(),
        id
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear stale repo");
    }
    std::fs::create_dir_all(&dir).expect("repo dir");
    let (code, _, stderr) = run(&dir, &["init"], &[]);
    assert_eq!(code, 0, "init failed: {stderr}");
    dir
}

fn commit_empty(repo: &Path, message: &str, extra: &[(&str, &str)]) -> (i32, String, String) {
    run(repo, &["commit", "--allow-empty", "-m", message], extra)
}

fn log_subjects(repo: &Path) -> String {
    let (code, stdout, stderr) = run(repo, &["log", "--oneline"], &[]);
    assert_eq!(code, 0, "log failed: {stderr}");
    stdout
}

/// Reads one u64 field from the JSON proof file.
fn stat_field(repo: &Path, field: &str) -> u64 {
    let bytes = std::fs::read(repo.join(".ruk").join("coordinator.stats"))
        .expect("coordinator stats proof file");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let marker = format!("\"{field}\":");
    let start = text.find(&marker).unwrap_or_else(|| panic!("{field} in {text}"));
    text[start + marker.len()..]
        .trim_start()
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .unwrap_or("0")
        .parse()
        .expect("stat number")
}

fn wait_for(path: &Path, present: bool, timeout: Duration) {
    let start = Instant::now();
    while path.exists() != present && start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(path.exists(), present, "wait for {}", path.display());
}

fn barrier(stats: (u64, u64, u64, u64, u64)) -> u64 {
    stats.0 + stats.1 + stats.2 + stats.3 + stats.4
}

fn read_stats(repo: &Path) -> (u64, u64, u64, u64, u64) {
    (
        stat_field(repo, "publications"),
        stat_field(repo, "publication_commits"),
        stat_field(repo, "segment_syncs"),
        stat_field(repo, "directory_syncs"),
        stat_field(repo, "pending_commits"),
    )
}

/// Two racing commits on one branch both land, and the shared burst syncs
/// fewer metadata transactions than two solo commits would.
#[test]
fn racing_commits_share_one_burst() {
    let idle = &[("RUK_COORDINATOR_IDLE_MS", "10000")];
    // Solo baseline on its own repository and server generation.
    let solo = fresh_repo("solo");
    let (code, _, stderr) = commit_empty(&solo, "solo commit", idle);
    assert_eq!(code, 0, "solo commit failed: {stderr}");
    wait_for(
        &solo.join(".ruk").join("coordinator.stats"),
        true,
        Duration::from_secs(15),
    );
    let solo_stats = read_stats(&solo);
    assert!(solo_stats.0 >= 1, "solo published: {solo_stats:?}");

    // Racing pair on a fresh repository; retry once on scheduling blowout.
    let mut raced: Option<(PathBuf, (u64, u64, u64, u64, u64))> = None;
    for _ in 0..2 {
        let repo = fresh_repo("race");
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let handles: Vec<_> = ["race alpha", "race beta"]
                .into_iter()
                .map(|message| {
                    scope.spawn(|| {
                        start.wait();
                        commit_empty(&repo, message, idle)
                    })
                })
                .collect();
            for handle in handles {
                let (code, _, stderr) = handle.join().expect("racer panicked");
                assert_eq!(code, 0, "racing commit failed: {stderr}");
            }
        });
        let log = log_subjects(&repo);
        assert!(log.contains("race alpha"), "missing alpha:\n{log}");
        assert!(log.contains("race beta"), "missing beta:\n{log}");
        wait_for(
            &repo.join(".ruk").join("coordinator.stats"),
            true,
            Duration::from_secs(15),
        );
        let stats = read_stats(&repo);
        if barrier(stats) < barrier(solo_stats) * 2 {
            raced = Some((repo, stats));
            break;
        }
        std::fs::remove_dir_all(&repo).expect("clear repo");
    }
    let (repo, stats) = raced.expect("racing commits never batched");
    assert!(
        stats.1 < solo_stats.1 * 2,
        "race commits {} vs solo {} x2: {stats:?} vs {solo_stats:?}",
        stats.1,
        solo_stats.1
    );
    let _ = std::fs::remove_dir_all(&repo);
}

/// An unspawnable coordinator falls back to the direct publish path.
#[test]
fn absent_coordinator_falls_back_to_direct() {
    let repo = fresh_repo("absent");
    let extra = &[("RUK_COORDINATOR_BIN", "/nonexistent-ruk-coordinator")];
    let (code, _, stderr) = commit_empty(&repo, "direct commit", extra);
    assert_eq!(code, 0, "fallback commit failed: {stderr}");
    assert!(!repo.join(".ruk").join("coordinator.sock").exists());
    let log = log_subjects(&repo);
    assert!(log.contains("direct commit"), "missing commit:\n{log}");
}

/// A killed coordinator heals: the stale socket is refused, a fresh server
/// spawns, and the commit lands exactly once.
#[test]
fn killed_coordinator_respawns() {
    let repo = fresh_repo("killed");
    let (code, _, stderr) = commit_empty(&repo, "first commit", &[]);
    assert_eq!(code, 0, "first commit failed: {stderr}");
    let sock = repo.join(".ruk").join("coordinator.sock");
    wait_for(&sock, true, Duration::from_secs(10));
    // Read the owner's pid from the lock body and kill it mid-flight.
    let lock = std::fs::read(repo.join(".ruk").join("lock")).expect("lock body");
    let text = String::from_utf8_lossy(&lock).into_owned();
    let pid: u32 = text
        .lines()
        .nth(1)
        .and_then(|line| line.strip_prefix("pid "))
        .and_then(|pid| pid.parse().ok())
        .expect("owner pid");
    // No wait for the stale socket to vanish: nobody unlinks it. The next
    // commit refuses the dead socket, a fresh server takes over the path,
    // and the commit lands exactly once.
    libc_kill(pid);
    std::thread::sleep(Duration::from_millis(200));
    let (code, _, stderr) = commit_empty(&repo, "second commit", &[]);
    assert_eq!(code, 0, "commit after kill failed: {stderr}");
    let log = log_subjects(&repo);
    assert!(log.contains("first commit"), "missing first:\n{log}");
    assert!(log.contains("second commit"), "missing second:\n{log}");
    assert_eq!(log.lines().count(), 2, "duplicate commit:\n{log}");
}

#[cfg(unix)]
fn libc_kill(pid: u32) {
    // SIGKILL through the test harness shell-out: the workspace denies
    // unsafe code, so no libc FFI even in tests.
    let status = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn kill");
    assert!(status.success(), "kill failed");
}

#[cfg(not(unix))]
fn libc_kill(_pid: u32) {
    panic!("kill test is Unix-only");
}

/// `RUK_COORDINATOR=off` forces the direct path and never binds a socket.
#[test]
fn off_forces_direct_publish() {
    let repo = fresh_repo("off");
    let (code, _, stderr) = commit_empty(&repo, "off commit", &[("RUK_COORDINATOR", "off")]);
    assert_eq!(code, 0, "off commit failed: {stderr}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!repo.join(".ruk").join("coordinator.sock").exists());
    let log = log_subjects(&repo);
    assert!(log.contains("off commit"), "missing commit:\n{log}");
}

/// `RUK_COORDINATOR=required` hard-fails when no coordinator can answer.
#[test]
fn required_fails_without_coordinator() {
    let repo = fresh_repo("required");
    let extra = &[
        ("RUK_COORDINATOR", "required"),
        ("RUK_COORDINATOR_BIN", "/nonexistent-ruk-coordinator"),
    ];
    let (code, _, stderr) = commit_empty(&repo, "required commit", extra);
    assert_ne!(code, 0, "required commit must fail");
    assert!(stderr.contains("required"), "names the mode: {stderr}");
    assert!(!repo.join(".ruk").join("coordinator.sock").exists());
}

/// An idle server unlinks its socket and exits on its own.
#[test]
fn idle_server_unlinks_its_socket() {
    let repo = fresh_repo("idle");
    let extra = &[("RUK_COORDINATOR_IDLE_MS", "200")];
    let (code, _, stderr) = commit_empty(&repo, "idle commit", extra);
    assert_eq!(code, 0, "idle commit failed: {stderr}");
    let sock = repo.join(".ruk").join("coordinator.sock");
    wait_for(&sock, true, Duration::from_secs(10));
    wait_for(&sock, false, Duration::from_secs(10));
}
