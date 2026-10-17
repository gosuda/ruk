//! Interpreter tests: pure units plus end-to-end verb flows on temp stores.
//!
//! Store-backed tests build real repositories under the system temp
//! directory and drive the verb functions directly; every assertion checks
//! observable bytes or store state, never source text.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ruk_core::ids::HashKind;
use ruk_core::store::{PreparationBudget, Store};

use super::dispatch::{VERBS, lookup};
use super::verbs_branch;
use super::verbs_history;
use super::verbs_objects;
use super::verbs_repo;
use super::verbs_stage;
use super::verbs_transport;
use super::{CliEnv, Ctx, collect};

/// Hands out unique temp directory names across parallel tests.
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Creates an empty temp directory for one test.
fn temp_base(case: &str) -> PathBuf {
    let id = NEXT_TEMP.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("ruk-cli-{}-{}-{}", std::process::id(), id, case));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp base");
    base
}

/// Builds an environment with a fixed test identity and one cwd.
fn test_env(cwd: &PathBuf) -> CliEnv {
    let vars = [
        ("GIT_AUTHOR_NAME", "Ada"),
        ("GIT_AUTHOR_EMAIL", "ada@example.invalid"),
        ("GIT_COMMITTER_NAME", "Ada"),
        ("GIT_COMMITTER_EMAIL", "ada@example.invalid"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect::<HashMap<String, String>>();
    CliEnv {
        vars,
        cwd: cwd.clone(),
    }
}

/// Opens the store at one root with the reference budget.
fn open_store(root: &PathBuf) -> Store {
    Store::open(
        &root.join(".ruk"),
        Arc::new(PreparationBudget::reference_defaults()),
    )
    .expect("open store")
}

/// Builds a repo-backed context for verb calls.
fn repo_ctx(root: &PathBuf, mut env: CliEnv) -> Ctx {
    env.cwd = root.clone();
    let store = open_store(root);
    let kind = store.hash_kind();
    Ctx {
        store: Some(store),
        root: root.clone(),
        file_base: root.clone(),
        kind: Some(kind),
        env,
        bare: false,
        cli_config: Vec::new(),
    }
}

/// Creates a repository with one committed file, returning its root.
fn seeded_repo(case: &str, file: &str, body: &[u8]) -> (PathBuf, CliEnv) {
    let base = temp_base(case);
    let env = test_env(&base);
    let mut ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env: env.clone(),
        bare: false,
        cli_config: Vec::new(),
    };
    verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
    let root = base.join("repo");
    std::fs::write(root.join(file), body).expect("seed file");
    let env = test_env(&base);
    let mut ctx = repo_ctx(&root, env.clone());
    verbs_stage::add(&mut ctx, &[file.to_owned()]).expect("add");
    verbs_history::commit(&mut ctx, &["-m".to_owned(), "seed".to_owned()]).expect("commit");
    (root, env)
}

/// Calls one verb with string arguments.
fn run(
    verb: fn(&mut Ctx, &[String]) -> Result<Vec<u8>, ruk_git::GitError>,
    ctx: &mut Ctx,
    args: &[&str],
) -> Result<Vec<u8>, ruk_git::GitError> {
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    verb(ctx, &owned)
}

#[test]
fn verb_table_covers_56_names() {
    assert_eq!(VERBS.len(), 56);
    let mut names: Vec<&str> = VERBS.iter().map(|verb| verb.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 56);
    for name in [
        "add",
        "archive",
        "branch",
        "bundle",
        "cat-file",
        "check-ref-format",
        "checkout",
        "cherry-pick",
        "clone",
        "commit",
        "commit-tree",
        "config",
        "count-objects",
        "diff",
        "fetch",
        "for-each-ref",
        "fsck",
        "gc",
        "hash-object",
        "help",
        "index-pack",
        "init",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "merge",
        "merge-base",
        "mktree",
        "mv",
        "pack-objects",
        "pull",
        "push",
        "rebase",
        "receive-pack",
        "remote",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "revert",
        "rm",
        "show",
        "show-ref",
        "stash",
        "status",
        "switch",
        "symbolic-ref",
        "tag",
        "update-index",
        "update-ref",
        "upload-pack",
        "verify-pack",
        "version",
        "worktree",
        "write-tree",
    ] {
        assert!(lookup(name).is_some(), "missing verb {name}");
    }
    assert!(lookup("checkout--worker").is_none());
}

#[test]
fn option_collection_splits_forms() {
    let args = [
        "--message",
        "hi",
        "--force",
        "--depth=2",
        "-n",
        "5",
        "--",
        "-x",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<String>>();
    let specs = [
        super::FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        super::FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        super::FlagSpec {
            long: "depth",
            short: None,
            takes_value: true,
        },
        super::FlagSpec {
            long: "count",
            short: Some('n'),
            takes_value: true,
        },
    ];
    let collected = collect(&args, &specs).expect("collect");
    assert_eq!(
        collected.single("message").expect("one"),
        Some("hi".to_owned())
    );
    assert!(collected.is_set("force"));
    assert_eq!(
        collected.single("depth").expect("one"),
        Some("2".to_owned())
    );
    assert_eq!(
        collected.single("count").expect("one"),
        Some("5".to_owned())
    );
    assert_eq!(collected.positionals, vec!["-x".to_owned()]);
    assert!(collect(&["--nope".to_owned()], &specs).is_err());
    assert!(collect(&["--force=x".to_owned()], &specs).is_err());
    assert!(collect(&["--message".to_owned()], &specs).is_err());
}

#[test]
fn tree_codec_round_trips() {
    let kind = HashKind::Sha1;
    let entries = vec![
        super::tree::TreeEntry {
            mode: ruk_core::index::FileMode::Regular,
            name: b"b.txt".to_vec(),
            oid: kind.hash_git_object("blob", b"b").expect("hash"),
        },
        super::tree::TreeEntry {
            mode: ruk_core::index::FileMode::Executable,
            name: b"a.txt".to_vec(),
            oid: kind.hash_git_object("blob", b"a").expect("hash"),
        },
    ];
    let body = super::tree::encode_tree(&entries);
    let parsed = super::tree::parse_tree(kind, &body).expect("parse");
    assert_eq!(parsed, entries);
    assert!(super::tree::parse_tree(kind, b"100644 a.txt").is_err());
    let payload = super::tree::commit_payload(
        &"0".repeat(40),
        &["1".repeat(40)],
        &author_signature(),
        &author_signature(),
        b"msg\n",
    );
    assert!(
        payload.starts_with(
            format!("tree {}\nparent {}\n", "0".repeat(40), "1".repeat(40)).as_bytes()
        )
    );
}

/// Builds a fixed test signature without a repository.
fn author_signature() -> ruk_core::conflict::Signature {
    ruk_core::conflict::Signature::parse(b"Ada <ada@example.invalid> 1700000000 +0000")
        .expect("signature")
}

#[test]
fn init_add_commit_log_status_flow() {
    let (root, env) = seeded_repo("flow", "hello.txt", b"hello\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain"]).expect("status");
    assert!(
        out.is_empty(),
        "clean tree: {}",
        String::from_utf8_lossy(&out)
    );
    let out = run(verbs_history::log, &mut ctx, &["--oneline"]).expect("log");
    assert!(String::from_utf8_lossy(&out).contains("seed"));
    let out = run(verbs_branch::branch, &mut ctx, &[]).expect("branch");
    assert!(String::from_utf8_lossy(&out).contains("* main"));
    let out = run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse");
    assert_eq!(out.len(), 41);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn modify_diff_reset_cycle() {
    let (root, env) = seeded_repo("diffcycle", "file.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("file.txt"), b"two\n").expect("modify");
    let out = run(verbs_history::diff, &mut ctx, &["--name-only"]).expect("diff");
    assert_eq!(out, b"file.txt\n");
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain"]).expect("status");
    assert!(String::from_utf8_lossy(&out).contains(" M file.txt"));
    run(verbs_branch::reset, &mut ctx, &["--hard", "HEAD"]).expect("reset");
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain"]).expect("status");
    assert!(
        out.is_empty(),
        "hard reset cleans: {}",
        String::from_utf8_lossy(&out)
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn branch_checkout_merge_fast_forward() {
    let (root, env) = seeded_repo("ffmerge", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    std::fs::write(root.join("next.txt"), b"next\n").expect("new file");
    run(verbs_stage::add, &mut ctx, &["next.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "feature work"]).expect("commit");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    let out = run(verbs_history::merge, &mut ctx, &["feature"]).expect("merge");
    assert!(String::from_utf8_lossy(&out).contains("Fast-forward"));
    assert!(root.join("next.txt").exists());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn ref_plumbing_round_trip() {
    let (root, env) = seeded_repo("refs", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let head = run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("head");
    let hex = String::from_utf8_lossy(&head).trim().to_owned();
    run(
        verbs_branch::update_ref,
        &mut ctx,
        &["refs/heads/side", hex.as_str()],
    )
    .expect("update-ref");
    let out = run(verbs_branch::show_ref, &mut ctx, &[]).expect("show-ref");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("refs/heads/side"));
    assert!(text.contains("refs/heads/main"));
    let out = run(
        verbs_objects::check_ref_format,
        &mut ctx,
        &["--print", "refs/heads/ok"],
    )
    .expect("check");
    assert_eq!(out, b"refs/heads/ok\n");
    assert!(run(verbs_objects::check_ref_format, &mut ctx, &["HEAD"]).is_err());
    assert!(
        run(
            verbs_objects::check_ref_format,
            &mut ctx,
            &["refs/heads/..bad"]
        )
        .is_err()
    );
    let absolute = root.join("a.txt");
    let out = run(
        verbs_objects::hash_object,
        &mut ctx,
        &[absolute.to_str().expect("utf8")],
    )
    .expect("hash");
    assert_eq!(out.len(), 41);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn tag_stash_remote_config_cycle() {
    let (root, env) = seeded_repo("misc", "m.txt", b"m\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::tag, &mut ctx, &["v1"]).expect("tag");
    let out = run(verbs_branch::tag, &mut ctx, &[]).expect("tag list");
    assert_eq!(out, b"v1\n");
    run(verbs_branch::tag, &mut ctx, &["-a", "-m", "note", "v2"]).expect("annotated");
    run(verbs_repo::config, &mut ctx, &["user.nick", "ada"]).expect("config set");
    let out = run(verbs_repo::config, &mut ctx, &["user.nick"]).expect("config get");
    assert_eq!(out, b"ada\n");
    run(
        verbs_repo::remote,
        &mut ctx,
        &["add", "origin", "/elsewhere"],
    )
    .expect("remote add");
    let out = run(verbs_repo::remote, &mut ctx, &[]).expect("remote list");
    assert_eq!(out, b"origin\n");
    std::fs::write(root.join("m.txt"), b"m2\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["m.txt"]).expect("stage");
    let out = run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    assert!(String::from_utf8_lossy(&out).contains("stash@0"));
    let out = run(verbs_branch::stash, &mut ctx, &["list"]).expect("stash list");
    assert!(String::from_utf8_lossy(&out).contains("wip"));
    run(verbs_branch::stash, &mut ctx, &["pop"]).expect("stash pop");
    let out = run(verbs_stage::ls_files, &mut ctx, &["-s"]).expect("ls-files");
    assert!(String::from_utf8_lossy(&out).contains("m.txt"));
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn clone_fetch_push_local_cycle() {
    let (root, _) = seeded_repo("clone-src", "c.txt", b"c\n");
    let base = root.parent().expect("parent").to_path_buf();
    let env = test_env(&base);
    let mut ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env: env.clone(),
        bare: false,
        cli_config: Vec::new(),
    };
    run(
        verbs_repo::clone,
        &mut ctx,
        &[root.to_str().expect("utf8"), "copy"],
    )
    .expect("clone");
    let copy = base.join("copy");
    let mut copy_ctx = repo_ctx(&copy, env.clone());
    let out = run(verbs_branch::branch, &mut copy_ctx, &["-a"]).expect("branches");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("main"));
    assert!(text.contains("origin/main"));
    std::fs::write(copy.join("d.txt"), b"d\n").expect("new file");
    run(verbs_stage::add, &mut copy_ctx, &["d.txt"]).expect("add");
    run(verbs_history::commit, &mut copy_ctx, &["-m", "downstream"]).expect("commit");
    run(verbs_transport::push, &mut copy_ctx, &["origin", "main"]).expect("push");
    let mut src_ctx = repo_ctx(&root, test_env(&base));
    let out = run(verbs_history::log, &mut src_ctx, &["--oneline"]).expect("log");
    assert!(String::from_utf8_lossy(&out).contains("downstream"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn unsupported_verbs_report_closed_codes() {
    let base = temp_base("unsupported");
    let env = test_env(&base);
    let mut ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env,
        bare: false,
        cli_config: Vec::new(),
    };
    for verb in [
        verbs_objects::pack_objects
            as fn(&mut Ctx, &[String]) -> Result<Vec<u8>, ruk_git::GitError>,
        verbs_objects::index_pack,
        verbs_objects::count_objects,
        verbs_transport::gc,
        verbs_transport::archive,
        verbs_transport::bundle,
        verbs_transport::receive_pack,
        verbs_transport::upload_pack,
        verbs_repo::worktree,
    ] {
        let err = run(verb, &mut ctx, &[]).expect_err("unsupported");
        assert_eq!(err.exit_code(), 1, "{err}");
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn sequencer_absent_reads_clean() {
    let (root, env) = seeded_repo("seq", "s.txt", b"s\n");
    let mut ctx = repo_ctx(&root, env);
    assert!(
        super::state::sequencer_read(ctx.store().expect("store"), "merge")
            .expect("read")
            .is_none()
    );
    let err = run(verbs_history::rebase, &mut ctx, &["--abort"]).expect_err("abort");
    assert!(err.to_string().contains("no rebase in progress"));
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
