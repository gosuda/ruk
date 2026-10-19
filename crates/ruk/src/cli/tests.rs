//! Interpreter tests: pure units plus end-to-end verb flows on temp stores.
//!
//! Store-backed tests build real repositories under the system temp
//! directory and drive the verb functions directly; every assertion checks
//! observable bytes or store state, never source text.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ruk_core::ids::HashKind;
use ruk_core::store::{FactTable, PreparationBudget, Store};

use super::dispatch::{VERBS, lookup};
use super::verbs_bisect;
use super::verbs_blame;
use super::verbs_branch;
use super::verbs_bundle;
use super::verbs_grep;
use super::verbs_history;
use super::verbs_objects;
use super::verbs_patch;
use super::verbs_repo;
use super::verbs_stage;
use super::verbs_transport;
use super::verbs_worktree;
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
        stdin: None,
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
        stderr: Vec::new(),
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
        stderr: Vec::new(),
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
fn verb_table_covers_advertised_names() {
    assert_eq!(VERBS.len(), 81);
    let mut names: Vec<&str> = VERBS.iter().map(|verb| verb.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 81);
    for name in [
        "add",
        "am",
        "annotate",
        "apply",
        "archive",
        "bisect",
        "blame",
        "branch",
        "bundle",
        "cat-file",
        "check-attr",
        "check-ignore",
        "check-ref-format",
        "checkout",
        "cherry",
        "cherry-pick",
        "clean",
        "clone",
        "commit",
        "commit-tree",
        "config",
        "count-objects",
        "credential",
        "describe",
        "diff",
        "fetch",
        "fmt-merge-msg",
        "for-each-ref",
        "format-patch",
        "fsck",
        "gc",
        "get-tar-commit-id",
        "grep",
        "hash-object",
        "help",
        "index-pack",
        "init",
        "interpret-trailers",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "merge",
        "merge-base",
        "migrate",
        "mktree",
        "mv",
        "name-rev",
        "pack-objects",
        "pull",
        "push",
        "rebase",
        "receive-pack",
        "reflog",
        "remote",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "revert",
        "rm",
        "show",
        "shortlog",
        "show-ref",
        "stash",
        "status",
        "stripspace",
        "switch",
        "symbolic-ref",
        "tag",
        "update-index",
        "update-ref",
        "upload-archive",
        "upload-pack",
        "var",
        "verify-commit",
        "verify-pack",
        "verify-tag",
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
            mode: super::tree::TreeMode::Regular,
            name: b"b.txt".to_vec(),
            oid: kind.hash_git_object("blob", b"b").expect("hash"),
        },
        super::tree::TreeEntry {
            mode: super::tree::TreeMode::Executable,
            name: b"a.txt".to_vec(),
            oid: kind.hash_git_object("blob", b"a").expect("hash"),
        },
    ];
    let body = super::tree::encode_tree(&entries);
    let parsed = super::tree::parse_tree(kind, &body).expect("parse");
    assert_eq!(parsed, entries);
    assert!(super::tree::parse_tree(kind, b"100644 a.txt").is_err());
    // Directory modes round-trip: `40000` encodes and both `40000` and
    // zero-padded `040000` parse back to the tree mode the index refuses.
    let dir_oid = kind.hash_git_object("tree", b"").expect("hash");
    let dir_entries = vec![super::tree::TreeEntry {
        mode: super::tree::TreeMode::Tree,
        name: b"sub".to_vec(),
        oid: dir_oid,
    }];
    let dir_body = super::tree::encode_tree(&dir_entries);
    assert!(dir_body.starts_with(b"40000 sub\0"));
    assert_eq!(
        super::tree::parse_tree(kind, &dir_body).expect("parse dir"),
        dir_entries
    );
    let mut padded = b"040000 sub\0".to_vec();
    padded.extend_from_slice(dir_oid.as_bytes());
    assert_eq!(
        super::tree::parse_tree(kind, &padded).expect("parse padded"),
        dir_entries
    );
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
    assert_eq!(
        String::from_utf8_lossy(&out),
        "Saved working directory and index state On main: wip\n"
    );
    let out = run(verbs_branch::stash, &mut ctx, &["list"]).expect("stash list");
    assert_eq!(String::from_utf8_lossy(&out), "stash@{0}: On main: wip\n");
    run(verbs_branch::stash, &mut ctx, &["pop"]).expect("stash pop");
    let out = run(verbs_stage::ls_files, &mut ctx, &["-s"]).expect("ls-files");
    assert!(String::from_utf8_lossy(&out).contains("m.txt"));
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_push_mints_oracle_shaped_commits() {
    let (root, env) = seeded_repo("stash-shape", "s.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    // Unstaged worktree edit, mirroring the parity harness `d/stash-*` rows.
    std::fs::write(root.join("s.txt"), b"one\nwip\n").expect("modify");
    let out = run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "Saved working directory and index state On main: wip\n"
    );
    // The push resets the worktree to HEAD.
    assert_eq!(std::fs::read(root.join("s.txt")).expect("read"), b"one\n");
    let refs = String::from_utf8(run(verbs_branch::show_ref, &mut ctx, &[]).expect("show-ref"))
        .expect("refs utf8");
    let ref_oid = |suffix: &str| {
        refs.lines()
            .find(|line| line.ends_with(suffix))
            .expect("ref present")
            .split_whitespace()
            .next()
            .expect("ref oid")
            .to_owned()
    };
    let head = ref_oid(" refs/heads/main");
    let stash = ref_oid(" refs/stash");
    let mut payload = |oid: &str| {
        String::from_utf8(run(verbs_objects::cat_file, &mut ctx, &["-p", oid]).expect("cat object"))
            .expect("object utf8")
    };
    let tree_of = |text: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix("tree "))
            .expect("tree line")
            .to_owned()
    };
    // The worktree commit has two parents (HEAD, index commit) and the
    // oracle subject, and its tree differs from HEAD by the stashed edit.
    let wip = payload(&stash);
    let parents: Vec<&str> = wip
        .lines()
        .filter_map(|line| line.strip_prefix("parent "))
        .collect();
    assert_eq!(parents, vec![head.as_str(), parents[1]]);
    // The oracle stores the worktree subject bare, without a trailing
    // newline, and `cat-file` renders payload bytes faithfully.
    assert!(wip.ends_with("\n\nOn main: wip"));
    assert!(!wip.ends_with("\n\nOn main: wip\n"));
    assert_ne!(tree_of(&wip), tree_of(&payload(&head)));
    // The index commit has HEAD as its only parent, the oracle subject,
    // and the HEAD tree (the index was clean at push time).
    let index = payload(parents[1]);
    let index_parents: Vec<&str> = index
        .lines()
        .filter_map(|line| line.strip_prefix("parent "))
        .collect();
    assert_eq!(index_parents, vec![head.as_str()]);
    let short = head.chars().take(7).collect::<String>();
    assert!(index.ends_with(&format!("\n\nindex on main: {short} seed\n")));
    assert_eq!(tree_of(&index), tree_of(&payload(&head)));
    // Popping restores the worktree edit unstaged and drops the slot,
    // naming the worktree commit oid like the oracle `Dropped` line.
    let out = run(verbs_branch::stash, &mut ctx, &["pop"]).expect("stash pop");
    assert_eq!(
        std::fs::read(root.join("s.txt")).expect("read"),
        b"one\nwip\n"
    );
    assert!(
        String::from_utf8_lossy(&out).ends_with(&format!("Dropped refs/stash@{{0}} ({stash})\n"))
    );
    let out = run(verbs_branch::stash, &mut ctx, &["list"]).expect("stash list");
    assert!(out.is_empty());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_pop_index_flag_restores_staged_state() {
    let (root, env) = seeded_repo("stash-index", "s.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let porcelain = |ctx: &mut Ctx| {
        String::from_utf8(run(verbs_stage::status, ctx, &["--porcelain"]).expect("status"))
            .expect("status utf8")
    };
    std::fs::write(root.join("s.txt"), b"one\nwip\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["s.txt"]).expect("stage");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    // Without `--index` a stashed staged change comes back unstaged.
    run(verbs_branch::stash, &mut ctx, &["pop"]).expect("pop");
    assert_eq!(
        std::fs::read(root.join("s.txt")).expect("read"),
        b"one\nwip\n"
    );
    assert_eq!(porcelain(&mut ctx), " M s.txt\n");
    // With `--index` the staged state comes back staged.
    run(verbs_stage::add, &mut ctx, &["s.txt"]).expect("stage");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    run(verbs_branch::stash, &mut ctx, &["pop", "--index"]).expect("pop --index");
    assert_eq!(
        std::fs::read(root.join("s.txt")).expect("read"),
        b"one\nwip\n"
    );
    assert_eq!(porcelain(&mut ctx), "M  s.txt\n");
    let out = run(verbs_branch::stash, &mut ctx, &["list"]).expect("stash list");
    assert!(out.is_empty());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Seeds a repo with two committed files for stash overlap tests.
fn two_file_repo(case: &str) -> (PathBuf, CliEnv) {
    let (root, env) = seeded_repo(case, "s.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("t.txt"), b"two\n").expect("seed t");
    run(verbs_stage::add, &mut ctx, &["t.txt"]).expect("stage t");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit t");
    let env = ctx.env.clone();
    (root, env)
}

#[test]
fn stash_apply_keeps_unrelated_staged_changes() {
    // Git refuses only overlapping changes: a staged edit on a path the
    // stash never names restores cleanly (measured against git 2.53, where
    // staged non-overlap plus plain apply exits 0).
    let (root, env) = two_file_repo("stash-relax");
    let mut ctx = repo_ctx(&root, env);
    let porcelain = |ctx: &mut Ctx| {
        String::from_utf8(run(verbs_stage::status, ctx, &["--porcelain"]).expect("status"))
            .expect("status utf8")
    };
    std::fs::write(root.join("t.txt"), b"two\nwip\n").expect("modify t");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    std::fs::write(root.join("s.txt"), b"one\nstaged\n").expect("modify s");
    run(verbs_stage::add, &mut ctx, &["s.txt"]).expect("stage s");
    run(verbs_branch::stash, &mut ctx, &["apply"]).expect("apply");
    assert_eq!(
        std::fs::read(root.join("t.txt")).expect("read t"),
        b"two\nwip\n"
    );
    assert_eq!(porcelain(&mut ctx), "M  s.txt\n M t.txt\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_apply_refuses_overlapping_index_and_worktree_changes() {
    // Measured against git 2.53: staged overlap merge-conflicts and
    // unstaged overlap refuses outright; this lane refuses both instead
    // of merging, keeping the safety either way.
    let (root, env) = two_file_repo("stash-overlap");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("t.txt"), b"two\nwip\n").expect("modify t");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    std::fs::write(root.join("t.txt"), b"two\noverlap\n").expect("overlap t");
    run(verbs_stage::add, &mut ctx, &["t.txt"]).expect("stage overlap");
    let err = run(verbs_branch::stash, &mut ctx, &["apply"]).expect_err("overlapping apply");
    assert!(err.to_string().contains("clean index on: t.txt"), "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));

    let (root, env) = two_file_repo("stash-overlap-wt");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("t.txt"), b"two\nwip\n").expect("modify t");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    std::fs::write(root.join("t.txt"), b"two\ndirty\n").expect("dirty t");
    let err = run(verbs_branch::stash, &mut ctx, &["apply"]).expect_err("dirty apply");
    assert!(err.to_string().contains("clean worktree: t.txt"), "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_apply_index_flag_keeps_unrelated_staged_changes() {
    // With `--index` the stashed index rows come back alongside unrelated
    // staged changes instead of demanding a fully clean index.
    let (root, env) = two_file_repo("stash-index-relax");
    let mut ctx = repo_ctx(&root, env);
    let porcelain = |ctx: &mut Ctx| {
        String::from_utf8(run(verbs_stage::status, ctx, &["--porcelain"]).expect("status"))
            .expect("status utf8")
    };
    std::fs::write(root.join("t.txt"), b"two\nwip\n").expect("modify t");
    run(verbs_stage::add, &mut ctx, &["t.txt"]).expect("stage t");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    std::fs::write(root.join("s.txt"), b"one\nstaged\n").expect("modify s");
    run(verbs_stage::add, &mut ctx, &["s.txt"]).expect("stage s");
    run(verbs_branch::stash, &mut ctx, &["apply", "--index"]).expect("apply --index");
    assert_eq!(
        std::fs::read(root.join("t.txt")).expect("read t"),
        b"two\nwip\n"
    );
    assert_eq!(porcelain(&mut ctx), "M  s.txt\nM  t.txt\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_apply_restores_deletion_without_touching_neighbors() {
    let (root, env) = two_file_repo("stash-delete");
    let mut ctx = repo_ctx(&root, env);
    std::fs::remove_file(root.join("t.txt")).expect("delete t");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    // The push resets the worktree to HEAD; the apply must delete t.txt
    // again while an unrelated unstaged edit to s.txt stays.
    assert!(root.join("t.txt").is_file());
    std::fs::write(root.join("s.txt"), b"one\nneighbor\n").expect("modify s");
    run(verbs_branch::stash, &mut ctx, &["apply"]).expect("apply");
    assert!(!root.join("t.txt").exists());
    assert_eq!(
        std::fs::read(root.join("s.txt")).expect("read s"),
        b"one\nneighbor\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn stash_push_uses_paragraph_subject_and_short_abbrev() {
    // HEAD's message has a two-line first paragraph: the oracle joins it
    // with spaces (`format_subject` with " ") instead of cutting at the
    // first newline, and shortens HEAD to its unique abbrev (7 hex here).
    let (root, env) = seeded_repo("stash-subject", "s.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("s.txt"), b"one\ntwo\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["s.txt"]).expect("stage");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "first line\nsecond line\n\nbody"],
    )
    .expect("commit");
    std::fs::write(root.join("s.txt"), b"one\ntwo\nwip\n").expect("modify");
    let out = run(verbs_branch::stash, &mut ctx, &["push"]).expect("stash");
    let saved = String::from_utf8_lossy(&out).into_owned();
    let refs = String::from_utf8(run(verbs_branch::show_ref, &mut ctx, &[]).expect("show-ref"))
        .expect("refs utf8");
    let head = refs
        .lines()
        .find(|line| line.ends_with(" refs/heads/main"))
        .expect("main ref")
        .split_whitespace()
        .next()
        .expect("head oid");
    assert_eq!(
        saved,
        format!(
            "Saved working directory and index state WIP on main: {} first line second line\n",
            &head[..7]
        )
    );
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
        stderr: Vec::new(),
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
fn fetch_prune_drops_orphaned_tracking_ref() {
    // Stores open exclusively: each context drops before the other end
    // opens the same store, the way the clone/fetch/push cycle test does.
    let (src, _) = seeded_repo("prune-src", "p.txt", b"p\n");
    {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(verbs_branch::branch, &mut src_ctx, &["gone"]).expect("branch gone");
    }
    let (dst, _) = seeded_repo("prune-dst", "q.txt", b"q\n");
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        run(
            verbs_repo::remote,
            &mut dst_ctx,
            &["add", "origin", src.to_str().expect("utf8")],
        )
        .expect("remote add");
        run(verbs_transport::fetch, &mut dst_ctx, &["origin"]).expect("fetch");
        let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/remotes/origin/gone"), "got {text}");
    }
    {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(
            verbs_branch::branch,
            &mut src_ctx,
            &["--force-delete", "gone"],
        )
        .expect("delete gone upstream");
    }
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        let out = run(verbs_transport::fetch, &mut dst_ctx, &["--prune", "origin"])
            .expect("fetch --prune");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("[deleted]"), "got {text}");
        assert!(text.contains("refs/remotes/origin/gone"), "got {text}");
        let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(!text.contains("refs/remotes/origin/gone"), "got {text}");
        assert!(text.contains("refs/remotes/origin/main"), "got {text}");
    }
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn fetch_advances_tracking_ref_through_new_commits_but_refuses_rewind() {
    // The fast-forward check runs after the fetched objects publish: moving
    // an existing tracking ref through commits unknown before the fetch
    // fast-forwards, while a genuine rewind is refused with its objects
    // kept, the way git keeps the pack on a refused ref update.
    let (src, _) = seeded_repo("ffwd-src", "f.txt", b"f\n");
    let (dst, _) = seeded_repo("ffwd-dst", "g.txt", b"g\n");
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        run(
            verbs_repo::remote,
            &mut dst_ctx,
            &["add", "origin", src.to_str().expect("utf8")],
        )
        .expect("remote add");
        run(
            verbs_transport::fetch,
            &mut dst_ctx,
            &["origin", "refs/heads/main:refs/remotes/origin/main"],
        )
        .expect("first fetch");
    }
    let (tip2, side) = {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(verbs_branch::checkout, &mut src_ctx, &["-b", "side"]).expect("checkout -b side");
        std::fs::write(src.join("side.txt"), b"side\n").expect("side file");
        run(verbs_stage::add, &mut src_ctx, &["side.txt"]).expect("add side");
        run(verbs_history::commit, &mut src_ctx, &["-m", "side work"]).expect("commit side");
        let store = src_ctx.store().expect("store");
        let side =
            super::state::resolve_rev(store, src_ctx.kind().expect("kind"), "refs/heads/side")
                .expect("side tip");
        run(verbs_branch::checkout, &mut src_ctx, &["main"]).expect("checkout main");
        std::fs::write(src.join("h.txt"), b"h\n").expect("new file");
        run(verbs_stage::add, &mut src_ctx, &["h.txt"]).expect("add");
        run(verbs_history::commit, &mut src_ctx, &["-m", "second"]).expect("commit main");
        let tip2 = super::state::head_oid(src_ctx.store().expect("store")).expect("src tip");
        (tip2, side)
    };
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        let out = run(
            verbs_transport::fetch,
            &mut dst_ctx,
            &["origin", "refs/heads/main:refs/remotes/origin/main"],
        )
        .expect("second fetch fast-forwards through new commits");
        assert!(
            String::from_utf8_lossy(&out).contains(&tip2.to_hex()),
            "got {:?}",
            out
        );
        let landed = super::state::resolve_rev(
            dst_ctx.store().expect("store"),
            dst_ctx.kind().expect("kind"),
            "refs/remotes/origin/main",
        )
        .expect("tracking tip");
        assert_eq!(tip2, landed);
        let out = run(
            verbs_transport::fetch,
            &mut dst_ctx,
            &["origin", "refs/heads/side:refs/remotes/origin/main"],
        )
        .expect("rewind is a refusal, not an error");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("non-fast-forward"), "got {text}");
        let kept = super::state::resolve_rev(
            dst_ctx.store().expect("store"),
            dst_ctx.kind().expect("kind"),
            "refs/remotes/origin/main",
        )
        .expect("tracking tip after refusal");
        assert_eq!(tip2, kept);
        assert!(
            ruk_git::transport::has_object(dst_ctx.store().expect("store"), side)
                .expect("has side"),
            "refused tip's objects stay"
        );
    }
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn push_mirror_syncs_refs_and_deletes_stale() {
    let (src, _) = seeded_repo("mirror-src", "m.txt", b"m\n");
    let src_tip = {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(verbs_branch::branch, &mut src_ctx, &["feat"]).expect("branch feat");
        run(verbs_branch::tag, &mut src_ctx, &["v1"]).expect("tag v1");
        super::state::head_oid(src_ctx.store().expect("store")).expect("src tip")
    };
    let (dst, _) = seeded_repo("mirror-dst", "d.txt", b"d\n");
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        run(verbs_branch::branch, &mut dst_ctx, &["stale"]).expect("branch stale");
    }
    {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(
            verbs_repo::remote,
            &mut src_ctx,
            &["add", "origin", dst.to_str().expect("utf8")],
        )
        .expect("remote add");
        let out = run(verbs_transport::push, &mut src_ctx, &["--mirror", "origin"])
            .expect("push --mirror");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("ok refs/heads/feat"), "got {text}");
    }
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/heads/feat"), "got {text}");
        assert!(text.contains("refs/tags/v1"), "got {text}");
        assert!(!text.contains("refs/heads/stale"), "got {text}");
        let dst_main = super::state::resolve_rev(
            dst_ctx.store().expect("store"),
            dst_ctx.kind().expect("kind"),
            "refs/heads/main",
        )
        .expect("dst main");
        assert_eq!(src_tip, dst_main, "mirror forces main to the source tip");
    }
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn remote_update_fetches_configured_specs() {
    let (src, _) = seeded_repo("update-src", "u.txt", b"u\n");
    let (dst, _) = seeded_repo("update-dst", "w.txt", b"w\n");
    let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
    run(
        verbs_repo::remote,
        &mut dst_ctx,
        &["add", "origin", src.to_str().expect("utf8")],
    )
    .expect("remote add");
    let out = run(verbs_repo::remote, &mut dst_ctx, &["update", "origin"]).expect("remote update");
    assert!(
        String::from_utf8_lossy(&out).contains("refs/remotes/origin/main"),
        "got {:?}",
        out
    );
    let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
    assert!(
        String::from_utf8_lossy(&out).contains("refs/remotes/origin/main"),
        "tracking ref landed"
    );
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn receive_pack_enforces_store_lfs_policy() {
    use ruk_core::store::types::ObjectKind;
    use ruk_git::transport::Interrupt;
    use ruk_git::transport::pack::{PackEntry, write_pack};
    use ruk_git::transport::pktline::{Packet, decode_frame, encode_data};

    const POINTER: &[u8] = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n";

    fn pointer_pack(kind: HashKind) -> (String, Vec<u8>) {
        let blob = kind.hash_git_object("blob", POINTER).expect("blob id");
        let mut tree = b"100644 asset.bin\0".to_vec();
        tree.extend_from_slice(blob.as_bytes());
        let tree_id = kind.hash_git_object("tree", &tree).expect("tree id");
        let commit = format!(
            "tree {}\nauthor T <t@example.invalid> 0 +0000\ncommitter T <t@example.invalid> 0 +0000\n\npointer\n",
            tree_id.to_hex()
        );
        let commit_id = kind
            .hash_git_object("commit", commit.as_bytes())
            .expect("commit id");
        let entries = [
            (blob, ObjectKind::Blob, POINTER.to_vec()),
            (tree_id, ObjectKind::Tree, tree),
            (commit_id, ObjectKind::Commit, commit.into_bytes()),
        ];
        let pack_entries: Vec<PackEntry<'_>> = entries
            .iter()
            .map(|(oid, kind, bytes)| PackEntry {
                oid: *oid,
                kind: *kind,
                bytes,
                base: None,
            })
            .collect();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, &Interrupt::none()).expect("pack");
        (commit_id.to_hex(), pack)
    }

    fn push_input(tip: &str, zero: &str, pack: &[u8]) -> Vec<u8> {
        let mut input = Vec::new();
        encode_data(
            &mut input,
            format!("{zero} {tip} refs/heads/lfs\0report-status\n").as_bytes(),
        )
        .expect("frame");
        input.extend_from_slice(b"0000");
        input.extend_from_slice(pack);
        input
    }

    fn report_lines(report: &[u8]) -> Vec<Vec<u8>> {
        let mut bytes = report;
        let mut sections = Vec::new();
        for _ in 0..2 {
            let mut lines = Vec::new();
            loop {
                let (packet, consumed) = decode_frame(bytes).expect("frame").expect("complete");
                bytes = &bytes[consumed..];
                match packet {
                    Packet::Flush => break,
                    Packet::Data(payload) => lines.push(payload.to_vec()),
                    other => panic!("unexpected {other:?}"),
                }
            }
            sections.push(lines);
        }
        sections.into_iter().nth(1).expect("report section")
    }

    let (root, _) = seeded_repo("lfs-policy", "l.txt", b"l\n");
    let mut ctx = repo_ctx(&root, test_env(&root));
    let kind = ctx.kind().expect("kind");
    let (tip, pack) = pointer_pack(kind);
    let zero = kind.zero_oid().to_hex();
    // Default: no policy.toml, so pointers are refused.
    ctx.env.stdin = Some(push_input(&tip, &zero, &pack));
    let report = run(verbs_transport::receive_pack, &mut ctx, &[]).expect("receive reports ng");
    let lines = report_lines(&report);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], b"unpack ok\n".to_vec());
    assert!(
        lines[1].starts_with(b"ng refs/heads/lfs "),
        "got {:?}",
        lines[1]
    );
    assert!(
        String::from_utf8_lossy(&lines[1]).contains("E_UNSUPPORTED_LFS"),
        "got {:?}",
        lines[1]
    );
    // Opt-in: `lfs = "pointers"` records the bytes plainly.
    std::fs::write(
        root.join(".ruk").join("policy.toml"),
        "version = 1\nlfs = \"pointers\"\n",
    )
    .expect("policy");
    ctx.env.stdin = Some(push_input(&tip, &zero, &pack));
    let report = run(verbs_transport::receive_pack, &mut ctx, &[]).expect("receive accepts");
    let lines = report_lines(&report);
    assert_eq!(
        lines,
        vec![b"unpack ok\n".to_vec(), b"ok refs/heads/lfs\n".to_vec()]
    );
    // Fail-closed: a file the coordinator policy loader refuses never
    // enables pointers, even with `lfs = "pointers"` set.
    std::fs::write(
        root.join(".ruk").join("policy.toml"),
        "version = 1\nlfs = \"pointers\"\nunknown = 1\n",
    )
    .expect("policy");
    ctx.env.stdin = Some(push_input(&tip, &zero, &pack));
    let report = run(verbs_transport::receive_pack, &mut ctx, &[]).expect("receive reports ng");
    let lines = report_lines(&report);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], b"unpack ok\n".to_vec());
    assert!(
        lines[1].starts_with(b"ng refs/heads/lfs "),
        "got {:?}",
        lines[1]
    );
    assert!(
        String::from_utf8_lossy(&lines[1]).contains("E_UNSUPPORTED_LFS"),
        "got {:?}",
        lines[1]
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Indexes one pack into a fresh repository, returning its context.
fn indexed_repo(case: &str, pack: Vec<u8>) -> (PathBuf, CliEnv, Ctx) {
    let base = temp_base(case);
    let env = test_env(&base);
    let mut init_ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env: env.clone(),
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    run(verbs_repo::init, &mut init_ctx, &["dst"]).expect("init");
    let root = base.join("dst");
    let env = test_env(&base);
    let mut ctx = repo_ctx(&root, env.clone());
    ctx.env.stdin = Some(pack);
    run(verbs_objects::index_pack, &mut ctx, &["--stdin"]).expect("index-pack");
    (root, env, ctx)
}

#[test]
fn pack_objects_revs_round_trip_through_index_pack() {
    let (root, env) = seeded_repo("packobj-rt", "a.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env.clone());
    std::fs::write(root.join("b.txt"), b"two\n").expect("second file");
    run(verbs_stage::add, &mut ctx, &["b.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let tip = String::from_utf8_lossy(
        &run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .trim()
    .to_owned();
    ctx.env.stdin = Some(b"HEAD\n".to_vec());
    let pack = run(
        verbs_objects::pack_objects,
        &mut ctx,
        &["--revs", "--stdout"],
    )
    .expect("pack-objects");
    assert!(pack.starts_with(b"PACK"), "not a pack stream");
    let (_dst, _env, mut dst) = indexed_repo("packobj-rt-dst", pack);
    let count =
        String::from_utf8_lossy(&run(verbs_objects::count_objects, &mut dst, &[]).expect("count"))
            .into_owned();
    assert!(count.starts_with("6 objects,"), "{count}");
    let walked = String::from_utf8_lossy(
        &run(
            verbs_history::rev_list,
            &mut dst,
            &[tip.as_str(), "--count"],
        )
        .expect("rev-list"),
    )
    .into_owned();
    assert_eq!(walked, "2\n", "{walked}");
}

#[test]
fn pack_objects_exact_mode_packs_named_objects_only() {
    let (root, env) = seeded_repo("packobj-exact", "a.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let kind = ctx.kind().expect("kind");
    let (blob, commit) = {
        let store = ctx.store().expect("store");
        (
            super::verbs_history::resolve_local(store, kind, "HEAD:a.txt").expect("blob"),
            super::verbs_history::resolve_local(store, kind, "HEAD").expect("commit"),
        )
    };
    ctx.env.stdin = Some(
        format!(
            "{}\n-{}\n{}\n",
            blob.to_hex(),
            blob.to_hex(),
            commit.to_hex()
        )
        .into_bytes(),
    );
    let pack = run(verbs_objects::pack_objects, &mut ctx, &["--stdout"]).expect("pack-objects");
    let (_dst, _env, mut dst) = indexed_repo("packobj-exact-dst", pack);
    let count =
        String::from_utf8_lossy(&run(verbs_objects::count_objects, &mut dst, &[]).expect("count"))
            .into_owned();
    assert!(count.starts_with("2 objects,"), "{count}");
    let hex = commit.to_hex();
    let present = run(verbs_objects::cat_file, &mut dst, &["-e", hex.as_str()]);
    assert!(present.is_ok(), "indexed commit must exist");
}

#[test]
fn pack_objects_file_mode_writes_base_pack() {
    let (root, env) = seeded_repo("packobj-file", "a.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    ctx.env.stdin = Some(b"HEAD\n".to_vec());
    let out = run(verbs_objects::pack_objects, &mut ctx, &["--revs", "out"]).expect("pack-objects");
    assert!(out.is_empty(), "file mode stays silent");
    let pack = std::fs::read(root.join("out.pack")).expect("pack file");
    assert!(pack.starts_with(b"PACK"), "not a pack stream");
    let (_dst, _env, mut dst) = indexed_repo("packobj-file-dst", pack);
    let count =
        String::from_utf8_lossy(&run(verbs_objects::count_objects, &mut dst, &[]).expect("count"))
            .into_owned();
    assert!(count.starts_with("3 objects,"), "{count}");
}

#[test]
fn pack_plumbing_rejects_thin_file_garbage_and_usage() {
    let (root, env) = seeded_repo("packobj-err", "a.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let err =
        run(verbs_objects::pack_objects, &mut ctx, &["--thin", "out"]).expect_err("thin file pack");
    assert!(matches!(err, ruk_git::GitError::Invalid { .. }), "{err}");
    let err = run(
        verbs_objects::pack_objects,
        &mut ctx,
        &["--stdout", "extra"],
    )
    .expect_err("trailing argv");
    assert!(matches!(err, ruk_git::GitError::Invalid { .. }), "{err}");
    ctx.env.stdin = Some(b"not-an-oid\n".to_vec());
    let err = run(verbs_objects::pack_objects, &mut ctx, &["--stdout"]).expect_err("garbage oid");
    assert!(matches!(err, ruk_git::GitError::Invalid { .. }), "{err}");
    ctx.env.stdin = None;
    let err = run(verbs_objects::index_pack, &mut ctx, &[]).expect_err("no source");
    assert!(matches!(err, ruk_git::GitError::Invalid { .. }), "{err}");
    ctx.env.stdin = Some(b"garbage".to_vec());
    let err = run(verbs_objects::index_pack, &mut ctx, &["--stdin"]).expect_err("garbage pack");
    assert!(matches!(err, ruk_git::GitError::Corrupt { .. }), "{err}");
}

/// Builds a repo with one orphaned side commit, returning its hex.
fn orphaned_side_commit(case: &str) -> (PathBuf, CliEnv, String) {
    let (root, env) = seeded_repo(case, "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env.clone());
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    std::fs::write(root.join("side.txt"), b"side\n").expect("side file");
    run(verbs_stage::add, &mut ctx, &["side.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "side"]).expect("commit");
    let orphan = String::from_utf8_lossy(
        &run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .trim()
    .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    // Forced delete records no reflog, so the side commit is truly orphaned.
    run(verbs_branch::branch, &mut ctx, &["-D", "side"]).expect("branch -D");
    (root, env, orphan)
}

#[test]
fn gc_prunes_orphaned_commit_and_keeps_reachable() {
    let (root, env, orphan) = orphaned_side_commit("gcprune");
    let mut ctx = repo_ctx(&root, env);
    let dangling = String::from_utf8_lossy(
        &run(verbs_transport::fsck, &mut ctx, &["--unreachable"]).expect("fsck"),
    )
    .into_owned();
    assert!(dangling.contains(&orphan), "orphan dangling: {dangling}");
    let before = String::from_utf8_lossy(
        &run(verbs_objects::count_objects, &mut ctx, &[]).expect("count before"),
    )
    .into_owned();
    let out =
        String::from_utf8_lossy(&run(verbs_transport::gc, &mut ctx, &[]).expect("gc")).into_owned();
    assert!(out.contains("pruned"), "{out}");
    assert!(
        run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).is_err(),
        "orphan pruned"
    );
    run(verbs_objects::cat_file, &mut ctx, &["-e", "HEAD"]).expect("HEAD kept");
    let after = String::from_utf8_lossy(
        &run(verbs_objects::count_objects, &mut ctx, &[]).expect("count after"),
    )
    .into_owned();
    assert_ne!(before, after, "census shrank");
    let clean = String::from_utf8_lossy(
        &run(verbs_transport::fsck, &mut ctx, &["--unreachable"]).expect("fsck clean"),
    )
    .into_owned();
    assert!(!clean.contains("dangling"), "no dangling left: {clean}");
    let out = run(verbs_transport::gc, &mut ctx, &["--auto"]).expect("auto");
    assert!(out.is_empty(), "auto is quiet with no work");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn gc_dry_run_reports_without_mutating() {
    let (root, env, orphan) = orphaned_side_commit("gcdry");
    let mut ctx = repo_ctx(&root, env);
    let before = String::from_utf8_lossy(
        &run(verbs_objects::count_objects, &mut ctx, &[]).expect("count before"),
    )
    .into_owned();
    let out = String::from_utf8_lossy(
        &run(verbs_transport::gc, &mut ctx, &["--dry-run"]).expect("dry-run"),
    )
    .into_owned();
    assert!(out.contains("Would prune"), "{out}");
    run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).expect("orphan kept");
    let after = String::from_utf8_lossy(
        &run(verbs_objects::count_objects, &mut ctx, &[]).expect("count after"),
    )
    .into_owned();
    assert_eq!(before, after, "dry-run changes nothing");
    let out = String::from_utf8_lossy(
        &run(verbs_transport::gc, &mut ctx, &["--prune=never"]).expect("prune=never"),
    )
    .into_owned();
    assert!(!out.contains("pruned"), "{out}");
    run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).expect("orphan still kept");
    let err =
        run(verbs_transport::gc, &mut ctx, &["--prune=2.weeks.ago"]).expect_err("dated prune");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn serve_verbs_round_trip_scripted_stdin() {
    use ruk_git::transport::pktline::{Packet, decode_frame, encode_data, encode_flush};

    fn framed(line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_data(&mut out, line).expect("frame");
        out
    }

    /// Splits data payloads up to the first flush from the raw rest.
    fn split_at_flush(mut bytes: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut lines = Vec::new();
        loop {
            let (packet, consumed) = decode_frame(bytes).expect("frame").expect("complete");
            bytes = &bytes[consumed..];
            match packet {
                Packet::Flush => return (lines, bytes.to_vec()),
                Packet::Data(payload) => lines.push(payload.to_vec()),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    let (root_a, _) = seeded_repo("serve-a", "a.txt", b"a\n");
    let mut ctx_a = repo_ctx(&root_a, test_env(&root_a));
    let tip = super::state::head_oid(ctx_a.store().expect("store")).expect("tip");
    let mut input =
        framed(format!("want {} multi_ack_detailed agent=test\n", tip.to_hex()).as_bytes());
    input.extend_from_slice(b"0000");
    input.extend_from_slice(b"0000");
    input.extend_from_slice(&framed(b"done\n"));
    ctx_a.env.stdin = Some(input);
    let out = run(verbs_transport::upload_pack, &mut ctx_a, &[]).expect("upload");
    let (adv, rest) = split_at_flush(&out);
    let needle = b"refs/heads/main";
    assert!(
        adv.iter()
            .any(|line| line.windows(needle.len()).any(|w| w == needle))
    );
    // Two NAK verdicts, then the raw pack with no closing flush.
    let (packet, consumed) = decode_frame(&rest).expect("frame").expect("complete");
    assert!(matches!(packet, Packet::Data(payload) if payload == b"NAK\n"));
    let rest = &rest[consumed..];
    let (packet, consumed) = decode_frame(rest).expect("frame").expect("complete");
    assert!(matches!(packet, Packet::Data(payload) if payload == b"NAK\n"));
    let pack = &rest[consumed..];
    assert!(pack.starts_with(b"PACK"), "pack magic");

    let (root_b, _) = seeded_repo("serve-b", "b.txt", b"b\n");
    let mut ctx_b = repo_ctx(&root_b, test_env(&root_b));
    let zero = tip.kind().zero_oid().to_hex();
    let mut push = framed(
        format!(
            "{zero} {} refs/heads/from-upload\0report-status\n",
            tip.to_hex()
        )
        .as_bytes(),
    );
    push.extend_from_slice(b"0000");
    push.extend_from_slice(&pack);
    ctx_b.env.stdin = Some(push);
    let report = run(verbs_transport::receive_pack, &mut ctx_b, &[]).expect("receive");
    let (_, after_adv) = split_at_flush(&report);
    let (lines, rest) = split_at_flush(&after_adv);
    assert!(rest.is_empty());
    assert_eq!(
        lines,
        vec![
            b"unpack ok\n".to_vec(),
            b"ok refs/heads/from-upload\n".to_vec(),
        ]
    );
    let refs = super::state::list_refs(ctx_b.store().expect("store")).expect("refs");
    assert!(refs.iter().any(
        |(name, target)| name.as_bytes() == b"refs/heads/from-upload"
            && matches!(target, ruk_core::refdata::RefTarget::Direct(oid) if *oid == tip)
    ));

    let _ = std::fs::remove_dir_all(root_a.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(root_b.parent().expect("parent"));
}

#[test]
fn upload_archive_argv_reaches_serve_half() {
    use ruk_git::transport::pktline::encode_data;

    let (root, env) = seeded_repo("serve-archive", "a.txt", b"a\n");
    let mut input = Vec::new();
    encode_data(&mut input, b"argument HEAD\n").expect("frame");
    input.extend_from_slice(b"0000");
    let env = CliEnv {
        stdin: Some(input),
        ..env
    };
    let argv = vec![
        "ruk".to_owned(),
        "upload-archive".to_owned(),
        root.to_str().expect("utf8 root").to_owned(),
    ];
    let (stdout, _) = super::run_inner(&argv, env).expect("upload-archive routes");
    assert!(
        stdout.starts_with(b"0008ACK\n0000"),
        "argv reaches serve_upload_archive: {stdout:?}"
    );
    assert!(lookup("upload-archive").is_some());

    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn serve_argv_maps_ssh_argv0_and_ruk_spellings() {
    // argv[0] dashed names: ssh spawns `git-upload-pack '<dir>'` verbatim.
    for (arg0, verb) in [
        ("git-upload-pack", "upload-pack"),
        ("git-receive-pack", "receive-pack"),
        ("git-upload-archive", "upload-archive"),
        ("/usr/lib/ssh/git-upload-pack", "upload-pack"),
    ] {
        let argv = vec![arg0.to_owned(), "repo".to_owned()];
        let rest = super::serve_argv(&argv).expect("server argv");
        assert_eq!(
            rest,
            vec![arg0.to_owned(), verb.to_owned(), "repo".to_owned()]
        );
    }
    // `ruk upload-pack <dir>` (and `git upload-pack <dir>`) from a shell.
    for prog in ["ruk", "git"] {
        let argv = vec![prog.to_owned(), "upload-pack".to_owned(), "repo".to_owned()];
        assert_eq!(super::serve_argv(&argv).expect("plain spelling"), argv);
    }
    // Untouched: ordinary verbs and the `ruk git` path keep their dispatch.
    assert!(super::serve_argv(&["ruk".to_owned(), "status".to_owned()]).is_none());
    assert!(super::serve_argv(&["ruk".to_owned()]).is_none());
    assert!(super::serve_argv(&[]).is_none());
    assert!(
        super::serve_argv(&["ruk".to_owned(), "git".to_owned(), "upload-pack".to_owned()])
            .is_none()
    );
    // Dashed names resolve through the dispatch table like `git.c`.
    for (dashed, plain) in [
        ("git-upload-pack", "upload-pack"),
        ("git-receive-pack", "receive-pack"),
        ("git-upload-archive", "upload-archive"),
    ] {
        let entry = lookup(dashed).expect("dashed resolves");
        assert_eq!(entry.name, plain);
        assert_eq!(lookup(plain).expect("plain resolves").name, plain);
    }
    assert!(lookup("git-nope").is_none());
}

#[test]
fn dashed_upload_archive_argv_reaches_serve_half() {
    use ruk_git::transport::pktline::encode_data;

    let (root, env) = seeded_repo("serve-archive-dashed", "a.txt", b"a\n");
    let mut input = Vec::new();
    encode_data(&mut input, b"argument HEAD\n").expect("frame");
    input.extend_from_slice(b"0000");
    let env = CliEnv {
        stdin: Some(input),
        ..env
    };
    let argv = vec![
        "ruk".to_owned(),
        "git-upload-archive".to_owned(),
        root.to_str().expect("utf8 root").to_owned(),
    ];
    let (stdout, _) = super::run_inner(&argv, env).expect("dashed routes");
    assert!(
        stdout.starts_with(b"0008ACK\n0000"),
        "dashed argv reaches serve_upload_archive: {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn parity_cosmetic_output_shapes() {
    let (root, env) = seeded_repo("shapes", "a.txt", b"hello\n");
    let mut ctx = repo_ctx(&root, env);
    // Second commit on a modified file: short branch, diffstat, no
    // per-file lines, no create/delete lines for pure modifications.
    std::fs::write(root.join("a.txt"), b"hello world\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["a.txt"]).expect("add");
    let out = run(verbs_history::commit, &mut ctx, &["-m", "two"]).expect("commit");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.starts_with("[main "), "header: {text}");
    assert!(text.contains(" 1 file changed, 1 insertion(+), 1 deletion(-)\n"));
    assert!(!text.contains("create mode"), "no mode lines: {text}");
    // Dirty long status carries the oracle hint lines and aligned entries.
    std::fs::write(root.join("a.txt"), b"hello again\n").expect("dirty");
    let out = run(verbs_stage::status, &mut ctx, &[]).expect("status");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.starts_with("On branch main\n"), "branch: {text}");
    assert!(text.contains("  (use \"git add <file>...\" to update what will be committed)\n"));
    assert!(text.contains("\tmodified:   a.txt\n"), "entry: {text}");
    assert!(
        text.contains("no changes added to commit (use \"git add\" and/or \"git commit -a\")\n")
    );
    // Unstaged diff carries the index line and the compact hunk header.
    let out = run(verbs_history::diff, &mut ctx, &[]).expect("diff");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("diff --git a/a.txt b/a.txt\n"));
    assert!(text.contains("index "), "index line: {text}");
    assert!(text.contains("@@ -1 +1 @@\n"), "hunk: {text}");
    // Branch switches report on stderr, leaving stdout empty.
    ctx.stderr.clear();
    let out = run(verbs_branch::checkout, &mut ctx, &["-b", "feat"]).expect("checkout -b");
    assert!(out.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&ctx.stderr),
        "Switched to a new branch 'feat'\n"
    );
    ctx.stderr.clear();
    let out = run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout");
    assert!(out.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&ctx.stderr),
        "Switched to branch 'main'\n"
    );
    // Remote verbose lists fetch and push lines; rm names each file.
    run(
        verbs_repo::remote,
        &mut ctx,
        &["add", "origin", "https://example.com/x.git"],
    )
    .expect("remote add");
    let out = run(verbs_repo::remote, &mut ctx, &["-v"]).expect("remote -v");
    assert_eq!(
        String::from_utf8_lossy(&out),
        "origin\thttps://example.com/x.git (fetch)\norigin\thttps://example.com/x.git (push)\n"
    );
    let out = run(verbs_stage::rm, &mut ctx, &["a.txt"]).expect("rm");
    assert_eq!(String::from_utf8_lossy(&out), "rm 'a.txt'\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn walk_orders_merge_topology_by_committer_date() {
    use ruk_core::ByteString;
    use ruk_core::conflict::{Signature, TzOffset};
    use ruk_core::heads::Head;
    use ruk_core::ids::Oid;
    use ruk_core::ops::{NewRequest, new as ops_new};
    use ruk_core::store::ObjectKind;

    let base = temp_base("logdate");
    let env = test_env(&base);
    let mut ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env,
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
    let root = base.join("repo");
    let store = open_store(&root);
    let tree = super::tree::store_object(&store, ObjectKind::Tree, Vec::new()).expect("empty tree");
    let sig = |timestamp: i64| Signature {
        name: ByteString::from("Tariq"),
        email: ByteString::from("tariq@example.invalid"),
        timestamp,
        offset: TzOffset::UTC,
    };
    let make = |parents: Vec<Head>, timestamp: i64, message: &str| -> Oid {
        ops_new(
            &store,
            NewRequest {
                tree,
                parents,
                author: sig(timestamp),
                committer: sig(timestamp),
                message: ByteString::from(message),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("new commit")
        .oid
        .expect("git commit")
    };
    // Two parents with interleaved stamps: the second parent (1500) is
    // newer than the first parent (1200), so date order must list it first
    // even though LIFO discovery would emit the first parent's chain first.
    let seed = make(vec![], 1000, "seed\n");
    let add_a = make(vec![Head::Git { oid: seed }], 1100, "add a\n");
    let feature = make(vec![Head::Git { oid: add_a }], 1500, "feature work\n");
    let main2 = make(vec![Head::Git { oid: add_a }], 1200, "main moves on\n");
    let merge = make(
        vec![Head::Git { oid: main2 }, Head::Git { oid: feature }],
        1600,
        "merge feature\n",
    );
    let history = super::state::walk_history(&store, &[merge], None).expect("walk history");
    let subjects: Vec<String> = history
        .iter()
        .map(|(_, record)| {
            let message = record.message();
            let end = message
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(message.len());
            String::from_utf8_lossy(&message[..end]).into_owned()
        })
        .collect();
    assert_eq!(
        subjects,
        vec![
            "merge feature",
            "feature work",
            "main moves on",
            "add a",
            "seed",
        ]
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn log_excluding_skips_branch_in_date_order() {
    use ruk_core::ByteString;
    use ruk_core::conflict::{Signature, TzOffset};
    use ruk_core::heads::Head;
    use ruk_core::ids::Oid;
    use ruk_core::ops::{NewRequest, new as ops_new};
    use ruk_core::store::ObjectKind;

    let base = temp_base("logexclude");
    let env = test_env(&base);
    let mut ctx = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env,
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
    let root = base.join("repo");
    let store = open_store(&root);
    let tree = super::tree::store_object(&store, ObjectKind::Tree, Vec::new()).expect("empty tree");
    let sig = |timestamp: i64| Signature {
        name: ByteString::from("Tariq"),
        email: ByteString::from("tariq@example.invalid"),
        timestamp,
        offset: TzOffset::UTC,
    };
    let make = |parents: Vec<Head>, timestamp: i64, message: &str| -> Oid {
        ops_new(
            &store,
            NewRequest {
                tree,
                parents,
                author: sig(timestamp),
                committer: sig(timestamp),
                message: ByteString::from(message),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("new commit")
        .oid
        .expect("git commit")
    };
    // Same interleaved merge topology as the walk test, excluding only the
    // root: both sides stay live, so LIFO discovery (second-parent chain
    // first) disagrees with date order on `main moves on` vs `add a` — the
    // exact shape `log <tip> ^<exclude>` walks.
    let seed = make(vec![], 1000, "seed\n");
    let add_a = make(vec![Head::Git { oid: seed }], 1100, "add a\n");
    let feature = make(vec![Head::Git { oid: add_a }], 1500, "feature work\n");
    let main2 = make(vec![Head::Git { oid: add_a }], 1200, "main moves on\n");
    let merge = make(
        vec![Head::Git { oid: main2 }, Head::Git { oid: feature }],
        1600,
        "merge feature\n",
    );
    let history = super::verbs_history::walk_history_excluding(&store, &[merge], &[seed], None)
        .expect("excluding walk");
    let subjects: Vec<String> = history
        .iter()
        .map(|(_, record)| {
            let message = record.message();
            let end = message
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(message.len());
            String::from_utf8_lossy(&message[..end]).into_owned()
        })
        .collect();
    assert_eq!(
        subjects,
        vec!["merge feature", "feature work", "main moves on", "add a"]
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn file_url_remote_fetch_push_cycle() {
    // `file://` remotes route through URL parsing into the same local
    // stores bare paths reach: fetch, ls-remote, and push all work.
    let (src, _) = seeded_repo("fileurl-src", "f.txt", b"f\n");
    let src_url = format!("file://{}", src.to_str().expect("utf8"));
    let (dst, _) = seeded_repo("fileurl-dst", "g.txt", b"g\n");
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        run(
            verbs_repo::remote,
            &mut dst_ctx,
            &["add", "origin", &src_url],
        )
        .expect("remote add file://");
        run(verbs_transport::fetch, &mut dst_ctx, &["origin"]).expect("fetch file://");
        let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/remotes/origin/main"), "got {text}");
        let out =
            run(verbs_transport::ls_remote, &mut dst_ctx, &["origin"]).expect("ls-remote file://");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/heads/main"), "got {text}");
    }
    {
        // Push back through the URL onto a new branch (the two seeds are
        // unrelated histories, so main-to-main would rightly not
        // fast-forward), then read the branch from the source.
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        std::fs::write(dst.join("h.txt"), b"h\n").expect("new file");
        run(verbs_stage::add, &mut dst_ctx, &["h.txt"]).expect("add");
        run(verbs_history::commit, &mut dst_ctx, &["-m", "via file url"]).expect("commit");
        run(
            verbs_transport::push,
            &mut dst_ctx,
            &["origin", "main:refs/heads/contrib"],
        )
        .expect("push file://");
    }
    {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        let out = run(verbs_branch::show_ref, &mut src_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/heads/contrib"), "got {text}");
        let out =
            run(verbs_history::log, &mut src_ctx, &["--oneline", "contrib"]).expect("log contrib");
        assert!(
            String::from_utf8_lossy(&out).contains("via file url"),
            "got {:?}",
            out
        );
    }
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn file_url_positional_push_with_refspec() {
    // A positional `file://` URL (no remote name) pushes an explicit
    // refspec through the same routing.
    let (src, _) = seeded_repo("filepos-src", "f.txt", b"f\n");
    let (dst, _) = seeded_repo("filepos-dst", "g.txt", b"g\n");
    let dst_url = format!("file://{}", dst.to_str().expect("utf8"));
    {
        let mut src_ctx = repo_ctx(&src, test_env(&src));
        run(
            verbs_transport::push,
            &mut src_ctx,
            &[&dst_url, "main:refs/heads/seeded"],
        )
        .expect("push file:// url");
    }
    {
        let mut dst_ctx = repo_ctx(&dst, test_env(&dst));
        let out = run(verbs_branch::show_ref, &mut dst_ctx, &[]).expect("show-ref");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("refs/heads/seeded"), "got {text}");
    }
    let _ = std::fs::remove_dir_all(src.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(dst.parent().expect("parent"));
}

#[test]
fn network_scheme_routing_names_gaps() {
    use ruk_git::GitError;
    let (root, _) = seeded_repo("netroute", "n.txt", b"n\n");
    // SSH to a closed loopback port: TCP refuses at once (no prompt, no
    // hang), and the failure must come from the network path, never the
    // old local-path refusal.
    let mut ctx = repo_ctx(&root, test_env(&root));
    let err = run(
        verbs_transport::ls_remote,
        &mut ctx,
        &["ssh://127.0.0.1:1/srv/a.git"],
    )
    .expect_err("ssh ls-remote must fail");
    assert!(
        !matches!(err, GitError::Offline { .. }),
        "took the local path: {err}"
    );
    let err = run(
        verbs_transport::fetch,
        &mut ctx,
        &["ssh://127.0.0.1:1/srv/a.git"],
    )
    .expect_err("ssh fetch must fail");
    assert!(
        !matches!(err, GitError::Offline { .. }),
        "took the local path: {err}"
    );
    // HTTP serves smart-http, so an unroutable host fails in the network
    // path (resolution), never as a gap and never as a local path. The
    // dumb-http gap itself is covered by the smart-http discovery tests.
    let err = run(
        verbs_transport::fetch,
        &mut ctx,
        &["https://host.invalid/a.git"],
    )
    .expect_err("https fetch must fail");
    assert!(
        !matches!(err, GitError::Unsupported { .. }),
        "smart-http regressed to the gap: {err}"
    );
    let err = run(
        verbs_transport::push,
        &mut ctx,
        &["http://host.invalid/a.git"],
    )
    .expect_err("http push must fail");
    assert!(
        !matches!(err, GitError::Unsupported { .. }),
        "smart-http regressed to the gap: {err}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn fetch_over_smart_http_publishes_pack_and_ref() {
    use std::net::TcpListener;

    use ruk_core::refdata::{RefName, RefRead as _};
    use ruk_core::refs::StoreRefs;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
        out.extend_from_slice(payload);
        out
    }
    fn sideband(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:04x}", payload.len() + 5).into_bytes();
        out.push(1);
        out.extend_from_slice(payload);
        out
    }
    let mut adv = frame(b"# service=git-upload-pack\n");
    adv.extend_from_slice(b"0000");
    adv.extend_from_slice(&frame(
        format!(
            "{FOUR} HEAD\0multi_ack_detailed side-band-64k thin-pack ofs-delta object-format=sha1\n"
        )
        .as_bytes(),
    ));
    adv.extend_from_slice(&frame(format!("{FOUR} refs/heads/main\n").as_bytes()));
    adv.extend_from_slice(b"0000");
    let pack = include_bytes!("../../../ruk-git/src/transport/fixtures/basic.pack");
    let mut result = frame(b"NAK\n");
    result.extend_from_slice(&sideband(pack));
    result.extend_from_slice(b"0000");

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
    let port = listener.local_addr().expect("addr").port();
    let (served_tx, served_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        for (body, ctype) in [
            (adv, "application/x-git-upload-pack-advertisement"),
            (result, "application/x-git-upload-pack-result"),
        ] {
            let (socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut reader = BufReader::new(socket.try_clone().expect("split"));
            let mut head = Vec::new();
            loop {
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).expect("request line");
                if line.is_empty() {
                    panic!("client hung up mid-request");
                }
                head.extend_from_slice(&line);
                if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let length = text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.trim().to_ascii_lowercase() == "content-length")
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if length > 0 {
                let mut discard = vec![0_u8; length];
                reader.read_exact(&mut discard).expect("request body");
            }
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {ctype}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut socket = socket;
            socket.write_all(reply.as_bytes()).expect("reply head");
            socket.write_all(&body).expect("reply body");
        }
        served_tx.send(()).expect("signal served");
    });

    let (root, env) = seeded_repo("httpfetch", "f.txt", b"f\n");
    let mut ctx = repo_ctx(&root, env);
    let url = format!("http://127.0.0.1:{port}/a.git");
    // Into a remote-tracking name: the seeded `main` already exists
    // locally, and fast-forward planning cannot walk a tip it has not
    // fetched yet.
    run(
        verbs_transport::fetch,
        &mut ctx,
        &[&url, "refs/heads/main:refs/remotes/origin/main"],
    )
    .expect("http fetch");
    // Bounded wait, never a bare join: a client that stops after
    // discovery must fail the test, not hang the suite.
    served_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("server finished both RPCs");
    let store = ctx.store().expect("store");
    let oid = ruk_core::ids::Oid::from_hex(FOUR).expect("hex");
    store.read(oid).expect("fetched object present");
    let name = RefName::new(b"refs/remotes/origin/main".to_vec()).expect("name");
    let target = StoreRefs::new(&store)
        .get(&name)
        .expect("read ref")
        .expect("ref present");
    assert_eq!(target, ruk_core::refdata::RefTarget::Direct(oid));
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Serves canned smart-http replies on loopback, recording every
/// request head plus body and delivering the log once all replies
/// are served. The receiver bounds the wait: a client that stops
/// early fails the test instead of hanging the suite.
fn smart_http_server(
    replies: Vec<(Vec<u8>, &'static str)>,
) -> (String, std::sync::mpsc::Receiver<Vec<(String, Vec<u8>)>>) {
    use std::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (body, ctype) in replies {
            let (socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut reader = BufReader::new(socket.try_clone().expect("split"));
            let mut head = Vec::new();
            loop {
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).expect("request line");
                if line.is_empty() {
                    panic!("client hung up mid-request");
                }
                head.extend_from_slice(&line);
                if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let length = text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.trim().to_ascii_lowercase() == "content-length")
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut request_body = vec![0_u8; length];
            if length > 0 {
                reader.read_exact(&mut request_body).expect("request body");
            }
            requests.push((text, request_body));
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {ctype}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut socket = socket;
            socket.write_all(reply.as_bytes()).expect("reply head");
            socket.write_all(&body).expect("reply body");
        }
        tx.send(requests).expect("deliver log");
    });
    (format!("http://127.0.0.1:{port}/a.git"), rx)
}

fn pkt_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload);
    out
}

#[test]
fn push_over_smart_http_reports_status() {
    const ZERO: &str = "0000000000000000000000000000000000000000";
    let mut adv = pkt_frame(b"# service=git-receive-pack\n");
    adv.extend_from_slice(b"0000");
    adv.extend_from_slice(&pkt_frame(
        format!("{ZERO} capabilities^{{}}\0report-status report-status-v2 side-band-64k delete-refs ofs-delta object-format=sha1\n")
            .as_bytes(),
    ));
    adv.extend_from_slice(b"0000");
    // side-band-64k was advertised, so the report rides channel 1.
    let mut report = pkt_frame(b"\x01unpack ok\n");
    report.extend_from_slice(&pkt_frame(b"\x01ok refs/heads/main\n"));
    report.extend_from_slice(b"0000");
    let (base, log) = smart_http_server(vec![
        (adv, "application/x-git-receive-pack-advertisement"),
        (report, "application/x-git-receive-pack-result"),
    ]);
    let (root, env) = seeded_repo("httppush", "p.txt", b"p\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(
        verbs_transport::push,
        &mut ctx,
        &[&base, "refs/heads/main:refs/heads/main"],
    )
    .expect("http push");
    assert_eq!(out, b"ok refs/heads/main\n");
    let requests = log
        .recv_timeout(Duration::from_secs(30))
        .expect("server finished both RPCs");
    assert_eq!(requests.len(), 2);
    let (head, body) = &requests[1];
    assert!(
        head.starts_with("POST /a.git/git-receive-pack HTTP/1.1\r\n"),
        "{head:?}"
    );
    assert!(
        body.windows(b"refs/heads/main".len())
            .any(|w| w == b"refs/heads/main"),
        "no command line"
    );
    assert!(body.windows(4).any(|w| w == b"PACK"), "no pack bytes");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn ls_remote_over_dumb_http_reads_info_refs() {
    const TIP: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    let dumb = format!("{TIP}\trefs/heads/main\n");
    let (base, log) = smart_http_server(vec![
        (b"not a smart advertisement".to_vec(), "text/plain"),
        (dumb.into_bytes(), "text/plain"),
        (b"ref: refs/heads/main\n".to_vec(), "text/plain"),
    ]);
    let (root, env) = seeded_repo("httpdumb", "l.txt", b"l\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_transport::ls_remote, &mut ctx, &[&base]).expect("dumb ls-remote");
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains(TIP), "{text}");
    assert!(text.contains("refs/heads/main"), "{text}");
    // The oracle reads the `HEAD` text file for the leading symref row.
    assert!(text.contains("ref: refs/heads/main\tHEAD\n"), "{text}");
    let requests = log
        .recv_timeout(Duration::from_secs(30))
        .expect("server saw all GETs");
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0].0.contains("service=git-upload-pack"),
        "{:?}",
        requests[0].0
    );
    assert!(
        requests[1].0.contains("GET /a.git/info/refs "),
        "{:?}",
        requests[1].0
    );
    assert!(
        requests[2].0.contains("GET /a.git/HEAD "),
        "{:?}",
        requests[2].0
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn ls_remote_over_smart_http_lists_refs() {
    const TIP: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    let mut adv = pkt_frame(b"# service=git-upload-pack\n");
    adv.extend_from_slice(b"0000");
    adv.extend_from_slice(&pkt_frame(
        format!("{TIP} HEAD\0multi_ack object-format=sha1\n").as_bytes(),
    ));
    adv.extend_from_slice(&pkt_frame(format!("{TIP} refs/heads/main\n").as_bytes()));
    adv.extend_from_slice(b"0000");
    let (base, log) = smart_http_server(vec![(adv, "application/x-git-upload-pack-advertisement")]);
    let (root, env) = seeded_repo("httpls", "l.txt", b"l\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_transport::ls_remote, &mut ctx, &[&base]).expect("http ls-remote");
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains(TIP), "{text}");
    assert!(text.contains("refs/heads/main"), "{text}");
    log.recv_timeout(Duration::from_secs(30))
        .expect("server finished discovery");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn credential_rejects_usage_before_reading_stdin() {
    let (root, env) = seeded_repo("cred-usage", "c.txt", b"c\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_transport::credential, &mut ctx, &[]).expect_err("no operation");
    run(verbs_transport::credential, &mut ctx, &["bogus"]).expect_err("bad operation");
    run(verbs_transport::credential, &mut ctx, &["fill", "extra"]).expect_err("two positionals");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn credential_fill_approve_reject_round_trip() {
    let base = temp_base("credential-live");
    let log = base.join("cred-ops.log");
    let script = base.join("cred-helper.sh");
    std::fs::write(
        &script,
        format!(
            "op=\"$1\"\ncat > /dev/null\nprintf '%s\\n' \"$op\" >> \"{}\"\n\
             if [ \"$op\" = \"get\" ]; then printf 'username=alice\\npassword=s3cret\\n'; fi\n",
            log.display()
        ),
    )
    .expect("helper script");
    let config = base.join("gitconfig");
    std::fs::write(
        &config,
        format!(
            "[credential \"https://cred-test.invalid\"]\n\thelper = !/bin/sh {}\n",
            script.display()
        ),
    )
    .expect("helper config");
    let (root, env) = seeded_repo("cred-live", "c.txt", b"c\n");
    let mut ctx = repo_ctx(&root, env);
    // Helper config files resolve against the captured environment only:
    // pointing the chain at the temp config touches no process state, so
    // parallel tests stay isolated.
    ctx.env
        .vars
        .insert("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned());
    ctx.env.vars.insert(
        "GIT_CONFIG_GLOBAL".to_owned(),
        config.to_string_lossy().into_owned(),
    );
    let desc =
        b"url=https://cred-test.invalid/x\nprotocol=https\nhost=cred-test.invalid\n\n".to_vec();
    ctx.env.stdin = Some(desc.clone());
    let out = run(verbs_transport::credential, &mut ctx, &["fill"]).expect("fill");
    assert_eq!(
        out,
        b"url=https://cred-test.invalid/x\nprotocol=https\nhost=cred-test.invalid\n\
          username=alice\npassword=s3cret\n"
    );
    ctx.env.stdin = Some(desc.clone());
    assert_eq!(
        run(verbs_transport::credential, &mut ctx, &["approve"]).expect("approve"),
        Vec::<u8>::new()
    );
    ctx.env.stdin = Some(desc);
    assert_eq!(
        run(verbs_transport::credential, &mut ctx, &["reject"]).expect("reject"),
        Vec::<u8>::new()
    );
    assert_eq!(
        std::fs::read_to_string(&log).expect("helper log"),
        "get\nstore\nerase\n"
    );
    // A description outside the scoped helper's URL matches nothing, so
    // `fill` reports no username instead of answering.
    ctx.env.stdin = Some(b"protocol=https\nhost=elsewhere.invalid\n\n".to_vec());
    run(verbs_transport::credential, &mut ctx, &["fill"]).expect_err("unmatched fill");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn archive_over_smart_http_streams_tar() {
    let tar = b"fake-tar-bytes".to_vec();
    let mut body = pkt_frame(b"ACK\n");
    body.extend_from_slice(b"0000");
    let mut frame = format!("{:04x}", tar.len() + 5).into_bytes();
    frame.push(1);
    frame.extend_from_slice(&tar);
    body.extend_from_slice(&frame);
    body.extend_from_slice(b"0000");
    let (base, log) = smart_http_server(vec![(body, "application/x-git-upload-archive-result")]);
    let (root, env) = seeded_repo("uarchive-http", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let remote = format!("--remote={base}");
    let out = run(verbs_transport::archive, &mut ctx, &[&remote, "HEAD"]).expect("http archive");
    assert_eq!(out, tar);
    let requests = log
        .recv_timeout(Duration::from_secs(30))
        .expect("server finished the RPC");
    assert_eq!(requests.len(), 1);
    let (head, req_body) = &requests[0];
    assert!(
        head.starts_with("POST /a.git/git-upload-archive HTTP/1.1\r\n"),
        "{head:?}"
    );
    assert!(
        req_body
            .windows(b"argument --format=tar\n".len())
            .any(|w| w == b"argument --format=tar\n"),
        "no format line in {req_body:?}"
    );
    assert!(
        req_body
            .windows(b"argument HEAD\n".len())
            .any(|w| w == b"argument HEAD\n"),
        "no revision line in {req_body:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_local_streams_tar() {
    let (root, env) = seeded_repo("uarchive-local", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_transport::archive, &mut ctx, &["HEAD"]).expect("local archive");
    assert!(
        out.len() >= 1024,
        "tar ends with two zero blocks: {}",
        out.len()
    );
    assert!(
        out[out.len() - 1024..].iter().all(|byte| *byte == 0),
        "missing tar trailer"
    );
    assert!(
        out.windows(b"a.txt".len()).any(|w| w == b"a.txt"),
        "tar names the file"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_zip_roundtrip_reads_back() {
    let (root, env) = seeded_repo("uarchive-zip", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    // The tar path stays byte-identical to the default (no --format) flow.
    let tar = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=tar", "HEAD"],
    )
    .expect("explicit tar");
    let default = run(verbs_transport::archive, &mut ctx, &["HEAD"]).expect("default tar");
    assert_eq!(tar, default);
    let zip = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=zip", "HEAD"],
    )
    .expect("zip archive");
    assert!(
        zip.starts_with(b"PK"),
        "zip magic, got {:?}",
        &zip[..4.min(zip.len())]
    );
    // Read back through the writer crate: the central directory parses and
    // the payload verifies against its CRC.
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip)).expect("readable zip");
    let names: Vec<String> = archive
        .file_names()
        .map(|name| name.expect("entry name").into_owned())
        .collect();
    assert!(names.contains(&"a.txt".to_owned()), "{names:?}");
    let mut file = archive.by_name("a.txt").expect("entry");
    assert_eq!(file.compression(), zip::CompressionMethod::Deflated);
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut body).expect("payload");
    assert_eq!(body, b"a\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_zip_prefix_and_path_limits() {
    // A nested path commits through a `40000` directory tree entry, the
    // mode the index lane refuses: the limited and full archives below
    // prove that lane end to end.
    let (root, env) = seeded_two_file_repo("uarchive-zip-pre");
    std::fs::create_dir_all(root.join("sub")).expect("seed dir");
    std::fs::write(root.join("sub/b.txt"), b"b\n").expect("seed nested");
    let mut ctx = repo_ctx(&root, env);
    verbs_stage::add(&mut ctx, &["sub/b.txt".to_owned()]).expect("add nested");
    verbs_history::commit(&mut ctx, &["-m".to_owned(), "nested".to_owned()])
        .expect("commit nested");
    let zip = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=zip", "--prefix=pre/", "HEAD", "b.txt"],
    )
    .expect("zip with prefix and limit");
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip)).expect("readable zip");
    let names: Vec<String> = archive
        .file_names()
        .map(|name| name.expect("entry name").into_owned())
        .collect();
    assert!(!names.is_empty(), "path limit kept the file");
    for name in &names {
        assert!(name.starts_with("pre/"), "prefix applies: {name:?}");
        assert!(
            !name.starts_with("pre/a.txt"),
            "path limit drops a.txt: {names:?}"
        );
    }
    assert!(names.iter().any(|name| name == "pre/b.txt"), "{names:?}");
    let full = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=zip", "--prefix=pre/", "HEAD"],
    )
    .expect("full zip");
    let mut full_archive =
        zip::ZipArchive::new(std::io::Cursor::new(&full)).expect("readable full zip");
    let full_names: Vec<String> = full_archive
        .file_names()
        .map(|name| name.expect("entry name").into_owned())
        .collect();
    assert!(
        full_names.iter().any(|name| name == "pre/sub/b.txt"),
        "nested path archives: {full_names:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_zip_output_file_matches_stdout() {
    let (root, env) = seeded_repo("uarchive-zip-out", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let stdout = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=zip", "HEAD"],
    )
    .expect("stdout zip");
    assert!(stdout.starts_with(b"PK"));
    let dest = root
        .parent()
        .expect("parent")
        .join("out.zip")
        .to_str()
        .expect("utf8")
        .to_owned();
    let out = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=zip", "-o", dest.as_str(), "HEAD"],
    )
    .expect("file zip");
    assert!(out.is_empty(), "file output returns no stdout bytes");
    let filed = std::fs::read(root.parent().expect("parent").join("out.zip")).expect("written zip");
    assert_eq!(filed, stdout, "-o writes the streamed bytes");
    // Only tar and zip are spoken.
    let err = run(
        verbs_transport::archive,
        &mut ctx,
        &["--format=rar", "HEAD"],
    )
    .expect_err("unknown format must fail");
    assert!(
        matches!(err, ruk_git::GitError::Unsupported { .. }),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_refusals_pin_exit_codes() {
    // An unreachable SSH remote fails at dial time, not as a named gap:
    // the ssh/git-daemon duplex session is served.
    let (root, env) = seeded_repo("uarchive-gap", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let err = run(
        verbs_transport::archive,
        &mut ctx,
        &["--remote=ssh://127.0.0.1:1/srv/a.git", "HEAD"],
    )
    .expect_err("ssh archive must fail");
    assert!(
        !matches!(err, ruk_git::GitError::Unsupported { .. }),
        "took the gap path: {err}"
    );
    assert_eq!(err.exit_code(), 1, "{err}");
    // A NACK naming an unknown revision surfaces NotFound, not a corrupt stream.
    let body = pkt_frame(b"NACK unknown revision nope\n");
    let (base, log) = smart_http_server(vec![(body, "application/x-git-upload-archive-result")]);
    let remote = format!("--remote={base}");
    let err = run(verbs_transport::archive, &mut ctx, &[&remote, "nope"])
        .expect_err("unknown revision must fail");
    assert!(matches!(err, ruk_git::GitError::NotFound { .. }), "{err}");
    assert_eq!(err.exit_code(), 1, "{err}");
    log.recv_timeout(Duration::from_secs(30))
        .expect("server finished the RPC");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Lists tar members as (full name, typeflag, payload).
fn tar_members(tar: &[u8]) -> Vec<(Vec<u8>, u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 512 <= tar.len() {
        let header = &tar[pos..pos + 512];
        pos += 512;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let name_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let prefix_end = header[345..500]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(155);
        let mut name = header[345..345 + prefix_end].to_vec();
        if !name.is_empty() {
            name.push(b'/');
        }
        name.extend_from_slice(&header[..name_end]);
        let size_end = header[124..136]
            .iter()
            .position(|byte| *byte == 0 || *byte == b' ')
            .unwrap_or(12);
        let text = std::str::from_utf8(&header[124..124 + size_end]).unwrap_or("");
        let size = if text.trim().is_empty() {
            0
        } else {
            usize::from_str_radix(text.trim(), 8).expect("octal size")
        };
        let data = tar[pos..pos + size].to_vec();
        pos += size.div_ceil(512) * 512;
        out.push((name, header[156], data));
    }
    out
}

/// Seeds `a.txt` plus `b.txt`: nested trees are out of reach in this
/// slice (the index lane stages no directories and `mktree` refuses
/// `040000`), so directory and pax shapes are covered by synthetic-tar
/// unit tests beside the rewrap code instead.
fn seeded_two_file_repo(case: &str) -> (PathBuf, CliEnv) {
    let (root, env) = seeded_repo(case, "a.txt", b"a\n");
    std::fs::write(root.join("b.txt"), b"b\n").expect("seed");
    let mut ctx = repo_ctx(&root, env.clone());
    verbs_stage::add(&mut ctx, &["b.txt".to_owned()]).expect("add");
    verbs_history::commit(&mut ctx, &["-m".to_owned(), "two".to_owned()]).expect("commit");
    (root, env)
}

#[test]
fn archive_prefix_prepends_member_names() {
    let (root, env) = seeded_two_file_repo("uarchive-prefix");
    let mut ctx = repo_ctx(&root, env);
    let plain = run(verbs_transport::archive, &mut ctx, &["HEAD"]).expect("plain");
    let out = run(
        verbs_transport::archive,
        &mut ctx,
        &["--prefix=lead/", "HEAD"],
    )
    .expect("prefixed");
    let plain_members = tar_members(&plain);
    let members = tar_members(&out);
    assert!(
        members.iter().any(|(_, flag, _)| *flag == b'g'),
        "global header survives the rewrap"
    );
    assert_eq!(
        members.iter().filter(|(_, flag, _)| *flag == b'g').count(),
        1,
        "exactly one global header: {members:?}"
    );
    for (name, flag, _) in &members {
        if *flag == b'g' || *flag == b'x' {
            assert!(
                !name.starts_with(b"lead/"),
                "metadata header takes no prefix: {name:?}"
            );
            continue;
        }
        assert!(
            name.starts_with(b"lead/"),
            "member takes the prefix: {name:?}"
        );
    }
    let stripped: Vec<Vec<u8>> = members
        .iter()
        .filter(|(_, flag, _)| *flag != b'g' && *flag != b'x')
        .map(|(name, _, _)| name[b"lead/".len()..].to_vec())
        .collect();
    let plain_names: Vec<Vec<u8>> = plain_members
        .iter()
        .filter(|(_, flag, _)| *flag != b'g' && *flag != b'x')
        .map(|(name, _, _)| name.clone())
        .collect();
    assert_eq!(stripped, plain_names, "prefix only prepends");
    // A missing trailing slash normalizes to one.
    let bare = run(
        verbs_transport::archive,
        &mut ctx,
        &["--prefix=lead", "HEAD"],
    )
    .expect("bare prefix");
    assert_eq!(bare, out, "prefix without a slash matches");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_output_writes_file() {
    let (root, env) = seeded_repo("uarchive-output", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let dest = root.join("out.tar");
    let arg = format!("--output={}", dest.display());
    let out = run(verbs_transport::archive, &mut ctx, &[&arg, "HEAD"]).expect("output");
    assert!(out.is_empty(), "file output keeps stdout empty");
    let file = std::fs::read(&dest).expect("archive file");
    let direct = run(verbs_transport::archive, &mut ctx, &["HEAD"]).expect("direct");
    assert_eq!(file, direct, "file bytes match the stdout stream");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_paths_limit_members() {
    let (root, env) = seeded_two_file_repo("uarchive-paths");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_transport::archive, &mut ctx, &["HEAD", "b.txt"]).expect("limited");
    let names: Vec<Vec<u8>> = tar_members(&out)
        .iter()
        .filter(|(_, flag, _)| *flag != b'g' && *flag != b'x')
        .map(|(name, _, _)| name.clone())
        .collect();
    assert_eq!(names, vec![b"b.txt".to_vec()], "{names:?}");
    let file = run(verbs_transport::archive, &mut ctx, &["HEAD", "a.txt"]).expect("file");
    let file_names: Vec<Vec<u8>> = tar_members(&file)
        .iter()
        .filter(|(_, flag, _)| *flag != b'g' && *flag != b'x')
        .map(|(name, _, _)| name.clone())
        .collect();
    assert_eq!(file_names, vec![b"a.txt".to_vec()], "{file_names:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn archive_over_git_daemon_streams_tar() {
    use std::io::{Read as _, Write as _};
    let tar = b"daemon-tar-bytes".to_vec();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut prefix = [0u8; 4];
        socket.read_exact(&mut prefix).expect("length prefix");
        let len =
            usize::from_str_radix(std::str::from_utf8(&prefix).expect("hex"), 16).expect("length");
        let mut body = vec![0u8; len - 4];
        socket.read_exact(&mut body).expect("request body");
        assert!(
            body.starts_with(b"git-upload-archive /srv/a.git\0"),
            "daemon request names the archive service: {body:?}"
        );
        let mut args = Vec::new();
        loop {
            let mut head = [0u8; 4];
            socket.read_exact(&mut head).expect("frame head");
            if &head == b"0000" {
                break;
            }
            let n = usize::from_str_radix(std::str::from_utf8(&head).expect("hex"), 16)
                .expect("frame length");
            let mut frame = vec![0u8; n - 4];
            socket.read_exact(&mut frame).expect("frame body");
            args.push(frame);
        }
        assert!(
            args.iter().any(|arg| arg == b"argument HEAD\n"),
            "client sends the revision: {args:?}"
        );
        let mut reply = pkt_frame(b"ACK\n");
        reply.extend_from_slice(b"0000");
        let mut frame = format!("{:04x}", tar.len() + 5).into_bytes();
        frame.push(1);
        frame.extend_from_slice(&tar);
        reply.extend_from_slice(&frame);
        reply.extend_from_slice(b"0000");
        socket.write_all(&reply).expect("reply");
    });
    let (root, env) = seeded_repo("uarchive-daemon", "a.txt", b"a\n");
    let mut ctx = repo_ctx(&root, env);
    let remote = format!("--remote=git://127.0.0.1:{port}/srv/a.git");
    let out = run(verbs_transport::archive, &mut ctx, &[&remote, "HEAD"]).expect("daemon archive");
    assert_eq!(out, b"daemon-tar-bytes");
    server.join().expect("server");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
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

// ---------------------------------------------------------------------------
// lfs-payload-sync over the git-lfs batch API
// ---------------------------------------------------------------------------

/// Payload bytes every batch test points at: sha256 `BATCH_HEX`, 22 bytes.
const BATCH_PAYLOAD: &[u8] = b"lfs-batch-test-payload";
const BATCH_HEX: &str = "0f686d73e97c3f05112d032e21b0de1dc3c04986b04d7a41012c89413d9bded0";

/// Builds a Full-mode repo with one committed LFS pointer at `big.bin`.
fn lfs_pointer_repo(case: &str) -> (PathBuf, CliEnv) {
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
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
    let root = base.join("repo");
    std::fs::write(
        root.join(".ruk").join("policy.toml"),
        "version = 1\nlfs = \"full\"\n",
    )
    .expect("policy");
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{BATCH_HEX}\nsize {}\n",
        BATCH_PAYLOAD.len()
    );
    std::fs::write(root.join("big.bin"), pointer.as_bytes()).expect("pointer");
    let env = test_env(&base);
    let mut ctx = repo_ctx(&root, env.clone());
    verbs_stage::add(&mut ctx, &["big.bin".to_owned()]).expect("add");
    verbs_history::commit(&mut ctx, &["-m".to_owned(), "pointer".to_owned()]).expect("commit");
    (root, env)
}

/// Reads one HTTP request head plus its declared body from `socket`.
fn read_http_request(socket: &std::net::TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(socket.try_clone().expect("split"));
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).expect("request line");
        if line.is_empty() {
            panic!("client hung up mid-request");
        }
        head.extend_from_slice(&line);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let length = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().to_ascii_lowercase() == "content-length")
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader.read_exact(&mut body).expect("request body");
    }
    (text, body)
}

/// Serves a fake git-lfs endpoint on loopback: the batch POST answers one
/// object, either with a download `href` to `/dl/<oid>` (`mode == "ok"`)
/// or with a 404 error entry (`mode == "error"`); `/dl/<oid>` serves
/// [`BATCH_PAYLOAD`]. Accepts stop at a 10-second deadline, so a client
/// that never dials cannot hang the suite; returns the port plus the
/// request paths seen, in order.
fn lfs_batch_server(mode: &str) -> (u16, std::thread::JoinHandle<Vec<String>>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let mode = mode.to_owned();
    // "ok" serves one batch POST plus one payload GET; "error" serves the
    // batch POST only. The count breaks the accept loop early so the
    // error test never sits out the full deadline.
    let expected = if mode == "ok" { 2 } else { 1 };
    let server = std::thread::spawn(move || {
        let mut paths = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while paths.len() < expected && Instant::now() < deadline {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(err) => panic!("accept: {err}"),
            };
            // Accepted sockets inherit the listener's nonblocking flag on
            // Linux, which would neuter the read timeout below: force
            // blocking mode back on before any I/O.
            socket.set_nonblocking(false).expect("blocking");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let (head, body) = read_http_request(&socket);
            let path = head
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            paths.push(path.clone());
            if path.ends_with("/objects/batch") {
                assert!(head.starts_with("POST "), "batch is a POST: {head:?}");
                assert!(
                    body.windows(BATCH_HEX.len())
                        .any(|window| window == BATCH_HEX.as_bytes()),
                    "batch must request the pointer oid"
                );
                let entry = if mode == "ok" {
                    format!(
                        "{{\"oid\":\"{BATCH_HEX}\",\"size\":{},\"actions\":{{\"download\":{{\"href\":\"http://127.0.0.1:{port}/dl/{BATCH_HEX}\"}}}}}}",
                        BATCH_PAYLOAD.len()
                    )
                } else {
                    format!(
                        "{{\"oid\":\"{BATCH_HEX}\",\"size\":{},\"error\":{{\"code\":404,\"message\":\"not found\"}}}}",
                        BATCH_PAYLOAD.len()
                    )
                };
                let reply_body = format!("{{\"objects\":[{entry}]}}");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply_body}",
                    reply_body.len()
                );
                socket.write_all(reply.as_bytes()).expect("batch reply");
            } else if let Some(oid) = path.strip_prefix("/dl/") {
                assert_eq!(oid, BATCH_HEX, "payload path carries the oid");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    BATCH_PAYLOAD.len()
                );
                socket.write_all(reply.as_bytes()).expect("payload head");
                socket.write_all(BATCH_PAYLOAD).expect("payload body");
            } else {
                panic!("unexpected path {path:?}");
            }
        }
        paths
    });
    (port, server)
}

/// Serves a fake git-lfs upload endpoint on loopback: the batch POST must
/// carry `"operation":"upload"` and answers one object, either with an
/// upload `href` to `/up/<oid>` (`mode == "upload"`) or with a bare entry
/// meaning already present (`mode == "upload-present"`); `/up/<oid>`
/// accepts the PUT and keeps its body. Returns the port plus the join
/// handle for the request paths seen in order and the PUT body bytes.
fn lfs_batch_upload_server(mode: &str) -> (u16, std::thread::JoinHandle<(Vec<String>, Vec<u8>)>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let mode = mode.to_owned();
    // "upload" serves one batch POST plus one payload PUT;
    // "upload-present" serves the batch POST only.
    let expected = if mode == "upload" { 2 } else { 1 };
    let server = std::thread::spawn(move || {
        let mut paths = Vec::new();
        let mut landed = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while paths.len() < expected && Instant::now() < deadline {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(err) => panic!("accept: {err}"),
            };
            socket.set_nonblocking(false).expect("blocking");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let (head, body) = read_http_request(&socket);
            let request_line = head.lines().next().unwrap_or_default().to_owned();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            paths.push(path.clone());
            if path.ends_with("/objects/batch") {
                assert_eq!(method, "POST", "batch is a POST: {head:?}");
                let text = String::from_utf8_lossy(&body);
                assert!(
                    text.contains("\"operation\":\"upload\""),
                    "batch must offer an upload: {text:?}"
                );
                assert!(
                    body.windows(BATCH_HEX.len())
                        .any(|window| window == BATCH_HEX.as_bytes()),
                    "batch must offer the pointer oid"
                );
                let entry = if mode == "upload" {
                    format!(
                        "{{\"oid\":\"{BATCH_HEX}\",\"size\":{},\"actions\":{{\"upload\":{{\"href\":\"http://127.0.0.1:{port}/up/{BATCH_HEX}\"}}}}}}",
                        BATCH_PAYLOAD.len()
                    )
                } else {
                    format!(
                        "{{\"oid\":\"{BATCH_HEX}\",\"size\":{}}}",
                        BATCH_PAYLOAD.len()
                    )
                };
                let reply_body = format!("{{\"objects\":[{entry}]}}");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply_body}",
                    reply_body.len()
                );
                socket.write_all(reply.as_bytes()).expect("batch reply");
            } else if let Some(oid) = path.strip_prefix("/up/") {
                assert_eq!(method, "PUT", "payload send is a PUT: {head:?}");
                assert_eq!(oid, BATCH_HEX, "payload path carries the oid");
                landed = body;
                let reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                socket.write_all(reply.as_bytes()).expect("upload reply");
            } else {
                panic!("unexpected path {path:?}");
            }
        }
        (paths, landed)
    });
    (port, server)
}

#[test]
fn lfs_payload_sync_downloads_via_batch() {
    let (root, env) = lfs_pointer_repo("lfs-batch-ok");
    let (port, server) = lfs_batch_server("ok");
    let mut ctx = repo_ctx(&root, env);
    super::state::config_write(
        ctx.store().expect("store"),
        "lfs.url",
        &format!("http://127.0.0.1:{port}/repo.git/info/lfs"),
    )
    .expect("lfs.url");
    let out = run(verbs_transport::lfs_payload_sync, &mut ctx, &[]).expect("sync");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains(&format!("\"{BATCH_HEX}\"")), "got {text:?}");
    assert!(text.contains("\"missing\": []"), "got {text:?}");
    // The payload verifies under its hash and the presence row is latched.
    let store_root = ctx.store().expect("store").root().to_path_buf();
    assert!(ruk_core::store::lfs::sidecar_verified(
        &store_root,
        BATCH_HEX,
        BATCH_PAYLOAD.len() as u64
    ));
    assert!(
        ctx.store()
            .expect("store")
            .fact(FactTable::LfsObjects, BATCH_HEX.as_bytes())
            .expect("row read")
            .is_some()
    );
    let paths = server.join().expect("server");
    assert_eq!(
        paths,
        vec![
            "/repo.git/info/lfs/objects/batch".to_owned(),
            format!("/dl/{BATCH_HEX}")
        ]
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn lfs_payload_sync_reports_batch_errors_as_missing() {
    let (root, env) = lfs_pointer_repo("lfs-batch-error");
    let (port, server) = lfs_batch_server("error");
    let mut ctx = repo_ctx(&root, env);
    super::state::config_write(
        ctx.store().expect("store"),
        "lfs.url",
        &format!("http://127.0.0.1:{port}/repo.git/info/lfs"),
    )
    .expect("lfs.url");
    // An error entry is reported, never fatal: exit stays 0.
    let out = run(verbs_transport::lfs_payload_sync, &mut ctx, &[]).expect("sync");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains(&format!("\"oid\": \"{BATCH_HEX}\"")),
        "got {text:?}"
    );
    assert!(text.contains("code 404: not found"), "got {text:?}");
    assert!(text.contains("\"synced\": []"), "got {text:?}");
    let _ = server.join().expect("server");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn lfs_payload_sync_uploads_via_batch() {
    let (root, env) = lfs_pointer_repo("lfs-batch-upload");
    // The sidecar already holds the payload: upload offers it, never fetches.
    let mut ctx = repo_ctx(&root, env);
    let store_root = ctx.store().expect("store").root().to_path_buf();
    let sidecar = ruk_core::store::lfs::sidecar_path(&store_root, BATCH_HEX).expect("sidecar path");
    std::fs::create_dir_all(sidecar.parent().expect("sidecar dir")).expect("sidecar dirs");
    std::fs::write(&sidecar, BATCH_PAYLOAD).expect("seed payload");
    let (port, server) = lfs_batch_upload_server("upload");
    super::state::config_write(
        ctx.store().expect("store"),
        "lfs.url",
        &format!("http://127.0.0.1:{port}/repo.git/info/lfs"),
    )
    .expect("lfs.url");
    let out = run(verbs_transport::lfs_payload_sync, &mut ctx, &["--upload"]).expect("sync");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains(&format!("\"uploaded\": [\"{BATCH_HEX}\"]")),
        "got {text:?}"
    );
    assert!(text.contains("\"missing\": []"), "got {text:?}");
    let (paths, landed) = server.join().expect("server");
    assert_eq!(
        paths,
        vec![
            "/repo.git/info/lfs/objects/batch".to_owned(),
            format!("/up/{BATCH_HEX}")
        ]
    );
    assert_eq!(landed, BATCH_PAYLOAD);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn lfs_payload_sync_upload_skips_remote_present_objects() {
    let (root, env) = lfs_pointer_repo("lfs-batch-upload-present");
    let mut ctx = repo_ctx(&root, env);
    let store_root = ctx.store().expect("store").root().to_path_buf();
    let sidecar = ruk_core::store::lfs::sidecar_path(&store_root, BATCH_HEX).expect("sidecar path");
    std::fs::create_dir_all(sidecar.parent().expect("sidecar dir")).expect("sidecar dirs");
    std::fs::write(&sidecar, BATCH_PAYLOAD).expect("seed payload");
    let (port, server) = lfs_batch_upload_server("upload-present");
    super::state::config_write(
        ctx.store().expect("store"),
        "lfs.url",
        &format!("http://127.0.0.1:{port}/repo.git/info/lfs"),
    )
    .expect("lfs.url");
    let out = run(verbs_transport::lfs_payload_sync, &mut ctx, &["--upload"]).expect("sync");
    let text = String::from_utf8(out).expect("utf8");
    // The remote already holds the payload: nothing sent, nothing reported.
    assert!(text.contains("\"uploaded\": []"), "got {text:?}");
    assert!(text.contains("\"missing\": []"), "got {text:?}");
    let (paths, landed) = server.join().expect("server");
    assert_eq!(paths, vec!["/repo.git/info/lfs/objects/batch".to_owned()]);
    assert!(landed.is_empty());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn lfs_payload_sync_without_endpoint_reports_a_clear_error() {
    let (root, env) = lfs_pointer_repo("lfs-batch-no-endpoint");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_transport::lfs_payload_sync, &mut ctx, &[]).expect("sync");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains(&format!("\"oid\": \"{BATCH_HEX}\"")),
        "got {text:?}"
    );
    assert!(text.contains("set lfs.url"), "got {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_fixed_string_match() {
    let (root, env) = seeded_repo("grep-fixed", "a.txt", b"alpha one\nbeta two\nalpha three\n");
    let mut ctx = repo_ctx(&root, env);
    // One file searched: no filename prefix, like the oracle.
    let out = run(verbs_grep::grep, &mut ctx, &["-F", "alpha"]).expect("grep");
    assert_eq!(out, b"alpha one\nalpha three\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_name_only_lists_files() {
    let (root, env) = seeded_repo("grep-names", "a.txt", b"alpha one\n");
    std::fs::write(root.join("b.txt"), b"alpha four\n").expect("second file");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_grep::grep, &mut ctx, &["-l", "alpha"]).expect("grep -l");
    assert_eq!(out, b"a.txt\nb.txt\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_count_reports_per_file_hits() {
    let (root, env) = seeded_repo("grep-count", "a.txt", b"alpha one\nbeta two\nalpha three\n");
    std::fs::write(root.join("b.txt"), b"no hit here\n").expect("second file");
    let mut ctx = repo_ctx(&root, env);
    // Files without hits are omitted, like the oracle.
    let out = run(verbs_grep::grep, &mut ctx, &["-c", "alpha"]).expect("grep -c");
    assert_eq!(out, b"a.txt:2\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_line_numbers() {
    let (root, env) = seeded_repo("grep-lines", "a.txt", b"alpha one\nbeta two\nalpha three\n");
    std::fs::write(root.join("b.txt"), b"alpha four\n").expect("second file");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_grep::grep, &mut ctx, &["-n", "alpha"]).expect("grep -n");
    assert_eq!(
        out,
        b"a.txt:1:alpha one\na.txt:3:alpha three\nb.txt:1:alpha four\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_no_match_exits_one() {
    let (root, env) = seeded_repo("grep-empty", "a.txt", b"alpha one\n");
    let mut ctx = repo_ctx(&root, env);
    let err = run(verbs_grep::grep, &mut ctx, &["zzz-nope"]).expect_err("no match");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_tree_scope_searches_commit() {
    let (root, env) = seeded_repo("grep-tree", "a.txt", b"alpha one\nbeta two\n");
    // Untracked worktree-only content must not leak into tree scope.
    std::fs::write(root.join("worktree-only.txt"), b"alpha hidden\n").expect("untracked");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_grep::grep, &mut ctx, &["alpha", "HEAD"]).expect("grep HEAD");
    assert_eq!(out, b"HEAD:a.txt:alpha one\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_word_case_and_repeatable_patterns() {
    let (root, env) = seeded_repo("grep-opts", "a.txt", b"Foo bar\nfood fight\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_grep::grep, &mut ctx, &["-w", "Foo"]).expect("grep -w");
    assert_eq!(out, b"Foo bar\n");
    let out = run(verbs_grep::grep, &mut ctx, &["-i", "-w", "foo"]).expect("grep -iw");
    assert_eq!(out, b"Foo bar\n");
    let out = run(verbs_grep::grep, &mut ctx, &["-e", "bar", "-e", "fight"]).expect("grep -e");
    assert_eq!(out, b"Foo bar\nfood fight\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn grep_word_prefix_alternatives_both_match() {
    // Oracle check: `git grep -w -e foo -e foobar` matches both lines;
    // a shared leftmost alternation would drop "foobar x".
    let (root, env) = seeded_repo("grep-shadow", "a.txt", b"foobar x\nfoo y\nxfoobarbaz\n");
    let mut ctx = repo_ctx(&root, env);
    let out = run(
        verbs_grep::grep,
        &mut ctx,
        &["-w", "-e", "foo", "-e", "foobar"],
    )
    .expect("grep -w -e");
    assert_eq!(out, b"foobar x\nfoo y\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn worktree_add_list_remove_round_trip() {
    let (root, env) = seeded_repo("worktree-round-trip", "a.txt", b"alpha\n");
    let base = root.parent().expect("parent").to_path_buf();
    let wt_arg = base
        .join("wt-round-trip")
        .to_str()
        .expect("utf8")
        .to_owned();
    let mut ctx = repo_ctx(&root, env);
    let out = run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", wt_arg.as_str(), "--detach"],
    )
    .expect("add");
    assert!(
        String::from_utf8_lossy(&out).contains("detached HEAD"),
        "got {out:?}"
    );
    assert_eq!(
        std::fs::read(base.join("wt-round-trip").join("a.txt")).expect("read"),
        b"alpha\n"
    );
    assert!(base.join("wt-round-trip").join(".ruk").is_file());
    let out = run(verbs_worktree::worktree, &mut ctx, &["list"]).expect("list");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.contains(&wt_arg) && text.contains("(detached)"),
        "got {text:?}"
    );
    let out = run(verbs_worktree::worktree, &mut ctx, &["list", "--porcelain"]).expect("porcelain");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.contains(&format!("worktree {wt_arg}")) && text.contains("\ndetached\n"),
        "got {text:?}"
    );
    run(
        verbs_worktree::worktree,
        &mut ctx,
        &["remove", wt_arg.as_str()],
    )
    .expect("remove");
    assert!(!base.join("wt-round-trip").exists());
    let out = run(verbs_worktree::worktree, &mut ctx, &["list"]).expect("list");
    assert!(
        !String::from_utf8_lossy(&out).contains(&wt_arg),
        "got {:?}",
        String::from_utf8_lossy(&out)
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn worktree_add_refuses_checked_out_branch() {
    let (root, env) = seeded_repo("worktree-busy", "a.txt", b"alpha\n");
    let base = root.parent().expect("parent").to_path_buf();
    let wt_arg = base.join("wt-busy").to_str().expect("utf8").to_owned();
    let mut ctx = repo_ctx(&root, env);
    let err = run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", wt_arg.as_str()],
    )
    .expect_err("same branch");
    assert!(
        format!("{err}").contains("already used by worktree"),
        "{err}"
    );
    assert!(!base.join("wt-busy").exists());
    let out = run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", "-b", "feature", wt_arg.as_str()],
    )
    .expect("add -b");
    assert!(
        String::from_utf8_lossy(&out).contains("new branch 'feature'"),
        "got {out:?}"
    );
    let other = base.join("wt-busy-2").to_str().expect("utf8").to_owned();
    let err = run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", other.as_str(), "feature"],
    )
    .expect_err("branch busy");
    assert!(
        format!("{err}").contains("already used by worktree"),
        "{err}"
    );
    run(
        verbs_worktree::worktree,
        &mut ctx,
        &["remove", wt_arg.as_str()],
    )
    .expect("remove");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn worktree_remove_refuses_dirty_without_force() {
    let (root, env) = seeded_repo("worktree-dirty", "a.txt", b"alpha\n");
    let base = root.parent().expect("parent").to_path_buf();
    let wt_arg = base.join("wt-dirty").to_str().expect("utf8").to_owned();
    let mut ctx = repo_ctx(&root, env);
    run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", wt_arg.as_str(), "--detach"],
    )
    .expect("add");
    std::fs::write(base.join("wt-dirty").join("a.txt"), b"dirty\n").expect("dirty");
    let err = run(
        verbs_worktree::worktree,
        &mut ctx,
        &["remove", wt_arg.as_str()],
    )
    .expect_err("dirty");
    assert!(format!("{err}").contains("modified or untracked"), "{err}");
    assert!(base.join("wt-dirty").exists());
    run(
        verbs_worktree::worktree,
        &mut ctx,
        &["remove", "--force", wt_arg.as_str()],
    )
    .expect("force remove");
    assert!(!base.join("wt-dirty").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn worktree_prune_drops_missing_checkout() {
    let (root, env) = seeded_repo("worktree-prune", "a.txt", b"alpha\n");
    let base = root.parent().expect("parent").to_path_buf();
    let wt_arg = base.join("wt-prune").to_str().expect("utf8").to_owned();
    let mut ctx = repo_ctx(&root, env);
    run(
        verbs_worktree::worktree,
        &mut ctx,
        &["add", wt_arg.as_str(), "--detach"],
    )
    .expect("add");
    std::fs::remove_dir_all(base.join("wt-prune")).expect("drop dir");
    let out = run(verbs_worktree::worktree, &mut ctx, &["prune", "--dry-run"]).expect("dry run");
    assert!(
        String::from_utf8_lossy(&out).contains(&wt_arg),
        "got {out:?}"
    );
    let out = run(verbs_worktree::worktree, &mut ctx, &["list"]).expect("list");
    assert!(String::from_utf8_lossy(&out).contains(&wt_arg));
    let out = run(verbs_worktree::worktree, &mut ctx, &["prune"]).expect("prune");
    assert!(
        String::from_utf8_lossy(&out).contains(&wt_arg),
        "got {out:?}"
    );
    let out = run(verbs_worktree::worktree, &mut ctx, &["list"]).expect("list");
    assert!(!String::from_utf8_lossy(&out).contains(&wt_arg));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn grep_bad_invocation_exits_128() {
    let (root, env) = seeded_repo("grep-usage", "a.txt", b"alpha one\n");
    let mut ctx = repo_ctx(&root, env);
    let err = run(verbs_grep::grep, &mut ctx, &[]).expect_err("no pattern");
    assert_eq!(err.exit_code(), 128, "{err}");
    let err = run(verbs_grep::grep, &mut ctx, &["-E", "(["]).expect_err("bad regex");
    assert_eq!(err.exit_code(), 128, "{err}");
    let err = run(verbs_grep::grep, &mut ctx, &["alpha", "no-such-rev"]).expect_err("bad rev");
    assert_eq!(err.exit_code(), 128, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bundle_create_verify_unbundle_round_trip() {
    let (root, env) = seeded_repo("bundle-rt", "file.txt", b"hello bundle\n");
    let mut ctx = repo_ctx(&root, env.clone());
    let tip =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"))
            .expect("utf8")
            .trim()
            .to_owned();
    let bundle = root
        .parent()
        .expect("parent")
        .join("rt.bundle")
        .display()
        .to_string();
    let out = run(verbs_bundle::bundle, &mut ctx, &["create", &bundle, "main"]).expect("create");
    assert!(out.is_empty(), "got {out:?}");
    assert!(std::path::Path::new(&bundle).is_file(), "no bundle written");

    let heads = String::from_utf8(
        run(verbs_bundle::bundle, &mut ctx, &["list-heads", &bundle]).expect("list-heads"),
    )
    .expect("utf8");
    assert_eq!(heads, format!("{tip} refs/heads/main\n"), "got {heads:?}");

    let report = String::from_utf8(
        run(verbs_bundle::bundle, &mut ctx, &["verify", &bundle]).expect("verify"),
    )
    .expect("utf8");
    assert!(report.contains(&tip), "got {report:?}");
    assert!(report.ends_with("is okay\n"), "got {report:?}");

    // `verify` stages the pack without publishing: the census is unchanged.
    let before =
        String::from_utf8(run(verbs_objects::count_objects, &mut ctx, &[]).expect("count"))
            .expect("utf8");

    // Fresh repository ingests the bundle's objects but gains no refs.
    let base = root.parent().expect("parent").to_path_buf();
    let mut naked = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env: test_env(&base),
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    run(verbs_repo::init, &mut naked, &["repo2"]).expect("init");
    let root2 = base.join("repo2");
    let mut ctx2 = repo_ctx(&root2, test_env(&base));
    let unbundled = String::from_utf8(
        run(verbs_bundle::bundle, &mut ctx2, &["unbundle", &bundle]).expect("unbundle"),
    )
    .expect("utf8");
    assert_eq!(
        unbundled,
        format!("{tip} refs/heads/main\n"),
        "got {unbundled:?}"
    );
    let kind = String::from_utf8(
        run(verbs_objects::cat_file, &mut ctx2, &["-t", &tip]).expect("cat type"),
    )
    .expect("utf8");
    assert_eq!(kind, "commit\n", "got {kind:?}");
    let body = String::from_utf8(
        run(verbs_objects::cat_file, &mut ctx2, &["-p", &tip]).expect("cat body"),
    )
    .expect("utf8");
    assert!(body.contains("seed"), "got {body:?}");

    let after = String::from_utf8(run(verbs_objects::count_objects, &mut ctx, &[]).expect("count"))
        .expect("utf8");
    assert_eq!(before, after, "verify mutated the store");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn bundle_clone_from_file_plants_refs() {
    let (root, env) = seeded_repo("bundle-clone", "file.txt", b"clone me\n");
    let mut ctx = repo_ctx(&root, env.clone());
    let tip =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"))
            .expect("utf8")
            .trim()
            .to_owned();
    let base = root.parent().expect("parent").to_path_buf();
    let bundle = base.join("clone.bundle").display().to_string();
    run(
        verbs_bundle::bundle,
        &mut ctx,
        &["create", &bundle, "main", "HEAD"],
    )
    .expect("create");

    let mut naked = Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env: test_env(&base),
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    let out =
        String::from_utf8(run(verbs_repo::clone, &mut naked, &[&bundle, "cloned"]).expect("clone"))
            .expect("utf8");
    assert!(out.contains("Cloned into"), "got {out:?}");
    let mut cloned = repo_ctx(&base.join("cloned"), test_env(&base));
    let head = String::from_utf8(
        run(verbs_history::rev_parse, &mut cloned, &["HEAD"]).expect("rev-parse"),
    )
    .expect("utf8")
    .trim()
    .to_owned();
    assert_eq!(head, tip, "clone tip moved");
    let branch =
        String::from_utf8(run(verbs_history::rev_parse, &mut cloned, &["main"]).expect("branch"))
            .expect("utf8")
            .trim()
            .to_owned();
    assert_eq!(branch, tip, "clone branch moved");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn bundle_exclusion_records_prerequisite() {
    let (root, env) = seeded_repo("bundle-pre", "file.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env.clone());
    std::fs::write(root.join("file.txt"), b"two\n").expect("rewrite");
    run(verbs_stage::add, &mut ctx, &["file.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let base = root.parent().expect("parent").to_path_buf();
    let bundle = base.join("pre.bundle").display().to_string();
    run(
        verbs_bundle::bundle,
        &mut ctx,
        &["create", &bundle, "main", "^HEAD~1"],
    )
    .expect("create");
    let report = String::from_utf8(
        run(verbs_bundle::bundle, &mut ctx, &["verify", &bundle]).expect("verify"),
    )
    .expect("utf8");
    assert!(report.contains("prerequisites"), "got {report:?}");
    assert!(report.ends_with("is okay\n"), "got {report:?}");
    let _ = std::fs::remove_dir_all(&base);
}

// ---------------------------------------------------------------------------
// merge lane: three-way content merge, sequencer verbs
// ---------------------------------------------------------------------------

/// Writes, stages, and commits one file in a lane test.
fn lane_commit(ctx: &mut Ctx, root: &PathBuf, file: &str, body: &[u8], message: &str) {
    std::fs::write(root.join(file), body).expect("write file");
    run(verbs_stage::add, ctx, &[file]).expect("add");
    run(verbs_history::commit, ctx, &["-m", message]).expect("commit");
}

/// Counts parents of the current `HEAD` commit.
fn head_parent_count(ctx: &mut Ctx) -> usize {
    let store = ctx.store().expect("store");
    let head = super::state::head_oid(store).expect("head");
    super::state::commit_record(store, head)
        .expect("record")
        .parents()
        .len()
}

/// Stages present for one worktree-relative path in the index.
fn index_stages(ctx: &mut Ctx, file: &str) -> Vec<u8> {
    let store = ctx.store().expect("store");
    let kind = ctx.kind().expect("kind");
    super::state::scan_index(store, kind)
        .expect("scan")
        .into_iter()
        .filter(|(path, _, _)| path.as_bytes() == file.as_bytes())
        .map(|(_, stage, _)| stage.as_u8())
        .collect()
}

#[test]
fn merge_three_way_clean_makes_two_parent_commit() {
    let (root, env) = seeded_repo("lane-clean", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nb\nC\n", "feature side");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"A\nb\nc\n", "main side");
    // Created after the last checkout so only the merge lane can touch it:
    // the scoped worktree sync must preserve it.
    std::fs::write(root.join("untracked.txt"), b"keep me\n").expect("untracked");
    let out = run(verbs_history::merge, &mut ctx, &["feature"]).expect("merge");
    assert!(String::from_utf8_lossy(&out).contains("ort"), "got {out:?}");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"A\nb\nC\n"
    );
    assert_eq!(
        std::fs::read(root.join("untracked.txt")).expect("read"),
        b"keep me\n"
    );
    assert_eq!(head_parent_count(&mut ctx), 2);
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![0]);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_conflict_leaves_stages_and_merge_head() {
    let (root, env) = seeded_repo("lane-conflict", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nX\nc\n", "feature side");
    let tip =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["feature"]).expect("tip"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nY\nc\n", "main side");
    let err = run(verbs_history::merge, &mut ctx, &["feature"]).expect_err("conflict");
    assert_eq!(err.exit_code(), 1, "conflict exits 1, got {err:?}");
    assert!(err.to_string().contains("CONFLICT"), "got {err:?}");
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![1, 2, 3]);
    let store = ctx.store().expect("store");
    let merge_head = super::state::pseudo_read(store, "MERGE_HEAD")
        .expect("read")
        .expect("MERGE_HEAD");
    assert_eq!(String::from_utf8_lossy(&merge_head), tip.as_str());
    let body = std::fs::read(root.join("f.txt")).expect("read");
    let text = String::from_utf8_lossy(&body).into_owned();
    assert!(text.contains("<<<<<<< HEAD"), "got {text:?}");
    assert!(text.contains(">>>>>>> feature"), "got {text:?}");
    assert!(
        super::state::sequencer_read(store, "merge")
            .expect("read")
            .is_some()
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_continue_concludes_after_resolve() {
    let (root, env) = seeded_repo("lane-continue", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nX\nc\n", "feature side");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nY\nc\n", "main side");
    run(verbs_history::merge, &mut ctx, &["feature"]).expect_err("conflict");
    std::fs::write(root.join("f.txt"), b"a\nZ\nc\n").expect("resolve");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let out = run(verbs_history::merge, &mut ctx, &["--continue"]).expect("continue");
    assert!(!out.is_empty());
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"a\nZ\nc\n"
    );
    assert_eq!(head_parent_count(&mut ctx), 2);
    let store = ctx.store().expect("store");
    assert!(
        super::state::sequencer_read(store, "merge")
            .expect("read")
            .is_none()
    );
    assert!(
        super::state::pseudo_read(store, "MERGE_HEAD")
            .expect("read")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_abort_restores_pre_merge_state() {
    let (root, env) = seeded_repo("lane-abort", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nX\nc\n", "feature side");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nY\nc\n", "main side");
    run(verbs_history::merge, &mut ctx, &["feature"]).expect_err("conflict");
    let out = run(verbs_history::merge, &mut ctx, &["--abort"]).expect("abort");
    assert!(out.is_empty());
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"a\nY\nc\n"
    );
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![0]);
    assert_eq!(head_parent_count(&mut ctx), 1);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_no_ff_forces_merge_commit() {
    let (root, env) = seeded_repo("lane-noff", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "next.txt", b"next\n", "feature work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    run(verbs_history::merge, &mut ctx, &["--no-ff", "feature"]).expect("merge");
    assert_eq!(head_parent_count(&mut ctx), 2);
    assert!(root.join("next.txt").exists());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_rust_file_both_sides_clean() {
    // Edits land in different functions, so the syntax lane (and the text
    // fallback) must reconcile them into one clean result.
    let base = b"fn a() {\n    1\n}\nfn b() {\n    2\n}\n";
    let (root, env) = seeded_repo("lane-syntax", "main.rs", base);
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(
        &mut ctx,
        &root,
        "main.rs",
        b"fn a() {\n    10\n}\nfn b() {\n    2\n}\n",
        "feature fn",
    );
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(
        &mut ctx,
        &root,
        "main.rs",
        b"fn a() {\n    1\n}\nfn b() {\n    20\n}\n",
        "main fn",
    );
    let out = run(verbs_history::merge, &mut ctx, &["feature"]).expect("merge");
    assert!(String::from_utf8_lossy(&out).contains("ort"), "got {out:?}");
    assert_eq!(
        std::fs::read(root.join("main.rs")).expect("read"),
        b"fn a() {\n    10\n}\nfn b() {\n    20\n}\n"
    );
    assert_eq!(head_parent_count(&mut ctx), 2);
    assert_eq!(index_stages(&mut ctx, "main.rs"), vec![0]);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn cherry_pick_middle_commit_applies_content_and_message() {
    let (root, env) = seeded_repo("lane-pick", "base.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "b.txt", b"b\n", "pick B");
    lane_commit(&mut ctx, &root, "c.txt", b"c\n", "pick C");
    lane_commit(&mut ctx, &root, "d.txt", b"d\n", "pick D");
    let middle =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side~1"]).expect("middle"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    run(verbs_history::cherry_pick, &mut ctx, &[middle.as_str()]).expect("pick");
    assert_eq!(std::fs::read(root.join("c.txt")).expect("read"), b"c\n");
    assert!(!root.join("b.txt").exists());
    assert!(!root.join("d.txt").exists());
    assert_eq!(head_parent_count(&mut ctx), 1);
    let store = ctx.store().expect("store");
    let head = super::state::head_oid(store).expect("head");
    let message = String::from_utf8_lossy(
        super::state::commit_record(store, head)
            .expect("record")
            .message(),
    )
    .into_owned();
    assert_eq!(message, "pick C\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn revert_removes_picked_change() {
    let (root, env) = seeded_repo("lane-revert", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "add line");
    run(verbs_history::revert, &mut ctx, &["HEAD"]).expect("revert");
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"one\n");
    let store = ctx.store().expect("store");
    let head = super::state::head_oid(store).expect("head");
    let message = String::from_utf8_lossy(
        super::state::commit_record(store, head)
            .expect("record")
            .message(),
    )
    .into_owned();
    assert!(
        message.starts_with("Revert \"add line\""),
        "got {message:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn cherry_pick_skip_drops_stopped_pick_cleanly() {
    // P1 conflicts on a.txt but cleanly adds p1.txt; skipping P1 must drop
    // both, so the P2 commit cannot inherit the leaked p1.txt.
    let (root, env) = seeded_repo("lane-skip", "a.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    std::fs::write(root.join("a.txt"), b"side a\n").expect("write");
    std::fs::write(root.join("p1.txt"), b"p1\n").expect("write");
    run(verbs_stage::add, &mut ctx, &["a.txt", "p1.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "pick P1"]).expect("commit");
    lane_commit(&mut ctx, &root, "p2.txt", b"p2\n", "pick P2");
    let p1 = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side~1"]).expect("p1"))
        .expect("utf8")
        .trim()
        .to_owned();
    let p2 = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("p2"))
        .expect("utf8")
        .trim()
        .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "a.txt", b"main a\n", "main side");
    run(
        verbs_history::cherry_pick,
        &mut ctx,
        &[p1.as_str(), p2.as_str()],
    )
    .expect_err("conflict");
    assert_eq!(index_stages(&mut ctx, "a.txt"), vec![1, 2, 3]);
    assert_eq!(index_stages(&mut ctx, "p1.txt"), vec![0]);
    run(verbs_history::cherry_pick, &mut ctx, &["--skip"]).expect("skip");
    assert_eq!(
        std::fs::read(root.join("a.txt")).expect("read"),
        b"main a\n"
    );
    assert_eq!(std::fs::read(root.join("p2.txt")).expect("read"), b"p2\n");
    assert!(!root.join("p1.txt").exists());
    assert!(index_stages(&mut ctx, "p1.txt").is_empty());
    let count = String::from_utf8(
        run(verbs_history::rev_list, &mut ctx, &["--count", "HEAD"]).expect("count"),
    )
    .expect("utf8");
    assert_eq!(count.trim(), "3", "got {count:?}");
    let store = ctx.store().expect("store");
    assert!(
        super::state::sequencer_read(store, "cherry-pick")
            .expect("read")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn cherry_pick_continue_concludes_after_resolve() {
    let (root, env) = seeded_repo("lane-pick-continue", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nX\nc\n", "side change");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nY\nc\n", "main change");
    let oid = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("oid"))
        .expect("utf8")
        .trim()
        .to_owned();
    run(verbs_history::cherry_pick, &mut ctx, &[oid.as_str()]).expect_err("conflict");
    std::fs::write(root.join("f.txt"), b"a\nZ\nc\n").expect("resolve");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::cherry_pick, &mut ctx, &["--continue"]).expect("continue");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"a\nZ\nc\n"
    );
    let store = ctx.store().expect("store");
    let head = super::state::head_oid(store).expect("head");
    let message = String::from_utf8_lossy(
        super::state::commit_record(store, head)
            .expect("record")
            .message(),
    )
    .into_owned();
    assert_eq!(message, "side change\n");
    assert!(
        super::state::pseudo_read(store, "CHERRY_PICK_HEAD")
            .expect("read")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn cherry_pick_abort_restores_pre_pick_state() {
    let (root, env) = seeded_repo("lane-pick-abort", "f.txt", b"a\nb\nc\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nX\nc\n", "side change");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "f.txt", b"a\nY\nc\n", "main change");
    let oid = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("oid"))
        .expect("utf8")
        .trim()
        .to_owned();
    run(verbs_history::cherry_pick, &mut ctx, &[oid.as_str()]).expect_err("conflict");
    run(verbs_history::cherry_pick, &mut ctx, &["--abort"]).expect("abort");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"a\nY\nc\n"
    );
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![0]);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn rebase_conflict_abort_restores_branch() {
    let (root, env) = seeded_repo("lane-rebase-abort", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "base.txt", b"side\n", "side work");
    let orig = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("orig"))
        .expect("utf8")
        .trim()
        .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "base.txt", b"main\n", "main work");
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    run(verbs_history::rebase, &mut ctx, &["main"]).expect_err("conflict");
    run(verbs_history::rebase, &mut ctx, &["--abort"]).expect("abort");
    let tip = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("tip"))
        .expect("utf8")
        .trim()
        .to_owned();
    assert_eq!(tip, orig);
    assert_eq!(
        std::fs::read(root.join("base.txt")).expect("read"),
        b"side\n"
    );
    assert_eq!(index_stages(&mut ctx, "base.txt"), vec![0]);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn rebase_conflict_continue_replays() {
    let (root, env) = seeded_repo("lane-rebase-continue", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "base.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "other.txt", b"other\n", "main work");
    // The replayed commit touches only base.txt, which main left alone, so
    // manufacture the conflict on the main side instead.
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    lane_commit(&mut ctx, &root, "other.txt", b"side other\n", "side other");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "other.txt", b"main other\n", "main other");
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    run(verbs_history::rebase, &mut ctx, &["main"]).expect_err("conflict");
    std::fs::write(root.join("other.txt"), b"both\n").expect("resolve");
    run(verbs_stage::add, &mut ctx, &["other.txt"]).expect("add");
    let out = run(verbs_history::rebase, &mut ctx, &["--continue"]).expect("continue");
    assert!(
        String::from_utf8_lossy(&out).contains("Successfully rebased"),
        "got {out:?}"
    );
    assert_eq!(
        std::fs::read(root.join("other.txt")).expect("read"),
        b"both\n"
    );
    assert_eq!(
        std::fs::read(root.join("base.txt")).expect("read"),
        b"side\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn revert_conflict_abort_restores() {
    let (root, env) = seeded_repo("lane-revert-abort", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "add two");
    lane_commit(&mut ctx, &root, "f.txt", b"one\nTWO\n", "change two");
    let middle =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~1"]).expect("middle"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(verbs_history::revert, &mut ctx, &[middle.as_str()]).expect_err("conflict");
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![1, 2, 3]);
    run(verbs_history::revert, &mut ctx, &["--abort"]).expect("abort");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"one\nTWO\n"
    );
    assert_eq!(index_stages(&mut ctx, "f.txt"), vec![0]);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_fast_forward_keeps_untracked() {
    let (root, env) = seeded_repo("lane-ff-untracked", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "next.txt", b"next\n", "feature work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    std::fs::write(root.join("untracked.txt"), b"keep me\n").expect("untracked");
    let out = run(verbs_history::merge, &mut ctx, &["feature"]).expect("merge");
    assert!(
        String::from_utf8_lossy(&out).contains("Fast-forward"),
        "got {out:?}"
    );
    assert!(root.join("next.txt").exists());
    assert_eq!(
        std::fs::read(root.join("untracked.txt")).expect("read"),
        b"keep me\n"
    );
    assert_eq!(head_parent_count(&mut ctx), 1);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn rebase_replays_side_onto_main() {
    let (root, env) = seeded_repo("lane-rebase", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "base.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "other.txt", b"other\n", "main work");
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    let out = run(verbs_history::rebase, &mut ctx, &["main"]).expect("rebase");
    assert!(
        String::from_utf8_lossy(&out).contains("Successfully rebased"),
        "got {out:?}"
    );
    assert_eq!(
        std::fs::read(root.join("base.txt")).expect("read"),
        b"side\n"
    );
    assert_eq!(
        std::fs::read(root.join("other.txt")).expect("read"),
        b"other\n"
    );
    let count = String::from_utf8(
        run(verbs_history::rev_list, &mut ctx, &["--count", "HEAD"]).expect("count"),
    )
    .expect("utf8");
    assert_eq!(count.trim(), "3", "got {count:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Commits `body` as `file` under one author name for blame tests.
fn blame_commit(ctx: &mut Ctx, root: &PathBuf, file: &str, body: &[u8], name: &str, message: &str) {
    for role in ["AUTHOR", "COMMITTER"] {
        ctx.env
            .vars
            .insert(format!("GIT_{role}_NAME"), name.to_owned());
        ctx.env.vars.insert(
            format!("GIT_{role}_EMAIL"),
            format!("{}@example.invalid", name.to_lowercase()),
        );
    }
    std::fs::write(root.join(file), body).expect("write blamed file");
    run(verbs_stage::add, ctx, &[file]).expect("add blamed file");
    run(verbs_history::commit, ctx, &["-m", message]).expect("commit blamed file");
}

/// Starts a repository whose root commit is blame-controlled (unlike
/// [`seeded_repo`], whose seed commit would steal the boundary role).
fn blame_repo(case: &str) -> (PathBuf, CliEnv) {
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
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
    (base.join("repo"), env)
}

/// Splits one default blame line into `(id, author, lineno, content)`.
fn parse_blame_line(line: &str) -> (String, String, usize, String) {
    let (head, content) = line.split_once(") ").expect("close paren");
    let (id, rest) = head.split_once(" (").expect("open paren");
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let lineno: usize = parts
        .last()
        .expect("lineno")
        .parse()
        .expect("lineno number");
    (
        id.to_owned(),
        parts.first().expect("author").to_string(),
        lineno,
        content.to_owned(),
    )
}

/// Reads one rev's full hex through `rev-parse`.
fn blame_hex(ctx: &mut Ctx, rev: &str) -> String {
    String::from_utf8(run(verbs_history::rev_parse, ctx, &[rev]).expect("rev-parse"))
        .expect("utf8")
        .trim()
        .to_owned()
}

#[test]
fn blame_attributes_three_commit_interleaved_history() {
    let (root, env) = blame_repo("blame-interleaved");
    let mut ctx = repo_ctx(&root, env);
    // c1 introduces alpha/bravo/charlie/zulu; c2 edits bravo, deletes
    // zulu, appends delta; c3 edits alpha, appends echo. The blamed lines
    // interleave origins c3/c2/c1/c2/c3, and the deleted zulu exercises
    // the walk's parent-only slots.
    blame_commit(
        &mut ctx,
        &root,
        "poem.txt",
        b"alpha\nbravo\ncharlie\nzulu\n",
        "Ada",
        "first",
    );
    blame_commit(
        &mut ctx,
        &root,
        "poem.txt",
        b"alpha\nBRAVO\ncharlie\ndelta\n",
        "Ben",
        "second",
    );
    blame_commit(
        &mut ctx,
        &root,
        "poem.txt",
        b"ALPHA\nBRAVO\ncharlie\ndelta\necho\n",
        "Cat",
        "third",
    );
    let first = blame_hex(&mut ctx, "HEAD~2");
    let second = blame_hex(&mut ctx, "HEAD~1");
    let third = blame_hex(&mut ctx, "HEAD");

    let out = run(verbs_blame::blame, &mut ctx, &["HEAD", "--", "poem.txt"]).expect("blame");
    let text = String::from_utf8(out).expect("utf8");
    let rows: Vec<(String, String, usize, String)> = text.lines().map(parse_blame_line).collect();
    assert_eq!(rows.len(), 5, "got {text:?}");
    // (expected short id, author, lineno, content) per final line.
    let want = [
        (third.clone(), "Cat", 1, "ALPHA"),
        (second.clone(), "Ben", 2, "BRAVO"),
        (first.clone(), "Ada", 3, "charlie"),
        (second.clone(), "Ben", 4, "delta"),
        (third.clone(), "Cat", 5, "echo"),
    ];
    for (index, (oid, author, lineno, content)) in want.iter().enumerate() {
        let (id, got_author, got_lineno, got_content) = &rows[index];
        let mut expected_id: String = oid.chars().take(8).collect();
        if index == 2 {
            // The root commit's lines carry the boundary marker.
            expected_id = format!("^{expected_id}");
        }
        assert_eq!(id, &expected_id, "line {}", index + 1);
        assert_eq!(got_author, author, "line {}", index + 1);
        assert_eq!(got_lineno, lineno, "line {}", index + 1);
        assert_eq!(got_content, content, "line {}", index + 1);
    }

    // `-L` slices the same attribution with real line numbers.
    let out = run(
        verbs_blame::blame,
        &mut ctx,
        &["-L", "2,4", "HEAD", "--", "poem.txt"],
    )
    .expect("blame -L");
    let ranged: Vec<(String, String, usize, String)> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(parse_blame_line)
        .collect();
    assert_eq!(ranged.len(), 3, "got {ranged:?}");
    assert_eq!(ranged[0].2, 2);
    assert_eq!(ranged[1].2, 3);
    assert_eq!(ranged[2].2, 4);
    assert_eq!(ranged[0].0, second.chars().take(8).collect::<String>());

    // Porcelain groups carry author facts, summaries, and boundary/previous
    // markers: c1 is the root (boundary, no previous), c2/c3 name parents.
    let out = run(
        verbs_blame::blame,
        &mut ctx,
        &["-p", "HEAD", "--", "poem.txt"],
    )
    .expect("blame -p");
    let porcelain = String::from_utf8(out).expect("utf8");
    assert!(
        porcelain.contains(&format!("{third} 1 1 1\n")),
        "c3 ALPHA header: {porcelain:?}"
    );
    assert!(
        porcelain.contains(&format!("{second} 2 2 1\n")),
        "c2 BRAVO header: {porcelain:?}"
    );
    assert!(
        porcelain.contains(&format!("{first} 3 3 1\n")),
        "c1 charlie header: {porcelain:?}"
    );
    assert!(
        porcelain.contains("author Cat\nauthor-mail <cat@example.invalid>\n"),
        "c3 author facts: {porcelain:?}"
    );
    assert!(
        porcelain.contains("summary third\n"),
        "c3 summary: {porcelain:?}"
    );
    assert!(
        porcelain.contains(&format!("previous {second} poem.txt\n")),
        "c3 previous: {porcelain:?}"
    );
    assert!(
        porcelain.contains(&format!("previous {first} poem.txt\n")),
        "c2 previous: {porcelain:?}"
    );
    assert!(
        porcelain.contains("boundary\n"),
        "c1 boundary: {porcelain:?}"
    );
    assert!(
        porcelain.contains("filename poem.txt\n\tALPHA\n"),
        "content lines: {porcelain:?}"
    );
    // The root group has no `previous` line: every other group (two c3,
    // two c2) names its parent.
    assert_eq!(
        porcelain.matches("previous ").count(),
        4,
        "two c3 groups plus two c2 groups: {porcelain:?}"
    );

    // The `annotate` row reaches the same entry point.
    let annotate = lookup("annotate").expect("annotate row");
    let out = (annotate.run)(
        &mut ctx,
        &["HEAD".to_owned(), "--".to_owned(), "poem.txt".to_owned()],
    )
    .expect("annotate");
    assert_eq!(
        out,
        run(verbs_blame::blame, &mut ctx, &["HEAD", "--", "poem.txt"]).expect("blame again"),
        "annotate matches blame"
    );

    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn blame_worktree_overlay_reports_uncommitted_lines() {
    let (root, env) = blame_repo("blame-worktree");
    let mut ctx = repo_ctx(&root, env);
    blame_commit(&mut ctx, &root, "note.txt", b"one\ntwo\n", "Ada", "first");
    // Uncommitted edit plus append: no revision names the worktree file.
    std::fs::write(root.join("note.txt"), b"one\nTWO\nthree\n").expect("dirty");
    let out = run(verbs_blame::blame, &mut ctx, &["note.txt"]).expect("blame worktree");
    let text = String::from_utf8(out).expect("utf8");
    let rows: Vec<(String, String, usize, String)> = text.lines().map(parse_blame_line).collect();
    assert_eq!(rows.len(), 3, "got {text:?}");
    assert_eq!(rows[0].3, "one");
    assert_eq!(rows[0].1, "Ada");
    assert_eq!(rows[1].0, "00000000");
    assert_eq!(rows[1].1, "Not");
    assert_eq!(rows[1].3, "TWO");
    assert_eq!(rows[2].0, "00000000");
    assert_eq!(rows[2].3, "three");
    // An explicit revision ignores the worktree edits.
    let out = run(verbs_blame::blame, &mut ctx, &["HEAD", "--", "note.txt"]).expect("blame HEAD");
    let committed: Vec<(String, String, usize, String)> = String::from_utf8(out)
        .expect("utf8")
        .lines()
        .map(parse_blame_line)
        .collect();
    assert_eq!(committed.len(), 2, "explicit rev skips worktree");
    assert!(committed.iter().all(|row| row.0 != "00000000"));
    // Porcelain marks the uncommitted group with the zero oid.
    let out = run(verbs_blame::blame, &mut ctx, &["-p", "note.txt"]).expect("blame -p");
    let porcelain = String::from_utf8(out).expect("utf8");
    assert!(
        porcelain.contains("author Not Committed Yet\n"),
        "uncommitted header: {porcelain:?}"
    );
    assert!(
        porcelain.contains("\tTWO\n"),
        "uncommitted content: {porcelain:?}"
    );
    // Unknown paths fail instead of blaming nothing.
    run(verbs_blame::blame, &mut ctx, &["missing.txt"]).expect_err("unknown path");
    run(
        verbs_blame::blame,
        &mut ctx,
        &["-L", "99", "HEAD", "--", "note.txt"],
    )
    .expect_err("line range past end");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

// ---------------------------------------------------------------------------
// bisect: midpoint state machine over cli/pseudo/ session state
// ---------------------------------------------------------------------------

/// Reads `HEAD` as hex for bisect step assertions.
fn bisect_head(ctx: &mut Ctx) -> String {
    String::from_utf8(run(verbs_history::rev_parse, ctx, &["HEAD"]).expect("head"))
        .expect("utf8")
        .trim()
        .to_owned()
}

/// Commits `extra - 1` more revisions on `f.txt`, returning every `HEAD`
/// oid oldest-first (the seed commit starts the chain).
fn bisect_chain(ctx: &mut Ctx, root: &PathBuf, extra: usize) -> Vec<String> {
    let mut oids = vec![bisect_head(ctx)];
    for index in 2..=extra {
        lane_commit(
            ctx,
            root,
            "f.txt",
            format!("v{index}\n").as_bytes(),
            &format!("commit {index}"),
        );
        oids.push(bisect_head(ctx));
    }
    oids
}

#[test]
fn bisect_linear_halves_to_first_bad() {
    let (root, env) = seeded_repo("bisect-linear", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    let oids = bisect_chain(&mut ctx, &root, 8);
    assert_eq!(oids.len(), 8);
    // Commits 1..=5 are good; commit 6 (index 5) is the planted first bad.
    let planted = 5;
    let out = run(
        verbs_bisect::bisect,
        &mut ctx,
        &["start", oids[7].as_str(), oids[0].as_str()],
    )
    .expect("start");
    assert!(
        String::from_utf8_lossy(&out).contains("Bisecting"),
        "got {out:?}"
    );
    // The first checkout is the midpoint (commit 5), not a linear scan.
    assert_eq!(bisect_head(&mut ctx), oids[4]);
    let mut marks = 0;
    for _ in 0..10 {
        let head = bisect_head(&mut ctx);
        let index = oids
            .iter()
            .position(|oid| *oid == head)
            .expect("checked-out commit is known");
        let out = if index < planted {
            run(verbs_bisect::bisect, &mut ctx, &["good"]).expect("good")
        } else {
            run(verbs_bisect::bisect, &mut ctx, &["bad"]).expect("bad")
        };
        marks += 1;
        let text = String::from_utf8_lossy(&out).into_owned();
        if text.contains("first bad commit") {
            assert!(text.contains(&oids[planted]), "got {text:?}");
            break;
        }
    }
    assert_eq!(bisect_head(&mut ctx), oids[planted]);
    assert!(marks <= 4, "bisection took {marks} marks");
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    assert_eq!(bisect_head(&mut ctx), oids[7]);
    run(verbs_bisect::bisect, &mut ctx, &["log"]).expect_err("session is gone");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bisect_start_without_revs_waits_then_resets() {
    let (root, env) = seeded_repo("bisect-wait", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second");
    let tip = bisect_head(&mut ctx);
    let out = run(verbs_bisect::bisect, &mut ctx, &["start"]).expect("start");
    assert!(
        String::from_utf8_lossy(&out).contains("waiting"),
        "got {out:?}"
    );
    let empty: &[&str] = &[];
    let status = run(verbs_bisect::bisect, &mut ctx, empty).expect("status");
    assert!(
        String::from_utf8_lossy(&status).contains("waiting"),
        "got {status:?}"
    );
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    assert_eq!(bisect_head(&mut ctx), tip);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bisect_contradictory_marks_rejected() {
    let (root, env) = seeded_repo("bisect-clash", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second");
    let tip = bisect_head(&mut ctx);
    let first =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~1"]).expect("first"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(
        verbs_bisect::bisect,
        &mut ctx,
        &["start", tip.as_str(), first.as_str()],
    )
    .expect("start");
    // The good root cannot go bad: it is an ancestor of itself as good.
    run(verbs_bisect::bisect, &mut ctx, &["bad", first.as_str()]).expect_err("clash");
    // The bad tip cannot go good: the range would empty.
    run(verbs_bisect::bisect, &mut ctx, &["good", tip.as_str()]).expect_err("empty");
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bisect_terms_aliases_and_log() {
    let (root, env) = seeded_repo("bisect-terms", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second");
    lane_commit(&mut ctx, &root, "f.txt", b"v3\n", "third");
    let tip = bisect_head(&mut ctx);
    let first =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~2"]).expect("first"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(
        verbs_bisect::bisect,
        &mut ctx,
        &[
            "start",
            "--term-bad",
            "old",
            "--term-new",
            "new",
            tip.as_str(),
            first.as_str(),
        ],
    )
    .expect("start");
    let shown = run(verbs_bisect::bisect, &mut ctx, &["terms"]).expect("terms");
    assert!(
        String::from_utf8_lossy(&shown).contains("new and old"),
        "got {shown:?}"
    );
    let marked = run(verbs_bisect::bisect, &mut ctx, &["new"]).expect("alias good");
    let marked_text = String::from_utf8_lossy(&marked);
    assert!(
        marked_text.contains("Bisecting") || marked_text.contains("first bad commit"),
        "got {marked:?}"
    );
    let log = run(verbs_bisect::bisect, &mut ctx, &["log"]).expect("log");
    let text = String::from_utf8_lossy(&log).into_owned();
    assert!(text.contains("git bisect start"), "got {text:?}");
    assert!(text.contains("# bad:"), "got {text:?}");
    assert!(text.contains("# good:"), "got {text:?}");
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bisect_first_parent_ignores_side_branch() {
    let (root, env) = seeded_repo("bisect-fp", "base.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    let first = bisect_head(&mut ctx);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "side.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "main.txt", b"main\n", "main work");
    let second = bisect_head(&mut ctx);
    run(verbs_history::merge, &mut ctx, &["side"]).expect("merge");
    let tip = bisect_head(&mut ctx);
    let out = run(
        verbs_bisect::bisect,
        &mut ctx,
        &["start", "--first-parent", tip.as_str(), first.as_str()],
    )
    .expect("start");
    assert!(
        String::from_utf8_lossy(&out).contains("Bisecting"),
        "got {out:?}"
    );
    // First-parent order walks the merge tip then the main line only.
    assert_eq!(bisect_head(&mut ctx), second);
    let verdict = run(verbs_bisect::bisect, &mut ctx, &["bad"]).expect("bad");
    let text = String::from_utf8_lossy(&verdict).into_owned();
    assert!(text.contains("first bad commit"), "got {text:?}");
    assert!(text.contains(&second), "got {text:?}");
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn bisect_run_finds_first_bad() {
    let (root, env) = seeded_repo("bisect-run", "f.txt", b"GOOD\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"GOOD\n", "still good");
    lane_commit(&mut ctx, &root, "f.txt", b"BAD\n", "turns bad");
    let planted = bisect_head(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"BAD\n", "still bad");
    let tip = bisect_head(&mut ctx);
    let first =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~3"]).expect("first"))
            .expect("utf8")
            .trim()
            .to_owned();
    run(
        verbs_bisect::bisect,
        &mut ctx,
        &["start", tip.as_str(), first.as_str()],
    )
    .expect("start");
    let out = run(
        verbs_bisect::bisect,
        &mut ctx,
        &["run", "sh", "-c", "grep -q GOOD f.txt"],
    )
    .expect("run");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("first bad commit"), "got {text:?}");
    assert!(text.contains(&planted), "got {text:?}");
    assert_eq!(bisect_head(&mut ctx), planted);
    run(verbs_bisect::bisect, &mut ctx, &["reset"]).expect("reset");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

// ---------------------------------------------------------------------------
// email-patch lane: format-patch, apply, am
// ---------------------------------------------------------------------------

#[test]
fn patch_round_trip_format_patch_am() {
    let (root, env) = seeded_repo("patch-roundtrip", "f.txt", b"one\ntwo\nthree\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "gone.txt", b"bye\n", "add gone");
    std::fs::write(root.join("f.txt"), b"one\nTWO\nthree\n").expect("write f");
    std::fs::write(root.join("new.txt"), b"fresh\n").expect("write new");
    run(verbs_stage::add, &mut ctx, &["f.txt", "new.txt"]).expect("add");
    run(verbs_stage::rm, &mut ctx, &["gone.txt"]).expect("rm");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "swap gone for new"],
    )
    .expect("commit");
    let tip = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("tip"))
        .expect("utf8")
        .trim()
        .to_owned();
    let dates_before = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--format=%ad", "-n", "2"]).expect("dates before"),
    )
    .expect("utf8");
    let mbox = run(verbs_patch::format_patch, &mut ctx, &["HEAD~2..HEAD"]).expect("format-patch");
    let text = String::from_utf8(mbox.clone()).expect("utf8");
    assert!(
        text.contains("Subject: [PATCH 1/2] add gone"),
        "got {text:?}"
    );
    assert!(
        text.contains("Subject: [PATCH 2/2] swap gone for new"),
        "got {text:?}"
    );
    // `-o` writes one file per patch outside the repository.
    let out_dir = root.parent().expect("parent").join("patch-out");
    let out_flag = format!("--output-directory={}", out_dir.display());
    run(
        verbs_patch::format_patch,
        &mut ctx,
        &["HEAD~2..HEAD", out_flag.as_str()],
    )
    .expect("format-patch -o");
    assert_eq!(
        std::fs::read_dir(&out_dir).expect("read dir").count(),
        2,
        "got {:?}",
        std::fs::read_dir(&out_dir).expect("readdir")
    );
    // Rewind to the base and replay the mbox onto it.
    run(verbs_branch::reset, &mut ctx, &["--hard", "HEAD~2"]).expect("reset");
    assert!(!root.join("new.txt").exists());
    ctx.env.stdin = Some(mbox);
    let applied = run(verbs_patch::am, &mut ctx, &[]).expect("am");
    let applied_text = String::from_utf8(applied).expect("utf8");
    assert!(
        applied_text.contains("Applying: add gone"),
        "got {applied_text:?}"
    );
    assert!(
        applied_text.contains("Applying: swap gone for new"),
        "got {applied_text:?}"
    );
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"one\nTWO\nthree\n"
    );
    assert_eq!(
        std::fs::read(root.join("new.txt")).expect("read"),
        b"fresh\n"
    );
    assert!(!root.join("gone.txt").exists());
    let log = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--oneline", "-n", "2"]).expect("log"),
    )
    .expect("utf8");
    assert!(
        log.contains("swap gone for new") && log.contains("add gone"),
        "got {log:?}"
    );
    // Authors (name, email, and date) survive the mbox round-trip.
    let authors = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--format=%an <%ae>", "-n", "2"]).expect("authors"),
    )
    .expect("utf8");
    assert_eq!(authors.lines().count(), 2);
    assert!(
        authors
            .lines()
            .all(|line| line == "Ada <ada@example.invalid>"),
        "got {authors:?}"
    );
    let dates = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--format=%ad", "-n", "2"]).expect("dates"),
    )
    .expect("utf8");
    assert_eq!(dates, dates_before);
    // The replayed history resolves to the original tip tree.
    let diff = run(verbs_history::diff, &mut ctx, &[tip.as_str()]).expect("diff");
    assert!(diff.is_empty(), "round-trip tree differs: {diff:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn apply_check_stat_reverse_index() {
    let (root, env) = seeded_repo(
        "patch-apply",
        "f.txt",
        b"line1\nline2\nline3\nline4\nline5\nline6\n",
    );
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("old.txt"), b"bye\n").expect("write old");
    run(verbs_stage::add, &mut ctx, &["old.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "add old"]).expect("commit");
    // The first hunk claims offset 5 for content living at lines 4-6, so
    // only the offset search can place it.
    let patch = b"diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -5,3 +5,3 @@\n line4\n-line5\n+LINE5\n line6\ndiff --git a/created.txt b/created.txt\nnew file mode 100644\n--- /dev/null\n+++ b/created.txt\n@@ -0,0 +1,2 @@\n+hello\n+world\ndiff --git a/old.txt b/old.txt\ndeleted file mode 100644\n--- a/old.txt\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-bye\n";
    ctx.env.stdin = Some(patch.to_vec());
    run(verbs_patch::apply, &mut ctx, &["--check"]).expect("check");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"line1\nline2\nline3\nline4\nline5\nline6\n"
    );
    assert!(!root.join("created.txt").exists());
    let stat = String::from_utf8(run(verbs_patch::apply, &mut ctx, &["--stat"]).expect("stat"))
        .expect("utf8");
    assert!(
        stat.contains("f.txt") && stat.contains("created.txt") && stat.contains("old.txt"),
        "got {stat:?}"
    );
    let numstat =
        String::from_utf8(run(verbs_patch::apply, &mut ctx, &["--numstat"]).expect("numstat"))
            .expect("utf8");
    assert!(numstat.contains("1\t1\tf.txt"), "got {numstat:?}");
    run(verbs_patch::apply, &mut ctx, &[]).expect("apply");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"line1\nline2\nline3\nline4\nLINE5\nline6\n"
    );
    assert_eq!(
        std::fs::read(root.join("created.txt")).expect("read"),
        b"hello\nworld\n"
    );
    assert!(!root.join("old.txt").exists());
    // A worktree-only apply leaves the index on the old blobs.
    assert!(index_stages(&mut ctx, "created.txt").is_empty());
    let rows = super::state::scan_index(ctx.store().expect("store"), ctx.kind().expect("kind"))
        .expect("scan");
    let (_, _, entry) = rows
        .iter()
        .find(|(path, stage, _)| path.as_bytes() == b"f.txt" && stage.as_u8() == 0)
        .expect("index f");
    let (_, body) =
        super::tree::read_object_bytes(ctx.store().expect("store"), entry.oid()).expect("blob");
    assert_eq!(body, b"line1\nline2\nline3\nline4\nline5\nline6\n");
    run(verbs_patch::apply, &mut ctx, &["--reverse"]).expect("reverse");
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"line1\nline2\nline3\nline4\nline5\nline6\n"
    );
    assert!(!root.join("created.txt").exists());
    assert_eq!(std::fs::read(root.join("old.txt")).expect("read"), b"bye\n");
    run(verbs_patch::apply, &mut ctx, &["--index"]).expect("index");
    assert_eq!(
        std::fs::read(root.join("created.txt")).expect("read"),
        b"hello\nworld\n"
    );
    assert!(!index_stages(&mut ctx, "created.txt").is_empty());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn am_abort_restores_session() {
    let (root, env) = seeded_repo("patch-am-abort", "f.txt", b"one\ntwo\nthree\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\nTWO\nthree\n", "change two");
    let mbox = run(verbs_patch::format_patch, &mut ctx, &["HEAD~1..HEAD"]).expect("format-patch");
    run(verbs_branch::reset, &mut ctx, &["--hard", "HEAD~1"]).expect("reset");
    let base = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("base"))
        .expect("utf8")
        .trim()
        .to_owned();
    // Corrupt one context line so the hunk no longer matches anything.
    let bad_text = String::from_utf8(mbox.clone())
        .expect("utf8")
        .replace(" one\n", " oneX\n");
    ctx.env.stdin = Some(bad_text.into_bytes());
    let err = run(verbs_patch::am, &mut ctx, &[]).expect_err("am fails");
    assert!(err.to_string().contains("am --abort"), "got {err:?}");
    // The failure leaves HEAD, the worktree, and the session behind.
    let head = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("head"))
        .expect("utf8")
        .trim()
        .to_owned();
    assert_eq!(head, base);
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"one\ntwo\nthree\n"
    );
    assert!(
        super::state::pseudo_read(ctx.store().expect("store"), "AM_STATE")
            .expect("state")
            .is_some()
    );
    run(verbs_patch::am, &mut ctx, &["--abort"]).expect("abort");
    let head = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("head"))
        .expect("utf8")
        .trim()
        .to_owned();
    assert_eq!(head, base);
    assert!(
        super::state::pseudo_read(ctx.store().expect("store"), "AM_STATE")
            .expect("state")
            .is_none()
    );
    // The good mbox still applies after the abort.
    ctx.env.stdin = Some(mbox);
    let out = run(verbs_patch::am, &mut ctx, &[]).expect("am");
    assert!(
        String::from_utf8(out)
            .expect("utf8")
            .contains("Applying: change two")
    );
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"one\nTWO\nthree\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
