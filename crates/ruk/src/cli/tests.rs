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
use super::verbs_fastio;
use super::verbs_grep;
use super::verbs_history;
use super::verbs_hooks;
use super::verbs_misc;
use super::verbs_maintenance;
use super::verbs_merge_plumbing;
use super::verbs_notes;
use super::verbs_objects;
use super::verbs_patch;
use super::verbs_repo;
use super::verbs_sparse;
use super::verbs_stage;
use super::verbs_submodule;
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
    assert_eq!(VERBS.len(), 128);
    let mut names: Vec<&str> = VERBS.iter().map(|verb| verb.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 128);
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
        "bugreport",
        "cat-file",
        "check-attr",
        "check-ignore",
        "check-mailmap",
        "check-ref-format",
        "checkout",
        "checkout-index",
        "cherry",
        "cherry-pick",
        "clean",
        "clone",
        "commit",
        "commit-graph",
        "commit-tree",
        "config",
        "count-objects",
        "credential",
        "describe",
        "diagnose",
        "diff",
        "difftool",
        "fast-export",
        "fast-import",
        "fetch",
        "filter-branch",
        "fmt-merge-msg",
        "for-each-ref",
        "for-each-repo",
        "format-patch",
        "fsck",
        "gc",
        "get-tar-commit-id",
        "grep",
        "hash-object",
        "help",
        "index-pack",
        "imap-send",
        "init",
        "instaweb",
        "interpret-trailers",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "last-modified",
        "maintenance",
        "merge",
        "merge-base",
        "merge-file",
        "merge-tree",
        "mergetool",
        "migrate",
        "mktag",
        "mktree",
        "mv",
        "name-rev",
        "notes",
        "pack-objects",
        "pack-redundant",
        "pack-refs",
        "prune",
        "pull",
        "push",
        "quiltimport",
        "range-diff",
        "rebase",
        "receive-pack",
        "read-tree",
        "reflog",
        "remote",
        "remote-ext",
        "remote-fd",
        "remote-ftp",
        "remote-ftps",
        "remote-helper",
        "remote-http",
        "remote-https",
        "repack",
        "replace",
        "request-pull",
        "rerere",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "revert",
        "rm",
        "send-email",
        "send-pack",
        "show",
        "show-index",
        "shortlog",
        "show-ref",
        "sparse-checkout",
        "stage",
        "stash",
        "status",
        "stripspace",
        "submodule",
        "switch",
        "symbolic-ref",
        "tag",
        "unpack-file",
        "unpack-objects",
        "update-index",
        "update-ref",
        "update-server-info",
        "upload-archive",
        "upload-pack",
        "var",
        "verify-commit",
        "verify-pack",
        "verify-tag",
        "version",
        "web--browse",
        "whatchanged",
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
    lane_commit(&mut ctx, &root, "f.txt", b"GOOD still\n", "still good");
    lane_commit(&mut ctx, &root, "f.txt", b"BAD\n", "turns bad");
    let planted = bisect_head(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"BAD still\n", "still bad");
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
        run(
            verbs_history::log,
            &mut ctx,
            &["--format=%an <%ae>", "-n", "2"],
        )
        .expect("authors"),
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

// ---------------------------------------------------------------------------
// submodule lane: gitlink bindings, child checkouts
// ---------------------------------------------------------------------------

/// Builds a parent repo with one submodule added at `vendor/lib`.
///
/// Returns the parent root, its env, the child root, and the child `HEAD`.
fn submodule_case(case: &str) -> (PathBuf, CliEnv, PathBuf, String) {
    let (child_root, _) = seeded_repo(case, "lib.txt", b"lib v1\n");
    let child_head = {
        let env = test_env(&child_root);
        let mut ctx = repo_ctx(&child_root, env);
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("head"))
            .expect("utf8")
            .trim()
            .to_owned()
    };
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
    verbs_repo::init(&mut ctx, &["parent".to_owned()]).expect("init");
    let root = base.join("parent");
    let env = test_env(&root);
    let mut ctx = repo_ctx(&root, env.clone());
    let url = child_root.to_string_lossy().into_owned();
    run(
        verbs_submodule::submodule,
        &mut ctx,
        &["add", &url, "vendor/lib"],
    )
    .expect("add");
    (root, env, child_root, child_head)
}

#[test]
fn submodule_add_records_gitlink_and_modules() {
    let (root, env, child_root, child_head) = submodule_case("submodule-add");
    let ctx = repo_ctx(&root, env);
    let store = ctx.store().expect("store");
    let kind = ctx.kind().expect("kind");
    let link = super::state::scan_index(store, kind)
        .expect("scan")
        .into_iter()
        .find(|(path, stage, _)| path.as_bytes() == b"vendor/lib" && stage.as_u8() == 0)
        .expect("gitlink row");
    assert_eq!(link.2.mode(), ruk_core::index::FileMode::Gitlink);
    assert_eq!(link.2.oid().to_hex(), child_head);
    let text = String::from_utf8(std::fs::read(root.join(".rukmodules")).expect("modules file"))
        .expect("utf8");
    assert!(text.contains("vendor/lib"), "got {text:?}");
    assert!(
        text.contains(&child_root.to_string_lossy().into_owned()),
        "got {text:?}"
    );
    assert_eq!(
        std::fs::read(root.join("vendor/lib/lib.txt")).expect("read"),
        b"lib v1\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(child_root.parent().expect("parent"));
}

#[test]
fn submodule_update_init_materializes_checkout() {
    let (root, env, child_root, child_head) = submodule_case("submodule-update");
    let mut ctx = repo_ctx(&root, env);
    run(
        verbs_submodule::submodule,
        &mut ctx,
        &["deinit", "vendor/lib"],
    )
    .expect("deinit");
    assert!(!root.join("vendor/lib").exists());
    let out = run(verbs_submodule::submodule, &mut ctx, &["status"]).expect("status");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.starts_with('-') && text.contains("vendor/lib"),
        "got {text:?}"
    );
    let out = run(verbs_submodule::submodule, &mut ctx, &["update", "--init"]).expect("update");
    assert!(
        String::from_utf8(out)
            .expect("utf8")
            .contains("checked out"),
        "update reports the checkout"
    );
    assert_eq!(
        std::fs::read(root.join("vendor/lib/lib.txt")).expect("read"),
        b"lib v1\n"
    );
    let child_root_path = root.join("vendor/lib");
    let child_env = test_env(&child_root_path);
    let child_ctx = repo_ctx(&child_root_path, child_env);
    let checked_out = super::state::head_oid(child_ctx.store().expect("store")).expect("head");
    assert_eq!(checked_out.to_hex(), child_head);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(child_root.parent().expect("parent"));
}

#[test]
fn submodule_status_summary_foreach_and_gap() {
    let (root, env, child_root, child_head) = submodule_case("submodule-misc");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_submodule::submodule, &mut ctx, &["status"]).expect("status");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains(&child_head), "got {text:?}");
    assert!(text.contains("vendor/lib (main)"), "got {text:?}");
    let out = run(
        verbs_submodule::submodule,
        &mut ctx,
        &["foreach", "echo", "hello-$name"],
    )
    .expect("foreach");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("Entering 'vendor/lib'"), "got {text:?}");
    assert!(text.contains("hello-vendor/lib"), "got {text:?}");
    // Uncommitted binding: summary reports the addition; after the parent
    // commit the lane is quiet.
    let out = run(verbs_submodule::submodule, &mut ctx, &["summary"]).expect("summary");
    assert!(
        String::from_utf8(out).expect("utf8").contains("vendor/lib"),
        "summary reports the uncommitted binding"
    );
    run(verbs_history::commit, &mut ctx, &["-m", "add lib"]).expect("commit");
    let out = run(verbs_submodule::submodule, &mut ctx, &["summary"]).expect("summary");
    assert!(out.is_empty(), "in sync: {}", String::from_utf8_lossy(&out));
    let err = run(verbs_submodule::submodule, &mut ctx, &["absorbgitdirs"]).expect_err("gap");
    assert!(err.to_string().contains("absorbgitdirs"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(child_root.parent().expect("parent"));
}

#[test]
fn submodule_deinit_refuses_dirty_without_force() {
    let (root, env, child_root, _) = submodule_case("submodule-deinit");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("vendor/lib/lib.txt"), b"dirty\n").expect("dirty file");
    let err = run(
        verbs_submodule::submodule,
        &mut ctx,
        &["deinit", "vendor/lib"],
    )
    .expect_err("refuses");
    assert!(err.to_string().contains("--force"), "got {err:?}");
    assert!(root.join("vendor/lib/lib.txt").exists());
    run(
        verbs_submodule::submodule,
        &mut ctx,
        &["deinit", "--force", "vendor/lib"],
    )
    .expect("force");
    assert!(!root.join("vendor/lib").exists());
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(child_root.parent().expect("parent"));
}

// ---------------------------------------------------------------------------
// sparse + merge-plumbing lane: sparse-checkout, merge-file, merge-tree,
// read-tree, checkout-index, rerere
// ---------------------------------------------------------------------------

/// Seeds a repo with several committed files.
fn plumbing_repo(case: &str, files: &[(&str, &[u8])]) -> (PathBuf, CliEnv) {
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
    for (name, body) in files {
        let full = root.join(name);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("dirs");
        }
        std::fs::write(&full, body).expect("seed file");
    }
    let env = test_env(&base);
    let mut ctx = repo_ctx(&root, env.clone());
    run(verbs_stage::add, &mut ctx, &["-A"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "seed"]).expect("commit");
    (root, env)
}

/// Resolves `HEAD` to its hex.
fn plumbing_head(ctx: &mut Ctx) -> String {
    String::from_utf8(run(verbs_history::rev_parse, ctx, &["HEAD"]).expect("head"))
        .expect("utf8")
        .trim()
        .to_owned()
}

/// Builds a file-only context for repository-optional verbs.
fn file_ctx(base: &PathBuf, env: CliEnv) -> Ctx {
    Ctx {
        store: None,
        root: base.clone(),
        file_base: base.clone(),
        kind: None,
        env,
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    }
}

#[test]
fn merge_file_clean_writes_current() {
    let base = temp_base("merge-file-clean");
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    std::fs::write(base.join("base.txt"), b"a\nbase\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\nbase\nc\n").expect("write");
    let mut ctx = file_ctx(&base, test_env(&base));
    let out = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["current.txt", "base.txt", "other.txt"],
    )
    .expect("merge");
    assert!(out.is_empty());
    assert_eq!(
        std::fs::read(base.join("current.txt")).expect("read"),
        b"a\nours\nc\n"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn merge_file_conflict_markers_stdout_and_resolve() {
    let base = temp_base("merge-file-conflict");
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    std::fs::write(base.join("base.txt"), b"a\nbase\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\ntheirs\nc\n").expect("write");
    let mut ctx = file_ctx(&base, test_env(&base));
    let err = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["current.txt", "base.txt", "other.txt"],
    )
    .expect_err("conflict");
    assert!(err.to_string().contains("conflicts"), "got {err:?}");
    let body = std::fs::read(base.join("current.txt")).expect("read");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("<<<<<<< current.txt"), "got {text:?}");
    assert!(text.contains(">>>>>>> other.txt"), "got {text:?}");
    // `-p` keeps the bytes in the error detail with status 1; the file is
    // rewritten by the earlier in-place run, so restore inputs first.
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    let err = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["-p", "current.txt", "base.txt", "other.txt"],
    )
    .expect_err("stdout conflict");
    assert!(
        err.to_string().contains("<<<<<<< current.txt"),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(base.join("current.txt")).expect("read"),
        b"a\nours\nc\n"
    );
    // `--ours` resolves without markers.
    run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["--ours", "current.txt", "base.txt", "other.txt"],
    )
    .expect("ours");
    assert_eq!(
        std::fs::read(base.join("current.txt")).expect("read"),
        b"a\nours\nc\n"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn merge_file_union_and_diff3_labels() {
    let base = temp_base("merge-file-union");
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    std::fs::write(base.join("base.txt"), b"a\nbase\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\ntheirs\nc\n").expect("write");
    let mut ctx = file_ctx(&base, test_env(&base));
    run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &[
            "--union",
            "-L",
            "mine",
            "current.txt",
            "base.txt",
            "other.txt",
        ],
    )
    .expect("union");
    let body = std::fs::read(base.join("current.txt")).expect("read");
    assert_eq!(body, b"a\nours\ntheirs\nc\n");
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    let err = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["--diff3", "current.txt", "base.txt", "other.txt"],
    )
    .expect_err("diff3 conflict");
    let detail = err.to_string();
    assert!(detail.contains("||||||| base.txt"), "got {detail:?}");
    let err = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["--marker-size=9", "current.txt", "base.txt", "other.txt"],
    )
    .expect_err("marker size");
    assert!(err.to_string().contains("<<<<<<<<<"), "got {err:?}");
    assert!(err.to_string().contains("=========\n"), "got {err:?}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn merge_file_union_preserves_repeated_lines() {
    // Union concatenates both sides verbatim: lines shared across the
    // sides (Y) and repeated within one side (W, W) are all kept.
    let base = temp_base("merge-file-union-dups");
    std::fs::write(base.join("current.txt"), b"a\nX\nY\nc\n").expect("write");
    std::fs::write(base.join("base.txt"), b"a\nb\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\nY\nZ\nc\n").expect("write");
    let mut ctx = file_ctx(&base, test_env(&base));
    run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["--union", "current.txt", "base.txt", "other.txt"],
    )
    .expect("union");
    assert_eq!(
        std::fs::read(base.join("current.txt")).expect("read"),
        b"a\nX\nY\nY\nZ\nc\n"
    );
    // Repeated lines within one side survive as well.
    std::fs::write(base.join("current.txt"), b"a\nQ\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\nW\nW\nc\n").expect("write");
    run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &["--union", "current.txt", "base.txt", "other.txt"],
    )
    .expect("union");
    assert_eq!(
        std::fs::read(base.join("current.txt")).expect("read"),
        b"a\nQ\nW\nW\nc\n"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn merge_file_custom_labels_in_markers() {
    // `-L` labels replace the file names on every marker line.
    let base = temp_base("merge-file-labels");
    std::fs::write(base.join("current.txt"), b"a\nours\nc\n").expect("write");
    std::fs::write(base.join("base.txt"), b"a\nbase\nc\n").expect("write");
    std::fs::write(base.join("other.txt"), b"a\ntheirs\nc\n").expect("write");
    let mut ctx = file_ctx(&base, test_env(&base));
    let err = run(
        verbs_merge_plumbing::merge_file_cmd,
        &mut ctx,
        &[
            "--diff3",
            "-L",
            "mine",
            "-L",
            "ancestor",
            "-L",
            "theirs-side",
            "current.txt",
            "base.txt",
            "other.txt",
        ],
    )
    .expect_err("labeled conflict");
    let detail = err.to_string();
    assert!(detail.contains("<<<<<<< mine\n"), "got {detail:?}");
    assert!(detail.contains("||||||| ancestor\n"), "got {detail:?}");
    assert!(detail.contains(">>>>>>> theirs-side\n"), "got {detail:?}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn merge_tree_merges_disjoint_sides() {
    let (root, env) = plumbing_repo("merge-tree-clean", &[("f.txt", b"base\n")]);
    let mut ctx = repo_ctx(&root, env);
    let base = plumbing_head(&mut ctx);
    std::fs::write(root.join("f.txt"), b"ours\n").expect("ours");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "ours side"]).expect("commit");
    let ours = plumbing_head(&mut ctx);
    run(verbs_branch::reset, &mut ctx, &["--hard", &base]).expect("reset");
    std::fs::write(root.join("g.txt"), b"theirs\n").expect("theirs");
    run(verbs_stage::add, &mut ctx, &["g.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "theirs side"]).expect("commit");
    let theirs = plumbing_head(&mut ctx);
    let out = run(
        verbs_merge_plumbing::merge_tree,
        &mut ctx,
        &[base.as_str(), ours.as_str(), theirs.as_str()],
    )
    .expect("merge-tree");
    let text = String::from_utf8(out).expect("utf8");
    assert!(!text.contains("CONFLICT"), "got {text:?}");
    let tree = text.lines().next().expect("tree").trim().to_owned();
    assert!(tree.chars().all(|cell| cell.is_ascii_hexdigit()));
    let body = run(verbs_objects::cat_file, &mut ctx, &["-p", &tree]).expect("cat tree");
    let raw = String::from_utf8_lossy(&body);
    assert!(raw.contains("f.txt"), "got {raw:?}");
    assert!(raw.contains("g.txt"), "got {raw:?}");
    // The index and worktree still hold the theirs tip untouched.
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"base\n");
    assert_eq!(
        std::fs::read(root.join("g.txt")).expect("read"),
        b"theirs\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn merge_tree_reports_content_conflicts() {
    let (root, env) = plumbing_repo("merge-tree-conflict", &[("f.txt", b"one\ntwo\n")]);
    let mut ctx = repo_ctx(&root, env);
    let base = plumbing_head(&mut ctx);
    std::fs::write(root.join("f.txt"), b"one\ntwo B\n").expect("ours");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "ours side"]).expect("commit");
    let ours = plumbing_head(&mut ctx);
    run(verbs_branch::reset, &mut ctx, &["--hard", &base]).expect("reset");
    std::fs::write(root.join("f.txt"), b"one\ntwo C\n").expect("theirs");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "theirs side"]).expect("commit");
    let theirs = plumbing_head(&mut ctx);
    let out = run(
        verbs_merge_plumbing::merge_tree,
        &mut ctx,
        &[base.as_str(), ours.as_str(), theirs.as_str()],
    )
    .expect("merge-tree");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains("CONFLICT (content): Merge conflict in f.txt"),
        "got {text:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn read_tree_single_empty_and_checkout() {
    let (root, env) = two_file_repo("read-tree-single");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("extra.txt"), b"extra\n").expect("extra");
    run(verbs_stage::add, &mut ctx, &["extra.txt"]).expect("stage extra");
    run(verbs_merge_plumbing::read_tree, &mut ctx, &["HEAD"]).expect("read-tree");
    let out = run(verbs_stage::ls_files, &mut ctx, &[]).expect("ls-files");
    let text = String::from_utf8(out).expect("utf8");
    assert!(!text.contains("extra.txt"), "got {text:?}");
    run(verbs_merge_plumbing::read_tree, &mut ctx, &["--empty"]).expect("empty");
    let out = run(verbs_stage::ls_files, &mut ctx, &[]).expect("ls-files");
    assert!(out.is_empty());
    // `-u` restores the worktree from the reseated index.
    std::fs::remove_file(root.join("s.txt")).expect("remove");
    run(verbs_merge_plumbing::read_tree, &mut ctx, &["HEAD", "-u"]).expect("read -u");
    assert_eq!(std::fs::read(root.join("s.txt")).expect("read"), b"one\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn read_tree_merge_stages_conflicts() {
    let (root, env) = plumbing_repo("read-tree-m", &[("f.txt", b"base\n")]);
    let mut ctx = repo_ctx(&root, env);
    let base = plumbing_head(&mut ctx);
    std::fs::write(root.join("f.txt"), b"b\n").expect("b");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "b side"]).expect("commit");
    let b_side = plumbing_head(&mut ctx);
    run(verbs_branch::reset, &mut ctx, &["--hard", &base]).expect("reset");
    std::fs::write(root.join("f.txt"), b"c\n").expect("c");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "c side"]).expect("commit");
    let c_side = plumbing_head(&mut ctx);
    run(
        verbs_merge_plumbing::read_tree,
        &mut ctx,
        &["-m", base.as_str(), b_side.as_str(), c_side.as_str()],
    )
    .expect("three-tree");
    let out = run(verbs_stage::ls_files, &mut ctx, &["-u"]).expect("stages");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("f.txt"), "got {text:?}");
    // The worktree keeps the pre-merge bytes; no markers are written.
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"c\n");
    // A clean three-way collapses back to stage zero (clear the stopped
    // stages first: `-m` refuses an unmerged index).
    run(
        verbs_merge_plumbing::read_tree,
        &mut ctx,
        &["--reset", base.as_str()],
    )
    .expect("reset clears");
    run(
        verbs_merge_plumbing::read_tree,
        &mut ctx,
        &["-m", base.as_str(), b_side.as_str(), b_side.as_str()],
    )
    .expect("clean");
    let out = run(verbs_stage::ls_files, &mut ctx, &["-u"]).expect("no stages");
    assert!(out.is_empty());
    // One-tree `-m` only fast-forwards an unchanged index.
    let err = run(
        verbs_merge_plumbing::read_tree,
        &mut ctx,
        &["-m", c_side.as_str()],
    )
    .expect_err("one-tree refuses");
    assert!(err.to_string().contains("two trees"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn checkout_index_round_trip() {
    let (root, env) = seeded_repo("checkout-index", "f.txt", b"data\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::remove_file(root.join("f.txt")).expect("remove");
    let out = run(verbs_merge_plumbing::checkout_index, &mut ctx, &["f.txt"]).expect("checkout");
    assert_eq!(String::from_utf8(out).expect("utf8"), "f.txt\n");
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"data\n");
    // A dirty file refuses without `--force`.
    std::fs::write(root.join("f.txt"), b"dirty\n").expect("dirty");
    let err = run(verbs_merge_plumbing::checkout_index, &mut ctx, &["f.txt"]).expect_err("refuse");
    assert!(err.to_string().contains("no checkout"), "got {err:?}");
    run(
        verbs_merge_plumbing::checkout_index,
        &mut ctx,
        &["-f", "f.txt"],
    )
    .expect("force");
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"data\n");
    // `--prefix` roots the materialization elsewhere.
    run(
        verbs_merge_plumbing::checkout_index,
        &mut ctx,
        &["-f", "--prefix=out", "f.txt"],
    )
    .expect("prefix");
    assert_eq!(
        std::fs::read(root.join("out/f.txt")).expect("read"),
        b"data\n"
    );
    let err = run(
        verbs_merge_plumbing::checkout_index,
        &mut ctx,
        &["nope.txt"],
    )
    .expect_err("missing");
    assert!(err.to_string().contains("not in the index"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn sparse_checkout_set_filters_worktree() {
    let (root, env) = plumbing_repo(
        "sparse",
        &[
            ("top.txt", b"top\n"),
            ("sub/a.txt", b"a\n"),
            ("sub/b.txt", b"b\n"),
        ],
    );
    let mut ctx = repo_ctx(&root, env);
    run(
        verbs_sparse::sparse_checkout,
        &mut ctx,
        &["set", "sub/", "!sub/b.txt"],
    )
    .expect("set");
    assert!(!root.join("top.txt").exists());
    assert!(root.join("sub/a.txt").exists());
    assert!(!root.join("sub/b.txt").exists());
    let store = ctx.store().expect("store");
    let kind = ctx.kind().expect("kind");
    for (name, skipped) in [("top.txt", true), ("sub/a.txt", false), ("sub/b.txt", true)] {
        let rows = super::state::scan_index(store, kind).expect("scan");
        let Some(row) = rows.iter().find(|(path, stage, _)| {
            path.as_bytes() == name.as_bytes() && *stage == ruk_core::index::Stage::Zero
        }) else {
            panic!("row for {name}");
        };
        assert_eq!(row.2.flags().skip_worktree, skipped, "flag for {name}");
    }
    let out = run(verbs_sparse::sparse_checkout, &mut ctx, &["list"]).expect("list");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("sub/"), "got {text:?}");
    // A dirty in-cone file blocks reapply.
    std::fs::write(root.join("sub/a.txt"), b"dirty\n").expect("dirty");
    let err =
        run(verbs_sparse::sparse_checkout, &mut ctx, &["set", "sub/"]).expect_err("dirty refuses");
    assert!(
        err.to_string().contains("would be overwritten"),
        "got {err:?}"
    );
    std::fs::write(root.join("sub/a.txt"), b"a\n").expect("restore");
    run(verbs_sparse::sparse_checkout, &mut ctx, &["disable"]).expect("disable");
    assert_eq!(std::fs::read(root.join("top.txt")).expect("read"), b"top\n");
    assert_eq!(std::fs::read(root.join("sub/b.txt")).expect("read"), b"b\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn rerere_records_and_replays_resolution() {
    let (root, env) = seeded_repo("rerere", "f.txt", b"base\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    std::fs::write(root.join("f.txt"), b"side\n").expect("side");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "side work"]).expect("commit");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    std::fs::write(root.join("f.txt"), b"main\n").expect("main");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "main work"]).expect("commit");
    let err = run(verbs_history::merge, &mut ctx, &["side"]).expect_err("conflict");
    assert!(err.to_string().contains("Merge conflict"), "got {err:?}");
    let body = std::fs::read(root.join("f.txt")).expect("read");
    assert!(
        String::from_utf8_lossy(&body).contains("<<<<<<<"),
        "markers"
    );
    // First run records the preimage; nothing is resolved yet.
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &[]).expect("record");
    assert!(out.is_empty());
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &["status"]).expect("status");
    assert!(String::from_utf8(out).expect("utf8").contains("f.txt"));
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &["remaining"]).expect("remaining");
    assert!(String::from_utf8(out).expect("utf8").contains("f.txt"));
    // Resolving graduates the preimage into a postimage.
    std::fs::write(root.join("f.txt"), b"resolved\n").expect("resolve");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &[]).expect("graduate");
    assert!(
        String::from_utf8(out)
            .expect("utf8")
            .contains("Recorded resolution for 'f.txt'"),
        "graduate"
    );
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &["remaining"]).expect("none left");
    assert!(out.is_empty());
    // Recreate the same conflict; the recorded resolution replays.
    run(verbs_history::merge, &mut ctx, &["--abort"]).expect("abort");
    run(verbs_history::merge, &mut ctx, &["side"]).expect_err("conflict again");
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &[]).expect("replay");
    assert!(
        String::from_utf8(out)
            .expect("utf8")
            .contains("using previous resolution"),
        "replay"
    );
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read"),
        b"resolved\n"
    );
    let out = run(verbs_stage::ls_files, &mut ctx, &["-u"]).expect("no stages");
    assert!(out.is_empty());
    // Forgetting drops the record: the next identical conflict stays manual.
    run(verbs_history::merge, &mut ctx, &["--abort"]).expect("abort");
    run(verbs_history::merge, &mut ctx, &["side"]).expect_err("conflict third");
    run(verbs_merge_plumbing::rerere, &mut ctx, &["forget", "f.txt"]).expect("forget");
    let out = run(verbs_merge_plumbing::rerere, &mut ctx, &["remaining"]).expect("manual");
    assert!(String::from_utf8(out).expect("utf8").contains("f.txt"));
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
// ---------------------------------------------------------------------------
// notes + replace lane: commit-backed notes and refs/replace/* redirection
// ---------------------------------------------------------------------------

/// Reads `HEAD` as trimmed hex for notes/replace tests.
fn notes_tip(ctx: &mut Ctx) -> String {
    String::from_utf8(run(verbs_history::rev_parse, ctx, &["HEAD"]).expect("head"))
        .expect("utf8")
        .trim()
        .to_owned()
}

/// Rev-parses one explicit revision as trimmed hex.
fn notes_tip_of(ctx: &mut Ctx, rev: &str) -> String {
    String::from_utf8(run(verbs_history::rev_parse, ctx, &[rev]).expect("rev-parse"))
        .expect("utf8")
        .trim()
        .to_owned()
}

#[test]
fn notes_add_show_list_round_trip() {
    let (root, env) = seeded_repo("notes-round-trip", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let head = notes_tip(&mut ctx);
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-m", "first note", head.as_str()],
    )
    .expect("add");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", head.as_str()]).expect("show");
    assert_eq!(shown, b"first note");
    let listed = String::from_utf8(run(verbs_notes::notes, &mut ctx, &["list"]).expect("list"))
        .expect("utf8");
    let line = listed.trim();
    assert_eq!(line.split_whitespace().count(), 2, "got {listed:?}");
    assert!(line.ends_with(head.as_str()), "got {listed:?}");
    // The notes ref always points at a commit, never a blob or tree.
    let refname =
        String::from_utf8(run(verbs_notes::notes, &mut ctx, &["get-ref"]).expect("get-ref"))
            .expect("utf8");
    assert_eq!(refname.trim(), "refs/notes/commits");
    let tip = String::from_utf8(
        run(verbs_history::rev_parse, &mut ctx, &["refs/notes/commits"]).expect("notes tip"),
    )
    .expect("utf8");
    let kind = run(verbs_objects::cat_file, &mut ctx, &["-t", tip.trim()]).expect("type");
    assert_eq!(String::from_utf8_lossy(&kind).trim_end(), "commit");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn notes_append_copy_remove() {
    let (root, env) = seeded_repo("notes-acr", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    let first = notes_tip(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second change");
    let second = notes_tip(&mut ctx);
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-m", "base", first.as_str()],
    )
    .expect("add");
    let err = run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-m", "again", first.as_str()],
    )
    .expect_err("clobber refused");
    assert!(
        err.to_string().contains("already has a note"),
        "got {err:?}"
    );
    run(
        verbs_notes::notes,
        &mut ctx,
        &["append", "-m", "more", first.as_str()],
    )
    .expect("append");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", first.as_str()]).expect("show");
    assert_eq!(shown, b"base\nmore");
    run(
        verbs_notes::notes,
        &mut ctx,
        &["copy", first.as_str(), second.as_str()],
    )
    .expect("copy");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", second.as_str()]).expect("show copy");
    assert_eq!(shown, b"base\nmore");
    let err = run(
        verbs_notes::notes,
        &mut ctx,
        &["copy", first.as_str(), second.as_str()],
    )
    .expect_err("copy clobber refused");
    assert!(
        err.to_string().contains("already has a note"),
        "got {err:?}"
    );
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-f", "-m", "new", first.as_str()],
    )
    .expect("force add");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", first.as_str()]).expect("show new");
    assert_eq!(shown, b"new");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", second.as_str()]).expect("copy kept");
    assert_eq!(shown, b"base\nmore");
    run(
        verbs_notes::notes,
        &mut ctx,
        &["remove", first.as_str(), second.as_str()],
    )
    .expect("remove");
    let listed = run(verbs_notes::notes, &mut ctx, &["list"]).expect("list");
    assert!(listed.is_empty(), "got {listed:?}");
    let err = run(verbs_notes::notes, &mut ctx, &["show", first.as_str()]).expect_err("gone");
    assert!(err.to_string().contains("no note"), "got {err:?}");
    // Removing the last note deletes the ref instead of leaving emptiness.
    run(verbs_history::rev_parse, &mut ctx, &["refs/notes/commits"]).expect_err("ref gone");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn notes_refs_merge_and_prune() {
    let (root, env) = seeded_repo("notes-merge-prune", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    let head = notes_tip(&mut ctx);
    let out = run(
        verbs_notes::notes,
        &mut ctx,
        &["get-ref", "--ref", "my-notes"],
    )
    .expect("get-ref");
    assert_eq!(
        String::from_utf8(out).expect("utf8").trim(),
        "refs/notes/my-notes"
    );
    run(
        verbs_notes::notes,
        &mut ctx,
        &["--ref", "my-notes", "add", "-m", "custom", head.as_str()],
    )
    .expect("add other ref");
    let listed = run(verbs_notes::notes, &mut ctx, &["list"]).expect("default empty");
    assert!(listed.is_empty(), "got {listed:?}");
    run(verbs_notes::notes, &mut ctx, &["merge", "my-notes"]).expect("merge");
    let shown = run(verbs_notes::notes, &mut ctx, &["show", head.as_str()]).expect("merged");
    assert_eq!(shown, b"custom");
    run(
        verbs_notes::notes,
        &mut ctx,
        &[
            "--ref",
            "my-notes",
            "add",
            "-f",
            "-m",
            "diverged",
            head.as_str(),
        ],
    )
    .expect("diverge");
    let err =
        run(verbs_notes::notes, &mut ctx, &["merge", "my-notes"]).expect_err("conflict refused");
    assert!(
        err.to_string().contains("differs on both sides"),
        "got {err:?}"
    );
    // A note for a missing object prunes away; live notes stay.
    let mut ghost = head.clone();
    ghost.replace_range(0..1, if &head[0..1] == "a" { "b" } else { "a" });
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-m", "ghost", ghost.as_str()],
    )
    .expect("ghost");
    let dry = String::from_utf8(run(verbs_notes::notes, &mut ctx, &["prune", "-n"]).expect("dry"))
        .expect("utf8");
    assert!(dry.contains(&format!("would prune {ghost}")), "got {dry:?}");
    let listed = String::from_utf8(run(verbs_notes::notes, &mut ctx, &["list"]).expect("list"))
        .expect("utf8");
    assert!(listed.contains(ghost.as_str()), "got {listed:?}");
    let pruned =
        String::from_utf8(run(verbs_notes::notes, &mut ctx, &["prune", "-v"]).expect("prune"))
            .expect("utf8");
    assert!(
        pruned.contains(&format!("pruned {ghost}")),
        "got {pruned:?}"
    );
    let shown = run(verbs_notes::notes, &mut ctx, &["show", head.as_str()]).expect("live kept");
    assert_eq!(shown, b"custom");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn replace_redirects_history_verbs() {
    let (root, env) = seeded_repo("replace-history", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    let first = notes_tip(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second change");
    let second = notes_tip(&mut ctx);
    let before = run(verbs_history::diff, &mut ctx, &[first.as_str()]).expect("diff before");
    assert!(!before.is_empty(), "baseline diff is empty");
    run(
        verbs_notes::replace,
        &mut ctx,
        &[first.as_str(), second.as_str()],
    )
    .expect("create");
    // Raw resolution still spells the stored oid.
    assert_eq!(notes_tip_of(&mut ctx, first.as_str()), first);
    // Log walks the replacement: only the second subject renders.
    let logged = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--oneline", first.as_str()]).expect("log"),
    )
    .expect("utf8");
    assert!(logged.contains("second change"), "got {logged:?}");
    assert!(!logged.contains("seed"), "got {logged:?}");
    // Show renders the replacement commit.
    let shown =
        String::from_utf8(run(verbs_history::show, &mut ctx, &[first.as_str()]).expect("show"))
            .expect("utf8");
    assert!(shown.contains("second change"), "got {shown:?}");
    // Diff against the worktree (which holds v2) goes quiet.
    let after = run(verbs_history::diff, &mut ctx, &[first.as_str()]).expect("diff after");
    assert!(after.is_empty(), "got {after:?}");
    // Blame attributes lines to the replacement commit.
    let blamed = String::from_utf8(
        run(verbs_blame::blame, &mut ctx, &[first.as_str(), "f.txt"]).expect("blame"),
    )
    .expect("utf8");
    assert!(blamed.contains(&second[..7]), "got {blamed:?}");
    // Checkout materializes the replacement tree.
    run(
        verbs_branch::checkout,
        &mut ctx,
        &["--detach", first.as_str()],
    )
    .expect("detach");
    assert_eq!(std::fs::read(root.join("f.txt")).expect("read"), b"v2\n");
    // Deleting the replacement restores the original history.
    run(verbs_notes::replace, &mut ctx, &["-d", first.as_str()]).expect("delete");
    let logged = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--oneline", first.as_str()]).expect("log back"),
    )
    .expect("utf8");
    assert!(logged.contains("seed"), "got {logged:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn replace_list_force_delete() {
    let (root, env) = seeded_repo("replace-list", "f.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    let first = notes_tip(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"v2\n", "second change");
    let second = notes_tip(&mut ctx);
    lane_commit(&mut ctx, &root, "f.txt", b"v3\n", "third change");
    let third = notes_tip(&mut ctx);
    run(
        verbs_notes::replace,
        &mut ctx,
        &[first.as_str(), second.as_str()],
    )
    .expect("create");
    let err = run(
        verbs_notes::replace,
        &mut ctx,
        &[first.as_str(), third.as_str()],
    )
    .expect_err("clobber refused");
    assert!(err.to_string().contains("already exists"), "got {err:?}");
    let listed = String::from_utf8(run(verbs_notes::replace, &mut ctx, &["-l"]).expect("list"))
        .expect("utf8");
    assert_eq!(listed.trim(), first.as_str());
    let pattern = format!("{}*", &first[..12]);
    let filtered = String::from_utf8(
        run(verbs_notes::replace, &mut ctx, &["-l", pattern.as_str()]).expect("glob"),
    )
    .expect("utf8");
    assert_eq!(filtered.trim(), first.as_str());
    let missed =
        String::from_utf8(run(verbs_notes::replace, &mut ctx, &["-l", "no-such-*"]).expect("miss"))
            .expect("utf8");
    assert!(missed.is_empty(), "got {missed:?}");
    run(
        verbs_notes::replace,
        &mut ctx,
        &["-f", first.as_str(), third.as_str()],
    )
    .expect("force");
    let shown = String::from_utf8(
        run(verbs_history::show, &mut ctx, &[first.as_str()]).expect("show third"),
    )
    .expect("utf8");
    assert!(shown.contains("third change"), "got {shown:?}");
    run(verbs_notes::replace, &mut ctx, &["-d", first.as_str()]).expect("delete");
    let listed = run(verbs_notes::replace, &mut ctx, &["-l"]).expect("empty");
    assert!(listed.is_empty(), "got {listed:?}");
    let err =
        run(verbs_notes::replace, &mut ctx, &["-d", first.as_str()]).expect_err("double delete");
    assert!(err.to_string().contains("no replacement"), "got {err:?}");
    let err = run(
        verbs_notes::replace,
        &mut ctx,
        &[second.as_str(), second.as_str()],
    )
    .expect_err("self refused");
    assert!(err.to_string().contains("itself"), "got {err:?}");
    let mut ghost = second.clone();
    ghost.replace_range(0..1, if &second[0..1] == "a" { "b" } else { "a" });
    let err = run(
        verbs_notes::replace,
        &mut ctx,
        &[ghost.as_str(), third.as_str()],
    )
    .expect_err("missing orig");
    assert!(err.to_string().contains("does not exist"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn fastio_import_creates_branch_history() {
    let base = temp_base("fastio-import");
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
    let mut ctx = repo_ctx(&root, env);
    ctx.env.stdin = Some(
        b"blob\nmark :1\ndata 5\nhello\ncommit refs/heads/main\nmark :2\nauthor Ada <ada@example.invalid> 1700000000 +0000\ncommitter Ada <ada@example.invalid> 1700000000 +0000\ndata 12\nfirst import\nM 100644 :1 hello.txt\ndone\n"
            .to_vec(),
    );
    run(verbs_fastio::fast_import, &mut ctx, &[]).expect("fast-import");
    let head = String::from_utf8(
        run(verbs_history::rev_parse, &mut ctx, &["refs/heads/main"]).expect("rev-parse"),
    )
    .expect("utf8");
    let head = head.trim();
    assert!(
        head.len() == 40 || head.len() == 64,
        "unexpected head {head:?}"
    );
    assert!(head.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let log = String::from_utf8(run(verbs_history::log, &mut ctx, &["--oneline"]).expect("log"))
        .expect("utf8");
    assert!(log.contains("first import"), "got {log:?}");
    let body =
        String::from_utf8(run(verbs_objects::cat_file, &mut ctx, &["-p", head]).expect("cat-file"))
            .expect("utf8");
    assert!(body.contains("first import"), "got {body:?}");
    // The importer never touches the worktree: a checkout materializes it.
    assert!(!root.join("hello.txt").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn fastio_export_import_roundtrip() {
    let (root, env) = seeded_repo("fastio-roundtrip", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "change two");
    run(verbs_branch::tag, &mut ctx, &["v1"]).expect("tag");
    let stream = run(verbs_fastio::fast_export, &mut ctx, &["--all"]).expect("export");
    let text = String::from_utf8(stream.clone()).expect("utf8");
    assert!(
        text.contains("commit refs/heads/main\nmark :"),
        "got {text:?}"
    );
    assert!(text.contains("\nblob\nmark :"), "got {text:?}");
    assert!(text.contains("from :"), "got {text:?}");
    assert!(text.contains("reset refs/tags/v1\n"), "got {text:?}");
    assert!(text.ends_with("done\n"), "got {text:?}");
    let before_log = run(verbs_history::log, &mut ctx, &["--oneline"]).expect("log");
    let before_refs = run(verbs_branch::show_ref, &mut ctx, &[]).expect("show-ref");
    let dest_base = temp_base("fastio-roundtrip-dest");
    let dest_env = test_env(&dest_base);
    let mut dest_ctx = Ctx {
        store: None,
        root: dest_base.clone(),
        file_base: dest_base.clone(),
        kind: None,
        env: dest_env.clone(),
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut dest_ctx, &["repo".to_owned()]).expect("init");
    let dest_root = dest_base.join("repo");
    let mut dest_ctx = repo_ctx(&dest_root, dest_env);
    dest_ctx.env.stdin = Some(stream);
    run(verbs_fastio::fast_import, &mut dest_ctx, &[]).expect("import");
    let after_log = run(verbs_history::log, &mut dest_ctx, &["--oneline"]).expect("log");
    let after_refs = run(verbs_branch::show_ref, &mut dest_ctx, &[]).expect("show-ref");
    assert_eq!(before_log, after_log);
    assert_eq!(before_refs, after_refs);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(&dest_base);
}

#[test]
fn fastio_export_marks_skip_known_objects() {
    let (root, env) = seeded_repo("fastio-marks", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(
        verbs_fastio::fast_export,
        &mut ctx,
        &["--export-marks=marks.out"],
    )
    .expect("export");
    let marks = std::fs::read(root.join("marks.out")).expect("marks file");
    let marks_text = String::from_utf8(marks).expect("utf8");
    assert!(
        !marks_text.contains("refs/heads/main"),
        "marks hold oids, got {marks_text:?}"
    );
    assert!(
        marks_text.lines().all(|line| line.starts_with(':')),
        "got {marks_text:?}"
    );
    let again = run(
        verbs_fastio::fast_export,
        &mut ctx,
        &["--import-marks=marks.out"],
    )
    .expect("re-export");
    let text = String::from_utf8(again).expect("utf8");
    // Every object is already known, so the tip rides a reset line and no
    // commit or blob block is re-emitted.
    assert!(text.contains("reset refs/heads/main\n"), "got {text:?}");
    assert!(!text.contains("commit refs/heads/main\n"), "got {text:?}");
    assert!(!text.contains("\nblob\n"), "got {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn fastio_range_diff_pairs_patches() {
    let (root, env) = seeded_repo("fastio-range-diff", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "change two");
    let base =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~1"]).expect("base"))
            .expect("utf8")
            .trim()
            .to_owned();
    let main = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("main"))
        .expect("utf8")
        .trim()
        .to_owned();
    run(verbs_branch::checkout, &mut ctx, &["-b", "side", &base]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "change two");
    let side = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("side"))
        .expect("utf8")
        .trim()
        .to_owned();
    let same = String::from_utf8(
        run(
            verbs_fastio::range_diff,
            &mut ctx,
            &[&format!("{base}..{main}"), &format!("{base}..{side}")],
        )
        .expect("range-diff"),
    )
    .expect("utf8");
    assert!(same.contains(" = "), "got {same:?}");
    assert!(same.contains("change two"), "got {same:?}");
    run(verbs_branch::checkout, &mut ctx, &["-b", "side2", &base]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"one\nTHREE\n", "change two");
    let moved =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("moved"))
            .expect("utf8")
            .trim()
            .to_owned();
    let changed = String::from_utf8(
        run(
            verbs_fastio::range_diff,
            &mut ctx,
            &[&format!("{base}..{main}"), &format!("{base}..{moved}")],
        )
        .expect("range-diff"),
    )
    .expect("utf8");
    // Same subject but a different patch pairs with `!`.
    assert!(changed.contains(" ! "), "got {changed:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn fastio_request_pull_template() {
    let (root, env) = seeded_repo("fastio-request-pull", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"one\ntwo\n", "change two");
    let start =
        String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD~1"]).expect("start"))
            .expect("utf8")
            .trim()
            .to_owned();
    let out = String::from_utf8(
        run(
            verbs_fastio::request_pull,
            &mut ctx,
            &[&start, "https://example.invalid/repo"],
        )
        .expect("request-pull"),
    )
    .expect("utf8");
    assert!(
        out.contains(&format!("The following changes since commit {start}:")),
        "got {out:?}"
    );
    assert!(
        out.contains("are available in the Git repository at:"),
        "got {out:?}"
    );
    assert!(out.contains("https://example.invalid/repo"), "got {out:?}");
    assert!(out.contains("change two"), "got {out:?}");
    assert!(out.contains("f.txt"), "got {out:?}");
    let err = run(
        verbs_fastio::request_pull,
        &mut ctx,
        &["-p", &start, "https://example.invalid/repo"],
    )
    .expect_err("request-pull -p");
    assert!(err.to_string().contains("request-pull -p"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
// Wave J (LogFlags): `log` flag parity.
// ---------------------------------------------------------------------------

/// Builds a three-commit repo: seed, a one-line change, and a new file.
fn log_flags_repo(case: &str) -> (PathBuf, CliEnv) {
    let (root, env) = seeded_repo(case, "a.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env.clone());
    lane_commit(&mut ctx, &root, "a.txt", b"one\ntwo\n", "add two");
    lane_commit(&mut ctx, &root, "b.txt", b"bee\n", "add b");
    (root, env)
}

#[test]
fn log_merges_filter() {
    let (root, env) = log_flags_repo("logflags-merges");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "feature"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "f.txt", b"feat\n", "feature work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "m.txt", b"main\n", "main work");
    run(verbs_history::merge, &mut ctx, &["feature"]).expect("merge");
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "--merges"]).expect("merges");
    assert_eq!(String::from_utf8_lossy(&out).lines().count(), 1);
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "--no-merges"]).expect("no-merges");
    assert_eq!(String::from_utf8_lossy(&out).lines().count(), 5);
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_pickaxe_s_and_g() {
    let (root, env) = log_flags_repo("logflags-pickaxe");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "-S", "two"]).expect("-S");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("add two"), "got {text}");
    assert!(!text.contains("add b"), "got {text}");
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "-G", "bee"]).expect("-G");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("add b"), "got {text}");
    assert!(!text.contains("add two"), "got {text}");
    let err = run(verbs_history::log, &mut ctx, &["-G", "(["]).expect_err("bad -G");
    assert!(err.to_string().contains("bad -G regex"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_first_parent_hides_side_branch() {
    let (root, env) = log_flags_repo("logflags-firstparent");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "s.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "m.txt", b"main\n", "main work");
    run(verbs_history::merge, &mut ctx, &["side"]).expect("merge");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--first-parent"],
    )
    .expect("first-parent");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(!text.contains("side work"), "got {text}");
    assert!(text.contains("main work"), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_format_placeholders_and_colon_alias() {
    let (root, env) = log_flags_repo("logflags-format");
    let mut ctx = repo_ctx(&root, env);
    let out =
        run(verbs_history::log, &mut ctx, &["--format=%H %P %T %s"]).expect("format placeholders");
    let err = run(verbs_history::log, &mut ctx, &["--format:%H"]).expect_err("colon");
    assert!(err.to_string().contains("unknown option"), "got {err:?}");
    let line = String::from_utf8_lossy(&out).into_owned();
    let fields: Vec<&str> = line.trim().split(' ').collect();
    assert!(fields.len() >= 4, "got {line}");
    assert!(fields[0].len() >= 40, "got {line}");
    assert!(fields[2].len() >= 40, "got {line}");
    assert!(line.contains("add b"), "got {line}");
    let out = run(verbs_history::log, &mut ctx, &["--format=%h %s", "-n", "1"]).expect("format eq");
    assert!(
        String::from_utf8_lossy(&out).contains("add b"),
        "got {:?}",
        out
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_pretty_shapes() {
    let (root, env) = log_flags_repo("logflags-pretty");
    let mut ctx = repo_ctx(&root, env);
    for (flag, marker) in [
        ("--pretty=full", "Commit: "),
        ("--pretty=fuller", "CommitDate: "),
        ("--pretty=email", "Subject: [PATCH]"),
        ("--pretty=raw", "\ntree "),
    ] {
        let out = run(verbs_history::log, &mut ctx, &[flag, "-n", "1"]).expect(flag);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains(marker), "{flag} got {text}");
    }
    // An explicit pretty overrides a bare `--oneline`.
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--pretty=full", "-n", "1"],
    )
    .expect("pretty over oneline");
    assert!(
        String::from_utf8_lossy(&out).contains("Commit: "),
        "got {:?}",
        out
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_extra_stat_shapes() {
    let (root, env) = log_flags_repo("logflags-stat");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_history::log, &mut ctx, &["--numstat", "-n", "1"]).expect("numstat");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("\tb.txt"), "got {text}");
    let out = run(verbs_history::log, &mut ctx, &["--shortstat", "-n", "1"]).expect("shortstat");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("1 file changed"), "got {text}");
    let out = run(verbs_history::log, &mut ctx, &["--summary", "-n", "1"]).expect("summary");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("create mode"), "got {text}");
    let out = run(verbs_history::log, &mut ctx, &["--dirstat", "-n", "1"]).expect("dirstat");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains('%'), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_date_shapes_and_abbrev() {
    let (root, env) = log_flags_repo("logflags-date");
    let mut ctx = repo_ctx(&root, env);
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--format=%ad", "--date=short", "-n", "1"],
    )
    .expect("date short");
    let strict_out = run(
        verbs_history::log,
        &mut ctx,
        &["--format=%ad", "--date=iso-strict", "-n", "1"],
    )
    .expect("date iso-strict");
    let strict_text = String::from_utf8_lossy(&strict_out).trim().to_owned();
    assert!(strict_text.contains('T'), "got {strict_text}");
    assert!(
        strict_text.contains('+') || strict_text.contains('-'),
        "got {strict_text}"
    );
    let text = String::from_utf8_lossy(&out).trim().to_owned();
    assert_eq!(text.len(), 10, "got {text}");
    assert_eq!(text.as_bytes()[4], b'-', "got {text}");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--format=%ad", "--relative-date", "-n", "1"],
    )
    .expect("relative");
    assert!(
        String::from_utf8_lossy(&out).contains("ago"),
        "got {:?}",
        out
    );
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--abbrev=12", "-n", "1"],
    )
    .expect("abbrev");
    let line = String::from_utf8_lossy(&out).into_owned();
    assert_eq!(line.split(' ').next().map(str::len), Some(12), "got {line}");
    let err = run(verbs_history::log, &mut ctx, &["--date=bogus"]).expect_err("bad date");
    assert!(err.to_string().contains("bad --date"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_follow_tracks_rename() {
    let (root, env) = seeded_repo("logflags-follow", "old.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "old.txt", b"v1\nv2\n", "grow old");
    std::fs::rename(root.join("old.txt"), root.join("new.txt")).expect("rename");
    run(verbs_stage::add, &mut ctx, &["new.txt"]).expect("add new");
    run(verbs_stage::rm, &mut ctx, &["old.txt"]).expect("rm old");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "rename old to new"],
    )
    .expect("commit");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--follow", "--", "new.txt"],
    )
    .expect("follow");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("grow old"), "got {text}");
    assert!(text.contains("rename old to new"), "got {text}");
    let err = run(verbs_history::log, &mut ctx, &["--follow"]).expect_err("follow needs path");
    assert!(err.to_string().contains("--follow"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_source_and_left_right() {
    let (root, env) = log_flags_repo("logflags-source");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "s.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "m.txt", b"main\n", "main work");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--format=%H %S %s", "main...side"],
    )
    .expect("symmetric source");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains(" side "), "got {text}");
    assert!(text.contains(" main "), "got {text}");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--left-right", "main...side"],
    )
    .expect("left-right");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.lines().any(|line| line.starts_with("< ")),
        "got {text}"
    );
    assert!(
        text.lines().any(|line| line.starts_with("> ")),
        "got {text}"
    );
    // Custom formats carry no side marks, as in the oracle.
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--format=%s", "--left-right", "main...side"],
    )
    .expect("format suppresses marks");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.lines()
            .all(|line| !line.starts_with('<') && !line.starts_with('>')),
        "got {text}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_branches_tags_exclude() {
    let (root, env) = log_flags_repo("logflags-refs");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::branch, &mut ctx, &["kept"]).expect("branch kept");
    run(verbs_branch::tag, &mut ctx, &["v1"]).expect("tag");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--branches=ke*"],
    )
    .expect("branches glob");
    assert!(
        String::from_utf8_lossy(&out).contains("add b"),
        "got {:?}",
        out
    );
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "--tags"]).expect("tags");
    assert!(
        String::from_utf8_lossy(&out).contains("add b"),
        "got {:?}",
        out
    );
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "s.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "--all"]).expect("all");
    assert!(
        String::from_utf8_lossy(&out).contains("side work"),
        "got {:?}",
        out
    );
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--all", "--exclude=refs/heads/side"],
    )
    .expect("exclude side");
    assert!(
        !String::from_utf8_lossy(&out).contains("side work"),
        "got {:?}",
        out
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_notes_boundary_decorate() {
    let (root, env) = log_flags_repo("logflags-notes");
    let mut ctx = repo_ctx(&root, env);
    let head = notes_tip(&mut ctx);
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "-m", "reviewed", head.as_str()],
    )
    .expect("note add");
    let out = run(verbs_history::log, &mut ctx, &["--show-notes", "-n", "1"]).expect("show-notes");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("reviewed"), "got {text}");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--show-notes", "--no-notes", "-n", "1"],
    )
    .expect("no-notes");
    assert!(
        !String::from_utf8_lossy(&out).contains("reviewed"),
        "got {:?}",
        out
    );
    // A custom ref stays hidden unless named: `GIT_NOTES_REF` names it.
    run(
        verbs_notes::notes,
        &mut ctx,
        &["add", "--ref", "review", "-m", "looks good", head.as_str()],
    )
    .expect("note add custom");
    let out =
        run(verbs_history::log, &mut ctx, &["--show-notes", "-n", "1"]).expect("other ref hidden");
    assert!(
        !String::from_utf8_lossy(&out).contains("looks good"),
        "got {:?}",
        out
    );
    ctx.env
        .vars
        .insert("GIT_NOTES_REF".to_owned(), "refs/notes/review".to_owned());
    let out = run(verbs_history::log, &mut ctx, &["--show-notes", "-n", "1"]).expect("env ref");
    assert!(
        String::from_utf8_lossy(&out).contains("looks good"),
        "got {:?}",
        out
    );
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--decorate=full", "-n", "1"],
    )
    .expect("decorate full");
    // `auto` never decorates off-terminal; explicit full does.
    let auto_out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--decorate=auto", "-n", "1"],
    )
    .expect("decorate auto");
    assert!(
        !String::from_utf8_lossy(&auto_out).contains("HEAD ->"),
        "got {:?}",
        auto_out
    );
    assert!(
        String::from_utf8_lossy(&out).contains("refs/heads/main"),
        "got {:?}",
        out
    );
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--boundary", "HEAD~1..HEAD"],
    )
    .expect("boundary");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.lines().any(|line| line.starts_with("- ")),
        "got {text}"
    );
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--simplify-by-decoration"],
    )
    .expect("simplify");
    assert_eq!(
        String::from_utf8_lossy(&out).lines().count(),
        1,
        "got {:?}",
        out
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_rename_pathspec_shows_onesided() {
    // The pathspec bounds pairing first: a rename with only its new side
    // in spec prints as an addition, and vice versa for deletions.
    let (root, env) = seeded_repo("logflags-renamepath", "old.txt", b"v1\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::rename(root.join("old.txt"), root.join("new.txt")).expect("rename");
    run(verbs_stage::add, &mut ctx, &["new.txt"]).expect("add new");
    run(verbs_stage::rm, &mut ctx, &["old.txt"]).expect("rm old");
    run(verbs_history::commit, &mut ctx, &["-m", "rename"]).expect("commit");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--name-status", "-M", "--oneline", "--", "new.txt"],
    )
    .expect("spec new");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("A\tnew.txt"), "got {text}");
    assert!(!text.contains('R'), "got {text}");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--name-status", "-M", "--oneline", "--", "old.txt"],
    )
    .expect("spec old");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("D\told.txt"), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_boundary_ignores_disjoint_root() {
    use ruk_core::ByteString;
    use ruk_core::conflict::{Signature, TzOffset};
    use ruk_core::heads::Head;
    use ruk_core::ids::Oid;
    use ruk_core::ops::{NewRequest, new as ops_new};
    use ruk_core::store::ObjectKind;

    // Two unrelated roots: excluding one borders nothing in the other's
    // walk, so the shown commit prints with no boundary rows. (Excluding a
    // descendant would empty the walk instead of testing this.)
    let base = temp_base("logflags-disjoint");
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
    let (alpha, beta) = {
        let store = open_store(&root);
        let tree =
            super::tree::store_object(&store, ObjectKind::Tree, Vec::new()).expect("empty tree");
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
        (make(vec![], 1000, "alpha\n"), make(vec![], 1000, "beta\n"))
    };
    let mut ctx = repo_ctx(&root, test_env(&root));
    let alpha_hex = alpha.to_hex();
    let beta_ex = format!("^{}", beta.to_hex());
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--boundary", &alpha_hex, &beta_ex],
    )
    .expect("disjoint boundary");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("alpha"), "got {text}");
    assert!(!text.contains("beta"), "got {text}");
    assert!(
        text.lines().all(|line| !line.starts_with("- ")),
        "got {text}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_topo_orders_shared_root_last() {
    let (root, env) = log_flags_repo("logflags-toporoot");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "s.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "m.txt", b"main\n", "main work");
    run(verbs_history::merge, &mut ctx, &["side"]).expect("merge");
    let out = run(verbs_history::log, &mut ctx, &["--oneline", "--topo-order"]).expect("topo");
    let text = String::from_utf8_lossy(&out).into_owned();
    let position = |needle: &str| {
        text.lines()
            .position(|line| line.contains(needle))
            .expect("subject present")
    };
    // The shared root prints after both merged sides, never between them.
    assert!(position("seed") > position("side work"), "got {text}");
    assert!(position("seed") > position("main work"), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_path_limits_diff() {
    let (root, env) = log_flags_repo("logflags-pathdiff");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("a.txt"), b"one\nA\n").expect("write a");
    std::fs::write(root.join("b.txt"), b"bee\nB\n").expect("write b");
    run(verbs_stage::add, &mut ctx, &["a.txt", "b.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "touch both"]).expect("commit");
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--numstat", "-n", "1", "--", "b.txt"],
    )
    .expect("numstat path");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("b.txt"), "got {text}");
    assert!(!text.contains("a.txt"), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn log_topo_order_cherry_pick_smoke() {
    let (root, env) = log_flags_repo("logflags-topo");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    lane_commit(&mut ctx, &root, "s.txt", b"side\n", "side work");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    lane_commit(&mut ctx, &root, "m.txt", b"main\n", "main work");
    for flag in ["--topo-order", "--date-order"] {
        let out = run(
            verbs_history::log,
            &mut ctx,
            &["--oneline", "--all", flag],
        )
        .expect(flag);
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.contains("side work"), "{flag} got {text}");
        assert!(text.contains("add b"), "{flag} got {text}");
        let head_only = run(verbs_history::log, &mut ctx, &["--oneline", flag]).expect(flag);
        let head_text = String::from_utf8_lossy(&head_only).into_owned();
        assert!(!head_text.contains("side work"), "{flag} got {head_text}");
    }
    let out = run(
        verbs_history::log,
        &mut ctx,
        &["--oneline", "--cherry-pick", "--left-right", "main...side"],
    )
    .expect("cherry-pick");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("side work"), "got {text}");
    assert!(text.contains("main work"), "got {text}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_branch_copy_and_filters() {
    let (root, env) = seeded_repo("wavej-branch", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::branch, &mut ctx, &["-c", "copied"]).expect("copy");
    let out =
        String::from_utf8(run(verbs_branch::branch, &mut ctx, &[]).expect("list")).expect("utf8");
    assert!(out.contains("copied"), "got {out:?}");
    let out = String::from_utf8(
        run(verbs_branch::branch, &mut ctx, &["--merged", "HEAD"]).expect("merged"),
    )
    .expect("utf8");
    assert!(out.contains("main"), "got {out:?}");
    let out = String::from_utf8(
        run(
            verbs_branch::branch,
            &mut ctx,
            &["--format=%(refname:short)"],
        )
        .expect("format"),
    )
    .expect("utf8");
    assert!(out.contains("main"), "got {out:?}");
    let out =
        String::from_utf8(run(verbs_branch::branch, &mut ctx, &["--sort=-refname"]).expect("sort"))
            .expect("utf8");
    assert!(out.contains("main"), "got {out:?}");
    let err =
        run(verbs_branch::branch, &mut ctx, &["--edit-description"]).expect_err("edit-description");
    assert!(err.to_string().contains("editor"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_tag_filters_cleanup_and_format() {
    let (root, env) = seeded_repo("wavej-tag", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::tag, &mut ctx, &["-a", "-m", "note", "v1"]).expect("annotated");
    run(verbs_branch::tag, &mut ctx, &["v2"]).expect("lightweight");
    let out = String::from_utf8(
        run(verbs_branch::tag, &mut ctx, &["--contains", "HEAD"]).expect("contains"),
    )
    .expect("utf8");
    assert!(out.contains("v1"), "got {out:?}");
    let out = String::from_utf8(
        run(verbs_branch::tag, &mut ctx, &["--format=%(refname:short)"]).expect("format"),
    )
    .expect("utf8");
    assert!(out.contains("v1"), "got {out:?}");
    run(
        verbs_branch::tag,
        &mut ctx,
        &["-a", "-m", "  spaced  ", "--cleanup=verbatim", "v3"],
    )
    .expect("verbatim");
    let err = run(verbs_branch::tag, &mut ctx, &["-e", "v4"]).expect_err("edit");
    assert!(err.to_string().contains("editor"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_switch_orphan_and_track() {
    let (root, env) = seeded_repo("wavej-switch", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::switch, &mut ctx, &["--orphan", "fresh"]).expect("orphan");
    let out = String::from_utf8(
        run(
            verbs_history::rev_parse,
            &mut ctx,
            &["--abbrev-ref", "HEAD"],
        )
        .expect("abbrev"),
    )
    .expect("utf8");
    assert!(out.trim() == "fresh", "got {out:?}");
    let err = run(verbs_branch::switch, &mut ctx, &["--conflict", "merge"]).expect_err("conflict");
    assert!(err.to_string().contains("--merge"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_checkout_orphan_source_and_stages() {
    let (root, env) = seeded_repo("wavej-checkout", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["--orphan", "fresh2"]).expect("orphan");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("back");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(
        verbs_branch::checkout,
        &mut ctx,
        &["--source", "HEAD", "--", "f.txt"],
    )
    .expect("source");
    let err = run(verbs_branch::checkout, &mut ctx, &["-p", "--", "f.txt"]).expect_err("patch");
    assert!(err.to_string().contains("interactive"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_reset_keep_and_intent() {
    let (root, env) = seeded_repo("wavej-reset", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::reset, &mut ctx, &["--keep", "HEAD"]).expect("keep");
    run(verbs_branch::reset, &mut ctx, &["-N", "--", "f.txt"]).expect("intent");
    let err = run(verbs_branch::reset, &mut ctx, &["--merge", "HEAD"]).expect_err("merge");
    assert!(err.to_string().contains("merge lane"), "got {err:?}");
    let err = run(verbs_branch::reset, &mut ctx, &["-p"]).expect_err("patch");
    assert!(err.to_string().contains("interactive"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
// ---------------------------------------------------------------------------
// Wave J (DiffFlags): diff/show flag parity -- each flag must alter bytes,
// selected pairs, file output, or status, or fail loudly.
// ---------------------------------------------------------------------------

#[test]
fn wave_j_diff_word_plain_marks_words() {
    let (root, env) = seeded_repo("wavej-diff-word", "f.txt", b"alpha beta gamma\nline2\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"alpha beta DELTA\nline2\n").expect("modify");
    let out = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--word-diff=plain"]).expect("word"),
    )
    .expect("utf8");
    assert!(out.contains("alpha beta [-gamma-]{+DELTA+}"), "got {out:?}");
    assert!(out.contains("line2"), "got {out:?}");
    let plain =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &[]).expect("plain")).expect("utf8");
    assert!(!plain.contains("[-"), "got {plain:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_word_porcelain_runs() {
    let (root, env) = seeded_repo("wavej-diff-porc", "f.txt", b"alpha beta gamma\nline2\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"alpha beta DELTA\nline2\n").expect("modify");
    let out = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--word-diff=porcelain"]).expect("porcelain"),
    )
    .expect("utf8");
    assert!(out.contains(" alpha beta \n"), "got {out:?}");
    assert!(out.contains("-gamma\n+DELTA\n~\n"), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_word_none_and_regex() {
    let (root, env) = seeded_repo("wavej-diff-wordnone", "f.txt", b"alpha beta gamma\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"alpha beta DELTA\n").expect("modify");
    let plain = run(verbs_history::diff, &mut ctx, &[]).expect("plain");
    let none = run(verbs_history::diff, &mut ctx, &["--word-diff=none"]).expect("none");
    assert_eq!(none, plain);
    let custom = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--word-diff", "--word-diff-regex=\\w+"],
        )
        .expect("regex"),
    )
    .expect("utf8");
    assert!(custom.contains("[-gamma-]{+DELTA+}"), "got {custom:?}");
    let err = run(
        verbs_history::diff,
        &mut ctx,
        &["--word-diff", "--word-diff-regex=([)"],
    )
    .expect_err("bad regex");
    assert!(
        err.to_string().contains("bad --word-diff-regex"),
        "got {err:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_color_stays_uncolored() {
    let (root, env) = seeded_repo("wavej-diff-color", "f.txt", b"alpha beta gamma\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"alpha beta DELTA\n").expect("modify");
    let plain = run(verbs_history::diff, &mut ctx, &[]).expect("plain");
    for flag in ["--color", "--color=auto", "--no-color"] {
        let out = run(verbs_history::diff, &mut ctx, &[flag]).expect(flag);
        assert_eq!(out, plain, "flag {flag}");
        assert!(
            !String::from_utf8_lossy(&out).contains('\x1b'),
            "flag {flag}"
        );
    }
    let words = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--color-words"]).expect("color-words"),
    )
    .expect("utf8");
    assert!(words.contains("[-gamma-]{+DELTA+}"), "got {words:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_named_gaps_fail_loudly() {
    let (root, env) = seeded_repo("wavej-diff-gaps", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    for flag in [
        "--minimal",
        "--patience",
        "--histogram",
        "-W",
        "--function-context",
        "--binary",
        "--exit-code",
        "--color-moved",
    ] {
        let err = run(verbs_history::diff, &mut ctx, &[flag]).expect_err(flag);
        assert!(
            err.to_string().contains("not supported"),
            "flag {flag}: got {err:?}"
        );
    }
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_find_copies_pairs_additions() {
    let (root, env) = seeded_repo(
        "wavej-diff-copies",
        "f.txt",
        b"alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n",
    );
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join("f.txt"),
        b"alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\nseventh\n",
    )
    .expect("modify");
    std::fs::write(
        root.join("cp.txt"),
        b"alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n",
    )
    .expect("copy");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add f");
    run(verbs_stage::add, &mut ctx, &["cp.txt"]).expect("add cp");
    let plain = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--cached", "--name-status"],
        )
        .expect("plain"),
    )
    .expect("utf8");
    assert!(plain.contains("A\tcp.txt"), "got {plain:?}");
    let out = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--cached", "-C", "--name-status"],
        )
        .expect("copies"),
    )
    .expect("utf8");
    assert!(out.contains("C100\tf.txt\tcp.txt"), "got {out:?}");
    // No pathspec: the oracle pairs copies before filtering, so scoping to
    // the copy alone would hide its source the same way.
    let patch =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &["--cached", "-C"]).expect("patch"))
            .expect("utf8");
    assert!(patch.contains("copy from f.txt"), "got {patch:?}");
    assert!(patch.contains("copy to cp.txt"), "got {patch:?}");
    let off = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--cached", "-C0", "--name-status"],
        )
        .expect("c0"),
    )
    .expect("utf8");
    assert!(off.contains("A\tcp.txt"), "got {off:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_filter_selects_classes() {
    let (root, env) = seeded_repo("wavej-diff-filter", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    std::fs::write(root.join("n.txt"), b"new\n").expect("add file");
    let added = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--name-status", "--diff-filter=A"],
        )
        .expect("filter A"),
    )
    .expect("utf8");
    assert!(added.contains("A\tn.txt"), "got {added:?}");
    assert!(!added.contains("f.txt"), "got {added:?}");
    let modified = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--name-status", "--diff-filter=M"],
        )
        .expect("filter M"),
    )
    .expect("utf8");
    assert!(modified.contains("M\tf.txt"), "got {modified:?}");
    assert!(!modified.contains("n.txt"), "got {modified:?}");
    let excluded = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--name-status", "--diff-filter=a"],
        )
        .expect("filter a"),
    )
    .expect("utf8");
    assert!(excluded.contains("M\tf.txt"), "got {excluded:?}");
    assert!(!excluded.contains("n.txt"), "got {excluded:?}");
    let err = run(verbs_history::diff, &mut ctx, &["--diff-filter=Z"]).expect_err("bad filter");
    assert!(err.to_string().contains("unknown letter"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_text_diffs_binaries() {
    let (root, env) = seeded_repo("wavej-diff-text", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("b.dat"), b"a\x00b\n").expect("binary");
    let out =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &["--", "b.dat"]).expect("diff"))
            .expect("utf8");
    assert!(out.contains("Binary files"), "got {out:?}");
    let text = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--text", "--", "b.dat"]).expect("text"),
    )
    .expect("utf8");
    assert!(text.contains("@@"), "got {text:?}");
    assert!(!text.contains("Binary files"), "got {text:?}");
    let no_text = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--no-text", "--", "b.dat"]).expect("no-text"),
    )
    .expect("utf8");
    assert!(no_text.contains("Binary files"), "got {no_text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_ws_folds_silence_whitespace() {
    let (root, env) = seeded_repo("wavej-diff-ws", "f.txt", b"one two\nthree\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"one  two\nthree\n").expect("spaces");
    let plain = run(verbs_history::diff, &mut ctx, &[]).expect("plain");
    assert!(!plain.is_empty(), "whitespace change must show by default");
    for flag in ["-b", "--ignore-space-change", "-w", "--ignore-all-space"] {
        let out = run(verbs_history::diff, &mut ctx, &[flag]).expect(flag);
        assert!(out.is_empty(), "flag {flag}: got {out:?}");
    }
    std::fs::write(root.join("f.txt"), b"one two \nthree\n").expect("eol space");
    let eol = run(verbs_history::diff, &mut ctx, &["--ignore-space-at-eol"]).expect("eol");
    assert!(eol.is_empty(), "got {eol:?}");
    std::fs::write(root.join("f.txt"), b"one two\n\nthree\n").expect("blank");
    let blank = run(verbs_history::diff, &mut ctx, &["--ignore-blank-lines"]).expect("blank");
    assert!(blank.is_empty(), "got {blank:?}");
    std::fs::write(root.join("f.txt"), b"one  TWO\nthree\n").expect("real");
    let kept = run(verbs_history::diff, &mut ctx, &["-b"]).expect("kept");
    assert!(!kept.is_empty(), "real change must survive -b");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_inter_hunk_fuses_close_hunks() {
    let mut body = Vec::new();
    for i in 1..=30 {
        body.extend_from_slice(format!("L{i:02}\n").as_bytes());
    }
    let (root, env) = seeded_repo("wavej-diff-inter", "h.txt", &body);
    let mut ctx = repo_ctx(&root, env);
    let mut modified = Vec::new();
    for i in 1..=30 {
        match i {
            6 => modified.extend_from_slice(b"CHANGED06\n"),
            13 => modified.extend_from_slice(b"CHANGED13\n"),
            26 => modified.extend_from_slice(b"CHANGED26\n"),
            _ => modified.extend_from_slice(format!("L{i:02}\n").as_bytes()),
        }
    }
    std::fs::write(root.join("h.txt"), &modified).expect("modify");
    let count = |out: &[u8]| {
        String::from_utf8_lossy(out)
            .lines()
            .filter(|line| line.starts_with("@@"))
            .count()
    };
    let split = run(verbs_history::diff, &mut ctx, &["-U1", "--", "h.txt"]).expect("split");
    assert_eq!(
        count(&split),
        3,
        "got {:?}",
        String::from_utf8_lossy(&split)
    );
    let fused = run(
        verbs_history::diff,
        &mut ctx,
        &["-U1", "--inter-hunk-context=20", "--", "h.txt"],
    )
    .expect("fused");
    assert_eq!(
        count(&fused),
        1,
        "got {:?}",
        String::from_utf8_lossy(&fused)
    );
    let err = run(
        verbs_history::diff,
        &mut ctx,
        &["--inter-hunk-context=bogus"],
    )
    .expect_err("bad inter");
    assert!(
        err.to_string().contains("bad --inter-hunk-context"),
        "got {err:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_prefixes_rewrite_every_line() {
    let (root, env) = seeded_repo("wavej-diff-prefix", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    let out = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--src-prefix=SRC/", "--dst-prefix=DST/"],
        )
        .expect("prefix"),
    )
    .expect("utf8");
    assert!(
        out.contains("diff --git SRC/f.txt DST/f.txt"),
        "got {out:?}"
    );
    assert!(out.contains("--- SRC/f.txt"), "got {out:?}");
    assert!(out.contains("+++ DST/f.txt"), "got {out:?}");
    let lined = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--line-prefix=>>"]).expect("line-prefix"),
    )
    .expect("utf8");
    assert!(!lined.is_empty());
    assert!(
        lined.lines().all(|line| line.starts_with(">>")),
        "got {lined:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_machine_sections() {
    let (root, env) = seeded_repo("wavej-diff-machine", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    let raw = String::from_utf8(run(verbs_history::diff, &mut ctx, &["--raw"]).expect("raw"))
        .expect("utf8");
    assert!(raw.starts_with(":100644 100644 "), "got {raw:?}");
    assert!(raw.contains(" M\tf.txt\n"), "got {raw:?}");
    let numstat =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &["--numstat"]).expect("numstat"))
            .expect("utf8");
    assert_eq!(numstat, "1\t1\tf.txt\n");
    let short =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &["--shortstat"]).expect("shortstat"))
            .expect("utf8");
    assert!(
        short.contains("1 file changed, 1 insertion(+), 1 deletion(-)"),
        "got {short:?}"
    );
    std::fs::write(root.join("n2.txt"), b"new\n").expect("new file");
    let summary =
        String::from_utf8(run(verbs_history::diff, &mut ctx, &["--summary"]).expect("summary"))
            .expect("utf8");
    assert!(
        summary.contains(" create mode 100644 n2.txt"),
        "got {summary:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_output_writes_file() {
    let (root, env) = seeded_repo("wavej-diff-output", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    let stdout = run(
        verbs_history::diff,
        &mut ctx,
        &["--stat", "--output=rel.diff"],
    )
    .expect("output");
    assert!(stdout.is_empty(), "got {stdout:?}");
    let file = std::fs::read(root.join("rel.diff")).expect("read back");
    assert!(
        String::from_utf8_lossy(&file).contains("file changed"),
        "got {file:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_relative_limits_to_prefix() {
    let (root, env) = seeded_repo("wavej-diff-relative", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    std::fs::create_dir(root.join("sub")).expect("mkdir");
    std::fs::write(root.join("sub/s.txt"), b"s\n").expect("sub file");
    let out = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--relative=sub"]).expect("relative"),
    )
    .expect("utf8");
    assert!(out.contains("s.txt"), "got {out:?}");
    assert!(!out.contains("sub/s.txt"), "got {out:?}");
    assert!(!out.contains("f.txt"), "got {out:?}");
    let empty = run(verbs_history::diff, &mut ctx, &["--relative=nope"]).expect("nope");
    assert!(empty.is_empty(), "got {empty:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_no_index_compares_files() {
    let (root, env) = seeded_repo("wavej-diff-noindex", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("a.txt"), b"a1\na2\n").expect("a");
    std::fs::write(root.join("b.txt"), b"a1\nb2\n").expect("b");
    let out = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--no-index", "a.txt", "b.txt"],
        )
        .expect("no-index"),
    )
    .expect("utf8");
    assert!(out.contains("diff --git a/a.txt b/b.txt"), "got {out:?}");
    assert!(out.contains("-a2\n+b2"), "got {out:?}");
    let status = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--no-index", "--name-status", "a.txt", "b.txt"],
        )
        .expect("name-status"),
    )
    .expect("utf8");
    assert_eq!(status, "M\ta.txt\n");
    let same = run(
        verbs_history::diff,
        &mut ctx,
        &["--no-index", "a.txt", "a.txt"],
    )
    .expect("identical");
    assert!(same.is_empty(), "got {same:?}");
    let err = run(
        verbs_history::diff,
        &mut ctx,
        &["--no-index", "a.txt", "missing.txt"],
    )
    .expect_err("missing");
    assert!(err.to_string().contains("missing.txt"), "got {err:?}");
    let err = run(verbs_history::diff, &mut ctx, &["--no-index", "a.txt"]).expect_err("arity");
    assert!(err.to_string().contains("usage"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_quiet_signals_through_status() {
    let (root, env) = seeded_repo("wavej-diff-quiet", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    let err = run(verbs_history::diff, &mut ctx, &["--quiet"]).expect_err("dirty");
    assert!(err.to_string().contains("differences found"), "got {err:?}");
    lane_commit(&mut ctx, &root, "f.txt", b"two\n", "second");
    let clean = run(verbs_history::diff, &mut ctx, &["--quiet"]).expect("clean");
    assert!(clean.is_empty(), "got {clean:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_show_machine_sections_and_output() {
    let (root, env) = seeded_repo("wavej-show-sections", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    lane_commit(&mut ctx, &root, "f.txt", b"alpha beta gamma\n", "second");
    let raw =
        String::from_utf8(run(verbs_history::show, &mut ctx, &["HEAD", "--raw"]).expect("raw"))
            .expect("utf8");
    assert!(raw.contains(" M\tf.txt\n"), "got {raw:?}");
    assert!(raw.contains("second"), "got {raw:?}");
    let stdout = run(verbs_history::show, &mut ctx, &["HEAD", "--output=sh.out"]).expect("output");
    assert!(stdout.is_empty(), "got {stdout:?}");
    let file = std::fs::read(root.join("sh.out")).expect("read back");
    assert!(
        String::from_utf8_lossy(&file).contains("diff --git"),
        "got {file:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_no_patch_suppresses_patch() {
    let (root, env) = seeded_repo("wavej-diff-nopatch", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    let stat = run(verbs_history::diff, &mut ctx, &["--stat"]).expect("stat");
    let suppressed =
        run(verbs_history::diff, &mut ctx, &["--stat", "--no-patch"]).expect("no-patch");
    assert_eq!(suppressed, stat);
    let empty = run(verbs_history::diff, &mut ctx, &["--no-patch"]).expect("empty");
    assert!(empty.is_empty(), "got {empty:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_diff_raw_rename_old_first() {
    let mut body = Vec::new();
    for i in 1..=10 {
        body.extend_from_slice(format!("L{i:02}\n").as_bytes());
    }
    let (root, env) = seeded_repo("wavej-diff-rawrename", "f.txt", &body);
    let mut ctx = repo_ctx(&root, env);
    // Rename with one changed line: similarity 90, exercising the padded
    // `R090` status and the old-first path order.
    let mut moved = Vec::new();
    for i in 1..=10 {
        if i == 5 {
            moved.extend_from_slice(b"CHANGED05\n");
        } else {
            moved.extend_from_slice(format!("L{i:02}\n").as_bytes());
        }
    }
    std::fs::write(root.join("r.txt"), &moved).expect("copy");
    run(verbs_stage::rm, &mut ctx, &["f.txt"]).expect("rm");
    run(verbs_stage::add, &mut ctx, &["r.txt"]).expect("add");
    let raw = String::from_utf8(
        run(verbs_history::diff, &mut ctx, &["--cached", "-M", "--raw"]).expect("raw"),
    )
    .expect("utf8");
    assert!(raw.contains(" R090\tf.txt\tr.txt\n"), "got {raw:?}");
    let status = String::from_utf8(
        run(
            verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--name-status"],
        )
        .expect("status"),
    )
    .expect("utf8");
    assert!(status.contains("R090\tf.txt\tr.txt\n"), "got {status:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
/// Pins author/committer dates for one test context. Rapid successive
/// commits otherwise share a wall-clock second, and an amended commit
/// identical in every byte to its tip trips the store's
/// absent-expectation CAS flakily at second boundaries; distinct stamps
/// keep each commit's bytes distinct by construction.
fn wave_j_stamp(ctx: &mut Ctx, epoch: i64) {
    let value = format!("{epoch} +0000");
    ctx.env
        .vars
        .insert("GIT_AUTHOR_DATE".to_owned(), value.clone());
    ctx.env.vars.insert("GIT_COMMITTER_DATE".to_owned(), value);
}

/// Reads the message of the current `HEAD` commit.
fn wave_j_head_message(ctx: &mut Ctx) -> String {
    let store = ctx.store().expect("store");
    let tip = super::state::head_oid(store).expect("head");
    let record = super::state::commit_record(store, tip).expect("record");
    String::from_utf8_lossy(record.message()).into_owned()
}

#[test]
fn wave_j_commit_file_signoff_cleanup_template() {
    let (root, env) = seeded_repo("wavej-commit-file", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"one\ntwo\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let msg = root.join("msg.txt");
    std::fs::write(&msg, b"# comment\nreal subject\n\nbody text\n").expect("msg");
    let msg_arg = msg.to_str().expect("utf8").to_owned();
    run(verbs_history::commit, &mut ctx, &[&"-F", &msg_arg, &"-s"]).expect("commit -F -s");
    assert_eq!(
        wave_j_head_message(&mut ctx),
        "# comment\nreal subject\n\nbody text\n\nSigned-off-by: Ada <ada@example.invalid>\n"
    );
    // Without an editor the default cleanup keeps `#` comments ...
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "# gone"]).expect("kept comment");
    assert_eq!(wave_j_head_message(&mut ctx), "# gone\n");
    // ... while an explicit `--cleanup=strip` drops them ...
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\nfour\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "# stripped", "-m", "real", "--cleanup=strip"],
    )
    .expect("strip");
    assert_eq!(wave_j_head_message(&mut ctx), "real\n");
    // ... but verbatim keeps it, and templates seed the message as-is.
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\nfour\nfive\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "# keep me", "--cleanup=verbatim"],
    )
    .expect("verbatim");
    assert_eq!(wave_j_head_message(&mut ctx), "# keep me\n");
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\nfour\nfive\nsix\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let tpl = root.join("tpl.txt");
    std::fs::write(&tpl, b"templated\n").expect("template");
    let tpl_arg = tpl.to_str().expect("utf8").to_owned();
    run(verbs_history::commit, &mut ctx, &[&"--template", &tpl_arg]).expect("template");
    assert_eq!(wave_j_head_message(&mut ctx), "templated\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_commit_squash_fixup_amend() {
    let (root, env) = seeded_repo("wavej-squash", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let base = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev"))
        .expect("utf8")
        .trim()
        .to_owned();
    std::fs::write(root.join("f.txt"), b"one\ntwo\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    wave_j_stamp(&mut ctx, 1700000001);
    run(verbs_history::commit, &mut ctx, &[&"--fixup", &base]).expect("fixup");
    assert_eq!(wave_j_head_message(&mut ctx), "fixup! seed\n");
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    wave_j_stamp(&mut ctx, 1700000002);
    run(
        verbs_history::commit,
        &mut ctx,
        &[&"--squash", &base, &"-m", &"extra body"],
    )
    .expect("squash -m");
    assert_eq!(
        wave_j_head_message(&mut ctx),
        "squash! seed\n\nextra body\n"
    );
    // A sourceless amend reuses the `HEAD` message like the oracle's editor
    // seed; `--reset-author` renews authorship on the same path.
    wave_j_stamp(&mut ctx, 1700000003);
    run(verbs_history::commit, &mut ctx, &["--amend"]).expect("amend");
    assert_eq!(
        wave_j_head_message(&mut ctx),
        "squash! seed\n\nextra body\n"
    );
    wave_j_stamp(&mut ctx, 1700000004);
    run(
        verbs_history::commit,
        &mut ctx,
        &["--amend", "--reset-author"],
    )
    .expect("reset-author");
    assert_eq!(
        wave_j_head_message(&mut ctx),
        "squash! seed\n\nextra body\n"
    );
    // A byte-identical amend (same stamp, no changes) reuses the tip
    // instead of tripping the store's absent-expectation CAS.
    let tip = super::state::head_oid(ctx.store().expect("store")).expect("head");
    wave_j_stamp(&mut ctx, 1700000004);
    run(verbs_history::commit, &mut ctx, &["--amend"]).expect("no-op amend");
    assert_eq!(
        super::state::head_oid(ctx.store().expect("store")).expect("head"),
        tip
    );
    assert_eq!(
        wave_j_head_message(&mut ctx),
        "squash! seed\n\nextra body\n"
    );
    // Both `amend:` spellings lift the empty-tree refusal on a clean tree;
    // `reword:` shares the `amend!` subject line, never `reword!`.
    let amend_arg = format!("--fixup=amend:{base}");
    wave_j_stamp(&mut ctx, 1700000005);
    run(verbs_history::commit, &mut ctx, &[amend_arg.as_str()]).expect("empty amend fixup");
    assert_eq!(wave_j_head_message(&mut ctx), "amend! seed\n\nseed\n");
    assert_eq!(head_parent_count(&mut ctx), 1);
    let reword_arg = format!("--fixup=reword:{base}");
    wave_j_stamp(&mut ctx, 1700000006);
    run(verbs_history::commit, &mut ctx, &[reword_arg.as_str()]).expect("empty reword fixup");
    assert_eq!(wave_j_head_message(&mut ctx), "amend! seed\n\nseed\n");
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &[reword_arg.as_str(), "-m", "x"],
    )
    .expect_err("fixup reword -m");
    assert!(err.to_string().contains("cannot be used together"), "{err}");
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &[reword_arg.as_str(), "-a"],
    )
    .expect_err("fixup reword -a");
    assert!(err.to_string().contains("cannot be used together"), "{err}");
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\nfour\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let fixup_arg = format!("--fixup=amend:{base}");
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &[fixup_arg.as_str(), "-m", "x"],
    )
    .expect_err("fixup amend -m");
    assert!(err.to_string().contains("cannot be used together"), "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_commit_rejections() {
    let (root, env) = seeded_repo("wavej-commit-reject", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"one\ntwo\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let msg = root.join("msg.txt");
    std::fs::write(&msg, b"file body\n").expect("msg");
    let msg_arg = msg.to_str().expect("utf8").to_owned();
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &[&"-m", &"x", &"-F", &msg_arg],
    )
    .expect_err("-m -F");
    assert!(err.to_string().contains("cannot be combined"), "{err}");
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "x", "--reset-author"],
    )
    .expect_err("reset-author");
    assert!(
        err.to_string().contains("only with -C, -c or --amend"),
        "{err}"
    );
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &[
            "-m",
            "x",
            "--reset-author",
            "--author=Bo <bo@example.invalid>",
        ],
    )
    .expect_err("reset-author author");
    assert!(err.to_string().contains("cannot be used together"), "{err}");
    let err = run(verbs_history::commit, &mut ctx, &["--edit"]).expect_err("--edit");
    assert!(err.to_string().contains("interactive editor"), "{err}");
    // `--edit` with a message source is a no-op editor, not an error.
    run(verbs_history::commit, &mut ctx, &["-m", "edited", "--edit"]).expect("edit -m");
    assert_eq!(wave_j_head_message(&mut ctx), "edited\n");
    let err = run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "x", "--cleanup=bogus"],
    )
    .expect_err("cleanup");
    assert!(err.to_string().contains("bad --cleanup"), "{err}");
    std::fs::write(root.join("f.txt"), b"one\ntwo\nthree\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let err = run(verbs_history::commit, &mut ctx, &["-m", ""]).expect_err("empty");
    assert!(err.to_string().contains("empty commit message"), "{err}");
    // A signoff-only message still counts as empty, like the oracle.
    let blank = root.join("blank.txt");
    std::fs::write(&blank, b"\n").expect("blank");
    let blank_arg = blank.to_str().expect("utf8").to_owned();
    let err = run(verbs_history::commit, &mut ctx, &[&"-F", &blank_arg, &"-s"])
        .expect_err("signoff-only");
    assert!(err.to_string().contains("empty commit message"), "{err}");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "", "--allow-empty-message"],
    )
    .expect("allow-empty-message");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_status_porcelain_v2_null() {
    let (root, env) = seeded_repo("wavej-v2", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"one\ntwo\n").expect("modify");
    std::fs::write(root.join("new.txt"), b"new\n").expect("untracked");
    let out = run(
        verbs_stage::status,
        &mut ctx,
        &["--porcelain=v2", "--branch"],
    )
    .expect("v2");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("# branch.head main\n"), "head: {text}");
    assert!(text.contains("# branch.oid "), "oid: {text}");
    assert!(!text.contains("# branch.upstream"), "no upstream: {text}");
    assert!(
        text.contains("1 .M N... 100644 100644 100644 "),
        "ordinary: {text}"
    );
    assert!(text.contains(" f.txt\n"), "path: {text}");
    assert!(text.contains("? new.txt\n"), "untracked: {text}");
    let out = run(
        verbs_stage::status,
        &mut ctx,
        &["--porcelain=v1", "--branch"],
    )
    .expect("v1");
    assert!(
        String::from_utf8_lossy(&out).contains("## main\n"),
        "v1 branch"
    );
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "--null"]).expect("null");
    assert!(out.contains(&b'\0'), "NUL terminated");
    assert!(!out.contains(&b'\n'), "no newlines: {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_status_untracked_ignored() {
    let (root, env) = seeded_repo("wavej-untracked", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::create_dir_all(root.join("sub")).expect("mkdir");
    std::fs::write(root.join("sub").join("a.txt"), b"a\n").expect("a");
    std::fs::write(root.join("sub").join("b.txt"), b"b\n").expect("b");
    std::fs::write(root.join("top.txt"), b"top\n").expect("top");
    std::fs::write(root.join(".rukignore"), b"*.log\n").expect("ignore");
    std::fs::write(root.join("debug.log"), b"log\n").expect("log");
    // Default `normal` collapses the clean directory and hides ignored files.
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain"]).expect("normal");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("?? sub/\n"), "collapsed: {text}");
    assert!(!text.contains("sub/a.txt"), "not listed: {text}");
    assert!(text.contains("?? top.txt\n"), "top: {text}");
    assert!(!text.contains("debug.log"), "hidden: {text}");
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "--ignored"]).expect("ignored");
    assert!(
        String::from_utf8_lossy(&out).contains("!! debug.log\n"),
        "ignored shown"
    );
    // A bare `-u` carries the oracle `all` default, not the absent-flag
    // `normal` collapse.
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "-u"]).expect("bare u");
    assert!(
        String::from_utf8_lossy(&out).contains("?? sub/a.txt\n"),
        "bare -u lists"
    );
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "-uall"]).expect("all");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("?? sub/a.txt\n"), "all lists: {text}");
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "-uno"]).expect("no");
    assert!(
        !String::from_utf8_lossy(&out).contains("??"),
        "hidden untracked"
    );
    let err =
        run(verbs_stage::status, &mut ctx, &["--porcelain", "-ubogus"]).expect_err("bad mode");
    assert!(err.to_string().contains("bad --untracked-files"), "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_status_ahead_behind_stash() {
    let (root, env) = seeded_repo("wavej-ab", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::checkout, &mut ctx, &["-b", "side"]).expect("checkout -b");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("checkout main");
    run(
        verbs_branch::branch,
        &mut ctx,
        &["--set-upstream-to", "side"],
    )
    .expect("set upstream");
    lane_commit(&mut ctx, &root, "g.txt", b"two\n", "ahead work");
    let out = run(verbs_stage::status, &mut ctx, &[]).expect("long");
    assert!(
        String::from_utf8_lossy(&out).contains("Your branch is ahead of 'side' by 1 commit.\n"),
        "tracking: {}",
        String::from_utf8_lossy(&out)
    );
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "--branch"]).expect("v1 branch");
    assert!(
        String::from_utf8_lossy(&out).contains("## main...side [ahead 1]\n"),
        "v1 tracking"
    );
    let out = run(
        verbs_stage::status,
        &mut ctx,
        &["--porcelain=v2", "--branch"],
    )
    .expect("v2 upstream");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.contains("# branch.upstream side\n"),
        "upstream: {text}"
    );
    assert!(text.contains("# branch.ab +1 -0\n"), "ab: {text}");
    let out = run(
        verbs_stage::status,
        &mut ctx,
        &["--porcelain", "--branch", "--no-ahead-behind"],
    )
    .expect("no ab");
    assert!(
        String::from_utf8_lossy(&out).contains("## main...side\n"),
        "suppressed"
    );
    std::fs::write(root.join("f.txt"), b"one\nwip\n").expect("modify");
    run(verbs_branch::stash, &mut ctx, &["push", "-m", "wip"]).expect("stash");
    let out = run(verbs_stage::status, &mut ctx, &["--show-stash"]).expect("stash");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.contains("nothing to commit, working tree clean\n"),
        "clean: {text}"
    );
    assert!(
        text.contains("Your stash currently has 1 entry\n"),
        "stash: {text}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_status_verbose_column_renames() {
    let (root, env) = seeded_repo("wavej-verbose", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let err = run(verbs_stage::status, &mut ctx, &["--column"]).expect_err("column");
    assert!(err.to_string().contains("--column"), "{err}");
    std::fs::write(root.join("f.txt"), b"one\ntwo\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let out = run(verbs_stage::status, &mut ctx, &["-v"]).expect("verbose");
    assert!(
        String::from_utf8_lossy(&out).contains("diff --git a/f.txt b/f.txt\n"),
        "staged diff"
    );
    // Identical-blob staged moves pair; `--no-renames` keeps add+delete.
    // The copy must equal the HEAD blob: exact pairing matches index
    // additions against HEAD deletions by oid.
    std::fs::write(root.join("g.txt"), b"one\n").expect("copy");
    run(verbs_stage::add, &mut ctx, &["g.txt"]).expect("add g");
    run(verbs_stage::rm, &mut ctx, &["f.txt"]).expect("rm f");
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain"]).expect("rename");
    assert!(
        String::from_utf8_lossy(&out).contains("R  f.txt -> g.txt\n"),
        "paired: {}",
        String::from_utf8_lossy(&out)
    );
    let out = run(
        verbs_stage::status,
        &mut ctx,
        &["--porcelain", "--no-renames"],
    )
    .expect("no renames");
    assert!(
        !String::from_utf8_lossy(&out).contains("R  "),
        "unpaired: {}",
        String::from_utf8_lossy(&out)
    );
    // Under `-z` the rename is `XY new\0old\0`, never `old -> new` text.
    let out = run(verbs_stage::status, &mut ctx, &["--porcelain", "-z"]).expect("null rename");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("R  g.txt\0f.txt\0"), "nul rename: {text:?}");
    // `-vv` heads the staged diff; the grouped spelling parses as two hits.
    let out = run(verbs_stage::status, &mut ctx, &["-vv"]).expect("grouped vv");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(
        text.contains("Changes to be committed:\n"),
        "vv header: {text}"
    );
    // The verbose diff runs without `-M`, so the staged rename renders as
    // separate deletion/addition diffs, never a paired header.
    assert!(
        text.contains("diff --git a/g.txt b/g.txt\n"),
        "vv diff: {text}"
    );
    assert!(
        !text.contains("diff --git a/f.txt b/g.txt\n"),
        "no pair: {text}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_switch_merge_guard() {
    let (root, env) = seeded_repo("wavej-mergeguard", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("g.txt"), b"same\n").expect("same file");
    run(verbs_stage::add, &mut ctx, &["g.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "add g"]).expect("commit");
    run(verbs_branch::branch, &mut ctx, &["side"]).expect("branch");
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    std::fs::write(root.join("f.txt"), b"side\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "side work"]).expect("commit");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("back");
    std::fs::write(root.join("f.txt"), b"dirty\n").expect("dirty");
    std::fs::write(root.join("g.txt"), b"dirty2\n").expect("unrelated dirty");
    let err = run(verbs_branch::switch, &mut ctx, &["-m", "side"]).expect_err("merge refuses");
    assert!(err.to_string().contains("overwritten"), "got {err:?}");
    run(verbs_branch::checkout, &mut ctx, &["--", "f.txt"]).expect("restore f");
    run(verbs_branch::switch, &mut ctx, &["-m", "side"]).expect("merge clean");
    // Unrelated edits ride across the merging switch untouched.
    assert_eq!(
        std::fs::read(root.join("g.txt")).expect("read g"),
        b"dirty2\n"
    );
    assert_eq!(
        std::fs::read(root.join("f.txt")).expect("read f"),
        b"side\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_reset_intent_full_tree() {
    let (root, env) = seeded_repo("wavej-intentfull", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("new.txt"), b"new\n").expect("new file");
    run(verbs_stage::add, &mut ctx, &["new.txt"]).expect("add");
    run(verbs_branch::reset, &mut ctx, &["-N", "HEAD"]).expect("intent reset");
    let out = String::from_utf8(
        run(verbs_stage::ls_files, &mut ctx, &["-s"]).expect("ls-files"),
    )
    .expect("utf8");
    assert!(out.contains("new.txt"), "intent row kept: {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_prune_drops_orphan_and_honors_expire() {
    let (root, env, orphan) = orphaned_side_commit("hk-prune");
    let mut ctx = repo_ctx(&root, env);
    // Dry run lists without deleting.
    let dry = String::from_utf8_lossy(
        &run(verbs_maintenance::prune, &mut ctx, &["--dry-run"]).expect("dry run"),
    )
    .into_owned();
    assert!(dry.contains(&orphan), "dry run lists orphan: {dry}");
    run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).expect("orphan kept");
    // Verbose prune deletes and reports the oid.
    let out = String::from_utf8_lossy(
        &run(verbs_maintenance::prune, &mut ctx, &["--verbose"]).expect("prune"),
    )
    .into_owned();
    assert!(out.contains(&orphan), "verbose lists pruned oid: {out}");
    assert!(
        run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).is_err(),
        "orphan pruned"
    );
    run(verbs_objects::cat_file, &mut ctx, &["-e", "HEAD"]).expect("HEAD kept");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_prune_expire_never_keeps_and_dates_refuse() {
    let (root, env, orphan) = orphaned_side_commit("hk-prune-expire");
    let mut ctx = repo_ctx(&root, env);
    let out = run(verbs_maintenance::prune, &mut ctx, &["--expire=never"]).expect("never");
    assert!(out.is_empty(), "never prunes nothing quietly");
    run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).expect("orphan kept");
    let err = run(verbs_maintenance::prune, &mut ctx, &["--expire=2.weeks.ago"])
        .expect_err("dated expire");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_pack_refs_keeps_refs_resolving() {
    let (root, env) = seeded_repo("hk-packrefs", "a.txt", b"alpha\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::branch, &mut ctx, &["side"]).expect("branch");
    let out = String::from_utf8_lossy(
        &run(verbs_maintenance::pack_refs, &mut ctx, &["--all"]).expect("pack-refs"),
    )
    .into_owned();
    assert!(out.contains("Packed 2 refs"), "got {out}");
    let head = String::from_utf8_lossy(
        &run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .trim()
    .to_owned();
    assert!(!head.is_empty(), "HEAD resolves after pack-refs");
    run(verbs_history::rev_parse, &mut ctx, &["side"]).expect("side resolves");
    run(verbs_maintenance::pack_refs, &mut ctx, &["--all", "--prune"]).expect("prune accepted");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_repack_prunes_compacts_and_refreshes_server_info() {
    let (root, env, orphan) = orphaned_side_commit("hk-repack");
    let mut ctx = repo_ctx(&root, env);
    assert!(
        !root.join(".ruk/info/refs").exists(),
        "no server info before repack"
    );
    let out = String::from_utf8_lossy(
        &run(verbs_maintenance::repack, &mut ctx, &["-a", "-d", "-n"]).expect("repack -n"),
    )
    .into_owned();
    assert!(out.contains("Pruned"), "prune phase reported: {out}");
    assert!(
        run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).is_err(),
        "orphan pruned"
    );
    run(verbs_objects::cat_file, &mut ctx, &["-e", "HEAD"]).expect("HEAD kept");
    assert!(
        !root.join(".ruk/info/refs").exists(),
        "-n skips the server-info refresh"
    );
    run(verbs_maintenance::repack, &mut ctx, &[]).expect("bare repack");
    assert!(root.join(".ruk/info/refs").exists(), "refresh wrote info/refs");
    let err =
        run(verbs_maintenance::repack, &mut ctx, &["-a", "--window=10"]).expect_err("window gap");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_maintenance_run_registry_and_tasks() {
    let (root, env) = seeded_repo("hk-maint", "a.txt", b"alpha\n");
    let mut ctx = repo_ctx(&root, env);
    // Default run covers gc plus pack-refs with visible reports.
    let out = String::from_utf8_lossy(
        &run(verbs_maintenance::maintenance, &mut ctx, &["run"]).expect("run"),
    )
    .into_owned();
    assert!(out.contains("Packed"), "pack-refs ran: {out}");
    // Registry rows round-trip through config.
    run(verbs_maintenance::maintenance, &mut ctx, &["register"]).expect("register");
    let registered = String::from_utf8_lossy(
        &run(verbs_repo::config, &mut ctx, &["maintenance.registered"]).expect("read registered"),
    )
    .into_owned();
    assert!(registered.contains("true"), "registered: {registered}");
    // Task list flips with stop/start.
    run(
        verbs_maintenance::maintenance,
        &mut ctx,
        &["stop", "--task=gc"],
    )
    .expect("stop gc");
    let list = String::from_utf8_lossy(
        &run(verbs_maintenance::maintenance, &mut ctx, &["task"]).expect("task list"),
    )
    .into_owned();
    assert!(list.contains("gc: disabled"), "stop recorded: {list}");
    assert!(list.contains("pack-refs: enabled"), "untouched task stays enabled: {list}");
    run(
        verbs_maintenance::maintenance,
        &mut ctx,
        &["start", "--task=gc"],
    )
    .expect("start gc");
    let list = String::from_utf8_lossy(
        &run(verbs_maintenance::maintenance, &mut ctx, &["task"]).expect("task list"),
    )
    .into_owned();
    assert!(list.contains("gc: enabled"), "start recorded: {list}");
    run(verbs_maintenance::maintenance, &mut ctx, &["unregister"]).expect("unregister");
    // Single-task runs and unknown tasks.
    run(verbs_maintenance::maintenance, &mut ctx, &["run", "--task=prefetch"])
        .expect("prefetch with no remotes");
    let err = run(
        verbs_maintenance::maintenance,
        &mut ctx,
        &["run", "--task=bogus"],
    )
    .expect_err("unknown task");
    assert_eq!(err.exit_code(), 1, "{err}");
    let err = run(verbs_maintenance::maintenance, &mut ctx, &[]).expect_err("no subcommand");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_maintenance_loose_objects_task_prunes() {
    let (root, env, orphan) = orphaned_side_commit("hk-loose");
    let mut ctx = repo_ctx(&root, env);
    let out = String::from_utf8_lossy(
        &run(
            verbs_maintenance::maintenance,
            &mut ctx,
            &["run", "--task=loose-objects"],
        )
        .expect("loose-objects"),
    )
    .into_owned();
    assert!(out.contains("Pruned"), "got {out}");
    assert!(
        run(verbs_objects::cat_file, &mut ctx, &["-e", &orphan]).is_err(),
        "orphan pruned"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_commit_graph_verify_list_and_named_gaps() {
    let (root, env) = seeded_repo("hk-cgraph", "a.txt", b"alpha\n");
    let mut ctx = repo_ctx(&root, env);
    let out = String::from_utf8_lossy(
        &run(verbs_maintenance::commit_graph, &mut ctx, &["verify"]).expect("verify"),
    )
    .into_owned();
    assert!(out.contains("Verified"), "got {out}");
    let head = String::from_utf8_lossy(
        &run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .trim()
    .to_owned();
    let list = String::from_utf8_lossy(
        &run(verbs_maintenance::commit_graph, &mut ctx, &["list"]).expect("list"),
    )
    .into_owned();
    assert!(list.contains(&head), "list covers HEAD: {list}");
    for subcommand in ["write", "read"] {
        let err = run(verbs_maintenance::commit_graph, &mut ctx, &[subcommand])
            .expect_err("named gap");
        assert_eq!(err.exit_code(), 1, "{subcommand}: {err}");
    }
    let err =
        run(verbs_maintenance::commit_graph, &mut ctx, &["bogus"]).expect_err("bad subcommand");
    assert_eq!(err.exit_code(), 1, "{err}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn housekeeping_update_server_info_writes_dumb_files() {
    let (root, env) = seeded_repo("hk-serverinfo", "a.txt", b"alpha\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_maintenance::update_server_info, &mut ctx, &[]).expect("update");
    let refs_body =
        std::fs::read_to_string(root.join(".ruk/info/refs")).expect("info/refs written");
    assert!(
        refs_body.contains("refs/heads/main"),
        "refs advertised: {refs_body}"
    );
    let packs_body = std::fs::read(root.join(".ruk/objects/info/packs")).expect("packs written");
    assert_eq!(packs_body, b"\n", "empty pack list body");
    // Idempotent without --force, rewrites with it.
    run(verbs_maintenance::update_server_info, &mut ctx, &[]).expect("rerun");
    run(verbs_maintenance::update_server_info, &mut ctx, &["--force"]).expect("force");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_capabilities() {
    let (root, env) = seeded_repo("wavek-helpercaps", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env: env.clone(),
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"capabilities\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out)
        .expect("capabilities");
    assert_eq!(
        out,
        b"connect\nimport\nexport\nrefspec refs/heads/*:refs/ruk/test/heads/*\nrefspec refs/tags/*:refs/ruk/test/tags/*\noption\nobject-format\n\n"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_list() {
    let (root, env) = seeded_repo("wavek-helperlist", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env.clone());
    let tip = String::from_utf8(run(verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("tip"))
        .expect("utf8");
    // The helper opens the store per command under an exclusive lock,
    // so the context store must close before the session runs.
    drop(ctx);
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"list\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("list");
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains(":object-format sha1\n"), "format: {text:?}");
    assert!(
        text.contains("@refs/heads/main HEAD\n"),
        "head symref: {text:?}"
    );
    assert!(
        text.contains(&format!("{} refs/heads/main\n", tip.trim())),
        "main row: {text:?}"
    );
    assert!(text.ends_with("\n\n"), "blank terminated: {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_options() {
    let (root, env) = seeded_repo("wavek-helperopts", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"option verbosity 2\noption depth 1\noption frobnicate x\noption dry-run true\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("options");
    assert_eq!(out, b"ok\nok\nunsupported\nok\n");
    assert!(session.dry_run, "dry-run sticks");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_import_batch() {
    let (root, env) = seeded_repo("wavek-helperimport", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"import refs/heads/main\n\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("import");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains("commit refs/ruk/test/heads/main\n"),
        "branch rides the private namespace: {text:?}"
    );
    assert!(
        !text.contains("commit refs/heads/main\n"),
        "no bare branch name leaks: {text:?}"
    );
    assert!(text.ends_with("done\n"), "stream ends done: {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_import_unknown_is_empty() {
    let (root, env) = seeded_repo("wavek-helperempty", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"import refs/heads/nope\n\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("import");
    assert_eq!(out, b"done\n");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_export_round_trip() {
    let (root_a, env_a) = seeded_repo("wavek-helperexp-a", "f.txt", b"one\n");
    let mut ctx_a = repo_ctx(&root_a, env_a.clone());
    std::fs::write(root_a.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx_a, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx_a, &["-m", "second"]).expect("commit");
    let tip_a = String::from_utf8(run(verbs_history::rev_parse, &mut ctx_a, &["HEAD"]).expect("tip"))
        .expect("utf8");
    let stream = run(verbs_fastio::fast_export, &mut ctx_a, &["--all"]).expect("export");
    drop(ctx_a);
    let base_b = temp_base("wavek-helperexp-b");
    let env_b = test_env(&base_b);
    let mut ctx_init = Ctx {
        store: None,
        root: base_b.clone(),
        file_base: base_b.clone(),
        kind: None,
        env: env_b.clone(),
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    verbs_repo::init(&mut ctx_init, &["repo".to_owned()]).expect("init");
    let root_b = base_b.join("repo");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root_b.clone(),
        env: env_b,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let mut input_bytes = b"export\n".to_vec();
    input_bytes.extend_from_slice(&stream);
    let mut input = input_bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("export");
    assert_eq!(out, b"ok refs/heads/main\n\n");
    let mut ctx_b = repo_ctx(&root_b, test_env(&base_b));
    let tip_b = String::from_utf8(run(verbs_history::rev_parse, &mut ctx_b, &["HEAD"]).expect("tip"))
        .expect("utf8");
    assert_eq!(tip_a, tip_b, "pushed tip matches");
    drop(ctx_b);
    // A stock delete spelling (bare reset) removes the ref and reports ok.
    let bytes = b"export\nreset refs/heads/main\n\ndone\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("delete");
    assert_eq!(out, b"ok refs/heads/main\n\n");
    let mut ctx_b = repo_ctx(&root_b, test_env(&base_b));
    let refs = String::from_utf8(run(verbs_branch::show_ref, &mut ctx_b, &[]).expect("show-ref"))
        .expect("utf8");
    assert!(!refs.contains("refs/heads/main"), "deleted: {refs:?}");
    let _ = std::fs::remove_dir_all(root_a.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(base_b);
}

#[test]
fn wave_k_remote_helper_verb_entry() {
    let (root, env) = seeded_repo("wavek-helperverb", "f.txt", b"one\n");
    let mut env = env;
    env.stdin = Some(b"capabilities\nlist\n".to_vec());
    // The verb opens the remote store itself, so it takes a storeless
    // context (needs_repo is false); holding repo_ctx open would collide
    // on the store lock.
    let mut ctx = Ctx {
        store: None,
        root: root.clone(),
        file_base: root.clone(),
        kind: None,
        env,
        bare: false,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    };
    let url = root.display().to_string();
    let out = run(
        super::verbs_remote_helper::remote_helper,
        &mut ctx,
        &["origin", &url],
    )
    .expect("verb");
    let text = String::from_utf8(out).expect("utf8");
    // The verb derives the alias from the real URL, so only the
    // capability structure (not the dynamic alias) is pinned here.
    assert!(
        text.starts_with("connect\nimport\nexport\nrefspec refs/heads/*:refs/ruk/"),
        "caps first: {text:?}"
    );
    assert!(
        text.contains("/heads/*\nrefspec refs/tags/*:refs/ruk/"),
        "both refspecs: {text:?}"
    );
    assert!(text.contains("refs/heads/main\n"), "list follows: {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_rejects_unknown_connect_service() {
    let (root, env) = seeded_repo("wavek-helperconn", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"connect git-upload-archive\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    let err = super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out)
        .expect_err("unknown service refused");
    assert!(
        err.to_string().contains("connect service"),
        "got {err:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_rejects_pack_commands() {
    let (root, env) = seeded_repo("wavek-helperrej", "f.txt", b"one\n");
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"push refs/heads/main:refs/heads/main\n\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    let err = super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out)
        .expect_err("pack push refused");
    assert!(
        err.to_string().contains("remote-helper command"),
        "got {err:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_k_remote_helper_import_maps_heads_not_tags() {
    let (root, env) = seeded_repo("wavek-helpermap", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env.clone());
    run(verbs_branch::tag, &mut ctx, &["v1"]).expect("tag");
    drop(ctx);
    let mut session = super::verbs_remote_helper::HelperSession {
        root: root.clone(),
        env,
        dry_run: false,
        alias: "test".to_owned(),
    };
    let bytes = b"import refs/heads/main\nimport refs/tags/v1\n\n".to_vec();
    let mut input = bytes.as_slice();
    let mut out = Vec::new();
    super::verbs_remote_helper::serve_commands(&mut session, &mut input, &mut out).expect("import");
    let text = String::from_utf8(out).expect("utf8");
    assert!(
        text.contains("commit refs/ruk/test/heads/main\n"),
        "branch mapped: {text:?}"
    );
    assert!(
        text.contains("reset refs/ruk/test/tags/v1\n"),
        "lightweight tag rides the private namespace: {text:?}"
    );
    assert!(
        !text.contains("reset refs/tags/v1\n"),
        "no bare tag name leaks: {text:?}"
    );
    assert!(text.ends_with("done\n"), "stream ends done: {text:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_stage_alias() {
    let (root, env) = seeded_repo("leftover-stage", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("g.txt"), b"g\n").expect("new file");
    run(super::verbs_misc::stage, &mut ctx, &["g.txt"]).expect("stage");
    let out = String::from_utf8(
        run(super::verbs_stage::ls_files, &mut ctx, &[]).expect("ls-files"),
    )
    .expect("utf8");
    assert!(out.contains("g.txt"), "staged through the alias: {out:?}");
    assert!(
        run(super::verbs_misc::stage, &mut ctx, &["missing.txt"]).is_err(),
        "unknown paths fail through the alias too"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_whatchanged_raw() {
    let (root, env) = seeded_repo("leftover-whatchanged", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(super::verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(super::verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let out = String::from_utf8(
        run(super::verbs_misc::whatchanged, &mut ctx, &[]).expect("whatchanged"),
    )
    .expect("utf8");
    assert!(
        out.contains("second") && out.contains("seed"),
        "both subjects walk: {out:?}"
    );
    assert!(
        out.contains("\n:") && out.contains("f.txt"),
        "raw per-file lines: {out:?}"
    );
    let capped = String::from_utf8(
        run(super::verbs_misc::whatchanged, &mut ctx, &["-n", "1"]).expect("capped"),
    )
    .expect("utf8");
    assert!(
        capped.contains("second") && !capped.contains("seed"),
        "capped to the tip: {capped:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_show_index_round_trip() {
    let (root, env) = seeded_repo("leftover-showindex", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let mut idx = b"\xfftOc\x00\x00\x00\x02".to_vec();
    for first in 0..256u32 {
        idx.extend_from_slice(&(if first < 0xab { 0u32 } else { 1u32 }).to_be_bytes());
    }
    idx.extend_from_slice(&[0xabu8; 20]);
    idx.extend_from_slice(&0x12345678u32.to_be_bytes());
    idx.extend_from_slice(&8u32.to_be_bytes());
    idx.extend_from_slice(&[0u8; 40]);
    let path = root.join("t.idx");
    std::fs::write(&path, &idx).expect("idx file");
    let out = String::from_utf8(
        run(
            super::verbs_misc::show_index,
            &mut ctx,
            &[path.to_str().expect("utf8")],
        )
        .expect("show-index"),
    )
    .expect("utf8");
    assert_eq!(out, format!("8 {} 12345678\n", "ab".repeat(20)));
    ctx.env.stdin = Some(b"nope".to_vec());
    assert!(
        run(super::verbs_misc::show_index, &mut ctx, &[]).is_err(),
        "non-index bytes refuse"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_unpack_objects_round_trip() {
    let (root, env) = seeded_repo("leftover-unpack-src", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let head = String::from_utf8(
        run(super::verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .expect("utf8");
    let head = head.trim().to_owned();
    ctx.env.stdin = Some(b"HEAD\n".to_vec());
    let pack = run(
        super::verbs_objects::pack_objects,
        &mut ctx,
        &["--stdout", "--revs"],
    )
    .expect("pack");
    assert!(!pack.is_empty(), "pack carries the tip");
    let (root2, env2) = seeded_repo("leftover-unpack-dst", "g.txt", b"other\n");
    let mut ctx2 = repo_ctx(&root2, env2);
    ctx2.env.stdin = Some(pack.clone());
    let out = String::from_utf8(
        run(super::verbs_misc::unpack_objects, &mut ctx2, &[]).expect("unpack"),
    )
    .expect("utf8");
    assert!(out.contains("objects unpacked"), "got {out:?}");
    run(super::verbs_objects::cat_file, &mut ctx2, &["-e", &head]).expect("arrived");
    ctx2.env.stdin = Some(pack);
    let out = String::from_utf8(
        run(super::verbs_misc::unpack_objects, &mut ctx2, &["-n"]).expect("dry run"),
    )
    .expect("utf8");
    assert!(out.contains("dry run"), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(root2.parent().expect("parent"));
}

#[test]
fn leftover_unpack_file_blob() {
    let (root, env) = seeded_repo("leftover-unpackfile", "f.txt", b"hello\n");
    let mut ctx = repo_ctx(&root, env);
    let listing = String::from_utf8(
        run(super::verbs_objects::ls_tree, &mut ctx, &["HEAD"]).expect("ls-tree"),
    )
    .expect("utf8");
    let hex = listing
        .split_whitespace()
        .nth(2)
        .expect("blob column")
        .to_owned();
    let name = String::from_utf8(
        run(super::verbs_misc::unpack_file, &mut ctx, &[&hex]).expect("unpack-file"),
    )
    .expect("utf8");
    let name = name.trim().to_owned();
    assert_eq!(
        std::fs::read(root.join(&name)).expect("spilled file"),
        b"hello\n"
    );
    let name2 = String::from_utf8(
        run(super::verbs_misc::unpack_file, &mut ctx, &[&hex]).expect("unpack again"),
    )
    .expect("utf8");
    assert_ne!(name, name2.trim(), "second unpack mints a fresh name");
    assert!(
        run(super::verbs_misc::unpack_file, &mut ctx, &["HEAD"]).is_err(),
        "commits are not blobs"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_mktag_object() {
    let (root, env) = seeded_repo("leftover-mktag", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let head = String::from_utf8(
        run(super::verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .expect("utf8");
    let head = head.trim().to_owned();
    ctx.env.stdin = Some(
        format!("object {head}\ntype commit\ntag v1\ntagger T <t@x> 0 +0000\n\nnotes\n").into_bytes(),
    );
    let oid = String::from_utf8(
        run(super::verbs_misc::mktag, &mut ctx, &[]).expect("mktag"),
    )
    .expect("utf8");
    let oid = oid.trim().to_owned();
    let kind = String::from_utf8(
        run(super::verbs_objects::cat_file, &mut ctx, &["-t", &oid]).expect("type"),
    )
    .expect("utf8");
    assert_eq!(kind, "tag\n");
    ctx.env.stdin = Some(
        format!("object {head}\ntype bogus\ntag v1\n\nnotes\n").into_bytes(),
    );
    assert!(
        run(super::verbs_misc::mktag, &mut ctx, &[]).is_err(),
        "bogus type refuses"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_bugreport_diagnose() {
    let (root, env) = seeded_repo("leftover-bugreport", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let report = String::from_utf8(
        run(super::verbs_misc::bugreport, &mut ctx, &[]).expect("bugreport"),
    )
    .expect("utf8");
    assert!(
        report.contains("ruk version") && report.contains("head:"),
        "report covers version and head: {report:?}"
    );
    let diag = String::from_utf8(
        run(super::verbs_misc::diagnose, &mut ctx, &[]).expect("diagnose"),
    )
    .expect("utf8");
    assert!(diag.contains("objects:"), "diagnose adds the census: {diag:?}");
    let path = root.join("report.txt");
    let path_str = path.to_str().expect("utf8").to_owned();
    run(super::verbs_misc::bugreport, &mut ctx, &["-o", &path_str]).expect("output file");
    assert!(
        std::fs::read(&path).expect("written report").starts_with(b"ruk version"),
        "file holds the report"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_for_each_repo() {
    let (root1, env1) = seeded_repo("leftover-fer1", "f.txt", b"one\n");
    let (root2, _) = seeded_repo("leftover-fer2", "g.txt", b"two\n");
    let mut ctx = repo_ctx(&root1, env1);
    let list = format!("{}\n{}\n", root1.display(), root2.display());
    run(super::verbs_repo::config, &mut ctx, &["leftover.repos", &list]).expect("config");
    let out = run(
        super::verbs_misc::for_each_repo,
        &mut ctx,
        &[
            "--config=leftover.repos",
            "rev-parse",
            "--is-inside-work-tree",
        ],
    )
    .expect("for-each-repo");
    assert_eq!(out, b"true\ntrue\n".to_vec());
    assert!(
        run(
            super::verbs_misc::for_each_repo,
            &mut ctx,
            &["--config=leftover.repos", "no-such-verb"]
        )
        .is_err(),
        "unknown commands fail"
    );
    assert!(
        run(
            super::verbs_misc::for_each_repo,
            &mut ctx,
            &["--config=missing.key", "status"]
        )
        .is_err(),
        "unset keys fail"
    );
    let _ = std::fs::remove_dir_all(root1.parent().expect("parent"));
    let _ = std::fs::remove_dir_all(root2.parent().expect("parent"));
}

#[test]
fn leftover_last_modified() {
    let (root, env) = seeded_repo("leftover-lastmod", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(super::verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(super::verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let second = String::from_utf8(
        run(super::verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .expect("utf8");
    let second = second.trim().to_owned();
    std::fs::write(root.join("g.txt"), b"g\n").expect("new file");
    run(super::verbs_stage::add, &mut ctx, &["g.txt"]).expect("add");
    run(super::verbs_history::commit, &mut ctx, &["-m", "third"]).expect("commit");
    let third = String::from_utf8(
        run(super::verbs_history::rev_parse, &mut ctx, &["HEAD"]).expect("rev-parse"),
    )
    .expect("utf8");
    let third = third.trim().to_owned();
    let out = String::from_utf8(
        run(super::verbs_misc::last_modified, &mut ctx, &["f.txt"]).expect("touch"),
    )
    .expect("utf8");
    assert_eq!(out, format!("{second}\tf.txt\n"));
    let out = String::from_utf8(
        run(super::verbs_misc::last_modified, &mut ctx, &["g.txt"]).expect("touch"),
    )
    .expect("utf8");
    assert_eq!(out, format!("{third}\tg.txt\n"));
    assert!(
        run(super::verbs_misc::last_modified, &mut ctx, &["missing.txt"]).is_err(),
        "untouched paths fail"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_count_objects_human() {
    let (root, env) = seeded_repo("leftover-counth", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let out = String::from_utf8(
        run(super::verbs_objects::count_objects, &mut ctx, &["-H"]).expect("count -H"),
    )
    .expect("utf8");
    assert!(
        out.contains("objects,") && out.contains('B'),
        "human sizes: {out:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_verify_pack_stat_only() {
    let (root, env) = seeded_repo("leftover-verifystat", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    ctx.env.stdin = Some(b"HEAD\n".to_vec());
    let pack = run(
        super::verbs_objects::pack_objects,
        &mut ctx,
        &["--stdout", "--revs"],
    )
    .expect("pack");
    let path = root.join("t.pack");
    std::fs::write(&path, &pack).expect("pack file");
    let path_str = path.to_str().expect("utf8").to_owned();
    let out = String::from_utf8(
        run(
            super::verbs_objects::verify_pack,
            &mut ctx,
            &["-v", "--stat-only", &path_str],
        )
        .expect("stat-only"),
    )
    .expect("utf8");
    assert_eq!(out.lines().count(), 1, "stat-only prints one line: {out:?}");
    assert!(out.contains("ok ("), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_cat_file_batch_command() {
    let (root, env) = seeded_repo("leftover-batchcmd", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    ctx.env.stdin = Some(b"info HEAD\ncontents HEAD\nflush\ndance party\n".to_vec());
    let out = run(
        super::verbs_objects::cat_file,
        &mut ctx,
        &["--batch-command"],
    )
    .expect("batch-command");
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("commit"), "info line names the type: {text:?}");
    assert!(text.contains("dance party missing"), "unknown commands miss: {text:?}");
    ctx.env.stdin = Some(b"info HEAD\n".to_vec());
    assert!(
        run(
            super::verbs_objects::cat_file,
            &mut ctx,
            &["--batch-check", "--batch-command"]
        )
        .is_err(),
        "one batch mode at a time"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn leftover_dispatch_rows_and_named_gaps() {
    let (root, env) = seeded_repo("leftover-gaps", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    let stubs: &[(
        &str,
        fn(&mut Ctx, &[String]) -> Result<Vec<u8>, ruk_git::GitError>,
    )] = &[
        ("filter-branch", super::verbs_misc::filter_branch),
        ("pack-redundant", super::verbs_misc::pack_redundant),
        ("web--browse", super::verbs_misc::web_browse),
        ("mergetool", super::verbs_misc::mergetool),
        ("difftool", super::verbs_misc::difftool),
        ("instaweb", super::verbs_misc::instaweb),
        ("imap-send", super::verbs_misc::imap_send),
        ("send-email", super::verbs_misc::send_email),
        ("send-pack", super::verbs_misc::send_pack),
        ("quiltimport", super::verbs_misc::quiltimport),
        ("remote-http", super::verbs_misc::remote_http),
        ("remote-https", super::verbs_misc::remote_https),
        ("remote-ftp", super::verbs_misc::remote_ftp),
        ("remote-ftps", super::verbs_misc::remote_ftps),
        ("remote-ext", super::verbs_misc::remote_ext),
        ("remote-fd", super::verbs_misc::remote_fd),
    ];
    for (name, verb) in stubs {
        assert!(lookup(name).is_some(), "dispatch row for {name}");
        let err = run(*verb, &mut ctx, &[]).expect_err("named gap refuses");
        assert!(
            err.to_string().contains("unsupported"),
            "{name}: got {err:?}"
        );
    }
    for name in [
        "bugreport",
        "diagnose",
        "for-each-repo",
        "last-modified",
        "mktag",
        "show-index",
        "stage",
        "unpack-file",
        "unpack-objects",
        "whatchanged",
    ] {
        assert!(lookup(name).is_some(), "dispatch row for {name}");
    }
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_mailmap_parse_forms() {
    let map = verbs_misc::Mailmap::parse(
        "# comment\n\nProper Name <proper@example.invalid> Commit Name <commit@example.invalid>\nMail Only <mail@example.invalid> <oldmail@example.invalid>\n<new@example.invalid> <old2@example.invalid>\nLone Name <lone@example.invalid>\nbroken line\n",
    );
    // Full pair maps name and email.
    assert_eq!(
        map.map_ident("Commit Name", "commit@example.invalid"),
        Some((
            "Proper Name".to_owned(),
            "proper@example.invalid".to_owned()
        ))
    );
    // Email-only old side maps any name, case-insensitively.
    assert_eq!(
        map.map_ident("Anything", "OLDMAIL@example.invalid"),
        Some(("Mail Only".to_owned(), "mail@example.invalid".to_owned()))
    );
    // Bare `<new> <old>` keeps the caller's name, replaces the email.
    assert_eq!(
        map.map_ident("Whatever", "old2@example.invalid"),
        Some(("Whatever".to_owned(), "new@example.invalid".to_owned()))
    );
    // A lone `Name <email>` canonicalizes that email's name.
    assert_eq!(
        map.map_ident("Other", "lone@example.invalid"),
        Some(("Lone Name".to_owned(), "lone@example.invalid".to_owned()))
    );
    assert_eq!(map.map_ident("Nobody", "nowhere@example.invalid"), None);
    // Later rows win per key; unknown names fall back to the simple row,
    // which is empty here and maps nothing.
    let map = verbs_misc::Mailmap::parse(
        "Proper <proper@example.invalid> Commit <commit@example.invalid>\nOther <other@example.invalid> Commit <commit@example.invalid>\n",
    );
    assert_eq!(
        map.map_ident("Commit", "commit@example.invalid"),
        Some(("Other".to_owned(), "other@example.invalid".to_owned()))
    );
    assert_eq!(map.map_ident("Stranger", "commit@example.invalid"), None);
}

#[test]
fn hooks_mailmap_check_mailmap_verb() {
    let (root, env) = seeded_repo("hooksm-check", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join(".mailmap"),
        "Proper Name <proper@example.invalid> Ada <ada@example.invalid>\n",
    )
    .expect("mailmap");
    let out = String::from_utf8(
        run(
            verbs_misc::check_mailmap,
            &mut ctx,
            &["Ada <ada@example.invalid>"],
        )
        .expect("mapped"),
    )
    .expect("utf8");
    assert_eq!(out, "Proper Name <proper@example.invalid>\n");
    let out = String::from_utf8(
        run(
            verbs_misc::check_mailmap,
            &mut ctx,
            &["plain@example.invalid"],
        )
        .expect("bare"),
    )
    .expect("utf8");
    assert_eq!(out, "<plain@example.invalid>\n");
    ctx.env.stdin = Some(b"Second <second@example.invalid>\n".to_vec());
    let out = String::from_utf8(
        run(verbs_misc::check_mailmap, &mut ctx, &["--stdin"]).expect("stdin"),
    )
    .expect("utf8");
    assert_eq!(out, "Second <second@example.invalid>\n");
    assert!(run(verbs_misc::check_mailmap, &mut ctx, &[]).is_err());
    assert!(
        run(
            verbs_misc::check_mailmap,
            &mut ctx,
            &["--mailmap-blob=HEAD:.mailmap", "Ada <ada@example.invalid>"]
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_mailmap_log_canon_placeholders() {
    let (root, env) = seeded_repo("hooksm-log", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join(".mailmap"),
        "Proper Name <proper@example.invalid> Ada <ada@example.invalid>\n",
    )
    .expect("mailmap");
    let out = String::from_utf8(
        run(
            verbs_history::log,
            &mut ctx,
            &["--format=%aN <%aE> / %an <%ae> / %cN <%cE>"],
        )
        .expect("log"),
    )
    .expect("utf8");
    assert_eq!(
        out,
        "Proper Name <proper@example.invalid> / Ada <ada@example.invalid> / Proper Name <proper@example.invalid>\n",
        "got {out:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_mailmap_shortlog_canonicalizes() {
    let (root, env) = seeded_repo("hooksm-short", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join(".mailmap"),
        "Proper Name <proper@example.invalid> Ada <ada@example.invalid>\n",
    )
    .expect("mailmap");
    let out = String::from_utf8(
        run(verbs_misc::shortlog, &mut ctx, &["-s", "-e"]).expect("shortlog"),
    )
    .expect("utf8");
    assert!(
        out.contains("Proper Name <proper@example.invalid>"),
        "got {out:?}"
    );
    assert!(!out.contains("Ada <ada@example.invalid>"), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_mailmap_blame_author_column() {
    let (root, env) = seeded_repo("hooksm-blame", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join(".mailmap"),
        "Proper Name <proper@example.invalid> Ada <ada@example.invalid>\n",
    )
    .expect("mailmap");
    let out = String::from_utf8(
        run(verbs_blame::blame, &mut ctx, &["f.txt"]).expect("blame"),
    )
    .expect("utf8");
    assert!(out.contains("Proper Name"), "got {out:?}");
    assert!(!out.contains("Ada"), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_mailmap_var_ident() {
    let (root, env) = seeded_repo("hooksm-var", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(
        root.join(".mailmap"),
        "Proper Name <proper@example.invalid> Ada <ada@example.invalid>\n",
    )
    .expect("mailmap");
    let out = String::from_utf8(
        run(verbs_misc::var, &mut ctx, &["GIT_AUTHOR_IDENT"]).expect("var"),
    )
    .expect("utf8");
    assert!(
        out.starts_with("Proper Name <proper@example.invalid> "),
        "got {out:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

/// Writes an executable hook script under `.ruk/hooks`.
fn write_hook(root: &std::path::PathBuf, name: &str, body: &str) {
    let dir = root.join(".ruk").join("hooks");
    std::fs::create_dir_all(&dir).expect("hooks dir");
    let path = dir.join(name);
    std::fs::write(&path, body).expect("hook file");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[test]
fn hooks_pre_commit_blocks_commit() {
    let (root, env) = seeded_repo("hooksm-pre", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    write_hook(&root, "pre-commit", "#!/bin/sh\nexit 1\n");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    let err = run(verbs_history::commit, &mut ctx, &["-m", "blocked"]).expect_err("blocked");
    assert!(err.to_string().contains("pre-commit"), "got {err:?}");
    run(
        verbs_history::commit,
        &mut ctx,
        &["-m", "forced", "--no-verify"],
    )
    .expect("forced");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_commit_msg_rewrites_message() {
    let (root, env) = seeded_repo("hooksm-msg", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    write_hook(&root, "commit-msg", "#!/bin/sh\necho hooked > \"$1\"\n");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "original"]).expect("commit");
    let out = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--format=%s"]).expect("log"),
    )
    .expect("utf8");
    assert_eq!(out, "hooked\nseed\n", "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_post_commit_runs_after_commit() {
    let (root, env) = seeded_repo("hooksm-post", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    write_hook(&root, "post-commit", "#!/bin/sh\ntouch post-commit-ran\n");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    assert!(
        root.join("post-commit-ran").exists(),
        "post-commit did not run"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_post_checkout_records_old_new_flag() {
    let (root, env) = seeded_repo("hooksm-co", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::branch, &mut ctx, &["side"]).expect("branch");
    write_hook(
        &root,
        "post-checkout",
        "#!/bin/sh\necho \"$1 $2 $3\" > post-checkout-args\n",
    );
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout");
    let args = std::fs::read_to_string(root.join("post-checkout-args")).expect("args file");
    let parts: Vec<&str> = args.trim().split(' ').collect();
    assert_eq!(parts.len(), 3, "got {args:?}");
    assert_eq!(parts[0], parts[1], "same-tip switch: got {args:?}");
    assert_eq!(parts[0].len(), 40, "full hex: got {args:?}");
    assert_eq!(parts[2], "1", "branch flag: got {args:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_core_hooks_path_beats_ruk_hooks() {
    let (root, env) = seeded_repo("hooksm-path", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    // A failing hook in the default dir, a passing one behind
    // `core.hooksPath`: the override wins and the commit lands.
    write_hook(&root, "pre-commit", "#!/bin/sh\nexit 1\n");
    let alt = root.join("alt-hooks");
    std::fs::create_dir_all(&alt).expect("alt dir");
    let path = alt.join("pre-commit");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("alt hook");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    run(
        verbs_repo::config,
        &mut ctx,
        &["core.hooksPath", alt.to_str().expect("utf8")],
    )
    .expect("config");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "via-path"]).expect("commit");
    // A configured hooks path replaces the defaults: with an empty
    // override dir the failing `.ruk/hooks` hook never runs.
    let empty = root.join("empty-hooks");
    std::fs::create_dir_all(&empty).expect("empty dir");
    run(
        verbs_repo::config,
        &mut ctx,
        &["core.hooksPath", empty.to_str().expect("utf8")],
    )
    .expect("config");
    std::fs::write(root.join("f.txt"), b"three\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "via-empty-path"]).expect("commit");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_pre_push_records_args_and_stdin() {
    let (root, env) = seeded_repo("hooksm-push", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    write_hook(
        &root,
        "pre-push",
        "#!/bin/sh\necho \"$1 $2\" > pre-push-args\ncat > pre-push-stdin\nexit 1\n",
    );
    // Feed one resolved ref line: the hook must see it on stdin.
    let err = verbs_hooks::run_pre_push(
        &mut ctx,
        "origin",
        "origin-url",
        b"refs/heads/main abcdef1 refs/heads/main 0000000\n",
    )
    .expect_err("blocked");
    assert!(err.to_string().contains("pre-push"), "got {err:?}");
    let args = std::fs::read_to_string(root.join("pre-push-args")).expect("args file");
    assert_eq!(args.trim(), "origin origin-url", "got {args:?}");
    let stdin = std::fs::read_to_string(root.join("pre-push-stdin")).expect("stdin file");
    assert_eq!(
        stdin, "refs/heads/main abcdef1 refs/heads/main 0000000\n",
        "got {stdin:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_pre_push_blocks_local_push() {
    let (src, _) = seeded_repo("hooksm-pushfull", "f.txt", b"one\n");
    let base = src.parent().expect("parent").to_path_buf();
    let env = test_env(&base);
    // A bare destination repo beside the source.
    let mut setup = Ctx {
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
        verbs_repo::init,
        &mut setup,
        &[base.join("dst").to_str().expect("utf8")],
    )
    .expect("init dst");
    let mut ctx = repo_ctx(&src, test_env(&base));
    run(
        verbs_repo::remote,
        &mut ctx,
        &["add", "origin", base.join("dst").to_str().expect("utf8")],
    )
    .expect("remote add");
    // A recording hook sees the expanded local ref on stdin: the short
    // `main` refspec arrives as `refs/heads/main`.
    write_hook(
        &src,
        "pre-push",
        "#!/bin/sh\necho \"$1 $2\" > pre-push-args\ncat > pre-push-stdin\n",
    );
    run(verbs_transport::push, &mut ctx, &["origin", "main"]).expect("push");
    let args = std::fs::read_to_string(src.join("pre-push-args")).expect("args file");
    let want = format!("origin {}", base.join("dst").display());
    assert_eq!(args.trim(), want, "got {args:?}");
    let stdin = std::fs::read_to_string(src.join("pre-push-stdin")).expect("stdin file");
    let fields: Vec<&str> = stdin.trim().split(' ').collect();
    assert_eq!(fields.len(), 4, "got {stdin:?}");
    assert_eq!(fields[0], "refs/heads/main", "expanded local ref: {stdin:?}");
    assert_eq!(fields[2], "refs/heads/main", "got {stdin:?}");
    assert_ne!(fields[1], fields[3], "new vs old: {stdin:?}");
    assert_eq!(fields[1].len(), 40, "full hex: {stdin:?}");
    // A failing hook blocks the push; `--no-verify` skips it.
    write_hook(&src, "pre-push", "#!/bin/sh\nexit 1\n");
    std::fs::write(src.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let err = run(verbs_transport::push, &mut ctx, &["origin"]).expect_err("blocked");
    assert!(err.to_string().contains("pre-push"), "got {err:?}");
    run(
        verbs_transport::push,
        &mut ctx,
        &["origin", "--no-verify"],
    )
    .expect("forced push");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn hooks_failing_post_commit_still_succeeds() {
    let (root, env) = seeded_repo("hooksm-postfail", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    // The oracle discards `post-commit` status: the commit lands even
    // when the hook fails.
    write_hook(&root, "post-commit", "#!/bin/sh\nexit 1\n");
    std::fs::write(root.join("f.txt"), b"two\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit");
    let out = String::from_utf8(
        run(verbs_history::log, &mut ctx, &["--format=%s"]).expect("log"),
    )
    .expect("utf8");
    assert!(out.starts_with("second\n"), "got {out:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn hooks_post_merge_runs_on_fast_forward() {
    let (root, env) = seeded_repo("hooksm-merge", "f.txt", b"one\n");
    let mut ctx = repo_ctx(&root, env);
    run(verbs_branch::branch, &mut ctx, &["side"]).expect("branch");
    run(verbs_branch::checkout, &mut ctx, &["side"]).expect("checkout side");
    std::fs::write(root.join("f.txt"), b"side\n").expect("modify");
    run(verbs_stage::add, &mut ctx, &["f.txt"]).expect("add");
    run(verbs_history::commit, &mut ctx, &["-m", "side work"]).expect("commit");
    run(verbs_branch::checkout, &mut ctx, &["main"]).expect("back");
    write_hook(&root, "post-merge", "#!/bin/sh\ntouch post-merge-ran\n");
    run(verbs_history::merge, &mut ctx, &["side"]).expect("merge");
    assert!(root.join("post-merge-ran").exists(), "post-merge did not run");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}

#[test]
fn wave_j_edit_description_needs_terminal() {
    let (root, env) = seeded_repo("wavej-noeditor-term", "f.txt", b"one\n");
    // Configured editor but no terminal: verbs fail instead of hanging.
    let mut vars = env.vars.clone();
    vars.insert("GIT_EDITOR".to_owned(), "true".to_owned());
    let term_env = super::CliEnv {
        vars,
        cwd: env.cwd.clone(),
        stdin: None,
    };
    let mut ctx = repo_ctx(&root, term_env);
    let err =
        run(verbs_branch::branch, &mut ctx, &["--edit-description"]).expect_err("no tty");
    assert!(err.to_string().contains("terminal"), "got {err:?}");
    let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
}
