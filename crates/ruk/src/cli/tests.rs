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
use super::verbs_branch;
use super::verbs_grep;
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
    assert_eq!(VERBS.len(), 59);
    let mut names: Vec<&str> = VERBS.iter().map(|verb| verb.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 59);
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
        "grep",
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
        "migrate",
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
        "upload-archive",
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
        let side = super::state::resolve_rev(store, src_ctx.kind().expect("kind"), "refs/heads/side")
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
            ruk_git::transport::has_object(dst_ctx.store().expect("store"), side).expect("has side"),
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
        stderr: Vec::new(),
    };
    for verb in [
        verbs_objects::pack_objects
            as fn(&mut Ctx, &[String]) -> Result<Vec<u8>, ruk_git::GitError>,
        verbs_objects::index_pack,
        verbs_objects::count_objects,
        verbs_transport::gc,
        verbs_transport::bundle,
        verbs_repo::worktree,
    ] {
        let err = run(verb, &mut ctx, &[]).expect_err("unsupported");
        assert_eq!(err.exit_code(), 1, "{err}");
    }
    let _ = std::fs::remove_dir_all(&base);
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
fn archive_over_smart_http_streams_tar() {
    let tar = b"fake-tar-bytes".to_vec();
    let mut body = pkt_frame(b"ACK\n");
    body.extend_from_slice(b"0000");
    let mut frame = format!("{:04x}", tar.len() + 5).into_bytes();
    frame.push(1);
    frame.extend_from_slice(&tar);
    body.extend_from_slice(&frame);
    body.extend_from_slice(b"0000");
    let (base, log) = smart_http_server(vec![(
        body,
        "application/x-git-upload-archive-result",
    )]);
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
    assert!(out.len() >= 1024, "tar ends with two zero blocks: {}", out.len());
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
