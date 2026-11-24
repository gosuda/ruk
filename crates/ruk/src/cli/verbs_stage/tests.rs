use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ruk_core::ids::HashKind;
use ruk_git::GitError;

use super::super::{CliEnv, run_inner};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn run(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let argv = std::iter::once("ruk")
        .chain(args.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let env = CliEnv {
        vars: HashMap::from([("RUK_COORDINATOR".to_owned(), "off".to_owned())]),
        cwd: cwd.to_path_buf(),
        stdin: Some(Vec::new()),
    };
    run_inner(
        &argv,
        env,
        ruk_git::transport::net::EgressPolicy::deny_private(),
    )
    .map(|(stdout, _)| stdout)
}

fn init(case: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!(
        "ruk-stage-{}-{}-{case}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&base).expect("test directory");
    run(&base, &["init", "repo"]).expect("init");
    let root = base.join("repo");
    (base, root)
}

fn blob_hex(body: &[u8]) -> String {
    HashKind::Sha1
        .hash_git_object("blob", body)
        .expect("blob id")
        .to_hex()
}

#[test]
fn absolute_add_operand_matches_canonical_worktree() {
    let (base, root) = init("absolute");
    let file = root.join("file.txt");
    let body = b"absolute operand\n";
    std::fs::write(&file, body).expect("file");
    run(
        &base,
        &[
            "-C",
            root.to_str().expect("root"),
            "add",
            file.to_str().expect("file path"),
        ],
    )
    .expect("add absolute operand");
    let hex = blob_hex(body);
    let index = run(
        &base,
        &["-C", root.to_str().expect("root"), "ls-files", "-s"],
    )
    .expect("index");
    assert_eq!(index, format!("100644 {hex} 0\tfile.txt\n").into_bytes());
    let stored = run(
        &base,
        &["-C", root.to_str().expect("root"), "cat-file", "-p", &hex],
    )
    .expect("stored blob");
    assert_eq!(stored, body);
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[test]
fn missing_parent_paths_support_moves_and_cached_removals() {
    let (base, root) = init("missing-parent");
    let source = root.join("source");
    let other = root.join("gone").join("dir").join("other");
    let destination = root.join("gone").join("more").join("deep").join("moved");
    std::fs::create_dir_all(other.parent().expect("other parent")).expect("directory");
    std::fs::write(&source, b"moved content\n").expect("source");
    std::fs::write(&other, b"other content\n").expect("other");
    let root_text = root.to_str().expect("root");
    run(
        &base,
        &[
            "-C",
            root_text,
            "add",
            source.to_str().expect("source path"),
            other.to_str().expect("other path"),
        ],
    )
    .expect("add sources");
    run(
        &base,
        &[
            "-C",
            root_text,
            "mv",
            source.to_str().expect("source path"),
            destination.to_str().expect("destination path"),
        ],
    )
    .expect("move to missing parents");
    assert_eq!(
        std::fs::read(&destination).expect("moved file"),
        b"moved content\n"
    );
    std::fs::remove_dir_all(root.join("gone")).expect("remove worktree directory");
    run(
        &base,
        &[
            "-C",
            root_text,
            "update-index",
            "--force-remove",
            destination.to_str().expect("deleted path"),
        ],
    )
    .expect("remove deleted leaf from index");
    assert_eq!(
        run(&base, &["-C", root_text, "ls-files"]).expect("remaining index"),
        b"gone/dir/other\n"
    );
    let gone = root.join("gone");
    run(
        &base,
        &[
            "-C",
            root_text,
            "rm",
            "--cached",
            "-r",
            gone.to_str().expect("deleted directory"),
        ],
    )
    .expect("remove deleted directory from index");
    assert!(
        run(&base, &["-C", root_text, "ls-files"])
            .expect("empty index")
            .is_empty()
    );
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[test]
fn add_all_from_nested_directory_uses_repository_relative_walk_paths() {
    let (base, root) = init("nested-all");
    let nested = root.join("nested");
    std::fs::create_dir(&nested).expect("nested directory");
    std::fs::write(root.join("root.txt"), b"root\n").expect("root file");
    std::fs::write(nested.join("child.txt"), b"child\n").expect("nested file");
    run(
        &base,
        &["-C", nested.to_str().expect("nested path"), "add", "-A"],
    )
    .expect("add all from nested directory");
    assert_eq!(
        run(
            &base,
            &["-C", root.to_str().expect("root"), "ls-files"],
        )
        .expect("index"),
        b"nested/child.txt\nroot.txt\n"
    );
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn absolute_worktree_alias_preserves_final_symlink() {
    use std::os::unix::fs::symlink;

    let (base, root) = init("worktree-alias");
    let alias = base.join("alias");
    symlink(&root, &alias).expect("worktree alias");
    std::fs::write(base.join("outside"), b"outside content must not be staged\n")
        .expect("outside file");
    symlink("../outside", root.join("link")).expect("final symlink");
    let operand = alias.join("link");
    run(
        &base,
        &[
            "-C",
            alias.to_str().expect("alias"),
            "add",
            operand.to_str().expect("link path"),
        ],
    )
    .expect("stage link through worktree alias");
    let hex = blob_hex(b"../outside");
    let index = run(
        &base,
        &["-C", alias.to_str().expect("alias"), "ls-files", "-s"],
    )
    .expect("index");
    assert_eq!(index, format!("120000 {hex} 0\tlink\n").into_bytes());
    let stored = run(
        &base,
        &["-C", alias.to_str().expect("alias"), "cat-file", "-p", &hex],
    )
    .expect("stored link");
    assert_eq!(stored, b"../outside");
    assert_eq!(
        std::fs::read_link(root.join("link")).expect("unchanged symlink"),
        PathBuf::from("../outside")
    );
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn intermediate_symlink_escape_is_rejected_before_staging() {
    use std::os::unix::fs::symlink;

    let (base, root) = init("parent-escape");
    let outside = base.join("outside");
    std::fs::create_dir(&outside).expect("outside directory");
    std::fs::write(outside.join("private"), b"outside bytes\n").expect("outside file");
    symlink(&outside, root.join("escape")).expect("intermediate symlink");
    let absolute = root.join("escape").join("private");
    for operand in ["escape/private", absolute.to_str().expect("absolute path")] {
        let err = run(
            &base,
            &["-C", root.to_str().expect("root"), "add", operand],
        )
        .expect_err("outside parent");
        assert!(matches!(
            err,
            GitError::Invalid { detail } if detail.contains("outside the repository")
        ));
    }
    symlink(base.join("absent"), root.join("dangling")).expect("dangling parent");
    assert!(super::normalize_staging_path(&root.join("dangling").join("file")).is_err());
    assert!(
        run(
            &base,
            &["-C", root.to_str().expect("root"), "ls-files"],
        )
        .expect("unchanged index")
        .is_empty()
    );
    assert_eq!(
        std::fs::read(outside.join("private")).expect("unchanged outside file"),
        b"outside bytes\n"
    );
    std::fs::remove_dir_all(base).expect("cleanup");
}
