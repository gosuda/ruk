use super::{
    Ctx, index_stages, repo_ctx, run, seeded_repo, verbs_branch, verbs_history, verbs_stage,
};

#[test]
fn staged_restore_rejects_untraversable_outside_prefixes() {
    let (root, env) = seeded_repo("lexical-outside-file", "seed.txt", b"seed\n");
    let base = root.parent().expect("parent");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("seed.txt"), b"staged change\n").expect("staged content");
    run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage change");
    let before =
        super::super::state::scan_index(ctx.store().expect("store"), ctx.kind().expect("kind"))
            .expect("index before");
    let outside = base.join("build.log");
    std::fs::write(&outside, b"outside file\n").expect("outside file");
    let reject = |ctx: &mut Ctx, prefix: &std::path::Path| {
        let operand = format!("{}/../repo/seed.txt", prefix.display());
        #[cfg(unix)]
        assert!(std::fs::canonicalize(&operand).is_err());
        let error = run(
            verbs_branch::restore,
            ctx,
            &["--staged", "--", operand.as_str()],
        )
        .expect_err("untraversable outside prefix must fail");
        assert!(error.to_string().contains("prefix"), "{error:?}");
        let after =
            super::super::state::scan_index(ctx.store().expect("store"), ctx.kind().expect("kind"))
                .expect("index after");
        assert_eq!(before, after);
        assert_eq!(index_stages(ctx, "seed.txt"), vec![0]);
        assert_eq!(
            std::fs::read(root.join("seed.txt")).expect("staged content intact"),
            b"staged change\n"
        );
        assert_eq!(
            std::fs::read(&outside).expect("outside file intact"),
            b"outside file\n"
        );
    };
    reject(&mut ctx, &outside);
    reject(&mut ctx, &base.join("missing-prefix"));
    #[cfg(unix)]
    {
        let links = base.join("links");
        std::fs::create_dir(&links).expect("links directory");
        let jump = links.join("jump");
        std::os::unix::fs::symlink(&outside, &jump).expect("outside file symlink");
        reject(&mut ctx, &jump);
    }
    let staged = run(verbs_history::diff, &mut ctx, &["--cached"]).expect("staged diff");
    assert!(String::from_utf8_lossy(&staged).contains("+staged change"));
    drop(ctx);
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[cfg(windows)]
mod windows {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::super::{
        index_stages, repo_ctx, run, run_argv, seeded_repo, temp_base, test_env, verbs_branch,
        verbs_history, verbs_stage,
    };

    #[derive(Debug)]
    struct SubstDrive {
        label: String,
        root: PathBuf,
    }

    impl SubstDrive {
        fn new(target: &Path) -> Self {
            let letter = (b'D'..=b'Z')
                .rev()
                .find(|letter| !Path::new(&format!("{}:\\", char::from(*letter))).exists())
                .expect("unused drive letter");
            let label = format!("{}:", char::from(letter));
            let root = PathBuf::from(format!("{label}\\"));
            let output = Command::new("subst.exe")
                .arg(&label)
                .arg(target)
                .output()
                .expect("map owned test directory");
            assert!(
                output.status.success(),
                "map test drive: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Self { label, root }
        }
    }

    impl Drop for SubstDrive {
        fn drop(&mut self) {
            let output = Command::new("subst.exe")
                .arg(&self.label)
                .arg("/D")
                .output()
                .expect("release owned test drive");
            assert!(
                output.status.success(),
                "release test drive: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn staged_restore_accepts_a_missing_file_at_drive_root() {
        let base = temp_base("lexical-drive-root");
        let drive = SubstDrive::new(&base);
        let root = &drive.root;
        let root_text = root.to_str().expect("root text");
        run_argv(test_env(&base), &["ruk", "init", root_text]).expect("init drive-root worktree");
        let mut ctx = repo_ctx(root, test_env(root));
        std::fs::write(root.join("seed.txt"), b"seed\n").expect("seed file");
        run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage seed");
        run(verbs_history::commit, &mut ctx, &["-m", "seed"]).expect("commit seed");
        run(verbs_stage::rm, &mut ctx, &["seed.txt"]).expect("remove tracked file");
        assert!(!root.join("seed.txt").exists());
        assert!(index_stages(&mut ctx, "seed.txt").is_empty());
        let operand = format!("{root_text}seed.txt");
        run(
            verbs_branch::restore,
            &mut ctx,
            &["--staged", "--", operand.as_str()],
        )
        .expect("restore missing tracked path at drive root");
        assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
        assert!(!root.join("seed.txt").exists());
        assert!(
            run(verbs_history::diff, &mut ctx, &["--cached"])
                .expect("restored index")
                .is_empty()
        );
        drop(ctx);
        drop(drive);
        std::fs::remove_dir_all(base).expect("cleanup");
    }

    #[test]
    fn relative_reentry_resolves_a_junction_after_dash_c() {
        let (root, env) = seeded_repo("lexical-relative-junction", "seed.txt", b"first\n");
        let base = root.parent().expect("parent");
        let mut ctx = repo_ctx(&root, env.clone());
        std::fs::write(root.join("seed.txt"), b"second\n").expect("second content");
        run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage second");
        run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit second");
        run(verbs_stage::rm, &mut ctx, &["seed.txt"]).expect("remove tracked file");
        drop(ctx);
        let target = base.join("build");
        let links = base.join("links");
        std::fs::create_dir(&target).expect("target directory");
        std::fs::create_dir(&links).expect("links directory");
        let jump = links.join("jump");
        let output = Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&jump)
            .arg(&target)
            .output()
            .expect("create owned directory junction");
        assert!(
            output.status.success(),
            "create junction: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::canonicalize(&jump).expect("resolved junction"),
            std::fs::canonicalize(&target).expect("resolved target")
        );
        let root_text = root.to_str().expect("root text");
        let operand = r"..\links\jump\..\repo\seed.txt";
        run_argv(
            env.clone(),
            &["ruk", "-C", root_text, "restore", "--staged", "--", operand],
        )
        .expect("relative staged restore through a junction");
        let (diff, _) = run_argv(
            env.clone(),
            &[
                "ruk", "-C", root_text, "diff", "HEAD~1", "HEAD", "--", operand,
            ],
        )
        .expect("relative historical diff through a junction");
        let text = String::from_utf8(diff).expect("diff text");
        assert!(
            text.contains("seed.txt") && text.contains("+second"),
            "unexpected diff: {text:?}"
        );
        let mut ctx = repo_ctx(&root, env);
        assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
        assert!(!root.join("seed.txt").exists());
        assert!(
            run(verbs_history::diff, &mut ctx, &["--cached"])
                .expect("restored index")
                .is_empty()
        );
        drop(ctx);
        std::fs::remove_dir(&jump).expect("remove owned junction");
        assert!(target.is_dir());
        std::fs::remove_dir_all(base).expect("cleanup");
    }
}
