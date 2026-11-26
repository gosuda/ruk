use super::{
    Ctx, index_stages, repo_ctx, run, run_argv, seeded_repo, verbs_branch, verbs_history,
    verbs_stage,
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

#[test]
fn stored_paths_clamp_parent_steps_at_the_filesystem_root() {
    let (root, env) = seeded_repo("lexical-root-parent", "seed.txt", b"first\n");
    let base = root.parent().expect("parent");
    let mut ctx = repo_ctx(&root, env.clone());
    std::fs::write(root.join("seed.txt"), b"second\n").expect("second content");
    run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage second");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit second");
    run(verbs_stage::rm, &mut ctx, &["seed.txt"]).expect("remove tracked file");
    drop(ctx);
    let canonical = std::fs::canonicalize(&root).expect("canonical worktree");
    let tail: Vec<_> = canonical
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    let mut operand = std::path::PathBuf::new();
    for _ in 0..tail.len() + 2 {
        operand.push("..");
    }
    for part in tail {
        operand.push(part);
    }
    operand.push("seed.txt");
    let operand = operand.to_str().expect("operand text");
    let root_text = root.to_str().expect("root text");
    run_argv(
        env.clone(),
        &["ruk", "-C", root_text, "restore", "--staged", "--", operand],
    )
    .expect("staged restore clamps parent steps at the filesystem root");
    let (diff, _) = run_argv(
        env.clone(),
        &[
            "ruk", "-C", root_text, "diff", "HEAD~1", "HEAD", "--", operand,
        ],
    )
    .expect("historical diff clamps parent steps at the filesystem root");
    assert!(
        String::from_utf8(diff)
            .expect("diff text")
            .contains("+second")
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
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[test]
fn parent_steps_clamp_at_the_seeded_drive_root() {
    // Pins the extracted `..` decision behind the drive-root floor: staying
    // at the canonicalized drive root is the same step the walk takes on
    // every platform, with synthetic paths standing in for spellings (a
    // substituted drive and its backing path) Linux cannot parse.
    let floor = std::path::Path::new("/srv/share");
    let mut physical = std::path::PathBuf::from("/srv/share");
    assert!(verbs_stage::step_parent_within_floor(
        &mut physical,
        Some(floor)
    ));
    assert_eq!(physical, floor);
    let mut above = std::path::PathBuf::from("/srv/share/sub");
    assert!(verbs_stage::step_parent_within_floor(
        &mut above,
        Some(floor)
    ));
    assert_eq!(above, floor);
    let mut at_root = std::path::PathBuf::from("/");
    assert!(verbs_stage::step_parent_within_floor(
        &mut at_root,
        Some(std::path::Path::new("/"))
    ));
    assert_eq!(at_root, std::path::Path::new("/"));
    let mut relative = std::path::PathBuf::new();
    assert!(!verbs_stage::step_parent_within_floor(&mut relative, None));
}

#[cfg(unix)]
#[test]
fn absolute_operands_clamp_parent_steps_at_the_filesystem_root() {
    // Absolute spelling of the filesystem-root clamp: excess `..` above `/`
    // stays at `/`, then the walk re-descends into the repository. Pins the
    // seeded-root floor on the platform where the floor is `/` itself.
    let (root, env) = seeded_repo("lexical-absolute-root", "seed.txt", b"first\n");
    let base = root.parent().expect("parent");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("seed.txt"), b"second\n").expect("second content");
    run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage second");
    run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit second");
    run(verbs_stage::rm, &mut ctx, &["seed.txt"]).expect("remove tracked file");
    let canonical = std::fs::canonicalize(&root).expect("canonical worktree");
    let tail: Vec<_> = canonical
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    let mut operand = std::path::PathBuf::from("/");
    for _ in 0..tail.len() + 2 {
        operand.push("..");
    }
    for part in tail {
        operand.push(part);
    }
    operand.push("seed.txt");
    let operand = operand.to_str().expect("operand text").to_owned();
    run(
        verbs_branch::restore,
        &mut ctx,
        &["--staged", "--", operand.as_str()],
    )
    .expect("absolute staged restore clamps parent steps at the filesystem root");
    assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
    assert!(!root.join("seed.txt").exists());
    drop(ctx);
    std::fs::remove_dir_all(base).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn absolute_climb_above_the_filesystem_root_cannot_escape_the_repo() {
    // Contrast: climbing above `/` and re-descending outside the repository
    // fails instead of resolving elsewhere, leaving staged state untouched.
    let (root, env) = seeded_repo("lexical-absolute-escape", "seed.txt", b"first\n");
    let base = root.parent().expect("parent");
    let mut ctx = repo_ctx(&root, env);
    std::fs::write(root.join("seed.txt"), b"second\n").expect("second content");
    run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage second");
    let before =
        super::super::state::scan_index(ctx.store().expect("store"), ctx.kind().expect("kind"))
            .expect("index before");
    let error = run(
        verbs_branch::restore,
        &mut ctx,
        &["--staged", "--", "/../lexical-no-such-entry.txt"],
    )
    .expect_err("climb above the root to a missing path must fail");
    assert!(error.to_string().contains("outside"), "{error:?}");
    let after =
        super::super::state::scan_index(ctx.store().expect("store"), ctx.kind().expect("kind"))
            .expect("index after");
    assert_eq!(before, after);
    assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
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
        let nested = drive.root.join("repo");
        let nested_text = nested.to_str().expect("nested root text");
        run_argv(test_env(&drive.root), &["ruk", "init", nested_text])
            .expect("init nested worktree on substituted drive");
        let mut ctx = repo_ctx(&nested, test_env(&nested));
        std::fs::write(nested.join("seed.txt"), b"first\n").expect("nested first content");
        run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage nested first");
        run(verbs_history::commit, &mut ctx, &["-m", "first"]).expect("commit nested first");
        std::fs::write(nested.join("seed.txt"), b"second\n").expect("nested second content");
        run(verbs_stage::add, &mut ctx, &["seed.txt"]).expect("stage nested second");
        run(verbs_history::commit, &mut ctx, &["-m", "second"]).expect("commit nested second");
        run(verbs_stage::rm, &mut ctx, &["seed.txt"]).expect("remove nested tracked file");
        let rooted = r"\repo\seed.txt";
        run(verbs_branch::restore, &mut ctx, &["--staged", "--", rooted])
            .expect("rooted restore retains the substituted cwd drive");
        assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
        assert!(!nested.join("seed.txt").exists());
        assert!(
            run(verbs_history::diff, &mut ctx, &["--cached"])
                .expect("nested restored index")
                .is_empty()
        );
        run(verbs_branch::reset, &mut ctx, &["HEAD~1", "--", rooted])
            .expect("rooted reset retains the substituted cwd drive");
        let staged = run(verbs_history::diff, &mut ctx, &["--cached"]).expect("nested reset index");
        assert!(
            String::from_utf8(staged)
                .expect("staged text")
                .contains("+first")
        );
        let diff = run(
            verbs_history::diff,
            &mut ctx,
            &["HEAD~1", "HEAD", "--", rooted],
        )
        .expect("rooted historical diff retains the substituted cwd drive");
        assert!(
            String::from_utf8(diff)
                .expect("diff text")
                .contains("+second")
        );
        assert!(!nested.join("seed.txt").exists());
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

    #[test]
    fn rooted_climb_above_the_subst_root_cannot_reenter_the_repo() {
        // Thread PRRT_kwDOVOGZ-868XrPT: a rooted `\..\` operand climbs above
        // the substituted drive root through the backing path and re-descends
        // into the repository, so staged restore would overwrite a different
        // file's staged changes. The OS clamps `..` at the drive root, so
        // both spellings must fail and leave staged rows untouched.
        let base = temp_base("lexical-subst-climb");
        let drive = SubstDrive::new(&base);
        let root = drive.root.join("repo");
        std::fs::create_dir(&root).expect("nested repo dir");
        std::fs::create_dir(base.join("sub")).expect("backing sub dir");
        let root_text = root.to_str().expect("root text");
        run_argv(test_env(&base), &["ruk", "init", root_text]).expect("init nested worktree");
        let mut ctx = repo_ctx(&root, test_env(&root));
        for name in ["seed.txt", "other.txt"] {
            std::fs::write(root.join(name), b"first\n").expect("first content");
            run(verbs_stage::add, &mut ctx, &[name]).expect("stage first");
        }
        run(verbs_history::commit, &mut ctx, &["-m", "first"]).expect("commit first");
        for name in ["seed.txt", "other.txt"] {
            std::fs::write(root.join(name), b"second\n").expect("second content");
            run(verbs_stage::add, &mut ctx, &[name]).expect("stage second");
        }
        let basename = base
            .file_name()
            .expect("base name")
            .to_str()
            .expect("base text");
        // Climbs from S:\repo above the substituted root through the backing
        // path, then re-descends through the backing spelling of this very
        // repository naming a different file than the caller holds.
        let direct = format!(r"\..\{basename}\repo\other.txt");
        // Variant: the alias resolves below the root first, then the climb
        // continues from the backing spelling of the drive root.
        let via_sub = format!(r"\sub\..\..\{basename}\repo\other.txt");
        for rooted in [direct.as_str(), via_sub.as_str()] {
            let error = run(verbs_branch::restore, &mut ctx, &["--staged", "--", rooted])
                .expect_err("climb above the substituted root must fail");
            assert!(error.to_string().contains("outside"), "{error:?}");
        }
        assert_eq!(index_stages(&mut ctx, "seed.txt"), vec![0]);
        assert_eq!(index_stages(&mut ctx, "other.txt"), vec![0]);
        assert_eq!(
            std::fs::read(root.join("other.txt")).expect("other intact"),
            b"second\n"
        );
        let staged = run(verbs_history::diff, &mut ctx, &["--cached"]).expect("staged diff");
        assert!(
            String::from_utf8(staged)
                .expect("staged text")
                .contains("+second"),
            "staged rows for both files must survive the rejected operands"
        );
        drop(ctx);
        drop(drive);
        std::fs::remove_dir_all(base).expect("cleanup");
    }
}
