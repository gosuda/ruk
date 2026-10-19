//! Rename detection: flag parsing, content similarity, add/delete pairing.
//!
//! Oracle: `git/diffcore-rename.c` (`-M` similarity), `git/wt-status.c`
//! (staged `R` rows), `git/merge-ort.c` (rename tracking, common case).
//! Git scores similarity from common bytes with `-M<threshold>` defaulting
//! to 50%; this lane scores text from common lines (Dice over a line
//! multiset: `200 * common / (len_a + len_b)`), which agrees with git at
//! 100% and degrades monotonically the same way for small edits. Binary
//! sides pair only when identical, never by score.

use std::collections::HashMap;

use ruk_git::GitError;

/// How add/delete sides pair into renames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenameMode {
    /// `--no-renames` or `-M0`: pure add plus delete, not even exact blobs.
    Disabled,
    /// Default: identical blobs pair, edited ones stay add plus delete.
    ExactOnly,
    /// `-M[<n>]` / `--find-renames[=<n>]`: exact plus similarity at or
    /// above the threshold percent (1..=100).
    Similar(u8),
}

impl RenameMode {
    /// Whether any pairing runs at all.
    #[must_use]
    pub(crate) fn pairs(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Strips rename flags from `args`, stopping at `--` so paths that look
/// like flags survive. Later flags win, the way the oracle parses `-M`
/// after `--no-renames`; bare `-M`/`--find-renames` mean 50%.
pub(crate) fn split_rename_args(args: &[String]) -> Result<(Vec<String>, RenameMode), GitError> {
    let mut kept = Vec::with_capacity(args.len());
    let mut mode = RenameMode::ExactOnly;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            kept.extend(args[index..].iter().cloned());
            break;
        }
        if arg == "--no-renames" {
            mode = RenameMode::Disabled;
        } else if arg == "--renames" {
            mode = RenameMode::ExactOnly;
        } else if arg == "--find-renames" || arg == "-M" {
            mode = RenameMode::Similar(50);
        } else if let Some(spec) = arg.strip_prefix("--find-renames=") {
            mode = threshold_mode(spec)?;
        } else if let Some(spec) = arg.strip_prefix("-M") {
            mode = threshold_mode(spec)?;
        } else {
            kept.push(arg.clone());
        }
        index += 1;
    }
    Ok((kept, mode))
}

/// Parses one `-M<spec>` / `--find-renames=<spec>` threshold: an optional
/// trailing `%`, defaulting to 50% when empty. Zero disables pairing, the
/// way `-M0` keeps the old add-plus-delete output.
fn threshold_mode(spec: &str) -> Result<RenameMode, GitError> {
    let digits = spec.strip_suffix('%').unwrap_or(spec);
    if digits.is_empty() {
        return Ok(RenameMode::Similar(50));
    }
    let value: u8 = digits.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad rename threshold {spec:?}: want 0-100"),
    })?;
    if value > 100 {
        return Err(GitError::Invalid {
            detail: format!("bad rename threshold {spec:?}: want 0-100"),
        });
    }
    if value == 0 {
        return Ok(RenameMode::Disabled);
    }
    Ok(RenameMode::Similar(value))
}

/// Scores two blobs 0..=100. Identical bytes are 100 (binaries included);
/// differing binaries are 0; text uses common-line Dice. Inputs past the
/// caps score 0 instead of paying an unbounded comparison.
pub(crate) fn similarity(old: &[u8], new: &[u8]) -> u8 {
    if old == new {
        return 100;
    }
    if old.contains(&0) || new.contains(&0) {
        return 0;
    }
    if old.is_empty() || new.is_empty() {
        return 0;
    }
    const MAX_BYTES: usize = 1 << 20;
    const MAX_LINES: usize = 20_000;
    if old.len() + new.len() > 2 * MAX_BYTES {
        return 0;
    }
    let old_lines = split(old);
    let new_lines = split(new);
    if old_lines.len() + new_lines.len() > 2 * MAX_LINES {
        return 0;
    }
    let mut counts: HashMap<&[u8], u32> = HashMap::with_capacity(old_lines.len());
    for line in old_lines {
        *counts.entry(line).or_insert(0) += 1;
    }
    let mut common: u64 = 0;
    for line in new_lines {
        if let Some(left) = counts.get_mut(line) {
            if *left > 0 {
                *left -= 1;
                common += 1;
            }
        }
    }
    let total_lines = line_count(old) + line_count(new);
    if total_lines == 0 {
        return 100;
    }
    // Capped at 100 two lines above, so the narrowing bound is proven.
    u8::try_from((200 * common / total_lines).min(100)).expect("score capped at 100")
}

/// Counts `\n`-separated lines, ignoring a trailing-newline phantom.
fn line_count(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut count = 0u64;
    for byte in bytes {
        if *byte == b'\n' {
            count += 1;
        }
    }
    if bytes.last() == Some(&b'\n') {
        count
    } else {
        count + 1
    }
}

/// Splits bytes into lines without terminators, ignoring a trailing
/// trailing-newline phantom, mirroring the diff lane's `split_lines`.
fn split(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if lines.last() == Some(&b"".as_slice()) {
        lines.pop();
    }
    lines
}

/// One rename side for pairing: its path and byte length. Lengths back the
/// size prefilter so hopeless pairs never pay for scoring.
pub(crate) struct RenameSide {
    /// Full path bytes.
    pub(crate) path: Vec<u8>,
    /// Blob byte length.
    pub(crate) size: usize,
}

/// One paired rename: indices into the old/new side lists plus its score.
pub(crate) struct RenamePair {
    /// Index into the deleted-side list.
    pub(crate) old: usize,
    /// Index into the added-side list.
    pub(crate) new: usize,
    /// Similarity score that cleared the threshold.
    pub(crate) score: u8,
}

/// Pairs deleted sides with added sides at or above `threshold`
/// (1..=100). Exact-100 pairs need no scoring when `score` returns 100
/// without reading (oid equality); the rest score through `score`.
/// Evaluation is bounded: basename matches score first and the tail past
/// 20,000 pairs is dropped, so unbounded inputs degrade to fewer renames,
/// never to quadratic blowup. Winners take greedily by score, then path.
pub(crate) fn pair_renames(
    old: &[RenameSide],
    new: &[RenameSide],
    threshold: u8,
    mut score: impl FnMut(usize, usize) -> u8,
) -> Vec<RenamePair> {
    const MAX_EVALS: usize = 20_000;
    const SIZE_SLACK: usize = 64;
    if old.is_empty() || new.is_empty() || threshold == 0 {
        return Vec::new();
    }
    let mut order: Vec<(usize, usize, bool)> = Vec::new();
    for (oi, del) in old.iter().enumerate() {
        for (ni, add) in new.iter().enumerate() {
            let (small, big) = if del.size < add.size {
                (del.size, add.size)
            } else {
                (add.size, del.size)
            };
            if big > 0 && small * 100 < usize::from(threshold) * big && big - small > SIZE_SLACK {
                continue;
            }
            order.push((oi, ni, same_basename(&del.path, &add.path)));
        }
    }
    order.sort_by(|left, right| right.2.cmp(&left.2));
    order.truncate(MAX_EVALS);
    let mut scored: Vec<(u8, usize, usize)> = Vec::new();
    for (oi, ni, _) in order {
        let value = score(oi, ni);
        if value >= threshold {
            scored.push((value, oi, ni));
        }
    }
    scored.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| old[left.1].path.cmp(&old[right.1].path))
            .then_with(|| new[left.2].path.cmp(&new[right.2].path))
    });
    let mut used_old = vec![false; old.len()];
    let mut used_new = vec![false; new.len()];
    let mut out = Vec::new();
    for (value, oi, ni) in scored {
        if used_old[oi] || used_new[ni] {
            continue;
        }
        used_old[oi] = true;
        used_new[ni] = true;
        out.push(RenamePair {
            old: oi,
            new: ni,
            score: value,
        });
    }
    out
}

/// Reports whether two paths share a file name, the oracle's fast path:
/// same-basename pairs score first under the evaluation cap.
fn same_basename(left: &[u8], right: &[u8]) -> bool {
    fn base(path: &[u8]) -> &[u8] {
        match path.iter().rposition(|byte| *byte == b'/') {
            None => path,
            Some(index) => &path[index + 1..],
        }
    }
    base(left) == base(right)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ruk_core::store::{PreparationBudget, Store};

    use super::super::{CliEnv, Ctx};
    use super::{RenameMode, RenameSide, pair_renames, similarity, split_rename_args};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(10_000);

    fn temp_base(case: &str) -> PathBuf {
        let id = NEXT_TEMP.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("ruk-rename-{}-{}-{}", std::process::id(), id, case));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("temp base");
        base
    }

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

    fn repo_ctx(root: &PathBuf, mut env: CliEnv) -> Ctx {
        env.cwd = root.clone();
        let store = Store::open(
            &root.join(".ruk"),
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("open store");
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

    fn seeded(case: &str, file: &str, body: &[u8]) -> (PathBuf, CliEnv) {
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
        super::super::verbs_repo::init(&mut ctx, &["repo".to_owned()]).expect("init");
        let root = base.join("repo");
        std::fs::write(root.join(file), body).expect("seed file");
        let env = test_env(&base);
        let mut ctx = repo_ctx(&root, env.clone());
        run(super::super::verbs_stage::add, &mut ctx, &[file]);
        run(
            super::super::verbs_history::commit,
            &mut ctx,
            &["-m", "seed"],
        );
        (root, env)
    }

    fn run(
        verb: fn(&mut Ctx, &[String]) -> Result<Vec<u8>, ruk_git::GitError>,
        ctx: &mut Ctx,
        args: &[&str],
    ) -> Vec<u8> {
        let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        verb(ctx, &owned).expect("verb")
    }

    fn ctx_for(root: &PathBuf, env: &CliEnv) -> Ctx {
        repo_ctx(root, env.clone())
    }

    const TEN: &[u8] = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n";
    const TEN_EDIT: &[u8] =
        b"line1\nline2CHANGED\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\n";

    #[test]
    fn similarity_grades_edits() {
        assert_eq!(similarity(b"a\n", b"a\n"), 100);
        assert_eq!(similarity(b"", b""), 100);
        assert_eq!(similarity(b"", b"a\n"), 0);
        assert_eq!(similarity(b"a\0b", b"a\0c"), 0);
        assert_eq!(similarity(TEN, TEN_EDIT), 90);
    }

    #[test]
    fn rename_flags_parse() {
        let (_, mode) = split_rename_args(&["-M".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Similar(50));
        let (_, mode) = split_rename_args(&["-M90%".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Similar(90));
        let (_, mode) = split_rename_args(&["--find-renames=20".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Similar(20));
        let (_, mode) = split_rename_args(&["-M0".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Disabled);
        let (_, mode) = split_rename_args(&["--no-renames".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Disabled);
        let (kept, mode) =
            split_rename_args(&["-M".to_owned(), "--".to_owned(), "-M".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Similar(50));
        assert_eq!(kept, vec!["--".to_owned(), "-M".to_owned()]);
        let (_, mode) =
            split_rename_args(&["-M".to_owned(), "--no-renames".to_owned()]).expect("parse");
        assert_eq!(mode, RenameMode::Disabled);
        assert!(split_rename_args(&["-Mabc".to_owned()]).is_err());
    }

    #[test]
    fn pairing_greeds_by_score() {
        let old = vec![
            RenameSide {
                path: b"a.txt".to_vec(),
                size: 10,
            },
            RenameSide {
                path: b"b.txt".to_vec(),
                size: 10,
            },
        ];
        let new = vec![RenameSide {
            path: b"c.txt".to_vec(),
            size: 10,
        }];
        // Only the first old side scores above threshold: one pair wins.
        let wins = pair_renames(&old, &new, 50, |oi, _| if oi == 0 { 80 } else { 10 });
        assert_eq!(wins.len(), 1);
        assert_eq!((wins[0].old, wins[0].new, wins[0].score), (0, 0, 80));
        // Nothing clears a high threshold.
        assert!(pair_renames(&old, &new, 90, |_, _| 80).is_empty());
    }

    #[test]
    fn diff_pairs_rename_with_threshold() {
        let (root, env) = seeded("diffpair", "a.txt", TEN);
        let mut ctx = ctx_for(&root, &env);
        run(super::super::verbs_stage::mv, &mut ctx, &["a.txt", "b.txt"]);
        std::fs::write(root.join("b.txt"), TEN_EDIT).expect("edit");
        run(super::super::verbs_stage::add, &mut ctx, &["b.txt"]);
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("similarity index 90%"), "got:\n{text}");
        assert!(text.contains("rename from a.txt"), "got:\n{text}");
        assert!(text.contains("rename to b.txt"), "got:\n{text}");
        assert!(text.contains("-line2\n+line2CHANGED\n"), "got:\n{text}");
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--name-status"],
        );
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "R090\ta.txt\tb.txt\n"
        );
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--stat"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("a.txt => b.txt"), "got:\n{text}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn diff_pathspec_applies_before_pairing() {
        let (root, env) = seeded("diffpaths", "a.txt", TEN);
        let mut ctx = ctx_for(&root, &env);
        run(super::super::verbs_stage::mv, &mut ctx, &["a.txt", "b.txt"]);
        std::fs::write(root.join("b.txt"), TEN_EDIT).expect("edit");
        run(super::super::verbs_stage::add, &mut ctx, &["b.txt"]);
        // New side only: plain add, never half of a rename.
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--", "b.txt"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("new file mode"), "got:\n{text}");
        assert!(!text.contains("rename from"), "got:\n{text}");
        // Old side only: plain delete.
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--", "a.txt"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("deleted file mode"), "got:\n{text}");
        assert!(!text.contains("rename from"), "got:\n{text}");
        // Both sides: the rename shows.
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M", "--", "a.txt", "b.txt"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("rename from a.txt"), "got:\n{text}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn diff_without_threshold_keeps_add_delete() {
        let (root, env) = seeded("diffplain", "a.txt", TEN);
        let mut ctx = ctx_for(&root, &env);
        run(super::super::verbs_stage::mv, &mut ctx, &["a.txt", "b.txt"]);
        std::fs::write(root.join("b.txt"), TEN_EDIT).expect("edit");
        run(super::super::verbs_stage::add, &mut ctx, &["b.txt"]);
        for args in [
            &["--cached"][..],
            &["--cached", "-M0"],
            &["--cached", "--no-renames"],
        ] {
            let out = run(super::super::verbs_history::diff, &mut ctx, args);
            let text = String::from_utf8(out).expect("utf8");
            assert!(!text.contains("rename from"), "got:\n{text}");
        }
        // Below-threshold edits stay unpaired even with `-M`.
        let heavy = TEN_EDIT
            .split(|byte| *byte == b'\n')
            .enumerate()
            .map(|(index, _)| format!("other{index}"))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        std::fs::write(root.join("b.txt"), &heavy).expect("rewrite");
        run(super::super::verbs_stage::add, &mut ctx, &["b.txt"]);
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("rename from"), "got:\n{text}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn diff_pure_rename_reports_hundred() {
        let (root, env) = seeded("diffpure", "a.txt", TEN);
        let mut ctx = ctx_for(&root, &env);
        run(super::super::verbs_stage::mv, &mut ctx, &["a.txt", "b.txt"]);
        let out = run(
            super::super::verbs_history::diff,
            &mut ctx,
            &["--cached", "-M"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("similarity index 100%"), "got:\n{text}");
        assert!(!text.contains("@@"), "got:\n{text}");
        let out = run(super::super::verbs_history::show, &mut ctx, &["HEAD", "-M"]);
        let _ = String::from_utf8(out).expect("utf8");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn status_reports_staged_and_unstaged_renames() {
        // Staged: exact pairs report `R` with and without `-M`.
        let (root, env) = seeded("statmv", "a.txt", TEN);
        let mut ctx = ctx_for(&root, &env);
        run(super::super::verbs_stage::mv, &mut ctx, &["a.txt", "b.txt"]);
        let out = run(
            super::super::verbs_stage::status,
            &mut ctx,
            &["--porcelain"],
        );
        assert_eq!(String::from_utf8(out).expect("utf8"), "R  a.txt -> b.txt\n");
        let out = run(super::super::verbs_stage::status, &mut ctx, &[]);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("renamed:"), "got:\n{text}");
        assert!(text.contains("a.txt -> b.txt"), "got:\n{text}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
        // Unstaged: plain moves stay delete plus untracked; `-M` pairs them.
        let (root, env) = seeded("statwt", "a.txt", TEN);
        std::fs::rename(root.join("a.txt"), root.join("b.txt")).expect("move");
        std::fs::write(root.join("b.txt"), TEN_EDIT).expect("edit");
        let mut ctx = ctx_for(&root, &env);
        let out = run(
            super::super::verbs_stage::status,
            &mut ctx,
            &["--porcelain"],
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains(" D a.txt"), "got:\n{text}");
        assert!(text.contains("?? b.txt"), "got:\n{text}");
        let out = run(
            super::super::verbs_stage::status,
            &mut ctx,
            &["--porcelain", "-M"],
        );
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            " R a.txt -> b.txt\n",
            "got"
        );
        let out = run(super::super::verbs_stage::status, &mut ctx, &["-M"]);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("renamed:"), "got:\n{text}");
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }

    #[test]
    fn merge_tracks_rename_plus_edit() {
        let (root, env) = seeded("mergerename", "f.txt", b"l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\n");
        let mut ctx = ctx_for(&root, &env);
        run(
            super::super::verbs_branch::checkout,
            &mut ctx,
            &["-b", "side"],
        );
        run(super::super::verbs_stage::mv, &mut ctx, &["f.txt", "g.txt"]);
        std::fs::write(
            root.join("g.txt"),
            b"l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9extra\n",
        )
        .expect("edit g");
        run(super::super::verbs_stage::add, &mut ctx, &["g.txt"]);
        run(
            super::super::verbs_history::commit,
            &mut ctx,
            &["-m", "rename"],
        );
        run(super::super::verbs_branch::checkout, &mut ctx, &["main"]);
        std::fs::write(root.join("f.txt"), b"l1\nl2EDIT\nl3\nl4\nl5\nl6\nl7\nl8\n")
            .expect("edit f");
        run(super::super::verbs_stage::add, &mut ctx, &["f.txt"]);
        run(
            super::super::verbs_history::commit,
            &mut ctx,
            &["-m", "edit"],
        );
        run(super::super::verbs_history::merge, &mut ctx, &["side"]);
        assert!(!root.join("f.txt").exists(), "old path survives");
        assert_eq!(
            std::fs::read(root.join("g.txt")).expect("read"),
            b"l1\nl2EDIT\nl3\nl4\nl5\nl6\nl7\nl8\nl9extra\n"
        );
        let _ = std::fs::remove_dir_all(root.parent().expect("parent"));
    }
}
