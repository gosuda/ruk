# Task report: stash merge-shape parity

## Status
Done for the assigned scope. `stash push` mints the oracle two-commit
shape (index commit + `WIP` worktree commit under `refs/stash`);
`pop`/`apply` restore the worktree (+ index only with `--index`); the
parity row `d/stash-pop` passes byte-identical. Harness is 55/56 — the
only failure is the intentional `a/init` (`.ruk` vs `.git` wording).

Scope boundary (pre-existing, documented in `STATUS.md`): restoring onto
a moved `HEAD` still refuses (`stash restore with a moved HEAD needs the
merge lane`) instead of three-way merging like the oracle. The assigned
criterion was the harness row's observable behavior, which matches.

## Commits
- `b6d8a4d` — implementation (`verbs_branch.rs`, `verbs_stage.rs`
  one-word visibility, `STATUS.md` notes).
- `abef056` — structure test (`tests.rs`,
  `stash_push_mints_oracle_shaped_commits`).
- `379522e` — regenerated `tasks/parity-harness/GAPS.md` (force-added;
  `tasks/` is gitignored but the file is tracked).
- Follow-up commit below — bare verbs default to newest slot,
  idempotent mint, `--index` behavior test, report.

## Harness row result
`d/stash-push`, `d/stash-list`, `d/stash-pop`, `d/stash-list-empty` all PASS
exact. `d/stash-pop` previously failed only on the `Dropped` oid; the
status portion already matched.

## Deviations and notes
- Oracle newline asymmetry, verified against raw objects: the index message
  ends with `\n`, the `WIP` message is bare. Both reproduced verbatim.
- `push` on a clean tree now returns `Ok("No local changes to save")`
  (exit 0, oracle behavior) instead of an error; unborn-branch push errors
  like the oracle even with `-m`.
- `apply`/`pop` keep the clean-index guard and add a worktree-overwrite
  guard (refuse when a restored path has unsaved edits); `stash branch`
  restores the index. `verbs_stage::file_mode_of` went `pub(crate)` —
  additive only, no `ruk-core` changes needed.
- Bare `pop`/`apply`/`drop`/`show`/`branch` address the newest live slot
  (oracle `stash@{0}` semantics); slot numbers are monotonic with gaps.
- Re-pushing identical state reuses the existing commits (prepare-first,
  publish only when missing) instead of failing stale like a re-put.
- One test commit incidentally includes a peer's uncommitted rustfmt
  reflow in `tests.rs` (whitespace-only, pre-existing in the tree).
- No gates run (per brief); `cargo build -p ruk`, filtered `cargo test -p
  ruk stash` (3 passed), and the harness were run. Mid-task workspace
  breaks came from the concurrent transport lane, not this change.
