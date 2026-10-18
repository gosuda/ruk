# Wave-5 fix report (Wave5Fix)

All 7 assigned findings fixed (+M3 dead code in the same function). 4 per-concern commits, all ancestors of HEAD.

## Commits
- `edff88a` compaction (I1 + M3): `store/compact.rs`
- `5ddcb85` close/drain (I2): `store/mod.rs`, `coord/lane.rs`, `coord/hosted.rs`
- `ab7934c` transport (M1 + M2): `ruk-git/.../hooks.rs`, `proc_receive.rs`, `serve.rs`
- `2f99e40` harness (I3 + M4 + M5): `tasks/capacity/{gen-fixture,run,check-structure}.sh`, `RESULTS.md`

## Resolutions
- **I1**: `compact_guarded` snapshots the open set under the writer lock BEFORE `all_manifests()`, and `live` admits only sealed segments (sealed `records_end` is final). Racing-publish test now requires healthy compaction.
- **I2**: `Store::close` syncs, drops the handle, and latches the writer closed (terminal: reopen resumes the single open segment; a second open would fail recovery — caught during review, fixed before commit). The lane runner closes the store after its drain; `shutdown()` only signals. New close/reopen regression test.
- **I3**: `gen-fixture.sh --ruk` migrates every repo to a co-located `.ruk` store (manifest: `ruk-stores: 10`). `run.sh` uses argv identical to git and probe-gates each ruk workload: real numbers for adv-1k/adv-10k/page1/write; honest BLOCKED for lookup (`unknown option --quiet`), clone (`unknown option -q`), fetch (no `.ruk` in git-made clone / no remote support).
- **M1**: accepted diversions accumulate `(index, AlternateRef)`; post-receive lines name the review ref with hook OIDs (fallback: pushed OIDs). New test asserts `refs/pull/1/head` delivery.
- **M2**: `negotiated` threads through `run_hook`/`execute`/`apply_hook_env`; COUNT exports only when negotiated. New test asserts absence unnegotiated; existing test covers COUNT=1 negotiated.
- **M3**: dead `staged.current.take()` block removed (covered by `edff88a`).
- **M4**: `walk_opolog_page` → `walk_oplog_page`; gate still passes (`ABSENT=0`).
- **M5**: `row()` emits via `python3 json.dumps`; `results.json`/`RESULTS.md` regenerated from it without parse errors.

## Verification
- `cargo build -p ruk-core -p ruk-git`: clean.
- `cargo test -p ruk-core --lib store::`: 201 passed, 0 failed (incl. new close test).
- `cargo nextest run -p ruk-core coord`: 236 passed.
- `cargo test -p ruk-git --lib transport::`: 93 passed, incl. both new tests (evidence: `/tmp/gittest.log`).
- `RESULTS.md` regenerated live from `/tmp/cap-w5` (seed `0x52554b01`); ruk adv-1k p50 1671ms, adv-10k p50 10547ms, page1 p50 9342ms, write p50 127ms vs git 31/40/130/27ms.
- Caveat: ambient peers share this checkout. Untracked `transport/lfs.rs` + `mirror.rs` (not wave-5) briefly broke `cargo test -p ruk-git` test-cfg compilation (`IngestLimits` import); their authors repaired it, and the two new transport tests plus the negotiated-options guard re-ran green on the final tree (3 passed, 0 failed). No ambient path was committed by this worker (`change.rs`, `commit.rs`, `records/*`, `workcopy/lfs.rs`, `parity-harness/*`, `transport/mod.rs` untouched).

## Follow-ups (post-review feedback, same session)
- Close latch order (`store/mod.rs`, own commit after `5ddcb85`): the latch now sets before the fallible sync, so a flush `Io` still refuses further publication. No deterministic test exists (fault injection covers dir syncs only); the close/reopen test re-ran green after the reorder.
- Fetch fairness (`run.sh`): `fetch_setup` and the fetch probe migrate the seeded bare clone for ruk backends, so the BLOCKED row names the true verb gap (`unknown option -q`) instead of the missing store. `RESULTS.md` regenerated from a clean solo re-run (ruk p50: adv-1k 1689ms, adv-10k 9674ms, page1 10406ms, write 160ms).
- Oplog gate (`check-structure.sh`): split into `oplog-walker` (`walk_oplog_page` in `hosted.rs`) and `oplog-visit-bound` (`MAX_PAGE_SIZE`), each with its own evidence line; `ABSENT=0`.
- Attribution disclosure: commit `5ddcb85` swept one foreign hunk — MutW01's `prepare_for_dispatch` + `PrepareContext` import in `hosted.rs` landed in the working tree between this worker's last purity check and the commit. The tree holds exactly one copy, MutW01's `944f2ba` builds on it, and MutW01 acknowledged no harm. Not rewritten (shared stacked history, no-rebase rule); recorded here instead.
- M3 note: the dead `staged.current.take()` removal stays inside `edff88a` (compaction concern, disclosed in its message) rather than restored; reverting would reintroduce dead code the review itself flagged.
