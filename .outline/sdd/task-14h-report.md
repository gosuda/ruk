# Task 14h report — Slice-14 capacity harness scaffolding

## Status

Done. `tasks/capacity/` scaffold built, first measurement run recorded,
structural gates checked. No product-code changes.

## Files (all under `tasks/capacity/`)

- `gen-fixture.sh` — deterministic fixture generator (seed `0x52554b01`,
  `--shape mixed`, steps 1k/10k; 100k/1M behind `--full`).
- `run.sh` — 7-workload measurement runner (adv-1k/adv-10k, lookup, page1,
  write, clone, fetch) vs git AND ruk (`ruk git`, parity-harness pattern);
  3 warm-ups + measured reps, p50/p95/p99 via python3; regenerates
  `RESULTS.md` from observed output. Optional `--hyperfine` cross-check.
- `check-structure.sh` — static gate checker: STATIC-PRESENT / ABSENT /
  NEEDS-RUNTIME-PROOF per mandatory-structural gate. Result: **0 ABSENT**.
- `README.md` — what is measured, dev-vs-profile gap table, full-run remains.
- `RESULTS.md` — first run, generated 2026-10-18T01:09Z.

## First-run headline numbers (git baseline, warm single-host CLI ms)

adv-1k p50 31 / adv-10k p50 38 (60 kB / 600 kB) / lookup p50 9 /
page1 p50 129 / write p50 27 / clone ~1.3 s / fetch p50 85.
Ruk side: **BLOCKED** — `target/debug/ruk` absent; `cargo build -p ruk`
fails on pre-existing `ruk-git` errors (`push_options`/`offer_push_options`
not in scope, sibling-owned files). Git baseline runs regardless.

## Unreachable at dev scale

100k/1M branches, GiB-scale repos, 1000 ops/s open-loop load, heavy jobs,
burst/recovery/soak, crash-around-publish, HTTP 429/503, cgroup/disk
budgets, daemon admission accounting (CLI has no admission layer:
offered=reps, rejected=0 by construction).

## Concerns

1. First run caught 4 harness bugs (date-%N portability → EPOCHREALTIME
   clock; `{`/`]` JSON mismatch; clone warmup>reps; SIGPIPE-to-head);
   all fixed and re-run green — but review `run.sh` rep fns once more
   before trusting a full-profile run.
2. `ruk git` on git-format fixture clones may fail once ruk builds
   (format mismatch); reps will record it as completed<offered — validate
   then, consider a `ruk migrate` setup path.
3. `shellcheck`/`shfmt`/`bats` not installed here; scripts follow the
   shell rules manually — gate on them in CI.
