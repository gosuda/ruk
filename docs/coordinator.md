# Per-repository coordinator sidecar

One coordinator process per repository batches commit publications across
CLI processes through the single linearizable publication lane
(`HostedCoordinator` + `git.commit` lane method).

## Semantics

- **Single writer per repository.** The server wins the store-directory
  ownership lock, binds `<repo>/.ruk/coordinator.sock`, and serves until its
  idle TTL (`RUK_COORDINATOR_IDLE_MS`, default 5000 ms) lapses or it is
  terminated. The lock is an OS-advisory flock released by the kernel on
  crash, so a killed coordinator never wedges the repo: the next starter
  takes over the stale socket after a refused connect.
- **Store lives only in bursts.** An idle server holds the socket and the
  lock but no store handle (bursts retire 50 ms past the last submission),
  so reads and direct publishes never starve behind a retained redb lock.
- **Idempotent replays.** Delivery is at-least-once; every submission
  carries the caller's stable request id. Replays hit the lane's receipt
  ledger (same session, same id), and the `git.commit` producer skips its
  ref transaction when the commit already landed and the ref already holds
  it, so cross-generation retries succeed instead of failing their own CAS.
- **Fallback contract.** The coordinator is an accelerator: pre-submit
  failures publish directly with identical arguments; post-submit failures
  replay the same id first and only then resolve (landed check, else direct
  publish). A crashed coordinator never loses a commit. `RUK_COORDINATOR`
  selects `auto` (default), `off` (direct, for tests/debugging), or
  `required` (hard-fail when unreachable).
- **Atomic commit plus ref move.** The lane publishes staged objects, change
  facts, and the branch compare-and-swap in one batch; a kill between them
  is impossible. Lost branch races return `E_STALE`, and the CLI retries
  with a fresh tip (up to three times) before reporting the conflict.

## Batched vs unbatched

Through the lane: `commit` (incl. `--amend`), `am`, `merge`, `cherry-pick`
(via the shared commit helper), and `stash push` (its two commits; slot,
rows, and index rewrite stay direct).

Still direct: tree/index/blob staging (content-addressed object writes that
must precede the lane — the lane records pre-staged trees), `rebase`,
`revert`, `notes`, `tag`, `update-ref`, `fast-import`, reflogs, and
detached-HEAD advances (no ref producer on the lane).

## Consistency notes

- Publication is linearizable (single lane owner); receipts make every
  consumer idempotent because exactly-once delivery does not exist.
- Commit plus ref move commit atomically in one batch (the transactional
  unit); no cross-service saga is needed because one lane owns the write.
- Under a sustained commit storm, opens contend on the store lock (bounded
  by `RUK_OPEN_TIMEOUT_MS`, 10 s default); `RUK_COORDINATOR=off` escapes to
  unbatched direct publishes.
