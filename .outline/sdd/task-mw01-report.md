# Task MW01 report — mutation-translation W0 + W1

Status: done. W0 and W1 implemented, tested, and committed separately.

## SHAs

- W0 (`PrepareContext`, dispatch glue): `37d4e7c` (prepare.rs + daemon/mod.rs).
  The hosted.rs hunk (`prepare_for_dispatch`) landed inside peer commit
  `5ddcb85`, which swept the shared tree mid-edit; verified byte-identical
  to the authored hunk, no re-apply needed.
- W0 fixup (defer policy/claim-clock loads): `944f2ba`.
- W1 (5 ref/data arms + proofs): `262fba0`.

## Newly covered (W1, 5 entries)

- `bookmark.set` change-target arm — resolves `ChangeRef` via the stored
  change entry (`E_NOT_FOUND` unknown change, `E_STALE` foreign pin,
  `E_DIVERGENT` unpinned multi-head, `E_INVALID` conflicted head), then the
  existing `check_ref_update` path. Reply target is the resolved `Oid`.
- `tag.set` annotation arm — renders canonical git tag payload
  `object <oid>\ntype commit\ntag <short>\ntagger Name <email> <secs> +0000\n\n<msg>`,
  hashes with `hash_git_object("tag")`, stages via `Store::prepare`
  (skipped when already stored), ref points at the tag object.
  Tagger = annotation else session identity else `E_INVALID`; clock absent
  (legacy path) = named `E_HOSTED`.
- `pin` / `unpin` — exact-expectation `Pins` facts keyed by
  `records::head_key` (presence = empty value). Unstored pin target and
  missing pin are `E_NOT_FOUND`; re-pin fails stale at publish on `Absent`.
- `attest.add` — `attestation::prepare_add` with the caller's checkpoint;
  facts + `AttestAddReply.record` from the single prepared record.
  No checkpoint (legacy path) = named `E_HOSTED` with the old catch-all text.

## Still refused (named reasons, unchanged)

`new`, `describe`, `edit`, `split`, `squash`, `rebase`, `abandon`,
`resolve`, `revert` (ops-backed, per-arm messages intact),
`claim.acquire`/`claim.release` (lane-owned sealer), `ws.*`,
`snapshot`, `write`, `fetch`, `push`, `land.*`, `undo`, `op.prune`
(catch-all). Proven by `full_context_still_refuses_future_waves` (full
context unlocks only W1) plus the unchanged ops-backed/refusal suites.

## Deviations from mutation-translation-design.md (with reasons)

1. `PrepareContext` fields are `Option` (doc: required refs) — keeps the
   legacy `prepare_mutation(store, session, request)` wrapper compiling for
   existing callers/tests. Arms refuse honestly when inputs are absent;
   dispatch always passes the full context.
2. Legacy wrapper serves store-only W1 arms (`bookmark.set` change target,
   `pin`, `unpin`); only clock/gate arms refuse there. Doc says W1 is
   independent and needs only the checkpoint — refusing store-only arms
   would invent missing inputs.
3. No new `coord/pins.rs`: key encoding already exists as
   `records::keys::head_key`; fact shaping is inline (~10 lines each).
4. `prepare_for_dispatch` does NOT load policy/claim-clock (W0 fixup):
   no W1 arm consumes them, and eager loads would fail covered mutations
   on unread rows. They wire up when W2 needs them.
5. Tag payload uses the short name (`refs/tags/` stripped); doc's `<name>`
   is ambiguous and git convention is the short name.
6. `attest.add` ships without a prepare-held subject lease (contested ×6;
   decided for ship): task orders prescribe the checkpoint path, the doc
   scopes W1 machinery to the checkpoint, and lease carriage
   (PreparedMutation → candidate → settle) needs lane/commit changes
   outside this lane's boundaries. Verified the collector exists
   (`leases/barrier.rs::begin_mark` over Head roots), so the residual
   prepare→submit window for unrooted subjects is real but narrow (batch
   commits atomically once submitted; facts are exact-CAS). Follow-up:
   registry acquire in prepare + release after settle.
7. No repo-wide `cargo fmt`: installed rustfmt wants import reorderings
   across untouched lines (pre-existing drift); new code matches
   file-local style instead.

## Test summary

- `nextest -p ruk-core coord::prepare`: 10/10 (5 new W1 proofs —
  change-target incl. stale/different/divergent/conflicted, tag incl.
  explicit/session/missing tagger + byte-exact payload pin, pin/unpin
  round-trip, attest incl. duplicate-idempotency + legacy refusal —
  plus future-wave refusal and all pre-existing tests).
- `nextest -p ruk-core -E 'test(coord::)'`: 241/241 (covers the touched
  hosted publish test, updated pin assertion).
- `nextest -p ruk` daemon pair: 2/2 (new annotated-`tag.set`
  socket test proving dispatch→context→render→publish; updated
  dispatch test now expects `E_NOT_FOUND` for unstored pin).
- Full `ruk-core` suite post-W0-fixup: 972 passed. `cargo check`
  clean for both crates. `ruk` bin had a transient peer-breakage
  window (uncommitted `FetchPlan::prune` field vs initializer, not this
  lane); healed before the W1 runs above.
