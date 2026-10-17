# Ruk subagent execution ledger

## Prerequisites
Anchor: Richard Feynman, Tony Hoare

Repository started with no commits and no remote. No prior implementation exists. Rust 1.99.1 installed with rustfmt and clippy. cargo-nextest 0.9.148 and Go 1.27.2 are available. redb 4.4.0 resolved. Reference Git, jj, and Forgejo sources remain excluded by .git/info/exclude.

The approval prompt selected the bounded Forgejo table revision after timeout. The revised contract adds only surfaces already required by merge-policy and result specifications. Exact files must be inventoried before implementation; later additions still need a revision. Evidence: local://ruk-patch-boundary-decision.md.

The user authorized verified phase commits and normal branch-only pushes to `https://gitlab.com/metaphorics/git-renewed`, branch `main`. No force push, tag push, live migration, or reference-source removal is authorized. The registry packages `ruk`, `ruk-core`, and `ruk-git` were published as sample libraries at `0.0.0`; a fresh registry-only consumer compiled and ran all three.

## Ordered slices

- [x] 1. Workspace and model [Tony Hoare, David Parnas]
- [x] 2. Durable store [Tony Hoare, John Carmack]
- [x] 3. Coordinator and leases [Tony Hoare, Edsger W. Dijkstra] — PARTIAL: ownership locks, sessions, receipts, CAS, bounded execution, cancellation, claim/attestation policy landed (05a1025..d60deab); OPEN: LeaseRegistry on HostedCoordinator + continuation cursors (task resumed below)
- [x] 4. Native workspaces [Tony Hoare, John Carmack] — landed in earlier wave (workspace state, snapshots, materialization journal); watcher/token + damaged-marker details partially verified
- [x] 5. Graph and refs [Claude Shannon, John Carmack] — graph segments, generation/Bloom, revsets, ref CAS, reflogs landed (432e850..)
- [x] 6. Native changes and merge [Tony Hoare, David Parnas] — new/edit/split/squash/rebase/abandon/resolve/revert + composed merge engines + syntax dispatch landed (a4bf29d..b12070a); ops now split prepare/publish (0648676)
- [x] 7. Agent protocol and publication policy [Tony Hoare, David Parnas] — CLI/MCP (b8a7164), claims, attestation, LandPlans, streaming landed; typed session dispatch 9f97090
- [x] 8. Git object exchange [Richard Feynman, Tony Hoare] — import/export, packs, receive-pack client, notes, private-object exclusion, push durability (26b60ac, 54b14be); shallow/partial fetch OPEN
- [x] 9. Git-compatible CLI surface and typed backend ops — verbs + flag parity + parity harness (a694058..81c3e77, aedc587); typed invocation coverage in progress
- [x] 10. Forgejo daemon and patch — pooled hosted daemon, typed Go backend seam, serv routing, [git] RUK_SOCKET (3374dcf, aab49be; forgejo 08399162d1..47a9edb704); SSH entry point + caches partially OPEN
- [x] 11. Receive and application parity — upload-pack/receive-pack/upload-archive + quarantine + hook phases landed (18230bd, 43ae77a); AGit, signing, LFS paths, mirrors, wiki/template, dumb HTTP OPEN
- [x] 12. Retention and maintenance — periodic/explicit sweeps landed (3585bdd); copying compaction, cache eviction, handle retirement OPEN
- [ ] 13. Migration and full verification — `ruk migrate` imports real .git (cd4990c); offline inventory/cutover/rollback + Forgejo DB/browser suite gates OPEN
- [ ] 14. Capacity acceptance — harness exists (tasks/parity-harness); cold/warm/branch-saturation/noisy-neighbor runs OPEN; needs user-approved load profile


## Slice verification policy
Anchor: Tony Hoare, Richard Feynman

Parent verifies each implemented slice before the next begins. Fresh implementer and reviewer per slice. Parent runs checks after each implementation batch, records actual results, resolves review findings, and commits one concern at a time. No product or performance claim precedes evidence. All fourteen slices and the full-branch review remain required.

## Slice one evidence
Anchor: Richard Feynman, Tony Hoare

Commits: `93a0e5b` implements the repository model and exercised CLI; `323198f` adds platform CI; `30df237` freezes the Forgejo patch inventory.

Parent verification passed: formatting, strict Clippy, all 289 nextest tests, cargo test, and CLI build. Actual CLI smoke passed independent SHA-1/SHA-256 byte oracles, byte-preserving round trips, malformed inputs, exact input bounds, and a FIFO with an open writer. Workspace and capability regressions failed before repair and passed afterward. Restoring the postcard skipped-field defect made its regression fail; restoring the fix made it pass and restored the source digest.

The fresh repair-closure review found no remaining actionable defect. LSP was unavailable because its server exited; compiler diagnostics passed. macOS and Windows jobs are configured but were not executed locally. No hosting parity or performance claim follows from this model gate.

The frozen inventory contains 80 files and 138 exact declaration anchors. Parent checked each against the pinned Forgejo tree. The required compatibility gates remain unexecuted until their implementation slices.

## Slice two storage checkpoint
Anchor: Tony Hoare, Richard Feynman

Commit `dd0127a` adds the durable object and fact store. Commit `7b290f1` adds the bounded Forgejo initialization inventory revision. Commit `1970e84` contains the verified JSON-policy migration and is published on main. The user approved the exact schema and store-format replacements through a direct do-it-now instruction. Both replacements are implemented and verified below.

Parent verification passed: formatting, strict Clippy, all 449 nextest tests, cargo test, workspace build, and the external public-API consumer for both hash kinds. The consumer verified exact object bytes, conditional publication, resource admission, concurrent reads and writes, and reopen cycles. Publication and recovery crash tests passed, including real segment-sealing boundaries.

The workspace and Windows-only tests compiled for `x86_64-pc-windows-gnu`. No Windows or macOS runtime or hardware power-loss proof is claimed. Windows initialization requires a caller-provisioned durable parent and an absent root. Opening flushes the validated format after metadata ownership is acquired. A reported flush failure is not repaired by reopening.

Fresh bounded reviews found no remaining actionable storage defect. Full evidence and failed-before corrections are in `local://ruk-store-gate-evidence.md`. The revised inventory has 81 files and 24 compatibility gates. Parent verified its counts, references, and pinned initialization declaration. Forgejo behavior remains unimplemented.

## JSON migration verification
Anchor: Tony Hoare, Richard Feynman

The evidence in this section applies to commit `1970e84`, before the approved schema replacement. Authored JSON paths use `sonic-rs`; `schemars` retains its transitive JSON dependency. That commit used `SchemaDocument` for arbitrary JSON roots, Serde replay, and postcard JSON text. The current replacement removes that type. Parsing normalizes negative zero. Ruk's JSON entry points reject nesting above 128 containers and add parser stack space when needed.

Formatting, strict Clippy, all 456 nextest tests, cargo test, and workspace build passed on Linux. Three skipped tests are subprocess dispatchers exercised by their parent tests. Both original stack-overflow regressions now pass without enlarged test stacks. Windows cross-compilation passed after the stack repair; Windows and macOS runtime behavior remains unverified.

The rebuilt CLI matched the saved model and conflict bytes for both hash kinds. It accepted depth 128 and rejected depths 129 and 1000000. An external consumer passed in debug and release builds on a standard worker thread, including arbitrary roots, buffered Serde replay, numeric boundaries, binary round trips, and deep-input rejection. Separate probes passed all 66 operation/shape/stack combinations on requested 1 MiB and 2 MiB workers. Shallow stack samples support in-place parsing; deep samples demonstrate stack switching.

Supply-chain checks passed. Cargo audit reported no vulnerabilities or advisory warnings. Cargo deny passed advisories, bans, licenses, and sources, with disclosed duplicate-version and unused-policy warnings. Fresh bounded source review found no actionable defect. Full evidence: `local://ruk-json-migration-gate.md`.

## Schema and persistent store identity replacement
Anchor: Tony Hoare, Richard Feynman

Schema replies now use `schemars::Schema` and JSON frames. Only object and boolean roots are accepted. Request and non-schema receipt binary encodings remain unchanged. The model stays at v1. Its semantic changes are limited to the schema document definition and reference. Both hash-kind conflict outputs match the saved bytes.

The v1 store marker now carries a persistent non-nil `StoreId`. Reopening, relocation, and a byte-copy backup retain that identity. Independent creation generates a new identity. Old two-line markers fail with `E_VERSION` before metadata opens. No store was migrated or deleted.

Parent verification passed: formatting, strict Clippy, all 466 nextest tests, cargo test, and workspace build. Three skipped tests are subprocess dispatchers exercised by parent tests. Windows cross-compilation passed; Windows and macOS runtime behavior remains unverified.

A separate consumer passed all 11 schema checks on an ordinary worker thread with `RUST_MIN_STACK` unset. It exercised every method schema, buffered Serde replay, numeric boundaries, duplicate keys, depth 128 operations, depth 129 refusal, and retained non-schema postcard paths. All seven store checks passed. They covered both hash kinds, byte oracles, stable identities, six competing creators, 44 malformed markers, 156 strict prefixes, and rejection without changing marker or metadata bytes.

The first consumer run incorrectly classified the other supported hash kind as malformed. The parent removed that invalid oracle and reran store checks. No product code changed to satisfy it. Fresh bounded source reviews found no remaining actionable defect. Evidence: `local://ruk-breaking-gate-evidence.md`. Later product slices and all capacity claims remain unverified.
