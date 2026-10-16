# Ruk subagent execution ledger

## Prerequisites
Anchor: Richard Feynman, Tony Hoare

Repository started with no commits and no remote. No prior implementation exists. Rust 1.99.1 installed with rustfmt and clippy. cargo-nextest 0.9.148 and Go 1.27.2 are available. redb 4.4.0 resolved. Reference Git, jj, and Forgejo sources remain excluded by .git/info/exclude.

The approval prompt selected the bounded Forgejo table revision after timeout. The revised contract adds only surfaces already required by merge-policy and result specifications. Exact files must be inventoried before implementation; later additions still need a revision. Evidence: local://ruk-patch-boundary-decision.md.

No publishing destination is configured. No remote write, live migration, or reference-source removal is authorized by this ledger.

## Ordered slices

- [x] 1. Workspace and model [Tony Hoare, David Parnas]
- [ ] 2. Durable store [Tony Hoare, John Carmack]
- [ ] 3. Coordinator and leases [Tony Hoare, Edsger W. Dijkstra]
- [ ] 4. Native workspaces [Tony Hoare, John Carmack]
- [ ] 5. Graph and refs [Claude Shannon, John Carmack]
- [ ] 6. Native changes and merge [Tony Hoare, David Parnas]
- [ ] 7. Agent protocol and publication policy [Tony Hoare, David Parnas]
- [ ] 8. Git object exchange [Richard Feynman, Tony Hoare]
- [ ] 9. Strict Git workspace and command interpreter [Tony Hoare, Christopher Alexander]
- [ ] 10. Forgejo daemon and patch [David Parnas, Christopher Alexander]
- [ ] 11. Receive and application parity [Christopher Alexander, Tony Hoare]
- [ ] 12. Retention and maintenance [Tony Hoare, John Carmack]
- [ ] 13. Migration and full verification [Richard Feynman, John Carmack]
- [ ] 14. Capacity acceptance [John Carmack, Richard Feynman]

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

Commit `dd0127a` adds the durable object and fact store. Commit `7b290f1` adds the bounded Forgejo initialization inventory revision. The required JSON-policy migration remains open, so slice two is not yet complete.

Parent verification passed: formatting, strict Clippy, all 449 nextest tests, cargo test, workspace build, and the external public-API consumer for both hash kinds. The consumer verified exact object bytes, conditional publication, resource admission, concurrent reads and writes, and reopen cycles. Publication and recovery crash tests passed, including real segment-sealing boundaries.

The workspace and Windows-only tests compiled for `x86_64-pc-windows-gnu`. No Windows or macOS runtime or hardware power-loss proof is claimed. Windows initialization requires a caller-provisioned durable parent and an absent root. Opening flushes the validated format after metadata ownership is acquired. A reported flush failure is not repaired by reopening.

Fresh bounded reviews found no remaining actionable storage defect. Full evidence and failed-before corrections are in `local://ruk-store-gate-evidence.md`. The revised inventory has 81 files and 24 compatibility gates. Parent verified its counts, references, and pinned initialization declaration. Forgejo behavior remains unimplemented.
