# Ruk subagent execution ledger

## Prerequisites
Anchor: Richard Feynman, Tony Hoare

Repository started with no commits and no remote. No prior implementation exists. Rust 1.99.1 installed with rustfmt and clippy. cargo-nextest 0.9.148 and Go 1.27.2 are available. redb 4.4.0 resolved. Reference Git, jj, and Forgejo sources remain excluded by .git/info/exclude.

The approval prompt selected the bounded Forgejo table revision after timeout. The revised contract adds only surfaces already required by merge-policy and result specifications. Exact files must be inventoried before implementation; later additions still need a revision. Evidence: local://ruk-patch-boundary-decision.md.

No publishing destination is configured. No remote write, live migration, or reference-source removal is authorized by this ledger.

## Ordered slices

- [ ] 1. Workspace and model [Tony Hoare, David Parnas]
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
