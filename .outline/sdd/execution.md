# Ruk ordered execution

The authoritative full plan is local://agent-native-git-plan.md. Its mandatory specifications remain binding. This file extracts the current task for the subagent workflow.

## Task 1: Workspace and model
Anchor: Tony Hoare, David Parnas

Create the three crates and locked dependencies, CI for Linux/macOS/Windows, typed IDs, Head, native conflict encoding, WorkspaceState, RefTarget, real index stages, capability grammar, and method schemas. Port the pinned jj algebra and license with exhaustive enumeration/property checks.

### Inputs and scope

Work in /home/alpha/rewrite/git-renewed. There is no product implementation. Own Cargo.toml, Cargo.lock, rust-toolchain.toml, .gitignore, .github/workflows/, crates/ruk-core/, crates/ruk-git/, crates/ruk/, and licenses/ as needed. Do not edit git/, jj/, forgejo/, the Forgejo patch inventory, .outline/ except your named report, or any mandatory specification.

Read all mandatory specs with local:// URIs: ruk-core-contract-plan.md, ruk-forgejo-contract-plan.md, ruk-forgejo-scale-plan.md, ruk-reference-production-profile.md, ruk-forgejo-source-evidence.md, ruk-forgejo-command-inventory.md, ruk-syntax-language-plan.md, ruk-composed-file-merge-plan.md, ruk-grammar-abi-evidence.md. Use local://ruk-native-preflight.md for exact jj reuse anchors. Full ordered plan: local://agent-native-git-plan.md.

Rust 1.99.1, edition 2024, resolver 3. The exact toolchain is installed with rustfmt/clippy. cargo-nextest 0.9.148 is available. redb 4.4.0 resolves. Pin dependencies exactly to approved versions where listed; add only dependencies required by this slice. Std-first for small port support instead of bringing jj's internal ContentHash machinery. Retain jj Apache license and attribution. Do not rewrite the semantics of its merge algebra.

### Contracts

Dependency direction ruk -> ruk-git -> ruk-core. Native schemas derive serde/schemars; errors use thiserror, anyhow only at executable boundary. Core denies unsafe code; git forbids it. No source stub, todo!, unimplemented!, no-op, runtime Git fallback, or pretend working native operations. CLI may expose the actually implemented model schema/encoding through a real narrow command; do not advertise later operations as implemented.

Use gix hash IDs for exact SHA-1/SHA-256 identity. A repository has one fixed hash kind. Include tagged Head, change/operation/workspace/session/request/plan/lease identities, checked counters, CommitRecord and native conflict-v1 encoding, byte-authoritative imported Git payloads, actual index stage state and exclusivity, validated ref targets/names, native versus GitCompat state, authorization capability grammar, and typed request/reply schemas for specified methods. Preserve unknown optional fields as specified; reject invalid states at deserialization boundaries. SameChange::Keep is default. Native conflict keys must use canonical conflict framing and repository hash kind; no placeholder Git trees.

Public schemas must not erase byte paths, unmerged stages, ambiguity, applicable stamps, or typed mutation arguments into untyped JSON maps. The one merge-notice record belongs at ruk-core::merge::composed and every future surface reuses it unchanged. Mode/language_set_version belong in result metadata as required. Implement only model-level validation/encoding now, not fake operational handlers.

### Verification and report

Add adversarial and invariant tests for malformed IDs/refs/index stages/capability inputs, conflict encoding, imported byte fidelity, counter overflow, and jj exhaustive/property algebra. Reuse independent pinned jj enumeration semantics. No source-text or wiring tests.

Skip builds, tests, lint, and formatters during implementation; parent runs them once at the barrier. Do not commit. Parent owns atomic commits and verification. Report exact recommended commands and runnable smoke input/expected behavior. Parent gates: cargo fmt --check; cargo clippy --workspace --all-targets --all-features --locked -- -D warnings; cargo nextest run --workspace --locked; cargo test --workspace --locked; actual CLI model/schema smoke with valid and malformed inputs. Missing pins or incompatible dependencies are blockers, never silent substitutions.

Write full implementation report to local://ruk-slice-1-report.md. Return DONE, DONE_WITH_CONCERNS, NEEDS_CONTEXT, or BLOCKED with exact residual issues. Never call a subset complete.

### Stance limits

Offense stays inside the surface the request touches. A half-rebuilt state never ships: finish it or revert it. Formal rigor goes where a plausible defect breaks an invariant: trust boundaries, state lifecycles, concurrency, money, parsers, protocols. Minimalism keeps each useful part. One shallow level, never two layers between the same caller and the same operation. Reject a seal that costs more than half the complexity it hides.
