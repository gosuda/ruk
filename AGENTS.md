# ruk: agent rules

Rules for agents that change this repository. These rules cover `crates/`, `.github/`, and top-level docs. The zero-JS, operation-table, store, and Ruk-client rules belong to rukie and do not apply here.

## Scope

- Do not change `git/`, `jj/`, `forgejo/`, or `tasks/`. `.gitignore` marks them as reference oracles, "never part of this repository". [David Parnas]

## Build, test, and lint

- Build with the toolchain pinned in `rust-toolchain.toml`, Rust 1.99.1. [John Carmack]
- Before you claim a Rust change works, run the three CI gates exactly as written. Format: `cargo fmt --all -- --check`. Lint: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`. Test: `cargo nextest run --workspace --locked`. The brief's short forms (`cargo fmt --check`, `cargo clippy`, `cargo nextest run --workspace`) name these same gates. Read each exit status. [Richard Feynman]
- Suppress a lint only with an `expect` attribute that gives a reason. Do not relax the lint tables in `Cargo.toml`, and do not use `allow` attributes; `allow_attributes` is denied. [Edward Tufte]

## Unsafe code

- Unsafe code in workspace crates follows the pattern the lints require: an `expect` attribute naming `unsafe_code` with a reason, and a `// SAFETY:` comment that names the invariant. `Cargo.toml` denies `undocumented_unsafe_blocks`. [Tony Hoare]
- Vendored crates under `crates/ruk-core/vendor/` are outside this pattern. [David Parnas]

## Comments and errors

- Add no comments to implementation code, except the `// SAFETY:` comment that `undocumented_unsafe_blocks` requires. Leave existing comments alone unless you change that code. [Dieter Rams]
- Library crates return typed errors built with `thiserror`. Add context when an error crosses a crate boundary. [John Carmack]

## Commits and docs

- Write each commit subject in capitalized imperative. Keep it to 72 characters, target 50, with no trailing period. Wrap the body at 72 characters and say what changed and why, never how. [Claude Shannon]
- Each commit MUST hold one concern and MUST build with its tests passing. [Edsger W. Dijkstra]
- Commit with the global git identity. Pass no per-command identity, and add no trailer that names an agent. [Kenya Hara]
- Do not rewrite published history unless the user asks. Push fixes as new commits. [Christopher Alexander]
- Write README, CLI help, and tutorials in ISO 24495-1 plain language. [Milton Erickson]
- Write design notes, ADRs, and these rules in ASD-STE100: one meaning per word, one instruction per sentence. [J.R.R. Tolkien]
