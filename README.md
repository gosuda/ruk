# Ruk

Ruk is an agent-native version control system built in Rust with exact Git SHA-1 and SHA-256 object interoperability, transactional repository state (`redb` metadata and zstd-compressed, CRC32C-framed object segments), isolated concurrent workspaces, first-class conflict records, and a typed v1 agent protocol. It provides a Git-compatible CLI (`ruk git`), a stdio Model Context Protocol server (`ruk mcp`), and a hosted multi-repository daemon (`ruk forgejo serve`) targeting Forgejo through a bounded backend patch.

- **Agent-native protocol**: 46 v1 protocol method schemas (`ruk model`) and a stdio MCP server (`ruk mcp`). Coordinator mutation translation serves `new`, `edit`, `ws.scope`, `ws.take`, `ws.drop`, `describe`, `split`, `squash`, `rebase`, `abandon`, `resolve`, `revert`, `undo`, `claim.acquire`, `claim.release`, and `land.prepare` over a single serialized `PublicationLane` per repository (2ms group-commit linger, up to 64 requests or 64 MiB per batch), with 30-second lease-bound cursors on `op.log`, `claim.list`, and `attest.list` and 7-day idempotent mutation receipts (`FactTable::Receipts`).
- **Native conflict algebra**: First-class `conflict-v1` records (`ruk encode-conflict`, `ruk decode-conflict`) preserve ordered `+`/`-` tree terms, parents, signatures, and headers without adding headers to exported Git commits, paired with syntax-aware merges across 21 pinned Tree-sitter grammars plus Markdown and MDX.
- **Git CLI and wire interop**: `ruk git <verb>` (or invoking the binary as `git`) dispatches 58 advertised verb names in `crates/ruk/src/cli/dispatch.rs` (48 implemented or served, 3 partial (`cherry-pick`, `rebase`, `revert`), and 7 unsupported (`archive`, `bundle`, `count-objects`, `gc`, `index-pack`, `pack-objects`, `worktree`), passing 56/56 scripted scenario checks against Git 2.53.0 in `tasks/parity-harness/GAPS.md`). `ruk git migrate` imports existing `.git` repositories (loose objects, pack v2/v3, refs, and `HEAD`, 73/73 checks passing in `tasks/migration/RESULTS.md`), while `ruk-git` supports transport over local paths, `file://`, `ssh://`, and `git://` (`http(s)://` is a named unimplemented gap).
- **Verified storage integrity**: Every segment record carries a CRC32C header-and-payload checksum, and sealed segments end with a 24-byte `RUKSEAL1` CRC32C footer. `Store::open` validates segment manifests on every open, caches `verified_generation` in committed metadata so repeat opens skip full object-hash sweeps, and supports `RUK_VERIFY=full` to force full parallel object-identity verification on every open (exercised across 7 publication and recovery kill points in `crates/ruk-core/src/store/crash_tests.rs`).
- **Measured dev-scale capacity**: In warm-cache CLI benchmarks on an 80-CPU, 754 GiB host (`tasks/capacity/RESULTS.md`, not the reference deployment or open-loop daemon load), Ruk p50 vs. Git 2.53.0 p50 is **22ms vs. 47ms** on `adv-1k` (2.1x faster) and **98ms vs. 149ms** on `page1` (1.5x faster), **61ms vs. 54ms** on `adv-10k`, **49ms vs. 10ms** on single-ref `lookup`, **49ms vs. 28ms** on `write`, **6.94s vs. 1.38s** on 10k-branch bare `clone`, and **990ms vs. 87ms** on incremental `fetch`.

## Usage example

```bash
ruk git init repo && printf 'one
' > repo/f.txt
ruk git -C repo add f.txt
ruk git -C repo -c user.name=Ada -c user.email=ada@example.invalid commit -m seed
ruk git -C repo hash-object f.txt
ruk git -C repo config user.nick ada && ruk git -C repo config user.nick
ruk git -C repo status --porcelain
# Initialized empty Ruk repository in /tmp/repo/.ruk/
# 9117217ff36c2893110e6526d217e9596b16bb85
# ada
```

---

## Getting started

Build the release binary with Cargo (requires Rust 1.99.1 per `rust-toolchain.toml`):

```bash
cargo build --release
```

This produces `target/release/ruk`. Initialize a repository, stage a file, and commit through the Git-compatible CLI:

```bash
./target/release/ruk git init my-repo
printf 'hello world
' > my-repo/README.txt
./target/release/ruk git -C my-repo add README.txt
./target/release/ruk git -C my-repo -c user.name="Your Name" -c user.email="you@example.com" commit -m "first commit"
./target/release/ruk git -C my-repo log --oneline
```

To import an existing Git repository into a co-located `.ruk` store without modifying `.git`:

```bash
./target/release/ruk git migrate /path/to/git-repo
```

---

## Command surface

`ruk` exposes native protocol, conflict, and service subcommands alongside the `ruk git` compatibility dispatcher:

| Command | Purpose |
|---|---|
| `ruk git <verb> [args...]` | Run the Git-compatible CLI interpreter (`init`, `add`, `commit`, `status`, `diff`, `log`, `branch`, `checkout`, `merge`, `stash`, `migrate`, `fetch`, `push`, and 45 other advertised verbs). |
| `ruk new --repo <path> [--input <file\|->]` | Create a native commit atomically from a JSON `NewRequest` document. |
| `ruk describe --repo <path> [--input <file\|->]` | Describe a commit or change from a JSON `DescribeRequest` document. |
| `ruk model [--format json]` | Emit the draft 2020-12 JSON Schema for the v1 protocol, error codes, and 46 method contracts. |
| `ruk encode-conflict` / `ruk decode-conflict` | Convert between JSON `ConflictRecordInput` documents and binary `conflict-v1` records (`--object-format sha1\|sha256`). |
| `ruk mcp --repo <path>` | Serve the typed operation table over stdio as a Model Context Protocol (JSON-RPC 2.0) server. |
| `ruk forgejo serve --config <path.toml>` | Run the hosted multi-repository Unix-socket daemon for Forgejo. |

---

## Capacity benchmarks (dev-scale)

Measured by `bash tasks/capacity/run.sh` (`tasks/capacity/RESULTS.md`, commit `8487835b`, seed `0x52554b01`, warm cache, 80 CPUs / 754 GiB RAM). These are single-host CLI wall times, not the reference deployment hardware and not open-loop daemon admission under load:

| Workload | Ruk p50 (ms) | Git 2.53.0 p50 (ms) | Notes |
|---|---:|---:|---|
| `adv-1k` | 22.0 | 47.0 | 1,000-branch ref advertisement (`60,057` bytes) |
| `adv-10k` | 61.0 | 54.0 | 10,000-branch ref advertisement (`600,057` bytes) |
| `lookup` | 49.0 | 10.0 | Single ref resolution (`refs/heads/b005000`) |
| `page1` | 98.0 | 149.0 | First commit log page (`rows=20`) |
| `write` | 49.0 | 28.0 | Single-path commit write (`paths=1`) |
| `clone` | 6940.0 | 1376.0 | Bare `file://` clone of `large-10000` |
| `fetch` | 990.0 | 87.0 | Incremental fetch (`+1` branch; includes first-open verification) |

---

## Workspace layout

- `crates/ruk-core`: Native v1 data model, jj-derived conflict algebra, composed and Tree-sitter syntax merge engines, `redb` + segment `Store`, revset engine, and coordinator (`PublicationLane`, sessions, leases, claims, receipts, `op.log`, `undo`).
- `crates/ruk-git`: Exact Git object import/export, pack v2/v3 streaming ingest and generation, pkt-line wire protocol (`upload-pack`, `receive-pack`, `upload-archive`), and `file://`, `ssh://`, and `git://` transports.
- `crates/ruk`: The `ruk` binary, including the Git-compatible CLI (`crates/ruk/src/cli/`), MCP stdio server (`crates/ruk/src/mcp/`), and Forgejo multi-repository daemon (`crates/ruk/src/daemon/`).

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
