# Ruk

Ruk is an agent-native version-control system designed for exact Git object interoperability, native transactional state, efficient concurrent workspaces, recoverable merge conflicts, and a typed agent protocol. It also targets Forgejo as a first-class consumer through a bounded backend patch.

## Current Executable Scope

The current `ruk` executable implements three commands covering data models, schema reflection, and native conflict record encoding:

* `ruk model`
* `ruk encode-conflict`
* `ruk decode-conflict`

This executable slice does not accept repository operations. Commands such as commit, checkout, branch, merge, push, or fetch are not yet implemented. The JSON schema emitted by `ruk model` defines the method interfaces and framing parameters for the planned agent wire protocol, but those schemas represent interface contracts rather than operational method implementations.

External Git and Forgejo checkouts used alongside this repository serve as development oracles and reference specifications. Ruk does not invoke the `git` binary at runtime and has no runtime dependency on Git or Forgejo.

## Building

Build the `ruk` CLI binary using Cargo with locked dependencies:

```bash
cargo build -p ruk --locked
```

The compiled binary will be placed at `target/debug/ruk` (or `target/release/ruk` when using `--release`).

## Command Reference

### `ruk model`

Outputs the protocol JSON schema document defining framing limits, closed error codes, supported object formats, and method definitions.

```bash
ruk model [--format json]
```

* `--format <json>`: Output schema format (default: `json`).

### `ruk encode-conflict`

Reads a JSON conflict description (`ConflictRecordInput`), validates field invariants and object identifier lengths for the selected hash kind, and writes the framed binary `conflict-v1` record to standard output.

```bash
ruk encode-conflict [--object-format sha1|sha256] [--input <path>]
```

* `--object-format <sha1|sha256>`: Hash algorithm of the target repository (default: `sha1`).
* `--input <path>`: Path to JSON input file, or `-` for standard input (default: `-`).

### `ruk decode-conflict`

Reads a framed binary `conflict-v1` record, validates framing headers and field bounds, confirms that re-encoding reproduces the input byte-for-byte, and outputs the canonical JSON representation to standard output.

```bash
ruk decode-conflict [--object-format sha1|sha256] [--input <path>]
```

* `--object-format <sha1|sha256>`: Hash algorithm of the target repository (default: `sha1`).
* `--input <path>`: Path to binary record file, or `-` for standard input (default: `-`).

## Conflict Record Format & Minimal Example

A native conflict record retains ordered tree terms with signs `+,-,+,...,+`, ordered parents, signatures, extra headers, and message bytes. The codec validates the record without accessing a repository.

### Minimal JSON Input (`conflict.json`)

This sample uses synthetic object IDs to demonstrate the encoding. It does not refer to existing repository objects.

```json
{
  "trees": [
    "1111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333"
  ],
  "parents": [
    {
      "type": "git",
      "oid": "4444444444444444444444444444444444444444"
    },
    {
      "type": "conflicted",
      "key": "5555555555555555555555555555555555555555"
    }
  ],
  "author": {
    "name": "A U Thor",
    "email": "author@example.com",
    "timestamp": 1700000000,
    "offset": "+0100"
  },
  "committer": {
    "name": "C O Mitter",
    "email": "committer@example.com",
    "timestamp": 1700000100,
    "offset": "-0000"
  },
  "extra_headers": [
    {
      "name": "change-id",
      "value": "lkonztmnvsxytrwkxpvuutrmompwylqq"
    }
  ],
  "message": "resolve later\n"
}
```

* **Trees**: Must contain an odd, non-zero number of real Git tree object IDs (40 hex characters for SHA-1, 64 hex characters for SHA-256).
* **Parents**: An array of `Head` references tagged with `"type"`. A Git commit parent is `{"type": "git", "oid": "<hex>"}`. A parent that is itself a native conflict is `{"type": "conflicted", "key": "<hex>"}`.
* **Signatures**: Contain `name`, `email`, numeric Unix `timestamp`, and `offset`. The timezone offset is a five-character string `[+-]DDDD` (such as `"+0100"` or `"-0000"`). The string representation keeps `-0000` distinct from `+0000`, matching Git ident rules.
* **Extra headers**: Key-value pairs sorted canonically by name then value. Structural headers (`tree`, `parent`, `author`, `committer`) are rejected. If omitted, `extra_headers` defaults to `[]`.

For a SHA-256 repository, provide 64-character hex strings for all tree IDs, parent OIDs, and conflict keys, and pass `--object-format sha256`.

### Encoding and Decoding

Encode the JSON file to framed binary `conflict-v1` format:

```bash
cargo run -p ruk --locked -- encode-conflict --object-format sha1 --input conflict.json > conflict.bin
```

Decode the binary record back to canonical JSON:

```bash
cargo run -p ruk --locked -- decode-conflict --object-format sha1 --input conflict.bin
```

Pipes and standard I/O roundtrips function identically:

```bash
cat conflict.json | cargo run -p ruk --locked -- encode-conflict --object-format sha1 | cargo run -p ruk --locked -- decode-conflict --object-format sha1
```

## Object and Fact Store

`ruk_core::store::Store` provides the storage library. Repository commands such as commit, checkout, branch, merge, push, and fetch are not yet implemented.

- **Prepare:** stream object bytes into bounded memory or disk spools. Use a committed local predecessor for delta compression when the delta meets the size threshold.
- **Publish:** append prepared objects to segments, flush their bytes and new entries, then commit object locators and conditional metadata facts together in redb. A stale condition rejects the whole batch before append. A failure after append begins closes the writer until recovery.
- **Read:** verify record checksums, decode content, and verify object identity. Release metadata transactions before payload I/O.
- **Recover:** verify committed extents and object identities on open. Truncate only an open segment's uncommitted tail. Refuse service on committed corruption rather than roll back acknowledged state.

The store preserves exact object bytes for both SHA-1 and SHA-256. Native conflicts remain distinct from Git objects. Resource reservations bound preparation and release with the prepared objects.

On POSIX, initialization synchronizes the existing ancestor chain before creating missing directories. On Windows, you must provide an already durable parent and an absent store root; merely creating the parent directory is not enough. Ruk publishes the owned root exclusively and refuses to adopt an existing or interrupted layout. Opening a store flushes its validated format marker before recovery. A reported filesystem flush failure may require operator storage recovery; reopening alone does not repair failed writeback.

## I/O and Framing Rules

* **Data on stdout, diagnostics on stderr**: Successful commands emit raw bytes to stdout (binary payload for `encode-conflict`, JSON text for `model` and `decode-conflict`). Diagnostics, error descriptions, and hints are written exclusively to stderr in the format `ruk: <message>`, followed by optional `hint: <text>` lines.
* **Exit codes**: Process exit codes correspond to Ruk's closed `ErrorCode` classification (e.g. status 1 for `E_INVALID`, `E_LIMIT`, and `E_IO`; status 2 for conflict states; status 3 for concurrency/lease conflicts; status 4 for transport/push rejections; status 5 for corruption).
* **String-or-hex byte encoding**: Git commit messages, paths, author names, and header values are arbitrary byte strings. When encoded as JSON, valid UTF-8 sequences render as standard JSON strings. Non-UTF-8 bytes render as `{"hex": "<lowercase hex>"}` objects. Both representations are accepted on input; valid UTF-8 strings are emitted whenever possible.
* **Bounded 16 MiB CLI input**: The CLI enforces `MAX_CONTROL_FRAME_BYTES` (16 MiB, or 16,777,216 bytes). Input streams (`--input`, standard input, files, or FIFOs) are bounded by reading at most `limit + 1` bytes (`read.take(limit + 1)`). If an input exceeds 16 MiB, Ruk terminates consumption immediately with `E_LIMIT` (`exit status 1`). A FIFO that exceeds the limit is rejected without waiting for its writer to close. A shorter stream still needs an end-of-file signal.
* **JSON nesting**: CLI conflict input, protocol envelope decoders, `ruk_core::protocol::decode_json`, and JSON text inside binary `SchemaDocument` values accept at most 128 open arrays or objects, counting the root. Deeper input fails with `E_INVALID`. The CLI and control-frame byte limits remain unchanged. The generic `decode_json` function does not impose a byte limit.
* **Rust JSON values**: Public value APIs use `sonic_rs::Value`. `SchemaDocument` accepts any JSON root and retains its postcard JSON-string representation. Use `protocol::decode_json` for bounded JSON parsing, including tagged, untagged, and flattened Serde containers. The parser adds stack space when needed. Direct third-party Serde decoding does not enforce Ruk's nesting limit or protect recursion outside the `SchemaDocument` visitor.
* **Negative zero**: Parsing normalizes `-0` and `-0.0` to positive zero, including JSON text embedded in binary `SchemaDocument` values. Exact floating-point parsing equivalence with other JSON libraries is not guaranteed.

## Verification Instructions

Developers can run workspace verification checks with Cargo:

```bash
# Run workspace behavioral test suite
cargo nextest run --workspace --locked

# Run strict clippy analysis across all targets
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Formatting, strict Clippy, and workspace tests passed on Linux. The CLI smoke covered both hash kinds, byte-preserving round trips, malformed input, and bounded file/FIFO reads. An external Rust consumer exercised the store's public APIs with independent byte and object-ID oracles, concurrent readers and writers, resource limits, and reopen cycles. Process-kill tests cover atomic publication and recovery at segment-sealing boundaries; they do not prove hardware power-loss durability.

An external JSON consumer verified bounded decoding, Serde replay, and binary document round trips on a standard Linux worker thread. Separate probes exercised 128-level array, object, and mixed documents on requested 1 MiB and 2 MiB worker stacks. The generated model and conflict outputs matched the saved pre-migration bytes.

The workspace, including Windows-only code and tests, also passed cross-compilation checks for `x86_64-pc-windows-gnu`. The [CI workflow](.github/workflows/ci.yml) defines macOS and Windows jobs. Those jobs were not executed during local verification, so runtime behavior on those platforms remains unverified.

See the [changelog](CHANGELOG.md) for implemented functionality. Repository operations remain outside this executable's current scope.
