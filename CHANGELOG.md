# Changelog

Entries describe implemented, unreleased functionality.

## [Unreleased]

### Added

- `ruk model` command rendering the draft 2020-12 JSON schema for the Ruk core protocol, including framing boundaries, the 30-code closed error registry, object formats, and 46 protocol method contracts.
- `ruk encode-conflict` command converting JSON `ConflictRecordInput` documents into byte-exact framed binary `conflict-v1` records for SHA-1 and SHA-256 repositories.
- `ruk decode-conflict` command parsing framed binary `conflict-v1` records into canonical JSON documents with byte-for-byte roundtrip verification.
- Support for both SHA-1 (40 hex characters) and SHA-256 (64 hex characters) object identity validation in conflict records via `--object-format`.
- Stream-bounded CLI input reader enforcing the 16 MiB (`MAX_CONTROL_FRAME_BYTES`) limit via bounded consumption (`take(limit + 1)`), stopping input consumption at the limit even when a FIFO writer remains open.
- String-or-hex JSON serialization for `ByteString` fields, rendering valid UTF-8 as JSON strings and non-UTF-8 bytes as `{"hex": "<lowercase hex>"}` objects.
- Timezone offset representation (`TzOffset`) in author and committer signatures, preserving exact `[+-]DDDD` strings and maintaining the distinction between `-0000` and `+0000`.
- Discriminated JSON serialization for `Head` references using the `type` tag (`{"type": "git", "oid": "..."}` for Git commits and `{"type": "conflicted", "key": "..."}` for native conflict keys).
- Stream separation directing output data to stdout and diagnostics (`ruk: <error>` and `hint: <hint>`) to stderr, returning process exit codes derived from `ErrorCode`.
- `ruk_core::store::Store` library with append-only object segments and transactional redb metadata. POSIX initialization synchronizes ancestor directories; Windows initialization requires an already durable parent and an absent root, which Ruk publishes exclusively.
- Streaming object preparation with bounded memory and disk spools, zstd compression, and deltas against committed local predecessors.
- Atomic publication of prepared objects and conditional metadata facts. Stale conditions reject the batch before append; failures after append begins close the writer until recovery.
- Startup verification of committed extents and object identities, truncation of uncommitted open tails, and refusal of service on committed corruption.
- Checksum- and identity-verified object reads that release metadata transactions before payload I/O.
