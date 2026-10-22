# Changelog

Entries describe implemented, unreleased functionality.

## [Unreleased]

### Added

- Protocol schema minor 4 adds `release.freeze.set` and `release.freeze.clear`, bringing the method count to 63. A release owner can freeze a tag at one target and clear its marker. Tag mutations, imports, CLI ref writes, undo, and pushes refuse frozen tags with the owner named. Marker guards publish atomically with ref changes; an atomic push refuses every sibling when any tag is frozen.

- Protocol schema minor 3: `repo.fork` serves a staged fork. Sealed segments hardlink into the fork (a cross-device link copies and is reported), tail objects re-publish base-first, and facts copy under full CAS revalidation. The destination carries the forked generation, the default branch, and the refs the `refs` selection keeps; freeze markers, attestations, and live coordination state stay behind.
- Protocol schema minor 2 with the `Admin` method kind and 14 hosted forge methods (`repo.stat`, `tree`, `refs.list`, `compare`, `search`, `archive`, `events.tail`, `repo.init`, `repo.delete`, `repo.rename`, `repo.fork`, `remote.refs`, `claim.renew`, `policy.set`), bringing the `ruk model` contract count to 61. Admin methods dispatch before any coordinator call, gated by `admin_uids`, with no session and no receipt; unserved arms refuse `E_HOSTED`.
- `ruk model` command rendering the draft 2020-12 JSON schema for the Ruk core protocol, including framing boundaries, the 30-code closed error registry, object formats, and 61 protocol method contracts.
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
- Group commit for concurrent `Store::publish` calls: publications waiting for the writer share one publication transaction when their keys do not conflict. `RUK_COMMIT_LINGER_MS` sets an optional linger window (default 0, capped at 50 ms). Each caller still receives the outcome its publication would have had alone.

### Changed

- **Breaking:** `release.freeze.set` now requires the tag to exist at the pinned target: an absent tag or a tag at another target is refused with `E_STALE` naming the live tag. A fresh freeze publishes a `Refs` guard (exact serialized `RefTarget` bytes, never the raw oid) alongside the marker create, so a tag that moves after prepare fails the freeze publish with `E_STALE`; a retry with the same owner and target stays a marker-only rewrite of the stored bytes. A live marker is removed only by owner-checked `release.freeze.clear`.
- **Breaking:** renamed `ruk forgejo serve` to `ruk serve`. No alias or shim remains.
- **Breaking:** unknown daemon config keys now refuse startup. Every key in the daemon config must be known.
- **Breaking:** an empty `allowed_uids` now refuses hosted startup and denies every peer. At least one authorized peer uid is required.
- **Breaking:** `merge-notices` and `outcome-lookup` are no longer advertised. Frame kind 9 stays retired and is refused, and kinds 12 and 13 carry hook calls and replies.
- **Breaking:** IPC error frames now carry the full error reply with hints. A nonzero exit reports `Failed` instead of `Completed`.
- Migrated authored JSON parsing and serialization to `sonic-rs`; `serde` and `schemars` remain in use.
- Limited CLI conflict input, protocol envelope decoding, and `protocol::decode_json` to 128 open arrays or objects. Deeper input returns `E_INVALID`. Bounded parsing adds stack space when needed; existing CLI and control-frame byte limits are unchanged.
- Normalized parsed `-0` and `-0.0` to positive zero.
- **Breaking:** replaced `SchemaDocument` with `schemars::Schema`. `SchemaReply.document`, `model_schema_json`, and `method_schema_json` now use the typed schema representation, which accepts only object and boolean roots. Removed `Eq` from schema-containing reply types; `PartialEq` remains.
- **Breaking:** schema documents no longer decode from postcard JSON strings. Schema replies use JSON frames; non-schema receipt and request binary encodings remain unchanged.
- Kept protocol v1 while replacing the generated `SchemaDocument` definition and reference with `Schema`. Model output uses standard schema serialization and remains deterministic. Conflict output bytes remain unchanged.
- **Breaking:** added a persistent `StoreId` to the v1 store marker and `StoreFormat`. The marker now requires three LF-terminated lines, including `store-id <uuid>`. Earlier two-line markers fail with `E_VERSION` before metadata opens and remain untouched; no automatic migration is provided.
- Added `Store::store_id()`. New stores receive distinct identities; reopening or relocating a store preserves its identity. Object, segment, and fact encodings remain unchanged.
