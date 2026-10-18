# Store open per-invocation cost: report

| stage (warm, large-10000) | before | after |
|---|---|---|
| `lookup` wall (`rev-parse --verify`) | ~50ms | ~30ms |
| open total | 40–48ms | 24–33ms |
| └ recovery segments (1×24MB seg, 15.6k recs) | 36–40ms | 22–28ms |
| └ meta (redb open+ensure+census) | 2.3–2.6ms | 1.6–2.7ms (ensure 1.2→0.04ms) |
| write pair add+commit (small-000) | 47ms (ticket) | 27ms (small opens already sub-ms; rest is publish path) |

Fix: `validate_segment_file_concurrent` shards ≥1MB extents over ≤8 scoped workers (sequential header walk carves ranges; same `scan_range` checks per worker; CRCs combine in offset order; first failing range wins); `ensure_census` probes via read txn, write txn only when `lfs_objects` is absent. `RUK_PROFILE=1` timers kept in `mod.rs`/`recovery.rs`/`metadata.rs`; `RUK_VERIFY=full` still forces the object pass (210ms on this fixture).
Integrity: no check skipped — full sweep runs every open with identical checks and error order; mid-file bit flip → open refuses (`record checksum mismatch at offset 12185314`); equivalence test asserts same CRC/detail/earliest-error. <20ms lookup not reachable in this slice: remaining ≈ serve (~8ms) + startup live outside `store/`.
Gate note: `cargo test -p ruk-core --lib store::` green here (212 passed, 0 failed, incl. `crash_tests` and the new equivalence test); wider gates (nextest, clippy, fmt) stay with the orchestrator.
