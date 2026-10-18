# Closure-read report: parallel local_closure (0ed7f8a)

- Root cause: not the kernel. `PreadReader` is positional/lock-free and the `SegmentFileCache` mutex is hit-path-short; serial strace shows ~16k `pread64` @ ~9us (1/object). The 2026-10-18 convoy was userspace sharing: discovery state across threads, plus ~2ms thread-spawn per batch (measured: scope-per-batch wall 2.7ms vs 0.4ms compute).
- Fix (`session.rs` only): batches of 256 with visited marked serially before dispatch; one `ClosureReadPool` (16 lanes, `sync_channel(1)`, stop-and-wait) spawned once per closure; workers do read+link-parse (pure), queue extension stays serial in batch order; lane death returns `Io`, never panics. No store API change needed.
- Evidence: `strace -f` shows 15,971 preads (no amplification vs 15,966 serial) and 3.8k futex (no storm); x8/x12 segment bytes identical; all 10,001 source refs present; `fsck` exit 0.
- Clone before/after (large-10000, 15,600 objs, release): closure 1802ms -> 544ms (reads 332, links 81, collect 114, sort 7), fetch total 3276ms -> 1934ms, wall 3.55s -> 2.16s.
- Cover tests for the gate: `local_fetch_publishes_closure_directly`, `local_fetch_depth_records_boundaries`, `truncated_closure_is_corrupt_on_any_path`, `private_exclusion` closure tests.
