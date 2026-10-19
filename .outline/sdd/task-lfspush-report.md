# Push LFS upload and census consumers
- push `c48c0cb`: `push --lfs` batch-uploads the outgoing closure's sidecar-verified pointer payloads before the pack moves (endpoint order: `lfs.url`, `remote.<n>.lfsurl`, `<url>/info/lfs`); silent skip when non-Full, endpoint-less, or payload-less, misses to stderr, only a refused batch fails. `push_closure`/`ClosureObject` now `pub`; upload transfer shared as `sync_via_batch_upload_at`; `PushFlags` groups the lane options.
- count-objects `6809704`: `<n> objects, <bytes>` from one `iter_objects` pass, no payload I/O; dropped from the unsupported-verbs test.
- fsck `4f5c0b0`: `--dangling`/`--unreachable` list `dangling <kind> <oid>` for census-minus-ref-closure (tag chains peeled via `peel_tip_chain`, subtrees marked); plain `fsck` output unchanged.
- `cargo check -p ruk-git -p ruk`: no errors, no new warnings. STATUS rows synced. Skipped fmt/clippy/nextest per ticket.
