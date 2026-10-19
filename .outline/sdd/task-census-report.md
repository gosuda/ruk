# Census and mirror LFS sync
- store `99fe19a`: `Store::iter_objects() -> Result<Vec<(Oid, ObjectKind, u64)>, StoreError>`, locator table pages in digest order with no payload I/O.
- cat-file `685d8d7` (Corrupt propagates fix folded into `1620366`): `--batch-check [--batch-all-objects]` prints `<oid> <type> <size>`; stdin revs answer `missing` on NotFound only, Corrupt aborts.
- fetch `1620366` plus tag peel `b6f454f`: `run_fetch` returns `(report, tips)`; `fetch --lfs` peels tag tips to commits, walks the fetched tips for pointers, and batch pulls missing payloads via `sync_via_batch_at` (endpoint order: `lfs.url`, `remote.<n>.lfsurl`, `<url>/info/lfs`); silent skip when absent or non-Full, misses to stderr.
- mirror.rs gap docs and STATUS rows updated. `cargo check -p ruk-core -p ruk -p ruk-git`: no errors, no new warnings.
- Still absent: push mirror upload (`push --lfs` wiring; the `lfs-payload-sync --upload` verb exists), `count-objects` and `fsck --dangling` atop the census, `remote update --lfs` for wiki mirrors.
