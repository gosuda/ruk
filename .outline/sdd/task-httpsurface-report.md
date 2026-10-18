# task-httpsurface report
- `4c8b640` new modules: `credentials` (external-helper fill, never spawns git; helper-then-env; 10s/attempt, 16-attempt cap) and `dumb_http` (text info/refs, info/packs, loose-object closure walk).
- Staging honesty: pack objects ingest (staged, dropped unpublished) then ALL raw objects stage once finally, so double CPU work with a single publication; loose objects stage once.
- `b137099` wiring: endpoint-scoped smart_http auth with runner seam; `UploadArchive` POST matches the oracle (`/git-upload-archive`, x-git-upload-archive-request/result); `FetchSource::DumbHttp` fetch fallback on the dumb gap.
- Gaps: discover() never GETs HEAD (no symref); fetch_archive skips discovery (oracle probes via git-upload-pack; v2 gap anyway); no UploadArchive-discovery or verb-level dumb tests; `cargo test -p ruk` not run.
- Evidence: `cargo test -p ruk-git --lib -- transport::credentials transport::dumb_http transport::smart_http` gives 29 passed; `cargo check -p ruk-git --tests -p ruk` is clean (Group1 re-checked with Group2 stashed; peer ruk-core edits present throughout, untouched).
