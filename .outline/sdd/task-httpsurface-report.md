# task-httpsurface report
- `4c8b640` new modules: `credentials` (external-helper fill, never spawns git; helper-then-env auth; 10s/attempt, 16-attempt cap) and `dumb_http` (text info/refs, info/packs, loose-object closure walk, one `stage_local_objects` staging; push stays refused).
- `b137099` wiring: smart_http endpoint-scoped auth with runner seam, `UploadArchive` service + `fetch_archive` (argument framing, ACK/NACK→NotFound, sideband tar; no consuming verb), `FetchSource::DumbHttp` fetch fallback on the dumb gap.
- Evidence: `cargo test -p ruk-git --lib -- transport::credentials transport::dumb_http transport::smart_http` → 29 passed, 0 failed (fake TcpListener servers; stub-runner auth); `cargo check -p ruk-git --tests -p ruk` clean.
- Gaps: upload-archive has no verb; bare builtin helpers (`store`/`cache`) and `!` commands unrun; `ls-remote` stays smart-only; fmt/clippy/nextest left to orchestrator gates.
