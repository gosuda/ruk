CredHdr: 829a2b7 `!` helpers via `sh -c "<cmd> get"` (verbatim config + fixed suffix, same trust as `GIT_SSH_COMMAND`); bare `store`/`cache`/`manager` stay a gap (PATH-resolved Git binaries + GUI-prompt risk).
CredHdr: da99577 `http.extraHeader` rows from gitconfig files + longest-scope-wins resolver in `http::extra_headers_for_url` (empty resets; bad lines drop; unscoped never mixes with scoped).
CredHdr: e1a5966/ccf6958 resolved headers threaded through smart/dumb fetch/push/archive/ls-remote; wire-proven by `extra_headers_join_the_wire_verbatim` on the fake-server log.
Store rows stay single-valued (`ruk config` last-wins); multivalued rows come from gitconfig files and repeated `-c` flags only.
Still absent: LFS batch auth/headers (`sync_via_batch` env-only), `net.rs:620` probe sends no extraHeader (no repo config in that layer), git `urlmatch` normalization (case/port/percent) simplified to prefix-boundary match.
