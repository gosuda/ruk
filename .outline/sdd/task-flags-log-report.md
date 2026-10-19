# Wave J — LogFlags report
Added to `log`: --follow, -S/-G, --merges/--no-merges, --first-parent,
--left-right/--cherry-pick (first A...B fixes sides), --topo-order,
--date-order (default walk), --date/--relative-date, --abbrev[=N],
%P/%T/%S, --pretty=full/fuller/email/raw, --summary/--shortstat/--numstat/
--dirstat, --show-notes[=ref]/--no-notes, --decorate=modes, --source,
--simplify-by-decoration, --branches/--tags/--remotes/--exclude, --boundary.
Named gaps: --cherry-pick outside symmetric ranges is a no-op (per git);
--date=local/rfc/format: → Unsupported; -n stays --max-count (git).
Divergences: non-rev positionals DWIM to paths only if present in worktree/
HEAD tree; --source/--left-right markers use first-reach tip naming.
Tests: 12 new `log_*` cases appended to tests.rs; STATUS.md log row updated.
