commit+status flag parity (Wave J)
- commit added: -F, --allow-empty-message, --signoff/-s, --squash, --fixup[=amend:|reword:], --no-edit, --cleanup, --template, --reset-author, --status/--no-status/--verbose (no-op); --amend reuses HEAD; sourceless --edit Unsupported.
- status added: --porcelain=v1/v2, --long/--short, --null, -u/--untracked-files, --ignored, --show-stash, --ahead-behind/--no-ahead-behind, --renames, -v/-vv diffs.
- named-gap: status --column; commit/status --verbose real via diff lane (status), no-op (commit).
- tests: 7 wave_j_* fns appended; STATUS.md commit+status rows updated.
