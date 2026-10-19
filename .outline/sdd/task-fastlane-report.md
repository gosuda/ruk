# FastLane report (fast-export / fast-import / range-diff / request-pull)

- Verbs: `fast-export`, `fast-import` (`diff`|`fetch`), `range-diff` (`push`|`read-tree`), `request-pull` (`replace`|`rerere`); 90 → 94 in `dispatch.rs`/`mod.rs`/`STATUS.md`/`tests.rs`. New module `cli/verbs_fastio.rs`.
- fast-export: `commit`/`blob`/`tag`/`reset` stream, single `:mark` namespace, topo order (reversed walk + insertion repair), `--all`/ref args/`HEAD`-default, `--import/export-marks`, unclaimed tips ride `reset` lines, trailing `done`. Tag refs never emit `commit` lines.
- fast-import: `blob`/`commit` (`M`/`D`/`R`/`C`/`deleteall`, `from`/`merge`, `data <n>` + `<<eof`, C-quoted paths), env-identity fallback, lightweight + annotated `tag`, `reset`; refs always overwritten; worktree untouched.
- range-diff: two `A..B` ranges, first-parent content fingerprint then subject match, `=`/`!`/`<`/`>` mapping lines only.
- request-pull: mail template (base, end subject, url, oldest-first shortlog, range diffstat).
- Named gaps: `ls`/`cat-blob`/`get-mark`/`alias`/`N` file ops, `request-pull -p`, patch-of-patch hunks, `...` ranges.
- Tests (5, `tests.rs` EOF): import-creates-history, export/import roundtrip (log + show-ref equality), marks continuation, range-diff `=`/`!`, request-pull template + `-p` refusal.
