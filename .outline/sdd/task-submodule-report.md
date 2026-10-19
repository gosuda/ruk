# Submodule lane report

- Code: `4afe2ebb40ff98c0e249d3524e404d0a8485efa7` (sparse lane checkpoint; carries `verbs_submodule.rs` plus submodule hunks in shared files).
- Report: this commit (see``, filled by Main at merge).
- Verb surface: `submodule add/status/init/deinit/update/summary/foreach` plus `absorbgitdirs` gap; dispatch row `submodule` (oracle `git/builtin/submodule--helper.c`); table at 90 with all lanes.
- Semantics: `.rukmodules` sections (`path`, `url`, `branch`); gitlink rows via `IndexEntry::new(..Gitlink..)` plus `path_row_mutations`; child store at `<path>/.ruk` with `gitdir:` pointer followed; `add` is a local clone plus attached checkout with single-transaction gitlink and modules staging; `update` clones or fetches on `--init` then checks out detached at the recorded oid; `status` flags sync (` `), drift (`+`), uninitialized (`-`), conflict (`U`) with `--cached` and `--recursive`; `foreach` runs `sh -c` with `name`, `sm_path`, `displaypath`, `sha1`, `toplevel`.
- Named gaps: `absorbgitdirs` is `Unsupported` (in-place `.ruk` needs none); `update --merge/--rebase` is `Unsupported`; network urls are `Offline`; `summary` omits commit subjects.
- Tests (`tests.rs` EOF): `add` lands gitlink, modules row, and materialized file; `deinit` shows `-`, then `update --init` checks out the recorded oid; status shows `(main)`, `foreach` echoes, `summary` quiets after commit, `absorbgitdirs` errors.
- Gates: no local runs per wave rules; checkpoint commit message records peer `check --tests`; full gates belong to the orchestrator.
- Note: `stash@{0}` (`wip`) predates this report and is not mine; left untouched.
