# Submodule lane report

- Code: `d1fcb4f` (sparse checkpoint; carries `verbs_submodule.rs` plus submodule hunks in shared files; supersedes `4afe2eb`).
- Report: this commit (amends `df82458`).
- Verb surface: `submodule add/status/init/deinit/update/summary/foreach` plus `absorbgitdirs` gap; dispatch row `submodule` (oracle `git/builtin/submodule--helper.c`); table at 90 with all lanes.
- Semantics: `.rukmodules` sections (`path`, `url`, `branch`); gitlink rows via `IndexEntry::new(..Gitlink..)` plus `path_row_mutations`; child store at `<path>/.ruk` with `gitdir:` pointer followed; `add` is a local clone plus attached checkout with single-transaction gitlink and modules staging; `update` clones or fetches on `--init` then checks out detached at the recorded oid; `status` flags sync (` `), drift (`+`), uninitialized (`-`), conflict (`U`) with `--cached` and `--recursive`; `foreach` runs `sh -c` with `name`, `sm_path`, `displaypath`, `sha1`, `toplevel`.
- Named gaps: `absorbgitdirs` is `Unsupported` (in-place `.ruk` needs none); `update --merge/--rebase` is `Unsupported`; network urls are `Offline`; `summary` omits commit subjects; `foreach --quiet` is parsed but inert (the `Entering` header always prints).
- Tests (`tests.rs` EOF; written here, not executed here): `add` lands gitlink, modules row, and materialized file; `deinit` shows `-`, then `update --init` re-clones at the recorded oid (a gitlink move to a newer child commit is untested); status shows `(main)`, `foreach` echoes, `summary` quiets after commit, `absorbgitdirs` errors.
- Gates: no local runs per wave rules (only grep-level reads here); checkpoint message records peer `check --tests`; full gates belong to the orchestrator.
- Note: `stash@{0}` (`wip`) is not mine; left untouched.
