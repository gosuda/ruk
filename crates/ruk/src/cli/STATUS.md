# CLI verb status

59 verbs, one row each. Statuses: **implemented** (real native-store
transitions), **partial** (resolves and validates, then completes only the
cases its backing covers), **unsupported** (typed `Unsupported` with the
reason; exit code 1 through `GitError::exit_code`).

Oracle anchors are `git/git.c` (`commands[]`, `handle_options`,
`handle_builtin`) plus the `git/builtin/<verb>.c` file per row.

## State layout

- `HEAD` is a workspace field: `GitCompatWorkspace.head: HeadRef` in
  `FactTable::Workspaces` under `cli/workspaces/git-compat`, CAS-fenced on
  the read bytes. Resolution goes through the ref namespace on demand
  (`HeadRef::resolve` over `StoreRefs`). `HEAD` is never a `Refs` entry.
- Index rows live in `FactTable::WsIndex` under `cli/index/row/` with the
  stage as the final key byte; the workspace row's `index_generation`
  advances in the one transaction that writes the rows
  (`mutate_index`/`checkout`).
- Config (`cli/config/`), sequencer (`cli/sequencer/`), stash slots
  (`cli/stash/`, counter `cli/stash-next`), reflog operation ids
  (`cli/reflog-next`), and `FETCH_HEAD` (`cli/pseudo/FETCH_HEAD`) are fact
  records in `FactTable::Pins`, the table with no typed readers.
- Branches, tags, `refs/stash`, and remote-tracking refs are real `Refs`
  rows written through checked ref transactions.
- Remotes are config records (`remote.<name>.url`, `remote.<name>.fetch`).

## Global options

Honored before the verb: `-v`/`--version`, `-h`/`--help`, `-C <path>`,
`-c name=value`, `--config-env name=ENVVAR`, `--git-dir=<path>`,
`--work-tree=<path>`, `--bare`. Accepted and inert (no pager exists):
`-p`/`--paginate`/`-P`/`--no-pager`, `--no-replace-objects`,
`--no-lazy-fetch`, `--no-optional-locks`, `--no-advice`. Anything else,
including `--exec-path` and `--namespace`, is `Unsupported`.
`ruk <verb> --help` rewrites to `ruk help <verb>`.

## Verbs

| verb | status | notes |
| --- | --- | --- |
| add | implemented | explicit paths, `-u`, `-A`, `-N`; worktree bytes hashed per file |
| archive | unsupported | no archive writer in this slice |
| branch | implemented | list/create/delete/rename; `-d` checks ancestry, `-D` forces |
| bundle | unsupported | no bundle format in this slice |
| cat-file | implemented | `-p`, `-t`, `-s`, `-e` over the bounded object reader |
| check-ref-format | implemented | `RefName` validation; `--print`, `--branch` |
| checkout | implemented | branch switch, detach, `-b`/`-B`, path restore |
| cherry-pick | partial | revisions resolve; `--abort`/`--quit`/`--continue` report absent sequencer state; application needs the merge lane |
| clone | implemented | local paths only; branches, tags, remote-tracking refs, `HEAD` branch, fetch refspec config; network sources are `Offline` |
| commit | implemented | `-m` (required, no editor), `-a`, `--amend` via `ops::edit`; empty tree-matching commits refuse |
| commit-tree | implemented | canonical payload, parents verified as stored commits |
| config | implemented | `--local` scope only; `--global`/`--system`/`--worktree` are `Unsupported` |
| count-objects | unsupported | the store exposes no object census |
| diff | implemented | worktree/index/`HEAD`/revision compares, `--cached`, `--stat`, `--name-only`, paths; hunks from a bounded LCS differ with labeled omissions |
| fetch | implemented | local paths only; refspec globs, force flags, fast-forward checks, tags, depth passthrough, `FETCH_HEAD` |
| for-each-ref | implemented | `%(refname)`, `%(objectname)`, `%(objecttype)`; other fields are `Invalid` |
| fsck | implemented | reachable refs, history, trees, blobs, and index rows; unreachable-object (`dangling`) reporting needs the absent object census |
| gc | unsupported | no repack or prune lane in this slice |
| grep | implemented | subset: `-l`, `-c`, `-n`, `-e`, `-i`, `-w`, `-F`, `-E` (last of `-F`/`-E` wins), `-H`/`--with-filename`/`--no-filename`, one `<commit>` for tree scope; 0 hit / 1 no hit / 128 bad use; no pathspecs, no `.rukignore`, always-Rust-regex patterns |
| hash-object | implemented | `-t blob/tree/commit`, `-w` stores; works outside a repository without `-w` |
| help | implemented | verb list and per-verb summaries |
| index-pack | unsupported | declared absent for this slice |
| init | implemented | `--object-format`, `--bare`, reinit; unborn `HEAD` on `refs/heads/main` |
| log | implemented | `--oneline`, `-n`/`--max-count` |
| ls-files | implemented | `-s`, `-u`, `--others`, `--error-unmatch` |
| ls-remote | implemented | local paths only; network remotes are `Offline` |
| ls-tree | implemented | `-r`, `--name-only`; gitlinks report as commits |
| merge | implemented | fast-forward only; anything needing content resolution is `Unsupported` and writes no state |
| merge-base | implemented | pairwise paint-down; `--is-ancestor` exits 1 when false |
| migrate | implemented | exact import of a real `.git` (loose, packs, refs, `HEAD`); `--force` replaces an existing `.ruk`; no checkout/config/hooks |
| mktree | implemented | canonical sort, mode/type agreement checks |
| mv | implemented | all stages renamed, worktree file renamed; `-f` allows overwrite |
| pack-objects | unsupported | declared absent for this slice |
| pull | implemented | local paths only; fetch plus fast-forward merge |
| push | implemented | local paths only; persisted push plan, per-ref outcomes, non-fast-forward rejected without force |
| rebase | partial | up-to-date succeeds; `--abort`/`--quit`/`--continue` report absent state; replay needs the merge lane |
| receive-pack | unsupported | `ruk-git` holds the client half; serving pushes is absent |
| remote | implemented | backed by `remote.<name>.*` config records |
| reset | implemented | `--soft`, `--mixed` (default), `--hard` with worktree sync, path form |
| restore | implemented | `--staged`/`--worktree` (default worktree), `--source` |
| rev-list | implemented | `--count`, `-n`/`--max-count` |
| rev-parse | implemented | `HEAD`/refs/oids/`~n`/`^n` plus `--git-dir`, `--show-toplevel`, `--is-inside-work-tree`, `--abbrev-ref`, `--short` |
| revert | partial | same shape as `cherry-pick` |
| rm | implemented | `--cached`, `-r`; unknown paths fail |
| show | implemented | `--oneline`, `-s`, `--stat`, `--name-only`, parent diff |
| show-ref | implemented | `--head`, `--verify`, `--tags`, `--heads`, patterns |
| stash | implemented | `push`/`list`/`show`/`drop`/`pop`/`apply`/`clear`; oracle two-commit shape (index + `WIP` parents); apply requires a clean index on the stashed base |
| status | implemented | `--porcelain`, `--short`, `--branch`, long format; renames undetected |
| switch | implemented | `-c`/`-C`, `--detach`, remote guess |
| symbolic-ref | implemented | `HEAD` moves the workspace row; other names are ref symrefs |
| tag | implemented | lightweight, annotated (`-a`/`-m`), list with globs, delete |
| update-index | implemented | `--cacheinfo`, `--stdin`, `--add`, `--remove`, `--assume-unchanged`, `--skip-worktree`, `--refresh` |
| update-ref | implemented | expected-value CAS, `-d`, `-m` reflog rows |
| upload-archive | implemented | serves archives over the upload-archive protocol |
| upload-pack | unsupported | `ruk-git` holds the client half; serving fetches is absent |
| verify-pack | implemented | header, version, and trailer validation plus full verify-mode ingest with staged output dropped |
| version | implemented | reports `CARGO_PKG_VERSION` |
| worktree | unsupported | no workcopy lane in this slice |
| write-tree | implemented | refuses unmerged paths |

## Known divergences from Git

- Exit statuses are the native 1–5 map (`ErrorCode::exit_code`), not Git's
  128/129 conventions; unknown verbs and unsupported families exit 1. The
  one exception is `grep` usage errors, which exit 128 through
  `GitError::Usage` (its no-match exit stays 1).
- `--bare` unifies the store layout (`.ruk/` under the root); no separate
  bare format exists.
- `diff` hunks come from a simple bounded LCS differ, split every 20
  operations; large inputs are labeled omissions, never silent truncation.
- `status` and `diff` do not detect renames.
- `stash apply`/`pop` require a clean index on the stashed base and a clean
  worktree on the restored paths instead of merging; the index rows come
  back only with `--index` (`stash branch` always restores them); bare
  subcommands address the newest slot; dropped slots leave numbering gaps.
- `rev-list` order is ancestry-discovery order, not date order.
- `fetch`/`push`/`clone`/`pull`/`ls-remote` route local paths only.
