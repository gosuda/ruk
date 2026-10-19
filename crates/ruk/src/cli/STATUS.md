# CLI verb status

94 verbs, one row each. Statuses: **implemented** (real native-store
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
| am | implemented | mbox apply plus commit; `--signoff`, `-k`, `--continue`/`--skip`/`--abort`/`--quit` over `AM_STATE`; dirty index refused; no `-3` |
| apply | implemented | hunk match with offset search; `--index`/`--cached`/`--check`/`--stat`/`--numstat`/`--reverse`/`-p`; no binary patches or gitlinks |
| annotate | implemented | alias of `blame` through the same first-parent LCS attribution |
| archive | implemented | `--format=tar` (server default) and `--format=zip` (client-side transcode of the tar); `--prefix`, `-o`, path limits |
| bisect | implemented | `start`/`bad`/`good`/`skip`/`reset`/`log`/`terms`/`run` over an ancestor paint-down; midpoint minimizes `|total-2·weight|` (~log2 steps); `--first-parent`, `--no-checkout`, `--term-*`; `BISECT_*` pseudo-heads under `cli/pseudo/`; `replay`/`visualize` are `Unsupported` |
| blame | implemented | first-parent walk with per-commit LCS alignment; default `<oid> (<author> <date> <line>) <content>`, `-L`, `-p`/`--porcelain`, `--line-porcelain`, `-l`; no `<rev>` blames the worktree with `Not Committed Yet` lines; `-C`/`-M` parse but do no cross-file copy/move detection |
| branch | implemented | list/create/delete/rename; `-d` checks ancestry, `-D` forces |
| bundle | implemented | git bundle v2/v3 headers plus pack v2; `create [--all] [<rev>...]` (refs only, `^rev` exclusions become prerequisites), `verify`, `list-heads`, `unbundle` (objects only, no refs); `clone <file>` plants refs; bundle verbs need a repository |
| cat-file | implemented | `-p`, `-t`, `-s`, `-e` over the bounded object reader; `--batch-check [--batch-all-objects]` lists `<oid> <type> <size>` from the store census |
| check-attr | implemented | `.rukattributes` glob scan; absent file means every attr `unspecified` |
| check-ignore | implemented | `.rukignore` glob scan (`*`/`?`/`[...]`/`!`); no file means nothing ignored (exit 1) |
| check-ref-format | implemented | `RefName` validation; `--print`, `--branch` |
| checkout | implemented | branch switch, detach, `-b`/`-B`, path restore |
| checkout-index | implemented | `-a`, `-f`, `-u` (accepts, stat-less), `-q`, `--prefix`, `--stage=1/2/3`, `--stdin` (`-z`); existing differing files refuse without `-f`; gitlinks skipped; `--stage=all`, `--temp` are `Unsupported` |
| cherry | implemented | `upstream [head [base]]`, `+`/`-` by tree-diff content patch-id, `-v` |
| cherry-pick | implemented | per-commit three-way replay (syntax lane, text fallback); `-n`, `-m`, `-x`; `--continue`/`--skip`/`--abort` over `CHERRY_PICK_HEAD` + todo state |
| clean | implemented | `-f`/`-d`/`-n`/`-e`; `.rukignore` skipped by default, `-x` includes ignored, `-X` only ignored; files under untracked dirs need `-d` |
| clone | implemented | local paths only; branches, tags, remote-tracking refs, `HEAD` branch, fetch refspec config; network sources are `Offline` |
| commit | implemented | `-m` (required, no editor), `-a`, `--amend` via `ops::edit`; empty tree-matching commits refuse; concludes `MERGE_HEAD` merges with two parents |
| commit-tree | implemented | canonical payload, parents verified as stored commits |
| config | implemented | `--local` scope only; `--global`/`--system`/`--worktree` are `Unsupported` |
| count-objects | implemented | `<n> objects, <bytes>` from the store census, no payload I/O |
| credential | implemented | `fill`/`approve`/`reject` over stdin `key=value` descriptions through the configured helpers (`get`/`store`/`erase`); needs no repository |
| describe | implemented | nearest tag by parent depth; `--tags`/`--exact-match`/`--long`/`--abbrev`/`--always` |
| diff | implemented | worktree/index/`HEAD`/revision compares, `--cached`, `--stat`, `--name-only`, paths; `-M`/`--find-renames` pairs renames by similarity, merge lane tracks rename-plus-edit |
| fast-export | implemented | `commit`/`blob`/`tag`/`reset` stream with `:mark` ids in topo order; ref args (default `HEAD` branch), `--all`, `--import-marks`/`--export-marks`; un-emitted tips ride as `reset` lines; trailing `done` |
| fast-import | implemented | `blob`/`commit` (`M`/`D`/`R`/`C`/`deleteall`, `from`/`merge`, explicit idents or env fallback)/lightweight and annotated `tag`/`reset`; `data <n>` and `data <<eof`; `feature`/`option`/`checkpoint`/`progress` ignored; `ls`/`cat-blob`/`get-mark`/`alias` and `N` file ops are `Unsupported`; `--import-marks`/`--export-marks`; refs always overwritten, worktree untouched |
| fetch | implemented | refspec globs, force flags, fast-forward checks, tags, depth passthrough, `FETCH_HEAD`; local, `ssh://`, `git://`, smart-http v2→v0, dumb-http fetch fallback; `--lfs` pulls payloads for fetched tips under `LfsMode::Full` (mirror parity) |
| fmt-merge-msg | implemented | subject from the `FETCH_HEAD` pseudo record; `-m`, `--log[=n]`/`--no-log`, `--stdin`/file |
| for-each-ref | implemented | `%(refname)`, `%(objectname)`, `%(objecttype)`; other fields are `Invalid` |
| format-patch | implemented | mbox to stdout (or `-o` files); `-n`, `--numbered`/`--no-numbered`, `-U`; merge commits refused; raw UTF-8 subjects |
| fsck | implemented | reachable refs, history, trees, blobs, and index rows; `--dangling`/`--unreachable` list `dangling <kind> <oid>` from the census minus the ref closure |
| gc | implemented | prune unreachable (ref closure + detached `HEAD`/index/stash/`FETCH_HEAD`/sequencer/reflog pins, delta-base closure in store) then compact; `--aggressive` repeats compaction, `--auto` exits quietly with no work, `--dry-run` reports, `--prune=now` (default) prunes and `--prune=never` compacts only (other dates are `Unsupported`: no object ages, no grace period) |
| get-tar-commit-id | implemented | stdin tar `comment` pax scan; honest miss when no id is stored |
| grep | implemented | subset: `-l`, `-c`, `-n`, `-e`, `-i`, `-w`, `-F`, `-E` (last of `-F`/`-E` wins), `-H`/`--with-filename`/`--no-filename`, one `<commit>` for tree scope; 0 hit / 1 no hit / 128 bad use; no pathspecs, no `.rukignore`, always-Rust-regex patterns |
| hash-object | implemented | `-t blob/tree/commit`, `-w` stores; works outside a repository without `-w` |
| help | implemented | verb list and per-verb summaries |
| index-pack | implemented | ingest plus publication with commit-record facts; `-v`, `--stdin`; no `.idx` (the store keeps no loose/pack split); thin bases must already be committed |
| init | implemented | `--object-format`, `--bare`, reinit; unborn `HEAD` on `refs/heads/main` |
| interpret-trailers | implemented | trailer-block parse; `--only-trailers`/`--only-input`/`--parse`/`--unfold`/`--trailer`/`--where`/`--key` |
| log | implemented | `--oneline`, `-n`/`--max-count` |
| ls-files | implemented | `-s`, `-u`, `--others`, `--error-unmatch` |
| ls-remote | implemented | local, `ssh://`, `git://`, smart-http v2→v0, dumb-http text fallback |
| ls-tree | implemented | `-r`, `--name-only`; gitlinks report as commits |
| merge | implemented | fast-forward fast-path; three-way content merge via the syntax lane (bounded text fallback); `--no-ff`, `--ff-only`; conflicts leave stages 1/2/3, `MERGE_HEAD`/`ORIG_HEAD`, sequencer state with `--continue`/`--abort`/`--quit` |
| merge-base | implemented | pairwise paint-down; `--is-ancestor` exits 1 when false |
| merge-file | implemented | three worktree files, markers back into `<current>` (or `-p` stdout); `-q`, `-L`, `--ours`/`--theirs`/`--union`, `--diff3`, `--marker-size`; conflicts exit 1 (`-p` bytes ride the error detail); binary refuses without a resolve mode; needs no repository |
| merge-tree | implemented | `<base> <ours> <theirs>` merged to a new tree, index/worktree untouched; prints the tree id plus `CONFLICT` lines, exit 0; no `--write-tree`/`--name-only` |
| migrate | implemented | exact import of a real `.git` (loose, packs, refs, `HEAD`); `--force` replaces an existing `.ruk`; no checkout/config/hooks |
| mktree | implemented | canonical sort, mode/type agreement checks |
| mv | implemented | all stages renamed, worktree file renamed; `-f` allows overwrite |
| name-rev | implemented | multi-tip breadth-first naming; `--tags`/`--name-only`/`--refs` |
| notes | implemented | `add`/`show`/`list`/`append`/`edit`/`copy`/`remove`/`get-ref`/`merge`/`prune` over `refs/notes/commits` (commit-backed flat hex map); `--ref`, `GIT_NOTES_REF`, `core.notesRef`; `edit` reads `-m`/`-F`/stdin, no editor |
| pack-objects | implemented | self-contained pack v2 to `<base>.pack` or `--stdout`; stdin-only input (exact oids, or rev-list args with `--revs`, plus `--all`); `--thin` needs `--stdout` and stays full without receiver haves; `--no-thin`, `--delta-base-offset`/`--no-delta-base-offset` inert |
| pull | implemented | local paths only; fetch plus fast-forward merge |
| push | implemented | local, `ssh://`, `git://`, and smart/dumb-http; persisted push plan, per-ref outcomes, non-fast-forward rejected without force; `--lfs` uploads the outgoing range's verified payloads via the batch API (mirror parity) |
| range-diff | implemented | pairs `A..B` against `C..D` by first-parent content fingerprint then subject (`=`/`!`/`<`/`>`); mapping lines only, no patch-of-patch hunks; `...` ranges refused |
| read-tree | implemented | one-tree replace, `--empty`, `-m` two/three-tree (stages 1/2/3, no content merge), `--reset`, `-u` scoped checkout; one-tree `-m` only fast-forwards; `--prefix`, `--index-output`, `--trivial`, `--aggressive`, `--dry-run` are `Unsupported` |
| rebase | implemented | `<upstream>` and `--onto <new> <upstream>` replay over the merge lane; `--continue`/`--skip`/`--abort`; drops merge commits; no branch switching |
| receive-pack | implemented | serves pushes over stdin/stdout via `ruk receive-pack <dir>` and the `git-receive-pack` argv0 name; v0 wire |
| reflog | implemented | `show`/`list`/`expire`/`delete` over the rows `update-ref -m` writes |
| remote | implemented | backed by `remote.<name>.*` config records |
| rerere | implemented | bare run replays recorded resolutions (staging stage zero) and records preimages/postimages under `cli/rerere/`; `status`/`diff`/`remaining`/`forget`/`clear`/`gc` (15d preimage / 60d resolved); ids hash conflict hunks, labels excluded; no `rerere.enabled` config |
| replace | implemented | create (`-f`), `-l [<pattern>]`, `-d`; `refs/replace/*` redirects commit reads and history walks plus tip redirection in `log`/`blame`/`diff`/`checkout`; no graft/edit, no transfer over fetch/push/clone, `--no-replace-objects` stays inert |
| request-pull | implemented | mail template with base, end subject, source url, oldest-first shortlog, and range diffstat; `-p` is `Unsupported` |
| reset | implemented | `--soft`, `--mixed` (default), `--hard` with worktree sync, path form |
| restore | implemented | `--staged`/`--worktree` (default worktree), `--source` |
| rev-list | implemented | `--count`, `-n`/`--max-count` |
| rev-parse | implemented | `HEAD`/refs/oids/`~n`/`^n` plus `--git-dir`, `--show-toplevel`, `--is-inside-work-tree`, `--abbrev-ref`, `--short` |
| revert | implemented | inverse three-way replay per commit; `-n`, `-m`; `--continue`/`--skip`/`--abort` over `REVERT_HEAD` + todo state |
| rm | implemented | `--cached`, `-r`; unknown paths fail |
| show | implemented | `--oneline`, `-s`, `--stat`, `--name-only`, parent diff |
| shortlog | implemented | `-s`/`-n`/`-e`, ranges, `--all` |
| show-ref | implemented | `--head`, `--verify`, `--tags`, `--heads`, patterns |
| sparse-checkout | implemented | `init`/`set` (patterns, `--stdin`, `--no-reapply`)/`list`/`disable`/`reapply` over `.ruk/info/sparse-checkout` + `core.sparseCheckout`; out-of-cone stage-zero rows carry skip-worktree, worktree holds only matches; dirty rewrites refuse; `--cone` is `Unsupported`; branch-switch checkouts and `status` ignore the sparse set |
| stash | implemented | `push`/`list`/`show`/`drop`/`pop`/`apply`/`clear`; oracle two-commit shape (index + `WIP` parents); apply refuses only staged or worktree changes on paths the stash touches |
| status | implemented | `--porcelain`, `--short`, `--branch`, long format; staged renames always paired when identical, `-M` pairs by similarity staged and worktree |
| stripspace | implemented | trailing-blank collapse; `--strip-comments` |
| submodule | implemented | `add` (local clone, gitlink + `.rukmodules`), `status` (`--cached`/`--recursive`), `init`, `deinit` (refuses dirty trees without `--force`), `update` (`--init`/`--recursive`/`--remote`), `summary`, `foreach` (`--recursive`); `absorbgitdirs` is `Unsupported` (child `.ruk` needs no gitdir absorption) |
| switch | implemented | `-c`/`-C`, `--detach`, remote guess |
| symbolic-ref | implemented | `HEAD` moves the workspace row; other names are ref symrefs |
| tag | implemented | lightweight, annotated (`-a`/`-m`), list with globs, delete |
| update-index | implemented | `--cacheinfo`, `--stdin`, `--add`, `--remove`, `--assume-unchanged`, `--skip-worktree`, `--refresh` |
| update-ref | implemented | expected-value CAS, `-d`, `-m` reflog rows |
| upload-archive | implemented | serves archives over the upload-archive protocol |
| upload-pack | implemented | serves fetches over stdin/stdout via `ruk upload-pack <dir>` and the `git-upload-pack` argv0 name; protocol v2 negotiated on `GIT_PROTOCOL`, v0 fallback |
| var | implemented | `GIT_AUTHOR_IDENT`, `GIT_COMMITTER_IDENT`, `GIT_DEFAULT_BRANCH`, `GIT_EDITOR`, `GIT_PAGER`, `-l` |
| verify-commit | partial | existence checked, then honest refusal (the store holds no signatures) |
| verify-pack | implemented | header, version, and trailer validation plus full verify-mode ingest with staged output dropped |
| verify-tag | partial | structure checked, then honest refusal (the store holds no signatures) |
| version | implemented | reports `CARGO_PKG_VERSION` |
| worktree | implemented | `add` (branches, detach, `-b`/`-B`, `--force`)/`list` (`--porcelain`) /`remove` (`--force`)/`prune` (`--dry-run`) over `cli/worktrees/` snapshot checkouts; secondaries share the store but not `HEAD`/index, and `add` inside the root is refused |
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
- `diff`/`log`/`show` pair renames by similarity only with `-M`/`--find-renames` (default 50%, `--no-renames`/`-M0` disables); worktree diffs never pair untracked sides.
- `stash apply`/`pop` refuse only staged or worktree changes on paths the
  stash touches instead of merging; the index rows come back only with
  `--index` (`stash branch` always restores them); bare subcommands address
  the newest slot; dropped slots leave numbering gaps.
- `rev-list` order is ancestry-discovery order, not date order.
- `clone` routes local paths only; network sources are `Offline`.
