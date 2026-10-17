# Operation-contract manifest

Data + generator only. No Go/Rust source changes live here.

## Files

| File | Role |
|---|---|
| `build_manifest.py` | Source of truth: checked-in `TABLE` (56 verbs) + `DYNAMIC_SITES` (11 sites). Regenerates `manifest.json`. |
| `manifest.json` | Derived output. Do not hand-edit; change the table and regenerate. |
| `README.md` | This file. |

## Regenerate / drift check

```sh
python3 build_manifest.py            # rewrite manifest.json from TABLE
python3 build_manifest.py --check    # exit 2 when manifest.json drifts from TABLE
```

`--check` is the drift gate: any table edit without a regenerated
`manifest.json` fails loudly instead of silently diverging.

## Verb row schema

Each entry of `verbs` answers: given a Forgejo callsite, exactly which
argv shape, exit semantics, and observable bytes the ruk git-compatibility
surface must produce.

| Key | Meaning |
|---|---|
| `verb` | Git verb, e.g. `rev-list`. Sorted; exactly the 56 production verbs from inventory §1. |
| `category` | Classification from `git/command-list.txt` (porcelain / plumbing / sync-helper …). |
| `inventory_ref` | Citation into the bounded inventory (`inventory §2 …` row or `§3` site). Every row has one. |
| `forgejo_callsites` | Verbatim Forgejo anchors (`file:line`) that issue this verb. |
| `git_sources` | Git anchors: `command-list.txt` category + `builtin/<verb>.c`; plus `parse-options.c` conventions for exit 129. |
| `option_families` | `[{family, options, source}]`. Pinned families list the exact flags Forgejo uses; dynamic tails (clone/fetch/gc/…) live in `dynamic_sites` and are referenced from the verb row. |
| `exit_codes` | `[{code, meaning}]`. `0` success; `129` usage error per `parse-options.c`; `128` fatal; verb-specific codes recorded where they are control flow: `merge-base --is-ancestor` → 1 means “not ancestor”, `show-ref --verify --quiet` / `rev-parse --verify --quiet` → 1 means “missing”, `grep` → 1 no match / 2 error, `merge`/`merge-file`/`merge-tree`/`rebase`/`replay` → 1 means conflicts held. |
| `byte_shape` | `{stdin, stdout, stderr}`. Exact byte grammar: NUL-delimited forms (`-z`), `--batch` headers (`<oid> <type> <size>`), porcelain fetch line length, `--file=-` message stdin, pkt-line streams for `upload-pack`/`receive-pack`. stderr is `LC_ALL=C` human text (never parsed) except the `fatal: couldn't find remote ref ` prefix mapped to `ErrRemoteRefNotFound`. |
| `side_effects` | `{head, index, sequencer, config, refs, objects, worktree}`. `"none"` unless stated. Records the inventory §4 invariant: `HEAD` only via `symbolic-ref`, config only via `config`, refs only via `update-ref`/`symbolic-ref`, index only via `read-tree`/`update-index`/`write-tree`/`apply`/`hash-object`. |
| `argv_shape` | Canonical assembled argv for the pinned Forgejo usage. |
| `notes` | Gate warnings: real `git version` string (never faked, inventory §6), fetch porcelain length validation, modern `merge-tree --write-tree` form only. |

## Dynamic-site row schema

Each entry of `dynamic_sites` covers one argv family assembled at a
callsite rather than a fixed flag list (inventory §3):

`{site, verb, inventory_ref, anchors, family, options, expansion_source,
argv_shape, exit_semantics, observable_bytes}`.

| Site | Family | Expansion source |
|---|---|---|
| D01 | `clone-args` | `CloneRepoOptions` fields + caller `TrustedCmdArgs` prefix (`repo.go:143-200`) |
| D02 | `fetch-args-temp-repo` | Local `fetchArgs` var + caller refspecs (`temp_repo.go:106,139,177`) |
| D03 | `fetch-porcelain` | `SupportFetchPorcelain` gate + refspec (`fetch.go:25-80`) |
| D04 | `for-each-ref-extra-args` | Caller `extraArgs` tails (`repo_branch.go:253-255`) |
| D05 | `compare-switch` | `tmpRemote`/`directComparison` runtime branch (`repo_compare.go:32-105`) |
| D06 | `http-service-dispatch` | `?service=` value, allowlist receive/upload-pack (`githttp.go:397-405`) |
| D07 | `ssh-serv-dispatch` | SSH verb + `git-<verb>` binary probe (`cmd/serv.go:333-347`) |
| D08 | `gc-args` | `setting.Git.GCArgs` config; fsck `TrustedCmdArgs` (`check.go:88`, `git.go:440`) |
| D09 | `apply-git-dir-prefix` | Temp-repo `basePath` + stdin patch (`patch.go:163-166`) |
| D10 | `add-commit-globals` | `globalCommandArgs` prefix (`commit.go:88,115`) |
| D11 | `env-object-locations` | `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_QUARANTINE_PATH`, `GIT_INDEX_FILE`, `GIT_WORK_TREE` + base env (`command.go:251,271,338`) |

## How the CLI-parity harness consumes it

1. Load `manifest.json` (`schema_version` 1).
2. For each verb: for each `option_families` entry × `argv_shape`,
   run the case against stock git (oracle) and ruk, then diff:
   - exit code in `exit_codes` (including negative-answer 1-codes),
   - `byte_shape.stdout/stderr` bytes (exact; NUL framing included),
   - `side_effects` state (HEAD/index/refs/objects/config/worktree/sequencer).
3. For each dynamic site: expand `expansion_source` into concrete argv
   vectors (e.g. every `CloneRepoOptions` combination, both porcelain
   gate states, allowlisted vs rejected service strings) and run the same
   triple comparison.
4. Env matrix (D11): rerun index/object verbs under each env var set;
   quarantine/alternate stores must resolve identically.
5. Version gate: assert `version` stdout parses as `git version <semver>`
   ≥ 2.34.1 and `replay` availability keys off the real string.

Coverage bar: 56/56 verbs + 11/11 dynamic sites, every row carrying its
`inventory_ref` citation. A new Forgejo callsite form fails the harness
(unknown argv) instead of silently passing.
