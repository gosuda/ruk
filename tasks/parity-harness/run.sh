#!/usr/bin/env bash
# ruk-vs-git parity harness.
#
# For each scripted scenario this builds two fresh repos (oracle driven by
# system git, subject driven by `ruk git`), runs a fixed verb sequence in
# both, and diffs stdout bytes, stderr bytes, and exit codes per command.
# Repo layout is never compared: ruk stores at <root>/.ruk, git at
# <root>/.git. Only observable command output is compared.
#
# Usage: bash tasks/parity-harness/run.sh
# Env overrides: GITBIN (default /usr/bin/git), RUKBIN (default
# <repo>/target/debug/ruk).
# The run also rewrites tasks/parity-harness/GAPS.md from its own observed
# output, so the report cannot drift from the harness.
#
# Volatile fields are masked before comparison: the two tempdir paths always
# (mode "exact"), plus 40-hex object ids and abbreviated-oid lines (mode
# "oid") for commands whose output names commit objects. Commit oids differ
# legitimately because ruk appends a change-id trailer to commit payloads
# (blob/tree oids are identical and compared exactly).
set -euo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "$0")/../.." && pwd)" || exit 1
GITBIN="${GITBIN:-/usr/bin/git}"
RUKBIN="${RUKBIN:-$ROOT/target/debug/ruk}"

BASE="$(mktemp -d)" || exit 1
CAP="$BASE/cap"
GAPS_FRAG="$BASE/gaps-frag.md"
GAPS_OUT=""
ODIR=""
RDIR=""
PASS_N=0
FAIL_N=0
PASS_ROWS=""
FAIL_ROWS=""

cleanup() {
  rm -rf -- "${BASE:?unset base dir}"
}
trap cleanup EXIT INT TERM

die() {
  printf 'run.sh: %s\n' "$1" >&2
  exit 1
}

[ -x "$GITBIN" ] || die "GITBIN not executable: $GITBIN"
[ -x "$RUKBIN" ] || die "RUKBIN not executable: $RUKBIN (build with: cargo build -p ruk)"
mkdir -p -- "$CAP" || die "cannot create cap dir"
mkdir -p -- "$BASE/home" || die "cannot create fake home"
: >"$GAPS_FRAG" || die "cannot init gaps fragment"
export HOME="$BASE/home"

export LC_ALL=C TZ=UTC0 PAGER=cat GIT_PAGER=cat GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_DATE='@946684800 +0000' GIT_COMMITTER_DATE='@946684800 +0000'
export GIT_AUTHOR_NAME=Oracle GIT_AUTHOR_EMAIL=oracle@x
export GIT_COMMITTER_NAME=Oracle GIT_COMMITTER_EMAIL=oracle@x

O_CODE=0
R_CODE=0

new_pair() {
  ODIR="$BASE/$1-o"
  RDIR="$BASE/$1-r"
  mkdir -p -- "$ODIR" "$RDIR" || die "cannot create scenario dirs for $1"
}

run_o() {
  O_CODE=0
  "$GITBIN" --no-pager -C "$ODIR" "$@" >"$CAP/o_std.txt" 2>"$CAP/o_err.txt" || O_CODE=$?
}

run_r() {
  R_CODE=0
  "$RUKBIN" git --no-pager -C "$RDIR" "$@" >"$CAP/r_std.txt" 2>"$CAP/r_err.txt" || R_CODE=$?
}

mask_paths() {
  sed -e "s|$ODIR|<REPO>|g" -e "s|$RDIR|<REPO>|g" "$1" >"$2"
}

mask_oids() {
  sed -E -e 's/[0-9a-f]{40}/<OID>/g' \
    -e 's/^[0-9a-f]{7,39} /<OID> /' \
    -e 's/^[0-9a-f]{7,39}$/<OID>/' "$1" >"$2"
}

compare() {
  label="$1"
  mode="$2"
  mask_paths "$CAP/o_std.txt" "$CAP/w_o_std.txt" || die "mask oracle stdout failed"
  mask_paths "$CAP/o_err.txt" "$CAP/w_o_err.txt" || die "mask oracle stderr failed"
  mask_paths "$CAP/r_std.txt" "$CAP/w_r_std.txt" || die "mask ruk stdout failed"
  mask_paths "$CAP/r_err.txt" "$CAP/w_r_err.txt" || die "mask ruk stderr failed"
  if [ "$mode" = "oid" ]; then
    mask_oids "$CAP/w_o_std.txt" "$CAP/n_o_std.txt" || die "oid-mask oracle stdout failed"
    mask_oids "$CAP/w_o_err.txt" "$CAP/n_o_err.txt" || die "oid-mask oracle stderr failed"
    mask_oids "$CAP/w_r_std.txt" "$CAP/n_r_std.txt" || die "oid-mask ruk stdout failed"
    mask_oids "$CAP/w_r_err.txt" "$CAP/n_r_err.txt" || die "oid-mask ruk stderr failed"
  else
    cp -- "$CAP/w_o_std.txt" "$CAP/n_o_std.txt" || die "stage oracle stdout failed"
    cp -- "$CAP/w_o_err.txt" "$CAP/n_o_err.txt" || die "stage oracle stderr failed"
    cp -- "$CAP/w_r_std.txt" "$CAP/n_r_std.txt" || die "stage ruk stdout failed"
    cp -- "$CAP/w_r_err.txt" "$CAP/n_r_err.txt" || die "stage ruk stderr failed"
  fi
  if cmp -s -- "$CAP/n_o_std.txt" "$CAP/n_r_std.txt" && cmp -s -- "$CAP/n_o_err.txt" "$CAP/n_r_err.txt" && [ "$O_CODE" -eq "$R_CODE" ]; then
    PASS_N=$((PASS_N + 1))
    PASS_ROWS="$PASS_ROWS $label"
    printf 'PASS  %s\n' "$label"
    return 0
  fi
  FAIL_N=$((FAIL_N + 1))
  FAIL_ROWS="$FAIL_ROWS $label"
  diff -u -- "$CAP/n_o_std.txt" "$CAP/n_r_std.txt" | tail -n +3 | head -n 40 >"$CAP/d_std.txt" || true
  diff -u -- "$CAP/n_o_err.txt" "$CAP/n_r_err.txt" | tail -n +3 | head -n 20 >"$CAP/d_err.txt" || true
  printf 'FAIL  %s\n' "$label"
  printf '  --- stdout (unified, first 40 lines) ---\n'
  cat -- "$CAP/d_std.txt" || die "print stdout diff failed"
  printf '  --- stderr (unified, first 20 lines) ---\n'
  cat -- "$CAP/d_err.txt" || die "print stderr diff failed"
  printf '  exit codes: oracle=%s ruk=%s\n' "$O_CODE" "$R_CODE"
  {
    printf '### %s [%s]\n' "$label" "$(classify "$label")"
    printf 'exit codes: oracle=%s ruk=%s\n' "$O_CODE" "$R_CODE"
    printf '%s\n' '```diff stdout'
    cat -- "$CAP/d_std.txt" || die "record stdout diff failed"
    printf '%s\n' '```'
    printf '%s\n' '```diff stderr'
    cat -- "$CAP/d_err.txt" || die "record stderr diff failed"
    printf '%s\n' '```'
  } >>"$GAPS_FRAG" || die "record gap evidence failed"
  return 0
}

classify() {
  case "$1" in
    a/merge-ff) printf 'unsupported-flag' ;;
    b/status-porcelain-mv|b/checkout-path|c/cat-file-t-head|c/cat-file-p-head) printf 'semantic-diff' ;;
    *) printf 'byte-diff-vs-git' ;;
  esac
}

run_both() {
  label="$1"
  mode="$2"
  shift 2 || die "run_both needs label, mode, argv"
  o_argv=()
  r_argv=()
  for arg in "$@"; do
    o_argv+=("${arg//@REPO@/$ODIR}")
    r_argv+=("${arg//@REPO@/$RDIR}")
  done
  run_o "${o_argv[@]}"
  run_r "${r_argv[@]}"
  compare "$label" "$mode"
}

seed() {
  printf '%b' "$2" >"$ODIR/$1" || die "cannot seed oracle file $1"
  printf '%b' "$2" >"$RDIR/$1" || die "cannot seed ruk file $1"
}

setup_add_commit() {
  run_o add "$1" >/dev/null 2>&1
  [ "$O_CODE" -eq 0 ] || die "oracle setup add failed for $1"
  run_o -c user.email=oracle@x -c user.name=Oracle commit -m "$2" >/dev/null 2>&1
  [ "$O_CODE" -eq 0 ] || die "oracle setup commit failed: $2"
  run_r add "$1" >/dev/null 2>&1
  [ "$R_CODE" -eq 0 ] || die "ruk setup add failed for $1"
  run_r -c user.email=oracle@x -c user.name=Oracle commit -m "$2" >/dev/null 2>&1
  [ "$R_CODE" -eq 0 ] || die "ruk setup commit failed: $2"
}

scenario_a() {
  printf '### scenario (a): init/add/commit/log/status/diff/branch/checkout/merge/tag/show-ref\n'
  new_pair a
  run_o init -b main
  run_r init
  compare "a/init" exact
  seed a.txt 'hello\n'
  run_both "a/add" exact add a.txt
  run_both "a/commit-1" exact -c user.email=oracle@x -c user.name=Oracle commit -m one
  run_both "a/log-oneline" oid log --oneline
  run_both "a/status-clean" exact status
  seed a.txt 'hello world\n'
  run_both "a/status-dirty" exact status
  run_both "a/diff-unstaged" exact diff
  run_both "a/add-2" exact add a.txt
  run_both "a/diff-staged" exact diff --cached
  run_both "a/commit-2" exact -c user.email=oracle@x -c user.name=Oracle commit -m two
  run_both "a/branch-feat" exact branch feat
  run_both "a/branch-list" exact branch
  run_both "a/checkout-feat" exact checkout feat
  seed f2.txt 'second\n'
  run_both "a/add-f2" exact add f2.txt
  run_both "a/commit-3" exact -c user.email=oracle@x -c user.name=Oracle commit -m three
  run_both "a/checkout-main" exact checkout main
  run_both "a/merge-ff-only" exact merge --ff-only feat
  run_both "a/merge-ff" exact merge --ff feat
  run_both "a/tag-v1" exact tag v1
  run_both "a/tag-list" exact tag
  run_both "a/show-ref" oid show-ref
}

scenario_b() {
  printf '### scenario (b): commit -a/mv/rm/reset/restore\n'
  new_pair b
  run_o init -b main >/dev/null 2>&1
  run_r init >/dev/null 2>&1
  seed a.txt 'one\n'
  setup_add_commit a.txt one
  seed b.txt 'two\n'
  setup_add_commit b.txt two
  seed a.txt 'one\nmodified\n'
  run_both "b/commit-a" exact -c user.email=oracle@x -c user.name=Oracle commit -a -m three
  run_both "b/mv" exact mv a.txt aa.txt
  run_both "b/status-porcelain-mv" exact status --porcelain
  run_both "b/commit-rename" exact -c user.email=oracle@x -c user.name=Oracle commit -m rename
  run_both "b/rm" exact rm aa.txt
  run_both "b/reset-soft" exact reset --soft 'HEAD~1'
  run_both "b/status-porcelain-soft" exact status --porcelain
  run_both "b/reset-mixed" exact reset --mixed HEAD
  run_both "b/status-porcelain-mixed" exact status --porcelain
  run_both "b/restore" exact restore --source=HEAD -- a.txt
  run_both "b/status-porcelain-restored" exact status --porcelain
  run_both "b/checkout-path" exact checkout -- a.txt
}

scenario_c() {
  printf '### scenario (c): ls-files/rev-parse/rev-list/cat-file/show\n'
  new_pair c
  run_o init -b main >/dev/null 2>&1
  run_r init >/dev/null 2>&1
  seed f.txt 'one\n'
  setup_add_commit f.txt one
  run_both "c/ls-files" exact ls-files
  run_both "c/ls-files-s" exact ls-files -s
  run_both "c/rev-parse" oid rev-parse HEAD
  run_both "c/rev-parse-short" oid rev-parse --short HEAD
  run_both "c/rev-list-count" exact rev-list --count HEAD
  run_both "c/hash-object" exact hash-object @REPO@/f.txt
  blob="$(cat -- "$CAP/o_std.txt")"
  [ -n "$blob" ] || die "could not capture blob oid"
  run_both "c/cat-file-p-blob" exact cat-file -p "$blob"
  run_both "c/cat-file-t-blob" exact cat-file -t "$blob"
  run_both "c/cat-file-s-blob" exact cat-file -s "$blob"
  run_both "c/cat-file-t-head" exact cat-file -t HEAD
  run_both "c/cat-file-p-head" exact cat-file -p HEAD
  run_both "c/show-stat" exact show --stat HEAD
  run_both "c/ls-tree" exact ls-tree HEAD
  run_both "c/write-tree" exact write-tree
}

scenario_d() {
  printf '### scenario (d): config/remote/stash\n'
  new_pair d
  run_o init -b main >/dev/null 2>&1
  run_r init >/dev/null 2>&1
  seed f.txt 'one\n'
  setup_add_commit f.txt one
  run_both "d/config-set" exact config test.key hello
  run_both "d/config-get" exact config --get test.key
  run_both "d/remote-add" exact remote add origin https://example.com/x.git
  run_both "d/remote" exact remote
  run_both "d/remote-v" exact remote -v
  seed f.txt 'one\nwip\n'
  run_both "d/stash-push" exact stash push -m wip
  run_both "d/stash-list" exact stash list
  run_both "d/stash-pop" exact stash pop
  run_both "d/stash-list-empty" exact stash list
}

probe_unsupported() {
  printf '%s\n' '## live probes (same run, outside compared rows)' >>"$GAPS_FRAG" || die "record probe header failed"
  for v in archive bundle count-objects gc index-pack pack-objects worktree; do
    U_CODE=0
    "$RUKBIN" git -C "$RDIR" "$v" >"$CAP/u_out.txt" 2>&1 || U_CODE="$?"
    u_line="$(head -n 1 -- "$CAP/u_out.txt")" || die "read probe output failed"
    printf -- '- `%s` (exit %s): %s\n' "$v" "$U_CODE" "$u_line" >>"$GAPS_FRAG" || die "record probe failed"
  done
  ib="$BASE/ibprobe"
  mkdir -p -- "$ib" || die "cannot create init probe dir"
  U_CODE=0
  "$RUKBIN" git -C "$ib" init -b main >"$CAP/u_out.txt" 2>&1 || U_CODE="$?"
  u_line="$(head -n 1 -- "$CAP/u_out.txt")" || die "read init probe failed"
  printf -- '- `init -b main` (exit %s): %s\n' "$U_CODE" "$u_line" >>"$GAPS_FRAG" || die "record init probe failed"
  U_CODE=0
  "$RUKBIN" git -C "$RDIR" hash-object f.txt >"$CAP/u_out.txt" 2>&1 || U_CODE="$?"
  u_line="$(head -n 1 -- "$CAP/u_out.txt")" || die "read hash-object probe failed"
  printf -- '- `hash-object f.txt` via -C from repo root (exit %s): %s\n' "$U_CODE" "$u_line" >>"$GAPS_FRAG" || die "record hash-object probe failed"
}

write_gaps() {
  {
    printf '%s\n' '# Parity gaps: ruk vs system git'
    printf '\n'
    printf '%s\n' 'Generated by `bash tasks/parity-harness/run.sh` on this run; do not hand-edit.'
    printf 'oracle: %s / subject: %s\n' "$oracle_v" "$ruk_v"
    printf '\n'
    printf 'Result this run: PASS %s / FAIL %s / TOTAL %s.\n' "$PASS_N" "$FAIL_N" "$((PASS_N + FAIL_N))"
    printf 'failing rows:%s\n' "$FAIL_ROWS"
    printf '\n'
    printf '%s\n' 'Masking: tempdir paths always; 40-hex and abbreviated oids in oid-mode rows only.'
    printf '%s\n' 'Root divergence: ruk appends a `change-id` trailer to commit payloads, so commit'
    printf '%s\n' 'oids always differ while blob/tree oids match exactly (see c/hash-object, c/ls-tree,'
    printf '%s\n' 'c/write-tree PASS rows). Classes: byte-diff-vs-git / unsupported-flag /'
    printf '%s\n' 'unsupported-verb (probes below) / semantic-diff.'
    printf '\n'
    printf '%s\n' '## failing rows (observed diffs)'
    cat -- "$GAPS_FRAG" || die "read gaps fragment failed"
    printf '\n%s\n' '## passing rows (exact or oid-masked parity this run)'
    printf 'passing rows:%s\n' "$PASS_ROWS"
  } >"$GAPS_OUT" || die "write GAPS.md failed"
  printf 'wrote %s\n' "$GAPS_OUT"
}

oracle_v="$("$GITBIN" --version)" || die "cannot query oracle version"
ruk_v="$("$RUKBIN" git version)" || die "cannot query ruk version"
GAPS_OUT="$ROOT/tasks/parity-harness/GAPS.md"
printf 'oracle: %s\n' "$oracle_v"
printf 'ruk: %s\n' "$ruk_v"
scenario_a
scenario_b
scenario_c
scenario_d
probe_unsupported
printf -- '----\n'
printf 'PASS: %d  FAIL: %d  TOTAL: %d\n' "$PASS_N" "$FAIL_N" "$((PASS_N + FAIL_N))"
write_gaps
if [ "$FAIL_N" -ne 0 ]; then
  printf 'failing rows:%s\n' "$FAIL_ROWS"
  exit 1
fi
