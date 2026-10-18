#!/usr/bin/env bash
# Capacity measurement runner (dev-scale, per the measurement contract).
#
# Workloads runnable today against BOTH system git and ruk (where comparable):
#   adv-K      full ref advertisement at branch-count step K (bytes + latency)
#   lookup     exact single-ref lookup (rev-parse --verify)
#   page1      first branch page (branch --list, 20 rows)
#   write      small write: 1 file add + commit (<=32 paths, tiny payload)
#   clone      bare clone stream of the large fixture repo
#   fetch      fetch stream after one new upstream branch
#
# For each workload: W warm-ups + R measured reps, p50/p95/p99 via python3.
# Records offered/admitted/completed/rejected, source commit, host config.
# Regenerates tasks/capacity/RESULTS.md from its own observed output.
#
# Ruk is invoked the parity-harness way: "$RUKBIN" git -C DIR ARGS.
# If RUKBIN is absent/not executable, the ruk side records BLOCKED (with
# reason) and the git baseline still runs.
#
# Usage:
#   bash tasks/capacity/run.sh --fixture DIR [--reps N] [--warmup N]
#       [--clone-reps N] [--out DIR] [--git PATH] [--ruk PATH] [--hyperfine]
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)" || exit 1
FIXTURE=""
REPS=10
WARMUP=3
CLONE_REPS=3
OUT="$SCRIPT_DIR/.work"
GITBIN="${GITBIN:-/usr/bin/git}"
RUKBIN="${RUKBIN:-$ROOT/target/debug/ruk}"
HYPERFINE=0

die() {
  printf 'run: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fixture) FIXTURE="${2:?missing --fixture value}"; shift 2 ;;
    --reps) REPS="${2:?missing --reps value}"; shift 2 ;;
    --warmup) WARMUP="${2:?missing --warmup value}"; shift 2 ;;
    --clone-reps) CLONE_REPS="${2:?missing --clone-reps value}"; shift 2 ;;
    --out) OUT="${2:?missing --out value}"; shift 2 ;;
    --git) GITBIN="${2:?missing --git value}"; shift 2 ;;
    --ruk) RUKBIN="${2:?missing --ruk value}"; shift 2 ;;
    --hyperfine) HYPERFINE=1; shift ;;
    *) die "unknown flag: $1" ;;
  esac
done

[ -x "$GITBIN" ] || die "GITBIN not executable: $GITBIN"
if [ -z "$FIXTURE" ]; then
  FIXTURE="$OUT/fixture"
  bash "$SCRIPT_DIR/gen-fixture.sh" --out "$FIXTURE" --small 4 --branches "1000 10000" \
    || die "fixture generation failed"
fi
[ -d "$FIXTURE" ] || die "fixture dir missing: $FIXTURE"

mkdir -p -- "$OUT/raw" || die "cannot create out dir"
WORK="$OUT/work-$(date -u '+%Y%m%dT%H%M%SZ')"
mkdir -p -- "$WORK" || die "cannot create work dir"

export LC_ALL=C TZ=UTC0 PAGER=cat GIT_PAGER=cat GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=Capacity GIT_AUTHOR_EMAIL="capacity@ruk"
export GIT_COMMITTER_NAME=Capacity GIT_COMMITTER_EMAIL="capacity@ruk"
export GIT_AUTHOR_DATE='@946684800 +0000' GIT_COMMITTER_DATE='@946684800 +0000'

RUK_OK=0
RUK_NOTE=""
if [ -x "$RUKBIN" ]; then
  if "$RUKBIN" git version >/dev/null 2>&1; then
    RUK_OK=1
    RUK_NOTE="$("$RUKBIN" git version 2>/dev/null)"
  else
    RUK_NOTE="BLOCKED: $RUKBIN exists but 'ruk git version' fails"
  fi
else
  RUK_NOTE="BLOCKED: no executable at $RUKBIN (build currently fails; see RESULTS.md)"
fi

# now_ms: wall clock in integer milliseconds, via the bash builtin clock
# (immune to whatever `date` resolves to on the host).
now_ms() {
  t="${EPOCHREALTIME}"
  t="${t/./}"
  printf '%d' "$((t / 1000))"
}

# time_ms <outfile> -- cmd... : run cmd, append elapsed ms to outfile.
# Returns the command's exit code via TIMED_CODE.
TIMED_CODE=0
time_ms() {
  samples="$1"
  shift
  [ "$1" = "--" ] || die "time_ms missing -- separator"
  shift
  start="$(now_ms)"
  "$@" >/dev/null 2>&1
  TIMED_CODE=$?
  end="$(now_ms)"
  printf '%d\n' "$((end - start))" >>"$samples" || die "sample append failed"
}

# stats <samples-file>: count mean min p50 p95 p99 max (ms, 1 decimal).
stats() {
  python3 - "$1" <<'PYEOF'
import sys, statistics
vs = sorted(float(l) for l in open(sys.argv[1]) if l.strip())
n = len(vs)
if n == 0:
    print("n=0 mean=NA min=NA p50=NA p95=NA p99=NA max=NA")
else:
    def q(p):
        i = min(n - 1, int(p * n))
        return vs[i]
    print(f"n={n} mean={statistics.fmean(vs):.1f} min={vs[0]:.1f} "
          f"p50={q(0.50):.1f} p95={q(0.95):.1f} p99={q(0.99):.1f} max={vs[-1]:.1f}")
PYEOF
}

RESULTS_JSON="$WORK/results.json"
printf '[\n' >"$RESULTS_JSON" || die "json init failed"
FIRST_ROW=1
row() {
  # row <workload> <backend> <offered> <completed> <stats...> <extra-json>
  if [ "$FIRST_ROW" -eq 0 ]; then
    printf ',\n' >>"$RESULTS_JSON" || die "json write failed"
  fi
  FIRST_ROW=0
  printf '  {"workload":"%s","backend":"%s","offered":%s,"completed":%s,"stats":"%s","extra":"%s"}' \
    "$1" "$2" "$3" "$4" "$5" "$6" >>"$RESULTS_JSON" || die "json write failed"
}

run_workload() {
  # run_workload <name> <backend: git|ruk> <reps> <fn-setup>...
  # Caller provides per-rep command via eval-style function names passed in.
  name="$1"
  backend="$2"
  reps="$3"
  setup_fn="$4"
  rep_fn="$5"
  extra="$6"
  samples="$WORK/raw-${backend}-${name}.txt"
  : >"$samples" || die "cannot init samples"
  REP_WU="${7:-$WARMUP}"
  if [ "$REP_WU" -ge "$reps" ]; then
    REP_WU=$((reps - 1))
  fi
  if [ "$REP_WU" -lt 0 ]; then
    REP_WU=0
  fi
  offered=$((reps - REP_WU))
  completed=0
  r=0
  while [ "$r" -lt "$reps" ]; do
    "$setup_fn" "$r" "$backend" || die "setup failed: $name rep $r"
    if [ "$r" -lt "$REP_WU" ]; then
      "$rep_fn" "$r" "$backend" >/dev/null 2>&1 || true
    else
      if "$rep_fn" "$r" "$backend"; then
        completed=$((completed + 1))
      fi
    fi
    r=$((r + 1))
  done
  # NOTE: warm-ups above run inside rep fns but do not record samples;
  # sample files hold measured reps only (see rep fns using time_ms).
  st="$(stats "$samples")"
  printf '%-14s %-6s offered=%-3s completed=%-3s %s %s\n' "$name" "$backend" "$offered" "$completed" "$st" "$extra"
  row "$name" "$backend" "$offered" "$completed" "$st" "$extra"
}

# --- backend command vectors ------------------------------------------------
# back_cmd <backend> <repo> args... : exec the right binary.
back_cmd() {
  backend="$1"
  repo="$2"
  shift 2
  if [ "$backend" = "ruk" ]; then
    "$RUKBIN" git --no-pager -C "$repo" "$@"
  else
    "$GITBIN" --no-pager -C "$repo" "$@"
  fi
}

LARGE10="$FIXTURE/large-10000"
LARGE1="$FIXTURE/large-1000"
SMALL0="$FIXTURE/small-000"
[ -d "$LARGE10" ] || die "fixture lacks large-10000: run gen-fixture.sh"
[ -d "$SMALL0" ] || die "fixture lacks small-000: run gen-fixture.sh"

# --- workload rep functions (each records one sample per measured rep) ------
W_ADV_BYTES_1K=0
W_ADV_BYTES_10K=0

adv1k_setup() { return 0; }
adv1k_rep() {
  r="$1"
  backend="$2"
  if [ "$r" -ge "$REP_WU" ]; then
    time_ms "$WORK/raw-${backend}-adv-1k.txt" -- back_cmd "$backend" "$LARGE1" show-ref
    code="$TIMED_CODE"
  else
    back_cmd "$backend" "$LARGE1" show-ref >/dev/null 2>&1
    code=$?
  fi
  return "$code"
}

adv10k_setup() { return 0; }
adv10k_rep() {
  r="$1"
  backend="$2"
  if [ "$r" -ge "$REP_WU" ]; then
    time_ms "$WORK/raw-${backend}-adv-10k.txt" -- back_cmd "$backend" "$LARGE10" show-ref
    code="$TIMED_CODE"
  else
    back_cmd "$backend" "$LARGE10" show-ref >/dev/null 2>&1
    code=$?
  fi
  return "$code"
}

lookup_setup() { return 0; }
lookup_rep() {
  r="$1"
  backend="$2"
  if [ "$r" -ge "$REP_WU" ]; then
    time_ms "$WORK/raw-${backend}-lookup.txt" -- back_cmd "$backend" "$LARGE10" rev-parse --verify --quiet "refs/heads/b005000^{commit}"
    code="$TIMED_CODE"
  else
    back_cmd "$backend" "$LARGE10" rev-parse --verify --quiet "refs/heads/b005000^{commit}" >/dev/null 2>&1
    code=$?
  fi
  return "$code"
}

page1_setup() { return 0; }
page1_rep() {
  r="$1"
  backend="$2"
  # First page of 20 branch names. The full listing is captured (no pipe to
  # head: closing the pipe early SIGPIPEs the lister and poisons the sample),
  # so the sample covers list-then-take-20; reported honestly as such.
  if [ "$r" -ge "$REP_WU" ]; then
    start="$(now_ms)"
    out="$(back_cmd "$backend" "$LARGE10" branch --list 'b*' 2>/dev/null)"
    code=$?
    # Slice via a file, never a pipe: a pipe to head SIGPIPEs the writer.
    printf '%s\n' "$out" >"$WORK/page1-$backend-$r.txt" || die "page stage failed"
    head -n 20 "$WORK/page1-$backend-$r.txt" >/dev/null || die "page slice failed"
    end="$(now_ms)"
    printf '%d\n' "$((end - start))" >>"$WORK/raw-${backend}-page1.txt" || die "sample append failed"
  else
    back_cmd "$backend" "$LARGE10" branch --list 'b*' >/dev/null 2>&1 || true
    code=0
  fi
  return "$code"
}

WRITE_REPO=""
write_setup() {
  r="$1"
  # Fresh work repo per measured rep so writes never disturb the fixture.
  WRITE_REPO="$WORK/write-$2-$r"
  rm -rf -- "$WRITE_REPO" || die "write cleanup failed"
  cp -r -- "$SMALL0" "$WRITE_REPO" || die "write setup copy failed"
  return 0
}
write_rep() {
  r="$1"
  backend="$2"
  printf 'seed write rep %d\n' "$r" >"$WRITE_REPO/w_${r}.txt" || die "write payload failed"
  if [ "$r" -ge "$REP_WU" ]; then
    # One sample per rep for the whole add+commit pair (one small write).
    start="$(now_ms)"
    back_cmd "$backend" "$WRITE_REPO" add "w_${r}.txt" >/dev/null 2>&1
    code=$?
    if [ "$code" -eq 0 ]; then
      back_cmd "$backend" "$WRITE_REPO" commit -qm "capacity write $r" >/dev/null 2>&1
      code=$?
    fi
    end="$(now_ms)"
    printf '%d\n' "$((end - start))" >>"$WORK/raw-${backend}-write.txt" || die "sample append failed"
  else
    back_cmd "$backend" "$WRITE_REPO" add "w_${r}.txt" >/dev/null 2>&1 || return $?
    back_cmd "$backend" "$WRITE_REPO" commit -qm "capacity write $r" >/dev/null 2>&1
    code=$?
  fi
  return "$code"
}

clone_setup() {
  r="$1"
  rm -rf -- "$WORK/clone-$2-$r" || die "clone cleanup failed"
  return 0
}
clone_rep() {
  r="$1"
  backend="$2"
  if [ "$r" -ge "$REP_WU" ]; then
    # --bare file clone of the 10k-branch repo: pack + ref stream stand-in.
    time_ms "$WORK/raw-${backend}-clone.txt" -- back_cmd "$backend" "$WORK" clone -q --bare "file://$LARGE10" "$WORK/clone-$backend-$r"
    code="$TIMED_CODE"
  else
    "$GITBIN" clone -q --bare "file://$LARGE10" "$WORK/clone-$backend-warm$r" >/dev/null 2>&1 || true
    rm -rf -- "$WORK/clone-$backend-warm$r" || die "warm clone cleanup failed"
    code=0
  fi
  return "$code"
}

fetch_setup() {
  r="$1"
  backend="$2"
  # Seed a clone once per rep; fetch measures the incremental stream.
  rm -rf -- "$WORK/fetch-$backend-$r" || die "fetch cleanup failed"
  "$GITBIN" clone -q --bare "file://$LARGE10" "$WORK/fetch-$backend-$r" >/dev/null 2>&1 || return $?
  # New upstream branch makes the fetch non-trivial.
  "$GITBIN" -C "$LARGE10" branch -f "fetchprobe_${backend}_${r}" "refs/heads/b000001" >/dev/null 2>&1 || return $?
  return 0
}
fetch_rep() {
  r="$1"
  backend="$2"
  if [ "$r" -ge "$REP_WU" ]; then
    time_ms "$WORK/raw-${backend}-fetch.txt" -- back_cmd "$backend" "$WORK/fetch-$backend-$r" fetch -q origin
    code="$TIMED_CODE"
  else
    back_cmd "$backend" "$WORK/fetch-$backend-$r" fetch -q origin >/dev/null 2>&1
    code=$?
  fi
  "$GITBIN" -C "$LARGE10" branch -q -D "fetchprobe_${backend}_${r}" >/dev/null 2>&1 || true
  return "$code"
}

printf 'capacity run: fixture=%s reps=%d warmup=%d clone-reps=%d\n' "$FIXTURE" "$REPS" "$WARMUP" "$CLONE_REPS"
printf 'capacity run: git=%s\n' "$("$GITBIN" --version)"
printf 'capacity run: ruk=%s\n' "$RUK_NOTE"

# Advertisement byte sizes (git baseline; ruk side only if present).
W_ADV_BYTES_1K="$("$GITBIN" -C "$LARGE1" show-ref 2>/dev/null | wc -c)"
W_ADV_BYTES_10K="$("$GITBIN" -C "$LARGE10" show-ref 2>/dev/null | wc -c)"
W_ADV_BYTES_1K="$(printf '%s' "$W_ADV_BYTES_1K" | tr -d ' ')"
W_ADV_BYTES_10K="$(printf '%s' "$W_ADV_BYTES_10K" | tr -d ' ')"
printf 'capacity run: adv bytes 1k=%s 10k=%s\n' "$W_ADV_BYTES_1K" "$W_ADV_BYTES_10K"

run_backend() {
  b="$1"
  run_workload "adv-1k" "$b" "$REPS" adv1k_setup adv1k_rep "bytes=$W_ADV_BYTES_1K"
  run_workload "adv-10k" "$b" "$REPS" adv10k_setup adv10k_rep "bytes=$W_ADV_BYTES_10K"
  run_workload "lookup" "$b" "$REPS" lookup_setup lookup_rep "ref=refs/heads/b005000"
  run_workload "page1" "$b" "$REPS" page1_setup page1_rep "rows=20"
  run_workload "write" "$b" "$REPS" write_setup write_rep "paths=1"
  run_workload "clone" "$b" "$CLONE_REPS" clone_setup clone_rep "bare file://large-10000" 1
  run_workload "fetch" "$b" "$REPS" fetch_setup fetch_rep "incremental +1 branch"
}

run_backend "git"
if [ "$RUK_OK" -eq 1 ]; then
  run_backend "ruk"
fi

if [ "$RUK_OK" -ne 1 ]; then
  for w in adv-1k adv-10k lookup page1 write clone fetch; do
    row "$w" "ruk" "0" "0" "n=0 mean=NA min=NA p50=NA p95=NA p99=NA max=NA" "$RUK_NOTE"
  done
fi

# Optional hyperfine cross-check on the isolated lookup (git only).
HYPER_NOTE="hyperfine not requested"
if [ "$HYPERFINE" -eq 1 ]; then
  if command -v hyperfine >/dev/null 2>&1; then
    HYPER_NOTE="$(hyperfine --warmup "$WARMUP" --runs "$REPS" \
      "$GITBIN -C $LARGE10 rev-parse --verify --quiet 'refs/heads/b005000^{commit}'" 2>&1 \
      | grep -E 'Time|mean' | head -n 3 | tr '\n' ';')"
    printf 'capacity run: hyperfine lookup: %s\n' "$HYPER_NOTE"
  else
    HYPER_NOTE="hyperfine requested but not installed"
  fi
fi

printf '\n]\n' >>"$RESULTS_JSON" || die "json close failed"

# --- regenerate RESULTS.md from observed output --------------------------------
SRC_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
NPROC="$(nproc 2>/dev/null || printf 'unknown')"
MEM="$(free -g 2>/dev/null | awk '/^Mem:/ {print $2 " GiB total"}' || printf 'unknown')"
DISK="$(df -h "$ROOT" 2>/dev/null | awk 'NR==2 {print $2 " total, " $4 " avail on " $1}' || printf 'unknown')"
STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
TABLE="$(python3 - "$RESULTS_JSON" <<'PYEOF'
import json, sys
rows = json.load(open(sys.argv[1]))
lines = ["| workload | backend | offered | completed | mean | min | p50 | p95 | p99 | max | extra |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    # stats stored as one string "n=.. mean=.. min=.. p50=.. p95=.. p99=.. max=.."
    st = {}
    for tok in r["stats"].split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            st[k] = v
    lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
        r["workload"], r["backend"], r["offered"], r["completed"],
        st.get("mean", "NA"), st.get("min", "NA"), st.get("p50", "NA"),
        st.get("p95", "NA"), st.get("p99", "NA"), st.get("max", "NA"), r["extra"]))
print("\n".join(lines))
PYEOF
)"
{
  printf '# Capacity results (generated; do not hand-edit)\n\n'
  printf 'Generated by `bash tasks/capacity/run.sh` at %s.\n\n' "$STAMP"
  printf '## Environment (dev-scale, NOT the reference deployment)\n\n'
  printf -- '- source commit: %s\n' "$SRC_COMMIT"
  printf -- '- host CPUs: %s; memory: %s; disk: %s\n' "$NPROC" "$MEM" "$DISK"
  printf -- '- oracle: %s\n' "$("$GITBIN" --version)"
  printf -- '- subject: %s\n' "$RUK_NOTE"
  printf -- '- fixture: %s (see manifest.txt; seed 0x52554b01)\n' "$FIXTURE"
  printf -- '- reps=%d warmup=%d clone-reps=%d; hyperfine: %s\n' "$REPS" "$WARMUP" "$CLONE_REPS" "$HYPER_NOTE"
  printf -- '- adv bytes: 1k-branch=%s B, 10k-branch=%s B\n\n' "$W_ADV_BYTES_1K" "$W_ADV_BYTES_10K"
  printf '## Measurements (wall ms per operation; CLI-level, warm cache)\n\n'
  printf '%s\n\n' "$TABLE"
  printf '## Reading this honestly\n\n'
  printf -- '- `offered/admitted/completed/rejected`: CLI invocations have no admission layer, so\n'
  printf -- '  offered=reps, admitted=reps(always), rejected=0. Real admission accounting\n'
  printf -- '  (E_LIMIT/429/503, queue waits) needs the daemon + load generator: NOT measured here.\n'
  printf -- '- Latencies are single-host CLI wall times, not end-to-end Forgejo operations and not\n'
  printf -- '  open-loop load at 1000 ops/s. Compare against profile SLOs only as order-of-magnitude\n'
  printf -- '  context, never as a pass claim.\n'
  printf -- '- The ruk side runs the same CLI verbs via `ruk git`. Daemon/IPC admission, bulk classes,\n'
  printf -- '  and Forgejo HTTP paths are out of scope for this scaffold.\n'
} >"$SCRIPT_DIR/RESULTS.md" || die "RESULTS.md write failed"

printf 'capacity run: done -> %s ; report -> %s\n' "$WORK" "$SCRIPT_DIR/RESULTS.md"
