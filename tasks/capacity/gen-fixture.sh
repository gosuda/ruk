#!/usr/bin/env bash
# Capacity fixture generator (dev-scale shape of the production profile).
#
# Produces a deterministic repository population:
#   <out>/small-NNN      N small repos (few files/commits each)
#   <out>/large-<K>      one repo per branch-count step K with K branches
#   <out>/manifest.txt   seed, generator version, counts, sizes
#
# Shape follows local://ruk-reference-production-profile.md; byte volume is
# deliberately DEV-SCALE (see README.md). Deterministic seed 0x52554b01.
#
# Usage:
#   bash tasks/capacity/gen-fixture.sh --out DIR [--small N]
#       [--branches "1000 10000"] [--shape mixed] [--large-commits C] [--full]
#       [--ruk PATH]
#   --full adds the 100000 and 1000000 steps (slow; needs a full-profile host).
#   --ruk PATH (default: <root>/target/debug/ruk) also migrates every created
#   repo into a co-located `.ruk` store (`ruk migrate <gitdir> <worktree>`),
#   so run.sh can serve `ruk git -C <dir>` beside the git baseline. When the
#   binary is missing, fixtures stay git-only with a manifest note.
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)" || exit 1

GEN_VERSION="capacity-gen-0.1.0"
SEED="${SEED:-0x52554b01}"
OUT=""
SMALL_N=8
BRANCH_STEPS="1000 10000"
SHAPE="mixed"
LARGE_COMMITS=200
FULL=0
GITBIN="${GITBIN:-/usr/bin/git}"
RUKBIN="${RUKBIN:-$ROOT/target/debug/ruk}"

die() {
  printf 'gen-fixture: %s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?missing --out value}"; shift 2 ;;
    --small) SMALL_N="${2:?missing --small value}"; shift 2 ;;
    --branches) BRANCH_STEPS="${2:?missing --branches value}"; shift 2 ;;
    --shape) SHAPE="${2:?missing --shape value}"; shift 2 ;;
    --large-commits) LARGE_COMMITS="${2:?missing --large-commits value}"; shift 2 ;;
    --full) FULL=1; shift ;;
    --ruk) RUKBIN="${2:?missing --ruk value}"; shift 2 ;;
    *) die "unknown flag: $1" ;;
  esac
done

[ -n "$OUT" ] || die "--out DIR is required"
[ -x "$GITBIN" ] || die "GITBIN not executable: $GITBIN"
case "$SHAPE" in
  shared | distinct | mixed) ;;
  *) die "--shape must be shared, distinct, or mixed" ;;
esac
if [ "$FULL" -eq 1 ]; then
  BRANCH_STEPS="1000 10000 100000 1000000"
fi

mkdir -p -- "$OUT" || die "cannot create out dir: $OUT"

export LC_ALL=C TZ=UTC0 PAGER=cat GIT_PAGER=cat GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=Fixture GIT_AUTHOR_EMAIL="fixture@ruk-capacity"
export GIT_COMMITTER_NAME=Fixture GIT_COMMITTER_EMAIL="fixture@ruk-capacity"

# Deterministic ISO-ish date from an integer index (base 2001-01-01 + n sec).
fdate() {
  printf '@%d +0000' "$((946684800 + $1))"
}

# make_small <dir> <index>: 5 commits x 4 deterministic ~1 KiB files.
make_small() {
  dir="$1"
  idx="$2"
  mkdir -p -- "$dir" || die "cannot create $dir"
  "$GITBIN" init -q -b main "$dir" || die "init failed: $dir"
  c=1
  while [ "$c" -le 5 ]; do
    f=1
    while [ "$f" -le 4 ]; do
      # Deterministic ~1 KiB payload: no $RANDOM anywhere.
      {
        printf 'seed=%s repo=%d commit=%d file=%d\n' "$SEED" "$idx" "$c" "$f"
        n=1
        while [ "$n" -le 32 ]; do
          printf 'line %d of repo %d commit %d file %d seed %s\n' "$n" "$idx" "$c" "$f" "$SEED"
          n=$((n + 1))
        done
      } >"$dir/f${c}_${f}.txt" || die "write failed: $dir"
      f=$((f + 1))
    done
    export GIT_AUTHOR_DATE GIT_COMMITTER_DATE
    GIT_AUTHOR_DATE="$(fdate "$((idx * 100 + c))")"
    GIT_COMMITTER_DATE="$(fdate "$((idx * 100 + c))")"
    "$GITBIN" -C "$dir" add -A || die "add failed: $dir"
    "$GITBIN" -C "$dir" commit -qm "small $idx commit $c seed $SEED" || die "commit failed: $dir"
    c=$((c + 1))
  done
}

# make_large <dir> <K>: base history + K branches per --shape.
make_large() {
  dir="$1"
  total="$2"
  mkdir -p -- "$dir" || die "cannot create $dir"
  "$GITBIN" init -q -b main "$dir" || die "init failed: $dir"
  c=1
  while [ "$c" -le "$LARGE_COMMITS" ]; do
    printf 'seed=%s large base commit %d\n' "$SEED" "$c" >"$dir/base_${c}.txt" || die "write failed"
    export GIT_AUTHOR_DATE GIT_COMMITTER_DATE
    GIT_AUTHOR_DATE="$(fdate "$c")"
    GIT_COMMITTER_DATE="$(fdate "$c")"
    "$GITBIN" -C "$dir" add -A || die "add failed: $dir"
    "$GITBIN" -C "$dir" commit -qm "large base $c seed $SEED" || die "commit failed: $dir"
    c=$((c + 1))
  done
  tip="$("$GITBIN" -C "$dir" rev-parse HEAD)" || die "rev-parse failed: $dir"
  i=1
  while [ "$i" -le "$total" ]; do
    name="$(printf 'b%06d' "$i")"
    case "$SHAPE" in
      shared)
        "$GITBIN" -C "$dir" branch "$name" "$tip" || die "branch failed: $name"
        ;;
      distinct)
        printf 'seed=%s branch %s\n' "$SEED" "$name" >"$dir/tip_${name}.txt" || die "write failed"
        export GIT_AUTHOR_DATE GIT_COMMITTER_DATE
        GIT_AUTHOR_DATE="$(fdate "$((LARGE_COMMITS + i))")"
        GIT_COMMITTER_DATE="$(fdate "$((LARGE_COMMITS + i))")"
        "$GITBIN" -C "$dir" add -A || die "add failed"
        "$GITBIN" -C "$dir" checkout -qb "$name" || die "checkout -b failed: $name"
        "$GITBIN" -C "$dir" commit -qm "tip $name seed $SEED" || die "commit failed: $name"
        "$GITBIN" -C "$dir" checkout -q main || die "checkout main failed"
        ;;
      mixed)
        if [ "$((i % 2))" -eq 0 ]; then
          "$GITBIN" -C "$dir" branch "$name" "$tip" || die "branch failed: $name"
        else
          printf 'seed=%s branch %s\n' "$SEED" "$name" >"$dir/tip_${name}.txt" || die "write failed"
          export GIT_AUTHOR_DATE GIT_COMMITTER_DATE
          GIT_AUTHOR_DATE="$(fdate "$((LARGE_COMMITS + i))")"
          GIT_COMMITTER_DATE="$(fdate "$((LARGE_COMMITS + i))")"
          "$GITBIN" -C "$dir" add -A || die "add failed"
          "$GITBIN" -C "$dir" checkout -qb "$name" || die "checkout -b failed: $name"
          "$GITBIN" -C "$dir" commit -qm "tip $name seed $SEED" || die "commit failed: $name"
          "$GITBIN" -C "$dir" checkout -q main || die "checkout main failed"
        fi
        ;;
    esac
    if [ "$((i % 2000))" -eq 0 ]; then
      printf 'gen-fixture: %s branches...\n' "$i"
    fi
    i=$((i + 1))
  done
  # Remove worktree tip files for odd branches so the tree stays small-ish.
  "$GITBIN" -C "$dir" checkout -q main || die "final checkout failed"
}

# seed_ruk <dir>: migrate a git-created fixture repo into a co-located `.ruk`
# store so `ruk git -C <dir>` serves it. Never fails: without an executable
# ruk the fixtures stay git-only and run.sh records BLOCKED with a reason.
seed_ruk() {
  dir="$1"
  if [ ! -x "$RUKBIN" ]; then
    return 0
  fi
  if abs_dir="$(cd -- "$dir" 2>/dev/null && pwd)" && [ -n "$abs_dir" ]; then
    if "$RUKBIN" git -C "$abs_dir" migrate "$abs_dir/.git" "$abs_dir" >/dev/null 2>&1; then
      return 0
    fi
  fi
  printf 'gen-fixture: warning: ruk migrate failed for %s\n' "$dir" >&2
}

if [ -x "$RUKBIN" ]; then
  RUK_INFO="$("$RUKBIN" git version 2>/dev/null || printf 'ruk git version failed')"
else
  RUK_INFO="unavailable: no executable at $RUKBIN"
fi
printf 'gen-fixture %s seed=%s shape=%s out=%s\n' "$GEN_VERSION" "$SEED" "$SHAPE" "$OUT"
printf 'gen-fixture: ruk: %s\n' "$RUK_INFO"

i=0
while [ "$i" -lt "$SMALL_N" ]; do
  name="$(printf 'small-%03d' "$i")"
  make_small "$OUT/$name" "$i"
  seed_ruk "$OUT/$name"
  i=$((i + 1))
done
printf 'gen-fixture: %d small repos done\n' "$SMALL_N"

# Iterate steps without word-splitting hazards: steps are validated integers.
printf '%s\n' "$BRANCH_STEPS" | tr ' ' '\n' | while IFS= read -r k; do
  case "$k" in
    '' | *[!0-9]*) die "bad branch step: $k" ;;
  esac
  if [ "$k" -ge 100000 ] && [ "$FULL" -ne 1 ]; then
    die "step $k requires --full"
  fi
  make_large "$OUT/large-$k" "$k"
  seed_ruk "$OUT/large-$k"
  printf 'gen-fixture: large-%s done\n' "$k"
done

{
  printf 'generator: %s\n' "$GEN_VERSION"
  printf 'seed: %s\n' "$SEED"
  printf 'shape: %s\n' "$SHAPE"
  printf 'date-utc: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'git: %s\n' "$("$GITBIN" --version)"
  printf 'ruk: %s\n' "$RUK_INFO"
  printf 'ruk-stores: %s\n' "$(find "$OUT" -maxdepth 2 -name .ruk 2>/dev/null | wc -l | tr -d ' ')"
  printf 'small-repos: %d\n' "$SMALL_N"
  printf 'branch-steps: %s\n' "$BRANCH_STEPS"
  printf 'large-base-commits: %d\n' "$LARGE_COMMITS"
  printf 'full-profile-steps: %d\n' "$FULL"
} >"$OUT/manifest.txt" || die "manifest write failed"

printf 'gen-fixture: sizes (dev-scale; profile wants median 16 MiB / 1-100 GiB large):\n'
du -sh -- "$OUT"/* | sort -k2 || die "du failed"
printf 'gen-fixture: done -> %s\n' "$OUT"
