#!/usr/bin/env bash
# Structural-gate checker: verifies the code-level invariants it can and
# reports honestly which gates need runtime proof.
#
# Each gate prints one of:
#   STATIC-PRESENT <evidence>  — mechanism exists in the tree (not a
#                                correctness proof; behavior needs runtime runs)
#   ABSENT <what is missing>   — no mechanism found; gate fails statically
#   NEEDS-RUNTIME-PROOF <note> — static presence is meaningless here; only a
#                                live run (tasks/capacity/run.sh full profile,
#                                daemon + load generator) can decide it
#
# Mandatory-structural list (from the scale plan):
#   bounded memory/queues/disk reservations; no corruption; no lost
#   acknowledged update; no authorization bypass; exact command/protocol
#   outcomes; no unrelated ref scan for single-ref lookup/update;
#   bounded-memory complete advertisements; no starvation after overload.
#
# Usage: bash tasks/capacity/check-structure.sh [--root DIR]
set -euo pipefail
IFS=$'\n\t'

ROOT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) ROOT="${2:?missing --root value}"; shift 2 ;;
    *) printf 'check-structure: unknown flag: %s\n' "$1" >&2; exit 1 ;;
  esac
done
if [ -z "$ROOT" ]; then
  ROOT="$(cd "$(dirname "$0")/../.." && pwd)" || exit 1
fi

CORE="$ROOT/crates/ruk-core/src"
DAEMON="$ROOT/crates/ruk/src/daemon"
FAIL_N=0

# has <label> <grep-pattern> <paths...>: STATIC-PRESENT with first hit, else ABSENT.
has() {
  label="$1"
  pattern="$2"
  shift 2
  hit="$(grep -rn -- "$pattern" "$@" 2>/dev/null | head -n 1 || true)"
  if [ -n "$hit" ]; then
    printf 'STATIC-PRESENT  %-28s %s\n' "$label" "$hit"
  else
    printf 'ABSENT          %-28s pattern not found: %s\n' "$label" "$pattern"
    FAIL_N=$((FAIL_N + 1))
  fi
}

runtime() {
  printf 'NEEDS-RUNTIME-PROOF  %-22s %s\n' "$1" "$2"
}

printf 'check-structure: root=%s\n' "$ROOT"
printf 'check-structure: source=%s\n' "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
printf -- '--- bounded memory / queues / disk ---\n'
has "admission-limits" "AdmissionLimits::reference_profile" "$CORE/coord"
has "admission-validate" "fn validate" "$CORE/coord/admission.rs"
has "queue-refusal" "ELimit" "$CORE/coord/admission.rs" "$CORE/coord/admission"
has "deficit-round-robin" "deficit" "$CORE/coord/admission/scheduler.rs"
has "queue-deadline-refusal" "refuse_expired\|queue wait exceeded" "$CORE/coord/admission/scheduler.rs"
has "control-frame-bound" "MAX_CONTROL_FRAME_BYTES" "$CORE"
has "page-size-bound" "MAX_PAGE_SIZE" "$CORE"
has "lease-byte-budget" "LEASE_BOOKS_LIMIT\|ByteBudget" "$CORE/coord/leases.rs"
has "lease-refusal" "ELimit" "$CORE/coord/leases.rs"
runtime "cgroup-hwm" "memory.high/max, 128 repos / 32768 fds, per-repo 8-slot caps are deployment + load-run properties; no static check"
runtime "disk-reservation" "20%%/10%% free-space halts and per-txn reservations need a live filesystem run"
printf -- '--- no corruption ---\n'
has "durability-seam" "sync_file\|sync_dir" "$CORE/store/durability.rs"
has "immediate-commit" "Durability::Immediate" "$CORE/store/metadata.rs"
has "quarantine-latch" "quarantine" "$CORE/store"
has "crash-ack-proofs" "after_ack\|acknowledged publication is present" "$CORE/store/crash_tests.rs"
runtime "power-loss" "crash_tests prove process-kill boundaries only; power-loss persistence is unproven by design (see crash_tests.rs header)"
printf -- '--- no lost acknowledged update ---\n'
has "land-exactness" "equal the base\|exact.*base tip\|one atomic publication" "$CORE/coord/land.rs"
has "plan-single-use" "same commit as the ref" "$CORE/coord/land.rs"
has "idempotent-receipts" "idempotent" "$CORE/coord/receipt.rs"
has "digest-mismatch-refusal" "DigestMismatch\|E_REQUEST_REUSED\|Reused" "$CORE/coord/receipt.rs" "$DAEMON/mod.rs"
has "outcome-ledger" "outcome" "$DAEMON/mod.rs"
runtime "crash-around-publish" "survival of acknowledged ref updates needs kill-during-publish runs on the full fixture"
printf -- '--- no authorization bypass ---\n'
has "registry-roots" "canonicalized.*roots\|outside.*roots.*forbidden\|resolve" "$DAEMON/registry.rs"
has "dotdot-forbidden" "dotdot_escape_is_forbidden\|outside_roots_are_forbidden" "$DAEMON/registry.rs"
has "peer-auth" "authorize_peer\|allowed_uids" "$DAEMON"
has "endpoint-handshake" "reject_client\|STATUS_FORBIDDEN" "$CORE/coord/handshake.rs"
has "session-forbidden" "EForbidden" "$CORE/coord/hosted.rs"
has "claim-authz" "authorize_claim_list_args" "$CORE/coord/claims.rs"
runtime "http-429-503" "HTTP 429/503 + Retry-After mapping lives in the Forgejo layer; needs the HTTP boundary run"
printf -- '--- exact outcomes / no unrelated scan / bounded advertisement ---\n'
has "typed-errors" "ErrorCode::" "$CORE/error.rs"
has "bounded-pages" "FactPageBudget\|PageLimit" "$CORE"
has "oplog-walker" "walk_oplog_page" "$CORE/coord/hosted.rs"
has "oplog-visit-bound" "MAX_PAGE_SIZE" "$CORE/coord/hosted.rs"
has "cursor-binding" "CursorWant\|binding mismatch\|stale" "$CORE/coord/leases.rs" "$CORE/coord/claims.rs"
runtime "single-ref-no-scan" "indexed lookup without unrelated-ref scan needs profiling proof at 1M branches (run.sh lookup + adv-1M)"
runtime "adv-budget" "1 GiB / 30 s unfiltered advertisement budget needs the 1M-branch run; dev scale covers 1k/10k only"
runtime "no-starvation" "60 s recovery after burst needs the burst + recovery run, not grep"
printf -- '---\n'
printf 'check-structure: ABSENT=%d (static mechanism missing; gate fails without it)\n' "$FAIL_N"
printf 'check-structure: STATIC-PRESENT means the mechanism exists, never that the gate passes.\n'
if [ "$FAIL_N" -ne 0 ]; then
  exit 1
fi
