#!/usr/bin/env bash
#
# SENTINEL security source gate.
#
# Rejects TODO markers, @ts-ignore, and untyped `any` in source. This is a
# Definition-of-Done gate (execution plan section 7): "No `any`, no
# `@ts-ignore`, no TODO in security-critical paths."
#
# WHY THIS IS A SCRIPT AND NOT INLINE YAML
# ----------------------------------------
# The previous inline version was a false green for the whole life of the
# pipeline. `ripgrep` is not installed on the GitHub runner image, and the
# checks were written as:
#
#     if rg ... ; then echo 'failed'; exit 1; fi        # rg missing -> 127
#     matches="$(rg ... || true)"                       # rg missing -> ""
#
# A missing scanner exits 127, the `if` read that as "no matches", and `|| true`
# swallowed the rest — so "the scanner found nothing" and "the scanner never
# ran" were indistinguishable, and the step reported success while scanning
# nothing. A security gate that cannot tell those apart is worse than no gate,
# because it manufactures evidence.
#
# This version fails closed:
#   * the scanner's presence is verified before any scan;
#   * ripgrep's exit codes are interpreted explicitly — 0 means matches were
#     found, 1 means none were, and ANY other status is a scanner failure;
#   * there is no `|| true` anywhere on a scanner invocation.
#
# Exit codes:
#   0  clean
#   1  a forbidden pattern was found
#   2  the gate could not run (missing scanner, missing roots, scanner error)
#
# Usage: security-source-gate.sh [root-directory]
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

FAIL_VIOLATION=1
FAIL_CANNOT_RUN=2

if ! command -v rg >/dev/null 2>&1; then
  echo "Security source gate CANNOT RUN: ripgrep (rg) is not on PATH." >&2
  echo "Install it before this gate runs; a skipped scan must never look like a passing scan." >&2
  exit "$FAIL_CANNOT_RUN"
fi

# EVERY canonical root must be present. Accepting whichever roots happened to
# exist left a false green: a tree missing `services/` would still report
# "passed: scanned apps packages tests", which reads as a clean scan of the
# whole repository. A partially-scanned tree is not a passing tree.
#
# `-d` rather than `-e`: a FILE named `services` must not satisfy a directory
# invariant.
CANDIDATE_ROOTS=(services apps packages tests)
ROOTS=()
for candidate in "${CANDIDATE_ROOTS[@]}"; do
  if [ ! -d "$candidate" ]; then
    echo "Security source gate CANNOT RUN: required source root '$candidate' is missing under '$ROOT'." >&2
    exit "$FAIL_CANNOT_RUN"
  fi
  ROOTS+=("$candidate")
done

# Runs ripgrep and returns its output, distinguishing "no matches" from failure.
# Sets RG_OUTPUT and returns 0 when matches exist, 1 when there are none, and
# exits the whole gate when ripgrep itself fails.
RG_OUTPUT=""
run_scan() {
  local description="$1"
  shift
  set +e
  RG_OUTPUT="$(rg "$@")"
  local status=$?
  set -e
  case "$status" in
    0) return 0 ;;
    1) RG_OUTPUT=""; return 1 ;;
    *)
      echo "Security source gate CANNOT RUN: scanner failed during ${description} (rg exit ${status})." >&2
      exit "$FAIL_CANNOT_RUN"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# 1. TODO markers and @ts-ignore
# ---------------------------------------------------------------------------
if run_scan "the TODO/@ts-ignore scan" -n --glob '*.ts' --glob '*.tsx' --glob '*.prisma' 'TODO|@ts-ignore' "${ROOTS[@]}"; then
  printf '%s\n' "$RG_OUTPUT"
  echo 'Security source gate FAILED: TODO marker or @ts-ignore found.' >&2
  exit "$FAIL_VIOLATION"
fi

# ---------------------------------------------------------------------------
# 2. Untyped `any`
#
# Matches TypeScript any annotations/casts/generic arguments, while
# intentionally ignoring prose and Vitest's expect.any(...).
# ---------------------------------------------------------------------------
ANY_PATTERN='(:[[:space:]]*any\b|\bas[[:space:]]+any\b|<[[:space:]]*any[[:space:]]*>|,[[:space:]]*any\b|\bany\[\])'

if run_scan "the untyped-any scan" -n --glob '*.ts' --glob '*.tsx' "$ANY_PATTERN" "${ROOTS[@]}"; then
  any_candidates="$RG_OUTPUT"

  # Strip comment lines. `rg -v` exits 1 when EVERY line was filtered out, which
  # is the clean case here rather than an error — so the same explicit status
  # handling applies in reverse.
  set +e
  any_code="$(printf '%s\n' "$any_candidates" | rg -v ':[0-9]+:[[:space:]]*(//|\*|/\*)')"
  filter_status=$?
  set -e
  case "$filter_status" in
    0) ;;
    1) any_code="" ;;
    *)
      echo "Security source gate CANNOT RUN: scanner failed while filtering comments (rg exit ${filter_status})." >&2
      exit "$FAIL_CANNOT_RUN"
      ;;
  esac

  if [ -n "$any_code" ]; then
    printf '%s\n' "$any_code"
    echo 'Security source gate FAILED: untyped any detected.' >&2
    exit "$FAIL_VIOLATION"
  fi
fi

echo "Security source gate passed: scanned ${ROOTS[*]}"
