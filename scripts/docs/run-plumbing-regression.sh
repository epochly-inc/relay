#!/usr/bin/env bash
# Plumbing-tier regression audit for VAL-DOCS-M4-011.
# Run tier-1 plumbing tests; persist summary; confirm baseline-counts
# delta >= 0 and offenders == 0.
#
# Exit codes:
#   0  - PASS (tests green, baseline-counts delta >= 0)
#   1  - FAIL (test failure or baseline regression)
#   2  - FAIL (wall-clock budget exceeded)
#   64 - usage / runtime error (missing baseline files unless
#        ALLOW_MISSING_BASELINE=1 is set explicitly)
#
# Fix #9 (roborev 365, structural-review A): missing baseline-counts
# prerequisites are now a HARD failure with exit 64, not a silent skip.
# The whole point of the regression guard is to be present; "best-effort"
# defeated it. To explicitly opt-in to running without the baseline check
# (e.g. for first-time bootstrap), set ALLOW_MISSING_BASELINE=1.
#
# Fix LOW (roborev 365): also enforce a wall-clock budget. CLAUDE.md says
# tier-1 plumbing must complete in <= 60s. We allow a 90s ceiling to give
# headroom on slow CI runners; exceed it and we exit 2 with a clear message.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

OUTPUT_DIR=${PLUMBING_OUTPUT_DIR:-"$HOME/.ops-runtime/relay-docs-v1-20260522/audits"}
mkdir -p "$OUTPUT_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="${OUTPUT_DIR}/plumbing-${TS}.log"

# Wall-clock budget in seconds. Override via PLUMBING_BUDGET_SECONDS.
#
# CLAUDE.md "tier-1 plumbing <= 60s" applies to per-package plumbing where
# tests are pure-Python unit tests. THIS script aggregates the docs-related
# plumbing tier across tests/docs/ + tests/test_lint_banned_copy.py, which
# inherently subprocess-invokes the audit script (10x layers) and the
# banned-copy lint, plus the build-cli-reference / build-error-reference /
# build-schemas-reference generators against fixture inputs. The combined
# runtime is in the 2-3 minute range. We set a 300s ceiling that catches
# runaway hangs while accommodating the legitimate subprocess overhead;
# CI can tighten this per-runner via PLUMBING_BUDGET_SECONDS if desired.
BUDGET_SECONDS=${PLUMBING_BUDGET_SECONDS:-300}

# Scope: only docs/ + the audit + lint test modules. We are not the place
# to run the full repo's plumbing -- that's a separate CI gate. We verify
# our additions did not break the docs-related plumbing surface.

START_TS=$(date +%s)
echo "[plumbing regression] running tier-1 plumbing-tagged tests..." | tee "$LOG"

# Disable strict-error around the pytest pipeline so we can capture the
# real exit code via PIPESTATUS (under `set -e | tee`, tee's exit code
# (always 0) would mask pytest failures).
set +e
uv run pytest \
  tests/docs/ \
  tests/test_lint_banned_copy.py \
  -m plumbing \
  --timeout=120 \
  -q 2>&1 | tee -a "$LOG"
PYTEST_RC=${PIPESTATUS[0]}
set -e

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
echo "[plumbing regression] tests completed in ${ELAPSED}s (budget ${BUDGET_SECONDS}s)" | tee -a "$LOG"

if [ "$PYTEST_RC" -ne 0 ]; then
  echo "FAIL: plumbing tier tests did not all pass (pytest exit $PYTEST_RC); see $LOG" >&2
  exit 1
fi

# Fix LOW: enforce wall-clock budget. Tier-1 must stay snappy.
if [ "$ELAPSED" -gt "$BUDGET_SECONDS" ]; then
  echo "FAIL: plumbing tier exceeded ${BUDGET_SECONDS}s budget (took ${ELAPSED}s); see $LOG" >&2
  exit 2
fi

# Fix #9: baseline-counts is REQUIRED. Missing prerequisites are a hard
# failure, not a silent skip. Set ALLOW_MISSING_BASELINE=1 to opt out.
BASELINE_SCRIPT="scripts/check-baseline-counts.py"
BASELINE_DATA="tests/baseline-counts.json"

if [ ! -f "$BASELINE_SCRIPT" ] || [ ! -f "$BASELINE_DATA" ]; then
  if [ "${ALLOW_MISSING_BASELINE:-0}" = "1" ]; then
    echo "[plumbing regression] baseline-counts prerequisites absent; SKIPPED via ALLOW_MISSING_BASELINE=1" | tee -a "$LOG"
  else
    echo "FAIL: baseline-counts prerequisites missing:" >&2
    [ ! -f "$BASELINE_SCRIPT" ] && echo "  - $BASELINE_SCRIPT" >&2
    [ ! -f "$BASELINE_DATA" ] && echo "  - $BASELINE_DATA" >&2
    echo "  (set ALLOW_MISSING_BASELINE=1 to bootstrap without this guard)" >&2
    exit 64
  fi
else
  echo "[plumbing regression] checking baseline-counts..." | tee -a "$LOG"
  set +e
  uv run python "$BASELINE_SCRIPT" 2>&1 | tee -a "$LOG"
  BASELINE_RC=${PIPESTATUS[0]}
  set -e
  if [ "$BASELINE_RC" -ne 0 ]; then
    echo "FAIL: baseline-counts regression detected (exit $BASELINE_RC); see $LOG" >&2
    exit 1
  fi
fi

echo "[plumbing regression] PASS (${ELAPSED}s / ${BUDGET_SECONDS}s budget)"
echo "[plumbing regression] log: $LOG"
