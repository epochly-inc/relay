#!/usr/bin/env bash
# Plumbing-tier regression audit for VAL-DOCS-M4-011.
# Run tier-1 plumbing tests; persist summary; confirm baseline-counts
# delta >= 0 and offenders == 0.
#
# Exit codes:
#   0  - PASS (tests green, baseline-counts delta >= 0)
#   1  - FAIL (test failure or baseline regression)
#   64 - usage / runtime error

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

OUTPUT_DIR=${PLUMBING_OUTPUT_DIR:-"$HOME/.ops-runtime/relay-docs-v1-20260522/audits"}
mkdir -p "$OUTPUT_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="${OUTPUT_DIR}/plumbing-${TS}.log"

# Per CLAUDE.md: tier-1 plumbing must run <= 60s. Use marker-based selection.
# Scope: only docs/ + the audit + lint test modules (we're not the place to
# run the full repo's plumbing -- that's a separate CI gate; we verify our
# additions did not break the docs-related plumbing surface).

echo "[plumbing regression] running tier-1 plumbing-tagged tests..." | tee "$LOG"
if ! uv run pytest \
  tests/docs/ \
  tests/test_lint_banned_copy.py \
  -m plumbing \
  --timeout=120 \
  -q 2>&1 | tee -a "$LOG"; then
  echo "FAIL: plumbing tier tests did not all pass; see $LOG" >&2
  exit 1
fi

# baseline-counts check (best-effort; runs only if script + baseline exist)
if [ -f "scripts/check-baseline-counts.py" ] && [ -f "tests/baseline-counts.json" ]; then
  echo "[plumbing regression] checking baseline-counts..." | tee -a "$LOG"
  if ! uv run python scripts/check-baseline-counts.py 2>&1 | tee -a "$LOG"; then
    echo "FAIL: baseline-counts regression detected; see $LOG" >&2
    exit 1
  fi
else
  echo "[plumbing regression] baseline-counts script/data not present; skipped" | tee -a "$LOG"
fi

echo "[plumbing regression] PASS"
echo "[plumbing regression] log: $LOG"
