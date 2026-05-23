#!/usr/bin/env bash
# Final-acceptance regression audit for relay-docs-v1-20260522 operation.
# Run all 4 audit layers across every wave; persist JSON evidence + assert
# zero P0 findings and bounded P1.
#
# This script is invoked by:
#   - VAL-DOCS-M4-009 (final-acceptance gate)
#   - m4-f10 (persona walkthrough -- checks audit is green before walkthrough)
#   - CI on every push to main (via .github/workflows/lint-docs.yml)
#
# Exit codes:
#   0  - PASS (p0=0, p1<=3)
#   1  - FAIL (p0>0 or p1>3)
#   64 - usage / runtime error
#
# Fix #8 (roborev 362): the symlink update MUST happen on every run
# (pass or fail) so downstream consumers reading final-latest.json never
# see a stale-but-passing snapshot when the current run failed. Previously
# the script exited 1 on audit failure BEFORE the symlink ran, leaving
# the prior green result as "latest".
# Fix LOW-#24 (roborev 362): run all 4 layers as the script and contract
# document. Layer 3 is currently a stub that exits clean; including it
# keeps the JSON evidence matching the stated --layers 1,2,3,4 contract.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

AUDIT_OUTPUT_DIR=${AUDIT_OUTPUT_DIR:-"$HOME/.ops-runtime/relay-docs-v1-20260522/audits"}
mkdir -p "$AUDIT_OUTPUT_DIR"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTPUT="${AUDIT_OUTPUT_DIR}/final-${TS}.json"
LATEST="${AUDIT_OUTPUT_DIR}/final-latest.json"

# Fix #8 helper: update the canonical symlink to whatever JSON we just
# produced, even if the audit reported P0/P1 failures or the audit script
# itself crashed. Operators reading final-latest.json get the current run.
update_latest_symlink() {
  if [ -f "$OUTPUT" ]; then
    ln -sf "$(basename "$OUTPUT")" "$LATEST"
    echo "[final-acceptance audit] latest symlink updated: $LATEST -> $(basename "$OUTPUT")"
  fi
}

echo "[final-acceptance audit] running --all-waves --layers 1,2,3,4..."
# Disable pipefail/errexit just for the audit invocation so we can capture
# a non-zero exit and still proceed to validate + update the symlink.
set +e
uv run python scripts/docs/audit-codebase-alignment.py --all-waves --layers 1,2,3,4 --json > "$OUTPUT"
AUDIT_RC=$?
set -e

# Always refresh the latest symlink before evaluating pass/fail so that
# downstream consumers see THIS run regardless of the verdict.
update_latest_symlink

if [ "$AUDIT_RC" -ne 0 ]; then
  echo "[final-acceptance audit] audit script exited with rc=$AUDIT_RC"
  # Fall through to the python validator below so we surface structured
  # failure info instead of just a numeric rc.
fi

# Validate and print summary. Reads $OUTPUT which is the just-written JSON.
# Disable strict-error around the python heredoc so the trailing echo +
# explicit "exit $PY_RC" runs even when python exits non-zero (otherwise
# `set -e` would abort before we can report the result path).
set +e
OUTPUT="$OUTPUT" AUDIT_RC="$AUDIT_RC" python3 - <<'PY'
import json, os, sys
path = os.environ["OUTPUT"]
audit_rc = int(os.environ.get("AUDIT_RC", "0"))
try:
    d = json.load(open(path))
except Exception as exc:  # pragma: no cover - defensive
    print(f"FAIL: could not parse audit JSON at {path}: {exc}")
    sys.exit(64)
s = d.get('summary', {})
p0 = s.get('p0', 0); p1 = s.get('p1', 0); p2 = s.get('p2', 0); n = s.get('files_audited', 0)
print(f"[final-acceptance audit] files_audited={n} p0={p0} p1={p1} p2={p2}")
if p0 > 0:
    print(f"FAIL: p0={p0} findings (must be 0):")
    for f in d.get('findings', [])[:5]:
        if f.get('severity') == 'P0':
            print(f"  {f.get('file','?')}:{f.get('line','?')} {f.get('message','')[:100]}")
    sys.exit(1)
if p1 > 3:
    print(f"FAIL: p1={p1} > 3 cap")
    sys.exit(1)
if audit_rc != 0 and p0 == 0 and p1 == 0:
    # Audit script crashed before emitting findings; treat as runtime error.
    print(f"FAIL: audit script exited rc={audit_rc} with no findings recorded")
    sys.exit(64)
print("[final-acceptance audit] PASS")
sys.exit(0)
PY
PY_RC=$?
set -e

echo "[final-acceptance audit] result: $OUTPUT (latest: $LATEST)"
exit "$PY_RC"
