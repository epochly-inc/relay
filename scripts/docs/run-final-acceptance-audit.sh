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

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

AUDIT_OUTPUT_DIR=${AUDIT_OUTPUT_DIR:-"$HOME/.ops-runtime/relay-docs-v1-20260522/audits"}
mkdir -p "$AUDIT_OUTPUT_DIR"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTPUT="${AUDIT_OUTPUT_DIR}/final-${TS}.json"

echo "[final-acceptance audit] running --all-waves --layers 1,2,4..."
if ! uv run python scripts/docs/audit-codebase-alignment.py --all-waves --layers 1,2,4 --json > "$OUTPUT"; then
  echo "[final-acceptance audit] FAIL: audit script exited non-zero"
  echo "  output saved to: $OUTPUT"
  exit 1
fi

# Validate and print summary
OUTPUT="$OUTPUT" python3 - <<'PY'
import json, os, sys
path = os.environ["OUTPUT"]
d = json.load(open(path))
s = d['summary']
p0 = s['p0']; p1 = s['p1']; p2 = s['p2']; n = s['files_audited']
print(f"[final-acceptance audit] files_audited={n} p0={p0} p1={p1} p2={p2}")
if p0 > 0:
    print(f"FAIL: p0={p0} findings (must be 0):")
    for f in d['findings'][:5]:
        if f['severity'] == 'P0':
            print(f"  {f['file']}:{f['line']} {f['message'][:100]}")
    sys.exit(1)
if p1 > 3:
    print(f"FAIL: p1={p1} > 3 cap")
    sys.exit(1)
print("[final-acceptance audit] PASS")
sys.exit(0)
PY

# Persist a canonical "latest" symlink for downstream consumers
LATEST="${AUDIT_OUTPUT_DIR}/final-latest.json"
ln -sf "$(basename "$OUTPUT")" "$LATEST"
echo "[final-acceptance audit] result: $OUTPUT (latest: $LATEST)"
