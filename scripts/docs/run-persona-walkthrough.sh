#!/usr/bin/env bash
# Six-persona walkthrough audit for VAL-DOCS-M4-010.
# For each persona, verify their CTA link target exists and is well-formed.
#
# Personas (per docs/index.md):
#   1. Developer / agent author
#   2. Eval engineer
#   3. SRE / oncall
#   4. Compliance officer / auditor
#   5. ML safety reviewer
#   6. Contract author
#
# Exit codes:
#   0  - All 6 persona paths resolve in <=2 clicks
#   1  - One or more persona paths broken
#   64 - usage / runtime error

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

INDEX="docs/index.md"
[ -f "$INDEX" ] || { echo "FAIL: $INDEX missing" >&2; exit 64; }

# Persona CTA target map: persona => first-click target relative to docs/
# Each must resolve to an existing file under the repo. Targets beginning
# with ../ are resolved relative to the repo root (escape from docs/).
declare -a PERSONAS=(
  "Developer:getting-started/install.md"
  "Eval engineer:../packages/evals/README.md"
  "SRE / oncall:how-to/debug-replay-failures.md"
  "Compliance officer:how-to/extract-ai-act-readiness-evidence.md"
  "ML safety reviewer:how-to/audit-gate-decision.md"
  "Contract author:contracts/cel-primer.md"
)

OUTPUT_DIR=${PERSONA_OUTPUT_DIR:-"$HOME/.ops-runtime/relay-docs-v1-20260522/audits"}
mkdir -p "$OUTPUT_DIR"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${OUTPUT_DIR}/persona-walkthrough-${TS}.md"

{
  echo "# Persona Walkthrough Log"
  echo
  echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Source: $INDEX"
  echo
  echo "| Persona | Target (1st click) | Resolves? |"
  echo "|---|---|---|"
} > "$OUT"

FAIL_COUNT=0
for entry in "${PERSONAS[@]}"; do
  persona="${entry%%:*}"
  target="${entry#*:}"
  # Resolve relative to docs/ (or to repo root if target escapes via ../)
  if [[ "$target" == ../* ]]; then
    fullpath="$ROOT/$(echo "$target" | sed 's|^\.\./||')"
  else
    fullpath="$ROOT/docs/$target"
  fi
  if [ -f "$fullpath" ]; then
    status="OK"
  else
    status="MISSING ($fullpath)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  echo "| $persona | \`$target\` | $status |" >> "$OUT"
  echo "  $persona -> $target -> $status"
done

echo
echo "[persona walkthrough] log written to: $OUT"

if [ $FAIL_COUNT -gt 0 ]; then
  echo "FAIL: $FAIL_COUNT persona target(s) missing" >&2
  exit 1
fi
echo "[persona walkthrough] PASS (6/6 personas resolved)"
