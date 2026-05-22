#!/usr/bin/env bash
# Regenerate TypeScript SDK reference from packages/sdk-typescript/src/index.ts.
# Requires: npx typedoc + typedoc-plugin-markdown (installed via npm).
# Graceful skip if npx unavailable (e.g., CI runner without Node).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
if ! command -v npx >/dev/null 2>&1; then
  echo "[SKIP] npx not found; install Node 22+ to regenerate." >&2
  exit 0
fi
OUT="${ROOT}/docs/reference/typescript-sdk"
mkdir -p "$OUT"
npx --yes -p typedoc -p typedoc-plugin-markdown -- typedoc \
  --plugin typedoc-plugin-markdown \
  --readme none \
  --excludePrivate \
  --out "$OUT" \
  packages/sdk-typescript/src/index.ts
echo "[OK] regenerated $OUT"
