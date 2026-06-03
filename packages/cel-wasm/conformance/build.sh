#!/usr/bin/env bash
# Conformance pipeline for relay-cel-wasm, runnable FROM THE REPO.
#
#   build  : cargo build the wasm (release, wasm32-unknown-unknown)
#   oracle : build the Go parser+oracle and emit oracle_records.jsonl
#            (textproto ground truth + cel-go reference, typed-canonical)
#   run    : drive the wasm through the corpus -> results.jsonl + summary.json
#   parity : cross-host byte-parity (Python vs Node) -> diff must be exit 0
#   all    : build + oracle + run + parity
#
# Requirements: rustc + wasm32-unknown-unknown target, Go 1.25, Node, and the
# Python venv with wasmtime-py. The cel-spec corpus path defaults to the WS1
# checkout but is overridable via CEL_SPEC_CORPUS.
#
# ASCII-only output (CLAUDE.md directive 3).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/.." && pwd)"
CRATE="$PKG/crate"
ORACLE_DIR="$HERE/oracle"
HARNESS="$HERE/harness"

WASM="$CRATE/target/wasm32-unknown-unknown/release/relay_cel_wasm.wasm"
CEL_SPEC_CORPUS="${CEL_SPEC_CORPUS:-/tmp/cel-spec-ws1/tests/simple/testdata}"
SCOPE="${SCOPE:-basic,comparisons,conversions,dynamic,fp_math,integer_math,lists,logic,macros,macros2,namespace,parse,plumbing,string,timestamps,type_deduction}"

# Python: prefer the repo venv if present.
REPO_ROOT="$(cd "$PKG/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
  PYTHON="$REPO_ROOT/.venv/bin/python"
fi

cmd_build() {
  echo "[build] cargo build --release --target wasm32-unknown-unknown"
  ( cd "$CRATE" && cargo build --release --target wasm32-unknown-unknown )
  ls -la "$WASM"
}

cmd_oracle() {
  echo "[oracle] building Go parser+oracle"
  ( cd "$ORACLE_DIR" && go build -o celoracle . )
  echo "[oracle] corpus=$CEL_SPEC_CORPUS scope=$SCOPE"
  if [ ! -d "$CEL_SPEC_CORPUS" ]; then
    echo "[oracle] FAIL: corpus dir not found: $CEL_SPEC_CORPUS" >&2
    echo "[oracle] set CEL_SPEC_CORPUS to a google/cel-spec tests/simple/testdata dir" >&2
    exit 2
  fi
  "$ORACLE_DIR/celoracle" -corpus "$CEL_SPEC_CORPUS" -only "$SCOPE" \
    > "$HARNESS/oracle_records.jsonl"
  echo "[oracle] wrote $HARNESS/oracle_records.jsonl ($(wc -l < "$HARNESS/oracle_records.jsonl") records)"
}

cmd_run() {
  echo "[run] driving relay-cel-wasm through the corpus"
  CEL_WASM="$WASM" "$PYTHON" "$HARNESS/compare.py"
}

cmd_parity() {
  echo "[parity] Python dump"
  CEL_WASM="$WASM" "$PYTHON" "$HARNESS/py_dump.py"
  echo "[parity] Node dump"
  CEL_WASM="$WASM" node "$HARNESS/js_dump.mjs"
  echo "[parity] diff (must be exit 0 == byte-identical)"
  if diff "$HARNESS/py_dump.txt" "$HARNESS/js_dump.txt"; then
    echo "[parity] PASS: Python and Node output byte-identical"
  else
    echo "[parity] FAIL: cross-host byte divergence (P0)" >&2
    exit 1
  fi
}

case "${1:-all}" in
  build) cmd_build ;;
  oracle) cmd_oracle ;;
  run) cmd_run ;;
  parity) cmd_parity ;;
  all)
    cmd_build
    cmd_oracle
    cmd_run
    cmd_parity
    ;;
  *)
    echo "usage: $0 {build|oracle|run|parity|all}" >&2
    exit 2
    ;;
esac
