#!/usr/bin/env bash
# Conformance pipeline for relay-cel-wasm, runnable FROM THE REPO.
#
#   build  : cargo build the wasm (release, wasm32-unknown-unknown)
#   oracle : build the Go parser+oracle and emit oracle_records.jsonl
#            (textproto ground truth + cel-go reference, typed-canonical)
#   run    : drive the wasm through the corpus -> results.jsonl + summary.json
#   parity : cross-host byte-parity (Python vs Node) -> diff must be exit 0
#   all    : build + oracle + run + parity
#   repro  : WS3 cmp-rebuild gate -- two clean builds must produce an identical
#            sha256 (a signed, transparency-logged wasm is an evidence dependency,
#            so the build MUST be byte-deterministic). Slow: two full rebuilds.
#   gate   : WS6 conformance gate -- build + oracle + run + parity, then assert
#            the floor: ex-proto conformance == 100% AND cross-host byte-parity.
#            Non-zero exit on any regression. This is the CI release-block check
#            for the cel-wasm engine.
#   dist   : WS3 size pass -- wasm-opt -Oz the release wasm into dist/ and report
#            raw + gzip size vs the Cloudflare Workers 1MB compressed budget.
#            Optional (forward-looking for the edge deploy); requires binaryen.
#
# Requirements: rustc + wasm32-unknown-unknown target, Go 1.25, Node, and the
# Python venv with wasmtime-py. The cel-spec corpus path defaults to the WS1
# checkout but is overridable via CEL_SPEC_CORPUS. `dist` additionally needs
# wasm-opt (binaryen); `repro`/`gate` need a sha256 tool (sha256sum or shasum).
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

# Deterministic RUSTFLAGS for the reproducible release recipe. cargo 1.93.1 does
# NOT stabilize the in-manifest `trim-paths`, so we remap source-path prefixes on
# the stable compiler instead: CARGO_HOME -> /cargo (dependency panic-location
# strings), repo root -> /build (the crate + vendored cel), rustc sysroot ->
# /rust (std/core). This makes the embedded path strings independent of the build
# machine + checkout location, so two machines with the same pinned toolchain and
# Cargo.lock produce a byte-identical wasm. Verified: strips all ~123 embedded
# $HOME/.cargo paths. The reproducible artifact is defined by THIS recipe; a bare
# `cargo build` (no remap) is a dev build and may differ in embedded paths only
# (semantically identical -- remap rewrites strings, not behavior).
det_rustflags() {
  local cargo_home sysroot
  cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  sysroot="$(rustc --print sysroot)"
  printf -- '--remap-path-prefix=%s=/cargo --remap-path-prefix=%s=/build --remap-path-prefix=%s=/rust' \
    "$cargo_home" "$REPO_ROOT" "$sysroot"
}

# Portable sha256 (macOS dev box has /sbin/sha256sum; Linux CI has sha256sum;
# fall back to `shasum -a 256`). Prints the hex digest only.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cmd_build() {
  local rf; rf="$(det_rustflags)"
  echo "[build] cargo build --release --target wasm32-unknown-unknown (deterministic remap recipe)"
  ( cd "$CRATE" && RUSTFLAGS="$rf" cargo build --release --target wasm32-unknown-unknown )
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

# WS3 cmp-rebuild gate: two clean builds (via the deterministic recipe) must
# produce a byte-identical wasm. A signed, transparency-logged wasm is an
# evidence dependency -- a non-deterministic build is a P0 (the signature would
# not survive a rebuild + the transparency log could not be reproduced offline).
cmd_repro() {
  echo "[repro] cmp-rebuild: two clean builds must produce an identical sha256"
  ( cd "$CRATE" && cargo clean ) >/dev/null 2>&1
  cmd_build >/dev/null
  local h1; h1="$(sha256_of "$WASM")"
  echo "[repro] build 1 sha256: $h1"
  ( cd "$CRATE" && cargo clean ) >/dev/null 2>&1
  cmd_build >/dev/null
  local h2; h2="$(sha256_of "$WASM")"
  echo "[repro] build 2 sha256: $h2"
  # cross-machine leak check: the reproducible recipe must strip absolute paths
  local leaks; leaks="$(LC_ALL=C strings "$WASM" 2>/dev/null | grep -c "$HOME" || true)"
  echo "[repro] embedded \$HOME absolute paths: $leaks (must be 0 for cross-machine repro)"
  if [ "$h1" = "$h2" ] && [ "$leaks" -eq 0 ]; then
    echo "[repro] PASS: byte-deterministic ($h1), no machine-specific paths embedded"
  else
    echo "[repro] FAIL: build is not reproducible (h1=$h1 h2=$h2 leaks=$leaks) -- P0" >&2
    exit 1
  fi
}

# WS6 conformance gate (CI release-block for the cel-wasm engine): build + oracle
# + run, assert the floor ex-proto conformance == 100% (no in-scope regression),
# then assert cross-host byte-parity (diff exit 0). Either failing is non-zero.
cmd_gate() {
  cmd_build
  cmd_oracle
  cmd_run
  echo "[gate] asserting ex-proto conformance floor (== 100.0%)"
  local exproto
  exproto="$("$PYTHON" -c "import json;print(json.load(open('$HARNESS/summary.json'))['headline_exproto_pct'])")"
  echo "[gate] measured ex-proto: ${exproto}%"
  if ! "$PYTHON" -c "import json,sys;d=json.load(open('$HARNESS/summary.json'));sys.exit(0 if d['headline_exproto_pct']>=100.0 else 1)"; then
    echo "[gate] FAIL: ex-proto conformance regressed below 100.0% (got ${exproto}%) -- release blocked" >&2
    exit 1
  fi
  cmd_parity
  echo "[gate] PASS: ex-proto 100.0% AND cross-host byte-parity (release-block satisfied)"
}

# WS3 size pass (forward-looking for the Cloudflare edge deploy): wasm-opt -Oz the
# release wasm into dist/ and report raw + gzip size vs the CF Workers 1MB
# compressed budget. Optional: the raw release wasm is already 660KB gzip (63% of
# budget); this widens headroom. wasm-opt is deterministic for a pinned binaryen
# version, so the dist artifact stays reproducible given that pin.
cmd_dist() {
  local OUT="$PKG/dist/relay_cel_wasm.wasm"
  if ! command -v wasm-opt >/dev/null 2>&1; then
    echo "[dist] FAIL: wasm-opt (binaryen) not found." >&2
    echo "[dist] install: 'brew install binaryen' (macOS) or 'apt-get install binaryen' (Debian/CI)" >&2
    exit 2
  fi
  [ -f "$WASM" ] || cmd_build
  mkdir -p "$PKG/dist"
  echo "[dist] wasm-opt -Oz ($(wasm-opt --version))"
  wasm-opt -Oz "$WASM" -o "$OUT"
  local raw gz lim
  raw="$(wc -c < "$OUT" | tr -d ' ')"
  gz="$(gzip -9 -c "$OUT" | wc -c | tr -d ' ')"
  lim=1048576
  echo "[dist] $OUT"
  echo "[dist] raw=${raw} gzip=${gz} (CF 1MB compressed budget; ${gz}/${lim})"
  if [ "$gz" -ge "$lim" ]; then
    echo "[dist] FAIL: gzip size exceeds the 1MB Cloudflare Workers budget" >&2
    exit 1
  fi
  echo "[dist] PASS: under the 1MB compressed budget (sha256 $(sha256_of "$OUT"))"
}

case "${1:-all}" in
  build) cmd_build ;;
  oracle) cmd_oracle ;;
  run) cmd_run ;;
  parity) cmd_parity ;;
  repro) cmd_repro ;;
  gate) cmd_gate ;;
  dist) cmd_dist ;;
  all)
    cmd_build
    cmd_oracle
    cmd_run
    cmd_parity
    ;;
  *)
    echo "usage: $0 {build|oracle|run|parity|repro|gate|dist|all}" >&2
    exit 2
    ;;
esac
