// VAL-CWC-P7EDGE-004: Node half of the FUEL-EXHAUSTION cross-host envelope
// byte-parity gate.
//
// This is the NODE counterpart to the Python wasmtime host in the pytest runner
// tests/conformance/cel/test_fuel_exhaustion_cross_host_envelope_parity.py. The
// pytest runner drives the FIXED fuel-exhausting expr+budget through the Python
// wasmtime host AND invokes THIS harness over the SAME pinned .wasm, then asserts
// the two RAW serialized envelopes are BYTE-IDENTICAL (same key order, same code
// RELAY-CEL-003, same subtype RELAY-CEL-TIMEOUT-001, same message bytes).
//
// Why this is distinct from wsj_edge_fuel_timeout.test.mjs (VAL-CWC-P7EDGE-006):
// that sibling exercises the .mjs LOADER's optional `fuelBudget` opt surface (the
// loader threads it through). THIS harness instead drives the wasm eval request
// JSON DIRECTLY -- it marshals memory in/out through the wasm's own
// alloc/eval/dealloc exports with the `fuel_budget` field set on the request --
// bypassing the loader's optional-param surface entirely. That keeps THIS gate
// independent of the in-flight loader fuel wiring (a concurrent work-stream): the
// cross-host envelope byte-parity is a property of the WASM + the host
// marshaling, not of the loader's optional-arg ergonomics.
//
// Raw bytes, not a re-encode: the harness captures the EXACT bytes the wasm wrote
// to linear memory (before any JSON.parse) and reports {len, sha256, hex,
// envelope_text}. The Python side captures the SAME raw bytes the SAME way, so
// the comparison is over the wasm-emitted wire bytes -- a divergence in the
// `error` MESSAGE text or the key ORDER (which a code+subtype check would miss)
// is caught.
//
// No-WASI reactor: instantiated with an EMPTY import object {} (the fuel counter
// is in-wasm; no host clock, no host fuel hook), preserving the no-import reactor
// contract both hosts rely on (VAL-CWC-P7EDGE-005).
//
// Invocation (the Python runner sets CEL_WASM to the artifact both hosts load):
//   CEL_WASM=$PWD/.../relay_cel_wasm.wasm node \
//     packages/cel-wasm/conformance/harness/fuel_exhaustion_cross_host.mjs
//
// Output: a single JSON line on stdout:
//   {"len": <int>, "sha256": "<hex>", "hex": "<envelope-bytes-hex>",
//    "envelope_text": "<utf8 decoding of the envelope>"}
// The harness FAILS LOUD (non-zero exit, message on stderr) if the wasm is
// missing -- a silent skip would let a cross-host byte divergence ship undetected
// (keystone invariant #16).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// The FIXED fuel-exhaustion fixture (the cross-host contract is over THIS
// expr+budget). The triple-nested .map comprehension (10*10*10 inner iterations)
// whose evaluated-node count far exceeds a budget of 8 -- the SAME
// PATHOLOGICAL_EXPR/Some(8) the crate native fuel_tests, the Python-host
// test_wsj_fuel_timeout.py, and the pytest runner here use, so every layer
// exhausts on the identical fixture by construction.
// ---------------------------------------------------------------------------
const PATHOLOGICAL_EXPR =
  "[0,1,2,3,4,5,6,7,8,9].map(x, " +
  "[0,1,2,3,4,5,6,7,8,9].map(y, " +
  "[0,1,2,3,4,5,6,7,8,9].map(z, x + y + z)))";
const EXHAUSTING_BUDGET = 8;

// Default wasm resolution mirrors the dual-run cross-host harness: the COMMITTED,
// git-tracked package-data wasm of @epochly/relay-contracts first (always present
// on a clean checkout, byte-identical to the pinned sha), then the crate/target
// build (dev-tree fallback). CEL_WASM overrides both -- the Python runner sets it
// so BOTH hosts load the SAME bytes.
function packageDataWasmPath() {
  return normalize(
    join(
      HERE,
      "..",
      "..",
      "..",
      "contracts-typescript",
      "src",
      "_wasm",
      "relay_cel_wasm.wasm",
    ),
  );
}

function crateTargetWasmPath() {
  return normalize(
    join(
      HERE,
      "..",
      "..",
      "crate",
      "target",
      "wasm32-unknown-unknown",
      "release",
      "relay_cel_wasm.wasm",
    ),
  );
}

function defaultWasmPath() {
  const packaged = packageDataWasmPath();
  return existsSync(packaged) ? packaged : crateTargetWasmPath();
}

function failLoud(message) {
  // Fail-loud (non-zero) rather than skip: a silent skip would let a cross-host
  // byte divergence ship undetected (keystone invariant #16).
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(2);
}

/**
 * Drive the FIXED fuel-exhausting expr+budget DIRECTLY through the wasm exports
 * (alloc/eval/dealloc) with the fuel_budget field set on the request JSON, and
 * return the RAW envelope bytes EXACTLY as the wasm wrote them (before any
 * JSON.parse). The SAME marshaling the .mjs loader performs, minus the loader's
 * optional-param surface (so this gate does not depend on the in-flight loader
 * fuel wiring). Instantiated with an EMPTY import object {} (no-WASI reactor).
 *
 * @param {string} wasmPath
 * @returns {Promise<Uint8Array>}
 */
async function fuelExhaustionEnvelopeBytes(wasmPath) {
  if (!existsSync(wasmPath)) {
    failLoud(
      `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
        "`make -C packages/cel-wasm build` (or set CEL_WASM). The harness must " +
        "not skip: a missing wasm would mask a cross-host byte divergence " +
        "(keystone invariant #16).",
    );
  }
  const bytes = readFileSync(wasmPath);
  // Empty import object: the fuel counter is in-wasm (no host clock / fuel hook),
  // preserving the no-WASI reactor contract (VAL-CWC-P7EDGE-005).
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { memory, alloc, eval: evalFn, dealloc } = instance.exports;

  // The request JSON with fuel_budget set directly. The INPUT field order does
  // not affect the OUTPUT bytes (the wasm re-serializes its own response).
  const req = { expr: PATHOLOGICAL_EXPR, fuel_budget: EXHAUSTING_BUDGET };
  const inp = new TextEncoder().encode(JSON.stringify(req));
  const n = inp.length;

  const ptr = alloc(n);
  new Uint8Array(memory.buffer, ptr, n).set(inp);
  const packed = BigInt.asUintN(64, evalFn(ptr, n));
  const outPtr = Number(packed >> 32n);
  const outLen = Number(packed & 0xffffffffn);
  // Copy the exact out bytes out of linear memory BEFORE freeing (the slice is a
  // copy, so a later dealloc cannot perturb it).
  const out = new Uint8Array(memory.buffer.slice(outPtr, outPtr + outLen));
  dealloc(outPtr, outLen);
  dealloc(ptr, n);
  return out;
}

async function main() {
  const wasmPath = process.env.CEL_WASM ?? defaultWasmPath();
  const out = await fuelExhaustionEnvelopeBytes(wasmPath);
  const buf = Buffer.from(out);
  const envelope = {
    len: buf.length,
    sha256: createHash("sha256").update(buf).digest("hex"),
    hex: buf.toString("hex"),
    envelope_text: buf.toString("utf-8"),
  };
  // Single JSON line on stdout for the Python runner.
  process.stdout.write(JSON.stringify(envelope));
  process.exit(0);
}

// Export the core for any in-process consumer (parity with the sibling drivers).
export { fuelExhaustionEnvelopeBytes, PATHOLOGICAL_EXPR, EXHAUSTING_BUDGET };

// Run as a CLI when invoked directly.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
