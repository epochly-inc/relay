// VAL-CWC-P4DUALRUN-005: Node cross-host driver over the FULL Relay-CEL corpus.
//
// This is the NODE half of the dual-run CROSS-HOST parity gate
// (Py-wasm == Node-wasm) over the FULL main Relay-CEL corpus
// (tests/conformance/cel/relay_cel_corpus.json, 224 cases). The Python half is
// the pytest runner tests/conformance/cel/test_dual_run_cross_host_wasm_parity.py:
// it invokes THIS harness once over the full corpus, captures the per-case JSON
// emitted here on stdout, computes the SAME per-case typed-canonical result via
// the PYTHON wasm host, and asserts byte-identical (sha256/hex) parity per case.
//
// Why this is distinct from udf_via_cel_cross_host.mjs (VAL-CWC-P3CORPUS-006):
// that sibling drives the small UDF-via-CEL corpus (relay_udf_via_cel_corpus.json,
// 15 cases) and compares the Node bytes against a STORED Python golden
// (py_jcs_b64). THIS driver instead drives the FULL relay_cel_corpus.json and
// emits a machine-readable per-case digest map for the Python runner to compare
// LIVE against the Python wasm host (no stored golden; both sides recompute).
//
// What a corpus case looks like / which cases this harness covers:
//   - eval_value / eval_error cases carry a CEL `expression` string (+ optional
//     plain-JSON `bindings`). These ARE driven THROUGH the wasm `.eval(...)` and
//     are the COVERED set.
//   - udf_value cases carry NO `expression` -- they are direct Python-callable
//     UDF invocations (`udf` + `args`) with no CEL surface. Neither host's wasm
//     `.eval(expression, ...)` can drive them (there is no expression to compile),
//     so they are EXCLUDED here and on the Python side IDENTICALLY. The Python
//     runner asserts the excluded id set equals exactly the udf_value-kind ids,
//     so nothing is silently dropped.
//
// Per-case output (one entry per COVERED case in the emitted JSON `results`):
//   - wasm `ok:true`  -> { "hex": sha256hex(jcsCanonicalize(response.value)) }
//        where `response.value` is the typed-canonical {t,v} the wasm emits and
//        jcsCanonicalize is the RFC 8785 encoder from the built
//        @epochly/relay-contracts dist (the SAME encoder the Python host uses,
//        so the bytes are comparable BY CONSTRUCTION).
//   - wasm `ok:false` -> { "error_code": response.code, "error_subtype":
//        response.subtype ?? null }  (the structured engine-error classification;
//        both hosts load the SAME wasm, so the wasm-produced code/subtype are
//        identical across hosts -- a difference would be a host-marshalling bug,
//        exactly what this gate catches).
//
// Bindings encoding: the plain-JSON `bindings` are encoded to the typed-canonical
// wire form via `nativeToTyped` (the TS mirror of the Python `py_to_typed` --
// same int/uint/double/bool classification + map-key handling). An empty bindings
// map is sent as `undefined`, byte-identical to the Python loader's
// `typed_bindings or None`. `{relayProfile:true}` matches the Python host's
// `relay_profile=True` so both hosts hit the wasm with the identical request.
//
// The emitted JSON envelope on stdout:
//   {
//     "corpus_total": <number of cases in relay_cel_corpus.json>,
//     "covered_ids":  [<id>, ...],   // cases with a CEL expression (driven)
//     "excluded_ids": [<id>, ...],   // cases WITHOUT a CEL expression (udf_value)
//     "results": { "<id>": { "hex": ... } | { "error_code": ..., "error_subtype": ... }, ... }
//   }
// The harness FAILS LOUD (non-zero exit, message on stderr) if the dist, the
// corpus, the loader, or the wasm is missing -- a silent skip would let a
// cross-host byte divergence ship undetected (keystone invariant #16). On the
// normal path it emits the JSON envelope to stdout and exits 0; any wasm trap on
// a covered case is surfaced as an ENGINE_PANIC error envelope (code
// RELAY-CEL-PANIC) so it is COMPARED, not hidden.
//
// Invocation (the Python runner sets CEL_WASM to the built artifact):
//   CEL_WASM=$PWD/.../relay_cel_wasm.wasm node \
//     packages/cel-wasm/conformance/harness/cel_corpus_cross_host.mjs
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Repo root: this driver lives at
// relay/packages/cel-wasm/conformance/harness/cel_corpus_cross_host.mjs
// -> four levels up is the repo root (.../relay).
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..");

// The FULL main Relay-CEL corpus (the 224-case corpus -- NOT the small
// UDF-via-CEL corpus the sibling driver uses).
const CORPUS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "cel",
  "relay_cel_corpus.json",
);

// The built @epochly/relay-contracts dist: the SINGLE source of the
// typed-canonical codec (`nativeToTyped`) and the RFC 8785 JCS encoder
// (`jcsCanonicalize`). Importing the built dist (not the .ts source) keeps the
// driver runnable under plain Node and exercises the SAME primitives a published
// consumer would -- and the SAME ones the Python host uses, so the bytes match
// by construction.
const CONTRACTS_DIST = resolve(
  REPO_ROOT,
  "packages",
  "contracts-typescript",
  "dist",
  "index.js",
);

// The sibling `.mjs` wasm loader (RelayCel.load + eval with relayProfile).
const LOADER_PATH = resolve(
  HERE,
  "..",
  "..",
  "typescript",
  "relay-cel-wasm.mjs",
);

// The COMMITTED, git-tracked package-data wasm vendored as data of
// @epochly/relay-contracts (packages/contracts-typescript/src/_wasm/). This is
// the SAME canonical artifact the .mjs loader's own defaultWasmPath() prefers,
// is ALWAYS present on a clean checkout (no build), and is byte-identical to the
// pinned sha 49a6a6a2... (a Python+TS sha-drift guard enforces that). Mirrors
// the Python runner's package-data resolution so BOTH standalone hosts load the
// same committed bytes with no crate build.
const PACKAGE_DATA_WASM_PATH = resolve(
  REPO_ROOT,
  "packages",
  "contracts-typescript",
  "src",
  "_wasm",
  "relay_cel_wasm.wasm",
);

// The (gitignored) reproducible build.sh crate/target artifact -- a local-dev
// fallback used only when the committed package-data copy is absent.
const CRATE_TARGET_WASM_PATH = resolve(
  HERE,
  "..",
  "..",
  "crate",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "relay_cel_wasm.wasm",
);

// Default wasm resolution when no explicit path and no CEL_WASM env: the
// committed package-data copy first (works on a clean checkout), then the
// crate/target build (dev-tree fallback). CEL_WASM overrides both for CI
// layouts that vendor the wasm elsewhere; both hosts MUST load the SAME bytes.
function defaultWasmPath() {
  return existsSync(PACKAGE_DATA_WASM_PATH)
    ? PACKAGE_DATA_WASM_PATH
    : CRATE_TARGET_WASM_PATH;
}

// Back-compat alias for the previously-exported constant name. Now resolves the
// committed package-data wasm first (was the gitignored crate/target path).
const DEFAULT_WASM_PATH = defaultWasmPath();

function failLoud(message) {
  // Fail-loud (non-zero) rather than skip: a silent skip would let a cross-host
  // byte divergence ship undetected (keystone invariant #16).
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(2);
}

/** Lowercase sha256 hex of a byte buffer (Uint8Array). */
function sha256Hex(bytes) {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

/**
 * Drive every CEL-expression corpus case through the Node-loaded wasm and emit a
 * per-case digest map. udf_value cases (no `expression`) are excluded identically
 * to the Python side.
 *
 * Returns the JSON envelope object { corpus_total, covered_ids, excluded_ids,
 * results }.
 */
async function runDriver({ wasmPath } = {}) {
  if (!existsSync(CONTRACTS_DIST)) {
    failLoud(
      `built @epochly/relay-contracts dist not found at ${CONTRACTS_DIST}. ` +
        "Build it via `npm run build --workspace=packages/contracts-typescript`. " +
        "The driver needs nativeToTyped + jcsCanonicalize (the typed-canonical " +
        "codec + RFC 8785 encoder) to reproduce the Python host bytes.",
    );
  }
  if (!existsSync(CORPUS_PATH)) {
    failLoud(
      `Relay-CEL corpus not found at ${CORPUS_PATH}. ` +
        "It is the main relay_cel_corpus.json conformance corpus.",
    );
  }
  if (!existsSync(wasmPath)) {
    failLoud(
      `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
        "`make -C packages/cel-wasm build` (or set CEL_WASM). The driver must " +
        "not skip: a missing wasm would mask a cross-host byte divergence " +
        "(keystone invariant #16).",
    );
  }

  const { nativeToTyped, jcsCanonicalize } = await import(
    pathToFileURL(CONTRACTS_DIST).href
  );
  const { RelayCel } = await import(pathToFileURL(LOADER_PATH).href);

  const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8"));
  const cases = corpus.cases;
  if (!Array.isArray(cases) || cases.length === 0) {
    failLoud("corpus 'cases' must be a non-empty array");
  }

  const cel = await RelayCel.load(wasmPath);

  const coveredIds = [];
  const excludedIds = [];
  const results = {};

  for (const c of cases) {
    const id = c.id;
    const expr = c.expression;
    // A case is COVERED iff it carries a non-empty CEL expression string. The
    // udf_value cases carry no `expression` (direct Python-callable UDFs), so
    // neither host's wasm `.eval(expr, ...)` can drive them; they are EXCLUDED
    // identically on both hosts (the Python runner asserts the excluded id set
    // equals exactly the udf_value-kind ids, so nothing is silently dropped).
    if (typeof expr !== "string" || expr === "") {
      excludedIds.push(id);
      continue;
    }
    coveredIds.push(id);

    // Encode the plain-JSON bindings to the typed-canonical wire form (the TS
    // mirror of py_to_typed). Empty bindings -> undefined, byte-identical to the
    // Python loader's `typed_bindings or None`.
    const typedBindings = {};
    for (const [k, v] of Object.entries(c.bindings ?? {})) {
      typedBindings[k] = nativeToTyped(v);
    }
    const bindingsArg =
      Object.keys(typedBindings).length > 0 ? typedBindings : undefined;

    const response = await cel.eval(expr, bindingsArg, { relayProfile: true });

    if (response && response.ok === true) {
      // Take the typed-canonical {t,v} DIRECTLY (the wire form), JCS-encode it
      // with the SAME RFC 8785 encoder the Python host uses, and sha256-hex it.
      results[id] = {
        hex: sha256Hex(jcsCanonicalize(response.value)),
      };
    } else {
      // ok:false (or a defensive non-envelope) -> the structured engine-error
      // classification. Both hosts load the SAME wasm, so the wasm-produced
      // code/subtype are identical across hosts; a difference is a
      // host-marshalling bug, which is exactly what this gate catches. An
      // ENGINE_PANIC (RELAY-CEL-PANIC) from a wasm trap is surfaced here too, so
      // it is COMPARED, not hidden.
      results[id] = {
        error_code: response && typeof response.code === "string"
          ? response.code
          : null,
        error_subtype:
          response && typeof response.subtype === "string"
            ? response.subtype
            : null,
      };
    }
  }

  return {
    corpus_total: cases.length,
    covered_ids: coveredIds,
    excluded_ids: excludedIds,
    results,
  };
}

async function main() {
  const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;
  const envelope = await runDriver({ wasmPath });
  // Emit the machine-readable per-case envelope on stdout for the Python runner.
  process.stdout.write(JSON.stringify(envelope));
  process.exit(0);
}

// Export the core for any in-process consumer (parity with the sibling driver).
export { runDriver, CORPUS_PATH, DEFAULT_WASM_PATH };

// Run as a CLI when invoked directly.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
