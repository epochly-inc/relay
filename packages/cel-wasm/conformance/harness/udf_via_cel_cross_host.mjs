// VAL-CWC-P3CORPUS-006: Node cross-host UDF-via-CEL driver (Py-wasm == Node-wasm).
//
// This driver proves the cross-host byte-parity half of the M3 P3CORPUS
// keystone: the SAME built wasm, loaded by BOTH hosts, produces BYTE-IDENTICAL
// typed-canonical JCS output for every UDF-via-CEL corpus case. The Python half
// (the per-case byte-match runner, VAL-CWC-P3CORPUS-005,
// tests/conformance/cel/test_udf_via_cel_byte_match_runner.py) records the
// golden `py_jcs_b64` as base64(jcs_canonicalize(wasm_response.value)) where
// `wasm_response.value` is the typed-canonical {t,v} the wasm emits for
// `eval(input_expression, py_to_typed(bindings), relay_profile=True)`.
//
// THIS driver re-derives, on the NODE host, the SAME byte form:
//   1. load the SAME wasm via the `.mjs` RelayCel loader (CEL_WASM env);
//   2. for every corpus case, encode the plain-JSON `bindings` to the
//      typed-canonical wire form via `nativeToTyped` (the TS mirror of the
//      Python `py_to_typed` -- same int/double/bool classification + key sort);
//   3. evaluate `input_expression` with `{relayProfile:true}` (the same fence
//      the Python loader sets);
//   4. take the wasm response `value` (the typed-canonical {t,v}) DIRECTLY --
//      NOT round-tripped through `typedToNative` (the golden is the JCS of the
//      typed-canonical form, the wire bytes, not of the host-native value);
//   5. `jcsCanonicalize(value)` (the SAME RFC 8785 encoder the Python golden
//      used) and compare its bytes (as lowercase hex AND base64) to the stored
//      `py_jcs_b64`.
//
// Because both hosts load the SAME wasm, the wasm OUTPUT bytes are identical by
// construction -- but this driver does NOT assume that: it COMPUTES the Node
// bytes and COMPARES them per case. On ANY single-case hex divergence the driver
// prints `FAIL: <case label> Py=<hex> Node=<hex>` and exits NON-ZERO (a real
// Py-wasm != Node-wasm divergence is a P0 keystone-#16 violation). On full
// success it prints `PASS: Py-wasm and Node-wasm hex-identical on N/N UDF-via-CEL
// cases`.
//
// Invocation (the evidence command):
//   CEL_WASM=$PWD/.../relay_cel_wasm.wasm node \
//     packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs
//
// Non-vacuity self-test (proves the assertion is real; corpus on disk is NEVER
// mutated -- the mutation is a single forced wrong Node output IN MEMORY):
//   node .../udf_via_cel_cross_host.mjs --self-test-mutation
// which forces ONE case's Node bytes to differ by one appended byte and asserts
// the driver reports FAIL on exactly that label with a non-zero exit.
//
// The TS typed-canonical primitives (`nativeToTyped`, `jcsCanonicalize`) are
// imported from the BUILT `@epochly/relay-contracts` dist (the same primitives
// the cross-host P1HOST-019 golden parity uses), so the Node golden matches the
// Python golden BY CONSTRUCTION. Build the dist first via
// `npm run build --workspace=packages/contracts-typescript`. The driver fails
// loud (non-zero) if the dist or the wasm is absent -- a silent skip would mask
// a byte divergence (keystone invariant #16).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Repo root: this driver lives at
// relay/packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs
// -> four levels up is the repo root (.../relay).
const REPO_ROOT = resolve(HERE, "..", "..", "..", "..");

const CORPUS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "cel",
  "relay_udf_via_cel_corpus.json",
);

// The built @epochly/relay-contracts dist: the SINGLE source of the
// typed-canonical codec (`nativeToTyped`) and the RFC 8785 JCS encoder
// (`jcsCanonicalize`). Importing the built dist (not the .ts source) keeps the
// driver runnable under plain Node without a TS loader and exercises the SAME
// primitives a published consumer would.
const CONTRACTS_DIST = resolve(
  REPO_ROOT,
  "packages",
  "contracts-typescript",
  "dist",
  "index.js",
);

// The sibling `.mjs` wasm loader (RelayCel.load + eval with relayProfile). The
// harness dir is packages/cel-wasm/conformance/harness/, so the loader is at
// packages/cel-wasm/typescript/relay-cel-wasm.mjs.
const LOADER_PATH = resolve(
  HERE,
  "..",
  "..",
  "typescript",
  "relay-cel-wasm.mjs",
);

// The reproducible build.sh wasm artifact. CEL_WASM overrides for CI layouts
// that vendor the wasm elsewhere; both hosts MUST load the SAME bytes.
const DEFAULT_WASM_PATH = resolve(
  HERE,
  "..",
  "..",
  "crate",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "relay_cel_wasm.wasm",
);

function failLoud(message) {
  // Fail-loud (non-zero) rather than skip: a silent skip would let a cross-host
  // byte divergence ship undetected (keystone invariant #16).
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(2);
}

/** Lowercase-hex string of a byte buffer (Uint8Array). */
function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

/**
 * Drive every corpus case through the Node-loaded wasm and compare the
 * Node-produced typed-canonical JCS bytes against the stored Python golden.
 *
 * `mutateLabel` (optional, self-test only) forces the Node bytes of the case
 * with that label to differ from the wasm output by one appended byte, so the
 * non-vacuity probe can prove the driver reports FAIL on exactly that label.
 * The on-disk corpus is NEVER mutated; only the in-memory Node bytes for one
 * case are perturbed AFTER the wasm has produced the genuine output.
 *
 * Returns { total, passed, failures: [{label, pyHex, nodeHex}] }.
 */
async function runDriver({ wasmPath, mutateLabel = null } = {}) {
  if (!existsSync(CONTRACTS_DIST)) {
    failLoud(
      `built @epochly/relay-contracts dist not found at ${CONTRACTS_DIST}. ` +
        "Build it via `npm run build --workspace=packages/contracts-typescript`. " +
        "The driver needs nativeToTyped + jcsCanonicalize (the typed-canonical " +
        "codec + RFC 8785 encoder) to reproduce the Python golden bytes.",
    );
  }
  if (!existsSync(CORPUS_PATH)) {
    failLoud(
      `UDF-via-CEL corpus not found at ${CORPUS_PATH}. Regenerate via ` +
        "`uv run python scripts/generate-relay-udf-via-cel-corpus.py`.",
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

  const failures = [];
  let passed = 0;

  for (const c of cases) {
    const label = c.label;
    const pyB64 = c.py_jcs_b64;
    const pyHex = toHex(Buffer.from(pyB64, "base64"));

    // Encode the plain-JSON bindings to the typed-canonical wire form (the TS
    // mirror of py_to_typed). An empty bindings map is sent as `undefined` --
    // byte-identical to the Python loader, which passes `typed_bindings or None`.
    const typedBindings = {};
    for (const [k, v] of Object.entries(c.bindings ?? {})) {
      typedBindings[k] = nativeToTyped(v);
    }
    const bindingsArg =
      Object.keys(typedBindings).length > 0 ? typedBindings : undefined;

    const response = await cel.eval(c.input_expression, bindingsArg, {
      relayProfile: true,
    });

    if (!response || response.ok !== true) {
      // A non-ok envelope is itself a cross-host finding: the Python golden was
      // recorded from an ok envelope, so a Node non-ok is a divergence.
      failures.push({
        label,
        pyHex,
        nodeHex: `<wasm non-ok: ${JSON.stringify(response)}>`,
      });
      continue;
    }

    // Take the typed-canonical {t,v} DIRECTLY (the wire form the Python golden
    // JCS-encodes). Do NOT round-trip through typedToNative.
    let nodeBytes = jcsCanonicalize(response.value);

    // Self-test ONLY: perturb the in-memory Node bytes for exactly one case so
    // the non-vacuity probe can prove the per-case assertion is real. The wasm
    // output above is the GENUINE value; the corpus on disk is untouched.
    if (mutateLabel !== null && label === mutateLabel) {
      nodeBytes = Buffer.concat([Buffer.from(nodeBytes), Buffer.from([0x21])]);
    }

    const nodeHex = toHex(nodeBytes);
    if (nodeHex === pyHex) {
      passed += 1;
    } else {
      failures.push({ label, pyHex, nodeHex });
    }
  }

  return { total: cases.length, passed, failures };
}

async function main() {
  const args = process.argv.slice(2);
  const selfTestMutation = args.includes("--self-test-mutation");
  const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;

  if (selfTestMutation) {
    // Non-vacuity probe: force ONE case's Node bytes to differ and assert the
    // driver reports FAIL on exactly that label with a non-zero outcome. We
    // pick the first case's label as the victim. The corpus file is NEVER
    // mutated -- only the in-memory Node bytes for that one case are perturbed.
    const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf-8"));
    const victim = corpus.cases[0].label;
    const { failures } = await runDriver({ wasmPath, mutateLabel: victim });

    const offending = failures.map((f) => f.label);
    const onlyVictimFailed =
      failures.length === 1 && failures[0].label === victim;
    if (!onlyVictimFailed) {
      process.stdout.write(
        `FAIL: self-test-mutation expected exactly ${JSON.stringify(victim)} ` +
          `to diverge, got failures=${JSON.stringify(offending)}\n`,
      );
      process.exit(1);
    }
    process.stdout.write(
      `FAIL: ${failures[0].label} Py=${failures[0].pyHex} ` +
        `Node=${failures[0].nodeHex}\n`,
    );
    process.stdout.write(
      "PASS: self-test-mutation correctly reported FAIL on the mutated case " +
        `${JSON.stringify(victim)} and on NO other case (non-vacuity proven)\n`,
    );
    process.exit(1);
  }

  const { total, passed, failures } = await runDriver({ wasmPath });

  if (failures.length > 0) {
    for (const f of failures) {
      process.stdout.write(`FAIL: ${f.label} Py=${f.pyHex} Node=${f.nodeHex}\n`);
    }
    process.stdout.write(
      `FAIL: Py-wasm and Node-wasm DIVERGED on ${failures.length}/${total} ` +
        "UDF-via-CEL cases (P0 keystone-#16 violation)\n",
    );
    process.exit(1);
  }

  process.stdout.write(
    `PASS: Py-wasm and Node-wasm hex-identical on ${passed}/${total} ` +
      "UDF-via-CEL cases\n",
  );
  process.exit(0);
}

// Export the core for the vitest wrapper (the equivalent suite) so the suite
// asserts the same per-case hex parity without re-implementing the loop.
export { runDriver, CORPUS_PATH, DEFAULT_WASM_PATH };

// Run as a CLI when invoked directly.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
