// VAL-CWC-P3CORPUS-006: Node cross-host UDF-via-CEL parity (Py-wasm == Node-wasm).
//
// This is the vitest "equivalent suite" for the standalone `.mjs` driver
// packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs. It imports
// the driver's CORE (`runDriver`) -- it does NOT re-implement the per-case loop
// -- and asserts:
//   1. PASS path: every UDF-via-CEL corpus case is hex-identical between the
//      Python loader's golden (`py_jcs_b64`) and the Node-loaded wasm output
//      (15/15, zero failures) -- the cross-host byte-parity keystone (#16).
//   2. Non-vacuity: forcing ONE case's Node bytes to differ by a single byte
//      (the driver's in-memory `mutateLabel` hook; the corpus on disk is NEVER
//      mutated) makes EXACTLY that case fail with a divergent hex pair -- so the
//      per-case assertion is real, not trivially satisfied.
//
// Both hosts load the SAME built wasm, so the wasm OUTPUT bytes are identical by
// construction; this suite COMPUTES and COMPARES them per case rather than
// assuming. A real Py-wasm != Node-wasm divergence is a P0 keystone-#16
// violation. The wasm artifact is the reproducible build.sh output (or CEL_WASM);
// if it is absent the suite fails LOUDLY rather than skipping -- a silent skip
// would mask a byte divergence.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));

// The standalone driver lives at
// packages/cel-wasm/conformance/harness/udf_via_cel_cross_host.mjs. The test
// dir is packages/contracts-typescript/test/, so the harness is two levels up
// then into cel-wasm/conformance/harness.
const DRIVER_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "conformance",
  "harness",
  "udf_via_cel_cross_host.mjs",
);

// The reproducible build.sh wasm artifact. CEL_WASM overrides for CI layouts
// that vendor the wasm elsewhere; both hosts MUST load the SAME bytes.
const DEFAULT_WASM_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "crate",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "relay_cel_wasm.wasm",
);

interface DriverFailure {
  label: string;
  pyHex: string;
  nodeHex: string;
}

interface DriverResult {
  total: number;
  passed: number;
  failures: DriverFailure[];
}

interface DriverModule {
  runDriver(options: {
    wasmPath: string;
    mutateLabel?: string | null;
  }): Promise<DriverResult>;
}

const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;
const wasmPresent = existsSync(wasmPath);

let driver: DriverModule;

describe("VAL-CWC-P3CORPUS-006: Node cross-host UDF-via-CEL Py-wasm == Node-wasm hex parity", () => {
  beforeAll(async () => {
    // Fail-loud if the wasm is missing: a silent skip would hide a cross-host
    // byte divergence (keystone invariant #16). Build it via
    // `make -C packages/cel-wasm build` (or set CEL_WASM).
    if (!wasmPresent) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip: a missing wasm would mask a cross-host byte " +
          "divergence (keystone invariant #16).",
      );
    }
    driver = (await import(
      pathToFileURL(DRIVER_PATH).href
    )) as unknown as DriverModule;
  });

  test("every corpus case is hex-identical between the Python golden and the Node-loaded wasm", async () => {
    const { total, passed, failures } = await driver.runDriver({ wasmPath });

    // Diagnostic on any divergence: surface every offending label + both hex
    // strings before the assertion (a real divergence is a P0).
    if (failures.length > 0) {
      for (const f of failures) {
        // eslint-disable-next-line no-console
        console.error(`FAIL: ${f.label} Py=${f.pyHex} Node=${f.nodeHex}`);
      }
    }

    expect(failures).toEqual([]);
    expect(passed).toBe(total);
    // The corpus exercises all three Relay UDFs across 15 cases; assert the
    // full-corpus count so a truncated corpus cannot vacuously pass.
    expect(total).toBe(15);
  });

  test("non-vacuity: a single forced 1-byte Node divergence makes EXACTLY that case FAIL", async () => {
    // Use the driver's in-memory mutate hook (the corpus on disk is NEVER
    // touched). The victim is the first case's label.
    const baseline = await driver.runDriver({ wasmPath });
    expect(baseline.failures).toEqual([]);

    // Find the first case label by running once mutated; the driver perturbs the
    // case whose label matches `mutateLabel`. We do not need to read the corpus
    // here -- we mutate by label, so derive a known label deterministically: the
    // first corpus case label is covcel_first_match_binding (the relay.coverage
    // first-match binding case). If the corpus order changes this assertion
    // would surface it, which is the intended sensitivity.
    const victim = "covcel_first_match_binding";
    const mutated = await driver.runDriver({ wasmPath, mutateLabel: victim });

    // EXACTLY the victim diverges; every other case still matches.
    expect(mutated.failures.length).toBe(1);
    expect(mutated.failures[0]?.label).toBe(victim);
    // The hex pair is genuinely different (the mutation appended one byte).
    expect(mutated.failures[0]?.nodeHex).not.toBe(mutated.failures[0]?.pyHex);
    expect(mutated.failures[0]?.nodeHex.startsWith(mutated.failures[0]!.pyHex)).toBe(
      true,
    );
    // And no other case was affected (passed == total - 1).
    expect(mutated.passed).toBe(mutated.total - 1);
  });
});
