// roborev finding 3: wasm-evaluator.ts `canonicalDouble` MUST match the
// Rust/Python canonical double format (`_format_double_g` / `_canonical_double`)
// for the cel-go strconv.FormatFloat(f, 'g', -1, 64) thresholds/padding -- not
// `String(n)`, which diverges at the %e/%f boundary (1e-7, 1000000.5, big
// exponents, inf/-inf/nan).
//
// Byte-parity keystone #16: the canonical double bytes feed udf_outputs_jcs /
// the typed-canonical {"t":"double","v":...} wire form, so a single-byte
// divergence between this TS encoder and the Python `_canonical_double` is a P0.
// The Python `_canonical_double` is the parity REFERENCE (it is byte-faithful to
// the Rust lib.rs format_double_g).
//
// Tool: vitest. Evidence: vitest exit code + the asserted decimal strings, cross
// checked against the Python `_canonical_double` golden generated below.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { canonicalDoubleString } from "../src/wasm-evaluator.js";

// The set of doubles that exercise every branch of format_double_g:
//   - the %e/%f selection boundary at exp10 < -4 and exp10 >= 6
//   - exponent two-digit zero padding (e+06, e-07)
//   - whole-valued doubles in %f range (1000000.5 is %f; 1e7 is %e)
//   - the inf/-inf/nan sentinels
//   - +0 / -0 -> "0.0" / "-0.0"
const FINITE_CASES: number[] = [
  1e-7, // exp10 = -7 -> %e -> "1e-07"
  1e-5, // exp10 = -5 -> %e -> "1e-05"
  1e-4, // exp10 = -4 -> %f -> "0.0001"
  0.0001,
  1.5,
  100.0, // whole double in %f range (defensive; integral binding never hits)
  1000000.5, // exp10 = 6 -> %e? leading digit exp is 6 -> %e -> "1.0000005e+06"
  1e6, // exp10 = 6 -> %e -> "1e+06"
  1e5, // exp10 = 5 -> %f -> "100000.0"
  1e7, // exp10 = 7 -> %e -> "1e+07"
  1e21, // huge -> %e
  1e-21, // tiny -> %e
  123456.789,
  0.1,
  3.141592653589793,
  2.5e-10,
  9.999999e22,
];

// Compute the Python `_canonical_double` golden for the SAME doubles, so the
// assertion is a genuine cross-host byte comparison (not a re-derivation of the
// TS logic). The Python module is the parity reference.
function pythonCanonicalDoubles(values: number[]): string[] {
  // Emit each double with repr() so Python parses the identical IEEE-754 value
  // (repr round-trips). Special sentinels are passed by name.
  const reprs = values.map((v) => {
    if (Number.isNaN(v)) {
      return "float('nan')";
    }
    if (v === Number.POSITIVE_INFINITY) {
      return "float('inf')";
    }
    if (v === Number.NEGATIVE_INFINITY) {
      return "float('-inf')";
    }
    // A JS number's full-precision decimal: toExponential(20) then float() in
    // Python yields the identical IEEE-754 double (over-precise input rounds to
    // the same nearest double). Object.is(-0) handled by the script.
    if (Object.is(v, -0)) {
      return "-0.0";
    }
    return `float('${v.toExponential(20)}')`;
  });
  // Load wasm_codec.py BY FILE LOCATION (not `from relay_contracts...`) so the
  // package __init__ -- which imports relay_schemas -- is bypassed: wasm_codec.py
  // itself only needs celpy + stdlib. This keeps the parity golden independent of
  // the full relay_contracts package install while still exercising the EXACT
  // reference implementation (_canonical_double).
  const root = repoRoot();
  const codecPath = resolve(
    root,
    "packages",
    "contracts",
    "src",
    "relay_contracts",
    "wasm_codec.py",
  );
  const script = [
    "import sys, json, importlib.util",
    `spec = importlib.util.spec_from_file_location('wcodec', ${JSON.stringify(codecPath)})`,
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    `vals = [${reprs.join(", ")}]`,
    "print(json.dumps([m._canonical_double(v) for v in vals]))",
  ].join("\n");
  const out = execFileSync(pythonExecutable(root), ["-c", script], {
    cwd: root,
    encoding: "utf-8",
  });
  return JSON.parse(out) as string[];
}

// The relay/ package root (where .venv lives). test/ is
// packages/contracts-typescript/test/ -> the relay root is three directories up.
function repoRoot(): string {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return resolve(here, "..", "..", "..");
}

// Prefer the repo venv python (which has celpy installed); fall back to the
// ambient python3. The codec needs celpy, so the venv is required for this
// golden -- fail loud if neither resolves rather than skip (a silent skip would
// hide a byte-parity divergence; keystone invariant #16).
function pythonExecutable(root: string): string {
  const venvPy = resolve(root, ".venv", "bin", "python3");
  if (existsSync(venvPy)) {
    return venvPy;
  }
  return "python3";
}

describe("roborev finding 3: canonicalDouble matches Python _canonical_double", () => {
  test("finite doubles byte-match the Python _canonical_double golden", () => {
    const golden = pythonCanonicalDoubles(FINITE_CASES);
    expect(golden.length).toBe(FINITE_CASES.length);
    FINITE_CASES.forEach((v, i) => {
      expect(canonicalDoubleString(v), `value=${v}`).toBe(golden[i]);
    });
  });

  // Explicit boundary expectations (also pinned literally so a regression is
  // legible without re-running Python): cel-go 'g'-verb thresholds.
  test("1e-7 -> '1e-07' (%e, two-digit exponent)", () => {
    expect(canonicalDoubleString(1e-7)).toBe("1e-07");
  });
  test("1e6 -> '1e+06' (%e at exp10 == 6)", () => {
    expect(canonicalDoubleString(1e6)).toBe("1e+06");
  });
  test("1e5 -> '100000.0' (%f at exp10 == 5, decimal point forced)", () => {
    expect(canonicalDoubleString(1e5)).toBe("100000.0");
  });
  test("1000000.5 -> '1.0000005e+06' (%e at exp10 == 6)", () => {
    expect(canonicalDoubleString(1000000.5)).toBe("1.0000005e+06");
  });
  test("0.0001 -> '0.0001' (%f at exp10 == -4)", () => {
    expect(canonicalDoubleString(0.0001)).toBe("0.0001");
  });
  test("+0 -> '0.0', -0 -> '-0.0'", () => {
    expect(canonicalDoubleString(0)).toBe("0.0");
    expect(canonicalDoubleString(-0)).toBe("-0.0");
  });

  // inf / -inf / nan sentinels (the _canonical_double non-finite branch).
  test("inf/-inf/nan map to the canonical sentinels", () => {
    expect(canonicalDoubleString(Number.POSITIVE_INFINITY)).toBe("inf");
    expect(canonicalDoubleString(Number.NEGATIVE_INFINITY)).toBe("-inf");
    expect(canonicalDoubleString(Number.NaN)).toBe("nan");
  });
});
