// ROBOREV round-2 finding G (MED): the CEL_WASM env override was bypassed by the
// packaged-loader preference.
//
// In pipeline.ts loadRelayCel() and the WasmCelBackend constructor, when NO
// explicit wasmPath was given AND the packaged loader exists, the host resolved
// the PACKAGE-DATA wasm and passed it into the loader -- so the loader's own
// `wasmPath || process.env.CEL_WASM || defaultWasmPath()` fallback never saw
// CEL_WASM (the package-data path was already truthy). An operator who set
// CEL_WASM to point at a specific artifact was silently ignored, while the docs
// still claimed CEL_WASM is honored.
//
// The fix makes the precedence EXPLICIT and shared:
//   explicit wasmPath  >  process.env.CEL_WASM  >  packaged-data wasm
// The packaged wasm is passed ONLY when neither an explicit path nor CEL_WASM is
// set. This is the path-resolution env var (NOT the RELAY_CEL_ENGINE engine
// selector), so reading it here does not affect engine-selection determinism.
//
// Tool: vitest. Evidence: vitest exit code + the resolved path under each
// precedence combination.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { resolveWasmPathForLoader } from "../src/wasm-artifact.js";

describe("roborev round-2 finding G: CEL_WASM precedence over the packaged-data wasm", () => {
  const SAVED = process.env.CEL_WASM;

  beforeEach(() => {
    delete process.env.CEL_WASM;
  });

  afterEach(() => {
    if (SAVED === undefined) {
      delete process.env.CEL_WASM;
    } else {
      process.env.CEL_WASM = SAVED;
    }
  });

  test("an explicit wasmPath wins over CEL_WASM and over the packaged wasm", () => {
    process.env.CEL_WASM = "/env/cel.wasm";
    const resolved = resolveWasmPathForLoader("/explicit/cel.wasm");
    expect(resolved).toBe("/explicit/cel.wasm");
  });

  test("CEL_WASM is HONORED when set and no explicit wasmPath is given", () => {
    process.env.CEL_WASM = "/env/cel.wasm";
    const resolved = resolveWasmPathForLoader(undefined);
    // The whole point of the finding: CEL_WASM must NOT be shadowed by the
    // packaged-data wasm. The env path is returned.
    expect(resolved).toBe("/env/cel.wasm");
  });

  test("an EMPTY CEL_WASM is treated as unset (falls through to packaged/undefined)", () => {
    process.env.CEL_WASM = "";
    const resolved = resolveWasmPathForLoader(undefined);
    // Empty string is not a usable path; it must NOT be returned. The result is
    // either the packaged wasm (if present in this tree) or undefined (defer to
    // the loader's own default) -- but NEVER the empty string.
    expect(resolved).not.toBe("");
  });

  test("with neither explicit nor CEL_WASM set, the result is the packaged wasm or undefined (never throws)", () => {
    const resolved = resolveWasmPathForLoader(undefined);
    // In the dev tree the packaged wasm exists, so a concrete path is returned;
    // in a checkout without package data it is undefined (defer to the loader).
    expect(resolved === undefined || typeof resolved === "string").toBe(true);
    if (typeof resolved === "string") {
      expect(resolved.length).toBeGreaterThan(0);
    }
  });
});
