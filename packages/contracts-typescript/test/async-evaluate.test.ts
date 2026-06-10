// VAL-CWC-P2TSGATE-006: the WasmCelBackend evaluate() is async (returns a
// Promise) and resolves to the host-checked result; the host guards
// (checkRegexBackref before the wasm call, checkFinite on the converted result)
// remain HOST-SIDE.
//
// The breaking change blast radius is test-files-only: there are zero
// production (src/, non-test) call sites that consume a synchronous evaluate()
// result. The grep evidence for that claim is enforced separately
// (VAL-CWC-P2TSGATE-006 grep); this suite proves the async contract on the
// backend itself.
//
// The wasm is loaded from the reproducible build.sh artifact (or CEL_WASM).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { MAX_TIMEOUT_MS } from "../src/evaluator.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

const HERE = dirname(fileURLToPath(import.meta.url));
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
const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;

describe("VAL-CWC-P2TSGATE-006: WasmCelBackend evaluate() is async", () => {
  let backend: WasmCelBackend;

  beforeAll(() => {
    // Fail-loud if the wasm is missing: a silent skip would hide whether the
    // async path works at all. Build via `make -C packages/cel-wasm build`.
    if (!existsSync(wasmPath)) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip.",
      );
    }
    // timeoutMs is MAX_TIMEOUT_MS (the 250ms Relay cap), NOT the 50ms default:
    // this suite asserts RESULTS (not timeout behavior), and the budget covers
    // Worker COLD START (spawn + .mjs import + wasm compile) on the first
    // evaluate(). Under concurrent full-suite load a 50ms budget spuriously
    // times out trivial evals -- the SAME jitter class the Python side swept in
    // commit 7a2bc04. Root cause is resolved by M7 P7EDGE deterministic fuel
    // metering; this is the interim tier-1 robustness measure.
    backend = new WasmCelBackend({ wasmPath, timeoutMs: MAX_TIMEOUT_MS });
  });

  afterAll(async () => {
    await backend.dispose();
  });

  test("evaluate(...) returns a Promise (thenable)", () => {
    const p = backend.evaluate("1 + 2");
    expect(p).toBeInstanceOf(Promise);
    // Settle it so the test does not leak an unhandled rejection.
    return p.then((v) => {
      expect(v).toBe(3);
    });
  });

  test("await evaluate('1+2') resolves to 3", async () => {
    const v = await backend.evaluate("1+2");
    expect(v).toBe(3);
  });

  test("await evaluate resolves a string result", async () => {
    const v = await backend.evaluate('"a" + "b"');
    expect(v).toBe("ab");
  });

  test("host checkFinite guard stays host-side: an OOB integer rejects with RELAY-CEL-006", async () => {
    // 2**53 is outside the safe integer range; the host-side finiteness/safe-
    // range guard (checkFinite) runs on the converted result, not delegated to
    // the wasm, and rejects with RELAY-CEL-006.
    await expect(
      backend.evaluate("9007199254740992 + 1"),
    ).rejects.toMatchObject({ code: "RELAY-CEL-006" });
  });

  test("host regex-backref guard stays host-side: a backref rejects with RELAY-CEL-007 before the wasm call", async () => {
    await expect(
      backend.evaluate('"x".matches("(a)\\\\1")'),
    ).rejects.toMatchObject({ code: "RELAY-CEL-007" });
  });
});
