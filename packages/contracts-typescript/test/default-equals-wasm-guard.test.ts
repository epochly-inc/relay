// VAL-CWC-P5FLIP-012 cross-host guard (TS half): default equals wasm.
//
// This is the ADR-acceptance-gate-named guard ('a test asserts default ==
// wasm'): it encodes the M5 FLIP ITSELF as a guarded invariant, so a future
// accidental revert of the TS factory default is caught by name. The Python
// half of the cross-host pair lives in
// packages/contracts/tests/test_p5flip_default_equals_wasm_guard.py (pytest
// -k default_equals_wasm_guard); this file is the vitest
// -t "default equals wasm" half. Both selectors are the contract.md Evidence
// commands for VAL-CWC-P5FLIP-012.
//
// M6 WS-I transition: the legacy engine no longer exists. The main guard is
// unchanged (the bare factory MUST construct the wasm backend). The non-vacuity
// companion is transitioned to match the Python half: under a simulated revert
// (an explicit unknown / legacy engine token) the factory FAILS CLOSED with the
// structured unknown-engine error instead of constructing a legacy class --
// still a loud, named failure, proving the guard's instanceof discriminator is
// not vacuous (a non-wasm selection does NOT yield a WasmCelBackend; it yields
// an exception).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

describe("VAL-CWC-P5FLIP-012: cross-host guard (TS half)", () => {
  test("default equals wasm: makeCelEvaluator() with no engine selection constructs WasmCelBackend (M5 flip invariant)", async () => {
    // THE GUARD (ADR acceptance gate 'a test asserts default == wasm'): a
    // bare factory call -- no engine argument, no config -- MUST construct
    // the wasm backend. If a future change reverts the default (engine.ts
    // DEFAULT_ENGINE), every assertion here fails loudly by name
    // (-t "default equals wasm").
    const ev = makeCelEvaluator();
    try {
      expect(ev).toBeInstanceOf(WasmCelBackend);
      expect(ev.constructor).toBe(WasmCelBackend);
      expect(ev.constructor.name).toBe("WasmCelBackend");
    } finally {
      await ev.dispose();
    }
  });

  test("default equals wasm guard is non-vacuous: an explicit legacy/unknown engine token FAILS CLOSED (no wasm instance)", () => {
    // NON-VACUITY (M6 WS-I form): the legacy engine is removed, so there is no
    // alternative class to construct. An explicit legacy/unknown selection is
    // an unhandled token and the factory FAILS CLOSED with the structured
    // unknown-engine error -- it does NOT return a WasmCelBackend by accident.
    // This proves the guard above cannot pass vacuously: a non-wasm selection
    // never yields a WasmCelBackend (it yields an exception), exactly as a real
    // revert of the default would fail the toBeInstanceOf(WasmCelBackend) check.
    for (const legacy of ["celjs", "cel-js", "celpy"]) {
      let constructed: unknown = null;
      let threw = false;
      try {
        constructed = makeCelEvaluator({ engine: legacy });
      } catch {
        threw = true;
      }
      expect(threw, `engine ${JSON.stringify(legacy)} must fail closed`).toBe(
        true,
      );
      expect(constructed).not.toBeInstanceOf(WasmCelBackend);
      // The error names the bad value and the wasm-only allowed set.
      expect(() => makeCelEvaluator({ engine: legacy })).toThrow(
        /not a recognized CEL engine/,
      );
      expect(() => makeCelEvaluator({ engine: legacy })).toThrow(/wasm/);
    }
  });
});
