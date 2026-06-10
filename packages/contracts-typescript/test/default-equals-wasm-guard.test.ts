// VAL-CWC-P5FLIP-012 cross-host guard (TS half): default equals wasm.
//
// This is the ADR-acceptance-gate-named guard ('a test asserts default ==
// wasm'): it encodes the M5 FLIP ITSELF as a guarded invariant, so a future
// accidental revert of the TS factory default back to cel-js is caught by
// name. The Python half of the cross-host pair lives in
// packages/contracts/tests/test_p5flip_default_equals_wasm_guard.py (pytest
// -k default_equals_wasm_guard); this file is the vitest
// -t "default equals wasm" half. Both selectors are the contract.md Evidence
// commands for VAL-CWC-P5FLIP-012.
//
// Relationship to the existing post-flip default suite (this guard is
// ADDITIVE, not a duplicate): default-engine.test.ts (VAL-CWC-P5FLIP-011)
// already pins the wasm default behaviorally. THIS file is the
// explicitly-named acceptance-gate guard with its own REAL assertions
// (instanceof WasmCelBackend on the unset default) plus an in-suite
// NON-VACUITY case proving the instanceof discriminator actually
// discriminates (an explicit "celjs" selection produces a
// non-WasmCelBackend instance) -- so the guard can never rot into a
// tautology that any returned object would satisfy.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import { RelayCelEvaluator } from "../src/evaluator.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

describe("VAL-CWC-P5FLIP-012: cross-host guard (TS half)", () => {
  test("default equals wasm: makeCelEvaluator() with no engine selection constructs WasmCelBackend (M5 flip invariant)", async () => {
    // THE GUARD (ADR acceptance gate 'a test asserts default == wasm'): a
    // bare factory call -- no engine argument, no config -- MUST construct
    // the wasm backend. If a future change reverts the default (engine.ts
    // DEFAULT_ENGINE) back to cel-js, every assertion here fails loudly by
    // name (-t "default equals wasm").
    const ev = makeCelEvaluator();
    try {
      expect(ev).toBeInstanceOf(WasmCelBackend);
      expect(ev.constructor).toBe(WasmCelBackend);
      expect(ev).not.toBeInstanceOf(RelayCelEvaluator);
    } finally {
      await ev.dispose();
    }
  });

  test("default equals wasm guard is non-vacuous: explicit 'celjs' selection produces a non-WasmCelBackend instance", () => {
    // NON-VACUITY: prove the guard's instanceof discriminator actually
    // discriminates between the two engines. The SAME factory, asked
    // explicitly for the legacy engine, returns an instance that FAILS the
    // guard's WasmCelBackend check (and is the legacy RelayCelEvaluator).
    // Therefore the guard above cannot pass vacuously -- under a real revert
    // of the default to cel-js, its toBeInstanceOf(WasmCelBackend)
    // assertion fails, exactly as it does for this explicit selection.
    const legacy = makeCelEvaluator({ engine: "celjs" });
    try {
      expect(legacy).not.toBeInstanceOf(WasmCelBackend);
      expect(legacy).toBeInstanceOf(RelayCelEvaluator);
      expect(legacy.constructor).not.toBe(WasmCelBackend);
    } finally {
      legacy.dispose();
    }
  });
});
