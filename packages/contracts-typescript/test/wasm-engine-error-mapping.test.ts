// VAL-CWC-P2TSGATE-002: the TS WasmCelBackend maps a wasm {ok:false} response
// envelope's error tags {compile, exec, request, PANIC / RELAY-CEL-PANIC} to
// RelayCelEngineError (code RELAY-CEL-009) with the matching engine subtype,
// and NEVER surfaces a wasm EXEC (the wasm's own 004) or REQUEST (the wasm's
// own 006) failure as the host RELAY-CEL-004 (UDF-IMPURE) / RELAY-CEL-006
// (NUMERIC-OOB) classification.
//
// This is the TS mirror of the Python WasmCelEvaluator._decode_envelope ->
// RelayCelEngineError.from_wasm_envelope mapping
// (packages/contracts/src/relay_contracts/wasm_backed_evaluator.py:433-475 and
// errors.py:193-225) and the Revisions s1 guard: a wasm engine failure must be
// distinguishable from a host classification so it never poisons the gate's
// signed per-condition error_code.
//
// The mapping is exercised directly via the backend's envelope-decoder so the
// test feeds each wasm tag deterministically (no reliance on coaxing the wasm
// into each failure mode). The wasm's OWN code namespace is:
//   RELAY-CEL-001 = compile  -> RELAY-CEL-ENGINE-COMPILE
//   RELAY-CEL-004 = exec     -> RELAY-CEL-ENGINE-EXEC
//   RELAY-CEL-006 = request  -> RELAY-CEL-ENGINE-REQUEST
//   RELAY-CEL-PANIC          -> RELAY-CEL-ENGINE-PANIC
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { describe, expect, test } from "vitest";

import {
  CODE_RELAY_CEL_004,
  CODE_RELAY_CEL_006,
  CODE_RELAY_CEL_009,
  RelayCelEngineError,
  RelayCelError,
  SUBTYPE_ENGINE_COMPILE,
  SUBTYPE_ENGINE_EXEC,
  SUBTYPE_ENGINE_PANIC,
  SUBTYPE_ENGINE_REQUEST,
} from "../src/errors.js";
import { decodeWasmEnvelope } from "../src/wasm-evaluator.js";

// Each row: a wasm {ok:false} envelope tag, the cause label, and the engine
// subtype the host MUST surface. The "exec"/"request" rows carry the wasm's OWN
// 004/006 codes -- the collision guard asserts they never surface as host
// 004/006.
const CASES: ReadonlyArray<{
  label: string;
  wasmCode: string;
  expectedSubtype: string;
  collisionGuard: boolean;
}> = [
  {
    label: "compile",
    wasmCode: "RELAY-CEL-001",
    expectedSubtype: SUBTYPE_ENGINE_COMPILE,
    collisionGuard: false,
  },
  {
    label: "exec",
    wasmCode: "RELAY-CEL-004",
    expectedSubtype: SUBTYPE_ENGINE_EXEC,
    collisionGuard: true,
  },
  {
    label: "request",
    wasmCode: "RELAY-CEL-006",
    expectedSubtype: SUBTYPE_ENGINE_REQUEST,
    collisionGuard: true,
  },
  {
    label: "PANIC",
    wasmCode: "RELAY-CEL-PANIC",
    expectedSubtype: SUBTYPE_ENGINE_PANIC,
    collisionGuard: false,
  },
];

describe("VAL-CWC-P2TSGATE-002: wasm envelope -> RelayCelEngineError (no 004/006 collision)", () => {
  for (const c of CASES) {
    test(`wasm ${c.label} (${c.wasmCode}) -> RELAY-CEL-009 / ${c.expectedSubtype}`, () => {
      const envelope = {
        ok: false,
        code: c.wasmCode,
        error: `wasm ${c.label} failure`,
      };
      let thrown: unknown;
      try {
        decodeWasmEnvelope(envelope);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(RelayCelEngineError);
      expect(thrown).toBeInstanceOf(RelayCelError);
      const err = thrown as RelayCelEngineError;
      expect(err.code).toBe(CODE_RELAY_CEL_009);
      expect(err.subtype).toBe(c.expectedSubtype);
      // The wasm engine failure NEVER surfaces as a host classification.
      expect(err.code).not.toBe(CODE_RELAY_CEL_004);
      expect(err.code).not.toBe(CODE_RELAY_CEL_006);
    });
  }

  test("RELAY-CEL-PANIC maps to RELAY-CEL-ENGINE-PANIC under RELAY-CEL-009", () => {
    const env = { ok: false, code: "RELAY-CEL-PANIC", error: "ENGINE_PANIC" };
    expect(() => decodeWasmEnvelope(env)).toThrow(RelayCelEngineError);
    try {
      decodeWasmEnvelope(env);
    } catch (e) {
      const err = e as RelayCelEngineError;
      expect(err.code).toBe(CODE_RELAY_CEL_009);
      expect(err.subtype).toBe(SUBTYPE_ENGINE_PANIC);
    }
  });

  test("a wasm exec failure (its 004) NEVER surfaces as host RELAY-CEL-004", () => {
    const env = { ok: false, code: "RELAY-CEL-004", error: "exec boom" };
    try {
      decodeWasmEnvelope(env);
      throw new Error("expected decode to throw");
    } catch (e) {
      const err = e as RelayCelEngineError;
      expect(err.code).toBe(CODE_RELAY_CEL_009);
      expect(err.code).not.toBe(CODE_RELAY_CEL_004);
      expect(err.subtype).toBe(SUBTYPE_ENGINE_EXEC);
    }
  });

  test("a wasm request failure (its 006) NEVER surfaces as host RELAY-CEL-006", () => {
    const env = { ok: false, code: "RELAY-CEL-006", error: "request boom" };
    try {
      decodeWasmEnvelope(env);
      throw new Error("expected decode to throw");
    } catch (e) {
      const err = e as RelayCelEngineError;
      expect(err.code).toBe(CODE_RELAY_CEL_009);
      expect(err.code).not.toBe(CODE_RELAY_CEL_006);
      expect(err.subtype).toBe(SUBTYPE_ENGINE_REQUEST);
    }
  });

  test("an unknown wasm failure code defaults to ENGINE-EXEC under 009 (fail-closed)", () => {
    const env = { ok: false, code: "RELAY-CEL-999", error: "unknown" };
    try {
      decodeWasmEnvelope(env);
      throw new Error("expected decode to throw");
    } catch (e) {
      const err = e as RelayCelEngineError;
      expect(err.code).toBe(CODE_RELAY_CEL_009);
      expect(err.subtype).toBe(SUBTYPE_ENGINE_EXEC);
    }
  });
});
