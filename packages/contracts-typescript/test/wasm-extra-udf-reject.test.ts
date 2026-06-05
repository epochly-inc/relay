// VAL-CWC-P2TSGATE-003: WasmCelBackend rejects any caller-supplied UDF whose
// name is not in the 3-UDF allowlist (relay.coverage / relay.tool_arg /
// relay.schema_match) fail-closed BEFORE evaluation, with a structured
// RelayCelError carrying code RELAY-CEL-004 and subtype
// RELAY-CEL-UDF-UNREGISTERED.
//
// The wasm exposes only the 3 hardcoded relay.* UDFs and has NO registration
// slot for a custom callable, so an extra UDF is an unregistered-UDF error --
// distinct from the purity subtype RELAY-CEL-UDF-IMPURE which shares code 004.
//
// TS mirror of the Python WasmCelEvaluator.__init__ extra-UDF reject
// (packages/contracts/src/relay_contracts/wasm_backed_evaluator.py:169-185) and
// the Python SUBTYPE_UDF_UNREGISTERED (errors.py:52).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { describe, expect, test } from "vitest";

import {
  CODE_RELAY_CEL_004,
  RelayCelError,
  SUBTYPE_UDF_UNREGISTERED,
} from "../src/errors.js";
import { registerUdf } from "../src/udf.js";
import { RELAY_UDFS } from "../src/udfs/registry.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

describe("VAL-CWC-P2TSGATE-003: WasmCelBackend rejects non-allowlist UDFs", () => {
  test("a non-allowlist UDF 'my_check' is rejected with RELAY-CEL-004 / RELAY-CEL-UDF-UNREGISTERED", () => {
    const myCheck = registerUdf({
      name: "my_check",
      fn: (x: unknown) => x,
      pure: true,
      arity: 1,
    });
    let thrown: unknown;
    try {
      new WasmCelBackend({ udfs: [myCheck] });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(RelayCelError);
    const err = thrown as RelayCelError;
    expect(err.code).toBe(CODE_RELAY_CEL_004);
    expect(err.subtype).toBe(SUBTYPE_UDF_UNREGISTERED);
  });

  test("the rejection is fail-closed: construction throws (no evaluation can run)", () => {
    const bad = registerUdf({
      name: "totally_custom",
      fn: () => 0,
      pure: true,
      arity: 0,
    });
    expect(() => new WasmCelBackend({ udfs: [bad] })).toThrow(RelayCelError);
  });

  test("the 3 native relay.* UDFs (RELAY_UDFS) are accepted (no rejection)", () => {
    // The native allowlist is baked into the wasm; passing those names is fine.
    expect(() => new WasmCelBackend({ udfs: RELAY_UDFS })).not.toThrow();
  });

  test("an empty UDF set constructs without error", () => {
    expect(() => new WasmCelBackend({ udfs: [] })).not.toThrow();
    expect(() => new WasmCelBackend({})).not.toThrow();
  });

  test("a mix of an allowlist UDF and a non-allowlist UDF still rejects", () => {
    const coverage = RELAY_UDFS[0];
    if (coverage === undefined) {
      throw new Error("RELAY_UDFS must contain the native relay.coverage UDF");
    }
    const rogue = registerUdf({
      name: "rogue.udf",
      fn: () => true,
      pure: true,
      arity: 0,
    });
    try {
      new WasmCelBackend({ udfs: [coverage, rogue] });
      throw new Error("expected construction to throw");
    } catch (e) {
      const err = e as RelayCelError;
      expect(err.code).toBe(CODE_RELAY_CEL_004);
      expect(err.subtype).toBe(SUBTYPE_UDF_UNREGISTERED);
    }
  });
});
