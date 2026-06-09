// roborev findings 8 + 10 (errors.ts) + the decodeWasmEnvelope struct-subtype path.
//
// Finding 8: the wasm emits RELAY-CEL-PROFILE-STRUCT-DISABLED (struct/message
// construction fence, lib.rs:106) but errors.ts's RelayCelSubtype union + the
// profile-subtype cast omitted it. The fix adds SUBTYPE_PROFILE_STRUCT_DISABLED,
// includes it in the union, exports it from index.ts, and validates the wasm
// profile subtype against the known set in decodeWasmEnvelope before casting.
//
// Finding 10: RelayCelEngineError's constructor accepted ANY RelayCelSubtype
// (should be only the 4 ENGINE subtypes). The fix narrows it to a
// RelayCelEngineSubtype union (the 4 ENGINE subtypes) on the constructor + the
// WASM_CODE_TO_ENGINE_SUBTYPE record type.
//
// Tool: vitest. Evidence: vitest exit code + the constructed error subtypes and
// the decodeWasmEnvelope behavior on the struct-disabled / unknown subtypes.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  decodeWasmEnvelope,
  type WasmResponseEnvelope,
} from "../src/wasm-evaluator.js";
import {
  CODE_RELAY_CEL_002,
  RelayCelEngineError,
  RelayCelProfileError,
  SUBTYPE_ENGINE_COMPILE,
  SUBTYPE_ENGINE_EXEC,
  SUBTYPE_ENGINE_PANIC,
  SUBTYPE_ENGINE_REQUEST,
  SUBTYPE_PROFILE_STRUCT_DISABLED,
} from "../src/index.js";

describe("roborev finding 8: RELAY-CEL-PROFILE-STRUCT-DISABLED subtype", () => {
  test("SUBTYPE_PROFILE_STRUCT_DISABLED is exported with the wasm spelling", () => {
    expect(SUBTYPE_PROFILE_STRUCT_DISABLED).toBe(
      "RELAY-CEL-PROFILE-STRUCT-DISABLED",
    );
  });

  test("decodeWasmEnvelope maps a STRUCT-DISABLED profile rejection to RelayCelProfileError", () => {
    const env: WasmResponseEnvelope = {
      ok: false,
      code: CODE_RELAY_CEL_002,
      error: "Relay CEL profile disables message/struct construction",
      subtype: "RELAY-CEL-PROFILE-STRUCT-DISABLED",
    };
    let thrown: unknown = null;
    try {
      decodeWasmEnvelope(env);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(RelayCelProfileError);
    const err = thrown as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_STRUCT_DISABLED);
  });

  // The known-set validation: a RELAY-CEL-002 envelope whose subtype is NOT a
  // recognized profile subtype must NOT be blindly cast/propagated as a profile
  // error -- it is an engine-request anomaly (the wasm should never emit an
  // unknown profile subtype).
  test("decodeWasmEnvelope rejects an UNKNOWN RELAY-CEL-002 subtype as an engine anomaly", () => {
    const env: WasmResponseEnvelope = {
      ok: false,
      code: CODE_RELAY_CEL_002,
      error: "bogus",
      subtype: "RELAY-CEL-PROFILE-NOT-A-REAL-SUBTYPE",
    };
    let thrown: unknown = null;
    try {
      decodeWasmEnvelope(env);
    } catch (e) {
      thrown = e;
    }
    // An unknown profile subtype is NOT a valid profile rejection -> engine error.
    expect(thrown).toBeInstanceOf(RelayCelEngineError);
    expect(thrown).not.toBeInstanceOf(RelayCelProfileError);
  });

  // The known DYN/TS/DUR/STRUCT subtypes are all accepted as profile errors.
  test.each([
    "RELAY-CEL-PROFILE-DYN-DISABLED",
    "RELAY-CEL-PROFILE-TS-DISABLED",
    "RELAY-CEL-PROFILE-DUR-DISABLED",
    "RELAY-CEL-PROFILE-STRUCT-DISABLED",
  ])("decodeWasmEnvelope accepts known profile subtype %s", (subtype) => {
    const env: WasmResponseEnvelope = {
      ok: false,
      code: CODE_RELAY_CEL_002,
      error: "profile",
      subtype,
    };
    expect(() => decodeWasmEnvelope(env)).toThrow(RelayCelProfileError);
  });
});

describe("roborev finding 10: RelayCelEngineError subtype is narrowed to the 4 engine subtypes", () => {
  // The four engine subtypes are constructible.
  test.each([
    SUBTYPE_ENGINE_COMPILE,
    SUBTYPE_ENGINE_EXEC,
    SUBTYPE_ENGINE_REQUEST,
    SUBTYPE_ENGINE_PANIC,
  ])("RelayCelEngineError accepts engine subtype %s", (subtype) => {
    const err = new RelayCelEngineError("x", subtype);
    expect(err.code).toBe("RELAY-CEL-009");
    expect(err.subtype).toBe(subtype);
  });

  // fromWasmEnvelope maps wasm codes to the engine subtypes.
  test("fromWasmEnvelope maps the wasm codes to engine subtypes", () => {
    expect(
      RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-001", "m").subtype,
    ).toBe(SUBTYPE_ENGINE_COMPILE);
    expect(
      RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-004", "m").subtype,
    ).toBe(SUBTYPE_ENGINE_EXEC);
    expect(
      RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-006", "m").subtype,
    ).toBe(SUBTYPE_ENGINE_REQUEST);
    expect(
      RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-PANIC", "m").subtype,
    ).toBe(SUBTYPE_ENGINE_PANIC);
    // an unknown wasm code defaults to ENGINE-EXEC.
    expect(
      RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-999", "m").subtype,
    ).toBe(SUBTYPE_ENGINE_EXEC);
  });
});
