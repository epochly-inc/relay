// VAL-CWC-P2TSGATE-001: errors.ts mirrors the Python RELAY-CEL-009 engine-error
// surface.
//
// `RelayCelEngineError` carries code RELAY-CEL-009 and exactly the four engine
// subtypes RELAY-CEL-ENGINE-COMPILE / -EXEC / -REQUEST / -PANIC, mirroring the
// already-landed Python `relay_contracts.errors.RelayCelEngineError`
// (packages/contracts/src/relay_contracts/errors.py:201-225). Constructing each
// subtype yields `envelope() === {code:'RELAY-CEL-009', subtype:<that subtype>,
// message:<str>}`. The from-wasm-envelope factory maps the wasm's OWN error
// codes/tags to the engine subtype with the SAME mapping as Python
// (001/compile -> COMPILE, 004/exec -> EXEC, 006/request -> REQUEST,
// PANIC -> PANIC; unknown -> EXEC). RELAY-CEL-009 is added to the `RelayCelCode`
// union and the four engine subtypes (plus RELAY-CEL-UDF-UNREGISTERED) to the
// `RelayCelSubtype` union.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  CODE_RELAY_CEL_009,
  RelayCelEngineError,
  RelayCelError,
  SUBTYPE_ENGINE_COMPILE,
  SUBTYPE_ENGINE_EXEC,
  SUBTYPE_ENGINE_PANIC,
  SUBTYPE_ENGINE_REQUEST,
  SUBTYPE_UDF_UNREGISTERED,
} from "../src/index.js";
import type {
  RelayCelCode,
  RelayCelEngineSubtype,
  RelayCelSubtype,
} from "../src/index.js";

describe("VAL-CWC-P2TSGATE-001: RelayCelEngineError mirrors the Python RELAY-CEL-009 surface", () => {
  test("CODE_RELAY_CEL_009 is the canonical engine code", () => {
    expect(CODE_RELAY_CEL_009).toBe("RELAY-CEL-009");
  });

  test("the four engine subtype constants match the Python tokens exactly", () => {
    expect(SUBTYPE_ENGINE_COMPILE).toBe("RELAY-CEL-ENGINE-COMPILE");
    expect(SUBTYPE_ENGINE_EXEC).toBe("RELAY-CEL-ENGINE-EXEC");
    expect(SUBTYPE_ENGINE_REQUEST).toBe("RELAY-CEL-ENGINE-REQUEST");
    expect(SUBTYPE_ENGINE_PANIC).toBe("RELAY-CEL-ENGINE-PANIC");
  });

  test("SUBTYPE_UDF_UNREGISTERED matches the Python token", () => {
    expect(SUBTYPE_UDF_UNREGISTERED).toBe("RELAY-CEL-UDF-UNREGISTERED");
  });

  test("RelayCelEngineError extends RelayCelError (except RelayCelError catches it)", () => {
    const err = new RelayCelEngineError("boom");
    expect(err).toBeInstanceOf(RelayCelError);
    expect(err).toBeInstanceOf(RelayCelEngineError);
  });

  test("default subtype is RELAY-CEL-ENGINE-EXEC (matches Python default)", () => {
    const err = new RelayCelEngineError("boom");
    expect(err.envelope()).toEqual({
      code: "RELAY-CEL-009",
      subtype: "RELAY-CEL-ENGINE-EXEC",
      message: "boom",
    });
  });

  const subtypeCases: Array<readonly [RelayCelEngineSubtype, string]> = [
    [SUBTYPE_ENGINE_COMPILE, "RELAY-CEL-ENGINE-COMPILE"],
    [SUBTYPE_ENGINE_EXEC, "RELAY-CEL-ENGINE-EXEC"],
    [SUBTYPE_ENGINE_REQUEST, "RELAY-CEL-ENGINE-REQUEST"],
    [SUBTYPE_ENGINE_PANIC, "RELAY-CEL-ENGINE-PANIC"],
  ];

  for (const [subtype, expectedSubtype] of subtypeCases) {
    test(`constructing RelayCelEngineError with ${expectedSubtype} yields RELAY-CEL-009 envelope`, () => {
      const err = new RelayCelEngineError("engine failure", subtype);
      expect(err.code).toBe("RELAY-CEL-009");
      expect(err.subtype).toBe(expectedSubtype);
      expect(err.envelope()).toEqual({
        code: "RELAY-CEL-009",
        subtype: expectedSubtype,
        message: "engine failure",
      });
      // envelope().code === 'RELAY-CEL-009' for each of the four subtypes.
      expect(err.envelope().code).toBe("RELAY-CEL-009");
    });
  }
});

describe("VAL-CWC-P2TSGATE-001: from-wasm-envelope mapping mirrors the Python _WASM_CODE_TO_ENGINE_SUBTYPE", () => {
  // Mirrors packages/contracts/src/relay_contracts/errors.py:193-198 +
  // from_wasm_envelope (errors.py:216-225). The wasm emits its OWN
  // RELAY-CEL-NNN namespace (001 compile / 004 exec / 006 request) plus the
  // RELAY-CEL-PANIC trap marker; these map to the DISTINCT RELAY-CEL-009 code
  // so a wasm exec/request failure is never confused with host 004/006.
  const wasmCases: Array<readonly [string, RelayCelSubtype]> = [
    ["RELAY-CEL-001", SUBTYPE_ENGINE_COMPILE],
    ["RELAY-CEL-004", SUBTYPE_ENGINE_EXEC],
    ["RELAY-CEL-006", SUBTYPE_ENGINE_REQUEST],
    ["RELAY-CEL-PANIC", SUBTYPE_ENGINE_PANIC],
  ];

  for (const [wasmCode, expectedSubtype] of wasmCases) {
    test(`wasm code ${wasmCode} maps to ${expectedSubtype} under RELAY-CEL-009`, () => {
      const err = RelayCelEngineError.fromWasmEnvelope(wasmCode, "from wasm");
      expect(err).toBeInstanceOf(RelayCelEngineError);
      expect(err).toBeInstanceOf(RelayCelError);
      expect(err.code).toBe("RELAY-CEL-009");
      expect(err.subtype).toBe(expectedSubtype);
      // A wasm exec (004) / request (006) failure NEVER surfaces as host
      // RELAY-CEL-004 / RELAY-CEL-006.
      expect(err.code).not.toBe("RELAY-CEL-004");
      expect(err.code).not.toBe("RELAY-CEL-006");
    });
  }

  test("the original wasm code is preserved in the message (mirrors Python prefix)", () => {
    const err = RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-004", "exec blew up");
    expect(err.message).toBe("[RELAY-CEL-004] exec blew up");
  });

  test("an unknown wasm code defaults to ENGINE-EXEC (matches Python default)", () => {
    const err = RelayCelEngineError.fromWasmEnvelope("RELAY-CEL-999", "mystery");
    expect(err.code).toBe("RELAY-CEL-009");
    expect(err.subtype).toBe(SUBTYPE_ENGINE_EXEC);
  });
});

describe("VAL-CWC-P2TSGATE-001: union widening (type-level + runtime)", () => {
  test("RELAY-CEL-009 is assignable to RelayCelCode", () => {
    const code: RelayCelCode = CODE_RELAY_CEL_009;
    expect(code).toBe("RELAY-CEL-009");
  });

  test("the new engine subtypes + UDF-UNREGISTERED are assignable to RelayCelSubtype", () => {
    const subtypes: RelayCelSubtype[] = [
      SUBTYPE_ENGINE_COMPILE,
      SUBTYPE_ENGINE_EXEC,
      SUBTYPE_ENGINE_REQUEST,
      SUBTYPE_ENGINE_PANIC,
      SUBTYPE_UDF_UNREGISTERED,
    ];
    expect(subtypes).toHaveLength(5);
  });
});
