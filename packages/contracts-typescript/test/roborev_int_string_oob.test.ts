// roborev finding 4: `encodeIntString` used `toFixed(0)`, which yields
// EXPONENTIAL notation ('1e+21') for |n| >= ~1e21. `BigInt('1e+21')` then throws
// a RAW SyntaxError instead of the structured RelayCelNumericOutOfBoundsError
// (RELAY-CEL-006). A >= 1e21 integral binding value MUST surface the structured
// numeric-out-of-bounds error, never a bare SyntaxError.
//
// Tool: vitest. Evidence: vitest exit code + the caught error class/code.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  RelayCelNumericOutOfBoundsError,
  SUBTYPE_NUMERIC_OOB,
} from "../src/index.js";
import { nativeToTyped } from "../src/wasm-evaluator.js";

describe("roborev finding 4: large integral magnitudes raise the structured numeric-OOB error", () => {
  // 1e21 is integral (Number.isInteger(1e21) === true) and far beyond the
  // 2**53 - 1 safe range. The codec must reject it with the structured
  // RelayCelNumericOutOfBoundsError (RELAY-CEL-006), not a raw BigInt SyntaxError.
  test("nativeToTyped(1e21) throws RelayCelNumericOutOfBoundsError (RELAY-CEL-006), not SyntaxError", () => {
    expect(Number.isInteger(1e21)).toBe(true);
    let caught: unknown = null;
    try {
      nativeToTyped(1e21);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
    const err = caught as RelayCelNumericOutOfBoundsError;
    expect(err.code).toBe("RELAY-CEL-006");
    expect(err.subtype).toBe(SUBTYPE_NUMERIC_OOB);
  });

  test("nativeToTyped(-1e21) (negative large magnitude) also raises the structured error", () => {
    let caught: unknown = null;
    try {
      nativeToTyped(-1e21);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
  });

  test("nativeToTyped(1e30) (very large magnitude) raises the structured error", () => {
    let caught: unknown = null;
    try {
      nativeToTyped(1e30);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
  });
});
