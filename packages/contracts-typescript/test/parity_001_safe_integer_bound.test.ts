// VAL-PARITY-001: the wasm-backed evaluator rejects integral evaluation
// results whose magnitude exceeds Number.MAX_SAFE_INTEGER (2**53 - 1) at the
// result boundary, mirroring the cel-python bound in
// packages/contracts/src/relay_contracts/evaluator.py _check_finite.
//
// M6 WS-I: the host-side finiteness / safe-integer guard (checkFinite) survives
// the legacy engine's removal in the engine-agnostic host-guards module (locked
// decision #4) and runs on the typedToNative-converted wasm result. This file
// pins that guard via BOTH the public makeCelEvaluator()/WasmCelBackend
// evaluate() path AND the directly-imported host guard.
//
// Rationale for the >= 2**53 (i.e. > MAX_SAFE_INTEGER) threshold:
// 2**53 is NOT a safe integer -- it is indistinguishable from 2**53 + 1
// after IEEE-754 double rounding (both round to the same float64). cel-python
// keeps an integer exact (arbitrary precision) while a JS double rounds it.
// For ANY integer V: float64(V) > MAX_SAFE_INTEGER  <=>  V >= 2**53. So
// rejecting magnitude >= 2**53 makes a float-rounded integer overflow that
// lands exactly on 2**53 (e.g. 9007199254740992 + 1 -> 9007199254740993,
// rounded by a JS double to 9007199254740992) REJECT, matching cel-python's
// exact-integer rejection. The previous bound (abs > 2**53, EXCLUSIVE)
// accepted 2**53 itself, which let a rounded integer overflow silently pass --
// a cross-runtime digest break and a fail-open relative to cel-python
// (CLAUDE.md keystone invariant #11). Found by `codex review`
// (CEL +-2^53 Py<->TS parity P1), CONFIRMED empirically.
//
// Tool: vitest. Evidence: vitest exit code, captured error code/subtype.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import {
  MAX_TIMEOUT_MS,
  RelayCelNumericOutOfBoundsError,
  SUBTYPE_NUMERIC_OOB,
} from "../src/index.js";
// SAFE_INTEGER_BOUND and the host finiteness guard are engine-agnostic
// host-side constants/functions (host-guards.ts) -- not part of the public
// cross-runtime surface mirrored in __init__.py; import them from the module
// directly to pin the threshold and exercise the guard in isolation without
// widening the public API.
import { checkFinite, SAFE_INTEGER_BOUND } from "../src/host-guards.js";
import type { WasmCelBackend } from "../src/wasm-evaluator.js";

// A single shared wasm backend per test; disposed in afterEach so a hung /
// terminated Worker never leaks across cases.
let ev: WasmCelBackend | null = null;

afterEach(async () => {
  if (ev !== null) {
    await ev.dispose();
    ev = null;
  }
});

function backend(): WasmCelBackend {
  ev = makeCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
  return ev;
}

describe("VAL-PARITY-001: the wasm host rejects out-of-safe-range integer results", () => {
  test("SAFE_INTEGER_BOUND is Number.MAX_SAFE_INTEGER (2**53 - 1)", () => {
    expect(SAFE_INTEGER_BOUND).toBe(9007199254740991);
    expect(SAFE_INTEGER_BOUND).toBe(2 ** 53 - 1);
    expect(SAFE_INTEGER_BOUND).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("an integral product overflowing past 2**53 is rejected", async () => {
    // 1e9 * 1e9 = 1e18; abs > MAX_SAFE_INTEGER in both runtimes.
    let caught: unknown = null;
    try {
      await backend().evaluate("1000000000 * 1000000000");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    const err = caught as RelayCelNumericOutOfBoundsError;
    expect(err.code).toBe("RELAY-CEL-006");
    expect(err.subtype).toBe(SUBTYPE_NUMERIC_OOB);
  });

  test("a negative integral overflow past -(2**53) is rejected", async () => {
    // -(2**53) * 2 = -2**54; abs > MAX_SAFE_INTEGER in both runtimes.
    let caught: unknown = null;
    try {
      await backend().evaluate("-9007199254740992 * 2");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("an integer literal just past MAX_SAFE_INTEGER (2**53 + 1) is rejected", async () => {
    // 9007199254740993 == 2**53 + 1. cel-python keeps it exact and rejects;
    // a JS double rounds it to 9007199254740992 == 2**53 and -- with this
    // bound -- ALSO rejects (>= 2**53). This is the exact divergence codex
    // flagged, now closed identically on both hosts.
    let caught: unknown = null;
    try {
      await backend().evaluate("9007199254740993");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("Number.MAX_SAFE_INTEGER (2**53 - 1) is accepted", async () => {
    const out = await backend().evaluate("9007199254740991");
    expect(Number(out)).toBe(SAFE_INTEGER_BOUND);
    expect(Number(out)).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("a non-integral number well within range is accepted", async () => {
    const out = await backend().evaluate("1.5 + 2.5");
    expect(Number(out)).toBe(4);
  });

  // The host guard (checkFinite) is the single source of the safe-range
  // rejection on EVERY engine path (locked decision #4). Exercise it directly
  // so the boundary semantics are pinned independently of the engine arithmetic
  // -- these are the exact result-boundary cases the wasm result flows through.
  describe("the host finiteness guard (checkFinite) pins the boundary directly", () => {
    test("the boundary value 2**53 is REJECTED (unsafe integer)", () => {
      // 2**53 is NOT a safe integer (it is indistinguishable from 2**53 + 1
      // after double rounding), so a result of exactly 2**53 may be a rounded
      // integer overflow. cel-python rejects the exact integer 9007199254740993
      // (which it keeps exact); rejecting 2**53 here makes the rounded value
      // (9007199254740992) reject identically. Fail-closed in both runtimes.
      expect(() => checkFinite(9007199254740992)).toThrow(
        RelayCelNumericOutOfBoundsError,
      );
    });

    test("an integer overflow by addition (2**53 + 1 -> rounded 2**53) is rejected", () => {
      // 9007199254740992 + 1 in float64 rounds to 9007199254740992 == 2**53,
      // which the bound rejects -- the codex-flagged integer-overflow
      // pass-through, now closed.
      expect(() => checkFinite(9007199254740992 + 1)).toThrow(
        RelayCelNumericOutOfBoundsError,
      );
    });

    test("a whole-valued double >= 2**53 is rejected", () => {
      // A whole-valued double of magnitude 9007199254740994 is bound as a JS
      // number; the integral safe-range bound rejects it, matching the
      // cel-python whole-double branch.
      let caught: unknown = null;
      try {
        checkFinite(9007199254740994);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
      expect((caught as RelayCelNumericOutOfBoundsError).code).toBe(
        "RELAY-CEL-006",
      );
      expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
        SUBTYPE_NUMERIC_OOB,
      );
    });

    test("the negation of a whole value >= 2**53 is rejected", () => {
      expect(() => checkFinite(-9007199254740994)).toThrow(
        RelayCelNumericOutOfBoundsError,
      );
    });

    test("a whole value == MAX_SAFE_INTEGER (2**53 - 1) is accepted", () => {
      expect(checkFinite(9007199254740991)).toBe(9007199254740991);
      expect(checkFinite(9007199254740991)).toBe(Number.MAX_SAFE_INTEGER);
    });

    test("a small whole-valued double (100) is accepted", () => {
      expect(checkFinite(100)).toBe(100);
    });

    test("a non-finite number is rejected", () => {
      expect(() => checkFinite(Number.POSITIVE_INFINITY)).toThrow(
        RelayCelNumericOutOfBoundsError,
      );
      expect(() => checkFinite(Number.NaN)).toThrow(
        RelayCelNumericOutOfBoundsError,
      );
    });
  });
});
