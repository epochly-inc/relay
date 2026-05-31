// VAL-PARITY-001: cel-js rejects integral evaluation results whose
// magnitude exceeds Number.MAX_SAFE_INTEGER (2**53 - 1) at the result
// boundary, mirroring the cel-python bound in
// packages/contracts/src/relay_contracts/evaluator.py _check_finite.
//
// Rationale for the >= 2**53 (i.e. > MAX_SAFE_INTEGER) threshold:
// 2**53 is NOT a safe integer -- it is indistinguishable from 2**53 + 1
// after IEEE-754 double rounding (both round to the same float64). cel-python
// keeps an integer exact (arbitrary precision) while a JS double rounds it.
// For ANY integer V: float64(V) > MAX_SAFE_INTEGER  <=>  V >= 2**53. So
// rejecting magnitude >= 2**53 makes a float-rounded integer overflow that
// lands exactly on 2**53 (e.g. 9007199254740992 + 1 -> 9007199254740993,
// rounded by cel-js to 9007199254740992) REJECT in cel-js, matching
// cel-python's exact-integer rejection. The previous bound (abs > 2**53,
// EXCLUSIVE) accepted 2**53 itself, which let cel-js silently pass a
// rounded integer overflow -- a cross-runtime digest break and a fail-open
// relative to cel-python (CLAUDE.md keystone invariant #11). Found by
// `codex review` (CEL +-2^53 Py<->TS parity P1), CONFIRMED empirically.
//
// Tool: vitest. Evidence: vitest exit code, captured error code/subtype.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  MAX_TIMEOUT_MS,
  RelayCelEvaluator,
  RelayCelNumericOutOfBoundsError,
  SUBTYPE_NUMERIC_OOB,
} from "../src/index.js";
// SAFE_INTEGER_BOUND is an internal evaluator constant (not part of the
// public cross-runtime surface mirrored in __init__.py); import it from the
// module directly to pin the threshold without widening the public API.
import { SAFE_INTEGER_BOUND } from "../src/evaluator.js";

describe("VAL-PARITY-001: cel-js rejects out-of-safe-range integer results", () => {
  test("SAFE_INTEGER_BOUND is Number.MAX_SAFE_INTEGER (2**53 - 1)", () => {
    expect(SAFE_INTEGER_BOUND).toBe(9007199254740991);
    expect(SAFE_INTEGER_BOUND).toBe(2 ** 53 - 1);
    expect(SAFE_INTEGER_BOUND).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("an integral product overflowing past 2**53 is rejected", () => {
    // 1e9 * 1e9 = 1e18; abs > MAX_SAFE_INTEGER in both runtimes.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("1000000000 * 1000000000");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    const err = caught as RelayCelNumericOutOfBoundsError;
    expect(err.code).toBe("RELAY-CEL-006");
    expect(err.subtype).toBe(SUBTYPE_NUMERIC_OOB);
  });

  test("a negative integral overflow past -(2**53) is rejected", () => {
    // -(2**53) * 2 = -2**54; abs > MAX_SAFE_INTEGER in both runtimes.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("-9007199254740992 * 2");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("the boundary value 2**53 is now REJECTED (unsafe integer)", () => {
    // CHANGED: the prior bound accepted exactly 2**53. 2**53 is NOT a safe
    // integer (it is indistinguishable from 2**53 + 1 after double rounding),
    // so a cel-js result of exactly 2**53 may be a rounded integer overflow.
    // cel-python rejects the exact integer 9007199254740993 (which it keeps
    // exact); rejecting 2**53 on the cel-js side makes the rounded value
    // (9007199254740992) reject identically. Fail-closed in both runtimes.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("9007199254740992");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("an integer literal just past MAX_SAFE_INTEGER (2**53 + 1) is rejected", () => {
    // 9007199254740993 == 2**53 + 1. cel-python keeps it exact and rejects;
    // cel-js rounds it to 9007199254740992 == 2**53 and -- with the corrected
    // bound -- ALSO rejects (>= 2**53). Previously cel-js ACCEPTED this
    // rounded value (fail-open). This is the exact divergence codex flagged.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("9007199254740993");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("an integer overflow by addition (2**53 + 1) is rejected", () => {
    // 9007199254740992 + 1: cel-python computes the exact int 9007199254740993
    // and rejects; cel-js does float64 arithmetic, rounding to 9007199254740992
    // == 2**53, which the corrected bound ALSO rejects. Previously ACCEPTED
    // (fail-open) -- the codex-flagged integer-overflow pass-through.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("9007199254740992 + 1");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("Number.MAX_SAFE_INTEGER (2**53 - 1) is accepted", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("9007199254740991");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(SAFE_INTEGER_BOUND);
    expect(Number(out)).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("a non-integral number well within range is accepted", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("1.5 + 2.5");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(4);
  });

  // VAL-PARITY-001 whole-DOUBLE branch (Py<->TS parity closure): cel-js 0.8.2
  // collapses CEL int and CEL double to a bare JS `number` and re-derives the
  // type from the value (getCelType classifies any whole-valued number as
  // int), so a whole-valued CEL DOUBLE literal >= 2**53 is INDISTINGUISHABLE
  // here from the same-magnitude CEL int and is rejected by the integral
  // bound. cel-python preserved the DoubleType, so its int-only bound let
  // cel-python ACCEPT the double while cel-js REJECTED it. cel-python now
  // rejects the whole-valued double too (evaluator.py _check_finite
  // whole-double branch), so BOTH runtimes give the SAME verdict on these.
  test("a whole-valued double literal >= 2**53 is rejected", () => {
    // 9007199254740994.0 -- a DOUBLE literal; cel-js sees the bare number
    // 9007199254740994 (whole) and rejects via the integral bound.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("9007199254740994.0");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    const err = caught as RelayCelNumericOutOfBoundsError;
    expect(err.code).toBe("RELAY-CEL-006");
    expect(err.subtype).toBe(SUBTYPE_NUMERIC_OOB);
  });

  test("the negation of a whole-valued double >= 2**53 is rejected", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let caught: unknown = null;
    try {
      ev.evaluate("-9007199254740994.0");
    } catch (e) {
      caught = e;
    } finally {
      ev.dispose();
    }
    expect(caught).toBeInstanceOf(RelayCelNumericOutOfBoundsError);
    expect((caught as RelayCelNumericOutOfBoundsError).subtype).toBe(
      SUBTYPE_NUMERIC_OOB,
    );
  });

  test("a whole-valued double == MAX_SAFE_INTEGER (2**53 - 1) is accepted", () => {
    // 9007199254740991.0 -- the LARGEST whole double accepted (abs not > the
    // bound). Must NOT over-reject: the whole-double branch fires only beyond
    // the bound.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("9007199254740991.0");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(SAFE_INTEGER_BOUND);
    expect(Number(out)).toBe(Number.MAX_SAFE_INTEGER);
  });

  test("a small whole-valued double (100.0) is accepted", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("100.0");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(100);
  });
});
