// VAL-PARITY-001: cel-js rejects integral evaluation results whose
// magnitude exceeds 2**53 at the result boundary, mirroring the
// cel-python bound in
// packages/contracts/src/relay_contracts/evaluator.py _check_finite.
//
// cel-python keeps such an integer exact (arbitrary precision) while a JS
// double rounds it, so the same logical result would canonicalise to
// DIFFERENT RFC 8785 JCS bytes in each runtime -- a cross-runtime digest
// break (CLAUDE.md keystone invariant #11). Both runtimes apply the SAME
// numeric threshold (abs > 2**53) so they fail-closed identically.
//
// cel-js produces a JS double, so the bound is enforced only on overflows
// whose ROUNDED magnitude still exceeds 2**53 (e.g. 2**53 * 2 = 2**54). A
// true value of exactly 2**53 + 1 rounds down to 2**53 in cel-js and is
// indistinguishable from the accepted boundary there; that asymmetry is
// precisely the hazard VAL-PARITY-001 fixes by failing closed on the
// Python side, where the value is still exact (covered by
// packages/contracts/tests/test_w6_1_evaluator.py).
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
  test("SAFE_INTEGER_BOUND is 2**53", () => {
    expect(SAFE_INTEGER_BOUND).toBe(9007199254740992);
    expect(SAFE_INTEGER_BOUND).toBe(2 ** 53);
  });

  test("an integral product overflowing past 2**53 is rejected", () => {
    // 1e9 * 1e9 = 1e18; abs > 2**53 in both runtimes.
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
    // -(2**53) * 2 = -2**54; abs > 2**53 in both runtimes.
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

  test("the boundary value 2**53 is accepted (exactly representable)", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("9007199254740992");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(SAFE_INTEGER_BOUND);
  });

  test("Number.MAX_SAFE_INTEGER (2**53 - 1) is accepted", () => {
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    let out: unknown;
    try {
      out = ev.evaluate("9007199254740991");
    } finally {
      ev.dispose();
    }
    expect(Number(out)).toBe(SAFE_INTEGER_BOUND - 1);
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
});
