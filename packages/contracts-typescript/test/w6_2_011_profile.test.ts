// VAL-W6-011: cel-js evaluator enforces the same Relay profile as cel-python.
//
// The TS evaluator MUST reject expressions containing `dyn(...)`, native
// CEL `timestamp(...)`, or `duration(...)` at parse/check time with the
// same `RELAY-CEL-PROFILE-NNN` error code emitted by cel-python on the
// same expression. Identical input expression -> identical error code on
// both runtimes is the test contract.
//
// VAL-W6-014's regex backref subtype is also covered here for the same
// "identical error code on identical input" reason; the dedicated 014
// file pairs the JCS bytes against the Python golden output.
//
// Evidence: vitest exit code, captured error code equal to the cel-python
// error code for the matching fixture from
// `tests/conformance/cel/profile/`.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  RelayCelEvaluator,
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_REGEX_BACKREF,
  SUBTYPE_PROFILE_TS_DISABLED,
} from "../src/index.js";

describe("VAL-W6-011: cel-js evaluator enforces the Relay profile", () => {
  test("dyn(...) is rejected at compile() time with RELAY-CEL-002 / DYN-DISABLED", () => {
    const ev = new RelayCelEvaluator();
    let caught: unknown = null;
    try {
      ev.compile("dyn(1)");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_DYN_DISABLED);
  });

  test("native timestamp(...) is rejected at compile() time with RELAY-CEL-002 / TS-DISABLED", () => {
    const ev = new RelayCelEvaluator();
    let caught: unknown = null;
    try {
      ev.compile('timestamp("2026-01-01T00:00:00Z")');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_TS_DISABLED);
  });

  test("native duration(...) is rejected at compile() time with RELAY-CEL-002 / DUR-DISABLED", () => {
    const ev = new RelayCelEvaluator();
    let caught: unknown = null;
    try {
      ev.compile('duration("3600s")');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_DUR_DISABLED);
  });

  test("regex backref in a string literal is rejected with RELAY-CEL-007 / REGEX-BACKREF", () => {
    const ev = new RelayCelEvaluator();
    let caught: unknown = null;
    try {
      // Source CEL: "abba".matches("a(b)\1")
      ev.compile('"abba".matches("a(b)\\1")');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("simple backref pattern (.)\\1+ is rejected with RELAY-CEL-007", () => {
    const ev = new RelayCelEvaluator();
    let caught: unknown = null;
    try {
      ev.compile('"abc".matches("(.)\\1+")');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
  });

  test("a clean RE2-safe pattern compiles without error (baseline)", () => {
    const ev = new RelayCelEvaluator();
    // cel-js does not implement string.matches() so this expression
    // would fail at parse() if we tried to evaluate it -- but the
    // profile pre-screen returns BEFORE parse(). The Python contract
    // for the equivalent baseline test (test_re2_safe_pattern_compiles_cleanly
    // in test_w6_1_evaluator.py:431-437) only asserts the COMPILE call
    // does not throw a profile error. cel-js's parse failure surfaces
    // as a generic profile error, not a backref error -- so we cannot
    // mirror this assertion exactly. Instead, we assert that a clean
    // arithmetic expression compiles cleanly to confirm the profile
    // checks do not have false positives.
    expect(() => ev.compile("1 + 2 * 3")).not.toThrow();
  });
});
