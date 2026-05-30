// VAL-PARITY-007: regex-backreference profile screen scope parity.
//
// The cel-js `checkRegexBackref` (packages/contracts-typescript/src/
// evaluator.ts) scans the ENTIRE raw expression text for any string
// literal containing `\<digit>` and rejects it with RELAY-CEL-007
// (fail-closed). The cel-python mirror used to only inspect the FIRST
// string literal inside a `.matches()` call's exprlist, so a
// backreference in a sibling sub-expression, a bare string literal, a
// non-first `.matches()` argument, or a concatenated operand slipped
// through cel-python (fail-open) while cel-js rejected it. That asymmetry
// let an RE2-illegal backreference be published as a valid behavioral
// assertion against one runtime but not the other.
//
// The pinned scope is the broader fail-closed whole-expression scan on
// BOTH runtimes. This file pins the cel-js side; the cel-python side is
// pinned by packages/contracts/tests/test_parity_007_regex_backref_scope.py
// and the cross-runtime corpus parity loop reads the same expressions out
// of tests/conformance/cel/relay_cel_corpus.json. Identical input
// expression -> identical RELAY-CEL-007 reject on both runtimes is the
// test contract.
//
// Tool: vitest. Evidence: vitest exit code, captured error code/subtype.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  RelayCelEvaluator,
  RelayCelRegexBackreferenceError,
  SUBTYPE_PROFILE_REGEX_BACKREF,
} from "../src/index.js";

// A regex backreference: capture group `(b)` followed by `\1`. The single
// backslash in the TS source string is itself escaped (`\\1`) so the
// compiled CEL source carries the literal `\1` -- the RE2-illegal backref.
const BACKREF_BODY = "a(b)\\1";

function compileError(expression: string): unknown {
  const ev = new RelayCelEvaluator();
  try {
    ev.compile(expression);
    return null;
  } catch (e) {
    return e;
  } finally {
    ev.dispose();
  }
}

describe("VAL-PARITY-007: cel-js backref screen is whole-expression scoped", () => {
  test("backref in a sibling sub-expression (not inside matches()) is rejected", () => {
    const caught = compileError(`req.matches("ok") && note == "${BACKREF_BODY}"`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref in a bare string literal with no matches() call is rejected", () => {
    const caught = compileError(`note == "${BACKREF_BODY}"`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref in a concatenated matches() argument is rejected", () => {
    const caught = compileError(`req.matches("a" + "${BACKREF_BODY}")`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref as the first matches() argument is still rejected (regression guard)", () => {
    const caught = compileError(`req.matches("${BACKREF_BODY}")`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("RE2 shorthand classes \\d \\w \\s are not treated as backreferences", () => {
    // backslash followed by a LETTER, not a digit -- must NOT be flagged.
    // No top-level matches() so the expression is a clean comparison.
    const caught = compileError('note == "[a-z]+\\d\\w\\s"');
    expect(caught).toBeNull();
  });
});
