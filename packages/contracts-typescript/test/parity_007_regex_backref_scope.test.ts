// VAL-PARITY-007: regex-backreference profile screen scope parity.
//
// The host-side `checkRegexBackref` (packages/contracts-typescript/src/
// host-guards.ts) scans the ENTIRE raw expression text for any string literal
// containing `\<digit>` and rejects it with RELAY-CEL-007 (fail-closed). The
// cel-python mirror used to only inspect the FIRST string literal inside a
// `.matches()` call's exprlist, so a backreference in a sibling sub-expression,
// a bare string literal, a non-first `.matches()` argument, or a concatenated
// operand slipped through cel-python (fail-open) while the TS host rejected it.
// That asymmetry let an RE2-illegal backreference be published as a valid
// behavioral assertion against one runtime but not the other.
//
// M6 WS-I: the regex-backref pre-screen survives the legacy engine's removal in
// the engine-agnostic host-guards module (locked decision #4) and runs in the
// TS host on EVERY engine path (the wasm-backed WasmCelBackend.compile() calls
// it before the wasm). This file pins the host-guard side directly AND through
// the wasm backend's compile(); the cel-python side is pinned by
// packages/contracts/tests/test_parity_007_regex_backref_scope.py and the
// cross-runtime corpus parity loop reads the same expressions out of
// tests/conformance/cel/relay_cel_corpus.json. Identical input expression ->
// identical RELAY-CEL-007 reject on both runtimes is the test contract.
//
// Tool: vitest. Evidence: vitest exit code, captured error code/subtype.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import {
  RelayCelRegexBackreferenceError,
  SUBTYPE_PROFILE_REGEX_BACKREF,
} from "../src/index.js";
import { checkRegexBackref } from "../src/host-guards.js";
import type { WasmCelBackend } from "../src/wasm-evaluator.js";

// A regex backreference: capture group `(b)` followed by `\1`. The single
// backslash in the TS source string is itself escaped (`\\1`) so the
// compiled CEL source carries the literal `\1` -- the RE2-illegal backref.
const BACKREF_BODY = "a(b)\\1";

// Non-ASCII digit codepoints (Unicode Nd category) built at RUNTIME via
// String.fromCodePoint so this source file stays ASCII (CLAUDE.md
// "ASCII-Safe Source"). A real backref is ASCII `\1`..`\9` only; `\`
// followed by a NON-ASCII digit (fullwidth zero U+FF10, Arabic-Indic zero
// U+0660) is NOT a backref. The host `/\\\d/` (no `u` flag; JS `\d` is
// ASCII-only) ACCEPTS it -- so this side needs no code change; the cel-python
// mirror was pinned to ASCII so both runtimes now agree (VAL-PARITY-007).
const FULLWIDTH_ZERO = String.fromCodePoint(0xff10); // U+FF10
const ARABIC_ZERO = String.fromCodePoint(0x0660); // U+0660

// The host guard is the load-bearing invariant (locked decision #4): it runs in
// the TS host on every engine path. Exercise it directly so the whole-
// expression scope is pinned independently of any engine.
function guardError(expression: string): unknown {
  try {
    checkRegexBackref(expression);
    return null;
  } catch (e) {
    return e;
  }
}

describe("VAL-PARITY-007: the host backref screen is whole-expression scoped", () => {
  test("backref in a sibling sub-expression (not inside matches()) is rejected", () => {
    const caught = guardError(`req.matches("ok") && note == "${BACKREF_BODY}"`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref in a bare string literal with no matches() call is rejected", () => {
    const caught = guardError(`note == "${BACKREF_BODY}"`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref in a concatenated matches() argument is rejected", () => {
    const caught = guardError(`req.matches("a" + "${BACKREF_BODY}")`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("backref as the first matches() argument is still rejected (regression guard)", () => {
    const caught = guardError(`req.matches("${BACKREF_BODY}")`);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("RE2 shorthand classes \\d \\w \\s are not treated as backreferences", () => {
    // backslash followed by a LETTER, not a digit -- must NOT be flagged.
    const caught = guardError('note == "[a-z]+\\d\\w\\s"');
    expect(caught).toBeNull();
  });

  test("backslash + fullwidth digit (U+FF10) is NOT a backreference (accepted)", () => {
    // A real backref is ASCII \1..\9; `\` + a non-ASCII digit is not.
    // The host `\d` is ASCII-only so this is accepted -- matching the
    // ASCII-pinned cel-python mirror (VAL-PARITY-007).
    const expr = 'note == "' + "\\" + FULLWIDTH_ZERO + '"';
    expect(guardError(expr)).toBeNull();
  });

  test("backslash + Arabic-Indic digit (U+0660) is NOT a backreference (accepted)", () => {
    const expr = 'note == "' + "\\" + ARABIC_ZERO + '"';
    expect(guardError(expr)).toBeNull();
  });

  test("ASCII backref \\1 is still rejected (regression guard for the ASCII pin)", () => {
    // The ASCII pin must NOT widen the accepted set: a genuine ASCII
    // backref stays rejected on both runtimes.
    const expr = 'note == "' + "\\1" + '"';
    const caught = guardError(expr);
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });
});

// The pre-screen runs on the production engine path too: WasmCelBackend.compile()
// (and therefore evaluate()) invokes the SAME host guard BEFORE the wasm sees
// the expression. Prove the backref reject reaches the public wasm path so the
// guard is not merely a standalone helper.
describe("VAL-PARITY-007: the wasm backend applies the same host screen at compile()", () => {
  let ev: WasmCelBackend | null = null;

  afterEach(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  test("WasmCelBackend.compile() rejects a backref before the wasm call", () => {
    ev = makeCelEvaluator();
    let caught: unknown = null;
    try {
      ev.compile(`req.matches("${BACKREF_BODY}")`);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    expect((caught as RelayCelRegexBackreferenceError).code).toBe(
      "RELAY-CEL-007",
    );
  });

  test("WasmCelBackend.evaluate() rejects a backref fail-closed (host pre-screen)", async () => {
    ev = makeCelEvaluator();
    let caught: unknown = null;
    try {
      await ev.evaluate(`note == "${BACKREF_BODY}"`);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    expect((caught as RelayCelRegexBackreferenceError).subtype).toBe(
      SUBTYPE_PROFILE_REGEX_BACKREF,
    );
  });
});
