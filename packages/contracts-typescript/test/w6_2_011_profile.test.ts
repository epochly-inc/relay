// VAL-W6-011: the wasm CEL evaluator enforces the same Relay profile as
// cel-python.
//
// The TS evaluator MUST reject expressions containing `dyn(...)`, native
// CEL `timestamp(...)`, or `duration(...)` with the same `RELAY-CEL-002`
// profile-rejection code (and structured subtype) emitted by cel-python on
// the same expression. Identical input expression -> identical error code on
// both runtimes is the test contract.
//
// M6 WS-I: the dyn/timestamp/duration profile rejection is enforced by the
// SINGLE wasm engine (it emits a STRUCTURED RELAY-CEL-002 subtype which the
// host maps verbatim onto RelayCelProfileError). The regex-backref rejection
// (RELAY-CEL-007) is the host-side pre-screen (host-guards.ts, locked decision
// #4) that runs before the wasm. Both are exercised here through the public
// WasmCelBackend facade.
//
// VAL-W6-014's regex backref subtype is also covered here for the same
// "identical error code on identical input" reason; the dedicated 014
// file pairs the JCS bytes against the Python golden output.
//
// Tool: vitest. Evidence: vitest exit code, captured error code equal to the
// cel-python error code for the matching fixture.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import {
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_REGEX_BACKREF,
  SUBTYPE_PROFILE_TS_DISABLED,
} from "../src/index.js";
import type { WasmCelBackend } from "../src/wasm-evaluator.js";

let ev: WasmCelBackend | null = null;

afterEach(async () => {
  if (ev !== null) {
    await ev.dispose();
    ev = null;
  }
});

function backend(): WasmCelBackend {
  ev = makeCelEvaluator();
  return ev;
}

async function evalError(expression: string): Promise<unknown> {
  try {
    await backend().evaluate(expression);
    return null;
  } catch (e) {
    return e;
  }
}

describe("VAL-W6-011: the wasm evaluator enforces the Relay profile", () => {
  test("dyn(...) is rejected with RELAY-CEL-002 / DYN-DISABLED", async () => {
    const caught = await evalError("dyn(1)");
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_DYN_DISABLED);
  });

  test("native timestamp(...) is rejected with RELAY-CEL-002 / TS-DISABLED", async () => {
    const caught = await evalError('timestamp("2026-01-01T00:00:00Z")');
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_TS_DISABLED);
  });

  test("native duration(...) is rejected with RELAY-CEL-002 / DUR-DISABLED", async () => {
    const caught = await evalError('duration("3600s")');
    expect(caught).toBeInstanceOf(RelayCelProfileError);
    const err = caught as RelayCelProfileError;
    expect(err.code).toBe("RELAY-CEL-002");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_DUR_DISABLED);
  });

  test("regex backref in a string literal is rejected with RELAY-CEL-007 / REGEX-BACKREF", async () => {
    // Source CEL: "abba".matches("a(b)\1"). The host pre-screen
    // (host-guards.ts checkRegexBackref) rejects this BEFORE the wasm call.
    const caught = await evalError('"abba".matches("a(b)\\1")');
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
    const err = caught as RelayCelRegexBackreferenceError;
    expect(err.code).toBe("RELAY-CEL-007");
    expect(err.subtype).toBe(SUBTYPE_PROFILE_REGEX_BACKREF);
  });

  test("simple backref pattern (.)\\1+ is rejected with RELAY-CEL-007", async () => {
    const caught = await evalError('"abc".matches("(.)\\1+")');
    expect(caught).toBeInstanceOf(RelayCelRegexBackreferenceError);
  });

  test("a clean RE2-safe arithmetic expression evaluates without a profile error", async () => {
    // The Python contract for the equivalent baseline test only asserts the
    // profile checks do not have false positives; a clean arithmetic
    // expression evaluates cleanly through the wasm engine.
    ev = makeCelEvaluator();
    const out = await ev.evaluate("1 + 2 * 3");
    expect(Number(out)).toBe(7);
  });
});
