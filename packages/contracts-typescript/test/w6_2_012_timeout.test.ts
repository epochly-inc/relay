// VAL-W6-012: the wasm CEL evaluator's wall-clock timeout is enforced.
//
// Same contract as VAL-W6-003 but in JS: an evaluation that exceeds the
// configured budget aborts with RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001 and does
// not leak a partial result; the constructor validates the timeout bounds.
//
// M6 WS-I: the legacy slow-pure-UDF instrument is gone (the wasm engine accepts
// only the 3 native relay.* UDFs -- locked decision #3), so the budget-exceed
// is forced deterministically via the backend's `hangSentinel` construction
// option: an evaluated expression equal to the sentinel makes the in-Worker
// runner block past the budget so the host's worker.terminate() hard-kill path
// fires against a REAL Worker. The fuller hard-kill + recovery matrix lives in
// wasm-timeout.test.ts (VAL-CWC-P2TSGATE-008); this file pins the VAL-W6-012
// contract on the single wasm engine: the timeout fires, and the constructor
// rejects out-of-bounds budgets.
//
// Tool: vitest.
// Evidence: vitest exit code, error code captured.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import {
  MAX_TIMEOUT_MS,
  RelayCelTimeoutError,
  SUBTYPE_TIMEOUT,
} from "../src/index.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

const HANG_SENTINEL = "__RELAY_CEL_W6_2_012_HANG__";

describe("VAL-W6-012: the wasm evaluator wall-clock timeout", () => {
  let ev: WasmCelBackend | null = null;

  afterEach(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  test(
    "a budget-exceeding evaluation triggers RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001",
    async () => {
      // The hangSentinel makes the in-Worker runner spin past the budget so the
      // host's worker.terminate() hard-kill fires deterministically at any
      // budget (the spin is unbounded). timeoutMs is MAX_TIMEOUT_MS so the
      // Worker COLD START (spawn + .mjs import + wasm compile) fits inside the
      // budget; the sentinel still forces the hard-kill regardless.
      ev = new WasmCelBackend({
        timeoutMs: MAX_TIMEOUT_MS,
        hangSentinel: HANG_SENTINEL,
      });
      const start = process.hrtime.bigint();
      let caught: unknown = null;
      try {
        await ev.evaluate(HANG_SENTINEL);
      } catch (e) {
        caught = e;
      }
      const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
      expect(caught).toBeInstanceOf(RelayCelTimeoutError);
      const err = caught as RelayCelTimeoutError;
      expect(err.code).toBe("RELAY-CEL-003");
      expect(err.subtype).toBe(SUBTYPE_TIMEOUT);
      // The abort must fire promptly. A correctly-aborting run finishes in well
      // under 5 s (budget + cold-spawn jitter); a regressed abort (never fires)
      // would hang until the per-test vitest ceiling below and be recorded as a
      // failure, not a silent pass.
      expect(elapsedMs).toBeLessThan(5000);
    },
    20000,
  );

  test("constructor validates timeoutMs bounds", () => {
    expect(() => new WasmCelBackend({ timeoutMs: 0 })).toThrow();
    expect(() => new WasmCelBackend({ timeoutMs: -5 })).toThrow();
    expect(() => new WasmCelBackend({ timeoutMs: MAX_TIMEOUT_MS + 1 })).toThrow();
    // The factory forwards the same bounds (never masks them).
    expect(() => makeCelEvaluator({ timeoutMs: 0 })).toThrow(/positive integer/);
    expect(() => makeCelEvaluator({ timeoutMs: 1234 })).toThrow(
      /exceeds Relay cap/,
    );
  });

  test("a fast expression evaluates well within an explicit budget", async () => {
    // Worker thread cold-spawn under vitest takes longer than the default 50ms
    // budget on a quiet box; use the per-tenant cap (MAX_TIMEOUT_MS = 250 ms)
    // for this baseline so the assertion measures evaluator correctness, not
    // worker-spawn latency.
    ev = new WasmCelBackend({ timeoutMs: MAX_TIMEOUT_MS });
    const out = await ev.evaluate("1 + 2 * 3");
    expect(Number(out)).toBe(7);
  });
});
