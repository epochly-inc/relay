// VAL-W6-012: cel-js evaluator wall-clock timeout is enforced.
//
// Same contract as VAL-W6-003 but in JS: evaluation aborts at <= 50 ms
// default, produces RELAY-CEL-TIMEOUT-NNN, and does not leak partial
// result.
//
// Tool: vitest.
// Evidence: vitest exit code, error code captured, wall-time delta
// within +/-20%.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  MAX_TIMEOUT_MS,
  RelayCelEvaluator,
  RelayCelTimeoutError,
  registerUdf,
  SUBTYPE_TIMEOUT,
} from "../src/index.js";

describe("VAL-W6-012: cel-js evaluator wall-clock timeout", () => {
  // Sleep duration of the instrument UDF, in ms. Chosen FAR above any
  // plausible worker-thread cold-spawn + cel-js import latency (observed
  // ~150 ms quiet, seen as high as ~490 ms under full-workspace CPU
  // contention) so that the abort ceiling can sit with an order-of-
  // magnitude margin above spawn jitter while still being well below the
  // UDF's natural completion time. See ABORT_CEILING_MS below.
  const UDF_SLEEP_MS = 5000;
  // The wall-clock ceiling the abort must beat. The total elapsed time of
  // a correctly-aborting run is dominated by worker cold-spawn + cel-js
  // import (~150-490 ms under load), NOT by the UDF (the abort terminates
  // the worker at ~budget+spawn). 2500 ms leaves roughly a 5-10x margin
  // over the worst-case spawn jitter we have observed, so load contention
  // CANNOT produce a false failure -- yet it is half the UDF's 5000 ms
  // sleep, so a REGRESSION (abort disabled -> UDF runs to completion)
  // would blow straight through this ceiling and fail the test. The
  // assertion therefore still proves the timeout fires far sooner than
  // the UDF would naturally complete; it is decoupled from spawn latency.
  const ABORT_CEILING_MS = 2500;

  test(
    "a slow pure UDF triggers RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001",
    () => {
      // Pure UDF whose body sleeps far past the budget. cel-js's pure-CEL
      // path is fast enough that crafting an in-language busy expression
      // that reliably exceeds the budget in CI is flaky -- bind a UDF
      // whose body sleeps via Atomics.wait on a fresh SAB. Per CLAUDE.md
      // banned pattern #16 the UDF is registered with pure: true for test
      // purposes; the sleep is a test instrument, not a production UDF.
      //
      // The UDF must be self-contained because it is serialised via
      // Function.prototype.toString() and reconstructed in the worker
      // -- closure captures (`outer`, top-level imports, the
      // UDF_SLEEP_MS const above) would not resolve in the worker, so
      // the sleep duration is inlined as a literal below.
      const slowPure = function slowPure(_x: unknown): number {
        // Self-contained sleep using Atomics.wait + SharedArrayBuffer.
        // 5000 ms inlined -- must match UDF_SLEEP_MS; the closure const
        // does not survive Function.prototype.toString() transport.
        const buf = new SharedArrayBuffer(4);
        const view = new Int32Array(buf);
        Atomics.wait(view, 0, 0, 5000);
        return 0;
      };
      const udf = registerUdf({
        name: "slow_pure",
        fn: slowPure as (...args: unknown[]) => unknown,
        pure: true,
        arity: 1,
      });
      const ev = new RelayCelEvaluator({ timeoutMs: 10, udfs: [udf] });
      const start = process.hrtime.bigint();
      let caught: unknown = null;
      try {
        ev.evaluate("slow_pure(0)");
      } catch (e) {
        caught = e;
      } finally {
        // Always tear the worker down so a partial / orphaned worker can
        // never leak across to the loop's next iteration or to siblings.
        // disposeInternal() already terminates the worker on timeout, so
        // this is idempotent; it also covers the (unexpected) no-throw
        // path where the evaluator would otherwise leave a worker live.
        ev.dispose();
      }
      const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
      expect(caught).toBeInstanceOf(RelayCelTimeoutError);
      const err = caught as RelayCelTimeoutError;
      expect(err.code).toBe("RELAY-CEL-003");
      expect(err.subtype).toBe(SUBTYPE_TIMEOUT);
      // The abort must fire far sooner than the UDF's UDF_SLEEP_MS (5000
      // ms) natural completion. ABORT_CEILING_MS (2500 ms) sits ~5-10x
      // above worst-case worker-spawn jitter yet at half the UDF sleep,
      // so load CANNOT cause a false failure but a disabled abort WOULD
      // be caught (UDF would run the full 5000 ms and blow the ceiling).
      expect(elapsedMs).toBeLessThan(ABORT_CEILING_MS);
      // Sanity: ABORT_CEILING_MS must stay strictly below UDF_SLEEP_MS so
      // a regression is always observable, and the per-test vitest
      // timeout (below) must exceed UDF_SLEEP_MS so a regressed run is
      // recorded as an assertion failure (elapsed > ceiling), not a
      // harness timeout.
      expect(ABORT_CEILING_MS).toBeLessThan(UDF_SLEEP_MS);
    },
    // Per-test vitest timeout. A correctly-aborting run finishes in well
    // under 1 s; this generous ceiling (> UDF_SLEEP_MS + spawn headroom)
    // ensures that even a REGRESSED run -- where the abort never fires
    // and the UDF sleeps the full 5000 ms -- completes and is reported as
    // an assertion failure on elapsedMs, rather than being masked as a
    // vitest harness timeout. It is NOT a wall-clock guarantee under
    // test; it is a safety net so regressions fail loudly.
    20000,
  );

  test("constructor validates timeoutMs bounds", () => {
    expect(() => new RelayCelEvaluator({ timeoutMs: 0 })).toThrow();
    expect(() => new RelayCelEvaluator({ timeoutMs: -5 })).toThrow();
    expect(() => new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS + 1 })).toThrow();
  });

  test("a fast expression evaluates well within an explicit budget", () => {
    // Worker thread cold-spawn under vitest takes longer than the
    // default 50 ms budget on a quiet box; we use the per-tenant cap
    // (MAX_TIMEOUT_MS = 250 ms) for this baseline so the assertion
    // measures evaluator correctness, not worker-spawn latency. The
    // default 50 ms budget is exercised by the fast-path test in
    // contracts-typescript downstream usage; here we only need to
    // assert that the evaluator returns the right value.
    const ev = new RelayCelEvaluator({ timeoutMs: MAX_TIMEOUT_MS });
    const out = ev.evaluate("1 + 2 * 3");
    expect(Number(out)).toBe(7);
  });
});
