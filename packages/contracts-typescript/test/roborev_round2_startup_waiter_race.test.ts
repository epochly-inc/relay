// ROBOREV round-2 finding F (MED): concurrent evals awaiting the SAME hung Worker
// startup did not reject promptly when the shared startup timed out.
//
// runOnWorker inserts an eval into `pending` only AFTER ensureWorker() resolves.
// If multiple evals await the SAME hung startup (the shared workerReady promise
// never settles) and ONE eval's wall-clock timer fires, onTimeout calls
// failAllPending() + disposeWorker() -- but `pending` is EMPTY (no eval reached
// the post-ensureWorker() insertion), so the OTHER startup waiters are NOT
// rejected. They hang until their OWN later timers despite the shared Worker
// already being terminated.
//
// The fix rejects the shared startup promise for ALL waiters when the Worker is
// disposed due to a startup timeout, so every concurrent eval awaiting that
// startup rejects ON the teardown (~the first budget), not at its own later
// timer.
//
// ROBOREV round-3 finding D (LOW): the round-2 version of this test relied on a
// 90ms wall-clock sleep + tight elapsed-time bounds and did NOT prove the second
// evaluation had joined the SAME hung startup before the first timeout fired ->
// scheduler-sensitive on slow CI. This version uses a DETERMINISTIC BARRIER: the
// backend's `onStartupWait` hook fires (with the shared startup promise's
// identity) each time an eval begins awaiting the startup, so the test confirms
// BOTH evals are awaiting the SAME startup BEFORE any timeout path can fire. No
// wall-clock sleep gates the synchronization. The test still asserts both
// concurrent evals reject promptly on the shared-Worker teardown.
//
// Tool: vitest. Evidence: vitest exit code + the barrier confirming two waiters on
// one startup, both rejecting on the teardown.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeAll, describe, expect, test } from "vitest";

import {
  RelayCelEngineError,
  RelayCelError,
  RelayCelTimeoutError,
} from "../src/errors.js";
import { WasmCelBackend } from "../src/wasm-evaluator.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_WASM_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "crate",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "relay_cel_wasm.wasm",
);
const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;

describe("roborev finding F: concurrent evals on a hung startup BOTH reject on teardown", () => {
  let backend: WasmCelBackend | null = null;

  beforeAll(() => {
    if (!existsSync(wasmPath)) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip.",
      );
    }
  });

  afterEach(async () => {
    if (backend !== null) {
      await backend.dispose();
      backend = null;
    }
  });

  test("two evals awaiting the SAME hung startup BOTH reject on the teardown (deterministic barrier, no sleep)", async () => {
    // The Relay per-eval cap (MAX_TIMEOUT_MS = 250). The barrier (not the budget)
    // is what synchronizes the two waiters: both evals attach to the shared
    // startup SYNCHRONOUSLY in the same tick (the hook fires before any timer
    // can), so the budget is not raced against a stagger -- it only bounds how
    // long the (hung) startup is allowed to run before the deadline tears the
    // shared Worker down and rejects BOTH waiters.
    const budget = 250;

    // Resolves when TWO DISTINCT evals are awaiting the SAME shared startup
    // promise. The hook fires synchronously with the shared startup's identity;
    // we record each distinct waiter and resolve once the set contains both.
    let resolveBothWaiting!: () => void;
    const bothWaiting = new Promise<void>((r) => {
      resolveBothWaiting = r;
    });
    let waiterCount = 0;
    let sharedStartup: Promise<unknown> | null = null;
    // ROBOREV round-4 finding B1: an `expect()` thrown INSIDE onStartupWait is
    // SWALLOWED by the host (wasm-evaluator.ts wraps the hook call in a try/catch
    // so a test barrier hook can never break the eval path). So the prior
    // in-hook `expect(startup).toBe(sharedStartup)` did NOT bite -- a regression
    // that handed each eval its OWN startup promise was silently swallowed and the
    // test still passed. We instead RECORD the observed promise identities here
    // (no assertion inside the hook) and ASSERT after `await bothWaiting`, OUTSIDE
    // the swallowed hook, that both evals awaited the SAME startup.
    const observedStartups: Array<Promise<unknown>> = [];

    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: budget,
      startupHangSentinel: true,
      onStartupWait: (startup) => {
        // RECORD only -- never assert in here (the host swallows hook throws,
        // finding B1). The identity check runs after bothWaiting, in test scope.
        observedStartups.push(startup);
        if (sharedStartup === null) {
          sharedStartup = startup;
        }
        waiterCount += 1;
        if (waiterCount === 2) {
          resolveBothWaiting();
        }
      },
    });

    // Fire BOTH evals. Each synchronously arms its timer and attaches to the
    // shared (hung) startup, invoking the barrier hook. No stagger needed: the
    // barrier deterministically tells us when both are awaiting the same startup.
    const first = backend.evaluate("1 + 1");
    const second = backend.evaluate("2 + 2");

    // Deterministic synchronization: proceed only once BOTH evals are confirmed
    // awaiting the SAME startup. This replaces the round-2 wall-clock sleep.
    await bothWaiting;
    expect(waiterCount).toBe(2);

    // ROBOREV round-4 finding B1: assert the SHARED-startup property HERE, in test
    // scope, where an assertion actually bites (the in-hook version was swallowed
    // by the host). Both evals must have awaited the SAME startup promise identity
    // -- the precise property the fix relies on (a single shared startup whose
    // rejection reaches every waiter). A regression handing each eval its OWN
    // startup promise is caught here.
    expect(observedStartups).toHaveLength(2);
    expect(observedStartups[0]).toBe(observedStartups[1]);
    expect(observedStartups[1]).toBe(sharedStartup);

    // Both evals reject (the shared startup never resolves; the first eval's
    // deadline fires and tears down the shared Worker, rejecting the shared
    // startup for BOTH waiters -- the second does NOT wait for its own timer).
    const results = await Promise.allSettled([first, second]);
    const [firstResult, secondResult] = results;

    expect(firstResult.status).toBe("rejected");
    expect(secondResult.status).toBe("rejected");
    if (firstResult.status !== "rejected" || secondResult.status !== "rejected") {
      throw new Error("both evals must reject");
    }
    // Both rejections are RelayCelErrors (the closed error envelope contract).
    expect(firstResult.reason).toBeInstanceOf(RelayCelError);
    expect(secondResult.reason).toBeInstanceOf(RelayCelError);

    // ROBOREV round-4 finding B2: "both reject as RelayCelError" does NOT prove the
    // SECOND waiter was rejected by the shared-Worker TEARDOWN rather than by its
    // OWN later timer -- a RelayCelTimeoutError IS a RelayCelError, so a broken
    // impl that leaves the 2nd waiter to its own timeout (the very bug finding F
    // fixes) would still pass the weak check (both fire at ~the same budget).
    //
    // The two rejection paths are DISTINGUISHABLE by error CLASS / code:
    //   - SELF-TIMEOUT (a waiter's own deadline fires)  -> RelayCelTimeoutError
    //     (RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001), thrown at the timer callback.
    //   - SHARED TEARDOWN (disposeWorker rejects the shared startup for the OTHER
    //     waiters) -> RelayCelEngineError (RELAY-CEL-009 / RELAY-CEL-ENGINE-REQUEST),
    //     message "wasm Worker torn down before startup completed ...".
    //
    // Exactly ONE waiter's timer wins the race and tears the Worker down (that
    // waiter rejects with the TIMEOUT error); the OTHER waiter is rejected by that
    // teardown (the shared-startup rejection reaches its ensureWorker().catch as a
    // MICROTASK, which runs before its own timer MACROTASK) -- so it rejects with
    // the ENGINE teardown error, NOT a second timeout. We assert that split:
    // exactly one TIMEOUT + exactly one ENGINE teardown across the two rejections.
    // A regression where the 2nd waiter is left to its OWN timer would produce TWO
    // RelayCelTimeoutErrors (and ZERO teardown ENGINE errors) -- failing this.
    const reasons = [firstResult.reason, secondResult.reason];
    const timeoutRejections = reasons.filter(
      (r) => r instanceof RelayCelTimeoutError,
    );
    const teardownRejections = reasons.filter(
      (r) =>
        r instanceof RelayCelEngineError &&
        // The teardown path is RELAY-CEL-009 / ENGINE-REQUEST, NOT the timeout's
        // RELAY-CEL-003. (RelayCelTimeoutError is NOT a RelayCelEngineError, so
        // the instanceof already excludes the timeout; the code is the explicit
        // teardown discriminant.)
        (r as RelayCelEngineError).code === "RELAY-CEL-009",
    );
    // Exactly one of each: the winning timer (TIMEOUT) and the waiter it tore down
    // (ENGINE teardown). This is the proof that the second waiter did NOT reject
    // from its own timeout.
    expect(
      timeoutRejections,
      "exactly one waiter must reject from its OWN wall-clock timeout " +
        `(the timer that won the race); got ${timeoutRejections.length}`,
    ).toHaveLength(1);
    expect(
      teardownRejections,
      "exactly one waiter must reject from the SHARED-Worker TEARDOWN " +
        "(RELAY-CEL-009 / ENGINE-REQUEST), proving it was NOT left to its own " +
        `timeout; got ${teardownRejections.length}`,
    ).toHaveLength(1);
  });
});
