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

import { RelayCelError } from "../src/errors.js";
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

    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: budget,
      startupHangSentinel: true,
      onStartupWait: (startup) => {
        // Every eval awaiting the startup must await the SAME promise identity --
        // that is the precise property the fix relies on (a shared startup whose
        // rejection reaches all waiters). Assert it here so a regression that
        // gives each eval its OWN startup promise is caught.
        if (sharedStartup === null) {
          sharedStartup = startup;
        } else {
          expect(startup).toBe(sharedStartup);
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

    // Both evals reject (the shared startup never resolves; the first eval's
    // deadline fires and tears down the shared Worker, rejecting the shared
    // startup for BOTH waiters -- the second does NOT wait for its own timer).
    const results = await Promise.allSettled([first, second]);
    const [firstResult, secondResult] = results;

    expect(firstResult.status).toBe("rejected");
    if (firstResult.status === "rejected") {
      expect(firstResult.reason).toBeInstanceOf(RelayCelError);
    }
    expect(secondResult.status).toBe("rejected");
    if (secondResult.status === "rejected") {
      expect(secondResult.reason).toBeInstanceOf(RelayCelError);
    }
  });
});
