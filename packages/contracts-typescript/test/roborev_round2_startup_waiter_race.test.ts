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
// Tool: vitest. Evidence: vitest exit code + both promises settle promptly (the
// second eval, submitted after a stagger, must settle close to the FIRST eval's
// budget, NOT at its own independent timer).
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

describe("roborev round-2 finding F: concurrent evals on a hung startup BOTH reject on teardown", () => {
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

  test("a second eval awaiting a hung startup rejects ON the first eval's teardown, not at its own later timer", async () => {
    const budget = 200;
    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: budget,
      startupHangSentinel: true,
    });

    // First eval: occupies the shared (hung) startup; its timer fires at ~budget
    // and disposes the Worker.
    const t0 = Date.now();
    const first = backend.evaluate("1 + 1");

    // Second eval: submitted after a stagger, awaits the SAME hung startup
    // promise (ensureWorker() returns the same pending workerReady). Its OWN
    // timer would fire at (stagger + budget) -- strictly AFTER the first eval's
    // teardown at ~budget. The fix must reject it ON the teardown, not at its
    // own timer.
    const stagger = 90;
    await new Promise((r) => setTimeout(r, stagger));
    const secondSubmit = Date.now();
    const second = backend.evaluate("2 + 2");

    const results = await Promise.allSettled([first, second]);
    const settledAt = Date.now();

    const [firstResult, secondResult] = results;
    // Both reject with a structured RelayCelError.
    expect(firstResult.status).toBe("rejected");
    if (firstResult.status === "rejected") {
      expect(firstResult.reason).toBeInstanceOf(RelayCelError);
    }
    expect(secondResult.status).toBe("rejected");
    if (secondResult.status === "rejected") {
      expect(secondResult.reason).toBeInstanceOf(RelayCelError);
    }

    // The discriminating bound: the second eval must settle close to the FIRST
    // eval's teardown (~budget from t0), NOT at its own independent timer
    // (~stagger + budget). With the fix it rejects on the teardown, so it is
    // outstanding for well under its own full budget.
    const secondElapsedFromT0 = settledAt - t0;
    const secondOutstanding = settledAt - secondSubmit;
    expect(secondElapsedFromT0).toBeLessThan(budget + stagger * 0.75);
    expect(secondOutstanding).toBeLessThan(budget * 0.9);
  });
});
