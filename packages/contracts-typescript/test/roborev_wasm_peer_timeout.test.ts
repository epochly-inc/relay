// roborev finding 7: on a timeout, only the timed-out reqId was removed before
// disposeWorker() terminated the SHARED worker, leaving OTHER concurrent evals on
// that worker hanging until their own timers fired.
//
// The fix rejects all pending requests for the terminated worker (failAllPending
// / a failPendingExcept) with a clear "worker terminated" error BEFORE / as part
// of disposing it, so a peer eval whose Worker was hard-killed under it rejects
// promptly rather than waiting out its own full budget.
//
// Tool: vitest. Evidence: vitest exit code + both promises settle promptly (the
// timed-out one as RelayCelTimeoutError, the peer as a rejection that arrives
// well before its own budget would have elapsed).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeAll, describe, expect, test } from "vitest";

import { RelayCelError, RelayCelTimeoutError } from "../src/errors.js";
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

describe("roborev finding 7: a timeout rejects PEER pending requests promptly", () => {
  let backend: WasmCelBackend | null = null;

  beforeAll(() => {
    if (!existsSync(wasmPath)) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM).",
      );
    }
  });

  afterEach(async () => {
    if (backend !== null) {
      await backend.dispose();
      backend = null;
    }
  });

  test("when one eval times out and hard-kills the shared Worker, a concurrent peer eval rejects ON the kill (not at its own later timer)", async () => {
    const budget = 150;
    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: budget,
      hangSentinel: "__RELAY_CEL_TEST_HANG__",
    });

    // Kick off the hanging eval first so it occupies the Worker and its timer
    // (budget ms from t=0) fires, terminating the shared Worker at ~budget.
    const hangStart = Date.now();
    const hanging = backend.evaluate("__RELAY_CEL_TEST_HANG__");

    // Submit the peer LATER (after a stagger), so its OWN timer would fire at
    // (stagger + budget) -- strictly AFTER the hang's kill at (~budget). The
    // peer rides the SAME Worker and is mid-flight when that Worker is hard-
    // killed. The fix rejects the peer ON the kill (~budget from t=0); the
    // unfixed code only rejects it at its own later timer (~stagger + budget).
    const stagger = 80;
    await new Promise((r) => setTimeout(r, stagger));
    const peerSubmit = Date.now();
    const peer = backend.evaluate("2 + 2");

    const results = await Promise.allSettled([hanging, peer]);
    const peerSettled = Date.now();
    // Time from the hang's start to when the peer settled. If the peer was
    // rejected ON the kill it is ~budget; if it had to wait its own timer it is
    // ~stagger + budget.
    const peerElapsedFromHangStart = peerSettled - hangStart;
    // Time the peer itself was outstanding.
    const peerOutstanding = peerSettled - peerSubmit;

    const [hangingResult, peerResult] = results;
    // The hanging eval is the timeout.
    expect(hangingResult.status).toBe("rejected");
    if (hangingResult.status === "rejected") {
      expect(hangingResult.reason).toBeInstanceOf(RelayCelTimeoutError);
    }
    // The peer is rejected with a structured RelayCelError (its Worker was
    // terminated under it).
    expect(peerResult.status).toBe("rejected");
    if (peerResult.status === "rejected") {
      expect(peerResult.reason).toBeInstanceOf(RelayCelError);
    }
    // Discriminating bound: the peer must settle close to the KILL time
    // (~budget from the hang start), NOT at its own independent timer
    // (~stagger + budget). With the fix it rejects on the kill, so it is
    // outstanding for well under a full budget. Without the fix it waits its
    // own full budget (~budget) after being submitted.
    expect(peerElapsedFromHangStart).toBeLessThan(budget + stagger * 0.75);
    expect(peerOutstanding).toBeLessThan(budget * 0.9);
  });
});
