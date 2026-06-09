// roborev finding 6: evaluate() awaited ensureWorker() BEFORE installing the
// timeout, so a stalled Worker startup (loader import / RelayCel.load()) could
// hang the first eval forever past the wall-clock budget.
//
// The fix bounds the ENTIRE ensureWorker() + eval sequence with the timeout: a
// startup that never posts `ready` must still reject within the budget with
// RelayCelTimeoutError (RELAY-CEL-003 / TIMEOUT-001).
//
// To force a deterministic startup hang WITHOUT a real slow loader, the backend
// accepts a test-only `startupHangSentinel`: when set, the in-Worker startup
// busy-blocks before posting `ready`, so the host's bounded-startup gate is the
// only thing that can unblock the first evaluate(). OFF (undefined) in
// production -- it adds no branch to the shipped startup path.
//
// Tool: vitest. Evidence: vitest exit code + the caught timeout error + the
// wall-clock bound observed (reject within ~budget, not unbounded).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeAll, describe, expect, test } from "vitest";

import {
  CODE_RELAY_CEL_003,
  RelayCelTimeoutError,
  SUBTYPE_TIMEOUT,
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

describe("roborev finding 6: a hanging Worker startup still rejects within the budget", () => {
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

  test("a stalled startup rejects with RelayCelTimeoutError within ~the budget (not unbounded)", async () => {
    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: 200,
      startupHangSentinel: true,
    });
    const start = Date.now();
    let thrown: unknown;
    try {
      await backend.evaluate("1 + 1");
    } catch (e) {
      thrown = e;
    }
    const elapsed = Date.now() - start;
    expect(thrown).toBeInstanceOf(RelayCelTimeoutError);
    const err = thrown as RelayCelTimeoutError;
    expect(err.code).toBe(CODE_RELAY_CEL_003);
    expect(err.subtype).toBe(SUBTYPE_TIMEOUT);
    // The whole ensureWorker()+eval sequence is bounded: it must reject close to
    // the budget, NOT hang indefinitely. Allow generous slack for CI jitter
    // while still proving the bound is enforced (well under 5x the budget).
    expect(elapsed).toBeLessThan(200 * 5);
  });
});
