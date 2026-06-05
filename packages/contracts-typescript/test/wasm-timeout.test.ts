// VAL-CWC-P2TSGATE-008: under Node, an evaluation that exceeds the configured
// wall-clock budget is hard-killed via a node:worker_threads Worker +
// worker.terminate() and surfaces RelayCelTimeoutError (RELAY-CEL-003 /
// RELAY-CEL-TIMEOUT-001). The timeout is HOST-enforced (the host guards stay
// host-side per the locked decision); the wasm itself is not asked to honor a
// budget.
//
// The Cloudflare path is documented as platform-CPU-limit-only until WS-J (no
// silent fallthrough) -- the backend selects the Node Worker timeout path under
// Node and an explicit documented branch otherwise.
//
// To force a budget-exceeding evaluation deterministically (without a slow CEL
// expression, which the wasm evaluates in microseconds), the backend accepts a
// `hangSentinel` construction option: when an evaluated expression equals the
// sentinel, the in-Worker runner deliberately blocks past the wall-clock budget
// so the host's worker.terminate() hard-kill path fires against a REAL Worker
// (not a mocked timer). The sentinel is OFF by default (undefined) so it adds no
// branch to the shipped evaluation path for any real expression.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

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

describe("VAL-CWC-P2TSGATE-008: per-runtime wall-clock timeout (Node Worker hard-kill)", () => {
  let backend: WasmCelBackend;

  beforeAll(() => {
    if (!existsSync(wasmPath)) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip.",
      );
    }
    backend = new WasmCelBackend({
      wasmPath,
      timeoutMs: 50,
      hangSentinel: "__RELAY_CEL_TEST_HANG__",
    });
  });

  afterAll(async () => {
    await backend.dispose();
  });

  test("a budget-exceeding evaluation under Node rejects with RelayCelTimeoutError (RELAY-CEL-003 / TIMEOUT-001)", async () => {
    // The hangSentinel is honored ONLY by the backend's Node-Worker runner and
    // ONLY when explicitly configured (this test): when the expression matches
    // the sentinel, the in-Worker evaluation deliberately blocks past the
    // wall-clock budget so the host's worker.terminate() path fires. This
    // exercises the REAL hard-kill machinery (a Worker is spawned and
    // terminated), not a mocked timer.
    let thrown: unknown;
    try {
      await backend.evaluate("__RELAY_CEL_TEST_HANG__");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(RelayCelTimeoutError);
    const err = thrown as RelayCelTimeoutError;
    expect(err.code).toBe(CODE_RELAY_CEL_003);
    expect(err.subtype).toBe(SUBTYPE_TIMEOUT);
  });

  test("after a timeout the backend recovers: the next evaluate() still works", async () => {
    // The timed-out Worker is terminated and quarantined; the next evaluate()
    // must spawn a fresh Worker and return the correct result (Store/Worker
    // quarantine across the terminate boundary).
    const v = await backend.evaluate("2 + 3");
    expect(v).toBe(5);
  });

  test("a normal evaluation under the budget does NOT time out", async () => {
    const v = await backend.evaluate("1 + 1");
    expect(v).toBe(2);
  });
});
