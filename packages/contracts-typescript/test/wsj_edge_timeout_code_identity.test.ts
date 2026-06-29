// VAL-CWC-P7EDGE-007: fuel-derived edge timeout maps to the exact existing
// timeout envelope (TS <-> wasm timeout code identity).
//
// The Cloudflare-Workers / edge path obtains a structured timeout purely from
// the in-engine deterministic fuel counter: the wasm returns a
//   {ok:false, code:"RELAY-CEL-003", subtype:"RELAY-CEL-TIMEOUT-001"}
// envelope. The worker-thread (Node) path obtains the SAME timeout from a
// wall-clock worker.terminate() hard-kill, which throws a RelayCelTimeoutError
// (code RELAY-CEL-003, subtype RELAY-CEL-TIMEOUT-001; wasm-evaluator.ts:1256).
//
// The WS-C backend's `{ok:false}` envelope -> RelayCelError decode
// (`decodeWasmEnvelope`, wasm-evaluator.ts:803) is the single chokepoint that
// turns the raw edge envelope into a host error class (WasmCelBackend.evaluate
// routes through it at wasm-evaluator.ts:1181). It MUST map the RELAY-CEL-003 /
// RELAY-CEL-TIMEOUT-001 fuel-exhaustion envelope to a RelayCelTimeoutError --
// the SAME class + code + subtype the wall-clock path produces -- so a
// downstream caller cannot tell whether the timeout came from the in-engine
// fuel budget (edge) or the worker-thread wall-clock kill (Node). No new
// RELAY-CEL-NNN timeout code, no divergent subtype.
//
// This suite proves indistinguishability:
//   1. Drive a deterministically fuel-exhausting expression through the REAL
//      .mjs loader (the edge path: no worker_threads, no Worker.terminate) with
//      a small fuelBudget and assert the RAW envelope is
//      {ok:false, code:RELAY-CEL-003, subtype:RELAY-CEL-TIMEOUT-001}.
//   2. Pass that raw envelope through `decodeWasmEnvelope` and assert it throws
//      a RelayCelTimeoutError whose .code === CODE_RELAY_CEL_003 and
//      .subtype === SUBTYPE_TIMEOUT.
//   3. Construct a worker-thread RelayCelTimeoutError (the wall-clock class) and
//      assert the fuel-path error's .code / .subtype are STRICTLY EQUAL to it
//      -- proving the two paths are indistinguishable downstream.
//   4. Assert NO new timeout code/subtype was introduced: the timeout pair in
//      src/errors.ts is exactly {RELAY-CEL-003, RELAY-CEL-TIMEOUT-001}.
//
// Tool: vitest.
// Evidence: vitest exit code; the fuel envelope is byte-driven from the real
// wasm (not hand-built), the decode result class/code/subtype are captured, and
// the no-new-code grep over src/errors.ts is asserted.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";

import {
  CODE_RELAY_CEL_003,
  decodeWasmEnvelope,
  RelayCelTimeoutError,
  SUBTYPE_TIMEOUT,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// The reproducible build.sh wasm artifact. CEL_WASM overrides for CI layouts
// that vendor the wasm elsewhere; both hosts MUST load the SAME bytes.
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

// The sibling .mjs loader under test (the Workers/edge path). Two levels up
// under packages/cel-wasm/typescript/.
const LOADER_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "typescript",
  "relay-cel-wasm.mjs",
);

const ERRORS_TS_PATH = resolve(HERE, "..", "src", "errors.ts");

// A deterministically fuel-exhausting expression: a nested .map (25 inner
// multiplications) whose iteration count far exceeds a tiny budget. Same expr
// the Python and .mjs harnesses prove (wsj_edge_fuel_timeout.test.mjs:33).
const EXHAUSTING_EXPR = "[1,2,3,4,5].map(x, [1,2,3,4,5].map(y, x*y)).size()";
const SMALL_BUDGET = 8;

interface WasmEnvelope {
  ok: boolean;
  value?: { t: string; v?: unknown };
  error?: string;
  code?: string;
  subtype?: string;
}

interface EvalOptions {
  relayProfile?: boolean;
  container?: string;
  fuelBudget?: number;
}

interface RelayCelLoader {
  eval(
    expr: string,
    bindings?: Record<string, { t: string; v?: unknown }>,
    options?: EvalOptions,
  ): Promise<WasmEnvelope>;
}

interface RelayCelModule {
  RelayCel: {
    load(wasmPath?: string): Promise<RelayCelLoader>;
  };
}

const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;
const wasmPresent = existsSync(wasmPath);

let cel: RelayCelLoader;

describe("VAL-CWC-P7EDGE-007: fuel-path timeout == wall-clock timeout (code identity)", () => {
  beforeAll(async () => {
    // Fail-loud if the wasm is missing: a silent skip would hide whether the
    // fuel path produces the timeout envelope at all (keystone invariant #16).
    if (!wasmPresent) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip: a missing wasm would mask whether the fuel-derived " +
          "edge timeout maps to RelayCelTimeoutError (keystone invariant #16).",
      );
    }
    const mod = (await import(
      pathToFileURL(LOADER_PATH).href
    )) as unknown as RelayCelModule;
    cel = await mod.RelayCel.load(wasmPath);
  });

  test(
    "fuel-exhaustion envelope decodes to RelayCelTimeoutError, " +
      "code/subtype strictly equal to a wall-clock RelayCelTimeoutError",
    async () => {
      // (1) Drive the REAL edge/Workers path: the .mjs loader has no
      // worker_threads and no Worker.terminate (VAL-CWC-P7EDGE-006); the timeout
      // here is in-engine fuel only. Capture the RAW wasm envelope.
      const fuelEnvelope = await cel.eval(EXHAUSTING_EXPR, undefined, {
        fuelBudget: SMALL_BUDGET,
      });
      // Sanity: the wasm produced the structured fuel-exhaustion envelope (not a
      // value, not some other failure). This is the precise envelope shape the
      // decode must recognise as a timeout.
      expect(fuelEnvelope.ok).toBe(false);
      expect(fuelEnvelope.code).toBe("RELAY-CEL-003");
      expect(fuelEnvelope.subtype).toBe("RELAY-CEL-TIMEOUT-001");

      // (2) Run the raw edge envelope through the WS-C backend decode -- the same
      // function WasmCelBackend.evaluate() routes its envelope through
      // (wasm-evaluator.ts:1181). It MUST throw a RelayCelTimeoutError.
      let caught: unknown = null;
      try {
        decodeWasmEnvelope(fuelEnvelope);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(RelayCelTimeoutError);
      const fuelErr = caught as RelayCelTimeoutError;
      expect(fuelErr.code).toBe(CODE_RELAY_CEL_003);
      expect(fuelErr.subtype).toBe(SUBTYPE_TIMEOUT);

      // (3) The worker-thread (wall-clock) path throws this exact class
      // (wasm-evaluator.ts:1256). Construct one and assert STRICT equality of
      // the downstream-visible (code, subtype) pair -- the two timeout origins
      // are indistinguishable to a caller.
      const wallClockErr = new RelayCelTimeoutError(
        "Relay CEL wasm evaluation exceeded the wall-clock budget",
      );
      expect(fuelErr.code).toBe(wallClockErr.code);
      expect(fuelErr.subtype).toBe(wallClockErr.subtype);
      // Same class, not merely same code: instanceof identity both directions.
      expect(fuelErr).toBeInstanceOf(RelayCelTimeoutError);
      expect(wallClockErr).toBeInstanceOf(RelayCelTimeoutError);
      // Concrete literal pin (the canonical timeout pair).
      expect(fuelErr.code).toBe("RELAY-CEL-003");
      expect(fuelErr.subtype).toBe("RELAY-CEL-TIMEOUT-001");
    },
    20000,
  );

  test("no new RELAY-CEL-NNN timeout code/subtype was introduced", () => {
    // Lock the timeout identity at the definition: SUBTYPE_TIMEOUT and
    // CODE_RELAY_CEL_003 are the canonical pair; the RelayCelTimeoutError class
    // binds exactly those. A divergent timeout code/subtype (a new
    // RELAY-CEL-NNN constant feeding RelayCelTimeoutError, or a second timeout
    // subtype) would break indistinguishability and is forbidden by VAL-007.
    expect(CODE_RELAY_CEL_003).toBe("RELAY-CEL-003");
    expect(SUBTYPE_TIMEOUT).toBe("RELAY-CEL-TIMEOUT-001");

    const src = readFileSync(ERRORS_TS_PATH, "utf8");

    // Exactly one timeout subtype token is DEFINED in errors.ts. A second
    // `RELAY-CEL-TIMEOUT-` token (e.g. RELAY-CEL-TIMEOUT-002) would be a
    // divergent timeout subtype.
    const timeoutSubtypeTokens = src.match(/RELAY-CEL-TIMEOUT-\d+/g) ?? [];
    const uniqueTimeoutSubtypes = [...new Set(timeoutSubtypeTokens)];
    expect(uniqueTimeoutSubtypes).toEqual(["RELAY-CEL-TIMEOUT-001"]);

    // The RelayCelTimeoutError constructor binds exactly the canonical pair
    // (CODE_RELAY_CEL_003, SUBTYPE_TIMEOUT). Assert the source still wires those
    // two constants into it and introduces no alternate timeout code constant.
    const ctorMatch = src.match(
      /class RelayCelTimeoutError extends RelayCelError \{[\s\S]*?\n\}/,
    );
    expect(ctorMatch).not.toBeNull();
    const ctorBody = ctorMatch?.[0] ?? "";
    expect(ctorBody).toContain("CODE_RELAY_CEL_003");
    expect(ctorBody).toContain("SUBTYPE_TIMEOUT");
    // No alternate timeout code constant feeding the timeout class.
    expect(ctorBody).not.toContain("CODE_RELAY_CEL_008");
    expect(ctorBody).not.toMatch(/RELAY-CEL-TIMEOUT-(?!001\b)\d+/);
  });
});
