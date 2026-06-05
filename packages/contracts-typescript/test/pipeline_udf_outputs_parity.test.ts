// VAL-CWC-P1HOST-019: pipeline.ts mirror reconstructs udf_outputs_jcs from the
// same wasm udf_trace, byte-identical to the Python host.
//
// The TS host (packages/contracts-typescript/src/pipeline.ts) loads the SAME
// signed .wasm the Python backend loads, drives a relay.* assertion through it,
// and reconstructs udf_outputs_jcs / udfs_invoked from the wasm udf_trace
// response field. Because BOTH hosts load the SAME wasm, the udf_trace payload
// is byte-identical across hosts by construction; the only remaining variable
// is whether the TS host encodes it to udf_outputs_jcs IDENTICALLY to Python.
//
// This test asserts the TS udf_outputs_jcs BYTES EQUAL the Python wasm-path
// golden (test/fixtures/udf_outputs_jcs.golden.json, generated from the REAL
// Python wasm pipeline by generate_udf_outputs_golden.py). Byte-identity here
// is keystone invariant #16 (a P0): the udf_outputs_jcs bytes feed a
// cryptographic digest, so any single-byte divergence is a release-block.
//
// The wasm artifact is the reproducible build.sh output at
// crate/target/wasm32-unknown-unknown/release/relay_cel_wasm.wasm (or CEL_WASM).
// If it is absent the suite fails loudly rather than skipping silently -- a
// silent skip would let a byte-divergence ship undetected.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";

import { evaluateUdfOutputs } from "../src/pipeline.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const GOLDEN_PATH = resolve(HERE, "fixtures", "udf_outputs_jcs.golden.json");

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

interface GoldenCase {
  label: string;
  expression: string;
  bindings: Record<string, unknown>;
  udf_outputs_jcs: string;
  udfs_invoked: string[];
  outcome: string;
}

interface Golden {
  engine: string;
  cases: GoldenCase[];
}

const golden = JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as Golden;

const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;
const wasmPresent = existsSync(wasmPath);

const TEXT = new TextDecoder();

describe("VAL-CWC-P1HOST-019: TS pipeline udf_outputs_jcs byte-equals the Python wasm golden", () => {
  beforeAll(() => {
    // Fail-loud if the wasm is missing: a silent skip would hide a byte
    // divergence (keystone invariant #16). The build.sh artifact is the
    // prerequisite; produce it via `make -C packages/cel-wasm build`.
    if (!wasmPresent) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip: a missing wasm would mask a cross-host byte " +
          "divergence (keystone invariant #16).",
      );
    }
    expect(golden.engine).toBe("wasm");
    expect(golden.cases.length).toBeGreaterThan(0);
  });

  for (const gc of golden.cases) {
    test(`${gc.label}: TS udf_outputs_jcs bytes equal the Python golden`, async () => {
      const result = await evaluateUdfOutputs(gc.expression, gc.bindings, {
        wasmPath,
      });

      // Byte-level equality: compare the UTF-8 bytes of the TS-emitted
      // udf_outputs_jcs against the Python golden bytes, NOT a structural
      // deep-equal. The digest consumes BYTES; structural equality could pass
      // while bytes diverge (key order, number formatting, whitespace).
      const tsBytes = result.udfOutputsJcsBytes;
      const goldenBytes = new TextEncoder().encode(gc.udf_outputs_jcs);

      expect(Array.from(tsBytes)).toEqual(Array.from(goldenBytes));
      // Also assert the decoded string matches (human-readable failure).
      expect(TEXT.decode(tsBytes)).toBe(gc.udf_outputs_jcs);

      // udfs_invoked derives from the udf_trace keys (sorted), matching the
      // Python contract's de-dup/order semantics.
      expect(result.udfsInvoked).toEqual(gc.udfs_invoked);
    });
  }
});
