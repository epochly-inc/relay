// w6.3 -- Cross-language parity for the three Relay UDFs.
//
// Loads tests/conformance/cel/relay_udfs_parity.json (seeded by the
// Python side at packages/contracts/tests/test_w6_3_behavior.py) and
// asserts byte-identical JCS canonical bytes from the cel-js mirror
// for every case. This is the W6.3 contribution to the Relay
// Conformance Corpus required by eng plan CQ1 line 147-150.
//
// Tool: vitest.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";

import {
  jcsCanonicalize,
  RELAY_COVERAGE_NAME,
  RELAY_SCHEMA_MATCH_NAME,
  RELAY_TOOL_ARG_NAME,
  relayCoverage,
  relaySchemaMatch,
  relayToolArg,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(
  HERE,
  "..",
  "..",
  "..",
  "tests",
  "conformance",
  "cel",
  "relay_udfs_parity.json",
);

interface ParityCase {
  udf: string;
  name: string;
  args: unknown[];
  py_jcs_b64: string;
}

interface ParityCorpus {
  version: number;
  cases: ParityCase[];
}

function loadCorpus(): ParityCorpus {
  const raw = readFileSync(CORPUS_PATH, "utf-8");
  return JSON.parse(raw) as ParityCorpus;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function applyUdf(udf: string, args: unknown[]): unknown {
  if (udf === RELAY_COVERAGE_NAME) {
    return relayCoverage(args[0], args[1]);
  }
  if (udf === RELAY_TOOL_ARG_NAME) {
    return relayToolArg(args[0], args[1]);
  }
  if (udf === RELAY_SCHEMA_MATCH_NAME) {
    return relaySchemaMatch(args[0], args[1]);
  }
  throw new Error(`unknown udf in corpus: ${udf}`);
}

describe("w6.3 cross-runtime parity corpus (relay_udfs_parity.json)", () => {
  const corpus = loadCorpus();

  test("corpus loaded with non-zero case count", () => {
    expect(corpus.version).toBe(1);
    expect(corpus.cases.length).toBeGreaterThan(0);
  });

  for (const c of corpus.cases) {
    test(`${c.udf} :: ${c.name} :: TS bytes match Python bytes`, () => {
      const tsValue = applyUdf(c.udf, c.args);
      const tsBytes = jcsCanonicalize(tsValue);
      const pyBytes = Buffer.from(c.py_jcs_b64, "base64");
      const equal = bytesEqual(tsBytes, new Uint8Array(pyBytes));
      if (!equal) {
        // Surface a useful diff for debugging.
        const tsB64 = Buffer.from(tsBytes).toString("base64");
        throw new Error(
          `parity mismatch for ${c.udf}::${c.name}\n` +
            `  args   = ${JSON.stringify(c.args)}\n` +
            `  py_b64 = ${c.py_jcs_b64}\n` +
            `  ts_b64 = ${tsB64}\n` +
            `  py_str = ${Buffer.from(pyBytes).toString("utf-8")}\n` +
            `  ts_str = ${Buffer.from(tsBytes).toString("utf-8")}`,
        );
      }
      expect(equal).toBe(true);
    });
  }
});
