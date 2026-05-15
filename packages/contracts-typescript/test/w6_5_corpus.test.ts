// W6.5 -- Relay-CEL Conformance Corpus runner (TypeScript side).
//
// Loads ../../../tests/conformance/cel/relay_cel_corpus.json (the same
// file the Python runner exercises in
// packages/contracts/tests/test_w6_5_corpus.py) and asserts the
// cel-js evaluator produces JCS-canonical bytes byte-identical to the
// recorded ``py_jcs_b64`` for every ``eval_value`` and ``udf_value``
// case (VAL-W6-051), and that ``eval_error`` cases raise on the cel-js
// side (VAL-W6-051's both-runtimes-must-throw clause).
//
// Each corpus case is its own vitest test so per-case failures
// localise (mismatch surface = exactly one test name + payload diff).
//
// The corpus generator
// (scripts/generate-relay-cel-corpus.py) computes ``py_jcs_b64`` from
// the cel-python evaluator. This file's job is to prove cel-js
// agrees byte-for-byte.
//
// Tool: vitest. Runs in tier-2 smoke (npm test --workspaces). Idiom
// matrix and per-UDF-floor structure assertions live on the Python
// side in test_w6_5_corpus.py to avoid duplicating the truth.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import {
  jcsCanonicalize,
  RELAY_COVERAGE_NAME,
  RELAY_SCHEMA_MATCH_NAME,
  RELAY_TOOL_ARG_NAME,
  RelayCelEvaluator,
  relayCoverage,
  relaySchemaMatch,
  relayToolArg,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = resolve(
  HERE,
  "..",
  "..",
  "..",
  "tests",
  "conformance",
  "cel",
  "relay_cel_corpus.json",
);
const VENDOR_PATH = resolve(
  HERE,
  "..",
  "..",
  "..",
  "tests",
  "conformance",
  "cel",
  "vendor",
  "cel_spec_vectors.json",
);

interface EvalValueCase {
  id: string;
  kind: "eval_value";
  idiom: string;
  expression: string;
  bindings?: Record<string, unknown>;
  py_jcs_b64: string;
  edge_category?: string;
}

interface EvalErrorCase {
  id: string;
  kind: "eval_error";
  idiom: string;
  expression: string;
  bindings?: Record<string, unknown>;
}

interface UdfValueCase {
  id: string;
  kind: "udf_value";
  idiom: string;
  udf: string;
  args: unknown[];
  py_jcs_b64: string;
  edge_category?: string;
}

type CorpusCase = EvalValueCase | EvalErrorCase | UdfValueCase;

interface Corpus {
  schema_version: number;
  cases: CorpusCase[];
}

function loadCorpus(): Corpus {
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as Corpus;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
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
  throw new Error(`unknown UDF in corpus case: ${udf}`);
}

const corpus = loadCorpus();

describe("VAL-W6-050: corpus is well-formed", () => {
  test("schema_version is 1", () => {
    expect(corpus.schema_version).toBe(1);
  });

  test("corpus contains >= 200 cases", () => {
    expect(corpus.cases.length).toBeGreaterThanOrEqual(200);
  });

  test("all case ids are unique", () => {
    const ids = corpus.cases.map((c) => c.id);
    const seen = new Set<string>();
    const dupes: string[] = [];
    for (const id of ids) {
      if (seen.has(id)) dupes.push(id);
      seen.add(id);
    }
    expect(dupes).toEqual([]);
  });
});

describe("VAL-W6-051: cel-js eval_value bytes match cel-python golden", () => {
  // Use the cel-js parser-only path (parse + walk + evaluate) via the
  // public ``evaluate`` export from cel-js. The Relay profile checker
  // is exercised via RelayCelEvaluator separately; here we assert
  // raw byte-equality for the value-producing cases.
  //
  // Importing cel-js directly via ``evaluate`` keeps each parametrised
  // test cheap (no per-case worker spawn). The Relay profile rejects
  // dyn / timestamp / duration which appear ONLY in the eval_error
  // bucket below -- value cases never trip the profile.
  for (const c of corpus.cases) {
    if (c.kind !== "eval_value") continue;
    test(c.id, async () => {
      // Lazy-import cel-js for the same reason the Python side uses
      // a per-test evaluator: parametrised vitest tests run quickly
      // and we don't want to pay cel-js cold-import cost on every
      // case (the import is module-cached after the first test).
      const mod = await import("cel-js");
      const evaluate = mod.evaluate;
      let result: unknown;
      try {
        result = evaluate(c.expression, c.bindings ?? {}, {});
      } catch (e) {
        throw new Error(
          `VAL-W6-051: cel-js failed to evaluate eval_value case ${c.id}: ${(e as Error).message}\n  expression: ${c.expression}\n  bindings: ${JSON.stringify(c.bindings ?? {})}`,
        );
      }
      const tsBytes = jcsCanonicalize(result);
      const pyBytes = new Uint8Array(Buffer.from(c.py_jcs_b64, "base64"));
      const equal = bytesEqual(tsBytes, pyBytes);
      if (!equal) {
        const tsB64 = Buffer.from(tsBytes).toString("base64");
        throw new Error(
          `VAL-W6-051: cel-js bytes diverged from cel-python golden for case ${c.id}\n  expression: ${c.expression}\n  bindings:   ${JSON.stringify(c.bindings ?? {})}\n  py_b64: ${c.py_jcs_b64}\n  ts_b64: ${tsB64}\n  py_str: ${Buffer.from(pyBytes).toString("utf-8")}\n  ts_str: ${Buffer.from(tsBytes).toString("utf-8")}`,
        );
      }
      expect(equal).toBe(true);
    });
  }
});

describe("VAL-W6-051: cel-js eval_error cases throw", () => {
  // Use RelayCelEvaluator (which carries the Relay profile checker)
  // for these cases since some eval_error idioms (dyn / timestamp /
  // duration / regex backreferences) are caught by the Relay profile,
  // not by cel-js itself. Sharing one evaluator across tests keeps the
  // worker spawn cost amortised.
  const ev = new RelayCelEvaluator();
  for (const c of corpus.cases) {
    if (c.kind !== "eval_error") continue;
    test(c.id, () => {
      let raised = false;
      try {
        ev.evaluate(c.expression, c.bindings ?? {});
      } catch {
        raised = true;
      }
      if (!raised) {
        throw new Error(
          `VAL-W6-051: cel-js (with Relay profile) did NOT raise for eval_error case ${c.id}\n  expression: ${c.expression}\n  bindings:   ${JSON.stringify(c.bindings ?? {})}`,
        );
      }
      expect(raised).toBe(true);
    });
  }
});

describe("VAL-W6-051: cel-js udf_value direct-call bytes match cel-python golden", () => {
  for (const c of corpus.cases) {
    if (c.kind !== "udf_value") continue;
    test(c.id, () => {
      const result = applyUdf(c.udf, c.args);
      const tsBytes = jcsCanonicalize(result);
      const pyBytes = new Uint8Array(Buffer.from(c.py_jcs_b64, "base64"));
      const equal = bytesEqual(tsBytes, pyBytes);
      if (!equal) {
        const tsB64 = Buffer.from(tsBytes).toString("base64");
        throw new Error(
          `VAL-W6-051: TS UDF bytes diverged from Python golden for case ${c.id}\n  udf: ${c.udf}\n  args: ${JSON.stringify(c.args)}\n  py_b64: ${c.py_jcs_b64}\n  ts_b64: ${tsB64}`,
        );
      }
      expect(equal).toBe(true);
    });
  }
});

describe("VAL-W6-055: cel-spec drift -- vendored vectors resolve in corpus", () => {
  test("vendor file exists and has at least 10 vectors", () => {
    const vendor = JSON.parse(readFileSync(VENDOR_PATH, "utf-8")) as {
      _schema_version: number;
      vectors: Array<{
        vector_id: string;
        corpus_case_id: string;
      }>;
    };
    expect(vendor._schema_version).toBe(1);
    expect(vendor.vectors.length).toBeGreaterThanOrEqual(10);
  });

  test("every vendored corpus_case_id resolves to a real corpus case", () => {
    const vendor = JSON.parse(readFileSync(VENDOR_PATH, "utf-8")) as {
      vectors: Array<{
        vector_id: string;
        corpus_case_id: string;
      }>;
    };
    const ids = new Set<string>(corpus.cases.map((c) => c.id));
    const missing: string[] = [];
    for (const v of vendor.vectors) {
      if (!ids.has(v.corpus_case_id)) {
        missing.push(`${v.vector_id} -> ${v.corpus_case_id}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
