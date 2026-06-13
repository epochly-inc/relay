// W6.5 -- Relay-CEL Conformance Corpus runner (TypeScript side).
//
// Loads ../../../tests/conformance/cel/relay_cel_corpus.json (the same
// file the Python runner exercises in
// packages/contracts/tests/test_w6_5_corpus.py) and asserts the wasm-backed
// evaluator produces JCS-canonical bytes byte-identical to the recorded
// ``py_jcs_b64`` for every ``eval_value`` and ``udf_value`` case (VAL-W6-051),
// and that ``eval_error`` cases raise on the TS side (VAL-W6-051's
// both-runtimes-must-throw clause).
//
// M6 WS-I: the corpus value cases evaluate through the SINGLE wasm CEL engine
// (the cel-js axis is removed). EXACTLY TWO frozen eval_value cases record the
// REMOVED legacy engine's lenient (spec-INCORRECT) lexing of a backslash +
// non-ASCII digit string literal; the wasm correctly raises RELAY-CEL-009 /
// RELAY-CEL-ENGINE-COMPILE for them (a lexical error per the CEL spec). The
// per-case runner asserts the DOCUMENTED wasm behavior for those two ids --
// strongly guarded (the pinned expression must match) so a corpus edit or a
// wasm regression cannot hide behind the carve-out. Mirrors the Python
// adjudicated carve-out in test_w6_5_corpus.py.
//
// Each corpus case is its own vitest test so per-case failures
// localise (mismatch surface = exactly one test name + payload diff).
//
// The corpus generator (scripts/generate-relay-cel-corpus.py) computes
// ``py_jcs_b64`` from the cel-python evaluator. This file's job is to prove the
// wasm engine + the TS UDFs + the TS JCS encoder agree byte-for-byte.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import {
  jcsCanonicalize,
  MAX_TIMEOUT_MS,
  RELAY_COVERAGE_NAME,
  RELAY_SCHEMA_MATCH_NAME,
  RELAY_TOOL_ARG_NAME,
  RELAY_UDFS,
  RelayCelEngineError,
  relayCoverage,
  relaySchemaMatch,
  relayToolArg,
  SUBTYPE_ENGINE_COMPILE,
} from "../src/index.js";
import type { WasmCelBackend } from "../src/wasm-evaluator.js";

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

// M6 WS-I: the user-adjudicated legacy-lexer carve-out, mirrored from
// scripts/generate-relay-cel-corpus.py and the Python test_w6_5_corpus.py. The
// FROZEN golden records the REMOVED legacy engine's lenient lexing of a
// backslash + non-ASCII digit string literal; the wasm correctly raises
// RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE. The non-ASCII digit is built with
// String.fromCodePoint so this source stays pure ASCII (CLAUDE.md "ASCII-Safe
// Source"): each expression is a CEL string literal `"\<digit>"` -- a double
// quote, a backslash, the fullwidth (U+FF10) / Arabic-Indic (U+0660) zero, and
// a closing double quote.
const ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS: Record<string, string> = {
  regex_backslash_fullwidth_digit_accepted: `"\\${String.fromCodePoint(0xff10)}"`,
  regex_backslash_arabic_digit_accepted: `"\\${String.fromCodePoint(0x0660)}"`,
};

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

describe("VAL-W6-051: wasm-host eval_value bytes match cel-python golden", () => {
  // Each parametrised case constructs a fresh wasm backend so a hung/terminated
  // Worker never leaks across cases; it is disposed in afterEach.
  let ev: WasmCelBackend | null = null;

  afterEach(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  for (const c of corpus.cases) {
    if (c.kind !== "eval_value") continue;
    test(c.id, async () => {
      ev = makeCelEvaluator({ udfs: RELAY_UDFS, timeoutMs: MAX_TIMEOUT_MS });
      if (c.id in ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS) {
        // M6 WS-I adjudicated carve-out: the FROZEN golden records the removed
        // legacy engine's lenient lexing; the wasm correctly raises the
        // documented compile error. Assert the pinned expression AND the
        // documented structured error -- the case is still exercised, with the
        // spec-correct expectation.
        expect(c.expression).toBe(ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS[c.id]);
        let caught: unknown = null;
        try {
          await ev.evaluate(c.expression, c.bindings ?? {});
        } catch (e) {
          caught = e;
        }
        expect(caught).toBeInstanceOf(RelayCelEngineError);
        expect((caught as RelayCelEngineError).code).toBe("RELAY-CEL-009");
        expect((caught as RelayCelEngineError).subtype).toBe(
          SUBTYPE_ENGINE_COMPILE,
        );
        return;
      }
      let result: unknown;
      try {
        result = await ev.evaluate(c.expression, c.bindings ?? {});
      } catch (e) {
        throw new Error(
          `VAL-W6-051: wasm host failed to evaluate eval_value case ${c.id}: ${(e as Error).message}\n  expression: ${c.expression}\n  bindings: ${JSON.stringify(c.bindings ?? {})}`,
        );
      }
      const tsBytes = jcsCanonicalize(result);
      const pyBytes = new Uint8Array(Buffer.from(c.py_jcs_b64, "base64"));
      const equal = bytesEqual(tsBytes, pyBytes);
      if (!equal) {
        const tsB64 = Buffer.from(tsBytes).toString("base64");
        throw new Error(
          `VAL-W6-051: wasm-host bytes diverged from cel-python golden for case ${c.id}\n  expression: ${c.expression}\n  bindings:   ${JSON.stringify(c.bindings ?? {})}\n  py_b64: ${c.py_jcs_b64}\n  ts_b64: ${tsB64}\n  py_str: ${Buffer.from(pyBytes).toString("utf-8")}\n  ts_str: ${Buffer.from(tsBytes).toString("utf-8")}`,
        );
      }
      expect(equal).toBe(true);
    });
  }
});

describe("VAL-W6-051: wasm-host eval_error cases throw", () => {
  let ev: WasmCelBackend | null = null;

  afterEach(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  for (const c of corpus.cases) {
    if (c.kind !== "eval_error") continue;
    test(c.id, async () => {
      ev = makeCelEvaluator({ udfs: RELAY_UDFS, timeoutMs: MAX_TIMEOUT_MS });
      let raised = false;
      try {
        await ev.evaluate(c.expression, c.bindings ?? {});
      } catch {
        raised = true;
      }
      if (!raised) {
        throw new Error(
          `VAL-W6-051: the wasm host did NOT raise for eval_error case ${c.id}\n  expression: ${c.expression}\n  bindings:   ${JSON.stringify(c.bindings ?? {})}`,
        );
      }
      expect(raised).toBe(true);
    });
  }
});

describe("VAL-W6-051: udf_value direct-call bytes match cel-python golden", () => {
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
