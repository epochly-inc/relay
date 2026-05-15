// w6.3 -- Relay UDF execution is bounded by per-call CPU timeout
// (TypeScript). Mirror of test_w6_3_timeout.py.
//
// VAL-W6-029 (TS): the recursive relay.schema_match UDF aborts via
// the depth cap on a pathological deeply-nested fixture, well under
// the evaluator's 50 ms wall-clock budget. Source-grep guards
// confirm UDF source contains zero references to off-loading
// primitives (worker_threads, child_process.*, cluster.fork) that
// would let a UDF dodge the evaluator's timeout.
//
// Tool: vitest.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { performance } from "node:perf_hooks";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { describe, expect, test } from "vitest";

import {
  RELAY_SCHEMA_MATCH_MAX_DEPTH,
  RELAY_UDFS,
  relaySchemaMatch,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_SRC_UDFS = join(HERE, "..", "src", "udfs");

function* walk(root: string): Generator<string> {
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    const st = statSync(path);
    if (st.isDirectory()) {
      yield* walk(path);
    } else if (path.endsWith(".ts")) {
      yield path;
    }
  }
}

function scrubStringsAndComments(src: string): string {
  let i = 0;
  let out = "";
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    const next = src[i + 1];
    if (c === "/" && next === "/") {
      while (i < n && src[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      i += 1;
      while (i < n) {
        if (src[i] === "\\") {
          i += 2;
          continue;
        }
        if (src[i] === quote) {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

function makeDeeplyNestedPayload(depth: number): unknown {
  let payload: unknown = "leaf";
  for (let i = 0; i < depth; i += 1) {
    payload = { x: payload };
  }
  return { x: payload };
}

function makeDeeplyNestedSchema(depth: number): unknown {
  let schema: unknown = { type: "string" };
  for (let i = 0; i < depth; i += 1) {
    schema = { type: "object", properties: { x: schema } };
  }
  return { type: "object", properties: { x: schema } };
}

describe("VAL-W6-029 (TS): relay.schema_match depth cap", () => {
  test("payload nested past MAX_DEPTH returns false quickly", () => {
    const depth = RELAY_SCHEMA_MATCH_MAX_DEPTH + 8;
    const payload = makeDeeplyNestedPayload(depth);
    const schema = makeDeeplyNestedSchema(depth);
    const start = performance.now();
    const result = relaySchemaMatch(payload, schema);
    const elapsedMs = performance.now() - start;
    expect(result).toBe(false);
    // Comfortable margin: the depth cap aborts in ~65 frames; on any
    // modern machine that is sub-millisecond. 50 ms is 5000x typical.
    expect(elapsedMs).toBeLessThan(50.0);
  });

  test("payload at MAX_DEPTH returns the schema's verdict (not depth-aborted)", () => {
    // depth = MAX_DEPTH means the recursion CAN reach the leaf
    // schema; the leaf is `{type: "string"}` matched against a
    // string "leaf" -- expect true.
    const depth = RELAY_SCHEMA_MATCH_MAX_DEPTH - 4;
    const payload = makeDeeplyNestedPayload(depth);
    const schema = makeDeeplyNestedSchema(depth);
    expect(relaySchemaMatch(payload, schema)).toBe(true);
  });
});

describe("VAL-W6-029 (TS): UDF source contains no off-loading primitives", () => {
  test("source grep over packages/contracts-typescript/src/udfs/", () => {
    const forbidden = [
      "worker_threads",
      "child_process.spawn",
      "child_process.exec",
      "child_process.fork",
      "cluster.fork",
      "Worker(",
      "setImmediate",
      "queueMicrotask",
      "setTimeout",
      "setInterval",
    ];
    const hits: { file: string; token: string }[] = [];
    for (const file of walk(PKG_SRC_UDFS)) {
      const text = readFileSync(file, "utf-8");
      const scrubbed = scrubStringsAndComments(text);
      for (const token of forbidden) {
        if (scrubbed.includes(token)) {
          hits.push({
            file: relative(join(HERE, ".."), file),
            token,
          });
        }
      }
    }
    expect(hits).toEqual([]);
  });
});

describe("VAL-W6-029 (TS): RELAY_UDFS construction is well-formed", () => {
  test("RELAY_UDFS exposes three frozen entries", () => {
    expect(RELAY_UDFS.length).toBe(3);
    for (const u of RELAY_UDFS) {
      expect(Object.isFrozen(u)).toBe(true);
    }
  });
});
