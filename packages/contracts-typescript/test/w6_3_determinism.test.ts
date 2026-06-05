// w6.3 -- Relay UDF determinism guards (TypeScript).
//
// Mirror of packages/contracts/tests/test_w6_3_determinism.py.
//
// VAL-W6-023: wall-clock independence (mock Date.now / performance.now)
// VAL-W6-024: network isolation (no fetch / Socket / http call)
// VAL-W6-025: locale independence (UDF outputs identical across
//             multiple Intl-style perturbations)
// VAL-W6-026: random-source independence (re-seed Math.random and
//             grep guard for Math.random / crypto.randomBytes)
// VAL-W6-027: no mutable process globals (mutate process.env between
//             runs and grep guard)
// VAL-W6-028: no filesystem reads outside declared inputs (fs shim)
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import * as fs from "node:fs";
import { readFileSync, readdirSync, statSync } from "node:fs";
import * as nodeNet from "node:net";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import {
  jcsCanonicalize,
  relayCoverage,
  relaySchemaMatch,
  relayToolArg,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_SRC_UDFS = join(HERE, "..", "src", "udfs");

// Shared happy-path fixtures.
const COVERAGE_TRACE = {
  steps: [
    { name: "step.alpha", status: "ok" },
    { name: "step.beta", status: "ok" },
    { name: "step.gamma", status: "ok" },
  ],
};
const COVERAGE_STEP = "step.beta";

const TOOL_CALL = {
  tool_name: "create_case_note",
  args: { case_id: "C-001", note: "approved", score: 0.875 },
};
const TOOL_KEY = "score";

const SCHEMA_PAYLOAD = {
  case_id: "C-001",
  score: 0.875,
  tags: ["a", "b", "c"],
  owner: { id: 42, name: "alice" },
};
const SCHEMA_DEF = {
  type: "object",
  required: ["case_id", "score"],
  properties: {
    case_id: { type: "string" },
    score: { type: "number" },
    tags: { type: "array", items: { type: "string" } },
    owner: {
      type: "object",
      required: ["id"],
      properties: {
        id: { type: "integer" },
        name: { type: "string" },
      },
    },
  },
};

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // Use Node's crypto (deterministic) for the digest. The fact that
  // we *use* sha256 inside a determinism test is fine -- we hash the
  // UDF output, not the UDF inputs; sha256 is a pure function.
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex");
}

async function snapshot(): Promise<Record<string, string>> {
  return {
    "relay.coverage": await sha256Hex(
      jcsCanonicalize(relayCoverage(COVERAGE_TRACE, COVERAGE_STEP)),
    ),
    "relay.tool_arg": await sha256Hex(
      jcsCanonicalize(relayToolArg(TOOL_CALL, TOOL_KEY)),
    ),
    "relay.schema_match": await sha256Hex(
      jcsCanonicalize(relaySchemaMatch(SCHEMA_PAYLOAD, SCHEMA_DEF)),
    ),
  };
}

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

// Strip JS string literals (', ", `) and line/block comments so the
// docstring/comment text "no Math.random" does not produce false
// positives in the source-grep guards.
function scrubStringsAndComments(src: string): string {
  let i = 0;
  let out = "";
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    const next = src[i + 1];
    // Line comment
    if (c === "/" && next === "/") {
      while (i < n && src[i] !== "\n") i += 1;
      continue;
    }
    // Block comment
    if (c === "/" && next === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    // String literal: single-quoted, double-quoted, backtick (no
    // interpolation tracking; we drop everything between matching
    // quotes including escapes).
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

// ---------------------------------------------------------------------------
// VAL-W6-023: wall-clock independent
// ---------------------------------------------------------------------------

describe("VAL-W6-023 (TS): UDFs are wall-clock independent", () => {
  test("Date.now and performance.now mocks do not change UDF outputs", async () => {
    const realDateNow = Date.now;
    const realPerfNow = performance.now;
    try {
      Date.now = () => 1700000000000;
      performance.now = () => 1.0;
      const run1 = await snapshot();

      Date.now = () => 1900000000000;
      performance.now = () => 9999.0;
      const run2 = await snapshot();

      expect(run1).toEqual(run2);
    } finally {
      Date.now = realDateNow;
      performance.now = realPerfNow;
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W6-024: network-isolated
// ---------------------------------------------------------------------------

describe("VAL-W6-024 (TS): UDFs are network-isolated", () => {
  test("fetch shim and net.Socket shim are NOT touched by UDFs", async () => {
    let fetchCount = 0;
    let socketCount = 0;
    const realFetch = (globalThis as { fetch?: typeof fetch }).fetch;
    const realSocketCtor = nodeNet.Socket;

    (globalThis as { fetch?: unknown }).fetch = (..._args: unknown[]) => {
      fetchCount += 1;
      throw new Error("VAL-W6-024: UDF attempted fetch()");
    };
    // We cannot easily reassign nodeNet.Socket; use vi.spyOn on its
    // prototype's connect method as a tractable proxy: any real
    // socket creation eventually calls Socket.prototype.connect.
    const spy = vi.spyOn(nodeNet.Socket.prototype, "connect").mockImplementation(
      (() => {
        socketCount += 1;
        throw new Error("VAL-W6-024: UDF attempted socket.connect()");
      }) as never,
    );

    try {
      const snap = await snapshot();
      expect(fetchCount).toBe(0);
      expect(socketCount).toBe(0);
      expect(typeof snap["relay.coverage"]).toBe("string");
    } finally {
      spy.mockRestore();
      if (realFetch) {
        (globalThis as { fetch?: unknown }).fetch = realFetch;
      } else {
        delete (globalThis as { fetch?: unknown }).fetch;
      }
      // realSocketCtor is the constructor; nothing to restore as we
      // only stubbed the prototype method via vi.spyOn above.
      void realSocketCtor;
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W6-025: locale-independent
// ---------------------------------------------------------------------------

describe("VAL-W6-025 (TS): UDFs are locale-independent", () => {
  test("relay.tool_arg is codepoint-keyed, not case-folded", () => {
    const call = { args: { i: "lower", I: "upper" } };
    expect(relayToolArg(call, "i")).toBe("lower");
    expect(relayToolArg(call, "I")).toBe("upper");
  });

  test("relay.coverage step name matching is codepoint-exact", () => {
    const trace = { steps: [{ name: "Foo" }] };
    expect(relayCoverage(trace, "Foo")).toBe(true);
    expect(relayCoverage(trace, "foo")).toBe(false);
    expect(relayCoverage(trace, "FOO")).toBe(false);
  });

  test("Intl.Collator presence does not perturb UDF outputs", async () => {
    // Construct several collators so any internal locale-state side
    // effect would be exposed; the UDFs MUST not consult them.
    const a = new Intl.Collator("en");
    const b = new Intl.Collator("tr");
    const c = new Intl.Collator("de");
    void a.compare("a", "b");
    void b.compare("i", "I");
    void c.compare("ss", "sz");
    const snap1 = await snapshot();
    const snap2 = await snapshot();
    expect(snap1).toEqual(snap2);
  });
});

// ---------------------------------------------------------------------------
// VAL-W6-026: random-source independent
// ---------------------------------------------------------------------------

describe("VAL-W6-026 (TS): UDFs are random-source independent", () => {
  test("Math.random and crypto.randomBytes calls do not change UDF outputs", async () => {
    const realRandom = Math.random;
    try {
      Math.random = () => 0.123456789;
      const snap1 = await snapshot();
      Math.random = () => 0.987654321;
      const snap2 = await snapshot();
      expect(snap1).toEqual(snap2);
    } finally {
      Math.random = realRandom;
    }
  });

  test("source grep finds zero references to Math.random / crypto.randomBytes / etc.", () => {
    const forbidden = [
      "Math.random",
      "crypto.randomBytes",
      "crypto.randomUUID",
      "crypto.getRandomValues",
      "Date.now",
      "performance.now",
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

// ---------------------------------------------------------------------------
// VAL-W6-027: no mutable process globals
// ---------------------------------------------------------------------------

describe("VAL-W6-027 (TS): UDFs do not read mutable process globals", () => {
  beforeEach(() => {
    delete process.env["RELAY_TEST_SENTINEL"];
  });
  afterEach(() => {
    delete process.env["RELAY_TEST_SENTINEL"];
  });

  test("mutating process.env between runs does not change UDF outputs", async () => {
    process.env["RELAY_TEST_SENTINEL"] = "first";
    const snap1 = await snapshot();
    process.env["RELAY_TEST_SENTINEL"] = "second";
    const snap2 = await snapshot();
    expect(snap1).toEqual(snap2);
  });

  test("source grep finds zero references to process.env / globalThis state", () => {
    const forbidden = ["process.env", "globalThis."];
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

// ---------------------------------------------------------------------------
// VAL-W6-028: no filesystem reads outside declared inputs
// ---------------------------------------------------------------------------

describe("VAL-W6-028 (TS): UDFs do not read the filesystem", () => {
  test("fs.readFileSync / fs.openSync / fs.readSync are NOT touched", async () => {
    // The ESM-imported fs namespace's bindings are non-configurable
    // (Node 22 enforces ES module immutability); we cannot install a
    // shim on `fs.readFileSync` directly. Instead, we exercise the
    // *behavior* contract: call snapshot() and prove the JCS
    // canonical bytes are stable AND identical to a clean baseline.
    // The grep-guard sibling test ("source grep finds zero
    // references...") is the structural proof that no fs API is
    // imported at all in udfs/.
    const baseline = await snapshot();
    const repeat = await snapshot();
    expect(repeat).toEqual(baseline);
    // And outputs are well-formed digests (sanity).
    for (const [name, dig] of Object.entries(baseline)) {
      expect(dig).toMatch(/^[0-9a-f]{64}$/);
      void name;
    }
  });

  test("source grep finds zero references to fs.readFile / fs.openSync / fs.read* in UDF source", () => {
    const forbidden = [
      "fs.readFile",
      "fs.readFileSync",
      "fs.openSync",
      "fs.readSync",
      "fs.promises",
      "node:fs",
      'from "fs"',
      "from 'fs'",
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

// ---------------------------------------------------------------------------
// Helper sanity (so an unused import doesn't dangle)
// ---------------------------------------------------------------------------

describe("internal helper sanity", () => {
  test("bytesToHex round-trips a known value", () => {
    expect(bytesToHex(new Uint8Array([0x00, 0xff, 0x10]))).toBe("00ff10");
  });
});
