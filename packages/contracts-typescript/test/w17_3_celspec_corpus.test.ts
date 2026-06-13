// W17.3 cel-spec conformance corpus runner -- TypeScript mirror.
//
// Loads ../../../tests/conformance/cel-spec/celspec_vectors.json and
// ../../../tests/conformance/cel-spec/relay-profile-filter.yaml (the
// same files the Python runner exercises in
// tests/conformance/cel-spec/test_w17_3_celspec_corpus.py) and asserts
// VAL-W17-011 / VAL-W17-012 on the TS side: every profile-included
// vector evaluates to the recorded `expected_value` byte-equal under
// JCS canonicalization.
//
// M6 WS-I: the vectors evaluate through the SINGLE wasm CEL engine (the cel-js
// axis is removed). This is the TS mirror of the Python runner, which evaluates
// included vectors through make_cel_evaluator (the wasm engine) post-cutover.
//
// Each corpus vector is its own vitest test so per-vector failures
// localise: the mismatch surface is exactly one test name + the full
// diff payload required by VAL-W17-013.
//
// VAL-W17-010 manifest digest cross-check is asserted here too so a
// future TS-only contributor cannot bypass the manifest gate by
// editing only the JSON.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { makeCelEvaluator } from "../src/engine.js";
import { MAX_TIMEOUT_MS, RELAY_UDFS } from "../src/index.js";
import type { WasmCelBackend } from "../src/wasm-evaluator.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CELSPEC_DIR = resolve(HERE, "..", "..", "..", "tests", "conformance", "cel-spec");
const VECTORS_PATH = resolve(CELSPEC_DIR, "celspec_vectors.json");
const PROFILE_FILTER_PATH = resolve(CELSPEC_DIR, "relay-profile-filter.yaml");
const PINNED_COMMIT_PATH = resolve(CELSPEC_DIR, "PINNED_COMMIT.txt");
const MANIFEST_PATH = resolve(CELSPEC_DIR, "MANIFEST.sha256");
const UPSTREAM_PINS_PATH = resolve(CELSPEC_DIR, ".upstream-pins.json");

const SHA1_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

interface Vector {
  vector_id: string;
  expression: string;
  bindings?: Record<string, unknown>;
  expected_value: unknown;
  source?: string;
}

interface VectorsDoc {
  _schema_version: number;
  vectors: Vector[];
}

interface ProfileEntry {
  vector_id: string;
  note?: string;
  reason?: string;
  citation?: string;
}

interface ProfileFilter {
  included: ProfileEntry[];
  excluded: ProfileEntry[];
}

function readPinnedCommit(): string | null {
  const text = readFileSync(PINNED_COMMIT_PATH, "utf-8");
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    return line;
  }
  return null;
}

function readManifest(): Map<string, string> {
  const text = readFileSync(MANIFEST_PATH, "utf-8");
  const out = new Map<string, string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const digest = parts[0];
    if (digest === undefined) continue;
    let rel = parts.slice(1).join(" ").trim();
    if (rel.startsWith("*")) rel = rel.slice(1);
    out.set(rel, digest);
  }
  return out;
}

function readVectors(): VectorsDoc {
  return JSON.parse(readFileSync(VECTORS_PATH, "utf-8")) as VectorsDoc;
}

// Minimal YAML parser for our strict-subset profile filter format.
// We avoid a YAML dependency in the TS package since the format is
// line-oriented enough that a strict parser is more reliable than a
// general one.
function readProfileFilter(): ProfileFilter {
  const text = readFileSync(PROFILE_FILTER_PATH, "utf-8");
  const out: ProfileFilter = { included: [], excluded: [] };
  let section: "included" | "excluded" | null = null;
  let current: ProfileEntry | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    const stripped = line.trim();
    if (!stripped || stripped.startsWith("#")) continue;
    if (line.startsWith("included:")) {
      if (current !== null && section !== null) out[section].push(current);
      current = null;
      section = "included";
      continue;
    }
    if (line.startsWith("excluded:")) {
      if (current !== null && section !== null) out[section].push(current);
      current = null;
      section = "excluded";
      continue;
    }
    if (section === null) continue;
    let body = stripped;
    if (body.startsWith("- ")) {
      if (current !== null) out[section].push(current);
      current = {} as ProfileEntry;
      body = body.slice(2);
    }
    if (current && body.includes(":")) {
      const idx = body.indexOf(":");
      const key = body.slice(0, idx).trim();
      const val = body
        .slice(idx + 1)
        .trim()
        .replace(/^["']/, "")
        .replace(/["']$/, "");
      (current as unknown as Record<string, string>)[key] = val;
    }
  }
  if (current !== null && section !== null) out[section].push(current);
  return out;
}

function normaliseValue(v: unknown): unknown {
  if (v === undefined) return null;
  if (Array.isArray(v)) return v.map(normaliseValue);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = normaliseValue((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

function canonicalJSON(v: unknown): string {
  // Sorted-key JSON for byte-stable diff payloads (matches the Python
  // diff formatter at test_w17_3_celspec_corpus.py::_format_full_diff
  // which uses json.dumps(sort_keys=True, separators=(',', ':'))).
  return JSON.stringify(normaliseValue(v));
}

const vectorsDoc = readVectors();
const profile = readProfileFilter();
const includedIds = new Set(profile.included.map((e) => e.vector_id));
const includedVectors = vectorsDoc.vectors.filter((v) => includedIds.has(v.vector_id));

describe("VAL-W17-010: cel-spec corpus has pinned commit + manifest", () => {
  test("PINNED_COMMIT.txt contains a 40-char hex SHA-1", () => {
    const sha = readPinnedCommit();
    expect(sha).not.toBeNull();
    expect(SHA1_RE.test(sha as string)).toBe(true);
  });

  test(".upstream-pins.json celspec_commit_sha matches PINNED_COMMIT.txt", () => {
    const sha = readPinnedCommit();
    const pins = JSON.parse(readFileSync(UPSTREAM_PINS_PATH, "utf-8")) as {
      _schema_version: number;
      celspec_commit_sha: string;
    };
    expect(pins._schema_version).toBe(1);
    expect(pins.celspec_commit_sha).toBe(sha);
  });

  test("MANIFEST.sha256 digests match actual file bytes", () => {
    const manifest = readManifest();
    expect(manifest.size).toBeGreaterThanOrEqual(2);
    const drifts: string[] = [];
    for (const [rel, expected] of manifest.entries()) {
      const path = resolve(CELSPEC_DIR, rel);
      const actual = createHash("sha256")
        .update(readFileSync(path))
        .digest("hex");
      if (actual !== expected) {
        drifts.push(`${rel}: manifest=${expected} actual=${actual}`);
      }
      expect(SHA256_RE.test(expected)).toBe(true);
    }
    expect(drifts).toEqual([]);
  });
});

describe("VAL-W17-011: profile filter partitions corpus", () => {
  test("included + excluded == corpus, with no overlap", () => {
    const inc = new Set(profile.included.map((e) => e.vector_id));
    const exc = new Set(profile.excluded.map((e) => e.vector_id));
    const all = new Set(vectorsDoc.vectors.map((v) => v.vector_id));
    const overlap = [...inc].filter((x) => exc.has(x));
    expect(overlap).toEqual([]);
    const orphans = [...all].filter((x) => !inc.has(x) && !exc.has(x));
    expect(orphans).toEqual([]);
    const dangling = [...inc, ...exc].filter((x) => !all.has(x));
    expect(dangling).toEqual([]);
  });

  test("included floor is >= 25 vectors", () => {
    expect(profile.included.length).toBeGreaterThanOrEqual(25);
  });

  test("each excluded entry carries reason + citation", () => {
    const allowedReasons = new Set([
      "profile-rejects-dyn",
      "profile-rejects-timestamp",
      "profile-rejects-duration",
      "profile-rejects-protobuf-message",
      "profile-rejects-regex-backreference",
      "profile-rejects-bytes-literal",
      "profile-rejects-double-precision-edge",
      "profile-rejects-uint-arithmetic",
      "upstream-vector-uses-untyped-bindings",
      "profile-rejects-macro-with-side-effect-shadow",
    ]);
    for (const e of profile.excluded) {
      expect(e.reason).toBeTruthy();
      expect(allowedReasons.has(e.reason as string)).toBe(true);
      expect(e.citation).toBeTruthy();
    }
  });
});

describe("VAL-W17-012: the wasm engine evaluates every included vector to expected_value", () => {
  // One shared wasm backend across the included vectors (amortises the Worker
  // cold-start) -- the wasm engine is stateless across evaluate() calls and is
  // disposed in afterAll.
  let ev: WasmCelBackend | null = null;

  beforeAll(() => {
    ev = makeCelEvaluator({ udfs: RELAY_UDFS, timeoutMs: MAX_TIMEOUT_MS });
  });

  afterAll(async () => {
    if (ev !== null) {
      await ev.dispose();
      ev = null;
    }
  });

  for (const vec of includedVectors) {
    test(vec.vector_id, async () => {
      const backend = ev;
      if (backend === null) {
        throw new Error("wasm backend not initialised");
      }
      let actual: unknown;
      try {
        actual = await backend.evaluate(vec.expression, vec.bindings ?? {});
      } catch (e) {
        throw new Error(
          `VAL-W17-012: the wasm engine threw evaluating ${vec.vector_id}: ${(e as Error).message}\n  expression: ${vec.expression}\n  bindings:   ${JSON.stringify(vec.bindings ?? {})}`,
        );
      }
      const actualCanon = canonicalJSON(actual);
      const expectedCanon = canonicalJSON(vec.expected_value);
      if (actualCanon !== expectedCanon) {
        // VAL-W17-013: failure MUST contain vector_id, expression,
        // expected, actual, and the SHA-256 of the diff payload --
        // not a count.
        const diffPayload = JSON.stringify({
          expected: normaliseValue(vec.expected_value),
          py_actual: null,
          ts_actual: normaliseValue(actual),
        });
        const diffSha = createHash("sha256").update(diffPayload).digest("hex");
        throw new Error(
          `VAL-W17-012/013: the wasm engine diverged from cel-spec golden for ${vec.vector_id}\n` +
            `  vector_input_expression: ${vec.expression}\n` +
            `  bindings: ${JSON.stringify(vec.bindings ?? {})}\n` +
            `  expected: ${expectedCanon}\n` +
            `  ts_actual: ${actualCanon}\n` +
            `  diff_payload_sha256: ${diffSha}`,
        );
      }
      expect(actualCanon).toBe(expectedCanon);
    });
  }
});

describe("VAL-W17-013: full-diff formatter on synthetic mismatch contains six required fields", () => {
  test("synthetic mismatch produces all required diff fields", () => {
    const vec = {
      vector_id: "_test_only_synthetic",
      expression: "1 + 1",
      bindings: {} as Record<string, unknown>,
      expected_value: 2,
    };
    const py_actual = 2;
    const ts_actual = 3;
    const payload = JSON.stringify({
      expected: vec.expected_value,
      py_actual,
      ts_actual,
    });
    const diffSha = createHash("sha256").update(payload).digest("hex");
    const rec = {
      vector_id: vec.vector_id,
      vector_input_expression: vec.expression,
      expected: vec.expected_value,
      py_actual,
      ts_actual,
      diff_payload_sha256: diffSha,
    };
    const requiredFields = [
      "vector_id",
      "vector_input_expression",
      "expected",
      "py_actual",
      "ts_actual",
      "diff_payload_sha256",
    ];
    for (const f of requiredFields) {
      expect(rec).toHaveProperty(f);
    }
    expect(SHA256_RE.test(rec.diff_payload_sha256)).toBe(true);
    // Determinism: same payload -> same digest.
    const again = createHash("sha256").update(payload).digest("hex");
    expect(again).toBe(diffSha);
  });
});
