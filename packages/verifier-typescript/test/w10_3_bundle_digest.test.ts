// W10.3 bundle-digest tests (TS verifier mirror).
//
// Asserts that `@epochly/relay-verifier`'s `bundleDigest` computes
// `sha256(jcsCanonicalize(claim_payload_without_signatures)).hex` per
// spec section K line 4390 and matches the Python verifier's
// `bundle_digest` byte-for-byte. Combined with
// packages/verifier/tests/test_w10_3_bundle_digest.py this enforces
// VAL-W10-020 cross-runtime.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { bundleDigest, jcsCanonicalize } from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = resolve(__dirname, "..");
const REPO_ROOT = resolve(PKG_ROOT, "..", "..");
const CORPUS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "jcs",
  "rfc8785_corpus.json",
);

interface BundleDigestCase {
  name: string;
  kind: "bundle_digest";
  input: unknown;
  strip_signatures: boolean;
  expected_canonical_b64: string;
  expected_canonical_utf8: string;
  expected_sha256: string;
}

interface ValueCase {
  name: string;
  kind: "value";
  category: string;
  input: unknown;
  expected_canonical_b64: string;
  expected_canonical_utf8: string;
  expected_sha256: string;
}

type AnyCase = ValueCase | BundleDigestCase;

interface Corpus {
  schema: string;
  cases: AnyCase[];
}

function loadCorpus(): Corpus {
  if (!existsSync(CORPUS_PATH)) {
    throw new Error(`VAL-W10-020 corpus missing at ${CORPUS_PATH}`);
  }
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as Corpus;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

const HEX_64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// VAL-W10-020: bundle digest computed correctly from canonical claims
// ---------------------------------------------------------------------------

describe("VAL-W10-020: bundle digest computed correctly from canonical claims", () => {
  test("strips top-level signatures field by default", () => {
    const payload = { kid: "k1", data: { a: 1, b: 2 } };
    const withSigs = { ...payload, signatures: [{ alg: "EdDSA", sig: "xxx" }] };
    expect(bundleDigest(payload)).toBe(bundleDigest(withSigs));
  });

  test("includes signatures when strip disabled", () => {
    const payload = { kid: "k1", data: { a: 1 } };
    const withSigs = { ...payload, signatures: [{ alg: "EdDSA", sig: "xxx" }] };
    expect(bundleDigest(payload, { stripSignatures: false })).not.toBe(
      bundleDigest(withSigs, { stripSignatures: false }),
    );
  });

  test("equals sha256 of jcsCanonicalize bytes", () => {
    const payload = { a: 1, b: 2 };
    const expected = sha256Hex(jcsCanonicalize(payload));
    expect(bundleDigest(payload)).toBe(expected);
  });

  test("returns lowercase hex 64 chars", () => {
    expect(bundleDigest({ a: 1 })).toMatch(HEX_64);
  });

  test("corpus bundle_digest cases round-trip", () => {
    const corpus = loadCorpus();
    const cases = corpus.cases.filter(
      (c): c is BundleDigestCase => c.kind === "bundle_digest",
    );
    expect(cases.length).toBeGreaterThan(0);
    const failures: string[] = [];
    for (const c of cases) {
      const actualDigest = bundleDigest(c.input, {
        stripSignatures: c.strip_signatures,
      });
      if (actualDigest !== c.expected_sha256) {
        failures.push(
          `${c.name}: expected=${c.expected_sha256} actual=${actualDigest}`,
        );
      }
      // Cross-check canonical bytes too.
      let payload: unknown = c.input;
      if (
        c.strip_signatures &&
        c.input !== null &&
        typeof c.input === "object" &&
        !Array.isArray(c.input) &&
        Object.prototype.hasOwnProperty.call(c.input, "signatures")
      ) {
        const obj = c.input as Record<string, unknown>;
        const stripped: Record<string, unknown> = {};
        for (const k of Object.keys(obj)) {
          if (k !== "signatures") {
            stripped[k] = obj[k];
          }
        }
        payload = stripped;
      }
      const actualBytes = jcsCanonicalize(payload);
      const expectedBytes = b64ToBytes(c.expected_canonical_b64);
      if (!bytesEqual(actualBytes, expectedBytes)) {
        failures.push(`${c.name}: canonical-bytes mismatch`);
      }
    }
    expect(failures).toEqual([]);
  });

  test("changes when any byte of the payload changes", () => {
    const base = { claim_id: "c1", value: 100 };
    const baseDigest = bundleDigest(base);
    expect(bundleDigest({ claim_id: "c1", value: 101 })).not.toBe(baseDigest);
    expect(bundleDigest({ claim_id: "c2", value: 100 })).not.toBe(baseDigest);
    expect(bundleDigest({ claim_id: "c1", value: 100, extra: true })).not.toBe(
      baseDigest,
    );
    expect(bundleDigest({ claim_id: "c1" })).not.toBe(baseDigest);
  });

  test("stable across key insertion order", () => {
    const a = { a: 1, b: 2, c: 3 };
    const b = { c: 3, b: 2, a: 1 };
    const d: Record<string, number> = {};
    d["b"] = 2;
    d["a"] = 1;
    d["c"] = 3;
    expect(bundleDigest(a)).toBe(bundleDigest(b));
    expect(bundleDigest(a)).toBe(bundleDigest(d));
  });

  test("artifact digest round-trips and tamper breaks the binding", () => {
    const artifact = { kind: "log_excerpt", lines: ["a", "b", "c"] };
    const declared = sha256Hex(jcsCanonicalize(artifact));
    expect(bundleDigest(artifact, { stripSignatures: false })).toBe(declared);
    const tampered = { kind: "log_excerpt", lines: ["a", "b", "X"] };
    expect(bundleDigest(tampered, { stripSignatures: false })).not.toBe(
      declared,
    );
  });

  test("non-dict value digests as-is", () => {
    const arr = [1, 2, 3];
    const expected = sha256Hex(jcsCanonicalize(arr));
    expect(bundleDigest(arr)).toBe(expected);
    expect(bundleDigest(arr, { stripSignatures: false })).toBe(expected);
  });
});
