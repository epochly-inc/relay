// W10.3 RFC 8785 JCS conformance corpus (TS verifier).
//
// Cross-language parity: this test loads the SAME corpus file as the
// Python verifier (tests/conformance/jcs/rfc8785_corpus.json) and
// asserts that `@epochly/relay-verifier`'s `jcsCanonicalize` produces
// byte-equal output for every value-kind case AND that the SHA-256
// digest matches the corpus golden. Combined with the Python-side
// test_w10_3_jcs_corpus.py, this enforces VAL-W10-016, -017, -018,
// -019 across both runtimes.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { JCSEncodeError, jcsCanonicalize } from "../src/index.js";

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

interface ValueCase {
  name: string;
  kind: "value";
  category: string;
  input: unknown;
  expected_canonical_b64: string;
  expected_canonical_utf8: string;
  expected_sha256: string;
}

interface BundleDigestCase {
  name: string;
  kind: "bundle_digest";
  input: unknown;
  strip_signatures: boolean;
  expected_canonical_b64: string;
  expected_canonical_utf8: string;
  expected_sha256: string;
}

type AnyCase = ValueCase | BundleDigestCase;

interface RejectCase {
  name: string;
  kind: "reject";
  reason: string;
}

interface Corpus {
  schema: string;
  cases: AnyCase[];
  reject_cases: RejectCase[];
}

function loadCorpus(): Corpus {
  if (!existsSync(CORPUS_PATH)) {
    throw new Error(
      `VAL-W10-016 corpus missing at ${CORPUS_PATH}; ` +
        "regenerate from the Python reference encoder.",
    );
  }
  const raw = readFileSync(CORPUS_PATH, "utf-8");
  return JSON.parse(raw) as Corpus;
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
// VAL-W10-016: corpus loads and reaches case-count threshold
// ---------------------------------------------------------------------------

describe("VAL-W10-016: RFC 8785 conformance corpus loads", () => {
  test("schema and minimum case count", () => {
    const corpus = loadCorpus();
    expect(corpus.schema).toBe("relay.conformance.jcs.v1");
    const valueCases = corpus.cases.filter((c) => c.kind === "value");
    expect(valueCases.length).toBeGreaterThanOrEqual(12);
  });

  test("every value case canonicalises byte-for-byte", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      const actual = jcsCanonicalize(c.input);
      const expected = b64ToBytes(c.expected_canonical_b64);
      if (!bytesEqual(actual, expected)) {
        failures.push(
          `${c.name}: actual=${JSON.stringify(Buffer.from(actual).toString("utf-8"))} ` +
            `expected=${JSON.stringify(Buffer.from(expected).toString("utf-8"))}`,
        );
      }
      // Cross-check: the corpus's UTF-8 string mirror MUST equal the
      // bytes when re-encoded. Catches editor-side normalisation.
      const utf8Encoded = new TextEncoder().encode(c.expected_canonical_utf8);
      if (!bytesEqual(actual, utf8Encoded)) {
        failures.push(`${c.name}: utf8-string mirror diverges from b64 bytes`);
      }
    }
    expect(failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// VAL-W10-017: numeric edge cases
// ---------------------------------------------------------------------------

describe("VAL-W10-017: numeric edge cases (IEEE 754 + negative zero)", () => {
  test("negative zero collapses to '0'", () => {
    expect(Buffer.from(jcsCanonicalize(-0))).toEqual(Buffer.from("0"));
    expect(Buffer.from(jcsCanonicalize(0))).toEqual(Buffer.from("0"));
  });

  test("whole-valued double emits without trailing .0", () => {
    expect(Buffer.from(jcsCanonicalize(1.0))).toEqual(Buffer.from("1"));
    expect(Buffer.from(jcsCanonicalize(2.0))).toEqual(Buffer.from("2"));
    expect(Buffer.from(jcsCanonicalize(-1.0))).toEqual(Buffer.from("-1"));
  });

  test("fractional double round-trips via String(n)", () => {
    expect(Buffer.from(jcsCanonicalize(0.5))).toEqual(Buffer.from("0.5"));
    expect(Buffer.from(jcsCanonicalize(-0.5))).toEqual(Buffer.from("-0.5"));
  });

  test("large decimal float emits decimal not scientific (1e10)", () => {
    expect(Buffer.from(jcsCanonicalize(1e10))).toEqual(
      Buffer.from("10000000000"),
    );
  });

  test("NaN rejected with JCSEncodeError", () => {
    expect(() => jcsCanonicalize(Number.NaN)).toThrow(JCSEncodeError);
  });

  test("+Infinity rejected with JCSEncodeError", () => {
    expect(() => jcsCanonicalize(Number.POSITIVE_INFINITY)).toThrow(
      JCSEncodeError,
    );
  });

  test("-Infinity rejected with JCSEncodeError", () => {
    expect(() => jcsCanonicalize(Number.NEGATIVE_INFINITY)).toThrow(
      JCSEncodeError,
    );
  });

  test("corpus reject_cases enumerate non-finite rejection", () => {
    const corpus = loadCorpus();
    const names = new Set(corpus.reject_cases.map((c) => c.name));
    expect(names.has("reject_nan")).toBe(true);
    expect(names.has("reject_positive_infinity")).toBe(true);
    expect(names.has("reject_negative_infinity")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VAL-W10-018: key ordering by UTF-16 code units
// ---------------------------------------------------------------------------

describe("VAL-W10-018: key ordering by UTF-16 code units", () => {
  test("ASCII 'A' (0x41) sorts before Cyrillic 'A' (0x410)", () => {
    const out = jcsCanonicalize({ A: "ascii", "А": "cyr" });
    const expected = new TextEncoder().encode('{"A":"ascii","А":"cyr"}');
    expect(Buffer.from(out)).toEqual(Buffer.from(expected));
  });

  test("uppercase precedes lowercase by code unit", () => {
    const out = jcsCanonicalize({ b: 1, B: 2, a: 3, A: 4 });
    expect(Buffer.from(out)).toEqual(
      Buffer.from('{"A":4,"B":2,"a":3,"b":1}'),
    );
  });

  test("corpus key_sort_utf16 vectors match", () => {
    const corpus = loadCorpus();
    const cases = corpus.cases.filter(
      (c) => c.kind === "value" && c.category === "key_sort_utf16",
    ) as ValueCase[];
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const actual = jcsCanonicalize(c.input);
      const expected = b64ToBytes(c.expected_canonical_b64);
      expect(bytesEqual(actual, expected)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W10-019: digest stability across runtime versions
// ---------------------------------------------------------------------------

describe("VAL-W10-019: digest stability across runtime versions", () => {
  test("every corpus digest is lowercase 64-char hex", () => {
    const corpus = loadCorpus();
    for (const c of corpus.cases) {
      expect(c.expected_sha256).toMatch(HEX_64);
    }
  });

  test("every value-case digest matches corpus golden (Node parity)", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      const actual = sha256Hex(jcsCanonicalize(c.input));
      if (actual !== c.expected_sha256) {
        failures.push(
          `${c.name}: expected=${c.expected_sha256} actual=${actual}`,
        );
      }
    }
    expect(failures).toEqual([]);
  });

  test("inline known digest is independent of corpus file", () => {
    const payload = { name: "relay", ok: true, count: 3, items: [1, 2, 3] };
    const canonical = jcsCanonicalize(payload);
    const expected = new TextEncoder().encode(
      '{"count":3,"items":[1,2,3],"name":"relay","ok":true}',
    );
    expect(bytesEqual(canonical, expected)).toBe(true);
    const digest = sha256Hex(canonical);
    const referenceDigest = sha256Hex(
      new TextEncoder().encode(
        '{"count":3,"items":[1,2,3],"name":"relay","ok":true}',
      ),
    );
    expect(digest).toBe(referenceDigest);
  });
});
