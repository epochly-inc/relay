// W17.1 RFC 8785 JCS IETF conformance corpus (TS verifier).
//
// Cross-language parity: this test loads the SAME corpus file as the
// Python verifier (tests/conformance/jcs/rfc8785_ietf_corpus.json) and
// asserts that @epochly/relay-verifier's jcsCanonicalize produces
// byte-equal output for every value-kind case AND that the SHA-256
// digest matches the corpus golden. Combined with the Python-side
// test_w17_1_rfc8785_corpus.py, this enforces VAL-W17-001..005 plus
// VAL-W17-022 across both runtimes.
//
// VAL-W17-022 per-vector full diff: any byte mismatch reports the
// case name, expected vs actual bytes (UTF-8 + hex), and the first
// diverging byte index. No count-only summary.
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
  "rfc8785_ietf_corpus.json",
);
const PINS_PATH = resolve(
  REPO_ROOT,
  "tests",
  "conformance",
  "jcs",
  ".upstream-pins.json",
);

const SCHEMA_ID = "relay.conformance.jcs.ietf.v1";
const MIN_APPENDIX_B_CASES = 15;
const MIN_NFC_CASES = 10;
const MIN_NUM_EDGE_CASES = 10;
const MIN_SORT_UTF16_CASES = 6;
const HEX_64 = /^[0-9a-f]{64}$/;
const IETF_DATATRACKER_URL = "https://datatracker.ietf.org/doc/html/rfc8785";

interface ValueCase {
  name: string;
  kind: "value";
  category: string;
  input: unknown;
  expected_canonical_b64: string;
  expected_canonical_utf8: string;
  expected_sha256: string;
  notes?: string;
}

interface RejectCase {
  name: string;
  kind: "reject";
  reason: string;
}

interface Corpus {
  schema: string;
  source: { url: string; rfc: string };
  case_counts: Record<string, number>;
  cases: (ValueCase | RejectCase)[];
  reject_cases: RejectCase[];
}

interface Pins {
  source_url: string;
  rfc: string;
  transcript_sha256: string;
  transcript_byte_length: number;
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

function loadCorpus(): Corpus {
  if (!existsSync(CORPUS_PATH)) {
    throw new Error(
      `VAL-W17-001 corpus missing at ${CORPUS_PATH}; ` +
        "regenerate via scripts/generate-jcs-rfc8785-ietf-corpus.py.",
    );
  }
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as Corpus;
}

function loadPins(): Pins {
  if (!existsSync(PINS_PATH)) {
    throw new Error(
      `VAL-W17-001 pins missing at ${PINS_PATH}; ` +
        "regenerate via scripts/generate-jcs-rfc8785-ietf-corpus.py.",
    );
  }
  return JSON.parse(readFileSync(PINS_PATH, "utf-8")) as Pins;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function bytesToHex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

function bytesToUtf8(data: Uint8Array): string {
  return Buffer.from(data).toString("utf-8");
}

// VAL-W17-022: per-vector full diff formatter.
function formatDiff(
  caseName: string,
  caseCategory: string,
  expected: Uint8Array,
  actual: Uint8Array,
): string {
  const minLen = Math.min(expected.length, actual.length);
  let firstDiffIdx = -1;
  for (let i = 0; i < minLen; i++) {
    if (expected[i] !== actual[i]) {
      firstDiffIdx = i;
      break;
    }
  }
  if (firstDiffIdx === -1 && expected.length !== actual.length) {
    firstDiffIdx = minLen;
  }
  const lines = [
    "VAL-W17-022 per-vector diff:",
    `  case_name      = ${JSON.stringify(caseName)}`,
    `  category       = ${JSON.stringify(caseCategory)}`,
    `  expected_utf8  = ${JSON.stringify(bytesToUtf8(expected))}`,
    `  actual_utf8    = ${JSON.stringify(bytesToUtf8(actual))}`,
    `  expected_hex   = ${bytesToHex(expected)}`,
    `  actual_hex     = ${bytesToHex(actual)}`,
    `  expected_len   = ${expected.length}`,
    `  actual_len     = ${actual.length}`,
    `  first_diff_idx = ${firstDiffIdx}`,
  ];
  if (firstDiffIdx >= 0) {
    const e = firstDiffIdx < expected.length ? expected[firstDiffIdx] : null;
    const a = firstDiffIdx < actual.length ? actual[firstDiffIdx] : null;
    lines.push(`  first_diff_exp_byte = ${e} actual_byte = ${a}`);
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Schema + coverage shape
// ---------------------------------------------------------------------------

describe("VAL-W17-001: corpus schema and minimum coverage", () => {
  test("declares v1 schema id and per-category minimum case counts", () => {
    const corpus = loadCorpus();
    expect(corpus.schema).toBe(SCHEMA_ID);
    expect(corpus.case_counts["appendix_b"]).toBeGreaterThanOrEqual(
      MIN_APPENDIX_B_CASES,
    );
    expect(corpus.case_counts["nfc"]).toBeGreaterThanOrEqual(MIN_NFC_CASES);
    expect(corpus.case_counts["num_edge"]).toBeGreaterThanOrEqual(
      MIN_NUM_EDGE_CASES,
    );
    expect(corpus.case_counts["sort_utf16"]).toBeGreaterThanOrEqual(
      MIN_SORT_UTF16_CASES,
    );
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-001: IETF datatracker pin
// ---------------------------------------------------------------------------

describe("VAL-W17-001: corpus pinned to IETF datatracker", () => {
  test("pins file references IETF datatracker URL + SHA-256 transcript", () => {
    const pins = loadPins();
    expect(pins.source_url).toBe(IETF_DATATRACKER_URL);
    expect(pins.rfc).toBe("RFC 8785");
    expect(pins.transcript_sha256).toMatch(HEX_64);
    expect(pins.transcript_byte_length).toBeGreaterThan(0);
    const corpus = loadCorpus();
    expect(corpus.source.url).toBe(IETF_DATATRACKER_URL);
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-002: 100% pass on TS SDK JCS path
// ---------------------------------------------------------------------------

describe("VAL-W17-002: every vector canonicalizes byte-for-byte on TS path", () => {
  test("every value-kind case matches the corpus golden bytes", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    let passCount = 0;
    let expectedTotal = 0;
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      expectedTotal += 1;
      const v = c as ValueCase;
      const actual = jcsCanonicalize(v.input);
      const expected = b64ToBytes(v.expected_canonical_b64);
      if (!bytesEqual(actual, expected)) {
        failures.push(formatDiff(v.name, v.category, expected, actual));
        continue;
      }
      // Defence in depth: the UTF-8 string mirror MUST equal the bytes.
      const utf8Mirror = new TextEncoder().encode(v.expected_canonical_utf8);
      if (!bytesEqual(actual, utf8Mirror)) {
        failures.push(
          formatDiff(`${v.name} (utf8 mirror)`, v.category, utf8Mirror, actual),
        );
        continue;
      }
      passCount += 1;
    }
    if (failures.length > 0) {
      throw new Error(
        `VAL-W17-002: ${failures.length} vector(s) failed TS parity:\n\n` +
          failures.join("\n\n"),
      );
    }
    expect(passCount).toBe(expectedTotal);
  });

  test("SHA-256 digests match the corpus golden across Node runtime", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      const v = c as ValueCase;
      const actual = sha256Hex(jcsCanonicalize(v.input));
      if (actual !== v.expected_sha256) {
        failures.push(
          `${v.name}: expected=${v.expected_sha256} actual=${actual}`,
        );
      }
    }
    if (failures.length > 0) {
      throw new Error(
        `VAL-W17-002: SHA-256 drift on ${failures.length} case(s):\n  ` +
          failures.join("\n  "),
      );
    }
  });

  test("every digest is lowercase 64-char hex", () => {
    const corpus = loadCorpus();
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      expect((c as ValueCase).expected_sha256).toMatch(HEX_64);
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-003: UTF-8 NFC normalization
// ---------------------------------------------------------------------------

describe("VAL-W17-003: UTF-8 NFC normalization enforced", () => {
  test("NFC vector count meets floor", () => {
    const corpus = loadCorpus();
    const nfcCases = corpus.cases.filter(
      (c) => c.kind === "value" && (c as ValueCase).category === "nfc",
    );
    expect(nfcCases.length).toBeGreaterThanOrEqual(MIN_NFC_CASES);
  });

  test("decomposed string value canonicalizes to NFC form", () => {
    // 'e' + COMBINING ACUTE ACCENT (U+0301) -> NFC -> U+00E9
    const decomposed = "é";
    const precomposed = "é";
    const outD = jcsCanonicalize(decomposed);
    const outP = jcsCanonicalize(precomposed);
    expect(bytesEqual(outD, outP)).toBe(true);
    // U+00E9 -> UTF-8 bytes 0xC3 0xA9
    expect(Buffer.from(outD)).toEqual(Buffer.from('"é"', "utf-8"));
  });

  test("decomposed object key canonicalizes to NFC form", () => {
    const outD = jcsCanonicalize({ "é": 1 });
    const outP = jcsCanonicalize({ "é": 1 });
    expect(bytesEqual(outD, outP)).toBe(true);
  });

  test("canonical output is NFC-idempotent", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      const text = bytesToUtf8(jcsCanonicalize((c as ValueCase).input));
      if (text.normalize("NFC") !== text) {
        failures.push(`${c.name}: canonical output is NOT NFC-idempotent`);
      }
    }
    if (failures.length > 0) {
      throw new Error("VAL-W17-003: " + failures.join("; "));
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-004: numeric edge cases
// ---------------------------------------------------------------------------

describe("VAL-W17-004: numeric edge cases pass (RFC 8785 sec 3.2.2.3)", () => {
  test("num_edge vector count meets floor", () => {
    const corpus = loadCorpus();
    const nums = corpus.cases.filter(
      (c) => c.kind === "value" && (c as ValueCase).category === "num_edge",
    );
    expect(nums.length).toBeGreaterThanOrEqual(MIN_NUM_EDGE_CASES);
  });

  test("negative zero collapses to '0'", () => {
    expect(Buffer.from(jcsCanonicalize(-0))).toEqual(Buffer.from("0"));
    expect(Buffer.from(jcsCanonicalize(0))).toEqual(Buffer.from("0"));
  });

  test("1e-6 lower boundary emits decimal; just below emits exponential", () => {
    expect(Buffer.from(jcsCanonicalize(1e-6))).toEqual(Buffer.from("0.000001"));
    expect(Buffer.from(jcsCanonicalize(9.999999e-7))).toEqual(
      Buffer.from("9.999999e-7"),
    );
    expect(Buffer.from(jcsCanonicalize(1e-7))).toEqual(Buffer.from("1e-7"));
  });

  test("1e21 upper boundary emits exponential; just below emits decimal", () => {
    expect(Buffer.from(jcsCanonicalize(1e21))).toEqual(Buffer.from("1e+21"));
    expect(Buffer.from(jcsCanonicalize(1e20))).toEqual(
      Buffer.from("100000000000000000000"),
    );
  });

  test("max-safe-integer boundaries emit as plain decimal", () => {
    expect(Buffer.from(jcsCanonicalize(9007199254740991))).toEqual(
      Buffer.from("9007199254740991"),
    );
    expect(Buffer.from(jcsCanonicalize(-9007199254740991))).toEqual(
      Buffer.from("-9007199254740991"),
    );
  });

  test("smallest positive subnormal emits in exponential form", () => {
    expect(Buffer.from(jcsCanonicalize(5e-324))).toEqual(Buffer.from("5e-324"));
  });

  test("max finite double emits in exponential form", () => {
    expect(Buffer.from(jcsCanonicalize(1.7976931348623157e308))).toEqual(
      Buffer.from("1.7976931348623157e+308"),
    );
  });

  test("NaN / +Inf / -Inf rejected with JCSEncodeError", () => {
    expect(() => jcsCanonicalize(Number.NaN)).toThrow(JCSEncodeError);
    expect(() => jcsCanonicalize(Number.POSITIVE_INFINITY)).toThrow(
      JCSEncodeError,
    );
    expect(() => jcsCanonicalize(Number.NEGATIVE_INFINITY)).toThrow(
      JCSEncodeError,
    );
  });

  test("corpus reject_cases enumerate non-finite rejection", () => {
    const corpus = loadCorpus();
    const names = new Set(corpus.reject_cases.map((c) => c.name));
    expect(names.has("reject-nan")).toBe(true);
    expect(names.has("reject-positive-infinity")).toBe(true);
    expect(names.has("reject-negative-infinity")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-005: object-key sort order
// ---------------------------------------------------------------------------

describe("VAL-W17-005: object-key sort by UTF-16 code units (RFC 8785 sec 3.2.3)", () => {
  test("sort_utf16 vector count meets floor", () => {
    const corpus = loadCorpus();
    const sorts = corpus.cases.filter(
      (c) => c.kind === "value" && (c as ValueCase).category === "sort_utf16",
    );
    expect(sorts.length).toBeGreaterThanOrEqual(MIN_SORT_UTF16_CASES);
  });

  test("uppercase precedes lowercase by code unit", () => {
    const out = jcsCanonicalize({ b: 1, B: 2, a: 3, A: 4 });
    expect(Buffer.from(out)).toEqual(Buffer.from('{"A":4,"B":2,"a":3,"b":1}'));
  });

  test("cross-script BMP sort: Latin A < Greek A < Cyrillic A", () => {
    const out = jcsCanonicalize({
      A: "ascii",
      "А": "cyr", // U+0410 Cyrillic A
      "Α": "greek", // U+0391 Greek Alpha
    });
    const expected = new TextEncoder().encode(
      '{"A":"ascii","Α":"greek","А":"cyr"}',
    );
    expect(Buffer.from(out)).toEqual(Buffer.from(expected));
  });

  test("empty key sorts before non-empty keys", () => {
    const out = jcsCanonicalize({ a: 1, "": 2, b: 3 });
    expect(Buffer.from(out)).toEqual(Buffer.from('{"":2,"a":1,"b":3}'));
  });

  test("numeric-looking keys sort lexicographically not numerically", () => {
    const out = jcsCanonicalize({ "10": "ten", "2": "two", "1": "one" });
    expect(Buffer.from(out)).toEqual(
      Buffer.from('{"1":"one","10":"ten","2":"two"}'),
    );
  });

  test("every sort_utf16 corpus vector matches the pinned bytes", () => {
    const corpus = loadCorpus();
    const failures: string[] = [];
    for (const c of corpus.cases) {
      if (c.kind !== "value") continue;
      const v = c as ValueCase;
      if (v.category !== "sort_utf16") continue;
      const actual = jcsCanonicalize(v.input);
      const expected = b64ToBytes(v.expected_canonical_b64);
      if (!bytesEqual(actual, expected)) {
        failures.push(formatDiff(v.name, "sort_utf16", expected, actual));
      }
    }
    if (failures.length > 0) {
      throw new Error(
        `VAL-W17-005: ${failures.length} sort_utf16 failure(s):\n\n` +
          failures.join("\n\n"),
      );
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W17-022: per-vector full diff
// ---------------------------------------------------------------------------

describe("VAL-W17-022: per-vector full diff formatter", () => {
  test("formatDiff emits required fields", () => {
    const msg = formatDiff(
      "example-case",
      "appendix_b",
      new TextEncoder().encode('{"a":1}'),
      new TextEncoder().encode('{"a":2}'),
    );
    expect(msg).toContain("example-case");
    expect(msg).toContain("appendix_b");
    expect(msg).toContain("expected_utf8");
    expect(msg).toContain("actual_utf8");
    expect(msg).toContain("expected_hex");
    expect(msg).toContain("actual_hex");
    expect(msg).toContain("first_diff_idx");
    expect(msg).toContain("first_diff_idx = 5");
  });

  test("formatDiff handles length mismatch by reporting boundary index", () => {
    const msg = formatDiff(
      "length-diff",
      "appendix_b",
      new TextEncoder().encode('{"a":1}'),
      new TextEncoder().encode('{"a":1'),
    );
    expect(msg).toContain("first_diff_idx = 6");
  });
});

// ---------------------------------------------------------------------------
// Generator drift guard
// ---------------------------------------------------------------------------

describe("VAL-W17-001: corpus case-name uniqueness", () => {
  test("no duplicate case names in corpus", () => {
    const corpus = loadCorpus();
    const seen = new Set<string>();
    for (const c of corpus.cases) {
      expect(seen.has(c.name)).toBe(false);
      seen.add(c.name);
    }
  });
});
