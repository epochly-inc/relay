// P1 cross-runtime parity: TS verifier JCS encoder MUST reject non-BMP keys.
//
// RFC 8785 section 3.2.3 sorts object keys by UTF-16 code-unit sequence.
// Python sorts dict keys by codepoint; JS sorts object keys by UTF-16
// code unit. For Basic Multilingual Plane keys (< U+10000) these match.
// For supplementary-plane keys (>= U+10000) they diverge -- the same
// input produces DIFFERENT canonical bytes between runtimes, so a
// Python-signed evidence bundle with a non-BMP object key would verify
// on Python but be rejected as tampered on TypeScript (or vice versa),
// silently breaking cross-runtime signature verification (CLAUDE.md
// keystone invariant #11).
//
// Until both encoders implement the full UTF-16-code-unit sort, the
// verifier fails-closed: any object key with a codepoint >= U+10000
// throws JCSEncodeError whose message carries the wire-stable code
// RELAY-CANON-NON-BMP-KEY. Mirrors the Python verifier sibling test
// packages/verifier/tests/test_canonical_bmp_only_keys.py, which refuses
// the SAME input -- the two per-sibling tests together give cross-runtime
// parity (identical non-BMP key refused by BOTH runtimes).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import { JCSEncodeError, jcsCanonicalize } from "../src/index.js";

// U+1F600 (GRINNING FACE) is in the supplementary plane (>= U+10000).
// The Python verifier sibling rejects the SAME codepoint.
const SMP_CODEPOINT = 0x1f600;

describe("P1 parity: verifier JCS rejects non-BMP object keys (TS)", () => {
  test("rejects an object key containing a supplementary-plane codepoint", () => {
    const badKey = "a" + String.fromCodePoint(SMP_CODEPOINT);
    expect(() => jcsCanonicalize({ [badKey]: 1 })).toThrow(JCSEncodeError);
    try {
      jcsCanonicalize({ [badKey]: 1 });
    } catch (err) {
      expect((err as Error).message).toContain("RELAY-CANON-NON-BMP-KEY");
    }
  });

  test("BMP-only keys (including non-ASCII) still encode", () => {
    // U+00E9 (LATIN SMALL LETTER E WITH ACUTE) is in the BMP.
    const bmpKey = "caf" + String.fromCodePoint(0x00e9);
    const out = jcsCanonicalize({ [bmpKey]: 1 });
    expect(out).toBeInstanceOf(Uint8Array);
    const decoded = new TextDecoder().decode(out);
    expect(decoded).toContain("caf");
  });

  test("recursive: nested object keys are also screened", () => {
    const badKey = String.fromCodePoint(SMP_CODEPOINT) + "nested";
    const value = { outer: { [badKey]: 1 } };
    expect(() => jcsCanonicalize(value)).toThrow(JCSEncodeError);
  });

  test("supplementary-plane codepoint in a VALUE is allowed", () => {
    // Only KEYS are screened. A string value with U+1F600 must encode.
    const out = jcsCanonicalize({ emoji: String.fromCodePoint(SMP_CODEPOINT) });
    expect(out).toBeInstanceOf(Uint8Array);
  });
});
