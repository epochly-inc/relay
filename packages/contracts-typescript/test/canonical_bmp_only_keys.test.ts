// VAL-V3M5-006 (V3 audit-resolution m5-f02): TypeScript JCS encoder MUST
// reject non-BMP object keys with CanonicalEncodingError. This file is
// the canonical evidence anchor for the assertion.
//
// Round-3 P1 fix #5: TypeScript JCS encoder MUST reject non-BMP object keys.
//
// Python sorts dict keys by codepoint; JS sorts object keys by UTF-16
// code unit. For Basic Multilingual Plane keys (< U+10000) these
// orderings match. For supplementary-plane keys (>= U+10000) they
// diverge -- the same input produces DIFFERENT canonical bytes between
// runtimes, silently breaking cross-runtime signature verification
// (CLAUDE.md keystone invariant #11: trust anchor / cross-runtime byte
// equality).
//
// Until both encoders implement the full UTF-16-code-unit sort
// algorithm with identical semantics, both runtimes fail-closed on
// supplementary-plane KEYS. Values may contain supplementary-plane
// characters; only keys are sorted.
//
// Mirror of packages/contracts/tests/test_canonical_bmp_only_keys.py.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";

import {
  CanonicalEncodingError,
  jcsCanonicalize,
} from "../src/canonical.js";

describe("VAL-V3M5-006 / Round-3 P1 fix #5: BMP-only object keys (TS mirror)", () => {
  test("rejects an object key containing a supplementary-plane codepoint", () => {
    // U+1F600 (GRINNING FACE) is in the supplementary plane.
    const badKey = "a" + String.fromCodePoint(0x1f600);
    expect(() => jcsCanonicalize({ [badKey]: 1 })).toThrow(
      CanonicalEncodingError,
    );
    try {
      jcsCanonicalize({ [badKey]: 1 });
    } catch (err) {
      expect((err as CanonicalEncodingError).code).toBe(
        "RELAY-CANON-NON-BMP-KEY",
      );
    }
  });

  test("BMP-only keys (including non-ASCII) still encode", () => {
    // U+00E9 (LATIN SMALL LETTER E WITH ACUTE) is in the BMP.
    const bmpKey = "caf" + String.fromCodePoint(0x00e9);
    const out = jcsCanonicalize({ [bmpKey]: 1 });
    expect(out).toBeInstanceOf(Uint8Array);
    // Decode and sanity-check that the ASCII prefix appears.
    const decoded = new TextDecoder().decode(out);
    expect(decoded).toContain("caf");
  });

  test("recursive: nested object keys are also screened", () => {
    const badKey = String.fromCodePoint(0x1f600) + "nested";
    const value = { outer: { [badKey]: 1 } };
    expect(() => jcsCanonicalize(value)).toThrow(CanonicalEncodingError);
  });

  test("supplementary-plane codepoint in a VALUE is allowed", () => {
    // Only KEYS are screened. A string value with U+1F600 must encode.
    const out = jcsCanonicalize({ emoji: String.fromCodePoint(0x1f600) });
    expect(out).toBeInstanceOf(Uint8Array);
  });
});
