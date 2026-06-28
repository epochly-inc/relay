// RFC 8785 JCS canonicalization for the OSS evidence verifier (W10.3, TS).
//
// Mirror of packages/verifier/src/relay_verifier/canonical.py and of
// packages/contracts-typescript/src/canonical.ts. Output bytes MUST be
// byte-equal to BOTH the Python verifier (`relay_verifier.canonical
// .jcs_canonicalize`) and the TS contracts mirror
// (`@epochly/relay-contracts.jcsCanonicalize`) for every input value
// in tests/conformance/jcs/rfc8785_corpus.json. The conformance test
// `test/w10_3_jcs_corpus.test.ts` enforces this byte-for-byte.
//
// Why a second copy instead of importing from @epochly/relay-contracts?
// Same reason as the Python side: the verifier package's import
// boundary forbids depending on the contracts package, so an
// auditor-only verifier wheel does not drag in the CEL evaluator.
//
// What this module pins (RFC 8785):
//   - section 3.2.2: number representation per ECMA-262 7.1.12.1
//     (Number.toString) -- whole-valued doubles emit without trailing
//     `.0`; negative zero collapses to `0`; NaN/Inf rejected.
//   - section 3.2.2.1: only `"`, `\\`, U+0000..U+001F escaped; higher
//     code points emitted literally as UTF-8.
//   - section 3.2.3: object keys sorted by UTF-16 code-unit sequence.
//
// Bundle-digest helper (VAL-W10-020): `bundleDigest(value)` returns
// `sha256(jcsCanonicalize(value_without_signatures))` as a lowercase
// hex string -- strips a top-level `signatures` field by default to
// match the bundle-signing convention (`_payload_for_signing` in the
// Python verifier).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";

// Wire-stable code for the BMP-only object-key screen. JS strings sort
// by UTF-16 code unit; Python strings sort by codepoint. For Basic
// Multilingual Plane keys (< U+10000) these match. For supplementary-
// plane keys (>= U+10000) they diverge -- the same input produces
// DIFFERENT canonical bytes between runtimes, silently breaking
// cross-runtime signature verification (CLAUDE.md keystone invariant
// #11). Both verifiers fail-closed on supplementary-plane KEYS; values
// may contain supplementary-plane chars (only keys are sorted). Mirrors
// @epochly/relay-contracts canonical.ts CANONICAL_NON_BMP_KEY_CODE.
export const CANONICAL_NON_BMP_KEY_CODE = "RELAY-CANON-NON-BMP-KEY" as const;

// JCSEncodeError mirrors the Python class. TypeScript has no protected
// distinction between Error subclasses across module boundaries, so the
// class is exported and consumers branch on `instanceof JCSEncodeError`.
export class JCSEncodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JCSEncodeError";
  }
}

// RFC 8785 section 3.2.2.1 escape map. Mirrors the Python ESCAPE_MAP
// in packages/verifier/src/relay_verifier/canonical.py:54-65 and the
// contracts-typescript ESCAPE_MAP at canonical.ts:29-40.
const ESCAPE_MAP: Record<number, string> = {
  0x00: "\\u0000", 0x01: "\\u0001", 0x02: "\\u0002", 0x03: "\\u0003",
  0x04: "\\u0004", 0x05: "\\u0005", 0x06: "\\u0006", 0x07: "\\u0007",
  0x08: "\\b",     0x09: "\\t",     0x0a: "\\n",     0x0b: "\\u000b",
  0x0c: "\\f",     0x0d: "\\r",     0x0e: "\\u000e", 0x0f: "\\u000f",
  0x10: "\\u0010", 0x11: "\\u0011", 0x12: "\\u0012", 0x13: "\\u0013",
  0x14: "\\u0014", 0x15: "\\u0015", 0x16: "\\u0016", 0x17: "\\u0017",
  0x18: "\\u0018", 0x19: "\\u0019", 0x1a: "\\u001a", 0x1b: "\\u001b",
  0x1c: "\\u001c", 0x1d: "\\u001d", 0x1e: "\\u001e", 0x1f: "\\u001f",
  0x22: '\\"',
  0x5c: "\\\\",
};

function encodeString(s: string): string {
  // RFC 8785 + spec line 5696 + VAL-W17-003: all canonicalized JSON
  // for digest uses UTF-8 NFC. JS String.prototype.normalize("NFC")
  // is ECMAScript-standard and idempotent; ASCII strings are fixed
  // points. Mirrors unicodedata.normalize("NFC", s) on the Python side.
  s = s.normalize("NFC");
  // Iterate by UTF-16 code units so high/low surrogate pairs are
  // emitted as the original two code units (which TextEncoder
  // reassembles into the correct UTF-8 byte sequence). Code units
  // 0x00-0x1F, 0x22, 0x5C escape; everything else passes through.
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    const esc = ESCAPE_MAP[cp];
    if (esc !== undefined) {
      out += esc;
    } else {
      // String.fromCharCode(cp) preserves the exact code unit;
      // String.fromCodePoint would re-pair surrogates and break the
      // round-trip. We want the raw code-unit form here.
      out += String.fromCharCode(cp);
    }
  }
  out += '"';
  return out;
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new JCSEncodeError(
      `JCS cannot encode non-finite number: ${String(n)}`,
    );
  }
  // ECMA-262 ToString collapses both +0 and -0 to "0".
  if (n === 0) {
    return "0";
  }
  // JS Number.prototype.toString() implements ECMA-262 7.1.12.1
  // ToString, which JCS section 3.2.2 also mandates. Whole-valued
  // doubles like 1.0 stringify as "1" natively (matching the Python
  // encoder's special case at canonical.py:_encode_number).
  return String(n);
}

function encode(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  const t = typeof value;
  if (t === "boolean") {
    return value ? "true" : "false";
  }
  if (t === "number") {
    return encodeNumber(value as number);
  }
  if (t === "bigint") {
    // BigInt encodes as its decimal string form. The Python encoder
    // accepts arbitrary-precision int via str(int), which yields the
    // same form. Negative zero is unrepresentable in BigInt.
    return (value as bigint).toString(10);
  }
  if (t === "string") {
    return encodeString(value as string);
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      parts.push(encode(item));
    }
    return "[" + parts.join(",") + "]";
  }
  if (t === "object") {
    // RFC 8785 section 3.2.3: keys sorted by UTF-16 code-unit
    // sequence. JS string `<` compares by code unit, matching the spec
    // for BMP. For supplementary-plane (>= U+10000) characters JS
    // compares by surrogate-pair code units while Python sorts by
    // codepoint -- divergent canonical bytes silently break
    // cross-runtime signature verification (CLAUDE.md keystone
    // invariant #11). Fail-closed on supplementary-plane object KEYS
    // BEFORE sorting. Values may contain supplementary-plane chars;
    // only keys are screened. Mirrors @epochly/relay-contracts
    // canonical.ts.
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    for (const k of keys) {
      // for...of iterates Unicode codepoints (surrogate pairs collapse
      // to a single step yielding the full codepoint via codePointAt(0)).
      for (const ch of k) {
        const cp = ch.codePointAt(0);
        if (cp !== undefined && cp >= 0x10000) {
          throw new JCSEncodeError(
            CANONICAL_NON_BMP_KEY_CODE +
              ": non-BMP codepoint U+" +
              cp.toString(16).toUpperCase().padStart(4, "0") +
              " in object key " +
              JSON.stringify(k) +
              "; supplementary-plane keys produce runtime-divergent " +
              "canonical bytes and are refused. Re-key the object " +
              "with BMP-only strings.",
          );
        }
      }
    }
    const sortedKeys = keys.slice().sort();
    const parts: string[] = [];
    for (const k of sortedKeys) {
      const v = obj[k];
      parts.push(encodeString(k) + ":" + encode(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new JCSEncodeError(
    `JCS: unsupported type ${t} for value ${String(value)}`,
  );
}

const ENCODER = new TextEncoder();

/**
 * Return the RFC 8785 JCS canonical-bytes form of `value`.
 *
 * Output is UTF-8 bytes (no BOM). NaN / +Inf / -Inf throw
 * `JCSEncodeError`. Spec anchors: RFC 8785 sections 3.2.2 / 3.2.2.1 /
 * 3.2.3.
 */
export function jcsCanonicalize(value: unknown): Uint8Array {
  return ENCODER.encode(encode(value));
}

/**
 * Return `sha256(jcsCanonicalize(value)).hex` as a lowercase hex
 * string. By default strips a top-level `signatures` field (the
 * bundle-signing convention -- the signer signs the canonical bytes
 * of the signature-free payload, then appends signatures).
 *
 * Pass `{ stripSignatures: false }` to digest the value as supplied.
 */
export function bundleDigest(
  value: unknown,
  options?: { stripSignatures?: boolean },
): string {
  const stripSignatures = options?.stripSignatures ?? true;
  let payload: unknown = value;
  if (
    stripSignatures &&
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.prototype.hasOwnProperty.call(value, "signatures")
  ) {
    const obj = value as Record<string, unknown>;
    const stripped: Record<string, unknown> = {};
    for (const k of Object.keys(obj)) {
      if (k === "signatures") {
        continue;
      }
      stripped[k] = obj[k];
    }
    payload = stripped;
  }
  const canonical = jcsCanonicalize(payload);
  return createHash("sha256").update(canonical).digest("hex");
}
