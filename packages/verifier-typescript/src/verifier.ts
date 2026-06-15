// Relay offline JWS verifier (TypeScript).
//
// Mirrors packages/verifier/src/relay_verifier/verifier.py at the
// behavioral level. The two implementations MUST agree byte-for-byte
// on every conformance-corpus verdict envelope (VAL-W10-015 parity):
//
//   * Allow-list: {EdDSA, ES256, RS256}; everything else rejected with
//     RELAY-VERIFY-011 BEFORE any cryptographic primitive runs.
//   * Alg-substitution: alg in allow-list paired with a JWK whose kty
//     does not match -> RELAY-VERIFY-010.
//   * Detached JWS (RFC 7797 + Relay claim binding): claim canonical
//     bytes recomputed; payload-digest mismatch -> RELAY-EVID-014.
//   * Multi-signature: per-signature verdicts in deterministic order;
//     aggregate is `all_valid` / `mixed` / `all_invalid`.
//
// Spec anchors: AO.4 (trust anchor), L.1 (alg allow-list), K (verifier
// output schema). RFC 7515 (JWS), RFC 7518 (JWA), RFC 7797 (detached
// payload), RFC 8037 (Ed25519 in JWK), RFC 8725 (best-current-practice).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import {
  createHash,
  createPublicKey,
  createVerify,
  verify as nodeVerify,
} from "node:crypto";

import { jcsCanonicalize } from "./canonical.js";
import {
  RELAY_EVID_014,
  RELAY_VERIFY_ALG_MISMATCH,
  RELAY_VERIFY_UNSUPPORTED_ALG,
} from "./errors.js";

// ----------------------------------------------------------------------------
// Constants (must match Python verifier.py)
// ----------------------------------------------------------------------------

export const ALG_EDDSA = "EdDSA" as const;
export const ALG_ES256 = "ES256" as const;
export const ALG_RS256 = "RS256" as const;
export const SUPPORTED_ALGS: ReadonlySet<string> = new Set([
  ALG_EDDSA,
  ALG_ES256,
  ALG_RS256,
]);

export const VERIFIER_RESULT_SCHEMA = "relay.verifier.result.v1" as const;

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

export interface SignatureCheck {
  /** JWK kid that produced (or would have produced) the signature. */
  readonly kid: string;
  /** JWS header `alg` value, or "<unknown>" if unparseable. */
  readonly alg: string;
  /** True iff the signature verified under the resolved JWK. */
  readonly ok: boolean;
  /** Human-readable reason; empty when ok=true. */
  readonly reason: string;
  /** Structured wire-code for the rejection class; empty when ok=true. */
  readonly code: string;
}

export type MultiSignatureAggregate =
  | "all_valid"
  | "mixed"
  | "all_invalid";

export interface MultiSignatureResult {
  readonly ok: boolean;
  readonly aggregate: MultiSignatureAggregate;
  readonly signaturesChecked: readonly SignatureCheck[];
}

// JWK / JWKS are deliberately permissive: incoming bytes from JSON.parse
// are unknown-shaped; the loader validates `kty` at runtime before
// dispatch (Ed25519/P-256/RSA branches). Strict typing of `kty` would
// force every test fixture to assert the literal narrowing -- not
// useful given the loader is the actual gate.
export interface JWK {
  readonly kty?: unknown;
  readonly kid?: unknown;
  readonly alg?: unknown;
  readonly use?: unknown;
  readonly crv?: unknown;
  readonly x?: unknown;
  readonly y?: unknown;
  readonly n?: unknown;
  readonly e?: unknown;
  // Allow extra annotation fields (not_before / not_after / etc.) per
  // the spec section L.2 trust-bundle download format.
  readonly [key: string]: unknown;
}

export interface JWKS {
  readonly keys: readonly JWK[];
}

// ----------------------------------------------------------------------------
// Base64URL helpers (RFC 4648 sec 5; unpadded form per RFC 7515)
// ----------------------------------------------------------------------------

export function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function b64uDecode(s: string): Uint8Array {
  // Buffer.from(...,"base64url") accepts both padded and unpadded forms
  // and decodes to a Buffer (which is a Uint8Array subclass).
  return new Uint8Array(Buffer.from(s, "base64url"));
}

// ----------------------------------------------------------------------------
// Canonical-JSON bytes (BUG-C2: delegator to RFC 8785 JCS)
// ----------------------------------------------------------------------------
//
// Cross-language parity moat: Python `verifier.py:140-166` makes
// `canonical_json_bytes` a thin delegator to `jcs_canonicalize` so the
// sign-side encoder used by `_payload_for_signing` and the JCS encoder
// used elsewhere in the verifier package cannot drift apart. The
// pre-fix TS implementation used `JSON.stringify` + `_ensureAscii`
// (\\uXXXX escapes), which produced spec-incorrect bytes for any
// non-ASCII string field -- different sha256 from Python for the same
// wire bundle -> split-brain verdict.
//
// Post-fix, this function is a thin delegator to `jcsCanonicalize`
// (RFC 8785: literal UTF-8, ECMA-262 number form, sorted keys, compact
// separators). The Python and TS verifiers MUST agree byte-for-byte on
// every conformance-corpus case; the `w10_3_jcs_corpus` and
// `w17_2_appendix_a` test suites enforce this on every PR.
//
// Kept as a named export rather than deleted because the
// bundle_validator and transparency_log modules import it; the rename
// to `jcsCanonicalize` is a separate cleanup pass.
export function canonicalJsonBytes(value: unknown): Uint8Array {
  return jcsCanonicalize(value);
}

// ----------------------------------------------------------------------------
// JWK -> Node KeyObject loader (RFC 7517 / 7518 / 8037)
// ----------------------------------------------------------------------------

// Internal helpers re-exported below under their underscore names so the
// transparency-log and bundle-validator modules can resolve a JWK by kid
// and load the public key without re-implementing the dispatch. Parity
// with Python's relay_verifier.verifier:_select_jwk / _load_public_key_from_jwk.
export function _loadPublicKeyFromJwk(jwk: JWK): import("node:crypto").KeyObject {
  if (jwk === null || typeof jwk !== "object") {
    throw new Error("JWK must be an object");
  }
  if (jwk.kty === "OKP") {
    if (jwk.crv !== "Ed25519") {
      throw new Error(`unsupported OKP crv: ${String(jwk.crv)}`);
    }
    if (typeof jwk.x !== "string") {
      throw new Error("OKP JWK missing 'x' (public key)");
    }
    const pub = b64uDecode(jwk.x);
    if (pub.length !== 32) {
      throw new Error(
        `Ed25519 public key must be 32 bytes; got ${pub.length}`,
      );
    }
    // Node's createPublicKey accepts a JWK directly.
    return createPublicKey({ key: jwk as Record<string, unknown>, format: "jwk" });
  }
  if (jwk.kty === "EC") {
    if (jwk.crv !== "P-256") {
      throw new Error(`unsupported EC crv: ${String(jwk.crv)}`);
    }
    if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      throw new Error("EC JWK missing 'x' or 'y'");
    }
    return createPublicKey({ key: jwk as Record<string, unknown>, format: "jwk" });
  }
  if (jwk.kty === "RSA") {
    if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
      throw new Error("RSA JWK missing 'n' or 'e'");
    }
    const n = b64uDecode(jwk.n);
    // bit length = (length in bytes - 1) * 8 + bits used in the most-
    // significant byte. `Math.clz32(msb)` returns the count of leading
    // zero bits when `msb` is treated as an unsigned 32-bit integer; for
    // an 8-bit value that count is at least 24. The bit-length of `msb`
    // alone is therefore (32 - clz32(msb)).
    const msb = n[0] ?? 0;
    let bitLength: number;
    if (msb === 0) {
      // Leading-zero byte indicates positive-integer DER padding; the
      // true bit length comes from the remaining bytes (which is what
      // a well-formed JWK should not have, but we are defensive).
      bitLength = (n.length - 1) * 8;
    } else {
      bitLength = (n.length - 1) * 8 + (32 - Math.clz32(msb));
    }
    if (bitLength < 2048) {
      throw new Error(
        `RSA modulus is ${bitLength} bits; spec L.1 allow-list rejects ` +
          `modulus < 2048 bits`,
      );
    }
    return createPublicKey({ key: jwk as Record<string, unknown>, format: "jwk" });
  }
  throw new Error(`unsupported JWK kty: ${String(jwk.kty)}`);
}

export function _selectJwk(jwks: JWKS, kid: string): JWK | null {
  if (jwks === null || typeof jwks !== "object") {
    return null;
  }
  if (!Array.isArray(jwks.keys)) {
    return null;
  }
  for (const jwk of jwks.keys) {
    if (jwk !== null && typeof jwk === "object" && jwk.kid === kid) {
      return jwk;
    }
  }
  return null;
}

function _ktyForAlg(alg: string): string | null {
  if (alg === ALG_EDDSA) return "OKP";
  if (alg === ALG_ES256) return "EC";
  if (alg === ALG_RS256) return "RSA";
  return null;
}

// ----------------------------------------------------------------------------
// Signature verification primitives
// ----------------------------------------------------------------------------

function _verifySignature(args: {
  alg: string;
  publicKey: import("node:crypto").KeyObject;
  signingInput: Uint8Array;
  signature: Uint8Array;
}): boolean {
  const { alg, publicKey, signingInput, signature } = args;
  if (alg === ALG_EDDSA) {
    // Node's nodeVerify(algorithm, data, key, sig) returns boolean for
    // Ed25519 when algorithm is null.
    try {
      return nodeVerify(null, Buffer.from(signingInput), publicKey, Buffer.from(signature));
    } catch {
      return false;
    }
  }
  if (alg === ALG_ES256) {
    // JWS wire form for ES256 is r || s (each 32 bytes for P-256).
    // Node's createVerify wants DER-encoded ASN.1; pass dsaEncoding:'ieee-p1363'
    // via nodeVerify to consume the raw r||s form directly.
    if (signature.length !== 64) {
      return false;
    }
    try {
      return nodeVerify(
        "sha256",
        Buffer.from(signingInput),
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(signature),
      );
    } catch {
      return false;
    }
  }
  if (alg === ALG_RS256) {
    try {
      const v = createVerify("RSA-SHA256");
      v.update(Buffer.from(signingInput));
      return v.verify(publicKey, Buffer.from(signature));
    } catch {
      return false;
    }
  }
  return false;
}

// ----------------------------------------------------------------------------
// Compact-form JWS (RFC 7515 sec 7.1)
// ----------------------------------------------------------------------------

function _decodeCompactSegments(token: string): [string, string, string] {
  if (typeof token !== "string") {
    throw new Error("compact JWS must be a string");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(
      `compact JWS must have 3 segments separated by '.', got ${parts.length}`,
    );
  }
  // Defensive narrowing under noUncheckedIndexedAccess:
  const a = parts[0];
  const b = parts[1];
  const c = parts[2];
  if (a === undefined || b === undefined || c === undefined) {
    throw new Error("compact JWS segments are unexpectedly undefined");
  }
  return [a, b, c];
}

function _decodeProtectedHeader(headerB64u: string): Record<string, unknown> {
  let raw: Uint8Array;
  try {
    raw = b64uDecode(headerB64u);
  } catch (exc) {
    throw new Error(
      `protected header is not valid base64url: ${(exc as Error).message}`,
    );
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch (exc) {
    throw new Error(
      `protected header is not valid UTF-8 JSON: ${(exc as Error).message}`,
    );
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("protected header must be a JSON object");
  }
  return decoded as Record<string, unknown>;
}

function _ascii(s: string): Uint8Array {
  // RFC 7515 / 7797 require ASCII octet input for the signing-input
  // concatenation. base64url segments are ASCII-only by construction.
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i) & 0xff;
  }
  return out;
}

function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function _check(args: Partial<SignatureCheck> & Pick<SignatureCheck, "kid" | "alg" | "ok">): SignatureCheck {
  return {
    kid: args.kid,
    alg: args.alg,
    ok: args.ok,
    reason: args.reason ?? "",
    code: args.code ?? "",
  };
}

/**
 * Format a string the way CPython's ``ascii()`` does, so signature-path
 * ``reason`` bytes match the Python verifier (roborev HIGH follow-on to
 * the round-2 #4 bundle_validator fix). The Python verifier now
 * interpolates attacker-controllable ``alg`` / ``kid`` (and the
 * ``expected_kty`` / ``actual_kty`` / ``payload_sha256`` operands that
 * travel alongside them) via ``_py_ascii(...)`` (the builtin ``ascii()``)
 * instead of ``!r``, because plain ``repr()`` keeps PRINTABLE non-ASCII
 * verbatim but ESCAPES non-printable non-ASCII (C1 controls, U+00A0,
 * format/separator chars like U+200B/U+2028/U+FEFF). That "printable"
 * distinction depends on the Unicode database and is intractable to mirror
 * byte-for-byte in TS. The pre-fix TS verifier interpolated these operands
 * with RAW template literals (``'${alg}'``), so a signature whose alg/kid
 * carried an interior non-printable non-ASCII code point produced
 * NON-IDENTICAL ``SignatureCheck.reason`` bytes vs Python -- a P0 Py<->TS
 * parity break on attacker-controllable verifier output.
 *
 * Routing both runtimes through the same pure code-point-range rule removes
 * the distinction: EVERY non-ASCII code point is escaped (``\\xNN`` for
 * cp<=0xff, ``\\uNNNN`` for cp<=0xffff, ``\\U`` + 8 hex for astral), so they
 * agree by construction. This is the SAME rule
 * ``bundle_validator.ts:pyReprStr`` already applies to namespace keys /
 * artifact ids / digests; it is duplicated here (rather than imported)
 * because the verifier module must stay free of a bundle_validator import
 * cycle. For ASCII alg/kid the output is byte-identical to ``repr()`` /
 * ``!r``, so existing ASCII verdict-parity tests stay unchanged.
 *
 * Rule (identical to CPython ``ascii()``): single quotes, switching to
 * double quotes only when the string contains a single quote and no double
 * quote; backslash-escape the quote char, backslash, and ``\t``/``\n``/``\r``;
 * emit ASCII control bytes (cp < 0x20) and DEL (0x7f) and every non-ASCII
 * code point by the range rule above.
 */
function pyReprStr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === quote || ch === "\\") {
      out += "\\" + ch;
    } else if (ch === "\t") {
      out += "\\t";
    } else if (ch === "\n") {
      out += "\\n";
    } else if (ch === "\r") {
      out += "\\r";
    } else if (cp < 0x20 || cp === 0x7f) {
      out += "\\x" + cp.toString(16).padStart(2, "0");
    } else if (cp >= 0x80) {
      // Non-ASCII: escape by code-point range exactly like CPython ascii().
      if (cp <= 0xff) {
        out += "\\x" + cp.toString(16).padStart(2, "0");
      } else if (cp <= 0xffff) {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      } else {
        out += "\\U" + cp.toString(16).padStart(8, "0");
      }
    } else {
      out += ch;
    }
  }
  return out + quote;
}

/**
 * Mirror CPython's ``ascii(value)`` for the operand types that can appear as
 * a JWK ``kty`` field after ``JSON.parse``. The Python verifier interpolates
 * ``actual_kty = candidate_jwk.get("kty")`` (the raw parsed value) via
 * ``_py_ascii(actual_kty)``; that value is usually a string but a malformed
 * JWK can carry ``null`` / a number / a boolean / a container. Rendering it
 * the CPython way keeps the alg-mismatch ``reason`` byte-identical across
 * runtimes for a STRING kty (the only realistic key-type) and for
 * null/bool/integer:
 *
 *   * string  -> ``pyReprStr`` (ascii()-escaped, quoted)
 *   * null    -> ``None``
 *   * boolean -> ``True`` / ``False``
 *   * integer -> decimal digits (``123``)
 *   * non-integer / non-finite number -> ``String(n)``
 *   * array / object -> element-wise ``ascii([...])`` / ``ascii({...})`` with
 *     Python's ``', '`` / ``': '`` separators
 *
 * BOUNDED residual (the unbounded "match Python repr of arbitrary JSON types"
 * class -- documented, not chased): for a NON-string kty (a malformed JWKS:
 * a JSON float like ``1.0`` / ``1e-07``, or an object), JS number normalisation
 * and ``Object.entries`` key-order can diverge from Python's float repr / dict
 * insertion order. That affects only the human-readable ``reason`` DIAGNOSTIC
 * bytes (not a signed/canonical surface), only for a malformed JWKS that BOTH
 * runtimes reject. Python ``dict.get`` returns ``None`` for a missing key,
 * which is exactly the ``undefined`` case here -- both render ``None``.
 */
// Mirror CPython ascii(repr(x)) for the operand types that reach the signature-
// failure reason messages. This is EXACT for strings (pyReprStr) -- the only
// realistic JWK `kty` domain ("RSA"/"EC"/"OKP") -- and for None/bool. For a
// NON-string `kty` (a malformed JWKS: a JSON number, or an object), JS Number
// normalisation (1.0 -> "1") and Object.entries key-order can diverge from
// Python's float repr / dict insertion order. That residual is a documented
// BOUNDED limitation (the unbounded "match Python repr of arbitrary JSON types"
// class): it only affects the human-readable `reason` DIAGNOSTIC bytes (not a
// signed/canonical surface), only for malformed JWKS that BOTH runtimes reject,
// and never for a well-formed string `kty`.
function pyAscii(value: unknown): string {
  if (value === null || value === undefined) {
    return "None";
  }
  if (typeof value === "string") {
    return pyReprStr(value);
  }
  if (typeof value === "boolean") {
    return value ? "True" : "False";
  }
  if (typeof value === "number") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => pyAscii(v)).join(", ") + "]";
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      "{" +
      entries.map(([k, v]) => `${pyReprStr(k)}: ${pyAscii(v)}`).join(", ") +
      "}"
    );
  }
  return pyReprStr(String(value));
}

export function verifyJwsCompact(
  token: string,
  jwks: JWKS,
  options: { allowedAlgs?: ReadonlySet<string> } = {},
): SignatureCheck {
  const allowed = options.allowedAlgs ?? SUPPORTED_ALGS;

  let segments: [string, string, string];
  try {
    segments = _decodeCompactSegments(token);
  } catch (exc) {
    return _check({ kid: "<unknown>", alg: "<unknown>", ok: false, reason: (exc as Error).message });
  }
  const [headerB64, payloadB64, sigB64] = segments;

  let header: Record<string, unknown>;
  try {
    header = _decodeProtectedHeader(headerB64);
  } catch (exc) {
    return _check({ kid: "<unknown>", alg: "<unknown>", ok: false, reason: (exc as Error).message });
  }

  const algRaw = header["alg"];
  const alg = typeof algRaw === "string" ? algRaw : "<unknown>";
  const kidRaw = header["kid"];
  const kid = typeof kidRaw === "string" ? kidRaw : "<unknown>";

  if (!allowed.has(alg)) {
    return _check({
      kid,
      alg,
      ok: false,
      reason: `unsupported alg: ${pyReprStr(alg)}`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }

  const candidate = _selectJwk(jwks, kid);
  if (candidate === null) {
    return _check({
      kid,
      alg,
      ok: false,
      reason: `no JWK in trust anchor matches kid ${pyReprStr(kid)}`,
    });
  }

  const expectedKty = _ktyForAlg(alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid,
      alg,
      ok: false,
      reason: `alg-mismatch: alg=${pyReprStr(alg)} requires kty=${pyReprStr(expectedKty)} but JWK has kty=${pyAscii(candidate.kty)}`,
      code: RELAY_VERIFY_ALG_MISMATCH,
    });
  }

  let publicKey: import("node:crypto").KeyObject;
  try {
    publicKey = _loadPublicKeyFromJwk(candidate);
  } catch (exc) {
    return _check({ kid, alg, ok: false, reason: `JWK load failed: ${(exc as Error).message}` });
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = b64uDecode(sigB64);
  } catch (exc) {
    return _check({ kid, alg, ok: false, reason: `signature segment is not valid base64url: ${(exc as Error).message}` });
  }

  const signingInput = _ascii(`${headerB64}.${payloadB64}`);

  const ok = _verifySignature({ alg, publicKey, signingInput, signature: signatureBytes });
  if (!ok) {
    return _check({ kid, alg, ok: false, reason: "signature did not verify under JWK" });
  }
  return _check({ kid, alg, ok: true });
}

// ----------------------------------------------------------------------------
// Detached JWS (RFC 7797 + Relay claim binding)
// ----------------------------------------------------------------------------

export function verifyJwsDetached(args: {
  protectedB64u: string;
  payloadBytes: Uint8Array;
  signatureB64u: string;
  jwks: JWKS;
  allowedAlgs?: ReadonlySet<string>;
}): SignatureCheck {
  const allowed = args.allowedAlgs ?? SUPPORTED_ALGS;

  let header: Record<string, unknown>;
  try {
    header = _decodeProtectedHeader(args.protectedB64u);
  } catch (exc) {
    return _check({ kid: "<unknown>", alg: "<unknown>", ok: false, reason: (exc as Error).message });
  }

  const algRaw = header["alg"];
  const alg = typeof algRaw === "string" ? algRaw : "<unknown>";
  const kidRaw = header["kid"];
  const kid = typeof kidRaw === "string" ? kidRaw : "<unknown>";

  if (!allowed.has(alg)) {
    return _check({
      kid, alg, ok: false,
      reason: `unsupported alg: ${pyReprStr(alg)}`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }

  const candidate = _selectJwk(args.jwks, kid);
  if (candidate === null) {
    return _check({
      kid, alg, ok: false,
      reason: `no JWK in trust anchor matches kid ${pyReprStr(kid)}`,
    });
  }

  const expectedKty = _ktyForAlg(alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid, alg, ok: false,
      reason: `alg-mismatch: alg=${pyReprStr(alg)} requires kty=${pyReprStr(expectedKty)} but JWK has kty=${pyAscii(candidate.kty)}`,
      code: RELAY_VERIFY_ALG_MISMATCH,
    });
  }

  let publicKey: import("node:crypto").KeyObject;
  try {
    publicKey = _loadPublicKeyFromJwk(candidate);
  } catch (exc) {
    return _check({ kid, alg, ok: false, reason: `JWK load failed: ${(exc as Error).message}` });
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = b64uDecode(args.signatureB64u);
  } catch (exc) {
    return _check({ kid, alg, ok: false, reason: `signature segment is not valid base64url: ${(exc as Error).message}` });
  }

  // RFC 7797 sec 3: detached signing input is ASCII(b64u(header)) || '.' || raw_payload.
  const signingInput = _concat(_ascii(`${args.protectedB64u}.`), args.payloadBytes);

  const ok = _verifySignature({ alg, publicKey, signingInput, signature: signatureBytes });
  if (!ok) {
    return _check({ kid, alg, ok: false, reason: "signature did not verify under JWK" });
  }
  return _check({ kid, alg, ok: true });
}

export function verifyDetachedClaimSignature(args: {
  protectedB64u: string;
  signatureB64u: string;
  claim: unknown;
  jwks: JWKS;
  allowedAlgs?: ReadonlySet<string>;
}): SignatureCheck {
  const canonicalPayload = canonicalJsonBytes(args.claim);
  const recomputedDigest = createHash("sha256").update(canonicalPayload).digest("hex");

  let header: Record<string, unknown>;
  try {
    header = _decodeProtectedHeader(args.protectedB64u);
  } catch (exc) {
    return _check({ kid: "<unknown>", alg: "<unknown>", ok: false, reason: (exc as Error).message });
  }

  const declaredDigest = header["payload_sha256"];
  if (typeof declaredDigest === "string" && declaredDigest !== recomputedDigest) {
    const algRaw = header["alg"];
    const kidRaw = header["kid"];
    return _check({
      kid: typeof kidRaw === "string" ? kidRaw : "<unknown>",
      alg: typeof algRaw === "string" ? algRaw : "<unknown>",
      ok: false,
      reason: `detached payload digest mismatch: header declared sha256=${pyReprStr(declaredDigest)} but recomputed sha256=${pyReprStr(recomputedDigest)} from claim canonical bytes`,
      code: RELAY_EVID_014,
    });
  }

  const inner = verifyJwsDetached({
    protectedB64u: args.protectedB64u,
    payloadBytes: canonicalPayload,
    signatureB64u: args.signatureB64u,
    jwks: args.jwks,
    allowedAlgs: args.allowedAlgs,
  });
  if (inner.ok) {
    return inner;
  }
  if (inner.reason === "signature did not verify under JWK" && !inner.code) {
    return _check({
      kid: inner.kid,
      alg: inner.alg,
      ok: false,
      reason:
        "detached payload digest mismatch: signature did not verify against " +
        "recomputed canonical claim bytes (claim was tampered after signing)",
      code: RELAY_EVID_014,
    });
  }
  return inner;
}

// ----------------------------------------------------------------------------
// Multi-signature payload verification (VAL-W10-013)
// ----------------------------------------------------------------------------

export function verifyMultiSignatures(args: {
  payload: unknown;
  signatures: ReadonlyArray<{ alg?: unknown; kid?: unknown; signature_b64u?: unknown }>;
  jwks: JWKS;
  allowedAlgs?: ReadonlySet<string>;
}): MultiSignatureResult {
  const allowed = args.allowedAlgs ?? SUPPORTED_ALGS;
  const canonicalBytes = canonicalJsonBytes(args.payload);
  const checks: SignatureCheck[] = [];

  if (!Array.isArray(args.signatures) || args.signatures.length === 0) {
    return { ok: false, aggregate: "all_invalid", signaturesChecked: [] };
  }

  let validCount = 0;
  let invalidCount = 0;
  for (const sig of args.signatures) {
    if (sig === null || typeof sig !== "object") {
      checks.push(_check({ kid: "<unknown>", alg: "<unknown>", ok: false, reason: "signature entry is not an object" }));
      invalidCount += 1;
      continue;
    }
    const alg = typeof sig.alg === "string" ? sig.alg : "<unknown>";
    const kid = typeof sig.kid === "string" ? sig.kid : "<unknown>";
    const sigB64 = sig.signature_b64u;
    if (typeof sigB64 !== "string" || sigB64.length === 0) {
      checks.push(_check({ kid, alg, ok: false, reason: "signature missing 'signature_b64u'" }));
      invalidCount += 1;
      continue;
    }
    const c = _verifyOneOverBytes({ alg, kid, signingInput: canonicalBytes, signatureB64u: sigB64, jwks: args.jwks, allowed });
    checks.push(c);
    if (c.ok) validCount += 1;
    else invalidCount += 1;
  }

  let aggregate: MultiSignatureAggregate;
  let ok: boolean;
  if (validCount > 0 && invalidCount === 0) {
    aggregate = "all_valid";
    ok = true;
  } else if (validCount > 0 && invalidCount > 0) {
    aggregate = "mixed";
    ok = false;
  } else {
    aggregate = "all_invalid";
    ok = false;
  }
  return { ok, aggregate, signaturesChecked: checks };
}

function _verifyOneOverBytes(args: {
  alg: string;
  kid: string;
  signingInput: Uint8Array;
  signatureB64u: string;
  jwks: JWKS;
  allowed: ReadonlySet<string>;
}): SignatureCheck {
  if (!args.allowed.has(args.alg)) {
    return _check({
      kid: args.kid, alg: args.alg, ok: false,
      reason: `unsupported alg: ${pyReprStr(args.alg)}`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }
  const candidate = _selectJwk(args.jwks, args.kid);
  if (candidate === null) {
    return _check({
      kid: args.kid, alg: args.alg, ok: false,
      reason: `no JWK in trust anchor matches kid ${pyReprStr(args.kid)}`,
    });
  }
  const expectedKty = _ktyForAlg(args.alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid: args.kid, alg: args.alg, ok: false,
      reason: `alg-mismatch: alg=${pyReprStr(args.alg)} requires kty=${pyReprStr(expectedKty)} but JWK has kty=${pyAscii(candidate.kty)}`,
      code: RELAY_VERIFY_ALG_MISMATCH,
    });
  }
  let publicKey: import("node:crypto").KeyObject;
  try {
    publicKey = _loadPublicKeyFromJwk(candidate);
  } catch (exc) {
    return _check({ kid: args.kid, alg: args.alg, ok: false, reason: `JWK load failed: ${(exc as Error).message}` });
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = b64uDecode(args.signatureB64u);
  } catch (exc) {
    return _check({ kid: args.kid, alg: args.alg, ok: false, reason: `signature_b64u is not valid base64url: ${(exc as Error).message}` });
  }
  const ok = _verifySignature({ alg: args.alg, publicKey, signingInput: args.signingInput, signature: signatureBytes });
  if (!ok) {
    return _check({ kid: args.kid, alg: args.alg, ok: false, reason: "signature did not verify under JWK" });
  }
  return _check({ kid: args.kid, alg: args.alg, ok: true });
}

// ----------------------------------------------------------------------------
// Bundle-signature verification (BUG-C3 wire-shape parity with Python)
// ----------------------------------------------------------------------------
//
// Per spec section L (`local_signer.py::sign_payload_ed25519` and
// `verifier.py::verify_bundle` lines 379-560), the canonical wire shape
// for each entry in a bundle's `signatures` array is:
//
//   {
//     "alg":              "EdDSA" | "ES256" | "RS256",
//     "kid":              "<string>",
//     "signing_input_b64u": "<b64url(jcs_canonicalize(bundle - signatures))>",
//     "signature_b64u":    "<b64url(raw signature)>"
//   }
//
// The verifier (1) re-canonicalizes the bundle minus `signatures` to
// recompute the expected signing-input bytes, (2) base64url-decodes the
// producer-supplied `signing_input_b64u` and asserts byte-equality with
// the recomputed canonical (detects bundle tampering after signing),
// (3) verifies the raw signature against the recomputed bytes under the
// JWK matched by `kid`.
//
// Backward-compatibility alias: the pre-fix TS validator emitted
// `protected_b64u` (a different concept -- a JWS protected header). The
// alias accepts a signature entry that supplies `protected_b64u` AS IF
// it were `signing_input_b64u`. This is a one-release compatibility
// bridge for any in-flight fixture; new bundles MUST use
// `signing_input_b64u` and the contract test in
// `audit_r3_parity.test.ts` enforces it.
export interface BundleSignatureEntry {
  alg?: unknown;
  kid?: unknown;
  signing_input_b64u?: unknown;
  /** Legacy alias for `signing_input_b64u`; one-release back-compat only. */
  protected_b64u?: unknown;
  signature_b64u?: unknown;
}

export function verifyBundleSignature(args: {
  signature: BundleSignatureEntry;
  expectedCanonicalBytes: Uint8Array;
  jwks: JWKS;
  signatureIndex?: number;
  allowedAlgs?: ReadonlySet<string>;
}): SignatureCheck {
  const allowed = args.allowedAlgs ?? SUPPORTED_ALGS;
  const sig = args.signature;
  const idxLabel =
    typeof args.signatureIndex === "number" ? `<sig[${args.signatureIndex}]>` : "<sig>";

  const kidRaw = sig.kid;
  const algRaw = sig.alg;
  const algStr = typeof algRaw === "string" ? algRaw : "<unknown>";

  if (typeof kidRaw !== "string" || kidRaw.length === 0) {
    return _check({
      kid: idxLabel,
      alg: algStr,
      ok: false,
      reason: "signature missing 'kid'",
    });
  }
  const kid = kidRaw;

  if (!allowed.has(algStr)) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `unsupported alg: ${pyReprStr(algStr)}`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }

  // Alg-substitution detection (VAL-W10-011 + RFC 8725): the JWK kty
  // MUST match the alg's expected kty.
  const candidateJwk = _selectJwk(args.jwks, kid);
  const expectedKty = _ktyForAlg(algStr);
  if (candidateJwk !== null && expectedKty !== null && candidateJwk.kty !== expectedKty) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `alg-mismatch: alg=${pyReprStr(algStr)} requires kty=${pyReprStr(expectedKty)} but JWK has kty=${pyAscii(candidateJwk.kty)}`,
      code: RELAY_VERIFY_ALG_MISMATCH,
    });
  }

  // Wire-field resolution: prefer the canonical `signing_input_b64u`,
  // accept legacy `protected_b64u` as an alias only when the canonical
  // field is absent. Mirrors Python's strict expectation while letting
  // in-flight fixtures pass during the transition.
  let signingInputB64u: unknown = sig.signing_input_b64u;
  if (typeof signingInputB64u !== "string" || signingInputB64u.length === 0) {
    if (typeof sig.protected_b64u === "string" && sig.protected_b64u.length > 0) {
      signingInputB64u = sig.protected_b64u;
    }
  }
  if (typeof signingInputB64u !== "string" || signingInputB64u.length === 0) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: "signature missing 'signing_input_b64u'",
    });
  }

  const signatureB64u = sig.signature_b64u;
  if (typeof signatureB64u !== "string" || signatureB64u.length === 0) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: "signature missing 'signature_b64u'",
    });
  }

  let recordedSigningInput: Uint8Array;
  try {
    recordedSigningInput = b64uDecode(signingInputB64u);
  } catch (exc) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `signing_input_b64u is not valid base64url: ${(exc as Error).message}`,
    });
  }

  // Tamper-detection: producer's recorded canonical bytes MUST equal
  // the verifier's recomputed canonical bytes. Python's verify_bundle
  // (line 486) gates here.
  const expected = args.expectedCanonicalBytes;
  if (recordedSigningInput.length !== expected.length) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason:
        "signing_input drift: recorded canonical bytes " +
        "do not match recomputed payload (bundle tampered)",
    });
  }
  for (let i = 0; i < expected.length; i++) {
    if (recordedSigningInput[i] !== expected[i]) {
      return _check({
        kid,
        alg: algStr,
        ok: false,
        reason:
          "signing_input drift: recorded canonical bytes " +
          "do not match recomputed payload (bundle tampered)",
      });
    }
  }

  if (candidateJwk === null) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `no JWK in trust anchor matches kid ${pyReprStr(kid)}`,
    });
  }

  let publicKey: import("node:crypto").KeyObject;
  try {
    publicKey = _loadPublicKeyFromJwk(candidateJwk);
  } catch (exc) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `JWK load failed: ${(exc as Error).message}`,
    });
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = b64uDecode(signatureB64u);
  } catch (exc) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: `signature_b64u is not valid base64url: ${(exc as Error).message}`,
    });
  }

  const ok = _verifySignature({
    alg: algStr,
    publicKey,
    signingInput: recordedSigningInput,
    signature: signatureBytes,
  });
  if (!ok) {
    return _check({
      kid,
      alg: algStr,
      ok: false,
      reason: "signature did not verify under JWK",
    });
  }
  return _check({ kid, alg: algStr, ok: true });
}
