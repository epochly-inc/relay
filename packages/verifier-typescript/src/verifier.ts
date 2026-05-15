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
// Canonical-JSON bytes (mirrors Python `canonical_json_bytes`)
// ----------------------------------------------------------------------------
//
// The Python verifier uses `json.dumps(obj, sort_keys=True,
// separators=(",", ":"), ensure_ascii=True)` for its claim canonicalisation.
// For byte-equality we must replicate that exact form here:
//
//   1. Sort object keys lexicographically (UTF-16 code-unit order matches
//      Python's str sort for ASCII-only keys, which the Relay claim
//      schema enforces).
//   2. Compact separators: "," between elements, ":" between key:value.
//   3. ASCII-only escapes for non-ASCII code points (\uXXXX for BMP,
//      surrogate-pair sequences for SMP).
//
// JSON.stringify with a sort-key replacer satisfies (1)+(2) for ASCII,
// but does NOT escape non-ASCII -- equivalent to ensure_ascii=False.
// We add an explicit non-ASCII escape pass to match Python's default.

function _sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(_sortObjectKeys);
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(obj).slice().sort()) {
      // Defensive lookup under noUncheckedIndexedAccess.
      const v = obj[k];
      sorted[k] = _sortObjectKeys(v);
    }
    return sorted;
  }
  return value;
}

function _ensureAscii(s: string): string {
  // Replace any code unit >= 0x80 with its \uXXXX escape. Surrogate pairs
  // are emitted as two consecutive escapes (matches Python's
  // ensure_ascii=True behavior for SMP code points).
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu < 0x80) {
      out += s.charAt(i);
    } else {
      out += "\\u" + cu.toString(16).padStart(4, "0");
    }
  }
  return out;
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  const sorted = _sortObjectKeys(value);
  const naive = JSON.stringify(sorted);
  if (naive === undefined) {
    throw new TypeError(
      "canonicalJsonBytes: value is not JSON-encodable (undefined or function)",
    );
  }
  const ascii = _ensureAscii(naive);
  return new TextEncoder().encode(ascii);
}

// ----------------------------------------------------------------------------
// JWK -> Node KeyObject loader (RFC 7517 / 7518 / 8037)
// ----------------------------------------------------------------------------

function _loadPublicKeyFromJwk(jwk: JWK): import("node:crypto").KeyObject {
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

function _selectJwk(jwks: JWKS, kid: string): JWK | null {
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
      reason: `unsupported alg: '${alg}'`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }

  const candidate = _selectJwk(jwks, kid);
  if (candidate === null) {
    return _check({
      kid,
      alg,
      ok: false,
      reason: `no JWK in trust anchor matches kid '${kid}'`,
    });
  }

  const expectedKty = _ktyForAlg(alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid,
      alg,
      ok: false,
      reason: `alg-mismatch: alg='${alg}' requires kty='${expectedKty}' but JWK has kty='${String(candidate.kty)}'`,
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
      reason: `unsupported alg: '${alg}'`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }

  const candidate = _selectJwk(args.jwks, kid);
  if (candidate === null) {
    return _check({
      kid, alg, ok: false,
      reason: `no JWK in trust anchor matches kid '${kid}'`,
    });
  }

  const expectedKty = _ktyForAlg(alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid, alg, ok: false,
      reason: `alg-mismatch: alg='${alg}' requires kty='${expectedKty}' but JWK has kty='${String(candidate.kty)}'`,
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
      reason: `detached payload digest mismatch: header declared sha256='${declaredDigest}' but recomputed sha256='${recomputedDigest}' from claim canonical bytes`,
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
      reason: `unsupported alg: '${args.alg}'`,
      code: RELAY_VERIFY_UNSUPPORTED_ALG,
    });
  }
  const candidate = _selectJwk(args.jwks, args.kid);
  if (candidate === null) {
    return _check({
      kid: args.kid, alg: args.alg, ok: false,
      reason: `no JWK in trust anchor matches kid '${args.kid}'`,
    });
  }
  const expectedKty = _ktyForAlg(args.alg);
  if (expectedKty !== null && candidate.kty !== expectedKty) {
    return _check({
      kid: args.kid, alg: args.alg, ok: false,
      reason: `alg-mismatch: alg='${args.alg}' requires kty='${expectedKty}' but JWK has kty='${String(candidate.kty)}'`,
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
