// Test-only HMAC-SHA256 / HMAC-SHA512 JWS verifier helper (TypeScript).
//
// This module is build-time isolated under `test/` per VAL-W17-023:
// it MUST NEVER be imported from any module under `src/` or referenced
// from the published package surface. The `tsconfig.build.json`
// `exclude` array lists `test`, and the `package.json` `files` array
// lists only `dist`, `src`, and `README.md` -- so neither the compiled
// dist tree nor the npm tarball contains this helper.
//
// Mirror of `tests/conformance/jws/_test_only_hs_verifier.py` (Python).
// Provides identical semantics for cross-runtime parity:
//
//   - `verifyHsCompact(token, sharedKey)` -- verify a compact-form JWS
//     whose alg is HS256 or HS512, given the shared key (Uint8Array
//     bytes). Returns true iff the HMAC matches.
//
// The helper accepts ONLY HS256 and HS512. Any other alg raises an
// `UnsupportedHsAlgError`. Production allow-list (ES256, EdDSA, RS256)
// is enforced separately by `src/verifier.ts` in a disjoint code path.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHmac, timingSafeEqual } from "node:crypto";

export class UnsupportedHsAlgError extends Error {
  constructor(alg: string) {
    super(
      `_test_only_hs_verifier refuses alg ${JSON.stringify(alg)}; ` +
        "only HS256/HS512 are accepted (production allow-list " +
        "{ES256, EdDSA, RS256} is enforced by packages/verifier-typescript/src/).",
    );
    this.name = "UnsupportedHsAlgError";
  }
}

const ALLOWED_HS_ALGS: ReadonlySet<string> = new Set(["HS256", "HS512"]);

function b64uDecode(s: string): Uint8Array {
  // Convert URL-safe base64 to standard base64 and pad.
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const std = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(std, "base64"));
}

interface ProtectedHeader {
  alg?: unknown;
  [k: string]: unknown;
}

function decodeProtectedHeader(headerB64u: string): ProtectedHeader {
  const raw = b64uDecode(headerB64u);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  const parsed = JSON.parse(text) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("JWS protected header must be a JSON object");
  }
  return parsed as ProtectedHeader;
}

export function verifyHsCompact(
  token: string,
  sharedKey: Uint8Array,
): boolean {
  const segments = token.split(".");
  if (segments.length !== 3) {
    return false;
  }
  const headerB64u = segments[0] as string;
  const payloadB64u = segments[1] as string;
  const sigB64u = segments[2] as string;

  let header: ProtectedHeader;
  try {
    header = decodeProtectedHeader(headerB64u);
  } catch {
    return false;
  }

  const alg = header.alg;
  if (typeof alg !== "string") {
    return false;
  }
  if (!ALLOWED_HS_ALGS.has(alg)) {
    throw new UnsupportedHsAlgError(alg);
  }

  let signature: Uint8Array;
  try {
    signature = b64uDecode(sigB64u);
  } catch {
    return false;
  }

  const signingInput = Buffer.from(`${headerB64u}.${payloadB64u}`, "ascii");
  const digestmod = alg === "HS256" ? "sha256" : "sha512";
  const hmac = createHmac(digestmod, Buffer.from(sharedKey));
  hmac.update(signingInput);
  const expected = hmac.digest();

  // Constant-time compare; lengths must match for timingSafeEqual.
  if (expected.length !== signature.length) {
    return false;
  }
  return timingSafeEqual(expected, signature);
}
