// Structured error envelope for the Relay TypeScript JWS verifier.
//
// Mirrors packages/verifier/src/relay_verifier/errors.py token-for-token.
// The cross-language conformance corpus enforces parity by comparing
// canonical-JSON verdict envelopes that include the `code` field; both
// runtimes MUST emit the same RELAY-VERIFY-NNN string for the same
// input. Adding a new code requires a paired Python edit.
//
// Spec anchors: section AO.4 (trust-anchor verifier surface), L.1
// (algorithm allow-list), K (verifier output structure).
// Eng plan anchors: W10 line 130-135 (verifier package scope).
// CLAUDE.md anchors: keystone invariant 6 (evidence binds), banned
// pattern 13 (default trust anchor pinning).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

// W10.1 inherited (defined for shape-parity even though the TS
// verifier does not currently emit them -- the JWKS loader lives only
// on the Python side in v0.1).
export const RELAY_VERIFY_JWKS_UNAVAILABLE = "RELAY-VERIFY-001" as const;
export const RELAY_VERIFY_BUNDLED_MISSING = "RELAY-VERIFY-002" as const;
export const RELAY_VERIFY_CONFIG_INVALID = "RELAY-VERIFY-003" as const;

// W10.2 introduced. See packages/verifier/src/relay_verifier/errors.py
// for the per-code semantics; this module repeats the docstrings
// verbatim modulo language to keep the cross-language token table
// reviewable at a glance.

/**
 * VAL-W10-011: JWS header `alg` is HS256 (or any symmetric MAC alg)
 * but the `kid` resolves to an asymmetric public JWK (kty=EC or
 * kty=OKP or kty=RSA). Surfacing this distinctly defeats the RFC 8725
 * section 3 RSA-public-key-as-HMAC-secret attack.
 *
 * Contract narrative spells this as RELAY-VERIFY-ALG-MISMATCH; the
 * wire code is the canonical RELAY-VERIFY-NNN form.
 */
export const RELAY_VERIFY_ALG_MISMATCH = "RELAY-VERIFY-010" as const;

/**
 * VAL-W10-014: JWS header `alg` is not in the allow-list
 * {EdDSA, ES256, RS256}. Includes `none`, `HS256`, `RS1`, unknown
 * vendor algorithms, and any other identifier outside the closed set.
 * Rejection MUST occur BEFORE any signature-verification primitive is
 * invoked; the `none` alg in particular MUST never reach a verify call
 * (RFC 8725 section 3.1).
 *
 * Contract narrative spells this as RELAY-VERIFY-UNSUPPORTED-ALG.
 */
export const RELAY_VERIFY_UNSUPPORTED_ALG = "RELAY-VERIFY-011" as const;

/**
 * VAL-W10-012 (structured detail code): detached-JWS payload digest
 * does not match the digest of the claim it is bound to. The verifier
 * recomputes the JCS canonical bytes of the claim payload, hashes
 * them, and compares to the digest recorded in the signature record.
 * Public-facing rejection code is RELAY-EVID-014; this local code is
 * carried in `details` for consumers branching on the underlying cause.
 */
export const RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH =
  "RELAY-VERIFY-012" as const;

/**
 * Public-facing evidence-bundle integrity error code (spec section B.4
 * line 3426). Surfaced when a detached-JWS payload digest mismatch is
 * detected (VAL-W10-012); also surfaced by the broader bundle verifier
 * for any tamper detection.
 */
export const RELAY_EVID_014 = "RELAY-EVID-014" as const;

export type RelayVerifyCode =
  | typeof RELAY_VERIFY_JWKS_UNAVAILABLE
  | typeof RELAY_VERIFY_BUNDLED_MISSING
  | typeof RELAY_VERIFY_CONFIG_INVALID
  | typeof RELAY_VERIFY_ALG_MISMATCH
  | typeof RELAY_VERIFY_UNSUPPORTED_ALG
  | typeof RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH
  | typeof RELAY_EVID_014;

/**
 * Base error for the verifier package. Carries a stable wire `code`
 * plus an optional structured `details` bag.
 */
export class RelayVerifierError extends Error {
  public readonly code: RelayVerifyCode | string;
  public readonly details: Record<string, unknown>;

  constructor(
    message: string,
    options: {
      code?: RelayVerifyCode | string;
      details?: Record<string, unknown>;
    } = {},
  ) {
    super(message);
    this.name = "RelayVerifierError";
    this.code = options.code ?? "RELAY-VERIFY-000";
    this.details = options.details ?? {};
  }
}
