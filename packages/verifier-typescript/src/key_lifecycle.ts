// Signing-key lifecycle checks for the bundle validator (TS parity with
// packages/verifier/src/relay_verifier/key_lifecycle.py).
//
// Per spec sections L.1 (line 4452 not_before/not_after) and L.4 (lines
// 4469-4472 revocation) every JWK in the trust anchor MAY carry the
// following lifecycle annotations:
//
//   {
//     "kid": "<key id>",
//     "kty": "OKP" | "EC" | "RSA",
//     ...
//     "not_before": "2026-01-01T00:00:00Z",
//     "not_after":  "2027-01-01T00:00:00Z",
//     "revoked_at": "2026-06-15T12:00:00Z"
//   }
//
// The +/-300 s constant is re-exported from tsa.ts (single source of truth).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { CLOCK_SKEW_TOLERANCE_SECONDS } from "./tsa.js";

export const RELAY_EVID_041 = "RELAY-EVID-041" as const;
/** Signer key expired: now > not_after + 300s tolerance (VAL-W10-032). */

export const RELAY_EVID_042 = "RELAY-EVID-042" as const;
/** Signer key revoked: bundle signed AFTER revoked_at (VAL-W10-033). */

export interface KeyLifecycleResult {
  /**
   * One of: "ok", "expired", "revoked", "premature", "missing_window".
   * Mirrors the Python KeyLifecycleResult.
   */
  outcome: "ok" | "expired" | "revoked" | "premature" | "missing_window";
  reason: string;
  code: string;
  signer_key_revoked: boolean;
  signer_key_revoked_at: string;
}

function _parseIsoZ(s: string): Date {
  if (typeof s !== "string" || s.length === 0) {
    throw new Error(`timestamp must be a non-empty string, got ${JSON.stringify(s)}`);
  }
  if (!s.endsWith("Z")) {
    throw new Error(`timestamp must end with 'Z' (UTC), got ${JSON.stringify(s)}`);
  }
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) {
    throw new Error(`timestamp not parseable as ISO-8601: ${JSON.stringify(s)}`);
  }
  return new Date(ms);
}

function _newResult(): KeyLifecycleResult {
  return {
    outcome: "ok",
    reason: "",
    code: "",
    signer_key_revoked: false,
    signer_key_revoked_at: "",
  };
}

/**
 * Apply VAL-W10-031..034 lifecycle checks to a JWK. Mirrors
 * `relay_verifier.key_lifecycle.check_signing_key_lifecycle`.
 *
 * Returns a `KeyLifecycleResult`; never throws. Every reject path is
 * encoded in `outcome`/`code` so the caller can aggregate verdicts.
 */
export function checkSigningKeyLifecycle(args: {
  jwk: Record<string, unknown>;
  bundleSignedAt: string;
  auditorNow?: Date;
  toleranceSeconds?: number;
}): KeyLifecycleResult {
  const auditorNow = args.auditorNow ?? new Date();
  const tolerance = args.toleranceSeconds ?? CLOCK_SKEW_TOLERANCE_SECONDS;
  const result = _newResult();
  const jwk = args.jwk;

  // Parse signed_at first; required for revocation comparison.
  let signedAt: Date;
  try {
    signedAt = _parseIsoZ(args.bundleSignedAt);
  } catch (exc) {
    result.outcome = "expired";
    result.reason = `bundle signed_at unparsable: ${(exc as Error).message}`;
    result.code = RELAY_EVID_041;
    return result;
  }

  // Revocation surface.
  const revokedAtRaw = jwk["revoked_at"];
  if (typeof revokedAtRaw === "string" && revokedAtRaw.length > 0) {
    result.signer_key_revoked = true;
    result.signer_key_revoked_at = revokedAtRaw;
    let revokedAt: Date;
    try {
      revokedAt = _parseIsoZ(revokedAtRaw);
    } catch (exc) {
      result.outcome = "revoked";
      result.reason = `jwk.revoked_at unparsable: ${(exc as Error).message}`;
      result.code = RELAY_EVID_042;
      return result;
    }
    if (signedAt.getTime() > revokedAt.getTime()) {
      result.outcome = "revoked";
      result.reason =
        `bundle signed at ${args.bundleSignedAt} AFTER key revoked at ${revokedAtRaw}`;
      result.code = RELAY_EVID_042;
      return result;
    }
    // signed_at <= revoked_at: surfaced as WARN by caller; not rejected here.
  }

  const notBeforeRaw = jwk["not_before"];
  const notAfterRaw = jwk["not_after"];

  if (
    (notBeforeRaw === undefined || notBeforeRaw === null) &&
    (notAfterRaw === undefined || notAfterRaw === null)
  ) {
    result.outcome = "missing_window";
    result.reason =
      "JWK does not declare not_before/not_after; verifier accepts " +
      "but surfaces the missing-window state";
    return result;
  }

  if (typeof notBeforeRaw === "string" && notBeforeRaw.length > 0) {
    let notBefore: Date;
    try {
      notBefore = _parseIsoZ(notBeforeRaw);
    } catch (exc) {
      result.outcome = "premature";
      result.reason = `jwk.not_before unparsable: ${(exc as Error).message}`;
      result.code = RELAY_EVID_041;
      return result;
    }
    const skew = Math.trunc((notBefore.getTime() - auditorNow.getTime()) / 1000);
    if (skew > tolerance) {
      result.outcome = "premature";
      result.reason =
        `key not_before ${notBeforeRaw} is ${skew}s in the future, ` +
        `exceeding +/-${tolerance}s tolerance`;
      result.code = RELAY_EVID_041;
      return result;
    }
  }

  if (typeof notAfterRaw === "string" && notAfterRaw.length > 0) {
    let notAfter: Date;
    try {
      notAfter = _parseIsoZ(notAfterRaw);
    } catch (exc) {
      result.outcome = "expired";
      result.reason = `jwk.not_after unparsable: ${(exc as Error).message}`;
      result.code = RELAY_EVID_041;
      return result;
    }
    const skew = Math.trunc((auditorNow.getTime() - notAfter.getTime()) / 1000);
    if (skew > tolerance) {
      result.outcome = "expired";
      result.reason =
        `key not_after ${notAfterRaw} is ${skew}s in the past, ` +
        `exceeding +/-${tolerance}s tolerance`;
      result.code = RELAY_EVID_041;
      return result;
    }
  }

  return result;
}
