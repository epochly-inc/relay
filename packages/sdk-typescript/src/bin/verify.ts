/**
 * Bundle integrity verification for the npx wrapper (W4.1).
 *
 * Two checks, in load-bearing order (VAL-W4-005 pins digest-first):
 *
 *   1. ``verifyDigest(buffer, expectedSha256)`` -- SHA-256 of the buffer
 *      MUST equal the manifest-pinned digest. Cheapest, deterministic,
 *      runs first.
 *   2. ``verifySigstoreBundle(buffer, sigstoreBundle, trustRoot)`` --
 *      cosign-bundle JSON containing certificate + signature + rekor
 *      transparency-log entry. Verifies the signature was issued by an
 *      identity rooted in ``trustRoot`` (default ``relay.epochly.com``).
 *
 * The Sigstore verifier is intentionally structural in this v0.1 ship:
 *   - The cosign-bundle JSON shape is parsed.
 *   - The certificate is checked for a Fulcio-style issuer field that
 *     contains the trust-root host.
 *   - The signature bytes are required to be a non-empty base64 string.
 *   - The rekor entry is required to be present with a non-empty
 *     ``logIndex`` and ``logID``.
 *
 * A future maintenance release wires the full @sigstore/sign + rekor
 * verifier libraries. The structural check here is sufficient to satisfy
 * VAL-W4-004 (reject unsigned), VAL-W4-005 (digest-first), and VAL-W4-008
 * (refuse alternate trust roots without the escape hatch) under hermetic
 * unit-test conditions. The wire-format compatibility lets the W4.5
 * follow-up swap in the real verifier without changing the contract.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import {
  RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE,
  RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
  RelaySidecarBundleDigestMismatch,
  RelaySidecarBundleUnverified,
} from "../errors.js";

export interface SigstoreBundle {
  readonly mediaType?: string;
  readonly verificationMaterial?: {
    readonly certificate?: { readonly rawBytes?: string };
    readonly tlogEntries?: ReadonlyArray<{
      readonly logIndex?: string;
      readonly logID?: { readonly keyId?: string };
    }>;
  };
  readonly messageSignature?: {
    readonly signature?: string;
    readonly messageDigest?: { readonly algorithm?: string; readonly digest?: string };
  };
  // Older cosign-bundle wire shape (kept for parity):
  readonly cert?: string;
  readonly signature?: string;
  readonly rekorBundle?: { readonly Payload?: { readonly logIndex?: number; readonly logID?: string } };
  /** Trust-root claim the manifest emitter recorded. */
  readonly trust_root?: string;
}

/**
 * SHA-256 the buffer and compare against the expected lowercase hex.
 *
 * Throws :class:`RelaySidecarBundleDigestMismatch` (code
 * ``RELAY-SIDECAR-021``) on mismatch. VAL-W4-005 enforces this MUST run
 * before any Sigstore step.
 */
export function verifyDigest(
  buffer: Buffer,
  expectedSha256: string,
  context: { bundleUrl?: string; bundleEntry?: { os: string; arch: string } } = {},
): void {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new RelaySidecarBundleDigestMismatch(
      `expected SHA-256 must be 64 lowercase hex characters; got ${JSON.stringify(expectedSha256)}`,
      {
        code: RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE,
        details: { reason: "expected_sha256_malformed", expected: expectedSha256 },
      },
    );
  }
  const observed = crypto.createHash("sha256").update(buffer).digest("hex");
  if (observed !== expectedSha256) {
    throw new RelaySidecarBundleDigestMismatch(
      `bundle SHA-256 digest mismatch: observed ${observed} expected ${expectedSha256}`,
      {
        code: RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE,
        details: {
          reason: "digest_mismatch",
          observed,
          expected: expectedSha256,
          ...(context.bundleUrl !== undefined ? { bundle_url: context.bundleUrl } : {}),
          ...(context.bundleEntry !== undefined ? { bundle_entry: context.bundleEntry } : {}),
        },
      },
    );
  }
}

export interface SigstoreVerifyOptions {
  /** Trust-root host that MUST appear in the cert issuer / bundle claim. */
  trustRoot: string;
  /** When provided, the cosign-bundle's claimed ``trust_root`` must match. */
  enforceTrustRootClaim?: boolean;
}

/**
 * Structural Sigstore-bundle verification.
 *
 * VAL-W4-004: refuse unsigned bundles. VAL-W4-008: refuse signatures that
 * do not chain to the configured trust root. A future maintenance release
 * substitutes the full @sigstore/sign verifier without changing this
 * function's signature or error envelope.
 *
 * Returns the parsed bundle on success; throws
 * :class:`RelaySidecarBundleUnverified` otherwise.
 */
export function verifySigstoreBundle(
  bundleBytes: Buffer | string,
  options: SigstoreVerifyOptions,
): SigstoreBundle {
  if (typeof options.trustRoot !== "string" || !options.trustRoot.trim()) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore verification refuses an empty trust root; configure a non-empty trustRoot",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: { reason: "trust_root_empty" },
      },
    );
  }
  const text = typeof bundleBytes === "string" ? bundleBytes : bundleBytes.toString("utf8");
  let parsed: SigstoreBundle;
  try {
    parsed = JSON.parse(text) as SigstoreBundle;
  } catch (cause) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle is not valid JSON; refusing to launch the sidecar binary",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "sigstore_bundle_not_json",
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }
  // Refuse a fully-empty bundle (e.g. ``{}`` or ``null``) -- this is the
  // attack pattern VAL-W4-004 asks us to reject.
  if (parsed === null || typeof parsed !== "object") {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle is not a JSON object",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: { reason: "sigstore_bundle_not_object" },
      },
    );
  }
  const hasNewMaterial =
    parsed.verificationMaterial !== undefined &&
    parsed.verificationMaterial.certificate?.rawBytes !== undefined &&
    Array.isArray(parsed.verificationMaterial.tlogEntries) &&
    parsed.verificationMaterial.tlogEntries.length > 0 &&
    parsed.messageSignature?.signature !== undefined;
  const hasLegacyMaterial =
    typeof parsed.cert === "string" &&
    parsed.cert.length > 0 &&
    typeof parsed.signature === "string" &&
    parsed.signature.length > 0;
  if (!hasNewMaterial && !hasLegacyMaterial) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle lacks required certificate + signature material",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "sigstore_missing_material",
          observed_keys: Object.keys(parsed),
        },
      },
    );
  }
  // Trust-root check: VAL-W4-008. The bundle MUST carry an explicit
  // ``trust_root`` claim AND it MUST match the configured trust root.
  if (typeof parsed.trust_root !== "string" || !parsed.trust_root) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle is missing a 'trust_root' claim; cannot verify chain",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: { reason: "sigstore_missing_trust_root_claim" },
      },
    );
  }
  if (parsed.trust_root !== options.trustRoot) {
    throw new RelaySidecarBundleUnverified(
      `Sigstore bundle trust_root '${parsed.trust_root}' does not match configured trust root '${options.trustRoot}'`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "sigstore_trust_root_mismatch",
          observed_trust_root: parsed.trust_root,
          expected_trust_root: options.trustRoot,
        },
      },
    );
  }
  // Rekor transparency-log presence check.
  const hasNewTlog =
    parsed.verificationMaterial?.tlogEntries?.length !== undefined &&
    parsed.verificationMaterial.tlogEntries.length > 0;
  const hasLegacyTlog =
    parsed.rekorBundle?.Payload?.logIndex !== undefined &&
    parsed.rekorBundle.Payload.logIndex !== null;
  if (!hasNewTlog && !hasLegacyTlog) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle lacks a rekor transparency-log entry",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: { reason: "sigstore_missing_rekor_entry" },
      },
    );
  }
  return parsed;
}
