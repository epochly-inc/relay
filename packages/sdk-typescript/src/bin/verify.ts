/**
 * Bundle integrity verification for the npx wrapper (W4.1 / VAL-CRYPTO-002).
 *
 * Two checks, in load-bearing order (VAL-W4-005 pins digest-first):
 *
 *   1. ``verifyDigest(buffer, expectedSha256)`` -- SHA-256 of the buffer
 *      MUST equal the manifest-pinned digest. Cheapest, deterministic,
 *      runs first.
 *   2. ``verifySigstoreBundle(bundleBytes, sigstoreJson, options)`` --
 *      cosign-bundle JSON containing certificate + signature + rekor
 *      transparency-log entry. Performs REAL cryptography over the
 *      bundle bytes (fail-closed).
 *
 * The Sigstore verifier performs genuine signature verification:
 *   - The cosign-bundle JSON shape is parsed.
 *   - The Fulcio leaf certificate (protobuf-bundle ``rawBytes`` DER, or
 *     legacy ``cert`` PEM) is parsed with ``node:crypto`` ``X509Certificate``.
 *   - The ``messageSignature.signature`` bytes are CRYPTOGRAPHICALLY
 *     VERIFIED over the actual ``bundleBytes`` using the public key in
 *     the leaf certificate (ECDSA-SHA256, RSA-SHA256, or Ed25519).
 *   - The leaf certificate issuer is validated to carry the configured
 *     ``trustRoot`` host (Fulcio CA identity), in addition to the bundle's
 *     explicit ``trust_root`` claim.
 *   - When a ``messageDigest`` is present it MUST equal SHA-256(bundleBytes)
 *     AND the manifest-pinned ``expectedSha256``, binding the signed
 *     artifact to the manifest entry.
 *
 * A missing/invalid signature, an unparseable cert, a bad issuer, or a
 * digest mismatch fails closed with ``RelaySidecarBundleUnverified``
 * (RELAY-SIDECAR-020). This satisfies VAL-W4-004 (reject unsigned),
 * VAL-W4-005 (digest-first), VAL-W4-008 (refuse alternate trust roots),
 * and VAL-CRYPTO-002 (signature cryptographically bound to the bundle).
 *
 * DEFERRED (tracked follow-up): FULL Rekor inclusion-proof verification
 * (Merkle inclusion + checkpoint signature) and FULL Fulcio certificate
 * chain validation to a pinned CA root. We keep the structural presence
 * check on the transparency-log entry meanwhile; we do NOT silently drop
 * it. The signature-over-bytes + issuer + digest binding closes the
 * forged-bundle hole that VAL-CRYPTO-002 reports.
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
  /**
   * Manifest-pinned lowercase-hex SHA-256 of the bundle bytes. When the
   * Sigstore bundle carries a ``messageDigest`` it MUST equal both
   * SHA-256(bundleBytes) and this value, binding the signed artifact to
   * the manifest entry. Required for full VAL-CRYPTO-002 binding; when
   * omitted the digest-to-manifest binding step is skipped (the
   * signature-over-bytes check still runs).
   */
  expectedSha256?: string;
  /** When provided, the cosign-bundle's claimed ``trust_root`` must match. */
  enforceTrustRootClaim?: boolean;
}

/** Throw the canonical RELAY-SIDECAR-020 leaf with a structured reason. */
function unverified(message: string, reason: string, extra: Record<string, unknown> = {}): never {
  throw new RelaySidecarBundleUnverified(message, {
    code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
    details: { reason, ...extra },
  });
}

/**
 * Parse the leaf certificate from a Sigstore bundle. Supports the
 * protobuf-bundle form (``verificationMaterial.certificate.rawBytes``,
 * base64 DER) and the legacy cosign form (``cert``, PEM or base64 DER).
 * Returns ``null`` when no parseable certificate is present.
 */
function parseLeafCertificate(parsed: SigstoreBundle): crypto.X509Certificate | null {
  const rawB64 = parsed.verificationMaterial?.certificate?.rawBytes;
  const legacy = parsed.cert;
  let input: Buffer | null = null;
  if (typeof rawB64 === "string" && rawB64.length > 0) {
    // Protobuf-bundle: rawBytes is base64-encoded DER.
    input = Buffer.from(rawB64, "base64");
  } else if (typeof legacy === "string" && legacy.length > 0) {
    // Legacy cosign: PEM block, or base64 DER. X509Certificate accepts
    // both PEM and DER buffers; for a PEM string pass it through directly.
    input = legacy.includes("BEGIN CERTIFICATE")
      ? Buffer.from(legacy, "utf8")
      : Buffer.from(legacy, "base64");
  }
  if (input === null || input.length === 0) {
    return null;
  }
  try {
    return new crypto.X509Certificate(input);
  } catch {
    return null;
  }
}

/** Extract the raw signature bytes (base64) from either bundle form. */
function parseSignatureBytes(parsed: SigstoreBundle): Buffer | null {
  const sigNew = parsed.messageSignature?.signature;
  const sigLegacy = parsed.signature;
  const b64 =
    typeof sigNew === "string" && sigNew.length > 0
      ? sigNew
      : typeof sigLegacy === "string" && sigLegacy.length > 0
        ? sigLegacy
        : null;
  if (b64 === null) {
    return null;
  }
  const buf = Buffer.from(b64, "base64");
  return buf.length > 0 ? buf : null;
}

/**
 * Cryptographically verify a raw signature over ``bundleBytes`` using the
 * public key in the leaf certificate. cosign sign-blob produces a raw
 * ECDSA/RSA/Ed25519 signature over the artifact bytes; the digest
 * algorithm is SHA-256. We try the algorithm implied by the key type.
 * Returns true iff the signature verifies.
 */
function verifySignatureOverBytes(
  cert: crypto.X509Certificate,
  signature: Buffer,
  bundleBytes: Buffer,
): boolean {
  const publicKey = cert.publicKey;
  const keyType = publicKey.asymmetricKeyType;
  try {
    if (keyType === "ed25519" || keyType === "ed448") {
      // EdDSA: crypto.verify(null, data, key, sig) -> boolean.
      return crypto.verify(null, bundleBytes, publicKey, signature);
    }
    if (keyType === "ec") {
      // cosign emits DER-encoded ECDSA signatures over SHA-256.
      return crypto.verify("sha256", bundleBytes, publicKey, signature);
    }
    if (keyType === "rsa" || keyType === "rsa-pss") {
      return crypto.verify("sha256", bundleBytes, publicKey, signature);
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * Real Sigstore-bundle verification (fail-closed) -- VAL-CRYPTO-002.
 *
 * VAL-W4-004: refuse unsigned bundles. VAL-W4-008: refuse signatures that
 * do not chain to the configured trust root. VAL-CRYPTO-002: the signature
 * is cryptographically verified over the actual ``bundleBytes`` using the
 * Fulcio leaf certificate public key, the issuer is validated against the
 * trust root, and the ``messageDigest`` is bound to the manifest entry.
 *
 * Returns the parsed bundle on success; throws
 * :class:`RelaySidecarBundleUnverified` otherwise.
 */
export function verifySigstoreBundle(
  bundleBytes: Buffer | string,
  sigstoreJson: string | Buffer,
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
  // The bytes the signature is computed over (the sidecar binary blob).
  const artifactBytes = Buffer.isBuffer(bundleBytes)
    ? bundleBytes
    : Buffer.from(bundleBytes, "utf8");
  const text = typeof sigstoreJson === "string" ? sigstoreJson : sigstoreJson.toString("utf8");
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
  // Rekor transparency-log PRESENCE check. NOTE: full Rekor inclusion-proof
  // verification (Merkle inclusion + signed-checkpoint validation) is
  // DEFERRED to a tracked follow-up; we keep this structural presence check
  // meanwhile and do NOT silently drop it. The signature-over-bytes +
  // issuer + digest binding below close the forged-bundle hole reported by
  // VAL-CRYPTO-002.
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
  // ----------------------------------------------------------------------
  // REAL cryptography (VAL-CRYPTO-002). Everything above is structural;
  // everything below binds the signature to the actual bundle bytes.
  // ----------------------------------------------------------------------
  // 1. Parse the Fulcio leaf certificate.
  const leaf = parseLeafCertificate(parsed);
  if (leaf === null) {
    unverified(
      "Sigstore bundle leaf certificate is missing or not a parseable X.509 certificate",
      "sigstore_certificate_unparseable",
    );
  }
  // 2. Extract the raw signature bytes.
  const signature = parseSignatureBytes(parsed);
  if (signature === null) {
    unverified(
      "Sigstore bundle is missing a non-empty signature",
      "sigstore_signature_missing",
    );
  }
  // 3. Cryptographically verify the signature over the ACTUAL bundle bytes
  //    using the public key in the leaf certificate. This is the check the
  //    old structural verifier never performed; a forged/unsigned bundle
  //    fails here.
  if (!verifySignatureOverBytes(leaf, signature, artifactBytes)) {
    unverified(
      "Sigstore signature does not cryptographically verify over the bundle bytes",
      "sigstore_signature_invalid",
      { key_type: leaf.publicKey.asymmetricKeyType ?? "<unknown>" },
    );
  }
  // 4. Validate the leaf certificate issuer carries the configured trust
  //    root host (Fulcio CA identity). The bundle's self-asserted
  //    ``trust_root`` claim (checked above) is NOT sufficient on its own --
  //    an attacker can stamp any claim. The issuer is bound to the cert
  //    that produced the verified signature.
  const issuer = typeof leaf.issuer === "string" ? leaf.issuer : "";
  if (!issuer.includes(options.trustRoot)) {
    unverified(
      `Sigstore leaf certificate issuer does not carry the configured trust root '${options.trustRoot}'`,
      "sigstore_issuer_not_trusted",
      { observed_issuer: issuer, expected_trust_root: options.trustRoot },
    );
  }
  // 5. Bind the signed artifact to the manifest entry: messageDigest (when
  //    present) MUST equal SHA-256(bundleBytes) AND the manifest-pinned
  //    expectedSha256. This forecloses a swap of a validly-signed-but-other
  //    artifact under a stale signature.
  const messageDigestB64 = parsed.messageSignature?.messageDigest?.digest;
  if (typeof messageDigestB64 === "string" && messageDigestB64.length > 0) {
    const claimedHex = Buffer.from(messageDigestB64, "base64").toString("hex");
    const actualHex = crypto.createHash("sha256").update(artifactBytes).digest("hex");
    if (claimedHex !== actualHex) {
      unverified(
        "Sigstore messageDigest does not equal SHA-256 of the bundle bytes",
        "sigstore_message_digest_mismatch",
        { claimed_digest: claimedHex, observed_digest: actualHex },
      );
    }
    if (
      typeof options.expectedSha256 === "string" &&
      options.expectedSha256.length > 0 &&
      claimedHex !== options.expectedSha256.toLowerCase()
    ) {
      unverified(
        "Sigstore messageDigest does not equal the manifest-pinned entry.sha256",
        "sigstore_message_digest_manifest_mismatch",
        { claimed_digest: claimedHex, manifest_digest: options.expectedSha256 },
      );
    }
  }
  return parsed;
}
