/**
 * Fail-CLOSED Sigstore bundle verification for the npx wrapper
 * (W4.1 / W4.7 / VAL-CRYPTO-002, VAL-CRYPTO-003).
 *
 * Two checks, in load-bearing order (VAL-W4-005 pins digest-first):
 *
 *   1. ``verifyDigest(buffer, expectedSha256)`` -- SHA-256 of the buffer
 *      MUST equal the manifest-pinned digest. Cheapest, deterministic,
 *      runs first.
 *   2. ``verifySigstoreBundle(artifactBytes, sigstoreJson, options)`` --
 *      a REAL Sigstore bundle is verified with the official
 *      ``@sigstore/verify`` against a PINNED public-good Sigstore trusted
 *      root bundled in-repo at ``sigstore-trusted-root.json`` (no network
 *      fetch). This performs, fail-closed, ALL of:
 *        - Fulcio leaf certificate chain validation to the pinned root;
 *        - certificate validity-window enforcement (notBefore/notAfter vs
 *          the signing timestamp);
 *        - SCT (certificate-transparency-log) verification;
 *        - Rekor transparency-log INCLUSION-PROOF verification (RFC 6962
 *          Merkle inclusion + signed checkpoint) AND/OR the inclusion-promise
 *          SET signature;
 *        - the artifact signature verified over the actual bytes;
 *        - an EXACT certificate-identity policy match (SAN by anchored
 *          regex + the OIDC ``issuer`` extension by exact equality).
 *      On top of the library guarantees, Relay additionally enforces:
 *        - a CURVE pin (EC keys MUST be P-256, the Fulcio/cosign profile);
 *        - a REQUIRED ``messageDigest`` binding for messageSignature bundles:
 *          messageDigest == SHA-256(artifactBytes) == manifest entry.sha256.
 *
 * The Gate-2 structural review of the prior implementation found it
 * fail-OPEN against a self-minted cert: trust binding was a SUBSTRING
 * issuer match (``issuer.includes(trustRoot)``) with NO chain validation,
 * no validity check, no curve pin, a skippable messageDigest binding, and
 * only a structural presence check on the Rekor entry. Every one of those
 * holes is closed here by delegating to ``@sigstore/verify`` against the
 * pinned root with full thresholds plus the two Relay-specific guards.
 *
 * A missing/invalid signature, an unchained or expired cert, a non-P-256
 * curve, an absent/mismatched messageDigest, an identity-policy miss, or an
 * absent/invalid Rekor inclusion proof fails closed with
 * ``RelaySidecarBundleUnverified`` (RELAY-SIDECAR-020).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import {
  toSignedEntity,
  toTrustMaterial,
  type Signer,
  type TrustMaterial,
  type VerificationPolicy,
  Verifier,
} from "@sigstore/verify";

import {
  RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE,
  RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
  RelaySidecarBundleDigestMismatch,
  RelaySidecarBundleUnverified,
} from "../errors.js";

/**
 * Exact-identity policy for a verified signer. The ``subjectAlternativeName``
 * is an ANCHORED regular expression (``@sigstore/verify`` tests the SAN
 * against it via ``String.match``); use ``^...$`` so a SAN that merely
 * CONTAINS the trusted identity is rejected. The ``extensions.issuer`` is
 * matched by EXACT string equality (the OIDC issuer that minted the Fulcio
 * cert).
 */
export type SigstoreIdentityPolicy = VerificationPolicy;

/**
 * The production Relay sidecar-bundle signing identity. The release pipeline
 * (.github/workflows/release-sidecar-bundle.yml) keyless-signs each binary
 * and the aggregated manifest with the GitHub Actions OIDC identity for that
 * workflow. The SAN therefore looks like::
 *
 *   https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/vX.Y.Z
 *
 * minted by the issuer ``https://token.actions.githubusercontent.com``. The
 * anchored SAN regex pins the exact repo + workflow path and constrains the
 * trailing ``@<ref>`` to a release tag or branch ref so a substring/lookalike
 * SAN is rejected. The ``relay.epochly.com`` manifest ``trust_root`` field is
 * a Relay routing claim -- NOT the cryptographic trust anchor; the anchor is
 * the public Fulcio root + this exact GitHub Actions identity.
 */
export const RELAY_SIDECAR_IDENTITY_POLICY: SigstoreIdentityPolicy = Object.freeze({
  subjectAlternativeName:
    "^https://github\\.com/epochly-inc/relay/\\.github/workflows/release-sidecar-bundle\\.yml@refs/(tags/v[0-9]+\\.[0-9]+\\.[0-9]+[^/]*|heads/[^/]+)$",
  extensions: Object.freeze({ issuer: "https://token.actions.githubusercontent.com" }),
}) as SigstoreIdentityPolicy;

/**
 * Identity policy used ONLY by the W4.7 happy-path test, which verifies a
 * real recorded production Sigstore bundle (sigstore-js's own keyless-signed
 * provenance attestation). Exported so the test pins the recorded signer's
 * EXACT SAN + OIDC issuer rather than relaxing the production policy.
 */
export const REAL_SIGSTORE_HAPPY_PATH_POLICY: SigstoreIdentityPolicy = Object.freeze({
  subjectAlternativeName:
    "^https://github\\.com/sigstore/sigstore-js/\\.github/workflows/release\\.yml@refs/heads/main$",
  extensions: Object.freeze({ issuer: "https://token.actions.githubusercontent.com" }),
}) as SigstoreIdentityPolicy;

/** Curves accepted for an EC signing key. Fulcio/cosign profile: P-256. */
const ALLOWED_EC_CURVE = "prime256v1"; // OpenSSL name for NIST P-256 (secp256r1).
const ALLOWED_EC_NAMED_CURVES = new Set(["prime256v1", "p-256", "secp256r1"]);

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
  /**
   * Manifest-pinned lowercase-hex SHA-256 of the artifact bytes. For a
   * messageSignature bundle the bundle's ``messageDigest`` MUST equal both
   * SHA-256(artifactBytes) and this value, binding the signed artifact to
   * the manifest entry. Required for messageSignature bundles; ignored for
   * DSSE-envelope bundles (which carry their own signed payload).
   */
  expectedSha256?: string;
  /**
   * Exact-identity policy the verified signer MUST satisfy. Defaults to the
   * production Relay sidecar-bundle signing identity
   * (:data:`RELAY_SIDECAR_IDENTITY_POLICY`).
   */
  identityPolicy?: SigstoreIdentityPolicy;
  /**
   * Legacy field retained for source/ABI compatibility with the wrapper and
   * the manifest-signature path. It is NOT used as a cryptographic anchor:
   * the anchor is the pinned Fulcio root + the identity policy. A non-empty
   * value is still required so a caller cannot disable trust by omission.
   */
  trustRoot?: string;
}

/** Throw the canonical RELAY-SIDECAR-020 leaf with a structured reason. */
function unverified(message: string, reason: string, extra: Record<string, unknown> = {}): never {
  throw new RelaySidecarBundleUnverified(message, {
    code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
    details: { reason, ...extra },
  });
}

/**
 * Load + cache the pinned public-good Sigstore trusted root and build the
 * verification trust material once. The JSON is bundled in-repo (it ships in
 * the package ``files`` set) so verification never fetches over the network.
 */
let cachedTrustMaterial: TrustMaterial | null = null;
function pinnedTrustMaterial(): TrustMaterial {
  if (cachedTrustMaterial !== null) {
    return cachedTrustMaterial;
  }
  // Resolve the pinned root for BOTH layouts: running from source (vitest:
  // ``src/bin/verify.ts``) and from the published build (``dist/src/bin/
  // verify.js`` with the JSON shipped under ``src/bin/`` via the package
  // ``files`` set). Mirrors packages/verifier-typescript loadBundledJwks.
  const ASSET = "sigstore-trusted-root.json";
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(here, ASSET), // src/bin/ (vitest) or dist/src/bin/ if copied
    resolve(here, "..", "..", "..", "src", "bin", ASSET), // dist/src/bin -> src/bin
    resolve(here, "..", "..", "src", "bin", ASSET),
  ];
  let raw: string | null = null;
  let foundPath: string | null = null;
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      raw = fs.readFileSync(p, "utf8");
      foundPath = p;
      break;
    }
  }
  if (raw === null || raw.length === 0) {
    throw new RelaySidecarBundleUnverified(
      "pinned Sigstore trusted root is missing; cannot verify any bundle",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: { reason: "pinned_trusted_root_missing", searched: candidates },
      },
    );
  }
  void foundPath;
  const trustedRoot = TrustedRoot.fromJSON(JSON.parse(raw));
  cachedTrustMaterial = toTrustMaterial(trustedRoot);
  return cachedTrustMaterial;
}

/**
 * Enforce the EC P-256 curve pin (the Fulcio/cosign profile). A non-EC key,
 * or an EC key on any curve other than P-256, fails closed. Exported for a
 * direct unit guard. RSA/Ed25519 leaf certs are rejected: the production
 * signing profile is EC P-256.
 */
export function enforceP256Curve(cert: crypto.X509Certificate): void {
  const publicKey = cert.publicKey;
  const keyType = publicKey.asymmetricKeyType;
  if (keyType !== "ec") {
    unverified(
      `Sigstore leaf certificate key type ${JSON.stringify(keyType ?? "<unknown>")} is not EC P-256`,
      "sigstore_curve_not_ec",
      { observed_key_type: keyType ?? "<unknown>" },
    );
  }
  const details = publicKey.asymmetricKeyDetails;
  const namedCurve = (details?.namedCurve ?? "").toLowerCase();
  if (!ALLOWED_EC_NAMED_CURVES.has(namedCurve)) {
    unverified(
      `Sigstore leaf certificate EC curve ${JSON.stringify(namedCurve || "<unknown>")} is not the pinned ${ALLOWED_EC_CURVE} (P-256)`,
      "sigstore_curve_not_p256",
      { observed_curve: namedCurve || "<unknown>", expected_curve: ALLOWED_EC_CURVE },
    );
  }
}

/**
 * Pull the leaf X.509 certificate (DER) out of a parsed Sigstore bundle's
 * verification material, for the Relay curve pin. Returns null when the
 * bundle carries a bare public key (no cert) -- the production sidecar
 * profile always uses a Fulcio cert, so a bare key is itself a rejection.
 */
function leafCertificateDer(bundle: ReturnType<typeof bundleFromJSON>): Buffer | null {
  const material = bundle.verificationMaterial;
  const content = material.content;
  if (content.$case === "certificate") {
    return Buffer.from(content.certificate.rawBytes);
  }
  if (content.$case === "x509CertificateChain") {
    const first = content.x509CertificateChain.certificates[0];
    return first ? Buffer.from(first.rawBytes) : null;
  }
  return null;
}

/**
 * Require + bind the messageDigest for a messageSignature bundle. DSSE
 * bundles do not carry a messageDigest (their payload is the signed DSSE
 * envelope) and are exempt. For messageSignature bundles the messageDigest
 * MUST be present, equal SHA-256(artifactBytes), and -- when provided --
 * equal the manifest-pinned ``expectedSha256``.
 */
function bindMessageDigest(
  bundle: ReturnType<typeof bundleFromJSON>,
  artifactBytes: Buffer | undefined,
  expectedSha256: string | undefined,
): void {
  if (bundle.content.$case !== "messageSignature") {
    return; // DSSE: nothing to bind here.
  }
  const messageDigest = bundle.content.messageSignature.messageDigest;
  const digestBytes = messageDigest?.digest;
  if (digestBytes === undefined || digestBytes.length === 0) {
    unverified(
      "Sigstore messageSignature bundle is missing the required messageDigest binding",
      "sigstore_message_digest_absent",
    );
  }
  const claimedHex = Buffer.from(digestBytes).toString("hex");
  if (artifactBytes === undefined) {
    unverified(
      "messageSignature bundle requires the artifact bytes to bind messageDigest",
      "sigstore_message_signature_requires_artifact",
    );
  }
  const actualHex = crypto.createHash("sha256").update(artifactBytes).digest("hex");
  if (claimedHex !== actualHex) {
    unverified(
      "Sigstore messageDigest does not equal SHA-256 of the artifact bytes",
      "sigstore_message_digest_mismatch",
      { claimed_digest: claimedHex, observed_digest: actualHex },
    );
  }
  if (
    typeof expectedSha256 === "string" &&
    expectedSha256.length > 0 &&
    claimedHex !== expectedSha256.toLowerCase()
  ) {
    unverified(
      "Sigstore messageDigest does not equal the manifest-pinned entry.sha256",
      "sigstore_message_digest_manifest_mismatch",
      { claimed_digest: claimedHex, manifest_digest: expectedSha256 },
    );
  }
}

/**
 * Real, fail-CLOSED Sigstore-bundle verification (VAL-CRYPTO-002/003).
 *
 * @param artifactBytes The bytes the signature is computed over (the sidecar
 *   binary blob / manifest bytes). Pass ``undefined`` for a DSSE-envelope
 *   bundle whose payload is self-contained.
 * @param sigstoreJson The Sigstore bundle JSON (protobuf-bundle wire form).
 * @param options Verification options (manifest digest + identity policy).
 * @returns The verified :class:`Signer` (key + identity) on success.
 * @throws RelaySidecarBundleUnverified on ANY verification failure.
 */
export function verifySigstoreBundle(
  artifactBytes: Buffer | string | undefined,
  sigstoreJson: string | Buffer,
  options: SigstoreVerifyOptions = {},
): Signer {
  const artifact =
    artifactBytes === undefined
      ? undefined
      : Buffer.isBuffer(artifactBytes)
        ? artifactBytes
        : Buffer.from(artifactBytes, "utf8");
  const text = typeof sigstoreJson === "string" ? sigstoreJson : sigstoreJson.toString("utf8");

  // Parse the bundle as a REAL Sigstore bundle. The forged/legacy shapes the
  // old structural check accepted (bare ``{cert, signature, trust_root}``)
  // are not valid Sigstore bundles and are rejected here, fail-closed.
  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(text);
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
  let bundle: ReturnType<typeof bundleFromJSON>;
  try {
    bundle = bundleFromJSON(parsedJson);
  } catch (cause) {
    throw new RelaySidecarBundleUnverified(
      "Sigstore bundle is not a valid Sigstore protobuf bundle",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "sigstore_bundle_invalid",
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }

  // Relay curve pin (EC P-256). Done before the heavy verification so an
  // out-of-profile key is rejected promptly.
  const leafDer = leafCertificateDer(bundle);
  if (leafDer === null) {
    unverified(
      "Sigstore bundle does not carry a Fulcio leaf certificate (bare public keys are not accepted)",
      "sigstore_no_leaf_certificate",
    );
  }
  let leafCert: crypto.X509Certificate;
  try {
    leafCert = new crypto.X509Certificate(leafDer);
  } catch (cause) {
    return unverified(
      "Sigstore leaf certificate is not a parseable X.509 certificate",
      "sigstore_certificate_unparseable",
      { cause_message: cause instanceof Error ? cause.message : String(cause) },
    );
  }
  enforceP256Curve(leafCert);

  // Require + bind the messageDigest for messageSignature bundles.
  bindMessageDigest(bundle, artifact, options.expectedSha256);

  // Build the signed entity and run the full Sigstore verification against
  // the PINNED public-good trusted root with FULL thresholds:
  //   - tlogThreshold: 1   -> at least one verified Rekor inclusion proof/SET
  //   - ctlogThreshold: 1  -> at least one verified SCT
  //   - timestampThreshold: 1 -> at least one verified timestamp
  // This enforces chain-to-pinned-root, validity window, SCT, Rekor Merkle
  // inclusion + checkpoint, and signature-over-bytes -- fail-closed.
  const trustMaterial = pinnedTrustMaterial();
  const verifier = new Verifier(trustMaterial, {
    tlogThreshold: 1,
    ctlogThreshold: 1,
    timestampThreshold: 1,
  });
  const policy = options.identityPolicy ?? RELAY_SIDECAR_IDENTITY_POLICY;
  let signer: Signer;
  try {
    const entity = toSignedEntity(bundle, artifact);
    signer = verifier.verify(entity, policy);
  } catch (cause) {
    return unverified(
      "Sigstore bundle failed fail-closed verification against the pinned trusted root",
      "sigstore_verification_failed",
      {
        cause_code: (cause as { code?: unknown })?.code ?? "<unknown>",
        cause_message: cause instanceof Error ? cause.message : String(cause),
      },
    );
  }
  return signer;
}
