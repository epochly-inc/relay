// End-to-end evidence bundle validator (TS parity with
// packages/verifier/src/relay_verifier/bundle_validator.py).
//
// Orchestrates the verifier sub-modules into a single `validateBundle`
// entry point that produces the canonical verifier output envelope
// (schema_version `relay.verifier.output.v1`).
//
// Validation pipeline (each step contributes to the output):
//   1. Archive-bomb gate (VAL-W10-036)
//   2. Structure + per-claim digest (VAL-W10-020 / 022)
//   3. JWS verification (VAL-W10-021 / 023 / 014)
//   4. Merkle root (VAL-W10-024)
//   5. TSA timestamp (VAL-W10-025..027)
//   6. Transparency-log inclusion (VAL-W10-028..030)
//   7. Signer key lifecycle (VAL-W10-031..034)
//   8. trust_anchor surfacing (VAL-W10-035 / 041)
//   9. Subject resolution (VAL-W10-037 / 038)
//
// Output is a plain object whose JCS serialisation matches the Python
// orchestrator's for the same fixture (VAL-V2M06-022).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createHash } from "node:crypto";

import { checkArtifactPath } from "./bundle_paths.js";
import { jcsCanonicalize, bundleDigest } from "./canonical.js";
import { DEFAULT_JWKS_URL } from "./constants.js";
import {
  RELAY_EVID_041,
  RELAY_EVID_042,
  checkSigningKeyLifecycle,
  type KeyLifecycleResult,
} from "./key_lifecycle.js";
import { computeMerkleRoot } from "./merkle.js";
import {
  SUBJECT_RESOLUTION_UNKNOWN,
  type SubjectStore,
  resolveSubject,
} from "./retention.js";
import { verifyLogInclusion } from "./transparency_log.js";
import {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  RELAY_EVID_031,
  RELAY_EVID_038,
  validateTsaToken,
  type TsaToken,
} from "./tsa.js";
import {
  _selectJwk,
  canonicalJsonBytes,
  verifyBundleSignature,
  verifyDetachedClaimSignature,
  type BundleSignatureEntry,
  type JWK,
  type JWKS,
  type SignatureCheck,
} from "./verifier.js";

export const VERIFIER_OUTPUT_SCHEMA = "relay.verifier.output.v1" as const;

export const MAX_BUNDLE_ENTRIES = 4096;
export const MAX_BUNDLE_BYTES = 256 * 1024 * 1024;

/**
 * Maximum number of cross-signing signatures the verifier will accept on
 * a single bundle. Per spec section L.5 line 4481 / VAL-V2M08-041 (parity
 * with Python `MAX_BUNDLE_SIGNATURES`).
 *
 * A bundle carrying more than this many signatures is rejected
 * fail-closed BEFORE any per-signature cryptographic work runs. Defends
 * against (1) producers padding bundles with hundreds of dummy
 * signatures to amplify verification cost (DoS); and (2) producers
 * abusing the cross-signing slot for non-signature data.
 */
export const MAX_BUNDLE_SIGNATURES = 4;

export const RELAY_EVID_024 = "RELAY-EVID-024" as const;
/** Archive-bomb limit exceeded (VAL-W10-036). */

export const RELAY_EVID_014 = "RELAY-EVID-014" as const;
/** Evidence-bundle integrity failure (per-claim signature). */

export const RELAY_EVID_040 = "RELAY-EVID-040" as const;
/** Merkle root mismatch (VAL-W10-024). */

export const RELAY_EVID_SIGCOUNT_EXCEEDED =
  "RELAY-EVID-SIGCOUNT-EXCEEDED" as const;
/**
 * Bundle carries more than {@link MAX_BUNDLE_SIGNATURES} signatures
 * (VAL-V2M08-041). Surfaced in {@link validateBundle} output as a
 * structured error with `signatures_present` echoing the wire count so
 * operators can identify the over-cap producer.
 */

export const RELAY_EVID_MISSING_TRUST_ANCHOR =
  "RELAY-EVID-MISSING-TRUST-ANCHOR" as const;
/**
 * Bundle is missing the top-level `trust_anchor` field (or the field is
 * not a non-empty string) (VAL-V2M08-043). Per spec section AO.4 line
 * 6166 every signed bundle MUST declare its trust anchor; absence means
 * the verifier cannot classify the bundle against the operator's trust
 * posture and the bundle is rejected fail-closed.
 */

export const RELAY_EVID_DECIDED_AT_MISSING =
  "RELAY-EVID-DECIDED-AT-MISSING" as const;
/**
 * Bundle missing the canonical `decided_at` TSA-binding anchor. The
 * validator MUST NOT silently fall back to `generated_at` or any other
 * sibling timestamp.
 */

export const TRUST_ANCHOR_LOCAL_DEV = "local_dev" as const;
export const WARN_LOCAL_DEV_UNSUPPORTED = "local_dev_unsupported_for_audit" as const;

// w8-trust-anchor: trust_anchor_class output enum (VAL-V2M08-044).
// Per spec section AO.4 lines 6164-6168 the verifier MUST classify the
// bundle's declared trust_anchor into one of three buckets, derived ONLY
// from the bundle's declared value (NEVER from the JWKS URL the verifier
// happens to be running under). A `local_dev` bundle stays
// `untrusted_local` even when the verifier is configured with the
// Relay-Inc default anchor.
export const TRUST_ANCHOR_CLASS_RELAY_INC = "relay_inc" as const;
export const TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL = "untrusted_local" as const;
export const TRUST_ANCHOR_CLASS_BYO = "byo" as const;

export type TrustAnchorClass =
  | ""
  | typeof TRUST_ANCHOR_CLASS_RELAY_INC
  | typeof TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL
  | typeof TRUST_ANCHOR_CLASS_BYO;

/**
 * Return the `trust_anchor_class` for a bundle-declared `trust_anchor`.
 *
 * Mirrors `relay_verifier.bundle_validator.classify_trust_anchor` so
 * Python and TypeScript verifiers emit the same classification for the
 * same wire value (VAL-V2M08-044).
 *
 * Returns:
 *   - {@link TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL} when value equals the
 *     `local_dev` sentinel.
 *   - {@link TRUST_ANCHOR_CLASS_RELAY_INC} when value is a URL whose
 *     host is `relay.epochly.com` AND whose path ends with
 *     `/.well-known/jwks.json`. The exact-path check defends against a
 *     producer pointing at an attacker-controlled path on the Relay-Inc
 *     host (e.g. `https://relay.epochly.com/evil`).
 *   - {@link TRUST_ANCHOR_CLASS_BYO} for any other non-empty string.
 *   - `""` when value is missing, non-string, or empty; caller emits
 *     {@link RELAY_EVID_MISSING_TRUST_ANCHOR} separately.
 */
export function classifyTrustAnchor(trustAnchorValue: unknown): TrustAnchorClass {
  if (typeof trustAnchorValue !== "string" || trustAnchorValue.length === 0) {
    return "";
  }
  if (trustAnchorValue === TRUST_ANCHOR_LOCAL_DEV) {
    return TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL;
  }
  let parsed: URL;
  try {
    parsed = new URL(trustAnchorValue);
  } catch {
    // Python's urlparse never raises on non-URL strings; it returns an
    // empty hostname. WHATWG URL throws on non-absolute strings -- treat
    // those as BYO to preserve Python's "any other non-empty string"
    // semantics.
    return TRUST_ANCHOR_CLASS_BYO;
  }
  const host = (parsed.hostname || "").trim().toLowerCase();
  if (host === "relay.epochly.com" && parsed.pathname.endsWith("/.well-known/jwks.json")) {
    return TRUST_ANCHOR_CLASS_RELAY_INC;
  }
  return TRUST_ANCHOR_CLASS_BYO;
}

export interface ValidateBundleOptions {
  strict_log?: boolean;
  strict_trust_anchor?: boolean;
  auditor_now?: Date;
  artifact_resolver?: ((artifactId: string) => Uint8Array | null) | null;
  subject_store?: SubjectStore | null;
  witness_jwks?: JWKS | Record<string, unknown> | null;
  default_trust_anchor?: string | null;
}

export interface VerifierOutputEnvelope {
  schema_version: string;
  overall: "pass" | "fail";
  bundle_path: string;
  bundle_digest_sha256: string;
  digest_ok: boolean;
  structure_ok: boolean;
  signatures_ok: boolean;
  signatures_checked: Array<{
    kid: string;
    alg: string;
    ok: boolean;
    reason: string;
    code: string;
  }>;
  /**
   * VAL-V2M08-041. Wire count of signature entries the producer attached
   * to the bundle, surfaced regardless of per-signature outcomes so
   * consumers can detect the over-cap-rejection case
   * (`signatures_present > MAX_BUNDLE_SIGNATURES`).
   */
  signatures_present: number;
  claims_count: number;
  merkle_check: "ok" | "absent" | "mismatch";
  tsa_check: "ok" | "missing" | "invalid" | "skew";
  log_inclusion: "ok" | "absent" | "witness_mismatch";
  trust_anchor: string;
  /**
   * VAL-V2M08-044. Classification of the bundle's declared `trust_anchor`
   * value. Derived ONLY from the bundle's declared anchor, never from
   * the JWKS URL the verifier is configured with. Empty string when the
   * bundle is missing the `trust_anchor` field; the verifier also emits
   * {@link RELAY_EVID_MISSING_TRUST_ANCHOR} in that case.
   */
  trust_anchor_class: TrustAnchorClass;
  trust_anchor_source: string;
  signer_key_revoked: boolean;
  signer_key_revoked_at: string | null;
  subject_resolution: string;
  warnings: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
  details?: Record<string, unknown>;
}

function _newOutput(): VerifierOutputEnvelope {
  return {
    schema_version: VERIFIER_OUTPUT_SCHEMA,
    overall: "fail",
    bundle_path: "",
    bundle_digest_sha256: "",
    digest_ok: false,
    structure_ok: false,
    signatures_ok: false,
    signatures_checked: [],
    // w8-trust-anchor: wire count of signatures the producer attached to
    // the bundle, surfaced regardless of per-signature outcomes so
    // consumers can detect the over-cap-rejection case (VAL-V2M08-041).
    signatures_present: 0,
    claims_count: 0,
    merkle_check: "absent",
    tsa_check: "missing",
    log_inclusion: "absent",
    trust_anchor: "",
    // w8-trust-anchor: classification of the bundle's declared
    // trust_anchor field (VAL-V2M08-044). Empty string when the bundle
    // lacks a declarable trust_anchor (which also produces a structural
    // error via RELAY-EVID-MISSING-TRUST-ANCHOR).
    trust_anchor_class: "",
    trust_anchor_source: "",
    signer_key_revoked: false,
    signer_key_revoked_at: null,
    subject_resolution: SUBJECT_RESOLUTION_UNKNOWN,
    warnings: [],
    errors: [],
  };
}

function _appendWarning(
  output: VerifierOutputEnvelope,
  args: { reason: string; message: string; code?: string },
): void {
  const entry: Record<string, unknown> = { reason: args.reason, message: args.message };
  if (args.code) {
    entry["code"] = args.code;
  }
  output.warnings.push(entry);
}

function _appendError(
  output: VerifierOutputEnvelope,
  args: { reason: string; message: string; code?: string },
): void {
  const entry: Record<string, unknown> = { reason: args.reason, message: args.message };
  if (args.code) {
    entry["code"] = args.code;
  }
  output.errors.push(entry);
}

function _claimDigestsInOrder(bundle: Record<string, unknown>): string[] {
  const claims = bundle["claims"];
  if (!Array.isArray(claims)) {
    return [];
  }
  const out: string[] = [];
  for (const claim of claims) {
    if (claim !== null && typeof claim === "object" && !Array.isArray(claim)) {
      out.push(bundleDigest(claim, { stripSignatures: true }));
    } else {
      out.push(createHash("sha256").update(jcsCanonicalize(claim)).digest("hex"));
    }
  }
  return out;
}

/**
 * Compute SHA-256(verifier-canonical-JSON(bundle minus signatures/tsa/log)).
 *
 * Mirrors `_compute_binding_digest` in Python: strips `signatures`,
 * `tsa_token`, and `log_inclusion_proof` before canonicalising and
 * hashing. Used by both the TSA token validator AND the transparency-log
 * inclusion-proof verifier so the producer's pre-extensions digest can
 * be recomputed by the verifier.
 */
function _computeBindingDigest(bundle: Record<string, unknown>): string {
  const stripped: Record<string, unknown> = {};
  for (const k of Object.keys(bundle)) {
    if (k === "signatures" || k === "tsa_token" || k === "log_inclusion_proof") {
      continue;
    }
    stripped[k] = bundle[k];
  }
  return createHash("sha256")
    .update(canonicalJsonBytes(stripped))
    .digest("hex");
}

/** VAL-W10-036 archive-bomb pre-flight. */
export function checkArchiveBombLimits(args: {
  entryCount: number;
  uncompressedSizeBytes: number;
}): { ok: boolean; reason: string } {
  if (args.entryCount > MAX_BUNDLE_ENTRIES) {
    return {
      ok: false,
      reason:
        `bundle entry_count ${args.entryCount} exceeds MAX_BUNDLE_ENTRIES ` +
        `${MAX_BUNDLE_ENTRIES} (VAL-W10-036)`,
    };
  }
  if (args.uncompressedSizeBytes > MAX_BUNDLE_BYTES) {
    return {
      ok: false,
      reason:
        `bundle uncompressed_size_bytes ${args.uncompressedSizeBytes} ` +
        `exceeds MAX_BUNDLE_BYTES ${MAX_BUNDLE_BYTES} (VAL-W10-036)`,
    };
  }
  return { ok: true, reason: "" };
}

// ----------------------------------------------------------------------------
// JWS structural verification (mirrors Python `verify_bundle`)
// ----------------------------------------------------------------------------

interface JwsResult {
  digest_ok: boolean;
  structure_ok: boolean;
  signatures_ok: boolean;
  bundle_digest_sha256: string;
  claims_count: number;
  signature_checks: SignatureCheck[];
}

function _verifyBundle(bundle: Record<string, unknown>, jwks: JWKS): JwsResult {
  const result: JwsResult = {
    digest_ok: false,
    structure_ok: false,
    signatures_ok: false,
    bundle_digest_sha256: "",
    claims_count: 0,
    signature_checks: [],
  };
  // Bundle-level digest is over the signature-stripped JCS canonical
  // bytes (mirrors bundleDigest convention and Python's
  // `_payload_for_signing` + `canonical_json_bytes`).
  result.bundle_digest_sha256 = bundleDigest(bundle, { stripSignatures: true });

  const claims = bundle["claims"];
  if (!Array.isArray(claims)) {
    return result;
  }
  result.claims_count = claims.length;
  result.structure_ok = true;
  result.digest_ok = true;

  const signatures = bundle["signatures"];
  if (!Array.isArray(signatures) || signatures.length === 0) {
    // No signatures: structure_ok stays true, signatures_ok is false.
    return result;
  }

  // BUG-C3 wire-shape parity: the canonical signing payload is the
  // bundle with `signatures` stripped. Each signature entry carries
  // `signing_input_b64u` (b64url(jcs_canonicalize(payload))) and
  // `signature_b64u`. This mirrors Python `verifier.py::verify_bundle`
  // lines 366-560 exactly.
  const stripped: Record<string, unknown> = {};
  for (const k of Object.keys(bundle)) {
    if (k === "signatures") continue;
    stripped[k] = bundle[k];
  }
  const expectedCanonicalBytes = jcsCanonicalize(stripped);

  let allValid = true;
  let digestOk = true;
  let anyPresent = false;
  for (let idx = 0; idx < signatures.length; idx++) {
    const sig = signatures[idx];
    if (sig === null || typeof sig !== "object" || Array.isArray(sig)) {
      result.signature_checks.push({
        kid: `<sig[${idx}]>`,
        alg: "<unknown>",
        ok: false,
        reason: "signature entry is not an object",
        code: "",
      });
      allValid = false;
      digestOk = false;
      continue;
    }
    const check = verifyBundleSignature({
      signature: sig as BundleSignatureEntry,
      expectedCanonicalBytes,
      jwks,
      signatureIndex: idx,
    });
    result.signature_checks.push(check);
    if (check.ok) {
      anyPresent = true;
    } else {
      allValid = false;
      // Python flips digest_ok=False on certain failures (missing kid,
      // missing signing_input_b64u, signing_input drift, b64url decode
      // failure). Conservatively flip digest_ok on any structural or
      // signing-input failure -- the surface symptom is "the bundle's
      // recorded canonical bytes don't equal the recomputed ones".
      if (
        check.reason === "signature missing 'kid'" ||
        check.reason === "signature missing 'signing_input_b64u'" ||
        check.reason.startsWith("signing_input drift:") ||
        check.reason.startsWith("signing_input_b64u is not valid base64url:")
      ) {
        digestOk = false;
      }
    }
  }
  result.digest_ok = digestOk;
  // Python's verify_bundle requires `any_signature_present` (line 563);
  // we mirror that here -- a bundle whose signatures all failed
  // pre-crypto checks is NOT `signatures_ok` even if `allValid` is
  // vacuously true (empty checks).
  result.signatures_ok = allValid && anyPresent;
  return result;
}

// ----------------------------------------------------------------------------
// Validator
// ----------------------------------------------------------------------------

/**
 * Validate a parsed evidence bundle end-to-end. Mirrors
 * `relay_verifier.bundle_validator.validate_bundle` line-for-line.
 *
 * Returns a `VerifierOutputEnvelope` whose JCS serialisation matches the
 * Python orchestrator's output for the same fixture (VAL-V2M06-022).
 *
 * Never throws for verification outcomes -- every failure mode is encoded
 * in the structured output.
 */
export function validateBundle(args: {
  bundle: Record<string, unknown>;
  jwks: JWKS | Record<string, unknown>;
  bundle_path?: string;
  trust_anchor_source?: string;
  options?: ValidateBundleOptions;
}): VerifierOutputEnvelope {
  const opts = args.options ?? {};
  const output = _newOutput();
  output.bundle_path = args.bundle_path ?? "";
  output.trust_anchor_source = args.trust_anchor_source ?? "";
  const jwks = args.jwks as JWKS;
  const bundle = args.bundle;

  // --- Trust anchor echo (VAL-W10-035) -------------------------------------
  const trustAnchor = bundle["trust_anchor"];
  if (typeof trustAnchor === "string") {
    output.trust_anchor = trustAnchor;
  }

  // --- Trust anchor classification (VAL-V2M08-044) -------------------------
  // Classification is derived from the BUNDLE's declared trust_anchor
  // field ONLY, never from the JWKS URL the verifier is configured
  // with. local_dev stays untrusted_local even if the verifier is
  // running under the Relay-Inc default anchor.
  output.trust_anchor_class = classifyTrustAnchor(trustAnchor);

  // --- Missing-trust_anchor rejection (VAL-V2M08-043) ----------------------
  // Fail-closed when the bundle declares no trust_anchor (or declares a
  // non-string / empty value). This MUST happen before signature work so
  // an unsigned classification cannot leak past the gate.
  if (typeof trustAnchor !== "string" || trustAnchor.length === 0) {
    _appendError(output, {
      reason: "trust_anchor_missing",
      message:
        "bundle is missing the required top-level 'trust_anchor' " +
        "field (spec section AO.4 line 6166); verifier cannot " +
        "classify the bundle against any trust posture",
      code: RELAY_EVID_MISSING_TRUST_ANCHOR,
    });
  }

  // --- Signature-count cap (VAL-V2M08-041) ---------------------------------
  // Per spec L.5 line 4481 bundles can carry up to MAX_BUNDLE_SIGNATURES
  // cross-signing signatures. An over-cap bundle is rejected BEFORE
  // per-signature verification work runs (defends against DoS and
  // against producers abusing the cross-signing slot for non-signature
  // data). The signatures_checked[] array stays empty for the over-cap
  // bundle.
  const rawSigs = bundle["signatures"];
  const signaturesCount = Array.isArray(rawSigs) ? rawSigs.length : 0;
  output.signatures_present = signaturesCount;
  if (signaturesCount > MAX_BUNDLE_SIGNATURES) {
    _appendError(output, {
      reason: "signature_count_exceeded",
      message:
        `bundle carries ${signaturesCount} signatures; the maximum ` +
        `supported is ${MAX_BUNDLE_SIGNATURES} per spec section L.5 ` +
        "line 4481 cross-signing cap",
      code: RELAY_EVID_SIGCOUNT_EXCEEDED,
    });
    // Refuse signature verification on the over-cap bundle. Recover the
    // bundle_digest_sha256 for diagnostic continuity but do NOT populate
    // signatures_checked[] -- per VAL-V2M08-041 the verifier does not
    // attempt verification on an over-cap bundle.
    try {
      output.bundle_digest_sha256 = bundleDigest(bundle, { stripSignatures: true });
    } catch {
      // Defensive: malformed payload that breaks canonicalisation leaves
      // bundle_digest_sha256 at its safe default "".
    }
    const claims = bundle["claims"];
    output.claims_count = Array.isArray(claims) ? claims.length : 0;
    output.overall = _computeOverall(output);
    return output;
  }

  // --- JWS + bundle-level verification ------------------------------------
  const jwsResult = _verifyBundle(bundle, jwks);
  output.bundle_digest_sha256 = jwsResult.bundle_digest_sha256;
  output.digest_ok = jwsResult.digest_ok;
  output.structure_ok = jwsResult.structure_ok;
  output.signatures_ok = jwsResult.signatures_ok;
  output.claims_count = jwsResult.claims_count;
  output.signatures_checked = jwsResult.signature_checks.map((sc) => ({
    kid: sc.kid,
    alg: sc.alg,
    ok: sc.ok,
    reason: sc.reason,
    code: sc.code,
  }));
  if (!jwsResult.signatures_ok) {
    const firstFail = jwsResult.signature_checks.find((sc) => !sc.ok);
    if (firstFail) {
      _appendError(output, {
        reason: "signature_verification_failed",
        message: firstFail.reason || "signature did not verify under JWK",
        code: firstFail.code || RELAY_EVID_014,
      });
    }
  }

  // --- Per-claim artifact-digest check (VAL-W10-022) ----------------------
  if (jwsResult.structure_ok && opts.artifact_resolver) {
    const claims = bundle["claims"];
    if (Array.isArray(claims)) {
      for (let ci = 0; ci < claims.length; ci++) {
        const claim = claims[ci];
        if (claim === null || typeof claim !== "object" || Array.isArray(claim)) continue;
        const refs = (claim as Record<string, unknown>)["evidence_refs"];
        if (!Array.isArray(refs)) continue;
        for (let ri = 0; ri < refs.length; ri++) {
          const ref = refs[ri];
          if (ref === null || typeof ref !== "object" || Array.isArray(ref)) continue;
          const r = ref as Record<string, unknown>;
          const artifactId = r["artifact_id"];
          const declaredDigest = r["digest"];
          if (typeof artifactId !== "string") continue;
          if (typeof declaredDigest !== "string") continue;
          // VAL-V2M08-015..017: path-traversal hardening MUST run BEFORE
          // the caller-supplied resolver is invoked. A malicious
          // artifact_id ("../../etc/passwd", "/etc/passwd", NFD-encoded
          // name, etc.) reaching the resolver unfiltered would let an
          // evidence bundle drive filesystem reads outside the session
          // sandbox. Parity with Python bundle_validator.py:574-589.
          const pathViolation = checkArtifactPath(artifactId);
          if (pathViolation !== null) {
            _appendError(output, {
              reason: "path_violation",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact_id ` +
                `${JSON.stringify(artifactId)} rejected by path screen ` +
                `(${pathViolation.path_violation})`,
              code: pathViolation.code,
            });
            output.digest_ok = false;
            continue;
          }
          let artifactBytes: Uint8Array | null = null;
          try {
            artifactBytes = opts.artifact_resolver(artifactId);
          } catch {
            artifactBytes = null;
          }
          if (artifactBytes === null) {
            _appendError(output, {
              reason: "artifact_unavailable",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact ` +
                `${JSON.stringify(artifactId)} could not be resolved`,
              code: RELAY_EVID_014,
            });
            output.digest_ok = false;
            continue;
          }
          const recomputed = createHash("sha256").update(Buffer.from(artifactBytes)).digest("hex");
          if (recomputed !== declaredDigest) {
            _appendError(output, {
              reason: "artifact_digest_mismatch",
              message:
                `claim[${ci}].evidence_refs[${ri}] artifact ` +
                `${JSON.stringify(artifactId)} digest mismatch: declared=` +
                `${JSON.stringify(declaredDigest)} recomputed=${JSON.stringify(recomputed)}`,
              code: RELAY_EVID_014,
            });
            output.digest_ok = false;
          }
        }
      }
    }
  }

  // --- Merkle root check (VAL-W10-024) ------------------------------------
  const declaredMerkle = bundle["merkle_root_hex"];
  if (typeof declaredMerkle === "string" && declaredMerkle.length > 0) {
    const recomputedMerkle = computeMerkleRoot(_claimDigestsInOrder(bundle));
    if (recomputedMerkle === declaredMerkle) {
      output.merkle_check = "ok";
    } else {
      output.merkle_check = "mismatch";
      _appendError(output, {
        reason: "merkle_root_mismatch",
        message:
          `declared merkle_root_hex ${JSON.stringify(declaredMerkle)} does not ` +
          `match recomputed root ${JSON.stringify(recomputedMerkle)}`,
        code: RELAY_EVID_040,
      });
    }
  } else {
    output.merkle_check = "absent";
  }

  // --- TSA timestamp + binding digest -------------------------------------
  const tsaTokenRaw = bundle["tsa_token"];
  const rawDecidedAt = bundle["decided_at"];
  const decidedAt = typeof rawDecidedAt === "string" ? rawDecidedAt : "";
  const bindingDigestHex = _computeBindingDigest(bundle);
  if (decidedAt.length > 0) {
    const tsaResult = validateTsaToken({
      token:
        tsaTokenRaw !== null && typeof tsaTokenRaw === "object" && !Array.isArray(tsaTokenRaw)
          ? (tsaTokenRaw as TsaToken)
          : null,
      bundleDigestHex: bindingDigestHex,
      decidedAt,
      chainCerts: null,
    });
    output.tsa_check = tsaResult.outcome;
    if (tsaResult.outcome === "missing") {
      _appendError(output, {
        reason: "tsa_missing",
        message: tsaResult.reason || "TSA timestamp absent",
        code: RELAY_EVID_031,
      });
    } else if (tsaResult.outcome === "skew") {
      _appendError(output, {
        reason: "tsa_skew",
        message: tsaResult.reason,
        code: RELAY_EVID_038,
      });
    } else if (tsaResult.outcome === "invalid") {
      _appendError(output, {
        reason: "tsa_invalid",
        message: tsaResult.reason,
        code: RELAY_EVID_031,
      });
    }
  } else {
    output.tsa_check = "missing";
    const presentFields = Object.keys(bundle).sort();
    _appendError(output, {
      reason: "decided_at_missing",
      message:
        "bundle is missing the canonical 'decided_at' TSA-binding " +
        "anchor (spec section AB); the validator refuses to fall " +
        "back to 'generated_at' or any sibling timestamp because " +
        "the TSA gen_time skew check binds to decided_at " +
        `specifically. bundle fields present: ${JSON.stringify(presentFields)}`,
      code: RELAY_EVID_DECIDED_AT_MISSING,
    });
    _appendError(output, {
      reason: "tsa_missing",
      message: "bundle missing decided_at; cannot evaluate TSA window",
      code: RELAY_EVID_031,
    });
  }

  // --- Transparency-log inclusion -----------------------------------------
  const logProof = bundle["log_inclusion_proof"];
  const witnessJwks = opts.witness_jwks ?? jwks;
  const logResult = verifyLogInclusion({
    proof:
      logProof !== null && typeof logProof === "object" && !Array.isArray(logProof)
        ? (logProof as Record<string, unknown>)
        : null,
    bundleDigestHex: bindingDigestHex,
    witnessJwks,
  });
  output.log_inclusion = logResult.outcome;
  if (logResult.outcome === "absent") {
    _appendWarning(output, {
      reason: "log_inclusion_absent",
      message:
        "no transparency-log inclusion proof attached; verification " +
        "proceeds but auditors should treat absence as a red flag",
    });
  } else if (logResult.outcome === "witness_mismatch") {
    if (opts.strict_log) {
      _appendError(output, {
        reason: "log_witness_mismatch",
        message: logResult.reason,
      });
    } else {
      _appendWarning(output, {
        reason: "log_witness_mismatch",
        message: logResult.reason,
      });
    }
  }

  // --- Signer key lifecycle (VAL-W10-031..034) ----------------------------
  if (jwsResult.signature_checks.length > 0) {
    // Primary signer: first OK, else fall back to slot 0 with telemetry.
    let primarySig: SignatureCheck | undefined = jwsResult.signature_checks.find(
      (sc) => sc.ok,
    );
    if (primarySig === undefined) {
      primarySig = jwsResult.signature_checks[0];
      if (primarySig !== undefined) {
        const details = (output.details ??= {});
        details["primary_signer_fallback"] = {
          reason: "no_signature_verified",
          note:
            "no signature in the bundle has ok=true; lifecycle " +
            "resolution falls back to signature_checks[0]",
          selected_kid: primarySig.kid,
        };
      }
    }
    if (primarySig !== undefined) {
      const primaryKid = primarySig.kid;
      const signerJwk = _selectJwk(jwks, primaryKid) as JWK | null;
      const signedAtRaw = bundle["signed_at"];
      const signedAt =
        typeof signedAtRaw === "string" && signedAtRaw.length > 0 ? signedAtRaw : decidedAt;
      if (signerJwk !== null && typeof signedAt === "string" && signedAt.length > 0) {
        const lifeResult: KeyLifecycleResult = checkSigningKeyLifecycle({
          jwk: signerJwk as unknown as Record<string, unknown>,
          bundleSignedAt: signedAt,
          auditorNow: opts.auditor_now,
        });
        output.signer_key_revoked = lifeResult.signer_key_revoked;
        output.signer_key_revoked_at = lifeResult.signer_key_revoked_at
          ? lifeResult.signer_key_revoked_at
          : null;
        if (lifeResult.outcome === "expired") {
          _appendError(output, {
            reason: "signer_key_expired",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_041,
          });
        } else if (lifeResult.outcome === "revoked") {
          _appendError(output, {
            reason: "signer_key_revoked_at_or_before_sign_time",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_042,
          });
        } else if (lifeResult.outcome === "premature") {
          _appendError(output, {
            reason: "signer_key_premature",
            message: lifeResult.reason,
            code: lifeResult.code || RELAY_EVID_041,
          });
        } else if (lifeResult.signer_key_revoked) {
          _appendWarning(output, {
            reason: "signer_key_revoked_after_sign_time",
            message:
              `key ${JSON.stringify(primaryKid)} was revoked at ` +
              `${lifeResult.signer_key_revoked_at}; bundle signed before ` +
              `revocation -- auditor decides acceptance`,
          });
        }
      }
    }
  }

  // --- trust_anchor / local_dev surfacing (VAL-W10-035 / 041) -------------
  const defaultAnchor = opts.default_trust_anchor ?? DEFAULT_JWKS_URL;
  if (output.trust_anchor === TRUST_ANCHOR_LOCAL_DEV) {
    const verifierUsingDefault =
      ["live", "cache", "bundled", ""].includes(output.trust_anchor_source) &&
      defaultAnchor.endsWith("relay.epochly.com/.well-known/jwks.json");
    if (verifierUsingDefault) {
      if (opts.strict_trust_anchor) {
        _appendError(output, {
          reason: WARN_LOCAL_DEV_UNSUPPORTED,
          message:
            "bundle trust_anchor='local_dev' is not supported for audit " +
            "under the default trust anchor; --strict-trust-anchor in effect",
        });
      } else {
        _appendWarning(output, {
          reason: WARN_LOCAL_DEV_UNSUPPORTED,
          message:
            "bundle trust_anchor='local_dev' is not supported for audit " +
            "under the default trust anchor; verification proceeds for " +
            "non-audit purposes",
        });
      }
    }
  }

  // --- Subject resolution (VAL-W10-037 / 038) -----------------------------
  const subjectIdRaw = bundle["subject_id"];
  const subjectDigestHexRaw = bundle["subject_digest_hex"];
  const subResult = resolveSubject({
    subjectId: typeof subjectIdRaw === "string" ? subjectIdRaw : null,
    subjectDigestHex: typeof subjectDigestHexRaw === "string" ? subjectDigestHexRaw : null,
    subjectStore: opts.subject_store ?? null,
  });
  output.subject_resolution = subResult.resolution;
  if (!subResult.original_digest_preserved) {
    _appendWarning(output, {
      reason: "subject_digest_drift",
      message: subResult.reason,
    });
  }

  // --- Overall verdict ----------------------------------------------------
  output.overall = _computeOverall(output);
  return output;
}

function _computeOverall(output: VerifierOutputEnvelope): "pass" | "fail" {
  if (output.errors.length > 0) return "fail";
  if (!output.structure_ok) return "fail";
  if (!output.digest_ok) return "fail";
  if (!output.signatures_ok) return "fail";
  if (output.merkle_check === "mismatch") return "fail";
  if (
    output.tsa_check === "missing" ||
    output.tsa_check === "invalid" ||
    output.tsa_check === "skew"
  ) {
    return "fail";
  }
  return "pass";
}

/**
 * Convenience: archive-bomb pre-flight + validate. Mirrors
 * `validate_bundle_with_archive_check` in Python.
 */
export function validateBundleWithArchiveCheck(args: {
  bundle: Record<string, unknown>;
  jwks: JWKS | Record<string, unknown>;
  entryCount: number;
  uncompressedSizeBytes: number;
  bundle_path?: string;
  trust_anchor_source?: string;
  options?: ValidateBundleOptions;
}): VerifierOutputEnvelope {
  const { ok, reason } = checkArchiveBombLimits({
    entryCount: args.entryCount,
    uncompressedSizeBytes: args.uncompressedSizeBytes,
  });
  if (!ok) {
    const output = _newOutput();
    output.bundle_path = args.bundle_path ?? "";
    output.trust_anchor_source = args.trust_anchor_source ?? "";
    _appendError(output, {
      reason: "archive_bomb_limit_exceeded",
      message: reason,
      code: RELAY_EVID_024,
    });
    output.overall = "fail";
    return output;
  }
  return validateBundle({
    bundle: args.bundle,
    jwks: args.jwks,
    bundle_path: args.bundle_path,
    trust_anchor_source: args.trust_anchor_source,
    options: args.options,
  });
}

// Side-effects: keep CLOCK_SKEW_TOLERANCE_SECONDS in the re-export
// surface so consumers do not need to import from tsa.ts directly when
// using the validator alone.
export { CLOCK_SKEW_TOLERANCE_SECONDS };
