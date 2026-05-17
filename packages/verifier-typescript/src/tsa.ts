// RFC 3161 TSA timestamp validation for evidence bundles (TS parity with
// packages/verifier/src/relay_verifier/tsa.py).
//
// Per spec section AB lines 5416-5417 every signed evidence bundle carries
// a Time-Stamp Authority response (RFC 3161) so an auditor can verify the
// bundle was signed AT a specific wall-clock time, not merely that it was
// signed by a particular key. Per VAL-W10-025 a bundle whose `.tsr` is
// absent is rejected with `RELAY-EVID-031`. Per VAL-W10-027 the TSA
// `genTime` MUST be within +/-300 s of the bundle's `decided_at`;
// outside the window raises `RELAY-EVID-038`.
//
// FAIL-CLOSED: per CLAUDE.md keystone invariant #2 the module's
// `validateTsaToken` MUST NOT report `outcome="ok"` based on a
// presence-only check. Until the CMS SignerInfo signature in the RFC
// 3161 TimeStampResp is cryptographically verified against the bundled
// TSA cert chain, the function fail-closes via TSA_CRYPTO_IMPLEMENTED
// (currently `false`). Flipping the flag to `true` without wiring real
// verification is a P1 keystone-invariant regression. Mirrors
// packages/verifier/src/relay_verifier/tsa.py:104-112.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { X509Certificate, createPublicKey } from "node:crypto";

// Single source +/-300 s skew bound per spec section L.5 line 4479 + AB
// line 5690. Shared with key_lifecycle.ts.
export const CLOCK_SKEW_TOLERANCE_SECONDS = 300;

export const RELAY_EVID_031 = "RELAY-EVID-031" as const;
/** TSA timestamp missing (VAL-W10-025). */

export const RELAY_EVID_038 = "RELAY-EVID-038" as const;
/**
 * Backdated/forward-dated evidence: TSA genTime outside +/-300 s of
 * decided_at (VAL-W10-027).
 */

// Canonical packaged path for the TSA cert chain shipped with the
// verifier (TS mirror at src/tsa_chain/tsa-chain.pem).
export const TSA_CHAIN_DIRNAME = "tsa_chain" as const;
export const TSA_CHAIN_FILENAME = "tsa-chain.pem" as const;

// Minimum key strengths per VAL-W10-042; mirrors the L.1 alg allow-list
// rejection of weaker primitives.
export const MIN_RSA_BITS = 2048;

/**
 * Cryptographic TSA signature verification feature flag. MUST remain
 * `false` until `validateTsaToken` verifies the CMS SignerInfo signature
 * in the RFC 3161 TimeStampResp against the bundled TSA cert chain.
 *
 * With the flag at `false`, the function fail-closes when a token is
 * present; flipping it to `true` without wiring real verification is a
 * P1 keystone-invariant regression guarded by m06_tsa_failclosed.test.ts.
 */
export const TSA_CRYPTO_IMPLEMENTED = false;

// ----------------------------------------------------------------------------
// Result types
// ----------------------------------------------------------------------------

export interface TSAValidationResult {
  /** One of: "ok", "invalid", "missing", "skew". */
  outcome: "ok" | "invalid" | "missing" | "skew";
  /** Human-readable detail; "" on ok. */
  reason: string;
  /** Wire code on reject paths (RELAY-EVID-031 / RELAY-EVID-038); "" otherwise. */
  code: string;
  /** Parsed gen_time echo or "" when missing. */
  gen_time: string;
  /** Abs delta between gen_time and decided_at; -1 when not computed. */
  skew_seconds: number;
}

export interface TSACertSummary {
  readonly subject: string;
  readonly issuer: string;
  readonly not_before: string;
  readonly not_after: string;
  readonly key_alg: string;
  readonly key_strength_bits: number;
  readonly is_self_signed: boolean;
}

export interface TSAChainCheck {
  chain_path: string;
  cert_count: number;
  certs: TSACertSummary[];
  chain_ok: boolean;
  reason: string;
}

// ----------------------------------------------------------------------------
// Time helpers
// ----------------------------------------------------------------------------

function _parseIsoZ(s: string): Date {
  if (typeof s !== "string" || s.length === 0) {
    throw new Error(`timestamp must be a non-empty string, got ${JSON.stringify(s)}`);
  }
  if (!s.endsWith("Z")) {
    throw new Error(`timestamp must end with 'Z' (UTC), got ${JSON.stringify(s)}`);
  }
  // ISO-8601 with Z suffix; Date.parse handles both seconds and
  // fractional-second forms. Reject on NaN.
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) {
    throw new Error(`timestamp not parseable as ISO-8601: ${JSON.stringify(s)}`);
  }
  return new Date(ms);
}

function _absSecondsDelta(a: Date, b: Date): number {
  return Math.abs(Math.trunc((a.getTime() - b.getTime()) / 1000));
}

// ----------------------------------------------------------------------------
// TSA token validation
// ----------------------------------------------------------------------------

export interface TsaToken {
  version?: unknown;
  policy_oid?: unknown;
  message_imprint?: unknown;
  serial_number?: unknown;
  gen_time?: unknown;
  tsa_signature_alg?: unknown;
  tsa_signer_cert_subject?: unknown;
  tsa_signature_b64u?: unknown;
  [key: string]: unknown;
}

function _newResult(): TSAValidationResult {
  return {
    outcome: "missing",
    reason: "",
    code: "",
    gen_time: "",
    skew_seconds: -1,
  };
}

/**
 * Validate a parsed RFC 3161 TSTInfo token against the bundle.
 *
 * Mirrors `packages/verifier/src/relay_verifier/tsa.py:195-354`. Failure
 * modes:
 *   - token null/undefined -> outcome="missing", code=RELAY-EVID-031
 *   - message_imprint mismatch / malformed -> outcome="invalid"
 *   - gen_time outside +/-300s -> outcome="skew", code=RELAY-EVID-038
 *   - unparseable gen_time / decided_at -> outcome="invalid"
 *   - missing tsa_signature_b64u -> outcome="invalid"
 *   - signer subject not in chainCerts -> outcome="invalid"
 *   - structural checks pass BUT TSA_CRYPTO_IMPLEMENTED is false ->
 *     outcome="invalid" with reason starting "TSA cryptographic signature
 *     verification" (fail-closed; VAL-V2M06-003).
 */
export function validateTsaToken(args: {
  token: TsaToken | null | undefined;
  bundleDigestHex: string;
  decidedAt: string;
  chainCerts?: X509Certificate[] | null;
}): TSAValidationResult {
  const { token, bundleDigestHex, decidedAt, chainCerts } = args;
  const result = _newResult();

  if (token === null || token === undefined) {
    result.outcome = "missing";
    result.reason = "no TSA token (.tsr) attached to bundle";
    result.code = RELAY_EVID_031;
    return result;
  }

  if (typeof token !== "object" || Array.isArray(token)) {
    result.outcome = "invalid";
    result.reason = `TSA token must be a structured object, got ${typeof token}`;
    return result;
  }

  // 1. message_imprint binds the bundle bytes to the timestamp.
  const msgImprint = token.message_imprint;
  if (msgImprint === null || typeof msgImprint !== "object" || Array.isArray(msgImprint)) {
    result.outcome = "invalid";
    result.reason = "TSA token missing or malformed 'message_imprint'";
    return result;
  }
  const mi = msgImprint as Record<string, unknown>;
  const declaredAlg = mi["hash_algorithm"];
  const declaredDigest = mi["hashed_message_hex"];
  if (declaredAlg !== "sha256") {
    result.outcome = "invalid";
    result.reason = `TSA message_imprint must use sha256, got ${JSON.stringify(declaredAlg)}`;
    return result;
  }
  if (declaredDigest !== bundleDigestHex) {
    result.outcome = "invalid";
    result.reason =
      `TSA message_imprint digest does not match recomputed bundle ` +
      `digest (declared=${JSON.stringify(declaredDigest)}, recomputed=${JSON.stringify(bundleDigestHex)})`;
    return result;
  }

  // 2. gen_time within +/-300s of decided_at.
  const genTimeRaw = token.gen_time;
  if (typeof genTimeRaw !== "string" || genTimeRaw.length === 0) {
    result.outcome = "invalid";
    result.reason = "TSA token missing 'gen_time'";
    return result;
  }
  result.gen_time = genTimeRaw;
  let genTime: Date;
  try {
    genTime = _parseIsoZ(genTimeRaw);
  } catch (exc) {
    result.outcome = "invalid";
    result.reason = `TSA gen_time unparsable: ${(exc as Error).message}`;
    return result;
  }
  let decided: Date;
  try {
    decided = _parseIsoZ(decidedAt);
  } catch (exc) {
    result.outcome = "invalid";
    result.reason = `bundle decided_at unparsable: ${(exc as Error).message}`;
    return result;
  }
  const skew = _absSecondsDelta(genTime, decided);
  result.skew_seconds = skew;
  if (skew > CLOCK_SKEW_TOLERANCE_SECONDS) {
    result.outcome = "skew";
    result.reason =
      `TSA gen_time skew ${skew}s exceeds +/-${CLOCK_SKEW_TOLERANCE_SECONDS}s ` +
      `tolerance (gen_time=${genTimeRaw}, decided_at=${decidedAt})`;
    result.code = RELAY_EVID_038;
    return result;
  }

  // 3. TSA signature presence (structural pre-check; full crypto verify
  // gated on TSA_CRYPTO_IMPLEMENTED below).
  const tsaSig = token.tsa_signature_b64u;
  if (typeof tsaSig !== "string" || tsaSig.length === 0) {
    result.outcome = "invalid";
    result.reason = "TSA token missing 'tsa_signature_b64u'";
    return result;
  }

  // 4. Subject membership in chain (VAL-W10-026 structural pre-check).
  if (chainCerts && chainCerts.length > 0) {
    const signerSubject = token.tsa_signer_cert_subject;
    if (typeof signerSubject !== "string" || signerSubject.length === 0) {
      result.outcome = "invalid";
      result.reason = "TSA token missing 'tsa_signer_cert_subject'";
      return result;
    }
    const chainSubjects = new Set<string>(chainCerts.map((c) => c.subject));
    if (!chainSubjects.has(signerSubject)) {
      result.outcome = "invalid";
      result.reason =
        `TSA signer subject ${JSON.stringify(signerSubject)} not present in bundled ` +
        `trust chain (${chainCerts.length} certs checked)`;
      return result;
    }
  }

  // 5. Cryptographic TSA signature verification (FAIL-CLOSED).
  // Mirrors packages/verifier/src/relay_verifier/tsa.py:336-347.
  if (!TSA_CRYPTO_IMPLEMENTED) {
    result.outcome = "invalid";
    result.reason =
      "TSA cryptographic signature verification is not implemented " +
      "in this build; refusing to claim outcome='ok'. The structural " +
      "checks (message_imprint match, gen_time within window, " +
      "signer-subject membership) passed, but the CMS SignerInfo " +
      "signature in the RFC 3161 token has not been verified " +
      "against the TSA cert chain. Tracking issue: P1 verifier " +
      "crypto gap.";
    return result;
  }

  // Unreachable while the flag is false.
  result.outcome = "ok";
  return result;
}

// ----------------------------------------------------------------------------
// Cert chain inspection (VAL-W10-042 / VAL-V2M06-006)
// ----------------------------------------------------------------------------

function _classifyPublicKey(cert: X509Certificate): { alg: string; bits: number } {
  let pubKey;
  try {
    pubKey = cert.publicKey;
  } catch {
    return { alg: "unknown", bits: 0 };
  }
  const asymType = pubKey.asymmetricKeyType;
  if (asymType === "ed25519") {
    return { alg: "Ed25519", bits: 256 };
  }
  if (asymType === "ec") {
    const details = pubKey.asymmetricKeyDetails;
    const curve = details?.namedCurve ?? "unknown";
    // Map node curve names to py-style label (ECDSA-secp256r1 etc).
    return { alg: `ECDSA-${curve}`, bits: _curveBits(curve) };
  }
  if (asymType === "rsa") {
    const details = pubKey.asymmetricKeyDetails;
    const modulusLength = details?.modulusLength ?? 0;
    return { alg: "RSA", bits: modulusLength };
  }
  return { alg: String(asymType), bits: 0 };
}

function _curveBits(curve: string): number {
  if (curve === "prime256v1" || curve === "secp256r1") return 256;
  if (curve === "secp384r1") return 384;
  if (curve === "secp521r1") return 521;
  return 0;
}

function _isSelfSigned(cert: X509Certificate): boolean {
  return cert.subject === cert.issuer;
}

export function loadTsaChainPemBytes(pemBytes: Uint8Array | Buffer): X509Certificate[] {
  // X509Certificate constructor accepts a single PEM cert. We split on
  // -----BEGIN CERTIFICATE----- markers to support multi-cert PEM files.
  const text = Buffer.from(pemBytes).toString("utf-8");
  const certs: X509Certificate[] = [];
  const pattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const matches = text.match(pattern);
  if (!matches) {
    throw new Error("no PEM CERTIFICATE blocks found in input");
  }
  for (const block of matches) {
    certs.push(new X509Certificate(block));
  }
  return certs;
}

export function loadBundledTsaChain(): { path: string; raw: Buffer } {
  // Locate the chain relative to this module file. After tsc emits to
  // dist/ the relative path src/tsa_chain/ is still preserved at
  // dist/tsa_chain/ by the build (or kept under src/ for vitest src runs).
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  // Candidate locations: alongside this file (dist or src), and at
  // src/tsa_chain when running tests directly from src.
  const candidates = [
    resolve(__dirname, TSA_CHAIN_DIRNAME, TSA_CHAIN_FILENAME),
    resolve(__dirname, "..", "src", TSA_CHAIN_DIRNAME, TSA_CHAIN_FILENAME),
    resolve(__dirname, "..", TSA_CHAIN_DIRNAME, TSA_CHAIN_FILENAME),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      return { path: p, raw: readFileSync(p) };
    }
  }
  throw new Error(
    `bundled TSA chain not found at packaged path ${TSA_CHAIN_DIRNAME}/${TSA_CHAIN_FILENAME}`,
  );
}

/**
 * Inspect a TSA cert chain per VAL-W10-042 / VAL-V2M06-006.
 *
 * Validates: cert_count >= 1, every notAfter in the future, every public
 * key meets the minimum strength threshold (RSA >= 2048, ECDSA >= P-256,
 * Ed25519 OK), chain links via subject==issuer hops up to a self-signed
 * root.
 */
export function inspectTsaChain(args: {
  pemBytes: Uint8Array | Buffer;
  chainPath?: string;
}): TSAChainCheck {
  const chainPath = args.chainPath ?? "";
  const summaries: TSACertSummary[] = [];
  let certs: X509Certificate[];
  try {
    certs = loadTsaChainPemBytes(args.pemBytes);
  } catch (exc) {
    return {
      chain_path: chainPath,
      cert_count: 0,
      certs: [],
      chain_ok: false,
      reason: `chain PEM parse failed: ${(exc as Error).message}`,
    };
  }
  if (certs.length === 0) {
    return {
      chain_path: chainPath,
      cert_count: 0,
      certs: [],
      chain_ok: false,
      reason: "chain contains zero certificates (VAL-W10-042 requires >= 1)",
    };
  }

  const now = new Date();
  const issues: string[] = [];
  for (const cert of certs) {
    const { alg, bits } = _classifyPublicKey(cert);
    const notAfter = new Date(cert.validTo);
    const notBefore = new Date(cert.validFrom);
    const summary: TSACertSummary = {
      subject: cert.subject,
      issuer: cert.issuer,
      not_before: _toIsoZ(notBefore),
      not_after: _toIsoZ(notAfter),
      key_alg: alg,
      key_strength_bits: bits,
      is_self_signed: _isSelfSigned(cert),
    };
    summaries.push(summary);
    if (notAfter <= now) {
      issues.push(`cert ${JSON.stringify(summary.subject)} expired at ${summary.not_after}`);
    }
    if (alg === "RSA" && bits < MIN_RSA_BITS) {
      issues.push(
        `cert ${JSON.stringify(summary.subject)} RSA key bits=${bits} below MIN_RSA_BITS=${MIN_RSA_BITS}`,
      );
    } else if (alg.startsWith("ECDSA-")) {
      const curveTail = alg.slice("ECDSA-".length);
      if (
        !(
          curveTail.startsWith("prime256") ||
          curveTail.startsWith("secp256") ||
          curveTail.startsWith("secp384") ||
          curveTail.startsWith("secp521")
        )
      ) {
        issues.push(`cert ${JSON.stringify(summary.subject)} ECDSA curve ${alg} below P-256`);
      }
    } else if (bits === 0 && alg !== "Ed25519") {
      issues.push(`cert ${JSON.stringify(summary.subject)} unsupported key type ${alg}`);
    }
  }

  // Chain linkage: every non-root cert's issuer must equal the next
  // cert's subject. Single self-signed cert is accepted as 1-hop.
  if (certs.length >= 2) {
    for (let i = 0; i < certs.length - 1; i++) {
      const me = certs[i];
      const parent = certs[i + 1];
      if (me === undefined || parent === undefined) {
        continue;
      }
      if (me.issuer !== parent.subject) {
        issues.push(
          `chain link broken at index ${i}: issuer ${JSON.stringify(me.issuer)} != ` +
            `parent subject ${JSON.stringify(parent.subject)}`,
        );
      }
    }
  }
  const last = certs[certs.length - 1];
  if (last !== undefined && !_isSelfSigned(last)) {
    issues.push(
      `chain root cert ${JSON.stringify(last.subject)} is not self-signed (issuer != subject)`,
    );
  }

  return {
    chain_path: chainPath,
    cert_count: certs.length,
    certs: summaries,
    chain_ok: issues.length === 0,
    reason: issues.join("; "),
  };
}

function _toIsoZ(d: Date): string {
  // ISO-8601 with millisecond precision then trimmed to seconds + 'Z'.
  // Date.toISOString() always emits a 'Z' suffix; we keep it as-is to
  // match Python's `.isoformat().replace("+00:00", "Z")` shape but
  // strip ms when zero for cleaner cross-runtime output.
  return d.toISOString();
}

// Side-effect: silence "createPublicKey unused" lint when bundlers
// tree-shake. (createPublicKey is reserved for the M09 crypto wiring
// rewrite; keeping the import documents the future flip site.)
void createPublicKey;
