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
// Per relay-v0.3-audit-resolution M5/F5.7 (VAL-V3M5-014..017) this module
// performs real RFC 3161 ``TimeStampResp`` verification using
// @peculiar/asn1-tsp + @peculiar/asn1-cms + @peculiar/asn1-x509 to decode
// the DER, and node:crypto for chain verify + CMS SignerInfo signature
// verify. This matches the Python verifier's real-crypto posture
// (TSA_CRYPTO_IMPLEMENTED=True since v0.2 M09 w9-2).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { X509Certificate, verify as cryptoVerify, createHash } from "node:crypto";

import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { TimeStampResp, TSTInfo } from "@peculiar/asn1-tsp";
import { SignedData, EncapsulatedContentInfo } from "@peculiar/asn1-cms";
import { Certificate as Asn1Certificate } from "@peculiar/asn1-x509";

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
 * Cryptographic TSA signature verification feature flag. Set to ``true``
 * in v0.3 M5/F5.7 (VAL-V3M5-014) once the @peculiar/asn1-tsp +
 * @peculiar/asn1-cms decode + node:crypto verify path landed.
 *
 * Flipping it back to ``false`` without removing the real verifier below
 * is a no-op for tests; flipping it to ``true`` without wiring real
 * verification is a P1 keystone-invariant regression.
 *
 * Mirrors packages/verifier/src/relay_verifier/tsa.py::TSA_CRYPTO_IMPLEMENTED.
 */
export const TSA_CRYPTO_IMPLEMENTED = true;

// ----------------------------------------------------------------------------
// Result types
// ----------------------------------------------------------------------------

export interface TSAValidationResult {
  /** One of: "ok", "invalid", "missing", "skew". */
  outcome: "ok" | "invalid" | "missing" | "skew";
  /** Human-readable detail or structured tag; "" on ok. */
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

/**
 * Restore standard-base64 '=' padding on a base64url string and translate the
 * URL-safe alphabet ('-' -> '+', '_' -> '/') so the result is decodable by
 * ``Buffer.from(s, "base64")``.
 *
 * The pad count is ``(4 - (b64.length % 4)) % 4``. This is the JS-correct form
 * of Python's ``(-len(s)) % 4`` (packages/verifier/src/relay_verifier/tsa.py::
 * _b64u_decode): in Python ``%`` takes the sign of the divisor so ``(-22) % 4
 * == 2``, but in JavaScript ``%`` takes the sign of the dividend so
 * ``(-22) % 4 == -2``. A naive port of the Python expression yields a pad
 * count that is always <= 0, leaving the padding branch dead and base64url
 * strings whose length mod 4 is 2 or 3 unpadded (VAL-PARITY-011). The form
 * here yields the same non-negative pad count as Python for every length.
 */
export function restoreBase64Padding(b64u: string): string {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  if (pad > 0) {
    return b64 + "=".repeat(pad);
  }
  return b64;
}

export function _b64uDecode(s: string): Buffer {
  // base64url -> base64 (restore '+', '/', and '=' padding) and decode.
  return Buffer.from(restoreBase64Padding(s), "base64");
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
  tsr_der_b64u?: unknown;
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

// ----------------------------------------------------------------------------
// Real RFC 3161 TimeStampResp verification (mirrors Python's
// _verify_cryptographic_signature in tsa.py).
// ----------------------------------------------------------------------------

/**
 * Mapping from OID -> (node algorithm name, signature shape). Limited to
 * the OIDs the Python TSA fixture builder and well-behaved real TSAs use
 * (ECDSA-SHA256, RSA-SHA256, Ed25519). Unknown OIDs cause a
 * tsa_signature_invalid rejection.
 */
const SIG_ALG_BY_OID: Record<string, { hash: string | null; isEcdsa: boolean }> = {
  // ecdsa-with-SHA256
  "1.2.840.10045.4.3.2": { hash: "sha256", isEcdsa: true },
  // ecdsa-with-SHA384
  "1.2.840.10045.4.3.3": { hash: "sha384", isEcdsa: true },
  // ecdsa-with-SHA512
  "1.2.840.10045.4.3.4": { hash: "sha512", isEcdsa: true },
  // sha256WithRSAEncryption
  "1.2.840.113549.1.1.11": { hash: "sha256", isEcdsa: false },
  // sha384WithRSAEncryption
  "1.2.840.113549.1.1.12": { hash: "sha384", isEcdsa: false },
  // sha512WithRSAEncryption
  "1.2.840.113549.1.1.13": { hash: "sha512", isEcdsa: false },
  // Ed25519: no separate hash function; algorithm is identifier-only.
  "1.3.101.112": { hash: null, isEcdsa: false },
};

/** Convert ArrayBuffer / ArrayBufferView to a Node Buffer (zero-copy view). */
function _toBuffer(b: ArrayBuffer | ArrayBufferView): Buffer {
  if (b instanceof ArrayBuffer) {
    return Buffer.from(b);
  }
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
}

function _findIdCtTstInfoOid(_: string): boolean {
  // id-ct-TSTInfo OID is "1.2.840.113549.1.9.16.1.4".
  return _ === "1.2.840.113549.1.9.16.1.4";
}

interface VerifyOutcome {
  ok: boolean;
  reason: string;
}

/**
 * RFC 3161 PKIStatus gate, fail-closed. A TimeStampToken is present only
 * when PKIStatus is granted(0) or grantedWithMods(1); every other value --
 * rejection(2), waiting(3), revocationWarning(4), revocationNotification(5),
 * any out-of-range integer, a missing/undefined status from a malformed
 * TSTInfo, or a large INTEGER decoded as a string by @peculiar/asn1-schema
 * -- MUST be rejected.
 *
 * Mirrors the Python posture: rfc3161_client verify.py raises
 * VerificationError("PKIStatus is not GRANTED") for non-granted statuses and
 * PKIStatus(value) raises ValueError for an out-of-range integer; the Python
 * verifier returns outcome="invalid" either way.
 *
 * Uses STRICT identity against the JS numbers 0 and 1 so the string "0", a
 * BigInt(0), NaN, and 0.5 all fail (none is the number 0 or 1).
 */
export function _isAcceptablePkiStatus(statusVal: unknown): boolean {
  return statusVal === 0 || statusVal === 1;
}

/**
 * Decode + verify a real RFC 3161 ``TimeStampResp`` DER blob against the
 * bundle binding digest and the supplied trust roots.
 *
 * Mirrors ``packages/verifier/src/relay_verifier/tsa.py::_verify_cryptographic_signature``.
 *
 * Returns:
 *   * `{ ok: true, reason: "" }` on success.
 *   * `{ ok: false, reason: "tsr_decode_failed: <type>" }` when the DER is
 *     not a parseable TimeStampResp.
 *   * `{ ok: false, reason: "message_imprint_mismatch" }` when the
 *     embedded MessageImprint does not match the bundle digest.
 *   * `{ ok: false, reason: "tsa_cert_chain_unknown_root" }` when the
 *     embedded leaf cert does not chain to any supplied trust root.
 *   * `{ ok: false, reason: "tsa_signature_invalid" }` when the chain
 *     built successfully but the SignedData SignerInfo signature did not
 *     verify over signed_attrs.
 */
function _verifyCryptographicSignature(args: {
  tsrDer: Buffer;
  bundleDigestBytes: Buffer;
  trustRoots: X509Certificate[];
  /**
   * The TSA gen_time. Per RFC 3161 the cert chain need only be valid AT the
   * timestamp time (not now), so the validity window is checked against this
   * instant. Mirrors rfc3161_client verify.py:347-352 which supplies
   * tst_info.gen_time as the PKCS7 verification time.
   */
  genTime: Date;
}): VerifyOutcome {
  const { tsrDer, bundleDigestBytes, trustRoots, genTime } = args;
  if (trustRoots.length === 0) {
    return { ok: false, reason: "tsa_cert_chain_unknown_root" };
  }

  // 1. Decode the TimeStampResp.
  let tsr: TimeStampResp;
  try {
    tsr = AsnParser.parse(tsrDer, TimeStampResp);
  } catch (exc) {
    return { ok: false, reason: `tsr_decode_failed: ${(exc as Error).name}` };
  }

  // 2. PKIStatus must indicate granted (== 0) or grantedWithMods (== 1).
  // PKIStatus is encoded as an INTEGER; @peculiar/asn1-schema decodes small
  // INTEGERs to a JS number but yields a *string* for values beyond
  // Number.MAX_SAFE_INTEGER, and a malformed TSTInfo leaves the field
  // undefined. The gate MUST fail closed on every non-granted shape -- the
  // prior `typeof statusVal === "number" && ...` form SKIPPED the check
  // entirely for non-numeric / missing / out-of-range status, letting a
  // non-granted (or garbage) TSR slip past. Python rejects all of these:
  // rfc3161_client verify.py raises VerificationError("PKIStatus is not
  // GRANTED") and PKIStatus(value) raises ValueError on an out-of-range
  // integer (parity).
  const statusVal = tsr.status?.status;
  if (!_isAcceptablePkiStatus(statusVal)) {
    return { ok: false, reason: `tsr_status_${String(statusVal)}` };
  }

  // 3. TimeStampToken (ContentInfo wrapping SignedData).
  const tst = tsr.timeStampToken;
  if (!tst) {
    return { ok: false, reason: "tsr_decode_failed: TimeStampToken absent" };
  }
  // tst.content is the ANY-typed inner -- DER bytes of the SignedData.
  let sd: SignedData;
  try {
    sd = AsnParser.parse(tst.content, SignedData);
  } catch (exc) {
    return { ok: false, reason: `tsr_decode_failed: SignedData ${(exc as Error).name}` };
  }

  // 4. Encapsulated content must be TSTInfo (OID id-ct-TSTInfo).
  const eci: EncapsulatedContentInfo = sd.encapContentInfo;
  if (!_findIdCtTstInfoOid(eci.eContentType)) {
    return { ok: false, reason: `tsr_decode_failed: unexpected eContentType ${eci.eContentType}` };
  }

  // 5. SignerInfos: exactly one signer per RFC 3161 sec 2.4.2.
  if (sd.signerInfos.length !== 1) {
    return { ok: false, reason: "tsr_decode_failed: expected exactly one SignerInfo" };
  }
  const signerInfo = sd.signerInfos[0];
  if (signerInfo === undefined) {
    return { ok: false, reason: "tsr_decode_failed: SignerInfo[0] undefined" };
  }

  // 6. Re-encode each certificate in SignedData.certificates back to DER
  // so we can construct node:crypto X509Certificate instances. Match the
  // SignerIdentifier (issuerAndSerialNumber) to find the leaf.
  const leafCert = _resolveSignerCert(sd, signerInfo);
  if (leafCert === null) {
    return { ok: false, reason: "tsr_decode_failed: signer cert not in SignedData.certificates" };
  }

  // 7. Verify the leaf chains to one of trustRoots. Per RFC 3161, the
  // chain is leaf -> ... -> root; here we only embed leaf + root for the
  // test fixture. checkIssued(parent) + parent.verify(parent.publicKey)
  // covers the single-hop case; if the leaf is itself self-signed (root)
  // we still require it to appear in trustRoots.
  const chainOk = _verifyLeafChainsToTrustRoots(leafCert, trustRoots, genTime);
  if (!chainOk) {
    return { ok: false, reason: "tsa_cert_chain_unknown_root" };
  }

  // 8. Verify CMS SignerInfo signature over signed_attrs.
  // RFC 5652 sec 5.4: when signedAttrs is present, the to-be-signed bytes
  // are the DER encoding of `SignedAttributes` (SET OF Attribute) under
  // the universal SET tag (0x31), NOT under the IMPLICIT [0] tag (0xA0)
  // that appears on the wire. @peculiar/asn1-cms does not populate
  // ``signedAttrsRaw`` for the IMPLICIT-tagged SET in TimeStampToken
  // SignerInfos, so we reconstruct the canonical DER from the parsed
  // attribute objects (which preserve the on-wire DER SET ordering).
  if (!signerInfo.signedAttrs || signerInfo.signedAttrs.length === 0) {
    // RFC 3161 sec 2.4.2 mandates signedAttrs; absence is malformed.
    return { ok: false, reason: "tsr_decode_failed: missing signedAttrs" };
  }
  let tbsBytes: Buffer;
  try {
    tbsBytes = _encodeSignedAttrsAsSet(signerInfo.signedAttrs);
  } catch (exc) {
    return { ok: false, reason: `tsr_decode_failed: signedAttrs re-encode: ${(exc as Error).name}` };
  }

  // 9. Verify message_digest signed-attribute against actual TSTInfo digest.
  // The signed_attrs message_digest MUST equal SHA-256(eContent bytes).
  // The @peculiar/asn1-cms parser stores eContent as OctetString (.single)
  // with the raw DER of TSTInfo inside.
  const tstInfoDer = _extractTstInfoDer(eci);
  if (tstInfoDer === null) {
    return { ok: false, reason: "tsr_decode_failed: eContent absent" };
  }
  const expectedTstInfoDigest = createHash("sha256").update(tstInfoDer).digest();
  const messageDigestAttrVal = _extractSignedAttrValue(
    signerInfo.signedAttrs,
    "1.2.840.113549.1.9.4", // id-messageDigest
  );
  if (messageDigestAttrVal === null) {
    return { ok: false, reason: "tsr_decode_failed: signedAttrs missing message_digest" };
  }
  // The attribute value is itself an ASN.1 OCTET STRING; strip the
  // 2-byte header (tag 0x04 + length) so we have the raw digest bytes.
  const declaredDigest = _decodeAttrOctetString(messageDigestAttrVal);
  if (declaredDigest === null || !declaredDigest.equals(expectedTstInfoDigest)) {
    return { ok: false, reason: "tsa_signature_invalid" };
  }

  // 10. Decode TSTInfo's embedded MessageImprint and cross-check the
  // bundle digest. The Python verifier delegates to rfc3161_client.verify
  // which does this check; we do it explicitly.
  const miOk = _verifyMessageImprint(tstInfoDer, bundleDigestBytes);
  if (!miOk) {
    return { ok: false, reason: "message_imprint_mismatch" };
  }

  // 11. Verify the SignerInfo signature using the leaf's public key.
  const sigAlgOid = signerInfo.signatureAlgorithm.algorithm;
  const algInfo = SIG_ALG_BY_OID[sigAlgOid];
  if (!algInfo) {
    return { ok: false, reason: `tsa_signature_invalid (alg ${sigAlgOid})` };
  }
  const signatureBytes = Buffer.from(signerInfo.signature.buffer);
  const publicKey = leafCert.publicKey;
  let verified: boolean;
  try {
    verified = cryptoVerify(
      algInfo.hash,
      tbsBytes,
      { key: publicKey, dsaEncoding: "der" },
      signatureBytes,
    );
  } catch {
    return { ok: false, reason: "tsa_signature_invalid" };
  }
  if (!verified) {
    return { ok: false, reason: "tsa_signature_invalid" };
  }

  return { ok: true, reason: "" };
}

function _resolveSignerCert(sd: SignedData, signerInfo: import("@peculiar/asn1-cms").SignerInfo): X509Certificate | null {
  if (!sd.certificates) {
    return null;
  }
  const ias = signerInfo.sid?.issuerAndSerialNumber;
  if (!ias) {
    // RFC 5652 also permits subjectKeyIdentifier. The Python fixture
    // builder always uses IssuerAndSerialNumber; matching that path here.
    return null;
  }
  const wantSerial = Buffer.from(ias.serialNumber);
  // Re-serialize the wanted issuer Name to DER so we can byte-compare.
  let wantIssuerDer: Buffer;
  try {
    wantIssuerDer = Buffer.from(AsnSerializer.serialize(ias.issuer));
  } catch {
    return null;
  }
  for (const choice of sd.certificates) {
    const c = choice.certificate;
    if (!c) continue;
    // Compare serial number bytes and issuer DER.
    let candidateIssuerDer: Buffer;
    try {
      candidateIssuerDer = Buffer.from(AsnSerializer.serialize(c.tbsCertificate.issuer));
    } catch {
      continue;
    }
    if (!candidateIssuerDer.equals(wantIssuerDer)) {
      continue;
    }
    const candSerial = Buffer.from(c.tbsCertificate.serialNumber);
    if (!_equalIntegerBytes(candSerial, wantSerial)) {
      continue;
    }
    // Re-encode the whole Certificate to DER, then hand to X509Certificate.
    try {
      const certDer = Buffer.from(AsnSerializer.serialize(c));
      return new X509Certificate(certDer);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Compare two ASN.1 INTEGER byte-encodings ignoring leading-zero padding.
 * INTEGER is big-endian two's-complement; positive serials may carry a
 * leading 0x00 to disambiguate from negative.
 */
function _equalIntegerBytes(a: Buffer, b: Buffer): boolean {
  const aTrim = _trimIntLeadingZero(a);
  const bTrim = _trimIntLeadingZero(b);
  return aTrim.equals(bTrim);
}

function _trimIntLeadingZero(b: Buffer): Buffer {
  if (b.length > 1 && b[0] === 0x00 && (b[1] !== undefined && b[1] < 0x80)) {
    return b.subarray(1);
  }
  return b;
}

/**
 * Is `cert` within its validity window (notBefore <= t <= notAfter) at
 * instant `t`? RFC 5280 sec 4.1.2.5 defines the validity period as the
 * closed interval [notBefore, notAfter], so both bounds are INCLUSIVE.
 * This matches the Python/Rust path-validation semantics used by
 * rfc3161_client (the certs "only need to be valid at timestamp time").
 *
 * node:crypto exposes validFrom/validTo as RFC-2822-ish date strings; we
 * parse them with the Date constructor (the same way inspectTsaChain does)
 * and reject (return false) if either parses to NaN -- fail closed.
 */
function _certValidAt(cert: X509Certificate, t: Date): boolean {
  const notBefore = new Date(cert.validFrom).getTime();
  const notAfter = new Date(cert.validTo).getTime();
  if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) {
    return false;
  }
  const tt = t.getTime();
  if (Number.isNaN(tt)) {
    return false;
  }
  return notBefore <= tt && tt <= notAfter;
}

function _verifyLeafChainsToTrustRoots(
  leaf: X509Certificate,
  trustRoots: X509Certificate[],
  genTime: Date,
): boolean {
  // Per RFC 3161 the cert chain need only be valid AT the timestamp time
  // (gen_time), not now. An expired-at-gen_time or not-yet-valid-at-gen_time
  // leaf (or root) MUST be rejected even when the signature chains cleanly --
  // matching rfc3161_client verify.py:347-352 which supplies gen_time as the
  // PKCS7 verification time and validates every cert in the path against it.
  if (!_certValidAt(leaf, genTime)) {
    return false;
  }
  // Single-hop chain: leaf -> root in trustRoots. The Python fixture
  // builder produces exactly this shape (root issues leaf directly).
  // node:crypto.X509Certificate.publicKey is already a KeyObject of type
  // "public"; pass it directly to .verify() (do NOT wrap in
  // createPublicKey() which expects a private key input).
  for (const root of trustRoots) {
    try {
      // checkIssued: does leaf claim to be issued by root (issuer == root.subject)?
      if (!leaf.checkIssued(root)) continue;
      // The issuing root must ALSO be valid at gen_time (full-path validity).
      if (!_certValidAt(root, genTime)) continue;
      // verify: does the leaf's signature verify under root's public key?
      if (leaf.verify(root.publicKey)) {
        return true;
      }
    } catch {
      continue;
    }
  }
  // Self-signed leaf? Accept if the leaf itself is one of the trust roots
  // AND it is valid at gen_time (the leaf-window check above already passed).
  for (const root of trustRoots) {
    if (leaf.raw.equals(root.raw)) {
      return true;
    }
  }
  return false;
}

function _extractTstInfoDer(eci: EncapsulatedContentInfo): Buffer | null {
  if (!eci.eContent) return null;
  if (eci.eContent.single) {
    // OctetString instance: content is at byteOffset/byteLength within
    // .buffer (the parser may hand back a view onto a larger buffer).
    const s = eci.eContent.single;
    return Buffer.from(s.buffer, s.byteOffset, s.byteLength);
  }
  if (eci.eContent.any) {
    return Buffer.from(eci.eContent.any);
  }
  return null;
}

/**
 * Re-encode a parsed ``SignedAttributes`` (Attribute[]) under the
 * universal SET tag (0x31) per RFC 5652 sec 5.4. Returns the canonical
 * DER bytes the TSA signed over.
 *
 * Each Attribute is serialized individually via AsnSerializer.serialize
 * (producing a DER SEQUENCE), then the children are sorted lex-byte-wise
 * (DER SET canonical ordering) and concatenated under the SET wrapper.
 */
function _encodeSignedAttrsAsSet(
  signedAttrs: import("@peculiar/asn1-cms").SignedAttributes,
): Buffer {
  const children: Buffer[] = [];
  for (const attr of signedAttrs) {
    const der = Buffer.from(AsnSerializer.serialize(attr));
    children.push(der);
  }
  // DER SET canonical order: lex-byte-wise ascending.
  children.sort(Buffer.compare);
  const body = Buffer.concat(children);
  return Buffer.concat([Buffer.from([0x31]), _encodeDerLength(body.byteLength), body]);
}

/** Encode a length in DER short or long form. */
function _encodeDerLength(n: number): Buffer {
  if (n < 0) throw new Error(`negative length: ${n}`);
  if (n < 0x80) {
    return Buffer.from([n]);
  }
  // Long form: leading byte 0x80 | numOctets, then big-endian length.
  const octets: number[] = [];
  let m = n;
  while (m > 0) {
    octets.unshift(m & 0xff);
    m = m >>> 8;
  }
  if (octets.length > 0x7e) {
    throw new Error(`length too large for DER long form: ${n}`);
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
}

function _extractSignedAttrValue(
  signedAttrs: import("@peculiar/asn1-cms").SignedAttributes | undefined,
  oid: string,
): ArrayBuffer | null {
  if (!signedAttrs) return null;
  for (const attr of signedAttrs) {
    if (attr.attrType === oid) {
      const values = attr.attrValues;
      if (values && values.length > 0 && values[0]) {
        return values[0];
      }
    }
  }
  return null;
}

export function _decodeAttrOctetString(val: ArrayBuffer): Buffer | null {
  // Attribute values for message_digest are DER-encoded OCTET STRINGs:
  // 0x04 <len> <bytes>. Strip the 2- to 5-byte header.
  const buf = Buffer.from(val);
  if (buf.length < 2 || buf[0] !== 0x04) {
    return null;
  }
  const lenByte = buf[1];
  if (lenByte === undefined) return null;
  let headerLen: number;
  let contentLen: number;
  if (lenByte < 0x80) {
    headerLen = 2;
    contentLen = lenByte;
  } else {
    const lengthOfLength = lenByte & 0x7f;
    if (lengthOfLength < 1 || lengthOfLength > 4) return null;
    if (buf.length < 2 + lengthOfLength) return null;
    headerLen = 2 + lengthOfLength;
    contentLen = 0;
    for (let i = 0; i < lengthOfLength; i++) {
      const b = buf[2 + i];
      if (b === undefined) return null;
      // Use Number arithmetic (contentLen * 256 + b), NOT the 32-bit bitwise
      // form (contentLen << 8) | b. For a 4-byte length whose top bit is set
      // (>= 0x80000000) the bitwise `<<` overflows JS's signed 32-bit
      // operand and yields a NEGATIVE length, which then mis-handles the
      // bounds check below. Number arithmetic keeps contentLen a correct
      // non-negative integer for all 4-byte lengths (max 0xFFFFFFFF, well
      // within Number.MAX_SAFE_INTEGER).
      contentLen = contentLen * 256 + b;
    }
  }
  // Fail closed on a length that runs past the buffer (DoS guard) rather
  // than relying on the exact-fit equality check below. contentLen is
  // guaranteed non-negative here, so a claimed length larger than the
  // available bytes is a clean reject, never a wrapped/negative slice.
  if (contentLen > buf.length - headerLen) return null;
  if (buf.length !== headerLen + contentLen) return null;
  return buf.subarray(headerLen, headerLen + contentLen);
}

function _verifyMessageImprint(
  tstInfoDer: Buffer,
  bundleDigestBytes: Buffer,
): boolean {
  // Re-parse TSTInfo to extract MessageImprint.hashedMessage bytes.
  // TSTInfo is statically imported at the top of the file so the
  // @peculiar/asn1-schema decorator metadata is registered before
  // AsnParser.parse runs (lazy CJS require from inside this ESM file
  // produced "Cannot get schema for 'TSTInfo' target").
  try {
    const tstInfo = AsnParser.parse(tstInfoDer, TSTInfo);
    const hm = tstInfo.messageImprint.hashedMessage;
    // OctetString-derived view: respect byteOffset/byteLength so we
    // don't read adjacent buffer bytes when the parser handed us a
    // sub-slice of a larger ArrayBuffer.
    const declared = Buffer.from(hm.buffer, hm.byteOffset, hm.byteLength);
    return declared.equals(bundleDigestBytes);
  } catch {
    return false;
  }
}

/**
 * Validate a parsed RFC 3161 TSTInfo token against the bundle.
 *
 * Mirrors `packages/verifier/src/relay_verifier/tsa.py::validate_tsa_token`.
 * Failure modes:
 *   - token null/undefined -> outcome="missing", code=RELAY-EVID-031
 *   - message_imprint dict-level mismatch / malformed -> outcome="invalid"
 *   - gen_time outside +/-300s -> outcome="skew", code=RELAY-EVID-038
 *   - unparseable gen_time / decided_at -> outcome="invalid"
 *   - missing tsr_der_b64u -> outcome="invalid", reason="tsr_der_missing"
 *   - tsr_der decode fails -> outcome="invalid", reason="tsr_decode_failed: ..."
 *   - chain unknown root -> outcome="invalid", reason="tsa_cert_chain_unknown_root"
 *   - signature invalid -> outcome="invalid", reason="tsa_signature_invalid"
 */
export function validateTsaToken(args: {
  token: TsaToken | null | undefined;
  bundleDigestHex: string;
  decidedAt: string;
  chainCerts?: X509Certificate[] | null;
  /**
   * Test-injection seam: additional PEM-encoded trust roots to merge with
   * ``chainCerts``. Production callers leave this undefined; tests pass
   * an ephemeral root generated by the fixture builder (see
   * packages/verifier/tests/conftest_w10_4.py). Mirrors the Python
   * ``extra_trusted_roots_pem`` parameter.
   */
  extraTrustedRootsPem?: Uint8Array | Buffer | null;
}): TSAValidationResult {
  const { token, bundleDigestHex, decidedAt, chainCerts, extraTrustedRootsPem } = args;
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
    result.code = RELAY_EVID_031;
    return result;
  }
  const mi = msgImprint as Record<string, unknown>;
  const declaredAlg = mi["hash_algorithm"];
  const declaredDigest = mi["hashed_message_hex"];
  if (declaredAlg !== "sha256") {
    result.outcome = "invalid";
    result.reason = `TSA message_imprint must use sha256, got ${JSON.stringify(declaredAlg)}`;
    result.code = RELAY_EVID_031;
    return result;
  }
  if (declaredDigest !== bundleDigestHex) {
    result.outcome = "invalid";
    result.reason = "message_imprint_mismatch";
    result.code = RELAY_EVID_031;
    return result;
  }

  // 2. gen_time within +/-300s of decided_at.
  const genTimeRaw = token.gen_time;
  if (typeof genTimeRaw !== "string" || genTimeRaw.length === 0) {
    result.outcome = "invalid";
    result.reason = "TSA token missing 'gen_time'";
    result.code = RELAY_EVID_031;
    return result;
  }
  result.gen_time = genTimeRaw;
  let genTime: Date;
  try {
    genTime = _parseIsoZ(genTimeRaw);
  } catch (exc) {
    result.outcome = "invalid";
    result.reason = `TSA gen_time unparsable: ${(exc as Error).message}`;
    result.code = RELAY_EVID_031;
    return result;
  }
  let decided: Date;
  try {
    decided = _parseIsoZ(decidedAt);
  } catch (exc) {
    result.outcome = "invalid";
    result.reason = `bundle decided_at unparsable: ${(exc as Error).message}`;
    result.code = RELAY_EVID_031;
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

  // 3. Cryptographic TSA verification (VAL-V3M5-014..017).
  const tsrB64u = token.tsr_der_b64u;
  if (typeof tsrB64u !== "string" || tsrB64u.length === 0) {
    result.outcome = "invalid";
    result.reason = "tsr_der_missing";
    result.code = RELAY_EVID_031;
    return result;
  }
  let tsrDer: Buffer;
  try {
    tsrDer = _b64uDecode(tsrB64u);
  } catch (exc) {
    result.outcome = "invalid";
    result.reason = `tsr_der_b64u_decode_failed: ${(exc as Error).message}`;
    result.code = RELAY_EVID_031;
    return result;
  }

  // Assemble trust roots: bundled chain + caller-provided extras.
  const trustRoots: X509Certificate[] = [];
  if (chainCerts) {
    for (const c of chainCerts) trustRoots.push(c);
  }
  if (extraTrustedRootsPem && extraTrustedRootsPem.byteLength > 0) {
    let extras: X509Certificate[];
    try {
      extras = loadTsaChainPemBytes(extraTrustedRootsPem);
    } catch (exc) {
      result.outcome = "invalid";
      result.reason = `extra_trusted_roots_pem_parse_failed: ${(exc as Error).message}`;
      result.code = RELAY_EVID_031;
      return result;
    }
    for (const c of extras) trustRoots.push(c);
  }
  if (trustRoots.length === 0) {
    result.outcome = "invalid";
    result.reason = "tsa_no_trust_roots_available";
    result.code = RELAY_EVID_031;
    return result;
  }

  // The message_imprint check above already confirmed
  // declared_digest == bundleDigestHex; the bytes the TSA signed are the
  // bundle binding digest.
  const bundleDigestBytes = Buffer.from(bundleDigestHex, "hex");
  const verify = _verifyCryptographicSignature({
    tsrDer,
    bundleDigestBytes,
    trustRoots,
    // The token gen_time parsed above is the RFC 3161 verification time for
    // the cert chain validity window (notBefore <= gen_time <= notAfter).
    genTime,
  });
  if (!verify.ok) {
    result.outcome = "invalid";
    result.reason = verify.reason;
    result.code = RELAY_EVID_031;
    return result;
  }

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

// Side-effect: keep Asn1Certificate import live for tooling that
// tree-shakes unused names. The class is referenced via SignedData's
// CertificateChoices member but TS does not pick it up structurally.
void Asn1Certificate;
