// Structural-review P2 parity gaps in the TS RFC 3161 TSA validator.
//
// Three findings, each a Python<->TypeScript parity gap where the TS
// offline verifier ACCEPTED what the Python verifier REJECTS. The verifier
// is keystone invariant #8/#11: it MUST fail closed.
//
//   F1  PKIStatus gate skipped on non-number status. tsa.ts only rejected
//       when `typeof statusVal === "number"`; a non-granted status decoded
//       as a string (large INTEGER) or absent (undefined, malformed
//       TSTInfo) slipped the gate. Python (rfc3161_client verify.py:210-212)
//       raises VerificationError on ANY status != GRANTED/GRANTED_WITH_MODS.
//
//   F2  leaf->root chain check omitted the cert validity window at the TSA
//       genTime. _verifyLeafChainsToTrustRoots verified signature chaining
//       only; an EXPIRED (or not-yet-valid) TSA leaf with a good signature
//       was accepted. Python (rfc3161_client verify.py:347-352) supplies
//       tst_info.gen_time as the PKCS7 verification time -- the leaf MUST be
//       valid at genTime (notBefore <= genTime <= notAfter, inclusive).
//
//   F3  DER multi-byte length wrapped negative. _decodeAttrOctetString used
//       (contentLen << 8) | b; a 4-byte length with the top bit set yields a
//       NEGATIVE JS 32-bit result. The decoder must compute a non-negative
//       length and reject lengths beyond the buffer.
//
// Strategy: shell out to the Python fixture builder (conftest_w10_4.py) for
// real RFC 3161 DER, mutating the status / cert-validity-window in inline
// Python so the fixtures are minted with real crypto (no live network, no
// private key bytes on disk). The same Python verifier is invoked on each
// bad fixture to assert it rejects too (Py<->TS parity). F3 is a direct unit
// test on the exported length decoder.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  validateTsaToken,
  _decodeAttrOctetString,
  _isAcceptablePkiStatus,
} from "../src/tsa.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const CONFTEST_DIR = resolve(REPO_ROOT, "packages", "verifier", "tests");

interface BuiltFixture {
  token: Record<string, unknown>;
  bundle_digest_hex: string;
  decided_at: string;
  tsa_root_pem: string;
  /** Echo of the Python verifier's outcome on this fixture (parity probe). */
  py_outcome?: string;
  py_reason?: string;
}

/**
 * Run an inline Python program (header sets up sys.path to the conftest
 * dir) and parse its last stdout line as JSON.
 */
function runPython(body: string): BuiltFixture {
  const code =
    `import base64, datetime, json, sys, hashlib\n` +
    `sys.path.insert(0, ${JSON.stringify(CONFTEST_DIR)})\n` +
    body;
  const tmpFile = resolve(
    tmpdir(),
    `relay-v3m5-p2-${process.pid}-${Math.random().toString(36).slice(2)}.py`,
  );
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120_000,
    });
    if (r.status !== 0) {
      throw new Error(`python fixture builder failed (status=${r.status}): ${r.stderr}`);
    }
    const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
    return JSON.parse(line) as BuiltFixture;
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

// Shared Python helpers (cert chain with explicit validity bounds, and a
// status-mutating TSR builder). Mirror conftest's _build_real_tsr_der but
// allow per-test parameterization of PKIStatus and the cert window.
const PY_CHAIN_HELPERS = `
import datetime as _dt
from cryptography import x509 as _cx509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.x509.oid import ExtendedKeyUsageOID as _EKUOID
from cryptography.x509.oid import NameOID as _NameOID

def make_chain(not_before, not_after):
    root_sk = _ec.generate_private_key(_ec.SECP256R1())
    root_subj = _cx509.Name([
        _cx509.NameAttribute(_NameOID.COMMON_NAME, "Relay Test P2 TSA Root"),
        _cx509.NameAttribute(_NameOID.ORGANIZATION_NAME, "Epochly, Inc. (test)"),
    ])
    root_cert = (
        _cx509.CertificateBuilder()
        .subject_name(root_subj).issuer_name(root_subj)
        .public_key(root_sk.public_key())
        .serial_number(_cx509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(_cx509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_cx509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(root_sk, _hashes.SHA256())
    )
    leaf_sk = _ec.generate_private_key(_ec.SECP256R1())
    leaf_subj = _cx509.Name([
        _cx509.NameAttribute(_NameOID.COMMON_NAME, "Relay Test P2 TSA Signer"),
        _cx509.NameAttribute(_NameOID.ORGANIZATION_NAME, "Epochly, Inc. (test)"),
    ])
    leaf_cert = (
        _cx509.CertificateBuilder()
        .subject_name(leaf_subj).issuer_name(root_subj)
        .public_key(leaf_sk.public_key())
        .serial_number(_cx509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(_cx509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_cx509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(_cx509.ExtendedKeyUsage([_EKUOID.TIME_STAMPING]), critical=True)
        .sign(root_sk, _hashes.SHA256())
    )
    return leaf_sk, leaf_cert, root_cert
`;

// Build a TSR with an explicit PKIStatus string (granted/grantedWithMods/
// rejection/...) so F1 can mint a non-granted, otherwise-well-formed token.
const PY_TSR_STATUS_BUILDER = `
from asn1crypto import algos as _asn1_algos
from asn1crypto import cms as _asn1_cms
from asn1crypto import core as _asn1_core
from asn1crypto import tsp as _asn1_tsp
from asn1crypto import x509 as _asn1_x509
from cryptography.hazmat.primitives import serialization as _serialization
_TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"

def build_tsr_with_status(*, leaf_sk, leaf_cert, bundle_digest_hex, gen_time_iso_z, status_name):
    bundle_digest_bytes = bytes.fromhex(bundle_digest_hex)
    gen_time_dt = _dt.datetime.fromisoformat(gen_time_iso_z[:-1] + "+00:00")
    tst_info = _asn1_tsp.TSTInfo()
    tst_info["version"] = 1
    tst_info["policy"] = "1.3.6.1.4.1.601.10.3.1"
    mi = _asn1_tsp.MessageImprint()
    mi["hash_algorithm"] = _asn1_algos.DigestAlgorithm({"algorithm": "sha256"})
    mi["hashed_message"] = bundle_digest_bytes
    tst_info["message_imprint"] = mi
    tst_info["serial_number"] = 424242
    tst_info["gen_time"] = gen_time_dt
    tst_info_der = tst_info.dump()
    signing_time = _asn1_cms.Time(name="utc_time", value=gen_time_dt.replace(microsecond=0))
    signed_attrs = _asn1_cms.CMSAttributes([
        _asn1_cms.CMSAttribute({"type": "content_type", "values": [_TST_INFO_OID]}),
        _asn1_cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(tst_info_der).digest()]}),
        _asn1_cms.CMSAttribute({"type": "signing_time", "values": [signing_time]}),
    ])
    signature_bytes = leaf_sk.sign(signed_attrs.dump(), _ec.ECDSA(_hashes.SHA256()))
    asn1_leaf = _asn1_x509.Certificate.load(leaf_cert.public_bytes(_serialization.Encoding.DER))
    signer_info = _asn1_cms.SignerInfo()
    signer_info["version"] = "v1"
    signer_info["sid"] = _asn1_cms.SignerIdentifier(name="issuer_and_serial_number",
        value=_asn1_cms.IssuerAndSerialNumber({"issuer": asn1_leaf.issuer, "serial_number": asn1_leaf.serial_number}))
    signer_info["digest_algorithm"] = _asn1_algos.DigestAlgorithm({"algorithm": "sha256"})
    signer_info["signed_attrs"] = signed_attrs
    signer_info["signature_algorithm"] = _asn1_algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    signer_info["signature"] = signature_bytes
    eci = _asn1_cms.EncapsulatedContentInfo()
    eci["content_type"] = _TST_INFO_OID
    eci["content"] = _asn1_core.ParsableOctetString(tst_info_der)
    sd = _asn1_cms.SignedData()
    sd["version"] = "v3"
    sd["digest_algorithms"] = [_asn1_algos.DigestAlgorithm({"algorithm": "sha256"})]
    sd["encap_content_info"] = eci
    sd["certificates"] = [_asn1_cms.CertificateChoices(name="certificate", value=asn1_leaf)]
    sd["signer_infos"] = [signer_info]
    ci = _asn1_cms.ContentInfo()
    ci["content_type"] = "signed_data"
    ci["content"] = sd
    tsr = _asn1_tsp.TimeStampResp()
    tsr["status"] = _asn1_tsp.PKIStatusInfo({"status": status_name})
    tsr["time_stamp_token"] = ci
    return tsr.dump()

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
`;

// Invoke the actual Python verifier on a token so we can assert Py<->TS
// parity (the Python verifier is the source of truth for "fail closed").
const PY_VERIFY = `
from relay_verifier.tsa import validate_tsa_token, load_tsa_chain_pem_bytes

def py_verify(token, bundle_digest_hex, decided_at, root_pem):
    res = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest_hex,
        decided_at=decided_at,
        chain_certs=None,
        extra_trusted_roots_pem=root_pem.encode("ascii"),
    )
    return res.outcome, res.reason
`;

// ===========================================================================
// FINDING 1: non-granted / non-numeric / missing PKIStatus must REJECT.
// ===========================================================================

describe("F1 PKIStatus gate fails closed on non-granted status", () => {
  // Gate-logic unit tests: prove the gate fails closed on EVERY non-granted
  // shape. The prior `typeof statusVal === "number" && ...` form SKIPPED the
  // gate when the decoded status was not a JS number -- a large INTEGER
  // decodes as a string under @peculiar/asn1-schema, and a malformed TSTInfo
  // yields undefined. Python rejects all of these (rfc3161_client verify.py
  // PKIStatus(...) raises on out-of-range; decode raises on malformed).
  test("granted(0) and grantedWithMods(1) are accepted", () => {
    expect(_isAcceptablePkiStatus(0)).toBe(true);
    expect(_isAcceptablePkiStatus(1)).toBe(true);
  });

  test("non-granted numeric status is rejected", () => {
    expect(_isAcceptablePkiStatus(2)).toBe(false); // rejection
    expect(_isAcceptablePkiStatus(3)).toBe(false); // waiting
    expect(_isAcceptablePkiStatus(5)).toBe(false); // revocationNotification
  });

  test("non-numeric / missing / out-of-range status is rejected (the gap)", () => {
    // Large INTEGER decoded as a string (the @peculiar/asn1-schema behavior
    // for values beyond Number.MAX_SAFE_INTEGER): the old gate skipped this.
    expect(_isAcceptablePkiStatus("9223372036854775807")).toBe(false);
    expect(_isAcceptablePkiStatus("0")).toBe(false); // string "0" is NOT number 0
    // Malformed TSTInfo -> tsr.status?.status is undefined.
    expect(_isAcceptablePkiStatus(undefined)).toBe(false);
    expect(_isAcceptablePkiStatus(null)).toBe(false);
    // bigint shape (defensive): not the number 0/1.
    expect(_isAcceptablePkiStatus(BigInt(0))).toBe(false);
    expect(_isAcceptablePkiStatus(NaN)).toBe(false);
    expect(_isAcceptablePkiStatus(0.5)).toBe(false);
  });

  test("rejection(2) status TSR is rejected end-to-end (Py<->TS parity)", () => {
    const fx = runPython(
      PY_CHAIN_HELPERS + PY_TSR_STATUS_BUILDER + PY_VERIFY +
      `
decided_at = "2026-05-15T12:34:56Z"
gen_time = decided_at
digest_hex = "0" * 64
from cryptography.hazmat.primitives import serialization
now = _dt.datetime.now(_dt.UTC)
nb = now - _dt.timedelta(days=365); na = now + _dt.timedelta(days=365)
leaf_sk, leaf_cert, root_cert = make_chain(nb, na)
tsr = build_tsr_with_status(leaf_sk=leaf_sk, leaf_cert=leaf_cert,
    bundle_digest_hex=digest_hex, gen_time_iso_z=gen_time, status_name="rejection")
token = {
  "version": 1, "policy_oid": "1.3.6.1.4.1.601.10.3.1",
  "message_imprint": {"hash_algorithm": "sha256", "hashed_message_hex": digest_hex},
  "serial_number": "424242", "gen_time": gen_time, "tsa_signature_alg": "ES256",
  "tsr_der_b64u": b64u(tsr),
}
root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
py_outcome, py_reason = py_verify(token, digest_hex, decided_at, root_pem)
print(json.dumps({"token": token, "bundle_digest_hex": digest_hex,
  "decided_at": decided_at, "tsa_root_pem": root_pem,
  "py_outcome": py_outcome, "py_reason": py_reason}))
`,
    );
    // Python source of truth: must reject the non-granted TSR.
    expect(fx.py_outcome).toBe("invalid");

    const r = validateTsaToken({
      token: fx.token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).not.toBe("");
  });
});

// ===========================================================================
// FINDING 2: cert validity window checked at TSA genTime (inclusive).
// ===========================================================================

describe("F2 leaf->root chain enforces cert validity window at genTime", () => {
  // gen_time is fixed at 2026-05-15T12:34:56Z (== decided_at, zero skew).
  // Cert windows are positioned RELATIVE to that gen_time so the validity
  // outcome is deterministic and independent of wall-clock.
  function buildWindowedFixture(windowKind: "valid" | "expired" | "not-yet-valid"): BuiltFixture {
    return runPython(
      PY_CHAIN_HELPERS + PY_TSR_STATUS_BUILDER + PY_VERIFY +
      `
from cryptography.hazmat.primitives import serialization
decided_at = "2026-05-15T12:34:56Z"
gen_time = decided_at
digest_hex = "0" * 64
g = _dt.datetime.fromisoformat(gen_time[:-1] + "+00:00")
kind = ${JSON.stringify(windowKind)}
if kind == "valid":
    nb = g - _dt.timedelta(days=30); na = g + _dt.timedelta(days=30)
elif kind == "expired":
    # cert expired one day BEFORE gen_time
    nb = g - _dt.timedelta(days=30); na = g - _dt.timedelta(days=1)
else:  # not-yet-valid: cert starts one day AFTER gen_time
    nb = g + _dt.timedelta(days=1); na = g + _dt.timedelta(days=30)
leaf_sk, leaf_cert, root_cert = make_chain(nb, na)
tsr = build_tsr_with_status(leaf_sk=leaf_sk, leaf_cert=leaf_cert,
    bundle_digest_hex=digest_hex, gen_time_iso_z=gen_time, status_name="granted")
token = {
  "version": 1, "policy_oid": "1.3.6.1.4.1.601.10.3.1",
  "message_imprint": {"hash_algorithm": "sha256", "hashed_message_hex": digest_hex},
  "serial_number": "424242", "gen_time": gen_time, "tsa_signature_alg": "ES256",
  "tsr_der_b64u": b64u(tsr),
}
root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
py_outcome, py_reason = py_verify(token, digest_hex, decided_at, root_pem)
print(json.dumps({"token": token, "bundle_digest_hex": digest_hex,
  "decided_at": decided_at, "tsa_root_pem": root_pem,
  "py_outcome": py_outcome, "py_reason": py_reason}))
`,
    );
  }

  test("expired-at-genTime leaf rejected (Py<->TS parity)", () => {
    const fx = buildWindowedFixture("expired");
    expect(fx.py_outcome).toBe("invalid"); // Python source of truth rejects
    const r = validateTsaToken({
      token: fx.token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsa_cert_chain_unknown_root");
  });

  test("not-yet-valid-at-genTime leaf rejected (Py<->TS parity)", () => {
    const fx = buildWindowedFixture("not-yet-valid");
    expect(fx.py_outcome).toBe("invalid");
    const r = validateTsaToken({
      token: fx.token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsa_cert_chain_unknown_root");
  });

  test("valid-at-genTime leaf STILL ACCEPTS (no false positive)", () => {
    const fx = buildWindowedFixture("valid");
    expect(fx.py_outcome).toBe("ok"); // Python accepts the in-window cert
    const r = validateTsaToken({
      token: fx.token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("ok");
    expect(r.reason).toBe("");
  });
});

// ===========================================================================
// FINDING 3: DER multi-byte length must not wrap negative.
// ===========================================================================

describe("F3 _decodeAttrOctetString multi-byte length never wraps negative", () => {
  test("4-byte length with top bit set is rejected, never negative", () => {
    // OCTET STRING header claiming a 4-byte length 0x80000000 (top bit set).
    // The buffer is far shorter than the claimed length, so the correct
    // behavior is a clean reject (return null), NOT a negative/wrapped len.
    const header = Buffer.from([0x04, 0x84, 0x80, 0x00, 0x00, 0x00]);
    const body = Buffer.from([0xaa, 0xbb]);
    const buf = Buffer.concat([header, body]);
    // Must not throw and must reject (null) -- the prior (<<8 | b) path
    // produced contentLen = -2147483648 and would mis-handle the bounds.
    const out = _decodeAttrOctetString(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
    expect(out).toBeNull();
  });

  test("valid 4-byte length decodes to correct positive content", () => {
    // 4-byte length encoding of 2 (0x00000002); content == 2 bytes.
    const buf = Buffer.from([0x04, 0x84, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad]);
    const out = _decodeAttrOctetString(
      buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
    );
    expect(out).not.toBeNull();
    expect(out!.equals(Buffer.from([0xde, 0xad]))).toBe(true);
  });

  test("short-form length still decodes correctly", () => {
    const buf = Buffer.from([0x04, 0x02, 0x12, 0x34]);
    const out = _decodeAttrOctetString(
      buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
    );
    expect(out).not.toBeNull();
    expect(out!.equals(Buffer.from([0x12, 0x34]))).toBe(true);
  });
});
