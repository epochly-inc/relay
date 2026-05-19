// VAL-V3M5-014..017: TS TSA crypto parity with Python.
//
// Python flipped TSA_CRYPTO_IMPLEMENTED=True in v0.2 M09 w9-2 via the
// rfc3161-client + asn1crypto stack. The TypeScript port at M06 was
// fail-closed (TSA_CRYPTO_IMPLEMENTED=false) because the ASN.1 stack had
// not yet been ported. Per relay-v0.3-audit-resolution M5/F5.7 the TS
// verifier now performs the same RFC 3161 verification using
// @peculiar/asn1-tsp + @peculiar/asn1-cms + @peculiar/asn1-x509 to decode
// the TimeStampResp DER, plus node:crypto for the chain verify and the
// CMS SignerInfo signature check.
//
// Strategy: shell out to the Python fixture builder in
// packages/verifier/tests/conftest_w10_4.py (the same builder the Python
// tsa.py verifier round-trips against). That gives a real
// TimeStampResp DER that the Python verifier accepts -- and that the new
// TS verifier MUST also accept. The fixture builder also returns the
// PEM-encoded ephemeral TSA root cert; we pass it via
// extraTrustedRootsPem so the TS verifier anchors against it.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, test } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  TSA_CRYPTO_IMPLEMENTED,
  validateTsaToken,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..", "..", "..");

// ---------------------------------------------------------------------------
// Python fixture builder bridge.
// ---------------------------------------------------------------------------

interface BuiltFixture {
  token: Record<string, unknown>;
  bundle_digest_hex: string;
  decided_at: string;
  tsa_root_pem: string;
}

function buildFixture(opts: {
  decidedAt?: string;
  skewSeconds?: number;
  bundleDigestHex?: string;
} = {}): BuiltFixture {
  const decidedAt = opts.decidedAt ?? "2026-05-15T12:34:56Z";
  const skew = opts.skewSeconds ?? 0;
  const digestHex =
    opts.bundleDigestHex ??
    // deterministic 32 bytes (sha256("v3m5-f07-bundle-digest"))
    "0".repeat(64);
  const code = `import base64, datetime, json, sys, hashlib

sys.path.insert(0, ${JSON.stringify(resolve(REPO_ROOT, "packages", "verifier", "tests"))})
from conftest_w10_4 import _make_test_tsa_chain, _build_tsa_token
from cryptography.hazmat.primitives import serialization

decided_at = ${JSON.stringify(decidedAt)}
skew = ${skew}
digest_hex = ${JSON.stringify(digestHex)}

dt = datetime.datetime.fromisoformat(decided_at[:-1] + "+00:00")
gen_time = (dt + datetime.timedelta(seconds=skew)).astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")

leaf_sk, leaf_cert, root_cert = _make_test_tsa_chain()
token = _build_tsa_token(
    bundle_digest_hex=digest_hex,
    gen_time=gen_time,
    leaf_sk=leaf_sk,
    leaf_cert=leaf_cert,
)
root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
sys.stdout.write(json.dumps({
    "token": token,
    "bundle_digest_hex": digest_hex,
    "decided_at": decided_at,
    "tsa_root_pem": root_pem,
}))
`;
  const tmpFile = resolve(tmpdir(), `relay-v3m5-tsa-fixture-${process.pid}-${Math.random().toString(36).slice(2)}.py`);
  writeFileSync(tmpFile, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", tmpFile], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120_000,
    });
    if (r.status !== 0) {
      throw new Error(`fixture builder failed (status=${r.status}): ${r.stderr}`);
    }
    const line = r.stdout.trim().split(/\r?\n/).pop() ?? "";
    return JSON.parse(line) as BuiltFixture;
  } finally {
    rmSync(tmpFile, { force: true });
  }
}

// ===========================================================================
// VAL-V3M5-014: TSA_CRYPTO_IMPLEMENTED flag is now true (parity with Python).
// ===========================================================================

describe("VAL-V3M5-014 TSA_CRYPTO_IMPLEMENTED is true", () => {
  test("TS exports TSA_CRYPTO_IMPLEMENTED=true", () => {
    expect(TSA_CRYPTO_IMPLEMENTED).toBe(true);
  });
});

// ===========================================================================
// VAL-V3M5-015: real TimeStampResp DER decodes + verifies end-to-end.
// ===========================================================================

describe("VAL-V3M5-015 valid TSR over ephemeral chain returns outcome=ok", () => {
  test("real fixture verifies", () => {
    const fx = buildFixture();
    const r = validateTsaToken({
      token: fx.token as Record<string, unknown>,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("ok");
    expect(r.reason).toBe("");
    expect(r.skew_seconds).toBe(0);
  });
});

// ===========================================================================
// VAL-V3M5-016: tampered TimeStampResp DER signature is rejected.
// ===========================================================================

describe("VAL-V3M5-016 tampered TSR signature rejected", () => {
  test("flipping a byte in the decoded TSR DER flips outcome to invalid", () => {
    const fx = buildFixture();
    const token = { ...(fx.token as Record<string, unknown>) };
    const orig = String(token["tsr_der_b64u"]);
    // Base64url-decode, XOR the last byte (lives inside the SignerInfo
    // signature OCTET STRING), re-encode. Changing a SignerInfo signature
    // byte guarantees the SignedData signature no longer verifies.
    let b64 = orig.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (-b64.length) % 4;
    if (pad > 0) b64 += "=".repeat(pad);
    const der = Buffer.from(b64, "base64");
    der[der.length - 1] = der[der.length - 1]! ^ 0xff;
    const tamperedB64u = der.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    token["tsr_der_b64u"] = tamperedB64u;
    const r = validateTsaToken({
      token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    // Either decode fails or signature fails -- both are valid rejection
    // categories. The contract is "ok was not falsely claimed".
    expect(r.reason).not.toBe("");
  });

  test("verification against unrelated root yields chain_unknown_root", () => {
    const fxA = buildFixture();
    const fxB = buildFixture();
    // Verify fxA's token against fxB's root only -- no chain.
    const r = validateTsaToken({
      token: fxA.token as Record<string, unknown>,
      bundleDigestHex: fxA.bundle_digest_hex,
      decidedAt: fxA.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fxB.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsa_cert_chain_unknown_root");
  });
});

// ===========================================================================
// VAL-V3M5-017: missing tsr_der_b64u rejected with tsr_der_missing.
// ===========================================================================

describe("VAL-V3M5-017 missing tsr_der_b64u rejected", () => {
  test("token without tsr_der_b64u => outcome=invalid, reason=tsr_der_missing", () => {
    const fx = buildFixture();
    const token = { ...(fx.token as Record<string, unknown>) };
    delete token["tsr_der_b64u"];
    const r = validateTsaToken({
      token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsr_der_missing");
  });

  test("empty string tsr_der_b64u => outcome=invalid, reason=tsr_der_missing", () => {
    const fx = buildFixture();
    const token = { ...(fx.token as Record<string, unknown>) };
    token["tsr_der_b64u"] = "";
    const r = validateTsaToken({
      token,
      bundleDigestHex: fx.bundle_digest_hex,
      decidedAt: fx.decided_at,
      chainCerts: null,
      extraTrustedRootsPem: Buffer.from(fx.tsa_root_pem, "utf-8"),
    });
    expect(r.outcome).toBe("invalid");
    expect(r.reason).toBe("tsr_der_missing");
  });
});
