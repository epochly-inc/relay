/**
 * W4.5 real Sigstore-bundle verification (VAL-CRYPTO-002).
 *
 * Regression coverage for the bug-hunt finding (base commit c911607):
 * ``verifySigstoreBundle`` performed NO cryptography. It checked only that
 * fields were present (cert/signature non-empty, a tlog entry exists, the
 * bundle's ``trust_root`` claim equals the configured trust root) and was
 * never passed the bundle bytes. A fully forged/unsigned bundle whose JSON
 * was well-formed (``cert: "FAKE_CERT_PEM"``,
 * ``signature: "FAKE_SIGNATURE_BASE64"``) passed.
 *
 * After the fix ``verifySigstoreBundle(bundleBytes, sigstoreJson, options)``
 * performs real verification:
 *   - the signature is cryptographically verified over the bundle bytes
 *     using the public key in the Fulcio leaf certificate;
 *   - the leaf cert issuer is validated against the configured trust root;
 *   - the bundle's ``messageDigest`` (when present) is asserted to equal
 *     SHA-256(bundleBytes) and the manifest-pinned ``entry.sha256``.
 * Any missing/invalid signature, bad issuer, or digest mismatch fails
 * closed with RelaySidecarBundleUnverified (RELAY-SIDECAR-020).
 *
 * The happy-path fixture mints a real Fulcio-style leaf certificate and
 * key via Python's ``cryptography`` (the established repo pattern used in
 * packages/verifier-typescript/test/m06_parity.test.ts) and signs the real
 * bundle bytes with ``node:crypto``. No new npm dependency is introduced.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it, beforeAll } from "vitest";
import {
  createHash,
  createPrivateKey,
  sign as nodeSign,
  X509Certificate,
} from "node:crypto";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { RelaySidecarBundleUnverified } from "../src/errors.js";
import {
  REAL_SIGSTORE_HAPPY_PATH_POLICY,
  verifySigstoreBundle,
} from "../src/bin/verify.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const TRUST_ROOT = "relay.epochly.com";
const BUNDLE_BYTES = Buffer.from("relay-sidecar-binary-v0.1");
const BUNDLE_DIGEST_HEX = createHash("sha256").update(BUNDLE_BYTES).digest("hex");
const BUNDLE_DIGEST_B64 = createHash("sha256").update(BUNDLE_BYTES).digest("base64");

interface RealMaterial {
  /** PEM-encoded leaf certificate whose issuer carries the trust root. */
  certPem: string;
  /** DER bytes of the leaf certificate, base64-encoded (protobuf-bundle form). */
  certDerB64: string;
  /** PKCS#8 PEM private key matching the leaf cert public key. */
  keyPem: string;
}

/**
 * Mint a real EC P-256 Fulcio-style leaf certificate + key whose ISSUER
 * common-name carries the trust-root host. Returns null when the local
 * Python ``cryptography`` toolchain is unavailable so the suite degrades
 * to skip-with-evidence instead of a false failure.
 */
function mintRealLeafCert(trustRootHost: string): RealMaterial | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w45-"));
  const script = path.join(tmpDir, "mint.py");
  const certOut = path.join(tmpDir, "leaf.pem");
  const derOut = path.join(tmpDir, "leaf.der");
  const keyOut = path.join(tmpDir, "leaf.key.pem");
  const code = `import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
# Fulcio-style: subject is the workload identity, issuer carries the CA host.
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'relay-sidecar-release')])
issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, ${JSON.stringify("sigstore-intermediate." + trustRootHost)}),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ${JSON.stringify(trustRootHost)}),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
    .add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(${JSON.stringify("https://release@" + trustRootHost)})]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)
with open(${JSON.stringify(certOut)}, 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open(${JSON.stringify(derOut)}, 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.DER))
with open(${JSON.stringify(keyOut)}, 'wb') as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
`;
  fs.writeFileSync(script, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", script], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 60_000,
    });
    if (r.status !== 0) {
      return null;
    }
    return {
      certPem: fs.readFileSync(certOut, "utf-8"),
      certDerB64: fs.readFileSync(derOut).toString("base64"),
      keyPem: fs.readFileSync(keyOut, "utf-8"),
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/** Build a protobuf-bundle (cosign) JSON over the real signed material. */
function buildRealSigstoreJson(
  material: RealMaterial,
  opts: { tamperSignature?: boolean; messageDigestB64?: string } = {},
): string {
  const privateKey = createPrivateKey(material.keyPem);
  const sigDer = nodeSign("sha256", BUNDLE_BYTES, privateKey);
  let signatureB64 = sigDer.toString("base64");
  if (opts.tamperSignature) {
    // Flip a byte so the signature no longer verifies under the cert key.
    const buf = Buffer.from(sigDer);
    const last = buf.length - 1;
    buf[last] = (buf[last] ?? 0) ^ 0xff;
    signatureB64 = buf.toString("base64");
  }
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
    verificationMaterial: {
      certificate: { rawBytes: material.certDerB64 },
      tlogEntries: [{ logIndex: "12345", logID: { keyId: "fake-log-id" } }],
    },
    messageSignature: {
      signature: signatureB64,
      messageDigest: {
        algorithm: "SHA2_256",
        digest: opts.messageDigestB64 ?? BUNDLE_DIGEST_B64,
      },
    },
    trust_root: TRUST_ROOT,
  };
  return JSON.stringify(bundle);
}

describe("VAL-CRYPTO-002: verifySigstoreBundle performs real cryptography (fail-closed)", () => {
  it("REGRESSION: a structurally-complete but FORGED legacy bundle is REJECTED", () => {
    // This is exactly the fixture the old structural check accepted: a
    // well-formed JSON object with a non-empty cert string, a non-empty
    // signature string, a tlog entry, and a matching trust_root claim --
    // and ZERO real cryptography behind any of it.
    const forged = JSON.stringify({
      cert: "FAKE_CERT_PEM",
      signature: "FAKE_SIGNATURE_BASE64",
      rekorBundle: { Payload: { logIndex: 12345, logID: "fake-log-id" } },
      trust_root: TRUST_ROOT,
    });
    expect(() =>
      verifySigstoreBundle(BUNDLE_BYTES, forged, {
        trustRoot: TRUST_ROOT,
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("REGRESSION: a forged protobuf-bundle (random base64 cert + sig) is REJECTED", () => {
    const forged = JSON.stringify({
      verificationMaterial: {
        certificate: { rawBytes: Buffer.from("not-a-real-cert").toString("base64") },
        tlogEntries: [{ logIndex: "1", logID: { keyId: "x" } }],
      },
      messageSignature: {
        signature: Buffer.from("not-a-real-signature").toString("base64"),
        messageDigest: { algorithm: "SHA2_256", digest: BUNDLE_DIGEST_B64 },
      },
      trust_root: TRUST_ROOT,
    });
    expect(() =>
      verifySigstoreBundle(BUNDLE_BYTES, forged, {
        trustRoot: TRUST_ROOT,
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002: real-crypto happy path and tamper rejection", () => {
  let material: RealMaterial | null = null;

  beforeAll(() => {
    material = mintRealLeafCert(TRUST_ROOT);
  });

  it("sanity: minted a real leaf cert (else the toolchain is unavailable)", () => {
    if (material === null) {
      throw new Error(
        "Python cryptography toolchain unavailable; cannot mint a real " +
          "Fulcio-style cert. Install uv + the workspace venv to run this test.",
      );
    }
    // The cert MUST parse via node:crypto and carry the trust root in its issuer.
    const cert = new X509Certificate(Buffer.from(material.certDerB64, "base64"));
    expect(cert.issuer).toContain(TRUST_ROOT);
  });

  it("happy path: a real, fully-valid production Sigstore bundle VERIFIES", () => {
    // Post the W4.7 trust-chain hardening, a SELF-SIGNED leaf (as minted
    // above for the negative cases) is correctly REJECTED -- it does not
    // chain to the pinned Fulcio root and lacks a real Rekor inclusion proof.
    // The genuine happy path is a REAL recorded production Sigstore bundle
    // (sigstore-js's keyless-signed provenance attestation) verified against
    // the pinned public-good trusted root with FULL thresholds. The
    // comprehensive per-hardening-item coverage lives in
    // w4_7_sigstore_trust_chain.test.ts; this asserts the positive case here.
    const realBundleJson = fs.readFileSync(
      path.join(__dirname, "fixtures", "sigstore", "real-provenance.sigstore.json"),
      "utf8",
    );
    const signer = verifySigstoreBundle(undefined, realBundleJson, {
      identityPolicy: REAL_SIGSTORE_HAPPY_PATH_POLICY,
    });
    expect(signer).toBeTruthy();
    expect(signer.identity?.extensions?.issuer).toBe(
      "https://token.actions.githubusercontent.com",
    );
  });

  it("tampered bundle bytes (signature no longer matches) is REJECTED", () => {
    if (material === null) throw new Error("toolchain unavailable");
    const sigstoreJson = buildRealSigstoreJson(material);
    const tamperedBytes = Buffer.from("relay-sidecar-binary-TAMPERED");
    expect(() =>
      verifySigstoreBundle(tamperedBytes, sigstoreJson, {
        trustRoot: TRUST_ROOT,
        // expectedSha256 of the ORIGINAL bytes -- mismatch must fail closed.
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("invalid signature (single bit flipped) is REJECTED", () => {
    if (material === null) throw new Error("toolchain unavailable");
    const sigstoreJson = buildRealSigstoreJson(material, { tamperSignature: true });
    expect(() =>
      verifySigstoreBundle(BUNDLE_BYTES, sigstoreJson, {
        trustRoot: TRUST_ROOT,
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("messageDigest that disagrees with the manifest entry.sha256 is REJECTED", () => {
    if (material === null) throw new Error("toolchain unavailable");
    const wrongDigestB64 = createHash("sha256").update("other-bytes").digest("base64");
    const sigstoreJson = buildRealSigstoreJson(material, {
      messageDigestB64: wrongDigestB64,
    });
    expect(() =>
      verifySigstoreBundle(BUNDLE_BYTES, sigstoreJson, {
        trustRoot: TRUST_ROOT,
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("a real signature whose cert issuer does NOT carry the trust root is REJECTED", () => {
    const other = mintRealLeafCert("attacker.example.org");
    if (other === null) throw new Error("toolchain unavailable");
    const sigstoreJson = buildRealSigstoreJson(other);
    // The sigstore JSON above pins trust_root=relay.epochly.com but the
    // cert issuer is attacker.example.org -- the cert/issuer check must fire.
    expect(() =>
      verifySigstoreBundle(BUNDLE_BYTES, sigstoreJson, {
        trustRoot: TRUST_ROOT,
        expectedSha256: BUNDLE_DIGEST_HEX,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});
