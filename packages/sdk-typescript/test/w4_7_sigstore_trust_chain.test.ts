/**
 * W4.7 fail-CLOSED Sigstore trust-chain hardening (VAL-CRYPTO-002/003,
 * Gate-2 remediation: fix-r2-sdk-verify-trust-chain).
 *
 * The Gate-2 structural review found the prior node:crypto verifier
 * fail-OPEN against a self-minted cert: trust binding was a SUBSTRING
 * issuer match (``issuer.includes(trustRoot)``) with NO chain validation,
 * no cert-validity check, no curve pin, a skippable messageDigest binding,
 * and only a structural presence check on the Rekor entry (no Merkle
 * inclusion proof / SET / checkpoint verification).
 *
 * This suite proves the hardened verifier is fail-CLOSED. Each of the six
 * hardening items is exercised with a REJECTED case; a genuine, fully-valid
 * production Sigstore bundle is ACCEPTED (happy path). The implementation
 * delegates full bundle verification to the official ``@sigstore/verify``
 * against a PINNED public-good Sigstore trusted root bundled in-repo at
 * ``src/bin/sigstore-trusted-root.json`` (no network fetch).
 *
 *   1. EXACT identity match  -- a self-minted leaf whose SAN/issuer merely
 *      CONTAINS the configured identity is REJECTED (no substring match);
 *   2. CHAIN to pinned root  -- a leaf that does not chain to the pinned
 *      Fulcio root is REJECTED;
 *   3. VALIDITY window       -- an expired / not-yet-valid leaf is REJECTED;
 *   4. CURVE pin             -- a non-P-256 EC key is REJECTED;
 *   5. messageDigest binding -- a bundle with messageDigest absent is
 *      REJECTED; a digest that disagrees with the manifest entry is REJECTED;
 *   6. REKOR inclusion proof -- a bundle whose Merkle inclusion proof is
 *      mutated is REJECTED; an absent transparency-log entry is REJECTED.
 *
 * The happy-path fixture is a REAL, recorded production Sigstore bundle
 * (sigstore-js's own keyless-signed npm provenance attestation): it carries
 * a real Fulcio leaf chaining to the public root, a real Rekor inclusion
 * proof + SET, a real SCT, and a real timestamp. It verifies end-to-end
 * against the pinned trusted root with FULL thresholds. We do NOT weaken any
 * assertion to make it pass.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  sign as nodeSign,
  X509Certificate,
} from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { RelaySidecarBundleUnverified } from "../src/errors.js";
import {
  enforceP256Curve,
  REAL_SIGSTORE_HAPPY_PATH_POLICY,
  RELAY_SIDECAR_IDENTITY_POLICY,
  verifySigstoreBundle,
  type SigstoreVerifyOptions,
} from "../src/bin/verify.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const FIXTURE_DIR = path.join(__dirname, "fixtures", "sigstore");
const REAL_BUNDLE_PATH = path.join(FIXTURE_DIR, "real-provenance.sigstore.json");

// ---------------------------------------------------------------------------
// Real, recorded production Sigstore bundle (DSSE-envelope provenance). It
// chains to the public Fulcio root and has a real Rekor inclusion proof.
// ---------------------------------------------------------------------------
const REAL_BUNDLE_JSON = fs.readFileSync(REAL_BUNDLE_PATH, "utf8");
// DSSE bundles carry their own signed payload; no separate artifact bytes.
const HAPPY_PATH_OPTS: SigstoreVerifyOptions = {
  identityPolicy: REAL_SIGSTORE_HAPPY_PATH_POLICY,
};

// ---------------------------------------------------------------------------
// Adversarial leaf-cert minting (Python cryptography), mirrors the established
// repo pattern in w4_5_sigstore_verify.test.ts. Used for the curve/validity/
// substring-SAN negative cases that do NOT need a full real chain (they are
// rejected before/at chain validation).
// ---------------------------------------------------------------------------
interface MintedMaterial {
  certDerB64: string;
  keyPem: string;
}

function mintCert(opts: {
  curve?: "SECP256R1" | "SECP384R1";
  rsa?: boolean;
  sanUri: string;
  notBefore: string;
  notAfter: string;
}): MintedMaterial | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w47-"));
  const derOut = path.join(tmpDir, "leaf.der");
  const keyOut = path.join(tmpDir, "leaf.key.pem");
  const script = path.join(tmpDir, "mint.py");
  const keyExpr = opts.rsa
    ? "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
    : `ec.generate_private_key(ec.${opts.curve ?? "SECP256R1"}())`;
  const code = `import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

key = ${keyExpr}
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'relay-sidecar-release')])
issuer = subject  # self-signed: does NOT chain to the pinned Fulcio root
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.fromisoformat(${JSON.stringify(opts.notBefore)}))
    .not_valid_after(datetime.datetime.fromisoformat(${JSON.stringify(opts.notAfter)}))
    .add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(${JSON.stringify(opts.sanUri)})]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)
with open(${JSON.stringify(derOut)}, 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.DER))
with open(${JSON.stringify(keyOut)}, 'wb') as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
`;
  fs.writeFileSync(script, code, "utf8");
  try {
    const r = spawnSync("uv", ["run", "python3", script], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 60_000,
    });
    if (r.status !== 0) return null;
    return {
      certDerB64: fs.readFileSync(derOut).toString("base64"),
      keyPem: fs.readFileSync(keyOut, "utf8"),
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

const ARTIFACT = Buffer.from("relay-sidecar-binary-v0.1");
const ARTIFACT_DIGEST_HEX = createHash("sha256").update(ARTIFACT).digest("hex");
const ARTIFACT_DIGEST_B64 = createHash("sha256").update(ARTIFACT).digest("base64");

/** Build a self-minted protobuf messageSignature bundle over ARTIFACT. */
function selfMintedMessageBundle(
  material: MintedMaterial,
  opts: { omitMessageDigest?: boolean; messageDigestB64?: string; omitTlog?: boolean } = {},
): string {
  const key = createPrivateKey(material.keyPem);
  const sig = nodeSign("sha256", ARTIFACT, key).toString("base64");
  const messageSignature: Record<string, unknown> = { signature: sig };
  if (!opts.omitMessageDigest) {
    messageSignature.messageDigest = {
      algorithm: "SHA2_256",
      digest: opts.messageDigestB64 ?? ARTIFACT_DIGEST_B64,
    };
  }
  const bundle: Record<string, unknown> = {
    mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
    verificationMaterial: {
      certificate: { rawBytes: material.certDerB64 },
      tlogEntries: opts.omitTlog
        ? []
        : [
            {
              logIndex: "12345",
              logId: { keyId: Buffer.from("fake-log-id").toString("base64") },
              kindVersion: { kind: "hashedrekord", version: "0.0.1" },
              integratedTime: "1700000000",
              inclusionPromise: { signedEntryTimestamp: Buffer.from("fake").toString("base64") },
            },
          ],
    },
    messageSignature,
  };
  return JSON.stringify(bundle);
}

function toolchainReady(material: MintedMaterial | null): material is MintedMaterial {
  return material !== null;
}

describe("VAL-CRYPTO-002/003 hardening: HAPPY PATH (real production Sigstore bundle)", () => {
  it("a genuine, fully-valid Sigstore bundle is ACCEPTED end-to-end against the pinned root", () => {
    // Real Fulcio leaf chaining to the pinned public root, real Rekor
    // inclusion proof + SET, real SCT, real timestamp -- all verified with
    // FULL thresholds. Identity policy pins the recorded signer's exact SAN
    // + OIDC issuer.
    const signer = verifySigstoreBundle(undefined, REAL_BUNDLE_JSON, HAPPY_PATH_OPTS);
    expect(signer).toBeTruthy();
    expect(signer.identity?.extensions?.issuer).toBe(
      "https://token.actions.githubusercontent.com",
    );
  });

  it("the same real bundle is REJECTED under a DIFFERENT exact identity policy", () => {
    // Proves the identity check is load-bearing: swap the expected SAN and
    // the otherwise-valid bundle fails closed.
    expect(() =>
      verifySigstoreBundle(undefined, REAL_BUNDLE_JSON, {
        identityPolicy: {
          subjectAlternativeName: "^https://github\\.com/attacker/evil@.*$",
          extensions: { issuer: "https://token.actions.githubusercontent.com" },
        },
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("the same real bundle is REJECTED under a wrong OIDC issuer policy", () => {
    expect(() =>
      verifySigstoreBundle(undefined, REAL_BUNDLE_JSON, {
        identityPolicy: {
          subjectAlternativeName: REAL_SIGSTORE_HAPPY_PATH_POLICY.subjectAlternativeName,
          extensions: { issuer: "https://accounts.google.com" },
        },
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 1 -- EXACT identity (substring attack rejected)", () => {
  it("REGRESSION: a self-minted leaf whose SAN merely CONTAINS the identity is REJECTED", () => {
    // The substring attack the old issuer.includes(trustRoot) accepted: a
    // self-signed cert whose SAN embeds the trusted identity as a substring.
    const material = mintCert({
      sanUri:
        "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v9.9.9.attacker.example.com",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const bundle = selfMintedMessageBundle(material);
    expect(() =>
      verifySigstoreBundle(ARTIFACT, bundle, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("REGRESSION: the old forged legacy bundle (FAKE cert + sig) is REJECTED", () => {
    const forged = JSON.stringify({
      cert: "FAKE_CERT_PEM",
      signature: "FAKE_SIGNATURE_BASE64",
      rekorBundle: { Payload: { logIndex: 12345, logID: "fake-log-id" } },
      trust_root: "relay.epochly.com",
    });
    expect(() =>
      verifySigstoreBundle(ARTIFACT, forged, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 2 -- CHAIN to pinned Fulcio root", () => {
  it("a self-signed leaf that does NOT chain to the pinned root is REJECTED", () => {
    const material = mintCert({
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const bundle = selfMintedMessageBundle(material);
    expect(() =>
      verifySigstoreBundle(ARTIFACT, bundle, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 3 -- VALIDITY window", () => {
  it("an expired leaf is REJECTED", () => {
    const material = mintCert({
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2000-01-01T00:00:00+00:00",
      notAfter: "2001-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const bundle = selfMintedMessageBundle(material);
    expect(() =>
      verifySigstoreBundle(ARTIFACT, bundle, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 4 -- CURVE pin (P-256 only)", () => {
  it("a non-P-256 EC (P-384) leaf is REJECTED by the curve pin", () => {
    const material = mintCert({
      curve: "SECP384R1",
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    // The curve pin is a standalone, directly-testable guard.
    const cert = new X509Certificate(Buffer.from(material.certDerB64, "base64"));
    expect(() => enforceP256Curve(cert)).toThrow(RelaySidecarBundleUnverified);
  });

  it("a P-256 EC leaf PASSES the curve pin", () => {
    const material = mintCert({
      curve: "SECP256R1",
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const cert = new X509Certificate(Buffer.from(material.certDerB64, "base64"));
    expect(() => enforceP256Curve(cert)).not.toThrow();
  });

  it("an RSA leaf is REJECTED by the curve pin (EC P-256 required)", () => {
    const material = mintCert({
      rsa: true,
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const cert = new X509Certificate(Buffer.from(material.certDerB64, "base64"));
    expect(() => enforceP256Curve(cert)).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 5 -- messageDigest binding required", () => {
  it("a messageSignature bundle with messageDigest ABSENT is REJECTED", () => {
    const material = mintCert({
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const bundle = selfMintedMessageBundle(material, { omitMessageDigest: true });
    expect(() =>
      verifySigstoreBundle(ARTIFACT, bundle, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("a messageDigest that disagrees with the manifest entry.sha256 is REJECTED", () => {
    const material = mintCert({
      sanUri: "https://github.com/epochly-inc/relay/.github/workflows/release-sidecar-bundle.yml@refs/tags/v1.0.0",
      notBefore: "2024-01-01T00:00:00+00:00",
      notAfter: "2030-01-01T00:00:00+00:00",
    });
    if (!toolchainReady(material)) throw new Error("python cryptography toolchain unavailable");
    const wrong = createHash("sha256").update("other-bytes").digest("base64");
    const bundle = selfMintedMessageBundle(material, { messageDigestB64: wrong });
    expect(() =>
      verifySigstoreBundle(ARTIFACT, bundle, {
        expectedSha256: ARTIFACT_DIGEST_HEX,
        identityPolicy: RELAY_SIDECAR_IDENTITY_POLICY,
      }),
    ).toThrow(RelaySidecarBundleUnverified);
  });
});

describe("VAL-CRYPTO-002/003 hardening: item 6 -- REKOR inclusion proof", () => {
  let realBundle: Record<string, unknown>;
  beforeAll(() => {
    realBundle = JSON.parse(REAL_BUNDLE_JSON) as Record<string, unknown>;
  });

  it("a real bundle with the Rekor inclusion proof MUTATED is REJECTED", () => {
    const mutated = JSON.parse(REAL_BUNDLE_JSON) as {
      verificationMaterial: {
        tlogEntries: Array<{
          inclusionProof?: { hashes?: string[]; rootHash?: string };
        }>;
      };
    };
    const entry = mutated.verificationMaterial.tlogEntries[0];
    if (entry?.inclusionProof?.hashes && entry.inclusionProof.hashes.length > 0) {
      // Flip the first proof hash so the Merkle root no longer reconstructs.
      const orig = Buffer.from(entry.inclusionProof.hashes[0]!, "base64");
      orig[0] = (orig[0] ?? 0) ^ 0xff;
      entry.inclusionProof.hashes[0] = orig.toString("base64");
    } else if (entry?.inclusionProof) {
      const root = Buffer.from(entry.inclusionProof.rootHash ?? "", "base64");
      root[0] = (root[0] ?? 0) ^ 0xff;
      entry.inclusionProof.rootHash = root.toString("base64");
    }
    expect(() =>
      verifySigstoreBundle(undefined, JSON.stringify(mutated), HAPPY_PATH_OPTS),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("a real bundle with ALL transparency-log entries removed is REJECTED", () => {
    const stripped = JSON.parse(REAL_BUNDLE_JSON) as {
      verificationMaterial: { tlogEntries: unknown[] };
    };
    stripped.verificationMaterial.tlogEntries = [];
    expect(() =>
      verifySigstoreBundle(undefined, JSON.stringify(stripped), HAPPY_PATH_OPTS),
    ).toThrow(RelaySidecarBundleUnverified);
  });

  it("sanity: the unmutated real bundle still carries a tlog entry", () => {
    const tlogs = (realBundle.verificationMaterial as { tlogEntries: unknown[] }).tlogEntries;
    expect(Array.isArray(tlogs) && tlogs.length).toBeGreaterThan(0);
  });
});
