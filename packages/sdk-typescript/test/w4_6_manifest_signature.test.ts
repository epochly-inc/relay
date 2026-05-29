/**
 * W4.6 release-manifest signature verification (VAL-CRYPTO-003).
 *
 * Regression coverage for the bug-hunt finding (base commit c911607):
 * ``launchFresh()`` fetched the release manifest over HTTPS and then
 * trusted every field it carried -- the per-bundle ``sha256`` digests and
 * the ``trust_root`` claim -- WITHOUT ever verifying a Sigstore signature
 * over the manifest itself. types.ts:5-8 promised a separate
 * ``manifest.json.sigstore`` cosign-bundle "so the wrapper can verify the
 * manifest itself before trusting any entry digest", but no code ever
 * fetched or verified it. An attacker who serves/MITMs the pinned manifest
 * URL could ship a malicious bundle: set ``entry.sha256 =
 * SHA-256(malicious_bundle)`` and ``trust_root = relay.epochly.com`` and
 * the wrapper would download + run the attacker's binary (the per-binary
 * Sigstore check would pass because the attacker's binary is signed-by /
 * digest-matches the attacker's own manifest entry, OR the attacker pins
 * a stale-but-valid signature). The manifest is the trust root for the
 * whole chain; signing only the leaf binaries is insufficient.
 *
 * After the fix ``launchFresh`` fetches ``<manifestUrl>.sigstore`` and
 * cryptographically verifies a Sigstore signature over the EXACT manifest
 * bytes (reusing the real ``verifySigstoreBundle`` from verify.ts /
 * VAL-CRYPTO-002), rooted in the configured trust root, BEFORE trusting any
 * manifest field. Enforcement is gated for the signed-release transition:
 *   - a signed manifest (a ``.sigstore`` is fetchable) is ALWAYS enforced;
 *   - a legacy manifest with no ``.sigstore`` is allowed ONLY while
 *     ``RELAY_REQUIRE_SIGNED_MANIFEST`` is not set to "1"; once that flag
 *     is on (the post-signed-release end state) an unsigned manifest is
 *     rejected fail-closed.
 *
 * The happy-path fixture mints a real Fulcio-style leaf certificate + key
 * via Python's ``cryptography`` (the established repo pattern -- no new npm
 * dependency) and signs the real manifest bytes with ``node:crypto``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { RelaySidecarBundleUnverified } from "../src/errors.js";
import { launchSidecar, ManifestSignatureAbsent } from "../src/bin/wrapper.js";
import {
  DEFAULT_TRUST_ROOT,
  SUPPORTED_OS_ARCH,
  type ReleaseManifest,
} from "../src/bin/types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const REQUIRE_SIGNED_MANIFEST_ENV = "RELAY_REQUIRE_SIGNED_MANIFEST";

// ---------------------------------------------------------------------------
// Real signing material (mirrors w4_5_sigstore_verify.test.ts). The signature
// is over the EXACT manifest JSON bytes the wrapper receives.
// ---------------------------------------------------------------------------
interface RealMaterial {
  certDerB64: string;
  keyPem: string;
}

function mintRealLeafCert(trustRootHost: string): RealMaterial | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w46-cert-"));
  const script = path.join(tmpDir, "mint.py");
  const derOut = path.join(tmpDir, "leaf.der");
  const keyOut = path.join(tmpDir, "leaf.key.pem");
  const code = `import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
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
  fs.writeFileSync(script, code, "utf-8");
  try {
    const r = spawnSync("uv", ["run", "python3", script], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 60_000,
    });
    if (r.status !== 0) return null;
    return {
      certDerB64: fs.readFileSync(derOut).toString("base64"),
      keyPem: fs.readFileSync(keyOut, "utf-8"),
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

let SIGNING_MATERIAL: RealMaterial | null = null;
beforeAll(() => {
  SIGNING_MATERIAL = mintRealLeafCert(DEFAULT_TRUST_ROOT);
});

/** Sign the EXACT manifest JSON bytes into a cosign protobuf-bundle. */
function signManifestBytes(material: RealMaterial, manifestBytes: Buffer): string {
  const privateKey = crypto.createPrivateKey(material.keyPem);
  const sigDer = crypto.sign("sha256", manifestBytes, privateKey);
  const digestB64 = crypto.createHash("sha256").update(manifestBytes).digest("base64");
  return JSON.stringify({
    mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
    verificationMaterial: {
      certificate: { rawBytes: material.certDerB64 },
      tlogEntries: [{ logIndex: "12345", logID: { keyId: "fake-log-id" } }],
    },
    messageSignature: {
      signature: sigDer.toString("base64"),
      messageDigest: { algorithm: "SHA2_256", digest: digestB64 },
    },
    trust_root: DEFAULT_TRUST_ROOT,
  });
}

interface ManifestFixture {
  bundleBytes: Buffer;
  bundleDigest: string;
  manifestText: string;
  manifestUrl: string;
  manifestSigstoreUrl: string;
  fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;
  fetchBundleImpl: (url: string) => Promise<Buffer>;
  fetchSigstoreImpl: (url: string) => Promise<string>;
  fetchManifestSigstoreImpl: (url: string) => Promise<string>;
  observedRequests: string[];
}

/**
 * Build a fixture where the manifest is served as RAW bytes (so the
 * signature is over the exact bytes the wrapper verifies). The per-binary
 * Sigstore bundle is real-signed (so the binary check is NOT what rejects
 * a manifest forgery -- the manifest-signature check is).
 */
function buildManifestFixture(
  opts: {
    /** When set, no manifest.json.sigstore is served (legacy / 404). */
    omitManifestSignature?: boolean;
    /** When set, the manifest.json.sigstore is over DIFFERENT bytes (forgery). */
    tamperManifestSignature?: boolean;
    /** Override the manifest bytes the attacker serves vs. signs. */
    forgedManifestText?: string;
  } = {},
): ManifestFixture {
  const material = SIGNING_MATERIAL;
  const bundleBytes = Buffer.from("relay-sidecar-binary-v0.1");
  const bundleDigest = crypto.createHash("sha256").update(bundleBytes).digest("hex");
  const manifestUrl =
    "https://relay.epochly.com/.well-known/relay-sidecar-bundle/manifest.json";
  const manifestSigstoreUrl = manifestUrl + ".sigstore";
  const manifest: ReleaseManifest = {
    schema_version: "relay.sidecar_bundle_manifest.v1",
    emitted_at: new Date("2026-05-29T00:00:00Z").toISOString(),
    sidecar_version: "0.1.21",
    trust_root: DEFAULT_TRUST_ROOT,
    bundles: SUPPORTED_OS_ARCH.map((cell) => ({
      os: cell.os,
      arch: cell.arch,
      url: `https://relay.epochly.com/relay-sidecar-bundle/${cell.os}-${cell.arch}.tar.gz`,
      sha256: bundleDigest,
      size_bytes: bundleBytes.length,
      sigstore_url: `https://relay.epochly.com/relay-sidecar-bundle/${cell.os}-${cell.arch}.sigstore.json`,
    })),
  };
  // The bytes the wrapper actually receives over the wire.
  const servedManifestText = opts.forgedManifestText ?? JSON.stringify(manifest);
  // The bytes the legitimate signer signed. When tampering, sign DIFFERENT
  // (legitimate) bytes than what is served, so the signature does not bind
  // the served bytes.
  const signedManifestBytes = opts.tamperManifestSignature
    ? Buffer.from(JSON.stringify({ ...manifest, sidecar_version: "0.1.0-legit" }))
    : Buffer.from(servedManifestText);

  // Per-binary sigstore bundle (real-signed over the bundle bytes).
  let binarySigstore: string;
  if (material !== null) {
    const privateKey = crypto.createPrivateKey(material.keyPem);
    const sigDer = crypto.sign("sha256", bundleBytes, privateKey);
    const digestB64 = crypto.createHash("sha256").update(bundleBytes).digest("base64");
    binarySigstore = JSON.stringify({
      mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
      verificationMaterial: {
        certificate: { rawBytes: material.certDerB64 },
        tlogEntries: [{ logIndex: "1", logID: { keyId: "x" } }],
      },
      messageSignature: {
        signature: sigDer.toString("base64"),
        messageDigest: { algorithm: "SHA2_256", digest: digestB64 },
      },
      trust_root: DEFAULT_TRUST_ROOT,
    });
  } else {
    binarySigstore = JSON.stringify({});
  }

  const manifestSigstore =
    material !== null ? signManifestBytes(material, signedManifestBytes) : JSON.stringify({});

  const observedRequests: string[] = [];
  const fetchImpl = async (url: string, _init?: RequestInit): Promise<Response> => {
    observedRequests.push(url);
    if (url === manifestUrl) {
      return new Response(servedManifestText, { status: 200 });
    }
    if (url === manifestSigstoreUrl) {
      if (opts.omitManifestSignature) {
        return new Response("not found", { status: 404 });
      }
      return new Response(manifestSigstore, { status: 200 });
    }
    throw new Error(`unexpected fetch URL in test: ${url}`);
  };
  const fetchBundleImpl = async (url: string): Promise<Buffer> => {
    observedRequests.push(url);
    return bundleBytes;
  };
  const fetchSigstoreImpl = async (url: string): Promise<string> => {
    observedRequests.push(url);
    return binarySigstore;
  };
  const fetchManifestSigstoreImpl = async (url: string): Promise<string> => {
    observedRequests.push(url);
    if (opts.omitManifestSignature) {
      // Signal ABSENCE the same way the default fetcher does on a 404, so
      // the transition policy applies (rather than a hard failure).
      throw new ManifestSignatureAbsent("manifest signature not found (404)");
    }
    return manifestSigstore;
  };
  return {
    bundleBytes,
    bundleDigest,
    manifestText: servedManifestText,
    manifestUrl,
    manifestSigstoreUrl,
    fetchImpl,
    fetchBundleImpl,
    fetchSigstoreImpl,
    fetchManifestSigstoreImpl,
    observedRequests,
  };
}

function setupTmpHome(): { home: string; cleanup: () => void } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w46-"));
  return {
    home,
    cleanup: () => {
      try {
        fs.rmSync(home, { recursive: true, force: true });
      } catch {
        // best effort
      }
    },
  };
}

let envBackup: Record<string, string | undefined>;
const ENV_KEYS = [
  "RELAY_HOME",
  "RELAY_BUNDLE_VERIFY_TTL",
  "RELAY_ALLOW_CUSTOM_TRUST_ROOT",
  REQUIRE_SIGNED_MANIFEST_ENV,
];
beforeEach(() => {
  envBackup = {};
  for (const k of ENV_KEYS) envBackup[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (envBackup[k] !== undefined) process.env[k] = envBackup[k];
    else delete process.env[k];
  }
});

function requireToolchain(): void {
  if (SIGNING_MATERIAL === null) {
    throw new Error(
      "Python cryptography toolchain unavailable; cannot mint a real " +
        "Fulcio-style cert. Install uv + the workspace venv to run this test.",
    );
  }
}

describe("VAL-CRYPTO-003: release manifest signature is cryptographically verified", () => {
  it("REGRESSION: a forged manifest with a non-binding signature is REJECTED (no launch)", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      // The attacker serves a manifest whose entry.sha256 = SHA-256(their
      // bundle) and trust_root = relay.epochly.com, accompanied by a
      // structurally-complete manifest.json.sigstore that does NOT sign the
      // served bytes (it signs different legitimate bytes). Under the old
      // code the wrapper trusted the manifest unconditionally.
      const f = buildManifestFixture({ tamperManifestSignature: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          fetchManifestSigstoreImpl: f.fetchManifestSigstoreImpl,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      // Fail-closed: nothing cached.
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("HAPPY PATH: a properly signed manifest verifies and launches fresh", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      const f = buildManifestFixture();
      const decision = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        fetchManifestSigstoreImpl: f.fetchManifestSigstoreImpl,
      });
      expect(decision.action).toBe("launched_fresh");
      expect(decision.digest).toBe(f.bundleDigest);
      expect(decision.trust_root).toBe(DEFAULT_TRUST_ROOT);
      // The manifest.json.sigstore MUST have been fetched (manifest-sig
      // verification happened) before the binary was trusted.
      expect(f.observedRequests).toContain(f.manifestSigstoreUrl);
    } finally {
      tmp.cleanup();
    }
  });

  it("GATE: legacy unsigned manifest is ALLOWED by default (transition policy)", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      // No manifest.json.sigstore is served (current legacy releases).
      // With RELAY_REQUIRE_SIGNED_MANIFEST unset, the wrapper must NOT
      // break npx -- it proceeds with the legacy unsigned manifest.
      const f = buildManifestFixture({ omitManifestSignature: true });
      const decision = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        fetchManifestSigstoreImpl: f.fetchManifestSigstoreImpl,
      });
      expect(decision.action).toBe("launched_fresh");
      expect(decision.digest).toBe(f.bundleDigest);
    } finally {
      tmp.cleanup();
    }
  });

  it("GATE: legacy unsigned manifest is REJECTED under RELAY_REQUIRE_SIGNED_MANIFEST=1", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      process.env[REQUIRE_SIGNED_MANIFEST_ENV] = "1";
      const f = buildManifestFixture({ omitManifestSignature: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          fetchManifestSigstoreImpl: f.fetchManifestSigstoreImpl,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("a present manifest signature is ALWAYS enforced even without the require flag", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      // Signature is present but does NOT bind the served bytes. Even with
      // the require-flag OFF, a present-but-invalid signature fails closed
      // (only a fully-ABSENT signature falls back to the transition policy).
      const f = buildManifestFixture({ tamperManifestSignature: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          fetchManifestSigstoreImpl: f.fetchManifestSigstoreImpl,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
    } finally {
      tmp.cleanup();
    }
  });
});
