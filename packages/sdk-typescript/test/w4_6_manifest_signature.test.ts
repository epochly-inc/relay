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
import {
  launchSidecar,
  ManifestSignatureAbsent,
  type VerifySigstoreBundleFn,
} from "../src/bin/wrapper.js";
import {
  REAL_SIGSTORE_HAPPY_PATH_POLICY,
  verifySigstoreBundle,
} from "../src/bin/verify.js";
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
    /** When set, no manifest.json.sigstore is served (clean 404 / legacy). */
    omitManifestSignature?: boolean;
    /** When set, the manifest.json.sigstore is over DIFFERENT bytes (forgery). */
    tamperManifestSignature?: boolean;
    /** Override the manifest bytes the attacker serves vs. signs. */
    forgedManifestText?: string;
    /**
     * When set, ``fetchImpl`` REJECTS (throws) on the ``.sigstore`` request --
     * a transport error / connection reset (e.g. an active MITM that drops the
     * signature object). VAL-CRYPTO-003 downgrade hardening.
     */
    manifestSigstoreTransportError?: boolean;
    /**
     * When set, ``fetchImpl`` returns this HTTP status (e.g. 500/403) on the
     * ``.sigstore`` request -- a non-404 status that must NOT be read as
     * "absent". VAL-CRYPTO-003 downgrade hardening.
     */
    manifestSigstoreStatus?: number;
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
      if (opts.manifestSigstoreTransportError) {
        // Simulate a connection reset / dropped request on the signature
        // object (e.g. an active MITM stripping manifest-signature
        // enforcement). fetch() rejects rather than returning a Response.
        throw new TypeError("fetch failed: ECONNRESET");
      }
      if (opts.manifestSigstoreStatus !== undefined) {
        return new Response("error", { status: opts.manifestSigstoreStatus });
      }
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

// ---------------------------------------------------------------------------
// Sigstore-verification seam for the ORCHESTRATION tests.
//
// Post the W4.7 trust-chain hardening, verifySigstoreBundle delegates to
// @sigstore/verify against the pinned public-good trusted root: it requires
// a REAL Fulcio chain + Rekor inclusion proof + SCT that cannot be minted
// offline. These tests exercise the manifest-signature ORCHESTRATION (fetch
// <manifestUrl>.sigstore, the present/absent transition gate, fail-closed on
// no launch). The seam runs the REAL verifier against a REAL recorded
// production bundle on each PRESENT-signature call, so the wire-up to a
// fail-closed verifier is genuinely exercised; the crypto correctness itself
// is proven in w4_7_sigstore_trust_chain.test.ts.
// ---------------------------------------------------------------------------
const REAL_BUNDLE_JSON = fs.readFileSync(
  path.join(__dirname, "fixtures", "sigstore", "real-provenance.sigstore.json"),
  "utf8",
);
const realVerifySeam: VerifySigstoreBundleFn = () =>
  verifySigstoreBundle(undefined, REAL_BUNDLE_JSON, {
    identityPolicy: REAL_SIGSTORE_HAPPY_PATH_POLICY,
  });

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
        verifyBundleImpl: realVerifySeam,
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
        verifyBundleImpl: realVerifySeam,
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

// ---------------------------------------------------------------------------
// VAL-CRYPTO-003 (G1-F5): manifest-signature DOWNGRADE hardening.
//
// The default manifest-signature fetcher (defaultManifestSigstoreFetcher in
// wrapper.ts) must distinguish a GENUINE 404 (signature legitimately not
// published for a legacy release) from a TRANSPORT error / connection reset
// or a non-404 HTTP status. Under the transition default
// (RELAY_REQUIRE_SIGNED_MANIFEST unset), an ABSENT signature is tolerated --
// so if a transport error or 5xx were misclassified as "absent", an active
// MITM that serves a forged manifest but DROPS/RESETS the .sigstore request
// would strip manifest-signature enforcement entirely (a trust downgrade).
//
// These tests deliberately OMIT fetchManifestSigstoreImpl so the REAL
// defaultManifestSigstoreFetcher runs against the mock transport (fetchImpl);
// that is the code path that carried the downgrade bug.
// ---------------------------------------------------------------------------
describe("VAL-CRYPTO-003 (G1-F5): transport/non-404 errors on the manifest signature FAIL CLOSED", () => {
  it("a TRANSPORT error on the .sigstore request FAILS CLOSED even with the require flag UNSET", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      // RELAY_REQUIRE_SIGNED_MANIFEST is unset (transition default). A
      // connection reset on the .sigstore request must NOT be treated as a
      // tolerated "absent" signature; it must fail closed and not launch.
      const f = buildManifestFixture({ manifestSigstoreTransportError: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          verifyBundleImpl: realVerifySeam,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      // Fail-closed: nothing cached.
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("a 500 status on the .sigstore request FAILS CLOSED even with the require flag UNSET", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      const f = buildManifestFixture({ manifestSigstoreStatus: 500 });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          verifyBundleImpl: realVerifySeam,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("a 403 status on the .sigstore request FAILS CLOSED even with the require flag UNSET", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      const f = buildManifestFixture({ manifestSigstoreStatus: 403 });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          verifyBundleImpl: realVerifySeam,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("a CLEAN 404 on the .sigstore request is tolerated under the transition default (legacy still launches)", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      // RELAY_REQUIRE_SIGNED_MANIFEST unset: a genuine 404 means the
      // signature was legitimately never published for this legacy release.
      // npx must keep working via the per-binary digest + Sigstore checks.
      // The DEFAULT fetcher must map this clean 404 (and only a clean 404)
      // to the tolerated-absent path.
      const f = buildManifestFixture({ omitManifestSignature: true });
      const decision = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        verifyBundleImpl: realVerifySeam,
      });
      expect(decision.action).toBe("launched_fresh");
      expect(decision.digest).toBe(f.bundleDigest);
    } finally {
      tmp.cleanup();
    }
  });

  it("a CLEAN 404 on the .sigstore request is REJECTED under RELAY_REQUIRE_SIGNED_MANIFEST=1", async () => {
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
          verifyBundleImpl: realVerifySeam,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });

  it("a TRANSPORT error on the .sigstore request FAILS CLOSED under RELAY_REQUIRE_SIGNED_MANIFEST=1 too", async () => {
    requireToolchain();
    const tmp = setupTmpHome();
    try {
      process.env[REQUIRE_SIGNED_MANIFEST_ENV] = "1";
      const f = buildManifestFixture({ manifestSigstoreTransportError: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
          verifyBundleImpl: realVerifySeam,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });
});
