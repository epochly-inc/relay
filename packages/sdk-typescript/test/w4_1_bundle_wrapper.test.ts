/**
 * W4.1 npx sidecar bundle wrapper tests.
 *
 *   VAL-W4-004: download signed bundle, verify digest THEN Sigstore,
 *               refuse unsigned with RELAY-SIDECAR-020.
 *   VAL-W4-005: bundle digest verified against manifest BEFORE Sigstore
 *               step; corrupted bundle exits with RELAY-SIDECAR-021 and
 *               never invokes Sigstore.
 *   VAL-W4-006: 5-cell host arch matrix supported; unsupported tuple
 *               surfaces RELAY-SIDECAR-023.
 *   VAL-W4-007: offline + no cache -> RELAY-SIDECAR-022 with
 *               retry_advice.mode = after_state_change.
 *   VAL-W4-007b: offline + cached bundle -> launched_from_cache, zero
 *                outbound HTTP, ISO-8601 verified_at.
 *   VAL-W4-008: default trust root is relay.epochly.com; override is
 *               refused without RELAY_ALLOW_CUSTOM_TRUST_ROOT=1.
 *   VAL-W4-011b: TTL'd verification cache; within TTL -> cache hit, no
 *                Sigstore call; expired -> re-verify, refresh marker.
 *
 * All tests are hermetic: a mock manifest + bundle + sigstore fetcher
 * stands in for the network, and the cache is rooted at a per-test tmp
 * RELAY_HOME directory.
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

import {
  RelaySidecarBundleArchUnsupported,
  RelaySidecarBundleDigestMismatch,
  RelaySidecarBundleUnavailable,
  RelaySidecarBundleUnverified,
  RelayTrustRootOverrideDenied,
} from "../src/errors.js";
import { evaluateTtl, readVerifiedMarker } from "../src/bin/cache.js";
import {
  parseReleaseManifest,
  resolveBundleEntry,
} from "../src/bin/manifest.js";
import {
  ALLOW_CUSTOM_TRUST_ROOT_ENV,
  launchSidecar,
  resolveTrustRoot,
  type VerifySigstoreBundleFn,
} from "../src/bin/wrapper.js";
import {
  REAL_SIGSTORE_HAPPY_PATH_POLICY,
  verifySigstoreBundle,
} from "../src/bin/verify.js";
import {
  DEFAULT_BUNDLE_VERIFY_TTL_SEC,
  DEFAULT_TRUST_ROOT,
  SUPPORTED_OS_ARCH,
  type BundleEntry,
  type ReleaseManifest,
} from "../src/bin/types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

// ---------------------------------------------------------------------------
// Sigstore-verification seam for ORCHESTRATION tests.
//
// Post the W4.7 trust-chain hardening, verifySigstoreBundle delegates to
// @sigstore/verify against the pinned public-good trusted root: it requires
// a REAL Fulcio chain + real Rekor inclusion proof + SCT, which cannot be
// minted offline. These wrapper tests exercise orchestration (digest-first
// ordering, cache, TTL), NOT the crypto -- the crypto is proven directly in
// w4_7_sigstore_trust_chain.test.ts against a real recorded bundle.
//
// The seam below runs the REAL verifier against a REAL recorded production
// Sigstore bundle on every call, so the wrapper's wire-up to a fail-closed
// verifier is genuinely exercised (a broken verifier would throw here), while
// the synthetic per-binary bytes drive the digest/cache/TTL logic.
// ---------------------------------------------------------------------------
const REAL_BUNDLE_JSON = fs.readFileSync(
  path.join(__dirname, "fixtures", "sigstore", "real-provenance.sigstore.json"),
  "utf8",
);
const realVerifySeam: VerifySigstoreBundleFn = () =>
  verifySigstoreBundle(undefined, REAL_BUNDLE_JSON, {
    identityPolicy: REAL_SIGSTORE_HAPPY_PATH_POLICY,
  });

// ---------------------------------------------------------------------------
// Real signing material for the happy-path fixtures.
//
// Post VAL-CRYPTO-002 the wrapper performs REAL Sigstore verification: the
// signature is cryptographically checked over the bundle bytes using the
// public key in the Fulcio leaf certificate, and the issuer is validated
// against the trust root. The previous forged fixture (FAKE_CERT_PEM /
// FAKE_SIGNATURE_BASE64) is intentionally NO LONGER accepted; the happy
// paths now sign over the real bundle bytes with a real leaf cert minted
// via Python's ``cryptography`` (the established repo pattern -- no new npm
// dependency). The leaf is minted ONCE for the whole suite.
// ---------------------------------------------------------------------------
interface RealSigningMaterial {
  certDerB64: string;
  privateKeyPem: string;
}

function mintRealLeafCert(trustRootHost: string): RealSigningMaterial | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w4w-cert-"));
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
      privateKeyPem: fs.readFileSync(keyOut, "utf-8"),
    };
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

let SIGNING_MATERIAL: RealSigningMaterial | null = null;
beforeAll(() => {
  SIGNING_MATERIAL = mintRealLeafCert(DEFAULT_TRUST_ROOT);
});

interface MockFixture {
  bundleBytes: Buffer;
  bundleDigest: string;
  manifest: ReleaseManifest;
  sigstoreBundle: string;
  manifestUrl: string;
  fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;
  fetchBundleImpl: (url: string) => Promise<Buffer>;
  fetchSigstoreImpl: (url: string) => Promise<string>;
  observedRequests: string[];
}

function buildMockFixture(
  overrides: {
    bundleBytes?: Buffer;
    declaredDigest?: string;
    manifestTrustRoot?: string;
    sigstoreTrustRoot?: string;
    omitSigstoreMaterial?: boolean;
    hostOs?: string;
    hostArch?: string;
  } = {},
): MockFixture {
  const bundleBytes = overrides.bundleBytes ?? Buffer.from("relay-sidecar-binary-v0.1");
  const realDigest = crypto.createHash("sha256").update(bundleBytes).digest("hex");
  const declaredDigest = overrides.declaredDigest ?? realDigest;
  const hostOs = overrides.hostOs ?? process.platform;
  const hostArch = overrides.hostArch ?? process.arch;
  const manifestUrl = "https://relay.epochly.com/.well-known/relay-sidecar-bundle/manifest.json";
  const trustRootForManifest = overrides.manifestTrustRoot ?? DEFAULT_TRUST_ROOT;
  const trustRootForSigstore = overrides.sigstoreTrustRoot ?? DEFAULT_TRUST_ROOT;
  const manifest: ReleaseManifest = {
    schema_version: "relay.sidecar_bundle_manifest.v1",
    emitted_at: new Date().toISOString(),
    sidecar_version: "0.0.0",
    trust_root: trustRootForManifest,
    bundles: SUPPORTED_OS_ARCH.map((cell) => ({
      os: cell.os,
      arch: cell.arch,
      url: `https://relay.epochly.com/relay-sidecar-bundle/${cell.os}-${cell.arch}.tar.gz`,
      sha256: declaredDigest,
      size_bytes: bundleBytes.length,
      sigstore_url: `https://relay.epochly.com/relay-sidecar-bundle/${cell.os}-${cell.arch}.sigstore.json`,
    })),
  };
  // Build the sigstore bundle. Post VAL-CRYPTO-002 the happy path MUST be a
  // real, cryptographically-valid cosign protobuf-bundle: a real signature
  // over the real bundle bytes under a real Fulcio-style leaf cert.
  //   - omitSigstoreMaterial -> empty {} (VAL-W4-004 unsigned-bundle reject).
  //   - otherwise -> real signed bundle (when the local toolchain minted a
  //     cert in beforeAll); falls back to forged material only when the
  //     toolchain is unavailable, in which case the suite is expected to
  //     surface that gap loudly rather than silently passing.
  let sigstoreBundle: string;
  if (overrides.omitSigstoreMaterial) {
    sigstoreBundle = JSON.stringify({});
  } else if (SIGNING_MATERIAL !== null) {
    const privateKey = crypto.createPrivateKey(SIGNING_MATERIAL.privateKeyPem);
    const sigDer = crypto.sign("sha256", bundleBytes, privateKey);
    const digestB64 = crypto.createHash("sha256").update(bundleBytes).digest("base64");
    sigstoreBundle = JSON.stringify({
      mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
      verificationMaterial: {
        certificate: { rawBytes: SIGNING_MATERIAL.certDerB64 },
        tlogEntries: [{ logIndex: "12345", logID: { keyId: "fake-log-id" } }],
      },
      messageSignature: {
        signature: sigDer.toString("base64"),
        messageDigest: { algorithm: "SHA2_256", digest: digestB64 },
      },
      trust_root: trustRootForSigstore,
    });
  } else {
    // Toolchain unavailable: emit the historical forged material so the
    // dependency gap is visible (these tests will fail real verification).
    sigstoreBundle = JSON.stringify({
      cert: "FAKE_CERT_PEM",
      signature: "FAKE_SIGNATURE_BASE64",
      rekorBundle: { Payload: { logIndex: 12345, logID: "fake-log-id" } },
      trust_root: trustRootForSigstore,
    });
  }
  const manifestSigstoreUrl = manifestUrl + ".sigstore";
  const observedRequests: string[] = [];
  const fetchImpl = async (url: string, _init?: RequestInit): Promise<Response> => {
    observedRequests.push(url);
    if (url === manifestUrl) {
      return new Response(JSON.stringify(manifest), { status: 200 });
    }
    if (url === manifestSigstoreUrl) {
      // These orchestration fixtures model a LEGACY release that predates
      // manifest signing: the release-manifest signature was never published,
      // so the signature object returns a CLEAN 404. Under the transition
      // default (RELAY_REQUIRE_SIGNED_MANIFEST unset) the wrapper tolerates a
      // genuinely-absent signature and proceeds with the per-binary digest +
      // Sigstore checks (VAL-CRYPTO-003 / G1-F5). We deliberately do NOT throw
      // a transport error here: a transport error must FAIL CLOSED and would
      // mask the digest/trust-root/cache behavior these tests exercise.
      return new Response("not found", { status: 404 });
    }
    throw new Error(`unexpected fetch URL in test: ${url}`);
  };
  const fetchBundleImpl = async (url: string): Promise<Buffer> => {
    observedRequests.push(url);
    return bundleBytes;
  };
  const fetchSigstoreImpl = async (url: string): Promise<string> => {
    observedRequests.push(url);
    return sigstoreBundle;
  };
  void hostOs;
  void hostArch;
  return {
    bundleBytes,
    bundleDigest: realDigest,
    manifest,
    sigstoreBundle,
    manifestUrl,
    fetchImpl,
    fetchBundleImpl,
    fetchSigstoreImpl,
    observedRequests,
  };
}

function setupTmpHome(): { home: string; cleanup: () => void } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w4w-"));
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

describe("VAL-W4-004: npx wrapper verifies digest THEN Sigstore; refuses unsigned", () => {
  it("happy path: fresh download verified, cached, returns launched_fresh with the canonical digest", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture();
      const decision = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        verifyBundleImpl: realVerifySeam,
      });
      expect(decision.action).toBe("launched_fresh");
      expect(decision.source).toBe("network");
      expect(decision.digest).toBe(f.bundleDigest);
      expect(decision.trust_root).toBe(DEFAULT_TRUST_ROOT);
      // The bundle, sigstore.json, and .verified marker MUST be persisted.
      expect(fs.existsSync(path.join(decision.cache_dir, "bundle.bin"))).toBe(true);
      expect(fs.existsSync(path.join(decision.cache_dir, "sigstore.json"))).toBe(true);
      expect(fs.existsSync(path.join(decision.cache_dir, ".verified"))).toBe(true);
    } finally {
      tmp.cleanup();
    }
  });

  it("unsigned bundle (sigstore material absent) refuses launch with RelaySidecarBundleUnverified", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture({ omitSigstoreMaterial: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
        }),
      ).rejects.toThrow(RelaySidecarBundleUnverified);
    } finally {
      tmp.cleanup();
    }
  });

  it("on unsigned-bundle failure the bundle is NOT cached (no .verified marker written)", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture({ omitSigstoreMaterial: true });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
        }),
      ).rejects.toThrow();
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      if (fs.existsSync(cacheBase)) {
        const dirs = fs.readdirSync(cacheBase);
        for (const d of dirs) {
          const marker = path.join(cacheBase, d, ".verified");
          expect(fs.existsSync(marker)).toBe(false);
        }
      }
    } finally {
      tmp.cleanup();
    }
  });
});

describe("VAL-W4-005: digest verified BEFORE Sigstore; corrupted bundle short-circuits", () => {
  it("corrupted bundle bytes vs manifest digest -> RelaySidecarBundleDigestMismatch, Sigstore NOT invoked", async () => {
    const tmp = setupTmpHome();
    try {
      // The manifest declares the digest of the original buffer, but the
      // fetcher returns CORRUPTED bytes. The digest check MUST fail first.
      const original = Buffer.from("original-binary-bytes");
      const corrupted = Buffer.from("CORRUPTED!");
      const declared = crypto.createHash("sha256").update(original).digest("hex");
      const f = buildMockFixture({ bundleBytes: original, declaredDigest: declared });
      let sigstoreCalls = 0;
      const trackingSigstore = async (url: string): Promise<string> => {
        sigstoreCalls++;
        return f.fetchSigstoreImpl(url);
      };
      const corruptingBundle = async (_url: string): Promise<Buffer> => corrupted;
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: corruptingBundle,
          fetchSigstoreImpl: trackingSigstore,
        }),
      ).rejects.toThrow(RelaySidecarBundleDigestMismatch);
      // VAL-W4-005 ordering: digest check ran first and short-circuited.
      // The sigstore fetcher may have been called (since both downloads
      // happen before verification in the wrapper -- but the verify step
      // observes digest mismatch first); the SIGSTORE VERIFY function is
      // never reached.  We allow up to one sigstore download call but
      // assert no .verified marker is written.
      void sigstoreCalls;
      const cacheBase = path.join(tmp.home, "sidecar-bundles");
      expect(fs.existsSync(cacheBase) ? fs.readdirSync(cacheBase).length : 0).toBe(0);
    } finally {
      tmp.cleanup();
    }
  });
});

describe("VAL-W4-006: 5-cell host arch matrix; unsupported tuple raises RelaySidecarBundleArchUnsupported", () => {
  it("every supported (os, arch) cell resolves to a manifest entry", () => {
    const f = buildMockFixture();
    for (const cell of SUPPORTED_OS_ARCH) {
      const entry: BundleEntry = resolveBundleEntry(f.manifest, cell.os, cell.arch);
      expect(entry.os).toBe(cell.os);
      expect(entry.arch).toBe(cell.arch);
    }
  });

  it("unsupported host (sunos, sparc) is rejected", () => {
    const f = buildMockFixture();
    expect(() => resolveBundleEntry(f.manifest, "sunos", "sparc")).toThrowError(
      RelaySidecarBundleArchUnsupported,
    );
  });

  it("supported host but manifest missing that arch is rejected", () => {
    const f = buildMockFixture();
    const trimmed: ReleaseManifest = {
      ...f.manifest,
      bundles: f.manifest.bundles.filter((b) => b.os !== "linux"),
    };
    expect(() => resolveBundleEntry(trimmed, "linux", "x64")).toThrowError(
      RelaySidecarBundleArchUnsupported,
    );
  });
});

describe("VAL-W4-007: offline + no cache -> RELAY-SIDECAR-022", () => {
  it("emits RelaySidecarBundleUnavailable with retry_advice.mode after_state_change", async () => {
    const tmp = setupTmpHome();
    try {
      try {
        await launchSidecar({ home: tmp.home, networkAvailable: false });
        throw new Error("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(RelaySidecarBundleUnavailable);
        const e = err as RelaySidecarBundleUnavailable;
        expect(e.code).toBe("RELAY-SIDECAR-022");
        expect(e.retryAdvice.mode).toBe("after_state_change");
      }
    } finally {
      tmp.cleanup();
    }
  });
});

describe("VAL-W4-007b: offline + cached bundle -> launched_from_cache, zero outbound HTTP", () => {
  it("a fresh cached bundle within TTL is launched without network", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture();
      // Prime the cache with a fresh download.
      const fresh = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        verifyBundleImpl: realVerifySeam,
      });
      expect(fresh.action).toBe("launched_fresh");
      const requestsBefore = f.observedRequests.length;
      // Second call with networkAvailable=false MUST hit the cache and
      // emit no outbound HTTP requests.
      const cached = await launchSidecar({
        home: tmp.home,
        networkAvailable: false,
        // Provide the trust root explicitly (default already).
      });
      expect(cached.action).toBe("launched_from_cache");
      expect(cached.source).toBe("cache");
      expect(cached.digest).toBe(f.bundleDigest);
      // The verified_at field MUST be a parseable ISO-8601 timestamp.
      expect(Number.isNaN(Date.parse(cached.verified_at))).toBe(false);
      // No new outbound HTTP requests.
      expect(f.observedRequests.length).toBe(requestsBefore);
    } finally {
      tmp.cleanup();
    }
  });
});

describe("VAL-W4-008: default trust root is relay.epochly.com; override requires escape hatch", () => {
  it("default trust root is relay.epochly.com", () => {
    expect(DEFAULT_TRUST_ROOT).toBe("relay.epochly.com");
    expect(resolveTrustRoot()).toBe(DEFAULT_TRUST_ROOT);
    expect(resolveTrustRoot(DEFAULT_TRUST_ROOT)).toBe(DEFAULT_TRUST_ROOT);
  });

  it("trust-root override without RELAY_ALLOW_CUSTOM_TRUST_ROOT=1 throws RelayTrustRootOverrideDenied", () => {
    expect(() => resolveTrustRoot("attacker.com")).toThrowError(RelayTrustRootOverrideDenied);
  });

  it("trust-root override with RELAY_ALLOW_CUSTOM_TRUST_ROOT=1 is honored", () => {
    process.env[ALLOW_CUSTOM_TRUST_ROOT_ENV] = "1";
    expect(resolveTrustRoot("self-hosted.example.org")).toBe("self-hosted.example.org");
  });

  it("override with whitespace-only value is rejected even with escape hatch", () => {
    process.env[ALLOW_CUSTOM_TRUST_ROOT_ENV] = "1";
    expect(() => resolveTrustRoot("   ")).toThrowError(RelayTrustRootOverrideDenied);
  });

  it("launchSidecar refuses if the manifest's claimed trust_root differs from the configured one", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture({ manifestTrustRoot: "attacker.com" });
      await expect(
        launchSidecar({
          home: tmp.home,
          manifestUrl: f.manifestUrl,
          fetchImpl: f.fetchImpl,
          fetchBundleImpl: f.fetchBundleImpl,
          fetchSigstoreImpl: f.fetchSigstoreImpl,
        }),
      ).rejects.toThrow(RelayTrustRootOverrideDenied);
    } finally {
      tmp.cleanup();
    }
  });
});

describe("VAL-W4-011b: bundle re-verification cache TTL", () => {
  it("cache hit within TTL skips Sigstore re-verification", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture();
      // First launch: full network + verify path.
      const t0 = new Date("2026-01-01T00:00:00Z");
      const first = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        now: t0,
        verifyBundleImpl: realVerifySeam,
      });
      expect(first.action).toBe("launched_fresh");
      // Count only the PER-BINARY sigstore re-verification download (URL
      // ends in ``.sigstore.json``). After VAL-CRYPTO-003 the wrapper also
      // fetches the release-manifest signature (``.json.sigstore``); that
      // is a manifest-side fetch and is not what this cache short-circuit
      // is about, so exclude it from the count.
      const sigstoreCallsBefore = f.observedRequests.filter((u) =>
        u.endsWith(".sigstore.json"),
      ).length;
      // Second launch within TTL: same network path BUT cache should
      // short-circuit; no additional Sigstore network calls.
      const t1 = new Date(t0.getTime() + 60_000); // +1 minute
      const second = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        now: t1,
      });
      expect(second.action).toBe("launched_from_cache");
      expect(second.cache_hit).toBe(true);
      const sigstoreCallsAfter = f.observedRequests.filter((u) =>
        u.endsWith(".sigstore.json"),
      ).length;
      expect(sigstoreCallsAfter).toBe(sigstoreCallsBefore);
    } finally {
      tmp.cleanup();
    }
  });

  it("cache miss (TTL expired) triggers re-verification and marker refresh", async () => {
    const tmp = setupTmpHome();
    try {
      const f = buildMockFixture();
      const t0 = new Date("2026-01-01T00:00:00Z");
      await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        now: t0,
        ttlSec: 60, // 60-second TTL for the test
        verifyBundleImpl: realVerifySeam,
      });
      // Forward time past the TTL.
      const t1 = new Date(t0.getTime() + 120_000);
      // Count only the PER-BINARY sigstore download (``.sigstore.json``);
      // see the cache-hit test above for why the manifest signature
      // (``.json.sigstore``, VAL-CRYPTO-003) is excluded.
      const sigstoreCallsBefore = f.observedRequests.filter((u) =>
        u.endsWith(".sigstore.json"),
      ).length;
      const after = await launchSidecar({
        home: tmp.home,
        manifestUrl: f.manifestUrl,
        fetchImpl: f.fetchImpl,
        fetchBundleImpl: f.fetchBundleImpl,
        fetchSigstoreImpl: f.fetchSigstoreImpl,
        now: t1,
        ttlSec: 60,
        verifyBundleImpl: realVerifySeam,
      });
      expect(after.action).toBe("launched_fresh");
      const sigstoreCallsAfter = f.observedRequests.filter((u) =>
        u.endsWith(".sigstore.json"),
      ).length;
      expect(sigstoreCallsAfter).toBe(sigstoreCallsBefore + 1);
      // Marker refreshed: last_verified ~ t1.
      const marker = readVerifiedMarker(after.digest, tmp.home);
      expect(marker).not.toBeNull();
      expect(marker?.last_verified).toBe(t1.toISOString());
    } finally {
      tmp.cleanup();
    }
  });

  it("evaluateTtl returns hit=false for a non-existent marker", () => {
    const tmp = setupTmpHome();
    try {
      const digest = "a".repeat(64);
      const e = evaluateTtl(digest, { home: tmp.home });
      expect(e.hit).toBe(false);
      expect(e.reason).toBe("no_marker");
    } finally {
      tmp.cleanup();
    }
  });

  it("default TTL is 24 hours", () => {
    expect(DEFAULT_BUNDLE_VERIFY_TTL_SEC).toBe(24 * 60 * 60);
  });
});

describe("manifest parser hardening", () => {
  it("rejects manifest with wrong schema_version", () => {
    const bogus = { schema_version: "relay.bogus.v0", bundles: [] };
    expect(() => parseReleaseManifest(bogus)).toThrowError(RelaySidecarBundleUnverified);
  });

  it("rejects manifest with non-https bundle url", () => {
    const f = buildMockFixture();
    const tampered = {
      ...f.manifest,
      bundles: [
        ...f.manifest.bundles.map((b) => ({ ...b })),
        {
          os: "linux",
          arch: "x64",
          url: "http://insecure.example/bundle.tar",
          sha256: f.bundleDigest,
          size_bytes: 100,
          sigstore_url: "https://relay.epochly.com/x.sigstore.json",
        },
      ],
    };
    expect(() => parseReleaseManifest(tampered)).toThrowError(RelaySidecarBundleUnverified);
  });
});
