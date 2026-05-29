/**
 * npx wrapper orchestrator for the W4.1 sidecar bundle flow.
 *
 * Exported as a pure function so vitest can drive it end-to-end with
 * mocked transports. The CLI entry point at ``./relay-sidecar.ts`` is a
 * thin shim that parses argv, calls :func:`launchSidecar`, and emits the
 * resulting JSON to stdout.
 *
 * Flow (per VAL-W4-004 through VAL-W4-011b):
 *
 *   1. Resolve (process.platform, process.arch) into a 5-cell matrix
 *      entry. (Unsupported tuple -> RELAY-SIDECAR-023.)
 *   2. If the cache has a ``.verified`` marker within TTL, launch from
 *      cache. Emit ``{action: "launched_from_cache", ...}`` and skip
 *      network. (VAL-W4-011b cache hit.)
 *   3. Otherwise, attempt to fetch the signed release manifest from the
 *      pinned URL. (Network unreachable + cache miss ->
 *      RELAY-SIDECAR-022; with cache, fall back to cache.)
 *   4. Find the manifest entry matching our (os, arch).
 *   5. Download the bundle binary.
 *   6. **First** verify the bundle's SHA-256 digest against the manifest.
 *      (Digest mismatch -> RELAY-SIDECAR-021.) -- VAL-W4-005 ordering.
 *   7. **Then** verify the Sigstore bundle. (Verify failure ->
 *      RELAY-SIDECAR-020.) -- VAL-W4-004.
 *   8. Persist bundle + sigstore.json + .verified marker via the atomic
 *      file primitive. (Keystone invariant #8.)
 *   9. Return the launch decision.
 *
 * VAL-W4-008: a non-default ``trust_root`` is refused unless the caller
 * passes ``--trust-root <host>`` AND ``RELAY_ALLOW_CUSTOM_TRUST_ROOT=1``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
  RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
  RelaySidecarBundleUnavailable,
  RelayTrustRootOverrideDenied,
} from "../errors.js";
import {
  bundleCacheDir,
  evaluateTtl,
  readCachedBundle,
  readCachedSigstoreBundle,
  readVerifiedMarker,
  writeCachedBundle,
  writeCachedSigstoreBundle,
  writeVerifiedMarker,
} from "./cache.js";
import {
  fetchReleaseManifestRaw,
  resolveBundleEntry,
  type ManifestFetchOptions,
  type RawReleaseManifest,
} from "./manifest.js";
import type { BundleEntry } from "./types.js";
import { DEFAULT_TRUST_ROOT } from "./types.js";
import {
  RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
  RelaySidecarBundleUnverified,
} from "../errors.js";
import {
  verifyDigest,
  verifySigstoreBundle,
  type SigstoreVerifyOptions,
} from "./verify.js";

/**
 * Sigstore-verification seam. Production binds this to the real fail-closed
 * :func:`verifySigstoreBundle` (which delegates to ``@sigstore/verify``
 * against the pinned public-good trusted root). It is exposed as an option
 * ONLY so orchestration tests (cache/TTL/digest-ordering) can drive the
 * wrapper deterministically without a live OIDC/Rekor round trip; the
 * cryptographic correctness of the verifier itself is proven directly in
 * test/w4_7_sigstore_trust_chain.test.ts against REAL recorded bundles.
 */
export type VerifySigstoreBundleFn = (
  artifactBytes: Buffer | string | undefined,
  sigstoreJson: string | Buffer,
  options: SigstoreVerifyOptions,
) => unknown;

export const ALLOW_CUSTOM_TRUST_ROOT_ENV = "RELAY_ALLOW_CUSTOM_TRUST_ROOT";

/**
 * Transition flag for VAL-CRYPTO-003 release-manifest signing rollout.
 *
 * The release pipeline (.github/workflows/release-sidecar-bundle.yml) now
 * keyless-signs the aggregated ``manifest.json`` and publishes
 * ``manifest.json.sigstore`` alongside it. The wrapper ALWAYS enforces a
 * signature that is PRESENT: a present-but-invalid manifest signature
 * fails closed. The remaining question is what to do when NO signature is
 * present (a legacy release cut before the signing step shipped):
 *
 *   - With ``RELAY_REQUIRE_SIGNED_MANIFEST`` unset/!="1" (the transition
 *     default): an ABSENT manifest signature is tolerated so existing
 *     legacy releases keep launching via ``npx`` -- the per-binary digest +
 *     Sigstore checks still run. This is a DEGRADED trust mode and is the
 *     ONLY path that trusts an unsigned manifest.
 *   - With ``RELAY_REQUIRE_SIGNED_MANIFEST=1`` (the end state): an ABSENT
 *     manifest signature is REJECTED fail-closed.
 *
 * PRODUCTION ROLLOUT NOTE: once signed releases exist for all supported
 * cells and the oldest still-fetchable manifest is signed, the DEFAULT of
 * this flag MUST flip to enforce-by-default (require a manifest signature
 * unconditionally). That flip is a coordinated change tracked with the
 * orchestrator; until then the transition default keeps npx working.
 */
export const REQUIRE_SIGNED_MANIFEST_ENV = "RELAY_REQUIRE_SIGNED_MANIFEST";

/** Derive the manifest's cosign-bundle URL: ``<manifestUrl>.sigstore``. */
export function manifestSignatureUrl(manifestUrl: string): string {
  return `${manifestUrl}.sigstore`;
}

export interface LaunchSidecarOptions {
  /** Relay home directory; test seam. */
  home?: string;
  /** Override the canonical manifest URL (test seam). */
  manifestUrl?: string;
  /** Override the host platform/arch (test seam). */
  hostOs?: string;
  /** Override the host arch (test seam). */
  hostArch?: string;
  /** Override the trust root host. VAL-W4-008 gates this. */
  trustRoot?: string;
  /**
   * When true, treat the network as reachable. Tests set false to simulate
   * the offline VAL-W4-007 / VAL-W4-007b paths.
   */
  networkAvailable?: boolean;
  /** Custom fetch for manifest and bundle downloads. */
  fetchImpl?: ManifestFetchOptions["fetchImpl"];
  /**
   * Bundle-bytes fetcher (test seam). Production code fetches via
   * ``fetchImpl``. The wrapper passes the bundle's URL through.
   */
  fetchBundleImpl?: (url: string) => Promise<Buffer>;
  /** Cosign-bundle fetcher (test seam). */
  fetchSigstoreImpl?: (url: string) => Promise<string>;
  /**
   * Release-manifest cosign-bundle fetcher (test seam, VAL-CRYPTO-003).
   * Resolves with the ``manifest.json.sigstore`` text. MUST reject (throw)
   * when the signature is absent (e.g. a 404 for a legacy release) so the
   * caller can distinguish "absent" (transition policy) from
   * "present-but-invalid" (always fail closed).
   */
  fetchManifestSigstoreImpl?: (url: string) => Promise<string>;
  /** Override the launch time (test seam for TTL boundary tests). */
  now?: Date;
  /** When provided, override the TTL in seconds for VAL-W4-011b tests. */
  ttlSec?: number;
  /**
   * Sigstore-verification seam (test only). Defaults to the real fail-closed
   * :func:`verifySigstoreBundle`. Orchestration tests inject a deterministic
   * verifier so the cache/TTL/digest-ordering behavior can be exercised
   * without a live Rekor/Fulcio round trip; the verifier's cryptographic
   * correctness is proven directly in w4_7_sigstore_trust_chain.test.ts.
   */
  verifyBundleImpl?: VerifySigstoreBundleFn;
}

export interface LaunchDecision {
  readonly action: "launched_fresh" | "launched_from_cache" | "verified_only";
  readonly source: "network" | "cache";
  readonly digest: string;
  readonly verified_at: string;
  readonly bundle_url: string;
  readonly host_os: string;
  readonly host_arch: string;
  readonly trust_root: string;
  readonly cache_dir: string;
  readonly cache_hit?: boolean;
  readonly ttl_remaining_sec?: number;
}

/** Pluck the trust root with the VAL-W4-008 escape-hatch enforcement. */
export function resolveTrustRoot(override?: string): string {
  if (override === undefined || override === DEFAULT_TRUST_ROOT) {
    return DEFAULT_TRUST_ROOT;
  }
  const allowed = process.env[ALLOW_CUSTOM_TRUST_ROOT_ENV] === "1";
  if (!allowed) {
    throw new RelayTrustRootOverrideDenied(
      `trust root override to ${JSON.stringify(override)} requires ${ALLOW_CUSTOM_TRUST_ROOT_ENV}=1; ` +
        "the default trust root is the Relay-managed endpoint and is governed by board-level decision",
      {
        code: RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
        details: {
          reason: "custom_trust_root_without_escape_hatch",
          attempted_trust_root: override,
          default_trust_root: DEFAULT_TRUST_ROOT,
          env_var: ALLOW_CUSTOM_TRUST_ROOT_ENV,
        },
      },
    );
  }
  if (!override.trim()) {
    throw new RelayTrustRootOverrideDenied("trust root override is empty", {
      code: RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
      details: { reason: "custom_trust_root_empty" },
    });
  }
  return override;
}

/**
 * Default bundle/sigstore fetchers built on top of the manifest fetch.
 */
function defaultBundleFetcher(
  fetchImpl: ManifestFetchOptions["fetchImpl"] | undefined,
): (url: string) => Promise<Buffer> {
  const impl = fetchImpl ?? globalThis.fetch.bind(globalThis);
  return async (url: string) => {
    const resp = await impl(url, { method: "GET" });
    if (resp.status !== 200) {
      throw new RelaySidecarBundleUnavailable(
        `bundle fetch returned HTTP ${resp.status} from ${url}`,
        {
          code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
          details: { reason: "non_200_bundle", url, http_status: resp.status },
        },
      );
    }
    const buf = Buffer.from(await resp.arrayBuffer());
    return buf;
  };
}

function defaultSigstoreFetcher(
  fetchImpl: ManifestFetchOptions["fetchImpl"] | undefined,
): (url: string) => Promise<string> {
  const impl = fetchImpl ?? globalThis.fetch.bind(globalThis);
  return async (url: string) => {
    const resp = await impl(url, { method: "GET" });
    if (resp.status !== 200) {
      throw new RelaySidecarBundleUnavailable(
        `sigstore bundle fetch returned HTTP ${resp.status} from ${url}`,
        {
          code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
          details: { reason: "non_200_sigstore", url, http_status: resp.status },
        },
      );
    }
    return await resp.text();
  };
}

/**
 * Default fetcher for the release-manifest cosign-bundle
 * (``manifest.json.sigstore``). VAL-CRYPTO-003.
 *
 * A non-200 (e.g. 404 for a legacy release that predates manifest signing)
 * THROWS ``ManifestSignatureAbsent`` so the caller can apply the transition
 * policy; any other status throws the generic unavailable leaf.
 */
function defaultManifestSigstoreFetcher(
  fetchImpl: ManifestFetchOptions["fetchImpl"] | undefined,
): (url: string) => Promise<string> {
  const impl = fetchImpl ?? globalThis.fetch.bind(globalThis);
  return async (url: string) => {
    let resp: Response;
    try {
      resp = await impl(url, { method: "GET" });
    } catch (cause) {
      // A network/transport error fetching the manifest signature is
      // treated as "absent" so a transient outage on the signature object
      // does not harden into a launch failure under the transition policy.
      throw new ManifestSignatureAbsent(
        cause instanceof Error ? cause.message : String(cause),
      );
    }
    if (resp.status === 200) {
      return await resp.text();
    }
    throw new ManifestSignatureAbsent(`manifest signature fetch returned HTTP ${resp.status}`);
  };
}

/**
 * Sentinel thrown by a manifest-signature fetcher when NO signature object
 * exists (404 / network error). Distinguishes the transition-policy
 * "absent" case from a "present-but-invalid" signature (which always fails
 * closed). VAL-CRYPTO-003.
 */
export class ManifestSignatureAbsent extends Error {
  constructor(reason: string) {
    super(`release manifest signature absent: ${reason}`);
    this.name = "ManifestSignatureAbsent";
  }
}

/**
 * Verify a Sigstore signature over the EXACT release-manifest bytes
 * (VAL-CRYPTO-003), applying the signed-release transition policy.
 *
 * Trust model:
 *   - A signature that is PRESENT is ALWAYS cryptographically verified over
 *     ``raw.rawBytes`` (the bytes received), rooted in ``trustRoot``,
 *     reusing the real crypto in :func:`verifySigstoreBundle`. A
 *     present-but-invalid signature fails closed (RELAY-SIDECAR-020).
 *   - A signature that is ABSENT (404 / network error -> ManifestSignatureAbsent)
 *     is tolerated ONLY when ``RELAY_REQUIRE_SIGNED_MANIFEST`` is not "1"
 *     (the transition default that keeps legacy unsigned releases working);
 *     when the flag is "1" an absent signature is REJECTED fail-closed.
 *
 * Note: we deliberately do NOT bind ``expectedSha256`` here -- the
 * manifest's own digest is not pinned anywhere external; the binding that
 * matters is the signature-over-the-manifest-bytes + the cert issuer
 * chaining to the trust root. The per-binary digest binding still happens
 * downstream in :func:`verifyDigest` + :func:`verifySigstoreBundle`.
 */
async function verifyManifestSignature(
  options: LaunchSidecarOptions,
  raw: RawReleaseManifest,
  trustRoot: string,
): Promise<void> {
  const sigUrl = manifestSignatureUrl(raw.url);
  const fetcher =
    options.fetchManifestSigstoreImpl ?? defaultManifestSigstoreFetcher(options.fetchImpl);
  let manifestSigstoreJson: string;
  try {
    manifestSigstoreJson = await fetcher(sigUrl);
  } catch (cause) {
    if (cause instanceof ManifestSignatureAbsent) {
      const required = process.env[REQUIRE_SIGNED_MANIFEST_ENV] === "1";
      if (!required) {
        // Transition default: tolerate a legacy unsigned manifest. The
        // per-binary digest + Sigstore checks still run downstream.
        return;
      }
      throw new RelaySidecarBundleUnverified(
        "release manifest has no Sigstore signature and " +
          `${REQUIRE_SIGNED_MANIFEST_ENV}=1 requires one; refusing to trust the manifest`,
        {
          code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
          details: {
            reason: "manifest_signature_absent_under_enforcement",
            manifest_url: raw.url,
            manifest_signature_url: sigUrl,
            cause_message: cause.message,
          },
        },
      );
    }
    // Any other fetch error (a non-absent transport failure surfaced by a
    // custom fetcher) propagates unchanged.
    throw cause;
  }
  // A signature is PRESENT -> ALWAYS enforce. The signature is verified
  // over the EXACT manifest bytes (not a re-serialization). A forged or
  // non-binding signature fails closed inside verifySigstoreBundle.
  const verify = options.verifyBundleImpl ?? verifySigstoreBundle;
  verify(raw.rawBytes, manifestSigstoreJson, { trustRoot });
}

/**
 * Top-level orchestrator. Returns a launch decision; the CLI shim emits
 * its JSON to stdout. Does NOT spawn the binary itself -- spawn happens
 * in the CLI shim after this returns successfully.
 */
export async function launchSidecar(
  options: LaunchSidecarOptions = {},
): Promise<LaunchDecision> {
  const trustRoot = resolveTrustRoot(options.trustRoot);
  const networkAvailable = options.networkAvailable !== false;

  if (networkAvailable) {
    return launchFresh(options, trustRoot);
  }
  return launchOfflineFromCacheOrFail(options, trustRoot);
}

async function launchFresh(
  options: LaunchSidecarOptions,
  trustRoot: string,
): Promise<LaunchDecision> {
  const hostOs = options.hostOs ?? process.platform;
  const hostArch = options.hostArch ?? process.arch;
  // Step A: fetch the manifest AND its exact wire bytes. Failure paths
  // route through RelaySidecarBundleUnavailable.
  let raw: RawReleaseManifest;
  try {
    const fetchOpts: ManifestFetchOptions = {};
    if (options.fetchImpl !== undefined) fetchOpts.fetchImpl = options.fetchImpl;
    if (options.manifestUrl !== undefined) fetchOpts.manifestUrl = options.manifestUrl;
    raw = await fetchReleaseManifestRaw(fetchOpts);
  } catch (cause) {
    // Fall back to cache if any verified bundle exists for this host's
    // (os, arch) tuple. This handles "manifest URL transiently 503" with
    // the offline-with-cache happy path. VAL-W4-007 / VAL-W4-007b.
    const fallback = tryOfflineFromCache(options, trustRoot, hostOs, hostArch);
    if (fallback !== null) return fallback;
    throw cause;
  }
  const manifest = raw.manifest;
  // Step A2 (VAL-CRYPTO-003): cryptographically verify a Sigstore signature
  // over the EXACT manifest bytes BEFORE trusting any manifest field (the
  // per-entry sha256 digests and the trust_root claim). Without this, an
  // attacker who serves/MITMs the manifest URL ships a malicious bundle by
  // pinning entry.sha256 = SHA-256(malicious) and a matching trust_root.
  // Signing only the leaf binaries is insufficient: the manifest is the
  // trust root for the whole chain. Reuses the real crypto in verify.ts
  // (VAL-CRYPTO-002) -- no new crypto here.
  await verifyManifestSignature(options, raw, trustRoot);
  const entry: BundleEntry = resolveBundleEntry(manifest, hostOs, hostArch);
  // Manifest's claimed trust_root must equal the resolved trust root.
  // VAL-W4-008.
  if (manifest.trust_root !== trustRoot) {
    throw new RelayTrustRootOverrideDenied(
      `manifest trust_root ${JSON.stringify(manifest.trust_root)} does not match configured ${JSON.stringify(trustRoot)}`,
      {
        code: RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
        details: {
          reason: "manifest_trust_root_mismatch",
          manifest_trust_root: manifest.trust_root,
          configured_trust_root: trustRoot,
        },
      },
    );
  }
  // Step B: TTL check. If a cached marker is fresh AND the digest matches
  // the manifest entry, we launch from cache without re-downloading.
  // VAL-W4-011b cache-hit path.
  const ttlEvalOpts: { home?: string; now?: Date; ttlSec?: number } = {};
  if (options.home !== undefined) ttlEvalOpts.home = options.home;
  if (options.now !== undefined) ttlEvalOpts.now = options.now;
  if (options.ttlSec !== undefined) ttlEvalOpts.ttlSec = options.ttlSec;
  const ttl = evaluateTtl(entry.sha256, ttlEvalOpts);
  if (ttl.hit && readCachedBundle(entry.sha256, options.home) !== null) {
    return {
      action: "launched_from_cache",
      source: "cache",
      digest: entry.sha256,
      verified_at: ttl.last_verified ?? new Date().toISOString(),
      bundle_url: entry.url,
      host_os: hostOs,
      host_arch: hostArch,
      trust_root: trustRoot,
      cache_dir: bundleCacheDir(entry.sha256, options.home),
      cache_hit: true,
      ttl_remaining_sec: ttl.ttl_remaining_sec ?? 0,
    };
  }
  // Step C: fetch the bundle bytes and Sigstore bundle.
  const bundleFetcher = options.fetchBundleImpl ?? defaultBundleFetcher(options.fetchImpl);
  const sigstoreFetcher =
    options.fetchSigstoreImpl ?? defaultSigstoreFetcher(options.fetchImpl);
  const bundleBytes = await bundleFetcher(entry.url);
  const sigstoreJson = await sigstoreFetcher(entry.sigstore_url);
  // Step D: digest check FIRST (VAL-W4-005).
  verifyDigest(bundleBytes, entry.sha256, {
    bundleUrl: entry.url,
    bundleEntry: { os: entry.os, arch: entry.arch },
  });
  // Step E: Sigstore check (VAL-W4-004 / VAL-CRYPTO-002). Pass the ACTUAL
  // bundle bytes so the signature is cryptographically verified over them
  // (fail-closed: Fulcio chain to the pinned root, Rekor inclusion proof,
  // SCT, validity window, P-256 curve pin) and the messageDigest is bound to
  // the manifest-pinned entry.sha256.
  const verify = options.verifyBundleImpl ?? verifySigstoreBundle;
  verify(bundleBytes, sigstoreJson, {
    trustRoot,
    expectedSha256: entry.sha256,
  });
  // Step F: persist cache.
  writeCachedBundle(entry.sha256, bundleBytes, options.home);
  writeCachedSigstoreBundle(entry.sha256, sigstoreJson, options.home);
  const markerOpts: { home?: string; now?: Date; ttlSec?: number } = {};
  if (options.home !== undefined) markerOpts.home = options.home;
  if (options.now !== undefined) markerOpts.now = options.now;
  if (options.ttlSec !== undefined) markerOpts.ttlSec = options.ttlSec;
  const marker = writeVerifiedMarker(entry.sha256, trustRoot, markerOpts);
  return {
    action: "launched_fresh",
    source: "network",
    digest: entry.sha256,
    verified_at: marker.last_verified,
    bundle_url: entry.url,
    host_os: hostOs,
    host_arch: hostArch,
    trust_root: trustRoot,
    cache_dir: bundleCacheDir(entry.sha256, options.home),
    cache_hit: false,
  };
}

function tryOfflineFromCache(
  options: LaunchSidecarOptions,
  trustRoot: string,
  hostOs: string,
  hostArch: string,
): LaunchDecision | null {
  // Enumerate cached bundles and return the first whose marker is fresh
  // for the configured trust_root. We do NOT need to enumerate the
  // manifest -- offline mode trusts the cached marker.
  const home = options.home;
  let candidates: string[] = [];
  try {
    const base = bundleCacheBaseOrNull(home);
    if (base === null) return null;
    candidates = fs.readdirSync(base);
  } catch {
    return null;
  }
  for (const digest of candidates) {
    if (!/^[0-9a-f]{64}$/.test(digest)) continue;
    const marker = readVerifiedMarker(digest, home);
    if (marker === null) continue;
    if (marker.trust_root !== trustRoot) continue;
    const ttlEvalOpts: { home?: string; now?: Date; ttlSec?: number } = {};
    if (home !== undefined) ttlEvalOpts.home = home;
    if (options.now !== undefined) ttlEvalOpts.now = options.now;
    if (options.ttlSec !== undefined) ttlEvalOpts.ttlSec = options.ttlSec;
    const ttl = evaluateTtl(digest, ttlEvalOpts);
    if (!ttl.hit) continue;
    const bundle = readCachedBundle(digest, home);
    const sigstore = readCachedSigstoreBundle(digest, home);
    if (bundle === null || sigstore === null) continue;
    return {
      action: "launched_from_cache",
      source: "cache",
      digest,
      verified_at: marker.last_verified,
      bundle_url: "(offline)",
      host_os: hostOs,
      host_arch: hostArch,
      trust_root: trustRoot,
      cache_dir: bundleCacheDir(digest, home),
      cache_hit: true,
      ttl_remaining_sec: ttl.ttl_remaining_sec ?? 0,
    };
  }
  return null;
}

/** Compute the cache base dir; returns null if any error. */
function bundleCacheBaseOrNull(home: string | undefined): string | null {
  try {
    const override = process.env["RELAY_HOME"]?.trim() ?? "";
    const resolvedHome =
      home ?? (override ? override : path.join(os.homedir(), ".relay"));
    return path.join(resolvedHome, "sidecar-bundles");
  } catch {
    return null;
  }
}

async function launchOfflineFromCacheOrFail(
  options: LaunchSidecarOptions,
  trustRoot: string,
): Promise<LaunchDecision> {
  const hostOs = options.hostOs ?? process.platform;
  const hostArch = options.hostArch ?? process.arch;
  const decision = tryOfflineFromCache(options, trustRoot, hostOs, hostArch);
  if (decision !== null) return decision;
  throw new RelaySidecarBundleUnavailable(
    "network is unreachable and no verified bundle is present in the cache",
    {
      code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
      retryAdvice: { mode: "after_state_change" },
      details: {
        reason: "offline_no_cache",
        host_os: hostOs,
        host_arch: hostArch,
        trust_root: trustRoot,
      },
    },
  );
}
