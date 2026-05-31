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
 *   1. Resolve (process.platform, process.arch) into a supported-host
 *      matrix entry (SUPPORTED_OS_ARCH; 4 cells -- Intel macOS / darwin-x64
 *      is unsupported). (Unsupported tuple -> RELAY-SIDECAR-023.)
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
 * Fail-closed enforcement flag for VAL-CRYPTO-003 release-manifest signing.
 *
 * The release pipeline (.github/workflows/release-sidecar-bundle.yml)
 * keyless-signs the aggregated ``manifest.json`` and publishes
 * ``manifest.json.sigstore`` alongside it (the "Keyless-sign the aggregated
 * manifest.json" step; asserted by scripts/check-sidecar-bundle.py). Current
 * releases therefore ship a signed manifest. The wrapper ALWAYS enforces a
 * signature that is PRESENT: a present-but-invalid manifest signature fails
 * closed. The remaining question is what to do when NO signature is present:
 *
 *   - DEFAULT (env unset, or ``=1``/``=true``): an ABSENT manifest signature
 *     is REJECTED fail-closed. A missing signature is treated as a downgrade
 *     / forgery surface, not as the norm. This is the post-rollout end state
 *     (plan A3 Step-2): the signing step has shipped, so an absent signature
 *     is anomalous and must not be silently trusted.
 *   - OPT-OUT (``=0``/``=false``): an ABSENT manifest signature is tolerated
 *     so forks, self-hosters, and legacy releases cut before the signing step
 *     keep launching via ``npx``. This is a DEGRADED trust mode -- the
 *     per-binary digest + Sigstore checks still run (the bundle BYTES remain
 *     hash-pinned), but the manifest provenance signature is skipped. The
 *     wrapper emits a stderr WARNING so the downgrade is never silent.
 *
 * A present-but-invalid signature ALWAYS fails closed regardless of this flag.
 */
export const REQUIRE_SIGNED_MANIFEST_ENV = "RELAY_REQUIRE_SIGNED_MANIFEST";

/**
 * Resolve whether a PRESENT manifest signature is mandatory, i.e. whether an
 * ABSENT signature must fail closed.
 *
 * Semantics (case- and whitespace-insensitive):
 *   - unset                      -> required (fail-closed default)
 *   - ``1`` / ``true``           -> required (explicit; back-compat with the
 *                                   prior ``=1`` enforcement value)
 *   - ``0`` / ``false``          -> NOT required (explicit documented opt-out)
 *   - any other non-empty value  -> required (fail closed; an unrecognized
 *                                   value must never silently downgrade)
 */
export function manifestSignatureRequired(): boolean {
  const raw = process.env[REQUIRE_SIGNED_MANIFEST_ENV];
  if (raw === undefined) return true;
  const v = raw.trim().toLowerCase();
  if (v === "0" || v === "false") return false;
  return true;
}

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
 * Trust-downgrade hardening (G1-F5): the caller's policy tolerates an ABSENT
 * manifest signature ONLY under the explicit opt-out
 * (``RELAY_REQUIRE_SIGNED_MANIFEST=0``) so forks / self-hosters / legacy
 * unsigned releases keep launching via npx. That tolerance is ONLY safe for a
 * signature that is GENUINELY not published. We therefore distinguish:
 *
 *   - a CLEAN HTTP 404 -> ``ManifestSignatureAbsent``. This is the only
 *     status that means "the signer never published a signature for this
 *     (legacy) release"; the opt-out policy may tolerate it.
 *   - a TRANSPORT / connection error (fetch rejects, e.g. ECONNRESET) ->
 *     ``RelaySidecarBundleUnverified`` (FAIL CLOSED). We cannot conclude the
 *     signature is absent -- an active MITM that serves a forged manifest but
 *     DROPS/RESETS the ``.sigstore`` request would otherwise strip manifest-
 *     signature enforcement entirely. This fails closed even under the
 *     transition default.
 *   - any OTHER non-200 status (403, 500, ...) ->
 *     ``RelaySidecarBundleUnverified`` (FAIL CLOSED). A 5xx/403 is an
 *     indeterminate answer, NOT a definitive "not published"; treating it as
 *     absent would be the same downgrade. Fails closed even under the
 *     transition default.
 *
 * A status 200 returns the signature body for cryptographic verification.
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
      // Transport / connection error: NOT "absent". We could not obtain a
      // definitive answer about the signature, so we must fail closed rather
      // than silently downgrade to an unsigned-manifest launch.
      throw new RelaySidecarBundleUnverified(
        `transport error fetching the release manifest signature from ${url}: ${
          cause instanceof Error ? cause.message : String(cause)
        }; refusing to treat an unreachable signature as absent`,
        {
          code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
          details: {
            reason: "manifest_signature_transport_error",
            manifest_signature_url: url,
            cause_message: cause instanceof Error ? cause.message : String(cause),
          },
          cause,
        },
      );
    }
    if (resp.status === 200) {
      return await resp.text();
    }
    if (resp.status === 404) {
      // Clean 404: the signer legitimately never published a signature for
      // this (legacy) release. ONLY this status maps to the tolerated-absent
      // transition path.
      throw new ManifestSignatureAbsent("manifest signature fetch returned HTTP 404");
    }
    // Any other non-200 (403, 500, ...) is indeterminate, not "absent".
    // Fail closed -- a non-404 HTTP error must never strip enforcement.
    throw new RelaySidecarBundleUnverified(
      `release manifest signature fetch returned HTTP ${resp.status} from ${url}; ` +
        "a non-404 status is indeterminate and is not treated as an absent signature",
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "manifest_signature_fetch_indeterminate",
          manifest_signature_url: url,
          http_status: resp.status,
        },
      },
    );
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
 * (VAL-CRYPTO-003), applying the fail-closed signed-release policy.
 *
 * Trust model:
 *   - A signature that is PRESENT is ALWAYS cryptographically verified over
 *     ``raw.rawBytes`` (the bytes received), rooted in ``trustRoot``,
 *     reusing the real crypto in :func:`verifySigstoreBundle`. A
 *     present-but-invalid signature fails closed (RELAY-SIDECAR-020).
 *   - A signature that is ABSENT (clean 404 -> ManifestSignatureAbsent) is
 *     REJECTED fail-closed BY DEFAULT (plan A3 Step-2). It is tolerated ONLY
 *     under the explicit documented opt-out ``RELAY_REQUIRE_SIGNED_MANIFEST=0``
 *     (forks / self-hosters / legacy unsigned releases), which emits a stderr
 *     WARNING; the per-binary digest + Sigstore checks still run.
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
      if (!manifestSignatureRequired()) {
        // Explicit, documented opt-out (RELAY_REQUIRE_SIGNED_MANIFEST=0):
        // tolerate an unsigned manifest for forks / self-hosters / legacy
        // releases. The per-binary digest + Sigstore checks still run
        // downstream, so the bundle BYTES remain hash-pinned; only the
        // manifest provenance signature is skipped. Emit a clear warning so
        // the downgrade is never silent.
        process.stderr.write(
          `[relay] WARNING: release manifest signature verification was SKIPPED ` +
            `because ${REQUIRE_SIGNED_MANIFEST_ENV} opts out of fail-closed ` +
            `enforcement. The manifest at ${raw.url} carries no Sigstore signature ` +
            `(${cause.message}); its provenance is UNVERIFIED. Per-binary digest + ` +
            `Sigstore checks still apply, but the manifest fields are trusted ` +
            `without a signature. Unset ${REQUIRE_SIGNED_MANIFEST_ENV} to restore ` +
            `fail-closed enforcement.\n`,
        );
        return;
      }
      throw new RelaySidecarBundleUnverified(
        "release manifest has no Sigstore signature; a signed manifest is " +
          `required by default (set ${REQUIRE_SIGNED_MANIFEST_ENV}=0 to opt out). ` +
          "Refusing to trust the manifest",
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
  if (ttl.hit) {
    const cachedBytes = readCachedBundle(entry.sha256, options.home);
    if (cachedBytes !== null) {
      // Never launch unverified bytes. The .verified marker only attests that
      // SOME bytes hashed to this digest at verification time; it does not
      // vouch for the bytes currently on disk. Re-hash bundle.bin against the
      // trusted digest directory name and fail closed on mismatch -- a
      // tampered/corrupted cache entry must be refused, not launched
      // (VAL-ISO-021). Reuses the existing fail-closed digest check.
      verifyDigest(cachedBytes, entry.sha256, {
        bundleUrl: entry.url,
        bundleEntry: { os: entry.os, arch: entry.arch },
      });
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
    // Never launch unverified bytes (VAL-ISO-021). The .verified marker does
    // not attest to the bytes currently on disk; re-hash bundle.bin against
    // the trusted digest directory name and fail closed on mismatch. A
    // tampered/corrupted offline cache entry must be refused, not launched.
    verifyDigest(bundle, digest, { bundleUrl: "(offline)" });
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
