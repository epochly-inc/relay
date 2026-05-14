/**
 * Bundle cache for the npx wrapper (W4.1).
 *
 * Layout under ``${RELAY_HOME:-~/.relay}/sidecar-bundles/<digest>/``:
 *
 *   bundle.bin       -- the verified bundle binary (chmod 0o700 on POSIX)
 *   manifest.json    -- the (verified) release manifest entry
 *   sigstore.json    -- the cosign-bundle JSON
 *   .verified        -- sentinel marker; body is a JSON object:
 *                       { last_verified: <ISO-8601>, ttl_sec: <int>,
 *                         digest: <hex>, trust_root: <host> }
 *
 * VAL-W4-007 / VAL-W4-007b: offline-with-cache happy path uses the cached
 * bundle. VAL-W4-011b: cache hit within TTL skips re-verification; cache
 * miss triggers re-verification and refreshes the marker.
 *
 * All persistent writes go through :func:`localAtomicFileWrite`
 * (CLAUDE.md keystone invariant #8).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { localAtomicFileWrite } from "../persistence/primitives/atomic_file.js";
import { DEFAULT_BUNDLE_VERIFY_TTL_SEC } from "./types.js";

export const BUNDLE_VERIFY_TTL_ENV = "RELAY_BUNDLE_VERIFY_TTL";

export interface VerifiedMarker {
  readonly last_verified: string;
  readonly ttl_sec: number;
  readonly digest: string;
  readonly trust_root: string;
}

/** Resolve the cache base directory: ``${home}/sidecar-bundles``. */
export function bundleCacheBase(home?: string): string {
  const override = process.env["RELAY_HOME"]?.trim() ?? "";
  const resolvedHome = home ?? (override ? override : path.join(os.homedir(), ".relay"));
  return path.join(resolvedHome, "sidecar-bundles");
}

/** Resolve the per-digest cache directory: ``<base>/<digest>``. */
export function bundleCacheDir(digest: string, home?: string): string {
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error(`bundle digest must be 64 lowercase hex; got ${JSON.stringify(digest)}`);
  }
  return path.join(bundleCacheBase(home), digest);
}

/**
 * Read the verified-marker for a given digest, if present.
 *
 * Returns ``null`` if the marker is absent, unparseable, or for a
 * different digest.
 */
export function readVerifiedMarker(digest: string, home?: string): VerifiedMarker | null {
  const markerPath = path.join(bundleCacheDir(digest, home), ".verified");
  let raw: string;
  try {
    raw = fs.readFileSync(markerPath, "utf8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const o = parsed as Record<string, unknown>;
  const lastVerified = o["last_verified"];
  const ttlSec = o["ttl_sec"];
  const markerDigest = o["digest"];
  const trustRoot = o["trust_root"];
  if (typeof lastVerified !== "string" || !lastVerified) return null;
  if (typeof ttlSec !== "number" || !Number.isFinite(ttlSec) || ttlSec < 0) return null;
  if (typeof markerDigest !== "string" || markerDigest !== digest) return null;
  if (typeof trustRoot !== "string" || !trustRoot) return null;
  // Refuse if the timestamp is unparseable.
  if (Number.isNaN(Date.parse(lastVerified))) return null;
  return { last_verified: lastVerified, ttl_sec: ttlSec, digest: markerDigest, trust_root: trustRoot };
}

/** Result of a TTL evaluation against a verified-marker. */
export interface TtlEvaluation {
  readonly hit: boolean;
  readonly last_verified?: string;
  readonly ttl_remaining_sec?: number;
  readonly reason?: "no_marker" | "expired";
}

/**
 * Evaluate whether the cache entry for ``digest`` is within its TTL.
 *
 * VAL-W4-011b: TTL default is :const:`DEFAULT_BUNDLE_VERIFY_TTL_SEC`;
 * callers may override via ``RELAY_BUNDLE_VERIFY_TTL=<seconds>``.
 */
export function evaluateTtl(
  digest: string,
  options: { home?: string; now?: Date; ttlSec?: number } = {},
): TtlEvaluation {
  const marker = readVerifiedMarker(digest, options.home);
  if (marker === null) {
    return { hit: false, reason: "no_marker" };
  }
  const ttlSec = options.ttlSec ?? ttlSecFromEnv() ?? marker.ttl_sec;
  const now = options.now ?? new Date();
  const lastMs = Date.parse(marker.last_verified);
  if (Number.isNaN(lastMs)) {
    return { hit: false, reason: "no_marker" };
  }
  const elapsedSec = (now.getTime() - lastMs) / 1000;
  const remaining = ttlSec - elapsedSec;
  if (remaining <= 0) {
    return { hit: false, reason: "expired", last_verified: marker.last_verified };
  }
  return {
    hit: true,
    last_verified: marker.last_verified,
    ttl_remaining_sec: Math.floor(remaining),
  };
}

/** Parse and validate ``RELAY_BUNDLE_VERIFY_TTL`` env var, returning seconds or ``null``. */
export function ttlSecFromEnv(): number | null {
  const raw = process.env[BUNDLE_VERIFY_TTL_ENV];
  if (raw === undefined || raw === "") return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.floor(n);
}

/**
 * Write the verified-marker for ``digest``, refreshing TTL bookkeeping.
 *
 * Uses the atomic-file primitive (keystone invariant #8). The parent
 * cache directory is created if absent.
 */
export function writeVerifiedMarker(
  digest: string,
  trustRoot: string,
  options: { home?: string; now?: Date; ttlSec?: number } = {},
): VerifiedMarker {
  const dir = bundleCacheDir(digest, options.home);
  fs.mkdirSync(dir, { recursive: true });
  const ttlSec = options.ttlSec ?? ttlSecFromEnv() ?? DEFAULT_BUNDLE_VERIFY_TTL_SEC;
  const now = options.now ?? new Date();
  const marker: VerifiedMarker = {
    last_verified: now.toISOString(),
    ttl_sec: ttlSec,
    digest,
    trust_root: trustRoot,
  };
  const markerPath = path.join(dir, ".verified");
  localAtomicFileWrite(markerPath, JSON.stringify(marker, null, 2) + "\n");
  return marker;
}

/** Read the cached bundle binary bytes; returns ``null`` if absent. */
export function readCachedBundle(digest: string, home?: string): Buffer | null {
  const binPath = path.join(bundleCacheDir(digest, home), "bundle.bin");
  try {
    return fs.readFileSync(binPath);
  } catch {
    return null;
  }
}

/**
 * Write the verified bundle binary to the per-digest cache dir.
 *
 * Uses the atomic-file primitive (keystone invariant #8). Mode 0o700 on
 * POSIX so the binary is owner-executable but not world-readable.
 */
export function writeCachedBundle(digest: string, bytes: Buffer, home?: string): string {
  const dir = bundleCacheDir(digest, home);
  fs.mkdirSync(dir, { recursive: true });
  const binPath = path.join(dir, "bundle.bin");
  localAtomicFileWrite(binPath, bytes, { mode: 0o700 });
  return binPath;
}

/** Write the cosign-bundle JSON for offline re-verification on the next launch. */
export function writeCachedSigstoreBundle(
  digest: string,
  sigstoreJson: string,
  home?: string,
): string {
  const dir = bundleCacheDir(digest, home);
  fs.mkdirSync(dir, { recursive: true });
  const sigPath = path.join(dir, "sigstore.json");
  localAtomicFileWrite(sigPath, sigstoreJson);
  return sigPath;
}

/** Read the cached cosign-bundle JSON; returns ``null`` if absent. */
export function readCachedSigstoreBundle(digest: string, home?: string): string | null {
  const sigPath = path.join(bundleCacheDir(digest, home), "sigstore.json");
  try {
    return fs.readFileSync(sigPath, "utf8");
  } catch {
    return null;
  }
}
