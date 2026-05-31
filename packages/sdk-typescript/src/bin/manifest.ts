/**
 * Release-manifest fetcher and parser for the npx wrapper (W4.1).
 *
 * The canonical manifest URL lives in
 * ``packages/sdk-typescript/release-manifest.url`` (a one-line text file).
 * The wrapper:
 *   1. Reads that URL.
 *   2. Fetches the manifest JSON over HTTPS.
 *   3. Parses + validates the wire shape.
 *   4. Resolves the entry for the current ``process.platform`` x
 *      ``process.arch``.
 *
 * Wire integrity (Sigstore signature over the manifest itself) is handled
 * separately in :mod:`./verify`; this module is pure structural parsing.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE,
  RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
  RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
  RelaySidecarBundleArchUnsupported,
  RelaySidecarBundleUnavailable,
  RelaySidecarBundleUnverified,
} from "../errors.js";
import type { BundleEntry, ReleaseManifest, SupportedArch, SupportedOs } from "./types.js";
import { SUPPORTED_OS_ARCH } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Read the canonical manifest URL from the pinned text file. */
export function readCanonicalManifestUrl(): string {
  // The file lives at packages/sdk-typescript/release-manifest.url. From a
  // source-relative import this is two levels up (..) from ./bin/.
  const candidate = path.resolve(__dirname, "..", "..", "release-manifest.url");
  let raw: string;
  try {
    raw = fs.readFileSync(candidate, "utf8");
  } catch (cause) {
    throw new RelaySidecarBundleUnavailable(
      `pinned manifest URL file not found at ${candidate}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: {
          reason: "manifest_url_file_missing",
          path: candidate,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }
  const url = raw.trim();
  if (!url) {
    throw new RelaySidecarBundleUnavailable(
      `pinned manifest URL file at ${candidate} is empty`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "manifest_url_file_empty", path: candidate },
      },
    );
  }
  if (!url.startsWith("https://")) {
    throw new RelaySidecarBundleUnavailable(
      `pinned manifest URL must be HTTPS; got ${JSON.stringify(url)}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "manifest_url_not_https", url },
      },
    );
  }
  return url;
}

export interface ManifestFetchOptions {
  /** Override the default Node fetch (test seam). */
  fetchImpl?: (url: string, init?: RequestInit) => Promise<Response>;
  /** Bypass the pinned-URL file (test seam) for a known mock URL. */
  manifestUrl?: string;
  /** Override the per-request HTTP timeout in ms. */
  httpTimeoutMs?: number;
}

const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

/**
 * Fetch and parse the signed release manifest.
 *
 * Throws ``RelaySidecarBundleUnavailable`` on network failure, non-200
 * status, malformed JSON, or non-HTTPS manifest URL.
 */
export async function fetchReleaseManifest(
  options: ManifestFetchOptions = {},
): Promise<ReleaseManifest> {
  const url = options.manifestUrl ?? readCanonicalManifestUrl();
  if (!url.startsWith("https://")) {
    throw new RelaySidecarBundleUnavailable(
      `manifest URL must be HTTPS; got ${JSON.stringify(url)}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "manifest_url_not_https", url },
      },
    );
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.httpTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetchImpl(url, { method: "GET", signal: controller.signal });
  } catch (cause) {
    throw new RelaySidecarBundleUnavailable(
      `network error fetching manifest from ${url}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: {
          reason: "network_error",
          url,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  } finally {
    clearTimeout(timer);
  }
  if (resp.status !== 200) {
    throw new RelaySidecarBundleUnavailable(
      `manifest fetch returned HTTP ${resp.status} from ${url}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "non_200", url, http_status: resp.status },
      },
    );
  }
  let body: unknown;
  try {
    body = await resp.json();
  } catch (cause) {
    throw new RelaySidecarBundleUnverified(
      `manifest at ${url} was not valid JSON`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "manifest_not_json",
          url,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }
  return parseReleaseManifest(body, url);
}

/** Manifest fetched as both the parsed object AND the exact bytes received. */
export interface RawReleaseManifest {
  /** The parsed + validated manifest. */
  readonly manifest: ReleaseManifest;
  /**
   * The EXACT bytes received over the wire. The release-manifest Sigstore
   * signature is computed over these bytes, so VAL-CRYPTO-003 verification
   * MUST use them verbatim (not a re-serialization of the parsed object,
   * which would not be byte-identical). VAL-CRYPTO-003.
   */
  readonly rawBytes: Buffer;
  /** The URL the manifest was fetched from (for deriving the .sigstore URL). */
  readonly url: string;
}

/**
 * Fetch the release manifest AND retain the exact bytes received.
 *
 * Identical fetch + validation semantics to :func:`fetchReleaseManifest`
 * but returns the raw response bytes alongside the parsed manifest so the
 * caller can verify a Sigstore signature over the EXACT bytes (the
 * signature does not bind a JSON re-serialization). VAL-CRYPTO-003.
 */
export async function fetchReleaseManifestRaw(
  options: ManifestFetchOptions = {},
): Promise<RawReleaseManifest> {
  const url = options.manifestUrl ?? readCanonicalManifestUrl();
  if (!url.startsWith("https://")) {
    throw new RelaySidecarBundleUnavailable(
      `manifest URL must be HTTPS; got ${JSON.stringify(url)}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "manifest_url_not_https", url },
      },
    );
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.httpTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let resp: Response;
  try {
    resp = await fetchImpl(url, { method: "GET", signal: controller.signal });
  } catch (cause) {
    throw new RelaySidecarBundleUnavailable(
      `network error fetching manifest from ${url}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: {
          reason: "network_error",
          url,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  } finally {
    clearTimeout(timer);
  }
  if (resp.status !== 200) {
    throw new RelaySidecarBundleUnavailable(
      `manifest fetch returned HTTP ${resp.status} from ${url}`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE,
        details: { reason: "non_200", url, http_status: resp.status },
      },
    );
  }
  // Read the EXACT bytes; parse from the same bytes so the parsed object
  // and the signed-over bytes are guaranteed to be the same wire payload.
  const rawBytes = Buffer.from(await resp.arrayBuffer());
  let body: unknown;
  try {
    body = JSON.parse(rawBytes.toString("utf8"));
  } catch (cause) {
    throw new RelaySidecarBundleUnverified(
      `manifest at ${url} was not valid JSON`,
      {
        code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
        details: {
          reason: "manifest_not_json",
          url,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }
  return { manifest: parseReleaseManifest(body, url), rawBytes, url };
}

/** Parse a manifest JSON value; throws ``RelaySidecarBundleUnverified`` on malformed input. */
export function parseReleaseManifest(value: unknown, sourceUrl?: string): ReleaseManifest {
  const refuse = (reason: string, extra: Record<string, unknown> = {}): never => {
    throw new RelaySidecarBundleUnverified(`release manifest is malformed: ${reason}`, {
      code: RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE,
      details: {
        reason: `manifest_${reason}`,
        ...(sourceUrl !== undefined ? { source_url: sourceUrl } : {}),
        ...extra,
      },
    });
  };
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return refuse("not_an_object");
  }
  const obj = value as Record<string, unknown>;
  if (obj["schema_version"] !== "relay.sidecar_bundle_manifest.v1") {
    return refuse("wrong_schema_version", {
      observed: obj["schema_version"],
      expected: "relay.sidecar_bundle_manifest.v1",
    });
  }
  if (typeof obj["emitted_at"] !== "string" || !obj["emitted_at"]) {
    return refuse("invalid_emitted_at");
  }
  if (typeof obj["sidecar_version"] !== "string" || !obj["sidecar_version"]) {
    return refuse("invalid_sidecar_version");
  }
  if (typeof obj["trust_root"] !== "string" || !obj["trust_root"]) {
    return refuse("invalid_trust_root");
  }
  const bundlesRaw = obj["bundles"];
  if (!Array.isArray(bundlesRaw)) {
    return refuse("bundles_not_array");
  }
  const bundles: BundleEntry[] = [];
  for (let i = 0; i < bundlesRaw.length; i++) {
    const b = bundlesRaw[i];
    if (b === null || typeof b !== "object" || Array.isArray(b)) {
      return refuse("bundle_entry_not_object", { index: i });
    }
    const e = b as Record<string, unknown>;
    const os = e["os"];
    const arch = e["arch"];
    const url = e["url"];
    const sha = e["sha256"];
    const size = e["size_bytes"];
    const sig = e["sigstore_url"];
    if (os !== "darwin" && os !== "linux" && os !== "win32") {
      return refuse("invalid_bundle_os", { index: i, os });
    }
    if (arch !== "x64" && arch !== "arm64") {
      return refuse("invalid_bundle_arch", { index: i, arch });
    }
    if (typeof url !== "string" || !url.startsWith("https://")) {
      return refuse("invalid_bundle_url", { index: i });
    }
    if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha)) {
      return refuse("invalid_bundle_sha256", { index: i });
    }
    if (typeof size !== "number" || !Number.isInteger(size) || size <= 0) {
      return refuse("invalid_bundle_size", { index: i });
    }
    if (typeof sig !== "string" || !sig.startsWith("https://")) {
      return refuse("invalid_bundle_sigstore_url", { index: i });
    }
    bundles.push({
      os: os as SupportedOs,
      arch: arch as SupportedArch,
      url,
      sha256: sha,
      size_bytes: size,
      sigstore_url: sig,
    });
  }
  return {
    schema_version: "relay.sidecar_bundle_manifest.v1",
    emitted_at: obj["emitted_at"] as string,
    sidecar_version: obj["sidecar_version"] as string,
    trust_root: obj["trust_root"] as string,
    bundles,
  };
}

/**
 * Resolve the bundle entry matching the running Node process's
 * (platform, arch).
 *
 * Throws :class:`RelaySidecarBundleArchUnsupported` if either the host is
 * not in the supported host matrix (SUPPORTED_OS_ARCH; 4 cells -- Intel
 * macOS / darwin-x64 is unsupported), or the manifest does not enumerate
 * the matching entry.
 */
export function resolveBundleEntry(
  manifest: ReleaseManifest,
  hostOs: string = process.platform,
  hostArch: string = process.arch,
): BundleEntry {
  const supported = SUPPORTED_OS_ARCH.some(
    (cell) => cell.os === hostOs && cell.arch === hostArch,
  );
  if (!supported) {
    throw new RelaySidecarBundleArchUnsupported(
      `host (${hostOs}, ${hostArch}) is not in the v0.1 supported sidecar bundle matrix`,
      {
        code: RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE,
        details: {
          reason: "host_not_in_matrix",
          host_os: hostOs,
          host_arch: hostArch,
          supported_matrix: SUPPORTED_OS_ARCH.map((c) => ({ os: c.os, arch: c.arch })),
        },
      },
    );
  }
  const entry = manifest.bundles.find((b) => b.os === hostOs && b.arch === hostArch);
  if (entry === undefined) {
    throw new RelaySidecarBundleArchUnsupported(
      `manifest does not enumerate a bundle for (${hostOs}, ${hostArch})`,
      {
        code: RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE,
        details: {
          reason: "manifest_missing_arch",
          host_os: hostOs,
          host_arch: hostArch,
          manifest_arches: manifest.bundles.map((b) => ({ os: b.os, arch: b.arch })),
        },
      },
    );
  }
  return entry;
}
