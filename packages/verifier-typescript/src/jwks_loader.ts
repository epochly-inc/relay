// Trust-anchor JWKS resolver for the OSS verifier (TS parity with
// packages/verifier/src/relay_verifier/jwks_loader.py).
//
// Owns the bundled-JWKS asset loader, the cached-JWKS reader, and the
// top-level resolveJwks orchestration that selects which JWKS source to
// use (offline flag, BYO flag URL, BYO config file, cache state, default).
//
// Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to the
// spec-pinned trust anchor (literal lives in constants.ts ONLY). Per
// banned pattern #13 changing the default is a board-level decision; BYO
// is the supported escape hatch for forks and self-hosters.
//
// On-disk cache envelope shape mirrors the Python CLI cache exactly so an
// operator's cache directory works with either runtime.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { DEFAULT_JWKS_URL } from "./constants.js";

export const JWKS_CACHE_SCHEMA_VERSION = "relay.cli.jwks_cache.v1" as const;
export const JWKS_CACHE_DIRNAME = "jwks-cache" as const;

/** 7 days; mirrors Python `CACHE_STALENESS_THRESHOLD_SECONDS`. */
export const CACHE_STALENESS_THRESHOLD_SECONDS = 7 * 24 * 60 * 60;

export const TRUST_ANCHOR_SOURCE_LIVE = "live_fetch" as const;
export const TRUST_ANCHOR_SOURCE_CACHE = "cached_jwks" as const;
export const TRUST_ANCHOR_SOURCE_BUNDLED = "bundled_jwks" as const;
export const TRUST_ANCHOR_SOURCE_BYO_FLAG = "byo_flag" as const;
export const TRUST_ANCHOR_SOURCE_BYO_CONFIG = "byo_config" as const;

export type TrustAnchorSource =
  | typeof TRUST_ANCHOR_SOURCE_LIVE
  | typeof TRUST_ANCHOR_SOURCE_CACHE
  | typeof TRUST_ANCHOR_SOURCE_BUNDLED
  | typeof TRUST_ANCHOR_SOURCE_BYO_FLAG
  | typeof TRUST_ANCHOR_SOURCE_BYO_CONFIG;

export const BUNDLED_JWKS_ASSET = "bundled_jwks.json" as const;

// Filesystem-safe charset for per-host cache filename; mirrors Python
// `_HOST_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")`.
const HOST_FILENAME_SAFE_RE = /[^A-Za-z0-9._-]/g;

export interface JWKSLoadResult {
  jwks: Record<string, unknown>;
  source: TrustAnchorSource;
  trust_anchor_url: string;
  warnings: Array<Record<string, unknown>>;
}

export type NetworkFetcher = (url: string) => Promise<Record<string, unknown>> | Record<string, unknown>;

// ----------------------------------------------------------------------------
// Bundled JWKS loader
// ----------------------------------------------------------------------------

export function loadBundledJwks(): Record<string, unknown> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const candidates = [
    resolve(__dirname, BUNDLED_JWKS_ASSET),
    resolve(__dirname, "..", "src", BUNDLED_JWKS_ASSET),
    resolve(__dirname, "..", BUNDLED_JWKS_ASSET),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      const raw = readFileSync(p, "utf-8");
      if (raw.length === 0) {
        throw new Error(`bundled JWKS asset ${BUNDLED_JWKS_ASSET} is empty`);
      }
      const parsed: unknown = JSON.parse(raw);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("bundled JWKS root must be a JSON object");
      }
      const obj = parsed as Record<string, unknown>;
      if (!Array.isArray(obj["keys"])) {
        throw new Error("bundled JWKS missing 'keys' array (RFC 7517 sec 5)");
      }
      return obj;
    }
  }
  // No bundled asset found is acceptable for the BYO/online path; raise a
  // structured error only when the caller actually requests the bundled
  // source.
  throw new Error(
    `bundled JWKS asset ${BUNDLED_JWKS_ASSET} not found in package ${"@epochly/relay-verifier"}`,
  );
}

// ----------------------------------------------------------------------------
// Cache helpers (mirrors Python `_cache_path_for_url` / `load_cached_jwks`)
// ----------------------------------------------------------------------------

function _relayHomeDefault(home?: string): string {
  if (home !== undefined && home.length > 0) {
    return home;
  }
  const env = process.env["RELAY_HOME"]?.trim();
  if (env && env.length > 0) {
    return env;
  }
  return join(homedir(), ".relay");
}

/**
 * Extract the cache-key hostname (and port when present) from a URL.
 * Mirrors Python `_hostname_for_url`: lowercases the hostname, appends
 * `_{port}` when an explicit port appears in the URL.
 *
 * WHATWG URL normalises default-port `:443` (https) / `:80` (http) to
 * the empty string in `parsed.port`, but Python's `urlparse` preserves
 * the explicit port. To preserve cross-runtime byte-equality of the
 * cache filename (VAL-V2M06-020), we read the explicit port from the
 * raw URL string when one appears between the host and the path.
 */
export function hostnameForUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`trust anchor URL has no hostname: ${JSON.stringify(url)}`);
  }
  const host = (parsed.hostname || "").toLowerCase().trim();
  if (host.length === 0) {
    throw new Error(`trust anchor URL has no hostname: ${JSON.stringify(url)}`);
  }
  // Look for an explicit `:<digits>` between the (bracketed-IPv6 or plain)
  // host and the path component of the original URL string. This preserves
  // default-port suffixes like `:443` that WHATWG URL strips away.
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/?#@]*@)?(?:\[[^\]]*\]|[^/:?#]+)(?::([0-9]+))?(?:[/?#]|$)/.exec(url);
  const explicitPort = m && m[1] ? m[1] : "";
  if (explicitPort.length > 0) {
    return `${host}_${explicitPort}`;
  }
  return host;
}

/**
 * Return the cache filename for `url` (host-safe characters only).
 * Mirrors Python `_cache_path_for_url`.
 */
export function cachePathForUrl(url: string, home?: string): string {
  const base = _relayHomeDefault(home);
  const host = hostnameForUrl(url);
  const safe = host.replace(HOST_FILENAME_SAFE_RE, "_");
  return join(base, JWKS_CACHE_DIRNAME, `${safe}.json`);
}

/**
 * Load the cached JWKS envelope for `url`. Returns `{jwks, ageSeconds}`
 * on cache hit, `null` for any failure path (missing file, bad JSON,
 * schema mismatch, expired). Mirrors Python `load_cached_jwks` exactly.
 */
export function loadCachedJwks(
  url: string,
  options?: { home?: string },
): { jwks: Record<string, unknown>; ageSeconds: number } | null {
  const path = cachePathForUrl(url, options?.home);
  if (!existsSync(path)) {
    return null;
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch {
    return null;
  }
  if (raw.length === 0) {
    return null;
  }
  let envelope: unknown;
  try {
    envelope = JSON.parse(raw);
  } catch {
    return null;
  }
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return null;
  }
  const env = envelope as Record<string, unknown>;
  if (env["schema_version"] !== JWKS_CACHE_SCHEMA_VERSION) {
    return null;
  }
  if (env["trust_anchor_url"] !== url) {
    return null;
  }
  const jwks = env["jwks"];
  if (jwks === null || typeof jwks !== "object" || Array.isArray(jwks)) {
    return null;
  }
  const jObj = jwks as Record<string, unknown>;
  if (!Array.isArray(jObj["keys"])) {
    return null;
  }
  const fetchedAt = env["fetched_at"];
  if (typeof fetchedAt !== "string" || fetchedAt.length === 0) {
    return null;
  }
  const ms = Date.parse(fetchedAt.endsWith("Z") || fetchedAt.includes("+") ? fetchedAt : `${fetchedAt}Z`);
  if (Number.isNaN(ms)) {
    return null;
  }
  const ageSeconds = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  return { jwks: jObj, ageSeconds };
}

// ----------------------------------------------------------------------------
// Trust-anchor URL precedence (flag > config > default)
// ----------------------------------------------------------------------------

export interface ResolveTrustAnchorArgs {
  flagUrl?: string | null;
  configPath?: string | null;
}

/**
 * Resolve the effective trust-anchor URL and its source label. Mirrors
 * Python `resolve_trust_anchor_url`: flag > config > default.
 *
 * Returns `[url, source_label]` where source_label is one of the
 * `TRUST_ANCHOR_SOURCE_*` constants. When the BYO config exists and
 * declares a URL the source is `byo_config`; otherwise the default URL
 * resolves with source `live_fetch` (the orchestrator downgrades to
 * `cached_jwks`/`bundled_jwks` if the live fetch fails).
 */
export function resolveTrustAnchorUrl(args: ResolveTrustAnchorArgs): [string, TrustAnchorSource] {
  const flagUrl = args.flagUrl?.trim();
  if (flagUrl && flagUrl.length > 0) {
    return [flagUrl, TRUST_ANCHOR_SOURCE_BYO_FLAG];
  }
  const configPath = args.configPath;
  if (configPath && existsSync(configPath)) {
    const configUrl = _loadConfigTrustAnchor(configPath);
    if (configUrl !== null) {
      return [configUrl, TRUST_ANCHOR_SOURCE_BYO_CONFIG];
    }
  }
  return [DEFAULT_JWKS_URL, TRUST_ANCHOR_SOURCE_LIVE];
}

function _loadConfigTrustAnchor(path: string): string | null {
  // Minimal TOML reader: look for a top-level `trust_anchor_url = "..."`
  // assignment. We avoid a full TOML dependency; the verifier config is
  // intentionally narrow (single key) and the Python equivalent uses
  // `tomllib` which lands in stdlib. A more complete TOML parser can be
  // added later if the verifier config grows.
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (exc) {
    throw new Error(`verifier config file ${path} is not readable: ${(exc as Error).message}`);
  }
  // Strip comments (everything from `#` to end of line) outside strings.
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    // Drop comments naively (acceptable for the single-key config).
    const cleaned = line.replace(/#.*$/, "").trim();
    if (cleaned.length === 0) continue;
    const m = /^trust_anchor_url\s*=\s*"([^"]*)"\s*$/.exec(cleaned);
    if (m) {
      const url = m[1];
      if (url === undefined || url.trim().length === 0) {
        throw new Error(
          `verifier config trust_anchor_url must be a non-empty string: ${path}`,
        );
      }
      // Light scheme check; mirrors Python's accept-set {https, http, file}.
      try {
        const parsed = new URL(url);
        if (!["https:", "http:", "file:"].includes(parsed.protocol)) {
          throw new Error(
            `verifier config trust_anchor_url must be an http/https/file URL: ${JSON.stringify(url)}`,
          );
        }
      } catch (exc) {
        if ((exc as Error).message.startsWith("verifier config")) {
          throw exc;
        }
        throw new Error(
          `verifier config trust_anchor_url must be an http/https/file URL: ${JSON.stringify(url)}`,
        );
      }
      return url;
    }
  }
  return null;
}

// ----------------------------------------------------------------------------
// Top-level resolver
// ----------------------------------------------------------------------------

export interface ResolveJwksArgs {
  flagUrl?: string | null;
  configPath?: string | null;
  offline?: boolean;
  fetcher?: NetworkFetcher | null;
  home?: string | null;
  emitWarning?: boolean;
}

/**
 * Resolve a trust-anchor JWKS dict from the most appropriate source.
 * Synchronous wrapper around an optionally-async fetcher: when the
 * fetcher returns a Promise, `resolveJwks` becomes async. Callers that
 * pass no fetcher get a synchronous result.
 */
export async function resolveJwks(args: ResolveJwksArgs = {}): Promise<JWKSLoadResult> {
  const warnings: Array<Record<string, unknown>> = [];
  const [url, sourceKind] = resolveTrustAnchorUrl({
    flagUrl: args.flagUrl ?? null,
    configPath: args.configPath ?? null,
  });

  if (sourceKind === TRUST_ANCHOR_SOURCE_BYO_FLAG) {
    const warn: Record<string, unknown> = {
      schema_version: "relay.verifier.warning.v1",
      code: "RELAY-VERIFY-BYO-FLAG",
      level: "warn",
      trust_anchor: url,
      default_trust_anchor: DEFAULT_JWKS_URL,
      message:
        "trust anchor overridden via --trust-anchor flag; the " +
        "spec-pinned default is the compiled-in URL",
    };
    warnings.push(warn);
    if (args.emitWarning ?? true) {
      _emitStderrWarning(warn);
    }
  }

  if (args.offline === true) {
    return {
      jwks: loadBundledJwks(),
      source: TRUST_ANCHOR_SOURCE_BUNDLED,
      trust_anchor_url: url,
      warnings,
    };
  }

  if (
    sourceKind === TRUST_ANCHOR_SOURCE_BYO_FLAG ||
    sourceKind === TRUST_ANCHOR_SOURCE_BYO_CONFIG
  ) {
    if (args.fetcher === null || args.fetcher === undefined) {
      throw new Error(
        `BYO trust anchor ${JSON.stringify(url)} requires a fetcher; pass offline=true for bundled-only mode`,
      );
    }
    let jwks: Record<string, unknown>;
    try {
      jwks = await args.fetcher(url);
    } catch (exc) {
      throw new Error(`BYO trust anchor fetch failed for ${JSON.stringify(url)}: ${(exc as Error).message}`);
    }
    if (jwks === null || typeof jwks !== "object" || !Array.isArray((jwks as Record<string, unknown>)["keys"])) {
      throw new Error(`BYO trust anchor returned malformed JWKS for ${JSON.stringify(url)}`);
    }
    return { jwks, source: sourceKind, trust_anchor_url: url, warnings };
  }

  // Default: live -> cache -> bundled -> fail.
  if (args.fetcher !== null && args.fetcher !== undefined) {
    try {
      const jwks = await args.fetcher(url);
      if (jwks !== null && typeof jwks === "object" && Array.isArray((jwks as Record<string, unknown>)["keys"])) {
        return {
          jwks: jwks as Record<string, unknown>,
          source: TRUST_ANCHOR_SOURCE_LIVE,
          trust_anchor_url: url,
          warnings,
        };
      }
    } catch {
      // fall through to cache
    }
  }

  const cached = loadCachedJwks(url, { home: args.home ?? undefined });
  if (cached !== null) {
    if (cached.ageSeconds <= CACHE_STALENESS_THRESHOLD_SECONDS) {
      const warn: Record<string, unknown> = {
        schema_version: "relay.verifier.warning.v1",
        code: "RELAY-VERIFY-CACHE-FALLBACK",
        level: "warn",
        trust_anchor: url,
        cache_age_seconds: cached.ageSeconds,
        cache_staleness_threshold_seconds: CACHE_STALENESS_THRESHOLD_SECONDS,
        message:
          "live JWKS fetch failed; using cached JWKS within staleness budget",
      };
      warnings.push(warn);
      if (args.emitWarning ?? true) {
        _emitStderrWarning(warn);
      }
      return {
        jwks: cached.jwks,
        source: TRUST_ANCHOR_SOURCE_CACHE,
        trust_anchor_url: url,
        warnings,
      };
    }
  }

  return {
    jwks: loadBundledJwks(),
    source: TRUST_ANCHOR_SOURCE_BUNDLED,
    trust_anchor_url: url,
    warnings,
  };
}

function _emitStderrWarning(warn: Record<string, unknown>): void {
  // Single JSON line per warning, ASCII-only.
  process.stderr.write(JSON.stringify(warn) + "\n");
}
