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
import { RELAY_VERIFY_CONFIG_INVALID, RelayVerifierError } from "./errors.js";

// ----------------------------------------------------------------------------
// UTS-39 confusables guard for trust_anchor URLs (VAL-V3M5-009 / VAL-PARITY-005)
// ----------------------------------------------------------------------------
//
// Token-for-token port of the Python guard in
// packages/verifier/src/relay_verifier/jwks_loader.py (`_CONFUSABLES_MAP`,
// `_script_of`, `_ascii_skeleton`, `check_host_confusable`,
// `_enforce_trust_anchor_homograph_guard`). The default trust_anchor URL is
// `DEFAULT_JWKS_URL`; an attacker who substitutes a homograph (visually
// identical) hostname for the canonical ASCII host bypasses the spec-pinned
// anchor without the operator noticing. Spec section AI line 5659 calls for a
// UTS-39 confusables guard. We implement the relevant subset against built-in
// `String.prototype.normalize("NFKC")`:
//
//   1. The candidate host is NFKC-normalized.
//   2. Pure-ASCII candidates (post-NFKC) pass: equal to the canonical host or a
//      deliberately-chosen different ASCII host (the BYO escape hatch).
//   3. Candidates containing any non-ASCII codepoint are folded to an ASCII
//      "skeleton" via the curated confusables map below. If the skeleton
//      equals the canonical host, the candidate is a homograph and is rejected
//      with reason `confusable`. If the skeleton still contains non-ASCII
//      codepoints after folding, the candidate is rejected with reason
//      `non_ascii`.
//   4. Mixed-script labels (a single DNS label mixing ASCII letters with a
//      non-Common foreign script after NFKC) are rejected with reason
//      `mixed_script` before the skeleton comparison so mixed-script attacks
//      against UNRELATED canonical hosts still surface a structured rejection.
//
// This is a hand-rolled UTS-39 subset, not the full Unicode confusables table;
// it MUST stay byte-for-byte equivalent to the Python map so Python<->TS agree
// on accept/reject for every documented attack variant.
//
// Non-ASCII map keys are written via `String.fromCodePoint(0x....)` so this
// source file stays pure ASCII per CLAUDE.md "ASCII-Safe Source".

// Curated UTS-39 confusables to ASCII skeleton; mirrors Python
// `_CONFUSABLES_MAP`. The hex codepoint and Unicode name appear inline.
const CONFUSABLES_MAP: Readonly<Record<string, string>> = {
  // Cyrillic small letters (most-targeted: e, a, o, p, c, x, y, i)
  [String.fromCodePoint(0x0430)]: "a", // CYRILLIC SMALL LETTER A
  [String.fromCodePoint(0x0435)]: "e", // CYRILLIC SMALL LETTER IE
  [String.fromCodePoint(0x043e)]: "o", // CYRILLIC SMALL LETTER O
  [String.fromCodePoint(0x0440)]: "p", // CYRILLIC SMALL LETTER ER
  [String.fromCodePoint(0x0441)]: "c", // CYRILLIC SMALL LETTER ES
  [String.fromCodePoint(0x0445)]: "x", // CYRILLIC SMALL LETTER HA
  [String.fromCodePoint(0x0443)]: "y", // CYRILLIC SMALL LETTER U
  [String.fromCodePoint(0x0456)]: "i", // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
  [String.fromCodePoint(0x0458)]: "j", // CYRILLIC SMALL LETTER JE
  [String.fromCodePoint(0x04bb)]: "h", // CYRILLIC SMALL LETTER SHHA
  // Greek small letters (omicron, rho, kappa, nu, alpha, iota look-alikes)
  [String.fromCodePoint(0x03bf)]: "o", // GREEK SMALL LETTER OMICRON
  [String.fromCodePoint(0x03c1)]: "p", // GREEK SMALL LETTER RHO
  [String.fromCodePoint(0x03ba)]: "k", // GREEK SMALL LETTER KAPPA
  [String.fromCodePoint(0x03bd)]: "v", // GREEK SMALL LETTER NU (visually similar to v)
  [String.fromCodePoint(0x03b1)]: "a", // GREEK SMALL LETTER ALPHA
  [String.fromCodePoint(0x03b9)]: "i", // GREEK SMALL LETTER IOTA (close to i)
  // Armenian small letters that visually echo ASCII
  [String.fromCodePoint(0x0585)]: "o", // ARMENIAN SMALL LETTER OH
  [String.fromCodePoint(0x0578)]: "n", // ARMENIAN SMALL LETTER VO -- visual approximation
  [String.fromCodePoint(0x0570)]: "h", // ARMENIAN SMALL LETTER HO
  [String.fromCodePoint(0x0566)]: "q", // ARMENIAN SMALL LETTER ZA (visual)
};

/**
 * Return a coarse script bucket for a single character; mirrors Python
 * `_script_of`. Buckets: `ascii` for ASCII letters/digits/hyphen,
 * `cyrillic`, `greek`, `armenian`, `fullwidth`, `math`, `common` for
 * punctuation/shared, `other` for anything else.
 */
function _scriptOf(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp < 0x80) {
    // ASCII alphanumeric or hyphen -> `ascii`; other ASCII -> `common`.
    if (/[A-Za-z0-9]/.test(ch) || ch === "-") {
      return "ascii";
    }
    return "common";
  }
  if (cp >= 0x0400 && cp <= 0x04ff) return "cyrillic";
  if (cp >= 0x0370 && cp <= 0x03ff) return "greek";
  if (cp >= 0x0530 && cp <= 0x058f) return "armenian";
  if (cp >= 0xff00 && cp <= 0xffef) return "fullwidth";
  if (cp >= 0x1d400 && cp <= 0x1d7ff) return "math";
  return "other";
}

/**
 * Return the ASCII confusables skeleton of `host`; mirrors Python
 * `_ascii_skeleton`. Applies NFKC normalization (folds Halfwidth/Fullwidth
 * Forms and Mathematical Alphanumeric Symbols to ASCII), then substitutes
 * every codepoint in `CONFUSABLES_MAP` with its ASCII partner. The output may
 * still contain non-ASCII codepoints, which the caller treats as `non_ascii`.
 */
function _asciiSkeleton(host: string): string {
  const nfkc = host.normalize("NFKC");
  // Iterate by code point (surrogate-safe) to mirror Python's per-codepoint map.
  let out = "";
  for (const ch of nfkc) {
    out += CONFUSABLES_MAP[ch] ?? ch;
  }
  return out;
}

function _isPureAscii(s: string): boolean {
  for (const ch of s) {
    if ((ch.codePointAt(0) ?? 0) >= 0x80) {
      return false;
    }
  }
  return true;
}

/**
 * Reject `host` if it is a UTS-39 confusable of `canonicalHost`. Mirrors
 * Python `check_host_confusable` exactly.
 *
 * Pure-ASCII candidates pass unconditionally (operators may BYO an unrelated
 * ASCII host on purpose). Any non-ASCII candidate is folded to its ASCII
 * skeleton via NFKC + the curated confusables map; if the skeleton equals the
 * canonical host (case-insensitive) the candidate is rejected with reason
 * `confusable`. A mixed-script label is rejected with reason `mixed_script`
 * before the skeleton check. A candidate whose skeleton still contains
 * non-ASCII codepoints after folding is rejected with reason `non_ascii`.
 *
 * @throws RelayVerifierError code RELAY-VERIFY-003 when the host is a
 *   confusable, a mixed-script label, or contains residual non-ASCII content.
 */
export function checkHostConfusable(host: string, canonicalHost: string): void {
  if (!host) {
    return;
  }
  const canonicalLower = canonicalHost.toLowerCase();

  // Pure-ASCII candidates: legitimate BYO or canonical. Either way they
  // cannot be a homograph of the canonical ASCII anchor.
  if (_isPureAscii(host)) {
    return;
  }

  // Per-label mixed-script detection. A label mixing ASCII letters with a
  // single non-Common foreign script is the canonical mixed-script attack;
  // reject before skeleton folding so the reason code attributes correctly
  // even against UNRELATED canonical hosts.
  for (const label of host.split(".")) {
    const scripts = new Set<string>();
    for (const ch of label) {
      const s = _scriptOf(ch);
      if (s === "ascii" || s === "common") {
        continue;
      }
      scripts.add(s);
    }
    let hasAscii = false;
    for (const ch of label) {
      if (_scriptOf(ch) === "ascii") {
        hasAscii = true;
        break;
      }
    }
    if (scripts.size >= 1 && hasAscii) {
      // ASCII letters mixed with foreign-script letters in one label --
      // canonical mixed-script attack. Fall through to the skeleton check
      // first; if it folds to the canonical host the rejection is more
      // specific (`confusable`).
      const skeletonLabel = _asciiSkeleton(label);
      if (_isPureAscii(skeletonLabel)) {
        // Folds cleanly to ASCII -- attribute the broader skeleton check below.
        continue;
      }
      throw new RelayVerifierError(`mixed-script label rejected: ${JSON.stringify(label)}`, {
        code: RELAY_VERIFY_CONFIG_INVALID,
        details: {
          host,
          canonical_host: canonicalHost,
          reason: "mixed_script",
          label,
          scripts: Array.from(scripts).sort(),
        },
      });
    }
  }

  const skeleton = _asciiSkeleton(host).toLowerCase();
  if (skeleton === canonicalLower) {
    throw new RelayVerifierError(
      `trust_anchor host is a UTS-39 confusable of ${JSON.stringify(canonicalHost)}: ${JSON.stringify(host)}`,
      {
        code: RELAY_VERIFY_CONFIG_INVALID,
        details: {
          host,
          canonical_host: canonicalHost,
          reason: "confusable",
          skeleton,
        },
      },
    );
  }

  if (!_isPureAscii(skeleton)) {
    throw new RelayVerifierError(
      `trust_anchor host contains non-ASCII codepoints not covered by the UTS-39 fold: ${JSON.stringify(host)}`,
      {
        code: RELAY_VERIFY_CONFIG_INVALID,
        details: {
          host,
          canonical_host: canonicalHost,
          reason: "non_ascii",
          skeleton,
        },
      },
    );
  }
}

// Authority extractor for the confusables guard. CRITICAL: we do NOT use
// `new URL(url).hostname` here -- WHATWG URL applies IDNA/punycode to IDN
// labels, so a Cyrillic homograph host like `relay.epochl<U+0443>.com` would
// be returned as the ASCII punycode form `relay.xn--epochl-1rf.com`, which the
// confusables fold treats as a benign pure-ASCII host and accepts. Python's
// `urlparse(url).hostname` preserves the raw Unicode codepoints, so the fold
// fires. To stay byte-for-byte parity with Python we parse the raw host
// substring from the URL string ourselves (same rationale as
// `hostnameForUrl` reading the explicit port from the raw string).
//
// Mirrors Python `urlparse(...).hostname` semantics: lowercases, strips the
// `userinfo@` prefix, strips a bracketed IPv6 host's brackets, strips the
// `:port` suffix.
const _RAW_AUTHORITY_RE =
  /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/?#@]*@)?(\[[^\]]*\]|[^/:?#]*)(?::[0-9]*)?(?:[/?#]|$)/;

/**
 * Extract the lowercased raw (non-punycoded) hostname component of `url` for
 * the confusables guard. Mirrors Python `_canonical_host_of`. Returns the
 * empty string for a URL with no extractable host (the downstream resolver
 * paths reject those with a more specific error; the homograph guard is a
 * no-op there).
 */
function _canonicalHostOf(url: string): string {
  const m = _RAW_AUTHORITY_RE.exec(url);
  if (m === null) {
    return "";
  }
  let host = m[1] ?? "";
  // Strip IPv6 brackets to mirror `urlparse(...).hostname`.
  if (host.startsWith("[") && host.endsWith("]")) {
    host = host.slice(1, -1);
  }
  return host.toLowerCase();
}

/**
 * Apply {@link checkHostConfusable} to the BYO trust-anchor URL. Mirrors
 * Python `_enforce_trust_anchor_homograph_guard`: compares the candidate
 * URL's host against the host of the compiled-in `DEFAULT_JWKS_URL`. Re-throws
 * with the offending URL attached under `details.trust_anchor` so the
 * CLI/verifier wrapper can surface the rejection envelope directly.
 *
 * @throws RelayVerifierError code RELAY-VERIFY-003 on rejection.
 */
function _enforceTrustAnchorHomographGuard(candidateUrl: string): void {
  const candidateHost = _canonicalHostOf(candidateUrl);
  const canonicalHost = _canonicalHostOf(DEFAULT_JWKS_URL);
  if (!candidateHost) {
    // Malformed URL -- the URL parser already returned an empty host. The
    // downstream resolver paths reject this with a more specific error; the
    // homograph guard is a no-op here.
    return;
  }
  try {
    checkHostConfusable(candidateHost, canonicalHost);
  } catch (exc) {
    if (exc instanceof RelayVerifierError) {
      const details = { ...exc.details, trust_anchor: candidateUrl };
      throw new RelayVerifierError(exc.message, { code: exc.code, details });
    }
    throw exc;
  }
}

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
    // VAL-PARITY-005 / VAL-V3M5-009: UTS-39 confusables guard on every BYO URL
    // whose host could be a homograph of the canonical default. Pure-ASCII
    // operator-chosen hosts pass; homograph hosts throw RelayVerifierError
    // (RELAY-VERIFY-003) before the resolver ever touches the network or
    // cache. Mirrors Python jwks_loader.py:657.
    _enforceTrustAnchorHomographGuard(flagUrl);
    return [flagUrl, TRUST_ANCHOR_SOURCE_BYO_FLAG];
  }
  const configPath = args.configPath;
  if (configPath && existsSync(configPath)) {
    const configUrl = _loadConfigTrustAnchor(configPath);
    if (configUrl !== null) {
      // Same homograph guard on the BYO config URL. Mirrors Python
      // jwks_loader.py:662.
      _enforceTrustAnchorHomographGuard(configUrl);
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
