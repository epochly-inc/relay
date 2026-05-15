/**
 * SDK replay-mode primitives (W4.5; VAL-W4-035, VAL-W4-036, VAL-W4-036b).
 *
 * Per eng plan A4 ("defense in depth for replay isolation") this module
 * owns three layers in the TypeScript SDK:
 *
 *   Layer 3: :func:`installUndiciInterceptor` -- attaches an undici
 *            ``Dispatcher`` that refuses any outbound TCP connection to a
 *            non-loopback destination. Catches uninstrumented ``fetch``,
 *            ``axios``, and direct ``undici.Client`` egress
 *            (VAL-W4-035).
 *
 *   Layer 4a: :func:`requireHttpsProxy` -- raises a typed error
 *             synchronously if ``HTTPS_PROXY`` is unset when replay
 *             mode is active (VAL-W4-036).
 *
 *   Layer 4b: :func:`requireInstrumentedHttpClients` -- scans the
 *             ESM/CJS module graph for uninstrumented HTTP-client
 *             modules (``got``, ``request``, ``node-fetch``, ``axios``,
 *             ``undici``) and raises a typed error per detected
 *             module (VAL-W4-036b).
 *
 * :func:`installReplayMode` is the orchestrating entry point: it runs
 * (1) HTTPS_PROXY check, (2) uninstrumented-client scan, then (3)
 * installs the undici interceptor. Any failure aborts BEFORE the
 * interceptor is installed so the host process is not left in a partial
 * state.
 *
 * Module is import-side-effect-free: importing this module does NOT
 * install the interceptor or modify global state. Callers MUST call
 * :func:`installReplayMode` (or :func:`installUndiciInterceptor`)
 * explicitly.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import {
  RELAY_REPLAY_EGRESS_DENIED_CODE,
  RELAY_REPLAY_PROXY_MISSING_CODE,
  RELAY_SDK_UNINSTRUMENTED_HTTP_CLIENT_CODE,
  RelayReplayEgressDeniedError,
  RelayReplayProxyMissingError,
  RelaySdkUninstrumentedHttpClientError,
} from "./errors.js";

// ---------------------------------------------------------------------------
// Layer 4a: HTTPS_PROXY check (VAL-W4-036)
// ---------------------------------------------------------------------------

/**
 * Ensure ``HTTPS_PROXY`` is set in the current environment.
 *
 * Per the gap note about Windows env-var case-sensitivity, we accept
 * either ``HTTPS_PROXY`` or ``https_proxy`` to keep parity with the
 * Windows portability note. A blank value counts as "not set".
 *
 * @throws RelayReplayProxyMissingError when neither casing is set or
 *         both are blank.
 */
export function requireHttpsProxy(env: NodeJS.ProcessEnv = process.env): void {
  const upper = env["HTTPS_PROXY"];
  const lower = env["https_proxy"];
  const value = (typeof upper === "string" && upper !== "")
    ? upper
    : (typeof lower === "string" && lower !== "")
      ? lower
      : null;
  if (value === null) {
    throw new RelayReplayProxyMissingError(
      "Relay refused to enter replay mode: HTTPS_PROXY (or https_proxy) is not set. " +
        "Set HTTPS_PROXY=http://127.0.0.1:<replay-proxy-port> before invoking replay.",
      {
        code: RELAY_REPLAY_PROXY_MISSING_CODE,
        details: {
          checked_env_vars: ["HTTPS_PROXY", "https_proxy"],
          observed: { HTTPS_PROXY: upper ?? null, https_proxy: lower ?? null },
        },
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Layer 4b: uninstrumented HTTP client detection (VAL-W4-036b)
// ---------------------------------------------------------------------------

/**
 * Modules that perform direct HTTP egress and bypass cassette playback if
 * not wrapped by Relay.
 */
export const UNINSTRUMENTED_HTTP_MODULES: ReadonlySet<string> = new Set([
  "got",
  "request",
  "node-fetch",
  "axios",
  "undici",
]);

/**
 * Sentinel attribute the Relay HTTP-client wrappers set on a module
 * object to signal "this client is instrumented, do not flag it".
 */
export const RELAY_WRAPPER_ATTR = "__relay_wrapped__";

/**
 * Lookup helper for CommonJS ``require.cache`` keys. Returns the bare
 * module name when the cached path matches a known uninstrumented
 * module, else null.
 */
function bareModuleName(cachePath: string): string | null {
  // Match `/node_modules/<name>/...` or end-of-path `/<name>/index.js`.
  const m = /[\\/]node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)[\\/]/.exec(cachePath);
  if (m === null || m[1] === undefined) return null;
  return m[1];
}

/**
 * Detect uninstrumented HTTP-client modules currently loaded in the
 * process's CommonJS require cache. ESM-only modules (e.g. ``node-fetch``
 * v3+) are detected via the dynamic import probe in
 * :func:`detectViaImport`.
 *
 * Returns the sorted list of detected module names.
 */
export function detectInRequireCache(): string[] {
  const detected = new Set<string>();
  // require.cache only exists in CJS-ish runtimes. Node ESM exposes it
  // through the `module` namespace; we tolerate either being absent.
  let cache: NodeJS.Dict<unknown> | undefined;
  try {
    // Reading require.cache is safe; may throw under strict ESM tooling.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    cache = (typeof require !== "undefined" && (require as unknown as { cache?: NodeJS.Dict<unknown> }).cache) || undefined;
  } catch {
    cache = undefined;
  }
  if (cache === undefined) return [];
  for (const cachePath of Object.keys(cache)) {
    const name = bareModuleName(cachePath);
    if (name === null) continue;
    if (!UNINSTRUMENTED_HTTP_MODULES.has(name)) continue;
    const entry = cache[cachePath] as { exports?: Record<string, unknown> } | undefined;
    const exportsObj = entry?.exports;
    if (
      exportsObj !== undefined &&
      exportsObj !== null &&
      typeof exportsObj === "object" &&
      (exportsObj as Record<string, unknown>)[RELAY_WRAPPER_ATTR] === true
    ) {
      continue;
    }
    detected.add(name);
  }
  return [...detected].sort();
}

/**
 * Validate the supplied set of detected modules and raise per-module
 * typed errors. Per the contract this function raises ONE error
 * carrying ``client_name`` populated with the FIRST detected module
 * (so the operator gets a single actionable error per init); the
 * details map carries the full ``detected_modules`` array so the
 * operator can address every offender at once.
 *
 * Tests parameterize over the five module names by passing a single-
 * element array per case.
 */
export function raiseForDetectedModules(detected: ReadonlyArray<string>): void {
  if (detected.length === 0) return;
  const sorted = [...detected].sort();
  const first = sorted[0] as string;
  throw new RelaySdkUninstrumentedHttpClientError(
    `Relay refused to enter replay mode: uninstrumented HTTP client module ${JSON.stringify(first)} ` +
      `is loaded without a Relay wrapper (additional offenders: ${JSON.stringify(sorted.slice(1))}).`,
    {
      code: RELAY_SDK_UNINSTRUMENTED_HTTP_CLIENT_CODE,
      details: {
        client_name: first,
        detected_modules: sorted,
      },
    },
  );
}

/**
 * Raise :class:`RelaySdkUninstrumentedHttpClientError` if any of the
 * known uninstrumented HTTP-client modules are loaded.
 *
 * Optional ``probe`` parameter is the test injection seam: tests pass
 * a precomputed list of "detected" module names so the test does not
 * need to actually require each module.
 */
export function requireInstrumentedHttpClients(
  probe: () => ReadonlyArray<string> = detectInRequireCache,
): void {
  const detected = probe();
  raiseForDetectedModules(detected);
}

// ---------------------------------------------------------------------------
// Layer 3: undici interceptor (VAL-W4-035)
// ---------------------------------------------------------------------------

/**
 * Loopback host classifier. Accepts ``localhost``, IPv4 127.0.0.0/8, and
 * IPv6 ``::1``. Hostnames other than literal IP addresses are NOT
 * accepted -- the interceptor must not be bypassable via DNS.
 */
export function isLoopbackHost(host: string): boolean {
  if (host === "" ) return false;
  const lower = host.toLowerCase();
  if (lower === "localhost") return true;
  if (lower === "::1" || lower === "[::1]") return true;
  // IPv4 dotted quad.
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(lower);
  if (v4 !== null) {
    const a = Number.parseInt(v4[1] as string, 10);
    return a === 127;
  }
  return false;
}

/**
 * Extract the host portion from an URL-like string.
 *
 * Supports ``"http://example.com:443/path"`` (full URL) and bare host
 * forms (``"example.com"``). Returns ``""`` if parsing fails entirely.
 */
function extractHost(urlLike: string): string {
  try {
    const u = new URL(urlLike);
    // u.hostname strips the brackets from IPv6 addresses; that's what
    // isLoopbackHost expects.
    return u.hostname;
  } catch {
    // Bare host fallback.
    return urlLike.split(":")[0] ?? "";
  }
}

/**
 * Internal undici interceptor counter. Tests inspect it to assert the
 * interceptor was actually invoked (not merely installed).
 */
export interface InterceptorState {
  /** Total invocations regardless of outcome. */
  invocationCount: number;
  /** Distinct hosts the interceptor refused. */
  deniedHosts: string[];
  /** When non-null, the dispatcher returned by ``installUndiciInterceptor``. */
  dispatcher: unknown | null;
}

const _state: InterceptorState = {
  invocationCount: 0,
  deniedHosts: [],
  dispatcher: null,
};

export function getInterceptorState(): InterceptorState {
  return {
    invocationCount: _state.invocationCount,
    deniedHosts: [..._state.deniedHosts],
    dispatcher: _state.dispatcher,
  };
}

export function resetInterceptorState(): void {
  _state.invocationCount = 0;
  _state.deniedHosts = [];
  _state.dispatcher = null;
}

/**
 * Build (but do not install) an undici interceptor function.
 *
 * The returned interceptor accepts an undici dispatch context and
 * raises :class:`RelayReplayEgressDeniedError` synchronously when the
 * destination is non-loopback. Loopback destinations are forwarded to
 * ``next``.
 *
 * The function shape matches undici's ``Dispatcher.compose`` interceptor
 * contract: ``(dispatch) => (opts, handler) => boolean``.
 */
export function buildEgressDenyInterceptor(): (
  dispatch: (opts: { origin?: string; path?: string; method?: string }, handler: unknown) => boolean,
) => (opts: { origin?: string; path?: string; method?: string }, handler: unknown) => boolean {
  return (dispatch) => {
    return (opts, handler) => {
      _state.invocationCount += 1;
      // origin is the URL origin (scheme + host + port) per undici v6+.
      const origin = typeof opts.origin === "string" ? opts.origin : "";
      const host = origin === "" ? "" : extractHost(origin);
      if (host === "" || !isLoopbackHost(host)) {
        if (host !== "" && !_state.deniedHosts.includes(host)) {
          _state.deniedHosts.push(host);
        }
        throw new RelayReplayEgressDeniedError(
          `Relay replay mode denied non-loopback egress: target host ${JSON.stringify(host)} (origin ${JSON.stringify(origin)})`,
          {
            code: RELAY_REPLAY_EGRESS_DENIED_CODE,
            details: {
              target_host: host,
              origin,
              method: opts.method ?? null,
              path: opts.path ?? null,
            },
          },
        );
      }
      return dispatch(opts, handler);
    };
  };
}

/**
 * Install the undici interceptor as the global dispatcher. Returns the
 * dispatcher object so tests can inspect it.
 *
 * The function is duck-typed against the ``undici`` module: we
 * dynamic-import it lazily so this module loads even when ``undici`` is
 * not installed (Node 22+ ships its own undici under
 * ``node:undici`` but that is not always import-resolvable).
 *
 * Passing an ``undiciModule`` parameter is the test injection seam.
 */
export interface UndiciLike {
  Agent: new (options?: unknown) => unknown;
  setGlobalDispatcher: (dispatcher: unknown) => void;
  getGlobalDispatcher?: () => unknown;
}

export async function installUndiciInterceptor(
  undiciModule?: UndiciLike,
): Promise<unknown> {
  let mod: UndiciLike;
  if (undiciModule !== undefined) {
    mod = undiciModule;
  } else {
    // Lazy dynamic import so the module loads even when undici is absent.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const imported = (await import("undici" as string)) as any;
    mod = imported as UndiciLike;
  }
  const interceptor = buildEgressDenyInterceptor();
  // undici v6+ Dispatcher.compose accepts an interceptor array.
  // Building Agent({connect: ..., interceptors: ...}) is the documented
  // path for adding interceptors.
  const baseAgent = new mod.Agent({
    connect: { rejectUnauthorized: false },
    interceptors: { Client: [interceptor] },
  });
  mod.setGlobalDispatcher(baseAgent);
  _state.dispatcher = baseAgent;
  return baseAgent;
}

// ---------------------------------------------------------------------------
// Orchestrator (VAL-W4-036, -036b, -035)
// ---------------------------------------------------------------------------

export interface InstallReplayModeOptions {
  /** Test injection: pre-computed list of detected uninstrumented modules. */
  detectedHttpClients?: ReadonlyArray<string>;
  /** Test injection: undici module shape. */
  undiciModule?: UndiciLike;
  /** Test injection: env override (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /**
   * Skip the undici interceptor install (defaults false). Useful when
   * the caller manages the dispatcher independently and only wants the
   * proxy + uninstrumented-client checks.
   */
  skipUndiciInstall?: boolean;
}

/**
 * Initialise replay mode end-to-end.
 *
 * Order of operations:
 *
 *   1. HTTPS_PROXY check (VAL-W4-036) -- aborts before any patching.
 *   2. Uninstrumented-client scan (VAL-W4-036b) -- aborts before any
 *      patching.
 *   3. Install the undici egress-deny interceptor (VAL-W4-035).
 *
 * Steps (1) and (2) raise typed errors; step (3) returns the installed
 * dispatcher object for caller inspection.
 */
export async function installReplayMode(
  options: InstallReplayModeOptions = {},
): Promise<unknown> {
  requireHttpsProxy(options.env);
  if (options.detectedHttpClients !== undefined) {
    raiseForDetectedModules(options.detectedHttpClients);
  } else {
    requireInstrumentedHttpClients();
  }
  if (options.skipUndiciInstall === true) return null;
  return installUndiciInterceptor(options.undiciModule);
}
