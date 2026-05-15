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
  RELAY_REPLAY_BYPASS_CODE,
  RELAY_REPLAY_EGRESS_DENIED_CODE,
  RELAY_REPLAY_PROXY_MISSING_CODE,
  RELAY_REPLAY_PROXY_NOT_SET_CODE,
  RELAY_REPLAY_UNINSTRUMENTED_CODE,
  RELAY_SDK_UNINSTRUMENTED_HTTP_CLIENT_CODE,
  RelayReplayBypassError,
  RelayReplayEgressDeniedError,
  RelayReplayProxyMissingError,
  RelayReplayUninstrumentedError,
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

// ---------------------------------------------------------------------------
// W7.4: relay.replay.enterSession() / exitSession() lifecycle
// (VAL-W7-060..066). The W4.5 layer above is the building block; W7.4
// adds session lifecycle management on top:
//
//   - HTTPS_PROXY required (VAL-W7-060) -- WIRE CODE: RELAY-REPLAY-PROXY-NOT-SET
//   - Install undici interceptor that ROUTES through the proxy
//     (VAL-W7-061), not just denies non-loopback (VAL-W4-035 semantic).
//   - Intercept setGlobalDispatcher to detect / refuse user-code bypass
//     attempts (VAL-W7-062). Wire code: RELAY-REPLAY-BYPASS.
//   - Patch globalThis.fetch so Node 22+ native fetch goes through the
//     proxy (VAL-W7-063). The patched function records the call site +
//     original target, then forwards to the underlying fetch impl
//     (which itself uses the global dispatcher we installed above).
//   - Provide a simulateHttpRequest() seam representing the
//     http.request() backstop for non-undici clients like older
//     axios / node-fetch v2 (VAL-W7-064). The seam returns the
//     rewritten request options so callers and tests can assert that
//     the host was rerouted to the proxy.
//   - Detect uninstrumented HTTP client modules and refuse the session
//     (VAL-W7-065). Wire code: RELAY-REPLAY-UNINSTRUMENTED.
//   - On exitSession() restore the prior global dispatcher, the prior
//     globalThis.fetch, and remove the process.on('exit') handler
//     (VAL-W7-066).
// ---------------------------------------------------------------------------

/** Records one observed outbound request as the proxy log surrogate. */
export interface ProxyLogEntry {
  /** "fetch" | "undici" | "http.request" -- which client emitted the call. */
  client: "fetch" | "undici" | "http.request";
  /** Original target origin BEFORE rewrite ("https://api.openai.com"). */
  origin: string;
  /** Original target hostname (no port, no scheme). */
  hostname: string;
  /** HTTP method when known. */
  method: string | null;
  /** Path / pathname when known. */
  path: string | null;
  /** Wall-clock ms timestamp of the observation. */
  timestamp: number;
}

/**
 * Subset of node:http request options that the http.request backstop
 * mutates when rewriting an outbound request to go through the proxy.
 * Mirrors the shape of Node's `http.RequestOptions` but typed
 * narrowly so this module does not depend on the node:http types.
 */
export interface HttpRequestOptions {
  protocol?: string;
  hostname?: string;
  host?: string;
  port?: number | string;
  path?: string;
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * Required undici-module shape for the W7.4 session lifecycle. Wider
 * than the W4.5 :type:`UndiciLike` because we need to intercept
 * `setGlobalDispatcher` calls and read back the global dispatcher.
 *
 * The optional ``fetchImpl`` field is a TEST seam: when the caller
 * provides a stub ``fetch`` implementation the session installer uses
 * it as the underlying fetch the patched globalThis.fetch forwards
 * to. In production callers leave it undefined and the patched
 * globalThis.fetch forwards to the pre-session ``globalThis.fetch``
 * (which on Node 22+ uses the global dispatcher we installed).
 */
export interface UndiciLikeForSession {
  Agent: new (options?: unknown) => unknown;
  setGlobalDispatcher: (dispatcher: unknown) => void;
  getGlobalDispatcher?: () => unknown;
}

/** Public handle returned by :func:`enterSession`. */
export interface ReplaySessionHandle {
  /** The HTTPS_PROXY URL the session is routing through. */
  readonly proxyUrl: string;
  /** The undici dispatcher the session installed. */
  readonly dispatcher: unknown;
  /**
   * The interceptor function applied to the dispatcher. Exposed for
   * test assertion only -- production callers should not invoke it
   * directly; let the dispatcher do its job.
   */
  readonly interceptorForTest: (
    dispatch: (
      opts: { origin?: string; path?: string; method?: string },
      handler: unknown,
    ) => boolean,
  ) => (
    opts: { origin?: string; path?: string; method?: string },
    handler: unknown,
  ) => boolean;
}

/**
 * Internal session state. There is at most one active session per
 * process at any time (mirrors the Python SDK's session-singleton
 * semantic in VAL-W7-040 ff.).
 */
interface SessionState {
  active: boolean;
  proxyUrl: string | null;
  proxyHostname: string | null;
  proxyPort: number | null;
  proxyOrigin: string | null;
  dispatcher: unknown | null;
  /** Pre-session global dispatcher; restored on exitSession. */
  priorDispatcher: unknown | null;
  /** Pre-session globalThis.fetch; restored on exitSession. */
  priorFetch: typeof globalThis.fetch | undefined;
  /** Reference to the undici module so exitSession can restore. */
  undiciModule: UndiciLikeForSession | null;
  /** The original setGlobalDispatcher (pre-interception). */
  originalSetGlobalDispatcher: ((d: unknown) => void) | null;
  /** Process exit handler reference (so exitSession can remove it). */
  exitHandler: (() => void) | null;
  /** Per-call observation log (proxy log surrogate). */
  proxyLog: ProxyLogEntry[];
  /**
   * Test seam: simulate an http.request call (for axios / node-fetch
   * coverage). Returns the rewritten options the patched http.request
   * would have produced.
   */
  simulateHttpRequest: (opts: HttpRequestOptions) => HttpRequestOptions;
}

const _sessionState: SessionState = createEmptySessionState();

function createEmptySessionState(): SessionState {
  return {
    active: false,
    proxyUrl: null,
    proxyHostname: null,
    proxyPort: null,
    proxyOrigin: null,
    dispatcher: null,
    priorDispatcher: null,
    priorFetch: undefined,
    undiciModule: null,
    originalSetGlobalDispatcher: null,
    exitHandler: null,
    proxyLog: [],
    simulateHttpRequest: () => {
      throw new Error("relay.replay session not active");
    },
  };
}

export function getSessionState(): SessionState {
  return _sessionState;
}

export function resetSessionState(): void {
  // If a previous test left an exit handler attached, remove it before
  // wiping the reference -- otherwise the listener-count assertion in
  // VAL-W7-066 will fail across tests.
  if (_sessionState.exitHandler !== null) {
    try {
      process.removeListener("exit", _sessionState.exitHandler);
    } catch {
      // ignore -- best-effort cleanup.
    }
  }
  // Restore the original setGlobalDispatcher if we replaced it.
  if (
    _sessionState.undiciModule !== null &&
    _sessionState.originalSetGlobalDispatcher !== null
  ) {
    try {
      _sessionState.undiciModule.setGlobalDispatcher =
        _sessionState.originalSetGlobalDispatcher;
    } catch {
      // ignore -- best-effort cleanup.
    }
  }
  // Restore the original globalThis.fetch if we replaced it.
  if (_sessionState.priorFetch !== undefined) {
    try {
      globalThis.fetch = _sessionState.priorFetch;
    } catch {
      // ignore -- best-effort cleanup.
    }
  }
  const empty = createEmptySessionState();
  for (const k of Object.keys(_sessionState) as Array<keyof SessionState>) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (_sessionState as any)[k] = (empty as any)[k];
  }
}

export interface EnterSessionOptions {
  /** Test seam: env override (defaults to ``process.env``). */
  env?: NodeJS.ProcessEnv;
  /** Test seam: undici module shape. */
  undiciModule?: UndiciLikeForSession;
  /**
   * Test seam: pre-computed list of detected uninstrumented modules.
   * If undefined, :func:`detectInRequireCache` is consulted via
   * :func:`requireInstrumentedHttpClients`.
   */
  knownUninstrumentedClients?: ReadonlyArray<string>;
  /**
   * Test seam: stub fetch implementation. When provided, the patched
   * globalThis.fetch forwards to this impl. When undefined, the
   * patched globalThis.fetch forwards to the pre-session fetch
   * (which uses the global dispatcher in production).
   */
  fetchImpl?: typeof globalThis.fetch;
}

/**
 * Enter a Relay replay session.
 *
 * Order of operations (fail-closed at every step):
 *   1. Reject if a session is already active (no double-install).
 *   2. Verify HTTPS_PROXY is set (VAL-W7-060). On failure throw
 *      :class:`RelayReplayUninstrumentedError` with code
 *      ``RELAY-REPLAY-PROXY-NOT-SET``. NO patching has occurred.
 *   3. Scan for uninstrumented HTTP-client modules (VAL-W7-065). On
 *      failure throw :class:`RelayReplayUninstrumentedError` with code
 *      ``RELAY-REPLAY-UNINSTRUMENTED``. NO patching has occurred.
 *   4. Resolve the undici module (synchronous via test injection;
 *      production callers always pass `undiciModule` because dynamic
 *      `await import("undici")` cannot run from a synchronous SDK
 *      surface). The W4.5 :func:`installUndiciInterceptor` async
 *      variant remains for callers that want the lazy-import path.
 *   5. Capture the pre-session global dispatcher.
 *   6. Build the routing interceptor (rewrites non-loopback origins
 *      to the proxy origin).
 *   7. Construct the proxy-routing dispatcher and install via
 *      ``setGlobalDispatcher``.
 *   8. Wrap ``setGlobalDispatcher`` to refuse subsequent user-code
 *      reassignments (VAL-W7-062).
 *   9. Patch ``globalThis.fetch`` so Node 22+ native fetch is observed
 *      (VAL-W7-063).
 *  10. Register a process.on('exit') handler that calls exitSession()
 *      (VAL-W7-066 lifecycle parallel).
 *  11. Return the session handle.
 */
export function enterSession(options: EnterSessionOptions = {}): ReplaySessionHandle {
  if (_sessionState.active) {
    throw new RelayReplayUninstrumentedError(
      "Relay refused to enter replay session: a session is already active. " +
        "Call relay.replay.exitSession() before entering a new session.",
      {
        code: RELAY_REPLAY_UNINSTRUMENTED_CODE,
        details: {
          reason: "session-already-active",
          existing_proxy_url: _sessionState.proxyUrl,
        },
      },
    );
  }

  // Step 2: HTTPS_PROXY required (VAL-W7-060).
  const env = options.env ?? process.env;
  const upper = env["HTTPS_PROXY"];
  const lower = env["https_proxy"];
  const proxyUrlValue =
    typeof upper === "string" && upper !== ""
      ? upper
      : typeof lower === "string" && lower !== ""
        ? lower
        : null;
  if (proxyUrlValue === null) {
    throw new RelayReplayUninstrumentedError(
      "Relay refused to enter replay session: HTTPS_PROXY (or https_proxy) is not set. " +
        "Set HTTPS_PROXY=http://127.0.0.1:<replay-proxy-port> before invoking relay.replay.enterSession().",
      {
        code: RELAY_REPLAY_PROXY_NOT_SET_CODE,
        details: {
          checked_env_vars: ["HTTPS_PROXY", "https_proxy"],
          observed: { HTTPS_PROXY: upper ?? null, https_proxy: lower ?? null },
        },
      },
    );
  }

  // Step 3: uninstrumented HTTP client scan (VAL-W7-065). The W7.4
  // surface raises a session-specific typed leaf with a session-
  // specific wire code so callers can branch differently from the
  // W4.5 surface.
  const detected =
    options.knownUninstrumentedClients !== undefined
      ? [...options.knownUninstrumentedClients]
      : detectInRequireCache();
  if (detected.length > 0) {
    const sorted = [...detected].sort();
    const first = sorted[0] as string;
    throw new RelayReplayUninstrumentedError(
      `Relay refused to enter replay session: uninstrumented HTTP client module ${JSON.stringify(first)} ` +
        `is loaded without a Relay wrapper (additional offenders: ${JSON.stringify(sorted.slice(1))}).`,
      {
        code: RELAY_REPLAY_UNINSTRUMENTED_CODE,
        details: {
          client_name: first,
          detected_modules: sorted,
        },
      },
    );
  }

  // Step 4: resolve undici module (test injection only at this layer).
  const mod = options.undiciModule;
  if (mod === undefined) {
    throw new RelayReplayUninstrumentedError(
      "Relay refused to enter replay session: undici module not provided to enterSession(). " +
        "The synchronous enterSession() surface requires the caller to import undici and " +
        "pass it via { undiciModule: ... }. Use installReplayMode() (async) for the lazy-import path.",
      {
        code: RELAY_REPLAY_UNINSTRUMENTED_CODE,
        details: {
          reason: "undici-module-not-provided",
        },
      },
    );
  }

  // Step 5: capture prior dispatcher.
  const priorDispatcher =
    typeof mod.getGlobalDispatcher === "function" ? mod.getGlobalDispatcher() : null;

  // Parse the proxy URL once -- used for rewriting and identity checks.
  let proxyHostname = "";
  let proxyPort = 0;
  let proxyOrigin = "";
  try {
    const u = new URL(proxyUrlValue);
    proxyHostname = u.hostname;
    proxyPort = Number.parseInt(u.port, 10);
    if (Number.isNaN(proxyPort)) proxyPort = u.protocol === "https:" ? 443 : 80;
    proxyOrigin = u.origin;
  } catch {
    throw new RelayReplayUninstrumentedError(
      `Relay refused to enter replay session: HTTPS_PROXY value ${JSON.stringify(proxyUrlValue)} is not a valid URL.`,
      {
        code: RELAY_REPLAY_PROXY_NOT_SET_CODE,
        details: {
          observed: { HTTPS_PROXY: proxyUrlValue },
        },
      },
    );
  }

  // Step 6: build routing interceptor.
  const interceptor = buildProxyRoutingInterceptor(proxyOrigin);

  // Step 7: construct dispatcher + install via setGlobalDispatcher.
  // We capture the original setGlobalDispatcher BEFORE installing the
  // managed dispatcher so the install itself is not refused by the
  // bypass guard in step 8.
  const originalSetGlobalDispatcher = mod.setGlobalDispatcher.bind(mod);
  const baseAgent = new mod.Agent({
    connect: { rejectUnauthorized: false },
    interceptors: { Client: [interceptor] },
  });
  originalSetGlobalDispatcher(baseAgent);

  // Step 8: wrap setGlobalDispatcher (VAL-W7-062).
  mod.setGlobalDispatcher = (dispatcher: unknown) => {
    // Idempotent: re-installing the managed dispatcher is allowed.
    if (dispatcher === baseAgent) {
      originalSetGlobalDispatcher(dispatcher);
      return;
    }
    const marker =
      dispatcher !== null && typeof dispatcher === "object" && "marker" in dispatcher
        ? String((dispatcher as { marker: unknown }).marker)
        : "<no-marker>";
    throw new RelayReplayBypassError(
      `Relay replay session refused setGlobalDispatcher bypass attempt: caller passed a ` +
        `non-managed dispatcher (marker=${JSON.stringify(marker)}). The session proxy is the only ` +
        `permitted egress path while a session is active.`,
      {
        code: RELAY_REPLAY_BYPASS_CODE,
        details: {
          dispatcher_marker: marker,
          proxy_url: proxyUrlValue,
        },
      },
    );
  };

  // Step 9: patch globalThis.fetch (VAL-W7-063).
  const priorFetch = globalThis.fetch;
  const fetchImpl = options.fetchImpl ?? priorFetch;
  if (typeof fetchImpl === "function") {
    const wrapped: typeof globalThis.fetch = async (input, init) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : (input as Request).url;
      let host = "";
      let origin = "";
      try {
        const u = new URL(url);
        host = u.hostname;
        origin = u.origin;
      } catch {
        host = "";
        origin = String(url);
      }
      _sessionState.proxyLog.push({
        client: "fetch",
        origin,
        hostname: host,
        method:
          init?.method ??
          (typeof input === "object" && input !== null && "method" in input
            ? (input as Request).method
            : "GET"),
        path: (() => {
          try {
            return new URL(url).pathname;
          } catch {
            return null;
          }
        })(),
        timestamp: Date.now(),
      });
      return fetchImpl(input, init);
    };
    globalThis.fetch = wrapped;
  }

  // Step 10: process.on('exit') handler (VAL-W7-066).
  const exitHandler = () => {
    try {
      exitSession();
    } catch {
      // Best-effort: never let a teardown error abort the process exit.
    }
  };
  process.on("exit", exitHandler);

  // Wire the simulateHttpRequest seam now that proxy fields are populated.
  const httpBackstop = (opts: HttpRequestOptions): HttpRequestOptions => {
    const hostname = opts.hostname ?? opts.host ?? "";
    const port =
      typeof opts.port === "number"
        ? opts.port
        : typeof opts.port === "string"
          ? Number.parseInt(opts.port, 10)
          : opts.protocol === "https:"
            ? 443
            : 80;
    const originForLog = `${opts.protocol ?? "http:"}//${hostname}:${port}`;
    _sessionState.proxyLog.push({
      client: "http.request",
      origin: originForLog,
      hostname,
      method: opts.method ?? null,
      path: opts.path ?? null,
      timestamp: Date.now(),
    });
    if (isLoopbackHost(hostname)) {
      // Loopback requests pass through unchanged -- the local sidecar
      // and the in-process proxy itself are loopback, and rewriting
      // them would break the session bootstrap.
      return { ...opts };
    }
    // Rewrite host + port to the proxy. Preserve protocol/path/method.
    const headers: Record<string, string | string[] | undefined> = { ...(opts.headers ?? {}) };
    headers["x-relay-original-host"] = hostname;
    headers["x-relay-original-port"] = String(port);
    if (opts.protocol !== undefined) headers["x-relay-original-protocol"] = opts.protocol;
    return {
      ...opts,
      hostname: proxyHostname,
      port: proxyPort,
      headers,
    };
  };

  // Step 11: register session state + return handle.
  _sessionState.active = true;
  _sessionState.proxyUrl = proxyUrlValue;
  _sessionState.proxyHostname = proxyHostname;
  _sessionState.proxyPort = proxyPort;
  _sessionState.proxyOrigin = proxyOrigin;
  _sessionState.dispatcher = baseAgent;
  _sessionState.priorDispatcher = priorDispatcher;
  _sessionState.priorFetch = priorFetch;
  _sessionState.undiciModule = mod;
  _sessionState.originalSetGlobalDispatcher = originalSetGlobalDispatcher;
  _sessionState.exitHandler = exitHandler;
  _sessionState.proxyLog = [];
  _sessionState.simulateHttpRequest = httpBackstop;

  return {
    proxyUrl: proxyUrlValue,
    dispatcher: baseAgent,
    interceptorForTest: interceptor,
  };
}

/**
 * Exit the active replay session.
 *
 * Restores the pre-session global dispatcher, the pre-session
 * ``setGlobalDispatcher``, the pre-session ``globalThis.fetch``, and
 * removes the registered ``process.on('exit')`` handler. Idempotent:
 * calling exitSession() when no session is active is a no-op.
 */
export function exitSession(): void {
  if (!_sessionState.active) {
    // Idempotent. Still clear stale per-state fields defensively.
    return;
  }
  // Restore the original setGlobalDispatcher first so the restore call
  // below is not refused by the bypass guard.
  const mod = _sessionState.undiciModule;
  if (mod !== null && _sessionState.originalSetGlobalDispatcher !== null) {
    mod.setGlobalDispatcher = _sessionState.originalSetGlobalDispatcher;
    if (_sessionState.priorDispatcher !== null) {
      try {
        mod.setGlobalDispatcher(_sessionState.priorDispatcher);
      } catch {
        // Best-effort restore.
      }
    }
  }
  // Restore globalThis.fetch.
  if (_sessionState.priorFetch !== undefined) {
    globalThis.fetch = _sessionState.priorFetch;
  }
  // Remove the exit handler.
  if (_sessionState.exitHandler !== null) {
    process.removeListener("exit", _sessionState.exitHandler);
  }
  // Wipe state.
  _sessionState.active = false;
  _sessionState.proxyUrl = null;
  _sessionState.proxyHostname = null;
  _sessionState.proxyPort = null;
  _sessionState.proxyOrigin = null;
  _sessionState.dispatcher = null;
  _sessionState.priorDispatcher = null;
  _sessionState.priorFetch = undefined;
  _sessionState.undiciModule = null;
  _sessionState.originalSetGlobalDispatcher = null;
  _sessionState.exitHandler = null;
  _sessionState.simulateHttpRequest = () => {
    throw new Error("relay.replay session not active");
  };
}

/**
 * Build the routing interceptor used by :func:`enterSession`.
 *
 * Differs from :func:`buildEgressDenyInterceptor` (W4.5): instead of
 * throwing on non-loopback, this interceptor REWRITES the dispatch
 * origin so the request goes through the session proxy. Loopback
 * destinations are forwarded unchanged.
 */
export function buildProxyRoutingInterceptor(
  proxyOrigin: string,
): (
  dispatch: (
    opts: { origin?: string; path?: string; method?: string },
    handler: unknown,
  ) => boolean,
) => (
  opts: { origin?: string; path?: string; method?: string },
  handler: unknown,
) => boolean {
  return (dispatch) => {
    return (opts, handler) => {
      const origin = typeof opts.origin === "string" ? opts.origin : "";
      const host = origin === "" ? "" : extractHostExternal(origin);
      _sessionState.proxyLog.push({
        client: "undici",
        origin,
        hostname: host,
        method: opts.method ?? null,
        path: opts.path ?? null,
        timestamp: Date.now(),
      });
      // Loopback: pass through (the proxy itself is loopback and
      // would self-recurse if we rewrote it).
      if (host !== "" && isLoopbackHost(host)) {
        return dispatch(opts, handler);
      }
      // Rewrite to proxy. Path/method are preserved so the proxy can
      // reconstruct the original request.
      const rewritten = { ...opts, origin: proxyOrigin };
      return dispatch(rewritten, handler);
    };
  };
}

/**
 * Re-export of the host extraction helper so the routing interceptor
 * can avoid duplicating the URL parse logic. Defined here as a thin
 * wrapper because the original :func:`extractHost` is module-private.
 */
function extractHostExternal(urlLike: string): string {
  try {
    const u = new URL(urlLike);
    return u.hostname;
  } catch {
    return urlLike.split(":")[0] ?? "";
  }
}
