/**
 * W7.4 replay-session tests (VAL-W7-060..066).
 *
 * Covers the TypeScript SDK ``relay.replay.enterSession()`` /
 * ``exitSession()`` lifecycle:
 *
 *   - VAL-W7-060: enterSession asserts HTTPS_PROXY is set; throws
 *     RelayReplayUninstrumentedError with code RELAY-REPLAY-PROXY-NOT-SET.
 *   - VAL-W7-061: enterSession installs an undici interceptor that routes
 *     ALL outbound requests through the HTTPS_PROXY URL.
 *   - VAL-W7-062: interceptor denies bypass via custom Dispatcher
 *     (intercepts setGlobalDispatcher in replay).
 *   - VAL-W7-063: interceptor covers globalThis.fetch (Node 22+ native).
 *   - VAL-W7-064: interceptor covers axios + node-fetch (third-party
 *     HTTP clients), patched via http.request / https.request fallback.
 *   - VAL-W7-065: enterSession detects an uninstrumented HTTP client
 *     library (got, request) and emits init ERROR
 *     (RelayReplayUninstrumentedError with code RELAY-REPLAY-UNINSTRUMENTED).
 *   - VAL-W7-066: exitSession uninstalls the interceptor + removes the
 *     process.on('exit') handler so subsequent non-replay code performs
 *     normal HTTP.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  RELAY_REPLAY_BYPASS_CODE,
  RELAY_REPLAY_PROXY_NOT_SET_CODE,
  RELAY_REPLAY_UNINSTRUMENTED_CODE,
  RelayReplayBypassError,
  RelayReplayError,
  RelayReplayUninstrumentedError,
} from "../src/errors.js";
import {
  enterSession,
  exitSession,
  getSessionState,
  resetSessionState,
  type ReplaySessionHandle,
  type UndiciLikeForSession,
} from "../src/replay_mode.js";

// -----------------------------------------------------------------------------
// Test helpers: a fake undici module with controllable setGlobalDispatcher.
// -----------------------------------------------------------------------------

interface FakeAgent {
  marker: string;
  composedFrom?: unknown;
}

function makeFakeUndici(): UndiciLikeForSession & {
  globalDispatcher: FakeAgent | null;
  setGlobalDispatcherCalls: Array<{ dispatcher: unknown }>;
} {
  let globalDispatcher: FakeAgent | null = null;
  const setGlobalDispatcherCalls: Array<{ dispatcher: unknown }> = [];
  return {
    Agent: class implements FakeAgent {
      marker: string;
      composedFrom?: unknown;
      constructor(opts?: unknown) {
        this.marker = "fake-agent";
        this.composedFrom = opts;
      }
    } as unknown as UndiciLikeForSession["Agent"],
    setGlobalDispatcher: function (dispatcher: unknown) {
      setGlobalDispatcherCalls.push({ dispatcher });
      globalDispatcher = dispatcher as FakeAgent;
    },
    getGlobalDispatcher: () => globalDispatcher,
    get globalDispatcher() {
      return globalDispatcher;
    },
    setGlobalDispatcherCalls,
  };
}

beforeEach(() => {
  resetSessionState();
});

afterEach(() => {
  // Best-effort teardown: tests should call exitSession themselves, but a
  // bug in the SUT must not leave global state dirty for the next test.
  try {
    if (getSessionState().active) exitSession();
  } catch {
    // ignore -- the next test resets state regardless.
  }
  resetSessionState();
});

// -----------------------------------------------------------------------------
// VAL-W7-060: enterSession asserts HTTPS_PROXY is set.
// -----------------------------------------------------------------------------

describe("VAL-W7-060: enterSession asserts HTTPS_PROXY is set", () => {
  it("throws RelayReplayUninstrumentedError synchronously when HTTPS_PROXY is unset", () => {
    expect(() =>
      enterSession({
        env: {},
        undiciModule: makeFakeUndici(),
        knownUninstrumentedClients: [],
      }),
    ).toThrow(RelayReplayUninstrumentedError);
  });

  it("error envelope carries code RELAY-REPLAY-PROXY-NOT-SET", () => {
    try {
      enterSession({
        env: {},
        undiciModule: makeFakeUndici(),
        knownUninstrumentedClients: [],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayReplayUninstrumentedError);
      expect(err).toBeInstanceOf(RelayReplayError);
      const envelope = (err as RelayReplayUninstrumentedError).toEnvelope();
      expect(envelope.code).toBe(RELAY_REPLAY_PROXY_NOT_SET_CODE);
      expect(envelope.code).toBe("RELAY-REPLAY-PROXY-NOT-SET");
      expect(envelope.error_class).toBe("RELAY-REPLAY-PROXY-NOT-SET");
      const details = envelope.details as Record<string, unknown>;
      expect(details["checked_env_vars"]).toEqual(["HTTPS_PROXY", "https_proxy"]);
    }
  });

  it("throws when HTTPS_PROXY is present but empty", () => {
    expect(() =>
      enterSession({
        env: { HTTPS_PROXY: "" },
        undiciModule: makeFakeUndici(),
        knownUninstrumentedClients: [],
      }),
    ).toThrow(RelayReplayUninstrumentedError);
  });

  it("does NOT install dispatcher when HTTPS_PROXY check fails (fail-closed)", () => {
    const fake = makeFakeUndici();
    expect(() =>
      enterSession({
        env: {},
        undiciModule: fake,
        knownUninstrumentedClients: [],
      }),
    ).toThrow(RelayReplayUninstrumentedError);
    expect(fake.setGlobalDispatcherCalls.length).toBe(0);
    expect(getSessionState().active).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-061: enterSession installs undici interceptor in replay mode.
// -----------------------------------------------------------------------------

describe("VAL-W7-061: enterSession installs undici interceptor", () => {
  let session: ReplaySessionHandle | null = null;
  afterEach(() => {
    if (session !== null) {
      exitSession();
      session = null;
    }
  });

  it("installs the dispatcher exactly once on enterSession", () => {
    const fake = makeFakeUndici();
    session = enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(fake.setGlobalDispatcherCalls.length).toBe(1);
    expect(getSessionState().active).toBe(true);
  });

  it("returns a session handle exposing the proxyUrl", () => {
    const fake = makeFakeUndici();
    session = enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(session.proxyUrl).toBe("http://127.0.0.1:9999");
  });

  it("interceptor records every dispatched origin (proxy log surrogate)", () => {
    const fake = makeFakeUndici();
    session = enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    const interceptor = session.interceptorForTest;
    const dispatch = ((_o: { origin?: string }, _h: unknown) => true) as (
      opts: { origin?: string; path?: string; method?: string },
      handler: unknown,
    ) => boolean;
    const wrapped = interceptor(dispatch);
    wrapped({ origin: "https://api.openai.com", path: "/v1/chat", method: "POST" }, {});
    wrapped({ origin: "https://api.anthropic.com", path: "/v1/messages", method: "POST" }, {});
    const log = getSessionState().proxyLog;
    expect(log.length).toBe(2);
    expect(log[0]?.origin).toBe("https://api.openai.com");
    expect(log[1]?.origin).toBe("https://api.anthropic.com");
  });

  it("interceptor rewrites non-proxy origin to route through the proxy", () => {
    const fake = makeFakeUndici();
    session = enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    const interceptor = session.interceptorForTest;
    let lastOrigin: string | undefined;
    const dispatch = ((opts: { origin?: string }, _h: unknown) => {
      lastOrigin = opts.origin;
      return true;
    }) as (opts: { origin?: string; path?: string; method?: string }, handler: unknown) => boolean;
    const wrapped = interceptor(dispatch);
    wrapped({ origin: "https://api.openai.com", path: "/v1/chat" }, {});
    // Backstop semantics: the interceptor MUST record the original target
    // and forward through the proxy. The downstream dispatch sees the
    // proxy origin so the request actually leaves on the proxy socket.
    expect(lastOrigin).toBe("http://127.0.0.1:9999");
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-062: interceptor denies bypass via custom Dispatcher.
// -----------------------------------------------------------------------------

describe("VAL-W7-062: interceptor denies bypass via custom Dispatcher", () => {
  it("intercepts setGlobalDispatcher calls inside an active session", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    // User code attempts to swap in a hostile dispatcher.
    const hostile = { marker: "hostile", composedFrom: undefined };
    expect(() => fake.setGlobalDispatcher(hostile)).toThrow(RelayReplayBypassError);
  });

  it("RelayReplayBypassError carries code RELAY-REPLAY-BYPASS and the offending dispatcher token", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    try {
      fake.setGlobalDispatcher({ marker: "hostile" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayReplayBypassError);
      const envelope = (err as RelayReplayBypassError).toEnvelope();
      expect(envelope.code).toBe(RELAY_REPLAY_BYPASS_CODE);
      const details = envelope.details as Record<string, unknown>;
      expect(typeof details["dispatcher_marker"]).toBe("string");
      expect(details["dispatcher_marker"]).toBe("hostile");
    }
  });

  it("does not throw when setGlobalDispatcher is called with the relay-managed dispatcher", () => {
    const fake = makeFakeUndici();
    const session = enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    // Re-installing the same managed dispatcher is a no-op (idempotent).
    expect(() => fake.setGlobalDispatcher(session.dispatcher)).not.toThrow();
  });

  it("after exitSession, setGlobalDispatcher works normally again (no-op interception)", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    exitSession();
    // Outside a session, user code may set whatever dispatcher it wants.
    expect(() => fake.setGlobalDispatcher({ marker: "post-exit" })).not.toThrow();
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-063: interceptor covers globalThis.fetch (Node 22+).
// -----------------------------------------------------------------------------

describe("VAL-W7-063: interceptor covers globalThis.fetch", () => {
  let originalFetch: typeof globalThis.fetch | undefined;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    if (originalFetch === undefined) {
      // @ts-expect-error -- restoring undefined when the runtime had no fetch
      delete globalThis.fetch;
    } else {
      globalThis.fetch = originalFetch;
    }
  });

  it("globalThis.fetch is a function in the Node 22+ test runtime", () => {
    expect(typeof globalThis.fetch).toBe("function");
  });

  it("enterSession patches globalThis.fetch to record the request and forward through proxy", async () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
      // Inject a stub fetch that records its arguments and never actually
      // hits the network. The session installer should preserve our
      // injected impl as the underlying implementation it forwards to.
      fetchImpl: async (input, init) => {
        return new Response(JSON.stringify({ recorded: true }), {
          status: 200,
          headers: { "content-type": "application/json", "x-recorded-by": "test-stub" },
        });
      },
    });
    const response = await globalThis.fetch("https://api.openai.com/v1/models");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ recorded: true });
    // Proxy log records the original target (not the proxy URL) so the
    // operator can audit which destinations the agent attempted to hit.
    const log = getSessionState().proxyLog;
    const fetchEntries = log.filter((e) => e.client === "fetch");
    expect(fetchEntries.length).toBe(1);
    expect(fetchEntries[0]?.origin).toBe("https://api.openai.com");
  });

  it("after exitSession, globalThis.fetch is restored to the pre-session implementation", async () => {
    const fake = makeFakeUndici();
    const sentinel = async () => new Response("sentinel", { status: 418 });
    globalThis.fetch = sentinel as typeof globalThis.fetch;
    const beforeRef = globalThis.fetch;
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
      fetchImpl: async () => new Response("during", { status: 200 }),
    });
    expect(globalThis.fetch).not.toBe(beforeRef);
    exitSession();
    expect(globalThis.fetch).toBe(beforeRef);
    const r = await globalThis.fetch("http://127.0.0.1:1/never");
    expect(r.status).toBe(418);
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-064: interceptor covers axios + node-fetch (third-party).
// -----------------------------------------------------------------------------

describe("VAL-W7-064: interceptor covers axios + node-fetch via http.request backstop", () => {
  it("enterSession patches http.request so non-fetch clients route through the proxy", async () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    // Simulate axios / node-fetch via the lower-level http.request seam
    // that the SUT exposes for testing. The seam returns the rewritten
    // request options so we can assert the host was rerouted to the proxy.
    const state = getSessionState();
    const rewritten = state.simulateHttpRequest({
      protocol: "https:",
      hostname: "api.openai.com",
      port: 443,
      path: "/v1/chat",
      method: "POST",
    });
    expect(rewritten.hostname).toBe("127.0.0.1");
    expect(rewritten.port).toBe(9999);
    // Original target is preserved so the proxy can dispatch correctly.
    expect(rewritten.headers?.["x-relay-original-host"]).toBe("api.openai.com");
  });

  it("loopback requests pass through unchanged (no rewrite)", async () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    const state = getSessionState();
    const out = state.simulateHttpRequest({
      protocol: "http:",
      hostname: "127.0.0.1",
      port: 8080,
      path: "/health",
      method: "GET",
    });
    expect(out.hostname).toBe("127.0.0.1");
    expect(out.port).toBe(8080);
  });

  it("proxyLog distinguishes axios/node-fetch traffic from globalThis.fetch traffic", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    const state = getSessionState();
    state.simulateHttpRequest({
      protocol: "https:",
      hostname: "api.example.com",
      port: 443,
      path: "/v1/x",
      method: "GET",
    });
    const log = getSessionState().proxyLog;
    const httpEntries = log.filter((e) => e.client === "http.request");
    expect(httpEntries.length).toBe(1);
    expect(httpEntries[0]?.origin).toBe("https://api.example.com:443");
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-065: detect uninstrumented HTTP client and emit init ERROR.
// -----------------------------------------------------------------------------

describe("VAL-W7-065: enterSession detects uninstrumented HTTP client and emits init ERROR", () => {
  it.each(["got", "request"])(
    "throws RelayReplayUninstrumentedError when %s is detected",
    (client) => {
      const fake = makeFakeUndici();
      try {
        enterSession({
          env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
          undiciModule: fake,
          knownUninstrumentedClients: [client],
        });
        throw new Error("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(RelayReplayUninstrumentedError);
        const envelope = (err as RelayReplayUninstrumentedError).toEnvelope();
        expect(envelope.code).toBe(RELAY_REPLAY_UNINSTRUMENTED_CODE);
        expect(envelope.code).toBe("RELAY-REPLAY-UNINSTRUMENTED");
        const details = envelope.details as Record<string, unknown>;
        expect(details["client_name"]).toBe(client);
        expect(Array.isArray(details["detected_modules"])).toBe(true);
        expect((details["detected_modules"] as string[]).includes(client)).toBe(true);
      }
    },
  );

  it("error message names every detected uninstrumented client", () => {
    const fake = makeFakeUndici();
    try {
      enterSession({
        env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
        undiciModule: fake,
        knownUninstrumentedClients: ["got", "request"],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayReplayUninstrumentedError);
      const envelope = (err as RelayReplayUninstrumentedError).toEnvelope();
      const details = envelope.details as Record<string, unknown>;
      const detected = details["detected_modules"] as string[];
      expect(detected.includes("got")).toBe(true);
      expect(detected.includes("request")).toBe(true);
    }
  });

  it("does NOT install dispatcher when uninstrumented client is detected (fail-closed)", () => {
    const fake = makeFakeUndici();
    expect(() =>
      enterSession({
        env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
        undiciModule: fake,
        knownUninstrumentedClients: ["got"],
      }),
    ).toThrow(RelayReplayUninstrumentedError);
    expect(fake.setGlobalDispatcherCalls.length).toBe(0);
    expect(getSessionState().active).toBe(false);
  });

  it("empty detected list does NOT raise (clean session entry)", () => {
    const fake = makeFakeUndici();
    expect(() =>
      enterSession({
        env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
        undiciModule: fake,
        knownUninstrumentedClients: [],
      }),
    ).not.toThrow();
    exitSession();
  });
});

// -----------------------------------------------------------------------------
// VAL-W7-066: interceptor uninstalls on session exit.
// -----------------------------------------------------------------------------

describe("VAL-W7-066: exitSession uninstalls the interceptor", () => {
  it("exitSession restores the pre-session global dispatcher", () => {
    const fake = makeFakeUndici();
    const beforeAgent = { marker: "user-original" };
    fake.setGlobalDispatcher(beforeAgent);
    const getDispatcher = fake.getGlobalDispatcher;
    expect(typeof getDispatcher).toBe("function");
    if (typeof getDispatcher !== "function") throw new Error("unreachable");
    expect(getDispatcher()).toBe(beforeAgent);
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(getDispatcher()).not.toBe(beforeAgent);
    exitSession();
    expect(getDispatcher()).toBe(beforeAgent);
  });

  it("exitSession sets session state to inactive", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(getSessionState().active).toBe(true);
    exitSession();
    expect(getSessionState().active).toBe(false);
  });

  it("exitSession removes the process.on('exit') handler", () => {
    const fake = makeFakeUndici();
    const before = process.listenerCount("exit");
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    const during = process.listenerCount("exit");
    expect(during).toBe(before + 1);
    exitSession();
    const after = process.listenerCount("exit");
    expect(after).toBe(before);
  });

  it("exitSession is idempotent (safe to call when no session is active)", () => {
    expect(() => exitSession()).not.toThrow();
    expect(getSessionState().active).toBe(false);
  });

  it("after exitSession, the registered exit-handler reference is null", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(getSessionState().exitHandler).not.toBeNull();
    exitSession();
    expect(getSessionState().exitHandler).toBeNull();
  });

  it("calling enterSession twice without exitSession is rejected (no double-install)", () => {
    const fake = makeFakeUndici();
    enterSession({
      env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
      undiciModule: fake,
      knownUninstrumentedClients: [],
    });
    expect(() =>
      enterSession({
        env: { HTTPS_PROXY: "http://127.0.0.1:9999" },
        undiciModule: fake,
        knownUninstrumentedClients: [],
      }),
    ).toThrow();
    exitSession();
  });
});
