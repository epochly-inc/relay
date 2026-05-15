/**
 * W4.5 replay-mode tests (VAL-W4-035, VAL-W4-036, VAL-W4-036b).
 *
 * Covers the three layers of A4 defense-in-depth that the TS SDK owns:
 * undici interceptor (egress deny), HTTPS_PROXY check, and
 * uninstrumented-HTTP-client scan.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  RelayReplayEgressDeniedError,
  RelayReplayProxyMissingError,
  RelaySdkUninstrumentedHttpClientError,
} from "../src/errors.js";
import {
  buildEgressDenyInterceptor,
  detectInRequireCache,
  getInterceptorState,
  installReplayMode,
  installUndiciInterceptor,
  isLoopbackHost,
  raiseForDetectedModules,
  requireHttpsProxy,
  requireInstrumentedHttpClients,
  resetInterceptorState,
  UNINSTRUMENTED_HTTP_MODULES,
} from "../src/replay_mode.js";

beforeEach(() => {
  resetInterceptorState();
});

afterEach(() => {
  resetInterceptorState();
});

describe("VAL-W4-036: SDK init in replay mode emits structured ERROR on missing HTTPS_PROXY", () => {
  it("throws RelayReplayProxyMissingError when HTTPS_PROXY is unset", () => {
    expect(() => requireHttpsProxy({})).toThrow(RelayReplayProxyMissingError);
  });

  it("throws when HTTPS_PROXY is the empty string", () => {
    expect(() => requireHttpsProxy({ HTTPS_PROXY: "" })).toThrow(
      RelayReplayProxyMissingError,
    );
  });

  it("accepts uppercase HTTPS_PROXY", () => {
    expect(() => requireHttpsProxy({ HTTPS_PROXY: "http://127.0.0.1:8080" })).not.toThrow();
  });

  it("accepts lowercase https_proxy (Windows portability)", () => {
    expect(() => requireHttpsProxy({ https_proxy: "http://127.0.0.1:8080" })).not.toThrow();
  });

  it("error envelope carries the structured code and observed values", () => {
    try {
      requireHttpsProxy({});
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayReplayProxyMissingError);
      const envelope = (err as RelayReplayProxyMissingError).toEnvelope();
      expect(envelope.code).toBe("RELAY-REPLAY-PROXY-MISSING");
      const details = envelope.details as Record<string, unknown>;
      expect(details["checked_env_vars"]).toEqual(["HTTPS_PROXY", "https_proxy"]);
    }
  });
});

describe("VAL-W4-036b: SDK init in REPLAY mode emits structured ERROR on uninstrumented HTTP client patterns", () => {
  it.each([...UNINSTRUMENTED_HTTP_MODULES])(
    "throws RelaySdkUninstrumentedHttpClientError for %s",
    (clientName) => {
      try {
        raiseForDetectedModules([clientName]);
        throw new Error("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(RelaySdkUninstrumentedHttpClientError);
        const envelope = (err as RelaySdkUninstrumentedHttpClientError).toEnvelope();
        expect(envelope.code).toBe("RELAY-SDK-UNINSTRUMENTED-HTTP-CLIENT");
        const details = envelope.details as Record<string, unknown>;
        expect(details["client_name"]).toBe(clientName);
        expect(Array.isArray(details["detected_modules"])).toBe(true);
      }
    },
  );

  it("does not throw when the detected list is empty", () => {
    expect(() => raiseForDetectedModules([])).not.toThrow();
  });

  it("requireInstrumentedHttpClients with an empty probe is a no-op", () => {
    expect(() => requireInstrumentedHttpClients(() => [])).not.toThrow();
  });

  it("requireInstrumentedHttpClients with a probed offender throws", () => {
    expect(() => requireInstrumentedHttpClients(() => ["axios"])).toThrow(
      RelaySdkUninstrumentedHttpClientError,
    );
  });

  it("detectInRequireCache returns an array (smoke test)", () => {
    // We can't deterministically populate require.cache from inside vitest
    // ESM, but the function MUST return a sorted array (possibly empty).
    const result = detectInRequireCache();
    expect(Array.isArray(result)).toBe(true);
  });

  it("class hierarchy: RelaySdkUninstrumentedHttpClientError is a RelaySdkError subclass", async () => {
    const { RelaySdkError } = await import("../src/errors.js");
    try {
      raiseForDetectedModules(["got"]);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelaySdkUninstrumentedHttpClientError);
      expect(err).toBeInstanceOf(RelaySdkError);
    }
  });
});

describe("VAL-W4-035: undici interceptor catches non-loopback egress", () => {
  it("isLoopbackHost recognises 127.0.0.1, ::1, localhost", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("127.99.0.1")).toBe(true);
    expect(isLoopbackHost("localhost")).toBe(true);
    expect(isLoopbackHost("::1")).toBe(true);
    expect(isLoopbackHost("[::1]")).toBe(true);
  });

  it("isLoopbackHost rejects example.com, 10.0.0.1, empty string", () => {
    expect(isLoopbackHost("example.com")).toBe(false);
    expect(isLoopbackHost("10.0.0.1")).toBe(false);
    expect(isLoopbackHost("")).toBe(false);
    expect(isLoopbackHost("8.8.8.8")).toBe(false);
  });

  it("interceptor throws RelayReplayEgressDeniedError on non-loopback origin", () => {
    const interceptor = buildEgressDenyInterceptor();
    const dispatch = (() => true) as (
      opts: { origin?: string; path?: string; method?: string },
      handler: unknown,
    ) => boolean;
    const wrapped = interceptor(dispatch);
    expect(() => wrapped({ origin: "https://example.com", path: "/", method: "GET" }, {})).toThrow(
      RelayReplayEgressDeniedError,
    );
    const state = getInterceptorState();
    expect(state.invocationCount).toBe(1);
    expect(state.deniedHosts).toContain("example.com");
  });

  it("interceptor allows loopback egress through to the inner dispatch", () => {
    const interceptor = buildEgressDenyInterceptor();
    let inner_called = 0;
    const dispatch = ((_o: { origin?: string }, _h: unknown) => {
      inner_called += 1;
      return true;
    }) as (opts: { origin?: string; path?: string; method?: string }, handler: unknown) => boolean;
    const wrapped = interceptor(dispatch);
    const ok = wrapped({ origin: "http://127.0.0.1:8080", path: "/" }, {});
    expect(ok).toBe(true);
    expect(inner_called).toBe(1);
  });

  it("interceptor counts each invocation, not each refusal", () => {
    const interceptor = buildEgressDenyInterceptor();
    const dispatch = ((_o: { origin?: string }, _h: unknown) => true) as (
      opts: { origin?: string; path?: string; method?: string },
      handler: unknown,
    ) => boolean;
    const wrapped = interceptor(dispatch);
    // 3 attempts: 2 to non-loopback hosts (throw), 1 to loopback (succeed).
    expect(() => wrapped({ origin: "https://example.com" }, {})).toThrow();
    expect(() => wrapped({ origin: "https://api.openai.com" }, {})).toThrow();
    wrapped({ origin: "http://127.0.0.1:9000" }, {});
    const state = getInterceptorState();
    expect(state.invocationCount).toBe(3);
    expect(state.deniedHosts.sort()).toEqual(["api.openai.com", "example.com"]);
  });

  it("error envelope carries target_host and origin", () => {
    const interceptor = buildEgressDenyInterceptor();
    const dispatch = (() => true) as (
      opts: { origin?: string; path?: string; method?: string },
      handler: unknown,
    ) => boolean;
    const wrapped = interceptor(dispatch);
    try {
      wrapped({ origin: "https://example.com", path: "/api", method: "POST" }, {});
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayReplayEgressDeniedError);
      const envelope = (err as RelayReplayEgressDeniedError).toEnvelope();
      expect(envelope.code).toBe("RELAY-REPLAY-EGRESS-DENIED");
      const details = envelope.details as Record<string, unknown>;
      expect(details["target_host"]).toBe("example.com");
      expect(details["origin"]).toBe("https://example.com");
      expect(details["method"]).toBe("POST");
      expect(details["path"]).toBe("/api");
    }
  });
});

describe("VAL-W4-035 + -036 + -036b: installReplayMode orchestrates all three checks", () => {
  it("aborts at HTTPS_PROXY check before patching", async () => {
    let installed = false;
    const fakeUndici = {
      Agent: class {
        constructor(_opts?: unknown) {}
      },
      setGlobalDispatcher: (_d: unknown) => {
        installed = true;
      },
    };
    await expect(
      installReplayMode({
        env: {},
        detectedHttpClients: [],
        undiciModule: fakeUndici,
      }),
    ).rejects.toThrow(RelayReplayProxyMissingError);
    expect(installed).toBe(false);
  });

  it("aborts at uninstrumented-client scan when proxy is set but client is loaded", async () => {
    let installed = false;
    const fakeUndici = {
      Agent: class {
        constructor(_opts?: unknown) {}
      },
      setGlobalDispatcher: (_d: unknown) => {
        installed = true;
      },
    };
    await expect(
      installReplayMode({
        env: { HTTPS_PROXY: "http://127.0.0.1:8080" },
        detectedHttpClients: ["axios"],
        undiciModule: fakeUndici,
      }),
    ).rejects.toThrow(RelaySdkUninstrumentedHttpClientError);
    expect(installed).toBe(false);
  });

  it("installs the undici dispatcher when both checks pass", async () => {
    let installed = false;
    const fakeUndici = {
      Agent: class {
        public marker = "fake-agent";
        constructor(_opts?: unknown) {}
      },
      setGlobalDispatcher: (d: unknown) => {
        installed = true;
        // dispatcher must be the agent we constructed
        expect((d as { marker?: string }).marker).toBe("fake-agent");
      },
    };
    const out = await installReplayMode({
      env: { HTTPS_PROXY: "http://127.0.0.1:8080" },
      detectedHttpClients: [],
      undiciModule: fakeUndici,
    });
    expect(installed).toBe(true);
    expect((out as { marker?: string }).marker).toBe("fake-agent");
    expect(getInterceptorState().dispatcher).not.toBeNull();
  });

  it("respects skipUndiciInstall: returns null without patching", async () => {
    let installed = false;
    const fakeUndici = {
      Agent: class {
        constructor(_opts?: unknown) {}
      },
      setGlobalDispatcher: (_d: unknown) => {
        installed = true;
      },
    };
    const out = await installReplayMode({
      env: { HTTPS_PROXY: "http://127.0.0.1:8080" },
      detectedHttpClients: [],
      undiciModule: fakeUndici,
      skipUndiciInstall: true,
    });
    expect(installed).toBe(false);
    expect(out).toBeNull();
  });

  it("installUndiciInterceptor returns the agent and registers state.dispatcher", async () => {
    const fakeUndici = {
      Agent: class {
        public marker = "x";
        constructor(_opts?: unknown) {}
      },
      setGlobalDispatcher: (_d: unknown) => {},
    };
    const agent = await installUndiciInterceptor(fakeUndici);
    expect((agent as { marker?: string }).marker).toBe("x");
    expect(getInterceptorState().dispatcher).toBe(agent);
  });
});
