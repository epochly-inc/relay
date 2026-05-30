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

  // Cross-language parity (matches Python sdk-python relay.replay_mode
  // _is_loopback_address). The Python side uses ipaddress.ip_address(...)
  // .is_loopback which covers IPv4-mapped IPv6 and rejects non-canonical
  // dotted-quad forms. The TS classifier MUST do the same so the two SDKs
  // make identical egress decisions.
  it("isLoopbackHost accepts IPv4-mapped IPv6 loopback ::ffff:127.0.0.1", () => {
    expect(isLoopbackHost("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackHost("[::ffff:127.0.0.1]")).toBe(true);
    expect(isLoopbackHost("::FFFF:127.0.0.1")).toBe(true);
    expect(isLoopbackHost("::ffff:127.255.255.255")).toBe(true);
  });

  // VAL-PARITY-010: Node's ``new URL(...)`` (used by ``extractHost``)
  // normalizes ``::ffff:127.0.0.1`` to the hex-compressed mapped form
  // ``::ffff:7f00:1`` (high 16 bits ``7f00`` . low 16 bits ``0001``).
  // Python's ``ipaddress.ip_address`` treats the hex-compressed form as
  // the loopback IPv4 ``127.0.0.1`` (``is_loopback == True``); the TS
  // classifier MUST agree or the two SDKs make divergent egress decisions
  // for the very form Node produces.
  it("isLoopbackHost accepts hex-compressed IPv4-mapped loopback ::ffff:7f00:1 (VAL-PARITY-010)", () => {
    // ::ffff:7f00:1 == ::ffff:127.0.0.1  (7f00 -> 127.0, 0001 -> 0.1)
    expect(isLoopbackHost("::ffff:7f00:1")).toBe(true);
    expect(isLoopbackHost("[::ffff:7f00:1]")).toBe(true);
    expect(isLoopbackHost("::FFFF:7F00:1")).toBe(true);
    // ::ffff:7f00:0001 (uncompressed low group) is the same address.
    expect(isLoopbackHost("::ffff:7f00:0001")).toBe(true);
    // Full 127.0.0.0/8: ::ffff:7fff:ffff == ::ffff:127.255.255.255
    expect(isLoopbackHost("::ffff:7fff:ffff")).toBe(true);
  });

  it("isLoopbackHost rejects non-loopback hex-compressed mapped forms (VAL-PARITY-010)", () => {
    // ::ffff:808:808 == ::ffff:8.8.8.8 (Node normalizes 8.8.8.8 to this).
    expect(isLoopbackHost("::ffff:808:808")).toBe(false);
    // ::ffff:0a00:1 == ::ffff:10.0.0.1 (private, not loopback).
    expect(isLoopbackHost("::ffff:a00:1")).toBe(false);
    // Extra group: ::ffff:0:7f00:1 is NOT the ::ffff:<ipv4> mapped prefix.
    expect(isLoopbackHost("::ffff:0:7f00:1")).toBe(false);
    // High group out of the 16-bit range must not parse as loopback.
    expect(isLoopbackHost("::ffff:7f00:1:1")).toBe(false);
  });

  // End-to-end via the interceptor, reproducing the exact divergence:
  // an origin whose host is an IPv4-mapped IPv6 loopback. ``extractHost``
  // routes it through ``new URL`` which normalizes to ``[::ffff:7f00:1]``.
  // Before the fix this loopback origin is wrongly denied egress.
  it("interceptor allows IPv4-mapped IPv6 loopback origin (VAL-PARITY-010)", () => {
    const interceptor = buildEgressDenyInterceptor();
    let inner_called = 0;
    const dispatch = ((_o: { origin?: string }, _h: unknown) => {
      inner_called += 1;
      return true;
    }) as (opts: { origin?: string; path?: string; method?: string }, handler: unknown) => boolean;
    const wrapped = interceptor(dispatch);
    // new URL normalizes the host to [::ffff:7f00:1]; must still be loopback.
    const ok = wrapped({ origin: "https://[::ffff:127.0.0.1]:443", path: "/" }, {});
    expect(ok).toBe(true);
    expect(inner_called).toBe(1);
  });

  it("isLoopbackHost accepts the full 127.0.0.0/8 range", () => {
    expect(isLoopbackHost("127.0.0.0")).toBe(true);
    expect(isLoopbackHost("127.255.255.255")).toBe(true);
  });

  it("isLoopbackHost rejects non-canonical IPv4 (leading zeros, oversize)", () => {
    // Python's ipaddress.ip_address("127.0.0.001") raises ValueError; TS
    // must reject for parity.
    expect(isLoopbackHost("127.0.0.001")).toBe(false);
    expect(isLoopbackHost("127.0.0.01")).toBe(false);
    expect(isLoopbackHost("127.000.000.001")).toBe(false);
    // Octet > 255 is not a valid IPv4 octet.
    expect(isLoopbackHost("127.0.0.256")).toBe(false);
    expect(isLoopbackHost("127.300.0.1")).toBe(false);
    // Not enough or too many octets.
    expect(isLoopbackHost("127.0.0")).toBe(false);
    expect(isLoopbackHost("127.0.0.0.1")).toBe(false);
  });

  it("isLoopbackHost rejects non-loopback IPv6 addresses", () => {
    expect(isLoopbackHost("::2")).toBe(false);
    expect(isLoopbackHost("2001:db8::1")).toBe(false);
    expect(isLoopbackHost("::ffff:8.8.8.8")).toBe(false);
    expect(isLoopbackHost("0.0.0.0")).toBe(false);
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
