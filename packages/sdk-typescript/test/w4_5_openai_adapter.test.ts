/**
 * W4.5 OpenAI TS adapter tests (VAL-W4-032, VAL-W4-038, VAL-W4-039,
 * VAL-W4-040).
 *
 * Tests use duck-typed stubs that mimic the OpenAI Node SDK shape; no
 * real ``openai`` package import.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { RelayAdapterUnsupportedVersionError } from "../src/errors.js";
import { SpanRecorder } from "../src/adapters/_spans.js";
import {
  assertOpenAiVersionSupported,
  scrubSecretShape,
  wrapOpenAi,
} from "../src/adapters/openai.js";

function buildOpenAiStub(args: {
  chatResponse?: unknown;
  responsesResponse?: unknown;
  chatStream?: AsyncIterable<unknown> | Iterable<unknown>;
}): { chat: { completions: { create: (a: Record<string, unknown>) => unknown } }; responses: { create: (a: Record<string, unknown>) => unknown } } {
  return {
    chat: {
      completions: {
        create: (a: Record<string, unknown>) => {
          if (a["stream"] === true) return args.chatStream;
          return args.chatResponse;
        },
      },
    },
    responses: {
      create: (_a: Record<string, unknown>) => args.responsesResponse,
    },
  };
}

describe("VAL-W4-032: OpenAI TS adapter wraps chat.completions.create and responses.create", () => {
  it("emits exactly one model_call span per chat.completions.create invocation", () => {
    const recorder = new SpanRecorder();
    const stub = buildOpenAiStub({
      chatResponse: {
        id: "chatcmpl-1",
        model: "gpt-4o-mini",
        system_fingerprint: "fp_abc123",
        usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
      },
    });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.10.0" });
    wrapped.chat.completions.create({ model: "gpt-4o-mini", messages: [] });
    const modelCalls = recorder.spansByKind("model_call");
    expect(modelCalls).toHaveLength(1);
    const span = modelCalls[0]!;
    expect(span.attributes["provider"]).toBe("openai");
    expect(span.attributes["model"]).toBe("gpt-4o-mini");
    expect(span.attributes["model_signature"]).toBe("openai:gpt-4o-mini:fp_abc123");
    expect(span.attributes["input_tokens"]).toBe(10);
    expect(span.attributes["output_tokens"]).toBe(5);
    expect(span.attributes["total_tokens"]).toBe(15);
    expect(span.attributes["finish_reason"]).toBe("stop");
    expect(span.attributes["api"]).toBe("chat.completions");
  });

  it("emits exactly one model_call span per responses.create invocation", () => {
    const recorder = new SpanRecorder();
    const stub = buildOpenAiStub({
      responsesResponse: {
        id: "resp-1",
        model: "gpt-4o",
        system_fingerprint: "fp_xyz",
        usage: { input_tokens: 8, output_tokens: 4, total_tokens: 12 },
        status: "completed",
        output: [],
      },
    });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.10.0" });
    wrapped.responses.create({ model: "gpt-4o", input: "hi" });
    const modelCalls = recorder.spansByKind("model_call");
    expect(modelCalls).toHaveLength(1);
    const span = modelCalls[0]!;
    expect(span.attributes["provider"]).toBe("openai");
    expect(span.attributes["api"]).toBe("responses");
    expect(span.attributes["model_signature"]).toBe("openai:gpt-4o:fp_xyz");
    expect(span.attributes["input_tokens"]).toBe(8);
    expect(span.attributes["output_tokens"]).toBe(4);
    expect(span.attributes["finish_reason"]).toBe("completed");
  });

  it("synthesises model_signature when system_fingerprint is absent", () => {
    const recorder = new SpanRecorder();
    const stub = buildOpenAiStub({
      chatResponse: {
        model: "gpt-4o-mini",
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        choices: [],
      },
    });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.0.0" });
    wrapped.chat.completions.create({ model: "gpt-4o-mini" });
    const sig = recorder.spansByKind("model_call")[0]!.attributes["model_signature"];
    expect(typeof sig).toBe("string");
    expect(String(sig)).toMatch(/^openai:gpt-4o-mini:[0-9a-f]{16}$/);
  });

  it("emits one tool_call span per tool call in chat.completions response", () => {
    const recorder = new SpanRecorder();
    const stub = buildOpenAiStub({
      chatResponse: {
        model: "gpt-4o",
        usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        choices: [
          {
            message: {
              tool_calls: [
                {
                  function: {
                    name: "search",
                    arguments: JSON.stringify({ query: "relay docs" }),
                  },
                },
                {
                  function: {
                    name: "lookup",
                    arguments: JSON.stringify({ id: 42 }),
                  },
                },
              ],
            },
            finish_reason: "tool_calls",
          },
        ],
      },
    });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.0.0" });
    wrapped.chat.completions.create({ model: "gpt-4o" });
    expect(recorder.spansByKind("tool_call")).toHaveLength(2);
    const toolNames = recorder.spansByKind("tool_call").map((s) => s.attributes["tool_name"]);
    expect(toolNames).toEqual(["search", "lookup"]);
  });
});

describe("VAL-W4-039: tool-call streaming chunks aggregate into one tool_call span", () => {
  it("aggregates streaming tool_call deltas into one span per logical invocation", async () => {
    const recorder = new SpanRecorder();
    // Construct a streaming response: two chunks for tool_call index 0,
    // one chunk for tool_call index 1, then final finish_reason chunk.
    async function* fakeStream(): AsyncGenerator<unknown> {
      yield {
        model: "gpt-4o",
        choices: [
          {
            delta: {
              tool_calls: [
                { index: 0, id: "call_a", function: { name: "search", arguments: '{"q":"a' } },
              ],
            },
          },
        ],
      };
      yield {
        model: "gpt-4o",
        choices: [
          {
            delta: {
              tool_calls: [
                { index: 0, function: { arguments: 'b"}' } },
              ],
            },
          },
        ],
      };
      yield {
        model: "gpt-4o",
        choices: [
          {
            delta: {
              tool_calls: [
                { index: 1, id: "call_b", function: { name: "lookup", arguments: '{"id":7}' } },
              ],
            },
          },
        ],
      };
      yield {
        model: "gpt-4o",
        system_fingerprint: "fp_stream",
        choices: [{ delta: {}, finish_reason: "tool_calls" }],
      };
    }
    const stub = buildOpenAiStub({ chatStream: fakeStream() });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.0.0" });
    const stream = wrapped.chat.completions.create({ model: "gpt-4o", stream: true }) as AsyncIterable<unknown>;
    const collected: unknown[] = [];
    for await (const chunk of stream) {
      collected.push(chunk);
    }
    // EXACTLY ONE model_call span (no per-chunk spans, no per-tool spans for chunks).
    expect(recorder.spansByKind("model_call")).toHaveLength(1);
    expect(recorder.spansByKind("stream_chunk")).toHaveLength(0);
    // Two distinct tool_calls aggregated, ONE span each.
    const toolCalls = recorder.spansByKind("tool_call");
    expect(toolCalls).toHaveLength(2);
    expect(toolCalls.map((s) => s.attributes["tool_name"]).sort()).toEqual(["lookup", "search"]);
    // Aggregator stitched the search args across two chunks.
    const search = toolCalls.find((s) => s.attributes["tool_name"] === "search");
    expect(search?.attributes["args_redacted"]).toEqual({ q: "ab" });
    // model_signature picked up the streamed system_fingerprint.
    expect(recorder.spansByKind("model_call")[0]!.attributes["model_signature"]).toBe(
      "openai:gpt-4o:fp_stream",
    );
    expect(collected.length).toBe(4);
  });
});

describe("VAL-W4-038: adapter routes tool args through the redaction engine (boundary scrub)", () => {
  it("masks api_key-like keys in tool arguments", () => {
    const recorder = new SpanRecorder();
    const stub = buildOpenAiStub({
      chatResponse: {
        model: "gpt-4o",
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        choices: [
          {
            message: {
              tool_calls: [
                {
                  function: {
                    name: "deploy",
                    arguments: JSON.stringify({ api_key: "sk-secret-AAAAAAAAAAAA", env: "prod" }),
                  },
                },
              ],
            },
            finish_reason: "tool_calls",
          },
        ],
      },
    });
    const wrapped = wrapOpenAi(stub, { recorder, sdkVersion: "openai@5.0.0" });
    wrapped.chat.completions.create({ model: "gpt-4o" });
    const tc = recorder.spansByKind("tool_call")[0]!;
    const argsRedacted = tc.attributes["args_redacted"] as Record<string, unknown>;
    expect(argsRedacted["api_key"]).toBe("[REDACTED]");
    expect(argsRedacted["env"]).toBe("prod");
    // adversarial: outbound serialised args MUST NOT contain the seed.
    const seedSerialized = JSON.stringify(tc.attributes);
    expect(seedSerialized).not.toContain("sk-secret-AAAAAAAAAAAA");
  });

  it("scrubSecretShape masks bare sk- prefixed strings", () => {
    expect(scrubSecretShape("sk-AAAAAAAAAAAA")).toBe("[REDACTED]");
    expect(scrubSecretShape("sk-ant-AAAAAAAAA")).toBe("[REDACTED]");
    expect(scrubSecretShape("regular text")).toBe("regular text");
  });

  // VAL-REDACT-008: high-risk credential key names beyond the original
  // exact-match set must also be scrubbed. Reproducing trigger: tool-call
  // arguments carrying HTTP/OAuth credential headers were recorded verbatim
  // because the key name was not equal to one of the original 8 hints.
  it("scrubSecretShape masks common credential key names (VAL-REDACT-008)", () => {
    const scrubbed = scrubSecretShape({
      authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload",
      auth: "Basic dXNlcjpwYXNz",
      bearer: "eyJabc",
      access_token: "ya29.A0ARrdaM-real-token",
      refresh_token: "1//refresh-token-value",
      session_token: "FQoGZXIvYXdzED",
      client_secret: "GOCSPX-client-secret",
      cookie: "session=abc123; csrf=def456",
      "set-cookie": "session=abc123; HttpOnly",
      private_key: "pk-test-REDACTME-0123456789",
      // benign keys that MUST NOT be scrubbed (no false positives)
      city: "Paris",
      token_count: 42,
      authorized_user: "alice",
      bearings: "north",
    }) as Record<string, unknown>;
    expect(scrubbed["authorization"]).toBe("[REDACTED]");
    expect(scrubbed["auth"]).toBe("[REDACTED]");
    expect(scrubbed["bearer"]).toBe("[REDACTED]");
    expect(scrubbed["access_token"]).toBe("[REDACTED]");
    expect(scrubbed["refresh_token"]).toBe("[REDACTED]");
    expect(scrubbed["session_token"]).toBe("[REDACTED]");
    expect(scrubbed["client_secret"]).toBe("[REDACTED]");
    expect(scrubbed["cookie"]).toBe("[REDACTED]");
    expect(scrubbed["set-cookie"]).toBe("[REDACTED]");
    expect(scrubbed["private_key"]).toBe("[REDACTED]");
    // no false positives on benign keys
    expect(scrubbed["city"]).toBe("Paris");
    expect(scrubbed["token_count"]).toBe(42);
    expect(scrubbed["authorized_user"]).toBe("alice");
    expect(scrubbed["bearings"]).toBe("north");
  });

  it("scrubSecretShape suffix rules cover *_token / *-token and *_secret / *-secret (VAL-REDACT-008)", () => {
    const scrubbed = scrubSecretShape({
      id_token: "eyJid",
      "x-csrf-token": "csrf-value",
      api_secret: "secret-value",
      "app-secret": "another-secret",
      // benign: substring 'token' / 'secret' inside a non-suffix position
      token_count: 7,
      secretary_name: "Bob",
    }) as Record<string, unknown>;
    expect(scrubbed["id_token"]).toBe("[REDACTED]");
    expect(scrubbed["x-csrf-token"]).toBe("[REDACTED]");
    expect(scrubbed["api_secret"]).toBe("[REDACTED]");
    expect(scrubbed["app-secret"]).toBe("[REDACTED]");
    expect(scrubbed["token_count"]).toBe(7);
    expect(scrubbed["secretary_name"]).toBe("Bob");
  });

  // VAL-REDACT-008: camelCase credential key names are common in JS/TS
  // tool-call arguments. The scrubber lowercased the key only, so
  // `accessToken` -> `accesstoken` (neither a hint-set member nor
  // `*_token`-suffixed) and was recorded verbatim -- a real leak. The
  // de-camelCase normalization rule maps `accessToken` -> `access_token`
  // before the check. Lockstep with the Python `_scrub`.
  it("scrubSecretShape masks camelCase credential key names (VAL-REDACT-008)", () => {
    const scrubbed = scrubSecretShape({
      accessToken: "ya29.A0ARrdaM-real-token",
      refreshToken: "1//refresh-token-value",
      sessionToken: "FQoGZXIvYXdzED",
      idToken: "eyJid",
      clientSecret: "GOCSPX-client-secret",
      privateKey: "pk-test-REDACTME-0123456789",
      // benign camelCase keys that MUST NOT be scrubbed (no false positives)
      tokenCount: 42,
      secretaryName: "Bob",
      authorizedUser: "alice",
      bearings: "north",
    }) as Record<string, unknown>;
    expect(scrubbed["accessToken"]).toBe("[REDACTED]");
    expect(scrubbed["refreshToken"]).toBe("[REDACTED]");
    expect(scrubbed["sessionToken"]).toBe("[REDACTED]");
    expect(scrubbed["idToken"]).toBe("[REDACTED]");
    expect(scrubbed["clientSecret"]).toBe("[REDACTED]");
    expect(scrubbed["privateKey"]).toBe("[REDACTED]");
    // no false positives on benign camelCase keys
    expect(scrubbed["tokenCount"]).toBe(42);
    expect(scrubbed["secretaryName"]).toBe("Bob");
    expect(scrubbed["authorizedUser"]).toBe("alice");
    expect(scrubbed["bearings"]).toBe("north");
  });
});

describe("VAL-W4-040: adapter init refuses out-of-range provider SDK version", () => {
  it("throws RelayAdapterUnsupportedVersionError for OpenAI v3.0.0", () => {
    const stub = buildOpenAiStub({});
    expect(() => wrapOpenAi(stub, { sdkVersion: "openai@3.0.0" })).toThrow(
      RelayAdapterUnsupportedVersionError,
    );
  });

  it("throws for OpenAI v8.0.0 (above the supported upper bound)", () => {
    const stub = buildOpenAiStub({});
    expect(() => wrapOpenAi(stub, { sdkVersion: "openai@8.0.0" })).toThrow(
      RelayAdapterUnsupportedVersionError,
    );
  });

  it("accepts OpenAI v5.x and v6.x", () => {
    const stub = buildOpenAiStub({ chatResponse: { model: "gpt-4o", usage: {}, choices: [] } });
    expect(() => wrapOpenAi(stub, { sdkVersion: "openai@5.10.0" })).not.toThrow();
    expect(() => wrapOpenAi(stub, { sdkVersion: "openai@6.0.0" })).not.toThrow();
  });

  it("error envelope carries observed_version and supported_range", () => {
    const stub = buildOpenAiStub({});
    try {
      wrapOpenAi(stub, { sdkVersion: "openai@2.0.0" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayAdapterUnsupportedVersionError);
      const envelope = (err as RelayAdapterUnsupportedVersionError).toEnvelope();
      expect(envelope.code).toBe("RELAY-SDK-ADAPTER-VERSION-UNSUPPORTED");
      const details = envelope.details as Record<string, unknown>;
      expect(details["adapter"]).toBe("openai");
      expect(details["observed_version"]).toBe("2.0.0");
      expect(typeof details["supported_range"]).toBe("string");
    }
  });

  it("assertOpenAiVersionSupported tolerates null/undefined/unknown", () => {
    expect(() => assertOpenAiVersionSupported(null)).not.toThrow();
    expect(() => assertOpenAiVersionSupported(undefined)).not.toThrow();
    expect(() => assertOpenAiVersionSupported("unknown")).not.toThrow();
    expect(() => assertOpenAiVersionSupported("")).not.toThrow();
  });
});

// Gate-2 structural REAL_DEFECT C: scrubSecretShape recursed with no cycle
// guard and no depth bound. A self-referential or pathologically deep
// tool-args object (reachable via the live, non-JSON-round-tripped call
// sites in anthropic.ts / vercel_ai.ts) caused a RangeError (stack
// overflow) that crashed inline span emission in the model-call wrap path.
// The fix fails safe: a cycle is replaced with the "[relay:cycle]" marker
// and a subtree past SCRUB_MAX_DEPTH with "[relay:elided-depth]", never
// crashing and never leaking secret values. Lockstep with the Python
// `_scrub` markers.
describe("Gate-2 C: scrubSecretShape is robust to cycles and deep nesting", () => {
  it("replaces a self-referential object with the cycle marker WITHOUT crashing", () => {
    const a: Record<string, unknown> = { token: "sk-secret-AAAAAAAAAAAA", n: 1 };
    a["self"] = a;
    const scrubbed = scrubSecretShape(a) as Record<string, unknown>;
    // The credential key is still masked.
    expect(scrubbed["token"]).toBe("[REDACTED]");
    expect(scrubbed["n"]).toBe(1);
    // The back-reference becomes a deterministic elision marker, not a
    // crash and not the live object reference.
    expect(scrubbed["self"]).toBe("[relay:cycle]");
    // Adversarial: the serialised output must not leak the seed secret.
    expect(JSON.stringify(scrubbed)).not.toContain("sk-secret-AAAAAAAAAAAA");
  });

  it("handles a cycle nested inside an array WITHOUT crashing", () => {
    const arr: unknown[] = [];
    const node: Record<string, unknown> = { items: arr, secret: "sk-deep-BBBBBBBB" };
    arr.push(node);
    const scrubbed = scrubSecretShape(node) as Record<string, unknown>;
    expect(scrubbed["secret"]).toBe("[REDACTED]");
    const items = scrubbed["items"] as unknown[];
    expect(items[0]).toBe("[relay:cycle]");
    expect(JSON.stringify(scrubbed)).not.toContain("sk-deep-BBBBBBBB");
  });

  it("elides a ~2000-deep nested object at the depth bound WITHOUT stack overflow", () => {
    // Build a 2000-deep chain of single-key objects, secret at the bottom.
    let deep: Record<string, unknown> = { token: "sk-bottom-CCCCCCCC" };
    for (let i = 0; i < 2000; i += 1) {
      deep = { child: deep };
    }
    // Base behaviour: this recursion overflows the stack -> RangeError.
    const scrubbed = scrubSecretShape(deep);
    // No crash. Output is deterministic JSON.
    const serialized = JSON.stringify(scrubbed);
    // The depth-elision marker appears (the chain is truncated past the bound).
    expect(serialized).toContain("[relay:elided-depth]");
    // The bottom secret is unreachable past the bound, so it cannot leak;
    // either way the raw value must never appear verbatim.
    expect(serialized).not.toContain("sk-bottom-CCCCCCCC");
    // Determinism: scrubbing twice yields byte-identical output.
    expect(JSON.stringify(scrubSecretShape(deep))).toBe(serialized);
  });

  it("does NOT treat sibling references to the same object as a cycle", () => {
    // A shared (but acyclic) sub-object must be scrubbed in both positions,
    // not elided as a false-positive cycle. The cycle guard tracks the
    // active recursion path, not every object ever seen.
    const shared: Record<string, unknown> = { api_key: "sk-shared-DDDDDDDD", keep: "ok" };
    const root = { left: shared, right: shared };
    const scrubbed = scrubSecretShape(root) as Record<string, unknown>;
    const left = scrubbed["left"] as Record<string, unknown>;
    const right = scrubbed["right"] as Record<string, unknown>;
    expect(left["api_key"]).toBe("[REDACTED]");
    expect(right["api_key"]).toBe("[REDACTED]");
    expect(left["keep"]).toBe("ok");
    expect(right["keep"]).toBe("ok");
    // Neither position is the cycle marker.
    expect(left["api_key"]).not.toBe("[relay:cycle]");
    expect(right["api_key"]).not.toBe("[relay:cycle]");
  });
});
