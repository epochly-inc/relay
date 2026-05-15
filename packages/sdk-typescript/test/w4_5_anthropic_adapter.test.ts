/**
 * W4.5 Anthropic TS adapter tests (VAL-W4-033, VAL-W4-038, VAL-W4-039,
 * VAL-W4-040).
 *
 * Tests use duck-typed stubs that mimic the Anthropic Node SDK shape;
 * no real ``@anthropic-ai/sdk`` package import.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { RelayAdapterUnsupportedVersionError } from "../src/errors.js";
import { SpanRecorder } from "../src/adapters/_spans.js";
import {
  assertAnthropicVersionSupported,
  wrapAnthropic,
} from "../src/adapters/anthropic.js";

function buildAnthropicStub(args: {
  response?: unknown;
  stream?: AsyncIterable<unknown> | Iterable<unknown>;
}): { messages: { create: (a: Record<string, unknown>) => unknown } } {
  return {
    messages: {
      create: (a: Record<string, unknown>) => {
        if (a["stream"] === true) return args.stream;
        return args.response;
      },
    },
  };
}

describe("VAL-W4-033: Anthropic TS adapter wraps messages.create (sync)", () => {
  it("emits one model_call span per sync messages.create call", () => {
    const recorder = new SpanRecorder();
    const stub = buildAnthropicStub({
      response: {
        id: "msg_abcdef",
        model: "claude-3-5-haiku",
        stop_reason: "end_turn",
        usage: {
          input_tokens: 22,
          output_tokens: 7,
          cache_creation_input_tokens: 3,
          cache_read_input_tokens: 1,
        },
        content: [{ type: "text", text: "ok" }],
      },
    });
    const wrapped = wrapAnthropic(stub, { recorder, sdkVersion: "anthropic@0.30.0" });
    wrapped.messages.create({ model: "claude-3-5-haiku" });
    const modelCalls = recorder.spansByKind("model_call");
    expect(modelCalls).toHaveLength(1);
    const span = modelCalls[0]!;
    expect(span.attributes["provider"]).toBe("anthropic");
    expect(span.attributes["model"]).toBe("claude-3-5-haiku");
    // VAL-W4-033 fallback: model_signature uses response.id.
    expect(span.attributes["model_signature"]).toBe("anthropic:claude-3-5-haiku:msg_abcdef");
    expect(span.attributes["input_tokens"]).toBe(22);
    expect(span.attributes["output_tokens"]).toBe(7);
    expect(span.attributes["cache_creation_input_tokens"]).toBe(3);
    expect(span.attributes["cache_read_input_tokens"]).toBe(1);
    expect(span.attributes["stop_reason"]).toBe("end_turn");
  });

  it("emits one tool_call span per tool_use block", () => {
    const recorder = new SpanRecorder();
    const stub = buildAnthropicStub({
      response: {
        id: "msg_tool",
        model: "claude-3-5-sonnet",
        stop_reason: "tool_use",
        usage: { input_tokens: 5, output_tokens: 3 },
        content: [
          { type: "text", text: "ok" },
          { type: "tool_use", name: "search", input: { query: "relay" } },
          { type: "tool_use", name: "lookup", input: { id: 7 } },
        ],
      },
    });
    const wrapped = wrapAnthropic(stub, { recorder, sdkVersion: "anthropic@0.30.0" });
    wrapped.messages.create({ model: "claude-3-5-sonnet" });
    expect(recorder.spansByKind("tool_call")).toHaveLength(2);
    const names = recorder.spansByKind("tool_call").map((s) => s.attributes["tool_name"]);
    expect(names).toEqual(["search", "lookup"]);
  });

  it("synthesises model_signature when response.id is absent", () => {
    const recorder = new SpanRecorder();
    const stub = buildAnthropicStub({
      response: {
        model: "claude-3-5-haiku",
        usage: { input_tokens: 1, output_tokens: 1 },
        content: [],
      },
    });
    const wrapped = wrapAnthropic(stub, { recorder, sdkVersion: "anthropic@0.30.0" });
    wrapped.messages.create({ model: "claude-3-5-haiku" });
    const sig = recorder.spansByKind("model_call")[0]!.attributes["model_signature"];
    expect(String(sig)).toMatch(/^anthropic:claude-3-5-haiku:[0-9a-f]{16}$/);
  });
});

describe("VAL-W4-033 + VAL-W4-039: Anthropic streaming aggregates to one model_call span", () => {
  it("aggregates message_start + content_block_start + content_block_delta + message_delta into one model_call + per-tool tool_call spans", async () => {
    const recorder = new SpanRecorder();
    async function* fakeStream(): AsyncGenerator<unknown> {
      yield {
        type: "message_start",
        message: {
          id: "msg_stream_123",
          model: "claude-3-5-sonnet",
          usage: { input_tokens: 12, output_tokens: 0 },
        },
      };
      yield {
        type: "content_block_start",
        index: 0,
        content_block: { type: "tool_use", name: "calculator", input: {} },
      };
      yield {
        type: "content_block_delta",
        index: 0,
        delta: { type: "input_json_delta", partial_json: '{"a":' },
      };
      yield {
        type: "content_block_delta",
        index: 0,
        delta: { type: "input_json_delta", partial_json: " 7}" },
      };
      yield {
        type: "content_block_start",
        index: 1,
        content_block: { type: "text", text: "" },
      };
      yield {
        type: "message_delta",
        delta: { stop_reason: "tool_use" },
        usage: { output_tokens: 5 },
      };
      yield { type: "message_stop" };
    }
    const stub = buildAnthropicStub({ stream: fakeStream() });
    const wrapped = wrapAnthropic(stub, { recorder, sdkVersion: "anthropic@0.30.0" });
    const stream = wrapped.messages.create({
      model: "claude-3-5-sonnet",
      stream: true,
    }) as AsyncIterable<unknown>;
    const collected: unknown[] = [];
    for await (const evt of stream) {
      collected.push(evt);
    }
    // VAL-W4-039: one model_call, no per-event spans, one tool_call.
    expect(recorder.spansByKind("model_call")).toHaveLength(1);
    expect(recorder.spansByKind("stream_chunk")).toHaveLength(0);
    const toolCalls = recorder.spansByKind("tool_call");
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0]!.attributes["tool_name"]).toBe("calculator");
    expect(toolCalls[0]!.attributes["args_redacted"]).toEqual({ a: 7 });
    // model_signature pulled from streamed message.id.
    const sig = recorder.spansByKind("model_call")[0]!.attributes["model_signature"];
    expect(sig).toBe("anthropic:claude-3-5-sonnet:msg_stream_123");
    // Tokens aggregated across message_start + message_delta.
    const span = recorder.spansByKind("model_call")[0]!;
    expect(span.attributes["input_tokens"]).toBe(12);
    expect(span.attributes["output_tokens"]).toBe(5);
    expect(collected.length).toBe(7);
  });
});

describe("VAL-W4-038: Anthropic adapter scrubs tool input args", () => {
  it("masks api_key keys in tool_use input", () => {
    const recorder = new SpanRecorder();
    const stub = buildAnthropicStub({
      response: {
        id: "msg_tool_scrub",
        model: "claude-3-5-sonnet",
        usage: { input_tokens: 1, output_tokens: 1 },
        content: [
          {
            type: "tool_use",
            name: "deploy",
            input: { api_key: "sk-secret-AAAAAAAAAA", env: "prod" },
          },
        ],
      },
    });
    const wrapped = wrapAnthropic(stub, { recorder, sdkVersion: "anthropic@0.30.0" });
    wrapped.messages.create({ model: "claude-3-5-sonnet" });
    const tc = recorder.spansByKind("tool_call")[0]!;
    const argsRedacted = tc.attributes["args_redacted"] as Record<string, unknown>;
    expect(argsRedacted["api_key"]).toBe("[REDACTED]");
    expect(argsRedacted["env"]).toBe("prod");
    const seedSerialized = JSON.stringify(tc.attributes);
    expect(seedSerialized).not.toContain("sk-secret-AAAAAAAAAA");
  });
});

describe("VAL-W4-040: Anthropic adapter init refuses out-of-range provider SDK version", () => {
  it("throws RelayAdapterUnsupportedVersionError for anthropic v3.0.0", () => {
    const stub = buildAnthropicStub({});
    expect(() => wrapAnthropic(stub, { sdkVersion: "anthropic@3.0.0" })).toThrow(
      RelayAdapterUnsupportedVersionError,
    );
  });

  it("accepts anthropic v0.x and v1.x", () => {
    const stub = buildAnthropicStub({ response: { model: "x", usage: {}, content: [] } });
    expect(() => wrapAnthropic(stub, { sdkVersion: "anthropic@0.30.0" })).not.toThrow();
    expect(() => wrapAnthropic(stub, { sdkVersion: "anthropic@1.5.0" })).not.toThrow();
  });

  it("error envelope carries adapter + supported_range", () => {
    const stub = buildAnthropicStub({});
    try {
      wrapAnthropic(stub, { sdkVersion: "anthropic@5.0.0" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayAdapterUnsupportedVersionError);
      const envelope = (err as RelayAdapterUnsupportedVersionError).toEnvelope();
      expect(envelope.code).toBe("RELAY-SDK-ADAPTER-VERSION-UNSUPPORTED");
      const details = envelope.details as Record<string, unknown>;
      expect(details["adapter"]).toBe("anthropic");
      expect(details["observed_version"]).toBe("5.0.0");
    }
  });

  it("assertAnthropicVersionSupported tolerates null/undefined/unknown", () => {
    expect(() => assertAnthropicVersionSupported(null)).not.toThrow();
    expect(() => assertAnthropicVersionSupported(undefined)).not.toThrow();
    expect(() => assertAnthropicVersionSupported("unknown")).not.toThrow();
  });
});
