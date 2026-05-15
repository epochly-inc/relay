/**
 * W4.5 Vercel AI SDK adapter tests (VAL-W4-034, VAL-W4-038, VAL-W4-039,
 * VAL-W4-040).
 *
 * The Vercel AI SDK is TS-only -- there is no Python parity adapter to
 * delegate to. Tests use duck-typed function stubs that mimic the
 * ``ai`` package surface (``generateText``, ``streamText``,
 * ``generateObject``).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { RelayAdapterUnsupportedVersionError } from "../src/errors.js";
import { SpanRecorder } from "../src/adapters/_spans.js";
import {
  assertVercelAiVersionSupported,
  wrapVercelAi,
} from "../src/adapters/vercel_ai.js";

const FAKE_OPENAI_MODEL = {
  modelId: "gpt-4o-mini",
  provider: "openai",
};

describe("VAL-W4-034: Vercel AI generateText emits one model_call span", () => {
  it("emits exactly one model_call span per generateText call", async () => {
    const recorder = new SpanRecorder();
    const fakeGenerateText = async (_args: Record<string, unknown>) => ({
      text: "hello",
      finishReason: "stop",
      usage: { inputTokens: 8, outputTokens: 3, totalTokens: 11 },
      response: { id: "resp_v_1" },
      toolCalls: [],
    });
    const wrapped = wrapVercelAi(
      { generateText: fakeGenerateText },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    await wrapped.generateText!({ model: FAKE_OPENAI_MODEL, prompt: "hi" });
    expect(recorder.spansByKind("model_call")).toHaveLength(1);
    const span = recorder.spansByKind("model_call")[0]!;
    expect(span.attributes["provider"]).toBe("vercel-ai");
    expect(span.attributes["underlying_provider"]).toBe("openai");
    expect(span.attributes["model"]).toBe("gpt-4o-mini");
    expect(span.attributes["api"]).toBe("generateText");
    expect(span.attributes["input_tokens"]).toBe(8);
    expect(span.attributes["output_tokens"]).toBe(3);
    expect(span.attributes["finish_reason"]).toBe("stop");
    expect(span.attributes["model_signature"]).toBe(
      "vercel-ai:gpt-4o-mini:resp_v_1",
    );
  });

  it("falls back to v4 promptTokens/completionTokens naming", async () => {
    const recorder = new SpanRecorder();
    const fakeGenerateText = async (_args: Record<string, unknown>) => ({
      text: "ok",
      finishReason: "stop",
      usage: { promptTokens: 5, completionTokens: 2 },
    });
    const wrapped = wrapVercelAi(
      { generateText: fakeGenerateText },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    await wrapped.generateText!({ model: FAKE_OPENAI_MODEL });
    const span = recorder.spansByKind("model_call")[0]!;
    expect(span.attributes["input_tokens"]).toBe(5);
    expect(span.attributes["output_tokens"]).toBe(2);
  });

  it("emits one tool_call span per toolCall in the response", async () => {
    const recorder = new SpanRecorder();
    const fakeGenerateText = async (_args: Record<string, unknown>) => ({
      text: "",
      finishReason: "tool-calls",
      usage: { inputTokens: 5, outputTokens: 3 },
      toolCalls: [
        { toolCallId: "c1", toolName: "search", args: { q: "relay" } },
        { toolCallId: "c2", toolName: "lookup", args: { id: 1 } },
      ],
    });
    const wrapped = wrapVercelAi(
      { generateText: fakeGenerateText },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    await wrapped.generateText!({ model: FAKE_OPENAI_MODEL });
    expect(recorder.spansByKind("tool_call")).toHaveLength(2);
    expect(recorder.spansByKind("tool_call").map((s) => s.attributes["tool_name"])).toEqual([
      "search",
      "lookup",
    ]);
  });
});

describe("VAL-W4-034: Vercel AI generateObject emits one model_call span", () => {
  it("emits one model_call span per generateObject call", async () => {
    const recorder = new SpanRecorder();
    const fakeGenerateObject = async (_args: Record<string, unknown>) => ({
      object: { result: 42 },
      finishReason: "stop",
      usage: { inputTokens: 10, outputTokens: 4 },
    });
    const wrapped = wrapVercelAi(
      { generateObject: fakeGenerateObject },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    await wrapped.generateObject!({ model: FAKE_OPENAI_MODEL, schema: {} });
    expect(recorder.spansByKind("model_call")).toHaveLength(1);
    expect(recorder.spansByKind("model_call")[0]!.attributes["api"]).toBe("generateObject");
  });
});

describe("VAL-W4-034 + VAL-W4-039: streamText aggregates parts into one model_call span", () => {
  it("aggregates fullStream parts and emits ONE tool_call span per logical invocation", async () => {
    const recorder = new SpanRecorder();
    async function* fakeFullStream(): AsyncGenerator<unknown> {
      yield { type: "text-delta", textDelta: "hel" };
      yield { type: "text-delta", textDelta: "lo" };
      yield {
        type: "tool-call",
        toolCallId: "c1",
        toolName: "calculator",
        args: { a: 7 },
      };
      yield {
        type: "tool-call",
        toolCallId: "c2",
        toolName: "weather",
        args: { city: "Brooklyn" },
      };
      yield {
        type: "finish",
        finishReason: "tool-calls",
        usage: { inputTokens: 5, outputTokens: 9 },
        response: { id: "resp_stream_v" },
      };
    }
    const fakeStreamText = (_args: Record<string, unknown>) => ({
      fullStream: fakeFullStream(),
      // textStream/text are present in real Vercel AI SDK; we don't need
      // them for this test.
      textStream: { [Symbol.asyncIterator]: () => ({ next: async () => ({ done: true, value: undefined }) }) },
    });
    const wrapped = wrapVercelAi(
      { streamText: fakeStreamText },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    const result = wrapped.streamText!({ model: FAKE_OPENAI_MODEL, prompt: "hi" }) as {
      fullStream: AsyncIterable<unknown>;
    };
    const collected: unknown[] = [];
    for await (const part of result.fullStream) {
      collected.push(part);
    }
    // One model_call span, no per-chunk spans.
    expect(recorder.spansByKind("model_call")).toHaveLength(1);
    expect(recorder.spansByKind("stream_chunk")).toHaveLength(0);
    // VAL-W4-039: two distinct tool calls -> two tool_call spans aggregated.
    const toolCalls = recorder.spansByKind("tool_call");
    expect(toolCalls).toHaveLength(2);
    expect(toolCalls.map((s) => s.attributes["tool_name"]).sort()).toEqual([
      "calculator",
      "weather",
    ]);
    // model_signature picked up the streamed response.id.
    expect(recorder.spansByKind("model_call")[0]!.attributes["model_signature"]).toBe(
      "vercel-ai:gpt-4o-mini:resp_stream_v",
    );
    expect(collected.length).toBe(5);
  });
});

describe("VAL-W4-038: Vercel AI adapter scrubs tool args via redaction boundary", () => {
  it("masks api_key keys in toolCalls.args", async () => {
    const recorder = new SpanRecorder();
    const fakeGenerateText = async (_args: Record<string, unknown>) => ({
      text: "",
      finishReason: "tool-calls",
      usage: { inputTokens: 1, outputTokens: 1 },
      toolCalls: [
        {
          toolCallId: "c1",
          toolName: "deploy",
          args: { api_key: "sk-secret-AAAAAAAAAA", env: "prod" },
        },
      ],
    });
    const wrapped = wrapVercelAi(
      { generateText: fakeGenerateText },
      { recorder, sdkVersion: "ai@4.0.0" },
    );
    await wrapped.generateText!({ model: FAKE_OPENAI_MODEL });
    const tc = recorder.spansByKind("tool_call")[0]!;
    const argsRedacted = tc.attributes["args_redacted"] as Record<string, unknown>;
    expect(argsRedacted["api_key"]).toBe("[REDACTED]");
    expect(argsRedacted["env"]).toBe("prod");
    expect(JSON.stringify(tc.attributes)).not.toContain("sk-secret-AAAAAAAAAA");
  });
});

describe("VAL-W4-040: Vercel AI adapter init refuses out-of-range provider SDK version", () => {
  it("throws RelayAdapterUnsupportedVersionError for ai@3.0.0", () => {
    expect(() => wrapVercelAi({}, { sdkVersion: "ai@3.0.0" })).toThrow(
      RelayAdapterUnsupportedVersionError,
    );
  });

  it("accepts ai@4.x and ai@5.x", () => {
    expect(() => wrapVercelAi({}, { sdkVersion: "ai@4.0.0" })).not.toThrow();
    expect(() => wrapVercelAi({}, { sdkVersion: "ai@5.0.0" })).not.toThrow();
  });

  it("error envelope carries adapter + supported_range", () => {
    try {
      wrapVercelAi({}, { sdkVersion: "ai@7.0.0" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(RelayAdapterUnsupportedVersionError);
      const envelope = (err as RelayAdapterUnsupportedVersionError).toEnvelope();
      expect(envelope.code).toBe("RELAY-SDK-ADAPTER-VERSION-UNSUPPORTED");
      const details = envelope.details as Record<string, unknown>;
      expect(details["adapter"]).toBe("vercel-ai");
    }
  });

  it("assertVercelAiVersionSupported tolerates null/undefined/unknown", () => {
    expect(() => assertVercelAiVersionSupported(null)).not.toThrow();
    expect(() => assertVercelAiVersionSupported(undefined)).not.toThrow();
    expect(() => assertVercelAiVersionSupported("unknown")).not.toThrow();
  });
});
