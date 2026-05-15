/**
 * Vercel AI SDK adapter (W4.5; VAL-W4-034, VAL-W4-039, VAL-W4-040).
 *
 * The Vercel AI SDK (``ai`` package, https://sdk.vercel.ai) is TS-native
 * and has no Python equivalent -- this adapter is the TS-only P0 surface
 * (the Python W3.5 adapter set does not include it).
 *
 * Surfaces wrapped (Vercel AI SDK v4+ shape):
 *
 *   * :func:`generateText`    -- single-shot text generation.
 *   * :func:`streamText`      -- streaming text + tool-call aggregation.
 *   * :func:`generateObject`  -- structured-output generation.
 *
 * Each wrapped surface emits exactly ONE ``model_call`` span per logical
 * call with ``provider: 'vercel-ai'``, the mapped underlying model
 * identifier, token usage, and (for streaming) aggregated tool-call spans
 * per VAL-W4-039.
 *
 * Duck-typed: this module never imports the ``ai`` package at module
 * load. Callers either pass functions explicitly via :func:`wrapVercelAi`
 * (the recommended seam for tests) or call :func:`wrapGenerateText` /
 * :func:`wrapStreamText` / :func:`wrapGenerateObject` on individual
 * exports they have already imported themselves.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import {
  RELAY_SDK_ADAPTER_VERSION_UNSUPPORTED_CODE,
  RelayAdapterUnsupportedVersionError,
} from "../errors.js";
import { type Span, SpanRecorder } from "./_spans.js";
import { scrubSecretShape } from "./openai.js";

const VERCEL_AI_PROVIDER = "vercel-ai";

/** Supported semver major-version range for the underlying ``ai`` package. */
export const VERCEL_AI_SUPPORTED_MAJOR_RANGE = ">=4 <6";

function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalStringify: non-finite number not allowed");
    }
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalStringify(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalStringify: unsupported type ${typeof value}`);
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function getProp(obj: unknown, key: string, fallback: unknown = undefined): unknown {
  if (obj === null || obj === undefined) return fallback;
  if (typeof obj !== "object") return fallback;
  const o = obj as Record<string, unknown>;
  return key in o ? o[key] : fallback;
}

function asInt(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  return fallback;
}

function asString(value: unknown, fallback = ""): string {
  if (typeof value === "string") return value;
  return fallback;
}

/**
 * Extract a stable model identifier from a Vercel AI SDK ``model``
 * argument. The Vercel AI SDK passes provider-specific model objects;
 * we normalize to a string by checking common fields.
 */
function extractModelId(modelArg: unknown): string {
  if (modelArg === null || modelArg === undefined) return "";
  if (typeof modelArg === "string") return modelArg;
  const id = asString(getProp(modelArg, "modelId"), "");
  if (id !== "") return id;
  const id2 = asString(getProp(modelArg, "model"), "");
  if (id2 !== "") return id2;
  const id3 = asString(getProp(modelArg, "id"), "");
  return id3;
}

/** Extract the underlying provider id (e.g. ``openai``, ``anthropic``). */
function extractUnderlyingProvider(modelArg: unknown): string {
  if (modelArg === null || modelArg === undefined) return "";
  const provider = asString(getProp(modelArg, "provider"), "");
  if (provider !== "") return provider;
  const provider2 = asString(getProp(getProp(modelArg, "config"), "provider"), "");
  return provider2;
}

function modelSignature(model: string, surrogate: string | null): string {
  if (surrogate !== null && surrogate !== "") {
    return `${VERCEL_AI_PROVIDER}:${model}:${surrogate}`;
  }
  const fallback = sha256Hex(model || "unknown").slice(0, 16);
  return `${VERCEL_AI_PROVIDER}:${model}:${fallback}`;
}

function redactToolArgs(value: unknown): { redacted: unknown; argsHash: string } {
  const redacted = scrubSecretShape(value);
  const canon = canonicalStringify(redacted);
  return { redacted, argsHash: sha256Hex(canon) };
}

function parseMajor(version: string): number | null {
  const m = /^v?(\d+)\b/.exec(version.trim());
  if (m === null || m[1] === undefined) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * VAL-W4-040: refuse to wrap an out-of-range Vercel AI SDK version.
 *
 * v4.x and v5.x are accepted (eng plan A6 weekly packaging matrix
 * exercises both); v3.x and earlier are rejected.
 */
export function assertVercelAiVersionSupported(version: string | null | undefined): void {
  if (version === null || version === undefined) return;
  const trimmed = version.trim();
  if (trimmed === "" || trimmed === "unknown") return;
  const major = parseMajor(trimmed);
  if (major === null) return;
  if (major >= 4 && major < 6) return;
  throw new RelayAdapterUnsupportedVersionError(
    `vercel-ai SDK version ${trimmed} is outside the supported range ${VERCEL_AI_SUPPORTED_MAJOR_RANGE}`,
    {
      code: RELAY_SDK_ADAPTER_VERSION_UNSUPPORTED_CODE,
      details: {
        adapter: "vercel-ai",
        observed_version: trimmed,
        supported_range: VERCEL_AI_SUPPORTED_MAJOR_RANGE,
        observed_major: major,
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Span emission helpers
// ---------------------------------------------------------------------------

function newModelCallSpan(
  recorder: SpanRecorder,
  args: Record<string, unknown>,
  api: string,
  sdkVersion: string,
): Span {
  const modelArg = args["model"];
  const modelId = extractModelId(modelArg);
  const underlyingProvider = extractUnderlyingProvider(modelArg);
  return recorder.newSpan("model_call", {
    provider: VERCEL_AI_PROVIDER,
    underlying_provider: underlyingProvider,
    model: modelId,
    sdk_version: sdkVersion,
    api,
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
    total_cost_usd: 0.0,
    model_signature: modelSignature(modelId, null),
  });
}

function populateFromResult(parent: Span, result: unknown): void {
  const usage = getProp(result, "usage");
  // Vercel AI SDK v4 uses promptTokens/completionTokens; v5 uses
  // inputTokens/outputTokens.
  const inputTokens = asInt(
    getProp(usage, "inputTokens", getProp(usage, "promptTokens", 0)),
  );
  const outputTokens = asInt(
    getProp(usage, "outputTokens", getProp(usage, "completionTokens", 0)),
  );
  const totalTokens = asInt(getProp(usage, "totalTokens"), inputTokens + outputTokens);
  parent.attributes["input_tokens"] = inputTokens;
  parent.attributes["output_tokens"] = outputTokens;
  parent.attributes["total_tokens"] = totalTokens;
  const finishReason = asString(getProp(result, "finishReason"), "");
  parent.attributes["finish_reason"] = finishReason || null;
  const responseId = asString(getProp(getProp(result, "response"), "id"), "");
  if (responseId !== "") {
    const model = asString(parent.attributes["model"], "");
    parent.attributes["model_signature"] = modelSignature(model, responseId);
    parent.attributes["response_id"] = responseId;
  }
}

function emitToolCallSpansFromResult(
  recorder: SpanRecorder,
  parent: Span,
  result: unknown,
): void {
  const toolCalls = getProp(result, "toolCalls");
  if (!Array.isArray(toolCalls)) return;
  for (const tc of toolCalls) {
    const toolName = asString(getProp(tc, "toolName"), "");
    const args = getProp(tc, "args");
    const { redacted, argsHash } = redactToolArgs(args);
    recorder.newSpan("tool_call", {
      tool_name: toolName,
      parent_span_id: parent.span_id,
      args_redacted: redacted,
      args_hash: argsHash,
      result_hash: "",
      status: "pending",
      duration_ms: 0.0,
      retry_count: 0,
      side_effect_marker: false,
      normalized_error_class: null,
    });
  }
}

// ---------------------------------------------------------------------------
// generateText / generateObject (sync surfaces)
// ---------------------------------------------------------------------------

export type GenerateTextFn = (args: Record<string, unknown>) => Promise<unknown>;
export type GenerateObjectFn = (args: Record<string, unknown>) => Promise<unknown>;
export type StreamTextFn = (args: Record<string, unknown>) => unknown;

export function wrapGenerateText(
  inner: GenerateTextFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): GenerateTextFn {
  return async (args: Record<string, unknown>) => {
    const parent = newModelCallSpan(recorder, args, "generateText", sdkVersion);
    const startMs = Date.now();
    const result = await inner(args);
    populateFromResult(parent, result);
    parent.attributes["duration_ms"] = Date.now() - startMs;
    emitToolCallSpansFromResult(recorder, parent, result);
    return result;
  };
}

export function wrapGenerateObject(
  inner: GenerateObjectFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): GenerateObjectFn {
  return async (args: Record<string, unknown>) => {
    const parent = newModelCallSpan(recorder, args, "generateObject", sdkVersion);
    const startMs = Date.now();
    const result = await inner(args);
    populateFromResult(parent, result);
    parent.attributes["duration_ms"] = Date.now() - startMs;
    return result;
  };
}

// ---------------------------------------------------------------------------
// streamText (VAL-W4-039 streaming aggregation)
// ---------------------------------------------------------------------------

interface StreamTextState {
  parent: Span;
  recorder: SpanRecorder;
  startMs: number;
  inputTokens: number;
  outputTokens: number;
  finishReason: string | null;
  chunkCount: number;
  responseId: string | null;
  // Aggregated tool calls keyed by toolCallId.
  toolCallsById: Map<string, { name: string; args: unknown }>;
}

function makeStreamTextState(parent: Span, recorder: SpanRecorder, startMs: number): StreamTextState {
  return {
    parent,
    recorder,
    startMs,
    inputTokens: 0,
    outputTokens: 0,
    finishReason: null,
    chunkCount: 0,
    responseId: null,
    toolCallsById: new Map(),
  };
}

function ingestStreamPart(state: StreamTextState, part: unknown): void {
  state.chunkCount += 1;
  const partType = asString(getProp(part, "type"), "");
  if (partType === "tool-call" || partType === "tool_call") {
    const id = asString(getProp(part, "toolCallId"), "") || asString(getProp(part, "id"), "");
    const name = asString(getProp(part, "toolName"), "");
    const args = getProp(part, "args");
    if (id !== "") {
      state.toolCallsById.set(id, { name, args });
    }
  } else if (partType === "finish") {
    const usage = getProp(part, "usage");
    state.inputTokens = asInt(
      getProp(usage, "inputTokens", getProp(usage, "promptTokens", 0)),
    );
    state.outputTokens = asInt(
      getProp(usage, "outputTokens", getProp(usage, "completionTokens", 0)),
    );
    const fr = asString(getProp(part, "finishReason"), "");
    if (fr !== "") state.finishReason = fr;
    const respId = asString(getProp(getProp(part, "response"), "id"), "");
    if (respId !== "") state.responseId = respId;
  }
}

function finalizeStreamText(state: StreamTextState): void {
  state.parent.attributes["duration_ms"] = Date.now() - state.startMs;
  state.parent.attributes["chunk_count"] = state.chunkCount;
  state.parent.attributes["input_tokens"] = state.inputTokens;
  state.parent.attributes["output_tokens"] = state.outputTokens;
  state.parent.attributes["total_tokens"] = state.inputTokens + state.outputTokens;
  state.parent.attributes["finish_reason"] = state.finishReason;
  if (state.responseId !== null) {
    state.parent.attributes["response_id"] = state.responseId;
    const model = asString(state.parent.attributes["model"], "");
    state.parent.attributes["model_signature"] = modelSignature(model, state.responseId);
  }
  // Emit ONE tool_call span per aggregated invocation (VAL-W4-039).
  for (const [, agg] of state.toolCallsById) {
    const { redacted, argsHash } = redactToolArgs(agg.args);
    state.recorder.newSpan("tool_call", {
      tool_name: agg.name,
      parent_span_id: state.parent.span_id,
      args_redacted: redacted,
      args_hash: argsHash,
      result_hash: "",
      status: "pending",
      duration_ms: 0.0,
      retry_count: 0,
      side_effect_marker: false,
      normalized_error_class: null,
    });
  }
}

export function wrapStreamText(
  inner: StreamTextFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): StreamTextFn {
  return (args: Record<string, unknown>): unknown => {
    const parent = newModelCallSpan(recorder, args, "streamText", sdkVersion);
    const startMs = Date.now();
    const result = inner(args);
    return wrapStreamTextResult(result, recorder, parent, startMs);
  };
}

/**
 * Vercel AI SDK ``streamText`` returns an object exposing
 * ``fullStream`` (an AsyncIterable of stream parts). The wrapper proxies
 * the result and intercepts ``fullStream`` so per-part events are
 * aggregated into a single ``model_call`` span (VAL-W4-039) without
 * disturbing the result's other surfaces (``textStream``, ``text``,
 * ``usage``, etc.).
 */
function wrapStreamTextResult(
  result: unknown,
  recorder: SpanRecorder,
  parent: Span,
  startMs: number,
): unknown {
  if (result === null || typeof result !== "object") return result;
  const r = result as Record<string, unknown>;
  const fullStream = r["fullStream"];
  const state = makeStreamTextState(parent, recorder, startMs);
  if (fullStream === null || fullStream === undefined) {
    return result;
  }
  // Replace fullStream with a wrapped async iterable.
  const wrappedFullStream: AsyncIterable<unknown> = {
    [Symbol.asyncIterator](): AsyncIterator<unknown> {
      const inner =
        Symbol.asyncIterator in (fullStream as object)
          ? (fullStream as AsyncIterable<unknown>)[Symbol.asyncIterator]()
          : Symbol.iterator in (fullStream as object)
            ? (fullStream as Iterable<unknown>)[Symbol.iterator]()
            : null;
      if (inner === null) {
        throw new Error("Vercel AI streamText fullStream is not iterable");
      }
      return {
        async next(): Promise<IteratorResult<unknown>> {
          const step = await Promise.resolve(inner.next());
          if (step.done === true) {
            finalizeStreamText(state);
            return { value: undefined, done: true };
          }
          ingestStreamPart(state, step.value);
          return { value: step.value, done: false };
        },
      };
    },
  };
  return new Proxy(result, {
    get(target, prop, receiver): unknown {
      if (prop === "fullStream") return wrappedFullStream;
      return Reflect.get(target, prop, receiver);
    },
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface WrapVercelAiOptions {
  recorder?: SpanRecorder;
  sdkVersion?: string;
}

export interface VercelAiSurface {
  generateText?: GenerateTextFn;
  streamText?: StreamTextFn;
  generateObject?: GenerateObjectFn;
  // streamObject is also wrappable but treated identically to streamText
  // for span emission; callers can wrap it with wrapStreamText.
}

export interface WrappedVercelAiSurface {
  readonly recorder: SpanRecorder;
  readonly generateText?: GenerateTextFn;
  readonly streamText?: StreamTextFn;
  readonly generateObject?: GenerateObjectFn;
}

/**
 * Wrap a Vercel AI SDK function bag.
 *
 * Args:
 *   surface:    Object exposing ``generateText`` / ``streamText`` /
 *               ``generateObject`` (any subset). In production callers
 *               pass ``import * as ai from "ai"`` (or destructured
 *               named imports) to this function.
 *   options:
 *     recorder:   Optional :class:`SpanRecorder`.
 *     sdkVersion: Override the SDK version string the spans carry.
 *
 * Returns a wrapped surface exposing the same function names with span
 * recording enabled. Functions that the surface does not expose are
 * absent from the return value (keeps the type narrow).
 *
 * Raises :class:`RelayAdapterUnsupportedVersionError` synchronously when
 * the SDK version parses to a major outside the supported range
 * (VAL-W4-040).
 */
export function wrapVercelAi(
  surface: VercelAiSurface,
  options: WrapVercelAiOptions = {},
): WrappedVercelAiSurface {
  const recorder = options.recorder ?? new SpanRecorder();
  const sdkVersion = options.sdkVersion ?? "ai@unknown";
  assertVercelAiVersionSupported(sdkVersion.replace(/^ai@/, ""));
  const out: { -readonly [K in keyof WrappedVercelAiSurface]: WrappedVercelAiSurface[K] } = {
    recorder,
  };
  if (typeof surface.generateText === "function") {
    out.generateText = wrapGenerateText(surface.generateText, recorder, sdkVersion);
  }
  if (typeof surface.streamText === "function") {
    out.streamText = wrapStreamText(surface.streamText, recorder, sdkVersion);
  }
  if (typeof surface.generateObject === "function") {
    out.generateObject = wrapGenerateObject(surface.generateObject, recorder, sdkVersion);
  }
  return out;
}
