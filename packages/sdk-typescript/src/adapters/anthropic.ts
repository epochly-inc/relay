/**
 * Anthropic TypeScript adapter (W4.5; VAL-W4-033, VAL-W4-039, VAL-W4-040).
 *
 * Wraps an Anthropic Node SDK client (``new Anthropic()`` instance) so
 * every ``client.messages.create(...)`` invocation emits Relay spans
 * describing the model call, embedded ``tool_use`` blocks, and (for
 * streaming) an aggregated single ``model_call`` span per logical
 * invocation (per VAL-W4-039 streaming aggregation).
 *
 * The adapter is duck-typed: it NEVER imports the ``@anthropic-ai/sdk``
 * package at module-load time, so installing the relay OSS SDK does NOT
 * pull the commercial Anthropic SDK as a transitive dependency.
 *
 * Per CLAUDE.md keystone invariant #1 the adapter NEVER writes canonical
 * results -- it accumulates spans into a :class:`SpanRecorder` for the
 * W4.2 lifecycle ingest surface to ship to the sidecar.
 *
 * VAL-W4-033 model_signature: Anthropic does not currently expose a
 * ``system_fingerprint`` analog, so this adapter falls back to
 * ``response.id`` as the signature surrogate per spec gap note.
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

const ANTHROPIC_PROVIDER = "anthropic";

/** Supported semver major-version range for ``@anthropic-ai/sdk``. */
export const ANTHROPIC_SUPPORTED_MAJOR_RANGE = ">=0 <2";

const ANTHROPIC_PRICE_TABLE: ReadonlyMap<string, readonly [number, number]> = new Map([
  ["claude-opus-4-7", [15.0, 75.0]],
  ["claude-opus-4", [15.0, 75.0]],
  ["claude-sonnet-4", [3.0, 15.0]],
  ["claude-3-7-sonnet", [3.0, 15.0]],
  ["claude-3-5-sonnet", [3.0, 15.0]],
  ["claude-3-5-haiku", [0.8, 4.0]],
]);

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

/**
 * VAL-W4-033 ``model_signature``: ``anthropic:<model>:<response.id>``.
 *
 * When ``response.id`` is null, falls back to a deterministic SHA-256
 * prefix of the model name so the refresh policy can still detect drift.
 */
function modelSignature(model: string, responseId: string | null): string {
  if (responseId !== null && responseId !== "") {
    return `${ANTHROPIC_PROVIDER}:${model}:${responseId}`;
  }
  const fallback = sha256Hex(model).slice(0, 16);
  return `${ANTHROPIC_PROVIDER}:${model}:${fallback}`;
}

function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const price = ANTHROPIC_PRICE_TABLE.get(model);
  if (price === undefined) return 0.0;
  const [inputPerM, outputPerM] = price;
  const usd =
    (inputTokens / 1_000_000) * inputPerM + (outputTokens / 1_000_000) * outputPerM;
  return Math.round(usd * 1_000_000) / 1_000_000;
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

function redactToolInput(value: unknown): { redacted: unknown; argsHash: string } {
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
 * VAL-W4-040: refuse to wrap an out-of-range Anthropic SDK version.
 *
 * Anthropic's TS SDK is currently 0.x; the supported range is
 * ``>=0 <2`` (i.e., 0.x and 1.x). ``null``/``undefined``/``"unknown"``
 * are tolerated for duck-typed test callers.
 */
export function assertAnthropicVersionSupported(version: string | null | undefined): void {
  if (version === null || version === undefined) return;
  const trimmed = version.trim();
  if (trimmed === "" || trimmed === "unknown") return;
  const major = parseMajor(trimmed);
  if (major === null) return;
  if (major >= 0 && major < 2) return;
  throw new RelayAdapterUnsupportedVersionError(
    `anthropic SDK version ${trimmed} is outside the supported range ${ANTHROPIC_SUPPORTED_MAJOR_RANGE}`,
    {
      code: RELAY_SDK_ADAPTER_VERSION_UNSUPPORTED_CODE,
      details: {
        adapter: "anthropic",
        observed_version: trimmed,
        supported_range: ANTHROPIC_SUPPORTED_MAJOR_RANGE,
        observed_major: major,
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

export interface WrapAnthropicOptions {
  recorder?: SpanRecorder;
  sdkVersion?: string;
}

export interface WrappedAnthropicClient {
  readonly recorder: SpanRecorder;
  readonly messages: { create: (args?: Record<string, unknown>) => unknown };
  readonly inner: unknown;
}

interface MessagesLike {
  create: (args: Record<string, unknown>) => unknown;
}

interface AnthropicClientLike {
  messages?: MessagesLike;
}

class WrappedMessages {
  constructor(
    private readonly inner: MessagesLike,
    private readonly recorder: SpanRecorder,
    private readonly sdkVersion: string,
  ) {}

  create(args: Record<string, unknown> = {}): unknown {
    const isStream = args["stream"] === true;
    const modelInArgs = asString(args["model"], "");
    const parent = this.recorder.newSpan("model_call", {
      provider: ANTHROPIC_PROVIDER,
      model: modelInArgs,
      sdk_version: this.sdkVersion,
      input_tokens: 0,
      output_tokens: 0,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0,
      total_cost_usd: 0.0,
      model_signature: modelSignature(modelInArgs, null),
    });
    const startMs = Date.now();
    const result = this.inner.create(args);
    if (isStream) {
      return wrapStreamingMessagesResult(result, this.recorder, parent, startMs);
    }
    return resolveAndPopulate(result, this.recorder, parent, startMs);
  }
}

function resolveAndPopulate(
  result: unknown,
  recorder: SpanRecorder,
  parent: Span,
  startMs: number,
): unknown {
  if (result !== null && typeof result === "object" && typeof (result as { then?: unknown }).then === "function") {
    return (result as Promise<unknown>).then((response: unknown) => {
      populateParentFromResponse(parent, response);
      parent.attributes["duration_ms"] = Date.now() - startMs;
      emitToolUseSpansFromResponse(recorder, parent, response);
      return response;
    });
  }
  populateParentFromResponse(parent, result);
  parent.attributes["duration_ms"] = Date.now() - startMs;
  emitToolUseSpansFromResponse(recorder, parent, result);
  return result;
}

function populateParentFromResponse(parent: Span, response: unknown): void {
  const model = asString(getProp(response, "model"), asString(parent.attributes["model"], ""));
  const responseId = asString(getProp(response, "id"), "") || null;
  const usage = getProp(response, "usage");
  const inputTokens = asInt(getProp(usage, "input_tokens"));
  const outputTokens = asInt(getProp(usage, "output_tokens"));
  const cacheCreation = asInt(getProp(usage, "cache_creation_input_tokens"));
  const cacheRead = asInt(getProp(usage, "cache_read_input_tokens"));
  parent.attributes["model"] = model;
  parent.attributes["input_tokens"] = inputTokens;
  parent.attributes["output_tokens"] = outputTokens;
  parent.attributes["cache_creation_input_tokens"] = cacheCreation;
  parent.attributes["cache_read_input_tokens"] = cacheRead;
  parent.attributes["total_cost_usd"] = estimateCostUsd(model, inputTokens, outputTokens);
  parent.attributes["model_signature"] = modelSignature(model, responseId);
  parent.attributes["stop_reason"] = getProp(response, "stop_reason") ?? null;
  parent.attributes["response_id"] = responseId;
}

function emitToolUseSpansFromResponse(
  recorder: SpanRecorder,
  parent: Span,
  response: unknown,
): void {
  const content = getProp(response, "content");
  if (!Array.isArray(content)) return;
  for (const block of content) {
    const btype = asString(getProp(block, "type"), "");
    if (btype !== "tool_use") continue;
    const toolName = asString(getProp(block, "name"), "");
    const toolInput = getProp(block, "input", {});
    const { redacted, argsHash } = redactToolInput(toolInput);
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
// Streaming aggregator (VAL-W4-039)
// ---------------------------------------------------------------------------

interface StreamState {
  parent: Span;
  recorder: SpanRecorder;
  startMs: number;
  model: string;
  responseId: string | null;
  cumInputTokens: number;
  cumOutputTokens: number;
  chunkCount: number;
  stopReason: string | null;
  // Aggregator: index -> { name, partialJsonInput }
  toolUsesByIndex: Map<number, { name: string; partialJson: string; input: unknown }>;
}

function makeStreamState(parent: Span, recorder: SpanRecorder, startMs: number): StreamState {
  return {
    parent,
    recorder,
    startMs,
    model: asString(parent.attributes["model"], ""),
    responseId: null,
    cumInputTokens: 0,
    cumOutputTokens: 0,
    chunkCount: 0,
    stopReason: null,
    toolUsesByIndex: new Map(),
  };
}

function ingestEvent(state: StreamState, event: unknown): void {
  state.chunkCount += 1;
  const eventType = asString(getProp(event, "type"), "");
  if (eventType === "message_start") {
    const message = getProp(event, "message");
    const id = asString(getProp(message, "id"), "");
    if (id !== "") state.responseId = id;
    const model = asString(getProp(message, "model"), "");
    if (model !== "") state.model = model;
    const usage = getProp(message, "usage");
    if (usage !== null && usage !== undefined) {
      state.cumInputTokens += asInt(getProp(usage, "input_tokens"));
      // message_start carries only the small initial output count (seed).
      // message_delta later supplies the authoritative CUMULATIVE total, so
      // we seed here but do not treat this as a delta to be summed; adding
      // both would double-count (VAL-ISO-020).
      state.cumOutputTokens = asInt(getProp(usage, "output_tokens"));
    }
  } else if (eventType === "content_block_start") {
    const block = getProp(event, "content_block");
    const btype = asString(getProp(block, "type"), "");
    if (btype === "tool_use") {
      const idx = asInt(getProp(event, "index"), -1);
      if (idx >= 0) {
        const name = asString(getProp(block, "name"), "");
        const initialInput = getProp(block, "input", {});
        state.toolUsesByIndex.set(idx, {
          name,
          partialJson: "",
          input: initialInput,
        });
      }
    }
  } else if (eventType === "content_block_delta") {
    const idx = asInt(getProp(event, "index"), -1);
    if (idx >= 0) {
      const delta = getProp(event, "delta");
      const dtype = asString(getProp(delta, "type"), "");
      if (dtype === "input_json_delta") {
        const partial = asString(getProp(delta, "partial_json"), "");
        const existing = state.toolUsesByIndex.get(idx);
        if (existing !== undefined) {
          existing.partialJson += partial;
        }
      }
    }
  } else if (eventType === "message_delta") {
    const usage = getProp(event, "usage");
    if (usage !== null && usage !== undefined) {
      // Anthropic's message_delta usage.output_tokens is the AUTHORITATIVE
      // CUMULATIVE final output count, not a per-event increment. Assign it
      // (do not add) so the running total is not double-counted with the
      // message_start seed (VAL-ISO-020). Absent usage leaves the seed intact.
      state.cumOutputTokens = asInt(getProp(usage, "output_tokens"));
    }
    const delta = getProp(event, "delta");
    const stopReason = asString(getProp(delta, "stop_reason"), "");
    if (stopReason !== "") state.stopReason = stopReason;
  }
}

function finalizeStream(state: StreamState): void {
  state.parent.attributes["model"] = state.model;
  state.parent.attributes["model_signature"] = modelSignature(state.model, state.responseId);
  state.parent.attributes["duration_ms"] = Date.now() - state.startMs;
  state.parent.attributes["chunk_count"] = state.chunkCount;
  state.parent.attributes["input_tokens"] = state.cumInputTokens;
  state.parent.attributes["output_tokens"] = state.cumOutputTokens;
  state.parent.attributes["total_cost_usd"] = estimateCostUsd(
    state.model,
    state.cumInputTokens,
    state.cumOutputTokens,
  );
  state.parent.attributes["stop_reason"] = state.stopReason;
  state.parent.attributes["response_id"] = state.responseId;
  // Emit ONE tool_call span per aggregated tool_use (VAL-W4-039).
  for (const [, agg] of state.toolUsesByIndex) {
    let parsedInput: unknown = agg.input;
    if (agg.partialJson !== "") {
      try {
        parsedInput = JSON.parse(agg.partialJson);
      } catch {
        parsedInput = agg.partialJson;
      }
    }
    const { redacted, argsHash } = redactToolInput(parsedInput);
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

function wrapStreamingMessagesResult(
  result: unknown,
  recorder: SpanRecorder,
  parent: Span,
  startMs: number,
): AsyncIterable<unknown> {
  const state = makeStreamState(parent, recorder, startMs);
  const resolveThenable = async (): Promise<unknown> => {
    if (result !== null && typeof result === "object" && typeof (result as { then?: unknown }).then === "function") {
      return await (result as Promise<unknown>);
    }
    return result;
  };
  return {
    [Symbol.asyncIterator](): AsyncIterator<unknown> {
      let inner: AsyncIterator<unknown> | Iterator<unknown> | null = null;
      const initInner = async (): Promise<void> => {
        const resolved = await resolveThenable();
        if (resolved !== null && typeof resolved === "object" && Symbol.asyncIterator in (resolved as object)) {
          inner = (resolved as AsyncIterable<unknown>)[Symbol.asyncIterator]();
        } else if (resolved !== null && typeof resolved === "object" && Symbol.iterator in (resolved as object)) {
          inner = (resolved as Iterable<unknown>)[Symbol.iterator]();
        } else {
          throw new Error("Anthropic streaming response is not iterable");
        }
      };
      return {
        async next(): Promise<IteratorResult<unknown>> {
          if (inner === null) await initInner();
          if (inner === null) throw new Error("stream not initialised");
          const step = await Promise.resolve(inner.next());
          if (step.done === true) {
            finalizeStream(state);
            return { value: undefined, done: true };
          }
          ingestEvent(state, step.value);
          return { value: step.value, done: false };
        },
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Wrap an Anthropic client so every ``messages.create(...)`` call records
 * Relay spans.
 *
 * Args:
 *   client:     Object exposing ``.messages.create(args)``. In production
 *               this is an ``Anthropic`` instance from
 *               ``@anthropic-ai/sdk``; tests pass any duck-typed
 *               stand-in.
 *   options:
 *     recorder:   Optional :class:`SpanRecorder`.
 *     sdkVersion: Override the SDK version string the spans carry.
 *
 * Returns the wrapped client mirroring ``.messages.create``.
 *
 * Raises :class:`RelayAdapterUnsupportedVersionError` synchronously when
 * the SDK version parses to a major outside the supported range
 * (VAL-W4-040).
 */
export function wrapAnthropic(
  client: AnthropicClientLike,
  options: WrapAnthropicOptions = {},
): WrappedAnthropicClient {
  const recorder = options.recorder ?? new SpanRecorder();
  const sdkVersion = options.sdkVersion ?? "anthropic@unknown";
  assertAnthropicVersionSupported(sdkVersion.replace(/^anthropic@/, ""));
  const innerMessages = client.messages;
  if (innerMessages === undefined || typeof innerMessages.create !== "function") {
    throw new Error("wrapAnthropic: client.messages.create is required");
  }
  const wrappedMessages = new WrappedMessages(innerMessages, recorder, sdkVersion);
  return {
    recorder,
    messages: wrappedMessages,
    inner: client,
  };
}
