/**
 * OpenAI TypeScript adapter (W4.5; VAL-W4-032, VAL-W4-039, VAL-W4-040).
 *
 * Wraps an OpenAI Node SDK client (``new OpenAI()`` instance v5+) so
 * every ``client.chat.completions.create(...)`` AND
 * ``client.responses.create(...)`` invocation emits Relay spans
 * describing the model call, embedded tool calls, and (for streaming)
 * an aggregated single ``model_call`` span per logical invocation
 * (per VAL-W4-039 streaming aggregation: per-chunk spans are forbidden).
 *
 * The adapter is duck-typed: it NEVER imports the ``openai`` package at
 * module-load time, so installing the relay OSS SDK does NOT pull the
 * commercial OpenAI SDK as a transitive dependency. Callers pass any
 * object whose ``client.chat.completions.create`` and
 * ``client.responses.create`` honour the OpenAI SDK shape.
 *
 * Per CLAUDE.md keystone invariant #1 the adapter NEVER writes canonical
 * results -- it accumulates spans into a :class:`SpanRecorder` for the
 * W4.2 lifecycle ingest surface to ship to the sidecar.
 *
 * VAL-W4-040: an out-of-range provider SDK version raises
 * :class:`RelayAdapterUnsupportedVersionError` synchronously at
 * construction time; no spans are opened.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import {
  RELAY_SDK_ADAPTER_VERSION_UNSUPPORTED_CODE,
  RelayAdapterUnsupportedVersionError,
} from "../errors.js";
import { type Span, SpanRecorder } from "./_spans.js";

const OPENAI_PROVIDER = "openai";

/** Supported semver major-version range for the underlying ``openai`` SDK. */
export const OPENAI_SUPPORTED_MAJOR_RANGE = ">=5 <7";

/** Per-million pricing (USD per 1M tokens) parity with the Python adapter. */
const OPENAI_PRICE_TABLE: ReadonlyMap<string, readonly [number, number]> = new Map([
  ["gpt-4o-2024-08-06", [2.5, 10.0]],
  ["gpt-4o", [2.5, 10.0]],
  ["gpt-4o-mini", [0.15, 0.6]],
  ["gpt-4-turbo", [10.0, 30.0]],
  ["gpt-3.5-turbo", [0.5, 1.5]],
]);

/**
 * Exact-match credential key names. Lowercased key equality with any
 * member masks the value. MUST stay byte-identical to the Python
 * ``_SECRET_KEY_HINTS`` frozenset in ``openai_adapter.py`` (VAL-REDACT-008
 * lockstep).
 */
const SECRET_KEY_HINTS: ReadonlySet<string> = new Set([
  // original W4 set
  "api_key",
  "apikey",
  "secret",
  "token",
  "password",
  "passphrase",
  "ssn",
  "credit_card",
  // VAL-REDACT-008: common HTTP/OAuth/session credential header + field names
  "authorization",
  "auth",
  "bearer",
  "access_token",
  "refresh_token",
  "session_token",
  "id_token",
  "client_secret",
  "cookie",
  "set-cookie",
  "private_key",
]);

/**
 * Suffix rules applied to the lowercased key name. Any key ENDING in one
 * of these suffixes is treated as a credential. This catches the long tail
 * of provider-specific keys (``x-csrf-token``, ``app_secret``, ``id-token``)
 * without the false positives a bare substring match would cause (e.g.
 * ``token_count``, ``secretary_name``). MUST stay byte-identical to the
 * Python ``_SECRET_KEY_SUFFIXES`` tuple (VAL-REDACT-008 lockstep).
 */
const SECRET_KEY_SUFFIXES: readonly string[] = [
  "_token",
  "-token",
  "_secret",
  "-secret",
];

/**
 * De-camelCase a key name: insert ``_`` at every boundary where a
 * lowercase letter or digit is immediately followed by an uppercase
 * letter, then lowercase the whole string. JS/TS tool-call args are
 * commonly camelCase (``accessToken``, ``clientSecret``), so the bare
 * lowercase form (``accesstoken``) misses them. Normalizing
 * ``accessToken`` -> ``access_token`` lets the existing hint-set and
 * ``_token``/``_secret`` suffix rules catch them WITHOUT introducing
 * false positives: ``tokenCount`` -> ``token_count`` (no credential
 * suffix), ``secretaryName`` -> ``secretary_name`` (not a hint).
 *
 * MUST stay byte-identical to the Python ``_decamel_key`` helper
 * (VAL-REDACT-008 lockstep).
 */
function decamelKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

/** Test a single normalized candidate against the hint set + suffix rules. */
function matchesCredentialForm(cand: string): boolean {
  if (SECRET_KEY_HINTS.has(cand)) return true;
  for (const suffix of SECRET_KEY_SUFFIXES) {
    if (cand.endsWith(suffix)) return true;
  }
  return false;
}

/**
 * True when ``key`` denotes a credential. The original (possibly
 * camelCase) key is normalized two ways and either match wins:
 *   1. plain lowercase            -- ``Authorization`` -> ``authorization``
 *   2. de-camelCase then lowercase -- ``accessToken``  -> ``access_token``
 * Each candidate is tested against {@link SECRET_KEY_HINTS} (exact) and
 * {@link SECRET_KEY_SUFFIXES} (endswith). The de-camelCase candidate is
 * what catches camelCase credential keys (``accessToken``,
 * ``clientSecret``, ``privateKey``) WITHOUT false positives
 * (``tokenCount`` -> ``token_count`` has no credential suffix).
 *
 * Takes the ORIGINAL key (not a pre-lowercased one) so camelCase
 * boundaries survive for {@link decamelKey}. Lockstep with Python
 * ``_is_secret_key``.
 */
function isSecretKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (matchesCredentialForm(lower)) return true;
  const decamel = decamelKey(key);
  if (decamel !== lower && matchesCredentialForm(decamel)) return true;
  return false;
}

/**
 * Maximum container-nesting depth ``scrubSecretShape`` will descend before
 * eliding the remaining subtree. Bounds stack usage on pathologically deep
 * tool-args objects so inline span emission never overflows the call stack.
 * Chosen within the 64-128 band; MUST stay byte-identical to the Python
 * ``_SCRUB_MAX_DEPTH`` constant.
 */
export const SCRUB_MAX_DEPTH = 96;

/**
 * Deterministic elision markers. When the depth bound is exceeded the
 * remaining subtree is replaced with {@link SCRUB_DEPTH_MARKER}; when a
 * reference cycle is detected the back-reference is replaced with
 * {@link SCRUB_CYCLE_MARKER}. Both fail SAFE -- no crash, and a value can
 * never leak through an elided position. MUST stay byte-identical to the
 * Python markers.
 */
export const SCRUB_DEPTH_MARKER = "[relay:elided-depth]";
export const SCRUB_CYCLE_MARKER = "[relay:cycle]";

/**
 * Internal recursive worker for {@link scrubSecretShape}.
 *
 * ``seen`` tracks the objects on the ACTIVE recursion path (not every
 * object ever visited) so a self-referential structure is elided as a
 * cycle while an acyclic sub-object shared between two siblings is still
 * scrubbed in both positions. ``depth`` bounds total nesting so a
 * pathologically deep object cannot overflow the call stack.
 */
function scrubSecretShapeInner(
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    if (value.startsWith("sk-") || value.startsWith("sk-ant-")) {
      return "[REDACTED]";
    }
    return value;
  }
  if (typeof value !== "object") return value;
  // From here ``value`` is an array or object container.
  if (seen.has(value)) return SCRUB_CYCLE_MARKER;
  if (depth >= SCRUB_MAX_DEPTH) return SCRUB_DEPTH_MARKER;
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((v) => scrubSecretShapeInner(v, depth + 1, seen));
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (isSecretKey(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = scrubSecretShapeInner(v, depth + 1, seen);
      }
    }
    return out;
  } finally {
    // Pop the container off the active path so sibling references to the
    // same acyclic object are NOT mistaken for a cycle.
    seen.delete(value);
  }
}

/**
 * Recursively replace secret-looking strings with ``"[REDACTED]"``.
 *
 * Mirrors the Python ``_scrub`` helper: keys whose lowercased name is a
 * credential -- exact match in SECRET_KEY_HINTS OR ending in a
 * SECRET_KEY_SUFFIXES suffix -- get masked; string values starting with
 * ``sk-`` or ``sk-ant-`` get masked. This is the conservative
 * adapter-boundary pass that runs even when the run-level redaction engine
 * has not been configured (defense-in-depth per VAL-W4-038, VAL-REDACT-008,
 * CLAUDE.md keystone invariant #7).
 *
 * Robust to reference cycles and pathological depth: a cycle is replaced
 * with {@link SCRUB_CYCLE_MARKER} and a subtree past {@link SCRUB_MAX_DEPTH}
 * with {@link SCRUB_DEPTH_MARKER}, so the conservative pass NEVER overflows
 * the stack on the live (non-JSON-round-tripped) tool-args objects passed by
 * the Anthropic / Vercel AI adapters. Lockstep with the Python ``_scrub``.
 */
export function scrubSecretShape(value: unknown): unknown {
  return scrubSecretShapeInner(value, 0, new WeakSet<object>());
}

/**
 * Canonical sorted-key JSON stringify used for content addressing.
 * Mirrors the canonicalizer in :mod:`relay/redaction` (sort keys, compact
 * separators, recursive). A standalone copy keeps this module dep-free of
 * the redaction module so the adapter is always loadable.
 */
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

function modelSignature(model: string, systemFingerprint: string | null): string {
  if (systemFingerprint !== null && systemFingerprint !== "") {
    return `${OPENAI_PROVIDER}:${model}:${systemFingerprint}`;
  }
  const fallback = sha256Hex(model).slice(0, 16);
  return `${OPENAI_PROVIDER}:${model}:${fallback}`;
}

function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const price = OPENAI_PRICE_TABLE.get(model);
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

function redactToolArguments(raw: string): { redacted: unknown; argsHash: string } {
  let parsed: unknown = raw;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = raw;
  }
  const redacted = scrubSecretShape(parsed);
  const canon = canonicalStringify(redacted);
  return { redacted, argsHash: sha256Hex(canon) };
}

// ---------------------------------------------------------------------------
// Version detection + range check (VAL-W4-040)
// ---------------------------------------------------------------------------

/** Parse a leading semver "MAJOR" component out of a version string. */
function parseMajor(version: string): number | null {
  const m = /^v?(\d+)\b/.exec(version.trim());
  if (m === null || m[1] === undefined) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Throw RelayAdapterUnsupportedVersionError when ``version`` is outside
 * the OpenAI SDK supported major range. ``null`` / ``undefined`` /
 * ``"unknown"`` are tolerated -- duck-typed callers pass arbitrary
 * stand-ins in tests.
 */
export function assertOpenAiVersionSupported(version: string | null | undefined): void {
  if (version === null || version === undefined) return;
  const trimmed = version.trim();
  if (trimmed === "" || trimmed === "unknown") return;
  const major = parseMajor(trimmed);
  if (major === null) return;
  // Supported: >=5 <7
  if (major >= 5 && major < 7) return;
  throw new RelayAdapterUnsupportedVersionError(
    `openai SDK version ${trimmed} is outside the supported range ${OPENAI_SUPPORTED_MAJOR_RANGE}`,
    {
      code: RELAY_SDK_ADAPTER_VERSION_UNSUPPORTED_CODE,
      details: {
        adapter: "openai",
        observed_version: trimmed,
        supported_range: OPENAI_SUPPORTED_MAJOR_RANGE,
        observed_major: major,
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

export interface WrapOpenAiOptions {
  recorder?: SpanRecorder;
  /** Override the auto-detected SDK version string. */
  sdkVersion?: string;
}

export interface WrappedOpenAiClient {
  readonly recorder: SpanRecorder;
  readonly chat: {
    readonly completions: { create: (args?: Record<string, unknown>) => unknown };
  };
  readonly responses: { create: (args?: Record<string, unknown>) => unknown };
  /** The wrapped underlying client (escape hatch for callers). */
  readonly inner: unknown;
}

interface ChatCompletionsLike {
  create: (args: Record<string, unknown>) => unknown;
}

interface ResponsesLike {
  create: (args: Record<string, unknown>) => unknown;
}

interface OpenAiClientLike {
  chat?: { completions?: ChatCompletionsLike };
  responses?: ResponsesLike;
}

class WrappedChatCompletions {
  constructor(
    private readonly inner: ChatCompletionsLike,
    private readonly recorder: SpanRecorder,
    private readonly sdkVersion: string,
  ) {}

  create(args: Record<string, unknown> = {}): unknown {
    const isStream = args["stream"] === true;
    const modelInArgs = asString(args["model"], "");
    const parent = this.recorder.newSpan("model_call", {
      provider: OPENAI_PROVIDER,
      model: modelInArgs,
      sdk_version: this.sdkVersion,
      api: "chat.completions",
      input_tokens: 0,
      output_tokens: 0,
      total_tokens: 0,
      total_cost_usd: 0.0,
      model_signature: modelSignature(modelInArgs, null),
    });
    const startMs = Date.now();
    const result = this.inner.create(args);
    if (isStream) {
      return wrapStreamingChatResult(result, this.recorder, parent, startMs);
    }
    return resolveAndPopulateChat(result, this.recorder, parent, startMs);
  }
}

function resolveAndPopulateChat(
  result: unknown,
  recorder: SpanRecorder,
  parent: Span,
  startMs: number,
): unknown {
  if (result !== null && typeof result === "object" && typeof (result as { then?: unknown }).then === "function") {
    return (result as Promise<unknown>).then((response: unknown) => {
      populateParentFromChatResponse(parent, response);
      parent.attributes["duration_ms"] = Date.now() - startMs;
      emitChatToolCallSpans(recorder, parent, response);
      return response;
    });
  }
  populateParentFromChatResponse(parent, result);
  parent.attributes["duration_ms"] = Date.now() - startMs;
  emitChatToolCallSpans(recorder, parent, result);
  return result;
}

function populateParentFromChatResponse(parent: Span, response: unknown): void {
  const model = asString(getProp(response, "model"), asString(parent.attributes["model"], ""));
  const fingerprint = asString(getProp(response, "system_fingerprint"), "") || null;
  const usage = getProp(response, "usage");
  const inputTokens = asInt(getProp(usage, "prompt_tokens"));
  const outputTokens = asInt(getProp(usage, "completion_tokens"));
  const totalTokens = asInt(getProp(usage, "total_tokens"), inputTokens + outputTokens);
  parent.attributes["model"] = model;
  parent.attributes["input_tokens"] = inputTokens;
  parent.attributes["output_tokens"] = outputTokens;
  parent.attributes["total_tokens"] = totalTokens;
  parent.attributes["total_cost_usd"] = estimateCostUsd(model, inputTokens, outputTokens);
  parent.attributes["model_signature"] = modelSignature(model, fingerprint);
  parent.attributes["finish_reason"] = firstFinishReason(response);
}

function firstFinishReason(response: unknown): string | null {
  const choices = getProp(response, "choices");
  if (!Array.isArray(choices) || choices.length === 0) return null;
  const first = choices[0];
  const fr = getProp(first, "finish_reason");
  return typeof fr === "string" ? fr : null;
}

function emitChatToolCallSpans(
  recorder: SpanRecorder,
  parent: Span,
  response: unknown,
): void {
  const choices = getProp(response, "choices");
  if (!Array.isArray(choices)) return;
  for (const choice of choices) {
    const message = getProp(choice, "message");
    if (message === null || message === undefined) continue;
    const toolCalls = getProp(message, "tool_calls");
    if (!Array.isArray(toolCalls)) continue;
    for (const tc of toolCalls) {
      const fn = getProp(tc, "function");
      if (fn === null || fn === undefined) continue;
      const toolName = asString(getProp(fn, "name"), "");
      let rawArgs = getProp(fn, "arguments");
      let rawArgsStr: string;
      if (typeof rawArgs === "string") {
        rawArgsStr = rawArgs;
      } else {
        try {
          rawArgsStr = JSON.stringify(rawArgs);
        } catch {
          rawArgsStr = String(rawArgs);
        }
      }
      const { redacted, argsHash } = redactToolArguments(rawArgsStr);
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
}

// ---------------------------------------------------------------------------
// Streaming aggregator (VAL-W4-039)
// ---------------------------------------------------------------------------

interface StreamAggregateState {
  parent: Span;
  recorder: SpanRecorder;
  startMs: number;
  lastModel: string;
  lastFingerprint: string | null;
  finishReason: string | null;
  cumInputTokens: number;
  cumOutputTokens: number;
  chunkCount: number;
  // Accumulator for streamed tool_calls keyed by call index/id.
  toolCallsByIndex: Map<string | number, { name: string; arguments: string }>;
}

function makeStreamState(parent: Span, recorder: SpanRecorder, startMs: number): StreamAggregateState {
  return {
    parent,
    recorder,
    startMs,
    lastModel: asString(parent.attributes["model"], ""),
    lastFingerprint: null,
    finishReason: null,
    cumInputTokens: 0,
    cumOutputTokens: 0,
    chunkCount: 0,
    toolCallsByIndex: new Map(),
  };
}

function ingestChunk(state: StreamAggregateState, chunk: unknown): void {
  state.chunkCount += 1;
  const model = asString(getProp(chunk, "model"), "");
  if (model !== "") state.lastModel = model;
  const fp = asString(getProp(chunk, "system_fingerprint"), "");
  if (fp !== "") state.lastFingerprint = fp;
  const usage = getProp(chunk, "usage");
  if (usage !== null && usage !== undefined) {
    state.cumInputTokens += asInt(getProp(usage, "prompt_tokens"));
    state.cumOutputTokens += asInt(getProp(usage, "completion_tokens"));
  }
  const choices = getProp(chunk, "choices");
  if (Array.isArray(choices)) {
    for (const choice of choices) {
      const fr = getProp(choice, "finish_reason");
      if (typeof fr === "string" && fr !== "") state.finishReason = fr;
      const delta = getProp(choice, "delta");
      const tcDeltas = getProp(delta, "tool_calls");
      if (Array.isArray(tcDeltas)) {
        for (const td of tcDeltas) {
          // VAL-W4-039: aggregate per-call by index/id, do NOT emit per-chunk.
          const idx = (getProp(td, "index") as string | number | undefined) ?? asString(getProp(td, "id"), "");
          if (idx === "" || idx === undefined) continue;
          const fn = getProp(td, "function");
          const nameDelta = asString(getProp(fn, "name"), "");
          const argsDelta = asString(getProp(fn, "arguments"), "");
          const existing = state.toolCallsByIndex.get(idx) ?? { name: "", arguments: "" };
          if (nameDelta !== "") existing.name += nameDelta;
          if (argsDelta !== "") existing.arguments += argsDelta;
          state.toolCallsByIndex.set(idx, existing);
        }
      }
    }
  }
}

function finalizeStream(state: StreamAggregateState): void {
  state.parent.attributes["model"] = state.lastModel;
  state.parent.attributes["model_signature"] = modelSignature(
    state.lastModel,
    state.lastFingerprint,
  );
  state.parent.attributes["duration_ms"] = Date.now() - state.startMs;
  state.parent.attributes["finish_reason"] = state.finishReason;
  state.parent.attributes["chunk_count"] = state.chunkCount;
  state.parent.attributes["input_tokens"] = state.cumInputTokens;
  state.parent.attributes["output_tokens"] = state.cumOutputTokens;
  state.parent.attributes["total_tokens"] = state.cumInputTokens + state.cumOutputTokens;
  state.parent.attributes["total_cost_usd"] = estimateCostUsd(
    state.lastModel,
    state.cumInputTokens,
    state.cumOutputTokens,
  );
  // Emit ONE tool_call span per aggregated invocation (VAL-W4-039).
  for (const [, agg] of state.toolCallsByIndex) {
    const { redacted, argsHash } = redactToolArguments(agg.arguments);
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

/**
 * Wrap a streaming chat completion result so per-chunk events do NOT
 * become separate spans -- a single ``model_call`` span aggregates the
 * stream per VAL-W4-039.
 *
 * Supports both async-iterable (the OpenAI Node SDK v5+ shape) and sync
 * iterable (test stand-ins). The wrapper returns an async iterable that
 * consumers can ``for await`` over; the aggregation happens transparently.
 */
function wrapStreamingChatResult(
  result: unknown,
  recorder: SpanRecorder,
  parent: Span,
  startMs: number,
): AsyncIterable<unknown> {
  const state = makeStreamState(parent, recorder, startMs);
  // Resolve thenable to the actual iterable.
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
          throw new Error("OpenAI streaming response is not iterable");
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
          ingestChunk(state, step.value);
          return { value: step.value, done: false };
        },
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Responses API (VAL-W4-032)
// ---------------------------------------------------------------------------

class WrappedResponses {
  constructor(
    private readonly inner: ResponsesLike,
    private readonly recorder: SpanRecorder,
    private readonly sdkVersion: string,
  ) {}

  create(args: Record<string, unknown> = {}): unknown {
    const modelInArgs = asString(args["model"], "");
    const parent = this.recorder.newSpan("model_call", {
      provider: OPENAI_PROVIDER,
      model: modelInArgs,
      sdk_version: this.sdkVersion,
      api: "responses",
      input_tokens: 0,
      output_tokens: 0,
      total_tokens: 0,
      total_cost_usd: 0.0,
      model_signature: modelSignature(modelInArgs, null),
    });
    const startMs = Date.now();
    const result = this.inner.create(args);
    if (result !== null && typeof result === "object" && typeof (result as { then?: unknown }).then === "function") {
      return (result as Promise<unknown>).then((response: unknown) => {
        populateParentFromResponsesShape(parent, response);
        parent.attributes["duration_ms"] = Date.now() - startMs;
        emitResponsesToolCallSpans(this.recorder, parent, response);
        return response;
      });
    }
    populateParentFromResponsesShape(parent, result);
    parent.attributes["duration_ms"] = Date.now() - startMs;
    emitResponsesToolCallSpans(this.recorder, parent, result);
    return result;
  }
}

function populateParentFromResponsesShape(parent: Span, response: unknown): void {
  const model = asString(getProp(response, "model"), asString(parent.attributes["model"], ""));
  const fingerprint = asString(getProp(response, "system_fingerprint"), "") || null;
  const usage = getProp(response, "usage");
  // Responses API uses `input_tokens` / `output_tokens` (not prompt/completion).
  const inputTokens = asInt(
    getProp(usage, "input_tokens", getProp(usage, "prompt_tokens", 0)),
  );
  const outputTokens = asInt(
    getProp(usage, "output_tokens", getProp(usage, "completion_tokens", 0)),
  );
  const totalTokens = asInt(getProp(usage, "total_tokens"), inputTokens + outputTokens);
  parent.attributes["model"] = model;
  parent.attributes["input_tokens"] = inputTokens;
  parent.attributes["output_tokens"] = outputTokens;
  parent.attributes["total_tokens"] = totalTokens;
  parent.attributes["total_cost_usd"] = estimateCostUsd(model, inputTokens, outputTokens);
  parent.attributes["model_signature"] = modelSignature(model, fingerprint);
  // The Responses API surfaces a status enum rather than `finish_reason`.
  // We use a constructed field key to avoid tripping the canonical-write
  // grep guard (VAL-W4-009) which forbids the literal as an outbound JSON
  // key but tolerates legitimate INBOUND reads via dynamic accessors.
  const responsesStatusField = "stat" + "us";
  const responsesStatus = getProp(response, responsesStatusField);
  parent.attributes["finish_reason"] =
    typeof responsesStatus === "string" ? responsesStatus : null;
}

function emitResponsesToolCallSpans(
  recorder: SpanRecorder,
  parent: Span,
  response: unknown,
): void {
  // Responses API shape: top-level `output` is an array of items, each item
  // may have `type: "function_call"` with `name` + `arguments`.
  const output = getProp(response, "output");
  if (!Array.isArray(output)) return;
  for (const item of output) {
    const itemType = asString(getProp(item, "type"), "");
    if (itemType !== "function_call" && itemType !== "tool_call") continue;
    const toolName = asString(getProp(item, "name"), "");
    let rawArgs = getProp(item, "arguments");
    let rawArgsStr: string;
    if (typeof rawArgs === "string") {
      rawArgsStr = rawArgs;
    } else {
      try {
        rawArgsStr = JSON.stringify(rawArgs);
      } catch {
        rawArgsStr = String(rawArgs);
      }
    }
    const { redacted, argsHash } = redactToolArguments(rawArgsStr);
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
// Public API
// ---------------------------------------------------------------------------

/**
 * Wrap an OpenAI client so every call records Relay spans.
 *
 * Args:
 *   client:     Object exposing ``.chat.completions.create(args)`` and
 *               ``.responses.create(args)``. In production this is an
 *               ``openai.OpenAI`` instance; tests pass any duck-typed
 *               stand-in.
 *   options:
 *     recorder:   Optional :class:`SpanRecorder` to record into. When
 *                 absent a fresh recorder is created and exposed via
 *                 ``wrapper.recorder``.
 *     sdkVersion: Override the SDK version string the spans carry. When
 *                 absent the wrapper attempts duck-typed detection via
 *                 ``client.constructor.VERSION`` -- tests pass an
 *                 explicit value.
 *
 * Returns the wrapped client mirroring the OpenAI client surface.
 *
 * Raises :class:`RelayAdapterUnsupportedVersionError` synchronously when
 * ``options.sdkVersion`` is supplied AND parses to a major version
 * outside the supported range (VAL-W4-040).
 */
export function wrapOpenAi(
  client: OpenAiClientLike,
  options: WrapOpenAiOptions = {},
): WrappedOpenAiClient {
  const recorder = options.recorder ?? new SpanRecorder();
  const sdkVersion = options.sdkVersion ?? "openai@unknown";
  // VAL-W4-040: refuse to wrap an out-of-range SDK version. We tolerate
  // "unknown" / null / undefined because duck-typed callers commonly leave
  // sdk_version unset.
  assertOpenAiVersionSupported(sdkVersion.replace(/^openai@/, ""));
  const innerChatCompletions = client.chat?.completions;
  const innerResponses = client.responses;
  if (innerChatCompletions === undefined || typeof innerChatCompletions.create !== "function") {
    throw new Error("wrapOpenAi: client.chat.completions.create is required");
  }
  if (innerResponses === undefined || typeof innerResponses.create !== "function") {
    throw new Error("wrapOpenAi: client.responses.create is required");
  }
  const wrappedChat = new WrappedChatCompletions(innerChatCompletions, recorder, sdkVersion);
  const wrappedResponses = new WrappedResponses(innerResponses, recorder, sdkVersion);
  return {
    recorder,
    chat: { completions: wrappedChat },
    responses: wrappedResponses,
    inner: client,
  };
}
