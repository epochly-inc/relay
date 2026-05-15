/**
 * Adapter span recorder primitives (W4.5).
 *
 * Parity with the Python adapter span recorder
 * (``packages/sdk-python/relay/adapters/_spans.py``). Adapters (OpenAI,
 * Anthropic, Vercel AI SDK) emit spans into a :class:`SpanRecorder`. The
 * recorder is the SDK-side staging buffer that the W4.2 lifecycle
 * surface (``Run.modelCall`` / ``Run.toolCall``) consumes; it is NOT a
 * canonical write path -- canonical results are written by the control
 * plane only (CLAUDE.md keystone invariant #1).
 *
 * A :class:`Span` carries:
 *
 *   * ``span_id``    -- a fresh ULID per span.
 *   * ``kind``       -- one of ``"model_call"``, ``"tool_call"``,
 *                       ``"stream_chunk"``.
 *   * ``attributes`` -- the per-span attribute object (provider/model/
 *                       tokens for ``model_call``; tool_name/args for
 *                       ``tool_call``; chunk_sequence/event_type for
 *                       ``stream_chunk``).
 *
 * The recorder is in-memory only. The transport layer (:mod:`relay/run`)
 * is the component that ships these spans to the sidecar; the adapter
 * does not make HTTP calls itself.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { newUlid } from "../ulid.js";

/** Closed enum of span kinds an adapter may emit. */
export const SPAN_KINDS: ReadonlySet<string> = new Set([
  "model_call",
  "tool_call",
  "stream_chunk",
]);

export type SpanKind = "model_call" | "tool_call" | "stream_chunk";

/**
 * A single span emitted by an adapter.
 *
 * ``attributes`` is a mutable object so the adapter can populate fields
 * incrementally as a streaming response unfolds; the SpanRecorder makes
 * no defensive copy.
 */
export interface Span {
  readonly span_id: string;
  readonly kind: SpanKind;
  attributes: Record<string, unknown>;
}

/**
 * In-memory list of spans produced by an adapter.
 *
 * Adapters call :meth:`newSpan` to mint a fresh ULID-identified
 * :class:`Span`, populate its attributes, and the recorder appends it.
 *
 * Single-threaded by design: Node runs JavaScript on a single event-loop
 * thread, so no locking is required (Python parity uses a threading.Lock
 * because of free-threading work in 3.13+; in Node concurrent ``newSpan``
 * is impossible without explicit worker threads).
 */
export class SpanRecorder {
  private readonly _spans: Span[] = [];

  /** Mint and append a fresh span. Returns the Span for further mutation. */
  newSpan(kind: SpanKind, attributes: Record<string, unknown> = {}): Span {
    if (!SPAN_KINDS.has(kind)) {
      throw new Error(`unknown span kind: ${JSON.stringify(kind)}`);
    }
    const span: Span = {
      span_id: newUlid(),
      kind,
      attributes: { ...attributes },
    };
    this._spans.push(span);
    return span;
  }

  /** A snapshot copy of recorded spans, in insertion order. */
  get spans(): Span[] {
    return [...this._spans];
  }

  /** Number of recorded spans. */
  get length(): number {
    return this._spans.length;
  }

  clear(): void {
    this._spans.length = 0;
  }

  /** Return all spans of a given kind, in insertion order. */
  spansByKind(kind: SpanKind): Span[] {
    return this._spans.filter((s) => s.kind === kind);
  }
}
