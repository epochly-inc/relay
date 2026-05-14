/**
 * Flush policy + async dispatcher for the Relay TypeScript SDK (W4.2).
 *
 * Parity with the Python ``relay.flush`` module
 * (``packages/sdk-python/relay/flush.py``). The Relay SDK MUST be safe to
 * call in production: a slow or unreachable sidecar must never block the
 * caller (VAL-W3-018 / W4 parity) or crash the host application
 * (VAL-W4-018). This module owns:
 *
 *   * :class:`FlushPolicy` -- the user-facing object with two knobs:
 *       ``mode``     -- ``sync`` or ``async``.
 *       ``onError``  -- ``raise`` or ``drop_and_log``.
 *   * :class:`AsyncFlushDispatcher` -- a sequential background dispatcher
 *     that serialises outbound HTTP requests when ``mode='async'`` so the
 *     caller's ``run.close()`` returns immediately.
 *
 * Per VAL-W4-018 the default flush policy is
 * ``{mode: 'async', onError: 'drop_and_log'}``. Background flush failures
 * MUST log a structured error envelope to stderr and MUST NEVER raise
 * into the application's request path.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { RelayConfigError } from "./errors.js";

export type FlushMode = "sync" | "async";
export type OnErrorMode = "raise" | "drop_and_log";

export interface FlushPolicyShape {
  readonly mode: FlushMode;
  readonly onError: OnErrorMode;
}

/**
 * SDK flush policy (VAL-W4-018).
 *
 * The default is ``{mode: 'async', onError: 'drop_and_log'}`` so a slow
 * or unreachable sidecar never blocks the caller and never crashes the
 * host application. Callers needing strict synchronous semantics
 * (e.g. tests) opt in via ``new FlushPolicy({mode: 'sync', onError:
 * 'raise'})``.
 */
export class FlushPolicy implements FlushPolicyShape {
  readonly mode: FlushMode;
  readonly onError: OnErrorMode;

  constructor(options: Partial<FlushPolicyShape> = {}) {
    const mode = options.mode ?? "async";
    const onError = options.onError ?? "drop_and_log";
    if (mode !== "sync" && mode !== "async") {
      throw new RelayConfigError(
        `flush_policy.mode must be 'sync' or 'async'; received ${JSON.stringify(mode)}`,
        { details: { field: "mode", received: mode } },
      );
    }
    if (onError !== "raise" && onError !== "drop_and_log") {
      throw new RelayConfigError(
        `flush_policy.on_error must be 'raise' or 'drop_and_log'; received ${JSON.stringify(onError)}`,
        { details: { field: "onError", received: onError } },
      );
    }
    this.mode = mode;
    this.onError = onError;
  }

  /** Coerce a user-supplied object / FlushPolicy / undefined into one. */
  static fromInput(value: unknown): FlushPolicy {
    if (value === undefined || value === null) return new FlushPolicy();
    if (value instanceof FlushPolicy) return value;
    if (typeof value !== "object" || Array.isArray(value)) {
      throw new RelayConfigError("flush_policy must be an object or FlushPolicy", {
        details: { received_type: typeof value },
      });
    }
    const obj = value as Record<string, unknown>;
    const allowed = new Set(["mode", "onError"]);
    const unknown = Object.keys(obj).filter((k) => !allowed.has(k));
    if (unknown.length > 0) {
      throw new RelayConfigError(
        `flush_policy has unknown key(s): ${JSON.stringify(unknown.sort())}`,
        { details: { unknown_keys: unknown.sort(), allowed_keys: [...allowed].sort() } },
      );
    }
    const partial: { mode?: FlushMode; onError?: OnErrorMode } = {};
    if (obj["mode"] !== undefined) partial.mode = obj["mode"] as FlushMode;
    if (obj["onError"] !== undefined) partial.onError = obj["onError"] as OnErrorMode;
    return new FlushPolicy(partial);
  }
}

export type AsyncWork = () => Promise<void>;

/**
 * Sequential background dispatcher for ``mode='async'`` flushes.
 *
 * Lazily-started: the worker promise chain is created on first
 * :meth:`submit`. A call to :meth:`submit` enqueues the work and returns
 * synchronously; the dispatcher's worker runs each submitted callable
 * in order via Promise chaining.
 *
 * A failure inside the callable is caught and converted according to the
 * configured :class:`FlushPolicy.onError`:
 *
 *   * ``raise``: the failure is recorded on :attr:`lastError` and an
 *     ERROR-level structured log line is written to stderr; subsequent
 *     awaits of :meth:`waitIdle` resolve normally so the dispatcher can
 *     drain.
 *   * ``drop_and_log``: a single WARN-level structured envelope is
 *     written to stderr and the failure is otherwise swallowed
 *     (VAL-W4-018).
 *
 * The dispatcher is stopped via :meth:`close` (idempotent).
 */
export class AsyncFlushDispatcher {
  readonly onError: OnErrorMode;
  private chain: Promise<void> = Promise.resolve();
  private closed = false;
  /** Last error captured under ``onError='raise'`` mode (test seam). */
  lastError: unknown = null;
  /** Test-observability: count of items the worker has processed. */
  processedCount = 0;
  /** Test-observability: count of dropped items (drop_and_log mode). */
  dropCount = 0;
  /** Test-observability: count of errors recorded under raise mode. */
  errorCount = 0;
  /** Optional injected stderr writer for tests. Defaults to ``process.stderr``. */
  private readonly stderrWrite: (line: string) => void;

  constructor(options: {
    onError?: OnErrorMode;
    stderrWrite?: (line: string) => void;
  } = {}) {
    this.onError = options.onError ?? "drop_and_log";
    this.stderrWrite =
      options.stderrWrite ??
      ((line: string) => {
        // node:stream's writable.write returns a boolean; ignore.
        process.stderr.write(line.endsWith("\n") ? line : `${line}\n`);
      });
  }

  /**
   * Enqueue ``work`` for the background worker.
   *
   * Returns immediately; the only synchronous cost is the chained
   * Promise creation (tens of microseconds). The caller is guaranteed
   * not to block on outbound HTTP I/O.
   *
   * If the dispatcher is already closed, ``submit`` runs the work
   * inline as a degraded-mode fallback (best-effort; the on_error
   * policy still governs failure propagation).
   */
  submit(work: AsyncWork): void {
    if (this.closed) {
      // Fire-and-forget: do not return the promise; the caller has
      // already exited the context.
      void this.runOne(work);
      return;
    }
    this.chain = this.chain.then(() => this.runOne(work));
  }

  /** Block until every submitted item has been processed. */
  async waitIdle(): Promise<void> {
    await this.chain;
  }

  /** Stop accepting new work. The chain is allowed to finish. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    // Allow any pending chain to settle. The caller may choose to
    // ``await`` or fire-and-forget depending on the flush policy.
    await this.chain;
  }

  // -- internals ---------------------------------------------------------

  private async runOne(work: AsyncWork): Promise<void> {
    try {
      await work();
      this.processedCount += 1;
    } catch (err) {
      if (this.onError === "drop_and_log") {
        this.dropCount += 1;
        this.emitStructured("warning", "RELAY-SDK-FLUSH-DROP-AND-LOG", err);
        return;
      }
      this.errorCount += 1;
      this.lastError = err;
      this.emitStructured("error", "RELAY-SDK-FLUSH-ERROR", err);
    }
  }

  private emitStructured(level: "warning" | "error", code: string, err: unknown): void {
    const payload = {
      schema_version: "relay.error.v1",
      level,
      code,
      message: err instanceof Error ? err.message : String(err),
      error_class: err instanceof Error ? err.name : "UnknownError",
      details: {
        on_error: this.onError,
      },
    };
    try {
      this.stderrWrite(JSON.stringify(payload));
    } catch {
      // Stderr write must never throw into the host application.
    }
  }
}
