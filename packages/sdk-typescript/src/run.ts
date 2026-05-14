/**
 * ``Relay.run`` lifecycle surface (W4.2).
 *
 * Parity with the Python ``relay.run`` module
 * (``packages/sdk-python/relay/run.py``). This module owns the SDK-side
 * lifecycle surface a caller uses inside a trace context: capture
 * lifecycle events, submit gate-evaluate drafts, create replay cases
 * (cassette mode by default), submit evidence bundles, and flush.
 *
 * Per CLAUDE.md keystone invariant #1 the SDK NEVER writes canonical
 * results; it submits lifecycle metadata + drafts and reads canonical
 * decisions the control plane writes.
 *
 * The :class:`Run` is the user-facing handle returned by ``relay.trace``.
 * Caller code drives lifecycle events via :meth:`Run.capture` /
 * :meth:`Run.modelCall` / :meth:`Run.toolCall` / :meth:`Run.gateEvaluate`
 * / :meth:`Run.replayCreate` / :meth:`Run.submitEvidence`. On
 * :meth:`Run.close` the SDK flushes pending lifecycle events according to
 * the configured :class:`FlushPolicy`.
 *
 * Streaming model_call (VAL-W4-012):
 *   :meth:`Run.modelCall` accepts a streaming response and emits ONE
 *   ``model_call`` span with summarised token deltas (``promptTokens``,
 *   ``completionTokens``, ``chunkCount``, ``firstTokenLatencyMs``,
 *   ``modelSignature``). Per-chunk events do NOT become separate spans.
 *
 * Side-effect tool calls (VAL-W4-013):
 *   :meth:`Run.toolCall` with ``sideEffect: true`` requires both
 *   ``idempotencyKey`` AND ``replayPolicy``. Missing either raises
 *   :class:`RelaySideEffectMissingFieldsError` BEFORE the span opens.
 *
 * Replay (VAL-W4-017):
 *   :meth:`Run.replayCreate` defaults to cassette mode. Live mode
 *   requires the caller to explicitly opt in via
 *   ``{mode: 'live', acknowledgeDegradedApproximation: true}``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import { FlushPolicy } from "./flush.js";
import { AsyncFlushDispatcher } from "./flush.js";
import {
  RelayCanonicalStatusForbidden,
  RelayConfigError,
  RelayError,
  RelayEvidenceIncomplete,
  RelayHandoffIncomplete,
  RelayReplayLiveModeUnacknowledgedError,
  RelayReplayPrecondition,
  RelaySideEffectMissingFieldsError,
  RelayUnknownError,
  RELAY_EVID_002_CODE,
  RELAY_GATE_021_CODE,
  RELAY_ING_022_CODE,
  RELAY_ING_031_CODE,
  RELAY_REPLAY_002_CODE,
  RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
  RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE,
  resolveClassForCode,
  type ErrorEnvelopeWire,
} from "./errors.js";
import {
  buildEvidenceEnvelope,
  buildGateDraftEnvelope,
  buildIngestRunEnvelope,
  type EvidenceEnvelope,
  type GateDraftEnvelope,
  type IngestRunEnvelope,
  type LifecycleStatus,
} from "./lifecycle.js";
import { newUlid } from "./ulid.js";

/** SDK version string the SDK includes in every envelope. */
export const SDK_VERSION = "relay-typescript@0.0.0";

/** UTC timestamp with millisecond precision (mirrors Python ``_utcnow_iso8601``). */
export function utcNowIso8601(): string {
  const now = new Date();
  // ISO string already in UTC with millisecond precision; replace 'Z' as-is.
  return now.toISOString();
}

/**
 * Replay-policy enum for side-effecting tool calls (VAL-W4-013, spec X).
 *
 *   * ``replay_in_sandbox``      -- tool re-executes in the sandbox.
 *   * ``block_in_replay``        -- tool is BLOCKED in any replay; cassette
 *                                   used if available.
 *   * ``external_irreversible``  -- tool MUST NEVER replay; only cassette
 *                                   playback is permitted.
 */
export const REPLAY_POLICIES: ReadonlySet<string> = new Set([
  "replay_in_sandbox",
  "block_in_replay",
  "external_irreversible",
]);

export type ReplayPolicy = "replay_in_sandbox" | "block_in_replay" | "external_irreversible";

// ---------------------------------------------------------------------------
// Span types
// ---------------------------------------------------------------------------

export interface ModelCallSpan {
  readonly span_id: string;
  readonly span_kind: "model_call";
  readonly provider: string;
  readonly model: string;
  readonly model_signature: string;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly chunk_count: number;
  readonly first_token_latency_ms: number | null;
  readonly started_at: string;
  readonly ended_at: string;
}

export interface ToolCallSpan {
  readonly span_id: string;
  readonly span_kind: "tool_call";
  readonly tool_name: string;
  readonly side_effect: boolean;
  readonly idempotency_key?: string;
  readonly replay_policy?: ReplayPolicy;
  readonly args_digest: string;
  readonly started_at: string;
  readonly ended_at: string;
}

// ---------------------------------------------------------------------------
// Streaming model-call adapter
// ---------------------------------------------------------------------------

export interface StreamChunk {
  /** Optional inferred token delta. */
  readonly tokens?: number;
  /** Optional partial output text (not persisted). */
  readonly content?: string;
  /** Provider-specific raw chunk; not persisted by the SDK. */
  readonly raw?: unknown;
}

export interface ModelCallInput {
  readonly provider: string;
  readonly model: string;
  /**
   * Provider-supplied response identifier surrogate (Anthropic uses
   * ``response.id``; OpenAI uses ``system_fingerprint`` when present).
   * Required for refresh-policy parity with the Python adapter.
   */
  readonly modelSignature: string;
  /** Optional caller-supplied prompt-token count. */
  readonly promptTokens?: number;
  /** When provided, the SDK aggregates tokens + first_token_latency from the stream. */
  readonly stream?: AsyncIterable<StreamChunk>;
  /** Optional caller-supplied non-streaming completion-token count. */
  readonly completionTokens?: number;
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

export interface RunHttpClientOptions {
  baseUrl: string;
  authHeader?: string;
  bearerDigest?: string;
  /** Test-only fetch injection. */
  fetchImpl?: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface RunHttpClient {
  postIngestRun(envelope: IngestRunEnvelope): Promise<Record<string, unknown>>;
  postGateDraft(gateId: string, envelope: GateDraftEnvelope): Promise<Record<string, unknown>>;
  getGateDecision(decisionId: string): Promise<Record<string, unknown>>;
  getRunResult(runId: string): Promise<Record<string, unknown>>;
  postEvidence(envelope: EvidenceEnvelope): Promise<Record<string, unknown>>;
  postReplayCaseRun(
    caseId: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}

/**
 * Default RunHttpClient implementation backed by Node's native fetch.
 *
 * Every POST that creates a resource attaches an ``Idempotency-Key``
 * header carrying a fresh Crockford base32 ULID (VAL-W4-014). Every
 * non-2xx response is parsed for a structured error envelope and
 * surfaced as the appropriate typed exception.
 */
export class FetchRunHttpClient implements RunHttpClient {
  readonly baseUrl: string;
  private readonly authHeader: string | null;
  private readonly bearerDigest: string | null;
  private readonly fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;

  constructor(options: RunHttpClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.authHeader = options.authHeader ?? null;
    this.bearerDigest = options.bearerDigest ?? null;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  private headers(extraIdempotencyKey?: string): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.authHeader !== null) h["X-Relay-Auth"] = this.authHeader;
    if (this.bearerDigest !== null) h["X-Relay-Bearer-Digest"] = this.bearerDigest;
    if (extraIdempotencyKey !== undefined) h["Idempotency-Key"] = extraIdempotencyKey;
    return h;
  }

  private async parseJson(resp: Response): Promise<Record<string, unknown>> {
    try {
      const obj = (await resp.json()) as unknown;
      if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return {};
      return obj as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  private async raiseForError(resp: Response): Promise<void> {
    if (resp.status >= 200 && resp.status < 300) return;
    const body = await this.parseJson(resp);
    const code = String(body["code"] ?? "");
    const message = String(body["message"] ?? `sidecar returned HTTP ${resp.status}`);
    let blockedSurface = typeof body["blocked_surface"] === "string"
      ? (body["blocked_surface"] as string)
      : undefined;
    if (blockedSurface === undefined) {
      try {
        const u = new URL(resp.url);
        blockedSurface = `REQUEST ${u.pathname}`;
      } catch {
        blockedSurface = "relay-sdk";
      }
    }
    const requestId = typeof body["request_id"] === "string" ? (body["request_id"] as string) : null;
    const traceId = typeof body["trace_id"] === "string" ? (body["trace_id"] as string) : null;

    const details: Record<string, unknown> = {
      http_status: resp.status,
      code,
      url: resp.url,
      response_body: body,
    };
    if (code === RELAY_ING_022_CODE || code === RELAY_GATE_021_CODE) {
      // VAL-W4-015 / spec C.5: surface the offending anchor name(s) so
      // callers can attribute stale-handoff failures precisely.
      details["mismatched_anchor"] = body["mismatched_anchor"] ?? [];
    }
    if (code === RELAY_ING_031_CODE) {
      // VAL-W4-010: surface forged_field attribution.
      const detailsBody = body["details"];
      if (detailsBody !== undefined && typeof detailsBody === "object" && detailsBody !== null) {
        const forged = (detailsBody as Record<string, unknown>)["forbidden_field"]
          ?? (detailsBody as Record<string, unknown>)["forged_field"];
        if (forged !== undefined) {
          details["forged_field"] = forged;
        }
      }
    }

    const envelope: ErrorEnvelopeWire = {
      code: code || "RELAY-FUTURE-999",
      http_status: resp.status,
      message,
      ...(blockedSurface !== undefined ? { blocked_surface: blockedSurface } : {}),
      ...(typeof body["retry_advice"] === "string" || (typeof body["retry_advice"] === "object" && body["retry_advice"] !== null)
        ? { retry_advice: body["retry_advice"] }
        : {}),
      request_id: requestId,
      trace_id: traceId,
      details,
    };
    const targetCls = resolveClassForCode(envelope.code);
    // Special-case the canonical-write rejection: surface as the W4
    // adversarial typed leaf RelayCanonicalStatusForbidden by default;
    // tests can sub-class for finer attribution.
    if (envelope.code === RELAY_ING_031_CODE) {
      throw new RelayCanonicalStatusForbidden(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_REPLAY_002_CODE) {
      throw new RelayReplayPrecondition(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_EVID_002_CODE) {
      throw new RelayEvidenceIncomplete(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_ING_022_CODE) {
      throw new RelayHandoffIncomplete(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    // Fall back to namespace intermediate / RelayUnknownError per the
    // resolver. Always surface a typed exception (never a raw Error).
    throw new (targetCls as unknown as { new (m: string, opts: object): RelayError })(message, {
      code: envelope.code || RelayUnknownError.defaultCode,
      httpStatus: resp.status,
      ...(blockedSurface !== undefined ? { blockedSurface } : {}),
      retryAdvice: envelope.retry_advice,
      requestId,
      traceId,
      details,
    });
  }

  async postIngestRun(envelope: IngestRunEnvelope): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/ingest/runs`, {
      method: "POST",
      headers: this.headers(envelope.idempotency_key),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postGateDraft(
    gateId: string,
    envelope: GateDraftEnvelope,
  ): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/gates/${gateId}/drafts`, {
      method: "POST",
      headers: this.headers(envelope.draft_id),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async getGateDecision(decisionId: string): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/gate-decisions/${decisionId}`, {
      method: "GET",
      headers: this.headers(),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async getRunResult(runId: string): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/runs/${runId}/result`, {
      method: "GET",
      headers: this.headers(),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postEvidence(envelope: EvidenceEnvelope): Promise<Record<string, unknown>> {
    const idempotency = newUlid();
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/evidence-bundles`, {
      method: "POST",
      headers: this.headers(idempotency),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postReplayCaseRun(
    caseId: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const idempotency = newUlid();
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/replay-cases/${caseId}/run`, {
      method: "POST",
      headers: this.headers(idempotency),
      body: JSON.stringify(body),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

export interface RunOptions {
  runId?: string;
  agent: Record<string, unknown>;
  /** Optional release_sha mapped from caller-supplied ``version``. */
  releaseSha?: string;
  actorIdentityHash: string;
  manifestCommitHash: string;
  redactionPolicyVersion: string;
  projectId?: string;
  flushPolicy?: FlushPolicy | Partial<{ mode: "sync" | "async"; onError: "raise" | "drop_and_log" }>;
  /** Pre-built HTTP client. Tests can inject a stub here. */
  httpClient: RunHttpClient;
}

export interface ToolCallOptions {
  toolName: string;
  args: unknown;
  sideEffect?: boolean;
  idempotencyKey?: string;
  replayPolicy?: ReplayPolicy;
}

export interface ReplayCreateOptions {
  caseId?: string;
  runId?: string;
  mode?: "cassette" | "live";
  acknowledgeDegradedApproximation?: boolean;
}

/**
 * SDK-side run-scoped lifecycle context (W4.2).
 *
 * Open via :class:`Relay.trace`; release via :meth:`Run.close`. The
 * :class:`Run` instance carries the three-anchor handoff state, the
 * configured flush policy, and the SDK-generated ``run_id``. Per
 * CLAUDE.md invariant #1 the :class:`Run` NEVER writes canonical
 * results -- it submits drafts and reads canonical decisions the
 * control plane writes.
 */
export class Run {
  readonly runId: string;
  readonly traceId: string;
  readonly projectId: string;
  readonly agent: Record<string, unknown>;
  readonly releaseSha: string | undefined;
  readonly actorIdentityHash: string;
  readonly manifestCommitHash: string;
  readonly redactionPolicyVersion: string;
  readonly flushPolicy: FlushPolicy;
  /** Idempotency keys emitted across all envelopes (test seam). */
  readonly idempotencyKeys: string[] = [];
  /** Most recent lifecycle status the SDK observed. */
  private lastStatus: LifecycleStatus = "started";
  private sequenceNumber = 0;
  private readonly httpClient: RunHttpClient;
  private dispatcher: AsyncFlushDispatcher | null = null;
  private closed = false;

  constructor(options: RunOptions) {
    this.runId = options.runId ?? newUlid();
    this.traceId = newUlid();
    this.projectId = options.projectId ?? crypto.randomUUID();
    this.agent = { ...options.agent };
    this.releaseSha = options.releaseSha;
    this.actorIdentityHash = options.actorIdentityHash;
    this.manifestCommitHash = options.manifestCommitHash;
    this.redactionPolicyVersion = options.redactionPolicyVersion;
    this.flushPolicy =
      options.flushPolicy instanceof FlushPolicy
        ? options.flushPolicy
        : FlushPolicy.fromInput(options.flushPolicy);
    this.httpClient = options.httpClient;
  }

  /** Submit a lifecycle-metadata envelope (started/succeeded/failed/aborted). */
  async capture(args: { clientLifecycleStatus: LifecycleStatus }): Promise<Record<string, unknown>> {
    this.lastStatus = args.clientLifecycleStatus;
    return this.submitLifecycle(args.clientLifecycleStatus);
  }

  /**
   * Streaming-aware model_call (VAL-W4-012).
   *
   * Collects stream chunks (or accepts pre-aggregated counts) and emits
   * exactly ONE ``model_call`` span per logical call with summarised
   * fields. Per-chunk events do NOT become separate spans.
   */
  async modelCall(input: ModelCallInput): Promise<ModelCallSpan> {
    const startedAt = utcNowIso8601();
    const startMs = Date.now();
    let chunkCount = 0;
    let completionTokens = input.completionTokens ?? 0;
    let firstTokenLatencyMs: number | null = null;
    if (input.stream !== undefined) {
      for await (const chunk of input.stream) {
        chunkCount += 1;
        if (firstTokenLatencyMs === null) {
          firstTokenLatencyMs = Date.now() - startMs;
        }
        if (typeof chunk.tokens === "number" && Number.isInteger(chunk.tokens)) {
          completionTokens += chunk.tokens;
        }
      }
    } else {
      // Non-streaming: caller-supplied counts.
      completionTokens = input.completionTokens ?? 0;
    }
    const endedAt = utcNowIso8601();
    const span: ModelCallSpan = {
      span_id: newUlid(),
      span_kind: "model_call",
      provider: input.provider,
      model: input.model,
      model_signature: input.modelSignature,
      prompt_tokens: input.promptTokens ?? 0,
      completion_tokens: completionTokens,
      chunk_count: chunkCount,
      first_token_latency_ms: firstTokenLatencyMs,
      started_at: startedAt,
      ended_at: endedAt,
    };
    return span;
  }

  /**
   * Tool-call span (VAL-W4-013).
   *
   * If ``sideEffect: true``, both ``idempotencyKey`` AND ``replayPolicy``
   * MUST be supplied. Missing either raises
   * :class:`RelaySideEffectMissingFieldsError` BEFORE the span opens.
   */
  toolCall(options: ToolCallOptions): ToolCallSpan {
    const sideEffect = options.sideEffect === true;
    if (sideEffect) {
      const missing: string[] = [];
      if (typeof options.idempotencyKey !== "string" || options.idempotencyKey === "") {
        missing.push("idempotencyKey");
      }
      if (
        typeof options.replayPolicy !== "string" ||
        !REPLAY_POLICIES.has(options.replayPolicy)
      ) {
        missing.push("replayPolicy");
      }
      if (missing.length > 0) {
        throw new RelaySideEffectMissingFieldsError(
          `tool_call with side_effect: true requires both idempotencyKey AND replayPolicy; missing: ${JSON.stringify(missing)}`,
          {
            code: RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE,
            details: {
              missing_fields: missing,
              tool_name: options.toolName,
              side_effect: true,
            },
          },
        );
      }
    }
    const startedAt = utcNowIso8601();
    const argsDigest = digestArgs(options.args);
    const endedAt = utcNowIso8601();
    const span: ToolCallSpan = {
      span_id: newUlid(),
      span_kind: "tool_call",
      tool_name: options.toolName,
      side_effect: sideEffect,
      ...(sideEffect
        ? {
            idempotency_key: options.idempotencyKey as string,
            replay_policy: options.replayPolicy as ReplayPolicy,
          }
        : {}),
      args_digest: argsDigest,
      started_at: startedAt,
      ended_at: endedAt,
    };
    return span;
  }

  /**
   * Submit a gate-decision DRAFT and read the canonical decision
   * (VAL-W4-015). The SDK NEVER computes pass/fail.
   */
  async gateEvaluate(args: {
    gateId: string;
    releaseSha: string;
    evalRunIds: string[];
    workerId?: string;
    scopeType?: string;
    round?: number;
    evidenceRefs?: string[];
  }): Promise<{ envelope: GateDraftEnvelope; decision: Record<string, unknown> }> {
    const envelope = buildGateDraftEnvelope({
      gateId: args.gateId,
      releaseSha: args.releaseSha,
      evalRunIds: args.evalRunIds,
      manifestCommitHash: this.manifestCommitHash,
      actorIdentityHash: this.actorIdentityHash,
      ...(args.workerId !== undefined ? { workerId: args.workerId } : {}),
      ...(args.scopeType !== undefined ? { scopeType: args.scopeType } : {}),
      ...(args.round !== undefined ? { round: args.round } : {}),
      ...(args.evidenceRefs !== undefined ? { evidenceRefs: args.evidenceRefs } : {}),
    });
    this.idempotencyKeys.push(envelope.draft_id);
    const draftResp = await this.httpClient.postGateDraft(args.gateId, envelope);
    const decisionId =
      (typeof draftResp["decision_id"] === "string" && (draftResp["decision_id"] as string)) ||
      (typeof draftResp["draft_id"] === "string" && (draftResp["draft_id"] as string));
    if (!decisionId) {
      throw new RelayError("sidecar gate draft response omitted decision_id", {
        details: { response: draftResp },
      });
    }
    const decision = await this.httpClient.getGateDecision(decisionId);
    return { envelope, decision };
  }

  /**
   * Create a replay case bound to the canonical RunResult (VAL-W4-017).
   *
   * Defaults to cassette mode. Live mode requires the caller to opt in
   * via ``{mode: 'live', acknowledgeDegradedApproximation: true}``.
   */
  async replayCreate(options: ReplayCreateOptions = {}): Promise<Record<string, unknown>> {
    const mode: "cassette" | "live" = options.mode ?? "cassette";
    if (mode !== "cassette" && mode !== "live") {
      throw new RelayConfigError(
        `replay mode must be 'cassette' or 'live'; received ${JSON.stringify(mode)}`,
        { details: { field: "mode", received: mode } },
      );
    }
    if (mode === "live" && options.acknowledgeDegradedApproximation !== true) {
      throw new RelayReplayLiveModeUnacknowledgedError(
        "live replay is a degraded approximation; pass {mode: 'live', acknowledgeDegradedApproximation: true} to opt in",
        {
          code: RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
          details: {
            mode: "live",
            acknowledge_required: true,
          },
        },
      );
    }
    const caseId = options.caseId ?? newUlid();
    const runIdRef = options.runId ?? this.runId;
    // Pre-flight: confirm the canonical RunResult exists (parity with
    // Python, spec line 2122-2178). The sidecar returns RELAY-REPLAY-002
    // when the run is still in flight; raiseForError() surfaces it as
    // RelayReplayPrecondition.
    await this.httpClient.getRunResult(runIdRef);
    const body = {
      schema_version: "relay.replay_case.run.v1",
      case_id: caseId,
      run_id: runIdRef,
      mode,
      manifest_commit_hash: this.manifestCommitHash,
      actor_identity_hash: this.actorIdentityHash,
      ...(mode === "live"
        ? { acknowledge_degraded_approximation: true }
        : {}),
    };
    return this.httpClient.postReplayCaseRun(caseId, body);
  }

  /**
   * Submit an evidence-bundle envelope bound to its claim (VAL-W4-016).
   *
   * Per CLAUDE.md invariant #2 every required field MUST be present and
   * bound. A missing field raises :class:`RelayEvidenceIncomplete` at
   * the SDK boundary BEFORE the request is sent. The wire payload
   * carries metadata + content digests only -- never plaintext.
   */
  async submitEvidence(args: {
    artifactDigestSha256: string;
    commandId: string;
    exitCode: number;
    spanIds: string[];
    assertionIds: string[];
    runId?: string;
  }): Promise<{ envelope: EvidenceEnvelope; response: Record<string, unknown> }> {
    const envelope = buildEvidenceEnvelope({
      runId: args.runId ?? this.runId,
      artifactDigestSha256: args.artifactDigestSha256,
      commandId: args.commandId,
      exitCode: args.exitCode,
      spanIds: args.spanIds,
      assertionIds: args.assertionIds,
      actorIdentityHash: this.actorIdentityHash,
      manifestCommitHash: this.manifestCommitHash,
      redactionPolicyVersion: this.redactionPolicyVersion,
    });
    const response = await this.httpClient.postEvidence(envelope);
    return { envelope, response };
  }

  /** Wait for any background-dispatched work to drain (test seam). */
  async flush(): Promise<void> {
    if (this.dispatcher !== null) {
      await this.dispatcher.waitIdle();
    }
  }

  /**
   * Release SDK-side resources. Submits the terminal lifecycle envelope
   * per the configured flush policy. Per VAL-W4-018, async mode does
   * NOT block on outbound HTTP I/O.
   */
  async close(args: { exception?: unknown } = {}): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    let terminal: LifecycleStatus;
    if (args.exception !== undefined && this.lastStatus === "started") {
      terminal = "client_failed";
    } else if (this.lastStatus === "started") {
      terminal = "client_succeeded";
    } else {
      terminal = this.lastStatus;
    }
    try {
      await this.submitLifecycle(terminal);
    } finally {
      // Release the dispatcher; do not block in async mode.
      if (this.dispatcher !== null) {
        // Best-effort drain in async/drop_and_log; in sync mode this
        // is a no-op because no work was enqueued.
        if (this.flushPolicy.mode === "sync") {
          await this.dispatcher.close();
        } else {
          // Fire-and-forget close: do not await the chain here so the
          // caller's close() returns immediately (VAL-W4-018).
          void this.dispatcher.close();
        }
      }
    }
  }

  // -- internals ---------------------------------------------------------

  private async submitLifecycle(
    clientLifecycleStatus: LifecycleStatus,
  ): Promise<Record<string, unknown>> {
    this.sequenceNumber += 1;
    const envelope = buildIngestRunEnvelope({
      runId: this.runId,
      traceId: this.traceId,
      projectId: this.projectId,
      agent: this.agent,
      clientLifecycleStatus,
      startedAt: utcNowIso8601(),
      sdkVersion: SDK_VERSION,
      sdkClock: utcNowIso8601(),
      manifestCommitHash: this.manifestCommitHash,
      actorIdentityHash: this.actorIdentityHash,
      redactionPolicyVersion: this.redactionPolicyVersion,
      sequenceNumber: this.sequenceNumber,
    });
    this.idempotencyKeys.push(envelope.idempotency_key);
    if (this.flushPolicy.mode === "sync") {
      try {
        return await this.httpClient.postIngestRun(envelope);
      } catch (err) {
        if (this.flushPolicy.onError === "drop_and_log") {
          // VAL-W4-018: emit one structured stderr envelope and swallow.
          try {
            process.stderr.write(
              `${JSON.stringify({
                schema_version: "relay.error.v1",
                level: "warning",
                code: "RELAY-SDK-FLUSH-DROP-AND-LOG",
                message: err instanceof Error ? err.message : String(err),
                error_class: err instanceof Error ? err.name : "UnknownError",
                details: {
                  on_error: "drop_and_log",
                  run_id: this.runId,
                  sequence_number: envelope.sequence_number,
                },
              })}\n`,
            );
          } catch {
            // Stderr write must never throw into host application.
          }
          return { dropped: true, idempotent_replay: false };
        }
        throw err;
      }
    }
    // async path -- enqueue and return immediately.
    const dispatcher = this.ensureDispatcher();
    dispatcher.submit(async () => {
      await this.httpClient.postIngestRun(envelope);
    });
    return {
      queued: true,
      idempotent_replay: false,
      idempotency_key: envelope.idempotency_key,
    };
  }

  private ensureDispatcher(): AsyncFlushDispatcher {
    if (this.dispatcher === null) {
      this.dispatcher = new AsyncFlushDispatcher({ onError: this.flushPolicy.onError });
    }
    return this.dispatcher;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function digestArgs(args: unknown): string {
  let serialised: string;
  try {
    serialised = JSON.stringify(args ?? null);
  } catch {
    serialised = String(args);
  }
  return "sha256-" + crypto.createHash("sha256").update(serialised, "utf8").digest("hex");
}
