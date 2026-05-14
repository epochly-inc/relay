/**
 * W4.2 streaming model_call + side-effect tool_call tests
 * (VAL-W4-012, VAL-W4-013).
 *
 * VAL-W4-012: streaming-aware modelCall emits exactly ONE span per
 *             logical call with token deltas summarised; per-chunk
 *             events do NOT become separate spans.
 *
 * VAL-W4-013: toolCall with sideEffect: true requires both
 *             idempotencyKey AND replayPolicy. Missing either throws
 *             RelaySideEffectMissingFieldsError BEFORE the span opens.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import {
  RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE,
  RelaySideEffectMissingFieldsError,
} from "../src/errors.js";
import { Run, type RunHttpClient } from "../src/run.js";

const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

class StubHttpClient implements RunHttpClient {
  postIngestRun = async () => ({ accepted: true });
  postGateDraft = async () => ({ decision_id: "dec-001" });
  getGateDecision = async () => ({ decision: "accepted" });
  getRunResult = async () => ({ run_result_id: "rr-001" });
  postEvidence = async () => ({ stored: true });
  postReplayCaseRun = async () => ({ replayed: true });
}

function makeRun(): Run {
  return new Run({
    agent: VALID_AGENT,
    actorIdentityHash: VALID_ACTOR,
    manifestCommitHash: VALID_MANIFEST,
    redactionPolicyVersion: "v1",
    flushPolicy: { mode: "sync", onError: "raise" },
    httpClient: new StubHttpClient(),
  });
}

describe("VAL-W4-012: streaming model_call emits ONE span with token deltas summarised", () => {
  it("a 50-chunk stream yields a single span with chunk_count=50 and aggregated tokens", async () => {
    const run = makeRun();
    async function* fiftyChunks() {
      for (let i = 0; i < 50; i++) {
        yield { tokens: 1, content: "tok" + i };
      }
    }
    const span = await run.modelCall({
      provider: "openai",
      model: "gpt-test",
      modelSignature: "fp-1234",
      promptTokens: 7,
      stream: fiftyChunks(),
    });
    expect(span.span_kind).toBe("model_call");
    expect(span.chunk_count).toBe(50);
    expect(span.completion_tokens).toBe(50);
    expect(span.prompt_tokens).toBe(7);
    expect(span.model_signature).toBe("fp-1234");
    expect(span.first_token_latency_ms).not.toBeNull();
    await run.close();
  });

  it("non-streaming model_call uses caller-supplied completionTokens and chunk_count=0", async () => {
    const run = makeRun();
    const span = await run.modelCall({
      provider: "anthropic",
      model: "claude-test",
      modelSignature: "msg-id-abc",
      promptTokens: 12,
      completionTokens: 34,
    });
    expect(span.chunk_count).toBe(0);
    expect(span.first_token_latency_ms).toBeNull();
    expect(span.completion_tokens).toBe(34);
    expect(span.prompt_tokens).toBe(12);
    await run.close();
  });

  it("an empty stream still produces a single well-formed span", async () => {
    const run = makeRun();
    async function* empty() {
      // intentionally empty
      if (false) yield { tokens: 0 };
    }
    const span = await run.modelCall({
      provider: "openai",
      model: "gpt-test",
      modelSignature: "fp-empty",
      stream: empty(),
    });
    expect(span.chunk_count).toBe(0);
    expect(span.completion_tokens).toBe(0);
    expect(span.first_token_latency_ms).toBeNull();
    await run.close();
  });
});

describe("VAL-W4-013: tool_call sideEffect requires idempotencyKey AND replayPolicy", () => {
  it("toolCall({sideEffect: true}) without idempotencyKey + replayPolicy throws", () => {
    const run = makeRun();
    let raised: unknown;
    try {
      run.toolCall({ toolName: "send_email", args: { to: "x@y.z" }, sideEffect: true });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(RelaySideEffectMissingFieldsError);
    const err = raised as RelaySideEffectMissingFieldsError;
    expect(err.code).toBe(RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE);
    const missing = err.details["missing_fields"] as string[];
    expect(missing).toContain("idempotencyKey");
    expect(missing).toContain("replayPolicy");
  });

  it("toolCall({sideEffect: true, idempotencyKey: 'x'}) without replayPolicy throws", () => {
    const run = makeRun();
    expect(() =>
      run.toolCall({
        toolName: "send_email",
        args: {},
        sideEffect: true,
        idempotencyKey: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      }),
    ).toThrowError(RelaySideEffectMissingFieldsError);
  });

  it("toolCall({sideEffect: true, replayPolicy: 'replay_in_sandbox'}) without idempotencyKey throws", () => {
    const run = makeRun();
    expect(() =>
      run.toolCall({
        toolName: "send_email",
        args: {},
        sideEffect: true,
        replayPolicy: "replay_in_sandbox",
      }),
    ).toThrowError(RelaySideEffectMissingFieldsError);
  });

  it("toolCall({sideEffect: true, idempotencyKey, replayPolicy}) succeeds", () => {
    const run = makeRun();
    const span = run.toolCall({
      toolName: "send_email",
      args: { to: "x@y.z" },
      sideEffect: true,
      idempotencyKey: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
      replayPolicy: "replay_in_sandbox",
    });
    expect(span.span_kind).toBe("tool_call");
    expect(span.side_effect).toBe(true);
    expect(span.idempotency_key).toBe("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    expect(span.replay_policy).toBe("replay_in_sandbox");
  });

  it("toolCall without sideEffect does NOT require idempotencyKey or replayPolicy", () => {
    const run = makeRun();
    const span = run.toolCall({
      toolName: "calculator",
      args: { a: 1, b: 2 },
    });
    expect(span.span_kind).toBe("tool_call");
    expect(span.side_effect).toBe(false);
    expect(span.idempotency_key).toBeUndefined();
    expect(span.replay_policy).toBeUndefined();
  });

  it("invalid replayPolicy enum value is treated as missing", () => {
    const run = makeRun();
    expect(() =>
      run.toolCall({
        toolName: "send_email",
        args: {},
        sideEffect: true,
        idempotencyKey: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        replayPolicy: "not_a_real_policy" as never,
      }),
    ).toThrowError(RelaySideEffectMissingFieldsError);
  });
});
