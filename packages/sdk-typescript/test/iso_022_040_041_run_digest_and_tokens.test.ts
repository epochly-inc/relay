/**
 * Bug-hunt isolated findings VAL-ISO-022 / VAL-ISO-040 / VAL-ISO-041.
 *
 * All three defects live in packages/sdk-typescript/src/run.ts.
 *
 * VAL-ISO-022 (determinism): digestArgs() hashed tool-call arguments with
 *   plain JSON.stringify, which serializes object keys in insertion order.
 *   Two processes/SDKs that build the same logical args in a different key
 *   order therefore produced different args_digest values, so the spans were
 *   treated as different evidence and cross-SDK/replay determinism broke. The
 *   fix routes args through the RFC 8785 JCS canonicalizer
 *   (_canonicalJsonStringify in redaction.ts: sorted keys, compact
 *   separators), matching the Python SDK's
 *   json.dumps(..., sort_keys=True, separators=(",", ":")).
 *
 * VAL-ISO-040 (correctness): modelCall initialized the completion-token
 *   accumulator to input.completionTokens and then ADDED each stream chunk's
 *   token delta to that same base. A caller that supplied both
 *   completionTokens (a pre-aggregated count) AND a stream got
 *   base + sum(chunk deltas) -- a double count. The streaming branch now
 *   starts the accumulator from 0 and ignores the caller's completionTokens.
 *
 * VAL-ISO-041 (correctness): on JSON.stringify failure (circular reference,
 *   BigInt, etc.) digestArgs fell back to String(args), which is the constant
 *   "[object Object]" for any non-primitive object. Every unserializable
 *   tool-call arg therefore hashed to the SAME content-free, collision-prone
 *   digest. The fix raises a typed RelayConfigError instead of producing a
 *   colliding digest. String(args) is no longer used anywhere.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { RelayConfigError } from "../src/errors.js";
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

describe("VAL-ISO-022: tool_call args_digest is canonical (key-order independent, JCS)", () => {
  it("identical logical args in different key order produce the same args_digest", () => {
    const run = makeRun();
    const a = run.toolCall({ toolName: "calc", args: { a: 1, b: 2, c: { z: 9, y: 8 } } });
    const b = run.toolCall({ toolName: "calc", args: { c: { y: 8, z: 9 }, b: 2, a: 1 } });
    expect(a.args_digest).toBe(b.args_digest);
  });

  it("args_digest byte-matches the Python canonical form (sort_keys + compact separators)", () => {
    const run = makeRun();
    const span = run.toolCall({ toolName: "calc", args: { b: 2, a: 1 } });
    // Python: json.dumps({"b":2,"a":1}, sort_keys=True, separators=(",", ":"))
    // == '{"a":1,"b":2}'. The digest must be sha256 of that exact byte string.
    const canonical = '{"a":1,"b":2}';
    const expected =
      "sha256-" + createHash("sha256").update(canonical, "utf8").digest("hex");
    expect(span.args_digest).toBe(expected);
  });
});

describe("VAL-ISO-040: modelCall does not double-count completion tokens on the stream path", () => {
  it("stream + completionTokens both supplied: completion tokens counted once (from the stream)", async () => {
    const run = makeRun();
    async function* fiveOnes() {
      for (let i = 0; i < 5; i++) {
        yield { tokens: 1, content: "t" + i };
      }
    }
    const span = await run.modelCall({
      provider: "openai",
      model: "gpt-test",
      modelSignature: "fp-iso040",
      promptTokens: 7,
      completionTokens: 100, // pre-aggregated count the caller also passes
      stream: fiveOnes(),
    });
    // Stream yields 5 tokens. The pre-aggregated 100 must NOT be added on top.
    expect(span.chunk_count).toBe(5);
    expect(span.completion_tokens).toBe(5);
    await run.close();
  });
});

describe("VAL-ISO-041: digestArgs rejects unserializable args instead of colliding", () => {
  it("distinct circular args objects raise RelayConfigError (no shared '[object Object]' digest)", () => {
    const run = makeRun();

    const circularA: Record<string, unknown> = { kind: "A" };
    circularA["self"] = circularA;
    const circularB: Record<string, unknown> = { kind: "B" };
    circularB["self"] = circularB;

    expect(() => run.toolCall({ toolName: "x", args: circularA })).toThrowError(
      RelayConfigError,
    );
    expect(() => run.toolCall({ toolName: "x", args: circularB })).toThrowError(
      RelayConfigError,
    );
  });

  it("BigInt args (JSON-unserializable) raise RelayConfigError rather than collapsing to a digest", () => {
    const run = makeRun();
    expect(() =>
      run.toolCall({ toolName: "x", args: { id: 9007199254740993n } as unknown }),
    ).toThrowError(RelayConfigError);
  });
});
