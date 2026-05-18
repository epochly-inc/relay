/**
 * Audit R3 P1 misc fix -- TS gate-draft optional-field validation parity.
 *
 * Covers BUG-E1: ``buildGateDraftEnvelope`` MUST validate optional
 * ``workerId``, ``scopeType``, ``evidenceRefs`` and coerce ``round``
 * exactly as the Python SDK's ``build_gate_draft_envelope``
 * (sdk-python/relay/lifecycle.py:367-377) does.
 *
 * Pre-fix the TS SDK accepted ``workerId: ""``, non-Array ``evidenceRefs``,
 * and ``round: NaN`` -- producing envelopes the Python SDK would reject
 * with a structured error. This test pins the new validation surface
 * so the two SDKs stay byte-equal under JCS canonicalisation.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { buildGateDraftEnvelope } from "../src/lifecycle.js";

const BASE_ARGS = {
  gateId: "gate-1",
  releaseSha: "deadbeef".repeat(8),
  evalRunIds: ["eval-run-1"],
  actorIdentityHash: "a".repeat(64),
  manifestCommitHash: "b".repeat(64),
  draftId: "DRAFT-1",
};

describe("buildGateDraftEnvelope optional-field validation (BUG-E1)", () => {
  it("rejects empty workerId", () => {
    expect(() =>
      buildGateDraftEnvelope({ ...BASE_ARGS, workerId: "" }),
    ).toThrow(/worker_id/);
  });

  it("rejects empty scopeType", () => {
    expect(() =>
      buildGateDraftEnvelope({ ...BASE_ARGS, scopeType: "" }),
    ).toThrow(/scope_type/);
  });

  it("rejects evidenceRefs that is not an Array", () => {
    expect(() =>
      buildGateDraftEnvelope({
        ...BASE_ARGS,
        // Force the non-array path; cast bypasses TS structural typing.
        evidenceRefs: "not-an-array" as unknown as ReadonlyArray<string>,
      }),
    ).toThrow(/evidence_refs/);
  });

  it("rejects empty-string entries inside evidenceRefs", () => {
    expect(() =>
      buildGateDraftEnvelope({
        ...BASE_ARGS,
        evidenceRefs: ["valid", ""],
      }),
    ).toThrow(/evidence_ref/);
  });

  it("rejects NaN round", () => {
    expect(() =>
      buildGateDraftEnvelope({
        ...BASE_ARGS,
        round: Number.NaN,
      }),
    ).toThrow(/round/);
  });

  it("rejects Infinity round", () => {
    expect(() =>
      buildGateDraftEnvelope({
        ...BASE_ARGS,
        round: Number.POSITIVE_INFINITY,
      }),
    ).toThrow(/round/);
  });

  it("rejects negative round after truncation", () => {
    expect(() =>
      buildGateDraftEnvelope({ ...BASE_ARGS, round: -1 }),
    ).toThrow(/round/);
  });

  it("truncates fractional round via Math.trunc (matches Python int())", () => {
    const envelope = buildGateDraftEnvelope({ ...BASE_ARGS, round: 3.7 });
    expect(envelope.round).toBe(3);
  });

  it("accepts a well-formed envelope with all optionals populated", () => {
    const envelope = buildGateDraftEnvelope({
      ...BASE_ARGS,
      workerId: "worker-1",
      scopeType: "run",
      round: 0,
      evidenceRefs: ["run-results:1", "evidence_bundles:1"],
    });
    expect(envelope.worker_id).toBe("worker-1");
    expect(envelope.scope_type).toBe("run");
    expect(envelope.round).toBe(0);
    expect(envelope.evidence_refs).toEqual([
      "run-results:1",
      "evidence_bundles:1",
    ]);
  });
});
