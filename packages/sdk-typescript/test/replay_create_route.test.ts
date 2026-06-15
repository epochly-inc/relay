/**
 * Run.replayCreate routes against the real sidecar contract (roborev HIGH
 * follow-on on the round-2 #10 route fix; Py<->TS parity with run.py
 * replay_create).
 *
 * The sidecar run endpoint POST /v1/replay-cases/{case_id}/run returns 404
 * for a case it never created. So replayCreate WITHOUT an explicit caseId must
 * CREATE the case first (POST /v1/replay-cases with from_run_id) and run the
 * id the sidecar returns -- generating a client-side id and POSTing straight
 * to /run (the prior behaviour) 404s end-to-end. An explicit caseId runs that
 * case directly with NO create POST.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import { Run, type RunHttpClient } from "../src/run.js";

const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";

class RecordingHttpClient implements RunHttpClient {
  createCalls: Array<Record<string, unknown>> = [];
  runCalls: Array<{ caseId: string; body: Record<string, unknown> }> = [];
  callOrder: string[] = [];
  postIngestRun = async () => ({ accepted: true });
  postGateDraft = async () => ({ decision_id: "dec-001" });
  getGateDecision = async () => ({ decision: "accepted" });
  getRunResult = async () => {
    this.callOrder.push("getRunResult");
    return { run_result_id: "rr-001", run_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV" };
  };
  postEvidence = async () => ({ stored: true });
  postReplayCaseCreate = async (body: Record<string, unknown>) => {
    this.callOrder.push("create");
    this.createCalls.push(body);
    return { replay_case_id: "01CASECREATEDBYSIDECAR0001" };
  };
  postReplayCaseRun = async (caseId: string, body: Record<string, unknown>) => {
    this.callOrder.push(`run:${caseId}`);
    this.runCalls.push({ caseId, body });
    return { replayed: true, mode: body["mode"] };
  };
}

function makeRun(stub: RunHttpClient): Run {
  return new Run({
    agent: { name: "ops-agent", version: "0.1.0" },
    actorIdentityHash: VALID_ACTOR,
    manifestCommitHash: VALID_MANIFEST,
    redactionPolicyVersion: "v1",
    flushPolicy: { mode: "sync", onError: "raise" },
    httpClient: stub,
  });
}

describe("Run.replayCreate sidecar-contract routing", () => {
  it("with no caseId: getRunResult -> create -> run(returned id), in order", async () => {
    const stub = new RecordingHttpClient();
    const run = makeRun(stub);
    await run.replayCreate({ runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    // Created the case before running it.
    expect(stub.createCalls.length).toBe(1);
    expect(stub.createCalls[0]?.["from_run_id"]).toBe("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    // Ran the id the SIDECAR returned, not a client-invented one.
    expect(stub.runCalls.length).toBe(1);
    expect(stub.runCalls[0]?.caseId).toBe("01CASECREATEDBYSIDECAR0001");
    expect(stub.runCalls[0]?.body["case_id"]).toBe("01CASECREATEDBYSIDECAR0001");
    // Ordering: preflight, create, run.
    expect(stub.callOrder).toEqual([
      "getRunResult",
      "create",
      "run:01CASECREATEDBYSIDECAR0001",
    ]);
    await run.close();
  });

  it("with an explicit caseId: runs that case directly, NO create POST", async () => {
    const stub = new RecordingHttpClient();
    const run = makeRun(stub);
    await run.replayCreate({ caseId: "caller-owned-case", runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
    expect(stub.createCalls.length).toBe(0);
    expect(stub.runCalls.length).toBe(1);
    expect(stub.runCalls[0]?.caseId).toBe("caller-owned-case");
    expect(stub.callOrder).toEqual(["getRunResult", "run:caller-owned-case"]);
    await run.close();
  });
});
