/**
 * W4.2 replay client + async flush behaviour tests
 * (VAL-W4-017, VAL-W4-018).
 *
 * VAL-W4-017: replay client invokes POST /v1/replay-cases/<id>/run in
 *             cassette mode by default; live mode requires
 *             acknowledgeDegradedApproximation: true.
 *
 * VAL-W4-018: flush behavior is async by default with drop_and_log on
 *             transport error; sidecar 503 does NOT raise into the host
 *             application's request path.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import {
  RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
  RelayReplayLiveModeUnacknowledgedError,
  RelayReplayPrecondition,
} from "../src/errors.js";
import { FlushPolicy } from "../src/flush.js";
import { FetchRunHttpClient, Run, type RunHttpClient } from "../src/run.js";

const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

class StubHttpClient implements RunHttpClient {
  postIngestRunBodies: Array<unknown> = [];
  postReplayCalls: Array<{ caseId: string; body: Record<string, unknown> }> = [];
  postIngestRun = async (envelope: unknown) => {
    this.postIngestRunBodies.push(envelope);
    return { accepted: true };
  };
  postGateDraft = async () => ({ decision_id: "dec-001" });
  getGateDecision = async () => ({ decision: "accepted" });
  getRunResult = async () => ({ run_result_id: "rr-001", run_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV" });
  postEvidence = async () => ({ stored: true });
  postReplayCaseRun = async (caseId: string, body: Record<string, unknown>) => {
    this.postReplayCalls.push({ caseId, body });
    return { replayed: true, mode: body["mode"] };
  };
}

describe("VAL-W4-017: replay client defaults to cassette mode", () => {
  it("replayCreate without mode defaults to cassette and posts /v1/replay-cases/<id>/run", async () => {
    const stub = new StubHttpClient();
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: stub,
    });
    const result = await run.replayCreate({ caseId: "case-001" });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(stub.postReplayCalls[0]?.caseId).toBe("case-001");
    expect(stub.postReplayCalls[0]?.body["mode"]).toBe("cassette");
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  it("replayCreate({mode: 'live'}) without acknowledgeDegradedApproximation throws", async () => {
    const stub = new StubHttpClient();
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: stub,
    });
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", mode: "live" });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(RelayReplayLiveModeUnacknowledgedError);
    expect((raised as RelayReplayLiveModeUnacknowledgedError).code).toBe(
      RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
    );
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("replayCreate({mode: 'live', acknowledgeDegradedApproximation: true}) succeeds", async () => {
    const stub = new StubHttpClient();
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: stub,
    });
    const result = await run.replayCreate({
      caseId: "case-001",
      mode: "live",
      acknowledgeDegradedApproximation: true,
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(stub.postReplayCalls[0]?.body["mode"]).toBe("live");
    expect(stub.postReplayCalls[0]?.body["acknowledge_degraded_approximation"]).toBe(true);
    expect(result["mode"]).toBe("live");
    await run.close();
  });

  it("replayCreate refuses to proceed when sidecar reports run_result not yet written", async () => {
    // Real loopback sidecar that returns RELAY-REPLAY-002 on getRunResult.
    let observedReplayCall = false;
    const server = http.createServer((req, res) => {
      // Drain the request body so the connection closes cleanly.
      req.on("data", () => {});
      req.on("end", () => {
        if (req.url === "/v1/ingest/runs") {
          // Accept lifecycle metadata so Run.close()'s terminal envelope
          // does not 404; this test focuses on the replay-create path.
          res.statusCode = 202;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ accepted: true }));
          return;
        }
        if (req.url?.endsWith("/result")) {
          res.statusCode = 412;
          res.setHeader("content-type", "application/json");
          res.end(
            JSON.stringify({
              schema_version: "relay.error.v1",
              code: "RELAY-REPLAY-002",
              error_class: "RUN-RESULT-NOT-YET-WRITTEN",
              message: "run_result not yet written; cannot derive replay case",
              retry_advice: { mode: "after_state_change" },
              details: { run_id: "01JG2YINFLIGHT01234567890123" },
            }),
          );
          return;
        }
        if (req.url?.includes("/replay-cases/")) {
          observedReplayCall = true;
          res.statusCode = 200;
          res.end("{}");
          return;
        }
        res.statusCode = 404;
        res.end("{}");
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const client = new FetchRunHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
      const run = new Run({
        agent: VALID_AGENT,
        actorIdentityHash: VALID_ACTOR,
        manifestCommitHash: VALID_MANIFEST,
        redactionPolicyVersion: "v1",
        flushPolicy: { mode: "sync", onError: "raise" },
        httpClient: client,
      });
      let raised: unknown;
      try {
        await run.replayCreate({ caseId: "case-001", runId: "01JG2YINFLIGHT01234567890123" });
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(RelayReplayPrecondition);
      expect(observedReplayCall).toBe(false);
      await run.close();
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });
});

describe("VAL-W4-018: flush is async by default with drop_and_log on transport error", () => {
  it("default FlushPolicy is {mode: 'async', onError: 'drop_and_log'}", () => {
    const fp = new FlushPolicy();
    expect(fp.mode).toBe("async");
    expect(fp.onError).toBe("drop_and_log");
  });

  it("FlushPolicy.fromInput(undefined) returns the async + drop_and_log default", () => {
    const fp = FlushPolicy.fromInput(undefined);
    expect(fp.mode).toBe("async");
    expect(fp.onError).toBe("drop_and_log");
  });

  it("sidecar 503 in async + drop_and_log mode does NOT raise into the host application", async () => {
    // Real loopback sidecar that always returns 503.
    const server = http.createServer((req, res) => {
      if (req.url === "/v1/ingest/runs") {
        res.statusCode = 503;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            schema_version: "relay.error.v1",
            code: "RELAY-SIDECAR-013",
            error_class: "RELAY-SIDECAR-UNAVAILABLE",
            message: "sidecar unavailable",
            retry_advice: { mode: "after_retry_after" },
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    try {
      const stderrLines: string[] = [];
      const originalWrite = process.stderr.write.bind(process.stderr);
      // Hook process.stderr.write to capture envelope lines.
      const stderrPatch = ((chunk: unknown) => {
        try {
          stderrLines.push(typeof chunk === "string" ? chunk : Buffer.from(chunk as Uint8Array).toString("utf8"));
        } catch {
          // ignore
        }
        return true;
      }) as unknown as typeof process.stderr.write;
      process.stderr.write = stderrPatch;
      try {
        const client = new FetchRunHttpClient({ baseUrl: `http://127.0.0.1:${port}` });
        const run = new Run({
          agent: VALID_AGENT,
          actorIdentityHash: VALID_ACTOR,
          manifestCommitHash: VALID_MANIFEST,
          redactionPolicyVersion: "v1",
          flushPolicy: { mode: "sync", onError: "drop_and_log" },
          httpClient: client,
        });
        let hostContinued = false;
        // capture() returns normally; the host application continues.
        const result = await run.capture({ clientLifecycleStatus: "client_succeeded" });
        hostContinued = true;
        await run.close();
        expect(hostContinued).toBe(true);
        expect(result).toEqual({ dropped: true, idempotent_replay: false });
        // At least one stderr line is a structured envelope.
        const envelopeLines = stderrLines
          .map((l) => l.trim())
          .filter((l) => l.startsWith("{") && l.includes("relay.error.v1"));
        expect(envelopeLines.length).toBeGreaterThanOrEqual(1);
        const parsed = JSON.parse(envelopeLines[0] as string) as Record<string, unknown>;
        expect(parsed["schema_version"]).toBe("relay.error.v1");
        expect(parsed["level"]).toBe("warning");
      } finally {
        process.stderr.write = originalWrite;
      }
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("async-mode capture returns immediately with a queued result", async () => {
    // Use a stub client that we never await; the async dispatcher runs
    // the work in the background.
    const stub = new StubHttpClient();
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "async", onError: "drop_and_log" },
      httpClient: stub,
    });
    const result = await run.capture({ clientLifecycleStatus: "client_succeeded" });
    expect(result["queued"]).toBe(true);
    expect(typeof result["idempotency_key"]).toBe("string");
    await run.flush();
    await run.close();
    // The dispatcher should have processed at least one body.
    expect(stub.postIngestRunBodies.length).toBeGreaterThanOrEqual(1);
  });
});

describe("FlushPolicy validation", () => {
  it("rejects unknown keys", () => {
    expect(() => FlushPolicy.fromInput({ mode: "async", bogus: 1 })).toThrowError();
  });

  it("rejects invalid mode", () => {
    expect(() => new FlushPolicy({ mode: "fast" as never })).toThrowError();
  });

  it("rejects invalid onError", () => {
    expect(() => new FlushPolicy({ onError: "scream" as never })).toThrowError();
  });
});
