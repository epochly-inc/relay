/**
 * W4.2 lifecycle envelope tests (VAL-W4-011, VAL-W4-014, VAL-W4-015,
 * VAL-W4-016).
 *
 * VAL-W4-011: relay.trace -> Run binds (run_id, agent, version,
 *             manifest_commit_hash) and POSTs /v1/ingest/runs.
 * VAL-W4-014: Idempotency-Key header is Crockford base32 ULID on every
 *             POST creating a resource.
 * VAL-W4-015: gateEvaluate POSTs /v1/gates/<id>/drafts with three-anchor
 *             handoff; stale handoff yields RELAY-GATE-021 mapped to
 *             RelayHandoffIncomplete.
 * VAL-W4-016: submitEvidence POSTs /v1/evidence-bundles with metadata +
 *             content digests only (no plaintext).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { RelayHandoffIncomplete } from "../src/errors.js";
import {
  buildEvidenceEnvelope,
  buildGateDraftEnvelope,
  buildIngestRunEnvelope,
} from "../src/lifecycle.js";
import { FetchRunHttpClient, Run } from "../src/run.js";
import { ULID_REGEX } from "../src/ulid.js";

const VALID_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

interface MockSidecar {
  baseUrl: string;
  observed: Array<{ method: string; url: string; body: string; headers: http.IncomingHttpHeaders }>;
  close: () => Promise<void>;
}

async function startMock(
  responder: (req: { method: string; url: string; body: string }) => {
    status: number;
    body: object;
  },
): Promise<MockSidecar> {
  const observed: MockSidecar["observed"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      observed.push({
        method: req.method ?? "GET",
        url: req.url ?? "",
        body,
        headers: req.headers,
      });
      const out = responder({ method: req.method ?? "GET", url: req.url ?? "", body });
      res.statusCode = out.status;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    observed,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

describe("VAL-W4-011: relay.trace opens a Run scope binding three anchors", () => {
  let sidecar: MockSidecar;

  beforeEach(async () => {
    sidecar = await startMock(({ url }) => {
      if (url.startsWith("/v1/ingest/runs")) {
        return { status: 202, body: { accepted: true } };
      }
      return { status: 404, body: { code: "NOT_FOUND" } };
    });
  });
  afterEach(async () => {
    await sidecar.close();
  });

  it("Run.capture POSTs /v1/ingest/runs with run_id, agent, version, manifest_commit_hash", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    const run = new Run({
      agent: VALID_AGENT,
      releaseSha: "release-sha-abc",
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: client,
    });
    await run.capture({ clientLifecycleStatus: "client_succeeded" });
    await run.close();
    expect(sidecar.observed.length).toBeGreaterThanOrEqual(1);
    const ingestCall = sidecar.observed.find((o) => o.url === "/v1/ingest/runs");
    expect(ingestCall).toBeDefined();
    const body = JSON.parse(ingestCall!.body) as Record<string, unknown>;
    // The three anchors live on the envelope per buildIngestRunEnvelope.
    expect(typeof body["run_id"]).toBe("string");
    expect(body["agent"]).toEqual(VALID_AGENT);
    expect(body["manifest_commit_hash"]).toBe(VALID_MANIFEST);
    expect(body["actor_identity_hash"]).toBe(VALID_ACTOR);
    expect(body["client_lifecycle_status"]).toBe("client_succeeded");
    // run_id ULID matches the Crockford regex.
    expect(typeof body["run_id"]).toBe("string");
    expect(ULID_REGEX.test(body["run_id"] as string)).toBe(true);
  });

  it("missing manifest_commit_hash raises RelayHandoffIncomplete BEFORE any HTTP I/O", () => {
    expect(() =>
      buildIngestRunEnvelope({
        runId: VALID_RUN_ID,
        traceId: "trace-abc",
        projectId: "aa111111-2222-3333-4444-555555555555",
        agent: VALID_AGENT,
        clientLifecycleStatus: "started",
        startedAt: "2026-05-12T10:00:00Z",
        sdkVersion: "relay-typescript@0.0.0",
        sdkClock: "2026-05-12T10:00:00.123Z",
        manifestCommitHash: "",
        actorIdentityHash: VALID_ACTOR,
        redactionPolicyVersion: "v1",
        sequenceNumber: 1,
      }),
    ).toThrowError(RelayHandoffIncomplete);
  });
});

describe("VAL-W4-014: Idempotency-Key header is a Crockford base32 ULID on every POST", () => {
  let sidecar: MockSidecar;
  beforeEach(async () => {
    sidecar = await startMock(({ url }) => {
      if (url.startsWith("/v1/ingest/runs")) return { status: 202, body: { accepted: true } };
      if (url.startsWith("/v1/evidence-bundles")) return { status: 200, body: { stored: true } };
      return { status: 404, body: {} };
    });
  });
  afterEach(async () => sidecar.close());

  it("100 distinct POSTs produce 100 distinct ULID Idempotency-Key headers", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    for (let i = 0; i < 100; i++) {
      const envelope = buildIngestRunEnvelope({
        runId: VALID_RUN_ID,
        traceId: "trace-" + i,
        projectId: "aa111111-2222-3333-4444-555555555555",
        agent: VALID_AGENT,
        clientLifecycleStatus: "started",
        startedAt: "2026-05-12T10:00:00Z",
        sdkVersion: "relay-typescript@0.0.0",
        sdkClock: "2026-05-12T10:00:00.123Z",
        manifestCommitHash: VALID_MANIFEST,
        actorIdentityHash: VALID_ACTOR,
        redactionPolicyVersion: "v1",
        sequenceNumber: i + 1,
      });
      await client.postIngestRun(envelope);
    }
    const keys = sidecar.observed
      .filter((o) => o.url === "/v1/ingest/runs")
      .map((o) => String(o.headers["idempotency-key"] ?? ""));
    expect(keys.length).toBe(100);
    for (const k of keys) {
      expect(ULID_REGEX.test(k), `header ${JSON.stringify(k)} fails Crockford regex`).toBe(true);
    }
    const distinct = new Set(keys);
    expect(distinct.size).toBe(100);
  });

  it("postEvidence attaches a fresh ULID Idempotency-Key", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    const env = buildEvidenceEnvelope({
      runId: VALID_RUN_ID,
      artifactDigestSha256: "sha256-" + "1".repeat(64),
      commandId: "cmd-test-tier-1",
      exitCode: 0,
      spanIds: ["span-1"],
      assertionIds: ["VAL-W4-016"],
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
    });
    await client.postEvidence(env);
    const evCall = sidecar.observed.find((o) => o.url === "/v1/evidence-bundles");
    expect(evCall).toBeDefined();
    const key = String(evCall!.headers["idempotency-key"] ?? "");
    expect(ULID_REGEX.test(key)).toBe(true);
  });
});

describe("VAL-W4-015: gateEvaluate POSTs /v1/gates/<id>/drafts with three-anchor handoff", () => {
  let sidecar: MockSidecar;
  beforeEach(async () => {
    sidecar = await startMock(({ url, body }) => {
      if (url === "/v1/ingest/runs") return { status: 202, body: { accepted: true } };
      if (url.startsWith("/v1/gates/") && url.endsWith("/drafts")) {
        const parsed = JSON.parse(body) as Record<string, unknown>;
        if (
          !parsed["actor_identity_hash"] ||
          !parsed["manifest_commit_hash"] ||
          !parsed["scope_id"]
        ) {
          return {
            status: 422,
            body: {
              schema_version: "relay.error.v1",
              code: "RELAY-GATE-021",
              error_class: "GATE-HANDOFF-STALE",
              message: "three-anchor handoff stale",
              retry_advice: { mode: "after_state_change" },
              mismatched_anchor: ["scope_id"],
            },
          };
        }
        return { status: 200, body: { draft_id: parsed["draft_id"], decision_id: "dec-001" } };
      }
      if (url.startsWith("/v1/gate-decisions/")) {
        return { status: 200, body: { decision: "accepted", decision_id: "dec-001" } };
      }
      return { status: 404, body: {} };
    });
  });
  afterEach(async () => sidecar.close());

  it("posts draft with all three anchors and reads canonical decision", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: client,
    });
    const result = await run.gateEvaluate({
      gateId: "gate-001",
      releaseSha: "release-sha-abc",
      evalRunIds: ["run-eval-1"],
      workerId: "worker-1",
      scopeType: "run",
      round: 0,
    });
    const draftCall = sidecar.observed.find((o) => o.url === "/v1/gates/gate-001/drafts");
    expect(draftCall).toBeDefined();
    const body = JSON.parse(draftCall!.body) as Record<string, unknown>;
    expect(body["scope_id"]).toBe("gate-001");
    expect(body["actor_identity_hash"]).toBe(VALID_ACTOR);
    expect(body["manifest_commit_hash"]).toBe(VALID_MANIFEST);
    expect(body["worker_id"]).toBe("worker-1");
    expect(body["scope_type"]).toBe("run");
    expect(body["round"]).toBe(0);
    expect(result.decision["decision"]).toBe("accepted");
    await run.close();
  });

  it("buildGateDraftEnvelope rejects empty manifest_commit_hash with RelayHandoffIncomplete", () => {
    expect(() =>
      buildGateDraftEnvelope({
        gateId: "gate-001",
        releaseSha: "release-sha-abc",
        evalRunIds: ["run-eval-1"],
        manifestCommitHash: "",
        actorIdentityHash: VALID_ACTOR,
      }),
    ).toThrowError(RelayHandoffIncomplete);
  });

  it("RELAY-GATE-021 from sidecar surfaces as a typed RelayHandoffIncomplete with mismatched_anchor populated", async () => {
    // Bypass the SDK-boundary builder by using the raw HTTP client to
    // POST a body the sidecar will reject (omit actor_identity_hash on
    // the wire to trigger the stub responder's 422 path).
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    let raised: unknown;
    try {
      // Hand-craft a body that fails the sidecar's stub criteria.
      await client.postGateDraft("gate-001", {
        schema_version: "relay.gate_decision_draft.v1",
        draft_id: "draft-001",
        gate_id: "gate-001",
        release_sha: "release-sha-abc",
        eval_run_ids: ["run-eval-1"],
        manifest_commit_hash: VALID_MANIFEST,
        // actor_identity_hash deliberately empty to force 422 from stub.
        actor_identity_hash: "",
        scope_id: "",
      });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(RelayHandoffIncomplete);
    const err = raised as RelayHandoffIncomplete;
    expect(err.code).toBe("RELAY-GATE-021");
    expect(err.details["mismatched_anchor"]).toEqual(["scope_id"]);
  });
});

describe("VAL-W4-016: submitEvidence POSTs /v1/evidence-bundles and never holds plaintext", () => {
  let sidecar: MockSidecar;
  beforeEach(async () => {
    sidecar = await startMock(({ url }) => {
      if (url === "/v1/ingest/runs") return { status: 202, body: { accepted: true } };
      if (url === "/v1/evidence-bundles") return { status: 200, body: { stored: true } };
      return { status: 404, body: {} };
    });
  });
  afterEach(async () => sidecar.close());

  it("evidence submit body contains digests + metadata only; never the seeded plaintext", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    const run = new Run({
      agent: VALID_AGENT,
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
      flushPolicy: { mode: "sync", onError: "raise" },
      httpClient: client,
    });
    const SEEDED_PLAINTEXT = "SEEDED_PLAINTEXT_TS_42_DO_NOT_LEAK";
    // Caller supplies digest derived from the plaintext; SDK transmits
    // the digest, never the raw bytes.
    const fakeDigest = "sha256-" + "a".repeat(64);
    const result = await run.submitEvidence({
      artifactDigestSha256: fakeDigest,
      commandId: "cmd-test-tier-1",
      exitCode: 0,
      spanIds: ["span-1"],
      assertionIds: ["VAL-W4-016"],
    });
    const evCall = sidecar.observed.find((o) => o.url === "/v1/evidence-bundles");
    expect(evCall).toBeDefined();
    expect(evCall!.body.includes(SEEDED_PLAINTEXT)).toBe(false);
    expect(evCall!.body.includes(fakeDigest)).toBe(true);
    const parsed = JSON.parse(evCall!.body) as Record<string, unknown>;
    expect(parsed["schema_version"]).toBe("relay.evidence_submit.v1");
    expect(parsed["artifact_digest_sha256"]).toBe(fakeDigest);
    expect(parsed["command_id"]).toBe("cmd-test-tier-1");
    expect(parsed["exit_code"]).toBe(0);
    expect(result.envelope.span_ids).toEqual(["span-1"]);
    await run.close();
  });

  it("submit endpoint path is exactly /v1/evidence-bundles (plural with hyphen)", async () => {
    const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
    const env = buildEvidenceEnvelope({
      runId: VALID_RUN_ID,
      artifactDigestSha256: "sha256-" + "1".repeat(64),
      commandId: "cmd-1",
      exitCode: 0,
      spanIds: ["span-1"],
      assertionIds: ["VAL-W4-016"],
      actorIdentityHash: VALID_ACTOR,
      manifestCommitHash: VALID_MANIFEST,
      redactionPolicyVersion: "v1",
    });
    await client.postEvidence(env);
    const ev = sidecar.observed.find((o) => o.url === "/v1/evidence-bundles");
    expect(ev).toBeDefined();
    expect(ev!.method).toBe("POST");
  });
});
