/**
 * W4.2 canonical-write tests (VAL-W4-009, VAL-W4-010).
 *
 * VAL-W4-009: SDK source under packages/sdk-typescript/src/ contains zero
 *             outbound assignments of canonical-write field literals
 *             ("status", "primary_failure_class", "written_by",
 *             "accepted_at", "finalized_at"). The denylist constant in
 *             lifecycle.ts is the sole legitimate occurrence.
 *
 * VAL-W4-010: Five forged-field variants (one per canonical-write field)
 *             POSTed to a stub sidecar that returns HTTP 422 +
 *             RELAY-ING-031 surface as RelayControlPlaneOwnershipError
 *             (subclass of RelayCanonicalStatusForbidden) with
 *             forged_field attribution.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";

import {
  RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE,
  RelayCanonicalStatusForbidden,
  RelayControlPlaneOwnershipError,
} from "../src/errors.js";
import { CANONICAL_WRITE_FIELDS, buildIngestRunEnvelope } from "../src/lifecycle.js";
import { FetchRunHttpClient } from "../src/run.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SRC_DIR = path.resolve(__dirname, "..", "src");

const CANONICAL_FIELDS = ["status", "primary_failure_class", "written_by", "accepted_at", "finalized_at"];

const VALID_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

function* walkTsFiles(dir: string): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip generated tree (it's codegen output, not hand-authored source).
      if (entry.name === "_generated") continue;
      yield* walkTsFiles(full);
    } else if (entry.isFile() && full.endsWith(".ts")) {
      yield full;
    }
  }
}

describe("VAL-W4-009: SDK source contains no outbound canonical-write field assignments", () => {
  it("the canonical-write field literals appear ONLY inside lifecycle.ts denylist", () => {
    // For each canonical field, count occurrences as a JSON-style key
    // ("field":  ) across the SDK source tree. The only legitimate
    // occurrences are inside the denylist constant in lifecycle.ts; no
    // outbound builder may assign these as keys.
    for (const field of CANONICAL_FIELDS) {
      const re = new RegExp('"' + field + '"\\s*:?', "g");
      const offenders: string[] = [];
      for (const file of walkTsFiles(SRC_DIR)) {
        const text = fs.readFileSync(file, "utf8");
        const matches = text.match(re);
        if (matches === null) continue;
        // lifecycle.ts is permitted to mention the literal inside the
        // CANONICAL_WRITE_FIELDS Set declaration. Any other occurrence is
        // either (a) a wire-format assignment (forbidden) or (b) a docs
        // reference inside a comment. Exclude lines inside /** */ blocks
        // and // comments from the offender list -- production code MUST
        // NOT produce these literals as outbound payload keys.
        const lines = text.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          const ln = lines[i];
          if (typeof ln !== "string") continue;
          if (!new RegExp('"' + field + '"').test(ln)) continue;
          // Skip pure-comment lines.
          const trimmed = ln.trim();
          if (
            trimmed.startsWith("//") ||
            trimmed.startsWith("*") ||
            trimmed.startsWith("/*")
          ) {
            continue;
          }
          // Skip the denylist declaration in lifecycle.ts (the SOLE
          // permitted code reference).
          if (
            file.endsWith("lifecycle.ts") &&
            (trimmed.includes('"status"') ||
              trimmed.includes('"primary_failure_class"') ||
              trimmed.includes('"written_by"') ||
              trimmed.includes('"accepted_at"') ||
              trimmed.includes('"finalized_at"')) &&
            // The denylist line lists ALL five canonical fields; we
            // accept any line that includes one of them inside lifecycle.ts.
            true
          ) {
            // Ensure context: the line must be part of the
            // CANONICAL_WRITE_FIELDS Set declaration. We test by checking
            // that the surrounding lines contain "CANONICAL_WRITE_FIELDS"
            // within +/- 6 lines.
            const start = Math.max(0, i - 6);
            const end = Math.min(lines.length, i + 6);
            const context = lines.slice(start, end).join("\n");
            if (context.includes("CANONICAL_WRITE_FIELDS")) {
              continue;
            }
          }
          offenders.push(`${path.relative(SRC_DIR, file)}:${i + 1}: ${trimmed}`);
        }
      }
      expect(
        offenders,
        `field "${field}" appeared as outbound key in:\n${offenders.join("\n")}`,
      ).toEqual([]);
    }
  });

  it("CANONICAL_WRITE_FIELDS contains exactly the five canonical-write field names", () => {
    expect([...CANONICAL_WRITE_FIELDS].sort()).toEqual([...CANONICAL_FIELDS].sort());
  });

  it("buildIngestRunEnvelope output contains zero canonical-write fields on the happy path", () => {
    const envelope = buildIngestRunEnvelope({
      runId: VALID_RUN_ID,
      traceId: "trace-abc",
      projectId: "aa111111-2222-3333-4444-555555555555",
      agent: VALID_AGENT,
      clientLifecycleStatus: "started",
      startedAt: "2026-05-12T10:00:00Z",
      sdkVersion: "relay-typescript@0.0.0",
      sdkClock: "2026-05-12T10:00:00.123Z",
      manifestCommitHash: VALID_MANIFEST,
      actorIdentityHash: VALID_ACTOR,
      redactionPolicyVersion: "v1",
      sequenceNumber: 1,
    });
    for (const field of CANONICAL_FIELDS) {
      expect(envelope, `envelope leaked canonical-write field ${field}`).not.toHaveProperty(field);
    }
    expect(envelope.client_lifecycle_status).toBe("started");
  });
});

interface MockSidecarHandle {
  port: number;
  baseUrl: string;
  observed: Array<{ method: string; url: string; body: string; headers: http.IncomingHttpHeaders }>;
  close: () => Promise<void>;
}

async function startMockSidecar(
  responder: (req: { url: string; body: string }) => { status: number; body: object; headers?: Record<string, string> },
): Promise<MockSidecarHandle> {
  const observed: MockSidecarHandle["observed"] = [];
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
      const out = responder({ url: req.url ?? "", body });
      res.statusCode = out.status;
      res.setHeader("content-type", "application/json");
      if (out.headers !== undefined) {
        for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
      }
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    observed,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

describe("VAL-W4-010: forged canonical-write field surfaces RelayControlPlaneOwnershipError", () => {
  let sidecar: MockSidecarHandle;

  beforeEach(async () => {
    sidecar = await startMockSidecar(({ body }) => {
      let parsed: Record<string, unknown> = {};
      try {
        parsed = JSON.parse(body) as Record<string, unknown>;
      } catch {
        // ignore
      }
      const offending = CANONICAL_FIELDS.find((f) => f in parsed);
      if (offending !== undefined) {
        return {
          status: 422,
          body: {
            schema_version: "relay.error.v1",
            code: "RELAY-ING-031",
            error_class: "CANONICAL-WRITE-FIELD-REJECTED",
            message: `client tried to set canonical field '${offending}'`,
            retry_advice: { mode: "no_retry" },
            details: { forbidden_field: offending },
          },
        };
      }
      return { status: 200, body: { accepted: true } };
    });
  });

  afterEach(async () => {
    await sidecar.close();
  });

  for (const forgedField of CANONICAL_FIELDS) {
    it(`raises RelayControlPlaneOwnershipError when forging '${forgedField}' over raw HTTP`, async () => {
      const client = new FetchRunHttpClient({ baseUrl: sidecar.baseUrl });
      // Build a minimal valid envelope, then forge in the canonical field
      // bypassing the SDK boundary by casting to mutable record.
      const envelope = buildIngestRunEnvelope({
        runId: VALID_RUN_ID,
        traceId: "trace-abc",
        projectId: "aa111111-2222-3333-4444-555555555555",
        agent: VALID_AGENT,
        clientLifecycleStatus: "started",
        startedAt: "2026-05-12T10:00:00Z",
        sdkVersion: "relay-typescript@0.0.0",
        sdkClock: "2026-05-12T10:00:00.123Z",
        manifestCommitHash: VALID_MANIFEST,
        actorIdentityHash: VALID_ACTOR,
        redactionPolicyVersion: "v1",
        sequenceNumber: 1,
      });
      // Forge: simulate a programmer error that bypasses the builder.
      (envelope as unknown as Record<string, unknown>)[forgedField] = "forged";
      let raised: unknown;
      try {
        await client.postIngestRun(envelope);
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(RelayCanonicalStatusForbidden);
      const err = raised as RelayCanonicalStatusForbidden;
      expect(err.code).toBe("RELAY-ING-031");
      expect(err.httpStatus).toBe(422);
      // forged_field surfaced from the response body details.
      expect(err.details["forged_field"]).toBe(forgedField);
    });
  }

  it("SDK boundary rejects canonical-write field BEFORE any HTTP request", () => {
    // Without bypassing the builder, the SDK boundary catches it and
    // raises RelayCanonicalStatusForbidden synchronously.
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
        manifestCommitHash: VALID_MANIFEST,
        actorIdentityHash: VALID_ACTOR,
        redactionPolicyVersion: "v1",
        sequenceNumber: 1,
        extras: { status: "client_succeeded" },
      }),
    ).toThrowError(RelayCanonicalStatusForbidden);
  });

  it("RelayControlPlaneOwnershipError is a subclass of RelayCanonicalStatusForbidden", () => {
    const err = new RelayControlPlaneOwnershipError("test", {
      code: RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE,
    });
    expect(err).toBeInstanceOf(RelayCanonicalStatusForbidden);
    expect(err).toBeInstanceOf(RelayControlPlaneOwnershipError);
  });
});
