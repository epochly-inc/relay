/**
 * Cross-language parity for ``buildGateDraftEnvelope`` (P0 audit fix).
 *
 * Loads ``tests/conformance/lifecycle/gate_draft_parity_fixtures.json``
 * and asserts the TypeScript SDK's :func:`buildGateDraftEnvelope`
 * emits the canonical envelope shape declared in the fixture for each
 * input case. The Python SDK runs the same fixture against
 * :func:`build_gate_draft_envelope`; combined, the two suites guarantee
 * byte-equality of the JCS-canonicalised wire body across SDKs.
 *
 * Pre-fix the Python SDK omitted ``scope_id`` (and never accepted
 * ``worker_id`` / ``scope_type`` / ``round`` / ``evidence_refs``), so a
 * direct comparison of envelopes for the same logical input mismatched.
 * Post-fix both SDKs emit the SAME key set for the same logical input,
 * and JCS canonicalisation (sort keys, compact separators) produces
 * byte-identical UTF-8 output.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { buildGateDraftEnvelope } from "../src/lifecycle.js";

interface ParityFixture {
  readonly name: string;
  readonly inputs: Record<string, unknown>;
  readonly expected_envelope: Record<string, unknown>;
}

interface ParityCorpus {
  readonly schema_version: string;
  readonly fixtures: ReadonlyArray<ParityFixture>;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(
  HERE,
  "..",
  "..",
  "..",
  "tests",
  "conformance",
  "lifecycle",
  "gate_draft_parity_fixtures.json",
);

function loadCorpus(): ParityCorpus {
  return JSON.parse(readFileSync(CORPUS_PATH, "utf-8")) as ParityCorpus;
}

// Minimal RFC-8785-compatible canonicaliser identical to the one used
// by the redaction module. Inlined here so this test has no dependency
// on internal redaction helpers. Mirrors
// ``packages/schemas/python/relay_schemas/envelopes.py::canonical_bytes``.
function canonicalJsonStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalJsonStringify: non-finite number not allowed");
    }
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJsonStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalJsonStringify(v));
    }
    return "{" + parts.join(",") + "}";
  }
  if (value === undefined) return "null";
  throw new Error(`canonicalJsonStringify: unsupported type ${typeof value}`);
}

describe("buildGateDraftEnvelope :: cross-language parity corpus", () => {
  const corpus = loadCorpus();

  it("corpus loaded with non-zero fixture count", () => {
    expect(corpus.schema_version).toBe("relay.gate_draft_parity.v1");
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(2);
  });

  for (const fx of corpus.fixtures) {
    it(`fixture "${fx.name}" :: TS builder output equals canonical envelope`, () => {
      const inputs = fx.inputs;
      // Required fields:
      const args: Parameters<typeof buildGateDraftEnvelope>[0] = {
        gateId: inputs["gate_id"] as string,
        releaseSha: inputs["release_sha"] as string,
        evalRunIds: inputs["eval_run_ids"] as string[],
        manifestCommitHash: inputs["manifest_commit_hash"] as string,
        actorIdentityHash: inputs["actor_identity_hash"] as string,
        draftId: inputs["draft_id"] as string,
      };
      if (inputs["worker_id"] !== undefined) {
        args.workerId = inputs["worker_id"] as string;
      }
      if (inputs["scope_type"] !== undefined) {
        args.scopeType = inputs["scope_type"] as string;
      }
      if (inputs["round"] !== undefined) {
        args.round = inputs["round"] as number;
      }
      if (inputs["evidence_refs"] !== undefined) {
        args.evidenceRefs = inputs["evidence_refs"] as string[];
      }
      const env = buildGateDraftEnvelope(args);
      // Compare key-by-key against the canonical expected envelope.
      const envelopeAsRecord = env as unknown as Record<string, unknown>;
      expect(envelopeAsRecord).toEqual(fx.expected_envelope);
    });

    it(`fixture "${fx.name}" :: TS JCS bytes match canonical fixture bytes`, () => {
      const inputs = fx.inputs;
      const args: Parameters<typeof buildGateDraftEnvelope>[0] = {
        gateId: inputs["gate_id"] as string,
        releaseSha: inputs["release_sha"] as string,
        evalRunIds: inputs["eval_run_ids"] as string[],
        manifestCommitHash: inputs["manifest_commit_hash"] as string,
        actorIdentityHash: inputs["actor_identity_hash"] as string,
        draftId: inputs["draft_id"] as string,
      };
      if (inputs["worker_id"] !== undefined) {
        args.workerId = inputs["worker_id"] as string;
      }
      if (inputs["scope_type"] !== undefined) {
        args.scopeType = inputs["scope_type"] as string;
      }
      if (inputs["round"] !== undefined) {
        args.round = inputs["round"] as number;
      }
      if (inputs["evidence_refs"] !== undefined) {
        args.evidenceRefs = inputs["evidence_refs"] as string[];
      }
      const tsBytes = canonicalJsonStringify(buildGateDraftEnvelope(args));
      const fixtureBytes = canonicalJsonStringify(fx.expected_envelope);
      expect(tsBytes).toBe(fixtureBytes);
    });
  }

  it("buildGateDraftEnvelope always emits scope_id == gate_id", () => {
    const env = buildGateDraftEnvelope({
      gateId: "gate-anchor",
      releaseSha: "rel-anchor",
      evalRunIds: ["e-1"],
      manifestCommitHash: "sha256-" + "m".repeat(64),
      actorIdentityHash: "sha256-" + "a".repeat(64),
    });
    expect(env.scope_id).toBe("gate-anchor");
  });
});
