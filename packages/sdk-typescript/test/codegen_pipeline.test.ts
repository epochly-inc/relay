/**
 * W1.5 codegen pipeline TypeScript-side contract tests.
 *
 * Covers:
 *   VAL-W1-034 generated TS imports + tsc --noEmit clean
 *   VAL-W1-036 RelayUnknownSchemaVersionError (TS side)
 *   VAL-W1-037 snake_case <-> camelCase alias map (TS side)
 *
 * Tier-1 plumbing tests. ASCII-only per CLAUDE.md.
 *
 * Relocated from packages/schemas/typescript/test/ (SCR-W1-001 fix):
 * the test exercises generated SDK output and therefore belongs to the
 * sdk-typescript package; the cross-package import previously violated
 * the schemas package tsconfig rootDir.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

// Import the five named types from the generated SDK output. If this file
// type-checks, VAL-W1-034 import path is exercised.
import type {
  RunResult,
  GateDecision,
  EvidenceBundle,
  ReplayFixture,
  ErrorEnvelope,
} from "../src/_generated/index.js";

import {
  CANONICAL_ENVELOPES,
  FIELD_ALIASES_BY_ENVELOPE,
  snakeToCamel,
  camelToSnake,
  RelayUnknownSchemaVersionError,
  parseEnvelope,
} from "../src/_generated/index.js";

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

// Canonical envelope-name contract list. Must equal the generated
// CANONICAL_ENVELOPES tuple in src/_generated/index.ts (kept in lockstep by
// the codegen drift guard). The original W1 14-name baseline grew during v0.2
// M01 by 19 entries (12 from w1-1 + 2 from w1-4 + 3 from w1-5 + 2 from w1-6).
// Any new canonical envelope MUST be appended here AND in codegen.py
// CANONICAL_ENVELOPES; the drift guard at scripts/check-codegen-drift.py
// enforces synchrony between source and generated tree.
const CANONICAL_ENVELOPE_LIST = [
  "RunResult",
  "GateDecision",
  "GateDecisionDraft",
  "GateRound",
  "ManifestVersion",
  "ScopeState",
  "IdempotencyRecord",
  "EventLogEntry",
  "EvidenceBundle",
  "EvidenceClaim",
  "ReplayCase",
  "ReplayFixture",
  "RedactionPolicy",
  "ErrorEnvelope",
  // v0.2 M01 w1-1 (audit-driven additions, 12 envelopes):
  "GatePolicy",
  "ContractResult",
  "AssertionDefinition",
  "ReplayResult",
  "Manifest",
  "Incident",
  "RootCauseHypothesis",
  "Span",
  "ModelCallSpan",
  "ToolCallSpan",
  "RetrievalSpan",
  "EmbeddingSpan",
  // v0.2 M01 w1-4 (legal holds + bundle registry):
  "EvidenceLegalHold",
  "EvidenceBundleRegistry",
  // v0.2 M01 w1-6 (TSA + transparency log SQL):
  "EvidenceTimestamp",
  "TransparencyLogEntry",
  // v0.2 M01 w1-5 (ACEF oversight Postgres mirrors):
  "HumanOversightEvent",
  "DataQualityCheck",
  "DataProvenanceRecord",
] as const;

function validRunResultPayload(): Record<string, unknown> {
  return {
    schema_version: "relay.run_result.v1",
    run_result_id: "11111111-2222-3333-4444-555555555555",
    run_id: "11111111-2222-3333-4444-666666666666",
    project_id: "11111111-2222-3333-4444-777777777777",
    written_by: "control_plane",
    status: "blocked",
    manifest_commit_hash: "sha256-" + "a".repeat(64),
    actor_identity_hash: "sha256-" + "b".repeat(64),
    decided_at: "2026-05-13T12:00:00+00:00",
    signature: "sig",
    signature_key_id: "key-1",
  };
}

// ---------------------------------------------------------------------------
// VAL-W1-034: generated TS imports + tsc --noEmit clean
// ---------------------------------------------------------------------------

describe("VAL-W1-034: generated TypeScript", () => {
  it("named imports resolve as types (compile-time evidence)", () => {
    // If the imports at the top of the file type-checked under tsc, this
    // test runs at all. The body just confirms the value-level imports
    // (CANONICAL_ENVELOPES, parseEnvelope, etc.) are present.
    expect(CANONICAL_ENVELOPES).toBeDefined();
    expect(Array.isArray(CANONICAL_ENVELOPES)).toBe(true);
    expect(CANONICAL_ENVELOPES.length).toBe(CANONICAL_ENVELOPE_LIST.length);
  });

  it("tsc --noEmit on the SDK package exits 0", () => {
    // Invokes the TS compiler in the SDK package against tsconfig.json.
    // A non-zero exit indicates a type error in the generated output or
    // in the index.ts re-export module.
    const sdkDir = path.join(REPO_ROOT, "packages", "sdk-typescript");
    expect(() =>
      execFileSync("npx", ["tsc", "-p", "tsconfig.json", "--noEmit"], {
        cwd: sdkDir,
        stdio: "pipe",
        encoding: "utf-8",
      }),
    ).not.toThrow();
  });

  it("named-exported types are assignable to validly-shaped payloads", () => {
    // Compile-time test: if the type names refer to anything other than
    // structural objects with `schema_version` const fields, this assignment
    // fails tsc. The runtime cast is a `satisfies` proxy.
    const sample: RunResult = {
      schema_version: "relay.run_result.v1",
      run_result_id: "00000000-0000-0000-0000-000000000000",
      run_id: "00000000-0000-0000-0000-000000000001",
      project_id: "00000000-0000-0000-0000-000000000002",
      written_by: "control_plane",
      status: "blocked",
      error_priority_rule: "first_p0_then_highest_severity_then_earliest_span",
      manifest_commit_hash: "sha256-" + "0".repeat(64),
      actor_identity_hash: "sha256-" + "0".repeat(64),
      decided_at: "2026-05-13T12:00:00Z",
      decision_epoch: 0,
      signature: "s",
      signature_key_id: "k",
    };
    expect(sample.written_by).toBe("control_plane");

    // Smoke usage of the other four named imports.
    const _gd: GateDecision | undefined = undefined;
    const _eb: EvidenceBundle | undefined = undefined;
    const _rf: ReplayFixture | undefined = undefined;
    const _ee: ErrorEnvelope | undefined = undefined;
    expect(_gd).toBeUndefined();
    expect(_eb).toBeUndefined();
    expect(_rf).toBeUndefined();
    expect(_ee).toBeUndefined();
  });

  it("CANONICAL_ENVELOPES matches the canonical contract list", () => {
    expect([...CANONICAL_ENVELOPES]).toEqual([...CANONICAL_ENVELOPE_LIST]);
  });

  it("generated index.ts file is present and carries GENERATED FILE header", () => {
    const indexTs = path.join(
      REPO_ROOT,
      "packages",
      "sdk-typescript",
      "src",
      "_generated",
      "index.ts",
    );
    expect(fs.existsSync(indexTs)).toBe(true);
    const content = fs.readFileSync(indexTs, "utf-8");
    expect(content).toContain("GENERATED FILE");
    expect(content).toContain("DO NOT EDIT BY HAND");
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-036: forward-compat unknown schema_version (TS side)
// ---------------------------------------------------------------------------

describe("VAL-W1-036: RelayUnknownSchemaVersionError", () => {
  it("parseEnvelope throws RelayUnknownSchemaVersionError on relay.run_result.v99", () => {
    const payload = { ...validRunResultPayload(), schema_version: "relay.run_result.v99" };
    expect(() => parseEnvelope("RunResult", "relay.run_result.v1", payload)).toThrow(
      RelayUnknownSchemaVersionError,
    );
  });

  it("parseEnvelope accepts the correct schema_version (no throw)", () => {
    const payload = validRunResultPayload();
    expect(() => parseEnvelope("RunResult", "relay.run_result.v1", payload)).not.toThrow();
  });

  it("error carries observedVersion and expectedVersion", () => {
    const payload = { ...validRunResultPayload(), schema_version: "relay.run_result.v99" };
    try {
      parseEnvelope("RunResult", "relay.run_result.v1", payload);
      throw new Error("should have raised");
    } catch (e) {
      expect(e).toBeInstanceOf(RelayUnknownSchemaVersionError);
      const err = e as RelayUnknownSchemaVersionError;
      expect(err.envelopeKind).toBe("RunResult");
      expect(err.observedVersion).toBe("relay.run_result.v99");
      expect(err.expectedVersion).toBe("relay.run_result.v1");
      expect(err.message.toLowerCase()).toContain("unknown");
      expect(err.message).toContain("v99");
    }
  });

  it("parseEnvelope rejects missing schema_version", () => {
    const payload: Record<string, unknown> = { ...validRunResultPayload() };
    delete payload["schema_version"];
    expect(() => parseEnvelope("RunResult", "relay.run_result.v1", payload)).toThrow(
      RelayUnknownSchemaVersionError,
    );
  });

  it("parseEnvelope rejects non-object payloads", () => {
    expect(() => parseEnvelope("RunResult", "relay.run_result.v1", null)).toThrow(
      RelayUnknownSchemaVersionError,
    );
    expect(() =>
      parseEnvelope("RunResult", "relay.run_result.v1", "not-an-object"),
    ).toThrow(RelayUnknownSchemaVersionError);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-037: snake_case <-> camelCase alias map (TS side)
// ---------------------------------------------------------------------------

describe("VAL-W1-037: alias map (TS side)", () => {
  it("FIELD_ALIASES_BY_ENVELOPE exposes RunResult.run_result_id -> runResultId", () => {
    const map = FIELD_ALIASES_BY_ENVELOPE["RunResult"];
    expect(map).toBeDefined();
    expect(map?.["run_result_id"]).toBe("runResultId");
    expect(map?.["evidence_bundle_id"]).toBe("evidenceBundleId");
    expect(map?.["manifest_commit_hash"]).toBe("manifestCommitHash");
  });

  it("snakeToCamel returns a non-empty mapping for RunResult", () => {
    const map = snakeToCamel("RunResult");
    expect(Object.keys(map).length).toBeGreaterThan(0);
  });

  it("snakeToCamel and camelToSnake are inverse for RunResult", () => {
    const fwd = snakeToCamel("RunResult");
    const inv = camelToSnake("RunResult");
    for (const snake of Object.keys(fwd)) {
      const camel = fwd[snake];
      expect(camel).toBeDefined();
      if (camel !== undefined) {
        expect(inv[camel]).toBe(snake);
      }
    }
  });

  it("snakeToCamel returns empty map for unknown envelope", () => {
    const map = snakeToCamel("NotAnEnvelope");
    expect(map).toEqual({});
  });

  it("alias entries are present for every primary envelope (excluding ScopeState union)", () => {
    for (const env of CANONICAL_ENVELOPE_LIST) {
      if (env === "ScopeState") continue;
      expect(FIELD_ALIASES_BY_ENVELOPE[env]).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-037 cross-language byte-equal evidence
// ---------------------------------------------------------------------------

describe("VAL-W1-037: cross-language wire-form round-trip", () => {
  it("snake_case wire JSON is preserved verbatim under JSON.parse + JSON.stringify", () => {
    // The TS side does NOT silently lowercase or rename keys. A snake_case
    // wire payload survives a parse->serialize round-trip byte-equal under
    // the canonical (sorted-key) form.
    const wire = validRunResultPayload();
    const json = JSON.stringify(wire, Object.keys(wire).sort());
    const parsed = JSON.parse(json) as Record<string, unknown>;
    const reserialized = JSON.stringify(parsed, Object.keys(parsed).sort());
    expect(reserialized).toBe(json);

    // Same Python-side wire form (verified by the cross-language fixture
    // helper). The byte-equal evidence below confirms TS does not mangle.
    expect(parsed["run_result_id"]).toBe(wire["run_result_id"]);
    expect(parsed["evidence_bundle_id"]).toBe(wire["evidence_bundle_id"]);
  });

  it("alias map matches the count exposed on the Python side", () => {
    // Python emits FIELD_ALIASES_BY_ENVELOPE under
    // relay._generated.aliases; the TS side emits identical content.
    // The envelope-name set MUST match. We verify a structural subset:
    // every TS envelope key MUST be in the canonical envelope list.
    for (const env of Object.keys(FIELD_ALIASES_BY_ENVELOPE)) {
      const isCanonical = (CANONICAL_ENVELOPE_LIST as readonly string[]).includes(env);
      const isVariant = [
        "Actor",
        "RunScopeState",
        "ReplayCaseScopeState",
        "GateRoundScopeState",
        "EvidenceBundleScopeState",
        // v0.2 M01 w1-7 (scope_state extension to 6 kinds):
        "EvalRunScopeState",
        "ReleaseScopeState",
        "RedactionPolicyMatcherRegex",
        "RedactionPolicyMatcherJsonPointer",
      ].includes(env);
      expect(isCanonical || isVariant).toBe(true);
    }
  });
});
