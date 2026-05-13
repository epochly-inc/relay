/**
 * W1.1 envelope schema tests (TypeScript).
 *
 * Covers contract assertions VAL-W1-001 through VAL-W1-008, VAL-W1-046,
 * VAL-W1-047, VAL-W1-048, VAL-W1-058, VAL-W1-059 from the TypeScript side.
 *
 * Each describe block carries the assertion ID in its title so the gate
 * engine can attribute pass/fail to the contract assertion.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  Actor,
  GateDecision,
  GateDecisionDraft,
  GateRound,
  RunResult,
  isActor,
  isGateDecision,
  isGateDecisionDraft,
  isGateRound,
  isRunResult,
  parseActor,
  parseGateDecision,
  parseGateDecisionDraft,
  parseGateRound,
  parseRunResult,
  SHA256_HASH_PATTERN,
} from "../src/envelopes.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const VALID_ACTOR_HASH = "sha256-" + "a".repeat(64);
const VALID_MANIFEST_HASH = "sha256-" + "b".repeat(64);
const VALID_KEY_ID = "key-" + "c".repeat(16);
const VALID_SIGNATURE = "MEUCIQ" + "D".repeat(80);

function newUuid(): string {
  // Deterministic stub UUID generator for tests; format is sufficient for
  // the schema's UUID validation (RFC 4122 v4 string form).
  const hex = "0123456789abcdef";
  const segments = [8, 4, 4, 4, 12];
  let out = "";
  for (let i = 0; i < segments.length; i++) {
    if (i > 0) out += "-";
    for (let j = 0; j < segments[i]!; j++) {
      out += hex[Math.floor(Math.random() * 16)];
    }
  }
  return out;
}

function baseRunResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "relay.run_result.v1",
    run_result_id: newUuid(),
    run_id: newUuid(),
    project_id: newUuid(),
    written_by: "control_plane",
    status: "accepted",
    primary_failure_class: null,
    error_priority_rule: "first_p0_then_highest_severity_then_earliest_span",
    evidence_bundle_id: newUuid(),
    manifest_commit_hash: VALID_MANIFEST_HASH,
    actor_identity_hash: VALID_ACTOR_HASH,
    decided_at: "2026-05-12T00:00:00Z",
    decision_epoch: 0,
    signature: VALID_SIGNATURE,
    signature_key_id: VALID_KEY_ID,
    ...overrides,
  };
}

function baseGateDecision(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "relay.gate_decision.v1",
    gate_decision_id: newUuid(),
    gate_id: newUuid(),
    scope_type: "run",
    scope_id: newUuid(),
    round: 1,
    action: "accept",
    strict_pass: true,
    failed_assertion_ids: [],
    unmet_conditions: [],
    evidence_bundle_id: newUuid(),
    cascade_on_block: true,
    decided_by: "gate_engine",
    decided_at: "2026-05-12T00:00:00Z",
    manifest_commit_hash: VALID_MANIFEST_HASH,
    actor_identity_hash: VALID_ACTOR_HASH,
    signature: VALID_SIGNATURE,
    signature_key_id: VALID_KEY_ID,
    decision_epoch: 0,
    ...overrides,
  };
}

function baseGateDecisionDraft(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.gate_decision_draft.v1",
    draft_id: newUuid(),
    gate_id: newUuid(),
    scope_type: "run",
    scope_id: newUuid(),
    round: 1,
    release_sha: null,
    eval_run_ids: [],
    evidence_refs: [],
    worker_id: newUuid(),
    manifest_commit_hash: VALID_MANIFEST_HASH,
    actor_identity_hash: VALID_ACTOR_HASH,
    submitted_at: "2026-05-12T00:00:00Z",
    resolved_gate_decision_id: null,
    draft_kind: "submitted",
    resolution_state: "pending",
    cancelled_at: null,
    cancellation_reason: null,
    ...overrides,
  };
}

function baseGateRound(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "relay.gate_round.v1",
    gate_round_id: newUuid(),
    gate_id: newUuid(),
    scope_type: "run",
    scope_id: newUuid(),
    round: 1,
    initiated_at: "2026-05-12T00:00:00Z",
    initiated_by: "control_plane",
    initiation_reason: null,
    gate_decision_id: null,
    restart_predecessor: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Compile-time literal type pinning (VAL-W1-002, VAL-W1-004)
// ---------------------------------------------------------------------------
//
// Type-level assertions: these declarations would fail tsc --noEmit if the
// generated types were not literal-typed. The tests below also verify
// runtime behavior; the type-level assertions ensure the type contract is
// preserved alongside the runtime contract.

type AssertEqual<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B
  ? 1
  : 2
  ? true
  : false;

const _writtenByLiteralIsControlPlane: AssertEqual<RunResult["written_by"], "control_plane"> =
  true;

const _decidedByLiteralIsGateEngine: AssertEqual<GateDecision["decided_by"], "gate_engine"> =
  true;

const _runResultSchemaVersion: AssertEqual<
  RunResult["schema_version"],
  "relay.run_result.v1"
> = true;

const _gateDecisionSchemaVersion: AssertEqual<
  GateDecision["schema_version"],
  "relay.gate_decision.v1"
> = true;

const _gateDecisionDraftSchemaVersion: AssertEqual<
  GateDecisionDraft["schema_version"],
  "relay.gate_decision_draft.v1"
> = true;

const _gateRoundSchemaVersion: AssertEqual<
  GateRound["schema_version"],
  "relay.gate_round.v1"
> = true;

void _writtenByLiteralIsControlPlane;
void _decidedByLiteralIsGateEngine;
void _runResultSchemaVersion;
void _gateDecisionSchemaVersion;
void _gateDecisionDraftSchemaVersion;
void _gateRoundSchemaVersion;

// ---------------------------------------------------------------------------
// VAL-W1-001: run_result schema_version pinned
// ---------------------------------------------------------------------------

describe("VAL-W1-001 run_result schema_version", () => {
  it("accepts the canonical schema_version", () => {
    expect(isRunResult(baseRunResult())).toBe(true);
  });

  it("rejects a missing schema_version", () => {
    const payload = baseRunResult();
    delete (payload as { schema_version?: string }).schema_version;
    expect(isRunResult(payload)).toBe(false);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(isRunResult(baseRunResult({ schema_version: "relay.run_result.v2" }))).toBe(false);
  });

  it("parseRunResult throws ValidationError on wrong schema_version", () => {
    expect(() =>
      parseRunResult(baseRunResult({ schema_version: "relay.run_result.v2" })),
    ).toThrow(/schema_version/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-002: written_by hard-pinned to "control_plane"
// ---------------------------------------------------------------------------

describe("VAL-W1-002 run_result.written_by literal", () => {
  it("accepts written_by = control_plane", () => {
    expect(isRunResult(baseRunResult())).toBe(true);
  });

  it("rejects any other written_by value", () => {
    expect(isRunResult(baseRunResult({ written_by: "worker" }))).toBe(false);
    expect(isRunResult(baseRunResult({ written_by: "sdk" }))).toBe(false);
    expect(isRunResult(baseRunResult({ written_by: "" }))).toBe(false);
  });

  it("generated TS source contains the control_plane string literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"control_plane"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-003: status closed enum + accepted requires evidence_bundle_id
// ---------------------------------------------------------------------------

describe("VAL-W1-003 run_result.status closed enum", () => {
  it.each(["accepted", "remediate_required", "blocked", "invalid"] as const)(
    "accepts canonical status %s",
    (status) => {
      const overrides: Record<string, unknown> = { status };
      if (status !== "accepted") overrides.evidence_bundle_id = null;
      expect(isRunResult(baseRunResult(overrides))).toBe(true);
    },
  );

  it("rejects a fifth status value", () => {
    expect(isRunResult(baseRunResult({ status: "approved" }))).toBe(false);
  });

  it("rejects status=accepted with null evidence_bundle_id", () => {
    expect(
      isRunResult(baseRunResult({ status: "accepted", evidence_bundle_id: null })),
    ).toBe(false);
  });

  it("parseRunResult error message names accepted_requires_evidence", () => {
    expect(() =>
      parseRunResult(baseRunResult({ status: "accepted", evidence_bundle_id: null })),
    ).toThrow(/accepted_requires_evidence|evidence_bundle_id/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-004: gate_decision.action closed enum; decided_by literal "gate_engine"
// ---------------------------------------------------------------------------

describe("VAL-W1-004 gate_decision action enum + decided_by literal", () => {
  it.each(["accept", "remediate", "block", "invalid"] as const)(
    "accepts canonical action %s",
    (action) => {
      expect(isGateDecision(baseGateDecision({ action }))).toBe(true);
    },
  );

  it("rejects an invalid action", () => {
    expect(isGateDecision(baseGateDecision({ action: "approve" }))).toBe(false);
  });

  it("accepts decided_by = gate_engine", () => {
    expect(isGateDecision(baseGateDecision())).toBe(true);
  });

  it("rejects any other decided_by", () => {
    expect(isGateDecision(baseGateDecision({ decided_by: "worker" }))).toBe(false);
    expect(isGateDecision(baseGateDecision({ decided_by: "sdk" }))).toBe(false);
  });

  it("generated TS source contains the gate_engine string literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"gate_engine"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-005: round int >= 1; failed_assertion_ids list[str] default []
// ---------------------------------------------------------------------------

describe("VAL-W1-005 gate_decision round + failed_assertion_ids", () => {
  it("accepts round = 1", () => {
    expect(isGateDecision(baseGateDecision({ round: 1 }))).toBe(true);
  });

  it("accepts round = 42", () => {
    expect(isGateDecision(baseGateDecision({ round: 42 }))).toBe(true);
  });

  it("rejects round = 0", () => {
    expect(isGateDecision(baseGateDecision({ round: 0 }))).toBe(false);
  });

  it("rejects round = -1", () => {
    expect(isGateDecision(baseGateDecision({ round: -1 }))).toBe(false);
  });

  it("rejects round = 1.5 (non-integer)", () => {
    expect(isGateDecision(baseGateDecision({ round: 1.5 }))).toBe(false);
  });

  it("accepts failed_assertion_ids as empty list by default", () => {
    const payload = baseGateDecision();
    delete (payload as { failed_assertion_ids?: unknown }).failed_assertion_ids;
    const parsed = parseGateDecision(payload);
    expect(parsed.failed_assertion_ids).toEqual([]);
  });

  it("rejects non-string entries in failed_assertion_ids", () => {
    expect(isGateDecision(baseGateDecision({ failed_assertion_ids: [123] }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-006: two orthogonal state columns + cross-field rule
// ---------------------------------------------------------------------------

describe("VAL-W1-006 gate_decision_drafts orthogonal state columns", () => {
  it.each(["submitted", "dry_run_unsigned"] as const)(
    "accepts draft_kind = %s",
    (draft_kind) => {
      expect(isGateDecisionDraft(baseGateDecisionDraft({ draft_kind }))).toBe(true);
    },
  );

  it("rejects an invalid draft_kind", () => {
    expect(isGateDecisionDraft(baseGateDecisionDraft({ draft_kind: "other" }))).toBe(false);
  });

  it.each([
    "pending",
    "resolved",
    "rejected_handoff",
    "expired",
    "cancelled",
    "duplicate_submission",
  ] as const)("accepts resolution_state = %s", (resolution_state) => {
    const overrides: Record<string, unknown> = { resolution_state };
    if (resolution_state === "resolved") overrides.resolved_gate_decision_id = newUuid();
    expect(isGateDecisionDraft(baseGateDecisionDraft(overrides))).toBe(true);
  });

  it("rejects an invalid resolution_state", () => {
    expect(
      isGateDecisionDraft(baseGateDecisionDraft({ resolution_state: "approved" })),
    ).toBe(false);
  });

  it("rejects dry_run_unsigned + resolved (cross-field rule)", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({
          draft_kind: "dry_run_unsigned",
          resolution_state: "resolved",
        }),
      ),
    ).toBe(false);
  });

  it("parseGateDecisionDraft error names both fields", () => {
    expect(() =>
      parseGateDecisionDraft(
        baseGateDecisionDraft({
          draft_kind: "dry_run_unsigned",
          resolution_state: "resolved",
        }),
      ),
    ).toThrow(/draft_kind.*resolution_state|resolution_state.*draft_kind/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-007: dry-run forbids decision link
// ---------------------------------------------------------------------------

describe("VAL-W1-007 dry-run forbids resolved_gate_decision_id", () => {
  it("rejects dry_run_unsigned with non-null resolved_gate_decision_id", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({
          draft_kind: "dry_run_unsigned",
          resolved_gate_decision_id: newUuid(),
        }),
      ),
    ).toBe(false);
  });

  it("parseGateDecisionDraft error names both fields", () => {
    expect(() =>
      parseGateDecisionDraft(
        baseGateDecisionDraft({
          draft_kind: "dry_run_unsigned",
          resolved_gate_decision_id: newUuid(),
        }),
      ),
    ).toThrow(/draft_kind.*resolved_gate_decision_id|resolved_gate_decision_id.*draft_kind/);
  });

  it("submitted draft can carry a resolved_gate_decision_id", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({
          draft_kind: "submitted",
          resolution_state: "resolved",
          resolved_gate_decision_id: newUuid(),
        }),
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-008: gate_rounds.initiated_by enum + nullable restart_predecessor
// ---------------------------------------------------------------------------

describe("VAL-W1-008 gate_rounds initiated_by + restart_predecessor", () => {
  it.each(["control_plane", "cron", "user", "remediation"] as const)(
    "accepts initiated_by = %s",
    (initiated_by) => {
      expect(isGateRound(baseGateRound({ initiated_by }))).toBe(true);
    },
  );

  it("rejects an invalid initiated_by", () => {
    expect(isGateRound(baseGateRound({ initiated_by: "orchestrator" }))).toBe(false);
  });

  it("accepts restart_predecessor = null", () => {
    expect(isGateRound(baseGateRound({ restart_predecessor: null }))).toBe(true);
  });

  it("accepts restart_predecessor as a UUID string", () => {
    expect(isGateRound(baseGateRound({ restart_predecessor: newUuid() }))).toBe(true);
  });

  it("rejects a malformed UUID for restart_predecessor", () => {
    expect(isGateRound(baseGateRound({ restart_predecessor: "not-a-uuid" }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-046: gate_decision schema_version literal
// ---------------------------------------------------------------------------

describe("VAL-W1-046 gate_decision schema_version", () => {
  it("accepts canonical schema_version", () => {
    expect(isGateDecision(baseGateDecision())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isGateDecision(baseGateDecision({ schema_version: "relay.gate_decision.v2" })),
    ).toBe(false);
  });

  it("generated TS source contains the schema_version literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"relay\.gate_decision\.v1"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-047: gate_decision_drafts schema_version literal
// ---------------------------------------------------------------------------

describe("VAL-W1-047 gate_decision_drafts schema_version", () => {
  it("accepts canonical schema_version", () => {
    expect(isGateDecisionDraft(baseGateDecisionDraft())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({ schema_version: "relay.gate_decision_draft.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the schema_version literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"relay\.gate_decision_draft\.v1"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-048: gate_round schema_version literal
// ---------------------------------------------------------------------------

describe("VAL-W1-048 gate_round schema_version", () => {
  it("accepts canonical schema_version", () => {
    expect(isGateRound(baseGateRound())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(isGateRound(baseGateRound({ schema_version: "relay.gate_round.v2" }))).toBe(false);
  });

  it("generated TS source contains the schema_version literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"relay\.gate_round\.v1"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-058: actor_identity_hash sha256-<hex> pattern + actors
// ---------------------------------------------------------------------------

describe("VAL-W1-058 actor_identity_hash pattern + actors registry", () => {
  it("SHA256_HASH_PATTERN matches canonical form", () => {
    expect(SHA256_HASH_PATTERN).toBe("^sha256-[0-9a-f]{64}$");
  });

  it("accepts canonical sha256 wire form", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({ actor_identity_hash: "sha256-" + "f".repeat(64) }),
      ),
    ).toBe(true);
  });

  it("rejects the colon form", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({ actor_identity_hash: "sha256:" + "a".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("rejects short hex (63 chars)", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({ actor_identity_hash: "sha256-" + "a".repeat(63) }),
      ),
    ).toBe(false);
  });

  it("rejects uppercase hex", () => {
    expect(
      isGateDecisionDraft(
        baseGateDecisionDraft({ actor_identity_hash: "sha256-" + "A".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("Actor type accepts canonical fields", () => {
    const actor: Actor = {
      identity_hash: "sha256-" + "0".repeat(64),
      kind: "worker",
      created_at: "2026-05-12T00:00:00Z",
      revoked_at: null,
    };
    expect(isActor(actor)).toBe(true);
  });

  it.each(["human", "bot", "worker", "reviewer"] as const)(
    "accepts actor.kind = %s",
    (kind) => {
      const a = parseActor({
        identity_hash: "sha256-" + "1".repeat(64),
        kind,
        created_at: "2026-05-12T00:00:00Z",
        revoked_at: null,
      });
      expect(a.kind).toBe(kind);
    },
  );

  it("rejects an invalid actor.kind", () => {
    expect(
      isActor({
        identity_hash: "sha256-" + "2".repeat(64),
        kind: "robot",
        created_at: "2026-05-12T00:00:00Z",
        revoked_at: null,
      }),
    ).toBe(false);
  });

  it("generated TS source pins the sha256 pattern", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    expect(text).toContain("^sha256-[0-9a-f]{64}$");
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-059: gate_decision optional decision_epoch >= 0 default 0
// ---------------------------------------------------------------------------

describe("VAL-W1-059 gate_decision decision_epoch", () => {
  it("defaults to 0 when omitted", () => {
    const payload = baseGateDecision();
    delete (payload as { decision_epoch?: number | null }).decision_epoch;
    const parsed = parseGateDecision(payload);
    expect(parsed.decision_epoch).toBe(0);
  });

  it("accepts a positive integer", () => {
    expect(isGateDecision(baseGateDecision({ decision_epoch: 42 }))).toBe(true);
  });

  it("rejects a negative integer", () => {
    expect(isGateDecision(baseGateDecision({ decision_epoch: -1 }))).toBe(false);
  });

  it("coerces null to 0 (int | None default 0)", () => {
    const parsed = parseGateDecision(baseGateDecision({ decision_epoch: null }));
    expect(parsed.decision_epoch).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Defense-in-depth: extra fields rejected
// ---------------------------------------------------------------------------

describe("extra-field rejection (defense in depth)", () => {
  it("rejects unknown fields on RunResult", () => {
    expect(isRunResult(baseRunResult({ unknown_field: "value" }))).toBe(false);
  });

  it("rejects unknown fields on GateDecision", () => {
    expect(isGateDecision(baseGateDecision({ unknown_field: "value" }))).toBe(false);
  });
});
