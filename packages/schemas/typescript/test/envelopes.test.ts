/**
 * W1.1 + W1.2 envelope schema tests (TypeScript).
 *
 * Covers contract assertions VAL-W1-001 through VAL-W1-017, VAL-W1-046,
 * VAL-W1-047, VAL-W1-048, VAL-W1-049, VAL-W1-050, VAL-W1-051, VAL-W1-058,
 * and VAL-W1-059 from the TypeScript side.
 *
 * Each describe block carries the assertion ID in its title so the gate
 * engine can attribute pass/fail to the contract assertion.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, it, expect } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  Actor,
  canonicalBytes,
  ErrorEnvelope,
  EventLogEntry,
  EvidenceBundle,
  EvidenceClaim,
  GateDecision,
  GateDecisionDraft,
  GateRound,
  IdempotencyRecord,
  ManifestVersion,
  RedactionPolicy,
  ReplayCase,
  ReplayFixture,
  RunResult,
  ScopeStateEvalRun,
  ScopeStateEvidenceBundle,
  ScopeStateGateRound,
  ScopeStateRelease,
  ScopeStateReplayCase,
  ScopeStateRun,
  isActor,
  isErrorEnvelope,
  isEventLogEntry,
  isEvidenceBundle,
  isEvidenceClaim,
  isGateDecision,
  isGateDecisionDraft,
  isGateRound,
  isIdempotencyRecord,
  isManifestVersion,
  isRedactionPolicy,
  isReplayCase,
  isReplayFixture,
  isRunResult,
  isScopeState,
  parseActor,
  parseErrorEnvelope,
  parseEventLogEntry,
  parseEvidenceBundle,
  parseEvidenceClaim,
  parseGateDecision,
  parseGateDecisionDraft,
  parseGateRound,
  parseIdempotencyRecord,
  parseManifestVersion,
  parseRedactionPolicy,
  parseReplayCase,
  parseReplayFixture,
  parseRunResult,
  parseScopeState,
  RELAY_ERROR_CODE_PATTERN,
  serializeEventLogEntryCanonical,
  serializeReplayFixtureCanonical,
  SHA256_HASH_PATTERN,
  ULID_PATTERN,
} from "../src/envelopes.js";
import { RelayErrorCode } from "../src/error_codes.js";

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

// ===========================================================================
// W1.2 control-plane envelopes
// ===========================================================================
//
// Covers VAL-W1-009 through VAL-W1-017 plus the schema_version pins
// VAL-W1-049, VAL-W1-050, VAL-W1-051 from the TypeScript side.

const VALID_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VALID_REQUEST_DIGEST = "sha256-" + "c".repeat(64);
const VALID_COMMIT_HASH = "sha256-" + "d".repeat(64);

function baseManifestVersion(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.manifest.v1",
    manifest_version_id: newUuid(),
    manifest_id: newUuid(),
    commit_hash: VALID_COMMIT_HASH,
    body: { manifest_schema: "relay.manifest.v1" },
    signed_by: null,
    signature: null,
    signature_key_id: null,
    effective_at: "2026-05-12T00:00:00+00:00",
    effective_until: null,
    ...overrides,
  };
}

function baseScopeStateRun(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.scope_state.v1",
    scope_kind: "run",
    scope_id: newUuid(),
    project_id: newUuid(),
    state: "pending",
    epoch: 0,
    created_at: "2026-05-12T00:00:00+00:00",
    updated_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

function baseScopeStateReplayCase(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...baseScopeStateRun(),
    scope_kind: "replay_case",
    state: "proposed",
    ...overrides,
  };
}

function baseScopeStateGateRound(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...baseScopeStateRun(),
    scope_kind: "gate_round",
    state: "open",
    ...overrides,
  };
}

function baseScopeStateEvidenceBundle(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...baseScopeStateRun(),
    scope_kind: "evidence_bundle",
    state: "building",
    ...overrides,
  };
}

function baseScopeStateEvalRun(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...baseScopeStateRun(),
    scope_kind: "eval_run",
    state: "pending",
    ...overrides,
  };
}

function baseScopeStateRelease(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...baseScopeStateRun(),
    scope_kind: "release",
    state: "open",
    ...overrides,
  };
}

function baseIdempotencyRecord(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.idempotency_record.v1",
    idempotency_key: VALID_ULID,
    project_id: newUuid(),
    request_digest: VALID_REQUEST_DIGEST,
    response_status: 200,
    response_ref: null,
    first_seen_at: "2026-05-12T00:00:00+00:00",
    expires_at: "2026-05-13T00:00:00+00:00",
    ...overrides,
  };
}

function baseEventLogEntry(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.event_log_entry.v1",
    event_id: newUuid(),
    project_id: newUuid(),
    scope_type: "run",
    scope_id: newUuid(),
    event_type: "run.captured",
    actor_kind: "control_plane",
    actor_id: null,
    manifest_commit_hash: null,
    payload: {},
    occurred_at: "2026-05-12T00:00:00+00:00",
    ingest_sequence: 1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// VAL-W1-009: manifest_versions.commit_hash canonical sha256-<hex> form
// ---------------------------------------------------------------------------

describe("VAL-W1-009 manifest_versions.commit_hash canonical sha256 form", () => {
  it("accepts the canonical sha256-<64 lowercase hex> wire form", () => {
    expect(isManifestVersion(baseManifestVersion())).toBe(true);
  });

  it("rejects the colon form (sha256:<hex>)", () => {
    expect(
      isManifestVersion(
        baseManifestVersion({ commit_hash: "sha256:" + "a".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("rejects the bare-hex form (no prefix)", () => {
    expect(
      isManifestVersion(baseManifestVersion({ commit_hash: "a".repeat(64) })),
    ).toBe(false);
  });

  it("rejects 63-char hex", () => {
    expect(
      isManifestVersion(
        baseManifestVersion({ commit_hash: "sha256-" + "a".repeat(63) }),
      ),
    ).toBe(false);
  });

  it("rejects 64-char non-hex (contains 'g')", () => {
    expect(
      isManifestVersion(
        baseManifestVersion({ commit_hash: "sha256-" + "g" + "a".repeat(63) }),
      ),
    ).toBe(false);
  });

  it("parseManifestVersion error names commit_hash", () => {
    expect(() =>
      parseManifestVersion(
        baseManifestVersion({ commit_hash: "sha256:" + "a".repeat(64) }),
      ),
    ).toThrow(/commit_hash/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-010: manifest_versions.schema_version = "relay.manifest.v1"
// ---------------------------------------------------------------------------

describe("VAL-W1-010 manifest_versions.schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    const parsed = parseManifestVersion(baseManifestVersion());
    expect(parsed.schema_version).toBe("relay.manifest.v1");
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isManifestVersion(
        baseManifestVersion({ schema_version: "relay.manifest.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the manifest.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"relay\.manifest\.v1"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-011: scope_state is a discriminated union on scope_kind
// ---------------------------------------------------------------------------

describe("VAL-W1-011 scope_state discriminated union on scope_kind", () => {
  it.each([
    "pending",
    "captured",
    "validating",
    "gated",
    "result_written",
    "terminal",
  ] as const)("scope_kind=run accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateRun({ state }))).toBe(true);
  });

  it.each([
    "proposed",
    "fixtures_ready",
    "executing",
    "analyzed",
    "terminal",
  ] as const)("scope_kind=replay_case accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateReplayCase({ state }))).toBe(true);
  });

  it.each([
    "open",
    "draft_received",
    "evaluating",
    "decision_written",
    "restarted",
    "terminal",
  ] as const)("scope_kind=gate_round accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateGateRound({ state }))).toBe(true);
  });

  it.each([
    "building",
    "signed",
    "published",
    "superseded",
    "revoked",
  ] as const)("scope_kind=evidence_bundle accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateEvidenceBundle({ state }))).toBe(true);
  });

  it("rejects scope_kind=run with state=building (cross-tag)", () => {
    expect(isScopeState(baseScopeStateRun({ state: "building" }))).toBe(false);
  });

  it("rejects scope_kind=evidence_bundle with state=pending (cross-tag)", () => {
    expect(
      isScopeState(baseScopeStateEvidenceBundle({ state: "pending" })),
    ).toBe(false);
  });

  it("rejects an unknown scope_kind", () => {
    expect(
      isScopeState(baseScopeStateRun({ scope_kind: "orchestrator" })),
    ).toBe(false);
  });

  it("TS narrowing on the union discriminator returns the variant", () => {
    const parsed = parseScopeState(baseScopeStateRun()) as ScopeStateRun;
    expect(parsed.scope_kind).toBe("run");
    // Type-level narrowing: parsed.state is the run-only literal union.
    const _state: ScopeStateRun["state"] = parsed.state;
    expect(_state).toBe("pending");
  });

  it("narrows correctly across each scope_kind branch", () => {
    const r = parseScopeState(baseScopeStateReplayCase()) as ScopeStateReplayCase;
    expect(r.scope_kind).toBe("replay_case");
    const g = parseScopeState(baseScopeStateGateRound()) as ScopeStateGateRound;
    expect(g.scope_kind).toBe("gate_round");
    const e = parseScopeState(
      baseScopeStateEvidenceBundle(),
    ) as ScopeStateEvidenceBundle;
    expect(e.scope_kind).toBe("evidence_bundle");
  });
});

// ---------------------------------------------------------------------------
// VAL-V2M01-036: scope_state union spans all SIX scope_kinds. Python accepts
// scope_kind=eval_run and scope_kind=release (envelopes.py EvalRunScopeState /
// ReleaseScopeState, union spanning spec W lines 5072-5085); the hand-authored
// TS guard must accept the same documents. Py<->TS verdict parity.
// ---------------------------------------------------------------------------

describe("VAL-V2M01-036 scope_state union covers eval_run and release", () => {
  it.each([
    "pending",
    "running",
    "scored",
    "terminal",
  ] as const)("scope_kind=eval_run accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateEvalRun({ state }))).toBe(true);
  });

  it.each([
    "open",
    "gated",
    "released",
    "rolled_back",
    "terminal",
  ] as const)("scope_kind=release accepts state=%s", (state) => {
    expect(isScopeState(baseScopeStateRelease({ state }))).toBe(true);
  });

  it("rejects scope_kind=eval_run with a release state (cross-tag)", () => {
    expect(isScopeState(baseScopeStateEvalRun({ state: "open" }))).toBe(false);
  });

  it("rejects scope_kind=release with an eval_run state (cross-tag)", () => {
    expect(isScopeState(baseScopeStateRelease({ state: "running" }))).toBe(
      false,
    );
  });

  it("rejects scope_kind=eval_run with a run state (cross-tag)", () => {
    expect(
      isScopeState(baseScopeStateEvalRun({ state: "captured" })),
    ).toBe(false);
  });

  it("parseScopeState narrows eval_run and release variants", () => {
    const ev = parseScopeState(
      baseScopeStateEvalRun(),
    ) as ScopeStateEvalRun;
    expect(ev.scope_kind).toBe("eval_run");
    const evState: ScopeStateEvalRun["state"] = ev.state;
    expect(evState).toBe("pending");

    const rel = parseScopeState(
      baseScopeStateRelease(),
    ) as ScopeStateRelease;
    expect(rel.scope_kind).toBe("release");
    const relState: ScopeStateRelease["state"] = rel.state;
    expect(relState).toBe("open");
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-012: scope_state.epoch non-negative integer
// ---------------------------------------------------------------------------

describe("VAL-W1-012 scope_state.epoch non-negative", () => {
  it("accepts epoch = 0", () => {
    expect(isScopeState(baseScopeStateRun({ epoch: 0 }))).toBe(true);
  });

  it("accepts a large bigint-shaped number", () => {
    // 2**52 is the safe-integer ceiling; well within TS number's bigint
    // representational range.
    expect(isScopeState(baseScopeStateRun({ epoch: 2 ** 52 }))).toBe(true);
  });

  it("rejects epoch = -1", () => {
    expect(isScopeState(baseScopeStateRun({ epoch: -1 }))).toBe(false);
  });

  it("rejects a non-integer epoch", () => {
    expect(isScopeState(baseScopeStateRun({ epoch: 1.5 }))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-013: idempotency_records.idempotency_key ULID grammar
// ---------------------------------------------------------------------------

describe("VAL-W1-013 idempotency_records.idempotency_key ULID grammar", () => {
  it("accepts the canonical ULID", () => {
    expect(isIdempotencyRecord(baseIdempotencyRecord())).toBe(true);
  });

  it("rejects a 25-char key", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({ idempotency_key: VALID_ULID.slice(0, 25) }),
      ),
    ).toBe(false);
  });

  it("rejects a 27-char key", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({ idempotency_key: VALID_ULID + "Z" }),
      ),
    ).toBe(false);
  });

  it("rejects a lowercase ULID", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({ idempotency_key: VALID_ULID.toLowerCase() }),
      ),
    ).toBe(false);
  });

  it("rejects an excluded letter (I) at position 0", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({ idempotency_key: "I" + VALID_ULID.slice(1) }),
      ),
    ).toBe(false);
  });

  it("ULID_PATTERN constant is the canonical Crockford regex", () => {
    expect(ULID_PATTERN).toBe("^[0-9A-HJKMNP-TV-Z]{26}$");
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-014: idempotency_records.request_digest sha256 form (inherited)
// ---------------------------------------------------------------------------

describe("VAL-W1-014 idempotency_records.request_digest sha256 form", () => {
  it("accepts a canonical request_digest", () => {
    expect(isIdempotencyRecord(baseIdempotencyRecord())).toBe(true);
  });

  it("rejects the colon form on request_digest", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({
          request_digest: "sha256:" + "a".repeat(64),
        }),
      ),
    ).toBe(false);
  });

  it("rejects short request_digest", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({
          request_digest: "sha256-" + "a".repeat(63),
        }),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-015: event_log_entries.scope_type closed enum
// ---------------------------------------------------------------------------

describe("VAL-W1-015 event_log_entries.scope_type closed enum", () => {
  it.each([
    "run",
    "replay",
    "gate",
    "eval_run",
    "release",
    "manifest",
    "key",
    "other",
  ] as const)("accepts scope_type = %s", (scope_type) => {
    expect(isEventLogEntry(baseEventLogEntry({ scope_type }))).toBe(true);
  });

  it("rejects an unknown scope_type", () => {
    expect(
      isEventLogEntry(baseEventLogEntry({ scope_type: "unknown_kind" })),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-016: event_log_entries.actor_kind closed enum
// ---------------------------------------------------------------------------

describe("VAL-W1-016 event_log_entries.actor_kind closed enum", () => {
  it.each([
    "control_plane",
    "gate_engine",
    "worker",
    "sdk",
    "user",
    "cron",
  ] as const)("accepts actor_kind = %s", (actor_kind) => {
    expect(isEventLogEntry(baseEventLogEntry({ actor_kind }))).toBe(true);
  });

  it("rejects an unknown actor_kind", () => {
    expect(
      isEventLogEntry(baseEventLogEntry({ actor_kind: "orchestrator" })),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-017: event_log_entries.occurred_at RFC 3339 with timezone offset
// ---------------------------------------------------------------------------

describe("VAL-W1-017 event_log_entries.occurred_at RFC 3339 + offset required", () => {
  it("accepts the UTC 'Z' form", () => {
    expect(
      isEventLogEntry(baseEventLogEntry({ occurred_at: "2026-05-12T00:00:00Z" })),
    ).toBe(true);
  });

  it("accepts a positive offset (+05:30)", () => {
    expect(
      isEventLogEntry(
        baseEventLogEntry({ occurred_at: "2026-05-12T10:00:00+05:30" }),
      ),
    ).toBe(true);
  });

  it("accepts a negative offset (-08:00)", () => {
    expect(
      isEventLogEntry(
        baseEventLogEntry({ occurred_at: "2026-05-12T00:00:00-08:00" }),
      ),
    ).toBe(true);
  });

  it("rejects a naive string (no offset)", () => {
    expect(
      isEventLogEntry(
        baseEventLogEntry({ occurred_at: "2026-05-12T00:00:00" }),
      ),
    ).toBe(false);
  });

  it("parseEventLogEntry error message names occurred_at on naive input", () => {
    expect(() =>
      parseEventLogEntry(
        baseEventLogEntry({ occurred_at: "2026-05-12T00:00:00" }),
      ),
    ).toThrow(/occurred_at/);
  });

  it("canonical serializer preserves the offset string byte-for-byte", () => {
    for (const offsetStr of [
      "2026-05-12T10:00:00+05:30",
      "2026-05-12T10:00:00-08:00",
      "2026-05-12T10:00:00+00:00",
    ]) {
      const e = parseEventLogEntry(baseEventLogEntry({ occurred_at: offsetStr }));
      const bytes = serializeEventLogEntryCanonical(e);
      const decoded = JSON.parse(Buffer.from(bytes).toString("utf-8"));
      expect(decoded.occurred_at).toBe(offsetStr);
    }
  });

  it("cross-language fixture digest matches the Python serializer output", () => {
    // Fixture lives under packages/schemas/python/tests/fixtures/. Locate it
    // by walking up from this file's directory: dirname(test)=test/,
    // parent=packages/schemas/typescript/, then to ../python/tests/fixtures.
    const fixtureDir = path.resolve(
      __dirname,
      "..",
      "..",
      "python",
      "tests",
      "fixtures",
    );
    const payload = JSON.parse(
      fs.readFileSync(path.join(fixtureDir, "event_log_entry.json"), "utf-8"),
    );
    const expectedDigest = fs
      .readFileSync(path.join(fixtureDir, "event_log_entry.sha256"), "utf-8")
      .trim();

    const e = parseEventLogEntry(payload);
    const canonical = serializeEventLogEntryCanonical(e);
    const actualDigest =
      "sha256-" + crypto.createHash("sha256").update(canonical).digest("hex");
    expect(actualDigest).toBe(expectedDigest);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-049: scope_state schema_version literal "relay.scope_state.v1"
// ---------------------------------------------------------------------------

describe("VAL-W1-049 scope_state schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isScopeState(baseScopeStateRun())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isScopeState(
        baseScopeStateRun({ schema_version: "relay.scope_state.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the scope_state.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (text.match(/"relay\.scope_state\.v1"/g) ?? []).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-050: idempotency_record schema_version literal
// ---------------------------------------------------------------------------

describe("VAL-W1-050 idempotency_record schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isIdempotencyRecord(baseIdempotencyRecord())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isIdempotencyRecord(
        baseIdempotencyRecord({
          schema_version: "relay.idempotency_record.v2",
        }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the idempotency_record.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.idempotency_record\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-051: event_log_entry schema_version literal
// ---------------------------------------------------------------------------

describe("VAL-W1-051 event_log_entry schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isEventLogEntry(baseEventLogEntry())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isEventLogEntry(
        baseEventLogEntry({ schema_version: "relay.event_log_entry.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the event_log_entry.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.event_log_entry\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Defense-in-depth: extra-field rejection on the W1.2 envelopes
// ---------------------------------------------------------------------------

describe("extra-field rejection on W1.2 envelopes", () => {
  it("rejects unknown fields on ManifestVersion", () => {
    expect(
      isManifestVersion(baseManifestVersion({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on ScopeState (run variant)", () => {
    expect(
      isScopeState(baseScopeStateRun({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on IdempotencyRecord", () => {
    expect(
      isIdempotencyRecord(baseIdempotencyRecord({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on EventLogEntry", () => {
    expect(
      isEventLogEntry(baseEventLogEntry({ unknown_field: "value" })),
    ).toBe(false);
  });
});

// ===========================================================================
// W1.3 evidence + replay envelopes
// ===========================================================================
//
// Covers VAL-W1-018 through VAL-W1-025 (field-level constraints) and
// VAL-W1-052 through VAL-W1-055 (schema_version literal pins) from the
// TypeScript side.

const VALID_BUNDLE_DIGEST = "sha256-" + "e".repeat(64);
const VALID_CLAIM_DIGEST = "sha256-" + "f".repeat(64);
const VALID_INPUT_DIGEST = "sha256-" + "1".repeat(64);
const VALID_OUTPUT_DIGEST = "sha256-" + "2".repeat(64);
const VALID_INPUTS_DIGEST = "sha256-" + "3".repeat(64);
const VALID_FAILURE_SIG = "sha256-" + "4".repeat(64);

function baseEvidenceBundle(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_bundle.v1",
    evidence_bundle_id: newUuid(),
    org_id: newUuid(),
    project_id: newUuid(),
    scope_type: "run",
    scope_id: newUuid(),
    bundle_digest: VALID_BUNDLE_DIGEST,
    acef_core_version: "0.1.0",
    relay_extension_version: "0.1.0",
    signing_key_id: "key-evidence-001",
    signature_algorithm: "ES256",
    verification_status: "unverified",
    redaction_policy_version: "relay.redaction.v1#default",
    manifest_commit_hash: VALID_MANIFEST_HASH,
    object_ref: "r2://evidence/00000000-0000-4000-8000-000000000001",
    supersedes_bundle_id: null,
    created_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

// Canonical nested-subject EvidenceClaim per the V3M1-F05 wire shape
// (spec K lines 4388-4438). Python EvidenceClaim.model_validate requires the
// nested subject + actor_kind / actor_identity_hash / occurred_at fields; the
// TS guard must accept the same document. Py<->TS verdict parity.
function baseEvidenceClaim(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_claim.v1",
    evidence_claim_id: newUuid(),
    evidence_bundle_id: newUuid(),
    claim_type: "run_result",
    subject: {
      kind: "run",
      id: newUuid(),
      manifest_commit_hash: VALID_MANIFEST_HASH,
    },
    evidence_refs: [],
    claim_predicate: null,
    claim_digest: VALID_CLAIM_DIGEST,
    redaction_transform_version: "relay.redaction.v1#transform-001",
    actor_kind: "control_plane",
    actor_identity_hash: VALID_ACTOR_HASH,
    occurred_at: "2026-05-12T00:00:00+00:00",
    manifest_commit_hash: VALID_MANIFEST_HASH,
    signer_key_id: "key-claim-001",
    signature: VALID_SIGNATURE,
    supersedes_claim_id: null,
    namespaces: null,
    created_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

// Legacy FLAT-subject EvidenceClaim construction form. Mirrors Python's
// back-compat shim (envelopes.py _absorb_flat_subject) which absorbs
// subject_kind / subject_id into a nested subject before extra-field
// rejection. Carries the V3M1-F05 fields (required by both runtimes) but
// supplies the subject via the flat keys instead of the nested object.
function baseEvidenceClaimFlat(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.evidence_claim.v1",
    evidence_claim_id: newUuid(),
    evidence_bundle_id: newUuid(),
    claim_type: "run_result",
    subject_kind: "run",
    subject_id: newUuid(),
    evidence_refs: [],
    claim_predicate: null,
    claim_digest: VALID_CLAIM_DIGEST,
    redaction_transform_version: "relay.redaction.v1#transform-001",
    actor_kind: "control_plane",
    actor_identity_hash: VALID_ACTOR_HASH,
    occurred_at: "2026-05-12T00:00:00+00:00",
    manifest_commit_hash: VALID_MANIFEST_HASH,
    signer_key_id: "key-claim-001",
    signature: VALID_SIGNATURE,
    supersedes_claim_id: null,
    namespaces: null,
    created_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

function baseReplayCase(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.replay_case.v1",
    replay_case_id: newUuid(),
    project_id: newUuid(),
    source_run_id: newUuid(),
    failure_signature_hash: VALID_FAILURE_SIG,
    inputs_ref: "r2://replay/inputs/00000000-0000-4000-8000-000000000002",
    inputs_digest: VALID_INPUTS_DIGEST,
    expected_assertion_ids: [],
    human_reviewed: false,
    reviewer_email: null,
    reviewed_at: null,
    status: "proposed",
    created_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

function baseReplayFixture(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.replay_fixture.v1",
    fixture_id: newUuid(),
    replay_case_id: newUuid(),
    source_span_id: newUuid(),
    kind: "model_call",
    mode: "cassette",
    redaction_policy_version: "relay.redaction.v1#default",
    input_digest: VALID_INPUT_DIGEST,
    output_ref: "r2://replay/outputs/00000000-0000-4000-8000-000000000003",
    output_digest: VALID_OUTPUT_DIGEST,
    provider: "openai",
    model: "gpt-4o-mini",
    model_signature: "fp_abc123",
    capture_clock: "2026-05-12T10:00:00+05:30",
    refresh_policy: "invalidate_on_signature_change",
    side_effect_class: "read_only",
    allowed_in_replay: false,
    created_at: "2026-05-12T00:00:00+00:00",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// VAL-W1-018: evidence_bundles.bundle_digest sha256 pattern, non-nullable
// ---------------------------------------------------------------------------

describe("VAL-W1-018 evidence_bundles.bundle_digest sha256 pattern", () => {
  it("accepts a canonical sha256-<hex> bundle_digest", () => {
    expect(isEvidenceBundle(baseEvidenceBundle())).toBe(true);
  });

  it("rejects a missing bundle_digest", () => {
    const payload = baseEvidenceBundle();
    delete payload.bundle_digest;
    expect(isEvidenceBundle(payload)).toBe(false);
  });

  it("rejects a null bundle_digest", () => {
    expect(
      isEvidenceBundle(baseEvidenceBundle({ bundle_digest: null })),
    ).toBe(false);
  });

  it("rejects the colon-form bundle_digest", () => {
    expect(
      isEvidenceBundle(
        baseEvidenceBundle({ bundle_digest: "sha256:" + "a".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("rejects a 63-char hex bundle_digest", () => {
    expect(
      isEvidenceBundle(
        baseEvidenceBundle({ bundle_digest: "sha256-" + "a".repeat(63) }),
      ),
    ).toBe(false);
  });

  it("parseEvidenceBundle names bundle_digest in the error message", () => {
    expect(() =>
      parseEvidenceBundle(
        baseEvidenceBundle({ bundle_digest: "sha256:" + "a".repeat(64) }),
      ),
    ).toThrow(/bundle_digest/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-019: evidence_bundles.verification_status closed enum
// ---------------------------------------------------------------------------

describe("VAL-W1-019 evidence_bundles.verification_status closed enum", () => {
  for (const status of ["unverified", "verified", "tampered", "revoked"]) {
    it(`accepts the canonical verification_status '${status}'`, () => {
      expect(
        isEvidenceBundle(baseEvidenceBundle({ verification_status: status })),
      ).toBe(true);
    });
  }

  it("rejects an unknown verification_status value", () => {
    expect(
      isEvidenceBundle(
        baseEvidenceBundle({ verification_status: "approved" }),
      ),
    ).toBe(false);
  });

  it("rejects an empty verification_status", () => {
    expect(
      isEvidenceBundle(baseEvidenceBundle({ verification_status: "" })),
    ).toBe(false);
  });

  it("parseEvidenceBundle names verification_status in the error message", () => {
    expect(() =>
      parseEvidenceBundle(
        baseEvidenceBundle({ verification_status: "approved" }),
      ),
    ).toThrow(/verification_status/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-020: evidence_claims.claim_type closed enum of eight kinds
// ---------------------------------------------------------------------------

describe("VAL-W1-020 evidence_claims.claim_type closed enum of eight kinds", () => {
  for (const claimType of [
    "run_result",
    "gate_decision",
    "contract_result",
    "replay_result",
    "human_oversight",
    "incident",
    "data_quality_check",
    "provider_compatibility",
  ]) {
    it(`accepts the canonical claim_type '${claimType}'`, () => {
      expect(
        isEvidenceClaim(baseEvidenceClaim({ claim_type: claimType })),
      ).toBe(true);
    });
  }

  it("rejects an unknown claim_type", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ claim_type: "orchestrator_decision" }),
      ),
    ).toBe(false);
  });
});

// EvidenceRef extra-field rejection (roborev a2adc74): Python EvidenceRef is
// extra="forbid"; the TS parser must reject unknown keys too, not silently drop
// them. Exercised through parseEvidenceClaim, which parses each evidence_ref.
describe("EvidenceRef extra=forbid parity", () => {
  it("accepts a well-formed evidence_ref", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          evidence_refs: [
            { kind: "artifact", ref: "artifact:abc", digest: null, value: null },
          ],
        }),
      ),
    ).toBe(true);
  });

  it("rejects an evidence_ref carrying an unexpected key", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          evidence_refs: [
            {
              kind: "artifact",
              ref: "artifact:abc",
              digest: null,
              value: null,
              unexpected_key: 1,
            },
          ],
        }),
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-021: evidence_claims.claim_digest + signature + supersedes_claim_id
// ---------------------------------------------------------------------------

describe("VAL-W1-021 evidence_claims field constraints", () => {
  it("accepts the canonical claim_digest", () => {
    expect(isEvidenceClaim(baseEvidenceClaim())).toBe(true);
  });

  it("rejects colon-form claim_digest", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ claim_digest: "sha256:" + "a".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("rejects 63-char hex claim_digest", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ claim_digest: "sha256-" + "a".repeat(63) }),
      ),
    ).toBe(false);
  });

  it("rejects an empty signature", () => {
    expect(isEvidenceClaim(baseEvidenceClaim({ signature: "" }))).toBe(false);
  });

  it("parseEvidenceClaim names signature in the error message on empty", () => {
    expect(() => parseEvidenceClaim(baseEvidenceClaim({ signature: "" }))).toThrow(
      /signature/,
    );
  });

  it("accepts a null supersedes_claim_id", () => {
    expect(
      isEvidenceClaim(baseEvidenceClaim({ supersedes_claim_id: null })),
    ).toBe(true);
  });

  it("accepts a UUID supersedes_claim_id", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ supersedes_claim_id: newUuid() }),
      ),
    ).toBe(true);
  });

  it("rejects a non-UUID supersedes_claim_id", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ supersedes_claim_id: "not-a-uuid" }),
      ),
    ).toBe(false);
  });

  it("parseEvidenceClaim names supersedes_claim_id on a non-UUID string", () => {
    expect(() =>
      parseEvidenceClaim(
        baseEvidenceClaim({ supersedes_claim_id: "not-a-uuid" }),
      ),
    ).toThrow(/supersedes_claim_id/);
  });
});

// ---------------------------------------------------------------------------
// VAL-V3M1-015: EvidenceClaim canonical NESTED subject shape. Python
// EvidenceClaim.model_validate (envelopes.py) requires subject:{kind,id,
// manifest_commit_hash} + the V3M1-F05 fields (evidence_refs, claim_predicate,
// actor_kind, actor_identity_hash, occurred_at, namespaces) and absorbs a flat
// subject_kind/subject_id legacy claim via _absorb_flat_subject. The
// hand-authored TS guard must accept the same documents. Py<->TS verdict
// parity.
// ---------------------------------------------------------------------------

describe("VAL-V3M1-015 evidence_claims nested subject + V3M1-F05 fields", () => {
  it("accepts the canonical nested-subject claim", () => {
    expect(isEvidenceClaim(baseEvidenceClaim())).toBe(true);
  });

  it("exposes nested subject.kind / subject.id / subject.manifest_commit_hash", () => {
    const subjectId = newUuid();
    const claim = parseEvidenceClaim(
      baseEvidenceClaim({
        subject: {
          kind: "eval_run",
          id: subjectId,
          manifest_commit_hash: VALID_MANIFEST_HASH,
        },
      }),
    );
    expect(claim.subject.kind).toBe("eval_run");
    expect(claim.subject.id).toBe(subjectId);
    expect(claim.subject.manifest_commit_hash).toBe(VALID_MANIFEST_HASH);
  });

  it.each([
    "run",
    "replay",
    "eval_run",
    "release",
    "domain_pack",
    "ai_system",
  ] as const)("accepts subject.kind=%s", (kind) => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          subject: {
            kind,
            id: newUuid(),
            manifest_commit_hash: VALID_MANIFEST_HASH,
          },
        }),
      ),
    ).toBe(true);
  });

  it("rejects an unknown subject.kind", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          subject: {
            kind: "bogus_kind",
            id: newUuid(),
            manifest_commit_hash: VALID_MANIFEST_HASH,
          },
        }),
      ),
    ).toBe(false);
  });

  it("rejects a non-UUID subject.id", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          subject: {
            kind: "run",
            id: "not-a-uuid",
            manifest_commit_hash: VALID_MANIFEST_HASH,
          },
        }),
      ),
    ).toBe(false);
  });

  it("rejects a missing subject object entirely", () => {
    const payload = baseEvidenceClaim();
    delete payload.subject;
    expect(isEvidenceClaim(payload)).toBe(false);
  });

  it("requires actor_kind (V3M1-F05) and rejects when absent", () => {
    const payload = baseEvidenceClaim();
    delete payload.actor_kind;
    expect(isEvidenceClaim(payload)).toBe(false);
  });

  it("rejects an unknown actor_kind enum value", () => {
    expect(
      isEvidenceClaim(baseEvidenceClaim({ actor_kind: "orchestrator" })),
    ).toBe(false);
  });

  it("requires actor_identity_hash (canonical sha256 form)", () => {
    const payload = baseEvidenceClaim();
    delete payload.actor_identity_hash;
    expect(isEvidenceClaim(payload)).toBe(false);
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ actor_identity_hash: "sha256:" + "a".repeat(64) }),
      ),
    ).toBe(false);
  });

  it("requires occurred_at as an RFC 3339 datetime", () => {
    const payload = baseEvidenceClaim();
    delete payload.occurred_at;
    expect(isEvidenceClaim(payload)).toBe(false);
  });

  it("defaults evidence_refs to [] when omitted", () => {
    const payload = baseEvidenceClaim();
    delete payload.evidence_refs;
    const claim = parseEvidenceClaim(payload);
    expect(claim.evidence_refs).toEqual([]);
  });

  it("accepts a populated evidence_refs list", () => {
    const claim = parseEvidenceClaim(
      baseEvidenceClaim({
        evidence_refs: [
          { kind: "artifact", ref: "r2://x", digest: VALID_CLAIM_DIGEST },
          { kind: "exit_code", ref: "exit", value: 0 },
        ],
      }),
    );
    expect(claim.evidence_refs).toHaveLength(2);
  });

  it("accepts a null claim_predicate and a nested op/args predicate", () => {
    expect(isEvidenceClaim(baseEvidenceClaim({ claim_predicate: null }))).toBe(
      true,
    );
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          claim_predicate: {
            op: "and",
            args: [{ op: "run_result_status_is", value: "accepted" }],
          },
        }),
      ),
    ).toBe(true);
  });

  it("accepts a null namespaces and an x-relay extension envelope", () => {
    expect(isEvidenceClaim(baseEvidenceClaim({ namespaces: null }))).toBe(true);
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({
          namespaces: { "x-relay": { schema_version: "v1" } },
        }),
      ),
    ).toBe(true);
  });

  it("absorbs a flat subject_kind/subject_id legacy claim (back-compat shim)", () => {
    const flatId = newUuid();
    const claim = parseEvidenceClaim(
      baseEvidenceClaimFlat({ subject_kind: "run", subject_id: flatId }),
    );
    // Flat keys are absorbed into the nested subject; manifest_commit_hash is
    // mirrored from the top-level field (Python _absorb_flat_subject parity).
    expect(claim.subject.kind).toBe("run");
    expect(claim.subject.id).toBe(flatId);
    expect(claim.subject.manifest_commit_hash).toBe(VALID_MANIFEST_HASH);
  });

  it("rejects a legacy flat claim whose subject_id is not a UUID", () => {
    expect(
      isEvidenceClaim(baseEvidenceClaimFlat({ subject_id: "not-a-uuid" })),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-022: replay_cases.status enum + expected_assertion_ids +
//             required failure_signature_hash
// ---------------------------------------------------------------------------

describe("VAL-W1-022 replay_cases field constraints", () => {
  for (const status of ["proposed", "approved", "retired"]) {
    it(`accepts the canonical status '${status}'`, () => {
      expect(isReplayCase(baseReplayCase({ status }))).toBe(true);
    });
  }

  it("rejects an invalid status", () => {
    expect(
      isReplayCase(baseReplayCase({ status: "approved_with_gaps" })),
    ).toBe(false);
  });

  it("status defaults to 'proposed' when omitted", () => {
    const payload = baseReplayCase();
    delete payload.status;
    const rc = parseReplayCase(payload);
    expect(rc.status).toBe("proposed");
  });

  it("expected_assertion_ids defaults to [] when omitted", () => {
    const payload = baseReplayCase();
    delete payload.expected_assertion_ids;
    const rc = parseReplayCase(payload);
    expect(rc.expected_assertion_ids).toEqual([]);
  });

  it("accepts non-empty string IDs in expected_assertion_ids", () => {
    expect(
      isReplayCase(
        baseReplayCase({
          expected_assertion_ids: ["VAL-STRUCTURED-001", "VAL-STRUCTURED-002"],
        }),
      ),
    ).toBe(true);
  });

  it("rejects an empty-string member in expected_assertion_ids", () => {
    expect(
      isReplayCase(baseReplayCase({ expected_assertion_ids: [""] })),
    ).toBe(false);
  });

  it("rejects a non-string member in expected_assertion_ids", () => {
    expect(
      isReplayCase(baseReplayCase({ expected_assertion_ids: [123] })),
    ).toBe(false);
  });

  it("rejects a missing failure_signature_hash", () => {
    const payload = baseReplayCase();
    delete payload.failure_signature_hash;
    expect(isReplayCase(payload)).toBe(false);
  });

  it("rejects an empty failure_signature_hash", () => {
    expect(
      isReplayCase(baseReplayCase({ failure_signature_hash: "" })),
    ).toBe(false);
  });

  it("parseReplayCase names failure_signature_hash in the error message", () => {
    expect(() =>
      parseReplayCase(baseReplayCase({ failure_signature_hash: "" })),
    ).toThrow(/failure_signature_hash/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-023: replay_fixtures kind / mode / side_effect_class enums +
//             allowed_in_replay strict bool
// ---------------------------------------------------------------------------

describe("VAL-W1-023 replay_fixtures closed enums + strict bool", () => {
  for (const kind of [
    "model_call",
    "tool_call",
    "retrieval",
    "embedding",
    "custom",
  ]) {
    it(`accepts the canonical kind '${kind}'`, () => {
      expect(isReplayFixture(baseReplayFixture({ kind }))).toBe(true);
    });
  }

  it("rejects an unknown kind", () => {
    expect(
      isReplayFixture(baseReplayFixture({ kind: "planning_call" })),
    ).toBe(false);
  });

  for (const mode of ["cassette", "live", "degraded_live", "mock"]) {
    it(`accepts the canonical mode '${mode}'`, () => {
      expect(isReplayFixture(baseReplayFixture({ mode }))).toBe(true);
    });
  }

  it("rejects an unknown mode", () => {
    expect(
      isReplayFixture(baseReplayFixture({ mode: "passthrough" })),
    ).toBe(false);
  });

  for (const side_effect_class of [
    "read_only",
    "mutating",
    "external_irreversible",
    "approval_required",
  ]) {
    it(`accepts the canonical side_effect_class '${side_effect_class}'`, () => {
      expect(
        isReplayFixture(baseReplayFixture({ side_effect_class })),
      ).toBe(true);
    });
  }

  it("rejects an unknown side_effect_class", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ side_effect_class: "audited" }),
      ),
    ).toBe(false);
  });

  it("allowed_in_replay defaults to false when omitted", () => {
    const payload = baseReplayFixture();
    delete payload.allowed_in_replay;
    const rf = parseReplayFixture(payload);
    expect(rf.allowed_in_replay).toBe(false);
  });

  it("accepts allowed_in_replay = true", () => {
    expect(
      isReplayFixture(baseReplayFixture({ allowed_in_replay: true })),
    ).toBe(true);
  });

  it("rejects string 'true' for allowed_in_replay", () => {
    expect(
      isReplayFixture(baseReplayFixture({ allowed_in_replay: "true" })),
    ).toBe(false);
  });

  it("rejects string 'false' for allowed_in_replay", () => {
    expect(
      isReplayFixture(baseReplayFixture({ allowed_in_replay: "false" })),
    ).toBe(false);
  });

  it("rejects int 1 for allowed_in_replay", () => {
    expect(
      isReplayFixture(baseReplayFixture({ allowed_in_replay: 1 })),
    ).toBe(false);
  });

  it("parseReplayFixture names allowed_in_replay in the error message", () => {
    expect(() =>
      parseReplayFixture(baseReplayFixture({ allowed_in_replay: "true" })),
    ).toThrow(/allowed_in_replay/);
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-024: replay_fixtures.capture_clock RFC 3339 timezone-aware +
//             cross-language byte-equal round-trip fixture
// ---------------------------------------------------------------------------

describe("VAL-W1-024 replay_fixtures.capture_clock RFC 3339 + offset required", () => {
  it("accepts the UTC 'Z' form", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ capture_clock: "2026-05-12T00:00:00Z" }),
      ),
    ).toBe(true);
  });

  it("accepts a positive offset (+05:30)", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ capture_clock: "2026-05-12T10:00:00+05:30" }),
      ),
    ).toBe(true);
  });

  it("accepts a negative offset (-08:00)", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ capture_clock: "2026-05-12T00:00:00-08:00" }),
      ),
    ).toBe(true);
  });

  it("rejects a naive string (no offset)", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ capture_clock: "2026-05-12T00:00:00" }),
      ),
    ).toBe(false);
  });

  it("parseReplayFixture names capture_clock on naive input", () => {
    expect(() =>
      parseReplayFixture(
        baseReplayFixture({ capture_clock: "2026-05-12T00:00:00" }),
      ),
    ).toThrow(/capture_clock/);
  });

  it("canonical serializer preserves the capture_clock offset byte-for-byte", () => {
    for (const offsetStr of [
      "2026-05-12T10:00:00+05:30",
      "2026-05-12T10:00:00-08:00",
      "2026-05-12T10:00:00+00:00",
    ]) {
      const rf = parseReplayFixture(
        baseReplayFixture({ capture_clock: offsetStr }),
      );
      const bytes = serializeReplayFixtureCanonical(rf);
      const decoded = JSON.parse(Buffer.from(bytes).toString("utf-8"));
      expect(decoded.capture_clock).toBe(offsetStr);
    }
  });

  it("cross-language fixture digest matches the Python serializer output", () => {
    const fixtureDir = path.resolve(
      __dirname,
      "..",
      "..",
      "python",
      "tests",
      "fixtures",
    );
    const payload = JSON.parse(
      fs.readFileSync(
        path.join(fixtureDir, "replay_fixture_capture_clock.json"),
        "utf-8",
      ),
    );
    const expectedDigest = fs
      .readFileSync(
        path.join(fixtureDir, "replay_fixture_capture_clock.sha256"),
        "utf-8",
      )
      .trim();

    const rf = parseReplayFixture(payload);
    const canonical = serializeReplayFixtureCanonical(rf);
    const actualDigest =
      "sha256-" + crypto.createHash("sha256").update(canonical).digest("hex");
    expect(actualDigest).toBe(expectedDigest);
  });
});

// ---------------------------------------------------------------------------
// MED #8 follow-on: the offset-required datetime fields (occurred_at,
// capture_clock) MUST enforce the SAME strict RFC 3339 grammar as the plain
// fields, NOT a Date.parse-permissive trailing-offset check. Earlier
// checkRfc3339WithOffset only verified an offset tail (Z|+/-HH:MM) plus
// Date.parse, so it accepted Date.parse-permissive forms that Python's
// anchored strict regex (Rfc3339Datetime) rejects -- a Py<->TS verdict
// divergence (a P0 keystone). It also must reject a trailing newline so a
// value such as "...Z\n" is rejected on BOTH sides byte-for-byte.
//
// Each rejected literal below is also a `def`-mirrored Python test in
// packages/schemas/python/tests/test_envelopes.py so the two readers give
// the SAME accept/reject verdict for identical wire bytes.
// ---------------------------------------------------------------------------

// Forms with an RFC-3339-ish offset tail that the permissive Date.parse path
// accepted but the strict shared regex (and Python) reject.
const STRICT_OFFSET_REJECTS = [
  // No offset tail at all and a non-RFC-3339 (RFC-2822 / Date.parse) shape.
  "Mon May 12 2025 00:00:00",
  // RFC-2822-ish WITH a colon offset tail: passes a naive offset-tail check
  // and Date.parse, but is not strict RFC 3339.
  "Mon, 12 May 2025 00:00:00 +02:00",
  // Hour 24 with a 'Z' tail: Date.parse coerces it to a finite instant, but
  // strict RFC 3339 caps the hour at 23.
  "2026-05-12T24:00:00Z",
  // Missing the seconds component but with a 'Z' tail.
  "2026-05-12T00:00Z",
  // Colon-less offset: Date.parse-permissive, strict RFC 3339 forbids it.
  "2026-05-12T00:00:00+0200",
  // Trailing newline after a canonical timestamp: MUST be rejected on both
  // sides (Python anchors with \Z; TS must use a true end-of-input check).
  "2026-05-12T00:00:00Z\n",
  "2026-05-12T00:00:00+02:00\n",
];

const STRICT_OFFSET_ACCEPTS = [
  "2026-05-12T00:00:00Z",
  "2026-05-12T10:00:00+05:30",
  "2026-05-12T00:00:00-08:00",
  "2026-05-12T00:00:00.123456+00:00",
];

describe("MED#8 occurred_at enforces the strict RFC 3339 grammar (Py<->TS parity)", () => {
  for (const bad of STRICT_OFFSET_REJECTS) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      expect(
        isEventLogEntry(baseEventLogEntry({ occurred_at: bad })),
      ).toBe(false);
      expect(() =>
        parseEventLogEntry(baseEventLogEntry({ occurred_at: bad })),
      ).toThrow(/occurred_at/);
    });
  }

  for (const good of STRICT_OFFSET_ACCEPTS) {
    it(`accepts the canonical RFC 3339 + offset form ${JSON.stringify(good)}`, () => {
      expect(
        isEventLogEntry(baseEventLogEntry({ occurred_at: good })),
      ).toBe(true);
    });
  }
});

describe("MED#8 capture_clock enforces the strict RFC 3339 grammar (Py<->TS parity)", () => {
  for (const bad of STRICT_OFFSET_REJECTS) {
    it(`rejects ${JSON.stringify(bad)}`, () => {
      expect(
        isReplayFixture(baseReplayFixture({ capture_clock: bad })),
      ).toBe(false);
      expect(() =>
        parseReplayFixture(baseReplayFixture({ capture_clock: bad })),
      ).toThrow(/capture_clock/);
    });
  }

  for (const good of STRICT_OFFSET_ACCEPTS) {
    it(`accepts the canonical RFC 3339 + offset form ${JSON.stringify(good)}`, () => {
      expect(
        isReplayFixture(baseReplayFixture({ capture_clock: good })),
      ).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// VAL-W1-025: replay_fixtures.refresh_policy closed enum + default
// ---------------------------------------------------------------------------

describe("VAL-W1-025 replay_fixtures.refresh_policy closed enum", () => {
  for (const refreshPolicy of [
    "invalidate_on_signature_change",
    "hold_forever",
    "refresh_weekly",
    "invalidate_on_model_version_change",
  ]) {
    it(`accepts the canonical refresh_policy '${refreshPolicy}'`, () => {
      expect(
        isReplayFixture(
          baseReplayFixture({ refresh_policy: refreshPolicy }),
        ),
      ).toBe(true);
    });
  }

  it("rejects an unknown refresh_policy", () => {
    expect(
      isReplayFixture(baseReplayFixture({ refresh_policy: "refresh_daily" })),
    ).toBe(false);
  });

  it("refresh_policy defaults to invalidate_on_signature_change", () => {
    const payload = baseReplayFixture();
    delete payload.refresh_policy;
    const rf = parseReplayFixture(payload);
    expect(rf.refresh_policy).toBe("invalidate_on_signature_change");
  });
});

// ---------------------------------------------------------------------------
// VAL-W1-052..055: schema_version literal pins (W1.3 envelopes)
// ---------------------------------------------------------------------------

describe("VAL-W1-052 evidence_bundle schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isEvidenceBundle(baseEvidenceBundle())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isEvidenceBundle(
        baseEvidenceBundle({ schema_version: "relay.evidence_bundle.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the evidence_bundle.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.evidence_bundle\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

describe("VAL-W1-053 evidence_claim schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isEvidenceClaim(baseEvidenceClaim())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isEvidenceClaim(
        baseEvidenceClaim({ schema_version: "relay.evidence_claim.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the evidence_claim.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.evidence_claim\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

describe("VAL-W1-054 replay_case schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isReplayCase(baseReplayCase())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isReplayCase(baseReplayCase({ schema_version: "relay.replay_case.v2" })),
    ).toBe(false);
  });

  it("generated TS source contains the replay_case.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.replay_case\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

describe("VAL-W1-055 replay_fixture schema_version pinned", () => {
  it("accepts the canonical schema_version", () => {
    expect(isReplayFixture(baseReplayFixture())).toBe(true);
  });

  it("rejects a non-canonical schema_version", () => {
    expect(
      isReplayFixture(
        baseReplayFixture({ schema_version: "relay.replay_fixture.v2" }),
      ),
    ).toBe(false);
  });

  it("generated TS source contains the replay_fixture.v1 literal", () => {
    const src = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(src, "utf-8");
    const occurrences = (
      text.match(/"relay\.replay_fixture\.v1"/g) ?? []
    ).length;
    expect(occurrences).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Defense-in-depth: extra-field rejection on W1.3 envelopes
// ---------------------------------------------------------------------------

describe("extra-field rejection on W1.3 envelopes", () => {
  it("rejects unknown fields on EvidenceBundle", () => {
    expect(
      isEvidenceBundle(baseEvidenceBundle({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on EvidenceClaim", () => {
    expect(
      isEvidenceClaim(baseEvidenceClaim({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on ReplayCase", () => {
    expect(
      isReplayCase(baseReplayCase({ unknown_field: "value" })),
    ).toBe(false);
  });

  it("rejects unknown fields on ReplayFixture", () => {
    expect(
      isReplayFixture(baseReplayFixture({ unknown_field: "value" })),
    ).toBe(false);
  });
});

// Avoid TS "declared but never used" by referencing the type-narrowing
// constants. (Type-level usage suffices for the import to be reachable.)
const _typeRefs: ReadonlyArray<
  | ManifestVersion
  | ScopeStateRun
  | ScopeStateReplayCase
  | ScopeStateGateRound
  | ScopeStateEvidenceBundle
  | ScopeStateEvalRun
  | ScopeStateRelease
  | IdempotencyRecord
  | EventLogEntry
  | EvidenceBundle
  | EvidenceClaim
  | ReplayCase
  | ReplayFixture
  | RedactionPolicy
  | ErrorEnvelope
> = [];
void _typeRefs;

// ===========================================================================
// W1.4 - RedactionPolicy + ErrorEnvelope (VAL-W1-026..031, 056)
// ===========================================================================

function baseRedactionPolicy(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.redaction.v1",
    redaction_policy_id: newUuid(),
    org_id: newUuid(),
    version: "v1",
    raw_capture: false,
    dpa_ref: null,
    approver_user_id: null,
    matchers: [],
    created_at: "2026-05-13T00:00:00Z",
    ...overrides,
  };
}

function baseErrorEnvelope(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: "relay.error.v1",
    code: "RELAY-ING-031",
    http_status: 422,
    blocked_surface: "POST /api/ingest",
    retry_advice: "do_not_retry",
    request_id: "req-01HMA1ABCDEFG",
    trace_id: "trace-01HMA1ABCDEFG",
    ...overrides,
  };
}

describe("VAL-W1-026 RedactionPolicy schema_version + raw_capture StrictBool", () => {
  it("accepts the canonical schema_version literal", () => {
    const p = parseRedactionPolicy(baseRedactionPolicy());
    expect(p.schema_version).toBe("relay.redaction.v1");
  });

  it("rejects a wrong schema_version literal", () => {
    expect(() =>
      parseRedactionPolicy(baseRedactionPolicy({ schema_version: "relay.redaction.v2" })),
    ).toThrow(/schema_version/);
  });

  it("defaults raw_capture to false when omitted", () => {
    const payload = baseRedactionPolicy();
    delete payload.raw_capture;
    const p = parseRedactionPolicy(payload);
    expect(p.raw_capture).toBe(false);
  });

  it.each(["true", "false", "True", "False", 0, 1])(
    "rejects coercible raw_capture %p",
    (bad) => {
      expect(() =>
        parseRedactionPolicy(baseRedactionPolicy({ raw_capture: bad })),
      ).toThrow(/raw_capture/);
    },
  );

  it("accepts native true with required cross-fields", () => {
    const p = parseRedactionPolicy(
      baseRedactionPolicy({
        raw_capture: true,
        dpa_ref: "DPA-2026-001",
        approver_user_id: newUuid(),
      }),
    );
    expect(p.raw_capture).toBe(true);
  });
});

describe("VAL-W1-027 raw_capture=true requires dpa_ref + approver_user_id", () => {
  it("rejects when dpa_ref is null", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          raw_capture: true,
          dpa_ref: null,
          approver_user_id: newUuid(),
        }),
      ),
    ).toThrow(/raw_capture_requires_dpa_and_approver/);
  });

  it("rejects when approver_user_id is null", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          raw_capture: true,
          dpa_ref: "DPA-2026-001",
          approver_user_id: null,
        }),
      ),
    ).toThrow(/raw_capture_requires_dpa_and_approver/);
  });

  it("rejects when both are null", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          raw_capture: true,
          dpa_ref: null,
          approver_user_id: null,
        }),
      ),
    ).toThrow(/raw_capture_requires_dpa_and_approver/);
  });

  it("allows raw_capture=false with null dpa_ref and null approver", () => {
    const p = parseRedactionPolicy(
      baseRedactionPolicy({
        raw_capture: false,
        dpa_ref: null,
        approver_user_id: null,
      }),
    );
    expect(p.raw_capture).toBe(false);
  });
});

describe("VAL-W1-028 matchers[] tagged discriminated union on `kind`", () => {
  it("accepts a regex matcher with pattern", () => {
    const p = parseRedactionPolicy(
      baseRedactionPolicy({
        matchers: [{ kind: "regex", pattern: "[a-z]+@example.com" }],
      }),
    );
    expect(p.matchers).toHaveLength(1);
    expect(p.matchers[0]!.kind).toBe("regex");
  });

  it("accepts a json_pointer matcher with paths", () => {
    const p = parseRedactionPolicy(
      baseRedactionPolicy({
        matchers: [{ kind: "json_pointer", paths: ["/inputs/ssn"] }],
      }),
    );
    expect(p.matchers[0]!.kind).toBe("json_pointer");
  });

  it("rejects regex matcher carrying paths", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          matchers: [{ kind: "regex", pattern: "foo", paths: ["/x"] }],
        }),
      ),
    ).toThrow(/paths|extra/);
  });

  it("rejects json_pointer matcher carrying pattern", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          matchers: [
            { kind: "json_pointer", paths: ["/inputs/ssn"], pattern: "foo" },
          ],
        }),
      ),
    ).toThrow(/pattern|extra/);
  });

  it("rejects regex matcher missing pattern", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({ matchers: [{ kind: "regex" }] }),
      ),
    ).toThrow(/pattern/);
  });

  it("rejects unknown matcher kind", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          matchers: [{ kind: "fnmatch", pattern: "*.txt" }],
        }),
      ),
    ).toThrow(/kind/);
  });

  it("rejects json_pointer matcher with empty paths", () => {
    expect(() =>
      parseRedactionPolicy(
        baseRedactionPolicy({
          matchers: [{ kind: "json_pointer", paths: [] }],
        }),
      ),
    ).toThrow(/paths/);
  });

  it("type-narrowing: isRedactionPolicy returns false for bad input", () => {
    expect(isRedactionPolicy({ schema_version: "wrong" })).toBe(false);
  });
});

describe("VAL-W1-029 ErrorEnvelope required fields + retry_advice closed enum", () => {
  it("happy path", () => {
    const e = parseErrorEnvelope(baseErrorEnvelope());
    expect(e.schema_version).toBe("relay.error.v1");
    expect(e.code).toBe("RELAY-ING-031");
    expect(e.http_status).toBeGreaterThanOrEqual(400);
    expect(e.http_status).toBeLessThanOrEqual(599);
  });

  it.each([
    "schema_version",
    "code",
    "http_status",
    "blocked_surface",
    "retry_advice",
    "request_id",
    "trace_id",
  ])("rejects missing required field %s", (field) => {
    const payload = baseErrorEnvelope();
    delete payload[field];
    expect(() => parseErrorEnvelope(payload)).toThrow(new RegExp(field));
  });

  it.each([
    "relay-ing-031",
    "RELAY_ING_031",
    "ING-031",
    "RELAY-ING-31",
    "RELAY-ing-031",
    "",
    "RELAY-ING-0031",
  ])("rejects malformed code %p", (bad) => {
    expect(() => parseErrorEnvelope(baseErrorEnvelope({ code: bad }))).toThrow(
      /code/,
    );
  });

  it.each([200, 399, 600, 700, -1])(
    "rejects http_status %p outside [400,599]",
    (bad) => {
      expect(() =>
        parseErrorEnvelope(baseErrorEnvelope({ http_status: bad })),
      ).toThrow(/http_status/);
    },
  );

  it.each([400, 422, 499, 500, 599])(
    "accepts http_status %p in [400,599]",
    (good) => {
      const e = parseErrorEnvelope(baseErrorEnvelope({ http_status: good }));
      expect(e.http_status).toBe(good);
    },
  );

  it("rejects empty blocked_surface", () => {
    expect(() =>
      parseErrorEnvelope(baseErrorEnvelope({ blocked_surface: "" })),
    ).toThrow(/blocked_surface/);
  });

  it.each([
    "do_not_retry",
    "after_fix",
    "after_retry_after",
    "after_split",
    "after_recapture",
    "after_re_auth",
  ])("accepts retry_advice %p", (advice) => {
    const e = parseErrorEnvelope(baseErrorEnvelope({ retry_advice: advice }));
    expect(e.retry_advice).toBe(advice);
  });

  it.each(["After fix", "After Retry-After", "RETRY", "yes", "", "do-not-retry"])(
    "rejects non-canonical retry_advice %p",
    (bad) => {
      expect(() =>
        parseErrorEnvelope(baseErrorEnvelope({ retry_advice: bad })),
      ).toThrow(/retry_advice/);
    },
  );

  it("rejects unknown field on ErrorEnvelope", () => {
    expect(
      isErrorEnvelope(baseErrorEnvelope({ extra_field: "x" })),
    ).toBe(false);
  });
});

describe("VAL-W1-030 known RELAY-* codes generated as constants", () => {
  const REQUIRED_B4_CODES = [
    "RELAY-ING-001",
    "RELAY-ING-014",
    "RELAY-ING-021",
    "RELAY-ING-031",
    "RELAY-AUTH-001",
    "RELAY-AUTH-014",
    "RELAY-RATE-001",
    "RELAY-RATE-014",
    "RELAY-GATE-001",
    "RELAY-GATE-014",
    "RELAY-GATE-021",
    "RELAY-EVID-001",
    "RELAY-EVID-014",
    "RELAY-REPLAY-001",
    "RELAY-REPLAY-014",
  ];

  it.each(REQUIRED_B4_CODES)("RelayErrorCode contains constant for %s", (code) => {
    const attr = code.replace(/-/g, "_") as keyof typeof RelayErrorCode;
    expect(RelayErrorCode[attr]).toBe(code);
  });

  it("generated TS source contains all 15 spec B.4 codes", () => {
    const tsSrc = path.resolve(__dirname, "..", "src", "error_codes.ts");
    const text = fs.readFileSync(tsSrc, "utf-8");
    let count = 0;
    for (const c of REQUIRED_B4_CODES) {
      if (text.includes(`"${c}"`)) count++;
    }
    expect(count).toBe(15);
  });

  it("ErrorEnvelope accepts a code referenced via the generated constant", () => {
    const e = parseErrorEnvelope(
      baseErrorEnvelope({ code: RelayErrorCode.RELAY_GATE_021 }),
    );
    expect(e.code).toBe("RELAY-GATE-021");
  });
});

describe("VAL-W1-031 request_id + trace_id required non-empty strings", () => {
  it("rejects empty request_id", () => {
    expect(() =>
      parseErrorEnvelope(baseErrorEnvelope({ request_id: "" })),
    ).toThrow(/request_id/);
  });

  it("rejects empty trace_id", () => {
    expect(() =>
      parseErrorEnvelope(baseErrorEnvelope({ trace_id: "" })),
    ).toThrow(/trace_id/);
  });

  it("rejects non-string request_id", () => {
    expect(() =>
      parseErrorEnvelope(baseErrorEnvelope({ request_id: 12345 })),
    ).toThrow(/request_id/);
  });
});

describe("VAL-W1-056 ErrorEnvelope.schema_version literal 'relay.error.v1'", () => {
  it("rejects wrong schema_version", () => {
    expect(() =>
      parseErrorEnvelope(baseErrorEnvelope({ schema_version: "relay.error.v2" })),
    ).toThrow(/schema_version/);
  });

  it("generated TS source contains the 'relay.error.v1' literal at least once", () => {
    const tsSrc = path.resolve(__dirname, "..", "src", "envelopes.ts");
    const text = fs.readFileSync(tsSrc, "utf-8");
    const matches = text.match(/"relay\.error\.v1"/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });
});

describe("W1.4 RELAY_ERROR_CODE_PATTERN exported", () => {
  it("matches canonical RELAY-{AREA}-NNN wire form", () => {
    const re = new RegExp(RELAY_ERROR_CODE_PATTERN);
    expect(re.test("RELAY-ING-031")).toBe(true);
    expect(re.test("RELAY-GATE-021")).toBe(true);
    expect(re.test("relay-ing-031")).toBe(false);
    expect(re.test("RELAY-ING-31")).toBe(false);
  });
});

// canonicalBytes RFC-8785 behaviors (roborev 2132ab7): non-optional vitest
// coverage so the new TS canonicalization (ECMA-262 number ToString, UTF-16 key
// sort, unsafe-integer + non-finite rejection, raw-UTF-8 strings) is exercised
// even when the Python<->TS node parity test is skipped. The byte values mirror
// the Python relay_schemas.envelopes.canonical_bytes assertions.
describe("canonicalBytes RFC-8785 Py<->TS parity behaviors", () => {
  const dec = new TextDecoder();
  const enc = (v: unknown): string => dec.decode(canonicalBytes(v));

  it("ECMA-262 number ToString: whole float -> integer, -0 -> 0, small float exponential", () => {
    expect(enc({ whole: 1.0 })).toBe('{"whole":1}');
    expect(enc({ z: -0.0 })).toBe('{"z":0}');
    expect(enc({ e: 1e-7 })).toBe('{"e":1e-7}');
    expect(enc({ a: 12.5, b: 0.1, c: 0.001 })).toBe('{"a":12.5,"b":0.1,"c":0.001}');
  });

  it("object keys sort by UTF-16 code unit: SMP key sorts before U+FFFF", () => {
    // UTF-16 code units: "a"=0x0061 < U+1F600 (high surrogate 0xD83D) < U+FFFF.
    // (U+1F600 < U+FFFF is the OPPOSITE of Unicode code-point ordering.) Both
    // Python canonical_bytes and TS canonicalBytes emit this exact order.
    expect(enc({ "￿": 2, "\u{1F600}": 1, a: 3 })).toBe(
      '{"a":3,"\u{1F600}":1,"￿":2}',
    );
  });

  it("non-ASCII strings emit raw UTF-8 (no \\uXXXX escaping)", () => {
    expect(enc({ m: "café" })).toBe('{"m":"café"}');
  });

  it("rejects integers outside the JS safe-integer range (fail-closed parity)", () => {
    expect(() => canonicalBytes({ x: 2 ** 53 })).toThrow();
    expect(() => canonicalBytes({ x: -(2 ** 53) })).toThrow();
    expect(() => canonicalBytes({ x: 1e16 })).toThrow(); // integer-valued, > 2^53
    expect(() => canonicalBytes({ x: 1e18 })).toThrow();
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalBytes({ x: NaN })).toThrow();
    expect(() => canonicalBytes({ x: Infinity })).toThrow();
    expect(() => canonicalBytes({ x: -Infinity })).toThrow();
  });

  it("safe integers + nested structures round-trip identically", () => {
    expect(enc({ ints: [0, -1, 42, 9007199254740991, -9007199254740991] })).toBe(
      '{"ints":[0,-1,42,9007199254740991,-9007199254740991]}',
    );
    expect(enc({ nested: { z: [1, 2, { b: null, a: true }], y: "x" } })).toBe(
      '{"nested":{"y":"x","z":[1,2,{"a":true,"b":null}]}}',
    );
  });
});
