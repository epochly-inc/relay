/**
 * Generated TypeScript types and runtime guards for the Relay control-plane
 * envelopes.
 *
 * Source of truth: packages/schemas/raw/envelopes.yaml.
 *
 * This module is hand-authored to match the canonical YAML; the W1.5 codegen
 * pipeline (openapi-typescript) will replace the hand-authoring with generator
 * output, and the W1.5 drift check (VAL-W1-035) will enforce sync.
 *
 * Per CLAUDE.md keystone invariant #1, the canonical literal-string types on
 * `written_by` and `decided_by` enforce the control-plane-writes-the-result
 * rule at the wire-format layer in addition to the SQL CHECK constraints.
 *
 * Per CLAUDE.md keystone invariant #10, every canonical envelope carries a
 * `schema_version` field pinned to a string literal type. Engines refuse
 * unknown versions on write.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

/* -------------------------------------------------------------------------- */
/* Shared type aliases and constants                                           */
/* -------------------------------------------------------------------------- */

/**
 * Canonical Relay sha256 wire form: `sha256-` + 64 lowercase hex chars.
 * The colon form (`sha256:<hex>`) and bare-hex form are both rejected.
 */
export const SHA256_HASH_PATTERN = "^sha256-[0-9a-f]{64}$";
const SHA256_HASH_RE = new RegExp(SHA256_HASH_PATTERN);

/**
 * RFC 4122 UUID string form. Accepts versioned and nil UUIDs in canonical
 * 8-4-4-4-12 lowercase-hex form. We do not validate the version nibble.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * RFC 3339 timestamp form (date-time with timezone offset or 'Z'). The
 * full RFC 3339 grammar is permissive; we accept anything Date.parse
 * recognizes plus the canonical 'YYYY-MM-DDTHH:MM:SS[.fff]Z' form.
 */
function isRfc3339Datetime(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length < 20) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}

/* -------------------------------------------------------------------------- */
/* ValidationError                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Structured validation error with field-path context. Thrown by `parse*`
 * functions when input fails schema validation. The `field` and `reason`
 * properties are stable, machine-readable evidence the gate engine can
 * attribute to a contract assertion.
 */
export class ValidationError extends Error {
  public readonly field: string;
  public readonly reason: string;
  public readonly observed: unknown;

  constructor(field: string, reason: string, observed: unknown) {
    super(`${field}: ${reason} (observed=${describeValue(observed)})`);
    this.name = "ValidationError";
    this.field = field;
    this.reason = reason;
    this.observed = observed;
  }
}

function describeValue(v: unknown): string {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return typeof v;
}

/* -------------------------------------------------------------------------- */
/* Field-level validators (private)                                            */
/* -------------------------------------------------------------------------- */

function checkLiteral<T extends string>(
  field: string,
  value: unknown,
  expected: T,
): asserts value is T {
  if (value !== expected) {
    throw new ValidationError(field, `must equal literal ${JSON.stringify(expected)}`, value);
  }
}

function checkEnum<T extends string>(
  field: string,
  value: unknown,
  allowed: readonly T[],
): asserts value is T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new ValidationError(
      field,
      `must be one of {${allowed.map((a) => JSON.stringify(a)).join(", ")}}`,
      value,
    );
  }
}

function checkUuid(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new ValidationError(field, "must be a canonical RFC 4122 UUID string", value);
  }
}

function checkUuidNullable(field: string, value: unknown): asserts value is string | null {
  if (value === null || value === undefined) return;
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new ValidationError(field, "must be a canonical RFC 4122 UUID string or null", value);
  }
}

function checkSha256Hash(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || !SHA256_HASH_RE.test(value)) {
    throw new ValidationError(
      field,
      "must match canonical sha256-<64 lowercase hex> wire form",
      value,
    );
  }
}

function checkString(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string") {
    throw new ValidationError(field, "must be a string", value);
  }
}

function checkStringNullable(field: string, value: unknown): asserts value is string | null {
  if (value === null || value === undefined) return;
  if (typeof value !== "string") {
    throw new ValidationError(field, "must be a string or null", value);
  }
}

function checkBool(field: string, value: unknown): asserts value is boolean {
  if (typeof value !== "boolean") {
    throw new ValidationError(field, "must be a boolean", value);
  }
}

function checkIntegerGe(field: string, value: unknown, min: number): asserts value is number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min) {
    throw new ValidationError(field, `must be an integer >= ${min}`, value);
  }
}

function checkRfc3339(field: string, value: unknown): asserts value is string {
  if (!isRfc3339Datetime(value)) {
    throw new ValidationError(field, "must be an RFC 3339 date-time string", value);
  }
}

function checkRfc3339Nullable(
  field: string,
  value: unknown,
): asserts value is string | null {
  if (value === null || value === undefined) return;
  if (!isRfc3339Datetime(value)) {
    throw new ValidationError(field, "must be an RFC 3339 date-time string or null", value);
  }
}

function checkListOfStrings(field: string, value: unknown): asserts value is string[] {
  if (!Array.isArray(value)) {
    throw new ValidationError(field, "must be a list of strings", value);
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string") {
      throw new ValidationError(`${field}[${i}]`, "must be a string", value[i]);
    }
  }
}

function checkListOfUuids(field: string, value: unknown): asserts value is string[] {
  if (!Array.isArray(value)) {
    throw new ValidationError(field, "must be a list of UUID strings", value);
  }
  for (let i = 0; i < value.length; i++) {
    const v = value[i];
    if (typeof v !== "string" || !UUID_RE.test(v)) {
      throw new ValidationError(`${field}[${i}]`, "must be a canonical UUID string", v);
    }
  }
}

function checkListOfAny(field: string, value: unknown): asserts value is unknown[] {
  if (!Array.isArray(value)) {
    throw new ValidationError(field, "must be a list", value);
  }
}

function checkExtraFields(
  modelName: string,
  payload: Record<string, unknown>,
  allowed: readonly string[],
): void {
  for (const key of Object.keys(payload)) {
    if (!allowed.includes(key)) {
      throw new ValidationError(
        key,
        `extra field not permitted on ${modelName} (allowed: ${allowed.join(", ")})`,
        payload[key],
      );
    }
  }
}

/* -------------------------------------------------------------------------- */
/* RunResult (spec A.1)                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Canonical run outcome. Written exclusively by the control plane.
 *
 * - VAL-W1-001: schema_version pinned to "relay.run_result.v1"
 * - VAL-W1-002: written_by pinned to "control_plane"
 * - VAL-W1-003: status closed enum; accepted requires evidence_bundle_id
 */
export interface RunResult {
  readonly schema_version: "relay.run_result.v1";
  readonly run_result_id: string;
  readonly run_id: string;
  readonly project_id: string;
  readonly written_by: "control_plane";
  readonly status: "accepted" | "remediate_required" | "blocked" | "invalid";
  readonly primary_failure_class: string | null;
  readonly error_priority_rule: string;
  readonly evidence_bundle_id: string | null;
  readonly manifest_commit_hash: string;
  readonly actor_identity_hash: string;
  readonly decided_at: string;
  readonly decision_epoch: number;
  readonly signature: string;
  readonly signature_key_id: string;
}

const RUN_RESULT_FIELDS = [
  "schema_version",
  "run_result_id",
  "run_id",
  "project_id",
  "written_by",
  "status",
  "primary_failure_class",
  "error_priority_rule",
  "evidence_bundle_id",
  "manifest_commit_hash",
  "actor_identity_hash",
  "decided_at",
  "decision_epoch",
  "signature",
  "signature_key_id",
] as const;

const RUN_RESULT_STATUS = ["accepted", "remediate_required", "blocked", "invalid"] as const;

export function parseRunResult(input: unknown): RunResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("RunResult", p, RUN_RESULT_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.run_result.v1");
  checkUuid("run_result_id", p.run_result_id);
  checkUuid("run_id", p.run_id);
  checkUuid("project_id", p.project_id);
  checkLiteral("written_by", p.written_by, "control_plane");
  checkEnum("status", p.status, RUN_RESULT_STATUS);
  checkStringNullable("primary_failure_class", p.primary_failure_class);
  // error_priority_rule may be omitted (defaults), but if present must be a string.
  let errorPriorityRule = p.error_priority_rule;
  if (errorPriorityRule === undefined) {
    errorPriorityRule = "first_p0_then_highest_severity_then_earliest_span";
  } else {
    checkString("error_priority_rule", errorPriorityRule);
  }
  checkUuidNullable("evidence_bundle_id", p.evidence_bundle_id);
  checkSha256Hash("manifest_commit_hash", p.manifest_commit_hash);
  checkSha256Hash("actor_identity_hash", p.actor_identity_hash);
  checkRfc3339("decided_at", p.decided_at);

  let decisionEpoch = p.decision_epoch;
  if (decisionEpoch === undefined || decisionEpoch === null) {
    decisionEpoch = 0;
  } else {
    checkIntegerGe("decision_epoch", decisionEpoch, 0);
  }

  checkString("signature", p.signature);
  checkString("signature_key_id", p.signature_key_id);

  // VAL-W1-003 cross-field: status=accepted requires evidence_bundle_id.
  if (p.status === "accepted" && (p.evidence_bundle_id === null || p.evidence_bundle_id === undefined)) {
    throw new ValidationError(
      "evidence_bundle_id",
      "accepted_requires_evidence: status='accepted' requires evidence_bundle_id to be non-null",
      p.evidence_bundle_id,
    );
  }

  return {
    schema_version: "relay.run_result.v1",
    run_result_id: p.run_result_id as string,
    run_id: p.run_id as string,
    project_id: p.project_id as string,
    written_by: "control_plane",
    status: p.status as RunResult["status"],
    primary_failure_class: (p.primary_failure_class ?? null) as string | null,
    error_priority_rule: errorPriorityRule as string,
    evidence_bundle_id: (p.evidence_bundle_id ?? null) as string | null,
    manifest_commit_hash: p.manifest_commit_hash as string,
    actor_identity_hash: p.actor_identity_hash as string,
    decided_at: p.decided_at as string,
    decision_epoch: decisionEpoch as number,
    signature: p.signature as string,
    signature_key_id: p.signature_key_id as string,
  };
}

export function isRunResult(input: unknown): input is RunResult {
  try {
    parseRunResult(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* GateDecision (spec A.2)                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Canonical gate decision. Written exclusively by the gate engine.
 *
 * - VAL-W1-046: schema_version pinned to "relay.gate_decision.v1"
 * - VAL-W1-004: action closed enum; decided_by pinned to "gate_engine"
 * - VAL-W1-005: round int >= 1; failed_assertion_ids string[] default []
 * - VAL-W1-059: optional decision_epoch int >= 0 default 0; null coerces to 0
 */
export interface GateDecision {
  readonly schema_version: "relay.gate_decision.v1";
  readonly gate_decision_id: string;
  readonly gate_id: string;
  readonly scope_type: "run" | "replay" | "eval_run" | "release" | "domain_pack";
  readonly scope_id: string;
  readonly round: number;
  readonly action: "accept" | "remediate" | "block" | "invalid";
  readonly strict_pass: boolean;
  readonly failed_assertion_ids: readonly string[];
  readonly unmet_conditions: readonly unknown[];
  readonly evidence_bundle_id: string;
  readonly cascade_on_block: boolean;
  readonly decided_by: "gate_engine";
  readonly decided_at: string;
  readonly manifest_commit_hash: string;
  readonly actor_identity_hash: string;
  readonly signature: string;
  readonly signature_key_id: string;
  readonly decision_epoch: number;
}

const GATE_DECISION_FIELDS = [
  "schema_version",
  "gate_decision_id",
  "gate_id",
  "scope_type",
  "scope_id",
  "round",
  "action",
  "strict_pass",
  "failed_assertion_ids",
  "unmet_conditions",
  "evidence_bundle_id",
  "cascade_on_block",
  "decided_by",
  "decided_at",
  "manifest_commit_hash",
  "actor_identity_hash",
  "signature",
  "signature_key_id",
  "decision_epoch",
] as const;

const GATE_DECISION_SCOPE_TYPE = [
  "run",
  "replay",
  "eval_run",
  "release",
  "domain_pack",
] as const;

const GATE_DECISION_ACTION = ["accept", "remediate", "block", "invalid"] as const;

export function parseGateDecision(input: unknown): GateDecision {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("GateDecision", p, GATE_DECISION_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.gate_decision.v1");
  checkUuid("gate_decision_id", p.gate_decision_id);
  checkUuid("gate_id", p.gate_id);
  checkEnum("scope_type", p.scope_type, GATE_DECISION_SCOPE_TYPE);
  checkUuid("scope_id", p.scope_id);
  checkIntegerGe("round", p.round, 1);
  checkEnum("action", p.action, GATE_DECISION_ACTION);

  let strictPass = p.strict_pass;
  if (strictPass === undefined) {
    strictPass = false;
  } else {
    checkBool("strict_pass", strictPass);
  }

  let failedAssertionIds = p.failed_assertion_ids;
  if (failedAssertionIds === undefined) {
    failedAssertionIds = [];
  } else {
    checkListOfStrings("failed_assertion_ids", failedAssertionIds);
  }

  let unmetConditions = p.unmet_conditions;
  if (unmetConditions === undefined) {
    unmetConditions = [];
  } else {
    checkListOfAny("unmet_conditions", unmetConditions);
  }

  checkUuid("evidence_bundle_id", p.evidence_bundle_id);

  let cascadeOnBlock = p.cascade_on_block;
  if (cascadeOnBlock === undefined) {
    cascadeOnBlock = true;
  } else {
    checkBool("cascade_on_block", cascadeOnBlock);
  }

  checkLiteral("decided_by", p.decided_by, "gate_engine");
  checkRfc3339("decided_at", p.decided_at);
  checkSha256Hash("manifest_commit_hash", p.manifest_commit_hash);
  checkSha256Hash("actor_identity_hash", p.actor_identity_hash);
  checkString("signature", p.signature);
  checkString("signature_key_id", p.signature_key_id);

  // VAL-W1-059: decision_epoch is optional; null/undefined coerce to 0.
  let decisionEpoch = p.decision_epoch;
  if (decisionEpoch === undefined || decisionEpoch === null) {
    decisionEpoch = 0;
  } else {
    checkIntegerGe("decision_epoch", decisionEpoch, 0);
  }

  return {
    schema_version: "relay.gate_decision.v1",
    gate_decision_id: p.gate_decision_id as string,
    gate_id: p.gate_id as string,
    scope_type: p.scope_type as GateDecision["scope_type"],
    scope_id: p.scope_id as string,
    round: p.round as number,
    action: p.action as GateDecision["action"],
    strict_pass: strictPass as boolean,
    failed_assertion_ids: failedAssertionIds as readonly string[],
    unmet_conditions: unmetConditions as readonly unknown[],
    evidence_bundle_id: p.evidence_bundle_id as string,
    cascade_on_block: cascadeOnBlock as boolean,
    decided_by: "gate_engine",
    decided_at: p.decided_at as string,
    manifest_commit_hash: p.manifest_commit_hash as string,
    actor_identity_hash: p.actor_identity_hash as string,
    signature: p.signature as string,
    signature_key_id: p.signature_key_id as string,
    decision_epoch: decisionEpoch as number,
  };
}

export function isGateDecision(input: unknown): input is GateDecision {
  try {
    parseGateDecision(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* GateDecisionDraft (spec A.3)                                                */
/* -------------------------------------------------------------------------- */

/**
 * Submitter-facing draft. NOT authoritative.
 *
 * - VAL-W1-047: schema_version pinned to "relay.gate_decision_draft.v1"
 * - VAL-W1-006: two orthogonal state columns + cross-field rule
 * - VAL-W1-007: dry_run_unsigned forbids resolved_gate_decision_id
 * - VAL-W1-058: actor_identity_hash uses canonical sha256-<hex> pattern
 */
export interface GateDecisionDraft {
  readonly schema_version: "relay.gate_decision_draft.v1";
  readonly draft_id: string;
  readonly gate_id: string;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly round: number;
  readonly release_sha: string | null;
  readonly eval_run_ids: readonly string[];
  readonly evidence_refs: readonly unknown[];
  readonly worker_id: string;
  readonly manifest_commit_hash: string;
  readonly actor_identity_hash: string;
  readonly submitted_at: string;
  readonly resolved_gate_decision_id: string | null;
  readonly draft_kind: "submitted" | "dry_run_unsigned";
  readonly resolution_state:
    | "pending"
    | "resolved"
    | "rejected_handoff"
    | "expired"
    | "cancelled"
    | "duplicate_submission";
  readonly cancelled_at: string | null;
  readonly cancellation_reason: string | null;
}

const GATE_DECISION_DRAFT_FIELDS = [
  "schema_version",
  "draft_id",
  "gate_id",
  "scope_type",
  "scope_id",
  "round",
  "release_sha",
  "eval_run_ids",
  "evidence_refs",
  "worker_id",
  "manifest_commit_hash",
  "actor_identity_hash",
  "submitted_at",
  "resolved_gate_decision_id",
  "draft_kind",
  "resolution_state",
  "cancelled_at",
  "cancellation_reason",
] as const;

const DRAFT_KIND = ["submitted", "dry_run_unsigned"] as const;
const RESOLUTION_STATE = [
  "pending",
  "resolved",
  "rejected_handoff",
  "expired",
  "cancelled",
  "duplicate_submission",
] as const;

export function parseGateDecisionDraft(input: unknown): GateDecisionDraft {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("GateDecisionDraft", p, GATE_DECISION_DRAFT_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.gate_decision_draft.v1");
  checkUuid("draft_id", p.draft_id);
  checkUuid("gate_id", p.gate_id);
  checkString("scope_type", p.scope_type);
  checkUuid("scope_id", p.scope_id);
  checkIntegerGe("round", p.round, 1);
  checkStringNullable("release_sha", p.release_sha);

  let evalRunIds = p.eval_run_ids;
  if (evalRunIds === undefined) {
    evalRunIds = [];
  } else {
    checkListOfUuids("eval_run_ids", evalRunIds);
  }

  let evidenceRefs = p.evidence_refs;
  if (evidenceRefs === undefined) {
    evidenceRefs = [];
  } else {
    checkListOfAny("evidence_refs", evidenceRefs);
  }

  checkUuid("worker_id", p.worker_id);
  checkSha256Hash("manifest_commit_hash", p.manifest_commit_hash);
  checkSha256Hash("actor_identity_hash", p.actor_identity_hash);
  checkRfc3339("submitted_at", p.submitted_at);
  checkUuidNullable("resolved_gate_decision_id", p.resolved_gate_decision_id);

  let draftKind = p.draft_kind;
  if (draftKind === undefined) {
    draftKind = "submitted";
  } else {
    checkEnum("draft_kind", draftKind, DRAFT_KIND);
  }

  let resolutionState = p.resolution_state;
  if (resolutionState === undefined) {
    resolutionState = "pending";
  } else {
    checkEnum("resolution_state", resolutionState, RESOLUTION_STATE);
  }

  checkRfc3339Nullable("cancelled_at", p.cancelled_at);
  checkStringNullable("cancellation_reason", p.cancellation_reason);

  // VAL-W1-006: dry_run_never_resolves cross-field rule.
  if (draftKind === "dry_run_unsigned" && resolutionState === "resolved") {
    throw new ValidationError(
      "draft_kind",
      "dry_run_never_resolves: a draft_kind='dry_run_unsigned' draft cannot have resolution_state='resolved' (fields: draft_kind, resolution_state)",
      { draft_kind: draftKind, resolution_state: resolutionState },
    );
  }

  // VAL-W1-007: dry_run_no_decision cross-field rule.
  if (
    draftKind === "dry_run_unsigned"
    && p.resolved_gate_decision_id !== null
    && p.resolved_gate_decision_id !== undefined
  ) {
    throw new ValidationError(
      "draft_kind",
      "dry_run_no_decision: a draft_kind='dry_run_unsigned' draft cannot link a resolved_gate_decision_id (fields: draft_kind, resolved_gate_decision_id)",
      {
        draft_kind: draftKind,
        resolved_gate_decision_id: p.resolved_gate_decision_id,
      },
    );
  }

  return {
    schema_version: "relay.gate_decision_draft.v1",
    draft_id: p.draft_id as string,
    gate_id: p.gate_id as string,
    scope_type: p.scope_type as string,
    scope_id: p.scope_id as string,
    round: p.round as number,
    release_sha: (p.release_sha ?? null) as string | null,
    eval_run_ids: evalRunIds as readonly string[],
    evidence_refs: evidenceRefs as readonly unknown[],
    worker_id: p.worker_id as string,
    manifest_commit_hash: p.manifest_commit_hash as string,
    actor_identity_hash: p.actor_identity_hash as string,
    submitted_at: p.submitted_at as string,
    resolved_gate_decision_id: (p.resolved_gate_decision_id ?? null) as string | null,
    draft_kind: draftKind as GateDecisionDraft["draft_kind"],
    resolution_state: resolutionState as GateDecisionDraft["resolution_state"],
    cancelled_at: (p.cancelled_at ?? null) as string | null,
    cancellation_reason: (p.cancellation_reason ?? null) as string | null,
  };
}

export function isGateDecisionDraft(input: unknown): input is GateDecisionDraft {
  try {
    parseGateDecisionDraft(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* GateRound (spec A.4)                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Per-round audit trail.
 *
 * - VAL-W1-048: schema_version pinned to "relay.gate_round.v1"
 * - VAL-W1-008: initiated_by closed enum; restart_predecessor nullable UUID
 */
export interface GateRound {
  readonly schema_version: "relay.gate_round.v1";
  readonly gate_round_id: string;
  readonly gate_id: string;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly round: number;
  readonly initiated_at: string;
  readonly initiated_by: "control_plane" | "cron" | "user" | "remediation";
  readonly initiation_reason: string | null;
  readonly gate_decision_id: string | null;
  readonly restart_predecessor: string | null;
}

const GATE_ROUND_FIELDS = [
  "schema_version",
  "gate_round_id",
  "gate_id",
  "scope_type",
  "scope_id",
  "round",
  "initiated_at",
  "initiated_by",
  "initiation_reason",
  "gate_decision_id",
  "restart_predecessor",
] as const;

const GATE_ROUND_INITIATED_BY = [
  "control_plane",
  "cron",
  "user",
  "remediation",
] as const;

export function parseGateRound(input: unknown): GateRound {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("GateRound", p, GATE_ROUND_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.gate_round.v1");
  checkUuid("gate_round_id", p.gate_round_id);
  checkUuid("gate_id", p.gate_id);
  checkString("scope_type", p.scope_type);
  checkUuid("scope_id", p.scope_id);
  checkIntegerGe("round", p.round, 1);
  checkRfc3339("initiated_at", p.initiated_at);
  checkEnum("initiated_by", p.initiated_by, GATE_ROUND_INITIATED_BY);
  checkStringNullable("initiation_reason", p.initiation_reason);
  checkUuidNullable("gate_decision_id", p.gate_decision_id);
  checkUuidNullable("restart_predecessor", p.restart_predecessor);

  return {
    schema_version: "relay.gate_round.v1",
    gate_round_id: p.gate_round_id as string,
    gate_id: p.gate_id as string,
    scope_type: p.scope_type as string,
    scope_id: p.scope_id as string,
    round: p.round as number,
    initiated_at: p.initiated_at as string,
    initiated_by: p.initiated_by as GateRound["initiated_by"],
    initiation_reason: (p.initiation_reason ?? null) as string | null,
    gate_decision_id: (p.gate_decision_id ?? null) as string | null,
    restart_predecessor: (p.restart_predecessor ?? null) as string | null,
  };
}

export function isGateRound(input: unknown): input is GateRound {
  try {
    parseGateRound(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Actor (spec C.5; VAL-W1-058)                                                */
/* -------------------------------------------------------------------------- */

/**
 * Actor identity registry row. FK target for the three-anchor handoff.
 */
export interface Actor {
  readonly identity_hash: string;
  readonly kind: "human" | "bot" | "worker" | "reviewer";
  readonly created_at: string;
  readonly revoked_at: string | null;
}

const ACTOR_FIELDS = [
  "identity_hash",
  "kind",
  "created_at",
  "revoked_at",
] as const;

const ACTOR_KIND = ["human", "bot", "worker", "reviewer"] as const;

export function parseActor(input: unknown): Actor {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("Actor", p, ACTOR_FIELDS);
  checkSha256Hash("identity_hash", p.identity_hash);
  checkEnum("kind", p.kind, ACTOR_KIND);
  checkRfc3339("created_at", p.created_at);
  checkRfc3339Nullable("revoked_at", p.revoked_at);

  return {
    identity_hash: p.identity_hash as string,
    kind: p.kind as Actor["kind"],
    created_at: p.created_at as string,
    revoked_at: (p.revoked_at ?? null) as string | null,
  };
}

export function isActor(input: unknown): input is Actor {
  try {
    parseActor(input);
    return true;
  } catch {
    return false;
  }
}
