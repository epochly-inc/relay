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
 * Canonical Crockford-base32 ULID grammar (spec B.6 line 3517). 26 chars
 * from the alphabet 0-9 + A-H + J,K,M,N,P-T,V-Z (lowercase, I, L, O, U
 * are excluded). Used by IdempotencyRecord.idempotency_key (VAL-W1-013).
 */
export const ULID_PATTERN = "^[0-9A-HJKMNP-TV-Z]{26}$";
const ULID_RE = new RegExp(ULID_PATTERN);

/**
 * RFC 3339 trailing-offset marker (Z or +/-HH:MM). Used by EventLogEntry
 * occurred_at validation to reject naive timestamps per VAL-W1-017.
 */
const RFC3339_OFFSET_RE = /(Z|[+-]\d{2}:\d{2})$/;

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
/* W1.6 unknown enum value reader policy (VAL-W1-040; RELAY-SCHEMA-001)        */
/* -------------------------------------------------------------------------- */
//
// Locked in packages/schemas/raw/enum-forward-compat.md (Option A: strict
// reject). Mirror of the Python `RelayUnknownEnumValueError` at
// packages/schemas/python/relay_schemas/envelopes.py.
//
// The existing `parse*` functions throw `ValidationError` on unknown enum
// values; `RelayUnknownEnumValueError` carries the additional structured
// metadata (envelope_name, field, observed_value, allowed_values,
// relay_error_code) required by VAL-W1-040 for cross-language behavior
// digest comparison. The helper `toRelayUnknownEnumValueError` re-classifies
// a `ValidationError` raised by an enum mismatch into the typed error.

/**
 * Raised when a reader observes an enum value outside the canonical closed
 * set. Locked policy: packages/schemas/raw/enum-forward-compat.md.
 */
export class RelayUnknownEnumValueError extends Error {
  public readonly envelope_name: string;
  public readonly field: string;
  public readonly observed_value: string;
  public readonly allowed_values: readonly string[];
  public readonly relay_error_code: "RELAY-SCHEMA-001";

  constructor(
    envelopeName: string,
    field: string,
    observedValue: string,
    allowedValues: readonly string[],
  ) {
    const sorted = [...allowedValues].sort();
    super(
      `unknown enum value for ${envelopeName}.${field}: ` +
        `observed=${JSON.stringify(observedValue)} ` +
        `allowed=${JSON.stringify(sorted)} ` +
        `(VAL-W1-040, RELAY-SCHEMA-001)`,
    );
    this.name = "RelayUnknownEnumValueError";
    this.envelope_name = envelopeName;
    this.field = field;
    this.observed_value = observedValue;
    this.allowed_values = sorted;
    this.relay_error_code = "RELAY-SCHEMA-001";
  }
}

/* -------------------------------------------------------------------------- */
/* W1.6 generic JCS-compatible canonical bytes (VAL-W1-038..044)               */
/* -------------------------------------------------------------------------- */
//
// Cross-language golden corpus canonicalizer. Mirrors the Python
// `canonical_bytes` helper at envelopes.py. Strings (including RFC 3339
// timestamps) are emitted verbatim; decimals MUST be passed in as strings.
// The function name is exposed at module scope so the corpus harness can
// invoke it without going through any parse* path.

/**
 * Emit RFC-8785-compatible canonical JSON bytes (UTF-8) for the JSON value
 * subset Relay envelopes use. Recurses into nested objects (sort keys
 * lexicographically) and arrays (preserve order). Strings are emitted
 * verbatim; numbers must be finite integers (decimals are emitted as JSON
 * strings by the caller per VAL-W1-041).
 */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonStringify(value));
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

/* -------------------------------------------------------------------------- */
/* W1.2 additional field validators                                            */
/* -------------------------------------------------------------------------- */

function checkUlid(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || !ULID_RE.test(value)) {
    throw new ValidationError(
      field,
      "must match canonical Crockford-base32 ULID grammar (26 uppercase chars)",
      value,
    );
  }
}

function checkSha256HashNullable(
  field: string,
  value: unknown,
): asserts value is string | null {
  if (value === null || value === undefined) return;
  if (typeof value !== "string" || !SHA256_HASH_RE.test(value)) {
    throw new ValidationError(
      field,
      "must match canonical sha256-<64 lowercase hex> wire form or be null",
      value,
    );
  }
}

function checkRecordOrObject(
  field: string,
  value: unknown,
): asserts value is Record<string, unknown> {
  if (
    typeof value !== "object"
    || value === null
    || Array.isArray(value)
  ) {
    throw new ValidationError(field, "must be a JSON object", value);
  }
}

function checkRfc3339WithOffset(
  field: string,
  value: unknown,
): asserts value is string {
  if (typeof value !== "string") {
    throw new ValidationError(
      field,
      "must be an RFC 3339 date-time string with a timezone offset",
      value,
    );
  }
  // Reject naive RFC 3339 (no 'Z' and no '+/-HH:MM' tail).
  if (RFC3339_OFFSET_RE.exec(value) === null) {
    throw new ValidationError(
      field,
      "RFC 3339 timestamp MUST carry a timezone offset (Z or +/-HH:MM) per VAL-W1-017",
      value,
    );
  }
  // Verify the overall string parses to a finite Date instant.
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new ValidationError(
      field,
      "must be an RFC 3339 date-time string with a timezone offset",
      value,
    );
  }
}

/* -------------------------------------------------------------------------- */
/* ManifestVersion (spec A.9; VAL-W1-009, VAL-W1-010)                          */
/* -------------------------------------------------------------------------- */

/**
 * A committed manifest version.
 *
 * - VAL-W1-009: commit_hash matches canonical sha256-<hex> wire form
 * - VAL-W1-010: schema_version pinned to "relay.manifest.v1"
 */
export interface ManifestVersion {
  readonly schema_version: "relay.manifest.v1";
  readonly manifest_version_id: string;
  readonly manifest_id: string;
  readonly commit_hash: string;
  readonly body: Record<string, unknown>;
  readonly signed_by: string | null;
  readonly signature: string | null;
  readonly signature_key_id: string | null;
  readonly effective_at: string;
  readonly effective_until: string | null;
}

const MANIFEST_VERSION_FIELDS = [
  "schema_version",
  "manifest_version_id",
  "manifest_id",
  "commit_hash",
  "body",
  "signed_by",
  "signature",
  "signature_key_id",
  "effective_at",
  "effective_until",
] as const;

export function parseManifestVersion(input: unknown): ManifestVersion {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("ManifestVersion", p, MANIFEST_VERSION_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.manifest.v1");
  checkUuid("manifest_version_id", p.manifest_version_id);
  checkUuid("manifest_id", p.manifest_id);
  checkSha256Hash("commit_hash", p.commit_hash);
  checkRecordOrObject("body", p.body);
  checkStringNullable("signed_by", p.signed_by);
  checkStringNullable("signature", p.signature);
  checkStringNullable("signature_key_id", p.signature_key_id);
  checkRfc3339("effective_at", p.effective_at);
  checkRfc3339Nullable("effective_until", p.effective_until);

  return {
    schema_version: "relay.manifest.v1",
    manifest_version_id: p.manifest_version_id as string,
    manifest_id: p.manifest_id as string,
    commit_hash: p.commit_hash as string,
    body: p.body as Record<string, unknown>,
    signed_by: (p.signed_by ?? null) as string | null,
    signature: (p.signature ?? null) as string | null,
    signature_key_id: (p.signature_key_id ?? null) as string | null,
    effective_at: p.effective_at as string,
    effective_until: (p.effective_until ?? null) as string | null,
  };
}

export function isManifestVersion(input: unknown): input is ManifestVersion {
  try {
    parseManifestVersion(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* ScopeState (spec W; VAL-W1-011, VAL-W1-012, VAL-W1-049)                     */
/* -------------------------------------------------------------------------- */
//
// Implemented as a tagged-union type on `scope_kind` so each scope kind's
// allowed state set (spec C.1 lines 3632-3636) is statically enforced. A
// document with scope_kind=run carrying state=building (an evidence_bundle
// state) MUST fail validation per VAL-W1-011.

interface ScopeStateCommon {
  readonly schema_version: "relay.scope_state.v1";
  readonly scope_id: string;
  readonly project_id: string;
  readonly epoch: number;
  readonly created_at: string;
  readonly updated_at: string;
}

/** scope_kind='run' (spec C.1). */
export interface ScopeStateRun extends ScopeStateCommon {
  readonly scope_kind: "run";
  readonly state:
    | "pending"
    | "captured"
    | "validating"
    | "gated"
    | "result_written"
    | "terminal";
}

/** scope_kind='replay_case' (spec C.1). */
export interface ScopeStateReplayCase extends ScopeStateCommon {
  readonly scope_kind: "replay_case";
  readonly state:
    | "proposed"
    | "fixtures_ready"
    | "executing"
    | "analyzed"
    | "terminal";
}

/** scope_kind='gate_round' (spec C.1). */
export interface ScopeStateGateRound extends ScopeStateCommon {
  readonly scope_kind: "gate_round";
  readonly state:
    | "open"
    | "draft_received"
    | "evaluating"
    | "decision_written"
    | "restarted"
    | "terminal";
}

/** scope_kind='evidence_bundle' (spec C.1). */
export interface ScopeStateEvidenceBundle extends ScopeStateCommon {
  readonly scope_kind: "evidence_bundle";
  readonly state:
    | "building"
    | "signed"
    | "published"
    | "superseded"
    | "revoked";
}

/**
 * scope_kind='eval_run' (spec AM eval lifecycle: pending -> running ->
 * scored | terminal). Per spec W lines 5072-5085 the union spans all six
 * scope_kinds; VAL-V2M01-036 landed this variant in milestone M01 (mirror of
 * the Python EvalRunScopeState at envelopes.py).
 */
export interface ScopeStateEvalRun extends ScopeStateCommon {
  readonly scope_kind: "eval_run";
  readonly state: "pending" | "running" | "scored" | "terminal";
}

/**
 * scope_kind='release' (spec Q.2 release lifecycle: open -> gated ->
 * released | rolled_back | terminal). Per spec W lines 5072-5085 the union
 * spans all six scope_kinds; VAL-V2M01-036 landed this variant in milestone
 * M01 (mirror of the Python ReleaseScopeState at envelopes.py).
 */
export interface ScopeStateRelease extends ScopeStateCommon {
  readonly scope_kind: "release";
  readonly state:
    | "open"
    | "gated"
    | "released"
    | "rolled_back"
    | "terminal";
}

/** Tagged union over all six scope_kind variants (VAL-W1-011, VAL-V2M01-036). */
export type ScopeState =
  | ScopeStateRun
  | ScopeStateReplayCase
  | ScopeStateGateRound
  | ScopeStateEvidenceBundle
  | ScopeStateEvalRun
  | ScopeStateRelease;

const SCOPE_STATE_COMMON_FIELDS = [
  "schema_version",
  "scope_kind",
  "scope_id",
  "project_id",
  "state",
  "epoch",
  "created_at",
  "updated_at",
] as const;

const SCOPE_STATE_RUN_STATES = [
  "pending",
  "captured",
  "validating",
  "gated",
  "result_written",
  "terminal",
] as const;

const SCOPE_STATE_REPLAY_CASE_STATES = [
  "proposed",
  "fixtures_ready",
  "executing",
  "analyzed",
  "terminal",
] as const;

const SCOPE_STATE_GATE_ROUND_STATES = [
  "open",
  "draft_received",
  "evaluating",
  "decision_written",
  "restarted",
  "terminal",
] as const;

const SCOPE_STATE_EVIDENCE_BUNDLE_STATES = [
  "building",
  "signed",
  "published",
  "superseded",
  "revoked",
] as const;

const SCOPE_STATE_EVAL_RUN_STATES = [
  "pending",
  "running",
  "scored",
  "terminal",
] as const;

const SCOPE_STATE_RELEASE_STATES = [
  "open",
  "gated",
  "released",
  "rolled_back",
  "terminal",
] as const;

const SCOPE_KIND_VALUES = [
  "run",
  "replay_case",
  "gate_round",
  "evidence_bundle",
  "eval_run",
  "release",
] as const;

export function parseScopeState(input: unknown): ScopeState {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("ScopeState", p, SCOPE_STATE_COMMON_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.scope_state.v1");
  checkEnum("scope_kind", p.scope_kind, SCOPE_KIND_VALUES);
  checkUuid("scope_id", p.scope_id);
  checkUuid("project_id", p.project_id);
  checkIntegerGe("epoch", p.epoch, 0);
  checkRfc3339("created_at", p.created_at);
  checkRfc3339("updated_at", p.updated_at);

  const scopeKind = p.scope_kind as (typeof SCOPE_KIND_VALUES)[number];
  switch (scopeKind) {
    case "run":
      checkEnum("state", p.state, SCOPE_STATE_RUN_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "run",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateRun["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
    case "replay_case":
      checkEnum("state", p.state, SCOPE_STATE_REPLAY_CASE_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "replay_case",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateReplayCase["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
    case "gate_round":
      checkEnum("state", p.state, SCOPE_STATE_GATE_ROUND_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "gate_round",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateGateRound["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
    case "evidence_bundle":
      checkEnum("state", p.state, SCOPE_STATE_EVIDENCE_BUNDLE_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "evidence_bundle",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateEvidenceBundle["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
    case "eval_run":
      checkEnum("state", p.state, SCOPE_STATE_EVAL_RUN_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "eval_run",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateEvalRun["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
    case "release":
      checkEnum("state", p.state, SCOPE_STATE_RELEASE_STATES);
      return {
        schema_version: "relay.scope_state.v1",
        scope_kind: "release",
        scope_id: p.scope_id as string,
        project_id: p.project_id as string,
        state: p.state as ScopeStateRelease["state"],
        epoch: p.epoch as number,
        created_at: p.created_at as string,
        updated_at: p.updated_at as string,
      };
  }
}

export function isScopeState(input: unknown): input is ScopeState {
  try {
    parseScopeState(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* IdempotencyRecord (spec A.12; VAL-W1-013, VAL-W1-014, VAL-W1-050)           */
/* -------------------------------------------------------------------------- */

/**
 * Request dedupe record.
 *
 * - VAL-W1-013: idempotency_key matches Crockford-base32 ULID grammar
 * - VAL-W1-014: request_digest inherits canonical sha256-<hex> form
 * - VAL-W1-050: schema_version pinned to "relay.idempotency_record.v1"
 */
export interface IdempotencyRecord {
  readonly schema_version: "relay.idempotency_record.v1";
  readonly idempotency_key: string;
  readonly project_id: string;
  readonly request_digest: string;
  readonly response_status: number;
  readonly response_ref: string | null;
  readonly first_seen_at: string;
  readonly expires_at: string;
}

const IDEMPOTENCY_RECORD_FIELDS = [
  "schema_version",
  "idempotency_key",
  "project_id",
  "request_digest",
  "response_status",
  "response_ref",
  "first_seen_at",
  "expires_at",
] as const;

export function parseIdempotencyRecord(input: unknown): IdempotencyRecord {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("IdempotencyRecord", p, IDEMPOTENCY_RECORD_FIELDS);
  checkLiteral(
    "schema_version",
    p.schema_version,
    "relay.idempotency_record.v1",
  );
  checkUlid("idempotency_key", p.idempotency_key);
  checkUuid("project_id", p.project_id);
  checkSha256Hash("request_digest", p.request_digest);
  checkIntegerGe("response_status", p.response_status, 0);
  checkStringNullable("response_ref", p.response_ref);
  checkRfc3339("first_seen_at", p.first_seen_at);
  checkRfc3339("expires_at", p.expires_at);

  return {
    schema_version: "relay.idempotency_record.v1",
    idempotency_key: p.idempotency_key as string,
    project_id: p.project_id as string,
    request_digest: p.request_digest as string,
    response_status: p.response_status as number,
    response_ref: (p.response_ref ?? null) as string | null,
    first_seen_at: p.first_seen_at as string,
    expires_at: p.expires_at as string,
  };
}

export function isIdempotencyRecord(
  input: unknown,
): input is IdempotencyRecord {
  try {
    parseIdempotencyRecord(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* EventLogEntry (spec A.11; VAL-W1-015..017, VAL-W1-051)                      */
/* -------------------------------------------------------------------------- */

/**
 * Append-only audit-trail row.
 *
 * - VAL-W1-015: scope_type closed enum
 * - VAL-W1-016: actor_kind closed enum
 * - VAL-W1-017: occurred_at RFC 3339 with required timezone offset
 * - VAL-W1-051: schema_version pinned to "relay.event_log_entry.v1"
 */
export interface EventLogEntry {
  readonly schema_version: "relay.event_log_entry.v1";
  readonly event_id: string;
  readonly project_id: string;
  readonly scope_type:
    | "run"
    | "replay"
    | "gate"
    | "eval_run"
    | "release"
    | "manifest"
    | "key"
    | "other";
  readonly scope_id: string;
  readonly event_type: string;
  readonly actor_kind:
    | "control_plane"
    | "gate_engine"
    | "worker"
    | "sdk"
    | "user"
    | "cron";
  readonly actor_id: string | null;
  readonly manifest_commit_hash: string | null;
  readonly payload: Record<string, unknown>;
  readonly occurred_at: string;
  readonly ingest_sequence: number;
}

const EVENT_LOG_ENTRY_FIELDS = [
  "schema_version",
  "event_id",
  "project_id",
  "scope_type",
  "scope_id",
  "event_type",
  "actor_kind",
  "actor_id",
  "manifest_commit_hash",
  "payload",
  "occurred_at",
  "ingest_sequence",
] as const;

const EVENT_LOG_SCOPE_TYPE = [
  "run",
  "replay",
  "gate",
  "eval_run",
  "release",
  "manifest",
  "key",
  "other",
] as const;

const EVENT_LOG_ACTOR_KIND = [
  "control_plane",
  "gate_engine",
  "worker",
  "sdk",
  "user",
  "cron",
] as const;

export function parseEventLogEntry(input: unknown): EventLogEntry {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("EventLogEntry", p, EVENT_LOG_ENTRY_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.event_log_entry.v1");
  checkUuid("event_id", p.event_id);
  checkUuid("project_id", p.project_id);
  checkEnum("scope_type", p.scope_type, EVENT_LOG_SCOPE_TYPE);
  checkUuid("scope_id", p.scope_id);
  checkString("event_type", p.event_type);
  checkEnum("actor_kind", p.actor_kind, EVENT_LOG_ACTOR_KIND);
  checkUuidNullable("actor_id", p.actor_id);
  checkSha256HashNullable("manifest_commit_hash", p.manifest_commit_hash);

  // payload defaults to {} when omitted; otherwise must be a JSON object.
  let payload = p.payload;
  if (payload === undefined) {
    payload = {};
  } else {
    checkRecordOrObject("payload", payload);
  }

  // VAL-W1-017: offset required.
  checkRfc3339WithOffset("occurred_at", p.occurred_at);
  checkIntegerGe("ingest_sequence", p.ingest_sequence, 0);

  return {
    schema_version: "relay.event_log_entry.v1",
    event_id: p.event_id as string,
    project_id: p.project_id as string,
    scope_type: p.scope_type as EventLogEntry["scope_type"],
    scope_id: p.scope_id as string,
    event_type: p.event_type as string,
    actor_kind: p.actor_kind as EventLogEntry["actor_kind"],
    actor_id: (p.actor_id ?? null) as string | null,
    manifest_commit_hash: (p.manifest_commit_hash ?? null) as string | null,
    payload: payload as Record<string, unknown>,
    occurred_at: p.occurred_at as string,
    ingest_sequence: p.ingest_sequence as number,
  };
}

export function isEventLogEntry(input: unknown): input is EventLogEntry {
  try {
    parseEventLogEntry(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Canonical serializer for cross-language round-trip (VAL-W1-017 evidence)    */
/* -------------------------------------------------------------------------- */

/**
 * Canonical JSON byte serialization of an EventLogEntry. Output is byte-equal
 * to the Python `serialize_event_log_entry_canonical` for the same input.
 * Rules:
 *
 * 1. Keys sorted lexicographically across the top-level object AND any nested
 *    object inside `payload`. (Arrays preserve order.)
 * 2. Compact separators (no whitespace).
 * 3. `occurred_at` rendered as the original wire-format string, preserving
 *    the timezone offset byte-for-byte.
 * 4. UTF-8 encoded bytes.
 */
export function serializeEventLogEntryCanonical(
  entry: EventLogEntry,
): Uint8Array {
  const canonical: Record<string, unknown> = {
    schema_version: entry.schema_version,
    event_id: entry.event_id,
    project_id: entry.project_id,
    scope_type: entry.scope_type,
    scope_id: entry.scope_id,
    event_type: entry.event_type,
    actor_kind: entry.actor_kind,
    actor_id: entry.actor_id,
    manifest_commit_hash: entry.manifest_commit_hash,
    payload: entry.payload,
    occurred_at: entry.occurred_at,
    ingest_sequence: entry.ingest_sequence,
  };
  const text = canonicalJsonStringify(canonical);
  return new TextEncoder().encode(text);
}

/* -------------------------------------------------------------------------- */
/* W1.3 evidence + replay envelopes                                            */
/* -------------------------------------------------------------------------- */
//
// Spec anchors:
//   J line 2798-2810   evidence_bundles DDL (verification_status column)
//   A.16 lines 3331-3353 evidence_claims DDL
//   A.8 lines 3131-3145 replay_cases DDL
//   A.8 lines 3147-3168 replay_fixtures DDL (kind / mode / side_effect_class
//                       closed enums; allowed_in_replay strict bool default
//                       false; refresh_policy default
//                       invalidate_on_signature_change)
//   E.2 lines 3913-3914 capture_clock + refresh_policy semantics
//   E.3 lines 3928-3935 side_effect_class enumeration
//   K   lines 4394+     evidence bundle signature semantics
//
// VAL-W1-019 enum-lock-in: spec J does not enumerate verification_status
// values; the eng-plan-locked candidate set
// {unverified, verified, tampered, revoked} is locked in the canonical YAML.

function checkNonEmptyString(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ValidationError(field, "must be a non-empty string", value);
  }
}

function checkStrictBool(field: string, value: unknown): asserts value is boolean {
  // VAL-W1-023: strict boolean required for allowed_in_replay. JS does not
  // distinguish int 0/1 from bool, but we still reject string forms
  // ("true"/"false") and numeric forms.
  if (typeof value !== "boolean") {
    throw new ValidationError(
      field,
      "strict boolean required; string and numeric forms rejected per VAL-W1-023",
      value,
    );
  }
}

function checkListOfNonEmptyStrings(
  field: string,
  value: unknown,
): asserts value is string[] {
  if (!Array.isArray(value)) {
    throw new ValidationError(field, "must be a list of non-empty strings", value);
  }
  for (let i = 0; i < value.length; i++) {
    const v = value[i];
    if (typeof v !== "string" || v.length === 0) {
      throw new ValidationError(
        `${field}[${i}]`,
        "must be a non-empty string",
        v,
      );
    }
  }
}

/* -------------------------------------------------------------------------- */
/* EvidenceBundle (spec J; VAL-W1-018, VAL-W1-019, VAL-W1-052)                 */
/* -------------------------------------------------------------------------- */

/**
 * Signed evidence bundle row.
 *
 * - VAL-W1-018: bundle_digest non-nullable, canonical sha256-<hex> form
 * - VAL-W1-019: verification_status closed enum
 *   {unverified, verified, tampered, revoked}
 * - VAL-W1-052: schema_version pinned to "relay.evidence_bundle.v1"
 */
export interface EvidenceBundle {
  readonly schema_version: "relay.evidence_bundle.v1";
  readonly evidence_bundle_id: string;
  readonly org_id: string;
  readonly project_id: string;
  readonly scope_type: string;
  readonly scope_id: string;
  readonly bundle_digest: string;
  readonly acef_core_version: string;
  readonly relay_extension_version: string;
  readonly signing_key_id: string | null;
  readonly signature_algorithm: string | null;
  readonly verification_status:
    | "unverified"
    | "verified"
    | "tampered"
    | "revoked";
  readonly redaction_policy_version: string;
  readonly manifest_commit_hash: string | null;
  readonly object_ref: string;
  readonly supersedes_bundle_id: string | null;
  readonly created_at: string;
}

const EVIDENCE_BUNDLE_FIELDS = [
  "schema_version",
  "evidence_bundle_id",
  "org_id",
  "project_id",
  "scope_type",
  "scope_id",
  "bundle_digest",
  "acef_core_version",
  "relay_extension_version",
  "signing_key_id",
  "signature_algorithm",
  "verification_status",
  "redaction_policy_version",
  "manifest_commit_hash",
  "object_ref",
  "supersedes_bundle_id",
  "created_at",
] as const;

const EVIDENCE_BUNDLE_VERIFICATION_STATUS = [
  "unverified",
  "verified",
  "tampered",
  "revoked",
] as const;

export function parseEvidenceBundle(input: unknown): EvidenceBundle {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("EvidenceBundle", p, EVIDENCE_BUNDLE_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.evidence_bundle.v1");
  checkUuid("evidence_bundle_id", p.evidence_bundle_id);
  checkUuid("org_id", p.org_id);
  checkUuid("project_id", p.project_id);
  checkString("scope_type", p.scope_type);
  checkUuid("scope_id", p.scope_id);
  // VAL-W1-018: bundle_digest non-nullable canonical sha256-<hex>.
  checkSha256Hash("bundle_digest", p.bundle_digest);
  checkString("acef_core_version", p.acef_core_version);
  checkString("relay_extension_version", p.relay_extension_version);
  checkStringNullable("signing_key_id", p.signing_key_id);
  checkStringNullable("signature_algorithm", p.signature_algorithm);
  // VAL-W1-019: closed four-member enum.
  checkEnum(
    "verification_status",
    p.verification_status,
    EVIDENCE_BUNDLE_VERIFICATION_STATUS,
  );
  checkString("redaction_policy_version", p.redaction_policy_version);
  checkSha256HashNullable("manifest_commit_hash", p.manifest_commit_hash);
  checkString("object_ref", p.object_ref);
  checkUuidNullable("supersedes_bundle_id", p.supersedes_bundle_id);
  checkRfc3339("created_at", p.created_at);

  return {
    schema_version: "relay.evidence_bundle.v1",
    evidence_bundle_id: p.evidence_bundle_id as string,
    org_id: p.org_id as string,
    project_id: p.project_id as string,
    scope_type: p.scope_type as string,
    scope_id: p.scope_id as string,
    bundle_digest: p.bundle_digest as string,
    acef_core_version: p.acef_core_version as string,
    relay_extension_version: p.relay_extension_version as string,
    signing_key_id: (p.signing_key_id ?? null) as string | null,
    signature_algorithm: (p.signature_algorithm ?? null) as string | null,
    verification_status: p.verification_status as EvidenceBundle["verification_status"],
    redaction_policy_version: p.redaction_policy_version as string,
    manifest_commit_hash: (p.manifest_commit_hash ?? null) as string | null,
    object_ref: p.object_ref as string,
    supersedes_bundle_id: (p.supersedes_bundle_id ?? null) as string | null,
    created_at: p.created_at as string,
  };
}

export function isEvidenceBundle(input: unknown): input is EvidenceBundle {
  try {
    parseEvidenceBundle(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* EvidenceClaim (spec A.16; VAL-W1-020, VAL-W1-021, VAL-W1-053)               */
/* -------------------------------------------------------------------------- */

/**
 * Atomic claim inside an evidence bundle (spec K lines 4388-4438).
 *
 * - VAL-W1-020: claim_type closed enum of eight kinds
 * - VAL-W1-021: claim_digest sha256-<hex> + signature non-empty + nullable UUID
 * - VAL-W1-053: schema_version pinned to "relay.evidence_claim.v1"
 *
 * V3M1-F05 additions (mirror of the Python EvidenceClaim at
 * packages/schemas/python/relay_schemas/envelopes.py):
 *   VAL-V3M1-011: evidence_refs (list of EvidenceRef; defaults to [])
 *   VAL-V3M1-012: claim_predicate (ClaimPredicate | null; recursion bounded
 *                 at depth 8)
 *   VAL-V3M1-013: actor_kind closed enum + actor_identity_hash sha256 required
 *   VAL-V3M1-014: occurred_at datetime distinct from created_at
 *   VAL-V3M1-015: subject is the nested {kind,id,manifest_commit_hash} object;
 *                 a flat subject_kind/subject_id legacy claim is absorbed into
 *                 the nested subject before the extra-field check (Python
 *                 _absorb_flat_subject parity)
 *   VAL-V3M1-021: namespaces (dict | null) carrying the ACEF x-relay envelope
 */

/**
 * Nested subject object for EvidenceClaim per spec K lines 4397-4401. The
 * kind enum mirrors the Python ClaimSubject.
 */
export interface ClaimSubject {
  readonly kind:
    | "run"
    | "replay"
    | "eval_run"
    | "release"
    | "domain_pack"
    | "ai_system";
  readonly id: string;
  readonly manifest_commit_hash: string;
}

/**
 * Reference to a piece of evidence inside an EvidenceClaim (spec K lines
 * 4402-4406). digest and value are independently optional; the verifier
 * bundle-validator (VAL-V3M1-019) enforces the manifest-binding rule.
 */
export interface EvidenceRef {
  readonly kind: string;
  readonly ref: string;
  readonly digest: string | null;
  readonly value: unknown;
}

/**
 * Recursive op/args structure per spec K lines 4407-4413. Leaf rows of the
 * form {op, value} ride along via the optional `value` extra. Recursion depth
 * is bounded at EVIDENCE_CLAIM_PREDICATE_MAX_DEPTH (8) per VAL-V3M1-012.
 */
export interface ClaimPredicate {
  readonly op: string;
  readonly args: readonly ClaimPredicate[];
  readonly value?: unknown;
}

export interface EvidenceClaim {
  readonly schema_version: "relay.evidence_claim.v1";
  readonly evidence_claim_id: string;
  readonly evidence_bundle_id: string;
  readonly claim_type:
    | "run_result"
    | "gate_decision"
    | "contract_result"
    | "replay_result"
    | "human_oversight"
    | "incident"
    | "data_quality_check"
    | "provider_compatibility";
  readonly subject: ClaimSubject;
  readonly evidence_refs: readonly EvidenceRef[];
  readonly claim_predicate: ClaimPredicate | null;
  readonly claim_digest: string;
  readonly redaction_transform_version: string;
  readonly actor_kind:
    | "control_plane"
    | "gate_engine"
    | "worker"
    | "sdk"
    | "user"
    | "cron";
  readonly actor_identity_hash: string;
  readonly occurred_at: string;
  readonly manifest_commit_hash: string;
  readonly signer_key_id: string;
  readonly signature: string;
  readonly supersedes_claim_id: string | null;
  readonly namespaces: Record<string, unknown> | null;
  readonly created_at: string;
}

// Canonical (nested-subject) field set. The flat subject_kind / subject_id
// keys are absorbed into `subject` BEFORE this check runs (Python
// _absorb_flat_subject parity), so they are not listed here.
const EVIDENCE_CLAIM_FIELDS = [
  "schema_version",
  "evidence_claim_id",
  "evidence_bundle_id",
  "claim_type",
  "subject",
  "evidence_refs",
  "claim_predicate",
  "claim_digest",
  "redaction_transform_version",
  "actor_kind",
  "actor_identity_hash",
  "occurred_at",
  "manifest_commit_hash",
  "signer_key_id",
  "signature",
  "supersedes_claim_id",
  "namespaces",
  "created_at",
] as const;

const EVIDENCE_CLAIM_TYPES = [
  "run_result",
  "gate_decision",
  "contract_result",
  "replay_result",
  "human_oversight",
  "incident",
  "data_quality_check",
  "provider_compatibility",
] as const;

const CLAIM_SUBJECT_KINDS = [
  "run",
  "replay",
  "eval_run",
  "release",
  "domain_pack",
  "ai_system",
] as const;

const EVIDENCE_CLAIM_ACTOR_KIND = [
  "control_plane",
  "gate_engine",
  "worker",
  "sdk",
  "user",
  "cron",
] as const;

// Spec K line 4407 recursion depth bound, mirrored from the Python
// _CLAIM_PREDICATE_MAX_DEPTH. A leaf predicate (no args) is depth 1.
const EVIDENCE_CLAIM_PREDICATE_MAX_DEPTH = 8;

/**
 * Mirror of the Python EvidenceClaim._absorb_flat_subject (mode='before')
 * validator. If a nested `subject` object is already present it is kept
 * as-is; otherwise a flat subject_kind/subject_id pair (legacy construction
 * form) is folded into a nested subject whose manifest_commit_hash is mirrored
 * from the top-level field. Returns a shallow copy; the input is not mutated.
 */
function absorbFlatSubject(
  p: Record<string, unknown>,
): Record<string, unknown> {
  if ("subject" in p) {
    return p;
  }
  const hasFlatKind = "subject_kind" in p;
  const hasFlatId = "subject_id" in p;
  if (!hasFlatKind && !hasFlatId) {
    return p;
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(p)) {
    if (key === "subject_kind" || key === "subject_id") continue;
    out[key] = p[key];
  }
  out.subject = {
    kind: p.subject_kind,
    id: p.subject_id,
    manifest_commit_hash: p.manifest_commit_hash,
  };
  return out;
}

/**
 * Validate and normalize a nested ClaimSubject (VAL-V3M1-015). subject.kind
 * is the closed CLAIM_SUBJECT_KINDS enum; subject.id is a UUID;
 * subject.manifest_commit_hash inherits the canonical sha256 form.
 */
function parseClaimSubject(field: string, value: unknown): ClaimSubject {
  checkRecordOrObject(field, value);
  const s = value as Record<string, unknown>;
  checkExtraFields(`${field}`, s, [
    "kind",
    "id",
    "manifest_commit_hash",
  ]);
  checkEnum(`${field}.kind`, s.kind, CLAIM_SUBJECT_KINDS);
  checkUuid(`${field}.id`, s.id);
  checkSha256Hash(`${field}.manifest_commit_hash`, s.manifest_commit_hash);
  return {
    kind: s.kind as ClaimSubject["kind"],
    id: s.id as string,
    manifest_commit_hash: s.manifest_commit_hash as string,
  };
}

/** Validate and normalize a single EvidenceRef (VAL-V3M1-011). */
function parseEvidenceRef(field: string, value: unknown): EvidenceRef {
  checkRecordOrObject(field, value);
  const r = value as Record<string, unknown>;
  checkString(`${field}.kind`, r.kind);
  checkString(`${field}.ref`, r.ref);
  checkSha256HashNullable(`${field}.digest`, r.digest);
  return {
    kind: r.kind as string,
    ref: r.ref as string,
    digest: (r.digest ?? null) as string | null,
    value: r.value ?? null,
  };
}

/**
 * Validate and normalize a recursive ClaimPredicate (VAL-V3M1-012). The Python
 * model is lenient on extras (leaf {op,value} rows), so we preserve any extra
 * keys. `depth` tracks the current op-layer; a leaf is depth 1.
 */
function parseClaimPredicate(
  field: string,
  value: unknown,
  depth: number,
): ClaimPredicate {
  if (depth > EVIDENCE_CLAIM_PREDICATE_MAX_DEPTH) {
    throw new ValidationError(
      field,
      `claim_predicate recursion depth ${depth} exceeds spec K bound of ` +
        `${EVIDENCE_CLAIM_PREDICATE_MAX_DEPTH} (VAL-V3M1-012)`,
      value,
    );
  }
  checkRecordOrObject(field, value);
  const node = value as Record<string, unknown>;
  checkString(`${field}.op`, node.op);
  const rawArgs = node.args;
  let args: ClaimPredicate[] = [];
  if (rawArgs !== undefined) {
    checkListOfAny(`${field}.args`, rawArgs);
    args = (rawArgs as unknown[]).map((arg, i) =>
      parseClaimPredicate(`${field}.args[${i}]`, arg, depth + 1),
    );
  }
  const out: ClaimPredicate = { op: node.op as string, args };
  if ("value" in node) {
    return { ...out, value: node.value };
  }
  return out;
}

export function parseEvidenceClaim(input: unknown): EvidenceClaim {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  // VAL-V3M1-015: absorb a flat subject_kind/subject_id legacy claim into the
  // nested subject BEFORE the extra-field check (Python _absorb_flat_subject
  // parity).
  const p = absorbFlatSubject(input as Record<string, unknown>);

  checkExtraFields("EvidenceClaim", p, EVIDENCE_CLAIM_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.evidence_claim.v1");
  checkUuid("evidence_claim_id", p.evidence_claim_id);
  checkUuid("evidence_bundle_id", p.evidence_bundle_id);
  checkEnum("claim_type", p.claim_type, EVIDENCE_CLAIM_TYPES);

  // VAL-V3M1-015: nested subject object (required).
  const subject = parseClaimSubject("subject", p.subject);

  // VAL-V3M1-011: evidence_refs defaults to [] when omitted.
  let evidenceRefs: EvidenceRef[] = [];
  if (p.evidence_refs !== undefined) {
    checkListOfAny("evidence_refs", p.evidence_refs);
    evidenceRefs = (p.evidence_refs as unknown[]).map((r, i) =>
      parseEvidenceRef(`evidence_refs[${i}]`, r),
    );
  }

  // VAL-V3M1-012: claim_predicate is nullable; recursion bounded at depth 8.
  let claimPredicate: ClaimPredicate | null = null;
  if (p.claim_predicate !== undefined && p.claim_predicate !== null) {
    claimPredicate = parseClaimPredicate("claim_predicate", p.claim_predicate, 1);
  }

  // VAL-W1-021: claim_digest canonical sha256-<hex>.
  checkSha256Hash("claim_digest", p.claim_digest);
  checkString("redaction_transform_version", p.redaction_transform_version);

  // VAL-V3M1-013: actor_kind closed enum + actor_identity_hash sha256.
  checkEnum("actor_kind", p.actor_kind, EVIDENCE_CLAIM_ACTOR_KIND);
  checkSha256Hash("actor_identity_hash", p.actor_identity_hash);

  // VAL-V3M1-014: occurred_at RFC 3339 datetime distinct from created_at.
  checkRfc3339("occurred_at", p.occurred_at);

  checkSha256Hash("manifest_commit_hash", p.manifest_commit_hash);
  checkString("signer_key_id", p.signer_key_id);
  // VAL-W1-021: signature non-empty string.
  checkNonEmptyString("signature", p.signature);
  checkUuidNullable("supersedes_claim_id", p.supersedes_claim_id);

  // VAL-V3M1-021: namespaces dict | null (defaults to null when omitted).
  let namespaces: Record<string, unknown> | null = null;
  if (p.namespaces !== undefined && p.namespaces !== null) {
    checkRecordOrObject("namespaces", p.namespaces);
    namespaces = p.namespaces as Record<string, unknown>;
  }

  checkRfc3339("created_at", p.created_at);

  return {
    schema_version: "relay.evidence_claim.v1",
    evidence_claim_id: p.evidence_claim_id as string,
    evidence_bundle_id: p.evidence_bundle_id as string,
    claim_type: p.claim_type as EvidenceClaim["claim_type"],
    subject,
    evidence_refs: evidenceRefs,
    claim_predicate: claimPredicate,
    claim_digest: p.claim_digest as string,
    redaction_transform_version: p.redaction_transform_version as string,
    actor_kind: p.actor_kind as EvidenceClaim["actor_kind"],
    actor_identity_hash: p.actor_identity_hash as string,
    occurred_at: p.occurred_at as string,
    manifest_commit_hash: p.manifest_commit_hash as string,
    signer_key_id: p.signer_key_id as string,
    signature: p.signature as string,
    supersedes_claim_id: (p.supersedes_claim_id ?? null) as string | null,
    namespaces,
    created_at: p.created_at as string,
  };
}

export function isEvidenceClaim(input: unknown): input is EvidenceClaim {
  try {
    parseEvidenceClaim(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* ReplayCase (spec A.8; VAL-W1-022, VAL-W1-054)                               */
/* -------------------------------------------------------------------------- */

/**
 * Replay case row.
 *
 * - VAL-W1-022: status enum {proposed, approved, retired};
 *   expected_assertion_ids list of non-empty strings default [];
 *   failure_signature_hash required non-empty
 * - VAL-W1-054: schema_version pinned to "relay.replay_case.v1"
 */
export interface ReplayCase {
  readonly schema_version: "relay.replay_case.v1";
  readonly replay_case_id: string;
  readonly project_id: string;
  readonly source_run_id: string | null;
  readonly failure_signature_hash: string;
  readonly inputs_ref: string;
  readonly inputs_digest: string;
  readonly expected_assertion_ids: readonly string[];
  readonly human_reviewed: boolean;
  readonly reviewer_email: string | null;
  readonly reviewed_at: string | null;
  readonly status: "proposed" | "approved" | "retired";
  readonly created_at: string;
}

const REPLAY_CASE_FIELDS = [
  "schema_version",
  "replay_case_id",
  "project_id",
  "source_run_id",
  "failure_signature_hash",
  "inputs_ref",
  "inputs_digest",
  "expected_assertion_ids",
  "human_reviewed",
  "reviewer_email",
  "reviewed_at",
  "status",
  "created_at",
] as const;

const REPLAY_CASE_STATUS = ["proposed", "approved", "retired"] as const;

export function parseReplayCase(input: unknown): ReplayCase {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("ReplayCase", p, REPLAY_CASE_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.replay_case.v1");
  checkUuid("replay_case_id", p.replay_case_id);
  checkUuid("project_id", p.project_id);
  checkUuidNullable("source_run_id", p.source_run_id);
  // VAL-W1-022: failure_signature_hash required, non-empty.
  checkNonEmptyString("failure_signature_hash", p.failure_signature_hash);
  checkString("inputs_ref", p.inputs_ref);
  checkSha256Hash("inputs_digest", p.inputs_digest);

  let expectedAssertionIds = p.expected_assertion_ids;
  if (expectedAssertionIds === undefined) {
    expectedAssertionIds = [];
  } else {
    checkListOfNonEmptyStrings("expected_assertion_ids", expectedAssertionIds);
  }

  let humanReviewed = p.human_reviewed;
  if (humanReviewed === undefined) {
    humanReviewed = false;
  } else {
    checkBool("human_reviewed", humanReviewed);
  }

  checkStringNullable("reviewer_email", p.reviewer_email);
  checkRfc3339Nullable("reviewed_at", p.reviewed_at);

  let status = p.status;
  if (status === undefined) {
    status = "proposed";
  } else {
    checkEnum("status", status, REPLAY_CASE_STATUS);
  }

  checkRfc3339("created_at", p.created_at);

  return {
    schema_version: "relay.replay_case.v1",
    replay_case_id: p.replay_case_id as string,
    project_id: p.project_id as string,
    source_run_id: (p.source_run_id ?? null) as string | null,
    failure_signature_hash: p.failure_signature_hash as string,
    inputs_ref: p.inputs_ref as string,
    inputs_digest: p.inputs_digest as string,
    expected_assertion_ids: expectedAssertionIds as readonly string[],
    human_reviewed: humanReviewed as boolean,
    reviewer_email: (p.reviewer_email ?? null) as string | null,
    reviewed_at: (p.reviewed_at ?? null) as string | null,
    status: status as ReplayCase["status"],
    created_at: p.created_at as string,
  };
}

export function isReplayCase(input: unknown): input is ReplayCase {
  try {
    parseReplayCase(input);
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* ReplayFixture (spec A.8, E.2-E.3; VAL-W1-023, VAL-W1-024, VAL-W1-025, V055) */
/* -------------------------------------------------------------------------- */

/**
 * Replay fixture row.
 *
 * - VAL-W1-023: kind / mode / side_effect_class closed enums;
 *   allowed_in_replay STRICT bool (no string/numeric coercion)
 * - VAL-W1-024: capture_clock RFC 3339 with required timezone offset
 * - VAL-W1-025: refresh_policy closed four-member enum, default
 *   "invalidate_on_signature_change"
 * - VAL-W1-055: schema_version pinned to "relay.replay_fixture.v1"
 */
export interface ReplayFixture {
  readonly schema_version: "relay.replay_fixture.v1";
  readonly fixture_id: string;
  readonly replay_case_id: string;
  readonly source_span_id: string;
  readonly kind:
    | "model_call"
    | "tool_call"
    | "retrieval"
    | "embedding"
    | "custom";
  readonly mode: "cassette" | "live" | "degraded_live" | "mock";
  readonly redaction_policy_version: string;
  readonly input_digest: string;
  readonly output_ref: string | null;
  readonly output_digest: string | null;
  readonly provider: string | null;
  readonly model: string | null;
  readonly model_signature: string | null;
  readonly capture_clock: string;
  readonly refresh_policy:
    | "invalidate_on_signature_change"
    | "hold_forever"
    | "refresh_weekly"
    | "invalidate_on_model_version_change";
  readonly side_effect_class:
    | "read_only"
    | "mutating"
    | "external_irreversible"
    | "approval_required";
  readonly allowed_in_replay: boolean;
  readonly created_at: string;
}

const REPLAY_FIXTURE_FIELDS = [
  "schema_version",
  "fixture_id",
  "replay_case_id",
  "source_span_id",
  "kind",
  "mode",
  "redaction_policy_version",
  "input_digest",
  "output_ref",
  "output_digest",
  "provider",
  "model",
  "model_signature",
  "capture_clock",
  "refresh_policy",
  "side_effect_class",
  "allowed_in_replay",
  "created_at",
] as const;

const REPLAY_FIXTURE_KIND = [
  "model_call",
  "tool_call",
  "retrieval",
  "embedding",
  "custom",
] as const;

const REPLAY_FIXTURE_MODE = [
  "cassette",
  "live",
  "degraded_live",
  "mock",
] as const;

const REPLAY_FIXTURE_REFRESH_POLICY = [
  "invalidate_on_signature_change",
  "hold_forever",
  "refresh_weekly",
  "invalidate_on_model_version_change",
] as const;

const REPLAY_FIXTURE_SIDE_EFFECT_CLASS = [
  "read_only",
  "mutating",
  "external_irreversible",
  "approval_required",
] as const;

export function parseReplayFixture(input: unknown): ReplayFixture {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("ReplayFixture", p, REPLAY_FIXTURE_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.replay_fixture.v1");
  checkUuid("fixture_id", p.fixture_id);
  checkUuid("replay_case_id", p.replay_case_id);
  checkUuid("source_span_id", p.source_span_id);
  checkEnum("kind", p.kind, REPLAY_FIXTURE_KIND);
  checkEnum("mode", p.mode, REPLAY_FIXTURE_MODE);
  checkString("redaction_policy_version", p.redaction_policy_version);
  checkSha256Hash("input_digest", p.input_digest);
  checkStringNullable("output_ref", p.output_ref);
  checkSha256HashNullable("output_digest", p.output_digest);
  checkStringNullable("provider", p.provider);
  checkStringNullable("model", p.model);
  checkStringNullable("model_signature", p.model_signature);
  // VAL-W1-024: capture_clock RFC 3339 with required timezone offset.
  checkRfc3339WithOffset("capture_clock", p.capture_clock);

  // VAL-W1-025: refresh_policy default invalidate_on_signature_change.
  let refreshPolicy = p.refresh_policy;
  if (refreshPolicy === undefined) {
    refreshPolicy = "invalidate_on_signature_change";
  } else {
    checkEnum("refresh_policy", refreshPolicy, REPLAY_FIXTURE_REFRESH_POLICY);
  }

  checkEnum(
    "side_effect_class",
    p.side_effect_class,
    REPLAY_FIXTURE_SIDE_EFFECT_CLASS,
  );

  // VAL-W1-023: allowed_in_replay strict bool default false.
  let allowedInReplay = p.allowed_in_replay;
  if (allowedInReplay === undefined) {
    allowedInReplay = false;
  } else {
    checkStrictBool("allowed_in_replay", allowedInReplay);
  }

  checkRfc3339("created_at", p.created_at);

  return {
    schema_version: "relay.replay_fixture.v1",
    fixture_id: p.fixture_id as string,
    replay_case_id: p.replay_case_id as string,
    source_span_id: p.source_span_id as string,
    kind: p.kind as ReplayFixture["kind"],
    mode: p.mode as ReplayFixture["mode"],
    redaction_policy_version: p.redaction_policy_version as string,
    input_digest: p.input_digest as string,
    output_ref: (p.output_ref ?? null) as string | null,
    output_digest: (p.output_digest ?? null) as string | null,
    provider: (p.provider ?? null) as string | null,
    model: (p.model ?? null) as string | null,
    model_signature: (p.model_signature ?? null) as string | null,
    capture_clock: p.capture_clock as string,
    refresh_policy: refreshPolicy as ReplayFixture["refresh_policy"],
    side_effect_class: p.side_effect_class as ReplayFixture["side_effect_class"],
    allowed_in_replay: allowedInReplay as boolean,
    created_at: p.created_at as string,
  };
}

export function isReplayFixture(input: unknown): input is ReplayFixture {
  try {
    parseReplayFixture(input);
    return true;
  } catch {
    return false;
  }
}

/**
 * Canonical JSON byte serialization of a ReplayFixture. Output is byte-equal
 * to the Python `serialize_replay_fixture_canonical` for the same input.
 * Rules mirror `serializeEventLogEntryCanonical` (VAL-W1-017):
 *
 * 1. Keys sorted lexicographically.
 * 2. Compact separators (no whitespace).
 * 3. capture_clock and created_at preserved verbatim from input (timezone
 *    offset byte-for-byte). Since this entrypoint receives a parsed
 *    `ReplayFixture` whose `capture_clock` and `created_at` are the raw
 *    wire-format strings, no further normalization is required.
 * 4. UTF-8 encoded bytes.
 */
export function serializeReplayFixtureCanonical(
  fixture: ReplayFixture,
): Uint8Array {
  const canonical: Record<string, unknown> = {
    schema_version: fixture.schema_version,
    fixture_id: fixture.fixture_id,
    replay_case_id: fixture.replay_case_id,
    source_span_id: fixture.source_span_id,
    kind: fixture.kind,
    mode: fixture.mode,
    redaction_policy_version: fixture.redaction_policy_version,
    input_digest: fixture.input_digest,
    output_ref: fixture.output_ref,
    output_digest: fixture.output_digest,
    provider: fixture.provider,
    model: fixture.model,
    model_signature: fixture.model_signature,
    capture_clock: fixture.capture_clock,
    refresh_policy: fixture.refresh_policy,
    side_effect_class: fixture.side_effect_class,
    allowed_in_replay: fixture.allowed_in_replay,
    created_at: fixture.created_at,
  };
  const text = canonicalJsonStringify(canonical);
  return new TextEncoder().encode(text);
}

/* -------------------------------------------------------------------------- */
/* W1.4 RedactionPolicy + ErrorEnvelope (spec A.10, G.1, G.2, B.4)              */
/* -------------------------------------------------------------------------- */
/*
 * VAL-W1-026: RedactionPolicy.schema_version pinned to "relay.redaction.v1";
 *             raw_capture STRICT boolean (string "true"/"false" rejected,
 *             numeric forms rejected); default false.
 * VAL-W1-027: cross-field invariant - raw_capture=true REQUIRES non-null
 *             dpa_ref AND approver_user_id (CLAUDE.md banned pattern #11).
 * VAL-W1-028: matchers[] tagged discriminated union on `kind`:
 *               kind="regex"        -> requires `pattern`, forbids `paths`.
 *               kind="json_pointer" -> requires `paths`,   forbids `pattern`.
 * VAL-W1-029: ErrorEnvelope closed schema with code matching
 *             /^RELAY-[A-Z]+-[0-9]{3}$/, http_status in [400, 599],
 *             blocked_surface non-empty, retry_advice closed enum.
 * VAL-W1-030: known RELAY-* codes generated as RelayErrorCode constants
 *             from packages/schemas/raw/relay-error-codes.yaml.
 * VAL-W1-031: request_id, trace_id required non-empty strings.
 * VAL-W1-056: ErrorEnvelope.schema_version literal pin.
 */

export const RELAY_ERROR_CODE_PATTERN = "^RELAY-[A-Z]+-[0-9]{3}$";
const RELAY_ERROR_CODE_RE = new RegExp(RELAY_ERROR_CODE_PATTERN);

function checkRelayErrorCode(field: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || !RELAY_ERROR_CODE_RE.test(value)) {
    throw new ValidationError(
      field,
      "must match canonical RELAY-{AREA}-NNN wire form (^RELAY-[A-Z]+-[0-9]{3}$)",
      value,
    );
  }
}

function checkHttpStatus4xx5xx(field: string, value: unknown): asserts value is number {
  if (
    typeof value !== "number"
    || !Number.isInteger(value)
    || value < 400
    || value > 599
  ) {
    throw new ValidationError(field, "must be an integer in [400, 599]", value);
  }
}

function checkAnyObject(
  field: string,
  value: unknown,
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ValidationError(field, "must be a JSON object", value);
  }
}

/* ---------- RedactionPolicy matchers --------------------------------------- */

export interface RedactionPolicyMatcherRegex {
  readonly kind: "regex";
  readonly pattern: string;
}

export interface RedactionPolicyMatcherJsonPointer {
  readonly kind: "json_pointer";
  readonly paths: readonly string[];
}

export type RedactionPolicyMatcher =
  | RedactionPolicyMatcherRegex
  | RedactionPolicyMatcherJsonPointer;

const REDACTION_MATCHER_REGEX_FIELDS = ["kind", "pattern"] as const;
const REDACTION_MATCHER_JSON_POINTER_FIELDS = ["kind", "paths"] as const;

function parseRedactionMatcher(
  field: string,
  raw: unknown,
): RedactionPolicyMatcher {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ValidationError(field, "matcher must be an object", raw);
  }
  const m = raw as Record<string, unknown>;
  const kind = m.kind;
  if (kind === "regex") {
    // VAL-W1-028: regex variant requires pattern, forbids paths.
    checkExtraFields(
      "RedactionPolicyMatcherRegex",
      m,
      REDACTION_MATCHER_REGEX_FIELDS,
    );
    checkNonEmptyString(`${field}.pattern`, m.pattern);
    return { kind: "regex", pattern: m.pattern as string };
  }
  if (kind === "json_pointer") {
    // VAL-W1-028: json_pointer variant requires paths, forbids pattern.
    checkExtraFields(
      "RedactionPolicyMatcherJsonPointer",
      m,
      REDACTION_MATCHER_JSON_POINTER_FIELDS,
    );
    if (!Array.isArray(m.paths) || m.paths.length === 0) {
      throw new ValidationError(
        `${field}.paths`,
        "must be a non-empty list of non-empty strings",
        m.paths,
      );
    }
    const paths = m.paths as unknown[];
    for (let i = 0; i < paths.length; i++) {
      const v = paths[i];
      if (typeof v !== "string" || v.length === 0) {
        throw new ValidationError(
          `${field}.paths[${i}]`,
          "must be a non-empty string",
          v,
        );
      }
    }
    return {
      kind: "json_pointer",
      paths: paths as string[],
    };
  }
  throw new ValidationError(
    `${field}.kind`,
    'must be one of {"regex", "json_pointer"}',
    kind,
  );
}

/* ---------- RedactionPolicy ------------------------------------------------ */

export interface RedactionPolicy {
  readonly schema_version: "relay.redaction.v1";
  readonly redaction_policy_id: string;
  readonly org_id: string;
  readonly version: string;
  readonly raw_capture: boolean;
  readonly dpa_ref: string | null;
  readonly approver_user_id: string | null;
  readonly matchers: readonly RedactionPolicyMatcher[];
  readonly created_at: string;
}

const REDACTION_POLICY_FIELDS = [
  "schema_version",
  "redaction_policy_id",
  "org_id",
  "version",
  "raw_capture",
  "dpa_ref",
  "approver_user_id",
  "matchers",
  "created_at",
] as const;

export function parseRedactionPolicy(input: unknown): RedactionPolicy {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("RedactionPolicy", p, REDACTION_POLICY_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.redaction.v1");
  checkUuid("redaction_policy_id", p.redaction_policy_id);
  checkUuid("org_id", p.org_id);
  checkString("version", p.version);

  // VAL-W1-026: raw_capture STRICT bool. String "true"/"false" and numeric
  // 0/1 are rejected; default false when omitted.
  let rawCapture = p.raw_capture;
  if (rawCapture === undefined) {
    rawCapture = false;
  } else {
    checkStrictBool("raw_capture", rawCapture);
  }

  checkStringNullable("dpa_ref", p.dpa_ref);
  checkUuidNullable("approver_user_id", p.approver_user_id);

  let matchersInput = p.matchers;
  if (matchersInput === undefined) {
    matchersInput = [];
  }
  if (!Array.isArray(matchersInput)) {
    throw new ValidationError("matchers", "must be a list", matchersInput);
  }
  const matchers: RedactionPolicyMatcher[] = [];
  for (let i = 0; i < matchersInput.length; i++) {
    matchers.push(parseRedactionMatcher(`matchers[${i}]`, matchersInput[i]));
  }

  checkRfc3339("created_at", p.created_at);

  // VAL-W1-027 cross-field: raw_capture=true requires non-null dpa_ref
  // AND approver_user_id. Mirrors hosted invariant spec G.1.
  if (rawCapture === true) {
    if (p.dpa_ref === null || p.dpa_ref === undefined) {
      throw new ValidationError(
        "dpa_ref",
        "raw_capture_requires_dpa_and_approver: raw_capture=true requires dpa_ref to be non-null (VAL-W1-027)",
        p.dpa_ref,
      );
    }
    if (p.approver_user_id === null || p.approver_user_id === undefined) {
      throw new ValidationError(
        "approver_user_id",
        "raw_capture_requires_dpa_and_approver: raw_capture=true requires approver_user_id to be non-null (VAL-W1-027)",
        p.approver_user_id,
      );
    }
  }

  return {
    schema_version: "relay.redaction.v1",
    redaction_policy_id: p.redaction_policy_id as string,
    org_id: p.org_id as string,
    version: p.version as string,
    raw_capture: rawCapture as boolean,
    dpa_ref: (p.dpa_ref ?? null) as string | null,
    approver_user_id: (p.approver_user_id ?? null) as string | null,
    matchers,
    created_at: p.created_at as string,
  };
}

export function isRedactionPolicy(input: unknown): input is RedactionPolicy {
  try {
    parseRedactionPolicy(input);
    return true;
  } catch {
    return false;
  }
}

/* ---------- ErrorEnvelope -------------------------------------------------- */

export interface ErrorEnvelope {
  readonly schema_version: "relay.error.v1";
  readonly code: string;
  readonly http_status: number;
  readonly blocked_surface: string;
  readonly retry_advice:
    | "do_not_retry"
    | "after_fix"
    | "after_retry_after"
    | "after_split"
    | "after_recapture"
    | "after_re_auth";
  readonly request_id: string;
  readonly trace_id: string;
  readonly message: string | null;
  readonly details: Record<string, unknown>;
}

const ERROR_ENVELOPE_FIELDS = [
  "schema_version",
  "code",
  "http_status",
  "blocked_surface",
  "retry_advice",
  "request_id",
  "trace_id",
  "message",
  "details",
] as const;

const ERROR_ENVELOPE_RETRY_ADVICE = [
  "do_not_retry",
  "after_fix",
  "after_retry_after",
  "after_split",
  "after_recapture",
  "after_re_auth",
] as const;

export function parseErrorEnvelope(input: unknown): ErrorEnvelope {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ValidationError("<root>", "must be an object", input);
  }
  const p = input as Record<string, unknown>;

  checkExtraFields("ErrorEnvelope", p, ERROR_ENVELOPE_FIELDS);
  checkLiteral("schema_version", p.schema_version, "relay.error.v1");
  checkRelayErrorCode("code", p.code);
  checkHttpStatus4xx5xx("http_status", p.http_status);
  checkNonEmptyString("blocked_surface", p.blocked_surface);
  checkEnum("retry_advice", p.retry_advice, ERROR_ENVELOPE_RETRY_ADVICE);
  checkNonEmptyString("request_id", p.request_id);
  checkNonEmptyString("trace_id", p.trace_id);
  checkStringNullable("message", p.message);

  let details = p.details;
  if (details === undefined) {
    details = {};
  } else {
    checkAnyObject("details", details);
  }

  return {
    schema_version: "relay.error.v1",
    code: p.code as string,
    http_status: p.http_status as number,
    blocked_surface: p.blocked_surface as string,
    retry_advice: p.retry_advice as ErrorEnvelope["retry_advice"],
    request_id: p.request_id as string,
    trace_id: p.trace_id as string,
    message: (p.message ?? null) as string | null,
    details: details as Record<string, unknown>,
  };
}

export function isErrorEnvelope(input: unknown): input is ErrorEnvelope {
  try {
    parseErrorEnvelope(input);
    return true;
  } catch {
    return false;
  }
}

/**
 * Sort-keys + compact-separator JSON stringifier. Recurses into nested
 * objects (NOT arrays -- arrays preserve order). Matches Python's
 * `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
 */
function canonicalJsonStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    // JSON allows integers and finite floats; Infinity/NaN are not JSON.
    if (!Number.isFinite(value)) {
      throw new Error("canonicalJsonStringify: non-finite number not allowed");
    }
    // An integer outside the JS safe-integer range cannot round-trip exactly:
    // String(value) would emit a ROUNDED token while Python str(int) is exact,
    // an irreconcilable Py<->TS divergence. Reject it fail-closed so both
    // runtimes agree (Python canonical_bytes raises on the same input). Such
    // values MUST be string-encoded by the caller (re-hunt schemas-03).
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error(
        "canonicalJsonStringify: integer outside the JS safe-integer range " +
          "must be string-encoded for Py<->TS byte parity",
      );
    }
    // String(value) implements ECMA-262 Number::toString, matching the Python
    // ECMA-262 number encoder for finite safe values.
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
      parts.push(JSON.stringify(k) + ":" + canonicalJsonStringify(obj[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(
    `canonicalJsonStringify: unsupported type ${typeof value}`,
  );
}
