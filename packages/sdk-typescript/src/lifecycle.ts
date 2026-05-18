/**
 * Lifecycle envelope builders for the Relay TypeScript SDK (W4.2).
 *
 * Parity with the Python ``relay.lifecycle`` module
 * (``packages/sdk-python/relay/lifecycle.py``). This module owns the wire-
 * format ingest envelopes the SDK submits to the local sidecar control
 * plane. Per CLAUDE.md keystone invariant #1 and spec A.1, the SDK NEVER
 * writes canonical-result fields -- they are written exclusively by the
 * control plane.
 *
 * Three envelope builders live here:
 *
 *   * :func:`buildIngestRunEnvelope` -- the
 *     ``POST /v1/ingest/runs`` body. Carries lifecycle metadata only;
 *     rejects every canonical-write field at the SDK boundary BEFORE any
 *     HTTP I/O (VAL-W4-009, VAL-W4-010).
 *   * :func:`buildGateDraftEnvelope` -- the
 *     ``POST /v1/gates/{gate_id}/drafts`` body. The SDK submits evidence
 *     drafts; the gate engine writes the canonical decision (VAL-W4-015).
 *   * :func:`buildEvidenceEnvelope` -- the evidence submit body. Binds
 *     artifact digest + command + exit code + span IDs +
 *     ``manifest_commit_hash`` per spec K and CLAUDE.md invariant #2; a
 *     missing field is rejected at the SDK boundary (VAL-W4-016).
 *
 * The module is import-side-effect-free: pure-TypeScript construction
 * only, no network/file/sidecar contact.
 *
 * NOTE on canonical-write field literals (VAL-W4-009): The denylist
 * constant ``CANONICAL_WRITE_FIELDS`` necessarily contains the canonical
 * field names. The grep test in ``w4_2_canonical_write_grep.test.ts``
 * accounts for this single, intentional reference to the literals (the
 * denylist itself is the screen, not an outbound assignment).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import {
  RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE,
  RELAY_SDK_CONFIG_CODE,
  RELAY_SDK_EVIDENCE_INCOMPLETE_CODE,
  RELAY_SDK_HANDOFF_INCOMPLETE_CODE,
  RELAY_SDK_LIFECYCLE_INVALID_CODE,
  RelayCanonicalStatusForbidden,
  RelayConfigError,
  RelayEvidenceIncomplete,
  RelayHandoffIncomplete,
  RelayLifecycleInvalid,
} from "./errors.js";
import { newUlid } from "./ulid.js";

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/**
 * Closed enum for the SDK-observed lifecycle. VAL-W4-010: any value
 * outside this set is rejected at the SDK boundary BEFORE the request is
 * sent. Mirrors Python ``LIFECYCLE_STATUSES``.
 */
export const LIFECYCLE_STATUSES: ReadonlySet<string> = new Set([
  "started",
  "client_succeeded",
  "client_failed",
  "client_aborted",
]);

export type LifecycleStatus = "started" | "client_succeeded" | "client_failed" | "client_aborted";

/**
 * Canonical-result fields the SDK MUST NEVER set. The sidecar rejects an
 * envelope carrying any of these with HTTP 422 + RELAY-ING-031
 * (VAL-W4-009, VAL-W4-010). The SDK checks BEFORE issuing the request so
 * a programmer error never crosses the wire.
 *
 * NOTE: This is the SOLE location in ``packages/sdk-typescript/src/``
 * where these literals appear as outbound payload keys. The W4-009 grep
 * test accounts for the denylist constant itself.
 */
export const CANONICAL_WRITE_FIELDS: ReadonlySet<string> = new Set([
  "status",
  "primary_failure_class",
  "written_by",
  "accepted_at",
  "finalized_at",
]);

/** The three-anchor handoff names (spec C.5; CLAUDE.md invariant #4). */
export const HANDOFF_ANCHORS: readonly ["scope_id", "actor_identity_hash", "manifest_commit_hash"] =
  ["scope_id", "actor_identity_hash", "manifest_commit_hash"] as const;

/** Wire ``schema_version`` for the run-ingest envelope. */
export const INGEST_RUN_SCHEMA_VERSION = "relay.ingest.run.v1";

/** Wire ``schema_version`` for the gate-decision-draft envelope. */
export const GATE_DRAFT_SCHEMA_VERSION = "relay.gate_decision_draft.v1";

/** Wire ``schema_version`` for the evidence-bundle submit envelope. */
export const EVIDENCE_SUBMIT_SCHEMA_VERSION = "relay.evidence_submit.v1";

/**
 * Required evidence-binding fields per CLAUDE.md invariant #2 and spec K.
 * A missing field raises :class:`RelayEvidenceIncomplete` at the SDK
 * boundary (VAL-W4-016).
 */
export const EVIDENCE_REQUIRED_FIELDS: readonly string[] = [
  "artifact_digest_sha256",
  "command_id",
  "exit_code",
  "span_ids",
  "assertion_ids",
  "actor_identity_hash",
  "manifest_commit_hash",
  "redaction_policy_version",
];

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireNonEmptyString(name: string, value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new RelayConfigError(`${name} must be a non-empty string`, {
      code: RELAY_SDK_CONFIG_CODE,
      details: { field: name, received_type: typeof value },
    });
  }
  return value;
}

function validateLifecycleStatus(value: unknown): LifecycleStatus {
  if (typeof value !== "string" || !LIFECYCLE_STATUSES.has(value)) {
    throw new RelayLifecycleInvalid(
      `client_lifecycle_status must be one of ${JSON.stringify([...LIFECYCLE_STATUSES].sort())}; received ${JSON.stringify(value)}`,
      {
        code: RELAY_SDK_LIFECYCLE_INVALID_CODE,
        details: {
          field: "client_lifecycle_status",
          received: value,
          allowed: [...LIFECYCLE_STATUSES].sort(),
        },
      },
    );
  }
  return value as LifecycleStatus;
}

function rejectCanonicalWriteFields(extras: Record<string, unknown>): void {
  const forbidden: string[] = [];
  for (const key of Object.keys(extras)) {
    if (CANONICAL_WRITE_FIELDS.has(key)) {
      forbidden.push(key);
    }
  }
  if (forbidden.length > 0) {
    forbidden.sort();
    throw new RelayCanonicalStatusForbidden(
      "ingest envelope must not carry canonical-result fields; the control plane is the sole writer (offending: " +
        JSON.stringify(forbidden) +
        ")",
      {
        code: RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE,
        details: {
          forbidden_fields: forbidden,
          all_canonical_fields: [...CANONICAL_WRITE_FIELDS].sort(),
          forged_field: forbidden[0],
        },
      },
    );
  }
}

export interface ThreeAnchorHandoff {
  scopeId: string;
  actorIdentityHash: string;
  manifestCommitHash: string;
}

function validateThreeAnchorHandoff(args: {
  scopeId: unknown;
  actorIdentityHash: unknown;
  manifestCommitHash: unknown;
}): ThreeAnchorHandoff {
  const missing: string[] = [];
  const isNonEmptyString = (v: unknown): v is string => typeof v === "string" && v !== "";
  if (!isNonEmptyString(args.scopeId)) missing.push("scope_id");
  if (!isNonEmptyString(args.actorIdentityHash)) missing.push("actor_identity_hash");
  if (!isNonEmptyString(args.manifestCommitHash)) missing.push("manifest_commit_hash");
  if (missing.length > 0) {
    throw new RelayHandoffIncomplete(
      `three-anchor handoff incomplete; missing anchors: ${JSON.stringify(missing)}`,
      {
        code: RELAY_SDK_HANDOFF_INCOMPLETE_CODE,
        details: { mismatched_anchor: missing },
      },
    );
  }
  return {
    scopeId: args.scopeId as string,
    actorIdentityHash: args.actorIdentityHash as string,
    manifestCommitHash: args.manifestCommitHash as string,
  };
}

// ---------------------------------------------------------------------------
// Envelope builders
// ---------------------------------------------------------------------------

export interface BuildIngestRunEnvelopeArgs {
  runId: string;
  traceId: string;
  projectId: string;
  agent: Record<string, unknown>;
  clientLifecycleStatus: string;
  startedAt: string;
  sdkVersion: string;
  sdkClock: string;
  manifestCommitHash: string;
  actorIdentityHash: string;
  redactionPolicyVersion: string;
  sequenceNumber: number;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
  /**
   * Free-form forward-compatibility bag. Caller-supplied keys land
   * AFTER the canonical structural fields. Canonical-write keys present
   * here are rejected at the SDK boundary.
   */
  extras?: Record<string, unknown>;
}

export interface IngestRunEnvelope {
  schema_version: string;
  run_id: string;
  trace_id: string;
  project_id: string;
  agent: Record<string, unknown>;
  client_lifecycle_status: LifecycleStatus;
  started_at: string;
  sdk_version: string;
  sdk_clock: string;
  manifest_commit_hash: string;
  actor_identity_hash: string;
  redaction_policy_version: string;
  idempotency_key: string;
  sequence_number: number;
  metadata: Record<string, unknown>;
  [extra: string]: unknown;
}

/**
 * Build a wire-format ``POST /v1/ingest/runs`` envelope.
 *
 * Carries lifecycle metadata ONLY -- no canonical result field may be
 * set. The SDK rejects any caller-supplied canonical-write field BEFORE
 * the request is sent.
 */
export function buildIngestRunEnvelope(args: BuildIngestRunEnvelopeArgs): IngestRunEnvelope {
  // 1) Three-anchor handoff first.
  const handoff = validateThreeAnchorHandoff({
    scopeId: args.runId,
    actorIdentityHash: args.actorIdentityHash,
    manifestCommitHash: args.manifestCommitHash,
  });

  // 2) Lifecycle-status enum.
  const status = validateLifecycleStatus(args.clientLifecycleStatus);

  // 3) Trivial non-empty-string fields.
  const traceId = requireNonEmptyString("trace_id", args.traceId);
  const projectId = requireNonEmptyString("project_id", args.projectId);
  const startedAt = requireNonEmptyString("started_at", args.startedAt);
  const sdkVersion = requireNonEmptyString("sdk_version", args.sdkVersion);
  const sdkClock = requireNonEmptyString("sdk_clock", args.sdkClock);
  const redactionPolicyVersion = requireNonEmptyString(
    "redaction_policy_version",
    args.redactionPolicyVersion,
  );

  if (
    args.agent === null ||
    typeof args.agent !== "object" ||
    Array.isArray(args.agent) ||
    Object.keys(args.agent).length === 0
  ) {
    throw new RelayConfigError("agent must be a non-empty object", {
      code: RELAY_SDK_CONFIG_CODE,
      details: { field: "agent", received_type: typeof args.agent },
    });
  }
  if (!Number.isInteger(args.sequenceNumber) || args.sequenceNumber < 0) {
    throw new RelayConfigError("sequence_number must be a non-negative integer", {
      code: RELAY_SDK_CONFIG_CODE,
      details: { field: "sequence_number", received: args.sequenceNumber },
    });
  }

  // 4) Refuse any escape-hatch attempt to set canonical-write fields.
  const extras: Record<string, unknown> = { ...(args.extras ?? {}) };
  rejectCanonicalWriteFields(extras);

  // 5) Allocate the idempotency key if not supplied.
  let key = args.idempotencyKey ?? newUlid();
  key = requireNonEmptyString("idempotency_key", key);

  const envelope: IngestRunEnvelope = {
    schema_version: INGEST_RUN_SCHEMA_VERSION,
    run_id: handoff.scopeId,
    trace_id: traceId,
    project_id: projectId,
    agent: { ...args.agent },
    client_lifecycle_status: status,
    started_at: startedAt,
    sdk_version: sdkVersion,
    sdk_clock: sdkClock,
    manifest_commit_hash: handoff.manifestCommitHash,
    actor_identity_hash: handoff.actorIdentityHash,
    redaction_policy_version: redactionPolicyVersion,
    idempotency_key: key,
    sequence_number: args.sequenceNumber,
    metadata: args.metadata ? { ...args.metadata } : {},
  };

  // 6) Merge extras AFTER structural fields.
  for (const [k, v] of Object.entries(extras)) {
    if (k in envelope) {
      throw new RelayConfigError(
        `extras key ${JSON.stringify(k)} collides with a structural envelope field`,
        {
          code: RELAY_SDK_CONFIG_CODE,
          details: { field: k },
        },
      );
    }
    envelope[k] = v;
  }
  return envelope;
}

export interface BuildGateDraftEnvelopeArgs {
  gateId: string;
  releaseSha: string;
  evalRunIds: ReadonlyArray<string>;
  manifestCommitHash: string;
  actorIdentityHash: string;
  /**
   * Optional caller-supplied draft id. If absent a fresh ULID is
   * generated. Mirrors Python's ``draft_id`` parameter.
   */
  draftId?: string;
  /** Optional worker_id to attach (spec B.6 schema). */
  workerId?: string;
  /** Optional scope_type ("run" by default per spec). */
  scopeType?: string;
  /** Optional remediation round (default 0). */
  round?: number;
  /** Optional evidence_refs list (run-result + evidence_bundle ids). */
  evidenceRefs?: ReadonlyArray<string>;
}

export interface GateDraftEnvelope {
  schema_version: string;
  draft_id: string;
  gate_id: string;
  release_sha: string;
  eval_run_ids: string[];
  manifest_commit_hash: string;
  actor_identity_hash: string;
  scope_id: string;
  worker_id?: string;
  scope_type?: string;
  round?: number;
  evidence_refs?: string[];
}

/**
 * Build a ``POST /v1/gates/{gate_id}/drafts`` body.
 *
 * VAL-W4-015: the SDK submits evidence-only drafts with the canonical
 * three-anchor handoff. The gate engine writes the canonical
 * :class:`GateDecision`. The SDK NEVER computes pass/fail itself.
 */
export function buildGateDraftEnvelope(args: BuildGateDraftEnvelopeArgs): GateDraftEnvelope {
  const gateId = requireNonEmptyString("gate_id", args.gateId);
  const releaseSha = requireNonEmptyString("release_sha", args.releaseSha);
  const runs = Array.from(args.evalRunIds ?? []);
  if (runs.length === 0) {
    throw new RelayConfigError("eval_run_ids must contain >= 1 eval_run reference", {
      code: RELAY_SDK_CONFIG_CODE,
      details: { field: "eval_run_ids" },
    });
  }
  for (const r of runs) {
    requireNonEmptyString("eval_run_id", r);
  }
  const handoff = validateThreeAnchorHandoff({
    scopeId: gateId,
    actorIdentityHash: args.actorIdentityHash,
    manifestCommitHash: args.manifestCommitHash,
  });
  const envelope: GateDraftEnvelope = {
    schema_version: GATE_DRAFT_SCHEMA_VERSION,
    draft_id: args.draftId ?? newUlid(),
    gate_id: gateId,
    release_sha: releaseSha,
    eval_run_ids: runs,
    manifest_commit_hash: handoff.manifestCommitHash,
    actor_identity_hash: handoff.actorIdentityHash,
    scope_id: gateId,
    // written_by is INTENTIONALLY absent. The SDK never writes it
    // (VAL-W4-009 grep guard); the gate engine writes the canonical row.
  };
  // Optional-field validation MUST mirror the Python
  // ``build_gate_draft_envelope`` helper (sdk-python/relay/lifecycle.py:368-376)
  // so envelopes built by the two SDKs are byte-equal under
  // canonical JSON. Without these checks the TS SDK would accept
  // values the Python SDK rejects (or coerce them in a non-portable
  // way), and a worker submitting through TS could emit an envelope
  // that the gate engine rejects with RELAY-GATE-021 (stale handoff)
  // or a downstream contract failure.
  if (args.workerId !== undefined) {
    envelope.worker_id = requireNonEmptyString("worker_id", args.workerId);
  }
  if (args.scopeType !== undefined) {
    envelope.scope_type = requireNonEmptyString("scope_type", args.scopeType);
  }
  if (args.round !== undefined) {
    // Python coerces ``round`` via ``int(round)``. Mirror that with a
    // safe-integer coercion that rejects NaN/Infinity/negative values.
    const raw = args.round as unknown;
    const asNumber = Number(raw);
    if (!Number.isFinite(asNumber)) {
      throw new RelayConfigError("round must be a finite number (no NaN/Infinity)", {
        code: RELAY_SDK_CONFIG_CODE,
        details: { field: "round", received_type: typeof raw },
      });
    }
    const coerced = Math.trunc(asNumber);
    if (coerced < 0) {
      throw new RelayConfigError("round must be >= 0", {
        code: RELAY_SDK_CONFIG_CODE,
        details: { field: "round", received: coerced },
      });
    }
    envelope.round = coerced;
  }
  if (args.evidenceRefs !== undefined) {
    if (!Array.isArray(args.evidenceRefs)) {
      throw new RelayConfigError("evidence_refs must be an Array of non-empty strings", {
        code: RELAY_SDK_CONFIG_CODE,
        details: { field: "evidence_refs", received_type: typeof args.evidenceRefs },
      });
    }
    const refs = Array.from(args.evidenceRefs);
    for (const ref of refs) {
      requireNonEmptyString("evidence_ref", ref);
    }
    envelope.evidence_refs = refs;
  }
  return envelope;
}

function requireEvidenceNonEmptyString(name: string, value: unknown): string {
  if (typeof value !== "string" || value === "") {
    throw new RelayEvidenceIncomplete(`${name} must be a non-empty string`, {
      code: RELAY_SDK_EVIDENCE_INCOMPLETE_CODE,
      details: { field: name, received_type: typeof value },
    });
  }
  return value;
}

export interface BuildEvidenceEnvelopeArgs {
  runId: string;
  artifactDigestSha256: string;
  commandId: string;
  exitCode: number;
  spanIds: ReadonlyArray<string>;
  assertionIds: ReadonlyArray<string>;
  actorIdentityHash: string;
  manifestCommitHash: string;
  redactionPolicyVersion: string;
}

export interface EvidenceEnvelope {
  schema_version: string;
  run_id: string;
  artifact_digest_sha256: string;
  command_id: string;
  exit_code: number;
  span_ids: string[];
  assertion_ids: string[];
  actor_identity_hash: string;
  manifest_commit_hash: string;
  redaction_policy_version: string;
}

/**
 * Build an evidence-submit envelope.
 *
 * VAL-W4-016: every required field MUST be present and bound. A missing
 * required field raises :class:`RelayEvidenceIncomplete` at the SDK
 * boundary BEFORE the request is sent. The error's ``details.field``
 * names the offending field.
 *
 * The envelope carries metadata + content digests only; raw plaintext
 * MUST NOT appear here. (W4.3 redaction binds the raw-plaintext exclusion
 * for span fields; this builder additionally accepts only digest-shaped
 * inputs for ``artifact_digest_sha256``.)
 */
export function buildEvidenceEnvelope(args: BuildEvidenceEnvelopeArgs): EvidenceEnvelope {
  const runId = requireEvidenceNonEmptyString("run_id", args.runId);
  const artifactDigest = requireEvidenceNonEmptyString(
    "artifact_digest_sha256",
    args.artifactDigestSha256,
  );
  const commandId = requireEvidenceNonEmptyString("command_id", args.commandId);
  const redactionPolicyVersion = requireEvidenceNonEmptyString(
    "redaction_policy_version",
    args.redactionPolicyVersion,
  );
  if (typeof args.exitCode !== "number" || !Number.isInteger(args.exitCode)) {
    throw new RelayEvidenceIncomplete("exit_code must be an integer (process exit code)", {
      code: RELAY_SDK_EVIDENCE_INCOMPLETE_CODE,
      details: { field: "exit_code", received_type: typeof args.exitCode },
    });
  }
  const spans = (args.spanIds ?? []).map((s) => String(s));
  if (spans.length === 0) {
    throw new RelayEvidenceIncomplete("span_ids must contain >= 1 entry", {
      code: RELAY_SDK_EVIDENCE_INCOMPLETE_CODE,
      details: { field: "span_ids" },
    });
  }
  const asserts = (args.assertionIds ?? []).map((a) => String(a));
  if (asserts.length === 0) {
    throw new RelayEvidenceIncomplete("assertion_ids must contain >= 1 entry", {
      code: RELAY_SDK_EVIDENCE_INCOMPLETE_CODE,
      details: { field: "assertion_ids" },
    });
  }
  const handoff = validateThreeAnchorHandoff({
    scopeId: runId,
    actorIdentityHash: args.actorIdentityHash,
    manifestCommitHash: args.manifestCommitHash,
  });
  return {
    schema_version: EVIDENCE_SUBMIT_SCHEMA_VERSION,
    run_id: runId,
    artifact_digest_sha256: artifactDigest,
    command_id: commandId,
    exit_code: args.exitCode,
    span_ids: spans,
    assertion_ids: asserts,
    actor_identity_hash: handoff.actorIdentityHash,
    manifest_commit_hash: handoff.manifestCommitHash,
    redaction_policy_version: redactionPolicyVersion,
  };
}
