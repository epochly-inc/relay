# GENERATED FILE - DO NOT EDIT BY HAND.
#
# Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
# Regenerate: uv run python packages/schemas/scripts/codegen.py
# Drift check: uv run python scripts/check-codegen-drift.py
#
# Per VAL-W1-033 every class is a Pydantic v2 BaseModel subclass with
# model_config = ConfigDict(extra='forbid').

"""Field alias maps for VAL-W1-037 snake_case <-> camelCase boundary.

Canonical wire-format field names are snake_case (e.g. ``run_result_id``).
The Python side exposes snake_case attributes directly (Pydantic default).
The TS side uses camelCase property names with the alias mapping under
``packages/sdk-typescript/src/_generated/aliases.ts``.

The dictionaries below are the source-of-truth for the cross-language
round-trip test (VAL-W1-037): both languages MUST produce identical
serialized output when given the same snake_case wire payload.
"""

from __future__ import annotations

# Mapping per envelope: snake_case field name -> camelCase field name.
# Fields with no underscores (already camelCase-equivalent) are omitted.
FIELD_ALIASES_BY_ENVELOPE: dict[str, dict[str, str]] = {
    "Actor": {
        "created_at": "createdAt",
        "identity_hash": "identityHash",
        "revoked_at": "revokedAt",
    },
    "ErrorEnvelope": {
        "blocked_surface": "blockedSurface",
        "http_status": "httpStatus",
        "request_id": "requestId",
        "retry_advice": "retryAdvice",
        "schema_version": "schemaVersion",
        "trace_id": "traceId",
    },
    "EventLogEntry": {
        "actor_id": "actorId",
        "actor_kind": "actorKind",
        "event_id": "eventId",
        "event_type": "eventType",
        "ingest_sequence": "ingestSequence",
        "manifest_commit_hash": "manifestCommitHash",
        "occurred_at": "occurredAt",
        "project_id": "projectId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_type": "scopeType",
    },
    "EvidenceBundle": {
        "acef_core_version": "acefCoreVersion",
        "bundle_digest": "bundleDigest",
        "created_at": "createdAt",
        "evidence_bundle_id": "evidenceBundleId",
        "manifest_commit_hash": "manifestCommitHash",
        "object_ref": "objectRef",
        "org_id": "orgId",
        "project_id": "projectId",
        "redaction_policy_version": "redactionPolicyVersion",
        "relay_extension_version": "relayExtensionVersion",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_type": "scopeType",
        "signature_algorithm": "signatureAlgorithm",
        "signing_key_id": "signingKeyId",
        "supersedes_bundle_id": "supersedesBundleId",
        "verification_status": "verificationStatus",
    },
    "EvidenceBundleScopeState": {
        "created_at": "createdAt",
        "project_id": "projectId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_kind": "scopeKind",
        "updated_at": "updatedAt",
    },
    "EvidenceClaim": {
        "claim_digest": "claimDigest",
        "claim_type": "claimType",
        "created_at": "createdAt",
        "evidence_bundle_id": "evidenceBundleId",
        "evidence_claim_id": "evidenceClaimId",
        "manifest_commit_hash": "manifestCommitHash",
        "redaction_transform_version": "redactionTransformVersion",
        "schema_version": "schemaVersion",
        "signer_key_id": "signerKeyId",
        "subject_id": "subjectId",
        "subject_kind": "subjectKind",
        "supersedes_claim_id": "supersedesClaimId",
    },
    "GateDecision": {
        "actor_identity_hash": "actorIdentityHash",
        "cascade_on_block": "cascadeOnBlock",
        "decided_at": "decidedAt",
        "decided_by": "decidedBy",
        "decision_epoch": "decisionEpoch",
        "evidence_bundle_id": "evidenceBundleId",
        "failed_assertion_ids": "failedAssertionIds",
        "gate_decision_id": "gateDecisionId",
        "gate_id": "gateId",
        "manifest_commit_hash": "manifestCommitHash",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_type": "scopeType",
        "signature_key_id": "signatureKeyId",
        "strict_pass": "strictPass",
        "unmet_conditions": "unmetConditions",
    },
    "GateDecisionDraft": {
        "actor_identity_hash": "actorIdentityHash",
        "cancellation_reason": "cancellationReason",
        "cancelled_at": "cancelledAt",
        "draft_id": "draftId",
        "draft_kind": "draftKind",
        "eval_run_ids": "evalRunIds",
        "evidence_refs": "evidenceRefs",
        "gate_id": "gateId",
        "manifest_commit_hash": "manifestCommitHash",
        "release_sha": "releaseSha",
        "resolution_state": "resolutionState",
        "resolved_gate_decision_id": "resolvedGateDecisionId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_type": "scopeType",
        "submitted_at": "submittedAt",
        "worker_id": "workerId",
    },
    "GateRound": {
        "gate_decision_id": "gateDecisionId",
        "gate_id": "gateId",
        "gate_round_id": "gateRoundId",
        "initiated_at": "initiatedAt",
        "initiated_by": "initiatedBy",
        "initiation_reason": "initiationReason",
        "restart_predecessor": "restartPredecessor",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_type": "scopeType",
    },
    "GateRoundScopeState": {
        "created_at": "createdAt",
        "project_id": "projectId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_kind": "scopeKind",
        "updated_at": "updatedAt",
    },
    "IdempotencyRecord": {
        "expires_at": "expiresAt",
        "first_seen_at": "firstSeenAt",
        "idempotency_key": "idempotencyKey",
        "project_id": "projectId",
        "request_digest": "requestDigest",
        "response_ref": "responseRef",
        "response_status": "responseStatus",
        "schema_version": "schemaVersion",
    },
    "ManifestVersion": {
        "commit_hash": "commitHash",
        "effective_at": "effectiveAt",
        "effective_until": "effectiveUntil",
        "manifest_id": "manifestId",
        "manifest_version_id": "manifestVersionId",
        "schema_version": "schemaVersion",
        "signature_key_id": "signatureKeyId",
        "signed_by": "signedBy",
    },
    "RedactionPolicy": {
        "approver_user_id": "approverUserId",
        "created_at": "createdAt",
        "dpa_ref": "dpaRef",
        "org_id": "orgId",
        "raw_capture": "rawCapture",
        "redaction_policy_id": "redactionPolicyId",
        "schema_version": "schemaVersion",
    },
    "ReplayCase": {
        "created_at": "createdAt",
        "expected_assertion_ids": "expectedAssertionIds",
        "failure_signature_hash": "failureSignatureHash",
        "human_reviewed": "humanReviewed",
        "inputs_digest": "inputsDigest",
        "inputs_ref": "inputsRef",
        "project_id": "projectId",
        "replay_case_id": "replayCaseId",
        "reviewed_at": "reviewedAt",
        "reviewer_email": "reviewerEmail",
        "schema_version": "schemaVersion",
        "source_run_id": "sourceRunId",
    },
    "ReplayCaseScopeState": {
        "created_at": "createdAt",
        "project_id": "projectId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_kind": "scopeKind",
        "updated_at": "updatedAt",
    },
    "ReplayFixture": {
        "allowed_in_replay": "allowedInReplay",
        "capture_clock": "captureClock",
        "created_at": "createdAt",
        "fixture_id": "fixtureId",
        "input_digest": "inputDigest",
        "model_signature": "modelSignature",
        "output_digest": "outputDigest",
        "output_ref": "outputRef",
        "redaction_policy_version": "redactionPolicyVersion",
        "refresh_policy": "refreshPolicy",
        "replay_case_id": "replayCaseId",
        "schema_version": "schemaVersion",
        "side_effect_class": "sideEffectClass",
        "source_span_id": "sourceSpanId",
    },
    "RunResult": {
        "actor_identity_hash": "actorIdentityHash",
        "decided_at": "decidedAt",
        "decision_epoch": "decisionEpoch",
        "error_priority_rule": "errorPriorityRule",
        "evidence_bundle_id": "evidenceBundleId",
        "manifest_commit_hash": "manifestCommitHash",
        "primary_failure_class": "primaryFailureClass",
        "project_id": "projectId",
        "run_id": "runId",
        "run_result_id": "runResultId",
        "schema_version": "schemaVersion",
        "signature_key_id": "signatureKeyId",
        "written_by": "writtenBy",
    },
    "RunScopeState": {
        "created_at": "createdAt",
        "project_id": "projectId",
        "schema_version": "schemaVersion",
        "scope_id": "scopeId",
        "scope_kind": "scopeKind",
        "updated_at": "updatedAt",
    },
}


def snake_to_camel(envelope: str) -> dict[str, str]:
    """Return the snake_case -> camelCase alias map for ``envelope``.

    If ``envelope`` is not in the canonical envelope set, returns an empty
    dict (no aliases known).
    """
    return dict(FIELD_ALIASES_BY_ENVELOPE.get(envelope, {}))


def camel_to_snake(envelope: str) -> dict[str, str]:
    """Return the camelCase -> snake_case alias map for ``envelope``.

    Inverse of ``snake_to_camel``.
    """
    fwd = FIELD_ALIASES_BY_ENVELOPE.get(envelope, {})
    return {v: k for k, v in fwd.items()}


__all__ = [
    "FIELD_ALIASES_BY_ENVELOPE",
    "snake_to_camel",
    "camel_to_snake",
]
