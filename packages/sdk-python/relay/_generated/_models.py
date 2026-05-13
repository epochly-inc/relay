# GENERATED FILE - DO NOT EDIT BY HAND.
#
# Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
# Regenerate: uv run python packages/schemas/scripts/codegen.py
# Drift check: uv run python scripts/check-codegen-drift.py
#
# Per VAL-W1-033 every class is a Pydantic v2 BaseModel subclass with
# model_config = ConfigDict(extra='forbid').

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    conint,
    constr,
)


class Sha256Hash(RootModel[constr(pattern=r"^sha256-[0-9a-f]{64}$")]):
    root: constr(pattern=r"^sha256-[0-9a-f]{64}$") = Field(
        ...,
        description="Canonical Relay sha256 wire form: 'sha256-' + 64 lowercase hex chars.\nThe colon form (sha256:<hex>) and bare-hex form are rejected\n(VAL-W1-009).\n",
    )


class Ulid(RootModel[constr(pattern=r"^[0-9A-HJKMNP-TV-Z]{26}$")]):
    root: constr(pattern=r"^[0-9A-HJKMNP-TV-Z]{26}$") = Field(
        ...,
        description="Crockford-base32 ULID, 26 uppercase chars (spec B.6 line 3517).\nLowercase letters not permitted; I, L, O, U excluded.\n",
    )


class RelayErrorCodeStr(RootModel[constr(pattern=r"^RELAY-[A-Z]+-[0-9]{3}$")]):
    root: constr(pattern=r"^RELAY-[A-Z]+-[0-9]{3}$") = Field(
        ...,
        description="Canonical Relay error-code wire form per VAL-W1-029. Known values\nenumerated in packages/schemas/raw/relay-error-codes.yaml.\n",
    )


class RunResult(BaseModel):
    """
    Canonical run outcome. Written exclusively by the control plane.
    A successful run requires a bound evidence_bundle_id (CLAUDE.md
    keystone invariant #2). Spec A.1.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.run_result.v1"]
    run_result_id: UUID
    run_id: UUID
    project_id: UUID
    written_by: Literal["control_plane"]
    status: Literal["accepted", "remediate_required", "blocked", "invalid"]
    primary_failure_class: str | None = None
    error_priority_rule: str | None = (
        "first_p0_then_highest_severity_then_earliest_span"
    )
    evidence_bundle_id: UUID | None = None
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    decided_at: AwareDatetime
    decision_epoch: conint(ge=0) | None = 0
    signature: str
    signature_key_id: str


class GateDecision(BaseModel):
    """
    Canonical gate decision. Written exclusively by the gate engine.
    Spec A.2.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.gate_decision.v1"]
    gate_decision_id: UUID
    gate_id: UUID
    scope_type: Literal["run", "replay", "eval_run", "release", "domain_pack"]
    scope_id: UUID
    round: conint(ge=1)
    action: Literal["accept", "remediate", "block", "invalid"]
    strict_pass: bool | None = False
    failed_assertion_ids: list[str] | None = []
    unmet_conditions: list[Any] | None = []
    evidence_bundle_id: UUID
    cascade_on_block: bool | None = True
    decided_by: Literal["gate_engine"]
    decided_at: AwareDatetime
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    signature: str
    signature_key_id: str
    decision_epoch: conint(ge=0) | None = 0


class GateDecisionDraft(BaseModel):
    """
    Submitter-facing draft. NOT authoritative. Resolved into a
    gate_decision exactly once by the state engine. Spec A.3.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.gate_decision_draft.v1"]
    draft_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: conint(ge=1)
    release_sha: str | None = None
    eval_run_ids: list[UUID] | None = []
    evidence_refs: list[Any] | None = []
    worker_id: UUID
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    submitted_at: AwareDatetime
    resolved_gate_decision_id: UUID | None = None
    draft_kind: Literal["submitted", "dry_run_unsigned"] | None = "submitted"
    resolution_state: (
        Literal[
            "pending",
            "resolved",
            "rejected_handoff",
            "expired",
            "cancelled",
            "duplicate_submission",
        ]
        | None
    ) = "pending"
    cancelled_at: AwareDatetime | None = None
    cancellation_reason: str | None = None


class GateRound(BaseModel):
    """
    Per-round audit trail. Spec A.4.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.gate_round.v1"]
    gate_round_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: conint(ge=1)
    initiated_at: AwareDatetime
    initiated_by: Literal["control_plane", "cron", "user", "remediation"]
    initiation_reason: str | None = None
    gate_decision_id: UUID | None = None
    restart_predecessor: UUID | None = None


class Actor(BaseModel):
    """
    Actor identity registry. FK target for the three-anchor handoff.
    Spec C.5.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    identity_hash: Sha256Hash
    kind: Literal["human", "bot", "worker", "reviewer"]
    created_at: AwareDatetime
    revoked_at: AwareDatetime | None = None


class ManifestVersion(BaseModel):
    """
    A specific committed manifest version. commit_hash is the canonical
    Relay sha256 wire form (sha256-<64 lowercase hex>). Spec A.9.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.manifest.v1"]
    manifest_version_id: UUID
    manifest_id: UUID
    commit_hash: Sha256Hash
    body: dict[str, Any]
    signed_by: str | None = None
    signature: str | None = None
    signature_key_id: str | None = None
    effective_at: AwareDatetime
    effective_until: AwareDatetime | None = None


class RunScopeState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["run"]
    state: Literal[
        "pending", "captured", "validating", "gated", "result_written", "terminal"
    ]
    scope_id: UUID
    project_id: UUID
    epoch: conint(ge=0)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ReplayCaseScopeState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["replay_case"]
    state: Literal["proposed", "fixtures_ready", "executing", "analyzed", "terminal"]
    scope_id: UUID
    project_id: UUID
    epoch: conint(ge=0)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class GateRoundScopeState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["gate_round"]
    state: Literal[
        "open",
        "draft_received",
        "evaluating",
        "decision_written",
        "restarted",
        "terminal",
    ]
    scope_id: UUID
    project_id: UUID
    epoch: conint(ge=0)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class EvidenceBundleScopeState(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["evidence_bundle"]
    state: Literal["building", "signed", "published", "superseded", "revoked"]
    scope_id: UUID
    project_id: UUID
    epoch: conint(ge=0)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class IdempotencyRecord(BaseModel):
    """
    Request dedupe record. idempotency_key is a Crockford-base32 ULID
    (spec B.2/B.6 line 3517). Spec A.12.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.idempotency_record.v1"]
    idempotency_key: Ulid
    project_id: UUID
    request_digest: Sha256Hash
    response_status: conint(ge=0)
    response_ref: str | None = None
    first_seen_at: AwareDatetime
    expires_at: AwareDatetime


class EventLogEntry(BaseModel):
    """
    Append-only audit-trail row. occurred_at is RFC 3339 with a required
    timezone offset; naive timestamps fail at the hand-authored wrapper
    layer (VAL-W1-017). Spec A.11.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.event_log_entry.v1"]
    event_id: UUID
    project_id: UUID
    scope_type: Literal[
        "run", "replay", "gate", "eval_run", "release", "manifest", "key", "other"
    ]
    scope_id: UUID
    event_type: str
    actor_kind: Literal["control_plane", "gate_engine", "worker", "sdk", "user", "cron"]
    actor_id: UUID | None = None
    manifest_commit_hash: Sha256Hash | None = None
    payload: dict[str, Any] | None = {}
    occurred_at: AwareDatetime
    ingest_sequence: conint(ge=0)


class EvidenceBundle(BaseModel):
    """
    Signed evidence bundle row. Spec J line 2792-2810.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.evidence_bundle.v1"]
    evidence_bundle_id: UUID
    org_id: UUID
    project_id: UUID
    scope_type: str
    scope_id: UUID
    bundle_digest: Sha256Hash
    acef_core_version: str
    relay_extension_version: str
    signing_key_id: str | None = None
    signature_algorithm: str | None = None
    verification_status: Literal["unverified", "verified", "tampered", "revoked"]
    redaction_policy_version: str
    manifest_commit_hash: Sha256Hash | None = None
    object_ref: str
    supersedes_bundle_id: UUID | None = None
    created_at: AwareDatetime


class EvidenceClaim(BaseModel):
    """
    Atomic claim inside an evidence bundle. Spec A.16 lines 3331-3353.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.evidence_claim.v1"]
    evidence_claim_id: UUID
    evidence_bundle_id: UUID
    claim_type: Literal[
        "run_result",
        "gate_decision",
        "contract_result",
        "replay_result",
        "human_oversight",
        "incident",
        "data_quality_check",
        "provider_compatibility",
    ]
    subject_kind: str
    subject_id: UUID
    claim_digest: Sha256Hash
    redaction_transform_version: str
    manifest_commit_hash: Sha256Hash
    signer_key_id: str
    signature: constr(min_length=1)
    supersedes_claim_id: UUID | None = None
    created_at: AwareDatetime


class ReplayCase(BaseModel):
    """
    Replay case row. Spec A.8 lines 3131-3145.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.replay_case.v1"]
    replay_case_id: UUID
    project_id: UUID
    source_run_id: UUID | None = None
    failure_signature_hash: constr(min_length=1)
    inputs_ref: str
    inputs_digest: Sha256Hash
    expected_assertion_ids: list[constr(min_length=1)] | None = []
    human_reviewed: bool | None = False
    reviewer_email: str | None = None
    reviewed_at: AwareDatetime | None = None
    status: Literal["proposed", "approved", "retired"] | None = "proposed"
    created_at: AwareDatetime


class ReplayFixture(BaseModel):
    """
    Replay fixture row. Spec A.8 lines 3147-3168 + E.2-E.3.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.replay_fixture.v1"]
    fixture_id: UUID
    replay_case_id: UUID
    source_span_id: UUID
    kind: Literal["model_call", "tool_call", "retrieval", "embedding", "custom"]
    mode: Literal["cassette", "live", "degraded_live", "mock"]
    redaction_policy_version: str
    input_digest: Sha256Hash
    output_ref: str | None = None
    output_digest: Sha256Hash | None = None
    provider: str | None = None
    model: str | None = None
    model_signature: str | None = None
    capture_clock: AwareDatetime
    refresh_policy: (
        Literal[
            "invalidate_on_signature_change",
            "hold_forever",
            "refresh_weekly",
            "invalidate_on_model_version_change",
        ]
        | None
    ) = "invalidate_on_signature_change"
    side_effect_class: Literal[
        "read_only", "mutating", "external_irreversible", "approval_required"
    ]
    allowed_in_replay: bool | None = False
    created_at: AwareDatetime


class RedactionPolicyMatcherRegex(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["regex"]
    pattern: constr(min_length=1)


class Path(RootModel[constr(min_length=1)]):
    root: constr(min_length=1)


class RedactionPolicyMatcherJsonPointer(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["json_pointer"]
    paths: list[Path] = Field(..., min_length=1)


class RedactionPolicyMatcher(
    RootModel[RedactionPolicyMatcherRegex | RedactionPolicyMatcherJsonPointer]
):
    root: RedactionPolicyMatcherRegex | RedactionPolicyMatcherJsonPointer = Field(
        ...,
        description="Tagged discriminated union on `kind` (VAL-W1-028). Spec G.2 lines\n4127-4133.\n",
        discriminator="kind",
    )


class RedactionPolicy(BaseModel):
    """
    Per-org redaction policy version. Spec A.10 lines 3219-3225.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.redaction.v1"]
    redaction_policy_id: UUID
    org_id: UUID
    version: str
    raw_capture: bool | None = False
    dpa_ref: str | None = None
    approver_user_id: UUID | None = None
    matchers: list[RedactionPolicyMatcher] | None = Field([], validate_default=True)
    created_at: AwareDatetime


class ErrorEnvelope(BaseModel):
    """
    Canonical Relay error envelope. Spec B.4 lines 3392-3408.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.error.v1"]
    code: RelayErrorCodeStr
    http_status: conint(ge=400, le=599)
    blocked_surface: constr(min_length=1)
    retry_advice: Literal[
        "do_not_retry",
        "after_fix",
        "after_retry_after",
        "after_split",
        "after_recapture",
        "after_re_auth",
    ]
    request_id: constr(min_length=1)
    trace_id: constr(min_length=1)
    message: str | None = None
    details: dict[str, Any] | None = {}


class ScopeState(
    RootModel[
        RunScopeState
        | ReplayCaseScopeState
        | GateRoundScopeState
        | EvidenceBundleScopeState
    ]
):
    root: (
        RunScopeState
        | ReplayCaseScopeState
        | GateRoundScopeState
        | EvidenceBundleScopeState
    ) = Field(
        ...,
        description="Mutable scope state per (scope_kind, scope_id). Discriminated union\non scope_kind so each kind's allowed state set (spec C.1) is\nstatically enforced at the wire-format layer. Spec W.\n",
        discriminator="scope_kind",
    )
