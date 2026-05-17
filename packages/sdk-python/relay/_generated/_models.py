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
    confloat,
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


class EvalRunScopeState(BaseModel):
    """
    scope_kind='eval_run' variant of ScopeState. Spec AM eval lifecycle:
    pending -> running -> scored | terminal. Initial state 'pending' per
    spec W lines 5101-5111. VAL-V2M01-036.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["eval_run"]
    state: Literal["pending", "running", "scored", "terminal"]
    scope_id: UUID
    project_id: UUID
    epoch: conint(ge=0)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ReleaseScopeState(BaseModel):
    """
    scope_kind='release' variant of ScopeState. Spec Q.2 release
    lifecycle: open -> gated -> released | rolled_back | terminal.
    Initial state 'open' per spec W lines 5101-5111. VAL-V2M01-036.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.scope_state.v1"]
    scope_kind: Literal["release"]
    state: Literal["open", "gated", "released", "rolled_back", "terminal"]
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


class GatePolicy(BaseModel):
    """
    Per-gate policy version. Spec A.5 lines 3063-3076 (VAL-V2M01-001).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.gate_policy.v1"]
    gate_policy_id: UUID
    gate_id: UUID
    policy_version: str
    conditions: dict[str, Any]
    baseline_selector: dict[str, Any] | None = None
    flaky_quarantine_policy: dict[str, Any] | None = None
    blocking_severity: Literal["p0_only", "p0_p1", "any_failure"] | None = "p0_only"
    effective_at: AwareDatetime
    effective_until: AwareDatetime | None = None


class ContractResult(BaseModel):
    """
    Per-run contract evaluation result. Spec A.6 lines 3082-3102
    (VAL-V2M01-002).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.contract_result.v1"]
    contract_result_id: UUID
    run_id: UUID
    contract_id: UUID
    contract_version: str
    assertion_id: str | None = None
    span_id: UUID | None = None
    outcome: Literal["pass", "fail", "repaired", "skipped", "error"]
    severity: Literal["p0", "p1", "p2", "info"] | None = None
    raw_signature_hash: str | None = None
    repair_attempt: conint(ge=0) | None = 0
    evaluation_engine_version: str
    evaluated_at: AwareDatetime
    metadata: dict[str, Any] | None = {}


class AssertionDefinition(BaseModel):
    """
    Atomic assertion definition. Spec A.7 lines 3108-3125
    (VAL-V2M01-003).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.assertion_definition.v1"]
    assertion_id: str
    project_id: UUID
    kind: Literal["schema_contract", "behavioral", "tool_arg", "eval", "coverage"]
    severity: Literal["p0", "p1", "p2", "info"]
    title: str
    description: str | None = None
    owner_email: str
    expression: dict[str, Any]
    applies_to: dict[str, Any] | None = {}
    lifecycle_state: Literal["draft", "active", "deprecated", "retired"] | None = (
        "draft"
    )
    current_version: conint(ge=1)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class ReplayResult(BaseModel):
    """
    Per-replay outcome row. Spec A.8 lines 3172-3187 (VAL-V2M01-004).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.replay_result.v1"]
    replay_result_id: UUID
    replay_case_id: UUID
    replay_run_id: UUID
    outcome: Literal["reproduced", "diverged", "blocked", "sandbox_error"]
    failure_signature_match: bool | None = None
    fixture_hits: conint(ge=0) | None = 0
    fixture_misses: conint(ge=0) | None = 0
    sandbox_driver: str
    sandbox_id: str | None = None
    network_egress_denied: conint(ge=0) | None = 0
    side_effect_attempts: conint(ge=0) | None = 0
    side_effect_approved: conint(ge=0) | None = 0
    evidence_bundle_id: UUID | None = None
    created_at: AwareDatetime


class Manifest(BaseModel):
    """
    Manifest parent identity row. Spec A.9 lines 3193-3199 (VAL-V2M01-005).
    Uses schema_version literal `relay.manifest_parent.v1` to avoid
    colliding with the existing ManifestVersion `relay.manifest.v1`.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.manifest_parent.v1"]
    manifest_id: UUID
    project_id: UUID
    name: str
    created_at: AwareDatetime


class Incident(BaseModel):
    """
    Incident cluster row. Spec A.13 lines 3274-3290 (VAL-V2M01-007).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.incident.v1"]
    incident_id: UUID
    project_id: UUID
    cluster_signature_hash: str
    severity: Literal["sev1", "sev2", "sev3", "sev4"]
    state: Literal["open", "mitigated", "closed", "suppressed"] | None = "open"
    affected_run_ids: list[UUID] | None = []
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    owner_email: str | None = None
    postmortem_ref: str | None = None
    promoted_to_regression: bool | None = False
    created_at: AwareDatetime | None = None


class RootCauseHypothesis(BaseModel):
    """
    Explain root-cause hypothesis. Spec A.15 lines 3316-3328; sectionT
    (VAL-V2M01-008).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.root_cause_hypothesis.v1"]
    hypothesis_id: UUID
    run_id: UUID
    span_id: UUID | None = None
    hypothesis_class: str
    confidence: confloat(ge=0.0, le=1.0)
    evidence_refs: list[Any] | None = []
    generator: str
    reviewer_email: str | None = None
    reviewer_decision: Literal["accept", "reject", "modify", "pending"] | None = None
    promoted_to_replay_case_id: UUID | None = None
    created_at: AwareDatetime


class Span(BaseModel):
    """
    Parent span row. Spec Z lines 1825-1836 (VAL-V2M01-009). span_type
    is the polymorphic discriminator that drives the typed-detail
    invariant: span_type in {model_call, tool_call, retrieval,
    embedding} MUST have a matching typed-detail row in the same
    INSERT transaction. span_type='custom' requires no typed-detail
    row. Canonical missing-detail error code:
    RELAY-INGEST-SPAN-DETAIL-MISSING.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.span.v1"]
    span_id: UUID
    run_id: UUID | None = None
    parent_span_id: UUID | None = None
    span_type: Literal["model_call", "tool_call", "retrieval", "embedding", "custom"]
    name: str
    status: str
    started_at: AwareDatetime
    ended_at: AwareDatetime | None = None
    error_class: str | None = None
    metadata: dict[str, Any] | None = {}


class ModelCallSpan(BaseModel):
    """
    Typed-detail row for span_type='model_call'. Spec Z lines 5226-5249
    (VAL-V2M01-010).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.model_call_span.v1"]
    span_id: UUID
    provider: str
    model: str
    model_signature: str | None = None
    request_message_count: conint(ge=0) | None = None
    request_token_count: conint(ge=0) | None = None
    response_token_count: conint(ge=0) | None = None
    cached_token_count: conint(ge=0) | None = None
    reasoning_token_count: conint(ge=0) | None = None
    cost_usd: float | None = None
    latency_ms: conint(ge=0) | None = None
    finish_reason: str | None = None
    structured_output_mode: str | None = None
    schema_contract_id: str | None = None
    tool_choice_mode: str | None = None
    streaming: bool | None = False
    input_redaction_policy_version: str
    input_digest: str | None = None
    output_digest: str | None = None
    http_status: conint(ge=0) | None = None
    provider_error_code: str | None = None
    provider_error_class: str | None = None


class ToolCallSpan(BaseModel):
    """
    Typed-detail row for span_type='tool_call'. Spec Z lines 5251-5264
    (VAL-V2M01-011).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.tool_call_span.v1"]
    span_id: UUID
    tool_name: str
    side_effect_class: str
    args_digest: str | None = None
    args_redaction_policy_version: str
    args_schema_contract_id: str | None = None
    args_validation_outcome: (
        Literal["pass", "fail", "repaired", "skipped", "error"] | None
    ) = None
    result_digest: str | None = None
    status: str
    latency_ms: conint(ge=0) | None = None
    marker_id: UUID | None = None
    parallel_index: conint(ge=0) | None = None


class RetrievalSpan(BaseModel):
    """
    Typed-detail row for span_type='retrieval'. Spec Z lines 5266-5279
    (VAL-V2M01-012).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.retrieval_span.v1"]
    span_id: UUID
    retriever_name: str
    query_digest: str | None = None
    query_redaction_policy_version: str
    document_count: conint(ge=0) | None = None
    duplicate_document_count: conint(ge=0) | None = None
    empty_retrieval: bool | None = False
    relevance_proxy_score: float | None = None
    citation_coverage: float | None = None
    context_token_count: conint(ge=0) | None = None
    context_waste_tokens: conint(ge=0) | None = None
    latency_ms: conint(ge=0) | None = None


class EmbeddingSpan(BaseModel):
    """
    Typed-detail row for span_type='embedding'. Spec Z lines 5281-5290
    (VAL-V2M01-013).

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.embedding_span.v1"]
    span_id: UUID
    provider: str
    model: str
    input_token_count: conint(ge=0) | None = None
    embedding_dim: conint(ge=0) | None = None
    cached: bool | None = False
    cost_usd: float | None = None
    latency_ms: conint(ge=0) | None = None


class EvidenceLegalHold(BaseModel):
    """
    Legal hold row. Spec Y lines 5184-5200 (VAL-V2M01-026). scope_kind
    is the closed four-member set {org, project, run, evidence_bundle}.
    state is the closed two-member workflow {active, released}.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.evidence_legal_hold.v1"]
    hold_id: UUID
    org_id: UUID
    scope_kind: Literal["org", "project", "run", "evidence_bundle"]
    scope_id: UUID
    reason: str
    legal_matter_ref: str | None = None
    imposed_by_user_id: UUID
    counsel_signoff_at: AwareDatetime | None = None
    counsel_signoff_by: str | None = None
    state: Literal["active", "released"] | None = "active"
    imposed_at: AwareDatetime
    released_at: AwareDatetime | None = None
    released_by_user_id: UUID | None = None


class EvidenceBundleRegistry(BaseModel):
    """
    Mutable sibling row to the immutable signed evidence_bundles
    table. Spec Y lines 5202-5213 (VAL-V2M01-027). state is the closed
    four-member machine {active, superseded, tombstoned, legal_hold}.
    Tombstoned is terminal and records the subject_redaction_tombstone
    claim that enables compliant deletion without mutating signed
    content (spec Y line 5219). State-machine transition rules beyond
    the closed enum live in
    relay_schemas.bundle_registry.validate_registry_transition.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.evidence_bundle_registry.v1"]
    evidence_bundle_id: UUID
    state: Literal["active", "superseded", "tombstoned", "legal_hold"] | None = "active"
    superseded_by: UUID | None = None
    subject_redacted_after_signing: bool | None = False
    redaction_event_ref: str | None = None
    legal_hold_id: UUID | None = None
    last_state_change_at: AwareDatetime


class EvidenceTimestamp(BaseModel):
    """
    RFC 3161 TSA timestamp row for an evidence bundle. Spec AB lines
    5421-5429 (VAL-V2M01-033). One row per bundle. tsa_genTime is
    parsed from the TimeStampResp CMS SignerInfo; tsa_response_ref
    points at the canonical .tsr blob; tsa_response_digest is the
    sha256 over the .tsr bytes so verifiers detect mutation.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.evidence_timestamp.v1"]
    evidence_bundle_id: UUID
    tsa_url: str
    tsa_response_digest: str
    tsa_response_ref: str
    tsa_serial_number: str | None = None
    tsa_genTime: AwareDatetime
    tsa_witness_signature: str | None = None


class TransparencyLogEntry(BaseModel):
    """
    Append-only public transparency log entry. Spec AB lines 5431-5439
    (VAL-V2M01-035). Inspired by Sigstore Rekor. log_index is the
    canonical 1-based serial index; tree_root_after is the Merkle root
    after the append; inclusion_proof_ref points at the served proof
    JSON. Per spec AB line 5445 the log is append-only; application
    role grants are INSERT,SELECT only.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.transparency_log_entry.v1"]
    log_index: conint(ge=1)
    evidence_bundle_id: UUID
    bundle_digest: str
    signer_key_id: str
    appended_at: AwareDatetime
    tree_root_after: str
    inclusion_proof_ref: str | None = None


class HumanOversightEvent(BaseModel):
    """
    Human-in-the-loop oversight event row. Spec AE lines 5494-5508
    (VAL-V2M01-030). oversight_kind is the closed six-member enum
    {pre_action_review, post_action_review, escalation, override,
    manual_classification, content_review} mirrored from the SQL
    CHECK constraint. evidence_refs is a JSON array of evidence-bundle
    / evidence-claim references binding the event to durable evidence;
    defaults to [] so a freshly-created event can be progressively
    enriched before sealing.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.human_oversight_event.v1"]
    oversight_id: UUID
    project_id: UUID
    run_id: UUID | None = None
    ai_system_classification_id: UUID | None = None
    oversight_kind: Literal[
        "pre_action_review",
        "post_action_review",
        "escalation",
        "override",
        "manual_classification",
        "content_review",
    ]
    actor_user_id: UUID | None = None
    decision: str | None = None
    rationale: str | None = None
    evidence_refs: list[Any] | None = []
    occurred_at: AwareDatetime


class DataQualityCheck(BaseModel):
    """
    Per-dataset data-quality check row. Spec AE lines 5510-5525
    (VAL-V2M01-031). check_kind is the closed seven-member enum
    {lineage, representativeness, duplicate_detection,
    schema_conformance, pii_minimization, licensing, staleness} and
    outcome is the closed five-member enum {pass, fail, warn,
    skipped, error}; both mirrored from the SQL CHECK constraints.
    evaluator canonical forms are 'code:<module>.<fn>:vN' or
    'human:<user_id>'; the wire-format layer does not lock the
    evaluator grammar.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.data_quality_check.v1"]
    data_quality_check_id: UUID
    project_id: UUID
    dataset_id: UUID | None = None
    check_kind: Literal[
        "lineage",
        "representativeness",
        "duplicate_detection",
        "schema_conformance",
        "pii_minimization",
        "licensing",
        "staleness",
    ]
    check_name: str
    inputs_ref: str | None = None
    outcome: Literal["pass", "fail", "warn", "skipped", "error"]
    metric_value: float | None = None
    threshold_value: float | None = None
    evaluator: str
    evidence_refs: list[Any] | None = []
    performed_at: AwareDatetime


class DataProvenanceRecord(BaseModel):
    """
    Per-dataset data-provenance row. Spec AE lines 5527-5539
    (VAL-V2M01-032). source_kind is the closed six-member enum
    {first_party, licensed, public_domain, web_scrape, synthetic,
    user_generated} mirrored from the SQL CHECK constraint.
    license_ref is the canonical license identifier (SPDX expression
    preferred, e.g. 'Apache-2.0' / 'CC-BY-4.0') or a customer
    license-registry URI; the wire-format layer does not lock the
    grammar.

    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_version: Literal["relay.data_provenance_record.v1"]
    provenance_id: UUID
    project_id: UUID
    dataset_id: UUID
    source_kind: Literal[
        "first_party",
        "licensed",
        "public_domain",
        "web_scrape",
        "synthetic",
        "user_generated",
    ]
    license_ref: str | None = None
    acquired_at: AwareDatetime | None = None
    acquired_by_user_id: UUID | None = None
    notes: str | None = None
    evidence_refs: list[Any] | None = []


class ScopeState(
    RootModel[
        RunScopeState
        | ReplayCaseScopeState
        | GateRoundScopeState
        | EvidenceBundleScopeState
        | EvalRunScopeState
        | ReleaseScopeState
    ]
):
    root: (
        RunScopeState
        | ReplayCaseScopeState
        | GateRoundScopeState
        | EvidenceBundleScopeState
        | EvalRunScopeState
        | ReleaseScopeState
    ) = Field(
        ...,
        description="Mutable scope state per (scope_kind, scope_id). Discriminated union\non scope_kind so each kind's allowed state set (spec C.1, spec AM,\nspec Q.2) is statically enforced at the wire-format layer. Spec W\nlines 5072-5085 enumerate all six scope_kind values; eval_run and\nrelease land in milestone M01 feature w1.7 (VAL-V2M01-036).\n",
        discriminator="scope_kind",
    )
