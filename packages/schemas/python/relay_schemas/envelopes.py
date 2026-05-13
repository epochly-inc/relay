"""Generated Pydantic v2 models for the Relay control-plane envelopes.

Source of truth: ``packages/schemas/raw/envelopes.yaml``.

This module is hand-authored to match the canonical YAML; the W1.5 codegen
pipeline (datamodel-code-generator) will replace the hand-authoring with
generator output, and the W1.5 drift check (VAL-W1-035) will enforce sync.

Per CLAUDE.md keystone invariant #1, the canonical Literal pins on
``written_by`` and ``decided_by`` enforce the control-plane-writes-the-result
rule at the wire-format layer in addition to SQL CHECK constraints.

Per CLAUDE.md keystone invariant #10, every canonical envelope carries a
``schema_version`` field pinned to a string literal. Engines refuse unknown
versions on write.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

Spec anchors:
    A.1 run_results         (RunResult)
    A.2 gate_decisions      (GateDecision)
    A.3 gate_decision_drafts (GateDecisionDraft)
    A.4 gate_rounds         (GateRound)
    C.5 three-anchor handoff (Actor identity registry)
    B.7 schema versioning rules
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

# -----------------------------------------------------------------------------
# Shared type aliases
# -----------------------------------------------------------------------------
#
# The canonical Relay sha256 wire format is ``sha256-<64 lowercase hex>``
# (hyphen separator, lowercase hex, exactly 64 hex chars). The colon form
# (``sha256:<hex>``) and the bare-hex form are both rejected (VAL-W1-009).

SHA256_HASH_PATTERN = r"^sha256-[0-9a-f]{64}$"

Sha256Hash = Annotated[str, Field(pattern=SHA256_HASH_PATTERN)]
"""Canonical Relay sha256 wire form: ``sha256-`` + 64 lowercase hex chars."""

PositiveRound = Annotated[int, Field(ge=1)]
"""Round counter, >= 1 (spec A.2 ``check (round >= 1)``)."""

NonNegativeEpoch = Annotated[int, Field(ge=0)]
"""Decision epoch, >= 0 (spec A.1 / VAL-W1-059)."""


# -----------------------------------------------------------------------------
# Base configuration
# -----------------------------------------------------------------------------


class _RelayEnvelope(BaseModel):
    """Base for every canonical control-plane envelope.

    ``extra="forbid"`` rejects unknown fields at construction time so a
    typo in client code surfaces as a ValidationError rather than silently
    dropping data. ``frozen=False`` is intentional: the SQL layer enforces
    immutability of canonical rows post-insert; the wire-format model is
    used both for outbound serialization and for inbound parsing where
    field-by-field assignment is sometimes needed during deserialization.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=False,
        validate_assignment=False,
    )


# -----------------------------------------------------------------------------
# RunResult (spec A.1)
# -----------------------------------------------------------------------------


class RunResult(_RelayEnvelope):
    """Canonical run outcome. Written exclusively by the control plane.

    VAL-W1-001: schema_version pinned to ``relay.run_result.v1``.
    VAL-W1-002: written_by pinned to ``Literal["control_plane"]``.
    VAL-W1-003: status closed enum {accepted, remediate_required, blocked, invalid};
                accepted requires non-null evidence_bundle_id.
    """

    schema_version: Literal["relay.run_result.v1"]
    run_result_id: UUID
    run_id: UUID
    project_id: UUID
    written_by: Literal["control_plane"]
    status: Literal["accepted", "remediate_required", "blocked", "invalid"]
    primary_failure_class: str | None = None
    error_priority_rule: str = "first_p0_then_highest_severity_then_earliest_span"
    evidence_bundle_id: UUID | None = None
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    decided_at: datetime
    decision_epoch: NonNegativeEpoch = 0
    signature: str
    signature_key_id: str

    @model_validator(mode="after")
    def _check_accepted_requires_evidence(self) -> "RunResult":
        # VAL-W1-003: mirrors SQL constraint accepted_requires_evidence.
        # An accepted RunResult MUST bind to an evidence_bundle_id.
        if self.status == "accepted" and self.evidence_bundle_id is None:
            raise ValueError(
                "accepted_requires_evidence: status='accepted' requires "
                "evidence_bundle_id to be non-null (field=evidence_bundle_id)"
            )
        return self


# -----------------------------------------------------------------------------
# GateDecision (spec A.2)
# -----------------------------------------------------------------------------


class GateDecision(_RelayEnvelope):
    """Canonical gate decision. Written exclusively by the gate engine.

    VAL-W1-046: schema_version pinned to ``relay.gate_decision.v1``.
    VAL-W1-004: action closed enum; decided_by pinned to ``Literal["gate_engine"]``.
    VAL-W1-005: round int >= 1; failed_assertion_ids list[str] default [].
    VAL-W1-059: decision_epoch optional int >= 0 default 0; accepted as
                int | None and coerced to 0 on None per the contract evidence.
    """

    schema_version: Literal["relay.gate_decision.v1"]
    gate_decision_id: UUID
    gate_id: UUID
    scope_type: Literal["run", "replay", "eval_run", "release", "domain_pack"]
    scope_id: UUID
    round: PositiveRound
    action: Literal["accept", "remediate", "block", "invalid"]
    strict_pass: bool = False
    failed_assertion_ids: list[str] = Field(default_factory=list)
    unmet_conditions: list[Any] = Field(default_factory=list)
    evidence_bundle_id: UUID
    cascade_on_block: bool = True
    decided_by: Literal["gate_engine"]
    decided_at: datetime
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    signature: str
    signature_key_id: str
    decision_epoch: NonNegativeEpoch | None = 0

    @model_validator(mode="before")
    @classmethod
    def _coerce_decision_epoch_none_to_zero(cls, data: Any) -> Any:
        # VAL-W1-059: contract says "field accepted as int | None default 0".
        # Coerce None -> 0 BEFORE field validation so the ge=0 constraint is
        # checked against the coerced integer rather than rejected as a type
        # error.
        if isinstance(data, dict) and data.get("decision_epoch") is None:
            data = {**data, "decision_epoch": 0}
        return data


# -----------------------------------------------------------------------------
# GateDecisionDraft (spec A.3)
# -----------------------------------------------------------------------------


class GateDecisionDraft(_RelayEnvelope):
    """Submitter-facing draft. NOT authoritative.

    VAL-W1-047: schema_version pinned to ``relay.gate_decision_draft.v1``.
    VAL-W1-006: two orthogonal state columns (draft_kind, resolution_state)
                with the cross-field rule ``dry_run_never_resolves``.
    VAL-W1-007: dry_run_unsigned drafts forbid a decision link
                (resolved_gate_decision_id MUST be NULL).
    VAL-W1-058: actor_identity_hash uses the canonical sha256-<hex> pattern
                and is logically a FK to actors(identity_hash). The FK
                constraint itself lives in the SQL migration; the wire-format
                model enforces only the value pattern.
    """

    schema_version: Literal["relay.gate_decision_draft.v1"]
    draft_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: PositiveRound
    release_sha: str | None = None
    eval_run_ids: list[UUID] = Field(default_factory=list)
    evidence_refs: list[Any] = Field(default_factory=list)
    worker_id: UUID
    manifest_commit_hash: Sha256Hash
    actor_identity_hash: Sha256Hash
    submitted_at: datetime
    resolved_gate_decision_id: UUID | None = None
    draft_kind: Literal["submitted", "dry_run_unsigned"] = "submitted"
    resolution_state: Literal[
        "pending",
        "resolved",
        "rejected_handoff",
        "expired",
        "cancelled",
        "duplicate_submission",
    ] = "pending"
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = None

    @model_validator(mode="after")
    def _check_dry_run_constraints(self) -> "GateDecisionDraft":
        # VAL-W1-006: dry_run_never_resolves
        if self.draft_kind == "dry_run_unsigned" and self.resolution_state == "resolved":
            raise ValueError(
                "dry_run_never_resolves: a draft_kind='dry_run_unsigned' draft "
                "cannot have resolution_state='resolved' "
                "(fields: draft_kind, resolution_state)"
            )
        # VAL-W1-007: dry_run_no_decision
        if (
            self.draft_kind == "dry_run_unsigned"
            and self.resolved_gate_decision_id is not None
        ):
            raise ValueError(
                "dry_run_no_decision: a draft_kind='dry_run_unsigned' draft "
                "cannot link a resolved_gate_decision_id "
                "(fields: draft_kind, resolved_gate_decision_id)"
            )
        return self


# -----------------------------------------------------------------------------
# GateRound (spec A.4)
# -----------------------------------------------------------------------------


class GateRound(_RelayEnvelope):
    """Per-round audit trail.

    VAL-W1-048: schema_version pinned to ``relay.gate_round.v1``.
    VAL-W1-008: initiated_by closed enum {control_plane, cron, user, remediation};
                restart_predecessor is a nullable UUID self-reference. NULL on
                the first round; the predecessor gate_round_id on every restart.
    """

    schema_version: Literal["relay.gate_round.v1"]
    gate_round_id: UUID
    gate_id: UUID
    scope_type: str
    scope_id: UUID
    round: PositiveRound
    initiated_at: datetime
    initiated_by: Literal["control_plane", "cron", "user", "remediation"]
    initiation_reason: str | None = None
    gate_decision_id: UUID | None = None
    restart_predecessor: UUID | None = None


# -----------------------------------------------------------------------------
# Actor registry (spec C.5; VAL-W1-058)
# -----------------------------------------------------------------------------


class Actor(_RelayEnvelope):
    """Actor identity registry row.

    FK target for the three-anchor handoff. A handoff whose actor_identity_hash
    is missing from this table OR whose revoked_at is non-null MUST fail with
    HandoffResult(ok=False, reason="ACTOR_NOT_REGISTERED") (contract preamble
    line 912 narrative). The FK enforcement lives in the SQL migration; the
    wire-format model carries the identity_hash pattern and the kind enum.
    """

    identity_hash: Sha256Hash
    kind: Literal["human", "bot", "worker", "reviewer"]
    created_at: datetime
    revoked_at: datetime | None = None


__all__ = [
    "Actor",
    "GateDecision",
    "GateDecisionDraft",
    "GateRound",
    "RunResult",
    "Sha256Hash",
    "SHA256_HASH_PATTERN",
]
