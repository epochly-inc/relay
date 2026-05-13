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
    A.1  run_results         (RunResult)
    A.2  gate_decisions      (GateDecision)
    A.3  gate_decision_drafts (GateDecisionDraft)
    A.4  gate_rounds         (GateRound)
    A.9  manifest_versions   (ManifestVersion)
    A.11 event_log_entries   (EventLogEntry)
    A.12 idempotency_records (IdempotencyRecord)
    B.2  idempotency ULID grammar
    B.6  ULID alphabet ^[0-9A-HJKMNP-TV-Z]{26}$
    B.7  schema versioning rules
    C.1  per-scope-kind state sets
    C.4  scope_state.epoch aggregate version
    C.5  three-anchor handoff (Actor identity registry)
    W    scope_state aggregate version table
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

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

# Crockford-base32 ULID grammar per spec B.6 line 3517: 26 chars from
# the alphabet 0-9 + A-H + JKMNP-TV-Z (I, L, O, U excluded). Lowercase
# letters are NOT permitted. Used by IdempotencyRecord.idempotency_key
# (VAL-W1-013).
ULID_PATTERN = r"^[0-9A-HJKMNP-TV-Z]{26}$"

Ulid = Annotated[str, Field(pattern=ULID_PATTERN)]
"""Canonical Crockford-base32 ULID, exactly 26 uppercase chars."""

# RFC 3339 offset-marker regex: matches the trailing 'Z' or '+/-HH:MM' on a
# string. Used by EventLogEntry.occurred_at (VAL-W1-017) to reject naive
# wire-format inputs before Pydantic's datetime coercion silently drops the
# distinction.
_RFC3339_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:\d{2})$")


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
    def _check_accepted_requires_evidence(self) -> RunResult:
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
    def _check_dry_run_constraints(self) -> GateDecisionDraft:
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


# -----------------------------------------------------------------------------
# ManifestVersion (spec A.9; VAL-W1-009, VAL-W1-010)
# -----------------------------------------------------------------------------


class ManifestVersion(_RelayEnvelope):
    """A committed manifest version.

    VAL-W1-009: ``commit_hash`` MUST match the canonical sha256-<hex> wire
                form. The colon form (sha256:<hex>) and bare-hex form are
                rejected.
    VAL-W1-010: ``schema_version`` pinned to ``Literal["relay.manifest.v1"]``.

    The manifest body is modelled as ``dict[str, Any]`` for forward-compat;
    the W1.5 codegen pipeline will replace this with a typed Manifest model
    once the spec F manifest schema is itself generated from this YAML.
    """

    schema_version: Literal["relay.manifest.v1"]
    manifest_version_id: UUID
    manifest_id: UUID
    commit_hash: Sha256Hash
    body: dict[str, Any]
    signed_by: str | None = None
    signature: str | None = None
    signature_key_id: str | None = None
    effective_at: datetime
    effective_until: datetime | None = None


# -----------------------------------------------------------------------------
# ScopeState (spec W; VAL-W1-011, VAL-W1-012, VAL-W1-049)
# -----------------------------------------------------------------------------
#
# Implemented as a discriminated union on ``scope_kind`` so each scope kind's
# allowed state set (spec C.1 lines 3632-3636) is statically enforced at the
# wire-format layer. A document with scope_kind=run carrying state=building
# (an evidence_bundle state) MUST fail validation per VAL-W1-011.


class _ScopeStateBase(_RelayEnvelope):
    """Common fields for every scope_state variant.

    VAL-W1-049: ``schema_version`` literal pin.
    VAL-W1-012: ``epoch`` non-negative bigint; -1 rejected by Field(ge=0).
    """

    schema_version: Literal["relay.scope_state.v1"]
    scope_id: UUID
    project_id: UUID
    epoch: NonNegativeEpoch
    created_at: datetime
    updated_at: datetime


class RunScopeState(_ScopeStateBase):
    """scope_kind='run' (spec C.1: pending -> captured -> validating -> gated
    -> result_written -> terminal)."""

    scope_kind: Literal["run"]
    state: Literal[
        "pending",
        "captured",
        "validating",
        "gated",
        "result_written",
        "terminal",
    ]


class ReplayCaseScopeState(_ScopeStateBase):
    """scope_kind='replay_case' (spec C.1: proposed -> fixtures_ready ->
    executing -> analyzed -> terminal)."""

    scope_kind: Literal["replay_case"]
    state: Literal[
        "proposed",
        "fixtures_ready",
        "executing",
        "analyzed",
        "terminal",
    ]


class GateRoundScopeState(_ScopeStateBase):
    """scope_kind='gate_round' (spec C.1: open -> draft_received -> evaluating
    -> decision_written -> restarted | terminal)."""

    scope_kind: Literal["gate_round"]
    state: Literal[
        "open",
        "draft_received",
        "evaluating",
        "decision_written",
        "restarted",
        "terminal",
    ]


class EvidenceBundleScopeState(_ScopeStateBase):
    """scope_kind='evidence_bundle' (spec C.1: building -> signed -> published
    | superseded | revoked)."""

    scope_kind: Literal["evidence_bundle"]
    state: Literal[
        "building",
        "signed",
        "published",
        "superseded",
        "revoked",
    ]


# Discriminated union (Pydantic v2 ``discriminator='scope_kind'``). The union
# is exposed both as a TypeAlias for callers AND as a ``ScopeState`` class
# wrapper that mirrors the Pydantic ``model_validate`` surface used by the
# tests.
_ScopeStateUnion = Annotated[
    RunScopeState | ReplayCaseScopeState | GateRoundScopeState | EvidenceBundleScopeState,
    Field(discriminator="scope_kind"),
]


class _ScopeStateAdapterMeta(type):
    """Metaclass exposing ``ScopeState.model_validate(payload)`` that dispatches
    through the discriminated union and returns the concrete variant instance.

    Direct ``Union[...]`` types do not carry a ``.model_validate`` classmethod,
    so we wrap the union in a small adapter so the tests can call
    ``ScopeState.model_validate(payload)`` exactly like every other envelope.
    """

    def model_validate(cls, payload: Any) -> _ScopeStateBase:
        from pydantic import TypeAdapter

        adapter: TypeAdapter[_ScopeStateBase] = TypeAdapter(_ScopeStateUnion)
        return adapter.validate_python(payload)


class ScopeState(metaclass=_ScopeStateAdapterMeta):
    """Discriminated-union facade over the four per-scope-kind state models.

    Calling ``ScopeState.model_validate(payload)`` returns the concrete
    variant (RunScopeState / ReplayCaseScopeState / GateRoundScopeState /
    EvidenceBundleScopeState) selected by the ``scope_kind`` field per
    VAL-W1-011.
    """


# -----------------------------------------------------------------------------
# IdempotencyRecord (spec A.12; VAL-W1-013, VAL-W1-014, VAL-W1-050)
# -----------------------------------------------------------------------------


class IdempotencyRecord(_RelayEnvelope):
    """Request dedupe record.

    VAL-W1-013: ``idempotency_key`` matches the Crockford-base32 ULID grammar
                ``^[0-9A-HJKMNP-TV-Z]{26}$``.
    VAL-W1-014: ``request_digest`` matches the canonical sha256-<hex> form
                (inherited from VAL-W1-009).
    VAL-W1-050: ``schema_version`` literal pin.
    """

    schema_version: Literal["relay.idempotency_record.v1"]
    idempotency_key: Ulid
    project_id: UUID
    request_digest: Sha256Hash
    response_status: NonNegativeEpoch
    response_ref: str | None = None
    first_seen_at: datetime
    expires_at: datetime


# -----------------------------------------------------------------------------
# EventLogEntry (spec A.11; VAL-W1-015, VAL-W1-016, VAL-W1-017, VAL-W1-051)
# -----------------------------------------------------------------------------


class EventLogEntry(_RelayEnvelope):
    """Append-only audit-trail row.

    VAL-W1-015: ``scope_type`` closed enum.
    VAL-W1-016: ``actor_kind`` closed enum.
    VAL-W1-017: ``occurred_at`` is RFC 3339 with a required timezone offset.
                Naive timestamps (no Z, no +/-HH:MM) MUST fail validation.
                The original input string is preserved verbatim on a private
                ``_occurred_at_raw`` attribute so the canonical serializer
                (``serialize_event_log_entry_canonical``) can emit it
                byte-for-byte for the cross-language round-trip fixture.
    VAL-W1-051: ``schema_version`` literal pin.
    """

    schema_version: Literal["relay.event_log_entry.v1"]
    event_id: UUID
    project_id: UUID
    scope_type: Literal[
        "run",
        "replay",
        "gate",
        "eval_run",
        "release",
        "manifest",
        "key",
        "other",
    ]
    scope_id: UUID
    event_type: str
    actor_kind: Literal[
        "control_plane",
        "gate_engine",
        "worker",
        "sdk",
        "user",
        "cron",
    ]
    actor_id: UUID | None = None
    manifest_commit_hash: Sha256Hash | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime
    ingest_sequence: NonNegativeEpoch

    # Private sidecar storing the original wire-format string for occurred_at
    # so the canonical serializer can emit the offset byte-for-byte. Populated
    # by the wrap-mode model_validator below from the raw input. Not a
    # model field (no extra_forbidden interaction); declared via PrivateAttr.
    _occurred_at_raw: str | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def _check_occurred_at_offset_required(cls, data: Any) -> Any:
        # VAL-W1-017: when occurred_at is a string, reject naive forms here
        # BEFORE Pydantic's datetime coercion silently produces a tz-naive
        # datetime. Field-level mode='after' check below catches direct
        # datetime objects that lack tzinfo.
        if isinstance(data, dict):
            raw = data.get("occurred_at")
            if isinstance(raw, str) and _RFC3339_OFFSET_RE.search(raw) is None:
                raise ValueError(
                    "occurred_at: naive RFC 3339 timestamp rejected; wire "
                    "form MUST carry a timezone offset (Z or +/-HH:MM) per "
                    f"VAL-W1-017 (observed={raw!r})"
                )
        return data

    @field_validator("occurred_at", mode="after")
    @classmethod
    def _occurred_at_requires_tzinfo(cls, value: datetime) -> datetime:
        # VAL-W1-017: a naive ``datetime`` object passed in directly bypasses
        # the string regex above; assert tzinfo is non-None here.
        if value.tzinfo is None:
            raise ValueError(
                "occurred_at: timezone-naive datetime rejected; tzinfo MUST "
                "be set per VAL-W1-017"
            )
        return value

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> EventLogEntry:
        # Override to capture the raw occurred_at string on the validated
        # instance. Pydantic's default model_validate does not expose a
        # raw-input hook compatible with PrivateAttr population, so we
        # intercept here, run the parent validator, then stash the raw.
        raw_occurred_at: str | None = None
        if isinstance(obj, dict):
            candidate = obj.get("occurred_at")
            if isinstance(candidate, str):
                raw_occurred_at = candidate
        instance = super().model_validate(
            obj,
            strict=strict,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )
        if raw_occurred_at is not None:
            instance._occurred_at_raw = raw_occurred_at
        return instance


def serialize_event_log_entry_canonical(entry: EventLogEntry) -> bytes:
    """Canonical JSON byte serialization for cross-language round-trip.

    Produces the byte stream that both the Python and TypeScript canonical
    serializers MUST agree on (VAL-W1-017 evidence). Rules:

    1. Sort keys lexicographically (``sort_keys=True``).
    2. Use compact separators ``(",", ":")`` (no extra whitespace).
    3. UUID fields rendered as canonical 8-4-4-4-12 lowercase-hex strings.
    4. ``occurred_at`` rendered as the captured original wire-format string
       (``_occurred_at_raw``) preserving the timezone offset byte-for-byte.
    5. Output encoded as UTF-8 bytes.

    The TS canonical serializer in envelopes.ts mirrors these rules so the
    same fixture produces an identical SHA-256 digest in both languages.
    """
    if entry._occurred_at_raw is None:
        # The model was constructed from a datetime object rather than a
        # string. Fall back to isoformat with the offset preserved; the
        # round-trip in this path is best-effort because the original
        # wire-format string was not supplied.
        occurred_at_str = entry.occurred_at.isoformat()
    else:
        occurred_at_str = entry._occurred_at_raw

    canonical: dict[str, Any] = {
        "schema_version": entry.schema_version,
        "event_id": str(entry.event_id),
        "project_id": str(entry.project_id),
        "scope_type": entry.scope_type,
        "scope_id": str(entry.scope_id),
        "event_type": entry.event_type,
        "actor_kind": entry.actor_kind,
        "actor_id": str(entry.actor_id) if entry.actor_id is not None else None,
        "manifest_commit_hash": entry.manifest_commit_hash,
        "payload": entry.payload,
        "occurred_at": occurred_at_str,
        "ingest_sequence": entry.ingest_sequence,
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = [
    "Actor",
    "EventLogEntry",
    "EvidenceBundleScopeState",
    "GateDecision",
    "GateDecisionDraft",
    "GateRound",
    "GateRoundScopeState",
    "IdempotencyRecord",
    "ManifestVersion",
    "ReplayCaseScopeState",
    "RunResult",
    "RunScopeState",
    "ScopeState",
    "Sha256Hash",
    "SHA256_HASH_PATTERN",
    "ULID_PATTERN",
    "Ulid",
    "serialize_event_log_entry_canonical",
]
