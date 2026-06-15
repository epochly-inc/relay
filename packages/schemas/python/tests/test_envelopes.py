"""W1.1 + W1.2 envelope schema tests.

Covers contract assertions VAL-W1-001 through VAL-W1-008, VAL-W1-009 through
VAL-W1-017, VAL-W1-046, VAL-W1-047, VAL-W1-048, VAL-W1-049, VAL-W1-050,
VAL-W1-051, VAL-W1-058, and VAL-W1-059.

Each test is bound to its assertion via the pytest.mark.fulfills marker so the
gate engine can attribute pass/fail to the assertion's evidence requirement.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from relay_schemas.envelopes import (
    Actor,
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
    ScopeState,
    serialize_event_log_entry_canonical,
    serialize_replay_fixture_canonical,
)
from relay_schemas.error_codes import RelayErrorCode

VALID_ACTOR_HASH = "sha256-" + ("a" * 64)
VALID_MANIFEST_HASH = "sha256-" + ("b" * 64)
VALID_KEY_ID = "key-" + ("c" * 16)
VALID_SIGNATURE = "MEUCIQ" + ("D" * 80)


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _base_run_result(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.run_result.v1",
        "run_result_id": _new_uuid(),
        "run_id": _new_uuid(),
        "project_id": _new_uuid(),
        "written_by": "control_plane",
        "status": "accepted",
        "evidence_bundle_id": _new_uuid(),
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "actor_identity_hash": VALID_ACTOR_HASH,
        "decided_at": "2026-05-12T00:00:00Z",
        "decision_epoch": 0,
        "signature": VALID_SIGNATURE,
        "signature_key_id": VALID_KEY_ID,
        "error_priority_rule": "first_p0_then_highest_severity_then_earliest_span",
    }
    payload.update(overrides)
    return payload


def _base_gate_decision(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.gate_decision.v1",
        "gate_decision_id": _new_uuid(),
        "gate_id": _new_uuid(),
        "scope_type": "run",
        "scope_id": _new_uuid(),
        "round": 1,
        "action": "accept",
        "strict_pass": True,
        "failed_assertion_ids": [],
        "unmet_conditions": [],
        "evidence_bundle_id": _new_uuid(),
        "cascade_on_block": True,
        "decided_by": "gate_engine",
        "decided_at": "2026-05-12T00:00:00Z",
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "actor_identity_hash": VALID_ACTOR_HASH,
        "signature": VALID_SIGNATURE,
        "signature_key_id": VALID_KEY_ID,
    }
    payload.update(overrides)
    return payload


def _base_gate_decision_draft(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.gate_decision_draft.v1",
        "draft_id": _new_uuid(),
        "gate_id": _new_uuid(),
        "scope_type": "run",
        "scope_id": _new_uuid(),
        "round": 1,
        "release_sha": None,
        "eval_run_ids": [],
        "evidence_refs": [],
        "worker_id": _new_uuid(),
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "actor_identity_hash": VALID_ACTOR_HASH,
        "submitted_at": "2026-05-12T00:00:00Z",
        "resolved_gate_decision_id": None,
        "draft_kind": "submitted",
        "resolution_state": "pending",
        "cancelled_at": None,
        "cancellation_reason": None,
    }
    payload.update(overrides)
    return payload


def _base_gate_round(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.gate_round.v1",
        "gate_round_id": _new_uuid(),
        "gate_id": _new_uuid(),
        "scope_type": "run",
        "scope_id": _new_uuid(),
        "round": 1,
        "initiated_at": "2026-05-12T00:00:00Z",
        "initiated_by": "control_plane",
        "initiation_reason": None,
        "gate_decision_id": None,
        "restart_predecessor": None,
    }
    payload.update(overrides)
    return payload


# -----------------------------------------------------------------------------
# VAL-W1-001: run_result requires schema_version "relay.run_result.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-001")
def test_run_result_schema_version_pinned() -> None:
    rr = RunResult.model_validate(_base_run_result())
    assert rr.schema_version == "relay.run_result.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-001")
def test_run_result_rejects_missing_schema_version() -> None:
    payload = _base_run_result()
    del payload["schema_version"]
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-001")
def test_run_result_rejects_wrong_schema_version() -> None:
    payload = _base_run_result(schema_version="relay.run_result.v2")
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-002: run_result.written_by hard-pinned to "control_plane"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-002")
def test_run_result_written_by_pinned_literal() -> None:
    rr = RunResult.model_validate(_base_run_result())
    assert rr.written_by == "control_plane"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-002")
def test_run_result_rejects_non_control_plane_written_by() -> None:
    payload = _base_run_result(written_by="worker")
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    assert "written_by" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-002")
def test_generated_model_file_contains_control_plane_literal() -> None:
    """grep-test: confirm the generated source file pins the literal type.

    Mirrors `grep -c 'Literal["control_plane"]' packages/schemas/python/...`.
    """
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('Literal["control_plane"]') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-003: status closed enum + accepted requires evidence_bundle_id
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-003")
@pytest.mark.parametrize(
    "status",
    ["accepted", "remediate_required", "blocked", "invalid"],
)
def test_run_result_accepts_all_canonical_statuses(status: str) -> None:
    overrides: dict[str, object] = {"status": status}
    if status != "accepted":
        overrides["evidence_bundle_id"] = None
    rr = RunResult.model_validate(_base_run_result(**overrides))
    assert rr.status == status


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-003")
def test_run_result_rejects_fifth_status_value() -> None:
    payload = _base_run_result(status="approved")
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    assert "status" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-003")
def test_run_result_accepted_requires_evidence_bundle_id() -> None:
    payload = _base_run_result(status="accepted", evidence_bundle_id=None)
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    msg = str(excinfo.value)
    assert "evidence_bundle_id" in msg or "accepted_requires_evidence" in msg


# -----------------------------------------------------------------------------
# VAL-W1-004: gate_decision.action closed enum; decided_by pinned literal
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-004")
@pytest.mark.parametrize(
    "action",
    ["accept", "remediate", "block", "invalid"],
)
def test_gate_decision_accepts_all_canonical_actions(action: str) -> None:
    gd = GateDecision.model_validate(_base_gate_decision(action=action))
    assert gd.action == action


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-004")
def test_gate_decision_rejects_invalid_action() -> None:
    payload = _base_gate_decision(action="approve")
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "action" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-004")
def test_gate_decision_decided_by_pinned_literal() -> None:
    gd = GateDecision.model_validate(_base_gate_decision())
    assert gd.decided_by == "gate_engine"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-004")
def test_gate_decision_rejects_non_gate_engine_decided_by() -> None:
    payload = _base_gate_decision(decided_by="worker")
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "decided_by" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-005: gate_decision.round int >= 1; failed_assertion_ids list[str] = []
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-005")
def test_gate_decision_round_accepts_one() -> None:
    gd = GateDecision.model_validate(_base_gate_decision(round=1))
    assert gd.round == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-005")
def test_gate_decision_round_rejects_zero() -> None:
    payload = _base_gate_decision(round=0)
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "round" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-005")
def test_gate_decision_round_rejects_negative() -> None:
    payload = _base_gate_decision(round=-1)
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "round" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-005")
def test_gate_decision_failed_assertion_ids_defaults_to_empty_list() -> None:
    payload = _base_gate_decision()
    del payload["failed_assertion_ids"]
    gd = GateDecision.model_validate(payload)
    assert gd.failed_assertion_ids == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-005")
def test_gate_decision_failed_assertion_ids_typed_list_str() -> None:
    payload = _base_gate_decision(failed_assertion_ids=[123])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        GateDecision.model_validate(payload)


# -----------------------------------------------------------------------------
# VAL-W1-006: two orthogonal state columns + cross-field rule
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-006")
@pytest.mark.parametrize("draft_kind", ["submitted", "dry_run_unsigned"])
def test_draft_kind_accepts_canonical_values(draft_kind: str) -> None:
    payload = _base_gate_decision_draft(draft_kind=draft_kind)
    d = GateDecisionDraft.model_validate(payload)
    assert d.draft_kind == draft_kind


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-006")
def test_draft_kind_rejects_invalid_value() -> None:
    payload = _base_gate_decision_draft(draft_kind="other")
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "draft_kind" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-006")
@pytest.mark.parametrize(
    "resolution_state",
    [
        "pending",
        "resolved",
        "rejected_handoff",
        "expired",
        "cancelled",
        "duplicate_submission",
    ],
)
def test_resolution_state_accepts_all_canonical_values(resolution_state: str) -> None:
    overrides: dict[str, object] = {"resolution_state": resolution_state}
    if resolution_state == "resolved":
        overrides["resolved_gate_decision_id"] = _new_uuid()
    payload = _base_gate_decision_draft(**overrides)
    d = GateDecisionDraft.model_validate(payload)
    assert d.resolution_state == resolution_state


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-006")
def test_resolution_state_rejects_invalid_value() -> None:
    payload = _base_gate_decision_draft(resolution_state="approved")
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "resolution_state" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-006")
def test_dry_run_unsigned_with_resolved_fails_cross_field() -> None:
    payload = _base_gate_decision_draft(
        draft_kind="dry_run_unsigned",
        resolution_state="resolved",
    )
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    msg = str(excinfo.value)
    assert "draft_kind" in msg
    assert "resolution_state" in msg


# -----------------------------------------------------------------------------
# VAL-W1-007: dry-run forbids decision link
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-007")
def test_dry_run_unsigned_with_decision_link_fails() -> None:
    payload = _base_gate_decision_draft(
        draft_kind="dry_run_unsigned",
        resolved_gate_decision_id=_new_uuid(),
    )
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    msg = str(excinfo.value)
    assert "draft_kind" in msg
    assert "resolved_gate_decision_id" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-007")
def test_submitted_draft_can_link_decision() -> None:
    payload = _base_gate_decision_draft(
        draft_kind="submitted",
        resolution_state="resolved",
        resolved_gate_decision_id=_new_uuid(),
    )
    d = GateDecisionDraft.model_validate(payload)
    assert d.resolved_gate_decision_id is not None


# -----------------------------------------------------------------------------
# VAL-W1-008: gate_rounds.initiated_by closed enum + nullable restart_predecessor
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
@pytest.mark.parametrize(
    "initiated_by",
    ["control_plane", "cron", "user", "remediation"],
)
def test_gate_round_initiated_by_canonical(initiated_by: str) -> None:
    gr = GateRound.model_validate(_base_gate_round(initiated_by=initiated_by))
    assert gr.initiated_by == initiated_by


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
def test_gate_round_initiated_by_rejects_invalid() -> None:
    payload = _base_gate_round(initiated_by="orchestrator")
    with pytest.raises(ValidationError) as excinfo:
        GateRound.model_validate(payload)
    assert "initiated_by" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
def test_gate_round_restart_predecessor_nullable() -> None:
    gr = GateRound.model_validate(_base_gate_round(restart_predecessor=None))
    assert gr.restart_predecessor is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
def test_gate_round_restart_predecessor_accepts_uuid() -> None:
    pred = _new_uuid()
    gr = GateRound.model_validate(_base_gate_round(restart_predecessor=pred))
    assert str(gr.restart_predecessor) == pred


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
def test_gate_round_restart_predecessor_rejects_malformed_uuid() -> None:
    payload = _base_gate_round(restart_predecessor="not-a-uuid")
    with pytest.raises(ValidationError) as excinfo:
        GateRound.model_validate(payload)
    assert "restart_predecessor" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-008")
def test_generated_model_file_marks_restart_predecessor_optional() -> None:
    """grep-test: generated source declares restart_predecessor as Optional UUID."""
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    # Either UUID | None or Optional[UUID] form is acceptable.
    has_union = "UUID | None" in text and "restart_predecessor" in text
    has_optional = "Optional[UUID]" in text and "restart_predecessor" in text
    assert has_union or has_optional


# -----------------------------------------------------------------------------
# VAL-W1-046: gate_decision schema_version literal "relay.gate_decision.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-046")
def test_gate_decision_schema_version_pinned() -> None:
    gd = GateDecision.model_validate(_base_gate_decision())
    assert gd.schema_version == "relay.gate_decision.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-046")
def test_gate_decision_rejects_wrong_schema_version() -> None:
    payload = _base_gate_decision(schema_version="relay.gate_decision.v2")
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-046")
def test_generated_file_contains_gate_decision_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.gate_decision.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-047: gate_decision_drafts schema_version literal "relay.gate_decision_draft.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-047")
def test_gate_decision_draft_schema_version_pinned() -> None:
    d = GateDecisionDraft.model_validate(_base_gate_decision_draft())
    assert d.schema_version == "relay.gate_decision_draft.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-047")
def test_gate_decision_draft_rejects_wrong_schema_version() -> None:
    payload = _base_gate_decision_draft(schema_version="relay.gate_decision_draft.v2")
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-047")
def test_generated_file_contains_gate_decision_draft_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.gate_decision_draft.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-048: gate_round schema_version literal "relay.gate_round.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-048")
def test_gate_round_schema_version_pinned() -> None:
    gr = GateRound.model_validate(_base_gate_round())
    assert gr.schema_version == "relay.gate_round.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-048")
def test_gate_round_rejects_wrong_schema_version() -> None:
    payload = _base_gate_round(schema_version="relay.gate_round.v2")
    with pytest.raises(ValidationError) as excinfo:
        GateRound.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-048")
def test_generated_file_contains_gate_round_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.gate_round.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-058: actor_identity_hash sha256-<hex> pattern + actors table FK
# -----------------------------------------------------------------------------


_SHA256_PATTERN = re.compile(r"^sha256-[0-9a-f]{64}$")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_identity_hash_accepts_canonical_form() -> None:
    payload = _base_gate_decision_draft(actor_identity_hash="sha256-" + "f" * 64)
    d = GateDecisionDraft.model_validate(payload)
    assert _SHA256_PATTERN.match(d.actor_identity_hash) is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_identity_hash_rejects_colon_form() -> None:
    payload = _base_gate_decision_draft(actor_identity_hash="sha256:" + "a" * 64)
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "actor_identity_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_identity_hash_rejects_short_hex() -> None:
    payload = _base_gate_decision_draft(actor_identity_hash="sha256-" + "a" * 63)
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "actor_identity_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_identity_hash_rejects_uppercase_hex() -> None:
    payload = _base_gate_decision_draft(actor_identity_hash="sha256-" + "A" * 64)
    with pytest.raises(ValidationError) as excinfo:
        GateDecisionDraft.model_validate(payload)
    assert "actor_identity_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_table_canonical_columns() -> None:
    a = Actor.model_validate(
        {
            "identity_hash": "sha256-" + "0" * 64,
            "kind": "worker",
            "created_at": "2026-05-12T00:00:00Z",
            "revoked_at": None,
        }
    )
    assert a.identity_hash == "sha256-" + "0" * 64
    assert a.kind == "worker"
    assert a.revoked_at is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
@pytest.mark.parametrize("kind", ["human", "bot", "worker", "reviewer"])
def test_actor_kind_accepts_canonical_values(kind: str) -> None:
    a = Actor.model_validate(
        {
            "identity_hash": "sha256-" + "1" * 64,
            "kind": kind,
            "created_at": "2026-05-12T00:00:00Z",
            "revoked_at": None,
        }
    )
    assert a.kind == kind


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_actor_kind_rejects_invalid() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Actor.model_validate(
            {
                "identity_hash": "sha256-" + "2" * 64,
                "kind": "robot",
                "created_at": "2026-05-12T00:00:00Z",
                "revoked_at": None,
            }
        )
    assert "kind" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_generated_sql_declares_actor_fk() -> None:
    """grep-test: SQL migration declares FK from gate_decision_drafts to actors.

    Path math: this test file lives at
    ``packages/schemas/python/tests/test_envelopes.py``; SQL migrations live at
    ``packages/schemas/sql/``. parents[0]=tests, [1]=python, [2]=schemas.
    """
    sql_root = Path(__file__).resolve().parents[2] / "sql"
    found_actors = False
    found_fk = False
    for sql_file in sql_root.glob("*.sql"):
        text = sql_file.read_text(encoding="utf-8")
        lowered = text.lower()
        if "create table actors" in lowered and "identity_hash" in lowered:
            found_actors = True
        if (
            "foreign key" in lowered
            and "actor_identity_hash" in lowered
            and "actors(identity_hash)" in lowered
        ):
            found_fk = True
    assert found_actors, f"No SQL migration declares the actors table under {sql_root}"
    assert found_fk, (
        f"No SQL migration declares FOREIGN KEY (actor_identity_hash) "
        f"REFERENCES actors(identity_hash) under {sql_root}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-058")
def test_generated_python_pins_sha256_pattern() -> None:
    """grep-test: generated Pydantic source uses the canonical sha256-<hex> pattern."""
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    # Either inline or via the SHA256_HASH_PATTERN constant.
    assert "^sha256-[0-9a-f]{64}$" in text


# -----------------------------------------------------------------------------
# VAL-W1-059: gate_decision optional decision_epoch int >= 0 default 0
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-059")
def test_gate_decision_decision_epoch_default_zero() -> None:
    payload = _base_gate_decision()
    gd = GateDecision.model_validate(payload)
    assert gd.decision_epoch == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-059")
def test_gate_decision_decision_epoch_accepts_positive() -> None:
    payload = _base_gate_decision(decision_epoch=42)
    gd = GateDecision.model_validate(payload)
    assert gd.decision_epoch == 42


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-059")
def test_gate_decision_decision_epoch_rejects_negative() -> None:
    payload = _base_gate_decision(decision_epoch=-1)
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "decision_epoch" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-059")
def test_gate_decision_decision_epoch_optional_none_coerces_to_zero() -> None:
    payload = _base_gate_decision(decision_epoch=None)
    gd = GateDecision.model_validate(payload)
    assert gd.decision_epoch == 0


# -----------------------------------------------------------------------------
# Defense-in-depth: extra fields rejected (model_config = ConfigDict(extra="forbid"))
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-001")
def test_run_result_rejects_unknown_field() -> None:
    payload = _base_run_result(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        RunResult.model_validate(payload)
    assert "unknown_field" in str(excinfo.value) or "extra" in str(excinfo.value).lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-046")
def test_gate_decision_rejects_unknown_field() -> None:
    payload = _base_gate_decision(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        GateDecision.model_validate(payload)
    assert "unknown_field" in str(excinfo.value) or "extra" in str(excinfo.value).lower()


# =============================================================================
# W1.2 control-plane envelopes
# =============================================================================
#
# Covers VAL-W1-009 through VAL-W1-017 (canonical wire-form / discriminated
# union / RFC 3339 offset enforcement) plus VAL-W1-049, VAL-W1-050, VAL-W1-051
# (schema_version Literal pins).
#
# Helpers below construct minimally-valid payloads; per-test overrides exercise
# the boundary cases the contract evidence lines name.


VALID_ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
VALID_REQUEST_DIGEST = "sha256-" + ("c" * 64)
VALID_COMMIT_HASH = "sha256-" + ("d" * 64)


def _base_manifest_version(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.manifest.v1",
        "manifest_version_id": _new_uuid(),
        "manifest_id": _new_uuid(),
        "commit_hash": VALID_COMMIT_HASH,
        "body": {"manifest_schema": "relay.manifest.v1"},
        "signed_by": None,
        "signature": None,
        "signature_key_id": None,
        "effective_at": "2026-05-12T00:00:00+00:00",
        "effective_until": None,
    }
    payload.update(overrides)
    return payload


def _base_scope_state_run(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.scope_state.v1",
        "scope_kind": "run",
        "scope_id": _new_uuid(),
        "project_id": _new_uuid(),
        "state": "pending",
        "epoch": 0,
        "created_at": "2026-05-12T00:00:00+00:00",
        "updated_at": "2026-05-12T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _base_scope_state_replay_case(**overrides: object) -> dict[str, object]:
    p = _base_scope_state_run()
    p["scope_kind"] = "replay_case"
    p["state"] = "proposed"
    p.update(overrides)
    return p


def _base_scope_state_gate_round(**overrides: object) -> dict[str, object]:
    p = _base_scope_state_run()
    p["scope_kind"] = "gate_round"
    p["state"] = "open"
    p.update(overrides)
    return p


def _base_scope_state_evidence_bundle(**overrides: object) -> dict[str, object]:
    p = _base_scope_state_run()
    p["scope_kind"] = "evidence_bundle"
    p["state"] = "building"
    p.update(overrides)
    return p


def _base_idempotency_record(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.idempotency_record.v1",
        "idempotency_key": VALID_ULID,
        "project_id": _new_uuid(),
        "request_digest": VALID_REQUEST_DIGEST,
        "response_status": 200,
        "response_ref": None,
        "first_seen_at": "2026-05-12T00:00:00+00:00",
        "expires_at": "2026-05-13T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _base_event_log_entry(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.event_log_entry.v1",
        "event_id": _new_uuid(),
        "project_id": _new_uuid(),
        "scope_type": "run",
        "scope_id": _new_uuid(),
        "event_type": "run.captured",
        "actor_kind": "control_plane",
        "actor_id": None,
        "manifest_commit_hash": None,
        "payload": {},
        "occurred_at": "2026-05-12T00:00:00+00:00",
        "ingest_sequence": 1,
    }
    payload.update(overrides)
    return payload


# -----------------------------------------------------------------------------
# VAL-W1-009: manifest_versions.commit_hash canonical sha256-<hex> wire form
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_manifest_version_accepts_canonical_commit_hash() -> None:
    mv = ManifestVersion.model_validate(_base_manifest_version())
    assert mv.commit_hash == VALID_COMMIT_HASH


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_manifest_version_rejects_colon_form() -> None:
    payload = _base_manifest_version(commit_hash="sha256:" + ("a" * 64))
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert "commit_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_manifest_version_rejects_bare_hex() -> None:
    payload = _base_manifest_version(commit_hash="a" * 64)
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert "commit_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_manifest_version_rejects_63_char_hex() -> None:
    payload = _base_manifest_version(commit_hash="sha256-" + ("a" * 63))
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert "commit_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_manifest_version_rejects_64_char_non_hex() -> None:
    # Replace one hex char with a non-hex letter ('g').
    payload = _base_manifest_version(commit_hash="sha256-" + "g" + ("a" * 63))
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert "commit_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_raw_yaml_does_not_contain_colon_form_sha256() -> None:
    """grep-test: canonical YAML must not use the rejected sha256:<hex> form."""
    raw_dir = Path(__file__).resolve().parents[2] / "raw"
    colon_pat = re.compile(r"sha256:[0-9a-f]{64}")
    for yaml_file in raw_dir.glob("*.yaml"):
        text = yaml_file.read_text(encoding="utf-8")
        assert colon_pat.search(text) is None, (
            f"{yaml_file.name} contains the rejected sha256:<hex> colon form"
        )


# -----------------------------------------------------------------------------
# VAL-W1-010: manifest_versions.schema_version literal "relay.manifest.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-010")
def test_manifest_version_schema_version_pinned() -> None:
    mv = ManifestVersion.model_validate(_base_manifest_version())
    assert mv.schema_version == "relay.manifest.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-010")
def test_manifest_version_rejects_wrong_schema_version() -> None:
    payload = _base_manifest_version(schema_version="relay.manifest.v2")
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-010")
def test_generated_python_contains_manifest_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.manifest.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-011: scope_state.state is a per-scope-kind enumeration (discriminated)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
@pytest.mark.parametrize(
    "state",
    ["pending", "captured", "validating", "gated", "result_written", "terminal"],
)
def test_scope_state_run_accepts_all_canonical_states(state: str) -> None:
    s = ScopeState.model_validate(_base_scope_state_run(state=state))
    assert s.state == state
    assert s.scope_kind == "run"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
@pytest.mark.parametrize(
    "state",
    ["proposed", "fixtures_ready", "executing", "analyzed", "terminal"],
)
def test_scope_state_replay_case_accepts_all_canonical_states(state: str) -> None:
    s = ScopeState.model_validate(_base_scope_state_replay_case(state=state))
    assert s.state == state
    assert s.scope_kind == "replay_case"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
@pytest.mark.parametrize(
    "state",
    [
        "open",
        "draft_received",
        "evaluating",
        "decision_written",
        "restarted",
        "terminal",
    ],
)
def test_scope_state_gate_round_accepts_all_canonical_states(state: str) -> None:
    s = ScopeState.model_validate(_base_scope_state_gate_round(state=state))
    assert s.state == state
    assert s.scope_kind == "gate_round"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
@pytest.mark.parametrize(
    "state",
    ["building", "signed", "published", "superseded", "revoked"],
)
def test_scope_state_evidence_bundle_accepts_all_canonical_states(state: str) -> None:
    s = ScopeState.model_validate(_base_scope_state_evidence_bundle(state=state))
    assert s.state == state
    assert s.scope_kind == "evidence_bundle"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
def test_scope_state_rejects_cross_tag_state_run_with_building() -> None:
    """A scope_kind=run document with state=building (an evidence_bundle state)
    MUST fail validation per VAL-W1-011 narrative."""
    payload = _base_scope_state_run(state="building")
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    msg = str(excinfo.value)
    assert "state" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
def test_scope_state_rejects_cross_tag_evidence_bundle_with_run_state() -> None:
    """A scope_kind=evidence_bundle document with state=pending (a run state)
    MUST fail validation."""
    payload = _base_scope_state_evidence_bundle(state="pending")
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    assert "state" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-011")
def test_scope_state_rejects_unknown_scope_kind() -> None:
    payload = _base_scope_state_run(scope_kind="orchestrator")
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    assert "scope_kind" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-012: scope_state.epoch is monotonic non-negative bigint
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-012")
def test_scope_state_epoch_accepts_zero() -> None:
    s = ScopeState.model_validate(_base_scope_state_run(epoch=0))
    assert s.epoch == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-012")
def test_scope_state_epoch_accepts_large_bigint() -> None:
    # 2**62 fits a bigint and tests we didn't accidentally constrain to int32.
    big = 2**62
    s = ScopeState.model_validate(_base_scope_state_run(epoch=big))
    assert s.epoch == big


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-012")
def test_scope_state_epoch_rejects_negative_one() -> None:
    payload = _base_scope_state_run(epoch=-1)
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    assert "epoch" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-013: idempotency_records.idempotency_key matches ULID grammar
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-013")
def test_idempotency_record_accepts_canonical_ulid() -> None:
    ir = IdempotencyRecord.model_validate(_base_idempotency_record())
    assert ir.idempotency_key == VALID_ULID


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-013")
def test_idempotency_record_rejects_25_char_key() -> None:
    payload = _base_idempotency_record(idempotency_key=VALID_ULID[:25])
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "idempotency_key" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-013")
def test_idempotency_record_rejects_lowercase_base32() -> None:
    payload = _base_idempotency_record(idempotency_key="01arz3ndektsv4rrffq69g5fav")
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "idempotency_key" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-013")
def test_idempotency_record_rejects_excluded_letter_I() -> None:
    """The Crockford base32 alphabet excludes I, L, O, U. 'I' in position 0
    must fail validation."""
    payload = _base_idempotency_record(idempotency_key="I" + VALID_ULID[1:])
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "idempotency_key" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-013")
def test_idempotency_record_rejects_27_char_key() -> None:
    payload = _base_idempotency_record(idempotency_key=VALID_ULID + "Z")
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "idempotency_key" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-014: idempotency_records.request_digest canonical sha256-<hex> form
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-014")
def test_idempotency_record_accepts_canonical_request_digest() -> None:
    ir = IdempotencyRecord.model_validate(_base_idempotency_record())
    assert ir.request_digest == VALID_REQUEST_DIGEST


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-014")
def test_idempotency_record_rejects_colon_form_request_digest() -> None:
    payload = _base_idempotency_record(request_digest="sha256:" + ("a" * 64))
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "request_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-014")
def test_idempotency_record_rejects_short_request_digest() -> None:
    payload = _base_idempotency_record(request_digest="sha256-" + ("a" * 63))
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "request_digest" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-015: event_log_entries.scope_type closed enum
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-015")
@pytest.mark.parametrize(
    "scope_type",
    ["run", "replay", "gate", "eval_run", "release", "manifest", "key", "other"],
)
def test_event_log_entry_scope_type_accepts_all_canonical_values(
    scope_type: str,
) -> None:
    e = EventLogEntry.model_validate(_base_event_log_entry(scope_type=scope_type))
    assert e.scope_type == scope_type


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-015")
def test_event_log_entry_scope_type_rejects_unknown_value() -> None:
    payload = _base_event_log_entry(scope_type="unknown_kind")
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert "scope_type" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-016: event_log_entries.actor_kind closed enum
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-016")
@pytest.mark.parametrize(
    "actor_kind",
    ["control_plane", "gate_engine", "worker", "sdk", "user", "cron"],
)
def test_event_log_entry_actor_kind_accepts_all_canonical_values(
    actor_kind: str,
) -> None:
    e = EventLogEntry.model_validate(_base_event_log_entry(actor_kind=actor_kind))
    assert e.actor_kind == actor_kind


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-016")
def test_event_log_entry_actor_kind_rejects_unknown_value() -> None:
    payload = _base_event_log_entry(actor_kind="orchestrator")
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert "actor_kind" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-017: event_log_entries.occurred_at is RFC 3339 with timezone offset
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_accepts_utc_z_form() -> None:
    payload = _base_event_log_entry(occurred_at="2026-05-12T00:00:00Z")
    e = EventLogEntry.model_validate(payload)
    assert e.occurred_at.tzinfo is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_accepts_positive_offset() -> None:
    payload = _base_event_log_entry(occurred_at="2026-05-12T10:00:00+05:30")
    e = EventLogEntry.model_validate(payload)
    assert e.occurred_at.tzinfo is not None
    assert e.occurred_at.utcoffset() == timedelta(hours=5, minutes=30)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_accepts_negative_offset() -> None:
    payload = _base_event_log_entry(occurred_at="2026-05-12T00:00:00-08:00")
    e = EventLogEntry.model_validate(payload)
    assert e.occurred_at.utcoffset() == timedelta(hours=-8)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_rejects_naive_string() -> None:
    payload = _base_event_log_entry(occurred_at="2026-05-12T00:00:00")
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert "occurred_at" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_rejects_naive_datetime_object() -> None:
    payload = _base_event_log_entry(occurred_at=datetime(2026, 5, 12, 0, 0, 0))
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert "occurred_at" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_occurred_at_round_trip_preserves_offset() -> None:
    """Round-trip preserves the offset character-by-character through
    serialize_event_log_entry_canonical."""
    for original_offset_str in [
        "2026-05-12T10:00:00+05:30",
        "2026-05-12T10:00:00-08:00",
        "2026-05-12T10:00:00+00:00",
    ]:
        payload = _base_event_log_entry(occurred_at=original_offset_str)
        e = EventLogEntry.model_validate(payload)
        # serialize_event_log_entry_canonical returns a bytes blob in canonical
        # JSON form (sorted keys, no whitespace, occurred_at preserved verbatim).
        blob = serialize_event_log_entry_canonical(e)
        decoded = json.loads(blob.decode("utf-8"))
        assert decoded["occurred_at"] == original_offset_str


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_event_log_entry_cross_language_digest_fixture() -> None:
    """Cross-language byte-equal round-trip fixture.

    The fixture file packages/schemas/python/tests/fixtures/event_log_entry.json
    is the canonical wire-form bytes. We assert:
      1. Python parses it into an EventLogEntry with tzinfo preserved.
      2. Re-serializing via serialize_event_log_entry_canonical produces
         BYTES whose SHA-256 matches the fixture's recorded digest.
    The TS test (envelopes.test.ts) reads the SAME fixture and asserts the
    SAME digest. Byte-equal Py and TS canonicalization = VAL-W1-017 evidence.
    """
    fixture_dir = Path(__file__).parent / "fixtures"
    fixture_file = fixture_dir / "event_log_entry.json"
    digest_file = fixture_dir / "event_log_entry.sha256"

    raw = fixture_file.read_bytes()
    payload = json.loads(raw.decode("utf-8"))

    e = EventLogEntry.model_validate(payload)
    assert e.occurred_at.tzinfo is not None

    canonical = serialize_event_log_entry_canonical(e)
    actual_digest = "sha256-" + hashlib.sha256(canonical).hexdigest()
    expected_digest = digest_file.read_text(encoding="utf-8").strip()
    assert actual_digest == expected_digest, (
        f"Cross-language fixture digest mismatch. expected={expected_digest} "
        f"actual={actual_digest}"
    )


# -----------------------------------------------------------------------------
# VAL-W1-049: scope_state schema_version literal "relay.scope_state.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-049")
def test_scope_state_schema_version_pinned() -> None:
    s = ScopeState.model_validate(_base_scope_state_run())
    assert s.schema_version == "relay.scope_state.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-049")
def test_scope_state_rejects_wrong_schema_version() -> None:
    payload = _base_scope_state_run(schema_version="relay.scope_state.v2")
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-049")
def test_generated_python_contains_scope_state_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.scope_state.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-050: idempotency_records schema_version literal
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-050")
def test_idempotency_record_schema_version_pinned() -> None:
    ir = IdempotencyRecord.model_validate(_base_idempotency_record())
    assert ir.schema_version == "relay.idempotency_record.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-050")
def test_idempotency_record_rejects_wrong_schema_version() -> None:
    payload = _base_idempotency_record(schema_version="relay.idempotency_record.v2")
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-050")
def test_generated_python_contains_idempotency_record_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.idempotency_record.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-051: event_log_entries schema_version literal
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-051")
def test_event_log_entry_schema_version_pinned() -> None:
    e = EventLogEntry.model_validate(_base_event_log_entry())
    assert e.schema_version == "relay.event_log_entry.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-051")
def test_event_log_entry_rejects_wrong_schema_version() -> None:
    payload = _base_event_log_entry(schema_version="relay.event_log_entry.v2")
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-051")
def test_generated_python_contains_event_log_entry_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.event_log_entry.v1"') >= 1


# -----------------------------------------------------------------------------
# Defense in depth: extra-field rejection on the W1.2 envelopes
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-010")
def test_manifest_version_rejects_unknown_field() -> None:
    payload = _base_manifest_version(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        ManifestVersion.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-049")
def test_scope_state_rejects_unknown_field() -> None:
    payload = _base_scope_state_run(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        ScopeState.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-050")
def test_idempotency_record_rejects_unknown_field() -> None:
    payload = _base_idempotency_record(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        IdempotencyRecord.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-051")
def test_event_log_entry_rejects_unknown_field() -> None:
    payload = _base_event_log_entry(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        EventLogEntry.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


# =============================================================================
# W1.3 evidence + replay envelopes
# =============================================================================
#
# Covers VAL-W1-018 through VAL-W1-025 (field-level constraints) and
# VAL-W1-052 through VAL-W1-055 (schema_version literal pins). Helpers
# below construct minimally-valid payloads; per-test overrides exercise
# the boundary cases the contract evidence lines name.


VALID_BUNDLE_DIGEST = "sha256-" + ("e" * 64)
VALID_CLAIM_DIGEST = "sha256-" + ("f" * 64)
VALID_INPUT_DIGEST = "sha256-" + ("1" * 64)
VALID_OUTPUT_DIGEST = "sha256-" + ("2" * 64)
VALID_INPUTS_DIGEST = "sha256-" + ("3" * 64)
VALID_FAILURE_SIG = "sha256-" + ("4" * 64)


def _base_evidence_bundle(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.evidence_bundle.v1",
        "evidence_bundle_id": _new_uuid(),
        "org_id": _new_uuid(),
        "project_id": _new_uuid(),
        "scope_type": "run",
        "scope_id": _new_uuid(),
        "bundle_digest": VALID_BUNDLE_DIGEST,
        "acef_core_version": "0.1.0",
        "relay_extension_version": "0.1.0",
        "signing_key_id": "key-evidence-001",
        "signature_algorithm": "ES256",
        "verification_status": "unverified",
        "redaction_policy_version": "relay.redaction.v1#default",
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "object_ref": "r2://evidence/00000000-0000-4000-8000-000000000001",
        "supersedes_bundle_id": None,
        "created_at": "2026-05-12T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _base_evidence_claim(**overrides: object) -> dict[str, object]:
    # V3M1-F05 (2026-05-18): spec K shape added 3 required fields
    # (actor_kind, actor_identity_hash, occurred_at) and restructured the
    # subject to a nested object. The flat subject_kind / subject_id keys
    # below ride the back-compat mode='before' validator absorption shim
    # in EvidenceClaim per VAL-V3M1-015, so this fixture stays minimal.
    payload: dict[str, object] = {
        "schema_version": "relay.evidence_claim.v1",
        "evidence_claim_id": _new_uuid(),
        "evidence_bundle_id": _new_uuid(),
        "claim_type": "run_result",
        "subject_kind": "run",
        "subject_id": _new_uuid(),
        "claim_digest": VALID_CLAIM_DIGEST,
        "redaction_transform_version": "relay.redaction.v1#transform-001",
        "actor_kind": "control_plane",
        "actor_identity_hash": VALID_ACTOR_HASH,
        "occurred_at": "2026-05-12T00:00:00+00:00",
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "signer_key_id": "key-claim-001",
        "signature": VALID_SIGNATURE,
        "supersedes_claim_id": None,
        "created_at": "2026-05-12T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _base_replay_case(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.replay_case.v1",
        "replay_case_id": _new_uuid(),
        "project_id": _new_uuid(),
        "source_run_id": _new_uuid(),
        "failure_signature_hash": VALID_FAILURE_SIG,
        "inputs_ref": "r2://replay/inputs/00000000-0000-4000-8000-000000000002",
        "inputs_digest": VALID_INPUTS_DIGEST,
        "expected_assertion_ids": [],
        "human_reviewed": False,
        "reviewer_email": None,
        "reviewed_at": None,
        "status": "proposed",
        "created_at": "2026-05-12T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


def _base_replay_fixture(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.replay_fixture.v1",
        "fixture_id": _new_uuid(),
        "replay_case_id": _new_uuid(),
        "source_span_id": _new_uuid(),
        "kind": "model_call",
        "mode": "cassette",
        "redaction_policy_version": "relay.redaction.v1#default",
        "input_digest": VALID_INPUT_DIGEST,
        "output_ref": "r2://replay/outputs/00000000-0000-4000-8000-000000000003",
        "output_digest": VALID_OUTPUT_DIGEST,
        "provider": "openai",
        "model": "gpt-4o-mini",
        "model_signature": "fp_abc123",
        "capture_clock": "2026-05-12T10:00:00+05:30",
        "refresh_policy": "invalidate_on_signature_change",
        "side_effect_class": "read_only",
        "allowed_in_replay": False,
        "created_at": "2026-05-12T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


# -----------------------------------------------------------------------------
# VAL-W1-018: evidence_bundles.bundle_digest sha256-<hex> pattern, non-nullable
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_accepts_canonical_bundle_digest() -> None:
    eb = EvidenceBundle.model_validate(_base_evidence_bundle())
    assert eb.bundle_digest == VALID_BUNDLE_DIGEST


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_rejects_missing_bundle_digest() -> None:
    payload = _base_evidence_bundle()
    del payload["bundle_digest"]
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "bundle_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_rejects_null_bundle_digest() -> None:
    payload = _base_evidence_bundle(bundle_digest=None)
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "bundle_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_rejects_colon_form_bundle_digest() -> None:
    payload = _base_evidence_bundle(bundle_digest="sha256:" + ("a" * 64))
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "bundle_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_rejects_short_bundle_digest() -> None:
    payload = _base_evidence_bundle(bundle_digest="sha256-" + ("a" * 63))
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "bundle_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-018")
def test_evidence_bundle_rejects_non_hex_bundle_digest() -> None:
    payload = _base_evidence_bundle(
        bundle_digest="sha256-" + "g" + ("a" * 63)
    )
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "bundle_digest" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-019: evidence_bundles.verification_status closed enum
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-019")
@pytest.mark.parametrize(
    "status",
    ["unverified", "verified", "tampered", "revoked"],
)
def test_evidence_bundle_accepts_all_verification_statuses(status: str) -> None:
    eb = EvidenceBundle.model_validate(
        _base_evidence_bundle(verification_status=status)
    )
    assert eb.verification_status == status


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-019")
def test_evidence_bundle_rejects_unknown_verification_status() -> None:
    payload = _base_evidence_bundle(verification_status="approved")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "verification_status" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-019")
def test_evidence_bundle_rejects_empty_verification_status() -> None:
    payload = _base_evidence_bundle(verification_status="")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "verification_status" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-019")
def test_raw_yaml_documents_verification_status_enum_lock() -> None:
    """The canonical YAML must lock the four-member enum and reference the
    eng-plan-locked candidate set. Mirrors the VAL-W1-019 gap-flag."""
    raw_dir = Path(__file__).resolve().parents[2] / "raw"
    text = (raw_dir / "envelopes.yaml").read_text(encoding="utf-8")
    assert "[unverified, verified, tampered, revoked]" in text
    # The lock-in comment must cite the gap.
    assert "VAL-W1-019" in text


# -----------------------------------------------------------------------------
# VAL-W1-020: evidence_claims.claim_type closed enum of eight kinds
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-020")
@pytest.mark.parametrize(
    "claim_type",
    [
        "run_result",
        "gate_decision",
        "contract_result",
        "replay_result",
        "human_oversight",
        "incident",
        "data_quality_check",
        "provider_compatibility",
    ],
)
def test_evidence_claim_accepts_all_canonical_claim_types(claim_type: str) -> None:
    ec = EvidenceClaim.model_validate(_base_evidence_claim(claim_type=claim_type))
    assert ec.claim_type == claim_type


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-020")
def test_evidence_claim_rejects_unknown_claim_type() -> None:
    payload = _base_evidence_claim(claim_type="orchestrator_decision")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "claim_type" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-021: evidence_claims.claim_digest sha256 pattern, signature non-empty,
#             supersedes_claim_id nullable UUID
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_accepts_canonical_claim_digest() -> None:
    ec = EvidenceClaim.model_validate(_base_evidence_claim())
    assert ec.claim_digest == VALID_CLAIM_DIGEST


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_rejects_colon_form_claim_digest() -> None:
    payload = _base_evidence_claim(claim_digest="sha256:" + ("a" * 64))
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "claim_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_rejects_short_claim_digest() -> None:
    payload = _base_evidence_claim(claim_digest="sha256-" + ("a" * 63))
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "claim_digest" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_rejects_empty_signature() -> None:
    payload = _base_evidence_claim(signature="")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "signature" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_accepts_null_supersedes_claim_id() -> None:
    ec = EvidenceClaim.model_validate(
        _base_evidence_claim(supersedes_claim_id=None)
    )
    assert ec.supersedes_claim_id is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_accepts_uuid_supersedes_claim_id() -> None:
    pred = _new_uuid()
    ec = EvidenceClaim.model_validate(
        _base_evidence_claim(supersedes_claim_id=pred)
    )
    assert str(ec.supersedes_claim_id) == pred


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-021")
def test_evidence_claim_rejects_non_uuid_supersedes_claim_id() -> None:
    payload = _base_evidence_claim(supersedes_claim_id="not-a-uuid")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "supersedes_claim_id" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-022: replay_cases.status enum + expected_assertion_ids + required
#             failure_signature_hash
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
@pytest.mark.parametrize("status", ["proposed", "approved", "retired"])
def test_replay_case_accepts_all_canonical_statuses(status: str) -> None:
    rc = ReplayCase.model_validate(_base_replay_case(status=status))
    assert rc.status == status


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_rejects_invalid_status() -> None:
    payload = _base_replay_case(status="approved_with_gaps")
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "status" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_status_defaults_to_proposed() -> None:
    payload = _base_replay_case()
    del payload["status"]
    rc = ReplayCase.model_validate(payload)
    assert rc.status == "proposed"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_expected_assertion_ids_defaults_to_empty() -> None:
    payload = _base_replay_case()
    del payload["expected_assertion_ids"]
    rc = ReplayCase.model_validate(payload)
    assert rc.expected_assertion_ids == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_expected_assertion_ids_accepts_non_empty_strings() -> None:
    payload = _base_replay_case(
        expected_assertion_ids=["VAL-STRUCTURED-001", "VAL-STRUCTURED-002"]
    )
    rc = ReplayCase.model_validate(payload)
    assert rc.expected_assertion_ids == ["VAL-STRUCTURED-001", "VAL-STRUCTURED-002"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_expected_assertion_ids_rejects_empty_string() -> None:
    payload = _base_replay_case(expected_assertion_ids=[""])
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "expected_assertion_ids" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_expected_assertion_ids_rejects_non_string_member() -> None:
    payload = _base_replay_case(expected_assertion_ids=[123])  # type: ignore[list-item]
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "expected_assertion_ids" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_rejects_missing_failure_signature_hash() -> None:
    payload = _base_replay_case()
    del payload["failure_signature_hash"]
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "failure_signature_hash" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-022")
def test_replay_case_rejects_empty_failure_signature_hash() -> None:
    payload = _base_replay_case(failure_signature_hash="")
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "failure_signature_hash" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-023: replay_fixtures.kind / mode / side_effect_class enums +
#             allowed_in_replay strict bool
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
@pytest.mark.parametrize(
    "kind",
    ["model_call", "tool_call", "retrieval", "embedding", "custom"],
)
def test_replay_fixture_accepts_all_canonical_kinds(kind: str) -> None:
    rf = ReplayFixture.model_validate(_base_replay_fixture(kind=kind))
    assert rf.kind == kind


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_rejects_unknown_kind() -> None:
    payload = _base_replay_fixture(kind="planning_call")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "kind" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
@pytest.mark.parametrize(
    "mode",
    ["cassette", "live", "degraded_live", "mock"],
)
def test_replay_fixture_accepts_all_canonical_modes(mode: str) -> None:
    rf = ReplayFixture.model_validate(_base_replay_fixture(mode=mode))
    assert rf.mode == mode


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_rejects_unknown_mode() -> None:
    payload = _base_replay_fixture(mode="passthrough")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "mode" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
@pytest.mark.parametrize(
    "side_effect_class",
    ["read_only", "mutating", "external_irreversible", "approval_required"],
)
def test_replay_fixture_accepts_all_side_effect_classes(
    side_effect_class: str,
) -> None:
    rf = ReplayFixture.model_validate(
        _base_replay_fixture(side_effect_class=side_effect_class)
    )
    assert rf.side_effect_class == side_effect_class


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_rejects_unknown_side_effect_class() -> None:
    payload = _base_replay_fixture(side_effect_class="audited")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "side_effect_class" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_allowed_in_replay_defaults_false() -> None:
    payload = _base_replay_fixture()
    del payload["allowed_in_replay"]
    rf = ReplayFixture.model_validate(payload)
    assert rf.allowed_in_replay is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_allowed_in_replay_accepts_true_bool() -> None:
    rf = ReplayFixture.model_validate(_base_replay_fixture(allowed_in_replay=True))
    assert rf.allowed_in_replay is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_allowed_in_replay_rejects_string_true() -> None:
    payload = _base_replay_fixture(allowed_in_replay="true")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "allowed_in_replay" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_allowed_in_replay_rejects_string_false() -> None:
    payload = _base_replay_fixture(allowed_in_replay="false")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "allowed_in_replay" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-023")
def test_replay_fixture_allowed_in_replay_rejects_int_one() -> None:
    payload = _base_replay_fixture(allowed_in_replay=1)
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "allowed_in_replay" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-024: replay_fixtures.capture_clock RFC 3339 timezone-aware +
#             cross-language byte-equal round-trip fixture
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_accepts_utc_z() -> None:
    rf = ReplayFixture.model_validate(
        _base_replay_fixture(capture_clock="2026-05-12T00:00:00Z")
    )
    assert rf.capture_clock.tzinfo is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_accepts_positive_offset() -> None:
    rf = ReplayFixture.model_validate(
        _base_replay_fixture(capture_clock="2026-05-12T10:00:00+05:30")
    )
    assert rf.capture_clock.utcoffset() == timedelta(hours=5, minutes=30)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_accepts_negative_offset() -> None:
    rf = ReplayFixture.model_validate(
        _base_replay_fixture(capture_clock="2026-05-12T00:00:00-08:00")
    )
    assert rf.capture_clock.utcoffset() == timedelta(hours=-8)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_rejects_naive_string() -> None:
    payload = _base_replay_fixture(capture_clock="2026-05-12T00:00:00")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "capture_clock" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_rejects_naive_datetime_object() -> None:
    payload = _base_replay_fixture(capture_clock=datetime(2026, 5, 12, 0, 0, 0))
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "capture_clock" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_capture_clock_round_trip_preserves_offset() -> None:
    for original_offset_str in [
        "2026-05-12T10:00:00+05:30",
        "2026-05-12T10:00:00-08:00",
        "2026-05-12T10:00:00+00:00",
    ]:
        payload = _base_replay_fixture(capture_clock=original_offset_str)
        rf = ReplayFixture.model_validate(payload)
        blob = serialize_replay_fixture_canonical(rf)
        decoded = json.loads(blob.decode("utf-8"))
        assert decoded["capture_clock"] == original_offset_str


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-024")
def test_replay_fixture_cross_language_digest_fixture() -> None:
    """Cross-language byte-equal round-trip fixture for replay_fixture.

    Same pattern as VAL-W1-017 event_log_entry fixture. The TS test reads
    the SAME fixture and asserts the SAME digest. Byte-equal Py and TS
    canonicalization = VAL-W1-024 evidence.
    """
    fixture_dir = Path(__file__).parent / "fixtures"
    fixture_file = fixture_dir / "replay_fixture_capture_clock.json"
    digest_file = fixture_dir / "replay_fixture_capture_clock.sha256"

    raw = fixture_file.read_bytes()
    payload = json.loads(raw.decode("utf-8"))

    rf = ReplayFixture.model_validate(payload)
    assert rf.capture_clock.tzinfo is not None

    canonical = serialize_replay_fixture_canonical(rf)
    actual_digest = "sha256-" + hashlib.sha256(canonical).hexdigest()
    expected_digest = digest_file.read_text(encoding="utf-8").strip()
    assert actual_digest == expected_digest, (
        f"Cross-language fixture digest mismatch. expected={expected_digest} "
        f"actual={actual_digest}"
    )


# -----------------------------------------------------------------------------
# VAL-W1-025: replay_fixtures.refresh_policy closed enum, default
#             invalidate_on_signature_change
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-025")
@pytest.mark.parametrize(
    "refresh_policy",
    [
        "invalidate_on_signature_change",
        "hold_forever",
        "refresh_weekly",
        "invalidate_on_model_version_change",
    ],
)
def test_replay_fixture_accepts_all_canonical_refresh_policies(
    refresh_policy: str,
) -> None:
    rf = ReplayFixture.model_validate(
        _base_replay_fixture(refresh_policy=refresh_policy)
    )
    assert rf.refresh_policy == refresh_policy


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-025")
def test_replay_fixture_rejects_unknown_refresh_policy() -> None:
    payload = _base_replay_fixture(refresh_policy="refresh_daily")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "refresh_policy" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-025")
def test_replay_fixture_refresh_policy_default_is_signature_change() -> None:
    payload = _base_replay_fixture()
    del payload["refresh_policy"]
    rf = ReplayFixture.model_validate(payload)
    assert rf.refresh_policy == "invalidate_on_signature_change"


# -----------------------------------------------------------------------------
# VAL-W1-052: evidence_bundle schema_version literal "relay.evidence_bundle.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-052")
def test_evidence_bundle_schema_version_pinned() -> None:
    eb = EvidenceBundle.model_validate(_base_evidence_bundle())
    assert eb.schema_version == "relay.evidence_bundle.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-052")
def test_evidence_bundle_rejects_wrong_schema_version() -> None:
    payload = _base_evidence_bundle(schema_version="relay.evidence_bundle.v2")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-052")
def test_generated_python_contains_evidence_bundle_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.evidence_bundle.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-053: evidence_claim schema_version literal "relay.evidence_claim.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-053")
def test_evidence_claim_schema_version_pinned() -> None:
    ec = EvidenceClaim.model_validate(_base_evidence_claim())
    assert ec.schema_version == "relay.evidence_claim.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-053")
def test_evidence_claim_rejects_wrong_schema_version() -> None:
    payload = _base_evidence_claim(schema_version="relay.evidence_claim.v2")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-053")
def test_generated_python_contains_evidence_claim_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.evidence_claim.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-054: replay_case schema_version literal "relay.replay_case.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-054")
def test_replay_case_schema_version_pinned() -> None:
    rc = ReplayCase.model_validate(_base_replay_case())
    assert rc.schema_version == "relay.replay_case.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-054")
def test_replay_case_rejects_wrong_schema_version() -> None:
    payload = _base_replay_case(schema_version="relay.replay_case.v2")
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-054")
def test_generated_python_contains_replay_case_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.replay_case.v1"') >= 1


# -----------------------------------------------------------------------------
# VAL-W1-055: replay_fixture schema_version literal "relay.replay_fixture.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-055")
def test_replay_fixture_schema_version_pinned() -> None:
    rf = ReplayFixture.model_validate(_base_replay_fixture())
    assert rf.schema_version == "relay.replay_fixture.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-055")
def test_replay_fixture_rejects_wrong_schema_version() -> None:
    payload = _base_replay_fixture(schema_version="relay.replay_fixture.v2")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-055")
def test_generated_python_contains_replay_fixture_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.replay_fixture.v1"') >= 1


# -----------------------------------------------------------------------------
# Defense-in-depth: extra-field rejection on W1.3 envelopes
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-052")
def test_evidence_bundle_rejects_unknown_field() -> None:
    payload = _base_evidence_bundle(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceBundle.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-053")
def test_evidence_claim_rejects_unknown_field() -> None:
    payload = _base_evidence_claim(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        EvidenceClaim.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-054")
def test_replay_case_rejects_unknown_field() -> None:
    payload = _base_replay_case(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        ReplayCase.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-055")
def test_replay_fixture_rejects_unknown_field() -> None:
    payload = _base_replay_fixture(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        ReplayFixture.model_validate(payload)
    assert (
        "unknown_field" in str(excinfo.value)
        or "extra" in str(excinfo.value).lower()
    )


# =============================================================================
# W1.4 - RedactionPolicy + ErrorEnvelope (VAL-W1-026..031, 056, 057, 060)
# =============================================================================


def _base_redaction_policy(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.redaction.v1",
        "redaction_policy_id": _new_uuid(),
        "org_id": _new_uuid(),
        "version": "v1",
        "raw_capture": False,
        "dpa_ref": None,
        "approver_user_id": None,
        "matchers": [],
        "created_at": "2026-05-13T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def _base_error_envelope(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "relay.error.v1",
        "code": "RELAY-ING-031",
        "http_status": 422,
        "blocked_surface": "POST /api/ingest",
        "retry_advice": "do_not_retry",
        "request_id": "req-01HMA1ABCDEFG",
        "trace_id": "trace-01HMA1ABCDEFG",
    }
    payload.update(overrides)
    return payload


# -----------------------------------------------------------------------------
# VAL-W1-026: redaction_policies.schema_version + raw_capture StrictBool
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
def test_redaction_policy_schema_version_pinned() -> None:
    rp = RedactionPolicy.model_validate(_base_redaction_policy())
    assert rp.schema_version == "relay.redaction.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
def test_redaction_policy_rejects_wrong_schema_version() -> None:
    payload = _base_redaction_policy(schema_version="relay.redaction.v2")
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
def test_redaction_policy_raw_capture_default_false() -> None:
    payload = _base_redaction_policy()
    payload.pop("raw_capture")
    rp = RedactionPolicy.model_validate(payload)
    assert rp.raw_capture is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
@pytest.mark.parametrize("bad_value", ["true", "false", "True", "False", 0, 1])
def test_redaction_policy_raw_capture_rejects_coercible_forms(bad_value: object) -> None:
    payload = _base_redaction_policy(raw_capture=bad_value)
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    assert "raw_capture" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
def test_redaction_policy_raw_capture_accepts_native_bool() -> None:
    # raw_capture=True is acceptable IF cross-field VAL-W1-027 is satisfied.
    payload = _base_redaction_policy(
        raw_capture=True,
        dpa_ref="DPA-2026-001",
        approver_user_id=_new_uuid(),
    )
    rp = RedactionPolicy.model_validate(payload)
    assert rp.raw_capture is True


# -----------------------------------------------------------------------------
# VAL-W1-027: raw_capture=true requires dpa_ref + approver_user_id
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-027")
def test_redaction_policy_raw_capture_true_requires_dpa() -> None:
    payload = _base_redaction_policy(
        raw_capture=True,
        dpa_ref=None,
        approver_user_id=_new_uuid(),
    )
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value)
    assert "raw_capture" in msg and "dpa_ref" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-027")
def test_redaction_policy_raw_capture_true_requires_approver() -> None:
    payload = _base_redaction_policy(
        raw_capture=True,
        dpa_ref="DPA-2026-001",
        approver_user_id=None,
    )
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value)
    assert "raw_capture" in msg and "approver_user_id" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-027")
def test_redaction_policy_raw_capture_true_requires_both() -> None:
    payload = _base_redaction_policy(
        raw_capture=True,
        dpa_ref=None,
        approver_user_id=None,
    )
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value)
    assert "raw_capture" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-027")
def test_redaction_policy_raw_capture_false_does_not_require_dpa() -> None:
    # raw_capture=False is the default; dpa_ref/approver_user_id may be null.
    payload = _base_redaction_policy(raw_capture=False, dpa_ref=None, approver_user_id=None)
    rp = RedactionPolicy.model_validate(payload)
    assert rp.raw_capture is False
    assert rp.dpa_ref is None
    assert rp.approver_user_id is None


# -----------------------------------------------------------------------------
# VAL-W1-028: matchers[] tagged union on `kind`
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_regex_happy_path() -> None:
    payload = _base_redaction_policy(matchers=[
        {"kind": "regex", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"},
    ])
    rp = RedactionPolicy.model_validate(payload)
    assert len(rp.matchers) == 1
    assert rp.matchers[0].kind == "regex"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_json_pointer_happy_path() -> None:
    payload = _base_redaction_policy(matchers=[
        {"kind": "json_pointer", "paths": ["/inputs/ssn", "/outputs/email"]},
    ])
    rp = RedactionPolicy.model_validate(payload)
    assert len(rp.matchers) == 1
    assert rp.matchers[0].kind == "json_pointer"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_regex_with_paths_rejected() -> None:
    # VAL-W1-028: kind="regex" forbids `paths`.
    payload = _base_redaction_policy(matchers=[
        {"kind": "regex", "pattern": "foo", "paths": ["/x"]},
    ])
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value).lower()
    assert "paths" in msg or "extra" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_json_pointer_with_pattern_rejected() -> None:
    # VAL-W1-028: kind="json_pointer" forbids `pattern`.
    payload = _base_redaction_policy(matchers=[
        {"kind": "json_pointer", "paths": ["/inputs/ssn"], "pattern": "foo"},
    ])
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value).lower()
    assert "pattern" in msg or "extra" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_regex_missing_pattern_rejected() -> None:
    payload = _base_redaction_policy(matchers=[{"kind": "regex"}])
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    assert "pattern" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-028")
def test_redaction_policy_matcher_unknown_kind_rejected() -> None:
    payload = _base_redaction_policy(matchers=[{"kind": "fnmatch", "pattern": "*.txt"}])
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    assert "kind" in str(excinfo.value).lower() or "discriminator" in str(excinfo.value).lower()


# -----------------------------------------------------------------------------
# VAL-W1-029: error_envelope required fields + retry_advice closed enum
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
def test_error_envelope_happy_path() -> None:
    e = ErrorEnvelope.model_validate(_base_error_envelope())
    assert e.schema_version == "relay.error.v1"
    assert e.code == "RELAY-ING-031"
    assert 400 <= e.http_status <= 599


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize(
    "missing_field",
    [
        "schema_version",
        "code",
        "http_status",
        "blocked_surface",
        "retry_advice",
        "request_id",
        "trace_id",
    ],
)
def test_error_envelope_rejects_missing_required_field(missing_field: str) -> None:
    payload = _base_error_envelope()
    payload.pop(missing_field)
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert missing_field in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize(
    "bad_code",
    [
        "relay-ing-031",
        "RELAY_ING_031",
        "ING-031",
        "RELAY-ING-31",
        "RELAY-ing-031",
        "",
        "RELAY-ING-0031",
    ],
)
def test_error_envelope_rejects_malformed_code(bad_code: str) -> None:
    payload = _base_error_envelope(code=bad_code)
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "code" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize("bad_status", [200, 399, 600, 700, -1])
def test_error_envelope_rejects_http_status_out_of_range(bad_status: int) -> None:
    payload = _base_error_envelope(http_status=bad_status)
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "http_status" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize("bad_status", [400, 422, 499, 500, 599])
def test_error_envelope_accepts_http_status_in_range(bad_status: int) -> None:
    payload = _base_error_envelope(http_status=bad_status)
    e = ErrorEnvelope.model_validate(payload)
    assert e.http_status == bad_status


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
def test_error_envelope_rejects_empty_blocked_surface() -> None:
    payload = _base_error_envelope(blocked_surface="")
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "blocked_surface" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize(
    "advice",
    [
        "do_not_retry",
        "after_fix",
        "after_retry_after",
        "after_split",
        "after_recapture",
        "after_re_auth",
    ],
)
def test_error_envelope_accepts_each_retry_advice(advice: str) -> None:
    payload = _base_error_envelope(retry_advice=advice)
    e = ErrorEnvelope.model_validate(payload)
    assert e.retry_advice == advice


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
@pytest.mark.parametrize(
    "bad_advice",
    ["After fix", "After Retry-After", "RETRY", "yes", "no", "", "do-not-retry"],
)
def test_error_envelope_rejects_non_canonical_retry_advice(bad_advice: str) -> None:
    payload = _base_error_envelope(retry_advice=bad_advice)
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "retry_advice" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-030: RELAY-* codes generated as constants in BOTH Py and TS
# -----------------------------------------------------------------------------


REQUIRED_B4_CODES = [
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
]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-030")
def test_required_15_b4_codes_present_on_python_class() -> None:
    for code in REQUIRED_B4_CODES:
        attr = code.replace("-", "_")
        assert hasattr(RelayErrorCode, attr), f"RelayErrorCode missing attribute {attr}"
        assert getattr(RelayErrorCode, attr) == code


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-030")
def test_required_15_b4_codes_in_python_module_text() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "error_codes.py"
    text = src.read_text(encoding="utf-8")
    count = sum(1 for c in REQUIRED_B4_CODES if f'"{c}"' in text)
    assert count == 15, f"expected 15 spec B.4 codes in {src.name}, found {count}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-030")
def test_required_15_b4_codes_in_typescript_module_text() -> None:
    ts_src = (
        Path(__file__).resolve().parents[2]
        / "typescript"
        / "src"
        / "error_codes.ts"
    )
    text = ts_src.read_text(encoding="utf-8")
    count = sum(1 for c in REQUIRED_B4_CODES if f'"{c}"' in text)
    assert count == 15, f"expected 15 spec B.4 codes in {ts_src.name}, found {count}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-030")
def test_error_envelope_accepts_known_relay_error_code() -> None:
    e = ErrorEnvelope.model_validate(_base_error_envelope(code=RelayErrorCode.RELAY_GATE_021))
    assert e.code == "RELAY-GATE-021"


# -----------------------------------------------------------------------------
# VAL-W1-031: request_id + trace_id required non-empty strings
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-031")
def test_error_envelope_rejects_empty_request_id() -> None:
    payload = _base_error_envelope(request_id="")
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "request_id" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-031")
def test_error_envelope_rejects_empty_trace_id() -> None:
    payload = _base_error_envelope(trace_id="")
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "trace_id" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-031")
def test_error_envelope_rejects_non_string_request_id() -> None:
    payload = _base_error_envelope(request_id=12345)
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "request_id" in str(excinfo.value)


# -----------------------------------------------------------------------------
# VAL-W1-056: error_envelope.schema_version literal "relay.error.v1"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-056")
def test_error_envelope_rejects_wrong_schema_version() -> None:
    payload = _base_error_envelope(schema_version="relay.error.v2")
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    assert "schema_version" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-056")
def test_generated_python_contains_error_envelope_v1_literal() -> None:
    src = Path(__file__).resolve().parents[1] / "relay_schemas" / "envelopes.py"
    text = src.read_text(encoding="utf-8")
    assert text.count('"relay.error.v1"') >= 1


# -----------------------------------------------------------------------------
# Defense-in-depth: extra-field rejection on W1.4 envelopes
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-026")
def test_redaction_policy_rejects_unknown_field() -> None:
    payload = _base_redaction_policy(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        RedactionPolicy.model_validate(payload)
    msg = str(excinfo.value).lower()
    assert "unknown_field" in str(excinfo.value) or "extra" in msg


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-029")
def test_error_envelope_rejects_unknown_field() -> None:
    payload = _base_error_envelope(unknown_field="value")
    with pytest.raises(ValidationError) as excinfo:
        ErrorEnvelope.model_validate(payload)
    msg = str(excinfo.value).lower()
    assert "unknown_field" in str(excinfo.value) or "extra" in msg


# ---------------------------------------------------------------------------
# VAL-W1-017 (re-hunt #7): datetime fields are strict like the TS reader.
# The TS checkRfc3339 requires typeof === "string" (length >= 20) -- an integer
# Unix epoch (or float/bool) is REJECTED. Pydantic's default coercion accepted
# an int epoch, so the same wire bytes got opposite Py/TS verdicts.
# ---------------------------------------------------------------------------


def test_run_result_rejects_integer_epoch_decided_at() -> None:
    """An integer Unix epoch in a datetime field is rejected (Py<->TS parity)."""
    with pytest.raises(ValidationError):
        RunResult.model_validate(_base_run_result(decided_at=1747008000))


def test_run_result_rejects_float_epoch_and_bool_decided_at() -> None:
    with pytest.raises(ValidationError):
        RunResult.model_validate(_base_run_result(decided_at=1747008000.0))
    with pytest.raises(ValidationError):
        RunResult.model_validate(_base_run_result(decided_at=True))


def test_run_result_rejects_too_short_datetime_string() -> None:
    """The TS reader requires length >= 20; a bare date string is rejected."""
    with pytest.raises(ValidationError):
        RunResult.model_validate(_base_run_result(decided_at="2026-05-12"))


def test_run_result_accepts_canonical_rfc3339_string() -> None:
    """Every currently-valid RFC 3339 wire value still parses (no regression)."""
    rr = RunResult.model_validate(
        _base_run_result(decided_at="2026-05-12T00:00:00Z")
    )
    assert rr.decided_at.year == 2026
    rr_offset = RunResult.model_validate(
        _base_run_result(decided_at="2026-05-12T00:00:00+02:00")
    )
    assert rr_offset.decided_at.utcoffset() is not None


# ---------------------------------------------------------------------------
# MED #8 (re-hunt): Rfc3339Datetime Py<->TS VERDICT parity (P0 keystone).
#
# Finding #7 made Python reject int/float epochs and too-short strings, but it
# still deferred the remaining RFC 3339 grammar to Pydantic's parser while the
# TS isRfc3339Datetime deferred to Date.parse. Those two acceptance sets DIVERGE
# in both directions: Date.parse accepts RFC-2822-ish forms
# ('Mon May 12 2025 00:00:00', 'Wed, 12 May 2025 00:00:00 GMT') and an
# out-of-range hour ('...T24:00:00Z') that Pydantic rejects; Pydantic accepts a
# colon-less offset ('+0200') that strict RFC 3339 forbids. Same wire bytes ->
# opposite verdicts.
#
# Fix: BOTH sides enforce ONE shared strict RFC 3339 grammar via an identical
# regex (required 'T'/'t'/space separator, HH:MM:SS, optional fraction, and a
# 'Z'/'z' or +/-HH:MM offset with a required colon). This corpus pins the SAME
# accept/reject verdict in Python and TypeScript for the same wire bytes.
# ---------------------------------------------------------------------------

# (wire_value, expected_accept) -- the contract the two readers MUST agree on.
_RFC3339_PARITY_CORPUS: list[tuple[object, bool]] = [
    # Canonical RFC 3339 values every producer emits -- accept on BOTH sides.
    ("2026-05-12T00:00:00Z", True),
    ("2026-05-12T00:00:00+02:00", True),
    ("2026-05-12T00:00:00-08:00", True),
    ("2026-05-12T10:00:00+05:30", True),
    ("2026-05-12T00:00:00.123456Z", True),
    ("2026-05-12t00:00:00z", True),
    ("2026-05-12 00:00:00+00:00", True),
    # Permissive Date.parse extras that strict RFC 3339 forbids -- reject BOTH.
    ("Mon May 12 2025 00:00:00", False),
    ("Wed, 12 May 2025 00:00:00 GMT", False),
    ("2026-05-12T24:00:00Z", False),  # hour 24 out of range
    ("2026-05-12T00:00:00+0200", False),  # offset missing the ':' separator
    ("2026-05-12T00:00:00", False),  # naive: no offset
    # Non-string / too-short forms -- reject BOTH (finding #7 carried forward).
    (1747008000, False),  # integer Unix epoch
    (1747008000.5, False),  # float Unix epoch
    ("2026-05-12", False),  # too short
]


def _python_rfc3339_accepts(value: object) -> bool:
    """True iff the Python reader accepts ``value`` in a datetime field."""
    try:
        RunResult.model_validate(_base_run_result(decided_at=value))
        return True
    except ValidationError:
        return False


def _typescript_rfc3339_verdicts(values: list[object]) -> list[bool]:
    """Run the TS parseRunResult against each candidate ``decided_at`` value.

    Returns a list of accept/reject booleans, one per input, computed by the
    compiled TS dist via a Node subprocess (mirrors the harness in
    test_canonical_bytes_parity.py). Skips when Node or the dist are absent.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    repo_root = Path(__file__).resolve().parents[4]
    ts_dist = repo_root / "packages" / "schemas" / "typescript" / "dist" / "envelopes.js"
    if node is None or not ts_dist.exists():
        pytest.skip(
            "node binary or TS dist (packages/schemas/typescript/dist) absent"
        )

    base = {
        "schema_version": "relay.run_result.v1",
        "run_result_id": _new_uuid(),
        "run_id": _new_uuid(),
        "project_id": _new_uuid(),
        "written_by": "control_plane",
        "status": "accepted",
        "evidence_bundle_id": _new_uuid(),
        "manifest_commit_hash": VALID_MANIFEST_HASH,
        "actor_identity_hash": VALID_ACTOR_HASH,
        "decided_at": None,
        "decision_epoch": 0,
        "signature": VALID_SIGNATURE,
        "signature_key_id": VALID_KEY_ID,
        "error_priority_rule": "first_p0_then_highest_severity_then_earliest_span",
    }
    script = (
        f"import {{ parseRunResult }} from {json.dumps(str(ts_dist))};\n"
        "let buf='';process.stdin.on('data',c=>buf+=c);"
        "process.stdin.on('end',()=>{const job=JSON.parse(buf);"
        "const out=job.values.map(v=>{const p={...job.base,decided_at:v};"
        "try{parseRunResult(p);return true;}catch(e){return false;}});"
        "process.stdout.write(JSON.stringify(out));});"
    )
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps({"base": base, "values": values}, ensure_ascii=False),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"node failed: rc={proc.returncode} {proc.stderr!r}")
    verdicts = json.loads(proc.stdout.strip())
    assert isinstance(verdicts, list) and len(verdicts) == len(values)
    return [bool(v) for v in verdicts]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
@pytest.mark.parametrize("value,expected_accept", _RFC3339_PARITY_CORPUS)
def test_rfc3339_python_verdict_matches_contract(
    value: object, expected_accept: bool
) -> None:
    """Python reader gives the contract-specified accept/reject for each value."""
    assert _python_rfc3339_accepts(value) is expected_accept, repr(value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-017")
def test_rfc3339_python_typescript_verdict_parity() -> None:
    """Python and TypeScript give the SAME accept/reject verdict for the SAME
    wire bytes (P0 keystone). Authoritative when Node + TS dist are present."""
    values = [v for v, _ in _RFC3339_PARITY_CORPUS]
    expected = [exp for _, exp in _RFC3339_PARITY_CORPUS]
    py_verdicts = [_python_rfc3339_accepts(v) for v in values]
    ts_verdicts = _typescript_rfc3339_verdicts(values)
    divergences = [
        (values[i], py_verdicts[i], ts_verdicts[i], expected[i])
        for i in range(len(values))
        if py_verdicts[i] != ts_verdicts[i] or py_verdicts[i] != expected[i]
    ]
    assert not divergences, (
        "Py<->TS RFC 3339 verdict divergence (value, py, ts, expected):\n"
        + "\n".join(repr(d) for d in divergences)
    )
