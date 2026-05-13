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
    EventLogEntry,
    GateDecision,
    GateDecisionDraft,
    GateRound,
    IdempotencyRecord,
    ManifestVersion,
    RunResult,
    ScopeState,
    serialize_event_log_entry_canonical,
)

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
