"""Caller payload MUST NOT override engine-authoritative audit fields.

P2 control-plane bug (bug-hunt 2026): on a WINNING transition the action-row
payload was built as ``{engine keys} | caller payload`` with the caller's
``payload`` applied LAST, so a caller could clobber the engine-authoritative
audit keys (``event``, ``expected_from``, ``applied_at_epoch``) -- exactly the
keys the idempotency probe (:func:`_was_event_already_applied`) reads. A
malicious or buggy caller passing
``payload={"applied_at_epoch": 999, "event": "ATTACKER_EVENT",
"expected_from": "spoofed"}`` could therefore:

  - corrupt audit attribution (the persisted row records the attacker's event
    name / expected_from / applied_at_epoch instead of the engine's), and
  - poison idempotency detection: a later legitimate retry of the same
    (scope, expected_from, event) mis-detects, returning EXPECTED_FROM_MISMATCH
    instead of idempotent=True.

This mirrors the existing ``actor_identity_hash`` override precedent (the
authenticated actor anchor wins over any caller-supplied value): the engine's
audit keys MUST win over caller payload on BOTH the success path and the
invalid-transition forensic path.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import json
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION,
    INVALID_TRANSITION_EVENT_TYPE,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


async def _seed_scope(
    db: SidecarDatabase, scope_kind: str = "run"
) -> tuple[str, str]:
    """Insert a scope_state row at the canonical initial state. Returns (scope_id, project_id)."""
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    await init_scope(
        database=db,
        scope_kind=scope_kind,
        scope_id=scope_id,
        project_id=project_id,
    )
    return scope_id, project_id


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_caller_payload_cannot_override_engine_audit_keys_on_success(
    tmp_path,
) -> None:
    """Winning transition with a spoofing payload -> engine audit keys win.

    The persisted ``state_transition`` action row MUST carry the engine's
    ``event`` / ``expected_from`` / ``applied_at_epoch`` (not the caller's
    bogus values), AND a legitimate idempotent retry of the real triple MUST
    still be recognised (idempotent=True), proving the idempotency probe was
    not poisoned.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        real_event = "ingest.run_received"
        real_expected_from = "pending"

        # Winning transition pending -> captured, but the caller stuffs the
        # engine-authoritative audit keys with attacker-controlled values.
        malicious_payload = {
            "applied_at_epoch": 999,
            "event": "ATTACKER_EVENT",
            "expected_from": "spoofed",
            "benign_caller_field": "ok-to-keep",
        }
        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from=real_expected_from,
            event=real_event,
            actor=actor,
            payload=malicious_payload,
            project_id=project_id,
        )
        assert first.ok is True, first
        assert first.new_state == "captured"
        assert first.epoch == 1, first

        # Read back the persisted action-row payload (the state_transition
        # row, distinct from the state_transition_summary row).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, rows
        persisted = json.loads(rows[0][0])

        # Engine-authoritative keys WIN over caller payload.
        assert persisted["event"] == real_event, persisted
        assert persisted["expected_from"] == real_expected_from, persisted
        assert persisted["applied_at_epoch"] == 0, persisted
        # The authenticated actor anchor is still the engine's value.
        assert persisted["actor_identity_hash"] == "sha256-aaaa", persisted
        # A benign (non-reserved) caller field is preserved.
        assert persisted["benign_caller_field"] == "ok-to-keep", persisted

        # The idempotency probe was NOT poisoned: a legitimate retry of the
        # REAL triple is recognised as an idempotent replay (state is now
        # 'captured', so the engine consults _was_event_already_applied,
        # which matches on the engine's recorded {event, applied_at_epoch}).
        retry = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from=real_expected_from,
            event=real_event,
            actor=actor,
            project_id=project_id,
        )
        assert retry.ok is True, retry
        assert retry.idempotent is True, retry
        assert retry.epoch == 1, retry
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_caller_payload_cannot_override_engine_audit_keys_on_invalid(
    tmp_path,
) -> None:
    """Invalid transition forensic row -> engine verdict keys win over caller.

    The persisted ``state.invalid_transition`` forensic row MUST carry the
    engine's ``event`` / ``expected_from`` / ``observed_state`` /
    ``rejected_reason`` (not the caller's spoofed values).
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        real_event = "not.a.real.event"
        real_expected_from = "pending"

        malicious_payload = {
            "event": "ATTACKER_EVENT",
            "expected_from": "spoofed",
            "observed_state": "spoofed_state",
            "rejected_reason": "ATTACKER_REASON",
            "benign_caller_field": "ok-to-keep",
        }
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from=real_expected_from,
            event=real_event,
            actor=actor,
            payload=malicious_payload,
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == INVALID_TRANSITION, result

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = ?",
            (scope_id, INVALID_TRANSITION_EVENT_TYPE),
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, rows
        persisted = json.loads(rows[0][0])

        # Engine-authoritative verdict keys WIN over caller payload.
        assert persisted["event"] == real_event, persisted
        assert persisted["expected_from"] == real_expected_from, persisted
        assert persisted["observed_state"] == "pending", persisted
        assert persisted["rejected_reason"] == INVALID_TRANSITION, persisted
        assert persisted["actor_identity_hash"] == "sha256-aaaa", persisted
        # A benign (non-reserved) caller field is preserved.
        assert persisted["benign_caller_field"] == "ok-to-keep", persisted
    finally:
        await db.close()
