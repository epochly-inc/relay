"""W8.4 plumbing tests: circuit-breaker trip + stalled-state guard.

Covers VAL-W8-032, VAL-W8-033, VAL-W8-034, VAL-W8-038. Drives the real
migration 0011 schema (``gate_stalled_state``, ``event_log_entries``,
``gates``) and the ``CircuitBreaker`` coordinator end-to-end.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _w8_4_helpers import (
    fetch_all,
    fetch_event_log_payload,
    fetch_one,
    seed_gate,
    seed_gate_round,
    seed_stalled,
    setup_circuit_breaker_fixture,
)
from relay_gate_engine import (
    EVENT_GATE_STALLED,
    EVENT_GATE_TERMINAL_BLOCK,
    EVENT_KIND_VALIDATION_CIRCUIT_BREAKER,
    STALLED_REASON_ADMIN_TERMINATED,
    STALLED_REASON_CAP_EXCEEDED,
    CircuitBreaker,
    StalledScopeRejectedError,
)
from relay_schemas.error_codes import RelayErrorCode

# ---------------------------------------------------------------------------
# Pure predicate.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-032")
def test_would_exceed_cap_predicate() -> None:
    """The pure predicate fires iff ``current_round + 1 > cap``."""
    # Default cap=5: round 5 -> attempting 6 trips.
    assert CircuitBreaker.would_exceed_cap(current_round=5, remediation_round_cap=5)
    # Round 4 -> attempting 5 still within budget.
    assert not CircuitBreaker.would_exceed_cap(
        current_round=4, remediation_round_cap=5
    )
    # Round 0 -> attempting 1, never trips with sane caps.
    assert not CircuitBreaker.would_exceed_cap(
        current_round=0, remediation_round_cap=1
    )
    # Cap=1, round 1 -> attempting 2 trips.
    assert CircuitBreaker.would_exceed_cap(
        current_round=1, remediation_round_cap=1
    )


# ---------------------------------------------------------------------------
# VAL-W8-032: trip to gate.stalled; no gate_decisions row for cap+1.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-032")
@pytest.mark.asyncio
async def test_trip_to_stalled_inserts_row_no_decision(tmp_path: Path) -> None:
    """trip_to_stalled writes one gate_stalled_state row; zero
    gate_decisions rows for the cap-exceeded round."""
    f = await setup_circuit_breaker_fixture(tmp_path, remediation_round_cap=5)
    try:
        wf = f.writer
        result = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result.ok is True
        assert result.terminal_round == 5
        assert result.event_id != ""

        # gate_stalled_state row exists.
        row = await fetch_one(
            wf.database,
            "SELECT gate_id, terminal_round, reason, opened_at, "
            "       reopened_at, terminated_at "
            "FROM gate_stalled_state "
            "WHERE scope_type = ? AND scope_id = ?",
            ("run", wf.scope_id),
        )
        assert row is not None
        assert row[0] == wf.gate_id
        assert int(row[1]) == 5
        assert row[2] == STALLED_REASON_CAP_EXCEEDED
        assert row[3] is not None
        assert row[4] is None  # reopened_at -- not yet
        assert row[5] is None  # terminated_at -- not yet

        # NO gate_decisions row at round 6 for this scope+gate.
        decisions = await fetch_all(
            wf.database,
            "SELECT round FROM gate_decisions "
            "WHERE scope_type = ? AND scope_id = ? AND round >= 6",
            ("run", wf.scope_id),
        )
        assert decisions == []
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-032")
@pytest.mark.asyncio
async def test_trip_to_stalled_is_idempotent(tmp_path: Path) -> None:
    """A second trip on an already-stalled scope is a no-op."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        first = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert first.ok is True

        second = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert second.ok is False
        assert second.stalled_at == first.stalled_at

        # Still only ONE gate_stalled_state row.
        rows = await fetch_all(
            wf.database,
            "SELECT scope_id FROM gate_stalled_state WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert len(rows) == 1
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-033: event_log_entries row with the five named payload keys.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-033")
@pytest.mark.asyncio
async def test_trip_writes_event_log_with_five_payload_keys(
    tmp_path: Path,
) -> None:
    """event_log_entries row has scope_id, gate_id, current_round,
    remediation_round_cap, failing_assertion_ids in the payload."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b", "VAL-W8-027c"),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )

        payload = await fetch_event_log_payload(
            wf.database, event_type=EVENT_GATE_STALLED, scope_id=wf.scope_id
        )
        assert payload is not None
        # All five required keys are present.
        for required in (
            "scope_id",
            "gate_id",
            "current_round",
            "remediation_round_cap",
            "failing_assertion_ids",
        ):
            assert required in payload, f"missing payload key: {required!r}"
        assert payload["scope_id"] == wf.scope_id
        assert payload["gate_id"] == wf.gate_id
        assert payload["current_round"] == 5
        assert payload["remediation_round_cap"] == 5
        assert payload["failing_assertion_ids"] == [
            "VAL-W8-027b",
            "VAL-W8-027c",
        ]

        # The event row carries both name forms per contract gap #2:
        # event_type='gate.stalled' AND event_kind='validation_circuit_breaker'.
        evt_row = await fetch_one(
            wf.database,
            "SELECT event_type, event_kind FROM event_log_entries "
            "WHERE event_type = ? AND scope_id = ? "
            "ORDER BY ingest_sequence DESC LIMIT 1",
            (EVENT_GATE_STALLED, wf.scope_id),
        )
        assert evt_row is not None
        assert evt_row[0] == EVENT_GATE_STALLED
        assert evt_row[1] == EVENT_KIND_VALIDATION_CIRCUIT_BREAKER
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-034: stalled state blocks new draft submissions.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-034")
@pytest.mark.asyncio
async def test_assert_not_stalled_raises_on_stalled_scope(
    tmp_path: Path,
) -> None:
    """A scope in gate.stalled raises StalledScopeRejectedError with
    the RELAY-GATE-051 code."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Stall the scope.
        await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )

        with pytest.raises(StalledScopeRejectedError) as excinfo:
            await f.breaker.assert_not_stalled(
                scope_type="run", scope_id=wf.scope_id
            )
        env = excinfo.value.to_envelope()
        assert env["code"] == RelayErrorCode.RELAY_GATE_051
        assert env["payload"]["scope_id"] == wf.scope_id
        assert env["payload"]["gate_id"] == wf.gate_id
        assert env["payload"]["reason"] == STALLED_REASON_CAP_EXCEEDED
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-034")
@pytest.mark.asyncio
async def test_assert_not_stalled_silent_on_healthy_scope(
    tmp_path: Path,
) -> None:
    """A scope with no gate_stalled_state row passes silently."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # No trip; the scope is healthy.
        await f.breaker.assert_not_stalled(
            scope_type="run", scope_id=wf.scope_id
        )
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-034")
@pytest.mark.asyncio
async def test_assert_not_stalled_allows_drafts_after_reopen(
    tmp_path: Path,
) -> None:
    """After admin.reopen sets reopened_at, drafts may flow again."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Manually seed a stalled row with reopened_at set (no terminated_at).
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
            reopened_at="2026-05-15T12:00:00.000000Z",
            terminated_at=None,
        )
        # Should NOT raise.
        await f.breaker.assert_not_stalled(
            scope_type="run", scope_id=wf.scope_id
        )
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-034")
@pytest.mark.asyncio
async def test_assert_not_stalled_still_blocks_after_terminate(
    tmp_path: Path,
) -> None:
    """terminated_at takes precedence over reopened_at: drafts stay
    rejected against a terminated scope."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
            reopened_at="2026-05-15T12:00:00.000000Z",
            terminated_at="2026-05-15T13:00:00.000000Z",
        )
        with pytest.raises(StalledScopeRejectedError) as excinfo:
            await f.breaker.assert_not_stalled(
                scope_type="run", scope_id=wf.scope_id
            )
        assert excinfo.value.to_envelope()["code"] == RelayErrorCode.RELAY_GATE_051
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-038: cascade_on_block=false -> terminal, no new round.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-038")
@pytest.mark.asyncio
async def test_handle_block_decision_terminates_when_cascade_false(
    tmp_path: Path,
) -> None:
    """A block with cascade_on_block=False writes the terminal marker
    and emits gate.terminal_block; no new gate_rounds row appears."""
    f = await setup_circuit_breaker_fixture(
        tmp_path, cascade_on_block=False
    )
    try:
        wf = f.writer
        # Seed an existing round=1 for the scope.
        await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=1,
        )
        before_rounds = await fetch_all(
            wf.database,
            "SELECT round FROM gate_rounds WHERE scope_id = ? "
            "ORDER BY round",
            (wf.scope_id,),
        )

        result = await f.breaker.handle_block_decision(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=1,
            cascade_on_block=False,
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result is not None
        assert result.ok is True

        # gate_stalled_state row exists with reason='admin_terminated'.
        row = await fetch_one(
            wf.database,
            "SELECT reason, terminated_at FROM gate_stalled_state "
            "WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert row is not None
        assert row[0] == STALLED_REASON_ADMIN_TERMINATED
        assert row[1] is not None

        # No new gate_rounds rows have been opened (cascade_on_block=False
        # means terminal-without-restart per VAL-W8-038).
        after_rounds = await fetch_all(
            wf.database,
            "SELECT round FROM gate_rounds WHERE scope_id = ? "
            "ORDER BY round",
            (wf.scope_id,),
        )
        assert after_rounds == before_rounds

        # event_log_entries carries the terminal_block event.
        payload = await fetch_event_log_payload(
            wf.database,
            event_type=EVENT_GATE_TERMINAL_BLOCK,
            scope_id=wf.scope_id,
        )
        assert payload is not None
        assert payload["cascade_on_block"] is False
        assert payload["gate_id"] == wf.gate_id
        assert payload["current_round"] == 1
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-038")
@pytest.mark.asyncio
async def test_handle_block_decision_returns_none_when_cascade_true(
    tmp_path: Path,
) -> None:
    """cascade_on_block=True yields None so the caller proceeds with the
    normal restart path. No gate_stalled_state row is written."""
    f = await setup_circuit_breaker_fixture(tmp_path, cascade_on_block=True)
    try:
        wf = f.writer
        result = await f.breaker.handle_block_decision(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=1,
            cascade_on_block=True,
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result is None

        # No stalled-state row.
        rows = await fetch_all(
            wf.database,
            "SELECT scope_id FROM gate_stalled_state WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert rows == []
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Boundary: a different scope is unaffected by another scope's trip.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-034")
@pytest.mark.asyncio
async def test_trip_scoped_per_scope_id(tmp_path: Path) -> None:
    """Tripping scope A does NOT block submissions on scope B."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Make a sibling scope id.
        scope_b = str(uuid.uuid4())
        # Trip A.
        await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("X",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        # B is silent.
        await f.breaker.assert_not_stalled(scope_type="run", scope_id=scope_b)
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Boundary: load_gate_config returns None for unknown gate.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-030")
@pytest.mark.asyncio
async def test_load_gate_config_returns_none_for_unknown_gate(
    tmp_path: Path,
) -> None:
    """load_gate_config returns None when no gates row matches."""
    from relay_gate_engine import load_gate_config

    f = await setup_circuit_breaker_fixture(tmp_path, seed_gate_row=False)
    try:
        cfg = await load_gate_config(
            f.writer.database, gate_id=str(uuid.uuid4())
        )
        assert cfg is None
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Cross-gate cap configurability (VAL-W8-031 surface contact).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-031")
@pytest.mark.asyncio
async def test_load_gate_config_returns_configured_cap(tmp_path: Path) -> None:
    """A gate with a non-default cap roundtrips through load_gate_config."""
    f = await setup_circuit_breaker_fixture(
        tmp_path, seed_gate_row=False, remediation_round_cap=5
    )
    try:
        wf = f.writer
        gate_3 = str(uuid.uuid4())
        await seed_gate(
            wf.database,
            gate_id=gate_3,
            name="cap-3-gate",
            remediation_round_cap=3,
        )
        from relay_gate_engine import load_gate_config

        cfg = await load_gate_config(wf.database, gate_id=gate_3)
        assert cfg is not None
        assert cfg.remediation_round_cap == 3
    finally:
        await f.writer.database.close()
