"""VAL-W2-035: Every successful transition emits exactly one event_log_entries row.

After N successful transitions, the row count for that scope's
state_transition rows MUST equal N. Failures (INVALID_TRANSITION, etc.)
MUST NOT emit a state_transition row -- they emit a separate
state.invalid_transition row (event_kind='state_invalid_transition').

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION_EVENT_TYPE,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-035")
@pytest.mark.asyncio
async def test_one_event_per_successful_transition(tmp_path) -> None:
    """Walk pending->captured->validating->gated; assert one row per step."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )

        steps = [
            ("pending", "ingest.run_received", "sdk"),
            ("captured", "validation.start", "ingest_worker"),
            ("validating", "validation.complete", "validation_worker"),
        ]
        for expected_from, event, actor_kind in steps:
            result = await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from=expected_from,
                event=event,
                actor=ActorRef(kind=actor_kind, identity_hash="sha256-aaaa"),
                project_id=project_id,
            )
            assert result.ok is True, (expected_from, event, result)

        # Exactly 3 state_transition rows for this scope.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 3, row

        # event_ids are globally unique.
        async with reader.execute(
            "SELECT COUNT(DISTINCT event_id) FROM event_log_entries "
            "WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            distinct = await cur.fetchone()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            total = await cur.fetchone()
        assert distinct is not None and total is not None
        assert int(distinct[0]) == int(total[0]), (distinct[0], total[0])
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-035")
@pytest.mark.asyncio
async def test_failure_does_not_emit_state_transition_row(tmp_path) -> None:
    """INVALID_TRANSITION emits a state.invalid_transition row, NOT state_transition."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )

        # Force invalid transition.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="completely.bogus.event",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert result.ok is False

        reader = db.acquire_reader()
        # Zero state_transition rows.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0, row

        # Exactly one state.invalid_transition row.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = ?",
            (scope_id, INVALID_TRANSITION_EVENT_TYPE),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        await db.close()
