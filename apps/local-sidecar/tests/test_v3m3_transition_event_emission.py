"""VAL-V3M3-004 / VAL-V3M3-005: compare_and_set_state emits {scope_kind}.transition.

Per spec AP.5.c (planning/epochly-replay-spec.md lines 6391-6398): every
successful state transition emits exactly one row of
``event_type='<scope_kind>.transition'`` carrying
``payload.from_state``, ``payload.to_state``, and ``payload.epoch_after``.
This is in addition to the existing action event row (e.g.,
``run.captured``) emitted on the same CAS commit. The temporal-query
SQL function (m3-f03) reads these ``*.transition`` rows.

Failed transitions (INVALID_TRANSITION / GUARD_FAILED / etc.) emit ONLY
the existing ``state.invalid_transition`` audit row -- no additional
``*.transition`` row.

  VAL-V3M3-004: Successful CAS pending -> captured writes 2 rows:
                event_type='run.captured' (existing action event) and
                event_type='run.transition' (new summary) with payload
                {from_state='pending', to_state='captured', epoch_after=1}.
  VAL-V3M3-005: Failed CAS (INVALID_TRANSITION) writes ONLY the existing
                state.invalid_transition row -- NO '<scope>.transition' row.

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


async def _seed_scope(db: SidecarDatabase) -> tuple[str, str]:
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    await init_scope(
        database=db,
        scope_kind="run",
        scope_id=scope_id,
        project_id=project_id,
    )
    return scope_id, project_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-004")
@pytest.mark.asyncio
async def test_successful_transition_emits_action_and_summary_rows(tmp_path) -> None:
    """Successful CAS emits BOTH the existing action event AND a new
    '<scope_kind>.transition' summary row with from/to/epoch_after payload.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert result.ok is True, result
        assert result.new_state == "captured"
        assert result.epoch == 1

        # Two rows must be present for this scope after a single successful
        # transition: the action event (run.captured) AND the summary
        # transition row (run.transition).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT event_type, payload, ingest_sequence FROM event_log_entries "
            "WHERE scope_id = ? ORDER BY ingest_sequence ASC",
            (scope_id,),
        ) as cur:
            rows = await cur.fetchall()

        event_types = [str(r[0]) for r in rows]
        assert "run.captured" in event_types, event_types
        assert "run.transition" in event_types, event_types
        # Exactly one of each.
        assert event_types.count("run.captured") == 1, event_types
        assert event_types.count("run.transition") == 1, event_types

        # Ordering: action event first, transition summary second
        # (per task spec: same ingest_sequence ordering -- action then summary).
        action_idx = event_types.index("run.captured")
        summary_idx = event_types.index("run.transition")
        assert action_idx < summary_idx, (
            "action event must come before transition summary"
        )

        # Inspect summary payload.
        summary_payload_text = next(
            r[1] for r in rows if str(r[0]) == "run.transition"
        )
        summary_payload = json.loads(summary_payload_text)
        assert summary_payload.get("from_state") == "pending", summary_payload
        assert summary_payload.get("to_state") == "captured", summary_payload
        assert summary_payload.get("epoch_after") == 1, summary_payload
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-005")
@pytest.mark.asyncio
async def test_failed_transition_emits_no_summary_row(tmp_path) -> None:
    """Failed CAS (INVALID_TRANSITION) emits ONLY the existing
    state.invalid_transition row -- NO '<scope_kind>.transition' summary row.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        # Bogus event for the 'pending' state -> INVALID_TRANSITION.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
        )
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION

        reader = db.acquire_reader()
        # Exactly one state.invalid_transition row exists.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = ?",
            (scope_id, INVALID_TRANSITION_EVENT_TYPE),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row

        # NO '<scope_kind>.transition' summary row was written on the
        # failed path.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = 'run.transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0, row
    finally:
        await db.close()
