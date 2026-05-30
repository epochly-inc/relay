"""VAL-ISO-028: INVALID_TRANSITION forensic log row MUST be durably recorded.

Defect (base commit c911607): on an unknown transition the engine ROLLBACKs
the parent transaction (compare_and_set.py:448), THEN runs the anti-bypass
``screen_payload`` / ``maybe_spillover`` step, THEN opens a brand-new
``BEGIN IMMEDIATE`` (line 510) to INSERT the ``state.invalid_transition``
forensic row. Two consequences:

  1. If the merged payload trips the anti-bypass screen (caller payload
     contains a bypass marker), the canonical INVALID_TRANSITION verdict is
     returned but NO forensic ``event_log_entries`` row is committed -- the
     invalid transition goes entirely unaudited (audit invariant violated).
  2. Because the forensic row lives in a SEPARATE transaction issued after
     the parent ROLLBACK, any secondary failure between rollback and the
     secondary COMMIT silently loses the forensic row.

Fix: compute and validate ``full_payload``/``screen_payload`` BEFORE the
parent ROLLBACK so the forensic INSERT is part of a SINGLE transaction, and
durably record a (sanitized) forensic row even when the caller payload trips
the screen. The invalid-transition decision is always logged.

These tests are RED at base commit c911607 and GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION,
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


async def _count_invalid_transition_rows(
    db: SidecarDatabase, scope_id: str
) -> int:
    conn = db.acquire_reader()
    async with conn.execute(
        "SELECT COUNT(*) FROM event_log_entries "
        "WHERE scope_id = ? AND event_kind = 'state_invalid_transition'",
        (scope_id,),
    ) as cur:
        row = await cur.fetchone()
    return int(row[0]) if row is not None else 0


async def _fetch_invalid_transition_payloads(
    db: SidecarDatabase, scope_id: str
) -> list[dict[str, object]]:
    conn = db.acquire_reader()
    async with conn.execute(
        "SELECT payload FROM event_log_entries "
        "WHERE scope_id = ? AND event_kind = 'state_invalid_transition'",
        (scope_id,),
    ) as cur:
        rows = await cur.fetchall()
    out: list[dict[str, object]] = []
    for (payload_text,) in rows:
        out.append(json.loads(payload_text))
    return out


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_invalid_transition_forensic_row_durable_on_clean_screen(
    tmp_path,
) -> None:
    """A clean INVALID_TRANSITION durably records exactly one forensic row.

    Baseline behaviour: the row is committed in a separate transaction. This
    test asserts the row is present after the call returns, which is the
    durability contract the fix preserves within a single transaction.
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
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
            payload={"some_field": "ordinary value"},
        )

        assert result.ok is False
        assert result.reason == INVALID_TRANSITION
        assert result.event_id is not None
        assert await _count_invalid_transition_rows(db, scope_id) == 1
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_invalid_transition_forensic_row_durable_when_payload_trips_screen(
    tmp_path,
) -> None:
    """When the caller payload trips the anti-bypass screen, the invalid
    transition MUST STILL be durably recorded in event_log_entries.

    Base-commit defect: the screen rejection short-circuits with a structured
    ``secondary_error_reason`` and NO forensic row is committed -- the invalid
    transition is entirely unaudited. The fix records a sanitized forensic row
    (engine-supplied fields only, with a screen-rejection note) so the audit
    invariant ("every decision logged") holds.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-dddd")

        # Caller payload carries a bypass marker -> screen_payload rejects.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
            payload={"note": "fix later # TODO clean this up"},
        )

        # Canonical verdict preserved.
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION

        # The invalid transition is durably audited despite the screen reject.
        rows = await _fetch_invalid_transition_payloads(db, scope_id)
        assert len(rows) == 1, (
            "invalid transition must be durably recorded even when the caller "
            "payload trips the anti-bypass screen"
        )
        # Sanitized: the engine-supplied verdict fields are present...
        forensic = rows[0]
        assert forensic.get("rejected_reason") == INVALID_TRANSITION
        assert forensic.get("event") == "not.a.real.event"
        # ...and the offending caller payload (which carried the marker) is
        # NOT spliced verbatim into the durable row.
        scannable = json.dumps(forensic, sort_keys=True, separators=(",", ":"))
        assert "# TODO" not in scannable
    finally:
        await db.close()
