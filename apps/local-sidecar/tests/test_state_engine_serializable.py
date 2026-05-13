"""VAL-W2-034: State engine transitions use SERIALIZABLE isolation.

Every ``compare_and_set_state`` write executes under BEGIN IMMEDIATE
(SQLite's equivalent of SERIALIZABLE per eng plan A2 + A5). Concurrent
state-engine writes with overlapping read sets MUST produce one success
+ N-1 EXPECTED_FROM_MISMATCH / idempotent results, never two original
successes with stale reads.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    ActorRef,
    compare_and_set_state,
    init_scope,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-034")
@pytest.mark.asyncio
async def test_concurrent_writers_one_original_success(tmp_path) -> None:
    """N=8 concurrent CAS on same scope -> exactly one ok=True non-idempotent.

    Every other call must observe state already advanced and either:
      - hit the idempotency probe (same event) and return idempotent=True, OR
      - report EXPECTED_FROM_MISMATCH if the test uses different events.
    Our test uses the SAME event so we expect (1 original) + (N-1 idempotent).
    """
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
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        async def one_call():
            return await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from="pending",
                event="ingest.run_received",
                actor=actor,
                project_id=project_id,
            )

        results = await asyncio.gather(*(one_call() for _ in range(8)))
        original_wins = [r for r in results if r.ok and not r.idempotent]
        idempotent_wins = [r for r in results if r.ok and r.idempotent]
        # Exactly one original commit (no phantom-read duplicate winner).
        assert len(original_wins) == 1, [
            (r.ok, r.idempotent, r.reason, r.new_state) for r in results
        ]
        # Every other call must be idempotent (no failures).
        assert len(idempotent_wins) == 7, len(idempotent_wins)

        # scope_state epoch is exactly 1 -- single original commit, no double-bump.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-034")
@pytest.mark.asyncio
async def test_concurrent_writers_different_events_no_two_successes(
    tmp_path,
) -> None:
    """Two callers with DIFFERENT events from pending -> only one event is in YAML.

    The 'run' scope at 'pending' allows only ingest.run_received. A second
    caller with a different event hits INVALID_TRANSITION, never produces
    a state advance. So even with race conditions there's exactly one
    state-state advance.
    """
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
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        async def with_event(event: str):
            return await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from="pending",
                event=event,
                actor=actor,
                project_id=project_id,
            )

        results = await asyncio.gather(
            with_event("ingest.run_received"),
            with_event("not.a.real.event"),
        )
        ok_results = [r for r in results if r.ok]
        # At most one ok=True (the valid event). The invalid one fails.
        assert len(ok_results) == 1, ok_results
        # The state advanced exactly once.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT epoch, state FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert int(row[0]) == 1, row
        assert row[1] == "captured", row
    finally:
        await db.close()
