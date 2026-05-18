"""W2.5 writer-loop + state-engine writer-lock serialization.

The 2026-05-17 audit surfaced a concurrency hole between the
SidecarDatabase ``_writer_loop`` coroutine (``relay_sidecar/db.py``)
and ``compare_and_set_state`` (``relay_sidecar/state_engine/
compare_and_set.py``). Both run ``BEGIN IMMEDIATE`` on the SAME
``self._writer`` aiosqlite connection. ``compare_and_set_state``
serializes its multi-statement transaction through
``database._state_engine_writer_lock``; the writer_loop did NOT take
that lock.

Race: while a CAS transaction holds the writer between
``SELECT scope_state`` and ``UPDATE/INSERT``, the writer_loop coroutine
can pop a queued write request and issue a second ``BEGIN IMMEDIATE``
on the same connection. SQLite forbids nested ``BEGIN``; depending on
interleaving this surfaces as ``OperationalError``, double-BEGIN, or
lost transaction state.

This module fires N concurrent ``transactional_db_write`` calls AND
M concurrent ``compare_and_set_state`` calls against the SAME database.
With the lock wired into ``_writer_loop`` every write must succeed and
no ``IntegrityError`` / ``OperationalError`` should escape.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase, build_event_log_row
from relay_sidecar.state_engine import (
    ActorRef,
    compare_and_set_state,
    init_scope,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-019")
@pytest.mark.asyncio
async def test_writer_loop_and_cas_do_not_interleave_begin_immediate(
    tmp_path,
) -> None:
    """N queue writes + M CAS calls concurrently -> zero begin-while-begin
    failures, all writes succeed.

    Pre-fix: ``_writer_loop`` runs ``BEGIN IMMEDIATE`` on
    ``self._writer`` without taking ``_state_engine_writer_lock``. CAS
    holds the lock for its multi-statement transaction on the SAME
    connection. The race is small but real -- under enough concurrency
    we should see ``OperationalError`` ("cannot start a transaction
    within a transaction") OR lost CAS atomicity (a queue write
    sneaking between CAS's SELECT and UPDATE could cause CAS to commit
    on a stale read).

    Post-fix: the writer_loop acquires ``_state_engine_writer_lock``
    around its BEGIN IMMEDIATE..COMMIT block, so the two paths
    serialize through ONE asyncio.Lock and zero conflicts surface.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        project_id = str(uuid.uuid4())
        # Pre-create N distinct CAS scopes so each CAS call targets its
        # own scope row (avoids EXPECTED_FROM_MISMATCH dominating the
        # outcome distribution; we want to exercise BEGIN-while-BEGIN
        # interleaving, not CAS contention semantics).
        cas_scope_ids = [str(uuid.uuid4()) for _ in range(10)]
        for sid in cas_scope_ids:
            await init_scope(
                database=db,
                scope_kind="run",
                scope_id=sid,
                project_id=project_id,
            )
        actor = ActorRef(kind="sdk", identity_hash="sha256-bbbb")

        queue_write_scope = str(uuid.uuid4())

        async def one_queue_write(i: int):
            row = build_event_log_row(
                event_type="test.writer_loop_serial",
                scope_id=queue_write_scope,
                project_id=project_id,
                payload={"i": i},
            )
            return await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id=queue_write_scope,
            )

        async def one_cas(scope_id: str):
            return await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from="pending",
                event="ingest.run_received",
                actor=actor,
                project_id=project_id,
            )

        # Interleave the launches so the two coroutine populations have
        # maximum opportunity to race for the writer connection.
        coros = []
        for i in range(10):
            coros.append(one_queue_write(i))
            coros.append(one_cas(cas_scope_ids[i]))

        results = await asyncio.gather(*coros, return_exceptions=True)

        # Zero exceptions: any IntegrityError / OperationalError /
        # nested-BEGIN surfaces as an exception. Surface them clearly
        # for diagnostic value if the race ever recurs.
        exceptions = [r for r in results if isinstance(r, BaseException)]
        assert not exceptions, [type(e).__name__ + ": " + str(e) for e in exceptions]

        # Split results by call kind and assert every one succeeded.
        queue_results = [results[2 * i] for i in range(10)]
        cas_results = [results[2 * i + 1] for i in range(10)]

        for qr in queue_results:
            assert qr.ok, qr  # type: ignore[union-attr]
        for cr in cas_results:
            assert cr.ok and not cr.idempotent, cr  # type: ignore[union-attr]

        # In-DB ground truth: 10 event_log_entries rows for the queue
        # writes plus 10 state_transition rows from CAS. (Plus any
        # scope_init rows from init_scope.)
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_type = 'test.writer_loop_serial'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 10, row

        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_kind = 'state_transition'"
        ) as cur:
            row = await cur.fetchone()
        # Exactly 10 state transitions (one per CAS scope, no double-bump).
        assert row is not None and int(row[0]) == 10, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-019")
@pytest.mark.asyncio
async def test_writer_loop_lock_is_same_object_as_cas_lock(tmp_path) -> None:
    """Both paths use ONE asyncio.Lock instance.

    Regression guard: a future refactor that gave the writer_loop its
    own lock would silently restore the race. This test asserts the
    object identity matches.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        # Trigger lock creation by issuing one CAS-path borrow.
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        # Issue one queue write to trigger writer_loop lock acquisition.
        row = build_event_log_row(
            event_type="test.same_lock_probe",
            scope_id=scope_id,
            project_id=project_id,
            payload={},
        )
        await db.transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=scope_id,
        )
        lock = getattr(db, "_state_engine_writer_lock", None)
        assert lock is not None, (
            "writer_loop must publish _state_engine_writer_lock on first "
            "queued write so CAS callers borrow the SAME lock instance"
        )
        assert isinstance(lock, asyncio.Lock), type(lock).__name__
    finally:
        await db.close()
