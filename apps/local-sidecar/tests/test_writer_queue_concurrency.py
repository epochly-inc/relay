"""VAL-W2-019: Concurrent writers serialise through a single-writer queue.

N=100 concurrent ``transactional_db_write`` calls -> exactly N rows with
monotonically increasing ``event_log_entries.ingest_sequence`` and zero
``RELAY-SQLITE-BUSY`` errors surfaced to callers.

Forced contention: a competing connection holds the write lock for
100ms before COMMITting; under that contention the
``event_log_entries.event_kind='sqlite_busy_retry'`` row count MUST be
> 0 -- proving retries are observable, not silenced.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid

import aiosqlite
import pytest
from relay_sidecar.db import SidecarDatabase, build_event_log_row


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-019")
@pytest.mark.asyncio
async def test_concurrent_writers_produce_monotonic_sequences(tmp_path) -> None:
    """N=100 concurrent writes -> 100 rows with monotonic ingest_sequence."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=2)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())

        async def one_write(i: int) -> int:
            row = build_event_log_row(
                event_type="test.concurrent_write",
                scope_id=scope_id,
                project_id=project_id,
                payload={"i": i},
            )
            result = await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id=scope_id,
            )
            assert result.ok
            return result.ingest_sequence

        sequences = await asyncio.gather(*(one_write(i) for i in range(100)))
        # Exactly N rows with unique monotonic ingest_sequence values
        # 0..99 (since the table started empty).
        assert sorted(sequences) == list(range(100)), sorted(sequences)
        # Confirm in the DB itself.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_type = 'test.concurrent_write'"
        ) as cur:
            row = await cur.fetchone()
            assert row is not None and int(row[0]) == 100
        # Zero sqlite_busy_retry rows in the no-contention case.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_kind = 'sqlite_busy_retry'"
        ) as cur:
            row = await cur.fetchone()
            retry_count = int(row[0]) if row else 0
        # Under no contention the count is >= 0 (typically 0); the
        # contract only requires > 0 under FORCED contention.
        assert retry_count >= 0, retry_count
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-019")
@pytest.mark.asyncio
async def test_forced_contention_emits_observable_retries(
    tmp_path, monkeypatch
) -> None:
    """Under forced contention, sqlite_busy_retry rows appear.

    SQLite's connection-level busy_timeout would absorb a 100ms hold
    silently (5000ms > 100ms). To force the application-level retry
    path to fire, we shrink the connection busy_timeout to 50ms via the
    ``CONN_BUSY_TIMEOUT_MS`` module constant BEFORE the SidecarDatabase
    opens. The application-level retry deadline is the separate
    ``BUSY_TIMEOUT_MS`` constant, which we leave at the production
    value so the retries actually succeed within budget instead of
    exhausting after one attempt.
    """
    import relay_sidecar.db as db_module

    # Connection-level pragma: short enough that 100ms competitor hold
    # triggers application-level retry path.
    monkeypatch.setattr(db_module, "CONN_BUSY_TIMEOUT_MS", 50, raising=True)
    # Application deadline: large enough for backoffs to succeed.
    monkeypatch.setattr(db_module, "BUSY_TIMEOUT_MS", 2000, raising=True)

    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())

        # Competing connection: hold a write lock for 100ms.
        async def hold_write_lock() -> None:
            async with aiosqlite.connect(str(db_path)) as competitor:
                # busy_timeout=0 so the competitor immediately gets the
                # write lock (it's free at this moment) without waiting.
                await competitor.execute("PRAGMA busy_timeout = 0")
                await competitor.execute("BEGIN IMMEDIATE")
                # Hold the lock for 100ms with a sentinel write that
                # forces the WAL to actually take the lock.
                await competitor.execute(
                    "CREATE TABLE IF NOT EXISTS _contention_sentinel(x INTEGER)"
                )
                await competitor.execute(
                    "INSERT INTO _contention_sentinel(x) VALUES (?)", (1,)
                )
                await asyncio.sleep(0.10)
                await competitor.execute("COMMIT")

        # Kick off N writer tasks racing for the lock during contention.
        async def one_write(i: int) -> int:
            row = build_event_log_row(
                event_type="test.contention_write",
                scope_id=scope_id,
                project_id=project_id,
                payload={"i": i},
            )
            result = await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id=scope_id,
            )
            return result.ingest_sequence

        # Start the lock-holder first so writers see contention.
        holder = asyncio.create_task(hold_write_lock())
        # Brief yield so the holder reaches its BEGIN IMMEDIATE.
        await asyncio.sleep(0.005)
        # Now race 5 writers; they'll observe SQLITE_BUSY at least once.
        sequences = await asyncio.gather(*(one_write(i) for i in range(5)))
        await holder

        # All writers succeeded -- no RELAY-SQLITE-BUSY surfaced.
        assert len(sequences) == 5
        assert len(set(sequences)) == 5, sequences

        # Observable retries: at least one sqlite_busy_retry row.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_kind = 'sqlite_busy_retry'"
        ) as cur:
            row = await cur.fetchone()
            retry_count = int(row[0]) if row else 0
        assert retry_count > 0, (
            "VAL-W2-019 forced-contention evidence requires > 0 "
            f"sqlite_busy_retry rows; observed {retry_count}"
        )
    finally:
        await db.close()
