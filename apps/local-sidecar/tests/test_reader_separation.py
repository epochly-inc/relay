"""VAL-W2-023: Reads use separate connection from writes.

The sidecar MUST maintain at least 2 aiosqlite connections: one writer
(queued, serialised) and one or more reader connections. Asserted by
counting ``aiosqlite.connect`` calls during startup (expected >= 2) and
by issuing ``PRAGMA query_only`` on every reader connection and
verifying the value is 1.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import uuid

import pytest
from relay_sidecar.db import SidecarDatabase


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-023")
@pytest.mark.asyncio
async def test_default_pool_has_at_least_two_connections(tmp_path) -> None:
    """Default pool: 1 writer + 2 readers -> >= 2 aiosqlite.connect calls."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db")  # default reader_count=2
    try:
        await db.open()
        assert db.connect_call_count >= 2, db.connect_call_count
        assert db.reader_count >= 1, db.reader_count
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-023")
@pytest.mark.asyncio
async def test_reader_connections_have_query_only_pragma(tmp_path) -> None:
    """Every reader reports PRAGMA query_only = 1."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=3)
    try:
        await db.open()
        for i in range(db.reader_count):
            reader = db.acquire_reader()
            async with reader.execute("PRAGMA query_only") as cur:
                row = await cur.fetchone()
                assert row is not None, f"reader[{i}] returned no row"
                assert int(row[0]) == 1, (
                    f"reader[{i}] query_only={row[0]} (expected 1)"
                )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-023")
@pytest.mark.asyncio
async def test_reader_cannot_write(tmp_path) -> None:
    """Attempting a write on a reader connection raises OperationalError."""
    import sqlite3

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        reader = db.acquire_reader()
        # PRAGMA query_only = 1 blocks every write. Attempting an INSERT
        # raises OperationalError "attempt to write a readonly database".
        with pytest.raises(sqlite3.OperationalError) as exc_info:
            await reader.execute(
                "INSERT INTO event_log_entries (event_id, project_id, "
                "scope_type, scope_id, event_type, actor_kind, "
                "occurred_at, ingest_sequence) VALUES (?, ?, ?, ?, ?, ?, "
                "?, ?)",
                (
                    str(uuid.uuid4()),
                    "00000000-0000-0000-0000-000000000000",
                    "other",
                    str(uuid.uuid4()),
                    "test.reader_write_blocked",
                    "control_plane",
                    "2026-05-13T00:00:00Z",
                    0,
                ),
            )
        assert "readonly" in str(exc_info.value).lower() or "write" in str(
            exc_info.value
        ).lower(), str(exc_info.value)
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-023")
@pytest.mark.asyncio
async def test_writer_can_write_concurrent_with_reader(tmp_path) -> None:
    """Writer writes succeed while a reader runs in parallel."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=2)
    try:
        await db.open()
        # Issue a read on one reader; doesn't block the writer.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries"
        ) as cur:
            row = await cur.fetchone()
            assert row is not None
            assert int(row[0]) == 0

        # Now a write through the writer succeeds.
        from relay_sidecar.db import build_event_log_row

        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        row = build_event_log_row(
            event_type="test.parallel_read_write",
            scope_id=scope_id,
            project_id=project_id,
        )
        result = await db.transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=scope_id,
        )
        assert result.ok
        assert result.ingest_sequence == 0
    finally:
        await db.close()
