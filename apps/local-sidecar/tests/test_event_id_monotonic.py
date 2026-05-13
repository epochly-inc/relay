"""VAL-W2-041: event_id is unique and ingest_sequence is strictly monotonic.

Seeds N events from concurrent writers through the canonical
``transactional_db_write`` primitive and asserts:

  - COUNT(DISTINCT event_id) == COUNT(*) -- no duplicate UUIDs.
  - ORDER BY ingest_sequence -- strictly increasing, no gaps.

The W2.3 writer queue serializes inserts through one coroutine; the
ingest_sequence is computed atomically inside each BEGIN IMMEDIATE
transaction via SELECT COALESCE(MAX(ingest_sequence), -1) + 1 (db.py:584-589).

This test uses 1000 concurrent writers (not 10000) to keep the tier-1
plumbing budget under 60s; the invariant is identical at any N.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
from relay_sidecar.db import SidecarDatabase, build_event_log_row
from relay_sidecar.primitives.transactional_db_write import (
    set_active_database,
    transactional_db_write,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-041")
def test_event_id_unique_and_sequence_monotonic(tmp_path: Path) -> None:
    """N concurrent writers produce unique event_ids and monotonic sequences."""
    N = 1000

    async def _run() -> None:
        db = SidecarDatabase(
            db_path=tmp_path / "sidecar.db",
            reader_count=2,
            queue_maxsize=N * 2,
        )
        await db.open()
        set_active_database(db)
        try:
            scope_id = str(uuid.uuid4())
            project_id = str(uuid.uuid4())

            async def _one_write(i: int) -> int:
                row = build_event_log_row(
                    event_type="test.concurrent",
                    scope_id=scope_id,
                    project_id=project_id,
                    payload={"_blob_sha256": "x" * 64, "i": i},
                    event_kind="concurrent_seed",
                )
                wr = await transactional_db_write(
                    table="event_log_entries",
                    row=row,
                    scope_id=scope_id,
                )
                return wr.ingest_sequence

            sequences = await asyncio.gather(
                *[_one_write(i) for i in range(N)]
            )
            assert len(sequences) == N

            reader = db.acquire_reader()
            # COUNT(DISTINCT event_id) == COUNT(*)
            async with reader.execute(
                "SELECT COUNT(DISTINCT event_id) FROM event_log_entries "
                "WHERE event_kind = 'concurrent_seed'"
            ) as cur:
                (distinct,) = await cur.fetchone()
            async with reader.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_kind = 'concurrent_seed'"
            ) as cur:
                (total,) = await cur.fetchone()
            assert distinct == total == N, (distinct, total, N)

            # ORDER BY ingest_sequence -- strictly increasing, no gaps.
            async with reader.execute(
                "SELECT ingest_sequence FROM event_log_entries "
                "WHERE event_kind = 'concurrent_seed' "
                "ORDER BY ingest_sequence ASC"
            ) as cur:
                rows = await cur.fetchall()
            seq_list = [r[0] for r in rows]
            assert len(seq_list) == N
            for i in range(1, len(seq_list)):
                assert seq_list[i] == seq_list[i - 1] + 1, (
                    i,
                    seq_list[i - 1],
                    seq_list[i],
                )
        finally:
            await db.close()
            set_active_database(None)

    asyncio.run(_run())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-041")
def test_event_id_unique_across_two_passes(tmp_path: Path) -> None:
    """Two sequential bursts MUST keep event_id unique across the union."""

    async def _run() -> None:
        db = SidecarDatabase(
            db_path=tmp_path / "sidecar.db",
            reader_count=1,
            queue_maxsize=200,
        )
        await db.open()
        set_active_database(db)
        try:
            scope_id = str(uuid.uuid4())
            project_id = str(uuid.uuid4())

            async def _one_write(i: int) -> int:
                row = build_event_log_row(
                    event_type="test.burst",
                    scope_id=scope_id,
                    project_id=project_id,
                    payload={"_blob_sha256": "x" * 64, "i": i},
                    event_kind="burst",
                )
                wr = await transactional_db_write(
                    table="event_log_entries",
                    row=row,
                    scope_id=scope_id,
                )
                return wr.ingest_sequence

            BURST = 50
            await asyncio.gather(*[_one_write(i) for i in range(BURST)])
            await asyncio.gather(*[_one_write(i) for i in range(BURST)])

            reader = db.acquire_reader()
            async with reader.execute(
                "SELECT COUNT(DISTINCT event_id), COUNT(*) FROM event_log_entries "
                "WHERE event_kind = 'burst'"
            ) as cur:
                distinct, total = await cur.fetchone()
            assert distinct == total == 2 * BURST, (distinct, total)
        finally:
            await db.close()
            set_active_database(None)

    asyncio.run(_run())
