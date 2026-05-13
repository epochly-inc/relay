"""VAL-W2-017: PRAGMA journal_mode=wal persists across connections + restarts.

After first sidecar startup, ``PRAGMA journal_mode`` MUST return ``wal``
on every subsequent connection. Test opens fresh aiosqlite connections
AND simulates a sidecar restart by closing the SidecarDatabase and
opening a new one against the same DB file.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import aiosqlite
import pytest
from relay_sidecar.db import SidecarDatabase


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-017")
@pytest.mark.asyncio
async def test_journal_mode_wal_on_fresh_connection(tmp_path) -> None:
    """A freshly opened aiosqlite connection to the same DB sees wal."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=2)
    try:
        await db.open()
        # Open a completely new connection (not via the manager) and
        # confirm WAL persists.
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute("PRAGMA journal_mode") as cur,
        ):
            row = await cur.fetchone()
            assert row is not None
            assert str(row[0]).lower() == "wal", row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-017")
@pytest.mark.asyncio
async def test_journal_mode_persists_across_sidecar_restart(tmp_path) -> None:
    """Close and re-open the SidecarDatabase; WAL must still report wal."""
    db_path = tmp_path / "sidecar.db"
    db1 = SidecarDatabase(db_path=db_path, reader_count=1)
    await db1.open()
    await db1.close()

    db2 = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db2.open()
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute("PRAGMA journal_mode") as cur,
        ):
            row = await cur.fetchone()
            assert row is not None
            assert str(row[0]).lower() == "wal", row
    finally:
        await db2.close()
