"""Shared test helpers for the W2.5 event-log constraint test suite.

Co-located so the test files do not need to depend on each other via
relative imports (the tests directory is not a Python package).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from relay_sidecar.db import SidecarDatabase


def seed_db(tmp_path: Path) -> Path:
    """Open + close a SidecarDatabase once to run migrations on a fresh DB."""
    db_path = tmp_path / "sidecar.db"

    async def _open_then_close() -> None:
        db = SidecarDatabase(db_path=db_path, reader_count=1)
        await db.open()
        await db.close()

    asyncio.run(_open_then_close())
    return db_path


def now_rfc3339_utc() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def direct_insert(
    db_path: Path,
    *,
    payload: dict,
    schema_version: str = "relay.event_log_entry.v1",
    event_id: str | None = None,
) -> str:
    """Raw INSERT bypassing the state engine + writer queue.

    Returns the event_id of the inserted (or attempted-insert) row.
    """
    eid = event_id if event_id is not None else str(uuid.uuid4())
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type,"
            "  scope_id, event_type, actor_kind, payload, occurred_at,"
            "  ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                eid,
                schema_version,
                str(uuid.uuid4()),
                "other",
                str(uuid.uuid4()),
                "test.event",
                "control_plane",
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                now_rfc3339_utc(),
                0,
                "test_seed",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return eid


__all__ = ["direct_insert", "now_rfc3339_utc", "seed_db"]
