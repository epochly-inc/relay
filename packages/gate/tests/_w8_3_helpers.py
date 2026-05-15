"""Shared helpers for W8.3 gate-restart plumbing tests.

Builds on the W8.2 ``setup_writer_fixture`` to seed a database that has
a resolved prior round (gate_rounds row + recorded gate_round_inputs)
so the restart coordinator has something to restart FROM.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
from _w8_2_helpers import (
    WriterFixture,
    setup_writer_fixture,
)
from relay_gate_engine import (
    SCHEMA_GATE_ROUND,
    RestartCoordinator,
)
from relay_sidecar.db import SidecarDatabase


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def seed_gate_round(
    db: SidecarDatabase,
    *,
    scope_type: str,
    scope_id: str,
    round_: int,
    initiated_by: str = "submission",
    restart_predecessor: str | None = None,
    gate_decision_id: str | None = None,
) -> str:
    """Insert one gate_rounds row directly. Returns gate_round_id."""
    gate_round_id = str(uuid.uuid4())
    now = _ts(datetime.now(UTC))
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO gate_rounds ("
            "  gate_round_id, schema_version, scope_type, scope_id, "
            "  round, initiated_by, restart_predecessor, "
            "  gate_decision_id, opened_at, closed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                gate_round_id,
                SCHEMA_GATE_ROUND,
                scope_type,
                scope_id,
                int(round_),
                initiated_by,
                restart_predecessor,
                gate_decision_id,
                now,
                now,
            ),
        )
        await conn.commit()
    return gate_round_id


async def seed_extra_draft(
    db: SidecarDatabase,
    *,
    draft_id: str,
    gate_id: str,
    scope_type: str,
    scope_id: str,
    round_: int,
    worker_id: str,
    actor_identity_hash: str,
    manifest_commit_hash: str,
    resolution_state: str = "pending",
    release_sha: str | None = None,
) -> None:
    """Insert one gate_decision_drafts row with a configurable resolution_state."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO gate_decision_drafts "
            "(draft_id, gate_id, scope_type, scope_id, round, worker_id, "
            " manifest_commit_hash, actor_identity_hash, submitted_at, "
            " resolution_state, release_sha) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                draft_id,
                gate_id,
                scope_type,
                scope_id,
                int(round_),
                worker_id,
                manifest_commit_hash,
                actor_identity_hash,
                _ts(datetime.now(UTC)),
                resolution_state,
                release_sha,
            ),
        )
        await conn.commit()


@dataclass(frozen=True)
class RestartFixture:
    """Bundle of (writer fixture, coordinator, seeded prior round)."""

    writer: WriterFixture
    coordinator: RestartCoordinator
    prior_gate_round_id: str
    prior_round: int


async def setup_restart_fixture(
    tmp_path: Path,
    *,
    seed_prior_round: bool = True,
) -> RestartFixture:
    """Build a W8.3 fixture: writer + coordinator + a seeded prior round.

    The prior round is seeded as ``round=1, initiated_by='submission'`` so
    a restart will open ``round=2, initiated_by='remediation'``.
    """
    wf = await setup_writer_fixture(tmp_path)
    coordinator = RestartCoordinator(database=wf.database)
    prior_gate_round_id = ""
    prior_round = wf.round_
    if seed_prior_round:
        prior_gate_round_id = await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=prior_round,
        )
    return RestartFixture(
        writer=wf,
        coordinator=coordinator,
        prior_gate_round_id=prior_gate_round_id,
        prior_round=prior_round,
    )


async def fetch_all(
    db: SidecarDatabase,
    sql: str,
    params: tuple[Any, ...] = (),
) -> list[tuple[Any, ...]]:
    async with (
        aiosqlite.connect(str(db.db_path)) as conn,
        conn.execute(sql, params) as cur,
    ):
        rows = await cur.fetchall()
    return [tuple(r) for r in rows]


async def fetch_event_log_payload(
    db: SidecarDatabase,
    *,
    event_type: str,
    scope_id: str,
) -> dict[str, Any] | None:
    """Return the JSON payload of the most recent matching event row."""
    rows = await fetch_all(
        db,
        "SELECT payload FROM event_log_entries "
        "WHERE event_type = ? AND scope_id = ? "
        "ORDER BY ingest_sequence DESC LIMIT 1",
        (event_type, str(scope_id)),
    )
    if not rows:
        return None
    import json

    return json.loads(rows[0][0])


__all__ = [
    "RestartFixture",
    "fetch_all",
    "fetch_event_log_payload",
    "seed_extra_draft",
    "seed_gate_round",
    "setup_restart_fixture",
]
