"""Shared helpers for W8.4 gate-circuit-breaker plumbing tests.

Builds on the W8.2 ``setup_writer_fixture`` to seed a SidecarDatabase
that has gates, evidence bundles, gate_rounds, and (optionally) a
stalled-state row so the circuit-breaker + admin-action coordinators
have a populated DB to operate against.

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
    make_bundle_inputs,
    setup_writer_fixture,
)
from relay_gate_engine import (
    SCHEMA_GATE_ROUND,
    STALLED_REASON_CAP_EXCEEDED,
    AdminActionService,
    CircuitBreaker,
    EvidenceBundleInputs,
)
from relay_sidecar.db import SidecarDatabase


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def seed_gate(
    db: SidecarDatabase,
    *,
    gate_id: str,
    name: str = "test-gate",
    scope_type: str = "run",
    remediation_round_cap: int = 5,
    cascade_on_block: bool = True,
    project_id: str = "00000000-0000-0000-0000-000000000000",
) -> None:
    """Insert one ``gates`` row directly via aiosqlite."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO gates ("
            "  gate_id, project_id, name, scope_type, "
            "  remediation_round_cap, cascade_on_block, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                gate_id,
                project_id,
                name,
                scope_type,
                int(remediation_round_cap),
                1 if cascade_on_block else 0,
                _ts(datetime.now(UTC)),
            ),
        )
        await conn.commit()


async def try_seed_gate(
    db: SidecarDatabase,
    *,
    gate_id: str,
    remediation_round_cap: int,
    name: str | None = None,
) -> None:
    """Insert one ``gates`` row; lets aiosqlite raise on CHECK failure."""
    await seed_gate(
        db,
        gate_id=gate_id,
        name=name or f"gate-{gate_id[:8]}",
        remediation_round_cap=remediation_round_cap,
    )


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
    """Insert one ``gate_rounds`` row directly. Returns gate_round_id."""
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


async def seed_evidence_bundle(
    db: SidecarDatabase,
    *,
    manifest_commit_hash: str,
    bundle_id: str | None = None,
    inputs: EvidenceBundleInputs | None = None,
) -> str:
    """Insert one ``evidence_bundles`` row. Returns the bundle_id."""
    bid = bundle_id or str(uuid.uuid4())
    if inputs is None:
        inputs = make_bundle_inputs(manifest_commit_hash=manifest_commit_hash)
    # Use a minimal bundle_digest placeholder; the W8.2 writer normally
    # computes this, but seeding-side tests only need a row that
    # satisfies the CHECK constraints.
    bundle_digest = "sha256-" + ("e" * 64)
    async with aiosqlite.connect(str(db.db_path)) as conn:
        import json
        await conn.execute(
            "INSERT INTO evidence_bundles ("
            "  bundle_id, artifact_digest, command, exit_code, "
            "  span_ids, contract_assertion_ids, agent_worker_id, "
            "  manifest_commit_hash, timestamp, environment, "
            "  redaction_policy_version, bundle_digest"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                bid,
                inputs.artifact_digest,
                inputs.command,
                int(inputs.exit_code),
                json.dumps(list(inputs.span_ids)),
                json.dumps(list(inputs.contract_assertion_ids)),
                inputs.agent_worker_id,
                manifest_commit_hash,
                inputs.timestamp,
                inputs.environment,
                inputs.redaction_policy_version,
                bundle_digest,
            ),
        )
        await conn.commit()
    return bid


async def seed_stalled(
    db: SidecarDatabase,
    *,
    scope_type: str,
    scope_id: str,
    gate_id: str,
    terminal_round: int,
    reason: str = STALLED_REASON_CAP_EXCEEDED,
    reopened_at: str | None = None,
    terminated_at: str | None = None,
) -> None:
    """Insert one ``gate_stalled_state`` row directly."""
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO gate_stalled_state ("
            "  scope_type, scope_id, gate_id, terminal_round, "
            "  reason, opened_at, reopened_at, terminated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scope_type,
                scope_id,
                gate_id,
                int(terminal_round),
                reason,
                _ts(datetime.now(UTC)),
                reopened_at,
                terminated_at,
            ),
        )
        await conn.commit()


@dataclass(frozen=True)
class CircuitBreakerFixture:
    """Bundle of (writer fixture, circuit breaker, admin service)."""

    writer: WriterFixture
    breaker: CircuitBreaker
    admin: AdminActionService


async def setup_circuit_breaker_fixture(
    tmp_path: Path,
    *,
    seed_gate_row: bool = True,
    remediation_round_cap: int = 5,
    cascade_on_block: bool = True,
) -> CircuitBreakerFixture:
    """Build a writer fixture + circuit breaker + admin service.

    When ``seed_gate_row=True`` (default), a ``gates`` row is inserted
    for ``wf.gate_id`` so :func:`load_gate_config` returns a config.
    """
    wf = await setup_writer_fixture(tmp_path)
    if seed_gate_row:
        await seed_gate(
            wf.database,
            gate_id=wf.gate_id,
            name=f"gate-{wf.gate_id[:8]}",
            scope_type="run",
            remediation_round_cap=remediation_round_cap,
            cascade_on_block=cascade_on_block,
        )
    breaker = CircuitBreaker(database=wf.database)
    admin = AdminActionService(database=wf.database)
    return CircuitBreakerFixture(writer=wf, breaker=breaker, admin=admin)


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


async def fetch_one(
    db: SidecarDatabase,
    sql: str,
    params: tuple[Any, ...] = (),
) -> tuple[Any, ...] | None:
    async with (
        aiosqlite.connect(str(db.db_path)) as conn,
        conn.execute(sql, params) as cur,
    ):
        return await cur.fetchone()


async def fetch_event_log_payload(
    db: SidecarDatabase,
    *,
    event_type: str,
    scope_id: str,
) -> dict[str, Any] | None:
    """Return JSON payload of the most recent matching event row."""
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
    "CircuitBreakerFixture",
    "fetch_all",
    "fetch_event_log_payload",
    "fetch_one",
    "seed_evidence_bundle",
    "seed_gate",
    "seed_gate_round",
    "seed_stalled",
    "setup_circuit_breaker_fixture",
    "try_seed_gate",
]
