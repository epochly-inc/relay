"""VAL-V3M3-006/007/008/010: reconstruct_scope_state_at temporal query.

Per spec section AP.5.a (planning/epochly-replay-spec.md lines 6273-6336):
the canonical Postgres profile ships a STABLE PL/pgSQL function
``reconstruct_scope_state_at(scope_kind, scope_id, at)`` that replays the
``event_log_entries`` ``*.transition`` rows up to timestamp T to derive the
state machine state of any scope at any past instant.

The OSS SQLite sidecar cannot host PL/pgSQL, so this milestone also ships
a Python equivalent helper
``relay_sidecar.state_engine.temporal_query.reconstruct_scope_state_at_local``
that reads the SQLite event_log_entries mirror and applies the same
algorithm. The two tiers are required to return the same
``(state, epoch_at_t, last_event_type)`` triple for any common input
(VAL-V3M3-009 parity is asserted in
``packages/schemas/python/tests/test_v3m3_temporal_query_parity.py``).

This file covers the SQLite half:

  VAL-V3M3-006  Postgres migration 0017_v3_temporal_query.sql exists and
                carries the spec function verbatim (text-level grep).
  VAL-V3M3-007  Migration also adds the supporting index
                event_log_entries(scope_kind, scope_id, occurred_at,
                ingest_sequence) on the canonical column names declared in
                packages/schemas/sql/0002_control_plane.sql.
  VAL-V3M3-008  reconstruct_scope_state_at_local replays three sequential
                transitions; querying at t1 returns the t1 state and
                querying at t3 returns the final state.
  VAL-V3M3-010  Querying before the scope existed returns None
                (spec line 6291 "RETURN" with no value).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine.temporal_query import (
    TemporalScopeStateRow,
    reconstruct_scope_state_at_local,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PG_MIGRATION = (
    _REPO_ROOT / "packages" / "schemas" / "sql" / "0017_v3_temporal_query.sql"
)


def _ts(at: datetime) -> str:
    """RFC 3339 UTC with explicit ``Z`` offset (matches sidecar storage)."""
    return at.isoformat(timespec="microseconds").replace("+00:00", "Z")


async def _insert_event(
    db: SidecarDatabase,
    *,
    project_id: str,
    scope_type: str,
    scope_id: str,
    event_type: str,
    payload: dict[str, object],
    occurred_at: str,
    ingest_sequence: int,
    event_kind: str = "state_transition_summary",
) -> str:
    """Direct INSERT helper for tests only.

    This path bypasses the state engine because the tests seed historical
    rows at arbitrary past timestamps; the production write path always
    stamps ``now()``. Lives in the test module and is the documented
    test-only seed pattern per the test_event_log_*.py precedents in this
    directory. Opens a short-lived aiosqlite connection against the same
    file (SQLite WAL mode admits concurrent readers + a second writer
    serialised through SQLite-level locking).
    """
    import aiosqlite

    event_id = str(uuid.uuid4())
    payload_text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type, "
            "  scope_id, event_type, actor_kind, actor_id, "
            "  manifest_commit_hash, payload, occurred_at, "
            "  ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                "relay.event_log_entry.v1",
                project_id,
                scope_type,
                scope_id,
                event_type,
                "control_plane",
                None,
                None,
                payload_text,
                occurred_at,
                ingest_sequence,
                event_kind,
            ),
        )
        await conn.commit()
    return event_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-006")
def test_pg_migration_file_exists_and_carries_spec_function() -> None:
    """The Postgres migration 0017 must exist and declare the function with
    the spec signature and ``LANGUAGE plpgsql STABLE`` volatility marker.
    """
    assert _PG_MIGRATION.is_file(), f"missing migration: {_PG_MIGRATION}"
    text = _PG_MIGRATION.read_text(encoding="utf-8")
    assert "CREATE OR REPLACE FUNCTION reconstruct_scope_state_at(" in text
    assert "p_scope_kind text" in text
    assert "p_scope_id uuid" in text
    assert "p_at timestamptz" in text
    assert "RETURNS TABLE (" in text
    assert "LANGUAGE plpgsql STABLE" in text
    # Spec line 6321: the WHERE clause must filter on the .transition
    # suffix so only summary rows feed the reconstruction.
    assert "'%.transition%'" in text
    # Spec line 6300-6306 initial-state mapping verbatim.
    for kind in (
        "'run'",
        "'replay_case'",
        "'gate_round'",
        "'evidence_bundle'",
        "'eval_run'",
        "'release'",
    ):
        assert kind in text, f"missing scope_kind initial-state mapping: {kind}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-007")
def test_pg_migration_declares_supporting_index() -> None:
    """The supporting index for the temporal query MUST be on
    (scope_type, scope_id, occurred_at, ingest_sequence) -- the canonical
    column name in event_log_entries is ``scope_type`` (per
    packages/schemas/sql/0002_control_plane.sql:143). The migration header
    documents the spec-vs-DDL naming reconciliation.
    """
    text = _PG_MIGRATION.read_text(encoding="utf-8")
    assert "CREATE INDEX" in text
    assert "event_log_entries_temporal_lookup" in text
    # Index columns in order.
    assert "(scope_type, scope_id, occurred_at, ingest_sequence)" in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-008")
@pytest.mark.asyncio
async def test_reconstruct_at_t1_and_t3_returns_corresponding_states(
    tmp_path,
) -> None:
    """Seed three sequential transitions at t1 < t2 < t3. Reconstruct at
    t1 returns the t1 state; reconstruct at t3 returns the final state.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        project_id = str(uuid.uuid4())
        scope_id = str(uuid.uuid4())
        t0 = datetime.now(tz=UTC)
        t1 = t0 + timedelta(seconds=10)
        t2 = t0 + timedelta(seconds=20)
        t3 = t0 + timedelta(seconds=30)

        # Three summary rows: pending->captured (epoch 1), captured->gated
        # (epoch 2), gated->accepted (epoch 3). The event_kind matches the
        # post-m3-f02 production write path.
        await _insert_event(
            db,
            project_id=project_id,
            scope_type="run",
            scope_id=scope_id,
            event_type="run.transition",
            payload={"from_state": "pending", "to_state": "captured", "epoch_after": 1},
            occurred_at=_ts(t1),
            ingest_sequence=1,
        )
        await _insert_event(
            db,
            project_id=project_id,
            scope_type="run",
            scope_id=scope_id,
            event_type="run.transition",
            payload={"from_state": "captured", "to_state": "gated", "epoch_after": 2},
            occurred_at=_ts(t2),
            ingest_sequence=3,
        )
        await _insert_event(
            db,
            project_id=project_id,
            scope_type="run",
            scope_id=scope_id,
            event_type="run.transition",
            payload={"from_state": "gated", "to_state": "accepted", "epoch_after": 3},
            occurred_at=_ts(t3),
            ingest_sequence=5,
        )

        # Reconstruct at t1: state = captured, epoch = 1.
        row_t1 = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            at=_ts(t1),
        )
        assert row_t1 is not None
        assert isinstance(row_t1, TemporalScopeStateRow)
        assert row_t1.state == "captured", row_t1
        assert row_t1.epoch_at_t == 1, row_t1
        assert row_t1.last_event_type == "run.transition", row_t1

        # Reconstruct at t3: state = accepted, epoch = 3.
        row_t3 = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            at=_ts(t3),
        )
        assert row_t3 is not None
        assert row_t3.state == "accepted", row_t3
        assert row_t3.epoch_at_t == 3, row_t3
        assert row_t3.last_event_type == "run.transition", row_t3

        # Reconstruct at the half-way point (between t1 and t2) returns the
        # t1 state because no later transition has been observed yet.
        between = t1 + timedelta(seconds=1)
        row_mid = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            at=_ts(between),
        )
        assert row_mid is not None
        assert row_mid.state == "captured", row_mid
        assert row_mid.epoch_at_t == 1, row_mid
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-010")
@pytest.mark.asyncio
async def test_reconstruct_before_scope_exists_returns_none(tmp_path) -> None:
    """Querying before the scope's first event returns None (spec line 6291
    "RETURN" without a row).
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        project_id = str(uuid.uuid4())
        scope_id = str(uuid.uuid4())
        t0 = datetime.now(tz=UTC)
        t1 = t0 + timedelta(seconds=10)
        t_before = t0  # strictly before any event

        await _insert_event(
            db,
            project_id=project_id,
            scope_type="run",
            scope_id=scope_id,
            event_type="run.transition",
            payload={"from_state": "pending", "to_state": "captured", "epoch_after": 1},
            occurred_at=_ts(t1),
            ingest_sequence=1,
        )

        result = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            at=_ts(t_before),
        )
        assert result is None, result

        # A completely unknown scope id also returns None even after now().
        result_unknown = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=str(uuid.uuid4()),
            at=_ts(datetime.now(tz=UTC)),
        )
        assert result_unknown is None, result_unknown
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-008")
@pytest.mark.asyncio
async def test_initial_state_returned_when_only_non_transition_events_exist(
    tmp_path,
) -> None:
    """If the scope has rows in event_log_entries at <= T but no
    ``*.transition`` summary rows yet, the function returns the scope_kind's
    canonical initial state with epoch 0 (spec lines 6298-6306).
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        project_id = str(uuid.uuid4())
        scope_id = str(uuid.uuid4())
        t1 = datetime.now(tz=UTC) + timedelta(seconds=5)
        # An action event row (NOT a *.transition summary).
        await _insert_event(
            db,
            project_id=project_id,
            scope_type="run",
            scope_id=scope_id,
            event_type="run.captured",
            payload={"event": "ingest.run_received"},
            occurred_at=_ts(t1),
            ingest_sequence=1,
            event_kind="state_transition",
        )
        row = await reconstruct_scope_state_at_local(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            at=_ts(t1),
        )
        # Scope existed at T (has a row) but no transition summary -> initial state.
        assert row is not None
        assert row.state == "pending", row
        assert row.epoch_at_t == 0, row
        assert row.last_event_type is None, row
        assert row.last_event_id is None, row
    finally:
        await db.close()
