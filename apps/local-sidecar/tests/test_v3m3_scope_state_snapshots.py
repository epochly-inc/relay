"""V3M3-F04: scope_state_snapshots table + daily snapshot helper + 90-day retention sweep.

Spec anchors (planning/epochly-replay-spec.md):
  AP.5.b lines 6347-6390  scope_state_snapshots forensic / audit / DR table.

The OSS local-sidecar mirror of AP.5.b stores one row per active
``scope_state`` row per snapshot day. The hosted Postgres edition stores
the full body in object storage and only carries metadata in the row;
the sidecar (SQLite, single-host) stores the snapshot directly because
it has no companion object store. The PK
``(snapshot_date, scope_kind, scope_id)`` is the idempotency anchor for
re-running the daily helper.

Tests:

  VAL-V3M3-011  Migration applied: the ``scope_state_snapshots`` table
                exists with the spec AP.5.b columns and PK / index.

  VAL-V3M3-012  ``write_daily_snapshot(now)`` writes exactly one row per
                active ``scope_state`` row for the snapshot date. Re-run
                with the same date is idempotent (PK collision is
                tolerated; the row count stays at N).

  VAL-V3M3-013  ``prune_old_scope_state_snapshots(retention_days=90)``
                deletes rows whose ``snapshot_date`` is strictly older
                than ``CURRENT_DATE - retention_days`` and KEEPS rows
                whose snapshot_date is within the retention window.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine.compare_and_set import init_scope
from relay_sidecar.state_engine.retention import (
    prune_old_scope_state_snapshots,
    write_daily_snapshot,
)


async def _seed_scopes(
    db: SidecarDatabase, *, project_id: str, count: int
) -> list[tuple[str, str]]:
    """Seed ``count`` active scope_state rows via the canonical init_scope
    helper. Returns the (scope_kind, scope_id) pairs that were created so
    the test can assert per-row presence in the snapshot.
    """
    pairs: list[tuple[str, str]] = []
    for _ in range(count):
        scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        pairs.append(("run", scope_id))
    return pairs


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-011")
@pytest.mark.asyncio
async def test_scope_state_snapshots_migration_creates_table(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """Migration 0030 MUST create scope_state_snapshots with the spec
    AP.5.b column set, PK on (snapshot_date, scope_kind, scope_id), and
    a btree index on snapshot_date.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        reader = db.acquire_reader()
        # Table presence.
        async with reader.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='scope_state_snapshots'"
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "scope_state_snapshots table missing"

        # Column set (spec AP.5.b sidecar shape).
        async with reader.execute(
            "PRAGMA table_info(scope_state_snapshots)"
        ) as cur:
            cols = await cur.fetchall()
        col_names = {c[1] for c in cols}
        assert col_names == {
            "snapshot_id",
            "snapshot_date",
            "scope_kind",
            "scope_id",
            "state",
            "epoch",
        }, col_names

        # PK MUST be the composite (snapshot_date, scope_kind, scope_id).
        # SQLite reports pk ordering as a positive integer in column index 5.
        pk_cols = {c[1]: c[5] for c in cols if c[5] > 0}
        assert pk_cols == {
            "snapshot_date": 1,
            "scope_kind": 2,
            "scope_id": 3,
        }, pk_cols

        # Index on snapshot_date MUST exist for the retention sweep.
        async with reader.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND tbl_name='scope_state_snapshots'"
        ) as cur:
            idx_rows = await cur.fetchall()
        idx_names = {r[0] for r in idx_rows}
        assert any(
            "snapshot_date" in n for n in idx_names
        ), idx_names
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-012")
@pytest.mark.asyncio
async def test_write_daily_snapshot_one_row_per_active_scope(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """``write_daily_snapshot(now)`` MUST write exactly one row per
    active ``scope_state`` row for the snapshot date.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        project_id = str(uuid.uuid4())
        pairs = await _seed_scopes(db, project_id=project_id, count=4)
        snapshot_at = datetime(2026, 5, 19, 0, 5, tzinfo=UTC)

        written = await write_daily_snapshot(db, now=snapshot_at)
        assert written == 4, written

        # Verify the rows are in the table with snapshot_date = 2026-05-19.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT scope_kind, scope_id, state, epoch, snapshot_date "
            "FROM scope_state_snapshots "
            "WHERE snapshot_date = ? "
            "ORDER BY scope_id ASC",
            ("2026-05-19",),
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 4, rows
        snapped_pairs = {(r[0], r[1]) for r in rows}
        assert snapped_pairs == set(pairs), (snapped_pairs, set(pairs))
        for _kind, _scope, state, epoch, snap_date in rows:
            assert state == "pending", state
            assert epoch == 0, epoch
            assert snap_date == "2026-05-19", snap_date
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-012")
@pytest.mark.asyncio
async def test_write_daily_snapshot_is_idempotent(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """Re-running the snapshot helper for the same date MUST NOT raise
    on PK collision and MUST leave the row count unchanged.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        project_id = str(uuid.uuid4())
        await _seed_scopes(db, project_id=project_id, count=3)
        snapshot_at = datetime(2026, 5, 19, 0, 5, tzinfo=UTC)

        first = await write_daily_snapshot(db, now=snapshot_at)
        # Second invocation MUST NOT raise; idempotent.
        second = await write_daily_snapshot(db, now=snapshot_at)
        # Second call observes existing rows and writes nothing new.
        assert first == 3, first
        assert second == 0, second

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM scope_state_snapshots WHERE snapshot_date = ?",
            ("2026-05-19",),
        ) as cur:
            (count,) = await cur.fetchone()
        assert count == 3, count
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-013")
@pytest.mark.asyncio
async def test_prune_old_scope_state_snapshots_deletes_beyond_window(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """``prune_old_scope_state_snapshots(retention_days=90)`` MUST
    delete rows whose ``snapshot_date`` is older than
    ``CURRENT_DATE - 90 days`` and PRESERVE rows within the window.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        project_id = str(uuid.uuid4())
        await _seed_scopes(db, project_id=project_id, count=2)

        # Snapshot at four dates: 200 days ago (well outside), 91 days
        # ago (just outside), 89 days ago (inside the window), and today.
        today = date(2026, 5, 19)
        old_outside = datetime.combine(
            today - timedelta(days=200), datetime.min.time(), tzinfo=UTC
        )
        boundary_outside = datetime.combine(
            today - timedelta(days=91), datetime.min.time(), tzinfo=UTC
        )
        boundary_inside = datetime.combine(
            today - timedelta(days=89), datetime.min.time(), tzinfo=UTC
        )
        today_dt = datetime.combine(today, datetime.min.time(), tzinfo=UTC)

        await write_daily_snapshot(db, now=old_outside)
        await write_daily_snapshot(db, now=boundary_outside)
        await write_daily_snapshot(db, now=boundary_inside)
        await write_daily_snapshot(db, now=today_dt)

        # Sanity: 4 dates * 2 scopes = 8 rows.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM scope_state_snapshots"
        ) as cur:
            (before,) = await cur.fetchone()
        assert before == 8, before

        deleted = await prune_old_scope_state_snapshots(
            db, retention_days=90, today=today
        )
        # 200d + 91d = 4 rows beyond the window.
        assert deleted == 4, deleted

        async with reader.execute(
            "SELECT DISTINCT snapshot_date FROM scope_state_snapshots "
            "ORDER BY snapshot_date ASC"
        ) as cur:
            remaining_dates = [r[0] for r in await cur.fetchall()]
        # Only the 89-day-old and today rows survive.
        assert remaining_dates == [
            (today - timedelta(days=89)).isoformat(),
            today.isoformat(),
        ], remaining_dates
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-013")
@pytest.mark.asyncio
async def test_prune_returns_zero_on_empty_table(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """Pruning an empty snapshots table MUST return 0 (no error)."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        deleted = await prune_old_scope_state_snapshots(
            db, retention_days=90, today=date(2026, 5, 19)
        )
        assert deleted == 0, deleted
    finally:
        await db.close()


# -----------------------------------------------------------------------------
# Static lints: confirm both PG and sidecar migrations exist with the
# expected shape. These are static lints (no DB), keeping the asyncio
# fixture overhead off the lint path.
# -----------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PG_MIGRATION = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "sql"
    / "0018_v3_scope_state_snapshots.sql"
)
_SIDECAR_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0030_v3_scope_state_snapshots.sql"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-011")
def test_pg_migration_exists_with_table_and_index() -> None:
    """PG migration 0018 MUST declare the table + snapshot_date index."""
    assert _PG_MIGRATION.is_file(), _PG_MIGRATION
    body = _PG_MIGRATION.read_text(encoding="utf-8")
    assert "CREATE TABLE" in body
    assert "scope_state_snapshots" in body
    assert "snapshot_date" in body
    assert "scope_kind" in body
    assert "scope_id" in body
    assert "state" in body
    assert "epoch" in body
    # PK + index requirements.
    assert "PRIMARY KEY" in body
    assert "CREATE INDEX" in body
    # 90-day retention sweep query MUST be documented in the migration.
    assert "90" in body, body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-011")
def test_sidecar_migration_exists() -> None:
    """Sidecar migration 0030 MUST create the table for SQLite."""
    assert _SIDECAR_MIGRATION.is_file(), _SIDECAR_MIGRATION
    body = _SIDECAR_MIGRATION.read_text(encoding="utf-8")
    assert "CREATE TABLE" in body
    assert "scope_state_snapshots" in body
    assert "PRIMARY KEY" in body
    assert "CREATE INDEX" in body


# -----------------------------------------------------------------------------
# V3M3-SR-R1-001 (P1): scope_state_snapshots CHECK enumeration must include
# the ``gate`` scope_kind that m3-f05 added to ``scope_state``. Without this
# extension the daily snapshot helper rolls the txn back on CHECK violation
# the first time a ``gate`` row exists in scope_state.
# -----------------------------------------------------------------------------

_PG_MIGRATION_GATE_EXTENSION = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "sql"
    / "0022_v3_snapshot_gate_scope_check_extension.sql"
)
_SIDECAR_MIGRATION_GATE_EXTENSION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0033_v3_snapshot_gate_scope_check_extension.sql"
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-012")
@pytest.mark.asyncio
async def test_write_daily_snapshot_admits_gate_scope_kind(
    tmp_path: Path, relay_home_tmp: Path
) -> None:
    """SR-M3-R1-001 (P1): m3-f05 added ``gate`` to the ``scope_state``
    scope_kind enumeration but the ``scope_state_snapshots`` CHECK was not
    synced. Seeding a ``gate`` scope_state row and invoking
    ``write_daily_snapshot`` MUST succeed and write the snapshot row,
    instead of aborting the txn with a CHECK constraint violation.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    try:
        project_id = str(uuid.uuid4())
        gate_scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="gate",
            scope_id=gate_scope_id,
            project_id=project_id,
        )

        snapshot_at = datetime(2026, 5, 19, 0, 5, tzinfo=UTC)
        written = await write_daily_snapshot(db, now=snapshot_at)
        assert written == 1, written

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT scope_kind, scope_id, state, epoch, snapshot_date "
            "FROM scope_state_snapshots "
            "WHERE snapshot_date = ?",
            ("2026-05-19",),
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, rows
        (scope_kind, scope_id, state, epoch, snap_date) = rows[0]
        assert scope_kind == "gate", scope_kind
        assert scope_id == gate_scope_id, scope_id
        # gate's canonical initial state per spec section AD line 5471.
        assert state == "open", state
        assert epoch == 0, epoch
        assert snap_date == "2026-05-19", snap_date
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-011")
def test_pg_migration_0022_extends_snapshots_check_to_gate() -> None:
    """PG migration 0022 MUST extend the scope_state_snapshots CHECK to
    admit the ``gate`` scope_kind (DROP + re-ADD pattern).
    """
    assert _PG_MIGRATION_GATE_EXTENSION.is_file(), _PG_MIGRATION_GATE_EXTENSION
    body = _PG_MIGRATION_GATE_EXTENSION.read_text(encoding="utf-8")
    assert "scope_state_snapshots" in body
    assert "DROP CONSTRAINT" in body
    assert "ADD CONSTRAINT" in body
    assert "'gate'" in body
    # The new CHECK MUST enumerate all 7 kinds.
    for kind in (
        "'run'",
        "'replay_case'",
        "'gate_round'",
        "'evidence_bundle'",
        "'eval_run'",
        "'release'",
        "'gate'",
    ):
        assert kind in body, kind


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-011")
def test_sidecar_migration_0033_rebuilds_snapshots_check_to_gate() -> None:
    """Sidecar migration 0033 MUST rebuild the SQLite scope_state_snapshots
    CHECK to admit ``gate`` (SQLite has no ALTER TABLE DROP CONSTRAINT).
    """
    assert (
        _SIDECAR_MIGRATION_GATE_EXTENSION.is_file()
    ), _SIDECAR_MIGRATION_GATE_EXTENSION
    body = _SIDECAR_MIGRATION_GATE_EXTENSION.read_text(encoding="utf-8")
    assert "scope_state_snapshots" in body
    assert "CREATE TABLE" in body
    # Data preservation: copy-then-rename pattern.
    assert "INSERT INTO" in body
    assert "DROP TABLE" in body
    assert "RENAME TO scope_state_snapshots" in body
    # Index recreation for snapshot_date.
    assert "CREATE INDEX" in body
    assert "snapshot_date" in body
    # All 7 scope_kinds present in the rebuilt CHECK.
    for kind in (
        "'run'",
        "'replay_case'",
        "'gate_round'",
        "'evidence_bundle'",
        "'eval_run'",
        "'release'",
        "'gate'",
    ):
        assert kind in body, kind
