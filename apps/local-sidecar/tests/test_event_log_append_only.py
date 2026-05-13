"""VAL-W2-061: event_log_entries is append-only except for retention role.

Migration 0007 installs two triggers on event_log_entries:

    event_log_entries_no_delete -- BEFORE DELETE, aborts when the active
        role in _sidecar_role is not 'relay_retention_archive'.
    event_log_entries_no_update -- BEFORE UPDATE, same role gate.

Tests assert:
    1. DELETE under the default (relay_state_engine) role raises.
    2. UPDATE under the default role raises.
    3. DELETE under the retention role succeeds.
    4. Reverting the role re-locks DELETE.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from _w25_helpers import seed_db as _seed_db


def _seed_one_row(db_path: Path) -> str:
    """Insert exactly one event_log_entries row under the default role.

    Returns the event_id so the caller can target it for DELETE/UPDATE.
    """
    event_id = str(uuid.uuid4())
    now = (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type,"
            "  scope_id, event_type, actor_kind, payload, occurred_at,"
            "  ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                "relay.event_log_entry.v1",
                str(uuid.uuid4()),
                "other",
                str(uuid.uuid4()),
                "test.event",
                "control_plane",
                json.dumps({"_blob_sha256": "x" * 64}),
                now,
                0,
                "test_seed",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return event_id


def _set_role(conn: sqlite3.Connection, role: str) -> None:
    conn.execute("UPDATE _sidecar_role SET role = ? WHERE id = 0", (role,))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-061")
def test_delete_under_state_engine_role_rejected(tmp_path: Path) -> None:
    """DELETE under default (state engine) role MUST raise."""
    db_path = _seed_db(tmp_path)
    event_id = _seed_one_row(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        # Default role is 'relay_state_engine' from migration 0007.
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute(
                "DELETE FROM event_log_entries WHERE event_id = ?",
                (event_id,),
            )
        assert "event_log_entries_no_delete" in str(excinfo.value), excinfo.value
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-061")
def test_update_under_state_engine_role_rejected(tmp_path: Path) -> None:
    """UPDATE under default role MUST raise."""
    db_path = _seed_db(tmp_path)
    event_id = _seed_one_row(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute(
                "UPDATE event_log_entries SET event_type = ? WHERE event_id = ?",
                ("hacked", event_id),
            )
        assert "event_log_entries_no_update" in str(excinfo.value), excinfo.value
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-061")
def test_delete_under_retention_role_succeeds(tmp_path: Path) -> None:
    """DELETE under relay_retention_archive role MUST succeed."""
    db_path = _seed_db(tmp_path)
    event_id = _seed_one_row(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        _set_role(conn, "relay_retention_archive")
        conn.execute(
            "DELETE FROM event_log_entries WHERE event_id = ?",
            (event_id,),
        )
        conn.commit()
        cursor = conn.execute(
            "SELECT COUNT(*) FROM event_log_entries WHERE event_id = ?",
            (event_id,),
        )
        (count,) = cursor.fetchone()
        assert count == 0, count
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-061")
def test_role_revert_re_locks_delete(tmp_path: Path) -> None:
    """After reverting to relay_state_engine, DELETE is rejected again."""
    db_path = _seed_db(tmp_path)
    event_id_a = _seed_one_row(db_path)
    event_id_b = _seed_one_row(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        _set_role(conn, "relay_retention_archive")
        conn.execute(
            "DELETE FROM event_log_entries WHERE event_id = ?",
            (event_id_a,),
        )
        conn.commit()
        _set_role(conn, "relay_state_engine")
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute(
                "DELETE FROM event_log_entries WHERE event_id = ?",
                (event_id_b,),
            )
        assert "event_log_entries_no_delete" in str(excinfo.value), excinfo.value
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-061")
def test_unknown_role_blocks_delete(tmp_path: Path) -> None:
    """Any role NOT equal to relay_retention_archive blocks DELETE."""
    db_path = _seed_db(tmp_path)
    event_id = _seed_one_row(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        _set_role(conn, "some_other_role")
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute(
                "DELETE FROM event_log_entries WHERE event_id = ?",
                (event_id,),
            )
        assert "event_log_entries_no_delete" in str(excinfo.value), excinfo.value
    finally:
        conn.close()
