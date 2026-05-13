"""VAL-W2-024 / -025 / -026: run_results CHECK constraints.

These tests open a raw aiosqlite connection (bypassing the state engine)
to PROVE the SQL-layer CHECK constraints reject non-control-plane writes
and accepted-without-evidence writes. Per CLAUDE.md keystone invariant
#1, this is the schema-layer enforcement of "the control plane writes
the result".

VAL-W2-024 grep guard lives in ``test_state_engine_writes_only.py``;
this file covers the DB-layer CHECK constraints.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
import uuid

import aiosqlite
import pytest
from relay_sidecar.db import SidecarDatabase


def _ts() -> str:
    """Minimal RFC 3339 UTC timestamp for tests."""
    return "2026-05-13T00:00:00.000000Z"


async def _open_sidecar(tmp_path) -> SidecarDatabase:
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    await db.open()
    return db


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-025")
@pytest.mark.asyncio
async def test_run_results_written_by_check_rejects_sdk(tmp_path) -> None:
    """Direct INSERT with written_by='sdk' MUST raise IntegrityError."""
    db = await _open_sidecar(tmp_path)
    try:
        # Open a raw aiosqlite connection (bypass the state engine) so we
        # can prove the SQL-layer CHECK constraint fires.
        async with aiosqlite.connect(str(db.db_path)) as conn:
            with pytest.raises(sqlite3.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO run_results ("
                    "  run_result_id, run_id, project_id, written_by, status,"
                    "  manifest_commit_hash, actor_identity_hash, decided_at,"
                    "  decision_epoch, signature, signature_key_id, evidence_bundle_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        "sdk",  # forbidden
                        "blocked",
                        "sha256-aaaa",
                        "sha256-bbbb",
                        _ts(),
                        1,
                        "sig",
                        "key1",
                        None,
                    ),
                )
                await conn.commit()
            # Constraint name must appear in error string.
            err = str(exc_info.value)
            assert "written_by_control_plane" in err, err
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-026")
@pytest.mark.asyncio
async def test_run_results_accepted_requires_evidence(tmp_path) -> None:
    """status='accepted' AND evidence_bundle_id IS NULL MUST raise IntegrityError."""
    db = await _open_sidecar(tmp_path)
    try:
        async with aiosqlite.connect(str(db.db_path)) as conn:
            with pytest.raises(sqlite3.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO run_results ("
                    "  run_result_id, run_id, project_id, written_by, status,"
                    "  manifest_commit_hash, actor_identity_hash, decided_at,"
                    "  decision_epoch, signature, signature_key_id, evidence_bundle_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        "control_plane",
                        "accepted",
                        "sha256-aaaa",
                        "sha256-bbbb",
                        _ts(),
                        1,
                        "sig",
                        "key1",
                        None,  # forbidden when status='accepted'
                    ),
                )
                await conn.commit()
            err = str(exc_info.value)
            assert "accepted_requires_evidence" in err, err
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-026")
@pytest.mark.asyncio
async def test_run_results_accepted_with_evidence_passes(tmp_path) -> None:
    """status='accepted' AND evidence_bundle_id IS NOT NULL succeeds."""
    db = await _open_sidecar(tmp_path)
    try:
        async with aiosqlite.connect(str(db.db_path)) as conn:
            await conn.execute(
                "INSERT INTO run_results ("
                "  run_result_id, run_id, project_id, written_by, status,"
                "  manifest_commit_hash, actor_identity_hash, decided_at,"
                "  decision_epoch, signature, signature_key_id, evidence_bundle_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    str(uuid.uuid4()),
                    str(uuid.uuid4()),
                    "control_plane",
                    "accepted",
                    "sha256-aaaa",
                    "sha256-bbbb",
                    _ts(),
                    1,
                    "sig",
                    "key1",
                    str(uuid.uuid4()),  # evidence present
                ),
            )
            await conn.commit()
            async with conn.execute(
                "SELECT COUNT(*) FROM run_results WHERE status='accepted'"
            ) as cur:
                row = await cur.fetchone()
            assert row is not None and int(row[0]) == 1
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-026")
@pytest.mark.asyncio
async def test_run_results_non_accepted_without_evidence_passes(tmp_path) -> None:
    """Non-accepted statuses can have NULL evidence_bundle_id."""
    db = await _open_sidecar(tmp_path)
    try:
        async with aiosqlite.connect(str(db.db_path)) as conn:
            for status in ("remediate_required", "blocked", "invalid"):
                await conn.execute(
                    "INSERT INTO run_results ("
                    "  run_result_id, run_id, project_id, written_by, status,"
                    "  manifest_commit_hash, actor_identity_hash, decided_at,"
                    "  decision_epoch, signature, signature_key_id, evidence_bundle_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        str(uuid.uuid4()),
                        "control_plane",
                        status,
                        "sha256-aaaa",
                        "sha256-bbbb",
                        _ts(),
                        1,
                        "sig",
                        "key1",
                        None,
                    ),
                )
            await conn.commit()
            async with conn.execute("SELECT COUNT(*) FROM run_results") as cur:
                row = await cur.fetchone()
            assert row is not None and int(row[0]) == 3
    finally:
        await db.close()
