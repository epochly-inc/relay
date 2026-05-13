"""VAL-W2-030 / -031 / -032: three-anchor handoff guard.

Verifies the spec C.5 three-anchor handoff validator rejects:

  VAL-W2-030: ``payload['run_id'] != scope_id`` (scope_kind='run') -> SCOPE_ID_MISMATCH.
  VAL-W2-031: unknown actor_identity_hash OR revoked actor -> ACTOR_NOT_REGISTERED.
  VAL-W2-032: manifest_commit_hash not active and not in grace -> MANIFEST_NOT_ACTIVE.
              Manifest in grace window MUST succeed.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    ACTOR_NOT_REGISTERED,
    MANIFEST_NOT_ACTIVE,
    SCOPE_ID_MISMATCH,
    validate_three_anchor_handoff,
)


def _ts(dt: datetime) -> str:
    """Format a tz-aware datetime as RFC 3339 with ``Z``."""
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


async def _seed_actor(
    db: SidecarDatabase,
    *,
    identity_hash: str,
    kind: str = "sdk",
    revoked: bool = False,
) -> None:
    """Insert a row into actors via raw writer (bypasses state engine).

    The state engine never writes to actors directly; seeding is a test-
    setup operation, not a state transition.
    """
    import aiosqlite

    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?)",
            (
                identity_hash,
                kind,
                _ts(datetime.now(UTC)),
                _ts(datetime.now(UTC)) if revoked else None,
            ),
        )
        await conn.commit()


async def _seed_manifest(
    db: SidecarDatabase,
    *,
    commit_hash: str,
    project_id: str = "00000000-0000-0000-0000-000000000000",
    effective_at: datetime | None = None,
    effective_until: datetime | None = None,
    grace_window_seconds: int = 86400,
) -> None:
    import aiosqlite

    async with aiosqlite.connect(str(db.db_path)) as conn:
        await conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                project_id,
                commit_hash,
                _ts(effective_at or datetime.now(UTC)),
                _ts(effective_until) if effective_until is not None else None,
                grace_window_seconds,
            ),
        )
        await conn.commit()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-030")
@pytest.mark.asyncio
async def test_scope_id_mismatch_for_run(tmp_path) -> None:
    """run_id != scope_id when scope_kind='run' -> SCOPE_ID_MISMATCH."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        await _seed_actor(db, identity_hash=identity_hash)
        await _seed_manifest(db, commit_hash=commit_hash)

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        other_run_id = str(uuid.uuid4())  # deliberately different
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": other_run_id,
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is False
        assert result.reason == SCOPE_ID_MISMATCH
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-031")
@pytest.mark.asyncio
async def test_actor_not_registered_rejects(tmp_path) -> None:
    """Unknown actor_identity_hash -> ACTOR_NOT_REGISTERED."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        # Seed a valid manifest but NO actor row.
        commit_hash = "sha256-" + "b" * 64
        await _seed_manifest(db, commit_hash=commit_hash)

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": scope_id,  # matches -> passes scope anchor
                "actor_identity_hash": "sha256-" + "z" * 64,  # not registered
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is False
        assert result.reason == ACTOR_NOT_REGISTERED
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-031")
@pytest.mark.asyncio
async def test_actor_revoked_rejects(tmp_path) -> None:
    """Registered but revoked actor -> ACTOR_NOT_REGISTERED."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "c" * 64
        commit_hash = "sha256-" + "b" * 64
        await _seed_actor(db, identity_hash=identity_hash, revoked=True)
        await _seed_manifest(db, commit_hash=commit_hash)

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": scope_id,
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is False
        assert result.reason == ACTOR_NOT_REGISTERED
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-032")
@pytest.mark.asyncio
async def test_manifest_not_active_and_not_in_grace_rejects(tmp_path) -> None:
    """Manifest expired beyond grace window -> MANIFEST_NOT_ACTIVE."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        await _seed_actor(db, identity_hash=identity_hash)
        # Manifest effective_until was 3 days ago, grace is 1 day -> expired.
        await _seed_manifest(
            db,
            commit_hash=commit_hash,
            effective_at=datetime.now(UTC) - timedelta(days=10),
            effective_until=datetime.now(UTC) - timedelta(days=3),
            grace_window_seconds=86400,  # 1 day grace
        )

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": scope_id,
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is False
        assert result.reason == MANIFEST_NOT_ACTIVE
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-032")
@pytest.mark.asyncio
async def test_manifest_in_grace_window_succeeds(tmp_path) -> None:
    """Manifest within grace window -> handoff succeeds."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        await _seed_actor(db, identity_hash=identity_hash)
        # Manifest effective_until was 1 hour ago, grace is 1 day -> in grace.
        await _seed_manifest(
            db,
            commit_hash=commit_hash,
            effective_at=datetime.now(UTC) - timedelta(days=2),
            effective_until=datetime.now(UTC) - timedelta(hours=1),
            grace_window_seconds=86400,
        )

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": scope_id,
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is True, result
        assert result.reason is None
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-032")
@pytest.mark.asyncio
async def test_manifest_currently_active_succeeds(tmp_path) -> None:
    """Manifest with effective_until=NULL (currently active) succeeds."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        await _seed_actor(db, identity_hash=identity_hash)
        await _seed_manifest(db, commit_hash=commit_hash)  # effective_until=None

        reader = db.acquire_reader()
        scope_id = str(uuid.uuid4())
        result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run",
            scope_id=scope_id,
            payload={
                "run_id": scope_id,
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            },
        )
        assert result.ok is True
    finally:
        await db.close()
