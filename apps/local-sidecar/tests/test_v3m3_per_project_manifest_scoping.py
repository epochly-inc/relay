"""VAL-V3M3-001 / -002 / -003: per-project manifest scoping in handoff guards.

Spec C.5 lines 3748-3756 require the manifest-commit-hash anchor to scope
by ``(project_id, commit_hash)``, not by ``commit_hash`` alone. The prior
implementation looked up ``manifest_versions`` by ``commit_hash`` only,
which meant a manifest_commit_hash leaked from project A would validate
for project B -- a tenant-isolation defect even on the single-tenant OSS
local sidecar (which still tracks ``project_id`` per spec A.9 / migration
0006).

This test file pins three invariants:

  VAL-V3M3-001  cross-project handoff is rejected: project B submits a
                gate-draft naming project A's manifest_commit_hash, the
                state-engine guard rejects with ``GUARD_FAILED`` (or
                ``HANDOFF_INVALID`` when surfaced via the handoff guard)
                and the diagnostic names the per-project mismatch.
  VAL-V3M3-002  within-project lookup still succeeds (regression guard for
                the same-project happy path under the new scoping).
  VAL-V3M3-003  within-project grace-window logic is preserved (the
                tightened key does not break the rotation grace window).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    GUARD_FAILED,
    HANDOFF_INVALID,
    MANIFEST_NOT_ACTIVE,
    ActorRef,
    compare_and_set_state,
    init_scope,
    validate_three_anchor_handoff,
)
from relay_sidecar.state_engine.handoff import _manifest_is_active_or_in_grace


def _ts(dt: datetime) -> str:
    """Format an aware datetime as RFC 3339 with ``Z`` suffix."""
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _seed_manifest_row(
    db_path: Path,
    *,
    project_id: str,
    commit_hash: str,
    effective_at: datetime | None = None,
    effective_until: datetime | None = None,
    grace_window_seconds: int = 86400,
) -> None:
    """Insert a manifest_versions row directly (test setup, not a transition)."""
    now = effective_at or datetime.now(UTC)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO manifest_versions ("
            " manifest_version_id, manifest_id, project_id, commit_hash,"
            " effective_at, effective_until, grace_window_seconds)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                project_id,
                commit_hash,
                _ts(now),
                _ts(effective_until) if effective_until is not None else None,
                grace_window_seconds,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_actor_row(
    db_path: Path,
    *,
    identity_hash: str,
    kind: str = "sdk",
) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at)"
            " VALUES (?, ?, ?, NULL)",
            (identity_hash, kind, _ts(datetime.now(UTC))),
        )
        conn.commit()
    finally:
        conn.close()


# --- VAL-V3M3-001: cross-project handoff rejected --------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-001")
@pytest.mark.asyncio
async def test_cross_project_manifest_handoff_rejected_at_validator(
    tmp_path,
) -> None:
    """Project B references project A's commit_hash -> MANIFEST_NOT_ACTIVE.

    Validates the leaf primitive ``validate_three_anchor_handoff`` is now
    project-scoped: even though the hash exists in manifest_versions, it
    belongs to project A. A submission carrying ``project_id`` = B must
    reject with ``MANIFEST_NOT_ACTIVE``.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_a = str(uuid.uuid4())
        project_b = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
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
                "project_id": project_b,
            },
        )
        assert result.ok is False, result
        assert result.reason == MANIFEST_NOT_ACTIVE, result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-001")
@pytest.mark.asyncio
async def test_cross_project_manifest_handoff_rejected_via_state_engine(
    tmp_path,
) -> None:
    """Cross-project gate-draft handoff surfaces ``HANDOFF_INVALID`` (per the
    three-anchor guard) via compare_and_set_state.

    Seeds two projects (A, B), seeds a manifest for project A only, and
    submits a gate-draft transition for project B citing A's commit_hash.
    The state engine MUST reject with HANDOFF_INVALID (the three-anchor
    guard's failure code) and surface a per-project mismatch diagnostic.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "c" * 64
        commit_hash = "sha256-" + "e" * 64
        project_a = str(uuid.uuid4())
        project_b = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
        )

        gate_scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="gate_round",
            scope_id=gate_scope_id,
            project_id=project_b,
        )

        actor = ActorRef(kind="worker", identity_hash=identity_hash)
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=gate_scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            project_id=project_b,
            manifest_commit_hash=commit_hash,
            payload={
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
                "project_id": project_b,
            },
        )
        assert result.ok is False, result
        # The three-anchor guard surfaces failures as HANDOFF_INVALID.
        assert result.reason == HANDOFF_INVALID, result
        assert result.extras is not None
        assert result.extras.get("failed_guard") == "three_anchor_handoff_valid"
        # Diagnostic must surface the underlying manifest miss -- this is
        # what makes the cross-project rejection auditable.
        handoff_reason = (
            result.extras.get("guard_diagnostics", {}).get("handoff_reason")
        )
        assert handoff_reason == MANIFEST_NOT_ACTIVE, result.extras
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-001")
@pytest.mark.asyncio
async def test_guard_valid_manifest_commit_hash_cross_project_rejects(
    tmp_path,
) -> None:
    """`_guard_valid_manifest_commit_hash` rejects cross-project lookup.

    Direct test of the ingest-path guard (run.pending -> run.captured).
    Project B submits a run citing project A's manifest_commit_hash; the
    guard MUST fail with a structured per-project diagnostic.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        commit_hash = "sha256-" + "f" * 64
        project_a = str(uuid.uuid4())
        project_b = str(uuid.uuid4())
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
        )

        scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_b,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            payload={},
            project_id=project_b,
            manifest_commit_hash=commit_hash,
        )
        assert result.ok is False, result
        assert result.reason == GUARD_FAILED, result
        assert result.extras is not None
        assert result.extras.get("failed_guard") == "valid_manifest_commit_hash"
        diagnostics = result.extras.get("guard_diagnostics", {})
        assert diagnostics.get("field") == "manifest_commit_hash"
        # Diagnostic phrasing names the (project_id, commit_hash) miss so an
        # auditor can distinguish a per-project mismatch from a fully
        # unknown hash. We intentionally do not assert the exact prose to
        # avoid copy churn; we only require ``project`` appears in the
        # reason text.
        assert "project" in str(diagnostics.get("reason", "")).lower(), diagnostics
    finally:
        await db.close()


# --- VAL-V3M3-002: within-project happy path still works -------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-002")
@pytest.mark.asyncio
async def test_within_project_handoff_succeeds(tmp_path) -> None:
    """Project A submission with project A's manifest -> handoff ok."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_a = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
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
                "project_id": project_a,
            },
        )
        assert result.ok is True, result
        assert result.reason is None
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-002")
@pytest.mark.asyncio
async def test_within_project_state_engine_handoff_succeeds(tmp_path) -> None:
    """Gate-draft handoff succeeds when project matches."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "1" * 64
        commit_hash = "sha256-" + "2" * 64
        project_a = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
        )

        gate_scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="gate_round",
            scope_id=gate_scope_id,
            project_id=project_a,
        )
        actor = ActorRef(kind="worker", identity_hash=identity_hash)
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=gate_scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            project_id=project_a,
            manifest_commit_hash=commit_hash,
            payload={
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
                "project_id": project_a,
            },
        )
        assert result.ok is True, result
    finally:
        await db.close()


# --- VAL-V3M3-003: grace-window logic preserved within project -------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-003")
@pytest.mark.asyncio
async def test_grace_window_preserved_within_project(tmp_path) -> None:
    """Manifest rotated 1h ago within project A; grace 24h -> still valid."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_a = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
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
                "project_id": project_a,
            },
        )
        assert result.ok is True, result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-003")
@pytest.mark.asyncio
async def test_grace_window_expired_within_project_rejects(tmp_path) -> None:
    """Manifest rotated 3d ago, grace 1d -> MANIFEST_NOT_ACTIVE within project."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_a = str(uuid.uuid4())
        _seed_actor_row(tmp_path / "sidecar.db", identity_hash=identity_hash)
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
            effective_at=datetime.now(UTC) - timedelta(days=10),
            effective_until=datetime.now(UTC) - timedelta(days=3),
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
                "project_id": project_a,
            },
        )
        assert result.ok is False, result
        assert result.reason == MANIFEST_NOT_ACTIVE, result
    finally:
        await db.close()


# --- Direct primitive signatures (regression guards on new project_id kw) --


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-002")
@pytest.mark.asyncio
async def test_manifest_is_active_or_in_grace_accepts_project_id(
    tmp_path,
) -> None:
    """`_manifest_is_active_or_in_grace` accepts (project_id, commit_hash).

    Pins the new keyword. Project A's manifest under project A's key returns
    True; the same hash under project B's key returns False.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        commit_hash = "sha256-" + "b" * 64
        project_a = str(uuid.uuid4())
        project_b = str(uuid.uuid4())
        _seed_manifest_row(
            tmp_path / "sidecar.db",
            project_id=project_a,
            commit_hash=commit_hash,
        )
        async with aiosqlite.connect(str(db.db_path)) as reader:
            await reader.execute("PRAGMA query_only = 1")
            ok_a = await _manifest_is_active_or_in_grace(
                reader,
                project_id=project_a,
                manifest_commit_hash=commit_hash,
                now=datetime.now(UTC),
            )
            ok_b = await _manifest_is_active_or_in_grace(
                reader,
                project_id=project_b,
                manifest_commit_hash=commit_hash,
                now=datetime.now(UTC),
            )
        assert ok_a is True
        assert ok_b is False
    finally:
        await db.close()
