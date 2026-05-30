"""VAL-ISO-029: three-anchor handoff guard MUST use the authenticated actor.

Defect (base commit c911607): ``compare_and_set_state`` invokes the
per-transition guards with ``guard.check(conn, scope_kind, scope_id,
payload_in, manifest_commit_hash)``. The AUTHENTICATED actor
(``ActorRef.identity_hash``) is NEVER injected into ``payload_in``. The
``three_anchor_handoff_valid`` guard reads ``actor_identity_hash`` from the
CALLER PAYLOAD, so a caller authenticated as one identity can pass the actor
anchor by stuffing a DIFFERENT (registered) ``actor_identity_hash`` into the
payload -- a CLAUDE.md keystone #4 integrity bypass.

Fix: ``compare_and_set_state`` injects ``actor.identity_hash`` into the guard
payload before evaluation, unconditionally overriding any payload-supplied
``actor_identity_hash``. The guard (and the audit row) then enforce the
authenticated identity, not the caller's claim.

Transition under test (state-transition-table.yaml gate_round): from ``open``
on event ``draft.submitted`` to ``draft_received``, actor ``worker``, guard
``three_anchor_handoff_valid``.

These tests are RED at base commit c911607 (the spoof case PASSES the guard)
and GREEN after the fix (the spoof case is rejected; the genuine actor still
passes).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    HANDOFF_INVALID,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_actor_and_manifest(
    db_path: Path,
    *,
    identity_hash: str,
    commit_hash: str,
    actor_kind: str,
    project_id: str,
) -> None:
    """Seed one active actor + one active manifest version (project-scoped)."""
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, NULL)",
            (identity_hash, actor_kind, now),
        )
        conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, NULL, 86400)",
            (str(uuid.uuid4()), str(uuid.uuid4()), project_id, commit_hash, now),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_handoff_guard_rejects_payload_spoofed_actor(tmp_path) -> None:
    """A caller authenticated as an UNREGISTERED actor MUST NOT pass the
    three-anchor handoff guard by putting a REGISTERED ``actor_identity_hash``
    in the payload.

    Base-commit defect: the guard reads the payload's (registered) hash and
    PASSES, letting the unregistered authenticated actor perform the handoff
    under a borrowed identity. After the fix the guard uses the authenticated
    (unregistered) actor and rejects with HANDOFF_INVALID.
    """
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        registered_hash = "sha256-" + "a" * 64
        spoofing_actor_hash = "sha256-" + "e" * 64  # NOT registered
        commit_hash = "sha256-" + "b" * 64
        project_id = str(uuid.uuid4())

        # Only ``registered_hash`` is in the actors registry. The manifest is
        # active for this project so the manifest anchor is NOT the cause of
        # any rejection -- the actor anchor is the only variable.
        _seed_actor_and_manifest(
            db_path,
            identity_hash=registered_hash,
            commit_hash=commit_hash,
            actor_kind="worker",
            project_id=project_id,
        )

        scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            project_id=project_id,
        )

        # Authenticated actor is the UNREGISTERED hash; the payload lies,
        # claiming the REGISTERED hash for the actor anchor.
        actor = ActorRef(kind="worker", identity_hash=spoofing_actor_hash)
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            project_id=project_id,
            manifest_commit_hash=commit_hash,
            payload={
                # Spoofed actor anchor: a registered identity the caller is
                # NOT authenticated as.
                "actor_identity_hash": registered_hash,
                "manifest_commit_hash": commit_hash,
                "project_id": project_id,
            },
        )

        assert result.ok is False, (
            "spoofed payload actor_identity_hash must NOT pass the handoff "
            "guard; the authenticated (unregistered) actor governs the anchor"
        )
        assert result.reason == HANDOFF_INVALID, result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_handoff_guard_accepts_genuine_authenticated_actor(tmp_path) -> None:
    """A genuine authenticated, REGISTERED actor still passes the guard.

    Guards against over-rejection from the fix: the authenticated actor that
    IS in the registry transitions open -> draft_received successfully.
    """
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        registered_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_id = str(uuid.uuid4())

        _seed_actor_and_manifest(
            db_path,
            identity_hash=registered_hash,
            commit_hash=commit_hash,
            actor_kind="worker",
            project_id=project_id,
        )

        scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            project_id=project_id,
        )

        actor = ActorRef(kind="worker", identity_hash=registered_hash)
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            project_id=project_id,
            manifest_commit_hash=commit_hash,
            # No actor_identity_hash in payload: the engine injects the
            # authenticated actor. (Even if present and matching, the genuine
            # actor passes.)
            payload={
                "manifest_commit_hash": commit_hash,
                "project_id": project_id,
            },
        )

        assert result.ok is True, result
        assert result.new_state == "draft_received", result
    finally:
        await db.close()
