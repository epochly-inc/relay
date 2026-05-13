"""VAL-W2-056: Context reinjection guard.

A resumed worker that holds a STALE manifest_commit_hash relative to
the active pinned hash for its scope MUST be refused at the HTTP boundary
with HTTP 409 + RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED. The check fires
BEFORE the state engine is invoked.

Test flow:
  1. Seed actor + manifest A + manifest B (both currently active).
  2. Issue a first transition using manifest A. State advances to
     captured; the scope's pinned manifest hash is recorded on the
     emitted event_log row.
  3. Simulate a worker that resumed with stale in-memory manifest B.
     The worker's second transition attempt MUST be rejected with
     409 + RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED because the scope's
     pinned hash (A) differs from the supplied hash (B).
  4. State remains at 'captured' (scope_state.epoch unchanged).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from relay_sidecar.health import HealthState
from relay_sidecar.runtime import build_runtime_app


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _build_app(tmp_path: Path):
    token = "t" * 64
    digest = "sha256-" + hashlib.sha256(token.encode("utf-8")).hexdigest()
    health = HealthState(
        port=0, bearer_token=token, bearer_token_digest=digest
    )
    return build_runtime_app(
        health=health,
        sqlite_path=tmp_path / "sidecar.db",
        relay_home_override=tmp_path,
    )


def _seed_registries(
    db_path: Path,
    *,
    identity_hash: str,
    manifest_hashes: list[str],
) -> None:
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, NULL)",
            (identity_hash, "sdk", now),
        )
        for h in manifest_hashes:
            conn.execute(
                "INSERT INTO manifest_versions "
                "(manifest_version_id, manifest_id, project_id, commit_hash, "
                " effective_at, effective_until, grace_window_seconds) "
                "VALUES (?, ?, ?, ?, ?, NULL, 86400)",
                (
                    str(uuid.uuid4()),
                    str(uuid.uuid4()),
                    str(uuid.uuid4()),
                    h,
                    now,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _seed_scope(db_path: Path, *, scope_id: str, project_id: str) -> None:
    """Insert a pending scope_state row via raw sqlite for test setup."""
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO scope_state "
            "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            ("run", scope_id, project_id, "pending", now, now),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-056")
def test_stale_manifest_hash_returns_context_not_rehydrated(tmp_path) -> None:
    """Resumed worker with stale hash -> HTTP 409 + RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED."""
    app = _build_app(tmp_path)
    with TestClient(app) as client:
        identity_hash = "sha256-" + "a" * 64
        manifest_a = "sha256-" + "b" * 64
        manifest_b = "sha256-" + "c" * 64
        _seed_registries(
            tmp_path / "sidecar.db",
            identity_hash=identity_hash,
            manifest_hashes=[manifest_a, manifest_b],
        )
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope(
            tmp_path / "sidecar.db", scope_id=scope_id, project_id=project_id
        )

        # First transition with manifest A -> pins the scope to manifest A.
        first = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": manifest_a,
                "project_id": project_id,
                "run_id": scope_id,
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["new_state"] == "captured"

        # Second transition with STALE manifest B -> rejected.
        second = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "captured",
                "event": "validation.start",
                "actor": {"kind": "ingest_worker", "identity_hash": identity_hash},
                "manifest_commit_hash": manifest_b,  # STALE
                "project_id": project_id,
                "run_id": scope_id,
            },
        )
        assert second.status_code == 409, second.text
        body = second.json()
        assert body["code"] == "RELAY-SIDECAR-008", body
        assert body["error_class"] == "RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED", body
        # State unchanged (still 'captured', epoch still 1).
        verify_conn = sqlite3.connect(str(tmp_path / "sidecar.db"))
        try:
            row = verify_conn.execute(
                "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
                (scope_id,),
            ).fetchone()
        finally:
            verify_conn.close()
        assert row[0] == "captured"
        assert int(row[1]) == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-056")
def test_same_manifest_hash_proceeds(tmp_path) -> None:
    """Resumed worker with SAME hash as pinned -> proceeds normally."""
    app = _build_app(tmp_path)
    with TestClient(app) as client:
        identity_hash = "sha256-" + "a" * 64
        manifest_a = "sha256-" + "b" * 64
        _seed_registries(
            tmp_path / "sidecar.db",
            identity_hash=identity_hash,
            manifest_hashes=[manifest_a],
        )
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope(
            tmp_path / "sidecar.db", scope_id=scope_id, project_id=project_id
        )
        # First transition with manifest A.
        first = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": manifest_a,
                "project_id": project_id,
                "run_id": scope_id,
            },
        )
        assert first.status_code == 200
        # Second transition with SAME manifest A -> succeeds.
        second = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "captured",
                "event": "validation.start",
                "actor": {"kind": "ingest_worker", "identity_hash": identity_hash},
                "manifest_commit_hash": manifest_a,
                "project_id": project_id,
                "run_id": scope_id,
            },
        )
        assert second.status_code == 200, second.text
        assert second.json()["new_state"] == "validating"
