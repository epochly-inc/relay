"""VAL-W2-033: Failed three-anchor handoff on gate draft -> RELAY-GATE-021.

When a worker submits a draft whose three-anchor handoff fails on any
anchor, the response MUST carry error envelope code ``RELAY-GATE-021``
AND no ``gate_decisions`` row is written.

For W2.4 the gate-draft submission *flow* (writing a ``gate_decision_drafts``
row with ``resolution_state='rejected_handoff'``) is owned by W7. W2.4
covers the contract piece that is the W2 sidecar's responsibility:
(a) all three failing-anchor cases surface ``RELAY-GATE-021`` at the
HTTP boundary, (b) zero ``gate_decisions`` rows are written. The
boundary is the ``POST /v1/state/transition`` endpoint which is the
generic state-engine entrypoint and is reused by W7 for draft
submissions.

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


def _build_app(tmp_path: Path):
    token = "t" * 64
    digest = "sha256-" + hashlib.sha256(token.encode("utf-8")).hexdigest()
    health = HealthState(
        port=0,
        bearer_token=token,
        bearer_token_digest=digest,
    )
    return build_runtime_app(
        health=health,
        sqlite_path=tmp_path / "sidecar.db",
        relay_home_override=tmp_path,
    )


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_actor_and_manifest(
    db_path: Path,
    *,
    identity_hash: str = "sha256-" + "a" * 64,
    commit_hash: str = "sha256-" + "b" * 64,
    revoked: bool = False,
) -> tuple[str, str]:
    """Seed registry rows using stdlib sqlite3 (sync test path)."""
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        # Harden against SQLITE_BUSY when the aiosqlite writer holds a lock.
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?)",
            (identity_hash, "sdk", now, now if revoked else None),
        )
        conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, NULL, 86400)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                commit_hash,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return identity_hash, commit_hash


def _gate_decisions_count(db_path: Path, scope_id: str) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM gate_decisions WHERE scope_id = ?",
            (scope_id,),
        ).fetchone()
    finally:
        conn.close()
    return int(row[0])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-033")
def test_failed_handoff_scope_id_returns_relay_gate_021(tmp_path) -> None:
    """Scope anchor failure -> RELAY-GATE-021; zero gate_decisions rows."""
    app = _build_app(tmp_path)
    with TestClient(app) as client:
        # Lifespan startup ran inside TestClient context -> DB now exists +
        # migrations applied; we can seed.
        identity_hash, commit_hash = _seed_actor_and_manifest(
            tmp_path / "sidecar.db"
        )
        scope_id = str(uuid.uuid4())
        wrong_run_id = str(uuid.uuid4())
        response = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": commit_hash,
                "run_id": wrong_run_id,
            },
        )
        assert response.status_code == 409, response.text
        body = response.json()
        assert body["code"] == "RELAY-GATE-021", body
        assert body["error_class"] == "RELAY-GATE-021", body
        assert _gate_decisions_count(tmp_path / "sidecar.db", scope_id) == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-033")
def test_failed_handoff_unknown_actor_returns_relay_gate_021(tmp_path) -> None:
    """Actor anchor failure -> RELAY-GATE-021; zero gate_decisions rows."""
    app = _build_app(tmp_path)
    with TestClient(app) as client:
        _, commit_hash = _seed_actor_and_manifest(tmp_path / "sidecar.db")
        scope_id = str(uuid.uuid4())
        response = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {
                    "kind": "sdk",
                    "identity_hash": "sha256-" + "z" * 64,
                },
                "manifest_commit_hash": commit_hash,
                "run_id": scope_id,
            },
        )
        assert response.status_code == 409
        body = response.json()
        assert body["code"] == "RELAY-GATE-021", body
        assert _gate_decisions_count(tmp_path / "sidecar.db", scope_id) == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-033")
def test_failed_handoff_unknown_manifest_returns_relay_gate_021(tmp_path) -> None:
    """Manifest anchor failure -> RELAY-GATE-021; zero gate_decisions rows."""
    app = _build_app(tmp_path)
    with TestClient(app) as client:
        identity_hash, _ = _seed_actor_and_manifest(tmp_path / "sidecar.db")
        scope_id = str(uuid.uuid4())
        response = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": "sha256-" + "9" * 64,
                "run_id": scope_id,
            },
        )
        assert response.status_code == 409
        body = response.json()
        assert body["code"] == "RELAY-GATE-021", body
        assert _gate_decisions_count(tmp_path / "sidecar.db", scope_id) == 0
