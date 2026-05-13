"""VAL-W2-062: Stale handoff at HTTP boundary returns 409 + RELAY-GATE-021
BEFORE state engine invocation.

The HTTP handler at POST /v1/state/transition MUST validate the three-
anchor handoff at handler entry. A stale manifest hash MUST produce an
HTTP 409 + RELAY-GATE-021 response AND MUST NOT invoke the state engine.

Verification: a mock state engine records all invocations. After issuing
a request with a stale (non-registered) manifest hash, the mock's
invocation count MUST be 0.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import StateTransitionResult
from relay_sidecar.state_engine.http_endpoint import (
    StateEngineProtocol,
    build_state_router,
)


@dataclass
class _MockEngine:
    """Records every invocation of transition_fn."""

    invocations: list[dict[str, Any]] = field(default_factory=list)

    async def transition_fn(self, **kwargs: Any) -> StateTransitionResult:
        self.invocations.append(kwargs)
        return StateTransitionResult(ok=True, new_state="captured", epoch=1)


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_actor(db_path: Path, *, identity_hash: str) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, NULL)",
            (identity_hash, "sdk", _now_z()),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_manifest(db_path: Path, *, commit_hash: str) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
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
                _now_z(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def boundary_app(tmp_path):
    """Build a minimal FastAPI app with the state router and a mock engine.

    The mock state engine records every invocation. The fixture yields
    (app, mock, db_path) so tests can issue requests, then assert on
    ``mock.invocations`` AND verify DB rows.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    mock = _MockEngine()

    def _factory(_db: SidecarDatabase) -> StateEngineProtocol:
        return StateEngineProtocol(transition_fn=mock.transition_fn)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await db.open()
        try:
            yield
        finally:
            await db.close()

    app = FastAPI(lifespan=_lifespan)
    app.include_router(
        build_state_router(
            database_getter=lambda: db,
            state_engine_factory=_factory,
        )
    )
    yield app, mock, tmp_path / "sidecar.db"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_stale_manifest_returns_409_without_calling_state_engine(
    boundary_app,
) -> None:
    """Stale manifest hash -> 409 + RELAY-GATE-021; mock invocation count = 0."""
    app, mock, db_path = boundary_app
    with TestClient(app) as client:
        identity_hash = "sha256-" + "a" * 64
        _seed_actor(db_path, identity_hash=identity_hash)
        # Deliberately do NOT seed the manifest -> stale hash.
        scope_id = str(uuid.uuid4())
        response = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": "sha256-" + "9" * 64,  # not registered
                "run_id": scope_id,
            },
        )
        assert response.status_code == 409, response.text
        body = response.json()
        assert body["code"] == "RELAY-GATE-021", body
        # CRITICAL: state engine was never invoked.
        assert mock.invocations == [], mock.invocations


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_valid_handoff_does_call_state_engine(boundary_app) -> None:
    """Sanity: valid handoff -> mock IS invoked exactly once."""
    app, mock, db_path = boundary_app
    with TestClient(app) as client:
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        _seed_actor(db_path, identity_hash=identity_hash)
        _seed_manifest(db_path, commit_hash=commit_hash)
        scope_id = str(uuid.uuid4())
        response = client.post(
            "/v1/state/transition",
            json={
                "scope_kind": "run",
                "scope_id": scope_id,
                "expected_from": "pending",
                "event": "ingest.run_received",
                "actor": {"kind": "sdk", "identity_hash": identity_hash},
                "manifest_commit_hash": commit_hash,
                "run_id": scope_id,
            },
        )
        # Mock returns success.
        assert response.status_code == 200, response.text
        assert len(mock.invocations) == 1, mock.invocations
        call = mock.invocations[0]
        assert call["scope_kind"] == "run"
        assert call["scope_id"] == scope_id
        assert call["event"] == "ingest.run_received"
