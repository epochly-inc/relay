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
from relay_schemas.envelopes import ErrorEnvelope
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import StateTransitionResult
from relay_sidecar.state_engine.compare_and_set import (
    EXPECTED_FROM_MISMATCH,
    HANDOFF_INVALID,
)
from relay_sidecar.state_engine.http_endpoint import (
    StateEngineProtocol,
    _context_envelope,
    _gate_021_envelope,
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
def test_malformed_json_body_returns_relay_ing_001_not_500(
    boundary_app,
) -> None:
    """Malformed JSON body -> structured RELAY-ING-001, NOT a bare 500.

    The POST /v1/state/transition handler is the three-anchor handoff
    entry point and is reachable pre-auth. A malformed JSON body MUST NOT
    surface as an unhandled starlette HTTP 500 "Internal Server Error";
    it MUST return the same RELAY-ING-001 envelope the handler already
    returns for a non-object body, and the state engine MUST NOT be
    invoked.
    """
    app, mock, _db_path = boundary_app
    with TestClient(app) as client:
        response = client.post(
            "/v1/state/transition",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code != 500, response.text
        assert response.status_code == 400, response.text
        body = response.json()
        assert body["code"] == "RELAY-ING-001", body
        # CRITICAL: state engine was never invoked on a malformed body.
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


# ---------------------------------------------------------------------------
# ErrorEnvelope conformance (fix: route declares ErrorEnvelope for 400/409 in
# packages/schemas/raw/openapi.yaml, so every error body on this route MUST
# validate against the canonical ErrorEnvelope model, which is
# additionalProperties:false and forbids the legacy ``error_class`` field).
# ---------------------------------------------------------------------------


def _assert_error_envelope(body: dict[str, Any]) -> ErrorEnvelope:
    """Validate ``body`` against the canonical ErrorEnvelope model.

    ErrorEnvelope (relay_schemas.envelopes) is ``extra="forbid"`` and
    requires schema_version/code/http_status/blocked_surface/retry_advice/
    request_id/trace_id. The legacy ``error_class`` field is rejected.
    """
    # error_class is forbidden by the closed envelope schema.
    assert "error_class" not in body, body
    env = ErrorEnvelope.model_validate(body)
    assert env.schema_version == "relay.error.v1"
    assert env.blocked_surface == "state_transition"
    assert env.request_id
    assert env.trace_id
    return env


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_malformed_json_body_is_error_envelope_compliant(boundary_app) -> None:
    """Malformed JSON -> 400 body validates against ErrorEnvelope (no error_class)."""
    app, _mock, _db_path = boundary_app
    with TestClient(app) as client:
        response = client.post(
            "/v1/state/transition",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400, response.text
        body = response.json()
        env = _assert_error_envelope(body)
        assert env.code == "RELAY-ING-001"
        assert env.http_status == 400
        assert env.retry_advice == "after_fix"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_missing_anchor_body_is_error_envelope_compliant(boundary_app) -> None:
    """Missing required anchor -> 400 body validates against ErrorEnvelope."""
    app, mock, _db_path = boundary_app
    with TestClient(app) as client:
        response = client.post(
            "/v1/state/transition",
            json={"scope_kind": "run"},  # missing scope_id and the rest
        )
        assert response.status_code == 400, response.text
        body = response.json()
        env = _assert_error_envelope(body)
        assert env.code == "RELAY-ING-001"
        assert env.http_status == 400
        assert env.retry_advice == "after_fix"
        assert mock.invocations == [], mock.invocations


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_stale_handoff_gate_021_is_error_envelope_compliant(boundary_app) -> None:
    """Stale handoff -> 409 RELAY-GATE-021 body validates against ErrorEnvelope."""
    app, _mock, db_path = boundary_app
    with TestClient(app) as client:
        identity_hash = "sha256-" + "a" * 64
        _seed_actor(db_path, identity_hash=identity_hash)
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
        env = _assert_error_envelope(body)
        assert env.code == "RELAY-GATE-021"
        assert env.http_status == 409
        assert env.retry_advice == "do_not_retry"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_gate_021_envelope_helper_is_error_envelope_compliant() -> None:
    """``_gate_021_envelope`` output validates against ErrorEnvelope directly."""
    body = _gate_021_envelope(reason="manifest_not_active")
    env = _assert_error_envelope(body)
    assert env.code == "RELAY-GATE-021"
    assert env.http_status == 409
    assert env.retry_advice == "do_not_retry"
    assert env.details == {"reason": "manifest_not_active"}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-056")
def test_context_envelope_helper_is_error_envelope_compliant() -> None:
    """``_context_envelope`` output validates against ErrorEnvelope directly."""
    body = _context_envelope(
        observed_hash="sha256-" + "c" * 64,
        pinned_hash="sha256-" + "b" * 64,
    )
    env = _assert_error_envelope(body)
    assert env.code == "RELAY-SIDECAR-008"
    assert env.http_status == 409
    assert env.retry_advice == "after_fix"
    assert env.details is not None
    assert env.details["observed_manifest_commit_hash"] == "sha256-" + "c" * 64
    assert env.details["pinned_manifest_commit_hash"] == "sha256-" + "b" * 64


# ---------------------------------------------------------------------------
# F4: post-CAS (compare_and_set) failure branch MUST return a canonical
# ErrorEnvelope, not a bare dict. The route's 4xx bodies are declared as
# ``$ref: ErrorEnvelope`` in openapi.yaml (additionalProperties:false +
# code pattern ^RELAY-[A-Z]+-[0-9]{3}$). Two concrete defects fixed here:
#   (a) EXPECTED_FROM_MISMATCH / TERMINAL_STATE returned a bare 409 dict.
#   (b) HANDOFF_INVALID had NO status_map entry -> fell through to an
#       UNDECLARED 422 + bare dict instead of 409 + RELAY-GATE-021.
# ---------------------------------------------------------------------------


@dataclass
class _ResultMockEngine:
    """State engine that returns a preset StateTransitionResult.

    Used to exercise the post-CAS failure branch deterministically: the
    pre-CAS three-anchor handoff (seeded actor + manifest) passes, the
    engine is invoked exactly once, and it returns the configured failure.
    """

    result: StateTransitionResult
    invocations: list[dict[str, Any]] = field(default_factory=list)

    async def transition_fn(self, **kwargs: Any) -> StateTransitionResult:
        self.invocations.append(kwargs)
        return self.result


def _build_boundary_app_with_engine(db_path: Path, engine: Any) -> FastAPI:
    """Build a FastAPI app whose state router uses ``engine``.

    Mirrors the ``boundary_app`` fixture but lets the caller inject an
    engine that returns a specific (failing) StateTransitionResult.
    """
    db = SidecarDatabase(db_path=db_path, reader_count=1)

    def _factory(_db: SidecarDatabase) -> StateEngineProtocol:
        return StateEngineProtocol(transition_fn=engine.transition_fn)

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
    return app


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_post_cas_handoff_invalid_returns_409_gate_021_envelope(tmp_path) -> None:
    """Post-CAS HANDOFF_INVALID -> 409 + RELAY-GATE-021 canonical envelope.

    The pre-CAS handoff passes (actor + manifest seeded). The CAS-internal
    three-anchor guard then rejects with reason HANDOFF_INVALID. Before the
    fix this fell through ``status_map.get(..., 422)`` -> an undeclared 422
    + bare dict. It MUST be 409 + RELAY-GATE-021 (keystone #4).
    """
    db_path = tmp_path / "sidecar.db"
    engine = _ResultMockEngine(
        result=StateTransitionResult(
            ok=False,
            reason=HANDOFF_INVALID,
            observed_state="pending",
            epoch=0,
            extras={"failed_guard": "three_anchor_handoff"},
        )
    )
    app = _build_boundary_app_with_engine(db_path, engine)
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
        assert response.status_code == 409, response.text
        body = response.json()
        env = _assert_error_envelope(body)
        assert env.code == "RELAY-GATE-021", body
        assert env.http_status == 409
        assert env.details is not None
        assert env.details["reason"] == HANDOFF_INVALID
        # The engine WAS invoked once (this is the post-CAS path).
        assert len(engine.invocations) == 1, engine.invocations


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-062")
def test_post_cas_expected_from_mismatch_is_error_envelope_compliant(
    tmp_path,
) -> None:
    """Post-CAS EXPECTED_FROM_MISMATCH -> 409 + schema-complete ErrorEnvelope.

    Before the fix this returned a bare ``{ok, reason, observed_state, ...}``
    dict that fails ErrorEnvelope validation (missing schema_version/code/
    http_status/blocked_surface/retry_advice/request_id/trace_id).
    """
    db_path = tmp_path / "sidecar.db"
    engine = _ResultMockEngine(
        result=StateTransitionResult(
            ok=False,
            reason=EXPECTED_FROM_MISMATCH,
            observed_state="gated",
            epoch=3,
        )
    )
    app = _build_boundary_app_with_engine(db_path, engine)
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
        assert response.status_code == 409, response.text
        body = response.json()
        env = _assert_error_envelope(body)
        # Registered, pattern-matching code (^RELAY-[A-Z]+-[0-9]{3}$).
        assert env.code == "RELAY-GATE-001", body
        assert env.http_status == 409
        assert env.details is not None
        assert env.details["reason"] == EXPECTED_FROM_MISMATCH
        assert env.details["observed_state"] == "gated"
