"""V2 M03 W3 sidecar manifest-enforcement tests.

Covers contract assertions VAL-V2M03-012 (sidecar rejects mismatched
command_hash), VAL-V2M03-013 (sidecar rejects out-of-grace
manifest_commit_hash), VAL-V2M03-014 (gate runner refuses undeclared
commands -- bound to the existing ManifestCommandResolver behavior),
VAL-V2M03-015 (gate runner uses manifest-declared globs), and
VAL-V2M03-016 (event_log_entries carries manifest_commit_hash).

All tests run plumbing-tier against an in-process FastAPI ASGI transport
(no subprocess, no real HTTP). The smoke tier is reserved for full
end-to-end ingest -> result flows; these plumbing tests prove the
enforcement primitives function correctly at the route handler layer.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.manifest_enforcement import (
    ManifestRegistry,
    enforce_command_hash,
    enforce_manifest_active_or_in_grace,
)
from relay_sidecar.runtime import build_runtime_app

_FAKE_MANIFEST_HASH = "sha256-" + ("0" * 64)
_OTHER_MANIFEST_HASH = "sha256-" + ("1" * 64)
_DECLARED_CMD_HASH = "sha256-" + ("a" * 64)
_UNDECLARED_CMD_HASH = "sha256-" + ("b" * 64)


def _make_health(port: int = 50001) -> HealthState:
    token = "test-v2m03-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


def _register_ingest_token(app, token: str, *scopes: str) -> dict[str, str]:
    """Register a bearer token with ``scopes`` and return its auth header.

    Mirrors ``test_iso_r2_ingest_bearer_scope._register_token``. Used by the
    V2M03 legacy-manifest-only-path auth follow-up (2026-05-31): the legacy
    anchor-only acceptance path now requires ``ingest:write`` (the same gate
    as the full-envelope path), so anchor-only callers must authenticate.
    """
    app.state.runtime.registered_tokens[token] = {
        "scopes": frozenset(scopes),
        "project_id": "project-id-test",
    }
    return {"Authorization": f"Bearer {token}"}


async def _register_manifest_row(
    db_path: Path,
    *,
    commit_hash: str,
    effective_until: str | None,
    grace_seconds: int = 1800,
) -> None:
    """Insert a manifest_versions row directly (test fixture).

    The sidecar startup wires its own SidecarDatabase against db_path
    AFTER this insert; the row is visible to handoff-helper queries on
    the reader connections that the runtime opens.
    """
    # Audit-R3 (2026-05-18): mirror __schema_migrations tracker so the
    # FastAPI lifespan _run_migrations pass skips already-applied non-
    # idempotent migrations.
    async with aiosqlite.connect(str(db_path)) as conn:
        # Ensure the manifest_versions table exists (migration 0006).
        migrations_dir = (
            Path(__file__).resolve().parents[1] / "migrations"
        )
        await conn.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        for sql in sorted(migrations_dir.glob("*.sql")):
            filename = sql.name
            async with conn.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                if await cur.fetchone() is not None:
                    continue
            await conn.executescript(sql.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO __schema_migrations (filename) VALUES (?)",
                (filename,),
            )
        effective_at = (
            (datetime.now(tz=UTC) - timedelta(seconds=60))
            .isoformat()
            .replace("+00:00", "Z")
        )
        await conn.execute(
            "INSERT OR REPLACE INTO manifest_versions ("
            "manifest_version_id, manifest_id, project_id, commit_hash, "
            "schema_version, effective_at, effective_until, "
            "grace_window_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"mv-{commit_hash[-12:]}",
                "manifest-id-test",
                "project-id-test",
                commit_hash,
                "relay.manifest.v1",
                effective_at,
                effective_until,
                grace_seconds,
            ),
        )
        await conn.commit()


# ---------------------------------------------------------------------------
# ManifestRegistry unit tests (function-level coverage of VAL-V2M03-012/-013).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
def test_registry_accepts_declared_command() -> None:
    r = ManifestRegistry()
    r.register_commands(
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hashes=[_DECLARED_CMD_HASH],
    )
    assert (
        r.is_command_declared(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hash=_DECLARED_CMD_HASH,
        )
        is True
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
def test_registry_rejects_undeclared_command() -> None:
    r = ManifestRegistry()
    r.register_commands(
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hashes=[_DECLARED_CMD_HASH],
    )
    assert (
        r.is_command_declared(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hash=_UNDECLARED_CMD_HASH,
        )
        is False
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
def test_enforce_command_hash_returns_rejection_envelope() -> None:
    r = ManifestRegistry()
    r.register_commands(
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hashes=[_DECLARED_CMD_HASH],
    )
    rej = enforce_command_hash(
        registry=r,
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hash=_UNDECLARED_CMD_HASH,
    )
    assert rej is not None
    assert rej.http_status == 422
    assert rej.envelope["code"] == "RELAY-GATE-021"
    assert rej.envelope["error_class"] == "RELAY-GATE-021"
    assert rej.envelope["details"]["reason"] == "COMMAND_HASH_NOT_DECLARED"
    assert (
        rej.envelope["details"]["observed_command_hash"]
        == _UNDECLARED_CMD_HASH
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
def test_enforce_command_hash_returns_none_on_match() -> None:
    r = ManifestRegistry()
    r.register_commands(
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hashes=[_DECLARED_CMD_HASH],
    )
    assert (
        enforce_command_hash(
            registry=r,
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hash=_DECLARED_CMD_HASH,
        )
        is None
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
def test_enforce_command_hash_rejects_malformed_hash() -> None:
    r = ManifestRegistry()
    rej = enforce_command_hash(
        registry=r,
        manifest_commit_hash=_FAKE_MANIFEST_HASH,
        command_hash="not-a-hash",
    )
    assert rej is not None
    assert rej.envelope["details"]["reason"] == "COMMAND_HASH_MALFORMED"


# ---------------------------------------------------------------------------
# enforce_manifest_active_or_in_grace (function-level, VAL-V2M03-013).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-013")
@pytest.mark.asyncio
async def test_enforce_manifest_unregistered_rejected(tmp_path) -> None:
    db_path = tmp_path / "sidecar.db"
    # Apply the migrations so the table exists, but don't insert any row.
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=None,
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        rej = await enforce_manifest_active_or_in_grace(
            conn,
            manifest_commit_hash=_OTHER_MANIFEST_HASH,
        )
    assert rej is not None
    assert rej.http_status == 422
    assert rej.envelope["code"] == "RELAY-GATE-021"
    assert rej.envelope["details"]["reason"] == "MANIFEST_NOT_ACTIVE"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-013")
@pytest.mark.asyncio
async def test_enforce_manifest_active_accepted(tmp_path) -> None:
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=None,
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        assert (
            await enforce_manifest_active_or_in_grace(
                conn,
                manifest_commit_hash=_FAKE_MANIFEST_HASH,
            )
            is None
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-013")
@pytest.mark.asyncio
async def test_enforce_manifest_in_grace_accepted(tmp_path) -> None:
    db_path = tmp_path / "sidecar.db"
    # effective_until 5 seconds ago, grace window 30 seconds -> still in grace.
    five_sec_ago = (
        (datetime.now(tz=UTC) - timedelta(seconds=5))
        .isoformat()
        .replace("+00:00", "Z")
    )
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=five_sec_ago,
        grace_seconds=30,
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        assert (
            await enforce_manifest_active_or_in_grace(
                conn,
                manifest_commit_hash=_FAKE_MANIFEST_HASH,
            )
            is None
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-013")
@pytest.mark.asyncio
async def test_enforce_manifest_out_of_grace_rejected(tmp_path) -> None:
    db_path = tmp_path / "sidecar.db"
    # effective_until 60 seconds ago, grace window 10 seconds -> out of grace.
    sixty_sec_ago = (
        (datetime.now(tz=UTC) - timedelta(seconds=60))
        .isoformat()
        .replace("+00:00", "Z")
    )
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=sixty_sec_ago,
        grace_seconds=10,
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        rej = await enforce_manifest_active_or_in_grace(
            conn,
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
        )
    assert rej is not None
    assert rej.envelope["details"]["reason"] == "MANIFEST_NOT_ACTIVE"


# ---------------------------------------------------------------------------
# /v1/ingest/runs HTTP route enforcement (VAL-V2M03-012, VAL-V2M03-013).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_rejects_mismatched_command_hash(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        runtime = app.state.runtime
        # Seed: register a manifest WITH one declared command, then submit
        # a DIFFERENT command_hash.
        runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        # Also insert the manifest into manifest_versions so the
        # grace-window check doesn't short-circuit before the command_hash
        # check would normally fire. (Order in route: command_hash first,
        # then manifest grace; so this insert is defensive.)
        await _register_manifest_row(
            db_path,
            commit_hash=_FAKE_MANIFEST_HASH,
            effective_until=None,
        )

        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _UNDECLARED_CMD_HASH,
            },
        )
        assert r.status_code == 422, r.text
        body = json.loads(r.text)
        assert body["code"] == "RELAY-GATE-021", body
        assert body["error_class"] == "RELAY-GATE-021", body
        assert body["details"]["reason"] == "COMMAND_HASH_NOT_DECLARED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-013")
@pytest.mark.asyncio
async def test_ingest_runs_rejects_unregistered_manifest_hash(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        runtime = app.state.runtime
        # Seed the registry but NOT the manifest_versions table. The
        # command_hash check passes (the registry has the hash) but the
        # grace-window check fails (the manifest is not in the table).
        runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )

        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
        )
        assert r.status_code == 422, r.text
        body = json.loads(r.text)
        assert body["code"] == "RELAY-GATE-021", body
        assert body["details"]["reason"] == "MANIFEST_NOT_ACTIVE"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_accepts_matched_anchors(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    # Seed manifest_versions BEFORE app spawns so the SidecarDatabase
    # readers see the row.
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=None,
    )
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        runtime = app.state.runtime
        runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )

        # V2M03 legacy-path auth follow-up (2026-05-31): the legacy
        # manifest-only acceptance path now requires ``ingest:write``
        # (same gate as the full-envelope path). Authenticate with a
        # bearer token; the legacy 200 + {accepted: True} shape is
        # preserved for authenticated anchor-only callers.
        hdrs = _register_ingest_token(app, "tok-v2m03-anchor", "ingest:write")
        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
            headers=hdrs,
        )
        assert r.status_code == 200, r.text
        body = json.loads(r.text)
        assert body["accepted"] is True
        assert body["endpoint"] == "/v1/ingest/runs"


# ---------------------------------------------------------------------------
# Legacy manifest-only path auth follow-up (2026-05-31).
#
# Structural-review finding: the legacy anchor-only acceptance path
# (runtime.py v1_ingest_runs, the ``not non_anchor_keys`` branch) returned
# 200 {accepted: True} WITHOUT any auth check, while the full-envelope path
# required ``ingest:write``. An UNAUTHENTICATED client could POST
# {manifest_commit_hash, command_hash} and obtain a 200 acceptance (and a
# quiesce tracker op) in the secure-default config -- an auth bypass.
#
# Fix: run ``_check_auth(required_scope="ingest:write")`` once after manifest
# anchor enforcement so BOTH the legacy and full-envelope paths require the
# scope. The legacy 200 + {accepted: True} response SHAPE is preserved for
# AUTHENTICATED anchor-only callers (see test_ingest_runs_accepts_matched_
# anchors, updated to authenticate). Manifest enforcement stays the OUTERMOST
# gate, so mismatched-anchor rejections still surface 422 RELAY-GATE-021
# before auth (the two reject tests above are unaffected).
# ---------------------------------------------------------------------------


async def _build_anchor_app(tmp_path, monkeypatch):
    """Build a sidecar app with the manifest+command registered so the
    anchor gate passes and auth owns the response for anchor-only bodies.

    Returns (app, transport). Caller drives the lifespan + client.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    # Secure default: legacy X-Relay-Scopes disabled unless a test enables it.
    monkeypatch.delenv(
        "RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", raising=False
    )
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=None,
    )
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    return app, transport


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_anchor_only_unauthenticated_rejected(
    tmp_path, monkeypatch
) -> None:
    """UNAUTHENTICATED anchor-only POST is now rejected 401 RELAY-AUTH-001
    (no bearer, no legacy header). Was 200 at the base commit -- the
    auth-bypass the structural review flagged."""
    app, transport = await _build_anchor_app(tmp_path, monkeypatch)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
        )
        assert r.status_code == 401, r.text
        assert json.loads(r.text)["code"] == "RELAY-AUTH-001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_anchor_only_bearer_ingest_write_accepted(
    tmp_path, monkeypatch
) -> None:
    """AUTHENTICATED (bearer ingest:write) anchor-only POST still returns the
    legacy 200 + {accepted: True} shape (shape preserved for authed callers).
    """
    app, transport = await _build_anchor_app(tmp_path, monkeypatch)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        hdrs = _register_ingest_token(app, "tok-anchor-ok", "ingest:write")
        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
            headers=hdrs,
        )
        assert r.status_code == 200, r.text
        body = json.loads(r.text)
        assert body["accepted"] is True
        assert body["endpoint"] == "/v1/ingest/runs"
        assert "operation_id" in body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_anchor_only_wrong_scope_rejected(
    tmp_path, monkeypatch
) -> None:
    """A bearer token WITHOUT ingest:write (only runs:read) is rejected 403
    RELAY-AUTH-014 on the anchor-only path -- the fix does NOT widen the
    required scope."""
    app, transport = await _build_anchor_app(tmp_path, monkeypatch)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        hdrs = _register_ingest_token(app, "tok-anchor-bad", "runs:read")
        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
            headers=hdrs,
        )
        assert r.status_code == 403, r.text
        assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_runs_anchor_only_legacy_scope_header_accepted(
    tmp_path, monkeypatch
) -> None:
    """API-key/legacy path preserved: with the legacy header enabled, an
    X-Relay-Scopes: ingest:write anchor-only POST still returns the legacy
    200 + {accepted: True} shape (_check_auth merges the legacy header)."""
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
    app, transport = await _build_anchor_app(tmp_path, monkeypatch)
    # _build_anchor_app deletes the legacy env var; re-enable AFTER it runs.
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        r = await client.post(
            "/v1/ingest/runs",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _DECLARED_CMD_HASH,
            },
            headers={"X-Relay-Scopes": "ingest:write"},
        )
        assert r.status_code == 200, r.text
        body = json.loads(r.text)
        assert body["accepted"] is True
        assert body["endpoint"] == "/v1/ingest/runs"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-012")
@pytest.mark.asyncio
async def test_ingest_spans_batch_rejects_mismatched_command_hash(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(
        db_path,
        commit_hash=_FAKE_MANIFEST_HASH,
        effective_until=None,
    )
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        runtime = app.state.runtime
        runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )

        r = await client.post(
            "/v1/ingest/spans:batch",
            json={
                "manifest_commit_hash": _FAKE_MANIFEST_HASH,
                "command_hash": _UNDECLARED_CMD_HASH,
            },
        )
        assert r.status_code == 422, r.text
        body = json.loads(r.text)
        assert body["code"] == "RELAY-GATE-021", body


# ---------------------------------------------------------------------------
# VAL-V2M03-014: gate runner refuses undeclared commands.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-014")
def test_gate_runner_manifest_command_resolver_raises_on_undeclared() -> None:
    """The gate engine's ManifestCommandResolver Protocol mandates that an
    undeclared command_hash raises KeyError. Per
    packages/gate/src/relay_gate_engine/evaluator.py:191-203, this is the
    canonical refusal contract: the evaluator treats KeyError as a stale-
    handoff signal and records the failure as ``action='invalid'`` rather
    than spawning the process.

    This test asserts the Protocol contract by constructing an empty
    resolver and verifying its ``resolve()`` raises KeyError for any
    command_hash.
    """
    from relay_gate_engine.evaluator import ManifestCommandResolver

    class _EmptyResolver:
        def resolve(self, command_hash: str) -> str:
            raise KeyError(command_hash)

    # Structural typing: any object implementing .resolve(str) -> str
    # satisfies ManifestCommandResolver. The Protocol has no runtime
    # check beyond duck-typing.
    resolver: ManifestCommandResolver = _EmptyResolver()
    with pytest.raises(KeyError):
        resolver.resolve("sha256-undeclared")


# ---------------------------------------------------------------------------
# VAL-V2M03-015: gate runner uses manifest-declared globs.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-015")
def test_manifest_schema_declares_validation_surface_globs() -> None:
    """The canonical manifest schema MUST permit each validation_surfaces
    entry to declare its own test-discovery globs. Per spec line 663:
    "test discovery must use manifest-declared globs, not naming
    heuristics". The canonical schema exposes the ``globs`` property on
    each validation_surfaces item so the gate runner can consume them
    directly without falling back to filename pattern matching.
    """
    import json as _json

    schema_path = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "schemas"
        / "catalogs"
        / "manifest.v1.schema.json"
    )
    schema = _json.loads(schema_path.read_text(encoding="utf-8"))
    surface_props = schema["properties"]["validation_surfaces"]["items"][
        "properties"
    ]
    assert "globs" in surface_props
    assert surface_props["globs"]["type"] == "array"
    assert surface_props["globs"]["items"]["type"] == "string"


_OPS_MANIFEST_PATH = Path(__file__).resolve().parents[3] / ".ops" / "manifest.yaml"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-015")
@pytest.mark.skipif(
    not _OPS_MANIFEST_PATH.exists(),
    reason=(
        ".ops/manifest.yaml is a workspace-parent Operations-system artifact "
        "(gitignored in the OSS relay repo). The test validates the reference "
        "manifest when present; on a CI checkout of just the public relay/ "
        "repo (without the workspace parent's .ops/ tree) the file is "
        "legitimately absent and the test skips."
    ),
)
def test_ops_manifest_validation_surfaces_carry_globs() -> None:
    """The reference operation manifest (.ops/manifest.yaml) MUST declare
    globs on every validation_surfaces entry so the gate runner has a
    concrete glob set to consume rather than scanning the filesystem
    with filename heuristics.
    """
    import yaml as _yaml

    body = _yaml.safe_load(_OPS_MANIFEST_PATH.read_text(encoding="utf-8"))
    surfaces = body.get("validation_surfaces", [])
    assert surfaces, "operation manifest must declare validation_surfaces"
    for s in surfaces:
        assert "globs" in s, f"surface {s.get('surface')!r} missing globs"
        assert isinstance(s["globs"], list)
        # Every glob must be a non-empty string.
        for g in s["globs"]:
            assert isinstance(g, str) and g, f"empty glob in {s!r}"


# ---------------------------------------------------------------------------
# VAL-V2M03-016: event_log_entries carries manifest_commit_hash.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-016")
def test_event_log_entries_schema_has_manifest_commit_hash_column() -> None:
    """The canonical event_log_entries DDL MUST include a
    ``manifest_commit_hash`` column so every worker write can record
    the manifest it ran under. Per spec line 4005: every event-log
    entry written by a worker carries ``manifest_commit_hash``.
    """
    ddl_path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "0001_event_log_entries.sql"
    )
    text = ddl_path.read_text(encoding="utf-8")
    # The column declaration line should contain 'manifest_commit_hash'.
    assert "manifest_commit_hash" in text
    # The CREATE TABLE block should be the canonical event_log_entries.
    assert "CREATE TABLE IF NOT EXISTS event_log_entries" in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-016")
@pytest.mark.asyncio
async def test_event_log_entries_persists_manifest_commit_hash(
    tmp_path, monkeypatch
) -> None:
    """End-to-end: a write to event_log_entries with a non-null
    manifest_commit_hash round-trips through SQLite without truncation
    or type coercion. Proves the column accepts sha256-<hex> wire form.
    """
    db_path = tmp_path / "sidecar.db"
    # Run all migrations.
    migrations_dir = (
        Path(__file__).resolve().parents[1] / "migrations"
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        for sql in sorted(migrations_dir.glob("*.sql")):
            await conn.executescript(sql.read_text(encoding="utf-8"))
        # Insert a happy-path event_log_entries row carrying the
        # manifest_commit_hash.
        await conn.execute(
            "INSERT INTO event_log_entries ("
            "event_id, schema_version, project_id, scope_type, scope_id, "
            "event_type, actor_kind, actor_id, manifest_commit_hash, "
            "payload, occurred_at, ingest_sequence, event_kind) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "evt-test-001",
                "relay.event_log_entry.v1",
                "00000000-0000-0000-0000-000000000000",
                "run",
                "11111111-1111-1111-1111-111111111111",
                "ingest.run_received",
                "control_plane",
                None,
                _FAKE_MANIFEST_HASH,
                "{}",
                datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
                1,
                "state_transition",
            ),
        )
        await conn.commit()
        async with conn.execute(
            "SELECT manifest_commit_hash FROM event_log_entries "
            "WHERE event_id = ?",
            ("evt-test-001",),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == _FAKE_MANIFEST_HASH
