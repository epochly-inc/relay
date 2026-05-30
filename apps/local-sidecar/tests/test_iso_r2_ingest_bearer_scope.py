"""VAL-ISO-002 (round-2 follow-up): bearer-authenticated clients must reach
the /v1/ingest/* WRITE endpoints in the secure-default config.

Bug (base commit eef1007): iso-002 migrated the read/replay/eval handlers
from ``_check_required_scope`` to ``_check_auth`` so bearer-token scopes are
consulted, but the three ``/v1/ingest/*`` full-envelope write paths
(``v1_ingest_runs``, ``v1_ingest_spans_batch``,
``v1_ingest_contract_results_batch``) were OUT OF iso-002's stated scope and
still gate on ``_check_required_scope``. That helper sources scopes ONLY from
``_extract_request_scopes`` (the legacy ``X-Relay-Scopes`` CSV header), which
returns the empty set whenever ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` is
not truthy (the SECURE DEFAULT). A bearer token registered with ``ingest:write``
is therefore rejected with 403 RELAY-AUTH-014 from every ingest write route --
the exact same class of bug iso-002 fixed for reads.

Fix: migrate the three ingest write handlers to ``_check_auth(request,
required_scope="ingest:write", blocked_surface=...)``, which merges the
bearer-token scopes. The CORRECT scope (``ingest:write``) is preserved (no
widening), so a bearer token with the wrong/absent scope is still rejected.
The auth gate stays in its current position (after the manifest-anchor /
body-shape gate, before the canonical-write / required-field / raw_capture
gates), so those subsequent gates still fire after auth passes.

These tests run WITHOUT enabling the legacy header (production default) for the
bearer cases; the API-key (legacy ``X-Relay-Scopes``) case explicitly enables
the legacy header to prove that path is preserved.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app

_FAKE_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DECLARED_CMD_HASH = "sha256-" + ("a" * 64)


def _make_health(port: int = 50094) -> HealthState:
    token = "test-iso-r2-ingest-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _register_manifest_row(db_path: Path, *, commit_hash: str) -> None:
    """Seed migrations + a manifest_versions row so the manifest anchors
    pass and the SCOPE gate owns the response. Mirrors
    ``test_rawcap_ingest_runs_gate._register_manifest_row``.
    """
    async with aiosqlite.connect(str(db_path)) as conn:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
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
                f"mv-isor2-{commit_hash[-12:]}",
                "manifest-id-isor2",
                "project-id-isor2",
                commit_hash,
                "relay.manifest.v1",
                effective_at,
                None,
                1800,
            ),
        )
        await conn.commit()


def _well_formed_run_envelope() -> dict[str, object]:
    """Minimal well-formed relay.ingest.run.v1 envelope (returns 201 when the
    scope gate passes and no raw-eligible field is present)."""
    return {
        "schema_version": "relay.ingest.run.v1",
        "run_id": "01HX0000000000000000ISOR201",
        "project_id": "project-id-isor2",
        "trace_id": "01HX0000000000000000ISOR202",
        "client_lifecycle_status": "started",
        "started_at": "2026-05-28T00:00:00.000Z",
        "sdk_version": "relay-python@0.0.0",
        "sdk_clock": "2026-05-28T00:00:00.000Z",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "actor_identity_hash": "sha256-" + ("c" * 64),
        "redaction_policy_version": "relay.redaction.v1@2026-05-28",
        "idempotency_key": "01HX0000000000000000ISOR203",
        "sequence_number": 1,
        "agent": {"name": "test-agent", "version": "0.0.0"},
        "metadata": {},
    }


def _spans_batch_body() -> dict[str, object]:
    """Full-envelope spans:batch body (carries a non-anchor key so the
    handler takes the v2m02 scope-checked path, not the legacy 200 path)."""
    return {
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "spans": [],
    }


def _contract_results_batch_body() -> dict[str, object]:
    """Full-envelope contract-results:batch body."""
    return {
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "contract_results": [],
    }


@pytest_asyncio.fixture
async def secure_ingest_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    """Sidecar in the SECURE DEFAULT config (legacy X-Relay-Scopes header
    disabled) with the manifest + command pre-registered so anchors pass
    and the SCOPE gate owns the response. Only bearer-token scopes
    authenticate.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.delenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", raising=False)
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(db_path, commit_hash=_FAKE_MANIFEST_HASH)
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as c,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        yield c, db_path, app


@pytest_asyncio.fixture
async def legacy_ingest_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    """Same as ``secure_ingest_client`` but with the legacy
    ``X-Relay-Scopes`` header ENABLED, to prove the API-key/legacy scope
    path is preserved after the migration.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(db_path, commit_hash=_FAKE_MANIFEST_HASH)
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as c,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        yield c, db_path, app


def _register_token(app: object, token: str, *scopes: str) -> dict[str, str]:
    """Register a bearer token with ``scopes`` and return its header."""
    app.state.runtime.registered_tokens[token] = {  # type: ignore[attr-defined]
        "scopes": frozenset(scopes),
        "project_id": "project-id-isor2",
    }
    return {"Authorization": f"Bearer {token}"}


# ---- /v1/ingest/runs ----------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_ingest_write_reaches_runs_ingest(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """A bearer token WITH ingest:write must REACH the runs ingest body
    gates. Before the fix this is 403 RELAY-AUTH-014 (bearer scopes never
    consulted by _check_required_scope). After the fix the scope gate passes
    and a clean envelope returns 201.
    """
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-ingest", "ingest:write")
    r = await c.post(
        "/v1/ingest/runs", json=_well_formed_run_envelope(), headers=hdrs
    )
    assert r.status_code != 403, r.text
    assert r.status_code == 201, r.text
    assert json.loads(r.text)["run_id"] == "01HX0000000000000000ISOR201"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_ingest_write_rejected_from_runs_ingest(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """A bearer token WITHOUT ingest:write (only runs:read) is still
    rejected -- the fix must NOT widen the required scope."""
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-noingest", "runs:read")
    r = await c.post(
        "/v1/ingest/runs", json=_well_formed_run_envelope(), headers=hdrs
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_ingest_write_runs_raw_capture_gate_still_fires(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """After auth passes for a bearer with ingest:write, the downstream
    raw_capture default-deny gate must STILL fire (auth is the FIRST gate,
    not the only gate). A root-level raw-eligible field with no policy must
    be denied 422 -- proving the subsequent gates run after auth passes."""
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-ingest-raw", "ingest:write")
    envelope = _well_formed_run_envelope()
    envelope["model_call"] = {"input": "raw secret prompt text"}
    r = await c.post("/v1/ingest/runs", json=envelope, headers=hdrs)
    assert r.status_code != 403, r.text
    assert r.status_code == 422, r.text


# ---- /v1/ingest/spans:batch ---------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_ingest_write_reaches_spans_batch(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """A bearer token WITH ingest:write must REACH the spans:batch body
    gates (202 on an empty spans list). Before the fix this is 403."""
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-spans", "ingest:write")
    r = await c.post(
        "/v1/ingest/spans:batch", json=_spans_batch_body(), headers=hdrs
    )
    assert r.status_code != 403, r.text
    assert r.status_code == 202, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_ingest_write_rejected_from_spans_batch(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-spans-noscope", "runs:read")
    r = await c.post(
        "/v1/ingest/spans:batch", json=_spans_batch_body(), headers=hdrs
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- /v1/ingest/contract-results:batch ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_ingest_write_reaches_contract_results_batch(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """A bearer token WITH ingest:write must REACH the contract-results:batch
    body gates (202 on an empty list). Before the fix this is 403."""
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-cr", "ingest:write")
    r = await c.post(
        "/v1/ingest/contract-results:batch",
        json=_contract_results_batch_body(),
        headers=hdrs,
    )
    assert r.status_code != 403, r.text
    assert r.status_code == 202, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_ingest_write_rejected_from_contract_results_batch(
    secure_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_ingest_client
    hdrs = _register_token(app, "tok-cr-noscope", "runs:read")
    r = await c.post(
        "/v1/ingest/contract-results:batch",
        json=_contract_results_batch_body(),
        headers=hdrs,
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- Legacy X-Relay-Scopes path preserved (API-key path) ----------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_legacy_scope_header_still_reaches_runs_ingest(
    legacy_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """With the legacy header enabled, an X-Relay-Scopes: ingest:write
    request must STILL reach the runs ingest body gates (201) -- the
    migration must not break the existing legacy/API-key scope path."""
    c, _db, _app = legacy_ingest_client
    r = await c.post(
        "/v1/ingest/runs",
        json=_well_formed_run_envelope(),
        headers={"X-Relay-Scopes": "ingest:write"},
    )
    assert r.status_code != 403, r.text
    assert r.status_code == 201, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_legacy_scope_header_without_ingest_write_still_rejected(
    legacy_ingest_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """A legacy X-Relay-Scopes lacking ingest:write is still rejected 403."""
    c, _db, _app = legacy_ingest_client
    r = await c.post(
        "/v1/ingest/runs",
        json=_well_formed_run_envelope(),
        headers={"X-Relay-Scopes": "runs:read"},
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
