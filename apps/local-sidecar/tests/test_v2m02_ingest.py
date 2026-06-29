"""V2 M02 W2.1 sidecar ingest-namespace HTTP endpoint tests.

Covers contract assertions VAL-V2M02-001..009 (the nine assertions owned
by sub-feature w2.1 in the relay-v0.2-oss-completeness operation):

  - VAL-V2M02-001  POST /v1/ingest/runs accepts well-formed envelope (201).
  - VAL-V2M02-002  POST /v1/ingest/runs rejects malformed body (422 RELAY-ING-001).
  - VAL-V2M02-003  POST /v1/ingest/runs rejects SDK-set canonical status (422 RELAY-ING-031).
  - VAL-V2M02-004  POST /v1/ingest/runs enforces ingest:write scope (403 RELAY-AUTH-014).
  - VAL-V2M02-005  POST /v1/ingest/spans:batch accepts batched envelope (202).
  - VAL-V2M02-006  POST /v1/ingest/spans:batch rejects >1 MiB body (413 RELAY-ING-021).
  - VAL-V2M02-007  POST /v1/ingest/spans:batch enforces ingest:write scope.
  - VAL-V2M02-008  POST /v1/ingest/contract-results:batch accepts batch (202).
  - VAL-V2M02-009  POST /v1/ingest/contract-results:batch enforces ingest:write.

All tests run plumbing-tier against the in-process FastAPI ASGI transport
(no subprocess, no real HTTP). Scopes are seeded onto a local "dev" token
via the ``X-Relay-Scopes`` request header (the contract calls out this
local fixture mechanism explicitly: "scopes are seeded onto a local 'dev'
token via a fixture").

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

# ---- Test fixtures --------------------------------------------------------

_FAKE_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DECLARED_CMD_HASH = "sha256-" + ("a" * 64)


def _make_health(port: int = 50091) -> HealthState:
    token = "test-v2m02-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _register_manifest_row(
    db_path: Path,
    *,
    commit_hash: str,
    effective_until: str | None = None,
    grace_seconds: int = 1800,
) -> None:
    """Insert a manifest_versions row before the sidecar starts so the
    manifest grace-window check returns ACCEPT for ``commit_hash``.
    """
    # Audit-R3 (2026-05-18): mirror __schema_migrations tracker so the
    # FastAPI lifespan _run_migrations pass skips already-applied non-
    # idempotent migrations.
    async with aiosqlite.connect(str(db_path)) as conn:
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
                f"mv-v2m02-{commit_hash[-12:]}",
                "manifest-id-v2m02",
                "project-id-v2m02",
                commit_hash,
                "relay.manifest.v1",
                effective_at,
                effective_until,
                grace_seconds,
            ),
        )
        await conn.commit()


def _well_formed_run_envelope() -> dict[str, object]:
    """Build a minimal well-formed relay.run.v1 envelope per spec B.2.

    Carries the three-anchor handoff + the declared command_hash so the
    manifest-enforcement layer also accepts. Lifecycle status uses the
    spec's ``client_lifecycle_status`` enum (started) -- this is SDK
    lifecycle metadata, NOT the canonical run_results.status field.
    """
    return {
        "schema_version": "relay.ingest.run.v1",
        "run_id": "01HX0000000000000000000001",
        "project_id": "project-id-v2m02",
        "trace_id": "01HX0000000000000000000002",
        "client_lifecycle_status": "started",
        "started_at": "2026-05-17T00:00:00.000Z",
        "sdk_version": "relay-python@0.0.0",
        "sdk_clock": "2026-05-17T00:00:00.000Z",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "actor_identity_hash": "sha256-" + ("c" * 64),
        "redaction_policy_version": "relay.redaction.v1@2026-05-17",
        "idempotency_key": "01HX0000000000000000000003",
        "sequence_number": 1,
        "agent": {"name": "test-agent", "version": "0.0.0"},
        "metadata": {},
    }


def _ingest_write_headers() -> dict[str, str]:
    """Headers seeding the local 'dev' token with ingest:write scope."""
    return {"X-Relay-Scopes": "ingest:write"}


def _no_scope_headers() -> dict[str, str]:
    """Headers with an empty scope set (token present but no scopes)."""
    return {"X-Relay-Scopes": ""}


@pytest_asyncio.fixture
async def sidecar_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, object]]:
    """Yield an HTTP client + runtime with manifest+command pre-registered.

    Both the manifest_versions row AND the in-memory command-hash registry
    are seeded so the manifest-enforcement layer (which runs BEFORE the
    body-shape validation per W3 design) returns ACCEPT and the
    body-shape / scope checks own the actual response.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    # Audit fix (2026-05-17 P0): legacy X-Relay-Scopes header opt-in.
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
        ) as client,
    ):
        runtime = app.state.runtime
        runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        yield client, runtime


# ---- VAL-V2M02-001: runs happy path ---------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-001")
@pytest.mark.asyncio
async def test_ingest_runs_accepts_well_formed_envelope(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    envelope = _well_formed_run_envelope()
    r = await client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 201, r.text
    assert r.headers["content-type"].startswith("application/json")
    body = json.loads(r.text)
    assert body["run_id"] == envelope["run_id"]
    assert body["schema_version"] == "relay.ingest.run.v1"


# ---- VAL-V2M02-002: runs malformed body -> 422 RELAY-ING-001 -------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-002")
@pytest.mark.asyncio
async def test_ingest_runs_rejects_malformed_body(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    envelope = _well_formed_run_envelope()
    # Strip a required envelope field (project_id is required by relay.run.v1).
    envelope.pop("project_id")
    r = await client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 422, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-ING-001"
    assert body["http_status"] == 422
    assert body["blocked_surface"] == "POST /v1/ingest/runs"
    # The canonical error envelope MUST carry schema_version per spec B.4.
    assert body["schema_version"] == "relay.error.v1"


# ---- VAL-V2M02-003: SDK-set canonical status -> 422 RELAY-ING-031 --------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-003")
@pytest.mark.asyncio
async def test_ingest_runs_rejects_sdk_set_canonical_status(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    envelope = _well_formed_run_envelope()
    # CLAUDE.md keystone invariant #1: the control plane writes the
    # canonical status; the SDK must NEVER include it on the wire.
    envelope["status"] = "accepted"
    r = await client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 422, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-ING-031"
    assert body["http_status"] == 422


# ---- VAL-V2M02-004: ingest:write scope enforced --------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-004")
@pytest.mark.asyncio
async def test_ingest_runs_enforces_ingest_write_scope(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    envelope = _well_formed_run_envelope()
    # Empty scope set -> 403 RELAY-AUTH-014.
    r = await client.post(
        "/v1/ingest/runs", json=envelope, headers=_no_scope_headers()
    )
    assert r.status_code == 403, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-AUTH-014"
    assert body["http_status"] == 403

    # Same body WITH scope succeeds.
    r2 = await client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r2.status_code == 201, r2.text


# ---- VAL-V2M02-005: spans:batch happy path -------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-005")
@pytest.mark.asyncio
async def test_ingest_spans_batch_accepts_batched_envelope(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    body = {
        "schema_version": "relay.ingest.spans.v1",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "spans": [
            {
                "span_id": "01HX0000000000000000000010",
                "run_id": "01HX0000000000000000000011",
                "span_type": "custom",
                "name": "test-span-a",
                "status": "ok",
                "started_at": "2026-05-17T00:00:00.000Z",
                "side_effect_class": "read_only",
            },
            {
                "span_id": "01HX0000000000000000000012",
                "run_id": "01HX0000000000000000000011",
                "span_type": "custom",
                "name": "test-span-b",
                "status": "ok",
                "started_at": "2026-05-17T00:00:00.000Z",
                "side_effect_class": "read_only",
            },
        ],
    }
    r = await client.post(
        "/v1/ingest/spans:batch", json=body, headers=_ingest_write_headers()
    )
    assert r.status_code == 202, r.text
    resp = json.loads(r.text)
    assert resp["accepted_count"] == 2
    assert isinstance(resp["batch_id"], str) and resp["batch_id"]


# ---- VAL-V2M02-006: spans:batch >1 MiB -> 413 RELAY-ING-021 --------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-006")
@pytest.mark.asyncio
async def test_ingest_spans_batch_rejects_oversized_payload(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    # Build a body whose serialized JSON is strictly greater than 1 MiB.
    # 1 MiB = 1048576 bytes; pad with a 1.5 MiB string so the encoded
    # request body easily exceeds the cap.
    padding = "x" * (1024 * 1024 + 64 * 1024)
    body = {
        "schema_version": "relay.ingest.spans.v1",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "spans": [],
        "oversize_padding": padding,
    }
    r = await client.post(
        "/v1/ingest/spans:batch", json=body, headers=_ingest_write_headers()
    )
    assert r.status_code == 413, r.text
    resp = json.loads(r.text)
    assert resp["code"] == "RELAY-ING-021"
    assert resp["http_status"] == 413


# ---- VAL-V2M02-007: spans:batch scope check ------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-007")
@pytest.mark.asyncio
async def test_ingest_spans_batch_enforces_ingest_write_scope(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    body = {
        "schema_version": "relay.ingest.spans.v1",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "spans": [],
    }
    r = await client.post(
        "/v1/ingest/spans:batch", json=body, headers=_no_scope_headers()
    )
    assert r.status_code == 403, r.text
    resp = json.loads(r.text)
    assert resp["code"] == "RELAY-AUTH-014"

    r2 = await client.post(
        "/v1/ingest/spans:batch", json=body, headers=_ingest_write_headers()
    )
    assert r2.status_code == 202, r2.text


# ---- VAL-V2M02-008: contract-results:batch happy path --------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-008")
@pytest.mark.asyncio
async def test_ingest_contract_results_batch_accepts(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    body = {
        "schema_version": "relay.ingest.contract_results.v1",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "contract_results": [
            {
                "contract_result_id": "01HX0000000000000000000020",
                "run_id": "01HX0000000000000000000011",
                "contract_id": "contract-a",
                "contract_version": "1",
                "outcome": "pass",
                "evaluation_engine_version": "cel-wasm@1.0.0",
                "evaluated_at": "2026-05-17T00:00:00.000Z",
            },
            {
                "contract_result_id": "01HX0000000000000000000021",
                "run_id": "01HX0000000000000000000011",
                "contract_id": "contract-b",
                "contract_version": "1",
                "outcome": "fail",
                "severity": "p1",
                "evaluation_engine_version": "cel-wasm@1.0.0",
                "evaluated_at": "2026-05-17T00:00:00.000Z",
            },
        ],
    }
    r = await client.post(
        "/v1/ingest/contract-results:batch",
        json=body,
        headers=_ingest_write_headers(),
    )
    assert r.status_code == 202, r.text
    resp = json.loads(r.text)
    assert resp["accepted_count"] == 2


# ---- VAL-V2M02-009: contract-results:batch scope check -------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-009")
@pytest.mark.asyncio
async def test_ingest_contract_results_batch_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, object],
) -> None:
    client, _runtime = sidecar_client
    body = {
        "schema_version": "relay.ingest.contract_results.v1",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "contract_results": [],
    }
    r = await client.post(
        "/v1/ingest/contract-results:batch",
        json=body,
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403, r.text
    resp = json.loads(r.text)
    assert resp["code"] == "RELAY-AUTH-014"
