"""V2 M02 W2.3 sidecar replay-namespace HTTP endpoint tests.

Covers contract assertions VAL-V2M02-021..030 (the ten assertions owned
by sub-feature w2.3 in the relay-v0.2-oss-completeness operation):

  - VAL-V2M02-021  POST /v1/replay-cases creates case (201).
  - VAL-V2M02-022  /v1/replay-cases enforces replay:write.
  - VAL-V2M02-023  GET /v1/replay-cases/{case_id} returns detail.
  - VAL-V2M02-024  /v1/replay-cases/{case_id} enforces runs:read.
  - VAL-V2M02-025  POST /v1/replay-cases/{case_id}/fixtures uploads fixture.
  - VAL-V2M02-026  /fixtures enforces replay:write.
  - VAL-V2M02-027  POST /v1/replay-cases/{case_id}/run executes (202)
    with cassette default; live + mutating returns 422 RELAY-REPLAY-014.
  - VAL-V2M02-028  /run enforces replay:write.
  - VAL-V2M02-029  GET /v1/replay-results/{result_id} canonical result.
  - VAL-V2M02-030  /v1/replay-results/{result_id} enforces runs:read.

The underlying replay_cases/replay_fixtures writer services do not exist
in the OSS sidecar yet; routes use the runtime in-memory replay registry
to round-trip canonical shapes and exercise the 404/422 paths. The
canonical shape contract (case_id, fixture_id+digest, replay_mode
defaulting to cassette, RELAY-REPLAY-014 on mutating live) is the
load-bearing surface that M02 owns.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
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


def _make_health(port: int = 50093) -> HealthState:
    token = "test-v2m02-replay-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _bootstrap_db(db_path: Path) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        for sql in sorted(migrations_dir.glob("*.sql")):
            await conn.executescript(sql.read_text(encoding="utf-8"))
        await conn.commit()


async def _seed_run(db_path: Path, *, run_id: str, project_id: str) -> None:
    decided_at = (
        (datetime.now(tz=UTC) - timedelta(minutes=5))
        .isoformat()
        .replace("+00:00", "Z")
    )
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute(
            "INSERT INTO run_results ("
            "run_result_id, run_id, project_id, schema_version, written_by, "
            "status, primary_failure_class, error_priority_rule, "
            "evidence_bundle_id, manifest_commit_hash, actor_identity_hash, "
            "decided_at, decision_epoch, signature, signature_key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"rr-{run_id}",
                run_id,
                project_id,
                "relay.run_result.v1",
                "control_plane",
                "remediate_required",
                "contract_fail",
                "first_p0_then_highest_severity_then_earliest_span",
                None,
                "sha256-" + ("0" * 64),
                "sha256-" + ("c" * 64),
                decided_at,
                1,
                "sig-stub",
                "key-stub",
            ),
        )
        await conn.commit()


def _replay_write_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "replay:write,runs:read"}


def _runs_read_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "runs:read"}


def _no_scope_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": ""}


@pytest_asyncio.fixture
async def sidecar_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path]]:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _bootstrap_db(db_path)
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        yield client, db_path


# ---- VAL-V2M02-021: POST /v1/replay-cases creates case -------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-021")
@pytest.mark.asyncio
async def test_create_replay_case(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    run_id = "01HXRUNREPLAY00000000000001"
    await _seed_run(db_path, run_id=run_id, project_id="project-rep-001")
    r = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id, "scope_name": "checkout"},
        headers=_replay_write_headers(),
    )
    assert r.status_code == 201, r.text
    body = json.loads(r.text)
    assert isinstance(body["case_id"], str) and body["case_id"]
    # Unknown from_run_id -> 404.
    r404 = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": "01HXNOSUCHRUN0000000000000"},
        headers=_replay_write_headers(),
    )
    assert r404.status_code == 404, r404.text


# ---- VAL-V2M02-022: replay-cases scope check -----------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-022")
@pytest.mark.asyncio
async def test_create_replay_case_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": "01HXRUN0000000000000000000"},
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-023: GET case detail --------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-023")
@pytest.mark.asyncio
async def test_get_replay_case_returns_detail(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    run_id = "01HXRUNREPLAY00000000000002"
    await _seed_run(db_path, run_id=run_id, project_id="project-rep-002")
    create = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers=_replay_write_headers(),
    )
    case_id = json.loads(create.text)["case_id"]
    r = await client.get(
        f"/v1/replay-cases/{case_id}", headers=_runs_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert body["case_id"] == case_id
    assert body["from_run_id"] == run_id
    assert "fixtures_count" in body

    r404 = await client.get(
        "/v1/replay-cases/case-nonexistent", headers=_runs_read_headers()
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-024: GET case scope check ---------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-024")
@pytest.mark.asyncio
async def test_get_replay_case_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/replay-cases/case-any", headers=_no_scope_headers()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-025: POST fixtures ----------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-025")
@pytest.mark.asyncio
async def test_post_replay_fixtures_uploads_and_digests(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    run_id = "01HXRUNREPLAY00000000000003"
    await _seed_run(db_path, run_id=run_id, project_id="project-rep-003")
    create = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers=_replay_write_headers(),
    )
    case_id = json.loads(create.text)["case_id"]
    fixture_body = {
        "fixture_kind": "model_call",
        "payload": {"prompt": "hello", "response": "world"},
    }
    r = await client.post(
        f"/v1/replay-cases/{case_id}/fixtures",
        json=fixture_body,
        headers=_replay_write_headers(),
    )
    assert r.status_code == 201, r.text
    body = json.loads(r.text)
    assert isinstance(body["fixture_id"], str) and body["fixture_id"]
    assert body["digest"].startswith("sha256:")
    # Digest is sha256 of the canonicalized payload.
    expected = hashlib.sha256(
        json.dumps(fixture_body, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    assert body["digest"] == f"sha256:{expected}"

    # Unknown case_id -> 404.
    r404 = await client.post(
        "/v1/replay-cases/case-missing/fixtures",
        json=fixture_body,
        headers=_replay_write_headers(),
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-026: fixtures scope check ---------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-026")
@pytest.mark.asyncio
async def test_post_replay_fixtures_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.post(
        "/v1/replay-cases/case-any/fixtures",
        json={"fixture_kind": "tool_call", "payload": {}},
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-027: POST run executes reproduction -----------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-027")
@pytest.mark.asyncio
async def test_post_replay_run_cassette_default_and_mutating_rejection(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    run_id = "01HXRUNREPLAY00000000000004"
    await _seed_run(db_path, run_id=run_id, project_id="project-rep-004")
    create = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers=_replay_write_headers(),
    )
    case_id = json.loads(create.text)["case_id"]
    manifest_hash = "sha256-" + ("0" * 64)

    # 1. Default mode -> 202 with replay_mode=cassette.
    r = await client.post(
        f"/v1/replay-cases/{case_id}/run",
        json={"manifest_commit_hash": manifest_hash},
        headers=_replay_write_headers(),
    )
    assert r.status_code == 202, r.text
    body = json.loads(r.text)
    assert isinstance(body["replay_result_id"], str)
    assert isinstance(body["await_url"], str)

    # Look up the result row to confirm replay_mode defaulted to cassette.
    result_id = body["replay_result_id"]
    detail = await client.get(
        f"/v1/replay-results/{result_id}", headers=_runs_read_headers()
    )
    assert detail.status_code == 200
    assert json.loads(detail.text)["replay_mode"] == "cassette"

    # 2. Live mode on mutating tools -> 422 RELAY-REPLAY-014.
    r_mut = await client.post(
        f"/v1/replay-cases/{case_id}/run",
        json={
            "mode": "live",
            "manifest_commit_hash": manifest_hash,
            "side_effect_class": "mutating",
        },
        headers=_replay_write_headers(),
    )
    assert r_mut.status_code == 422, r_mut.text
    assert json.loads(r_mut.text)["code"] == "RELAY-REPLAY-014"

    # 3. Live mode on external_irreversible -> 422 RELAY-REPLAY-014.
    r_ext = await client.post(
        f"/v1/replay-cases/{case_id}/run",
        json={
            "mode": "live",
            "manifest_commit_hash": manifest_hash,
            "side_effect_class": "external_irreversible",
        },
        headers=_replay_write_headers(),
    )
    assert r_ext.status_code == 422
    assert json.loads(r_ext.text)["code"] == "RELAY-REPLAY-014"


# ---- VAL-V2M02-028: run scope check --------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-028")
@pytest.mark.asyncio
async def test_post_replay_run_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.post(
        "/v1/replay-cases/case-any/run",
        json={"manifest_commit_hash": "sha256-" + ("0" * 64)},
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-029: GET /v1/replay-results/{result_id} -------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-029")
@pytest.mark.asyncio
async def test_get_replay_result_returns_canonical_shape(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    run_id = "01HXRUNREPLAY00000000000005"
    await _seed_run(db_path, run_id=run_id, project_id="project-rep-005")
    create = await client.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers=_replay_write_headers(),
    )
    case_id = json.loads(create.text)["case_id"]
    run_resp = await client.post(
        f"/v1/replay-cases/{case_id}/run",
        json={"manifest_commit_hash": "sha256-" + ("0" * 64)},
        headers=_replay_write_headers(),
    )
    result_id = json.loads(run_resp.text)["replay_result_id"]
    r = await client.get(
        f"/v1/replay-results/{result_id}", headers=_runs_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    for required in ("replay_result_id", "digest_ok", "outcome", "evidence"):
        assert required in body, f"missing {required}"

    r404 = await client.get(
        "/v1/replay-results/result-missing", headers=_runs_read_headers()
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-030: replay result scope ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-030")
@pytest.mark.asyncio
async def test_get_replay_result_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/replay-results/result-any", headers=_no_scope_headers()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
