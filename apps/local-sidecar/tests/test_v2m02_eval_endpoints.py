"""V2 M02 W2.4 sidecar eval-namespace HTTP endpoint tests.

Covers contract assertions VAL-V2M02-031..036 (the six assertions owned
by sub-feature w2.4 in the relay-v0.2-oss-completeness operation):

  - VAL-V2M02-031  POST /v1/eval-datasets creates dataset (201).
  - VAL-V2M02-032  /v1/eval-datasets enforces replay:write.
  - VAL-V2M02-033  POST /v1/eval-runs enqueues an eval run (202).
  - VAL-V2M02-034  /v1/eval-runs enforces replay:write.
  - VAL-V2M02-035  GET /v1/eval-runs/{eval_run_id} canonical envelope.
  - VAL-V2M02-036  /v1/eval-runs/{eval_run_id} enforces runs:read.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health(port: int = 50094) -> HealthState:
    token = "test-v2m02-eval-token"  # noqa: S105
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


# ---- VAL-V2M02-031: create eval dataset ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-031")
@pytest.mark.asyncio
async def test_create_eval_dataset(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    body = {
        "name": "regression-pack-1",
        "description": "smoke regression cases",
        "fixtures": [
            {"fixture_id": "fix-a", "digest": "sha256:" + ("a" * 64)},
            {"fixture_id": "fix-b", "digest": "sha256:" + ("b" * 64)},
        ],
    }
    r = await client.post(
        "/v1/eval-datasets", json=body, headers=_replay_write_headers()
    )
    assert r.status_code == 201, r.text
    resp = json.loads(r.text)
    assert isinstance(resp["dataset_id"], str) and resp["dataset_id"]
    assert isinstance(resp["schema_version"], str)
    assert resp["schema_version"].startswith("relay.eval_dataset.v")


# ---- VAL-V2M02-032: eval-datasets scope ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-032")
@pytest.mark.asyncio
async def test_create_eval_dataset_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.post(
        "/v1/eval-datasets",
        json={"name": "x", "fixtures": []},
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-033: enqueue eval run + 404 on unknown dataset ------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-033")
@pytest.mark.asyncio
async def test_enqueue_eval_run(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    # Create a dataset to reference.
    ds = await client.post(
        "/v1/eval-datasets",
        json={"name": "dataset-for-run", "fixtures": []},
        headers=_replay_write_headers(),
    )
    dataset_id = json.loads(ds.text)["dataset_id"]
    body = {
        "dataset_id": dataset_id,
        "contract_id": "contract-checkout-v1",
        "manifest_commit_hash": "sha256-" + ("0" * 64),
    }
    r = await client.post(
        "/v1/eval-runs", json=body, headers=_replay_write_headers()
    )
    assert r.status_code == 202, r.text
    resp = json.loads(r.text)
    assert isinstance(resp["eval_run_id"], str) and resp["eval_run_id"]
    assert isinstance(resp["await_url"], str)

    # Unknown dataset -> 404.
    r404 = await client.post(
        "/v1/eval-runs",
        json={
            "dataset_id": "dataset-missing",
            "contract_id": "c",
            "manifest_commit_hash": "sha256-" + ("0" * 64),
        },
        headers=_replay_write_headers(),
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-034: eval-runs POST scope ---------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-034")
@pytest.mark.asyncio
async def test_enqueue_eval_run_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.post(
        "/v1/eval-runs",
        json={
            "dataset_id": "dataset-x",
            "contract_id": "c",
            "manifest_commit_hash": "sha256-" + ("0" * 64),
        },
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-035: GET eval run canonical envelope ----------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-035")
@pytest.mark.asyncio
async def test_get_eval_run_returns_canonical_envelope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    ds = await client.post(
        "/v1/eval-datasets",
        json={"name": "ds-2", "fixtures": []},
        headers=_replay_write_headers(),
    )
    dataset_id = json.loads(ds.text)["dataset_id"]
    enq = await client.post(
        "/v1/eval-runs",
        json={
            "dataset_id": dataset_id,
            "contract_id": "c-1",
            "manifest_commit_hash": "sha256-" + ("0" * 64),
        },
        headers=_replay_write_headers(),
    )
    eval_run_id = json.loads(enq.text)["eval_run_id"]
    r = await client.get(
        f"/v1/eval-runs/{eval_run_id}", headers=_runs_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    for required in ("eval_run_id", "status", "metrics", "written_by", "evidence"):
        assert required in body, f"missing {required}"
    assert body["written_by"] == "control_plane"

    r404 = await client.get(
        "/v1/eval-runs/run-missing", headers=_runs_read_headers()
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-036: GET eval run scope -----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-036")
@pytest.mark.asyncio
async def test_get_eval_run_enforces_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/eval-runs/run-any", headers=_no_scope_headers()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
