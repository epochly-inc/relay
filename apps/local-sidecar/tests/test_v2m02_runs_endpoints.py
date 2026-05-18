"""V2 M02 W2.2 sidecar runs read-namespace HTTP endpoint tests.

Covers contract assertions VAL-V2M02-010..020 (the eleven assertions owned
by sub-feature w2.2 in the relay-v0.2-oss-completeness operation):

  - VAL-V2M02-010  GET /v1/projects/{project_id}/runs cursor pagination.
  - VAL-V2M02-011  cursor round-trip returns disjoint next page.
  - VAL-V2M02-012  /v1/projects/{project_id}/runs enforces runs:read.
  - VAL-V2M02-013  GET /v1/runs/{run_id} returns canonical envelope.
  - VAL-V2M02-014  /v1/runs/{run_id} enforces runs:read.
  - VAL-V2M02-015  GET /v1/runs/{run_id}/trace returns ordered span tree.
  - VAL-V2M02-016  /v1/runs/{run_id}/trace enforces runs:read.
  - VAL-V2M02-017  GET /v1/runs/{run_id}/result canonical RunResult.
  - VAL-V2M02-018  /v1/runs/{run_id}/result enforces runs:read.
  - VAL-V2M02-019  GET /v1/runs/{run_id}/explain root cause hypotheses.
  - VAL-V2M02-020  /v1/runs/{run_id}/explain enforces runs:read.

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


def _make_health(port: int = 50092) -> HealthState:
    token = "test-v2m02-runs-token"  # noqa: S105
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


async def _seed_runs(db_path: Path, *, project_id: str, count: int) -> list[str]:
    """Seed ``count`` run_results rows for ``project_id``; return their run_ids."""
    run_ids: list[str] = []
    async with aiosqlite.connect(str(db_path)) as conn:
        for i in range(count):
            run_id = f"01HX0000RUN{project_id[-4:].upper():>04s}{i:010d}"[-26:]
            run_ids.append(run_id)
            decided_at = (
                (datetime.now(tz=UTC) - timedelta(minutes=count - i))
                .isoformat()
                .replace("+00:00", "Z")
            )
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
                    i + 1,
                    "sig-stub",
                    "key-stub",
                ),
            )
        await conn.commit()
    return run_ids


async def _seed_spans(
    db_path: Path, *, run_id: str, span_specs: list[tuple[str, str | None]]
) -> None:
    """Seed spans for a run. Each spec is (span_id, parent_span_id)."""
    async with aiosqlite.connect(str(db_path)) as conn:
        for idx, (span_id, parent_id) in enumerate(span_specs):
            started_at = (
                (datetime.now(tz=UTC) + timedelta(seconds=idx))
                .isoformat()
                .replace("+00:00", "Z")
            )
            await conn.execute(
                "INSERT INTO spans ("
                "span_id, run_id, parent_span_id, span_type, name, status, "
                "started_at, ended_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    span_id,
                    run_id,
                    parent_id,
                    "custom",
                    f"span-{idx}",
                    "ok",
                    started_at,
                    started_at,
                ),
            )
        await conn.commit()


async def _seed_root_cause(db_path: Path, *, run_id: str, count: int) -> None:
    """Seed root_cause_hypotheses rows matching migration 0017_explain.sql."""
    async with aiosqlite.connect(str(db_path)) as conn:
        for i in range(count):
            hypothesis_id = f"rch-{run_id}-{i}"
            created_at = (
                datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
            )
            evidence_refs = json.dumps([])
            await conn.execute(
                "INSERT INTO root_cause_hypotheses ("
                "hypothesis_id, run_id, span_id, hypothesis_class, "
                "confidence, evidence_refs, evidence_refs_digest, "
                "generator, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hypothesis_id,
                    run_id,
                    None,
                    "prompt_regression",
                    0.8,
                    evidence_refs,
                    # Each seeded row needs a unique evidence_refs_digest
                    # because the table has a UNIQUE constraint on
                    # (run_id, hypothesis_class, evidence_refs_digest).
                    f"sha256:{i:064d}",
                    "heuristic.v1",
                    created_at,
                ),
            )
        await conn.commit()


def _read_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "runs:read"}


def _no_scope_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": ""}


@pytest_asyncio.fixture
async def sidecar_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path]]:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    # Audit fix (2026-05-17 P0): opt-in to the legacy X-Relay-Scopes
    # header (now disabled by default) so these W2.2 legacy tests keep
    # passing under the production default-deny gate.
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
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


# ---- VAL-V2M02-010: list runs with cursor pagination shape ---------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-010")
@pytest.mark.asyncio
async def test_list_runs_returns_pagination_envelope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-list-001"
    await _seed_runs(db_path, project_id=project_id, count=3)
    r = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 2},
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert "items" in body
    assert "next_cursor" in body
    assert "has_more" in body
    assert isinstance(body["items"], list)
    assert len(body["items"]) <= 2


# ---- VAL-V2M02-011: cursor round-trip disjoint pages ---------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-011")
@pytest.mark.asyncio
async def test_list_runs_cursor_round_trip(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-rt-001"
    seeded = await _seed_runs(db_path, project_id=project_id, count=3)
    page1 = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 2},
    )
    assert page1.status_code == 200, page1.text
    p1 = json.loads(page1.text)
    assert p1["has_more"] is True
    assert isinstance(p1["next_cursor"], str) and p1["next_cursor"]
    page1_ids = {item["run_id"] for item in p1["items"]}

    page2 = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 2, "cursor": p1["next_cursor"]},
    )
    assert page2.status_code == 200, page2.text
    p2 = json.loads(page2.text)
    page2_ids = {item["run_id"] for item in p2["items"]}
    # No overlap and final page terminates.
    assert page1_ids.isdisjoint(page2_ids)
    assert p2["has_more"] is False
    assert p2["next_cursor"] is None
    # Together the two pages cover the seeded set.
    assert page1_ids | page2_ids == set(seeded)


# ---- Audit P1: list runs cursor carries 1h TTL ---------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-010")
@pytest.mark.asyncio
async def test_list_runs_cursor_expires_after_1h(
    sidecar_client: tuple[httpx.AsyncClient, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Audit P1 regression: ``_sign_cursor`` had no TTL; cursors lived
    forever. The runs endpoint now uses ``_sign_cursor_ttl`` per spec
    B.3 lines 3381-3390. A cursor older than 1h must reject with
    ``RELAY-PAGE-EXPIRED``.
    """
    client, db_path = sidecar_client
    project_id = "project-ttl-001"
    await _seed_runs(db_path, project_id=project_id, count=3)
    page1 = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 1},
    )
    assert page1.status_code == 200, page1.text
    cursor = json.loads(page1.text)["next_cursor"]
    assert isinstance(cursor, str) and cursor

    # Freeze the clock 2h forward so the cursor's issued_at appears
    # > _CURSOR_TTL_S (1h) old. Patch the runtime module's `datetime`
    # symbol (same approach as the gate-rounds expiry test in
    # test_v2m02_pagination.py).
    import time as _time

    import relay_sidecar.runtime as rt_mod

    real_dt = rt_mod.datetime

    class _FrozenDT:
        @staticmethod
        def now(tz=None):  # noqa: ANN001
            return real_dt.now(tz=tz).fromtimestamp(_time.time() + 7200, tz=tz)

    monkeypatch.setattr(rt_mod, "datetime", _FrozenDT)
    try:
        r2 = await client.get(
            f"/v1/projects/{project_id}/runs",
            headers=_read_headers(),
            params={"limit": 1, "cursor": cursor},
        )
        assert r2.status_code == 400, r2.text
        assert json.loads(r2.text)["code"] == "RELAY-PAGE-EXPIRED"
    finally:
        monkeypatch.setattr(rt_mod, "datetime", real_dt)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-010")
@pytest.mark.asyncio
async def test_list_runs_tampered_cursor_returns_400(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """A tampered cursor must reject with RELAY-PAGE-001."""
    client, db_path = sidecar_client
    project_id = "project-tamper-001"
    await _seed_runs(db_path, project_id=project_id, count=3)
    page1 = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 1},
    )
    cursor = json.loads(page1.text)["next_cursor"]
    tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    r2 = await client.get(
        f"/v1/projects/{project_id}/runs",
        headers=_read_headers(),
        params={"limit": 1, "cursor": tampered},
    )
    assert r2.status_code == 400, r2.text
    body = json.loads(r2.text)
    assert body["code"] in ("RELAY-PAGE-001", "RELAY-PAGE-EXPIRED")


# ---- VAL-V2M02-012: list scope check -------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-012")
@pytest.mark.asyncio
async def test_list_runs_enforces_runs_read_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/projects/project-x/runs", headers=_no_scope_headers()
    )
    assert r.status_code == 403, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-013: run detail happy + 404 -------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-013")
@pytest.mark.asyncio
async def test_get_run_returns_canonical_envelope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-detail-001"
    [run_id] = await _seed_runs(db_path, project_id=project_id, count=1)
    r = await client.get(f"/v1/runs/{run_id}", headers=_read_headers())
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert body["run_id"] == run_id
    # Audit fix (2026-05-17 P0): the GET /v1/runs/{run_id} response no
    # longer carries a made-up ``relay.run.v1`` schema_version (not in
    # KNOWN_SCHEMA_IDS). The canonical run shape is the ``RunResult``
    # envelope returned by /v1/runs/{run_id}/result.
    assert "schema_version" not in body
    for required in (
        "status",
        "started_at",
        "manifest_commit_hash",
        "actor_identity_hash",
    ):
        assert required in body, f"missing {required}"

    # 404 for unknown run_id (separate path).
    r404 = await client.get(
        "/v1/runs/01HXNOSUCHRUN0000000000000", headers=_read_headers()
    )
    assert r404.status_code == 404, r404.text
    err = json.loads(r404.text)
    assert "code" in err


# ---- VAL-V2M02-014: run detail scope check -------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-014")
@pytest.mark.asyncio
async def test_get_run_enforces_runs_read_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/runs/01HXANYRUN0000000000000000", headers=_no_scope_headers()
    )
    assert r.status_code == 403, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-015: trace returns ordered span tree ----------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-015")
@pytest.mark.asyncio
async def test_get_run_trace_returns_ordered_spans(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-trace-001"
    [run_id] = await _seed_runs(db_path, project_id=project_id, count=1)
    span_specs = [
        ("01HXSPAN0000000000000000A1", None),
        ("01HXSPAN0000000000000000A2", "01HXSPAN0000000000000000A1"),
        ("01HXSPAN0000000000000000A3", "01HXSPAN0000000000000000A1"),
    ]
    await _seed_spans(db_path, run_id=run_id, span_specs=span_specs)
    r = await client.get(f"/v1/runs/{run_id}/trace", headers=_read_headers())
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert "spans" in body
    assert len(body["spans"]) == 3
    # Spans are ordered by started_at.
    starts = [s["started_at"] for s in body["spans"]]
    assert starts == sorted(starts)
    # parent_span_id references are valid (parent is None or in returned span_ids).
    span_ids = {s["span_id"] for s in body["spans"]}
    for s in body["spans"]:
        parent = s.get("parent_span_id")
        assert parent is None or parent in span_ids

    # 404 for unknown run.
    r404 = await client.get(
        "/v1/runs/01HXNOSUCHRUN0000000000000/trace", headers=_read_headers()
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-016: trace scope check ------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-016")
@pytest.mark.asyncio
async def test_get_run_trace_enforces_runs_read_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/runs/01HXANYRUN0000000000000000/trace",
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-017: canonical RunResult ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-017")
@pytest.mark.asyncio
async def test_get_run_result_returns_canonical_runresult(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-res-001"
    [run_id] = await _seed_runs(db_path, project_id=project_id, count=1)
    r = await client.get(f"/v1/runs/{run_id}/result", headers=_read_headers())
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert body["written_by"] == "control_plane"
    assert body["run_id"] == run_id
    assert body["status"] in (
        "accepted",
        "remediate_required",
        "blocked",
        "invalid",
    )

    # 404 for unknown run.
    r404 = await client.get(
        "/v1/runs/01HXNOSUCHRUN0000000000000/result", headers=_read_headers()
    )
    assert r404.status_code == 404


# ---- VAL-V2M02-018: result scope check -----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-018")
@pytest.mark.asyncio
async def test_get_run_result_enforces_runs_read_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/runs/01HXANYRUN0000000000000000/result",
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-019: explain returns root cause hypotheses ----------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-019")
@pytest.mark.asyncio
async def test_get_run_explain_returns_root_cause_array(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, db_path = sidecar_client
    project_id = "project-exp-001"
    [run_id] = await _seed_runs(db_path, project_id=project_id, count=1)
    await _seed_root_cause(db_path, run_id=run_id, count=2)
    r = await client.get(
        f"/v1/runs/{run_id}/explain", headers=_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert "hypotheses" in body
    assert isinstance(body["hypotheses"], list)
    assert len(body["hypotheses"]) == 2

    # Run that has no hypotheses -> 200 with empty array (not 404).
    project2 = "project-exp-empty"
    [run2] = await _seed_runs(db_path, project_id=project2, count=1)
    r2 = await client.get(
        f"/v1/runs/{run2}/explain", headers=_read_headers()
    )
    assert r2.status_code == 200, r2.text
    assert json.loads(r2.text)["hypotheses"] == []


# ---- VAL-V2M02-020: explain scope check ----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-020")
@pytest.mark.asyncio
async def test_get_run_explain_enforces_runs_read_scope(
    sidecar_client: tuple[httpx.AsyncClient, Path],
) -> None:
    client, _db = sidecar_client
    r = await client.get(
        "/v1/runs/01HXANYRUN0000000000000000/explain",
        headers=_no_scope_headers(),
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
