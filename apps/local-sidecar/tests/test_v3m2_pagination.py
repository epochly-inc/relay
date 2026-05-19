"""V3 M02 F04 pagination-everywhere tests.

Fulfills VAL-V3M2-008 (every list endpoint exposes ``next_cursor``) and
VAL-V3M2-009 (every list endpoint rejects a forged-HMAC cursor with
``RELAY-PAGE-001``).

Per-endpoint coverage matrix:

  * ``GET /v1/projects/{project_id}/runs`` (already paginated before F04)
  * ``GET /v1/gates/{gate_id}/rounds``      (already paginated before F04)
  * ``GET /v1/runs/{run_id}/trace``         (added by F04)
  * ``GET /v1/runs/{run_id}/explain``       (added by F04)

The script ``scripts/check-pagination-coverage.py`` performs a static
build-time guard that enumerates list endpoints from ``runtime.py``
AST + asserts ``next_cursor`` presence; this test suite performs the
matching dynamic guard (call each endpoint, assert the wire shape).

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

# ---- Fixtures -----------------------------------------------------------


def _make_health(port: int = 50096) -> HealthState:
    token = "test-v3m2-f04-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _bootstrap_db(db_path: Path) -> None:
    migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
    async with aiosqlite.connect(str(db_path)) as conn:
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
        await conn.commit()


@pytest_asyncio.fixture
async def v3m2_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path]]:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
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


def _runs_read_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "runs:read"}


def _gates_configure_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "gates:configure"}


def _gates_execute_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "gates:execute"}


# ---- Seed helpers -------------------------------------------------------


async def _seed_run(
    db_path: Path, *, project_id: str, run_id: str
) -> None:
    decided_at = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
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


async def _seed_spans(
    db_path: Path, *, run_id: str, count: int
) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        for i in range(count):
            started_at = (
                (datetime.now(tz=UTC) + timedelta(seconds=i))
                .isoformat()
                .replace("+00:00", "Z")
            )
            span_id = f"01HXSPAN{i:018d}"[:26]
            await conn.execute(
                "INSERT INTO spans ("
                "span_id, run_id, parent_span_id, span_type, name, status, "
                "started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    span_id,
                    run_id,
                    None,
                    "custom",
                    f"span-{i}",
                    "ok",
                    started_at,
                    started_at,
                ),
            )
        await conn.commit()


async def _seed_hypotheses(
    db_path: Path, *, run_id: str, count: int
) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        for i in range(count):
            created_at = (
                datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
            )
            await conn.execute(
                "INSERT INTO root_cause_hypotheses ("
                "hypothesis_id, run_id, span_id, hypothesis_class, "
                "confidence, evidence_refs, evidence_refs_digest, "
                "generator, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"rch-{run_id}-{i}",
                    run_id,
                    None,
                    "prompt_regression",
                    0.8,
                    json.dumps([]),
                    f"sha256:{i:064d}",
                    "heuristic.v1",
                    created_at,
                ),
            )
        await conn.commit()


# ========================================================================
# VAL-V3M2-008: every list endpoint exposes next_cursor
# ========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-008")
@pytest.mark.asyncio
async def test_trace_endpoint_exposes_next_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/runs/{run_id}/trace MUST expose a next_cursor field."""
    client, db_path = v3m2_client
    run_id = "01HXTRACE000000000000000001"
    await _seed_run(db_path, project_id="p-trace", run_id=run_id)
    await _seed_spans(db_path, run_id=run_id, count=3)

    r = await client.get(
        f"/v1/runs/{run_id}/trace", headers=_runs_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert "next_cursor" in body, (
        "trace response MUST carry next_cursor (VAL-V3M2-008)"
    )
    assert "has_more" in body, "trace response MUST carry has_more"
    # Small page; no next_cursor needed.
    assert body["has_more"] is False
    assert body["next_cursor"] is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-008")
@pytest.mark.asyncio
async def test_trace_cursor_round_trip(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """Round-trip: trace cursor returns disjoint subsequent page."""
    client, db_path = v3m2_client
    run_id = "01HXTRACE000000000000000002"
    await _seed_run(db_path, project_id="p-trace-rt", run_id=run_id)
    await _seed_spans(db_path, run_id=run_id, count=5)

    page1 = await client.get(
        f"/v1/runs/{run_id}/trace?limit=2",
        headers=_runs_read_headers(),
    )
    assert page1.status_code == 200, page1.text
    p1 = json.loads(page1.text)
    assert p1["has_more"] is True
    assert isinstance(p1["next_cursor"], str) and p1["next_cursor"]
    p1_ids = {s["span_id"] for s in p1["spans"]}

    page2 = await client.get(
        f"/v1/runs/{run_id}/trace?limit=2&cursor={p1['next_cursor']}",
        headers=_runs_read_headers(),
    )
    assert page2.status_code == 200, page2.text
    p2 = json.loads(page2.text)
    p2_ids = {s["span_id"] for s in p2["spans"]}
    assert p1_ids.isdisjoint(p2_ids), "pages must not overlap"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-008")
@pytest.mark.asyncio
async def test_explain_endpoint_exposes_next_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/runs/{run_id}/explain MUST expose a next_cursor field."""
    client, db_path = v3m2_client
    run_id = "01HXEXPLAIN0000000000000003"
    await _seed_run(db_path, project_id="p-explain", run_id=run_id)
    await _seed_hypotheses(db_path, run_id=run_id, count=2)

    r = await client.get(
        f"/v1/runs/{run_id}/explain", headers=_runs_read_headers()
    )
    assert r.status_code == 200, r.text
    body = json.loads(r.text)
    assert "next_cursor" in body, (
        "explain response MUST carry next_cursor (VAL-V3M2-008)"
    )
    assert "has_more" in body
    assert body["has_more"] is False
    assert body["next_cursor"] is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-008")
@pytest.mark.asyncio
async def test_explain_cursor_round_trip(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """Round-trip: explain cursor returns disjoint subsequent page."""
    client, db_path = v3m2_client
    run_id = "01HXEXPLAIN0000000000000004"
    await _seed_run(db_path, project_id="p-explain-rt", run_id=run_id)
    await _seed_hypotheses(db_path, run_id=run_id, count=4)

    page1 = await client.get(
        f"/v1/runs/{run_id}/explain?limit=2",
        headers=_runs_read_headers(),
    )
    assert page1.status_code == 200, page1.text
    p1 = json.loads(page1.text)
    assert p1["has_more"] is True
    assert isinstance(p1["next_cursor"], str) and p1["next_cursor"]
    p1_ids = {h["hypothesis_id"] for h in p1["hypotheses"]}

    page2 = await client.get(
        f"/v1/runs/{run_id}/explain?limit=2&cursor={p1['next_cursor']}",
        headers=_runs_read_headers(),
    )
    assert page2.status_code == 200, page2.text
    p2 = json.loads(page2.text)
    p2_ids = {h["hypothesis_id"] for h in p2["hypotheses"]}
    assert p1_ids.isdisjoint(p2_ids)


# ========================================================================
# VAL-V3M2-009: per-endpoint cursor tamper-detection
# ========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-009")
@pytest.mark.asyncio
async def test_runs_list_rejects_forged_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/projects/{project_id}/runs rejects forged-HMAC cursor."""
    client, _db = v3m2_client
    forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r = await client.get(
        f"/v1/projects/p-forge/runs?cursor={forged}",
        headers=_runs_read_headers(),
    )
    assert r.status_code == 400, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-PAGE-001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-009")
@pytest.mark.asyncio
async def test_trace_rejects_forged_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/runs/{run_id}/trace rejects forged-HMAC cursor."""
    client, db_path = v3m2_client
    run_id = "01HXTRACEFORG0000000000005"
    await _seed_run(db_path, project_id="p-trace-forge", run_id=run_id)
    forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r = await client.get(
        f"/v1/runs/{run_id}/trace?cursor={forged}",
        headers=_runs_read_headers(),
    )
    assert r.status_code == 400, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-PAGE-001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-009")
@pytest.mark.asyncio
async def test_explain_rejects_forged_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/runs/{run_id}/explain rejects forged-HMAC cursor."""
    client, db_path = v3m2_client
    run_id = "01HXEXPLNFORG0000000000006"
    await _seed_run(db_path, project_id="p-explain-forge", run_id=run_id)
    forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r = await client.get(
        f"/v1/runs/{run_id}/explain?cursor={forged}",
        headers=_runs_read_headers(),
    )
    assert r.status_code == 400, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-PAGE-001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-009")
@pytest.mark.asyncio
async def test_gate_rounds_rejects_forged_cursor(
    v3m2_client: tuple[httpx.AsyncClient, Path],
) -> None:
    """GET /v1/gates/{gate_id}/rounds rejects forged-HMAC cursor."""
    client, _db = v3m2_client
    forged = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r = await client.get(
        f"/v1/gates/g-forge/rounds?cursor={forged}",
        headers=_gates_configure_headers(),
    )
    assert r.status_code == 400, r.text
    body = json.loads(r.text)
    assert body["code"] == "RELAY-PAGE-001"


# ========================================================================
# VAL-V3M2-008: coverage-script integration guard
# ========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M2-008")
def test_coverage_script_reports_zero_offenders() -> None:
    """Running ``check-pagination-coverage.py`` against the committed
    runtime.py MUST exit 0 with zero offenders.

    This binds the build-time AST check to the test suite so a future
    regression that lands an un-paginated GET list route fails CI in
    both surfaces: lint command + plumbing tier.
    """
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parents[3]
    script = repo_root / "scripts" / "check-pagination-coverage.py"
    assert script.is_file(), f"missing script: {script}"
    proc = subprocess.run(
        [sys.executable, str(script), "--json"],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
    assert proc.returncode == 0, (
        f"pagination coverage failed:\nstdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )
    report = json.loads(proc.stdout)
    assert report["total_offenders"] == 0
    assert report["total_list_endpoints"] >= 4
