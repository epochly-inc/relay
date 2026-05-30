"""VAL-ISO-002 regression: bearer-authenticated clients must reach the
read/replay/eval endpoints in the secure-default config.

Bug (base commit c911607): the W2.x read/replay/eval handlers gate on
``_check_required_scope``, which sources scopes ONLY from
``_extract_request_scopes`` (the legacy ``X-Relay-Scopes`` CSV header).
After the 2026-05-17 audit fix, ``_extract_request_scopes`` returns the
empty set whenever ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` is not
truthy (the SECURE DEFAULT). ``_check_required_scope`` never consults the
bearer-token scope set, so a bearer token registered with the correct
scope is rejected with 403 RELAY-AUTH-014 from every read/replay/eval
endpoint.

Fix: migrate those handlers to ``_check_auth(request,
required_scope=..., blocked_surface=...)``, which merges the bearer-token
scopes. The CORRECT scope per endpoint is preserved (read endpoints want
``runs:read``; replay/eval write endpoints want ``replay:write``), so a
bearer token with the wrong/absent scope is still rejected (no scope
widening).

These tests run WITHOUT enabling the legacy header (production default).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from _v2m02_w25_helpers import bootstrap_db, make_health
from relay_sidecar.runtime import build_runtime_app


@pytest_asyncio.fixture
async def secure_default_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    """Sidecar client in the SECURE DEFAULT config (legacy
    ``X-Relay-Scopes`` header disabled). Only bearer-token scopes
    authenticate. Mirrors ``v2m02_client`` but deliberately does NOT set
    ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER``.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.delenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", raising=False)
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await bootstrap_db(db_path)
    app = build_runtime_app(health=make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as c,
    ):
        yield c, db_path, app


def _register_token(app: object, token: str, *scopes: str) -> dict[str, str]:
    """Register a bearer token with ``scopes`` and return its header."""
    app.state.runtime.registered_tokens[token] = {  # type: ignore[attr-defined]
        "scopes": frozenset(scopes),
        "project_id": "proj-iso002",
    }
    return {"Authorization": f"Bearer {token}"}


# Representative endpoints: one read (runs:read), one replay-write
# (replay:write), one eval-write (replay:write). Each must be REACHABLE
# with the correct bearer scope and REJECTED (403) with the wrong scope.
# We assert on the scope-gate outcome only (not on 200 vs 404/422 of the
# downstream business logic), so the test isolates the auth fix.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_runs_read_reaches_read_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    hdrs = _register_token(app, "tok-read", "runs:read")
    # GET /v1/runs/{run_id} with the correct bearer scope. Before the fix
    # this returns 403 RELAY-AUTH-014 (bearer scopes never consulted).
    # After the fix it passes the scope gate; the run does not exist so
    # the downstream returns 404 -- which proves the gate was PASSED.
    r = await c.get("/v1/runs/01HXANYRUN0000000000000000", headers=hdrs)
    assert r.status_code != 403, r.text
    assert r.status_code == 404, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_runs_read_rejected_from_read_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    # A bearer token WITHOUT runs:read (only replay:write) must still be
    # rejected -- the fix must NOT widen the required scope.
    hdrs = _register_token(app, "tok-noread", "replay:write")
    r = await c.get("/v1/runs/01HXANYRUN0000000000000000", headers=hdrs)
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_replay_write_reaches_replay_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    hdrs = _register_token(app, "tok-replay", "replay:write")
    # POST /v1/replay-cases with the correct bearer scope. Before the fix
    # this is 403; after the fix the scope gate passes (a malformed/empty
    # body then yields a 4xx body-shape error other than 403).
    r = await c.post("/v1/replay-cases", json={}, headers=hdrs)
    assert r.status_code != 403, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_replay_write_rejected_from_replay_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    # runs:read alone must NOT grant replay:write (no scope widening).
    hdrs = _register_token(app, "tok-replay-noscope", "runs:read")
    r = await c.post("/v1/replay-cases", json={}, headers=hdrs)
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_with_replay_write_reaches_eval_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    hdrs = _register_token(app, "tok-eval", "replay:write")
    # POST /v1/eval-runs requires replay:write. Before the fix this is
    # 403; after the fix the scope gate passes.
    r = await c.post("/v1/eval-runs", json={}, headers=hdrs)
    assert r.status_code != 403, r.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-002")
@pytest.mark.asyncio
async def test_bearer_without_eval_scope_rejected_from_eval_endpoint(
    secure_default_client: tuple[httpx.AsyncClient, Path, object],
) -> None:
    c, _db, app = secure_default_client
    hdrs = _register_token(app, "tok-eval-noscope", "runs:read")
    r = await c.post("/v1/eval-runs", json={}, headers=hdrs)
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
