"""VAL-W2-044: SIGTERM -> drain mode rejects new POST /v1/ingest with 503.

After ``runtime.draining=True`` the DrainMiddleware short-circuits new
HTTP requests with HTTP 503 + ``Retry-After: 30`` + the structured
error envelope ``{code: "RELAY-SIDECAR-007",
error_class: "RELAY-SIDECAR-DRAINING"}``. In-flight requests continue
to completion (proven via VAL-W2-015 / W2.2 prior work).

W2.6 extends the W2.2 drain coverage to the new ``POST /v1/ingest``
endpoint (the placeholder added in this milestone). The W2.2
DrainMiddleware applies uniformly to every HTTP route, so the
assertion is structurally identical: flip ``runtime.draining=True``,
issue POST /v1/ingest, observe the 503 envelope.

This test runs against an in-process ASGI transport so it is hermetic
and not subject to uvicorn's graceful-shutdown listener-closing timing
(the SIGTERM end-to-end test for VAL-W2-015 is xfail-marked for that
reason; the middleware-level path is the deterministic surface).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-drain-ingest-token"  # noqa: S105
    return HealthState(
        port=49994,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-044")
@pytest.mark.asyncio
async def test_drain_rejects_new_v1_ingest_with_503(tmp_path, monkeypatch) -> None:
    """POST /v1/ingest while draining returns 503 + Retry-After + envelope."""
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        runtime = app.state.runtime
        # Sanity: not draining, ingest succeeds.
        r1 = await client.post("/v1/ingest")
        assert r1.status_code == 200, r1.text
        assert r1.json()["accepted"] is True

        # Flip the drain flag (simulates the lifespan tear-down's first
        # action, which the SIGTERM handler triggers).
        runtime.draining = True

        # Now POST /v1/ingest is rejected with 503 + Retry-After + envelope.
        r2 = await client.post("/v1/ingest")
        assert r2.status_code == 503, r2.text
        assert r2.headers.get("retry-after") == "30", (
            f"expected Retry-After: 30, got {r2.headers.get('retry-after')!r}"
        )
        body = json.loads(r2.text)
        assert body["code"] == "RELAY-SIDECAR-007", body
        assert body["error_class"] == "RELAY-SIDECAR-DRAINING", body
        assert "draining" in body["message"], body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-044")
@pytest.mark.asyncio
async def test_drain_rejects_v1_ingest_with_hold_ms_query(tmp_path, monkeypatch) -> None:
    """Drain rejects POST /v1/ingest even with a non-default query string.

    Defends against accidental coupling: the drain check is at the
    middleware layer, BEFORE any handler-side logic that might branch
    on query parameters. Asserts the 503 fires regardless of payload.
    """
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        app.state.runtime.draining = True
        r = await client.post("/v1/ingest", params={"hold_ms": "1000"})
        assert r.status_code == 503, r.text
        body = json.loads(r.text)
        assert body["error_class"] == "RELAY-SIDECAR-DRAINING", body
        # Body confirms the request was short-circuited at the middleware
        # (no operation_id key in the response).
        assert "operation_id" not in body, body
