"""VAL-W2-014: lifespan initialises SQLite WAL BEFORE the listener binds.

The FastAPI lifespan startup hook MUST complete ``PRAGMA journal_mode=WAL``
before the HTTP listener becomes bindable. The diagnostic endpoint
``GET /diagnostics/sqlite`` reads ``PRAGMA journal_mode`` on a fresh
connection; the test asserts:

  - The endpoint returns 200.
  - ``response.body['sqlite']['journal_mode'] == 'wal'``.
  - ``runtime.bound_at_monotonic`` (set at the end of lifespan startup,
    just before ``yield``) is <= the timestamp observed by the FIRST
    request inside the handler. We compare against
    ``/diagnostics/runtime``'s ``observed_at_monotonic`` field, which is
    captured at handler entry.

We use httpx.ASGITransport so the test is offline and deterministic; the
ASGI transport drives the lifespan + request pipeline in-process without
binding a real TCP port.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-wal-token"  # noqa: S105 (test token)
    return HealthState(
        port=49996,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-014")
@pytest.mark.asyncio
async def test_diagnostics_reports_wal_journal_mode(tmp_path) -> None:
    """``/diagnostics/sqlite`` returns ``journal_mode == 'wal'`` after startup."""
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)

    transport = httpx.ASGITransport(app=app)
    # httpx.ASGITransport does NOT drive ASGI lifespan messages; we run
    # the lifespan manually around the request block.
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=transport, base_url="http://sidecar.test"
    ) as client:
        # The ASGI transport drives lifespan startup before the first
        # request is dispatched.
        resp = await client.get("/diagnostics/sqlite")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["sqlite"]["journal_mode"] == "wal", body
        # busy_timeout was set to 5000 ms; aiosqlite reflects it back.
        assert body["sqlite"]["busy_timeout"] == 5000, body

    # The DB file exists on disk after startup.
    assert db_path.exists()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-014")
@pytest.mark.asyncio
async def test_bind_timestamp_precedes_first_request(tmp_path) -> None:
    """``bound_at_monotonic`` is set in startup BEFORE the first request runs."""
    app = build_runtime_app(
        health=_make_health(),
        sqlite_path=tmp_path / "sidecar.db",
    )
    transport = httpx.ASGITransport(app=app)
    # httpx.ASGITransport does NOT drive ASGI lifespan messages; we run
    # the lifespan manually around the request block.
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=transport, base_url="http://sidecar.test"
    ) as client:
        resp = await client.get("/diagnostics/runtime")
        assert resp.status_code == 200
        body = resp.json()
        bound = body["bound_at_monotonic"]
        observed = body["observed_at_monotonic"]
        assert bound is not None, "lifespan startup did not set bound_at_monotonic"
        assert bound <= observed, (
            f"port-bind timestamp ({bound}) must be <= first-request "
            f"timestamp ({observed}); lifespan ordering violation."
        )
        assert body["draining"] is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-014")
@pytest.mark.asyncio
async def test_wal_persists_across_independent_connections(tmp_path) -> None:
    """A fresh aiosqlite connection sees ``journal_mode = wal`` after startup."""
    import aiosqlite

    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)

    transport = httpx.ASGITransport(app=app)
    # httpx.ASGITransport does NOT drive ASGI lifespan messages; we run
    # the lifespan manually around the request block.
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=transport, base_url="http://sidecar.test"
    ) as client:
        # Drive startup by issuing a request.
        r = await client.get("/diagnostics/sqlite")
        assert r.status_code == 200

    # Outside the ASGI client (lifespan torn down). Open an independent
    # connection and assert journal_mode persists (WAL is per-file).
    async with (
        aiosqlite.connect(str(db_path)) as conn,
        conn.execute("PRAGMA journal_mode") as cur,
    ):
        row = await cur.fetchone()
        assert row is not None
        assert str(row[0]).lower() == "wal", f"observed {row[0]!r}"
