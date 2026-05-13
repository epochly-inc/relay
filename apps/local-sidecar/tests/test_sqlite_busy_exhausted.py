"""VAL-W2-020: SQLITE_BUSY retry/backoff exhausts -> structured error.

After ``busy_timeout`` (5000ms) + application-level retry/backoff have
exhausted, the operation MUST raise ``RelaySQLiteBusyExhausted`` (mapped
to ``RELAY-SQLITE-BUSY-EXHAUSTED`` + HTTP 503), NOT a raw
``sqlite3.OperationalError``.

We force exhaustion by holding a competing write lock for longer than
the 5s busy_timeout budget. To avoid making the test itself take >5s, we
PATCH ``BUSY_TIMEOUT_MS`` to a much shorter value via monkeypatch.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid

import aiosqlite
import httpx
import pytest
import relay_sidecar.db as db_module
from relay_sidecar.db import SidecarDatabase, build_event_log_row
from relay_sidecar.errors import RelaySQLiteBusyExhausted
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-busy-exhausted-token"  # noqa: S105 (test token)
    return HealthState(
        port=49997,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-020")
@pytest.mark.asyncio
async def test_busy_exhausted_raises_structured_error(
    tmp_path, monkeypatch
) -> None:
    """After busy_timeout + backoff budget exhausts, RelaySQLiteBusyExhausted."""
    # Shrink BOTH budgets so the test completes quickly.
    # CONN_BUSY_TIMEOUT_MS is the per-connection sqlite wait window; we
    # set it to 50ms so sqlite gives up quickly. BUSY_TIMEOUT_MS is the
    # application-level retry deadline; we set it to 100ms so the
    # application retry path exhausts after one or two backoffs.
    monkeypatch.setattr(db_module, "CONN_BUSY_TIMEOUT_MS", 50, raising=True)
    monkeypatch.setattr(db_module, "BUSY_TIMEOUT_MS", 100, raising=True)

    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    ready = asyncio.Event()
    release = asyncio.Event()
    holder: asyncio.Task[None] | None = None
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())

        async def hold_forever() -> None:
            async with aiosqlite.connect(str(db_path)) as comp:
                await comp.execute("PRAGMA busy_timeout = 0")
                await comp.execute("BEGIN IMMEDIATE")
                await comp.execute(
                    "CREATE TABLE IF NOT EXISTS _hold_sentinel(x INTEGER)"
                )
                await comp.execute(
                    "INSERT INTO _hold_sentinel(x) VALUES (?)", (1,)
                )
                ready.set()
                await release.wait()
                await comp.execute("COMMIT")

        holder = asyncio.create_task(hold_forever())
        await ready.wait()

        # Now attempt a write; the budget should exhaust within ~200ms.
        row = build_event_log_row(
            event_type="test.exhausted",
            scope_id=scope_id,
            project_id=project_id,
        )
        with pytest.raises(RelaySQLiteBusyExhausted) as exc_info:
            await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id=scope_id,
            )
        err = exc_info.value
        assert err.code == "RELAY-SQLITE-001"
        assert err.error_class == "RELAY-SQLITE-BUSY-EXHAUSTED"
        assert err.http_status == 503
        assert err.attempts >= 1, err.attempts
        assert err.sql_statement_digest.startswith("sha256-")
    finally:
        # Always release the holder so cleanup proceeds even if the
        # assertions above fail.
        release.set()
        if holder is not None:
            try:
                await asyncio.wait_for(holder, timeout=2.0)
            except (TimeoutError, asyncio.CancelledError):
                holder.cancel()
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-020")
@pytest.mark.asyncio
async def test_busy_exhausted_maps_to_http_503(tmp_path, monkeypatch) -> None:
    """The FastAPI exception handler maps the error to HTTP 503 envelope."""
    monkeypatch.setattr(db_module, "BUSY_TIMEOUT_MS", 200, raising=True)

    app = build_runtime_app(
        health=_make_health(),
        sqlite_path=tmp_path / "sidecar.db",
    )

    # Register a probe route that forces a RelaySQLiteBusyExhausted.
    @app.get("/__probe_busy")
    async def probe_busy() -> dict[str, str]:
        raise RelaySQLiteBusyExhausted(
            message="forced for VAL-W2-020 test",
            attempts=3,
            sql_statement_digest="sha256-" + "0" * 64,
        )

    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app), httpx.AsyncClient(
        transport=transport, base_url="http://sidecar.test"
    ) as client:
        resp = await client.get("/__probe_busy")
        assert resp.status_code == 503, resp.text
        body = resp.json()
        assert body["code"] == "RELAY-SQLITE-001"
        assert body["error_class"] == "RELAY-SQLITE-BUSY-EXHAUSTED"
        assert body["http_status"] == 503
        assert body["details"]["attempts"] == 3
