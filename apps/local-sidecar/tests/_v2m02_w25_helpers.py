"""Shared helpers for V2 M02 W2.5..W2.11 endpoint tests.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def make_health(port: int = 50095) -> HealthState:
    token = "test-v2m02-w25-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def bootstrap_db(db_path: Path) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        for sql in sorted(migrations_dir.glob("*.sql")):
            await conn.executescript(sql.read_text(encoding="utf-8"))
        await conn.commit()


def scope_header(*scopes: str) -> dict[str, str]:
    return {"X-Relay-Scopes": ",".join(scopes)}


def no_scope_header() -> dict[str, str]:
    return {"X-Relay-Scopes": ""}


def bearer_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def v2m02_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
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
