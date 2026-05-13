"""VAL-W2-013: single shared ``httpx.AsyncClient`` per sidecar process.

The sidecar instantiates exactly ONE ``httpx.AsyncClient`` during lifespan
startup and reuses it for every outbound request. Asserted by:

  1. Resetting the test counter (``reset_async_client_init_counter``).
  2. Building the runtime app + running its lifespan once.
  3. Issuing N=50 outbound requests through ``app.state.http_client``.
  4. Reading ``get_async_client_init_count()`` and asserting == 1.

We use httpx's MockTransport so the test is offline-friendly (tier-1
plumbing budget) and deterministic. The mock returns 204 No Content for
any URL; the assertion is the construction counter, not the response body.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import (
    build_runtime_app,
    get_async_client_init_count,
    reset_async_client_init_counter,
)


def _make_health() -> HealthState:
    token = "test-httpx-shared-token"  # noqa: S105 (test token)
    return HealthState(
        port=49997,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-013")
@pytest.mark.asyncio
async def test_single_async_client_after_n50_outbound_requests(tmp_path) -> None:
    """N=50 outbound requests through the shared client; init count must equal 1."""
    reset_async_client_init_counter()
    assert get_async_client_init_count() == 0

    app = build_runtime_app(
        health=_make_health(),
        sqlite_path=tmp_path / "sidecar.db",
    )

    # Drive the lifespan manually so we exercise the same code path uvicorn
    # would. ``app.router.lifespan_context`` is the modern attachment point.
    async with app.router.lifespan_context(app):
        client = app.state.http_client
        assert isinstance(client, httpx.AsyncClient)
        assert get_async_client_init_count() == 1

        # Swap the client's transport to a mock so the test is offline.
        # We instantiate the transport in place (no new AsyncClient).
        client._transport = httpx.MockTransport(  # type: ignore[attr-defined]
            lambda request: httpx.Response(204)
        )

        # Issue 50 requests concurrently. Each call uses the SAME client
        # instance; no implicit construction allowed.
        async def one_request(i: int) -> int:
            r = await client.get(f"http://test.invalid/{i}")
            return r.status_code

        results = await asyncio.gather(*[one_request(i) for i in range(50)])
        assert all(rc == 204 for rc in results)

        # The hard assertion: still exactly one client constructed.
        assert get_async_client_init_count() == 1, (
            f"VAL-W2-013 violated: observed "
            f"{get_async_client_init_count()} httpx.AsyncClient init "
            f"calls (expected exactly 1)."
        )

    # After lifespan teardown the count is unchanged (aclose does not
    # construct a new client).
    assert get_async_client_init_count() == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-013")
@pytest.mark.asyncio
async def test_httpx_client_is_closed_after_lifespan(tmp_path) -> None:
    """Lifespan teardown calls ``aclose`` on the shared httpx client."""
    reset_async_client_init_counter()
    app = build_runtime_app(
        health=_make_health(),
        sqlite_path=tmp_path / "sidecar.db",
    )
    async with app.router.lifespan_context(app):
        client = app.state.http_client
        assert isinstance(client, httpx.AsyncClient)
        assert client.is_closed is False
    # Outside the context the client is closed.
    assert client.is_closed is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-013")
def test_runtime_module_has_exactly_one_httpx_asyncclient_construction_site() -> None:
    """Source guard: only one ``httpx.AsyncClient(`` call site in runtime.py.

    A future refactor that adds a second construction site (e.g. a helper
    that lazily creates a second client) would silently break the
    single-client invariant. This grep guard catches it at lint time.
    """
    from pathlib import Path

    runtime_py = (
        Path(__file__).resolve().parent.parent
        / "relay_sidecar"
        / "runtime.py"
    )
    text = runtime_py.read_text(encoding="utf-8")
    sites = text.count("httpx.AsyncClient(")
    assert sites == 1, (
        f"Expected exactly 1 `httpx.AsyncClient(` construction site in "
        f"runtime.py; found {sites}. VAL-W2-013 requires a singleton."
    )
