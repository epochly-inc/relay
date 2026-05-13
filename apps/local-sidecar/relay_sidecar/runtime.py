"""FastAPI asyncio runtime + lifecycle for the local sidecar (W2.2).

Builds on the W2.1 ``health.build_app`` skeleton. W2.2 lands:

  - The modern FastAPI ``lifespan`` async context manager (replacing the
    deprecated ``@app.on_event`` decorators).
  - A SINGLE shared ``httpx.AsyncClient`` instantiated in lifespan startup
    and reused for every outbound request the sidecar issues (eng plan A2;
    VAL-W2-013). Construction calls are counted via a module-level
    ``_async_client_init_counter`` so tests can assert ``count == 1`` after
    N=50 outbound requests.
  - An ``aiosqlite`` connection pool whose ``PRAGMA journal_mode=WAL`` and
    ``PRAGMA busy_timeout = 5000`` run BEFORE the HTTP listener binds the
    port (VAL-W2-014). The bind timestamp is recorded on
    ``app.state.bound_at_monotonic`` so tests can assert
    ``port_bind_timestamp <= first_request_timestamp``.
  - A ``_draining`` flag toggled in lifespan shutdown plus an HTTP
    middleware that returns ``503 Retry-After: 30`` for new requests once
    draining is true (eng plan A1 + X1; VAL-W2-015). In-flight requests
    proceed to completion; SIGTERM is wired to an ``asyncio.Event`` that
    the lifespan awaits.
  - All route handlers are ``async def`` (VAL-W2-012; grep guard).
  - Zero blocking I/O inside async handler bodies (VAL-W2-016; AST lint).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
from fastapi import FastAPI
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .db import DEFAULT_READER_COUNT, SidecarDatabase
from .errors import RelaySQLiteBusyExhausted
from .health import HealthState, _register_health_routes
from .lockfile import relay_home
from .primitives.transactional_db_write import set_active_database
from .state_engine.http_endpoint import build_state_router

# Drain grace window advertised to clients via ``Retry-After``. Matches the
# manifest service.local-sidecar.quiesce_timeout_ms (30000 ms = 30 s).
DRAIN_RETRY_AFTER_S: int = 30

# Sidecar SQLite database filename. Lives under ``${RELAY_HOME}``. W2.2
# only enables WAL on this DB; full schema lands in W2.3+.
SIDECAR_DB_FILENAME: str = "sidecar.db"

# Module-level test counter. Every ``httpx.AsyncClient.__init__`` call
# through ``build_runtime_app`` increments this; VAL-W2-013 asserts the
# value is exactly 1 after N=50 outbound requests. Tests reset it via
# ``reset_async_client_init_counter()``.
_async_client_init_counter: int = 0


def reset_async_client_init_counter() -> None:
    """Reset the test counter to 0. Test-only entrypoint."""
    global _async_client_init_counter
    _async_client_init_counter = 0


def get_async_client_init_count() -> int:
    """Return the current count of httpx.AsyncClient instantiations."""
    return _async_client_init_counter


def _make_async_client() -> httpx.AsyncClient:
    """Construct the singleton ``httpx.AsyncClient`` and bump the counter.

    Centralising construction here makes the VAL-W2-013 counter exact:
    each call to ``build_runtime_app`` produces exactly one client, and
    callers obtain the client via ``app.state.http_client`` rather than
    re-instantiating.
    """
    global _async_client_init_counter
    client = httpx.AsyncClient(
        # Modest defaults: the sidecar is local-only and proxies to the
        # hosted control plane / model providers. Aggressive timeouts here
        # would surface latency issues clearly during W3+ ingest work.
        timeout=httpx.Timeout(30.0, connect=10.0),
        # No follow_redirects: providers should return non-redirected.
        follow_redirects=False,
    )
    _async_client_init_counter += 1
    return client


@dataclass
class RuntimeState:
    """Per-process runtime state attached to ``app.state``.

    Attributes:
        health: The W2.1 ``HealthState`` (bearer token, nonce store, port).
        sqlite_path: Absolute path to ``sidecar.db``.
        bound_at_monotonic: ``loop.time()`` value captured at the end of
            lifespan startup, just before ``yield``. Used by VAL-W2-014
            to prove ``port_bind_timestamp <= first_request_timestamp``.
        draining: Toggled to True in the lifespan ``finally`` block when
            uvicorn invokes shutdown on SIGTERM. The DrainMiddleware
            checks this flag and returns 503 + Retry-After for new
            requests once set.
        database: The W2.3 ``SidecarDatabase`` owning the writer + reader
            connections and the single-writer queue. None before lifespan
            startup; populated in ``lifespan`` and closed in shutdown.
        reader_count: Number of reader connections to open. Default
            ``DEFAULT_READER_COUNT`` (2) per VAL-W2-023 (>= 2 connections).
    """

    health: HealthState
    sqlite_path: Path
    bound_at_monotonic: float | None = None
    draining: bool = False
    database: SidecarDatabase | None = None
    reader_count: int = DEFAULT_READER_COUNT


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan: init SQLite WAL + httpx client BEFORE serving.

    Order matters for VAL-W2-014: the listener does not begin accepting
    connections until ``yield``. Uvicorn calls the lifespan startup
    portion, awaits its completion, THEN binds the port. Therefore every
    PRAGMA executed here completes strictly before the first request.

    Shutdown: uvicorn installs its own SIGTERM/SIGINT handlers which, on
    receipt, trigger graceful shutdown and invoke this lifespan's
    ``__aexit__`` (the ``finally`` block below) BEFORE waiting for
    in-flight handlers (uvicorn's ``timeout_graceful_shutdown`` controls
    that wait). We do NOT install our own asyncio signal handler here;
    doing so would clobber uvicorn's handler and the process would never
    drain. The ``finally`` block sets the drain flag, briefly yields so
    other tasks see it (the DrainMiddleware reads it on each request),
    then closes the httpx client.
    """
    state: RuntimeState = app.state.runtime

    # ---- Startup ----
    # 1. SQLite database manager (writer + N readers, WAL + busy_timeout
    #    + migrations + single-writer queue). Per VAL-W2-014 ALL of this
    #    completes BEFORE the listener binds the port. Per VAL-W2-017/-018
    #    every connection runs PRAGMA journal_mode=WAL + busy_timeout=5000.
    state.database = SidecarDatabase(
        db_path=state.sqlite_path,
        reader_count=state.reader_count,
    )
    await state.database.open()
    # Register the database as the process-wide instance backing the
    # ``transactional_db_write`` module-level primitive.
    set_active_database(state.database)
    # 2. Single shared httpx.AsyncClient.
    app.state.http_client = _make_async_client()
    # 3. Record bind-ready timestamp. Uvicorn binds AFTER startup yields,
    #    so the next ``time.monotonic()`` (taken from the handler side) is
    #    strictly greater than this value.
    loop = asyncio.get_running_loop()
    state.bound_at_monotonic = loop.time()

    try:
        yield
    finally:
        # ---- Shutdown ----
        # Toggle drain BEFORE closing the client so any concurrent handler
        # sees the flag on its next entry to the middleware.
        state.draining = True
        # Brief yield to let scheduled tasks observe the flag.
        await asyncio.sleep(0)
        # Close the httpx client. ``aclose`` cancels in-flight outbound
        # requests gracefully.
        client: httpx.AsyncClient | None = getattr(app.state, "http_client", None)
        if client is not None:
            await client.aclose()
        # Close the SQLite database manager (cancels the writer task,
        # drains pending requests, closes all connections). Clear the
        # module-level registration so a subsequent
        # ``transactional_db_write`` call surfaces a clean RuntimeError
        # rather than touching a closed connection.
        if state.database is not None:
            await state.database.close()
            state.database = None
        set_active_database(None)


class DrainMiddleware:
    """Pure-ASGI middleware: 503 + Retry-After for new requests when draining.

    Why pure-ASGI (not starlette's BaseHTTPMiddleware): the BaseHTTPMiddleware
    runs the wrapped handler in a separate task and surfaces uvicorn
    graceful-shutdown cancellation as HTTP 500 "Internal Server Error" for
    in-flight requests. The pure-ASGI form below sits directly on the
    ASGI receive/send wire so in-flight responses pass through unmodified
    while new requests during drain are short-circuited.

    VAL-W2-015 semantics:
      - HTTP request arrives, draining=False -> pass through to downstream.
      - HTTP request arrives, draining=True  -> 503 + Retry-After.
      - Lifespan / websocket scopes always pass through (drain applies only
        to HTTP requests).
    """

    def __init__(self, app: ASGIApp, runtime: RuntimeState) -> None:
        self.app = app
        self.runtime = runtime

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http" or not self.runtime.draining:
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=503,
            content={
                "code": "RELAY-SIDECAR-007",
                "error_class": "RELAY-SIDECAR-DRAINING",
                "message": (
                    "sidecar is draining; retry after the advertised window"
                ),
            },
            headers={"Retry-After": str(DRAIN_RETRY_AFTER_S)},
        )
        await response(scope, receive, send)


def build_runtime_app(
    *,
    health: HealthState,
    sqlite_path: Path | None = None,
    relay_home_override: Path | None = None,
) -> FastAPI:
    """Build the full asyncio runtime app (W2.2 entrypoint).

    Composes the W2.1 ``build_health_app`` routes (``/health``,
    ``/health/nonce``) with the W2.2 lifespan + drain middleware + the
    diagnostic ``GET /diagnostics/sqlite`` route used by VAL-W2-014.

    Args:
        health: HealthState carrying bearer-token + port + nonce store.
        sqlite_path: Override the SQLite DB path (tests inject a tmpdir).
            Defaults to ``${RELAY_HOME}/sidecar.db``.
        relay_home_override: Override ``${RELAY_HOME}`` discovery.

    Returns:
        A FastAPI app ready for ``uvicorn.run(app, ...)``. The app's
        ``state.runtime`` carries the RuntimeState; ``state.http_client``
        is bound during startup (None before).
    """
    base_home = relay_home_override if relay_home_override is not None else relay_home()
    db_path = (
        sqlite_path if sqlite_path is not None else base_home / SIDECAR_DB_FILENAME
    )

    runtime = RuntimeState(health=health, sqlite_path=db_path)

    # Construct the FastAPI app with the lifespan attached at __init__.
    # This is critical: starlette captures the lifespan during app
    # construction; mutating ``app.router.lifespan_context`` afterwards
    # does NOT re-bind, and the lifespan will silently never run. We
    # then graft the W2.1 health routes onto the same app via the
    # helper from health.py (instead of constructing a second FastAPI).
    app = FastAPI(title="relay-sidecar", version=__version__, lifespan=lifespan)
    _register_health_routes(app, health)
    # Drain middleware fires for every HTTP request including /health.
    # Pass the runtime explicitly so the middleware does not depend on
    # ``app.state.runtime`` being set (FastAPI builds the middleware stack
    # lazily on first request, so app.state assignment timing matters).
    app.add_middleware(DrainMiddleware, runtime=runtime)

    # VAL-W2-020: SQLITE_BUSY exhaustion surfaces as HTTP 503 with a
    # structured RELAY-SQLITE-BUSY-EXHAUSTED envelope (NOT a bare 500
    # carrying sqlite3.OperationalError).
    @app.exception_handler(RelaySQLiteBusyExhausted)
    async def _sqlite_busy_handler(
        _request: Any, exc: RelaySQLiteBusyExhausted
    ) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_envelope())

    # Attach runtime state.
    app.state.runtime = runtime
    app.state.http_client = None  # populated in lifespan startup

    # W2.4: register the state-engine HTTP boundary.
    # ``POST /v1/state/transition`` validates the three-anchor handoff
    # (VAL-W2-062) BEFORE forwarding to ``compare_and_set_state``. The
    # database_getter closure resolves the active SidecarDatabase from
    # app.state.runtime so the router does not need lifespan visibility.
    def _get_database() -> SidecarDatabase:
        db = runtime.database
        if db is None:
            raise RuntimeError(
                "state-transition handler invoked before lifespan startup "
                "registered SidecarDatabase on app.state.runtime"
            )
        return db

    app.include_router(build_state_router(database_getter=_get_database))

    @app.get("/diagnostics/sqlite")
    async def diagnostics_sqlite() -> dict[str, Any]:
        """Return the current SQLite journal_mode + busy_timeout values.

        Used by VAL-W2-014 to prove ``journal_mode == "wal"`` is in effect
        on a fresh connection AFTER the lifespan startup hook completed.
        The handler opens a short-lived aiosqlite connection per call;
        WAL is a file-level mode so the value is visible from any
        connection to the same DB file.
        """
        async with aiosqlite.connect(str(runtime.sqlite_path)) as conn:
            async with conn.execute("PRAGMA journal_mode") as cur:
                row = await cur.fetchone()
                journal_mode = row[0] if row else None
            async with conn.execute("PRAGMA busy_timeout") as cur:
                row = await cur.fetchone()
                busy_timeout = row[0] if row else None
        return {
            "sqlite": {
                "journal_mode": journal_mode,
                "busy_timeout": busy_timeout,
                "db_path": str(runtime.sqlite_path),
            },
            "sidecar_version": __version__,
        }

    @app.get("/diagnostics/runtime")
    async def diagnostics_runtime() -> dict[str, Any]:
        """Return runtime metadata: bound_at_monotonic, draining, port."""
        loop_time = asyncio.get_running_loop().time()
        return {
            "bound_at_monotonic": runtime.bound_at_monotonic,
            "observed_at_monotonic": loop_time,
            "draining": runtime.draining,
            "port": runtime.health.port,
            "sidecar_version": __version__,
        }

    @app.get("/diagnostics/db")
    async def diagnostics_db() -> dict[str, Any]:
        """Return SidecarDatabase stats: connection counts, reader pragmas.

        Used by VAL-W2-023 to prove >= 2 aiosqlite connections (writer +
        readers) are open and that readers carry PRAGMA query_only = 1.
        Reader pragmas are read via the actual reader connections (NOT a
        fresh transient connection) so the test sees the persistent
        query_only setting.
        """
        db = runtime.database
        if db is None:
            return {
                "open": False,
                "connect_call_count": 0,
                "reader_count": 0,
                "readers": [],
            }
        readers_info: list[dict[str, Any]] = []
        for i in range(db.reader_count):
            conn = db.acquire_reader()
            async with conn.execute("PRAGMA query_only") as cur:
                row = await cur.fetchone()
                query_only = int(row[0]) if row else None
            async with conn.execute("PRAGMA busy_timeout") as cur:
                row = await cur.fetchone()
                busy_timeout = int(row[0]) if row else None
            readers_info.append(
                {
                    "index": i,
                    "query_only": query_only,
                    "busy_timeout": busy_timeout,
                }
            )
        return {
            "open": True,
            "connect_call_count": db.connect_call_count,
            "reader_count": db.reader_count,
            "readers": readers_info,
        }

    return app


def run_uvicorn(
    *,
    health: HealthState,
    host: str = "127.0.0.1",
    port: int = 0,
    sqlite_path: Path | None = None,
) -> None:  # pragma: no cover (exercised by subprocess tests, not in-process)
    """Run the sidecar under uvicorn.

    Used by W5's CLI entrypoint and by the W2.2 shutdown-drain tests
    (which spawn this via ``subprocess.Popen`` so SIGTERM is real).

    Args:
        health: HealthState for the bearer/nonce surface.
        host: Bind host. Defaults to 127.0.0.1 (loopback-only; never 0.0.0.0).
        port: Bind port. 0 means ephemeral.
        sqlite_path: SQLite DB path override.
    """
    import uvicorn

    app = build_runtime_app(health=health, sqlite_path=sqlite_path)
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=os.environ.get("RELAY_SIDECAR_LOG_LEVEL", "warning"),
        access_log=False,
        # Force the default asyncio loop so the loop.add_signal_handler path
        # is reachable. uvloop on macOS supports add_signal_handler but the
        # test surface is more portable on the stdlib loop.
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    server.run()


__all__ = [
    "DRAIN_RETRY_AFTER_S",
    "DrainMiddleware",
    "RuntimeState",
    "SIDECAR_DB_FILENAME",
    "build_runtime_app",
    "get_async_client_init_count",
    "lifespan",
    "reset_async_client_init_counter",
    "run_uvicorn",
]
