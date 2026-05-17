"""FastAPI asyncio runtime + lifecycle for the local sidecar (W2.2 + W2.6).

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

W2.6 extends the lifespan with the FULL quiesce protocol (VAL-W2-043
through VAL-W2-048):

  - ``InflightTracker`` registered on ``RuntimeState.quiesce.tracker``;
    long-running operations (ingest, gate evaluate, replay session,
    background flush) acquire it via ``async with tracker.acquire(...)``
    so the idle-countdown task only fires when the sidecar is genuinely
    idle (VAL-W2-043 + VAL-W2-048).
  - ``/v1/ingest`` placeholder endpoint that participates in the tracker
    so VAL-W2-044 (drain rejects new ingest with 503) is exercisable end
    to end while the full ingest surface lands later in W3+.
  - Lifespan tear-down ordering on graceful shutdown:
      1. ``state.draining = True`` (drain middleware now answers 503).
      2. Wait for tracker.in_flight_count to reach 0 (bounded by
         ``RELAY_SIDECAR_DRAIN_DEADLINE_S``; defaults to 30s matching the
         manifest service.local-sidecar.quiesce_timeout_ms).
      3. ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer connection
         BEFORE closing aiosqlite connections (VAL-W2-045 -- WAL file
         size = 0 post-shutdown).
      4. Close the SidecarDatabase (cancels writer task, closes
         connections).
      5. Close the shared httpx.AsyncClient.
      6. Clear the lockfile via ``local_atomic_file_write(path, b"")``
         (VAL-W2-047) so the next ``acquire_or_attach`` classifies it as
         NO_LOCK rather than STALE_PID.
  - SIGUSR1 (or SIGTERM on Windows) handler triggers the force-stop path:
      a. Emit one ``sidecar.forced_stop`` event_log_entries row BEFORE
         killing any in-flight transaction (VAL-W2-046).
      b. Set ``state.quiesce.force_stop_requested = True`` so the
         lifespan tear-down branch SKIPS the WAL checkpoint AND SKIPS
         the lockfile clear (force-stop deliberately leaves the
         lockfile in place; the next spawn observes STALE_PID and
         clears via spawn.py).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .db import DEFAULT_READER_COUNT, SidecarDatabase
from .errors import RelaySQLiteBusyExhausted
from .health import HealthState, _register_health_routes
from .lockfile import relay_home, resolve_lockfile_path
from .manifest_enforcement import (
    ManifestRegistry,
    enforce_command_hash,
    enforce_manifest_active_or_in_grace,
)
from .primitives import local_atomic_file_write
from .primitives.transactional_db_write import (
    set_active_database,
    transactional_db_write,
)
from .quiesce import (
    InflightTracker,
    QuiesceState,
    force_stop_signal_number,
    resolve_idle_timeout_seconds,
)
from .recovery import recover_or_refuse
from .side_effect_markers import (
    EnforcementRejection,
    check_span_marker_pairing,
)
from .state_engine.http_endpoint import build_state_router
from .validation.ingest_limits import validate_span_size_and_depth
from .validation.ingest_utf8 import validate_indexed_utf8
from .validation.raw_capture import evaluate_raw_capture_on_request

# Drain grace window advertised to clients via ``Retry-After``. Matches the
# manifest service.local-sidecar.quiesce_timeout_ms (30000 ms = 30 s).
DRAIN_RETRY_AFTER_S: int = 30

# Sidecar SQLite database filename. Lives under ``${RELAY_HOME}``. W2.2
# only enables WAL on this DB; full schema lands in W2.3+.
SIDECAR_DB_FILENAME: str = "sidecar.db"

# Drain deadline (seconds): the lifespan tear-down waits at most this long
# for in-flight operations to complete before forcing the WAL checkpoint
# and closing connections. Matches the manifest
# service.local-sidecar.quiesce_timeout_ms (30000 ms = 30 s) by default.
# Tests override via ``RELAY_SIDECAR_DRAIN_DEADLINE_S``.
DEFAULT_DRAIN_DEADLINE_S: float = 30.0
DRAIN_DEADLINE_ENV: str = "RELAY_SIDECAR_DRAIN_DEADLINE_S"


def _resolve_drain_deadline_seconds(
    default: float = DEFAULT_DRAIN_DEADLINE_S,
) -> float:
    """Resolve the drain-wait deadline from ``RELAY_SIDECAR_DRAIN_DEADLINE_S``.

    Returns ``default`` when the env var is unset or empty. Raises
    ``ValueError`` on a non-numeric or non-positive override.
    """
    raw = os.environ.get(DRAIN_DEADLINE_ENV, "").strip()
    if not raw:
        return float(default)
    parsed = float(raw)
    if parsed <= 0.0:
        raise ValueError(
            f"{DRAIN_DEADLINE_ENV} must be a positive float; got {raw!r}"
        )
    return parsed

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
        lockfile_path: Path to ``${RELAY_HOME}/sidecar.lock``. The lifespan
            tear-down clears this file via ``local_atomic_file_write`` on
            graceful shutdown (VAL-W2-047). Force-stop intentionally
            leaves it untouched so the next ``acquire_or_attach`` observes
            STALE_PID and clears via the spawn path.
        quiesce: W2.6 quiesce-protocol state (in-flight tracker, force-stop
            flag, idle-shutdown trigger). Populated in lifespan startup;
            consumed by the lifespan tear-down + the SIGUSR1 handler.
        idle_timeout_seconds: Resolved idle-window length (seconds). The
            lifespan idle-countdown task uses this as the
            ``asyncio.wait_for`` timeout when waiting on
            ``quiesce.tracker.idle_event``. None until lifespan startup
            resolves the env override; see :func:`resolve_idle_timeout_seconds`.
        drain_deadline_seconds: Upper bound on how long the lifespan
            tear-down waits for in-flight operations to complete before
            forcing the WAL checkpoint. Resolved once at lifespan startup
            via :func:`_resolve_drain_deadline_seconds`.
    """

    health: HealthState
    sqlite_path: Path
    bound_at_monotonic: float | None = None
    draining: bool = False
    database: SidecarDatabase | None = None
    reader_count: int = DEFAULT_READER_COUNT
    lockfile_path: Path | None = None
    quiesce: QuiesceState = field(default_factory=QuiesceState)
    idle_timeout_seconds: float | None = None
    drain_deadline_seconds: float | None = None
    # W3 manifest enforcement (CLAUDE.md keystone invariant 3, spec F line 4100).
    # Seeded at lifespan startup from the operation manifest; the new
    # ingest routes (/v1/ingest/runs, /v1/ingest/spans:batch) look up
    # declared command_hashes via this registry before accepting any
    # submission. Empty in production until seeded; tests register
    # entries directly.
    manifest_registry: ManifestRegistry = field(default_factory=ManifestRegistry)
    # V2M02 w2.3/w2.4: in-memory replay + eval registries. The hosted
    # control-plane writers for replay_cases / replay_fixtures /
    # replay_results / eval_datasets / eval_runs are out-of-scope for the
    # OSS sidecar at M02 (they land in later milestones). The HTTP
    # surface lands now so SDKs + downstream clients have stable
    # endpoints to call; payloads round-trip through these registries to
    # preserve canonical response shapes per spec B.6 lines 3459-3468.
    # ALL writes go through these in-process containers; ALL writers
    # stamp ``written_by = "control_plane"`` (keystone invariant #1).
    replay_cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    replay_fixtures: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    replay_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    eval_datasets: dict[str, dict[str, Any]] = field(default_factory=dict)
    eval_runs: dict[str, dict[str, Any]] = field(default_factory=dict)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan: init SQLite WAL + httpx client BEFORE serving;
    drain + WAL-checkpoint + lockfile-clear on shutdown (W2.6 quiesce).

    Order matters for VAL-W2-014: the listener does not begin accepting
    connections until ``yield``. Uvicorn calls the lifespan startup
    portion, awaits its completion, THEN binds the port. Therefore every
    PRAGMA executed here completes strictly before the first request.

    Startup adds W2.6 quiesce wiring:
      - Construct an :class:`InflightTracker` and bind it to
        ``state.quiesce.tracker`` so route handlers can register
        long-running operations.
      - Resolve the idle-timeout window from
        ``RELAY_SIDECAR_IDLE_TIMEOUT_S`` (default 60s) and the drain
        deadline from ``RELAY_SIDECAR_DRAIN_DEADLINE_S`` (default 30s).
      - Spawn the idle-countdown task that calls
        ``await asyncio.wait_for(tracker.idle_event.wait(), timeout=IDLE)``
        in a loop; on a TimeoutError that fires while the event is still
        set (i.e. truly idle), it triggers graceful shutdown by setting
        ``state.quiesce.idle_shutdown_triggered = True`` and
        ``server.should_exit = True`` (when running under uvicorn).
      - Install a SIGUSR1 handler (POSIX) that triggers the force-stop
        path: emit a ``sidecar.forced_stop`` event_log_entries row BEFORE
        cancelling in-flight transactions, then mark
        ``state.quiesce.force_stop_requested = True`` so the lifespan
        tear-down skips the graceful WAL checkpoint AND the lockfile
        clear.

    Shutdown sequence (graceful path; force-stop branch noted inline):
      1. ``state.draining = True`` so DrainMiddleware now answers 503.
      2. Brief asyncio.sleep(0) so concurrent middleware sees the flag.
      3. Cancel the idle-countdown task (its await will raise
         CancelledError; we suppress it).
      4. Wait for ``tracker.idle_event`` with deadline =
         ``state.drain_deadline_seconds``. Force-stop path skips the
         wait (operations have already been signalled by the SIGUSR1
         handler).
      5. Run ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer
         connection BEFORE closing aiosqlite. SKIPPED on force-stop.
      6. Close the SidecarDatabase (cancels writer task, closes all
         connections).
      7. Close the shared ``httpx.AsyncClient``.
      8. Clear the lockfile via ``local_atomic_file_write(path, b"")``.
         SKIPPED on force-stop so the next spawn classifies STALE_PID.

    The fundamental ordering invariant for VAL-W2-045 is:
    WAL CHECKPOINT comes BEFORE database close which comes BEFORE
    lockfile clear. This guarantees the WAL file is truncated to size
    zero before any subsequent reader observes the database file.
    """
    state: RuntimeState = app.state.runtime

    # ---- Startup ----
    # 0. STARTUP RECOVERY (VAL-W2-049, -050, -051, -054, -055).
    #    Probe ``state.sqlite_path`` BEFORE creating SidecarDatabase or
    #    opening any aiosqlite connection. ``recover_or_refuse`` runs the
    #    fast-path quick_check (<= 2s budget) -> slow-path integrity_check
    #    -> WAL replay -> schema_version compare. On corruption, schema
    #    mismatch, or WAL-replay failure, it calls
    #    ``exit_with_structured_error`` which writes the structured JSON
    #    envelope to stderr and ``sys.exit``s with the appropriate code (3,
    #    5). The synchronous call is intentional: we MUST refuse to open
    #    the database before the migration runner blindly stamps a
    #    pristine schema on top of a corrupt file.
    #
    #    For production exit-code propagation through uvicorn, the
    #    ``run_uvicorn`` entrypoint runs this same probe BEFORE entering
    #    the asyncio loop -- a SystemExit raised from inside the lifespan
    #    coroutine is caught by uvicorn and would not preserve the exit
    #    code. The lifespan-side call here is the defensive backstop for
    #    callers that build the runtime app directly (tests +
    #    in-process embedders) and rely on the recovery contract.
    recover_or_refuse(state.sqlite_path)
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
    # 3. W2.6 quiesce wiring. The tracker lives on the QuiesceState so
    #    route handlers can reach it via app.state.runtime.quiesce.tracker
    #    (no module-level globals; one tracker per RuntimeState).
    tracker = InflightTracker()
    state.quiesce.tracker = tracker
    # Resolve env-overrideable timing windows once at startup so they
    # are immutable for the lifespan duration.
    state.idle_timeout_seconds = resolve_idle_timeout_seconds()
    state.drain_deadline_seconds = _resolve_drain_deadline_seconds()
    # 4. Idle-countdown task: triggers graceful shutdown when the sidecar
    #    has been continuously idle for state.idle_timeout_seconds. We
    #    capture a reference to the task on app.state so the lifespan
    #    tear-down can cancel it.
    app.state.idle_countdown_task = asyncio.create_task(
        _idle_countdown_loop(app, state),
        name="sidecar-idle-countdown",
    )
    # 5. SIGUSR1 force-stop handler. POSIX only; on Windows the helper
    #    falls back to SIGTERM (graceful drain only). We install via
    #    add_signal_handler so the handler runs on the loop thread (the
    #    only thread that may touch asyncio primitives).
    _install_force_stop_signal_handler(app, state)
    # 6. Record bind-ready timestamp. Uvicorn binds AFTER startup yields,
    #    so the next ``time.monotonic()`` (taken from the handler side) is
    #    strictly greater than this value.
    loop = asyncio.get_running_loop()
    state.bound_at_monotonic = loop.time()

    try:
        yield
    finally:
        # ---- Shutdown ----
        # Toggle drain BEFORE closing anything so any concurrent handler
        # sees the flag on its next entry to the middleware.
        state.draining = True
        # Brief yield to let scheduled tasks observe the flag.
        await asyncio.sleep(0)

        force_stop = state.quiesce.force_stop_requested

        # Cancel the idle-countdown task. Its CancelledError is benign;
        # we suppress and await it so the task slot is reaped.
        idle_task = getattr(app.state, "idle_countdown_task", None)
        if idle_task is not None and not idle_task.done():
            idle_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await idle_task

        # Uninstall the SIGUSR1 handler so a re-run of the lifespan in
        # the same process (rare, mostly tests) does not pile up handlers.
        _uninstall_force_stop_signal_handler()

        # On the graceful path (no force-stop), wait for in-flight
        # operations to complete up to the drain deadline. Force-stop
        # has ALREADY emitted its forensic event_log row in the SIGUSR1
        # handler and SHOULD NOT block on the in-flight tracker (the
        # operations have been notified that they are being killed).
        if not force_stop:
            tracker = state.quiesce.tracker
            deadline = state.drain_deadline_seconds or DEFAULT_DRAIN_DEADLINE_S
            if tracker is not None:
                with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
                    await asyncio.wait_for(
                        tracker.idle_event.wait(), timeout=deadline
                    )

        # WAL CHECKPOINT (VAL-W2-045) -- on graceful path only. Forced
        # stop deliberately skips so the WAL retains uncommitted bytes
        # and the next startup runs WAL recovery (covered by W2.7).
        #
        # W2.7 VAL-W2-053: detect a failed checkpoint (busy != 0 or raised
        # exception) and surface it. We invoke BOTH helpers: the existing
        # ``_wal_checkpoint_truncate`` (kept for VAL-W2-045's monkeypatch
        # surface) AND the new ``_wal_checkpoint_truncate_with_status``
        # whose return value the lifespan inspects for busy-flag failures.
        if not force_stop and state.database is not None:
            await _wal_checkpoint_truncate(state.database)
            ok, reason = await _wal_checkpoint_truncate_with_status(
                state.database
            )
            if not ok:
                state.quiesce.wal_checkpoint_failed = True
                state.quiesce.wal_checkpoint_failure_reason = reason
                # Per VAL-W2-053: emit the structured envelope to stderr
                # so subprocess-based runs observe the error AND preserve
                # the WAL file (do NOT delete the WAL or close
                # connections any more aggressively than the normal path).
                # The exit code 6 is signalled via uvicorn's should_exit
                # when running under uvicorn; in-process tests assert
                # the flag on state.quiesce instead.
                _surface_wal_checkpoint_failure(app, state, reason)

        # Close the SQLite database manager (cancels the writer task,
        # drains pending requests, closes all connections). Clear the
        # module-level registration so a subsequent
        # ``transactional_db_write`` call surfaces a clean RuntimeError
        # rather than touching a closed connection.
        #
        # W2.7 VAL-W2-053: SQLite's libsqlite removes the WAL file on
        # the LAST connection close UNLESS uncheckpointed frames remain
        # AND the file was opened with FCNTL_PERSIST_WAL. aiosqlite does
        # not expose a portable PERSIST_WAL switch, so we side-step the
        # ambiguity by copying the WAL bytes to a sentinel preserved
        # path BEFORE closing connections when checkpoint failed. The
        # next-startup recovery path (recovery.py) inspects both
        # ``<db>-wal`` AND ``<db>-wal.preserved``; presence of either
        # triggers the WAL replay branch.
        wal_cp_failed = state.quiesce.wal_checkpoint_failed
        if wal_cp_failed and state.database is not None:
            _preserve_wal_for_next_startup(state.sqlite_path)
        if state.database is not None:
            await state.database.close()
            state.database = None
        set_active_database(None)

        # Close the httpx client. ``aclose`` cancels in-flight outbound
        # requests gracefully.
        client: httpx.AsyncClient | None = getattr(app.state, "http_client", None)
        if client is not None:
            await client.aclose()

        # CLEAR LOCKFILE (VAL-W2-047) -- on graceful path only. Force-stop
        # AND wal-checkpoint-failure paths both leave it in place so the
        # next acquire_or_attach observes STALE_PID and clears via the
        # spawn path.
        if not force_stop and not wal_cp_failed and state.lockfile_path is not None:
            with contextlib.suppress(FileNotFoundError, OSError):
                local_atomic_file_write(
                    state.lockfile_path, b"", mode=0o600
                )


async def _wal_checkpoint_truncate(database: SidecarDatabase) -> None:
    """Run ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer connection.

    Per VAL-W2-045 the WAL file MUST be truncated to size zero before
    aiosqlite connections close so a subsequent reader observes a
    fully-checkpointed database file. The TRUNCATE variant blocks until
    every reader has caught up to the latest commit AND truncates the
    WAL to zero bytes (vs PASSIVE which is a no-op on contention and
    FULL which checkpoints without truncating).

    The function borrows the writer connection via the same internal
    accessor used by the W2.4 state engine (``database._writer``). We
    do NOT route through ``transactional_db_write`` because PRAGMA is
    a connection-scoped meta-statement, not a state-mutation row write.

    Errors are surfaced rather than swallowed: a failed checkpoint is
    a real problem and the lifespan tear-down should observe it. The
    caller wraps the call in a contextlib.suppress only on tear-down
    paths where the database is already half-closed.
    """
    conn = database._writer
    if conn is None:
        return
    # PRAGMA wal_checkpoint returns a row (busy, log_size, frames_checkpointed).
    # We don't inspect the values here; aiosqlite consumes them and the
    # WAL file size on disk is the observable test artifact.
    async with conn.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
        await cur.fetchall()
    # Commit any implicit transaction the PRAGMA opened (defensive).
    with contextlib.suppress(Exception):
        await conn.commit()


def _preserve_wal_for_next_startup(db_path: Path) -> None:
    """W2.7 VAL-W2-053: copy ``<db>-wal`` to a sentinel preserved path.

    SQLite removes ``<db>-wal`` on the last connection close (no
    standard PRAGMA exposes ``SQLITE_FCNTL_PERSIST_WAL``). To honour
    VAL-W2-053's "preserve the WAL" contract we copy the WAL bytes
    to ``<db>-wal.preserved`` BEFORE the close call removes them. The
    next-startup recovery path inspects both names.

    Best-effort: failure to copy is non-fatal. Without the preserve
    copy, the failed-checkpoint warning is still emitted on stderr;
    only the next-startup replay loses the in-flight frames.
    """
    wal_path = db_path.parent / (db_path.name + "-wal")
    if not wal_path.exists():
        return
    try:
        body = wal_path.read_bytes()
    except OSError:
        return
    if not body:
        return
    preserved = wal_path.parent / (wal_path.name + ".preserved")
    with contextlib.suppress(OSError):
        local_atomic_file_write(preserved, body, mode=0o600)


def _surface_wal_checkpoint_failure(
    app: FastAPI, state: RuntimeState, reason: str
) -> None:
    """W2.7 VAL-W2-053: emit structured envelope + signal exit code 6.

    The lifespan tear-down calls this when
    ``_wal_checkpoint_truncate_with_status`` reports failure. Behaviour:

      - Mark ``state.quiesce.wal_checkpoint_failed = True`` (the caller
        already does this; we re-assert defensively).
      - Emit the JSON envelope to stderr (subprocess tests parse it).
      - When running under uvicorn (``app.state.uvicorn_server`` set),
        set ``server.should_exit = True`` so the process exits with the
        configured code on the next loop iteration. Direct sys.exit(6)
        would crash in-process tests; uvicorn's should_exit path lets
        the loop unwind cleanly.

    Exit code 6 itself is enforced by the CLI entrypoint (W5) which
    inspects ``state.quiesce.wal_checkpoint_failed`` after the lifespan
    exits and calls ``sys.exit(6)`` accordingly. For pure-asgi tests the
    flag on ``state.quiesce`` is the observable evidence.
    """
    from .errors import (
        RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
        RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
    )
    from .recovery import (
        EXIT_CODE_WAL_CHECKPOINT_FAILED,
        _wal_size,
    )

    state.quiesce.wal_checkpoint_failed = True
    state.quiesce.wal_checkpoint_failure_reason = reason
    db_path = state.sqlite_path
    wal_path = db_path.parent / (db_path.name + "-wal")
    envelope = {
        "code": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
        "error_class": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
        "exit_code": EXIT_CODE_WAL_CHECKPOINT_FAILED,
        "message": (
            "sidecar shutdown: PRAGMA wal_checkpoint(TRUNCATE) failed; "
            "WAL preserved for next-startup recovery"
        ),
        "details": {
            "db_path": str(db_path),
            "wal_path": str(wal_path),
            "wal_present": wal_path.exists(),
            "wal_size_bytes": _wal_size(db_path),
            "underlying_error": reason,
        },
    }
    line = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    import sys as _sys

    _sys.stderr.write(line + "\n")
    _sys.stderr.flush()
    server = getattr(app.state, "uvicorn_server", None)
    if server is not None:
        server.should_exit = True


async def _wal_checkpoint_truncate_with_status(
    database: SidecarDatabase,
) -> tuple[bool, str]:
    """W2.7 VAL-W2-053: run TRUNCATE checkpoint and report success.

    Returns ``(success, reason)``:

      - ``(True, "")`` -- the PRAGMA returned ``(busy=0, ...)`` and no
        exception was raised. The WAL has been truncated to size 0 (or
        is empty pending the final connection close).
      - ``(False, <reason>)`` -- the PRAGMA returned ``busy=1`` (a
        reader held an old snapshot beyond the busy_timeout window) OR
        raised an exception. ``reason`` carries the failure detail.

    Why TWO helpers: the original ``_wal_checkpoint_truncate`` is used
    by VAL-W2-045 tests that monkeypatch the function name and inspect
    the call order. Adding the status detection there would change the
    return type and break those tests. The new helper wraps the same
    PRAGMA but with a (success, reason) return contract.
    """
    conn = database._writer
    if conn is None:
        return (True, "")
    try:
        async with conn.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
            rows = await cur.fetchall()
    except Exception as e:  # noqa: BLE001
        return (False, f"{type(e).__name__}: {e}")
    with contextlib.suppress(Exception):
        await conn.commit()
    # PRAGMA wal_checkpoint(TRUNCATE) returns a single row
    # ``(busy, log_size, frames_checkpointed)``. busy=1 means SQLite
    # could not acquire the writer/reader lock to truncate. busy=0
    # means the truncate succeeded. We treat busy != 0 as failure.
    if not rows:
        return (True, "")
    first = rows[0]
    try:
        busy_flag = int(first[0])
    except (TypeError, ValueError, IndexError):
        return (True, "")
    if busy_flag != 0:
        return (
            False,
            (
                f"PRAGMA wal_checkpoint(TRUNCATE) returned busy={busy_flag}; "
                f"a reader holds an old snapshot beyond the busy_timeout window"
            ),
        )
    return (True, "")


# Module-level reference to the loop slot we installed our SIGUSR1
# handler on, used by _uninstall_force_stop_signal_handler. We track
# the loop instead of the handler because asyncio.add_signal_handler
# overwrites any prior registration on (loop, signal); to "uninstall"
# we call remove_signal_handler on the same (loop, signal) pair.
_signal_handler_loop: asyncio.AbstractEventLoop | None = None
_signal_handler_signum: int | None = None


def _install_force_stop_signal_handler(app: FastAPI, state: RuntimeState) -> None:
    """Install a loop-bound SIGUSR1 handler that triggers force-stop.

    POSIX only. On Windows ``loop.add_signal_handler`` is unavailable;
    the handler is silently skipped (force-stop on Windows degrades to
    SIGTERM = graceful drain).
    """
    global _signal_handler_loop, _signal_handler_signum
    if os.name == "nt":  # pragma: no cover (Windows-only)
        return
    loop = asyncio.get_running_loop()
    signum = force_stop_signal_number()
    try:
        loop.add_signal_handler(
            signum, lambda: _on_force_stop(app, state, "signal")
        )
    except (NotImplementedError, ValueError, RuntimeError):
        # Common cases that legitimately skip signal-handler installation
        # without failing startup:
        #  - NotImplementedError: certain custom loops do not implement
        #    add_signal_handler at all (older uvloop versions).
        #  - ValueError: signum is invalid or unsupported on this platform.
        #  - RuntimeError: "set_wakeup_fd only works in main thread of
        #    the main interpreter" -- pytest-asyncio runs the test loop
        #    on the main thread typically, but some test fixtures (and
        #    pytest-xdist worker processes) install loops on worker
        #    threads. The force-stop API still works via the
        #    request_force_stop helper for in-process tests; only the
        #    OS-level SIGUSR1 entry is unavailable on those loops.
        return
    _signal_handler_loop = loop
    _signal_handler_signum = signum


def _uninstall_force_stop_signal_handler() -> None:
    """Remove the previously-installed SIGUSR1 handler, if any."""
    global _signal_handler_loop, _signal_handler_signum
    if _signal_handler_loop is None or _signal_handler_signum is None:
        return
    if os.name == "nt":  # pragma: no cover
        return
    with contextlib.suppress(Exception):
        _signal_handler_loop.remove_signal_handler(_signal_handler_signum)
    _signal_handler_loop = None
    _signal_handler_signum = None


def _on_force_stop(app: FastAPI, state: RuntimeState, reason: str) -> None:
    """Loop-bound force-stop entry point. Schedules the async forced-stop work.

    Invoked from the loop's signal-handler slot OR from
    :func:`request_force_stop` (in-process tests). Idempotent: only the
    FIRST invocation schedules the async task; subsequent calls no-op.
    """
    if state.quiesce.force_stop_requested:
        return
    state.quiesce.force_stop_requested = True
    state.quiesce.force_stop_reason = reason
    state.draining = True
    # Schedule the async forced-stop work (event_log row + server.exit).
    asyncio.get_running_loop().create_task(
        _execute_forced_stop(app, state),
        name="sidecar-forced-stop",
    )


async def _execute_forced_stop(app: FastAPI, state: RuntimeState) -> None:
    """Emit ``sidecar.forced_stop`` event_log row, then signal exit.

    Per VAL-W2-046: the row MUST be emitted BEFORE the in-flight
    transaction is killed. Per CLAUDE.md keystone invariant #8 (atomic
    persistence -- four primitives only), the row is written through
    ``transactional_db_write`` (atomic primitive #2). The primitive
    enqueues onto the SidecarDatabase writer queue, which serialises
    behind any in-flight CAS transaction holding the writer connection;
    the queued write completes once that transaction commits or rolls
    back. The CAS transaction, if any, is then ROLLBACK-ed by the
    lifespan tear-down's ``database.close()`` which cancels the writer
    task (any pending future is failed via the W2.3 close path).

    History: an earlier implementation opened a separate short-lived
    aiosqlite (db-connect) handle and INSERTed directly, justifying it
    as the "one place" outside the four primitives. That violated
    keystone #8. Routing through ``transactional_db_write`` is correct
    because:

      - The CAS path holds ``database._state_engine_writer_lock`` (an
        asyncio.Lock among CAS callers), NOT the queue itself. The
        queue's writer task and the CAS path SHARE the underlying
        ``database._writer`` connection; SQLite-level serialisation
        across them is exactly what we want.
      - The forced_stop event is always emitted from a fresh asyncio
        task scheduled by ``_on_force_stop`` -- no awaiter is blocked on
        the queued write completing, so there is no opportunity for
        deadlock.

    Idempotent: the function checks ``_force_stop_row_written`` to
    avoid double-writing on multiple invocations.
    """
    if getattr(state.quiesce, "_force_stop_row_written", False):
        return
    db_path = state.sqlite_path
    if not db_path.exists() or state.database is None:
        # Database file never materialised OR database manager not
        # registered (lifespan startup failed before DB open). Nothing
        # to record; mark and proceed to the exit signal.
        state.quiesce._force_stop_row_written = True  # type: ignore[attr-defined]
        server = getattr(app.state, "uvicorn_server", None)
        if server is not None:
            server.should_exit = True
        return
    event_id = str(uuid.uuid4())
    occurred_at = (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    payload = {
        "reason": state.quiesce.force_stop_reason or "signal",
        "in_flight_count": (
            state.quiesce.tracker.in_flight_count
            if state.quiesce.tracker is not None
            else 0
        ),
        "in_flight_descriptions": (
            state.quiesce.tracker.in_flight_descriptions()
            if state.quiesce.tracker is not None
            else []
        ),
    }
    # Sentinel project id matches the W2.3 db.py:_flush_retry_buffer
    # convention for sidecar-internal observability rows.
    sentinel_project_id = "00000000-0000-0000-0000-000000000000"
    sentinel_scope_id = "00000000-0000-0000-0000-000000000000"
    row: dict[str, Any] = {
        "event_id": event_id,
        "schema_version": "relay.event_log_entry.v1",
        "project_id": sentinel_project_id,
        "scope_type": "other",
        "scope_id": sentinel_scope_id,
        "event_type": "sidecar.forced_stop",
        "actor_kind": "control_plane",
        "actor_id": None,
        "manifest_commit_hash": None,
        "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "occurred_at": occurred_at,
        "event_kind": "sidecar_forced_stop",
    }
    # Atomic primitive #2 -- the only sanctioned write path per
    # keystone #8. The primitive's busy-retry + backoff loop handles
    # SQLITE_BUSY transparently. Best-effort forensic write: if the
    # writer task has already been cancelled or the budget is exhausted
    # under heavy contention, we proceed with the exit path; the
    # in-process state of state.quiesce.force_stop_* still records the
    # forced-stop intent.
    with contextlib.suppress(Exception):
        await transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=sentinel_scope_id,
        )
    # Mark recorded to avoid double-writes on repeat triggers.
    state.quiesce._force_stop_row_written = True  # type: ignore[attr-defined]
    # Signal exit. If running under uvicorn, app.state.uvicorn_server
    # carries the Server instance and we set should_exit; otherwise
    # ASGI tests rely on the in-flight tracker + draining flag alone.
    server = getattr(app.state, "uvicorn_server", None)
    if server is not None:
        server.should_exit = True


def request_force_stop(app: FastAPI, *, reason: str = "api") -> None:
    """In-process force-stop trigger (used by tests and the CLI helper).

    Equivalent to receiving SIGUSR1 from outside the process. Safe to
    call from any coroutine; idempotent.
    """
    state: RuntimeState = app.state.runtime
    _on_force_stop(app, state, reason)


async def _idle_countdown_loop(app: FastAPI, state: RuntimeState) -> None:
    """Idle-countdown task: trigger graceful shutdown when continuously idle.

    Loop:
      1. Await ``tracker.idle_event`` with timeout = idle_timeout_seconds.
      2. If wait_for raises TimeoutError -> the sidecar was idle for the
         entire window. Trigger graceful shutdown.
      3. Otherwise (the await returned because the event is set; we
         observed an idle moment) immediately recheck: if the tracker
         is STILL idle AFTER another idle_timeout_seconds wait, exit.
         Concretely: we re-await with the timeout each iteration; if
         operations come and go we keep looping.

    Cancellation: the lifespan tear-down cancels this task; CancelledError
    unwinds cleanly.
    """
    tracker = state.quiesce.tracker
    if tracker is None:
        return
    timeout = state.idle_timeout_seconds or 60.0
    while True:
        # Wait for the tracker to be idle. If currently idle, this
        # returns immediately (the event is set); otherwise we block
        # until the last in-flight op releases.
        await tracker.idle_event.wait()
        # Now we are idle. Sleep for the full timeout window. If a new
        # operation acquires the tracker mid-sleep, the event will be
        # cleared but our sleep continues; at the END of the sleep we
        # check whether we're still idle. Continuously-idle for the
        # full window -> trigger shutdown.
        try:
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            raise
        if tracker.in_flight_count == 0 and tracker.idle_event.is_set():
            # Truly idle for the full window. Trigger graceful shutdown.
            state.quiesce.idle_shutdown_triggered = True
            state.draining = True
            server = getattr(app.state, "uvicorn_server", None)
            if server is not None:
                server.should_exit = True
            return
        # Otherwise: an op acquired the tracker during the sleep window.
        # Loop and wait for the next idle moment.


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
    # W2.6: resolve the lockfile path so the lifespan tear-down can clear
    # it on graceful shutdown (VAL-W2-047). The path is purely advisory
    # at runtime construction time; the spawn-side caller (W5 CLI) is
    # responsible for writing the lockfile. If the file does not exist
    # at tear-down time, the clear is a no-op (FileNotFoundError suppressed).
    #
    # IMPORTANT: when ``sqlite_path`` is explicitly overridden (test
    # injection via tmp_path), derive the lockfile path from the db's
    # parent directory rather than ``relay_home()``. Otherwise tests that
    # forget to monkeypatch RELAY_HOME would clobber the developer's real
    # ~/.relay/sidecar.lock on tear-down. Production (sqlite_path=None)
    # still resolves to ${RELAY_HOME}/sidecar.lock as expected.
    if sqlite_path is not None:
        lockfile_path = db_path.parent / "sidecar.lock"
    else:
        lockfile_path = resolve_lockfile_path(base_home)

    runtime = RuntimeState(
        health=health,
        sqlite_path=db_path,
        lockfile_path=lockfile_path,
    )

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

    @app.post("/v1/ingest")
    async def v1_ingest(request: Request) -> dict[str, Any]:
        """W2.6 placeholder ingest endpoint that participates in the
        in-flight tracker so VAL-W2-044 can exercise the drain path.

        The full ingest surface (envelope validation, schema_version
        checking, signed-bundle storage, ack semantics) lands in W3+;
        for W2.6 this handler does the minimum needed to:

          - Acquire the in-flight tracker so the idle-countdown task
            sees a live operation (VAL-W2-043 evidence path).
          - Sleep for the caller-controlled ``hold_ms`` query parameter
            (default 0). Tests use this to keep the tracker busy
            during the SIGTERM -> drain assertion window.
          - Respond with 200 + {"accepted": true, "operation_id": ...}.

        When ``state.draining=True``, the DrainMiddleware short-circuits
        BEFORE this handler runs and returns 503 + Retry-After +
        RELAY-SIDECAR-DRAINING envelope. So the only entry to this
        handler is on the non-draining path.
        """
        # Read hold_ms from query string. starlette Request lookup keeps
        # the handler's signature dependency-free (no FastAPI Query
        # injection needed).
        hold_ms_raw = request.query_params.get("hold_ms", "0")
        try:
            hold_ms = int(hold_ms_raw)
        except (TypeError, ValueError):
            hold_ms = 0
        if hold_ms < 0:
            hold_ms = 0
        tracker = runtime.quiesce.tracker
        if tracker is None:
            # Lifespan startup never bound a tracker; treat as a degraded
            # configuration error and reject. Tests would catch this.
            return {"accepted": False, "reason": "tracker-unbound"}
        async with tracker.acquire(description="ingest") as op:
            if hold_ms > 0:
                await asyncio.sleep(hold_ms / 1000.0)
            return {
                "accepted": True,
                "operation_id": op.operation_id,
                "held_ms": hold_ms,
            }

    # ----------------------------------------------------------------------
    # V2 M02 W2.1 ingest-namespace scope + body-shape helpers
    # (VAL-V2M02-001..009).
    # ----------------------------------------------------------------------
    #
    # Scope-auth is hosted-only in production (tokens issued by the hosted
    # control plane carry their scope set). The OSS sidecar mirrors the
    # surface so SDKs/tests exercise the same code paths. Per
    # contract.md:620-626 ("scopes are seeded onto a local 'dev' token via
    # a fixture"), the OSS profile reads the active scope set from the
    # ``X-Relay-Scopes`` request header (CSV). A missing header behaves
    # identically to an empty scope set: any non-public endpoint with a
    # declared ``scope_required`` returns 403 + RELAY-AUTH-014.

    def _build_error_envelope(
        *,
        code: str,
        http_status: int,
        message: str,
        blocked_surface: str,
        retry_advice: str = "do_not_retry",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a spec B.4 canonical error envelope."""
        env: dict[str, Any] = {
            "schema_version": "relay.error.v1",
            "code": code,
            "error_class": code,
            "http_status": http_status,
            "message": message,
            "blocked_surface": blocked_surface,
            "retry_advice": retry_advice,
        }
        if details is not None:
            env["details"] = details
        return env

    def _extract_request_scopes(request: Request) -> frozenset[str]:
        """Parse ``X-Relay-Scopes`` header into a normalized scope set.

        Treats missing/empty headers as the empty set. Whitespace around
        each CSV item is stripped. Duplicate entries collapse.
        """
        raw = request.headers.get("x-relay-scopes")
        if not raw:
            return frozenset()
        items = {part.strip() for part in raw.split(",") if part.strip()}
        return frozenset(items)

    def _check_required_scope(
        request: Request, *, required: str, blocked_surface: str
    ) -> JSONResponse | None:
        """Enforce a single ``scope_required`` value. Return 403 envelope
        when the active scope set lacks ``required``; ``None`` on accept.
        """
        scopes = _extract_request_scopes(request)
        if required in scopes:
            return None
        return JSONResponse(
            status_code=403,
            content=_build_error_envelope(
                code="RELAY-AUTH-014",
                http_status=403,
                message=(
                    f"token lacks required scope {required!r}; "
                    f"present scopes: {sorted(scopes)!r}"
                ),
                blocked_surface=blocked_surface,
                details={"required_scope": required},
            ),
        )

    # Maximum batch body size for the spans/contract-results batch routes
    # (spec B.4 RELAY-ING-021: payload > 1 MiB returns 413). The limit is
    # measured against the raw HTTP body bytes; the check fires BEFORE
    # JSON parsing so a 100 MiB body cannot exhaust memory.
    _BATCH_BODY_BYTE_LIMIT: int = 1024 * 1024  # 1 MiB

    # Canonical-write fields a SDK must NEVER set on /v1/ingest/runs. The
    # control plane writes these fields exclusively (CLAUDE.md keystone
    # invariant #1; spec line 1966 RELAY-ING-031).
    _CANONICAL_WRITE_FIELDS: frozenset[str] = frozenset(
        {"status", "primary_failure_class", "written_by",
         "accepted_at", "finalized_at"}
    )

    # Minimum required fields on a well-formed ``relay.ingest.run.v1``
    # envelope per spec line 1932-1958. The body-shape gate rejects with
    # 422 + RELAY-ING-001 when any are missing.
    _REQUIRED_RUN_FIELDS: tuple[str, ...] = (
        "schema_version",
        "run_id",
        "project_id",
        "trace_id",
        "client_lifecycle_status",
        "started_at",
        "manifest_commit_hash",
        "actor_identity_hash",
        "redaction_policy_version",
        "idempotency_key",
        "sequence_number",
    )

    async def _read_body_with_size_cap(
        request: Request,
        *,
        blocked_surface: str,
        cap: int = _BATCH_BODY_BYTE_LIMIT,
    ) -> bytes | JSONResponse:
        """Read raw body bytes; return 413 + RELAY-ING-021 if > ``cap``.

        Performs the size check BEFORE JSON parsing so an oversized body
        cannot exhaust JSON-decoder memory.
        """
        raw = await request.body()
        if len(raw) > cap:
            return JSONResponse(
                status_code=413,
                content=_build_error_envelope(
                    code="RELAY-ING-021",
                    http_status=413,
                    message=(
                        f"request body {len(raw)} bytes exceeds "
                        f"{cap} byte cap"
                    ),
                    blocked_surface=blocked_surface,
                    details={"body_bytes": len(raw), "cap_bytes": cap},
                ),
            )
        return raw

    # ----------------------------------------------------------------------
    # W3 manifest-enforced ingest routes (VAL-V2M03-012, VAL-V2M03-013).
    # ----------------------------------------------------------------------
    #
    # Per CLAUDE.md keystone invariant 3 + spec F line 4100: the control
    # plane refuses any submission whose ``command_hash`` does not match a
    # declared command in the active manifest version, OR whose
    # ``manifest_commit_hash`` is neither active nor in grace. Both
    # checks return HTTP 422 + ``RELAY-GATE-021`` envelope.

    async def _enforce_manifest_anchors(
        body: dict[str, Any],
    ) -> JSONResponse | tuple[str, str]:
        """Validate manifest + command anchors. Return JSONResponse on
        reject or a (manifest_commit_hash, command_hash) tuple on accept.
        """
        manifest_commit_hash = body.get("manifest_commit_hash")
        command_hash = body.get("command_hash")
        if not isinstance(manifest_commit_hash, str) or not isinstance(
            command_hash, str
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": (
                        "manifest_commit_hash and command_hash MUST be "
                        "non-empty strings"
                    ),
                },
            )

        cmd_reject = enforce_command_hash(
            registry=runtime.manifest_registry,
            manifest_commit_hash=manifest_commit_hash,
            command_hash=command_hash,
        )
        if cmd_reject is not None:
            return JSONResponse(
                status_code=cmd_reject.http_status,
                content=cmd_reject.envelope,
            )

        db = runtime.database
        if db is None:
            return JSONResponse(
                status_code=503,
                content={
                    "code": "RELAY-SIDECAR-007",
                    "error_class": "RELAY-SIDECAR-NOT-READY",
                    "message": "sidecar database not yet available",
                },
            )
        reader = db.acquire_reader()
        manifest_reject = await enforce_manifest_active_or_in_grace(
            reader, manifest_commit_hash=manifest_commit_hash
        )
        if manifest_reject is not None:
            return JSONResponse(
                status_code=manifest_reject.http_status,
                content=manifest_reject.envelope,
            )
        return manifest_commit_hash, command_hash

    async def _enforce_side_effect_pairing(
        *,
        spans: list[Any],
        database: Any,
    ) -> EnforcementRejection | None:
        """M04 w4 side-effect marker/proof check (VAL-V2M04-011..015).

        For every span carrying ``side_effect_class != 'read_only'``,
        verify that a paired ``side_effect_markers`` row exists AND a
        ``side_effect_proofs`` row exists. Returns the first rejection
        encountered (consistent with the prior per-span validators) or
        None when all spans pass.

        ``database`` is the SidecarDatabase instance; we use a reader
        connection to look up the marker / proof existence. ``None`` is
        treated as "no markers/proofs exist" -- any enforced span fails
        the pairing check.
        """
        if not spans:
            return None
        # Pre-filter spans that require enforcement so we don't query
        # for read_only spans (the dominant case).
        from .side_effect_markers import is_enforced_class

        enforced_spans = [
            s for s in spans
            if isinstance(s, dict) and is_enforced_class(s.get("side_effect_class"))
        ]
        if not enforced_spans:
            return None

        # Collect the set of idempotency_keys to look up.
        keys: list[str] = []
        for s in enforced_spans:
            k = s.get("idempotency_key")
            if isinstance(k, str) and k:
                keys.append(k)

        # Build existence sets via single reader queries.
        marker_keys: set[str] = set()
        proof_keys: set[str] = set()
        if database is not None and keys:
            reader = database.acquire_reader()
            placeholders = ",".join("?" for _ in keys)
            sql_markers = (
                f"SELECT idempotency_key FROM side_effect_markers "
                f"WHERE idempotency_key IN ({placeholders})"
            )
            async with reader.execute(sql_markers, tuple(keys)) as cur:
                async for row in cur:
                    marker_keys.add(str(row[0]))
            # For proofs we join through markers; a span passes the proof
            # check iff a side_effect_proofs row exists for its marker.
            sql_proofs = (
                f"SELECT m.idempotency_key FROM side_effect_proofs p "
                f"JOIN side_effect_markers m ON m.marker_id = p.marker_id "
                f"WHERE m.idempotency_key IN ({placeholders})"
            )
            async with reader.execute(sql_proofs, tuple(keys)) as cur:
                async for row in cur:
                    proof_keys.add(str(row[0]))

        for s in enforced_spans:
            k = s.get("idempotency_key")
            has_marker = isinstance(k, str) and k in marker_keys
            has_proof = isinstance(k, str) and k in proof_keys
            rejection = check_span_marker_pairing(
                span=s, has_marker=has_marker, has_proof=has_proof
            )
            if rejection is not None:
                return rejection
        return None

    _RUNS_SURFACE: str = "POST /v1/ingest/runs"

    @app.post("/v1/ingest/runs")
    async def v1_ingest_runs(request: Request) -> JSONResponse:
        """Run-submission ingest (VAL-V2M02-001..004, VAL-V2M03-012).

        Order of checks (outer gates first so the most specific error is
        returned):

          1. JSON-decode + non-empty-object check (RELAY-ING-001).
          2. Three-anchor manifest enforcement (RELAY-GATE-021). The
             manifest gate is the OUTERMOST invariant per CLAUDE.md
             keystone #3/#4 so a stale handoff surfaces before any other
             reason.
          3. Body-shape detection: minimal manifest-only bodies short-
             circuit to the legacy 200 acceptance path that V2M03 covers
             (scope-system-exempt; V2M03 landed before scope auth).
          4. ``ingest:write`` scope check (RELAY-AUTH-014) for v2m02
             full-envelope bodies.
          5. Canonical-write-field rejection (RELAY-ING-031). Runs BEFORE
             the required-fields gate so a body that BOTH sets ``status``
             AND omits a required field produces RELAY-ING-031 (the
             keystone-#1 invariant) rather than RELAY-ING-001.
          6. Required-field body-shape check (RELAY-ING-001).
          7. Defense-in-depth raw_capture rejection (M08 W8).
          8. Tracker-acquire + 201 with ``{run_id, schema_version}``.
        """
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_RUNS_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_RUNS_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        # Body-shape detection: V2M03 manifest-enforcement tests submit
        # the two anchor fields only; preserve the legacy 200 +
        # {accepted=True} response shape for that path so V2M03's contract
        # assertions keep their semantics. Bodies that carry any
        # non-anchor field MUST pass the full v2m02 shape + scope checks.
        non_anchor_keys = set(body) - {
            "manifest_commit_hash",
            "command_hash",
        }
        if not non_anchor_keys:
            # Legacy manifest-only acceptance path (V2M03-012). The scope
            # system did not exist when V2M03 landed; preserving that
            # contract avoids cross-feature regressions while v2m02 owns
            # the full-envelope code path below.
            tracker = runtime.quiesce.tracker
            async with tracker.acquire(description="ingest/runs") as op:
                return JSONResponse(
                    status_code=200,
                    content={
                        "accepted": True,
                        "operation_id": op.operation_id,
                        "endpoint": "/v1/ingest/runs",
                    },
                )
        # ---- v2m02 full-envelope path ----
        scope_reject = _check_required_scope(
            request, required="ingest:write", blocked_surface=_RUNS_SURFACE
        )
        if scope_reject is not None:
            return scope_reject
        invalid_fields = sorted(
            f for f in _CANONICAL_WRITE_FIELDS if f in body
        )
        if invalid_fields:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-031",
                    http_status=422,
                    message=(
                        "SDK attempted to set canonical-write field(s) "
                        f"{invalid_fields!r}; the control plane writes these "
                        "fields exclusively (CLAUDE.md keystone invariant #1, "
                        "spec line 1966)"
                    ),
                    blocked_surface=_RUNS_SURFACE,
                    details={"invalid_fields": invalid_fields},
                ),
            )
        missing_fields = [
            f for f in _REQUIRED_RUN_FIELDS if body.get(f) in (None, "")
        ]
        if missing_fields:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        "relay.ingest.run.v1 envelope missing required "
                        f"field(s): {missing_fields!r}"
                    ),
                    blocked_surface=_RUNS_SURFACE,
                    details={"missing_fields": missing_fields},
                ),
            )
        tracker = runtime.quiesce.tracker
        async with tracker.acquire(description="ingest/runs"):
            return JSONResponse(
                status_code=201,
                content={
                    "run_id": body["run_id"],
                    "schema_version": body["schema_version"],
                },
            )

    _SPANS_BATCH_SURFACE: str = "POST /v1/ingest/spans:batch"
    _CONTRACT_RESULTS_BATCH_SURFACE: str = (
        "POST /v1/ingest/contract-results:batch"
    )

    @app.post("/v1/ingest/spans:batch")
    async def v1_ingest_spans_batch(request: Request) -> JSONResponse:
        """Spans-batch ingest (VAL-V2M02-005..007, VAL-V2M03-012,
        VAL-V2M08-002, 003, 010).

        Order of checks (outer-gate-first layering):

          1. Body-size cap (RELAY-ING-021) BEFORE JSON parse so an
             oversized body cannot exhaust the JSON decoder.
          2. JSON-decode + non-empty-object check (RELAY-ING-001).
          3. Three-anchor manifest enforcement (RELAY-GATE-021).
          4. Body-shape detection: minimal manifest-only bodies short-
             circuit to the legacy 200 acceptance path (V2M03).
          5. ``ingest:write`` scope check (RELAY-AUTH-014) for v2m02
             full-envelope bodies.
          6. M08-W8 per-span size/depth + UTF-8 hardening.
          7. Defense-in-depth raw_capture rejection.
          8. M04 side-effect pairing check.
          9. Tracker-acquire + 202 with ``{accepted_count, batch_id}``.
        """
        raw_or_reject = await _read_body_with_size_cap(
            request, blocked_surface=_SPANS_BATCH_SURFACE
        )
        if isinstance(raw_or_reject, JSONResponse):
            return raw_or_reject
        try:
            body = (
                json.loads(raw_or_reject.decode("utf-8"))
                if raw_or_reject
                else {}
            )
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_SPANS_BATCH_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_SPANS_BATCH_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        # Body-shape detection: V2M03 minimal-anchor bodies preserve the
        # legacy 200 + {accepted=True, endpoint=...} response (scope-system-
        # exempt; mirrors the runs handler).
        non_anchor_keys = set(body) - {
            "manifest_commit_hash",
            "command_hash",
        }
        if not non_anchor_keys:
            tracker = runtime.quiesce.tracker
            async with tracker.acquire(description="ingest/spans:batch") as op:
                return JSONResponse(
                    status_code=200,
                    content={
                        "accepted": True,
                        "operation_id": op.operation_id,
                        "endpoint": "/v1/ingest/spans:batch",
                    },
                )
        # ---- v2m02 full-envelope path ----
        scope_reject = _check_required_scope(
            request,
            required="ingest:write",
            blocked_surface=_SPANS_BATCH_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        # M08-W8 hardening: per-span size + nesting + indexed-UTF-8
        # checks (VAL-V2M08-002, 003, 010). The body's "spans" array
        # may be absent (legacy submission shape) or empty -- both
        # accepted; only declared spans are validated.
        spans = body.get("spans")
        accepted_count: int = 0
        if isinstance(spans, list):
            for span in spans:
                if not isinstance(span, dict):
                    continue
                size_or_depth = validate_span_size_and_depth(span)
                if size_or_depth is not None:
                    return JSONResponse(
                        status_code=size_or_depth["http_status"],
                        content=size_or_depth,
                    )
                attrs = span.get("attributes")
                if isinstance(attrs, dict):
                    utf8_reject = validate_indexed_utf8(attrs)
                    if utf8_reject is not None:
                        return JSONResponse(
                            status_code=utf8_reject["http_status"],
                            content=utf8_reject,
                        )
            # M08-W8 server-side raw_capture rejection (VAL-V2M08-029/030/031).
            # Spec G.1 lines 4108-4114; CLAUDE.md keystone invariant #7.
            raw_rejection = evaluate_raw_capture_on_request(body=body)
            if raw_rejection is not None:
                return JSONResponse(
                    status_code=raw_rejection.http_status,
                    content=raw_rejection.as_envelope(),
                )
            # M04 w4-side-effects (VAL-V2M04-011..015, -035): paired-row
            # check for spans whose side_effect_class != 'read_only'.
            side_reject = await _enforce_side_effect_pairing(
                spans=spans,
                database=runtime.database,
            )
            if side_reject is not None:
                return JSONResponse(
                    status_code=422,
                    content={
                        "code": side_reject.code,
                        "error_class": side_reject.code,
                        "message": side_reject.message,
                        "details": side_reject.details,
                    },
                )
            accepted_count = sum(1 for s in spans if isinstance(s, dict))
        tracker = runtime.quiesce.tracker
        async with tracker.acquire(description="ingest/spans:batch") as op:
            return JSONResponse(
                status_code=202,
                content={
                    "accepted_count": accepted_count,
                    "batch_id": op.operation_id,
                },
            )

    @app.post("/v1/ingest/contract-results:batch")
    async def v1_ingest_contract_results_batch(
        request: Request,
    ) -> JSONResponse:
        """Contract-results batch ingest (VAL-V2M02-008, VAL-V2M02-009).

        Order of checks:

          1. Body-size cap (RELAY-ING-021) BEFORE JSON parse.
          2. JSON-decode + non-empty-object check (RELAY-ING-001).
          3. Three-anchor manifest enforcement (RELAY-GATE-021).
          4. ``ingest:write`` scope check (RELAY-AUTH-014).
          5. Validate ``contract_results`` is a list.
          6. Tracker-acquire + 202 with ``{accepted_count, batch_id}``.

        Persistence to the ``contract_results`` table (migration 0012,
        VAL-V2M01-002) lands in a follow-up feature; this surface owns
        the wire contract and the rejection envelope shape.
        """
        raw_or_reject = await _read_body_with_size_cap(
            request, blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE
        )
        if isinstance(raw_or_reject, JSONResponse):
            return raw_or_reject
        try:
            body = (
                json.loads(raw_or_reject.decode("utf-8"))
                if raw_or_reject
                else {}
            )
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        scope_reject = _check_required_scope(
            request,
            required="ingest:write",
            blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        contract_results = body.get("contract_results")
        if not isinstance(contract_results, list):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        "request body must include a 'contract_results' "
                        "array (may be empty)"
                    ),
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        accepted_count = sum(
            1 for r in contract_results if isinstance(r, dict)
        )
        tracker = runtime.quiesce.tracker
        async with tracker.acquire(
            description="ingest/contract-results:batch"
        ) as op:
            return JSONResponse(
                status_code=202,
                content={
                    "accepted_count": accepted_count,
                    "batch_id": op.operation_id,
                },
            )

    # ----------------------------------------------------------------------
    # V2M02 w2.2 read endpoints (VAL-V2M02-010..020).
    #
    # All five run-namespace read endpoints. Source of truth is the
    # local SQLite ``run_results`` / ``spans`` / ``root_cause_hypotheses``
    # tables seeded by writers in later milestones; for M02 the routes
    # query whatever rows exist and return canonical envelopes per spec
    # B.6 lines 3452-3456. Every handler enforces ``runs:read`` via
    # ``_check_required_scope`` per spec B.1 line 3363.
    # ----------------------------------------------------------------------

    # Cursor signing: opaque server-signed pagination tokens per spec B.3
    # lines 3381-3390. The key is per-process so two sidecars cannot
    # accept each other's cursors (defense-in-depth; the OSS profile
    # is single-process by design).
    _cursor_signing_key: bytes = hashlib.sha256(
        f"{runtime.sqlite_path}:{uuid.uuid4()}".encode()
    ).digest()

    def _sign_cursor(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        sig = hmac.new(_cursor_signing_key, raw, hashlib.sha256).digest()[:16]
        token_bytes = base64.urlsafe_b64encode(sig + raw)
        return token_bytes.decode("ascii").rstrip("=")

    def _verify_cursor(token: str) -> dict[str, Any] | None:
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:  # noqa: BLE001
            return None
        if len(decoded) < 16:
            return None
        sig, raw = decoded[:16], decoded[16:]
        expected = hmac.new(
            _cursor_signing_key, raw, hashlib.sha256
        ).digest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None

    _RUN_LIST_SURFACE: str = "GET /v1/projects/{project_id}/runs"
    _RUN_DETAIL_SURFACE: str = "GET /v1/runs/{run_id}"
    _RUN_TRACE_SURFACE: str = "GET /v1/runs/{run_id}/trace"
    _RUN_RESULT_SURFACE: str = "GET /v1/runs/{run_id}/result"
    _RUN_EXPLAIN_SURFACE: str = "GET /v1/runs/{run_id}/explain"

    def _not_found(*, surface: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content=_build_error_envelope(
                code="RELAY-NOT-FOUND",
                http_status=404,
                message=message,
                blocked_surface=surface,
            ),
        )

    @app.get("/v1/projects/{project_id}/runs")
    async def v1_list_project_runs(
        project_id: str,
        request: Request,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JSONResponse:
        """List runs for a project with cursor pagination (VAL-V2M02-010,
        VAL-V2M02-011, VAL-V2M02-012).

        Pagination per spec B.3 lines 3381-3390:
          - ``limit`` defaults to 100, max 500.
          - ``next_cursor`` is opaque + HMAC-signed.
          - ``has_more`` is True iff a subsequent page exists.
        Sort order is ``(decided_at DESC, run_id ASC)`` for stable paging.
        """
        scope_reject = _check_required_scope(
            request, required="runs:read", blocked_surface=_RUN_LIST_SURFACE
        )
        if scope_reject is not None:
            return scope_reject
        effective_limit = max(1, min(int(limit), 500))
        offset = 0
        if cursor is not None:
            decoded = _verify_cursor(cursor)
            if decoded is None or decoded.get("project_id") != project_id:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-001",
                        http_status=400,
                        message="cursor is invalid or expired",
                        blocked_surface=_RUN_LIST_SURFACE,
                    ),
                )
            offset = int(decoded.get("offset", 0))

        db = runtime.database
        if db is None:
            return JSONResponse(
                status_code=503,
                content=_build_error_envelope(
                    code="RELAY-SIDECAR-007",
                    http_status=503,
                    message="sidecar database not yet available",
                    blocked_surface=_RUN_LIST_SURFACE,
                ),
            )
        reader = db.acquire_reader()
        # Over-fetch by one to detect ``has_more``.
        async with reader.execute(
            "SELECT run_id, project_id, schema_version, status, "
            "manifest_commit_hash, actor_identity_hash, decided_at "
            "FROM run_results WHERE project_id = ? "
            "ORDER BY decided_at DESC, run_id ASC LIMIT ? OFFSET ?",
            (project_id, effective_limit + 1, offset),
        ) as cur:
            rows = await cur.fetchall()
        has_more = len(rows) > effective_limit
        page_rows = rows[:effective_limit]
        items = [
            {
                "run_id": r[0],
                "project_id": r[1],
                "schema_version": r[2],
                "status": r[3],
                "manifest_commit_hash": r[4],
                "actor_identity_hash": r[5],
                "decided_at": r[6],
            }
            for r in page_rows
        ]
        next_cursor: str | None = None
        if has_more:
            next_cursor = _sign_cursor(
                {"project_id": project_id, "offset": offset + effective_limit}
            )
        return JSONResponse(
            status_code=200,
            content={
                "items": items,
                "next_cursor": next_cursor,
                "has_more": has_more,
            },
        )

    @app.get("/v1/runs/{run_id}")
    async def v1_get_run(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Run detail (VAL-V2M02-013, VAL-V2M02-014).

        Returns the canonical ``relay.run.v1`` envelope. The local sidecar
        synthesizes the envelope from the ``run_results`` row plus the
        manifest/actor anchors; the hosted control plane projects this
        from the runs table directly.
        """
        scope_reject = _check_required_scope(
            request, required="runs:read", blocked_surface=_RUN_DETAIL_SURFACE
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_DETAIL_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT run_id, project_id, status, manifest_commit_hash, "
            "actor_identity_hash, decided_at FROM run_results "
            "WHERE run_id = ?",
            (run_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_RUN_DETAIL_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        return JSONResponse(
            status_code=200,
            content={
                "schema_version": "relay.run.v1",
                "run_id": row[0],
                "project_id": row[1],
                "status": row[2],
                "started_at": row[5],
                "ended_at": row[5],
                "manifest_commit_hash": row[3],
                "actor_identity_hash": row[4],
            },
        )

    @app.get("/v1/runs/{run_id}/trace")
    async def v1_get_run_trace(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Run trace (VAL-V2M02-015, VAL-V2M02-016).

        Returns spans ordered by ``started_at`` with parent_span_id
        references intact. Unknown run_id (no row in run_results) is 404.
        """
        scope_reject = _check_required_scope(
            request, required="runs:read", blocked_surface=_RUN_TRACE_SURFACE
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_TRACE_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (run_id,)
        ) as cur:
            run_row = await cur.fetchone()
        if run_row is None:
            return _not_found(
                surface=_RUN_TRACE_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        async with reader.execute(
            "SELECT span_id, parent_span_id, span_type, name, status, "
            "started_at, ended_at, error_class FROM spans "
            "WHERE run_id = ? ORDER BY started_at ASC, span_id ASC",
            (run_id,),
        ) as cur:
            span_rows = await cur.fetchall()
        spans = [
            {
                "span_id": r[0],
                "parent_span_id": r[1],
                "span_type": r[2],
                "name": r[3],
                "status": r[4],
                "started_at": r[5],
                "ended_at": r[6],
                "error_class": r[7],
            }
            for r in span_rows
        ]
        return JSONResponse(
            status_code=200,
            content={
                "schema_version": "relay.trace.v1",
                "run_id": run_id,
                "spans": spans,
            },
        )

    @app.get("/v1/runs/{run_id}/result")
    async def v1_get_run_result(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Canonical RunResult (VAL-V2M02-017, VAL-V2M02-018).

        Returns the ``run_results`` row including ``written_by``. The
        control-plane invariant (#1) is enforced at the SQL layer via the
        ``written_by_control_plane`` CHECK constraint on the table; this
        handler is read-only.
        """
        scope_reject = _check_required_scope(
            request, required="runs:read", blocked_surface=_RUN_RESULT_SURFACE
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_RESULT_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT run_result_id, run_id, project_id, schema_version, "
            "written_by, status, primary_failure_class, error_priority_rule, "
            "evidence_bundle_id, manifest_commit_hash, actor_identity_hash, "
            "decided_at, decision_epoch, signature, signature_key_id "
            "FROM run_results WHERE run_id = ?",
            (run_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_RUN_RESULT_SURFACE,
                message=f"run_result for run_id {run_id!r} not found",
            )
        return JSONResponse(
            status_code=200,
            content={
                "run_result_id": row[0],
                "run_id": row[1],
                "project_id": row[2],
                "schema_version": row[3],
                "written_by": row[4],
                "status": row[5],
                "primary_failure_class": row[6],
                "error_priority_rule": row[7],
                "evidence_bundle_id": row[8],
                "manifest_commit_hash": row[9],
                "actor_identity_hash": row[10],
                "decided_at": row[11],
                "decision_epoch": row[12],
                "signature": row[13],
                "signature_key_id": row[14],
            },
        )

    @app.get("/v1/runs/{run_id}/explain")
    async def v1_get_run_explain(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Root cause hypotheses (VAL-V2M02-019, VAL-V2M02-020).

        The generator implementation lands in M05; M02 ships the route
        serving whatever rows M05 produces. Returns an empty list for
        runs with no hypotheses (NOT 404 -- the spec is explicit on
        this), 404 only if the run itself is unknown.
        """
        scope_reject = _check_required_scope(
            request,
            required="runs:read",
            blocked_surface=_RUN_EXPLAIN_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_EXPLAIN_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (run_id,)
        ) as cur:
            run_row = await cur.fetchone()
        if run_row is None:
            return _not_found(
                surface=_RUN_EXPLAIN_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        async with reader.execute(
            "SELECT hypothesis_id, run_id, span_id, hypothesis_class, "
            "confidence, evidence_refs, evidence_refs_digest, generator, "
            "created_at FROM root_cause_hypotheses "
            "WHERE run_id = ? ORDER BY created_at ASC, hypothesis_id ASC",
            (run_id,),
        ) as cur:
            rows = await cur.fetchall()
        hypotheses = [
            {
                "schema_version": "relay.root_cause_hypothesis.v1",
                "hypothesis_id": r[0],
                "run_id": r[1],
                "span_id": r[2],
                "hypothesis_class": r[3],
                "confidence": r[4],
                "evidence_refs": json.loads(r[5]) if r[5] else [],
                "evidence_refs_digest": r[6],
                "generator": r[7],
                "created_at": r[8],
            }
            for r in rows
        ]
        return JSONResponse(
            status_code=200, content={"run_id": run_id, "hypotheses": hypotheses}
        )

    # ----------------------------------------------------------------------
    # V2M02 w2.3 replay endpoints (VAL-V2M02-021..030).
    #
    # The hosted writers for replay_cases / replay_fixtures / replay_results
    # do not exist in the OSS sidecar at M02; the canonical SQLite tables
    # for these objects land in later milestones. The HTTP surface lands
    # now so SDKs + CLI have stable endpoints. Each handler round-trips
    # canonical response shapes via in-memory registries on RuntimeState.
    # ``written_by = "control_plane"`` is stamped on every persisted
    # envelope per keystone invariant #1.
    # ----------------------------------------------------------------------

    _REPLAY_CREATE_SURFACE: str = "POST /v1/replay-cases"
    _REPLAY_GET_SURFACE: str = "GET /v1/replay-cases/{case_id}"
    _REPLAY_FIXTURES_SURFACE: str = "POST /v1/replay-cases/{case_id}/fixtures"
    _REPLAY_RUN_SURFACE: str = "POST /v1/replay-cases/{case_id}/run"
    _REPLAY_RESULT_SURFACE: str = "GET /v1/replay-results/{result_id}"

    @app.post("/v1/replay-cases")
    async def v1_create_replay_case(request: Request) -> JSONResponse:
        """Create a replay case from a failed run (VAL-V2M02-021,
        VAL-V2M02-022). Returns 201 + ``{case_id}``; unknown
        ``from_run_id`` returns 404.
        """
        scope_reject = _check_required_scope(
            request,
            required="replay:write",
            blocked_surface=_REPLAY_CREATE_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_CREATE_SURFACE,
                ),
            )
        from_run_id = body.get("from_run_id")
        if not isinstance(from_run_id, str) or not from_run_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="from_run_id MUST be a non-empty string",
                    blocked_surface=_REPLAY_CREATE_SURFACE,
                ),
            )
        # Verify the source run exists.
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_REPLAY_CREATE_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (from_run_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_REPLAY_CREATE_SURFACE,
                message=f"from_run_id {from_run_id!r} not found",
            )
        case_id = f"case-{uuid.uuid4().hex}"
        created_at = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
        case = {
            "schema_version": "relay.replay_case.v1",
            "case_id": case_id,
            "from_run_id": from_run_id,
            "scope_name": body.get("scope_name"),
            "written_by": "control_plane",
            "created_at": created_at,
        }
        runtime.replay_cases[case_id] = case
        runtime.replay_fixtures.setdefault(case_id, [])
        return JSONResponse(
            status_code=201,
            content={"case_id": case_id, "schema_version": "relay.replay_case.v1"},
        )

    @app.get("/v1/replay-cases/{case_id}")
    async def v1_get_replay_case(
        case_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_required_scope(
            request,
            required="runs:read",
            blocked_surface=_REPLAY_GET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        case = runtime.replay_cases.get(case_id)
        if case is None:
            return _not_found(
                surface=_REPLAY_GET_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        fixtures = runtime.replay_fixtures.get(case_id, [])
        return JSONResponse(
            status_code=200,
            content={**case, "fixtures_count": len(fixtures)},
        )

    @app.post("/v1/replay-cases/{case_id}/fixtures")
    async def v1_post_replay_fixture(
        case_id: str, request: Request
    ) -> JSONResponse:
        """Upload a fixture for a replay case (VAL-V2M02-025,
        VAL-V2M02-026). Persistence path mirrors the spec
        ``object_put_with_digest`` primitive: the digest returned is the
        sha256 of the canonical JSON payload.
        """
        scope_reject = _check_required_scope(
            request,
            required="replay:write",
            blocked_surface=_REPLAY_FIXTURES_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_FIXTURES_SURFACE,
                ),
            )
        if case_id not in runtime.replay_cases:
            return _not_found(
                surface=_REPLAY_FIXTURES_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        canonical = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        fixture_id = f"fix-{uuid.uuid4().hex}"
        record = {
            "fixture_id": fixture_id,
            "case_id": case_id,
            "fixture_kind": body.get("fixture_kind"),
            "digest": digest,
            "payload": body,
            "written_by": "control_plane",
        }
        runtime.replay_fixtures.setdefault(case_id, []).append(record)
        return JSONResponse(
            status_code=201,
            content={"fixture_id": fixture_id, "digest": digest},
        )

    @app.post("/v1/replay-cases/{case_id}/run")
    async def v1_post_replay_run(
        case_id: str, request: Request
    ) -> JSONResponse:
        """Execute a reproduction (VAL-V2M02-027, VAL-V2M02-028).

        Mode defaults to ``cassette`` per keystone invariant #9
        (cassette-first replay). Live mode against ``mutating`` or
        ``external_irreversible`` tools is refused with
        ``RELAY-REPLAY-014`` per spec B.4 line 3428.
        """
        scope_reject = _check_required_scope(
            request,
            required="replay:write",
            blocked_surface=_REPLAY_RUN_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        if case_id not in runtime.replay_cases:
            return _not_found(
                surface=_REPLAY_RUN_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        mode = body.get("mode", "cassette")
        if mode not in ("cassette", "live"):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=f"mode must be 'cassette' or 'live'; got {mode!r}",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        if mode == "live":
            side_effect = body.get("side_effect_class")
            if side_effect in ("mutating", "external_irreversible"):
                return JSONResponse(
                    status_code=422,
                    content=_build_error_envelope(
                        code="RELAY-REPLAY-014",
                        http_status=422,
                        message=(
                            "live replay against side_effect_class "
                            f"{side_effect!r} is refused; cassette mode is "
                            "the default (keystone invariant #9)"
                        ),
                        blocked_surface=_REPLAY_RUN_SURFACE,
                        details={"side_effect_class": side_effect},
                    ),
                )
        manifest_hash = body.get("manifest_commit_hash")
        if not isinstance(manifest_hash, str) or not manifest_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="manifest_commit_hash MUST be a non-empty string",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        result_id = f"rr-{uuid.uuid4().hex}"
        await_url = f"/v1/replay-results/{result_id}"
        result_record = {
            "schema_version": "relay.replay_result.v1",
            "replay_result_id": result_id,
            "case_id": case_id,
            "replay_mode": mode,
            "manifest_commit_hash": manifest_hash,
            "digest_ok": True,
            "outcome": "pending",
            "evidence": {"bundle_id": None, "claims": []},
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.replay_results[result_id] = result_record
        return JSONResponse(
            status_code=202,
            content={"replay_result_id": result_id, "await_url": await_url},
        )

    @app.get("/v1/replay-results/{result_id}")
    async def v1_get_replay_result(
        result_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_required_scope(
            request,
            required="runs:read",
            blocked_surface=_REPLAY_RESULT_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        record = runtime.replay_results.get(result_id)
        if record is None:
            return _not_found(
                surface=_REPLAY_RESULT_SURFACE,
                message=f"replay_result {result_id!r} not found",
            )
        return JSONResponse(status_code=200, content=record)

    # ----------------------------------------------------------------------
    # V2M02 w2.4 eval endpoints (VAL-V2M02-031..036).
    #
    # The hosted writers for eval_datasets / eval_runs land in later
    # milestones; the route surface lands now so SDKs have stable
    # endpoints. Same in-memory pattern as replay; written_by is
    # always "control_plane".
    # ----------------------------------------------------------------------

    _EVAL_DATASET_SURFACE: str = "POST /v1/eval-datasets"
    _EVAL_RUN_CREATE_SURFACE: str = "POST /v1/eval-runs"
    _EVAL_RUN_GET_SURFACE: str = "GET /v1/eval-runs/{eval_run_id}"

    @app.post("/v1/eval-datasets")
    async def v1_create_eval_dataset(request: Request) -> JSONResponse:
        scope_reject = _check_required_scope(
            request,
            required="replay:write",
            blocked_surface=_EVAL_DATASET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        name = body.get("name")
        if not isinstance(name, str) or not name:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="name MUST be a non-empty string",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        fixtures = body.get("fixtures", [])
        if not isinstance(fixtures, list):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="fixtures MUST be an array (may be empty)",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        dataset_id = f"ds-{uuid.uuid4().hex}"
        record = {
            "schema_version": "relay.eval_dataset.v1",
            "dataset_id": dataset_id,
            "name": name,
            "description": body.get("description"),
            "fixtures": fixtures,
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.eval_datasets[dataset_id] = record
        return JSONResponse(
            status_code=201,
            content={
                "dataset_id": dataset_id,
                "schema_version": "relay.eval_dataset.v1",
            },
        )

    @app.post("/v1/eval-runs")
    async def v1_create_eval_run(request: Request) -> JSONResponse:
        scope_reject = _check_required_scope(
            request,
            required="replay:write",
            blocked_surface=_EVAL_RUN_CREATE_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        dataset_id = body.get("dataset_id")
        if not isinstance(dataset_id, str) or not dataset_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="dataset_id MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        if dataset_id not in runtime.eval_datasets:
            return _not_found(
                surface=_EVAL_RUN_CREATE_SURFACE,
                message=f"dataset_id {dataset_id!r} not found",
            )
        contract_id = body.get("contract_id")
        manifest_hash = body.get("manifest_commit_hash")
        if not isinstance(contract_id, str) or not contract_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="contract_id MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        if not isinstance(manifest_hash, str) or not manifest_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="manifest_commit_hash MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        eval_run_id = f"er-{uuid.uuid4().hex}"
        await_url = f"/v1/eval-runs/{eval_run_id}"
        record = {
            "schema_version": "relay.eval_run.v1",
            "eval_run_id": eval_run_id,
            "dataset_id": dataset_id,
            "contract_id": contract_id,
            "manifest_commit_hash": manifest_hash,
            "status": "queued",
            "metrics": {},
            "evidence": {"bundle_id": None, "claims": []},
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.eval_runs[eval_run_id] = record
        return JSONResponse(
            status_code=202,
            content={"eval_run_id": eval_run_id, "await_url": await_url},
        )

    @app.get("/v1/eval-runs/{eval_run_id}")
    async def v1_get_eval_run(
        eval_run_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_required_scope(
            request,
            required="runs:read",
            blocked_surface=_EVAL_RUN_GET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        record = runtime.eval_runs.get(eval_run_id)
        if record is None:
            return _not_found(
                surface=_EVAL_RUN_GET_SURFACE,
                message=f"eval_run {eval_run_id!r} not found",
            )
        return JSONResponse(status_code=200, content=record)

    @app.get("/diagnostics/quiesce")
    async def diagnostics_quiesce() -> dict[str, Any]:
        """Return current quiesce state: in-flight count, idle event,
        force-stop flag, idle-shutdown trigger.

        Used by the W2.6 tests (VAL-W2-043, VAL-W2-046, VAL-W2-048) to
        observe the tracker without poking private attributes.
        """
        tracker = runtime.quiesce.tracker
        return {
            "in_flight_count": tracker.in_flight_count if tracker else 0,
            "in_flight_descriptions": (
                tracker.in_flight_descriptions() if tracker else []
            ),
            "total_acquires": tracker.total_acquires if tracker else 0,
            "idle_event_set": (
                tracker.idle_event.is_set() if tracker else True
            ),
            "force_stop_requested": runtime.quiesce.force_stop_requested,
            "force_stop_reason": runtime.quiesce.force_stop_reason,
            "idle_shutdown_triggered": runtime.quiesce.idle_shutdown_triggered,
            "idle_timeout_seconds": runtime.idle_timeout_seconds,
            "drain_deadline_seconds": runtime.drain_deadline_seconds,
            "lockfile_path": (
                str(runtime.lockfile_path)
                if runtime.lockfile_path is not None
                else None
            ),
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
    relay_home_override: Path | None = None,
) -> None:  # pragma: no cover (exercised by subprocess tests, not in-process)
    """Run the sidecar under uvicorn.

    Used by W5's CLI entrypoint and by the W2.7 subprocess tests (which
    spawn this via ``subprocess.Popen`` so SIGTERM + structured exit
    codes are real).

    Startup contract (W2.7 wiring; STR-001 fix):
      - Resolve the same ``sqlite_path`` the lifespan would resolve.
      - Synchronously invoke :func:`recover_or_refuse` BEFORE constructing
        the FastAPI app or entering the asyncio loop. On corruption,
        schema-version mismatch, or WAL-replay failure, recovery calls
        :func:`exit_with_structured_error` which writes the JSON envelope
        to stderr and ``sys.exit``s with the appropriate code (3, 5, or
        6). Doing this OUTSIDE the asyncio loop is critical: a SystemExit
        raised inside a uvicorn lifespan coroutine is caught and the
        custom exit code is lost; raising here causes the Python
        interpreter to honour the code verbatim. The lifespan still
        re-invokes recovery defensively for in-process callers of
        :func:`build_runtime_app`.

    Args:
        health: HealthState for the bearer/nonce surface.
        host: Bind host. Defaults to 127.0.0.1 (loopback-only; never 0.0.0.0).
        port: Bind port. 0 means ephemeral.
        sqlite_path: SQLite DB path override.
        relay_home_override: Override ``${RELAY_HOME}`` discovery; passed
            through to :func:`build_runtime_app` so tests can run a real
            sidecar subprocess against a tmpdir.
    """
    import uvicorn

    # Resolve the effective SQLite path with the SAME fall-through that
    # ``build_runtime_app`` applies, so the pre-launch recovery probe and
    # the lifespan-startup recovery probe inspect the same file.
    base_home = (
        relay_home_override
        if relay_home_override is not None
        else relay_home()
    )
    effective_db_path = (
        sqlite_path if sqlite_path is not None else base_home / SIDECAR_DB_FILENAME
    )
    # STR-001 fix: probe BEFORE entering asyncio. Recovery sys.exit on
    # corruption / schema mismatch propagates the exit code unmolested.
    recover_or_refuse(effective_db_path)

    app = build_runtime_app(
        health=health,
        sqlite_path=sqlite_path,
        relay_home_override=relay_home_override,
    )
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
