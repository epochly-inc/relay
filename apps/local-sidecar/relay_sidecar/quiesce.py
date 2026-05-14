"""W2.6 in-flight tracker + idle countdown helpers (quiesce protocol).

Per CLAUDE.md keystone invariant #5 (gate restart on failure) + spec
eng plan A1 + X1 (quiesce protocol) + spec H.5 edge cases:

The local sidecar is a long-lived daemon. To shut down cleanly we must
distinguish "idle" (no work in flight, safe to exit after the configured
idle timeout) from "in flight" (a long-running operation must complete
before the sidecar tears down its writer connection, releases the SQLite
WAL, and clears the lockfile).

The :class:`InflightTracker` exposes two surfaces:

  - ``acquire(operation_id, description)`` -- async context manager that
    increments the in-flight counter on entry and decrements on exit.
    While the counter is > 0, the ``idle_event`` is *cleared*.
    When the counter falls back to 0, ``idle_event`` is *set*.

  - ``idle_event`` -- :class:`asyncio.Event` set IFF the in-flight
    counter is 0. The lifespan idle-countdown task awaits this event
    with a wall-clock timeout: when the timeout expires while the event
    is still set (i.e. the sidecar has been continuously idle for the
    full window), the lifespan signals graceful shutdown.

Per VAL-W2-043 the idle timer MUST NOT fire while a long-running
operation is in flight: the asyncio.wait_for(idle_event.wait(), ...)
schedule starts the moment we observe ``idle_event`` is set. If a
caller acquires the tracker mid-window the event is cleared, and the
NEXT idle window begins fresh once the last operation completes
(VAL-W2-048).

Per VAL-W2-046 the force-stop path is observable: the sidecar's
SIGUSR1 handler emits one ``sidecar.forced_stop`` row to
``event_log_entries`` BEFORE rolling back any in-flight transaction.
The ``request_force_stop`` helper records the trigger and sets the
``force_stop_event`` so the lifespan tear-down branch knows to skip the
graceful WAL checkpoint and lockfile clear (force-stop deliberately
LEAVES the lockfile in place so the next ``acquire_or_attach`` call
classifies it as STALE_PID and clears it via the spawn path).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

# Default idle timeout (seconds). Production default is 60s per spec eng plan
# A1 + the .ops/manifest.yaml service.local-sidecar.quiesce_timeout_ms (30s
# DRAIN window + 30s idle). Tests override via the constructor or the
# ``RELAY_SIDECAR_IDLE_TIMEOUT_S`` env var.
DEFAULT_IDLE_TIMEOUT_S: float = 60.0

# Env var name. Read once at lifespan startup; nameconforms to the existing
# ``RELAY_SIDECAR_*`` namespace.
IDLE_TIMEOUT_ENV: str = "RELAY_SIDECAR_IDLE_TIMEOUT_S"

# Force-stop signal. SIGUSR1 is the conventional "user-defined" POSIX signal
# and is NOT one of the signals uvicorn captures by default. The sidecar
# installs an asyncio loop signal handler for SIGUSR1 in the lifespan
# startup; the handler triggers the force-stop path.
#
# Windows lacks SIGUSR1; on Windows the force-stop helper falls back to
# SIGTERM which traverses the same code path as graceful drain (force-stop
# semantics on Windows degrade to graceful drain; this is documented in the
# CLI surface and acceptable for v0.1 OSS since the primary Windows path is
# the local-sidecar developer flow rather than a long-lived daemon).
def force_stop_signal_number() -> int:
    """Return the platform-native force-stop signal number.

    POSIX: ``signal.SIGUSR1``.
    Windows: ``signal.SIGTERM`` (degrades to graceful drain since
    SIGUSR1 is unavailable; acceptable for v0.1 OSS per the Windows
    documentation note in the docstring above).
    """
    import signal as _signal

    return getattr(_signal, "SIGUSR1", _signal.SIGTERM)


def resolve_idle_timeout_seconds(default: float = DEFAULT_IDLE_TIMEOUT_S) -> float:
    """Resolve the idle timeout from ``RELAY_SIDECAR_IDLE_TIMEOUT_S``.

    Returns ``default`` when the env var is unset or empty. Raises
    ``ValueError`` on a non-numeric or non-positive override (silent
    fallback would mask configuration bugs).
    """
    raw = os.environ.get(IDLE_TIMEOUT_ENV, "").strip()
    if not raw:
        return float(default)
    parsed = float(raw)
    if parsed <= 0.0:
        raise ValueError(
            f"{IDLE_TIMEOUT_ENV} must be a positive float; got {raw!r}"
        )
    return parsed


@dataclass
class InflightOperation:
    """Metadata describing one in-flight operation.

    Stored inside :class:`InflightTracker` for diagnostic surfacing.
    Tests use the description to assert which operation kept the idle
    timer from firing.
    """

    operation_id: str
    description: str


class InflightTracker:
    """Counter-backed asyncio.Event signalling sidecar idleness.

    Lifecycle:

      - Construct one tracker per :class:`runtime.RuntimeState`.
      - Long-running operations (ingest, gate evaluate, replay session,
        background flush) call ``async with tracker.acquire(...)`` to
        register themselves. The event is cleared on the first acquire
        and re-set on the last release.
      - The lifespan idle-countdown task awaits ``idle_event.wait()``
        with a wall-clock timeout. When the timeout fires while the
        event is still set the task triggers graceful shutdown.

    Thread safety: pure asyncio. Single event loop per sidecar process;
    there is no cross-thread access. Acquire/release ordering is
    serialised by the GIL plus asyncio's cooperative scheduling.
    """

    def __init__(self) -> None:
        self._count: int = 0
        # Event semantics: set IFF in_flight_count == 0. The asyncio.Event
        # starts SET because the sidecar starts idle (no operations yet).
        self._idle_event: asyncio.Event = asyncio.Event()
        self._idle_event.set()
        # Diagnostic registry of currently in-flight operations.
        self._operations: dict[str, InflightOperation] = {}
        # Counter of total acquires observed across the process lifetime.
        # Used by VAL-W2-048 to assert "after N completions, the idle
        # countdown observed N transitions back to idle".
        self._total_acquires: int = 0

    @property
    def in_flight_count(self) -> int:
        """Return the current count of registered in-flight operations."""
        return self._count

    @property
    def idle_event(self) -> asyncio.Event:
        """Return the asyncio.Event set IFF in_flight_count == 0."""
        return self._idle_event

    @property
    def total_acquires(self) -> int:
        """Return the lifetime count of acquire() calls."""
        return self._total_acquires

    def in_flight_descriptions(self) -> list[str]:
        """Return descriptions of currently in-flight operations (snapshot)."""
        return [op.description for op in self._operations.values()]

    @contextlib.asynccontextmanager
    async def acquire(
        self,
        *,
        description: str,
        operation_id: str | None = None,
    ) -> AsyncIterator[InflightOperation]:
        """Register an in-flight operation for the lifetime of the block.

        Args:
            description: Human-readable label for the operation
                (e.g. ``"ingest:run_id=...."``). Used in diagnostics.
            operation_id: Optional pre-allocated id. Auto-generated as a
                UUID4 string when not supplied.

        Yields:
            InflightOperation carrying the resolved id + description.
        """
        op_id = operation_id if operation_id is not None else str(uuid.uuid4())
        op = InflightOperation(operation_id=op_id, description=description)
        self._count += 1
        self._total_acquires += 1
        self._operations[op_id] = op
        # Clear the idle event the moment any operation is in-flight.
        self._idle_event.clear()
        try:
            yield op
        finally:
            self._operations.pop(op_id, None)
            self._count -= 1
            if self._count <= 0:
                # Defensive clamp: should not go negative under correct
                # acquire/release pairing but guards against double-release
                # bugs from poorly-written callers.
                self._count = 0
                self._idle_event.set()


@dataclass
class QuiesceState:
    """Lifecycle flags surfaced by the quiesce protocol.

    Attached to :class:`runtime.RuntimeState` so the lifespan, drain
    middleware, signal handlers, and force-stop path share one source
    of truth. Mutating these fields outside the runtime/lifespan path
    is a programmer error.
    """

    # Set by the SIGUSR1 handler when force-stop is requested. The lifespan
    # tear-down inspects this AFTER drain and BEFORE the WAL checkpoint;
    # when set, the lifespan SKIPS the graceful WAL checkpoint and lockfile
    # clear so the next ``acquire_or_attach`` observes a STALE_PID lockfile
    # and the spawn path clears it (matches spec H.5 force-stop semantics).
    force_stop_requested: bool = False
    # Reason recorded on the ``sidecar.forced_stop`` event_log row.
    force_stop_reason: str = ""
    # When the idle-countdown task triggers shutdown, it sets this so the
    # lifespan tear-down knows the trigger was "idle" rather than "external
    # SIGTERM" or "force-stop". Used for diagnostics + the
    # ``sidecar.idle_shutdown`` event_log row emitted in lifespan.
    idle_shutdown_triggered: bool = False
    # W2.7 VAL-W2-053: True when the lifespan tear-down's
    # ``PRAGMA wal_checkpoint(TRUNCATE)`` failed (e.g., a reader held an
    # old snapshot beyond the timeout). The lifespan emits the
    # ``RELAY-SIDECAR-WAL-CHECKPOINT-FAILED`` envelope to stderr +
    # signals exit code 6 when running under uvicorn; in-process tests
    # observe this flag.
    wal_checkpoint_failed: bool = False
    # Optional message from the failed checkpoint (PRAGMA returned
    # busy=1 OR raised an exception). Empty when checkpoint succeeded.
    wal_checkpoint_failure_reason: str = ""
    # Reference to the in-flight tracker. Populated in lifespan startup.
    tracker: InflightTracker | None = field(default=None)


__all__ = [
    "DEFAULT_IDLE_TIMEOUT_S",
    "IDLE_TIMEOUT_ENV",
    "InflightOperation",
    "InflightTracker",
    "QuiesceState",
    "force_stop_signal_number",
    "resolve_idle_timeout_seconds",
]
