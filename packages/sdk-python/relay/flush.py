"""Flush policy + async dispatcher for the Relay Python SDK (W3.2).

The Relay SDK MUST be safe to call in production: a slow or unreachable
sidecar must never block the calling thread (VAL-W3-018) or crash the
host application (VAL-W3-019). This module owns:

  * :class:`FlushPolicy` -- the user-facing dataclass with two knobs:
      ``mode``     -- ``sync`` or ``async``.
      ``on_error`` -- ``raise`` or ``drop_and_log``.
  * :class:`AsyncFlushDispatcher` -- a single-threaded background worker
    that serializes outbound HTTP requests when ``mode='async'`` so the
    caller's ``trace.__exit__`` returns immediately.

Per VAL-W3-018 the dispatcher does NOT use any wall-clock threshold. The
test contract is a synchronization marker: ``__exit__`` returns BEFORE
the slow sidecar handler has even ``accept()``-ed the inbound socket.
This is achieved by enqueueing the call onto a ``queue.Queue`` and
returning -- the dispatcher's worker thread pulls the call and runs it
asynchronously.

Per VAL-W3-019 the dispatcher under ``on_error='drop_and_log'`` emits a
single ``WARN``-level log line on transport failure and continues; no
exception is propagated to the host application.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Literal

logger = logging.getLogger("relay.flush")

FlushMode = Literal["sync", "async"]
OnErrorMode = Literal["raise", "drop_and_log"]

_DEFAULT_FLUSH_QUEUE_DEPTH: Final[int] = 1024


@dataclass(frozen=True)
class FlushPolicy:
    """SDK flush policy (spec line 2016).

    Attributes:
        mode: ``sync`` -- ``trace.__exit__`` blocks on outbound HTTP I/O
            until the sidecar acknowledges. ``async`` -- the call is
            enqueued onto a background dispatcher thread and
            ``trace.__exit__`` returns immediately (VAL-W3-018).
        on_error: ``raise`` -- a transport failure propagates as a
            :class:`relay.errors.RelayError` subclass. ``drop_and_log``
            -- a transport failure emits one WARN log line and is
            otherwise swallowed (VAL-W3-019).
    """

    mode: FlushMode = "sync"
    on_error: OnErrorMode = "raise"

    @classmethod
    def from_mapping(cls, value: Any) -> FlushPolicy:
        """Coerce a user-supplied mapping or :class:`FlushPolicy` into one.

        Accepts:
          - ``None`` -> defaults ``(sync, raise)``.
          - a :class:`FlushPolicy` instance (returned as-is).
          - a dict with ``mode`` and/or ``on_error`` keys; unknown keys
            raise :class:`relay.errors.RelayConfigError`.
        """
        from .errors import RelayConfigError

        if value is None:
            return cls()
        if isinstance(value, FlushPolicy):
            return value
        if not isinstance(value, dict):
            raise RelayConfigError(
                "flush_policy must be a dict or FlushPolicy",
                details={"received_type": type(value).__name__},
            )
        allowed = {"mode", "on_error"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise RelayConfigError(
                f"flush_policy has unknown key(s): {unknown!r}",
                details={"unknown_keys": unknown, "allowed_keys": sorted(allowed)},
            )
        mode = value.get("mode", "sync")
        on_error = value.get("on_error", "raise")
        if mode not in ("sync", "async"):
            raise RelayConfigError(
                f"flush_policy.mode must be 'sync' or 'async'; received {mode!r}",
                details={"field": "mode", "received": mode},
            )
        if on_error not in ("raise", "drop_and_log"):
            raise RelayConfigError(
                "flush_policy.on_error must be 'raise' or 'drop_and_log'; "
                f"received {on_error!r}",
                details={"field": "on_error", "received": on_error},
            )
        return cls(mode=mode, on_error=on_error)


class AsyncFlushDispatcher:
    """Single-threaded background dispatcher for ``mode='async'`` flushes.

    Lazily-started: the worker thread is created on first ``submit``.
    A call to :meth:`submit` enqueues the work and returns immediately
    (the only blocking is a microsecond-scale ``Queue.put``).

    The worker thread runs each submitted callable in order. A transport
    failure inside the callable is caught and converted according to the
    configured :class:`FlushPolicy.on_error`:

      * ``raise``: the exception is logged at ERROR level AND the
        :class:`AsyncFlushDispatcher` records it on
        :attr:`last_error` so callers can drain via :meth:`wait_idle`
        and inspect.
      * ``drop_and_log``: the exception is logged at WARN level and
        otherwise swallowed -- the host application is not perturbed
        (VAL-W3-019).

    The dispatcher is stopped explicitly via :meth:`close`, which signals
    the worker via a sentinel and joins it. The worker thread is a
    daemon thread so an un-closed dispatcher does not block interpreter
    shutdown.
    """

    _SENTINEL: Final[object] = object()

    def __init__(
        self,
        *,
        on_error: OnErrorMode = "raise",
        max_depth: int = _DEFAULT_FLUSH_QUEUE_DEPTH,
    ) -> None:
        self._on_error: OnErrorMode = on_error
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max_depth)
        self._worker: threading.Thread | None = None
        self._started_lock = threading.Lock()
        self._closed = False
        self.last_error: BaseException | None = None
        # Test-observability: counter of items the worker has processed.
        self.processed_count: int = 0
        # Test-observability: count of dropped (on_error='drop_and_log') items.
        self.drop_count: int = 0

    @property
    def on_error(self) -> OnErrorMode:
        return self._on_error

    def submit(self, work: Callable[[], Any]) -> None:
        """Enqueue ``work`` for the background worker.

        Returns immediately -- the only blocking is the ``Queue.put``
        which holds a lock for tens of microseconds. The caller is
        guaranteed not to block on outbound HTTP I/O (VAL-W3-018).

        If the dispatcher is already closed, ``submit`` runs the work
        inline. This is a degenerate degraded-mode path that should
        only occur during teardown.
        """
        if self._closed:
            # Cannot enqueue after close. Execute inline (best-effort)
            # so the call is not silently dropped at the SDK boundary;
            # ``on_error`` still governs whether failure propagates.
            self._run_one(work)
            return
        self._ensure_worker()
        self._queue.put(work)

    def wait_idle(self, *, timeout: float | None = None) -> bool:
        """Block until every submitted item has been processed.

        Returns True on idle; False if ``timeout`` elapsed first.
        Used by tests after they have released the slow handler.
        """
        if self._worker is None:
            return True
        # Queue.join honors task_done; we call task_done from the worker
        # AFTER each item completes.
        joined = threading.Event()

        def _waiter() -> None:
            self._queue.join()
            joined.set()

        t = threading.Thread(target=_waiter, daemon=True, name="relay-flush-wait")
        t.start()
        return joined.wait(timeout=timeout)

    def close(self, *, timeout: float = 30.0) -> None:
        """Drain the queue, stop the worker, and join it.

        Idempotent. After ``close`` returns the dispatcher is in a
        closed state and further ``submit`` calls run inline.
        """
        if self._closed:
            return
        self._closed = True
        worker = self._worker
        if worker is None:
            return
        # Push the sentinel; the worker loop exits on receiving it.
        self._queue.put(self._SENTINEL)
        worker.join(timeout=timeout)

    # -- internals -----------------------------------------------------------

    def _ensure_worker(self) -> None:
        if self._worker is not None:
            return
        with self._started_lock:
            if self._worker is not None:
                return
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="relay-flush-dispatcher",
                daemon=True,
            )
            self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._SENTINEL:
                    return
                self._run_one(item)
            finally:
                self._queue.task_done()

    def _run_one(self, work: Callable[[], Any]) -> None:
        try:
            work()
        except BaseException as exc:  # noqa: BLE001 - on_error governs disposition
            if self._on_error == "drop_and_log":
                # VAL-W3-019: WARN-level structured log line, NOT a stack
                # trace to stderr; the host application is not perturbed.
                self.drop_count += 1
                logger.warning(
                    "relay.flush.drop_and_log: dropped envelope; "
                    "error_type=%s error=%s",
                    type(exc).__name__,
                    str(exc),
                )
                return
            # 'raise' mode: record on last_error so wait_idle callers can
            # inspect, and log at ERROR so an inattentive operator can
            # find the failure.
            self.last_error = exc
            logger.error(
                "relay.flush.raise: dropped envelope (will be surfaced); "
                "error_type=%s error=%s",
                type(exc).__name__,
                str(exc),
            )
        else:
            self.processed_count += 1


__all__ = [
    "AsyncFlushDispatcher",
    "FlushMode",
    "FlushPolicy",
    "OnErrorMode",
]
