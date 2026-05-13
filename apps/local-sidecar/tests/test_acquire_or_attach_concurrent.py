"""VAL-W2-006: Portalocker exclusive lock serializes spawn races.

N=10 concurrent ``acquire_or_attach`` calls MUST result in exactly one
``sidecar.spawned`` event_log_entries row; the other 9 attach.

Uses ``multiprocessing.Process`` (NOT threading) so the file lock is
exercised across separate OS processes.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from collections.abc import Iterable
from pathlib import Path

import pytest
from relay_sidecar.event_log import count_events
from relay_sidecar.lockfile import resolve_lockfile_path
from relay_sidecar.spawn import acquire_or_attach


def _worker(
    home_path: str,
    barrier_sync_path: str,
    queue: mp.Queue[tuple[str, str]],
) -> None:
    """Child process entrypoint: run acquire_or_attach and report the action.

    The worker injects a process_runner that binds a real listening
    socket on a fresh ephemeral port and KEEPS the socket open so that
    other workers see ``port_bound == True`` and choose the ATTACH branch.

    All workers block briefly on the barrier (a file-based countdown)
    before invoking ``acquire_or_attach`` so the race window is wide
    enough to exercise the portalocker exclusive lock.
    """
    import socket as _socket
    import time as _time

    os.environ["RELAY_HOME"] = home_path

    # Open a real listener; the lockfile records this port. We keep the
    # listening socket bound for the worker's lifetime so subsequent
    # workers see a bound port and ATTACH.
    listener: _socket.socket | None = None

    def _runner() -> tuple[int, int]:
        nonlocal listener
        listener = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        listener.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        return os.getpid(), listener.getsockname()[1]

    # Synchronize start across workers: each worker writes a sentinel
    # file and waits for the expected count before proceeding.
    sentinel = Path(barrier_sync_path)
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    pid_str = f"{os.getpid()}\n"
    with open(sentinel, "a", encoding="utf-8") as f:
        f.write(pid_str)
    # Wait up to 5s for all workers to be present (best-effort barrier).
    deadline = _time.monotonic() + 5.0
    while _time.monotonic() < deadline:
        try:
            lines = sentinel.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        if len(lines) >= 10:
            break
        _time.sleep(0.01)

    try:
        decision = acquire_or_attach(
            home=Path(home_path),
            process_runner=_runner,
        )
        queue.put((str(decision.action), ""))
        # Keep the listening socket alive while peers contend.
        _time.sleep(2.0)
    except BaseException as e:  # pragma: no cover (children always succeed)
        queue.put(("error", repr(e)))
    finally:
        if listener is not None:
            import contextlib

            with contextlib.suppress(OSError):
                listener.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-006")
def test_n10_concurrent_spawn_produces_exactly_one_spawned_event(
    relay_home_tmp: Path,
) -> None:
    """N=10 concurrent processes; exactly one ``sidecar.spawned`` row."""
    n = 10
    ctx = mp.get_context("spawn")  # avoid fork to ensure clean child state
    queue: mp.Queue[tuple[str, str]] = ctx.Queue()
    barrier_path = relay_home_tmp / "barrier.txt"
    procs: list[mp.Process] = []
    for _ in range(n):
        p = ctx.Process(
            target=_worker,
            args=(str(relay_home_tmp), str(barrier_path), queue),
        )
        procs.append(p)
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert not p.is_alive(), "child worker exceeded 30s budget"

    actions: list[str] = []
    while not queue.empty():
        action, err = queue.get_nowait()
        assert action != "error", f"child error: {err}"
        actions.append(action)
    # Most workers should respond; a peer in the ZOMBIE_PORT branch may
    # SIGKILL another worker before it queues its response. The contract
    # assertion is on the event-log row count, not the response count.
    # We still require at least n//2 responses so a catastrophic spawn
    # failure can't silently pass.
    assert len(actions) >= n // 2, (
        f"only {len(actions)}/{n} workers responded; concurrent contract broken"
    )

    # PRIMARY CONTRACT (VAL-W2-006): exactly ONE ``sidecar.spawned``
    # event-log row regardless of how many recovery-respawns happen.
    # ``sidecar.respawned`` events from STALE/ZOMBIE recovery branches
    # are NOT counted here; only the literal first-spawn lineage marker.
    spawned_rows = count_events("sidecar.spawned", home=relay_home_tmp)
    assert spawned_rows == 1, (
        f"event_log_entries shows {spawned_rows} sidecar.spawned rows; expected 1"
        f" (actions={sorted(actions)})"
    )

    # Sanity: the lockfile exists.
    assert resolve_lockfile_path(relay_home_tmp).exists()


# Suppress unused-import warning for the typing helper.
_ = Iterable
