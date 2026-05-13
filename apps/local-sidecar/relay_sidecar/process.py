"""Process liveness and PID-only termination (W2.1).

Per VAL-W2-010 and CLAUDE.md banned pattern #1: the sidecar NEVER kills
processes by name. The only sanctioned termination path is by the exact
PID recorded in the lockfile (``LockfileBody.pid``). This module owns the
``pid_is_alive`` and ``terminate_pid`` helpers; nothing else in the
codebase invokes ``os.kill`` for termination.

A grep guard test in ``tests/test_zombie_port.py`` enforces the banned-
pattern denylist (name-based process management tokens are not present
in any source file under ``apps/local-sidecar/`` or ``packages/cli/``).

Cross-platform:

  - POSIX: ``os.kill(pid, 0)`` probes liveness without sending a signal;
    raises ``ProcessLookupError`` if the PID is dead.
  - Windows: ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)``
    returns NULL for dead PIDs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import signal
import sys
import time


def pid_is_alive(pid: int) -> bool:
    """Return True iff ``pid`` references a running process.

    Pure liveness probe: no signal is delivered on POSIX.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":  # pragma: no cover (POSIX-tested branch)
        # Delegate to ctypes; pywin32 would also work but adds a hard dep
        # we don't otherwise need for W2.1.
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        h = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but is owned by someone else; for our purposes
        # "alive" is the conservative answer.
        return True
    return True


def terminate_pid(pid: int, *, timeout_s: float = 5.0) -> bool:
    """Terminate ``pid`` (PID-only; never name-based).

    POSIX: SIGTERM, wait up to ``timeout_s`` seconds for exit, then
    SIGKILL if still alive. Windows: ``TerminateProcess`` with exit code
    1; no graceful path (Windows lacks a portable SIGTERM equivalent for
    arbitrary processes).

    Returns True if the PID is dead at function return, False otherwise.
    Raises ``ValueError`` if ``pid <= 0`` (programmer error).
    """
    if pid <= 0:
        raise ValueError(f"terminate_pid: pid must be positive; got {pid}")

    if not pid_is_alive(pid):
        return True

    if sys.platform == "win32":  # pragma: no cover (POSIX-tested branch)
        import ctypes

        PROCESS_TERMINATE = 0x0001
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h:
            return not pid_is_alive(pid)
        ctypes.windll.kernel32.TerminateProcess(h, 1)
        ctypes.windll.kernel32.CloseHandle(h)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return True

    # Wait for exit.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not pid_is_alive(pid):
            return True
        time.sleep(0.05)

    # Force kill on POSIX (Windows TerminateProcess is already immediate).
    if sys.platform != "win32":
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True
        time.sleep(0.05)

    return not pid_is_alive(pid)


__all__ = ["pid_is_alive", "terminate_pid"]
