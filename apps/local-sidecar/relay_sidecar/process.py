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
import subprocess
import sys
import time
from datetime import UTC, datetime


def pid_start_time_epoch_s(pid: int) -> float | None:
    """Return the wall-clock start time of ``pid`` as Unix epoch seconds.

    Audit R3 BUG-A3 (2026-05-18): PID-reuse race mitigation for the
    ZOMBIE_PORT branch of the four-state classifier. Before terminating
    a lockfile-recorded PID we MUST verify the running process is the
    one the lockfile points at -- a PID can be reused (kernel wrap or
    same-UID accidental match) after the original sidecar died. The
    only reliable identity check available without escalated privileges
    is the process start time: if the running PID was created AFTER the
    lockfile was written, the PID belongs to someone else and MUST NOT
    be terminated.

    Implementation precedence (no hard dep on psutil):

      1. ``psutil.Process(pid).create_time()`` when psutil is importable
         (preferred -- portable, cross-platform, tested).
      2. POSIX fallback: ``ps -p <pid> -o lstart=`` which returns a
         human-readable timestamp like ``Sat May 17 12:34:56 2026``
         parsed via ``time.strptime`` with the C locale. Available on
         macOS and Linux.
      3. Linux-specific fallback: ``/proc/<pid>/stat`` field 22 (clock
         ticks since boot) combined with ``/proc/uptime`` and
         ``time.time()`` to derive an absolute epoch. Used when psutil
         is absent AND ``ps`` is unavailable. The proc-stat parser
         tolerates the comm-with-spaces edge case by parsing from the
         trailing ')'.
      4. Windows fallback: psutil only. When psutil is not installed
         on Windows this returns ``None`` and the caller MUST treat the
         identity check as "indeterminate" and abort termination (the
         safe default).

    Returns ``None`` on any failure (process exited mid-probe, permission
    denied, parser failure, unsupported platform). Callers MUST treat
    ``None`` as "cannot verify identity -> do not terminate".
    """
    if pid <= 0:
        return None

    # 1. psutil (preferred when present).
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        psutil = None  # type: ignore[assignment]
    if psutil is not None:
        try:
            return float(psutil.Process(pid).create_time())
        except Exception:  # noqa: BLE001  (psutil.NoSuchProcess, AccessDenied)
            return None

    # 2. POSIX ``ps`` fallback.
    if sys.platform != "win32":
        try:
            out = subprocess.check_output(
                ["ps", "-p", str(pid), "-o", "lstart="],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2.0,
            ).strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            out = ""
        if out:
            # Format: "Sat May 17 12:34:56 2026" (locale-independent;
            # ``ps`` uses the C locale formatting for lstart). Parse with
            # an explicit format string so we don't depend on the test
            # host's locale.
            try:
                struct_time = time.strptime(out, "%a %b %d %H:%M:%S %Y")
                # ``ps -o lstart`` emits the local timezone but the
                # struct lacks tz info. ``time.mktime`` interprets it as
                # local time, which is what the surrounding ``ps`` value
                # represents. Equality is checked against
                # ``LockfileBody.launched_at`` (RFC 3339 UTC) by the
                # caller after both are converted to epoch seconds, so
                # any timezone offset cancels out as long as we use the
                # platform's local time consistently here.
                return float(time.mktime(struct_time))
            except (ValueError, OverflowError):
                pass

        # 3. /proc/<pid>/stat fallback (Linux only).
        if sys.platform.startswith("linux"):
            try:
                with open(f"/proc/{pid}/stat", encoding="ascii") as f:
                    stat_line = f.read()
            except OSError:
                return None
            # Field 22 (1-indexed) is starttime in clock ticks since
            # boot. The comm field (field 2) may contain spaces inside
            # parentheses; parse from the trailing ')' to be safe.
            close_paren = stat_line.rfind(")")
            if close_paren < 0:
                return None
            tail = stat_line[close_paren + 2 :].split()
            # tail[0] is 'state' (field 3). starttime is field 22, so
            # index 22 - 3 = 19 in ``tail``.
            try:
                starttime_ticks = int(tail[19])
            except (IndexError, ValueError):
                return None
            try:
                ticks_per_s = os.sysconf("SC_CLK_TCK")
            except (AttributeError, ValueError, OSError):
                ticks_per_s = 100
            try:
                with open("/proc/uptime", encoding="ascii") as f:
                    uptime_s = float(f.read().split()[0])
            except (OSError, ValueError, IndexError):
                return None
            now = time.time()
            boot_epoch = now - uptime_s
            return boot_epoch + (starttime_ticks / float(ticks_per_s))

    # 4. Windows without psutil: cannot verify safely.
    return None


def pid_identity_matches_lockfile(
    pid: int, launched_at_iso: str, *, tolerance_s: float = 5.0
) -> bool:
    """Return True iff ``pid``'s start time is within ``tolerance_s`` of
    or earlier than ``launched_at_iso``.

    Audit R3 BUG-A3 (2026-05-18): identity check used by the spawn
    classifier before terminating a lockfile-recorded PID. The check
    is asymmetric: a start time AT OR BEFORE the lockfile timestamp
    (plus a small forward tolerance for clock skew between the spawner
    and the sidecar process) is accepted; a start time later than
    ``launched_at + tolerance_s`` is REJECTED (the PID was reused
    after the lockfile was written -- terminating it would kill an
    unrelated process).

    Returns ``False`` whenever the start time cannot be determined
    (``pid_start_time_epoch_s`` returned None) -- conservative default:
    if we cannot verify identity, we MUST NOT terminate.

    Args:
        pid: Target PID.
        launched_at_iso: ``LockfileBody.launched_at`` (RFC 3339 UTC
            string ending in 'Z'). Parsed via ``datetime.fromisoformat``.
        tolerance_s: Forward clock-skew tolerance in seconds. Default 5s
            covers small NTP drift between the spawner and the kernel's
            process-table clock.
    """
    start_epoch = pid_start_time_epoch_s(pid)
    if start_epoch is None:
        return False
    try:
        # RFC 3339 with trailing 'Z' -> replace with '+00:00' for
        # fromisoformat on Python < 3.11; 3.12+ handles 'Z' natively but
        # the replace is a no-op so it's safe across versions.
        iso = launched_at_iso.replace("Z", "+00:00")
        launched_dt = datetime.fromisoformat(iso)
    except ValueError:
        return False
    if launched_dt.tzinfo is None:
        launched_dt = launched_dt.replace(tzinfo=UTC)
    launched_epoch = launched_dt.timestamp()
    return start_epoch <= launched_epoch + tolerance_s


def pid_is_alive(pid: int) -> bool:
    """Return True iff ``pid`` references a running process.

    Pure liveness probe: no signal is delivered on POSIX.
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":  # pragma: no cover (POSIX-tested branch)
        # Delegate to ctypes; pywin32 would also work but adds a hard dep
        # we don't otherwise need for W2.1.
        #
        # OpenProcess succeeding is NOT sufficient: Windows keeps the
        # process kernel object alive while any handle (parent, ours,
        # multiprocessing's internal bookkeeping) references it, even
        # AFTER TerminateProcess has marked the process exited. A zombie
        # in this state will report OpenProcess-success but is logically
        # dead. We must additionally check GetExitCodeProcess and treat
        # any value other than STILL_ACTIVE (259) as "dead".
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        h = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if not h:
            return False
        try:
            exit_code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(
                h, ctypes.byref(exit_code)
            )
            if not ok:
                # GetExitCodeProcess failed; conservative answer is "alive"
                # so callers do not delete a process they cannot verify
                # is dead.
                return True
            return exit_code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
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


def force_kill_pid(pid: int) -> bool:
    """Immediately terminate ``pid`` with no graceful path.

    POSIX: ``os.kill(pid, signal.SIGKILL)``.
    Windows: ``TerminateProcess`` via ctypes (no portable SIGKILL).

    Unlike :func:`terminate_pid` this does NOT send SIGTERM first or
    wait for a graceful exit window; it is the equivalent of
    ``kill -9`` and exists for test fixtures that need to simulate a
    hard crash mid-transaction (e.g. WAL recovery contract tests).

    Returns True if the PID is dead at function return, False
    otherwise. Raises ``ValueError`` if ``pid <= 0``.

    PROCESS SAFETY: PID-only; never name-based. Callers MUST only
    pass a PID they themselves started (test subprocess, owned spawn,
    etc.). Per CLAUDE.md process-safety rules, name-based kill
    variants are forbidden.
    """
    if pid <= 0:
        raise ValueError(f"force_kill_pid: pid must be positive; got {pid}")

    if not pid_is_alive(pid):
        return True

    if sys.platform == "win32":  # pragma: no cover (POSIX-tested branch)
        import ctypes

        PROCESS_TERMINATE = 0x0001
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h:
            return not pid_is_alive(pid)
        try:
            ctypes.windll.kernel32.TerminateProcess(h, 1)
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True

    # Brief settle period; both SIGKILL and TerminateProcess are
    # near-immediate but the OS bookkeeping (zombie reap on POSIX,
    # handle table cleanup on Windows) is asynchronous.
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not pid_is_alive(pid):
            return True
        time.sleep(0.02)
    return not pid_is_alive(pid)


__all__ = ["pid_is_alive", "terminate_pid", "force_kill_pid"]
