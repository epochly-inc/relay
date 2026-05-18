"""VAL-W2-010: ZOMBIE_PORT terminates only the lockfile-recorded PID.

NEVER name-based (``pkill``, ``killall``, ``os.system("kill ...")``).
Grep guard asserts:

  rg "pkill|killall|os\\.system.*kill" apps/local-sidecar/ packages/cli/

returns empty.

The integration leg uses a spawned sentinel child process so we have a
real PID we can terminate; the assertion checks that the terminated PID
matches the one recorded in the lockfile.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from relay_sidecar.event_log import count_events, read_event_log
from relay_sidecar.lockfile import (
    LockfileBody,
    resolve_lockfile_path,
    serialize_lockfile_body,
)
from relay_sidecar.primitives import local_atomic_file_write
from relay_sidecar.process import pid_is_alive
from relay_sidecar.spawn import acquire_or_attach


def _now_plus_seconds_z(delta_s: float) -> str:
    """Return an RFC 3339 'Z' timestamp at ``now + delta_s``.

    Audit R3 BUG-A3 (2026-05-18): the ZOMBIE_PORT branch now verifies
    the PID's start_time is at or before ``launched_at + 5s``, so test
    seed lockfiles MUST be timestamped AFTER the sentinel child starts.
    """
    dt = datetime.now(tz=UTC) + timedelta(seconds=delta_s)
    return dt.isoformat().replace("+00:00", "Z")

REPO_ROOT = Path(__file__).resolve().parents[3]
SCANNED_DIRS = (
    REPO_ROOT / "apps" / "local-sidecar",
    REPO_ROOT / "packages" / "cli",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-010")
def test_no_name_based_kill_in_source() -> None:
    """Grep guard: ``pkill|killall|os.system.*kill`` must not appear."""
    pattern = re.compile(r"\b(pkill|killall)\b|os\.system\([^)]*kill")
    offenders: list[str] = []
    # Files that legitimately enumerate the banned tokens for detection
    # purposes (the source-of-truth for what the grep guard prohibits
    # everywhere else). Each entry is a relative POSIX path.
    exempt_paths: set[str] = {
        # The W2 grep guard test itself.
        "apps/local-sidecar/tests/test_zombie_port.py",
        # The W5.5 verify-self banned-pattern detector and its closed
        # finding-codes enum / shared util module / its tests.
        "packages/cli/src/verify_self/finding_codes.py",
        "packages/cli/src/relay_cli/invariants/banned_patterns.py",
        "packages/cli/src/relay_cli/invariants/util.py",
        "packages/cli/tests/test_w5_5_verify_self.py",
    }
    for root in SCANNED_DIRS:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            rel = py.relative_to(REPO_ROOT).as_posix()
            if rel in exempt_paths:
                continue
            text = py.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    offenders.append(f"{py}:{lineno}: {line.strip()}")
    assert not offenders, "VAL-W2-010 grep violations:\n" + "\n".join(offenders)


def _sentinel_child() -> None:  # pragma: no cover (child process)
    """Sentinel: sleeps until terminated by parent."""
    time.sleep(30.0)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-010")
def test_zombie_port_terminates_only_lockfile_pid(relay_home_tmp: Path) -> None:
    """A real child PID + unbound port -> terminate_pid(child.pid) exactly."""
    ctx = mp.get_context("spawn")
    sentinel = ctx.Process(target=_sentinel_child)
    sentinel.start()
    assert sentinel.pid is not None
    sentinel_pid: int = sentinel.pid
    try:
        # Sanity: child is alive.
        assert pid_is_alive(sentinel_pid)

        # Seed a lockfile pointing at the sentinel pid + a port we know is
        # unbound (use a high ephemeral that nothing on the test host is
        # listening on; portalocker test fixtures use the same approach).
        unbound_port = 50080
        # Audit R3 BUG-A3 (2026-05-18): the seeded launched_at MUST be
        # AT or AFTER the sentinel's start_time (within the 5s tolerance)
        # for the identity check to accept termination. The sentinel was
        # spawned moments ago via mp.Process.start(); +1s is safely
        # AFTER its create_time on all tested kernels.
        zombie_body = LockfileBody(
            pid=sentinel_pid,
            port=unbound_port,
            launched_at=_now_plus_seconds_z(1.0),
            launched_by="zombie-user",
            sidecar_version="0.0.0",
            bearer_token_digest="sha256-" + "d" * 64,
        )
        lockfile = resolve_lockfile_path(relay_home_tmp)
        local_atomic_file_write(
            lockfile, serialize_lockfile_body(zombie_body), mode=0o600
        )

        # Run acquire_or_attach. Expectation: ZOMBIE_PORT branch fires;
        # the sentinel child is terminated; a new spawn proceeds.
        decision = acquire_or_attach(
            home=relay_home_tmp,
            process_runner=lambda: (os.getpid(), 50081),
        )
        assert decision.action == "zombie_port_terminated_and_spawned"
        assert decision.lockfile_body.pid == os.getpid()

        # The sentinel must be dead. Multiprocessing keeps the child as a
        # zombie until the parent reaps it (waitpid); we explicitly join
        # so the OS frees the PID before we re-probe. The contract
        # property under test is "terminate_pid sent the correct signal
        # to the correct PID"; verifying via post-join liveness is the
        # cleanest assertion that works across macOS/Linux.
        sentinel.join(timeout=5)
        assert not sentinel.is_alive(), (
            "sentinel multiprocessing.Process still alive after terminate_pid + join"
        )
        # Also probe via the OS-level liveness check.
        for _ in range(20):
            if not pid_is_alive(sentinel_pid):
                break
            time.sleep(0.05)
        assert not pid_is_alive(sentinel_pid), (
            f"sentinel PID {sentinel_pid} still alive after terminate_pid + join"
        )

        # The event log carries a sidecar.zombie_pid_terminated row
        # carrying the terminated PID.
        zombie_rows = count_events(
            "sidecar.zombie_pid_terminated", home=relay_home_tmp
        )
        assert zombie_rows == 1
        entries = read_event_log(home=relay_home_tmp)
        zombie = next(
            e for e in entries if e.event_type == "sidecar.zombie_pid_terminated"
        )
        assert zombie.payload.get("terminated_pid") == sentinel_pid
    finally:
        if sentinel.is_alive():
            sentinel.terminate()
            sentinel.join(timeout=5)
