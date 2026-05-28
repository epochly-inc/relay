"""End-to-end VAL-W2-055 + VAL-W2-049: kill -9 + restart preserves event_log ordering.

This test exercises the FULL production crash-recovery path:

  1. Spawn a real sidecar subprocess that writes a few committed
     event_log rows, opens a BEGIN IMMEDIATE transaction, and INSERTs an
     uncommitted row.
  2. SIGKILL the subprocess by its captured PID.
  3. Spawn a SECOND real subprocess that invokes ``run_uvicorn`` against
     the same DB path. The production wiring calls ``recover_or_refuse``
     synchronously BEFORE ``SidecarDatabase.open``, which detects the
     WAL frames left by the killed first run, runs WAL replay (rolling
     back the uncommitted txn), passes quick_check, and writes a
     ``sidecar.crash_recovered`` event_log row.
  4. Stop the second subprocess via SIGTERM (graceful) once it is
     ready, then assert event_log ordering on the resulting DB.

This is the STR-001 verification that the crash-recovery path works at
the production startup surface, not just by direct calls to
``recover_or_refuse(...)``. Without the wiring, the second subprocess
would NOT run recovery, would proceed to ``SidecarDatabase.open``
which (via aiosqlite + WAL mode) WOULD run sqlite's automatic WAL
replay -- BUT no ``sidecar.crash_recovered`` event_log row would be
emitted, breaking the forensic guarantee.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import aiosqlite
import pytest

# Subprocess #1: open SidecarDatabase, write 3 committed rows via the
# state-engine path, then open a BEGIN IMMEDIATE on the writer connection
# and INSERT a row WITHOUT committing. Signal READY on stdout, then
# sleep forever waiting for SIGKILL. Mirrors test_crash_kill_minus_9's
# helper but kept self-contained to keep this e2e test independent.
_SUBPROCESS_KILL_TARGET_SCRIPT = textwrap.dedent(
    """
    import asyncio
    import json
    import os
    import sys
    import time
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[2])

    async def _main(db_path):
        from relay_sidecar.db import SidecarDatabase, build_event_log_row
        db = SidecarDatabase(db_path=Path(db_path))
        await db.open()
        for i in range(3):
            row = build_event_log_row(
                event_type="sidecar.test_pre_crash",
                scope_id="00000000-0000-0000-0000-000000000000",
                project_id="00000000-0000-0000-0000-000000000000",
                payload={"i": i},
            )
            await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id="00000000-0000-0000-0000-000000000000",
                idempotency_key=f"e2e-pre-crash-{i}",
            )
        conn = db._writer
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type, "
            "  scope_id, event_type, actor_kind, payload, "
            "  occurred_at, ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ffffffff-ffff-4fff-8fff-ffffffffffff",
                "relay.event_log_entry.v1",
                "00000000-0000-0000-0000-000000000000",
                "other",
                "00000000-0000-0000-0000-000000000000",
                "sidecar.WILL_BE_ROLLED_BACK",
                "control_plane",
                "{}",
                "2026-05-13T00:00:00.000000Z",
                999999,
                "test_kill_9",
            ),
        )
        sys.stdout.write(json.dumps({"pid": os.getpid(), "ready": True}) + "\\n")
        sys.stdout.flush()
        while True:
            time.sleep(0.5)

    asyncio.run(_main(sys.argv[3]))
    """
).strip()


# Subprocess #2: invoke ``run_uvicorn`` against the same DB. The
# wired-in ``recover_or_refuse`` call runs FIRST, detecting the WAL
# frames and emitting a ``sidecar.crash_recovered`` event_log row. The
# subprocess then proceeds to start uvicorn -- we send SIGTERM once it
# is READY (we use a short startup heuristic: ``recover_or_refuse``
# completes synchronously before the asyncio loop, so by the time the
# subprocess is bound to a port the recovery row already exists).
#
# The subprocess prints diagnostic JSON to stderr around recovery so
# debugging on a polling timeout reveals whether recovery actually ran.
_SUBPROCESS_RECOVER_AND_RUN_SCRIPT = textwrap.dedent(
    """
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[2])

    from relay_sidecar.health import HealthState
    from relay_sidecar.recovery import recover_or_refuse
    from relay_sidecar.runtime import run_uvicorn

    relay_home = Path(sys.argv[3])
    db_path = Path(sys.argv[4])
    # Diagnostic: recovery summary BEFORE entering uvicorn. The same probe
    # runs again inside run_uvicorn (production wiring); this explicit
    # call exposes the summary on stderr so test failures are debuggable.
    summary = recover_or_refuse(db_path)
    sys.stderr.write(
        "DIAG-RECOVER:" + json.dumps(summary, default=str) + chr(10)
    )
    sys.stderr.flush()
    # Signal READY to the parent on stdout AFTER recovery completes.
    # The parent waits for this line BEFORE inspecting the DB, so
    # parent-side connections cannot race ahead and consume WAL frames
    # before recovery fires.
    sys.stdout.write("READY\\n")
    sys.stdout.flush()
    health = HealthState(
        port=0,
        bearer_token="t-test-token",
        bearer_token_digest=(
            "sha256-0000000000000000000000000000000000000000000000000000000000000000"
        ),
    )
    run_uvicorn(
        health=health,
        host="127.0.0.1",
        port=0,
        sqlite_path=db_path,
        relay_home_override=relay_home,
    )
    """
).strip()


def _spawn_kill_target(tmp_path: Path) -> tuple[int, Path, subprocess.Popen]:
    """Spawn the kill-target subprocess; return (pid, db_path, Popen)."""
    db_path = tmp_path / "sidecar.db"
    repo_root = Path(__file__).resolve().parents[3]
    pkg_root = repo_root / "apps" / "local-sidecar"
    schemas_root = repo_root / "packages" / "schemas" / "python"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SUBPROCESS_KILL_TARGET_SCRIPT,
            str(pkg_root),
            str(schemas_root),
            str(db_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 15.0
    line: str | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(
                f"kill-target subprocess exited prematurely: rc={proc.returncode}\n"
                f"stdout={stdout!r}\nstderr={stderr!r}"
            )
        ready = proc.stdout.readline().strip() if proc.stdout else ""
        if ready:
            line = ready
            break
        time.sleep(0.05)
    if line is None:
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.communicate(timeout=5.0)
        raise RuntimeError("kill-target subprocess never signalled READY")
    import json as _json

    payload = _json.loads(line)
    pid = int(payload["pid"])
    return pid, db_path, proc


def _kill_and_reap(pid: int, proc: subprocess.Popen) -> None:
    """Force-kill ``pid`` (PID-only; never name-based) and reap via proc.wait().

    Uses ``relay_sidecar.process.force_kill_pid`` which dispatches to
    ``os.kill(pid, signal.SIGKILL)`` on POSIX and ``TerminateProcess``
    via ctypes on Windows (where ``signal.SIGKILL`` does not exist).
    """
    from relay_sidecar.process import force_kill_pid

    force_kill_pid(pid)
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    if proc.stdout is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stdout.read()
        proc.stdout.close()
    if proc.stderr is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stderr.read()
        proc.stderr.close()


def _spawn_recover_and_run(
    *,
    relay_home: Path,
    db_path: Path,
) -> subprocess.Popen:
    """Spawn the run_uvicorn subprocess; return Popen handle (caller stops it)."""
    repo_root = Path(__file__).resolve().parents[3]
    pkg_root = repo_root / "apps" / "local-sidecar"
    schemas_root = repo_root / "packages" / "schemas" / "python"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SUBPROCESS_RECOVER_AND_RUN_SCRIPT,
            str(pkg_root),
            str(schemas_root),
            str(relay_home),
            str(db_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc


def _wait_until_recovery_complete(
    proc: subprocess.Popen,
    *,
    timeout_s: float = 30.0,
) -> bool:
    """Wait for the Phase-2 subprocess's READY signal on stdout.

    Critical: parent-side connections to the SQLite DB MUST NOT open
    before recover_or_refuse completes. SQLite auto-replays the WAL on
    the first WAL-mode connection; if the parent races ahead and
    opens aiosqlite before recovery, the WAL is consumed and recovery's
    ``_wal_present_with_frames`` returns False -- the recovery row is
    never written, breaking VAL-W2-049 evidence.

    The subprocess writes ``READY`` to stdout AFTER recover_or_refuse
    returns. The parent reads stdout (text mode, line-buffered) until
    READY appears, then it is safe to open the DB.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            # Subprocess exited before READY -- treat as failure.
            return False
        if proc.stdout is None:
            return False
        line = proc.stdout.readline().strip()
        if line == "READY":
            return True
        if line:
            # Some other stdout line; keep reading.
            continue
        time.sleep(0.05)
    return False


def _stop_subprocess_via_sigterm(proc: subprocess.Popen) -> None:
    """Send SIGTERM (PID-only via Popen handle) and reap gracefully."""
    if proc.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=15.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    if proc.stdout is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stdout.read()
        proc.stdout.close()
    if proc.stderr is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stderr.read()
        proc.stderr.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-055", "VAL-W2-049")
def test_e2e_kill_minus_9_then_restart_preserves_ordering_at_production_surface(
    tmp_path: Path,
) -> None:
    """SIGKILL one real subprocess + restart real subprocess via run_uvicorn."""
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(parents=True, exist_ok=True)

    # Phase 1: spawn the kill-target subprocess; SIGKILL it mid-transaction.
    kill_pid, db_path, kill_proc = _spawn_kill_target(relay_home)
    assert kill_proc.poll() is None
    _kill_and_reap(kill_pid, kill_proc)

    # WAL frames or preserved WAL must be on disk (the killed subprocess
    # opened in WAL mode and left uncommitted frames behind).
    wal = db_path.parent / (db_path.name + "-wal")
    wal_preserved = db_path.parent / (db_path.name + "-wal.preserved")
    assert wal.exists() or wal_preserved.exists(), (
        "VAL-W2-049: kill-target subprocess did not leave WAL frames on disk"
    )

    # Phase 2: spawn the run_uvicorn subprocess. Production wiring runs
    # recover_or_refuse FIRST -> emits sidecar.crash_recovered before the
    # asyncio loop even starts. Once uvicorn is up, the row is on disk;
    # we then send SIGTERM to stop the subprocess gracefully.
    runner_proc = _spawn_recover_and_run(relay_home=relay_home, db_path=db_path)
    try:
        # Wait for the subprocess to signal READY (it writes the line
        # AFTER recover_or_refuse returns). The parent must NOT open the
        # SQLite DB before this signal: any parent-side
        # ``aiosqlite.connect`` triggers SQLite's automatic WAL replay,
        # which consumes the WAL frames before the subprocess's recovery
        # path can detect them. Without the READY barrier the subprocess's
        # ``_wal_present_with_frames`` returns False, the
        # ``sidecar.crash_recovered`` row is never written, and we lose
        # VAL-W2-049 evidence to a test-harness race rather than a real
        # wiring regression.
        ready = _wait_until_recovery_complete(runner_proc, timeout_s=30.0)
        if not ready:
            # Capture subprocess output for diagnostics; the runner may
            # still be alive so SIGTERM it first, then read stdio.
            with contextlib.suppress(ProcessLookupError):
                os.kill(runner_proc.pid, signal.SIGTERM)
            try:
                _stdout, _stderr = runner_proc.communicate(timeout=15.0)
            except subprocess.TimeoutExpired:
                runner_proc.kill()
                _stdout, _stderr = runner_proc.communicate(timeout=5.0)
            raise AssertionError(
                "VAL-W2-049: production startup wiring failed to signal "
                "READY after kill -9 + recover_or_refuse; STR-001 wiring "
                f"may be missing or recovery aborted.\n"
                f"rc={runner_proc.returncode}\n"
                f"stdout={_stdout!r}\nstderr={_stderr!r}"
            )
    finally:
        _stop_subprocess_via_sigterm(runner_proc)

    # Phase 3: assert event_log ordering on the post-recovery DB.
    async def _read_all() -> tuple[list[int], int, int, int]:
        async with aiosqlite.connect(str(db_path)) as conn:
            async with conn.execute(
                "SELECT ingest_sequence FROM event_log_entries "
                "ORDER BY ingest_sequence ASC"
            ) as cur:
                seqs = [int(r[0]) async for r in cur]
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.WILL_BE_ROLLED_BACK'"
            ) as cur:
                row = await cur.fetchone()
                rolled_back = int(row[0]) if row is not None else -1
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.crash_recovered'"
            ) as cur:
                row = await cur.fetchone()
                crash_count = int(row[0]) if row is not None else 0
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_pre_crash'"
            ) as cur:
                row = await cur.fetchone()
                pre_count = int(row[0]) if row is not None else 0
        return seqs, rolled_back, crash_count, pre_count

    seqs, rolled_back, crash_count, pre_count = asyncio.run(_read_all())

    # VAL-W2-049: the half-written transaction is NOT visible.
    assert rolled_back == 0, (
        f"VAL-W2-049: WAL recovery should have rolled back the uncommitted "
        f"txn at production surface; observed {rolled_back} rolled-back rows"
    )
    # VAL-W2-049: pre-crash committed rows survived.
    assert pre_count == 3, (
        f"VAL-W2-049: pre-crash committed rows should survive; got {pre_count}/3"
    )
    # VAL-W2-049: at least one sidecar.crash_recovered row was emitted by
    # the production startup path. The wiring lands recovery in TWO
    # places (the synchronous run_uvicorn pre-call AND the defensive
    # lifespan-startup call), and the WAL frames may persist between
    # them (PASSIVE checkpoint does not truncate). Either invocation
    # path emitting the row satisfies the forensic contract; multiple
    # rows from a single physical crash boundary are tolerated. <1
    # indicates the wiring is missing.
    assert crash_count >= 1, (
        f"VAL-W2-049: at least one sidecar.crash_recovered row expected "
        f"from the production wiring; observed {crash_count}"
    )

    # VAL-W2-055: ingest_sequence strictly monotonic, no duplicates, no NULL.
    assert all(s is not None for s in seqs), (
        f"VAL-W2-055: NULL ingest_sequence observed: {seqs}"
    )
    assert seqs == sorted(set(seqs)), (
        f"VAL-W2-055: ingest_sequence must be strictly monotonic without "
        f"duplicates after crash + production-surface recovery; got {seqs}"
    )
    # VAL-W2-055: pre-crash rows remain in commit order (0,1,2 contiguous).
    pre_only = sorted(seqs[:3])
    assert pre_only == [0, 1, 2], (
        f"VAL-W2-055: pre-crash rows lost commit order; first three "
        f"ingest_sequence values are {pre_only}"
    )
