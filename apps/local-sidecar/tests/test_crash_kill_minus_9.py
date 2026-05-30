"""VAL-W2-049 + VAL-W2-055: kill -9 mid-transaction triggers WAL recovery.

A subprocess opens a SidecarDatabase, BEGIN IMMEDIATE, INSERT one row
(WITHOUT committing), then signals the parent and waits to be killed.
The parent SIGKILLs the child, then re-opens the database via the
recovery module + SidecarDatabase, and asserts:

  (VAL-W2-049)
    1. The half-written transaction is NOT visible in event_log_entries
       (sqlite WAL recovery rolled it back).
    2. ``recover_or_refuse`` invoked the WAL replay branch.
    3. A ``sidecar.crash_recovered`` event_log row was emitted with
       the recovery summary.

  (VAL-W2-055)
    4. After recovery, the surviving event_log_entries.ingest_sequence
       values are strictly monotonic with no NULLs and no duplicates.
       Gaps are acceptable per SQLite identity semantics, but committed
       rows must be contiguous in commit order.

Per CLAUDE.md process safety: SIGKILL goes to a SPECIFIC PID captured
from the subprocess we spawned ourselves. NO name-based termination
of any kind (the banned-token grep guard at VAL-W2-010 enforces this
across the source tree; we only call ``os.kill(specific_pid, ...)``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import aiosqlite
import pytest
from relay_sidecar.recovery import recover_or_refuse

# Subprocess script: open DB, BEGIN IMMEDIATE, INSERT (no commit), then
# write the PID + db_path to stdout and sleep forever waiting for SIGKILL.
# We use raw sqlite3 (sync) to keep the script as small as possible.
_SUBPROCESS_SCRIPT = textwrap.dedent(
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
        # Write a few committed rows first so the post-crash event_log has
        # contiguous ingest_sequence values (VAL-W2-055).
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
                idempotency_key=f"pre-crash-{i}",
            )
        # Force the writer connection into an open BEGIN IMMEDIATE that
        # the subprocess will be killed inside. We use the writer
        # directly (private API) because we need control over commit
        # timing.
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
        # Signal readiness via stdout.
        sys.stdout.write(json.dumps({"pid": os.getpid(), "ready": True}) + "\\n")
        sys.stdout.flush()
        # Sleep until killed.
        while True:
            time.sleep(0.5)

    db_path = sys.argv[3]
    asyncio.run(_main(db_path))
    """
).strip()


def _spawn_uncommitted_writer(
    tmp_path: Path,
) -> tuple[int, Path, subprocess.Popen]:
    """Spawn the subprocess; return (pid, db_path, proc) once READY signalled.

    The Popen handle is returned so the caller can call ``proc.wait()``
    after SIGKILL to reap the zombie + close the stdout/stderr pipes.
    Without that, pytest's ResourceWarning collector flags unclosed
    file handles on teardown.
    """
    db_path = tmp_path / "sidecar.db"
    repo_root = Path(__file__).resolve().parents[3]
    pkg_root = repo_root / "apps" / "local-sidecar"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SUBPROCESS_SCRIPT,
            str(pkg_root),
            str(repo_root / "packages" / "schemas" / "python"),
            str(db_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Wait up to 15s for the READY line (uv-managed envs may be slow on
    # cold start; after warm cache this is sub-second).
    deadline = time.monotonic() + 15.0
    line = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(
                f"subprocess exited prematurely: rc={proc.returncode}\n"
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
        raise RuntimeError("subprocess never signalled READY within 15s")
    import json as _json

    payload = _json.loads(line)
    pid = int(payload["pid"])
    return pid, db_path, proc


def _kill_and_reap(pid: int, proc: subprocess.Popen) -> None:
    """Force-kill ``pid`` and reap via proc.wait(); close stdio pipes.

    Uses ``relay_sidecar.process.force_kill_pid`` which dispatches to
    ``os.kill(pid, signal.SIGKILL)`` on POSIX and ``TerminateProcess``
    via ctypes on Windows (where ``signal.SIGKILL`` does not exist).

    Reaping (proc.wait) clears the zombie entry in the OS process table
    so subsequent ``pid_is_alive(pid)`` returns False. Closing
    proc.stdout / proc.stderr suppresses pytest's ResourceWarning.
    """
    # force_kill_pid swallows ProcessLookupError internally; no contextlib
    # suppression needed at the call site.
    from relay_sidecar.process import force_kill_pid

    force_kill_pid(pid)
    # proc.wait() reads the exit status and reaps the zombie. Without
    # this, the kernel keeps the PID slot occupied; os.kill(pid, 0)
    # would still report alive.
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)
    # Drain + close pipes so pytest's ResourceWarning collector is happy.
    if proc.stdout is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stdout.read()
        proc.stdout.close()
    if proc.stderr is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stderr.read()
        proc.stderr.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-049", "VAL-W2-055")
def test_kill_9_rolls_back_uncommitted_transaction(tmp_path: Path) -> None:
    """SIGKILL mid-BEGIN-IMMEDIATE: rollback + ingest_sequence monotonic + recovery row."""
    pid, db_path, proc = _spawn_uncommitted_writer(tmp_path)
    # Sanity: the subprocess is running.
    assert proc.poll() is None, "subprocess exited before kill"
    # SIGKILL the SPECIFIC PID we spawned + reap the zombie.
    _kill_and_reap(pid, proc)

    # Confirm WAL frames remain (the uncommitted txn left frames on disk).
    wal_path = db_path.parent / (db_path.name + "-wal")
    assert wal_path.exists() or (
        db_path.parent / (db_path.name + "-wal.preserved")
    ).exists()

    # Run recovery. This should detect the WAL, replay it (rolling back
    # the uncommitted txn), pass quick_check, and emit a
    # sidecar.crash_recovered row.
    summary = recover_or_refuse(db_path)
    assert summary["recovery_invoked"] is True, summary
    assert summary["quick_check_status"] == "ok", summary
    assert summary["crash_recovery_event_written"] is True, summary

    # The half-written transaction is NOT visible.
    import asyncio

    async def _verify_post_recovery():
        async with aiosqlite.connect(str(db_path)) as conn:
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.WILL_BE_ROLLED_BACK'"
            ) as cur:
                r = await cur.fetchone()
            rolled_back_count = int(r[0]) if r is not None else -1
            # ingest_sequence monotonic check (VAL-W2-055).
            async with conn.execute(
                "SELECT ingest_sequence FROM event_log_entries "
                "ORDER BY ingest_sequence ASC"
            ) as cur:
                seqs = [int(row[0]) async for row in cur]
            # The crash-recovered row added during recovery has its own seq.
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.crash_recovered'"
            ) as cur:
                r = await cur.fetchone()
            crash_count = int(r[0]) if r is not None else 0
            async with conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_pre_crash'"
            ) as cur:
                r = await cur.fetchone()
            pre_count = int(r[0]) if r is not None else 0
        return rolled_back_count, seqs, crash_count, pre_count

    rolled_back_count, seqs, crash_count, pre_count = asyncio.run(
        _verify_post_recovery()
    )
    assert rolled_back_count == 0, (
        f"VAL-W2-049: WAL recovery should have rolled back the uncommitted txn; "
        f"observed {rolled_back_count} rows with the rolled-back marker"
    )
    assert pre_count == 3, (
        f"VAL-W2-049: pre-crash committed rows should survive WAL replay; "
        f"observed {pre_count}/3"
    )
    assert crash_count == 1, (
        f"VAL-W2-049: exactly one sidecar.crash_recovered row expected; "
        f"observed {crash_count}"
    )

    # VAL-W2-055: ingest_sequence is strictly monotonic + no duplicates.
    assert seqs == sorted(set(seqs)), (
        f"VAL-W2-055: ingest_sequence must be strictly monotonic without "
        f"duplicates; observed {seqs}"
    )
    # No NULL values would have been excluded by the int() coercion above.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-055")
def test_committed_rows_contiguous_after_recovery(tmp_path: Path) -> None:
    """The 3 pre-crash committed rows have ingest_sequence 0, 1, 2."""
    pid, db_path, proc = _spawn_uncommitted_writer(tmp_path)
    _kill_and_reap(pid, proc)

    summary = recover_or_refuse(db_path)
    assert summary["recovery_invoked"] is True

    import asyncio

    async def _read_pre_crash_seqs():
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT ingest_sequence FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_pre_crash' "
                "ORDER BY ingest_sequence ASC"
            ) as cur,
        ):
            return [int(r[0]) async for r in cur]

    seqs = asyncio.run(_read_pre_crash_seqs())
    assert seqs == [0, 1, 2], (
        f"VAL-W2-055: committed pre-crash rows should be contiguous 0,1,2; "
        f"observed {seqs}"
    )
