"""VAL-W2-055: event_log ordering preserved across crash + recovery boundary.

After a SIGKILL mid-transaction:

  - committed event_log_entries rows MUST survive WAL replay,
  - their ``ingest_sequence`` values MUST be strictly monotonic
    (no duplicates, no NULL),
  - gaps are acceptable per SQLite identity-column semantics, but
    rows committed in commit-order remain in commit-order.

This file complements ``test_crash_kill_minus_9.py`` with the
narrower focus: event_log integrity post-recovery. The shared
subprocess fixtures live in this file as well so the two test files
remain independently runnable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite
import pytest
from relay_sidecar.recovery import recover_or_refuse

# Re-use the subprocess helpers from the kill-9 test to keep one source
# of truth for "spawn -> SIGKILL -> reap -> recover". The pytest tests/
# directory is not a Python package (no __init__.py); pytest places it
# on sys.path so absolute-by-module-name import works.
from test_crash_kill_minus_9 import (  # noqa: E402
    _kill_and_reap,
    _spawn_uncommitted_writer,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-055")
def test_event_log_ingest_sequence_strictly_monotonic_post_recovery(
    tmp_path: Path,
) -> None:
    """No duplicate / NULL ingest_sequence after WAL replay."""
    pid, db_path, proc = _spawn_uncommitted_writer(tmp_path)
    _kill_and_reap(pid, proc)

    summary = recover_or_refuse(db_path)
    assert summary["recovery_invoked"] is True

    async def _read():
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT ingest_sequence FROM event_log_entries "
                "ORDER BY ingest_sequence ASC"
            ) as cur,
        ):
            return [row[0] async for row in cur]

    seqs = asyncio.run(_read())

    # No NULLs.
    assert all(s is not None for s in seqs), (
        f"VAL-W2-055: NULL ingest_sequence value observed: {seqs}"
    )

    # Strictly monotonic (no duplicates, ascending).
    int_seqs = [int(s) for s in seqs]
    assert int_seqs == sorted(set(int_seqs)), (
        f"VAL-W2-055: ingest_sequence must be strictly monotonic; "
        f"observed {int_seqs}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-055")
def test_committed_pre_crash_rows_preserved_in_commit_order(
    tmp_path: Path,
) -> None:
    """Pre-crash committed rows remain in commit-order after replay."""
    pid, db_path, proc = _spawn_uncommitted_writer(tmp_path)
    _kill_and_reap(pid, proc)

    summary = recover_or_refuse(db_path)
    assert summary["recovery_invoked"] is True

    async def _read():
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT ingest_sequence, payload FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_pre_crash' "
                "ORDER BY ingest_sequence ASC"
            ) as cur,
        ):
            return [(int(r[0]), r[1]) async for r in cur]

    rows = asyncio.run(_read())
    assert len(rows) == 3, (
        f"VAL-W2-055: pre-crash committed rows count mismatch: {rows!r}"
    )
    # The subprocess's loop wrote i=0,1,2 in that order.
    import json

    expected_i_sequence = [0, 1, 2]
    actual_i_sequence = []
    for _seq, payload_text in rows:
        payload = json.loads(payload_text)
        actual_i_sequence.append(int(payload["i"]))
    assert actual_i_sequence == expected_i_sequence, (
        f"VAL-W2-055: pre-crash payload ordering mismatch; expected "
        f"{expected_i_sequence}, observed {actual_i_sequence}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-055")
def test_uncommitted_row_absent_post_recovery(tmp_path: Path) -> None:
    """The killed-mid-INSERT row (event_type WILL_BE_ROLLED_BACK) is absent."""
    pid, db_path, proc = _spawn_uncommitted_writer(tmp_path)
    _kill_and_reap(pid, proc)

    summary = recover_or_refuse(db_path)
    assert summary["recovery_invoked"] is True

    async def _read():
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.WILL_BE_ROLLED_BACK'"
            ) as cur,
        ):
            row = await cur.fetchone()
            return int(row[0]) if row is not None else -1

    assert asyncio.run(_read()) == 0, (
        "VAL-W2-055: WAL recovery did not roll back the uncommitted INSERT"
    )
