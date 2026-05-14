"""VAL-W2-051: corrupted SQLite refuses startup with structured error.

The recovery module ``relay_sidecar.recovery.recover_or_refuse``:

  1. Runs ``PRAGMA quick_check`` in a worker thread with a 2-second
     wall-clock budget. Clean DBs MUST complete inside the budget.
  2. On any non-``ok`` result OR on timeout, runs the full untimed
     ``PRAGMA integrity_check`` for diagnostic detail.
  3. Emits the ``RELAY-SIDECAR-DB-CORRUPT`` envelope to stderr and
     calls ``sys.exit(3)`` (per spec P.1 mapping).
  4. NEVER overwrites or deletes the on-disk database file.

Because the recovery code calls ``sys.exit``, in-process tests
monkeypatch ``recovery.exit_with_structured_error`` to capture the
envelope without actually exiting. A separate subprocess-based test
verifies the real ``sys.exit`` path.

Subprocess-based test for VAL-W2-049 (kill -9) lives in
``test_crash_kill_minus_9.py``; this file focuses on the corrupt-DB
refusal path.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import NoReturn

import pytest
from relay_sidecar import recovery
from relay_sidecar.recovery import (
    EXIT_CODE_DB_CORRUPT,
    QUICK_CHECK_BUDGET_S,
    full_integrity_check,
    quick_check_with_budget,
    recover_or_refuse,
)


class _ExitInterceptedError(RuntimeError):
    """Raised in tests that intercept ``recovery.exit_with_structured_error``."""

    def __init__(self, code: int, envelope: dict) -> None:
        super().__init__(f"intercepted exit({code})")
        self.code = code
        self.envelope = envelope


def _patch_exit(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, dict]]:
    """Replace ``recovery.exit_with_structured_error`` with an interceptor.

    Returns a mutable list that callers inspect to find captured exits.
    The replacement raises ``_ExitInterceptedError`` so the recovery
    flow unwinds (mirrors the NoReturn semantics).
    """
    captured: list[tuple[int, dict]] = []

    def _intercepted(code: int, envelope: dict) -> NoReturn:
        captured.append((code, envelope))
        raise _ExitInterceptedError(code, envelope)

    monkeypatch.setattr(recovery, "exit_with_structured_error", _intercepted)
    return captured


def _seed_clean_db(db_path: Path) -> None:
    """Create a minimal valid SQLite database the recovery path can scan."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE event_log_entries (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()


def _seed_corrupted_db(db_path: Path) -> None:
    """Write garbage bytes that begin with the SQLite magic but are damaged."""
    # SQLite magic header is 16 bytes "SQLite format 3\0" followed by a
    # full schema. A truncated or randomly-mangled file fails quick_check.
    db_path.write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_quick_check_returns_ok_on_clean_db(tmp_path: Path) -> None:
    """VAL-W2-051 fast-path: clean DB returns ``ok`` inside the budget."""
    db_path = tmp_path / "clean.db"
    _seed_clean_db(db_path)
    start = time.monotonic()
    status, payload = quick_check_with_budget(db_path)
    elapsed = time.monotonic() - start
    assert status == "ok", f"clean DB quick_check returned {status!r}: {payload!r}"
    assert payload is None
    assert elapsed <= QUICK_CHECK_BUDGET_S, (
        f"fast-path clean DB took {elapsed:.3f}s > budget {QUICK_CHECK_BUDGET_S}s"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_quick_check_returns_error_on_corrupt_db(tmp_path: Path) -> None:
    """quick_check on a corrupt file returns ``error`` (or open failure)."""
    db_path = tmp_path / "corrupt.db"
    _seed_corrupted_db(db_path)
    status, payload = quick_check_with_budget(db_path)
    assert status == "error", (
        f"corrupt DB quick_check should return 'error', got {status!r}/{payload!r}"
    )
    assert payload is not None and payload != "ok"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_full_integrity_check_returns_diagnostic_on_corrupt_db(
    tmp_path: Path,
) -> None:
    """Slow-path integrity_check returns a diagnostic string."""
    db_path = tmp_path / "corrupt.db"
    _seed_corrupted_db(db_path)
    diagnostic = full_integrity_check(db_path)
    assert diagnostic != "ok", f"expected non-ok diagnostic; got {diagnostic!r}"
    assert isinstance(diagnostic, str) and diagnostic


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_recover_or_refuse_exits_3_on_corrupt_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``recover_or_refuse`` exits 3 with RELAY-SIDECAR-DB-CORRUPT."""
    db_path = tmp_path / "corrupt.db"
    _seed_corrupted_db(db_path)
    captured = _patch_exit(monkeypatch)
    db_size_before = db_path.stat().st_size

    with pytest.raises(_ExitInterceptedError) as exc_info:
        recover_or_refuse(db_path)
    assert exc_info.value.code == EXIT_CODE_DB_CORRUPT
    assert len(captured) == 1
    code, envelope = captured[0]
    assert code == EXIT_CODE_DB_CORRUPT == 3
    assert envelope["code"] == "RELAY-SIDECAR-010"
    assert envelope["error_class"] == "RELAY-SIDECAR-DB-CORRUPT"
    assert "integrity_check" in envelope["details"]

    # File size unchanged: recovery never clobbers a corrupt DB.
    db_size_after = db_path.stat().st_size
    assert db_size_after == db_size_before, (
        f"recovery clobbered the DB file: before={db_size_before} after={db_size_after}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_recover_or_refuse_succeeds_on_clean_db_under_budget(
    tmp_path: Path,
) -> None:
    """Clean DB completes recovery (no exit) within the 2-second budget."""
    db_path = tmp_path / "clean.db"
    _seed_clean_db(db_path)
    start = time.monotonic()
    summary = recover_or_refuse(db_path)
    elapsed = time.monotonic() - start
    assert summary["quick_check_status"] == "ok", summary
    assert elapsed <= QUICK_CHECK_BUDGET_S, (
        f"fast-path total elapsed {elapsed:.3f}s exceeds budget {QUICK_CHECK_BUDGET_S}s"
    )
    assert summary["recovery_invoked"] is False  # no WAL frames present
    assert summary["crash_recovery_event_written"] is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-051")
def test_exit_with_structured_error_writes_json_to_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``exit_with_structured_error`` emits one JSON line to stderr then exits."""
    envelope = {
        "code": "RELAY-SIDECAR-010",
        "error_class": "RELAY-SIDECAR-DB-CORRUPT",
        "message": "test envelope",
        "details": {"db_path": "/tmp/x.db"},
    }
    with pytest.raises(SystemExit) as exc_info:
        recovery.exit_with_structured_error(3, envelope)
    assert exc_info.value.code == 3
    captured = capsys.readouterr()
    # The JSON line is on stderr; capsys captures both stdout and stderr.
    line = captured.err.strip()
    parsed = json.loads(line)
    assert parsed == envelope, f"stderr envelope mismatch: {parsed!r}"
