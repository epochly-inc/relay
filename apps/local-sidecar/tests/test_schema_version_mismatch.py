"""VAL-W2-054: schema_version mismatch refuses startup with exit 5.

The recovery module's ``recover_or_refuse`` reads the
``_sidecar_schema_version.version`` value and compares it to the
constant ``SUPPORTED_SCHEMA_VERSION`` (currently 8, matching migration
0008). On mismatch the recovery path emits the
``RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN`` envelope and exits 5.

Per CLAUDE.md keystone invariant #10: engines refuse unknown versions
on write. VAL-W2-054 extends this to read-side / startup refusal.

The pristine-DB path (no _sidecar_schema_version table at all) is
explicitly tolerated -- recovery cannot tell apart "fresh install"
from "old schema". The lifespan startup will then run migration 0008
which seeds the table with version=SUPPORTED_SCHEMA_VERSION. This
"pristine" branch is covered by a separate test.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import NoReturn

import pytest
from relay_sidecar import recovery
from relay_sidecar.recovery import (
    EXIT_CODE_SCHEMA_VERSION_UNKNOWN,
    SUPPORTED_SCHEMA_VERSION,
    _read_schema_version,
    recover_or_refuse,
)


class _ExitInterceptedError(RuntimeError):
    """Sentinel for tests that intercept ``recovery.exit_with_structured_error``."""

    def __init__(self, code: int, envelope: dict) -> None:
        super().__init__(f"intercepted exit({code})")
        self.code = code
        self.envelope = envelope


def _patch_exit(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, dict]]:
    captured: list[tuple[int, dict]] = []

    def _intercepted(code: int, envelope: dict) -> NoReturn:
        captured.append((code, envelope))
        raise _ExitInterceptedError(code, envelope)

    monkeypatch.setattr(recovery, "exit_with_structured_error", _intercepted)
    return captured


def _seed_db_with_schema_version(db_path: Path, version: int) -> None:
    """Create a minimal DB carrying ``_sidecar_schema_version.version=<version>``."""
    conn = sqlite3.connect(str(db_path))
    try:
        # Create the schema_version table the way migration 0008 does.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _sidecar_schema_version ("
            "  id INTEGER PRIMARY KEY CHECK (id = 0), "
            "  version INTEGER NOT NULL CHECK (version > 0), "
            "  installed_at TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT OR REPLACE INTO _sidecar_schema_version (id, version, installed_at) "
            "VALUES (0, ?, '2026-05-13T00:00:00.000000Z')",
            (version,),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_read_schema_version_returns_seeded_value(tmp_path: Path) -> None:
    """``_read_schema_version`` returns the integer from the seeded row."""
    db_path = tmp_path / "v9.db"
    _seed_db_with_schema_version(db_path, 9)
    assert _read_schema_version(db_path) == 9


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_read_schema_version_returns_none_on_pristine_db(tmp_path: Path) -> None:
    """A DB without ``_sidecar_schema_version`` returns None, not an error."""
    db_path = tmp_path / "pristine.db"
    # Bare valid DB without the schema_version table.
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE foo (id INTEGER)")
    conn.commit()
    conn.close()
    assert _read_schema_version(db_path) is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_recover_or_refuse_exits_5_on_unknown_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB carrying an unknown version triggers exit 5 + structured envelope."""
    db_path = tmp_path / "future.db"
    # Use SUPPORTED + 100 as a clearly unknown version.
    unknown_version = SUPPORTED_SCHEMA_VERSION + 100
    _seed_db_with_schema_version(db_path, unknown_version)
    captured = _patch_exit(monkeypatch)

    with pytest.raises(_ExitInterceptedError):
        recover_or_refuse(db_path)

    assert len(captured) == 1
    code, envelope = captured[0]
    assert code == EXIT_CODE_SCHEMA_VERSION_UNKNOWN == 5
    assert envelope["code"] == "RELAY-SIDECAR-013"
    assert envelope["error_class"] == "RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN"
    details = envelope["details"]
    assert details["observed_version"] == unknown_version
    assert details["supported_version"] == SUPPORTED_SCHEMA_VERSION


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_recover_or_refuse_passes_on_supported_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB carrying SUPPORTED_SCHEMA_VERSION clears the recovery gate."""
    db_path = tmp_path / "current.db"
    _seed_db_with_schema_version(db_path, SUPPORTED_SCHEMA_VERSION)
    captured = _patch_exit(monkeypatch)

    summary = recover_or_refuse(db_path)
    assert summary["schema_version"] == SUPPORTED_SCHEMA_VERSION
    assert captured == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-054")
def test_recover_or_refuse_tolerates_pristine_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pristine DBs (no schema-version table) do NOT trigger exit 5."""
    db_path = tmp_path / "pristine.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE foo (id INTEGER)")
    conn.commit()
    conn.close()
    captured = _patch_exit(monkeypatch)

    summary = recover_or_refuse(db_path)
    assert summary["schema_version"] is None
    assert captured == [], (
        "pristine DB (pre-migration) MUST NOT trigger exit 5; "
        "the lifespan startup runs migration 0008 to seed the row"
    )
