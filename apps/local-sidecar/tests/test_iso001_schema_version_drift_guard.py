"""VAL-ISO-001: schema-version drift guard must be LIVE, not frozen at 8.

Defect (bug-hunt finding ISO-001): ``recovery.py`` hard-froze
``SUPPORTED_SCHEMA_VERSION = 8`` and migration 0008 seeded the
``_sidecar_schema_version`` row to version=8 with INSERT OR IGNORE. No
migration after 0008 ever UPDATEs the row, yet 33 migrations now exist
(0001..0033). A sidecar binary at the 0008 era opened against a DB
migrated to 0033 read observed_version=8, compared equal to the frozen
SUPPORTED=8, and PASSED the recovery gate -- the drift was silently
undetected (keystone invariant #10 bypass).

Fix: make the version authoritative and LIVE. ``SUPPORTED_SCHEMA_VERSION``
is driven from the count of migration ``.sql`` files (so every new
migration advances it automatically), and the observed version is read
from the live ``__schema_migrations`` set (the runner's authoritative
record of which migrations the DB has applied), falling back to the
legacy ``_sidecar_schema_version`` row only when ``__schema_migrations``
is absent (pre-runner / unit-seed DBs).

These tests are RED at base commit (frozen 8) and GREEN after the fix.

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
    recover_or_refuse,
)

_MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[1] / "migrations"
)


class _ExitInterceptedError(RuntimeError):
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


def _migration_filenames() -> list[str]:
    return [p.name for p in sorted(_MIGRATIONS_DIR.glob("*.sql"))]


def _seed_db_with_applied_migrations(
    db_path: Path,
    *,
    applied: list[str],
    frozen_legacy_version: int = 8,
) -> None:
    """Create a DB that records ``applied`` migration filenames in
    ``__schema_migrations`` and a legacy ``_sidecar_schema_version`` row
    frozen at ``frozen_legacy_version`` (mirroring migration 0008's
    INSERT OR IGNORE that never advances)."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename TEXT PRIMARY KEY, "
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        conn.executemany(
            "INSERT OR IGNORE INTO __schema_migrations (filename) VALUES (?)",
            [(name,) for name in applied],
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _sidecar_schema_version ("
            "  id INTEGER PRIMARY KEY CHECK (id = 0), "
            "  version INTEGER NOT NULL CHECK (version > 0), "
            "  installed_at TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT OR REPLACE INTO _sidecar_schema_version "
            "(id, version, installed_at) "
            "VALUES (0, ?, '2026-05-13T00:00:00.000000Z')",
            (frozen_legacy_version,),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_supported_schema_version_tracks_migration_count() -> None:
    """SUPPORTED_SCHEMA_VERSION must equal the live migration count, not
    the frozen literal 8 (RED at base: 8 != 33)."""
    expected = len(_migration_filenames())
    assert expected > 8, "fixture invariant: more than 8 migrations exist"
    observed = SUPPORTED_SCHEMA_VERSION
    assert observed == expected, (
        f"VAL-ISO-001: SUPPORTED_SCHEMA_VERSION must track the {expected} "
        f"applied migrations, not the frozen 8; got {observed}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_drift_detected_when_legacy_row_frozen_but_migrations_advanced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB migrated to the FULL set of migrations but whose legacy
    _sidecar_schema_version row is frozen at 8 must NOT silently pass:
    the live __schema_migrations count is authoritative.

    Under the frozen-8 mechanism this DB read observed=8 == SUPPORTED=8
    and passed (the defect). After the fix the observed count equals the
    full migration count and clears the gate via the live source, while a
    DB stuck at only 8 applied migrations is detected as drift below."""
    db_path = tmp_path / "fully-migrated.db"
    all_migrations = _migration_filenames()
    _seed_db_with_applied_migrations(
        db_path, applied=all_migrations, frozen_legacy_version=8
    )
    captured = _patch_exit(monkeypatch)

    summary = recover_or_refuse(db_path)
    # The fully-migrated DB clears the gate, and the observed version is
    # the LIVE migration count, not the frozen 8.
    assert captured == [], (
        "fully-migrated DB must clear the recovery gate via the live "
        "__schema_migrations count"
    )
    assert summary["schema_version"] == len(all_migrations), summary


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_drift_detected_when_db_behind_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB that applied only the 0008-era migrations (8 rows) opened by a
    binary whose migration set is the full count must be detected as drift
    and refused with exit 5 -- the frozen-8 mechanism missed this."""
    db_path = tmp_path / "behind.db"
    eight = _migration_filenames()[:8]
    assert len(eight) == 8
    _seed_db_with_applied_migrations(
        db_path, applied=eight, frozen_legacy_version=8
    )
    captured = _patch_exit(monkeypatch)

    with pytest.raises(_ExitInterceptedError):
        recover_or_refuse(db_path)

    assert len(captured) == 1
    code, envelope = captured[0]
    assert code == EXIT_CODE_SCHEMA_VERSION_UNKNOWN == 5
    assert envelope["error_class"] == "RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN"
    details = envelope["details"]
    assert details["observed_version"] == 8, details
    assert details["supported_version"] == SUPPORTED_SCHEMA_VERSION, details
