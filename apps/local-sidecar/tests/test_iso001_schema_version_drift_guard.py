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

Follow-on defect (structural-review schema-drift upgrade-gate, P1): the
LIVE version made the gate's strict ``!=`` comparison upgrade-breaking.
``recover_or_refuse`` runs BEFORE the migration runner (runtime.py:510 in
lifespan, runtime.py:5802 in run_uvicorn, both before
``SidecarDatabase.open`` -> ``_run_migrations``). A production DB at
N-1 applied migrations, opened by a binary shipping migration N, read
observed=N-1 != supported=N and exited 5 BEFORE migrations could run --
so the migration that would reconcile the count was permanently
unreachable. EVERY incremental upgrade bricked the sidecar.

Directional fix: the gate refuses ONLY on ``observed > supported`` (DB
AHEAD of binary = genuine unsafe DOWNGRADE; no down-migrations exist).
``observed == supported`` is current; ``observed < supported`` is the
normal UPGRADE path and proceeds so the runner applies the pending
migrations. Downgrade refusal (exit 5 /
RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN) is preserved.

These tests are RED at base commit (frozen 8 / strict-!= gate) and GREEN
after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import shutil
import sqlite3
from pathlib import Path
from typing import NoReturn

import pytest
from relay_sidecar import recovery
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.recovery import (
    EXIT_CODE_SCHEMA_VERSION_UNKNOWN,
    SUPPORTED_SCHEMA_VERSION,
    _read_observed_schema_version,
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
def test_upgrade_path_db_behind_binary_boots_does_not_exit_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """UPGRADE PATH (schema-drift upgrade-gate fix).

    A DB that applied only the first N-1 migrations (``observed <
    supported``), opened by a binary shipping the Nth migration, is the
    NORMAL incremental-upgrade case. The recovery gate MUST NOT exit 5:
    refusing here bricked every upgrade because the gate runs BEFORE the
    migration runner, so the Nth migration that would reconcile the count
    could never run.

    The earlier strict ``!=`` codified the WRONG direction (this test
    previously asserted observed<supported -> exit 5). Inverted: the gate
    must let boot proceed so ``SidecarDatabase.open`` -> ``_run_migrations``
    applies the pending migration(s)."""
    db_path = tmp_path / "behind.db"
    all_migrations = _migration_filenames()
    behind = all_migrations[:-1]
    assert len(behind) == SUPPORTED_SCHEMA_VERSION - 1, (
        "fixture invariant: behind set is exactly one migration short of HEAD"
    )
    _seed_db_with_applied_migrations(
        db_path, applied=behind, frozen_legacy_version=8
    )
    captured = _patch_exit(monkeypatch)

    summary = recover_or_refuse(db_path)

    assert captured == [], (
        "schema-drift upgrade-gate: a DB BEHIND the binary (observed < "
        "supported) is the normal upgrade path and MUST NOT exit 5; the "
        f"migration runner reconciles it on open. envelope(s)={captured}"
    )
    # The observed version at the gate is the (count - 1) live migration
    # count; reconciliation to ``supported`` happens in the migration
    # runner (covered end-to-end by the e2e test below).
    assert summary["schema_version"] == SUPPORTED_SCHEMA_VERSION - 1, summary


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_downgrade_db_ahead_of_binary_still_exits_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DOWNGRADE PATH (preserved safety gate).

    A DB AHEAD of the binary (``observed > supported``) means a NEWER
    binary migrated this DB and an OLDER binary is now opening it -- a
    genuine, UNSAFE downgrade. There are no down-migrations, and
    destructive ALTER/DROP/RENAME migrations leave the older binary
    facing a schema it does not understand. The gate MUST still refuse
    with exit 5 / RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN."""
    db_path = tmp_path / "ahead.db"
    all_migrations = _migration_filenames()
    # Inject a higher __schema_migrations count than the binary ships by
    # recording one extra (synthetic) future migration filename.
    ahead = [*all_migrations, "9999_future_migration_from_newer_binary.sql"]
    _seed_db_with_applied_migrations(
        db_path, applied=ahead, frozen_legacy_version=8
    )
    captured = _patch_exit(monkeypatch)

    with pytest.raises(_ExitInterceptedError):
        recover_or_refuse(db_path)

    assert len(captured) == 1
    code, envelope = captured[0]
    assert code == EXIT_CODE_SCHEMA_VERSION_UNKNOWN == 5
    assert envelope["error_class"] == "RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN"
    details = envelope["details"]
    assert details["observed_version"] == SUPPORTED_SCHEMA_VERSION + 1, details
    assert details["supported_version"] == SUPPORTED_SCHEMA_VERSION, details
    # Filename-set model: the foreign migration is surfaced explicitly.
    assert "9999_future_migration_from_newer_binary.sql" in (
        details.get("unknown_migrations") or []
    ), details


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_count_matches_but_foreign_filename_refuses_exit_5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DEEPER FAIL-OPEN (codex-review schema-drift-filename-set, P1).

    The prior gate compared the COUNT of applied migrations against the
    shipped count. COUNT is not identity: a production DB can have
    ``COUNT(__schema_migrations) == SUPPORTED`` while ONE applied row is an
    UNKNOWN/foreign migration filename (e.g. a future or out-of-band
    migration) AND one shipped migration is ABSENT. The count matches, the
    directional ``observed > supported`` check sees ``observed ==
    supported`` and PASSES, and the OLD binary boots against an UNKNOWN
    schema -- a fail-open.

    Fix: drive the decision from the FILENAME SET, not the count. ``applied
    - shipped`` is non-empty here (the foreign filename), so the gate MUST
    refuse with exit 5 / RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN.

    RED at base (count == supported -> passes); GREEN after the
    filename-set fix."""
    db_path = tmp_path / "count-match-foreign.db"
    all_migrations = _migration_filenames()
    # Same COUNT as shipped, but swap the LAST shipped migration out for a
    # FOREIGN one: drop the real HEAD migration, add an unknown filename.
    # len(applied) == len(shipped) == SUPPORTED, yet identity differs.
    foreign = "9998_foreign_out_of_band_migration.sql"
    applied = [*all_migrations[:-1], foreign]
    assert len(applied) == SUPPORTED_SCHEMA_VERSION, (
        "fixture invariant: count must equal SUPPORTED so the OLD count "
        "check would have passed (proving the deeper fail-open)"
    )
    assert foreign not in all_migrations, "fixture invariant: foreign is unknown"
    _seed_db_with_applied_migrations(
        db_path, applied=applied, frozen_legacy_version=8
    )
    captured = _patch_exit(monkeypatch)

    with pytest.raises(_ExitInterceptedError):
        recover_or_refuse(db_path)

    assert len(captured) == 1, (
        "filename-set drift: a foreign applied migration (even when the "
        f"count matches) MUST refuse with exit 5; captured={captured}"
    )
    code, envelope = captured[0]
    assert code == EXIT_CODE_SCHEMA_VERSION_UNKNOWN == 5
    assert envelope["error_class"] == "RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN"
    details = envelope["details"]
    # The foreign filename is surfaced so an operator can diagnose the drift.
    assert foreign in (details.get("unknown_migrations") or []), details
    # The missing-but-shipped HEAD migration is NOT reported as unknown
    # (it is behind, not foreign); only the foreign extra is unknown.
    assert all_migrations[-1] not in (
        details.get("unknown_migrations") or []
    ), details
    assert details["supported_version"] == SUPPORTED_SCHEMA_VERSION, details


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-001")
def test_e2e_upgrade_at_head_minus_one_boots_and_applies_pending_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """END-TO-END (schema-drift upgrade-gate fix): the real boot order.

    Builds a DB at the genuine HEAD~1 state by running the REAL migration
    runner against a migrations dir containing only the first N-1 ``.sql``
    files, then reproduces production boot order on the FULL set:

        recover_or_refuse(db) -> SidecarDatabase(full_migrations).open()

    Proves the new migration N (currently 0034, and any future one) is NOT
    bricked: the gate lets boot proceed and the runner applies the pending
    migration so the observed live count reconciles to
    ``SUPPORTED_SCHEMA_VERSION``."""
    all_migrations = _migration_filenames()
    assert len(all_migrations) == SUPPORTED_SCHEMA_VERSION

    # Stage a migrations dir holding only the first N-1 real migration
    # files, then build the HEAD~1 DB with the REAL runner (not a stubbed
    # __schema_migrations seed) so the schema is genuinely at the prior
    # release.
    head_minus_one_dir = tmp_path / "migrations_head_minus_one"
    head_minus_one_dir.mkdir()
    for name in all_migrations[:-1]:
        shutil.copy2(_MIGRATIONS_DIR / name, head_minus_one_dir / name)

    db_path = tmp_path / "sidecar.db"

    async def _build_head_minus_one() -> None:
        db = SidecarDatabase(
            db_path=db_path,
            reader_count=1,
            migrations_dir=head_minus_one_dir,
        )
        await db.open()
        await db.close()

    asyncio.run(_build_head_minus_one())

    # Sanity: the DB is genuinely one migration behind the binary.
    assert _read_observed_schema_version(db_path) == SUPPORTED_SCHEMA_VERSION - 1

    # Production boot order: recovery gate FIRST (it ran before migrations
    # at runtime.py:510 / :5802). With the fix, observed < supported is the
    # upgrade path and the gate must not refuse.
    captured = _patch_exit(monkeypatch)
    summary = recover_or_refuse(db_path)
    assert captured == [], (
        "e2e upgrade: HEAD~1 DB must clear the recovery gate so migrations "
        f"can run; envelope(s)={captured}"
    )
    assert summary["schema_version"] == SUPPORTED_SCHEMA_VERSION - 1, summary

    # Then SidecarDatabase.open() -> _run_migrations applies the pending
    # migration(s) against the FULL (default) migrations dir, reconciling
    # the live count to supported.
    async def _open_full() -> None:
        db = SidecarDatabase(db_path=db_path, reader_count=1)
        await db.open()
        await db.close()

    asyncio.run(_open_full())

    assert _read_observed_schema_version(db_path) == SUPPORTED_SCHEMA_VERSION, (
        "e2e upgrade: after boot the migration runner must reconcile the "
        "live __schema_migrations count to SUPPORTED_SCHEMA_VERSION"
    )
