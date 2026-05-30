"""VAL-W2-052: disk-full mid-write rolls back the transaction + raises RelayDiskFullError.

When ``transactional_db_write`` hits ``sqlite3.OperationalError`` whose
message identifies a disk-full condition (ENOSPC), the writer queue
MUST:

  1. Roll back the BEGIN IMMEDIATE transaction (no partial rows visible).
  2. Raise ``RelayDiskFullError`` carrying the table + scope_id + (best
     effort) os_errno for the observability surface.
  3. NOT corrupt the WAL file: ``PRAGMA integrity_check`` returns ``ok``
     after the failure.

Test methodology -- mocking, NOT real tmpfs.

Per CLAUDE.md test-discipline note "evaluate applicability of a test
to the platform before we blindly skip it": real tmpfs filling is
deeply platform-specific (Linux loop-mounted tmpfs vs macOS
hdiutil-mounted ramdisk vs Windows VHD). The portable, faithful
substitute is to inject ``sqlite3.OperationalError("database or disk
is full")`` (the canonical SQLite ENOSPC message) into the writer
connection's ``execute`` method via monkeypatch. SQLite emits this
exact message on real ENOSPC; the helper ``_is_disk_full_message`` in
db.py matches it. The mock therefore exercises EXACTLY the same code
path as a real disk-full error.

The W2.7 plan explicitly approved mocking here.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import aiosqlite
import pytest
from relay_sidecar.db import (
    SidecarDatabase,
    _is_disk_full_message,
    build_event_log_row,
)
from relay_sidecar.errors import RelayDiskFullError

_SCOPE_ID = "00000000-0000-0000-0000-000000000000"
_PROJECT_ID = "00000000-0000-0000-0000-000000000000"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-052")
def test_is_disk_full_message_matches_canonical_strings() -> None:
    """Helper recognises every canonical disk-full message form."""
    for msg in (
        "database or disk is full",
        "disk full",
        "no space left on device",
        "ENOSPC: no space left on device",
        "Some prefix database or disk is full some suffix",
    ):
        assert _is_disk_full_message(msg.lower()), msg

    for negative in (
        "database is locked",
        "database is busy",
        "syntax error",
        "no such table",
        "",
    ):
        assert not _is_disk_full_message(negative), negative


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-052")
@pytest.mark.asyncio
async def test_transactional_db_write_raises_disk_full_on_enospc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inject ENOSPC at INSERT; assert RelayDiskFullError + clean rollback."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        # Patch the writer connection's execute so any INSERT raises
        # OperationalError with the canonical disk-full message. We
        # only intercept the INSERT (not BEGIN IMMEDIATE / COMMIT /
        # ROLLBACK / SELECT) so the txn lifecycle around the failure
        # runs normally.
        real_execute = db._writer.execute  # type: ignore[union-attr]

        def _injected(sql, *args, **kwargs):
            up = sql.strip().upper()
            if up.startswith("INSERT INTO EVENT_LOG_ENTRIES"):
                # Construct the OperationalError with a chained
                # OSError(errno=28) so _extract_errno picks up ENOSPC.
                cause = OSError(28, "No space left on device")
                err = sqlite3.OperationalError(
                    "database or disk is full"
                )
                err.__cause__ = cause
                raise err
            return real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db._writer, "execute", _injected)  # type: ignore[union-attr]

        row = build_event_log_row(
            event_type="sidecar.test_enospc",
            scope_id=_SCOPE_ID,
            project_id=_PROJECT_ID,
            payload={"x": 1},
        )

        with pytest.raises(RelayDiskFullError) as exc_info:
            await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id=_SCOPE_ID,
                idempotency_key="enospc-test-1",
            )
        err = exc_info.value
        assert err.code == "RELAY-SIDECAR-011"
        assert err.error_class == "RELAY-SIDECAR-DISK-FULL"
        assert err.table == "event_log_entries"
        assert err.scope_id == _SCOPE_ID
        # os_errno may be None depending on chained __cause__ propagation;
        # not strictly required by VAL-W2-052 evidence.

        # Restore the real execute and confirm no partial row landed.
        monkeypatch.undo()
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_enospc'"
            ) as cur,
        ):
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0, (
            f"disk-full failure left partial rows: count={row}"
        )

        # Integrity check after rollback returns 'ok'.
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute("PRAGMA integrity_check") as cur,
        ):
            ic_row = await cur.fetchone()
        assert ic_row is not None
        assert str(ic_row[0]) == "ok", (
            f"PRAGMA integrity_check post-failure should be 'ok'; got {ic_row[0]!r}"
        )
    finally:
        # Defensive: undo monkeypatch in case the test errored before the
        # explicit undo above.
        monkeypatch.undo()
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-052")
def test_relay_disk_full_error_envelope_has_correct_fields() -> None:
    """to_envelope() returns the canonical 507 + structured details."""
    err = RelayDiskFullError(
        message="test message",
        table="event_log_entries",
        scope_id=_SCOPE_ID,
        os_errno=28,
    )
    env = err.to_envelope()
    assert env["code"] == "RELAY-SIDECAR-011"
    assert env["error_class"] == "RELAY-SIDECAR-DISK-FULL"
    assert env["http_status"] == 507
    assert env["message"] == "test message"
    # to_envelope() is typed dict[str, object]; narrow the nested details map
    # so the field reads type-check without changing the assertions.
    details = env["details"]
    assert isinstance(details, dict)
    assert details["table"] == "event_log_entries"
    assert details["scope_id"] == _SCOPE_ID
    assert details["os_errno"] == 28


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-052")
@pytest.mark.asyncio
async def test_subsequent_write_succeeds_after_disk_full_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After RelayDiskFullError, the next write succeeds (no stuck txn)."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        # Inject one ENOSPC then revert.
        real_execute = db._writer.execute  # type: ignore[union-attr]
        injection_active = {"on": True}

        def _injected(sql, *args, **kwargs):
            if injection_active["on"]:
                up = sql.strip().upper()
                if up.startswith("INSERT INTO EVENT_LOG_ENTRIES"):
                    raise sqlite3.OperationalError(
                        "database or disk is full"
                    )
            return real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db._writer, "execute", _injected)  # type: ignore[union-attr]

        row1 = build_event_log_row(
            event_type="sidecar.test_enospc_then_ok",
            scope_id=_SCOPE_ID,
            project_id=_PROJECT_ID,
            payload={"phase": "first"},
        )
        with pytest.raises(RelayDiskFullError):
            await db.transactional_db_write(
                table="event_log_entries",
                row=row1,
                scope_id=_SCOPE_ID,
                idempotency_key="enospc-recovery-1",
            )

        # Disable injection; the writer connection must be usable again.
        injection_active["on"] = False
        # Yield once so writer loop processes.
        await asyncio.sleep(0)

        row2 = build_event_log_row(
            event_type="sidecar.test_enospc_then_ok",
            scope_id=_SCOPE_ID,
            project_id=_PROJECT_ID,
            payload={"phase": "second"},
        )
        result = await db.transactional_db_write(
            table="event_log_entries",
            row=row2,
            scope_id=_SCOPE_ID,
            idempotency_key="enospc-recovery-2",
        )
        assert result.ok
        assert result.idempotent is False

        # Read back to confirm.
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT COUNT(*) FROM event_log_entries "
                "WHERE event_type = 'sidecar.test_enospc_then_ok'"
            ) as cur,
        ):
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        monkeypatch.undo()
        await db.close()
