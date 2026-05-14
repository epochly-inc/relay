"""VAL-W2-053: WAL checkpoint failure on shutdown surfaces error and preserves WAL.

If ``PRAGMA wal_checkpoint(TRUNCATE)`` fails on graceful shutdown
(e.g., a reader holds an old snapshot beyond the busy_timeout window),
the lifespan tear-down MUST:

  1. Detect the failure: SQLite returns ``(busy=1, log_size,
     frames_checkpointed)`` from the PRAGMA when it could not acquire
     the writer/reader lock for TRUNCATE.
  2. Set ``state.quiesce.wal_checkpoint_failed = True`` so the CLI
     entrypoint can exit with code 6.
  3. Emit the structured ``RELAY-SIDECAR-WAL-CHECKPOINT-FAILED``
     envelope to stderr (subprocess tests parse it).
  4. PRESERVE the WAL file (do NOT delete) so the next-startup
     recovery can replay any uncheckpointed frames.

In-process tests assert the flag + the stderr envelope. The
exit-code-6 behaviour is the responsibility of the W5 CLI entrypoint
(which inspects ``state.quiesce.wal_checkpoint_failed`` after the
lifespan exits and calls ``sys.exit(6)``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from relay_sidecar import runtime as runtime_mod
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-wal-cp-fail-token"  # noqa: S105
    return HealthState(
        port=49993,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-053")
@pytest.mark.asyncio
async def test_wal_checkpoint_failure_sets_flag_and_emits_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Force the status helper to report failure; assert state + envelope."""
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    wal_path = db_path.parent / (db_path.name + "-wal")

    # Patch BOTH checkpoint helpers so the WAL is never truncated. The
    # original ``_wal_checkpoint_truncate`` is invoked first by the
    # lifespan (preserved for VAL-W2-045 monkeypatch surface); replacing
    # it with a no-op coroutine ensures the WAL frames stay on disk.
    # The status-aware helper then reports failure to drive the
    # VAL-W2-053 envelope + flag path.
    fake_reason = "PRAGMA wal_checkpoint(TRUNCATE) returned busy=1; reader holds snapshot"

    async def _noop_checkpoint(database):
        return None

    async def _failing_checkpoint(database):
        return (False, fake_reason)

    monkeypatch.setattr(
        runtime_mod,
        "_wal_checkpoint_truncate",
        _noop_checkpoint,
    )
    monkeypatch.setattr(
        runtime_mod,
        "_wal_checkpoint_truncate_with_status",
        _failing_checkpoint,
    )

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        # Drive at least one write so the WAL file exists pre-shutdown.
        from relay_sidecar.db import build_event_log_row
        from relay_sidecar.primitives.transactional_db_write import (
            transactional_db_write,
        )

        for i in range(3):
            row = build_event_log_row(
                event_type="sidecar.test_wal_cp_fail",
                scope_id="00000000-0000-0000-0000-000000000000",
                project_id="00000000-0000-0000-0000-000000000000",
                payload={"i": i},
            )
            await transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id="00000000-0000-0000-0000-000000000000",
                idempotency_key=f"wal-cp-fail-{i}",
            )

        assert wal_path.exists(), f"WAL file not created at {wal_path}"
        # Drive a request so the lifespan keeps state.runtime accessible.
        r = await client.get("/diagnostics/sqlite")
        assert r.status_code == 200

        runtime = app.state.runtime
        # The failure has not yet surfaced -- it fires during lifespan exit.
        assert runtime.quiesce.wal_checkpoint_failed is False

    # After lifespan exit, the failure flag is set.
    runtime_post = app.state.runtime
    assert runtime_post.quiesce.wal_checkpoint_failed is True, (
        "VAL-W2-053: lifespan must set wal_checkpoint_failed=True on PRAGMA failure"
    )
    assert fake_reason in runtime_post.quiesce.wal_checkpoint_failure_reason

    # Stderr should carry exactly one structured envelope JSON line for the failure.
    captured = capsys.readouterr()
    matched = None
    for line in captured.err.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(parsed, dict)
            and parsed.get("error_class") == "RELAY-SIDECAR-WAL-CHECKPOINT-FAILED"
        ):
            matched = parsed
            break
    assert matched is not None, (
        f"expected RELAY-SIDECAR-WAL-CHECKPOINT-FAILED envelope on stderr; "
        f"stderr was:\n{captured.err}"
    )
    assert matched["code"] == "RELAY-SIDECAR-012"
    assert matched["exit_code"] == 6
    assert matched["details"]["wal_present"] is True
    assert "underlying_error" in matched["details"]

    # WAL file MUST still be observable post-shutdown -- either at the
    # canonical ``<db>-wal`` path (sqlite preserved it because of
    # uncheckpointed frames) OR at the ``<db>-wal.preserved`` sentinel
    # path that the lifespan copies on the failure branch (because
    # sqlite's libsqlite removed ``<db>-wal`` on the last connection
    # close despite frames present).
    preserved_path = wal_path.parent / (wal_path.name + ".preserved")
    assert wal_path.exists() or preserved_path.exists(), (
        "VAL-W2-053: WAL file MUST be preserved on checkpoint failure; "
        f"neither {wal_path} nor {preserved_path} exists post-shutdown"
    )
    # If both routes preserved bytes, prefer the .preserved sentinel as
    # the forensic copy.
    preserved_size = (
        preserved_path.stat().st_size if preserved_path.exists() else 0
    )
    if not wal_path.exists():
        assert preserved_size > 0, (
            f"<db>-wal.preserved exists but is empty: size={preserved_size}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-053")
@pytest.mark.asyncio
async def test_status_helper_reports_failure_on_busy_pragma_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helper returns (False, reason) when PRAGMA returns busy != 0."""
    from relay_sidecar.db import SidecarDatabase
    from relay_sidecar.runtime import _wal_checkpoint_truncate_with_status

    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        # Patch the writer connection's execute so wal_checkpoint returns
        # a busy=1 row.
        real_execute = db._writer.execute  # type: ignore[union-attr]

        class _FakeBusyCursor:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def fetchall(self):
                return [(1, 5, 0)]  # busy=1 indicates failure

        def _injected(sql, *args, **kwargs):
            up = sql.strip().upper()
            if up.startswith("PRAGMA WAL_CHECKPOINT"):
                return _FakeBusyCursor()
            return real_execute(sql, *args, **kwargs)

        monkeypatch.setattr(db._writer, "execute", _injected)  # type: ignore[union-attr]

        ok, reason = await _wal_checkpoint_truncate_with_status(db)
        assert ok is False
        assert "busy=1" in reason
    finally:
        monkeypatch.undo()
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-053")
@pytest.mark.asyncio
async def test_status_helper_reports_success_on_clean_checkpoint(
    tmp_path: Path,
) -> None:
    """A real PRAGMA on a clean WAL returns (True, '')."""
    from relay_sidecar.db import SidecarDatabase, build_event_log_row
    from relay_sidecar.runtime import _wal_checkpoint_truncate_with_status

    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        # Seed a row so there is something to checkpoint.
        row = build_event_log_row(
            event_type="sidecar.test_clean_cp",
            scope_id="00000000-0000-0000-0000-000000000000",
            project_id="00000000-0000-0000-0000-000000000000",
            payload={"i": 1},
        )
        await db.transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id="00000000-0000-0000-0000-000000000000",
            idempotency_key="clean-cp-1",
        )
        ok, reason = await _wal_checkpoint_truncate_with_status(db)
        assert ok is True, f"clean checkpoint should succeed; reason={reason!r}"
        assert reason == ""
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-053")
def test_emit_wal_checkpoint_failed_and_exit_writes_envelope_and_exits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The standalone exit helper writes envelope + sys.exit(6)."""
    from relay_sidecar.recovery import emit_wal_checkpoint_failed_and_exit

    db_path = tmp_path / "fake.db"
    db_path.write_bytes(b"")
    wal_path = db_path.parent / (db_path.name + "-wal")
    wal_path.write_bytes(b"x" * 32)

    with pytest.raises(SystemExit) as exc_info:
        emit_wal_checkpoint_failed_and_exit(
            db_path, underlying_error="reader-held-snapshot"
        )
    assert exc_info.value.code == 6

    captured = capsys.readouterr()
    line = captured.err.strip()
    parsed = json.loads(line)
    assert parsed["code"] == "RELAY-SIDECAR-012"
    assert parsed["error_class"] == "RELAY-SIDECAR-WAL-CHECKPOINT-FAILED"
    assert parsed["details"]["wal_present"] is True
    assert parsed["details"]["wal_size_bytes"] == 32
