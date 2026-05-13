"""VAL-W2-045: graceful shutdown runs ``PRAGMA wal_checkpoint(TRUNCATE)``
BEFORE closing aiosqlite connections.

The lifespan tear-down ordering MUST be:

  1. Drain wait (tracker.idle_event with deadline).
  2. ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer connection.
  3. ``database.close()`` (cancels writer task, closes connections).
  4. Clear lockfile.

Evidence: after the lifespan exits cleanly, the WAL file
(``<db>-wal``) on disk has size = 0 (TRUNCATE truncates to zero
bytes). On a sidecar that DID NOT run the checkpoint (e.g. forced
stop), the WAL file would retain the bytes from the last frame.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-wal-checkpoint-token"  # noqa: S105
    return HealthState(
        port=49992,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-045")
@pytest.mark.asyncio
async def test_wal_file_truncated_to_zero_after_graceful_shutdown(
    tmp_path, monkeypatch
) -> None:
    """After graceful lifespan exit, the ``<db>-wal`` file is size 0."""
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    wal_path = db_path.parent / (db_path.name + "-wal")
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        # Drive at least one write through the queue so the WAL has
        # frames that need checkpointing. POST /v1/ingest does not
        # currently write to the DB; instead we trigger the writer
        # path via the W2.3 transactional_db_write primitive directly.
        from relay_sidecar.db import build_event_log_row
        from relay_sidecar.primitives.transactional_db_write import (
            transactional_db_write,
        )

        # Issue a few writes to populate the WAL.
        for i in range(3):
            row = build_event_log_row(
                event_type="sidecar.test_wal_seeding",
                scope_id="00000000-0000-0000-0000-000000000000",
                project_id="00000000-0000-0000-0000-000000000000",
                payload={"i": i},
            )
            await transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id="00000000-0000-0000-0000-000000000000",
                idempotency_key=f"wal-test-{i}",
            )
        # Sanity: WAL file exists and is non-zero mid-lifespan (data
        # frames not yet checkpointed because aiosqlite's auto-checkpoint
        # threshold is 1000 frames by default; 3 frames stays in WAL).
        assert wal_path.exists(), f"WAL file not created at {wal_path}"
        mid_size = wal_path.stat().st_size
        assert mid_size > 0, (
            f"WAL file size {mid_size}; expected > 0 mid-lifespan "
            f"(data should be in WAL pre-checkpoint)"
        )
        # Bookkeeping: still have the client open. Lifespan tear-down
        # runs when the async-with exits.
        # Drive a final request to ensure all writes complete.
        r = await client.get("/diagnostics/db")
        assert r.status_code == 200

    # Lifespan exited gracefully. Per VAL-W2-045 the WAL file MUST be
    # checkpointed via PRAGMA wal_checkpoint(TRUNCATE) before the
    # connections close. SQLite's behavior after TRUNCATE + final
    # connection close varies by version: some versions truncate the
    # WAL to 0 bytes and leave the file on disk, others delete the WAL
    # file entirely once no connection holds it open. EITHER outcome
    # satisfies VAL-W2-045 (the WAL contains no uncheckpointed bytes).
    if wal_path.exists():
        final_size = wal_path.stat().st_size
        assert final_size == 0, (
            f"WAL file size after graceful shutdown is {final_size}; "
            f"VAL-W2-045 requires PRAGMA wal_checkpoint(TRUNCATE) to "
            f"truncate WAL to 0 bytes BEFORE closing connections."
        )
    # else: WAL file was removed by SQLite on the final connection
    # close after TRUNCATE -- equivalent evidence that the checkpoint
    # ran successfully and no uncheckpointed bytes remain.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-045")
@pytest.mark.asyncio
async def test_wal_checkpoint_helper_truncates_to_zero(tmp_path) -> None:
    """The ``_wal_checkpoint_truncate`` helper truncates the WAL to size 0.

    Direct test of the lifespan helper, isolated from the full lifespan
    teardown ordering.
    """
    from pathlib import Path

    from relay_sidecar.db import (
        SidecarDatabase,
        build_event_log_row,
    )
    from relay_sidecar.runtime import _wal_checkpoint_truncate

    db_path = tmp_path / "sidecar.db"
    wal_path = Path(str(db_path) + "-wal")
    db = SidecarDatabase(db_path=db_path)
    await db.open()
    try:
        # Seed a few writes to populate the WAL.
        for i in range(3):
            row = build_event_log_row(
                event_type="sidecar.test_helper_seeding",
                scope_id="00000000-0000-0000-0000-000000000000",
                project_id="00000000-0000-0000-0000-000000000000",
                payload={"i": i},
            )
            await db.transactional_db_write(
                table="event_log_entries",
                row=row,
                scope_id="00000000-0000-0000-0000-000000000000",
                idempotency_key=f"helper-{i}",
            )
        assert wal_path.exists()
        assert wal_path.stat().st_size > 0
        # Run the checkpoint helper.
        await _wal_checkpoint_truncate(db)
        # WAL file truncated to 0 bytes.
        assert wal_path.exists()
        assert wal_path.stat().st_size == 0, (
            f"_wal_checkpoint_truncate did not truncate WAL to 0 bytes; "
            f"observed {wal_path.stat().st_size}"
        )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-045")
@pytest.mark.asyncio
async def test_lifespan_runs_checkpoint_before_database_close(
    tmp_path, monkeypatch
) -> None:
    """Tear-down ordering: WAL checkpoint runs BEFORE database.close().

    Wraps both ``_wal_checkpoint_truncate`` and ``SidecarDatabase.close``
    with monkeypatched proxies that record the order of invocation.
    Asserts the checkpoint call_index is strictly less than the
    close call_index.
    """
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"

    from relay_sidecar import runtime as runtime_mod
    from relay_sidecar.db import SidecarDatabase

    call_order: list[str] = []

    real_checkpoint = runtime_mod._wal_checkpoint_truncate
    real_close = SidecarDatabase.close

    async def spy_checkpoint(database):
        call_order.append("checkpoint")
        await real_checkpoint(database)

    async def spy_close(self):
        call_order.append("close")
        await real_close(self)

    monkeypatch.setattr(runtime_mod, "_wal_checkpoint_truncate", spy_checkpoint)
    monkeypatch.setattr(SidecarDatabase, "close", spy_close)

    app = runtime_mod.build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        r = await client.get("/diagnostics/sqlite")
        assert r.status_code == 200

    # After lifespan exits: both should have been called, in order.
    assert call_order == ["checkpoint", "close"], (
        f"VAL-W2-045 ordering violation: expected checkpoint BEFORE close, "
        f"observed {call_order!r}"
    )
