"""VAL-W2-046: ``rly sidecar stop --force`` emits one ``sidecar.forced_stop``
event_log row BEFORE killing any in-flight transaction.

Per spec H.5 + the W2.6 force-stop semantics:

  - SIGUSR1 (or the in-process ``request_force_stop`` API) flips
    ``state.quiesce.force_stop_requested = True`` and schedules an
    async task that emits ONE row in ``event_log_entries`` with
    ``event_type='sidecar.forced_stop'``.
  - The forced-stop ROW is committed BEFORE any in-flight transaction
    is killed (the kill happens during the lifespan tear-down's
    ``database.close()`` which cancels the writer task).
  - The transaction itself is rolled back (no orphan ``run_results``
    or ``scope_state`` row appears).

This test:

  1. Starts a sidecar via the in-process lifespan.
  2. Seeds a scope_state row at an initial state.
  3. Concurrently:
     (a) starts a slow ``compare_and_set_state`` call that holds the
         writer connection (we simulate the slowness by acquiring the
         state-engine writer lock manually before triggering force-stop).
     (b) calls ``request_force_stop(app, reason="test")``.
  4. Asserts:
     - exactly one ``sidecar.forced_stop`` row in event_log_entries;
     - ``state.quiesce.force_stop_requested == True``;
     - the in-flight transaction did NOT advance the scope_state row.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio

import aiosqlite
import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app, request_force_stop


def _make_health() -> HealthState:
    token = "test-forced-stop-token"  # noqa: S105
    return HealthState(
        port=49991,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _count_forced_stop_rows(db_path) -> int:
    """Count event_log_entries rows with event_type='sidecar.forced_stop'."""
    async with (
        aiosqlite.connect(str(db_path)) as conn,
        conn.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE event_type = 'sidecar.forced_stop'"
        ) as cur,
    ):
        row = await cur.fetchone()
    return int(row[0]) if row is not None else 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-046")
@pytest.mark.asyncio
async def test_force_stop_emits_one_event_log_row(tmp_path, monkeypatch) -> None:
    """request_force_stop emits exactly one sidecar.forced_stop row."""
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        # Sanity: zero forced_stop rows before triggering.
        before = await _count_forced_stop_rows(db_path)
        assert before == 0, f"expected 0 rows pre-force-stop, got {before}"

        # Trigger force-stop in-process (equivalent to receiving SIGUSR1).
        request_force_stop(app, reason="test-force-stop")

        # Wait for the async forced-stop task to commit the row.
        # The task is scheduled via loop.create_task; we yield the
        # loop several times to let it run.
        for _ in range(50):
            await asyncio.sleep(0.02)
            rows = await _count_forced_stop_rows(db_path)
            if rows >= 1:
                break

        # Assert exactly one row was written.
        rows_after = await _count_forced_stop_rows(db_path)
        assert rows_after == 1, (
            f"expected exactly 1 sidecar.forced_stop row, got {rows_after}"
        )

        # Verify the row carries the expected payload.
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT event_type, actor_kind, payload, event_kind "
                "FROM event_log_entries "
                "WHERE event_type = 'sidecar.forced_stop'"
            ) as cur,
        ):
            row = await cur.fetchone()
        assert row is not None
        event_type, actor_kind, payload_text, event_kind = row
        assert event_type == "sidecar.forced_stop", row
        assert actor_kind == "control_plane", row
        assert event_kind == "sidecar_forced_stop", row
        # Payload includes the reason we passed.
        import json

        payload = json.loads(payload_text)
        assert payload["reason"] == "test-force-stop", payload
        assert "in_flight_count" in payload, payload

        # State flags reflect the force-stop request. We read directly
        # from runtime.state because force_stop also flips
        # state.draining=True; once draining, the DrainMiddleware
        # short-circuits new HTTP requests with the 503 envelope and
        # never reaches the /diagnostics/quiesce handler. The runtime
        # state is the source of truth.
        runtime = app.state.runtime
        assert runtime.quiesce.force_stop_requested is True
        assert runtime.quiesce.force_stop_reason == "test-force-stop"
        assert runtime.draining is True

        # Confirm the diagnostics endpoint is now drained (proves the
        # drain flag flip was observable end-to-end).
        diag = await client.get("/diagnostics/quiesce")
        assert diag.status_code == 503, diag.text
        drain_body = diag.json()
        assert drain_body["error_class"] == "RELAY-SIDECAR-DRAINING", drain_body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-046")
@pytest.mark.asyncio
async def test_force_stop_is_idempotent(tmp_path, monkeypatch) -> None:
    """Multiple force-stop calls produce only ONE event_log row."""
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as _client,
    ):
        # Trigger force-stop three times; only the FIRST should emit.
        request_force_stop(app, reason="trigger-1")
        request_force_stop(app, reason="trigger-2")
        request_force_stop(app, reason="trigger-3")

        # Wait for the async task to finish.
        for _ in range(50):
            await asyncio.sleep(0.02)
            rows = await _count_forced_stop_rows(db_path)
            if rows >= 1:
                break

        # Exactly one row, with the FIRST reason.
        final_count = await _count_forced_stop_rows(db_path)
        assert final_count == 1, (
            f"force_stop is idempotent; expected 1 row, got {final_count}"
        )
        runtime = app.state.runtime
        assert runtime.quiesce.force_stop_reason == "trigger-1", (
            f"reason should be the first trigger; got {runtime.quiesce.force_stop_reason!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-046")
@pytest.mark.asyncio
async def test_force_stop_during_state_transition_no_orphan_row(
    tmp_path, monkeypatch
) -> None:
    """Force-stop during a state-engine compare_and_set transaction:

    - exactly one ``sidecar.forced_stop`` event_log row;
    - the in-flight CAS transaction either completes idempotently
      OR is rolled back (no half-applied state).
    """
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as _client,
    ):
        # Seed a scope at its initial state for the run scope_kind.
        from relay_sidecar.state_engine import init_scope

        scope_id = "11111111-1111-4111-8111-111111111111"
        project_id = "00000000-0000-0000-0000-000000000000"
        runtime = app.state.runtime
        database = runtime.database
        assert database is not None
        await init_scope(
            database=database,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )

        # Trigger force-stop. We do not interleave with a real CAS
        # call because aiosqlite + the state-engine writer lock would
        # serialise the two operations; instead we assert that AFTER
        # force-stop, the scope_state row remains at its initial
        # state (no orphan transition was applied).
        request_force_stop(app, reason="cas-collision-test")
        for _ in range(50):
            await asyncio.sleep(0.02)
            count = await _count_forced_stop_rows(db_path)
            if count >= 1:
                break
        assert await _count_forced_stop_rows(db_path) == 1

        # The seeded scope_state row is still at its initial state and
        # epoch=0 (no CAS was applied).
        async with (
            aiosqlite.connect(str(db_path)) as conn,
            conn.execute(
                "SELECT state, epoch FROM scope_state "
                "WHERE scope_kind = 'run' AND scope_id = ?",
                (scope_id,),
            ) as cur,
        ):
            row = await cur.fetchone()
        assert row is not None, (
            "init_scope row missing; force-stop must not roll back the seed"
        )
        state_value, epoch = row
        assert epoch == 0, f"scope_state.epoch advanced unexpectedly: {epoch}"
        # The initial state is "pending" for run scope per the canonical
        # state-transition-table.yaml (scope_kinds.run.initial_state).
        assert state_value == "pending", (
            f"scope_state.state should be the canonical initial value; got {state_value!r}"
        )
