"""VAL-W2-043: idle countdown does NOT fire while in-flight work is active.

Per the W2.6 quiesce protocol (eng plan A1 + X1): the sidecar tracks
in-flight long-running operations via :class:`InflightTracker`. The
idle-countdown task awaits ``tracker.idle_event`` -- which is CLEARED
the moment any operation acquires the tracker and re-SET when the last
operation releases. The lifespan only triggers graceful shutdown when
the sidecar has been continuously idle for ``idle_timeout_seconds``.

Tests use ``RELAY_SIDECAR_IDLE_TIMEOUT_S=2.0`` (instead of the production
default 60s) for fast CI per the worker prompt directive. The 60s
production default still applies in production via the env-var-driven
default in :func:`resolve_idle_timeout_seconds`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.quiesce import InflightTracker
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-idle-timer-token"  # noqa: S105
    return HealthState(
        port=49993,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-043")
@pytest.mark.asyncio
async def test_inflight_acquire_clears_idle_event() -> None:
    """Acquiring the tracker clears the idle event; release re-sets it."""
    tracker = InflightTracker()
    # Tracker boots idle: event is set.
    assert tracker.idle_event.is_set() is True
    assert tracker.in_flight_count == 0

    async with tracker.acquire(description="ingest:test-1") as op:
        # Inside the acquire block: in-flight=1, idle event cleared.
        assert tracker.in_flight_count == 1
        assert tracker.idle_event.is_set() is False
        assert op.description == "ingest:test-1"
        assert tracker.in_flight_descriptions() == ["ingest:test-1"]

    # After the block exits: in-flight=0, idle event re-set.
    assert tracker.in_flight_count == 0
    assert tracker.idle_event.is_set() is True
    assert tracker.in_flight_descriptions() == []
    # Lifetime acquire counter advanced.
    assert tracker.total_acquires == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-043")
@pytest.mark.asyncio
async def test_concurrent_acquires_keep_event_cleared_until_last_release() -> None:
    """Three concurrent acquires keep the event cleared until the LAST release."""
    tracker = InflightTracker()

    holders_in: list[asyncio.Event] = [asyncio.Event() for _ in range(3)]
    release_signals: list[asyncio.Event] = [asyncio.Event() for _ in range(3)]

    async def holder(i: int) -> None:
        async with tracker.acquire(description=f"op-{i}"):
            holders_in[i].set()
            await release_signals[i].wait()

    tasks = [asyncio.create_task(holder(i)) for i in range(3)]
    # Wait for all three to enter their acquire blocks.
    for ev in holders_in:
        await ev.wait()

    assert tracker.in_flight_count == 3
    assert tracker.idle_event.is_set() is False

    # Release first -> event still cleared (2 in flight).
    release_signals[0].set()
    await asyncio.sleep(0.01)
    assert tracker.in_flight_count == 2
    assert tracker.idle_event.is_set() is False

    # Release second -> event still cleared (1 in flight).
    release_signals[1].set()
    await asyncio.sleep(0.01)
    assert tracker.in_flight_count == 1
    assert tracker.idle_event.is_set() is False

    # Release last -> event SET, in-flight = 0.
    release_signals[2].set()
    await asyncio.gather(*tasks)
    assert tracker.in_flight_count == 0
    assert tracker.idle_event.is_set() is True
    assert tracker.total_acquires == 3


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-043")
@pytest.mark.asyncio
async def test_long_running_ingest_keeps_idle_event_cleared(
    tmp_path, monkeypatch
) -> None:
    """A 3s POST /v1/ingest holds the tracker; idle event stays cleared.

    Spec evidence requirement (VAL-W2-043): a 90s background flush keeps
    the sidecar alive at t=60s. We compress to 3s + a 2s idle timeout in
    CI; the assertion remains: at t=2.0s the sidecar is still running
    BECAUSE the tracker is non-idle.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "2.0")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)

    db_path = tmp_path / "sidecar.db"
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        # Issue an ingest that holds the tracker for 3s.
        ingest_task = asyncio.create_task(
            client.post("/v1/ingest", params={"hold_ms": "3000"}),
        )
        # Sleep 0.3s so the ingest acquires before we observe.
        await asyncio.sleep(0.3)

        # Mid-flight: tracker shows in-flight=1, idle event cleared.
        diag = await client.get("/diagnostics/quiesce")
        body = diag.json()
        assert body["in_flight_count"] == 1, body
        assert body["idle_event_set"] is False, body
        assert "ingest" in body["in_flight_descriptions"], body
        assert body["idle_timeout_seconds"] == 2.0, body
        # The idle countdown has NOT yet triggered shutdown.
        assert body["idle_shutdown_triggered"] is False, body
        assert body["force_stop_requested"] is False, body

        # Wait until ingest completes. With hold_ms=3000 the ingest takes
        # ~3s; we await the task with a generous timeout.
        resp = await ingest_task
        assert resp.status_code == 200, resp.text
        ingest_body = resp.json()
        assert ingest_body["accepted"] is True, ingest_body
        assert ingest_body["held_ms"] == 3000, ingest_body

        # Post-completion: tracker is idle again.
        diag2 = await client.get("/diagnostics/quiesce")
        post_body = diag2.json()
        assert post_body["in_flight_count"] == 0, post_body
        assert post_body["idle_event_set"] is True, post_body
        # The 2.0s idle countdown has NOT yet fired again because we
        # only just transitioned back to idle. The countdown task will
        # take another 2s to confirm idleness; we don't wait that long
        # here -- VAL-W2-048 covers the post-completion countdown path.
        assert post_body["idle_shutdown_triggered"] is False, post_body
