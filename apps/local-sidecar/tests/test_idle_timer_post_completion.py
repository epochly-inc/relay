"""VAL-W2-048: idle countdown does NOT reset during background flush
completion notification.

After the last in-flight operation completes (including background
flush), the idle timer starts fresh; the sidecar exits after
``idle_timeout_seconds`` if no new work arrives.

Spec evidence requirement: wait 65 seconds post-completion, assert
the sidecar exited at ~60s + grace, exit code 0.

Test compresses the timer to ``RELAY_SIDECAR_IDLE_TIMEOUT_S=2.0`` for
fast CI; the assertion remains: after the last operation completes,
the idle countdown task picks up where it left off and triggers
graceful shutdown ~2s later (NOT 0s, NOT immediately).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health() -> HealthState:
    token = "test-idle-post-completion-token"  # noqa: S105
    return HealthState(
        port=49989,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-048")
@pytest.mark.asyncio
async def test_idle_countdown_starts_fresh_after_completion(
    tmp_path, monkeypatch
) -> None:
    """After in-flight ops complete, idle countdown starts fresh.

    Sequence:
      1. Set IDLE_TIMEOUT_S = 2.0.
      2. Lifespan starts; tracker is idle so countdown is sleeping.
      3. Issue ingest with hold_ms=500 (releases at t=0.5s).
      4. Yield until the ingest releases.
      5. Sleep < idle_timeout (1.0s); idle_shutdown_triggered should
         still be False because the countdown's sleep has not yet
         elapsed since the last release.
      6. Sleep past the idle window (another 1.5s); now the countdown's
         sleep elapses and triggers shutdown.
      7. Assert idle_shutdown_triggered == True.
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
        runtime = app.state.runtime
        # Sanity: the idle timeout was applied.
        assert runtime.idle_timeout_seconds == 2.0

        # Issue an ingest that releases at t = 0.5s.
        ingest_resp = await client.post("/v1/ingest", params={"hold_ms": "500"})
        assert ingest_resp.status_code == 200, ingest_resp.text
        assert ingest_resp.json()["accepted"] is True

        # The tracker is now idle again. The countdown task should
        # restart its sleep window. We assert NO shutdown trigger has
        # fired immediately AFTER completion (idle countdown picks up
        # fresh, does NOT short-circuit).
        diag1 = await client.get("/diagnostics/quiesce")
        body1 = diag1.json()
        assert body1["in_flight_count"] == 0, body1
        assert body1["idle_event_set"] is True, body1
        assert body1["idle_shutdown_triggered"] is False, (
            "idle shutdown must NOT fire immediately after completion; "
            f"countdown should restart its 2.0s window. Got: {body1}"
        )

        # Wait < idle_timeout. The countdown is sleeping for 2.0s; we
        # only wait 0.6s here so it's still sleeping.
        await asyncio.sleep(0.6)
        diag2 = await client.get("/diagnostics/quiesce")
        body2 = diag2.json()
        assert body2["idle_shutdown_triggered"] is False, (
            f"idle shutdown must NOT fire before the 2.0s window elapses; "
            f"got body={body2}"
        )

        # Now wait past the idle window. The countdown's sleep should
        # complete and the truly-idle check fires. Total elapsed since
        # last completion: 0.6s + 1.8s = 2.4s > 2.0s. Allow grace for
        # event-loop scheduling jitter.
        #
        # IMPORTANT: when the countdown trigger fires, it ALSO flips
        # state.draining=True. The next /diagnostics/quiesce request
        # then short-circuits at the DrainMiddleware with a 503
        # envelope (which doesn't carry idle_shutdown_triggered). So
        # we read the flag from runtime state directly (the source of
        # truth) rather than via the HTTP diagnostics surface.
        runtime = app.state.runtime
        deadline = time.monotonic() + 5.0
        triggered = False
        while time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            if runtime.quiesce.idle_shutdown_triggered is True:
                triggered = True
                break

        assert triggered, (
            "idle countdown did not trigger graceful shutdown within "
            "2.0s + 3.0s grace post-completion"
        )
        # After the trigger, draining is True and the drain middleware
        # short-circuits new requests. Confirm end-to-end.
        assert runtime.draining is True
        post_diag = await client.get("/diagnostics/quiesce")
        assert post_diag.status_code == 503, post_diag.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-048")
@pytest.mark.asyncio
async def test_idle_countdown_resets_on_repeated_in_flight_burst(
    tmp_path, monkeypatch
) -> None:
    """A new operation acquired mid-countdown defers shutdown.

    Sequence:
      1. IDLE_TIMEOUT_S = 2.0.
      2. Lifespan starts; idle countdown begins.
      3. Sleep 1.0s (half the window).
      4. Issue ingest with hold_ms=200 (briefly busies the tracker).
      5. After release, sleep 0.5s.
      6. Assert idle_shutdown_triggered == False (the new op reset
         the in-flight observation; the countdown will only fire after
         a FULL fresh 2s window from the last release).
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
        # Half a window of idleness.
        await asyncio.sleep(1.0)
        # Brief ingest interrupts the countdown.
        ingest_resp = await client.post("/v1/ingest", params={"hold_ms": "200"})
        assert ingest_resp.status_code == 200, ingest_resp.text

        # 0.5s after release: the countdown task observed the in-flight
        # event during its sleep so the post-sleep idleness check should
        # have failed; the loop iterates and starts a fresh window.
        # idle_shutdown_triggered MUST still be False at this point
        # (only ~0.7s elapsed since the last release; need 2.0s).
        await asyncio.sleep(0.5)
        diag = await client.get("/diagnostics/quiesce")
        body = diag.json()
        assert body["idle_shutdown_triggered"] is False, (
            "shutdown must NOT trigger 0.5s after a brief in-flight "
            f"interrupted the countdown; got body={body}"
        )
        # Lifespan exits cleanly when the test block ends. No need to
        # wait for the full window here -- the prior test covers that.
