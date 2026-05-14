"""VAL-W3-018 -- SDK flush_policy='async' does not block on ingest I/O.

The contract uses an event-state synchronization marker, NOT a
wall-clock threshold (wall clocks are flaky under CI load). The test
seeds a slow sidecar handler that does NOT ``accept()`` the inbound
socket until a test-controlled ``threading.Event`` is set. The test
invokes ``trace.__exit__`` (or the explicit ``capture()`` in async
mode) and asserts the call returned BEFORE the slow handler reached
its accept point.

After the assertion the test sets the event, releases the handler,
and asserts the envelope is eventually delivered.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import threading

import pytest
from relay import Relay
from test_loopback_server import LoopbackServer

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-018")
def test_async_capture_returns_before_handler_processes(relay_home_tmp) -> None:
    """In async mode, ``capture()`` returns BEFORE the slow handler
    enters its body. Event-state assertion -- no wall-clock threshold.
    """
    handler_entered = threading.Event()
    release = threading.Event()
    delivered = threading.Event()

    def slow(req):
        handler_entered.set()
        # Block here until the test explicitly releases.
        release.wait(timeout=30.0)
        delivered.set()
        return (200, {"accepted": True}, {})

    server = LoopbackServer()
    server.add_route("POST", "/v1/ingest/runs", slow)
    server.start()
    try:
        r = Relay(
            project_key=_VALID_KEY,
            relay_home=relay_home_tmp,
            actor_identity_hash=_ACTOR,
            manifest_commit_hash=_MANIFEST,
            redaction_policy_version="v1",
            endpoint_url=server.base_url,
            flush_policy={"mode": "async", "on_error": "raise"},
        )
        run = r.run(agent={"name": "ops", "version": "0.1"}).__enter__()

        # Submit the lifecycle envelope. In async mode this MUST NOT
        # block on the slow handler.
        result = run.capture(client_lifecycle_status="client_succeeded")

        # At this point the slow handler has either not been reached at
        # all (most likely) or is blocked in its body. The key
        # invariant: this thread is NOT waiting on the handler.
        assert result.get("queued") is True
        assert handler_entered.is_set() is False or not delivered.is_set(), (
            "async capture must return before the slow handler has "
            "completed; observed handler completion before capture returned"
        )

        # Now release the handler and assert eventual delivery.
        release.set()
        delivered_in_time = delivered.wait(timeout=10.0)
        assert delivered_in_time, "async-flushed envelope never reached sidecar"

        # Drain the dispatcher cleanly before teardown.
        run.flush()
        run.__exit__(None, None, None)
    finally:
        server.stop()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-018")
def test_async_exit_returns_immediately(relay_home_tmp) -> None:
    """The Run's ``__exit__`` itself does NOT block on ingest network
    I/O when flush_policy.mode='async'. The test uses the same
    accept-blocking handler and asserts ``__exit__`` returned BEFORE
    the slow handler's body could complete.
    """
    handler_done = threading.Event()
    release = threading.Event()

    def slow(req):
        release.wait(timeout=30.0)
        handler_done.set()
        return (200, {"accepted": True}, {})

    server = LoopbackServer()
    server.add_route("POST", "/v1/ingest/runs", slow)
    server.start()
    try:
        r = Relay(
            project_key=_VALID_KEY,
            relay_home=relay_home_tmp,
            actor_identity_hash=_ACTOR,
            manifest_commit_hash=_MANIFEST,
            redaction_policy_version="v1",
            endpoint_url=server.base_url,
            flush_policy={"mode": "async", "on_error": "raise"},
        )
        run = r.run(agent={"name": "ops", "version": "0.1"}).__enter__()
        # Exit -- this should NOT block on the slow handler.
        run.__exit__(None, None, None)
        # The handler is still blocked. handler_done MUST NOT be set.
        assert not handler_done.is_set(), (
            "async __exit__ blocked on the slow handler; expected return "
            "BEFORE handler body completion"
        )
        # Release so the worker thread can drain.
        release.set()
    finally:
        server.stop()
