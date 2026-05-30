"""VAL-ISO-019: async teardown MUST NOT drop queued lifecycle envelopes.

Bug (base commit): ``Run._teardown`` (run.py, called from ``__exit__``)
closes the async dispatcher via ``self._dispatcher.close(timeout=0.0)``.
``AsyncFlushDispatcher.close`` pushes a sentinel and ``join(timeout=0.0)``,
returning immediately. The terminal lifecycle envelope enqueued in
``__exit__`` (via ``_submit_lifecycle``) is only delivered if the daemon
worker thread happens to win the race before the interpreter reaps it. In
a script that exits right after the ``with`` block, the terminal envelope
is silently lost at interpreter shutdown.

Because the loss happens at *interpreter shutdown* (the daemon worker is
reaped), an in-process assertion is racy by construction -- the daemon
will eventually drain while the test process stays alive. The
deterministic reproduction runs the SDK in a CHILD process that exits
immediately after the ``with`` block and asserts, from the parent's
loopback sidecar, whether the terminal envelope arrived BEFORE the child
exited.

PASS when: ``__exit__`` in async mode drains queued work with a BOUNDED
wait before close, so the terminal envelope is delivered without the
caller calling ``flush()`` first, while a hung sidecar still returns
within the bound (VAL-W3-018 still holds).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest
from relay import Relay

# Sibling test helper resolved at runtime via pytest's `prepend` import
# mode (the tests dir is on sys.path); pyright does not model that.
from test_loopback_server import LoopbackServer  # pyright: ignore[reportMissingImports]

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"

# A self-contained child program: construct a Relay in async mode, run a
# single context-managed Run, and EXIT IMMEDIATELY after the with-block
# (no explicit flush()). At base commit the terminal envelope enqueued in
# __exit__ is dropped when the daemon dispatcher thread is reaped at
# interpreter shutdown. The child prints nothing; the parent observes
# delivery via its loopback sidecar. All config is read from argv so the
# program text needs no templating.
#   argv: [endpoint, home, project_key, actor_identity_hash, manifest_hash]
_CHILD_PROGRAM = """
import sys
from relay import Relay
endpoint, home, key, actor, manifest = sys.argv[1:6]
r = Relay(
    project_key=key,
    relay_home=home,
    actor_identity_hash=actor,
    manifest_commit_hash=manifest,
    redaction_policy_version="v1",
    endpoint_url=endpoint,
    flush_policy={"mode": "async", "on_error": "raise"},
)
with r.run(agent={"name": "ops", "version": "0.1"}):
    pass
# Intentionally exit here without flush(): exercises teardown drainage.
"""


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-019")
def test_async_teardown_delivers_terminal_envelope_in_child_process(
    tmp_path,
) -> None:
    """A child process that exits right after the ``with`` block MUST have
    delivered its terminal lifecycle envelope to the sidecar.

    RED at base: ``_teardown`` closes with ``timeout=0.0`` so the terminal
    envelope is dropped when the child's daemon dispatcher thread is reaped
    at interpreter shutdown. GREEN after the bounded-drain fix.

    The handler holds a small, deterministic delay so the zero-timeout
    close cannot have completed the POST before the child exits; only a
    bounded drain in ``__exit__`` keeps the child alive long enough for the
    envelope to land.
    """
    received: list[str] = []
    delivered = threading.Event()

    def handler(req):
        # Small deterministic delay: guarantees the child's __exit__ would
        # have to WAIT for delivery; a zero-timeout close returns first.
        time.sleep(0.2)
        received.append(req.body_json.get("client_lifecycle_status", ""))
        delivered.set()
        return (200, {"accepted": True}, {})

    server = LoopbackServer()
    server.add_route("POST", "/v1/ingest/runs", handler)
    server.start()
    home = str(tmp_path / "relay_home")
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                _CHILD_PROGRAM,
                server.base_url,
                home,
                _VALID_KEY,
                _ACTOR,
                _MANIFEST,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, (
            f"child exited non-zero ({proc.returncode}); "
            f"stderr={proc.stderr[-600:]!r}"
        )
        # The child has now fully exited. If teardown drained the queue,
        # the handler ran (and recorded) BEFORE the child's interpreter
        # was torn down. Give a short grace for the recording thread.
        assert delivered.wait(timeout=2.0), (
            "terminal lifecycle envelope was dropped at async teardown: "
            "the child process exited before the queued envelope drained "
            "(close(timeout=0.0) abandoned the daemon worker)"
        )
        assert "client_succeeded" in received
    finally:
        server.stop()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-019")
def test_async_exit_drain_is_bounded_on_hung_sidecar(relay_home_tmp) -> None:
    """The bounded-drain fix MUST NOT reintroduce an unbounded block: a
    sidecar that never responds must not wedge ``__exit__`` forever
    (VAL-W3-018). ``__exit__`` returns within a generous bound even when
    the handler blocks far past the drain budget.
    """
    release = threading.Event()

    def hung(req):
        # Block well past any bounded drain budget; released in finally.
        release.wait(timeout=30.0)
        return (200, {"accepted": True}, {})

    server = LoopbackServer()
    server.add_route("POST", "/v1/ingest/runs", hung)
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
        t0 = time.monotonic()
        run.__exit__(None, None, None)
        elapsed = time.monotonic() - t0
        # The drain budget is bounded; __exit__ must return well under the
        # 30s handler block. 15s gives ample headroom over the drain cap.
        assert elapsed < 15.0, (
            f"async __exit__ blocked {elapsed:.1f}s on a hung sidecar; "
            "the drain must be bounded"
        )
    finally:
        release.set()
        server.stop()
