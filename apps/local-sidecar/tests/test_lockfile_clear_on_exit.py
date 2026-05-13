"""VAL-W2-047: graceful exit clears the lockfile via local_atomic_file_write.

Per W2.6 quiesce protocol + spec H.5: after a graceful sidecar
shutdown the lockfile MUST be cleared (size = 0). The next
``acquire_or_attach`` call then classifies the lockfile as
``NO_LOCKFILE`` (the SPAWN branch) rather than ``STALE_PID`` (the
recovery branch).

Force-stop deliberately leaves the lockfile in place; the next spawn
observes STALE_PID and clears via the W2.1 recovery path. That
asymmetry is observable and load-bearing for VAL-W2-046's "post-mortem
forensic" semantics.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app, request_force_stop


def _make_health() -> HealthState:
    token = "test-lockfile-clear-token"  # noqa: S105
    return HealthState(
        port=49990,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-047")
@pytest.mark.asyncio
async def test_graceful_exit_clears_lockfile_to_zero_bytes(
    tmp_path, monkeypatch
) -> None:
    """After graceful lifespan exit the lockfile is cleared to size 0.

    Pre-test: write a real lockfile body using the W2.1 spawn helper so
    the lifespan tear-down has something concrete to clear. Post-test:
    the file still exists (clear writes b"" via atomic rename, not
    unlink) and is size 0.
    """
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    relay_home = tmp_path / "relay-home"
    relay_home.mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"

    # Pre-populate the lockfile with a valid body so we can prove the
    # tear-down clears it (rather than asserting on an absent file).
    from relay_sidecar.lockfile import (
        LockfileBody,
        resolve_lockfile_path,
        serialize_lockfile_body,
    )
    from relay_sidecar.primitives import local_atomic_file_write

    lockfile_path = resolve_lockfile_path(relay_home)
    # The W2.6 build_runtime_app derives lockfile_path from db_path.parent
    # when sqlite_path is overridden. Use the same logic to produce the
    # path the lifespan tear-down will actually clear.
    lockfile_path_override = db_path.parent / "sidecar.lock"
    body = LockfileBody(
        pid=99999,
        port=12345,
        launched_at="2026-05-13T00:00:00.000000Z",
        launched_by="test-user",
        sidecar_version="0.0.0-test",
        bearer_token_digest="sha256-" + "a" * 64,
    )
    payload = serialize_lockfile_body(body)
    local_atomic_file_write(lockfile_path_override, payload, mode=0o600)
    assert lockfile_path_override.stat().st_size > 0
    # Sanity: the alternate path (under RELAY_HOME) should be untouched
    # by the test, so we only need to assert against lockfile_path_override.

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as client,
    ):
        # Sanity: the runtime resolved the same lockfile path the test
        # pre-populated.
        assert app.state.runtime.lockfile_path == lockfile_path_override
        # Drive at least one request to ensure lifespan startup completed.
        r = await client.get("/diagnostics/quiesce")
        assert r.status_code == 200, r.text

    # Lifespan exited gracefully. The lockfile is now cleared.
    assert lockfile_path_override.exists(), (
        "lockfile cleared via local_atomic_file_write(b'') keeps the file; "
        "did not exist post-shutdown"
    )
    assert lockfile_path_override.stat().st_size == 0, (
        f"lockfile size after graceful exit is "
        f"{lockfile_path_override.stat().st_size}; expected 0 "
        f"(VAL-W2-047 -- lockfile MUST be cleared via "
        f"local_atomic_file_write(path, b''))"
    )
    # Suppress unused warning for resolve_lockfile_path import.
    _ = lockfile_path


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-047")
def test_cleared_lockfile_classifies_as_no_lockfile_branch(tmp_path) -> None:
    """``acquire_or_attach`` on a cleared lockfile takes the NO_LOCKFILE branch.

    Pre-test: write the lockfile to size 0 via local_atomic_file_write
    (the same path the lifespan tear-down uses).
    Acquire-test: invoke acquire_or_attach with a stub process_runner;
    assert the action is "spawned" (the NO_LOCKFILE branch in
    spawn._classify_and_act, NOT "stale_pid_cleared_and_spawned").
    """
    from relay_sidecar.primitives import local_atomic_file_write
    from relay_sidecar.spawn import acquire_or_attach

    # Pre-populate by clearing (size 0) -- equivalent to graceful exit.
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    lockfile = home / "sidecar.lock"
    local_atomic_file_write(lockfile, b"", mode=0o600)
    assert lockfile.exists()
    assert lockfile.stat().st_size == 0

    # Stub the process_runner so we don't bind a real port.
    import os
    import socket

    def stub_runner() -> tuple[int, int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return os.getpid(), port

    decision = acquire_or_attach(home=home, process_runner=stub_runner)
    # Per spawn._classify_and_act:272-279, an empty (size 0) lockfile
    # falls into the NO_LOCKFILE branch which writes a fresh spawn and
    # the action label is "spawned" (NOT "stale_pid_cleared_and_spawned").
    assert decision.action == "spawned", (
        f"size-0 lockfile must classify as NO_LOCKFILE -> action='spawned'; "
        f"got action={decision.action!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-047")
@pytest.mark.asyncio
async def test_force_stop_does_not_clear_lockfile(tmp_path, monkeypatch) -> None:
    """Force-stop preserves the lockfile (asymmetry vs graceful exit).

    Per spec H.5: force-stop intentionally leaves the lockfile in place
    so the next acquire_or_attach observes STALE_PID and clears via the
    spawn recovery path. This asymmetry is the load-bearing forensic
    signal for VAL-W2-046.
    """
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    lockfile_path = db_path.parent / "sidecar.lock"

    # Pre-populate the lockfile.
    from relay_sidecar.lockfile import LockfileBody, serialize_lockfile_body
    from relay_sidecar.primitives import local_atomic_file_write

    body = LockfileBody(
        pid=99998,
        port=12346,
        launched_at="2026-05-13T00:00:00.000000Z",
        launched_by="test-user",
        sidecar_version="0.0.0-test",
        bearer_token_digest="sha256-" + "b" * 64,
    )
    payload = serialize_lockfile_body(body)
    local_atomic_file_write(lockfile_path, payload, mode=0o600)
    pre_size = lockfile_path.stat().st_size
    assert pre_size > 0

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://sidecar.test") as _client,
    ):
        # Trigger force-stop INSIDE the lifespan; the tear-down branch
        # then sees force_stop=True and skips the lockfile clear.
        request_force_stop(app, reason="lockfile-asymmetry-test")
        # Yield several times so the forced-stop task finishes its
        # event_log emit before we exit the lifespan.
        for _ in range(50):
            await asyncio.sleep(0.02)
            if app.state.runtime.quiesce.force_stop_requested:
                break

    # Lifespan exited via the force-stop branch. Lockfile is UNCHANGED.
    assert lockfile_path.exists(), "force-stop must NOT delete the lockfile"
    post_size = lockfile_path.stat().st_size
    assert post_size == pre_size, (
        f"force-stop must NOT clear the lockfile; size changed "
        f"{pre_size} -> {post_size}"
    )
