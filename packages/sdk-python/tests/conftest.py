"""Shared pytest fixtures for the Relay Python SDK (W3.1) test suite.

Every test that touches ``RELAY_HOME`` or spawns a sidecar MUST use a
per-test temp directory so the developer's real ``~/.relay`` is never
touched. The ``relay_home_tmp`` fixture sets ``RELAY_HOME`` to a fresh
tmpdir for one test and restores the prior value on teardown.

``stop_sidecar`` is a teardown helper that gracefully stops any sidecar a
test spawned: it reads the PID from the lockfile and sends SIGTERM (the
manifest-declared quiesce signal). PID-only, never name-based -- CLAUDE.md
banned pattern #1.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import time
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def relay_home_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Set RELAY_HOME to a fresh tmpdir for the test; yield the path.

    Also clears RELAY_NO_AUTOSPAWN so a leaked value from the ambient
    environment cannot perturb tests that assume auto-spawn is enabled.
    Tests that exercise the no-autospawn path set it explicitly.
    """
    home = tmp_path / "relay-home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_HOME", str(home))
    monkeypatch.delenv("RELAY_NO_AUTOSPAWN", raising=False)
    yield home


def _read_lockfile_pid(relay_home: Path) -> int | None:
    """Return the sidecar PID recorded in the lockfile, or None if absent."""
    lockfile = relay_home / "sidecar.lock"
    if not lockfile.exists() or lockfile.stat().st_size == 0:
        return None
    try:
        body = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    pid = body.get("pid")
    return int(pid) if isinstance(pid, int) else None


def _stop_sidecar(relay_home: Path) -> None:
    """Gracefully stop the sidecar recorded in ``relay_home``'s lockfile.

    Sends SIGTERM (the manifest-declared quiesce signal) to the
    lockfile-recorded PID. PID-only -- never name-based. Idempotent and
    best-effort: a missing lockfile or already-dead PID is a no-op.
    """
    pid = _read_lockfile_pid(relay_home)
    if pid is None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.kill(pid, signal.SIGTERM)
    # Give the sidecar a brief grace window to drain + checkpoint.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OSError):
            return
        time.sleep(0.05)


class _SidecarTeardown:
    """Teardown registry: stops sidecars and reaps SDK-spawned children.

    ``append(home)`` registers a RELAY_HOME whose sidecar is SIGTERM-ed on
    teardown. ``track(client)`` registers a :class:`relay.client.Relay`
    whose self-spawned sidecar child is reaped (after it has exited) so no
    ``Popen.__del__`` resource warning leaks into the next test.

    Backwards-compatible with the plain-list usage ``stop_sidecar.append``.
    """

    def __init__(self) -> None:
        self._homes: list[Path] = []
        self._clients: list[object] = []

    def append(self, home: Path) -> None:
        self._homes.append(home)

    def track(self, client: object) -> None:
        self._clients.append(client)

    def run(self) -> None:
        # Stop every registered sidecar first (SIGTERM by lockfile PID).
        for home in self._homes:
            _stop_sidecar(home)
        # Then close + reap every tracked SDK client. The sidecar is
        # already stopped, so reap_spawned_if_exited observes the exited
        # child and drops the Popen handle cleanly.
        for client in self._clients:
            close = getattr(client, "close", None)
            if callable(close):
                close()
            reap = getattr(client, "_reap_spawned_if_exited", None)
            if callable(reap):
                # Give the child a brief window to fully exit so poll()
                # sees the return code.
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    if reap():
                        break
                    time.sleep(0.05)


@pytest.fixture
def stop_sidecar() -> Iterator[_SidecarTeardown]:
    """Yield a teardown registry; sidecars + clients registered are cleaned up.

    Usage::

        def test_x(relay_home_tmp, stop_sidecar):
            stop_sidecar.append(relay_home_tmp)
            r = Relay(project_key=..., relay_home=relay_home_tmp)
            stop_sidecar.track(r)
            ... spawn a sidecar ...
    """
    teardown = _SidecarTeardown()
    yield teardown
    teardown.run()
