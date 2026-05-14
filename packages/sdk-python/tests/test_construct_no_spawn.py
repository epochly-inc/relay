"""VAL-W3-003: constructing ``Relay(...)`` alone does NOT spawn the sidecar.

Per eng plan A1 only operations that need the sidecar trigger a spawn.
``r = Relay(project_key="...")`` MUST NOT spawn the sidecar -- it only
validates config. After ``r.trace(...)`` the sidecar MUST exist.

The test:
  1. Instantiates ``Relay`` with a valid key.
  2. Asserts: no sidecar process running, no lockfile present, no port bound.
  3. Calls ``r.trace(...)``.
  4. Asserts the sidecar now exists (lockfile present + PID alive + port
     bound + /health answers).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import socket

import pytest
from relay import Relay
from relay_sidecar.process import pid_is_alive

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _port_is_bound(port: int) -> bool:
    """Return True iff 127.0.0.1:port accepts a TCP connect."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False
    finally:
        s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-003")
def test_construction_does_not_spawn_but_trace_does(
    relay_home_tmp,
    stop_sidecar,
) -> None:
    """Relay(...) does not spawn; the first trace() operation does."""
    stop_sidecar.append(relay_home_tmp)
    lockfile = relay_home_tmp / "sidecar.lock"

    # --- Phase 1: construction. No spawn permitted. ---
    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r)
    assert not lockfile.exists(), (
        "Relay(...) construction created the sidecar lockfile -- "
        "construction must not spawn (VAL-W3-003)"
    )

    # --- Phase 2: the first operation. Spawn / attach happens here. ---
    conn = r.trace("checkout-flow", attempt=1)

    # The lockfile now exists and is well-formed.
    assert lockfile.exists() and lockfile.stat().st_size > 0
    # The recorded PID is alive.
    assert pid_is_alive(conn.pid)
    # The recorded port is bound.
    assert _port_is_bound(conn.port)
    # The connection is authenticated and version-checked.
    assert conn.sidecar_version
    assert conn.base_url == f"http://127.0.0.1:{conn.port}"

    r.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-003")
def test_construction_with_invalid_key_still_no_spawn(relay_home_tmp) -> None:
    """A construction that raises also leaves no spawn artifact behind."""
    from relay import RelayConfigError

    with pytest.raises(RelayConfigError):
        Relay(project_key="", relay_home=relay_home_tmp)
    assert not (relay_home_tmp / "sidecar.lock").exists()
