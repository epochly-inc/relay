"""VAL-W3-008: SDK auto-spawn is disabled when ``RELAY_NO_AUTOSPAWN=1``.

With ``RELAY_NO_AUTOSPAWN=1`` set, the first SDK operation MUST NOT spawn a
sidecar. If no sidecar is reachable it MUST raise
``RelaySidecarNotReachable`` (code ``RELAY-SDK-003`` / error_class
``RELAY-SDK-NO-SIDECAR``) with retry advice ``after_state_change``.

If a sidecar IS already running (started out of band, the documented CI
escape hatch), the SDK attaches to it instead of spawning.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess

import pytest
from relay import Relay
from relay.errors import RelaySidecarNotReachable

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-008")
def test_no_autospawn_with_no_sidecar_raises_not_reachable(
    relay_home_tmp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RELAY_NO_AUTOSPAWN=1 + no sidecar -> RelaySidecarNotReachable.

    We also assert no subprocess was ever launched: subprocess.Popen is
    monkeypatched to fail the test if called.
    """
    monkeypatch.setenv("RELAY_NO_AUTOSPAWN", "1")

    def _boom_popen(*_a: object, **_k: object) -> object:
        raise AssertionError(
            "subprocess.Popen called -- RELAY_NO_AUTOSPAWN=1 must not spawn"
        )

    monkeypatch.setattr(subprocess, "Popen", _boom_popen)

    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    with pytest.raises(RelaySidecarNotReachable) as excinfo:
        r.trace("op")
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-NO-SIDECAR"
    assert err.code == "RELAY-SDK-003"
    # Retry advice: the caller must change state (start a sidecar) first.
    assert err.retry_advice == "after_state_change"
    assert err.details.get("autospawn_disabled") is True

    # No lockfile was created.
    assert not (relay_home_tmp / "sidecar.lock").exists()
    r.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-008")
def test_no_autospawn_with_stale_lockfile_raises_not_reachable(
    relay_home_tmp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lockfile pointing at a dead PID still raises RelaySidecarNotReachable."""
    monkeypatch.setenv("RELAY_NO_AUTOSPAWN", "1")

    # Write a lockfile whose PID is almost certainly dead.
    lockfile = relay_home_tmp / "sidecar.lock"
    dead_pid = 999_999_999
    body = (
        '{"pid":' + str(dead_pid) + ',"port":50000,'
        '"launched_at":"2026-01-01T00:00:00.000000Z",'
        '"launched_by":"test","sidecar_version":"0.0.0",'
        '"bearer_token_digest":"sha256-'
        + "0" * 64
        + '"}'
    )
    lockfile.write_text(body, encoding="utf-8")

    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    with pytest.raises(RelaySidecarNotReachable) as excinfo:
        r.trace("op")
    assert excinfo.value.code == "RELAY-SDK-003"
    assert excinfo.value.retry_advice == "after_state_change"
    r.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-008")
def test_no_autospawn_attaches_to_running_sidecar(
    relay_home_tmp,
    stop_sidecar,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RELAY_NO_AUTOSPAWN=1 still ATTACHES to a sidecar started out of band.

    First a normal client spawns the sidecar (autospawn enabled). Then,
    with RELAY_NO_AUTOSPAWN=1 set, a second client attaches to it -- the
    documented CI escape hatch where the sidecar is pre-started via
    ``relay sidecar start --daemon``.
    """
    stop_sidecar.append(relay_home_tmp)

    # Phase 1: a normal client spawns the sidecar.
    r1 = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r1)
    r1.trace("op")

    # Phase 2: RELAY_NO_AUTOSPAWN=1; a second client must attach, not raise.
    monkeypatch.setenv("RELAY_NO_AUTOSPAWN", "1")
    r2 = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    conn = r2.trace("op")
    assert conn.spawned is False
    assert conn.sidecar_version

    r1.close()
    r2.close()
