"""W3.5 replay-mode tests (VAL-W3-048, VAL-W3-049, VAL-W3-051).

Per eng plan A4 (defense in depth for replay isolation):

  * Layer 2: SDK in REPLAY mode patches ``socket.socket`` to deny
    non-loopback connect().
  * Layer 4: SDK init in REPLAY mode emits init ERROR if uninstrumented
    HTTP client patterns are detected (``requests``, ``aiohttp``,
    ``urllib.request``).

VAL-W3-051: ``relay.replay.run(case_id)`` defaults to cassette mode; live
mode requires ``mode='live'`` AND ``acknowledge_degraded_approximation=True``.
Persisted replay record carries the ``mode`` field.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import socket
import sys

import pytest
from relay.replay_mode import (
    RelayReplayDegradedModeNotAcknowledged,
    RelaySocketDenyError,
    RelayUninstrumentedHTTPError,
    install_socket_deny,
    replay_record,
    replay_run,
    require_instrumented_http_clients,
    uninstall_socket_deny,
)

# ---------------------------------------------------------------------------
# VAL-W3-048: uninstrumented HTTP clients raise init ERROR (not warning).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-048")
def test_replay_mode_raises_on_uninstrumented_requests_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate an unwrapped ``requests`` module having been imported.
    fake_requests = type(sys)("requests")
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    with pytest.raises(RelayUninstrumentedHTTPError) as excinfo:
        require_instrumented_http_clients()
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-REPLAY-UNINSTRUMENTED-HTTP"
    assert err.code == "RELAY-SDK-011"
    assert "requests" in err.details.get("unwrapped_modules", [])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-048")
@pytest.mark.parametrize("modname", ["aiohttp", "urllib3"])
def test_replay_mode_raises_on_other_uninstrumented_clients(
    modname: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = type(sys)(modname)
    monkeypatch.setitem(sys.modules, modname, fake)
    with pytest.raises(RelayUninstrumentedHTTPError):
        require_instrumented_http_clients()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-048")
def test_replay_mode_does_not_raise_when_no_uninstrumented_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Make sure no stray import is present in sys.modules. We cannot remove
    # `httpx` (the SDK itself depends on it; httpx is allowlisted because
    # the SDK only uses it on loopback). Confirm allowlist behavior.
    for name in ("requests", "aiohttp", "urllib3"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    require_instrumented_http_clients()  # must not raise


# ---------------------------------------------------------------------------
# VAL-W3-049: socket deny on non-loopback connect.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-049")
def test_replay_mode_denies_non_loopback_socket_connect() -> None:
    install_socket_deny()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(RelaySocketDenyError) as excinfo:
            s.connect(("8.8.8.8", 53))
        err = excinfo.value
        assert err.error_class == "RELAY-SDK-SOCKET-DENY"
        assert err.code == "RELAY-SDK-012"
        assert "8.8.8.8" in str(err.details.get("target", ""))
        s.close()
    finally:
        uninstall_socket_deny()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-049")
def test_replay_mode_allows_loopback_connect() -> None:
    """Loopback IPv4 and IPv6 connects are NOT denied (egress is only to
    non-loopback addresses)."""
    install_socket_deny()
    try:
        # We don't actually need to complete the connect; we only need
        # to assert RelaySocketDenyError is NOT raised. Use a port we
        # know is closed; the OS-level ConnectionRefusedError is fine.
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.settimeout(0.1)
        try:
            s4.connect(("127.0.0.1", 1))  # closed port; OS refuses.
        except RelaySocketDenyError:
            pytest.fail("loopback connect must not be denied")
        except OSError:
            pass  # ConnectionRefusedError / ETIMEDOUT are fine.
        finally:
            s4.close()
    finally:
        uninstall_socket_deny()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-049")
def test_socket_deny_can_be_uninstalled_cleanly() -> None:
    original_connect = socket.socket.connect
    install_socket_deny()
    try:
        assert socket.socket.connect is not original_connect
    finally:
        uninstall_socket_deny()
    # After uninstall the original is restored.
    assert socket.socket.connect is original_connect


# ---------------------------------------------------------------------------
# VAL-W3-051: cassette-first; live requires explicit acknowledgement.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_defaults_to_cassette_mode() -> None:
    record = replay_run(case_id="01H1234567890ABCDEFGHJKMNP")
    assert record.mode == "cassette"
    assert record.case_id == "01H1234567890ABCDEFGHJKMNP"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_explicit_cassette_mode() -> None:
    record = replay_run(
        case_id="01H1234567890ABCDEFGHJKMNP", mode="cassette"
    )
    assert record.mode == "cassette"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_live_without_acknowledgement_raises() -> None:
    """``mode='live'`` without ``acknowledge_degraded_approximation=True``
    raises ``RelayReplayDegradedModeNotAcknowledged`` SYNCHRONOUSLY before
    any network I/O."""
    with pytest.raises(RelayReplayDegradedModeNotAcknowledged) as excinfo:
        replay_run(case_id="01H1234567890ABCDEFGHJKMNP", mode="live")
    err = excinfo.value
    assert err.code == "RELAY-SDK-013"
    assert err.error_class == "RELAY-SDK-REPLAY-DEGRADED-MODE-NOT-ACKNOWLEDGED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_live_with_acknowledgement_runs() -> None:
    record = replay_run(
        case_id="01H1234567890ABCDEFGHJKMNP",
        mode="live",
        acknowledge_degraded_approximation=True,
    )
    assert record.mode == "live"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_record_carries_mode_in_persisted_form() -> None:
    """The persisted form (the dict the evidence binder writes) MUST carry
    a top-level ``mode`` field so consumers can distinguish faithful
    cassette replays from live degraded approximations."""
    record = replay_run(case_id="01H1234567890ABCDEFGHJKMNP")
    payload = record.to_dict()
    assert payload["mode"] == "cassette"
    assert payload["case_id"] == "01H1234567890ABCDEFGHJKMNP"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_run_unknown_mode_rejected() -> None:
    with pytest.raises(ValueError, match=r"(?i)mode"):
        replay_run(case_id="01H1234567890ABCDEFGHJKMNP", mode="banana")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-051")
def test_replay_record_writes_cassette_marker_with_mode() -> None:
    """``replay_record`` mirrors ``replay_run`` shape for evidence binding."""
    rec = replay_record(case_id="01H1234567890ABCDEFGHJKMNP")
    assert rec.mode == "cassette"


# ---------------------------------------------------------------------------
# Cross-language parity (matches TS sdk-typescript src/replay_mode.ts
# isLoopbackHost). Both SDKs must accept/reject the same set of host
# literals so they make identical egress decisions when run side by side.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_is_loopback_address_accepts_ipv4_127_range() -> None:
    from relay.replay_mode import _is_loopback_address

    assert _is_loopback_address("127.0.0.1") is True
    assert _is_loopback_address("127.0.0.0") is True
    assert _is_loopback_address("127.255.255.255") is True
    assert _is_loopback_address("127.99.0.1") is True


@pytest.mark.plumbing
def test_is_loopback_address_accepts_ipv6_loopback() -> None:
    from relay.replay_mode import _is_loopback_address

    assert _is_loopback_address("::1") is True
    assert _is_loopback_address("localhost") is True


@pytest.mark.plumbing
def test_is_loopback_address_accepts_ipv4_mapped_ipv6_loopback() -> None:
    from relay.replay_mode import _is_loopback_address

    assert _is_loopback_address("::ffff:127.0.0.1") is True
    assert _is_loopback_address("::FFFF:127.0.0.1") is True
    assert _is_loopback_address("::ffff:127.255.255.255") is True


@pytest.mark.plumbing
def test_is_loopback_address_rejects_non_loopback_hosts() -> None:
    from relay.replay_mode import _is_loopback_address

    assert _is_loopback_address("") is False
    assert _is_loopback_address("example.com") is False
    assert _is_loopback_address("10.0.0.1") is False
    assert _is_loopback_address("8.8.8.8") is False
    assert _is_loopback_address("0.0.0.0") is False
    assert _is_loopback_address("192.168.1.1") is False
    assert _is_loopback_address("::2") is False
    assert _is_loopback_address("2001:db8::1") is False
    assert _is_loopback_address("::ffff:8.8.8.8") is False


@pytest.mark.plumbing
def test_is_loopback_address_rejects_non_canonical_ipv4() -> None:
    """Parity with TS: leading zeros / oversize octets / wrong octet count.

    Python's stdlib ``ipaddress.ip_address`` already rejects these forms;
    this test pins the contract so a future refactor cannot relax it.
    """
    from relay.replay_mode import _is_loopback_address

    assert _is_loopback_address("127.0.0.001") is False
    assert _is_loopback_address("127.0.0.01") is False
    assert _is_loopback_address("127.000.000.001") is False
    assert _is_loopback_address("127.0.0.256") is False
    assert _is_loopback_address("127.300.0.1") is False
    assert _is_loopback_address("127.0.0") is False
    assert _is_loopback_address("127.0.0.0.1") is False
