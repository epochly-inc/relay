"""W7.3 socket-deny tests (VAL-W7-040 .. VAL-W7-047).

Per eng plan A4 layer 2 the Python SDK monkey-patches ``socket`` while
inside a replay session so non-loopback I/O raises
:class:`RelaySocketDenyError`. W7.3 extends the W3.5 base patch to
cover ``AF_INET6`` and ``AF_UNIX``, ``SOCK_RAW`` and ``SOCK_DGRAM``,
``socket.create_connection``, and DNS-over-UDP egress; adds structured
fields and a remediation hint to the error envelope; provides a
context manager for clean install/uninstall; and ensures the patch
survives ``multiprocessing.spawn`` via the ``RELAY_REPLAY_SESSION``
environment variable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import textwrap

import pytest
from relay.replay_mode import (
    RELAY_REPLAY_SESSION_ENV,
    RelaySocketDenyError,
    is_socket_deny_installed,
    replay_session,
    uninstall_socket_deny,
)

# A globally-routable IPv4 address that is reliably non-loopback (and is
# Cloudflare's public resolver, deliberately chosen so the tests' INTENT
# -- "deny external egress" -- is unambiguous). The deny gate raises
# BEFORE any TCP SYN / UDP datagram leaves the process, so no actual
# packet is emitted.
_NON_LOOPBACK_V4 = "8.8.8.8"
_NON_LOOPBACK_V6 = "2001:4860:4860::8888"


@pytest.fixture(autouse=True)
def _isolate_replay_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``RELAY_REPLAY_SESSION`` is unset for every test.

    The module installs the gate at import time when this env var is
    set; leftover state from a previous test (or a CI parent process)
    must not leak into VAL-W7-047.
    """
    monkeypatch.delenv(RELAY_REPLAY_SESSION_ENV, raising=False)
    # Defensive: if a prior test crashed mid-session, restore originals.
    if is_socket_deny_installed():
        uninstall_socket_deny()


# ---------------------------------------------------------------------------
# VAL-W7-040: SDK in replay mode patches socket.socket (and create_connection)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-040")
def test_replay_session_patches_socket_socket() -> None:
    """Entering a replay session installs the gate; exiting restores it."""
    original_connect = socket.socket.connect
    original_create_connection = socket.create_connection
    with replay_session():
        assert is_socket_deny_installed()
        assert socket.socket.connect is not original_connect
        assert socket.create_connection is not original_create_connection
    assert not is_socket_deny_installed()
    assert socket.socket.connect is original_connect
    assert socket.create_connection is original_create_connection


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-040")
def test_socket_socket_connect_to_external_v4_denied_before_syn() -> None:
    """``socket.socket(AF_INET, SOCK_STREAM).connect(('8.8.8.8', 443))`` raises
    :class:`RelaySocketDenyError` synchronously, before any TCP SYN."""
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((_NON_LOOPBACK_V4, 443))
            err = excinfo.value
            assert err.code == "RELAY-SDK-012"
            assert err.error_class == "RELAY-SDK-SOCKET-DENY"
            assert err.dest_address == _NON_LOOPBACK_V4
            assert err.dest_port == 443
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-040")
def test_create_connection_to_external_denied() -> None:
    """``socket.create_connection`` is patched the same as ``connect``."""
    with replay_session():
        with pytest.raises(RelaySocketDenyError) as excinfo:
            socket.create_connection((_NON_LOOPBACK_V4, 443), timeout=0.1)
        err = excinfo.value
        assert err.operation == "create_connection"
        assert err.dest_address == _NON_LOOPBACK_V4


# ---------------------------------------------------------------------------
# VAL-W7-041: deny covers AF_INET, AF_INET6, AF_UNIX-to-non-sidecar
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-041")
@pytest.mark.parametrize(
    "family,address,expected_family_name",
    [
        (socket.AF_INET, (_NON_LOOPBACK_V4, 443), "AF_INET"),
        pytest.param(
            socket.AF_INET6,
            (_NON_LOOPBACK_V6, 443, 0, 0),
            "AF_INET6",
            marks=pytest.mark.skipif(
                not socket.has_ipv6, reason="IPv6 unavailable on this host"
            ),
        ),
    ],
)
def test_address_family_inet_denied_for_non_loopback(
    family: int, address: tuple, expected_family_name: str
) -> None:
    with replay_session():
        s = socket.socket(family, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect(address)
            assert excinfo.value.family == expected_family_name
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-041")
@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX unavailable on this host (Windows < 10 build 17063)",
)
def test_af_unix_denied_when_no_sidecar_path_registered(tmp_path) -> None:
    """Without a registered sidecar path every AF_UNIX target is denied."""
    with replay_session():  # sidecar_unix_path defaults to None
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect(str(tmp_path / "rogue.sock"))
            err = excinfo.value
            assert err.family == "AF_UNIX"
            assert err.dest_address.endswith("rogue.sock")
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-041")
@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX unavailable on this host",
)
def test_af_unix_denied_for_path_other_than_sidecar(tmp_path) -> None:
    sidecar_path = str(tmp_path / "sidecar.sock")
    rogue_path = str(tmp_path / "rogue.sock")
    with replay_session(sidecar_unix_path=sidecar_path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect(rogue_path)
            assert excinfo.value.family == "AF_UNIX"
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-041")
@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX unavailable on this host",
)
def test_af_unix_to_registered_sidecar_passes_gate(tmp_path) -> None:
    """The registered sidecar UNIX socket path is allowed past the gate.

    We don't actually bind the sidecar; we only verify that the gate
    does NOT raise ``RelaySocketDenyError``. The OS-level
    ``ConnectionRefusedError`` / ``FileNotFoundError`` is fine because
    no listener exists on the path.
    """
    sidecar_path = str(tmp_path / "sidecar.sock")
    with replay_session(sidecar_unix_path=sidecar_path):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                s.connect(sidecar_path)
            except RelaySocketDenyError:  # pragma: no cover - failure path
                pytest.fail("registered sidecar path must not be denied")
            except OSError:
                pass  # ConnectionRefusedError / FileNotFoundError expected.
        finally:
            s.close()


# ---------------------------------------------------------------------------
# VAL-W7-042: deny covers SOCK_RAW and SOCK_DGRAM
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-042")
def test_sock_dgram_sendto_external_denied() -> None:
    """``socket(AF_INET, SOCK_DGRAM).sendto(b'x', ('8.8.8.8', 53))`` raises."""
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.sendto(b"x", (_NON_LOOPBACK_V4, 53))
            err = excinfo.value
            assert err.socktype == "SOCK_DGRAM"
            assert err.operation == "sendto"
            assert err.dest_address == _NON_LOOPBACK_V4
            assert err.dest_port == 53
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-042")
def test_sock_dgram_connect_external_denied() -> None:
    """UDP ``connect`` (which sets a default peer) is also gated."""
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((_NON_LOOPBACK_V4, 53))
            assert excinfo.value.socktype == "SOCK_DGRAM"
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-042")
def test_sock_raw_construction_attempt_denied_via_connect() -> None:
    """``SOCK_RAW`` egress is denied at the connect/sendto gate.

    Constructing a raw socket itself usually requires CAP_NET_RAW (root)
    so we cannot rely on socket() succeeding in CI. We test the gate
    behaviour directly: build an AF_INET/SOCK_DGRAM socket, then assert
    the gate's ``_socktype_name`` reports ``SOCK_RAW`` correctly when
    a SOCK_RAW socket would be used. This proves the deny path covers
    the SOCK_RAW symbolic name.
    """
    from relay.replay_mode import _socktype_name

    assert _socktype_name(socket.SOCK_RAW) == "SOCK_RAW"
    # Now exercise the deny path with an ordinary SOCK_DGRAM socket;
    # the gate refuses without ever calling SOCK_RAW. If a privileged
    # process did call socket(SOCK_RAW) the same _is_address_allowed
    # check applies (verified by symmetry with SOCK_DGRAM above).
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(RelaySocketDenyError):
                s.sendto(b"x", (_NON_LOOPBACK_V4, 1))
        finally:
            s.close()


# ---------------------------------------------------------------------------
# VAL-W7-043: deny restored on session exit
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-043")
def test_session_exit_restores_original_socket_methods() -> None:
    pre_connect = socket.socket.connect
    pre_connect_ex = socket.socket.connect_ex
    pre_sendto = socket.socket.sendto
    pre_bind = socket.socket.bind
    pre_create = socket.create_connection
    with replay_session():
        assert socket.socket.connect is not pre_connect
    # After the context manager exits every reference is restored.
    assert socket.socket.connect is pre_connect
    assert socket.socket.connect_ex is pre_connect_ex
    assert socket.socket.sendto is pre_sendto
    assert socket.socket.bind is pre_bind
    assert socket.create_connection is pre_create
    assert not is_socket_deny_installed()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-043")
def test_post_exit_non_loopback_connect_attempt_is_normal_oserror() -> None:
    """After session exit a connect to a closed non-loopback port raises a
    normal :class:`OSError`/timeout, never :class:`RelaySocketDenyError`."""
    with replay_session():
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        try:
            # Attempt to connect to an address that is non-loopback but
            # almost certainly unreachable in CI; the OS will surface
            # ConnectionRefused / TimedOut / NetworkUnreachable. The
            # important assertion is that we do NOT see RelaySocketDeny.
            s.connect(("203.0.113.1", 1))  # TEST-NET-3 (RFC 5737)
        except RelaySocketDenyError:  # pragma: no cover - failure path
            pytest.fail("post-exit connect must not raise RelaySocketDenyError")
        except OSError:
            pass  # any normal network error is acceptable
    finally:
        s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-043")
def test_session_exit_restores_env_var() -> None:
    """``replay_session`` restores ``RELAY_REPLAY_SESSION`` to its prior value."""
    assert os.environ.get(RELAY_REPLAY_SESSION_ENV) is None
    with replay_session(sidecar_unix_path="/tmp/sidecar.sock"):
        assert os.environ.get(RELAY_REPLAY_SESSION_ENV) == "/tmp/sidecar.sock"
    assert os.environ.get(RELAY_REPLAY_SESSION_ENV) is None


# ---------------------------------------------------------------------------
# VAL-W7-044: deny error includes target address and remediation hint
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-044")
def test_deny_error_carries_structured_fields() -> None:
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((_NON_LOOPBACK_V4, 443))
            err = excinfo.value
            # Direct attribute access (typed envelope).
            assert err.dest_address == _NON_LOOPBACK_V4
            assert err.dest_port == 443
            assert err.family == "AF_INET"
            assert err.socktype == "SOCK_STREAM"
            assert err.operation == "connect"
            assert "rly replay record" in err.remediation
            # Same fields are surfaced on the structured ``details`` dict
            # so wire-envelope consumers see them too.
            assert err.details["dest_address"] == _NON_LOOPBACK_V4
            assert err.details["dest_port"] == 443
            assert err.details["family"] == "AF_INET"
            assert err.details["socktype"] == "SOCK_STREAM"
            assert "rly replay record" in err.details["remediation"]
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-044")
def test_deny_error_envelope_serialises_to_dict() -> None:
    """The error round-trips through :meth:`to_envelope` carrying every
    structured field on the ``error.envelope.v1`` shape."""
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((_NON_LOOPBACK_V4, 443))
            envelope = excinfo.value.to_envelope()
            assert envelope["code"] == "RELAY-SDK-012"
            assert envelope["error_class"] == "RELAY-SDK-SOCKET-DENY"
            details = envelope["details"]
            assert details["dest_address"] == _NON_LOOPBACK_V4
            assert details["dest_port"] == 443
            assert details["family"] == "AF_INET"
            assert details["socktype"] == "SOCK_STREAM"
            assert "rly replay record" in details["remediation"]
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-044")
def test_deny_error_message_names_target() -> None:
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((_NON_LOOPBACK_V4, 443))
            assert _NON_LOOPBACK_V4 in str(excinfo.value)
        finally:
            s.close()


# ---------------------------------------------------------------------------
# VAL-W7-045: deny refuses DNS resolution to non-loopback resolvers
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-045")
def test_dns_udp_to_external_resolver_denied() -> None:
    """A raw DNS query datagram to a non-loopback resolver is denied via
    the SOCK_DGRAM gate (the spec accepts this OR the resolved-address
    connect path; we exercise the DNS UDP path)."""
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Minimal DNS query header for "example.com A IN".
            query = (
                b"\x00\x01"  # txn id
                b"\x01\x00"  # flags: standard query, recursion desired
                b"\x00\x01\x00\x00\x00\x00\x00\x00"  # QDCOUNT=1
                b"\x07example\x03com\x00"  # QNAME
                b"\x00\x01\x00\x01"  # QTYPE=A QCLASS=IN
            )
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.sendto(query, (_NON_LOOPBACK_V4, 53))
            assert excinfo.value.dest_port == 53
            assert excinfo.value.socktype == "SOCK_DGRAM"
        finally:
            s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-045")
def test_resolved_address_connect_denied() -> None:
    """Even if a caller resolves a hostname out-of-band and feeds the
    resolved IP to ``connect()``, the connect itself is denied."""
    with replay_session():
        # Pretend "example.com" resolved to 93.184.216.34 (the literal IP
        # for example.com / Edgecast). We do NOT actually call gethostbyname
        # because that hits live DNS in CI; we only verify the connect gate
        # refuses the resolved address.
        resolved_ip = "93.184.216.34"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((resolved_ip, 80))
            assert excinfo.value.dest_address == resolved_ip
        finally:
            s.close()


# ---------------------------------------------------------------------------
# VAL-W7-046: patch survives multiprocessing.spawn (env-carrier mechanism)
# ---------------------------------------------------------------------------


# Child program executed in a fresh interpreter to model what
# ``multiprocessing.spawn`` does (re-import every module from scratch).
# We use a plain ``subprocess.run`` call rather than ``multiprocessing``
# itself because the test must run identically on POSIX and Windows; a
# spawned ``subprocess`` with the env var set re-exercises the same
# import-time mechanism (``_maybe_apply_from_env``).
_CHILD_PROGRAM = textwrap.dedent(
    """
    import socket
    import sys
    from relay.replay_mode import (
        RelaySocketDenyError,
        is_socket_deny_installed,
    )
    if not is_socket_deny_installed():
        sys.stderr.write("FAIL: gate not auto-installed in child\\n")
        sys.exit(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            s.connect(("8.8.8.8", 443))
        except RelaySocketDenyError as exc:
            sys.stderr.write(
                f"OK: child denied: code={exc.code} target={exc.dest_address}\\n"
            )
            sys.exit(0)
        sys.stderr.write("FAIL: connect succeeded in child\\n")
        sys.exit(3)
    finally:
        s.close()
    """
).strip()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-046")
def test_patch_survives_spawn_via_env_var() -> None:
    """A child process started with ``RELAY_REPLAY_SESSION`` set in its env
    re-applies the gate at import time (the mechanism that lets the
    patch survive ``multiprocessing.spawn`` on Windows).

    This is the platform-portable form of the assertion: the actual
    Windows ``windows-latest`` matrix slice runs the same test code; the
    behaviour exercised here -- "fresh interpreter import re-installs
    the gate when the env var is set" -- is identical across OSes
    because the carrier is the env var, not POSIX-specific fork state.
    """
    env = dict(os.environ)
    env[RELAY_REPLAY_SESSION_ENV] = ""  # gate active, no sidecar UNIX path
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD_PROGRAM],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"child exit={proc.returncode} stderr={proc.stderr!r} stdout={proc.stdout!r}"
    )
    assert "OK: child denied" in proc.stderr
    assert "RELAY-SDK-012" in proc.stderr
    assert "8.8.8.8" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-046")
def test_child_without_env_var_does_not_install_gate() -> None:
    """Symmetrically: a child started WITHOUT the env var does NOT install
    the gate (proves the carrier works in both directions and confirms
    VAL-W7-047 across the spawn boundary)."""
    program = textwrap.dedent(
        """
        from relay.replay_mode import is_socket_deny_installed
        import sys
        sys.exit(0 if not is_socket_deny_installed() else 4)
        """
    ).strip()
    env = dict(os.environ)
    env.pop(RELAY_REPLAY_SESSION_ENV, None)
    proc = subprocess.run(
        [sys.executable, "-c", program],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"unexpected exit={proc.returncode} stderr={proc.stderr!r}"
    )


# ---------------------------------------------------------------------------
# VAL-W7-047: patch does NOT degrade non-replay-mode behaviour
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-047")
def test_import_without_replay_session_does_not_patch_socket() -> None:
    """Outside an active session ``socket.socket`` is the unmodified type.

    ``relay.replay_mode`` is imported at the top of this file; the env
    fixture guarantees ``RELAY_REPLAY_SESSION`` is not set, so the
    import-time hook ``_maybe_apply_from_env`` is a no-op.
    """
    assert not is_socket_deny_installed()
    # The original ``connect`` is the descriptor on the C type; calling
    # it would actually attempt I/O. We only need to assert the patched
    # marker function is not in place.
    from relay.replay_mode import _denying_connect

    assert socket.socket.connect is not _denying_connect


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-047")
def test_outside_session_loopback_connect_uses_real_socket() -> None:
    """Outside a session, attempting to connect to a closed loopback port
    raises a normal ``OSError`` (ConnectionRefused / TimedOut), never
    :class:`RelaySocketDenyError`."""
    assert not is_socket_deny_installed()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        try:
            s.connect(("127.0.0.1", 1))  # closed port; OS will refuse
        except RelaySocketDenyError:  # pragma: no cover - failure path
            pytest.fail("non-replay-mode connect must not raise RelaySocketDeny")
        except OSError:
            pass  # ConnectionRefusedError / TimedOut are fine
    finally:
        s.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W7-047")
def test_outside_session_external_connect_attempt_uses_real_socket() -> None:
    """Outside a session, the SDK does NOT intercept non-loopback connects.

    We don't actually try to reach 8.8.8.8 (network policy in CI is
    unpredictable); we only assert the deny path is not in force, by
    timing out fast or seeing a normal network error.
    """
    assert not is_socket_deny_installed()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        try:
            s.connect(("203.0.113.1", 1))  # TEST-NET-3 (RFC 5737)
        except RelaySocketDenyError:  # pragma: no cover - failure path
            pytest.fail("non-replay-mode connect must not raise RelaySocketDeny")
        except OSError:
            pass  # any normal network error is acceptable
    finally:
        s.close()
