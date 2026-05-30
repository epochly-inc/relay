"""Product-level socket-leak guard for the replay default-deny egress gate.

ROOT-CAUSE finding (bug-hunt 2026-05-28, finding
``fix-r4-iso-socket-leak-deep-latent``):

:class:`RelaySocketDenyError` is raised by the replay default-deny egress
gate when a non-loopback connection is blocked. Its MRO is
``RelaySocketDenyError -> RelaySdkError -> RelayError -> Exception`` -- it is
NOT an ``OSError``. Every stdlib / 3rd-party connection helper that builds a
socket itself (``socket.create_connection``, ``http.client.HTTPConnection``,
``urllib3.util.connection.create_connection``) closes the socket it just built
ONLY in an ``except OSError:`` cleanup branch, e.g.::

    sock = socket.socket(af, socktype, proto)
    try:
        sock.connect(sa)
    except OSError:          # <-- deny is NOT an OSError, so this is skipped
        sock.close()
        raise

Because the deny error is not an ``OSError`` that cleanup is bypassed, so
EVERY denied egress in a real replay session leaks the just-created
(unconnected) socket. At GC the leaked socket emits a ``ResourceWarning``
which the repo-wide ``filterwarnings = ["error", ...]`` policy promotes to a
teardown ERROR -- and, because finalization runs cross-file, the error is
misattributed to an unrelated test. (This is the ROOT cause the W7.5 test was
papering over with an explicit gc-and-close workaround.)

These tests prove the leak at the PRODUCT level -- with NO test-side
gc/close workaround for the leak itself -- and that it is closed by the fix
while the deny still fires (egress-denial behavior unchanged).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import gc
import socket
import warnings

import pytest
from relay.replay_mode import (
    RELAY_REPLAY_SESSION_ENV,
    RelaySocketDenyError,
    is_socket_deny_installed,
    replay_session,
    uninstall_socket_deny,
)

pytestmark = pytest.mark.plumbing

# Globally-routable IPv4 address: deliberately non-loopback so the deny gate
# fires. The gate raises BEFORE any TCP SYN leaves the process, so no real
# packet is emitted.
_NON_LOOPBACK_V4 = "8.8.8.8"


@pytest.fixture(autouse=True)
def _isolate_replay_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``RELAY_REPLAY_SESSION`` is unset and the gate is uninstalled.

    A leftover env var or gate from a prior test would corrupt these
    assertions. Defensive: restore originals if a prior test crashed
    mid-session.
    """
    monkeypatch.delenv(RELAY_REPLAY_SESSION_ENV, raising=False)
    if is_socket_deny_installed():
        uninstall_socket_deny()


def _connect_like_a_library(host: str, port: int) -> socket.socket:
    """Replicate the stdlib/urllib3 ``create_connection`` cleanup contract.

    This is the EXACT shape used by ``socket.create_connection``,
    ``http.client.HTTPConnection.connect`` and
    ``urllib3.util.connection.create_connection``: build the socket, connect,
    and close it ONLY in an ``except OSError:`` branch. A deny error that is
    not an ``OSError`` slips past this cleanup, leaking ``sock``.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError:
        # Library cleanup branch. The deny error is NOT an OSError, so on the
        # deny path this branch does NOT execute and ``sock`` would leak --
        # unless the gate closed it before raising.
        sock.close()
        raise
    return sock


def _fd_is_open(sock: socket.socket) -> bool:
    """Return True if ``sock`` still owns an open OS file descriptor.

    A closed ``socket.socket`` reports ``fileno() == -1``. We treat any
    non-negative fd as an open (leaked) socket.
    """
    try:
        return sock.fileno() != -1
    except Exception:
        return False


@pytest.mark.fulfills("VAL-W7-084")
def test_gate_closes_socket_before_raising_no_fd_leak() -> None:
    """The deny gate closes the socket it was called on BEFORE raising.

    We track every ``socket.socket`` constructed during the denied connect
    and, after the deny propagates, assert NONE of them still holds an open
    file descriptor (``fileno() == -1`` for each). No test-side close before
    the assertion: the fix must close the socket at the gate. This is the
    direct fd-leak proof.

    RED (before fix): the gate raises without closing ``self``; the tracked
    socket still has ``fileno() != -1`` -> assertion fails.
    GREEN (after fix): the gate closes ``self`` first; every tracked socket
    reports ``fileno() == -1``.
    """
    created: list[socket.socket] = []
    original_init = socket.socket.__init__

    def _tracking_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        original_init(self, *args, **kwargs)
        created.append(self)

    socket.socket.__init__ = _tracking_init  # type: ignore[assignment]
    try:
        with replay_session():
            with pytest.raises(RelaySocketDenyError) as excinfo:
                _connect_like_a_library(_NON_LOOPBACK_V4, 443)
            # Deny still fires with the canonical wire code (egress-denial
            # behavior unchanged).
            assert excinfo.value.code == "RELAY-SDK-012"
            assert excinfo.value.error_class == "RELAY-SDK-SOCKET-DENY"
            assert excinfo.value.dest_address == _NON_LOOPBACK_V4
            assert excinfo.value.dest_port == 443
            # Drop the traceback so the only thing that could keep the socket
            # alive is a genuine product leak, not a test-held reference.
            excinfo.traceback = excinfo.traceback[:0]
    finally:
        socket.socket.__init__ = original_init  # type: ignore[assignment]

    assert created, "the connect helper must have constructed a socket"
    # PRODUCT-level assertion: every socket the library built for the denied
    # connect must already be closed by the gate -- WITHOUT any test-side
    # close. A surviving open fd is the leak.
    open_fds = [s for s in created if _fd_is_open(s)]
    # Defensive cleanup of any genuinely-leaked socket so a FAILING run of
    # this test does not itself emit a ResourceWarning while reporting.
    for s in open_fds:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            s.close()
    assert not open_fds, (
        "denied egress leaked an unclosed socket: the gate raised "
        "RelaySocketDenyError (not an OSError) so the library's "
        "'except OSError: sock.close()' cleanup was skipped, and the gate "
        f"did not close it either. Leaked sockets: {[id(s) for s in open_fds]}"
    )


@pytest.mark.fulfills("VAL-W7-084")
def test_denied_egress_emits_no_resourcewarning_under_w_error() -> None:
    """End-to-end: a denied egress through a library helper emits no
    ``ResourceWarning`` at GC, with NO test-side gc/close workaround for the
    leak.

    This is the structural symptom the W7.5 test was working around. With the
    gate closing the socket at the source, a forced ``gc.collect()`` under
    ``warnings`` set to error-on-ResourceWarning produces nothing.

    RED (before fix): the leaked unconnected socket is finalized at
    ``gc.collect()`` and raises ``ResourceWarning`` (promoted to an error
    here) -> the test fails.
    GREEN (after fix): the gate closed the socket, so GC finds nothing to
    warn about.
    """
    with replay_session(), pytest.raises(RelaySocketDenyError):
        _connect_like_a_library(_NON_LOOPBACK_V4, 443)

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        # Force finalization of any leaked socket NOW. If the gate did not
        # close it, this raises ResourceWarning (promoted to an error).
        gc.collect()
