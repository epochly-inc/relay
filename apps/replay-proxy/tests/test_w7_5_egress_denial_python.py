"""W7.5 Python egress-denial matrix tests (VAL-W7-080..082, 084, 088).

Per eng plan A4 layered defense, the Python SDK's ``replay_session``
context manager installs a layer-2 socket-deny gate. While inside a
session, every non-loopback socket I/O MUST raise
:class:`RelaySocketDenyError` BEFORE any TCP SYN / UDP datagram leaves
the process. The W7.5 matrix proves this gate fires for every popular
Python HTTP client AND for raw socket / DNS-via-connect transports.

Coverage:

  * VAL-W7-080: ``requests.get('https://google.com')`` is blocked.
  * VAL-W7-081: ``urllib.request.urlopen`` is blocked.
  * VAL-W7-082: ``aiohttp.ClientSession.get`` is blocked under asyncio.
  * VAL-W7-084: raw ``socket.socket(AF_INET, SOCK_STREAM).connect(...)``
    is blocked (load-bearing layer-2 case from adversarial check #3).
  * VAL-W7-088: DNS resolution to a non-loopback resolver, followed by
    a connect to the resolved address, is blocked at the connect step
    (or earlier).

The cross-language matrix invariant: every transport, when invoked
under ``replay_session()``, raises a Relay-typed exception (subclass of
``RelaySocketDenyError``) AND emits zero non-loopback packets. The
"zero packets" guarantee is structural: ``RelaySocketDenyError`` is
raised on the connect / connect_ex / sendto / sendmsg call BEFORE the
kernel TCP/UDP path is reached.

VAL-W7-083 (subprocess curl HTTPS_PROXY inheritance) and the cassette-
hit / cassette-miss / side-effect tests live in sibling files so each
file stays focused on one transport family.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import urllib.error
import urllib.request

import pytest
from relay.replay_mode import (
    RELAY_REPLAY_SESSION_ENV,
    RelaySocketDenyError,
    is_socket_deny_installed,
    replay_session,
    uninstall_socket_deny,
)

pytestmark = pytest.mark.plumbing


# Globally-routable IPv4 / hostname pair used as the deny target across
# every transport. Cloudflare and Google public addresses are deliberately
# chosen so the test INTENT is unambiguous: "no packet leaves the box".
# Because the deny gate raises BEFORE any TCP SYN / UDP datagram leaves
# the process, no actual network traffic is emitted.
_NON_LOOPBACK_HOST = "google.com"
_NON_LOOPBACK_V4 = "8.8.8.8"


@pytest.fixture(autouse=True)
def _isolate_replay_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure ``RELAY_REPLAY_SESSION`` is unset for every test.

    A leftover env var from a prior test (or the CI parent process)
    would install the gate at module import time and corrupt every
    "outside the session" assertion. Defensive: if a prior test crashed
    mid-session, restore originals.
    """
    monkeypatch.delenv(RELAY_REPLAY_SESSION_ENV, raising=False)
    if is_socket_deny_installed():
        uninstall_socket_deny()


# ---------------------------------------------------------------------------
# VAL-W7-080: requests.get('https://...') is blocked under replay
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-080")
def test_requests_get_external_blocked_under_replay() -> None:
    """``requests.get('https://google.com')`` raises a Relay-typed deny.

    The ``requests`` library uses ``urllib3`` -> stdlib ``http.client``
    -> stdlib ``socket.create_connection``. The W7.3 socket-deny gate
    patches ``socket.create_connection`` so the raise happens BEFORE
    ``urllib3`` opens any TLS connection. The exception bubbles up
    through ``requests`` and surfaces as ``ConnectionError`` whose
    ``__cause__`` (or in newer urllib3, the chained
    ``urllib3.exceptions.NewConnectionError`` wrapping)
    is a :class:`RelaySocketDenyError`.
    """
    requests = pytest.importorskip("requests")
    with replay_session():
        with pytest.raises(Exception) as excinfo:
            requests.get(f"https://{_NON_LOOPBACK_HOST}/", timeout=2.0)
        # Walk the cause chain: requests wraps low-level errors in its
        # own ConnectionError. The Relay deny MUST be reachable from
        # the chain so operators can grep stack traces for the wire
        # code RELAY-SDK-012 / RELAY-SDK-SOCKET-DENY.
        seen_classes: list[str] = []
        cur: BaseException | None = excinfo.value
        while cur is not None:
            seen_classes.append(type(cur).__name__)
            if isinstance(cur, RelaySocketDenyError):
                assert cur.code == "RELAY-SDK-012"
                assert cur.error_class == "RELAY-SDK-SOCKET-DENY"
                return
            cur = cur.__cause__ or cur.__context__
        pytest.fail(
            "expected RelaySocketDenyError in cause chain; got "
            + " <- ".join(seen_classes)
        )


@pytest.mark.fulfills("VAL-W7-080")
# Narrow to the specific socket-cleanup unraisable we expect from
# urllib3 / socket.socket GC after an ECONNREFUSED tear-down -- not
# every PytestUnraisableExceptionWarning. The wording depends on
# CPython version:
#   3.13 and earlier: "Exception ignored in: <socket.socket fd=N, ...>"
#   3.14+:            "Exception ignored while finalizing socket
#                      <socket.socket fd=N, ...>: None"
# Both wordings contain the literal ``socket.socket`` substring
# (referencing the socket.socket class repr in the warning body), so
# match on ``Exception ignored.*socket\.socket`` to cover both forms
# without the brittleness of needing a space-prefixed " socket" after
# the wording prefix. A bare
# `ignore::pytest.PytestUnraisableExceptionWarning` would weaken the
# repo-wide ``filterwarnings = ["error", ...]`` policy for this test.
@pytest.mark.filterwarnings(
    "ignore:Exception ignored.*socket\\.socket"
    ":pytest.PytestUnraisableExceptionWarning"
)
def test_requests_get_loopback_passes_through() -> None:
    """A request to ``127.0.0.1:<closed>`` raises ``ConnectionError`` at
    the kernel level (not RelaySocketDenyError) because loopback is
    explicitly allowed by the gate. This proves we do NOT over-block.

    The ``PytestUnraisableExceptionWarning`` filter accommodates a
    benign socket-cleanup warning: ECONNREFUSED tears down urllib3's
    TCP socket, but the Python ``socket.socket`` wrapper may be
    GC-finalized AFTER pytest's capture window closes, producing a
    stray ``ResourceWarning`` that pyproject.toml's
    ``filterwarnings = ["error", ...]`` promotes to a test failure.
    Surfaces only on slower CI runners (timing-dependent); the
    assertion above already verifies test logic (correct exception
    type, absence of RelaySocketDenyError).
    """
    requests = pytest.importorskip("requests")
    # Pick a port that's almost certainly not bound. The kernel will
    # respond with ECONNREFUSED, which requests surfaces as
    # ConnectionError. Crucially, this is NOT a RelaySocketDenyError.
    with replay_session():
        with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
            requests.get("http://127.0.0.1:1/", timeout=2.0)
        cur: BaseException | None = excinfo.value
        while cur is not None:
            assert not isinstance(cur, RelaySocketDenyError), (
                "loopback must NOT be blocked by the deny gate"
            )
            cur = cur.__cause__ or cur.__context__


# ---------------------------------------------------------------------------
# VAL-W7-081: urllib.request.urlopen is blocked under replay
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-081")
def test_urllib_urlopen_external_blocked_under_replay() -> None:
    """``urllib.request.urlopen`` raises a Relay-typed deny.

    The stdlib ``urllib`` path goes:
        urlopen -> http.client.HTTPSConnection -> socket.create_connection.
    The W7.3 gate patches ``socket.create_connection`` so the raise
    happens before any TLS handshake. urllib wraps it in
    ``urllib.error.URLError``; the Relay deny MUST be reachable from
    the cause chain.
    """
    with replay_session():
        with pytest.raises(Exception) as excinfo:
            urllib.request.urlopen(
                f"https://{_NON_LOOPBACK_HOST}/", timeout=2.0
            )
        cur: BaseException | None = excinfo.value
        seen: list[str] = []
        while cur is not None:
            seen.append(type(cur).__name__)
            if isinstance(cur, RelaySocketDenyError):
                assert cur.code == "RELAY-SDK-012"
                assert cur.error_class == "RELAY-SDK-SOCKET-DENY"
                return
            cur = cur.__cause__ or cur.__context__
        pytest.fail(
            "expected RelaySocketDenyError in cause chain; got "
            + " <- ".join(seen)
        )


@pytest.mark.fulfills("VAL-W7-081")
def test_urllib_urlopen_outside_session_is_not_intercepted() -> None:
    """Outside an active session, urllib MUST NOT touch the deny gate.

    Negative assertion that proves VAL-W7-047 still holds for the
    urllib transport family.
    """
    # Use a closed loopback port to avoid actual external network.
    with pytest.raises(urllib.error.URLError) as excinfo:
        urllib.request.urlopen("http://127.0.0.1:1/", timeout=1.0)
    cur: BaseException | None = excinfo.value
    while cur is not None:
        assert not isinstance(cur, RelaySocketDenyError), (
            "outside replay_session, the gate must not fire"
        )
        cur = cur.__cause__ or cur.__context__


# ---------------------------------------------------------------------------
# VAL-W7-082: aiohttp.ClientSession.get is blocked under replay
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-082")
def test_aiohttp_get_external_blocked_under_replay() -> None:
    """``aiohttp.ClientSession.get`` is blocked under replay.

    aiohttp uses an asyncio event loop with its own connector that
    eventually calls ``socket.socket(AF_INET, SOCK_STREAM).connect()``
    via the loop's transport selector. The W7.3 gate patches
    ``socket.socket.connect`` so EVERY happy-eyeballs candidate raises
    :class:`RelaySocketDenyError` BEFORE the kernel TCP path is reached.

    aiohttp 3.10+ delegates connection establishment to the
    ``aiohappyeyeballs`` library, which collects per-candidate
    exceptions and (in some failure modes) presents an ``IndexError``
    when every candidate is denied synchronously. The contract
    assertion VAL-W7-082 is "the request MUST be blocked": we satisfy
    it by asserting (a) the request raises any non-success exception,
    and (b) ``socket.socket.connect`` was called by aiohttp during the
    attempt and EVERY such call raised :class:`RelaySocketDenyError`.
    The combined evidence proves no datagram leaves the process.

    The asyncio loop is created and torn down inside the test so
    leaked tasks cannot cross test boundaries.
    """
    aiohttp = pytest.importorskip("aiohttp")
    import gc
    import warnings

    # Track every connect() raise reason so we have direct evidence
    # that every aiohttp connection attempt was denied (not just that
    # the request raised SOMETHING). The deny gate patches
    # ``socket.socket.connect`` itself, so we wrap that BOUND method
    # post-install to record raises without re-installing the gate.
    raises_seen: list[BaseException] = []
    # Also track every socket aiohttp's connector created so we can
    # close them deterministically before pytest's unraisable hook
    # runs. aiohappyeyeballs leaks the per-candidate socket when the
    # deny gate raises synchronously (the candidate-cleanup branch
    # only runs on async timeouts), and the leaked socket triggers a
    # ResourceWarning at GC -- which pytest -W error promotes to a
    # session failure. Manual close before exiting replay_session()
    # avoids the leak without changing aiohttp behavior.
    created_sockets: list[socket.socket] = []
    original_socket_init = socket.socket.__init__

    def _tracking_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        original_socket_init(self, *args, **kwargs)
        created_sockets.append(self)

    async def _attempt() -> BaseException | None:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"https://{_NON_LOOPBACK_HOST}/",
                    timeout=aiohttp.ClientTimeout(total=2.0),
                ) as _resp:
                    return None  # Should be unreachable.
            except BaseException as exc:
                return exc
        return None

    with replay_session():
        # Wrap the (already patched) socket.connect to capture every
        # raise. The gate has installed its replacement on
        # ``socket.socket.connect``; we wrap it once more for tracing.
        gated_connect = socket.socket.connect

        def _tracing_connect(self, address):  # type: ignore[no-untyped-def]
            try:
                return gated_connect(self, address)
            except BaseException as exc:
                raises_seen.append(exc)
                raise

        socket.socket.connect = _tracing_connect  # type: ignore[assignment]
        socket.socket.__init__ = _tracking_init  # type: ignore[assignment]
        try:
            loop = asyncio.new_event_loop()
            try:
                err = loop.run_until_complete(_attempt())
            finally:
                loop.close()
        finally:
            socket.socket.connect = gated_connect  # type: ignore[assignment]
            socket.socket.__init__ = original_socket_init  # type: ignore[assignment]
            # Close every socket aiohttp created so the unraisable
            # ResourceWarning never fires. Use catch_warnings so even
            # close-time warnings stay scoped to this block.
            import contextlib
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                for sk in created_sockets:
                    with contextlib.suppress(Exception):
                        sk.close()
                gc.collect()

    # (a) Request raised some exception -- the connection did not
    # succeed. The exception class varies (ClientConnectorError,
    # IndexError from aiohappyeyeballs, etc.) per aiohttp version, so
    # we treat the failure mode itself as the proof of denial.
    assert err is not None, "aiohttp request must NOT succeed under replay"

    # (b) At least one socket.connect() attempt was made by aiohttp,
    # and EVERY observed raise was a Relay deny. The combined
    # invariant is the structural guarantee VAL-W7-082 requires:
    # "zero non-loopback packets" (because the deny raises before
    # the SYN) plus "Relay-wrapped error".
    assert len(raises_seen) >= 1, (
        "aiohttp must have attempted at least one socket.connect; "
        "the deny gate had nothing to fire on"
    )
    for exc in raises_seen:
        assert isinstance(exc, RelaySocketDenyError), (
            "every aiohttp connect attempt must raise the Relay deny; "
            f"got {type(exc).__name__}: {exc!r}"
        )
        assert exc.code == "RELAY-SDK-012"
        assert exc.error_class == "RELAY-SDK-SOCKET-DENY"


# ---------------------------------------------------------------------------
# VAL-W7-084: raw socket.socket(AF_INET, SOCK_STREAM).connect is blocked
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-084")
def test_raw_socket_af_inet_stream_connect_external_blocked() -> None:
    """``socket.socket(AF_INET, SOCK_STREAM).connect(('8.8.8.8', 443))``
    raises :class:`RelaySocketDenyError` synchronously, before any TCP
    SYN reaches the kernel.

    This is the load-bearing adversarial-check #3 case: raw sockets are
    NOT caught by HTTPS_PROXY env inheritance because they never go
    through libcurl/requests. Layer 2 socket-deny is the ONLY defense
    for this transport.
    """
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
            # The remediation hint MUST point at the cassette-record
            # flow so operators have a concrete recovery path.
            assert "rly replay record" in err.remediation
        finally:
            s.close()


@pytest.mark.fulfills("VAL-W7-084")
def test_raw_socket_connect_ex_external_blocked() -> None:
    """``socket.socket.connect_ex`` is patched the same as ``connect``.

    Some libraries call ``connect_ex`` to get an errno instead of an
    exception. The deny gate MUST raise on this path too; otherwise
    such libraries silently bypass replay isolation.
    """
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError):
                s.connect_ex((_NON_LOOPBACK_V4, 443))
        finally:
            s.close()


# ---------------------------------------------------------------------------
# VAL-W7-088: DNS resolution + connect to non-loopback resolvers blocked
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-088")
def test_resolved_address_connect_blocked_under_replay() -> None:
    """The post-DNS connect step MUST be denied.

    ``socket.gethostbyname`` itself is a stdlib resolver call that
    consults system DNS via UDP/53. The W7.3 gate does not patch
    ``gethostbyname`` (it patches socket I/O instead) because DNS
    resolution may be served from /etc/hosts or a sidecar that lives on
    loopback. What the gate MUST catch is the SUBSEQUENT connect to the
    resolved address: an agent that resolved 8.8.8.8 and tried to
    connect there is escaping replay isolation.
    """
    # The resolved address is hard-coded so the test does not depend
    # on the DNS state of the runner. Per VAL-W7-088 the structural
    # guarantee is "the connect to a non-loopback resolved address is
    # blocked"; we simulate the resolved address directly.
    resolved_ip = _NON_LOOPBACK_V4
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                s.connect((resolved_ip, 443))
            assert excinfo.value.dest_address == resolved_ip
        finally:
            s.close()


@pytest.mark.fulfills("VAL-W7-088")
def test_udp_sendto_external_resolver_blocked() -> None:
    """``socket.socket(AF_INET, SOCK_DGRAM).sendto((<external>, 53), ...)``
    raises a Relay deny.

    Direct DNS-over-UDP/53 to a non-loopback resolver is the second
    half of VAL-W7-088: the SOCK_DGRAM gate denies sendto() to
    non-loopback destinations so an agent cannot bypass the layer-2
    deny by sending raw DNS queries to 8.8.8.8:53.
    """
    with replay_session():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(RelaySocketDenyError) as excinfo:
                # A minimal DNS query packet header. The payload is
                # irrelevant; the deny gate fires on sendto() before
                # any datagram leaves the process.
                s.sendto(b"\x00" * 12, (_NON_LOOPBACK_V4, 53))
            err = excinfo.value
            assert err.dest_address == _NON_LOOPBACK_V4
            assert err.dest_port == 53
        finally:
            s.close()


# ---------------------------------------------------------------------------
# Coverage sentinel: every transport raises a Relay-typed deny
# ---------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-W7-080")
@pytest.mark.fulfills("VAL-W7-081")
@pytest.mark.fulfills("VAL-W7-082")
@pytest.mark.fulfills("VAL-W7-084")
def test_egress_denial_coverage_sentinel() -> None:
    """Sentinel: each Python transport class is reachable in this test
    module. Ensures no contract assertion silently loses its test
    binding to a refactor that drops a function.
    """
    transports = {
        "requests": "test_requests_get_external_blocked_under_replay",
        "urllib": "test_urllib_urlopen_external_blocked_under_replay",
        "aiohttp": "test_aiohttp_get_external_blocked_under_replay",
        "raw_socket": "test_raw_socket_af_inet_stream_connect_external_blocked",
    }
    # Optional imports: aiohttp / requests may be skipped if absent.
    have_requests = importlib.util.find_spec("requests") is not None
    have_aiohttp = importlib.util.find_spec("aiohttp") is not None
    assert have_requests, (
        "requests is a declared test dep of epochly-relay-replay-proxy "
        "(VAL-W7-080); install via 'uv sync --all-packages --all-extras'"
    )
    assert have_aiohttp, (
        "aiohttp is a declared test dep of epochly-relay-replay-proxy "
        "(VAL-W7-082); install via 'uv sync --all-packages --all-extras'"
    )
    # Every transport has a paired test in this module.
    import sys
    me = sys.modules[__name__]
    for transport, test_name in transports.items():
        assert hasattr(me, test_name), (
            f"missing test for transport {transport!r}: {test_name}"
        )
