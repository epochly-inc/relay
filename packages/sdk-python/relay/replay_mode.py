"""SDK replay-mode primitives (W3.5 + W7.3).

Per eng plan A4 ("defense in depth for replay isolation") this module
owns two of the four layers:

  Layer 2: ``install_socket_deny`` monkey-patches ``socket.socket`` so
           any non-loopback I/O (``connect``/``connect_ex``/``sendto``/
           ``sendmsg``/``send``/``sendall``/``bind``) raises
           :class:`RelaySocketDenyError`. ``socket.create_connection``
           is patched the same way. ``sendmsg`` carries an explicit
           destination like ``sendto`` (VAL-W7-088) so it is gated too
           where the platform provides it (absent on Windows).
           ``send``/``sendall`` and the no-address form of ``sendmsg``
           carry NO destination -- they target the socket's connected
           peer, which may have been set before the session was entered
           -- so they are gated against that peer via ``getpeername``
           (VAL-W7-088). ``socket.getaddrinfo`` is left intact
           (informational); the patch catches the resolved-address
           connect via the connect gate. ``uninstall_socket_deny``
           restores every original reference.

  Layer 4: ``require_instrumented_http_clients`` scans ``sys.modules``
           for uninstrumented HTTP-client modules (``requests``,
           ``aiohttp``, ``urllib3``) and raises
           :class:`RelayUninstrumentedHTTPError` if any are loaded
           without a Relay wrapper. The function is intended to be
           called by the SDK's replay-mode entry point so callers see
           an init ERROR (not warning) before any cassette/live work.

W7.3 extensions (VAL-W7-040 .. VAL-W7-047):
  * Coverage now includes ``AF_UNIX`` (denied unless target path is the
    registered local sidecar socket), ``SOCK_RAW``, ``SOCK_DGRAM``
    (UDP ``sendto`` and ``connect``), and ``socket.create_connection``.
  * :class:`RelaySocketDenyError` carries structured fields
    ``dest_address``, ``dest_port``, ``family``, ``socktype``, plus a
    ``remediation`` hint pointing at the cassette-recording flow
    (VAL-W7-044). The legacy ``details["target"]`` field is preserved
    for back-compat with W3.5 tests.
  * :func:`replay_session` is a context manager that installs the gate
    on ``__enter__`` and restores on ``__exit__`` (VAL-W7-043).
  * The patch is re-applied automatically on import when the
    ``RELAY_REPLAY_SESSION`` environment variable is set, which lets
    the gate survive ``multiprocessing.spawn`` on Windows
    (VAL-W7-046). The env var's value (when non-empty) is the
    allowed sidecar UNIX-socket path; an empty string means "no
    sidecar UNIX socket allowed, only loopback IP".
  * Outside an active session the SDK does NOT touch ``socket``
    (VAL-W7-047).

VAL-W3-051: :func:`replay_run` defaults to cassette mode and refuses
live mode unless the caller passes both ``mode="live"`` AND
``acknowledge_degraded_approximation=True``. The persisted record
carries the ``mode`` field so downstream binders can distinguish
faithful cassette replays from live degraded approximations.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import ssl
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from .errors import RelaySdkError

# -----------------------------------------------------------------------------
# Error codes / classes
# -----------------------------------------------------------------------------

RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CODE: Final[str] = "RELAY-SDK-011"
RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CLASS: Final[str] = (
    "RELAY-SDK-REPLAY-UNINSTRUMENTED-HTTP"
)

RELAY_SDK_SOCKET_DENY_CODE: Final[str] = "RELAY-SDK-012"
RELAY_SDK_SOCKET_DENY_CLASS: Final[str] = "RELAY-SDK-SOCKET-DENY"

RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CODE: Final[str] = "RELAY-SDK-013"
RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CLASS: Final[str] = (
    "RELAY-SDK-REPLAY-DEGRADED-MODE-NOT-ACKNOWLEDGED"
)

# Environment variable that signals "we are inside a replay session". When
# set (even to the empty string) at module import the gate is installed
# eagerly so that processes started via ``multiprocessing.spawn`` --
# which on Windows re-import this module from a fresh interpreter --
# inherit the patch (VAL-W7-046). The value, when non-empty, is the
# allowed sidecar UNIX-socket path.
RELAY_REPLAY_SESSION_ENV: Final[str] = "RELAY_REPLAY_SESSION"

# Default remediation hint surfaced on every RelaySocketDenyError. Points
# the user at the cassette-recording flow (VAL-W7-044). Kept short and
# ASCII so the message survives every CLI / log surface.
_REMEDIATION_HINT: Final[str] = (
    "Replay mode is cassette-only by default. Re-record the cassette via "
    "'rly replay record' against the desired target, or exit replay mode "
    "before performing non-loopback network I/O."
)


class RelayUninstrumentedHTTPError(RelaySdkError):
    """Replay-mode init detected an HTTP client module without a Relay wrapper.

    Per eng plan A4 layer 4 this is an init ERROR, not a warning. The
    SDK refuses to enter replay mode while uninstrumented modules are
    present in ``sys.modules`` because raw HTTP egress would bypass
    cassette playback.
    """

    code: str = RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CODE
    error_class: ClassVar[str] = RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CLASS
    http_status: int = 400
    default_blocked_surface: ClassVar[str] = "relay-sdk-replay-init"
    default_retry_advice: ClassVar[str] = "after_state_change"


class RelaySocketDenyError(RelaySdkError):
    """Replay-mode socket deny: non-loopback socket I/O blocked.

    Per eng plan A4 layer 2 the SDK monkey-patches ``socket.socket`` so
    any non-loopback egress raises this error synchronously. Loopback
    (127.0.0.0/8, ::1, ``localhost``) is allowed; ``AF_UNIX`` is
    allowed only when the target path matches the registered sidecar
    UNIX socket.

    The exception carries structured fields per VAL-W7-044:
      ``dest_address`` -- the host/path argument the caller passed.
      ``dest_port``    -- the port (None for AF_UNIX or non-tuple addrs).
      ``family``       -- the socket family name (e.g. ``"AF_INET"``).
      ``socktype``     -- the socket type name (e.g. ``"SOCK_STREAM"``).
      ``remediation``  -- a short hint pointing at cassette recording.
    These fields are also surfaced on the ``details`` dict for
    downstream consumers that read the structured envelope. The legacy
    ``details["target"]`` field is preserved for W3.5-era callers.
    """

    code: str = RELAY_SDK_SOCKET_DENY_CODE
    error_class: ClassVar[str] = RELAY_SDK_SOCKET_DENY_CLASS
    http_status: int = 403
    default_blocked_surface: ClassVar[str] = "socket.socket.connect"
    default_retry_advice: ClassVar[str] = "no_retry"

    def __init__(
        self,
        message: str,
        *,
        dest_address: str = "",
        dest_port: int | None = None,
        family: str = "",
        socktype: str = "",
        operation: str = "",
        remediation: str = _REMEDIATION_HINT,
        details: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        merged_details: dict[str, Any] = dict(details) if details else {}
        # W7.3 structured fields (VAL-W7-044).
        merged_details.setdefault("dest_address", dest_address)
        merged_details.setdefault("dest_port", dest_port)
        merged_details.setdefault("family", family)
        merged_details.setdefault("socktype", socktype)
        merged_details.setdefault("operation", operation)
        merged_details.setdefault("remediation", remediation)
        # W3.5 back-compat: existing tests assert ``details["target"]``
        # contains the host string. Preserve the legacy field.
        merged_details.setdefault("target", dest_address)
        super().__init__(message, details=merged_details, **kwargs)
        self.dest_address: str = dest_address
        self.dest_port: int | None = dest_port
        self.family: str = family
        self.socktype: str = socktype
        self.operation: str = operation
        self.remediation: str = remediation


class RelayReplayDegradedModeNotAcknowledged(RelaySdkError):
    """Caller requested live replay without acknowledging the degraded mode.

    Per CLAUDE.md keystone invariant #9 cassette replay is the default
    and the only mode that produces evidence-faithful records. Live
    replay is a "degraded approximation" -- side effects fire,
    timings drift, providers may have rotated model_signature -- so the
    caller MUST pass ``acknowledge_degraded_approximation=True`` to
    opt in.
    """

    code: str = RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CODE
    error_class: ClassVar[str] = (
        RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CLASS
    )
    http_status: int = 400
    default_blocked_surface: ClassVar[str] = "relay.replay.run"
    default_retry_advice: ClassVar[str] = "no_retry"


# -----------------------------------------------------------------------------
# Layer 4: uninstrumented HTTP client detection
# -----------------------------------------------------------------------------

# Modules that perform direct HTTP egress and bypass cassette playback if
# not wrapped by Relay. ``httpx`` is intentionally NOT in this set: the
# SDK uses httpx for loopback-only sidecar communication and that traffic
# is already loopback-bounded by the socket-deny layer.
_UNINSTRUMENTED_HTTP_MODULES: Final[frozenset[str]] = frozenset(
    {"requests", "aiohttp", "urllib3"}
)

# A module is considered "instrumented" when this attribute is present
# (the Relay wrappers set it). Tests can set it explicitly on a fake
# module to assert the allowlist path.
_RELAY_WRAPPER_ATTR: Final[str] = "__relay_wrapped__"


def require_instrumented_http_clients() -> None:
    """Raise :class:`RelayUninstrumentedHTTPError` if uninstrumented modules
    are loaded.

    A module is "uninstrumented" when it is present in ``sys.modules``
    AND it does not carry the ``__relay_wrapped__`` attribute set by
    the Relay HTTP-client wrappers. Per eng plan A4 layer 4 the SDK
    refuses to enter replay mode while any uninstrumented HTTP client is
    importable.

    Raises:
        RelayUninstrumentedHTTPError: One or more modules are loaded
            without a Relay wrapper.
    """
    unwrapped: list[str] = []
    for modname in _UNINSTRUMENTED_HTTP_MODULES:
        mod = sys.modules.get(modname)
        if mod is None:
            continue
        if getattr(mod, _RELAY_WRAPPER_ATTR, False):
            continue
        unwrapped.append(modname)
    if unwrapped:
        unwrapped.sort()
        raise RelayUninstrumentedHTTPError(
            "Relay refused to enter replay mode: uninstrumented HTTP "
            f"client modules detected in sys.modules: {unwrapped!r}. "
            "Wrap them with Relay's adapters before initializing replay mode.",
            details={"unwrapped_modules": unwrapped},
        )


# -----------------------------------------------------------------------------
# Layer 2: socket.socket deny (W3.5 base + W7.3 extensions)
# -----------------------------------------------------------------------------

_socket_lock = threading.Lock()

# Saved originals; populated when the gate is installed and restored on
# uninstall. Keys are method/function names; values are the original
# callables. Empty dict means "not currently patched".
_socket_originals: dict[str, Any] = {}

# Allowed sidecar UNIX-socket path. ``None`` means "no sidecar socket
# allowed, deny every AF_UNIX target". Set by :func:`install_socket_deny`.
_allowed_sidecar_unix_path: str | None = None


def _is_loopback_address(host: str) -> bool:
    """Return True if ``host`` is a loopback IPv4 or IPv6 literal.

    The literal ``"localhost"`` is also accepted because every modern
    libc resolver returns 127.0.0.1 / ::1 for it; gating on the literal
    string avoids forcing a DNS lookup inside the deny path.
    """
    if not host:
        return False
    if host == "localhost":
        return True
    # Strip scope id from IPv6 link-local (``fe80::1%eth0``) before parse.
    parsed = host.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(parsed)
    except ValueError:
        # A hostname; only literal IPs are accepted as loopback per A4
        # layer 2 (so the patch can't be bypassed by DNS resolution
        # returning a non-loopback A record).
        return False
    return ip.is_loopback


def _family_name(family: int) -> str:
    """Return the symbolic name for ``family`` (e.g. ``"AF_INET"``)."""
    try:
        return socket.AddressFamily(family).name
    except (ValueError, AttributeError):
        return f"AF_UNKNOWN({family})"


def _socktype_name(socktype: int) -> str:
    """Return the symbolic name for ``socktype`` (e.g. ``"SOCK_STREAM"``)."""
    try:
        # SOCK_NONBLOCK / SOCK_CLOEXEC may be ORed in on Linux; mask them
        # off for the symbolic lookup.
        base = socktype & 0xFF
        return socket.SocketKind(base).name
    except (ValueError, AttributeError):
        return f"SOCK_UNKNOWN({socktype})"


def _extract_host_port(address: Any) -> tuple[str, int | None]:
    """Pull (host, port) out of the various address shapes ``socket`` accepts."""
    if isinstance(address, tuple):
        if len(address) >= 2:
            host = str(address[0]) if address[0] is not None else ""
            try:
                port: int | None = int(address[1]) if address[1] is not None else None
            except (TypeError, ValueError):
                port = None
            return host, port
        if len(address) == 1:
            return (str(address[0]) if address[0] is not None else ""), None
        return "", None
    if isinstance(address, bytes | bytearray):
        # AF_UNIX abstract / filesystem path delivered as bytes.
        try:
            return bytes(address).decode("utf-8", errors="replace"), None
        except Exception:
            return repr(address), None
    if isinstance(address, str):
        return address, None
    return repr(address), None


def _is_address_allowed(
    family: int,
    socktype: int,
    address: Any,
) -> tuple[bool, str, int | None]:
    """Return ``(allowed, host, port)`` for the given socket parameters.

    Decision matrix:
      * AF_INET / AF_INET6: allowed iff host is a loopback literal or
        ``localhost``.
      * AF_UNIX: allowed iff the path equals the registered sidecar
        UNIX-socket path. An unset registration denies every AF_UNIX.
      * Anything else (AF_PACKET, AF_NETLINK, ...): denied. These
        families are never legitimate inside a replay sandbox.
    """
    host, port = _extract_host_port(address)
    if family == socket.AF_INET or family == socket.AF_INET6:
        return _is_loopback_address(host), host, port
    if hasattr(socket, "AF_UNIX") and family == socket.AF_UNIX:
        if _allowed_sidecar_unix_path is None:
            return False, host, port
        # Compare resolved paths so /var/relay vs /private/var/relay on
        # macOS still match. Empty / non-existent paths fall through to
        # plain string compare.
        try:
            real_target = os.path.realpath(host) if host else ""
            real_allowed = os.path.realpath(_allowed_sidecar_unix_path)
        except OSError:
            real_target = host
            real_allowed = _allowed_sidecar_unix_path
        return real_target == real_allowed, host, port
    return False, host, port


def _close_socket_quietly(sock: socket.socket) -> None:
    """Close ``sock`` swallowing any error, so the deny path never leaks it.

    Called by the connect / connect_ex gates BEFORE raising the deny.
    :func:`socket.socket.close` is idempotent, so callers that ALSO close
    the socket in their own ``finally`` are unaffected (the second close is a
    no-op). We close the ORIGINAL, unpatched object: ``close`` is not one of
    the patched methods, so ``sock.close()`` is the genuine close.
    """
    # A socket that was never given a real fd (or already closed) may raise
    # here. Either way there is nothing left to leak, so suppress.
    with contextlib.suppress(OSError):
        sock.close()


def _raise_deny(
    *,
    operation: str,
    family: int,
    socktype: int,
    host: str,
    port: int | None,
    address: Any,
) -> None:
    """Raise a fully-populated :class:`RelaySocketDenyError`."""
    fam = _family_name(family)
    sock = _socktype_name(socktype)
    target_repr = host if port is None else f"{host}:{port}"
    # Address-payload sanitisation: ``details`` is intended to be JSON-
    # serialisable. Coerce non-primitive shapes via repr so the envelope
    # never carries arbitrary objects.
    if isinstance(address, str | int | float | bool | list | dict | type(None)):
        addr_payload: Any = address
    elif isinstance(address, tuple):
        addr_payload = list(address)
    else:
        addr_payload = repr(address)
    raise RelaySocketDenyError(
        "Replay mode denied non-loopback socket "
        f"{operation}: family={fam} socktype={sock} target={target_repr!r}. "
        f"{_REMEDIATION_HINT}",
        dest_address=host,
        dest_port=port,
        family=fam,
        socktype=sock,
        operation=operation,
        remediation=_REMEDIATION_HINT,
        details={"address": addr_payload},
    )


# ---- patched socket.socket methods ----------------------------------------


def _gate_connected_peer(self: socket.socket, operation: str) -> None:
    """Deny an address-less send when the socket's connected peer is external.

    ``send``/``sendall`` and the no-address form of ``sendmsg`` carry no
    explicit destination: the datagram/stream targets whatever peer the
    socket was connected to. That ``connect`` may have happened BEFORE the
    replay session was entered (UDP ``connect`` emits no packet, so it
    completes outside the gate), leaving an external default peer that
    these address-less sends would egress to with no deny check (HIGH
    default-deny egress hole; keystone invariant #9 + VAL-W7-088).

    We resolve the peer via :meth:`socket.socket.getpeername` and route it
    through the same :func:`_is_address_allowed` decision as an explicit
    destination. A non-allowlisted external peer raises
    :class:`RelaySocketDenyError`. An UNCONNECTED socket --
    ``getpeername`` raises ``OSError`` (ENOTCONN) -- has no peer to
    evaluate, so we return and let the original method raise its own
    normal OS error.
    """
    # The connected-peer egress threat is IP networking only (VAL-W7-088).
    # AF_UNIX (sidecar IPC, the asyncio event loop's self-pipe socketpair,
    # other local IPC) cannot reach an external network and is already
    # controlled at connect time via sidecar_unix_path. Gating its
    # address-less sends here would deny asyncio's internal self-pipe wakeup
    # (BaseEventLoop._write_to_self -> csock.send(b"\\0")) and break ALL async
    # I/O (aiohttp, asyncio) run under replay_session. Only gate INET sockets.
    if self.family not in (socket.AF_INET, socket.AF_INET6):
        return
    try:
        peer = self.getpeername()
    except OSError:
        # Not connected: no peer to gate. Defer to the original method,
        # which itself raises the appropriate OSError.
        return
    allowed, host, port = _is_address_allowed(self.family, self.type, peer)
    if not allowed:
        _raise_deny(
            operation=operation,
            family=self.family,
            socktype=self.type,
            host=host,
            port=port,
            address=peer,
        )


def _denying_send(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``socket.socket.send``.

    ``send`` takes no destination -- it targets the socket's connected
    peer -- so it bypasses the address-based deny gates entirely. A
    socket connected to an external peer before the replay session (UDP
    ``connect`` sends no packet) would egress here unchecked. We gate the
    connected peer via :func:`_gate_connected_peer` (VAL-W7-088).
    """
    _gate_connected_peer(self, "send")
    return _socket_originals["send"](self, *args, **kwargs)


def _denying_sendall(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``socket.socket.sendall``.

    Shares the no-address connected-peer egress gap with ``send``; gated
    the same way via :func:`_gate_connected_peer` (VAL-W7-088).
    """
    _gate_connected_peer(self, "sendall")
    return _socket_originals["sendall"](self, *args, **kwargs)


def _denying_sendfile(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``socket.socket.sendfile``.

    ``sendfile`` is an address-less send to the connected peer; on
    Linux/macOS its default zero-copy ``os.sendfile`` path bypasses the
    patched ``socket.send``, so an external egress would slip past the
    gate. Patching the high-level ``socket.socket.sendfile`` itself gates
    BOTH the ``os.sendfile`` fast path and the ``send``-based fallback
    against the connected peer (VAL-W7-088).
    """
    _gate_connected_peer(self, "sendfile")
    return _socket_originals["sendfile"](self, *args, **kwargs)


def _denying_ssl_send(self: ssl.SSLSocket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``ssl.SSLSocket.send``.

    ``ssl.SSLSocket`` overrides ``send``/``sendall``/``write`` with its own
    SSL_write-backed implementations, so the ``socket.socket`` patches do NOT
    cover a TLS connection established BEFORE ``replay_session()`` -- a common
    HTTPS persistent-connection egress path. Gate the connected peer the same
    way (VAL-W7-088). asyncio's TLS uses a memory-BIO ``SSLObject`` (not
    ``SSLSocket``), so this does not touch the event loop.
    """
    _gate_connected_peer(self, "ssl_send")
    return _socket_originals["ssl_send"](self, *args, **kwargs)


def _denying_ssl_sendall(self: ssl.SSLSocket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``ssl.SSLSocket.sendall`` (VAL-W7-088)."""
    _gate_connected_peer(self, "ssl_sendall")
    return _socket_originals["ssl_sendall"](self, *args, **kwargs)


def _denying_ssl_write(self: ssl.SSLSocket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``ssl.SSLSocket.write`` (VAL-W7-088)."""
    _gate_connected_peer(self, "ssl_write")
    return _socket_originals["ssl_write"](self, *args, **kwargs)


def _denying_connect(self: socket.socket, address: Any) -> Any:
    """Replacement for ``socket.socket.connect``.

    Socket-leak hygiene (root-cause fix, finding
    ``fix-r4-iso-socket-leak-deep-latent``): library connect helpers
    (``socket.create_connection``, ``http.client``, urllib3's
    ``create_connection``) build the socket themselves then close it ONLY in
    an ``except OSError:`` branch. Because :class:`RelaySocketDenyError` is
    NOT an ``OSError`` that cleanup is skipped, so the just-built socket
    ``self`` would leak. We close ``self`` here -- BEFORE raising -- so no
    socket survives the deny regardless of how the caller handles the
    exception. ``socket.close`` is idempotent, so callers that also close in
    their own ``finally`` are unaffected.
    """
    allowed, host, port = _is_address_allowed(self.family, self.type, address)
    if not allowed:
        _close_socket_quietly(self)
        _raise_deny(
            operation="connect",
            family=self.family,
            socktype=self.type,
            host=host,
            port=port,
            address=address,
        )
    return _socket_originals["connect"](self, address)


def _denying_connect_ex(self: socket.socket, address: Any) -> Any:
    """Replacement for ``socket.socket.connect_ex``.

    ``connect_ex`` differs from ``connect`` only in that it returns the
    errno instead of raising; the deny gate still raises so callers
    cannot silently sweep the failure under a nonzero return code.

    Socket-leak hygiene: like :func:`_denying_connect`, close ``self``
    before raising so a denied ``connect_ex`` cannot leak the caller's
    just-built socket past a non-``OSError`` deny (idempotent close).
    """
    allowed, host, port = _is_address_allowed(self.family, self.type, address)
    if not allowed:
        _close_socket_quietly(self)
        _raise_deny(
            operation="connect_ex",
            family=self.family,
            socktype=self.type,
            host=host,
            port=port,
            address=address,
        )
    return _socket_originals["connect_ex"](self, address)


def _denying_sendto(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``socket.socket.sendto``.

    Accepts both call shapes: ``sendto(data, addr)`` and
    ``sendto(data, flags, addr)``. The address is the last positional
    argument; we extract it without copying ``data``.
    """
    address: Any = None
    if len(args) >= 2:
        address = args[-1]
    elif "address" in kwargs:
        address = kwargs["address"]
    allowed, host, port = _is_address_allowed(self.family, self.type, address)
    if not allowed:
        _raise_deny(
            operation="sendto",
            family=self.family,
            socktype=self.type,
            host=host,
            port=port,
            address=address,
        )
    return _socket_originals["sendto"](self, *args, **kwargs)


def _denying_sendmsg(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
    """Replacement for ``socket.socket.sendmsg``.

    ``sendmsg(buffers[, ancdata[, flags[, address]]])`` accepts an
    explicit destination as its 4th positional argument, exactly like
    ``sendto``. On an unconnected ``SOCK_DGRAM`` socket this is a UDP
    egress vector that would otherwise bypass the deny gate entirely
    (HIGH #12 default-deny egress hole; keystone invariant #9 +
    VAL-W7-088). We extract that destination and route it through the
    same :func:`_is_address_allowed` decision as ``sendto``.

    The CPython builtin ``socket.sendmsg`` accepts positional arguments
    only (it raises ``TypeError`` for keywords), so the destination --
    when supplied -- is always ``args[3]``. When fewer than four
    positionals are passed the caller omitted the address; the datagram
    then targets the socket's connected peer. That ``connect`` may have
    happened BEFORE the replay session (UDP ``connect`` emits no packet,
    so it completes outside the gate), so the no-address form is itself an
    egress vector: we gate the connected peer via
    :func:`_gate_connected_peer`. An unconnected socket has no peer to
    evaluate, so it falls through to the original ``sendmsg`` unchanged.
    """
    if len(args) >= 4:
        address: Any = args[3]
        allowed, host, port = _is_address_allowed(self.family, self.type, address)
        if not allowed:
            _raise_deny(
                operation="sendmsg",
                family=self.family,
                socktype=self.type,
                host=host,
                port=port,
                address=address,
            )
    else:
        _gate_connected_peer(self, "sendmsg")
    return _socket_originals["sendmsg"](self, *args, **kwargs)


def _denying_bind(self: socket.socket, address: Any) -> Any:
    """Replacement for ``socket.socket.bind``.

    Binding to a non-loopback interface would let a replay-mode process
    accept inbound traffic from outside the sandbox; the deny gate
    treats bind the same as connect.
    """
    allowed, host, port = _is_address_allowed(self.family, self.type, address)
    if not allowed:
        _raise_deny(
            operation="bind",
            family=self.family,
            socktype=self.type,
            host=host,
            port=port,
            address=address,
        )
    return _socket_originals["bind"](self, address)


# ---- patched module-level helpers -----------------------------------------


def _denying_create_connection(
    address: tuple[str, int],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Replacement for ``socket.create_connection``.

    ``create_connection`` is a higher-level helper that calls
    ``getaddrinfo`` then ``connect`` under the hood; we gate it directly
    so the deny error surfaces with the user's intended target rather
    than the (possibly misleading) post-resolution address.
    """
    host = ""
    port: int | None = None
    if isinstance(address, tuple) and len(address) >= 2:
        host = str(address[0])
        try:
            port = int(address[1])
        except (TypeError, ValueError):
            port = None
    if not _is_loopback_address(host):
        _raise_deny(
            operation="create_connection",
            family=socket.AF_INET,
            socktype=socket.SOCK_STREAM,
            host=host,
            port=port,
            address=address,
        )
    return _socket_originals["create_connection"](address, *args, **kwargs)


def install_socket_deny(*, sidecar_unix_path: str | None = None) -> None:
    """Patch ``socket`` to deny non-loopback I/O.

    Patches ``socket.socket.connect``, ``connect_ex``, ``sendto``,
    ``send``, ``sendall``, ``sendmsg`` (where the platform provides
    it), ``bind`` and ``socket.create_connection``. ``send``/``sendall``
    and the no-address ``sendmsg`` carry no destination, so they are
    gated against the socket's connected peer via ``getpeername``
    (VAL-W7-088). ``socket.getaddrinfo`` is intentionally LEFT INTACT
    (resolution is informational; the follow-up connect to the resolved
    address is what trips the gate; DNS UDP datagrams are denied via the
    SOCK_DGRAM ``sendto`` / ``sendmsg`` paths).

    Args:
        sidecar_unix_path: When non-None, AF_UNIX connects/sends to
            this exact path (after ``os.path.realpath``) are allowed.
            Every other AF_UNIX target is denied. ``None`` denies all
            AF_UNIX traffic.

    Idempotent: a second call while the patch is installed updates the
    allowed sidecar path but does not double-wrap the socket methods.

    Thread-safety: the patch is process-global and serialised by an
    internal lock. Per the contract gap note replay sessions running
    alongside non-replay sessions in the same process are out-of-scope
    for v0.1; tests assume single-process invocation.
    """
    global _allowed_sidecar_unix_path
    with _socket_lock:
        _allowed_sidecar_unix_path = sidecar_unix_path
        if _socket_originals:
            return
        _socket_originals["connect"] = socket.socket.connect
        _socket_originals["connect_ex"] = socket.socket.connect_ex
        _socket_originals["sendto"] = socket.socket.sendto
        _socket_originals["send"] = socket.socket.send
        _socket_originals["sendall"] = socket.socket.sendall
        _socket_originals["bind"] = socket.socket.bind
        _socket_originals["create_connection"] = socket.create_connection
        socket.socket.connect = _denying_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _denying_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = _denying_sendto  # type: ignore[method-assign,assignment]
        # ``send`` / ``sendall`` carry NO destination -- they target the
        # socket's connected peer, which may have been set before the
        # replay session was entered (VAL-W7-088). Gate the connected peer.
        socket.socket.send = _denying_send  # type: ignore[method-assign,assignment]
        socket.socket.sendall = _denying_sendall  # type: ignore[method-assign,assignment]
        socket.socket.bind = _denying_bind  # type: ignore[method-assign]
        socket.create_connection = _denying_create_connection  # type: ignore[assignment]
        # ``sendmsg`` carries an explicit destination just like ``sendto``
        # (VAL-W7-088); patch it too where the platform provides it. It is
        # absent on Windows, so guard with hasattr to keep the gate portable.
        if hasattr(socket.socket, "sendmsg"):
            _socket_originals["sendmsg"] = socket.socket.sendmsg
            socket.socket.sendmsg = _denying_sendmsg  # type: ignore[method-assign,assignment]
        # ``sendfile`` is an address-less connected-peer send whose default
        # zero-copy ``os.sendfile`` path bypasses the patched ``send``; gate it
        # the same way. Guard with hasattr for portability.
        if hasattr(socket.socket, "sendfile"):
            _socket_originals["sendfile"] = socket.socket.sendfile
            socket.socket.sendfile = _denying_sendfile  # type: ignore[method-assign,assignment]
        # ssl.SSLSocket overrides send/sendall/write with SSL_write-backed
        # methods that bypass the socket.socket patches; gate them too so a TLS
        # connection opened before replay_session cannot egress (VAL-W7-088).
        _socket_originals["ssl_send"] = ssl.SSLSocket.send
        _socket_originals["ssl_sendall"] = ssl.SSLSocket.sendall
        _socket_originals["ssl_write"] = ssl.SSLSocket.write
        ssl.SSLSocket.send = _denying_ssl_send  # type: ignore[method-assign,assignment]
        ssl.SSLSocket.sendall = _denying_ssl_sendall  # type: ignore[method-assign,assignment]
        ssl.SSLSocket.write = _denying_ssl_write  # type: ignore[method-assign,assignment]


def uninstall_socket_deny() -> None:
    """Restore every original ``socket`` reference patched by
    :func:`install_socket_deny`.

    Idempotent: safe to call when no patch is installed.
    """
    global _allowed_sidecar_unix_path
    with _socket_lock:
        if not _socket_originals:
            _allowed_sidecar_unix_path = None
            return
        socket.socket.connect = _socket_originals["connect"]  # type: ignore[method-assign]
        socket.socket.connect_ex = _socket_originals["connect_ex"]  # type: ignore[method-assign]
        socket.socket.sendto = _socket_originals["sendto"]  # type: ignore[method-assign,assignment]
        socket.socket.send = _socket_originals["send"]  # type: ignore[method-assign,assignment]
        socket.socket.sendall = _socket_originals["sendall"]  # type: ignore[method-assign,assignment]
        socket.socket.bind = _socket_originals["bind"]  # type: ignore[method-assign]
        socket.create_connection = _socket_originals["create_connection"]  # type: ignore[assignment]
        # Only present in the originals dict on platforms that have it.
        if "sendmsg" in _socket_originals:
            socket.socket.sendmsg = _socket_originals["sendmsg"]  # type: ignore[method-assign,assignment]
        if "sendfile" in _socket_originals:
            socket.socket.sendfile = _socket_originals["sendfile"]  # type: ignore[method-assign,assignment]
        if "ssl_send" in _socket_originals:
            ssl.SSLSocket.send = _socket_originals["ssl_send"]  # type: ignore[method-assign,assignment]
            ssl.SSLSocket.sendall = _socket_originals["ssl_sendall"]  # type: ignore[method-assign,assignment]
            ssl.SSLSocket.write = _socket_originals["ssl_write"]  # type: ignore[method-assign,assignment]
        _socket_originals.clear()
        _allowed_sidecar_unix_path = None


def is_socket_deny_installed() -> bool:
    """Return True if the socket deny gate is currently installed."""
    with _socket_lock:
        return bool(_socket_originals)


@contextlib.contextmanager
def replay_session(*, sidecar_unix_path: str | None = None) -> Iterator[None]:
    """Context manager that installs the socket-deny gate on entry and
    restores it on exit (VAL-W7-043).

    Within the ``with`` block the SDK behaves as if ``RELAY_REPLAY_SESSION``
    were set: every non-loopback socket I/O raises
    :class:`RelaySocketDenyError`. On exit the original ``socket``
    references are restored so subsequent code in the same process can
    perform normal network I/O.

    The env var ``RELAY_REPLAY_SESSION`` is also set (to the sidecar
    path or empty string) for the duration of the block so that
    ``multiprocessing.spawn`` children re-import ``relay.replay_mode``
    with the gate already active (VAL-W7-046).
    """
    prior_env = os.environ.get(RELAY_REPLAY_SESSION_ENV)
    os.environ[RELAY_REPLAY_SESSION_ENV] = sidecar_unix_path or ""
    install_socket_deny(sidecar_unix_path=sidecar_unix_path)
    try:
        yield
    finally:
        try:
            uninstall_socket_deny()
        finally:
            if prior_env is None:
                os.environ.pop(RELAY_REPLAY_SESSION_ENV, None)
            else:
                os.environ[RELAY_REPLAY_SESSION_ENV] = prior_env


def _maybe_apply_from_env() -> None:
    """If ``RELAY_REPLAY_SESSION`` is set, install the gate eagerly.

    Called once at module import. This is the mechanism by which the
    socket-deny gate survives ``multiprocessing.spawn``: on Windows
    (and on POSIX when ``set_start_method('spawn')`` is in force) the
    child interpreter re-imports every module from scratch, so a side
    effect at import time is the only reliable carrier across the
    spawn boundary (VAL-W7-046).
    """
    raw = os.environ.get(RELAY_REPLAY_SESSION_ENV)
    if raw is None:
        return
    install_socket_deny(sidecar_unix_path=raw or None)


# Apply at import. Outside an active replay session ``RELAY_REPLAY_SESSION``
# is unset and this is a no-op (VAL-W7-047).
_maybe_apply_from_env()


# -----------------------------------------------------------------------------
# VAL-W3-051: cassette-first replay
# -----------------------------------------------------------------------------

_KNOWN_MODES: Final[frozenset[str]] = frozenset({"cassette", "live"})


@dataclass(frozen=True)
class ReplayRecord:
    """The SDK-side replay evidence record.

    Bound to a replay_case_id; the persisted form is the dict returned
    by :meth:`to_dict`. The W3.2 evidence-submit surface binds this to
    the run's evidence_bundle.
    """

    case_id: str
    mode: str
    acknowledged_degraded_approximation: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "relay.replay_record.v1",
            "case_id": self.case_id,
            "mode": self.mode,
            "acknowledged_degraded_approximation": self.acknowledged_degraded_approximation,
        }


def _validate_run_args(
    case_id: str,
    mode: str,
    acknowledge_degraded_approximation: bool,
) -> None:
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    if mode not in _KNOWN_MODES:
        raise ValueError(
            f"unknown replay mode: {mode!r}; expected one of {sorted(_KNOWN_MODES)}"
        )
    if mode == "live" and not acknowledge_degraded_approximation:
        raise RelayReplayDegradedModeNotAcknowledged(
            "Live replay is a degraded approximation; pass "
            "acknowledge_degraded_approximation=True to opt in.",
            details={"case_id": case_id, "requested_mode": mode},
        )


def replay_run(
    *,
    case_id: str,
    mode: str = "cassette",
    acknowledge_degraded_approximation: bool = False,
) -> ReplayRecord:
    """Execute a replay case and return the SDK evidence record.

    Per VAL-W3-051: ``mode='cassette'`` is the default. ``mode='live'``
    is rejected synchronously (before any network I/O) unless the
    caller also passes ``acknowledge_degraded_approximation=True``.

    Args:
        case_id: The replay_case_id (ULID) the caller wants to replay.
        mode: ``"cassette"`` (default) or ``"live"``.
        acknowledge_degraded_approximation: Must be ``True`` when
            ``mode == "live"``; ignored when ``mode == "cassette"``.

    Returns:
        A :class:`ReplayRecord` carrying the bound mode.

    Raises:
        RelayReplayDegradedModeNotAcknowledged: ``mode='live'`` without
            ``acknowledge_degraded_approximation=True``.
        ValueError: ``case_id`` is empty / non-string, or ``mode`` is
            outside the known set.
    """
    _validate_run_args(case_id, mode, acknowledge_degraded_approximation)
    # NOTE: actual cassette playback / live execution is owned by the
    # replay-proxy in W4.1+; the SDK shim returns the metadata record
    # the evidence binder needs. The contract assertion VAL-W3-051 is
    # specifically about the mode field + degraded-mode acknowledgement.
    return ReplayRecord(
        case_id=case_id,
        mode=mode,
        acknowledged_degraded_approximation=acknowledge_degraded_approximation,
    )


def replay_record(
    *,
    case_id: str,
    mode: str = "cassette",
    acknowledge_degraded_approximation: bool = False,
) -> ReplayRecord:
    """Synonym for :func:`replay_run` used by callers that prefer the
    "record" verb when the focus is on the persisted evidence record
    rather than the act of running."""
    return replay_run(
        case_id=case_id,
        mode=mode,
        acknowledge_degraded_approximation=acknowledge_degraded_approximation,
    )


__all__ = [
    "RELAY_REPLAY_SESSION_ENV",
    "RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CLASS",
    "RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CODE",
    "RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CLASS",
    "RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CODE",
    "RELAY_SDK_SOCKET_DENY_CLASS",
    "RELAY_SDK_SOCKET_DENY_CODE",
    "RelayReplayDegradedModeNotAcknowledged",
    "RelaySocketDenyError",
    "RelayUninstrumentedHTTPError",
    "ReplayRecord",
    "install_socket_deny",
    "is_socket_deny_installed",
    "replay_record",
    "replay_run",
    "replay_session",
    "require_instrumented_http_clients",
    "uninstall_socket_deny",
]
