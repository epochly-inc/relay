"""SDK replay-mode primitives (W3.5, VAL-W3-048 / VAL-W3-049 / VAL-W3-051).

Per eng plan A4 ("defense in depth for replay isolation") this module
owns two of the four layers:

  Layer 2: ``install_socket_deny`` monkey-patches ``socket.socket`` so
           connect() to any non-loopback IP raises
           :class:`RelaySocketDenyError`. ``uninstall_socket_deny``
           restores the original method.

  Layer 4: ``require_instrumented_http_clients`` scans ``sys.modules``
           for uninstrumented HTTP-client modules (``requests``,
           ``aiohttp``, ``urllib3``) and raises
           :class:`RelayUninstrumentedHTTPError` if any are loaded
           without a Relay wrapper. The function is intended to be
           called by the SDK's replay-mode entry point so callers see
           an init ERROR (not warning) before any cassette/live work.

VAL-W3-051: :func:`replay_run` defaults to cassette mode and refuses
live mode unless the caller passes both ``mode="live"`` AND
``acknowledge_degraded_approximation=True``. The persisted record
carries the ``mode`` field so downstream binders can distinguish
faithful cassette replays from live degraded approximations.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import threading
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


class RelayUninstrumentedHTTPError(RelaySdkError):
    """Replay-mode init detected an HTTP client module without a Relay wrapper.

    Per eng plan A4 layer 4 this is an init ERROR, not a warning. The
    SDK refuses to enter replay mode while uninstrumented modules are
    present in ``sys.modules`` because raw HTTP egress would bypass
    cassette playback.
    """

    code: ClassVar[str] = RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CODE
    error_class: ClassVar[str] = RELAY_SDK_REPLAY_UNINSTRUMENTED_HTTP_CLASS
    http_status: ClassVar[int] = 400
    default_blocked_surface: ClassVar[str] = "relay-sdk-replay-init"
    default_retry_advice: ClassVar[str] = "after_state_change"


class RelaySocketDenyError(RelaySdkError):
    """Replay-mode socket deny: connect() to a non-loopback address blocked.

    Per eng plan A4 layer 2 the SDK monkey-patches ``socket.socket`` so
    any non-loopback egress raises this error synchronously. Loopback
    (127.0.0.0/8, ::1) is allowed.
    """

    code: ClassVar[str] = RELAY_SDK_SOCKET_DENY_CODE
    error_class: ClassVar[str] = RELAY_SDK_SOCKET_DENY_CLASS
    http_status: ClassVar[int] = 403
    default_blocked_surface: ClassVar[str] = "socket.socket.connect"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelayReplayDegradedModeNotAcknowledged(RelaySdkError):
    """Caller requested live replay without acknowledging the degraded mode.

    Per CLAUDE.md keystone invariant #9 cassette replay is the default
    and the only mode that produces evidence-faithful records. Live
    replay is a "degraded approximation" -- side effects fire,
    timings drift, providers may have rotated model_signature -- so the
    caller MUST pass ``acknowledge_degraded_approximation=True`` to
    opt in.
    """

    code: ClassVar[str] = RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CODE
    error_class: ClassVar[str] = (
        RELAY_SDK_REPLAY_DEGRADED_MODE_NOT_ACKNOWLEDGED_CLASS
    )
    http_status: ClassVar[int] = 400
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
# Layer 2: socket.socket deny
# -----------------------------------------------------------------------------

_socket_lock = threading.Lock()
_socket_original_connect: Any = None


def _is_loopback_address(host: str) -> bool:
    """Return True if ``host`` is a loopback IPv4 or IPv6 literal."""
    if not host:
        return False
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A hostname; only literal IPs are accepted as loopback per A4
        # layer 2 (so the patch can't be bypassed by DNS resolution
        # returning a non-loopback A record).
        return False
    return ip.is_loopback


def _denying_connect(self: socket.socket, address: Any) -> Any:
    """Replacement for ``socket.socket.connect`` that denies non-loopback."""
    host: str = ""
    if isinstance(address, tuple) and len(address) >= 1:
        host = str(address[0])
    elif isinstance(address, str):
        host = address
    if not _is_loopback_address(host):
        raise RelaySocketDenyError(
            "Replay mode denied non-loopback socket connect: "
            f"target={host!r}",
            details={"target": host, "address": address},
        )
    assert _socket_original_connect is not None
    return _socket_original_connect(self, address)


def install_socket_deny() -> None:
    """Patch ``socket.socket.connect`` to deny non-loopback addresses.

    Idempotent: a second call while the patch is installed is a no-op.

    Thread-safety: the patch is process-global and serialised by an
    internal lock. Per the contract gap note (1554) replay sessions
    running alongside non-replay sessions in the same process are
    out-of-scope for v0.1; tests assume single-process invocation.
    """
    global _socket_original_connect
    with _socket_lock:
        if _socket_original_connect is not None:
            return
        _socket_original_connect = socket.socket.connect
        socket.socket.connect = _denying_connect  # type: ignore[method-assign]


def uninstall_socket_deny() -> None:
    """Restore the original ``socket.socket.connect``.

    Idempotent: safe to call when no patch is installed.
    """
    global _socket_original_connect
    with _socket_lock:
        if _socket_original_connect is None:
            return
        socket.socket.connect = _socket_original_connect  # type: ignore[method-assign]
        _socket_original_connect = None


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
    "replay_record",
    "replay_run",
    "require_instrumented_http_clients",
    "uninstall_socket_deny",
]
