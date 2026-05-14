"""The Relay Python SDK client surface (W3.1).

:class:`Relay` is the SDK entry point. Construction validates the
``project_key`` synchronously and stores configuration -- it does NOT spawn
the sidecar, touch the lockfile, or make any network call (VAL-W3-003,
VAL-W3-005). The sidecar is spawned (or attached to) lazily on the first
operation that needs it -- :meth:`Relay.trace` is the W3.1 example
(VAL-W3-002).

Keystone invariant #1 (CLAUDE.md): the SDK submits lifecycle metadata
ONLY. It never writes ``run_results.status`` or any canonical outcome --
the sidecar control plane is the sole writer of canonical results. The
W3.1 surface (auto-spawn + attach + ``/health`` handshake) carries no
canonical-write path at all; the lifecycle-metadata ingest surface lands
in W3.2.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from relay_sidecar.lockfile import relay_home as _default_relay_home

from ._transport import SidecarConnection, SidecarTransport
from .errors import RelayConfigError

# A syntactically valid ``project_key`` is either:
#   - a Crockford-base32 ULID (26 chars, the canonical scope/identifier
#     form used across the Relay schemas), or
#   - a Relay project token: the prefix ``relay_pk_`` followed by >= 16
#     URL-safe base64 characters.
# VAL-W3-005 only requires that ``None``, ``""``, and an obviously-invalid
# string ("not-a-ulid-or-token") are rejected synchronously; this pattern
# set accepts the two real key shapes and rejects everything else.
_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_PROJECT_TOKEN_RE = re.compile(r"^relay_pk_[A-Za-z0-9_-]{16,}$")


def _validate_project_key(project_key: Any) -> str:
    """Validate ``project_key`` synchronously; raise RelayConfigError if bad.

    Per VAL-W3-005 this runs at :class:`Relay` construction, BEFORE any
    network or sidecar interaction, and raises :class:`RelayConfigError`
    (code ``RELAY-SDK-001`` / error_class ``RELAY-SDK-CONFIG-001``) on
    ``None``, an empty/blank string, a non-string, or a string that is
    neither a ULID nor a ``relay_pk_`` project token.
    """
    if project_key is None:
        raise RelayConfigError(
            "project_key is required; received None",
            details={"reason": "missing", "received": None},
        )
    if not isinstance(project_key, str):
        raise RelayConfigError(
            "project_key must be a string; received "
            f"{type(project_key).__name__}",
            details={
                "reason": "wrong_type",
                "received_type": type(project_key).__name__,
            },
        )
    stripped = project_key.strip()
    if not stripped:
        raise RelayConfigError(
            "project_key must be a non-empty string; received a blank value",
            details={"reason": "empty"},
        )
    if not (_ULID_RE.match(stripped) or _PROJECT_TOKEN_RE.match(stripped)):
        raise RelayConfigError(
            "project_key is not a recognised Relay project key; expected a "
            "26-character ULID or a 'relay_pk_' project token",
            details={"reason": "malformed", "received": project_key},
        )
    return stripped


class Relay:
    """Relay SDK client.

    Constructing a ``Relay`` validates configuration and stores it. It does
    NOT spawn the local sidecar, bind a port, or make any HTTP request --
    those side effects are deferred to the first operation that needs the
    sidecar (VAL-W3-002, VAL-W3-003).

    Args:
        project_key: A Relay project key -- a 26-character ULID or a
            ``relay_pk_`` project token. Validated synchronously; an
            invalid value raises :class:`relay.errors.RelayConfigError`
            BEFORE any network or sidecar interaction (VAL-W3-005).
        relay_home: Optional override of the Relay home directory
            (``${RELAY_HOME}`` or ``~/.relay``). The sidecar lockfile,
            event log, and database live here. Mainly a test-injection
            seam; production callers leave it ``None``.

    Raises:
        RelayConfigError: ``project_key`` is missing, empty, the wrong
            type, or not a recognised key shape.
    """

    def __init__(
        self,
        project_key: str,
        *,
        relay_home: Path | None = None,
    ) -> None:
        # VAL-W3-005: validate FIRST, synchronously, before anything else.
        self._project_key = _validate_project_key(project_key)
        # Resolve the relay home eagerly (pure path computation, no I/O,
        # no spawn). ``relay_home()`` only reads an env var / expands ~.
        self._relay_home: Path = (
            relay_home if relay_home is not None else _default_relay_home()
        )
        # The transport is constructed eagerly but is itself entirely
        # side-effect-free until ``ensure_attached`` is called. No spawn,
        # no lockfile touch, no port bind happens here (VAL-W3-003).
        self._transport = SidecarTransport(relay_home=self._relay_home)

    # -- read-only accessors -------------------------------------------------

    @property
    def project_key(self) -> str:
        """The validated project key this client was constructed with."""
        return self._project_key

    @property
    def relay_home(self) -> Path:
        """The resolved Relay home directory for this client."""
        return self._relay_home

    # -- operations ----------------------------------------------------------

    def _ensure_sidecar(self) -> SidecarConnection:
        """Lazily spawn/attach to the sidecar and return the connection.

        This is the single chokepoint every sidecar-requiring operation
        funnels through. The first call triggers exactly one
        ``sidecar.spawned`` OR one ``sidecar.attached`` event (VAL-W3-002);
        subsequent calls reuse the cached connection.
        """
        return self._transport.ensure_attached()

    def trace(self, name: str, **attributes: Any) -> SidecarConnection:
        """Begin a trace -- the first W3.1 operation that needs the sidecar.

        Per eng plan A1, an SDK *operation* (not import, not construction)
        is what triggers sidecar auto-spawn. ``trace`` is the canonical
        W3.1 example: calling it lazily spawns or attaches to the sidecar
        via the portalocker-serialized ``acquire_or_attach`` path and
        completes the ``/health`` authentication handshake.

        The full trace/span ingest surface (lifecycle-metadata envelopes)
        lands in W3.2; W3.1 ``trace`` returns the live
        :class:`SidecarConnection` so callers and tests can observe that
        the sidecar is up and authenticated. It deliberately carries NO
        canonical-write path -- keystone invariant #1.

        Args:
            name: A human-readable trace name. Required and non-empty.
            **attributes: Arbitrary trace attributes (forwarded to the
                ingest surface in W3.2; accepted but unused in W3.1).

        Returns:
            The live :class:`SidecarConnection` to the local sidecar.

        Raises:
            RelayConfigError: ``name`` is empty or not a string.
            RelaySidecarNotReachable: ``RELAY_NO_AUTOSPAWN=1`` is set and
                no sidecar is reachable.
            RelaySidecarVersionMismatch: the sidecar version is outside
                the SDK compatibility range.
            RelayAuthMismatch: the ``/health`` nonce challenge failed.
        """
        if not isinstance(name, str) or not name.strip():
            raise RelayConfigError(
                "trace name must be a non-empty string",
                details={"reason": "invalid_trace_name"},
            )
        _ = attributes  # W3.2 ingest surface consumes these.
        return self._ensure_sidecar()

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Release SDK-side resources (the shared httpx client).

        Does NOT stop the sidecar -- the sidecar owns its own lifecycle via
        the W2.6 quiesce / idle-shutdown protocol and ``relay sidecar
        stop``. The SDK never kills the sidecar.
        """
        self._transport.close()

    def _reap_spawned_if_exited(self) -> bool:
        """Reap a self-spawned sidecar child IFF it has already exited.

        Exit-hygiene helper: returns True once no defunct child is
        tracked. The SDK never signals a live sidecar. Mainly used by the
        test suite after it stops a sidecar via its lockfile PID.
        """
        return self._transport.reap_spawned_if_exited()

    def __enter__(self) -> Relay:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


__all__ = ["Relay"]
