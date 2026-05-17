"""Errors for the local-sidecar atomic primitives (W3-atomic).

Spec H lines 4163-4180 (``local_two_layer_locked_write``) requires a named
exception ``StateLockTimeout`` raised when either lock layer cannot be
acquired within ``timeout_seconds``. The contract assertion
VAL-V2M03-020 additionally requires:

  - ``StateLockTimeout`` is a subclass of ``RelayError``
  - importable as ``from relay_sidecar.primitives.errors import StateLockTimeout``

The local-sidecar workspace does not depend on the SDK Python package
(``epochly-relay``), so we cannot import ``relay.errors.RelayError`` from
the SDK here without creating a circular workspace edge. Instead we define
a minimal, sidecar-local ``RelayError`` root class. The two surfaces (SDK
errors vs sidecar primitive errors) are structurally distinct: SDK errors
travel over the wire envelope (``relay.error.v1``) and carry W1-compliant
numeric codes; sidecar primitive errors are raised process-locally and do
not need a wire envelope. Keeping a sidecar-local ``RelayError`` root
preserves the assertion ``issubclass(StateLockTimeout, RelayError)`` without
forcing the sidecar to depend on the SDK.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations


class RelayError(Exception):
    """Root class for Relay sidecar process-local errors.

    Distinct from the SDK's ``relay.errors.RelayError`` -- this one is the
    sidecar-local root used by atomic primitives (and any future sidecar
    primitive errors). It carries no wire envelope: sidecar primitives
    surface failures to in-process callers, not to remote SDKs.
    """


class StateLockTimeout(RelayError):
    """Raised by ``local_two_layer_locked_write`` when a lock layer cannot
    be acquired within ``timeout_seconds``.

    Spec H lines 4165-4166:
        "...a 5-second timeout that raises StateLockTimeout rather than
        hanging."

    Attributes:
        message: Human-readable explanation including which layer timed out.
        layer: Which lock layer triggered the timeout. One of
            ``"rlock"`` (in-process threading.RLock) or
            ``"portalocker"`` (OS-level file lock).
        timeout_seconds: The timeout that was applied.
        path: Path of the file being written when the timeout occurred.
            Optional; populated when the caller's destination is known
            at the point of failure.
    """

    def __init__(
        self,
        message: str,
        *,
        layer: str = "unknown",
        timeout_seconds: float = 0.0,
        path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.layer = layer
        self.timeout_seconds = timeout_seconds
        self.path = path

    def __str__(self) -> str:  # noqa: D401
        suffix = (
            f" (layer={self.layer}, timeout_seconds={self.timeout_seconds},"
            f" path={self.path!r})"
        )
        return self.message + suffix


__all__ = ["RelayError", "StateLockTimeout"]
