"""Relay Python SDK package root.

The W3.1 SDK client surface lives here. Importing this package -- or any
submodule -- is entirely side-effect-free: it spawns no sidecar process,
touches no lockfile, binds no port, and makes no HTTP request (VAL-W3-001).
All side effects are deferred to the first :class:`relay.client.Relay`
operation that needs the sidecar (VAL-W3-002, VAL-W3-003).

Public surface:
  - :class:`Relay` -- the SDK client.
  - :class:`RelayError` and its subclasses -- the SDK error hierarchy.

The generated canonical control-plane envelope models live under
:mod:`relay._generated.schemas` (source of truth:
``packages/schemas/raw/openapi.yaml``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .client import Relay
from .errors import (
    RelayAuthMismatch,
    RelayConfigError,
    RelayError,
    RelaySidecarNotReachable,
    RelaySidecarVersionMismatch,
)

__all__ = [
    "Relay",
    "RelayAuthMismatch",
    "RelayConfigError",
    "RelayError",
    "RelaySidecarNotReachable",
    "RelaySidecarVersionMismatch",
]
