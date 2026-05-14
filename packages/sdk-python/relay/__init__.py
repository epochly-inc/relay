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
    RelayCanonicalStatusForbidden,
    RelayConfigError,
    RelayError,
    RelayEvidenceIncomplete,
    RelayHandoffIncomplete,
    RelayLifecycleInvalid,
    RelayPolicyError,
    RelayReplayPrecondition,
    RelaySidecarNotReachable,
    RelaySidecarVersionMismatch,
)
from .flush import FlushPolicy
from .redaction import (
    DEFAULT_APPLIES_TO_FIELDS,
    RedactionEngine,
    RedactionPolicy,
    SaltProvider,
    redact_capture_payload,
)
from .run import Run

__all__ = [
    "DEFAULT_APPLIES_TO_FIELDS",
    "FlushPolicy",
    "RedactionEngine",
    "RedactionPolicy",
    "Relay",
    "RelayAuthMismatch",
    "RelayCanonicalStatusForbidden",
    "RelayConfigError",
    "RelayError",
    "RelayEvidenceIncomplete",
    "RelayHandoffIncomplete",
    "RelayLifecycleInvalid",
    "RelayPolicyError",
    "RelayReplayPrecondition",
    "RelaySidecarNotReachable",
    "RelaySidecarVersionMismatch",
    "Run",
    "SaltProvider",
    "redact_capture_payload",
]
