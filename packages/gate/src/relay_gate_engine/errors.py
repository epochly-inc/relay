"""Structured error envelope for the W8.1 gate engine.

Every rejection surfaces a canonical ``RELAY-GATE-NNN`` code (registered
in :mod:`packages/schemas/raw/relay-error-codes.yaml` and emitted as
:class:`relay_schemas.error_codes.RelayErrorCode` constants by W1.5
codegen). The ``payload`` dict carries caller-side rendering context
(scope_id, gate name, draft_id, etc.) without leaking implementation
internals.

Wire-format codes used by w8.1:

  - ``RELAY-GATE-001``  -- generic gate evaluation failure
  - ``RELAY-GATE-014``  -- concurrent draft conflict (VAL-W8-007)
  - ``RELAY-GATE-021``  -- stale three-anchor handoff (VAL-W8-001b
                            invariant; w8.1 does not own the full
                            three-anchor validator -- W2.4 / W8.2 do --
                            but this exception is the type the engine
                            raises if a caller-supplied handoff fails
                            pre-validation)
  - ``RELAY-GATE-024``  -- draft TTL expired (VAL-W8-006)
  - ``RELAY-GATE-051``  -- new draft submission rejected: scope is in
                            ``gate.stalled`` state and requires
                            ``admin.reopen`` or ``admin.terminate``
                            (VAL-W8-034, spec AD lines 5479-5488,
                            contract gap #1)
  - ``RELAY-GATE-061``  -- anti-bypass marker present in declared
                            command (VAL-W8-041)

The exception classes are intentionally NOT a single :class:`Exception`
subtype; callers may catch :class:`GateEngineError` (the abstract base)
or any concrete subclass. Each subclass carries its canonical code as a
class-level attribute so the wire envelope is fixed and not user-typed.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from relay_schemas.error_codes import RelayErrorCode


class GateEngineError(Exception):
    """Abstract base for every w8.1 rejection.

    ``code`` is the canonical wire-format token. ``payload`` is a
    caller-side rendering dict; never mutate after construction.
    """

    code: str = RelayErrorCode.RELAY_GATE_001

    def __init__(
        self,
        message: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.payload: dict[str, Any] = dict(payload or {})

    def to_envelope(self) -> dict[str, Any]:
        """Render to the structured error envelope shape used by callers."""
        return {
            "code": self.code,
            "message": self.message,
            "payload": dict(self.payload),
        }


class DraftTtlExpiredError(GateEngineError):
    """The submitted draft is older than ``draft_ttl_seconds`` (VAL-W8-006).

    Surfaces ``RELAY-GATE-024``. The CLI maps this to exit code 7 per
    the contract preamble exit-code table.
    """

    code: str = RelayErrorCode.RELAY_GATE_024


class GateOrderingError(GateEngineError):
    """The pipeline was asked to evaluate a gate out of order (VAL-W8-001).

    Surfaces ``RELAY-GATE-001``. The fixed order is
    ``scrutiny -> structural-review -> testing``; an attempt to enter
    structural before scrutiny has produced an ``accept`` decision for
    the current round (or testing before structural) is rejected with
    this error.
    """

    code: str = RelayErrorCode.RELAY_GATE_001


class StaleHandoffError(GateEngineError):
    """Three-anchor handoff (scope_id, actor_identity_hash, manifest_commit_hash)
    failed pre-validation. Surfaces ``RELAY-GATE-021``.

    The full handoff validator lives in W2 / W8.2; this exception is
    raised by the W8.1 engine when a caller hands it a draft whose
    ``manifest_commit_hash`` does not match a manifest the engine knows
    about, OR when an anti-bypass override claim names an actor the
    actors-registry has not registered (or has revoked).
    """

    code: str = RelayErrorCode.RELAY_GATE_021


class AntiBypassRejectedError(GateEngineError):
    """The draft's declared command contains a banned bypass flag.

    Surfaces ``RELAY-GATE-061`` (VAL-W8-041). The only legitimate path
    to record such a command is an explicit org-admin operator override
    referenced via the draft's ``evidence_refs[]`` -- absence of the
    override yields this rejection.
    """

    code: str = RelayErrorCode.RELAY_GATE_061


class StalledScopeRejectedError(GateEngineError):
    """A new gate_decision_drafts submission was made against a scope that
    is in the ``gate.stalled`` state (cap exceeded or admin paused) and
    has not been reopened or terminated.

    Surfaces ``RELAY-GATE-051`` (VAL-W8-034). Spec AD lines 5479-5488:
    only ``admin.reopen`` (returns to ``gate.open`` with a new round) or
    ``admin.terminate`` (final block) move the scope out of stalled.

    Per contract gap #1, the canonical code is not yet formally assigned
    in spec section B.4; this module uses ``RELAY-GATE-051`` as the
    proposed wire-format token (already present in
    ``relay-error-codes.yaml`` and ``relay_schemas.error_codes``).
    """

    code: str = RelayErrorCode.RELAY_GATE_051


class AdminAuthorizationError(GateEngineError):
    """An admin action (``admin.reopen`` / ``admin.terminate``) was
    invoked by an actor whose role is not ``org_owner`` or ``org_admin``.

    VAL-W8-035 requires the API to return 403. The error envelope uses
    ``RELAY-AUTH-014`` to differentiate authorization failure from a
    state-engine rejection (the stalled scope is in a valid state; the
    rejection is about the caller's authority).
    """

    code: str = RelayErrorCode.RELAY_AUTH_014


__all__ = [
    "AdminAuthorizationError",
    "AntiBypassRejectedError",
    "DraftTtlExpiredError",
    "GateEngineError",
    "GateOrderingError",
    "StaleHandoffError",
    "StalledScopeRejectedError",
]
