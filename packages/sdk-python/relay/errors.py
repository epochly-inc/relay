"""Relay Python SDK error hierarchy (W3.1).

Every SDK-surfaced failure is a subclass of :class:`RelayError`. Each error
carries BOTH:

  - ``code``: the W1-compliant numeric wire token (``RELAY-SDK-NNN``,
    matching ``^RELAY-[A-Z]+-[0-9]{3}$`` per VAL-W1-029). This is the value
    that would populate the ``code`` field of a wire-format error envelope.
  - ``error_class``: the descriptive contract.md prose token
    (``RELAY-SDK-CONFIG-001``, ``RELAY-SDK-VERSION-MISMATCH``,
    ``RELAY-SDK-NO-SIDECAR``, ``RELAY-SDK-AUTH-MISMATCH``). This is the
    token the contract assertions name directly.

This mirrors the W2 sidecar ``errors.py`` convention exactly: a numeric
``code`` for the wire envelope plus a descriptive ``error_class`` for the
contract prose. Tests may match either form.

These ``RELAY-SDK-*`` codes are SDK-local: they never round-trip through
the sidecar. They are registered in
``packages/schemas/raw/relay-error-codes.yaml`` so the codegen pipeline
emits constants for them.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any, Final, Literal

# --- Numeric wire codes (registered in relay-error-codes.yaml) ---------------
# Per VAL-W1-029 every wire ``code`` matches ^RELAY-[A-Z]+-[0-9]{3}$.
RELAY_SDK_CONFIG_CODE: Final[str] = "RELAY-SDK-001"
RELAY_SDK_VERSION_MISMATCH_CODE: Final[str] = "RELAY-SDK-002"
RELAY_SDK_NO_SIDECAR_CODE: Final[str] = "RELAY-SDK-003"
RELAY_SDK_AUTH_MISMATCH_CODE: Final[str] = "RELAY-SDK-004"
# W3.2 SDK-local codes for the lifecycle / evidence / replay surface.
RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE: Final[str] = "RELAY-SDK-005"
RELAY_SDK_LIFECYCLE_INVALID_CODE: Final[str] = "RELAY-SDK-006"
RELAY_SDK_HANDOFF_INCOMPLETE_CODE: Final[str] = "RELAY-SDK-007"
RELAY_SDK_EVIDENCE_INCOMPLETE_CODE: Final[str] = "RELAY-SDK-008"
RELAY_SDK_REPLAY_PRECONDITION_CODE: Final[str] = "RELAY-SDK-009"
RELAY_SDK_POLICY_INVALID_CODE: Final[str] = "RELAY-SDK-010"

# --- Descriptive error_class tokens (contract.md prose) ----------------------
RELAY_SDK_CONFIG_CLASS: Final[str] = "RELAY-SDK-CONFIG-001"
RELAY_SDK_VERSION_MISMATCH_CLASS: Final[str] = "RELAY-SDK-VERSION-MISMATCH"
RELAY_SDK_NO_SIDECAR_CLASS: Final[str] = "RELAY-SDK-NO-SIDECAR"
RELAY_SDK_AUTH_MISMATCH_CLASS: Final[str] = "RELAY-SDK-AUTH-MISMATCH"
RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS: Final[str] = (
    "RELAY-SDK-CANONICAL-STATUS-FORBIDDEN"
)
RELAY_SDK_LIFECYCLE_INVALID_CLASS: Final[str] = "RELAY-SDK-LIFECYCLE-INVALID"
RELAY_SDK_HANDOFF_INCOMPLETE_CLASS: Final[str] = "RELAY-SDK-HANDOFF-INCOMPLETE"
RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS: Final[str] = "RELAY-SDK-EVIDENCE-INCOMPLETE"
RELAY_SDK_REPLAY_PRECONDITION_CLASS: Final[str] = "RELAY-SDK-REPLAY-PRECONDITION"
RELAY_SDK_POLICY_INVALID_CLASS: Final[str] = "RELAY-SDK-POLICY-INVALID"

# Wire codes for sidecar-side ingest rejection that the SDK surfaces back to
# callers. RELAY-ING-031 is the canonical "client tried to set a canonical-
# result field" code (spec line 1966); the SDK maps a sidecar HTTP 422 carrying
# this code to :class:`RelayCanonicalStatusForbidden` for the caller.
RELAY_ING_031_CODE: Final[str] = "RELAY-ING-031"
# RELAY-ING-022 is the scope-anchor-missing ingest-side code (per contract
# Gaps note); the SDK maps it to :class:`RelayHandoffIncomplete`.
RELAY_ING_022_CODE: Final[str] = "RELAY-ING-022"
# RELAY-REPLAY-002 is the "run_result not yet written" precondition code
# (spec line 2125); maps to :class:`RelayReplayPrecondition`.
RELAY_REPLAY_002_CODE: Final[str] = "RELAY-REPLAY-002"
# RELAY-EVID-002 is the sidecar-side "evidence envelope incomplete" code
# (per contract Gaps note); maps to :class:`RelayEvidenceIncomplete`.
RELAY_EVID_002_CODE: Final[str] = "RELAY-EVID-002"
# RELAY-ING-RAW-PAYLOAD is the sidecar-side "raw plaintext detected;
# redaction policy violated" code (W3.3 / VAL-W3-027 defense-in-depth).
# The contract Gaps note (contract.md line 1547) flagged this code as
# pending addition to the spec inventory; the SDK side stabilises it
# here so the W3.3 surface can map it to a typed RelayPolicyError. The
# code is registered in packages/schemas/raw/relay-error-codes.yaml.
RELAY_ING_RAW_PAYLOAD_CODE: Final[str] = "RELAY-ING-032"

# Retry-advice modes. Mirrors the spec B.4 error-envelope ``retry_advice``
# vocabulary. Only the values the W3.1 surface emits are enumerated here.
RetryAdviceMode = Literal[
    "no_retry",
    "after_state_change",
    "after_retry_after",
]


class RelayError(Exception):
    """Base class for every Relay SDK error.

    Attributes:
        code: W1-compliant numeric wire token (``RELAY-SDK-NNN``).
        error_class: Descriptive contract.md prose token.
        message: Human-readable explanation.
        retry_advice: One of the :data:`RetryAdviceMode` values describing
            whether and how the caller may retry. ``no_retry`` by default.
        details: Optional structured payload (paths, observed values).
    """

    code: str = "RELAY-SDK-001"
    error_class: str = "RELAY-SDK-ERROR"
    default_retry_advice: RetryAdviceMode = "no_retry"

    def __init__(
        self,
        message: str,
        *,
        retry_advice: RetryAdviceMode | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.retry_advice: RetryAdviceMode = (
            retry_advice if retry_advice is not None else self.default_retry_advice
        )
        self.details: dict[str, Any] = details or {}

    def __str__(self) -> str:
        return f"[{self.code}/{self.error_class}] {self.message}"

    def to_envelope(self) -> dict[str, Any]:
        """Return a JSON-serialisable error-envelope payload.

        The shape mirrors the spec B.4 error envelope: ``code``,
        ``error_class``, ``message``, ``retry_advice`` (an object with a
        ``mode`` field), and ``details``.
        """
        return {
            "code": self.code,
            "error_class": self.error_class,
            "message": self.message,
            "retry_advice": {"mode": self.retry_advice},
            "details": dict(self.details),
        }


class RelayConfigError(RelayError):
    """Invalid SDK configuration detected synchronously at construction.

    Raised by :class:`relay.client.Relay` when ``project_key`` is missing,
    empty, or not a syntactically valid project key. Per VAL-W3-005 this is
    raised BEFORE any network or sidecar interaction.
    """

    code = RELAY_SDK_CONFIG_CODE
    error_class = RELAY_SDK_CONFIG_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelaySidecarVersionMismatch(RelayError):
    """The attached sidecar reports a version outside the SDK compat range.

    Per VAL-W3-007 the SDK compares ``sidecar_version`` from ``/health``
    against its declared compatibility range and refuses to proceed on a
    mismatch.
    """

    code = RELAY_SDK_VERSION_MISMATCH_CODE
    error_class = RELAY_SDK_VERSION_MISMATCH_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelaySidecarNotReachable(RelayError):
    """No sidecar is reachable and auto-spawn is disabled.

    Per VAL-W3-008 this is raised when ``RELAY_NO_AUTOSPAWN=1`` is set and
    the first SDK operation finds no reachable sidecar. The retry advice is
    ``after_state_change``: the caller must start a sidecar (for example via
    ``relay sidecar start --daemon``) before retrying.
    """

    code = RELAY_SDK_NO_SIDECAR_CODE
    error_class = RELAY_SDK_NO_SIDECAR_CLASS
    default_retry_advice: RetryAdviceMode = "after_state_change"


class RelayAuthMismatch(RelayError):
    """The sidecar rejected, or failed to satisfy, the nonce-challenge auth.

    Per VAL-W3-004 the SDK issues ``GET /health`` to obtain a server nonce,
    signs it with the lockfile bearer token, and presents the proof on the
    next call. If the sidecar omits the nonce path or rejects the proof the
    SDK surfaces this error.
    """

    code = RELAY_SDK_AUTH_MISMATCH_CODE
    error_class = RELAY_SDK_AUTH_MISMATCH_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelayCanonicalStatusForbidden(RelayError):
    """SDK refused to submit an envelope containing a canonical-result field.

    Per VAL-W3-010 the SDK MUST reject any ingest envelope carrying any of
    ``status``, ``primary_failure_class``, ``written_by``, ``accepted_at``,
    or ``finalized_at`` BEFORE the request is sent. The sidecar enforces
    the same invariant with HTTP 422 + ``RELAY-ING-031``; when the SDK
    receives that response it raises this same exception type so callers
    have a single typed surface.

    This is keystone invariant #1: the control plane is the SOLE writer of
    canonical results.
    """

    code = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE
    error_class = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelayLifecycleInvalid(RelayError):
    """``client_lifecycle_status`` value is outside the closed enum.

    Per VAL-W3-012 only ``{started, client_succeeded, client_failed,
    client_aborted}`` are valid; any other value is rejected at the SDK
    boundary BEFORE the request is sent.
    """

    code = RELAY_SDK_LIFECYCLE_INVALID_CODE
    error_class = RELAY_SDK_LIFECYCLE_INVALID_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelayHandoffIncomplete(RelayError):
    """Three-anchor handoff is missing or stale.

    Per VAL-W3-011 every SDK-submitted envelope MUST carry all three of
    ``scope_id`` (``run_id`` / ``gate_id`` / ...),
    ``actor_identity_hash``, and ``manifest_commit_hash``. A missing,
    empty, revoked, or stale anchor raises this error; the offending
    anchor(s) are listed in ``details.mismatched_anchor`` so tests and
    callers can attribute the failure precisely.
    """

    code = RELAY_SDK_HANDOFF_INCOMPLETE_CODE
    error_class = RELAY_SDK_HANDOFF_INCOMPLETE_CLASS
    default_retry_advice: RetryAdviceMode = "after_state_change"


class RelayEvidenceIncomplete(RelayError):
    """Evidence envelope is missing one or more required binding fields.

    Per VAL-W3-015 and CLAUDE.md invariant #2, an evidence claim is only
    a pass when it binds artifact digest + command + exit code + span IDs
    + assertion IDs + actor identity + manifest commit hash + redaction
    policy version. A claim missing any of these is ``invalid``, not
    ``accepted``. The SDK refuses to submit at the boundary.
    """

    code = RELAY_SDK_EVIDENCE_INCOMPLETE_CODE
    error_class = RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


class RelayReplayPrecondition(RelayError):
    """Replay creation precondition failed.

    Per VAL-W3-014 the SDK's ``replay_create`` requires the canonical
    ``run_result`` to exist for the source run; the SDK refuses to create
    a replay case from raw SDK lifecycle. Raised when the sidecar
    responds with ``RELAY-REPLAY-002`` ("run_result not yet written")
    OR an equivalent precondition failure.
    """

    code = RELAY_SDK_REPLAY_PRECONDITION_CODE
    error_class = RELAY_SDK_REPLAY_PRECONDITION_CLASS
    default_retry_advice: RetryAdviceMode = "after_state_change"


class RelayPolicyError(RelayError):
    """Redaction policy failed to parse or violated a structural invariant.

    Per VAL-W3-025 the SDK refuses to capture under a malformed policy
    (bad regex, unknown matcher kind, missing required field). Per
    VAL-W3-026 the SDK refuses ``raw_capture=true`` without both
    ``dpa_ref`` and ``approver_user_id``. This is the typed surface for
    both failure shapes; ``error_class`` discriminates further via
    ``details.reason``.
    """

    code = RELAY_SDK_POLICY_INVALID_CODE
    error_class = RELAY_SDK_POLICY_INVALID_CLASS
    default_retry_advice: RetryAdviceMode = "no_retry"


__all__ = [
    "RELAY_EVID_002_CODE",
    "RELAY_ING_022_CODE",
    "RELAY_ING_031_CODE",
    "RELAY_ING_RAW_PAYLOAD_CODE",
    "RELAY_REPLAY_002_CODE",
    "RELAY_SDK_AUTH_MISMATCH_CLASS",
    "RELAY_SDK_AUTH_MISMATCH_CODE",
    "RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS",
    "RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE",
    "RELAY_SDK_CONFIG_CLASS",
    "RELAY_SDK_CONFIG_CODE",
    "RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS",
    "RELAY_SDK_EVIDENCE_INCOMPLETE_CODE",
    "RELAY_SDK_HANDOFF_INCOMPLETE_CLASS",
    "RELAY_SDK_HANDOFF_INCOMPLETE_CODE",
    "RELAY_SDK_LIFECYCLE_INVALID_CLASS",
    "RELAY_SDK_LIFECYCLE_INVALID_CODE",
    "RELAY_SDK_NO_SIDECAR_CLASS",
    "RELAY_SDK_NO_SIDECAR_CODE",
    "RELAY_SDK_POLICY_INVALID_CLASS",
    "RELAY_SDK_POLICY_INVALID_CODE",
    "RELAY_SDK_REPLAY_PRECONDITION_CLASS",
    "RELAY_SDK_REPLAY_PRECONDITION_CODE",
    "RELAY_SDK_VERSION_MISMATCH_CLASS",
    "RELAY_SDK_VERSION_MISMATCH_CODE",
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
    "RetryAdviceMode",
]
