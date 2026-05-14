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

# --- Descriptive error_class tokens (contract.md prose) ----------------------
RELAY_SDK_CONFIG_CLASS: Final[str] = "RELAY-SDK-CONFIG-001"
RELAY_SDK_VERSION_MISMATCH_CLASS: Final[str] = "RELAY-SDK-VERSION-MISMATCH"
RELAY_SDK_NO_SIDECAR_CLASS: Final[str] = "RELAY-SDK-NO-SIDECAR"
RELAY_SDK_AUTH_MISMATCH_CLASS: Final[str] = "RELAY-SDK-AUTH-MISMATCH"

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


__all__ = [
    "RELAY_SDK_AUTH_MISMATCH_CLASS",
    "RELAY_SDK_AUTH_MISMATCH_CODE",
    "RELAY_SDK_CONFIG_CLASS",
    "RELAY_SDK_CONFIG_CODE",
    "RELAY_SDK_NO_SIDECAR_CLASS",
    "RELAY_SDK_NO_SIDECAR_CODE",
    "RELAY_SDK_VERSION_MISMATCH_CLASS",
    "RELAY_SDK_VERSION_MISMATCH_CODE",
    "RelayAuthMismatch",
    "RelayConfigError",
    "RelayError",
    "RelaySidecarNotReachable",
    "RelaySidecarVersionMismatch",
    "RetryAdviceMode",
]
