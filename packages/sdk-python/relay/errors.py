"""Relay Python SDK error hierarchy (W3.1 / W3.4).

Every SDK-surfaced failure is a subclass of :class:`RelayError`. The
hierarchy is two-deep:

  * :class:`RelayError` -- the abstract root.
  * Ten **namespace intermediates**, one per ``RELAY-{AREA}-*`` code prefix
    in the canonical error-code registry
    (``packages/schemas/raw/relay-error-codes.yaml``):
      :class:`RelayIngestError`     (RELAY-ING-*)
      :class:`RelayAuthError`       (RELAY-AUTH-*)
      :class:`RelayRateLimitError`  (RELAY-RATE-*)
      :class:`RelayGateError`       (RELAY-GATE-*)
      :class:`RelayEvidenceError`   (RELAY-EVID-*)
      :class:`RelayReplayError`     (RELAY-REPLAY-*)
      :class:`RelaySchemaError`     (RELAY-SCHEMA-*)
      :class:`RelaySidecarError`    (RELAY-SIDECAR-*)
      :class:`RelaySdkError`        (RELAY-SDK-*)
      :class:`RelaySQLiteError`     (RELAY-SQLITE-*)
  * Typed **leaves** for the codes the v0.1 SDK surface explicitly maps:
    :class:`RelayCanonicalStatusForbidden`, :class:`RelayHandoffIncomplete`,
    :class:`RelayPolicyError`, :class:`RelayAuthMismatch`,
    :class:`RelayEvidenceIncomplete`, :class:`RelayReplayPrecondition`,
    :class:`RelaySidecarVersionMismatch`, :class:`RelaySidecarNotReachable`,
    :class:`RelayConfigError`, :class:`RelayLifecycleInvalid`.
  * A forward-compat fallback :class:`RelayUnknownError` for any sidecar
    code the SDK doesn't recognise (VAL-W3-035 -- the SDK never crashes
    on a future code; it raises a typed Unknown carrying the original
    code so callers can still log and retry).

Each error carries:

  * ``code`` -- the W1-compliant wire token (``RELAY-{AREA}-NNN``,
    matching ``^RELAY-[A-Z]+-[0-9]{3}$`` per VAL-W1-029). Sourced from
    :class:`relay_schemas.error_codes.RelayErrorCode` for spec-defined
    codes; declared as ``Final[str]`` constants in this module for
    SDK-local codes (each constant is also registered in
    ``packages/schemas/raw/relay-error-codes.yaml``).
  * ``error_class`` -- the descriptive contract.md prose token.
  * ``http_status`` -- the HTTP status the wire envelope would carry.
  * ``blocked_surface`` -- the API path that failed (e.g.,
    ``"POST /v1/ingest/runs"``).
  * ``documentation_url`` -- the canonical docs URL for this code.
  * ``retry_advice`` -- a STRUCTURED dict ``{"mode": str, ...}`` (NOT a
    boolean; VAL-W3-031). ``mode`` is one of ``no_retry``, ``retryable``,
    ``after_state_change``, ``after_retry_after``. Optional keys
    ``delay_seconds`` and ``max_attempts`` may carry the retry hint.
  * ``request_id`` / ``trace_id`` -- propagated from the sidecar's error
    response body or from ``X-Request-ID`` / ``X-Trace-ID`` headers
    (VAL-W3-033).
  * ``details`` -- optional structured payload (paths, observed values).

The SDK exposes :meth:`RelayError.to_envelope` to serialize the exception
into a dict and :meth:`RelayError.from_envelope` to parse a sidecar
response back into the correct typed subclass.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any, ClassVar, Final, Literal

# -----------------------------------------------------------------------------
# Wire codes (Final[str] constants; codegen source of truth is
# packages/schemas/raw/relay-error-codes.yaml). VAL-W3-034 requires that
# every RELAY-* code referenced in this module is bound to a Final[str]
# constant declared here, not embedded as a bare literal in business logic.
# Per VAL-W1-029 every wire token matches ^RELAY-[A-Z]+-[0-9]{3}$.
# -----------------------------------------------------------------------------

# SDK-local codes (never round-trip through the sidecar; SDK-side only).
RELAY_SDK_CONFIG_CODE: Final[str] = "RELAY-SDK-001"
RELAY_SDK_VERSION_MISMATCH_CODE: Final[str] = "RELAY-SDK-002"
RELAY_SDK_NO_SIDECAR_CODE: Final[str] = "RELAY-SDK-003"
RELAY_SDK_AUTH_MISMATCH_CODE: Final[str] = "RELAY-SDK-004"
RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE: Final[str] = "RELAY-SDK-005"
RELAY_SDK_LIFECYCLE_INVALID_CODE: Final[str] = "RELAY-SDK-006"
RELAY_SDK_HANDOFF_INCOMPLETE_CODE: Final[str] = "RELAY-SDK-007"
RELAY_SDK_EVIDENCE_INCOMPLETE_CODE: Final[str] = "RELAY-SDK-008"
RELAY_SDK_REPLAY_PRECONDITION_CODE: Final[str] = "RELAY-SDK-009"
RELAY_SDK_POLICY_INVALID_CODE: Final[str] = "RELAY-SDK-010"
# VAL-REDACT-006 (MEDIUM / resource-leak): a policy-supplied regex matcher
# whose pattern has catastrophic-backtracking (ReDoS) structure -- a quantifier
# applied to a group whose body itself contains a quantifier, e.g. ``(a+)+`` /
# ``(a*)*`` / ``(.*a){10,}``. The SDK REJECTS such a pattern at policy LOAD time
# (it is never compiled or executed). The TypeScript SDK surfaces the identical
# code + ``details.reason`` ("redos_pattern") for cross-language parity
# (Pattern B/C); see packages/sdk-typescript/src/errors.ts.
RELAY_SDK_REGEX_REDOS_CODE: Final[str] = "RELAY-SDK-017"

# Wire codes for sidecar-side ingest rejection the SDK surfaces back.
RELAY_ING_001_CODE: Final[str] = "RELAY-ING-001"
RELAY_ING_022_CODE: Final[str] = "RELAY-ING-022"
RELAY_ING_031_CODE: Final[str] = "RELAY-ING-031"
RELAY_ING_RAW_PAYLOAD_CODE: Final[str] = "RELAY-ING-032"
RELAY_REPLAY_002_CODE: Final[str] = "RELAY-REPLAY-002"
RELAY_EVID_002_CODE: Final[str] = "RELAY-EVID-002"
# Spec B.4 stale-handoff wire code surfaced via the typed
# RelayHandoffIncomplete leaf for cross-language parity with the TS leaf
# registry (VAL-W4-028 / VAL-W4-029).
RELAY_GATE_021_CODE: Final[str] = "RELAY-GATE-021"

# Namespace-intermediate default codes. When a namespace class is
# instantiated without specifying ``code``, it uses these defaults.
RELAY_ING_DEFAULT_CODE: Final[str] = "RELAY-ING-001"
RELAY_AUTH_DEFAULT_CODE: Final[str] = "RELAY-AUTH-001"
RELAY_RATE_DEFAULT_CODE: Final[str] = "RELAY-RATE-001"
RELAY_GATE_DEFAULT_CODE: Final[str] = "RELAY-GATE-001"
RELAY_EVID_DEFAULT_CODE: Final[str] = "RELAY-EVID-001"
RELAY_REPLAY_DEFAULT_CODE: Final[str] = "RELAY-REPLAY-001"
RELAY_SCHEMA_DEFAULT_CODE: Final[str] = "RELAY-SCHEMA-001"
RELAY_SIDECAR_DEFAULT_CODE: Final[str] = "RELAY-SIDECAR-001"
RELAY_SQLITE_DEFAULT_CODE: Final[str] = "RELAY-SQLITE-001"
# Forward-compat placeholder for the "unknown future code" wire form. The
# canonical RELAY-FUTURE-999 token from relay-error-codes.yaml is used as
# the default placeholder; RelayUnknownError preserves the ORIGINAL code
# the sidecar emitted, so this constant is only the construction default.
RELAY_FUTURE_999_CODE: Final[str] = "RELAY-FUTURE-999"

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

# Retry-advice modes. The SDK exception's ``retry_advice`` envelope field is
# a dict carrying one of these mode strings (VAL-W3-031, NOT a boolean).
# ``no_retry`` is the spec wire form for "do not retry" rendered in SDK form.
RetryAdviceMode = Literal[
    "no_retry",
    "retryable",
    "after_state_change",
    "after_retry_after",
]

# Default base URL the SDK uses to construct documentation_url values.
_DEFAULT_DOC_URL_PREFIX: Final[str] = "https://relay.epochly.com/docs/errors/"

# Mapping from spec B.4 wire ``retry_advice`` enum strings to the SDK
# structured retry_advice dict shape. Used by :meth:`RelayError.from_envelope`
# to interpret wire envelopes whose ``retry_advice`` is a plain string.
_WIRE_RETRY_ADVICE_TO_DICT: dict[str, dict[str, Any]] = {
    "do_not_retry": {"mode": "no_retry"},
    "after_fix": {"mode": "after_state_change"},
    "after_retry_after": {"mode": "after_retry_after"},
    "after_split": {"mode": "after_state_change"},
    "after_recapture": {"mode": "after_state_change"},
    "after_re_auth": {"mode": "after_state_change"},
}


def _coerce_retry_advice(value: Any) -> dict[str, Any]:
    """Normalise a retry_advice input into the SDK structured dict shape.

    Accepts:
      * ``None`` -- returns ``{"mode": "no_retry"}``.
      * a string matching the W1 wire enum (``do_not_retry``, ``after_fix``,
        ``after_retry_after``, ...) -- mapped via
        :data:`_WIRE_RETRY_ADVICE_TO_DICT`.
      * a string matching an SDK ``RetryAdviceMode`` value -- promoted to
        ``{"mode": value}``.
      * a dict with a ``mode`` key -- returned with the mode preserved and
        unknown extra keys carried through.
      * any other input -- coerced to ``{"mode": "no_retry"}`` so the SDK
        never carries a boolean or list as retry_advice (VAL-W3-031).
    """
    if value is None:
        return {"mode": "no_retry"}
    if isinstance(value, bool):
        # Booleans are explicitly forbidden by VAL-W3-031.
        return {"mode": "no_retry"}
    if isinstance(value, str):
        if value in _WIRE_RETRY_ADVICE_TO_DICT:
            return dict(_WIRE_RETRY_ADVICE_TO_DICT[value])
        if value in ("no_retry", "retryable", "after_state_change", "after_retry_after"):
            return {"mode": value}
        # Unknown string -- fail closed to no_retry but preserve the raw form.
        return {"mode": "no_retry", "raw": value}
    if isinstance(value, dict):
        mode = value.get("mode")
        if not isinstance(mode, str) or not mode:
            return {"mode": "no_retry", **{k: v for k, v in value.items() if k != "mode"}}
        return dict(value)
    return {"mode": "no_retry"}


class RelayError(Exception):
    """Base class for every Relay SDK error.

    Attributes:
        code: W1-compliant numeric wire token (``RELAY-{AREA}-NNN``).
        error_class: Descriptive contract.md prose token.
        http_status: HTTP status the wire envelope would carry.
        message: Human-readable explanation.
        blocked_surface: The API path that failed (e.g.
            ``"POST /v1/ingest/runs"``). Populated for every non-2xx
            response (VAL-W3-032).
        documentation_url: The canonical docs URL for this code.
        retry_advice: Structured dict carrying ``mode`` plus optional
            ``delay_seconds`` and ``max_attempts`` (VAL-W3-031).
        request_id: The sidecar's correlation id for the failed request
            (VAL-W3-033). May be ``None`` if not propagated.
        trace_id: The OpenTelemetry-style trace id (VAL-W3-033). May be
            ``None`` if not propagated.
        details: Optional structured payload.
    """

    # Class-level defaults. Subclasses override.
    code: ClassVar[str] = "RELAY-SDK-001"
    error_class: ClassVar[str] = "RELAY-SDK-ERROR"
    http_status: ClassVar[int] = 500
    default_retry_advice: ClassVar[str] = "no_retry"
    default_blocked_surface: ClassVar[str] = "relay-sdk"

    # Pinned envelope schema version. Distinct from ``relay.error.v1``
    # (the wire envelope) because the SDK envelope carries the SDK-only
    # ``documentation_url`` field and a structured ``retry_advice`` dict
    # rather than the wire string enum.
    ENVELOPE_SCHEMA_VERSION: ClassVar[str] = "relay.sdk_error.v1"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        http_status: int | None = None,
        blocked_surface: str | None = None,
        retry_advice: dict[str, Any] | str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        documentation_url: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        # Instance-bound code/http_status; defaults come from the class.
        self.code: str = code if code is not None else type(self).code
        self.http_status: int = (
            http_status if http_status is not None else type(self).http_status
        )
        self.message: str = message
        self.blocked_surface: str = (
            blocked_surface
            if blocked_surface is not None
            else type(self).default_blocked_surface
        )
        self.retry_advice_dict: dict[str, Any] = _coerce_retry_advice(
            retry_advice if retry_advice is not None else type(self).default_retry_advice
        )
        self.request_id: str | None = request_id
        self.trace_id: str | None = trace_id
        self.documentation_url: str = (
            documentation_url
            if documentation_url is not None
            else f"{_DEFAULT_DOC_URL_PREFIX}{self.code}"
        )
        self.details: dict[str, Any] = details or {}

    @property
    def retry_advice(self) -> str:
        """Back-compat string accessor.

        Pre-W3.4 tests assert ``exc.retry_advice == "after_state_change"``
        directly against the exception. The W3.4 envelope-level field is a
        dict (VAL-W3-031); this property surfaces the ``mode`` string for
        the legacy attribute access. ``retry_advice_dict`` exposes the full
        structured dict.
        """
        mode = self.retry_advice_dict.get("mode")
        if isinstance(mode, str) and mode:
            return mode
        return "no_retry"

    def __str__(self) -> str:
        return f"[{self.code}/{self.error_class}] {self.message}"

    def to_envelope(self) -> dict[str, Any]:
        """Return a JSON-serialisable error envelope (VAL-W3-029).

        Fields: ``schema_version`` (``"relay.sdk_error.v1"``), ``code``,
        ``http_status``, ``message``, ``blocked_surface``,
        ``documentation_url``, ``retry_advice`` (dict; VAL-W3-031),
        ``request_id``, ``trace_id``, ``error_class``, ``details``.
        """
        return {
            "schema_version": self.ENVELOPE_SCHEMA_VERSION,
            "code": self.code,
            "http_status": self.http_status,
            "message": self.message,
            "blocked_surface": self.blocked_surface,
            "documentation_url": self.documentation_url,
            "retry_advice": dict(self.retry_advice_dict),
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "error_class": self.error_class,
            "details": dict(self.details),
        }

    # -- forward-compatible from_envelope ---------------------------------------

    @classmethod
    def from_envelope(cls, envelope: dict[str, Any]) -> RelayError:
        """Construct the correct RelayError subclass from a wire envelope.

        Routes by the envelope's ``code`` field:

          1. If ``code`` is a known typed leaf (e.g. ``RELAY-ING-031``),
             returns an instance of that leaf class.
          2. Else if ``code`` matches a namespace prefix
             (``RELAY-ING-``, ``RELAY-AUTH-``, ...), returns an instance of
             the namespace intermediate class.
          3. Else (forward-compat per VAL-W3-035) returns
             :class:`RelayUnknownError` with the original code preserved.

        Accepts both wire envelopes (``retry_advice`` as a closed-enum
        string per spec B.4) and SDK envelopes (``retry_advice`` as a
        structured dict).
        """
        code = str(envelope.get("code") or "")
        message = str(envelope.get("message") or "")
        http_status = envelope.get("http_status")
        if not isinstance(http_status, int):
            http_status = None
        blocked_surface = envelope.get("blocked_surface")
        if not isinstance(blocked_surface, str):
            blocked_surface = None
        request_id = envelope.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            request_id = None
        trace_id = envelope.get("trace_id")
        if not isinstance(trace_id, str) or not trace_id:
            trace_id = None
        retry_advice = envelope.get("retry_advice")
        documentation_url = envelope.get("documentation_url")
        if not isinstance(documentation_url, str):
            documentation_url = None
        details = envelope.get("details")
        if not isinstance(details, dict):
            details = None

        target_cls = _resolve_class_for_code(code)
        return target_cls(
            message,
            code=code,
            http_status=http_status,
            blocked_surface=blocked_surface,
            retry_advice=retry_advice,
            request_id=request_id,
            trace_id=trace_id,
            documentation_url=documentation_url,
            details=details,
        )


# =============================================================================
# Namespace intermediates (one per RELAY-{AREA}-* prefix).
# =============================================================================


class RelayIngestError(RelayError):
    """Errors in the RELAY-ING-* namespace (ingest endpoints)."""

    code: ClassVar[str] = RELAY_ING_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-ING-ERROR"
    http_status: ClassVar[int] = 400
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"


class RelayAuthError(RelayError):
    """Errors in the RELAY-AUTH-* namespace."""

    code: ClassVar[str] = RELAY_AUTH_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-AUTH-ERROR"
    http_status: ClassVar[int] = 401
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"


class RelayRateLimitError(RelayError):
    """Errors in the RELAY-RATE-* namespace (rate-limit rejection)."""

    code: ClassVar[str] = RELAY_RATE_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-RATE-ERROR"
    http_status: ClassVar[int] = 429
    default_retry_advice: ClassVar[str] = "after_retry_after"
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"


class RelayGateError(RelayError):
    """Errors in the RELAY-GATE-* namespace (gate evaluation)."""

    code: ClassVar[str] = RELAY_GATE_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-GATE-ERROR"
    http_status: ClassVar[int] = 404
    default_blocked_surface: ClassVar[str] = "POST /v1/gates/{gate_id}/drafts"


class RelayEvidenceError(RelayError):
    """Errors in the RELAY-EVID-* namespace (evidence ingest / verify)."""

    code: ClassVar[str] = RELAY_EVID_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-EVID-ERROR"
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/evidence"


class RelayReplayError(RelayError):
    """Errors in the RELAY-REPLAY-* namespace (replay create / playback)."""

    code: ClassVar[str] = RELAY_REPLAY_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-REPLAY-ERROR"
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/runs/{run_id}/replays"


class RelaySchemaError(RelayError):
    """Errors in the RELAY-SCHEMA-* namespace (envelope schema rejection)."""

    code: ClassVar[str] = RELAY_SCHEMA_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-SCHEMA-ERROR"
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"


class RelaySidecarError(RelayError):
    """Errors in the RELAY-SIDECAR-* namespace (local sidecar lifecycle)."""

    code: ClassVar[str] = RELAY_SIDECAR_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-SIDECAR-ERROR"
    http_status: ClassVar[int] = 503
    default_retry_advice: ClassVar[str] = "after_state_change"
    default_blocked_surface: ClassVar[str] = "relay-sidecar"


class RelaySdkError(RelayError):
    """Errors in the RELAY-SDK-* namespace (SDK-local validation failures)."""

    code: ClassVar[str] = RELAY_SDK_CONFIG_CODE
    error_class: ClassVar[str] = "RELAY-SDK-ERROR"
    http_status: ClassVar[int] = 400
    default_blocked_surface: ClassVar[str] = "relay-sdk"


class RelaySQLiteError(RelayError):
    """Errors in the RELAY-SQLITE-* namespace (sidecar SQLite-layer faults)."""

    code: ClassVar[str] = RELAY_SQLITE_DEFAULT_CODE
    error_class: ClassVar[str] = "RELAY-SQLITE-ERROR"
    http_status: ClassVar[int] = 500
    default_blocked_surface: ClassVar[str] = "relay-sidecar-sqlite"


# =============================================================================
# Typed leaves (specific known codes).
# =============================================================================


class RelayConfigError(RelaySdkError):
    """Invalid SDK configuration detected synchronously at construction."""

    code: ClassVar[str] = RELAY_SDK_CONFIG_CODE
    error_class: ClassVar[str] = RELAY_SDK_CONFIG_CLASS
    http_status: ClassVar[int] = 400
    default_blocked_surface: ClassVar[str] = "relay-sdk"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelaySidecarVersionMismatch(RelaySidecarError):
    """The attached sidecar reports a version outside the SDK compat range."""

    code: ClassVar[str] = RELAY_SDK_VERSION_MISMATCH_CODE
    error_class: ClassVar[str] = RELAY_SDK_VERSION_MISMATCH_CLASS
    http_status: ClassVar[int] = 503
    default_blocked_surface: ClassVar[str] = "GET /health"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelaySidecarNotReachable(RelaySidecarError):
    """No sidecar is reachable and auto-spawn is disabled."""

    code: ClassVar[str] = RELAY_SDK_NO_SIDECAR_CODE
    error_class: ClassVar[str] = RELAY_SDK_NO_SIDECAR_CLASS
    http_status: ClassVar[int] = 503
    default_blocked_surface: ClassVar[str] = "GET /health"
    default_retry_advice: ClassVar[str] = "after_state_change"


class RelayAuthMismatch(RelayAuthError):
    """The sidecar rejected, or failed to satisfy, the nonce-challenge auth."""

    code: ClassVar[str] = RELAY_SDK_AUTH_MISMATCH_CODE
    error_class: ClassVar[str] = RELAY_SDK_AUTH_MISMATCH_CLASS
    http_status: ClassVar[int] = 401
    default_blocked_surface: ClassVar[str] = "GET /health"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelayCanonicalStatusForbidden(RelayIngestError):
    """SDK refused to submit an envelope containing a canonical-result field.

    Class-default ``code`` is the SDK-local ``RELAY-SDK-005`` because the
    SDK raises this from its OWN boundary BEFORE any sidecar round-trip
    (per VAL-W3-010). When the sidecar enforces the same invariant and
    returns the wire code ``RELAY-ING-031``, the transport surfaces that
    via the same exception type with the wire code passed explicitly,
    preserving both the typed surface and the wire-code observability.
    """

    code: ClassVar[str] = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE
    error_class: ClassVar[str] = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelayLifecycleInvalid(RelaySdkError):
    """``client_lifecycle_status`` value is outside the closed enum."""

    code: ClassVar[str] = RELAY_SDK_LIFECYCLE_INVALID_CODE
    error_class: ClassVar[str] = RELAY_SDK_LIFECYCLE_INVALID_CLASS
    http_status: ClassVar[int] = 400
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelayHandoffIncomplete(RelayIngestError):
    """Three-anchor handoff is missing or stale.

    Class-default ``code`` is the SDK-local ``RELAY-SDK-007``. The wire
    code ``RELAY-ING-022`` is preserved by the transport in
    ``details["code"]`` when the sidecar surfaces this code.
    """

    code: ClassVar[str] = RELAY_SDK_HANDOFF_INCOMPLETE_CODE
    error_class: ClassVar[str] = RELAY_SDK_HANDOFF_INCOMPLETE_CLASS
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"
    default_retry_advice: ClassVar[str] = "after_state_change"


class RelayEvidenceIncomplete(RelayEvidenceError):
    """Evidence envelope is missing one or more required binding fields.

    Class-default ``code`` is the SDK-local ``RELAY-SDK-008``. The wire
    code ``RELAY-EVID-002`` is preserved by the transport in
    ``details["code"]``.
    """

    code: ClassVar[str] = RELAY_SDK_EVIDENCE_INCOMPLETE_CODE
    error_class: ClassVar[str] = RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/evidence"
    default_retry_advice: ClassVar[str] = "no_retry"


class RelayReplayPrecondition(RelayReplayError):
    """Replay creation precondition failed (run_result not yet written).

    Class-default ``code`` is the SDK-local ``RELAY-SDK-009``. The wire
    code ``RELAY-REPLAY-002`` is preserved by the transport in
    ``details["code"]``.
    """

    code: ClassVar[str] = RELAY_SDK_REPLAY_PRECONDITION_CODE
    error_class: ClassVar[str] = RELAY_SDK_REPLAY_PRECONDITION_CLASS
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/runs/{run_id}/replays"
    default_retry_advice: ClassVar[str] = "after_state_change"


class RelayPolicyError(RelayIngestError):
    """Redaction policy failed to parse or violated a structural invariant.

    Class-default ``code`` is the SDK-local ``RELAY-SDK-010``. When the
    sidecar surfaces the W3.3 defense-in-depth wire code ``RELAY-ING-032``
    it is preserved by the transport in ``details["code"]``.
    """

    code: ClassVar[str] = RELAY_SDK_POLICY_INVALID_CODE
    error_class: ClassVar[str] = RELAY_SDK_POLICY_INVALID_CLASS
    http_status: ClassVar[int] = 422
    default_blocked_surface: ClassVar[str] = "POST /v1/ingest/runs"
    default_retry_advice: ClassVar[str] = "no_retry"


# =============================================================================
# Forward-compat fallback for unknown codes (VAL-W3-035).
# =============================================================================


class RelayUnknownError(RelayError):
    """Sidecar returned a code the SDK does not recognise.

    Per VAL-W3-035 the SDK MUST NOT crash on a future or
    namespace-out-of-band wire code; it raises ``RelayUnknownError`` with
    the original ``code`` preserved on the instance so callers can still
    log, attribute, and decide how to retry.
    """

    code: ClassVar[str] = RELAY_FUTURE_999_CODE
    error_class: ClassVar[str] = "RELAY-UNKNOWN-ERROR"
    http_status: ClassVar[int] = 500
    default_blocked_surface: ClassVar[str] = "relay-unknown"
    default_retry_advice: ClassVar[str] = "no_retry"


# =============================================================================
# Code-prefix -> class routing (used by RelayError.from_envelope and by the
# transport layer when classifying a sidecar response).
# =============================================================================

# Specific known leaves (most-specific first). Wire codes the SDK has a
# typed leaf for. Mirrors the TS leaf registry in
# packages/sdk-typescript/src/errors.ts CODE_LEAF_REGISTRY byte-for-byte
# so the cross-language error envelope parity (VAL-W4-029) holds: a
# wire code routed via Python ``from_envelope`` MUST produce the same
# typed leaf (and therefore the same ``error_class`` envelope field) as
# the TypeScript ``RelayError.fromEnvelope`` would for the identical
# input.
_CODE_LEAF_REGISTRY: dict[str, type[RelayError]] = {
    # Sidecar wire codes the SDK surfaces back as typed leaves.
    RELAY_ING_031_CODE: RelayCanonicalStatusForbidden,
    RELAY_ING_022_CODE: RelayHandoffIncomplete,
    RELAY_ING_RAW_PAYLOAD_CODE: RelayPolicyError,
    RELAY_REPLAY_002_CODE: RelayReplayPrecondition,
    RELAY_EVID_002_CODE: RelayEvidenceIncomplete,
    # RELAY-GATE-021 (stale handoff) -> typed leaf, parity with TS.
    RELAY_GATE_021_CODE: RelayHandoffIncomplete,
    # SDK-local codes the Py SDK also surfaces as typed leaves so the
    # ``error_class`` envelope field matches the TS leaf class default.
    RELAY_SDK_CONFIG_CODE: RelayConfigError,
    RELAY_SDK_VERSION_MISMATCH_CODE: RelaySidecarVersionMismatch,
    RELAY_SDK_NO_SIDECAR_CODE: RelaySidecarNotReachable,
    RELAY_SDK_AUTH_MISMATCH_CODE: RelayAuthMismatch,
    RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE: RelayCanonicalStatusForbidden,
    RELAY_SDK_LIFECYCLE_INVALID_CODE: RelayLifecycleInvalid,
    RELAY_SDK_HANDOFF_INCOMPLETE_CODE: RelayHandoffIncomplete,
    RELAY_SDK_EVIDENCE_INCOMPLETE_CODE: RelayEvidenceIncomplete,
    RELAY_SDK_REPLAY_PRECONDITION_CODE: RelayReplayPrecondition,
    RELAY_SDK_POLICY_INVALID_CODE: RelayPolicyError,
}

# Namespace prefix -> intermediate class. Ordered so the longer prefixes
# match first (RELAY-REPLAY- before RELAY-SCHEMA-, etc.).
_NAMESPACE_PREFIX_REGISTRY: list[tuple[str, type[RelayError]]] = [
    ("RELAY-ING-", RelayIngestError),
    ("RELAY-AUTH-", RelayAuthError),
    ("RELAY-RATE-", RelayRateLimitError),
    ("RELAY-GATE-", RelayGateError),
    ("RELAY-EVID-", RelayEvidenceError),
    ("RELAY-REPLAY-", RelayReplayError),
    ("RELAY-SCHEMA-", RelaySchemaError),
    ("RELAY-SIDECAR-", RelaySidecarError),
    ("RELAY-SDK-", RelaySdkError),
    ("RELAY-SQLITE-", RelaySQLiteError),
]


def _resolve_class_for_code(code: str) -> type[RelayError]:
    """Return the RelayError subclass to instantiate for ``code``.

    Lookup order:
      1. Specific leaf registry (exact code match).
      2. Namespace prefix registry (prefix match).
      3. :class:`RelayUnknownError` (forward-compat fallback;
         VAL-W3-035).
    """
    leaf = _CODE_LEAF_REGISTRY.get(code)
    if leaf is not None:
        return leaf
    for prefix, cls in _NAMESPACE_PREFIX_REGISTRY:
        if code.startswith(prefix):
            return cls
    return RelayUnknownError


def resolve_class_for_code(code: str) -> type[RelayError]:
    """Public re-export of the prefix/leaf routing table."""
    return _resolve_class_for_code(code)


__all__ = [
    "RELAY_AUTH_DEFAULT_CODE",
    "RELAY_EVID_002_CODE",
    "RELAY_EVID_DEFAULT_CODE",
    "RELAY_FUTURE_999_CODE",
    "RELAY_GATE_DEFAULT_CODE",
    "RELAY_ING_001_CODE",
    "RELAY_ING_022_CODE",
    "RELAY_ING_031_CODE",
    "RELAY_ING_DEFAULT_CODE",
    "RELAY_ING_RAW_PAYLOAD_CODE",
    "RELAY_RATE_DEFAULT_CODE",
    "RELAY_REPLAY_002_CODE",
    "RELAY_REPLAY_DEFAULT_CODE",
    "RELAY_SCHEMA_DEFAULT_CODE",
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
    "RELAY_SDK_REGEX_REDOS_CODE",
    "RELAY_SDK_REPLAY_PRECONDITION_CLASS",
    "RELAY_SDK_REPLAY_PRECONDITION_CODE",
    "RELAY_SDK_VERSION_MISMATCH_CLASS",
    "RELAY_SDK_VERSION_MISMATCH_CODE",
    "RELAY_SIDECAR_DEFAULT_CODE",
    "RELAY_SQLITE_DEFAULT_CODE",
    "RelayAuthError",
    "RelayAuthMismatch",
    "RelayCanonicalStatusForbidden",
    "RelayConfigError",
    "RelayError",
    "RelayEvidenceError",
    "RelayEvidenceIncomplete",
    "RelayGateError",
    "RelayHandoffIncomplete",
    "RelayIngestError",
    "RelayLifecycleInvalid",
    "RelayPolicyError",
    "RelayRateLimitError",
    "RelayReplayError",
    "RelayReplayPrecondition",
    "RelaySchemaError",
    "RelaySdkError",
    "RelaySidecarError",
    "RelaySidecarNotReachable",
    "RelaySidecarVersionMismatch",
    "RelaySQLiteError",
    "RelayUnknownError",
    "RetryAdviceMode",
    "resolve_class_for_code",
]
