"""CLI error envelope construction (VAL-W5-004 / VAL-W5-005).

Every CLI exception path produces a single line of JSON on stderr matching
the spec section B.4 error envelope shape. The envelope schema_version is
``relay.error.v1`` -- the single source of truth declared in
``packages/schemas/raw/envelopes.yaml`` (``ErrorEnvelope`` model under
:mod:`relay_schemas.envelopes`).

The CLI envelope is wire-compatible with the spec section B.4 error JSON
illustrated at spec lines 3392-3408, including the ``documentation_url``
field shown in the spec illustration. Per spec section B.4 the wire
``retry_advice`` value is a closed enum string (``do_not_retry``,
``after_fix``, ``after_retry_after``, ``after_split``, ``after_recapture``,
``after_re_auth``); the SDK structured-dict form (VAL-W3-031) is mapped
back to the wire enum here so a piped consumer always sees the spec
section B.4 shape.

Two utility functions:

  * :func:`build_envelope` -- construct a wire envelope dict from explicit
    fields. Used by signal handlers and uncaught-exception wrappers that
    do not start from a :class:`relay.errors.RelayError` instance.
  * :func:`envelope_from_relay_error` -- build a wire envelope from an SDK
    :class:`relay.errors.RelayError` instance. Used by the typed-exception
    wrapper.

Per CLAUDE.md banned product copy rules (VAL-W5-009 / VAL-W5-009b, see
``scripts/lint-banned-copy.py`` for the enumerated tokens) every
``message`` and ``blocked_surface`` value MUST avoid the banned-marketing
tokens enforced by that lint. Callers are responsible for the prose
content; this module only assembles the envelope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
import uuid
from typing import Any, Final

from relay.errors import RelayError

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# VAL-W5-004 / VAL-W1-056: schema_version literal pin. Identical to the
# wire ErrorEnvelope schema in ``packages/schemas/raw/envelopes.yaml``.
ERROR_ENVELOPE_SCHEMA_VERSION: Final[str] = "relay.error.v1"

# Closed enum of valid wire retry_advice values (spec section B.4
# lines 3392-3408 + envelopes.yaml ErrorEnvelope.retry_advice).
WIRE_RETRY_ADVICE_VALUES: Final[frozenset[str]] = frozenset(
    {
        "do_not_retry",
        "after_fix",
        "after_retry_after",
        "after_split",
        "after_recapture",
        "after_re_auth",
    }
)

# Map from SDK structured retry_advice mode -> spec wire enum string.
# Inverse of ``packages/sdk-python/relay/errors.py::_WIRE_RETRY_ADVICE_TO_DICT``
# but condensed to the canonical wire form: SDK ``mode`` strings flow back
# to the closest spec wire enum value. ``no_retry`` SDK mode -> wire
# ``do_not_retry``. ``after_state_change`` SDK mode -> wire ``after_fix``
# (the spec section B.4 narrative collapses the multiple "after_*" wire
# values into the SDK ``after_state_change`` mode; the inverse mapping
# picks ``after_fix`` as the safest default because it is the most
# permissive remediation form).
_SDK_MODE_TO_WIRE_RETRY_ADVICE: Final[dict[str, str]] = {
    "no_retry": "do_not_retry",
    "retryable": "after_fix",
    "after_state_change": "after_fix",
    "after_retry_after": "after_retry_after",
}

# VAL-W5-004: the CLI's uncaught-exception wrapper emits this code on any
# exception path that did NOT start from a typed ``RelayError`` (e.g., a
# bare ``KeyError`` raised during option parsing). Defined in the canonical
# error-code registry at ``packages/schemas/raw/relay-error-codes.yaml``.
RELAY_CLI_UNCAUGHT_CODE: Final[str] = "RELAY-CLI-070"

# VAL-W5-007: the CLI's SIGINT/SIGTERM signal handler emits this code on
# terminal interrupt. Listed in the canonical error-code registry as
# ``RELAY-CLI-130``.
RELAY_CLI_INTERRUPTED_CODE: Final[str] = "RELAY-CLI-130"

# Canonical Relay docs base URL. Mirrors the SDK constant in
# ``packages/sdk-python/relay/errors.py::_DEFAULT_DOC_URL_PREFIX`` so a
# CLI envelope's documentation_url matches what the SDK produces for the
# same code.
_DEFAULT_DOC_URL_PREFIX: Final[str] = "https://relay.epochly.com/docs/errors/"


# -----------------------------------------------------------------------------
# Envelope construction
# -----------------------------------------------------------------------------


def _coerce_retry_advice_to_wire(value: Any) -> str:
    """Project an SDK structured retry_advice into the wire enum string.

    Accepts:
      * a string already in the wire enum -- returned verbatim
      * a string SDK ``mode`` value -- mapped via :data:`_SDK_MODE_TO_WIRE_RETRY_ADVICE`
      * a dict with a ``mode`` key -- the mode is mapped as above
      * any other value -- defaults to ``do_not_retry`` (spec section B.4
        narrative: "do_not_retry" means the error is terminal and the
        submitter MUST NOT retry; this is the safest default for an
        opaque value)

    The wire enum is closed; an unknown value is coerced to ``do_not_retry``
    rather than passed through, which would fail the W1 ErrorEnvelope schema.
    """
    if isinstance(value, str):
        if value in WIRE_RETRY_ADVICE_VALUES:
            return value
        mapped = _SDK_MODE_TO_WIRE_RETRY_ADVICE.get(value)
        if mapped is not None:
            return mapped
        return "do_not_retry"
    if isinstance(value, dict):
        mode = value.get("mode")
        if isinstance(mode, str):
            return _coerce_retry_advice_to_wire(mode)
    return "do_not_retry"


def _new_request_id() -> str:
    """Return a request_id string for envelopes that do not carry one.

    VAL-W1-031 requires ``request_id`` to be a non-empty string; SDK errors
    typically carry one propagated from the sidecar, but the CLI's signal
    handler and the uncaught-exception wrapper run before any sidecar
    round-trip, so a fresh ULID-shape (UUIDv4 hex prefixed with ``cli_``)
    is generated. This is a CLI-local id; auditors correlate via trace_id
    if the CLI managed to emit one.
    """
    return "cli_" + uuid.uuid4().hex


def build_envelope(
    *,
    code: str,
    http_status: int,
    message: str,
    blocked_surface: str,
    retry_advice: Any = "do_not_retry",
    request_id: str | None = None,
    trace_id: str | None = None,
    documentation_url: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a CLI error envelope (wire-compatible with spec section B.4).

    Returns a dict ready for ``json.dumps(envelope, separators=(",", ":"))``.
    Field order is: schema_version, code, http_status, message,
    blocked_surface, documentation_url, retry_advice, request_id, trace_id,
    details. The order matches the spec section B.4 illustration (lines
    3396-3407) for readability when the envelope is rendered as a single
    JSON line.

    Per VAL-W1-031 ``request_id`` and ``trace_id`` are required non-empty
    strings; ``trace_id`` defaults to a CLI-local id if the caller does not
    propagate one. Per VAL-W1-029 ``http_status`` MUST be in [400, 599];
    callers passing 2xx values violate the wire envelope contract -- this
    function does NOT silently rewrite the value; the W1 ErrorEnvelope
    schema validation in :mod:`relay_cli.tests` catches it.
    """
    envelope: dict[str, Any] = {
        "schema_version": ERROR_ENVELOPE_SCHEMA_VERSION,
        "code": code,
        "http_status": http_status,
        "message": message,
        "blocked_surface": blocked_surface,
        "documentation_url": (
            documentation_url
            if documentation_url is not None
            else f"{_DEFAULT_DOC_URL_PREFIX}{code}"
        ),
        "retry_advice": _coerce_retry_advice_to_wire(retry_advice),
        "request_id": request_id if request_id else _new_request_id(),
        "trace_id": trace_id if trace_id else _new_request_id(),
        "details": dict(details) if details else {},
    }
    return envelope


def envelope_from_relay_error(error: RelayError) -> dict[str, Any]:
    """Build a wire CLI envelope from an SDK :class:`RelayError`.

    The SDK error carries a structured ``retry_advice_dict`` (VAL-W3-031)
    and a ``documentation_url`` already rendered against the canonical
    docs base. This function maps both into the wire form: the structured
    dict is collapsed to the closed-enum string via
    :func:`_coerce_retry_advice_to_wire` and the documentation URL is
    passed through unchanged.

    The SDK ``http_status`` is preserved verbatim. Per VAL-W1-029 callers
    of the SDK ensure status is in [400, 599] for any non-2xx error; the
    SDK's :class:`RelayError` subclasses default to valid 4xx/5xx values.
    """
    return build_envelope(
        code=error.code,
        http_status=error.http_status,
        message=error.message,
        blocked_surface=error.blocked_surface,
        retry_advice=error.retry_advice_dict,
        request_id=error.request_id,
        trace_id=error.trace_id,
        documentation_url=error.documentation_url,
        details=error.details,
    )


def emit_envelope(envelope: dict[str, Any]) -> None:
    """Write a single line of JSON to stderr.

    Per VAL-W5-004 every CLI exception path emits a single line of JSON on
    stderr -- not stdout, not interleaved with progress logs. The line is
    serialized with the compact separators ``(",", ":")`` to match what
    the gate engine expects when piping CLI stderr into structured log
    storage. A trailing newline ensures line-oriented consumers
    (``grep``, ``jq -c``) see a complete record.

    This function does NOT call ``sys.exit`` -- the caller is responsible
    for resolving the canonical exit code (via
    :func:`relay_cli.exit_codes.exit_code_for_code_and_status`) and
    invoking ``sys.exit`` itself. The separation keeps the envelope-emit
    pure and unit-testable without a SystemExit teardown.
    """
    line = json.dumps(
        envelope, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


__all__ = [
    "ERROR_ENVELOPE_SCHEMA_VERSION",
    "RELAY_CLI_INTERRUPTED_CODE",
    "RELAY_CLI_UNCAUGHT_CODE",
    "WIRE_RETRY_ADVICE_VALUES",
    "build_envelope",
    "emit_envelope",
    "envelope_from_relay_error",
]
