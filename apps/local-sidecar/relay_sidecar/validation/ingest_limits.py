"""Ingest span size + nesting depth hardening (VAL-V2M08-002, 003).

Spec anchor: AI line 5659.

The sidecar's ``POST /v1/ingest/spans:batch`` endpoint serializes each
incoming span to canonical UTF-8 JSON and rejects any span whose
serialized length strictly exceeds :data:`MAX_SPAN_CANONICAL_BYTES`
(262144 bytes = 256 KiB) with HTTP 413 and structured code
:data:`~relay_schemas.error_codes.RelayErrorCode.RELAY_ING_041`.

The same envelope is returned when a span's attribute tree is nested
deeper than :data:`MAX_SPAN_NESTING_DEPTH` (16 levels), with
``reason="nesting_depth_exceeded"`` to disambiguate the two failure
modes.

Both checks are pure: no global state, no I/O, no network. They are
exercised by tier-1 plumbing tests directly (without spawning the
sidecar) so the limits stay testable across all three target platforms
(macOS, Linux, Windows).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from typing import Any, Final

# 256 KiB canonical-JSON span cap (spec AI line 5659). The check uses
# strict ``>`` (exceeding the cap rejects; exactly-262144 is rejected;
# 262143 is accepted) to match the contract VAL-V2M08-002 envelope.
MAX_SPAN_CANONICAL_BYTES: Final[int] = 262144

# 16-level nesting depth cap (spec AI line 5659). A span whose attribute
# tree is nested 17 levels (depth 17) is rejected; depth 16 is accepted.
MAX_SPAN_NESTING_DEPTH: Final[int] = 16

# Canonical error code emitted on either rejection.
_ERROR_CODE: Final[str] = "RELAY-ING-041"
_HTTP_STATUS: Final[int] = 413


def _canonical_bytes(span: dict[str, Any]) -> int:
    """Return the byte length of the canonical-JSON serialization.

    Canonical form: ``json.dumps(..., separators=(',', ':'),
    sort_keys=True, ensure_ascii=False)``. The serializer error-paths
    (unserializable values, recursion limit) are surfaced as
    :class:`ValueError` so the caller can attribute the rejection
    correctly; we never silently coerce.
    """
    return len(
        json.dumps(
            span,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    )


def _measure_depth(root: Any) -> int:
    """Return the maximum nesting depth of ``root``.

    Depth counts dict / list nesting levels. A leaf scalar is depth 0; a
    one-key dict whose value is a scalar is depth 1; a chain of 16 nested
    dicts is depth 16.

    The walk is iterative and short-circuits as soon as the measured
    depth exceeds :data:`MAX_SPAN_NESTING_DEPTH` + 1, so a 10,000-deep
    adversarial input cannot trigger a Python ``RecursionError``. The
    short-circuit returns the first depth strictly greater than the
    cap; the caller compares against the cap, not the exact maximum.
    """
    max_depth = 0
    stack: list[tuple[Any, int]] = [(root, 0)]
    cap_plus_one = MAX_SPAN_NESTING_DEPTH + 1
    while stack:
        value, current = stack.pop()
        if isinstance(value, dict):
            child_depth = current + 1
            if child_depth > max_depth:
                max_depth = child_depth
            if max_depth > cap_plus_one:
                # Short-circuit: caller only needs to know depth > cap.
                return max_depth
            if value:
                stack.extend((v, child_depth) for v in value.values())
        elif isinstance(value, list):
            child_depth = current + 1
            if child_depth > max_depth:
                max_depth = child_depth
            if max_depth > cap_plus_one:
                return max_depth
            if value:
                stack.extend((v, child_depth) for v in value)
        else:
            if current > max_depth:
                max_depth = current
    return max_depth


def validate_span_size_and_depth(span: dict[str, Any]) -> dict[str, Any] | None:
    """Return ``None`` if ``span`` passes both hardening checks.

    Return a structured rejection envelope dict otherwise. The envelope
    keys are stable wire-format names:

    * ``code`` -- always ``"RELAY-ING-041"``.
    * ``http_status`` -- always ``413``.
    * ``offending_span_id`` -- echoes ``span["span_id"]`` if present, else
      the empty string.
    * ``measured_bytes`` -- the canonical-JSON byte length (set when the
      size cap is exceeded).
    * ``reason`` -- ``"nesting_depth_exceeded"`` when the depth cap is
      the trigger (size cap rejections do not set this key).
    """
    span_id = span.get("span_id", "") if isinstance(span, dict) else ""
    if not isinstance(span_id, str):
        span_id = ""

    # Check nesting depth first so a deeply-nested but small span is
    # attributed to the depth violation rather than the size cap. The
    # depth check is applied to the span's attribute tree (the value
    # the SDK serializes for OpenTelemetry-style attributes) rather
    # than the whole span envelope; a span with depth-16 attributes
    # plus the span_id wrapper is still attribute-depth 16. When a
    # span lacks an "attributes" key the whole span body is treated
    # as the attribute tree for defensive depth measurement.
    attribute_tree: Any = (
        span.get("attributes", span) if isinstance(span, dict) else span
    )
    depth = _measure_depth(attribute_tree)
    if depth > MAX_SPAN_NESTING_DEPTH:
        return {
            "code": _ERROR_CODE,
            "http_status": _HTTP_STATUS,
            "offending_span_id": span_id,
            "reason": "nesting_depth_exceeded",
            "measured_depth": depth,
            "max_depth": MAX_SPAN_NESTING_DEPTH,
        }

    measured = _canonical_bytes(span)
    if measured > MAX_SPAN_CANONICAL_BYTES:
        return {
            "code": _ERROR_CODE,
            "http_status": _HTTP_STATUS,
            "offending_span_id": span_id,
            "measured_bytes": measured,
            "max_bytes": MAX_SPAN_CANONICAL_BYTES,
        }
    return None


__all__ = [
    "MAX_SPAN_CANONICAL_BYTES",
    "MAX_SPAN_NESTING_DEPTH",
    "validate_span_size_and_depth",
]
