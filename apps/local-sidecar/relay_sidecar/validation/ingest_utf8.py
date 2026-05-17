"""Invalid-UTF-8 check on indexed string fields (VAL-V2M08-010).

Spec anchor: AI line 5698.

The sidecar's ingest endpoint rejects any span carrying invalid UTF-8
byte sequences in an indexed string field (``prompt_template_id``,
``tool_name``, ``model``, ``retriever_name``, or any caller-supplied
extension via ``indexed_string_fields``) with HTTP 400 and structured
code ``RELAY-ING-045``. Valid UTF-8 NFC strings pass through unchanged.

The validator accepts both ``str`` (Python unicode code points -- a
lone surrogate is rejected because it cannot be encoded under
``errors='strict'``) and ``bytes`` (raw bytes that arrived through a
non-text transport -- decoded under ``errors='strict'`` to detect
invalid sequences).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

# Canonical indexed-string field set (spec AI line 5698 lists these
# four explicitly; any additional fields a caller declares via
# ``indexed_string_fields`` extend this set without replacing it).
DEFAULT_INDEXED_STRING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "prompt_template_id",
        "tool_name",
        "model",
        "retriever_name",
    }
)

_ERROR_CODE: Final[str] = "RELAY-ING-045"
_HTTP_STATUS: Final[int] = 400


def _is_valid_utf8(value: Any) -> bool:
    """Return True iff ``value`` is a string that round-trips through
    UTF-8 under ``errors='strict'`` (no lone surrogates), or bytes that
    decode cleanly under UTF-8.

    Returns True for non-string-like inputs (``int``, ``None``, ``dict``
    etc.) so they are skipped by the indexed-field check; only strings
    and bytes are subject to the UTF-8 hardening.
    """
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
            return True
        except UnicodeEncodeError:
            return False
    if isinstance(value, bytes | bytearray):
        try:
            bytes(value).decode("utf-8", errors="strict")
            return True
        except UnicodeDecodeError:
            return False
    return True


def validate_indexed_utf8(
    fields: dict[str, Any],
    *,
    indexed_string_fields: Iterable[str] | None = None,
) -> dict[str, Any] | None:
    """Return ``None`` if every indexed-string field in ``fields`` is
    valid UTF-8.

    Return a structured rejection envelope dict otherwise. The envelope
    keys are stable wire-format names:

    * ``code`` -- ``"RELAY-ING-045"``.
    * ``http_status`` -- ``400``.
    * ``field_path`` -- the offending field's dotted path within the
      span attributes; for the canonical fields this is just the field
      name (no nesting).

    The check is order-stable: fields are inspected in
    ``sorted(indexed_string_fields)`` order so the same rejection is
    surfaced across the OSS replay corpus regardless of dict iteration
    order on a given Python build.
    """
    if not isinstance(fields, dict):
        return None
    effective: frozenset[str] = (
        frozenset(indexed_string_fields)
        if indexed_string_fields is not None
        else DEFAULT_INDEXED_STRING_FIELDS
    )
    for field_name in sorted(effective):
        if field_name not in fields:
            continue
        value = fields[field_name]
        if not _is_valid_utf8(value):
            return {
                "code": _ERROR_CODE,
                "http_status": _HTTP_STATUS,
                "field_path": field_name,
            }
    return None


__all__ = [
    "DEFAULT_INDEXED_STRING_FIELDS",
    "validate_indexed_utf8",
]
