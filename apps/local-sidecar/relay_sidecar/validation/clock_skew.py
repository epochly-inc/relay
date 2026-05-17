"""Clock-skew rejection emitter (VAL-V2M08-007).

Spec anchors: L line 4479; AI lines 5651-5670.

An auth-bearing request whose signed timestamp is more than +/-300 s
outside the server's ``now()`` is rejected with HTTP 401 and structured
code ``RELAY-AUTH-017``. The envelope includes both ``server_now_utc``
and ``client_claim_utc`` so the client can self-diagnose the skew
direction; the human ``message`` carries the canonical remediation hint
(``sync the client clock via NTP or the host time service``) and is
produced from the registry's ``message_template`` for
``RELAY-AUTH-017``.

This module is pure and deterministic: it accepts unix-epoch seconds in
and emits envelope dicts out. Callers wire it into the actual HTTP
auth path (currently a private-platform concern; the OSS sidecar uses
the same primitive whenever it needs to enforce a signed-timestamp
window).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Final

# +/-300 s default clock-skew tolerance (spec AI lines 5651-5670; the
# registry's RELAY-AUTH-017 message_template also pins this value).
CLOCK_SKEW_WINDOW_S: Final[int] = 300

_ERROR_CODE: Final[str] = "RELAY-AUTH-017"
_HTTP_STATUS: Final[int] = 401


def _to_iso_z(unix_seconds: int | float) -> str:
    """Return the UTC ISO-8601 form (``YYYY-MM-DDTHH:MM:SSZ``).

    Uses the timezone-aware path (``datetime.fromtimestamp(..., tz=UTC)``)
    so the formatter is deterministic across host timezones. The format
    strips microseconds for stable evidence-bundle equality.
    """
    dt = _dt.datetime.fromtimestamp(unix_seconds, tz=_dt.UTC)
    return dt.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_clock_skew(
    *,
    server_now_unix: int | float,
    client_claim_unix: int | float,
    window_s: int = CLOCK_SKEW_WINDOW_S,
) -> dict[str, Any] | None:
    """Return ``None`` if the absolute skew is within ``window_s``.

    Return a structured rejection envelope otherwise. The envelope
    carries:

    * ``code`` -- ``"RELAY-AUTH-017"``.
    * ``http_status`` -- ``401``.
    * ``server_now_utc`` -- ISO-8601 UTC of ``server_now_unix``.
    * ``client_claim_utc`` -- ISO-8601 UTC of ``client_claim_unix``.
    * ``skew_seconds`` -- signed delta (``client_claim - server_now``)
      so the client can attribute the direction without recomputing.
    * ``window_seconds`` -- the active +/-window the server applied.
    * ``message`` -- the registry's RELAY-AUTH-017 message_template
      formatted against the envelope context (kept for transport
      surfaces that surface ``message`` verbatim to the caller).
    """
    skew = float(client_claim_unix) - float(server_now_unix)
    if abs(skew) <= window_s:
        return None
    server_iso = _to_iso_z(server_now_unix)
    client_iso = _to_iso_z(client_claim_unix)
    # Lazy import to keep this module importable without the schemas
    # package being present at import time (e.g. for unit tests that
    # only need the bare arithmetic).
    try:
        from relay_schemas.error_code_registry import get_code_details

        detail = get_code_details(_ERROR_CODE)
        if detail is not None and detail.message_template is not None:
            message = detail.message_template.format(
                server_now_utc=server_iso,
                client_claim_utc=client_iso,
            )
        else:
            message = (
                f"clock skew exceeds +/-{window_s} s window: "
                f"server_now_utc={server_iso} client_claim_utc={client_iso}"
            )
    except Exception:  # noqa: BLE001 -- defensive: never fail the envelope
        message = (
            f"clock skew exceeds +/-{window_s} s window: "
            f"server_now_utc={server_iso} client_claim_utc={client_iso}"
        )
    return {
        "code": _ERROR_CODE,
        "http_status": _HTTP_STATUS,
        "server_now_utc": server_iso,
        "client_claim_utc": client_iso,
        "skew_seconds": skew,
        "window_seconds": window_s,
        "message": message,
    }


__all__ = [
    "CLOCK_SKEW_WINDOW_S",
    "check_clock_skew",
]
