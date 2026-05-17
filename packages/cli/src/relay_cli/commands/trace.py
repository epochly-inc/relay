"""``rly trace`` command (M07 w7-cli-trace).

Implements VAL-V2M07-001..003: emits canonical trace JSON for a run by
querying the local sidecar's ``GET /v1/runs/{run_id}/trace`` endpoint.

Exit codes:
  * 0 -- success (run found, trace returned)
  * 3 -- run not found (RELAY-ING-NOTFOUND per VAL-V2M07-003)
  * 4 -- transient (sidecar 5xx / connection error)
  * 64 -- usage error (missing run_id)
  * 70 -- uncaught internal

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from typing import Any, Final

import httpx
import typer

from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_CASSETTE_MISS,
    EXIT_SUCCESS,
)
from ..output import emit_json

TRACE_SCHEMA: Final[str] = "relay.cli.trace.v1"
ENV_SIDECAR_URL: Final[str] = "RELAY_SIDECAR_URL"
DEFAULT_SIDECAR_URL: Final[str] = "http://127.0.0.1:8088"

# Test seam: when set to a JSON document, the command returns the
# document verbatim instead of querying the sidecar. The document MUST
# already match the canonical envelope. Used by plumbing tests that do
# not spin up a real sidecar.
ENV_TRACE_FIXTURE: Final[str] = "RELAY_CLI_TRACE_FIXTURE"
ENV_TRACE_FIXTURE_NOT_FOUND: Final[str] = "RELAY_CLI_TRACE_NOT_FOUND"


def _sidecar_url() -> str:
    return os.environ.get(ENV_SIDECAR_URL, DEFAULT_SIDECAR_URL).rstrip("/")


def cmd_trace(
    run_id: str = typer.Argument(
        ..., help="Run identifier (UUID) to fetch the canonical trace for."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly trace <run_id>`` -- emit the canonical trace JSON envelope.

    Per VAL-V2M07-001 the envelope's ``schema_version`` is exactly
    ``relay.cli.trace.v1``; per VAL-V2M07-002 each span carries
    ``span_id``, ``parent_span_id``, ``start_time_unix_nano``,
    ``end_time_unix_nano``, ``name``, ``attributes``.
    """
    del json_output  # JSON-on-pipe handled by emit_json
    if not run_id:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-RUN-ID",
            http_status=400,
            message="run_id is required",
            blocked_surface="rly trace",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64)

    # Test seam: not-found fixture -> exit 3
    if os.environ.get(ENV_TRACE_FIXTURE_NOT_FOUND, "").strip() == run_id:
        envelope = build_envelope(
            code="RELAY-ING-NOTFOUND",
            http_status=404,
            message=f"run_id {run_id!r} not found",
            blocked_surface="rly trace",
            retry_advice="do_not_retry",
            details={"run_id": run_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)

    # Test seam: fixture JSON path
    fixture_path = os.environ.get(ENV_TRACE_FIXTURE, "").strip()
    if fixture_path:
        import json
        from pathlib import Path
        try:
            payload = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            envelope = build_envelope(
                code="RELAY-CLI-FIXTURE-INVALID",
                http_status=500,
                message=f"trace fixture invalid: {exc}",
                blocked_surface="rly trace",
                retry_advice="do_not_retry",
                details={"fixture_path": fixture_path},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=70) from exc
        _emit_envelope_from_trace(run_id, payload)
        raise typer.Exit(code=EXIT_SUCCESS)

    # Real path: query the sidecar.
    url = f"{_sidecar_url()}/v1/runs/{run_id}/trace"
    try:
        resp = httpx.get(url, timeout=5.0)
    except httpx.HTTPError as exc:
        envelope = build_envelope(
            code="RELAY-SIDECAR-UNREACHABLE",
            http_status=503,
            message=f"sidecar unreachable at {url}: {exc}",
            blocked_surface="rly trace",
            retry_advice="after_fix",
            details={"sidecar_url": _sidecar_url()},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS) from exc

    if resp.status_code == 404:
        envelope = build_envelope(
            code="RELAY-ING-NOTFOUND",
            http_status=404,
            message=f"run_id {run_id!r} not found",
            blocked_surface="rly trace",
            retry_advice="do_not_retry",
            details={"run_id": run_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)
    if resp.status_code >= 500:
        envelope = build_envelope(
            code="RELAY-SIDECAR-TRANSIENT",
            http_status=resp.status_code,
            message=f"sidecar returned {resp.status_code}",
            blocked_surface="rly trace",
            retry_advice="after_fix",
            details={"sidecar_url": _sidecar_url()},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS)

    payload = resp.json()
    _emit_envelope_from_trace(run_id, payload)
    raise typer.Exit(code=EXIT_SUCCESS)


def _emit_envelope_from_trace(run_id: str, raw: dict[str, Any]) -> None:
    """Project a sidecar trace response into the canonical CLI envelope.

    The sidecar's ``relay.trace.v1`` envelope uses ``started_at`` /
    ``ended_at`` RFC 3339 timestamps; the CLI's ``relay.cli.trace.v1``
    envelope mandates ``start_time_unix_nano`` / ``end_time_unix_nano``
    per VAL-V2M07-002. We convert each span timestamp to unix nanos and
    populate the required fields.
    """
    spans_raw = raw.get("spans", [])
    out_spans: list[dict[str, Any]] = []
    for s in spans_raw if isinstance(spans_raw, list) else []:
        if not isinstance(s, dict):
            continue
        out_spans.append({
            "span_id": s.get("span_id", ""),
            "parent_span_id": s.get("parent_span_id"),
            "start_time_unix_nano": _rfc3339_to_nanos(s.get("started_at")),
            "end_time_unix_nano": _rfc3339_to_nanos(s.get("ended_at")),
            "name": s.get("name", ""),
            "attributes": {
                "span_type": s.get("span_type"),
                "status": s.get("status"),
                "error_class": s.get("error_class"),
            },
        })
    emit_json({
        "schema_version": TRACE_SCHEMA,
        "run_id": run_id,
        "spans": out_spans,
    })


def _rfc3339_to_nanos(ts: Any) -> int:
    """Convert RFC 3339 / ISO timestamp to nanoseconds since epoch.

    Returns 0 for None / unparseable input. The CLI envelope contract
    requires an integer; consumers parsing the envelope MUST tolerate
    zero as "unknown" without raising.
    """
    if not isinstance(ts, str) or not ts:
        return 0
    try:
        from datetime import datetime
        # Replace Z with +00:00 for fromisoformat
        canonical = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(canonical)
        return int(dt.timestamp() * 1_000_000_000)
    except (ValueError, TypeError):
        return 0


__all__ = ["TRACE_SCHEMA", "cmd_trace"]
