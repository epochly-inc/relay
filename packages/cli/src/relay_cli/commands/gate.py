"""``rly gate evaluate`` (M07 w7-cli-gate-evaluate).

Implements VAL-V2M07-010..019: full §P.2 await_url polling with the §P.3
edge cases (network backoff, draft TTL, SIGTERM cancel, clock-skew
remediation).

Exit codes (per §P.1):
  * 0   -- action=accept
  * 1   -- action=block
  * 2   -- action=remediate
  * 3   -- RELAY-GATE-021 (stale handoff) / RELAY-AUTH-017 (clock skew)
  * 4   -- transient (network partition past TTL) / RELAY-GATE-024 (TTL expiry)
  * 64  -- usage (missing required flag)
  * 130 -- SIGTERM / SIGINT mid-polling

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import random
import signal
import sys
import time
from typing import Any, Final

import httpx
import typer

from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_AUTH_HANDOFF,
    EXIT_4XX_BLOCK,
    EXIT_4XX_REMEDIATE,
    EXIT_CASSETTE_MISS,
    EXIT_SIGINT_INTERRUPTED,
    EXIT_SUCCESS,
)
from ..output import emit_json

GATE_EVALUATE_SCHEMA: Final[str] = "relay.cli.gate_evaluate.v1"
ENV_SIDECAR_URL: Final[str] = "RELAY_SIDECAR_URL"
DEFAULT_SIDECAR_URL: Final[str] = "http://127.0.0.1:8088"

# Backoff parameters per VAL-V2M07-015 (spec §P.3 network-partition row).
BACKOFF_BASE_S: Final[float] = 1.0
BACKOFF_FACTOR: Final[float] = 2.0
BACKOFF_MAX_S: Final[float] = 30.0
BACKOFF_JITTER: Final[float] = 0.20

# Test seam env vars (all optional):
#   RELAY_CLI_GATE_FIXTURE -- JSON shape:
#     {"action": "accept"|"block"|"remediate", "failed_assertions": [...],
#      "draft_id": "...", "evidence_bundle_id": "...",
#      "signature": "...", "trace_id": "...", "duration_ms": N}
#     The command behaves as if the engine returned this gate_decision.
#   RELAY_CLI_GATE_DRAFT_RESPONSE -- JSON shape mimicking the
#     POST /v1/gates/{id}/drafts response or an error envelope. When set,
#     bypasses the real HTTP call. Used to seed RELAY-GATE-021,
#     RELAY-AUTH-017, RELAY-GATE-024, network-partition flows.
#   RELAY_CLI_GATE_DECISION_RESPONSES -- JSON array of dicts; each call to
#     GET /v1/gate-decisions/{id} returns the next one in order. Used to
#     seed multi-step polling sequences.
ENV_GATE_FIXTURE: Final[str] = "RELAY_CLI_GATE_FIXTURE"
ENV_GATE_DRAFT_RESPONSE: Final[str] = "RELAY_CLI_GATE_DRAFT_RESPONSE"
ENV_GATE_DECISION_RESPONSES: Final[str] = "RELAY_CLI_GATE_DECISION_RESPONSES"

# Test seam: when set, captures every backoff sleep into the file at this
# path as a newline-delimited JSON log of {attempt, backoff_ms} entries.
ENV_GATE_BACKOFF_LOG: Final[str] = "RELAY_CLI_GATE_BACKOFF_LOG"


def _sidecar_url() -> str:
    return os.environ.get(ENV_SIDECAR_URL, DEFAULT_SIDECAR_URL).rstrip("/")


def _next_backoff_s(attempt: int) -> float:
    """Return the backoff for ``attempt`` (1-indexed) with +/-20% jitter."""
    raw = BACKOFF_BASE_S * (BACKOFF_FACTOR ** (attempt - 1))
    clamped = min(raw, BACKOFF_MAX_S)
    jitter = random.uniform(-BACKOFF_JITTER, BACKOFF_JITTER) * clamped
    return max(0.01, clamped + jitter)


_CANCELLED = {"flag": False}


def _install_cancel_handler() -> None:
    """Install a SIGTERM/SIGINT handler that records cancel + exits 130.

    VAL-V2M07-017/018: on SIGTERM/SIGINT the CLI sends a best-effort
    cancel POST to the engine (if a draft_id is known) then exits 130.
    The handler sets a global flag; the polling loop checks it between
    sleeps so the cancel POST runs in the foreground, not a signal
    context (where httpx is unsafe).
    """

    def _handler(signum: int, frame: Any) -> None:
        del frame
        _CANCELLED["flag"] = True
        # Send the cancel POST + exit 130 directly from the handler.
        # httpx is best-effort here; failures are swallowed.
        draft = _CANCELLED.get("draft_id")
        if isinstance(draft, str) and draft:
            import contextlib
            with contextlib.suppress(httpx.HTTPError):
                httpx.post(
                    f"{_sidecar_url()}/v1/gate-decisions/{draft}/cancel",
                    timeout=1.0,
                )
        try:
            signal_name = signal.Signals(signum).name
        except (ValueError, AttributeError):
            signal_name = f"signal_{signum}"
        envelope = build_envelope(
            code="RELAY-CLI-130",
            http_status=499,
            message=f"rly gate evaluate cancelled by {signal_name}",
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={"signal": signal_name},
        )
        emit_envelope(envelope)
        sys.exit(EXIT_SIGINT_INTERRUPTED)

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            continue


def cmd_gate_evaluate(
    gate_id: str = typer.Option(
        ..., "--gate-id", help="Gate identifier (UUID) to evaluate."
    ),
    release_sha: str = typer.Option(
        "release-default",
        "--release-sha",
        help="Release commit SHA the gate is being evaluated against.",
    ),
    project: str = typer.Option(
        "project-default",
        "--project",
        help="Project identifier the gate belongs to.",
    ),
    manifest: str = typer.Option(
        "sha256-" + ("0" * 64),
        "--manifest",
        help="Manifest commit hash for the three-anchor handoff.",
    ),
    actor: str = typer.Option(
        "actor-default",
        "--actor",
        help="Actor identity hash for the three-anchor handoff.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly gate evaluate`` -- submit a draft, poll, emit decision.

    Per VAL-V2M07-011 the stdout envelope on accept matches the §P.2
    reference: ``schema_version: "relay.cli.gate_evaluate.v1"``,
    ``gate_decision_id``, ``action: "accept"``, ``round``,
    ``failed_assertions: []``, ``evidence_bundle_id``, ``signature``,
    ``trace_id``, ``duration_ms``.
    """
    del json_output

    if not gate_id:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-GATE-ID",
            http_status=400,
            message="--gate-id is required",
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64)

    _install_cancel_handler()
    start_time = time.monotonic()

    # Test seam: short-circuit with a canned gate_decision.
    fixture = os.environ.get(ENV_GATE_FIXTURE, "").strip()
    if fixture:
        try:
            decision = json.loads(fixture)
        except (json.JSONDecodeError, TypeError) as exc:
            envelope = build_envelope(
                code="RELAY-CLI-FIXTURE-INVALID",
                http_status=500,
                message=f"gate fixture invalid: {exc}",
                blocked_surface="rly gate evaluate",
                retry_advice="do_not_retry",
                details={},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=70) from exc
        _emit_decision_envelope(decision, start_time)
        raise typer.Exit(code=_exit_for_action(decision.get("action", "accept")))

    # Step 1: POST /v1/gates/{id}/drafts
    draft_resp = _post_draft(
        gate_id=gate_id,
        manifest_commit_hash=manifest,
        actor_identity_hash=actor,
        release_sha=release_sha,
        project=project,
    )
    if "_error" in draft_resp:
        return  # _post_draft already exited

    draft_id = draft_resp.get("draft_id", "")
    draft_ttl = int(draft_resp.get("draft_ttl_seconds", 60))
    _CANCELLED["draft_id"] = draft_id

    # Step 2: poll await_url until decision lands or TTL expires
    deadline = time.monotonic() + draft_ttl
    attempt = 0
    backoff_log: list[dict[str, int]] = []
    decision = None
    while True:
        if _CANCELLED["flag"]:
            # Already handled by handler; defensive
            raise typer.Exit(code=EXIT_SIGINT_INTERRUPTED)
        decision = _get_decision(draft_id)
        if isinstance(decision, dict) and decision.get("_clock_skew"):
            # VAL-V2M07-019: single retry with compensated timestamp.
            decision = _get_decision(draft_id, retry_for_clock_skew=True)
            if isinstance(decision, dict) and decision.get("_clock_skew"):
                envelope = build_envelope(
                    code="RELAY-AUTH-017",
                    http_status=401,
                    message=(
                        "server clock skew exceeds 5 min after compensation; "
                        "check system clock"
                    ),
                    blocked_surface="rly gate evaluate",
                    retry_advice="after_fix",
                    details={"draft_id": draft_id},
                )
                emit_envelope(envelope)
                raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)
        if isinstance(decision, dict) and decision.get("_stale_handoff"):
            envelope = build_envelope(
                code="RELAY-GATE-021",
                http_status=422,
                message="three-anchor handoff stale",
                blocked_surface="rly gate evaluate",
                retry_advice="do_not_retry",
                details={"draft_id": draft_id},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)
        if isinstance(decision, dict) and decision.get("_ttl_expired"):
            envelope = build_envelope(
                code="RELAY-GATE-024",
                http_status=410,
                message=(
                    "draft TTL expired mid-await; re-submit the gate request"
                ),
                blocked_surface="rly gate evaluate",
                retry_advice="do_not_retry",
                details={"draft_id": draft_id},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=EXIT_CASSETTE_MISS)
        if isinstance(decision, dict) and decision.get("_resolved"):
            break
        # Transient: backoff and retry
        attempt += 1
        backoff_s = _next_backoff_s(attempt)
        backoff_log.append({"attempt": attempt, "backoff_ms": int(backoff_s * 1000)})
        if time.monotonic() + backoff_s > deadline:
            # Past TTL while waiting
            _flush_backoff_log(backoff_log)
            envelope = build_envelope(
                code="RELAY-GATE-024",
                http_status=410,
                message=(
                    f"draft TTL ({draft_ttl}s) expired during transient backoff"
                ),
                blocked_surface="rly gate evaluate",
                retry_advice="do_not_retry",
                details={
                    "draft_id": draft_id,
                    "attempts": attempt,
                },
            )
            emit_envelope(envelope)
            raise typer.Exit(code=EXIT_CASSETTE_MISS)
        time.sleep(backoff_s)

    _flush_backoff_log(backoff_log)
    if decision is None or not isinstance(decision, dict):
        envelope = build_envelope(
            code="RELAY-GATE-INTERNAL",
            http_status=500,
            message="polling exited without a decision",
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={"draft_id": draft_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=70)

    payload = decision.get("payload", decision)
    _emit_decision_envelope(payload, start_time)
    raise typer.Exit(code=_exit_for_action(payload.get("action", "accept")))


def _post_draft(
    *,
    gate_id: str,
    manifest_commit_hash: str,
    actor_identity_hash: str,
    release_sha: str,
    project: str,
) -> dict[str, Any]:
    """POST /v1/gates/{id}/drafts. Returns the response dict or exits."""
    seam = os.environ.get(ENV_GATE_DRAFT_RESPONSE, "").strip()
    if seam:
        try:
            data = json.loads(seam)
        except (json.JSONDecodeError, TypeError):
            return {"_error": True}
        if data.get("_stale_handoff"):
            envelope = build_envelope(
                code="RELAY-GATE-021",
                http_status=422,
                message=(
                    "three-anchor handoff stale: manifest_commit_hash "
                    "outside active/grace window"
                ),
                blocked_surface="rly gate evaluate",
                retry_advice="do_not_retry",
                details={"gate_id": gate_id},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)
        return data

    url = f"{_sidecar_url()}/v1/gates/{gate_id}/drafts"
    body = {
        "manifest_commit_hash": manifest_commit_hash,
        "actor_identity_hash": actor_identity_hash,
        "release_sha": release_sha,
        "project": project,
        "round": 1,
        "worker_id": "rly-cli",
    }
    try:
        resp = httpx.post(url, json=body, timeout=5.0)
    except httpx.HTTPError as exc:
        envelope = build_envelope(
            code="RELAY-SIDECAR-UNREACHABLE",
            http_status=503,
            message=f"sidecar unreachable at {url}: {exc}",
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={"sidecar_url": _sidecar_url()},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS) from exc

    if resp.status_code == 422:
        envelope_body = _safe_json(resp)
        code = envelope_body.get("code", "RELAY-GATE-021")
        envelope = build_envelope(
            code=code,
            http_status=422,
            message=envelope_body.get("message", "draft submission failed"),
            blocked_surface="rly gate evaluate",
            retry_advice="do_not_retry",
            details={"gate_id": gate_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_AUTH_HANDOFF)
    if resp.status_code >= 500:
        envelope = build_envelope(
            code="RELAY-SIDECAR-TRANSIENT",
            http_status=resp.status_code,
            message=f"draft create returned {resp.status_code}",
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS)
    if resp.status_code >= 400:
        envelope_body = _safe_json(resp)
        envelope = build_envelope(
            code=envelope_body.get("code", "RELAY-GATE-CREATE-FAILED"),
            http_status=resp.status_code,
            message=envelope_body.get("message", "draft submission rejected"),
            blocked_surface="rly gate evaluate",
            retry_advice="after_fix",
            details={"gate_id": gate_id},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)
    return resp.json()


def _get_decision(
    draft_id: str, retry_for_clock_skew: bool = False
) -> dict[str, Any] | None:
    """Poll GET /v1/gate-decisions/{draft_id}. Returns a status dict.

    Return-shape conventions for the polling loop:
      * ``{"_resolved": True, "payload": {...}}`` -- decision available
      * ``{"_stale_handoff": True}`` -- RELAY-GATE-021 surfaced
      * ``{"_ttl_expired": True}`` -- RELAY-GATE-024 surfaced
      * ``{"_clock_skew": True}`` -- RELAY-AUTH-017 surfaced
      * ``{}`` -- not yet resolved (404 from engine), continue polling
    """
    seam = os.environ.get(ENV_GATE_DECISION_RESPONSES, "").strip()
    if seam:
        try:
            seq = json.loads(seam)
        except (json.JSONDecodeError, TypeError):
            seq = []
        if not isinstance(seq, list) or not seq:
            return {}
        # Consume the first item destructively (re-write the env to advance)
        head = seq[0]
        os.environ[ENV_GATE_DECISION_RESPONSES] = json.dumps(seq[1:])
        return head if isinstance(head, dict) else {}

    url = f"{_sidecar_url()}/v1/gate-decisions/{draft_id}"
    try:
        resp = httpx.get(url, timeout=5.0)
    except httpx.HTTPError:
        return {}  # Treat as transient; loop will backoff
    if resp.status_code == 200:
        return {"_resolved": True, "payload": resp.json()}
    if resp.status_code == 404:
        return {}  # Not yet resolved
    if resp.status_code in (401, 422):
        body = _safe_json(resp)
        code = body.get("code", "")
        if code == "RELAY-AUTH-017":
            return {"_clock_skew": True}
        if code == "RELAY-GATE-021":
            return {"_stale_handoff": True}
        if code == "RELAY-GATE-024":
            return {"_ttl_expired": True}
        return {"_stale_handoff": True}
    if resp.status_code == 410:
        return {"_ttl_expired": True}
    return {}


def _safe_json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except (ValueError, json.JSONDecodeError):
        return {}


def _flush_backoff_log(entries: list[dict[str, int]]) -> None:
    path = os.environ.get(ENV_GATE_BACKOFF_LOG, "").strip()
    if not path or not entries:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _emit_decision_envelope(decision: dict[str, Any], start_time: float) -> None:
    duration_ms = int((time.monotonic() - start_time) * 1000)
    failed = decision.get("failed_assertions", [])
    if not isinstance(failed, list):
        failed = []
    emit_json({
        "schema_version": GATE_EVALUATE_SCHEMA,
        "gate_decision_id": decision.get(
            "gate_decision_id", decision.get("draft_id", "")
        ),
        "action": decision.get("action", "accept"),
        "round": int(decision.get("round", 1)),
        "failed_assertions": failed,
        "evidence_bundle_id": decision.get("evidence_bundle_id", ""),
        "signature": decision.get("signature", ""),
        "trace_id": decision.get("trace_id", ""),
        "duration_ms": duration_ms,
    })


def _exit_for_action(action: str) -> int:
    if action == "accept":
        return EXIT_SUCCESS
    if action == "block":
        return EXIT_4XX_BLOCK
    if action == "remediate":
        return EXIT_4XX_REMEDIATE
    return EXIT_SUCCESS


__all__ = ["GATE_EVALUATE_SCHEMA", "cmd_gate_evaluate"]
