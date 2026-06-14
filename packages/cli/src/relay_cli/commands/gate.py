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
    EXIT_UNCAUGHT_INTERNAL,
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


# Shared cancel state. ``flag`` is the async-signal-safe trip the SIGINT/
# SIGTERM handler sets; ``draft_id`` (str) and ``signum`` (int) are recorded
# so the FOREGROUND cancel path (VAL-ISO-033) can issue the cancel POST and
# emit a correctly-labelled envelope. Heterogeneous values -> typed Any.
_CANCELLED: dict[str, Any] = {"flag": False}


def _install_cancel_handler() -> None:
    """Install a SIGTERM/SIGINT handler that records cancel + exits 130.

    VAL-V2M07-017/018: on SIGTERM/SIGINT the CLI sends a best-effort
    cancel POST to the engine (if a draft_id is known) then exits 130.

    VAL-ISO-033: the handler is async-signal-safe -- it records ONLY the
    signal number and sets ``_CANCELLED['flag'] = True``. It performs NO
    network I/O (httpx connect/TLS is not async-signal-safe and can
    deadlock if the signal arrives mid-allocation or while a lock is
    held) and does NOT call ``sys.exit`` from the signal context. The
    cancel POST + RELAY-CLI-130 envelope emit + ``sys.exit`` are all
    performed by :func:`_perform_cancel_and_exit`, which the polling loop
    invokes in the FOREGROUND once it observes the flag.
    """

    def _handler(signum: int, frame: Any) -> None:
        del frame
        # Async-signal-safe: record the signal and set the flag only.
        _CANCELLED["signum"] = signum
        _CANCELLED["flag"] = True

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            continue


def _emit_gate_internal_and_exit(message: str, draft_id: str) -> None:
    """Emit the structured RELAY-GATE-INTERNAL envelope and exit 70.

    Centralizes the gate command's internal-error exit path so every
    internal-error branch (polling exited without a decision; a 200 body
    that is not a JSON object; a fixture seam carrying a non-dict body)
    emits an identical structured envelope instead of letting an
    AttributeError escape into the generic RELAY-CLI-070 wrapper. The
    code/http_status/exit code match the §P.1 internal-error contract:
    RELAY-GATE-INTERNAL -> http 500 -> exit 70 (EXIT_UNCAUGHT_INTERNAL).
    """
    envelope = build_envelope(
        code="RELAY-GATE-INTERNAL",
        http_status=500,
        message=message,
        blocked_surface="rly gate evaluate",
        retry_advice="after_fix",
        details={"draft_id": draft_id},
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_UNCAUGHT_INTERNAL)


def _perform_cancel_and_exit(signum: int | None = None) -> None:
    """Foreground cancel path: POST cancel, emit envelope, exit 130.

    Runs OUTSIDE the signal context (called from the polling loop's flag
    check), where httpx is safe. ``signum`` defaults to the value the
    handler recorded in ``_CANCELLED`` so the emitted envelope names the
    actual delivered signal.
    """
    if signum is None:
        recorded = _CANCELLED.get("signum")
        signum = recorded if isinstance(recorded, int) else signal.SIGINT
    # Best-effort cancel POST to the engine (if a draft_id is known).
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
        if not isinstance(decision, dict):
            # VAL-ISO-042: the fixture seam shares the same unguarded
            # ``.get`` hazard as the live path. A non-dict fixture body
            # (bare array/string/number/null) emits the structured
            # internal-error envelope rather than an AttributeError.
            _emit_gate_internal_and_exit(
                "gate fixture body is not a JSON object", ""
            )
        _emit_decision_and_exit(decision, start_time, "")

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
            # VAL-ISO-033: the handler set the flag only. Perform the
            # cancel POST + envelope emit + exit HERE, in the foreground,
            # where httpx is async-signal-safe.
            _perform_cancel_and_exit()
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
        if isinstance(decision, dict) and decision.get("_malformed_payload"):
            # VAL-ISO-042: a 200 whose body is not a JSON object is a
            # malformed engine response, not a valid decision. Emit the
            # structured internal-error envelope rather than dereferencing
            # ``.get`` on a non-dict payload (AttributeError -> traceback).
            _flush_backoff_log(backoff_log)
            _emit_gate_internal_and_exit(
                "engine returned a 200 with a non-object decision body",
                draft_id,
            )
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
        _emit_gate_internal_and_exit(
            "polling exited without a decision", draft_id
        )

    payload = decision.get("payload", decision)
    if not isinstance(payload, dict):
        # VAL-ISO-042 defense-in-depth: ``_get_decision`` already rejects a
        # non-dict 200 body, but guard here too so any future resolution
        # path that yields a non-dict payload emits the structured
        # internal-error envelope instead of an AttributeError traceback.
        _emit_gate_internal_and_exit(
            "resolved decision payload is not a JSON object", draft_id
        )
    _emit_decision_and_exit(payload, start_time, draft_id)


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
        (``payload`` is guaranteed to be a dict)
      * ``{"_stale_handoff": True}`` -- RELAY-GATE-021 surfaced
      * ``{"_ttl_expired": True}`` -- RELAY-GATE-024 surfaced
      * ``{"_clock_skew": True}`` -- RELAY-AUTH-017 surfaced
      * ``{"_malformed_payload": True}`` -- 200 with a non-dict/undecodable
        body; RELAY-GATE-INTERNAL surfaced (VAL-ISO-042)
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
        # The engine MUST return a JSON object (gate_decision) on 200. A
        # bare array/string/number/null body -- or an undecodable body --
        # is a malformed response, NOT a valid decision. Surface it as a
        # structured internal error so the loop emits RELAY-GATE-INTERNAL
        # rather than letting ``payload.get(...)`` raise AttributeError.
        try:
            body = resp.json()
        except (ValueError, json.JSONDecodeError):
            return {"_malformed_payload": True}
        if not isinstance(body, dict):
            return {"_malformed_payload": True}
        return {"_resolved": True, "payload": body}
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


def _exit_for_action(action: object) -> int:
    if action == "accept":
        return EXIT_SUCCESS
    if action == "block":
        return EXIT_4XX_BLOCK
    if action == "remediate":
        return EXIT_4XX_REMEDIATE
    # An unrecognized / missing / null action is a MALFORMED decision from the
    # control plane, NOT an implicit accept. Fail CLOSED: never let an unknown
    # action pass the merge gate as exit 0 (re-hunt gate-evaluate fail-open;
    # keystone #2 -- a pass without a valid decision is not a pass). Callers use
    # _emit_decision_and_exit which surfaces the structured internal-error
    # envelope; this is the defense-in-depth floor for any direct caller.
    return EXIT_UNCAUGHT_INTERNAL


# The §P.1 gate-decision action enum. Anything outside this set (or absent) is a
# malformed decision and is handled fail-closed by _emit_decision_and_exit.
_VALID_GATE_ACTIONS: frozenset[str] = frozenset({"accept", "block", "remediate"})


def _emit_decision_and_exit(
    decision: dict[str, Any], start_time: float, draft_id: str
) -> None:
    """Emit the §P.2 decision envelope and exit with the §P.1 action code.

    The single chokepoint for resolving a decision dict into a terminal outcome.
    A decision whose ``action`` is missing or not in the §P.1 enum
    {accept, block, remediate} is MALFORMED -- it must NOT be fabricated into an
    ``accept`` envelope with exit 0 (the fail-open defect, re-hunt
    gate-evaluate). Such a decision instead emits the structured
    RELAY-GATE-INTERNAL envelope and exits 70, exactly like a non-dict 200 body.
    """
    action = decision.get("action")
    # Guard the TYPE before the set-membership test: a JSON-valid but UNHASHABLE
    # action value (``[]`` / ``{}``) would otherwise raise TypeError on
    # ``in _VALID_GATE_ACTIONS`` (frozenset hashes the candidate), escaping this
    # structured fail-closed path into the generic uncaught-error handler
    # (roborev e456398). A non-string action is, by definition, not a valid
    # §P.1 action -> fail closed.
    if not isinstance(action, str) or action not in _VALID_GATE_ACTIONS:
        _emit_gate_internal_and_exit(
            f"gate decision has missing or unrecognized action: {action!r} "
            f"(expected one of {sorted(_VALID_GATE_ACTIONS)})",
            draft_id,
        )
    _emit_decision_envelope(decision, start_time)
    raise typer.Exit(code=_exit_for_action(action))


__all__ = ["GATE_EVALUATE_SCHEMA", "cmd_gate_evaluate"]
