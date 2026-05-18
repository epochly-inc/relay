"""``rly eval`` command group (M07 w7-cli-eval-run).

Implements VAL-V2M07-007..009: ``rly eval run --dataset <id>`` enqueues
an eval-run against the local sidecar and emits the canonical CLI
``relay.cli.eval_run.v1`` envelope.

Exit codes:
  * 0 -- success (all cases passed)
  * 1 -- block (one or more cases failed)
  * 4 -- transient (sidecar 5xx OR eval-run did not complete within
         ``--timeout``; envelope code ``RELAY-EVAL-TIMEOUT``)
  * 64 -- usage (missing --dataset)
  * 70 -- uncaught internal

Per CLAUDE.md keystone invariant #2 ("pass without evidence is not a
pass") the CLI MUST NOT fabricate an ``evidence_bundle_id`` when the
sidecar's eval-run record is still ``queued``. Prior implementation
(eval.py:167-169) synthesized ``str(uuid.uuid4())`` locally and exited
0 with ``total=passed=failed=0``; that surfaced as a P0 false-success
in the 2026-05-17 audit because downstream ``rly evidence verify
--bundle <id>`` would fail with "bundle not found". The fix polls the
sidecar for completion and either propagates the SIDECAR's bundle_id
(exit 0/1 per pass/fail) or emits ``RELAY-EVAL-TIMEOUT`` with
``evidence_bundle_id: null`` (exit 4).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Final

import httpx
import typer

from ..errors import build_envelope, emit_envelope
from ..exit_codes import (
    EXIT_4XX_BLOCK,
    EXIT_CASSETTE_MISS,
    EXIT_SUCCESS,
)
from ..output import emit_json

EVAL_RUN_SCHEMA: Final[str] = "relay.cli.eval_run.v1"
ENV_SIDECAR_URL: Final[str] = "RELAY_SIDECAR_URL"
DEFAULT_SIDECAR_URL: Final[str] = "http://127.0.0.1:8088"

# Test seam: a JSON fixture providing canned eval-run results.
# Shape: {"total_cases": N, "passed": N, "failed": N,
#         "evidence_bundle_id": "<uuid>"}
ENV_EVAL_FIXTURE: Final[str] = "RELAY_CLI_EVAL_FIXTURE"

# Test seams for the real (non-fixture) path. These let plumbing-tier
# tests exercise the sidecar POST + poll loop without spinning up a
# real sidecar process. When set:
#   * RELAY_CLI_EVAL_CREATE_RESPONSE -- JSON dict returned by the
#     POST /v1/eval-runs call (must include eval_run_id).
#   * RELAY_CLI_EVAL_POLL_RESPONSES -- JSON list of dicts; each call to
#     the polling function consumes the head of the list. An exhausted
#     list returns ``None`` (treated as transient -- continue polling).
# When unset the real httpx path is used.
ENV_EVAL_CREATE_RESPONSE: Final[str] = "RELAY_CLI_EVAL_CREATE_RESPONSE"
ENV_EVAL_POLL_RESPONSES: Final[str] = "RELAY_CLI_EVAL_POLL_RESPONSES"

# Default polling parameters. The OSS sidecar's eval-runs endpoint never
# advances past ``queued`` (no OSS worker exists), so most invocations
# in the OSS profile will hit DEFAULT_TIMEOUT_SECONDS and exit 4. The
# default is chosen to be short enough that ``rly eval run`` against the
# OSS sidecar fails fast rather than hanging the CI, but long enough
# that a hosted-profile sidecar with a real eval worker has room to
# return a completed record. Operators tune via ``--timeout``.
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
POLL_INTERVAL_SECONDS: Final[float] = 0.25

# Wire code for "eval-run did not reach a terminal state within the
# CLI's --timeout window". CLI-local (RELAY-CLI-* / RELAY-EVAL-* codes
# without -NNN suffix are CLI-local per the existing eval.py convention
# of using ``RELAY-EVAL-CREATE-FAILED`` et al.). Mapped to exit code 4
# (transient bucket) so CI runners retry per Retry-After semantics.
RELAY_EVAL_TIMEOUT: Final[str] = "RELAY-EVAL-TIMEOUT"

# Eval-run record statuses we treat as terminal for the poll loop.
# ``completed`` is the spec's success terminal; ``failed`` and
# ``accepted`` are reserved for hosted workers that produce a terminal
# state without metrics/bundle (e.g., dataset rejection). For OSS we
# only need ``completed``; anything else keeps polling until timeout.
TERMINAL_EVAL_STATUSES: Final[frozenset[str]] = frozenset({"completed"})


def _sidecar_url() -> str:
    return os.environ.get(ENV_SIDECAR_URL, DEFAULT_SIDECAR_URL).rstrip("/")


def cmd_eval_run(
    dataset: str = typer.Option(
        ...,
        "--dataset",
        help="Eval dataset id (UUID) to execute.",
    ),
    contract_id: str = typer.Option(
        "contract-default",
        "--contract-id",
        help="Contract id to evaluate against. Defaults to contract-default.",
    ),
    manifest_commit_hash: str = typer.Option(
        "sha256-" + ("0" * 64),
        "--manifest-commit-hash",
        help="Manifest commit hash for the three-anchor handoff.",
    ),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT_SECONDS,
        "--timeout",
        help=(
            "Seconds to wait for the eval-run to reach a terminal state "
            f"(default {DEFAULT_TIMEOUT_SECONDS}). On expiry the CLI "
            "exits 4 with RELAY-EVAL-TIMEOUT and emits the envelope "
            "with evidence_bundle_id=null; the eval-run record persists "
            "in the sidecar and can be polled out-of-band via "
            "GET /v1/eval-runs/<id>."
        ),
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly eval run --dataset <id>`` -- enqueue + summarize an eval run.

    Per VAL-V2M07-008 the stdout envelope carries ``schema_version:
    "relay.cli.eval_run.v1"``, ``eval_run_id``, ``dataset_id``,
    ``total_cases``, ``passed``, ``failed``, and ``evidence_bundle_id``.
    Per VAL-V2M07-009 the command exits 1 when ``failed > 0``.

    Real-path completion semantics (CLAUDE.md keystone #2):

      * POST /v1/eval-runs creates the eval-run record (status=queued)
        and returns ``eval_run_id``.
      * The CLI polls GET /v1/eval-runs/{id} every POLL_INTERVAL_SECONDS
        until ``status`` reaches one of TERMINAL_EVAL_STATUSES or until
        ``--timeout`` elapses.
      * On completion the CLI emits the SIDECAR's ``evidence.bundle_id``
        (NEVER a fabricated UUID) and exits 0 (all passed) or 1
        (failed > 0).
      * On timeout the CLI emits the envelope with
        ``evidence_bundle_id: null`` and ``total/passed/failed = 0``,
        plus a ``RELAY-EVAL-TIMEOUT`` stderr envelope, and exits 4.

    The previous OSS behavior at the queued branch synthesized
    ``str(uuid.uuid4())`` as a fake bundle id and exited 0 -- this
    misrepresented an incomplete eval as a successful one and broke
    every downstream consumer that tried to ``rly evidence verify
    --bundle <fabricated-id>`` (bundle not found). Fixed per the
    2026-05-17 audit.
    """
    del json_output

    if not dataset:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-DATASET",
            http_status=400,
            message="--dataset is required",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64)

    if timeout <= 0:
        envelope = build_envelope(
            code="RELAY-CLI-USAGE-TIMEOUT",
            http_status=400,
            message=f"--timeout must be > 0; got {timeout}",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"timeout": timeout},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=64)

    # Test seam: pre-canned results
    fixture = os.environ.get(ENV_EVAL_FIXTURE, "").strip()
    if fixture:
        try:
            data = json.loads(fixture)
        except (json.JSONDecodeError, TypeError) as exc:
            envelope = build_envelope(
                code="RELAY-CLI-FIXTURE-INVALID",
                http_status=500,
                message=f"eval fixture invalid: {exc}",
                blocked_surface="rly eval run",
                retry_advice="do_not_retry",
                details={},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=70) from exc
        eval_run_id = str(data.get("eval_run_id") or f"er-{uuid.uuid4().hex}")
        total = int(data.get("total_cases", 0))
        passed = int(data.get("passed", 0))
        failed = int(data.get("failed", 0))
        # Fixture seam: an explicit evidence_bundle_id in the fixture is
        # the SIDECAR's stand-in. If the fixture does not provide one,
        # the fixture itself is malformed (callers MUST supply a real
        # id) -- we fall back to a deterministic ``er-<run>-bundle``
        # placeholder so the fixture path stays self-contained for
        # downstream tests, but the real (non-fixture) path NEVER
        # fabricates.
        raw_bundle = data.get("evidence_bundle_id")
        bundle_id = str(raw_bundle) if raw_bundle else f"{eval_run_id}-bundle"
        _emit_envelope(eval_run_id, dataset, total, passed, failed, bundle_id)
        raise typer.Exit(code=EXIT_4XX_BLOCK if failed > 0 else EXIT_SUCCESS)

    # Real path: POST /v1/eval-runs then poll /v1/eval-runs/{id}
    create_resp = _create_eval_run(
        dataset=dataset,
        contract_id=contract_id,
        manifest_commit_hash=manifest_commit_hash,
    )
    eval_run_id = str(create_resp.get("eval_run_id") or "")
    if not eval_run_id:
        envelope = build_envelope(
            code="RELAY-EVAL-CREATE-FAILED",
            http_status=502,
            message="sidecar create response missing eval_run_id",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"dataset_id": dataset, "response": create_resp},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    # Poll until terminal or timeout. The deadline uses time.monotonic()
    # so wall-clock skew doesn't compromise the bound.
    deadline = time.monotonic() + timeout
    last_record: dict[str, Any] = {}
    while True:
        record = _poll_eval_run(eval_run_id)
        if record is not None:
            last_record = record
            status = str(record.get("status", ""))
            if status in TERMINAL_EVAL_STATUSES:
                metrics = record.get("metrics") or {}
                evidence = record.get("evidence") or {}
                bundle_id = evidence.get("bundle_id")
                if not bundle_id:
                    # Terminal status without a bundle id is a sidecar
                    # protocol violation. Surface it rather than fabricate.
                    envelope = build_envelope(
                        code="RELAY-EVAL-CREATE-FAILED",
                        http_status=502,
                        message=(
                            "sidecar reported terminal eval-run status "
                            f"{status!r} but no evidence.bundle_id; refusing "
                            "to fabricate. CLAUDE.md keystone #2."
                        ),
                        blocked_surface="rly eval run",
                        retry_advice="do_not_retry",
                        details={
                            "eval_run_id": eval_run_id,
                            "status": status,
                        },
                    )
                    emit_envelope(envelope)
                    raise typer.Exit(code=EXIT_4XX_BLOCK)
                total = int(metrics.get("total_cases", 0))
                passed = int(metrics.get("passed", 0))
                failed = int(metrics.get("failed", 0))
                _emit_envelope(
                    eval_run_id, dataset, total, passed, failed,
                    str(bundle_id),
                )
                raise typer.Exit(
                    code=EXIT_4XX_BLOCK if failed > 0 else EXIT_SUCCESS
                )
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    # Timeout path: emit envelope with explicit null bundle id and
    # zero counts, plus a RELAY-EVAL-TIMEOUT envelope on stderr. Exit 4
    # (transient bucket) so CI runners retry per Retry-After semantics.
    last_status = str(last_record.get("status", "unknown")) if last_record else "unknown"
    emit_json({
        "schema_version": EVAL_RUN_SCHEMA,
        "eval_run_id": eval_run_id,
        "dataset_id": dataset,
        "total_cases": 0,
        "passed": 0,
        "failed": 0,
        "evidence_bundle_id": None,
    })
    envelope = build_envelope(
        code=RELAY_EVAL_TIMEOUT,
        http_status=504,
        message=(
            f"eval-run {eval_run_id!r} did not reach a terminal state "
            f"within --timeout={timeout}s (last observed status: "
            f"{last_status!r}). The eval-run record persists in the "
            "sidecar; poll GET /v1/eval-runs/<id> out-of-band to retrieve "
            "the result when the worker completes."
        ),
        blocked_surface="rly eval run",
        retry_advice="after_retry_after",
        details={
            "eval_run_id": eval_run_id,
            "dataset_id": dataset,
            "timeout_seconds": timeout,
            "last_observed_status": last_status,
        },
    )
    emit_envelope(envelope)
    raise typer.Exit(code=EXIT_CASSETTE_MISS)


def _create_eval_run(
    *,
    dataset: str,
    contract_id: str,
    manifest_commit_hash: str,
) -> dict[str, Any]:
    """Create an eval-run record. Returns the parsed sidecar response.

    On any error path this function emits the appropriate stderr
    envelope and raises ``typer.Exit`` directly -- callers can assume
    a return value implies success and the result dict has structure.

    Honors the ``RELAY_CLI_EVAL_CREATE_RESPONSE`` test seam: when set
    the env value is parsed as JSON and returned without an HTTP call.
    """
    seam = os.environ.get(ENV_EVAL_CREATE_RESPONSE, "").strip()
    if seam:
        try:
            parsed = json.loads(seam)
        except (json.JSONDecodeError, TypeError) as exc:
            envelope = build_envelope(
                code="RELAY-CLI-FIXTURE-INVALID",
                http_status=500,
                message=(
                    f"{ENV_EVAL_CREATE_RESPONSE} is not valid JSON: {exc}"
                ),
                blocked_surface="rly eval run",
                retry_advice="do_not_retry",
                details={},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=70) from exc
        if not isinstance(parsed, dict):
            envelope = build_envelope(
                code="RELAY-CLI-FIXTURE-INVALID",
                http_status=500,
                message=(
                    f"{ENV_EVAL_CREATE_RESPONSE} must be a JSON object"
                ),
                blocked_surface="rly eval run",
                retry_advice="do_not_retry",
                details={},
            )
            emit_envelope(envelope)
            raise typer.Exit(code=70)
        return parsed

    url = f"{_sidecar_url()}/v1/eval-runs"
    body = {
        "dataset_id": dataset,
        "contract_id": contract_id,
        "manifest_commit_hash": manifest_commit_hash,
    }
    try:
        resp = httpx.post(url, json=body, timeout=5.0)
    except httpx.HTTPError as exc:
        envelope = build_envelope(
            code="RELAY-SIDECAR-UNREACHABLE",
            http_status=503,
            message=f"sidecar unreachable at {url}: {exc}",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"sidecar_url": _sidecar_url()},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS) from exc

    if resp.status_code >= 500:
        envelope = build_envelope(
            code="RELAY-SIDECAR-TRANSIENT",
            http_status=resp.status_code,
            message=f"sidecar returned {resp.status_code}",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_CASSETTE_MISS)
    if resp.status_code >= 400:
        body_raw = resp.text
        envelope = build_envelope(
            code="RELAY-EVAL-CREATE-FAILED",
            http_status=resp.status_code,
            message=f"create eval-run failed: {body_raw[:200]}",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"dataset_id": dataset},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)

    try:
        parsed = resp.json()
    except (json.JSONDecodeError, ValueError) as exc:
        envelope = build_envelope(
            code="RELAY-EVAL-CREATE-FAILED",
            http_status=502,
            message=f"sidecar create response not JSON: {exc}",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"dataset_id": dataset},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK) from exc

    if not isinstance(parsed, dict):
        envelope = build_envelope(
            code="RELAY-EVAL-CREATE-FAILED",
            http_status=502,
            message="sidecar create response is not a JSON object",
            blocked_surface="rly eval run",
            retry_advice="after_fix",
            details={"dataset_id": dataset},
        )
        emit_envelope(envelope)
        raise typer.Exit(code=EXIT_4XX_BLOCK)
    return parsed


def _poll_eval_run(eval_run_id: str) -> dict[str, Any] | None:
    """Single GET /v1/eval-runs/<id> poll.

    Returns the parsed eval-run record on 200, ``None`` on transient
    error (caller should backoff and retry). Does NOT raise on HTTP
    errors -- the polling loop owns the deadline.

    Honors the ``RELAY_CLI_EVAL_POLL_RESPONSES`` test seam: when set
    the env value is parsed as a JSON list; each call destructively
    consumes the head. An exhausted list returns ``None``.
    """
    seam = os.environ.get(ENV_EVAL_POLL_RESPONSES, "").strip()
    if seam:
        try:
            seq = json.loads(seam)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(seq, list) or not seq:
            return None
        head = seq[0]
        # Re-write env to advance the queue for the next poll.
        os.environ[ENV_EVAL_POLL_RESPONSES] = json.dumps(seq[1:])
        return head if isinstance(head, dict) else None

    url = f"{_sidecar_url()}/v1/eval-runs/{eval_run_id}"
    try:
        resp = httpx.get(url, timeout=5.0)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        parsed = resp.json()
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _emit_envelope(
    eval_run_id: str,
    dataset_id: str,
    total: int,
    passed: int,
    failed: int,
    bundle_id: str,
) -> None:
    emit_json({
        "schema_version": EVAL_RUN_SCHEMA,
        "eval_run_id": eval_run_id,
        "dataset_id": dataset_id,
        "total_cases": int(total),
        "passed": int(passed),
        "failed": int(failed),
        "evidence_bundle_id": bundle_id,
    })


__all__ = ["EVAL_RUN_SCHEMA", "cmd_eval_run"]
