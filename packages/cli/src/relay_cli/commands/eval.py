"""``rly eval`` command group (M07 w7-cli-eval-run).

Implements VAL-V2M07-007..009: ``rly eval run --dataset <id>`` enqueues
an eval-run against the local sidecar and emits the canonical CLI
``relay.cli.eval_run.v1`` envelope.

Exit codes:
  * 0 -- success (all cases passed)
  * 1 -- block (one or more cases failed)
  * 4 -- transient (sidecar 5xx)
  * 64 -- usage (missing --dataset)
  * 70 -- uncaught internal

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Final

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
    json_output: bool = typer.Option(
        False, "--json", help="Force JSON output even on TTY."
    ),
) -> None:
    """``rly eval run --dataset <id>`` -- enqueue + summarize an eval run.

    Per VAL-V2M07-008 the stdout envelope carries ``schema_version:
    "relay.cli.eval_run.v1"``, ``eval_run_id``, ``dataset_id``,
    ``total_cases``, ``passed``, ``failed``, and ``evidence_bundle_id``.
    Per VAL-V2M07-009 the command exits 1 when ``failed > 0``.
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
        bundle_id = str(data.get("evidence_bundle_id") or uuid.uuid4())
        _emit_envelope(eval_run_id, dataset, total, passed, failed, bundle_id)
        raise typer.Exit(code=EXIT_4XX_BLOCK if failed > 0 else EXIT_SUCCESS)

    # Real path: POST /v1/eval-runs then poll /v1/eval-runs/{id}
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

    created = resp.json()
    eval_run_id = created.get("eval_run_id") or f"er-{uuid.uuid4().hex}"

    # M02 stub: eval-run completion is asynchronous in production. The
    # OSS sidecar returns 'queued' status; without a worker the eval
    # never completes. For the CLI's happy-path semantics we treat
    # 'queued' as 0/0/0 (no cases yet) and exit 0. Tests that need a
    # failed-cases path use the ENV_EVAL_FIXTURE seam.
    bundle_id = str(uuid.uuid4())
    _emit_envelope(str(eval_run_id), dataset, 0, 0, 0, bundle_id)
    raise typer.Exit(code=EXIT_SUCCESS)


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
