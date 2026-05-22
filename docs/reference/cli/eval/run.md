# `rly eval run`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly eval run --dataset <id>`` -- enqueue + summarize an eval run.

Per VAL-V2M07-008 the stdout envelope carries ``schema_version: "relay.cli.eval_run.v1"``, ``eval_run_id``, ``dataset_id``, ``total_cases``, ``passed``, ``failed``, and ``evidence_bundle_id``. Per VAL-V2M07-009 the command exits 1 when ``failed > 0``.

Real-path completion semantics (CLAUDE.md keystone #2):

* POST /v1/eval-runs creates the eval-run record (status=queued) and returns ``eval_run_id``. * The CLI polls GET /v1/eval-runs/{id} every POLL_INTERVAL_SECONDS until ``status`` reaches one of TERMINAL_EVAL_STATUSES or until ``--timeout`` elapses. * On completion the CLI emits the SIDECAR's ``evidence.bundle_id`` (NEVER a fabricated UUID) and exits 0 (all passed) or 1 (failed > 0). * On timeout the CLI emits the envelope with ``evidence_bundle_id: null`` and ``total/passed/failed = 0``, plus a ``RELAY-EVAL-TIMEOUT`` stderr envelope, and exits 4.

The previous OSS behavior at the queued branch synthesized ``str(uuid.uuid4())`` as a fake bundle id and exited 0 -- this misrepresented an incomplete eval as a successful one and broke every downstream consumer that tried to ``rly evidence verify --bundle <fabricated-id>`` (bundle not found). Fixed per the 2026-05-17 audit.

## Usage

```
rly eval run [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--contract-id` | `text` | no | Contract id to evaluate against. Defaults to contract-default. |
| `--dataset` | `text` | yes | Eval dataset id (UUID) to execute. |
| `--help` | `boolean` | no | Show this message and exit. |
| `--json` | `boolean` | no | Force JSON output even on TTY. |
| `--manifest-commit-hash` | `text` | no | Manifest commit hash for the three-anchor handoff. |
| `--timeout` | `float` | no | Seconds to wait for the eval-run to reach a terminal state (default 30.0). On expiry the CLI exits 4 with RELAY-EVAL-TIMEOUT and emits the envelope with evidence_bundle_id=null; the eval-run record persists in the sidecar and can be polled out-of-band via GET /v1/eval-runs/<id>. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success (2xx) |
| `1` | 4xx with action=block |
| `2` | 4xx with action=remediate |
| `3` | 4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*) |
| `4` | transient (cassette miss, RELAY-GATE-024 draft TTL expired, network partition past TTL) |
| `5` | 5xx + network transient |
| `6` | WAL/storage error (RELAY-SIDECAR-STORAGE-*) |
| `8` | LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED) |
| `64` | wrong-flag (CLI usage error) |
| `70` | uncaught internal |
| `130` | SIGINT/SIGTERM interrupted |

---

Source: `packages/cli/src/relay_cli/main.py`

Spec: VAL-DOCS-M1-008
