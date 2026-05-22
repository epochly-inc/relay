# `rly replay create`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly replay create --from-run <run_id>`` -- create a replay case.

Per VAL-V2M07-005 the stdout envelope carries ``schema_version: "relay.cli.replay_create.v1"``, a newly minted ``replay_case_id``, the source ``run_id``, and a ``fixture_count`` int. Backed by the M02 ``POST /v1/replay-cases`` endpoint.

Per VAL-V2M07-006 missing ``--from-run`` exits 64 with a structured usage envelope.

## Usage

```
rly replay create [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--from-run` | `text` | yes | Source run_id (UUID) to seed the replay case from. |
| `--help` | `boolean` | no | Show this message and exit. |
| `--json` | `boolean` | no | Force JSON output even on TTY. |
| `--scope-name` | `text` | no | Optional human-friendly name for the replay case. |

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
