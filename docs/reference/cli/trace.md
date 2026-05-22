# `rly trace`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly trace <run_id>`` -- emit the canonical trace JSON envelope.

Per VAL-V2M07-001 the envelope's ``schema_version`` is exactly ``relay.cli.trace.v1``; per VAL-V2M07-002 each span carries ``span_id``, ``parent_span_id``, ``start_time_unix_nano``, ``end_time_unix_nano``, ``name``, ``attributes``.

## Usage

```
rly trace [OPTIONS] RUN_ID
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--json` | `boolean` | no | Force JSON output even on TTY. |

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
