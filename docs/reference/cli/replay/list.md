# `rly replay list`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly replay list`` -- paginated JSON registry (VAL-W5-019).

## Usage

```
rly replay list [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--cursor` | `text` | no | Opaque cursor returned by a previous --limit page (next_cursor). |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--limit` | `integer` | no | Maximum items per page (1..500; default 50). |

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
