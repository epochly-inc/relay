# `rly evidence list`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly evidence list`` -- list bundles with required binding fields.

## Usage

```
rly evidence list [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--limit` | `integer` | no | Maximum items per page (1..500; default 50). |
| `--project` | `text` | no | Optional project UUID filter. v0.1 OSS profile lists all local bundles regardless of project; the flag is accepted for forward compatibility with the hosted profile. |

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
