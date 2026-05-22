# `rly sidecar stop`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly sidecar stop`` -- PID-only termination (VAL-W5-013).

## Usage

```
rly sidecar stop [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--json` | `boolean` | no | Emit a single JSON object on stdout with schema_version=relay.cli.sidecar_stop.v1 (VAL-V3M2-010). Without --json, output is the default JSON-on-pipe / human-on-TTY contract. |
| `--timeout` | `float` | no | Seconds to wait for graceful exit before SIGKILL (POSIX). |

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
