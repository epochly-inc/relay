# `rly verify-self`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Run every checked invariant and emit a §K-conformant evidence bundle.

Exit 0 iff every invariant is green; exit 1 on any failure with a structured stderr envelope; exit 70 on internal failure (no Python traceback). Writes the bundle on every invocation (pass or fail).

## Usage

```
rly verify-self [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME for the evidence bundle write path. |
| `--json` | `boolean` | no | Force JSON output even when stdout is a TTY. |
| `--repo-root` | `text` | no | Override the repo-root directory scanned by the verifier. |

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
