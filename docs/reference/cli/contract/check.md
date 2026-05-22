# `rly contract check`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly contract check <dir>`` -- validate DSL + coverage invariants.

Per VAL-V2M07-026 the success envelope carries ``schema_version: "relay.cli.contract_check.v1"``, ``files_checked``, ``assertions_total``, ``coverage_valid: true``, and an empty ``violations`` array. Per VAL-V2M07-027 a coverage failure exits 1 with ``coverage_valid: false`` and a populated ``violations`` array including at least one entry of ``type: "orphan_assertion"`` or ``type: "duplicate_primary_owner"``.

## Usage

```
rly contract check [OPTIONS] DIRECTORY
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
