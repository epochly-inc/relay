# `rly gate evaluate`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly gate evaluate`` -- submit a draft, poll, emit decision.

Per VAL-V2M07-011 the stdout envelope on accept matches the §P.2 reference: ``schema_version: "relay.cli.gate_evaluate.v1"``, ``gate_decision_id``, ``action: "accept"``, ``round``, ``failed_assertions: []``, ``evidence_bundle_id``, ``signature``, ``trace_id``, ``duration_ms``.

## Usage

```
rly gate evaluate [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--actor` | `text` | no | Actor identity hash for the three-anchor handoff. |
| `--gate-id` | `text` | yes | Gate identifier (UUID) to evaluate. |
| `--help` | `boolean` | no | Show this message and exit. |
| `--json` | `boolean` | no | Force JSON output even on TTY. |
| `--manifest` | `text` | no | Manifest commit hash for the three-anchor handoff. |
| `--project` | `text` | no | Project identifier the gate belongs to. |
| `--release-sha` | `text` | no | Release commit SHA the gate is being evaluated against. |

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
