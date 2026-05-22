# `rly replay`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Record and play back agent traffic. Cassette mode is the default; live mode lands in W6. Side effects are blocked without an explicit --allow-side-effects override.

## Usage

```
rly replay [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`create`](replay/create.md) | ``rly replay create --from-run <run_id>`` -- create a replay case. Per VAL-V2M07-005 the stdout envelope carries ``schema_version: "relay.cli.replay_create.v1"``, a newly minted ``replay_case_id``, the source ``run_id``, and a ``fixture_count`` int. Backed by the M02 ``POST /v1/replay-cases`` endpoint. Per VAL-V2M07-006 missing ``--from-run`` exits 64 with a structured usage envelope. |
| [`list`](replay/list.md) | ``rly replay list`` -- paginated JSON registry (VAL-W5-019). |
| [`record`](replay/record.md) | ``rly replay record`` -- capture a run into a deterministic fixture. |
| [`run`](replay/run.md) | ``rly replay run`` -- cassette playback (VAL-W5-021..024). Per CLAUDE.md keystone invariant #1 the CLI never writes ``run_results``; the per-replay outcome is materialized as an operator-facing JSON envelope and the registry's ``last_status`` field. Canonical evidence binding is owned by the sidecar's replay- workers service, which W5.3 does not invoke (the OSS CLI's local sidecar profile uses cassette playback only). |

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
