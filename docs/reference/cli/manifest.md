# `rly manifest`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Validate Relay manifests against the canonical manifest.v1.json schema. The ``check`` subcommand validates the body, computes command_hash digests, and emits a structured report.

## Usage

```
rly manifest [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`check`](manifest/check.md) | ``rly manifest check <path>`` -- validate + emit command_hash map. Per VAL-V2M07-023 the success envelope carries ``schema_version: "relay.cli.manifest_check.v1"``, ``manifest_path``, ``schema_id: "manifest.v1.json"``, ``valid: true``, an empty ``errors`` array, and a ``command_hash`` map (command name -> sha256 hex digest of the canonical command string). |

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
