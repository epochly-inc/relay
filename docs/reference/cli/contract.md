# `rly contract`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Publish and validate Relay contract definitions (CEL + UDF). The ``publish`` subcommand enforces the coverage invariant (orphan / duplicate-digest / missing-owner / group-alias-owner) and emits a signed coverage report. Forks without GITHUB_TOKEN produce a dry-run-unsigned report; coverage failures still exit non-zero in dry-run mode.

## Usage

```
rly contract [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`check`](contract/check.md) | ``rly contract check <dir>`` -- validate DSL + coverage invariants. Per VAL-V2M07-026 the success envelope carries ``schema_version: "relay.cli.contract_check.v1"``, ``files_checked``, ``assertions_total``, ``coverage_valid: true``, and an empty ``violations`` array. Per VAL-V2M07-027 a coverage failure exits 1 with ``coverage_valid: false`` and a populated ``violations`` array including at least one entry of ``type: "orphan_assertion"`` or ``type: "duplicate_primary_owner"``. |
| [`publish`](contract/publish.md) | Publish a contract bundle and emit a signed coverage report. Coverage invariants per spec D.6 + line 2303 are enforced before the report is written: * RELAY-COVERAGE-001 -- orphan assertions * RELAY-COVERAGE-002 -- duplicate expression digests * RELAY-COVERAGE-003 -- missing owner_email on P0/P1 * RELAY-COVERAGE-004 -- group-alias owner_email Any failure exits non-zero with a structured stderr envelope listing the offending ids. On a clean publish the CLI emits a ``relay.contract_publish_report.v1`` document and exit 0. VAL-W6-066: when ``GITHUB_TOKEN`` is unset the publish runs in dry- run-unsigned mode -- coverage failures still surface non-zero exit codes, only the signing step is skipped. |

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
