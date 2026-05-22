# `rly contract publish`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Publish a contract bundle and emit a signed coverage report.

Coverage invariants per spec D.6 + line 2303 are enforced before the report is written:

* RELAY-COVERAGE-001 -- orphan assertions * RELAY-COVERAGE-002 -- duplicate expression digests * RELAY-COVERAGE-003 -- missing owner_email on P0/P1 * RELAY-COVERAGE-004 -- group-alias owner_email

Any failure exits non-zero with a structured stderr envelope listing the offending ids. On a clean publish the CLI emits a ``relay.contract_publish_report.v1`` document and exit 0.

VAL-W6-066: when ``GITHUB_TOKEN`` is unset the publish runs in dry- run-unsigned mode -- coverage failures still surface non-zero exit codes, only the signing step is skipped.

## Usage

```
rly contract publish [OPTIONS] BUNDLE
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--alias-local` | `text` | no | Additional group-alias local-part exact-match to deny (repeatable). |
| `--alias-prefix` | `text` | no | Additional group-alias local-part prefix to deny (repeatable). |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME for the report write path and JWKS cache. |
| `--metadata-generated-at` | `text` | no | Test seam: pin metadata.generated_at for deterministic byte tests. |
| `--metadata-report-id` | `text` | no | Test seam: pin metadata.report_id for deterministic byte tests. |
| `--out` | `text` | no | Override the on-disk report path; defaults to ${RELAY_HOME}/contract/coverage/<id>.json. |

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
