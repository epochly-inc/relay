# `rly sidecar install`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly sidecar install`` -- pinned-URL install with verification.

VAL-W5-015: refuses any URL not present in the pinned manifest. The CLI intentionally does NOT expose a ``--url`` flag. VAL-W5-016: Sigstore signature is verified before the bundle is moved. VAL-W5-017: SHA-256 digest is verified independently before signature. VAL-W5-018: install path is written through ``local_atomic_file_write``.

## Usage

```
rly sidecar install [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--manifest` | `text` | no | Override the pinned manifest path (test seam). Production uses packages/cli/src/sidecar_install/bundle_manifest.json. |

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
