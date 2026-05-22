# `rly verify-install`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Verify the integrity and provenance of installed Relay packages.

Exit 0 iff every requested check passes; non-zero with a structured error envelope on any failure. Produces a single composite JSON envelope on stdout (VAL-W12-031). Default trust anchor is the spec-pinned JWKS URL (VAL-W12-032).

## Usage

```
rly verify-install [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (used for the JWKS cache lookup). |
| `--json` | `boolean` | no | Force JSON output even when stdout is a TTY (default when piped). |
| `--npm` | `boolean` | no | Verify only the npm package install. |
| `--npm-record` | `text` | no | Path to the npm install record (test seam). |
| `--offline` | `boolean` | no | Offline mode: verify against the cached JWKS at ${RELAY_HOME}/jwks-cache/<host>.json and cached install records. No network egress. |
| `--print-trust-anchor` | `boolean` | no | Print the active trust anchor URL and exit 0. |
| `--python` | `boolean` | no | Verify only the Python package install. |
| `--python-record` | `text` | no | Path to the Python install record (test seam). |
| `--sidecar` | `boolean` | no | Verify only the sidecar binary install. |
| `--sidecar-record` | `text` | no | Path to the sidecar install record (test seam). |
| `--trust-anchor` | `text` | no | Override the default JWKS URL (VAL-W12-032 / CLAUDE.md keystone #11). Forks/self-hosters only; emits a structured stderr WARN. |

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
