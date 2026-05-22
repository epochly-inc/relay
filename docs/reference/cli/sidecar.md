# `rly sidecar`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Manage the local Relay sidecar: start, stop, status, restart, install. Lifecycle commands NEVER kill processes by name; PID is read from the sidecar lockfile.

## Usage

```
rly sidecar [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`install`](sidecar/install.md) | ``rly sidecar install`` -- pinned-URL install with verification. VAL-W5-015: refuses any URL not present in the pinned manifest. The CLI intentionally does NOT expose a ``--url`` flag. VAL-W5-016: Sigstore signature is verified before the bundle is moved. VAL-W5-017: SHA-256 digest is verified independently before signature. VAL-W5-018: install path is written through ``local_atomic_file_write``. |
| [`restart`](sidecar/restart.md) | ``rly sidecar restart`` -- bounded stop+start (VAL-W5-014). |
| [`start`](sidecar/start.md) | ``rly sidecar start`` -- attach if running, else spawn (VAL-W5-011). |
| [`status`](sidecar/status.md) | ``rly sidecar status`` -- four-state classifier outcome (VAL-W5-012). |
| [`stop`](sidecar/stop.md) | ``rly sidecar stop`` -- PID-only termination (VAL-W5-013). |

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
