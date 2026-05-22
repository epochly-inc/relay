# `rly replay run`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly replay run`` -- cassette playback (VAL-W5-021..024).

Per CLAUDE.md keystone invariant #1 the CLI never writes ``run_results``; the per-replay outcome is materialized as an operator-facing JSON envelope and the registry's ``last_status`` field. Canonical evidence binding is owned by the sidecar's replay- workers service, which W5.3 does not invoke (the OSS CLI's local sidecar profile uses cassette playback only).

## Usage

```
rly replay run [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--allow-side-effects` | `text` | no | Comma-separated side-effect classes to permit. Default empty: any 'mutating' or 'external_irreversible' call in the recorded fixture causes RELAY-REPLAY-014. Permitted values: 'mutating', 'external_irreversible'. Note: 'approval_required' is NOT accepted here; an approval_required fixture requires --approval-token=<token> per spec section X (audit-r3 BUG-B4). |
| `--approval-token` | `text` | no | Single-use human approval token (spec section X). Required when the recorded fixture declares an 'approval_required' side-effect class. There is no other CLI flag that bypasses this contract. |
| `--case` | `text` | yes | replay_case_id to play back (returned by `rly replay list`). |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--mode` | `text` | no | Playback mode. Only 'cassette' is supported in W5.3. |
| `--proxy/--no-proxy` | `boolean` | no | Spawn the W7.1 mitmproxy harness for this replay. When set, the CLI generates a per-session CA, allocates a free port, starts the proxy, and returns its URL + CA path in the result envelope (the agent subprocess is NOT spawned by the CLI; consumers that need that surface should call the harness library directly via relay_replay_proxy.HarnessSession). Default off. |
| `--session` | `text` | no | Override the session_id used by --proxy. Defaults to the replay case_id so cassettes recorded by 'rly replay record' are immediately usable. Cassette dir is ${RELAY_HOME}/cassettes/<session>/. |

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
