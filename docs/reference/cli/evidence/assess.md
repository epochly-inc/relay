# `rly evidence assess`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly evidence assess --bundle <id>`` -- bundle-existence preflight.

Per VAL-V2M07-021 the stdout envelope carries ``schema_version: "relay.cli.evidence_assess.v1"``, ``assessment_id``, ``bundle_id``, ``readiness_profile``, ``enqueued_at``, and ``status``.

Behavior (OSS v0.2):

* If the bundle is not found under ``${RELAY_HOME}/evidence/<id>.json`` the CLI emits ``RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND`` on stderr and exits with EXIT_4XX_BLOCK (1). No assess envelope is emitted because there is no backing artifact to assess. * If the bundle exists the CLI emits the assess envelope with ``assessment_id: null`` and ``status: "hosted_only_pending"``, accompanied by a ``RELAY-CLI-HOSTED-ONLY`` stderr envelope, and exits EXIT_4XX_BLOCK (1). This signals: the request reached a well-formed bundle but the OSS sidecar has no assessment worker to enqueue against; operators must point at hosted Relay to complete the assessment.

This shape preserves the canonical CLI envelope contract (so a CI runner sees a parseable stdout record) while making the absence of a backing hosted assessment explicit (``assessment_id`` null, non-zero exit). The previous OSS behavior fabricated a UUID and exited 0; that violated CLAUDE.md keystone #2 ("pass without evidence is not a pass") and was a P0 bug surfaced by the 2026-05-17 audit.

## Usage

```
rly evidence assess [OPTIONS]
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--bundle` | `text` | yes | Evidence bundle id (UUID) to assess. |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--json` | `boolean` | no | Force JSON output even on TTY. |
| `--readiness-profile` | `text` | no | Readiness profile to assess against (e.g., 'eu-ai-act', 'nist-ai-rmf'). Hosted-only in OSS v0.2: the OSS sidecar does not implement the assessment worker (lives in the hosted Relay runtime). The OSS CLI verifies the bundle exists locally and emits a hosted-only envelope. |

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
