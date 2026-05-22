# `rly evidence`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

List, show, verify, and assess evidence bundles. The verifier defaults to the spec-pinned trust anchor; --trust-anchor accepts a BYO JWKS URL for forks and self-hosters and emits a structured stderr WARN when used. The ``assess`` subcommand (M07 w7-cli-evidence-assess) enqueues a readiness-profile assessment against the bundle id.

## Usage

```
rly evidence [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`assess`](evidence/assess.md) | ``rly evidence assess --bundle <id>`` -- bundle-existence preflight. Per VAL-V2M07-021 the stdout envelope carries ``schema_version: "relay.cli.evidence_assess.v1"``, ``assessment_id``, ``bundle_id``, ``readiness_profile``, ``enqueued_at``, and ``status``. Behavior (OSS v0.2): * If the bundle is not found under ``${RELAY_HOME}/evidence/<id>.json`` the CLI emits ``RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND`` on stderr and exits with EXIT_4XX_BLOCK (1). No assess envelope is emitted because there is no backing artifact to assess. * If the bundle exists the CLI emits the assess envelope with ``assessment_id: null`` and ``status: "hosted_only_pending"``, accompanied by a ``RELAY-CLI-HOSTED-ONLY`` stderr envelope, and exits EXIT_4XX_BLOCK (1). This signals: the request reached a well-formed bundle but the OSS sidecar has no assessment worker to enqueue against; operators must point at hosted Relay to complete the assessment. This shape preserves the canonical CLI envelope contract (so a CI runner sees a parseable stdout record) while making the absence of a backing hosted assessment explicit (``assessment_id`` null, non-zero exit). The previous OSS behavior fabricated a UUID and exited 0; that violated CLAUDE.md keystone #2 ("pass without evidence is not a pass") and was a P0 bug surfaced by the 2026-05-17 audit. |
| [`list`](evidence/list.md) | ``rly evidence list`` -- list bundles with required binding fields. |
| [`show`](evidence/show.md) | ``rly evidence show <id>`` -- emit the full bundle JSON. |
| [`verify`](evidence/verify.md) | ``rly evidence verify`` -- offline JWS verification. Per VAL-W5-027 verification MUST work fully offline given a populated JWKS cache. No outbound network call is attempted at any point in this command; if the JWKS is not cached the CLI exits with ``RELAY-CLI-EVIDENCE-NO-JWKS-CACHE`` and instructs the operator to pre-fetch the JWKS. Per VAL-W5-028 a single-byte mutation of the bundle MUST cause a non-zero exit with stderr envelope ``RELAY-EVID-014`` and stdout JSON ``digest_ok=false, signatures_ok=false``. Per VAL-W5-029 the ``--trust-anchor`` flag accepts a BYO JWKS URL and emits a structured stderr WARN line; the stdout JSON includes ``trust_anchor_overridden=true`` and the provided URL. Per VAL-W5-030 the default trust anchor (no flag) is the canonical spec-pinned URL declared in :data:`DEFAULT_TRUST_ANCHOR_URL`; that constant is the SINGLE source of truth for the URL string in this package (CI grep guard enforces uniqueness). |

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
