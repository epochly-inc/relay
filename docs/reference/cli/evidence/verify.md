# `rly evidence verify`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

``rly evidence verify`` -- offline JWS verification.

Per VAL-W5-027 verification MUST work fully offline given a populated JWKS cache. No outbound network call is attempted at any point in this command; if the JWKS is not cached the CLI exits with ``RELAY-CLI-EVIDENCE-NO-JWKS-CACHE`` and instructs the operator to pre-fetch the JWKS.

Per VAL-W5-028 a single-byte mutation of the bundle MUST cause a non-zero exit with stderr envelope ``RELAY-EVID-014`` and stdout JSON ``digest_ok=false, signatures_ok=false``.

Per VAL-W5-029 the ``--trust-anchor`` flag accepts a BYO JWKS URL and emits a structured stderr WARN line; the stdout JSON includes ``trust_anchor_overridden=true`` and the provided URL.

Per VAL-W5-030 the default trust anchor (no flag) is the canonical spec-pinned URL declared in :data:`DEFAULT_TRUST_ANCHOR_URL`; that constant is the SINGLE source of truth for the URL string in this package (CI grep guard enforces uniqueness).

## Usage

```
rly evidence verify [OPTIONS] BUNDLE
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--home` | `text` | no | Override RELAY_HOME (test seam). |
| `--trust-anchor` | `text` | no | Override the spec-pinned default JWKS URL with a BYO trust anchor (forks / self-hosters per spec section AO.4). Emits a structured stderr WARN line when used. |

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
