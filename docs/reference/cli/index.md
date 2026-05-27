# `rly`

> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.

Relay control surface (rly). Apache 2.0 CLI for the Relay agent reliability OS. JSON output by default when piped; human-readable text on a TTY. Exit codes follow the canonical Relay exit-code table (see --help for the full list).

## Usage

```
rly [OPTIONS] COMMAND [ARGS]...
```

## Options

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `--help` | `boolean` | no | Show this message and exit. |
| `--json` | `boolean` | no | Force JSON output even when stdout is a TTY. |
| `--version` | `boolean` | no | Show the rly version and exit. |

## Subcommands

| Name | Description |
| --- | --- |
| [`contract`](contract.md) | Publish and validate Relay contract definitions (CEL + UDF). The ``publish`` subcommand enforces the coverage invariant (orphan / duplicate-digest / missing-owner / group-alias-owner) and emits a signed coverage report. Forks without GITHUB_TOKEN produce a dry-run-unsigned report; coverage failures still exit non-zero in dry-run mode. |
| [`eval`](eval.md) | Run evaluation datasets through the local sidecar. The ``run`` subcommand enqueues an eval-run against POST /v1/eval-runs and emits the canonical relay.cli.eval_run.v1 envelope. |
| [`evidence`](evidence.md) | List, show, verify, and assess evidence bundles. The verifier defaults to the spec-pinned trust anchor; --trust-anchor accepts a BYO JWKS URL for forks and self-hosters and emits a structured stderr WARN when used. The ``assess`` subcommand (M07 w7-cli-evidence-assess) enqueues a readiness-profile assessment against the bundle id. |
| [`gate`](gate.md) | Evaluate a contract gate against a release/manifest. Submits a draft via POST /v1/gates/{id}/drafts, polls await_url with exponential backoff, emits the canonical relay.cli.gate_evaluate.v1 envelope on resolution. |
| [`init`](init.md) | Reserved namespace for project-init. Invoking returns RELAY-CLI-NOT-IMPLEMENTED; the project-scaffold implementation ships in a separate sub-feature. |
| [`manifest`](manifest.md) | Validate Relay manifests against the canonical manifest.v1.json schema. The ``check`` subcommand validates the body, computes command_hash digests, and emits a structured report. |
| [`replay`](replay.md) | Record and play back agent traffic. Cassette mode is the default; live mode lands in W6. Side effects are blocked without an explicit --allow-side-effects override. |
| [`sidecar`](sidecar.md) | Manage the local Relay sidecar: start, stop, status, restart, install. Lifecycle commands NEVER kill processes by name; PID is read from the sidecar lockfile. |
| [`trace`](trace.md) | ``rly trace <run_id>`` -- emit the canonical trace JSON envelope. Per VAL-V2M07-001 the envelope's ``schema_version`` is exactly ``relay.cli.trace.v1``; per VAL-V2M07-002 each span carries ``span_id``, ``parent_span_id``, ``start_time_unix_nano``, ``end_time_unix_nano``, ``name``, ``attributes``. |
| [`verify-install`](verify-install.md) | Verify the integrity and provenance of installed Relay packages. Exit 0 iff every requested check passes; non-zero with a structured error envelope on any failure. Produces a single composite JSON envelope on stdout (VAL-W12-031). Default trust anchor is the spec-pinned JWKS URL (VAL-W12-032). |
| [`verify-self`](verify-self.md) | Run every checked invariant and emit a §K-conformant evidence bundle. Exit 0 iff every invariant is green; exit 1 on any failure with a structured stderr envelope; exit 70 on internal failure (no Python traceback). Writes the bundle on every invocation (pass or fail). |

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
