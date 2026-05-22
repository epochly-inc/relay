# Your First Contract

A Relay contract is a small, declarative document that says what behavior
your agent must exhibit. Each contract is a single YAML or JSON file
following one of the five schema kinds defined in spec section D.1-D.5
(behavioral, schema, gate-policy, tool-arg, eval). Behavioral and eval
assertions can express their check as a CEL string that calls Relay's
pure UDF registry. This page walks through writing a minimal behavioral
assertion, validating it locally, evaluating the gate, and reading the
exit code the CLI emits.

## What a contract is

A contract pairs an `assertion_id` with an expression that the gate
engine evaluates against trace data. The expression must be deterministic
(CLAUDE.md keystone invariant 6 and banned pattern #16) -- it can only
call UDFs registered as `pure=True`. The three UDFs that ship in v0.1
are listed in `packages/contracts/src/relay_contracts/__init__.py` in the
`RELAY_UDFS` tuple:

- `relay.coverage(trace, step_name)` -- returns `true` if a step with the
  given name appears in `trace.steps`.
- `relay.tool_arg(call, key)` -- returns the value at `call.args[key]`
  or `null` when missing.
- `relay.schema_match(payload, schema)` -- returns `true` when `payload`
  validates against the given JSON Schema.

Every assertion also carries a `schema_version`, `severity` (`p0`-`p3`),
`owner_email`, and `lifecycle_state` (`draft`, `active`, `deprecated`,
`retired`). Spec section D.6 documents the full lifecycle.

## Step 1 -- Write a minimal CEL behavioral assertion

Create a directory for your contracts (the CLI scans a whole directory,
not a single file) and drop in one YAML document:

```bash
mkdir -p ./contracts
```

```yaml
schema_version: relay.assertion.behavioral.v1
assertion_id: ASSERT-FIRST-CONTRACT-001
kind: behavioral
severity: p1
expression: "relay.coverage(trace, 'plan') && relay.coverage(trace, 'act')"
owner_email: you@example.com
lifecycle_state: active
```

Save that as `./contracts/first.yaml`. The expression uses only the
`relay.coverage` UDF from the registry above; the gate engine compiles
the CEL string through the pure-only profile in
`packages/contracts/src/relay_contracts/evaluator.py` so any attempt to
use a non-pure UDF would be rejected at publish time.

## Step 2 -- Validate locally

`rly contract check <dir>` parses every `*.yaml`, `*.yml`, and `*.json`
file under the given directory, runs the DSL validator, and evaluates
the coverage invariants from spec section D.6. The success envelope
carries `schema_version: "relay.cli.contract_check.v1"`,
`files_checked`, `assertions_total`, `coverage_valid: true`, and an
empty `violations` array (VAL-V2M07-026 in
`packages/cli/src/relay_cli/commands/contract.py`).

```bash
uv run rly contract check ./contracts
```

Exit code 0 means the document parsed, the `schema_version` is in the
allow-list, severity and lifecycle are valid, and no coverage invariant
fired. A coverage failure exits 1 with `coverage_valid: false` and a
populated `violations` array. The four coverage codes are
`RELAY-COVERAGE-001` through `RELAY-COVERAGE-004`; see
`docs/reference/errors/` for the per-code remediation pages.

## Step 3 -- Evaluate the gate

Once your contracts have been published and registered against a gate,
ask the control plane to evaluate that gate for a specific release SHA.
`rly gate evaluate` takes a required `--gate-id <UUID>` flag plus
optional `--release-sha`, `--project`, `--manifest`, and `--actor`
flags for the three-anchor handoff (spec section C.5).

```bash
uv run rly gate evaluate --gate-id 00000000-0000-0000-0000-000000000000
```

On accept the stdout envelope carries
`schema_version: "relay.cli.gate_evaluate.v1"`, `gate_decision_id`,
`action: "accept"`, `round`, `failed_assertions: []`,
`evidence_bundle_id`, `signature`, `trace_id`, and `duration_ms`
(VAL-V2M07-011). The control plane writes the canonical
`gate_decisions` row -- the CLI never does (keystone invariant 1).

## Step 4 -- Read the exit code

The CLI returns one of the canonical exit codes listed in the
`--help` JSON envelope and defined in
`packages/cli/src/relay_cli/main.py` lines 76-91:

| Exit code | Meaning |
|---:|---|
| 0 | success (2xx) |
| 1 | 4xx with action=block |
| 2 | 4xx with action=remediate |
| 3 | 4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*) |
| 4 | transient (cassette miss, RELAY-GATE-024 draft TTL expired, network partition past TTL) |
| 5 | 5xx + network transient |
| 6 | WAL/storage error (RELAY-SIDECAR-STORAGE-*) |
| 8 | LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED) |
| 64 | wrong-flag (CLI usage error) |
| 70 | uncaught internal |
| 130 | SIGINT/SIGTERM interrupted |

The same table is emitted in machine-readable form by any `rly` command
under `--help` when piped (the `exit_codes` array of the
`relay.cli.help.v1` envelope), so CI scripts can switch on the code
without screen-scraping prose.

## Next

Continue to [Your First Evidence Bundle](first-evidence-bundle.md) to
turn an accepted gate decision into a signed, offline-verifiable bundle.

Spec: §D.1
