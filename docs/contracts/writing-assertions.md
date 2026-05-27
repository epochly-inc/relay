# Writing Assertions

## What an assertion is

A Relay assertion declares what a run MUST satisfy for the gate engine to
let it through. Each assertion has a stable id, a CEL expression that
evaluates to `true` or `false` against a run trace, a human owner, and a
severity tier. The `rly contract check` command parses the assertion,
verifies the envelope shape against the `relay.assertion.behavioral.v1`
schema, and runs the coverage invariants from spec section D.6: every
active assertion must be referenced by at least one active gate, no two
active assertions may share a CEL expression digest, and every P0 or P1
active assertion must declare a non-empty, non-group-alias
`owner_email`.

## Anatomy of an assertion (YAML)

A behavioral assertion is a YAML mapping with this shape (required
fields per `packages/contracts/src/relay_contracts/dsl_parser.py`
`_REQUIRED_FIELDS["relay.assertion.behavioral.v1"]`):

```yaml
schema_version: relay.assertion.behavioral.v1
assertion_id: VAL-EXAMPLE-001
kind: behavioral
severity: p1
expression: "<CEL expression string>"
owner_email: someone@example.com
lifecycle_state: active
```

| Field             | Type   | Constraint                                                                                                                |
|-------------------|--------|----------------------------------------------------------------------------------------------------------------------------|
| `schema_version`  | string | Must be `relay.assertion.behavioral.v1`. Engines refuse unknown versions on write.                                         |
| `assertion_id`    | string | Stable identifier you cite in evidence (e.g., `VAL-EXAMPLE-001`).                                                          |
| `kind`            | string | `behavioral` for this schema.                                                                                              |
| `severity`        | string | One of `p0`, `p1`, `p2`, `p3` (lowercase).                                                                                 |
| `expression`      | string | A CEL expression that evaluates to `bool`. See the CEL primer.                                                             |
| `owner_email`     | string | Single human owner. Group aliases like `team-foo@...`, `eng@...`, `noreply@...` are rejected by `RELAY-COVERAGE-004`.      |
| `lifecycle_state` | string | One of `draft`, `active`, `deprecated`, `retired`.                                                                         |

## Step 1: write the CEL expression

Start narrow. The shortest useful assertion checks that a named step ran
in the trace. The UDF `relay.coverage(trace, step_name)` is registered
in `packages/contracts/src/relay_contracts/__init__.py` (`RELAY_UDFS`)
with `pure=True` and arity 2; it returns `true` when `trace.steps`
contains an entry whose `name` equals `step_name`, `false` otherwise.

```cel
relay.coverage(trace, "plan_tools")
```

This expression reads `trace.steps`, scans for `{"name": "plan_tools"}`,
and returns a boolean. It never raises, even on partial traces. See
[CEL Primer](cel-primer.md) and [UDF Reference](udf-reference.md) for
the full surface (`relay.coverage`, `relay.tool_arg`,
`relay.schema_match`).

## Step 2: add owner and severity

Every assertion needs exactly one human owner. The publish flow rejects
P0 or P1 assertions with an absent, empty, or group-alias
`owner_email` (`RELAY-COVERAGE-003` / `RELAY-COVERAGE-004`). Use a
mailbox a real person reads, not a shared alias. The owner is
contacted when the assertion fails in production, when the assertion
is up for quarterly review, and when an auditor asks who attests to
the behavior. A `noreply@`-style mailbox cannot satisfy any of those
roles, which is why the publish flow blocks it at submit time.

Pick the severity that matches the spec section S placement of the
behavior you are pinning. P0 is reserved for invariants whose
violation blocks release; P1 is a strong default for behavioral
assertions on shipping features; P2 is for non-blocking drift
checks; P3 is informational.

## Step 3: write the gate policy that covers it

An assertion is an orphan (`RELAY-COVERAGE-001`) until at least one
active gate policy lists its `assertion_id` in `gates_assertion_ids`.
The minimal gate policy looks like this:

```yaml
schema_version: relay.gate_policy.v1
policy_version: "2026-05-22.001"
conditions:
  - id: behavioral_pass_rate
    metric: behavioral.outcome.pass_rate
    comparator: gte
    value: 1.0
    scope: eval_dataset:smoke
owner_email: someone@example.com
lifecycle_state: active
gates_assertion_ids:
  - VAL-EXAMPLE-001
```

The `gates_assertion_ids` array is the explicit linkage between the
gate policy and the assertions it covers. A gate covers an assertion
when both are `lifecycle_state: active` and the gate lists the
assertion id.

Note: this YAML is a `relay.gate_policy.v1` document, not a Relay
runtime manifest. The runtime Manifest (`relay.manifest.v1`,
`packages/schemas/catalogs/manifest.v1.schema.json`) declares
services, commands, and validation surfaces — see the [Manifest
binding guide](manifest-binding.md) for that surface. The gate policy
above is what `rly contract check` and `rly contract publish` operate
on.

The sibling files [`_examples/assertion-example.yaml`](_examples/assertion-example.yaml)
and [`_examples/manifest-example.yaml`](_examples/manifest-example.yaml)
are the verbatim pair this tutorial validates against in step 4.

## Step 4: validate locally

Put the assertion and the gate policy in a directory and run
`rly contract check <directory>`. The command scans the directory for
`*.yaml`, `*.yml`, and `*.json`, parses each via the contract DSL
parser, and evaluates the coverage invariants. The command exists for
exactly this loop — local-first validation with no network calls and
no signing. The `--help` envelope is the source of truth for the
flags.

```bash
rly contract check docs/contracts/_examples
```

On a clean pair (matching the sibling example files) the command exits
0 and emits a single line of JSON to stdout. On a coverage failure it
exits 1 and emits a `violations` array describing each offending
assertion. Re-run after fixing each violation; the loop is fast
because nothing leaves your laptop.

The `publish` subcommand (`rly contract publish <bundle.json>`) is
the production path: it consumes a `relay.contract_publish_bundle.v1`
JSON document and emits a signed coverage report. When `GITHUB_TOKEN`
is unset the publish runs in `dry_run_unsigned` mode — coverage
failures still surface non-zero exit codes; only the signing step is
skipped. Run `rly contract publish --help` for the full flag list.

## Step 5: read the result

`rly contract check` emits a `relay.cli.contract_check.v1` envelope on
stdout. The clean-publish shape is:

```json
{
  "schema_version": "relay.cli.contract_check.v1",
  "directory": "docs/contracts/_examples",
  "files_checked": 2,
  "assertions_total": 1,
  "gates_total": 1,
  "coverage_valid": true,
  "violations": []
}
```

A failure carries `coverage_valid: false` and a populated
`violations` array. Each violation entry names the offending
`assertion_id` (or gate `policy_version`) and the canonical
`RELAY-COVERAGE-NNN` code. See the
[Coverage invariant guide](coverage-invariant.md) for the full
trigger-and-fix table for every `RELAY-COVERAGE-NNN` code.

The `publish` subcommand emits a different schema
(`relay.contract_publish_report.v1`) on success, written to
`${RELAY_HOME}/contract/coverage/<report_id>.json` via the
`local_atomic_file_write` primitive. That file is byte-deterministic
for the same bundle input (after stripping wall-clock metadata) —
the determinism token surfaces in the report's
`deterministic_digest` field.

---

Spec: §D, §D.6
