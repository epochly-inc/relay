# Coverage Invariant

The coverage invariant is the rule that keeps a contract bundle honest:
**every active assertion has exactly one owner, and no two active assertions
collapse into the same check.** It exists in two compatible forms:

- *Contract-bundle form* -- inside the YAML/JSON documents you publish with
  `rly contract publish`, every active assertion needs exactly one
  `owner_email` (a real person, not a distribution list), and every active
  assertion must be referenced by at least one active gate. No orphans, no
  duplicate expression digests, no group aliases.
- *Operations form* -- when assertions are claimed by feature manifests
  (e.g., in `features.json` for an operation), each assertion must be the
  `primaryFulfills` of exactly one feature. `secondaryFulfills` is
  unlimited; primary ownership is unique.

Same principle either way: **no orphans, no duplicates, no anonymous
ownership.** This page documents the contract-bundle form because that is
what `rly contract publish` enforces in the OSS CLI today.

## What `rly contract publish` checks

The publish command parses every assertion in the bundle, classifies each
one as `active` (vs. `draft` / `deprecated` / `retired` per spec D.6), and
runs four invariant checks before signing or writing the coverage report.
A failure exits non-zero with a structured stderr envelope; on a clean
publish the report is written to
`${RELAY_HOME}/contract/coverage/<id>.json` and the CLI exits 0.

The four invariants, in the order the source enforces them (see
`packages/cli/src/relay_cli/commands/contract.py`):

1. **Orphan assertions** -- every active assertion must be referenced by at
   least one active gate via the bundle's `gates_assertion_ids` linkage.
2. **Duplicate expression digests** -- no two active assertions may share
   the same JCS-canonical body digest (different `assertion_id`, same
   underlying check).
3. **Missing `owner_email` on P0/P1** -- every P0 or P1 active assertion
   must carry a non-empty `owner_email`.
4. **Group-alias `owner_email`** -- the `owner_email` must be a real person,
   not a distribution-list alias (`team-*`, `noreply@*`, `support@*`, etc.).

Each violation maps to a `RELAY-COVERAGE-NNN` wire code in the canonical
error registry at `packages/schemas/raw/error-codes.yaml`.

## RELAY-COVERAGE-001 -- orphan assertion

**Trigger.** An active assertion is not referenced by any active gate.
The bundle has an assertion definition but no `gates_assertion_ids` array
in any active gate that lists its `assertion_id`. Per spec D.6 every
shipped check must have an owning gate; an orphan would never run.

**Example offending assertion** (bundle excerpt; the assertion exists, no
active gate references it):

```yaml
schema_version: relay.contract_publish_bundle.v1
manifest_commit_hash: null
assertions:
  - schema_version: relay.assertion.behavioral.v1
    assertion_id: ASSERT-PLAN-COVERAGE-001
    kind: behavioral
    severity: p1
    expression: "relay.coverage(trace, 'plan')"
    owner_email: alice@example.com
    lifecycle_state: active
gates:
  - gate_id: 00000000-0000-0000-0000-000000000001
    lifecycle_state: active
    gates_assertion_ids: []
```

**Fix.** Add the assertion id to an active gate's `gates_assertion_ids`
array, or mark the assertion `lifecycle_state: deprecated` if it is no
longer in use. Re-publish.

Reference: [RELAY-COVERAGE-001](../reference/errors/RELAY-COVERAGE-001/index.md).

## RELAY-COVERAGE-002 -- duplicate expression digest

**Trigger.** Two or more active assertions canonicalise to the same
expression body. The JCS digest computed by
`relay_contracts.dsl_parser.ParsedContract` is identical, even if the
`assertion_id` and other metadata differ. Per spec D.6 a duplicate check
inflates the coverage count without adding coverage.

**Example offending assertion** (two assertions with different ids but the
same expression):

```yaml
schema_version: relay.contract_publish_bundle.v1
assertions:
  - schema_version: relay.assertion.behavioral.v1
    assertion_id: ASSERT-PLAN-A
    kind: behavioral
    severity: p1
    expression: "relay.coverage(trace, 'plan')"
    owner_email: alice@example.com
    lifecycle_state: active
  - schema_version: relay.assertion.behavioral.v1
    assertion_id: ASSERT-PLAN-B
    kind: behavioral
    severity: p1
    expression: "relay.coverage(trace, 'plan')"
    owner_email: bob@example.com
    lifecycle_state: active
```

**Fix.** Consolidate the duplicates: keep one assertion, retire the other
via `lifecycle_state: retired`. If the two checks need to remain distinct,
rewrite one expression so it covers a genuinely different step (e.g.,
`relay.coverage(trace, 'act')` instead of `'plan'`).

Reference: [RELAY-COVERAGE-002](../reference/errors/RELAY-COVERAGE-002/index.md).

## RELAY-COVERAGE-003 -- missing `owner_email` on P0/P1

**Trigger.** A P0 or P1 active assertion has no `owner_email`, or the
field is empty. Per spec D.6 line 3886 every load-bearing assertion must
have a human owner the gate engine can page when it fails.

**Example offending assertion** (severity p0, no owner):

```yaml
schema_version: relay.assertion.behavioral.v1
assertion_id: ASSERT-CRITICAL-001
kind: behavioral
severity: p0
expression: "relay.coverage(trace, 'safety_check')"
lifecycle_state: active
```

**Fix.** Add `owner_email: <person>@<domain>`. The owner must be a single
human; P0/P1 ownership is non-shareable. For lower-severity checks
(P2/P3) the field is optional, though recommended.

Reference: [RELAY-COVERAGE-003](../reference/errors/RELAY-COVERAGE-003/index.md).

## RELAY-COVERAGE-004 -- group-alias `owner_email`

**Trigger.** The `owner_email` matches a distribution-list pattern: a
prefix like `team-`, `group-`, `dl-`, `all-`, `eng-`, `ops-`, `list-`, or
a local-part like `team`, `eng`, `ops`, `security`, `support`, `noreply`,
`no-reply`, `info`, `admin`, `contact`, `hello`, `engineering`. Per spec
D.6 the owner must be a real person; a mailbox alias defeats accountability.

**Example offending assertion** (group local-part):

```yaml
schema_version: relay.assertion.behavioral.v1
assertion_id: ASSERT-PIPELINE-001
kind: behavioral
severity: p1
expression: "relay.coverage(trace, 'pipeline')"
owner_email: team-platform@example.com
lifecycle_state: active
```

**Fix.** Replace the alias with a human address (e.g.,
`alice@example.com`). Self-hosters that need to extend the deny list
(internal naming conventions, additional aliases) can pass
`--alias-prefix <prefix>` or `--alias-local <local>` repeatedly to
`rly contract publish`; the defaults are the list the OSS distribution
ships.

Reference: [RELAY-COVERAGE-004](../reference/errors/RELAY-COVERAGE-004/index.md).

## CI behavior

`rly contract publish` exits non-zero on **any** coverage-invariant
violation. The non-zero exit holds even in `dry_run_unsigned` mode (the
fork-PR fallback documented in spec B.6 and the §AI.6 CI gate matrix):
only the signing/decision-resolution step is skipped in dry-run, never
the coverage check. A CI workflow that runs `rly contract publish` and
keys merge approval off the exit code therefore blocks any PR that
introduces an orphan, a duplicate, a missing owner, or a group-alias
owner.

The four codes also surface in the structured stderr envelope as the
`code` field, with the offending `assertion_id`s (or duplicate groups)
in `details`. A CI script that wants per-violation handling can parse
the envelope rather than relying on the exit code alone.

Spec: §D.6
