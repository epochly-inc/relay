# How to Integrate Relay with GitHub Actions CI

This guide wires Relay into GitHub Actions as a required pull-request
check. After the workflow lands, every PR runs `rly contract publish`
to refresh the coverage report and `rly gate evaluate` to produce a
canonical `gate_decision` the branch-protection rule can require before
merge. Fork PRs that do not have access to repository secrets fall
back to a `dry_run_unsigned` draft so contributors can still see
assertion results without ever producing a canonical decision.

The getting-started page
[Add Relay to your CI](../getting-started/ci-integration.md) is the
30-second starter; this page is the production-grade reference --
token model, branch protection, fork fallback, decision post-back,
and troubleshooting. The full sample workflow lives at
[`_examples/relay-gate.yml`](./_examples/relay-gate.yml) and lints
clean with `actionlint`.

## Goal

After completing this guide:

- Every PR to `main` runs `rly contract publish` then
  `rly gate evaluate` against your project's gate.
- The job exit code is the gate's exit code, so branch protection
  on the `gate-evaluate: required check` job blocks merge until the
  gate decides `accept`.
- Forked PRs (no `RELAY_CI_TOKEN`) run the same workflow in
  `dry_run_unsigned` mode per spec section B.6: the CLI exits 0 and
  the contributor sees assertion results, but no canonical
  `gate_decision` is written. Branch protection that requires the
  gate decision blocks the fork PR from merging -- intentional.
- The hosted Relay control plane posts the canonical decision back
  to the PR as a check via webhook; this guide documents the
  contract so you can build an equivalent post-back step against a
  self-hosted control plane.

## Prerequisites

- A Relay project already provisioned. Project provisioning is a
  hosted Relay surface; the `project_key` referenced below is created
  through the hosted control plane (or by direct sidecar insertion
  for local development).
- A gate already configured for the project. The gate's UUID is the
  value you pass via `--gate-id` (see `rly gate evaluate --help`).
- A contract bundle in the repository. The path is the positional
  `BUNDLE` argument to `rly contract publish` (see
  `rly contract publish --help`).
- A project-scoped CI token (see "Token model" below) stored as a
  GitHub Actions repository secret named `RELAY_CI_TOKEN`.

## Token model

Relay CI tokens are project-scoped, not user-scoped. A project-scoped
token can:

- Submit contract coverage reports via `rly contract publish`.
- Submit gate drafts via `rly gate evaluate`.
- Read gate-decision history for the bound project.

A project-scoped token cannot:

- Cross project boundaries (cross-org reads are denied at the
  control-plane layer; see CLAUDE.md keystone invariants).
- Mutate redaction policies (those require an org-admin scope).
- Issue evidence-bundle signing requests (signing lives in the
  hosted plane and is gated on `evidence:sign` scope).

Mint the token from your hosted Relay dashboard or, for self-hosted
control planes, via the admin CLI. Once you have the token value,
store it as a GitHub Actions secret:

```bash
gh secret set RELAY_CI_TOKEN --body "rly_ci_..."
```

You will also want two repository variables (not secrets, since they
are not sensitive):

```bash
gh variable set RELAY_GATE_ID --body "00000000-0000-0000-0000-000000000000"
gh variable set RELAY_PROJECT_ID --body "your-project-id"
gh variable set RELAY_CONTRACT_BUNDLE --body "contracts/my-contract.json"
```

## The workflow

Drop the following file at `.github/workflows/relay-gate.yml`. The
full sample is also at
[`_examples/relay-gate.yml`](./_examples/relay-gate.yml) and lints
clean with `actionlint`.

```yaml
name: "relay-gate"

on:
  pull_request:
    branches:
      - main

permissions:
  contents: read
  pull-requests: write
  checks: write
  statuses: write

concurrency:
  group: "relay-gate-${{ github.event.pull_request.number }}"
  cancel-in-progress: true

jobs:
  setup:
    runs-on: ubuntu-latest
    timeout-minutes: 2
    outputs:
      is_fork: ${{ steps.fork.outputs.is_fork }}
      release_sha: ${{ steps.meta.outputs.release_sha }}
    steps:
      - uses: actions/checkout@v4
      - id: fork
        env:
          HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}
          BASE_REPO: ${{ github.event.pull_request.base.repo.full_name }}
        run: |
          if [ "$HEAD_REPO" != "$BASE_REPO" ]; then
            echo "is_fork=true" >> "$GITHUB_OUTPUT"
          else
            echo "is_fork=false" >> "$GITHUB_OUTPUT"
          fi
      - id: meta
        run: |
          echo "release_sha=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"

  contract-publish:
    needs: setup
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --all-packages
      - env:
          RELAY_CI_TOKEN: ${{ secrets.RELAY_CI_TOKEN }}
        run: |
          uv run rly contract publish "${{ vars.RELAY_CONTRACT_BUNDLE }}" \
            --out "${{ runner.temp }}/coverage.json"
      - uses: actions/upload-artifact@v4
        with:
          name: "relay-coverage"
          path: "${{ runner.temp }}/coverage.json"

  gate-evaluate:
    needs: [setup, contract-publish]
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --all-packages
      - if: needs.setup.outputs.is_fork == 'false'
        env:
          RELAY_CI_TOKEN: ${{ secrets.RELAY_CI_TOKEN }}
        run: |
          uv run rly gate evaluate \
            --gate-id "${{ vars.RELAY_GATE_ID }}" \
            --release-sha "${{ needs.setup.outputs.release_sha }}" \
            --project "${{ vars.RELAY_PROJECT_ID }}" \
            --json
      - if: needs.setup.outputs.is_fork == 'true'
        run: |
          uv run rly gate evaluate \
            --gate-id "${{ vars.RELAY_GATE_ID }}" \
            --release-sha "${{ needs.setup.outputs.release_sha }}" \
            --project "${{ vars.RELAY_PROJECT_ID }}" \
            --json
```

The complete sample at
[`_examples/relay-gate.yml`](./_examples/relay-gate.yml) adds the
optional `decision-post` job that surfaces the gate-evaluate result
as a PR check when the hosted webhook post-back is delayed.

### Exit codes

`rly gate evaluate` and `rly contract publish` share Relay's canonical
CLI exit codes. The relevant ones for CI wiring (full list emitted by
`rly gate evaluate --help` and documented at the top of
`packages/cli/src/relay_cli/main.py`):

| Code | Meaning |
|---|---|
| 0 | success (gate accepted, contract published, or dry-run) |
| 1 | 4xx with action=block (gate rejected; PR cannot merge) |
| 2 | 4xx with action=remediate (gate asks for a fix round) |
| 3 | 4xx auth/handoff (RELAY-GATE-021, RELAY-AUTH-*) |
| 4 | transient (cassette miss, draft TTL expired, network partition past TTL) |
| 5 | 5xx + network transient |
| 6 | WAL/storage error (RELAY-SIDECAR-STORAGE-*) |
| 8 | LLM-judge deferred (RELAY-EVAL-EVALUATOR-DEFERRED) |
| 64 | wrong-flag (CLI usage error) |
| 70 | uncaught internal |
| 130 | SIGINT/SIGTERM interrupted |

GitHub Actions treats any non-zero step exit as a job failure, so the
job's pass/fail status maps directly to the gate's pass/fail decision.

## Forks: dry_run_unsigned fallback

Pull requests from forks do not receive the repository's secrets, so
the CI worker cannot authenticate to the control plane to resolve a
canonical `gate_decision`. The spec handles this path explicitly:

> `draft_kind = 'dry_run_unsigned'` is used for fork PRs and other
> no-secrets paths (see §AI.6 CI workflows). Dry-run drafts NEVER
> produce a `gate_decision`; the CLI exits 0 with a flag noting the
> dry-run status. Branch protection that requires a `gate_decision`
> will block such a PR from merging -- that's intentional.

(Spec section B.6, via the `POST /v1/gates/{gate_id}/drafts` route
and the `gate_decision_drafts.draft_kind` column defined in
section A.3.)

What this means in practice:

- The fork CI job runs `rly contract publish` and `rly gate evaluate`
  identically to the non-fork path; the CLI detects the missing
  `RELAY_CI_TOKEN` and emits a `dry_run_unsigned` draft.
- The contributor sees assertion results in the workflow output so
  they can fix problems before a maintainer merges.
- No `gate_decision` row is written.
- The required-status check on the gate decision (see "Branch
  protection" below) blocks the fork PR until a maintainer re-runs
  the workflow on a trusted branch (typically by pushing the PR
  branch to the upstream repository).

The `setup` job in the sample workflow detects fork PRs by comparing
`github.event.pull_request.head.repo.full_name` with
`github.event.pull_request.base.repo.full_name` and emits the
`is_fork` output. Downstream jobs branch on `needs.setup.outputs.is_fork`
to skip steps that would error without the secret (such as the
hosted decision post-back).

## Branch protection

To make the gate a required check:

1. Open your repository's `Settings -> Branches -> Branch protection
   rules` for `main`.
2. Enable "Require status checks to pass before merging".
3. Search for and select `gate evaluate: required check` (the job
   name from the sample workflow's `gate-evaluate` job).
4. Save.

Once enabled, GitHub blocks merge on any PR where the
`gate-evaluate` job does not finish with exit 0. Fork PRs that
exit 0 with `draft_kind = 'dry_run_unsigned'` still satisfy the job
exit code, but the canonical `gate_decision` they did not produce
keeps any other check keyed to `gate_decisions.decision_id` red --
which is why most teams add a second required check that fires only
when the hosted webhook posts the canonical decision back (see next
section).

## Decision post-back contract

When the gate engine resolves a draft into a canonical
`gate_decision`, the hosted control plane posts the decision back
to the PR. The contract:

- Webhook target: configured per-project in the hosted dashboard
  (`Project -> Integrations -> GitHub`).
- HTTP method: `POST`.
- Payload schema: the `GateDecision` component in
  `packages/schemas/raw/openapi.yaml` (schema_version
  `relay.gate_decision.v1`) is the canonical shape. Key fields the
  post-back uses: `gate_decision_id`, `gate_id`, `scope_type`,
  `scope_id`, `round`, `action` (one of `accept`, `remediate`,
  `block`, `invalid`), `evidence_bundle_id`, `decided_at`,
  `manifest_commit_hash`, `signature`, `signature_key_id`.
- GitHub API call: `POST /repos/{owner}/{repo}/check-runs` with the
  `action` mapped to GitHub's `conclusion` field: `accept` becomes
  `success`, `block` and `invalid` become `failure`, `remediate`
  becomes `neutral`.
- Idempotency: the webhook uses `gate_decision_id` as the
  idempotency key so retries collapse into a single check-run
  update.

If you self-host the control plane, replicate this contract in your
own post-back service. The `decision-post` job in
[`_examples/relay-gate.yml`](./_examples/relay-gate.yml) is a
fallback that surfaces the gate-evaluate job's local result as a
status when the hosted webhook is unavailable or delayed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `gate-evaluate` exits 3 with `RELAY-GATE-021` | Three-anchor handoff mismatch -- stale `--manifest`, revoked actor, or wrong `--release-sha` (spec section C.5) | Verify `RELAY_GATE_ID`, `RELAY_PROJECT_ID`, and the `release_sha` match a gate currently in the active window; re-authenticate the CI token if the actor identity hash changed. |
| `gate-evaluate` exits 3 with `RELAY-AUTH-001` | `RELAY_CI_TOKEN` missing on a non-fork PR | Confirm the secret is set at the repository or org level: `gh secret list`. |
| `gate-evaluate` exits 3 with `RELAY-AUTH-014` | Token present but lacks the required scope | Re-mint the token with both `gates:execute` and `ingest:write` scopes. |
| `contract publish` exits 1 with `RELAY-COVERAGE-NNN` | Orphan assertion, duplicate `expression` digest, or missing `owner_email` on a P0/P1 assertion | Open the offending assertion in your contract bundle; every assertion must have exactly one human owner and a unique expression. See the [coverage-invariant guide](../contracts/coverage-invariant.md) for the full enumeration. |
| `gate-evaluate` exits 4 with `RELAY-GATE-024` | Draft TTL (default 900 s) expired before the engine resolved it | Re-run the workflow; transient capacity issue on the control plane. |
| `gate-evaluate` exits 0 but no PR check appears | Hosted webhook post-back disabled or wrong URL configured | Open `Project -> Integrations -> GitHub` in the hosted dashboard and re-enable; use the `decision-post` fallback job in the meantime. |
| Workflow cancelled mid-run after a force-push | `concurrency: cancel-in-progress: true` is doing its job | No action needed; the cancelled draft transitions to `cancelled` and the new run produces the canonical decision. |

For the full error-code catalog, see the
[error reference](../reference/errors/index.md).

## Related guides

- [Add Relay to your CI](../getting-started/ci-integration.md) -- the
  starter version of this guide.
- [Coverage invariant](../contracts/coverage-invariant.md) -- how to
  read `RELAY-COVERAGE-*` errors.
- [Audit a gate decision](./audit-gate-decision.md) -- how an ML
  safety reviewer reads a `gate_decisions` row after the fact.

Spec: §A.3, §B.6, §AI.6
