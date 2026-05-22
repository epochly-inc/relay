# Add Relay to Your CI

## What this does

This workflow runs your Relay contract on every pull request: it publishes
the coverage report with `rly contract publish`, evaluates the gate with
`rly gate evaluate`, and propagates the gate's exit code as the CI job's
exit code so branch protection can require an `accept` decision before
merge.

## Quickstart workflow

Drop the following file at `.github/workflows/relay-gate.yml` in your
repository. The action pins match the conventions used elsewhere in this
repo (`actions/checkout@v4`, `actions/setup-python@v5`,
`astral-sh/setup-uv@v3`).

```yaml
name: "relay-gate"

on:
  pull_request:
    branches:
      - main

permissions:
  contents: read

jobs:
  gate:
    name: "relay contract + gate"
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: "checkout"
        uses: actions/checkout@v4

      - name: "setup python 3.12"
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: "install uv"
        uses: astral-sh/setup-uv@v3

      - name: "install relay"
        run: uv sync --all-packages

      - name: "publish contract coverage"
        run: uv run rly contract publish

      - name: "evaluate gate"
        run: uv run rly gate evaluate --gate-id "${{ vars.RELAY_GATE_ID }}"
```

`rly gate evaluate` returns one of the canonical CLI exit codes
documented at the top of `packages/cli/src/relay_cli/main.py`: `0` on
accept, `1` on block, `2` on remediate, `3` on auth/handoff failure,
and so on. GitHub Actions treats any non-zero step exit as a job
failure, so no extra plumbing is needed to map the gate decision to a
required-check status.

## Forks (no GITHUB_TOKEN) behavior

PRs from forks do not receive the repository's secrets, so the CI worker
cannot authenticate to the control plane to resolve a canonical
`gate_decision`. The spec handles this path explicitly. Quoting spec
section A.3 (which the §B.6 endpoint inventory implements via the
`POST /v1/gates/{gate_id}/drafts` route):

> `draft_kind = 'dry_run_unsigned'` is used for fork PRs and other
> no-secrets paths (see §AI.6 CI workflows). Dry-run drafts NEVER
> produce a `gate_decision`; the CLI exits 0 with a flag noting the
> dry-run status. Branch protection that requires a `gate_decision`
> will block such a PR from merging -- that's intentional.

In other words, fork CI jobs still run the contract and produce a
`dry_run_unsigned` draft so the author can see the assertion results,
but no canonical decision is written. If your `main` branch has a
required status check keyed to the gate decision, the fork PR cannot
merge until a maintainer re-runs the workflow on a trusted branch.

## What hosted CI tokens add

The OSS path above is sufficient for any developer running against a
self-hosted local sidecar. Project-scoped CI tokens issued by a hosted
Relay control plane add capabilities documented in
`docs/cloud-upgrade/feature-parity.md`: server-side draft persistence,
gate decision history surfaced in the hosted dashboard, evidence bundle
storage, and webhook callbacks once a decision resolves. The OSS CLI
talks to whichever control plane URL the token is scoped to; the
workflow shape above does not change.

## Next

For the production-grade walkthrough -- token provisioning, idempotency
keys, matrix CI aggregation, cancelled-run cleanup, and the full forks
path with PR comment posting -- continue to
[Integrate Relay with GitHub Actions](../how-to/integrate-ci-github-actions.md).
This page is the starter on-ramp; that page is the reference.

Spec: §A.3, §B.6, §AI.6
