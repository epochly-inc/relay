# Contributing to Relay

Thanks for considering a contribution. Relay is a strict OSS project and
external contributions are gated on two requirements that have a real
legal purpose, not just process theater.

## Two-gate requirement

Every external contribution must satisfy **both** of these gates. They
cover different legal needs and the CI will block any PR missing either.

### Gate 1 — Relay CLA (signed once)

The first time you open a pull request, the **CLA Assistant Lite** bot
will comment asking you to sign the
[Relay Contributor License Agreement](CLA.md). Reply in the PR with
the exact phrase:

> `I have read the CLA Document and I hereby sign the CLA`

Your signature is stored at `signatures/version1/cla.json` in this
repository. Subsequent PRs from the same GitHub account do not re-prompt.

The Relay CLA is adapted from the Apache Software Foundation ICLA v2.2 —
the most-litigated, most-trusted OSS contributor agreement template. The
mechanical changes (receiving entity = Epochly, Inc.; project field =
Relay; electronic signature instead of email) are documented inline in
[CLA.md](CLA.md). The patent grant scope is identical to ASF v2.2.

### Gate 2 — DCO sign-off on every commit

Every commit must include a `Signed-off-by:` trailer per the
[Developer Certificate of Origin](https://developercertificate.org/).
The DCO Bot enforces this as a required status check.

Practical workflow:

```bash
# Sign each commit as you make it:
git commit -s -m "Your commit message"

# Or set up an alias once so every commit gets signed:
git config --global alias.cs "commit -s"
git cs -m "Your commit message"

# If you forget on the last commit:
git commit --amend -s --no-edit

# If you forget across several commits on your branch:
git rebase HEAD~N --signoff
```

The DCO is a statement that you have the right to submit the code under
this project's license. The Linux Foundation's
[DCO page](https://wiki.linuxfoundation.org/dco) has the full text.

### Why both

The CLA grants Epochly the *copyright license and the right to relicense*
the combined work if the project's license has to change in the future
(e.g., move from Apache 2.0 to AGPL-3.0 for the commercial-defense
relicense fallback documented in the spec). The DCO is the per-commit
*attestation of provenance* — that you have the right to submit this
specific code.

Most modern OSS-with-a-commercial-parent projects (HashiCorp, Elastic,
Snowflake, Confluent) use both for exactly this reason. Linux uses
DCO-only because it has no commercial parent and never needs to relicense.

## Development setup

### Prerequisites

- **Python 3.12+** (3.12, 3.13, 3.14 supported; CI tests all three)
- **Node.js 22+** (22, 24, 26 supported; CI tests all three)
- **[uv](https://docs.astral.sh/uv/)** for Python packaging
- **Docker Desktop or compatible** for the optional sandbox driver
  (Linux: docker; macOS: Docker Desktop or colima; Windows: Docker
  Desktop + WSL2)

### First-time setup

```bash
git clone git@github.com:epochly-inc/relay.git
cd relay

# Python side
uv sync --frozen

# TypeScript side
cd packages/sdk-typescript && npm ci && cd ../..

# Verify the install
uv run rly verify-self
```

The `rly verify-self` command runs a smoke check across the platform
(macOS, Linux, Windows native are all P0) and exits 0 when the
environment is sound.

## Test tiers

Run the right tier before pushing:

```bash
# Tier 1 — plumbing, offline, ≤60s. Run on every change.
uv run pytest -m plumbing

# Tier 2 — smoke, real APIs, ≤8 min. Run before opening a PR.
uv run pytest -m smoke

# Tier 3 — evals, LLM-judged, ≤12 min. Nightly + pre-release; not on every PR.
uv run pytest -m eval
```

If a test is failing on your machine but not in CI, check that your local
Python is one of `3.12 / 3.13 / 3.14` and Node is one of `22 / 24 / 26`.

## Branch protection and review

- `main` requires both `CLA Assistant Lite` and `DCO` checks to pass.
- Tier-1 plumbing + tier-2 smoke must be green.
- The OSS standalone gate, license/header gate, and secret scan gate
  must be green.
- One maintainer review required.

## Project structure cheatsheet

Read the [README.md](README.md) for the directory layout. Quick pointers:

- New SDK feature? `packages/sdk-python/` or `packages/sdk-typescript/`
  with a tier-1 contract test in `tests/contract/`.
- New CLI subcommand? `packages/cli/` + tier-2 smoke test in
  `tests/integration/`.
- New contract operator or UDF? `packages/contracts/` + a CEL conformance
  test in `tests/conformance/cel/` (must pass parity between cel-python
  and cel-js).
- Schema change? `packages/schemas/raw/` is the canonical source;
  re-run codegen and commit the result.

## Security disclosures

Please **do not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the responsible-disclosure path.

## Code of conduct

We follow the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Be kind,
be specific, and assume good faith.
