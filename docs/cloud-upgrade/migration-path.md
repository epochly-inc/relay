# Migration: Local Sidecar to Hosted Relay

## What migrates and how

Moving from the OSS local sidecar to hosted Relay is, by design, mostly an
endpoint and token change rather than a data-model change. The trace, run,
contract, and evidence-claim schemas are identical in both profiles — they
are generated from `packages/schemas/` and consumed unchanged by the SDK,
CLI, and verifier. Your existing local bundles remain valid against the
same trust anchor on the hosted side. The work of migration is therefore
concentrated in: (1) confirming the integrity of the local data you want
to carry forward, (2) understanding that the local SQLite store is not
itself portable to the hosted Postgres store (you migrate evidence
bundles, not raw rows), (3) repointing the SDK at the hosted ingest
endpoint, (4) minting a hosted CI token, and (5) verifying that
locally-signed bundles still verify on the hosted side. None of those
steps require code changes inside your application.

## Step 1: Assess your local data

Before redirecting anything, take inventory of the local bundles you want
to preserve and confirm each one verifies offline. The OSS CLI exposes
both operations:

```bash
# List every local bundle with its binding fields (project, run, hashes).
rly evidence list --json

# Verify a specific bundle against the default trust anchor.
rly evidence verify path/to/bundle.json
```

`rly evidence list` paginates over `${RELAY_HOME}/evidence/*.json` and
emits a JSON envelope per bundle. `rly evidence verify` is offline-only
and resolves the trust anchor through the precedence rules documented in
[../evidence/offline-verification.md](../evidence/offline-verification.md).
A bundle that fails verification locally will fail verification on the
hosted side as well — fix it (re-sign, re-bind, or quarantine) before
moving on.

## Step 2: SQLite to Postgres

The OSS local sidecar stores control-plane rows in a per-host SQLite
database under `${RELAY_HOME}/sidecar.db` (managed by aiosqlite, with WAL
enabled). The hosted control plane stores the same logical rows in a
multi-tenant Postgres cluster. The two are not wire-compatible at the
storage layer, and there is no direct SQLite-to-Postgres dump-and-load
import path between them.

What IS portable is the canonical evidence bundle. Once a run has a
signed evidence bundle, that bundle is the durable artifact; the
underlying control-plane rows are a derivation. The migration path is
therefore:

1. On the local side: verify every bundle you care about (Step 1).
2. On the hosted side: re-ingest from your application going forward.
   Historical bundles remain verifiable in place; they do not need to be
   imported into hosted Postgres to be auditor-readable.

Any future breaking change to a shared control-plane schema (a column
rename, a constraint tightening, a type narrowing) follows the
schema-rename discipline described below — both for the OSS sidecar
schema and the hosted Postgres schema.

## Step 3: Redirect the SDK endpoint

The OSS SDK locates the local sidecar by reading the sidecar lockfile at
`${RELAY_HOME}/sidecar.lock` (see `packages/sdk-typescript/src/client.ts`
and `packages/sdk-python/relay/client.py`). No environment variable
points at the sidecar URL in production; the explicit
`RELAY_SIDECAR_URL` env var is gated behind
`RELAY_ALLOW_EXPLICIT_SIDECAR=1` and is intended for tests only.

Switching to hosted Relay therefore means switching to the hosted client
construction path — supplying your hosted project key to the SDK
constructor and letting the SDK resolve the hosted ingest endpoint from
the project key. Concretely, the change in your application code is:

- Stop relying on the local sidecar lockfile being present.
- Construct the SDK with the project key minted in your hosted dashboard
  (see Step 4).
- Leave every other call site identical — the SDK API surface does not
  change between profiles.

If you operate a self-hosted Relay control plane (the enterprise
deployment profile), the same project-key construction applies; only the
hosted base URL embedded in your project key changes.

## Step 4: Mint a CI token

CI submissions to hosted Relay use a project token of the form
`relay_pk_<id>`. Mint one from the hosted onboarding flow and store it
in your CI provider's secret store. The OSS side of this document does
not deep-link into the hosted onboarding UI; the broad shape of the flow
is "create org, create project, mint token, copy token into CI secret"
and the hosted docs will own the exact click-path.

For GitHub Actions specifically, the existing OSS guide at
[../how-to/integrate-ci-github-actions.md](../how-to/integrate-ci-github-actions.md)
documents the project-token wiring. The same workflow YAML works
against hosted Relay once the token is hosted-issued rather than
locally-minted.

## Step 5: Replay existing bundles on hosted

Every Relay-signed evidence bundle carries a `trust_anchor` field
identifying the JWKS that produced its signature. The OSS verifier
defaults to `https://relay.epochly.com/.well-known/jwks.json`; bundles
signed under that anchor remain valid after migration. You do not need
to re-sign locally-issued bundles to use them on hosted.

Two practical confirmations:

- Run `rly evidence verify path/to/bundle.json` after migration. The
  verdict must remain `verified`. If a bundle was signed under a
  different trust anchor (a BYO trust anchor, for example), use
  `rly evidence verify --trust-anchor <jwks-url> path/to/bundle.json`
  to pin the verifier at the matching anchor.
- The `trust_anchor` value in the verifier's `VerificationResult`
  output is the JWKS the bundle was signed under. Auditors can read
  that field to determine which root of trust they need to attest to.

See [../evidence/offline-verification.md](../evidence/offline-verification.md)
for the full lifecycle of trust-anchor caching and air-gapped review.

## Schema-rename windows

Any breaking schema change on either side — OSS sidecar SQLite or hosted
Postgres — runs through a two-release window so that read paths and
write paths overlap long enough for clients to roll forward without
breakage. The discipline is taken verbatim from the spec's release
runbook:

> Schema migrations run online with backward-compatible read paths; new
> columns added with defaults; renames require a two-release window
> (add -> write-both -> cut over -> drop).

Concretely, a column rename proceeds in four phases:

1. **Add.** The new column is added alongside the old column. Reads
   may use either; writes still go to the old column.
2. **Write-both.** Writes populate both columns. Reads still prefer
   the old column. Both releases must be deployable.
3. **Cut over.** Reads switch to the new column. Writes still
   populate both for one more release window.
4. **Drop.** Writes stop populating the old column; the old column
   is removed.

The same four-phase discipline applies whether the rename is in the
hosted Postgres schema or the OSS sidecar SQLite schema. Releases are
spaced far enough apart that a client running release N can talk to a
server running release N+1 without observing a missing column or a
silently-truncated field. Per spec section Q.2 (hosted release
runbook), destructive rollbacks of schema migrations are forbidden;
roll forward with a compensating migration instead.

## Rollback

The migration is fully reversible because the OSS install path is
self-contained. If you decide to move back to the local sidecar after
having pointed your application at hosted Relay, the rollback is:

1. Stop directing new traffic at hosted (revoke or scope the CI token,
   change the SDK construction to use the local sidecar locator).
2. Restart the local sidecar (`rly sidecar up` or your platform-specific
   service launcher) so the lockfile is present.
3. Resume from your local bundles. Bundles you generated on hosted
   between migration and rollback are still valid offline and still
   verify with `rly evidence verify` against the default trust anchor.

No data is destroyed on either side by the rollback. Hosted-issued
bundles remain in your hosted registry; locally-issued bundles remain in
`${RELAY_HOME}/evidence/`. The verifier is profile-agnostic.

## See also

- [Feature parity: OSS vs Hosted](feature-parity.md) — capability-by-
  capability comparison of the two profiles.
- [When to upgrade](when-to-upgrade.md) — decision framework for moving
  from OSS local to hosted.
- [Offline evidence verification](../evidence/offline-verification.md) —
  full lifecycle for cached JWKS and air-gapped auditor workflows.

Spec: §T
