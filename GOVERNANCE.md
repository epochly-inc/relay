# Governance

Relay is an open-source project published by **Epochly, Inc.** under the
Apache License 2.0. This document describes how decisions are made, who
holds maintainer authority, and how the project's trust anchor is governed.

## Project governance model

### Current phase: pre-1.0 BDFL

Until Relay reaches `v1.0.0`, the project operates under a **Benevolent
Dictator for Life** (BDFL) model:

- **Founder / current BDFL:** Chandler Vaughn ([@chandlercvaughn](https://github.com/chandlercvaughn))
- **Receiving entity:** Epochly, Inc.
- All merge decisions and roadmap calls go through the BDFL or designated
  maintainers.
- External contributors can propose changes via pull request; acceptance
  is gated on the CLA + DCO checks and one maintainer review.

This model exists because the project is too young to support the
overhead of a steering committee. The BDFL phase is bounded — see the
graduation criteria below.

### Graduation to steering-committee model at v1.0

When **all four** of the following are true, Relay's governance
transitions from BDFL to a Steering Committee:

1. The first `v1.0.0` release has shipped on PyPI (`epochly-relay`) and
   npm (`@epochly/relay`).
2. At least three independent maintainers (not employed by Epochly, Inc.)
   have commit access and have contributed substantively in the prior
   six months.
3. The trust anchor JWKS at `relay.epochly.com/.well-known/jwks.json` has
   been audited by an independent third party with the result published
   publicly.
4. A documented community process for proposing significant changes
   (RFC-style) is in place.

At graduation, the founder transitions to a steering-committee chair role
with one vote among the committee, not unilateral decision authority.

### Maintainers

The current list of maintainers with merge authority lives in
[MAINTAINERS.md](MAINTAINERS.md) (added when there are more than one).

## Decision-making

### Day-to-day

The BDFL or any maintainer can:

- Merge PRs that pass the CLA + DCO checks, all CI gates, tier-1
  plumbing tests, tier-2 smoke tests, and one maintainer review.
- Cut patch releases (`v0.x.y` → `v0.x.y+1`) for bug fixes.
- Approve documentation, examples, and developer-experience changes.

### Significant changes

These require **explicit BDFL approval** during the pre-1.0 phase and a
written rationale captured in [`docs/adr/`](docs/adr/) (Architecture
Decision Records):

- Adding or removing a P0 SDK (Python, TypeScript).
- Changing the local sidecar's API surface in a backward-incompatible way.
- Changing the contract DSL (the CEL profile, the UDF surface, or the
  conformance-corpus required-pass set).
- Changing the evidence bundle wire format (ACEF version pin or
  Relay-extension semantics).
- Changing the side-effect class taxonomy.
- Adding a new sandbox driver to P0.

After graduation, significant changes require steering-committee majority
vote plus a 14-day comment window on the RFC.

### Board-level decisions

The following are **board-level decisions** at Epochly, Inc. — not subject
to maintainer or committee vote, ever:

- **Changing the OSS verifier's default trust anchor** (the JWKS URL it
  fetches by default). Per the spec's Keystone Invariant #11 and the
  trust-anchor governance doc, the default is
  `relay.epochly.com/.well-known/jwks.json`. The OSS verifier supports
  BYO trust anchors via flag or config — that is the supported path for
  forks and self-hosters. Changing the default in the OSS code is a
  board-level decision.
- **License changes.** The Apache 2.0 license is preserved unless and
  until commercial-defense conditions documented in the spec's License
  posture section are met, in which case the CLA's relicense right is
  exercised by Epochly, Inc.

## Trust anchor governance

The Relay trust anchor — the JWKS, the transparency log, and the RFC
3161 timestamp authority — is governed separately by
[docs/legal/trust-anchor-governance.md](docs/legal/trust-anchor-governance.md).
That document is authoritative for:

- Signing-key custody and rotation
- Compromise response and revocation procedures
- Transparency-log governance and witness signature program
- Auditor onboarding
- Public communication policy for trust-anchor incidents

The trust-anchor governance doc must be reviewed by counsel and Epochly
security counsel before any signing infrastructure ships. Until then it
lives as a draft per the Pre-Week-1 Lockdown decisions.

## Contributor recognition

We credit contributors in the changelog and in release notes. We do not
gate visibility on contribution volume; a single high-quality bug report
is recognized the same as a feature PR.

## Code of conduct

All participants are bound by the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
Maintainers enforce it without discretion in egregious cases.

## Disagreements

If you disagree with a maintainer's decision:

1. First, comment on the PR or issue explaining your reasoning.
2. If unresolved, open a new issue tagged `governance-question`.
3. The BDFL (pre-1.0) or steering committee (post-1.0) will respond
   within 14 days with a written rationale.

Disagreements that cannot be resolved are documented in
[`docs/adr/`](docs/adr/) so the project's institutional memory captures
both the chosen path and the rejected alternatives.

## Forks

Apache 2.0 grants you the right to fork Relay. We don't view forks as
hostile; we view them as the OSS community working as intended. A fork
that re-publishes Relay-signed evidence bundles under their own trust
anchor is operating in a different trust system, which is the right
outcome and is documented in
[docs/legal/trust-anchor-governance.md](docs/legal/trust-anchor-governance.md).
