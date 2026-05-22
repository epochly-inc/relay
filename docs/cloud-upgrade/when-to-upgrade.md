# When to Upgrade to Hosted Relay

## What this page is

The OSS local sidecar is the right answer for many teams: it runs entirely on
your hardware, has no account dependency, and is fully usable under Apache 2.0.
This page is a decision framework, not a sales pitch. It helps you decide
whether the operational features the hosted Relay platform adds are worth the
shift in your operating model for **your** situation. If none of the upgrade
symptoms apply, staying on OSS is the correct call.

## Decision matrix

Three axes drive the decision. Score yourself on each and read the rows
together; one axis alone rarely settles it.

| Axis                                       | OSS local fits when ...                                            | Hosted starts to matter when ...                                          |
| ------------------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| **Team size**                              | 1-3 developers sharing one sidecar host or per-developer sidecars  | 5+ developers; you need per-user identity, role separation, project scopes |
| **Audit calendar**                         | No scheduled external review; ad-hoc internal use                  | Annual security review, AI Act conformity assessment, or recurring auditor handoff |
| **Side-effect blast radius**               | Agents are read-only or call internal-only tools at low volume      | Agents call mutating tools (write APIs, payments, external sends) at scale |

Read the table by row: the OSS column captures the situations where the local
sidecar's capabilities are sufficient. The Hosted column captures the
situations where the multi-tenant evidence registry, managed replay/eval
workers, and RBAC start carrying their weight. See
[Feature parity](feature-parity.md) for the row-by-row capability comparison.

### Team size

A 1-3 developer team can run a single shared sidecar, or per-developer
sidecars, and coordinate via filesystem-shared evidence bundles. There is
nobody to authorize against. At 5+ developers the lack of per-user identity
becomes a real friction: you cannot tell who triggered which gate decision,
you cannot scope projects per team, and rotating credentials means rotating a
single sidecar's secrets across the whole org. Hosted RBAC + SSO are the
features that pay back this cost.

### Audit calendar

If you do not have a scheduled external review, the local evidence bundle
output (`rly evidence bundle create`) plus the offline verifier
(`rly evidence verify`) is sufficient. You hand the auditor a `.zip` and a
JWKS pin and they verify on their own hardware with no Relay account. If you
**do** have a recurring audit cycle - annual security review, AI Act
conformity assessment, ISO 42001 surveillance - the hosted evidence registry
collapses the "find every bundle from the last 12 months and prove none were
tampered with" workflow into a query. The OSS path makes you the integrator;
the hosted path makes the registry the integrator.

### Side-effect blast radius

If your agents are read-only (search, summarization, retrieval) or call only
internal tools at modest volume, local replay against cassettes is fine. If
your agents call **mutating** tools (write APIs, payment systems, outbound
messaging, ticket creation), then the discipline of cassette-first replay
matters more, parallel replay capacity matters more, and sandbox isolation
matters more. The hosted replay workers run replays in queued, parallel,
isolated sandboxes - the local single-process model does not scale to the
same throughput.

## Symptoms that say "upgrade"

If you recognize yourself in two or more of these, the operational shift is
likely worth it:

- You are emailing evidence bundle `.zip` files to auditors and chasing which
  version is current.
- You cannot tell from a `gate_decisions` row who on your team triggered the
  decision (no per-user identity).
- You need cross-region replay (your developers and your agent runtime are
  in different regions, and the cassette latency hurts).
- Your local sidecar's uptime is now somebody's job - the host crashes affect
  your team's productivity.
- You need to onboard a contractor and cannot grant them scoped access
  without sharing the whole sidecar's secrets.
- Audit teams are requesting evidence across multiple projects and you are
  manually correlating bundles.

## Symptoms that say "stay on OSS"

If most of these apply, the OSS local sidecar is doing exactly what you need:

- Single developer, or a 2-3 person team that already coordinates closely.
- Low call volume - hundreds of agent runs per day, not thousands per hour.
- No audit calendar; no external review on the horizon.
- Air-gapped or regulated infrastructure where hosted is not an option
  (regulated industries, classified environments, on-prem-only).
- You value the "zero account, zero phone-home, Apache 2.0" property and
  your usage does not press on it.

## What does NOT change when you upgrade

This is the load-bearing reassurance. The upgrade is an operational shift,
not a re-architecture. Specifically:

- **Same SDK.** The Python and TypeScript SDKs are the same packages
  (`relay-sdk`, `@epochly/relay-sdk`). No code rewrite.
- **Same contracts.** Your CEL YAML files pass through `rly contract publish`
  unchanged. Your `relay.coverage`, `relay.schema_match`, `relay.tool_arg`
  UDFs work identically (they are `pure=True` on both surfaces, by
  construction).
- **Same evidence bundle format.** A bundle produced under OSS and a bundle
  produced under hosted are the same JWS envelope, the same claim structure,
  the same Merkle root, the same `trust_anchor` field.
- **Same CLI.** Every `rly` subcommand behaves the same. Auth changes
  (project-scoped tokens replace local-only mode), but the command surface
  does not.
- **Same offline verifier.** `rly evidence verify` runs anywhere, with no
  account, against either surface's bundles.

If you decide the OSS local sidecar still fits, you have lost nothing. The
public packages remain the canonical surfaces; the hosted platform is built
on top of them, not in place of them.

## Where to go next

- [Feature parity](feature-parity.md) - the row-by-row capability comparison.
- [Migration path](migration-path.md) - the operational steps to move a local
  deployment to hosted, including the two-release schema rename windows.

---

Spec: §S, §M
