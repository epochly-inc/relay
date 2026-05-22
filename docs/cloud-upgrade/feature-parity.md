# OSS vs Hosted: Feature Parity

## What this page is

This page compares what you get when you run Relay locally with the OSS sidecar
versus what the hosted Relay platform adds. Entries are limited to
user-visible behavior — capabilities you exercise from the CLI, the SDK, the
verifier, or a browser. Internal service decomposition, scheduler details, and
storage backends are out of scope here; see the
[architecture overview](../architecture/overview.md) for the system model.
Relay OSS is fully usable standalone — every row marked OSS Local is shippable
under Apache 2.0 with no hosted dependency.

## Comparison table

| Capability                                                              | OSS Local                                                | Hosted                                          |
| ----------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------- |
| Trace ingest                                                            | Yes (SDK to local sidecar over loopback HTTP)            | Yes (SDK to hosted ingest)                      |
| Local sidecar storage                                                   | Yes (per-host SQLite under XDG data dir)                 | Not applicable (managed storage)                |
| Multi-user RBAC / SSO                                                   | Not available (single-host, single-operator)             | Yes (org, project, role; SSO via your IdP)      |
| Evidence registry (multi-tenant)                                        | Not available (bundles stored on local disk)             | Yes (org-scoped registry with retention policy) |
| Replay workers (managed)                                                | Not available (replay runs in your local process)        | Yes (queued, parallel, isolated sandboxes)      |
| Eval workers (managed)                                                  | Not available (evals run in your local process)          | Yes (queued, parallel, judge-model isolation)   |
| Contract publish / gate evaluate                                        | Yes (`rly contract publish`, `rly gate evaluate` — exit code only, no remote registry) | Yes (publish to org registry; gate decisions persisted) |
| Compliance packs (EU AI Act, NIST AI RMF, ISO 42001)                    | Not available                                            | Yes (pack artifacts mapped to evidence claims)  |
| Vertical packs (healthcare RCM, finance ops, etc.)                      | Not available                                            | Yes (per-vertical assertion libraries)          |
| Audit log / activity stream                                             | Yes (local append-only event log)                        | Yes (org-scoped, multi-tenant, retained)        |
| Trust anchor JWKS                                                       | Yes (default points to `https://relay.epochly.com/.well-known/jwks.json`; `--trust-anchor` flag overrides) | Yes (same default; org may pin alternate JWKS)  |
| Bundle verifier                                                         | Yes (`rly evidence verify` — runs anywhere, no account)  | Yes (same verifier; runs anywhere)              |

## Notes on the rows

- **Contract publish / gate evaluate.** Both surfaces accept the same contract
  YAML and emit the same exit-code semantics. The OSS path is exit-code-only:
  `rly gate evaluate` returns 0 / 1 / 2 per the documented exit-code table and
  does not persist a `gate_decision` row to any remote registry. The hosted
  path persists the decision and binds it to the org's evidence registry.
- **Audit log.** OSS produces a local append-only event log readable via
  `rly events tail`. Hosted produces an equivalent stream scoped to your org,
  retained per your retention policy, and exportable.
- **Trust anchor JWKS.** The verifier's default trust anchor is
  `https://relay.epochly.com/.well-known/jwks.json` on both surfaces. The
  `--trust-anchor` flag (and the equivalent config field) accepts an
  alternate JWKS URL or file path for forks, self-hosters, and air-gapped
  verification.
- **Bundle verifier.** The verifier is the same binary on both surfaces and
  has no hosted dependency at runtime beyond fetching the JWKS (or reading a
  local pinned copy). You can hand a bundle to an auditor with no Relay
  account and they can verify it.

## Where to go next

- [Migration path](migration-path.md) — moving a local sidecar deployment to
  hosted (schema rename windows, data export, cutover).
- [When to upgrade](when-to-upgrade.md) — decision framework based on team
  size, audit calendar, and side-effect blast radius.
- [Architecture overview](../architecture/overview.md) — system tiers, write
  boundaries, and where each capability lives.

---

Spec: §M, §R
