---
status: counsel-review-pending
last-reviewed-by: Chandler Vaughn (Relay-Inc release engineering)
last-reviewed-on: 2026-05-16
next-review-due: 2026-11-12
counsel-reviewer: pending
---

# Trust Anchor Governance

> Doc-first governance for the Relay trust anchor: the JWKS endpoint,
> the transparency log, and the TSA partnership that together let
> auditors accept a Relay-signed evidence bundle as load-bearing
> evidence. Authoritative source for the cryptographic and
> institutional decisions that bind `relay.epochly.com/.well-known/jwks.json`
> to Relay-Inc.

This document satisfies the W13 deliverable of the Relay v0.1 OSS wedge
(eng plan W13; CEO plan cherry-pick #1) and the §AO.3 step 1 obligation
to "publish a transparent governance document for the trust anchor."
It is reviewed semi-annually; see the front-matter `next-review-due`
field for the scheduled cadence.

## Overview

The Relay trust anchor is the keystone commercial defense for an OSS-first
agent reliability OS. Apache 2.0 licensing on Relay Core is a deliberate
adoption-velocity bet, not a fork-prevention mechanism. The actual
defense against fork-and-clone is the trust anchor: the chain of
cryptographic and institutional authority that auditors, regulators,
and procurement teams reference when accepting a Relay-signed evidence
bundle as material evidence in an audit working paper. Spec section
§AO.1 names the three layered components; §AO.2 names the defense; §AO.4
names the architectural corollaries that keep the defense durable.

The governance posture for v0.1 is **doc-first**: this file declares the
custody model, the rotation cadence, the disclosure procedure, the
transparency-log design, the TSA partner selection, the JWKS hosting
arrangement, and the counsel-review path. Runtime signing infrastructure,
key escrow tooling, and the witness-signature scheduler live in the
private `relay-platform` repository (per CLAUDE.md banned pattern #14:
trust-anchor key material may never be committed to the public `relay`
repository). The OSS verifier, the bundle format, and the offline-verify
machinery live in the public `relay` repository under Apache 2.0; the
trust anchor itself — the keys, the log custody, the TSA contracts —
does not.

Why this matters: every auditor who accepts
`https://relay.epochly.com/.well-known/jwks.json` as a default trust
source compounds the moat for every other Relay customer who depends on
it. The trust anchor is the only moat that strengthens with time without
new code (spec §AO.5). The W13 document is the artifact that begins
that compounding: it is what counsel, audit firms, and procurement
reviewers read first when deciding whether the trust anchor is operated
to a standard worth accepting by default.

Scope boundaries enforced by this document (per CLAUDE.md Source of
Truth):

- The OSS verifier defaults to the Relay-Inc JWKS at
  `relay.epochly.com/.well-known/jwks.json`. Changing that default in
  the OSS code path is a board-level decision per CLAUDE.md banned
  pattern #13, not a routine PR.
- The OSS verifier supports BYO trust anchors (see "Fork Path" below);
  this is how forks, self-hosters, and air-gapped enterprises operate
  their own anchors without forking the verifier.
- All trust-anchor key custody, rotation, compromise response, and
  revocation publication procedures named below are operated by Relay-Inc
  out of the private `relay-platform` repository (per spec §L.1 and
  CLAUDE.md Keystone Invariant #11). Their interfaces are public; their
  key material is not.

Cross-references: see §AO.3 for the six-step governance program of
which this document is step 1; §AO.5 for the operational moats that
compound alongside the trust anchor; §AO.7 for what the architecture
is *not* betting on.

## Trust Anchor Architecture

Per spec §AO.1, the Relay trust anchor is three layered components,
each with a distinct failure mode and a distinct remediation:

1. **JWKS endpoint.** `https://relay.epochly.com/.well-known/jwks.json`
   publishes the public keys of Relay-Inc's hosted signing keys (one or
   more per `signer_key_id`, with full rotation history per spec §L.2).
   Verifiers — the OSS `relay-verifier`, the public verify endpoint at
   `https://relay.epochly.com/verify`, and any third-party verifier — fetch
   from this URL by default. The endpoint is hosted on Cloudflare
   (Cloudflare Pages for the static JSON, or Cloudflare Workers KV for
   low-latency reads at edge POPs) with Cloudflare Universal SSL and
   Cloudflare DDoS protection (per PW1-4). The DNS CNAME for
   `relay.epochly.com` is managed by Relay-Inc and points to the
   Cloudflare project; the founder owns DNS custody.

2. **Transparency log.** Relay operates an append-only Merkle-tree log
   of every issued evidence bundle (`bundle_id`, `bundle_digest`,
   `signer_key_id`, `appended_at`, `tree_root_after`) per spec §AB
   (transparency log) and the Sigstore Rekor design pattern. The log is
   publicly readable and Merkle-proof-verifiable offline. A bundle whose
   `(bundle_id, digest)` is not in the log raises a
   `log_inclusion: absent` warning in the verifier; auditors are
   trained to treat that as a red flag in their working papers.

3. **TSA partnership.** RFC 3161 timestamps come from a third-party
   Time Stamping Authority that Relay-Inc has contracted with. Per
   pre-week-1 lockdown decision PW1-3, the partner selection is:
   - **Sigstore TSA** at `https://timestamp.sigstore.dev/api/v1/timestamp`
     is the **primary** TSA. Sigstore TSA is RFC 3161, free at the
     point of use, Apache 2.0 licensed, has an official Python SDK
     (`sigstore-python`), and offers infinite retention via the Rekor
     transparency log.
   - **Sectigo TSA** is the **commercial fallback** for Sigstore TSA
     outage or rate-limit (pay-per-use, no minimum). DigiCert and
     GlobalSign were considered and rejected as overkill at v0.1
     volume; see `docs/release/sectigo-tsa-fallback.md` for the
     activation runbook.
   - **FreeTSA is rejected for production use.** FreeTSA does not
     publish a contractual retention SLA, does not publish a witness
     signature mechanism, and has shown intermittent outages in the
     2025-2026 operational record. Sigstore TSA is the credible free
     alternative; Sectigo is the credible paid alternative; FreeTSA is
     not used.

Together these three are the **Relay trust anchor**. A bundle signed
by a Relay-Inc key, timestamped by Relay's TSA partner, and inclusion-
proven against Relay's transparency log is "Relay-signed" in the
load-bearing sense (per spec §AO.1).

Anti-cloning architecture (spec §AO.4): the Relay-signed bundle
includes a `trust_anchor` field identifying which JWKS produced the
signature (`trust_anchor: relay.epochly.com` for hosted Relay;
`trust_anchor: local_dev` for OSS-local-signed; `trust_anchor: <other>`
for any third-party signer). The verifier surfaces this in its output
per spec §K. The transparency log is publicly readable; a fork can
clone the log software but cannot clone the log history. The trust
anchor is not in the OSS code; Apache 2.0 covers the verifier engine
and the bundle format only, and grants no rights to Relay-Inc's
signing keys, transparency log custody, or TSA contracts.

## Key Custody

Per spec §L.1 and CLAUDE.md Keystone Invariant #11, all Relay-Inc
signing private keys are held in a managed Key Management Service
(KMS) or a Hardware Security Module (HSM); private key material never
exists on disk in cleartext, never appears in environment variables,
and never lands in either git repository.

Custody model for v0.1:

- **Primary key storage: KMS.** Each `signer_key_id` is created and
  used inside the KMS via the `sign` API; the public key (in JWK form)
  is exported to the JWKS endpoint, and the private material never
  leaves the KMS perimeter. The KMS account is Relay-Inc-owned (not
  Chandler-personal), with a separate billing account from product
  infrastructure, so that a product-account compromise does not extend
  to key custody. The KMS provider, project, and key resource names
  are recorded in the private `relay-platform/ops/runbooks/`
  trust-anchor runbook (not in this OSS document, per CLAUDE.md banned
  pattern #14).
- **HSM-backed roots.** The root-of-trust signing identity (the key
  whose fingerprint is published out-of-band on the Relay status page,
  per spec §L.2) is HSM-backed. The HSM provider is named only in the
  private runbook. HSM access requires two-person presence; a single
  operator cannot use the root.
- **Local-development keys.** OSS developers running `rly` locally
  generate ephemeral keys via the verifier's `--local-dev` flag; those
  keys bind to `trust_anchor: local_dev` in the bundle envelope and
  are NEVER accepted by the verifier as `trust_anchor: relay.epochly.com`.
  Local-dev keys are stored under `~/.relay/keys/` with POSIX mode
  `0600` (or the Windows ACL equivalent), and the directory itself
  with mode `0700`. The four atomic-persistence primitives manage
  every write to that directory; no business logic touches the path
  directly (spec §H).

Rotation procedure (spec §L.3): default rotation cadence is every
twelve months for hosted signing keys. Rotation is a two-phase
commit. The new key is created with `not_before = now + 24h` and
written to JWKS first. Only after observers confirm that the new key
has propagated to the relevant Cloudflare edge POPs is the old key
marked deprecated. Bundles signed within the propagation window may
carry both the new `signer_key_id` and a witness signature from the
old key, so that verifiers that have not yet refreshed their JWKS
cache can still verify. The full rotation runbook lives in
`relay-platform/ops/runbooks/`; the schedule is recorded in the
public Relay release calendar.

Compromise response (spec §L.5): on suspected key compromise, the
on-call release engineer opens a sev1 incident automatically. Bundle
generation aborts for the affected `signer_key_id`; all in-flight
claims are rolled back via the standard `compare_and_set_state`
rollback path (spec §C.4). A new key is activated; the compromised
key is revoked (see below); a public incident write-up is published
within 72 hours, naming the affected `signer_key_id`, the affected
time window, and the verifier behavior auditors should adopt for
historic bundles signed by the compromised key. The incident
write-up is reviewed before publication by the security reviewer
named in the front-matter (or the `pending` placeholder while
counsel review is open).

Revocation publication (spec §L.4): revocation publishes a
CRL-style record on a static endpoint at
`https://relay.epochly.com/.well-known/revoked-keys.json` and
updates the `signing_keys.revoked_at` column in the private control
plane. The verifier surfaces `signer_key_revoked: true` and
`revoked_at: <timestamp>` in its output for every bundle signed by a
revoked key; auditors decide per audit policy whether to accept
bundles signed before the revocation time. The revoked-keys endpoint
is read by the verifier on each invocation (cached for 300 seconds)
unless the verifier is invoked with `--offline`, in which case the
auditor must provide a snapshot via `--revoked-keys <path>`.

## Transparency Log

Per spec §AB, every issued evidence bundle's
`(bundle_id, digest, timestamp, signer_key_id)` is appended to a
public log inspired by Sigstore Rekor. The log is implemented as an
append-only Merkle tree; bundles can be checked for inclusion offline
using a witness signature. Inclusion is required before a bundle can
be marked `evidence_bundle_registry.state='active'`; the signer
halts with `RELAY-EVID-031` if the timestamp or inclusion proof is
missing.

Three design properties bind the log to its evidence purpose (per
spec §AO.3 step 3 and §AB):

1. **Append-only Merkle tree.** Entries are immutable; once a
   `log_index` is assigned, the `tree_root_after` is recorded and any
   subsequent inclusion proof against that root remains valid in
   perpetuity. Admin tooling cannot delete rows; the only path to
   "remove" an entry is to publish a revocation event that the
   verifier surfaces alongside the original entry.
2. **Publicly readable.** The log is served at
   `https://relay.epochly.com/v1/transparency-log/` with documented
   endpoints for `get_entry`, `get_inclusion_proof`, and
   `get_consistency_proof`. The log's full history may be retrieved
   by any party; auditors and academic observers are encouraged to
   mirror it. Spec §AB defines the schema; the OSS verifier (in
   `packages/verifier/`) implements the offline inclusion check.
3. **Witness signatures.** Per spec §AO.3 step 3, the transparency
   log carries periodic (daily) signed commitments from at least
   three independent witnesses (initial set: a friendly audit firm,
   an academic institution, and a security-researcher organization)
   attesting that today's Merkle root is consistent with yesterday's.
   Witness signatures defeat the "what if Relay rewrites their own
   log?" concern; a rewrite would invalidate every witness signature
   issued before the rewrite, which observers monitor and publish.
   The witness onboarding procedure, including reviewer selection and
   the rotation schedule, lives in the private
   `relay-platform/ops/runbooks/trust-anchor-witness-roster.md`.

A bundle without a valid `evidence_timestamps` row cannot be marked
active; the signer halts with `RELAY-EVID-031` (spec §AB rule). The
verifier output always includes `tsa_check: ok|invalid|missing` and
`log_inclusion: ok|absent|witness_mismatch` so the auditor can
distinguish a missing timestamp from a missing log entry from a
witness inconsistency.

Mirror and export: any party may mirror the public log. Compliance
customers may export their slice of the log (every entry whose
`bundle_id` is associated with their tenant) as evidence in an
auditor working paper. The mirror format is the same Merkle entry
schema as the live log; mirrors are not authoritative, but their
consistency with the live log can be checked at any time using the
published consistency proofs.

## Governance Process

Per spec §AO.3 step 1, this document is reviewed semi-annually. The
front-matter `last-reviewed-on` and `next-review-due` fields are
the authoritative record of the review cadence; a review that slips
the `next-review-due` date triggers an ops-tier alert. Per the
CLAUDE.md approval-workflow discipline, the `status` field declares
whether the document is `draft`, under `review`, in
`counsel-review-pending`, or `approved`. The v0.1 publication state
is `counsel-review-pending` per PW1-6.

Counsel review path (per PW1-6 and §AO.3 step 4):

- **Paid counsel: deferred.** Per PW1-6, no paid legal review is
  contracted for v0.1. The decision is explicit, not accidental:
  v0.1 ships as an OSS wedge with the doc as evidence of governance
  intent, not as a counsel-attested artifact.
- **Pro-bono counsel: solicited.** Per PW1-6 and §AO.3 step 4, the
  pro-bono counsel review path solicits review from AI policy
  nonprofits with a track record of AI governance review. The
  candidate set is, by name:
  - **BABL AI** — an AI policy nonprofit with audit-firm
    relationships and an active AI governance review practice.
  - **Holistic AI** — an AI governance reviewer with published
    technical assessments of AI systems.
  - **Credo AI** — a governance reviewer with explicit AI risk
    management methodology.
  Outreach is cold-email, requesting a review-only-no-publication
  SLA with the typical six-week turnaround. Until one of these
  reviewers responds and provides a written review, the
  `counsel-reviewer` front-matter field carries the value `pending`.
  When a reviewer accepts the engagement, the field is updated to
  the reviewer's organization name.
- **Counsel-review-pending status.** The document remains in
  `status: counsel-review-pending` until either (a) a pro-bono
  reviewer provides a written review whose findings are folded into
  the document, or (b) Relay-Inc retains paid counsel and the review
  completes. Until then, the document is published as-is on
  `relay.epochly.com/legal/trust-anchor-governance` with the
  front-matter status visible in the rendered header.

Approval workflow (per CLAUDE.md approval-workflow discipline):

1. The release-engineering lead drafts material changes in a feature
   branch on the public `relay` repository.
2. The harsh-critic agent reviews the diff for product-copy hygiene,
   factual claims against spec §AO, and link rot.
3. A security reviewer (named in `last-reviewed-by`) signs off on
   the cryptographic claims and the custody model.
4. If material to the legal posture of the trust anchor, the
   pro-bono counsel reviewer (when retained) reviews the diff
   before merge.
5. Merge updates the `last-reviewed-on` and `next-review-due`
   front-matter, with `next-review-due` set to no more than 180
   days after `last-reviewed-on` (the §AO.3 "Updated semi-annually"
   rule).

Standards engagement (per spec §AO.3 step 5): Relay-Inc submits the
evidence-bundle format and the trust-anchor architecture as a
reference implementation to relevant standards work (ISO/IEC JTC1
SC42, NIST AI Safety Institute, EU AI Office post-Omnibus). The
trust anchor wins durability when it is referenced by name in
regulatory guidance. Standards-engagement status is tracked in the
private `relay-platform/ops/standards-engagement.md`; the public
summary appears in the Relay annual evidence-bundle report.

## Fork Path (BYO Trust Anchor)

Per spec §AO.4 and CLAUDE.md banned pattern #13, the OSS
`relay-verifier` defaults to the Relay-Inc JWKS at
`relay.epochly.com/.well-known/jwks.json`. A fork or self-hoster who
wishes to operate their own trust anchor MUST use the BYO trust
anchor mechanism rather than patching the default.

BYO mechanism: the verifier supports a `--trust-anchor` CLI flag and
a `RELAY_TRUST_ANCHOR` environment variable, and reads a per-bundle
override from a verifier config file at
`~/.relay/verifier-config.yaml`. Any of these surfaces accepts
either (a) a JWKS URL, (b) a local path to a JWKS file for
air-gapped environments, or (c) a multi-anchor configuration list
for verifying bundles signed under multiple trust anchors. Example
invocations:

```
rly evidence verify --trust-anchor https://acme.example/.well-known/jwks.json bundle.zip
rly evidence verify --trust-anchor file:///opt/audit/acme-trust.json bundle.zip
RELAY_TRUST_ANCHOR=https://acme.example/.well-known/jwks.json rly evidence verify bundle.zip
```

The verifier surfaces the active trust anchor in its output (per
spec §K verifier output schema), so the auditor can distinguish a
Relay-anchored bundle from an ACME-anchored bundle in their working
paper.

Why BYO matters: a fork can ship the verifier configured against
their own JWKS. Contributors to the OSS code path do not get to
silently change the default trust anchor in the verifier binary;
the default is a board-level decision per CLAUDE.md banned pattern
#13. The CI guard `tests/contract/test_default_trust_anchor_guard.py`
(scheduled for W10 implementation) enforces that the verifier's
default trust anchor string equals `https://relay.epochly.com/.well-known/jwks.json`.
A PR that changes the default is rejected by the structural-review
gate.

What a fork inherits and does not inherit (per spec §AO.2 and §AO.4):

- A fork **inherits**: the verifier engine, the bundle format, the
  contract DSL, the cassette format, the CLI surface, the SDKs, the
  schemas, the evidence-bundle generator, the local sidecar, and
  every Apache 2.0-licensed artifact in the public `relay` repo.
- A fork **does not inherit**: Relay-Inc's signing keys, Relay-Inc's
  transparency log history, the TSA partnership contracts (Sigstore
  and Sectigo are independently available to the fork, but the
  partnership status is Relay-Inc-specific), the auditor and
  procurement-team default trust in `relay.epochly.com/.well-known/jwks.json`,
  the regulatory references that name Relay-Inc by name, and the
  cross-customer evidence baselines that compound with adoption.

Per spec §AO.2, each of these is an institutional asset, not a
technical one. They take months to years per auditor to accumulate
and they compound: once an auditor accepts a trust anchor by default,
switching is expensive. The fork inherits the code; the fork does
not inherit the trust anchor.

## Disclosure & Rotation Policy

Per spec §L.3 and §L.4, the rotation, revocation, and disclosure
posture of every Relay-Inc signing key is public, predictable, and
audit-friendly. The policy:

- **Scheduled rotation.** Every hosted signing key rotates on a
  twelve-month default cadence (spec §L.3). Rotation is two-phase:
  the new `signer_key_id` is created with
  `not_before = now + 24h`, published in JWKS, and only after the
  release engineer observes JWKS propagation at the Cloudflare edge
  is the predecessor key marked deprecated. Predecessor keys remain
  valid for verifying historical bundles in perpetuity unless
  revoked. The rotation schedule is published in the Relay release
  calendar at `https://relay.epochly.com/release-calendar/`.
- **Emergency rotation.** On suspected key compromise, the rotation
  schedule is preempted; the affected `signer_key_id` is revoked
  within four hours of confirmation; a new key is activated; a sev1
  incident is opened automatically. The full emergency-rotation
  runbook lives in `relay-platform/ops/runbooks/key-compromise.md`;
  the public summary is published on the Relay status page.
- **Revocation publication.** Revocation events are published at
  `https://relay.epochly.com/.well-known/revoked-keys.json` and in
  the verifier's `signer_key_revoked` output field. Auditors are
  notified by webhook (subscription model) and by an entry on the
  Relay status page. Auditors decide per audit policy whether to
  accept bundles signed before the revocation timestamp; the
  verifier surfaces `revoked_at` so the policy can be applied
  consistently.
- **Disclosure SLA.** A public incident write-up is published within
  72 hours of compromise confirmation. The write-up names the
  affected `signer_key_id`, the affected time window, the
  remediation, and the verifier behavior auditors should adopt for
  historic bundles signed by the compromised key. Where law or
  contract prohibits naming the root cause, the write-up names the
  category (operator error, third-party vulnerability, supply-chain
  attack) and the corrective action.
- **Cross-signing during transitions.** Per spec §L.5, bundles can
  carry up to four signatures; verifier reports `signatures_checked[]`
  with valid/invalid per signature. During a contested rotation or
  during the addition of a new BYO trust anchor as a default, the
  bundle generator may attach cross-signatures so that verifiers
  trusting either anchor can validate the bundle without coordination.

Documentation cross-references (per spec §AO.3 step 1):

- The release pipeline that produces the signed artifacts is
  described in [`../release/runbook.md`](../release/runbook.md).
- The Sectigo TSA fallback activation procedure is described in
  [`../release/sectigo-tsa-fallback.md`](../release/sectigo-tsa-fallback.md).
- The OSS-facing release stub of this document is at
  [`../release/trust-anchor-governance.md`](../release/trust-anchor-governance.md);
  it points readers to this file as the authoritative public version.
- The public verifier source lives under `packages/verifier/`; see
  [`../../SECURITY.md`](../../SECURITY.md) for the supported-version
  policy and the security-disclosure channel.
- Spec sections are anchored in `planning/epochly-replay-spec.md` in
  the workspace parent (one directory above this `relay/` repository);
  §AO.1, §AO.2, §AO.3, §AO.4, §AB, §L.1, §L.2, §L.3, §L.4, §L.5, and
  §K are the load-bearing sections for this document. The workspace-
  parent path is not a relative markdown link because it intentionally
  references a sibling repository outside the `relay/` tree (CLAUDE.md
  Project Structure).

External references (no network probe is performed in tier-1
plumbing tests; the canonical, externally-resolvable URLs are
recorded here for the auditor's convenience):

- JWKS endpoint: [https://relay.epochly.com/.well-known/jwks.json](https://relay.epochly.com/.well-known/jwks.json)
- Public verify endpoint: [https://relay.epochly.com/verify](https://relay.epochly.com/verify)
- Sigstore TSA: [https://timestamp.sigstore.dev/api/v1/timestamp](https://timestamp.sigstore.dev/api/v1/timestamp)
- Sigstore Rekor (design reference): [https://docs.sigstore.dev/logging/overview/](https://docs.sigstore.dev/logging/overview/)
- RFC 3161 (Time-Stamp Protocol): [https://www.rfc-editor.org/rfc/rfc3161](https://www.rfc-editor.org/rfc/rfc3161)
- RFC 6962 (transparency log Merkle-tree design reference): [https://www.rfc-editor.org/rfc/rfc6962](https://www.rfc-editor.org/rfc/rfc6962)

---

Changelog (most recent first):

- 2026-05-16 — Initial publication as part of the W13 deliverable
  of the Relay v0.1 OSS wedge. Status set to
  `counsel-review-pending` per PW1-6; pro-bono outreach to BABL AI,
  Holistic AI, and Credo AI scheduled. Authors: Relay-Inc release
  engineering; reviewers: Relay-Inc security review (internal). Next
  review due 2026-11-12.
