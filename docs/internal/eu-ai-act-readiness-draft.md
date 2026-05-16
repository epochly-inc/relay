---
status: internal-only
audience: internal
publication-gated: true
gating-conditions:
  - "paid counsel review (deferred for v0.1 per PW1-6)"
  - "pro-bono counsel review accepted and folded into the document"
  - "self-publication with explicit no-legal-advice disclaimer (PW1-6 self-publication path #3)"
counsel-reviewer: pending
last-reviewed-by: Chandler Vaughn (Relay-Inc readiness mapping authoring)
last-reviewed-on: 2026-05-16
next-review-due: 2026-11-12
spec-anchors:
  - "planning/epochly-replay-spec.md section AI Act readiness mapping (the four sub-sections that ship the readiness model)"
  - "planning/epochly-replay-spec.md decision PW1-6"
---

# EU AI Act Readiness Draft (Internal Only)

> Internal-only draft of the Relay EU AI Act readiness mapping. This
> document expresses the Relay product as a generator of AI Act
> **readiness evidence** for auditor review; it does not make and
> never will make any certification claim. It is the working draft
> behind the eventual public readiness mapping, and it is the
> authoritative internal reference for the Article coverage map, the
> two-timeline scenario model, and the publication-gating policy.

This document is the W14 deliverable for the Relay v0.1 OSS wedge
(eng plan W14; CEO plan cherry-pick #5 fallback) and the working
draft behind the public AI Act readiness mapping that will publish
only after the publication-gating conditions enumerated in the
front-matter are satisfied. Until then, the document is DRAFT, NOT
PUBLISHED, INTERNAL REVIEW ONLY — see the Reviewer Path section
below.

## Status: Internal Only

**This is an INTERNAL document. Do not link from any customer-facing
surface (website, marketing materials, sales decks, dashboards, CLI
output) and do not share with prospects, customers, partners, or
press without explicit director-level approval per PW1-6.**

The Relay EU AI Act readiness mapping is a load-bearing artifact for
the compliance product surface that lands in the commercial
`relay-platform` repository. Per PW1-6 the v0.1 release ships the
**doc-first** mapping as an internal draft; the public publication
gate is opened only when one of the three conditions in the
front-matter `gating-conditions` field is met. Until then this draft
serves three internal purposes only:

1. It is the source-of-truth working draft for the Article-to-Relay
   mapping that the platform compliance surface implements.
2. It is the artifact a pro-bono reviewer reads when the cold-email
   outreach detailed in the Reviewer Path section yields an accepted
   engagement.
3. It is the document that Relay-Inc legal counsel (when retained)
   will counsel-review before any externally-visible AI Act readiness
   evidence claim is published from a Relay surface.

> **Disclaimer (mandatory placement at top of document body).** This
> document is **not legal advice**, does not constitute legal advice,
> and is not a substitute for legal advice. Nothing in this document
> may be relied on by any customer, prospect, partner, or third party
> as a legal opinion about the EU AI Act or any other regulation.
> Customers must obtain their own counsel review before relying on
> any Relay evidence, mapping, or readiness evidence surface in
> support of an EU AI Act readiness claim. The Relay product
> generates **readiness evidence** for auditor review; it does not
> issue certifications and does not, by issuing an evidence bundle,
> make a legal determination about the customer's regulatory
> posture. Per PW1-6 the document is published as DRAFT, NOT
> PUBLISHED, INTERNAL REVIEW ONLY until a publication-gating event
> occurs. (Spec § AI Act readiness mapping, §J.5; PW1-6.)

The document's status field in the front-matter is
`status: internal-only`; its `publication-gated` field is `true`;
its `gating-conditions` field enumerates the three publication
conditions per PW1-6 (paid counsel review, pro-bono counsel review,
self-publication with explicit no-legal-advice disclaimer). A reader
who finds this document outside `relay/docs/internal/` has
encountered a publication-discipline violation and should report it
to the Relay-Inc release engineering team.

## Scope

The Relay product expresses customer evidence for **EU AI Act
readiness evidence** (per the spec § AI Act readiness mapping; §J.5
permitted framing), never **certification**. The product surfaces
that participate in the readiness mapping are exactly the surfaces
defined by the spec § AI Act readiness mapping (sub-sections J.1
through J.5):

- **§J.1 — current legal state.** The two-timeline scenario model
  for AI Act applicability (original timeline vs Digital Omnibus
  amended timeline). See the date enumeration in the Reviewer Path
  section and the Two-Timeline Scenarios section below.
- **§J.2 — role classification workflow.** Per-AI-system
  self-attestation that the customer completes; Relay stores the
  attestation in the `ai_system_classifications` table per the
  schema declared in the spec § AI Act readiness mapping.
- **§J.3 — Article coverage map.** The Article-to-Relay-surface
  mapping enumerated in the Evidence Coverage by Annex IV Category
  section below.
- **§J.4 — edge cases.** Role-change, Omnibus mid-engagement
  adoption, GPAI threshold change, contested Art. 6(3) high-risk
  exception, withdrawn classifications, legal-hold conflicts, wrong
  self-attestation, watermarking-deadline acceleration, and offline
  trust-anchor fallback — all enumerated as named handlings in the
  spec.
- **§J.5 — forbidden product copy.** Customer-facing surfaces never
  contain the banned terms enumerated in spec §J.5; permitted framing
  is "AI Act readiness evidence", "evidence coverage", "gaps", and
  "ready for auditor review". A CLI lint rule enforces this
  invariant against shipping diffs (see CLAUDE.md §J.5 and banned
  pattern #9).

**Out of scope for this readiness mapping (v0.1):**

- Conformity assessment under Art. 28 — Relay points to an external
  CAB report; Relay does not perform conformity assessment.
- Fundamental Rights Impact Assessment (FRIA) authoring under
  Art. 27 — Relay surfaces a missing-FRIA indicator on the readiness
  dashboard for deployer-classified projects; Relay does not author
  the FRIA itself.
- Counsel sign-off — the v0.1 doc is DRAFT, NOT PUBLISHED, INTERNAL
  REVIEW ONLY per PW1-6 and below in Reviewer Path.

**Two-timeline scenarios (per spec § AI Act readiness mapping, §J.1).**
The Relay readiness mapping ships with two scenarios visible to
customers: the original 2 Aug 2026 timeline and the Digital Omnibus
amended timeline. Customers select the operative scenario for each
project; the default is "original timeline until Omnibus formally
adopted." The five load-bearing dates that the mapping enumerates
are:

1. **2 Aug 2026** — original high-risk Annex III obligations + Art. 50
   transparency deadline. Still technically in force pending Digital
   Omnibus formal adoption.
2. **2 Dec 2026** — Omnibus-amended watermarking deadline pulled
   forward + new CSAM-creation ban deadline.
3. **2 Aug 2027** — GPAI obligation date (explicit per spec § AI Act
   readiness mapping §J.1). The GPAI provider obligation date is the
   single date most likely to be omitted from a one-timeline
   document; per the readiness mapping it MUST be enumerated whether
   or not the Omnibus is formally adopted.
4. **2 Dec 2027** — Omnibus-amended Annex III high-risk obligations
   deadline (the principal Omnibus delay).
5. **2 Aug 2028** — Omnibus-amended Annex I high-risk
   safety-component deadline.

A single-timeline document does not satisfy the readiness mapping;
any project whose readiness dashboard omits one of the five dates
fails the §J.1 timeline-scenario invariant.

## Evidence Coverage by Annex IV Category

The Article-to-Relay-surface mapping below is a direct lift of the
spec § AI Act readiness mapping §J.3 Article coverage map. Each row
binds an Annex IV technical-documentation obligation to a Relay
evidence-claim type or bundle profile. The Relay surface column
names the claim type, bundle profile, or pointer-record exactly as
it appears in the spec; the spec is authoritative if any divergence
is observed.

The internal evidence-claim type names below are quoted from the spec
§ AI Act readiness mapping and from the Evidence Claim v1 schema. A
Relay surface citation in this section is a backtick-quoted claim
type, bundle profile, or pointer record. The §J.3 baseline density
is one Relay surface citation per Article row; this document
preserves that density.

| Annex IV / AI Act obligation | Required evidence | Relay surface |
| --- | --- | --- |
| Art. 9 risk management system | Risk register entries, mitigation records, periodic review evidence. | `governance_policy` evidence claims; ops-run records of mitigation rounds. |
| Art. 10 data and data governance | Training data summary, lineage, quality checks. | `data_provenance`, `data_quality_check` evidence claims. |
| Art. 11 technical documentation (Annex IV dossier) | Annex IV-style dossier. | Evidence bundle profile `eu-ai-act:annex-iv`. |
| Art. 12 record-keeping | Logs adequate to traceability. | Trace + `run_result` + `gate_decision` chained via three-anchor handoffs. |
| Art. 13 transparency and instructions to deployer | Instructions-for-use document; system behavior expectations. | `instructions_for_use_ref` on classification + signed customer-issued document. |
| Art. 14 human oversight | Human-in-the-loop records, escalation logs. | `human_oversight` claims linked to runs. |
| Art. 15 accuracy, robustness, cybersecurity | Eval coverage; security test results. | `eval_run` summaries + signed security review notes. |
| Art. 26 deployer obligations | 6-month log retention; oversight assignment; affected-person notifications. | Configurable retention >= 6 months for deployer-classified projects; default retention raised automatically when classification = deployer. |
| Art. 27 FRIA | Fundamental Rights Impact Assessment for specific deployers. | `fria_evidence_ref`; readiness dashboard surfaces missing FRIA when required. |
| Art. 28 provider conformity | Conformity assessment evidence; EU database registration. | Pointer to external CAB report; Relay does not perform conformity assessment. |
| Art. 50 transparency | Synthetic content labelling, AI-system disclosure to users. | `transparency_marking`, `disclosure_labeling` claims. |
| Art. 51 to Art. 55 GPAI | Tech doc, training data summary, copyright reservation, systemic-risk model evidence. | `gpai_annex_xi_model_doc` claims. |
| Art. 73 serious incidents | Reporting workflow with thresholds. | `incidents` rows promoted to "serious incident" require human acknowledgement; export forms generated. |

Notes on the table above:

- Each Article row pairs the obligation with a Relay-side
  evidence-claim type or bundle profile per spec § AI Act readiness
  mapping §J.3. The Relay surface column is the source of truth for
  the bindings the platform compliance product will implement.
- The Art. 51 to Art. 55 row is the GPAI cluster; the cluster maps to
  a single Relay evidence-claim type (`gpai_annex_xi_model_doc`)
  per the spec.
- The Art. 28 pointer-only treatment is intentional: Relay does not
  perform the conformity assessment itself. The pointer record is
  the Relay surface that binds the external CAB report to the
  project.
- The Art. 27 FRIA surface is a `fria_evidence_ref` pointer record;
  Relay surfaces a missing-FRIA indicator on the readiness dashboard
  for deployer-classified projects but does not author the FRIA.

The §J.3 mapping is the authoritative source. Where the platform
implementation diverges from the spec § AI Act readiness mapping
§J.3 mapping above, the spec wins and the divergence is a P0 bug to
surface immediately.

## Gaps

The following gaps in evidence coverage are known and tracked. A
"gap" is an Annex IV obligation for which a Relay-side
evidence-claim type is either (a) declared in the spec but not yet
implemented in the OSS or platform runtime, or (b) outside the
boundary of what Relay can structurally provide. The Relay
readiness dashboard surfaces gaps to the customer; per the
permitted framing in spec § AI Act readiness mapping §J.5, the
product describes them as "gaps" so the customer and the customer's
counsel can act on them.

The v0.1 known-gap list:

- **GPAI Code of Practice alignment.** The AI Office GPAI Code of
  Practice status is not confirmed as of the document's review date
  (per spec § AI Act readiness mapping §J.1). Until the Code is
  finalised, the Relay GPAI mapping ships against the Art. 51 to
  Art. 55 statutory text only; alignment with the Code of Practice
  is a tracked gap.
- **AI Office formal classification guidance.** The Provider /
  Deployer / GPAI classification guidance is listed as "upcoming"
  in the Commission Press Corner 7 May 2026 statement; until formal
  guidance lands, the Relay role-classification workflow per spec
  § AI Act readiness mapping §J.2 surfaces a banner when the
  classification depends on contested guidance.
- **Art. 27 FRIA authoring.** Relay does not author the FRIA; Relay
  surfaces a missing-FRIA indicator. Customers must obtain a FRIA
  authored by their own counsel or by an external assessor; the
  Relay readiness dashboard exposes this as a gap on
  deployer-classified projects where the `fria_required` flag is
  true.
- **Art. 28 conformity assessment.** Relay does not perform
  conformity assessment. The Relay surface is a pointer record to an
  external CAB report; the absence of a pointer is reported as a
  gap on the readiness dashboard.
- **Watermarking under accelerated 2 Dec 2026 deadline.** If the
  Digital Omnibus formally accelerates Art. 50 watermarking to
  2 Dec 2026, the watermarking-evidence collection becomes P0 for
  affected systems. The spec keeps a feature flag so the readiness
  scope can flip without code changes; the flag default is "track
  per original timeline until Omnibus formally adopted." Until the
  feature flag is flipped, the readiness dashboard reports the
  Art. 50 watermarking surface against the original timeline.
- **Counsel sign-off on the readiness mapping itself.** Per PW1-6
  the v0.1 doc is DRAFT, NOT PUBLISHED, INTERNAL REVIEW ONLY. The
  absence of counsel sign-off is a gap that the Reviewer Path
  section below tracks.

Each gap above is surfaced through the readiness dashboard as a
"ready for auditor review" indicator with the gap explicitly named;
no readiness surface declares an Article green when a gap is
present. The "ready for auditor review" framing is the permitted
phrasing per spec § AI Act readiness mapping §J.5 and the framing
the Relay product uses on customer-facing surfaces.

## Reviewer Path

Per PW1-6 the v0.1 readiness mapping is DRAFT, NOT PUBLISHED,
INTERNAL REVIEW ONLY. The document remains internal until one of
three publication-gating conditions is satisfied (see the
front-matter `gating-conditions` field for the canonical
enumeration):

1. **Paid counsel** review completes (deferred for v0.1).
2. **Pro-bono** counsel review accepted and the reviewer's findings
   are folded into the document.
3. **Self-publication** with an explicit no-legal-advice disclaimer
   (PW1-6 self-publication path #3; see the Status: Internal Only
   section's disclaimer block).

The v0.1 path is the pro-bono path; the self-publication path is the
explicit fallback if no pro-bono reviewer responds within a
reasonable window.

**No paid counsel for v0.1 (per PW1-6).** No paid counsel review is
contracted for the v0.1 readiness mapping. The decision is explicit,
not accidental: v0.1 ships as an OSS wedge with the doc as evidence
of governance intent, not as a counsel-attested artifact. The
absence of paid counsel review for v0.1 is itself recorded in the
front-matter `counsel-reviewer` field (value: `pending`) and is
re-evaluated at each semi-annual review cycle (see front-matter
`next-review-due`). The "no paid counsel" position is a deliberate
v0.1 choice per PW1-6; later releases may revisit this.

**Pro-bono counsel review path (per PW1-6).** The pro-bono review
path solicits review from AI policy nonprofits with a track record
of AI governance review. The candidate set, by name:

- **BABL AI** — an AI policy nonprofit with audit-firm
  relationships and an active AI governance review practice.
- **Holistic AI** — an AI governance reviewer with published
  technical assessments of AI systems.
- **Credo AI** — a governance reviewer with explicit AI risk
  management methodology and a published assessment framework.

Outreach is cold-email, addressed to the reviewer's published intake
address, requesting a review-only-no-publication SLA. The
review-only-no-publication SLA terms are: (a) the reviewer reads
the draft, (b) the reviewer returns written findings to Relay-Inc,
(c) Relay-Inc folds the findings into the document and credits the
reviewer in the `counsel-reviewer` front-matter field, and (d) the
reviewer does not publish, re-publish, blog about, or otherwise
disclose the draft until Relay-Inc publishes the public readiness
mapping. The typical turnaround for an AI policy nonprofit on a
review of this scope is approximately **six-week** (six weeks); the
intake SLA is set to "respond within two weeks; deliver within six
weeks of intake confirmation." A cold-email approach is the only
realistic v0.1 channel; the budget does not support a paid-counsel
engagement.

Until one of the three pro-bono reviewers responds and provides a
written review, the `counsel-reviewer` front-matter field carries
the value `pending`. When a reviewer accepts the engagement, the
field is updated to the reviewer's organization name (one of `BABL
AI`, `Holistic AI`, `Credo AI`). When a reviewer's findings are
folded into the document, the `status` field flips out of
`internal-only` only by the explicit publication-gating workflow
referenced by PW1-6.

**Self-publication fallback (per PW1-6 path #3).** If no pro-bono
reviewer responds within a window of reasonable retry attempts, the
document MAY be self-published under the explicit no-legal-advice
disclaimer enumerated in the Status: Internal Only section above.
The self-publication path explicitly retains the "DRAFT, NOT
PUBLISHED, INTERNAL REVIEW ONLY" markers until the moment of
publication, at which point the markers transition to "draft for
public review under no-legal-advice disclaimer" and the document
moves out of `relay/docs/internal/` to its public publication path.

**Document state markers (canonical literals).** Until a
publication-gating event occurs, the document is, in this exact
casing:

- **DRAFT** — the document is a draft, not a finalised mapping.
- **NOT PUBLISHED** — the document is not published to any
  customer-facing surface.
- **INTERNAL REVIEW ONLY** — the document is for internal review
  only, including by pro-bono reviewers under the
  review-only-no-publication SLA above.

These three literal markers MUST appear in this Reviewer Path
section in the casing above; the doc-content test
`test_w14_010_no_paid_counsel_position` enforces literal-substring
presence per VAL-W14-010.

**Publication-gating workflow.** The publication-gating workflow is
the explicit transition from `status: internal-only` to a published
state. The workflow is one of: (a) **paid counsel** review completes
and signs off (deferred for v0.1); (b) **pro-bono** counsel review
completes and the reviewer's findings are folded in; or
(c) **self-publication** with the explicit no-legal-advice
disclaimer. Any other transition is a publication-discipline
violation.

**Related governance documents.**

- See [trust-anchor governance](../legal/trust-anchor-governance.md)
  for the parallel doc-first governance scaffolding for the Relay
  trust anchor (the spec § Trust Anchor sections governance
  artifact); the trust-anchor doc shares the pro-bono reviewer
  candidate set and the same v0.1 no-paid-counsel posture.
- The authoritative readiness mapping (§J.1, §J.3, §J.5) lives in
  the workspace-parent spec file at
  `planning/epochly-replay-spec.md` (relative to the workspace
  parent `epochly-relay/`; the file is in a separate private
  workspace repo per the CLAUDE.md "Repository Topology" section
  and is not linked here because it sits outside the `relay/`
  Apache-2.0 boundary).
- The workspace governance directory at `planning/` (workspace
  parent) holds ADRs and decision logs; same boundary rule applies.

**External anchor references** (cited for reviewer context; archive
dates noted because law-and-regulation pages move):

- AI Act Service Desk (Commission portal):
  <https://artificialintelligenceact.eu/> [archive: 2026-05-12]
- Commission Press Corner, 7 May 2026 (Digital Omnibus political
  agreement):
  <https://ec.europa.eu/commission/presscorner/home/en>
  [archive: 2026-05-12]

Reviewer questions, corrections, and findings: email
<readiness-review@epochly.com> (internal alias routed to Relay-Inc
release engineering for triage).
