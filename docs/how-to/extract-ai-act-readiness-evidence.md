# How to Extract AI Act Readiness Evidence

This guide is for a compliance officer preparing material for auditor review
against the EU AI Act. It walks from a fresh Relay project to a signed
evidence bundle that an auditor can verify on their own hardware. It does
not produce a legal determination; it produces evidence the auditor uses
as the input to their review.

The product copy rules in spec section J.5 govern this entire workflow.
Permitted language used throughout this page: "readiness evidence",
"evidence coverage", "gaps", "ready for auditor review". The page never
makes claims of legal status, of certification, or of approval. Per spec
section J.3 a Relay bundle is the input to counsel review, not its
conclusion.

## Persona

You are the compliance officer (or auditor liaison) for an organisation
that ships an AI system. Your job is to produce, on demand, a signed
artifact that demonstrates which obligations have evidence captured
against them and where the gaps are. You are not asked to render a legal
opinion; the auditor and counsel render those. You are asked to deliver
the underlying evidence in a form the auditor can verify without your
help.

## What this guide produces

A single signed evidence bundle (the file produced by `rly verify-self`,
or by an eval-run that completes and emits an `evidence_bundle_id`). The
bundle contains:

- A set of typed evidence claims per spec section K, each bound to an
  artifact digest, a command + exit code, trace span IDs, contract
  assertion IDs, a manifest commit hash, and the redaction policy version
  in force when the claim was captured.
- A Merkle root over all claims.
- A JWS signature anchored to the trust anchor named in the bundle's
  `trust_anchor` field. The default trust anchor URL is the spec-pinned
  `https://relay.epochly.com/.well-known/jwks.json` declared in
  `DEFAULT_TRUST_ANCHOR_URL` in
  `packages/verifier/src/relay_verifier/constants.py`. Per CLAUDE.md
  keystone invariant #13 and spec section AO.4, changing this default is
  a board-level decision; forks and self-hosters use the
  `--trust-anchor` flag to point at their own JWKS.

This bundle, plus the JWKS cache the auditor uses to verify it, is the
deliverable. Everything else in this guide is the means of producing it.

## Step 1: identify which Article obligations apply

Before producing evidence you need a written record of which AI Act
obligations apply to the system in scope (role classification: provider,
deployer, importer, distributor, GPAI provider, etc.) and which risk
category the system sits in (prohibited, high-risk Annex III, high-risk
Annex I safety component, limited-risk transparency, minimal risk, GPAI,
GPAI systemic risk).

The public stub at
[`../compliance/eu-ai-act.md`](../compliance/eu-ai-act.md) is the
pointer page. It enumerates the operational scope Relay supports today
(the ACEF template at
`packages/acef/upstream/src/acef/templates/eu-ai-act-2024.json` is the
machine-readable list of Annex IV section identifiers and per-section
evidence claim shapes Relay recognises). The counsel-grade Annex IV
mapping that interprets the AI Act for your specific system is
publication-gated and lives in the private `relay-platform` tree per
spec section J. Until that mapping ships publicly, you complete the
role and risk-category classification with counsel and record the
decision outside of this OSS workflow.

The output of this step is a written role + risk-category
classification you can hand to the auditor alongside the evidence
bundle. Without it the bundle has no scope.

## Step 2: configure the redaction policy

Evidence claims captured under the wrong redaction policy are not
auditor-ready: either they leak material the policy must redact, or
they redact material the auditor needs to see. Configure the policy
before you start capturing claims so every claim binds to a policy
version your counsel has approved.

The how-to for redaction policies lives in
[`write-redaction-policy.md`](write-redaction-policy.md) (sibling page;
lands in this milestone). The relevant rule for the AI Act workflow:
`raw_capture: true` is default-deny per CLAUDE.md keystone invariant #7.
Enabling it requires a signed Data Processing Agreement on file and an
org-admin approver recorded on the policy version. For most AI Act
workflows you do not need `raw_capture`; the bound, redacted claim is
sufficient.

Confirm the policy version that will apply to your evidence by listing
your current bundles and reading the `redaction_policy_version` field
on each claim (see Step 4 below for how the bundle is structured).

## Step 3: run the evaluation suite

Run the evaluation suite that exercises the AI system end to end. The
canonical OSS command is `rly eval run --dataset <id>`. See the CLI
reference at [`../reference/cli/eval/run.md`](../reference/cli/eval/run.md)
for the full surface. Each `rly eval run` invocation:

- Creates an eval-run record via the local sidecar
  (`POST /v1/eval-runs`).
- Polls until the run reaches a terminal state.
- Emits a `relay.cli.eval_run.v1` envelope on stdout. The envelope's
  `evidence_bundle_id` field is the id of the bundle that captures the
  run's claims. The CLI never fabricates a bundle id; if the run has
  not produced one the envelope's `evidence_bundle_id` is `null` and
  the CLI exits non-zero per spec section K binding rules and CLAUDE.md
  keystone invariant #2 ("pass without evidence is not a pass").

You may run multiple eval datasets to cover different obligations
(accuracy, robustness, security, human oversight, transparency). Each
run produces a bundle id you carry forward into Step 4.

## Step 4: produce the evidence bundle

A Relay evidence bundle is produced by the same control plane that
captures the underlying claims; the CLI does not have a free-standing
"create a bundle from arbitrary inputs" command, and that is by design
(claims must be bound to artifacts and commands at the moment they are
captured, not retroactively assembled).

For workflows that need a system-wide invariant bundle (for example to
show coverage of the cross-cutting controls Relay itself enforces)
`rly verify-self` runs every checked invariant and writes a
spec-section-K-conformant evidence bundle to
`${RELAY_HOME}/evidence/<bundle_id>.json` on every invocation. Exit 0
indicates every invariant is green; exit 1 indicates one or more
failures with a structured stderr envelope. See the CLI reference at
[`../reference/cli/verify-self.md`](../reference/cli/verify-self.md).

For workflows that need an eval-scoped bundle the bundle id is the
`evidence_bundle_id` returned by `rly eval run` in Step 3.

List all locally available bundles to confirm what you have:

```
rly evidence list
```

See [`../reference/cli/evidence/list.md`](../reference/cli/evidence/list.md)
for filter and pagination flags. Inspect a single bundle's full JSON via
`rly evidence show <id>`; see
[`../reference/cli/evidence/show.md`](../reference/cli/evidence/show.md).

For every claim in every bundle that will go to the auditor, confirm
the binding fields are populated: artifact digest, command + exit
code, span IDs, assertion IDs, manifest commit hash, and redaction
policy version. A claim with any of these missing is `invalid` per
spec section K and the bundle will not verify; see
[`../evidence/claim-binding.md`](../evidence/claim-binding.md) for the
full pairing rule.

## Step 5: verify offline

Verify each bundle yourself before handing it to the auditor. The OSS
verifier is offline by design: it never opens an outbound socket and
reads the JWKS only from the local cache at
`${RELAY_HOME}/jwks-cache/<host>.json`. The CLI reference is at
[`../reference/cli/evidence/verify.md`](../reference/cli/evidence/verify.md);
the full offline lifecycle (cache the JWKS once, carry both the bundle
and the cache to an auditor workstation) is documented at
[`../evidence/offline-verification.md`](../evidence/offline-verification.md).

Exit 0 from `rly evidence verify` means the bundle's digests are intact
and its signatures validate against the cached JWKS for its declared
trust anchor. Any non-zero exit means the bundle has been tampered with,
the JWKS is missing or wrong, or the signing key has been revoked; do
not deliver a bundle that does not verify.

## Step 6: hand to auditor

Deliver three things to the auditor:

- The bundle file (`<bundle_id>.json`).
- The cached JWKS the bundle's `trust_anchor` field points at
  (`${RELAY_HOME}/jwks-cache/<host>.json`). Auditors who prefer to
  fetch the JWKS themselves from the trust-anchor URL on a connected
  machine may skip this; auditors verifying on air-gapped hardware
  must receive it.
- The written role and risk-category classification from Step 1.

The auditor runs `rly evidence verify` on their own hardware. The
verifier returns a `VerificationResult` whose fields document what was
checked; the auditor reads those fields and reaches their own
acceptance decision. The auditor walkthrough lives at
[`verify-bundle-offline.md`](verify-bundle-offline.md) (sibling page;
lands in this milestone).

## What this does and does not do

What this workflow does:

- Produces a signed evidence artifact that an auditor can verify
  byte-for-byte on hardware you do not control.
- Surfaces evidence coverage and gaps against the Annex IV section
  identifiers the ACEF template recognises.
- Binds every claim to the artifact, command, exit code, span IDs,
  assertion IDs, manifest hash, and redaction policy version that
  anchor it.
- Gives counsel and the auditor a deterministic input they can use to
  reach a readiness conclusion.

What this workflow does not do:

- It does not produce a legal determination. The bundle is evidence;
  the auditor and counsel reach the determination.
- It does not include the counsel-grade Annex IV interpretation that
  maps your specific system to specific clauses; that ships behind
  spec section J as part of `relay-platform`.
- It does not make any claim about the legal status of a deployed
  model or AI system.

## See also

- [`../compliance/eu-ai-act.md`](../compliance/eu-ai-act.md) -- the
  public pointer page for AI Act scope and the upstream ACEF template.
- [`../evidence/bundle-anatomy.md`](../evidence/bundle-anatomy.md) --
  the JWS payload structure and claim layout of a Relay bundle.
- [`../evidence/claim-binding.md`](../evidence/claim-binding.md) --
  the spec section K pairing rule every claim must satisfy.
- [`../evidence/offline-verification.md`](../evidence/offline-verification.md)
  -- the full offline `rly evidence verify` lifecycle.
- [`write-redaction-policy.md`](write-redaction-policy.md) -- redaction
  policy configuration (sibling; lands in this milestone).
- [`verify-bundle-offline.md`](verify-bundle-offline.md) -- the auditor
  persona walkthrough (sibling; lands in this milestone).

---

Spec: §J, §K
