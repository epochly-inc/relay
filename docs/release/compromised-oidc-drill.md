# Compromised-OIDC Drill (VAL-W12-041)

Authoritative procedure for responding to a compromised GitHub Actions
OIDC identity binding used by the Relay release pipeline. Per PW1-7
the release engineer (Chandler) owns "compromised-OIDC response" as
scope. Per contract assertion VAL-W12-041 this runbook entry MUST
exist AND have been rehearsed in a tabletop drill BEFORE the first
signed release ships.

This document is the source of truth; the release runbook at
`docs/release/runbook.md` cross-references it under the
"## Compromised OIDC response" heading.

## Scope

The compromised-OIDC scenario covers any of:

  1. A GitHub Actions workflow file in `epochly-inc/relay` (or a
     reusable workflow it consumes from `slsa-framework/`) is modified
     to issue a release with attacker-controlled content while
     presenting a valid OIDC identity to PyPI / npm / Sigstore Fulcio.
  2. An OIDC token issued by `https://token.actions.githubusercontent.com`
     bound to one of our trusted-publisher configurations is exfiltrated
     and reused by an attacker before its short-lived expiry.
  3. The PyPI / npm trusted-publisher binding itself is widened (a
     misconfiguration or attacker action that allows an unintended
     workflow or environment to receive publish tokens).
  4. The Sigstore Fulcio root trust is compromised (rare; see the
     Sigstore project's response runbook for the upstream procedure).

## Response steps

The response is a strict four-step sequence. Each step has an owner,
an expected duration, and a verification artifact that proves the step
completed.

### Step 1 -- Revoke the offending OIDC identity binding

Owner: release engineer.
Expected duration: 15 minutes.

  1. Sign in to PyPI as a maintainer of `epochly-relay`. Navigate to
     "Manage" -> "Publishing" and remove the affected trusted-publisher
     entry. If unsure which entry is compromised, remove all of them
     pending investigation -- this is safer than leaving a hot binding
     active.
  2. Sign in to npmjs.com as an owner of `@epochly/relay` and
     `@epochly/relay-sidecar-bundle`. Navigate to package settings ->
     "Trusted Publishers" and remove the affected GitHub Actions
     binding. As above, remove all of them if unsure.
  3. In `epochly-inc/relay` repo settings, navigate to "Environments"
     -> "release" and disable the environment temporarily (set
     `deployment branches` to `<none>`). This blocks any in-flight
     workflow run from reaching the publish step.

Verification artifact: screenshots of the PyPI/npm publishing
settings pages showing zero trusted publishers configured; GitHub API
output of `GET /repos/epochly-inc/relay/environments/release`
returning `protection_rules: []`.

### Step 2 -- Rotate impacted Sigstore Fulcio root anchors if needed

Owner: release engineer + security counsel.
Expected duration: 1-2 hours.

  1. If the compromise is scoped to the OIDC binding only (cases 1-3
     above), no Fulcio root rotation is required: short-lived Fulcio
     certs naturally expire within 10 minutes and the Rekor inclusion
     proof still binds the signature to the (now revoked) GitHub OIDC
     identity. Attestation that "the binding was revoked at timestamp
     T" is the verification artifact.
  2. If the compromise is scoped to the Sigstore Fulcio root trust
     itself (case 4), coordinate with the Sigstore project's incident
     response (per their SECURITY.md). Relay does NOT operate a
     private Fulcio; rotating the root trust is upstream's
     responsibility. Document the upstream incident ticket ID in our
     advisory.

Verification artifact: incident ticket ID (ours and/or upstream's),
plus a follow-up Rekor lookup proving any subsequently-issued
attestations are bound to a fresh OIDC identity.

### Step 3 -- Issue a security advisory

Owner: release engineer + comms.
Expected duration: 2 hours from detection.

  1. Publish a GitHub Security Advisory on `epochly-inc/relay` with:
       - the affected version range
       - the compromised OIDC binding (workflow file + environment)
       - the timestamp window of suspected unauthorized publish activity
       - mitigation: pin to last-known-good version pre-window, or wait
         for the next clean release
  2. If PyPI/npm distributions were published under the compromised
     binding within the window, yank the affected versions on PyPI
     (advisory-only) and request npm deprecate (npm unpublish within
     the 72-hour window is BLOCKED by our runbook per VAL-W12-039;
     deprecate is the substitute).
  3. Post the advisory link to the status page and the
     announcements directory under `docs/release/announcements/`.

Verification artifact: GitHub Security Advisory URL; PyPI yank
confirmation; npm deprecate confirmation.

### Step 4 -- Publish a new release with a clean OIDC binding

Owner: release engineer.
Expected duration: 4-6 hours from detection.

  1. In the `epochly-inc/relay` repo, audit `.github/workflows/` for
     unauthorized modifications. Revert to a known-good commit.
  2. Re-create the PyPI trusted-publisher binding (Manage ->
     Publishing -> Add new) with the canonical scope (repo:
     epochly-inc/relay, workflow: release-pypi.yml, environment:
     release). For npm, re-create the Trusted Publisher binding with
     the equivalent scope per the sister release workflows.
  3. Re-enable the `release` environment in repo settings with the
     standard protection rules (required reviewers, deployment branches
     restricted to protected tags).
  4. Tag and push a new patch-level version. The version increment is
     monotonic per VAL-W12-040 -- never reuse the compromised version
     tag.
  5. Verify the new release via `rly verify-install` end-to-end (per
     sub-feature w12.6); attach the verification JSON to the advisory.

Verification artifact: new release tag URL; `rly verify-install`
output showing all three checks pass; trusted-publisher reconfiguration
confirmation.

## Tabletop drill cadence

Per VAL-W12-041 a tabletop drill record MUST exist at
`docs/release/drills/<YYYY-MM-DD>-compromised-oidc-drill.md` before
the first tagged release ships. The drill walks through steps 1-4
above against a hypothetical scenario; the record captures observed
gaps and remediation items.

Drills are re-run semi-annually thereafter, or after any change to
the release pipeline that materially affects OIDC binding scope.

## Cross-references

  * VAL-W12-041 (this drill must exist + be rehearsed)
  * VAL-W12-039 (no destructive rollback -- yank/deprecate only)
  * VAL-W12-040 (monotonic SemVer -- never reuse the compromised tag)
  * `docs/release/runbook.md` (## Compromised OIDC response section
    cross-references this document)
  * PW1-7 (release engineer scope; Chandler owns this)
  * Spec section Q.3 (incident runbook structure)
