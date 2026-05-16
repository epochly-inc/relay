# Relay v0.1 OSS Release Runbook

Authoritative operational runbook for cutting a tagged release of the
`epochly-relay` Python distribution on PyPI. This document is the
human-readable companion to `.github/workflows/release-pypi.yml`; the
two MUST stay in lockstep. CI guards (see
`scripts/check-pypi-publish-workflow.py`) verify that the workflow's
behavior matches what this runbook declares.

**Status:** initial scaffold for feature `w12.1-release-pypi-trusted-publish`.
Sister sub-features `w12.2` (npm provenance), `w12.3` (SLSA L3), `w12.4`
(in-toto), `w12.5` (sidecar bundle), and `w12.6` (verify-install) will
each extend this runbook with their own sections. The structure below
satisfies VAL-W12-001..006, 038, 039, 040, 046.

---

## Trusted Publisher Binding

The PyPI trusted publisher for the `epochly-relay` distribution is
scoped to a single GitHub repo + workflow + environment triple:

- repo: epochly-inc/relay
- workflow: release-pypi.yml
- environment: release

A trusted publisher with a broader scope (any-workflow, no-environment,
or a different repo) is a misconfiguration and MUST be revoked from the
PyPI project settings. The binding above is the only acceptable form.

Configuration steps (one-time per project, performed by the release
engineering owner):

1. Sign in to https://pypi.org as a maintainer of the `epochly-relay`
   project.
2. Navigate to "Manage" -> "Publishing" -> "Add a new publisher".
3. Select "GitHub" as the publisher type.
4. Owner: `epochly-inc`. Repository: `relay`. Workflow filename:
   `release-pypi.yml`. Environment name: `release`.
5. Save. PyPI now issues short-lived publish tokens to ONLY this
   exact workflow run when invoked from the protected environment.

No long-lived PyPI API token, no `PYPI_TOKEN` repo secret, no
`TWINE_PASSWORD` env var is ever created. The CI guard
`scripts/check-pypi-publish-workflow.py` rejects any workflow that
references these names.

---

## Release Environment Protection

The GitHub environment named `release` MUST have the following
protection rules enabled:

- required_reviewers: Chandler (release engineering owner) is the
  designated approver. Any push of a release tag pauses at the
  publish job until Chandler approves the run from the GitHub UI.
- wait timer: 0 minutes (manual approval is the gate; no extra delay).
- deployment branches: only protected tags matching
  `v[0-9]+.[0-9]+.[0-9]+*` may deploy to `release`.

A push to `main`, a feature branch, or an unprotected tag MUST NOT
reach the publish job. The runbook explicitly forbids auto-publish
without manual approval; review the GitHub API output of
`GET /repos/epochly-inc/relay/environments/release` quarterly to
verify the `required_reviewers` rule is still in place.

---

## Publish Step Idempotency

`pypa/gh-action-pypi-publish` is invoked with `skip-existing: true`.
A re-run of the release workflow against a tag whose distribution is
already on PyPI is a no-op: the action skips the upload and exits 0.
The workflow does NOT delete, overwrite, or shadow an existing
distribution under any circumstance.

A second distribution under the same `(name, version)` tuple but with
a different digest is impossible under this flow: PyPI itself rejects
the second upload before this workflow's action is invoked.

---

## No Destructive Rollback

Per spec section Q.2 ("we don't roll back schemas; we roll forward")
and the OSS wedge release posture:

- `pypi-cli delete` is NEVER invoked from any release workflow.
- `gh release delete` is NEVER invoked from any release workflow.
- `npm unpublish` is NEVER invoked from any release workflow.
- PyPI yanking (advisory-only, leaves the distribution downloadable
  for pinned dependents) is permitted, BUT requires:
  - a tabletop incident review documenting the reason
  - a fresh release with the prior good content (per the rollback
    policy below)
  - the yank issued AFTER the replacement release is live

Rollback procedure (the only supported form):

1. Identify the broken release tag (e.g., `v0.1.5`).
2. Identify the prior good release tag (e.g., `v0.1.4`).
3. Cherry-pick the prior good state to `main` OR revert the offending
   commits to `main`.
4. Cut a new tag (e.g., `v0.1.6`) whose SemVer is strictly greater
   than the broken tag. This is the "version increment" rollback.
5. Run the release workflow against the new tag. Approve the
   environment gate. The new distribution ships.
6. ONLY THEN: yank the broken `v0.1.5` distribution on PyPI as an
   advisory action. Do NOT yank before the replacement is live.

There is no "force re-publish" path. There is no "delete and
re-upload" path. The workflow has no inputs that allow either.

---

## Version Monotonicity (SemVer)

Every new release MUST have a SemVer-conforming version string that
is strictly greater than every previously published version of
`epochly-relay`. The workflow runs
`scripts/check-semver-monotonic.py` as a pre-publish gate; the gate
exits non-zero (with RELAY-RELEASE-040) on:

- a version equal to a previously published version (would conflict
  with the no-destructive-rollback policy)
- a version less than the latest published version (non-monotonic)
- a malformed SemVer string (e.g., `v0.1` is rejected; `v0.1.0`
  is accepted)

Pre-release identifiers (`-alpha.1`, `-rc.2`) order per SemVer's
precedence rules: `0.1.0-alpha.1 < 0.1.0-alpha.2 < 0.1.0-rc.1 <
0.1.0 < 0.1.1`. The gate uses the `semver` PyPI library's
`compare()` for ordering; locale-independent and deterministic.

The phrasing "monotonic per SemVer" is preferred over alternative
phrasings in customer-facing surfaces. Authors should consult
CLAUDE.md banned pattern 9 and spec section J.5 for the full list of
banned product-copy terms.

---

## Pre-announcement Policy

Per spec section Q.2 ("major changes pre-announced 7 days in
advance"), a release tag annotated as `breaking: true` MUST NOT
publish unless an announcement file exists in
`docs/release/announcements/` whose timestamp is at least 7 days
earlier than the tag's commit timestamp.

Announcement file format:

- filename: `YYYY-MM-DD-<slug>.md` (UTC date prefix; required)
- frontmatter:
  - `target_version: <SemVer>` (required; the version this
    announcement is for)
  - `breaking: true` (required)
  - `published_at: <RFC 3339 UTC>` (required)
- body: human-readable description of the breaking change, including
  migration guidance for downstream users

The workflow runs `scripts/check-pre-announcement.py` as a
pre-publish gate. For non-breaking releases the gate is a no-op
(exits 0). For breaking releases the gate exits non-zero (with
RELAY-RELEASE-046) if no qualifying announcement file is found.

A tag is `breaking: true` when its annotated tag message contains
the literal token `RELAY-BREAKING-CHANGE` on its own line. The
release engineer sets this when cutting the tag:

```
git tag -a v1.0.0 -m "v1.0.0

RELAY-BREAKING-CHANGE

Drops Python 3.11 support. See announcement
docs/release/announcements/YYYY-MM-DD-drop-py311.md."
```

---

## SLSA Provenance + Sigstore Attestations

Every distribution uploaded by this workflow (sdist + wheel) carries:

- a SLSA v1.0 provenance attestation generated by the
  `slsa-framework/slsa-github-generator` reusable workflow, pinned by
  SHA (per VAL-W12-012)
- a PEP 740 Sigstore-backed PyPI distribution attestation generated
  by `pypa/gh-action-pypi-publish` with `attestations: true`

The SLSA attestation's `subject[].digest.sha256` entries are bound
to the actual uploaded artifact digests via the workflow's `hashes`
job output (base64-encoded `sha256sum` payload). `slsa-verifier
verify-artifact` validates this binding offline at install / verify
time. A mismatch is a supply-chain compromise and MUST trigger the
compromised-OIDC response procedure (documented separately under
sub-feature `w12.5` once that feature lands).

---

## Approved Long-lived Secret Table (initially empty)

The list of long-lived publish secrets approved by the release engineer
for use in any release workflow. Per VAL-W12-038, this table MUST be
empty for the v0.1 OSS wedge. Any future addition requires a board-level
decision and an audit trail entry.

| Secret name | Purpose | Approved by | Date | Audit reference |
|-------------|---------|-------------|------|-----------------|
| (none)      | n/a     | n/a         | n/a  | n/a             |

---

## Cross-references

- Spec sections: A.3, AI.6, K, L.1, Q.2, AO.4
- Engineering plan: L4 line 227, PW1-7 line 130
- CLAUDE.md banned patterns: 1, 9, 13, 14
- Sister sub-features (extend this runbook): w12.2 npm provenance,
  w12.3 SLSA L3, w12.4 in-toto, w12.5 sidecar bundle, w12.6
  verify-install
- Trust-anchor governance: extended under w12.5; see
  `relay-platform/ops/runbooks/trust-anchor-governance.md` (private)
- Workflow file: `.github/workflows/release-pypi.yml`
- Guard script: `scripts/check-pypi-publish-workflow.py`
- Semver gate: `scripts/check-semver-monotonic.py`
- Pre-announcement gate: `scripts/check-pre-announcement.py`
