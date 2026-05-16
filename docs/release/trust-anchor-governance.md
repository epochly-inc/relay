# Trust-anchor Governance (OSS-facing stub)

This is the OSS-facing stub for the Relay trust-anchor governance
document. The authoritative source lives in the private
`relay-platform` repository at
`relay-platform/ops/runbooks/trust-anchor-governance.md`; the
public-facing rendering at
`https://relay.epochly.com/legal/trust-anchor-governance` is derived
from the private source.

Per CLAUDE.md banned pattern 14, the signing keys, KMS references for
those keys, TSA partner credentials, and transparency-log custody
keys live ONLY in `relay-platform` (KMS / HSM). The Apache 2.0 grant
does NOT extend to that key material. This stub references the
release pipeline as the operational basis for how Relay-Inc protects
signing-identity binding; it does NOT carry any key material.

## Scope

The trust-anchor governance document covers:

  1. Which signing identities are trusted by the Relay verifier
     (`packages/verifier/`) by default (CLAUDE.md keystone invariant
     #11: `https://relay.epochly.com/.well-known/jwks.json`).
  2. The release pipeline as the operational basis for binding
     signing identities to Relay-Inc.
  3. Key rotation cadence (per spec section L) and revocation
     procedures.
  4. Transparency-log custody and Merkle checkpoint pinning.
  5. Procedures for adding, rotating, or revoking a functionary key.

## Release pipeline as operational evidence

The release pipeline provides the operational basis for how
Relay-Inc protects signing-identity binding. The pipeline's
attestation sources are:

  * **PyPI trusted publishing** (sub-feature w12.1) -- short-lived
    OIDC-issued credentials, scoped to `epochly-inc/relay` +
    `release-pypi.yml` + `release` environment. See
    `docs/release/runbook.md` for the full configuration.
  * **npm provenance + trusted publishing** (sub-feature w12.2) --
    short-lived OIDC-issued credentials for the npm registry; every
    published distribution carries a SLSA v1.0 provenance attestation.
  * **SLSA L3 hermetic builder** (sub-feature w12.3) -- every artifact
    is built and signed inside `slsa-framework/slsa-github-generator`'s
    hermetic runner, with builder identity attested in the provenance.
  * **in-toto layout + link metadata** (sub-feature w12.4) -- the
    canonical layout file enumerates the full release supply chain;
    every step emits link metadata signed by a registered functionary
    key. See `docs/release/runbook.md` for the layout signing-key
    rotation procedure.
  * **Sigstore keyless signing** (sub-feature w12.5) -- every
    sidecar binary is keyless-signed via Sigstore Fulcio (short-lived
    cert against a GitHub OIDC identity) and recorded in the Rekor
    transparency log with an offline-verifiable inclusion proof.
  * **Sectigo TSA fallback** (sub-feature w12.5, currently inactive
    by default) -- documented at `docs/release/sectigo-tsa-fallback.md`.

## Review cadence

This document and its private companion are reviewed by counsel and
security counsel semi-annually. The review log is maintained in the
private repository. Material changes to the release pipeline (e.g.,
adding or removing a trusted-publisher binding, changing the SLSA
builder version, rotating a functionary key) trigger an interim
review.

## Cross-references

  * VAL-W12-042 (this document MUST reference the release pipeline)
  * CLAUDE.md keystone invariant 11 (default trust anchor URL)
  * CLAUDE.md banned pattern 14 (no key material in either repo)
  * Spec section AO.3 (trust-anchor governance step 1)
  * Spec section AO.4 (auditor offline-verifiability)
  * `docs/release/runbook.md` (release runbook -- the operational
    basis this document references)
  * `relay-platform/ops/runbooks/trust-anchor-governance.md`
    (private, authoritative source)
