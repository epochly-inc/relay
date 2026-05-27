# Trust-anchor Governance — Release Pipeline View

The comprehensive trust-anchor governance document is
[`docs/legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md).
It covers the custody model, rotation cadence, disclosure procedure,
transparency-log design, TSA partner selection, JWKS hosting, and the
counsel-review path.

This page is the **release-engineering view** of that same surface: it
describes which release-pipeline mechanisms produce the attestations
the trust anchor verifies, so that release engineers can see at a
glance which pipeline change affects which governance commitment.

Signing private keys, KMS references for those keys, TSA partner
credentials, and transparency-log custody keys live exclusively in
the hosted Relay infrastructure (KMS / HSM). The Apache 2.0 grant
covers the verifier engine and the bundle format; it does not extend
to that key material.

## Scope

The release pipeline produces the operational basis for five trust
commitments:

1. **Default trust anchor.** The OSS verifier defaults to
   `https://relay.epochly.com/.well-known/jwks.json` (CLAUDE.md
   keystone invariant 11). Changing that default in OSS code is a
   board-level decision per CLAUDE.md banned pattern 13.
2. **Signing-identity binding.** Release artifacts are produced and
   signed through identities the trust anchor accepts.
3. **Key rotation cadence.** Documented in
   [`docs/legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md);
   release-pipeline reviews check the rotation evidence.
4. **Transparency-log custody.** Bundle issuance is recorded in the
   public, Merkle-verifiable transparency log; verifiers can prove
   inclusion offline.
5. **Functionary key procedures.** Adding, rotating, or revoking a
   release-pipeline functionary key follows the runbook procedure
   described below.

## Release-pipeline attestation sources

The release pipeline contributes five attestation classes:

- **PyPI trusted publishing** (sub-feature w12.1). Short-lived
  OIDC-issued credentials, scoped to `epochly-inc/relay` +
  `release-pypi.yml` + the `release` environment. Full configuration
  in [`runbook.md`](runbook.md).
- **npm provenance and trusted publishing** (sub-feature w12.2).
  Short-lived OIDC-issued credentials for the npm registry; every
  published distribution carries a SLSA v1.0 provenance attestation.
- **SLSA L3 hermetic builder** (sub-feature w12.3). Every artifact
  is built and signed inside the
  `slsa-framework/slsa-github-generator` hermetic runner, with
  builder identity attested in the provenance.
- **in-toto layout and link metadata** (sub-feature w12.4). The
  canonical layout file enumerates the full release supply chain;
  every step emits link metadata signed by a registered functionary
  key. The layout signing-key rotation procedure is in
  [`runbook.md`](runbook.md).
- **Sigstore keyless signing** (sub-feature w12.5). Every sidecar
  binary is keyless-signed via Sigstore Fulcio (short-lived cert
  against a GitHub OIDC identity) and recorded in the Rekor
  transparency log with an offline-verifiable inclusion proof. The
  Sectigo TSA fallback path is documented at
  [`sectigo-tsa-fallback.md`](sectigo-tsa-fallback.md).

## Review cadence

This document and the comprehensive legal version are reviewed by
counsel and security counsel semi-annually. Material changes to the
release pipeline (adding or removing a trusted-publisher binding,
changing the SLSA builder pin, rotating a functionary key) trigger
an interim review.

## Cross-references

- [`docs/legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md)
  — comprehensive governance document.
- [`runbook.md`](runbook.md) — release runbook (operational basis
  this document references).
- VAL-W12-042 — this document must reference the release pipeline.
- CLAUDE.md keystone invariant 11 — default trust anchor URL.
- CLAUDE.md banned pattern 14 — no key material in either repository.
- Spec section AO.3 — trust-anchor governance step 1.
- Spec section AO.4 — auditor offline-verifiability.
