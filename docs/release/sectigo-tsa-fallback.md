# Sectigo TSA Fallback (VAL-W12-043)

Per PW1-3, the Relay release pipeline uses Sigstore TSA
(`https://timestamp.sigstore.dev/api/v1/timestamp`) as the primary
RFC 3161 timestamp authority for every artifact signature. Sectigo is
the commercial fallback for Sigstore TSA outage or rate-limit, wired
into the release workflow but inactive by default.

## Default selection (load-bearing)

The release workflow declares:

```yaml
env:
  TSA_PRIMARY: "sigstore"
```

The static guard `scripts/check-sidecar-bundle.py` rejects any
workflow whose `TSA_PRIMARY` env value is anything other than
`sigstore` -- the default selection is part of the contract. The
canonical constant in code form is:

```python
TSA_PRIMARY = "sigstore"  # default: Sigstore primary, Sectigo fallback inactive
```

Changing the default requires an explicit ops decision, runbook
update, and a new release.

## Fallback activation

Sectigo TSA is activated by setting `TSA_PRIMARY = "sectigo"` in the
workflow OR via a workflow_dispatch input with the
`tsa_fallback_active` flag set. Activation conditions are:

  1. Sigstore TSA returns 5xx or hits the documented rate-limit on
     three consecutive retries with exponential backoff.
  2. The release engineer files an incident ticket documenting the
     Sigstore TSA outage AND the expected duration of the fallback.
  3. The release runbook is updated within the same PR to note the
     fallback window.

The fallback window MUST be time-boxed: a maximum of 72 hours of
Sectigo-timestamped releases before either Sigstore TSA recovers or
the release pipeline pauses. This bounds the divergence between our
artifacts' trust chain and the OSS verifier's default Sigstore-only
trust path.

## Nightly tier-3 exercise (VAL-W12-043 evidence)

A nightly tier-3 CI job tagged `tsa-fallback` exercises the Sectigo
TSA code path against a Sectigo sandbox / test endpoint (NOT against
the production billable account). The job:

  1. Sets `TSA_PRIMARY = "sectigo"` and `SECTIGO_TSA_ENDPOINT` to the
     sandbox URL.
  2. Runs a no-op signing operation against a test artifact.
  3. Verifies the resulting timestamp token parses as a valid RFC 3161
     TSR signed by the Sectigo test TSA certificate.
  4. Records the run outcome in the tier-3 results so an outage in the
     fallback path is detected within 24 hours.

Failure of the nightly job pages the release engineer and pauses
non-emergency releases until the Sectigo path is restored.

## Verifier-side trust handling (out-of-scope gap)

Per contract gap #1 (contract.md "Gaps flagged" section), the spec
does not yet define how a bundle timestamped under fallback Sectigo
TSA interacts with verifiers that trust ONLY Sigstore's transparency
log. Recommendation: the verifier output MUST report
`timestamp_authority: sigstore|sectigo|other` AND the trust-anchor
governance document MUST publish Sectigo's certificate chain
alongside Sigstore's.

This wiring (the workflow's Sectigo fallback path itself) lives here
and satisfies VAL-W12-043; the verifier-side trust handling is
tracked separately and will land with sub-feature w12.6
(`rly verify-install`).

## Why not FreeTSA

Per PW1-3 the FreeTSA option was rejected for production use because
its operational stability and key rotation cadence are not
contractually guaranteed. Sectigo's commercial TSA provides:

  * SLA-backed availability (99.9% uptime)
  * Predictable certificate rotation with public CRL/OCSP endpoints
  * RFC 3161-conforming TSR responses parseable by every standard
    OpenSSL `ts -verify` tooling

## Cross-references

  * VAL-W12-022 (TSA timestamp required on every signature)
  * VAL-W12-043 (Sectigo fallback wired but inactive by default)
  * PW1-3 (Sigstore primary, Sectigo fallback, FreeTSA rejected)
  * `docs/release/runbook.md` (## Sectigo TSA fallback section
    cross-references this document)
  * `docs/release/trust-anchor-governance.md` (the governance doc
    enumerates both Sigstore and Sectigo as trust roots for our
    timestamps)
