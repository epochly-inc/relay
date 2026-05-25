# Signing Key Lifecycle

Every Relay evidence bundle is signed by a JWK published in a trust anchor's
JWKS. Each JWK carries optional lifecycle annotations (`not_before`,
`not_after`, `revoked_at`) that the offline verifier evaluates on every
bundle. This page documents the lifecycle states the verifier recognizes,
what the verifier does when it encounters each one, how rotation and
revocation work technically, and the structured fields on `VerificationResult`
that surface lifecycle outcomes to auditors.

This page is the **technical** companion to the **governance** discipline
documented in
[`docs/legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md).
That file is the source of truth for who at Relay-Inc holds key custody,
the rotation cadence, the compromise-response procedure, and the counsel-
review cycle. This file does not duplicate those decisions; it explains
how the OSS verifier interprets a JWK once it has been published.

## JWK lifecycle annotations

Per spec sections L.1 (line 4452) and L.4 (lines 4469-4472), every JWK in
the trust anchor MAY carry the following lifecycle annotations:

```json
{
  "kid":        "kid_2026-05_relay-evidence",
  "kty":        "OKP",
  "crv":        "Ed25519",
  "x":          "<base64url public key>",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after":  "2027-01-01T00:00:00Z",
  "revoked_at": "2026-06-15T12:00:00Z"
}
```

`not_before` and `not_after` are RFC 3339 UTC ("Z") timestamps describing
the active window for the key. `revoked_at` is set when the key has been
revoked via the procedure documented in
[`trust-anchor-governance.md`](../legal/trust-anchor-governance.md).

When a JWK omits ALL three annotations, the verifier accepts signatures
under it but surfaces the missing-window state for auditor telemetry. This
matches the W10.1 default-JWKS behavior shipped inside the verifier wheel.

## Lifecycle states

The function `check_signing_key_lifecycle()` in
[`packages/verifier/src/relay_verifier/key_lifecycle.py`](https://github.com/epochly-inc/relay/blob/main/packages/verifier/src/relay_verifier/key_lifecycle.py)
returns a `KeyLifecycleResult` whose `outcome` field is one of five values.
Each maps to a specific JWK condition:

| `outcome`         | Trigger                                                                                                                          | Wire code        |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------|------------------|
| `ok`              | Key is within `not_before` / `not_after` window, not revoked (OR revoked AFTER the bundle was signed; see "revoked" below).      | (none)           |
| `expired`         | `auditor_now > not_after + 300s` tolerance. Also returned when `bundle.signed_at` or `jwk.not_after` is unparsable.              | `RELAY-EVID-041` |
| `premature`       | `not_before > auditor_now + 300s` tolerance. The key is dated more than 300 seconds in the future relative to the auditor clock. | `RELAY-EVID-041` |
| `revoked`         | `bundle.signed_at > jwk.revoked_at`. Also returned when `jwk.revoked_at` is unparsable.                                          | `RELAY-EVID-042` |
| `missing_window`  | JWK declares neither `not_before` nor `not_after`. Verifier accepts the signature but surfaces the state for telemetry.          | (none)           |

A "rotation in progress" state observable to operators (a new JWK
published to the JWKS with `not_before = now + 24h` and no historical
bundles signed by it yet, per spec L.3) is NOT a distinct verifier
outcome. The verifier evaluates each JWK independently against the
bundle's `signed_at` timestamp: during the propagation window both the
predecessor and the successor JWK return `outcome=ok` for bundles in
their respective windows. Bundles that carry multi-signature witness
attestations (spec L.3) verify under both JWKs and return one
`SignatureCheck` per signature.

## What the verifier does for each state

Each verdict is recorded on the structured `VerificationResult` output;
none of them raises. The aggregator in
[`packages/verifier/src/relay_verifier/bundle_validator.py`](https://github.com/epochly-inc/relay/blob/main/packages/verifier/src/relay_verifier/bundle_validator.py)
attaches the lifecycle outcome to the bundle's output envelope:

- **`outcome=ok`** -- signature verifies, `signer_key_revoked=false`,
  no lifecycle entry added to `errors[]` or `warnings[]`.
- **`outcome=expired`** -- `errors[]` gains an entry with
  `reason="signer_key_expired"` and `code="RELAY-EVID-041"`. The bundle is
  rejected.
- **`outcome=premature`** -- `errors[]` gains an entry with
  `reason="signer_key_premature"` and `code="RELAY-EVID-041"`. The bundle
  is rejected.
- **`outcome=revoked`** (signed AFTER `revoked_at`) -- `errors[]` gains an
  entry with `reason="signer_key_revoked_at_or_before_sign_time"` and
  `code="RELAY-EVID-042"`. The bundle is rejected.
- **`signer_key_revoked=true` with `outcome=ok`** (signed BEFORE
  `revoked_at`) -- `warnings[]` gains an entry with
  `reason="signer_key_revoked_after_sign_time"`. The bundle still verifies
  (exit 0); the auditor decides whether to accept it given the revocation
  reason published per spec L.4.
- **`outcome=missing_window`** -- accepted; no error, no warning. The
  state is implied by the absence of any lifecycle entry plus the JWK
  itself (which the auditor can inspect via `trust_anchor_source`).

Auditor clock skew is bounded at +/-300 seconds (per spec L.5 line 4479)
on BOTH boundaries (`not_before` and `not_after`). The constant lives in
`relay_verifier.tsa.CLOCK_SKEW_TOLERANCE_SECONDS` and is shared with the
TSA module so the tolerance has a single source of truth.

## Rotation procedure

The technical mechanics of rotation are documented in spec L.3:

1. A successor JWK is generated by the Relay-platform signing service with
   `not_before = now + 24h` and an internal pointer to the outgoing JWK's
   `signer_key_id` (the predecessor relationship is tracked in the
   Relay-platform key registry per spec L.1; the OSS verifier never reads
   it).
2. The successor JWK is published to
   `https://relay.epochly.com/.well-known/jwks.json` immediately.
3. Observers confirm propagation of the JWKS update.
4. Bundles signed during the propagation window MAY carry both a primary
   `signer_key_id` (the successor) and a witness signature under the
   predecessor. The verifier emits one `SignatureCheck` per signature; up
   to four signatures per bundle are accepted (spec L.5 line 4481).
5. The predecessor JWK is marked deprecated (its `not_after` is shortened)
   only after step 3 confirms propagation.
6. The predecessor JWK remains valid for verifying historical bundles in
   perpetuity unless revoked (spec L.3 line 4466).

The governance side -- who signs off on rotation, where the predecessor
private key is destroyed, who is on the rotation call, what the rollback
plan is -- lives in
[`trust-anchor-governance.md`](../legal/trust-anchor-governance.md). The
verifier does not need to know any of that to evaluate a bundle; it only
needs the JWKS the rotation procedure produced.

## Revocation

Revocation is the act of marking a JWK unusable for signing future
bundles. Per spec L.4 it is triggered by:

- A confirmed key-compromise incident (sev1; see spec L.5 line 4478).
- Customer offboarding for BYOK keys (spec L.5 line 4480).
- Scheduled retirement of a long-deprecated predecessor JWK that the
  organization no longer wishes to keep verifiable.

When revocation is approved by the procedure in
[`trust-anchor-governance.md`](../legal/trust-anchor-governance.md), three
things happen on the published trust anchor:

1. `signing_keys.revoked_at` is set to the revocation timestamp in the
   internal registry.
2. The JWK published at
   `https://relay.epochly.com/.well-known/jwks.json` gains a `revoked_at`
   field with the same timestamp.
3. A CRL-style record is published on a static endpoint (spec L.4 line
   4471) and a transparency-log entry is written so the revocation is
   externally observable (spec AO.1 line 6117). The transparency-log
   inclusion proof for the revocation event is verifiable offline with
   the same `verify_log_inclusion()` machinery used for evidence bundles.

The published `revoked_at` annotation is what the verifier reads to
populate `signer_key_revoked` and `signer_key_revoked_at` on
`VerificationResult`. Auditors who download the JWKS at the moment of
verification see the same revocation state any other consumer sees.

## Verifier output fields

The offline verifier's `VerificationResult` envelope is defined in
[`packages/schemas/raw/verifier-output.yaml`](https://github.com/epochly-inc/relay/blob/main/packages/schemas/raw/verifier-output.yaml).
Two fields specifically surface signing-key lifecycle outcomes; lifecycle-
related rejections additionally populate the standard `errors[]` and
`warnings[]` arrays.

| Field                                | Type                | Source                                                                       |
|--------------------------------------|---------------------|------------------------------------------------------------------------------|
| `signer_key_revoked`                 | `boolean`           | True iff the resolved JWK carries `revoked_at` (regardless of `signed_at`).  |
| `signer_key_revoked_at`              | `string` or `null`  | The JWK's `revoked_at` value, or `null` when not set.                        |
| `errors[].reason`                    | `string`            | One of `signer_key_expired`, `signer_key_premature`, `signer_key_revoked_at_or_before_sign_time`. |
| `errors[].code`                      | `string`            | `RELAY-EVID-041` (expired or premature) or `RELAY-EVID-042` (revoked).       |
| `warnings[].reason`                  | `string`            | `signer_key_revoked_after_sign_time` when the bundle was signed before the JWK's `revoked_at`. |

Example envelope fragment for a bundle whose signing key was revoked
AFTER the bundle was signed (the bundle still verifies; the warning lets
the auditor decide):

```json
{
  "digest_ok": true,
  "signatures_ok": true,
  "structure_ok": true,
  "signer_key_revoked": true,
  "signer_key_revoked_at": "2026-06-15T12:00:00Z",
  "warnings": [
    {
      "reason":  "signer_key_revoked_after_sign_time",
      "message": "key 'kid_2026-05_relay-evidence' was revoked at 2026-06-15T12:00:00Z; bundle signed before revocation -- auditor decides acceptance"
    }
  ],
  "errors": []
}
```

Example envelope fragment for a bundle whose signing key has expired:

```json
{
  "digest_ok": true,
  "signatures_ok": false,
  "structure_ok": true,
  "signer_key_revoked": false,
  "signer_key_revoked_at": null,
  "warnings": [],
  "errors": [
    {
      "reason":  "signer_key_expired",
      "code":    "RELAY-EVID-041",
      "message": "key not_after 2027-01-01T00:00:00Z is 1296000s in the past, exceeding +/-300s tolerance"
    }
  ]
}
```

## Cross-references

- [`trust-anchor.md`](trust-anchor.md) -- what the trust anchor is, the
  default JWKS URL, BYO trust anchors, and the board-level discipline that
  guards the default.
- [`offline-verification.md`](offline-verification.md) -- the walkthrough
  for running `rly evidence verify` against a cached JWKS with no network.
- [`../legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md)
  -- the governance source of truth for key custody, rotation cadence,
  revocation approval, and counsel review.
- [`bundle-anatomy.md`](bundle-anatomy.md) -- the JWS payload structure
  the lifecycle check applies to.

Spec: §L
