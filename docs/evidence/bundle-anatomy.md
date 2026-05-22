# Evidence Bundle Anatomy

## Overview

A Relay evidence bundle is a JSON document that records the artifacts,
commands, signatures, and provenance binding a run's outcome. Every bundle
is signed with one or more JWS signatures over a canonical (RFC 8785 JCS)
payload, so the bundle's contents and the signing-key identity can be
verified offline by any party who holds the matching JWKS. The verifier
in `packages/verifier/` is the reference offline implementation.

## Top-level structure

The canonical wire-format envelope is `relay.evidence_bundle.v1`, declared
in `packages/schemas/raw/envelopes.yaml`. The persisted control-plane row
(table `evidence_bundles`) and the on-disk signed JSON share the same
`schema_version` pin so a verifier reading either form refuses unknown
versions on write (§B.7).

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | literal `"relay.evidence_bundle.v1"` | yes | Wire-format pin per §B.7. |
| `evidence_bundle_id` | UUID | yes | Stable identifier referenced by `evidence_claims.evidence_bundle_id`. |
| `org_id` | UUID | yes | Owning organization (control-plane scope). |
| `project_id` | UUID | yes | Owning project. |
| `scope_type` | string | yes | The scope kind the bundle binds (e.g. `run`, `gate_round`, `evidence_bundle`). |
| `scope_id` | UUID | yes | The scope identifier. |
| `bundle_digest` | `sha256-<64 hex>` | yes | Canonical Relay wire form (`VAL-W1-018`). |
| `acef_core_version` | string | yes | Vendored ACEF core schema version the payload conforms to. |
| `relay_extension_version` | string | yes | Version of the Relay `x-relay/*` ACEF extension envelope. |
| `signing_key_id` | string | nullable | `kid` of the signer's JWK. Mirrors the signature record. |
| `signature_algorithm` | string | nullable | JWS `alg` value (one of `EdDSA`, `ES256`, `RS256`). |
| `verification_status` | enum | yes | Closed set: `unverified`, `verified`, `tampered`, `revoked` (`VAL-W1-019`). |
| `redaction_policy_version` | string | yes | Version of the redaction policy under which the bundle was produced. |
| `manifest_commit_hash` | `sha256-<hex>` | nullable | Commit hash of the manifest that produced the run (§F). |
| `object_ref` | string | yes | Storage reference for the signed bundle bytes (e.g. R2 key or local path). |
| `supersedes_bundle_id` | UUID | nullable | Set when a later bundle reissues the binding (registry transition). |
| `created_at` | RFC 3339 timestamp | yes | When the bundle row was written by the control plane. |

A signed bundle's on-disk JSON additionally carries fields that the OSS
verifier reads directly via `parse_bundle_bytes()` (see
`packages/verifier/src/relay_verifier/verifier.py`):

| Field | Type | Notes |
|---|---|---|
| `trust_anchor` | string | Operator-declared anchor identifier. Local-dev bundles carry the hard-coded value `local_dev` (`VAL-V2M08-043`). Hosted bundles carry the Relay-Inc anchor. See [`trust-anchor.md`](trust-anchor.md). |
| `decided_at` | RFC 3339 timestamp | When the canonical outcome was decided by the control plane. |
| `signed_at` | RFC 3339 timestamp | When the signing service produced the JWS. |
| `claims` | array | The atomic evidence claims. See [`claim-binding.md`](claim-binding.md) for the pairing rule. |
| `subject_id` | string \| null | Optional subject identifier the bundle binds to. |
| `subject_digest_hex` | hex | SHA-256 of `subject_id` when present. |
| `merkle_root_hex` | hex | SHA-256 Merkle root computed over claim digests when claims are present. Binds claim coverage into a single content-addressed digest. |
| `signatures` | array | One or more JWS signature records (see "Wire format" below). |

The persisted row in `evidence_bundles` is the canonical control-plane
record; the signed on-disk JSON is the auditor-facing wire form. The two
agree on `schema_version`, `evidence_bundle_id`, and `bundle_digest`.

## Wire format

The signing payload is every field of the bundle **except** `signatures`
(see `_payload_for_signing()` in
`packages/verifier/src/relay_verifier/verifier.py`). The payload is
canonicalised with RFC 8785 JCS (`jcs_canonicalize` in
`packages/verifier/src/relay_verifier/canonical.py`) and SHA-256 hashed to
produce `bundle_digest_sha256`. Each entry in `signatures[]` is a JWS-style
record with the following fields:

| Field | Notes |
|---|---|
| `kid` | The signing key identifier matching a JWK in the trust-anchor JWKS. |
| `alg` | JWS algorithm. The supported set is `EdDSA`, `ES256`, `RS256` (`SUPPORTED_ALGS` in `verifier.py`). |
| `signing_input_b64u` | base64url of the canonical signing bytes. The verifier confirms these recompute to the same JCS bytes; drift is reported as bundle tampering. |
| `signature_b64u` | base64url of the JWS signature over `signing_input_b64u`. |

Multi-signature bundles are supported. The verifier aggregates per-signature
verdicts (`SignatureCheck`) into the top-level `VerificationResult` and the
canonical verifier output envelope `relay.verifier.output.v1`
(`packages/schemas/raw/verifier-output.yaml`). The maximum number of
signatures is bounded by `MAX_BUNDLE_SIGNATURES` to prevent archive-bomb
attacks (`VAL-V2M08-041`).

## ACEF alignment

Relay vendors the ACEF reference SDK under `packages/acef/upstream/` at the
pin recorded in `packages/acef/vendor_manifest.json`. The bundle envelope's
`acef_core_version` field declares which ACEF core schema the payload
conforms to; `relay_extension_version` declares the version of the Relay
`x-relay/*` extension namespaces carried alongside the ACEF core. ACEF
bundles produced by Relay carry per-run control-plane bindings, replay
verification outcomes, contract-gate results, human-oversight events, and
incident-monitoring records. The Merkle root over claim digests binds the
evidence coverage of a run into a single content-addressed digest so an
auditor can reason about gaps in the evidence set.

The vendored upstream tree is byte-equal to the pinned commit per the
vendor-drift guard (`VAL-W11-004`). The TypeScript SDK never imports ACEF
symbols directly; all TS-side consumption goes through the sidecar's HTTP
surface.

## Trustworthy time and transparency log

Each persisted bundle is augmented by two sibling records that the
verifier checks offline:

- `EvidenceTimestamp` (`relay.evidence_timestamp.v1`) records the RFC 3161
  TSA timestamp (`tsa_response_digest`, `tsa_response_ref`,
  `tsa_genTime`). One row per bundle. The TSA chain is shipped alongside
  the JWKS in the trust bundle so the verifier can validate the timestamp
  without network access.
- `TransparencyLogEntry` (`relay.transparency_log_entry.v1`) records the
  `(log_index, evidence_bundle_id, bundle_digest, signer_key_id,
  appended_at, tree_root_after)` tuple appended to Relay's
  Sigstore-Rekor-style transparency log. Inclusion is checked offline via
  the served `inclusion_proof_ref` and witness signature.

Both envelopes are defined in `packages/schemas/raw/envelopes.yaml`.

---

Spec: §K, §AB
