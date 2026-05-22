# How to Verify a Relay Bundle Offline (Auditor)

This page is the auditor persona walkthrough for verifying a Relay evidence
bundle on your own hardware, with no live dependency on
`relay.epochly.com` at verify time. It is the operational companion to
[`../evidence/offline-verification.md`](../evidence/offline-verification.md),
written for an external reviewer who received a bundle and needs to
independently confirm its cryptographic integrity.

## Who this is for

You are an external auditor, customer security reviewer, or internal
review board member. Someone handed you a Relay evidence bundle file (a
single JSON document) and you need to verify that:

- The bundle bytes have not been altered since signing.
- Every embedded signature was produced by a key in the published
  Relay-Inc JWKS (or a Bring-Your-Own JWKS you trust).
- The bundle structure conforms to the published v1 schema.

This walkthrough does NOT cover bundle interpretation, evidence-claim
review, or compliance judgment. Verification proves cryptographic
integrity only; the policy judgment is yours.

## What you will need

- The bundle file itself (a `.json` document conforming to the v1
  evidence bundle schema). Bundles produced by `rly verify-self` are
  typical examples.
- A workstation with Python 3.12 or newer.
- The `rly` CLI installed (the verifier component is fully open source
  under Apache 2.0; see Step 1).
- One initial network connection (to fetch the JWKS once). After that,
  the workstation can be disconnected for the rest of the procedure.
- Optional: enough disk space to keep the bundle and the cached JWKS
  side by side.

## Step 1: Install the verifier (offline-capable)

The verifier ships as part of the `rly` CLI in the public
`epochly-inc/relay` repository (Apache 2.0). You have three install paths:

- **PyPI:** install the published wheel into a fresh virtualenv. The
  CLI exposes the `rly` entry point; the verifier component lives in
  the `relay_verifier` package
  (`packages/verifier/src/relay_verifier/__init__.py`).
- **From source:** clone `epochly-inc/relay` and run
  `uv sync` followed by `uv run rly --version`. This is the recommended
  path for auditors who want to read the verification code before
  trusting its verdict.
- **Vendored wheel:** for fully air-gapped environments, copy a
  pre-downloaded wheel onto the auditor workstation and
  `pip install` it from the local file. The verifier has no runtime
  dependency on `relay.epochly.com`.

Confirm the install:

```bash
rly --version
```

A working install prints the CLI version on stdout and exits 0.

## Step 2: Cache the JWKS once (the only online step)

The verifier reads the JWKS from a local cache at
`${RELAY_HOME}/jwks-cache/<host>.json`. `rly evidence verify` will not
fetch the JWKS itself; you must populate the cache from a connected
machine before disconnecting.

The simplest way to populate the cache for the default Relay-Inc trust
anchor is to run a single `rly verify-self` invocation on a connected
machine. That command both proves the install works and writes the
canonical envelope to
`${RELAY_HOME}/jwks-cache/relay.epochly.com.json`:

```bash
rly verify-self --json
```

The default trust-anchor URL is the spec-pinned literal
`https://relay.epochly.com/.well-known/jwks.json`, declared once in
`packages/verifier/src/relay_verifier/constants.py` as
`DEFAULT_TRUST_ANCHOR_URL`. Per spec section AO.4 and CLAUDE.md
keystone invariant #13, that default is a board-level constant; the
`--trust-anchor` flag is the supported path for forks and self-hosters
who pin their own JWKS.

Before you trust the cached JWKS, verify its provenance. The
governance discipline that protects the Relay-Inc signing keys is
documented in
[`../legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md);
read it once so you understand what the published JWKS represents
before you accept any verdict that depends on it.

The cache file is a versioned envelope (`relay.cli.jwks_cache.v1`),
not a raw JWKS document. Do not edit it by hand.

## Step 3: Disconnect from the network

On the auditor workstation, sever the network: physically unplug, disable
the interface, or run inside a sandbox that denies egress. Every
remaining step is offline-only by construction; this severance is a
belt-and-suspenders proof that the verdict cannot depend on a live JWKS
fetch.

## Step 4: Run verification

Invoke `rly evidence verify` with the path to the bundle. For the
default Relay-Inc trust anchor, no flag is required:

```bash
rly evidence verify "<bundle_path_or_id>"
```

For a BYO trust anchor (forks or self-hosters per spec section AO.4):

```bash
rly evidence verify "<bundle_path_or_id>" --trust-anchor https://example.invalid/.well-known/jwks.json
```

Exit code 0 means every check passed and the bundle is auditor-acceptable
on its cryptographic integrity. Any non-zero exit is a verification
failure; the structured stderr envelope identifies which check failed.

## Step 5: Interpret the VerificationResult

A successful run prints a single JSON envelope on stdout. The envelope
mirrors the `VerificationResult` dataclass exported from
`packages/verifier/src/relay_verifier/__init__.py`
(defined in `packages/verifier/src/relay_verifier/verifier.py`). The
dataclass attributes are the canonical source; every field below maps
to one of them.

| Field | Type | Meaning | What to record |
|---|---|---|---|
| `digest_ok` | bool | The recorded `signing_input_b64u` of every signature reproduces the recomputed canonical-JSON payload bytes. False signals bundle tampering between signing and verification. | Record the boolean; if false, treat the bundle as compromised. |
| `signatures_ok` | bool | Every signature on the bundle verified against a JWK resolved from the trust anchor. False if any signature failed or no signatures were present. | Record the boolean; if false, follow up via `signature_checks` to find which signature failed. |
| `structure_ok` | bool | The bundle JSON shape conforms to the v1 schema. False on malformed input. | Record the boolean; if false, the bundle is unusable. |
| `signature_checks` | list of `SignatureCheck` | Per-signature outcomes. Each entry carries `kid`, `alg`, `ok`, `reason`, and for known wire-coded rejections `code`. | Record each entry verbatim in your audit log; the `reason` and `code` strings are the audit record. |
| `claims_count` | int | Number of `evidence_claims` covered by the bundle. | Record the integer; cross-reference against the bundle's claim list when reviewing scope. |
| `bundle_digest_sha256` | str | Hex SHA-256 of the canonical bundle bytes that the digest check verified against. | Record the hex string; this is the canonical fingerprint of the bundle you verified. |
| `errors` | list of str | Structured failure reasons; empty list on success. | Empty on success. On failure, capture every entry. |

A verifier verdict is "pass" iff `digest_ok && signatures_ok &&
structure_ok` and `errors` is empty. Any other combination is a
verification failure.

The CLI wraps these attributes with a wire schema version, a
`trust_anchor` field, and a `trust_anchor_overridden` flag; the wire
shape is documented in
[`../evidence/offline-verification.md`](../evidence/offline-verification.md)
section "Step 4: Read the VerificationResult". On the wire,
`signature_checks` is rendered as `signatures_checked`.

## Step 6: Independent re-verification (optional but recommended)

For high-assurance audits, you may want to re-verify the bundle without
trusting the `rly` CLI binary. The verifier component is small,
single-file-readable, and the on-the-wire format is standard JWS
(RFC 7515) with detached payloads.

A second verification path looks like this:

- Read the bundle JSON. Recompute the canonical JSON bytes of the
  signing payload using an independent RFC 8785 (JCS) implementation.
- For each signature in the bundle, decode the JWS, look up the JWK
  by `kid` in the cached JWKS, and run the standard ECDSA / EdDSA /
  RSA-PKCS1-v1_5 verification primitive from your platform's
  cryptography library against the canonical payload bytes.
- Compare your independent verdict to the `signature_checks` entries
  emitted by `rly evidence verify`. Mismatches are themselves an audit
  finding.

The supported algorithms are `EdDSA`, `ES256`, and `RS256`
(`SUPPORTED_ALGS` in
`packages/verifier/src/relay_verifier/verifier.py`); the minimum RSA
modulus is 2048 bits (`MIN_RSA_BITS` in
`packages/verifier/src/relay_verifier/tsa.py`).

## What failure looks like

`rly evidence verify` maps verification failures to deterministic exit
codes and structured stderr envelopes. The most common cases:

- **Tampered bundle bytes.** `digest_ok=false` and / or
  `signatures_ok=false`; stderr reports `RELAY-EVID-014`. The bundle
  cannot be trusted; request the original from the sender.
- **Missing JWKS cache.** stderr reports
  `RELAY-CLI-EVIDENCE-NO-JWKS-CACHE`. Re-run Step 2 on a connected
  machine and copy the cache directory to the offline workstation.
- **Bundle file not found.** stderr reports
  `RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND`. Confirm the path or the
  `${RELAY_HOME}/evidence/<id>.json` resolution.
- **Malformed bundle JSON.** stderr reports
  `RELAY-CLI-EVIDENCE-BUNDLE-INVALID`. Inspect the bundle file; verify
  it was not truncated during transport.
- **Revoked key.** A signature was produced by a key that is now past
  its `not_after` window in the published JWKS. The verifier rejects
  the signature; `signature_checks[].reason` carries the structured
  rejection. Key lifecycle is documented in
  [`../evidence/signing-key-lifecycle.md`](../evidence/signing-key-lifecycle.md).
- **Missing claims.** `claims_count` is lower than you expected.
  Verification is still a pass on its own terms; the gap is a scope
  finding for your audit, not a verification failure.

A non-zero exit means the bundle is not auditor-acceptable. Do not
edit the stdout JSON to mask a failure; the `signature_checks` reasons
are the audit record.

## A note on what verification proves

Verification proves the bundle's cryptographic integrity: the bytes
were not altered between signing and verification, and the signatures
were produced by keys in the published JWKS. Verification does NOT
prove that the underlying agent behavior was correct, that the evidence
claims are sufficient for any regulatory regime, or that any policy
threshold was met. Those judgments are yours.

The companion how-to
[`extract-ai-act-readiness-evidence.md`](extract-ai-act-readiness-evidence.md)
covers what readiness evidence a Relay bundle provides for an EU AI Act
review, and what gaps you should expect to fill in yourself.

## Cross-references

- [`extract-ai-act-readiness-evidence.md`](extract-ai-act-readiness-evidence.md)
  — compliance officer persona walkthrough; pairs with this page for
  audit-ready evidence review.
- [`../evidence/offline-verification.md`](../evidence/offline-verification.md)
  — the technical reference for offline verification, including the
  CLI wire schema, the cached JWKS envelope shape, and the failure
  triage table.
- [`../legal/trust-anchor-governance.md`](../legal/trust-anchor-governance.md)
  — what the published Relay-Inc JWKS represents and the governance
  discipline that protects it.

---

Spec: §AO, §K
