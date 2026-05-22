# Offline Verification

This page is the air-gapped extension of
[`getting-started/first-evidence-bundle.md`](../getting-started/first-evidence-bundle.md).
The basic walkthrough assumed the JWKS was already cached. This page covers
the full lifecycle: how to cache the JWKS once on a connected machine, how
to carry both the bundle and the cache to an offline auditor workstation,
and how to interpret the verifier's `VerificationResult` byte-for-byte.

## Why offline matters

An evidence bundle is only as trustworthy as the chain that signs it.
Three concrete failure modes motivate offline verification:

- **Air-gapped auditor hardware.** Regulators, customer security teams, and
  internal review boards routinely require evidence to be verified on a
  machine with no outbound network. A bundle that cannot be verified
  offline is not auditor-portable.
- **Reproducibility.** A verifier that calls out to `relay.epochly.com`
  during verification produces a verdict that depends on the JWKS the
  endpoint happened to serve at that moment. Offline verification against
  a cached snapshot is fully deterministic; any two auditors with the
  same bundle and the same cached JWKS produce byte-identical results.
- **No dependency on `relay.epochly.com` reachability at verify time.**
  Network outages, DNS changes, captive portals, or a future migration of
  the JWKS host MUST NOT block verification of a bundle that was already
  produced.

`rly evidence verify` is offline-only by design. It never opens an
outbound socket. The only way it can read a JWKS is from the local cache
at `${RELAY_HOME}/jwks-cache/<host>.json` (see
`packages/cli/src/relay_cli/jwks_cache.py`).

## Prerequisites

- A Relay install with `rly --version` working (see
  [`getting-started/install.md`](../getting-started/install.md)).
- An evidence bundle file on disk. Produce one via `rly verify-self`
  (see [`getting-started/first-evidence-bundle.md`](../getting-started/first-evidence-bundle.md))
  or copy a `.json` bundle delivered by another party.
- A cached JWKS for the bundle's trust anchor under
  `${RELAY_HOME}/jwks-cache/<host>.json`. Step 1 below populates this
  cache; you only do it once per trust anchor per machine.

The default trust anchor URL is the spec-pinned
`https://relay.epochly.com/.well-known/jwks.json` declared in
`DEFAULT_TRUST_ANCHOR_URL` in
`packages/verifier/src/relay_verifier/constants.py`. Per CLAUDE.md
keystone invariant #13 and spec section AO.4 the default is a board-level
constant; forks and self-hosters use BYO trust anchors via the
`--trust-anchor` flag (see
[`trust-anchor.md`](trust-anchor.md) when it lands in M2).

## Step 1: Cache the JWKS (one-time online step)

The cache file is NOT a raw JWKS document. It is a versioned envelope
keyed by trust-anchor URL. Use `rly` to populate the cache rather than
writing the file by hand, so the schema version and URL binding are
correct.

The OSS profile produces a `verify-self` bundle that signs against the
spec-pinned anchor. Running `rly verify-self` once on a connected
machine performs the live JWKS fetch and stores the result in
`${RELAY_HOME}/jwks-cache/relay.epochly.com.json`:

```bash
rly verify-self --json
```

After this completes on a connected machine, the JWKS cache file
contains the envelope described in
`packages/cli/src/relay_cli/jwks_cache.py` (`relay.cli.jwks_cache.v1`):

```json
{
  "schema_version": "relay.cli.jwks_cache.v1",
  "trust_anchor_url": "https://relay.epochly.com/.well-known/jwks.json",
  "fetched_at": "<RFC 3339 UTC>",
  "jwks": { "keys": [ { "...": "..." } ] }
}
```

To transport the cache to an offline machine, copy the entire
`${RELAY_HOME}/jwks-cache/` directory alongside the bundle file. Both
ends of the transport MUST use the same `RELAY_HOME` layout (or pass
`--home` to the offline `rly evidence verify` invocation).

## Step 2: Disconnect network

On the auditor workstation, sever the network: physically unplug, disable
the interface, or run inside a sandbox that denies egress. The remaining
steps make no outbound calls; this severance is a belt-and-suspenders
proof that the verdict in Step 4 cannot depend on a live JWKS fetch.

## Step 3: Verify

`rly evidence verify` accepts either an absolute path to a bundle JSON
file or a bare bundle id resolved under `${RELAY_HOME}/evidence/<id>.json`:

```bash
rly evidence verify "<bundle_path_or_id>"
```

There is no `--no-network` flag because the command is offline-only by
construction. If the JWKS cache for the bundle's trust anchor is missing
or malformed, the CLI exits with `RELAY-CLI-EVIDENCE-NO-JWKS-CACHE` on
stderr and instructs you to pre-fetch the JWKS; it does not attempt to
fetch it itself.

For a BYO trust anchor (forks / self-hosters per spec section AO.4):

```bash
rly evidence verify "<bundle_path_or_id>" --trust-anchor https://example.invalid/.well-known/jwks.json
```

`--trust-anchor` emits a structured stderr WARN line
(`RELAY-CLI-TRUST-ANCHOR-OVERRIDE`) so the override is auditable. The
stdout JSON envelope also records the override under
`trust_anchor_overridden: true`.

## Step 4: Read the VerificationResult

A successful verification exits 0 and emits a single JSON envelope on
stdout. The envelope mirrors the `relay_verifier.VerificationResult`
dataclass in `packages/verifier/src/relay_verifier/verifier.py`
field-for-field; the CLI wraps it with the wire schema version and the
trust-anchor metadata. The schema version literal is
`EVIDENCE_VERIFY_SCHEMA` in
`packages/cli/src/relay_cli/commands/evidence.py`.

```json
{
  "schema_version": "relay.cli.evidence_verify.v1",
  "digest_ok": true,
  "signatures_ok": true,
  "structure_ok": true,
  "signatures_checked": [
    {"kid": "<kid>", "alg": "EdDSA", "ok": true, "reason": ""}
  ],
  "claims_count": 1,
  "trust_anchor": "https://relay.epochly.com/.well-known/jwks.json",
  "trust_anchor_overridden": false,
  "bundle_path": "<RELAY_HOME>/evidence/verify-self/<file>.json",
  "bundle_digest_sha256": "<hex>",
  "errors": []
}
```

Every field maps to a `VerificationResult` attribute (or a CLI-wrapper
field). The verifier source is the canonical reference.

| Envelope field | Source | Meaning |
|---|---|---|
| `digest_ok` | `VerificationResult.digest_ok` | The recorded `signing_input_b64u` of every signature reproduces the recomputed canonical-JSON payload bytes. False signals bundle tampering. |
| `signatures_ok` | `VerificationResult.signatures_ok` | Every signature on the bundle verified against a JWK resolved from the trust anchor. False if any signature failed or no signatures were present. |
| `structure_ok` | `VerificationResult.structure_ok` | The bundle's JSON shape conforms to the v1 schema. False on malformed input. |
| `signatures_checked` | `VerificationResult.signature_checks` (renamed on the wire) | Per-signature outcomes. Each entry carries `kid`, `alg`, `ok`, `reason`, and (for known wire-coded rejections) `code`. |
| `claims_count` | `VerificationResult.claims_count` | Number of `evidence_claims` covered by the bundle. |
| `bundle_digest_sha256` | `VerificationResult.bundle_digest_sha256` | Hex SHA-256 of the canonical bundle bytes (the value the digest check verified against). |
| `errors` | `VerificationResult.errors` | Structured failure reasons; empty list on success. |

A verifier outcome is "pass" iff `digest_ok && signatures_ok &&
structure_ok` and `errors` is empty. Any other combination is a
verification failure: the CLI exits non-zero and emits a structured
stderr envelope (see Interpreting failures below).

## Interpreting failures

`rly evidence verify` maps verification failures to deterministic exit
codes and structured stderr envelopes. Use the table below to triage.

| Stderr code | Exit | Trigger | Where to look |
|---|---|---|---|
| `RELAY-EVID-014` | 1 | Any verification check failed: a signature did not verify, the bundle was tampered (single-byte mutation), the canonical-JSON bytes drift from the recorded `signing_input_b64u`, or a detached claim payload digest does not match. | `signatures_checked[].reason`, `digest_ok`, `signatures_ok`. |
| `RELAY-CLI-EVIDENCE-NO-JWKS-CACHE` | 1 | No cached JWKS for the trust-anchor URL exists at `${RELAY_HOME}/jwks-cache/<host>.json`, or the cached envelope's `trust_anchor_url` does not match. | Re-run Step 1 on a connected machine; copy the cache directory to the offline workstation. |
| `RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND` | 1 | The path or id given as `BUNDLE` does not resolve to a file. | Confirm the path; for an id, confirm `${RELAY_HOME}/evidence/<id>.json` exists. |
| `RELAY-CLI-EVIDENCE-BUNDLE-INVALID` | 2 | The bundle file is not valid UTF-8 JSON, or its root is not a JSON object. | Inspect the bundle file; verify it was not truncated during transport. |

A non-zero exit means the bundle is not auditor-acceptable. Do not edit
the stdout JSON to mask a failure; the `signatures_checked[].reason`
strings are the audit record.

The verifier package also emits per-signature wire codes on the
`signatures_checked[].code` field for crypto-layer rejections
(unsupported algorithm, algorithm/key-type mismatch, detached payload
digest drift). These codes live in
`packages/verifier/src/relay_verifier/errors.py`; the CLI re-emits any
of them as a `RELAY-EVID-014` stderr envelope so a single triage path
applies regardless of which inner check failed.

## Cross-references

- [`signing-key-lifecycle.md`](signing-key-lifecycle.md) (M2; lands in
  this milestone) covers key rotation, the `not_before` / `not_after`
  fields on each JWK, and what to do when a key is revoked.
- [`trust-anchor.md`](trust-anchor.md) (M2; lands in this milestone)
  covers the default JWKS URL, the BYO `--trust-anchor` flag, and the
  board-level discipline that protects the default.
- [`../how-to/verify-bundle-offline.md`](../how-to/verify-bundle-offline.md)
  (M2; lands in this milestone) is the auditor persona walkthrough: it
  starts from receiving a bundle by email and ends at a documented
  acceptance decision.

---

Spec: §K, §AO.4
