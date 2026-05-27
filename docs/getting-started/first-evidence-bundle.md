# Your First Evidence Bundle

This page walks you from a working `rly` install (see
[`install.md`](install.md)) to producing, locating, and offline-verifying
your first Relay evidence bundle. Every shell block tagged `run` is
executed end-to-end by the docs codebase-alignment audit
(`scripts/docs/audit-codebase-alignment.py`); if a step on this page
ever drifts from what the OSS repo actually does, the audit fails and
the page does not ship.

## What an evidence bundle is

An evidence bundle is a content-addressed, JWS-signed JSON object that
binds one or more `evidence_claims` (artifact hashes, command IDs, exit
codes, span IDs, assertion IDs, manifest commit hashes) to a
machine-verifiable signature. The verifier resolves a JWKS (the trust
anchor) and confirms the bundle's digest, structure, and every signature
without making a network call. Per keystone invariant #2 a "pass" claim
that lacks any of those bindings is `invalid`, not `accepted` -- the
bundle is the only thing an auditor can take offline and trust.

## Produce a bundle

The OSS profile produces a §K-conformant evidence bundle on every
invocation of `rly verify-self` (pass or fail). The bundle is written
to `${RELAY_HOME}/evidence/verify-self/<timestamp>-<run_id>.json`.

```bash
rly verify-self --json
```

The stdout JSON envelope reports the overall verifier outcome; the
bundle is written to disk as a side effect. Inspect what landed:

```bash
rly evidence list --limit 5
```

`rly evidence list` paginates the locally stored bundles and prints
each bundle's binding fields (id, digest, claim count, written-at
timestamp). The most recent entry is the bundle `verify-self` just
produced.

To inspect the raw bundle JSON before verifying it, use `show`:

```bash
rly evidence show "<bundle_id>"
```

Replace `<bundle_id>` with the id from the previous `list` output. The
`--json/--no-json` flag controls rendering; the OSS profile defaults to
JSON for v0.1.

## Verify the bundle

`rly evidence verify` runs the offline JWS verifier from
`packages/verifier/`. No outbound network call is attempted at any
point in this command: if the JWKS is not cached locally the CLI exits
with `RELAY-CLI-EVIDENCE-NO-JWKS-CACHE` and instructs you to pre-fetch
the JWKS. The default trust anchor is the spec-pinned URL declared in
`DEFAULT_TRUST_ANCHOR_URL` in
`packages/verifier/src/relay_verifier/constants.py`; `--trust-anchor`
accepts a BYO JWKS URL for forks and self-hosters (it emits a
structured stderr WARN line when used).

```bash
rly evidence verify "<bundle_id>"
```

## Read the result

A successful verification exits 0 and emits a single JSON envelope on
stdout. The envelope mirrors the
`relay_verifier.VerificationResult` dataclass in
`packages/verifier/src/relay_verifier/verifier.py` field-for-field; the
CLI wraps it with the wire schema version and trust-anchor metadata.

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

The wire envelope combines fields from the verifier library's
`VerificationResult` dataclass with three CLI-level fields the
`rly evidence verify` command adds at emit time.

Fields from `VerificationResult` (verifier-library output):

| Field | Meaning |
|---|---|
| `digest_ok` | The bundle's content-addressed digest matches its recomputed digest. |
| `signatures_ok` | Every signature on the bundle verified against a resolved JWK. |
| `structure_ok` | The bundle's JSON shape conforms to the v1 schema. |
| `signatures_checked` | Per-signature outcomes (`kid`, `alg`, `ok`, `reason`). The CLI wire-envelope key is `signatures_checked`; the dataclass attribute is `signature_checks`. |
| `claims_count` | Number of `evidence_claims` covered by the bundle. |
| `bundle_digest_sha256` | Hex SHA-256 of the canonical bundle bytes (the value the digest check verified against). |
| `errors` | Structured failure reasons; empty list on success. |

Fields added by the CLI envelope (set by `rly evidence verify` after
the verifier returns):

| Field | Meaning |
|---|---|
| `trust_anchor` | The JWKS URL that resolved the bundle's signing keys. |
| `trust_anchor_overridden` | `true` when `--trust-anchor` was passed; `false` for the default anchor. |
| `bundle_path` | Filesystem path the CLI loaded the bundle from. |

A verifier outcome is "pass" iff `digest_ok && signatures_ok &&
structure_ok` and `errors` is empty. A single-byte mutation of the
bundle causes a non-zero exit, a `RELAY-EVID-014` stderr envelope, and
`digest_ok: false, signatures_ok: false` on stdout (per `VAL-W5-028`).

## What just happened

Three artifacts came together:

- **JWS payload.** The bundle's `evidence_claims` are canonicalized
  (RFC 8785 JCS) and signed under one or more JWKs. Supported
  algorithms are `EdDSA`, `ES256`, and `RS256` (see `SUPPORTED_ALGS`).
- **Merkle root.** Each claim is a leaf in a Merkle tree; the root
  appears in the signed payload so an auditor can prove a specific
  claim's inclusion offline (`compute_merkle_root`,
  `verify_inclusion_proof`).
- **Trust anchor.** The verifier resolved the JWKS via the
  precedence chain in `resolve_jwks` (BYO flag, BYO config, live
  fetch, cache, bundled snapshot) and recorded which source it used.
  The default JWKS URL is a board-level constant; the
  [`evidence/trust-anchor.md`](../evidence/trust-anchor.md) page (when
  it lands in M2) covers BYO trust anchors and the offline JWKS
  cache.

## Next

Continue to [`first-replay.md`](first-replay.md) to record a cassette
and play it back deterministically.

---

Spec: §K, §AO.4
