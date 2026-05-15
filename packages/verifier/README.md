# epochly-relay-verifier

Apache 2.0 OSS offline evidence verifier for Relay.

## What this package does (W10.1 surface)

Resolves a trust-anchor JWKS for verifying Relay evidence bundles, with
strict offline-first semantics. The verifier:

- Compiles in the spec-pinned default JWKS URL
  (`https://relay.epochly.com/.well-known/jwks.json`) per spec section AO.4.
- Ships a bundled JWKS snapshot inside the wheel so air-gapped auditors can
  verify without any network access.
- Accepts a BYO trust anchor via `--trust-anchor <url>` (flag) or
  `trust_anchor_url = "..."` (config file).
- Falls back to a cached JWKS when the live fetch fails, with a structured
  stderr WARN naming `cache_age_seconds` and `cache_staleness_threshold_seconds`.
- Fails clearly with a typed error (`RelayJWKSUnavailableError`) when no
  source is available -- no silent fallback.

Future sub-features (w10.2/w10.3/w10.4) add RFC 7515 JWS conformance
corpus, RFC 8785 JCS conformance corpus, and full evidence-bundle validate
flows on top of this loader.

## Trust-anchor governance (banned pattern #13)

Changing the compiled-in default JWKS URL is a CLAUDE.md banned pattern
#13 violation unless approved as a board-level decision. The OSS verifier
defaults to the spec-pinned Relay-Inc anchor; forks and self-hosters
override at runtime via `--trust-anchor` or a config file.

The single canonical occurrence of the default URL literal lives in
`src/relay_verifier/constants.py`. A guard test at
`tests/guards/default_trust_anchor_lock.py` asserts the constant against a
frozen reference value; any mutation trips a structured CI failure.

## Trust-anchor key material (banned pattern #14)

This package SHIPS a bundled JWKS snapshot containing **public keys only**.
The Apache 2.0 grant does NOT cover trust-anchor signing private keys, KMS
references, TSA partner credentials, or transparency-log custody keys --
those live exclusively in `relay-platform`.

The bootstrap bundled JWKS in `src/relay_verifier/bundled_jwks.json`
contains placeholder example keys; the W12 release pipeline replaces it
with the current production JWKS snapshot before each tagged release.

## Usage

```python
from relay_verifier import (
    resolve_jwks,
    verify_bundle,
    parse_bundle_bytes,
    RelayJWKSUnavailableError,
)

# Offline verification (bundled JWKS only; no network, no cache).
result = resolve_jwks(offline=True)
print(result.source)  # "bundled_jwks"

# BYO trust anchor via flag.
def my_fetcher(url): return ...  # caller-supplied HTTP client
result = resolve_jwks(flag_url="https://example.org/.well-known/jwks.json",
                     fetcher=my_fetcher)
print(result.source)  # "byo_flag"

# Verify a bundle.
bundle = parse_bundle_bytes(open("bundle.json", "rb").read())
verification = verify_bundle(bundle, result.jwks)
assert verification.digest_ok and verification.signatures_ok
```

## License

Apache 2.0. See `LICENSE` at the repository root.
