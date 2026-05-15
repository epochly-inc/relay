# @epochly/relay-verifier (TypeScript)

Relay offline JWS evidence verifier (TypeScript). Cross-language parity
with `packages/verifier` (Python).

## Scope

Implements the W10.2 contract surface (VAL-W10-010 through VAL-W10-015):

- RFC 7515 compact-form JWS verification
- Algorithm allow-list `{EdDSA, ES256, RS256}`
- Alg-substitution attack rejection (RFC 8725 sec 3)
- Detached JWS payload binding (RFC 7797 + Relay claim digest)
- Multi-signature payloads with per-signature verdicts
- Cross-language verdict parity with the Python verifier

## Status

`v0.1` OSS wedge. Pure-stdlib runtime: depends only on Node's built-in
`crypto` module. No external dependencies in the runtime tree.

## Public API

```ts
import {
  ALG_EDDSA, ALG_ES256, ALG_RS256, SUPPORTED_ALGS,
  RELAY_EVID_014,
  RELAY_VERIFY_ALG_MISMATCH,
  RELAY_VERIFY_UNSUPPORTED_ALG,
  verifyJwsCompact,
  verifyJwsDetached,
  verifyDetachedClaimSignature,
  verifyMultiSignatures,
  canonicalJsonBytes,
  type SignatureCheck,
  type MultiSignatureResult,
  type JWK, type JWKS,
} from "@epochly/relay-verifier";
```

## Design

The verifier is **defense-in-depth**: every public function gates on
allow-list -> kty-mismatch -> JWK load -> crypto verify. The corpus at
`tests/conformance/jws/rfc7515_corpus.json` is consumed by both this
package AND `packages/verifier` (Python); both implementations MUST
produce the same canonical-JSON verdict envelope per case
(VAL-W10-015).

## License

Apache-2.0. See `LICENSE` at the repository root.
