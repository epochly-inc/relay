// Public entry point for @epochly/relay-verifier (TypeScript).
//
// Cross-language parity with packages/verifier (Python). The conformance
// corpus at tests/conformance/jws/rfc7515_corpus.json is consumed by both
// implementations; both MUST produce the same canonical-JSON verdict
// envelope per case (VAL-W10-015).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export {
  RELAY_EVID_014,
  RELAY_VERIFY_ALG_MISMATCH,
  RELAY_VERIFY_BUNDLED_MISSING,
  RELAY_VERIFY_CONFIG_INVALID,
  RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH,
  RELAY_VERIFY_JWKS_UNAVAILABLE,
  RELAY_VERIFY_UNSUPPORTED_ALG,
  RelayVerifierError,
} from "./errors.js";
export type { RelayVerifyCode } from "./errors.js";

export {
  ALG_EDDSA,
  ALG_ES256,
  ALG_RS256,
  SUPPORTED_ALGS,
  VERIFIER_RESULT_SCHEMA,
  b64uDecode,
  b64uEncode,
  canonicalJsonBytes,
  verifyDetachedClaimSignature,
  verifyJwsCompact,
  verifyJwsDetached,
  verifyMultiSignatures,
} from "./verifier.js";
export type {
  JWK,
  JWKS,
  MultiSignatureAggregate,
  MultiSignatureResult,
  SignatureCheck,
} from "./verifier.js";
