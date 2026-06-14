// Public entry point for @epochly/relay-verifier (TypeScript).
//
// Cross-language parity with packages/verifier (Python). The conformance
// corpora at tests/conformance/jws/ and tests/conformance/verifier/ are
// consumed by both implementations; both MUST produce the same canonical-
// JSON verdict envelope per case (VAL-W10-015, VAL-V2M06-024).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export {
  JCSEncodeError,
  bundleDigest,
  jcsCanonicalize,
} from "./canonical.js";

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
  verifyBundleSignature,
  verifyDetachedClaimSignature,
  verifyJwsCompact,
  verifyJwsDetached,
  verifyMultiSignatures,
} from "./verifier.js";
export type {
  BundleSignatureEntry,
  JWK,
  JWKS,
  MultiSignatureAggregate,
  MultiSignatureResult,
  SignatureCheck,
} from "./verifier.js";

export {
  MAX_ARTIFACT_PATH_BYTES,
  RELAY_EVID_024_PATH,
  checkArtifactPath,
} from "./bundle_paths.js";
export type { PathViolation } from "./bundle_paths.js";

// ----------------------------------------------------------------------------
// M06: TypeScript verifier parity surface (VAL-V2M06-001..025)
// ----------------------------------------------------------------------------

export {
  DEFAULT_JWKS_URL,
  DEFAULT_TRUST_ANCHOR_URL,
  VERIFIER_PACKAGE_NAME,
} from "./constants.js";

export {
  CLOCK_SKEW_TOLERANCE_SECONDS,
  MIN_RSA_BITS,
  RELAY_EVID_031,
  RELAY_EVID_038,
  TSA_CHAIN_DIRNAME,
  TSA_CHAIN_FILENAME,
  TSA_CRYPTO_IMPLEMENTED,
  inspectTsaChain,
  loadBundledTsaChain,
  loadTsaChainPemBytes,
  restoreBase64Padding,
  validateTsaToken,
} from "./tsa.js";
export type {
  TSACertSummary,
  TSAChainCheck,
  TSAValidationResult,
  TsaToken,
} from "./tsa.js";

export {
  buildInclusionProof,
  computeMerkleRoot,
  verifyInclusionProof,
} from "./merkle.js";

export {
  verifyLogInclusion,
} from "./transparency_log.js";
export type { LogInclusionResult } from "./transparency_log.js";

export {
  RELAY_EVID_041,
  RELAY_EVID_042,
  checkSigningKeyLifecycle,
} from "./key_lifecycle.js";
export type { KeyLifecycleResult } from "./key_lifecycle.js";

export {
  InMemorySubjectStore,
  SUBJECT_RESOLUTION_LIVE,
  SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
  SUBJECT_RESOLUTION_TOMBSTONED,
  SUBJECT_RESOLUTION_UNKNOWN,
  resolveSubject,
} from "./retention.js";
export type {
  SubjectRecord,
  SubjectResolutionResult,
  SubjectStore,
} from "./retention.js";

export {
  BUNDLED_JWKS_ASSET,
  CACHE_STALENESS_THRESHOLD_SECONDS,
  JWKS_CACHE_DIRNAME,
  JWKS_CACHE_SCHEMA_VERSION,
  TRUST_ANCHOR_SOURCE_BUNDLED,
  TRUST_ANCHOR_SOURCE_BYO_CONFIG,
  TRUST_ANCHOR_SOURCE_BYO_FLAG,
  TRUST_ANCHOR_SOURCE_CACHE,
  TRUST_ANCHOR_SOURCE_LIVE,
  cachePathForUrl,
  checkHostConfusable,
  hostnameForUrl,
  loadBundledJwks,
  loadCachedJwks,
  resolveJwks,
  resolveTrustAnchorUrl,
} from "./jwks_loader.js";
export type {
  JWKSLoadResult,
  NetworkFetcher,
  ResolveJwksArgs,
  ResolveTrustAnchorArgs,
  TrustAnchorSource,
} from "./jwks_loader.js";

export {
  MAX_BUNDLE_BYTES,
  MAX_BUNDLE_ENTRIES,
  MAX_BUNDLE_SIGNATURES,
  RELAY_EVID_024,
  RELAY_EVID_040,
  RELAY_EVID_NAMESPACE_UNKNOWN,
  RELAY_EVID_DECIDED_AT_MISSING,
  RELAY_EVID_MISSING_TRUST_ANCHOR,
  RELAY_EVID_SIGCOUNT_EXCEEDED,
  SIGNER_ROLE_CONTROL_PLANE,
  SIGNER_ROLE_LOCAL_DEV,
  SIGNER_ROLE_UNKNOWN,
  TRUST_ANCHOR_CLASS_BYO,
  TRUST_ANCHOR_CLASS_RELAY_INC,
  TRUST_ANCHOR_CLASS_UNTRUSTED_LOCAL,
  TRUST_ANCHOR_LOCAL_DEV,
  VERIFIER_OUTPUT_SCHEMA,
  WARN_LOCAL_DEV_UNSUPPORTED,
  checkArchiveBombLimits,
  classifySignerRole,
  classifyTrustAnchor,
  validateBundle,
  validateBundleWithArchiveCheck,
} from "./bundle_validator.js";
export type {
  SignerRole,
  TrustAnchorClass,
  ValidateBundleOptions,
  VerifierOutputEnvelope,
} from "./bundle_validator.js";
