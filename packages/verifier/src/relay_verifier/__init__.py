"""Relay offline evidence verifier (Apache 2.0 OSS).

W10.1 surface: trust-anchor JWKS resolution with a compiled-in default
URL, a bundled JWKS snapshot shipped inside the wheel, BYO trust-anchor
via flag or config file, cached-JWKS fallback when live fetch fails,
and a clear-fail path when no JWKS source is available.

Per spec section AO.4 line 6165 and CLAUDE.md keystone invariant #11 the
OSS verifier defaults to the spec-pinned JWKS URL. The canonical literal
lives in :mod:`relay_verifier.constants` (single occurrence; CLAUDE.md
banned pattern #13 requires that changing this default is a board-level
decision).

This package is import-boundary safe: it depends only on
``epochly-relay-schemas`` (workspace) and the standard library plus
``cryptography`` for JWS verification. It does NOT import the CLI,
sidecar, or any control-plane service module.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .bundle_validator import (
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_ENTRIES,
    RELAY_EVID_024,
    RELAY_EVID_040,
    TRUST_ANCHOR_LOCAL_DEV,
    VERIFIER_OUTPUT_SCHEMA,
    WARN_LOCAL_DEV_UNSUPPORTED,
    ValidateBundleOptions,
    check_archive_bomb_limits,
    validate_bundle,
    validate_bundle_with_archive_check,
)
from .canonical import (
    JCSEncodeError,
    bundle_digest,
    jcs_canonicalize,
)
from .constants import (
    DEFAULT_JWKS_URL,
    DEFAULT_TRUST_ANCHOR_URL,
    VERIFIER_PACKAGE_NAME,
)
from .errors import (
    RELAY_VERIFY_ALG_MISMATCH,
    RELAY_VERIFY_BUNDLED_MISSING,
    RELAY_VERIFY_CONFIG_INVALID,
    RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH,
    RELAY_VERIFY_JWKS_UNAVAILABLE,
    RELAY_VERIFY_UNSUPPORTED_ALG,
    RelayBundledJWKSMissingError,
    RelayConfigInvalidError,
    RelayJWKSUnavailableError,
    RelayVerifierError,
)
from .jwks_loader import (
    JWKS_CACHE_DIRNAME,
    JWKS_CACHE_SCHEMA_VERSION,
    TRUST_ANCHOR_SOURCE_BUNDLED,
    TRUST_ANCHOR_SOURCE_BYO_CONFIG,
    TRUST_ANCHOR_SOURCE_BYO_FLAG,
    TRUST_ANCHOR_SOURCE_CACHE,
    TRUST_ANCHOR_SOURCE_LIVE,
    JWKSLoadResult,
    NetworkFetcher,
    load_bundled_jwks,
    load_cached_jwks,
    resolve_jwks,
    resolve_trust_anchor_url,
)
from .key_lifecycle import (
    RELAY_EVID_041,
    RELAY_EVID_042,
    KeyLifecycleResult,
    check_signing_key_lifecycle,
)
from .merkle import (
    build_inclusion_proof,
    compute_merkle_root,
    verify_inclusion_proof,
)
from .retention import (
    SUBJECT_RESOLUTION_LIVE,
    SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
    SUBJECT_RESOLUTION_TOMBSTONED,
    SUBJECT_RESOLUTION_UNKNOWN,
    InMemorySubjectStore,
    SubjectRecord,
    SubjectResolutionResult,
    SubjectStore,
    resolve_subject,
)
from .transparency_log import (
    LogInclusionResult,
    verify_log_inclusion,
)
from .tsa import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MIN_RSA_BITS,
    RELAY_EVID_031,
    RELAY_EVID_038,
    TSA_CHAIN_DIRNAME,
    TSA_CHAIN_FILENAME,
    TSACertSummary,
    TSAChainCheck,
    TSAValidationResult,
    inspect_tsa_chain,
    load_bundled_tsa_chain,
    load_tsa_chain_pem_bytes,
    validate_tsa_token,
)
from .verifier import (
    ALG_EDDSA,
    ALG_ES256,
    ALG_RS256,
    RELAY_EVID_014,
    SUPPORTED_ALGS,
    VERIFIER_RESULT_SCHEMA,
    MultiSignatureResult,
    SignatureCheck,
    VerificationResult,
    canonical_json_bytes,
    jwk_from_ec_p256_public_key,
    jwk_from_ed25519_public_key,
    jwk_from_rsa_public_key,
    parse_bundle_bytes,
    sign_payload_ed25519,
    sign_payload_es256,
    sign_payload_rs256,
    verify_bundle,
    verify_detached_claim_signature,
    verify_jws_compact,
    verify_jws_detached,
    verify_multi_signatures,
)

__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "ALG_RS256",
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "DEFAULT_JWKS_URL",
    "DEFAULT_TRUST_ANCHOR_URL",
    "InMemorySubjectStore",
    "JCSEncodeError",
    "JWKS_CACHE_DIRNAME",
    "JWKS_CACHE_SCHEMA_VERSION",
    "JWKSLoadResult",
    "KeyLifecycleResult",
    "LogInclusionResult",
    "MAX_BUNDLE_BYTES",
    "MAX_BUNDLE_ENTRIES",
    "MIN_RSA_BITS",
    "MultiSignatureResult",
    "NetworkFetcher",
    "RELAY_EVID_014",
    "RELAY_EVID_024",
    "RELAY_EVID_031",
    "RELAY_EVID_038",
    "RELAY_EVID_040",
    "RELAY_EVID_041",
    "RELAY_EVID_042",
    "RELAY_VERIFY_ALG_MISMATCH",
    "RELAY_VERIFY_BUNDLED_MISSING",
    "RELAY_VERIFY_CONFIG_INVALID",
    "RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH",
    "RELAY_VERIFY_JWKS_UNAVAILABLE",
    "RELAY_VERIFY_UNSUPPORTED_ALG",
    "RelayBundledJWKSMissingError",
    "RelayConfigInvalidError",
    "RelayJWKSUnavailableError",
    "RelayVerifierError",
    "SUBJECT_RESOLUTION_LIVE",
    "SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING",
    "SUBJECT_RESOLUTION_TOMBSTONED",
    "SUBJECT_RESOLUTION_UNKNOWN",
    "SUPPORTED_ALGS",
    "SignatureCheck",
    "SubjectRecord",
    "SubjectResolutionResult",
    "SubjectStore",
    "TRUST_ANCHOR_LOCAL_DEV",
    "TRUST_ANCHOR_SOURCE_BUNDLED",
    "TRUST_ANCHOR_SOURCE_BYO_CONFIG",
    "TRUST_ANCHOR_SOURCE_BYO_FLAG",
    "TRUST_ANCHOR_SOURCE_CACHE",
    "TRUST_ANCHOR_SOURCE_LIVE",
    "TSA_CHAIN_DIRNAME",
    "TSA_CHAIN_FILENAME",
    "TSACertSummary",
    "TSAChainCheck",
    "TSAValidationResult",
    "VERIFIER_OUTPUT_SCHEMA",
    "VERIFIER_PACKAGE_NAME",
    "VERIFIER_RESULT_SCHEMA",
    "ValidateBundleOptions",
    "VerificationResult",
    "WARN_LOCAL_DEV_UNSUPPORTED",
    "build_inclusion_proof",
    "bundle_digest",
    "canonical_json_bytes",
    "check_archive_bomb_limits",
    "check_signing_key_lifecycle",
    "compute_merkle_root",
    "inspect_tsa_chain",
    "jcs_canonicalize",
    "jwk_from_ec_p256_public_key",
    "jwk_from_ed25519_public_key",
    "jwk_from_rsa_public_key",
    "load_bundled_jwks",
    "load_bundled_tsa_chain",
    "load_cached_jwks",
    "load_tsa_chain_pem_bytes",
    "parse_bundle_bytes",
    "resolve_jwks",
    "resolve_subject",
    "resolve_trust_anchor_url",
    "sign_payload_ed25519",
    "sign_payload_es256",
    "sign_payload_rs256",
    "validate_bundle",
    "validate_bundle_with_archive_check",
    "validate_tsa_token",
    "verify_bundle",
    "verify_detached_claim_signature",
    "verify_inclusion_proof",
    "verify_jws_compact",
    "verify_jws_detached",
    "verify_log_inclusion",
    "verify_multi_signatures",
]
