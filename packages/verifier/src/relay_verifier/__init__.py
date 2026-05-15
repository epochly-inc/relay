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

from .constants import (
    DEFAULT_JWKS_URL,
    DEFAULT_TRUST_ANCHOR_URL,
    VERIFIER_PACKAGE_NAME,
)
from .errors import (
    RELAY_VERIFY_BUNDLED_MISSING,
    RELAY_VERIFY_CONFIG_INVALID,
    RELAY_VERIFY_JWKS_UNAVAILABLE,
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
from .verifier import (
    ALG_EDDSA,
    ALG_ES256,
    SUPPORTED_ALGS,
    VERIFIER_RESULT_SCHEMA,
    SignatureCheck,
    VerificationResult,
    canonical_json_bytes,
    parse_bundle_bytes,
    verify_bundle,
)

__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "DEFAULT_JWKS_URL",
    "DEFAULT_TRUST_ANCHOR_URL",
    "JWKS_CACHE_DIRNAME",
    "JWKS_CACHE_SCHEMA_VERSION",
    "JWKSLoadResult",
    "NetworkFetcher",
    "RELAY_VERIFY_BUNDLED_MISSING",
    "RELAY_VERIFY_CONFIG_INVALID",
    "RELAY_VERIFY_JWKS_UNAVAILABLE",
    "RelayBundledJWKSMissingError",
    "RelayConfigInvalidError",
    "RelayJWKSUnavailableError",
    "RelayVerifierError",
    "SUPPORTED_ALGS",
    "SignatureCheck",
    "TRUST_ANCHOR_SOURCE_BUNDLED",
    "TRUST_ANCHOR_SOURCE_BYO_CONFIG",
    "TRUST_ANCHOR_SOURCE_BYO_FLAG",
    "TRUST_ANCHOR_SOURCE_CACHE",
    "TRUST_ANCHOR_SOURCE_LIVE",
    "VERIFIER_PACKAGE_NAME",
    "VERIFIER_RESULT_SCHEMA",
    "VerificationResult",
    "canonical_json_bytes",
    "load_bundled_jwks",
    "load_cached_jwks",
    "parse_bundle_bytes",
    "resolve_jwks",
    "resolve_trust_anchor_url",
    "verify_bundle",
]
