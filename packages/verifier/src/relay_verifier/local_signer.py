"""OSS local-dev evidence bundle signer (w8-trust-anchor).

Builds an evidence bundle signed by an in-memory Ed25519 keypair and
stamped with ``trust_anchor: "local_dev"`` per spec section AO.4 line
6166. This is the OSS profile that lets a developer running the
local-sidecar produce a Relay-format evidence bundle WITHOUT having to
provision a hosted Relay account or contact the Relay-Inc trust anchor.

Load-bearing guarantees (CLAUDE.md keystone invariants #11, #13, #14;
contract assertions VAL-V2M08-043, VAL-V2M08-044):

  1. **Every bundle stamped ``trust_anchor: "local_dev"``.** No opt-in
     flag, no override. The OSS local signer cannot be persuaded to
     emit a Relay-Inc-labelled bundle: if a developer wants Relay-Inc
     trust they must run against the hosted control plane.

  2. **Private key material lives in memory only.** The signer accepts
     an in-process :class:`ed25519.Ed25519PrivateKey` and never writes
     it to disk, never logs it, never returns it through a serialisable
     surface. Banned pattern #14 (no private key material committed)
     applies.

  3. **Cache-key namespace isolation.** A JWKS fetched against a
     ``local_dev``-labelled bundle MUST occupy a separate cache
     namespace from the Relay-Inc default anchor cache. The helper
     :func:`local_dev_cache_key` returns the namespaced key and
     refuses the Relay-Inc URL outright (a local-dev cache slot for
     the Relay-Inc URL is the exact mis-classification VAL-V2M08-044
     defends against).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ed25519

from .bundle_validator import (
    TRUST_ANCHOR_CLASS_RELAY_INC,
    TRUST_ANCHOR_LOCAL_DEV,
    classify_trust_anchor,
)
from .canonical import bundle_digest
from .merkle import compute_merkle_root
from .verifier import (
    canonical_json_bytes,
    jwk_from_ed25519_public_key,
    sign_payload_ed25519,
)

# Re-export so callers can ``from relay_verifier.local_signer import
# TRUST_ANCHOR_LOCAL_DEV`` without indirecting through bundle_validator.
__all_consts__ = ("TRUST_ANCHOR_LOCAL_DEV",)


LOCAL_DEV_CACHE_PREFIX: Final[str] = "local_dev"
"""Cache-key namespace prefix for OSS local-dev JWKS entries.

Per VAL-V2M08-044 the OSS local signer's JWKS cache slot MUST occupy a
distinct namespace from the Relay-Inc default anchor cache so a
local-dev-labelled JWKS cannot auto-promote into the Relay-Inc cache
slot. The full cache key is
``<LOCAL_DEV_CACHE_PREFIX>:<filesystem-safe-host>``.
"""


_HOST_FILENAME_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]")


@dataclass(frozen=True)
class LocalDevBundle:
    """Container returned by :func:`build_local_dev_bundle`.

    Attributes:
        bundle: the assembled bundle dict (carries ``trust_anchor:
            "local_dev"``, the signed payload, and a single signature
            record).
        jwks: a JWKS dict containing only the local-dev signer's
            public key, suitable for passing to
            :func:`relay_verifier.validate_bundle` as the trust anchor.
        signer_kid: the kid embedded in the JWK and the signature
            record.
        bundle_digest_hex: the SHA-256 of the verifier-canonical-JSON
            of the signed payload (everything except ``signatures``).
            Useful for tests and for binding the bundle into downstream
            artifacts.
    """

    bundle: dict[str, Any]
    jwks: dict[str, Any]
    signer_kid: str
    bundle_digest_hex: str
    # Private signing key kept here for round-trip tests; never
    # persisted by this module. Stored as a non-default field so it
    # cannot be accidentally serialised through dataclasses.asdict
    # (cryptography key objects are not JSON-serialisable).
    signing_key: ed25519.Ed25519PrivateKey = field(repr=False, hash=False, compare=False)


def build_local_dev_bundle(
    *,
    claims: list[dict[str, Any]] | None = None,
    signer_kid: str = "relay-local-dev-signer",
    signer_seed: bytes | None = None,
    decided_at: str | None = None,
    signed_at: str | None = None,
    subject_id: str | None = "run_local_dev",
    include_merkle: bool = True,
) -> LocalDevBundle:
    """Construct a local-dev-signed evidence bundle.

    Every bundle produced by this helper carries ``trust_anchor:
    "local_dev"`` (VAL-V2M08-043; the value is hard-coded and cannot
    be overridden). The signature is an Ed25519 JWS over the canonical
    payload bytes.

    Args:
        claims: list of claim dicts. Defaults to a single placeholder
            claim if None.
        signer_kid: kid to embed in the signer JWK and the signature
            record. Defaults to ``relay-local-dev-signer``.
        signer_seed: optional 32-byte seed for deterministic key
            generation (test fixtures). When None a non-deterministic
            random key is generated via cryptography's secure RNG. The
            key is held in memory only and not returned through a
            serialisable surface.
        decided_at: ISO-8601 UTC timestamp the bundle records as its
            decided_at anchor. Defaults to "now" in UTC.
        signed_at: ISO-8601 UTC timestamp the bundle records as its
            signed_at anchor. Defaults to ``decided_at``.
        subject_id: optional subject id; the helper derives
            subject_digest_hex as SHA-256(subject_id) when subject_id
            is provided.
        include_merkle: when True, computes and embeds
            ``merkle_root_hex`` over claim digests.

    Returns:
        A :class:`LocalDevBundle` whose ``bundle`` is fully assembled
        (trust_anchor stamped, signature present) and whose ``jwks``
        is the matching public-key set for verification.

    Raises:
        ValueError: if ``signer_seed`` is provided but not exactly
            32 bytes.
    """
    if claims is None:
        claims = [
            {
                "claim_id": "claim-local-dev-placeholder",
                "kind": "command_evidence",
                "command_id": "echo",
                "exit_code": 0,
            },
        ]

    if signer_seed is not None:
        if len(signer_seed) != 32:
            raise ValueError(
                f"signer_seed must be exactly 32 bytes; got {len(signer_seed)}"
            )
        signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(signer_seed)
    else:
        signing_key = ed25519.Ed25519PrivateKey.generate()

    signer_jwk = jwk_from_ed25519_public_key(
        signing_key.public_key(),
        kid=signer_kid,
        not_before="2026-01-01T00:00:00Z",
        not_after="2028-01-01T00:00:00Z",
    )
    jwks: dict[str, Any] = {"keys": [signer_jwk]}

    if decided_at is None:
        decided_at = (
            _dt.datetime.now(tz=_dt.UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    if signed_at is None:
        signed_at = decided_at

    subject_digest_hex: str | None = None
    if subject_id is not None:
        subject_digest_hex = hashlib.sha256(
            subject_id.encode("utf-8")
        ).hexdigest()

    # Build the core payload (no signatures yet). The trust_anchor
    # value is HARD-CODED here -- this is the load-bearing guarantee
    # of VAL-V2M08-043. The OSS local signer cannot emit a Relay-Inc
    # bundle.
    core_payload: dict[str, Any] = {
        "schema_version": "relay.evidence_bundle.v1",
        "evidence_bundle_id": "bundle-local-dev",
        "trust_anchor": TRUST_ANCHOR_LOCAL_DEV,
        "decided_at": decided_at,
        "signed_at": signed_at,
        "claims": claims,
        "subject_id": subject_id,
        "subject_digest_hex": subject_digest_hex,
    }
    if include_merkle:
        claim_digests = [bundle_digest(c) for c in claims if isinstance(c, dict)]
        core_payload["merkle_root_hex"] = compute_merkle_root(claim_digests)

    binding_digest_hex = hashlib.sha256(
        canonical_json_bytes(core_payload)
    ).hexdigest()

    sig_record = sign_payload_ed25519(core_payload, signing_key, kid=signer_kid)
    bundle = dict(core_payload)
    bundle["signatures"] = [sig_record]

    return LocalDevBundle(
        bundle=bundle,
        jwks=jwks,
        signer_kid=signer_kid,
        bundle_digest_hex=binding_digest_hex,
        signing_key=signing_key,
    )


def local_dev_cache_key(jwks_url: str) -> str:
    """Return the namespaced cache key for a local-dev JWKS URL.

    The OSS local signer's JWKS cache MUST live in a distinct namespace
    from the default-anchor cache (VAL-V2M08-044): a local-dev JWKS
    cannot be allowed to silently auto-promote into the slot the
    Relay-Inc default anchor occupies on disk.

    The returned key has the shape
    ``{LOCAL_DEV_CACHE_PREFIX}:{host[:port]}`` where host is
    lowercase-normalised and filesystem-safe.

    Args:
        jwks_url: the URL the local-dev signer wants to cache a JWKS
            for. MUST classify as ``byo`` (typically a localhost or
            private-IP URL); the Relay-Inc default URL is refused
            outright with :class:`ValueError`.

    Raises:
        ValueError: when the URL classifies as Relay-Inc -- a local_dev
            cache slot for the Relay-Inc URL is the exact mis-namespace
            VAL-V2M08-044 defends against.
        ValueError: when the URL has no hostname (un-parseable).
    """
    cls = classify_trust_anchor(jwks_url)
    if cls == TRUST_ANCHOR_CLASS_RELAY_INC:
        raise ValueError(
            f"local_dev cache key refused for Relay-Inc URL {jwks_url!r}; "
            f"the Relay-Inc anchor occupies a separate cache namespace "
            f"and a local_dev slot for it would auto-promote local_dev "
            f"bundles into the default-anchor cache (VAL-V2M08-044)"
        )
    parsed = urlparse(jwks_url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError(f"local_dev cache key URL has no hostname: {jwks_url!r}")
    if parsed.port is not None:
        host = f"{host}_{parsed.port}"
    safe = _HOST_FILENAME_SAFE_RE.sub("_", host)
    return f"{LOCAL_DEV_CACHE_PREFIX}:{safe}"


__all__ = [
    "LOCAL_DEV_CACHE_PREFIX",
    "TRUST_ANCHOR_LOCAL_DEV",
    "LocalDevBundle",
    "build_local_dev_bundle",
    "local_dev_cache_key",
]
