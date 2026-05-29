"""W11.4 Relay-owned ACEF bundle JWS verifier (VAL-CRYPTO-001/004/005).

These tests reproduce three adversarially-verified findings against the
vendored ACEF SDK and prove the Relay-OWNED fail-closed verifier closes
them. The fixes live in ``packages/acef/src/relay_acef/bundle_verifier.py``;
the vendored ``upstream/`` tree is byte-immutable and is NOT touched.

  * VAL-CRYPTO-001 (finding #3): the vendored
    ``integrity_checker._check_signatures`` is a no-op -- it base64-decodes
    the JWS header and checks ``alg`` membership but never reconstructs the
    signing input nor verifies the signature. A tampered bundle with a
    recomputed content hash and a retained original signature passes. The
    Relay verifier reconstructs the JCS-canonical signed payload, verifies
    every signature cryptographically, and fails CLOSED on any mismatch.

  * VAL-CRYPTO-004 (finding #13): the vendored
    ``signing.verify_detached_jws`` resolves the verification key from the
    JWS header (``x5c``/``jwk``) when no explicit key is supplied, so a
    bundle signed with an attacker's own key whose public half is embedded
    in the header verifies. The Relay verifier NEVER reads a key from the
    header; it resolves the trusted public key from the supplied JWKS by
    ``kid`` only. A bundle whose ``kid`` is absent from the trusted JWKS is
    rejected even though its header carries a self-consistent ``jwk``.

  * VAL-CRYPTO-005 (finding #15): the vendored ``op_bundle_signed`` counts
    ``.jws`` files by header format (no crypto) and, when ``required_alg``
    is a string, does ``a in required_alg`` -- a Python substring test, so
    ``"S256" in "ES256"`` and ``"256" in "ES256"`` both pass. The Relay
    verifier exposes a count of CRYPTOGRAPHICALLY-VERIFIED signatures only
    (ok=True), and matches a required algorithm by EXACT set membership.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from relay_acef.bundle_verifier import (
    ACEFVerificationResult,
    count_verified_signatures,
    required_alg_matches,
    verify_acef_bundle,
)
from relay_acef.bundle_verifier import (
    jwk_from_ec_p256_public_key as _jwk_ec,
)
from relay_acef.bundle_verifier import (
    jwk_from_ed25519_public_key as _jwk_ed,
)
from relay_acef.bundle_verifier import (
    sign_acef_bundle_ed25519 as _sign_ed,
)
from relay_acef.bundle_verifier import (
    sign_acef_bundle_es256 as _sign_es,
)
from relay_extensions import (
    ACEF_CORE_SCHEMA_VERSION_PIN,
    RELAY_EXTENSIONS_SCHEMA_VERSION,
    X_RELAY_NAMESPACE_KEY,
)

pytestmark = pytest.mark.plumbing


# ---------------------------------------------------------------------------
# Fixture helpers: a signed ACEF bundle keyed by a trusted JWKS.
# ---------------------------------------------------------------------------


def _good_bindings() -> dict[str, Any]:
    return {
        "manifest_commit_hash": "a" * 64,
        "scope_kind": "run",
        "scope_id": "11111111-2222-3333-4444-555555555555",
        "actor_kind": "control_plane",
        "actor_identity_hash": "b" * 64,
        "written_by": "control_plane",
        "redaction_policy_version": "v1.0",
    }


def _base_bundle() -> dict[str, Any]:
    """A minimal valid emitted ACEF bundle (W11.2 contract) with claims."""
    return {
        "schema_version": ACEF_CORE_SCHEMA_VERSION_PIN,
        "claims": [
            {
                "evidence_claim_id": "claim-001",
                "kind": "contract_gate_result",
                "value": "pass",
            },
            {
                "evidence_claim_id": "claim-002",
                "kind": "replay_verification",
                "value": "match",
            },
        ],
        "namespaces": {
            X_RELAY_NAMESPACE_KEY: {
                "schema_version": RELAY_EXTENSIONS_SCHEMA_VERSION,
                **_good_bindings(),
            }
        },
    }


def _ed25519_signed_bundle(
    *, kid: str = "relay-ed-001"
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (signed_bundle, trusted_jwks) for an Ed25519-signed bundle."""
    priv = ed25519.Ed25519PrivateKey.generate()
    jwk = _jwk_ed(priv.public_key(), kid=kid)
    bundle = _base_bundle()
    bundle["signatures"] = [_sign_ed(bundle, priv, kid=kid)]
    jwks = {"keys": [jwk]}
    return bundle, jwks


def _es256_signed_bundle(
    *, kid: str = "relay-es-001"
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (signed_bundle, trusted_jwks) for an ES256-signed bundle."""
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = _jwk_ec(priv.public_key(), kid=kid)
    bundle = _base_bundle()
    bundle["signatures"] = [_sign_es(bundle, priv, kid=kid)]
    jwks = {"keys": [jwk]}
    return bundle, jwks


# ---------------------------------------------------------------------------
# VAL-CRYPTO-001: signature is actually verified; tamper is caught.
# ---------------------------------------------------------------------------


def test_valid_signed_bundle_verifies_crypto_001() -> None:
    bundle, jwks = _es256_signed_bundle()
    result = verify_acef_bundle(bundle, jwks, offline=True)
    assert isinstance(result, ACEFVerificationResult)
    assert result.structure_ok is True
    assert result.digest_ok is True
    assert result.signatures_ok is True
    assert result.verified_signature_count == 1
    assert all(c.ok for c in result.signature_checks)


def test_tampered_bundle_fails_closed_crypto_001() -> None:
    """Tamper a claim, keep the original signature -> verification FAILS.

    This is the exact regression for finding #3: the vendored
    integrity_checker recomputes content-hashes/merkle but never verifies
    the signature, so a re-hashed-but-resigned-with-old-sig bundle passes.
    The Relay verifier binds the signature to the canonical bundle bytes,
    so mutating any claim invalidates the recorded signature.
    """
    bundle, jwks = _ed25519_signed_bundle()
    tampered = copy.deepcopy(bundle)
    # Mutate a record AFTER signing; the original signature is retained.
    tampered["claims"][0]["value"] = "fail"
    result = verify_acef_bundle(tampered, jwks, offline=True)
    assert result.signatures_ok is False
    assert result.verified_signature_count == 0
    assert any(not c.ok for c in result.signature_checks)


def test_bundle_with_no_signatures_fails_closed_crypto_001() -> None:
    """A bundle that carries no signatures is NOT 'signed'."""
    bundle = _base_bundle()
    result = verify_acef_bundle(bundle, {"keys": []}, offline=True)
    assert result.signatures_ok is False
    assert result.verified_signature_count == 0


# ---------------------------------------------------------------------------
# VAL-CRYPTO-004: header-embedded key is never trusted.
# ---------------------------------------------------------------------------


def test_header_embedded_attacker_key_rejected_crypto_004() -> None:
    """A bundle signed by an attacker key whose jwk is embedded in the JWS
    header, with that kid NOT in the trusted JWKS, MUST be rejected.

    The vendored verify_detached_jws would load the header jwk and verify
    successfully. The Relay verifier resolves keys ONLY from the trusted
    JWKS by kid; the attacker kid is absent, so the signature cannot be
    verified.
    """
    attacker = ed25519.Ed25519PrivateKey.generate()
    attacker_kid = "attacker-key-001"
    bundle = _base_bundle()
    sig = _sign_ed(bundle, attacker, kid=attacker_kid)
    # The signing helper embeds the public jwk in the JWS header (mirroring
    # the vendored signer). Confirm the header genuinely carries a jwk so
    # the test exercises the header-trust path.
    assert "jwk" in _decode_jws_header(sig["jws"])
    bundle["signatures"] = [sig]

    # Trusted JWKS contains a DIFFERENT, legitimate key. The attacker kid
    # is absent.
    legit = ed25519.Ed25519PrivateKey.generate()
    trusted_jwks = {"keys": [_jwk_ed(legit.public_key(), kid="relay-prod-key")]}

    result = verify_acef_bundle(bundle, trusted_jwks, offline=True)
    assert result.signatures_ok is False
    assert result.verified_signature_count == 0
    # The rejection reason must attribute the missing trusted key, never a
    # crypto-pass against the header key.
    assert any("no JWK" in c.reason.lower() or "kid" in c.reason.lower()
               for c in result.signature_checks if not c.ok)


def test_attacker_kid_collision_still_uses_trusted_key_crypto_004() -> None:
    """Even if the attacker reuses a trusted kid, the signature is checked
    against the TRUSTED key bytes (header key ignored), so it fails."""
    trusted_priv = ec.generate_private_key(ec.SECP256R1())
    kid = "relay-prod-es"
    trusted_jwks = {"keys": [_jwk_ec(trusted_priv.public_key(), kid=kid)]}

    # Attacker signs with their OWN key but reuses the trusted kid and
    # embeds their own public jwk in the header.
    attacker = ec.generate_private_key(ec.SECP256R1())
    bundle = _base_bundle()
    bundle["signatures"] = [_sign_es(bundle, attacker, kid=kid)]

    result = verify_acef_bundle(bundle, trusted_jwks, offline=True)
    assert result.signatures_ok is False
    assert result.verified_signature_count == 0


# ---------------------------------------------------------------------------
# VAL-CRYPTO-005: verified-count semantics + exact alg set membership.
# ---------------------------------------------------------------------------


def test_forged_signature_does_not_increment_verified_count_crypto_005() -> None:
    """A forged/unverified signature must not count toward 'bundle signed'."""
    # One genuine ES256 signature.
    priv = ec.generate_private_key(ec.SECP256R1())
    kid = "relay-es-001"
    jwks = {"keys": [_jwk_ec(priv.public_key(), kid=kid)]}
    bundle = _base_bundle()
    good = _sign_es(bundle, priv, kid=kid)

    # A forged second signature: valid structure, wrong signature bytes.
    forged = dict(good)
    parts = forged["jws"].split(".")
    # Corrupt the signature segment so it cannot verify.
    bad_sig = "A" * len(parts[2]) if parts[2] else "AAAA"
    forged["jws"] = f"{parts[0]}.{parts[1]}.{bad_sig}"
    forged["kid"] = kid

    bundle["signatures"] = [good, forged]
    result = verify_acef_bundle(bundle, jwks, offline=True)

    # Exactly one cryptographically-verified signature.
    assert result.verified_signature_count == 1
    # signatures_ok is fail-closed: not ALL signatures verified.
    assert result.signatures_ok is False
    assert count_verified_signatures(result) == 1


def test_required_alg_exact_set_membership_crypto_005() -> None:
    """required_alg 'ES256' must NOT match '256'/'S256' (no substring)."""
    verified_algs = ["ES256"]
    # Exact membership: ES256 in {ES256} -> matches.
    assert required_alg_matches(verified_algs, "ES256") == 1
    assert required_alg_matches(verified_algs, ["ES256"]) == 1
    # Substring attack vectors must NOT match.
    assert required_alg_matches(verified_algs, "256") == 0
    assert required_alg_matches(verified_algs, "S256") == 0
    assert required_alg_matches(verified_algs, "ES") == 0
    # List form with an unrelated alg does not match.
    assert required_alg_matches(verified_algs, ["RS256", "EdDSA"]) == 0
    # List form including the exact alg matches once.
    assert required_alg_matches(verified_algs, ["RS256", "ES256"]) == 1


def test_verified_count_only_counts_ok_checks_crypto_005() -> None:
    """count_verified_signatures counts ONLY ok=True checks and the
    verified-alg list feeding required_alg_matches contains only those."""
    bundle, jwks = _es256_signed_bundle()
    result = verify_acef_bundle(bundle, jwks, offline=True)
    assert result.verified_signature_count == 1
    assert result.verified_algorithms == ["ES256"]
    # required_alg on the verified algs: exact match works, substring fails.
    assert required_alg_matches(result.verified_algorithms, "ES256") == 1
    assert required_alg_matches(result.verified_algorithms, "256") == 0


# ---------------------------------------------------------------------------
# Local JWS header decode (test-only; mirrors the verifier's b64u decode).
# ---------------------------------------------------------------------------


def _decode_jws_header(jws: str) -> dict[str, Any]:
    import base64
    import json

    header_b64 = jws.split(".")[0]
    padding = "=" * (-len(header_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64 + padding))
