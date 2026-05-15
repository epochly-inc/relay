"""JWS verification for Relay evidence bundles (W10.1 Python verifier).

Mirrors the surface of ``packages/cli/src/relay_cli/evidence_verifier.py``
(W5.4) so the OSS verifier package can verify evidence bundles without
importing the CLI. The two implementations agree byte-for-byte on the
canonical-JSON form and on every verdict; the W10.2/W10.3 conformance
corpus (added in later sub-features) will enforce parity via golden
vectors. Until that corpus lands, parity is preserved by mirroring the
algorithm here and exporting the same public names.

Supported JWS algorithms (per spec section AO.4 trust-anchor contract):

  * ``EdDSA`` -- Ed25519 (RFC 8037)
  * ``ES256`` -- ECDSA over P-256 with SHA-256 (RFC 7518)

Bundle file format (in-scope for v0.1 OSS profile): see
``packages/cli/src/relay_cli/evidence_verifier.py`` module docstring.

Per CLAUDE.md keystone invariant #11 the OSS verifier defaults to the
spec-pinned trust anchor declared in :mod:`relay_verifier.constants`
(``DEFAULT_JWKS_URL``); this module is URL-agnostic and operates on a
parsed JWKS dict supplied by the caller (typically the trust-anchor
loader in :mod:`relay_verifier.jwks_loader`).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# Verifier schema-version literal embedded in any result envelope a
# downstream CLI/test may emit; identical to the CLI's value so
# consumers parsing either envelope see the same string.
VERIFIER_RESULT_SCHEMA: Final[str] = "relay.verifier.result.v1"

# Supported JWS algorithms (RFC 7518 + RFC 8037 alg names).
ALG_EDDSA: Final[str] = "EdDSA"
ALG_ES256: Final[str] = "ES256"
SUPPORTED_ALGS: Final[frozenset[str]] = frozenset({ALG_EDDSA, ALG_ES256})


# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of verifying a single signature on a bundle."""

    kid: str
    alg: str
    ok: bool
    reason: str = ""


@dataclass
class VerificationResult:
    """Aggregate result of verifying a bundle.

    Attributes mirror :class:`relay_cli.evidence_verifier.VerificationResult`
    field-for-field; downstream code that imports either type by name
    sees the same shape.
    """

    digest_ok: bool = False
    signatures_ok: bool = False
    structure_ok: bool = False
    signature_checks: list[SignatureCheck] = field(default_factory=list)
    claims_count: int = 0
    bundle_digest_sha256: str = ""
    errors: list[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Base64URL helpers (RFC 4648 sec 5)
# -----------------------------------------------------------------------------


def _b64u_decode(s: str) -> bytes:
    """Decode an unpadded base64url string to bytes."""
    if not isinstance(s, str):
        raise ValueError("base64url input must be a string")
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _b64u_encode(b: bytes) -> str:
    """Encode bytes to unpadded base64url."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# -----------------------------------------------------------------------------
# Canonical JSON (RFC-8785-style; sorted keys, compact separators)
# -----------------------------------------------------------------------------


def canonical_json_bytes(obj: Any) -> bytes:
    """Return RFC-8785-style canonical JSON bytes for ``obj``.

    ``json.dumps(..., sort_keys=True, separators=(",", ":"),
    ensure_ascii=True)`` is sufficient for the OSS bundle format because
    every payload field is a JSON-typed value (string, int, bool, list,
    dict) and the producer controls the input shape at sign time. Full
    RFC 8785 number canonicalization (Number.toString-style float
    formatting) lands with the W10.3 JCS conformance corpus; the OSS
    bundle does not embed floats today.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# -----------------------------------------------------------------------------
# JWK -> public-key loader (RFC 7517 / 7518 / 8037)
# -----------------------------------------------------------------------------


def _load_public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Build a cryptography public-key object from a JWK dict.

    Supports:
      * Ed25519 (kty=OKP, crv=Ed25519, x=base64url(public bytes)) per
        RFC 8037 sec 2.
      * P-256 (kty=EC, crv=P-256, x/y=base64url(coordinates)) per
        RFC 7518 sec 6.2.

    Raises:
        ValueError: on unsupported kty/crv or missing required fields.
    """
    if not isinstance(jwk, dict):
        raise ValueError("JWK must be an object")
    kty = jwk.get("kty")
    if kty == "OKP":
        crv = jwk.get("crv")
        if crv != "Ed25519":
            raise ValueError(f"unsupported OKP crv: {crv!r}")
        x = jwk.get("x")
        if not isinstance(x, str):
            raise ValueError("OKP JWK missing 'x' (public key)")
        pub = _b64u_decode(x)
        if len(pub) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes; got {len(pub)}"
            )
        return ed25519.Ed25519PublicKey.from_public_bytes(pub)
    if kty == "EC":
        crv = jwk.get("crv")
        if crv != "P-256":
            raise ValueError(f"unsupported EC crv: {crv!r}")
        x_s = jwk.get("x")
        y_s = jwk.get("y")
        if not isinstance(x_s, str) or not isinstance(y_s, str):
            raise ValueError("EC JWK missing 'x' or 'y'")
        x = int.from_bytes(_b64u_decode(x_s), "big")
        y = int.from_bytes(_b64u_decode(y_s), "big")
        numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return numbers.public_key()
    raise ValueError(f"unsupported JWK kty: {kty!r}")


def _select_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the first JWK in ``jwks`` whose ``kid`` matches, or None."""
    keys = jwks.get("keys", [])
    if not isinstance(keys, list):
        return None
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("kid") == kid:
            return jwk
    return None


# -----------------------------------------------------------------------------
# Signature verification
# -----------------------------------------------------------------------------


def _verify_signature(
    *,
    alg: str,
    public_key: Any,
    signing_input: bytes,
    signature: bytes,
) -> bool:
    """Return True iff the signature verifies under ``alg``.

    For ``ES256`` the JWS wire form is r || s (each 32 bytes for P-256)
    per RFC 7518 sec 3.4. cryptography's ECDSA verify expects DER, so we
    re-encode r || s into a DSS signature here.
    """
    if alg == ALG_EDDSA:
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False
        try:
            public_key.verify(signature, signing_input)
            return True
        except InvalidSignature:
            return False
    if alg == ALG_ES256:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        if len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        try:
            der = encode_dss_signature(r, s)
            public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    return False


# -----------------------------------------------------------------------------
# Bundle helpers
# -----------------------------------------------------------------------------


def _payload_for_signing(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical signing payload for a bundle.

    The signing payload is every field of the bundle EXCEPT
    ``signatures``. The signer also includes a self-referential
    ``trust_anchor`` so a consumer can detect a swap of the anchor URL
    (signing key remains the same but the operator-declared anchor
    changed).
    """
    return {k: v for k, v in bundle.items() if k != "signatures"}


def parse_bundle_bytes(raw: bytes) -> dict[str, Any]:
    """Parse a bundle file's bytes into a dict; raises ValueError on malformed."""
    if not raw:
        raise ValueError("bundle file is empty")
    try:
        loaded = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"bundle is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError("bundle root must be a JSON object")
    return loaded


def verify_bundle(
    bundle: dict[str, Any],
    jwks: dict[str, Any],
) -> VerificationResult:
    """Verify a parsed bundle against a parsed JWKS.

    Returns a fully populated :class:`VerificationResult`. The function
    does NOT raise for verification failures -- the result fields encode
    the failure mode so callers can emit a structured envelope.
    """
    result = VerificationResult()

    sigs = bundle.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        result.errors.append("bundle has no 'signatures' array or it is empty")
        return result

    payload = _payload_for_signing(bundle)
    canonical_bytes = canonical_json_bytes(payload)
    payload_digest = hashlib.sha256(canonical_bytes).hexdigest()
    result.bundle_digest_sha256 = payload_digest
    result.structure_ok = True

    claims = bundle.get("claims")
    result.claims_count = len(claims) if isinstance(claims, list) else 0

    digest_ok = True
    sigs_ok = True
    any_signature_present = False

    for idx, sig in enumerate(sigs):
        if not isinstance(sig, dict):
            digest_ok = False
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=f"<sig[{idx}]>",
                    alg="<unknown>",
                    ok=False,
                    reason="signature entry is not an object",
                )
            )
            continue
        kid = sig.get("kid")
        alg = sig.get("alg")
        signing_input_b64u = sig.get("signing_input_b64u")
        signature_b64u = sig.get("signature_b64u")
        if not isinstance(kid, str) or not kid:
            sigs_ok = False
            digest_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=f"<sig[{idx}]>",
                    alg=str(alg) if alg else "<unknown>",
                    ok=False,
                    reason="signature missing 'kid'",
                )
            )
            continue
        if alg not in SUPPORTED_ALGS:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=str(alg) if alg else "<unknown>",
                    ok=False,
                    reason=f"unsupported alg: {alg!r}",
                )
            )
            continue
        if not isinstance(signing_input_b64u, str) or not signing_input_b64u:
            sigs_ok = False
            digest_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason="signature missing 'signing_input_b64u'",
                )
            )
            continue
        if not isinstance(signature_b64u, str) or not signature_b64u:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason="signature missing 'signature_b64u'",
                )
            )
            continue

        any_signature_present = True

        try:
            recorded_signing_input = _b64u_decode(signing_input_b64u)
        except (ValueError, base64.binascii.Error) as exc:
            sigs_ok = False
            digest_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason=f"signing_input_b64u is not valid base64url: {exc}",
                )
            )
            continue
        if recorded_signing_input != canonical_bytes:
            sigs_ok = False
            digest_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason=(
                        "signing_input drift: recorded canonical bytes "
                        "do not match recomputed payload (bundle tampered)"
                    ),
                )
            )
            continue

        jwk = _select_jwk(jwks, kid)
        if jwk is None:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason=f"no JWK in trust anchor matches kid {kid!r}",
                )
            )
            continue
        try:
            public_key = _load_public_key_from_jwk(jwk)
        except ValueError as exc:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason=f"JWK load failed: {exc}",
                )
            )
            continue
        try:
            signature_bytes = _b64u_decode(signature_b64u)
        except (ValueError, base64.binascii.Error) as exc:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason=f"signature_b64u is not valid base64url: {exc}",
                )
            )
            continue

        verified = _verify_signature(
            alg=alg,
            public_key=public_key,
            signing_input=recorded_signing_input,
            signature=signature_bytes,
        )
        if not verified:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason="signature did not verify under JWK",
                )
            )
            continue
        result.signature_checks.append(
            SignatureCheck(kid=kid, alg=alg, ok=True, reason="")
        )

    result.digest_ok = digest_ok
    result.signatures_ok = sigs_ok and any_signature_present
    return result


# -----------------------------------------------------------------------------
# Sign-side helpers (test fixtures only; never invoked from production paths)
# -----------------------------------------------------------------------------


def build_signing_input_b64u(payload: dict[str, Any]) -> str:
    """Return the base64url-encoded canonical-JSON of ``payload``.

    Used by tests to construct synthetic well-formed bundles. Production
    bundles are signed by the relay-platform signer service which lives
    outside this OSS package; the OSS verifier never produces signatures.
    """
    return _b64u_encode(canonical_json_bytes(payload))


def jwk_from_ed25519_public_key(
    public_key: ed25519.Ed25519PublicKey,
    *,
    kid: str,
    not_before: str | None = None,
    not_after: str | None = None,
) -> dict[str, Any]:
    """Project an Ed25519 public key into a JWK dict (RFC 8037).

    ``not_before``/``not_after`` are optional ISO-8601 timestamps; the
    bundled JWKS test corpus (VAL-W10-003) requires both annotations on
    every shipped key, so the helper supports populating them.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk: dict[str, Any] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "x": _b64u_encode(raw),
    }
    if not_before is not None:
        jwk["not_before"] = not_before
    if not_after is not None:
        jwk["not_after"] = not_after
    return jwk


def jwk_from_ec_p256_public_key(
    public_key: ec.EllipticCurvePublicKey,
    *,
    kid: str,
    not_before: str | None = None,
    not_after: str | None = None,
) -> dict[str, Any]:
    """Project a P-256 public key into a JWK dict (RFC 7518 sec 6.2)."""
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    jwk: dict[str, Any] = {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
        "x": _b64u_encode(x_bytes),
        "y": _b64u_encode(y_bytes),
    }
    if not_before is not None:
        jwk["not_before"] = not_before
    if not_after is not None:
        jwk["not_after"] = not_after
    return jwk


def sign_payload_ed25519(
    payload: dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
    *,
    kid: str,
) -> dict[str, Any]:
    """Test-only: produce a signature dict for ``payload`` under Ed25519."""
    canonical = canonical_json_bytes(payload)
    sig = private_key.sign(canonical)
    return {
        "alg": ALG_EDDSA,
        "kid": kid,
        "signing_input_b64u": _b64u_encode(canonical),
        "signature_b64u": _b64u_encode(sig),
    }


def sign_payload_es256(
    payload: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    *,
    kid: str,
) -> dict[str, Any]:
    """Test-only: produce a signature dict for ``payload`` under ES256."""
    canonical = canonical_json_bytes(payload)
    der = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "alg": ALG_ES256,
        "kid": kid,
        "signing_input_b64u": _b64u_encode(canonical),
        "signature_b64u": _b64u_encode(raw),
    }


__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "SUPPORTED_ALGS",
    "VERIFIER_RESULT_SCHEMA",
    "SignatureCheck",
    "VerificationResult",
    "build_signing_input_b64u",
    "canonical_json_bytes",
    "jwk_from_ec_p256_public_key",
    "jwk_from_ed25519_public_key",
    "parse_bundle_bytes",
    "sign_payload_ed25519",
    "sign_payload_es256",
    "verify_bundle",
]
