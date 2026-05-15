"""ACEF signing module — JWS detached signatures (RS256, ES256).

Implements bundle and record signing per spec Section 3.1.3:
- RS256 and ES256 only — all other algorithms rejected (ACEF-013)
- Detached JWS over content-hashes.json
- JWS header MUST include x5c or jwk per spec
- x5c certificate chain support
- JWK public key embedding
- Assessment Bundle signing
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509 import load_pem_x509_certificate

from acef.errors import ACEFSigningError

# Whitelist of allowed JWS algorithms per spec
_ALLOWED_ALGORITHMS = frozenset({"RS256", "ES256"})


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    # Only add padding if needed (when length is not already a multiple of 4)
    remainder = len(s) % 4
    if remainder:
        s = s + "=" * (4 - remainder)
    return base64.urlsafe_b64decode(s)


def _detect_algorithm(private_key: PrivateKeyTypes) -> str:
    """Detect JWS algorithm from private key type.

    For EC keys, validates that the curve is P-256 (NIST secp256r1)
    since ACEF only allows ES256 per spec Section 3.1.3.
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RS256"
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = private_key.curve
        if not isinstance(curve, ec.SECP256R1):
            raise ACEFSigningError(
                f"Unsupported EC curve: {curve.name!r}. "
                f"ACEF requires P-256 (secp256r1) for ES256.",
                code="ACEF-013",
            )
        return "ES256"
    else:
        raise ACEFSigningError(
            f"Unsupported key type: {type(private_key).__name__}",
            code="ACEF-013",
        )


def _load_private_key(key_path: str) -> PrivateKeyTypes:
    """Load a PEM-encoded private key."""
    key_data = Path(key_path).read_bytes()
    try:
        return serialization.load_pem_private_key(key_data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise ACEFSigningError(f"Failed to load private key: {e}", code="ACEF-012") from e


def _load_public_key_from_pem(key_data: bytes) -> PublicKeyTypes:
    """Load a PEM-encoded public key or certificate."""
    try:
        return serialization.load_pem_public_key(key_data)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Try loading as certificate
        try:
            cert = load_pem_x509_certificate(key_data)
            return cert.public_key()
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            raise ACEFSigningError(f"Failed to load public key: {e}", code="ACEF-012") from e


def _derive_jwk(private_key: PrivateKeyTypes) -> dict[str, str]:
    """Derive a JWK representation of the public key from a private key.

    Per spec Section 3.1.3: JWS header MUST include x5c or jwk.
    When x5c is not provided, the public key is auto-embedded as a JWK.

    Args:
        private_key: The private signing key.

    Returns:
        A JWK dict suitable for embedding in the JWS header.
    """
    public_key = private_key.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        public_numbers = public_key.public_numbers()
        # Encode n and e as base64url unsigned big-endian integers
        n_bytes = public_numbers.n.to_bytes(
            (public_numbers.n.bit_length() + 7) // 8, byteorder="big"
        )
        e_bytes = public_numbers.e.to_bytes(
            (public_numbers.e.bit_length() + 7) // 8, byteorder="big"
        )
        return {
            "kty": "RSA",
            "n": _base64url_encode(n_bytes),
            "e": _base64url_encode(e_bytes),
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_numbers = public_key.public_numbers()
        # For P-256, coordinates are 32 bytes each
        x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
        y_bytes = public_numbers.y.to_bytes(32, byteorder="big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }
    else:
        raise ACEFSigningError(
            f"Cannot derive JWK from key type: {type(public_key).__name__}",
            code="ACEF-013",
        )


def _load_public_key_from_jwk(jwk: dict[str, Any]) -> PublicKeyTypes:
    """Load a public key from a JWK dictionary.

    Supports RSA and EC (P-256) key types per spec Section 3.1.3.

    Args:
        jwk: JWK dictionary with key type and parameters.

    Returns:
        The deserialized public key.

    Raises:
        ACEFSigningError: If the JWK is malformed or uses unsupported parameters.
    """
    kty = jwk.get("kty", "")

    if kty == "RSA":
        n_b64 = jwk.get("n", "")
        e_b64 = jwk.get("e", "")
        if not n_b64 or not e_b64:
            raise ACEFSigningError(
                "RSA JWK missing required 'n' or 'e' parameters",
                code="ACEF-012",
            )
        n_bytes = _base64url_decode(n_b64)
        e_bytes = _base64url_decode(e_b64)
        n = int.from_bytes(n_bytes, byteorder="big")
        e = int.from_bytes(e_bytes, byteorder="big")
        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return public_numbers.public_key()

    elif kty == "EC":
        crv = jwk.get("crv", "")
        if crv != "P-256":
            raise ACEFSigningError(
                f"Unsupported EC curve in JWK: {crv!r}. ACEF requires P-256.",
                code="ACEF-013",
            )
        x_b64 = jwk.get("x", "")
        y_b64 = jwk.get("y", "")
        if not x_b64 or not y_b64:
            raise ACEFSigningError(
                "EC JWK missing required 'x' or 'y' parameters",
                code="ACEF-012",
            )
        x_bytes = _base64url_decode(x_b64)
        y_bytes = _base64url_decode(y_b64)
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")
        public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        return public_numbers.public_key()

    else:
        raise ACEFSigningError(
            f"Unsupported JWK key type: {kty!r}. ACEF requires RSA or EC.",
            code="ACEF-012",
        )


def create_detached_jws(
    payload: bytes,
    private_key: PrivateKeyTypes,
    *,
    kid: str = "",
    x5c: list[str] | None = None,
) -> str:
    """Create a detached JWS signature.

    Per spec Section 3.1.3: JWS with empty payload (detached), RS256 or ES256 only.
    The header MUST include x5c or jwk. If x5c is not provided, the public key
    is auto-derived from the private key and embedded as a jwk.

    Args:
        payload: The data to sign (raw bytes).
        private_key: The signing key.
        kid: Key identifier.
        x5c: Certificate chain (base64-encoded DER certificates).

    Returns:
        JWS compact serialization with empty payload (header..signature).
    """
    alg = _detect_algorithm(private_key)

    # Build JWS header
    header: dict[str, Any] = {"alg": alg}
    if kid:
        header["kid"] = kid
    if x5c:
        header["x5c"] = x5c
    else:
        # M2 (Scout R2): Auto-embed public key as JWK when no x5c provided.
        # Spec Section 3.1.3: header MUST include x5c or jwk.
        header["jwk"] = _derive_jwk(private_key)

    # Encode header
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(payload)

    # Sign
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg == "RS256":
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ACEFSigningError("Key type mismatch for RS256", code="ACEF-013")
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    elif alg == "ES256":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ACEFSigningError("Key type mismatch for ES256", code="ACEF-013")
        der_sig = private_key.sign(
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        # Convert DER to raw r||s format for JWS (32 bytes each for P-256)
        r, s = utils.decode_dss_signature(der_sig)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise ACEFSigningError(f"Unsupported algorithm: {alg}", code="ACEF-013")

    sig_b64 = _base64url_encode(signature)

    # Detached JWS: header..signature (empty payload)
    return f"{header_b64}..{sig_b64}"


def verify_detached_jws(
    jws_str: str,
    payload: bytes,
    public_key: PublicKeyTypes | None = None,
    *,
    key_data: bytes | None = None,
) -> dict[str, Any]:
    """Verify a detached JWS signature.

    Args:
        jws_str: The JWS compact serialization (header..signature).
        payload: The original signed data.
        public_key: The verification key (optional if key_data provided).
        key_data: PEM-encoded public key or certificate (alternative to public_key).

    Returns:
        The decoded JWS header.

    Raises:
        ACEFSigningError: If verification fails.
    """
    parts = jws_str.split(".")
    if len(parts) != 3:
        raise ACEFSigningError("Invalid JWS format: expected 3 parts", code="ACEF-012")

    header_b64 = parts[0]
    sig_b64 = parts[2]

    # Decode header
    try:
        header = json.loads(_base64url_decode(header_b64))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
        raise ACEFSigningError(f"Invalid JWS header: {e}", code="ACEF-012") from e

    alg = header.get("alg", "")
    if alg not in _ALLOWED_ALGORITHMS:
        raise ACEFSigningError(
            f"Unsupported JWS algorithm: {alg!r} (allowed: {sorted(_ALLOWED_ALGORITHMS)})",
            code="ACEF-013",
        )

    # Get public key
    if public_key is None:
        if key_data is not None:
            public_key = _load_public_key_from_pem(key_data)
        elif "x5c" in header and header["x5c"]:
            x5c_entry = header["x5c"][0]
            if len(x5c_entry) > 65536:
                raise ACEFSigningError(
                    f"x5c certificate too large: {len(x5c_entry)} bytes (max 65536)",
                    code="ACEF-012",
                )
            cert_der = base64.b64decode(x5c_entry)
            from cryptography.x509 import load_der_x509_certificate

            cert = load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
        elif "jwk" in header:
            # M-R2-5 / m7 (Scout): JWK-based key resolution
            public_key = _load_public_key_from_jwk(header["jwk"])
        else:
            raise ACEFSigningError(
                "No public key available: neither x5c nor jwk in header",
                code="ACEF-012",
            )

    # Validate EC public key curve for ES256
    if alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ACEFSigningError(
                f"EC public key curve mismatch: {public_key.curve.name!r}, expected P-256",
                code="ACEF-013",
            )

    # Reconstruct signing input
    payload_b64 = _base64url_encode(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _base64url_decode(sig_b64)

    try:
        if alg == "RS256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ACEFSigningError("Public key is not RSA for RS256 verification", code="ACEF-012")
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif alg == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ACEFSigningError("Public key is not EC for ES256 verification", code="ACEF-012")
            # Convert raw r||s back to DER (32 bytes each for P-256)
            if len(signature) != 64:
                raise ACEFSigningError(
                    f"Invalid ES256 signature length: {len(signature)} (expected 64)",
                    code="ACEF-012",
                )
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(
                der_sig,
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
    except ACEFSigningError:
        raise
    except Exception as e:
        raise ACEFSigningError(f"Signature verification failed: {e}", code="ACEF-012") from e

    return header


def sign_bundle(bundle_dir: Path, key_path: str, *, kid: str = "provider-key") -> str:
    """Sign an exported bundle's content-hashes.json.

    Per spec Section 3.1.3: the JWS signature is over the raw bytes of
    content-hashes.json after RFC 8785 canonicalization. This function
    re-canonicalizes the file to ensure correctness even if the file was
    modified or reformatted after initial export.

    Creates a JWS file in signatures/ using the kid for the filename.

    Args:
        bundle_dir: Path to the bundle directory.
        key_path: Path to the PEM private key file.
        kid: Key identifier.

    Returns:
        Path to the created signature file.
    """
    from acef.integrity import canonicalize_json_str

    content_hashes_path = bundle_dir / "hashes" / "content-hashes.json"
    if not content_hashes_path.exists():
        raise ACEFSigningError("content-hashes.json not found — export first", code="ACEF-014")

    # Re-canonicalize to ensure the payload matches RFC 8785 regardless of
    # whether the file was modified after export (e.g., pretty-printed by
    # an external JSON tool). The spec requires signing over the canonicalized
    # bytes of content-hashes.json.
    raw_content = content_hashes_path.read_text(encoding="utf-8")
    payload = canonicalize_json_str(raw_content)

    private_key = _load_private_key(key_path)
    jws = create_detached_jws(payload, private_key, kid=kid)

    sig_dir = bundle_dir / "signatures"
    sig_dir.mkdir(exist_ok=True)
    # Sanitize kid for filesystem use: keep only safe characters
    safe_kid = re.sub(r"[^A-Za-z0-9_\-.]", "-", kid)
    sig_filename = f"{safe_kid}.jws"
    sig_path = sig_dir / sig_filename
    sig_path.write_text(jws, encoding="utf-8")

    return str(sig_path)


def sign_assessment(
    assessment_data: dict[str, Any],
    key_path: str,
) -> dict[str, Any]:
    """Sign an Assessment Bundle.

    Per spec: set integrity to null, canonicalize, sign, then populate integrity.

    Creates a shallow copy of the input dict to avoid mutating the caller's
    data (m5 Scout R2).

    Args:
        assessment_data: The Assessment Bundle dict.
        key_path: Path to the PEM private key file.

    Returns:
        A new Assessment Bundle dict with populated integrity block.
    """
    from acef.integrity import canonicalize

    # m5 (Scout R2): Shallow copy to avoid mutating caller's dict
    assessment_data = dict(assessment_data)

    # Set integrity to null for signing
    assessment_data["integrity"] = None
    canonical = canonicalize(assessment_data)

    private_key = _load_private_key(key_path)
    jws = create_detached_jws(canonical, private_key, kid="assessor-key")

    assessment_data["integrity"] = {
        "signature": {
            "method": "jws",
            "signer": "",
            "value": jws,
        }
    }

    return assessment_data
