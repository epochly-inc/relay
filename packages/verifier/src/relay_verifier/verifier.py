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
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .canonical import jcs_canonicalize
from .errors import (
    RELAY_VERIFY_ALG_MISMATCH,
    RELAY_VERIFY_UNSUPPORTED_ALG,
)

# Verifier schema-version literal embedded in any result envelope a
# downstream CLI/test may emit; identical to the CLI's value so
# consumers parsing either envelope see the same string.
VERIFIER_RESULT_SCHEMA: Final[str] = "relay.verifier.result.v1"

# Supported JWS algorithms (RFC 7518 + RFC 8037 alg names).
#
# W10.2 extended the allow-list from {EdDSA, ES256} (the W10.1 minimum
# trust-anchor set) to {EdDSA, ES256, RS256} to match the spec section
# L.1 ``signing_keys.algorithm`` constraint (line 4449) and the
# contract assertion VAL-W10-014. RS256 is included because the
# ACEF-vendored evidence pipeline ships RS256-signed bundles for legacy
# regulator profiles; the Relay-platform-managed signers use EdDSA / ES256
# in production. ``HS256``, ``RS1``, ``none``, and any other algorithm
# identifier are rejected before signature verification is attempted
# (RFC 8725 hardening).
ALG_EDDSA: Final[str] = "EdDSA"
ALG_ES256: Final[str] = "ES256"
ALG_RS256: Final[str] = "RS256"
SUPPORTED_ALGS: Final[frozenset[str]] = frozenset({ALG_EDDSA, ALG_ES256, ALG_RS256})

# Public-facing error code surfaced when a detached-JWS payload digest
# diverges from the bound claim (VAL-W10-012). Re-exported here so the
# verifier module is the single citation for the public code without
# every caller importing from packages.schemas.
RELAY_EVID_014: Final[str] = "RELAY-EVID-014"


# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of verifying a single signature on a bundle.

    ``code`` carries the structured wire-code identifier of a rejection
    (e.g. ``RELAY-VERIFY-011`` for unsupported alg). Empty string when
    ``ok=True`` or when the failure pre-dates W10.2 wire-code routing.
    """

    kid: str
    alg: str
    ok: bool
    reason: str = ""
    code: str = ""


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
    """Return RFC 8785 (JCS) canonical JSON bytes for ``obj``.

    Round-4 P1 structural fix: this function is now a thin delegator to
    :func:`relay_verifier.canonical.jcs_canonicalize`, eliminating the
    drift risk between the sign-side encoder used by
    :func:`_payload_for_signing` and the JCS encoder used elsewhere in
    the verifier package. The previous implementation
    (``json.dumps(..., sort_keys=True, separators=(",", ":"),
    ensure_ascii=True)``) produced spec-incorrect bytes for non-ASCII
    strings (``\\u00XX`` escapes vs. literal UTF-8), float values
    (``1.0`` vs. ECMA-262 ``1``), and NFC-decomposed strings -- any of
    which would silently diverge from the canonical RFC 8785 encoder.

    Today the bundle-signing payload is constrained to ASCII strings
    plus ints/bools/None, so the byte output is identical for existing
    fixtures and the cross-language verdict-digest table is unchanged.
    The unification ensures the next field added to the payload cannot
    introduce a sign/verify drift.

    .. deprecated::
        New code SHOULD call :func:`jcs_canonicalize` directly. This
        wrapper is preserved so existing tests and external callers
        continue to import the same symbol. It is intentionally NOT
        removed -- external test fixtures may reference it.
    """
    return jcs_canonicalize(obj)


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
      * RSA (kty=RSA, n/e=base64url(big-endian unsigned ints)) per
        RFC 7518 sec 6.3. Only used for RS256 verification (PKCS#1 v1.5
        with SHA-256). Minimum modulus size enforced at 2048 bits per
        the spec section L.1 algorithm allow-list (modulus < 2048 is
        rejected -- modern auditor profiles refuse weaker RSA).

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
    if kty == "RSA":
        n_s = jwk.get("n")
        e_s = jwk.get("e")
        if not isinstance(n_s, str) or not isinstance(e_s, str):
            raise ValueError("RSA JWK missing 'n' or 'e'")
        n = int.from_bytes(_b64u_decode(n_s), "big")
        e = int.from_bytes(_b64u_decode(e_s), "big")
        if n.bit_length() < 2048:
            raise ValueError(
                f"RSA modulus is {n.bit_length()} bits; spec L.1 allow-list "
                "rejects modulus < 2048 bits"
            )
        rsa_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return rsa_numbers.public_key()
    raise ValueError(f"unsupported JWK kty: {kty!r}")


def _kty_for_alg(alg: str) -> str | None:
    """Return the JWK ``kty`` an algorithm requires, or None if unknown.

    Used by the alg-mismatch detector: an asymmetric ``alg`` paired with
    a ``kid`` whose JWK has the wrong ``kty`` is the W10.2 alg-substitution
    attack signal. The mapping below mirrors the JWA registry sections
    cited in :func:`_load_public_key_from_jwk`.
    """
    if alg == ALG_EDDSA:
        return "OKP"
    if alg == ALG_ES256:
        return "EC"
    if alg == ALG_RS256:
        return "RSA"
    return None


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
    if alg == ALG_RS256:
        if not isinstance(public_key, rsa.RSAPublicKey):
            return False
        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
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
                    code=RELAY_VERIFY_UNSUPPORTED_ALG,
                )
            )
            continue
        # Alg-substitution detection (VAL-W10-011 + RFC 8725 sec 3.2):
        # alg is in the asymmetric allow-list; verify the JWK's kty
        # matches before attempting verification. A naive verifier that
        # passes a public-key blob to an HMAC primitive is the attack
        # surface. Relay's allow-list already excludes HS256, so this
        # check defends future allow-list changes.
        expected_kty = _kty_for_alg(alg)
        candidate_jwk = _select_jwk(jwks, kid)
        if candidate_jwk is not None and expected_kty is not None:
            actual_kty = candidate_jwk.get("kty")
            if actual_kty != expected_kty:
                sigs_ok = False
                result.signature_checks.append(
                    SignatureCheck(
                        kid=kid,
                        alg=alg,
                        ok=False,
                        reason=(
                            f"alg-mismatch: alg={alg!r} requires "
                            f"kty={expected_kty!r} but JWK has "
                            f"kty={actual_kty!r}"
                        ),
                        code=RELAY_VERIFY_ALG_MISMATCH,
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
        except (ValueError, binascii.Error) as exc:
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
        except (ValueError, binascii.Error) as exc:
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


# -----------------------------------------------------------------------------
# RFC 7515 compact-form JWS verification (W10.2)
# -----------------------------------------------------------------------------


def _decode_compact_segments(token: str) -> tuple[str, str, str]:
    """Split a compact-form JWS into ``(header_b64u, payload_b64u, sig_b64u)``.

    Raises:
        ValueError: token does not have exactly three ``.``-separated
            segments (RFC 7515 sec 7.1).
    """
    if not isinstance(token, str):
        raise ValueError("compact JWS must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"compact JWS must have 3 segments separated by '.', got {len(parts)}"
        )
    return parts[0], parts[1], parts[2]


def _decode_protected_header(header_b64u: str) -> dict[str, Any]:
    """Decode the protected-header segment to a JSON object.

    Raises:
        ValueError: segment is not valid base64url, or its decoded bytes
            do not parse as a JSON object.
    """
    try:
        raw = _b64u_decode(header_b64u)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"protected header is not valid base64url: {exc}") from exc
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"protected header is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("protected header must be a JSON object")
    return decoded


def verify_jws_compact(
    token: str,
    jwks: dict[str, Any],
    *,
    allowed_algs: frozenset[str] | None = None,
) -> SignatureCheck:
    """Verify a compact-form JWS token (RFC 7515 sec 7.1).

    Returns a :class:`SignatureCheck` with the verdict; never raises for
    verification failures (malformed input is reported in the ``reason``
    + ``code`` fields). Used by the conformance corpus runner.

    ``allowed_algs`` defaults to :data:`SUPPORTED_ALGS`; pass a narrower
    set for stricter contexts. Algorithms outside the allow-list are
    rejected with :data:`RELAY_VERIFY_UNSUPPORTED_ALG` BEFORE any
    cryptographic primitive is invoked (RFC 8725 sec 3.1).
    """
    allowed = allowed_algs if allowed_algs is not None else SUPPORTED_ALGS

    try:
        header_b64, payload_b64, sig_b64 = _decode_compact_segments(token)
    except ValueError as exc:
        return SignatureCheck(
            kid="<unknown>",
            alg="<unknown>",
            ok=False,
            reason=str(exc),
        )

    try:
        header = _decode_protected_header(header_b64)
    except ValueError as exc:
        return SignatureCheck(
            kid="<unknown>",
            alg="<unknown>",
            ok=False,
            reason=str(exc),
        )

    alg_raw = header.get("alg")
    alg = alg_raw if isinstance(alg_raw, str) else "<unknown>"
    kid_raw = header.get("kid")
    kid = kid_raw if isinstance(kid_raw, str) else "<unknown>"

    # Allow-list FIRST. Defends against alg=none and any algorithm
    # outside the closed set without invoking the verifier primitive.
    if alg not in allowed:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"unsupported alg: {alg!r}",
            code=RELAY_VERIFY_UNSUPPORTED_ALG,
        )

    # JWK lookup by kid.
    candidate_jwk = _select_jwk(jwks, kid)
    if candidate_jwk is None:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"no JWK in trust anchor matches kid {kid!r}",
        )

    # Alg-substitution detection: alg's required kty MUST match the JWK.
    expected_kty = _kty_for_alg(alg)
    actual_kty = candidate_jwk.get("kty")
    if expected_kty is not None and actual_kty != expected_kty:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=(
                f"alg-mismatch: alg={alg!r} requires kty={expected_kty!r} "
                f"but JWK has kty={actual_kty!r}"
            ),
            code=RELAY_VERIFY_ALG_MISMATCH,
        )

    try:
        public_key = _load_public_key_from_jwk(candidate_jwk)
    except ValueError as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"JWK load failed: {exc}",
        )

    try:
        signature_bytes = _b64u_decode(sig_b64)
    except (ValueError, binascii.Error) as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"signature segment is not valid base64url: {exc}",
        )

    # RFC 7515 sec 5.2: signing input is ASCII(BASE64URL(header) || '.'
    # || BASE64URL(payload)). Recompute from the wire segments.
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if not _verify_signature(
        alg=alg,
        public_key=public_key,
        signing_input=signing_input,
        signature=signature_bytes,
    ):
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason="signature did not verify under JWK",
        )

    return SignatureCheck(kid=kid, alg=alg, ok=True)


# -----------------------------------------------------------------------------
# Detached JWS / claim-binding verification (W10.2 VAL-W10-012)
# -----------------------------------------------------------------------------


def verify_jws_detached(
    *,
    protected_b64u: str,
    payload_bytes: bytes,
    signature_b64u: str,
    jwks: dict[str, Any],
    allowed_algs: frozenset[str] | None = None,
) -> SignatureCheck:
    """Verify a detached JWS (RFC 7797).

    The protected header and signature are wire-form (base64url); the
    payload is the raw byte string the signer canonicalized at sign
    time. The verifier reconstructs the JWS signing input as
    ``protected_b64u || '.' || payload_bytes`` and checks the
    signature against the JWK selected by the header's kid.

    Used as the primitive for :func:`verify_detached_claim_signature`,
    which adds the claim-digest binding required by VAL-W10-012.
    """
    allowed = allowed_algs if allowed_algs is not None else SUPPORTED_ALGS

    try:
        header = _decode_protected_header(protected_b64u)
    except ValueError as exc:
        return SignatureCheck(
            kid="<unknown>",
            alg="<unknown>",
            ok=False,
            reason=str(exc),
        )

    alg_raw = header.get("alg")
    alg = alg_raw if isinstance(alg_raw, str) else "<unknown>"
    kid_raw = header.get("kid")
    kid = kid_raw if isinstance(kid_raw, str) else "<unknown>"

    if alg not in allowed:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"unsupported alg: {alg!r}",
            code=RELAY_VERIFY_UNSUPPORTED_ALG,
        )

    candidate_jwk = _select_jwk(jwks, kid)
    if candidate_jwk is None:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"no JWK in trust anchor matches kid {kid!r}",
        )

    expected_kty = _kty_for_alg(alg)
    actual_kty = candidate_jwk.get("kty")
    if expected_kty is not None and actual_kty != expected_kty:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=(
                f"alg-mismatch: alg={alg!r} requires kty={expected_kty!r} "
                f"but JWK has kty={actual_kty!r}"
            ),
            code=RELAY_VERIFY_ALG_MISMATCH,
        )

    try:
        public_key = _load_public_key_from_jwk(candidate_jwk)
    except ValueError as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"JWK load failed: {exc}",
        )

    try:
        signature_bytes = _b64u_decode(signature_b64u)
    except (ValueError, binascii.Error) as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"signature segment is not valid base64url: {exc}",
        )

    # RFC 7797 sec 3: detached payload signing input is
    # ASCII(BASE64URL(header)) || '.' || raw_payload_bytes.
    signing_input = protected_b64u.encode("ascii") + b"." + payload_bytes

    if not _verify_signature(
        alg=alg,
        public_key=public_key,
        signing_input=signing_input,
        signature=signature_bytes,
    ):
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason="signature did not verify under JWK",
        )

    return SignatureCheck(kid=kid, alg=alg, ok=True)


def verify_detached_claim_signature(
    *,
    protected_b64u: str,
    signature_b64u: str,
    claim: dict[str, Any],
    jwks: dict[str, Any],
    allowed_algs: frozenset[str] | None = None,
) -> SignatureCheck:
    """Verify a detached JWS bound to a Relay evidence claim (VAL-W10-012).

    The verifier:

      1. Recomputes the canonical-JSON bytes of ``claim`` (single
         source of truth for the payload digest).
      2. Hashes those bytes (SHA-256) and -- if the protected header
         declares a ``payload_sha256`` field -- compares against it.
         A mismatch is the exact attack VAL-W10-012 defeats: signer
         signed payload A but the bundle now stores payload B.
      3. Calls :func:`verify_jws_detached` with the recomputed payload
         bytes as the detached payload.

    A claim mutation that bypasses re-signing produces either a digest
    mismatch (rejected with :data:`RELAY_EVID_014` + structured detail
    :data:`RELAY_VERIFY_DETACHED_PAYLOAD_MISMATCH`) or, if the bundle
    omits the digest hint, an `InvalidSignature` rejection at the
    verify step. Both paths produce ``ok=False``.
    """
    canonical_payload = canonical_json_bytes(claim)
    recomputed_digest = hashlib.sha256(canonical_payload).hexdigest()

    try:
        header = _decode_protected_header(protected_b64u)
    except ValueError as exc:
        return SignatureCheck(
            kid="<unknown>",
            alg="<unknown>",
            ok=False,
            reason=str(exc),
        )

    declared_digest = header.get("payload_sha256")
    if isinstance(declared_digest, str) and declared_digest != recomputed_digest:
        kid_raw = header.get("kid")
        alg_raw = header.get("alg")
        return SignatureCheck(
            kid=kid_raw if isinstance(kid_raw, str) else "<unknown>",
            alg=alg_raw if isinstance(alg_raw, str) else "<unknown>",
            ok=False,
            reason=(
                "detached payload digest mismatch: header declared "
                f"sha256={declared_digest!r} but recomputed "
                f"sha256={recomputed_digest!r} from claim canonical bytes"
            ),
            code=RELAY_EVID_014,
        )

    inner = verify_jws_detached(
        protected_b64u=protected_b64u,
        payload_bytes=canonical_payload,
        signature_b64u=signature_b64u,
        jwks=jwks,
        allowed_algs=allowed_algs,
    )
    if inner.ok:
        return inner
    # Re-classify a generic verify-fail as a payload-binding rejection
    # so consumers branching on RELAY-EVID-014 catch claim-tampering
    # cases that did not include a header digest hint.
    if inner.reason == "signature did not verify under JWK" and not inner.code:
        return SignatureCheck(
            kid=inner.kid,
            alg=inner.alg,
            ok=False,
            reason=(
                "detached payload digest mismatch: signature did not "
                "verify against recomputed canonical claim bytes "
                "(claim was tampered after signing)"
            ),
            code=RELAY_EVID_014,
        )
    return inner


# -----------------------------------------------------------------------------
# Multi-signature bundle verification (W10.2 VAL-W10-013)
# -----------------------------------------------------------------------------


@dataclass
class MultiSignatureResult:
    """Aggregate verdict for a multi-signature payload.

    ``aggregate`` is one of:
      * ``"all_valid"`` -- every signature verified
      * ``"mixed"``     -- at least one valid AND at least one invalid
      * ``"all_invalid"`` -- no signature verified
    ``ok`` is True iff at least one signature verified AND none failed
    (i.e. ``aggregate == "all_valid"``); the strict-pass policy mirrors
    the spec section L.5 cross-signing guarantee for migration windows.
    """

    ok: bool = False
    aggregate: str = "all_invalid"
    signatures_checked: list[SignatureCheck] = field(default_factory=list)


def verify_multi_signatures(
    *,
    payload: dict[str, Any],
    signatures: list[dict[str, Any]],
    jwks: dict[str, Any],
    allowed_algs: frozenset[str] | None = None,
) -> MultiSignatureResult:
    """Verify a payload that carries N >= 1 signatures (VAL-W10-013).

    Each ``signatures[i]`` MUST carry ``alg``, ``kid``, and
    ``signature_b64u``. The signing input is the canonical-JSON bytes
    of ``payload``. Per-signature verdicts are returned in
    ``signatures_checked`` in the same order as ``signatures``.

    The spec section L.5 cross-signing model (line 4481) calls for at
    least one valid signature for the bundle to pass; mixed valid /
    invalid is reported as ``mixed`` so consumers can decide whether
    to accept (e.g. accept-during-migration) or reject (strict mode).
    The default ``ok`` boolean follows strict mode -- ``mixed`` returns
    ``ok=False`` -- because Relay's default verification posture
    refuses any unverified signature on the bundle.
    """
    canonical_bytes = canonical_json_bytes(payload)
    result = MultiSignatureResult()
    if not isinstance(signatures, list) or not signatures:
        return result

    valid_count = 0
    invalid_count = 0
    for sig in signatures:
        if not isinstance(sig, dict):
            result.signatures_checked.append(
                SignatureCheck(
                    kid="<unknown>",
                    alg="<unknown>",
                    ok=False,
                    reason="signature entry is not an object",
                )
            )
            invalid_count += 1
            continue
        alg_raw = sig.get("alg")
        kid_raw = sig.get("kid")
        sig_b64 = sig.get("signature_b64u")
        alg = alg_raw if isinstance(alg_raw, str) else "<unknown>"
        kid = kid_raw if isinstance(kid_raw, str) else "<unknown>"
        if not isinstance(sig_b64, str) or not sig_b64:
            result.signatures_checked.append(
                SignatureCheck(
                    kid=kid,
                    alg=alg,
                    ok=False,
                    reason="signature missing 'signature_b64u'",
                )
            )
            invalid_count += 1
            continue
        check = _verify_one_signature_over_bytes(
            alg=alg,
            kid=kid,
            signing_input=canonical_bytes,
            signature_b64u=sig_b64,
            jwks=jwks,
            allowed_algs=(
                allowed_algs if allowed_algs is not None else SUPPORTED_ALGS
            ),
        )
        result.signatures_checked.append(check)
        if check.ok:
            valid_count += 1
        else:
            invalid_count += 1

    if valid_count > 0 and invalid_count == 0:
        result.aggregate = "all_valid"
        result.ok = True
    elif valid_count > 0 and invalid_count > 0:
        result.aggregate = "mixed"
        result.ok = False
    else:
        result.aggregate = "all_invalid"
        result.ok = False
    return result


def _verify_one_signature_over_bytes(
    *,
    alg: str,
    kid: str,
    signing_input: bytes,
    signature_b64u: str,
    jwks: dict[str, Any],
    allowed_algs: frozenset[str],
) -> SignatureCheck:
    """Internal helper: verify a single signature over an arbitrary
    byte string. Encapsulates the allow-list -> kty-mismatch -> verify
    chain shared by :func:`verify_multi_signatures` and the bundle
    verifier."""
    if alg not in allowed_algs:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"unsupported alg: {alg!r}",
            code=RELAY_VERIFY_UNSUPPORTED_ALG,
        )
    candidate_jwk = _select_jwk(jwks, kid)
    if candidate_jwk is None:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"no JWK in trust anchor matches kid {kid!r}",
        )
    expected_kty = _kty_for_alg(alg)
    actual_kty = candidate_jwk.get("kty")
    if expected_kty is not None and actual_kty != expected_kty:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=(
                f"alg-mismatch: alg={alg!r} requires kty={expected_kty!r} "
                f"but JWK has kty={actual_kty!r}"
            ),
            code=RELAY_VERIFY_ALG_MISMATCH,
        )
    try:
        public_key = _load_public_key_from_jwk(candidate_jwk)
    except ValueError as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"JWK load failed: {exc}",
        )
    try:
        signature_bytes = _b64u_decode(signature_b64u)
    except (ValueError, binascii.Error) as exc:
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason=f"signature_b64u is not valid base64url: {exc}",
        )
    if not _verify_signature(
        alg=alg,
        public_key=public_key,
        signing_input=signing_input,
        signature=signature_bytes,
    ):
        return SignatureCheck(
            kid=kid,
            alg=alg,
            ok=False,
            reason="signature did not verify under JWK",
        )
    return SignatureCheck(kid=kid, alg=alg, ok=True)


# -----------------------------------------------------------------------------
# Sign-side helpers for RS256 (test fixtures only)
# -----------------------------------------------------------------------------


def jwk_from_rsa_public_key(
    public_key: rsa.RSAPublicKey,
    *,
    kid: str,
    not_before: str | None = None,
    not_after: str | None = None,
) -> dict[str, Any]:
    """Project an RSA public key into a JWK dict (RFC 7518 sec 6.3)."""
    nums = public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    jwk: dict[str, Any] = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64u_encode(n_bytes),
        "e": _b64u_encode(e_bytes),
    }
    if not_before is not None:
        jwk["not_before"] = not_before
    if not_after is not None:
        jwk["not_after"] = not_after
    return jwk


def sign_payload_rs256(
    payload: dict[str, Any],
    private_key: rsa.RSAPrivateKey,
    *,
    kid: str,
) -> dict[str, Any]:
    """Test-only: produce a signature dict for ``payload`` under RS256."""
    canonical = canonical_json_bytes(payload)
    sig = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    return {
        "alg": ALG_RS256,
        "kid": kid,
        "signing_input_b64u": _b64u_encode(canonical),
        "signature_b64u": _b64u_encode(sig),
    }


__all__ = [
    "ALG_EDDSA",
    "ALG_ES256",
    "ALG_RS256",
    "RELAY_EVID_014",
    "SUPPORTED_ALGS",
    "VERIFIER_RESULT_SCHEMA",
    "MultiSignatureResult",
    "SignatureCheck",
    "VerificationResult",
    "build_signing_input_b64u",
    "canonical_json_bytes",
    "jwk_from_ec_p256_public_key",
    "jwk_from_ed25519_public_key",
    "jwk_from_rsa_public_key",
    "parse_bundle_bytes",
    "sign_payload_ed25519",
    "sign_payload_es256",
    "sign_payload_rs256",
    "verify_bundle",
    "verify_detached_claim_signature",
    "verify_jws_compact",
    "verify_jws_detached",
    "verify_multi_signatures",
]
