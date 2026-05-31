"""Relay-owned, fail-closed ACEF bundle JWS verifier (W11.4).

This module is the Relay-OWNED verification surface for signed ACEF
bundles. It closes three adversarially-verified findings against the
vendored ACEF reference SDK WITHOUT modifying the byte-immutable
``upstream/`` tree and WITHOUT importing the (dormant, unshipped)
vendored ``acef`` package:

  * VAL-CRYPTO-001 (finding #3): the vendored
    ``validation/integrity_checker._check_signatures`` is a no-op -- it
    base64-decodes the JWS header and checks ``alg`` membership but never
    reconstructs the signing input nor verifies the signature. A bundle
    whose records were edited after signing (with content-hashes/merkle
    recomputed and the original signature retained) passes. This module
    reconstructs the JCS-canonical signed payload, verifies EVERY
    signature cryptographically, and fails CLOSED on any mismatch:
    ``signatures_ok`` is True only when there is at least one signature
    AND every signature verified.

  * VAL-CRYPTO-004 (finding #13): the vendored
    ``signing.verify_detached_jws`` resolves the verification key from the
    JWS header (``x5c``/``jwk``) when no explicit key is supplied, so an
    attacker who signs with their own key and embeds its public half in
    the header verifies. This module NEVER reads a key from the JWS
    header. For each signature it takes the signature's ``kid``, looks it
    up in the TRUSTED JWKS, loads that public key, and verifies the
    signature against the EXPLICIT trusted key. A ``kid`` absent from the
    trusted JWKS is a hard rejection.

  * VAL-CRYPTO-005 (finding #15): the vendored ``op_bundle_signed`` counts
    ``.jws`` files by header format (no crypto) and, when ``required_alg``
    is a string, does ``a in required_alg`` -- a Python substring test, so
    ``"S256"``/``"256"`` spuriously "match" ``"ES256"``. This module
    exposes :attr:`ACEFVerificationResult.verified_signature_count` (the
    count of cryptographically-verified signatures, ok=True only) and
    :func:`required_alg_matches`, which normalises ``required_alg`` to a
    set and matches by EXACT membership.

Trust-anchor resolution mirrors the OSS verifier's
``relay_verifier.jwks_loader.resolve_jwks`` precedence (offline ->
bundled; BYO flag/config; live -> cache -> bundled), and the JWK ->
public-key crypto helpers mirror
``relay_cli.evidence_verifier`` (EdDSA / ES256) extended with RS256 so
ACEF-signed bundles (RS256/ES256 per the ACEF spec) verify. The helpers
are re-implemented here (not imported from the vendored ``acef`` package)
so there is no production import of the dormant vendored tree.

Signed-bundle wire shape
------------------------
A signed ACEF bundle carries a ``signatures`` array. Each entry is a
detached JWS over the JCS-canonical bytes of the bundle MINUS its
``signatures`` field::

    {
      "schema_version": "v0.3",
      "claims": [...],
      "namespaces": {"x-relay": {...}},
      "signatures": [
        {"kid": "<kid>", "alg": "EdDSA"|"ES256"|"RS256",
         "jws": "<header_b64>..<sig_b64>"}
      ]
    }

The signed payload is ``jcs_canonicalize(bundle_without_signatures)``
(reusing the W11.3 JCS encoder). The JWS is the ACEF detached-JWS compact
form (``header..signature``); the signing input is
``b64u(header) + "." + b64u(payload)`` per RFC 7515 with a detached
payload. The bundle digest is bound: any tamper to a record changes the
canonical payload and invalidates every recorded signature.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .roundtrip import jcs_canonicalize

# Result/envelope schema-version literal.
ACEF_VERIFIER_RESULT_SCHEMA: Final[str] = "relay.acef.bundle_verifier_result.v1"

# Supported JWS algorithms. ACEF signs with RS256 / ES256 (spec section
# 3.1.3); the Relay evidence verifier uses EdDSA / ES256. The Relay ACEF
# verifier accepts the union so an ACEF-signed bundle and a Relay-signed
# bundle both verify. Algorithms outside this set are rejected fail-closed.
ALG_EDDSA: Final[str] = "EdDSA"
ALG_ES256: Final[str] = "ES256"
ALG_RS256: Final[str] = "RS256"
SUPPORTED_ALGS: Final[frozenset[str]] = frozenset({ALG_EDDSA, ALG_ES256, ALG_RS256})

# Key under which the detached JWS compact string lives in a signature
# entry. The signature entry also declares ``kid`` and ``alg`` so the
# verifier can resolve the trusted key WITHOUT decoding the header (the
# header ``alg`` is still cross-checked against the declared ``alg``).
_SIG_JWS_KEY: Final[str] = "jws"
_SIG_KID_KEY: Final[str] = "kid"
_SIG_ALG_KEY: Final[str] = "alg"


# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureCheck:
    """Outcome of verifying a single signature on an ACEF bundle.

    ``ok`` is True ONLY when the signature verified cryptographically
    against the TRUSTED key resolved by ``kid`` from the supplied JWKS.
    """

    kid: str
    alg: str
    ok: bool
    reason: str = ""


@dataclass
class ACEFVerificationResult:
    """Aggregate result of verifying a signed ACEF bundle.

    Attributes:
        digest_ok: content-integrity flag. True iff the bundle's canonical
            payload is intact relative to what was signed -- i.e. no
            structurally-valid signature against a resolved TRUSTED key
            failed to verify over the recomputed canonical bytes. Because
            the ACEF detached-JWS form records no separate signing input, a
            record tamper that retains the original signature is detectable
            ONLY by the cryptographic verification failing; so a
            verification failure against a resolved trusted key flips this
            False (mirroring the Relay-native verifier's signing-input-drift
            semantics and the CLI VAL-W5-028 contract). A missing/untrusted
            key or a malformed trusted JWK is a TRUST failure, not a content
            claim, and leaves digest_ok True. Starts True; a non-object
            signature entry (malformed structure) also flips it False.
        signatures_ok: True iff there is at least one signature AND every
            signature verified cryptographically against its TRUSTED key.
            Fail-closed: any unverified signature flips this False.
        structure_ok: True iff the bundle has a non-empty ``signatures``
            array of objects and a derivable canonical payload.
        signature_checks: per-signature outcomes.
        verified_signature_count: count of signatures with ok=True
            (cryptographically verified). VAL-CRYPTO-005 feeds this (not a
            header-only file count) to the ``bundle_signed`` decision.
        verified_algorithms: the ``alg`` of each VERIFIED signature, in
            check order. Used with :func:`required_alg_matches`.
        claims_count: number of claims in the bundle.
        bundle_digest_sha256: hex SHA-256 of the JCS-canonical payload.
        trust_anchor: the trust-anchor URL the JWKS was resolved from
            (empty when callers passed a JWKS directly).
        trust_anchor_source: source label for the JWKS (see
            ``relay_verifier.jwks_loader`` TRUST_ANCHOR_SOURCE_*).
        errors: structured reasons that prevented verification entirely
            (e.g., no signatures, payload not JCS-encodable). Empty when
            verification proceeded per-signature (whether or not any
            signature verified).
    """

    digest_ok: bool = False
    signatures_ok: bool = False
    structure_ok: bool = False
    signature_checks: list[SignatureCheck] = field(default_factory=list)
    verified_signature_count: int = 0
    verified_algorithms: list[str] = field(default_factory=list)
    claims_count: int = 0
    bundle_digest_sha256: str = ""
    trust_anchor: str = ""
    trust_anchor_source: str = ""
    errors: list[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Base64URL helpers (RFC 4648 sec 5) -- re-implemented locally (no vendored
# acef import).
# -----------------------------------------------------------------------------


def _b64u_decode(s: str) -> bytes:
    """Decode an unpadded base64url string to bytes."""
    if not isinstance(s, str):
        raise ValueError("base64url input must be a string")
    padding_len = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding_len)


def _b64u_encode(b: bytes) -> str:
    """Encode bytes to unpadded base64url."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# -----------------------------------------------------------------------------
# JWK -> public-key loader (RFC 7517 / 7518 / 8037). Mirrors
# relay_cli.evidence_verifier; extended with RSA for ACEF's RS256.
# -----------------------------------------------------------------------------


def _load_public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Build a cryptography public-key object from a TRUSTED JWK dict.

    Supports Ed25519 (kty=OKP, crv=Ed25519), P-256 (kty=EC, crv=P-256),
    and RSA (kty=RSA). Raises ValueError on unsupported/missing fields.

    NOTE: this is only ever called with a JWK taken from the TRUSTED
    JWKS, never with a header-embedded key (VAL-CRYPTO-004).
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
            raise ValueError(f"Ed25519 public key must be 32 bytes; got {len(pub)}")
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
        numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return numbers.public_key()
    raise ValueError(f"unsupported JWK kty: {kty!r}")


def _select_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the first JWK in ``jwks`` whose ``kid`` matches, or None.

    The kid is the ONLY selector; the JWS header is never consulted.
    """
    keys = jwks.get("keys", [])
    if not isinstance(keys, list):
        return None
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("kid") == kid:
            return jwk
    return None


# -----------------------------------------------------------------------------
# Signature verification over a detached-JWS signing input.
# -----------------------------------------------------------------------------


def _verify_signature(
    *,
    alg: str,
    public_key: Any,
    signing_input: bytes,
    signature: bytes,
) -> bool:
    """Return True iff ``signature`` verifies under ``alg`` and key.

    EdDSA over Ed25519, ES256 over P-256 (JWS r||s concat form), and
    RS256 (PKCS1v15 + SHA-256). Any type/length mismatch is a hard False
    (fail-closed).
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
        if not isinstance(public_key.curve, ec.SECP256R1):
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
                signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    return False


# -----------------------------------------------------------------------------
# Bundle payload helpers
# -----------------------------------------------------------------------------


def _payload_for_signing(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical signing payload: bundle MINUS ``signatures``."""
    return {k: v for k, v in bundle.items() if k != "signatures"}


def _decode_jws_parts(jws: str) -> tuple[str, str, bytes]:
    """Split a detached JWS compact string into (header_b64, alg, sig_bytes).

    The detached form is ``header_b64..sig_b64`` (empty payload segment).
    The header is decoded ONLY to cross-check the declared ``alg`` and to
    reject malformed JWS; its ``jwk``/``x5c`` fields are NEVER used to
    resolve a key (VAL-CRYPTO-004).

    Raises ValueError on a structurally invalid JWS.
    """
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWS: expected 3 dot-separated parts")
    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2]
    if not header_b64 or not sig_b64:
        raise ValueError("invalid JWS: empty header or signature segment")
    # RFC 7515 detached content (Appendix F): the JWS Payload is detached,
    # so the compact serialization's middle segment MUST be empty
    # (``header_b64..sig_b64``). The signature is verified ONLY over the
    # recomputed canonical detached content, so a non-empty middle segment
    # is an attacker-spliced payload that would otherwise be silently
    # accepted while the signature still verifies -- a forged-payload
    # fail-open. Reject it before any signature work.
    if payload_b64 != "":
        raise ValueError(
            "invalid JWS: detached signature must have an empty payload "
            "segment (got non-empty payload)"
        )
    try:
        header = json.loads(_b64u_decode(header_b64))
    except (ValueError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid JWS header: {exc}") from exc
    if not isinstance(header, dict):
        raise ValueError("invalid JWS header: not an object")
    header_alg = header.get("alg")
    if not isinstance(header_alg, str):
        raise ValueError("invalid JWS header: missing 'alg'")
    try:
        sig_bytes = _b64u_decode(sig_b64)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"invalid JWS signature segment: {exc}") from exc
    return header_b64, header_alg, sig_bytes


def _signing_input(header_b64: str, payload: bytes) -> bytes:
    """Reconstruct the detached-JWS signing input ``header_b64.payload_b64``."""
    return f"{header_b64}.{_b64u_encode(payload)}".encode("ascii")


# -----------------------------------------------------------------------------
# Verified-count + exact-alg helpers (VAL-CRYPTO-005)
# -----------------------------------------------------------------------------


def count_verified_signatures(result: ACEFVerificationResult) -> int:
    """Return the count of cryptographically-verified signatures (ok=True).

    This is the value the ``bundle_signed`` decision MUST use, never a
    header-only file count.
    """
    return sum(1 for c in result.signature_checks if c.ok)


def required_alg_matches(
    verified_algorithms: list[str], required_alg: str | list[str] | None
) -> int:
    """Count VERIFIED signatures whose alg is in ``required_alg``.

    Matching is EXACT SET MEMBERSHIP, never substring. ``required_alg`` is
    normalised to a set: a bare string becomes a single-element set
    (``"ES256"`` -> ``{"ES256"}``), so ``"256"`` / ``"S256"`` can never
    spuriously match (the vendored ``a in required_alg`` substring bug).
    A None/empty ``required_alg`` means "no algorithm constraint" -> every
    verified signature counts.

    Args:
        verified_algorithms: the alg of each cryptographically-verified
            signature (``ACEFVerificationResult.verified_algorithms``).
        required_alg: a single alg string, a list of allowed algs, or None.

    Returns:
        The number of verified algorithms that are members of the required
        set (or len(verified_algorithms) when no constraint is given).
    """
    if required_alg is None:
        return len(verified_algorithms)
    if isinstance(required_alg, str):
        required_set = {required_alg}
    else:
        required_set = {a for a in required_alg if isinstance(a, str)}
    if not required_set:
        return len(verified_algorithms)
    return sum(1 for a in verified_algorithms if a in required_set)


# -----------------------------------------------------------------------------
# Core verification
# -----------------------------------------------------------------------------


def verify_acef_bundle(
    bundle: dict[str, Any],
    jwks: dict[str, Any],
    *,
    trust_anchor_url: str = "",
    trust_anchor_source: str = "",
    offline: bool = False,
) -> ACEFVerificationResult:
    """Verify a signed ACEF bundle against a TRUSTED JWKS. Fails CLOSED.

    For each entry in ``bundle["signatures"]`` this:

      1. Reads the entry's declared ``kid`` and ``alg`` (NOT from the JWS
         header).
      2. Resolves the public key from ``jwks`` by ``kid`` ONLY. A missing
         kid is a hard rejection -- the JWS header's ``jwk``/``x5c`` is
         never trusted (VAL-CRYPTO-004).
      3. Reconstructs the detached-JWS signing input over the JCS-canonical
         bytes of the bundle minus ``signatures``, and verifies the
         signature cryptographically against the trusted key
         (VAL-CRYPTO-001). Any tamper to a record changes the canonical
         bytes and invalidates the signature.
      4. Records a per-signature :class:`SignatureCheck`.

    ``signatures_ok`` is True only when at least one signature is present
    AND every signature verified. ``verified_signature_count`` and
    ``verified_algorithms`` capture only ok=True checks for the
    ``bundle_signed`` decision (VAL-CRYPTO-005).

    The function does NOT raise on verification failure; failure modes are
    encoded in the result so a CLI can emit a structured envelope.

    Args:
        bundle: parsed ACEF bundle dict (must carry a ``signatures`` array).
        jwks: trusted JWKS dict (RFC 7517 ``{"keys": [...]}``).
        trust_anchor_url / trust_anchor_source: recorded verbatim in the
            result for the verification envelope.
        offline: recorded for provenance; this function performs no
            network access regardless (the JWKS is already resolved by the
            caller). The flag is accepted so callers that resolve the JWKS
            via ``relay_verifier.jwks_loader`` can thread it through.
    """
    del offline  # Provenance only; no network is touched here.
    result = ACEFVerificationResult(
        trust_anchor=trust_anchor_url, trust_anchor_source=trust_anchor_source
    )

    if not isinstance(bundle, dict):
        result.errors.append("bundle is not a JSON object")
        return result
    if not isinstance(jwks, dict):
        result.errors.append("jwks is not a JSON object")
        return result

    sigs = bundle.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        result.errors.append("bundle has no 'signatures' array or it is empty")
        return result

    payload = _payload_for_signing(bundle)
    try:
        canonical_bytes = jcs_canonicalize(payload)
    except Exception as exc:  # noqa: BLE001 -- surface any JCS encode failure
        result.errors.append(f"bundle payload is not JCS-encodable: {exc}")
        return result
    result.bundle_digest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    result.structure_ok = True

    claims = bundle.get("claims")
    result.claims_count = len(claims) if isinstance(claims, list) else 0

    digest_ok = True
    sigs_ok = True
    any_present = False

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

        kid = sig.get(_SIG_KID_KEY)
        declared_alg = sig.get(_SIG_ALG_KEY)
        jws = sig.get(_SIG_JWS_KEY)

        if not isinstance(kid, str) or not kid:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=f"<sig[{idx}]>",
                    alg=str(declared_alg) if declared_alg else "<unknown>",
                    ok=False,
                    reason="signature missing 'kid'",
                )
            )
            continue
        if declared_alg not in SUPPORTED_ALGS:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=str(declared_alg) if declared_alg else "<unknown>",
                    ok=False,
                    reason=f"unsupported alg: {declared_alg!r}",
                )
            )
            continue
        if not isinstance(jws, str) or not jws:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=declared_alg,
                    ok=False,
                    reason="signature missing detached JWS string",
                )
            )
            continue

        any_present = True

        try:
            header_b64, header_alg, sig_bytes = _decode_jws_parts(jws)
        except ValueError as exc:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid, alg=declared_alg, ok=False, reason=str(exc)
                )
            )
            continue

        # The header alg MUST match the declared alg; an attacker cannot
        # downgrade/confuse the algorithm via a mismatched header.
        if header_alg != declared_alg:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=declared_alg,
                    ok=False,
                    reason=(
                        f"JWS header alg {header_alg!r} does not match "
                        f"declared alg {declared_alg!r}"
                    ),
                )
            )
            continue

        # TRUSTED-KEY ONLY: resolve by kid from the trusted JWKS. The JWS
        # header's jwk/x5c is NEVER consulted (VAL-CRYPTO-004).
        jwk = _select_jwk(jwks, kid)
        if jwk is None:
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=declared_alg,
                    ok=False,
                    reason=f"no JWK in trusted anchor matches kid {kid!r}",
                )
            )
            continue
        try:
            public_key = _load_public_key_from_jwk(jwk)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            # A malformed TRUSTED-JWKS entry must fail CLOSED on THIS
            # signature, never escape the verifier (which would crash the
            # caller instead of emitting the structured fail-closed
            # envelope). ValueError covers bad b64url/field types and the
            # cryptography numeric-range checks (n/e/point-on-curve);
            # TypeError covers non-string/None fields slipping past the
            # isinstance guards; UnsupportedAlgorithm covers a key type the
            # backend refuses to construct. This is a TRUST failure, so
            # digest_ok is deliberately left unchanged (see the verify
            # branch below).
            sigs_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=declared_alg,
                    ok=False,
                    reason=f"trusted JWK load failed: {exc}",
                )
            )
            continue

        signing_input = _signing_input(header_b64, canonical_bytes)
        verified = _verify_signature(
            alg=declared_alg,
            public_key=public_key,
            signing_input=signing_input,
            signature=sig_bytes,
        )
        if not verified:
            sigs_ok = False
            # Content-integrity drift: a structurally-valid signature whose
            # key was resolved from the TRUSTED JWKS by kid did not verify
            # against the recomputed canonical bytes. Because the detached
            # JWS records no separate signing input, a record tamper that
            # retains the original signature is signalled SOLELY here -- the
            # canonical content no longer matches what was signed. This
            # mirrors the Relay-native verifier's signing-input-drift
            # semantics (evidence_verifier.py sets digest_ok=False on drift)
            # and the CLI VAL-W5-028 contract (a single-byte mutation yields
            # digest_ok=false, signatures_ok=false). A missing/untrusted key
            # or a malformed trusted JWK is a TRUST failure, not a content
            # claim, and deliberately leaves digest_ok unchanged above.
            digest_ok = False
            result.signature_checks.append(
                SignatureCheck(
                    kid=kid,
                    alg=declared_alg,
                    ok=False,
                    reason=(
                        "signature did not verify against the trusted key "
                        "(tampered bundle, wrong key, or forged signature)"
                    ),
                )
            )
            continue

        result.signature_checks.append(
            SignatureCheck(kid=kid, alg=declared_alg, ok=True, reason="")
        )

    result.digest_ok = digest_ok
    result.signatures_ok = sigs_ok and any_present
    verified_checks = [c for c in result.signature_checks if c.ok]
    result.verified_signature_count = len(verified_checks)
    result.verified_algorithms = [c.alg for c in verified_checks]
    return result


def verify_acef_bundle_path(
    bundle_path: str | Path,
    jwks: dict[str, Any],
    *,
    trust_anchor_url: str = "",
    trust_anchor_source: str = "",
    offline: bool = False,
) -> ACEFVerificationResult:
    """Read a bundle file and verify it (path variant of
    :func:`verify_acef_bundle`).

    On a read/parse failure the result carries a structured error and all
    ``*_ok`` flags stay False (fail-closed).
    """
    path = Path(bundle_path).expanduser()
    result = ACEFVerificationResult(
        trust_anchor=trust_anchor_url, trust_anchor_source=trust_anchor_source
    )
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError) as exc:
        result.errors.append(f"cannot read bundle file {path!s}: {exc}")
        return result
    if not raw:
        result.errors.append(f"bundle file {path!s} is empty")
        return result
    try:
        bundle = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        result.errors.append(f"bundle is not valid UTF-8 JSON: {exc}")
        return result
    if not isinstance(bundle, dict):
        result.errors.append("bundle root must be a JSON object")
        return result
    return verify_acef_bundle(
        bundle,
        jwks,
        trust_anchor_url=trust_anchor_url,
        trust_anchor_source=trust_anchor_source,
        offline=offline,
    )


def is_acef_bundle(bundle: dict[str, Any]) -> bool:
    """Return True iff ``bundle`` looks like a Relay-emitted ACEF bundle.

    Detection is by shape (used by the CLI to route ACEF bundles to this
    verifier instead of the Relay-native ``verify_bundle``):

      * ``schema_version == ACEF_CORE_SCHEMA_VERSION_PIN`` ("v0.3"), OR
      * a ``namespaces`` object carrying an ``x-relay`` block.

    Relay-native evidence bundles carry ``schema_version ==
    "relay.evidence_bundle.v1"`` and a ``signing_key_id`` /
    ``signing_input_b64u`` signature shape, so they do NOT match.
    """
    if not isinstance(bundle, dict):
        return False
    # Import here (not at module top) to keep this module importable even
    # if relay_extensions ever moves; the constant is a small string.
    from relay_extensions import (
        ACEF_CORE_SCHEMA_VERSION_PIN,
        X_RELAY_NAMESPACE_KEY,
    )

    if bundle.get("schema_version") == ACEF_CORE_SCHEMA_VERSION_PIN:
        return True
    namespaces = bundle.get("namespaces")
    return isinstance(namespaces, dict) and X_RELAY_NAMESPACE_KEY in namespaces


# -----------------------------------------------------------------------------
# Sign-side helpers (TEST fixtures only; never invoked from production paths).
# Production ACEF bundles are signed by the relay-platform signer service,
# outside this OSS package. These mirror the ACEF detached-JWS wire form so
# tests can build a trusted/attacker keypair, sign, and assert verification.
# -----------------------------------------------------------------------------


def jwk_from_ed25519_public_key(
    public_key: ed25519.Ed25519PublicKey, *, kid: str
) -> dict[str, Any]:
    """Project an Ed25519 public key into a JWK dict (RFC 8037)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": ALG_EDDSA,
        "use": "sig",
        "x": _b64u_encode(raw),
    }


def jwk_from_ec_p256_public_key(
    public_key: ec.EllipticCurvePublicKey, *, kid: str
) -> dict[str, Any]:
    """Project a P-256 public key into a JWK dict (RFC 7518 sec 6.2)."""
    numbers = public_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "alg": ALG_ES256,
        "use": "sig",
        "x": _b64u_encode(x_bytes),
        "y": _b64u_encode(y_bytes),
    }


def _detached_jws_header_b64(alg: str, *, embed_jwk: dict[str, Any] | None) -> str:
    """Build the base64url JWS header for a detached signature.

    When ``embed_jwk`` is provided the header carries a ``jwk`` (mirroring
    the vendored signer, which auto-embeds the public key). The Relay
    verifier ignores any header-embedded key, so this is purely so tests
    can prove the header-trust path is NOT taken (VAL-CRYPTO-004).
    """
    header: dict[str, Any] = {"alg": alg}
    if embed_jwk is not None:
        header["jwk"] = embed_jwk
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return _b64u_encode(header_bytes)


def sign_acef_bundle_ed25519(
    bundle: dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
    *,
    kid: str,
) -> dict[str, Any]:
    """TEST-ONLY: produce a detached-JWS signature entry for ``bundle``.

    Mirrors the vendored ACEF signer by embedding the public ``jwk`` in
    the JWS header (so tests exercise the header-trust attack path), but
    the Relay verifier resolves keys only from the trusted JWKS by kid.
    """
    embed = jwk_from_ed25519_public_key(private_key.public_key(), kid=kid)
    header_b64 = _detached_jws_header_b64(ALG_EDDSA, embed_jwk=embed)
    payload = jcs_canonicalize(_payload_for_signing(bundle))
    signing_input = _signing_input(header_b64, payload)
    sig = private_key.sign(signing_input)
    return {
        _SIG_KID_KEY: kid,
        _SIG_ALG_KEY: ALG_EDDSA,
        _SIG_JWS_KEY: f"{header_b64}..{_b64u_encode(sig)}",
    }


def sign_acef_bundle_es256(
    bundle: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    *,
    kid: str,
) -> dict[str, Any]:
    """TEST-ONLY: produce an ES256 detached-JWS signature entry for ``bundle``."""
    embed = jwk_from_ec_p256_public_key(private_key.public_key(), kid=kid)
    header_b64 = _detached_jws_header_b64(ALG_ES256, embed_jwk=embed)
    payload = jcs_canonicalize(_payload_for_signing(bundle))
    signing_input = _signing_input(header_b64, payload)
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        _SIG_KID_KEY: kid,
        _SIG_ALG_KEY: ALG_ES256,
        _SIG_JWS_KEY: f"{header_b64}..{_b64u_encode(raw)}",
    }


__all__ = [
    "ACEF_VERIFIER_RESULT_SCHEMA",
    "ALG_EDDSA",
    "ALG_ES256",
    "ALG_RS256",
    "SUPPORTED_ALGS",
    "ACEFVerificationResult",
    "SignatureCheck",
    "count_verified_signatures",
    "is_acef_bundle",
    "jwk_from_ec_p256_public_key",
    "jwk_from_ed25519_public_key",
    "required_alg_matches",
    "sign_acef_bundle_ed25519",
    "sign_acef_bundle_es256",
    "verify_acef_bundle",
    "verify_acef_bundle_path",
]
