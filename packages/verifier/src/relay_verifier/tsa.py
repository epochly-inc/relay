"""RFC 3161 TSA timestamp validation for evidence bundles (W10.4 + w9-2).

Per spec section AB lines 5416-5417 every signed evidence bundle carries
a Time-Stamp Authority response (RFC 3161) so an auditor can verify the
bundle was signed AT a specific wall-clock time, not merely that it was
signed by a particular key. Per VAL-W10-025 a bundle whose `.tsr` is
absent is rejected with `RELAY-EVID-031`. Per VAL-W10-026 the response
MUST validate against the TSA cert chain bundled in the trust bundle.
Per VAL-W10-027 the TSA `genTime` MUST be within +/-300 s of the bundle's
`decided_at`/`occurred_at`; outside the window raises `RELAY-EVID-038`.

The verifier package ships the TSA cert chain at the canonical path
`packages/verifier/trust/tsa-chain.pem` (VAL-W10-042). The chain ships
public certs only; banned pattern #14 forbids any private signing key
material from landing in OSS.

Implementation note (w9-2): the cryptographic verification path is
implemented in this build. The token dict carries a base64url-encoded
RFC 3161 ``TimeStampResp`` DER blob under the ``tsr_der_b64u`` field;
:func:`validate_tsa_token` decodes via :mod:`rfc3161_client` (which in
turn parses the ASN.1 via :mod:`asn1crypto`) and verifies the
:class:`~asn1crypto.cms.SignedData` ``SignerInfo`` signature against
the bundled TSA cert chain, anchored at the self-signed root in
``packages/verifier/src/relay_verifier/tsa_chain/tsa-chain.pem``. The
embedded ``MessageImprint.hashed_message`` is compared byte-for-byte
against the bundle binding digest under the token's declared hash
algorithm; a mismatch returns ``outcome="invalid"`` with reason
``"message_imprint_mismatch"``.

Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a
pass.") the module-level ``TSA_CRYPTO_IMPLEMENTED`` flag is True only
while the verifier actually performs the ASN.1 decode + SignerInfo
signature verification end-to-end. Flipping the flag without the
accompanying verifier is a P1 keystone-invariant regression guarded by
``packages/verifier/tests/test_tsa_crypto_failclosed.py``.

The structured token shape (mirrors ASN.1 RFC 3161 sec 2.4.2 TSTInfo):

    {
      "version": 1,
      "policy_oid": "1.3.6.1.4.1.601.10.3.1",   # TSA policy OID
      "message_imprint": {
        "hash_algorithm": "sha256",
        "hashed_message_hex": "<sha256 of bundle bytes>",
      },
      "serial_number": "<integer>",
      "gen_time": "2026-05-15T12:34:56Z",       # RFC 3339 UTC
      "tsa_signature_alg": "ES256" | "EdDSA" | "RS256",
      "tsa_signer_cert_subject": "<X.500 DN>",
      # Cryptographic payload (w9-2): real RFC 3161 TimeStampResp DER,
      # base64url-encoded, signing certificate embedded in SignedData.
      "tsr_der_b64u": "<base64url-encoded TimeStampResp DER>",
    }

The verifier checks:

  1. ``tsr_der_b64u`` is present and decodes via
     :func:`rfc3161_client.decode_timestamp_response`.
  2. ``message_imprint.hashed_message`` byte-equals the bundle binding
     digest under the declared hash algorithm (also cross-checked
     against ``hashed_message_hex`` in the dict for backward compat).
  3. ``gen_time`` is within +/-300 s of ``decided_at``.
  4. The :class:`~asn1crypto.cms.SignedData` ``SignerInfo`` signature
     verifies against the embedded leaf certificate, AND the leaf
     certificate chains to one of the bundled TSA root certificates.
     Tests may inject additional trusted roots via
     :func:`validate_tsa_token`'s ``extra_trusted_roots_pem`` parameter
     so an ephemeral test chain can be exercised without writing private
     key material to disk (banned pattern #14).
  5. The cert chain itself parses as PEM, has notAfter in the future
     (cert chain not expired), and meets minimum key strength
     (RSA >= 2048 / ECDSA >= P-256 / Ed25519).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import binascii as _binascii
import datetime as _dt
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final

import rfc3161_client
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from rfc3161_client.errors import VerificationError as _RFC3161VerificationError

# Base64 errors raised by Python's stdlib (binascii.Error is a subclass
# of ValueError on 3.11+; alias to keep the except clauses tidy).
_Base64Error = _binascii.Error

# Single-source +/-300 s skew bound per spec section L.5 line 4479 + AB
# line 5690. The same constant is used for VAL-W10-027 (TSA genTime vs
# decided_at) AND VAL-W10-034 (auditor clock skew tolerance) AND
# VAL-W10-031 (key not_before grace window). Changing this constant is a
# spec-amendment-level decision; no individual call-site should override
# it.
CLOCK_SKEW_TOLERANCE_SECONDS: Final[int] = 300

# Wire codes raised by this module.
RELAY_EVID_031: Final[str] = "RELAY-EVID-031"
"""TSA timestamp missing or cryptographically invalid (VAL-W10-025, VAL-V2M09-015..017)."""

RELAY_EVID_038: Final[str] = "RELAY-EVID-038"
"""Backdated/forward-dated evidence: TSA genTime outside +/-300 s of
decided_at (VAL-W10-027)."""

# Canonical packaged path for the TSA cert chain shipped with the
# verifier wheel. The directory is a hatch-include target in
# packages/verifier/pyproject.toml so it lands inside the installed
# package.
TSA_CHAIN_DIRNAME: Final[str] = "tsa_chain"
TSA_CHAIN_FILENAME: Final[str] = "tsa-chain.pem"

# Minimum key strengths per VAL-W10-042. Mirrors the L.1 algorithm
# allow-list rejection of weaker primitives.
MIN_RSA_BITS: Final[int] = 2048

# Cryptographic TSA signature verification feature flag. With the flag
# at True ``validate_tsa_token`` performs full RFC 3161 ``SignerInfo``
# signature verification (via :mod:`rfc3161_client`) against the bundled
# TSA cert chain. Flipping this False without removing the verifier
# implementation below is a no-op for tests; flipping True without
# wiring the real verifier is a P1 keystone-invariant regression
# guarded by ``test_tsa_crypto_failclosed.py::test_tsa_crypto_flag_is_true``.
TSA_CRYPTO_IMPLEMENTED: Final[bool] = True


# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass
class TSAValidationResult:
    """Aggregate verdict for a TSA timestamp on a bundle.

    `outcome` is one of: "ok", "invalid", "missing", "skew".
    `reason` carries a short, structured tag (e.g. "message_imprint_mismatch",
    "tsa_signature_invalid", "tsa_cert_chain_unknown_root") or, on
    structural-only failures, a human-readable detail.
    `code` carries the wire code when one applies
    (RELAY-EVID-031 / RELAY-EVID-038); "" on ok.
    `gen_time` echoes the parsed token genTime (or "" when missing).
    `skew_seconds` is the absolute delta between gen_time and
    decided_at; -1 when not computed.
    """

    outcome: str = "missing"
    reason: str = ""
    code: str = ""
    gen_time: str = ""
    skew_seconds: int = -1


@dataclass(frozen=True)
class TSACertSummary:
    """Summary of one cert in the TSA trust chain (VAL-W10-042)."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    key_alg: str
    key_strength_bits: int
    is_self_signed: bool


@dataclass
class TSAChainCheck:
    """Result of inspecting the bundled TSA cert chain."""

    chain_path: str
    cert_count: int
    certs: list[TSACertSummary]
    chain_ok: bool
    reason: str = ""


# -----------------------------------------------------------------------------
# Time helpers
# -----------------------------------------------------------------------------


def _parse_iso_z(s: str) -> _dt.datetime:
    """Parse an RFC 3339 UTC timestamp ending in 'Z' to a datetime.

    Raises :class:`ValueError` on malformed input. Accepts both
    seconds-resolution and fractional-second forms; both are emitted by
    the canonical bundle producer.
    """
    if not isinstance(s, str) or not s:
        raise ValueError(f"timestamp must be a non-empty string, got {s!r}")
    if not s.endswith("Z"):
        raise ValueError(f"timestamp must end with 'Z' (UTC), got {s!r}")
    # Python's fromisoformat accepts the form once we replace the trailing
    # Z with +00:00 (3.11+). 3.12+ tolerates the Z suffix directly but
    # we normalise for forward-compat.
    return _dt.datetime.fromisoformat(s[:-1] + "+00:00")


def _abs_seconds_delta(a: _dt.datetime, b: _dt.datetime) -> int:
    delta = a - b
    return abs(int(delta.total_seconds()))


def _b64u_decode(s: str) -> bytes:
    """Decode a base64url string (RFC 4648 sec 5) with padding restored."""
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


# -----------------------------------------------------------------------------
# TSA token validation
# -----------------------------------------------------------------------------


def _verify_cryptographic_signature(
    *,
    tsr_der: bytes,
    bundle_digest_bytes: bytes,
    trust_roots: list[x509.Certificate],
    common_name: str | None = None,
) -> tuple[bool, str]:
    """Cryptographically verify a real RFC 3161 ``TimeStampResp``.

    Returns ``(ok, reason)``. On success ``ok`` is True and ``reason`` is
    empty. On failure ``ok`` is False and ``reason`` is one of the
    structured tags consumed by :func:`validate_tsa_token`:

      * ``"tsr_decode_failed"`` -- DER is not a parseable TimeStampResp.
      * ``"tsa_cert_chain_unknown_root"`` -- the embedded leaf cert does
        not chain to any of the supplied ``trust_roots``.
      * ``"tsa_signature_invalid"`` or ``"signerinfo_signature_invalid"`` --
        the SignerInfo signature did not verify over the SignedData
        content (catches both the per-byte signature mutation case and
        the broader ``VerificationError`` family).

    The decode + verify path delegates to :mod:`rfc3161_client` so we
    rely on a single OpenSSL-backed PKCS#7 verifier rather than
    hand-rolling SignerInfo signature verification (which is
    notoriously easy to get wrong against the CMS DER signed-attrs
    rules). This satisfies VAL-V2M09-015 ("decoding of the TimeStampResp
    via either asn1crypto.tsp.TimeStampResp.load(...) OR
    rfc3161_client.TimeStampResponse.from_der(...)") -- the underlying
    rfc3161_client decoder is the asn1crypto-backed RFC 3161 parser.
    """
    if not trust_roots:
        return False, "tsa_cert_chain_unknown_root"

    try:
        ts_response = rfc3161_client.decode_timestamp_response(tsr_der)
    except (ValueError, _RFC3161VerificationError, Exception) as exc:
        return False, f"tsr_decode_failed: {type(exc).__name__}"

    # Build a verifier with the bundled (+ optional override) roots.
    builder = rfc3161_client.VerifierBuilder()
    for root in trust_roots:
        builder = builder.add_root_certificate(root)
    if common_name is not None:
        builder = builder.common_name(common_name)
    verifier = builder.build()

    try:
        ok = verifier.verify(ts_response, hashed_message=bundle_digest_bytes)
    except _RFC3161VerificationError as exc:
        msg = str(exc)
        lowered = msg.lower()
        # Distinguish chain failures (unknown root, expired cert, wrong
        # purpose, cert-issuer signature mismatch) from raw signed-content
        # signature failures (i.e. SignerInfo signature over signed_attrs
        # actually doesn't verify) so callers can branch on incident-
        # response category. OpenSSL's PKCS7_verify surfaces either an
        # "X509 path build" error (no trusted issuer for the leaf) OR a
        # "certificate signature failure" (the leaf's issuer cert exists
        # in the trust roots but doesn't validate the leaf's issuer
        # signature -- i.e. wrong root) when the chain cannot be built.
        # We treat all chain-build failures as ``tsa_cert_chain_unknown_root``
        # and reserve ``tsa_signature_invalid`` for cases where the chain
        # built successfully but the SignedData content signature was
        # tampered (the "signature_invalid" / "digest mismatch" cluster of
        # OpenSSL errors at the EVP_DigestVerifyFinal layer when the
        # signature is over the content, not over an X.509 cert).
        chain_failure_markers = (
            "unable to get local issuer",
            "self signed certificate",
            "self-signed certificate",
            "unable to verify the first certificate",
            "certificate verify failed",
            "certificate has expired",
            "unsuitable certificate purpose",
            # OpenSSL emits "certificate signature failure" when the
            # leaf's issuer-pubkey-cannot-verify-its-own-signature, which
            # is the unknown-root scenario.
            "certificate signature failure",
            "self-signed certificate in certificate chain",
            "unable to build certificate chain",
        )
        if any(marker in lowered for marker in chain_failure_markers):
            return False, "tsa_cert_chain_unknown_root"
        return False, "tsa_signature_invalid"
    except Exception:
        # VAL-ISO-023: fail closed on ANY other exception type. The decode
        # step above already guards with a bare ``Exception``; the verify
        # step must do the same. A non-VerificationError (e.g. a TypeError
        # on an unexpected internal state) MUST NOT escape this function and
        # propagate out of ``validate_bundle`` -- the contract is fail-closed,
        # not crash (CLAUDE.md keystone: the verifier fails closed). We treat
        # the unexpected error as a signature-invalid outcome rather than a
        # chain failure, since we cannot prove a valid chain at this point.
        return False, "tsa_signature_invalid"

    if not ok:
        return False, "tsa_signature_invalid"

    return True, ""


def validate_tsa_token(
    *,
    token: dict[str, Any] | None,
    bundle_digest_hex: str,
    decided_at: str,
    chain_certs: list[x509.Certificate] | None = None,
    extra_trusted_roots_pem: bytes | None = None,
) -> TSAValidationResult:
    """Validate a parsed RFC 3161 TSTInfo token against the bundle.

    See module docstring for the structured token shape. Returns a
    :class:`TSAValidationResult`. Failure modes:

      * ``token is None`` -> ``outcome="missing"``, ``code=RELAY-EVID-031``
        (VAL-W10-025).
      * ``message_imprint`` mismatch -> ``outcome="invalid"``,
        ``reason="message_imprint_mismatch"``, ``code=RELAY-EVID-031``
        (VAL-V2M09-015).
      * ``gen_time`` outside +/-300 s -> ``outcome="skew"``,
        ``code=RELAY-EVID-038`` (VAL-W10-027, VAL-V2M09-019).
      * unparsable ``gen_time`` -> ``outcome="invalid"``.
      * missing ``tsr_der_b64u`` -> ``outcome="invalid"``,
        ``reason="tsr_der_missing"`` (VAL-V2M09-005: real crypto
        requires a real DER blob).
      * signer chains to a root NOT in the bundled chain ->
        ``outcome="invalid"``, ``reason="tsa_cert_chain_unknown_root"``,
        ``code=RELAY-EVID-031`` (VAL-V2M09-016).
      * SignerInfo signature does not verify ->
        ``outcome="invalid"``, ``reason="tsa_signature_invalid"``,
        ``code=RELAY-EVID-031`` (VAL-V2M09-017).

    ``chain_certs`` carries the bundled TSA root chain (loaded by the
    caller via :func:`load_bundled_tsa_chain`). ``extra_trusted_roots_pem``
    is a test-injection seam: callers may pass an additional PEM blob of
    trust roots (e.g. an ephemeral root generated by a fixture builder).
    Production callers leave ``extra_trusted_roots_pem`` as None and the
    verifier uses only the bundled chain.
    """
    result = TSAValidationResult()

    if token is None:
        result.outcome = "missing"
        result.reason = "no TSA token (.tsr) attached to bundle"
        result.code = RELAY_EVID_031
        return result

    if not isinstance(token, dict):
        result.outcome = "invalid"
        result.reason = (
            f"TSA token must be a structured object, got {type(token).__name__}"
        )
        return result

    # 1. message_imprint binds the bundle bytes to the timestamp.
    msg_imprint = token.get("message_imprint")
    if not isinstance(msg_imprint, dict):
        result.outcome = "invalid"
        result.reason = "TSA token missing or malformed 'message_imprint'"
        result.code = RELAY_EVID_031
        return result
    declared_digest = msg_imprint.get("hashed_message_hex")
    declared_alg = msg_imprint.get("hash_algorithm")
    if declared_alg != "sha256":
        result.outcome = "invalid"
        result.reason = (
            f"TSA message_imprint must use sha256, got {declared_alg!r}"
        )
        result.code = RELAY_EVID_031
        return result
    if declared_digest != bundle_digest_hex:
        result.outcome = "invalid"
        result.reason = "message_imprint_mismatch"
        result.code = RELAY_EVID_031
        return result

    # 2. gen_time within +/-300 s of decided_at.
    gen_time_str = token.get("gen_time")
    if not isinstance(gen_time_str, str) or not gen_time_str:
        result.outcome = "invalid"
        result.reason = "TSA token missing 'gen_time'"
        result.code = RELAY_EVID_031
        return result
    result.gen_time = gen_time_str
    try:
        gen_time = _parse_iso_z(gen_time_str)
    except ValueError as exc:
        result.outcome = "invalid"
        result.reason = f"TSA gen_time unparsable: {exc}"
        result.code = RELAY_EVID_031
        return result
    try:
        decided = _parse_iso_z(decided_at)
    except ValueError as exc:
        result.outcome = "invalid"
        result.reason = f"bundle decided_at unparsable: {exc}"
        result.code = RELAY_EVID_031
        return result
    skew = _abs_seconds_delta(gen_time, decided)
    result.skew_seconds = skew
    if skew > CLOCK_SKEW_TOLERANCE_SECONDS:
        result.outcome = "skew"
        result.reason = "tsa_skew_exceeded"
        result.code = RELAY_EVID_038
        return result

    # 3. Cryptographic TSA verification (VAL-V2M09-005, 015, 016, 017).
    # The token MUST carry a base64url-encoded RFC 3161 TimeStampResp
    # DER under ``tsr_der_b64u``; we decode + verify via rfc3161_client
    # against the bundled TSA cert chain.
    tsr_b64u = token.get("tsr_der_b64u")
    if not isinstance(tsr_b64u, str) or not tsr_b64u:
        result.outcome = "invalid"
        result.reason = "tsr_der_missing"
        result.code = RELAY_EVID_031
        return result
    try:
        tsr_der = _b64u_decode(tsr_b64u)
    except (ValueError, _Base64Error) as exc:
        result.outcome = "invalid"
        result.reason = f"tsr_der_b64u_decode_failed: {exc}"
        result.code = RELAY_EVID_031
        return result

    # Bundled chain (production) + optional extra trusted roots
    # (test-injected ephemeral chain).
    trust_roots: list[x509.Certificate] = []
    if chain_certs:
        trust_roots.extend(chain_certs)
    if extra_trusted_roots_pem:
        try:
            extra = load_tsa_chain_pem_bytes(extra_trusted_roots_pem)
        except ValueError as exc:
            result.outcome = "invalid"
            result.reason = f"extra_trusted_roots_pem_parse_failed: {exc}"
            result.code = RELAY_EVID_031
            return result
        trust_roots.extend(extra)
    if not trust_roots:
        result.outcome = "invalid"
        result.reason = "tsa_no_trust_roots_available"
        result.code = RELAY_EVID_031
        return result

    # The message_imprint check above already confirmed
    # declared_digest == bundle_digest_hex, so the bytes the TSA signed
    # are the bundle binding digest.
    bundle_digest_bytes = bytes.fromhex(bundle_digest_hex)
    ok, reason = _verify_cryptographic_signature(
        tsr_der=tsr_der,
        bundle_digest_bytes=bundle_digest_bytes,
        trust_roots=trust_roots,
    )
    if not ok:
        result.outcome = "invalid"
        result.reason = reason
        result.code = RELAY_EVID_031
        return result

    result.outcome = "ok"
    return result


# -----------------------------------------------------------------------------
# Cert chain inspection (VAL-W10-042)
# -----------------------------------------------------------------------------


def _classify_public_key(pub_key: Any) -> tuple[str, int]:
    """Return (alg_label, strength_bits) for a public key."""
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pub_key.curve.name}", pub_key.key_size
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    return type(pub_key).__name__, 0


def _is_self_signed(cert: x509.Certificate) -> bool:
    """Heuristic self-signed check: subject == issuer."""
    return (
        cert.subject.rfc4514_string() == cert.issuer.rfc4514_string()
    )


def load_tsa_chain_pem_bytes(pem_bytes: bytes) -> list[x509.Certificate]:
    """Parse PEM bytes into a list of X.509 certs."""
    certs = x509.load_pem_x509_certificates(pem_bytes)
    return list(certs)


def load_bundled_tsa_chain() -> tuple[Path, bytes]:
    """Locate and read the verifier-bundled TSA chain PEM file.

    Returns (path, raw_bytes). Raises FileNotFoundError if the bundled
    asset is missing (i.e., a damaged install).
    """
    pkg_resources = resources.files("relay_verifier").joinpath(TSA_CHAIN_DIRNAME)
    chain_file = pkg_resources.joinpath(TSA_CHAIN_FILENAME)
    if not chain_file.is_file():
        raise FileNotFoundError(
            f"bundled TSA chain not found at packaged path "
            f"{TSA_CHAIN_DIRNAME}/{TSA_CHAIN_FILENAME}"
        )
    raw = chain_file.read_bytes()
    # Convert to a real Path for downstream consumers that want the
    # filesystem location (test assertions, error messages).
    return Path(str(chain_file)), raw


def inspect_tsa_chain(pem_bytes: bytes, *, chain_path: str = "") -> TSAChainCheck:
    """Inspect a TSA cert chain per VAL-W10-042.

    Validates: cert_count >= 1, every notAfter in the future, every
    public key meets the minimum strength threshold, and the chain links
    via subject==issuer hops up to a self-signed root.

    Returns a `TSAChainCheck` describing what was found; `chain_ok` is
    True iff every check passed.
    """
    summaries: list[TSACertSummary] = []
    try:
        certs = load_tsa_chain_pem_bytes(pem_bytes)
    except ValueError as exc:
        return TSAChainCheck(
            chain_path=chain_path,
            cert_count=0,
            certs=[],
            chain_ok=False,
            reason=f"chain PEM parse failed: {exc}",
        )

    if not certs:
        return TSAChainCheck(
            chain_path=chain_path,
            cert_count=0,
            certs=[],
            chain_ok=False,
            reason="chain contains zero certificates (VAL-W10-042 requires >= 1)",
        )

    now = _dt.datetime.now(tz=_dt.UTC)
    issues: list[str] = []
    for cert in certs:
        alg, bits = _classify_public_key(cert.public_key())
        # not_valid_after_utc is the cryptography 42+ API; fall back to
        # the deprecated property for older installs (the dep is pinned
        # >= 42 in pyproject.toml so the new API is always available).
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        summary = TSACertSummary(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=not_before.isoformat().replace("+00:00", "Z"),
            not_after=not_after.isoformat().replace("+00:00", "Z"),
            key_alg=alg,
            key_strength_bits=bits,
            is_self_signed=_is_self_signed(cert),
        )
        summaries.append(summary)
        if not_after <= now:
            issues.append(
                f"cert {summary.subject!r} expired at {summary.not_after}"
            )
        # Strength check.
        if alg == "RSA" and bits < MIN_RSA_BITS:
            issues.append(
                f"cert {summary.subject!r} RSA key bits={bits} below "
                f"MIN_RSA_BITS={MIN_RSA_BITS}"
            )
        elif alg.startswith("ECDSA-") and not alg.startswith(
            ("ECDSA-secp256", "ECDSA-secp384", "ECDSA-secp521")
        ):
            issues.append(
                f"cert {summary.subject!r} ECDSA curve {alg} below P-256"
            )
        elif bits == 0:
            issues.append(
                f"cert {summary.subject!r} unsupported key type {alg}"
            )

    # Chain linkage: every non-root cert's issuer must equal the next
    # cert's subject. Single self-signed cert is accepted as a
    # 1-hop chain.
    if len(certs) >= 2:
        for i, cert in enumerate(certs[:-1]):
            parent = certs[i + 1]
            if cert.issuer.rfc4514_string() != parent.subject.rfc4514_string():
                issues.append(
                    f"chain link broken at index {i}: "
                    f"issuer {cert.issuer.rfc4514_string()!r} != "
                    f"parent subject {parent.subject.rfc4514_string()!r}"
                )
    # Final cert in chain must be self-signed (the trust root).
    if not _is_self_signed(certs[-1]):
        issues.append(
            f"chain root cert {certs[-1].subject.rfc4514_string()!r} is not "
            "self-signed (issuer != subject)"
        )

    return TSAChainCheck(
        chain_path=chain_path,
        cert_count=len(certs),
        certs=summaries,
        chain_ok=not issues,
        reason="; ".join(issues),
    )


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "MIN_RSA_BITS",
    "RELAY_EVID_031",
    "RELAY_EVID_038",
    "TSA_CHAIN_DIRNAME",
    "TSA_CHAIN_FILENAME",
    "TSA_CRYPTO_IMPLEMENTED",
    "TSACertSummary",
    "TSAChainCheck",
    "TSAValidationResult",
    "inspect_tsa_chain",
    "load_bundled_tsa_chain",
    "load_tsa_chain_pem_bytes",
    "validate_tsa_token",
]
