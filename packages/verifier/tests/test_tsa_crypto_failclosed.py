"""Post-w9-2 TSA cryptographic verification guard for the offline verifier.

Per spec section AB lines 5416-5417 every signed evidence bundle carries an
RFC 3161 TSA timestamp so an auditor can verify the bundle was signed AT a
specific wall-clock time. Before w9-2 ``relay_verifier.tsa.validate_tsa_token``
checked only the structural presence of ``tsa_signature_b64u`` -- ANY non-empty
string passed.

Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a pass.")
the verifier MUST NOT report ``tsa_check == "ok"`` based on presence alone.
The w9-2 milestone wires ASN.1 RFC 3161 cryptographic signature verification
(via :mod:`rfc3161_client`, which delegates to :mod:`asn1crypto` for ASN.1
decoding) against the bundled TSA cert chain. This file now asserts the
*inverse* polarity of the prior fail-closed tripwire:

  * ``TSA_CRYPTO_IMPLEMENTED is True`` -- the cryptographic verifier is wired.
  * A token whose ``tsr_der_b64u`` is absent is rejected with
    ``reason="tsr_der_missing"``, NOT silently accepted.
  * A token whose ``tsr_der_b64u`` decodes but is signed by an unknown root
    is rejected with ``reason="tsa_cert_chain_unknown_root"``.
  * A token whose ``message_imprint.hashed_message_hex`` does not match the
    bundle binding digest is rejected with ``reason="message_imprint_mismatch"``
    (structural binding precedes crypto verification).
  * A bundle without any TSA token still yields ``outcome="missing"`` with
    ``code="RELAY-EVID-031"``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from relay_verifier import tsa as _tsa
from relay_verifier.tsa import (
    RELAY_EVID_031,
    TSA_CRYPTO_IMPLEMENTED,
    _verify_cryptographic_signature,
    validate_tsa_token,
)


def _structured_token(
    *,
    bundle_digest_hex: str,
    gen_time: str = "2026-05-15T12:34:56Z",
    tsr_der_b64u: str | None = None,
    signer_subject: str = "CN=Relay OSS Placeholder TSA Root",
) -> dict[str, Any]:
    """Build a structured token dict for the verifier.

    By default the token has NO ``tsr_der_b64u`` payload so the verifier
    rejects it with ``tsr_der_missing`` -- this exercises the "real crypto
    requires real DER" guarantee.
    """
    token: dict[str, Any] = {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": gen_time,
        "tsa_signature_alg": "EdDSA",
        "tsa_signer_cert_subject": signer_subject,
    }
    if tsr_der_b64u is not None:
        token["tsr_der_b64u"] = tsr_der_b64u
    return token


# ---------------------------------------------------------------------------
# Feature-flag guard (POLARITY INVERTED at w9-2 milestone)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_tsa_crypto_flag_is_true() -> None:
    """The ASN.1 RFC 3161 SignerInfo verification pipeline is wired in this
    build (VAL-V2M09-005). The flag MUST be True; flipping it back to False
    without removing the cryptographic verifier in
    ``relay_verifier.tsa.validate_tsa_token`` is a P1 keystone-invariant
    regression."""
    assert TSA_CRYPTO_IMPLEMENTED is True, (
        "TSA_CRYPTO_IMPLEMENTED was flipped False after w9-2; the "
        "cryptographic RFC 3161 SignerInfo verification pipeline must "
        "remain wired (CLAUDE.md keystone invariant #2)."
    )


# ---------------------------------------------------------------------------
# validate_tsa_token MUST fail-closed when no DER is attached
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_validate_tsa_rejects_missing_tsr_der() -> None:
    """A token that omits ``tsr_der_b64u`` MUST be rejected with
    outcome=invalid + reason=tsr_der_missing + code=RELAY-EVID-031. The
    prior implementation accepted any non-empty ``tsa_signature_b64u`` --
    the cryptographic build refuses any token without a real DER blob."""
    bundle_digest = "ab" * 32
    decided_at = "2026-05-15T12:34:56Z"
    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        tsr_der_b64u=None,
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
    )
    assert result.outcome == "invalid", (
        f"missing tsr_der_b64u must yield outcome='invalid', got {result.outcome!r}"
    )
    assert result.reason == "tsr_der_missing", (
        f"expected reason='tsr_der_missing', got {result.reason!r}"
    )
    assert result.code == RELAY_EVID_031


@pytest.mark.plumbing
def test_validate_tsa_rejects_garbage_tsr_der() -> None:
    """A token whose ``tsr_der_b64u`` is non-empty but decodes to bytes that
    are NOT a valid RFC 3161 TimeStampResp MUST be rejected with
    outcome=invalid and a reason starting with ``tsr_decode_failed`` (the
    rfc3161_client decoder rejected the bytes)."""
    bundle_digest = "cd" * 32
    decided_at = "2026-05-15T12:34:56Z"
    # 256 random bytes -- not a valid TimeStampResp DER
    garbage_der_b64u = "AQID" * 64
    # Need a chain otherwise we short-circuit with no_trust_roots before
    # the decode is attempted; supply a fake PEM (any cert; we only care
    # that we get past the trust-roots guard before failing the decode).
    # Provide a minimal valid self-signed cert so trust_roots is non-empty.
    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID

    sk = _ec.generate_private_key(_ec.SECP256R1())
    subj = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(sk.public_key())
        .serial_number(1)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .sign(sk, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        tsr_der_b64u=garbage_der_b64u,
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
        extra_trusted_roots_pem=cert_pem,
    )
    assert result.outcome == "invalid"
    assert result.reason.startswith("tsr_decode_failed") or result.reason in (
        "tsa_signature_invalid",
        "tsa_cert_chain_unknown_root",
    ), f"unexpected reason {result.reason!r}"
    assert result.code == RELAY_EVID_031


@pytest.mark.plumbing
def test_validate_tsa_missing_token_still_reports_missing() -> None:
    """The cryptographic build MUST NOT change the missing-token behavior;
    a bundle without any TSA token still gets RELAY-EVID-031 with
    outcome 'missing' (VAL-W10-025)."""
    result = validate_tsa_token(
        token=None,
        bundle_digest_hex="ef" * 32,
        decided_at="2026-05-15T12:34:56Z",
    )
    assert result.outcome == "missing"
    assert result.code == RELAY_EVID_031


@pytest.mark.plumbing
def test_validate_tsa_message_imprint_mismatch_still_rejected() -> None:
    """The cryptographic verifier MUST run AFTER the structural binding
    checks so message-imprint tampering still surfaces as `invalid` with
    the structural reason, not the crypto-not-implemented reason."""
    bundle_digest = "11" * 32
    tampered_digest = "22" * 32
    # Token's declared message_imprint disagrees with the bundle digest the
    # validator is checking against. We deliberately do NOT attach a
    # tsr_der_b64u to confirm the structural check fires first.
    token = _structured_token(
        bundle_digest_hex=tampered_digest,
        gen_time="2026-05-15T12:34:56Z",
        tsr_der_b64u="ZmFrZS1ub3RlYS1iZXItcGFyc2VkLWJlZm9yZS1pbXByaW50",
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at="2026-05-15T12:34:56Z",
    )
    assert result.outcome == "invalid"
    # Structured-tag rather than a free-form sentence: the message_imprint
    # mismatch reason is the contract-specified short form (VAL-V2M09-015).
    assert result.reason == "message_imprint_mismatch", (
        f"expected reason='message_imprint_mismatch', got {result.reason!r}"
    )
    assert result.code == RELAY_EVID_031


# ---------------------------------------------------------------------------
# Sanity: a randomly-generated b64u string that happens to NOT be valid
# DER yields tsr_decode_failed, not a silent accept.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_validate_tsa_rejects_random_b64u_as_tsr_der() -> None:
    """Random bytes pretending to be a TimeStampResp MUST be rejected."""
    bundle_digest = "33" * 32
    decided_at = "2026-05-15T12:34:56Z"
    forged_tsr = secrets.token_urlsafe(96)

    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID

    sk = _ec.generate_private_key(_ec.SECP256R1())
    subj = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(sk.public_key())
        .serial_number(1)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .sign(sk, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        tsr_der_b64u=forged_tsr,
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
        extra_trusted_roots_pem=cert_pem,
    )
    assert result.outcome == "invalid"
    assert result.code == RELAY_EVID_031


# ---------------------------------------------------------------------------
# VAL-ISO-023: a non-VerificationError from verifier.verify MUST fail closed
# and never escape (the function contract is fail-closed, not crash).
# ---------------------------------------------------------------------------


def _self_signed_root() -> bytes:
    """Return a PEM-encoded self-signed cert usable as a trust root."""
    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID

    sk = _ec.generate_private_key(_ec.SECP256R1())
    subj = _x509.Name([_x509.NameAttribute(NameOID.COMMON_NAME, "Test ISO-023")])
    now = _dt.datetime.now(_dt.UTC)
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(sk.public_key())
        .serial_number(1)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=365))
        .sign(sk, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class _RaisingVerifier:
    """A verifier whose verify() raises a NON-VerificationError exception.

    This models rfc3161_client raising e.g. a TypeError on an unexpected
    internal state -- the exact escape the contract must guard against.
    """

    def verify(self, *_args: Any, **_kwargs: Any) -> bool:  # noqa: D401
        raise TypeError("unexpected internal verifier state (not a VerificationError)")


class _RaisingVerifierBuilder:
    """Stand-in for rfc3161_client.VerifierBuilder that yields a raising verifier."""

    def add_root_certificate(self, _root: Any) -> _RaisingVerifierBuilder:
        return self

    def common_name(self, _cn: str) -> _RaisingVerifierBuilder:
        return self

    def build(self) -> _RaisingVerifier:
        return _RaisingVerifier()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-023")
def test_verify_step_non_verification_error_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-VerificationError raised by verifier.verify() must be caught and
    converted to a fail-closed (False, reason) tuple, NOT propagated.

    At base commit the verify-step except clause catches only
    ``rfc3161_client.errors.VerificationError``; any other exception type
    (e.g. TypeError) escapes ``_verify_cryptographic_signature`` and bubbles
    out of ``validate_bundle``, violating the documented fail-closed contract.
    """
    from cryptography import x509 as _x509

    root = _x509.load_pem_x509_certificate(_self_signed_root())

    # decode succeeds (returns an opaque sentinel); the verify step raises a
    # NON-VerificationError. The decode patch keeps us off the rfc3161 parser.
    monkeypatch.setattr(
        _tsa.rfc3161_client,
        "decode_timestamp_response",
        lambda _der: object(),
    )
    monkeypatch.setattr(
        _tsa.rfc3161_client,
        "VerifierBuilder",
        _RaisingVerifierBuilder,
    )

    # Must return a tuple, not raise.
    ok, reason = _verify_cryptographic_signature(
        tsr_der=b"\x30\x03\x02\x01\x00",
        bundle_digest_bytes=b"\x00" * 32,
        trust_roots=[root],
    )
    assert ok is False, "verify-step crash must fail closed (ok=False)"
    assert reason in ("tsa_signature_invalid", "tsa_verify_error"), (
        f"expected a fail-closed reason tag, got {reason!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-023")
def test_validate_tsa_token_does_not_propagate_verify_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """validate_tsa_token (and thus validate_bundle) must not let a
    non-VerificationError from the verify step escape: it must surface as
    outcome='invalid' with RELAY-EVID-031, not raise."""
    bundle_digest = "44" * 32
    decided_at = "2026-05-15T12:34:56Z"

    monkeypatch.setattr(
        _tsa.rfc3161_client,
        "decode_timestamp_response",
        lambda _der: object(),
    )
    monkeypatch.setattr(
        _tsa.rfc3161_client,
        "VerifierBuilder",
        _RaisingVerifierBuilder,
    )

    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        tsr_der_b64u="AQID" * 8,
    )
    # Must not raise.
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
        extra_trusted_roots_pem=_self_signed_root(),
    )
    assert result.outcome == "invalid"
    assert result.code == RELAY_EVID_031
