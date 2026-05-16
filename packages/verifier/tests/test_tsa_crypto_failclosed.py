"""Fail-closed TSA cryptographic verification guard for the offline verifier.

Per spec section AB lines 5416-5417 every signed evidence bundle carries an
RFC 3161 TSA timestamp so an auditor can verify the bundle was signed AT a
specific wall-clock time. The prior implementation in `relay_verifier.tsa.
validate_tsa_token` checked only the structural presence of
`tsa_signature_b64u` -- ANY non-empty string passed.

Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a pass.")
the verifier MUST NOT report `tsa_check == "ok"` based on presence alone.
Until the ASN.1 RFC 3161 cryptographic signature verification is wired
(asn1crypto / rfc3161-client), every TSA token whose contents have not
been cryptographically verified MUST be reported as `invalid` with reason
`tsa_crypto_not_implemented`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from relay_verifier.tsa import (
    RELAY_EVID_031,
    TSA_CRYPTO_IMPLEMENTED,
    validate_tsa_token,
)


def _structured_token(
    *,
    bundle_digest_hex: str,
    gen_time: str = "2026-05-15T12:34:56Z",
    signature_b64u: str = "AA" * 32,
    signer_subject: str = "CN=Relay OSS Placeholder TSA Root",
) -> dict[str, Any]:
    return {
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
        "tsa_signature_b64u": signature_b64u,
    }


# ---------------------------------------------------------------------------
# Feature-flag guard
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_tsa_crypto_flag_is_false() -> None:
    """Until ASN.1 RFC 3161 signature verification is wired the flag MUST
    be False so every code path treats the TSA verifier as unimplemented."""
    assert TSA_CRYPTO_IMPLEMENTED is False, (
        "TSA_CRYPTO_IMPLEMENTED was flipped True without the corresponding "
        "asn1crypto/rfc3161-client verification pipeline; this is a P1 "
        "keystone-invariant violation (CLAUDE.md #2)."
    )


# ---------------------------------------------------------------------------
# validate_tsa_token MUST fail-closed when a token is present
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_validate_tsa_rejects_forged_signature() -> None:
    """A TSA token with random bytes for `tsa_signature_b64u` MUST be
    rejected with `outcome="invalid"` and `reason="tsa_crypto_not_implemented"`.
    The prior implementation accepted any non-empty signature string."""
    bundle_digest = "ab" * 32
    decided_at = "2026-05-15T12:34:56Z"
    forged_sig = secrets.token_urlsafe(48)
    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        signature_b64u=forged_sig,
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
    )
    assert result.outcome == "invalid", (
        f"forged TSA signature must yield outcome='invalid', got {result.outcome!r}"
    )
    assert result.reason.startswith("TSA cryptographic signature verification"), (
        f"expected fail-closed reason, got {result.reason!r}"
    )


@pytest.mark.plumbing
def test_validate_tsa_rejects_placeholder_signature() -> None:
    """The historical placeholder signature 'AA'*32 (which the test
    fixture builder used) MUST be rejected by the fail-closed verifier."""
    bundle_digest = "cd" * 32
    decided_at = "2026-05-15T12:34:56Z"
    token = _structured_token(
        bundle_digest_hex=bundle_digest,
        gen_time=decided_at,
        signature_b64u="AA" * 32,
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at=decided_at,
    )
    assert result.outcome == "invalid"


@pytest.mark.plumbing
def test_validate_tsa_missing_token_still_reports_missing() -> None:
    """The fail-closed switch MUST NOT change the missing-token behavior;
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
    """The fail-closed switch MUST run AFTER the structural binding
    checks so message-imprint tampering still surfaces as `invalid` with
    the structural reason, not the crypto-not-implemented reason."""
    bundle_digest = "11" * 32
    tampered_digest = "22" * 32
    token = _structured_token(
        bundle_digest_hex=tampered_digest,
        gen_time="2026-05-15T12:34:56Z",
    )
    result = validate_tsa_token(
        token=token,
        bundle_digest_hex=bundle_digest,
        decided_at="2026-05-15T12:34:56Z",
    )
    assert result.outcome == "invalid"
    # The message_imprint mismatch reason is the structural one, not
    # the crypto-not-implemented one -- structural checks run first.
    assert "message_imprint" in result.reason
