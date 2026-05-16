"""Fail-closed cryptographic verification guards for the OSS verifier.

These tests encode the P0/P1 security requirement that the offline verifier
NEVER claim cryptographic success when only structural validation has been
performed. Per CLAUDE.md keystone invariant #2 ("Pass without evidence is
not a pass.") and #11 ("Trust anchor is the commercial moat."), a verifier
that reports `pass` based solely on JSON shape matching is a forgery
amplifier, not a trust anchor.

Two specific surfaces are guarded:

  1. `relay_cli.bundle.verify_sigstore` -- previously performed only
     structural JSON-shape checks (trust_root / oidc_issuer / identity
     string equality) and returned the parsed dict on success. An
     attacker who forged a JSON document with the right shape would
     pass. Until the full Sigstore cryptographic verification (Fulcio
     cert chain + Rekor inclusion proof + signature verification against
     the artifact bytes) is wired through `sigstore-python`, this
     function MUST raise to refuse making a verification claim.

  2. `relay_cli.commands.verify_install._verify_rekor_inclusion` --
     previously asserted only that `tlogEntries[*].inclusionProof` was
     a dict; the Merkle inclusion proof was never verified against
     Rekor's public key. Until the proof is cryptographically verified
     this function MUST return `(False, "rekor_crypto_not_implemented")`
     on every input.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from typing import Final

import pytest
from relay_cli.bundle import (
    VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED,
    BundleSignatureInvalid,
    verify_sigstore,
)
from relay_cli.commands.verify_install import (
    REKOR_CRYPTO_IMPLEMENTED,
    _verify_rekor_inclusion,
)

DEFAULT_TRUST_ROOT: Final[str] = "relay.epochly.com"
DEFAULT_OIDC_ISSUER: Final[str] = "https://token.actions.githubusercontent.com"
DEFAULT_IDENTITY: Final[str] = (
    "https://github.com/epochly-inc/relay/.github/workflows/release-pypi.yml@refs/heads/main"
)


def _forged_sigstore_bundle() -> str:
    """Construct a JSON document with the structural-pass shape but a
    bogus signature and bogus certificate -- the entire point is that
    an attacker can forge the JSON shape; the verifier MUST NOT pass it."""
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "verificationMaterial": {
                "certificate": {"rawBytes": "AAAAFORGEDCERTBYTESBASE64"},
                "tlogEntries": [
                    {
                        "logIndex": "1",
                        "integratedTime": "1700000000",
                        "logId": {"keyId": "AAAA"},
                        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                        "canonicalizedBody": "eyJraW5kIjoiaGFzaGVkcmVrb3JkIn0=",
                        "inclusionProof": {
                            "logIndex": "1",
                            "rootHash": "deadbeef" * 8,
                            "treeSize": "5000",
                            "hashes": ["00" * 32, "11" * 32],
                            "checkpoint": {"envelope": "rekor.sigstore.dev - 1\n"},
                        },
                    }
                ],
            },
            "messageSignature": {
                "signature": "FORGEDFORGEDFORGEDFORGEDFORGED==",
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "00" * 32,
                },
            },
            "trust_root": DEFAULT_TRUST_ROOT,
            "oidc_issuer": DEFAULT_OIDC_ISSUER,
            "identity": DEFAULT_IDENTITY,
        }
    )


# ---------------------------------------------------------------------------
# Bug 1: verify_sigstore MUST fail-closed until real Sigstore crypto is wired
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_verifier_sigstore_crypto_flag_is_false() -> None:
    """Until the real Sigstore verification pipeline is wired, the
    feature flag MUST be False so every code path treats the verifier as
    unimplemented. Flipping this to True without an accompanying
    `sigstore.verify` call is a security regression."""
    assert VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED is False, (
        "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED was flipped True without "
        "the corresponding cryptographic verification pipeline; this is "
        "a P0 keystone-invariant violation (CLAUDE.md #2: pass without "
        "evidence is not a pass)."
    )


@pytest.mark.plumbing
def test_verify_sigstore_rejects_forged_bundle() -> None:
    """A structurally-correct but cryptographically-forged Sigstore
    bundle MUST be rejected. Prior to the fail-closed switch, this
    bundle passed because the verifier only inspected JSON keys and
    string equality on `trust_root` / `oidc_issuer` / `identity`."""
    forged = _forged_sigstore_bundle()
    with pytest.raises(BundleSignatureInvalid) as exc_info:
        verify_sigstore(
            forged,
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=DEFAULT_OIDC_ISSUER,
            expected_identity=DEFAULT_IDENTITY,
        )
    # Distinct reason so auditors can tell apart "wrong issuer" from
    # "we are refusing to claim verification at all".
    reason = exc_info.value.details.get("reason", "")
    assert reason == "sigstore_crypto_not_implemented", (
        f"expected reason 'sigstore_crypto_not_implemented', got {reason!r} "
        f"(message={exc_info.value.message!r})"
    )


@pytest.mark.plumbing
def test_verify_sigstore_rejects_empty_bundle() -> None:
    """Even an empty JSON object MUST be rejected with the fail-closed
    reason -- there is no structural shortcut that lets a bundle skip
    cryptographic verification."""
    with pytest.raises(BundleSignatureInvalid) as exc_info:
        verify_sigstore(
            "{}",
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=DEFAULT_OIDC_ISSUER,
            expected_identity=DEFAULT_IDENTITY,
        )
    reason = exc_info.value.details.get("reason", "")
    assert reason == "sigstore_crypto_not_implemented", reason


# ---------------------------------------------------------------------------
# Bug 2: _verify_rekor_inclusion MUST fail-closed until Merkle proof is wired
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_rekor_crypto_flag_is_false() -> None:
    """Until the Merkle inclusion proof is verified against Rekor's
    public key, the flag MUST be False."""
    assert REKOR_CRYPTO_IMPLEMENTED is False, (
        "REKOR_CRYPTO_IMPLEMENTED was flipped True without the "
        "corresponding Merkle inclusion verification pipeline."
    )


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_well_formed_proof() -> None:
    """A bundle with a structurally-well-formed inclusion proof but
    cryptographically unverified hashes MUST be rejected. The previous
    implementation accepted any dict at `tlogEntries[*].inclusionProof`."""
    bundle = _forged_sigstore_bundle()
    ok, reason = _verify_rekor_inclusion(bundle.encode("utf-8"))
    assert ok is False
    assert reason == "rekor_crypto_not_implemented", (
        f"expected reason 'rekor_crypto_not_implemented', got {reason!r}"
    )


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_bad_hashes() -> None:
    """Even an inclusion proof with obviously-bogus hashes (all-zero
    Merkle siblings) MUST be rejected -- the verifier does NOT inspect
    hash contents because it does not perform real verification, so
    every bundle MUST fail-closed."""
    payload = json.loads(_forged_sigstore_bundle())
    payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][
        "hashes"
    ] = ["00" * 32]
    ok, reason = _verify_rekor_inclusion(json.dumps(payload).encode("utf-8"))
    assert ok is False
    assert reason == "rekor_crypto_not_implemented", reason


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_legacy_rekorbundle() -> None:
    """Legacy `rekorBundle.Payload` shape ALSO fails-closed; the
    previous code returned True if the payload key was present."""
    payload = {
        "cert": "fakecert",
        "signature": "fakesig",
        "rekorBundle": {"Payload": {"logIndex": 1, "integratedTime": 1}},
    }
    ok, reason = _verify_rekor_inclusion(json.dumps(payload).encode("utf-8"))
    assert ok is False
    assert reason == "rekor_crypto_not_implemented", reason
