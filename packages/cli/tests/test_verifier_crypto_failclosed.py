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
@pytest.mark.fulfills("VAL-V2M09-003")
def test_verifier_sigstore_crypto_flag_is_true() -> None:
    """M09 / VAL-V2M09-003: after the real Sigstore verification pipeline
    is wired, the feature flag MUST be True. Flipping this back to False
    without removing the corresponding `sigstore.verify` call is a
    keystone-invariant regression -- the polarity-inverted tripwire."""
    assert VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED is True, (
        "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED was flipped False after the "
        "real Sigstore verifier landed; this is a P0 keystone-invariant "
        "regression (CLAUDE.md #2: pass without evidence is not a pass)."
    )


@pytest.mark.plumbing
def test_verify_sigstore_rejects_forged_bundle() -> None:
    """A structurally-correct but cryptographically-forged Sigstore
    bundle MUST be rejected. With real verification wired (M09), the
    rejection reason is now ``bundle_parse_failed`` (the forged JSON
    does not deserialize via ``sigstore.models.Bundle.from_json``)
    instead of the prior fail-closed ``sigstore_crypto_not_implemented``;
    either way the bundle is rejected -- which is the invariant."""
    forged = _forged_sigstore_bundle()
    with pytest.raises(BundleSignatureInvalid) as exc_info:
        verify_sigstore(
            forged,
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=DEFAULT_OIDC_ISSUER,
            expected_identity=DEFAULT_IDENTITY,
            artifact_bytes=b"forged-artifact-bytes",
        )
    reason = exc_info.value.details.get("reason", "")
    # Real verifier rejects via bundle parse (the forged JSON is not a
    # valid Sigstore protobuf bundle) OR cert-chain failure -- both are
    # distinct from any successful-pass path. The invariant is: rejection.
    assert reason in {
        "bundle_parse_failed",
        "cert_validation_failed",
        "verification_failed",
        "identity_mismatch",
        "signature_invalid",
        "trust_metadata_invalid",
        "trust_root_invalid",
        "trust_root_unreachable",
    }, (
        f"forged bundle MUST be rejected with a structured reason, got "
        f"{reason!r} (message={exc_info.value.message!r})"
    )


@pytest.mark.plumbing
def test_verify_sigstore_rejects_empty_bundle() -> None:
    """Even an empty JSON object MUST be rejected with a structured
    reason -- there is no structural shortcut that lets a bundle skip
    cryptographic verification. With real verification wired the
    rejection now happens at the bundle-parse step."""
    with pytest.raises(BundleSignatureInvalid) as exc_info:
        verify_sigstore(
            "{}",
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=DEFAULT_OIDC_ISSUER,
            expected_identity=DEFAULT_IDENTITY,
            artifact_bytes=b"empty-bundle-artifact",
        )
    reason = exc_info.value.details.get("reason", "")
    assert reason in {
        "bundle_parse_failed",
        "verification_failed",
    }, f"empty bundle rejection reason {reason!r} unexpected"


# ---------------------------------------------------------------------------
# Bug 2: _verify_rekor_inclusion MUST fail-closed until Merkle proof is wired
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-004")
def test_rekor_crypto_flag_is_true() -> None:
    """M09-w9.3 / VAL-V2M09-004: after the real Merkle inclusion proof
    + checkpoint signature + SET signature verifiers are wired against
    Rekor's public key, the feature flag MUST be True. Flipping this
    back to False without removing the corresponding
    ``verify_merkle_inclusion`` / ``verify_checkpoint`` /
    ``TransparencyLogEntry._verify_set`` calls is a P0 keystone-
    invariant regression -- the polarity-inverted tripwire."""
    assert REKOR_CRYPTO_IMPLEMENTED is True, (
        "REKOR_CRYPTO_IMPLEMENTED was flipped False after the real "
        "Rekor verification pipeline landed; this is a P0 keystone-"
        "invariant regression (CLAUDE.md #2: pass without evidence "
        "is not a pass)."
    )


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_well_formed_proof() -> None:
    """A structurally-well-formed but cryptographically-forged inclusion
    proof MUST be rejected. With real verification wired (M09-w9.3) the
    rejection happens at one of: bundle parse (the forged JSON is not a
    valid Sigstore protobuf bundle), Rekor REST shape parse failure
    (forged body is not a valid hashedrekord/dsse), or Merkle
    inclusion verification (the proof's leaf does not chain to the
    claimed root). Either way the invariant is: rejection with a
    structured non-success reason."""
    bundle = _forged_sigstore_bundle()
    ok, reason = _verify_rekor_inclusion(bundle.encode("utf-8"))
    assert ok is False
    assert reason in {
        "transparency log entry missing",
        "transparency_log_entry_unparseable",
        "transparency_log_entry_bundle_invalid",
        "rekor_inclusion_proof_invalid",
        "rekor_checkpoint_signature_invalid",
        "rekor_set_signature_invalid",
        "rekor_trust_root_unavailable",
    }, (
        f"forged bundle MUST be rejected with a structured reason; "
        f"got {reason!r}"
    )
    # Historical fail-closed sentinel MUST be gone.
    assert reason != "rekor_crypto_not_implemented"


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_bad_hashes() -> None:
    """An inclusion proof with obviously-bogus hashes (all-zero Merkle
    siblings) MUST be rejected -- the real verifier inspects hash
    contents and chains the leaf hash through the proof's hashes up
    to the claimed root, which cannot match when the hashes are
    forged."""
    payload = json.loads(_forged_sigstore_bundle())
    payload["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][
        "hashes"
    ] = ["00" * 32]
    ok, reason = _verify_rekor_inclusion(json.dumps(payload).encode("utf-8"))
    assert ok is False
    assert reason != "rekor_crypto_not_implemented"
    # The structured reason is one of the post-flip rejection paths
    # (Bundle parse / Rekor REST decode / proof / checkpoint / SET).
    assert reason in {
        "transparency log entry missing",
        "transparency_log_entry_unparseable",
        "transparency_log_entry_bundle_invalid",
        "rekor_inclusion_proof_invalid",
        "rekor_checkpoint_signature_invalid",
        "rekor_set_signature_invalid",
        "rekor_trust_root_unavailable",
    }, reason


@pytest.mark.plumbing
def test_verify_rekor_inclusion_rejects_legacy_rekorbundle() -> None:
    """Legacy ``rekorBundle.Payload`` shape (cosign v1.x) is NOT a
    Sigstore Bundle and is NOT a Rekor REST single-entry response, so
    it MUST be rejected as a missing / invalid transparency-log entry.
    The previous structural-only verifier accepted it; the real
    verifier refuses because there is no inclusion proof or checkpoint
    to verify."""
    payload = {
        "cert": "fakecert",
        "signature": "fakesig",
        "rekorBundle": {"Payload": {"logIndex": 1, "integratedTime": 1}},
    }
    ok, reason = _verify_rekor_inclusion(json.dumps(payload).encode("utf-8"))
    assert ok is False
    assert reason != "rekor_crypto_not_implemented"
    assert reason in {
        "transparency log entry missing",
        "transparency_log_entry_unparseable",
        "transparency_log_entry_bundle_invalid",
    }, reason
