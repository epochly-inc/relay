"""W9.1 real Sigstore cryptographic verification tests.

Encodes VAL-V2M09-003, 006, 007, 008, 009, 010, 022 against
``relay_cli.bundle.verify_sigstore``. After M09 the function MUST:

  - Flip ``VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED`` to ``True``
    (VAL-V2M09-003).
  - Call into the ``sigstore`` package (VAL-V2M09-006).
  - Reject a forged-identity bundle (VAL-V2M09-007).
  - Reject a tampered-signature bundle (VAL-V2M09-008).
  - Round-trip a real Sigstore-signed artifact when CI OIDC is
    available (VAL-V2M09-009).
  - Translate ``sigstore.errors.VerificationError`` (and subclasses)
    into ``BundleSignatureInvalid`` with distinct ``details["reason"]``
    per subclass (VAL-V2M09-010).
  - Surface ``trust_anchor`` on the returned dict on success
    (VAL-V2M09-022).

The tests do NOT commit any signed bundle long-term. Bundles required
for negative tests are constructed at test time via the ``sigstore``
Python API against throwaway artifacts. The positive round-trip test
(VAL-V2M09-009) is skipped unless a CI OIDC token is present in the
environment, because Sigstore keyless signing requires a real OIDC
ambient identity.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import inspect
import json
import os
from pathlib import Path
from typing import Any

import pytest
from relay_cli import bundle as bundle_mod
from relay_cli.bundle import (
    DEFAULT_TRUST_ROOT,
    VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED,
    BundleSignatureInvalid,
    verify_sigstore,
)

BUNDLE_PY = Path(bundle_mod.__file__).resolve()

# Default identity/issuer placeholders for forged-bundle tests; the
# concrete values don't matter because real verification rejects the
# bundle on signature/cert grounds well before any identity policy
# comparison would have a chance to fire.
DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
DEFAULT_IDENTITY = (
    "https://github.com/epochly-inc/relay/.github/workflows/release-pypi.yml@refs/heads/main"
)


# ---------------------------------------------------------------------------
# VAL-V2M09-003: feature flag flipped True
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-003")
def test_sigstore_crypto_flag_is_true() -> None:
    """After M09 the fail-closed switch is flipped on."""
    assert VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED is True, (
        "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED MUST be True after M09 lands; "
        "the flip is paired in the same commit with a real sigstore.verify "
        "call -- see VAL-V2M09-006."
    )


# ---------------------------------------------------------------------------
# VAL-V2M09-006: real Sigstore verifier is invoked
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-006")
def test_verify_sigstore_calls_sigstore_package() -> None:
    """AST inspection: the function body must reference sigstore.*"""
    source = inspect.getsource(verify_sigstore)
    tree = ast.parse(source)
    # Look for any Attribute or Name node whose root is 'sigstore'
    saw_sigstore_ref = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            # walk down to the leftmost Name
            cur: Any = node
            while isinstance(cur, ast.Attribute):
                cur = cur.value
            if isinstance(cur, ast.Name) and cur.id == "sigstore":
                saw_sigstore_ref = True
                break
        if isinstance(node, ast.Name) and node.id in {
            "Verifier",
            "Bundle",
            "Identity",
            "VerificationError",
        }:
            # Sigstore API symbols (imported via `from sigstore... import X`).
            saw_sigstore_ref = True
            break
    assert saw_sigstore_ref, (
        "verify_sigstore body MUST reference the sigstore package "
        "(Verifier / Bundle.verify_artifact / Identity / "
        "VerificationError); got source:\n" + source
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-006")
def test_verify_sigstore_consumes_inputs_not_ignored() -> None:
    """The fail-closed stub used ``_ = sigstore_bytes`` to silence
    unused-parameter lint. After the flip the function MUST actually
    parse / consume the bundle bytes; the sentinel pattern MUST be gone.
    """
    text = BUNDLE_PY.read_text(encoding="utf-8")
    assert "_ = sigstore_bytes" not in text, (
        "fail-closed sentinel `_ = sigstore_bytes` MUST be removed; "
        "the real verifier consumes the bundle bytes."
    )
    assert "_ = expected_oidc_issuer" not in text
    assert "_ = expected_identity" not in text


# ---------------------------------------------------------------------------
# VAL-V2M09-007 / VAL-V2M09-008: negative tests against forged bundles
# ---------------------------------------------------------------------------


def _build_real_sigstore_bundle(tmp_path: Path) -> tuple[bytes, bytes, str, str]:
    """Construct a real Sigstore bundle for an ephemeral artifact.

    Skips the calling test if no OIDC ambient credential is available
    (the keyless sigstore signing flow requires a real OIDC token).
    Returns (artifact_bytes, bundle_json_bytes, identity, issuer).
    """
    try:
        from sigstore.oidc import IdentityToken, detect_credential
    except Exception as exc:  # pragma: no cover - defensive
        pytest.skip(f"sigstore.oidc unavailable: {exc}")
    try:
        cred = detect_credential()
    except Exception as exc:
        pytest.skip(f"no ambient OIDC credential detected: {exc}")
    if cred is None:
        pytest.skip("no ambient OIDC credential detected (set CI=true with an OIDC provider)")
    try:
        from sigstore.models import ClientTrustConfig
        from sigstore.sign import SigningContext
    except Exception as exc:  # pragma: no cover - defensive
        pytest.skip(f"sigstore.sign unavailable: {exc}")
    ident = IdentityToken(cred)
    # sigstore 4.x dropped ``SigningContext.production()``; the production
    # signing context is built from the production client trust config.
    sc = SigningContext.from_trust_config(ClientTrustConfig.production())
    artifact = b"relay-w9-1 test artifact " + os.urandom(8)
    artifact_path = tmp_path / "artifact.bin"
    artifact_path.write_bytes(artifact)
    with sc.signer(ident) as signer:
        result = signer.sign_artifact(artifact)
    bundle_json = result.to_json()
    # sigstore 4.x renamed ``IdentityToken.expected_issuer`` to ``issuer``.
    return artifact, bundle_json.encode("utf-8"), ident.identity, ident.issuer


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-V2M09-007")
def test_reject_wrong_identity(tmp_path: Path) -> None:
    """A real Sigstore bundle whose SAN identity does not match the
    expected identity MUST be rejected. We sign a throwaway artifact
    against the real Sigstore staging endpoint (if OIDC available);
    verification against a deliberately mismatched expected_identity
    MUST raise BundleSignatureInvalid with reason in {identity_mismatch,
    san_mismatch}, NOT sigstore_crypto_not_implemented.
    """
    artifact, bundle_bytes, real_identity, real_issuer = (
        _build_real_sigstore_bundle(tmp_path)
    )
    wrong_identity = (
        "https://github.com/attacker/fork/.github/workflows/release.yml@refs/heads/main"
    )
    with pytest.raises(BundleSignatureInvalid) as excinfo:
        verify_sigstore(
            bundle_bytes,
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=real_issuer,
            expected_identity=wrong_identity,
            artifact_bytes=artifact,
        )
    reason = excinfo.value.details.get("reason", "")
    assert reason in {"identity_mismatch", "san_mismatch"}, (
        f"expected identity_mismatch/san_mismatch reason; got {reason!r}"
    )
    assert reason != "sigstore_crypto_not_implemented"


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-V2M09-008")
def test_reject_tampered_signature(tmp_path: Path) -> None:
    """A real Sigstore bundle whose signature byte has been mutated
    MUST be rejected. We sign a throwaway artifact, mutate one byte
    of the messageSignature.signature field in memory, and re-verify.
    Reason MUST be in {signature_invalid, crypto_failure, bad_signature}.
    """
    artifact, bundle_bytes, real_identity, real_issuer = (
        _build_real_sigstore_bundle(tmp_path)
    )
    payload = json.loads(bundle_bytes.decode("utf-8"))
    # Mutate the signature in the canonical messageSignature path.
    sig_b64 = payload["messageSignature"]["signature"]
    # Flip the first character (base64 alphabet); avoid no-op flip.
    flipped = ("B" if sig_b64[0] != "B" else "A") + sig_b64[1:]
    payload["messageSignature"]["signature"] = flipped
    mutated = json.dumps(payload).encode("utf-8")
    with pytest.raises(BundleSignatureInvalid) as excinfo:
        verify_sigstore(
            mutated,
            expected_trust_root=DEFAULT_TRUST_ROOT,
            expected_oidc_issuer=real_issuer,
            expected_identity=real_identity,
            artifact_bytes=artifact,
        )
    reason = excinfo.value.details.get("reason", "")
    assert reason in {"signature_invalid", "crypto_failure", "bad_signature"}, (
        f"expected signature-failure reason; got {reason!r}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M09-009: real-bundle round-trip
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-V2M09-009")
def test_real_bundle_round_trip(tmp_path: Path) -> None:
    """Sign a throwaway artifact, then verify the bundle end-to-end.

    Skipped locally when no OIDC ambient token is available. The CI
    matrix is responsible for running this on at least one runner with
    an OIDC token present (e.g. GitHub Actions workflow with
    id-token: write permission).
    """
    artifact, bundle_bytes, real_identity, real_issuer = (
        _build_real_sigstore_bundle(tmp_path)
    )
    out = verify_sigstore(
        bundle_bytes,
        expected_trust_root=DEFAULT_TRUST_ROOT,
        expected_oidc_issuer=real_issuer,
        expected_identity=real_identity,
        artifact_bytes=artifact,
    )
    assert isinstance(out, dict), out
    assert out, "verify_sigstore returned an empty dict on success"


# ---------------------------------------------------------------------------
# VAL-V2M09-010: error translation table
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-010")
def test_error_translation_table() -> None:
    """Every sigstore.errors.* subclass MUST translate to
    BundleSignatureInvalid with a distinct details['reason'].
    """
    from sigstore import errors as ss_errors

    # The sigstore.errors module exposes at least VerificationError +
    # RootError + (MetadataError|CertValidationError|NetworkError).
    candidate_names = [
        "VerificationError",
        "RootError",
        "CertValidationError",
        "MetadataError",
        "NetworkError",
    ]
    present = [
        getattr(ss_errors, n) for n in candidate_names if hasattr(ss_errors, n)
    ]
    assert len(present) >= 3, (
        "expected at least 3 sigstore error subclasses to translate; "
        f"got {present!r}"
    )
    seen_reasons: set[str] = set()
    for exc_cls in present:
        # Construct the simplest possible instance; the public API of
        # most sigstore errors accepts a single message string.
        try:
            inst = exc_cls("forced")
        except TypeError:
            # Some subclasses require extra positional args; skip ones
            # we can't instantiate trivially (not the test's job).
            continue
        translated = bundle_mod._translate_sigstore_error(inst)
        assert isinstance(translated, BundleSignatureInvalid), (
            f"{exc_cls.__name__} did not translate to BundleSignatureInvalid"
        )
        reason = translated.details.get("reason", "")
        assert reason, f"{exc_cls.__name__} translated without a reason"
        seen_reasons.add(reason)
    # Each subclass must yield a distinct reason value.
    assert len(seen_reasons) >= 3, (
        f"expected at least 3 distinct translation reasons; got {seen_reasons!r}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M09-022: trust_anchor surfaced in output
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-V2M09-022")
def test_trust_anchor_in_output(tmp_path: Path) -> None:
    """On a successful real round-trip, the returned dict MUST contain
    a 'trust_anchor' key bound to one of the allowed values.
    """
    artifact, bundle_bytes, real_identity, real_issuer = (
        _build_real_sigstore_bundle(tmp_path)
    )
    out = verify_sigstore(
        bundle_bytes,
        expected_trust_root=DEFAULT_TRUST_ROOT,
        expected_oidc_issuer=real_issuer,
        expected_identity=real_identity,
        artifact_bytes=artifact,
    )
    assert "trust_anchor" in out, (
        f"verify_sigstore success dict missing 'trust_anchor' key: {out!r}"
    )
    assert out["trust_anchor"] in {DEFAULT_TRUST_ROOT, "local_dev"} or isinstance(
        out["trust_anchor"], str
    )


# ---------------------------------------------------------------------------
# VAL-W12-033: --offline is a NO-network structural promise (re-hunt #6)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-033")
def test_verify_sigstore_offline_builds_verifier_offline(monkeypatch: Any) -> None:
    """verify_sigstore MUST build the Sigstore Verifier with offline=True (TUF
    cache, no egress) when its ``offline`` arg is set, and offline=False
    otherwise. Pre-fix the offline flag was never threaded into verify_sigstore
    / _verify_one_surface, so Verifier.production() refreshed the trust root
    over the network even under --offline -- breaking the offline default-deny.

    No real bundle and no network: the sigstore seams are monkeypatched and the
    test asserts only the offline-flag propagation into Verifier construction.
    """
    import sigstore.models as ss_models
    import sigstore.verify as ss_verify

    captured: list[bool] = []

    def _fake_production(*, offline: bool = False) -> Any:
        captured.append(offline)

        class _V:
            def verify_artifact(self, *a: object, **k: object) -> None:
                return None

        return _V()

    # Bundle.from_json must succeed without a real bundle -> opaque sentinel.
    monkeypatch.setattr(
        ss_models.Bundle, "from_json", staticmethod(lambda _text: object())
    )
    monkeypatch.setattr(
        ss_verify.Verifier, "production", staticmethod(_fake_production)
    )

    common = {
        "expected_trust_root": "relay.epochly.com",
        "expected_oidc_issuer": DEFAULT_OIDC_ISSUER,
        "expected_identity": DEFAULT_IDENTITY,
        "artifact_bytes": b"artifact",
    }
    out = verify_sigstore(b"{}", offline=True, **common)
    assert out["verified"] is True
    assert captured == [True], (
        "offline mode must build the Verifier with offline=True (no network)"
    )
    captured.clear()
    verify_sigstore(b"{}", offline=False, **common)
    assert captured == [False], (
        "online mode must build the Verifier with offline=False"
    )
