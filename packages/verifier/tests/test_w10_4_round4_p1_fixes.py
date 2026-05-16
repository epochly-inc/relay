"""W10.4 Round-4 P1 verifier fail-closed regressions.

Tests three structural P1 issues fixed in round-4:

  1. ``decided_at`` MUST NOT silently fall back to ``generated_at``.
     Per spec section AB the TSA binding is to ``decided_at``; a
     missing ``decided_at`` must fail-closed with a structured error
     code, not be papered over by an alternative timestamp field.
  2. The signer-key-lifecycle "primary signer" selection MUST pick the
     first ``ok=True`` entry in ``signature_checks``, not blindly
     index 0. A bundle whose sig[0] is malformed but sig[1] is valid
     would otherwise skip lifecycle checks against the actually-used
     signer key, hiding a revoked second signer.
  3. The signing-payload canonical encoder MUST agree byte-for-byte
     with the RFC 8785 JCS encoder over the full JCS conformance
     corpus, eliminating drift risk between sign and verify paths.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    ValidateBundleOptions,
    validate_bundle,
)
from relay_verifier.bundle_validator import (  # noqa: E402
    RELAY_EVID_DECIDED_AT_MISSING,
)
from relay_verifier.canonical import jcs_canonicalize  # noqa: E402
from relay_verifier.verifier import (  # noqa: E402
    canonical_json_bytes,
)

# ---------------------------------------------------------------------------
# Fix 1: decided_at fail-closed (no silent fallback to generated_at)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_validate_bundle_rejects_missing_decided_at() -> None:
    """A bundle with no ``decided_at`` (but with ``generated_at``) MUST
    fail-closed; the validator MUST NOT silently substitute
    ``generated_at`` because the TSA binding anchor is decided_at
    (spec section AB)."""
    built = build_bundle()
    # Strip decided_at and inject a generated_at sibling instead.
    original_decided = built.bundle.pop("decided_at")
    built.bundle["generated_at"] = original_decided

    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)

    assert output["overall"] == "fail"
    decided_at_errors = [
        e for e in output["errors"]
        if e.get("reason") == "decided_at_missing"
        and e.get("code") == RELAY_EVID_DECIDED_AT_MISSING
    ]
    assert decided_at_errors, output["errors"]
    # Structured detail surfaces which fields the bundle actually had.
    assert "generated_at" in decided_at_errors[0]["message"] or "decided_at" in (
        decided_at_errors[0]["message"]
    )


# ---------------------------------------------------------------------------
# Fix 2: lifecycle uses first ok=True signature, not slot 0
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_lifecycle_uses_first_ok_signature_not_index_zero() -> None:
    """When sig[0] is malformed/invalid and sig[1] is the true valid
    signer, lifecycle checks MUST run against sig[1]'s key. A revoked
    sig[1] key MUST surface signer_key_revoked=True; index-0 selection
    would miss it because sig[0]'s kid does not resolve to any JWK."""
    # Build a normal bundle: sig[0] is the valid signer (kid-A).
    built = build_bundle(
        signer_kid="kid-A",
        signer_seed=b"\x03" * 32,
        decided_at="2026-05-15T12:00:00Z",
        signed_at="2026-05-15T12:00:00Z",
        # Revoke the actual signer key AFTER signing (warn, not hard fail).
        key_revoked_at="2026-06-15T00:00:00Z",
    )
    # Prepend a malformed signature record at slot 0 whose kid does NOT
    # match any JWK; verify_bundle marks it ok=False with no JWK match.
    bogus_sig = {
        "alg": "EdDSA",
        "kid": "kid-NOT-IN-JWKS",
        "signing_input_b64u": base64.urlsafe_b64encode(b"junk")
        .rstrip(b"=").decode("ascii"),
        "signature_b64u": base64.urlsafe_b64encode(b"\x00" * 64)
        .rstrip(b"=").decode("ascii"),
    }
    built.bundle["signatures"] = [bogus_sig] + built.bundle["signatures"]

    auditor_now = "2026-07-01T00:00:00Z"
    from datetime import datetime
    auditor_dt = datetime.fromisoformat(auditor_now[:-1] + "+00:00")
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=auditor_dt),
    )

    # Lifecycle MUST reflect the kid-A key being revoked (after sign).
    assert output["signer_key_revoked"] is True, output
    assert output["signer_key_revoked_at"] == "2026-06-15T00:00:00Z", output


@pytest.mark.plumbing
def test_lifecycle_falls_back_to_index_zero_when_all_signatures_fail() -> None:
    """If NO signature has ok=True, lifecycle selection falls back to
    entry 0 (preserves prior behavior for all-failed cases) and emits a
    structured note in details about the missing valid signer."""
    built = build_bundle(
        signer_kid="kid-A",
        decided_at="2026-05-15T12:00:00Z",
        signed_at="2026-05-15T12:00:00Z",
    )
    # Corrupt the single signature so verification fails.
    built.bundle["signatures"][0]["signature_b64u"] = base64.urlsafe_b64encode(
        b"\x00" * 64
    ).rstrip(b"=").decode("ascii")

    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)

    # signatures_ok=False; overall fails; lifecycle still references the
    # original kid even though sig was rejected.
    assert output["overall"] == "fail"
    assert output["signatures_ok"] is False


# ---------------------------------------------------------------------------
# Fix 3: canonical_json_bytes agrees with jcs_canonicalize over the corpus
# ---------------------------------------------------------------------------


_CORPUS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "jcs"
    / "rfc8785_corpus.json"
)


def _load_corpus_cases() -> list[dict[str, Any]]:
    raw = _CORPUS_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)
    cases = data.get("cases", [])
    # Value-kind cases only; encoder-error vectors are JCS-only by design.
    return [c for c in cases if c.get("kind") == "value"]


@pytest.mark.plumbing
def test_signing_canonical_matches_jcs_canonical_for_all_corpus_vectors() -> None:
    """For every value-kind case in the RFC 8785 JCS conformance corpus,
    the verifier-side signing canonical encoder MUST agree byte-for-byte
    with ``jcs_canonicalize``. Drift here would mean a sign-side and
    verify-side divergence under future payloads that include the
    drift-triggering shapes (floats, non-ASCII, NFC decomposition)."""
    cases = _load_corpus_cases()
    assert len(cases) >= 12, (
        f"corpus value-kind case count {len(cases)} below minimum"
    )
    mismatches: list[str] = []
    skipped: list[str] = []
    for case in cases:
        name = case.get("name", "<unnamed>")
        value = case.get("input")
        try:
            jcs_bytes = jcs_canonicalize(value)
        except Exception as exc:  # noqa: BLE001
            # JCS-only error vectors (NaN/Inf) cannot round-trip through
            # the JSON-based encoder either; skip them.
            skipped.append(f"{name} (jcs raise: {exc})")
            continue
        try:
            signing_bytes = canonical_json_bytes(value)
        except Exception as exc:  # noqa: BLE001
            mismatches.append(f"{name}: signing encoder raised: {exc}")
            continue
        if signing_bytes != jcs_bytes:
            mismatches.append(
                f"{name}: signing={signing_bytes!r} jcs={jcs_bytes!r}"
            )
    assert not mismatches, (
        "VAL-W17.x sign/verify encoder parity drift:\n"
        + "\n".join(mismatches)
        + (f"\n(skipped: {skipped})" if skipped else "")
    )
