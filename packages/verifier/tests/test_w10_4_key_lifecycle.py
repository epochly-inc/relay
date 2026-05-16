"""W10.4 signing-key lifecycle tests.

Covers:
  * VAL-W10-031 (rotation grace + not_before skew boundaries)
  * VAL-W10-032 (expired key)
  * VAL-W10-033 (revoked key, before vs after)
  * VAL-W10-034 (auditor clock skew tolerance +/-300s)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import _shift_iso, build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    RELAY_EVID_041,
    RELAY_EVID_042,
    ValidateBundleOptions,
    validate_bundle,
)


def _aware_utc(iso_z: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(iso_z[:-1] + "+00:00")


# Shared xfail reason for tests that depend on `validate_bundle`
# returning overall="pass" on the canonical happy-path bundle, which
# requires `validate_tsa_token` to report outcome="ok". That path is
# fail-closed until TSA_CRYPTO_IMPLEMENTED is True.
_TSA_CRYPTO_XFAIL_REASON = (
    "validate_tsa_token is fail-closed until ASN.1 RFC 3161 cryptographic "
    "signature verification is wired; the canonical happy-path bundle now "
    "yields overall='fail' on the TSA check. See "
    "packages/verifier/tests/test_tsa_crypto_failclosed.py (P1 verifier "
    "crypto gap)."
)


# ---------------------------------------------------------------------------
# VAL-W10-031: rotation grace + not_before +/-300s boundaries
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-031")
@pytest.mark.xfail(strict=True, reason=_TSA_CRYPTO_XFAIL_REASON)
def test_rotation_grace_old_key_within_window_verifies() -> None:
    """A bundle signed with a key whose window is current verifies."""
    built = build_bundle(
        key_not_before="2026-01-01T00:00:00Z",
        key_not_after="2028-01-01T00:00:00Z",
        decided_at="2026-05-15T12:00:00Z",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            auditor_now=_aware_utc("2026-05-15T12:00:00Z"),
        ),
    )
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-031")
@pytest.mark.xfail(strict=True, reason=_TSA_CRYPTO_XFAIL_REASON)
def test_rotation_future_not_before_at_plus_200s_accepted() -> None:
    """key.not_before = auditor_now + 200s -> ACCEPT (within +/-300s tolerance)."""
    auditor_now = "2026-05-15T12:00:00Z"
    nb = _shift_iso(auditor_now, 200)
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=auditor_now,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-031")
@pytest.mark.xfail(strict=True, reason=_TSA_CRYPTO_XFAIL_REASON)
def test_rotation_future_not_before_at_plus_300s_accepted_boundary() -> None:
    """key.not_before = auditor_now + 300s (exact) -> ACCEPT."""
    auditor_now = "2026-05-15T12:00:00Z"
    nb = _shift_iso(auditor_now, 300)
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=auditor_now,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-031")
def test_rotation_future_not_before_at_plus_301s_rejected_boundary() -> None:
    """key.not_before = auditor_now + 301s -> REJECT (just past tolerance)."""
    auditor_now = "2026-05-15T12:00:00Z"
    nb = _shift_iso(auditor_now, 301)
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=auditor_now,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "fail"
    assert any(
        e["reason"] == "signer_key_premature"
        and e.get("code") == RELAY_EVID_041
        for e in output["errors"]
    ), output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-031")
def test_rotation_future_not_before_at_plus_400s_rejected() -> None:
    """key.not_before = auditor_now + 400s -> REJECT (well past tolerance)."""
    auditor_now = "2026-05-15T12:00:00Z"
    nb = _shift_iso(auditor_now, 400)
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=auditor_now,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "fail"


# ---------------------------------------------------------------------------
# VAL-W10-032: expired key -> RELAY-EVID-041
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-032")
def test_expired_key_rejected_with_evid_041_signer_key_expired() -> None:
    """key.not_after well in the past -> REJECT with structured error
    naming the key, the expiration timestamp, and RELAY-EVID-041."""
    auditor_now = "2026-05-15T12:00:00Z"
    built = build_bundle(
        key_not_before="2024-01-01T00:00:00Z",
        key_not_after="2024-12-31T23:59:59Z",
        decided_at="2024-06-01T00:00:00Z",
        signed_at="2024-06-01T00:00:00Z",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "fail"
    assert any(
        e["reason"] == "signer_key_expired"
        and e.get("code") == RELAY_EVID_041
        for e in output["errors"]
    ), output["errors"]


# ---------------------------------------------------------------------------
# VAL-W10-033: revoked key, before vs after revocation
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-033")
@pytest.mark.xfail(strict=True, reason=_TSA_CRYPTO_XFAIL_REASON)
def test_revoked_key_signed_before_revocation_warns_but_passes() -> None:
    """Bundle signed BEFORE revoked_at -> signer_key_revoked=True + WARN,
    overall=pass (auditor decides)."""
    built = build_bundle(
        decided_at="2026-05-15T12:00:00Z",
        signed_at="2026-05-15T12:00:00Z",
        key_revoked_at="2026-06-15T00:00:00Z",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            auditor_now=_aware_utc("2026-07-01T00:00:00Z"),
        ),
    )
    assert output["signer_key_revoked"] is True
    assert output["signer_key_revoked_at"] == "2026-06-15T00:00:00Z"
    assert any(
        w["reason"] == "signer_key_revoked_after_sign_time"
        for w in output["warnings"]
    ), output["warnings"]
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-033")
def test_revoked_key_signed_after_revocation_rejected_with_evid_042() -> None:
    """Bundle signed AFTER revoked_at -> REJECT with RELAY-EVID-042."""
    built = build_bundle(
        decided_at="2026-07-01T00:00:00Z",
        signed_at="2026-07-01T00:00:00Z",
        key_revoked_at="2026-06-15T00:00:00Z",
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            auditor_now=_aware_utc("2026-07-15T00:00:00Z"),
        ),
    )
    assert output["overall"] == "fail"
    assert any(
        e["reason"] == "signer_key_revoked_at_or_before_sign_time"
        and e.get("code") == RELAY_EVID_042
        for e in output["errors"]
    ), output["errors"]


# ---------------------------------------------------------------------------
# VAL-W10-034: auditor clock skew +/-300s (200s OK, 400s reject)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-034")
@pytest.mark.xfail(strict=True, reason=_TSA_CRYPTO_XFAIL_REASON)
def test_auditor_clock_200s_before_not_before_accepted() -> None:
    """auditor_now = key.not_before - 200s -> ACCEPT."""
    nb = "2026-05-15T12:00:00Z"
    auditor_now = _shift_iso(nb, -200)
    # Decided_at must be on or after not_before for the bundle to be
    # internally consistent; we set it to nb itself.
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=nb,
        signed_at=nb,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-034")
def test_auditor_clock_400s_before_not_before_rejected() -> None:
    """auditor_now = key.not_before - 400s -> REJECT."""
    nb = "2026-05-15T12:00:00Z"
    auditor_now = _shift_iso(nb, -400)
    built = build_bundle(
        key_not_before=nb,
        key_not_after="2028-01-01T00:00:00Z",
        decided_at=nb,
        signed_at=nb,
    )
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(auditor_now=_aware_utc(auditor_now)),
    )
    assert output["overall"] == "fail"
