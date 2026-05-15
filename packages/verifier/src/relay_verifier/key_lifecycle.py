"""Signing-key lifecycle checks for the W10.4 bundle validator.

Per spec sections L.1 (line 4452 not_before/not_after) and L.4 (lines
4469-4472 revocation) every JWK in the trust anchor MAY carry the
following lifecycle annotations:

    {
      "kid":  "<key id>",
      "kty":  "OKP" | "EC" | "RSA",
      ...
      "not_before": "2026-01-01T00:00:00Z",   # ISO-8601 UTC
      "not_after":  "2027-01-01T00:00:00Z",
      "revoked_at": "2026-06-15T12:00:00Z",   # optional
    }

The verifier resolves a bundle's signature kid to the JWK and applies:

  * VAL-W10-031: rotation grace -- both NEW and OLD keys verify within
    their windows. A future-dated key with `not_before` more than
    +/-300 s beyond the auditor's clock is rejected.
  * VAL-W10-032: expired key -- `now > not_after + 300 s` -> rejected
    with `RELAY-EVID-041` ("SIGNER_KEY_EXPIRED").
  * VAL-W10-033: revoked key -- bundle signed BEFORE `revoked_at`
    verifies with `signer_key_revoked: true` (WARN, exit 0); bundle
    signed AFTER `revoked_at` is rejected with `RELAY-EVID-042`.
  * VAL-W10-034: auditor clock skew tolerance +/-300 s applied to BOTH
    boundaries.

The +/-300 s constant is shared with the TSA module
(:data:`relay_verifier.tsa.CLOCK_SKEW_TOLERANCE_SECONDS`); single source
of truth.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Final

from .tsa import CLOCK_SKEW_TOLERANCE_SECONDS, _parse_iso_z

RELAY_EVID_041: Final[str] = "RELAY-EVID-041"
"""Signer key expired: now > not_after + 300 s tolerance (VAL-W10-032)."""

RELAY_EVID_042: Final[str] = "RELAY-EVID-042"
"""Signer key revoked: bundle signed AFTER revoked_at (VAL-W10-033)."""


# -----------------------------------------------------------------------------
# Result type
# -----------------------------------------------------------------------------


@dataclass
class KeyLifecycleResult:
    """Verdict for a single signing-key lifecycle check.

    `outcome`:
      * "ok"      -- key is within window and not revoked, OR signed
                     before revocation (in the latter case
                     `signer_key_revoked=True` is set).
      * "expired" -- now > not_after + tolerance (VAL-W10-032).
      * "revoked" -- signed_at > revoked_at (VAL-W10-033 reject path).
      * "premature" -- now < not_before - tolerance (key issued in the
                     future beyond the auditor clock-skew tolerance).
      * "missing_window" -- the JWK does not carry not_before/not_after;
                     verifier accepts (matching the W10.1 default JWKS
                     behavior) but surfaces the missing-window state
                     for telemetry.
    `reason` carries the human-readable detail; "" on ok.
    `code` carries the wire code on the reject paths; "" otherwise.
    `signer_key_revoked` mirrors the verifier output field
        (True iff `revoked_at` is set on the JWK, regardless of whether
        the bundle was signed before or after it).
    `signer_key_revoked_at` is the JWK's revoked_at value (or "" when
        not set); also mirrored to the verifier output.
    """

    outcome: str = "ok"
    reason: str = ""
    code: str = ""
    signer_key_revoked: bool = False
    signer_key_revoked_at: str = ""


# -----------------------------------------------------------------------------
# Lifecycle check
# -----------------------------------------------------------------------------


def check_signing_key_lifecycle(
    *,
    jwk: dict[str, Any],
    bundle_signed_at: str,
    auditor_now: _dt.datetime | None = None,
    tolerance_seconds: int = CLOCK_SKEW_TOLERANCE_SECONDS,
) -> KeyLifecycleResult:
    """Apply VAL-W10-031..034 lifecycle checks to a JWK.

    Inputs:
      * `jwk` -- the resolved JWK dict (the key the bundle was signed
        with).
      * `bundle_signed_at` -- the bundle's `decided_at` / `signed_at`
        timestamp (RFC 3339 Z).
      * `auditor_now` -- optional override for the current wall-clock
        time. Defaults to ``datetime.now(UTC)``. The
        :func:`relay_verifier.bundle_validator.validate_bundle` caller
        passes a fixed clock during tests so the +/-300 s boundary
        cases are deterministic.
      * `tolerance_seconds` -- defaults to 300 (the L.5 single-source
        bound); callers SHOULD NOT override this in production.

    Returns a :class:`KeyLifecycleResult`. The function does not raise;
    every reject path is encoded in `outcome`/`code` so the caller can
    aggregate verdicts.
    """
    if auditor_now is None:
        auditor_now = _dt.datetime.now(tz=_dt.UTC)

    result = KeyLifecycleResult()

    # Parse signed_at first; it is required for the revocation comparison
    # AND defends a malformed bundle from silently passing.
    try:
        signed_at = _parse_iso_z(bundle_signed_at)
    except ValueError as exc:
        result.outcome = "expired"  # treat unparsable timestamp as fatal
        result.reason = f"bundle signed_at unparsable: {exc}"
        result.code = RELAY_EVID_041
        return result

    # Revocation surface (whether bundle was signed before or after).
    revoked_at_str = jwk.get("revoked_at")
    if isinstance(revoked_at_str, str) and revoked_at_str:
        result.signer_key_revoked = True
        result.signer_key_revoked_at = revoked_at_str
        try:
            revoked_at = _parse_iso_z(revoked_at_str)
        except ValueError as exc:
            result.outcome = "revoked"
            result.reason = f"jwk.revoked_at unparsable: {exc}"
            result.code = RELAY_EVID_042
            return result
        if signed_at > revoked_at:
            result.outcome = "revoked"
            result.reason = (
                f"bundle signed at {bundle_signed_at} AFTER key revoked at "
                f"{revoked_at_str}"
            )
            result.code = RELAY_EVID_042
            return result
        # signed_at <= revoked_at: surfaced as WARN by the caller; not
        # rejected here.

    # not_before / not_after window check against auditor clock.
    not_before_str = jwk.get("not_before")
    not_after_str = jwk.get("not_after")

    if not_before_str is None and not_after_str is None:
        result.outcome = "missing_window"
        result.reason = (
            "JWK does not declare not_before/not_after; verifier accepts "
            "but surfaces the missing-window state"
        )
        return result

    if isinstance(not_before_str, str) and not_before_str:
        try:
            not_before = _parse_iso_z(not_before_str)
        except ValueError as exc:
            result.outcome = "premature"
            result.reason = f"jwk.not_before unparsable: {exc}"
            result.code = RELAY_EVID_041
            return result
        # Auditor clock vs not_before, with +/- tolerance.
        skew = (not_before - auditor_now).total_seconds()
        if skew > tolerance_seconds:
            result.outcome = "premature"
            result.reason = (
                f"key not_before {not_before_str} is {int(skew)}s in the "
                f"future, exceeding +/-{tolerance_seconds}s tolerance"
            )
            result.code = RELAY_EVID_041
            return result

    if isinstance(not_after_str, str) and not_after_str:
        try:
            not_after = _parse_iso_z(not_after_str)
        except ValueError as exc:
            result.outcome = "expired"
            result.reason = f"jwk.not_after unparsable: {exc}"
            result.code = RELAY_EVID_041
            return result
        # Auditor clock vs not_after, with +/- tolerance.
        skew = (auditor_now - not_after).total_seconds()
        if skew > tolerance_seconds:
            result.outcome = "expired"
            result.reason = (
                f"key not_after {not_after_str} is {int(skew)}s in the "
                f"past, exceeding +/-{tolerance_seconds}s tolerance"
            )
            result.code = RELAY_EVID_041
            return result

    return result


__all__ = [
    "RELAY_EVID_041",
    "RELAY_EVID_042",
    "KeyLifecycleResult",
    "check_signing_key_lifecycle",
]
