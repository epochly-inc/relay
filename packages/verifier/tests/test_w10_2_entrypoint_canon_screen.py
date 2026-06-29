"""F3 coverage: every public verifier signature entrypoint that canonicalises
attacker-controllable signed-payload data fails closed IDENTICALLY across
Python and TypeScript for BOTH cross-runtime canonicalisation hazards --
a supplementary-plane (non-BMP, >= U+10000) object KEY, and an out-of-safe-range
integer VALUE (abs > 2**53 - 1).

Before F3 the non-BMP + unsafe-integer screens were wired into
validate_bundle only; verify_detached_claim_signature and
verify_multi_signatures canonicalised their claim/payload with no screen, so a
hazardous input either raised uncaught (non-BMP key) or produced Python-exact
vs TypeScript-rounded canonical bytes (unsafe integer) -- a cross-runtime
verify split (keystone invariant #11/#16). F3 routes every entrypoint through
the shared relay_verifier.canonical.screen_noncanonicalizable so they all
return the SAME structured fail-closed verdict.

The cross-runtime byte-identical proof lives in the TypeScript parity file
test/parity_016_entrypoint_canon_screen.test.ts (drives the REAL Python and
TypeScript implementations over identical inputs). This file asserts the
Python-side fail-closed verdict directly.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier import (
    verify_detached_claim_signature,
    verify_multi_signatures,
)
from relay_verifier.canonical import (
    CANONICAL_NON_BMP_KEY_CODE,
    CANONICAL_UNSAFE_INTEGER_CODE,
)

# U+1F600 (GRINNING FACE) is supplementary-plane (>= U+10000).
_SMP_CODEPOINT = 0x1F600
# 2**53 + 1: the classic value a float64 host rounds (-> 2**53) but a Python
# host keeps exact; > MAX_SAFE_INTEGER so it is refused.
_UNSAFE_INT = 9007199254740993

_DUMMY_PROTECTED_B64U = "eyJhbGciOiJFZERTQSIsImtpZCI6ImsifQ"  # {"alg":"EdDSA","kid":"k"}
_DUMMY_SIG_B64U = "AA"
_EMPTY_JWKS: dict = {"keys": []}
_DUMMY_SIGS = [{"alg": "EdDSA", "kid": "k", "signature_b64u": "AA"}]


# ---------------------------------------------------------------------------
# verify_detached_claim_signature
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_verify_detached_rejects_non_bmp_key_claim() -> None:
    """A claim with a non-BMP object key fails closed (ok=False) with the
    RELAY-CANON-NON-BMP-KEY code -- it does NOT raise."""
    claim = {"a" + chr(_SMP_CODEPOINT): 1}
    check = verify_detached_claim_signature(
        protected_b64u=_DUMMY_PROTECTED_B64U,
        signature_b64u=_DUMMY_SIG_B64U,
        claim=claim,
        jwks=_EMPTY_JWKS,
    )
    assert check.ok is False, check
    assert check.code == CANONICAL_NON_BMP_KEY_CODE, check


@pytest.mark.plumbing
def test_verify_detached_rejects_unsafe_integer_claim() -> None:
    """A claim with an out-of-safe-range integer value fails closed with the
    RELAY-CANON-UNSAFE-INTEGER code."""
    claim = {"count": _UNSAFE_INT}
    check = verify_detached_claim_signature(
        protected_b64u=_DUMMY_PROTECTED_B64U,
        signature_b64u=_DUMMY_SIG_B64U,
        claim=claim,
        jwks=_EMPTY_JWKS,
    )
    assert check.ok is False, check
    assert check.code == CANONICAL_UNSAFE_INTEGER_CODE, check


@pytest.mark.plumbing
def test_verify_detached_clean_claim_not_canon_rejected() -> None:
    """A canonicalisable claim (BMP keys, safe ints) is NOT screened: it flows
    to signature verification and fails for a NON-canon reason (guards against
    over-rejection)."""
    claim = {"caf" + chr(0x00E9): 1, "count": 9007199254740991}  # BMP key + MAX_SAFE
    check = verify_detached_claim_signature(
        protected_b64u=_DUMMY_PROTECTED_B64U,
        signature_b64u=_DUMMY_SIG_B64U,
        claim=claim,
        jwks=_EMPTY_JWKS,
    )
    assert check.ok is False, check
    assert check.code not in (
        CANONICAL_NON_BMP_KEY_CODE,
        CANONICAL_UNSAFE_INTEGER_CODE,
    ), check


# ---------------------------------------------------------------------------
# verify_multi_signatures
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_verify_multi_rejects_non_bmp_key_payload() -> None:
    """A multi-signature payload with a non-BMP object key fails closed:
    ok=False, aggregate=all_invalid, every per-signature check carries the
    RELAY-CANON-NON-BMP-KEY code -- it does NOT raise."""
    payload = {"a" + chr(_SMP_CODEPOINT): 1}
    result = verify_multi_signatures(
        payload=payload,
        signatures=_DUMMY_SIGS,
        jwks=_EMPTY_JWKS,
    )
    assert result.ok is False, result
    assert result.aggregate == "all_invalid", result
    assert len(result.signatures_checked) == len(_DUMMY_SIGS), result
    assert all(
        c.code == CANONICAL_NON_BMP_KEY_CODE for c in result.signatures_checked
    ), result


@pytest.mark.plumbing
def test_verify_multi_rejects_unsafe_integer_payload() -> None:
    """A multi-signature payload with an out-of-safe-range integer fails closed
    with the RELAY-CANON-UNSAFE-INTEGER code on every per-signature check."""
    payload = {"count": _UNSAFE_INT}
    result = verify_multi_signatures(
        payload=payload,
        signatures=_DUMMY_SIGS,
        jwks=_EMPTY_JWKS,
    )
    assert result.ok is False, result
    assert result.aggregate == "all_invalid", result
    assert len(result.signatures_checked) == len(_DUMMY_SIGS), result
    assert all(
        c.code == CANONICAL_UNSAFE_INTEGER_CODE for c in result.signatures_checked
    ), result


@pytest.mark.plumbing
def test_verify_multi_clean_payload_not_canon_rejected() -> None:
    """A canonicalisable payload is NOT screened (guards against
    over-rejection): the per-signature checks fail for non-canon reasons."""
    payload = {"caf" + chr(0x00E9): 1, "count": 9007199254740991}
    result = verify_multi_signatures(
        payload=payload,
        signatures=_DUMMY_SIGS,
        jwks=_EMPTY_JWKS,
    )
    assert result.ok is False, result
    assert all(
        c.code not in (CANONICAL_NON_BMP_KEY_CODE, CANONICAL_UNSAFE_INTEGER_CODE)
        for c in result.signatures_checked
    ), result
