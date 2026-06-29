"""P1 cross-runtime parity: verifier JCS encoder MUST reject non-BMP keys.

RFC 8785 section 3.2.3 sorts object keys by UTF-16 code-unit sequence.
For Basic Multilingual Plane (BMP) keys (code points < U+10000), Python's
``str`` codepoint ordering matches UTF-16 code-unit ordering. For
supplementary-plane keys (>= U+10000) the orderings diverge -- the Python
verifier (sorting by codepoint) and the TypeScript verifier (sorting by
UTF-16 code unit) produce DIFFERENT canonical bytes for the same input.
A Python-signed evidence bundle carrying a non-BMP object key would then
verify on Python but be rejected as tampered on TypeScript (or vice
versa), silently breaking cross-runtime signature verification.

Until both encoders implement the full UTF-16-code-unit sort, the
verifier fails-closed: any object key containing a codepoint >= U+10000
raises :class:`JCSEncodeError` whose message carries the wire-stable code
``RELAY-CANON-NON-BMP-KEY``. This mirrors
``relay_contracts.canonical.CanonicalEncodingError`` (Round-3 P1 fix #5)
and the TypeScript verifier sibling test
``test/canonical_bmp_only_keys.test.ts`` (which refuses the SAME input,
giving cross-runtime parity).

CLAUDE.md anchors: keystone invariant 11 (trust anchor / cross-runtime
byte equality), banned pattern #16.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier.canonical import (
    JCSEncodeError,
    jcs_canonicalize,
)

# U+1F600 (GRINNING FACE) is in the supplementary plane (>= U+10000).
# The TypeScript verifier sibling rejects the SAME codepoint, so the two
# per-sibling tests together assert that the identical non-BMP-key input
# is refused by BOTH runtimes (cross-runtime parity).
_SMP_CODEPOINT = 0x1F600


@pytest.mark.plumbing
def test_verifier_canonical_rejects_non_bmp_key() -> None:
    """An object key with a supplementary-plane codepoint raises."""
    bad_key = "a" + chr(_SMP_CODEPOINT)
    with pytest.raises(JCSEncodeError) as excinfo:
        jcs_canonicalize({bad_key: 1})
    assert "RELAY-CANON-NON-BMP-KEY" in str(excinfo.value), excinfo.value


@pytest.mark.plumbing
def test_verifier_canonical_bmp_only_key_works() -> None:
    """BMP-only keys (incl. non-ASCII like U+00E9) still encode."""
    # "caf" + U+00E9 -> "cafe-acute" -- BMP, must still canonicalise.
    bmp_key = "caf" + chr(0x00E9)
    out = jcs_canonicalize({bmp_key: 1})
    assert isinstance(out, bytes)
    assert b"caf" in out  # ASCII prefix intact in the output


@pytest.mark.plumbing
def test_verifier_canonical_rejects_non_bmp_nested_key() -> None:
    """The screen is recursive: nested object keys are also screened."""
    bad_key = chr(_SMP_CODEPOINT) + "nested"
    with pytest.raises(JCSEncodeError):
        jcs_canonicalize({"outer": {bad_key: 1}})


@pytest.mark.plumbing
def test_verifier_canonical_non_bmp_value_in_string_is_allowed() -> None:
    """The screen applies to KEYS only; a non-BMP string VALUE encodes."""
    out = jcs_canonicalize({"emoji": chr(_SMP_CODEPOINT)})
    assert isinstance(out, bytes)
