"""Round-3 P1 fix #5: JCS encoder MUST reject non-BMP object keys.

RFC 8785 section 3.2.3 sorts object keys by UTF-16 code-unit sequence.
For Basic Multilingual Plane (BMP) keys (code points < U+10000), Python's
``str`` codepoint ordering matches UTF-16 code-unit ordering. For
supplementary-plane keys (>= U+10000), the orderings diverge -- a Python
encoder sorting by codepoint and a JS encoder sorting by code unit
produce DIFFERENT canonical bytes for the same input, which silently
breaks cross-runtime signature verification.

Until the spec/encoders implement the full UTF-16-code-unit sort
algorithm in both runtimes, we fail-closed: any object key containing a
codepoint >= U+10000 raises ``CanonicalEncodingError`` (code
``RELAY-CANON-NON-BMP-KEY``).

CLAUDE.md anchors: keystone invariant 11 (trust anchor / cross-runtime
byte equality), banned pattern #16 (deterministic UDF / encoder).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_contracts.canonical import (
    CanonicalEncodingError,
    jcs_canonicalize,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-005")
def test_canonical_rejects_non_bmp_key() -> None:
    """An object key containing a supplementary-plane codepoint raises.

    The codepoint U+1F600 (GRINNING FACE) is in the supplementary plane.
    Per Fix 5, encoding ``{"a<U+1F600>": 1}`` MUST raise
    ``CanonicalEncodingError`` carrying ``code='RELAY-CANON-NON-BMP-KEY'``.

    V3 audit-resolution VAL-V3M5-005: this is the canonical assertion that
    Python JCS rejects non-BMP object keys at the JCS encoder entry.
    """
    bad_key = "a" + chr(0x1F600)
    with pytest.raises(CanonicalEncodingError) as excinfo:
        jcs_canonicalize({bad_key: 1})
    assert excinfo.value.code == "RELAY-CANON-NON-BMP-KEY", excinfo.value


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-005")
def test_canonical_bmp_only_key_works() -> None:
    """BMP-only keys (incl. non-ASCII like 'cafe-e-acute') still encode.

    Specifically, U+00E9 (LATIN SMALL LETTER E WITH ACUTE) is in the
    BMP (< U+10000); ``"cafe-e-acute"`` is fully ASCII; both must
    canonicalise without raising.
    """
    # "cafe" + U+00E9 -> "café" -- BMP, must work.
    bmp_key = "caf" + chr(0x00E9)
    out = jcs_canonicalize({bmp_key: 1})
    assert isinstance(out, bytes)
    assert b"caf" in out  # the ASCII prefix is intact in the output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-005")
def test_canonical_rejects_non_bmp_nested_key() -> None:
    """The check is recursive: nested object keys are also screened.

    Encoding ``{"outer": {"<U+1F600>nested": 1}}`` MUST raise.
    """
    bad_key = chr(0x1F600) + "nested"
    with pytest.raises(CanonicalEncodingError):
        jcs_canonicalize({"outer": {bad_key: 1}})


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-005")
def test_canonical_non_bmp_value_in_string_is_allowed() -> None:
    """The screen applies to KEYS only; non-BMP values inside a string
    value are still encoded literally per RFC 8785 string-escaping rules.

    Only object KEYS are sorted; values are not subject to the UTF-16-vs-
    codepoint divergence. ``{"emoji": "<U+1F600>"}`` MUST encode
    successfully.
    """
    out = jcs_canonicalize({"emoji": chr(0x1F600)})
    assert isinstance(out, bytes)
