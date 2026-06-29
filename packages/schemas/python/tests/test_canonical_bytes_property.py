"""Property-based tests for the RFC-8785 canonical encoder (ACCEPTANCE GATE #1,
formal-methods). Hypothesis-generated JSON values exercise the invariants that
underpin keystone #16 (Py<->TS byte parity) and #10 (canonical envelopes):

  * determinism -- the same value always yields the same bytes;
  * re-encode idempotence -- parsing the canonical bytes and re-encoding yields
    identical bytes (the canonical form is a fixed point);
  * key-order independence -- a dict's construction order never affects the
    output (RFC 8785 sorts keys by UTF-16 code unit);
  * fail-closed -- integers outside the JS safe-integer range are rejected
    (so a value that cannot round-trip byte-identically to TS never silently
    serializes).

These are the formal counterpart to the example-based byte-parity corpus
(test_canonical_bytes_parity.py): the corpus proves specific Py==TS bytes; these
properties prove the encoder's structural invariants over a generated domain.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from relay_schemas.envelopes import canonical_bytes

# JS Number.MAX_SAFE_INTEGER; canonical_bytes rejects ints with abs value above.
_SAFE_INT = 2**53 - 1

# JSON-safe text: exclude lone surrogates (category Cs), which are not valid in
# UTF-8 / JSON and are a separate fail-closed concern.
_text = st.text(st.characters(blacklist_categories=("Cs",)), max_size=20)

# Accepted-float domain: finite, and within the safe-integer magnitude so an
# integer-VALUED float (e.g. 2.0) is never above the safe range -- floats with
# |x| >= 2**53 are all integral and are REJECTED fail-closed (tested separately).
_accepted_float = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=-(2**53 - 1),
    max_value=2**53 - 1,
)

# Recursive JSON value: scalars at the leaves, lists / str-keyed dicts as nodes.
_json_value = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-_SAFE_INT, max_value=_SAFE_INT)
    | _accepted_float
    | _text,
    lambda children: st.lists(children, max_size=6)
    | st.dictionaries(_text, children, max_size=6),
    max_leaves=25,
)


@pytest.mark.plumbing
@given(_json_value)
@settings(max_examples=300, deadline=None)
def test_canonical_bytes_is_deterministic(value: object) -> None:
    assert canonical_bytes(value) == canonical_bytes(value)


@pytest.mark.plumbing
@given(_json_value)
@settings(max_examples=300, deadline=None)
def test_canonical_bytes_reencode_is_idempotent(value: object) -> None:
    """Parsing the canonical bytes and re-encoding yields identical bytes -- the
    canonical form is a fixed point of (encode . parse)."""
    once = canonical_bytes(value)
    twice = canonical_bytes(json.loads(once.decode("utf-8")))
    assert once == twice


@pytest.mark.plumbing
@given(
    st.dictionaries(
        _text,
        st.integers(min_value=-_SAFE_INT, max_value=_SAFE_INT),
        min_size=2,
        max_size=8,
    )
)
@settings(max_examples=200, deadline=None)
def test_canonical_bytes_key_order_independent(d: dict[str, int]) -> None:
    """RFC 8785 sorts object keys by UTF-16 code unit, so the construction order
    of a dict must never change the bytes."""
    reordered = dict(reversed(list(d.items())))
    assert canonical_bytes(d) == canonical_bytes(reordered)


@pytest.mark.plumbing
@given(st.integers(min_value=_SAFE_INT + 1, max_value=2**70))
@settings(max_examples=100, deadline=None)
def test_canonical_bytes_rejects_unsafe_positive_integers(n: int) -> None:
    """Integers above the JS safe range cannot round-trip byte-identically to TS
    and MUST be rejected fail-closed (not silently truncated)."""
    with pytest.raises((ValueError, OverflowError)):
        canonical_bytes(n)


@pytest.mark.plumbing
@given(st.integers(min_value=-(2**70), max_value=-_SAFE_INT - 1))
@settings(max_examples=100, deadline=None)
def test_canonical_bytes_rejects_unsafe_negative_integers(n: int) -> None:
    with pytest.raises((ValueError, OverflowError)):
        canonical_bytes(n)


@pytest.mark.plumbing
def test_canonical_bytes_rejects_integer_valued_floats_above_safe_range() -> None:
    """An integer-VALUED float at/above 2**53 (e.g. 9007199254740992.0, 1e16,
    1e21) cannot round-trip byte-identically to TS and MUST be rejected -- the
    boundary the property tests pin (canonical_bytes accepts 2**53-1 as a float
    but rejects 2**53)."""
    assert canonical_bytes(float(2**53 - 1)) == b"9007199254740991"
    for bad in (float(2**53), 1e16, 1e21, -1e16):
        with pytest.raises(ValueError):
            canonical_bytes(bad)
