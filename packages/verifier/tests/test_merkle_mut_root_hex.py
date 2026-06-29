"""Mutation-killing tests for the RFC-6962 Merkle hex-decode + root paths.

Targets residual cosmic-ray survivors in
``packages/verifier/src/relay_verifier/merkle.py`` that the existing
property/corpus suites do not detect:

  ``_hex_to_bytes`` length guard (``len(h) != 64``) and its ValueError
  re-wrap, plus the ``compute_merkle_root`` reduction loop.

These tests drive the mutated lines through the PUBLIC API
(``compute_merkle_root``) and pin the REAL behavior so each one passes now
and FAILS under the corresponding mutation. The source is correct; we only
pin it -- we do not modify it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier.merkle import compute_merkle_root

# A structurally valid 64-char lowercase hex SHA-256 digest (all-'a').
_VALID_LEAF = "a" * 64


# ---------------------------------------------------------------------------
# _hex_to_bytes L56: `len(h) != 64` length guard.
#
# The guard must reject ANY length other than 64 -- not just "> 64" and not
# just "< 64". A valid-hex string of even length != 64 decodes cleanly via
# bytes.fromhex, so a half-open guard would silently accept it and produce a
# (wrong-width) root instead of raising.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_compute_root_rejects_too_short_leaf_hex() -> None:
    """A 62-char valid-hex leaf (too short) MUST raise ValueError.

    Kills L56 NotEq_Gt (`len(h) > 64`): 62 > 64 is False, so the mutant skips
    the raise; bytes.fromhex("a"*62) succeeds (31 bytes) and a root is
    returned. Real code raises because 62 != 64.
    """
    too_short = "a" * 62  # valid hex, even length, decodes to 31 bytes
    with pytest.raises(ValueError):
        compute_merkle_root([too_short])


@pytest.mark.plumbing
def test_compute_root_rejects_too_long_leaf_hex() -> None:
    """A 66-char valid-hex leaf (too long) MUST raise ValueError.

    Kills L56 NotEq_Lt (`len(h) < 64`): 66 < 64 is False, so the mutant skips
    the raise; bytes.fromhex("a"*66) succeeds (33 bytes) and a root is
    returned. Real code raises because 66 != 64.
    """
    too_long = "a" * 66  # valid hex, even length, decodes to 33 bytes
    with pytest.raises(ValueError):
        compute_merkle_root([too_long])


# ---------------------------------------------------------------------------
# _hex_to_bytes L60: `except ValueError as exc:` re-wraps the fromhex error.
#
# A 64-char NON-hex string passes the length guard, then bytes.fromhex raises
# ValueError. Real code catches it and re-raises a ValueError whose message
# begins "not a valid hex digest: ...". The ExceptionReplacer mutant catches a
# sentinel class that does NOT match ValueError, so the RAW fromhex ValueError
# propagates with a different message. Both raise ValueError, so only the
# message distinguishes them.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_compute_root_non_hex_leaf_reraises_wrapped_message() -> None:
    """A 64-char non-hex leaf MUST raise the re-wrapped 'not a valid hex
    digest' ValueError.

    Kills L60 ExceptionReplacer: the mutant fails to catch the fromhex
    ValueError, so the propagated message is the raw fromhex text
    ('non-hexadecimal number found ...') which does NOT match.
    """
    non_hex = "z" * 64  # length 64 passes the guard; 'z' is not a hex digit
    with pytest.raises(ValueError, match="not a valid hex digest"):
        compute_merkle_root([non_hex])


# ---------------------------------------------------------------------------
# Sanity: the valid path used as the baseline for the negative tests above
# still produces a well-formed root (guards that the negatives fail for the
# RIGHT reason -- the hex defect -- not because the API is otherwise broken).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_compute_root_valid_single_leaf_well_formed() -> None:
    """A single valid 64-char leaf yields a well-formed 64-char lowercase hex
    root with no exception (baseline for the negative cases)."""
    root = compute_merkle_root([_VALID_LEAF])
    assert len(root) == 64
    assert root == root.lower()
    assert len(bytes.fromhex(root)) == 32
