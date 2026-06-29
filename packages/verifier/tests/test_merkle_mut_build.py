"""Mutation-killing tests for ``build_inclusion_proof`` bounds checking
(cosmic-ray survivors on
``packages/verifier/src/relay_verifier/merkle.py`` L195).

Each test pins the REAL behavior of :func:`build_inclusion_proof` on a
specific input for which a reported mutation diverges observably (a missing
or extra ``ValueError``, or admitting an out-of-range index). The source is
correct; these tests pin it so the bounds-guard mutants die.

The index-arithmetic mutants on L204/L206/L207/L208/L209/L214/L215 are
genuinely EQUIVALENT under the function's reachability constraints (parity
of ``idx``/``i``, non-negativity of ``last``, and ``x % 2 in {0, 1}``); see
the justification recorded by the harness. No test can observe a difference
for those, so none is added.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib

import pytest
from relay_verifier.merkle import (
    build_inclusion_proof,
    compute_merkle_root,
    verify_inclusion_proof,
)


def _leaves(n: int) -> list[str]:
    """Deterministic distinct claim digests for a tree of size ``n``."""
    return [hashlib.sha256(f"leaf-{i}".encode()).hexdigest() for i in range(n)]


# ---------------------------------------------------------------------------
# L195: ``if leaf_index < 0 or leaf_index >= n:`` -- lower bound (NumberReplacer)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_leaf_index_zero_builds_valid_proof() -> None:
    """leaf_index=0 is IN range and MUST build a proof that verifies.

    Kills L195 NumberReplacer ``< 0`` -> ``< 1``: that mutant would reject
    the valid index 0 with a spurious ValueError. The real code returns a
    proof that verifies against the root.
    """
    leaves = _leaves(4)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    assert verify_inclusion_proof(
        leaf_index=0,
        leaf_digest_hex=leaves[0],
        proof_path=proof,
        tree_size=4,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
def test_negative_leaf_index_raises() -> None:
    """leaf_index=-1 is out of range and MUST raise ValueError.

    Kills L195 NumberReplacer ``< 0`` -> ``< -1`` (the surviving lower-bound
    mutation: ``-1 < -1`` is False, so the mutant would NOT reject index -1)
    and L195 ReplaceOrWithAnd (``or`` -> ``and`` disables the whole guard,
    since ``(-1 < 0) and (-1 >= n)`` is False).
    """
    leaves = _leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_proof(leaf_index=-1, claim_digests_hex=leaves)


# ---------------------------------------------------------------------------
# L195: ``leaf_index >= n`` -- upper bound (GtE_Gt / GtE_Eq / GtE_Is / Or->And)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_leaf_index_equal_tree_size_raises() -> None:
    """leaf_index == n is out of range (valid indices are [0, n)) and MUST
    raise ValueError.

    Kills L195 GtE_Gt ``>= n`` -> ``> n`` (``4 > 4`` is False, mutant would
    admit leaf_index == n and silently return a wrong/empty proof) and
    L195 ReplaceOrWithAnd (``or`` -> ``and`` disables the guard).
    """
    leaves = _leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_proof(leaf_index=4, claim_digests_hex=leaves)


@pytest.mark.plumbing
def test_leaf_index_above_tree_size_raises() -> None:
    """leaf_index = n + 1 is out of range and MUST raise ValueError.

    Kills L195 GtE_Eq ``>= n`` -> ``== n`` (``5 == 4`` is False, mutant
    would admit any leaf_index strictly greater than n).
    """
    leaves = _leaves(4)
    with pytest.raises(ValueError):
        build_inclusion_proof(leaf_index=5, claim_digests_hex=leaves)


@pytest.mark.plumbing
def test_leaf_index_equal_large_tree_size_raises_identity_boundary() -> None:
    """For a tree larger than the CPython small-int cache (n > 256),
    leaf_index == n MUST still raise ValueError.

    Kills L195 GtE_Is ``>= n`` -> ``is n``: ``leaf_index`` (the literal int
    passed in) and ``n`` (a fresh int produced by ``len()``) are equal but
    DISTINCT objects when their value exceeds 256, so the mutant's identity
    check is False and it would fail to reject the out-of-range index. The
    real ``>=`` comparison raises.
    """
    n = 300
    leaves = _leaves(n)
    with pytest.raises(ValueError):
        build_inclusion_proof(leaf_index=n, claim_digests_hex=leaves)
