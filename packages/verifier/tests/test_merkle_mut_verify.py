"""Mutation-killing tests for ``verify_inclusion_proof`` input guards and the
geometry-driven walk in ``relay_verifier.merkle`` (RFC 6962 sec 2.1.1).

These tests pin the EXACT observable behavior of the verifier on boundary
inputs that the existing property corpus
(``test_merkle_property.py``) and example corpus
(``test_parity_006_merkle_inclusion.py``) do not exercise. Each test is
written to FAIL under a specific cosmic-ray mutation while PASSING against the
real (correct) source. No source change is made; the source is correct and we
pin it.

Survivors addressed (line numbers refer to merkle.py):

  L126 NumberReplacer  -- ``leaf_index < 0`` boundary (negative index).
  L128 NumberReplacer  -- ``tree_size <= 0`` literal-offset (tree_size == 0).
  L128 LtE_Eq          -- ``tree_size <= 0`` -> ``== 0`` (negative tree_size).
  L128 LtE_Lt          -- ``tree_size <= 0`` -> ``< 0``  (tree_size == 0).
  L130 GtE_Eq          -- ``leaf_index >= tree_size`` -> ``==`` (idx > size).
  L130 GtE_Gt          -- ``leaf_index >= tree_size`` -> ``>``  (idx == size).
  L130 GtE_Is          -- ``leaf_index >= tree_size`` -> ``is`` (idx > size).
  L153 Eq_Is           -- ``idx == last`` -> ``idx is last`` (non-cached ints).

The remaining listed survivors (L152 Gt_NotEq, L153 Eq_GtE, L153 Eq_LtE,
L166 Eq_GtE) are provably EQUIVALENT and intentionally have NO test here --
see the agent report for the per-survivor justification.

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
# L126 NumberReplacer: ``if leaf_index < 0``  (the ``0`` literal).
#
# cosmic-ray offsets the literal by +/-1. ``< 1`` over-raises for the valid
# index 0; ``< -1`` under-raises for the invalid index -1. We pin BOTH ends:
#   * leaf_index == 0 is VALID -> returns True  (kills ``< 1``).
#   * leaf_index == -1 is INVALID -> raises ValueError (kills ``< -1``).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_leaf_index_zero_is_valid_returns_true() -> None:
    """leaf_index 0 is a legal position; the verifier must NOT reject it.

    Kills the ``leaf_index < 1`` offset, which would raise on index 0.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    assert (
        verify_inclusion_proof(
            leaf_index=0,
            leaf_digest_hex=leaves[0],
            proof_path=proof,
            tree_size=3,
            claimed_root_hex=root,
        )
        is True
    )


@pytest.mark.plumbing
def test_negative_leaf_index_raises_value_error() -> None:
    """A negative leaf_index is malformed and MUST raise ValueError.

    Kills the ``leaf_index < -1`` offset: under that mutation -1 passes the
    guard, the function proceeds with a negative index and returns a (False)
    verdict instead of raising. We feed a fully valid tree/proof/root so the
    only divergence is the guard itself.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    with pytest.raises(ValueError):
        verify_inclusion_proof(
            leaf_index=-1,
            leaf_digest_hex=leaves[0],
            proof_path=proof,
            tree_size=3,
            claimed_root_hex=root,
        )


# ---------------------------------------------------------------------------
# L128: ``if tree_size <= 0``  raises ``tree_size must be > 0, got ...``.
#
# For any tree_size <= 0 with a non-negative leaf_index, L130 will ALSO raise
# (leaf_index >= tree_size is always true), so a bare ``pytest.raises`` cannot
# distinguish the mutants -- we must assert WHICH guard raised via its message.
# The discriminating substring "tree_size must be" appears only in L128's
# message; L130's message is "leaf_index N >= tree_size M".
#
#   * tree_size == 0 -> real raises at L128. Kills NumberReplacer (``<= -1``)
#     and LtE_Lt (``< 0``): both bypass L128 at 0, leaving L130 to raise the
#     WRONG message.
#   * tree_size == -1 -> real raises at L128. Kills LtE_Eq (``== 0``): bypasses
#     L128 for the negative value, leaving L130 to raise the wrong message.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_tree_size_zero_raises_at_tree_size_guard() -> None:
    """tree_size 0 must raise the L128 ``tree_size must be > 0`` error.

    Kills L128 NumberReplacer (``<= -1``) and L128 LtE_Lt (``< 0``): both let
    tree_size 0 through, so the mutant raises L130's "leaf_index ..." message
    instead, failing the message match.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    with pytest.raises(ValueError, match="tree_size must be"):
        verify_inclusion_proof(
            leaf_index=0,
            leaf_digest_hex=leaves[0],
            proof_path=[],
            tree_size=0,
            claimed_root_hex=root,
        )


@pytest.mark.plumbing
def test_negative_tree_size_raises_at_tree_size_guard() -> None:
    """tree_size -1 must raise the L128 ``tree_size must be > 0`` error.

    Kills L128 LtE_Eq (``tree_size == 0``): a negative tree_size bypasses the
    mutated equality check, so the mutant raises L130's "leaf_index ..."
    message instead, failing the message match.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    with pytest.raises(ValueError, match="tree_size must be"):
        verify_inclusion_proof(
            leaf_index=0,
            leaf_digest_hex=leaves[0],
            proof_path=[],
            tree_size=-1,
            claimed_root_hex=root,
        )


# ---------------------------------------------------------------------------
# L130: ``if leaf_index >= tree_size``  raises (index out of range).
#
#   * leaf_index == tree_size (3 == 3) -> real raises. Kills GtE_Gt (``>``),
#     which is False at the boundary and lets an out-of-range index through.
#   * leaf_index >  tree_size (4 vs 3) -> real raises. Kills GtE_Eq (``==``,
#     False for 4 vs 3) and GtE_Is (``4 is 3`` is False): both bypass the
#     guard and return a (False) verdict instead of raising.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_leaf_index_equal_to_tree_size_raises() -> None:
    """leaf_index == tree_size is one past the last valid index and MUST raise.

    Kills L130 GtE_Gt (``leaf_index > tree_size``): the strict ``>`` is False
    at the boundary, so the mutant proceeds and returns a verdict.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    with pytest.raises(ValueError):
        verify_inclusion_proof(
            leaf_index=3,
            leaf_digest_hex=leaves[0],
            proof_path=proof,
            tree_size=3,
            claimed_root_hex=root,
        )


@pytest.mark.plumbing
def test_leaf_index_greater_than_tree_size_raises() -> None:
    """leaf_index strictly greater than tree_size MUST raise.

    Kills L130 GtE_Eq (``==``) and GtE_Is (``is``): for 4 vs 3 both replacement
    operators are False, so the mutant bypasses the guard and returns a verdict
    instead of raising.
    """
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    with pytest.raises(ValueError):
        verify_inclusion_proof(
            leaf_index=4,
            leaf_digest_hex=leaves[0],
            proof_path=proof,
            tree_size=3,
            claimed_root_hex=root,
        )


# ---------------------------------------------------------------------------
# L153: ``if idx == last and idx % 2 == 0`` -- the lonely-leaf detector.
#
# Eq_Is mutates the first comparison to ``idx is last``. For the small trees
# the existing corpus uses (sizes <= 33), idx/last are cached ints (-5..256),
# so ``is`` coincides with ``==`` and the mutant survives. We force a tree whose
# rightmost-at-level-0 index is EVEN and GREATER THAN 256, so ``idx`` (the
# passed leaf_index object) and ``last`` (the computed ``tree_size - 1`` object)
# are equal in value but DISTINCT objects -> ``idx is last`` is False.
#
# tree_size=259 has level-0 indices 0..258 (odd count): index 258 is the lonely
# promoted node (258 is even). Under the real ``==`` the leaf is promoted with
# no sibling at level 0 and the valid proof verifies. Under ``is`` the mutant
# treats it as a paired node, consumes a phantom sibling, and the verdict flips
# to False.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_lonely_last_leaf_large_tree_verifies() -> None:
    """A valid proof for the lonely last leaf of a 259-leaf tree must verify.

    Kills L153 Eq_Is (``idx == last`` -> ``idx is last``): leaf_index 258 and
    the computed tree_size-1 (258) are equal but non-identical ints (> 256), so
    the identity-mutant misclassifies the lonely node and rejects a valid proof.
    """
    tree_size = 259
    leaf_index = 258  # even, rightmost at level 0 -> lonely promotion
    leaves = _leaves(tree_size)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(
        leaf_index=leaf_index, claim_digests_hex=leaves
    )
    assert (
        verify_inclusion_proof(
            leaf_index=leaf_index,
            leaf_digest_hex=leaves[leaf_index],
            proof_path=proof,
            tree_size=tree_size,
            claimed_root_hex=root,
        )
        is True
    )
