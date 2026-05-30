"""VAL-PARITY-006: Merkle inclusion-proof verification must model RFC 6962
lonely-leaf promotion.

Bug (HIGH/correctness): ``verify_inclusion_proof`` was driven by
``proof_path`` length -- it consumed exactly one proof entry per loop
iteration and advanced ``idx //= 2`` / ``last //= 2`` once per entry. RFC
6962 sec 2.1 promotes a node that has no sibling at a level verbatim with NO
proof entry ("lonely-leaf"). Because the verify loop never modeled that
promotion, VALID inclusion proofs for non-power-of-two trees (e.g.
tree_size=3 leaf_index=2, tree_size=5 leaf_index=4) were REJECTED. The proof
is valid; the verifier mis-rejected it.

Fix: drive the walk by tree GEOMETRY, not proof length. At each level, if the
current node is the lonely promoted node (``idx == last and idx % 2 == 0``)
advance without consuming a proof entry or hashing; otherwise consume one
sibling and hash. Terminate at ``last == 0`` and require the proof iterator be
fully consumed (reject leftover entries).

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
# RED at base c911607: lonely-leaf promotion levels rejected valid proofs.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_lonely_leaf_proof_tree_size_3_index_2_accepts() -> None:
    """tree_size=3, leaf_index=2: the leaf is promoted verbatim at level 0
    (lonely leaf), so the proof has a single sibling entry at level 1. The
    verifier MUST accept this valid proof."""
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=2, claim_digests_hex=leaves)
    assert verify_inclusion_proof(
        leaf_index=2,
        leaf_digest_hex=leaves[2],
        proof_path=proof,
        tree_size=3,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_lonely_leaf_proof_tree_size_5_index_4_accepts() -> None:
    """tree_size=5, leaf_index=4: the leaf is the lonely node at levels 0 and
    1, promoted verbatim, then paired at the top. The verifier MUST accept."""
    leaves = _leaves(5)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=4, claim_digests_hex=leaves)
    assert verify_inclusion_proof(
        leaf_index=4,
        leaf_digest_hex=leaves[4],
        proof_path=proof,
        tree_size=5,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
@pytest.mark.parametrize("tree_size", [3, 5, 6, 7])
def test_every_index_verifies_for_non_power_of_two_trees(tree_size: int) -> None:
    """For each non-power-of-two tree size, a self-built proof for EVERY leaf
    index MUST verify against the computed root. This is the geometry parity
    check between build_inclusion_proof and verify_inclusion_proof."""
    leaves = _leaves(tree_size)
    root = compute_merkle_root(leaves)
    for i in range(tree_size):
        proof = build_inclusion_proof(leaf_index=i, claim_digests_hex=leaves)
        assert verify_inclusion_proof(
            leaf_index=i,
            leaf_digest_hex=leaves[i],
            proof_path=proof,
            tree_size=tree_size,
            claimed_root_hex=root,
        ), f"valid proof rejected: tree_size={tree_size} leaf_index={i}"


# ---------------------------------------------------------------------------
# Do NOT over-accept: tampered proofs and malformed proof lengths must reject.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_tampered_sibling_in_lonely_leaf_proof_rejects() -> None:
    """Flipping a byte of a sibling in a valid lonely-leaf proof MUST reject
    (the fix must not blanket-accept lonely-leaf geometry)."""
    leaves = _leaves(5)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=4, claim_digests_hex=leaves)
    assert proof, "expected a non-empty proof for leaf_index=4"
    # Corrupt the first sibling entry by flipping its leading nibble.
    bad = proof[0]
    flipped = ("0" if bad[0] != "0" else "1") + bad[1:]
    tampered = [flipped, *proof[1:]]
    assert not verify_inclusion_proof(
        leaf_index=4,
        leaf_digest_hex=leaves[4],
        proof_path=tampered,
        tree_size=5,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_extra_trailing_proof_entry_rejected() -> None:
    """A proof carrying MORE entries than the tree geometry consumes MUST be
    rejected (the iterator-fully-consumed check). Otherwise a forger could
    pad a proof with attacker-controlled junk that the verifier ignores."""
    leaves = _leaves(3)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=2, claim_digests_hex=leaves)
    junk = hashlib.sha256(b"junk").hexdigest()
    assert not verify_inclusion_proof(
        leaf_index=2,
        leaf_digest_hex=leaves[2],
        proof_path=[*proof, junk],
        tree_size=3,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_too_few_proof_entries_rejected() -> None:
    """A proof MISSING a required sibling (truncated) MUST be rejected: the
    geometry expects a sibling at a paired level that is not provided."""
    leaves = _leaves(5)
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=0, claim_digests_hex=leaves)
    assert len(proof) >= 2, "expected a multi-entry proof for leaf_index=0"
    truncated = proof[:-1]
    assert not verify_inclusion_proof(
        leaf_index=0,
        leaf_digest_hex=leaves[0],
        proof_path=truncated,
        tree_size=5,
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-006")
def test_power_of_two_trees_still_verify() -> None:
    """Regression guard: power-of-two trees (no lonely-leaf at any index) must
    continue to verify for every leaf after the geometry-driven rewrite."""
    for tree_size in (1, 2, 4, 8):
        leaves = _leaves(tree_size)
        root = compute_merkle_root(leaves)
        for i in range(tree_size):
            proof = build_inclusion_proof(leaf_index=i, claim_digests_hex=leaves)
            assert verify_inclusion_proof(
                leaf_index=i,
                leaf_digest_hex=leaves[i],
                proof_path=proof,
                tree_size=tree_size,
                claimed_root_hex=root,
            ), f"power-of-two proof rejected: tree_size={tree_size} idx={i}"
