"""Property-based tests for RFC-6962 Merkle inclusion proofs (ACCEPTANCE GATE
#1, formal-methods). Keystone invariant #16 (Py<->TS parity) demands that the
offline verifier's Merkle primitives in
``packages/verifier/src/relay_verifier/merkle.py`` be correct for ANY tree
size -- including the non-power-of-two sizes (3, 5, 6, 7, ...) that exercise
RFC 6962 sec 2.1 "lonely-leaf" promotion. The example-based corpus
(test_parity_006_merkle_inclusion.py) pins specific cases; these properties
prove the structural invariants over a generated domain:

  1. INCLUSION SOUNDNESS -- for a tree of N leaves (N in [1..33], including
     non-powers-of-2), a self-built proof for EVERY leaf index verifies
     against the computed root.
  2. TAMPER DETECTION -- mutating the leaf digest, the claimed root, or any
     single proof node makes verification FAIL (returns False; the inputs
     stay structurally valid hex so the contract is a False verdict, not a
     raised exception).
  3. ROOT DETERMINISM -- the root for a fixed ordered leaf list is byte-stable
     across recomputation and is a well-formed 64-char lowercase hex digest.

A failing property here is either a real bug in merkle.py (report it, do NOT
weaken the property) or a mis-modeled invariant (fix the strategy). It is
never made green by asserting a falsehood.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from relay_verifier.merkle import (
    build_inclusion_proof,
    compute_merkle_root,
    verify_inclusion_proof,
)

# A leaf claim digest is a 64-char lowercase hex SHA-256 (the API contract in
# merkle._hex_to_bytes). Generate it directly as the hex of 32 random bytes so
# every generated leaf is a structurally valid digest; duplicates are allowed
# (inclusion geometry is index-driven, not content-keyed).
_LEAF = st.binary(min_size=32, max_size=32).map(bytes.hex)


@st.composite
def _tree_and_index(draw: st.DrawFn) -> tuple[list[str], int]:
    """Draw (leaves, leaf_index): N in [1..33] (covers non-powers-of-2 like
    3, 5, 6, 7), then a valid 0-based index into that tree."""
    leaves = draw(st.lists(_LEAF, min_size=1, max_size=33))
    idx = draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    return leaves, idx


def _flip_first_nibble(h: str) -> str:
    """Return ``h`` with its leading hex nibble changed -- a guaranteed-distinct
    but still structurally valid 64-char hex digest."""
    return ("0" if h[0] != "0" else "1") + h[1:]


# ---------------------------------------------------------------------------
# Property 1: INCLUSION SOUNDNESS
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(_tree_and_index())
@settings(max_examples=300, deadline=None)
def test_inclusion_proof_verifies_for_any_tree_size(
    tree_and_index: tuple[list[str], int],
) -> None:
    """For ANY tree of N leaves and ANY leaf index, the self-built inclusion
    proof MUST verify against the computed root. This universally quantifies
    the lonely-leaf parity check that the corpus only spot-checks at 3/5/6/7."""
    leaves, idx = tree_and_index
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=idx, claim_digests_hex=leaves)
    assert verify_inclusion_proof(
        leaf_index=idx,
        leaf_digest_hex=leaves[idx],
        proof_path=proof,
        tree_size=len(leaves),
        claimed_root_hex=root,
    ), f"valid proof rejected: tree_size={len(leaves)} leaf_index={idx}"


# ---------------------------------------------------------------------------
# Property 2: TAMPER DETECTION (leaf / root / proof node)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(_tree_and_index())
@settings(max_examples=300, deadline=None)
def test_tampered_leaf_digest_fails_verification(
    tree_and_index: tuple[list[str], int],
) -> None:
    """Substituting a different leaf digest (one nibble flipped) for the proved
    index MUST make a valid proof+root combination fail. The digest stays valid
    hex, so the contract is a False verdict, not a raised exception."""
    leaves, idx = tree_and_index
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=idx, claim_digests_hex=leaves)
    tampered_leaf = _flip_first_nibble(leaves[idx])
    assume(tampered_leaf != leaves[idx])
    assert not verify_inclusion_proof(
        leaf_index=idx,
        leaf_digest_hex=tampered_leaf,
        proof_path=proof,
        tree_size=len(leaves),
        claimed_root_hex=root,
    )


@pytest.mark.plumbing
@given(_tree_and_index())
@settings(max_examples=300, deadline=None)
def test_tampered_root_fails_verification(
    tree_and_index: tuple[list[str], int],
) -> None:
    """Claiming a different root (one nibble flipped) for an otherwise valid
    leaf+proof MUST fail. The verifier recomputes the true root and compares
    byte-for-byte."""
    leaves, idx = tree_and_index
    root = compute_merkle_root(leaves)
    proof = build_inclusion_proof(leaf_index=idx, claim_digests_hex=leaves)
    tampered_root = _flip_first_nibble(root)
    assume(tampered_root != root)
    assert not verify_inclusion_proof(
        leaf_index=idx,
        leaf_digest_hex=leaves[idx],
        proof_path=proof,
        tree_size=len(leaves),
        claimed_root_hex=tampered_root,
    )


@pytest.mark.plumbing
@given(_tree_and_index(), st.randoms(use_true_random=False))
@settings(max_examples=300, deadline=None)
def test_tampered_proof_node_fails_verification(
    tree_and_index: tuple[list[str], int],
    rng: object,
) -> None:
    """Mutating ANY single sibling node in an otherwise valid proof (one nibble
    flipped) MUST make verification fail. Requires a non-empty proof, which
    holds for every tree of size >= 2 (a singleton tree has an empty proof and
    nothing to tamper)."""
    leaves, idx = tree_and_index
    proof = build_inclusion_proof(leaf_index=idx, claim_digests_hex=leaves)
    assume(len(proof) > 0)
    root = compute_merkle_root(leaves)
    j = rng.randrange(len(proof))  # type: ignore[attr-defined]
    tampered = list(proof)
    tampered[j] = _flip_first_nibble(tampered[j])
    assume(tampered[j] != proof[j])
    assert not verify_inclusion_proof(
        leaf_index=idx,
        leaf_digest_hex=leaves[idx],
        proof_path=tampered,
        tree_size=len(leaves),
        claimed_root_hex=root,
    )


# ---------------------------------------------------------------------------
# Property 3: ROOT DETERMINISM
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(st.lists(_LEAF, min_size=1, max_size=33))
@settings(max_examples=300, deadline=None)
def test_root_is_deterministic_and_well_formed(leaves: list[str]) -> None:
    """The root for a fixed ordered leaf list is byte-stable across
    recomputation (including over an independent copy of the list) and is a
    well-formed 64-char lowercase hex digest."""
    first = compute_merkle_root(leaves)
    second = compute_merkle_root(list(leaves))
    assert first == second
    assert len(first) == 64
    assert first == first.lower()
    # 64 lowercase hex chars decode to exactly 32 bytes (SHA-256 width).
    assert len(bytes.fromhex(first)) == 32
