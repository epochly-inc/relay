"""Merkle tree binding for evidence claims (W10.4 VAL-W10-024 + VAL-W10-030).

Per spec section K line 4390 the evidence-bundle protocol "binds claims
into a Merkle tree" so a verifier can detect any tampering of either a
single claim digest OR the ordering of claims in the bundle. The same
primitives also drive transparency-log inclusion-proof verification
(VAL-W10-030); the inclusion proof is a Merkle path against a
transparency-log tree root produced by the witness service.

Tree shape (RFC 6962 sec 2):

  - Leaves are the lowercase-hex SHA-256 digests of each claim's JCS
    canonical bytes (see :func:`relay_verifier.canonical.bundle_digest`).
  - Internal nodes hash the concatenation of their two children. The
    domain-separation prefix follows RFC 6962:
        leaf hash:     SHA-256(0x00 || data)
        internal hash: SHA-256(0x01 || left || right)
    where ``data`` for a leaf is the binary digest of the claim (32 bytes,
    NOT the hex string) and ``left``/``right`` are 32-byte node digests.
  - Odd-cardinality levels promote the last unpaired node verbatim
    (Merkle "lonely-leaf" convention; RFC 6962 sec 2.1).

The verifier consumes:

  :func:`compute_merkle_root` over an ordered list of leaf claim digests
  (lowercase hex) -> returns lowercase hex root.

  :func:`verify_inclusion_proof` over (leaf_index, leaf_digest_hex,
  proof_path: list[hex_str], tree_size, claimed_root_hex) -> returns
  True iff the recomputation matches the claimed root.

Both helpers are pure-functional, deterministic, and have no I/O. They
operate exclusively on the inputs supplied so transparency-log inclusion
verification can run offline (VAL-W10-030 explicitly requires no network
call to the log server).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from typing import Final

# RFC 6962 domain-separation prefixes for leaf and internal node hashing.
# Distinct prefixes prevent second-preimage attacks where an internal hash
# could be reinterpreted as a leaf or vice versa.
_LEAF_PREFIX: Final[bytes] = b"\x00"
_INTERNAL_PREFIX: Final[bytes] = b"\x01"


def _hex_to_bytes(h: str) -> bytes:
    """Decode a 64-char lowercase hex digest to 32 bytes."""
    if not isinstance(h, str):
        raise TypeError(f"expected hex string, got {type(h).__name__}")
    if len(h) != 64:
        raise ValueError(f"expected 64-char hex digest, got len={len(h)}")
    try:
        return bytes.fromhex(h)
    except ValueError as exc:
        raise ValueError(f"not a valid hex digest: {exc}") from exc


def _hash_leaf(claim_digest_hex: str) -> bytes:
    """Hash a single leaf per RFC 6962 sec 2.1."""
    raw = _hex_to_bytes(claim_digest_hex)
    return hashlib.sha256(_LEAF_PREFIX + raw).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    """Hash an internal node per RFC 6962 sec 2.1."""
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def compute_merkle_root(claim_digests_hex: list[str]) -> str:
    """Compute the Merkle root over an ordered list of claim digests.

    Returns the lowercase-hex digest of the root node. For an empty list
    returns the SHA-256 of the empty string (RFC 6962 convention for the
    empty-tree root) so consumers do not need to special-case empty
    bundles separately.

    Raises :class:`ValueError` if any leaf is not a valid 64-char hex
    digest.
    """
    if not claim_digests_hex:
        return hashlib.sha256(b"").hexdigest()

    # Hash leaves first, then iteratively pair-wise hash up the tree.
    level: list[bytes] = [_hash_leaf(h) for h in claim_digests_hex]
    while len(level) > 1:
        next_level: list[bytes] = []
        # Pair-wise hash. Odd count: promote the last node verbatim.
        for i in range(0, len(level) - 1, 2):
            next_level.append(_hash_internal(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])
        level = next_level
    return level[0].hex()


def verify_inclusion_proof(
    *,
    leaf_index: int,
    leaf_digest_hex: str,
    proof_path: list[str],
    tree_size: int,
    claimed_root_hex: str,
) -> bool:
    """Verify a Merkle inclusion proof against a claimed tree root.

    Per RFC 6962 sec 2.1.1, the proof_path is the ordered list of sibling
    node hashes (lowercase hex) needed to recompute the root from the
    leaf. ``leaf_index`` selects the leaf position (0-indexed). The
    function returns True iff the recomputed root equals
    ``claimed_root_hex`` byte-for-byte.

    Raises :class:`ValueError` for malformed inputs (negative index,
    leaf_index >= tree_size, malformed hex). Returns False (no exception)
    on a digest-mismatch verdict so consumers can treat the verdict as
    a structured outcome rather than a control-flow exception.

    Per VAL-W10-030 this function performs zero I/O; it is suitable for
    offline transparency-log verification.
    """
    if leaf_index < 0:
        raise ValueError(f"leaf_index must be >= 0, got {leaf_index}")
    if tree_size <= 0:
        raise ValueError(f"tree_size must be > 0, got {tree_size}")
    if leaf_index >= tree_size:
        raise ValueError(
            f"leaf_index {leaf_index} >= tree_size {tree_size}"
        )

    node = _hash_leaf(leaf_digest_hex)
    claimed_root = _hex_to_bytes(claimed_root_hex)

    # Walk up the tree, consuming one sibling per level until we have
    # consumed the entire proof_path or reduced the subtree size to 1.
    last_index = tree_size - 1
    idx = leaf_index
    last = last_index
    proof_iter = iter(proof_path)
    for sibling_hex in proof_iter:
        # If we are the right child of a pair (idx odd), the sibling is
        # on our left. If we are the left child, the sibling is on our
        # right -- unless we are the lonely-leaf at this level
        # (idx == last AND last is even), in which case there is no
        # sibling and we promote ourselves; but the proof should NOT
        # include a path entry in that case. The producer of the proof
        # is responsible for omitting the sibling when promotion occurs.
        sibling = _hex_to_bytes(sibling_hex)
        node = (
            _hash_internal(sibling, node)
            if idx % 2 == 1
            else _hash_internal(node, sibling)
        )
        idx //= 2
        last //= 2

    # If recomputation consumed the entire path AND we have reduced to
    # the root level, compare. Otherwise the proof was malformed (too
    # many or too few path entries for the declared tree_size).
    if idx != 0 or last != 0:
        return False
    return node == claimed_root


def build_inclusion_proof(
    *,
    leaf_index: int,
    claim_digests_hex: list[str],
) -> list[str]:
    """Build the inclusion proof for ``claim_digests_hex[leaf_index]``.

    Test-only helper: production transparency-log inclusion proofs come
    from the witness service. Used here so the W10.4 plumbing tests can
    construct proofs without a live log dependency. The proof shape is
    compatible with :func:`verify_inclusion_proof`.

    Returns a list of lowercase-hex sibling digests in bottom-up order.
    """
    n = len(claim_digests_hex)
    if leaf_index < 0 or leaf_index >= n:
        raise ValueError(
            f"leaf_index {leaf_index} out of range for tree_size {n}"
        )

    level: list[bytes] = [_hash_leaf(h) for h in claim_digests_hex]
    proof: list[str] = []
    idx = leaf_index
    last = n - 1
    while last > 0:
        # Sibling exists iff we are paired (not the lonely promoted leaf).
        if idx % 2 == 1:
            proof.append(level[idx - 1].hex())
        elif idx + 1 <= last:
            proof.append(level[idx + 1].hex())
        # else: lonely promotion, no sibling to add
        # Build next level.
        next_level: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_hash_internal(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])
        level = next_level
        idx //= 2
        last //= 2
    return proof


__all__ = [
    "build_inclusion_proof",
    "compute_merkle_root",
    "verify_inclusion_proof",
]
