"""Transparency log inclusion-proof verification (W10.4 VAL-W10-028..030).

Per spec section AB line 5418 ("bundles can be checked for inclusion
offline using a witness signature") evidence bundles MAY carry an
inclusion proof against a transparency log that the issuer has
witnessed. The verifier checks the inclusion offline -- no network call
to the log server is required (VAL-W10-030).

Per VAL-W10-028 a bundle WITHOUT an inclusion proof verifies with
``log_inclusion: "absent"`` and a structured WARN; exit code remains 0.
Per VAL-W10-029 a proof whose witness signature is invalid produces
``log_inclusion: "witness_mismatch"`` and a WARN; exit code remains 0
unless the verifier is invoked with ``--strict-log``.

Witness signature shape (per contract Gap #6 default proposal: Sigstore
Rekor convention -- ed25519 detached signature over the tree_root):

    {
      "log_id": "rekor.epochly.com",
      "tree_size": 12345,
      "tree_root_hex": "<sha256 hex of merkle root after inclusion>",
      "leaf_index": 1234,
      "leaf_digest_hex": "<sha256 hex of bundle digest>",
      "inclusion_proof": ["<hex>", "<hex>", ...],
      "witness": {
        "alg": "EdDSA",
        "kid": "<witness key kid>",
        "signature_b64u": "<base64url ed25519 sig over tree_root_hex bytes>",
      },
    }

The verifier:
  1. Recomputes the leaf -> root path via :func:`merkle.verify_inclusion_proof`.
  2. Locates the witness public key in the trust-anchor JWKS (or in a
     dedicated `witness_keys` map if supplied; defaults to the same JWKS
     the bundle signatures use).
  3. Verifies the witness ed25519 signature over the canonical
     ``tree_root_hex`` bytes (raw lowercase hex string encoded UTF-8).

A malformed proof structure produces ``"witness_mismatch"`` (so the
verifier degrades gracefully and reports the structural problem in the
WARN reason) rather than a hard exception; the bundle as a whole still
verifies because log inclusion is informational per VAL-W10-028.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .merkle import verify_inclusion_proof
from .verifier import _b64u_decode, _load_public_key_from_jwk, _select_jwk

# -----------------------------------------------------------------------------
# Result type
# -----------------------------------------------------------------------------


@dataclass
class LogInclusionResult:
    """Verdict for a transparency-log inclusion check on a bundle.

    `outcome` is one of:
      * "ok"               -- proof verified AND witness signature verified
      * "absent"           -- no inclusion proof attached to the bundle
      * "witness_mismatch" -- proof present but verification failed
    `reason` carries a human-readable detail; "" on ok/absent.
    `log_id` echoes the proof's `log_id` when present.
    `tree_size` echoes the proof's `tree_size` when present (0 otherwise).
    `leaf_index` echoes the proof's `leaf_index` when present (-1 otherwise).
    """

    outcome: str = "absent"
    reason: str = ""
    log_id: str = ""
    tree_size: int = 0
    leaf_index: int = -1


# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------


def verify_log_inclusion(
    *,
    proof: dict[str, Any] | None,
    bundle_digest_hex: str,
    witness_jwks: dict[str, Any] | None = None,
) -> LogInclusionResult:
    """Verify a transparency-log inclusion proof offline.

    `proof` is the parsed inclusion structure (see module docstring) or
    None if absent. `bundle_digest_hex` is the lowercase-hex SHA-256 over
    the JCS canonical bytes of the bundle's signature-free payload (see
    :func:`relay_verifier.canonical.bundle_digest`); a leaf-digest
    mismatch indicates the proof was issued for a different bundle.
    `witness_jwks` is an optional JWKS dict containing the witness key;
    when None the verifier returns "witness_mismatch" with reason
    "no witness JWKS supplied".

    Per VAL-W10-030 this function performs zero I/O. All inputs are
    pre-parsed structures supplied by the caller.
    """
    result = LogInclusionResult()

    if proof is None:
        result.outcome = "absent"
        result.reason = "no inclusion proof attached"
        return result

    if not isinstance(proof, dict):
        result.outcome = "witness_mismatch"
        result.reason = (
            f"inclusion proof must be a structured object, got "
            f"{type(proof).__name__}"
        )
        return result

    # Echo identifying fields immediately so consumer telemetry has them
    # even if the proof later fails verification.
    log_id = proof.get("log_id")
    if isinstance(log_id, str):
        result.log_id = log_id
    tree_size = proof.get("tree_size")
    if isinstance(tree_size, int):
        result.tree_size = tree_size
    leaf_index = proof.get("leaf_index")
    if isinstance(leaf_index, int):
        result.leaf_index = leaf_index

    # 1. Leaf digest must match the bundle digest.
    leaf_digest_hex = proof.get("leaf_digest_hex")
    if not isinstance(leaf_digest_hex, str) or not leaf_digest_hex:
        result.outcome = "witness_mismatch"
        result.reason = "inclusion proof missing 'leaf_digest_hex'"
        return result
    if leaf_digest_hex != bundle_digest_hex:
        result.outcome = "witness_mismatch"
        result.reason = (
            f"inclusion proof leaf_digest_hex {leaf_digest_hex!r} does not "
            f"match bundle digest {bundle_digest_hex!r}"
        )
        return result

    # 2. Recompute the merkle path against the claimed tree root.
    proof_path = proof.get("inclusion_proof")
    if not isinstance(proof_path, list):
        result.outcome = "witness_mismatch"
        result.reason = "inclusion proof missing 'inclusion_proof' list"
        return result
    tree_root_hex = proof.get("tree_root_hex")
    if not isinstance(tree_root_hex, str) or not tree_root_hex:
        result.outcome = "witness_mismatch"
        result.reason = "inclusion proof missing 'tree_root_hex'"
        return result
    if not isinstance(leaf_index, int) or not isinstance(tree_size, int):
        result.outcome = "witness_mismatch"
        result.reason = "inclusion proof leaf_index/tree_size must be integers"
        return result
    try:
        path_ok = verify_inclusion_proof(
            leaf_index=leaf_index,
            leaf_digest_hex=leaf_digest_hex,
            proof_path=[str(p) for p in proof_path],
            tree_size=tree_size,
            claimed_root_hex=tree_root_hex,
        )
    except (ValueError, TypeError) as exc:
        result.outcome = "witness_mismatch"
        result.reason = f"inclusion proof recomputation failed: {exc}"
        return result
    if not path_ok:
        result.outcome = "witness_mismatch"
        result.reason = (
            "inclusion proof recomputation does not match claimed tree_root"
        )
        return result

    # 3. Witness signature over the tree_root_hex (UTF-8 encoded raw
    # hex string) per Sigstore Rekor convention.
    witness = proof.get("witness")
    if not isinstance(witness, dict):
        result.outcome = "witness_mismatch"
        result.reason = "inclusion proof missing 'witness' object"
        return result
    if witness_jwks is None:
        result.outcome = "witness_mismatch"
        result.reason = "no witness JWKS supplied to verifier"
        return result
    witness_alg = witness.get("alg")
    if witness_alg != "EdDSA":
        # Spec gap #6 default: ed25519 detached. Other algs are out of
        # scope for v0.1 OSS verifier.
        result.outcome = "witness_mismatch"
        result.reason = (
            f"witness alg {witness_alg!r} not supported (v0.1 ships EdDSA only)"
        )
        return result
    witness_kid = witness.get("kid")
    if not isinstance(witness_kid, str) or not witness_kid:
        result.outcome = "witness_mismatch"
        result.reason = "witness signature missing 'kid'"
        return result
    witness_sig_b64 = witness.get("signature_b64u")
    if not isinstance(witness_sig_b64, str) or not witness_sig_b64:
        result.outcome = "witness_mismatch"
        result.reason = "witness signature missing 'signature_b64u'"
        return result

    jwk = _select_jwk(witness_jwks, witness_kid)
    if jwk is None:
        result.outcome = "witness_mismatch"
        result.reason = (
            f"no JWK in witness JWKS matches kid {witness_kid!r}"
        )
        return result
    try:
        public_key = _load_public_key_from_jwk(jwk)
    except ValueError as exc:
        result.outcome = "witness_mismatch"
        result.reason = f"witness JWK load failed: {exc}"
        return result
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        result.outcome = "witness_mismatch"
        result.reason = (
            f"witness JWK kty mismatch: expected Ed25519, got "
            f"{type(public_key).__name__}"
        )
        return result

    try:
        sig = _b64u_decode(witness_sig_b64)
    except ValueError as exc:
        result.outcome = "witness_mismatch"
        result.reason = f"witness signature_b64u not valid base64url: {exc}"
        return result
    try:
        public_key.verify(sig, tree_root_hex.encode("utf-8"))
    except InvalidSignature:
        result.outcome = "witness_mismatch"
        result.reason = (
            "witness signature did not verify against tree_root_hex bytes"
        )
        return result

    result.outcome = "ok"
    return result


__all__ = [
    "LogInclusionResult",
    "verify_log_inclusion",
]
