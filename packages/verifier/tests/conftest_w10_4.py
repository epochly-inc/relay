"""Shared fixtures and helpers for the W10.4 bundle-validator tests.

Provides a small fixture-builder API:

    build_bundle(*, claims, signer_key_id, decided_at, trust_anchor,
                 tsa_token=..., log_inclusion_proof=..., merkle=True)
        -> (bundle_dict, jwks)

The helper creates a deterministic Ed25519 keypair (in-memory; never
written to disk so banned pattern #14 is preserved), signs the canonical
JCS bytes of the bundle payload, builds the Merkle root over claim
digests, and assembles the structured bundle dict.

These helpers are imported by test_w10_4_*.py modules. They are test-
only fixtures and do NOT leak private-key bytes onto disk.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_verifier import (
    build_inclusion_proof,
    bundle_digest,
    canonical_json_bytes,
    compute_merkle_root,
    jwk_from_ed25519_public_key,
    sign_payload_ed25519,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class BuiltBundle:
    """Container for a built test bundle + matching JWKS + signing key."""

    bundle: dict[str, Any]
    jwks: dict[str, Any]
    signing_key: ed25519.Ed25519PrivateKey
    witness_key: ed25519.Ed25519PrivateKey
    bundle_digest_hex: str


def make_keypair(seed: bytes) -> ed25519.Ed25519PrivateKey:
    """Deterministic Ed25519 keypair from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _build_tsa_token(
    *,
    bundle_digest_hex: str,
    gen_time: str,
    signer_subject: str = "CN=Relay OSS Placeholder TSA Root",
) -> dict[str, Any]:
    return {
        "version": 1,
        "policy_oid": "1.3.6.1.4.1.601.10.3.1",
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message_hex": bundle_digest_hex,
        },
        "serial_number": "424242",
        "gen_time": gen_time,
        "tsa_signature_alg": "EdDSA",
        "tsa_signer_cert_subject": signer_subject,
        "tsa_signature_b64u": "AA" * 32,  # placeholder; structural-only check
    }


def _build_inclusion_proof(
    *,
    claim_digests_hex: list[str],
    bundle_digest_hex: str,
    witness_key: ed25519.Ed25519PrivateKey,
    witness_kid: str = "witness-test-kid-1",
    leaf_index: int = 0,
) -> dict[str, Any]:
    """Build a transparency-log inclusion proof whose witness signature
    verifies against ``witness_key``.

    The leaf is bundle_digest_hex itself (not a per-claim digest); this
    mirrors how production bundles record their inclusion against the
    log: one log entry per bundle, with the leaf being the bundle's
    canonical SHA-256.
    """
    # For the inclusion proof, the tree contains the bundle_digest_hex
    # as one leaf among synthetic siblings so the proof has structure
    # to verify. Production uses real prior bundles; tests use synthetic
    # siblings.
    synthetic_sibling = hashlib.sha256(b"synthetic-sibling-leaf-1").hexdigest()
    tree_leaves = [bundle_digest_hex, synthetic_sibling]
    tree_root_hex = compute_merkle_root(tree_leaves)
    proof_path = build_inclusion_proof(
        leaf_index=leaf_index,
        claim_digests_hex=tree_leaves,
    )
    # Witness signs the lowercase-hex tree_root_hex bytes (UTF-8).
    sig_bytes = witness_key.sign(tree_root_hex.encode("utf-8"))
    return {
        "log_id": "rekor.test.epochly.com",
        "tree_size": len(tree_leaves),
        "tree_root_hex": tree_root_hex,
        "leaf_index": leaf_index,
        "leaf_digest_hex": bundle_digest_hex,
        "inclusion_proof": proof_path,
        "witness": {
            "alg": "EdDSA",
            "kid": witness_kid,
            "signature_b64u": _b64u_encode(sig_bytes),
        },
    }


def build_bundle(
    *,
    claims: list[dict[str, Any]] | None = None,
    signer_kid: str = "test-signer-kid-1",
    signer_seed: bytes = b"\x01" * 32,
    witness_kid: str = "witness-test-kid-1",
    witness_seed: bytes = b"\x02" * 32,
    decided_at: str = "2026-05-15T12:34:56Z",
    signed_at: str | None = None,
    trust_anchor: str = "https://relay.epochly.com/.well-known/jwks.json",
    include_tsa: bool = True,
    tsa_skew_seconds: int = 0,
    include_log_inclusion: bool = True,
    include_merkle: bool = True,
    subject_id: str | None = "run_01j0test",
    subject_digest_hex: str | None = None,
    key_not_before: str | None = "2026-01-01T00:00:00Z",
    key_not_after: str | None = "2028-01-01T00:00:00Z",
    key_revoked_at: str | None = None,
) -> BuiltBundle:
    """Construct a signed test bundle.

    Returns a `BuiltBundle` holding the bundle dict, a matching JWKS,
    and the signing + witness private keys (in memory only).
    """
    if claims is None:
        claims = [
            {
                "claim_id": "claim-1",
                "kind": "command_evidence",
                "command_id": "test-cmd",
                "exit_code": 0,
                "artifact_id": "art-1",
                "evidence_refs": [
                    {
                        "artifact_id": "art-1",
                        "digest": hashlib.sha256(b"artifact-1-bytes").hexdigest(),
                    },
                ],
            },
        ]

    signing_key = make_keypair(signer_seed)
    witness_key = make_keypair(witness_seed)

    signer_jwk = jwk_from_ed25519_public_key(
        signing_key.public_key(), kid=signer_kid,
        not_before=key_not_before, not_after=key_not_after,
    )
    if key_revoked_at is not None:
        signer_jwk["revoked_at"] = key_revoked_at
    witness_jwk = jwk_from_ed25519_public_key(
        witness_key.public_key(), kid=witness_kid,
    )
    jwks: dict[str, Any] = {"keys": [signer_jwk, witness_jwk]}

    # Build the payload (everything except signatures).
    if subject_digest_hex is None and subject_id is not None:
        subject_digest_hex = hashlib.sha256(
            subject_id.encode("utf-8")
        ).hexdigest()

    if signed_at is None:
        signed_at = decided_at

    claim_digests = [bundle_digest(c) for c in claims]
    merkle_root_hex = compute_merkle_root(claim_digests) if include_merkle else None

    # Build the core payload (NO tsa_token, NO log_inclusion_proof, NO
    # signatures). This is the digest the issuer binds the TSA token
    # and log inclusion proof to (the binding digest; see
    # bundle_validator._compute_binding_digest for the verifier-side
    # mirror).
    core_payload: dict[str, Any] = {
        "schema_version": "relay.evidence_bundle.v1",
        "evidence_bundle_id": "bundle-test-1",
        "trust_anchor": trust_anchor,
        "decided_at": decided_at,
        "signed_at": signed_at,
        "claims": claims,
        "subject_id": subject_id,
        "subject_digest_hex": subject_digest_hex,
    }
    if merkle_root_hex is not None:
        core_payload["merkle_root_hex"] = merkle_root_hex

    # Single source of truth: the binding digest is the SHA-256 of the
    # verifier-canonical JSON bytes of the core payload (signatures /
    # tsa_token / log_inclusion_proof all absent at this point).
    binding_digest_hex = hashlib.sha256(
        canonical_json_bytes(core_payload)
    ).hexdigest()

    # Now extend the payload with TSA + log inclusion bound to the
    # binding digest. Both extensions reference the same pre-extensions
    # digest; the verifier reverses this protocol by stripping them
    # before recomputing.
    payload = dict(core_payload)

    if include_tsa:
        gen_time = _shift_iso(decided_at, tsa_skew_seconds)
        payload["tsa_token"] = _build_tsa_token(
            bundle_digest_hex=binding_digest_hex,
            gen_time=gen_time,
        )

    if include_log_inclusion:
        payload["log_inclusion_proof"] = _build_inclusion_proof(
            claim_digests_hex=claim_digests,
            bundle_digest_hex=binding_digest_hex,
            witness_key=witness_key,
            witness_kid=witness_kid,
        )

    # Final sign over the full payload (everything except signatures).
    sig_record = sign_payload_ed25519(payload, signing_key, kid=signer_kid)
    # bundle_digest_hex returned to the test is the BINDING digest
    # (the one the issuer used to bind TSA and log inclusion), not
    # the full-payload digest. Tests that need the full-payload digest
    # can compute it from the bundle after the fact.
    payload_digest_hex = binding_digest_hex
    bundle = dict(payload)
    bundle["signatures"] = [sig_record]
    return BuiltBundle(
        bundle=bundle,
        jwks=jwks,
        signing_key=signing_key,
        witness_key=witness_key,
        bundle_digest_hex=payload_digest_hex,
    )


def _shift_iso(iso_z: str, delta_seconds: int) -> str:
    """Return ``iso_z`` shifted by ``delta_seconds``. Preserves the Z suffix."""
    dt = _dt.datetime.fromisoformat(iso_z[:-1] + "+00:00")
    dt2 = dt + _dt.timedelta(seconds=delta_seconds)
    return dt2.astimezone(_dt.UTC).isoformat().replace("+00:00", "Z")
