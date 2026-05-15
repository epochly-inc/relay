"""Ed25519 signing helpers for the W8.2 gate_decisions write path.

Per VAL-W8-019: every gate_decisions row MUST carry a non-null
``signature`` + ``signature_key_id``, computed over the row's canonical
JSON BEFORE the transaction commits. The signing primitive is Ed25519
(spec A.2 lines 2967-2968; spec AO trust anchor); the canonical JSON is
RFC 8785-equivalent JCS (sorted keys, tight separators, UTF-8).

Per VAL-W8-043: the canonical payload includes the
``manifest_commit_hash`` of the bound evidence bundle so the signature
binds the three-anchor handoff anchor as well.

This module is intentionally pure: it has no DB dependency and no side
effects at import time. The W8.2 ``decision_writer`` calls these
helpers to produce ``(signature, signature_key_id)`` for the INSERT.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Environment variables (test seams + hosted runtime configuration).
ENV_SIGNING_KEY_PATH: Final[str] = "RELAY_GATE_DECISION_SIGNING_KEY_PATH"
ENV_SIGNING_KEY_KID: Final[str] = "RELAY_GATE_DECISION_SIGNING_KEY_KID"

# Default key id when no explicit kid is configured (test/ephemeral path).
DEFAULT_EPHEMERAL_KID: Final[str] = "ephemeral-gate-engine"

# Canonical bundle digest format: sha256-<hex>.
SHA256_PREFIX: Final[str] = "sha256-"


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785-equivalent JCS).
# ---------------------------------------------------------------------------


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize ``payload`` to RFC 8785-equivalent JCS bytes.

    Properties:
      * Sorted dict keys at every nesting level.
      * Tight separators (no whitespace).
      * UTF-8 (no ASCII escaping of non-ASCII characters; matches RFC
        8785 section 3.2.4).
      * Stable output across runs given equal input dicts.

    The full RFC 8785 spec requires additional canonicalization for
    floats (-0 / NaN / +Inf forms) but Relay's gate_decision payloads
    are all strings + ints, so the trimmed implementation is
    byte-identical to the full spec for our payload shape.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_wire(data: bytes) -> str:
    """Return ``sha256-<hex>`` wire form for ``data``."""
    return SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def _b64u_encode(data: bytes) -> str:
    """RFC 4648 base64url WITHOUT padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    """RFC 4648 base64url decode tolerating missing padding."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


# ---------------------------------------------------------------------------
# Canonical gate_decision payload (the signing input).
# ---------------------------------------------------------------------------


def canonical_decision_payload(
    *,
    gate_decision_id: str,
    schema_version: str,
    gate_id: str,
    scope_type: str,
    scope_id: str,
    round_: int,
    action: str,
    strict_pass: bool,
    failed_assertion_ids: Sequence[str],
    unmet_conditions: Sequence[Mapping[str, Any]],
    evidence_bundle_id: str,
    cascade_on_block: bool,
    decided_by: str,
    decided_at: str,
    manifest_commit_hash: str,
    actor_identity_hash: str,
) -> dict[str, Any]:
    """Build the canonical signing-input dict for a gate_decisions row.

    The dict mirrors the persisted row's columns 1:1 EXCEPT the
    ``signature`` + ``signature_key_id`` columns (the output of the
    signing operation is computed FROM this payload, so including them
    would be circular).
    """
    return {
        "gate_decision_id": str(gate_decision_id),
        "schema_version": str(schema_version),
        "gate_id": str(gate_id),
        "scope_type": str(scope_type),
        "scope_id": str(scope_id),
        "round": int(round_),
        "action": str(action),
        "strict_pass": bool(strict_pass),
        "failed_assertion_ids": list(failed_assertion_ids),
        "unmet_conditions": [dict(c) for c in unmet_conditions],
        "evidence_bundle_id": str(evidence_bundle_id),
        "cascade_on_block": bool(cascade_on_block),
        "decided_by": str(decided_by),
        "decided_at": str(decided_at),
        "manifest_commit_hash": str(manifest_commit_hash),
        "actor_identity_hash": str(actor_identity_hash),
    }


# ---------------------------------------------------------------------------
# Signing key resolution + sign primitive.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SigningKey:
    """Bundle of (private key, key id) used for signing.

    Verifiers consume ``key_id`` to look up the public key in the active
    JWKS. The OSS local profile ships an ephemeral key when no PEM is
    configured; the hosted profile loads a KMS-backed key referenced by
    the env var.
    """

    private_key: ed25519.Ed25519PrivateKey
    key_id: str

    def public_bytes_b64u(self) -> str:
        """Return the corresponding public key in raw 32-byte form, b64url."""
        pub = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64u_encode(pub)


def load_signing_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Load a PEM-encoded Ed25519 private key from ``path``.

    Raises:
        ValueError: when the key is not Ed25519 or the file is malformed.
    """
    pem = path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(
            f"signing key at {path} is not Ed25519 (got {type(key).__name__})"
        )
    return key


def resolve_signing_key(
    *,
    key_path: Path | None = None,
    kid: str | None = None,
) -> SigningKey:
    """Resolve the active signing key.

    Resolution order:
      1. Explicit ``key_path`` arg (test seam) -> load PEM.
      2. ``RELAY_GATE_DECISION_SIGNING_KEY_PATH`` env var -> load PEM.
      3. Mint a fresh ephemeral Ed25519 key in memory (OSS local /
         test default).

    The ``kid`` arg / ``RELAY_GATE_DECISION_SIGNING_KEY_KID`` env var
    overrides the kid; defaults to the PEM filename stem or
    ``DEFAULT_EPHEMERAL_KID`` when an ephemeral key is used.
    """
    resolved_path: Path | None = None
    if key_path is not None:
        resolved_path = key_path
    else:
        env_value = os.environ.get(ENV_SIGNING_KEY_PATH, "").strip()
        if env_value:
            resolved_path = Path(env_value).expanduser()
    if resolved_path is not None and resolved_path.exists():
        private = load_signing_key(resolved_path)
        kid_resolved = kid or os.environ.get(ENV_SIGNING_KEY_KID, "").strip() or resolved_path.stem
        return SigningKey(private_key=private, key_id=kid_resolved)
    # Ephemeral path.
    private = ed25519.Ed25519PrivateKey.generate()
    kid_resolved = kid or os.environ.get(ENV_SIGNING_KEY_KID, "").strip() or DEFAULT_EPHEMERAL_KID
    return SigningKey(private_key=private, key_id=kid_resolved)


def sign_payload(
    payload: Mapping[str, Any],
    key: SigningKey,
) -> tuple[str, str]:
    """Sign the canonical JSON of ``payload``.

    Returns:
        ``(signature_b64u, signature_key_id)`` where ``signature_b64u``
        is the RFC 4648 base64url (no padding) encoded raw 64-byte
        Ed25519 signature.
    """
    signing_bytes = canonical_json_bytes(payload)
    signature_bytes = key.private_key.sign(signing_bytes)
    return _b64u_encode(signature_bytes), key.key_id


def verify_payload(
    *,
    payload: Mapping[str, Any],
    signature_b64u: str,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify ``signature_b64u`` against ``payload`` using ``public_key``.

    Returns True iff the signature is valid; False on any verification
    error (the underlying ``cryptography`` library raises
    ``InvalidSignature`` which we catch and convert to False so callers
    do not need to import the exception type).
    """
    from cryptography.exceptions import InvalidSignature

    signing_bytes = canonical_json_bytes(payload)
    try:
        public_key.verify(b64u_decode(signature_b64u), signing_bytes)
    except InvalidSignature:
        return False
    return True


__all__ = [
    "DEFAULT_EPHEMERAL_KID",
    "ENV_SIGNING_KEY_KID",
    "ENV_SIGNING_KEY_PATH",
    "SHA256_PREFIX",
    "SigningKey",
    "b64u_decode",
    "canonical_decision_payload",
    "canonical_json_bytes",
    "load_signing_key",
    "resolve_signing_key",
    "sha256_wire",
    "sign_payload",
    "verify_payload",
]
