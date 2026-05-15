"""§K-conformant evidence-bundle writer for ``rly verify-self`` (VAL-W5-040).

Per CLAUDE.md "Pass without evidence is not a pass" + spec section K
every successful invocation of ``rly verify-self`` (pass or fail) MUST
produce an on-disk bundle at
``${RELAY_HOME}/evidence/verify-self/<timestamp>-<run_id>.json`` whose
shape matches the contract VAL-W5-040 enumeration:

    {
      "evidence_bundle_id": "<uuid>",
      "schema_version": "relay.cli.verify_self_evidence.v1",
      "assertion_ids": [
        "VAL-W5-031", "VAL-W5-032", "VAL-W5-033", "VAL-W5-034",
        "VAL-W5-035", "VAL-W5-036", "VAL-W5-037", "VAL-W5-038",
        "VAL-W5-039", "VAL-W5-040"
      ],
      "artifacts": [
        {"path": "<stdout_capture>", "sha256": "...", "kind": "verify_self_result"}
      ],
      "commands": [
        {"command_id": "rly verify-self", "exit_code": <int>,
         "stdout_sha256": "...", "stderr_sha256": "..."}
      ],
      "trace_span_ids": [...],
      "agent_id": "<string>",
      "manifest_commit_hash": "<sha256-or-null>",
      "created_at": "<RFC3339-Z>",
      "signature": { ... } | null
    }

The ``assertion_ids`` array MUST be the explicit 10-element enumeration
above, in order. No range notation, no ``..`` shorthand. The bundle is
machine-consumed and any range syntax would defeat the §K binding.

Persistence goes through ``local_atomic_file_write`` (CLAUDE.md keystone
invariant #8). The bundle filename uses an RFC-3339 UTC timestamp
(seconds-resolution + ``Z`` suffix) plus a UUIDv4 ``run_id``. Files are
written 0o600 so the on-disk artifact never appears world-readable.

Signing (VAL-W5-040 last sentence): if a signing key is configured via
``RELAY_VERIFY_SELF_SIGNING_KEY_PATH`` (PEM-encoded Ed25519 private
key), the bundle is signed with EdDSA over the canonical-JSON bytes of
the unsigned payload. The resulting signature is attached as
``signature: {alg, kid, signing_input_b64u, signature_b64u}``. Absent
the env var the bundle is written unsigned (``signature: null``); the
verifier accepts both modes for the OSS local profile.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_sidecar.lockfile import relay_home
from relay_sidecar.primitives import local_atomic_file_write

# -----------------------------------------------------------------------------
# Schema-version literal pin
# -----------------------------------------------------------------------------

EVIDENCE_BUNDLE_SCHEMA: Final[str] = "relay.cli.verify_self_evidence.v1"

# -----------------------------------------------------------------------------
# Assertion-ids enumeration (VAL-W5-040: explicit, 10 elements, in order)
# -----------------------------------------------------------------------------
#
# Per VAL-W5-040 the array MUST be the explicit 10-element list with no
# range notation or ``..`` shorthand. The constant is exported so tests
# can pin the membership and ordering.

ASSERTION_IDS: Final[tuple[str, ...]] = (
    "VAL-W5-031",
    "VAL-W5-032",
    "VAL-W5-033",
    "VAL-W5-034",
    "VAL-W5-035",
    "VAL-W5-036",
    "VAL-W5-037",
    "VAL-W5-038",
    "VAL-W5-039",
    "VAL-W5-040",
)

# Environment variable holding the path to a PEM-encoded Ed25519 signing
# key. Optional; absence yields an unsigned bundle. The verifier accepts
# both signed and unsigned bundles for the OSS local profile.
ENV_SIGNING_KEY_PATH: Final[str] = "RELAY_VERIFY_SELF_SIGNING_KEY_PATH"

# Environment variable holding the kid for the signing key (matches the
# JWKS entry the verifier uses to look up the public key). Optional; the
# default kid value is the file basename stripped of extension.
ENV_SIGNING_KEY_KID: Final[str] = "RELAY_VERIFY_SELF_SIGNING_KEY_KID"

# Environment variable letting CI override the agent_id stamped into the
# bundle. Defaults to ``rly-verify-self`` when absent.
ENV_AGENT_ID: Final[str] = "RELAY_VERIFY_SELF_AGENT_ID"

# Environment variable letting CI override the manifest_commit_hash
# stamped into the bundle. Defaults to None when absent (per the spec
# §K shape this field is optional / nullable).
ENV_MANIFEST_COMMIT_HASH: Final[str] = "RELAY_VERIFY_SELF_MANIFEST_COMMIT_HASH"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _utc_iso_z(now: _dt.datetime | None = None) -> str:
    """Return an RFC-3339 UTC timestamp with seconds resolution + ``Z`` suffix."""
    moment = now if now is not None else _dt.datetime.now(_dt.UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.UTC)
    moment = moment.astimezone(_dt.UTC).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _filename_timestamp(now: _dt.datetime | None = None) -> str:
    """Return a filesystem-safe timestamp ``YYYYMMDDTHHMMSSZ``."""
    moment = now if now is not None else _dt.datetime.now(_dt.UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.UTC)
    moment = moment.astimezone(_dt.UTC).replace(microsecond=0)
    return moment.strftime("%Y%m%dT%H%M%SZ")


def _canonical_json_bytes(obj: Any) -> bytes:
    """RFC-8785-compatible canonical JSON bytes (sort_keys + compact)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _b64u_encode(data: bytes) -> str:
    """RFC 4648 base64url WITHOUT padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _load_signing_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Load a PEM-encoded Ed25519 private key from ``path``.

    Raises:
        ValueError: when the key is not Ed25519 or the file is malformed.
    """
    pem = path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(
            f"signing key at {path} is not Ed25519 "
            f"(got {type(key).__name__})"
        )
    return key


# -----------------------------------------------------------------------------
# Bundle dataclass + builder
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleInputs:
    """All non-derived inputs the writer needs to mint a bundle."""

    stdout_bytes: bytes
    stderr_bytes: bytes
    exit_code: int
    trace_span_ids: tuple[str, ...] = ()
    agent_id: str | None = None
    manifest_commit_hash: str | None = None


@dataclass(frozen=True)
class BundleResult:
    """The on-disk bundle and its top-level metadata."""

    bundle_path: Path
    evidence_bundle_id: str
    bundle_digest: str
    signed: bool


def _build_unsigned_payload(
    *,
    inputs: BundleInputs,
    evidence_bundle_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Build the canonical bundle payload BEFORE signing.

    The payload is the §K-conformant dict; signing (when active) appends
    a ``signature`` field bound to canonical-JSON bytes of THIS payload.
    """
    agent_id = inputs.agent_id or os.environ.get(
        ENV_AGENT_ID, "rly-verify-self"
    )
    manifest_commit_hash = (
        inputs.manifest_commit_hash
        if inputs.manifest_commit_hash is not None
        else os.environ.get(ENV_MANIFEST_COMMIT_HASH) or None
    )
    return {
        "schema_version": EVIDENCE_BUNDLE_SCHEMA,
        "evidence_bundle_id": evidence_bundle_id,
        "assertion_ids": list(ASSERTION_IDS),
        "artifacts": [
            {
                "path": "stdout",
                "sha256": _sha256_hex(inputs.stdout_bytes),
                "kind": "verify_self_result",
            }
        ],
        "commands": [
            {
                "command_id": "rly verify-self",
                "exit_code": int(inputs.exit_code),
                "stdout_sha256": _sha256_hex(inputs.stdout_bytes),
                "stderr_sha256": _sha256_hex(inputs.stderr_bytes),
            }
        ],
        "trace_span_ids": list(inputs.trace_span_ids),
        "agent_id": agent_id,
        "manifest_commit_hash": manifest_commit_hash,
        "created_at": created_at,
    }


def _maybe_sign_payload(
    payload: dict[str, Any],
    *,
    key_path_override: Path | None = None,
    kid_override: str | None = None,
) -> dict[str, Any] | None:
    """Sign the canonical JSON of ``payload`` with the configured Ed25519 key.

    Returns the signature dict ``{alg, kid, signing_input_b64u,
    signature_b64u}`` on success, or None when no signing key is
    configured.
    """
    key_path: Path | None
    if key_path_override is not None:
        key_path = key_path_override
    else:
        env_value = os.environ.get(ENV_SIGNING_KEY_PATH, "").strip()
        key_path = Path(env_value).expanduser() if env_value else None
    if key_path is None or not key_path.exists():
        return None
    key = _load_signing_key(key_path)
    signing_bytes = _canonical_json_bytes(payload)
    signature_bytes = key.sign(signing_bytes)
    if kid_override is not None:
        kid = kid_override
    else:
        env_kid = os.environ.get(ENV_SIGNING_KEY_KID, "").strip()
        kid = env_kid if env_kid else key_path.stem
    return {
        "alg": "EdDSA",
        "kid": kid,
        "signing_input_b64u": _b64u_encode(signing_bytes),
        "signature_b64u": _b64u_encode(signature_bytes),
    }


def write_bundle(
    inputs: BundleInputs,
    *,
    home: Path | None = None,
    now: _dt.datetime | None = None,
    key_path_override: Path | None = None,
    kid_override: str | None = None,
) -> BundleResult:
    """Write a §K-conformant evidence bundle to ``${RELAY_HOME}/evidence/verify-self/``.

    Returns a :class:`BundleResult` carrying the on-disk path, the
    bundle id, the SHA-256 digest of the canonical bundle bytes, and a
    flag indicating whether the bundle was signed.

    Raises:
        OSError: bundle directory is unwritable.
        ValueError: the configured signing key is not Ed25519.
    """
    base_home = home if home is not None else relay_home()
    bundle_dir = base_home / "evidence" / "verify-self"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    evidence_bundle_id = str(uuid.uuid4())
    created_at = _utc_iso_z(now)
    fname_ts = _filename_timestamp(now)
    out_path = bundle_dir / f"{fname_ts}-{evidence_bundle_id}.json"

    payload = _build_unsigned_payload(
        inputs=inputs,
        evidence_bundle_id=evidence_bundle_id,
        created_at=created_at,
    )
    signature = _maybe_sign_payload(
        payload, key_path_override=key_path_override, kid_override=kid_override
    )
    final_payload: dict[str, Any] = dict(payload)
    final_payload["signature"] = signature  # may be None when unsigned

    canonical_bytes = _canonical_json_bytes(final_payload)
    bundle_digest = _sha256_hex(canonical_bytes)

    # VAL-W5-040 + CLAUDE.md keystone invariant #8: write through the
    # atomic primitive. Mode 0o600 so the artifact is owner-only.
    local_atomic_file_write(out_path, canonical_bytes, mode=0o600)

    return BundleResult(
        bundle_path=out_path,
        evidence_bundle_id=evidence_bundle_id,
        bundle_digest=bundle_digest,
        signed=signature is not None,
    )


__all__ = [
    "ASSERTION_IDS",
    "BundleInputs",
    "BundleResult",
    "ENV_AGENT_ID",
    "ENV_MANIFEST_COMMIT_HASH",
    "ENV_SIGNING_KEY_KID",
    "ENV_SIGNING_KEY_PATH",
    "EVIDENCE_BUNDLE_SCHEMA",
    "write_bundle",
]
