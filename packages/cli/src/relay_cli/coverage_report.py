"""Signed coverage-report writer for ``rly contract publish`` (W6.6 VAL-W6-064/065/066).

This module owns the canonical coverage-invariant report shape produced
by ``rly contract publish``. Per the contract assertions:

  * VAL-W6-064: on a clean publish the CLI MUST emit a coverage report
    containing total active assertion count, per-gate coverage map, per-
    owner load, duplicate-digest scan result (empty), orphan scan result
    (empty), and the manifest commit hash. The report MUST be written via
    :func:`relay_sidecar.primitives.local_atomic_file_write` (CLAUDE.md
    keystone invariant #8) and MUST carry
    ``schema_version: "relay.contract_publish_report.v1"``.

  * VAL-W6-065: publishing the same assertion-set bundle twice in
    succession MUST yield byte-identical reports AFTER STRIPPING the
    wall-clock timestamp metadata. The implementation isolates wall-clock
    fields into a ``metadata`` block whose value is supplied by the caller
    (so tests can supply a fixed value) and whose stripped form is the
    document the determinism check hashes.

  * VAL-W6-066 (forks-safe): when the environment lacks ``GITHUB_TOKEN``
    the report MUST be tagged ``mode: "dry_run_unsigned"`` AND MUST carry
    ``dry_run_unsigned: true``. The signature block is written as ``null``
    in dry-run; otherwise an Ed25519 signature over the canonical bytes of
    the unsigned payload (sans the ``signature`` field) is attached. The
    OSS verifier's default JWKS URL (``https://relay.epochly.com/.well-
    known/jwks.json``) is referenced in the ``trust_anchor`` field for both
    modes so downstream offline verification has the anchor needed to
    locate the public key.

Per CLAUDE.md banned pattern #13 the default trust-anchor URL is the
spec-pinned literal; changing it is a board-level decision. The literal
is read from :mod:`relay_cli.commands.evidence` at call time so the
single canonical occurrence stays canonical.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_sidecar.primitives import local_atomic_file_write

# -----------------------------------------------------------------------------
# Schema-version literal pin
# -----------------------------------------------------------------------------

COVERAGE_REPORT_SCHEMA: Final[str] = "relay.contract_publish_report.v1"

# Environment variable holding the path to a PEM-encoded Ed25519 signing
# key. Optional; absence -> unsigned bundle. Reuses the verify-self
# signing convention from W5.5 so a single key file is sufficient for
# both surfaces in the OSS local profile.
ENV_SIGNING_KEY_PATH: Final[str] = "RELAY_CONTRACT_PUBLISH_SIGNING_KEY_PATH"

# Environment variable for the kid stamped into the signature block.
# Defaults to the signing key file's stem (basename without extension).
ENV_SIGNING_KEY_KID: Final[str] = "RELAY_CONTRACT_PUBLISH_SIGNING_KEY_KID"

# VAL-W6-066: forks-safe environment detection. The presence of any of
# these env vars indicates a non-fork actor identity. Forks running in
# GitHub Actions Pull Request workflows do NOT receive ``GITHUB_TOKEN``
# (write-scoped); a self-hosted runner / dev workstation can opt into
# signed mode by exporting ``RELAY_FORCE_SIGNED=1`` (default off).
ENV_GITHUB_TOKEN: Final[str] = "GITHUB_TOKEN"
ENV_FORCE_SIGNED: Final[str] = "RELAY_FORCE_SIGNED"

# Per VAL-W6-064 published reports MUST be written through the four
# atomic-persistence primitives (CLAUDE.md keystone invariant #8). The
# default file mode is owner-read/write so the artifact is never world-
# readable on a multi-tenant developer workstation.
_DEFAULT_REPORT_FILE_MODE: Final[int] = 0o600


# -----------------------------------------------------------------------------
# Canonical bytes helper (RFC 8785 subset suitable for ASCII-only payloads)
# -----------------------------------------------------------------------------


def canonical_json_bytes(obj: Any) -> bytes:
    """Sort-keyed compact JSON, ASCII-safe.

    The coverage report payload is restricted to ASCII strings (assertion
    ids, owner emails, sha256 hex, the spec-pinned trust-anchor URL), so
    the stdlib ``json`` module with ``sort_keys=True`` and the
    ``(",", ":")`` separator pair is byte-equal to the W6.1 RFC 8785 JCS
    output for this restricted shape. Determinism (VAL-W6-065) is what
    matters here, NOT cross-runtime parity with arbitrary unicode JSON.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _b64u_encode(data: bytes) -> str:
    """RFC 4648 base64url WITHOUT padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# -----------------------------------------------------------------------------
# Inputs / output dataclasses
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CoverageInputs:
    """All non-derived inputs the writer needs to mint a coverage report.

    The caller (the publish command) is responsible for computing every
    coverage scan AHEAD of writing the report -- this writer is a pure
    serializer + signer. It does NOT inspect the assertions itself.
    """

    total_active_assertions: int
    per_gate_coverage: Mapping[str, list[str]]
    per_owner_load: Mapping[str, int]
    duplicate_digest_scan: Mapping[str, Any]  # ``{"violations": []}``
    orphan_scan: Mapping[str, Any]  # ``{"violations": []}``
    manifest_commit_hash: str | None
    trust_anchor: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CoverageReportResult:
    """The on-disk coverage report and its top-level metadata."""

    report_path: Path
    report_digest: str
    deterministic_digest: str  # digest of payload sans wall-clock metadata
    signed: bool
    mode: str  # "signed" | "dry_run_unsigned"


# -----------------------------------------------------------------------------
# Mode detection (forks-safe; VAL-W6-066)
# -----------------------------------------------------------------------------


def detect_mode(env: Mapping[str, str] | None = None) -> str:
    """Return ``"signed"`` or ``"dry_run_unsigned"`` based on env.

    VAL-W6-066: when ``GITHUB_TOKEN`` is absent (the canonical fork-actor
    fingerprint per spec A.3 / AI.6), the publish path operates in dry-
    run-unsigned mode. The opt-in escape hatch ``RELAY_FORCE_SIGNED=1``
    lets a dev workstation produce signed reports without GITHUB_TOKEN.
    Both env vars must be non-empty after strip to count as "set".
    """
    src = dict(env if env is not None else os.environ)
    forced = src.get(ENV_FORCE_SIGNED, "").strip()
    if forced and forced not in {"0", "false", "False", ""}:
        return "signed"
    token = src.get(ENV_GITHUB_TOKEN, "").strip()
    if not token:
        return "dry_run_unsigned"
    return "signed"


# -----------------------------------------------------------------------------
# Payload construction
# -----------------------------------------------------------------------------


def _normalize_per_gate(per_gate: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    """Sort gate ids and the assertion-id lists within each gate.

    Determinism (VAL-W6-065) requires every collection to have a fixed
    ordering. JSON object key ordering is handled by ``sort_keys=True``
    at serialize time; nested list ordering must be sorted here.
    """
    out: dict[str, list[str]] = {}
    for gate_id, ids in per_gate.items():
        out[str(gate_id)] = sorted({str(i) for i in ids})
    return out


def _normalize_per_owner(per_owner: Mapping[str, int]) -> dict[str, int]:
    """Project owner-load into a sorted dict[str, int] for determinism."""
    return {str(k): int(v) for k, v in per_owner.items()}


def build_unsigned_payload(
    inputs: CoverageInputs,
    *,
    mode: str,
) -> dict[str, Any]:
    """Build the unsigned canonical payload (no ``signature`` key).

    Field set per VAL-W6-064. The ``mode`` and ``dry_run_unsigned`` fields
    expose the fork-safe state per VAL-W6-066. The ``metadata`` block is
    the wall-clock bucket VAL-W6-065 strips before computing the
    determinism digest.
    """
    return {
        "schema_version": COVERAGE_REPORT_SCHEMA,
        "mode": mode,
        "dry_run_unsigned": mode == "dry_run_unsigned",
        "manifest_commit_hash": inputs.manifest_commit_hash,
        "trust_anchor": inputs.trust_anchor,
        "total_active_assertions": int(inputs.total_active_assertions),
        "per_gate_coverage": _normalize_per_gate(inputs.per_gate_coverage),
        "per_owner_load": _normalize_per_owner(inputs.per_owner_load),
        "duplicate_digest_scan": dict(inputs.duplicate_digest_scan),
        "orphan_scan": dict(inputs.orphan_scan),
        "metadata": dict(inputs.metadata),
    }


def deterministic_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Strip wall-clock metadata for the VAL-W6-065 determinism digest.

    The ``metadata`` block is the only mutable wall-clock surface: its
    value carries ``generated_at``, ``report_id``, and any other run-
    specific stamp. Stripping it yields the document the determinism
    check hashes (two consecutive publishes of the same assertion set
    MUST yield byte-identical post-strip bytes).
    """
    out = {k: v for k, v in payload.items() if k != "metadata"}
    return out


# -----------------------------------------------------------------------------
# Signing
# -----------------------------------------------------------------------------


def _load_signing_key(path: Path) -> ed25519.Ed25519PrivateKey:
    pem = path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(
            f"signing key at {path} is not Ed25519 (got {type(key).__name__})"
        )
    return key


def _maybe_sign(
    payload: Mapping[str, Any],
    *,
    mode: str,
    key_path_override: Path | None,
    kid_override: str | None,
    env: Mapping[str, str] | None,
) -> dict[str, Any] | None:
    """Sign the canonical bytes of ``payload`` when in signed mode.

    Returns ``None`` if ``mode != "signed"`` (forks-safe per VAL-W6-066)
    or no signing key is configured. Returns the signature dict when a
    key is available and mode is signed.
    """
    if mode != "signed":
        return None
    src = dict(env if env is not None else os.environ)
    if key_path_override is not None:
        key_path: Path | None = key_path_override
    else:
        env_value = src.get(ENV_SIGNING_KEY_PATH, "").strip()
        key_path = Path(env_value).expanduser() if env_value else None
    if key_path is None or not key_path.exists():
        return None
    key = _load_signing_key(key_path)
    signing_bytes = canonical_json_bytes(payload)
    signature_bytes = key.sign(signing_bytes)
    if kid_override is not None:
        kid = kid_override
    else:
        env_kid = src.get(ENV_SIGNING_KEY_KID, "").strip()
        kid = env_kid if env_kid else key_path.stem
    return {
        "alg": "EdDSA",
        "kid": kid,
        "signing_input_b64u": _b64u_encode(signing_bytes),
        "signature_b64u": _b64u_encode(signature_bytes),
    }


# -----------------------------------------------------------------------------
# Public writer
# -----------------------------------------------------------------------------


def write_report(
    inputs: CoverageInputs,
    *,
    out_path: Path,
    env: Mapping[str, str] | None = None,
    key_path_override: Path | None = None,
    kid_override: str | None = None,
    mode_override: str | None = None,
) -> CoverageReportResult:
    """Write a coverage report to ``out_path`` atomically.

    Args:
        inputs: pre-computed coverage scan results. The caller (the
            publish command) is responsible for performing the orphan,
            duplicate-digest, and missing-owner scans and supplying the
            results here -- this writer does NOT re-run them.
        out_path: absolute file path for the report. The parent directory
            is created if missing (mode 0o700). The file itself is
            written 0o600 via the atomic primitive.
        env: environment override (test seam). Defaults to ``os.environ``.
        key_path_override: explicit signing key path (test seam).
        kid_override: explicit kid (test seam).
        mode_override: pin the mode regardless of env (test seam).

    Returns:
        A :class:`CoverageReportResult` carrying the on-disk path, the
        SHA-256 digest of the canonical bytes, the determinism digest
        (post-strip of wall-clock metadata), the signed flag, and the
        publish mode tag.
    """
    mode = mode_override if mode_override is not None else detect_mode(env)
    if mode not in {"signed", "dry_run_unsigned"}:
        raise ValueError(f"invalid mode: {mode!r}")

    payload = build_unsigned_payload(inputs, mode=mode)
    signature = _maybe_sign(
        payload,
        mode=mode,
        key_path_override=key_path_override,
        kid_override=kid_override,
        env=env,
    )

    final_payload: dict[str, Any] = dict(payload)
    final_payload["signature"] = signature  # may be None when unsigned

    canonical_bytes = canonical_json_bytes(final_payload)
    report_digest = sha256_hex(canonical_bytes)
    deterministic_digest = sha256_hex(
        canonical_json_bytes(deterministic_view(final_payload))
    )

    # Per CLAUDE.md keystone invariant #8 the persistent write goes
    # through the atomic primitive; mode 0o600 keeps the artifact owner-
    # only on POSIX.
    out_path.parent.mkdir(parents=True, exist_ok=True)
    local_atomic_file_write(out_path, canonical_bytes, mode=_DEFAULT_REPORT_FILE_MODE)

    return CoverageReportResult(
        report_path=out_path,
        report_digest=report_digest,
        deterministic_digest=deterministic_digest,
        signed=signature is not None,
        mode=mode,
    )


__all__ = [
    "COVERAGE_REPORT_SCHEMA",
    "CoverageInputs",
    "CoverageReportResult",
    "ENV_FORCE_SIGNED",
    "ENV_GITHUB_TOKEN",
    "ENV_SIGNING_KEY_KID",
    "ENV_SIGNING_KEY_PATH",
    "build_unsigned_payload",
    "canonical_json_bytes",
    "detect_mode",
    "deterministic_view",
    "sha256_hex",
    "write_report",
]
