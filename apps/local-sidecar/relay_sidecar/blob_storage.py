"""Content-addressed blob spillover for oversize event_log payloads (W2.5).

Per VAL-W2-038 / -039: event_log_entries.payload that would otherwise exceed
the spillover threshold (16 KiB by default; configurable via
``RELAY_BLOB_SPILLOVER_BYTES``) MUST be written to
``${RELAY_HOME}/evidence/blobs/<sha256-hex>`` via
``local_atomic_file_write`` (the atomic-persistence primitive #4 per CLAUDE.md
keystone invariant #8). The row's payload column then carries only a
reference envelope::

    {"_blob_sha256": "<hex>"}

Properties:

  - Content-addressed: identical payloads produce identical filenames; second
    writers no-op via the atomic primitive's idempotent rename.
  - Mode 0600 on POSIX (handled by ``local_atomic_file_write``). On Windows,
    the ACL is the per-user single-ACE DACL applied by the primitive.
  - The blob file content is the canonical payload BYTES (UTF-8 JSON) that
    would otherwise have been stored inline. No additional wrapping.

The spillover threshold is loaded once at module import from the
``RELAY_BLOB_SPILLOVER_BYTES`` environment variable, defaulting to 16384
bytes (16 KiB per eng plan A5). The default is also declared in
``packages/schemas/raw/sidecar-config.yaml`` so auditors can read the
canonical declaration.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .lockfile import relay_home
from .primitives import local_atomic_file_write

# Default spillover threshold. Spec eng plan A5 calls for "event log payload
# size bounded; large bodies spill to content-addressed storage" without
# pinning the exact threshold; VAL-W2-038 fixes it at 16 KiB. The default is
# repeated here AND in packages/schemas/raw/sidecar-config.yaml; the YAML is
# the auditable source. The two MUST stay in sync.
DEFAULT_BLOB_SPILLOVER_BYTES: int = 16 * 1024

# Reference key embedded in the on-row payload after spillover. Documented
# in VAL-W2-038 as the canonical replacement envelope.
BLOB_REF_KEY: str = "_blob_sha256"


def spillover_threshold() -> int:
    """Return the active spillover threshold in bytes.

    Reads ``RELAY_BLOB_SPILLOVER_BYTES`` on every call (cheap, allows tests
    to monkeypatch via ``monkeypatch.setenv`` without module reload).
    Falls back to ``DEFAULT_BLOB_SPILLOVER_BYTES`` when unset OR when the
    value is not a positive integer (defensive: a misconfigured env var
    must not silently disable the bound).
    """
    raw = os.environ.get("RELAY_BLOB_SPILLOVER_BYTES")
    if raw is None:
        return DEFAULT_BLOB_SPILLOVER_BYTES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_BLOB_SPILLOVER_BYTES
    if value <= 0:
        return DEFAULT_BLOB_SPILLOVER_BYTES
    return value


def blob_dir(home: Path | None = None) -> Path:
    """Return the absolute blob-storage directory under the resolved home.

    Caller is responsible for creating the directory before write. The
    spillover helper does that for you via ``maybe_spillover``.
    """
    base = home if home is not None else relay_home()
    return base / "evidence" / "blobs"


def _serialize_payload(payload: dict[str, Any]) -> bytes:
    """Canonical UTF-8 JSON serialization for a payload dict.

    Sorted keys + compact separators match the on-row encoding used by
    ``db._encode_value`` so the bytes that hit the DB are the same bytes
    that hit the blob file on spillover.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def maybe_spillover(
    payload: dict[str, Any],
    *,
    home: Path | None = None,
    threshold: int | None = None,
) -> dict[str, Any]:
    """If ``payload`` exceeds the spillover threshold, write it to a blob.

    Returns the dict that should be stored in ``event_log_entries.payload``.
    For payloads under threshold, returns ``payload`` unchanged. For
    payloads at or over threshold, writes the canonical JSON bytes to
    ``${RELAY_HOME}/evidence/blobs/<sha256-hex>`` via
    ``local_atomic_file_write`` and returns ``{"_blob_sha256": "<hex>"}``.

    Args:
        payload: The candidate payload dict. MUST be JSON-serialisable.
        home: Override the RELAY_HOME resolution (tests). Default uses the
            standard ``relay_home()`` resolver.
        threshold: Override the byte threshold (tests). Default reads from
            ``spillover_threshold()``.

    Returns:
        Dict to store inline. Either ``payload`` (under threshold) OR the
        blob reference envelope (at/over threshold).
    """
    if not isinstance(payload, dict):
        raise TypeError(
            f"maybe_spillover: payload must be a dict (got {type(payload).__name__})"
        )
    body = _serialize_payload(payload)
    limit = threshold if threshold is not None else spillover_threshold()
    if len(body) < limit:
        return payload
    # Spillover. The blob name is the sha256-hex of the canonical body so
    # identical payloads dedupe naturally (the atomic primitive overwrites
    # with identical bytes -- a content-hash safety property).
    digest = hashlib.sha256(body).hexdigest()
    base = home if home is not None else relay_home()
    blob_path = base / "evidence" / "blobs" / digest
    blob_path.parent.mkdir(parents=True, exist_ok=True)
    local_atomic_file_write(blob_path, body, mode=0o600)
    return {BLOB_REF_KEY: digest}


def read_blob(
    digest: str,
    *,
    home: Path | None = None,
) -> bytes:
    """Read a blob's raw bytes by sha256 digest.

    Caller is responsible for verifying the digest matches the payload
    reference. ``FileNotFoundError`` propagates when the blob is absent.
    """
    base = home if home is not None else relay_home()
    blob_path = base / "evidence" / "blobs" / digest
    return blob_path.read_bytes()


__all__ = [
    "BLOB_REF_KEY",
    "DEFAULT_BLOB_SPILLOVER_BYTES",
    "blob_dir",
    "maybe_spillover",
    "read_blob",
    "spillover_threshold",
]
