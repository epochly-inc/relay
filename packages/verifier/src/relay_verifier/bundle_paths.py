"""Bundle verifier path-traversal hardening (VAL-V2M08-015..017).

Spec anchor: AI line 5663.

The OSS bundle verifier rejects any bundle whose manifest declares an
artifact path that:

* contains ``..`` segments (``relative_traversal``)
* is absolute -- POSIX (``/``), Windows drive (``C:\\``), or UNC
  (``\\\\host\\share``) (``absolute_path``)
* is not Unicode NFC (``non_nfc_name``)
* contains invalid UTF-8 byte sequences (``invalid_utf8_name``)

Rejections surface under the existing :data:`RELAY-EVID-024`
path-violation code with a structured ``path_violation`` discriminator
so downstream tooling can branch on the specific violation class.

The check is pure (no filesystem access) so it can be exercised against
in-memory manifests at the tier-1 plumbing tier. Callers wire this
function into :func:`relay_verifier.bundle_validator.validate_bundle`
just before any artifact-resolver invocation.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Final

# Re-use the existing path-traversal code from bundle_validator. This
# keeps the wire surface stable: external consumers branching on
# RELAY-EVID-024 already know to attribute "bundle integrity / path"
# violations.
RELAY_EVID_024: Final[str] = "RELAY-EVID-024"

# Windows drive-letter prefix: a single letter followed by ":\" or ":/".
_WIN_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]:[\\/]")


def _is_unc_path(path: str) -> bool:
    """Return True if ``path`` is a Windows UNC path (``\\\\host\\share``)."""
    return path.startswith("\\\\") or path.startswith("//")


def _has_relative_traversal(path: str) -> bool:
    """Return True if any path segment is ``..``.

    The check normalizes both POSIX (``/``) and Windows (``\\``)
    separators so an attacker cannot smuggle a traversal under a
    cross-platform separator. The check is conservative: a literal
    ``..`` anywhere in the path -- even surrounded by other characters,
    e.g. ``foo/..bar/baz`` -- is treated as suspect only if it is a
    standalone segment (``foo/../bar``). The literal substring ``..``
    inside a filename is acceptable (e.g., ``my..file.txt``); only
    parent-directory traversal triggers the rejection.
    """
    normalized = path.replace("\\", "/")
    segments = normalized.split("/")
    return any(seg == ".." for seg in segments)


def _is_absolute(path: str) -> bool:
    """Return True if ``path`` is absolute under POSIX or Windows."""
    if not path:
        return False
    # POSIX absolute.
    if path.startswith("/"):
        return True
    # UNC absolute (Windows network path).
    if _is_unc_path(path):
        return True
    # Windows drive-letter absolute.
    return bool(_WIN_DRIVE_RE.match(path))


def check_artifact_path(path: Any) -> dict[str, Any] | None:
    """Return ``None`` if ``path`` passes every path-hardening check.

    Return a structured rejection envelope dict otherwise. The envelope
    keys are stable wire-format names:

    * ``code`` -- ``"RELAY-EVID-024"``.
    * ``path_violation`` -- one of ``relative_traversal``,
      ``absolute_path``, ``non_nfc_name``, ``invalid_utf8_name``.
    * ``offending_path`` -- the input verbatim (decoded to str when
      bytes; replaced with ``"<invalid-utf8>"`` if undecodable).

    ``path`` may be ``str`` or ``bytes``. A bytes input that does not
    decode under strict UTF-8 is rejected with
    ``path_violation="invalid_utf8_name"`` BEFORE any other check, so
    an attacker cannot smuggle a traversal under an invalid-bytes
    cover. A str input that contains a lone surrogate (cannot UTF-8
    encode) is also rejected as ``invalid_utf8_name``.
    """
    # Bytes input: must decode as strict UTF-8 first.
    if isinstance(path, bytes | bytearray):
        try:
            decoded = bytes(path).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Surface the raw repr without re-encoding, so logs can
            # cite the offending bytes without lossy substitution.
            return {
                "code": RELAY_EVID_024,
                "path_violation": "invalid_utf8_name",
                "offending_path": repr(bytes(path)),
            }
        path = decoded

    if not isinstance(path, str):
        return None

    # Lone-surrogate / non-encodable str -> invalid_utf8_name.
    try:
        path.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": repr(path),
        }

    # Absolute paths.
    if _is_absolute(path):
        return {
            "code": RELAY_EVID_024,
            "path_violation": "absolute_path",
            "offending_path": path,
        }

    # Relative traversal.
    if _has_relative_traversal(path):
        return {
            "code": RELAY_EVID_024,
            "path_violation": "relative_traversal",
            "offending_path": path,
        }

    # NFC normalization. Reject any path whose normalized form differs
    # from the input (NFD, NFKC, NFKD all map differently). The check
    # is conservative: a mixed-form name (some NFC code points, some
    # NFD) is rejected so downstream filesystems do not double-map.
    if unicodedata.normalize("NFC", path) != path:
        return {
            "code": RELAY_EVID_024,
            "path_violation": "non_nfc_name",
            "offending_path": path,
        }

    return None


__all__ = [
    "RELAY_EVID_024",
    "check_artifact_path",
]
