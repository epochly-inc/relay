"""Bundle verifier path-traversal hardening (VAL-V2M08-015..017).

Spec anchor: AI line 5663.

The OSS bundle verifier rejects any bundle whose manifest declares an
artifact path that:

* contains ``..`` segments (``relative_traversal``)
* is absolute -- POSIX (``/``), Windows drive (``C:\\``), or UNC
  (``\\\\host\\share``) (``absolute_path``)
* is not Unicode NFC (``non_nfc_name``)
* contains invalid UTF-8 byte sequences, NUL bytes, or lone
  surrogates (``invalid_utf8_name``)
* is empty / leading-or-trailing whitespace
  (``invalid_utf8_name`` fall-through bucket -- consumers branch on
  ``code`` not on the exact discriminator)
* exceeds 1024 UTF-8 bytes (``invalid_utf8_name``)

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

import errno
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Any, Final

# Re-use the existing path-traversal code from bundle_validator. This
# keeps the wire surface stable: external consumers branching on
# RELAY-EVID-024 already know to attribute "bundle integrity / path"
# violations.
RELAY_EVID_024: Final[str] = "RELAY-EVID-024"

# Maximum permitted UTF-8 length, in bytes, of an artifact path.
# Defends against pathological inputs that bypass downstream length
# checks (filesystem PATH_MAX or zip header limits). Mirrors
# ``packages/verifier-typescript/src/bundle_paths.ts::MAX_ARTIFACT_PATH_BYTES``.
MAX_ARTIFACT_PATH_BYTES: Final[int] = 1024

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
        encoded = path.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": repr(path),
        }

    # Empty / leading-or-trailing whitespace rejection (AUDIT-R4 BUG-H2
    # parity with packages/verifier-typescript/src/bundle_paths.ts:136-149).
    # Whitespace-bracketed paths are a path-collision attack surface
    # ("foo.txt" vs " foo.txt" referring to the same artifact under
    # filesystems that trim).
    if not path or not path.strip():
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": path,
        }
    if path != path.strip():
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": path,
        }

    # Embedded NUL byte rejection (AUDIT-R4 BUG-H2 parity with TS:153-159).
    # NUL bytes are a path-traversal escape under several filesystems
    # (the C-string truncation trick).
    if "\x00" in path:
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": path,
        }

    # UTF-8 byte length cap (AUDIT-R4 BUG-H2 parity with TS:188-194).
    # Computed after lone-surrogate rejection so we never measure an
    # un-encodable string. The cap defends against pathological
    # inputs that would bypass downstream length checks (PATH_MAX,
    # zip header limits).
    if len(encoded) > MAX_ARTIFACT_PATH_BYTES:
        return {
            "code": RELAY_EVID_024,
            "path_violation": "invalid_utf8_name",
            "offending_path": path,
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


# --------------------------------------------------------------------------
# VAL-V3M5-013: cross-platform symlink-safe bundle/manifest reads.
# --------------------------------------------------------------------------
#
# Spec anchor: AI line 5663 (path-traversal + TOCTOU hardening).
#
# The OSS bundle verifier reads on-disk bundle/manifest files from caller-
# supplied paths. ``pathlib.Path.read_bytes()`` (and the underlying
# ``open(...).read()``) silently follows symlinks at the final path
# component, opening a TOCTOU window:
#
#   1. Verifier observes path P as a regular file.
#   2. Attacker swaps P for a symlink pointing off-tree (e.g. /etc/passwd
#      or a sibling tenant's bundle).
#   3. Verifier dereferences the symlink and reads attacker-chosen content
#      under the bundle's authority. The resulting signature/digest check
#      then either validates content the verifier never approved, or
#      leaks file existence as an oracle.
#
# The fix is a cross-platform helper that refuses to dereference a
# symlink at the FINAL path component. Symlinks on intermediate
# components are out of scope: defending against those requires
# ``openat2(..., RESOLVE_NO_SYMLINKS)`` (Linux 5.6+) or per-segment
# ``O_NOFOLLOW`` walks, which is not portable. Callers must pass paths
# under directories they themselves created or validated.
#
# POSIX:   ``os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)``.
#          Kernel refuses the open with ``ELOOP`` (some BSDs: ``EMLINK``)
#          if the final component is a symlink. Atomic: there is no
#          stat-then-open TOCTOU because the check is in the open syscall.
#
# Windows: No ``O_NOFOLLOW`` equivalent. Use ``os.lstat`` and reject if
#          ``stat.S_ISLNK(mode)`` is True OR
#          ``st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`` is set.
#          The Windows path is NOT atomic against a TOCTOU swap between
#          the lstat and the subsequent open; this is a known Windows
#          limitation and documented for the §AI CI matrix.

# Windows reparse-point attribute (defined in winnt.h; mirrored by Python's
# ``stat`` module as ``FILE_ATTRIBUTE_REPARSE_POINT`` on Windows builds).
# Defined as a module-level constant so the POSIX branch can reference the
# symbol without a Windows-only import.
_FILE_ATTRIBUTE_REPARSE_POINT: Final[int] = 0x0400


class SymlinkRejectedError(OSError):
    """Raised when a path is rejected because the final component is a symlink.

    The exception is a subclass of :class:`OSError` so callers that catch
    broad filesystem errors still see it, but a structured
    :attr:`envelope` is also exposed for callers that branch on the
    wire-stable ``RELAY-EVID-024`` / ``path_violation`` discriminator.
    """

    def __init__(self, offending_path: str, reason: str) -> None:
        super().__init__(f"symlink rejected at {offending_path!r}: {reason}")
        self.offending_path: Final[str] = offending_path
        self.reason: Final[str] = reason

    @property
    def envelope(self) -> dict[str, Any]:
        """Structured rejection envelope matching ``check_artifact_path``.

        Wire-stable shape. Downstream tooling MUST branch on
        ``code`` + ``path_violation`` and not on the exception type
        alone (the type may evolve; the envelope keys do not).
        """
        return {
            "code": RELAY_EVID_024,
            "path_violation": "symlink_unsafe",
            "offending_path": self.offending_path,
            "reason": self.reason,
        }


def _is_symlink_errno(err: OSError) -> bool:
    """Return True if ``err.errno`` indicates a symlink-at-final-component.

    On Linux ``O_NOFOLLOW`` returns ``ELOOP``. Historical BSDs (and some
    legacy filesystems) return ``EMLINK`` for the same condition. The
    helper accepts both so we do not silently mis-classify the reject
    under exotic POSIX variants.
    """
    return err.errno in (errno.ELOOP, errno.EMLINK)


def read_bytes_symlink_safe(path: Path) -> bytes:
    """Read ``path`` as bytes, refusing to dereference final-component symlinks.

    Cross-platform contract:

    * **POSIX** (``os.name != "nt"``): uses
      ``os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)``. If
      the final component is a symlink, the kernel raises ``OSError``
      with ``errno`` set to ``ELOOP`` (or ``EMLINK`` on some BSDs);
      this is translated into :class:`SymlinkRejectedError`. The check
      is atomic with the open: there is no stat-then-open TOCTOU
      window.
    * **Windows** (``os.name == "nt"``): uses ``os.lstat`` to inspect
      the path WITHOUT dereferencing, then rejects if either
      ``stat.S_ISLNK(mode)`` is True (Windows symlinks) or
      ``st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`` is set
      (junction points, mount points, OneDrive cloud files, WSL
      symlinks, and other reparse-point variants). The Windows path
      is NOT atomic; a swap between the ``lstat`` and the subsequent
      ``open`` would not be caught. This is a documented Windows
      limitation; in practice the Windows OSS deployment runs the
      verifier against a directory the same process just wrote to,
      narrowing the attacker window.

    The helper is the single chokepoint for bundle/manifest filesystem
    reads in the verifier. Callers MUST route every persistent-on-disk
    read for caller-supplied paths through this function. Use of
    :meth:`pathlib.Path.read_bytes` or :func:`builtins.open` on a
    caller-supplied bundle/manifest path is a §AI banned pattern.

    Parameters
    ----------
    path:
        Filesystem path to read. Must point at a regular file under a
        directory the caller has either created or validated. Symlinks
        on intermediate path components are out of scope.

    Returns
    -------
    bytes
        The full file contents.

    Raises
    ------
    SymlinkRejectedError
        The final path component is a symlink (POSIX) or a reparse
        point (Windows). The exception carries the wire-stable
        ``RELAY-EVID-024`` / ``path_violation = "symlink_unsafe"``
        envelope via :attr:`SymlinkRejectedError.envelope`.
    FileNotFoundError
        ``path`` does not exist and is not a symlink. ``ENOENT`` on a
        plain non-existent path is NOT classified as a symlink reject
        (avoids an information-leak oracle).
    OSError
        Other filesystem errors (``EISDIR`` for directories, ``EACCES``
        for permission errors, etc.) propagate unchanged.
    """
    fspath = os.fspath(path)

    if os.name == "nt":
        # Windows: no O_NOFOLLOW. Inspect with lstat (does not follow),
        # then read via Path.read_bytes if and only if the entry is a
        # plain regular file.
        try:
            st = os.lstat(fspath)
        except FileNotFoundError:
            raise
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            raise SymlinkRejectedError(
                offending_path=fspath,
                reason="windows-symlink-rejected",
            )
        # Reparse points (junctions, mount points, OneDrive cloud files,
        # WSL symlinks) carry FILE_ATTRIBUTE_REPARSE_POINT. The
        # attribute may be absent on non-NTFS filesystems; guard with
        # getattr.
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise SymlinkRejectedError(
                offending_path=fspath,
                reason="windows-reparse-point-rejected",
            )
        # Cleared the lstat-based check; fall through to a plain read.
        # The Windows path is non-atomic: a swap between this point and
        # the read below would not be caught. Documented limitation.
        return Path(fspath).read_bytes()

    # POSIX path. O_NOFOLLOW is the atomic check.
    flags = os.O_RDONLY | os.O_NOFOLLOW
    # O_CLOEXEC is best-effort: not all POSIX platforms expose it as a
    # flag (notably very old macOS). Add it when available so a forked
    # child cannot inherit the bundle descriptor.
    cloexec = getattr(os, "O_CLOEXEC", 0)
    flags |= cloexec

    try:
        fd = os.open(fspath, flags)
    except OSError as exc:
        if _is_symlink_errno(exc):
            raise SymlinkRejectedError(
                offending_path=fspath,
                reason=f"posix-o-nofollow:errno={errno.errorcode.get(exc.errno, exc.errno)}",
            ) from exc
        # ENOENT on a plain non-existent path -> FileNotFoundError.
        # EISDIR / EACCES / etc. -> bubble unchanged.
        raise

    try:
        # Defensive: even after O_NOFOLLOW succeeded, fstat the open fd
        # and refuse to read anything that is not a regular file. This
        # closes the (theoretical) corner case where a POSIX exotic
        # opens a device or FIFO at the final component without
        # tripping O_NOFOLLOW.
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            if stat.S_ISDIR(st.st_mode):
                raise IsADirectoryError(
                    errno.EISDIR,
                    os.strerror(errno.EISDIR),
                    fspath,
                )
            raise OSError(
                errno.EINVAL,
                f"refusing to read non-regular file mode={oct(st.st_mode)}",
                fspath,
            )

        # Read in chunks until EOF. Bundle/manifest files are small
        # (a few MB at most) but a single os.read may short-read on
        # large files; loop to drain.
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 1 << 20)  # 1 MiB
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


__all__ = [
    "MAX_ARTIFACT_PATH_BYTES",
    "RELAY_EVID_024",
    "SymlinkRejectedError",
    "check_artifact_path",
    "read_bytes_symlink_safe",
]
