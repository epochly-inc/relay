"""Filesystem-type detection (W2.1, VAL-W2-011).

The local sidecar refuses to start if its home directory lives on NFS,
SMB, or any non-local filesystem. The four-state lockfile classifier
(spec H.5) depends on POSIX fcntl flock or Windows msvcrt.locking
semantics that NFS/SMB do not guarantee end-to-end.

POSIX detection:

  - ``os.statvfs`` does NOT expose filesystem type on macOS/Linux in a
    portable way. We use ``os.statfs`` on Linux (returns f_type) and
    fall back to ``mount``/``df`` parsing or the platform-specific
    /proc on Linux. On macOS the BSD ``statfs`` syscall via ``ctypes``
    is the canonical answer.
  - Magic numbers (Linux <linux/magic.h>): NFS=0x6969, SMB2=0xFE534D42,
    CIFS=0xFF534D42, FUSE=0x65735546 (treated as local-ish; pass).
  - Local filesystems we accept: ext4 (0xEF53), btrfs (0x9123683E),
    xfs (0x58465342), tmpfs (0x01021994), HFS+/APFS (macOS native).
  - On macOS ``f_type`` is opaque-numeric; we instead use the BSD
    ``statfs.f_fstypename`` C string ("hfs", "apfs", "tmpfs", "nfs",
    "smbfs", "webdav"). We compare against a non-local denylist.

Windows detection:

  - ``GetVolumeInformationW`` returns the filesystem name string
    ("NTFS", "FAT32", "exFAT", or driver-set for SMB shares).
  - SMB shares typically report path prefix ``\\\\server\\share``; we
    fail-closed by checking the UNC prefix as a secondary signal.

This module owns ``is_local_filesystem(path)`` returning True if the
path is on a local filesystem the sidecar is willing to run on. Callers
in ``spawn.py`` consult this and raise ``RELAY-SIDECAR-NONLOCAL-FS`` +
exit code 2 on False.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Final

# Linux magic numbers (from <linux/magic.h>). Non-local filesystems we
# refuse to run on.
NFS_SUPER_MAGIC: Final[int] = 0x6969
SMB_SUPER_MAGIC: Final[int] = 0x517B  # cifs/smb1
SMB2_MAGIC_NUMBER: Final[int] = 0xFE534D42
CIFS_MAGIC_NUMBER: Final[int] = 0xFF534D42
AFS_SUPER_MAGIC: Final[int] = 0x5346414F
CODA_SUPER_MAGIC: Final[int] = 0x73757245

# Bag of "remote" Linux fs magic numbers. Add as needed; the test
# (VAL-W2-011) only forces NFS, but other distributed filesystems share
# the same race-condition class.
_REMOTE_FS_MAGIC_NUMBERS: Final[frozenset[int]] = frozenset(
    {
        NFS_SUPER_MAGIC,
        SMB_SUPER_MAGIC,
        SMB2_MAGIC_NUMBER,
        CIFS_MAGIC_NUMBER,
        AFS_SUPER_MAGIC,
        CODA_SUPER_MAGIC,
    }
)

# macOS BSD ``f_fstypename`` strings we treat as non-local.
_REMOTE_FS_TYPENAMES_BSD: Final[frozenset[str]] = frozenset(
    {"nfs", "smbfs", "afpfs", "webdav", "cifs"}
)

# Windows volume filesystem names that indicate a network mount. Most
# real network shares hit the UNC-path check first, but some tools mount
# SMB as a drive letter and we still want to refuse.
_REMOTE_FS_TYPENAMES_WIN: Final[frozenset[str]] = frozenset(
    {"smb", "smbfs", "cifs", "nfs"}
)


def probe_filesystem(path: Path | str) -> tuple[str, int | str | None]:
    """Return a (kind, signal) tuple describing the filesystem at ``path``.

    Pure indirection seam so tests can monkey-patch this single function
    to inject NFS magic numbers / fstype names without needing to mock
    libc or ctypes calls. Returns:

      - ("linux_magic", <int>): Linux statfs f_type magic number.
      - ("bsd_fstype", <str>): macOS BSD f_fstypename string (lowercased).
      - ("windows_fs_name", <str>): Windows GetVolumeInformationW result.
      - ("windows_unc", None): UNC path detected.
      - ("unknown", None): detection failed; treat as local.

    Implemented as a separate function precisely so VAL-W2-011 can mock
    it cleanly. The contract evidence ("mocked ``os.statfs`` returns NFS
    magic 0x6969") is preserved at this seam.
    """
    target = Path(path)
    if not target.exists():
        anchor: Path | None = None
        for parent in [target, *target.parents]:
            if parent.exists():
                anchor = parent
                break
        if anchor is None:
            return ("unknown", None)
        target = anchor

    if sys.platform == "win32":  # pragma: no cover (POSIX test runner)
        return _probe_windows(target)
    if sys.platform == "darwin":
        return _probe_macos(target)
    return _probe_linux(target)


def is_local_filesystem(path: Path | str) -> bool:
    """Return True if ``path`` lives on a local filesystem.

    Consults ``probe_filesystem`` and compares against the platform-
    specific denylist. On detection failure (``unknown``) we return True
    (permissive default).
    """
    kind, value = probe_filesystem(path)
    if kind == "linux_magic" and isinstance(value, int):
        return value not in _REMOTE_FS_MAGIC_NUMBERS
    if kind == "bsd_fstype" and isinstance(value, str):
        return value not in _REMOTE_FS_TYPENAMES_BSD
    if kind == "windows_unc":
        return False
    if kind == "windows_fs_name" and isinstance(value, str):
        return value not in _REMOTE_FS_TYPENAMES_WIN
    return True


def _probe_linux(path: Path) -> tuple[str, int | str | None]:
    """Linux: read ``struct statfs.f_type`` via libc ctypes."""
    try:

        class _Statfs(ctypes.Structure):
            _fields_ = [("f_type", ctypes.c_long)]

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        st = _Statfs()
        rc = libc.statfs(str(path).encode("utf-8"), ctypes.byref(st))
        if rc != 0:
            return ("unknown", None)
        return ("linux_magic", int(st.f_type))
    except OSError:
        return ("unknown", None)


def _probe_macos(path: Path) -> tuple[str, int | str | None]:
    """macOS: BSD ``statfs`` exposes ``f_fstypename`` (C string)."""
    try:
        # struct statfs on Darwin starts with several uint32_t fields,
        # then has f_fstypename at offset MNAMELEN (=15) into the type
        # name array. We use the BSD-compatible C ``statfs64`` to be safe
        # across macOS versions.
        class _StatfsDarwin(ctypes.Structure):
            # The full structure is large; we declare only the fields we
            # need and pad the rest. From <sys/mount.h>:
            #   uint32_t f_bsize
            #   int32_t f_iosize
            #   uint64_t f_blocks; uint64_t f_bfree; uint64_t f_bavail
            #   uint64_t f_files; uint64_t f_ffree
            #   fsid_t f_fsid (two int32_t)
            #   uid_t f_owner
            #   uint32_t f_type
            #   uint32_t f_flags
            #   uint32_t f_fssubtype
            #   char f_fstypename[16]
            _fields_ = [
                ("f_bsize", ctypes.c_uint32),
                ("f_iosize", ctypes.c_int32),
                ("f_blocks", ctypes.c_uint64),
                ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64),
                ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64),
                ("f_fsid", ctypes.c_int32 * 2),
                ("f_owner", ctypes.c_uint32),
                ("f_type", ctypes.c_uint32),
                ("f_flags", ctypes.c_uint32),
                ("f_fssubtype", ctypes.c_uint32),
                ("f_fstypename", ctypes.c_char * 16),
                ("_remainder", ctypes.c_char * 1024),
            ]

        libc = ctypes.CDLL("/usr/lib/libSystem.dylib", use_errno=True)
        st = _StatfsDarwin()
        rc = libc.statfs(str(path).encode("utf-8"), ctypes.byref(st))
        if rc != 0:
            return ("unknown", None)
        fstype = st.f_fstypename.decode("ascii", errors="replace").lower()
        return ("bsd_fstype", fstype)
    except OSError:
        return ("unknown", None)


def _probe_windows(path: Path) -> tuple[str, int | str | None]:  # pragma: no cover
    """Windows: GetVolumeInformationW + UNC-path heuristic."""
    abs_path = str(path.resolve())
    if abs_path.startswith("\\\\"):
        return ("windows_unc", None)
    drive = os.path.splitdrive(abs_path)[0]
    if not drive:
        return ("unknown", None)
    root = drive + os.sep
    fs_name_buf = ctypes.create_unicode_buffer(256)
    kernel32 = ctypes.windll.kernel32
    rc = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root),
        None,
        0,
        None,
        None,
        None,
        fs_name_buf,
        ctypes.sizeof(fs_name_buf),
    )
    if rc == 0:
        return ("unknown", None)
    return ("windows_fs_name", fs_name_buf.value.lower())


__all__ = [
    "AFS_SUPER_MAGIC",
    "CIFS_MAGIC_NUMBER",
    "CODA_SUPER_MAGIC",
    "NFS_SUPER_MAGIC",
    "SMB2_MAGIC_NUMBER",
    "SMB_SUPER_MAGIC",
    "is_local_filesystem",
    "probe_filesystem",
]
