"""VAL-W2-011: NFS filesystem detection refuses sidecar startup.

POSIX path: ``probe_filesystem`` returns the f_type magic number. If the
number is in the remote denylist, ``is_local_filesystem`` returns False
and ``acquire_or_attach`` raises ``SidecarError`` with code
``RELAY-SIDECAR-006`` / class ``RELAY-SIDECAR-NONLOCAL-FS`` and exit code 2.

We mock the probe seam directly so the test is OS-agnostic and doesn't
require a real NFS mount. Windows leg is skipped (Windows-only contract
text would use ``GetVolumeInformationW``).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from relay_sidecar import filesystem
from relay_sidecar.errors import (
    RELAY_SIDECAR_NONLOCAL_FS,
    RELAY_SIDECAR_NONLOCAL_FS_CODE,
    SidecarError,
)
from relay_sidecar.spawn import acquire_or_attach

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only NFS test")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-011")
def test_is_local_filesystem_rejects_nfs_magic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mocked probe -> NFS magic number -> is_local_filesystem False."""

    def fake_probe(path: Path | str) -> tuple[str, int | str | None]:
        return ("linux_magic", filesystem.NFS_SUPER_MAGIC)  # 0x6969

    monkeypatch.setattr(filesystem, "probe_filesystem", fake_probe)
    assert filesystem.is_local_filesystem(tmp_path) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-011")
def test_is_local_filesystem_accepts_local_magic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ext4 magic number (0xEF53) is a local fs; not in the denylist."""

    def fake_probe(path: Path | str) -> tuple[str, int | str | None]:
        return ("linux_magic", 0xEF53)

    monkeypatch.setattr(filesystem, "probe_filesystem", fake_probe)
    assert filesystem.is_local_filesystem(tmp_path) is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-011")
def test_is_local_filesystem_rejects_bsd_nfs_fstype(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """macOS BSD fstypename ``nfs`` -> non-local."""

    def fake_probe(path: Path | str) -> tuple[str, int | str | None]:
        return ("bsd_fstype", "nfs")

    monkeypatch.setattr(filesystem, "probe_filesystem", fake_probe)
    assert filesystem.is_local_filesystem(tmp_path) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-011")
def test_acquire_or_attach_raises_nonlocal_fs(
    monkeypatch: pytest.MonkeyPatch, relay_home_tmp: Path
) -> None:
    """Full spawn pipeline refuses with RELAY-SIDECAR-NONLOCAL-FS on NFS."""

    def fake_probe(path: Path | str) -> tuple[str, int | str | None]:
        return ("linux_magic", filesystem.NFS_SUPER_MAGIC)

    monkeypatch.setattr(filesystem, "probe_filesystem", fake_probe)

    with pytest.raises(SidecarError) as exc:
        acquire_or_attach(
            home=relay_home_tmp,
            process_runner=lambda: (os.getpid(), 50090),
        )
    assert exc.value.code == RELAY_SIDECAR_NONLOCAL_FS_CODE
    assert exc.value.error_class == RELAY_SIDECAR_NONLOCAL_FS
    # The lockfile must NOT exist (refusal happens before any write).
    assert not (relay_home_tmp / "sidecar.lock").exists()
