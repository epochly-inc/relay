"""VAL-V3M5-013: cross-platform symlink-safe bundle/manifest reads.

The 2026-05-18 v0.3 audit surfaced that bundle and manifest file reads in
``packages/verifier/src/relay_verifier/bundle_paths.py`` (and callers)
used ``pathlib.Path.read_bytes()`` which silently follows symlinks. An
attacker with write access to a directory used to stage a bundle could:

1. Place a benign regular file at ``bundle.json`` (verifier opens it,
   reads attribute X).
2. Between the check and the read (TOCTOU window), swap that file with
   a symlink to ``/etc/passwd`` or another off-tree target.
3. The verifier dereferences the symlink and reads attacker-chosen
   content under the bundle's authority.

The fix is a cross-platform symlink-safe open primitive:

* POSIX: ``os.open(path, os.O_RDONLY | os.O_NOFOLLOW)`` -- the kernel
  refuses to dereference a symlink at the final path component and
  raises ``ELOOP``.
* Windows: ``os.lstat`` then check ``stat.S_ISLNK`` on the mode, and
  inspect ``st_file_attributes`` for ``FILE_ATTRIBUTE_REPARSE_POINT``.
  Reject before the read if either is set.

This test asserts the behavior at the tier-1 plumbing tier with no
network or large fixture dependencies.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from relay_verifier.bundle_paths import (
    RELAY_EVID_024,
    SymlinkRejectedError,
    read_bytes_symlink_safe,
)


@pytest.mark.plumbing
def test_regular_file_read_succeeds(tmp_path: Path) -> None:
    """A plain regular file is read end-to-end without rejection."""
    target = tmp_path / "manifest.json"
    payload = b'{"schema_version": "relay.bundle.v1"}'
    target.write_bytes(payload)

    got = read_bytes_symlink_safe(target)
    assert got == payload


@pytest.mark.plumbing
@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics test")
def test_symlink_to_regular_file_rejected_posix(tmp_path: Path) -> None:
    """A symlink at the final component is rejected, even if target is benign.

    POSIX path: ``os.open(..., O_NOFOLLOW)`` raises ``OSError`` with
    ``errno == ELOOP``. The helper must translate this into a structured
    ``SymlinkRejectedError`` carrying the ``RELAY-EVID-024`` code and a
    ``path_violation == "symlink_unsafe"`` discriminator so downstream
    tooling can branch deterministically.
    """
    real = tmp_path / "real_bundle.json"
    real.write_bytes(b'{"ok": true}')

    link = tmp_path / "bundle.json"
    os.symlink(real, link)

    with pytest.raises(SymlinkRejectedError) as exc_info:
        read_bytes_symlink_safe(link)

    envelope = exc_info.value.envelope
    assert envelope["code"] == RELAY_EVID_024
    assert envelope["path_violation"] == "symlink_unsafe"
    assert envelope["offending_path"] == str(link)


@pytest.mark.plumbing
@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink-swap TOCTOU test")
def test_symlink_swap_after_creation_rejected_posix(tmp_path: Path) -> None:
    """Simulate the TOCTOU swap: regular file replaced by symlink before read.

    This is the canonical attack: a verifier passes a `Path` it earlier
    saw as regular. Between that observation and the read, the path is
    swapped for a symlink pointing off-tree. ``read_bytes_symlink_safe``
    must reject AT the read syscall, not by re-running an earlier check.
    """
    target = tmp_path / "bundle.json"
    target.write_bytes(b"original")

    offtree = tmp_path / "offtree_secret"
    offtree.write_bytes(b"SECRET")

    # Swap: replace the regular file with a symlink to off-tree content.
    target.unlink()
    os.symlink(offtree, target)

    with pytest.raises(SymlinkRejectedError) as exc_info:
        read_bytes_symlink_safe(target)

    assert exc_info.value.envelope["path_violation"] == "symlink_unsafe"


@pytest.mark.plumbing
@pytest.mark.skipif(os.name == "nt", reason="POSIX dangling-symlink test")
def test_dangling_symlink_rejected_posix(tmp_path: Path) -> None:
    """A symlink whose target does not exist is rejected as symlink, not ENOENT.

    Without the symlink check we would surface ``FileNotFoundError`` and
    leak the symlink existence as an oracle. With ``O_NOFOLLOW`` the
    kernel returns ``ELOOP`` first.
    """
    link = tmp_path / "missing_bundle.json"
    os.symlink(tmp_path / "does_not_exist.json", link)

    with pytest.raises(SymlinkRejectedError):
        read_bytes_symlink_safe(link)


@pytest.mark.plumbing
def test_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    """Non-existent path (no symlink involved) raises FileNotFoundError.

    The helper must NOT translate ``ENOENT`` on a plain non-existent
    path into ``SymlinkRejectedError``; only ``ELOOP`` and the explicit
    Windows reparse-point branch produce a symlink rejection.
    """
    missing = tmp_path / "nope.json"
    with pytest.raises(FileNotFoundError):
        read_bytes_symlink_safe(missing)


@pytest.mark.plumbing
def test_directory_raises_oserror(tmp_path: Path) -> None:
    """Passing a directory raises ``OSError`` (EISDIR), not a silent empty read."""
    with pytest.raises(OSError):
        read_bytes_symlink_safe(tmp_path)


@pytest.mark.plumbing
def test_helper_documents_cross_platform_semantics() -> None:
    """The helper's docstring must document POSIX + Windows semantics.

    A reviewer scanning ``bundle_paths.py`` should see both branches
    documented so the Windows CI matrix is not load-bearing on tribal
    knowledge.
    """
    doc = read_bytes_symlink_safe.__doc__ or ""
    assert "O_NOFOLLOW" in doc, "POSIX branch must be documented"
    assert "reparse" in doc.lower(), "Windows reparse-point branch must be documented"


@pytest.mark.plumbing
@pytest.mark.skipif(os.name == "nt", reason="POSIX stat semantics test")
def test_symlink_to_directory_rejected_posix(tmp_path: Path) -> None:
    """Symlink-to-directory is rejected before any directory read attempt."""
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()

    link = tmp_path / "dir_link"
    os.symlink(real_dir, link)

    with pytest.raises(SymlinkRejectedError):
        read_bytes_symlink_safe(link)


@pytest.mark.plumbing
def test_symlink_rejected_error_carries_envelope_fields() -> None:
    """The exception envelope shape is wire-stable for callers branching on it."""
    err = SymlinkRejectedError(
        offending_path="/tmp/whatever",
        reason="test-fixture",
    )
    env = err.envelope
    assert env["code"] == RELAY_EVID_024
    assert env["path_violation"] == "symlink_unsafe"
    assert env["offending_path"] == "/tmp/whatever"
    assert "reason" in env


@pytest.mark.plumbing
@pytest.mark.skipif(os.name == "nt", reason="POSIX-only mode check")
def test_helper_uses_lstat_not_stat(tmp_path: Path) -> None:
    """Direct probe: the helper must never dereference a symlink probe.

    We construct a symlink whose target is a *different* regular file
    and verify the rejection cites the symlink path, not the resolved
    target path. If the helper followed the symlink for any reason the
    offending_path would be the target's resolved path.
    """
    real = tmp_path / "real.json"
    real.write_bytes(b"real")
    link = tmp_path / "link.json"
    os.symlink(real, link)

    with pytest.raises(SymlinkRejectedError) as exc_info:
        read_bytes_symlink_safe(link)

    # offending_path is reported as the input symlink path, not the
    # symlink target. This is load-bearing for audit log accuracy.
    assert exc_info.value.envelope["offending_path"] == str(link)
    # Sanity: the link is in fact a symlink.
    assert stat.S_ISLNK(os.lstat(link).st_mode)
