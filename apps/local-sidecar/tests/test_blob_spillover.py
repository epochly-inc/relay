"""VAL-W2-038 + VAL-W2-039: blob spillover for oversize payloads.

The W2.5 ``blob_storage.maybe_spillover`` helper writes payloads exceeding
``RELAY_BLOB_SPILLOVER_BYTES`` (default 16 KiB) to
``${RELAY_HOME}/evidence/blobs/<sha256-hex>`` via
``local_atomic_file_write``. The on-row payload then carries only
``{"_blob_sha256": "<hex>"}``.

VAL-W2-039 enforces that the write goes through the atomic primitive:
``rg "open(.*evidence/blobs.*['\"]w['\"]" apps/local-sidecar/`` returns
empty. A repo-tree regex test mirrors that grep here.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest
from relay_sidecar.blob_storage import (
    BLOB_REF_KEY,
    DEFAULT_BLOB_SPILLOVER_BYTES,
    maybe_spillover,
    spillover_threshold,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_small_payload_passes_inline(relay_home_tmp: Path) -> None:
    """Under-threshold payload returns unchanged."""
    payload = {"event": "x", "size": "small"}
    result = maybe_spillover(payload, home=relay_home_tmp)
    assert result == payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_oversize_payload_spills_to_blob(relay_home_tmp: Path) -> None:
    """Over-threshold payload writes a blob and returns the digest envelope."""
    big = {"_blob_sha256": "a", "filler": "x" * (DEFAULT_BLOB_SPILLOVER_BYTES + 8)}
    result = maybe_spillover(big, home=relay_home_tmp)
    assert BLOB_REF_KEY in result, result
    assert len(result) == 1, result
    digest = result[BLOB_REF_KEY]
    blob_path = relay_home_tmp / "evidence" / "blobs" / digest
    assert blob_path.is_file(), blob_path
    # Verify the file content matches the recorded digest.
    body = blob_path.read_bytes()
    assert hashlib.sha256(body).hexdigest() == digest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX permission bits not directly observable on Windows; "
        "ACL hardening covered by separate Windows tests."
    ),
)
def test_blob_file_mode_is_0600(relay_home_tmp: Path) -> None:
    """The spilled blob file MUST have mode 0o600 on POSIX."""
    big = {"_blob_sha256": "a", "filler": "y" * (DEFAULT_BLOB_SPILLOVER_BYTES + 8)}
    result = maybe_spillover(big, home=relay_home_tmp)
    digest = result[BLOB_REF_KEY]
    blob_path = relay_home_tmp / "evidence" / "blobs" / digest
    mode = stat.S_IMODE(blob_path.stat().st_mode)
    assert mode == 0o600, oct(mode)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_threshold_env_override(
    relay_home_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RELAY_BLOB_SPILLOVER_BYTES env override raises the threshold."""
    monkeypatch.setenv("RELAY_BLOB_SPILLOVER_BYTES", "1048576")  # 1 MiB
    assert spillover_threshold() == 1048576
    payload = {"data": "x" * (DEFAULT_BLOB_SPILLOVER_BYTES + 64)}
    # Under the new 1 MiB threshold, the payload no longer spills.
    result = maybe_spillover(payload, home=relay_home_tmp)
    assert BLOB_REF_KEY not in result, result


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_threshold_invalid_env_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Garbage / non-positive env values fall back to the safe default."""
    monkeypatch.setenv("RELAY_BLOB_SPILLOVER_BYTES", "not-a-number")
    assert spillover_threshold() == DEFAULT_BLOB_SPILLOVER_BYTES
    monkeypatch.setenv("RELAY_BLOB_SPILLOVER_BYTES", "0")
    assert spillover_threshold() == DEFAULT_BLOB_SPILLOVER_BYTES
    monkeypatch.setenv("RELAY_BLOB_SPILLOVER_BYTES", "-5")
    assert spillover_threshold() == DEFAULT_BLOB_SPILLOVER_BYTES


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_identical_payload_same_digest(relay_home_tmp: Path) -> None:
    """Content-addressed: two writes of the same payload produce one file."""
    big = {"_blob_sha256": "a", "x": "z" * (DEFAULT_BLOB_SPILLOVER_BYTES + 4)}
    a = maybe_spillover(big, home=relay_home_tmp)
    b = maybe_spillover(dict(big), home=relay_home_tmp)
    assert a[BLOB_REF_KEY] == b[BLOB_REF_KEY]
    # Exclude the sibling ``.<name>.wlock`` advisory-lock files introduced
    # by local_atomic_file_write in W3.1 (stable lock-file inode required
    # for VAL-W3-006 concurrent append serialization). The wlock file is
    # bookkeeping, not a blob.
    files = [
        p
        for p in (relay_home_tmp / "evidence" / "blobs").iterdir()
        if not p.name.endswith(".wlock")
    ]
    assert len(files) == 1, files


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-038")
def test_blob_payload_passes_sql_check(relay_home_tmp: Path) -> None:
    """The on-row replacement {_blob_sha256: ...} contains none of the
    raw-plaintext JSON keys ('"prompt":', '"completion":', '"messages":')
    so a direct INSERT of the spilled payload MUST pass the SQL check.
    """
    big = {
        "prompt": "secret prompt data" * 2048,
        "completion": "secret completion" * 2048,
    }
    on_row = maybe_spillover(big, home=relay_home_tmp)
    # No raw JSON keys in the on-row form.
    serial = json.dumps(on_row, sort_keys=True)
    assert '"prompt":' not in serial, serial
    assert '"completion":' not in serial, serial
    assert '"_blob_sha256":' in serial, serial


# ---- VAL-W2-039 grep guard mirror ----

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FORBIDDEN_BLOB_OPEN_PATTERN = re.compile(
    r"open\([^)]*evidence/blobs[^)]*['\"]w['\"]"
)


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        p
        for p in root.rglob("*.py")
        if "_generated" not in p.parts and "__pycache__" not in p.parts
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-039")
def test_no_direct_open_on_blobs() -> None:
    """No code under apps/local-sidecar/ opens evidence/blobs/* for write.

    All blob writes MUST route through ``local_atomic_file_write``.
    Mirrors the VAL-W2-039 grep guard: rg
    "open(.*evidence/blobs.*['\"]w['\"]" apps/local-sidecar/ MUST be empty.
    """
    sidecar_root = _REPO_ROOT / "apps" / "local-sidecar"
    offenders: list[tuple[Path, int, str]] = []
    for path in _python_files(sidecar_root):
        # Skip self-referential test bodies that intentionally name the
        # forbidden pattern in their own regex string.
        if path.name == "test_blob_spillover.py":
            continue
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if _FORBIDDEN_BLOB_OPEN_PATTERN.search(line):
                offenders.append((path, line_no, line.strip()))
    assert not offenders, (
        "VAL-W2-039 violated: direct open() on evidence/blobs/* outside "
        "local_atomic_file_write:\n"
        + "\n".join(f"  {p}:{ln} -> {src}" for p, ln, src in offenders)
    )


# Pyflakes pacifier for an otherwise-unused import.
_ = os
