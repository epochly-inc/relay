"""W12.5 build driver plumbing tests.

Tests the ``scripts/build-sidecar-bundle.py`` driver in dry-run mode
(no PyInstaller dependency required). Exercises the canonical
five-arch matrix (VAL-W12-020), SHA-256 digest computation
(VAL-W12-027), and the matrix-pin guard that rejects out-of-matrix
cells.

Per CLAUDE.md TDD discipline: tests use ``@pytest.mark.fulfills`` to
bind to contract assertions. ASCII-only source per CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
BUILD_DRIVER: Path = REPO_ROOT / "scripts" / "build-sidecar-bundle.py"

CANONICAL_MATRIX: tuple[tuple[str, str], ...] = (
    ("macos", "x86_64"),
    ("macos", "arm64"),
    ("linux", "x86_64"),
    ("linux", "arm64"),
    ("windows", "x86_64"),
)


# ---------------------------------------------------------------------------
# Invocation helpers.
# ---------------------------------------------------------------------------


def _run_driver(
    args: list[str], cwd: Path | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BUILD_DRIVER), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd) if cwd else None,
    )


# ---------------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_build_driver_exists_with_shebang_and_is_ascii() -> None:
    assert BUILD_DRIVER.is_file(), f"build driver missing at {BUILD_DRIVER}"
    text = BUILD_DRIVER.read_text(encoding="utf-8")
    assert text.startswith("#!"), "build driver missing shebang"
    text.encode("ascii")  # ASCII-safe per CLAUDE.md


# ---------------------------------------------------------------------------
# VAL-W12-020 -- canonical five-arch matrix pin.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-020")
def test_dry_run_all_cells_produces_full_matrix_manifest(
    tmp_path: Path,
) -> None:
    out_root = tmp_path / "out"
    manifest_path = tmp_path / "manifest.json"
    proc = _run_driver(
        [
            "--dry-run",
            "--out-root",
            str(out_root),
            "--manifest-out",
            str(manifest_path),
        ]
    )
    assert proc.returncode == 0, (
        f"driver exited {proc.returncode}: stdout={proc.stdout!r} "
        f"stderr={proc.stderr!r}"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == "relay.sidecar-bundle-manifest.v1"
    assert manifest["matrix_complete"] is True
    cells_in_manifest = {(e["os"], e["arch"]) for e in manifest["entries"]}
    assert cells_in_manifest == set(CANONICAL_MATRIX), (
        f"manifest cells {cells_in_manifest} != canonical {set(CANONICAL_MATRIX)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-020")
def test_out_of_matrix_cell_is_rejected(tmp_path: Path) -> None:
    """The driver MUST refuse to build a cell not in the canonical matrix.

    Adding a new arch (e.g., linux-armv7) requires a board-level
    decision per the contract.
    """
    proc = _run_driver(
        [
            "--dry-run",
            "--cell",
            "linux-armv7",  # not in canonical matrix
            "--out-root",
            str(tmp_path / "out"),
        ]
    )
    assert proc.returncode != 0, (
        "driver accepted out-of-matrix cell linux-armv7; should have rejected"
    )
    assert "canonical matrix" in proc.stderr.lower() or "canonical" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# VAL-W12-027 -- SHA-256 digest computation.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-027")
def test_manifest_records_sha256_per_cell(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    manifest_path = tmp_path / "manifest.json"
    proc = _run_driver(
        [
            "--dry-run",
            "--cell",
            "linux-x86_64",
            "--out-root",
            str(out_root),
            "--manifest-out",
            str(manifest_path),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["entries"]) == 1
    entry = manifest["entries"][0]
    assert entry["os"] == "linux"
    assert entry["arch"] == "x86_64"
    # Digest matches what we compute over the produced artifact bytes.
    artifact = Path(entry["artifact_path"])
    assert artifact.is_file(), f"artifact missing at {artifact}"
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert entry["sha256"] == expected, (
        f"manifest sha256 {entry['sha256']!r} != computed {expected!r}"
    )
    assert entry["size_bytes"] == artifact.stat().st_size


# ---------------------------------------------------------------------------
# Windows artifact path -- PyInstaller appends .exe; the driver MUST
# locate the .exe variant for Windows cells.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-020")
def test_windows_cell_emits_exe_artifact_path(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    manifest_path = tmp_path / "manifest.json"
    proc = _run_driver(
        [
            "--dry-run",
            "--cell",
            "windows-x86_64",
            "--out-root",
            str(out_root),
            "--manifest-out",
            str(manifest_path),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = manifest["entries"][0]
    assert entry["artifact_path"].endswith(".exe"), (
        f"windows artifact path should end with .exe; got {entry['artifact_path']!r}"
    )


# ---------------------------------------------------------------------------
# Stdout (no --manifest-out) emits JSON.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_driver_emits_json_on_stdout_without_manifest_out(
    tmp_path: Path,
) -> None:
    proc = _run_driver(
        [
            "--dry-run",
            "--cell",
            "linux-x86_64",
            "--out-root",
            str(tmp_path / "out"),
        ]
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads(proc.stdout)
    assert manifest["schema"] == "relay.sidecar-bundle-manifest.v1"
    assert manifest["matrix_complete"] is False  # only 1 of 5 cells built
