#!/usr/bin/env python3
"""W12.5 PyInstaller sidecar bundle build driver.

Invokes PyInstaller against ``apps/local-sidecar/pyinstaller/relay-sidecar.spec``
for a single (OS, arch) cell of the canonical five-arch matrix declared by
VAL-W12-020:

    1. macOS-x86_64    (darwin-amd64)
    2. macOS-arm64     (darwin-arm64)
    3. linux-x86_64    (linux-amd64)
    4. linux-arm64     (linux-aarch64)
    5. windows-x86_64  (windows-amd64)

The driver:

  1. Derives the per-cell binary name (``relay-sidecar-<os>-<arch>``) and
     exports it as ``PYINSTALLER_OUTPUT_NAME`` so the single spec file
     produces correctly-named output (see the spec's OUTPUT_NAME block).
  2. Runs ``pyinstaller`` against the spec with the cell's distpath +
     workpath isolated from other cells.
  3. Computes the SHA-256 of the produced binary and emits a structured
     manifest entry on stdout for the release workflow to consume.
  4. Refuses to embed any signing key material (CLAUDE.md banned #14);
     signing is performed post-build by the release workflow against
     Sigstore Fulcio + Rekor.

Exit codes:
    0  build succeeded; manifest entry on stdout
    1  build failed (PyInstaller non-zero exit)
    2  spec file or build artifact missing
    3  invalid invocation

Per CLAUDE.md "ASCII-Safe Source": ASCII-only.
Per CLAUDE.md keystone #3: this script is invoked through the manifest-
declared ``build-sidecar-bundle`` command, not ad-hoc.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Canonical four-arch matrix per VAL-W12-020 (revised 2026-05-28).
# Adding to this requires a board-level decision (orchestrator
# sidecar-bundle-arch pin). macos-x86_64 was removed on 2026-05-28 by
# board-level decision (GitHub Intel-macOS runner pool starvation,
# Apple 2022 Intel discontinuation, Rosetta fallback). See CHANGELOG
# v0.1.16. Further removals require an equivalent board-level decision.
CANONICAL_MATRIX: tuple[tuple[str, str], ...] = (
    ("macos", "arm64"),
    ("linux", "x86_64"),
    ("linux", "arm64"),
    ("windows", "x86_64"),
)

SPEC_RELPATH = Path("apps/local-sidecar/pyinstaller/relay-sidecar.spec")


@dataclass(frozen=True)
class BuildCell:
    """A single (OS, arch) build cell."""

    os: str
    arch: str

    @property
    def slug(self) -> str:
        # Canonical asset suffix used by VAL-W12-020 evidence (gh release view).
        return f"{self.os}-{self.arch}"

    @property
    def binary_name(self) -> str:
        # PyInstaller appends `.exe` on Windows; we record the bare name
        # here and let the spec/PyInstaller add the extension.
        return f"relay-sidecar-{self.slug}"

    def expected_artifact_path(self, distpath: Path) -> Path:
        if self.os == "windows":
            return distpath / f"{self.binary_name}.exe"
        return distpath / self.binary_name


def _parse_cell(value: str) -> BuildCell:
    if "-" not in value:
        raise argparse.ArgumentTypeError(
            f"cell must be '<os>-<arch>' (e.g., 'linux-x86_64'); got '{value}'"
        )
    os_, arch = value.split("-", 1)
    cell = BuildCell(os=os_, arch=arch)
    if (cell.os, cell.arch) not in CANONICAL_MATRIX:
        canonical = ", ".join(f"{o}-{a}" for o, a in CANONICAL_MATRIX)
        raise argparse.ArgumentTypeError(
            f"cell '{value}' is not in the canonical matrix: {canonical}"
        )
    return cell


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_pyinstaller(
    spec_path: Path,
    cell: BuildCell,
    distpath: Path,
    workpath: Path,
    extra_env: dict[str, str] | None = None,
) -> int:
    """Invoke PyInstaller against the spec for this cell.

    The spec reads ``PYINSTALLER_OUTPUT_NAME`` from the environment so a
    single spec file produces correctly-named binaries across the matrix.
    """
    env = os.environ.copy()
    env["PYINSTALLER_OUTPUT_NAME"] = cell.binary_name
    if extra_env:
        env.update(extra_env)

    cmd = [
        "pyinstaller",
        "--clean",
        "--noconfirm",
        "--distpath",
        str(distpath),
        "--workpath",
        str(workpath),
        str(spec_path),
    ]
    proc = subprocess.run(cmd, env=env, check=False)
    return proc.returncode


def build_one(
    cell: BuildCell,
    repo_root: Path,
    distpath: Path,
    workpath: Path,
    dry_run: bool = False,
) -> dict[str, object]:
    """Build a single cell. Returns the manifest entry dict."""
    spec_path = repo_root / SPEC_RELPATH
    if not spec_path.is_file():
        print(f"FAIL: spec file missing at {spec_path}", file=sys.stderr)
        raise SystemExit(2)

    distpath.mkdir(parents=True, exist_ok=True)
    workpath.mkdir(parents=True, exist_ok=True)

    if dry_run:
        # Dry-run mode (for tests + fork CI): produce a placeholder file
        # rather than invoking PyInstaller. This lets the workflow's
        # manifest-assembly + digest steps execute end-to-end without
        # requiring PyInstaller to be installed.
        artifact = cell.expected_artifact_path(distpath)
        artifact.write_bytes(
            f"RELAY-SIDECAR-DRY-RUN-UNSIGNED os={cell.os} arch={cell.arch}\n".encode("ascii")
        )
    else:
        if shutil.which("pyinstaller") is None:
            print(
                "FAIL: pyinstaller not on PATH; install via 'pip install pyinstaller'",
                file=sys.stderr,
            )
            raise SystemExit(2)
        rc = _run_pyinstaller(spec_path, cell, distpath, workpath)
        if rc != 0:
            print(
                f"FAIL: pyinstaller exited {rc} for {cell.slug}",
                file=sys.stderr,
            )
            raise SystemExit(1)

    artifact = cell.expected_artifact_path(distpath)
    if not artifact.is_file():
        print(
            f"FAIL: expected artifact missing at {artifact}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    digest = _sha256(artifact)
    size = artifact.stat().st_size
    return {
        "os": cell.os,
        "arch": cell.arch,
        "slug": cell.slug,
        "binary_name": cell.binary_name,
        "artifact_path": str(artifact),
        "sha256": digest,
        "size_bytes": size,
        "dry_run": dry_run,
    }


def build_all(
    cells: Iterable[BuildCell],
    repo_root: Path,
    out_root: Path,
    dry_run: bool = False,
) -> list[dict[str, object]]:
    """Build a sequence of cells. Each cell gets its own dist/work dirs."""
    entries: list[dict[str, object]] = []
    for cell in cells:
        cell_root = out_root / cell.slug
        entry = build_one(
            cell,
            repo_root=repo_root,
            distpath=cell_root / "dist",
            workpath=cell_root / "build",
            dry_run=dry_run,
        )
        entries.append(entry)
    return entries


def _resolve_repo_root(arg: str | None) -> Path:
    if arg:
        return Path(arg).resolve()
    # Script lives at scripts/build-sidecar-bundle.py; parent of scripts/
    # is the repo root.
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a PyInstaller sidecar bundle for one or more cells.",
    )
    parser.add_argument(
        "--cell",
        type=_parse_cell,
        action="append",
        help=(
            "(OS, arch) cell as '<os>-<arch>' (e.g., 'linux-x86_64'). "
            "Repeatable. Default: every cell in the canonical matrix."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root (default: parent of scripts/).",
    )
    parser.add_argument(
        "--out-root",
        default=None,
        help="Output root (default: <repo-root>/dist/sidecar-bundle).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Skip PyInstaller invocation; produce placeholder binaries. "
            "Used by fork CI (no PyInstaller) and by the test suite."
        ),
    )
    parser.add_argument(
        "--manifest-out",
        default=None,
        help="Write the build manifest JSON to this path instead of stdout.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the manifest as JSON on stdout (default).",
    )
    args = parser.parse_args(argv)

    repo_root = _resolve_repo_root(args.repo_root)
    out_root = (
        Path(args.out_root).resolve()
        if args.out_root
        else repo_root / "dist" / "sidecar-bundle"
    )

    cells: list[BuildCell] = (
        list(args.cell)
        if args.cell
        else [BuildCell(os=o, arch=a) for (o, a) in CANONICAL_MATRIX]
    )

    entries = build_all(cells, repo_root=repo_root, out_root=out_root, dry_run=args.dry_run)
    manifest = {
        "schema": "relay.sidecar-bundle-manifest.v1",
        "matrix_complete": len(entries) == len(CANONICAL_MATRIX),
        "entries": entries,
    }

    payload = json.dumps(manifest, indent=2, sort_keys=True)
    if args.manifest_out:
        Path(args.manifest_out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
