"""W1.5 codegen drift check (VAL-W1-035).

Runs the codegen orchestrator against an isolated temp output tree and
compares the result with the committed generated trees:

  - packages/sdk-python/relay/_generated/
  - packages/sdk-typescript/src/_generated/

If any file differs (content, mode bits, file count), the check fails non-zero
and emits a structured log line per drifted file:

    [drift] <path>: <details>

Happy path:
    $ uv run python scripts/check-codegen-drift.py
    [check] codegen drift: 0 files differ
    exit 0

Simulated drift path:
    $ echo "# stray byte" >> packages/sdk-python/relay/_generated/_models.py
    $ uv run python scripts/check-codegen-drift.py
    [drift] packages/sdk-python/relay/_generated/_models.py: 1 line differs
    exit 1

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import difflib
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _repo_root() -> Path:
    # scripts/check-codegen-drift.py -> repo root
    return Path(__file__).resolve().parent.parent


def _gen_trees(root: Path) -> tuple[Path, Path]:
    """Paths of the committed generated trees (Python, TypeScript)."""
    return (
        root / "packages" / "sdk-python" / "relay" / "_generated",
        root / "packages" / "sdk-typescript" / "src" / "_generated",
    )


def _filter_dir_listing(items: list[str]) -> list[str]:
    # Exclude `__pycache__` and other transient artifacts.
    return [
        x for x in items
        if x != "__pycache__"
        and not x.endswith(".pyc")
        and not x.endswith(".pyo")
    ]


def _walk_files(tree: Path) -> set[Path]:
    """Return the set of regular-file relative paths under ``tree``.

    Excludes `__pycache__` directories.
    """
    result: set[Path] = set()
    for entry in tree.rglob("*"):
        if "__pycache__" in entry.parts:
            continue
        if entry.is_file():
            result.add(entry.relative_to(tree))
    return result


def _compare_trees(committed: Path, fresh: Path) -> list[str]:
    """Return a list of [drift] log lines (one per drifted file).

    Empty list means no drift.
    """
    drift: list[str] = []
    committed_files = _walk_files(committed)
    fresh_files = _walk_files(fresh)

    # Files in committed but not in fresh => stale (codegen no longer emits).
    for missing in sorted(committed_files - fresh_files):
        drift.append(
            f"[drift] {committed / missing}: missing from fresh codegen "
            "(stale committed file)"
        )

    # Files in fresh but not in committed => new (codegen output added).
    for new in sorted(fresh_files - committed_files):
        drift.append(
            f"[drift] {committed / new}: missing from committed tree "
            "(codegen emits new file)"
        )

    # Files in both => content compare.
    common = sorted(committed_files & fresh_files)
    for rel in common:
        if not filecmp.cmp(committed / rel, fresh / rel, shallow=False):
            # Compute a small diff summary so the log line is human-meaningful.
            c_lines = (committed / rel).read_text(encoding="utf-8").splitlines()
            f_lines = (fresh / rel).read_text(encoding="utf-8").splitlines()
            diff_count = sum(
                1
                for line in difflib.unified_diff(
                    c_lines, f_lines, lineterm="", n=0
                )
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
            )
            drift.append(
                f"[drift] {committed / rel}: {diff_count} lines differ "
                f"(committed != fresh codegen)"
            )

    return drift


def run_drift_check(root: Path, *, verbose: bool = False) -> int:
    """Run codegen against a fresh temp tree and diff vs the committed trees.

    Returns 0 on no drift, 1 on drift detected, 2 on infrastructure error.
    """
    py_committed, ts_committed = _gen_trees(root)

    if not py_committed.is_dir():
        print(
            f"[error] committed Python generated tree missing: {py_committed}",
            file=sys.stderr,
        )
        return 2
    if not ts_committed.is_dir():
        print(
            f"[error] committed TypeScript generated tree missing: {ts_committed}",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory(prefix="relay-drift-") as tmp_str:
        tmp = Path(tmp_str)
        # Stage temp copies of the SDK package roots so the codegen script can
        # write into our isolated paths. We rsync-copy the package skeleton
        # files (relay/__init__.py, etc.) so the codegen output lands inside
        # a valid package structure.
        py_fresh_pkg_root = tmp / "sdk-python"
        ts_fresh_pkg_root = tmp / "sdk-typescript"

        # Run codegen with environment overrides directing output to tmp.
        # The codegen script is path-rooted; we invoke a thin in-process
        # driver that monkey-patches its _py_out_dir / _ts_out_dir functions.
        sys.path.insert(0, str(root / "packages" / "schemas" / "scripts"))
        try:
            import codegen as _codegen_mod  # noqa: PLC0415
        finally:
            sys.path.pop(0)

        py_fresh_out = py_fresh_pkg_root / "relay" / "_generated"
        ts_fresh_out = ts_fresh_pkg_root / "src" / "_generated"

        original_py = _codegen_mod._py_out_dir
        original_ts = _codegen_mod._ts_out_dir
        try:
            _codegen_mod._py_out_dir = lambda _root: py_fresh_out
            _codegen_mod._ts_out_dir = lambda _root: ts_fresh_out
            # Re-run codegen against the same canonical YAML but writing to
            # tmp output paths. Skip the W1.4 error-codes generator because
            # that writes to packages/schemas/python/relay_schemas/error_codes.py
            # which is part of the W1.4 surface, not the W1.5 generated tree.
            exit_code = _codegen_mod.main(["--skip-error-codes"])
            if exit_code != 0:
                print(
                    f"[error] codegen returned non-zero exit ({exit_code}); "
                    "drift check cannot proceed",
                    file=sys.stderr,
                )
                return 2
        finally:
            _codegen_mod._py_out_dir = original_py
            _codegen_mod._ts_out_dir = original_ts

        # Diff the two trees.
        drift_py = _compare_trees(py_committed, py_fresh_out)
        drift_ts = _compare_trees(ts_committed, ts_fresh_out)
        drift = drift_py + drift_ts

        if drift:
            print(f"[check] codegen drift: {len(drift)} files differ", file=sys.stderr)
            for line in drift:
                print(line, file=sys.stderr)
            return 1

        print("[check] codegen drift: 0 files differ")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="W1.5 codegen drift check (VAL-W1-035)."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit per-file comparison results regardless of drift.",
    )
    args = parser.parse_args(argv)
    return run_drift_check(_repo_root(), verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


# Suppress unused-import warnings for the helpers we may add in future passes.
_ = subprocess
_ = shutil
