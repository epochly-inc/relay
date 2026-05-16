"""W17.2 build-time test-only HS verifier helper isolation check (VAL-W17-023).

Enforces the C-GAP-003 reconciliation at build time. Two modes:

  * ``--dry-run`` (default for plumbing-tier CI): validates source-tree
    invariants only. No wheel build, no npm pack. Fast (<1s).
  * ``--full`` (release CI): builds the Python wheel and the npm
    tarball, then unpacks each and asserts the helper module path is
    NOT present. Slow (multiple minutes). Required by the release gate
    VAL-W17-020 conformance-release-block.

In either mode, exits 0 on success. On any violation, exits 1 with a
structured ``RELAY-VERIFY-HS-HELPER-LEAKED`` message.

Source-tree invariants asserted by both modes:

  1. Python helper exists ONLY at
     ``tests/conformance/jws/_test_only_hs_verifier.py``.
  2. TypeScript helper exists ONLY at
     ``packages/verifier-typescript/test/_test_only_hs_verifier.ts``.
  3. No file under ``packages/`` or ``apps/`` references the helper.
  4. ``packages/verifier-typescript/package.json`` ``files`` array does
     not include ``test`` or any ``test/...`` path.
  5. ``packages/verifier-typescript/tsconfig.build.json`` excludes
     ``test`` and sets ``rootDir`` to ``./src`` (so the compiled
     ``dist/`` tree cannot reach into ``test/``).
  6. The Python verifier package layout
     (``packages/verifier/pyproject.toml``) builds the wheel from
     ``src/relay_verifier`` only -- the helper at
     ``tests/conformance/jws/...`` cannot end up in the wheel.

Additional invariants asserted only in ``--full`` mode:

  7. The compiled Python wheel (built via ``uv build --package
     epochly-relay-verifier``) contains NO module path matching
     ``_test_only_hs_verifier``.
  8. The compiled npm tarball (built via ``npm pack`` from
     ``packages/verifier-typescript/``) contains NO file matching
     ``test/_test_only_hs_verifier.ts`` or
     ``dist/_test_only_hs_verifier.js``.

Exit codes:
  0 = all checks passed
  1 = a leak was detected (RELAY-VERIFY-HS-HELPER-LEAKED)
  2 = infrastructure error (failed to build wheel / tarball)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PY_HELPER_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / "_test_only_hs_verifier.py"
)
TS_HELPER_PATH = (
    REPO_ROOT
    / "packages"
    / "verifier-typescript"
    / "test"
    / "_test_only_hs_verifier.ts"
)

PRODUCTION_SCAN_ROOTS = (
    REPO_ROOT / "packages",
    REPO_ROOT / "apps",
)

BANNED_SUBSTRINGS = (
    "_test_only_hs_verifier",
    "verify_hs_compact",
    "verifyHsCompact",
)

EXCLUDED_DIR_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    ".venv",
    "venv",
    "tests",
    "test",
    "_generated",
}

SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".mts", ".cts"}

LEAK_CODE = "RELAY-VERIFY-HS-HELPER-LEAKED"


# ---------------------------------------------------------------------------
# Source-tree invariants
# ---------------------------------------------------------------------------


def _fail(msg: str) -> int:
    print(f"FAIL {LEAK_CODE}: {msg}", file=sys.stderr)
    return 1


def _check_helper_files_exist_at_canonical_paths() -> list[str]:
    issues: list[str] = []
    if not PY_HELPER_PATH.is_file():
        issues.append(
            f"Python helper missing at expected test-only path {PY_HELPER_PATH}"
        )
    if not TS_HELPER_PATH.is_file():
        issues.append(
            f"TypeScript helper missing at expected test-only path {TS_HELPER_PATH}"
        )
    return issues


def _check_no_init_py_in_helper_dir() -> list[str]:
    init_path = PY_HELPER_PATH.parent / "__init__.py"
    if init_path.exists():
        return [
            f"BANNED __init__.py at {init_path}; helper dir must NOT be a package"
        ]
    return []


def _grep_production_for_banned_substrings() -> list[str]:
    issues: list[str] = []
    scanned = 0
    for root in PRODUCTION_SCAN_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in SOURCE_SUFFIXES:
                continue
            if any(part in EXCLUDED_DIR_PARTS for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            scanned += 1
            for banned in BANNED_SUBSTRINGS:
                if banned in text:
                    for lineno, line in enumerate(text.splitlines(), start=1):
                        if banned in line:
                            issues.append(
                                f"{path.relative_to(REPO_ROOT)}:{lineno}: "
                                f"banned substring {banned!r}: "
                                f"{line.strip()[:120]!r}"
                            )
    if scanned == 0:
        issues.append(
            "grep guard scanned 0 production files; check PRODUCTION_SCAN_ROOTS"
        )
    return issues


def _check_typescript_package_files_array() -> list[str]:
    pkg_path = REPO_ROOT / "packages" / "verifier-typescript" / "package.json"
    if not pkg_path.is_file():
        return [f"missing package.json at {pkg_path}"]
    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    files = pkg.get("files", [])
    if not isinstance(files, list):
        return [f"package.json `files` is not a list: {type(files)}"]
    bad = [f for f in files if f == "test" or f.startswith(("test/", "./test"))]
    issues: list[str] = []
    if bad:
        issues.append(
            f"package.json `files` includes test paths {bad!r}; remove them"
        )
    for k in ("main", "types", "module"):
        v = pkg.get(k)
        if isinstance(v, str) and "test" in v.split("/"):
            issues.append(f"package.json `{k}` {v!r} contains 'test' segment")
    return issues


def _check_typescript_build_tsconfig() -> list[str]:
    tsc_path = (
        REPO_ROOT / "packages" / "verifier-typescript" / "tsconfig.build.json"
    )
    if not tsc_path.is_file():
        return [f"missing tsconfig.build.json at {tsc_path}"]
    raw = tsc_path.read_text(encoding="utf-8")
    # Strip simple line comments tsc allows.
    stripped = re.sub(r"//.*", "", raw)
    tsc = json.loads(stripped)
    issues: list[str] = []
    excludes = tsc.get("exclude", [])
    if "test" not in excludes:
        issues.append(
            f"tsconfig.build.json `exclude` does not list 'test': {excludes!r}"
        )
    co = tsc.get("compilerOptions", {})
    root = co.get("rootDir", "./src")
    if root not in ("./src", "src"):
        issues.append(f"tsconfig.build.json `rootDir` is {root!r} (must be ./src)")
    return issues


def _check_python_wheel_layout() -> list[str]:
    pyproject_path = REPO_ROOT / "packages" / "verifier" / "pyproject.toml"
    if not pyproject_path.is_file():
        return [f"missing pyproject.toml at {pyproject_path}"]
    text = pyproject_path.read_text(encoding="utf-8")
    if 'packages = ["src/relay_verifier"]' not in text:
        return [
            "pyproject.toml does not declare "
            "`packages = [\"src/relay_verifier\"]`; wheel layout may be wrong"
        ]
    # Confirm no force-include reaches into tests/.
    if "tests/" in text and "force-include" in text:
        return [
            "pyproject.toml `force-include` may reach into tests/; manual review"
        ]
    return []


def _run_source_invariants() -> int:
    all_issues: list[str] = []
    all_issues.extend(_check_helper_files_exist_at_canonical_paths())
    all_issues.extend(_check_no_init_py_in_helper_dir())
    all_issues.extend(_grep_production_for_banned_substrings())
    all_issues.extend(_check_typescript_package_files_array())
    all_issues.extend(_check_typescript_build_tsconfig())
    all_issues.extend(_check_python_wheel_layout())
    if all_issues:
        for issue in all_issues:
            _fail(issue)
        return 1
    print(
        "OK source-tree invariants: helper at canonical test-only paths; "
        "no production source reference; package.json/tsconfig/pyproject "
        "all exclude the helper from build output."
    )
    return 0


# ---------------------------------------------------------------------------
# Build-artifact invariants (--full only)
# ---------------------------------------------------------------------------


def _build_python_wheel(tmp_dir: Path) -> tuple[Path | None, str]:
    """Build the verifier wheel into ``tmp_dir`` and return its path."""
    out_dir = tmp_dir / "wheel-out"
    out_dir.mkdir()
    result = subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--package",
            "epochly-relay-verifier",
            "--out-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        return None, f"uv build failed: {result.stderr or result.stdout}"
    wheels = list(out_dir.glob("*.whl"))
    if not wheels:
        return None, "uv build produced no .whl file"
    return wheels[0], ""


def _build_npm_tarball(tmp_dir: Path) -> tuple[Path | None, str]:
    """Build the npm tarball via ``npm pack`` into ``tmp_dir``."""
    out_dir = tmp_dir / "tgz-out"
    out_dir.mkdir()
    pkg_dir = REPO_ROOT / "packages" / "verifier-typescript"
    result = subprocess.run(
        ["npm", "pack", "--pack-destination", str(out_dir)],
        cwd=pkg_dir,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        return None, f"npm pack failed: {result.stderr or result.stdout}"
    tarballs = list(out_dir.glob("*.tgz"))
    if not tarballs:
        return None, "npm pack produced no .tgz file"
    return tarballs[0], ""


def _check_wheel_for_helper(wheel_path: Path) -> list[str]:
    """Open the wheel (a zip file) and assert no member name contains
    any banned substring."""
    issues: list[str] = []
    with zipfile.ZipFile(wheel_path) as zf:
        for name in zf.namelist():
            for banned in BANNED_SUBSTRINGS:
                if banned in name:
                    issues.append(
                        f"wheel {wheel_path.name} contains "
                        f"banned-substring member {name!r}"
                    )
    return issues


def _check_tarball_for_helper(tarball_path: Path) -> list[str]:
    """Open the npm .tgz (gzipped tar) and assert no member name
    contains any banned substring."""
    issues: list[str] = []
    with tarfile.open(tarball_path, "r:gz") as tf:
        for member in tf.getmembers():
            for banned in BANNED_SUBSTRINGS:
                if banned in member.name:
                    issues.append(
                        f"npm tarball {tarball_path.name} contains "
                        f"banned-substring member {member.name!r}"
                    )
    return issues


def _run_build_artifact_invariants() -> int:
    with tempfile.TemporaryDirectory(prefix="relay-hs-iso-") as tmp:
        tmp_dir = Path(tmp)
        wheel, err = _build_python_wheel(tmp_dir)
        if wheel is None:
            print(f"INFRA-ERROR: {err}", file=sys.stderr)
            return 2
        wheel_issues = _check_wheel_for_helper(wheel)
        tgz, err2 = _build_npm_tarball(tmp_dir)
        if tgz is None:
            print(f"INFRA-ERROR: {err2}", file=sys.stderr)
            return 2
        tgz_issues = _check_tarball_for_helper(tgz)
        all_issues = wheel_issues + tgz_issues
        if all_issues:
            for issue in all_issues:
                _fail(issue)
            return 1
        print(
            f"OK build-artifact invariants: wheel {wheel.name} and "
            f"tarball {tgz.name} contain NO HS helper module path."
        )
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VAL-W17-023 HS verifier helper isolation check."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate source-tree invariants only (no wheel build). "
            "Used by plumbing-tier CI on every commit. Default if no "
            "mode flag is passed."
        ),
    )
    mode.add_argument(
        "--full",
        action="store_true",
        help=(
            "Run source-tree invariants AND build the Python wheel + "
            "npm tarball, then unpack each and assert the helper "
            "module path is absent. Used by the release gate."
        ),
    )
    args = parser.parse_args(argv)

    # Default to --dry-run if neither flag is passed.
    if not args.full and not args.dry_run:
        args.dry_run = True

    src_rc = _run_source_invariants()
    if src_rc != 0:
        return src_rc
    if args.full:
        return _run_build_artifact_invariants()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
