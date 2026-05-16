"""VAL-W17-023: test-only HS verifier helper isolation guard.

Enforces the C-GAP-003 reconciliation: the HMAC-based test-only
verifier helper MUST NOT be importable, packaged, or referenced from
any production source path. Two layers:

  * Python: a grep-guard sweep across ``packages/`` and ``apps/``
    asserts no production module imports or names the helper.
  * TypeScript: a manifest-shape check on
    ``packages/verifier-typescript/package.json`` asserts the
    test-only HS helper file (``test/_test_only_hs_verifier.ts``)
    sits under ``test/`` and is NOT in the package's ``files`` array
    (which means it never reaches the npm tarball).
  * Build-time wheel + tarball checks live in
    ``scripts/check-hs-helper-isolation.py``; this test invokes that
    script in dry-run mode (which only validates the source-tree
    invariants the script enforces, without actually building wheels).

The structural enforcement also includes:
  * The helper lives ONLY under ``tests/conformance/jws/`` (Python).
  * The directory has NO ``__init__.py`` so the helper cannot be
    imported via the standard package mechanism by any module outside
    the same directory.
  * The TS helper lives ONLY under ``packages/verifier-typescript/test/``
    and the package's ``tsconfig.build.json`` excludes the ``test/``
    directory from the build.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HS_HELPER_PY_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / "_test_only_hs_verifier.py"
)
HS_HELPER_TS_PATH = (
    REPO_ROOT
    / "packages"
    / "verifier-typescript"
    / "test"
    / "_test_only_hs_verifier.ts"
)
HS_HELPER_BUILD_CHECK = (
    REPO_ROOT / "scripts" / "check-hs-helper-isolation.py"
)

# Production source roots that must NEVER reference the helper.
PRODUCTION_SCAN_ROOTS = (
    REPO_ROOT / "packages",
    REPO_ROOT / "apps",
)

# Filename / symbol fragments we ban from production source code.
BANNED_SUBSTRINGS = (
    "_test_only_hs_verifier",  # module file basename and import-line token
    "verify_hs_compact",       # the helper's public function (Python)
    "verifyHsCompact",         # the helper's public function (TypeScript)
)


# ---------------------------------------------------------------------------
# Helper presence
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_python_hs_helper_lives_under_tests_conformance() -> None:
    """Helper file exists at the canonical test-only path."""
    assert HS_HELPER_PY_PATH.is_file(), (
        f"VAL-W17-023 Python helper missing at {HS_HELPER_PY_PATH}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_python_hs_helper_directory_has_no_init_file() -> None:
    """No __init__.py in ``tests/conformance/jws/`` -- the helper
    cannot be imported via the standard ``tests.conformance.jws`` path
    by any production module. Defense in depth."""
    init_path = HS_HELPER_PY_PATH.parent / "__init__.py"
    assert not init_path.exists(), (
        f"VAL-W17-023 BANNED __init__.py found at {init_path}; the test-only "
        "directory must not be a Python package -- otherwise production code "
        "could `from tests.conformance.jws._test_only_hs_verifier import ...`."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_typescript_hs_helper_lives_under_test_dir() -> None:
    """TS helper exists at the canonical test-only path."""
    assert HS_HELPER_TS_PATH.is_file(), (
        f"VAL-W17-023 TypeScript helper missing at {HS_HELPER_TS_PATH}"
    )


# ---------------------------------------------------------------------------
# Source-tree grep guard
# ---------------------------------------------------------------------------


def _iter_source_files() -> list[Path]:
    """Return every .py / .ts / .tsx / .mts / .cts file under
    ``packages/`` and ``apps/``, excluding generated trees and test
    directories (test files are PERMITTED to reference the helper
    indirectly via the same-directory import pattern)."""
    files: list[Path] = []
    excluded_parts = {
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
    suffixes = {".py", ".ts", ".tsx", ".mts", ".cts"}
    for root in PRODUCTION_SCAN_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in suffixes:
                continue
            if any(part in excluded_parts for part in path.parts):
                continue
            files.append(path)
    return files


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_no_production_source_references_hs_helper() -> None:
    """Grep guard: every production source file under packages/ and
    apps/ MUST NOT contain any banned substring referencing the
    test-only HS helper. The single allowed location is tests/.
    """
    files = _iter_source_files()
    assert files, (
        "VAL-W17-023 grep-guard found NO production source files to scan; "
        "this is suspicious. Check the PRODUCTION_SCAN_ROOTS and excluded_parts."
    )
    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # skip non-UTF-8 binary files
        for banned in BANNED_SUBSTRINGS:
            if banned in text:
                # Find the offending line number for actionable output.
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if banned in line:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}:{lineno}: "
                            f"contains banned substring {banned!r}: "
                            f"{line.strip()[:120]!r}"
                        )
    assert not offenders, (
        f"VAL-W17-023 RELAY-VERIFY-HS-HELPER-LEAKED: {len(offenders)} "
        "production source file(s) reference the test-only HS verifier helper. "
        "The helper MUST live ONLY under tests/conformance/jws/ (Python) or "
        "packages/verifier-typescript/test/ (TypeScript). Offenders:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# TypeScript package manifest check
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_typescript_package_files_array_excludes_test_dir() -> None:
    """The ``files`` array in packages/verifier-typescript/package.json
    MUST NOT include ``test`` or any path under it. This is what npm
    uses to decide what goes into the published tarball; anything not
    listed (and not implicitly included by ``main``/``types``) is
    excluded.
    """
    pkg_json_path = (
        REPO_ROOT / "packages" / "verifier-typescript" / "package.json"
    )
    pkg = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    files = pkg.get("files", [])
    assert isinstance(files, list), (
        f"VAL-W17-023: package.json `files` must be a list, got {type(files)}"
    )
    # No entry may name `test` or start with `test/`.
    bad_entries = [
        f
        for f in files
        if f == "test" or f.startswith("test/") or f.startswith("./test")
    ]
    assert not bad_entries, (
        f"VAL-W17-023 RELAY-VERIFY-HS-HELPER-LEAKED: "
        f"packages/verifier-typescript/package.json `files` array includes "
        f"test paths {bad_entries!r}; npm tarball would ship the test-only "
        "HS helper. Remove these entries."
    )
    # And the main/types entry must NOT point into test/.
    for k in ("main", "types", "module"):
        v = pkg.get(k)
        if isinstance(v, str):
            assert "test" not in v.split("/"), (
                f"VAL-W17-023: package.json `{k}` field {v!r} contains a "
                "`test` path segment"
            )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_typescript_build_tsconfig_excludes_test_dir() -> None:
    """tsconfig.build.json MUST exclude the ``test`` directory so the
    compiled ``dist/`` tree never contains the helper."""
    tsconfig_path = (
        REPO_ROOT
        / "packages"
        / "verifier-typescript"
        / "tsconfig.build.json"
    )
    raw = tsconfig_path.read_text(encoding="utf-8")
    # tsconfig may contain comments; strip simple // line comments.
    stripped = re.sub(r"//.*", "", raw)
    tsconfig = json.loads(stripped)
    excludes = tsconfig.get("exclude", [])
    assert "test" in excludes, (
        "VAL-W17-023: packages/verifier-typescript/tsconfig.build.json "
        f"`exclude` array does not list 'test'; got {excludes!r}. Without "
        "this exclusion the test-only HS helper would be compiled into dist/."
    )
    # And rootDir must be ./src (test/ is sibling, not under src/).
    compiler_opts = tsconfig.get("compilerOptions", {})
    root_dir = compiler_opts.get("rootDir", "./src")
    assert root_dir in ("./src", "src"), (
        f"VAL-W17-023: rootDir must be ./src to keep test/ outside the "
        f"build root; got {root_dir!r}"
    )


# ---------------------------------------------------------------------------
# Build-time wheel + tarball check (delegates to the standalone script)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_build_time_isolation_check_script_exists() -> None:
    """The standalone script at scripts/check-hs-helper-isolation.py
    is responsible for unpacking the built wheel + npm tarball at
    release time and asserting the helper is absent. The script MUST
    exist; CI invokes it as part of the conformance-release-block
    gate. (VAL-W17-020 release gate.)
    """
    assert HS_HELPER_BUILD_CHECK.is_file(), (
        f"VAL-W17-023 build-isolation script missing at {HS_HELPER_BUILD_CHECK}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-023")
def test_build_time_isolation_check_passes_in_dry_run() -> None:
    """The build-time isolation check supports a ``--dry-run`` mode
    that validates the source-tree invariants WITHOUT actually
    building artifacts. Dry-run is what runs on every plumbing-tier
    test cycle; the full unpack-wheel mode runs only at release."""
    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "scripts/check-hs-helper-isolation.py",
            "--dry-run",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"VAL-W17-023 dry-run check failed (exit {result.returncode}):\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}"
    )
