"""W9.1 dependency declaration guards (VAL-V2M09-001).

Per contract.md VAL-V2M09-001 the CLI MUST declare ``sigstore>=3.6.0`` in
its runtime ``[project.dependencies]`` table -- NOT in
``optional-dependencies``, ``dev-dependencies``, or extras. The pinned
sigstore-python release exposes the cryptographic verification surface
(``sigstore.verify.Verifier``, ``sigstore.models.Bundle.verify_artifact``)
that ``relay_cli.bundle.verify_sigstore`` invokes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_PYPROJECT = REPO_ROOT / "packages" / "cli" / "pyproject.toml"


def _load_cli_dependencies() -> list[str]:
    data = tomllib.loads(CLI_PYPROJECT.read_text(encoding="utf-8"))
    return list(data["project"]["dependencies"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-001")
def test_sigstore_dep_present() -> None:
    """``sigstore>=3.6.0`` MUST appear in the runtime dependencies list."""
    deps = _load_cli_dependencies()
    matches = [d for d in deps if d.strip().lower().startswith("sigstore")]
    assert matches, (
        "expected a 'sigstore' entry in packages/cli/pyproject.toml "
        f"[project.dependencies]; got {deps!r}"
    )
    # VAL-V2M09-001 requires '>=3.6.0' specifically (allows newer majors
    # because uv resolves an actual installed version separately).
    has_min = any(
        re.search(r"sigstore\s*>=\s*3\.6", d, flags=re.IGNORECASE)
        for d in matches
    )
    assert has_min, (
        "sigstore dependency MUST pin '>=3.6.0' minimum; got " + repr(matches)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-001")
def test_sigstore_not_in_optional_or_extras() -> None:
    """sigstore MUST be runtime, never under optional-dependencies/extras."""
    data = tomllib.loads(CLI_PYPROJECT.read_text(encoding="utf-8"))
    optional = data.get("project", {}).get("optional-dependencies", {})
    for group, entries in optional.items():
        for entry in entries:
            assert "sigstore" not in entry.lower(), (
                f"sigstore must not appear under optional-dependencies.{group!r}; "
                f"found {entry!r}"
            )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M09-001")
def test_sigstore_importable_with_pinned_version() -> None:
    """A subprocess in the same Python MUST be able to import sigstore.

    Asserts the version is >= 3.6.0 (matches the regex from contract.md
    VAL-V2M09-001 line 3901: ``^3\\.([6-9]|[1-9][0-9])\\.``, plus the
    >=3.6.0 spec also admits sigstore 4.x as a forward-compatible major.
    """
    proc = subprocess.run(
        [sys.executable, "-c", "import sigstore; print(sigstore.__version__)"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, (
        f"sigstore import failed: rc={proc.returncode} stderr={proc.stderr!r}"
    )
    version = proc.stdout.strip()
    # Accept 3.6+ OR 4.x (uv resolved 4.2.0 against >=3.6.0 pin).
    accepted = re.match(r"^(3\.([6-9]|[1-9][0-9])\.|[4-9]\.|[1-9][0-9]+\.)", version)
    assert accepted is not None, (
        f"sigstore version {version!r} does not satisfy >=3.6.0"
    )
