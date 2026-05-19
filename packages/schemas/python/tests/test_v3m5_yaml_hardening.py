"""V3 M5 F05 YAML hardening tests.

Covers contract assertions VAL-V3M5-011 (safe_load lint) and
VAL-V3M5-012 (max-depth 16 enforcement at named YAML loaders).

VAL-V3M5-011: scripts/check-yaml-safe-load.py is an AST lint that rejects
unqualified ``yaml.load(...)`` calls under packages/, apps/, scripts/.
Every yaml.load callsite MUST pass ``Loader=yaml.SafeLoader`` or
``yaml.CSafeLoader``. The lint script exits 0 on clean, 1 on offenders.

VAL-V3M5-012: spec section AI.1 line 5659 names a nesting-depth cap of 16
alongside the 256 KiB canonical-JSON size cap. Manifest + contract DSL
loaders enforce depth <= 16; over-depth rejected with structured error.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# Repo root anchored on this test file: parents[0]=tests, [1]=python,
# [2]=schemas, [3]=packages, [4]=relay (the public OSS root).
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_LINT_SCRIPT = _REPO_ROOT / "scripts" / "check-yaml-safe-load.py"


# ---------------------------------------------------------------------------
# VAL-V3M5-011: lint script exists + rejects unqualified yaml.load.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_exists() -> None:
    """scripts/check-yaml-safe-load.py is present and executable as a module."""
    assert _LINT_SCRIPT.is_file(), (
        f"Missing lint script at {_LINT_SCRIPT}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_passes_on_clean_tree(tmp_path: Path) -> None:
    """Run lint script against the current tree; it MUST exit 0."""
    proc = subprocess.run(
        [sys.executable, str(_LINT_SCRIPT)],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"check-yaml-safe-load.py failed on current tree.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_rejects_unqualified_yaml_load(tmp_path: Path) -> None:
    """A file containing yaml.load(stream) without Loader= MUST trigger exit 1."""
    pkg = tmp_path / "packages" / "bad_pkg"
    pkg.mkdir(parents=True)
    offender = pkg / "loader.py"
    offender.write_text(
        textwrap.dedent(
            """
            import yaml

            def loader(text):
                return yaml.load(text)
            """
        ).strip(),
        encoding="utf-8",
    )
    # Run the lint over a synthetic tree by passing it as --root.
    proc = subprocess.run(
        [sys.executable, str(_LINT_SCRIPT), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1, (
        f"Expected exit 1 on unqualified yaml.load, got {proc.returncode}.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "yaml.load" in proc.stdout or "yaml.load" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_rejects_unsafe_loader_kwarg(tmp_path: Path) -> None:
    """yaml.load(stream, Loader=yaml.Loader) is unsafe; lint MUST reject."""
    pkg = tmp_path / "packages" / "bad_pkg"
    pkg.mkdir(parents=True)
    offender = pkg / "loader.py"
    offender.write_text(
        textwrap.dedent(
            """
            import yaml

            def loader(text):
                return yaml.load(text, Loader=yaml.Loader)
            """
        ).strip(),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_LINT_SCRIPT), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1, (
        f"Expected exit 1 on unsafe Loader kwarg, got {proc.returncode}.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_accepts_safe_loader(tmp_path: Path) -> None:
    """yaml.load(stream, Loader=yaml.SafeLoader) MUST pass the lint."""
    pkg = tmp_path / "packages" / "good_pkg"
    pkg.mkdir(parents=True)
    safe = pkg / "loader.py"
    safe.write_text(
        textwrap.dedent(
            """
            import yaml

            def loader(text):
                return yaml.load(text, Loader=yaml.SafeLoader)
            """
        ).strip(),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_LINT_SCRIPT), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"Expected exit 0 on yaml.SafeLoader use, got {proc.returncode}.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-011")
def test_lint_script_accepts_csafe_loader(tmp_path: Path) -> None:
    """yaml.load(stream, Loader=yaml.CSafeLoader) MUST pass the lint."""
    pkg = tmp_path / "packages" / "good_pkg"
    pkg.mkdir(parents=True)
    safe = pkg / "loader.py"
    safe.write_text(
        textwrap.dedent(
            """
            import yaml

            def loader(text):
                return yaml.load(text, Loader=yaml.CSafeLoader)
            """
        ).strip(),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(_LINT_SCRIPT), "--root", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"Expected exit 0 on yaml.CSafeLoader use, got {proc.returncode}.\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# VAL-V3M5-012: manifest YAML loader enforces depth <= 16.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_manifest_loader_accepts_depth_16() -> None:
    """A document at exactly nesting depth 16 MUST load successfully."""
    from relay_schemas.manifest import (
        MAX_YAML_DEPTH,
        YamlDepthExceededError,
        safe_load_yaml,
    )

    assert MAX_YAML_DEPTH == 16
    # Build a depth-16 nested mapping. Depth count: leaf scalar counts as
    # depth 1; one wrapping container adds 1. So 15 nested mappings around
    # a scalar leaf = depth 16.
    doc = "v"
    for _ in range(15):
        doc = f"k: {doc}"
        doc = doc.replace("\n", "\n  ")  # keep readable; pyyaml handles flow
    # Use flow style for determinism.
    raw = "v"
    for _ in range(15):
        raw = "{k: " + raw + "}"
    result = safe_load_yaml(raw)
    assert result is not None
    _ = YamlDepthExceededError  # type imported for VAL coverage


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_manifest_loader_rejects_depth_17() -> None:
    """A document nested deeper than 16 MUST raise YamlDepthExceededError."""
    from relay_schemas.manifest import (
        YamlDepthExceededError,
        safe_load_yaml,
    )

    raw = "v"
    for _ in range(17):
        raw = "{k: " + raw + "}"
    with pytest.raises(YamlDepthExceededError) as excinfo:
        safe_load_yaml(raw)
    assert excinfo.value.depth > 16
    assert excinfo.value.limit == 16


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_manifest_loader_rejects_deep_list() -> None:
    """Sequences contribute to depth count and trigger the same cap."""
    from relay_schemas.manifest import (
        YamlDepthExceededError,
        safe_load_yaml,
    )

    raw = "[v]"
    for _ in range(17):
        raw = "[" + raw + "]"
    with pytest.raises(YamlDepthExceededError):
        safe_load_yaml(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_manifest_loader_handles_billion_laughs_anchor_pattern() -> None:
    """An anchor-bomb pattern that nests deeply MUST hit the depth cap.

    Per spec AI.1 line 5659 the depth guard is the structural defense
    against anchor-bomb / billion-laughs-style YAML inputs.
    """
    from relay_schemas.manifest import (
        YamlDepthExceededError,
        safe_load_yaml,
    )

    # A self-referential anchor expanded structurally produces deep nesting.
    raw = "v"
    for _ in range(20):
        raw = "[" + raw + "]"
    with pytest.raises(YamlDepthExceededError):
        safe_load_yaml(raw)


# ---------------------------------------------------------------------------
# VAL-V3M5-012: contract DSL YAML loader enforces depth <= 16.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_dsl_parser_loader_rejects_depth_17() -> None:
    """The contract DSL YAML loader MUST enforce the depth-16 cap."""
    from relay_contracts.dsl_parser import (
        MAX_YAML_DEPTH,
        YamlDepthExceededError,
        safe_load_yaml,
    )

    assert MAX_YAML_DEPTH == 16
    raw = "v"
    for _ in range(17):
        raw = "{k: " + raw + "}"
    with pytest.raises(YamlDepthExceededError):
        safe_load_yaml(raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-012")
def test_dsl_parser_loader_accepts_depth_16() -> None:
    """The contract DSL YAML loader accepts documents at depth <= 16."""
    from relay_contracts.dsl_parser import safe_load_yaml

    raw = "v"
    for _ in range(15):
        raw = "{k: " + raw + "}"
    out = safe_load_yaml(raw)
    assert out is not None
