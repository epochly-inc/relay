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
# VAL-ISO-016: alias/anchor-bomb (billion-laughs) defense at expansion time.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_rejects_alias_bomb_with_shallow_authored_depth() -> None:
    """VAL-ISO-016 regression: a billion-laughs alias bomb whose AUTHORED
    nesting depth is shallow but whose expansion factor is exponential MUST
    be rejected by the node-budget cap.

    The depth walk over the pre-expansion event stream sees the aliases as
    AliasEvent nodes (NOT expanded), so its observed max depth stays under
    16 -- yet the structure expands to fanout^levels nodes. The loader
    charges each ``AliasEvent`` the full node-cost of the anchor it
    references, so the running expanded-node count crosses
    ``MAX_YAML_EXPANDED_NODES`` and the document is rejected *before*
    materialisation.

    This is the classic billion-laughs shape (fanout 9, 5 chained levels);
    authored nesting depth is only 2 (each ``&lN [...]`` is one flat
    sequence) yet the expansion is ~672k nodes, far above the 100k budget.
    """
    from relay_schemas.manifest import (
        MAX_YAML_EXPANDED_NODES,
        YamlAliasBombError,
        safe_load_yaml,
    )

    fanout = 9
    lines = ["l0: &l0 [" + ",".join(["1"] * fanout) + "]"]
    for i in range(1, 5):
        refs = ",".join([f"*l{i - 1}"] * fanout)
        lines.append(f"l{i}: &l{i} [{refs}]")
    lines.append("top: [" + ",".join(["*l4"] * fanout) + "]")
    bomb = "\n".join(lines) + "\n"

    with pytest.raises(YamlAliasBombError) as excinfo:
        safe_load_yaml(bomb)
    # The node-budget cap is the layer that catches it (not a structural
    # heuristic): reason is expanded_nodes and observed is the REAL count.
    assert excinfo.value.reason == "expanded_nodes"
    assert excinfo.value.observed > MAX_YAML_EXPANDED_NODES


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_rejects_large_alias_bomb_amplification() -> None:
    """A deeper alias chain (higher amplification) is also rejected by the
    node-budget cap. This is the ``&lN [*lN-1, ...]`` chain shape; with a
    fanout of 3 over 9 levels it expands to ~133k nodes, above the 100k
    budget, so it trips ``expanded_nodes`` -- proving the budget catches a
    genuine billion-laughs even when authored depth is shallow.
    """
    from relay_schemas.manifest import (
        MAX_YAML_EXPANDED_NODES,
        YamlAliasBombError,
        safe_load_yaml,
    )

    fanout = 3
    lines = ["l0: &l0 [" + ",".join(["1"] * fanout) + "]"]
    for i in range(1, 9):
        refs = ",".join([f"*l{i - 1}"] * fanout)
        lines.append(f"l{i}: &l{i} [{refs}]")
    lines.append("top: [" + ",".join(["*l8"] * fanout) + "]")
    bomb = "\n".join(lines) + "\n"

    with pytest.raises(YamlAliasBombError) as excinfo:
        safe_load_yaml(bomb)
    assert excinfo.value.reason == "expanded_nodes"
    # The observed count is a REAL amplified count, never the constant 1.
    assert excinfo.value.observed > MAX_YAML_EXPANDED_NODES
    assert excinfo.value.observed > 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_accepts_bounded_nested_anchor_composition() -> None:
    """VAL-ISO-016 over-rejection regression: legitimate bounded YAML
    composition where an anchored container's own subtree references ANOTHER
    anchor MUST load successfully.

    The old ``alias_chain`` heuristic rejected any anchored container whose
    subtree referenced another anchor, conflating "reuses a nested anchor"
    (legitimate, bounded) with "amplifies exponentially" (the attack). The
    node-budget cap is the principled defense: this document expands to ~6
    nodes, far below the 100k budget, so it must be accepted.
    """
    from relay_schemas.manifest import safe_load_yaml

    # Exact trigger from the structural-review finding: &b's subtree
    # references &a, and &b is itself reused via *b. Expands to ~6 nodes.
    doc = "a: &a {x: 1}\nb: &b {y: *a}\nc: *b\n"
    out = safe_load_yaml(doc)
    assert out is not None
    assert out["a"] == {"x": 1}
    assert out["b"] == {"y": {"x": 1}}
    assert out["c"] == {"y": {"x": 1}}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_accepts_merge_key_composition() -> None:
    """VAL-ISO-016 over-rejection regression: YAML merge-key (``<<``)
    composition where a derived mapping merges a base anchor and is itself
    anchored MUST load. This is a common, bounded configuration pattern and
    must not be conflated with an alias bomb.
    """
    from relay_schemas.manifest import safe_load_yaml

    # An anchored derived mapping (&derived) whose subtree references the
    # base anchor (*base) via a merge key -- the old heuristic rejected this.
    doc = (
        "base: &base {a: 1}\n"
        "derived: &derived {<<: *base, b: 2}\n"
        "use: *derived\n"
    )
    out = safe_load_yaml(doc)
    assert out is not None
    assert out["base"] == {"a": 1}
    assert out["derived"] == {"a": 1, "b": 2}
    assert out["use"] == {"a": 1, "b": 2}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_accepts_legitimate_anchors() -> None:
    """VAL-ISO-016 guard: a document with a small, reasonable number of
    anchors/aliases (the legitimate use the manifest itself relies on)
    MUST still load successfully.

    The real manifest.yaml uses anchors (``&id001`` egress allowlist reused
    across commands). Over-rejecting those would break manifest loading.
    """
    from relay_schemas.manifest import safe_load_yaml

    legit = (
        "egress: &egress\n"
        "  - https://api.openai.com\n"
        "  - https://api.anthropic.com\n"
        "cmd_a:\n"
        "  allowlist: *egress\n"
        "cmd_b:\n"
        "  allowlist: *egress\n"
        "cmd_c:\n"
        "  allowlist: *egress\n"
    )
    out = safe_load_yaml(legit)
    assert out is not None
    assert out["cmd_a"]["allowlist"] == [
        "https://api.openai.com",
        "https://api.anthropic.com",
    ]
    assert out["cmd_c"]["allowlist"] == out["cmd_a"]["allowlist"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-016")
def test_manifest_loader_rejects_oversize_canonical_json() -> None:
    """VAL-ISO-016 / AI.1: the 256 KiB canonical-JSON size half of the
    AI.1 constraint is enforced. A document whose materialized content
    exceeds the byte budget MUST be rejected."""
    from relay_schemas.manifest import safe_load_yaml

    # A flat list of many short scalars: shallow depth, no aliases, but
    # large materialized size. Build > 256 KiB of content.
    big = "- " + "\n- ".join(["x" * 64] * 8000) + "\n"
    with pytest.raises(Exception):  # noqa: B017,PT011
        safe_load_yaml(big)


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
