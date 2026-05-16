"""W17.4 VAL-W17-019: weak-form idiom-coverage check.

Per contract.md gap #4 reconciliation, the v0.1 scope of this test is
the weak form: every Relay UDF referenced from CEL expressions in
``packages/contracts/`` MUST have a corresponding case directory under
``tests/conformance/cel/relay-udfs/`` with at least one case.

The full CEL-idiom taxonomy (every operator, builtin, type coercion,
comprehension, regex pattern) is deferred to v0.2. See
``idiom-coverage/README.md`` in the sibling directory for the
deferred-scope rationale.

Tool: conformance-corpus-test (custom static analyzer + coverage
cross-check).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
IDIOM_COVERAGE_DIR = REPO_ROOT / "tests" / "conformance" / "cel" / "idiom-coverage"
ANALYZER_PATH = IDIOM_COVERAGE_DIR / "analyzer.py"
RELAY_UDFS_DIR = REPO_ROOT / "tests" / "conformance" / "cel" / "relay-udfs"
README_PATH = IDIOM_COVERAGE_DIR / "README.md"

# The directory name ``idiom-coverage`` is not a valid Python
# identifier (contains a hyphen), so we load the analyzer by file
# path via importlib rather than via ``from ... import``.


def _load_analyzer() -> object:
    spec = importlib.util.spec_from_file_location(
        "w17_4_idiom_coverage_analyzer", ANALYZER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"VAL-W17-019: cannot load analyzer at {ANALYZER_PATH}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-019")
def test_analyzer_module_present() -> None:
    assert ANALYZER_PATH.exists(), (
        f"VAL-W17-019: missing analyzer at {ANALYZER_PATH}"
    )
    module = _load_analyzer()
    assert hasattr(module, "find_referenced_udfs"), (
        "VAL-W17-019: analyzer must expose find_referenced_udfs()"
    )
    assert hasattr(module, "find_udf_references"), (
        "VAL-W17-019: analyzer must expose find_udf_references()"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-019")
def test_readme_documents_deferred_v0_2_scope() -> None:
    """Gap #4 reconciliation requires that the deferred-scope rationale
    be documented in the idiom-coverage directory."""

    assert README_PATH.exists(), (
        f"VAL-W17-019: missing README at {README_PATH}; gap #4 "
        "reconciliation requires the deferred v0.2 scope be documented."
    )
    text = README_PATH.read_text(encoding="utf-8")
    required_substrings = [
        ("weak form", "README must use the term 'weak form'"),
        ("v0.2", "README must reference v0.2 deferral"),
        ("gap #4", "README must cite contract.md gap #4"),
        (
            "relay-udfs",
            "README must reference the relay-udfs/ corpus directory",
        ),
    ]
    missing: list[str] = []
    for needle, reason in required_substrings:
        if needle not in text:
            missing.append(reason)
    assert missing == [], (
        "VAL-W17-019: README missing required content:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-019")
def test_every_referenced_udf_has_a_corpus_directory() -> None:
    """Weak-form coverage check: every UDF referenced from
    ``packages/contracts/`` (Python or TypeScript) MUST have a
    directory under ``tests/conformance/cel/relay-udfs/<udf>/`` with
    at least one ``case_*.json`` file."""

    module = _load_analyzer()
    referenced: set[str] = module.find_referenced_udfs(REPO_ROOT)
    assert referenced, (
        "VAL-W17-019: analyzer found ZERO Relay UDF references in "
        "packages/contracts/. The Relay UDF call-site regex must "
        "match at least relay.coverage/relay.tool_arg/relay.schema_match "
        "documented in the UDF source modules."
    )
    missing: list[str] = []
    for udf in sorted(referenced):
        udf_dir = RELAY_UDFS_DIR / udf
        if not udf_dir.is_dir():
            missing.append(f"{udf}: no corpus directory at {udf_dir}")
            continue
        cases = list(udf_dir.glob("case_*.json"))
        if not cases:
            missing.append(
                f"{udf}: corpus directory has zero case_*.json files"
            )
    assert missing == [], (
        "VAL-W17-019: referenced UDFs without corpus coverage:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-019")
def test_analyzer_finds_known_production_udfs() -> None:
    """Sanity check: the analyzer MUST find at least the three
    production UDFs that v0.1 ships. If this test fails, the analyzer
    is broken (not the corpus)."""

    module = _load_analyzer()
    referenced: set[str] = module.find_referenced_udfs(REPO_ROOT)
    required = {"relay.coverage", "relay.tool_arg", "relay.schema_match"}
    missing = required - referenced
    assert missing == set(), (
        f"VAL-W17-019: analyzer did not find production UDFs in "
        f"packages/contracts/: {sorted(missing)}; found "
        f"{sorted(referenced)}"
    )
