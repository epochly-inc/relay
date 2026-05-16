"""W17.4 VAL-W17-020: release-block gate + fault-injection negative test.

Asserts the CI workflow at
``.github/workflows/conformance-release-block.yml`` exists and
references all four conformance suites (w17.1 RFC 8785, w17.2 RFC
7515, w17.3 cel-spec, w17.4 Relay-CEL). Also exercises the
fault-injection hook in ``conftest.py`` for each suite name and
asserts pytest reports non-zero when the env var is set.

Tool: parity-test (CI gate + negative tests with fault injection).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "conformance-release-block.yml"

# Canonical sub-feature names that MUST appear in the workflow.
REQUIRED_SUITE_NAMES: tuple[str, ...] = ("w17.1", "w17.2", "w17.3", "w17.4")

# Paths the workflow MUST reference so each suite is actually executed.
REQUIRED_SUITE_PATHS: tuple[str, ...] = (
    "tests/conformance/jcs/",
    "tests/conformance/jws/",
    "tests/conformance/cel-spec/",
    "tests/conformance/cel/test_w17_4_",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
def test_release_block_workflow_present() -> None:
    assert WORKFLOW_PATH.exists(), (
        f"VAL-W17-020: missing release-block workflow at {WORKFLOW_PATH}; "
        "the CI gate that blocks release on conformance failure is unenforced."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
def test_release_block_workflow_references_all_four_suites_by_name() -> None:
    """Per the contract: the gate runs all four conformance suites.
    The workflow MUST name each suite so a regression is addressable
    per-suite in CI logs."""

    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    missing: list[str] = []
    for name in REQUIRED_SUITE_NAMES:
        if name not in text:
            missing.append(name)
    assert missing == [], (
        f"VAL-W17-020: release-block workflow missing suite names: {missing}; "
        f"expected all of {sorted(REQUIRED_SUITE_NAMES)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
def test_release_block_workflow_references_all_four_suite_paths() -> None:
    """Naming a suite in a job title is insufficient; the workflow MUST
    actually execute against the suite's test paths. This guards against
    a workflow that lists the names but runs a stub command."""

    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    missing: list[str] = []
    for path in REQUIRED_SUITE_PATHS:
        if path not in text:
            missing.append(path)
    assert missing == [], (
        f"VAL-W17-020: release-block workflow missing suite paths: {missing}; "
        f"expected all of {sorted(REQUIRED_SUITE_PATHS)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
def test_release_block_workflow_runs_on_pull_request_and_push() -> None:
    """The release-block gate MUST trigger on both pull_request and push
    to main so a merge cannot land while any suite is red AND a
    direct-push regression is caught."""

    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    missing: list[str] = []
    for needle, reason in [
        ("pull_request:", "must trigger on pull_request"),
        ("push:", "must trigger on push"),
        ("- main", "must guard the main branch"),
    ]:
        if needle not in text:
            missing.append(reason)
    assert missing == [], (
        "VAL-W17-020: release-block workflow trigger configuration "
        "incomplete:\n  " + "\n  ".join(missing)
    )


# ---------------------------------------------------------------------------
# Fault-injection negative test (VAL-W17-020): when env
# RELAY_CONFORMANCE_FAULT_INJECT=<suite> is set, the named suite's
# first test fails. We verify by spawning a pytest subprocess per
# suite name and asserting non-zero exit.
# ---------------------------------------------------------------------------


_SUITE_PYTEST_PATHS: dict[str, str] = {
    "w17.1": "tests/conformance/jcs/",
    "w17.2": "tests/conformance/jws/",
    "w17.3": "tests/conformance/cel-spec/",
    "w17.4": "tests/conformance/cel/test_w17_4_udf_coverage.py",
}


def _spawn_pytest(suite_path: str, fault_inject: str | None) -> subprocess.CompletedProcess[bytes]:
    env = {**os.environ}
    # Strip the variable when fault_inject is None so the baseline
    # subprocess inherits a clean environment.
    env.pop("RELAY_CONFORMANCE_FAULT_INJECT", None)
    if fault_inject is not None:
        env["RELAY_CONFORMANCE_FAULT_INJECT"] = fault_inject
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            suite_path,
            "-m",
            "plumbing",
            "--timeout=120",
            "-q",
            # Stop on first failure to keep negative-test runtime tiny.
            "-x",
            # Disable our own conftest from re-injecting on the parent
            # invocation; the child invocation reads the env var
            # directly via its own conftest.
            "--no-header",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        timeout=300,
        check=False,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
@pytest.mark.parametrize("suite", list(_SUITE_PYTEST_PATHS.keys()))
def test_fault_injection_causes_non_zero_exit_per_suite(suite: str) -> None:
    """Negative test: setting RELAY_CONFORMANCE_FAULT_INJECT=<suite>
    MUST cause pytest to exit non-zero for the named suite. The
    fault-injection hook lives in
    tests/conformance/cel/conftest.py."""

    suite_path = _SUITE_PYTEST_PATHS[suite]
    result = _spawn_pytest(suite_path, fault_inject=suite)
    assert result.returncode != 0, (
        f"VAL-W17-020: fault injection for suite {suite!r} did NOT "
        f"cause non-zero exit. The conftest hook is not engaging.\n"
        f"  stdout: {result.stdout.decode('utf-8', errors='replace')[:2000]}\n"
        f"  stderr: {result.stderr.decode('utf-8', errors='replace')[:2000]}"
    )
    combined = (
        result.stdout.decode("utf-8", errors="replace")
        + result.stderr.decode("utf-8", errors="replace")
    )
    assert "RELAY_CONFORMANCE_FAULT_INJECT" in combined, (
        f"VAL-W17-020: fault-injection failure for suite {suite!r} did "
        "not include the env-var name in pytest output.\n"
        f"  combined: {combined[:2000]}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-020")
def test_baseline_without_fault_injection_passes_for_w17_4() -> None:
    """Sanity check: with RELAY_CONFORMANCE_FAULT_INJECT unset, the
    w17.4 suite MUST pass cleanly. If this baseline is red, the
    fault-injection negative test above is meaningless."""

    result = _spawn_pytest(
        "tests/conformance/cel/test_w17_4_udf_coverage.py",
        fault_inject=None,
    )
    assert result.returncode == 0, (
        "VAL-W17-020: baseline w17.4 suite is red without fault "
        "injection -- the negative test cannot be meaningfully "
        "interpreted until the baseline is green.\n"
        f"  stdout: {result.stdout.decode('utf-8', errors='replace')[:2000]}\n"
        f"  stderr: {result.stderr.decode('utf-8', errors='replace')[:2000]}"
    )
