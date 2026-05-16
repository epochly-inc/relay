"""W17.4 VAL-W17-021: tier-2 timing budget for all four conformance suites.

The full conformance suite (w17.1 + w17.2 + w17.3 + w17.4) MUST
complete in <= 480 seconds on the CI runner profile used for tier-2
smoke. If any single suite exceeds 300 seconds individually, a
warning is emitted recommending sharding (the suite is still
considered passing for the timing assertion).

Per C-CC-004 reconciliation: the canonical tool name for tier-N timing
assertions is ``tier-N-timing-test`` (here ``tier-2-timing-test``).

Tool: tier-2-timing-test (pytest plumbing tier).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# Per-suite test path. The four canonical conformance suites map to
# distinct directories or file globs.
_SUITE_PATHS: dict[str, list[str]] = {
    "w17.1": ["tests/conformance/jcs/"],
    "w17.2": ["tests/conformance/jws/"],
    "w17.3": ["tests/conformance/cel-spec/"],
    "w17.4": [
        "tests/conformance/cel/test_w17_4_udf_coverage.py",
        "tests/conformance/cel/test_w17_4_corpus_size.py",
        "tests/conformance/cel/test_w17_4_cross_runtime.py",
        "tests/conformance/cel/test_w17_4_purity.py",
        "tests/conformance/cel/test_w17_4_idiom_coverage.py",
    ],
}

# Tier-2 smoke budget per CLAUDE.md ("tier-2 smoke ... budget <= 8 min").
TOTAL_BUDGET_SECONDS: float = 480.0
# Per-suite shard recommendation threshold.
PER_SUITE_SHARD_THRESHOLD_SECONDS: float = 300.0


def _verify_suite_paths_exist() -> list[str]:
    missing: list[str] = []
    for suite, paths in _SUITE_PATHS.items():
        for p in paths:
            if not (REPO_ROOT / p).exists():
                missing.append(f"{suite}: {p}")
    return missing


def _run_suite_timed(suite: str, paths: list[str]) -> tuple[float, int, str]:
    """Run a single suite's pytest invocation and measure wall-clock.

    Returns (elapsed_seconds, exit_code, combined_output).
    Excludes the timing test itself from re-discovery so we don't
    recurse: passes ``--deselect`` for this file.
    """

    env = {**os.environ}
    env.pop("RELAY_CONFORMANCE_FAULT_INJECT", None)
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *paths,
        "-m",
        "plumbing",
        "--timeout=600",
        "-q",
        # Avoid infinite recursion: deselect this timing test itself.
        "--deselect",
        "tests/conformance/cel/test_w17_4_timing.py",
    ]
    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        timeout=PER_SUITE_SHARD_THRESHOLD_SECONDS + 60.0,
        check=False,
    )
    elapsed = time.monotonic() - start
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    combined = out + err
    return elapsed, proc.returncode, combined


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-021")
def test_all_four_suite_paths_exist() -> None:
    """Sanity: every suite path the timing test would invoke MUST
    exist on disk. Otherwise the timing measurement is degenerate."""

    missing = _verify_suite_paths_exist()
    assert missing == [], (
        f"VAL-W17-021: missing conformance suite paths: {missing}; "
        "cannot measure tier-2 timing budget."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-021")
def test_tier_2_timing_budget_for_all_four_conformance_suites() -> None:
    """Tool: tier-2-timing-test (canonical per C-CC-004).

    Runs all four conformance suites in sequence, measuring per-suite
    elapsed time. Asserts the aggregate is <= 480 s. Emits a warning
    (without failing) when any single suite exceeds 300 s.

    Per-suite exit codes are also checked: any non-zero exit means
    the suite is red and the timing measurement is moot. We surface
    that failure rather than masking it under the timing assertion.
    """

    if _verify_suite_paths_exist():
        pytest.skip(
            "VAL-W17-021: suite paths missing; sister test surfaces "
            "the failure (test_all_four_suite_paths_exist)."
        )

    per_suite: dict[str, float] = {}
    per_suite_exit: dict[str, int] = {}
    suite_failures: list[str] = []
    for suite, paths in _SUITE_PATHS.items():
        elapsed, rc, combined = _run_suite_timed(suite, paths)
        per_suite[suite] = elapsed
        per_suite_exit[suite] = rc
        if rc != 0:
            suite_failures.append(
                f"{suite}: pytest exit={rc}; output tail:\n"
                + combined[-2000:]
            )

    total = sum(per_suite.values())
    print(
        f"[tier-2-timing-test] total={total:.1f}s "
        + " ".join(f"{k}={v:.1f}s" for k, v in per_suite.items())
    )
    # Emit shard recommendation per VAL-W17-021 ("If any suite > 300 s,
    # emit a warning recommending sharding but don't fail").
    for suite, elapsed in per_suite.items():
        if elapsed > PER_SUITE_SHARD_THRESHOLD_SECONDS:
            print(
                f"[tier-2-timing-test] WARNING: suite {suite} took "
                f"{elapsed:.1f}s (>{PER_SUITE_SHARD_THRESHOLD_SECONDS:.0f}s "
                "threshold); recommend sharding before merge"
            )

    assert suite_failures == [], (
        "VAL-W17-021: one or more conformance suites failed (timing "
        "measurement moot until baseline is green):\n  "
        + "\n  ".join(suite_failures)
    )
    assert total <= TOTAL_BUDGET_SECONDS, (
        f"VAL-W17-021: aggregate conformance suite elapsed "
        f"{total:.1f}s exceeds tier-2 smoke budget "
        f"{TOTAL_BUDGET_SECONDS:.0f}s. Per-suite breakdown: "
        + ", ".join(f"{k}={v:.1f}s" for k, v in per_suite.items())
    )
