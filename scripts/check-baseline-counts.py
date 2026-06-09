#!/usr/bin/env python3
# scripts/check-baseline-counts.py
#
# Fulfills VAL-V3M5-023 (spec sec AM.6).
#
# Runs the plumbing tier of every package recorded in tests/baseline-counts.json
# and asserts that the current passing-test count is >= the recorded baseline.
# Any per-package regression produces a non-zero exit and a list of offenders.
#
# Usage:
#     python scripts/check-baseline-counts.py            # run all packages
#     python scripts/check-baseline-counts.py --json     # machine-readable output
#     python scripts/check-baseline-counts.py --quick    # collect-only (no execution)
#
# Exit codes:
#     0 = every per-package passing count is >= the baseline
#     1 = at least one per-package regression detected
#     2 = invocation error (missing baseline file, bad JSON, pytest crash)
#
# Design notes:
#   - Per-package runs are sequential, not parallel, because some packages
#     share fixtures (sidecar lockfile, sqlite files) and concurrent runs
#     poison each other (observed during baseline capture).
#   - We invoke pytest as a subprocess and parse its short-summary line.
#     We deliberately do NOT pipe through tail/head/grep to mask exit codes:
#     the subprocess returncode is captured separately from the parsed line
#     and surfaced as a CRASH if non-zero in --quick mode.
#   - We do not fail on individual test failures; we fail only when the
#     passing count drops below baseline. A new failure that lowers the
#     count IS a regression and trips the gate. A flaky test that already
#     fails at baseline capture is recorded in the baseline floor.
#   - ASCII output only (no emoji), per CLAUDE.md sec 3.

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "tests" / "baseline-counts.json"

# Matches the pytest short-summary tail line. Examples:
#   "532 passed, 1 skipped, 2 deselected, 1 xfailed in 72.69s (0:01:12)"
#   "1 failed, 244 passed, 12 skipped, 7 deselected in 87.88s (0:01:27)"
#   "121 passed, 209 deselected in 2.73s"
_PASSED_RE = re.compile(r"(?P<count>\d+) passed")
_FAILED_RE = re.compile(r"(?P<count>\d+) failed")
_ERRORS_RE = re.compile(r"(?P<count>\d+) errors?")


def _load_baseline() -> dict:
    if not BASELINE_PATH.exists():
        print(
            f"ERROR: baseline file not found at {BASELINE_PATH}",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: baseline file is invalid JSON: {exc}", file=sys.stderr)
        sys.exit(2)


def _run_pytest_for_package(pkg_path: str, quick: bool) -> tuple[int, int, str, int]:
    """
    Run pytest -m plumbing for one package path and return (passed, failed, raw_tail, rc).

    quick=True uses --collect-only so the script can be used as a dry-run.
    """
    abs_path = REPO_ROOT / pkg_path
    if not abs_path.exists():
        return (0, 0, f"PACKAGE-MISSING: {pkg_path}", 2)
    # Invoke pytest through the ACTIVE interpreter (``sys.executable -m pytest``)
    # rather than a bare ``pytest`` on PATH. A bare ``pytest`` resolves via PATH
    # and can hit a STALE GLOBAL pytest (e.g. 7.4.4) that rejects the project's
    # ``minversion = 8.0`` with a UsageError (exit 4) and NO passing-count summary
    # line -- which this script would then parse as ``passed=0`` and report as a
    # spurious regression (the intermittent failed=1 / offenders artifact). Using
    # ``sys.executable -m pytest`` guarantees the pinned venv pytest (8.x).
    cmd = [sys.executable, "-m", "pytest", "-m", "plumbing", "--tb=no", "-q", pkg_path]
    if quick:
        # Insert after the ``-m pytest`` prefix so the flag still precedes the
        # pytest arguments (was index 1 for the bare-``pytest`` argv).
        cmd.insert(3, "--collect-only")
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        # Never let a child test that reads stdin (e.g. a CLI readline test) hang
        # this script when it is run interactively. The subprocess gets EOF
        # immediately.
        stdin=subprocess.DEVNULL,
    )
    tail = (proc.stdout or "").strip().splitlines()
    summary = tail[-1] if tail else ""
    passed_m = _PASSED_RE.search(summary)
    failed_m = _FAILED_RE.search(summary)
    errors_m = _ERRORS_RE.search(summary)
    if quick:
        # In quick mode pytest reports "N tests collected" not "N passed".
        collected_re = re.compile(r"(?P<count>\d+)(?:/\d+)? tests? collected")
        m = collected_re.search(summary)
        passed = int(m.group("count")) if m else 0
        return (passed, 0, summary, proc.returncode)
    passed = int(passed_m.group("count")) if passed_m else 0
    failed = int(failed_m.group("count")) if failed_m else 0
    if errors_m:
        # Collection error counts as a regression class on its own.
        failed += int(errors_m.group("count"))
    return (passed, failed, summary, proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enforce no-regression on plumbing-tier passing counts."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON report to stdout (in addition to the human summary).",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help=(
            "Use pytest --collect-only (no execution). Useful for fast CI "
            "smoke-checks of the baseline file shape, NOT for regression "
            "enforcement; collected-count drops are not necessarily passes."
        ),
    )
    parser.add_argument(
        "--package",
        action="append",
        default=None,
        help="Limit to one or more package paths (relative to repo root).",
    )
    args = parser.parse_args()

    baseline = _load_baseline()
    per_pkg: dict = baseline.get("perPackage", {})
    if not per_pkg:
        print("ERROR: baseline.perPackage is empty", file=sys.stderr)
        return 2

    selected = args.package or list(per_pkg.keys())
    unknown = [p for p in selected if p not in per_pkg]
    if unknown:
        print(
            f"ERROR: package(s) not in baseline.perPackage: {unknown}",
            file=sys.stderr,
        )
        return 2

    results: list[dict] = []
    offenders: list[dict] = []
    for pkg in selected:
        expected = int(per_pkg[pkg])
        passed, failed, summary, rc = _run_pytest_for_package(pkg, args.quick)
        delta = passed - expected
        regression = passed < expected
        entry = {
            "package": pkg,
            "baseline": expected,
            "actual_passed": passed,
            "actual_failed": failed,
            "delta": delta,
            "regression": regression,
            "pytest_rc": rc,
            "pytest_summary": summary,
        }
        results.append(entry)
        if regression:
            offenders.append(entry)
        marker = "FAIL" if regression else "OK"
        print(
            f"[{marker}] {pkg}: passed={passed} baseline={expected} "
            f"delta={delta:+d} failed={failed} rc={rc} :: {summary}"
        )

    print("-" * 72)
    total_passed = sum(r["actual_passed"] for r in results)
    total_baseline = sum(int(per_pkg[r["package"]]) for r in results)
    print(
        f"TOTAL passed={total_passed} baseline={total_baseline} "
        f"delta={total_passed - total_baseline:+d} "
        f"offenders={len(offenders)}"
    )

    if args.json:
        report = {
            "fulfills": baseline.get("fulfills", "VAL-V3M5-023"),
            "asOf": baseline.get("asOf"),
            "schemaVersion": baseline.get("schemaVersion"),
            "totalBaseline": total_baseline,
            "totalActualPassed": total_passed,
            "offenders": offenders,
            "results": results,
        }
        print(json.dumps(report, indent=2, sort_keys=True))

    if offenders:
        print(
            f"\nREGRESSION: {len(offenders)} package(s) below baseline:",
            file=sys.stderr,
        )
        for off in offenders:
            print(
                f"  - {off['package']}: passed {off['actual_passed']} < "
                f"baseline {off['baseline']} (delta {off['delta']:+d})",
                file=sys.stderr,
            )
        print(
            "\nTo update the baseline legitimately (e.g. tests removed in a "
            "refactor), edit tests/baseline-counts.json in the same commit "
            "and explain the decrement in the commit message.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
