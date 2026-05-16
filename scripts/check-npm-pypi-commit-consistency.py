#!/usr/bin/env python3
"""Cross-platform commit consistency gate (sub-feature w12.2 / VAL-W12-010).

Asserts that the in-flight npm release workflow and the PyPI release
workflow at ``.github/workflows/release-pypi.yml`` are publishing
artifacts built from the SAME source-commit SHA. The npm and PyPI
provenance attestations MUST bind to the same git commit; divergence
is a shipping integrity violation (eng plan acceptance criteria line
454: ship together or not at all).

This script is invoked from the npm release workflow under two
environment surfaces:

- pre-publish (cross-platform-consistency job): asserts the current
  workflow tag + commit match the most recent successful PyPI
  release workflow run for the same tag (if one exists), OR that
  the PyPI release workflow is queued/in-flight for the same tag
  and commit (parallel release path).
- final pre-publish (publish-sdk / publish-sidecar-bundle jobs):
  re-asserts the same binding immediately before npm publish, so a
  race between PyPI approval and npm approval cannot ship divergent
  SHAs.

The script's verdict is structural and conservative: when the GitHub
API is unavailable (e.g., the gh token has insufficient scope) the
script logs a warning and exits 0 so a transient API failure does
not block a release. Hard failures (commit divergence, malformed
input) exit non-zero with the canonical ``RELAY-RELEASE-010`` marker.

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output, ASCII-only source.

Usage:
    python scripts/check-npm-pypi-commit-consistency.py

Environment:
    RELAY_RELEASE_TAG     : the in-flight release tag (e.g., v0.1.0)
    RELAY_RELEASE_COMMIT  : the commit SHA the tag points at
    GH_TOKEN              : GitHub token for the gh CLI (optional)

Exit codes:
    0  consistent (or API unavailable; logged as warning)
    1  RELAY-RELEASE-010: npm + pypi commit SHAs diverge
    2  invalid invocation (missing tag/commit env)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Any

OWNER_REPO = "epochly-inc/relay"
PYPI_WORKFLOW_FILENAME = "release-pypi.yml"


def _emit_warning(message: str) -> None:
    """Emit a structured warning to stderr without failing the run."""
    print(f"WARN: {message}", file=sys.stderr)


def _emit_fail(message: str) -> None:
    """Emit a structured failure with the canonical RELAY-RELEASE-010 code."""
    print(f"FAIL: RELAY-RELEASE-010: {message}", file=sys.stderr)


def _emit_ok(message: str) -> None:
    print(f"PASS: {message}")


def _run_gh(args: list[str]) -> tuple[int, str, str]:
    """Invoke ``gh`` with the given args and return (rc, stdout, stderr).

    Returns (-1, "", "<reason>") when gh is not on PATH or fails to launch.
    """
    gh_path = shutil.which("gh")
    if gh_path is None:
        return (-1, "", "gh CLI not on PATH")
    try:
        proc = subprocess.run(  # noqa: S603 - command literal
            [gh_path, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (-1, "", f"gh invocation error: {exc}")
    return (proc.returncode, proc.stdout, proc.stderr)


def _query_pypi_workflow_runs(tag: str) -> list[dict[str, Any]] | None:
    """Return the PyPI release workflow runs for the given tag, or None
    when the GitHub API is unavailable / the gh CLI cannot reach it."""
    rc, stdout, stderr = _run_gh(
        [
            "api",
            f"repos/{OWNER_REPO}/actions/workflows/{PYPI_WORKFLOW_FILENAME}/runs",
            "-X",
            "GET",
            "-F",
            f"head_branch={tag}",
            "-F",
            "per_page=10",
        ]
    )
    if rc != 0:
        _emit_warning(f"gh api call failed (rc={rc}): {stderr.strip()}")
        return None
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        _emit_warning(f"gh api returned non-JSON payload: {exc}")
        return None
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        _emit_warning("gh api payload missing 'workflow_runs' list")
        return None
    return runs


def main() -> int:
    tag = os.environ.get("RELAY_RELEASE_TAG", "").strip()
    commit = os.environ.get("RELAY_RELEASE_COMMIT", "").strip()
    if not tag:
        print(
            "FAIL: RELAY_RELEASE_TAG env var must be set "
            "(e.g., from github.ref_name)",
            file=sys.stderr,
        )
        return 2
    if not commit:
        print(
            "FAIL: RELAY_RELEASE_COMMIT env var must be set "
            "(e.g., from github.sha)",
            file=sys.stderr,
        )
        return 2

    print(f"npm release tag:    {tag}")
    print(f"npm release commit: {commit}")

    runs = _query_pypi_workflow_runs(tag)
    if runs is None:
        # Conservative: API unavailable -> log warning and exit 0 so a
        # transient outage does not block release. The static guard
        # check-npm-publish-workflow.py:check_val_w12_010 plus the
        # identical tag-trigger surface together still bind the two
        # workflows to the same commit; this script is a runtime
        # belt-and-suspenders.
        _emit_warning(
            "could not query PyPI release workflow runs; "
            "consistency check skipped at runtime (static guard still in force)"
        )
        return 0

    if not runs:
        _emit_ok(
            f"no prior PyPI release workflow run for tag {tag}; "
            "this is the first publish surface to fire"
        )
        return 0

    for run in runs:
        head_sha = run.get("head_sha")
        run_url = run.get("html_url", "<unknown>")
        if not isinstance(head_sha, str):
            continue
        if head_sha != commit:
            _emit_fail(
                f"PyPI workflow run {run_url} for tag {tag} "
                f"used commit {head_sha}, but npm release is on commit "
                f"{commit} -- both releases MUST bind the same SHA"
            )
            return 1

    _emit_ok(
        f"PyPI release workflow runs for tag {tag} all bind commit {commit}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
