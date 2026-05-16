#!/usr/bin/env python3
"""W12.1 PyPI trusted publishing workflow guard.

Static linter that parses ``.github/workflows/release-pypi.yml`` and the
release runbook at ``docs/release/runbook.md`` to enforce the 10
contract assertions assigned to feature ``w12.1-release-pypi-trusted-publish``:

- VAL-W12-001  PyPI publish uses GitHub OIDC, never an API token.
- VAL-W12-002  Publisher bound to specific repo + workflow + environment.
- VAL-W12-003  Release env requires manual approval before publish.
- VAL-W12-004  Published sdist + wheel digests match SLSA attestation subjects.
- VAL-W12-005  Publish workflow signs all distributions with Sigstore.
- VAL-W12-006  Publish step idempotent under re-runs of same tag.
- VAL-W12-038  NO long-lived publish credentials in repo secrets.
- VAL-W12-039  Rollback via version increment, never destructive removal.
- VAL-W12-040  Version increment monotonic per SemVer.
- VAL-W12-046  Pre-announcement of breaking changes 7 days ahead.

The script exits 0 when every check passes. On failure it prints the
canonical ``RELAY-RELEASE-NNN`` error code per assertion (per contract
preamble exit-code mapping) and exits with a non-zero code suitable
for use as a CI guard.

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output, ASCII-only source.
Per CLAUDE.md keystone #3: workers run only manifest-declared commands;
this lives in ``scripts/`` and is invoked via the manifest's
``lint-pypi-publish-workflow`` command (declared as part of this feature).

Usage:
    python scripts/check-pypi-publish-workflow.py [--repo-root PATH] [--json]

Exit codes:
    0  all checks passed
    1  one or more checks failed (RELAY-RELEASE-NNN reported)
    2  workflow file missing or unparseable
    3  invalid invocation
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants pinned to the contract.
# ---------------------------------------------------------------------------

WORKFLOW_RELPATH = ".github/workflows/release-pypi.yml"
RUNBOOK_RELPATH = "docs/release/runbook.md"
ANNOUNCEMENTS_RELDIR = "docs/release/announcements"

EXPECTED_REPO = "epochly-inc/relay"
EXPECTED_WORKFLOW_FILENAME = "release-pypi.yml"
EXPECTED_ENVIRONMENT = "release"

# Long-lived credential secret names that signal a token-based publish
# (anti-pattern; VAL-W12-001 / VAL-W12-038).  Trusted publishing exchanges
# an ephemeral GitHub OIDC token for an ephemeral PyPI token at publish
# time; no static secret is ever referenced.
LONG_LIVED_PYPI_SECRET_NAMES: tuple[str, ...] = (
    "PYPI_TOKEN",
    "PYPI_API_TOKEN",
    "TWINE_PASSWORD",
    "TWINE_USERNAME",
    "PYPI_PASSWORD",
)

# Destructive operations that VAL-W12-039 forbids.  A workflow that
# invokes any of these without an explicit operator-only override is
# rejected (we forbid them unconditionally in the publish workflow;
# any operator-driven destructive op must live in a separate, manually
# triggered workflow with `workflow_dispatch.inputs.confirm_destructive`).
DESTRUCTIVE_OPS: tuple[str, ...] = (
    "npm unpublish",
    "pypi-cli delete",
    "gh release delete",
    "twine delete",
)

# Runbook section headers VAL-W12-039 / VAL-W12-046 / VAL-W12-002 reference.
REQUIRED_RUNBOOK_SECTIONS: tuple[str, ...] = (
    "## Trusted Publisher Binding",
    "## No Destructive Rollback",
    "## Pre-announcement Policy",
)


# ---------------------------------------------------------------------------
# Result types.
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single VAL-W12-NNN check."""

    assertion: str
    error_code: str
    passed: bool
    message: str = ""


@dataclass
class GuardReport:
    """Aggregate report across every assertion this guard enforces."""

    workflow_path: str
    runbook_path: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_path": self.workflow_path,
            "runbook_path": self.runbook_path,
            "ok": self.ok,
            "checks": [
                {
                    "assertion": c.assertion,
                    "error_code": c.error_code,
                    "passed": c.passed,
                    "message": c.message,
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# YAML loading helpers.
# ---------------------------------------------------------------------------


def _load_workflow_yaml(workflow_path: Path) -> dict[str, Any]:
    """Parse the workflow YAML.

    Raises ``SystemExit`` (exit 2) when the file is missing or unparseable;
    the calling guard cannot do anything useful without it.
    """
    try:
        text = workflow_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"FAIL: workflow file not found at {workflow_path}", file=sys.stderr)
        raise SystemExit(2) from None

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        print(f"FAIL: workflow YAML unparseable: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    if not isinstance(data, dict):
        print("FAIL: workflow YAML root must be a mapping", file=sys.stderr)
        raise SystemExit(2)

    return data


def _iter_jobs(workflow: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return []
    return [(name, job) for name, job in jobs.items() if isinstance(job, dict)]


def _iter_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [s for s in steps if isinstance(s, dict)]


def _publish_jobs(workflow: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return the subset of jobs that perform the actual PyPI upload.

    A "publish job" is any job whose steps include ``pypa/gh-action-pypi-publish``.
    """
    publish: list[tuple[str, dict[str, Any]]] = []
    for name, job in _iter_jobs(workflow):
        for step in _iter_steps(job):
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("pypa/gh-action-pypi-publish"):
                publish.append((name, job))
                break
    return publish


# ---------------------------------------------------------------------------
# Individual assertion checks.
# ---------------------------------------------------------------------------


def check_val_w12_001(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """OIDC trusted publishing; no API token.

    Workflow MUST:
      - declare ``permissions.id-token: write`` (at workflow or job scope)
        on the publish job
      - NOT reference any long-lived publish secret name
      - NOT pass ``password:`` or ``with: password:`` to the publish step
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-001",
            "RELAY-RELEASE-001",
            False,
            "no pypa/gh-action-pypi-publish step found in workflow",
        )

    # Long-lived secret reference scan: simple substring grep handles both
    # ${{ secrets.PYPI_TOKEN }} and bare references in env blocks.
    for secret_name in LONG_LIVED_PYPI_SECRET_NAMES:
        if f"secrets.{secret_name}" in raw_text:
            return CheckResult(
                "VAL-W12-001",
                "RELAY-RELEASE-001",
                False,
                f"workflow references long-lived publish secret 'secrets.{secret_name}'",
            )

    workflow_perms = workflow.get("permissions")
    workflow_has_id_token = (
        isinstance(workflow_perms, dict) and workflow_perms.get("id-token") == "write"
    )

    for name, job in publish_jobs:
        # id-token: write must be present at workflow OR job scope.
        job_perms = job.get("permissions")
        job_has_id_token = (
            isinstance(job_perms, dict) and job_perms.get("id-token") == "write"
        )
        if not (workflow_has_id_token or job_has_id_token):
            return CheckResult(
                "VAL-W12-001",
                "RELAY-RELEASE-001",
                False,
                f"publish job '{name}' lacks 'permissions.id-token: write'",
            )

        # No password input to the publish action.
        for step in _iter_steps(job):
            uses = step.get("uses", "")
            if not (isinstance(uses, str) and uses.startswith("pypa/gh-action-pypi-publish")):
                continue
            with_block = step.get("with", {})
            if isinstance(with_block, dict) and "password" in with_block:
                return CheckResult(
                    "VAL-W12-001",
                    "RELAY-RELEASE-001",
                    False,
                    f"publish step in job '{name}' passes a 'password:' input",
                )

    return CheckResult("VAL-W12-001", "RELAY-RELEASE-001", True)


def check_val_w12_002(
    workflow: dict[str, Any], runbook_text: str | None
) -> CheckResult:
    """Publisher bound to specific repo + workflow + environment.

    Workflow MUST:
      - run from a file literally named ``release-pypi.yml``
      - bind the publish job to ``environment: release``

    Runbook MUST document the trusted-publisher binding with repo,
    workflow filename, and environment name.
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-002",
            "RELAY-RELEASE-002",
            False,
            "no publish job found",
        )

    for name, job in publish_jobs:
        env = job.get("environment")
        env_name = env if isinstance(env, str) else (
            env.get("name") if isinstance(env, dict) else None
        )
        if env_name != EXPECTED_ENVIRONMENT:
            return CheckResult(
                "VAL-W12-002",
                "RELAY-RELEASE-002",
                False,
                (
                    f"publish job '{name}' must use 'environment: {EXPECTED_ENVIRONMENT}', "
                    f"got '{env_name}'"
                ),
            )

    if runbook_text is None:
        return CheckResult(
            "VAL-W12-002",
            "RELAY-RELEASE-002",
            False,
            "runbook missing at docs/release/runbook.md",
        )
    required_phrases = (
        f"repo: {EXPECTED_REPO}",
        f"workflow: {EXPECTED_WORKFLOW_FILENAME}",
        f"environment: {EXPECTED_ENVIRONMENT}",
    )
    for phrase in required_phrases:
        if phrase not in runbook_text:
            return CheckResult(
                "VAL-W12-002",
                "RELAY-RELEASE-002",
                False,
                f"runbook does not declare trusted-publisher binding phrase '{phrase}'",
            )

    return CheckResult("VAL-W12-002", "RELAY-RELEASE-002", True)


def check_val_w12_003(
    workflow: dict[str, Any], runbook_text: str | None
) -> CheckResult:
    """Release env requires manual approval before publish.

    GitHub Environment protection rules (required reviewers) are configured
    out-of-band against the GitHub API; the workflow YAML cannot itself
    *configure* them.  This check verifies that the workflow consumes the
    protected environment (covered also by VAL-W12-002) AND that the
    runbook documents the required-reviewer expectation.  The actual API
    verification (`GET /repos/epochly-inc/relay/environments/release`)
    lives in the release-gate audit script invoked at tag-cut time;
    this static guard ensures the docs say it.
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-003",
            "RELAY-RELEASE-003",
            False,
            "no publish job found",
        )

    # Same environment check as VAL-W12-002; here we just confirm the
    # job did NOT use environment.url with no name (which would bypass
    # protection).  Belt-and-suspenders.
    for name, job in publish_jobs:
        env = job.get("environment")
        env_name = env if isinstance(env, str) else (
            env.get("name") if isinstance(env, dict) else None
        )
        if not env_name:
            return CheckResult(
                "VAL-W12-003",
                "RELAY-RELEASE-003",
                False,
                f"publish job '{name}' missing environment name",
            )

    if runbook_text is None:
        return CheckResult(
            "VAL-W12-003",
            "RELAY-RELEASE-003",
            False,
            "runbook missing",
        )
    required_phrases = (
        "required_reviewers",
        "manual approval",
    )
    for phrase in required_phrases:
        if phrase.lower() not in runbook_text.lower():
            return CheckResult(
                "VAL-W12-003",
                "RELAY-RELEASE-003",
                False,
                f"runbook does not document '{phrase}' for release environment",
            )

    return CheckResult("VAL-W12-003", "RELAY-RELEASE-003", True)


def check_val_w12_004(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Published sdist + wheel digests match SLSA attestation subjects.

    The release-pypi workflow itself produces sdist + wheel artifacts and
    delegates SLSA generation to the slsa-github-generator reusable
    workflow.  This static guard verifies:

      - the build job uploads the dist/ directory as an artifact, AND
      - the workflow declares an output ``hashes`` (base64-encoded
        ``sha256sum`` payload) that is fed into the SLSA generator's
        ``base64-subjects`` input, OR the workflow file references the
        SLSA generator reusable workflow with a ``base64-subjects``
        input wired from the build job's outputs.

    A workflow that publishes without wiring the hash chain into the
    SLSA generator FAILS.  ``slsa-verifier`` runs at install / verify
    time and validates the actual subject-digest equality on the
    published artifacts (per VAL-W12-004 evidence column); this guard
    enforces that the workflow *can* produce a matching attestation.
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-004",
            "RELAY-RELEASE-004",
            False,
            "no publish job found",
        )

    # Look for a job that declares `outputs.hashes` and uses sha256sum
    # over dist/* artifacts.
    has_hash_output = False
    for _name, job in _iter_jobs(workflow):
        outputs = job.get("outputs")
        if isinstance(outputs, dict) and "hashes" in outputs:
            has_hash_output = True
            break

    if not has_hash_output:
        return CheckResult(
            "VAL-W12-004",
            "RELAY-RELEASE-004",
            False,
            "no job declares 'outputs.hashes' (base64-encoded sha256sum payload)",
        )

    # Look for the SLSA generator reference (pinned by SHA per VAL-W12-012;
    # this guard only checks presence).
    if "slsa-framework/slsa-github-generator" not in raw_text:
        return CheckResult(
            "VAL-W12-004",
            "RELAY-RELEASE-004",
            False,
            "workflow does not invoke slsa-framework/slsa-github-generator",
        )

    if "base64-subjects" not in raw_text:
        return CheckResult(
            "VAL-W12-004",
            "RELAY-RELEASE-004",
            False,
            "workflow does not wire 'base64-subjects' into the SLSA generator",
        )

    return CheckResult("VAL-W12-004", "RELAY-RELEASE-004", True)


def check_val_w12_005(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Publish workflow signs all distributions with Sigstore.

    ``pypa/gh-action-pypi-publish@release/v1`` ships Sigstore signing
    when ``attestations: true`` (the action default since v1.10) AND the
    workflow runs with ``id-token: write``.  VAL-W12-005 requires the
    workflow to make signing explicit and non-optional.

    Acceptable forms:
      A) ``pypa/gh-action-pypi-publish`` step with ``with.attestations: true``
         (PEP 740 PyPI distribution attestations, Sigstore-backed)
      B) An additional ``sigstore/gh-action-sigstore-python`` step that
         signs every dist/* artifact before the publish step
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-005",
            "RELAY-RELEASE-005",
            False,
            "no publish job found",
        )

    for name, job in publish_jobs:
        steps = _iter_steps(job)
        signed_by_action = False
        signed_by_sigstore = False
        for step in steps:
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith("pypa/gh-action-pypi-publish"):
                with_block = step.get("with", {})
                if isinstance(with_block, dict):
                    attestations = with_block.get("attestations")
                    # Accept boolean true or string "true".
                    if attestations is True or (
                        isinstance(attestations, str) and attestations.lower() == "true"
                    ):
                        signed_by_action = True
            if isinstance(uses, str) and uses.startswith(
                "sigstore/gh-action-sigstore-python"
            ):
                signed_by_sigstore = True

        if not (signed_by_action or signed_by_sigstore):
            return CheckResult(
                "VAL-W12-005",
                "RELAY-RELEASE-005",
                False,
                (
                    f"publish job '{name}' does not sign distributions: "
                    "set 'attestations: true' on pypa/gh-action-pypi-publish OR "
                    "add a sigstore/gh-action-sigstore-python step"
                ),
            )

    return CheckResult("VAL-W12-005", "RELAY-RELEASE-005", True)


def check_val_w12_006(workflow: dict[str, Any]) -> CheckResult:
    """Publish step idempotent under re-runs of the same tag.

    Re-running a release workflow against an already-published tag MUST
    NOT attempt to overwrite or shadow a distribution.  PyPI itself
    rejects re-uploads of the same ``(name, version)``; the workflow
    MUST either:

      - pass ``skip-existing: true`` to ``pypa/gh-action-pypi-publish``
        (no-op behavior), or
      - fail fast with the canonical RELAY-RELEASE-006 marker (this
        workflow chooses skip-existing per the runbook).
    """
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-006",
            "RELAY-RELEASE-006",
            False,
            "no publish job found",
        )

    for name, job in publish_jobs:
        for step in _iter_steps(job):
            uses = step.get("uses", "")
            if not (isinstance(uses, str) and uses.startswith("pypa/gh-action-pypi-publish")):
                continue
            with_block = step.get("with", {})
            if not isinstance(with_block, dict):
                with_block = {}
            skip_existing = with_block.get("skip-existing") or with_block.get("skip_existing")
            if not (
                skip_existing is True
                or (isinstance(skip_existing, str) and skip_existing.lower() == "true")
            ):
                return CheckResult(
                    "VAL-W12-006",
                    "RELAY-RELEASE-006",
                    False,
                    (
                        f"publish step in job '{name}' must set 'skip-existing: true' "
                        "for idempotent re-runs"
                    ),
                )

    return CheckResult("VAL-W12-006", "RELAY-RELEASE-006", True)


def check_val_w12_038(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """No long-lived publish credentials anywhere in the workflow.

    Companion to VAL-W12-001; this is the broader audit that covers the
    entire workflow (any job, any step), not just the publish step.
    """
    for secret_name in LONG_LIVED_PYPI_SECRET_NAMES:
        if f"secrets.{secret_name}" in raw_text:
            return CheckResult(
                "VAL-W12-038",
                "RELAY-RELEASE-038",
                False,
                (
                    f"workflow references long-lived publish secret "
                    f"'secrets.{secret_name}' (use OIDC trusted publishing)"
                ),
            )
    # Also belt-check that no job env block injects a *_TOKEN env var
    # that resolves from a long-lived secret.
    for _name, job in _iter_jobs(workflow):
        env = job.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if k in LONG_LIVED_PYPI_SECRET_NAMES and isinstance(v, str):
                    return CheckResult(
                        "VAL-W12-038",
                        "RELAY-RELEASE-038",
                        False,
                        f"job env injects long-lived publish credential '{k}'",
                    )
    return CheckResult("VAL-W12-038", "RELAY-RELEASE-038", True)


def check_val_w12_039(
    workflow: dict[str, Any], raw_text: str, runbook_text: str | None
) -> CheckResult:
    """Rollback via version increment, never destructive removal.

    The publish workflow MUST NOT invoke any destructive op
    (``npm unpublish``, ``pypi-cli delete``, ``gh release delete``,
    ``twine delete``), AND the runbook MUST document the no-destructive
    policy in a dedicated section.
    """
    # Strip comments before scanning so that comment-form documentation
    # of the banned ops (e.g., "we never invoke `gh release delete`")
    # does not trigger a false positive.
    code_only_lines: list[str] = []
    for line in raw_text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Strip trailing inline comment (best-effort; YAML allows # mid-line
        # only when preceded by whitespace).
        if " #" in line:
            line = line[: line.index(" #")]
        code_only_lines.append(line)
    code_only = "\n".join(code_only_lines)

    for op in DESTRUCTIVE_OPS:
        if op in code_only:
            return CheckResult(
                "VAL-W12-039",
                "RELAY-RELEASE-039",
                False,
                f"workflow invokes destructive op '{op}' (forbidden by no-destructive-rollback)",
            )

    if runbook_text is None:
        return CheckResult(
            "VAL-W12-039",
            "RELAY-RELEASE-039",
            False,
            "runbook missing",
        )
    if "## No Destructive Rollback" not in runbook_text:
        return CheckResult(
            "VAL-W12-039",
            "RELAY-RELEASE-039",
            False,
            "runbook missing required '## No Destructive Rollback' section",
        )

    return CheckResult("VAL-W12-039", "RELAY-RELEASE-039", True)


def check_val_w12_040(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Version increment monotonic per SemVer.

    The workflow MUST include a guard step that compares the proposed
    tag to the latest published PyPI version and refuses to publish on
    non-monotonic ordering.  We look for a step that invokes the
    canonical guard script ``scripts/check-semver-monotonic.py`` (or
    inlines an equivalent ``semver.cmp`` assertion).
    """
    sentinel_phrases = (
        "check-semver-monotonic",
        "semver.cmp(",
        "Version must be strictly greater",
        "monotonic per SemVer",
    )
    if not any(p in raw_text for p in sentinel_phrases):
        return CheckResult(
            "VAL-W12-040",
            "RELAY-RELEASE-040",
            False,
            (
                "workflow lacks a monotonic-semver guard "
                "(expected reference to check-semver-monotonic or 'monotonic per SemVer')"
            ),
        )
    return CheckResult("VAL-W12-040", "RELAY-RELEASE-040", True)


def check_val_w12_046(
    workflow: dict[str, Any], raw_text: str, repo_root: Path
) -> CheckResult:
    """Pre-announcement of breaking changes 7 days ahead.

    The workflow MUST include a guard step that reads the proposed tag's
    metadata for a ``breaking: true`` marker and refuses to publish
    unless an announcement file exists in ``docs/release/announcements/``
    dated at least 7 days earlier.  We look for the canonical guard
    script ``scripts/check-pre-announcement.py`` (referenced by name)
    AND for the announcements directory's presence.
    """
    if "check-pre-announcement" not in raw_text:
        return CheckResult(
            "VAL-W12-046",
            "RELAY-RELEASE-046",
            False,
            "workflow does not invoke scripts/check-pre-announcement.py",
        )
    ann_dir = repo_root / ANNOUNCEMENTS_RELDIR
    if not ann_dir.is_dir():
        return CheckResult(
            "VAL-W12-046",
            "RELAY-RELEASE-046",
            False,
            f"announcements directory missing at {ANNOUNCEMENTS_RELDIR}",
        )
    return CheckResult("VAL-W12-046", "RELAY-RELEASE-046", True)


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------


def run_all_checks(repo_root: Path) -> GuardReport:
    workflow_path = repo_root / WORKFLOW_RELPATH
    runbook_path = repo_root / RUNBOOK_RELPATH

    workflow = _load_workflow_yaml(workflow_path)
    raw_text = workflow_path.read_text(encoding="utf-8")
    runbook_text: str | None = None
    if runbook_path.is_file():
        runbook_text = runbook_path.read_text(encoding="utf-8")

    report = GuardReport(
        workflow_path=str(workflow_path.relative_to(repo_root)),
        runbook_path=str(runbook_path.relative_to(repo_root))
        if runbook_path.is_file()
        else RUNBOOK_RELPATH,
    )
    report.checks.append(check_val_w12_001(workflow, raw_text))
    report.checks.append(check_val_w12_002(workflow, runbook_text))
    report.checks.append(check_val_w12_003(workflow, runbook_text))
    report.checks.append(check_val_w12_004(workflow, raw_text))
    report.checks.append(check_val_w12_005(workflow, raw_text))
    report.checks.append(check_val_w12_006(workflow))
    report.checks.append(check_val_w12_038(workflow, raw_text))
    report.checks.append(check_val_w12_039(workflow, raw_text, runbook_text))
    report.checks.append(check_val_w12_040(workflow, raw_text))
    report.checks.append(check_val_w12_046(workflow, raw_text, repo_root))
    return report


def _print_human(report: GuardReport) -> None:
    print(f"workflow: {report.workflow_path}")
    print(f"runbook:  {report.runbook_path}")
    print("")
    for c in report.checks:
        marker = "[OK]  " if c.passed else "[FAIL]"
        line = f"{marker} {c.assertion}  {c.error_code}"
        if not c.passed and c.message:
            line += f"  -- {c.message}"
        print(line)
    print("")
    print("PASS" if report.ok else "FAIL")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static guard for the PyPI trusted-publishing workflow."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root containing .github/workflows/release-pypi.yml "
            "(defaults to the working directory)."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )
    args = parser.parse_args(argv)

    repo_root = (args.repo_root or Path.cwd()).resolve()
    if not (repo_root / WORKFLOW_RELPATH).is_file():
        print(
            f"FAIL: workflow file not found at {repo_root / WORKFLOW_RELPATH}",
            file=sys.stderr,
        )
        return 2

    report = run_all_checks(repo_root)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_human(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
