#!/usr/bin/env python3
"""W12.2 npm provenance release workflow guard.

Static linter that parses ``.github/workflows/release-npm.yml`` (and
the sister ``.github/workflows/release-pypi.yml`` for the cross-
platform binding check) to enforce the four contract assertions
assigned to feature ``w12.2-release-npm-provenance``:

- VAL-W12-007  npm publish uses GitHub OIDC + ``--provenance``; never NPM_TOKEN.
- VAL-W12-008  Tarball digest matches provenance subject digest
              (workflow wires SHA-256 subjects + runs ``npm audit
              signatures`` post-publish).
- VAL-W12-009  Both ``@epochly/relay`` AND ``@epochly/relay-sidecar-bundle``
              publish with ``--provenance``.
- VAL-W12-010  npm provenance attestation references the same source
              commit SHA as the PyPI release.

The script exits 0 when every check passes. On failure it prints the
canonical ``RELAY-RELEASE-NNN`` error code per assertion (per contract
preamble exit-code mapping) and exits with a non-zero code suitable
for use as a CI guard.

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output, ASCII-only source.
Per CLAUDE.md keystone #3: workers run only manifest-declared commands;
this lives in ``scripts/`` and is invoked via the manifest's
``lint-npm-publish-workflow`` command (declared as part of this feature).

Usage:
    python scripts/check-npm-publish-workflow.py [--repo-root PATH] [--json]

Exit codes:
    0  all checks passed
    1  one or more checks failed (RELAY-RELEASE-NNN reported)
    2  workflow file missing or unparseable
    3  invalid invocation
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# SHA-pin enforcement (VAL-W12-012 strengthening per spec keystone #11).
# See scripts/check-pypi-publish-workflow.py for the rationale narrative.
# ---------------------------------------------------------------------------

SHA40_RE: re.Pattern[str] = re.compile(r"^[a-f0-9]{40}$")

# The npm release workflow consumes the SLSA reusable workflow (twice,
# once per package); ``--provenance`` itself ships with Node so there is
# no second-party action equivalent of pypa/gh-action-pypi-publish here.
SHA_PIN_REQUIRED_ACTIONS: tuple[str, ...] = (
    "slsa-framework/slsa-github-generator",
    # gitleaks/gitleaks-action is the trust-anchor key-material
    # secret scanner; if a future workflow refactor pulls it into
    # the release pipeline (e.g., a pre-publish key-leak check),
    # it MUST be SHA-pinned just like the SLSA generator.
    "gitleaks/gitleaks-action",
)

# ---------------------------------------------------------------------------
# Constants pinned to the contract.
# ---------------------------------------------------------------------------

NPM_WORKFLOW_RELPATH = ".github/workflows/release-npm.yml"
PYPI_WORKFLOW_RELPATH = ".github/workflows/release-pypi.yml"

EXPECTED_ENVIRONMENT = "release"

# The two npm packages that MUST publish together (VAL-W12-009).
EXPECTED_NPM_PACKAGES: tuple[str, ...] = (
    "@epochly/relay",
    "@epochly/relay-sidecar-bundle",
)

# Required publish jobs (one per package). VAL-W12-009 fails if either
# job is missing.
REQUIRED_PUBLISH_JOBS: tuple[str, ...] = (
    "publish-sdk",
    "publish-sidecar-bundle",
)
REQUIRED_BUILD_JOBS: tuple[str, ...] = (
    "build-sdk",
    "build-sidecar-bundle",
)

# Long-lived credential secret names that signal a token-based publish
# (anti-pattern; VAL-W12-007). Trusted publishing exchanges an
# ephemeral GitHub OIDC token for an ephemeral npm token at publish
# time; no static secret is ever referenced.
LONG_LIVED_NPM_SECRET_NAMES: tuple[str, ...] = (
    "NPM_TOKEN",
    "NPM_API_TOKEN",
    "NPM_AUTH_TOKEN",
    "NPM_PASSWORD",
    "NODE_AUTH_TOKEN",
)

# Canonical sentinel for the cross-platform consistency step.
COMMIT_CONSISTENCY_SENTINELS: tuple[str, ...] = (
    "check-npm-pypi-commit-consistency",
    "RELAY-RELEASE-010",
)

# Canonical post-publish digest verifier command.
POST_PUBLISH_VERIFIER = "npm audit signatures"

# Canonical npm publish invocation form. ``--provenance`` is REQUIRED;
# ``--access public`` is conventional for scoped packages and is
# checked separately by VAL-W12-007.
PROVENANCE_FLAG = "--provenance"


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
    pypi_workflow_path: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_path": self.workflow_path,
            "pypi_workflow_path": self.pypi_workflow_path,
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
# YAML helpers.
# ---------------------------------------------------------------------------


def _load_workflow_yaml(workflow_path: Path) -> dict[str, Any]:
    """Parse the workflow YAML.

    Raises ``SystemExit`` (exit 2) when the file is missing or unparseable.
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
    """Return the subset of jobs that perform an ``npm publish``."""
    publish: list[tuple[str, dict[str, Any]]] = []
    for name, job in _iter_jobs(workflow):
        for step in _iter_steps(job):
            run = step.get("run", "")
            if isinstance(run, str) and "npm publish" in run:
                publish.append((name, job))
                break
    return publish


def _triggers(workflow: dict[str, Any]) -> dict[str, Any] | None:
    """Return the ``on`` trigger block, tolerating PyYAML's boolean-True
    coercion of bare ``on:`` keys."""
    triggers = workflow.get("on")
    if triggers is None:
        triggers = workflow.get(True)
    if not isinstance(triggers, dict):
        return None
    return triggers


def _tag_trigger_patterns(workflow: dict[str, Any]) -> list[str]:
    """Return the list of tag-trigger glob patterns declared by the
    workflow's ``on.push.tags``."""
    triggers = _triggers(workflow)
    if triggers is None:
        return []
    push = triggers.get("push")
    if not isinstance(push, dict):
        return []
    tags = push.get("tags")
    if not isinstance(tags, list):
        return []
    return [t for t in tags if isinstance(t, str)]


# ---------------------------------------------------------------------------
# Individual assertion checks.
# ---------------------------------------------------------------------------


def _iter_uses_refs(
    workflow: dict[str, Any],
) -> list[tuple[str, int, str]]:
    """Yield every ``(job_name, step_index_or_-1, uses_value)`` triple."""
    out: list[tuple[str, int, str]] = []
    for name, job in _iter_jobs(workflow):
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            out.append((name, -1, job_uses))
        for idx, step in enumerate(_iter_steps(job)):
            uses = step.get("uses")
            if isinstance(uses, str):
                out.append((name, idx, uses))
    return out


def _split_uses_ref(uses: str) -> tuple[str, str]:
    if "@" not in uses:
        return ("", uses)
    action_path, _, ref = uses.partition("@")
    return (action_path, ref)


def _locate_uses_line(raw_text: str, uses_value: str) -> int:
    needle = uses_value.strip()
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("uses:"):
            value = stripped[len("uses:") :].strip().strip("'\"")
            if value == needle:
                return idx
    return 0


def check_sha_pinning(
    workflow: dict[str, Any], raw_text: str, workflow_relpath: str
) -> CheckResult:
    """Every reference to a supply-chain critical action MUST pin to a
    40-character lowercase-hex commit SHA. See pypi guard for narrative.
    """
    violations: list[str] = []
    for job_name, _step_idx, uses in _iter_uses_refs(workflow):
        action_path, ref = _split_uses_ref(uses)
        if not action_path:
            continue
        for required in SHA_PIN_REQUIRED_ACTIONS:
            if not action_path.startswith(required):
                continue
            if SHA40_RE.match(ref) is None:
                lineno = _locate_uses_line(raw_text, uses)
                msg = (
                    f"FAIL: {workflow_relpath}:{lineno}: action {uses!r} "
                    f"must be pinned to 40-char SHA, got {ref!r} "
                    f"(job={job_name!r})"
                )
                violations.append(msg)
                print(msg, file=sys.stderr)
            break
    if violations:
        return CheckResult(
            "VAL-W12-012",
            "RELAY-RELEASE-012",
            False,
            "; ".join(violations),
        )
    return CheckResult("VAL-W12-012", "RELAY-RELEASE-012", True)


def check_val_w12_007(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """npm publish uses OIDC + ``--provenance``; no NPM_TOKEN secret.

    Workflow MUST:
      - NOT reference any long-lived publish secret name
        (NPM_TOKEN, NPM_API_TOKEN, NPM_AUTH_TOKEN, NPM_PASSWORD,
        NODE_AUTH_TOKEN)
      - declare ``permissions.id-token: write`` on every publish job
      - run ``npm publish --provenance`` in every publish job
    """
    # Long-lived secret reference scan: simple substring grep handles both
    # ${{ secrets.NPM_TOKEN }} and bare references in env blocks.
    for secret_name in LONG_LIVED_NPM_SECRET_NAMES:
        if f"secrets.{secret_name}" in raw_text:
            return CheckResult(
                "VAL-W12-007",
                "RELAY-RELEASE-007",
                False,
                (
                    f"workflow references long-lived npm secret "
                    f"'secrets.{secret_name}' (use OIDC trusted publishing)"
                ),
            )

    # Job env scan: env blocks injecting long-lived credentials are also banned.
    for _name, job in _iter_jobs(workflow):
        env = job.get("env")
        if isinstance(env, dict):
            for key in env:
                if key in LONG_LIVED_NPM_SECRET_NAMES:
                    return CheckResult(
                        "VAL-W12-007",
                        "RELAY-RELEASE-007",
                        False,
                        f"job env injects long-lived npm credential '{key}'",
                    )

    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-007",
            "RELAY-RELEASE-007",
            False,
            "no job invokes 'npm publish'",
        )

    workflow_perms = workflow.get("permissions")
    workflow_has_id_token = (
        isinstance(workflow_perms, dict)
        and workflow_perms.get("id-token") == "write"
    )

    for name, job in publish_jobs:
        # id-token: write must be present at workflow OR job scope.
        job_perms = job.get("permissions")
        job_has_id_token = (
            isinstance(job_perms, dict) and job_perms.get("id-token") == "write"
        )
        if not (workflow_has_id_token or job_has_id_token):
            return CheckResult(
                "VAL-W12-007",
                "RELAY-RELEASE-007",
                False,
                f"publish job '{name}' lacks 'permissions.id-token: write'",
            )

        # Every npm publish step must include --provenance.
        found_provenance = False
        for step in _iter_steps(job):
            run = step.get("run", "")
            if not (isinstance(run, str) and "npm publish" in run):
                continue
            if PROVENANCE_FLAG not in run:
                return CheckResult(
                    "VAL-W12-007",
                    "RELAY-RELEASE-007",
                    False,
                    (
                        f"publish step in job '{name}' invokes 'npm publish' "
                        f"without '{PROVENANCE_FLAG}'"
                    ),
                )
            found_provenance = True

        if not found_provenance:
            return CheckResult(
                "VAL-W12-007",
                "RELAY-RELEASE-007",
                False,
                f"publish job '{name}' has no 'npm publish' step",
            )

    return CheckResult("VAL-W12-007", "RELAY-RELEASE-007", True)


def check_val_w12_008(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Tarball digest matches provenance subject digest.

    Two-part check:
      (1) workflow declares per-package ``outputs.hashes`` (base64
          sha256sum payload) and wires them into the SLSA generator
          via ``base64-subjects``; the static SHA-256 hash chain is
          checkable offline by ``slsa-verifier`` at install time.
      (2) workflow runs ``npm audit signatures`` post-publish on every
          publish job; this is the canonical online verifier that
          fetches the published tarball back, recomputes its SHA-512,
          and verifies the digest equals the attestation subject.
    """
    # (1) base64-subjects wiring via SLSA generator.
    has_hash_output = False
    for _name, job in _iter_jobs(workflow):
        outputs = job.get("outputs")
        if isinstance(outputs, dict) and "hashes" in outputs:
            has_hash_output = True
            break

    if not has_hash_output:
        return CheckResult(
            "VAL-W12-008",
            "RELAY-RELEASE-008",
            False,
            "no job declares 'outputs.hashes' (base64 sha256sum payload)",
        )

    if "slsa-framework/slsa-github-generator" not in raw_text:
        return CheckResult(
            "VAL-W12-008",
            "RELAY-RELEASE-008",
            False,
            "workflow does not invoke slsa-framework/slsa-github-generator",
        )

    if "base64-subjects" not in raw_text:
        return CheckResult(
            "VAL-W12-008",
            "RELAY-RELEASE-008",
            False,
            "workflow does not wire 'base64-subjects' into the SLSA generator",
        )

    # (2) every publish job runs `npm audit signatures` post-publish.
    publish_jobs = _publish_jobs(workflow)
    if not publish_jobs:
        return CheckResult(
            "VAL-W12-008",
            "RELAY-RELEASE-008",
            False,
            "no publish job found (cannot verify post-publish signature audit)",
        )
    for name, job in publish_jobs:
        has_audit = False
        for step in _iter_steps(job):
            run = step.get("run", "")
            if isinstance(run, str) and POST_PUBLISH_VERIFIER in run:
                has_audit = True
                break
        if not has_audit:
            return CheckResult(
                "VAL-W12-008",
                "RELAY-RELEASE-008",
                False,
                (
                    f"publish job '{name}' does not run "
                    f"'{POST_PUBLISH_VERIFIER}' post-publish "
                    "(tarball digest -> provenance subject binding unverified)"
                ),
            )

    return CheckResult("VAL-W12-008", "RELAY-RELEASE-008", True)


def check_val_w12_009(workflow: dict[str, Any], raw_text: str) -> CheckResult:
    """Both @epochly/relay AND @epochly/relay-sidecar-bundle publish
    with provenance.

    Three-part check:
      (1) every required publish job is present (publish-sdk,
          publish-sidecar-bundle)
      (2) every required build job is present (build-sdk,
          build-sidecar-bundle)
      (3) every publish job's npm publish step includes --provenance
          (overlap with VAL-W12-007 but scoped to each named package
          job so a regression in only one of the two is caught here).
    """
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return CheckResult(
            "VAL-W12-009",
            "RELAY-RELEASE-009",
            False,
            "workflow declares no jobs",
        )

    for required in REQUIRED_PUBLISH_JOBS:
        if required not in jobs:
            return CheckResult(
                "VAL-W12-009",
                "RELAY-RELEASE-009",
                False,
                (
                    f"required publish job '{required}' missing -- both "
                    f"@epochly/relay AND @epochly/relay-sidecar-bundle "
                    f"MUST publish with --provenance (eng plan L3 line 226)"
                ),
            )

    for required in REQUIRED_BUILD_JOBS:
        if required not in jobs:
            return CheckResult(
                "VAL-W12-009",
                "RELAY-RELEASE-009",
                False,
                f"required build job '{required}' missing",
            )

    # Per-job provenance check (defense in depth).
    for job_name in REQUIRED_PUBLISH_JOBS:
        job = jobs[job_name]
        if not isinstance(job, dict):
            return CheckResult(
                "VAL-W12-009",
                "RELAY-RELEASE-009",
                False,
                f"required publish job '{job_name}' has invalid shape",
            )
        found_publish = False
        for step in _iter_steps(job):
            run = step.get("run", "")
            if isinstance(run, str) and "npm publish" in run:
                found_publish = True
                if PROVENANCE_FLAG not in run:
                    return CheckResult(
                        "VAL-W12-009",
                        "RELAY-RELEASE-009",
                        False,
                        (
                            f"publish job '{job_name}' invokes 'npm publish' "
                            f"without '{PROVENANCE_FLAG}'"
                        ),
                    )
        if not found_publish:
            return CheckResult(
                "VAL-W12-009",
                "RELAY-RELEASE-009",
                False,
                f"publish job '{job_name}' has no 'npm publish' step",
            )

    # Sanity: the workflow references both package names somewhere
    # (in a publish URL, a package directory, or comment) so a future
    # rename does not silently break the binding.
    for pkg in EXPECTED_NPM_PACKAGES:
        if pkg not in raw_text:
            return CheckResult(
                "VAL-W12-009",
                "RELAY-RELEASE-009",
                False,
                (
                    f"workflow does not reference package '{pkg}' anywhere "
                    f"(both @epochly/relay AND @epochly/relay-sidecar-bundle "
                    f"must publish together)"
                ),
            )

    return CheckResult("VAL-W12-009", "RELAY-RELEASE-009", True)


def check_val_w12_010(
    workflow: dict[str, Any],
    raw_text: str,
    pypi_workflow_path: Path,
) -> CheckResult:
    """npm provenance attestation references same git commit as PyPI release.

    Three-part check:
      (1) the pypi release workflow exists at the expected path
      (2) both workflows fire on the SAME tag pattern (single trigger
          surface -> single source commit SHA)
      (3) the npm workflow runs the canonical cross-platform consistency
          script ``check-npm-pypi-commit-consistency.py`` (sentinel
          string ``check-npm-pypi-commit-consistency`` or the structured
          error code ``RELAY-RELEASE-010`` present in some step)
    """
    # (1) pypi workflow must exist for the cross-platform binding check.
    if not pypi_workflow_path.is_file():
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            (
                f"pypi release workflow missing at "
                f"{pypi_workflow_path}; cannot verify same-commit binding"
            ),
        )

    # (2) tag-trigger pattern equality.
    try:
        pypi_text = pypi_workflow_path.read_text(encoding="utf-8")
    except OSError as exc:
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            f"could not read pypi workflow: {exc}",
        )
    try:
        pypi_workflow = yaml.safe_load(pypi_text)
    except yaml.YAMLError as exc:
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            f"pypi workflow YAML unparseable: {exc}",
        )
    if not isinstance(pypi_workflow, dict):
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            "pypi workflow YAML root is not a mapping",
        )

    npm_tags = _tag_trigger_patterns(workflow)
    pypi_tags = _tag_trigger_patterns(pypi_workflow)
    if not npm_tags:
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            "npm workflow does not declare 'on.push.tags' trigger",
        )
    if not pypi_tags:
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            "pypi workflow does not declare 'on.push.tags' trigger",
        )
    if sorted(npm_tags) != sorted(pypi_tags):
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            (
                f"npm tag triggers {npm_tags!r} != pypi tag triggers "
                f"{pypi_tags!r}; both workflows must fire on the SAME tag "
                "to bind the same source commit SHA"
            ),
        )

    # (3) cross-platform consistency sentinel must appear in some step.
    found_sentinel = False
    for _name, job in _iter_jobs(workflow):
        for step in _iter_steps(job):
            run = step.get("run", "")
            if not isinstance(run, str):
                continue
            for sentinel in COMMIT_CONSISTENCY_SENTINELS:
                if sentinel in run:
                    found_sentinel = True
                    break
            if found_sentinel:
                break
        if found_sentinel:
            break

    if not found_sentinel:
        return CheckResult(
            "VAL-W12-010",
            "RELAY-RELEASE-010",
            False,
            (
                "workflow does not invoke the cross-platform commit "
                "consistency check (expected reference to "
                "'check-npm-pypi-commit-consistency' or "
                "'RELAY-RELEASE-010' in some step)"
            ),
        )

    return CheckResult("VAL-W12-010", "RELAY-RELEASE-010", True)


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------


def run_all_checks(repo_root: Path) -> GuardReport:
    workflow_path = repo_root / NPM_WORKFLOW_RELPATH
    pypi_workflow_path = repo_root / PYPI_WORKFLOW_RELPATH

    workflow = _load_workflow_yaml(workflow_path)
    raw_text = workflow_path.read_text(encoding="utf-8")

    report = GuardReport(
        workflow_path=str(workflow_path.relative_to(repo_root)),
        pypi_workflow_path=str(pypi_workflow_path.relative_to(repo_root))
        if pypi_workflow_path.is_file()
        else PYPI_WORKFLOW_RELPATH,
    )
    report.checks.append(check_val_w12_007(workflow, raw_text))
    report.checks.append(check_val_w12_008(workflow, raw_text))
    report.checks.append(check_val_w12_009(workflow, raw_text))
    report.checks.append(check_val_w12_010(workflow, raw_text, pypi_workflow_path))
    # VAL-W12-012 strengthening: SHA-pin enforcement for supply-chain
    # critical actions. See pypi guard for narrative.
    report.checks.append(
        check_sha_pinning(workflow, raw_text, NPM_WORKFLOW_RELPATH)
    )
    return report


def _print_human(report: GuardReport) -> None:
    print(f"workflow:      {report.workflow_path}")
    print(f"pypi workflow: {report.pypi_workflow_path}")
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
        description="Static guard for the npm provenance release workflow.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root containing .github/workflows/release-npm.yml "
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
    if not (repo_root / NPM_WORKFLOW_RELPATH).is_file():
        print(
            f"FAIL: workflow file not found at {repo_root / NPM_WORKFLOW_RELPATH}",
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
