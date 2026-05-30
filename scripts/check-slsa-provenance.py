#!/usr/bin/env python3
"""W12.3 SLSA L3 provenance guard (workflow lint + offline attestation verifier).

Two modes of operation, selected via ``--mode``:

  ``--mode workflow``
      Static linter that parses ``.github/workflows/release-pypi.yml``
      and ``.github/workflows/release-npm.yml`` and asserts the SLSA
      L3 build chain is wired correctly:

        - VAL-W12-011  every released artifact has a provenance attestation
        - VAL-W12-012  build uses slsa-github-generator reusable workflow
                      (pinned by SHA, NOT by tag)
        - VAL-W12-014  publish jobs ``needs:`` their provenance job
                      (failure to attest blocks publish)
        - VAL-W12-044  publish jobs include a fork-detection step that
                      sets ``dry_run_unsigned: true`` and exits cleanly
                      when the trusted-publisher OIDC binding is absent
                      (i.e., the workflow runs in a fork)

  ``--mode attestation``
      Offline verifier that loads a single ``.intoto.jsonl`` envelope
      (DSSE-shaped; payload base64-encoded), parses the embedded SLSA
      v1.0 in-toto Statement, and asserts:

        - VAL-W12-013  predicateType == https://slsa.dev/provenance/v1
                      AND builder.id is a slsa-framework/slsa-github-generator
                      reusable workflow URI
                      AND subject digest matches the supplied --expected-sha256
                      (offline; no network I/O whatsoever)
        - VAL-W12-015  buildDefinition has buildType, externalParameters,
                      internalParameters, and resolvedDependencies (with a
                      gitCommit dependency for the source-commit SHA)

Per CLAUDE.md "ASCII-Safe Source": ASCII-only output and source.
Per CLAUDE.md keystone #3: this script lives in ``scripts/`` and is
invoked through manifest-declared commands (``lint-slsa-provenance``
or via the release workflows themselves).

Exit codes:
    0  all checks passed
    1  one or more checks failed (RELAY-RELEASE-NNN reported in JSON)
    2  input file missing or unparseable
    3  invalid invocation
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants pinned to the contract.
# ---------------------------------------------------------------------------

PYPI_WORKFLOW_RELPATH = ".github/workflows/release-pypi.yml"
NPM_WORKFLOW_RELPATH = ".github/workflows/release-npm.yml"

# slsa-github-generator reusable workflow path prefix.  VAL-W12-012
# requires this exact org/repo prefix; any other ``uses:`` value for a
# provenance job FAILS.
SLSA_GENERATOR_PATH_PREFIX = (
    "slsa-framework/slsa-github-generator/.github/workflows/"
)
# VAL-W12-013 requires the attestation's builder.id to be under this
# org/repo prefix (the offline-verifiable identity).
SLSA_GENERATOR_BUILDER_ID_PREFIX = (
    "https://github.com/slsa-framework/slsa-github-generator"
)
# SLSA v1.0 predicate type.  v0.2 and earlier are explicitly rejected
# (VAL-W12-013).
SLSA_PREDICATE_TYPE_V1 = "https://slsa.dev/provenance/v1"

# A 40-character lowercase hex string is the canonical Git SHA pin
# format.  VAL-W12-012 forbids tag-form pins (@v1, @v2.0.0, @main).
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
# A bare git commit SHA in resolvedDependencies digest{} block.
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# The fork-detection sentinel that publish jobs MUST carry to satisfy
# VAL-W12-044.  Any of these tokens in step id or step name signals the
# dry-run-unsigned guard is wired (one canonical name; multiple acceptable
# spellings to allow future workflow tidying without test churn).
FORK_DETECTION_SENTINELS: tuple[str, ...] = (
    "dry-run-unsigned",
    "dry_run_unsigned",
)

# Publish-job names per workflow.  These are the jobs that perform the
# external publish (PyPI / npm registry); each must depend on a
# provenance job and must include a fork-detection step.
PYPI_PUBLISH_JOBS: tuple[str, ...] = (
    "publish-release",
    "publish-sidecar",
    "publish-cli",
)
PYPI_PROVENANCE_JOBS: tuple[str, ...] = ("provenance",)

NPM_PUBLISH_JOBS: tuple[str, ...] = ("publish-sdk", "publish-sidecar-bundle")
NPM_PROVENANCE_JOBS: tuple[str, ...] = (
    "provenance-sdk",
    "provenance-sidecar-bundle",
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
class WorkflowReport:
    """Static-linter aggregate report across the two release workflows."""

    workflow_paths: list[str] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "workflow",
            "workflow_paths": self.workflow_paths,
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


@dataclass
class AttestationReport:
    """Offline-verifier report for a single in-toto envelope."""

    attestation_path: str
    predicate_type: str | None = None
    build_type: str | None = None
    builder_id: str | None = None
    source_commit_sha: str | None = None
    subject_digest_sha256: str | None = None
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "attestation",
            "attestation_path": self.attestation_path,
            "predicate_type": self.predicate_type,
            "build_type": self.build_type,
            "builder_id": self.builder_id,
            "source_commit_sha": self.source_commit_sha,
            "subject_digest_sha256": self.subject_digest_sha256,
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


def _job(workflow: dict[str, Any], name: str) -> dict[str, Any] | None:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return None
    job = jobs.get(name)
    return job if isinstance(job, dict) else None


def _job_uses(job: dict[str, Any]) -> str | None:
    """Return the ``uses:`` value at the JOB level (reusable workflow
    invocation), or None when the job uses runs-on/steps."""
    uses = job.get("uses")
    return uses if isinstance(uses, str) else None


def _job_needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs")
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list):
        return [n for n in needs if isinstance(n, str)]
    return []


def _step_has_fork_sentinel(step: dict[str, Any]) -> bool:
    """Return True when a step's id, name, or `if:` expression contains
    one of the fork-detection sentinels (``dry-run-unsigned`` /
    ``dry_run_unsigned``)."""
    s_id = str(step.get("id") or "")
    s_name = str(step.get("name") or "")
    s_if = str(step.get("if") or "")
    haystack = f"{s_id}\n{s_name}\n{s_if}".lower()
    return any(sentinel.lower() in haystack for sentinel in FORK_DETECTION_SENTINELS)


def _job_has_fork_detection(job: dict[str, Any]) -> bool:
    """Return True when a publish job includes at least one
    fork-detection step (sets dry_run_unsigned + skips the publish on a
    fork)."""
    return any(_step_has_fork_sentinel(s) for s in _iter_steps(job))


# ---------------------------------------------------------------------------
# Workflow-mode checks.
# ---------------------------------------------------------------------------


def _provenance_jobs_for(
    workflow: dict[str, Any], expected_names: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    """Return the subset of expected provenance jobs that exist in the
    workflow.  Used by VAL-W12-011 and VAL-W12-012."""
    out: dict[str, dict[str, Any]] = {}
    for name in expected_names:
        job = _job(workflow, name)
        if job is not None:
            out[name] = job
    return out


def check_val_w12_011(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Every released artifact has a provenance attestation.

    Asserted by presence of a provenance job per artifact:
      - PyPI (sdist+wheel): one provenance job (`provenance`)
      - npm: one provenance job per package
        (`provenance-sdk`, `provenance-sidecar-bundle`)

    A missing provenance job means at least one artifact would ship
    without an attestation.
    """
    pypi_provs = _provenance_jobs_for(pypi, PYPI_PROVENANCE_JOBS)
    npm_provs = _provenance_jobs_for(npm, NPM_PROVENANCE_JOBS)
    missing: list[str] = []
    for name in PYPI_PROVENANCE_JOBS:
        if name not in pypi_provs:
            missing.append(f"release-pypi.yml:{name}")
    for name in NPM_PROVENANCE_JOBS:
        if name not in npm_provs:
            missing.append(f"release-npm.yml:{name}")
    if missing:
        return CheckResult(
            "VAL-W12-011",
            "RELAY-RELEASE-011",
            False,
            f"missing provenance job(s): {', '.join(missing)}",
        )
    return CheckResult("VAL-W12-011", "RELAY-RELEASE-011", True)


def check_val_w12_012(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Build uses slsa-github-generator reusable workflow, pinned by SHA.

    The provenance job's ``uses:`` value MUST:
      - start with the slsa-framework/slsa-github-generator path prefix
      - reference a tag of the form ``@<40-hex>`` (NOT ``@v1``,
        ``@v2.0.0``, ``@main``, or any other floating ref)
    """
    all_provs: list[tuple[str, str, dict[str, Any]]] = []
    for name in PYPI_PROVENANCE_JOBS:
        job = _job(pypi, name)
        if job is not None:
            all_provs.append(("release-pypi.yml", name, job))
    for name in NPM_PROVENANCE_JOBS:
        job = _job(npm, name)
        if job is not None:
            all_provs.append(("release-npm.yml", name, job))

    if not all_provs:
        return CheckResult(
            "VAL-W12-012",
            "RELAY-RELEASE-012",
            False,
            "no provenance jobs found in either workflow",
        )

    for workflow_label, job_name, job in all_provs:
        uses = _job_uses(job)
        if uses is None:
            return CheckResult(
                "VAL-W12-012",
                "RELAY-RELEASE-012",
                False,
                (
                    f"{workflow_label}:{job_name} has no job-level 'uses:' "
                    "(SLSA generator must be invoked as a reusable workflow)"
                ),
            )
        if not uses.startswith(SLSA_GENERATOR_PATH_PREFIX):
            return CheckResult(
                "VAL-W12-012",
                "RELAY-RELEASE-012",
                False,
                (
                    f"{workflow_label}:{job_name} uses '{uses}'; expected a "
                    f"{SLSA_GENERATOR_PATH_PREFIX}* reusable workflow"
                ),
            )
        if "@" not in uses:
            return CheckResult(
                "VAL-W12-012",
                "RELAY-RELEASE-012",
                False,
                f"{workflow_label}:{job_name} uses '{uses}' lacks any '@<ref>' pin",
            )
        ref = uses.split("@", 1)[1]
        if not _SHA40_RE.match(ref):
            return CheckResult(
                "VAL-W12-012",
                "RELAY-RELEASE-012",
                False,
                (
                    f"{workflow_label}:{job_name} pinned by tag '{ref}'; "
                    "must be pinned by 40-hex SHA"
                ),
            )

    return CheckResult("VAL-W12-012", "RELAY-RELEASE-012", True)


def check_val_w12_013_workflow_side(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Static workflow-side check that each provenance job is configured
    to emit an offline-verifiable attestation.

    The deep verification of attestation contents lives in
    ``--mode attestation`` (VAL-W12-013 also runs against the produced
    artifact at install time).  Workflow-side: the provenance job MUST
    declare ``permissions.id-token: write`` (the OIDC token exchange
    that lets Sigstore Fulcio issue a short-lived signing certificate
    bound to the workflow identity).
    """
    all_provs: list[tuple[str, str, dict[str, Any]]] = []
    for name in PYPI_PROVENANCE_JOBS:
        job = _job(pypi, name)
        if job is not None:
            all_provs.append(("release-pypi.yml", name, job))
    for name in NPM_PROVENANCE_JOBS:
        job = _job(npm, name)
        if job is not None:
            all_provs.append(("release-npm.yml", name, job))

    if not all_provs:
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            "no provenance jobs found",
        )
    for workflow_label, job_name, job in all_provs:
        perms = job.get("permissions")
        if not isinstance(perms, dict) or perms.get("id-token") != "write":
            return CheckResult(
                "VAL-W12-013",
                "RELAY-RELEASE-013",
                False,
                (
                    f"{workflow_label}:{job_name} lacks "
                    "'permissions.id-token: write' (required for keyless "
                    "Sigstore signing)"
                ),
            )
    return CheckResult("VAL-W12-013", "RELAY-RELEASE-013", True)


def check_val_w12_014(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Failure to produce SLSA attestation blocks the entire release.

    Each publish job MUST list its corresponding provenance job in
    ``needs:``, AND MUST NOT carry ``continue-on-error: true``.

    Pairing rules:
      - release-pypi.yml: publish-release  needs provenance
      - release-pypi.yml: publish-sidecar  needs provenance
      - release-pypi.yml: publish-cli      needs provenance
        (single shared provenance attestation covers all 3 PyPI publish
        jobs; base64-subjects payload binds every artifact's digest)
      - release-npm.yml: publish-sdk needs provenance-sdk;
                         publish-sidecar-bundle needs provenance-sidecar-bundle
    """
    pairings: list[tuple[str, str, str]] = [
        ("release-pypi.yml", "publish-release", "provenance"),
        ("release-pypi.yml", "publish-sidecar", "provenance"),
        ("release-pypi.yml", "publish-cli", "provenance"),
        ("release-npm.yml", "publish-sdk", "provenance-sdk"),
        (
            "release-npm.yml",
            "publish-sidecar-bundle",
            "provenance-sidecar-bundle",
        ),
    ]
    for workflow_label, publish_name, provenance_name in pairings:
        workflow = pypi if workflow_label == "release-pypi.yml" else npm
        publish = _job(workflow, publish_name)
        if publish is None:
            return CheckResult(
                "VAL-W12-014",
                "RELAY-RELEASE-014",
                False,
                f"{workflow_label}:{publish_name} job missing",
            )
        needs = _job_needs(publish)
        if provenance_name not in needs:
            return CheckResult(
                "VAL-W12-014",
                "RELAY-RELEASE-014",
                False,
                (
                    f"{workflow_label}:{publish_name} does not depend on "
                    f"'{provenance_name}' (needs={needs}); a failed "
                    "provenance step would not block publish"
                ),
            )
        if publish.get("continue-on-error") is True:
            return CheckResult(
                "VAL-W12-014",
                "RELAY-RELEASE-014",
                False,
                (
                    f"{workflow_label}:{publish_name} has "
                    "'continue-on-error: true' (would let publish proceed "
                    "after provenance failure)"
                ),
            )
        # The provenance job itself must not opt out of failure.
        provenance = _job(workflow, provenance_name)
        if provenance is not None and provenance.get("continue-on-error") is True:
            return CheckResult(
                "VAL-W12-014",
                "RELAY-RELEASE-014",
                False,
                (
                    f"{workflow_label}:{provenance_name} has "
                    "'continue-on-error: true'"
                ),
            )
    return CheckResult("VAL-W12-014", "RELAY-RELEASE-014", True)


def check_val_w12_015_workflow_side(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Static workflow-side check that the SLSA generator is invoked
    with the inputs needed to produce the four required buildDefinition
    fields (buildType, externalParameters, internalParameters,
    resolvedDependencies).

    The slsa-github-generator reusable workflows populate these fields
    automatically from the calling context when invoked via ``uses:``
    with ``base64-subjects`` (which encodes the artifact subjects that
    bind to the source commit and runtime parameters).  We assert the
    provenance job declares ``with.base64-subjects``; the deep field
    verification happens in ``--mode attestation``.
    """
    all_provs: list[tuple[str, str, dict[str, Any]]] = []
    for name in PYPI_PROVENANCE_JOBS:
        job = _job(pypi, name)
        if job is not None:
            all_provs.append(("release-pypi.yml", name, job))
    for name in NPM_PROVENANCE_JOBS:
        job = _job(npm, name)
        if job is not None:
            all_provs.append(("release-npm.yml", name, job))

    for workflow_label, job_name, job in all_provs:
        with_block = job.get("with")
        if not isinstance(with_block, dict):
            return CheckResult(
                "VAL-W12-015",
                "RELAY-RELEASE-015",
                False,
                (
                    f"{workflow_label}:{job_name} reusable invocation lacks "
                    "any 'with:' inputs"
                ),
            )
        if not with_block.get("base64-subjects"):
            return CheckResult(
                "VAL-W12-015",
                "RELAY-RELEASE-015",
                False,
                (
                    f"{workflow_label}:{job_name} does not pass "
                    "'base64-subjects' (required to bind artifacts to "
                    "buildDefinition.subject digests)"
                ),
            )
    return CheckResult("VAL-W12-015", "RELAY-RELEASE-015", True)


def check_val_w12_044(
    pypi: dict[str, Any], npm: dict[str, Any]
) -> CheckResult:
    """Release pipeline runs on free-tier-eligible infrastructure for
    OSS contributors (forks).

    Per spec section A.3 / AI.6, every publish job MUST carry a
    fork-detection step that:
      - sets ``dry_run_unsigned: true`` in workflow output
      - skips the actual publish step when the workflow runs from a fork
        (no trusted-publisher OIDC binding will resolve)
      - exits cleanly (the fork's CI is GREEN, attestation is still
        generated by the upstream provenance job)

    A workflow that errors hard on a fork because of missing publish
    credentials FAILS this assertion.

    Static check: each publish job has at least one step whose id, name,
    or ``if:`` expression contains the ``dry-run-unsigned`` /
    ``dry_run_unsigned`` sentinel.
    """
    pypi_publishes: list[tuple[str, str, dict[str, Any]]] = [
        ("release-pypi.yml", name, job)
        for name in PYPI_PUBLISH_JOBS
        if (job := _job(pypi, name)) is not None
    ]
    npm_publishes: list[tuple[str, str, dict[str, Any]]] = [
        ("release-npm.yml", name, job)
        for name in NPM_PUBLISH_JOBS
        if (job := _job(npm, name)) is not None
    ]
    all_publishes = pypi_publishes + npm_publishes
    if not all_publishes:
        return CheckResult(
            "VAL-W12-044",
            "RELAY-RELEASE-044",
            False,
            "no publish jobs found in either workflow",
        )
    for workflow_label, job_name, job in all_publishes:
        if not _job_has_fork_detection(job):
            return CheckResult(
                "VAL-W12-044",
                "RELAY-RELEASE-044",
                False,
                (
                    f"{workflow_label}:{job_name} has no fork-detection "
                    "step (expected a step with id/name/if containing "
                    f"one of {list(FORK_DETECTION_SENTINELS)} that "
                    "skips publish on forks)"
                ),
            )
    return CheckResult("VAL-W12-044", "RELAY-RELEASE-044", True)


# ---------------------------------------------------------------------------
# Workflow-mode orchestration.
# ---------------------------------------------------------------------------


def run_workflow_checks(repo_root: Path) -> WorkflowReport:
    pypi_path = repo_root / PYPI_WORKFLOW_RELPATH
    npm_path = repo_root / NPM_WORKFLOW_RELPATH

    pypi = _load_workflow_yaml(pypi_path)
    npm = _load_workflow_yaml(npm_path)

    report = WorkflowReport(
        workflow_paths=[
            str(pypi_path.relative_to(repo_root)),
            str(npm_path.relative_to(repo_root)),
        ]
    )
    report.checks.append(check_val_w12_011(pypi, npm))
    report.checks.append(check_val_w12_012(pypi, npm))
    report.checks.append(check_val_w12_013_workflow_side(pypi, npm))
    report.checks.append(check_val_w12_014(pypi, npm))
    report.checks.append(check_val_w12_015_workflow_side(pypi, npm))
    report.checks.append(check_val_w12_044(pypi, npm))
    return report


# ---------------------------------------------------------------------------
# Attestation-mode (offline verifier).
# ---------------------------------------------------------------------------


def _load_envelope(att_path: Path) -> dict[str, Any]:
    """Load and parse a single .intoto.jsonl envelope file.

    The .intoto.jsonl format is one DSSE envelope per line.  We accept
    a file containing exactly one envelope (the slsa-github-generator
    output).  Multi-envelope files are out of scope for v0.1.
    """
    try:
        text = att_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"FAIL: attestation file not found at {att_path}", file=sys.stderr)
        raise SystemExit(2) from None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        print(f"FAIL: attestation file empty: {att_path}", file=sys.stderr)
        raise SystemExit(2)
    if len(lines) > 1:
        print(
            f"FAIL: attestation file contains {len(lines)} envelopes; "
            "expected exactly 1",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        envelope = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        print(f"FAIL: attestation envelope not JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(envelope, dict):
        print("FAIL: attestation envelope must be a JSON object", file=sys.stderr)
        raise SystemExit(2)
    return envelope


def _decode_statement(envelope: dict[str, Any]) -> dict[str, Any]:
    """Extract and base64-decode the in-toto Statement payload."""
    payload_b64 = envelope.get("payload")
    if not isinstance(payload_b64, str):
        print("FAIL: envelope.payload missing or not a string", file=sys.stderr)
        raise SystemExit(2)
    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        print(f"FAIL: envelope.payload not valid base64: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    try:
        statement = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"FAIL: payload not JSON UTF-8: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(statement, dict):
        print("FAIL: payload must be a JSON object", file=sys.stderr)
        raise SystemExit(2)
    return statement


def check_attestation_val_w12_013(
    statement: dict[str, Any],
    expected_sha256: str | None,
    expected_source_repo: str | None,
) -> CheckResult:
    """Predicate type, builder identity, and subject digest verification.

    Offline-only: this function makes no network I/O.  The SLSA
    verifier's trust anchor for the builder identity is the literal
    URI prefix ``https://github.com/slsa-framework/slsa-github-generator``;
    a builder.id outside that prefix means the attestation was issued
    by an unrelated builder and MUST NOT be trusted.
    """
    predicate_type = statement.get("predicateType")
    if predicate_type != SLSA_PREDICATE_TYPE_V1:
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            (
                f"predicateType is '{predicate_type}'; "
                f"expected '{SLSA_PREDICATE_TYPE_V1}'"
            ),
        )
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            "predicate is missing or not an object",
        )
    run_details = predicate.get("runDetails")
    if not isinstance(run_details, dict):
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            "predicate.runDetails missing",
        )
    builder = run_details.get("builder")
    if not isinstance(builder, dict):
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            "predicate.runDetails.builder missing",
        )
    builder_id = builder.get("id")
    if not isinstance(builder_id, str) or not builder_id.startswith(
        SLSA_GENERATOR_BUILDER_ID_PREFIX
    ):
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            (
                f"builder.id is '{builder_id}'; expected prefix "
                f"'{SLSA_GENERATOR_BUILDER_ID_PREFIX}'"
            ),
        )

    # Subject digest check (binds artifact bytes to the attestation).
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        return CheckResult(
            "VAL-W12-013",
            "RELAY-RELEASE-013",
            False,
            "subject[] missing or empty",
        )
    if expected_sha256 is not None:
        digests = [
            s.get("digest", {}).get("sha256")
            for s in subjects
            if isinstance(s, dict)
        ]
        if expected_sha256 not in digests:
            return CheckResult(
                "VAL-W12-013",
                "RELAY-RELEASE-013",
                False,
                (
                    f"subject digest sha256 mismatch: expected "
                    f"'{expected_sha256}', got {digests}"
                ),
            )

    # Optional: assert the source repo claim in externalParameters.
    if expected_source_repo is not None:
        bd = predicate.get("buildDefinition", {})
        ext = bd.get("externalParameters", {}) if isinstance(bd, dict) else {}
        wf = ext.get("workflow", {}) if isinstance(ext, dict) else {}
        repo_uri = wf.get("repository") if isinstance(wf, dict) else None
        if not (isinstance(repo_uri, str) and expected_source_repo in repo_uri):
            return CheckResult(
                "VAL-W12-013",
                "RELAY-RELEASE-013",
                False,
                (
                    f"externalParameters.workflow.repository '{repo_uri}' "
                    f"does not contain expected source repo "
                    f"'{expected_source_repo}'"
                ),
            )

    return CheckResult("VAL-W12-013", "RELAY-RELEASE-013", True)


def check_attestation_val_w12_015(
    statement: dict[str, Any],
) -> CheckResult:
    """Four required buildDefinition fields.

    Per VAL-W12-015 evidence: ``jq '.predicate.buildDefinition' returns
    object with all four fields populated``.  The four fields are:

      1. buildType
      2. externalParameters (release tag, workflow repo, workflow path)
      3. internalParameters (build-time configuration)
      4. resolvedDependencies (with at least one entry whose digest
         carries a gitCommit -- the source-commit SHA being built)
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            "predicate missing",
        )
    bd = predicate.get("buildDefinition")
    if not isinstance(bd, dict):
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            "predicate.buildDefinition missing",
        )
    missing_fields: list[str] = []
    for field_name in (
        "buildType",
        "externalParameters",
        "internalParameters",
        "resolvedDependencies",
    ):
        if field_name not in bd:
            missing_fields.append(field_name)
    if missing_fields:
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            (
                "predicate.buildDefinition missing required field(s): "
                f"{', '.join(missing_fields)}"
            ),
        )
    # buildType must be a non-empty string.
    if not (isinstance(bd["buildType"], str) and bd["buildType"]):
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            "predicate.buildDefinition.buildType is empty or non-string",
        )
    # externalParameters and internalParameters must be objects (per
    # SLSA v1.0 schema, they are arbitrary JSON objects).
    for field_name in ("externalParameters", "internalParameters"):
        if not isinstance(bd[field_name], dict):
            return CheckResult(
                "VAL-W12-015",
                "RELAY-RELEASE-015",
                False,
                (
                    f"predicate.buildDefinition.{field_name} is not an "
                    "object"
                ),
            )
    # resolvedDependencies must contain at least one entry with a
    # gitCommit digest (the source-commit SHA the build consumed).
    rd = bd["resolvedDependencies"]
    if not isinstance(rd, list) or not rd:
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            "predicate.buildDefinition.resolvedDependencies must be a "
            "non-empty array",
        )
    found_commit = False
    for dep in rd:
        if not isinstance(dep, dict):
            continue
        digest = dep.get("digest")
        if not isinstance(digest, dict):
            continue
        sha = digest.get("gitCommit")
        if isinstance(sha, str) and _GIT_COMMIT_RE.match(sha):
            found_commit = True
            break
    if not found_commit:
        return CheckResult(
            "VAL-W12-015",
            "RELAY-RELEASE-015",
            False,
            "predicate.buildDefinition.resolvedDependencies has no "
            "gitCommit digest (40-hex)",
        )
    return CheckResult("VAL-W12-015", "RELAY-RELEASE-015", True)


def _extract_source_commit(statement: dict[str, Any]) -> str | None:
    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        return None
    bd = predicate.get("buildDefinition", {})
    if not isinstance(bd, dict):
        return None
    rd = bd.get("resolvedDependencies", [])
    if not isinstance(rd, list):
        return None
    for dep in rd:
        if not isinstance(dep, dict):
            continue
        digest = dep.get("digest", {})
        if not isinstance(digest, dict):
            continue
        sha = digest.get("gitCommit")
        if isinstance(sha, str) and _GIT_COMMIT_RE.match(sha):
            return sha
    return None


def _extract_builder_id(statement: dict[str, Any]) -> str | None:
    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        return None
    rd = predicate.get("runDetails", {})
    if not isinstance(rd, dict):
        return None
    builder = rd.get("builder", {})
    if not isinstance(builder, dict):
        return None
    bid = builder.get("id")
    return bid if isinstance(bid, str) else None


def _extract_subject_sha256(statement: dict[str, Any]) -> str | None:
    subjects = statement.get("subject", [])
    if not isinstance(subjects, list) or not subjects:
        return None
    first = subjects[0]
    if not isinstance(first, dict):
        return None
    digest = first.get("digest", {})
    if not isinstance(digest, dict):
        return None
    sha = digest.get("sha256")
    return sha if isinstance(sha, str) else None


def run_attestation_checks(
    att_path: Path,
    expected_sha256: str | None,
    expected_source_repo: str | None,
) -> AttestationReport:
    envelope = _load_envelope(att_path)
    statement = _decode_statement(envelope)

    predicate_type = statement.get("predicateType")
    bd = (
        statement.get("predicate", {}).get("buildDefinition", {})
        if isinstance(statement.get("predicate"), dict)
        else {}
    )
    build_type = bd.get("buildType") if isinstance(bd, dict) else None

    report = AttestationReport(
        attestation_path=str(att_path),
        predicate_type=predicate_type if isinstance(predicate_type, str) else None,
        build_type=build_type if isinstance(build_type, str) else None,
        builder_id=_extract_builder_id(statement),
        source_commit_sha=_extract_source_commit(statement),
        subject_digest_sha256=_extract_subject_sha256(statement),
    )
    report.checks.append(
        check_attestation_val_w12_013(
            statement, expected_sha256, expected_source_repo
        )
    )
    report.checks.append(check_attestation_val_w12_015(statement))
    return report


# ---------------------------------------------------------------------------
# Output helpers.
# ---------------------------------------------------------------------------


def _print_workflow_human(report: WorkflowReport) -> None:
    print("workflows:")
    for p in report.workflow_paths:
        print(f"  - {p}")
    print("")
    for c in report.checks:
        marker = "[OK]  " if c.passed else "[FAIL]"
        line = f"{marker} {c.assertion}  {c.error_code}"
        if not c.passed and c.message:
            line += f"  -- {c.message}"
        print(line)
    print("")
    print("PASS" if report.ok else "FAIL")


def _print_attestation_human(report: AttestationReport) -> None:
    print(f"attestation: {report.attestation_path}")
    print(f"  predicate_type: {report.predicate_type}")
    print(f"  build_type:     {report.build_type}")
    print(f"  builder_id:     {report.builder_id}")
    print(f"  source_commit:  {report.source_commit_sha}")
    print(f"  subject_sha256: {report.subject_digest_sha256}")
    print("")
    for c in report.checks:
        marker = "[OK]  " if c.passed else "[FAIL]"
        line = f"{marker} {c.assertion}  {c.error_code}"
        if not c.passed and c.message:
            line += f"  -- {c.message}"
        print(line)
    print("")
    print("PASS" if report.ok else "FAIL")


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "SLSA L3 provenance guard: workflow lint AND offline "
            "attestation verifier."
        )
    )
    parser.add_argument(
        "--mode",
        choices=("workflow", "attestation"),
        required=True,
        help="Select 'workflow' (static lint) or 'attestation' (offline verify).",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root containing .github/workflows/ (workflow mode).",
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        default=None,
        help="Path to a .intoto.jsonl SLSA provenance envelope (attestation mode).",
    )
    parser.add_argument(
        "--expected-sha256",
        type=str,
        default=None,
        help=(
            "Expected sha256 digest of the artifact bound to the attestation "
            "subject (attestation mode)."
        ),
    )
    parser.add_argument(
        "--expected-source-repo",
        type=str,
        default=None,
        help=(
            "Expected substring of externalParameters.workflow.repository "
            "(e.g., 'epochly-inc/relay'); attestation mode."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )
    args = parser.parse_args(argv)

    if args.mode == "workflow":
        repo_root = (args.repo_root or Path.cwd()).resolve()
        if not (repo_root / PYPI_WORKFLOW_RELPATH).is_file():
            print(
                f"FAIL: workflow file not found at "
                f"{repo_root / PYPI_WORKFLOW_RELPATH}",
                file=sys.stderr,
            )
            return 2
        if not (repo_root / NPM_WORKFLOW_RELPATH).is_file():
            print(
                f"FAIL: workflow file not found at "
                f"{repo_root / NPM_WORKFLOW_RELPATH}",
                file=sys.stderr,
            )
            return 2
        report = run_workflow_checks(repo_root)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_workflow_human(report)
        return 0 if report.ok else 1

    # attestation mode
    if args.attestation is None:
        print(
            "FAIL: --attestation PATH is required in attestation mode",
            file=sys.stderr,
        )
        return 3
    att_path = args.attestation.resolve()
    if not att_path.is_file():
        print(f"FAIL: attestation file not found at {att_path}", file=sys.stderr)
        return 2
    report = run_attestation_checks(
        att_path, args.expected_sha256, args.expected_source_repo
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_attestation_human(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
