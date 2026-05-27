"""W12.2 static guard tests for the npm provenance release workflow.

Plumbing-tier tests that (a) invoke ``scripts/check-npm-publish-workflow.py``
against the real committed workflow file at ``.github/workflows/release-npm.yml``
and assert it passes, and (b) construct minimal-mutated copies of the
workflow under ``tmp_path`` that violate each assertion and assert the
guard rejects them with the canonical ``RELAY-RELEASE-NNN`` code.

Per CLAUDE.md TDD discipline: each test binds to its contract assertion
via ``@pytest.mark.fulfills("VAL-W12-NNN")`` so the gate engine can
trace test-to-assertion coverage.

These tests run offline; no network access required.

Assertions covered (w12.2-release-npm-provenance):
- VAL-W12-007: npm publish workflow invokes ``npm publish --provenance``
  with OIDC; no long-lived NPM_TOKEN.
- VAL-W12-008: tarball digest matches the provenance subject digest
  (workflow wires SHA-256 subjects into SLSA generator and uses the
  npm publish --provenance flow which binds the published tarball
  digest to the attestation subject).
- VAL-W12-009: BOTH ``@epochly/relay`` AND ``@epochly/relay-sidecar-bundle``
  packages publish with provenance.
- VAL-W12-010: npm provenance attestation references the SAME source
  commit SHA as the PyPI release workflow (same trigger surface).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# Repository root: tests/release/test_*.py -> tests/release -> tests -> repo root.
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GUARD_SCRIPT: Path = REPO_ROOT / "scripts" / "check-npm-publish-workflow.py"
REAL_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "release-npm.yml"
REAL_PYPI_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "release-pypi.yml"
REAL_RUNBOOK: Path = REPO_ROOT / "docs" / "release" / "runbook.md"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _run_guard(repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the guard script and return the completed process."""
    return subprocess.run(  # noqa: S603 - command literal
        [sys.executable, str(GUARD_SCRIPT), "--repo-root", str(repo_root), "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _materialize_repo(
    tmp_path: Path,
    npm_workflow_text: str,
    pypi_workflow_text: str | None = None,
    runbook_text: str | None = None,
) -> Path:
    """Build a minimal repo-shaped tree containing the npm release workflow,
    the pypi release workflow (for VAL-W12-010 cross-platform check), and the
    release runbook."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows" / "release-npm.yml").write_text(
        npm_workflow_text, encoding="utf-8"
    )
    if pypi_workflow_text is not None:
        (tmp_path / ".github" / "workflows" / "release-pypi.yml").write_text(
            pypi_workflow_text, encoding="utf-8"
        )
    if runbook_text is not None:
        (tmp_path / "docs" / "release").mkdir(parents=True, exist_ok=True)
        (tmp_path / "docs" / "release" / "runbook.md").write_text(
            runbook_text, encoding="utf-8"
        )
    return tmp_path


def _real_workflow_text() -> str:
    return REAL_WORKFLOW.read_text(encoding="utf-8")


def _real_pypi_workflow_text() -> str:
    return REAL_PYPI_WORKFLOW.read_text(encoding="utf-8")


def _real_runbook_text() -> str:
    return REAL_RUNBOOK.read_text(encoding="utf-8")


def _mutate_workflow(transform) -> str:
    """Parse the real npm workflow, apply transform(dict), dump back to YAML."""
    data: dict[str, Any] = yaml.safe_load(_real_workflow_text())
    transform(data)
    return yaml.safe_dump(data, sort_keys=False)


def _parse_report(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise AssertionError(
            f"guard did not emit JSON; stdout={proc.stdout!r} stderr={proc.stderr!r}"
        ) from exc


def _check_for(report: dict[str, Any], assertion_id: str) -> dict[str, Any]:
    for check in report["checks"]:
        if check["assertion"] == assertion_id:
            return check
    raise AssertionError(f"no check entry for {assertion_id} in report")


# ---------------------------------------------------------------------------
# Sanity: the real, committed surface passes every assertion.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
@pytest.mark.fulfills("VAL-W12-008")
@pytest.mark.fulfills("VAL-W12-009")
@pytest.mark.fulfills("VAL-W12-010")
def test_real_release_npm_workflow_passes_every_w12_2_assertion() -> None:
    """The committed release-npm.yml satisfies every w12.2 assertion."""
    proc = _run_guard(REPO_ROOT)
    report = _parse_report(proc)
    failing = [c for c in report["checks"] if not c["passed"]]
    assert proc.returncode == 0, (
        f"guard rejected the real npm workflow: {failing} "
        f"(stderr={proc.stderr!r})"
    )
    expected_assertions = {
        "VAL-W12-007",
        "VAL-W12-008",
        "VAL-W12-009",
        "VAL-W12-010",
    }
    actual_assertions = {c["assertion"] for c in report["checks"]}
    assert expected_assertions <= actual_assertions, (
        f"guard skipped assertions: {expected_assertions - actual_assertions}"
    )


@pytest.mark.plumbing
def test_npm_guard_emits_canonical_error_codes_for_every_assertion() -> None:
    """Every check entry includes the canonical RELAY-RELEASE-NNN code."""
    proc = _run_guard(REPO_ROOT)
    report = _parse_report(proc)
    expected_pairs = {
        "VAL-W12-007": "RELAY-RELEASE-007",
        "VAL-W12-008": "RELAY-RELEASE-008",
        "VAL-W12-009": "RELAY-RELEASE-009",
        "VAL-W12-010": "RELAY-RELEASE-010",
    }
    for check in report["checks"]:
        expected = expected_pairs.get(check["assertion"])
        if expected is not None:
            assert check["error_code"] == expected, (
                f"{check['assertion']} reports {check['error_code']}, "
                f"expected {expected}"
            )


# ---------------------------------------------------------------------------
# VAL-W12-007: npm publish --provenance via OIDC, no NPM_TOKEN.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
def test_guard_rejects_npm_token_secret_reference(tmp_path: Path) -> None:
    """A workflow referencing ``secrets.NPM_TOKEN`` FAILS RELAY-RELEASE-007."""

    def transform(data: dict[str, Any]) -> None:
        sdk_job = data["jobs"]["publish-sdk"]
        sdk_job["steps"].append(
            {
                "name": "Bad: legacy token reference",
                "run": 'echo "${{ secrets.NPM_TOKEN }}"',
            }
        )

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-007")
    assert not check["passed"], "guard failed to reject NPM_TOKEN reference"
    assert check["error_code"] == "RELAY-RELEASE-007"
    assert proc.returncode == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
def test_guard_rejects_step_env_npm_token_injection(tmp_path: Path) -> None:
    """A step-level env block injecting NPM_TOKEN / NODE_AUTH_TOKEN FAILS.

    The publish step is the most common spot for an accidental token
    injection (copy-paste from npm tutorials). The guard MUST reject
    a NODE_AUTH_TOKEN env reference on a publish step with
    RELAY-RELEASE-007, in addition to its raw-text and job-env scans.
    """

    def transform(data: dict[str, Any]) -> None:
        publish_sdk = data["jobs"]["publish-sdk"]
        for step in publish_sdk["steps"]:
            run = step.get("run", "")
            if isinstance(run, str) and "npm publish" in run:
                step["env"] = {"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-007")
    assert not check["passed"], (
        "guard must reject NODE_AUTH_TOKEN step env injection"
    )
    assert check["error_code"] == "RELAY-RELEASE-007"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
def test_guard_rejects_publish_without_provenance_flag(tmp_path: Path) -> None:
    """A publish job that omits ``--provenance`` FAILS RELAY-RELEASE-007."""

    def transform(data: dict[str, Any]) -> None:
        for step in data["jobs"]["publish-sdk"]["steps"]:
            run = step.get("run", "")
            if isinstance(run, str) and "npm publish" in run:
                step["run"] = run.replace("--provenance", "")

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-007")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-007"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
def test_guard_rejects_publish_job_missing_id_token_write(tmp_path: Path) -> None:
    """A publish job missing ``permissions.id-token: write`` FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish-sdk"]["permissions"] = {"contents": "read"}

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-007")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-007"


# ---------------------------------------------------------------------------
# VAL-W12-008: tarball digest matches provenance subject digest.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-008")
def test_guard_rejects_workflow_without_hashes_output(tmp_path: Path) -> None:
    """A workflow without a job declaring ``outputs.hashes`` FAILS RELAY-RELEASE-008.

    npm publish --provenance auto-binds the published tarball digest to
    the provenance subject; for VAL-W12-008 we additionally require the
    workflow to wire its own SHA-256 subjects into the SLSA generator
    so the same artifact-digest chain is checkable by ``slsa-verifier``.
    """

    def transform(data: dict[str, Any]) -> None:
        for job_name in ("build-sdk", "build-sidecar-bundle"):
            job = data["jobs"].get(job_name, {})
            if "outputs" in job:
                job["outputs"] = {"placeholder": "value"}

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-008")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-008"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-008")
def test_guard_rejects_workflow_without_provenance_verifier_command(
    tmp_path: Path,
) -> None:
    """A workflow that does not run ``npm audit signatures`` post-publish
    FAILS RELAY-RELEASE-008.

    ``npm audit signatures`` is the canonical post-publish verifier: it
    fetches the published tarball, recomputes its SHA-512, and verifies
    the digest equals the attestation subject digest.
    """

    def transform(data: dict[str, Any]) -> None:
        for job_name, job in list(data["jobs"].items()):
            if not job_name.startswith("publish"):
                continue
            steps = job.get("steps", [])
            job["steps"] = [
                s
                for s in steps
                if not (
                    isinstance(s.get("run", ""), str)
                    and "npm audit signatures" in s.get("run", "")
                )
            ]

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-008")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-008"


# ---------------------------------------------------------------------------
# VAL-W12-009: BOTH packages publish with --provenance.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-009")
def test_guard_rejects_workflow_missing_sidecar_bundle_publish_job(
    tmp_path: Path,
) -> None:
    """A workflow without a publish-sidecar-bundle job FAILS RELAY-RELEASE-009."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"].pop("publish-sidecar-bundle", None)
        data["jobs"].pop("build-sidecar-bundle", None)

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-009")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-009"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-009")
def test_guard_rejects_workflow_missing_thin_sdk_publish_job(tmp_path: Path) -> None:
    """A workflow without a publish-sdk job FAILS RELAY-RELEASE-009."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"].pop("publish-sdk", None)
        data["jobs"].pop("build-sdk", None)

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-009")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-009"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-009")
def test_guard_rejects_sidecar_bundle_publish_without_provenance(
    tmp_path: Path,
) -> None:
    """The sidecar-bundle publish job lacking ``--provenance`` FAILS."""

    def transform(data: dict[str, Any]) -> None:
        for step in data["jobs"]["publish-sidecar-bundle"]["steps"]:
            run = step.get("run", "")
            if isinstance(run, str) and "npm publish" in run:
                step["run"] = run.replace("--provenance", "")

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-009")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-009"


# ---------------------------------------------------------------------------
# VAL-W12-010: npm provenance + PyPI provenance share the same git commit.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-010")
def test_guard_rejects_npm_workflow_with_different_tag_trigger(
    tmp_path: Path,
) -> None:
    """A workflow whose tag-trigger pattern differs from release-pypi.yml's
    pattern FAILS RELAY-RELEASE-010.

    Both workflows must fire on the SAME tag (same surface, same commit)
    so the provenance attestations bind to the same source git SHA.
    """

    def transform(data: dict[str, Any]) -> None:
        data["on"] = {"push": {"tags": ["npm-v[0-9]+.[0-9]+.[0-9]+*"]}}

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-010")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-010"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-010")
def test_guard_rejects_npm_workflow_missing_cross_platform_consistency_step(
    tmp_path: Path,
) -> None:
    """The workflow must include an explicit cross-platform consistency
    step asserting the npm release commit matches the pypi release commit.
    Removing the canonical sentinel ``check-npm-pypi-commit-consistency``
    invocation FAILS RELAY-RELEASE-010.
    """

    def transform(data: dict[str, Any]) -> None:
        for _job_name, job in data["jobs"].items():
            steps = job.get("steps", [])
            job["steps"] = [
                s
                for s in steps
                if not (
                    isinstance(s.get("run", ""), str)
                    and (
                        "check-npm-pypi-commit-consistency" in s.get("run", "")
                        or "RELAY-RELEASE-010" in s.get("run", "")
                    )
                )
            ]

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-010")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-010"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-010")
def test_guard_rejects_workflow_when_pypi_workflow_missing(tmp_path: Path) -> None:
    """The cross-platform binding cannot be verified when release-pypi.yml
    does not exist in the repo. The guard FAILS RELAY-RELEASE-010 with a
    structured message."""
    repo = _materialize_repo(
        tmp_path,
        _real_workflow_text(),
        pypi_workflow_text=None,
        runbook_text=_real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-010")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-010"


# ---------------------------------------------------------------------------
# Defense in depth: workflow surface invariants.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-007")
def test_real_workflow_uses_setup_node_with_registry_url() -> None:
    """Sanity: the real workflow configures actions/setup-node with the
    npm registry URL so that the OIDC token can be exchanged correctly."""
    data: dict[str, Any] = yaml.safe_load(_real_workflow_text())
    saw_registry_url = False
    for _name, job in data.get("jobs", {}).items():
        for step in job.get("steps", []) or []:
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if isinstance(uses, str) and uses.startswith("actions/setup-node"):
                with_block = step.get("with", {}) or {}
                if "registry-url" in with_block:
                    saw_registry_url = True
                    break
        if saw_registry_url:
            break
    assert saw_registry_url, (
        "actions/setup-node must declare registry-url so npm OIDC "
        "token exchange targets the correct registry"
    )


@pytest.mark.plumbing
def test_real_workflow_runs_on_tagged_pushes_only() -> None:
    """The npm release workflow MUST only fire on tag push (not on PR
    merge or workflow_dispatch). A non-tag trigger would publish outside
    the SemVer-monotonic gate."""
    data: dict[str, Any] = yaml.safe_load(_real_workflow_text())
    # PyYAML can parse a bare `on:` key as Python's True boolean depending
    # on flow context; tolerate both spellings.
    triggers = data.get("on")
    if triggers is None:
        triggers = data.get(True)
    assert isinstance(triggers, dict), f"unexpected 'on' shape: {triggers!r}"
    push = triggers.get("push")
    assert isinstance(push, dict), "workflow must have an 'on.push' trigger"
    tags = push.get("tags")
    assert isinstance(tags, list) and len(tags) >= 1, (
        "workflow must restrict trigger to tag pushes"
    )
    assert "pull_request" not in triggers, (
        "release workflow must not trigger on pull_request"
    )
    assert "schedule" not in triggers, (
        "release workflow must not trigger on schedule"
    )


# ---------------------------------------------------------------------------
# VAL-W12-012 SHA-pin enforcement (Bug 3 strengthening).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_real_npm_workflow_passes_sha_pinning_check() -> None:
    """Every supply-chain critical ``uses:`` ref in release-npm.yml is
    40-char SHA-pinned."""
    proc = _run_guard(REPO_ROOT)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-012")
    assert check["passed"], (
        f"VAL-W12-012 SHA-pin check rejected real npm workflow: "
        f"{check['message']!r}"
    )
    assert check["error_code"] == "RELAY-RELEASE-012"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_npm_guard_rejects_slsa_generator_tag_pin_in_sdk_job(
    tmp_path: Path,
) -> None:
    """A workflow pinning the SDK provenance SLSA generator to a tag FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance-sdk"]["uses"] = (
            "slsa-framework/slsa-github-generator/"
            ".github/workflows/generator_generic_slsa3.yml@v2.0.0"
        )

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-012")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-012"
    assert "'v2.0.0'" in check["message"]
    assert "provenance-sdk" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_npm_guard_rejects_slsa_generator_branch_pin_in_sidecar_job(
    tmp_path: Path,
) -> None:
    """A workflow pinning the sidecar-bundle provenance SLSA generator to
    a branch FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance-sidecar-bundle"]["uses"] = (
            "slsa-framework/slsa-github-generator/"
            ".github/workflows/generator_generic_slsa3.yml@main"
        )

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-012")
    assert not check["passed"]
    assert "'main'" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_npm_guard_failure_message_is_structured(tmp_path: Path) -> None:
    """Failure messages include workflow path, lineno, action ref, bad ref."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance-sdk"]["uses"] = (
            "slsa-framework/slsa-github-generator/"
            ".github/workflows/generator_generic_slsa3.yml@v2.0.0"
        )

    repo = _materialize_repo(
        tmp_path,
        _mutate_workflow(transform),
        _real_pypi_workflow_text(),
        _real_runbook_text(),
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-012")
    assert ".github/workflows/release-npm.yml" in check["message"]
    assert "must be pinned to 40-char SHA" in check["message"]


@pytest.mark.plumbing
def test_real_workflow_uses_release_environment_for_publish_jobs() -> None:
    """Both publish jobs MUST bind to the protected ``release`` environment
    so the required_reviewers gate applies (sister of VAL-W12-002/003)."""
    data: dict[str, Any] = yaml.safe_load(_real_workflow_text())
    for job_name in ("publish-sdk", "publish-sidecar-bundle"):
        job = data["jobs"][job_name]
        env = job.get("environment")
        env_name = (
            env if isinstance(env, str) else (env.get("name") if isinstance(env, dict) else None)
        )
        assert env_name == "release", (
            f"job {job_name!r} must use environment: release, got {env_name!r}"
        )
