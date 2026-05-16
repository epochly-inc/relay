"""W12.1 static guard tests for the PyPI trusted-publishing workflow.

Plumbing-tier tests that (a) invoke ``scripts/check-pypi-publish-workflow.py``
against the real committed workflow file at ``.github/workflows/release-pypi.yml``
and assert it passes, and (b) construct minimal-mutated copies of the
workflow under ``tmp_path`` that violate each assertion and assert the
guard rejects them with the canonical ``RELAY-RELEASE-NNN`` code.

Per CLAUDE.md TDD discipline: each test binds to its contract assertion
via ``@pytest.mark.fulfills("VAL-W12-NNN")`` so the gate engine can
trace test-to-assertion coverage.

These tests run offline; no network access required.
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
GUARD_SCRIPT: Path = REPO_ROOT / "scripts" / "check-pypi-publish-workflow.py"
REAL_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "release-pypi.yml"
REAL_RUNBOOK: Path = REPO_ROOT / "docs" / "release" / "runbook.md"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _run_guard(repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the guard script against ``repo_root`` and return the
    completed process (stdout/stderr captured, --json forced)."""
    return subprocess.run(  # noqa: S603 - command literal
        [sys.executable, str(GUARD_SCRIPT), "--repo-root", str(repo_root), "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _materialize_repo(
    tmp_path: Path,
    workflow_text: str,
    runbook_text: str | None = None,
    announcements_dir: bool = True,
) -> Path:
    """Build a minimal repo-shaped tree under ``tmp_path`` containing the
    workflow, runbook, and (optionally) announcements directory the guard
    expects to find."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "workflows" / "release-pypi.yml").write_text(
        workflow_text, encoding="utf-8"
    )
    if runbook_text is not None:
        (tmp_path / "docs" / "release").mkdir(parents=True, exist_ok=True)
        (tmp_path / "docs" / "release" / "runbook.md").write_text(
            runbook_text, encoding="utf-8"
        )
    if announcements_dir:
        (tmp_path / "docs" / "release" / "announcements").mkdir(
            parents=True, exist_ok=True
        )
    return tmp_path


def _real_workflow_text() -> str:
    return REAL_WORKFLOW.read_text(encoding="utf-8")


def _real_runbook_text() -> str:
    return REAL_RUNBOOK.read_text(encoding="utf-8")


def _mutate_workflow(transform) -> str:
    """Parse the real workflow, apply ``transform(dict)``, dump back to YAML."""
    data: dict[str, Any] = yaml.safe_load(_real_workflow_text())
    transform(data)
    return yaml.safe_dump(data, sort_keys=False)


def _parse_report(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse the guard's JSON output; raise AssertionError if malformed."""
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - test diagnostic
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
@pytest.mark.fulfills("VAL-W12-001")
@pytest.mark.fulfills("VAL-W12-002")
@pytest.mark.fulfills("VAL-W12-003")
@pytest.mark.fulfills("VAL-W12-004")
@pytest.mark.fulfills("VAL-W12-005")
@pytest.mark.fulfills("VAL-W12-006")
@pytest.mark.fulfills("VAL-W12-038")
@pytest.mark.fulfills("VAL-W12-039")
@pytest.mark.fulfills("VAL-W12-040")
@pytest.mark.fulfills("VAL-W12-046")
def test_real_release_workflow_passes_every_w12_1_assertion() -> None:
    """The committed release-pypi.yml + runbook satisfy every w12.1 check."""
    proc = _run_guard(REPO_ROOT)
    report = _parse_report(proc)
    failing = [c for c in report["checks"] if not c["passed"]]
    assert proc.returncode == 0, (
        f"guard rejected the real workflow: {failing} "
        f"(stderr={proc.stderr!r})"
    )
    # Defense in depth: ensure every expected assertion id was actually checked.
    expected_assertions = {
        "VAL-W12-001",
        "VAL-W12-002",
        "VAL-W12-003",
        "VAL-W12-004",
        "VAL-W12-005",
        "VAL-W12-006",
        "VAL-W12-038",
        "VAL-W12-039",
        "VAL-W12-040",
        "VAL-W12-046",
    }
    actual_assertions = {c["assertion"] for c in report["checks"]}
    assert expected_assertions <= actual_assertions, (
        f"guard skipped assertions: {expected_assertions - actual_assertions}"
    )


@pytest.mark.plumbing
def test_guard_emits_canonical_error_codes_for_every_assertion() -> None:
    """Every check entry includes the canonical RELAY-RELEASE-NNN code."""
    proc = _run_guard(REPO_ROOT)
    report = _parse_report(proc)
    expected_pairs = {
        "VAL-W12-001": "RELAY-RELEASE-001",
        "VAL-W12-002": "RELAY-RELEASE-002",
        "VAL-W12-003": "RELAY-RELEASE-003",
        "VAL-W12-004": "RELAY-RELEASE-004",
        "VAL-W12-005": "RELAY-RELEASE-005",
        "VAL-W12-006": "RELAY-RELEASE-006",
        "VAL-W12-038": "RELAY-RELEASE-038",
        "VAL-W12-039": "RELAY-RELEASE-039",
        "VAL-W12-040": "RELAY-RELEASE-040",
        "VAL-W12-046": "RELAY-RELEASE-046",
    }
    for check in report["checks"]:
        expected = expected_pairs.get(check["assertion"])
        if expected is not None:
            assert check["error_code"] == expected, (
                f"{check['assertion']} reports {check['error_code']}, "
                f"expected {expected}"
            )


# ---------------------------------------------------------------------------
# Negative tests: mutated workflows MUST be rejected with the canonical code.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-001")
def test_guard_rejects_long_lived_pypi_token_reference(tmp_path: Path) -> None:
    """A workflow referencing ``secrets.PYPI_TOKEN`` FAILS RELAY-RELEASE-001."""

    def transform(data: dict[str, Any]) -> None:
        # Inject a step that references the banned secret.
        data["jobs"]["publish"]["steps"].append(
            {
                "name": "Bad: legacy token reference",
                "run": 'echo "${{ secrets.PYPI_TOKEN }}"',
            }
        )

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-001")
    assert not check["passed"], "guard failed to reject PYPI_TOKEN reference"
    assert check["error_code"] == "RELAY-RELEASE-001"
    assert proc.returncode == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-001")
def test_guard_rejects_missing_id_token_write_permission(tmp_path: Path) -> None:
    """A publish job missing ``permissions.id-token: write`` FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish"]["permissions"] = {"contents": "read"}

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-001")
    assert not check["passed"], "guard failed to reject missing id-token: write"
    assert check["error_code"] == "RELAY-RELEASE-001"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-002")
def test_guard_rejects_missing_release_environment(tmp_path: Path) -> None:
    """A publish job not bound to environment ``release`` FAILS RELAY-RELEASE-002."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish"]["environment"] = {"name": "preview"}

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-002")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-002"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-002")
def test_guard_rejects_runbook_without_binding_phrases(tmp_path: Path) -> None:
    """A runbook that omits the trusted-publisher binding triple FAILS."""
    bad_runbook = (
        "# Stub runbook\n\nMissing the binding triple entirely.\n"
        "## No Destructive Rollback\nPlaceholder.\n"
    )
    repo = _materialize_repo(tmp_path, _real_workflow_text(), bad_runbook)
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-002")
    assert not check["passed"]
    assert "binding phrase" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-003")
def test_guard_rejects_runbook_without_required_reviewers_clause(
    tmp_path: Path,
) -> None:
    """A runbook that omits the ``required_reviewers`` clause FAILS RELAY-RELEASE-003."""
    bad_runbook = _real_runbook_text().replace(
        "required_reviewers", "AUTOMATIC_REVIEW"
    )
    repo = _materialize_repo(tmp_path, _real_workflow_text(), bad_runbook)
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-003")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-003"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-004")
def test_guard_rejects_workflow_without_slsa_generator(tmp_path: Path) -> None:
    """A workflow without the SLSA generator reference FAILS RELAY-RELEASE-004."""

    def transform(data: dict[str, Any]) -> None:
        # Strip the entire provenance job; replace with a no-op.
        del data["jobs"]["provenance"]
        data["jobs"]["publish"]["needs"] = ["build"]

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-004")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-004"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-004")
def test_guard_rejects_workflow_without_hashes_output(tmp_path: Path) -> None:
    """A build job not declaring ``outputs.hashes`` FAILS RELAY-RELEASE-004."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["build"]["outputs"] = {"placeholder": "value"}

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-004")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-004"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-005")
def test_guard_rejects_publish_step_without_attestations(tmp_path: Path) -> None:
    """A publish step lacking ``attestations: true`` FAILS RELAY-RELEASE-005."""

    def transform(data: dict[str, Any]) -> None:
        for step in data["jobs"]["publish"]["steps"]:
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith(
                "pypa/gh-action-pypi-publish"
            ):
                step.setdefault("with", {})
                step["with"]["attestations"] = False

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-005")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-005"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-005")
def test_guard_accepts_publish_step_with_sigstore_helper(tmp_path: Path) -> None:
    """An additional ``sigstore/gh-action-sigstore-python`` step satisfies VAL-W12-005.

    Acceptable form B per the assertion: even if ``attestations: false``
    (hypothetically), an explicit Sigstore signing step counts.
    """

    def transform(data: dict[str, Any]) -> None:
        for step in data["jobs"]["publish"]["steps"]:
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith(
                "pypa/gh-action-pypi-publish"
            ):
                step.setdefault("with", {})
                step["with"]["attestations"] = False
        # Insert the Sigstore step before publish.
        data["jobs"]["publish"]["steps"].insert(
            0,
            {
                "name": "Sigstore sign",
                "uses": "sigstore/gh-action-sigstore-python@v3.0.0",
                "with": {"inputs": "dist/*"},
            },
        )

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-005")
    assert check["passed"], (
        "guard rejected workflow with explicit sigstore-python step; "
        f"message={check['message']!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-006")
def test_guard_rejects_publish_step_without_skip_existing(tmp_path: Path) -> None:
    """A publish step without ``skip-existing: true`` FAILS RELAY-RELEASE-006."""

    def transform(data: dict[str, Any]) -> None:
        for step in data["jobs"]["publish"]["steps"]:
            uses = step.get("uses", "")
            if isinstance(uses, str) and uses.startswith(
                "pypa/gh-action-pypi-publish"
            ):
                step.setdefault("with", {})
                step["with"].pop("skip-existing", None)
                step["with"]["skip-existing"] = False

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-006")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-006"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-038")
def test_guard_rejects_long_lived_credential_anywhere(tmp_path: Path) -> None:
    """A workflow referencing ``secrets.TWINE_PASSWORD`` in ANY job FAILS RELAY-RELEASE-038."""

    def transform(data: dict[str, Any]) -> None:
        # Inject the token in the precheck job, far from the publish step.
        data["jobs"]["precheck"]["steps"].append(
            {
                "name": "Bad: leak twine password",
                "run": 'echo "${{ secrets.TWINE_PASSWORD }}"',
            }
        )

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-038")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-038"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-039")
def test_guard_rejects_workflow_with_destructive_op_in_code(tmp_path: Path) -> None:
    """A workflow that runs ``gh release delete`` in code (not comments) FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish"]["steps"].append(
            {
                "name": "Bad: delete prior release",
                "run": "gh release delete v0.0.1 --yes",
            }
        )

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-039")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-039"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-039")
def test_guard_ignores_destructive_op_inside_comments(tmp_path: Path) -> None:
    """Mention of ``gh release delete`` inside a YAML comment must NOT trip the guard."""
    annotated = _real_workflow_text() + (
        "\n# We never invoke 'gh release delete' or 'npm unpublish' from this workflow.\n"
    )
    repo = _materialize_repo(tmp_path, annotated, _real_runbook_text())
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-039")
    assert check["passed"], (
        "guard tripped on comment-only mention of destructive op; "
        f"message={check['message']!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-039")
def test_guard_rejects_runbook_missing_no_destructive_rollback_section(
    tmp_path: Path,
) -> None:
    """A runbook lacking ``## No Destructive Rollback`` section FAILS RELAY-RELEASE-039."""
    bad_runbook = _real_runbook_text().replace(
        "## No Destructive Rollback", "## Rollback Notes"
    )
    repo = _materialize_repo(tmp_path, _real_workflow_text(), bad_runbook)
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-039")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-039"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_guard_rejects_workflow_without_semver_gate(tmp_path: Path) -> None:
    """A workflow without the SemVer monotonic gate reference FAILS RELAY-RELEASE-040."""

    def transform(data: dict[str, Any]) -> None:
        new_steps = []
        for step in data["jobs"]["precheck"]["steps"]:
            run = step.get("run", "")
            if isinstance(run, str) and "check-semver-monotonic" in run:
                continue
            new_steps.append(step)
        data["jobs"]["precheck"]["steps"] = new_steps

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-040")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-040"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_guard_rejects_workflow_without_pre_announcement_step(tmp_path: Path) -> None:
    """A workflow without the pre-announcement gate FAILS RELAY-RELEASE-046."""

    def transform(data: dict[str, Any]) -> None:
        new_steps = []
        for step in data["jobs"]["precheck"]["steps"]:
            run = step.get("run", "")
            if isinstance(run, str) and "check-pre-announcement" in run:
                continue
            new_steps.append(step)
        data["jobs"]["precheck"]["steps"] = new_steps

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(transform), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-046")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-046"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_guard_rejects_missing_announcements_directory(tmp_path: Path) -> None:
    """A repo missing ``docs/release/announcements/`` FAILS RELAY-RELEASE-046."""
    repo = _materialize_repo(
        tmp_path,
        _real_workflow_text(),
        _real_runbook_text(),
        announcements_dir=False,
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check = _check_for(report, "VAL-W12-046")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-046"


@pytest.mark.plumbing
def test_guard_exits_2_when_workflow_file_missing(tmp_path: Path) -> None:
    """An empty repo (no workflow) yields exit code 2 (cannot run)."""
    # No workflow file written; guard must refuse to run.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(GUARD_SCRIPT), "--repo-root", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 2, (
        f"expected exit 2 on missing workflow; got {proc.returncode}, "
        f"stderr={proc.stderr!r}"
    )


@pytest.mark.plumbing
def test_guard_module_unit_check_accepts_dict_environment_form(tmp_path: Path) -> None:
    """The guard treats ``environment: release`` (string) equivalently to
    ``environment: {name: release, url: ...}`` (dict)."""

    def transform(data: dict[str, Any]) -> None:
        # Force the dict form (already the real form); also test a copy
        # converted to the bare-string form succeeds.
        ...

    # Bare-string form.
    def to_string_form(data: dict[str, Any]) -> None:
        data["jobs"]["publish"]["environment"] = "release"

    repo = _materialize_repo(
        tmp_path, _mutate_workflow(to_string_form), _real_runbook_text()
    )
    proc = _run_guard(repo)
    report = _parse_report(proc)
    check_002 = _check_for(report, "VAL-W12-002")
    check_003 = _check_for(report, "VAL-W12-003")
    assert check_002["passed"], (
        f"VAL-W12-002 rejected bare-string env: {check_002['message']!r}"
    )
    assert check_003["passed"], (
        f"VAL-W12-003 rejected bare-string env: {check_003['message']!r}"
    )


@pytest.mark.plumbing
def test_guard_script_is_invocable_without_unicode_output() -> None:
    """The guard's human-mode output is ASCII-only (CLAUDE.md ASCII-Safe Source)."""
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(GUARD_SCRIPT), "--repo-root", str(REPO_ROOT)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    combined = proc.stdout + proc.stderr
    # ASCII-safe: every byte must be < 128.
    non_ascii = [c for c in combined if ord(c) > 127]
    assert not non_ascii, (
        f"guard emitted non-ASCII characters: {non_ascii[:5]!r}"
    )
