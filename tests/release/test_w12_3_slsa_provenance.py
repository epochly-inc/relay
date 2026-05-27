"""W12.3 static + offline guard tests for SLSA L3 provenance.

Plumbing-tier tests for ``scripts/check-slsa-provenance.py``. The script
runs in two modes:

1. ``--mode workflow`` -- static linter that parses the release workflows
   under ``.github/workflows/`` and asserts the slsa-github-generator
   reusable workflow is wired into every artifact's build path, pinned
   by SHA, with publish jobs ``needs:`` the provenance job (so a failed
   provenance step blocks publish), and with a fork-detection step that
   exits cleanly under ``dry_run_unsigned`` mode (VAL-W12-044).

2. ``--mode attestation`` -- offline verifier that loads an SLSA v1.0
   provenance attestation (``.intoto.jsonl`` envelope), validates the
   ``predicateType`` URI, the ``buildDefinition.buildType`` (must be
   the slsa-github-generator reusable workflow URI), and the four
   required ``buildDefinition`` fields (source commit SHA in
   resolvedDependencies, builder workflow SHA, externalParameters,
   internalParameters); used by VAL-W12-013 / VAL-W12-015.

The 6 assertions covered:

- VAL-W12-011  every released artifact has SLSA L3 provenance attestation
- VAL-W12-012  build uses slsa-github-generator reusable workflow (SHA-pinned)
- VAL-W12-013  provenance offline-verifiable against builder identity
- VAL-W12-014  failure to produce SLSA attestation blocks the entire release
- VAL-W12-015  attestation records source-commit SHA + builder workflow
              SHA + invocation parameters
- VAL-W12-044  release pipeline runs on free-tier-eligible infrastructure
              for OSS contributors (forks)

Per CLAUDE.md TDD discipline: each test binds to its contract assertion
via ``@pytest.mark.fulfills("VAL-W12-NNN")`` so the gate engine can
trace test-to-assertion coverage. ASCII-only source per CLAUDE.md.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# Repository root: tests/release/test_*.py -> tests/release -> tests -> repo root.
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GUARD_SCRIPT: Path = REPO_ROOT / "scripts" / "check-slsa-provenance.py"
REAL_PYPI_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "release-pypi.yml"
REAL_NPM_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "release-npm.yml"

# Pinned SHA for the slsa-github-generator reusable workflow.  The
# committed release workflows reference this exact SHA today; the guard
# verifies pinning by SHA (40-hex), not by tag.
SLSA_GENERATOR_PIN_SHA = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
SLSA_GENERATOR_PATH_PREFIX = (
    "slsa-framework/slsa-github-generator/.github/workflows/"
)
SLSA_GENERATOR_BUILD_TYPE_PREFIX = (
    "https://github.com/slsa-framework/slsa-github-generator"
)
SLSA_PREDICATE_TYPE_V1 = "https://slsa.dev/provenance/v1"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _run_guard(
    *args: str,
    timeout_s: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke the guard script with arbitrary args; capture stdio."""
    return subprocess.run(  # noqa: S603 - command literal
        [sys.executable, str(GUARD_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_s,
    )


def _run_workflow_guard(repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Run the static workflow guard against ``repo_root`` with --json."""
    return _run_guard(
        "--mode", "workflow", "--repo-root", str(repo_root), "--json"
    )


def _materialize_repo(
    tmp_path: Path,
    pypi_workflow_text: str | None = None,
    npm_workflow_text: str | None = None,
) -> Path:
    """Build a minimal repo-shaped tree under ``tmp_path`` containing
    the two release workflows the guard expects."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    if pypi_workflow_text is None:
        pypi_workflow_text = REAL_PYPI_WORKFLOW.read_text(encoding="utf-8")
    if npm_workflow_text is None:
        npm_workflow_text = REAL_NPM_WORKFLOW.read_text(encoding="utf-8")
    (tmp_path / ".github" / "workflows" / "release-pypi.yml").write_text(
        pypi_workflow_text, encoding="utf-8"
    )
    (tmp_path / ".github" / "workflows" / "release-npm.yml").write_text(
        npm_workflow_text, encoding="utf-8"
    )
    return tmp_path


def _real_pypi_text() -> str:
    return REAL_PYPI_WORKFLOW.read_text(encoding="utf-8")


def _real_npm_text() -> str:
    return REAL_NPM_WORKFLOW.read_text(encoding="utf-8")


def _mutate_yaml(text: str, transform) -> str:
    data: dict[str, Any] = yaml.safe_load(text)
    transform(data)
    return yaml.safe_dump(data, sort_keys=False)


def _parse_json(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - test diagnostic
        raise AssertionError(
            f"guard did not emit JSON; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        ) from exc


def _check_for(report: dict[str, Any], assertion_id: str) -> dict[str, Any]:
    for check in report["checks"]:
        if check["assertion"] == assertion_id:
            return check
    raise AssertionError(f"no check entry for {assertion_id} in report")


def _well_formed_provenance(
    *,
    artifact_name: str = "epochly_relay-0.1.0-py3-none-any.whl",
    artifact_sha256: str = "a" * 64,
    source_commit_sha: str = "f" * 40,
    builder_workflow_sha: str = SLSA_GENERATOR_PIN_SHA,
    builder_id: str = (
        "https://github.com/slsa-framework/slsa-github-generator"
        "/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
    ),
    build_type: str = (
        "https://github.com/slsa-framework/slsa-github-generator"
        "/generic@v1"
    ),
    release_tag: str = "v0.1.0",
    omit: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build a minimal SLSA v1.0 provenance statement (in-toto Statement)
    suitable for offline-verification tests.  ``omit`` removes named
    fields from ``buildDefinition`` to exercise negative tests:

      "buildType"
      "externalParameters"
      "internalParameters"
      "resolvedDependencies"  -- removes the source-commit-SHA dep
      "builder.id"
    """
    resolved_dependencies = [
        {
            "uri": (
                f"git+https://github.com/epochly-inc/relay@refs/tags/"
                f"{release_tag}"
            ),
            "digest": {"gitCommit": source_commit_sha},
        }
    ]
    statement: dict[str, Any] = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact_name,
                "digest": {"sha256": artifact_sha256},
            }
        ],
        "predicateType": SLSA_PREDICATE_TYPE_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "workflow": {
                        "ref": f"refs/tags/{release_tag}",
                        "repository": "https://github.com/epochly-inc/relay",
                        "path": ".github/workflows/release-pypi.yml",
                    }
                },
                "internalParameters": {
                    "GITHUB_RUN_ID": "1234567890",
                    "GITHUB_RUN_NUMBER": "42",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_TRIGGERING_ACTOR_ID": "0",
                    "GITHUB_REPOSITORY_ID": "0",
                    "GITHUB_REPOSITORY_OWNER_ID": "0",
                    "GITHUB_EVENT_NAME": "push",
                },
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": builder_id,
                    "version": {
                        "slsa-github-generator": builder_workflow_sha,
                    },
                },
                "metadata": {
                    "invocationId": (
                        "https://github.com/epochly-inc/relay/actions/runs/1"
                        "/attempts/1"
                    ),
                    "startedOn": "2026-05-15T00:00:00Z",
                    "finishedOn": "2026-05-15T00:01:00Z",
                },
            },
        },
    }

    bd = statement["predicate"]["buildDefinition"]
    rd = statement["predicate"]["runDetails"]
    if "buildType" in omit:
        del bd["buildType"]
    if "externalParameters" in omit:
        del bd["externalParameters"]
    if "internalParameters" in omit:
        del bd["internalParameters"]
    if "resolvedDependencies" in omit:
        del bd["resolvedDependencies"]
    if "builder.id" in omit:
        del rd["builder"]["id"]
    return statement


def _intoto_envelope(statement: dict[str, Any]) -> str:
    """Wrap an in-toto Statement as a DSSE-shaped envelope on a single
    line (the .intoto.jsonl format the SLSA generator emits).  The
    payload is base64-encoded; the signature block is a placeholder
    that the offline verifier does NOT crypto-verify (Sigstore
    bundle verification is a separate code path covered by
    sigstore-python tests).  This guard verifies STRUCTURE only:
    predicateType, buildType, four required buildDefinition fields."""
    payload = json.dumps(statement, sort_keys=True).encode("utf-8")
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": "test-keyid", "sig": base64.b64encode(b"test").decode("ascii")}
        ],
    }
    return json.dumps(envelope) + "\n"


def _write_attestation(tmp_path: Path, statement: dict[str, Any]) -> Path:
    """Write an in-toto envelope to a .intoto.jsonl file."""
    p = tmp_path / "epochly-relay-provenance.intoto.jsonl"
    p.write_text(_intoto_envelope(statement), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Sanity: the real workflows + the well-formed provenance pass every check.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-011")
@pytest.mark.fulfills("VAL-W12-012")
@pytest.mark.fulfills("VAL-W12-013")
@pytest.mark.fulfills("VAL-W12-014")
@pytest.mark.fulfills("VAL-W12-015")
@pytest.mark.fulfills("VAL-W12-044")
def test_real_release_workflows_pass_every_w12_3_assertion() -> None:
    """The committed release-pypi.yml + release-npm.yml satisfy w12.3."""
    proc = _run_workflow_guard(REPO_ROOT)
    report = _parse_json(proc)
    failing = [c for c in report["checks"] if not c["passed"]]
    assert proc.returncode == 0, (
        f"guard rejected the real workflows: {failing} "
        f"(stderr={proc.stderr!r})"
    )
    expected = {
        "VAL-W12-011",
        "VAL-W12-012",
        "VAL-W12-013",
        "VAL-W12-014",
        "VAL-W12-015",
        "VAL-W12-044",
    }
    actual = {c["assertion"] for c in report["checks"]}
    assert expected <= actual, f"guard skipped: {expected - actual}"


@pytest.mark.plumbing
def test_guard_emits_canonical_error_codes_for_every_assertion() -> None:
    """Each check entry includes the canonical RELAY-RELEASE-NNN code."""
    proc = _run_workflow_guard(REPO_ROOT)
    report = _parse_json(proc)
    expected_pairs = {
        "VAL-W12-011": "RELAY-RELEASE-011",
        "VAL-W12-012": "RELAY-RELEASE-012",
        "VAL-W12-013": "RELAY-RELEASE-013",
        "VAL-W12-014": "RELAY-RELEASE-014",
        "VAL-W12-015": "RELAY-RELEASE-015",
        "VAL-W12-044": "RELAY-RELEASE-044",
    }
    for check in report["checks"]:
        expected = expected_pairs.get(check["assertion"])
        if expected is not None:
            assert check["error_code"] == expected, (
                f"{check['assertion']} reports {check['error_code']}, "
                f"expected {expected}"
            )


# ---------------------------------------------------------------------------
# VAL-W12-011 -- every released artifact has a provenance attestation.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-011")
def test_guard_rejects_pypi_workflow_missing_provenance_job(
    tmp_path: Path,
) -> None:
    """A PyPI workflow with no provenance job FAILS RELAY-RELEASE-011."""

    def transform(data: dict[str, Any]) -> None:
        del data["jobs"]["provenance"]
        # Update publish needs to remove provenance dependency.
        data["jobs"]["publish-release"]["needs"] = ["build"]

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-011")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-011"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-011")
def test_guard_rejects_npm_workflow_missing_sdk_provenance(
    tmp_path: Path,
) -> None:
    """An npm workflow missing SDK provenance job FAILS."""

    def transform(data: dict[str, Any]) -> None:
        del data["jobs"]["provenance-sdk"]
        data["jobs"]["publish-sdk"]["needs"] = [
            "build-sdk",
            "cross-platform-consistency",
        ]

    repo = _materialize_repo(
        tmp_path, npm_workflow_text=_mutate_yaml(_real_npm_text(), transform)
    )
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-011")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-011"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-011")
def test_guard_rejects_npm_workflow_missing_sidecar_provenance(
    tmp_path: Path,
) -> None:
    """An npm workflow missing sidecar-bundle provenance job FAILS."""

    def transform(data: dict[str, Any]) -> None:
        del data["jobs"]["provenance-sidecar-bundle"]
        data["jobs"]["publish-sidecar-bundle"]["needs"] = [
            "build-sidecar-bundle",
            "cross-platform-consistency",
        ]

    repo = _materialize_repo(
        tmp_path, npm_workflow_text=_mutate_yaml(_real_npm_text(), transform)
    )
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-011")
    assert not check["passed"]


# ---------------------------------------------------------------------------
# VAL-W12-012 -- slsa-github-generator reusable workflow, pinned by SHA.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_guard_rejects_unpinned_generator_reference_by_tag(
    tmp_path: Path,
) -> None:
    """A workflow referencing slsa-github-generator by TAG (not SHA) FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance"]["uses"] = (
            "slsa-framework/slsa-github-generator/.github/workflows/"
            "generator_generic_slsa3.yml@v2.0.0"
        )

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-012")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-012"
    assert "pinned" in check["message"].lower() or "sha" in check["message"].lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_guard_rejects_third_party_builder(tmp_path: Path) -> None:
    """A workflow using a non-SLSA reusable builder FAILS."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance"]["uses"] = (
            "evil-org/custom-builder/.github/workflows/build.yml"
            "@1234567890abcdef1234567890abcdef12345678"
        )

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-012")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-012"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-012")
def test_guard_accepts_generator_pinned_by_40_hex_sha(tmp_path: Path) -> None:
    """A different but well-formed 40-hex pin is accepted (SHA pinning is
    structural; the version review is a separate process)."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["provenance"]["uses"] = (
            f"{SLSA_GENERATOR_PATH_PREFIX}generator_generic_slsa3.yml"
            f"@{'b' * 40}"
        )

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-012")
    assert check["passed"], check.get("message")


# ---------------------------------------------------------------------------
# VAL-W12-014 -- failure to produce SLSA attestation blocks the entire release.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-014")
def test_guard_rejects_publish_job_not_needing_provenance(
    tmp_path: Path,
) -> None:
    """A PyPI publish job that does not list ``provenance`` in needs FAILS."""

    def transform(data: dict[str, Any]) -> None:
        # Drop the provenance dependency from publish (publish would
        # ship without waiting for the attestation).
        data["jobs"]["publish-release"]["needs"] = ["build"]

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-014")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-014")
def test_guard_rejects_npm_publish_jobs_not_needing_provenance(
    tmp_path: Path,
) -> None:
    """npm publish jobs that don't depend on their provenance jobs FAIL."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish-sdk"]["needs"] = [
            "build-sdk",
            "cross-platform-consistency",
        ]

    repo = _materialize_repo(
        tmp_path, npm_workflow_text=_mutate_yaml(_real_npm_text(), transform)
    )
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-014")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-014")
def test_guard_rejects_publish_using_continue_on_error(tmp_path: Path) -> None:
    """A publish step with ``continue-on-error: true`` FAILS (would let
    publish proceed even when the provenance step failed)."""

    def transform(data: dict[str, Any]) -> None:
        data["jobs"]["publish-release"]["continue-on-error"] = True

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-014")
    assert not check["passed"]


# ---------------------------------------------------------------------------
# VAL-W12-044 -- fork-friendly dry_run_unsigned mode.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-044")
def test_guard_rejects_workflow_without_fork_dry_run_step(
    tmp_path: Path,
) -> None:
    """A publish job that has no fork-detection step FAILS RELAY-RELEASE-044."""

    def transform(data: dict[str, Any]) -> None:
        # Strip the dry-run-unsigned guard from every PyPI publish job
        # (post-split: publish-release, publish-sidecar, publish-cli).
        for job_name in ("publish-release", "publish-sidecar", "publish-cli"):
            steps = data["jobs"][job_name].get("steps", [])
            data["jobs"][job_name]["steps"] = [
                s for s in steps if "dry-run-unsigned" not in (s.get("id") or "")
                and "dry-run-unsigned" not in (s.get("name") or "").lower()
            ]
            # Also strip env / if guards referencing the sentinel from the
            # publish-step itself.
            for s in data["jobs"][job_name]["steps"]:
                if "if" in s and "dry_run_unsigned" in str(s.get("if", "")):
                    del s["if"]

    repo = _materialize_repo(tmp_path, _mutate_yaml(_real_pypi_text(), transform))
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-044")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-044"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-044")
def test_guard_rejects_npm_workflow_without_fork_dry_run_step(
    tmp_path: Path,
) -> None:
    """npm publish jobs missing fork detection FAIL."""

    def transform(data: dict[str, Any]) -> None:
        for job_name in ("publish-sdk", "publish-sidecar-bundle"):
            steps = data["jobs"][job_name].get("steps", [])
            data["jobs"][job_name]["steps"] = [
                s for s in steps if "dry-run-unsigned" not in (s.get("id") or "")
                and "dry-run-unsigned" not in (s.get("name") or "").lower()
            ]
            for s in data["jobs"][job_name]["steps"]:
                if "if" in s and "dry_run_unsigned" in str(s.get("if", "")):
                    del s["if"]

    repo = _materialize_repo(
        tmp_path, npm_workflow_text=_mutate_yaml(_real_npm_text(), transform)
    )
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-044")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-044")
def test_guard_accepts_workflow_with_fork_detection(tmp_path: Path) -> None:
    """The committed real workflows have fork-detection wired and pass."""
    repo = _materialize_repo(tmp_path)  # uses real committed workflows
    proc = _run_workflow_guard(repo)
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-044")
    assert check["passed"], check.get("message")


# ---------------------------------------------------------------------------
# VAL-W12-013 / VAL-W12-015 -- offline verification of the provenance
# attestation contents.  We exercise --mode attestation against synthetic
# in-toto envelopes; no network access required.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-013")
def test_attestation_verifier_accepts_well_formed_provenance(
    tmp_path: Path,
) -> None:
    """A well-formed SLSA v1.0 provenance envelope verifies offline."""
    statement = _well_formed_provenance(artifact_sha256="a" * 64)
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--expected-source-repo",
        "epochly-inc/relay",
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode == 0, f"verifier rejected well-formed: {report}"
    assert report["ok"] is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-013")
def test_attestation_verifier_rejects_wrong_predicate_type(
    tmp_path: Path,
) -> None:
    """A statement with a non-SLSA-v1 predicateType FAILS RELAY-RELEASE-013."""
    statement = _well_formed_provenance()
    statement["predicateType"] = "https://slsa.dev/provenance/v0.2"
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode != 0
    check = _check_for(report, "VAL-W12-013")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-013"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-013")
def test_attestation_verifier_rejects_subject_digest_mismatch(
    tmp_path: Path,
) -> None:
    """A subject digest that does not match expected FAILS."""
    statement = _well_formed_provenance(artifact_sha256="a" * 64)
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "b" * 64,  # mismatch
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode != 0
    check = _check_for(report, "VAL-W12-013")
    assert not check["passed"]
    assert "digest" in check["message"].lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-013")
def test_attestation_verifier_rejects_third_party_builder_id(
    tmp_path: Path,
) -> None:
    """A builder.id NOT under slsa-framework/slsa-github-generator FAILS."""
    statement = _well_formed_provenance(
        builder_id="https://github.com/evil-org/custom-builder/.github/"
        "workflows/build.yml@refs/tags/v1",
    )
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode != 0
    check = _check_for(report, "VAL-W12-013")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-013")
def test_attestation_verifier_does_no_network_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifier MUST run with all *.epochly.com network egress denied
    (per VAL-W12-013 evidence: ``offline-verify``).  Pointing the script at
    an unreachable HTTP_PROXY MUST NOT cause failure -- the script makes
    no network calls."""
    statement = _well_formed_provenance()
    att_path = _write_attestation(tmp_path, statement)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    assert proc.returncode == 0, (
        f"verifier appears to perform network I/O: stderr={proc.stderr!r}"
    )


# ---------------------------------------------------------------------------
# VAL-W12-015 -- four required buildDefinition fields.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_rejects_missing_build_type(tmp_path: Path) -> None:
    """An attestation missing buildType FAILS RELAY-RELEASE-015."""
    statement = _well_formed_provenance(omit=("buildType",))
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode != 0
    check = _check_for(report, "VAL-W12-015")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-015"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_rejects_missing_external_parameters(
    tmp_path: Path,
) -> None:
    """Missing externalParameters FAILS."""
    statement = _well_formed_provenance(omit=("externalParameters",))
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-015")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_rejects_missing_internal_parameters(
    tmp_path: Path,
) -> None:
    """Missing internalParameters FAILS."""
    statement = _well_formed_provenance(omit=("internalParameters",))
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-015")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_rejects_missing_source_commit(
    tmp_path: Path,
) -> None:
    """Missing resolvedDependencies (source-commit-SHA) FAILS."""
    statement = _well_formed_provenance(omit=("resolvedDependencies",))
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-015")
    assert not check["passed"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_extracts_source_commit_sha(
    tmp_path: Path,
) -> None:
    """Verifier echoes the source commit SHA back from the predicate."""
    statement = _well_formed_provenance(source_commit_sha="9" * 40)
    att_path = _write_attestation(tmp_path, statement)
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(att_path),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    report = _parse_json(proc)
    assert proc.returncode == 0
    assert report["source_commit_sha"] == "9" * 40
    assert report["builder_id"].startswith(
        "https://github.com/slsa-framework/slsa-github-generator"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-015")
def test_attestation_verifier_rejects_unparseable_envelope(
    tmp_path: Path,
) -> None:
    """A malformed envelope FAILS gracefully (exit 2 per script convention)."""
    p = tmp_path / "junk.intoto.jsonl"
    p.write_text("this is not json\n", encoding="utf-8")
    proc = _run_guard(
        "--mode",
        "attestation",
        "--attestation",
        str(p),
        "--expected-sha256",
        "a" * 64,
        "--json",
    )
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# Wiring sanity: the static guard must point at and work with both
# release workflows simultaneously.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_guard_reports_both_workflow_paths_in_output() -> None:
    """The JSON report enumerates the workflow files inspected."""
    proc = _run_workflow_guard(REPO_ROOT)
    report = _parse_json(proc)
    workflow_paths = report.get("workflow_paths") or []
    assert any(p.endswith("release-pypi.yml") for p in workflow_paths), report
    assert any(p.endswith("release-npm.yml") for p in workflow_paths), report


@pytest.mark.plumbing
def test_guard_returns_exit_code_2_on_missing_workflow_file(
    tmp_path: Path,
) -> None:
    """Missing workflow file -> exit 2 (consistent with other guards)."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    # Don't write any workflows.
    proc = _run_workflow_guard(tmp_path)
    assert proc.returncode == 2
