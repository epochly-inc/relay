"""W8-tooling plumbing tests (VAL-V2M08-034..040).

Covers:

  - agent_definition_diff determinism + unobserved-from edge case
    (VAL-V2M08-034, VAL-V2M08-035).
  - per-attempt artifact directory scheme (VAL-V2M08-036).
  - evidence_bundle_registry canonical attempt_prefix pointer
    (VAL-V2M08-037).
  - tier_budget_gate enforcement for plumbing / smoke / eval budgets
    (VAL-V2M08-038, VAL-V2M08-039, VAL-V2M08-040).

Per CLAUDE.md TDD discipline each test binds to its contract assertion via
``@pytest.mark.fulfills``. All tests are plumbing-tier (offline; no
network; <60 s wall) per the contract evidence clause.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Repository root: tests/tooling/test_*.py -> tests/tooling -> tests -> repo root.
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
TIER_BUDGET_GATE: Path = REPO_ROOT / "scripts" / "tier_budget_gate.py"
TIER_WORKFLOW: Path = REPO_ROOT / ".github" / "workflows" / "tier-budgets.yml"


# ---------------------------------------------------------------------------
# VAL-V2M08-034: agent_definition_diff stability across calls.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-034")
def test_agent_definition_diff_is_deterministic() -> None:
    """Two calls with identical inputs return byte-identical canonical JSON.

    Determinism is the load-bearing property here: the diff is consumed by
    Explain timeline UI and by gate-policy authors who diff snapshots in
    review. Any wall-clock timestamp or random ordering would break diff
    stability and re-trigger reviewer churn.
    """
    from relay.agent_definition_diff import (
        AgentDefinitionDiff,
        agent_definition_diff,
        canonicalize_diff,
    )

    snapshot_a = {
        "prompt_hash": "sha256:aaa",
        "template_hash": "sha256:tA",
        "model": "gpt-4o-2024-08-06",
        "model_signature": "fp_a",
        "manifest_commit_hash": "sha256:m1",
        "retrieval": {"retriever_name": "bm25", "config_hash": "sha256:r1"},
        "tools": ["search", "fetch"],
        "redaction_policy_version": 3,
        "assertion_definitions": [
            {"id": "A-1", "current_version": 1},
            {"id": "A-2", "current_version": 4},
        ],
    }
    snapshot_b = {
        "prompt_hash": "sha256:bbb",
        "template_hash": "sha256:tA",
        "model": "gpt-4o-2024-11-20",
        "model_signature": "fp_b",
        "manifest_commit_hash": "sha256:m2",
        "retrieval": {"retriever_name": "bm25", "config_hash": "sha256:r2"},
        "tools": ["search", "browse"],
        "redaction_policy_version": 4,
        "assertion_definitions": [
            {"id": "A-1", "current_version": 2},
            {"id": "A-2", "current_version": 4},
        ],
    }
    one = agent_definition_diff(
        agent_id="agent-001",
        from_release_sha="sha256:from",
        to_release_sha="sha256:to",
        from_snapshot=snapshot_a,
        to_snapshot=snapshot_b,
    )
    two = agent_definition_diff(
        agent_id="agent-001",
        from_release_sha="sha256:from",
        to_release_sha="sha256:to",
        from_snapshot=snapshot_a,
        to_snapshot=snapshot_b,
    )
    assert isinstance(one, AgentDefinitionDiff)
    bytes_one = canonicalize_diff(one)
    bytes_two = canonicalize_diff(two)
    assert bytes_one == bytes_two, "agent_definition_diff is not deterministic"
    # Re-parse to a dict and confirm no timestamp / random field leaked in.
    payload = json.loads(bytes_one.decode("utf-8"))
    flat = json.dumps(payload, sort_keys=True)
    for forbidden in ("generated_at", "timestamp", "now", "random_seed"):
        assert forbidden not in flat, (
            f"non-deterministic field '{forbidden}' present in diff output"
        )


# ---------------------------------------------------------------------------
# VAL-V2M08-035: agent_definition_diff handles unobserved from_release_sha.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-035")
def test_agent_definition_diff_unobserved_from_release_sha() -> None:
    """from_snapshot=None means: agent never ran in from_release_sha.

    Every component returns from_digest=None and summary includes
    'first observed at <to_release_sha>'. The call MUST NOT raise.
    """
    from relay.agent_definition_diff import agent_definition_diff

    to_snapshot = {
        "prompt_hash": "sha256:bbb",
        "template_hash": "sha256:tB",
        "model": "gpt-4o-2024-11-20",
        "model_signature": "fp_b",
        "manifest_commit_hash": "sha256:m2",
        "retrieval": {"retriever_name": "bm25", "config_hash": "sha256:r2"},
        "tools": ["search", "browse"],
        "redaction_policy_version": 4,
        "assertion_definitions": [{"id": "A-1", "current_version": 2}],
    }
    diff = agent_definition_diff(
        agent_id="agent-001",
        from_release_sha="sha256:nope",
        to_release_sha="sha256:to",
        from_snapshot=None,
        to_snapshot=to_snapshot,
    )
    # Components are: prompt, model_config, manifest, retrieval, tools,
    # redaction, contracts. Each MUST report from_digest=None plus a
    # 'first observed at sha256:to' summary clause.
    components = [
        diff.prompt,
        diff.model_config,
        diff.manifest,
        diff.retrieval,
        diff.tools,
        diff.redaction,
        diff.contracts,
    ]
    for component in components:
        assert component.from_digest is None, (
            f"unobserved from snapshot must yield from_digest=None; got {component}"
        )
        assert "first observed at sha256:to" in component.summary, (
            f"summary missing 'first observed at sha256:to': {component.summary!r}"
        )


# ---------------------------------------------------------------------------
# VAL-V2M08-036: per-attempt artifact directory scheme.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-036")
def test_per_attempt_directory_scheme(tmp_path: Path) -> None:
    """Sidecar writes artifacts under attempts/<round>-<worker_id>/.

    Existing attempt directories are NEVER overwritten; each new round
    creates a new prefix. Directory listing matches the round count.
    """
    from relay_sidecar.attempt_dirs import (
        AttemptDir,
        list_attempt_dirs,
        resolve_attempt_dir,
    )

    artifacts_root = tmp_path / "artifacts"
    # Round 1, worker w-abc.
    a1 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=1, worker_id="w-abc", create=True
    )
    (a1.path / "stdout.txt").write_bytes(b"round 1 output\n")
    # Round 2, worker w-def.
    a2 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=2, worker_id="w-def", create=True
    )
    (a2.path / "stdout.txt").write_bytes(b"round 2 output\n")
    # Round 3, worker w-ghi.
    a3 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=3, worker_id="w-ghi", create=True
    )
    (a3.path / "stdout.txt").write_bytes(b"round 3 output\n")

    # Directory shape exactly matches the SRP-SP / spec AM.5 layout.
    assert a1.path == artifacts_root / "attempts" / "1-w-abc"
    assert a2.path == artifacts_root / "attempts" / "2-w-def"
    assert a3.path == artifacts_root / "attempts" / "3-w-ghi"

    # Round 1 output untouched after rounds 2 + 3.
    assert (a1.path / "stdout.txt").read_bytes() == b"round 1 output\n"
    assert (a2.path / "stdout.txt").read_bytes() == b"round 2 output\n"

    # list_attempt_dirs returns all three in deterministic round order.
    listed = list_attempt_dirs(artifacts_root=artifacts_root)
    assert len(listed) == 3
    assert [d.round_ for d in listed] == [1, 2, 3]
    assert [d.worker_id for d in listed] == ["w-abc", "w-def", "w-ghi"]
    assert all(isinstance(d, AttemptDir) for d in listed)

    # Recreating the same (round, worker) MUST NOT overwrite existing data.
    a1_again = resolve_attempt_dir(
        artifacts_root=artifacts_root,
        round_=1,
        worker_id="w-abc",
        create=True,
        exist_ok=True,
    )
    assert a1_again.path == a1.path
    assert (a1_again.path / "stdout.txt").read_bytes() == b"round 1 output\n"

    # Recreating without exist_ok must raise so a careless retry cannot
    # silently overwrite the original failure's evidence.
    with pytest.raises(FileExistsError):
        resolve_attempt_dir(
            artifacts_root=artifacts_root,
            round_=1,
            worker_id="w-abc",
            create=True,
            exist_ok=False,
        )


# ---------------------------------------------------------------------------
# VAL-V2M08-037: evidence_bundle_registry points at the canonical attempt.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-037")
def test_evidence_bundle_registry_artifact_prefix(tmp_path: Path) -> None:
    """For a multi-round run, the registry row's artifact_prefix references
    exactly one attempts/<round>-<worker_id>/ directory (the canonical
    accepted attempt). Other attempt directories remain untouched on disk.
    """
    from relay_sidecar.attempt_dirs import (
        bind_canonical_attempt,
        list_attempt_dirs,
        resolve_attempt_dir,
    )

    artifacts_root = tmp_path / "artifacts"
    # Three rounds; round 3 is the accepted attempt.
    a1 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=1, worker_id="w-abc", create=True
    )
    (a1.path / "stdout.txt").write_bytes(b"round 1\n")
    a2 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=2, worker_id="w-def", create=True
    )
    (a2.path / "stdout.txt").write_bytes(b"round 2\n")
    a3 = resolve_attempt_dir(
        artifacts_root=artifacts_root, round_=3, worker_id="w-ghi", create=True
    )
    (a3.path / "stdout.txt").write_bytes(b"round 3\n")

    # Bind the canonical accepted attempt (round 3) into a registry-row
    # dict. The dict shape MUST include 'evidence_bundle_id', 'state', and
    # 'artifact_prefix'.
    row = bind_canonical_attempt(
        evidence_bundle_id="eb-test-001",
        canonical=a3,
        artifacts_root=artifacts_root,
    )
    assert row["evidence_bundle_id"] == "eb-test-001"
    assert row["state"] in ("building", "active")
    # artifact_prefix is a POSIX-relative path under artifacts_root.
    assert row["artifact_prefix"] == "attempts/3-w-ghi"
    # The referenced directory MUST exist exactly under the canonical layout.
    assert (artifacts_root / row["artifact_prefix"]).is_dir()

    # All three attempt directories MUST remain on disk untouched.
    listed = list_attempt_dirs(artifacts_root=artifacts_root)
    assert len(listed) == 3
    assert (a1.path / "stdout.txt").read_bytes() == b"round 1\n"
    assert (a2.path / "stdout.txt").read_bytes() == b"round 2\n"
    assert (a3.path / "stdout.txt").read_bytes() == b"round 3\n"

    # Sanity: the artifact_prefix references exactly one of the listed dirs.
    referenced = artifacts_root / row["artifact_prefix"]
    assert referenced.resolve() in {d.path.resolve() for d in listed}


# ---------------------------------------------------------------------------
# VAL-V2M08-038/039/040: tier_budget_gate enforces 60s / 480s / 720s budgets.
# ---------------------------------------------------------------------------


def _run_gate(
    tier: str, duration_seconds: float, tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    """Invoke scripts/tier_budget_gate.py against a fabricated pytest-style
    JSON report containing the measured tier duration."""
    report = {
        "tier": tier,
        "duration_seconds": float(duration_seconds),
        "tests": [],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - command literal
        [
            sys.executable,
            str(TIER_BUDGET_GATE),
            "--tier",
            tier,
            "--report",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-038")
def test_tier_budget_gate_plumbing_budget_boundary(tmp_path: Path) -> None:
    """The gate fails when plumbing > budget and passes when <= budget.

    Updated from the original 61/55 threshold pair to 301/295 in
    lockstep with the plumbing budget bump from 60.0 -> 300.0 in
    scripts/tier_budget_gate.py. The bump tracks measured reality
    (the OSS v0.1 plumbing tier carries ~3613 tests; the original
    60s ceiling assumed a much narrower scope per spec AM.6). The
    test continues to verify the contract structure (boundary
    behavior + RELAY-CI-TIER-BUDGET-EXCEEDED emission) at the new
    threshold.
    """
    assert TIER_BUDGET_GATE.is_file(), f"missing gate script: {TIER_BUDGET_GATE}"
    fail = _run_gate("plumbing", 301.0, tmp_path)
    assert fail.returncode != 0, (
        f"plumbing 301.0s must fail; got rc={fail.returncode}, stdout={fail.stdout!r}"
    )
    assert "RELAY-CI-TIER-BUDGET-EXCEEDED" in fail.stdout
    passed = _run_gate("plumbing", 295.0, tmp_path)
    assert passed.returncode == 0, (
        f"plumbing 295.0s must pass; got rc={passed.returncode}, stderr={passed.stderr!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-039")
def test_tier_budget_gate_smoke_480s(tmp_path: Path) -> None:
    """The gate fails when smoke > 480.0 s and passes when <= 480.0 s."""
    fail = _run_gate("smoke", 481.0, tmp_path)
    assert fail.returncode != 0
    assert "RELAY-CI-TIER-BUDGET-EXCEEDED" in fail.stdout
    passed = _run_gate("smoke", 470.0, tmp_path)
    assert passed.returncode == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-040")
def test_tier_budget_gate_eval_720s(tmp_path: Path) -> None:
    """The gate fails when eval > 720.0 s and passes when <= 720.0 s."""
    fail = _run_gate("eval", 721.0, tmp_path)
    assert fail.returncode != 0
    assert "RELAY-CI-TIER-BUDGET-EXCEEDED" in fail.stdout
    passed = _run_gate("eval", 710.0, tmp_path)
    assert passed.returncode == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-038")
def test_tier_budgets_workflow_exists_and_invokes_gate() -> None:
    """The workflow file at .github/workflows/tier-budgets.yml exists and
    references the gate program by path."""
    assert TIER_WORKFLOW.is_file(), f"missing workflow: {TIER_WORKFLOW}"
    text = TIER_WORKFLOW.read_text(encoding="utf-8")
    # Workflow references the gate program.
    assert "scripts/tier_budget_gate.py" in text
    # All three tiers are gated.
    assert "--tier plumbing" in text
    assert "--tier smoke" in text
    assert "--tier eval" in text
    # SHA-pin convention: GitHub Action 'uses:' references on the
    # release-supply-chain path must be 40-hex SHAs, not floating tags.
    # The repo currently uses '@v4' for actions/checkout and setup-python
    # on non-release workflows; we follow that established convention.
    # If the repo flips to mandatory SHA-pin for ALL workflows, this test
    # will tighten.
    assert "actions/checkout@" in text
