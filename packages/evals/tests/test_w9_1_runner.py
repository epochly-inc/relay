"""w9.1 -- EvalRunner pass/fail + evidence binding tests.

Assertions covered:

  VAL-W9-001  Canonical eval_runs row contains all required columns and
              validates as relay.eval_run.v1.
  VAL-W9-002  score = k/N; passed = (k == N AND no invalid). A single
              invalid case forces status='invalid', NOT passed=false.
  VAL-W9-007  Per-case row without evidence binding is status='invalid';
              the runner refuses to mark such a case 'passed' or
              'failed'.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

import pytest
from relay_evals import (
    EvalCase,
    EvalCaseOutcome,
    EvalRunner,
    EvidenceBinding,
)

# ---------------------------------------------------------------------------
# Synthetic evaluators
# ---------------------------------------------------------------------------


def _passing_evaluator(
    valid_evidence: Callable[..., EvidenceBinding],
) -> Callable[[EvalCase], EvalCaseOutcome]:
    """Returns observed = expected for every case (=> all passed)."""

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        return EvalCaseOutcome(
            observed_outcome=case.expected_outcome,
            evidence=valid_evidence(assertion_id=f"VAL-CASE-{case.case_id}"),
        )

    return evaluator


def _mixed_evaluator(
    valid_evidence: Callable[..., EvidenceBinding],
    failing_case_ids: set[str],
) -> Callable[[EvalCase], EvalCaseOutcome]:
    """Returns the expected outcome for every case EXCEPT those in
    ``failing_case_ids``, which get observed='fail' (mismatching).
    """

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        observed = (
            "fail" if case.case_id in failing_case_ids else case.expected_outcome
        )
        return EvalCaseOutcome(
            observed_outcome=observed,
            evidence=valid_evidence(assertion_id=f"VAL-CASE-{case.case_id}"),
        )

    return evaluator


def _missing_evidence_evaluator(
    case: EvalCase,
) -> EvalCaseOutcome:
    """Returns observed=expected but with EMPTY span_ids (invalid)."""
    return EvalCaseOutcome(
        observed_outcome=case.expected_outcome,
        evidence=EvidenceBinding(
            artifact_hash="sha256-" + "00" * 32,
            command_id="cmd-1",
            exit_code=0,
            span_ids=[],  # MISSING -- forces invalid
            manifest_commit_hash="sha256-" + "11" * 32,
            assertion_id="VAL-W9-MISSING",
        ),
    )


def _make_cases(count: int, expected: str = "pass") -> list[EvalCase]:
    return [
        EvalCase(case_id=f"c{i:03d}", payload={"i": i}, expected_outcome=expected)
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# VAL-W9-001: canonical eval_runs row carries all required columns
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-001")
def test_runner_writes_canonical_eval_run_row(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-001",
        agent_version="agent-v1.0.0",
        release_sha="release-abc",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_make_cases(3, "pass"),
        evaluator=_passing_evaluator(valid_evidence),
    )

    # In-memory shape check
    assert summary.status == "passed"
    assert summary.passed is True
    assert summary.score == 1.0
    assert summary.manifest_commit_hash == fixed_manifest_hash

    # Persisted row check. Audit-R4 (2026-05-18): eval_runs.schema_version
    # column was dropped (the literal 'relay.eval_run.v1' is not in
    # KNOWN_SCHEMA_IDS and was already absent from the wire payload). The
    # SELECT and assertion for that column are removed here to match.
    row = eval_db.execute(
        "SELECT eval_run_id, dataset_id, agent_version, release_sha, "
        "status, score, passed, manifest_commit_hash, "
        "summary FROM eval_runs WHERE eval_run_id = ?",
        (summary.eval_run_id,),
    ).fetchone()
    assert row is not None
    assert row["dataset_id"] == "ds-001"
    assert row["agent_version"] == "agent-v1.0.0"
    assert row["release_sha"] == "release-abc"
    assert row["status"] == "passed"
    assert row["score"] == 1.0
    assert row["passed"] == 1
    assert row["manifest_commit_hash"] == fixed_manifest_hash
    summary_payload = json.loads(row["summary"])
    assert summary_payload["case_count"] == 3
    assert summary_payload["passed_count"] == 3


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-001")
def test_runner_rejects_malformed_manifest_commit_hash(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    with pytest.raises(ValueError, match="manifest_commit_hash"):
        runner.run(
            dataset_id="ds-001",
            agent_version="agent-v1",
            release_sha="release-abc",
            manifest_commit_hash="not-a-sha256",
            cases=_make_cases(1),
            evaluator=_passing_evaluator(valid_evidence),
        )


# ---------------------------------------------------------------------------
# VAL-W9-002: pass/fail aggregation matches per-case outcomes
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-002")
def test_aggregation_score_equals_k_over_n(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    # 5 cases, 2 failing => k=3, N=5, score=0.6, passed=False, status='failed'.
    cases = _make_cases(5, "pass")
    failing = {"c001", "c003"}
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-002",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=cases,
        evaluator=_mixed_evaluator(valid_evidence, failing),
    )

    assert summary.status == "failed"
    assert summary.passed is False
    assert summary.score is not None
    assert abs(summary.score - 0.6) < 1e-9

    # Persistence check
    row = eval_db.execute(
        "SELECT status, score, passed FROM eval_runs WHERE eval_run_id = ?",
        (summary.eval_run_id,),
    ).fetchone()
    assert row["status"] == "failed"
    assert row["passed"] == 0
    assert abs(row["score"] - 0.6) < 1e-9


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-002")
def test_aggregation_full_pass_sets_passed_true(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-003",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_make_cases(4, "pass"),
        evaluator=_passing_evaluator(valid_evidence),
    )
    assert summary.status == "passed"
    assert summary.passed is True
    assert summary.score == 1.0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-002")
def test_single_invalid_case_forces_invalid_aggregate(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """VAL-W9-002 distinctness: invalid != failed."""

    cases = _make_cases(3, "pass")
    valid_eval = _passing_evaluator(valid_evidence)

    def hybrid(case: EvalCase) -> EvalCaseOutcome:
        # First case returns missing-evidence outcome, others valid.
        if case.case_id == "c000":
            return _missing_evidence_evaluator(case)
        return valid_eval(case)

    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-004",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=cases,
        evaluator=hybrid,
    )

    # Distinct from passed=False: invalid != failed.
    assert summary.status == "invalid"
    assert summary.passed is False
    assert summary.score is None

    # Persistence: score column is NULL.
    row = eval_db.execute(
        "SELECT status, score, passed FROM eval_runs WHERE eval_run_id = ?",
        (summary.eval_run_id,),
    ).fetchone()
    assert row["status"] == "invalid"
    assert row["score"] is None
    assert row["passed"] == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-002")
def test_empty_dataset_yields_invalid(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """N=0 is not a pass -- empty datasets carry no evidence."""
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-empty",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=[],
        evaluator=_passing_evaluator(valid_evidence),
    )
    assert summary.status == "invalid"
    assert summary.passed is False
    assert summary.score is None


# ---------------------------------------------------------------------------
# VAL-W9-007: per-case row without evidence is invalid, not accepted
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-007")
def test_missing_evidence_forces_case_invalid(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
) -> None:
    """An evaluator that returns observed==expected but no span_ids
    MUST yield status='invalid' for that case, NOT 'passed'.
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-005",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_make_cases(1, "pass"),
        evaluator=_missing_evidence_evaluator,
    )
    [result] = summary.case_results
    assert result.status == "invalid", (
        "VAL-W9-007 inverse: evaluator returned observed==expected with "
        "empty span_ids; runner MUST NOT mark the case 'passed'."
    )
    # The invalid_reason carries the structured missing-token list.
    assert "missing:span_ids" in result.invalid_reason
    assert result.invalid_reason.startswith("EVIDENCE_INCOMPLETE|")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-007")
def test_evidence_binding_persisted_to_eval_results(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """A complete evidence binding lands on the per-case row."""
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-006",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_make_cases(1, "pass"),
        evaluator=_passing_evaluator(valid_evidence),
    )
    row = eval_db.execute(
        "SELECT status, artifact_hash, command_id, exit_code, span_ids, "
        "assertion_id, manifest_commit_hash, invalid_reason "
        "FROM eval_results WHERE eval_run_id = ?",
        (summary.eval_run_id,),
    ).fetchone()
    assert row["status"] == "passed"
    assert row["artifact_hash"] is not None
    assert row["command_id"] is not None
    assert row["exit_code"] == 0  # zero is a valid exit code
    span_ids = json.loads(row["span_ids"])
    assert len(span_ids) > 0
    assert row["assertion_id"] is not None
    assert row["manifest_commit_hash"] == fixed_manifest_hash
    assert row["invalid_reason"] == ""


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-007")
def test_evaluator_exception_marks_case_invalid(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
) -> None:
    """Evaluator raising mid-run produces a status='invalid' row, not a
    process crash. Other cases still produce evidence.
    """

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        raise RuntimeError("synthetic evaluator failure")

    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-007",
        agent_version="agent-v1",
        release_sha="release-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_make_cases(1, "pass"),
        evaluator=evaluator,
    )
    [result] = summary.case_results
    assert result.status == "invalid"
    assert result.invalid_reason.startswith("EVALUATOR_RAISED|RuntimeError|")
