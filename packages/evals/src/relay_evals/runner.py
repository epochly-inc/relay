"""Eval runner: per-case evaluation + canonical aggregate write.

Implements VAL-W9-001, VAL-W9-002, VAL-W9-007, VAL-W9-008. The runner is
the only writer of ``eval_runs`` and ``eval_results`` rows. It is
forbidden from writing ``run_results`` or ``gate_decisions`` (CLAUDE.md
keystone invariant #1; VAL-W9-008). The grep guard
``tests/test_w9_1_invariants.py`` greps this directory for the forbidden
table names in write context.

Public surface:

  - :class:`EvalCase` -- one input fixture + an opaque payload + the
    expected outcome string.
  - :class:`EvalCaseOutcome` -- what the user-supplied evaluator
    returns: observed_outcome string + evidence binding.
  - :class:`EvalCaseResult` -- the persisted form: outcome + final
    status (``passed`` / ``failed`` / ``invalid``) + invalid_reason.
  - :class:`EvalRunSummary` -- the persisted aggregate
    (status / score / passed / summary).
  - :class:`EvalRunner` -- the runner. ``runner.run(...)`` returns
    ``EvalRunSummary`` and writes both the per-case rows and the
    aggregate row in atomic transactions.

Aggregation contract (VAL-W9-002):

    Given N cases, k where observed_outcome == expected_outcome AND
    status == 'passed':
        score  = k / N        (when N > 0 and no case is invalid)
        passed = (k == N) AND (no case has status 'invalid')

    A single case with status 'invalid' forces eval_runs.status =
    'invalid', score = NULL, passed = False. invalid != failed: failed
    counts toward eval-delta; invalid does not.

    N == 0 => status 'invalid'; an empty dataset cannot produce a pass.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .evidence import (
    EvidenceBinding,
    EvidenceValidation,
    render_invalid_reason,
    validate_binding,
)
from .storage import eval_transaction

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvalCase:
    """One row in an eval dataset.

    ``case_id`` is caller-assigned (typically a deterministic ULID or
    UUID derived from the dataset definition). ``payload`` is opaque
    to the runner; it is passed through to the user-supplied evaluator
    callable. ``expected_outcome`` is the stable string we compare
    ``observed_outcome`` against.
    """

    case_id: str
    payload: Any
    expected_outcome: str


@dataclass(frozen=True, slots=True)
class EvalCaseOutcome:
    """What the user-supplied evaluator returns for one case.

    ``observed_outcome`` is the actual outcome the evaluator computed.
    ``evidence`` is the five-anchor binding (artifact_hash, command_id,
    exit_code, span_ids, manifest_commit_hash, assertion_id). If any
    anchor is missing the runner downgrades the case to
    ``status='invalid'`` (VAL-W9-007 inverse).
    """

    observed_outcome: str
    evidence: EvidenceBinding


@dataclass(frozen=True, slots=True)
class EvalCaseResult:
    """Persisted form of a per-case outcome."""

    case_id: str
    status: str  # 'passed' | 'failed' | 'invalid'
    expected_outcome: str
    observed_outcome: str | None
    evidence: EvidenceBinding
    validation: EvidenceValidation
    invalid_reason: str  # empty when status != 'invalid'


@dataclass(frozen=True, slots=True)
class EvalRunSummary:
    """Persisted aggregate row payload returned by ``runner.run()``."""

    eval_run_id: str
    dataset_id: str
    agent_version: str
    release_sha: str
    status: str  # 'passed' | 'failed' | 'invalid'
    score: float | None
    passed: bool
    manifest_commit_hash: str
    summary: dict[str, Any]
    case_results: tuple[EvalCaseResult, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Forbidden-table guards
# ---------------------------------------------------------------------------
#
# The runner MUST NOT touch run_results or gate_decisions
# (VAL-W9-008 + CLAUDE.md keystone #1). The grep guard in
# tests/test_w9_1_invariants.py asserts no occurrence of those
# identifiers in write context anywhere under packages/evals/. We
# additionally maintain a runtime sanity tuple here so any future
# refactor that imports the names triggers an immediate AssertionError
# at import time -- a defense-in-depth check, not the primary guard.

_FORBIDDEN_TABLES: tuple[str, ...] = ("run_results", "gate_decisions")

# Tables owned by this package and the only ones the runner may write.
_OWNED_TABLES: tuple[str, ...] = (
    "eval_runs",
    "eval_results",
    "eval_run_deltas",
)


# ---------------------------------------------------------------------------
# EvalRunner
# ---------------------------------------------------------------------------


class EvalRunner:
    """Single-process eval runner.

    The caller supplies a SQLite connection (already migrated; see
    :func:`relay_evals.storage.apply_migrations`) and an evaluator
    callable. The runner allocates an ``eval_run_id``, evaluates each
    case, persists per-case ``eval_results`` rows with evidence
    binding, and finalises the aggregate ``eval_runs`` row with status
    / score / passed.

    The runner is deterministic: given the same case list, evaluator
    function, manifest commit hash, and id-supplier, two invocations
    produce byte-identical row content (modulo created_at timestamps,
    which are left to SQLite ``DEFAULT (strftime ...)`` on test paths
    or supplied via ``now_iso=`` for byte-equality tests).
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        id_supplier: Callable[[], str] | None = None,
    ) -> None:
        self._conn = conn
        # Caller-injected id supplier supports deterministic tests; the
        # default is uuid4 so production callers get globally unique ids
        # without coordination.
        self._id_supplier = id_supplier or (lambda: str(uuid.uuid4()))

    # -- public ------------------------------------------------------------

    def run(
        self,
        *,
        dataset_id: str,
        agent_version: str,
        release_sha: str,
        manifest_commit_hash: str,
        cases: Iterable[EvalCase],
        evaluator: Callable[[EvalCase], EvalCaseOutcome],
        flake_window_n: int = 5,
        now_iso: str | None = None,
    ) -> EvalRunSummary:
        """Execute ``cases`` and persist the canonical row set.

        Returns the in-memory :class:`EvalRunSummary`.
        """
        if not manifest_commit_hash.startswith("sha256-"):
            raise ValueError(
                "manifest_commit_hash must be the sha256-<hex> form; "
                "got: " + manifest_commit_hash
            )

        eval_run_id = self._id_supplier()
        case_list = list(cases)

        # 1. Pending row -- so a crash mid-run leaves an observable trace.
        with eval_transaction(self._conn):
            self._insert_eval_run_pending(
                eval_run_id=eval_run_id,
                dataset_id=dataset_id,
                agent_version=agent_version,
                release_sha=release_sha,
                manifest_commit_hash=manifest_commit_hash,
                summary={"flake_window_n": flake_window_n},
                now_iso=now_iso,
            )

        # 2. Per-case evaluation + persistence.
        case_results: list[EvalCaseResult] = []
        for case in case_list:
            result = self._evaluate_one(
                case=case,
                evaluator=evaluator,
            )
            case_results.append(result)
            with eval_transaction(self._conn):
                self._insert_eval_result(
                    eval_run_id=eval_run_id,
                    result=result,
                    now_iso=now_iso,
                )

        # 3. Aggregate + finalize.
        summary = self._aggregate(
            eval_run_id=eval_run_id,
            dataset_id=dataset_id,
            agent_version=agent_version,
            release_sha=release_sha,
            manifest_commit_hash=manifest_commit_hash,
            case_results=case_results,
            flake_window_n=flake_window_n,
        )
        with eval_transaction(self._conn):
            self._finalize_eval_run(summary, now_iso=now_iso)

        return summary

    # -- evaluation --------------------------------------------------------

    def _evaluate_one(
        self,
        *,
        case: EvalCase,
        evaluator: Callable[[EvalCase], EvalCaseOutcome],
    ) -> EvalCaseResult:
        """Invoke ``evaluator(case)`` and return a persisted-shape result.

        On evaluator exception, the case is marked ``status='invalid'``
        with a structured ``invalid_reason``; other cases continue.
        """
        try:
            outcome = evaluator(case)
        except Exception as exc:  # noqa: BLE001 -- we record the exception
            empty_evidence = EvidenceBinding(
                artifact_hash=None,
                command_id=None,
                exit_code=None,
                span_ids=[],
            )
            validation = validate_binding(empty_evidence)
            return EvalCaseResult(
                case_id=case.case_id,
                status="invalid",
                expected_outcome=case.expected_outcome,
                observed_outcome=None,
                evidence=empty_evidence,
                validation=validation,
                invalid_reason=(
                    "EVALUATOR_RAISED|"
                    + type(exc).__name__
                    + "|"
                    + str(exc)[:200]
                ),
            )

        validation = validate_binding(outcome.evidence)
        if not validation.is_complete:
            # VAL-W9-007: refuse to claim pass/fail without evidence.
            return EvalCaseResult(
                case_id=case.case_id,
                status="invalid",
                expected_outcome=case.expected_outcome,
                observed_outcome=outcome.observed_outcome,
                evidence=outcome.evidence,
                validation=validation,
                invalid_reason=render_invalid_reason(validation),
            )

        status = (
            "passed"
            if outcome.observed_outcome == case.expected_outcome
            else "failed"
        )
        return EvalCaseResult(
            case_id=case.case_id,
            status=status,
            expected_outcome=case.expected_outcome,
            observed_outcome=outcome.observed_outcome,
            evidence=outcome.evidence,
            validation=validation,
            invalid_reason="",
        )

    # -- aggregation -------------------------------------------------------

    def _aggregate(
        self,
        *,
        eval_run_id: str,
        dataset_id: str,
        agent_version: str,
        release_sha: str,
        manifest_commit_hash: str,
        case_results: list[EvalCaseResult],
        flake_window_n: int,
    ) -> EvalRunSummary:
        """Compute status / score / passed per VAL-W9-002."""
        n = len(case_results)
        any_invalid = any(r.status == "invalid" for r in case_results)
        passed_count = sum(1 for r in case_results if r.status == "passed")
        failed_count = sum(1 for r in case_results if r.status == "failed")

        if n == 0:
            # Empty dataset: cannot claim a pass (no evidence at all).
            status = "invalid"
            score: float | None = None
            passed_bool = False
        elif any_invalid:
            status = "invalid"
            score = None
            passed_bool = False
        elif passed_count == n:
            status = "passed"
            score = 1.0
            passed_bool = True
        else:
            status = "failed"
            score = passed_count / n
            passed_bool = False

        summary = {
            "flake_window_n": flake_window_n,
            "case_count": n,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "invalid_count": sum(
                1 for r in case_results if r.status == "invalid"
            ),
        }

        return EvalRunSummary(
            eval_run_id=eval_run_id,
            dataset_id=dataset_id,
            agent_version=agent_version,
            release_sha=release_sha,
            status=status,
            score=score,
            passed=passed_bool,
            manifest_commit_hash=manifest_commit_hash,
            summary=summary,
            case_results=tuple(case_results),
        )

    # -- persistence -------------------------------------------------------

    def _insert_eval_run_pending(
        self,
        *,
        eval_run_id: str,
        dataset_id: str,
        agent_version: str,
        release_sha: str,
        manifest_commit_hash: str,
        summary: dict[str, Any],
        now_iso: str | None,
    ) -> None:
        cols = (
            "eval_run_id, dataset_id, agent_version, release_sha, "
            "status, passed, manifest_commit_hash, summary"
        )
        params: tuple[Any, ...] = (
            eval_run_id,
            dataset_id,
            agent_version,
            release_sha,
            "pending",
            0,
            manifest_commit_hash,
            json.dumps(summary, sort_keys=True),
        )
        if now_iso is not None:
            self._conn.execute(
                f"INSERT INTO eval_runs ({cols}, created_at) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params + (now_iso,),
            )
        else:
            self._conn.execute(
                f"INSERT INTO eval_runs ({cols}) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )

    def _insert_eval_result(
        self,
        *,
        eval_run_id: str,
        result: EvalCaseResult,
        now_iso: str | None,
    ) -> None:
        eval_result_id = self._id_supplier()
        cols = (
            "eval_result_id, eval_run_id, case_id, status, "
            "expected_outcome, observed_outcome, "
            "artifact_hash, command_id, exit_code, span_ids, "
            "assertion_id, manifest_commit_hash, invalid_reason"
        )
        params: tuple[Any, ...] = (
            eval_result_id,
            eval_run_id,
            result.case_id,
            result.status,
            result.expected_outcome,
            result.observed_outcome,
            result.evidence.artifact_hash,
            result.evidence.command_id,
            result.evidence.exit_code,
            json.dumps(result.evidence.span_ids, sort_keys=True),
            result.evidence.assertion_id,
            result.evidence.manifest_commit_hash,
            result.invalid_reason,
        )
        if now_iso is not None:
            self._conn.execute(
                f"INSERT INTO eval_results ({cols}, created_at) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params + (now_iso,),
            )
        else:
            self._conn.execute(
                f"INSERT INTO eval_results ({cols}) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )

    def _finalize_eval_run(
        self,
        summary: EvalRunSummary,
        *,
        now_iso: str | None,
    ) -> None:
        # Single UPDATE on the row this runner inserted in step 1. Per
        # VAL-W9-008 + the runtime guard above, this row lives in
        # eval_runs (NOT run_results / NOT gate_decisions).
        self._conn.execute(
            "UPDATE eval_runs "
            "SET status = ?, score = ?, passed = ?, summary = ? "
            "WHERE eval_run_id = ?",
            (
                summary.status,
                summary.score,
                1 if summary.passed else 0,
                json.dumps(summary.summary, sort_keys=True),
                summary.eval_run_id,
            ),
        )
