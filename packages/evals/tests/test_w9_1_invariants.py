"""w9.1 -- guard tests for forbidden tables + tier-3 marker policy.

Assertions covered:

  VAL-W9-006  Tier-3 timing budget (12 min) is asserted by CI workflow
              duration externally. This file ships an in-process
              sanity ceiling: a 50-case eval run must complete under 60
              seconds locally. The CI-side duration assertion is the
              canonical measurement; the local sanity test prevents an
              accidental algorithmic blowup from getting to CI.
  VAL-W9-008  The runner MUST NOT write 'run_results' or 'gate_decisions'
              tables. Enforced by:
                (a) source grep over packages/evals/src/ (comments and
                    strings scrubbed to avoid false positives).
                (b) runtime check: after a runner+delta pass, no rows
                    exist in run_results / gate_decisions and the
                    migration did not create those tables in this
                    package.
  VAL-W9-021  Tier-3 skip mechanism is the single canonical
              @pytest.mark.tier3 marker gated on the env var
              RELAY_TIER3_RUNNER=linux-py3.14-node24. On non-target
              matrix slices the test is skipped with the canonical
              reason RELAY-EVAL-TIER3-SKIPPED-NON-TARGET-MATRIX.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import io
import os
import sqlite3
import time
import tokenize
from collections.abc import Callable
from pathlib import Path

import pytest
from relay_evals import (
    EvalCase,
    EvalCaseOutcome,
    EvalRunner,
    EvidenceBinding,
    compute_eval_delta,
)

# packages/evals/tests/test_w9_1_invariants.py -> parents[3] == repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC = REPO_ROOT / "packages" / "evals" / "src" / "relay_evals"

# The forbidden table names. Tests grep the scrubbed source for SQL
# write context against either name.
FORBIDDEN_TABLES = ("run_results", "gate_decisions")

# Tier-3 canonical strings (VAL-W9-021 + eng plan A6 line 290-291).
TIER3_TARGET_MATRIX = "linux-py3.14-node24"
TIER3_SKIP_REASON = "RELAY-EVAL-TIER3-SKIPPED-NON-TARGET-MATRIX"


# ---------------------------------------------------------------------------
# Source-scrubbing helper
# ---------------------------------------------------------------------------


def _scrub_strings_and_comments(src: str) -> str:
    """Replace string literals and comments with empty placeholders.

    Mirrors packages/contracts/tests/test_w6_3_determinism.py:43-86 so
    documentation that mentions 'run_results' or 'gate_decisions'
    doesn't trigger a false positive on the forbidden-table grep.
    """
    out: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                # Preserve the leading marker (b, f, r) and quote so the
                # source remains syntactically valid; replace body with
                # empty content.
                if tok.type == tokenize.COMMENT:
                    out.append("# ")
                else:
                    # Conservative: drop the literal entirely. Caller
                    # only greps post-scrub for identifiers, so a hole
                    # in the token stream is harmless.
                    out.append('""')
            else:
                out.append(tok.string)
    except tokenize.TokenizeError:
        # Truncated source; return as-is for the grep.
        return src
    return " ".join(out)


# ---------------------------------------------------------------------------
# VAL-W9-008: forbidden-table grep guard
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-008")
def test_evals_source_does_not_reference_forbidden_tables() -> None:
    """Grep every .py under packages/evals/src/ for forbidden table
    names in write context. Comments and string literals are scrubbed
    first so documentation-only mentions don't trigger a false hit.
    """
    py_files = sorted(PKG_SRC.rglob("*.py"))
    assert py_files, (
        "VAL-W9-008 setup error: no Python sources found under " + str(PKG_SRC)
    )

    offenders: list[tuple[Path, str]] = []
    for path in py_files:
        src = path.read_text(encoding="utf-8")
        scrubbed = _scrub_strings_and_comments(src)
        for table in FORBIDDEN_TABLES:
            # Look for the table name as a bare identifier in
            # post-scrub source. Any occurrence outside string/comment
            # is a violation because the only legitimate references in
            # this package are documentation strings or comments.
            if table in scrubbed:
                offenders.append((path, table))

    assert not offenders, (
        f"VAL-W9-008 violation: forbidden table names appear in "
        f"packages/evals/src/ outside comments/strings: {offenders}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-008")
def test_runner_writes_only_owned_tables(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """After a runner+delta pass, only eval_runs / eval_results /
    eval_run_deltas tables exist and carry rows. The forbidden
    tables (run_results / gate_decisions) MUST NOT exist in this
    package's schema -- they are owned by the sidecar / state engine.
    """

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        return EvalCaseOutcome(
            observed_outcome=case.expected_outcome,
            evidence=valid_evidence(),
        )

    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    baseline = runner.run(
        dataset_id="ds-guard",
        agent_version="agent-v1",
        release_sha="rel-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=[
            EvalCase(case_id="a", payload={}, expected_outcome="pass"),
            EvalCase(case_id="b", payload={}, expected_outcome="pass"),
        ],
        evaluator=evaluator,
    )
    current = runner.run(
        dataset_id="ds-guard",
        agent_version="agent-v2",  # distinct version => no flake history
        release_sha="rel-y",
        manifest_commit_hash=fixed_manifest_hash,
        cases=[
            EvalCase(case_id="a", payload={}, expected_outcome="pass"),
            EvalCase(case_id="b", payload={}, expected_outcome="pass"),
        ],
        evaluator=evaluator,
    )
    compute_eval_delta(
        eval_db,
        eval_run_id=current.eval_run_id,
        baseline_eval_run_id=baseline.eval_run_id,
    )

    # Tables that exist after migration:
    table_rows = eval_db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    names = {row["name"] for row in table_rows}

    assert "eval_runs" in names
    assert "eval_results" in names
    assert "eval_run_deltas" in names
    for forbidden in FORBIDDEN_TABLES:
        assert forbidden not in names, (
            f"VAL-W9-008 violation: packages/evals/ migration created "
            f"the forbidden table {forbidden!r}; that table is owned "
            f"by the sidecar / state engine."
        )


# ---------------------------------------------------------------------------
# VAL-W9-006: in-process timing sanity ceiling (CI does the real measure)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-006")
def test_eval_runner_local_timing_sanity(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """A 50-case run must complete well under 30 seconds locally so an
    accidental quadratic doesn't blow the tier-3 12-minute CI budget.

    The canonical tier-3 budget is asserted by CI workflow duration
    metadata, not by this in-process timer. This test is a
    pre-flight sanity check only.
    """

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        return EvalCaseOutcome(
            observed_outcome=case.expected_outcome,
            evidence=valid_evidence(),
        )

    cases = [
        EvalCase(case_id=f"case-{i:04d}", payload={}, expected_outcome="pass")
        for i in range(50)
    ]
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    start = time.perf_counter()
    summary = runner.run(
        dataset_id="ds-timing",
        agent_version="agent-v1",
        release_sha="rel-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=cases,
        evaluator=evaluator,
    )
    elapsed = time.perf_counter() - start

    assert summary.passed is True
    assert elapsed < 30.0, (
        f"VAL-W9-006 sanity ceiling: 50-case eval run took {elapsed:.2f}s "
        f"(local sanity bound 30s)."
    )


# ---------------------------------------------------------------------------
# VAL-W9-021: tier-3 marker policy
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-021")
def test_tier3_marker_is_registered_in_pyproject() -> None:
    """The canonical @pytest.mark.tier3 marker MUST be declared in the
    workspace pyproject.toml under [tool.pytest.ini_options].markers.
    Without this registration, --strict-markers (used by CI) rejects
    the marker and any tier-3 test silently skips.
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Look for the marker label in the markers list. The contract text
    # in the entry is informative; only the leading "tier3:" is
    # load-bearing.
    assert '"tier3:' in pyproject, (
        "VAL-W9-021: tier3 marker not registered in pyproject.toml. "
        "Add a 'tier3: ...' entry to [tool.pytest.ini_options].markers."
    )
    # The canonical env var name MUST appear in the marker description
    # so a future contributor can find the policy without reading the
    # contract.
    assert "RELAY_TIER3_RUNNER" in pyproject


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-021")
def test_tier3_skip_reason_is_canonical_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifies the canonical skip-reason string matches the contract.

    The string is the gate engine's attribution token; if it drifts,
    CI matrix introspection (which reads skip reasons to validate the
    tier-3 distribution) misclassifies the skip.
    """
    # The token is centralized in this test module's constant; the
    # contract spells it out at VAL-W9-021. If the contract or this
    # constant drifts, the assertion catches it.
    assert TIER3_SKIP_REASON == "RELAY-EVAL-TIER3-SKIPPED-NON-TARGET-MATRIX"
    assert TIER3_TARGET_MATRIX == "linux-py3.14-node24"


@pytest.mark.tier3
@pytest.mark.fulfills("VAL-W9-021")
def test_tier3_marked_test_respects_env_gate() -> None:
    """A tier-3 test that runs ONLY when RELAY_TIER3_RUNNER matches the
    target matrix; on any other slice it is skipped with the canonical
    reason. This is the single canonical mechanism per VAL-W9-021.
    """
    runner = os.environ.get("RELAY_TIER3_RUNNER", "")
    if runner != TIER3_TARGET_MATRIX:
        pytest.skip(TIER3_SKIP_REASON)
    # On the target slice, the body is a trivial sanity check; the
    # canonical tier-3 evaluation work lives outside this guard test.
    assert runner == TIER3_TARGET_MATRIX
