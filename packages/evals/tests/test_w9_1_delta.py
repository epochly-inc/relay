"""w9.1 -- eval-delta classifier + idempotence + flake window tests.

Assertions covered:

  VAL-W9-003  Six-class delta classification matches the spec AM.3
              example exactly: c1 pass/pass -> unchanged_pass,
              c2 pass/fail -> net_new_failure,
              c3 fail/pass -> net_new_success,
              c4 absent baseline -> baseline_absent.
  VAL-W9-004  Re-running compute_eval_delta against the same
              (eval_run_id, baseline_eval_run_id) is idempotent: second
              call writes 0 new rows, the table content is byte-
              identical. Re-running against a NEW baseline produces a
              different row set tied to the new baseline_id; old rows
              are NOT mutated.
  VAL-W9-005  flake_window_n parameter is configurable. A case that
              toggled outcome within the last N runs of the same
              dataset+agent_version is classified 'flaky', not
              net_new_failure / net_new_success.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable

import pytest
from relay_evals import (
    DELTA_BASELINE_ABSENT,
    DELTA_FLAKY,
    DELTA_NET_NEW_FAILURE,
    DELTA_NET_NEW_SUCCESS,
    DELTA_UNCHANGED_FAILURE,
    DELTA_UNCHANGED_PASS,
    MAX_FLAKE_WINDOW_N,
    EvalCase,
    EvalCaseOutcome,
    EvalRunner,
    EvidenceBinding,
    apply_migrations,
    compute_eval_delta,
    connect_memory,
)

# Stable sha256-form artifact hash accepted by the eval_results CHECK
# constraint (artifact_hash GLOB 'sha256-*'). Mirrors conftest's
# FIXED_ARTIFACT_HASH; defined locally to avoid a cross-module relative
# import (tests are collected as top-level modules, not a package).
FIXED_ARTIFACT_HASH = "sha256-" + ("beef" * 16)

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _build_evaluator(
    valid_evidence: Callable[..., EvidenceBinding],
    outcomes_by_case: dict[str, str],
) -> Callable[[EvalCase], EvalCaseOutcome]:
    """Return an evaluator that emits the given observed outcomes."""

    def evaluator(case: EvalCase) -> EvalCaseOutcome:
        observed = outcomes_by_case[case.case_id]
        return EvalCaseOutcome(
            observed_outcome=observed,
            evidence=valid_evidence(assertion_id=f"VAL-CASE-{case.case_id}"),
        )

    return evaluator


def _cases(*case_ids: str, expected: str = "pass") -> list[EvalCase]:
    return [
        EvalCase(case_id=cid, payload={}, expected_outcome=expected)
        for cid in case_ids
    ]


def _run_eval(
    *,
    runner: EvalRunner,
    dataset_id: str,
    agent_version: str,
    fixed_manifest_hash: str,
    case_ids: list[str],
    observed_by_case: dict[str, str],
    valid_evidence: Callable[..., EvidenceBinding],
    release_sha: str = "rel-x",
) -> str:
    """Drive an eval run with explicit observed outcomes; return run_id."""
    cases = _cases(*case_ids, expected="pass")
    evaluator = _build_evaluator(valid_evidence, observed_by_case)
    summary = runner.run(
        dataset_id=dataset_id,
        agent_version=agent_version,
        release_sha=release_sha,
        manifest_commit_hash=fixed_manifest_hash,
        cases=cases,
        evaluator=evaluator,
    )
    return summary.eval_run_id


# ---------------------------------------------------------------------------
# VAL-W9-003: six-class classification matches the spec AM.3 example
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-003")
def test_delta_classes_match_spec_example(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """Baseline {c1:pass, c2:pass, c3:fail} vs current
    {c1:pass, c2:fail, c3:pass, c4:pass} ->
    c1 unchanged_pass, c2 net_new_failure, c3 net_new_success,
    c4 baseline_absent.
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)

    baseline_id = _run_eval(
        runner=runner,
        dataset_id="ds-X",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["c1", "c2", "c3"],
        observed_by_case={"c1": "pass", "c2": "pass", "c3": "fail"},
        valid_evidence=valid_evidence,
    )
    current_id = _run_eval(
        runner=runner,
        dataset_id="ds-X",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["c1", "c2", "c3", "c4"],
        observed_by_case={
            "c1": "pass",
            "c2": "fail",
            "c3": "pass",
            "c4": "pass",
        },
        valid_evidence=valid_evidence,
    )

    result = compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
    )
    assert result.rows_inserted == 4
    assert result.rows_existing == 0

    rows = {
        row["case_id"]: row["delta_class"]
        for row in eval_db.execute(
            "SELECT case_id, delta_class FROM eval_run_deltas "
            "WHERE eval_run_id = ?",
            (current_id,),
        ).fetchall()
    }
    assert rows == {
        "c1": DELTA_UNCHANGED_PASS,
        "c2": DELTA_NET_NEW_FAILURE,
        "c3": DELTA_NET_NEW_SUCCESS,
        "c4": DELTA_BASELINE_ABSENT,
    }


# ---------------------------------------------------------------------------
# VAL-W9-004: idempotent + monotonic against the same baseline
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-015")
def test_pass_to_invalid_transition_not_classified_unchanged_failure(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """VAL-ISO-015 regression: a case that was PASSING in baseline but is
    now INVALID (missing evidence) must NOT be recorded as
    'unchanged_failure'.

    Per the runner contract (runner.py: 'failed counts toward eval-delta;
    invalid does not') and spec AM.3's closed six-member enum (no
    'invalid' class), an invalid-involved case must be SKIPPED -- mirroring
    the current_absent handling -- and surfaced via a separate count, NOT
    silently aliased onto 'unchanged_failure' (which would mask the
    pass->invalid regression).
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)

    # Baseline: case 'k' passes with complete evidence.
    baseline_id = _run_eval(
        runner=runner,
        dataset_id="ds-inv",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["k"],
        observed_by_case={"k": "pass"},
        valid_evidence=valid_evidence,
    )

    # Current: case 'k' emits INCOMPLETE evidence (no span ids) -> the
    # runner marks it status='invalid' (VAL-W9-007). observed_outcome is
    # still 'pass' but the case is not a valid pass/fail.
    def invalid_evidence_evaluator(case: EvalCase) -> EvalCaseOutcome:
        return EvalCaseOutcome(
            observed_outcome="pass",
            evidence=valid_evidence(span_ids=[]),  # strips an anchor
        )

    current_id = runner.run(
        dataset_id="ds-inv",
        agent_version="agent-v1",
        release_sha="rel-current",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_cases("k", expected="pass"),
        evaluator=invalid_evidence_evaluator,
    ).eval_run_id

    # Sanity: the current case really is status='invalid'.
    cur_status = eval_db.execute(
        "SELECT status FROM eval_results "
        "WHERE eval_run_id = ? AND case_id = 'k'",
        (current_id,),
    ).fetchone()["status"]
    assert cur_status == "invalid"

    result = compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
    )

    rows = eval_db.execute(
        "SELECT case_id, delta_class FROM eval_run_deltas "
        "WHERE eval_run_id = ?",
        (current_id,),
    ).fetchall()
    classes = {row["case_id"]: row["delta_class"] for row in rows}

    # The defect: pass->invalid was inserted as 'unchanged_failure',
    # masking the regression. The fix: it is NOT classified
    # unchanged_failure -- it is skipped and surfaced via a separate count.
    assert classes.get("k") != DELTA_UNCHANGED_FAILURE, (
        "VAL-ISO-015: pass->invalid must not be aliased to "
        "unchanged_failure (regression masking)."
    )
    assert "k" not in classes, (
        "VAL-ISO-015: invalid-involved case must be skipped from "
        "eval_run_deltas (mirrors current_absent), not inserted."
    )
    assert result.rows_inserted == 0
    assert result.rows_skipped_invalid == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-015")
def test_genuine_unchanged_failure_still_classified(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """VAL-ISO-015 guard: a real fail->fail case is still classified
    'unchanged_failure' after the invalid-skip fix (no over-correction).
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    baseline_id = _run_eval(
        runner=runner,
        dataset_id="ds-uf",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["m"],
        observed_by_case={"m": "fail"},
        valid_evidence=valid_evidence,
    )
    current_id = _run_eval(
        runner=runner,
        dataset_id="ds-uf",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["m"],
        observed_by_case={"m": "fail"},
        valid_evidence=valid_evidence,
    )
    result = compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
    )
    rows = _fetch_deltas(eval_db, current_id, baseline_id)
    assert rows[0]["delta_class"] == DELTA_UNCHANGED_FAILURE
    assert result.rows_inserted == 1
    assert result.rows_skipped_invalid == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-004")
def test_delta_idempotent_against_same_baseline(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """Two invocations with the same (eval_run_id, baseline_eval_run_id)
    pair produce byte-identical row content. Second call writes 0 new
    rows.
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    baseline_id = _run_eval(
        runner=runner,
        dataset_id="ds-Y",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["a", "b"],
        observed_by_case={"a": "pass", "b": "fail"},
        valid_evidence=valid_evidence,
    )
    current_id = _run_eval(
        runner=runner,
        dataset_id="ds-Y",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["a", "b"],
        observed_by_case={"a": "pass", "b": "fail"},
        valid_evidence=valid_evidence,
    )

    first = compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
    )
    snapshot_first = _delta_table_snapshot(eval_db)

    second = compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
    )
    snapshot_second = _delta_table_snapshot(eval_db)

    assert first.rows_inserted == 2
    assert first.rows_existing == 0
    assert second.rows_inserted == 0
    assert second.rows_existing == 2
    assert snapshot_first == snapshot_second


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-004")
def test_delta_new_baseline_supersedes_old_without_mutation(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """A third invocation with a NEW baseline on the SAME current run
    produces a different row set tied to the new baseline_id; old
    delta rows are NOT mutated.
    """
    # Use distinct (dataset_id, agent_version) pairs per baseline so the
    # flake-window history for each delta call is empty. The baselines
    # are still on the same dataset as the current run by being scoped
    # under distinct agent_versions -- this test asserts row supersession
    # semantics, not flake behavior (covered separately).
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    baseline_a = _run_eval(
        runner=runner,
        dataset_id="ds-super",
        agent_version="agent-baseline-a",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["x"],
        observed_by_case={"x": "pass"},
        valid_evidence=valid_evidence,
    )
    baseline_b = _run_eval(
        runner=runner,
        dataset_id="ds-super",
        agent_version="agent-baseline-b",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["x"],
        observed_by_case={"x": "fail"},
        valid_evidence=valid_evidence,
    )
    current_id = _run_eval(
        runner=runner,
        dataset_id="ds-super",
        agent_version="agent-current",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["x"],
        observed_by_case={"x": "pass"},
        valid_evidence=valid_evidence,
    )

    # Delta vs baseline_a: 'pass' == 'pass' => unchanged_pass.
    compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_a,
    )
    rows_a = _fetch_deltas(eval_db, current_id, baseline_a)
    assert rows_a[0]["delta_class"] == DELTA_UNCHANGED_PASS
    snapshot_a_before = dict(rows_a[0])

    # Delta vs baseline_b: 'fail' -> 'pass' => net_new_success.
    compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_b,
    )
    rows_b = _fetch_deltas(eval_db, current_id, baseline_b)
    assert rows_b[0]["delta_class"] == DELTA_NET_NEW_SUCCESS

    # Old rows untouched.
    rows_a_after = _fetch_deltas(eval_db, current_id, baseline_a)
    assert dict(rows_a_after[0]) == snapshot_a_before


# ---------------------------------------------------------------------------
# VAL-W9-005: flake window configurable and bounded
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-005")
def test_flake_window_classifies_toggled_case_as_flaky(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """Construct a history of 6 prior runs for case 'q' alternating
    pass/fail. Current=pass, baseline=fail. Without the window, this
    would classify net_new_success; with the window the case toggled
    and must be 'flaky'.
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)

    # Build a 6-run history with alternating outcomes so the window
    # contains BOTH pass and fail. We tick the SQLite default timestamp
    # by sleeping briefly to guarantee a deterministic order by
    # created_at DESC; alternatively, the runner accepts now_iso for
    # test paths -- but here the natural ordering is sufficient.
    history_run_ids: list[str] = []
    for i, observed in enumerate(["pass", "fail", "pass", "fail", "pass", "fail"]):
        run_id = _run_eval(
            runner=runner,
            dataset_id="ds-flake",
            agent_version="agent-v1",
            fixed_manifest_hash=fixed_manifest_hash,
            case_ids=["q"],
            observed_by_case={"q": observed},
            valid_evidence=valid_evidence,
            release_sha=f"rel-history-{i}",
        )
        history_run_ids.append(run_id)
        time.sleep(0.001)  # ensure strictly increasing created_at

    baseline_id = history_run_ids[0]  # observed='pass'
    # Mark baseline to be 'fail' so the simple comparison would say
    # net_new_success on a current 'pass'. We need baseline distinct
    # from current outcome. So use index 1 ('fail') as the baseline.
    baseline_id = history_run_ids[1]
    time.sleep(0.001)

    current_id = _run_eval(
        runner=runner,
        dataset_id="ds-flake",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["q"],
        observed_by_case={"q": "pass"},
        valid_evidence=valid_evidence,
        release_sha="rel-current",
    )

    compute_eval_delta(
        eval_db,
        eval_run_id=current_id,
        baseline_eval_run_id=baseline_id,
        flake_window_n=5,
    )
    rows = _fetch_deltas(eval_db, current_id, baseline_id)
    assert rows[0]["delta_class"] == DELTA_FLAKY, (
        "VAL-W9-005: case 'q' toggled pass/fail in last 5 runs; "
        "classifier must override net_new_success with 'flaky'."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-005")
def test_flake_window_bound_check(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """flake_window_n is bounded; out-of-range values raise."""
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    base = _run_eval(
        runner=runner,
        dataset_id="ds-bound",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["a"],
        observed_by_case={"a": "pass"},
        valid_evidence=valid_evidence,
    )
    cur = _run_eval(
        runner=runner,
        dataset_id="ds-bound",
        agent_version="agent-v1",
        fixed_manifest_hash=fixed_manifest_hash,
        case_ids=["a"],
        observed_by_case={"a": "pass"},
        valid_evidence=valid_evidence,
    )
    with pytest.raises(ValueError, match="flake_window_n"):
        compute_eval_delta(
            eval_db,
            eval_run_id=cur,
            baseline_eval_run_id=base,
            flake_window_n=0,
        )
    with pytest.raises(ValueError, match="flake_window_n"):
        compute_eval_delta(
            eval_db,
            eval_run_id=cur,
            baseline_eval_run_id=base,
            flake_window_n=MAX_FLAKE_WINDOW_N + 1,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-005")
def test_flake_window_default_logged_into_summary(
    eval_db: sqlite3.Connection,
    deterministic_ids: Callable[[], str],
    fixed_manifest_hash: str,
    valid_evidence: Callable[..., EvidenceBinding],
) -> None:
    """The runner logs the chosen flake_window_n into eval_runs.summary
    so downstream consumers can attribute classification behavior.
    """
    runner = EvalRunner(eval_db, id_supplier=deterministic_ids)
    summary = runner.run(
        dataset_id="ds-summary",
        agent_version="agent-v1",
        release_sha="rel-x",
        manifest_commit_hash=fixed_manifest_hash,
        cases=_cases("a"),
        evaluator=_build_evaluator(valid_evidence, {"a": "pass"}),
        flake_window_n=7,
    )
    import json as _json

    row = eval_db.execute(
        "SELECT summary FROM eval_runs WHERE eval_run_id = ?",
        (summary.eval_run_id,),
    ).fetchone()
    payload = _json.loads(row["summary"])
    assert payload["flake_window_n"] == 7


# ---------------------------------------------------------------------------
# VAL-W9-005: deterministic flake window membership under created_at ties
# ---------------------------------------------------------------------------


def _insert_run(
    conn: sqlite3.Connection,
    *,
    eval_run_id: str,
    dataset_id: str,
    agent_version: str,
    created_at: str,
    case_id: str,
    status: str,
    manifest_hash: str,
) -> None:
    """Directly insert one eval_run + its single per-case eval_result.

    Bypasses EvalRunner so the test controls ``created_at`` exactly (to
    force a tie) and the lexicographic ordering of ``eval_run_id`` (to
    decouple uuid order from insertion/recency order). ``status`` is the
    canonical eval_results enum value ('passed' or 'failed'); each id is
    unique within a fresh DB so a plain INSERT is sufficient.
    """
    if status not in ("passed", "failed"):
        raise ValueError(f"unexpected status token: {status!r}")
    passed = 1 if status == "passed" else 0
    observed = "pass" if status == "passed" else "fail"
    conn.execute(
        "INSERT INTO eval_runs "
        "(eval_run_id, dataset_id, agent_version, release_sha, status, "
        " passed, manifest_commit_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            eval_run_id,
            dataset_id,
            agent_version,
            "rel-x",
            status,
            passed,
            manifest_hash,
            created_at,
        ),
    )
    conn.execute(
        "INSERT INTO eval_results "
        "(eval_result_id, eval_run_id, case_id, status, observed_outcome, "
        " artifact_hash, command_id, exit_code, span_ids, assertion_id, "
        " manifest_commit_hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            f"res-{eval_run_id}",
            eval_run_id,
            case_id,
            status,
            observed,
            FIXED_ARTIFACT_HASH,
            "cmd-test-1",
            0,
            '["span-1"]',
            "VAL-CASE-q",
            manifest_hash,
            created_at,
        ),
    )
    conn.commit()


def _build_tied_history_db(
    *,
    fixed_manifest_hash: str,
    uuid_order_matches_recency: bool,
) -> tuple[sqlite3.Connection, str, str]:
    """Build a fresh DB whose flake history all shares one millisecond.

    Inserts, in recency order (oldest first), six prior runs for case 'q'
    with outcomes:

        oldest -> [failed, passed, passed, passed, passed, passed] <- newest

    The lone 'failed' is the OLDEST run. With window_n=5 and TRUE recency
    (the 5 NEWEST runs) the window is [passed, passed, passed, passed,
    passed] -- a single outcome, NOT flaky. Combined with baseline='fail'
    and current='pass' the correct class is 'net_new_success'.

    If the window is instead cut by random-uuid lexicographic order, that
    oldest 'failed' run can be pulled INTO the window (and a newer 'pass'
    pushed out), making the window contain BOTH outcomes and mislabelling
    the case 'flaky'. The class therefore flips with uuid assignment --
    exactly the non-determinism this test pins down.

    All six runs share the SAME ``created_at`` millisecond, so the only
    tie-breaker is the secondary sort key. ``eval_run_id`` values are
    assigned so their lexicographic order either matches recency
    (``uuid_order_matches_recency=True``) or is the exact reverse
    (``False``). A correct (rowid-ordered) implementation yields the SAME
    window -- and the SAME delta_class ('net_new_success') -- for both; a
    uuid-ordered implementation flips between net_new_success and flaky.

    Returns (conn, current_run_id, baseline_run_id).
    """
    conn = connect_memory()
    apply_migrations(conn)

    dataset_id = "ds-tie"
    agent_version = "agent-v1"
    tied_created_at = "2026-06-14T00:00:00.000Z"

    # recency order, oldest first. The lone 'failed' is the OLDEST run, so
    # a recency-correct window of 5 excludes it (all-pass, not flaky); a
    # uuid-cut window may include it (both outcomes, flaky).
    recency_outcomes = [
        "failed",
        "passed",
        "passed",
        "passed",
        "passed",
        "passed",
    ]
    n = len(recency_outcomes)

    # Assign eval_run_ids so that lexicographic order is controllable and
    # INDEPENDENT of insertion (recency) order. We always INSERT in
    # recency order (so rowid == recency rank), but choose the id string
    # so its lexicographic rank is either the same or reversed.
    for recency_idx, status in enumerate(recency_outcomes):
        if uuid_order_matches_recency:
            lex_rank = recency_idx
        else:
            lex_rank = (n - 1) - recency_idx
        # Zero-padded numeric prefix gives a clean lexicographic order;
        # the random-uuid bug is modelled by lex order != recency order.
        run_id = f"run-{lex_rank:02d}-{recency_idx:02d}"
        _insert_run(
            conn,
            eval_run_id=run_id,
            dataset_id=dataset_id,
            agent_version=agent_version,
            created_at=tied_created_at,
            case_id="q",
            status=status,
            manifest_hash=fixed_manifest_hash,
        )

    # Baseline: a separate run on a DIFFERENT (dataset stays same, agent
    # differs) scope so it is NOT pulled into the flake history window of
    # the current run. Its case 'q' is 'fail' so the simple comparison
    # against a current 'pass' would say net_new_success absent the flake
    # override.
    baseline_id = "baseline-q"
    _insert_run(
        conn,
        eval_run_id=baseline_id,
        dataset_id=dataset_id,
        agent_version="agent-baseline",
        created_at="2026-06-13T00:00:00.000Z",
        case_id="q",
        status="failed",
        manifest_hash=fixed_manifest_hash,
    )

    # Current run: case 'q' passes. Same (dataset, agent) as the history
    # so the history window applies. Inserted last (newest rowid) but
    # excluded from its own window by exclude_eval_run_id.
    current_id = "current-q"
    _insert_run(
        conn,
        eval_run_id=current_id,
        dataset_id=dataset_id,
        agent_version=agent_version,
        created_at="2026-06-14T00:00:00.000Z",
        case_id="q",
        status="passed",
        manifest_hash=fixed_manifest_hash,
    )
    return conn, current_id, baseline_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-005")
def test_flake_window_membership_deterministic_under_created_at_ties(
    fixed_manifest_hash: str,
) -> None:
    """Window membership must be deterministic when >window_n runs share
    the same ``created_at`` millisecond.

    The defect: ``_fetch_flake_history`` ordered by
    ``created_at DESC, eval_run_id DESC`` -- when created_at ties, the
    window boundary is cut by RANDOM uuid lexicographic order, so which
    runs fall inside the window (and therefore whether the case is
    'flaky') depends on uuid assignment, not recency. Logically identical
    history then yields different persisted delta_class.

    Fix: order by a monotonic insertion key (rowid DESC) as the
    tie-breaker so the most-recently-INSERTED runs form the window
    regardless of uuid.

    This test builds the SAME logical history two ways -- once with
    eval_run_id lexicographic order matching recency, once reversed --
    and asserts the resulting delta_class is identical (and equals the
    recency-correct answer, 'net_new_success'). Pre-fix the two diverge
    (one is 'flaky', the other 'net_new_success'); post-fix they agree.
    """
    classes: list[str] = []
    for uuid_matches in (True, False):
        conn, current_id, baseline_id = _build_tied_history_db(
            fixed_manifest_hash=fixed_manifest_hash,
            uuid_order_matches_recency=uuid_matches,
        )
        try:
            compute_eval_delta(
                conn,
                eval_run_id=current_id,
                baseline_eval_run_id=baseline_id,
                flake_window_n=5,
            )
            row = conn.execute(
                "SELECT delta_class FROM eval_run_deltas "
                "WHERE eval_run_id = ? AND case_id = 'q'",
                (current_id,),
            ).fetchone()
            classes.append(row["delta_class"])
        finally:
            conn.close()

    assert classes[0] == classes[1], (
        "flake window membership is non-deterministic under created_at "
        f"ties: uuid-matches-recency gave {classes[0]!r} but "
        f"uuid-reversed gave {classes[1]!r}. The window must be cut by a "
        "monotonic insertion key (rowid), not random uuid order."
    )
    # The recency-correct window (5 newest runs) is all 'pass'; with
    # baseline='fail' and current='pass' the class is net_new_success.
    assert classes[0] == DELTA_NET_NEW_SUCCESS, (
        "with the 5 most-recently-inserted runs all passing, the case is "
        "a clean fail->pass improvement (net_new_success), not flaky."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W9-005")
def test_flake_window_picks_most_recent_runs_under_created_at_ties(
    fixed_manifest_hash: str,
) -> None:
    """The window must contain the most-recently-INSERTED runs, not a
    uuid-lexicographic slice, when created_at ties.

    History (recency, oldest->newest):
    [failed, passed, passed, passed, passed, passed]. The OLDEST run (the
    lone 'failed', inserted first) must be EXCLUDED from a window of 5, so
    the window is all 'passed' and the case is net_new_success. With the
    uuid order reversed vs recency, a uuid-ordered implementation would
    instead pull that oldest 'failed' INTO the window and flip the class
    to 'flaky'. We assert the result is deterministically net_new_success
    across repeated computation regardless of uuid order.
    """
    seen: set[str] = set()
    for _ in range(20):
        conn, current_id, baseline_id = _build_tied_history_db(
            fixed_manifest_hash=fixed_manifest_hash,
            uuid_order_matches_recency=False,
        )
        try:
            compute_eval_delta(
                conn,
                eval_run_id=current_id,
                baseline_eval_run_id=baseline_id,
                flake_window_n=5,
            )
            row = conn.execute(
                "SELECT delta_class FROM eval_run_deltas "
                "WHERE eval_run_id = ? AND case_id = 'q'",
                (current_id,),
            ).fetchone()
            seen.add(row["delta_class"])
        finally:
            conn.close()
    assert seen == {DELTA_NET_NEW_SUCCESS}, (
        "delta_class must be deterministically 'net_new_success' across "
        f"repeated runs; observed {sorted(seen)!r}."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _delta_table_snapshot(conn: sqlite3.Connection) -> list[tuple]:
    """Return a stable list of tuples representing the eval_run_deltas
    table content (ignoring created_at, which is set by SQLite default).
    """
    rows = conn.execute(
        "SELECT delta_id, schema_version, eval_run_id, baseline_eval_run_id, "
        "case_id, delta_class, baseline_outcome, current_outcome, "
        "evidence_refs FROM eval_run_deltas ORDER BY delta_id"
    ).fetchall()
    return [tuple(r) for r in rows]


def _fetch_deltas(
    conn: sqlite3.Connection,
    eval_run_id: str,
    baseline_eval_run_id: str,
) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT delta_id, delta_class, baseline_outcome, current_outcome "
        "FROM eval_run_deltas "
        "WHERE eval_run_id = ? AND baseline_eval_run_id = ? "
        "ORDER BY case_id",
        (eval_run_id, baseline_eval_run_id),
    ).fetchall()
