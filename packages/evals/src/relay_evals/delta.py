"""Eval-delta classifier and persistence.

Implements VAL-W9-003, VAL-W9-004, VAL-W9-005. Computes per-case delta
class between a current ``eval_run`` and a baseline ``eval_run`` over
the same dataset, persists to ``eval_run_deltas`` (append-only via
``INSERT OR IGNORE`` against a deterministic ``delta_id``), and applies
the configurable flake window.

Spec anchor: AM.3 line 5876-5898.

Determinism + idempotence (VAL-W9-004):

  - ``delta_id`` is derived from
        sha256(eval_run_id || '|' || baseline_eval_run_id || '|' || case_id).
    Re-running ``compute_eval_delta`` with the same
    ``(eval_run_id, baseline_eval_run_id)`` pair produces identical
    delta_id values; the UNIQUE constraint and ``INSERT OR IGNORE``
    keep the second invocation a no-op.
  - Re-running with a NEW baseline produces a different ``delta_id``
    (because baseline_eval_run_id is in the hash input). Old rows are
    not mutated. No UPDATE statement appears in this module (the
    runtime invariant guard ``test_w9_1_invariants.py`` greps for
    ``UPDATE eval_run_deltas`` and asserts zero hits).

Flake window (VAL-W9-005):

  - ``flake_window_n`` defaults to 5 (eng plan A6 reconciliation;
    contract gap #2 explicitly flags this default).
  - "Toggled within the window" means: among the last
    ``flake_window_n`` ``eval_runs`` for the same
    ``(dataset_id, agent_version)`` ordered by ``created_at DESC``
    (excluding the current run), this case's outcome includes BOTH
    'pass' and 'fail' values. A case with no prior history within the
    window is classified by baseline comparison only.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

from .storage import eval_transaction

# Closed six-member enum from spec AM.3 line 5886-5893.
DELTA_NET_NEW_FAILURE = "net_new_failure"
DELTA_NET_NEW_SUCCESS = "net_new_success"
DELTA_UNCHANGED_PASS = "unchanged_pass"
DELTA_UNCHANGED_FAILURE = "unchanged_failure"
DELTA_FLAKY = "flaky"
DELTA_BASELINE_ABSENT = "baseline_absent"

DELTA_CLASSES: tuple[str, ...] = (
    DELTA_NET_NEW_FAILURE,
    DELTA_NET_NEW_SUCCESS,
    DELTA_UNCHANGED_PASS,
    DELTA_UNCHANGED_FAILURE,
    DELTA_FLAKY,
    DELTA_BASELINE_ABSENT,
)

DEFAULT_FLAKE_WINDOW_N = 5
MAX_FLAKE_WINDOW_N = 50


@dataclass(frozen=True, slots=True)
class DeltaComputeResult:
    """Counts returned by :func:`compute_eval_delta`."""

    rows_inserted: int
    rows_existing: int  # rows that already existed (idempotent re-run)
    rows_skipped_current_absent: int
    rows_skipped_invalid: int = 0  # invalid-involved cases (no admissible delta)


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Materialised view of a per-case row needed for classification."""

    case_id: str
    status: str
    observed_outcome: str | None


def compute_eval_delta(
    conn: sqlite3.Connection,
    *,
    eval_run_id: str,
    baseline_eval_run_id: str,
    flake_window_n: int = DEFAULT_FLAKE_WINDOW_N,
) -> DeltaComputeResult:
    """Compute and persist eval-delta rows for one (current, baseline) pair.

    Raises:
        ``ValueError`` if ``flake_window_n`` is out of range
            (1 <= n <= 50).
        ``ValueError`` if either run id is missing or the two runs are
            on different datasets (cross-dataset deltas are nonsensical).
    """
    if not (1 <= flake_window_n <= MAX_FLAKE_WINDOW_N):
        raise ValueError(
            f"flake_window_n out of range [1, {MAX_FLAKE_WINDOW_N}]: "
            f"{flake_window_n}"
        )

    current_meta = _fetch_run_meta(conn, eval_run_id)
    baseline_meta = _fetch_run_meta(conn, baseline_eval_run_id)
    if current_meta is None:
        raise ValueError(f"unknown eval_run_id: {eval_run_id}")
    if baseline_meta is None:
        raise ValueError(
            f"unknown baseline_eval_run_id: {baseline_eval_run_id}"
        )

    cur_dataset, cur_agent = current_meta
    base_dataset, _base_agent = baseline_meta
    if cur_dataset != base_dataset:
        raise ValueError(
            "cross-dataset eval-delta not permitted: "
            f"current.dataset_id={cur_dataset!r}, "
            f"baseline.dataset_id={base_dataset!r}"
        )

    current_cases = _fetch_outcomes(conn, eval_run_id)
    baseline_cases = _fetch_outcomes(conn, baseline_eval_run_id)
    flake_history = _fetch_flake_history(
        conn,
        dataset_id=cur_dataset,
        agent_version=cur_agent,
        exclude_eval_run_id=eval_run_id,
        window_n=flake_window_n,
    )

    rows_inserted = 0
    rows_existing = 0
    rows_skipped_current_absent = 0
    rows_skipped_invalid = 0

    with eval_transaction(conn):
        for case_id, current in current_cases.items():
            baseline = baseline_cases.get(case_id)
            delta_class = _classify(
                case_id=case_id,
                current=current,
                baseline=baseline,
                flake_history=flake_history.get(case_id, []),
            )
            if delta_class is None:
                # Invalid-involved case: no admissible delta (spec AM.3's
                # closed six-member enum has no 'invalid' class, and the
                # runner contract states "failed counts toward eval-delta;
                # invalid does not"). Skip insertion -- mirroring the
                # current_absent handling below -- and surface via a
                # separate count so a pass->invalid break is not masked
                # as 'unchanged_failure' (VAL-ISO-015).
                rows_skipped_invalid += 1
                continue
            delta_id = _derive_delta_id(
                eval_run_id=eval_run_id,
                baseline_eval_run_id=baseline_eval_run_id,
                case_id=case_id,
            )
            cursor = conn.execute(
                "INSERT OR IGNORE INTO eval_run_deltas "
                "(delta_id, eval_run_id, baseline_eval_run_id, case_id, "
                " delta_class, baseline_outcome, current_outcome, "
                " evidence_refs) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    delta_id,
                    eval_run_id,
                    baseline_eval_run_id,
                    case_id,
                    delta_class,
                    baseline.observed_outcome if baseline else None,
                    current.observed_outcome,
                    json.dumps([], sort_keys=True),
                ),
            )
            if cursor.rowcount == 1:
                rows_inserted += 1
            else:
                rows_existing += 1

        # Cases present in baseline but absent in current: spec AM.3 does
        # not enumerate a "current_absent" delta class. We skip them to
        # stay within the six-member closed enum. The count is returned
        # so callers can surface the dropped cases via their own
        # observability surface if needed.
        for case_id in baseline_cases:
            if case_id not in current_cases:
                rows_skipped_current_absent += 1

    return DeltaComputeResult(
        rows_inserted=rows_inserted,
        rows_existing=rows_existing,
        rows_skipped_current_absent=rows_skipped_current_absent,
        rows_skipped_invalid=rows_skipped_invalid,
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify(
    *,
    case_id: str,
    current: _Outcome,
    baseline: _Outcome | None,
    flake_history: list[str],
) -> str | None:
    """Return one of the six DELTA_* classes, or ``None`` to skip.

    Returns ``None`` when either side of the comparison is ``invalid``:
    spec AM.3's ``delta_class`` is a closed six-member enum with no
    'invalid' member, and the runner contract states "failed counts
    toward eval-delta; invalid does not". An invalid-involved case has
    no admissible delta and must be SKIPPED (mirroring the current_absent
    handling) -- never aliased onto 'unchanged_failure', which would mask
    a pass->invalid regression (VAL-ISO-015).
    """
    # Map per-case status -> normalized 'pass' / 'fail' / 'invalid'
    # using observed_outcome plus status. For pass/fail aggregation
    # purposes:
    #   - status='passed'  => 'pass'
    #   - status='failed'  => 'fail'
    #   - status='invalid' => 'invalid' (no comparison admissible)
    cur = _normalize(current)
    base = _normalize(baseline) if baseline is not None else None

    if base is None:
        return DELTA_BASELINE_ABSENT

    # Invalid involvement: there is no admissible delta. The six-member
    # enum has no 'invalid' class, so we skip the case (return None) and
    # let the caller surface it via rows_skipped_invalid -- the same way
    # current_absent cases are skipped and counted. This must come BEFORE
    # the flake override: a case that is invalid in the current run is
    # not a comparable pass/fail outcome regardless of its history.
    if cur == "invalid" or base == "invalid":
        return None

    # Flake detection: if the prior history within window contains BOTH
    # 'pass' and 'fail' outcomes for this case, classify flaky and
    # override the simple comparison. This catches a case whose result
    # has bounced and shouldn't be counted as a true regression /
    # improvement (eng plan note: avoids false alarms in nightly evals).
    if base != cur and _is_flaky(flake_history):
        return DELTA_FLAKY

    if base == "pass" and cur == "pass":
        return DELTA_UNCHANGED_PASS
    if base == "fail" and cur == "fail":
        return DELTA_UNCHANGED_FAILURE
    if base == "pass" and cur == "fail":
        return DELTA_NET_NEW_FAILURE
    if base == "fail" and cur == "pass":
        return DELTA_NET_NEW_SUCCESS

    # Unreachable: cur/base are each in {pass, fail} here (invalid was
    # handled above), and all four pass/fail pairings are enumerated.
    # Defensive fallthrough that does not silently invent a class.
    raise AssertionError(
        f"unclassifiable delta for case {case_id!r}: "
        f"base={base!r}, cur={cur!r}"
    )


def _normalize(outcome: _Outcome) -> str:
    """Map an _Outcome onto 'pass' / 'fail' / 'invalid'."""
    if outcome.status == "passed":
        return "pass"
    if outcome.status == "failed":
        return "fail"
    return "invalid"


def _is_flaky(flake_history: list[str]) -> bool:
    """True iff the history contains both 'pass' and 'fail' outcomes."""
    seen_pass = False
    seen_fail = False
    for outcome in flake_history:
        if outcome == "pass":
            seen_pass = True
        elif outcome == "fail":
            seen_fail = True
        if seen_pass and seen_fail:
            return True
    return False


# ---------------------------------------------------------------------------
# delta_id derivation
# ---------------------------------------------------------------------------


def _derive_delta_id(
    *,
    eval_run_id: str,
    baseline_eval_run_id: str,
    case_id: str,
) -> str:
    """Deterministic UUID-shaped id from the three inputs.

    Format: sha256(eval_run_id|baseline_eval_run_id|case_id) hex
    truncated to 32 chars and rendered as 8-4-4-4-12 (UUID-shape).
    Two re-runs of compute_eval_delta with the same inputs produce
    identical ids -- the cornerstone of VAL-W9-004 idempotence.
    """
    payload = f"{eval_run_id}|{baseline_eval_run_id}|{case_id}".encode()
    digest = hashlib.sha256(payload).hexdigest()[:32]
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _fetch_run_meta(
    conn: sqlite3.Connection,
    eval_run_id: str,
) -> tuple[str, str] | None:
    """Return (dataset_id, agent_version) or None."""
    row = conn.execute(
        "SELECT dataset_id, agent_version FROM eval_runs WHERE eval_run_id = ?",
        (eval_run_id,),
    ).fetchone()
    if row is None:
        return None
    return (row["dataset_id"], row["agent_version"])


def _fetch_outcomes(
    conn: sqlite3.Connection,
    eval_run_id: str,
) -> dict[str, _Outcome]:
    """Return ``{case_id: _Outcome}`` for all cases of one run."""
    cursor = conn.execute(
        "SELECT case_id, status, observed_outcome FROM eval_results "
        "WHERE eval_run_id = ?",
        (eval_run_id,),
    )
    return {
        row["case_id"]: _Outcome(
            case_id=row["case_id"],
            status=row["status"],
            observed_outcome=row["observed_outcome"],
        )
        for row in cursor.fetchall()
    }


def _fetch_flake_history(
    conn: sqlite3.Connection,
    *,
    dataset_id: str,
    agent_version: str,
    exclude_eval_run_id: str,
    window_n: int,
) -> dict[str, list[str]]:
    """Return ``{case_id: [outcome, ...]}`` for the last ``window_n`` runs.

    Excludes the current run id. Outcomes are normalised to
    'pass' / 'fail' / 'invalid'.
    """
    # Get the last window_n eval_run_ids (excluding the current one) for
    # this (dataset_id, agent_version). Order by created_at DESC, then by
    # the monotonic insertion key (SQLite rowid) DESC as the tie-breaker.
    #
    # created_at has only millisecond resolution (the table default is
    # strftime('%Y-%m-%dT%H:%M:%fZ', 'now')). When more than window_n runs
    # for the same (dataset_id, agent_version) share one millisecond, the
    # window boundary must still reflect true recency. eval_run_id is a
    # uuid4 -- its lexicographic order is RANDOM and unrelated to insertion
    # order, so tie-breaking on it would cut the window non-deterministically
    # and flip a case's flake classification (and the persisted delta_class)
    # for logically identical history. rowid is assigned monotonically by
    # INSERT order on this (rowid'd, i.e. non WITHOUT ROWID) table, so
    # rowid DESC == most-recently-inserted-first == true recency, regardless
    # of uuid. This keeps window membership deterministic and meaningful.
    run_id_rows = conn.execute(
        "SELECT eval_run_id FROM eval_runs "
        "WHERE dataset_id = ? AND agent_version = ? "
        "  AND eval_run_id != ? "
        "ORDER BY created_at DESC, rowid DESC "
        "LIMIT ?",
        (dataset_id, agent_version, exclude_eval_run_id, window_n),
    ).fetchall()
    if not run_id_rows:
        return {}

    run_ids = [r["eval_run_id"] for r in run_id_rows]
    placeholders = ",".join("?" for _ in run_ids)
    cursor = conn.execute(
        f"SELECT eval_run_id, case_id, status "
        f"FROM eval_results "
        f"WHERE eval_run_id IN ({placeholders})",
        run_ids,
    )
    history: dict[str, list[str]] = {}
    # Preserve newest-first ordering by ordering rows by the run_id
    # position. Build a map run_id -> ordinal first.
    run_order = {rid: idx for idx, rid in enumerate(run_ids)}
    rows = cursor.fetchall()
    rows_sorted = sorted(rows, key=lambda r: run_order[r["eval_run_id"]])
    for row in rows_sorted:
        outcome = _status_to_outcome_token(row["status"])
        history.setdefault(row["case_id"], []).append(outcome)
    return history


def _status_to_outcome_token(status: str) -> str:
    if status == "passed":
        return "pass"
    if status == "failed":
        return "fail"
    return "invalid"
