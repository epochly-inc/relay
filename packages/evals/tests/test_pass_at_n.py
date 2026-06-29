"""pass@N shallow-history symmetry tests (spec AL.2; M05 w5-explain).

These tests pin the informativeness filter's handling of *shallow*
history -- a run window with fewer than ``n`` records. The pass@N
definition treats an all-same-outcome window shorter than ``n`` as
"insufficient history" and therefore equally (un)informative regardless
of outcome polarity: an all-pass shallow window and an all-fail shallow
window MUST receive the same accept/reject decision.

The all-pass edge and the all-fail edge are only "degenerate" (rejected
with ``RELAY-EVAL-024``) when the *full* window of ``n`` runs is
observed and lands entirely on one side. A shorter window does not yet
have enough signal to make that call, so it is accepted pending more
runs -- and that must hold symmetrically.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from relay_evals.pass_at_n import DEFAULT_N, PassAtNResult, check_pass_at_n


def _runs(pattern: str) -> list[dict[str, Any]]:
    """``'PPFP'`` -> pass/fail run records (one per char)."""
    out: list[dict[str, Any]] = []
    for ch in pattern:
        if ch == "P":
            out.append({"status": "pass", "run_id": str(uuid.uuid4())})
        elif ch == "F":
            out.append({"status": "fail", "run_id": str(uuid.uuid4())})
        else:
            raise ValueError(f"unknown char {ch!r}")
    return out


@pytest.mark.plumbing
def test_shallow_all_pass_and_all_fail_have_same_decision() -> None:
    """Shallow all-pass and shallow all-fail get the SAME decision.

    With ``n == DEFAULT_N`` (8) and only 3 runs in the window, neither
    polarity has a full window, so the accept/reject decision must not
    depend on whether the 3 runs are all-pass or all-fail.
    """
    n = DEFAULT_N
    shallow_all_pass = check_pass_at_n(object(), _runs("PPP"), n=n)
    shallow_all_fail = check_pass_at_n(object(), _runs("FFF"), n=n)

    assert isinstance(shallow_all_pass, PassAtNResult)
    assert isinstance(shallow_all_fail, PassAtNResult)
    # The keystone of this finding: same inclusion decision regardless
    # of polarity.
    assert shallow_all_pass.accepted == shallow_all_fail.accepted
    assert shallow_all_pass.error_code == shallow_all_fail.error_code
    assert shallow_all_pass.failing_edge == shallow_all_fail.failing_edge


@pytest.mark.plumbing
def test_shallow_all_fail_is_accepted_as_insufficient_history() -> None:
    """A sub-``n`` all-fail window is insufficient history -> accepted.

    This is the documented intent: with ``n == 8`` over fewer than 8
    runs, the degenerate-edge branch is NOT triggered. The existing
    all-pass shallow case is already accepted; the all-fail shallow case
    must match it.
    """
    result = check_pass_at_n(object(), _runs("FFF"), n=DEFAULT_N)
    assert result.accepted is True
    assert result.error_code is None
    assert result.failing_edge is None


@pytest.mark.plumbing
def test_full_window_edges_still_rejected() -> None:
    """A full ``n``-run window on either edge stays degenerate.

    The symmetry fix must not weaken the real degenerate-edge rejection:
    a complete window of all-pass or all-fail is still rejected with
    ``RELAY-EVAL-024``.
    """
    full_pass = check_pass_at_n(object(), _runs("P" * DEFAULT_N), n=DEFAULT_N)
    full_fail = check_pass_at_n(object(), _runs("F" * DEFAULT_N), n=DEFAULT_N)

    assert full_pass.accepted is False
    assert full_pass.failing_edge == "all_pass"
    assert full_pass.error_code == "RELAY-EVAL-024"

    assert full_fail.accepted is False
    assert full_fail.failing_edge == "all_fail"
    assert full_fail.error_code == "RELAY-EVAL-024"
