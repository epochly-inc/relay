"""pass@N filter (spec AL.2 lines 5775-5785; M05 w5-explain; VAL-V2M05-017/022..025).

An assertion set is *informative* only when it discriminates between
passing and failing runs over the last N executions. An all-pass edge
(``pass_count == N``) or an all-fail edge (``pass_count == 0``) carries
zero signal: the assertion either never fires (waste of CEL budget) or
always fires (degenerate "always reject" behavior).

The filter is consumed at *publish* time by the contract publish path:
when a new assertion set is registered, the most-recent ``N`` historical
runs are scored against it; if ``pass_count`` lands on either edge, the
publish request is rejected with HTTP 422 + ``RELAY-EVAL-024`` and a
``failing_edge`` reference to the run set so the author can iterate.

Default ``N`` is ``8`` (spec AL.2 line 5781); override via the ``n``
keyword for assertion-set authors that want a stricter or laxer window.

Spec anchors:
  AL.2 5775-5785   pass@N filter behavior and default

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from relay_schemas.error_codes import RelayErrorCode

DEFAULT_N: int = 8


@dataclass(frozen=True)
class PassAtNResult:
    """Outcome of one :func:`check_pass_at_n` call.

    When ``accepted`` is False, ``error_code`` is the wire-format token
    the publish path returns in its error envelope, and ``failing_edge``
    identifies which degenerate edge was hit (``"all_pass"`` or
    ``"all_fail"``).
    """

    accepted: bool
    n: int
    pass_count: int
    fail_count: int
    error_code: str | None
    failing_edge: str | None
    run_set: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "n": self.n,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "error_code": self.error_code,
            "failing_edge": self.failing_edge,
            "run_set": list(self.run_set),
        }


def check_pass_at_n(
    assertion_set: object,
    recent_runs: Sequence[Any],
    n: int = DEFAULT_N,
) -> PassAtNResult:
    """Return whether ``assertion_set`` is informative over ``recent_runs``.

    Inputs:
      - ``assertion_set``: opaque to the filter; included for ergonomic
        symmetry with the publish-time call site (the publish path passes
        the assertion set so future heuristics can correlate). The
        current filter does not inspect it.
      - ``recent_runs``: ordered iterable of "run records". Each record
        is either:
          - a mapping with at least a ``status`` key (``'pass'`` |
            ``'fail'``) and optionally a ``run_id`` key; OR
          - a mapping with a ``passed`` bool; OR
          - any object with attributes ``status`` / ``passed`` /
            ``run_id``.
        Only the last ``n`` records are considered.
      - ``n``: window size; defaults to :data:`DEFAULT_N` (8).

    Output: :class:`PassAtNResult`. ``accepted=False`` only when the
    FULL window of ``n`` runs landed on a single edge -- i.e.
    ``observed == n`` and (``pass_count == n`` or ``pass_count == 0``);
    the failing edge is captured in ``failing_edge``. ``accepted=True``
    otherwise. A window shorter than ``n`` ("insufficient history") is
    accepted regardless of outcome polarity: a shallow all-pass window
    and a shallow all-fail window receive the same decision.

    The function never raises on empty input; an empty ``recent_runs``
    is treated as insufficient history (``observed == 0 < n``) and is
    accepted, symmetric with any other sub-``n`` window. The publish
    path may still treat empty history as "insufficient" upstream.
    """
    if n <= 0:
        raise ValueError(f"n must be > 0, got {n}")
    # Materialise + cap to the last n. Callers passing a list slice the
    # window themselves; the safety net catches generators / longer lists.
    runs = list(recent_runs)[-n:]
    pass_count = 0
    fail_count = 0
    run_set: list[str] = []
    for record in runs:
        run_id = _extract_run_id(record)
        if run_id is not None:
            run_set.append(run_id)
        if _record_passed(record):
            pass_count += 1
        else:
            fail_count += 1
    observed = pass_count + fail_count
    if observed == n and pass_count == n:
        return PassAtNResult(
            accepted=False,
            n=n,
            pass_count=pass_count,
            fail_count=fail_count,
            error_code=RelayErrorCode.RELAY_EVAL_024,
            failing_edge="all_pass",
            run_set=run_set,
        )
    # Symmetric with the all-pass edge above: an all-fail window is only
    # degenerate when the FULL window of ``n`` runs landed on the fail
    # side. A shallow window (``observed < n``) is "insufficient history"
    # regardless of polarity, so it must not be rejected here -- otherwise
    # a sub-``n`` all-fail set would be rejected while an equally shallow
    # all-pass set is accepted.
    if observed == n and pass_count == 0:
        return PassAtNResult(
            accepted=False,
            n=n,
            pass_count=pass_count,
            fail_count=fail_count,
            error_code=RelayErrorCode.RELAY_EVAL_024,
            failing_edge="all_fail",
            run_set=run_set,
        )
    return PassAtNResult(
        accepted=True,
        n=n,
        pass_count=pass_count,
        fail_count=fail_count,
        error_code=None,
        failing_edge=None,
        run_set=run_set,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _record_passed(record: Any) -> bool:
    """Return True iff ``record`` represents a passing run."""
    if isinstance(record, dict):
        if "passed" in record:
            return bool(record["passed"])
        status = record.get("status")
        if isinstance(status, str):
            return status.lower() == "pass"
        return False
    passed = getattr(record, "passed", None)
    if isinstance(passed, bool):
        return passed
    status = getattr(record, "status", None)
    if isinstance(status, str):
        return status.lower() == "pass"
    return False


def _extract_run_id(record: Any) -> str | None:
    if isinstance(record, dict):
        rid = record.get("run_id")
        return str(rid) if rid is not None else None
    rid = getattr(record, "run_id", None)
    return str(rid) if rid is not None else None


__all__ = [
    "DEFAULT_N",
    "PassAtNResult",
    "check_pass_at_n",
]
