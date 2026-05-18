"""Audit R3 P1 misc fixes -- explain heuristic determinism.

Covers:
  * BUG-E5  HeuristicV1Generator MUST refuse to construct with implicit
            non-deterministic ``now``/``id_factory`` defaults. Production
            callers MUST supply deterministic seeds; the sentinel defaults
            raise ``RuntimeError`` on use.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_explain.heuristic import HeuristicV1Generator


@pytest.mark.plumbing
def test_heuristic_default_now_raises_on_use() -> None:
    """Calling generate() without injecting ``now`` MUST raise.

    The default sentinel raises a structured RuntimeError so callers
    are forced to supply a deterministic timestamp source (spec AJ).
    """
    gen = HeuristicV1Generator(id_factory=lambda: "id-deterministic")
    with pytest.raises(RuntimeError, match="now=...") as excinfo:
        gen.generate(
            run_id="run-1",
            spans=[],
            contract_results=[
                {
                    "contract_result_id": "cr1",
                    "status": "fail",
                    "failure_kind": "schema_drift",
                }
            ],
        )
    assert "deterministic" in str(excinfo.value).lower()


@pytest.mark.plumbing
def test_heuristic_default_id_factory_raises_on_use() -> None:
    """Calling generate() without injecting ``id_factory`` MUST raise.

    A uuid4 default would inject non-deterministic hypothesis_ids that
    diverge between captured and replayed runs.
    """
    from datetime import UTC, datetime

    gen = HeuristicV1Generator(
        now=lambda: datetime(2026, 5, 18, tzinfo=UTC),
    )
    with pytest.raises(RuntimeError, match="id_factory=...") as excinfo:
        gen.generate(
            run_id="run-1",
            spans=[],
            contract_results=[
                {
                    "contract_result_id": "cr1",
                    "status": "fail",
                    "failure_kind": "schema_drift",
                }
            ],
        )
    assert "deterministic" in str(excinfo.value).lower()


@pytest.mark.plumbing
def test_heuristic_explicit_injection_works() -> None:
    """When both fields are supplied, generate() is deterministic."""
    counter = {"n": 0}

    def _id() -> str:
        counter["n"] += 1
        return f"id-{counter['n']}"

    from datetime import UTC, datetime

    fixed_now = datetime(2026, 5, 18, 0, 0, 0, tzinfo=UTC)
    gen = HeuristicV1Generator(
        now=lambda: fixed_now,
        id_factory=_id,
    )
    drafts = gen.generate(
        run_id="run-1",
        spans=[],
        contract_results=[
            {
                "contract_result_id": "cr1",
                "status": "fail",
                "failure_kind": "schema_drift",
            }
        ],
    )
    assert len(drafts) == 1
    assert drafts[0].hypothesis_id == "id-1"
    assert drafts[0].created_at == "2026-05-18T00:00:00Z"
    assert drafts[0].hypothesis_class == "schema_contract_drift"
