"""Plumbing-tier tests for VAL-V3M4-001..004 (per-class quality thresholds).

Covers:
  - VAL-V3M4-001: QualityReport.per_class dict[str, ClassMetrics]
    where ClassMetrics = {precision, recall, fpr, support_count}.
    Pre-populated with all 12 canonical HYPOTHESIS_CLASSES keys.
  - VAL-V3M4-002: P0_FAILURE_CLASSES constant enumerates the 7 keystone-
    failure classes. Recall >= 0.7 enforced per P0 class via
    `criteria_failed` field.
  - VAL-V3M4-003: Precision >= 0.6 enforced per P0 class.
  - VAL-V3M4-004: FPR <= 0.05 enforced at confidence >= 0.9 per P0 class.

Spec anchors:
  AJ 5739-5742   precision/recall/FPR thresholds

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from dataclasses import is_dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from relay_explain.heuristic import GENERATOR_ID, HeuristicV1Generator
from relay_explain.quality.harness import (
    P0_FAILURE_CLASSES,
    ClassMetrics,
    GroundTruthCase,
    QualityReport,
    evaluate_generator,
)
from relay_schemas.root_cause_hypothesis import HYPOTHESIS_CLASSES

_EXPECTED_P0 = frozenset(
    {
        "schema_contract_violation",
        "p0_assertion_failure",
        "side_effect_attempt_blocked",
        "evidence_pairing_missing",
        "manifest_anchor_mismatch",
        "gate_handoff_invalid",
        "three_anchor_handoff_invalid",
    }
)


def _deterministic_factory() -> Any:
    counter = {"n": 0}

    def _id() -> str:
        counter["n"] += 1
        return f"h-{counter['n']:08d}"

    return _id


def _make_gen() -> HeuristicV1Generator:
    return HeuristicV1Generator(
        now=lambda: datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        id_factory=_deterministic_factory(),
    )


# ---------------------------------------------------------------------------
# VAL-V3M4-002: P0_FAILURE_CLASSES enumeration
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-002")
def test_p0_failure_classes_enumerated_exactly() -> None:
    """P0_FAILURE_CLASSES is a frozenset containing exactly the 7
    keystone-failure class names per contract VAL-V3M4-002.
    """
    assert isinstance(P0_FAILURE_CLASSES, frozenset)
    assert P0_FAILURE_CLASSES == _EXPECTED_P0
    assert len(P0_FAILURE_CLASSES) == 7


# ---------------------------------------------------------------------------
# VAL-V3M4-001: QualityReport.per_class shape
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-001")
def test_class_metrics_dataclass_shape() -> None:
    """ClassMetrics carries precision, recall, fpr, support_count."""
    cm = ClassMetrics(precision=0.5, recall=0.6, fpr=0.01, support_count=10)
    assert is_dataclass(cm)
    assert cm.precision == 0.5
    assert cm.recall == 0.6
    assert cm.fpr == 0.01
    assert cm.support_count == 10


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-001")
def test_quality_report_per_class_field_present_and_covers_canonical_classes() -> None:
    """QualityReport.per_class is a dict[str, ClassMetrics] and is
    pre-populated for every canonical hypothesis_class so dashboards
    do not have to handle missing keys.
    """
    gen = _make_gen()
    cases: list[GroundTruthCase] = []
    # one TP case so the harness has something to evaluate
    cases.append(
        GroundTruthCase(
            case_id=str(uuid.uuid4()),
            run_id=str(uuid.uuid4()),
            spans=[],
            contract_results=[
                {
                    "contract_result_id": str(uuid.uuid4()),
                    "status": "fail",
                    "failure_kind": "schema_drift",
                }
            ],
            expected_class="schema_contract_drift",
        )
    )
    report = evaluate_generator(
        gen, cases, generator_id=GENERATOR_ID, confidence_threshold=0.5
    )
    assert isinstance(report, QualityReport)
    assert isinstance(report.per_class, dict)
    # All 12 canonical hypothesis_class keys appear (VAL-V3M4-001 evidence
    # bullet: "passing test asserting all 12 hypothesis_class keys appear").
    for class_name in HYPOTHESIS_CLASSES:
        assert class_name in report.per_class, (
            f"per_class missing canonical key {class_name!r}"
        )
        metrics = report.per_class[class_name]
        assert isinstance(metrics, ClassMetrics)
        assert 0.0 <= metrics.precision <= 1.0
        assert 0.0 <= metrics.recall <= 1.0
        assert 0.0 <= metrics.fpr <= 1.0
        assert metrics.support_count >= 0
    # schema_contract_drift saw exactly one supporting case.
    assert report.per_class["schema_contract_drift"].support_count == 1
    assert report.per_class["schema_contract_drift"].recall == 1.0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-001")
def test_quality_report_per_class_serializable() -> None:
    """QualityReport.to_dict() includes per_class as nested mapping."""
    gen = _make_gen()
    report = evaluate_generator(
        gen, [], generator_id=GENERATOR_ID, confidence_threshold=0.5
    )
    payload = report.to_dict()
    assert "per_class" in payload
    assert isinstance(payload["per_class"], dict)
    # nested entries are plain dicts (JSON-serializable)
    for v in payload["per_class"].values():
        assert isinstance(v, dict)
        assert {"precision", "recall", "fpr", "support_count"} <= set(v.keys())


# ---------------------------------------------------------------------------
# VAL-V3M4-002: recall >= 0.7 per P0 class enforced via criteria_failed
# ---------------------------------------------------------------------------


def _seed_p0_class_with_recall(
    class_name: str, hits: int, misses: int
) -> list[GroundTruthCase]:
    """Return cases labeled with the given P0 class. The heuristic
    generator does NOT emit P0 keystone classes, so every such case is
    a miss (false negative). To synthesize TPs we use a synthetic
    'oracle' generator in tests; for misses we pass to the real
    heuristic which will fail to match.
    """
    cases: list[GroundTruthCase] = []
    for _ in range(hits + misses):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=class_name,
            )
        )
    return cases


class _OracleGenerator:
    """Test-only generator: emits a single hypothesis with the configured
    ``hypothesis_class`` and ``confidence`` for every input. Used to
    drive deterministic per-class metric scenarios without coupling
    tests to heuristic.v1 behavior.
    """

    def __init__(
        self,
        hypothesis_class: str,
        confidence: float,
        emit_for: set[str] | None = None,
    ) -> None:
        self._class = hypothesis_class
        self._confidence = confidence
        # `emit_for` lets the oracle stay silent on selected case ids,
        # producing FN/TN paths in a controlled way.
        self._emit_for = emit_for

    def generate(
        self,
        run_id: str,
        spans: list[dict[str, Any]] | None,
        contract_results: list[dict[str, Any]] | None,
    ) -> list[Any]:
        if self._emit_for is not None and run_id not in self._emit_for:
            return []

        class _Draft:
            pass

        d = _Draft()
        d.hypothesis_class = self._class
        d.confidence = self._confidence
        return [d]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-002")
def test_recall_below_threshold_on_p0_class_flags_criteria_failed() -> None:
    """A generator that recalls 4/10 (0.4) on a P0 class trips the
    >=0.7 recall threshold and the failing class appears in
    ``QualityReport.criteria_failed``.
    """
    p0_class = "schema_contract_violation"
    # 10 cases labeled with the P0 class.
    cases: list[GroundTruthCase] = []
    case_run_ids: list[str] = []
    for _ in range(10):
        run_id = str(uuid.uuid4())
        case_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=p0_class,
            )
        )
    # Oracle emits only on first 4 -> recall = 0.4.
    oracle = _OracleGenerator(
        p0_class, confidence=0.95, emit_for=set(case_run_ids[:4])
    )
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.5
    )
    assert report.per_class[p0_class].recall == pytest.approx(0.4)
    assert any(
        entry.class_name == p0_class and entry.criterion == "recall"
        for entry in report.criteria_failed
    ), report.criteria_failed


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-002")
def test_recall_at_or_above_threshold_passes() -> None:
    """A generator that recalls 8/10 (0.8) on a P0 class does NOT trip
    the recall criterion.
    """
    p0_class = "p0_assertion_failure"
    cases: list[GroundTruthCase] = []
    case_run_ids: list[str] = []
    for _ in range(10):
        run_id = str(uuid.uuid4())
        case_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=p0_class,
            )
        )
    oracle = _OracleGenerator(
        p0_class, confidence=0.95, emit_for=set(case_run_ids[:8])
    )
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.5
    )
    assert report.per_class[p0_class].recall == pytest.approx(0.8)
    assert not any(
        entry.class_name == p0_class and entry.criterion == "recall"
        for entry in report.criteria_failed
    )


# ---------------------------------------------------------------------------
# VAL-V3M4-003: precision >= 0.6 per P0 class
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-003")
def test_precision_below_threshold_on_p0_class_flags_criteria_failed() -> None:
    """A generator emitting P0 class on clean cases drops precision
    below 0.6 and trips the criterion.
    """
    p0_class = "side_effect_attempt_blocked"
    # 2 TP + 8 FP -> precision = 0.2
    cases: list[GroundTruthCase] = []
    p0_run_ids: list[str] = []
    for _ in range(2):
        run_id = str(uuid.uuid4())
        p0_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=p0_class,
            )
        )
    for _ in range(8):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    # Oracle emits on every case -> 2 TP (the labeled cases) + 8 FP.
    oracle = _OracleGenerator(p0_class, confidence=0.95)
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.5
    )
    assert report.per_class[p0_class].precision == pytest.approx(0.2)
    assert any(
        entry.class_name == p0_class and entry.criterion == "precision"
        for entry in report.criteria_failed
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-003")
def test_precision_at_threshold_passes() -> None:
    """Precision = 0.6 exactly does NOT trip the criterion (>= 0.6)."""
    p0_class = "evidence_pairing_missing"
    cases: list[GroundTruthCase] = []
    # 6 TP + 4 FP -> precision = 0.6
    for _ in range(6):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=p0_class,
            )
        )
    for _ in range(4):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    oracle = _OracleGenerator(p0_class, confidence=0.95)
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.5
    )
    assert report.per_class[p0_class].precision == pytest.approx(0.6)
    assert not any(
        entry.class_name == p0_class and entry.criterion == "precision"
        for entry in report.criteria_failed
    )


# ---------------------------------------------------------------------------
# VAL-V3M4-004: FPR <= 0.05 at confidence >= 0.9 per P0 class
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-004")
def test_fpr_above_threshold_at_high_confidence_flags_criteria_failed() -> None:
    """At confidence_threshold=0.9, FPR > 0.05 trips criteria_failed."""
    p0_class = "manifest_anchor_mismatch"
    # 0 TP + 10 FP + 90 TN -> FPR = 10/100 = 0.1
    cases: list[GroundTruthCase] = []
    fp_run_ids: list[str] = []
    for _ in range(10):
        run_id = str(uuid.uuid4())
        fp_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    for _ in range(90):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    # Oracle emits with confidence 0.95 only on the first 10 cases ->
    # 10 FP at the high-confidence cutoff.
    oracle = _OracleGenerator(p0_class, confidence=0.95, emit_for=set(fp_run_ids))
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.9
    )
    assert report.per_class[p0_class].fpr == pytest.approx(0.1)
    assert any(
        entry.class_name == p0_class and entry.criterion == "fpr"
        for entry in report.criteria_failed
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-004")
def test_fpr_below_threshold_at_high_confidence_passes() -> None:
    """FPR = 0.05 at confidence >= 0.9 does NOT trip the criterion."""
    p0_class = "gate_handoff_invalid"
    # 5 FP + 95 TN at confidence_threshold=0.9 -> FPR = 5/100 = 0.05
    cases: list[GroundTruthCase] = []
    fp_run_ids: list[str] = []
    for _ in range(5):
        run_id = str(uuid.uuid4())
        fp_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    for _ in range(95):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    oracle = _OracleGenerator(p0_class, confidence=0.95, emit_for=set(fp_run_ids))
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.9
    )
    assert report.per_class[p0_class].fpr == pytest.approx(0.05)
    assert not any(
        entry.class_name == p0_class and entry.criterion == "fpr"
        for entry in report.criteria_failed
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-004")
def test_fpr_only_evaluated_above_confidence_cutoff() -> None:
    """A generator emitting low-confidence (0.5) FPs does NOT trip the
    high-confidence (>=0.9) FPR criterion because those drafts are
    filtered before metric evaluation.
    """
    p0_class = "three_anchor_handoff_invalid"
    fp_run_ids: list[str] = []
    cases: list[GroundTruthCase] = []
    for _ in range(50):
        run_id = str(uuid.uuid4())
        fp_run_ids.append(run_id)
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=run_id,
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    # Confidence 0.5 -> filtered out at confidence_threshold=0.9.
    oracle = _OracleGenerator(p0_class, confidence=0.5, emit_for=set(fp_run_ids))
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.9
    )
    assert report.per_class[p0_class].fpr == 0.0
    assert not any(
        entry.class_name == p0_class and entry.criterion == "fpr"
        for entry in report.criteria_failed
    )


# ---------------------------------------------------------------------------
# Spec line 5742 anchor: confidence>=0.9 cutoff applies per-class FPR
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-001", "VAL-V3M4-002", "VAL-V3M4-003", "VAL-V3M4-004")
def test_criteria_failed_lists_non_p0_class_only_when_outside_p0_set_is_skipped() -> (
    None
):
    """Thresholds apply ONLY to classes in P0_FAILURE_CLASSES. A non-P0
    class with poor metrics does NOT appear in ``criteria_failed``.
    """
    non_p0_class = "schema_contract_drift"  # in HYPOTHESIS_CLASSES but not P0
    # 1 TP + 9 FP -> precision 0.1; this is intentionally bad.
    cases: list[GroundTruthCase] = []
    cases.append(
        GroundTruthCase(
            case_id=str(uuid.uuid4()),
            run_id=str(uuid.uuid4()),
            spans=[],
            contract_results=[],
            expected_class=non_p0_class,
        )
    )
    for _ in range(9):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    oracle = _OracleGenerator(non_p0_class, confidence=0.95)
    report = evaluate_generator(
        oracle, cases, generator_id="oracle.test:v1", confidence_threshold=0.5
    )
    assert report.per_class[non_p0_class].precision == pytest.approx(0.1)
    # Non-P0 class never appears in criteria_failed.
    for entry in report.criteria_failed:
        assert entry.class_name != non_p0_class, (
            "thresholds must only apply to P0_FAILURE_CLASSES"
        )
