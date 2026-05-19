"""Generator quality harness (M05 w5-explain; VAL-V2M05-026, VAL-V3M4-001..004).

Computes per-class precision, recall, and false-positive rate (FPR) for a
Relay explain generator against a labeled ground-truth corpus, and enforces
the spec AJ acceptance thresholds per enumerated P0 failure class.

A ground-truth case is a tuple of (inputs, expected hypothesis_class).
The generator under test is called once per case; the returned drafts are
compared against the expected class using a per-case "best-match"
strategy:

  - True positive  (TP): generator emitted a hypothesis whose
    ``hypothesis_class`` equals the expected class with
    ``confidence >= confidence_threshold``.
  - False negative (FN): the case has an expected class but no qualifying
    draft matched it.
  - False positive (FP): the generator emitted at least one qualifying
    draft for a case whose expected class is ``None`` (i.e. clean case).
  - True negative  (TN): expected class is ``None`` and the generator
    emitted no qualifying drafts.

Per-class accounting (VAL-V3M4-001): we additionally bucket TP/FP/FN/TN
by hypothesis_class so the harness can surface per-class metrics. The
per-class FP bucket counts cases where the generator emitted that class
on a clean (expected=None) case. The per-class FN bucket counts cases
labeled with that class for which no qualifying draft of that class was
emitted. The per-class TN bucket counts clean cases where the generator
did not emit that class.

Threshold enforcement (VAL-V3M4-002..004) is restricted to
``P0_FAILURE_CLASSES``: the 7 keystone-failure classes per
contract.md::VAL-V3M4-002.

Metrics:
  precision = TP / (TP + FP)
  recall    = TP / (TP + FN)
  FPR       = FP / (FP + TN)
  (denominators of 0 produce a metric value of 0.0 to avoid ZeroDivisionError)

Spec anchors:
  AJ 5739-5741   precision >= 0.6, recall >= 0.7 on P0, FPR <= 0.05 at confidence >= 0.9
  AJ 5742        FPR cutoff applies at confidence >= 0.9

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from relay_schemas.root_cause_hypothesis import HYPOTHESIS_CLASSES

# ---------------------------------------------------------------------------
# Spec AJ thresholds (literal constants from spec lines 5739-5742).
# ---------------------------------------------------------------------------

RECALL_THRESHOLD_P0: float = 0.7
PRECISION_THRESHOLD_P0: float = 0.6
FPR_THRESHOLD_P0: float = 0.05
FPR_CONFIDENCE_CUTOFF: float = 0.9

# ---------------------------------------------------------------------------
# P0 failure classes (VAL-V3M4-002 enumeration).
#
# Per contract.md VAL-V3M4-002, these 7 keystone-failure classes carry the
# AJ acceptance thresholds. They are intentionally distinct from the
# 12 canonical ``HYPOTHESIS_CLASSES`` enum values (which represent observed
# hypothesis_class output) and may appear as labels in ground-truth corpora
# even when the heuristic.v1 generator cannot emit them.
# ---------------------------------------------------------------------------

P0_FAILURE_CLASSES: frozenset[str] = frozenset(
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


class _GeneratorLike(Protocol):
    """Subset of HeuristicV1Generator used by the harness."""

    def generate(
        self,
        run_id: str,
        spans: list[dict[str, Any]] | None,
        contract_results: list[dict[str, Any]] | None,
    ) -> list[Any]:
        ...


@dataclass(frozen=True)
class GroundTruthCase:
    """A single labeled case used by the quality harness.

    ``expected_class`` is ``None`` for a "clean" case (no hypothesis
    should be raised); otherwise it is one of the 12 canonical
    hypothesis_class values or a P0 failure-class label.
    """

    case_id: str
    run_id: str
    spans: list[dict[str, Any]]
    contract_results: list[dict[str, Any]]
    expected_class: str | None


@dataclass(frozen=True)
class ClassMetrics:
    """Per-class metrics bucket.

    All metric values are floats in ``[0, 1]``. ``support_count`` is the
    number of ground-truth cases whose ``expected_class`` matched this
    class (i.e. the recall denominator).
    """

    precision: float
    recall: float
    fpr: float
    support_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "fpr": self.fpr,
            "support_count": self.support_count,
        }


@dataclass(frozen=True)
class CriteriaFailure:
    """A single criterion failure surfaced by the harness.

    Emitted when a P0 failure class violates one of the AJ thresholds
    (recall < 0.7, precision < 0.6, FPR > 0.05 at confidence >= 0.9).
    """

    class_name: str
    criterion: str  # "recall" | "precision" | "fpr"
    observed: float
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_name": self.class_name,
            "criterion": self.criterion,
            "observed": self.observed,
            "threshold": self.threshold,
        }


@dataclass(frozen=True)
class QualityReport:
    """Output of :func:`evaluate_generator`.

    ``generator_id`` mirrors the generator's wire-format id (e.g.
    ``heuristic.v1``). Aggregate metric values are floats in ``[0, 1]``.

    ``per_class`` maps each hypothesis_class (canonical + any label seen
    in the corpus + every ``P0_FAILURE_CLASSES`` entry) to a
    :class:`ClassMetrics` bucket. Keys for the 12 canonical
    ``HYPOTHESIS_CLASSES`` are always present so downstream consumers
    don't have to defend against missing keys.

    ``criteria_failed`` lists every P0-class threshold violation. An
    empty list means the generator meets spec AJ acceptance criteria.
    """

    generator_id: str
    n_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    confidence_threshold: float
    per_class: dict[str, ClassMetrics] = field(default_factory=dict)
    criteria_failed: list[CriteriaFailure] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generator_id": self.generator_id,
            "n_cases": self.n_cases,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "confidence_threshold": self.confidence_threshold,
            "per_class": {
                name: metrics.to_dict() for name, metrics in self.per_class.items()
            },
            "criteria_failed": [
                entry.to_dict() for entry in self.criteria_failed
            ],
        }


def _safe_div(num: float, denom: float) -> float:
    return float(num) / float(denom) if denom else 0.0


def evaluate_generator(
    generator: _GeneratorLike,
    ground_truth_cases: list[GroundTruthCase],
    *,
    generator_id: str,
    confidence_threshold: float = 0.5,
) -> QualityReport:
    """Run ``generator`` over ``ground_truth_cases`` and return metrics.

    The harness does not mutate any input. It is safe to call repeatedly
    with the same fixture corpus.

    Threshold enforcement (per VAL-V3M4-002..004) populates
    ``QualityReport.criteria_failed`` only for classes in
    ``P0_FAILURE_CLASSES``. The FPR criterion (VAL-V3M4-004) is only
    evaluated when ``confidence_threshold >= FPR_CONFIDENCE_CUTOFF``
    (spec line 5742: "at confidence >= 0.9").
    """
    if not 0.0 <= confidence_threshold <= 1.0:
        raise ValueError(
            f"confidence_threshold {confidence_threshold} not in [0, 1]"
        )

    # Aggregate counts (unchanged from V2M05-026 semantics).
    tp = fp = fn = tn = 0

    # Per-class counts. Keys are seeded with all canonical HYPOTHESIS_CLASSES
    # and every P0_FAILURE_CLASSES entry so the resulting per_class dict
    # always covers both sets, even when the corpus is empty.
    class_tp: dict[str, int] = {}
    class_fp: dict[str, int] = {}
    class_fn: dict[str, int] = {}
    class_tn: dict[str, int] = {}
    seeded: set[str] = set(HYPOTHESIS_CLASSES) | set(P0_FAILURE_CLASSES)
    for c in seeded:
        class_tp[c] = 0
        class_fp[c] = 0
        class_fn[c] = 0
        class_tn[c] = 0

    def _touch(class_name: str) -> None:
        if class_name not in class_tp:
            class_tp[class_name] = 0
            class_fp[class_name] = 0
            class_fn[class_name] = 0
            class_tn[class_name] = 0

    for case in ground_truth_cases:
        drafts = generator.generate(
            run_id=case.run_id,
            spans=case.spans,
            contract_results=case.contract_results,
        )
        qualifying = [
            d
            for d in drafts
            if float(getattr(d, "confidence", 0.0)) >= confidence_threshold
        ]
        emitted_classes = {
            str(getattr(d, "hypothesis_class", "")) for d in qualifying
        }
        # Ensure every emitted class has a per-class bucket.
        for ec in emitted_classes:
            _touch(ec)

        expected = case.expected_class
        if expected is None:
            # Aggregate FP/TN: any qualifying draft -> FP, else TN.
            if qualifying:
                fp += 1
            else:
                tn += 1
            # Per-class: every class that was emitted counts as a FP for
            # that class. Every class that was NOT emitted counts as a
            # TN for that class. We iterate over the union of seeded
            # classes and emitted classes so newly seen classes are
            # represented.
            for c in set(class_tp.keys()) | emitted_classes:
                if c in emitted_classes:
                    class_fp[c] += 1
                else:
                    class_tn[c] += 1
            continue

        # Expected != None: aggregate TP/FN by best-match.
        _touch(expected)
        match = expected in emitted_classes
        if match:
            tp += 1
            class_tp[expected] += 1
        else:
            fn += 1
            class_fn[expected] += 1
        # Per-class FP for classes other than the expected one that were
        # emitted (the generator over-fired on a labeled case).
        for c in emitted_classes:
            if c != expected:
                class_fp[c] += 1
        # Per-class TN for classes that were not emitted and are not the
        # expected class (the generator correctly stayed silent on them).
        for c in set(class_tp.keys()) - emitted_classes - {expected}:
            class_tn[c] += 1

    # Assemble per_class dict.
    per_class: dict[str, ClassMetrics] = {}
    for c in class_tp:
        ctp = class_tp[c]
        cfp = class_fp[c]
        cfn = class_fn[c]
        ctn = class_tn[c]
        per_class[c] = ClassMetrics(
            precision=_safe_div(ctp, ctp + cfp),
            recall=_safe_div(ctp, ctp + cfn),
            fpr=_safe_div(cfp, cfp + ctn),
            support_count=ctp + cfn,
        )

    # Threshold enforcement: P0 classes only.
    criteria_failed: list[CriteriaFailure] = []
    for c in sorted(P0_FAILURE_CLASSES):
        metrics = per_class.get(c)
        if metrics is None:
            continue
        # Recall criterion (VAL-V3M4-002): only meaningful when there is
        # at least one labeled case for this class.
        if metrics.support_count > 0 and metrics.recall < RECALL_THRESHOLD_P0:
            criteria_failed.append(
                CriteriaFailure(
                    class_name=c,
                    criterion="recall",
                    observed=metrics.recall,
                    threshold=RECALL_THRESHOLD_P0,
                )
            )
        # Precision criterion (VAL-V3M4-003): only meaningful when the
        # generator emitted at least one qualifying draft of this class.
        if (class_tp[c] + class_fp[c]) > 0 and metrics.precision < PRECISION_THRESHOLD_P0:
            criteria_failed.append(
                CriteriaFailure(
                    class_name=c,
                    criterion="precision",
                    observed=metrics.precision,
                    threshold=PRECISION_THRESHOLD_P0,
                )
            )
        # FPR criterion (VAL-V3M4-004): only evaluated at high confidence
        # cutoff per spec line 5742.
        if (
            confidence_threshold >= FPR_CONFIDENCE_CUTOFF
            and metrics.fpr > FPR_THRESHOLD_P0
        ):
            criteria_failed.append(
                CriteriaFailure(
                    class_name=c,
                    criterion="fpr",
                    observed=metrics.fpr,
                    threshold=FPR_THRESHOLD_P0,
                )
            )

    return QualityReport(
        generator_id=generator_id,
        n_cases=len(ground_truth_cases),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=_safe_div(tp, tp + fp),
        recall=_safe_div(tp, tp + fn),
        false_positive_rate=_safe_div(fp, fp + tn),
        confidence_threshold=confidence_threshold,
        per_class=per_class,
        criteria_failed=criteria_failed,
    )


__all__ = [
    "ClassMetrics",
    "CriteriaFailure",
    "FPR_CONFIDENCE_CUTOFF",
    "FPR_THRESHOLD_P0",
    "GroundTruthCase",
    "P0_FAILURE_CLASSES",
    "PRECISION_THRESHOLD_P0",
    "QualityReport",
    "RECALL_THRESHOLD_P0",
    "evaluate_generator",
]
