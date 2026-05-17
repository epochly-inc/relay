"""Generator quality harness (M05 w5-explain; VAL-V2M05-026).

Computes precision, recall, and false-positive rate (FPR) for a Relay
explain generator against a labeled ground-truth corpus.

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

Metrics:
  precision = TP / (TP + FP)
  recall    = TP / (TP + FN)
  FPR       = FP / (FP + TN)
  (denominators of 0 produce a metric value of 0.0 to avoid ZeroDivisionError)

Spec anchors:
  AJ 5739-5741   precision >= 0.6, recall >= 0.7 on P0, FPR <= 0.05 at confidence >= 0.9

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


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
    hypothesis_class values.
    """

    case_id: str
    run_id: str
    spans: list[dict[str, Any]]
    contract_results: list[dict[str, Any]]
    expected_class: str | None


@dataclass(frozen=True)
class QualityReport:
    """Output of :func:`evaluate_generator`.

    ``generator_id`` mirrors the generator's wire-format id (e.g.
    ``heuristic.v1``). All metric values are floats in ``[0, 1]``.
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
    """
    if not 0.0 <= confidence_threshold <= 1.0:
        raise ValueError(
            f"confidence_threshold {confidence_threshold} not in [0, 1]"
        )
    tp = fp = fn = tn = 0
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
        expected = case.expected_class
        if expected is None:
            if qualifying:
                fp += 1
            else:
                tn += 1
            continue
        match = any(
            str(getattr(d, "hypothesis_class", "")) == expected for d in qualifying
        )
        if match:
            tp += 1
        else:
            fn += 1
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
    )


__all__ = [
    "GroundTruthCase",
    "QualityReport",
    "evaluate_generator",
]
