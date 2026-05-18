"""Heuristic v1 explain generator (M05 w5-explain; VAL-V2M05-018).

A deterministic, rule-based root-cause hypothesis generator. Consumes the
spans / contract_results / run metadata for a single run and emits zero or
more :class:`RootCauseHypothesisDraft` objects ready for ingestion by the
explain engine.

The heuristic generator is the lowest tier of the spec AJ generator
taxonomy (``heuristic.v1``). Its output is intentionally explainable:
every hypothesis cites the spans / contract_results that triggered it,
and confidence is bounded conservatively. The LLM-augmented generators
(``llm.<model>:vN``) live in a separate module and are out of scope for
M05 w5.

Spec anchors:
  T 4882         "generator role"
  AJ 5733-5746   generator taxonomy + thresholds

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from relay_schemas.root_cause_hypothesis import SCHEMA_VERSION

GENERATOR_ID = "heuristic.v1"


def _missing_now() -> str:
    """Default ``now`` factory; raises to enforce explicit injection.

    Spec AJ requires the heuristic generator to be deterministic given
    the same inputs. A ``datetime.now`` default would silently inject
    wall-clock entropy, defeating replay parity. Production callers
    MUST supply a run-id-derived deterministic timestamp.
    """
    raise RuntimeError(
        "HeuristicV1Generator(now=...) MUST be supplied explicitly. "
        "Spec AJ requires deterministic heuristic.v1 output; a wall-"
        "clock default would inject non-deterministic timestamps. "
        "Production callers must derive ``now`` from the run's clock "
        "(e.g., run_results.created_at) and pass it in."
    )


def _missing_id_factory() -> str:
    """Default ``id_factory``; raises to enforce explicit injection.

    A ``uuid.uuid4()`` default would inject non-deterministic
    hypothesis_ids that diverge between captured and replayed runs.
    Production callers MUST supply a run-id-derived deterministic id
    factory (e.g., a counter seeded by ``run_id``).
    """
    raise RuntimeError(
        "HeuristicV1Generator(id_factory=...) MUST be supplied "
        "explicitly. Spec AJ requires deterministic heuristic.v1 "
        "output; a uuid4 default would inject non-deterministic "
        "hypothesis_ids. Production callers must derive ``id_factory`` "
        "from a deterministic seed (e.g., run_id-namespaced uuid5 or "
        "a counter)."
    )


@dataclass(frozen=True)
class RootCauseHypothesisDraft:
    """A draft hypothesis emitted by a generator before engine ingestion.

    Validates against ``relay.root_cause_hypothesis.v1`` once converted to
    a dict via :meth:`to_payload`.
    """

    hypothesis_id: str
    run_id: str
    hypothesis_class: str
    confidence: float
    evidence_refs: list[dict[str, Any]]
    generator: str
    created_at: str
    span_id: str | None = None
    reviewer_email: str | None = None
    reviewer_decision: str | None = None
    promoted_to_replay_case_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": self.hypothesis_id,
            "run_id": self.run_id,
            "span_id": self.span_id,
            "hypothesis_class": self.hypothesis_class,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "generator": self.generator,
            "reviewer_email": self.reviewer_email,
            "reviewer_decision": self.reviewer_decision,
            "promoted_to_replay_case_id": self.promoted_to_replay_case_id,
            "created_at": self.created_at,
        }


@dataclass
class HeuristicV1Generator:
    """Rule-based hypothesis generator (generator id = ``heuristic.v1``).

    The generator is deterministic given the same inputs (same span list,
    same contract results, fixed ``now`` timestamp). Production callers
    MUST inject ``now`` and ``id_factory`` derived from a deterministic
    seed (e.g., the run's canonical clock and a run-id-namespaced UUID
    counter); the defaults raise ``RuntimeError`` to prevent silent
    non-determinism from a missed injection.
    """

    now: Callable[[], Any] = field(default=_missing_now)
    id_factory: Callable[[], str] = field(default=_missing_id_factory)

    def generate(
        self,
        run_id: str,
        spans: list[dict[str, Any]] | None,
        contract_results: list[dict[str, Any]] | None,
    ) -> list[RootCauseHypothesisDraft]:
        """Return the hypothesis draft list for one run.

        Inputs:
          - ``run_id``: the canonical UUID of the run being explained.
          - ``spans``: list of span rows (each with at minimum ``span_id``,
            ``span_type``, ``status``, optional ``error_class``).
          - ``contract_results``: list of contract_result rows (each with
            at minimum ``contract_result_id``, ``status``, optional
            ``assertion_id``, ``failure_kind``).

        Heuristics implemented in v1:

        1. **schema_contract_drift**: any contract_result with
           ``status == 'fail'`` and ``failure_kind == 'schema_drift'``
           emits a hypothesis bound to that result.
        2. **tool_arg_invalid**: any contract_result with
           ``failure_kind == 'tool_arg_invalid'`` emits a hypothesis
           bound to the result and (when available) the originating
           tool_call span.
        3. **rate_limit**: any span with ``error_class in
           {'rate_limit', 'RateLimitError', '429'}`` emits a hypothesis.
        4. **provider_drift**: any span with ``error_class ==
           'provider_drift'`` or ``status == 'provider_drift'`` emits a
           hypothesis.
        5. **unknown**: any contract_result with ``status == 'fail'`` and
           no matched failure_kind emits an ``unknown`` hypothesis with
           low confidence (0.30) so the surface keeps a row for human
           review.
        """
        spans = list(spans or [])
        contract_results = list(contract_results or [])
        drafts: list[RootCauseHypothesisDraft] = []
        emit_at = self.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        for result in contract_results:
            failure_kind = result.get("failure_kind")
            status = result.get("status")
            result_id = result.get("contract_result_id")
            if status != "fail" or result_id is None:
                continue
            ref = {"kind": "contract_result", "ref": f"contract_results:{result_id}"}
            if failure_kind == "schema_drift":
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="schema_contract_drift",
                        confidence=0.85,
                        evidence_refs=[ref],
                        created_at=emit_at,
                    )
                )
            elif failure_kind == "tool_arg_invalid":
                evidence = [ref]
                span_id = result.get("span_id")
                if span_id is not None:
                    evidence.append({"kind": "span", "ref": f"spans:{span_id}"})
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="tool_arg_invalid",
                        confidence=0.80,
                        evidence_refs=evidence,
                        created_at=emit_at,
                        span_id=str(span_id) if span_id is not None else None,
                    )
                )
            else:
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="unknown",
                        confidence=0.30,
                        evidence_refs=[ref],
                        created_at=emit_at,
                    )
                )

        for span in spans:
            error_class = span.get("error_class")
            span_id = span.get("span_id")
            if span_id is None:
                continue
            ref = {"kind": "span", "ref": f"spans:{span_id}"}
            if error_class in {"rate_limit", "RateLimitError", "429"}:
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="rate_limit",
                        confidence=0.90,
                        evidence_refs=[ref],
                        created_at=emit_at,
                        span_id=str(span_id),
                    )
                )
            elif error_class == "provider_drift" or span.get("status") == "provider_drift":
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="provider_drift",
                        confidence=0.70,
                        evidence_refs=[ref],
                        created_at=emit_at,
                        span_id=str(span_id),
                    )
                )

        return drafts

    def _make(
        self,
        *,
        run_id: str,
        hypothesis_class: str,
        confidence: float,
        evidence_refs: list[dict[str, Any]],
        created_at: str,
        span_id: str | None = None,
    ) -> RootCauseHypothesisDraft:
        return RootCauseHypothesisDraft(
            hypothesis_id=self.id_factory(),
            run_id=run_id,
            hypothesis_class=hypothesis_class,
            confidence=confidence,
            evidence_refs=evidence_refs,
            generator=GENERATOR_ID,
            created_at=created_at,
            span_id=span_id,
        )


__all__ = [
    "GENERATOR_ID",
    "HeuristicV1Generator",
    "RootCauseHypothesisDraft",
]
