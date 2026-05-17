"""epochly-relay-explain: Explain pipeline primitives (M05 w5-explain).

Public re-exports for the package surface. Per CLAUDE.md keystone
invariant #1, the explain engine is the only writer of
``root_cause_hypotheses``; SDKs and CLIs may not bypass it.
"""

from __future__ import annotations

from relay_explain.engine import (
    DuplicateHypothesis,
    ExplainEngine,
    SpanNotOnRunError,
    canonical_evidence_refs_digest,
)
from relay_explain.heuristic import HeuristicV1Generator
from relay_explain.quality.harness import QualityReport, evaluate_generator

__all__ = [
    "DuplicateHypothesis",
    "ExplainEngine",
    "HeuristicV1Generator",
    "QualityReport",
    "SpanNotOnRunError",
    "canonical_evidence_refs_digest",
    "evaluate_generator",
]
