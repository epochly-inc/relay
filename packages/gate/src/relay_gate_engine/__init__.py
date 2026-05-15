"""Relay gate evaluation pipeline (Python; W8.1).

Public surface for w8.1:

- :class:`GateEvaluator` -- the deterministic three-gate evaluator that
  consumes a :class:`GateDecisionDraft` and produces a
  :class:`DraftOutcome`. Conditions on each gate's policy are evaluated
  through the W6 :class:`relay_contracts.RelayCelEvaluator`; assertions
  are sorted ``P0 > P1 > P2 > P3`` and short-circuit on the first failing
  P0 when ``cascade_on_block`` is true (VAL-W8-004). Pipeline order is
  fixed scrutiny -> structural-review -> testing (VAL-W8-001).
- :class:`GatePipeline` -- the three-gate orchestrator that enforces
  fixed evaluation order across rounds.
- :class:`DraftLock` -- the in-memory concurrent-draft conflict guard
  keyed on ``(gate_id, scope_type, scope_id, round)``; second submitter
  receives ``RELAY-GATE-014`` per VAL-W8-007.
- :class:`AntiBypassGuard` -- W2.5 mirror; refuses drafts whose declared
  command (resolved via the manifest's ``command_hash -> command_line``
  map) contains any banned bypass flag (VAL-W8-041).
- :func:`is_draft_expired` -- TTL helper (VAL-W8-006).
- Provider protocols :class:`EvidenceBundleProvider`,
  :class:`ManifestCommandResolver`, :class:`AssertionLoader` -- the gate
  engine consumes evidence by id (VAL-W8-003), commands by hash
  (CLAUDE.md keystone invariant 3), and assertions by id; concrete
  storage backends land in W8.2.

Spec anchors: A.2 / A.3 / A.4 / A.5, C, D.3, K.
Eng plan anchors: W8 (line 382), Lane D (line 398).
CLAUDE.md anchors: keystone invariants 1, 2, 4, 5; banned pattern 8;
the gate-decision-ownership / gate-restart / stale-handoff /
evidence-pairing / manifest-source-of-truth / anti-bypass guard tests.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .draft_lock import DraftLock, DraftLockConflictError
from .errors import (
    AntiBypassRejectedError,
    DraftTtlExpiredError,
    GateEngineError,
    GateOrderingError,
    StaleHandoffError,
)
from .evaluator import (
    BANNED_BYPASS_TOKENS,
    AntiBypassGuard,
    AssertionLoader,
    DraftOutcome,
    EvidenceBundleProvider,
    GateAssertion,
    GateEvaluator,
    GatePolicy,
    ManifestCommandResolver,
    is_draft_expired,
)
from .pipeline import (
    GATE_ORDER,
    GateDecisionDraft,
    GateName,
    GatePipeline,
    PipelineResult,
)

__all__ = [
    "AntiBypassGuard",
    "AntiBypassRejectedError",
    "AssertionLoader",
    "BANNED_BYPASS_TOKENS",
    "DraftLock",
    "DraftLockConflictError",
    "DraftOutcome",
    "DraftTtlExpiredError",
    "EvidenceBundleProvider",
    "GATE_ORDER",
    "GateAssertion",
    "GateDecisionDraft",
    "GateEngineError",
    "GateEvaluator",
    "GateName",
    "GateOrderingError",
    "GatePipeline",
    "GatePolicy",
    "ManifestCommandResolver",
    "PipelineResult",
    "StaleHandoffError",
    "is_draft_expired",
]
