"""Three-gate pipeline orchestrator for w8.1 (VAL-W8-001).

The pipeline enforces the fixed evaluation order
``scrutiny -> structural-review -> testing`` and records the per-gate
:class:`DraftOutcome` records into a :class:`PipelineResult`.

Per VAL-W8-001:

  - Calling ``run_gate("structural-review", ...)`` before
    ``run_gate("scrutiny", ...)`` has produced an ``accept`` decision
    for the current round MUST raise :class:`GateOrderingError`.
  - Calling ``run_gate("testing", ...)`` before
    ``run_gate("structural-review", ...)`` has produced an ``accept``
    decision for the current round MUST raise the same error.
  - Re-running an already-accepted gate is rejected with the same error
    (one decision per (gate, round) per VAL-W8-007 / spec A.4 unique
    constraint).

The pipeline is round-scoped: a fresh :class:`GatePipeline` is
constructed per ``(scope_type, scope_id, round)`` triple. The
gate-restart-on-failure rule (CLAUDE.md keystone invariant 5; VAL-W8-020
in W8.3) is implemented by allocating a NEW pipeline at round N+1 with
``restart_predecessor`` pointing at round N's gate_round_id; w8.1 does
not own restart -- w8.3 does.

The :class:`GateDecisionDraft` dataclass mirrors the
``relay.gate_decision_draft.v1`` envelope at packages/schemas/raw/
envelopes.yaml lines 122-182 for the fields w8.1 consumes. The full
persistent envelope (with ``draft_kind``, ``resolution_state``, and
``cancelled_at`` lifecycle columns) lands in W8.2.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Hashable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal

from .draft_lock import DraftLock
from .errors import GateOrderingError
from .evaluator import (
    DraftOutcome,
    GateEvaluator,
    GatePolicy,
)

# ----------------------------------------------------------------------------
# Pipeline gate names (canonical, ordered).
# ----------------------------------------------------------------------------

GateName = Literal["scrutiny", "structural-review", "testing"]

GATE_ORDER: Final[tuple[GateName, ...]] = (
    "scrutiny",
    "structural-review",
    "testing",
)


# ----------------------------------------------------------------------------
# Draft envelope (w8.1 view).
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class GateDecisionDraft:
    """Submitter-facing draft envelope (w8.1 fields).

    Mirrors :ref:`relay.gate_decision_draft.v1` at
    ``packages/schemas/raw/envelopes.yaml`` lines 122-182 for the
    subset w8.1 consumes. The W8.2 persistence layer wraps this with
    ``draft_kind``, ``resolution_state``, ``cancelled_at``, etc.

    ``command_hash`` is the manifest-resolved command hash for the
    command that produced the evidence -- the worker MUST submit the
    hash, not the raw command line. Per CLAUDE.md keystone invariant 3,
    the engine refuses any hash not declared in the active manifest
    (raises :class:`StaleHandoffError`).
    """

    draft_id: Hashable
    gate_id: Hashable
    scope_type: str
    scope_id: Hashable
    round: int
    worker_id: Hashable
    actor_identity_hash: str
    manifest_commit_hash: str
    command_hash: str
    submitted_at: datetime
    evidence_refs: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.round, int) or self.round < 1:
            raise ValueError(
                f"GateDecisionDraft.round MUST be a positive int (>= 1); "
                f"got {self.round!r}"
            )
        if not isinstance(self.scope_type, str) or not self.scope_type:
            raise ValueError(
                f"GateDecisionDraft.scope_type MUST be a non-empty string; "
                f"got {self.scope_type!r}"
            )
        if not isinstance(self.actor_identity_hash, str) or not self.actor_identity_hash:
            raise ValueError(
                "GateDecisionDraft.actor_identity_hash MUST be a non-empty str"
            )
        if not isinstance(self.manifest_commit_hash, str) or not self.manifest_commit_hash:
            raise ValueError(
                "GateDecisionDraft.manifest_commit_hash MUST be a non-empty str"
            )
        if not isinstance(self.command_hash, str) or not self.command_hash:
            raise ValueError(
                "GateDecisionDraft.command_hash MUST be a non-empty str"
            )
        if not isinstance(self.submitted_at, datetime):
            raise ValueError(
                f"GateDecisionDraft.submitted_at MUST be a datetime; "
                f"got {type(self.submitted_at).__name__}"
            )


# ----------------------------------------------------------------------------
# Pipeline result aggregator.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineResult:
    """Aggregate result of a three-gate pipeline run for one round.

    ``outcomes`` is in evaluation order (scrutiny first). ``finished``
    is True only when all three gates have produced an ``accept``
    decision; partial pipelines (a gate returned ``block`` or
    ``remediate``) are reflected by ``finished=False`` and ``outcomes``
    of length < 3.
    """

    scope_type: str
    scope_id: str
    round: int
    outcomes: tuple[DraftOutcome, ...] = ()
    finished: bool = False

    @property
    def gate_order(self) -> tuple[str, ...]:
        return tuple(o.gate_name for o in self.outcomes)


# ----------------------------------------------------------------------------
# The pipeline.
# ----------------------------------------------------------------------------


class GatePipeline:
    """Three-gate pipeline orchestrator for one ``(scope, round)`` pair.

    Instantiated per round. ``run_gate`` enforces the fixed order; the
    aggregate :class:`PipelineResult` is rebuilt on every call so the
    instance is thread-confined to the controller (the gate engine
    service in W8.2). Multiple concurrent pipelines for different
    rounds / scopes are independent instances.
    """

    def __init__(
        self,
        *,
        scope_type: str,
        scope_id: Hashable,
        round: int,
        evaluator: GateEvaluator,
        draft_lock: DraftLock | None = None,
    ) -> None:
        if not isinstance(round, int) or round < 1:
            raise ValueError(
                f"GatePipeline.round MUST be a positive int (>= 1); "
                f"got {round!r}"
            )
        self._scope_type = scope_type
        self._scope_id = scope_id
        self._round = round
        self._evaluator = evaluator
        self._draft_lock = draft_lock or DraftLock()
        self._outcomes_by_gate: dict[GateName, DraftOutcome] = {}

    # --- Public API ---------------------------------------------------

    @property
    def draft_lock(self) -> DraftLock:
        """The lock used to enforce VAL-W8-007 concurrent-draft conflict."""
        return self._draft_lock

    def run_gate(
        self,
        *,
        gate_name: GateName,
        gate: GatePolicy,
        draft: GateDecisionDraft,
        now: datetime,
        evaluator_bindings: Mapping[str, Any] | None = None,
    ) -> DraftOutcome:
        """Evaluate a single gate, enforcing the fixed pipeline order.

        Order: scrutiny -> structural-review -> testing. A call out of
        order raises :class:`GateOrderingError` with the canonical
        ``RELAY-GATE-001`` envelope.
        """
        self._check_pipeline_alignment(gate_name=gate_name, gate=gate, draft=draft)
        self._check_order(gate_name)

        # Acquire the draft lock for this (gate, scope, round) to enforce
        # VAL-W8-007 in-process. The W8.2 persistent guard is the
        # cross-process source of truth; this fast path catches same-
        # process races before the database round-trip.
        self._draft_lock.acquire(
            gate_id=draft.gate_id,
            scope_type=draft.scope_type,
            scope_id=draft.scope_id,
            round=draft.round,
            worker_id=draft.worker_id,
            draft_id=draft.draft_id,
        )
        try:
            outcome = self._evaluator.evaluate(
                gate=gate,
                draft=draft,
                now=now,
                evaluator_bindings=evaluator_bindings,
            )
        finally:
            self._draft_lock.release(
                gate_id=draft.gate_id,
                scope_type=draft.scope_type,
                scope_id=draft.scope_id,
                round=draft.round,
                worker_id=draft.worker_id,
            )

        if outcome.action == "accept":
            self._outcomes_by_gate[gate_name] = outcome
        return outcome

    def result(self) -> PipelineResult:
        """Return the aggregate :class:`PipelineResult` for this round."""
        outcomes_in_order = tuple(
            self._outcomes_by_gate[g]
            for g in GATE_ORDER
            if g in self._outcomes_by_gate
        )
        finished = len(outcomes_in_order) == len(GATE_ORDER) and all(
            o.action == "accept" for o in outcomes_in_order
        )
        return PipelineResult(
            scope_type=self._scope_type,
            scope_id=str(self._scope_id),
            round=self._round,
            outcomes=outcomes_in_order,
            finished=finished,
        )

    # --- Internals ----------------------------------------------------

    def _check_pipeline_alignment(
        self,
        *,
        gate_name: GateName,
        gate: GatePolicy,
        draft: GateDecisionDraft,
    ) -> None:
        """Ensure the gate name + draft scope + round match this pipeline.

        A pipeline is round-scoped; calling ``run_gate`` with a draft
        whose ``round`` differs from this pipeline's round is a
        programmer bug -- it indicates the caller created the wrong
        pipeline instance for the draft. Surface loudly.
        """
        if gate.gate_name != gate_name:
            raise GateOrderingError(
                f"gate_name argument {gate_name!r} does not match "
                f"GatePolicy.gate_name {gate.gate_name!r}",
                payload={
                    "expected_gate_name": gate_name,
                    "policy_gate_name": gate.gate_name,
                },
            )
        if draft.scope_type != self._scope_type:
            raise GateOrderingError(
                f"draft.scope_type {draft.scope_type!r} does not match "
                f"pipeline.scope_type {self._scope_type!r}",
                payload={
                    "pipeline_scope_type": self._scope_type,
                    "draft_scope_type": draft.scope_type,
                },
            )
        if draft.round != self._round:
            raise GateOrderingError(
                f"draft.round {draft.round} does not match pipeline.round "
                f"{self._round}",
                payload={
                    "pipeline_round": self._round,
                    "draft_round": draft.round,
                },
            )

    def _check_order(self, gate_name: GateName) -> None:
        """Reject out-of-order or duplicate calls."""
        if gate_name not in GATE_ORDER:
            raise GateOrderingError(
                f"unknown gate name {gate_name!r}; pipeline gates are "
                f"{list(GATE_ORDER)}",
                payload={"gate_name": gate_name, "expected": list(GATE_ORDER)},
            )
        # Reject re-run of an already-accepted gate.
        if gate_name in self._outcomes_by_gate:
            raise GateOrderingError(
                f"gate {gate_name!r} has already produced an accept "
                f"decision in this round; one decision per (gate, round)",
                payload={
                    "gate_name": gate_name,
                    "round": self._round,
                },
            )
        # Enforce the fixed order: every prior gate must be accepted.
        idx = GATE_ORDER.index(gate_name)
        for prior in GATE_ORDER[:idx]:
            if prior not in self._outcomes_by_gate:
                raise GateOrderingError(
                    f"cannot run {gate_name!r} before {prior!r} has "
                    f"produced an accept decision in round {self._round}",
                    payload={
                        "expected_prior_gate": prior,
                        "attempted_gate": gate_name,
                        "round": self._round,
                        "pipeline_order": list(GATE_ORDER),
                    },
                )


__all__ = [
    "GATE_ORDER",
    "GateDecisionDraft",
    "GateName",
    "GatePipeline",
    "PipelineResult",
]
