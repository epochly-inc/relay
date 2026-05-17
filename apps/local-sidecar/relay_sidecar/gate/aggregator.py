"""Matrix CI aggregator gate (VAL-V2M08-018, 019).

Spec anchor: AI line 5721.

A release gate ``(gate_kind='release')`` waits for N matrix leg
decisions and writes exactly one parent ``gate_decisions`` row keyed
``(gate_id_parent, release_sha)``. The parent decision is ``accept``
only if every leg decision is ``accept``; otherwise the parent is
``reject`` with ``reason.failed_legs[]`` listing the offending leg
gate_ids in stable order.

While any leg is still pending (no recorded decision), the aggregator
returns ``None`` from :meth:`MatrixAggregator.compute_parent_decision`;
no parent row is written until every leg has reported. Repeated calls
after every leg has reported return the same :class:`ParentDecision`
(idempotent compute; the caller is responsible for ensuring only one
INSERT actually lands in ``gate_decisions``).

This module is pure: it does not write to the database itself. The
caller wraps the returned :class:`ParentDecision` in a
``transactional_db_write`` (atomic-persistence primitive #1) and the
``written_by='control_plane'`` invariant is enforced at the row-level
write boundary.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

GATE_KIND_RELEASE: Final[str] = "release"
WRITTEN_BY_CONTROL_PLANE: Final[str] = "control_plane"

_ACCEPT: Final[str] = "accept"
_REJECT: Final[str] = "reject"
_PENDING: Final[str] = "pending"


@dataclass(frozen=True)
class ParentDecision:
    """Structured parent gate decision (the row the caller persists).

    Fields mirror the canonical ``gate_decisions`` row shape:

    * ``gate_id`` -- the parent gate's stable id.
    * ``gate_kind`` -- always ``"release"`` for this aggregator.
    * ``release_sha`` -- the release SHA the matrix is gating.
    * ``decision`` -- ``"accept"`` or ``"reject"``.
    * ``written_by`` -- always ``"control_plane"`` (the aggregator is a
      control-plane component; the OSS sidecar exposes it via the
      hosted/local result-writer primitive, never via SDK).
    * ``reason`` -- structured payload; for reject decisions contains
      ``failed_legs`` (list of leg gate_ids).
    * ``leg_decisions`` -- echo of each leg's recorded decision in the
      same order as ``leg_ids`` for evidence linkage.
    """

    gate_id: str
    gate_kind: str
    release_sha: str
    decision: str
    written_by: str
    reason: dict[str, Any] | None
    leg_decisions: tuple[tuple[str, str], ...]


@dataclass
class MatrixAggregator:
    """In-memory aggregator over N matrix leg decisions.

    Construct with a fixed set of leg ids; record each leg's decision
    via :meth:`record_leg`; call :meth:`compute_parent_decision` to
    derive the parent gate's outcome. Pending legs cause
    ``compute_parent_decision`` to return ``None`` so the caller does
    not write a parent row prematurely.
    """

    release_sha: str
    leg_ids: tuple[str, ...]
    parent_gate_id: str
    _leg_state: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.release_sha:
            raise ValueError("release_sha MUST be a non-empty string")
        if not self.parent_gate_id:
            raise ValueError("parent_gate_id MUST be a non-empty string")
        if not self.leg_ids:
            raise ValueError("leg_ids MUST be a non-empty tuple")
        # Initialise every leg as pending so callers can introspect
        # state before recording any decisions.
        for leg_id in self.leg_ids:
            self._leg_state[leg_id] = _PENDING

    def record_leg(self, leg_id: str, decision: str) -> None:
        """Record ``decision`` for ``leg_id``.

        ``decision`` MUST be one of ``"accept"`` or ``"reject"``.
        Recording a decision for an unknown leg id raises
        :class:`KeyError`. Recording a second decision for the same
        leg overwrites the prior decision (callers should not do this;
        the canonical CI flow records each leg exactly once).
        """
        if decision not in (_ACCEPT, _REJECT):
            raise ValueError(
                f"decision MUST be 'accept' or 'reject', got {decision!r}"
            )
        if leg_id not in self._leg_state:
            raise KeyError(
                f"leg_id {leg_id!r} not in aggregator's leg_ids {self.leg_ids}"
            )
        self._leg_state[leg_id] = decision

    def compute_parent_decision(self) -> ParentDecision | None:
        """Return the parent :class:`ParentDecision` or ``None``.

        Returns ``None`` while any leg is still ``pending``. Returns a
        :class:`ParentDecision` with ``decision="accept"`` when every
        leg is ``accept``; otherwise returns a :class:`ParentDecision`
        with ``decision="reject"`` and ``reason["failed_legs"]`` listing
        the offending leg gate_ids in the same order as ``leg_ids``.

        Repeated calls return an equivalent :class:`ParentDecision`
        (the dataclass is frozen so two calls produce two equal
        instances).
        """
        # Stable iteration order matches leg_ids so failed_legs and
        # leg_decisions are deterministic across pytest reruns.
        leg_decisions: list[tuple[str, str]] = [
            (leg_id, self._leg_state[leg_id]) for leg_id in self.leg_ids
        ]
        if any(state == _PENDING for _, state in leg_decisions):
            return None
        failed = [leg_id for leg_id, state in leg_decisions if state == _REJECT]
        if failed:
            return ParentDecision(
                gate_id=self.parent_gate_id,
                gate_kind=GATE_KIND_RELEASE,
                release_sha=self.release_sha,
                decision=_REJECT,
                written_by=WRITTEN_BY_CONTROL_PLANE,
                reason={"failed_legs": failed},
                leg_decisions=tuple(leg_decisions),
            )
        return ParentDecision(
            gate_id=self.parent_gate_id,
            gate_kind=GATE_KIND_RELEASE,
            release_sha=self.release_sha,
            decision=_ACCEPT,
            written_by=WRITTEN_BY_CONTROL_PLANE,
            reason=None,
            leg_decisions=tuple(leg_decisions),
        )


__all__ = [
    "GATE_KIND_RELEASE",
    "WRITTEN_BY_CONTROL_PLANE",
    "MatrixAggregator",
    "ParentDecision",
]
