"""Gate remediation circuit breaker (W8.4).

Implements CLAUDE.md keystone invariant #5 final clause ("Circuit breaker
trips at remediation_round_cap (default 5)") and spec section AD lines
5471-5488 ("Circuit breaker -- executable states and transitions").

The circuit breaker owns four behaviors:

  1. :func:`load_gate_config` -- read ``gates`` row for cap configuration
     (VAL-W8-030 default 5; VAL-W8-031 configurable per gate).
  2. :meth:`CircuitBreaker.would_exceed_cap` -- pure predicate the gate
     engine consults BEFORE allocating round N+1; given the prior round
     and the gate's ``remediation_round_cap``, returns True when
     ``prior_round + 1 > cap``.
  3. :meth:`CircuitBreaker.trip_to_stalled` -- atomically writes one
     ``gate_stalled_state`` row, appends one ``event_log_entries`` row
     with ``event_type='gate.stalled'``, and skips the ``gate_decisions``
     INSERT for the cap-exceeded round (VAL-W8-032 / VAL-W8-033).
  4. :meth:`CircuitBreaker.assert_not_stalled` -- consulted by the draft
     ingest path BEFORE persisting a new ``gate_decision_drafts`` row;
     raises :class:`StalledScopeRejectedError` (``RELAY-GATE-051``) when
     a ``gate_stalled_state`` row exists for the scope and has not been
     cleared by ``admin.reopen`` (VAL-W8-034).

VAL-W8-038 ``cascade_on_block=false`` is handled by
:meth:`CircuitBreaker.handle_block_decision`: when a block decision
lands on a gate with ``cascade_on_block=False``, no remediation round
opens regardless of cap; the scope goes terminal directly.

Per CLAUDE.md keystone #8, every state transition co-commits inside one
``BEGIN IMMEDIATE..COMMIT`` block on the sidecar writer connection
borrowed via :func:`_borrow_gate_writer` (shared with W8.2 and W8.3 so
the circuit breaker serializes against ``compare_and_set_state``).

Per contract gap #3 (VAL-W8-032 "scope_state.state='gate.stalled' or
equivalent stalled marker"): the W2 state engine is the only writer
allowed to mutate ``scope_state`` (VAL-W2-024). This module records the
equivalent stalled marker in the companion ``gate_stalled_state`` table
introduced by migration 0011 and emits a ``gate.stalled`` event into
``event_log_entries``; the canonical scope_state transition (when the
hosted profile lands) is delegated to the state engine via the same
event log entry.

Per contract gap #2, the canonical event_type name for the cap-exceeded
audit row is left flexible: this module records the row with
``event_type='gate.stalled'`` (spec AD line 5478 names the resulting
state) and ``event_kind='validation_circuit_breaker'`` (the plan text
name) on the same row so both names are queryable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from .decision_writer import SCHEMA_EVENT_LOG, _borrow_gate_writer
from .errors import StalledScopeRejectedError

# ---------------------------------------------------------------------------
# Canonical constants.
# ---------------------------------------------------------------------------

#: Spec A.5 line 3057 -- default ``remediation_round_cap`` when a ``gates``
#: row is inserted without an explicit value.
DEFAULT_REMEDIATION_ROUND_CAP: Final[int] = 5

#: VAL-W8-031 / spec A.5 -- the inclusive range of valid caps.
REMEDIATION_ROUND_CAP_MIN: Final[int] = 1
REMEDIATION_ROUND_CAP_MAX: Final[int] = 50

#: VAL-W8-032 / spec AD line 5478 -- event_type written on the
#: cap-exceeded transition. The resulting state is ``gate.stalled``.
EVENT_GATE_STALLED: Final[str] = "gate.stalled"

#: VAL-W8-033 / plan text -- ``event_kind`` discriminator co-written on
#: the cap-exceeded row so callers querying by either name find it.
EVENT_KIND_VALIDATION_CIRCUIT_BREAKER: Final[str] = "validation_circuit_breaker"

#: ``gate_stalled_state.reason`` value written by :meth:`trip_to_stalled`.
STALLED_REASON_CAP_EXCEEDED: Final[str] = "cap_exceeded"

#: ``gate_stalled_state.reason`` value written by admin.terminate.
STALLED_REASON_ADMIN_TERMINATED: Final[str] = "admin_terminated"

#: Event type emitted on a ``cascade_on_block=false`` block decision so
#: downstream observers know the scope went terminal without a restart.
EVENT_GATE_TERMINAL_BLOCK: Final[str] = "gate.terminal_block"


# ---------------------------------------------------------------------------
# Result records.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateConfig:
    """A subset of the ``gates`` row the circuit breaker consults.

    Attributes:
        gate_id: UUID of the gate.
        remediation_round_cap: Configured cap (VAL-W8-030 / VAL-W8-031).
        cascade_on_block: When False, a block decision goes terminal
            without opening a new remediation round (VAL-W8-038).
        scope_type: Used for ``gate_stalled_state`` key composition.
    """

    gate_id: str
    remediation_round_cap: int
    cascade_on_block: bool
    scope_type: str


@dataclass(frozen=True)
class TripResult:
    """Outcome of one :meth:`CircuitBreaker.trip_to_stalled` call.

    Attributes:
        ok: True iff a new ``gate_stalled_state`` row was written. False
            when an existing row already marked the scope stalled
            (idempotent re-trip).
        stalled_at: Timestamp recorded on the row.
        event_id: UUID of the ``gate.stalled`` event row.
        terminal_round: The round whose attempted submission triggered
            the transition (= ``current_round``; the new round at
            ``current_round + 1`` is never opened per VAL-W8-032).
    """

    ok: bool
    stalled_at: str
    event_id: str
    terminal_round: int


@dataclass(frozen=True)
class TerminalBlockResult:
    """Outcome of :meth:`CircuitBreaker.handle_block_decision` when
    ``cascade_on_block=False``.

    Attributes:
        ok: True iff a new terminal marker was recorded.
        terminated_at: Timestamp recorded on the row.
        event_id: UUID of the ``gate.terminal_block`` event row.
    """

    ok: bool
    terminated_at: str
    event_id: str


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _now_rfc3339_utc() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def validate_remediation_round_cap(value: int) -> int:
    """Return ``value`` if it falls within [MIN, MAX]; else raise.

    Helper for callers that create ``gates`` rows from validated input
    (CLI, API). The SQL CHECK constraint catches the same range, but
    application-level validation lets the caller surface a structured
    error before the round-trip to the database (VAL-W8-031).
    """
    iv = int(value)
    if iv < REMEDIATION_ROUND_CAP_MIN or iv > REMEDIATION_ROUND_CAP_MAX:
        raise ValueError(
            f"remediation_round_cap={iv!r} out of range "
            f"[{REMEDIATION_ROUND_CAP_MIN}, {REMEDIATION_ROUND_CAP_MAX}]"
        )
    return iv


async def load_gate_config(
    database: Any,
    *,
    gate_id: str,
) -> GateConfig | None:
    """Read one ``gates`` row and return :class:`GateConfig`.

    Returns ``None`` if no row exists (caller decides whether to treat
    that as a hard error or fall back to defaults).
    """
    async with (
        _borrow_gate_writer(database) as conn,
        conn.execute(
            "SELECT gate_id, remediation_round_cap, cascade_on_block, scope_type "
            "FROM gates WHERE gate_id = ?",
            (str(gate_id),),
        ) as cur,
    ):
        row = await cur.fetchone()
    if row is None:
        return None
    return GateConfig(
        gate_id=str(row[0]),
        remediation_round_cap=int(row[1]),
        cascade_on_block=bool(int(row[2])),
        scope_type=str(row[3]),
    )


# ---------------------------------------------------------------------------
# CircuitBreaker.
# ---------------------------------------------------------------------------


@dataclass
class CircuitBreaker:
    """Stalled-state coordinator for gate remediation rounds.

    The breaker is stateless w.r.t. request-state; one instance serves
    any number of trips and admit checks against the same SidecarDatabase.
    The ``project_id`` default matches the OSS single-tenant sentinel
    used elsewhere in the W8.2 / W8.3 writers.
    """

    database: Any
    project_id: str = "00000000-0000-0000-0000-000000000000"

    # ----- pure predicates --------------------------------------------

    @staticmethod
    def would_exceed_cap(
        *,
        current_round: int,
        remediation_round_cap: int,
    ) -> bool:
        """Return True iff allocating ``current_round + 1`` would exceed
        the cap.

        VAL-W8-032: "When ``current_round + 1 > gate.remediation_round_cap``
        (default: attempting round 6 with cap=5)". Pure function; no I/O.
        """
        return int(current_round) + 1 > int(remediation_round_cap)

    # ----- trip ------------------------------------------------------

    async def trip_to_stalled(
        self,
        *,
        scope_type: str,
        scope_id: str,
        gate_id: str,
        current_round: int,
        remediation_round_cap: int,
        failing_assertion_ids: Sequence[str],
        actor_identity_hash: str,
        manifest_commit_hash: str,
    ) -> TripResult:
        """Record the cap-exceeded transition atomically.

        VAL-W8-032: no ``gate_decisions`` row is written for the
        cap-exceeded round (this method does NOT touch gate_decisions).
        The caller (gate engine) MUST consult
        :meth:`would_exceed_cap` BEFORE attempting to write a decision
        for round ``current_round + 1`` and call this method instead.

        VAL-W8-033: appends one ``event_log_entries`` row with
        ``event_type='gate.stalled'``, ``event_kind=
        'validation_circuit_breaker'`` and a payload carrying the five
        named keys: scope_id, gate_id, current_round,
        remediation_round_cap, failing_assertion_ids.

        Idempotent: a second call for the same (scope_type, scope_id) is
        a no-op and returns ``ok=False`` with the existing row's
        ``opened_at``.

        Both writes co-commit in one BEGIN IMMEDIATE..COMMIT block.
        """
        now = _now_rfc3339_utc()
        event_id = str(uuid.uuid4())

        async with _borrow_gate_writer(self.database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                # Idempotency: existing stalled row?
                async with conn.execute(
                    "SELECT opened_at FROM gate_stalled_state "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (scope_type, str(scope_id)),
                ) as cur:
                    existing = await cur.fetchone()

                if existing is not None:
                    await conn.execute("COMMIT")
                    return TripResult(
                        ok=False,
                        stalled_at=str(existing[0]),
                        event_id="",
                        terminal_round=int(current_round),
                    )

                # 1. INSERT gate_stalled_state.
                await conn.execute(
                    "INSERT INTO gate_stalled_state ("
                    "  scope_type, scope_id, gate_id, terminal_round, "
                    "  reason, opened_at"
                    ") VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        scope_type,
                        str(scope_id),
                        str(gate_id),
                        int(current_round),
                        STALLED_REASON_CAP_EXCEEDED,
                        now,
                    ),
                )

                # 2. INSERT event_log_entries with the canonical payload.
                payload = {
                    "event": EVENT_GATE_STALLED,
                    "scope_id": str(scope_id),
                    "gate_id": str(gate_id),
                    "current_round": int(current_round),
                    "remediation_round_cap": int(remediation_round_cap),
                    "failing_assertion_ids": list(failing_assertion_ids),
                    "reason": STALLED_REASON_CAP_EXCEEDED,
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    seq_row = await cur.fetchone()
                next_seq = int(seq_row[0]) if seq_row is not None else 0
                await conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, actor_id, "
                    "  manifest_commit_hash, payload, occurred_at, "
                    "  ingest_sequence, event_kind"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        SCHEMA_EVENT_LOG,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        EVENT_GATE_STALLED,
                        "gate_engine",
                        actor_identity_hash,
                        manifest_commit_hash,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        now,
                        next_seq,
                        EVENT_KIND_VALIDATION_CIRCUIT_BREAKER,
                    ),
                )

                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise

        return TripResult(
            ok=True,
            stalled_at=now,
            event_id=event_id,
            terminal_round=int(current_round),
        )

    # ----- assert_not_stalled (VAL-W8-034) ---------------------------

    async def assert_not_stalled(
        self,
        *,
        scope_type: str,
        scope_id: str,
    ) -> None:
        """Raise :class:`StalledScopeRejectedError` when the scope is
        stalled AND has not been reopened.

        Called by the draft-ingest path BEFORE persisting a new
        ``gate_decision_drafts`` row. The row exists in
        ``gate_stalled_state`` for the scope; if ``reopened_at`` is set,
        the scope has been admin-reopened and is no longer rejecting
        drafts. ``terminated_at`` non-null means the scope is finally
        terminal and drafts are still rejected (the scope is closed).
        """
        async with (
            _borrow_gate_writer(self.database) as conn,
            conn.execute(
                "SELECT gate_id, terminal_round, reason, opened_at, "
                "       reopened_at, terminated_at "
                "FROM gate_stalled_state "
                "WHERE scope_type = ? AND scope_id = ?",
                (scope_type, str(scope_id)),
            ) as cur,
        ):
            row = await cur.fetchone()
        if row is None:
            return
        gate_id_str = str(row[0])
        terminal_round = int(row[1])
        reason = str(row[2])
        opened_at = str(row[3])
        reopened_at = row[4]
        terminated_at = row[5]

        # admin.reopen clears the rejection: the scope is back to gate.open
        # with a new round (VAL-W8-035). If reopened_at is set AND
        # terminated_at is NOT set, drafts may flow.
        if reopened_at is not None and terminated_at is None:
            return

        raise StalledScopeRejectedError(
            "scope is in gate.stalled state; "
            "admin.reopen or admin.terminate is required before new "
            "draft submissions",
            payload={
                "scope_type": scope_type,
                "scope_id": str(scope_id),
                "gate_id": gate_id_str,
                "terminal_round": terminal_round,
                "reason": reason,
                "opened_at": opened_at,
                "terminated_at": (
                    None if terminated_at is None else str(terminated_at)
                ),
            },
        )

    # ----- handle_block_decision (VAL-W8-038) ------------------------

    async def handle_block_decision(
        self,
        *,
        scope_type: str,
        scope_id: str,
        gate_id: str,
        current_round: int,
        cascade_on_block: bool,
        actor_identity_hash: str,
        manifest_commit_hash: str,
    ) -> TerminalBlockResult | None:
        """When ``cascade_on_block=False``, record a terminal marker so
        no remediation round opens.

        VAL-W8-038: "If ``gates.cascade_on_block=false`` AND a gate
        decides ``action='block'``, the engine MUST transition directly
        to terminal (no automatic remediation round), regardless of
        ``remediation_round_cap``."

        When ``cascade_on_block=True``, returns ``None`` and the caller
        proceeds with the normal restart path (W8.3). The terminal
        marker is recorded in ``gate_stalled_state`` with
        ``reason='admin_terminated'`` so the same stalled-state guard
        :meth:`assert_not_stalled` rejects subsequent drafts.
        """
        if cascade_on_block:
            return None

        now = _now_rfc3339_utc()
        event_id = str(uuid.uuid4())

        async with _borrow_gate_writer(self.database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                async with conn.execute(
                    "SELECT opened_at FROM gate_stalled_state "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (scope_type, str(scope_id)),
                ) as cur:
                    existing = await cur.fetchone()
                if existing is not None:
                    await conn.execute("COMMIT")
                    return TerminalBlockResult(
                        ok=False,
                        terminated_at=str(existing[0]),
                        event_id="",
                    )

                await conn.execute(
                    "INSERT INTO gate_stalled_state ("
                    "  scope_type, scope_id, gate_id, terminal_round, "
                    "  reason, opened_at, terminated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        scope_type,
                        str(scope_id),
                        str(gate_id),
                        int(current_round),
                        STALLED_REASON_ADMIN_TERMINATED,
                        now,
                        now,
                    ),
                )

                payload = {
                    "event": EVENT_GATE_TERMINAL_BLOCK,
                    "scope_id": str(scope_id),
                    "gate_id": str(gate_id),
                    "current_round": int(current_round),
                    "cascade_on_block": False,
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    seq_row = await cur.fetchone()
                next_seq = int(seq_row[0]) if seq_row is not None else 0
                await conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, actor_id, "
                    "  manifest_commit_hash, payload, occurred_at, "
                    "  ingest_sequence, event_kind"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        SCHEMA_EVENT_LOG,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        EVENT_GATE_TERMINAL_BLOCK,
                        "gate_engine",
                        actor_identity_hash,
                        manifest_commit_hash,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        now,
                        next_seq,
                        EVENT_GATE_TERMINAL_BLOCK,
                    ),
                )

                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise

        return TerminalBlockResult(
            ok=True,
            terminated_at=now,
            event_id=event_id,
        )


__all__ = [
    "DEFAULT_REMEDIATION_ROUND_CAP",
    "EVENT_GATE_STALLED",
    "EVENT_GATE_TERMINAL_BLOCK",
    "EVENT_KIND_VALIDATION_CIRCUIT_BREAKER",
    "REMEDIATION_ROUND_CAP_MAX",
    "REMEDIATION_ROUND_CAP_MIN",
    "STALLED_REASON_ADMIN_TERMINATED",
    "STALLED_REASON_CAP_EXCEEDED",
    "CircuitBreaker",
    "GateConfig",
    "TerminalBlockResult",
    "TripResult",
    "load_gate_config",
    "validate_remediation_round_cap",
]
