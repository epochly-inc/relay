"""``compare_and_set_state`` -- the canonical control-plane write primitive.

Per CLAUDE.md keystone invariant #1: this is the ONLY path that writes
canonical state rows (``scope_state``, ``run_results``) and the audit log
(``event_log_entries``). VAL-W2-024 + VAL-W2-058 grep guards enforce
"this module is the only writer" at the source-tree level.

Per spec C.4 (lines 3678-3724) and CLAUDE.md keystone invariant #8: the
write goes through a single SERIALIZABLE-equivalent transaction (BEGIN
IMMEDIATE on SQLite per eng plan A5; the W2.3 writer queue serialises one
writer at a time, equivalent to SERIALIZABLE for the single-writer
profile).

This module owns the dedicated writer connection rented from
``SidecarDatabase`` instead of going through the W2.3 single-row
``transactional_db_write`` primitive: a state transition is a multi-statement
transaction (SELECT scope_state -> UPDATE scope_state -> INSERT
event_log_entries) and must commit as one BEGIN IMMEDIATE..COMMIT block.
Sending three independent ``transactional_db_write`` calls would lose
atomicity. The writer connection is borrowed via a context manager that
asserts single-borrow ownership.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from ..anti_bypass import OPERATOR_OVERRIDE_EVENT_KIND, raise_on_reject, screen_payload
from ..blob_storage import maybe_spillover
from ..db import SidecarDatabase
from .guards import get_guard, is_handoff_guard
from .transitions import TRANSITION_TABLE, TransitionTable

# Structured reason codes returned by compare_and_set_state. These mirror
# spec C.4 pseudocode exactly so the test surface is a 1:1 match with the
# normative pseudocode (lines 3693, 3699, 3706, 3709, 3712).
UNKNOWN_SCOPE: str = "UNKNOWN_SCOPE"
EXPECTED_FROM_MISMATCH: str = "EXPECTED_FROM_MISMATCH"
INVALID_TRANSITION: str = "INVALID_TRANSITION"
ACTOR_NOT_ALLOWED: str = "ACTOR_NOT_ALLOWED"
GUARD_FAILED: str = "GUARD_FAILED"
HANDOFF_INVALID: str = "HANDOFF_INVALID"
TERMINAL_STATE: str = "TERMINAL_STATE"
UNKNOWN_GUARD: str = "UNKNOWN_GUARD"

# Event-type string written to event_log_entries on a rejected unknown transition.
INVALID_TRANSITION_EVENT_TYPE: str = "state.invalid_transition"


@dataclass(frozen=True)
class ActorRef:
    """The minimal actor reference required by compare_and_set_state.

    ``kind`` is matched against ``Transition.allowed_actor_kinds`` for the
    actor-anchor check. ``identity_hash`` is the sha256-<hex> wire form
    (VAL-W1-009); it is recorded on the event_log row for forensic audit.
    """

    kind: str
    identity_hash: str


@dataclass
class StateTransitionResult:
    """Outcome of one compare_and_set_state call.

    Attributes:
        ok: True only when the transition was applied OR was an idempotent
            no-op replay (in which case ``idempotent=True`` as well).
        reason: Structured failure code (one of the module-level constants)
            on ``ok=False``; None on success.
        new_state: The target state on success (or the observed state on
            idempotent replay); None on failure.
        observed_state: The state read from scope_state when a CAS
            mismatch occurs. Populated only on
            ``reason='EXPECTED_FROM_MISMATCH'``.
        idempotent: True iff the call was a deduped retry. ``ok=True`` AND
            ``idempotent=True`` means "we observed the target state already
            and recognised this as a replay".
        epoch: The post-transition epoch (or pre-transition epoch on a
            no-op idempotent replay).
        event_id: UUID of the event_log_entries row emitted by this call.
            None on failure paths that don't emit a log row.
    """

    ok: bool
    reason: str | None = None
    new_state: str | None = None
    observed_state: str | None = None
    idempotent: bool = False
    epoch: int | None = None
    event_id: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def _now_rfc3339_utc() -> str:
    """RFC 3339 UTC with explicit ``Z`` offset (matches W2.3 db.py)."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


@contextlib.asynccontextmanager
async def _borrow_writer(
    database: SidecarDatabase,
) -> AsyncIterator[aiosqlite.Connection]:
    """Acquire exclusive access to the writer connection for a multi-stmt txn.

    The W2.3 SidecarDatabase serialises writes through a single coroutine
    consuming an asyncio.Queue. A state-engine transition is a
    multi-statement transaction (SELECT -> UPDATE -> INSERT), so going
    through the queue's single-row INSERT path would lose atomicity.

    Instead we serialise multi-statement work through the dedicated
    ``database._state_engine_writer_lock`` asyncio.Lock. The lock is
    eagerly created in :meth:`SidecarDatabase.open` (W2.5 fix per
    2026-05-17 audit) so the writer_loop and every CAS / gate-decision /
    retention borrow share ONE Lock instance with stable identity.
    Holding the lock guarantees that no other writer can interleave on
    the shared ``self._writer`` connection. The W2.3 writer_loop now
    serializes via the same lock; safe -- BEGIN IMMEDIATE on
    ``self._writer`` from any caller (CAS multi-stmt txn, queue-path
    single-row INSERT, gate decision writer, retention pass) cannot
    nest with another caller's BEGIN.
    """
    # Lazily attach the lock; the SidecarDatabase pre-dates this primitive.
    lock = getattr(database, "_state_engine_writer_lock", None)
    if lock is None:
        # Use module-level import to avoid circular import with asyncio in db.py.
        import asyncio as _asyncio

        lock = _asyncio.Lock()
        database._state_engine_writer_lock = lock
    async with lock:
        conn = database._writer
        if conn is None:
            raise RuntimeError(
                "compare_and_set_state: SidecarDatabase is not open "
                "(call database.open() before any state transition)."
            )
        yield conn


async def init_scope(
    *,
    database: SidecarDatabase,
    scope_kind: str,
    scope_id: str,
    project_id: str,
    initial_state: str | None = None,
    table: TransitionTable | None = None,
) -> None:
    """Insert a fresh scope_state row at the canonical initial state.

    Per spec W "Initialization rules": the initial state must be a
    transition-table-defined origin state for the scope kind. If
    ``initial_state`` is None, the canonical initial state is read from
    the transition table.

    Raises:
        ValueError: scope_kind unknown to the transition table OR
            initial_state not the canonical origin state.
        sqlite3.IntegrityError: scope_state row already exists for
            (scope_kind, scope_id) -- the caller should treat this as an
            idempotent no-op or surface a structured error.
    """
    tbl = table if table is not None else TRANSITION_TABLE
    spec = tbl.scope_spec(scope_kind)
    if spec is None:
        raise ValueError(f"unknown scope_kind: {scope_kind!r}")
    actual_initial = initial_state if initial_state is not None else spec.initial_state
    if actual_initial != spec.initial_state:
        raise ValueError(
            f"initial_state {actual_initial!r} for scope_kind {scope_kind!r} "
            f"does not match the canonical initial state {spec.initial_state!r}"
        )
    now = _now_rfc3339_utc()
    async with _borrow_writer(database) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            await conn.execute(
                "INSERT INTO scope_state "
                "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 0, ?, ?)",
                (scope_kind, scope_id, project_id, actual_initial, now, now),
            )
            await conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise


async def init_scope_on_conn(
    *,
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    project_id: str,
    initial_state: str | None = None,
    table: TransitionTable | None = None,
) -> None:
    """Insert a fresh scope_state row at the canonical initial state, using
    the caller's existing connection and transaction.

    Same semantics as ``init_scope`` (spec W "Initialization rules": the
    initial state must be a transition-table-defined origin state for the
    scope kind), but runs INSIDE the caller's existing BEGIN IMMEDIATE..
    COMMIT transaction. The caller is responsible for committing or rolling
    back the surrounding transaction. This is the spec W line 5112 path
    used by canonical writers that already hold the writer connection and
    must co-commit the scope_state row alongside their object row insert
    (e.g., the gate decision writer inserting evidence_bundles +
    gate_rounds within its own BEGIN IMMEDIATE..COMMIT block, satisfying
    the migration 0008 / 0016 paired-row deferred trigger).

    Per CLAUDE.md keystone invariant #1: the state engine remains the
    canonical control-plane writer of scope_state; this helper merely
    permits inlining that write into another canonical writer's
    pre-existing transaction so the spec W invariant ("a creating
    transaction that inserts an object row without the matching
    scope_state row fails the integrity check at commit") is satisfiable
    without two-transaction race windows.

    Raises:
        ValueError: scope_kind unknown to the transition table OR
            initial_state not the canonical origin state.
        sqlite3.IntegrityError: scope_state row already exists for
            (scope_kind, scope_id) -- the caller should treat this as an
            idempotent no-op or surface a structured error.
    """
    tbl = table if table is not None else TRANSITION_TABLE
    spec = tbl.scope_spec(scope_kind)
    if spec is None:
        raise ValueError(f"unknown scope_kind: {scope_kind!r}")
    actual_initial = initial_state if initial_state is not None else spec.initial_state
    if actual_initial != spec.initial_state:
        raise ValueError(
            f"initial_state {actual_initial!r} for scope_kind {scope_kind!r} "
            f"does not match the canonical initial state {spec.initial_state!r}"
        )
    now = _now_rfc3339_utc()
    await conn.execute(
        "INSERT INTO scope_state "
        "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (scope_kind, scope_id, project_id, actual_initial, now, now),
    )


async def _was_event_already_applied(
    conn: aiosqlite.Connection,
    *,
    scope_kind: str,
    scope_id: str,
    event: str,
    current_epoch: int,
) -> bool:
    """Idempotency probe: has this event been applied recently?

    Spec C.4 line 3697-3698: ``was_event_already_applied`` is a separate
    event-log query. Our convention: the engine records the *triggering*
    event on every transition row's ``payload`` as
    ``{"event": <event-name>, "expected_from": <state-name>, "applied_at_epoch": <int>}``.
    A retry of the same (scope, event, expected_from) within ``current_epoch``
    range means the event already moved the state.

    We look for an event_log_entries row where:
      - scope_id matches,
      - event_type matches the TRANSITION event_log_type for the
        (scope_kind, expected_from, event) tuple -- but we resolve that
        mapping outside this helper so this query is a simple payload-
        text scan.
    Implementation: scan for the most recent row whose JSON payload contains
    the (event, applied_at_epoch=current_epoch - 1) tuple. The "-1" accounts
    for the epoch increment that was applied during the original transition.
    """
    async with conn.execute(
        "SELECT payload FROM event_log_entries "
        "WHERE scope_id = ? AND scope_type = ? "
        "AND event_kind = 'state_transition' "
        "ORDER BY ingest_sequence DESC LIMIT 16",
        (scope_id, scope_kind),
    ) as cur:
        rows = await cur.fetchall()
    target = {"event": event, "applied_at_epoch": current_epoch - 1}
    for (payload_text,) in rows:
        try:
            payload = json.loads(payload_text)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if (
            payload.get("event") == target["event"]
            and payload.get("applied_at_epoch") == target["applied_at_epoch"]
        ):
            return True
    return False


async def compare_and_set_state(
    *,
    database: SidecarDatabase,
    scope_kind: str,
    scope_id: str,
    expected_from: str,
    event: str,
    actor: ActorRef,
    payload: dict[str, Any] | None = None,
    project_id: str | None = None,
    manifest_commit_hash: str | None = None,
    table: TransitionTable | None = None,
) -> StateTransitionResult:
    """Atomic compare-and-set of scope state with audit log emission.

    Per CLAUDE.md keystone invariant #1 (control plane writes the result),
    invariant #8 (atomic persistence through four primitives), and spec C.4
    pseudocode (lines 3678-3724).

    Lifecycle:
        1. Borrow the writer connection.
        2. BEGIN IMMEDIATE.
        3. SELECT scope_state for (scope_kind, scope_id).
        4. If absent -> UNKNOWN_SCOPE.
        5. If current.state != expected_from -> check idempotency.
        6. If idempotent retry -> return ok=True, idempotent=True.
        7. Else -> EXPECTED_FROM_MISMATCH with observed_state.
        8. If TRANSITION_TABLE.lookup(...) is None -> emit
           state.invalid_transition log row, return INVALID_TRANSITION.
        9. If actor.kind not in transition.allowed_actor_kinds -> ACTOR_NOT_ALLOWED.
        10. UPDATE scope_state SET state=to_state, epoch=epoch+1, updated_at=now()
            WHERE scope_kind=? AND scope_id=? AND epoch=current.epoch.
            (Optimistic concurrency on the W2.3 single-writer connection.)
        11. INSERT one event_log_entries row with transition.event_log_type.
        12. COMMIT.

    Args:
        database: The active SidecarDatabase.
        scope_kind / scope_id: Composite primary key into scope_state.
        expected_from: The state the caller believes the scope is in.
        event: The transition-triggering event name.
        actor: ActorRef with kind + identity_hash. ``kind`` gates the
            transition; ``identity_hash`` is recorded on the audit row.
        payload: Optional structured payload for the audit row. Merged
            with the canonical {event, expected_from, applied_at_epoch}
            fields.
        project_id: project_id for the audit row. Defaults to the empty
            UUID sentinel if absent (local OSS single-tenant default).
        manifest_commit_hash: Optional manifest hash for the audit row's
            ``manifest_commit_hash`` column.
        table: Override the TRANSITION_TABLE singleton (tests).

    Returns:
        StateTransitionResult with ok, reason, new_state, observed_state,
        idempotent, epoch, event_id.

    Raises:
        sqlite3.OperationalError: SQLITE_BUSY / database locked errors.
            The W2.3 retry/backoff loop is NOT in scope here (state-engine
            transitions are single-writer per scope; concurrent CAS calls
            on the SAME scope serialise through the
            _state_engine_writer_lock). Callers that observe a non-BUSY
            OperationalError must treat it as a hard failure.
    """
    tbl = table if table is not None else TRANSITION_TABLE
    payload_in = dict(payload) if payload else {}
    project_id_eff = project_id or "00000000-0000-0000-0000-000000000000"

    async with _borrow_writer(database) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            # Step 3: read current state.
            async with conn.execute(
                "SELECT state, epoch FROM scope_state "
                "WHERE scope_kind = ? AND scope_id = ?",
                (scope_kind, scope_id),
            ) as cur:
                current = await cur.fetchone()

            if current is None:
                await conn.execute("ROLLBACK")
                return StateTransitionResult(
                    ok=False, reason=UNKNOWN_SCOPE, observed_state=None
                )

            current_state = str(current[0])
            current_epoch = int(current[1])

            # Steps 5-7: expected_from mismatch -> check idempotency.
            if current_state != expected_from:
                # Idempotent replay: the event was already applied, and we
                # are now observing the target state.
                applied_already = await _was_event_already_applied(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    event=event,
                    current_epoch=current_epoch,
                )
                await conn.execute("ROLLBACK")
                if applied_already:
                    return StateTransitionResult(
                        ok=True,
                        idempotent=True,
                        new_state=current_state,
                        epoch=current_epoch,
                    )
                return StateTransitionResult(
                    ok=False,
                    reason=EXPECTED_FROM_MISMATCH,
                    observed_state=current_state,
                    epoch=current_epoch,
                )

            # Terminal-state stickiness (spec C.1).
            if tbl.is_terminal(scope_kind, current_state):
                await conn.execute("ROLLBACK")
                return StateTransitionResult(
                    ok=False,
                    reason=TERMINAL_STATE,
                    observed_state=current_state,
                    epoch=current_epoch,
                )

            # Step 8: lookup transition.
            transition = tbl.lookup(scope_kind, expected_from, event)
            if transition is None:
                # Spec C.4 line 3704-3706: emit a state.invalid_transition
                # row, then rollback the scope_state SELECT but COMMIT the
                # invalid-transition log. We use a fresh micro-txn for
                # the log row -- this is the one place where the engine
                # deliberately writes outside the parent txn so that the
                # forensic audit row survives.
                await conn.execute("ROLLBACK")
                event_id = str(uuid.uuid4())
                now = _now_rfc3339_utc()
                full_payload = {
                    "event": event,
                    "expected_from": expected_from,
                    "observed_state": current_state,
                    "rejected_reason": INVALID_TRANSITION,
                }
                full_payload.update(payload_in)
                # Round-3 P1 fix #2: the INVALID_TRANSITION branch performs
                # async I/O (screen_payload, maybe_spillover) and a fresh
                # micro-txn AFTER the parent ROLLBACK. Per CLAUDE.md
                # keystone #1 (control plane writes the result), callers
                # are entitled to a structured StateTransitionResult on
                # every path -- a propagating exception is observed as
                # "unknown state" and provokes unsafe retries. We wrap
                # the secondary I/O so failures are reported as
                # ``extras['secondary_error_reason']`` on the
                # INVALID_TRANSITION result; the canonical reason is
                # preserved.
                #
                # W2.5 VAL-W2-057: anti-bypass screen on the caller-supplied
                # payload portion. The engine-supplied keys above never
                # contain bypass markers, but ``payload_in`` is caller-
                # controlled. We screen the merged payload defensively.
                # W2.5 VAL-W2-038: blob spillover for oversize payloads.
                try:
                    raise_on_reject(
                        await screen_payload(
                            payload=full_payload,
                            event_kind="state_invalid_transition",
                        )
                    )
                    full_payload_on_row = maybe_spillover(full_payload)
                except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
                    # Cooperative cancellation + interpreter teardown
                    # MUST propagate; otherwise the asyncio cancellation
                    # contract is violated.
                    raise
                except Exception as secondary_exc:  # noqa: BLE001
                    # Surface as structured outcome. We do NOT lose the
                    # INVALID_TRANSITION verdict -- the scope_state row
                    # was already ROLLBACK-ed above, so the canonical
                    # reason is unchanged; only the forensic log row was
                    # not written. Callers branch on
                    # ``extras['secondary_error_reason']`` if they need
                    # to distinguish the lost-forensic case from the
                    # clean rejection.
                    return StateTransitionResult(
                        ok=False,
                        reason=INVALID_TRANSITION,
                        observed_state=current_state,
                        epoch=current_epoch,
                        extras={
                            "secondary_error_reason": (
                                f"{type(secondary_exc).__name__}: "
                                f"{secondary_exc}"
                            ),
                        },
                    )
                # Compute next ingest_sequence in a fresh BEGIN IMMEDIATE.
                await conn.execute("BEGIN IMMEDIATE")
                try:
                    async with conn.execute(
                        "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                        "FROM event_log_entries"
                    ) as cur:
                        row = await cur.fetchone()
                    next_seq = int(row[0]) if row is not None else 0
                    await conn.execute(
                        "INSERT INTO event_log_entries ("
                        "  event_id, schema_version, project_id, scope_type, "
                        "  scope_id, event_type, actor_kind, actor_id, "
                        "  manifest_commit_hash, payload, occurred_at, "
                        "  ingest_sequence, event_kind"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            event_id,
                            "relay.event_log_entry.v1",
                            project_id_eff,
                            scope_kind,
                            scope_id,
                            INVALID_TRANSITION_EVENT_TYPE,
                            actor.kind,
                            actor.identity_hash,
                            manifest_commit_hash,
                            json.dumps(full_payload_on_row, sort_keys=True, separators=(",", ":")),
                            now,
                            next_seq,
                            "state_invalid_transition",
                        ),
                    )
                    await conn.execute("COMMIT")
                except BaseException:
                    with contextlib.suppress(Exception):
                        await conn.execute("ROLLBACK")
                    raise
                return StateTransitionResult(
                    ok=False,
                    reason=INVALID_TRANSITION,
                    observed_state=current_state,
                    epoch=current_epoch,
                    event_id=event_id,
                )

            # Step 9: actor-kind gate.
            if actor.kind not in transition.allowed_actor_kinds:
                await conn.execute("ROLLBACK")
                return StateTransitionResult(
                    ok=False,
                    reason=ACTOR_NOT_ALLOWED,
                    observed_state=current_state,
                    epoch=current_epoch,
                )

            # Step 9b (VAL-V2M03-025/030/031): per-transition guards.
            # Each guard runs INSIDE the SERIALIZABLE writer transaction
            # against the writer conn (read-only SELECTs only). The handoff
            # guard (spec C.5) is evaluated like any other guard but its
            # failure surfaces as HANDOFF_INVALID so callers map to the
            # canonical RELAY-GATE-021 envelope (per CLAUDE.md keystone #4
            # and VAL-V2M03-031). Unknown guard names -> UNKNOWN_GUARD
            # (defensive fail-closed against YAML drift).
            for guard_name in transition.guard_names:
                guard = get_guard(guard_name)
                if guard is None:
                    await conn.execute("ROLLBACK")
                    return StateTransitionResult(
                        ok=False,
                        reason=UNKNOWN_GUARD,
                        observed_state=current_state,
                        epoch=current_epoch,
                        extras={"failed_guard": guard_name},
                    )
                ok_g, diagnostics = await guard.check(
                    conn,
                    scope_kind,
                    scope_id,
                    payload_in,
                    manifest_commit_hash,
                )
                if not ok_g:
                    await conn.execute("ROLLBACK")
                    reason_code = (
                        HANDOFF_INVALID
                        if is_handoff_guard(guard_name)
                        else GUARD_FAILED
                    )
                    return StateTransitionResult(
                        ok=False,
                        reason=reason_code,
                        observed_state=current_state,
                        epoch=current_epoch,
                        extras={
                            "failed_guard": guard_name,
                            "guard_diagnostics": diagnostics,
                        },
                    )

            # Step 10: CAS UPDATE on epoch.
            now = _now_rfc3339_utc()
            cursor = await conn.execute(
                "UPDATE scope_state "
                "SET state = ?, epoch = epoch + 1, updated_at = ? "
                "WHERE scope_kind = ? AND scope_id = ? AND epoch = ?",
                (transition.to_state, now, scope_kind, scope_id, current_epoch),
            )
            rowcount = cursor.rowcount
            if rowcount != 1:
                # The CAS lost the race (epoch advanced between SELECT and
                # UPDATE). Treat as EXPECTED_FROM_MISMATCH.
                await conn.execute("ROLLBACK")
                async with conn.execute(
                    "SELECT state, epoch FROM scope_state "
                    "WHERE scope_kind = ? AND scope_id = ?",
                    (scope_kind, scope_id),
                ) as cur:
                    refreshed = await cur.fetchone()
                observed_state_refreshed = (
                    str(refreshed[0]) if refreshed is not None else current_state
                )
                observed_epoch_refreshed = (
                    int(refreshed[1]) if refreshed is not None else current_epoch
                )
                return StateTransitionResult(
                    ok=False,
                    reason=EXPECTED_FROM_MISMATCH,
                    observed_state=observed_state_refreshed,
                    epoch=observed_epoch_refreshed,
                )

            # Step 11: emit the audit row.
            new_epoch = current_epoch + 1
            event_id = str(uuid.uuid4())
            full_payload = {
                "event": event,
                "expected_from": expected_from,
                "applied_at_epoch": current_epoch,
            }
            full_payload.update(payload_in)
            # W2.5 VAL-W2-057: anti-bypass screen. The engine-supplied keys
            # are clean; ``payload_in`` is caller-controlled. The
            # ``operator_override`` event_kind path consults the actors
            # registry via the writer connection (it's read-only against
            # actors, so safe to share the conn mid-transaction).
            if isinstance(payload_in, dict):
                override_claim_raw = payload_in.get("operator_override_claim")
            else:
                override_claim_raw = None
            override_claim = (
                override_claim_raw if isinstance(override_claim_raw, dict) else None
            )
            override_event_kind = (
                OPERATOR_OVERRIDE_EVENT_KIND if override_claim is not None else None
            )
            override_conn = (
                conn if override_event_kind == OPERATOR_OVERRIDE_EVENT_KIND else None
            )
            raise_on_reject(
                await screen_payload(
                    payload=full_payload,
                    event_kind=override_event_kind,
                    operator_override_claim=override_claim,
                    actors_connection=override_conn,
                )
            )
            # W2.5 VAL-W2-038: blob spillover for oversize payloads.
            full_payload_on_row = maybe_spillover(full_payload)
            async with conn.execute(
                "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                "FROM event_log_entries"
            ) as cur:
                row = await cur.fetchone()
            next_seq = int(row[0]) if row is not None else 0
            await conn.execute(
                "INSERT INTO event_log_entries ("
                "  event_id, schema_version, project_id, scope_type, "
                "  scope_id, event_type, actor_kind, actor_id, "
                "  manifest_commit_hash, payload, occurred_at, "
                "  ingest_sequence, event_kind"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    "relay.event_log_entry.v1",
                    project_id_eff,
                    scope_kind,
                    scope_id,
                    transition.event_log_type,
                    actor.kind,
                    actor.identity_hash,
                    manifest_commit_hash,
                    json.dumps(full_payload_on_row, sort_keys=True, separators=(",", ":")),
                    now,
                    next_seq,
                    "state_transition",
                ),
            )

            # Spec AP.5.c (lines 6391-6398): every successful transition
            # ALSO emits exactly one row of
            # ``event_type='<scope_kind>.transition'`` carrying
            # ``payload.from_state / to_state / epoch_after``. The m3-f03
            # temporal-query SQL function filters on the ``.transition``
            # suffix to reconstruct scope state at an arbitrary
            # ``ingest_sequence``. This row is emitted INSIDE the same
            # BEGIN IMMEDIATE..COMMIT transaction as the action event so
            # both rows commit (or neither commits) atomically; failed
            # transitions (every early return above) never reach this
            # point so no summary row is written on the failure path.
            #
            # ``event_kind`` is deliberately distinct from
            # ``'state_transition'`` so:
            #   - the idempotency probe at _was_event_already_applied
            #     (filters event_kind='state_transition') keeps reading
            #     exactly one row per applied event, and
            #   - the context-reinjection guard at
            #     http_endpoint.py:_first_manifest_hash_for_scope (also
            #     filters event_kind='state_transition') keeps returning
            #     the canonical first transition row's manifest hash.
            summary_event_id = str(uuid.uuid4())
            summary_payload = {
                "from_state": expected_from,
                "to_state": transition.to_state,
                "epoch_after": new_epoch,
            }
            await conn.execute(
                "INSERT INTO event_log_entries ("
                "  event_id, schema_version, project_id, scope_type, "
                "  scope_id, event_type, actor_kind, actor_id, "
                "  manifest_commit_hash, payload, occurred_at, "
                "  ingest_sequence, event_kind"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    summary_event_id,
                    "relay.event_log_entry.v1",
                    project_id_eff,
                    scope_kind,
                    scope_id,
                    f"{scope_kind}.transition",
                    actor.kind,
                    actor.identity_hash,
                    manifest_commit_hash,
                    json.dumps(summary_payload, sort_keys=True, separators=(",", ":")),
                    now,
                    next_seq + 1,
                    "state_transition_summary",
                ),
            )

            await conn.execute("COMMIT")
            return StateTransitionResult(
                ok=True,
                new_state=transition.to_state,
                epoch=new_epoch,
                event_id=event_id,
            )
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise


__all__ = [
    "ACTOR_NOT_ALLOWED",
    "ActorRef",
    "EXPECTED_FROM_MISMATCH",
    "GUARD_FAILED",
    "HANDOFF_INVALID",
    "INVALID_TRANSITION",
    "INVALID_TRANSITION_EVENT_TYPE",
    "StateTransitionResult",
    "TERMINAL_STATE",
    "UNKNOWN_GUARD",
    "UNKNOWN_SCOPE",
    "compare_and_set_state",
    "init_scope",
]
