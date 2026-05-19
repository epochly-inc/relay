"""V3M3-F03 (2026-05-19): SQLite-equivalent of the spec section AP.5.a
``reconstruct_scope_state_at`` PL/pgSQL function.

The canonical Postgres profile ships
``reconstruct_scope_state_at(p_scope_kind text, p_scope_id uuid, p_at
timestamptz)`` as a STABLE PL/pgSQL function (per
``planning/epochly-replay-spec.md`` lines 6273-6336, mirrored into
``packages/schemas/sql/0017_v3_temporal_query.sql``). PL/pgSQL is not
available in the OSS sidecar profile (SQLite has no equivalent), so this
module replays the same algorithm in Python over the sidecar's SQLite
``event_log_entries`` mirror.

Algorithm (mirrors the PG body verbatim, with two profile-specific
translations):

  1. If no event_log_entries row exists for (scope_kind, scope_id) at or
     before T, return None. (Spec line 6291: scope did not exist at T.)
  2. Else determine the initial state for the scope kind from the spec
     section W initial-state mapping (lines 6299-6306).
  3. SELECT the latest ``*.transition`` summary row at or before T,
     ordered by (occurred_at, ingest_sequence). Its ``payload.to_state``
     and ``payload.epoch_after`` become the reconstructed state and epoch.
  4. If no transition row exists yet (only action-event rows are present),
     return the initial state at epoch 0.

Profile translations vs spec:

  * The spec function says ``WHERE scope_kind = p_scope_kind``. The
    canonical ``event_log_entries`` DDL (both Postgres
    ``packages/schemas/sql/0002_control_plane.sql:138`` and SQLite
    ``apps/local-sidecar/migrations/0001_event_log_entries.sql:28``) name
    the column ``scope_type``. The Postgres migration
    ``0017_v3_temporal_query.sql`` references the actual column name
    ``scope_type`` while exposing the same ``p_scope_kind`` parameter
    name the spec advertises. This helper follows the same convention.

  * The spec function uses ``payload->>'to_state'`` and
    ``(payload->>'epoch_after')::bigint``. SQLite stores the payload as
    TEXT, so this helper parses the payload as JSON and reads the keys
    directly. Both tiers therefore read the same logical values written
    by m3-f02 at ``compare_and_set.py:707-756``.

Return shape mirrors the PG function:
``TemporalScopeStateRow(state, epoch_at_t, last_event_id, last_event_type,
last_event_at)`` -- the same 5-tuple the PG RETURNS TABLE clause declares.

This module is read-only; it never writes to ``event_log_entries`` or any
other table. It does NOT bypass CLAUDE.md keystone invariant #8 (atomic
persistence) because no write occurs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from relay_sidecar.db import SidecarDatabase

# Spec section W initial-state mapping (lines 6299-6306 verbatim, mirrored
# from the PL/pgSQL CASE expression in 0017_v3_temporal_query.sql).
# A scope_kind absent from this map yields ``None`` for the initial state
# so the helper still returns a row carrying ``state=None`` rather than
# raising -- matching the PG function which would propagate a NULL
# v_initial_state from the unmatched CASE arm.
_INITIAL_STATE_BY_SCOPE_KIND: dict[str, str] = {
    "run": "pending",
    "replay_case": "proposed",
    "gate_round": "open",
    "evidence_bundle": "building",
    "eval_run": "pending",
    "release": "open",
}


@dataclass(frozen=True, slots=True)
class TemporalScopeStateRow:
    """One row returned by ``reconstruct_scope_state_at_local``.

    Mirrors the PL/pgSQL ``RETURNS TABLE`` clause (spec lines 6280-6285):
    ``state text, epoch_at_t bigint, last_event_id uuid, last_event_type
    text, last_event_at timestamptz``. The Python ``last_event_at`` is the
    RFC 3339 UTC string from SQLite storage; the PG function returns a
    ``timestamptz``. The cross-tier parity test (VAL-V3M3-009) compares
    only ``(state, epoch_at_t, last_event_type)`` because the storage
    representations of event_id and last_event_at legitimately differ.
    """

    state: str | None
    epoch_at_t: int
    last_event_id: str | None
    last_event_type: str | None
    last_event_at: str | None


async def reconstruct_scope_state_at_local(
    *,
    database: SidecarDatabase,
    scope_kind: str,
    scope_id: str,
    at: str,
) -> TemporalScopeStateRow | None:
    """Reconstruct the state of ``scope_kind/scope_id`` at timestamp ``at``.

    Args:
        database: live sidecar DB; an acquired reader connection is used.
        scope_kind: spec section W scope kind; one of ``run``, ``replay_case``,
            ``gate_round``, ``evidence_bundle``, ``eval_run``, ``release``.
            Any other value is accepted (it simply yields ``None`` for
            ``state`` from the initial-state lookup); the helper does not
            enforce the closed set so it remains forward-compatible with
            new spec scope kinds.
        scope_id: opaque scope identifier (UUID in production, any TEXT
            string in tests).
        at: RFC 3339 UTC timestamp string with ``Z`` offset; lexicographic
            comparison matches temporal comparison for this format (W2.3
            db.py records the same format on every write).

    Returns:
        ``None`` if no event_log_entries row exists for (scope_kind,
        scope_id) at or before ``at`` (the scope did not exist yet).
        Otherwise a ``TemporalScopeStateRow``: when at least one
        ``*.transition`` summary row exists at or before ``at`` the row
        carries the latest ``to_state`` and ``epoch_after``; otherwise it
        carries the canonical initial state for the scope kind with
        ``epoch_at_t=0`` and the three ``last_event_*`` fields set to
        ``None``.

    Raises:
        Never raises on input shape; database failures surface their
        native sqlite3/aiosqlite exception types.
    """
    reader = database.acquire_reader()

    # Step 1: validate the scope existed at or before T (spec lines 6291-6296).
    # We mirror the PG NOT EXISTS check by counting rows in the same window.
    async with reader.execute(
        "SELECT 1 FROM event_log_entries "
        "WHERE scope_type = ? AND scope_id = ? AND occurred_at <= ? "
        "LIMIT 1",
        (scope_kind, scope_id, at),
    ) as cur:
        existence_row = await cur.fetchone()
    if existence_row is None:
        return None

    # Step 2: determine the initial state for this scope_kind. Spec lines
    # 6299-6306. An unknown scope_kind yields ``None`` (matches the PG
    # CASE WHEN with no ELSE clause: v_initial_state stays NULL).
    initial_state = _INITIAL_STATE_BY_SCOPE_KIND.get(scope_kind)

    # Step 3: locate the latest ``*.transition`` summary row at or before T.
    # The spec body orders by (occurred_at, ingest_sequence) ASC and then
    # picks the last row via ROW_NUMBER() DESC; SQLite reaches the same
    # answer with ORDER BY ... DESC LIMIT 1.
    async with reader.execute(
        "SELECT event_id, event_type, occurred_at, payload "
        "FROM event_log_entries "
        "WHERE scope_type = ? AND scope_id = ? AND occurred_at <= ? "
        "  AND event_type LIKE '%.transition%' "
        "ORDER BY occurred_at DESC, ingest_sequence DESC "
        "LIMIT 1",
        (scope_kind, scope_id, at),
    ) as cur:
        transition_row = await cur.fetchone()

    if transition_row is None:
        # Scope existed at T (step 1 was non-empty) but no transition
        # summary row has been emitted yet. Mirrors the PG LEFT JOIN
        # behaviour where ``last_transition`` is empty and the SELECT
        # returns ``(COALESCE(NULL, v_initial_state), COALESCE(NULL, 0),
        # NULL, NULL, NULL)``.
        return TemporalScopeStateRow(
            state=initial_state,
            epoch_at_t=0,
            last_event_id=None,
            last_event_type=None,
            last_event_at=None,
        )

    event_id, event_type, occurred_at, payload_text = transition_row

    # Parse payload (TEXT JSON in SQLite; the production write path uses
    # JCS canonical form so order is deterministic but we just read by key).
    try:
        payload = json.loads(payload_text) if payload_text else {}
    except (TypeError, ValueError):
        payload = {}

    to_state = payload.get("to_state")
    epoch_after_raw = payload.get("epoch_after", 0)
    try:
        epoch_after = int(epoch_after_raw)
    except (TypeError, ValueError):
        epoch_after = 0

    # Mirrors the PG ``COALESCE(lt.to_state, v_initial_state)`` and
    # ``COALESCE(lt.epoch_after, 0)``: when the transition row's payload
    # is missing the expected keys we fall back to the initial state /
    # epoch 0 rather than returning None.
    resolved_state = to_state if isinstance(to_state, str) else initial_state

    return TemporalScopeStateRow(
        state=resolved_state,
        epoch_at_t=epoch_after,
        last_event_id=str(event_id) if event_id is not None else None,
        last_event_type=str(event_type) if event_type is not None else None,
        last_event_at=str(occurred_at) if occurred_at is not None else None,
    )


__all__ = [
    "TemporalScopeStateRow",
    "reconstruct_scope_state_at_local",
]
