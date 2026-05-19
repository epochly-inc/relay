-- 0017_v3_temporal_query.sql
--
-- V3M3-F03 (2026-05-19): canonical Postgres install of the section AP.5.a
-- temporal-query primitive ``reconstruct_scope_state_at(scope_kind,
-- scope_id, at)``. The function reconstructs the inferred state-machine
-- state of any scope at any timestamp by replaying the matching
-- ``event_log_entries`` ``*.transition`` summary rows up to T.
--
-- Spec authority: planning/epochly-replay-spec.md lines 6273-6336
-- (PL/pgSQL function body) plus the spec section AP.5.c
-- ``*.transition`` emission contract that the sidecar state engine
-- implements at apps/local-sidecar/relay_sidecar/state_engine/
-- compare_and_set.py:707-756 (m3-f02).
--
-- Why this migration ships now
-- ----------------------------
-- Audit V3 finding VAL-V3M3-006 / -007 / -008 / -009 / -010 noted that
-- the canonical Postgres profile is missing a primitive named in the
-- spec. The function is required for three downstream use cases the
-- spec calls out at lines 6339-6343:
--
--   * Incident postmortems ("what state was run X in at 14:32 UTC?")
--   * Audit responses ("which gate rounds were in decision_written at
--     the end of 2026-04-30?")
--   * Customer support ("why does the run show as blocked now when it
--     was accepted yesterday?")
--
-- The function is STABLE: it is a pure function of the event_log_entries
-- table at the snapshot visible inside the calling transaction. STABLE
-- is the correct volatility class because the function may be invoked
-- repeatedly inside a single query (e.g., a daily snapshot batch) and
-- must return the same answer for the same arguments within one
-- statement; it is NOT IMMUTABLE because event_log_entries is updated
-- by ongoing state transitions.
--
-- Spec vs. canonical-DDL naming reconciliation
-- --------------------------------------------
-- The spec body at line 6293 says ``WHERE scope_kind = p_scope_kind``.
-- The canonical event_log_entries DDL ships the column as ``scope_type``
-- (packages/schemas/sql/0002_control_plane.sql:143) and the SQLite
-- mirror does the same (apps/local-sidecar/migrations/0001_event_log_entries.sql:33).
-- This migration honours the column name actually present in the
-- catalog -- ``scope_type`` -- while preserving the
-- spec-advertised parameter name ``p_scope_kind`` so the function
-- signature still matches the spec verbatim.
--
-- The sidecar Python equivalent
-- ``apps/local-sidecar/relay_sidecar/state_engine/temporal_query.py:
-- reconstruct_scope_state_at_local`` applies the same translation.
-- Cross-tier parity is asserted by
-- ``packages/schemas/python/tests/test_v3m3_temporal_query_parity.py``
-- (VAL-V3M3-009).
--
-- Supporting index
-- ----------------
-- VAL-V3M3-007 requires a covering index for the temporal query so the
-- reconstruction stays cheap as event_log_entries grows. The index
-- ``event_log_entries_temporal_lookup`` matches the function's WHERE +
-- ORDER BY clauses: filter on (scope_type, scope_id, occurred_at) and
-- break the (occurred_at, ingest_sequence) tie deterministically.
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the
-- result): this migration adds a READ-ONLY function and an index. No
-- new write privileges are granted; no SECURITY DEFINER. The function
-- can be invoked by anyone with SELECT on event_log_entries; production
-- access is governed by role grants in the hosted profile.
--
-- Per CLAUDE.md keystone invariant #10 (schema versioning): no
-- envelope wire format changes here. The function reads payload
-- attributes written by m3-f02 with the existing
-- ``relay.event_log_entry.v1`` schema_version.
--
-- Idempotency: ``CREATE OR REPLACE FUNCTION`` permits re-running the
-- migration without DROP; ``CREATE INDEX IF NOT EXISTS`` (Postgres
-- 9.5+) makes the index install idempotent.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

BEGIN;

-- ---------------------------------------------------------------------------
-- VAL-V3M3-007: supporting index for the temporal query.
-- ---------------------------------------------------------------------------
--
-- The index keys ``(scope_type, scope_id, occurred_at, ingest_sequence)``
-- exactly match the WHERE + ORDER BY of the function below. The
-- existing index ``event_log_scope`` on
-- ``(scope_type, scope_id, occurred_at DESC)`` (per
-- packages/schemas/sql/0002_control_plane.sql:165-166) is the same
-- shape minus the ``ingest_sequence`` tiebreak; we add the explicit
-- four-column index so the planner can serve the function's
-- ``ORDER BY ... DESC LIMIT 1`` from a single index seek without
-- consulting the heap.

CREATE INDEX IF NOT EXISTS event_log_entries_temporal_lookup
    ON event_log_entries(scope_type, scope_id, occurred_at, ingest_sequence);

-- ---------------------------------------------------------------------------
-- VAL-V3M3-006 / VAL-V3M3-010: reconstruct_scope_state_at function.
-- ---------------------------------------------------------------------------
--
-- Spec body verbatim (planning/epochly-replay-spec.md lines 6273-6336)
-- with the spec-vs-DDL column-naming reconciliation described above
-- (every body reference to ``scope_kind`` becomes ``scope_type``; the
-- function parameter name ``p_scope_kind`` is preserved).

CREATE OR REPLACE FUNCTION reconstruct_scope_state_at(
    p_scope_kind text,
    p_scope_id uuid,
    p_at timestamptz
) RETURNS TABLE (
    state text,
    epoch_at_t bigint,
    last_event_id uuid,
    last_event_type text,
    last_event_at timestamptz
) AS $$
DECLARE
    v_initial_state text;
BEGIN
    -- Validate the scope was created at or before T.
    IF NOT EXISTS (
        SELECT 1 FROM event_log_entries
        WHERE scope_type = p_scope_kind AND scope_id = p_scope_id AND occurred_at <= p_at
    ) THEN
        RETURN;  -- scope did not exist at T
    END IF;

    -- Determine the initial state for this scope_kind (per section W initial-state mapping).
    v_initial_state := CASE p_scope_kind
        WHEN 'run' THEN 'pending'
        WHEN 'replay_case' THEN 'proposed'
        WHEN 'gate_round' THEN 'open'
        WHEN 'evidence_bundle' THEN 'building'
        WHEN 'eval_run' THEN 'pending'
        WHEN 'release' THEN 'open'
    END;

    -- Replay transitions in order to derive the state at T.
    -- payload->>'to_state' is written by every state transition event (see section C.3).
    RETURN QUERY
    WITH transitions AS (
        SELECT
            event_id, event_type, occurred_at,
            payload->>'to_state' AS to_state,
            (payload->>'epoch_after')::bigint AS epoch_after,
            ROW_NUMBER() OVER (ORDER BY occurred_at, ingest_sequence) AS rn
        FROM event_log_entries
        WHERE scope_type = p_scope_kind
          AND scope_id = p_scope_id
          AND occurred_at <= p_at
          AND event_type LIKE '%.transition%'   -- only state-transition events
        ORDER BY occurred_at, ingest_sequence
    ),
    last_transition AS (
        SELECT * FROM transitions ORDER BY rn DESC LIMIT 1
    )
    SELECT
        COALESCE(lt.to_state, v_initial_state),
        COALESCE(lt.epoch_after, 0),
        lt.event_id,
        lt.event_type,
        lt.occurred_at
    FROM (VALUES (NULL::uuid, NULL::text, NULL::timestamptz)) AS empty(event_id, event_type, occurred_at)
    LEFT JOIN last_transition lt ON TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

COMMIT;
