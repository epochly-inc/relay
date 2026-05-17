-- 0008_scope_state_extension.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1.7 scope: extend the
-- scope_state CHECK constraint to enumerate all SIX scope_kinds spec sectionW
-- declares (lines 5067-5113) and install a deferred-trigger initial-state
-- integrity guard.
--
-- Spec anchors:
--   sectionW lines 5072-5085   six scope_kind enumeration
--   sectionW lines 5095-5099   initialization rules; RELAY-STATE-001 on bad initial
--   sectionW lines 5101-5111   initial-state mapping per scope_kind (normative)
--   sectionW line 5112         deferred-trigger integrity rule (this migration)
--
-- The base migration (packages/schemas/sql/0002_control_plane.sql lines
-- 62-101) enumerated only the FOUR scope_kinds covered by spec sectionC.1
-- and marked the remaining two (eval_run, release) as deferred to a later
-- migration. This file is that later migration.
--
-- Three concerns land here:
--
--   1. Extend the scope_state.scope_kind CHECK constraint from
--      ('run','replay_case','gate_round','evidence_bundle')
--      to
--      ('run','replay_case','gate_round','evidence_bundle','eval_run','release').
--
--   2. Extend the scope_state.state per-kind CHECK to cover the eval_run
--      and release per-kind state sets:
--        eval_run  -> {pending, running, scored, terminal}
--        release   -> {open, gated, released, rolled_back, terminal}
--
--   3. Install the spec sectionW deferred-trigger initial-state guard:
--      a CONSTRAINT TRIGGER, DEFERRABLE INITIALLY DEFERRED, that runs at
--      COMMIT time on every INSERT into the six object tables (runs,
--      replay_cases, gate_rounds, evidence_bundles, eval_runs, releases)
--      and aborts the transaction when the matching scope_state row is
--      missing. This guarantees no object row exists in canonical storage
--      without a paired scope_state row.
--
--   4. Install the spec sectionW initial-state policy guard: a BEFORE INSERT
--      trigger on scope_state that aborts with RELAY-STATE-001 when a
--      newly-created row (epoch=0) carries any state other than the
--      transition-table-defined origin state for its scope_kind.
--
-- Object-table coverage handling:
--   Several object tables (runs, gate_rounds, eval_runs, releases) are
--   declared in parallel sibling features within milestone M01-W1 (the
--   eng-plan-locked sub-feature split puts each table's DDL in its own
--   migration). This migration uses DO $$ blocks per object table that
--   skip CONSTRAINT TRIGGER creation when the target table is not yet
--   present, mirroring the conditional FK pattern at
--   packages/schemas/sql/0004_v2_canonical_tables.sql lines 173-186.
--
--   Once the sibling features land, their migrations are responsible for
--   invoking the trigger-installer at the end of their own DDL block
--   (or re-running this migration against the populated catalog). The
--   trigger-installer is idempotent (DROP CONSTRAINT TRIGGER IF EXISTS
--   pattern via DO $$).
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result):
-- this migration extends scope_state's enforcement surface; it does not
-- grant any new write role. The state-engine module remains the only
-- caller that may transition scope_state rows.
--
-- Per CLAUDE.md keystone invariant #10 (schema versioning): the schema_version
-- pin (relay.scope_state.v1) is unchanged; no envelope version bump is
-- required because the wire format remains v1 with extended discriminator
-- variants (see envelopes.yaml + openapi.yaml updates landing in the same
-- feature).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---------------------------------------------------------------------------
-- VAL-V2M01-036: extend scope_state.scope_kind to enumerate all 6 kinds
-- ---------------------------------------------------------------------------

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_scope_kind_check;

-- The original 0002 migration declared the CHECK inline on the column;
-- depending on Postgres version the system-generated constraint name is
-- either scope_state_scope_kind_check (the most common form) or
-- scope_state_scope_kind1_check. We DROP both names defensively, then add
-- the canonical named constraint.

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_scope_kind1_check;

ALTER TABLE scope_state
    ADD CONSTRAINT scope_state_scope_kind_check
    CHECK (scope_kind IN (
        'run', 'replay_case', 'gate_round', 'evidence_bundle',
        'eval_run', 'release'
    ));

-- ---------------------------------------------------------------------------
-- VAL-V2M01-036 / VAL-V2M01-037: extend scope_state.state per-kind enum
-- ---------------------------------------------------------------------------
--
-- The 0002 migration's scope_state_state_per_kind CHECK enumerates only
-- four kinds. Drop and re-add with all six. The eval_run and release
-- per-kind state sets are sourced from spec sectionAM (eval_run lifecycle)
-- and spec sectionQ.2 (release lifecycle). Per spec sectionW table the
-- INITIAL state for each is enforced by the trigger below, NOT by this
-- CHECK; the CHECK encodes the legal set of states the engine may
-- transition into.

ALTER TABLE scope_state
    DROP CONSTRAINT IF EXISTS scope_state_state_per_kind;

ALTER TABLE scope_state
    ADD CONSTRAINT scope_state_state_per_kind CHECK (
        (scope_kind = 'run' AND state IN (
            'pending', 'captured', 'validating', 'gated',
            'result_written', 'terminal'
        ))
        OR (scope_kind = 'replay_case' AND state IN (
            'proposed', 'fixtures_ready', 'executing', 'analyzed',
            'terminal'
        ))
        OR (scope_kind = 'gate_round' AND state IN (
            'open', 'draft_received', 'evaluating', 'decision_written',
            'restarted', 'terminal'
        ))
        OR (scope_kind = 'evidence_bundle' AND state IN (
            'building', 'signed', 'published', 'superseded', 'revoked'
        ))
        OR (scope_kind = 'eval_run' AND state IN (
            'pending', 'running', 'scored', 'terminal'
        ))
        OR (scope_kind = 'release' AND state IN (
            'open', 'gated', 'released', 'rolled_back', 'terminal'
        ))
    );

-- ---------------------------------------------------------------------------
-- VAL-V2M01-037: initial-state policy trigger on scope_state INSERT
-- ---------------------------------------------------------------------------
--
-- Spec sectionW lines 5097-5099: "The initial state must be a
-- transition-table-defined origin state for the scope kind. Any other
-- initial state is a RELAY-STATE-001 and refuses creation."
--
-- A scope_state row is "initial" when its epoch = 0. Transitions through
-- compare_and_set_state increment epoch, so any later state is permitted
-- as long as the per-kind state CHECK constraint above allows it.
--
-- Initial-state mapping (spec sectionW table, lines 5101-5111):
--   run             -> pending
--   replay_case     -> proposed
--   gate_round      -> open
--   evidence_bundle -> building
--   eval_run        -> pending
--   release         -> open
--
-- The trigger fires BEFORE INSERT, aborting with the canonical
-- RELAY-STATE-001 marker for downstream error-envelope matching.

CREATE OR REPLACE FUNCTION relay_scope_state_initial_state_check()
    RETURNS trigger AS $$
DECLARE
    expected_initial text;
BEGIN
    -- Only validate true initial rows (epoch = 0). UPDATEs and engine
    -- transitions arrive with epoch > 0 and are out of scope here.
    IF NEW.epoch != 0 THEN
        RETURN NEW;
    END IF;
    expected_initial := CASE NEW.scope_kind
        WHEN 'run'             THEN 'pending'
        WHEN 'replay_case'     THEN 'proposed'
        WHEN 'gate_round'      THEN 'open'
        WHEN 'evidence_bundle' THEN 'building'
        WHEN 'eval_run'        THEN 'pending'
        WHEN 'release'         THEN 'open'
        ELSE NULL
    END;
    IF expected_initial IS NULL THEN
        -- scope_kind CHECK above will reject; this is defence-in-depth.
        RAISE EXCEPTION
            'RELAY-STATE-001: unknown scope_kind % for initial state',
            NEW.scope_kind;
    END IF;
    IF NEW.state != expected_initial THEN
        RAISE EXCEPTION
            'RELAY-STATE-001: initial state % invalid for scope_kind %; '
            'expected %', NEW.state, NEW.scope_kind, expected_initial;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scope_state_initial_state_check_trg ON scope_state;
CREATE TRIGGER scope_state_initial_state_check_trg
    BEFORE INSERT ON scope_state
    FOR EACH ROW
    EXECUTE FUNCTION relay_scope_state_initial_state_check();

-- ---------------------------------------------------------------------------
-- VAL-V2M01-038: deferred constraint trigger -- object row requires scope_state
-- ---------------------------------------------------------------------------
--
-- Spec sectionW line 5112: "A creating transaction that inserts an object
-- row without the matching scope_state row fails the integrity check at
-- commit (a deferred trigger validates the join). This guarantees that
-- every object the state engine can address has a state row from the
-- moment it exists."
--
-- The trigger function is shared across the six object tables. The
-- per-table CONSTRAINT TRIGGER carries the scope_kind as its argument
-- (TG_ARGV[0]) so the join target into scope_state is computed correctly.
-- DEFERRABLE INITIALLY DEFERRED means the check fires at COMMIT, allowing
-- the application to INSERT the object row first and the scope_state row
-- second within a single BEGIN..COMMIT block.

CREATE OR REPLACE FUNCTION relay_scope_state_paired_row_check()
    RETURNS trigger AS $$
DECLARE
    target_scope_kind text;
    target_pk_column  text;
    target_pk_value   uuid;
    row_count         int;
BEGIN
    -- Trigger arguments: (scope_kind, pk_column_name)
    -- Example: ('run', 'run_id'), ('evidence_bundle', 'evidence_bundle_id')
    target_scope_kind := TG_ARGV[0];
    target_pk_column  := TG_ARGV[1];
    EXECUTE format(
        'SELECT ($1).%I',
        target_pk_column
    ) INTO target_pk_value USING NEW;
    SELECT count(*) INTO row_count
        FROM scope_state
        WHERE scope_kind = target_scope_kind
          AND scope_id = target_pk_value;
    IF row_count = 0 THEN
        RAISE EXCEPTION
            'RELAY-STATE-002: object row inserted into table % '
            '(scope_kind=%, scope_id=%) without a matching scope_state '
            'row; the spec sectionW deferred trigger requires both rows '
            'to commit together',
            TG_TABLE_NAME, target_scope_kind, target_pk_value;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Install a DEFERRABLE INITIALLY DEFERRED CONSTRAINT TRIGGER on each of
-- the six object tables. Wrapped in DO $$ to skip tables not yet present
-- in the catalog (parallel-feature deferral).

-- runs
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'runs'
    ) THEN
        DROP TRIGGER IF EXISTS runs_scope_state_paired_check ON runs;
        CREATE CONSTRAINT TRIGGER runs_scope_state_paired_check
            AFTER INSERT ON runs
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('run', 'run_id');
    END IF;
END$$;

-- replay_cases
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'replay_cases'
    ) THEN
        DROP TRIGGER IF EXISTS replay_cases_scope_state_paired_check ON replay_cases;
        CREATE CONSTRAINT TRIGGER replay_cases_scope_state_paired_check
            AFTER INSERT ON replay_cases
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('replay_case', 'replay_case_id');
    END IF;
END$$;

-- gate_rounds
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'gate_rounds'
    ) THEN
        DROP TRIGGER IF EXISTS gate_rounds_scope_state_paired_check ON gate_rounds;
        CREATE CONSTRAINT TRIGGER gate_rounds_scope_state_paired_check
            AFTER INSERT ON gate_rounds
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('gate_round', 'gate_round_id');
    END IF;
END$$;

-- evidence_bundles
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'evidence_bundles'
    ) THEN
        DROP TRIGGER IF EXISTS evidence_bundles_scope_state_paired_check ON evidence_bundles;
        CREATE CONSTRAINT TRIGGER evidence_bundles_scope_state_paired_check
            AFTER INSERT ON evidence_bundles
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('evidence_bundle', 'evidence_bundle_id');
    END IF;
END$$;

-- eval_runs
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'eval_runs'
    ) THEN
        DROP TRIGGER IF EXISTS eval_runs_scope_state_paired_check ON eval_runs;
        CREATE CONSTRAINT TRIGGER eval_runs_scope_state_paired_check
            AFTER INSERT ON eval_runs
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('eval_run', 'eval_run_id');
    END IF;
END$$;

-- releases
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'releases'
    ) THEN
        DROP TRIGGER IF EXISTS releases_scope_state_paired_check ON releases;
        CREATE CONSTRAINT TRIGGER releases_scope_state_paired_check
            AFTER INSERT ON releases
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION relay_scope_state_paired_row_check('release', 'release_id');
    END IF;
END$$;
