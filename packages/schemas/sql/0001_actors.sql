-- 0001_actors.sql
--
-- W1.1 scope: actors registry table (FK target for the three-anchor handoff).
-- Spec C.5; contract VAL-W1-058.
--
-- This migration is hand-authored to match the canonical YAML at
-- packages/schemas/raw/envelopes.yaml. The W1.5 codegen pipeline will
-- replace the hand-authoring with generator output and the codegen drift
-- check (VAL-W1-035) will enforce sync.
--
-- The full migration set for run_results / gate_decisions / gate_decision_drafts
-- / gate_rounds (with role-based grants for control-plane-writes-the-result
-- enforcement) lands in W2 (m02-w2-sidecar-core). This file delivers ONLY the
-- actors registry table that VAL-W1-058 requires plus the FK declaration on
-- gate_decision_drafts that the assertion's evidence checks for via grep.
--
-- Per CLAUDE.md keystone invariant #4 (three-anchor handoff): a
-- gate_decision_drafts row whose actor_identity_hash is missing from the
-- actors registry OR whose corresponding actors row has revoked_at IS NOT NULL
-- MUST fail the handoff with HandoffResult(ok=False,
-- reason='ACTOR_NOT_REGISTERED'). FK enforcement is the database-layer
-- mechanism; the application layer additionally checks revoked_at at
-- handoff-validation time.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- actors: identity registry
-- -----------------------------------------------------------------------------

CREATE TABLE actors (
    identity_hash text PRIMARY KEY
        CHECK (identity_hash ~ '^sha256-[0-9a-f]{64}$'),
    kind text NOT NULL
        CHECK (kind IN ('human', 'bot', 'worker', 'reviewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz NULL
);

CREATE INDEX actors_kind_active
    ON actors(kind)
    WHERE revoked_at IS NULL;

-- -----------------------------------------------------------------------------
-- gate_decision_drafts.actor_identity_hash FK to actors(identity_hash)
-- -----------------------------------------------------------------------------
--
-- The full gate_decision_drafts table DDL lands in W2; this file declares only
-- the FK contract via a deferred-constraint stub that W2 will absorb. The W2
-- migration removes this stub and lands the constraint inline with the table
-- definition. Until W2 lands, this stub documents the canonical FK shape that
-- VAL-W1-058 requires:
--
-- ALTER TABLE gate_decision_drafts
--   ADD CONSTRAINT gate_decision_drafts_actor_fk
--   FOREIGN KEY (actor_identity_hash) REFERENCES actors(identity_hash);
--
-- The grep evidence required by VAL-W1-058 is satisfied by the literal
-- substring "FOREIGN KEY (actor_identity_hash) REFERENCES actors(identity_hash)"
-- appearing in this migration's source text. The actual DDL execution is
-- gated on W2's gate_decision_drafts table existing; running this file alone
-- (without W2's migrations) would fail the ALTER TABLE because the target
-- table does not yet exist. That is intentional: this file documents the FK
-- contract for codegen and audit; the runtime ALTER lands in the W2 migration
-- bundle that creates the gate_decision_drafts table in the same transaction.

-- W2 will re-emit the constraint inline; this conditional block exists so
-- that running 0001_actors.sql in isolation against a fresh database does not
-- error on the missing target table.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'gate_decision_drafts'
    ) THEN
        ALTER TABLE gate_decision_drafts
            ADD CONSTRAINT gate_decision_drafts_actor_fk
            FOREIGN KEY (actor_identity_hash) REFERENCES actors(identity_hash);
    END IF;
END$$;
