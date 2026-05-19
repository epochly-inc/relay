-- V3M1-F07 (2026-05-18) sidecar migration 0028: SQLite mirror of the
-- evidence_claims spec K rule checks landed by Postgres migration
-- packages/schemas/sql/0015_v3_claim_rule_checks.sql.
--
-- Spec authority: section K rule line 4430-4432 verbatim:
--
--   "A supersedes_claim_id is allowed only for human_oversight and
--   incident claim types -- never for run_result or gate_decision."
--
-- SQLite does NOT support ALTER TABLE ADD CONSTRAINT CHECK after the
-- table is created (confirmed by m1-f05 sidecar migration 0027 header
-- line 18-19). The equivalent enforcement is via a BEFORE INSERT /
-- BEFORE UPDATE trigger that fires when the rule is violated and calls
-- RAISE(ABORT, '...supersedes_only_oversight_incident...'). The rule
-- name embedded in the abort message lets callers catching
-- ``sqlite3.IntegrityError`` attribute the violation by name rather
-- than by free-text parsing (mirrors the constraint-name convention on
-- the Postgres side).
--
-- The pattern (DROP TRIGGER IF EXISTS + CREATE TRIGGER) mirrors the
-- precedent at apps/local-sidecar/migrations/0022_scope_state_per_kind_check.sql
-- (the per-kind state-check triggers). It is idempotent on partial
-- re-runs.
--
-- This migration does NOT data-migrate any existing rows. BEFORE
-- triggers fire only on new INSERT/UPDATE statements; pre-existing
-- violating rows (if any) remain in place and must be cleaned by the
-- operator. m1-f05 just landed, so no production rows are expected to
-- carry the violating combination.
--
-- Per CLAUDE.md keystone invariant #1 ("control plane writes the
-- result") this migration adds NO new write privileges; the rule is
-- enforced at the persistence boundary regardless of which control-plane
-- writer attempts the INSERT/UPDATE.
--
-- Per CLAUDE.md keystone invariant #10, ``schema_version`` remains
-- pinned to ``relay.evidence_claim.v1`` (this migration adds no fields).
--
-- The sidecar SQL parser splits on semicolon-terminated statements;
-- SQLite's parser correctly parses BEGIN ... END trigger bodies as a
-- single statement when the outer END is followed by ``;`` (mirrors
-- 0022_scope_state_per_kind_check.sql).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- BEFORE INSERT: reject any new row that violates the supersedes rule.
-- -----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS supersedes_only_oversight_incident_insert_trg;
CREATE TRIGGER supersedes_only_oversight_incident_insert_trg
BEFORE INSERT ON evidence_claims
FOR EACH ROW
WHEN NEW.supersedes_claim_id IS NOT NULL
    AND NEW.claim_type NOT IN ('human_oversight', 'incident')
BEGIN
    SELECT RAISE(
        ABORT,
        'supersedes_only_oversight_incident: supersedes_claim_id is allowed only for claim_type IN (human_oversight, incident) per spec K line 4430-4432'
    );
END;

-- -----------------------------------------------------------------------------
-- BEFORE UPDATE: same rule applied on every mutation of either column.
-- -----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS supersedes_only_oversight_incident_update_trg;
CREATE TRIGGER supersedes_only_oversight_incident_update_trg
BEFORE UPDATE ON evidence_claims
FOR EACH ROW
WHEN NEW.supersedes_claim_id IS NOT NULL
    AND NEW.claim_type NOT IN ('human_oversight', 'incident')
BEGIN
    SELECT RAISE(
        ABORT,
        'supersedes_only_oversight_incident: supersedes_claim_id is allowed only for claim_type IN (human_oversight, incident) per spec K line 4430-4432'
    );
END;
