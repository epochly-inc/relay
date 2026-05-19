-- 0015_v3_claim_rule_checks.sql
--
-- V3M1-F07 (2026-05-18): canonical Postgres CHECK constraints for the
-- ``evidence_claims`` rule set declared by spec section K lines
-- 4427-4432. The historical evidence_claims DDL (0003_evidence_replay.sql
-- lines 76-104) and the m1-f05 column-additions migration
-- (0014_v3_evidence_claim_shape.sql) deferred this rule explicitly to
-- m1-f07 (see 0014 header comment line 28-29). This migration delivers
-- the deferred constraint.
--
-- Spec authority: section K rule line 4430-4432 verbatim:
--
--   "A supersedes_claim_id is allowed only for human_oversight and
--   incident claim types -- never for run_result or gate_decision."
--
-- The CHECK clause:
--
--   (supersedes_claim_id IS NULL OR claim_type IN ('human_oversight','incident'))
--
-- evaluates true iff the rule holds. The constraint name
-- ``supersedes_only_oversight_incident`` encodes the rule for
-- greppability so a downstream caller catching a CHECK violation can
-- attribute it without parsing free-text error messages.
--
-- Per CLAUDE.md keystone invariant #1 ("control plane writes the
-- result") this migration adds NO new write privileges; the rule is
-- enforced at the persistence boundary regardless of which control-plane
-- writer attempts the INSERT.
--
-- Per CLAUDE.md keystone invariant #10, ``schema_version`` remains
-- pinned to ``relay.evidence_claim.v1`` (this migration adds no fields).
--
-- Idempotency: DROP CONSTRAINT IF EXISTS is paired with ADD CONSTRAINT
-- so partial re-runs of the migration do not fail. The pattern mirrors
-- m1-f05's actor_kind / actor_identity_hash CHECK migration (see
-- 0014_v3_evidence_claim_shape.sql lines 87-93).
--
-- Note: this migration does NOT data-migrate any existing rows. If a
-- pre-existing row violates the constraint the ADD CONSTRAINT will fail
-- and the operator must inspect and clean before re-running. The rule's
-- intent is that the violation be surfaced and corrected, not silently
-- rewritten. m1-f05 just landed, so no production rows are expected to
-- carry the violating combination.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

BEGIN;

-- -----------------------------------------------------------------------------
-- supersedes_claim_id rule (spec K line 4430-4432; VAL-V3M1-017)
-- -----------------------------------------------------------------------------
-- Drop-then-add for idempotency on partial re-runs. The constraint
-- name is the canonical identifier callers grep for.
ALTER TABLE evidence_claims
    DROP CONSTRAINT IF EXISTS supersedes_only_oversight_incident;

ALTER TABLE evidence_claims
    ADD CONSTRAINT supersedes_only_oversight_incident
        CHECK (
            supersedes_claim_id IS NULL
            OR claim_type IN ('human_oversight', 'incident')
        );

COMMIT;
