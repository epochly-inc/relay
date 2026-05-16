-- retention_sweep.sql
--
-- Canonical SELECT for the evidence-bundle retention sweep job (spec Y
-- line 5218; VAL-V2M01-029). The sweep delete-eligible set is exactly the
-- rows in evidence_bundle_registry whose state is in the open lifecycle
-- pair AND that are not held under legal hold:
--
--   state IN ('active','superseded') AND legal_hold_id IS NULL
--
-- Tombstoned rows are NEVER swept: a tombstone bundle is the compliant-
-- deletion record itself (spec Y line 5219), so removing it would erase
-- the only artifact of the deletion. Legal-hold rows are NEVER swept:
-- the existence of a non-null legal_hold_id pins the bundle until the
-- hold is released (state transitions back to 'active' once the hold's
-- own state moves to 'released' AND the registry row's legal_hold_id is
-- cleared by the writer).
--
-- This file is loaded by the retention sweep worker as a stable artifact
-- so the file sha256 lands in the evidence bundle for the sweep run
-- (CLAUDE.md keystone invariant #2: pass without evidence is not a pass).
-- The Python sweep-eligibility helper at
-- relay_schemas.bundle_registry.is_sweep_eligible mirrors the predicate
-- so unit tests can exercise the filter without a live database.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

SELECT
    evidence_bundle_id,
    state,
    superseded_by,
    subject_redacted_after_signing,
    redaction_event_ref,
    legal_hold_id,
    last_state_change_at
FROM
    evidence_bundle_registry
WHERE
    state IN ('active','superseded')
    AND legal_hold_id IS NULL
ORDER BY
    last_state_change_at ASC;
