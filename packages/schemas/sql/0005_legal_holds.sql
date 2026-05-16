-- 0005_legal_holds.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1-4 scope: legal holds +
-- evidence_bundle_registry. Closes the gap surfaced by the 2026-05-16 spec
-- audit: the incident runbook references evidence_legal_holds but no DDL
-- existed, and signed evidence bundles have no mutable sibling row that
-- can carry supersession / redaction / legal-hold state without mutating
-- the immutable signed bytes.
--
--   evidence_legal_holds         (spec Y lines 5184-5200)
--   evidence_bundle_registry     (spec Y lines 5202-5213)
--
-- Per CLAUDE.md keystone invariant #1: signed bundle bytes
-- (evidence_bundles) are immutable; direct UPDATE on evidence_bundles by
-- any role other than the writer is denied at the DB role layer (M02
-- delivers the runtime REVOKE). This file documents that boundary via
-- the inline comment "signed bundle bytes / role"; the mutable mirror
-- evidence_bundle_registry is the row that records supersession +
-- redaction + legal-hold state.
--
-- Per spec Y line 5218: the retention sweep job filters by
--   evidence_bundle_registry.state IN ('active','superseded')
--   AND legal_hold_id IS NULL
-- That stable query lives at packages/schemas/sql/queries/retention_sweep.sql
-- so the digest in evidence bundles is reproducible.
--
-- Per spec Y line 5219: the "compliant deletion without mutating signed
-- content" mechanism is the subject_redaction_tombstone claim carried on
-- a NEW superseding bundle (tombstoned state on the registry). Tombstoned
-- is a terminal state: once a bundle is tombstoned, the registry row does
-- not transition back. The state-machine validator
-- relay_schemas.bundle_registry.validate_registry_transition enforces
-- this at the wire-format layer; the SQL CHECK above pins the closed
-- enum but does not encode the transition rules (the writer service
-- carries them).
--
-- FK targets that may not exist yet on a fresh database (orgs, users)
-- are added conditionally via DO $$ blocks mirroring the approach in
-- 0001_actors.sql lines 67-80 and 0004_v2_canonical_tables.sql lines
-- 173-186. Running 0005 in isolation creates the tables without the
-- unresolved FKs; running it after the target tables exist absorbs the
-- FKs inline.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- evidence_legal_holds (spec Y lines 5184-5200; VAL-V2M01-026)
-- -----------------------------------------------------------------------------

CREATE TABLE evidence_legal_holds (
    hold_id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES orgs(org_id),
    scope_kind text NOT NULL
        CHECK (scope_kind IN ('org','project','run','evidence_bundle')),
    scope_id uuid NOT NULL,
    reason text NOT NULL,
    legal_matter_ref text,
    imposed_by_user_id uuid NOT NULL REFERENCES users(user_id),
    counsel_signoff_at timestamptz,
    counsel_signoff_by text,
    state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','released')),
    imposed_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    released_by_user_id uuid REFERENCES users(user_id)
);

-- Partial index on the active subset accelerates the
-- "is this scope under hold?" lookup the retention sweep performs.
CREATE INDEX evidence_legal_holds_active ON evidence_legal_holds(scope_kind, scope_id) WHERE state = 'active';

-- -----------------------------------------------------------------------------
-- evidence_bundle_registry (spec Y lines 5202-5213; VAL-V2M01-027)
-- -----------------------------------------------------------------------------
--
-- Mutable sibling to the immutable signed evidence_bundles table. The
-- signed bundle bytes never change once committed; this registry row
-- mutates as the bundle is superseded, redacted (subject deletion via
-- tombstone), or placed under legal hold. The closed four-member state
-- enum is pinned at the SQL layer; the wire-format layer mirrors via
-- the EvidenceBundleRegistry Pydantic model and the
-- validate_registry_transition state-machine helper.

CREATE TABLE evidence_bundle_registry (
    evidence_bundle_id uuid PRIMARY KEY REFERENCES evidence_bundles(evidence_bundle_id),
    state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','superseded','tombstoned','legal_hold')),
    superseded_by uuid REFERENCES evidence_bundles(evidence_bundle_id),
    subject_redacted_after_signing boolean NOT NULL DEFAULT false,
    redaction_event_ref text,
    legal_hold_id uuid REFERENCES evidence_legal_holds(hold_id),
    last_state_change_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX evidence_bundle_registry_state ON evidence_bundle_registry(state);
CREATE INDEX evidence_bundle_registry_legal_hold ON evidence_bundle_registry(legal_hold_id) WHERE legal_hold_id IS NOT NULL;
