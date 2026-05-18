-- 0000_v2_parent_tables.sql
--
-- Audit-R3 (2026-05-18): parent tables required as FK targets by downstream
-- canonical migrations. Per the 2026-05-18 audit, packages/schemas/sql/
-- 0004_v2_canonical_tables.sql declares FK constraints to runs(run_id),
-- projects(project_id), contracts(contract_id), and gates(gate_id), but no
-- DDL existed anywhere in packages/schemas/sql/ that created those parent
-- tables. Running migrations against a fresh Postgres database failed at
-- 0004 with "relation 'runs' does not exist".
--
-- Scope of this migration (intentionally narrow):
--   - runs       parent of run_results, contract_results, replay_results,
--                spans, root_cause_hypotheses, side_effect_markers.
--   - projects   parent of manifests, assertion_definitions, redaction_
--                policies, incidents, tool_side_effect_policies.
--   - contracts  parent of contract_results.
--   - gates      parent of gate_policies, gate_decisions, gate_decision_
--                drafts, gate_rounds, gate_stalled_state.
--
-- Each table carries the absolute minimum columns required to satisfy the
-- foreign-key target contract (PK + a created_at timestamp for ops
-- visibility). The hosted control plane will extend these tables (status
-- columns, billing fields, RBAC links, etc.) in private relay-platform
-- migrations -- but those extensions are additive and MUST preserve the
-- PK shape declared here.
--
-- Per CLAUDE.md keystone invariant #10: every persisted canonical envelope
-- carries schema_version pinned via SQL CHECK. ``gates`` declares one because
-- a canonical Gate envelope exists in envelopes.yaml + openapi.yaml + the
-- KNOWN_SCHEMA_IDS set (added by the same audit-R3 fix). runs / projects /
-- contracts do NOT carry schema_version here -- no canonical envelope exists
-- for them yet in envelopes.yaml; adding one prematurely would propagate
-- an unbacked literal across the codegen surface. When the spec promotes
-- those entities to canonical envelopes (planned for v0.3), a follow-up
-- migration adds the column with the appropriate Literal pin.
--
-- IF NOT EXISTS is intentional: these tables may already exist in
-- development databases where the audit fix was applied incrementally.
-- The shape declared here matches the FK targets in 0004 and 0010 byte-
-- for-byte; running this migration against a populated database is a
-- no-op.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- projects (parent of manifests, assertion_definitions, redaction_policies,
--           incidents, tool_side_effect_policies)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS projects (
    project_id  uuid PRIMARY KEY,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE(name)
);

-- -----------------------------------------------------------------------------
-- runs (parent of run_results, contract_results, replay_results, spans,
--       root_cause_hypotheses, side_effect_markers)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS runs (
    run_id      uuid PRIMARY KEY,
    project_id  uuid REFERENCES projects(project_id),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS runs_project ON runs(project_id);

-- -----------------------------------------------------------------------------
-- contracts (parent of contract_results)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS contracts (
    contract_id  uuid PRIMARY KEY,
    project_id   uuid REFERENCES projects(project_id),
    name         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_id, name)
);

-- -----------------------------------------------------------------------------
-- gates (parent of gate_policies, gate_decisions, gate_decision_drafts,
--        gate_rounds, gate_stalled_state)
--
-- Per CLAUDE.md keystone invariant #10: schema_version pinned to
-- relay.gate.v1 via SQL CHECK. The wire-format Literal pin lives in
-- relay_schemas.envelopes (added by audit-R3 alongside this migration).
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS gates (
    gate_id                  uuid PRIMARY KEY,
    project_id               uuid REFERENCES projects(project_id),
    name                     text NOT NULL,
    scope_type               text NOT NULL
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    enabled                  boolean NOT NULL DEFAULT true,
    draft_ttl_seconds        int NOT NULL DEFAULT 900
        CHECK (draft_ttl_seconds >= 1),
    remediation_round_cap    int NOT NULL DEFAULT 5
        CHECK (remediation_round_cap >= 1 AND remediation_round_cap <= 50),
    cascade_on_block         boolean NOT NULL DEFAULT true,
    schema_version           text NOT NULL DEFAULT 'relay.gate.v1'
        CHECK (schema_version = 'relay.gate.v1'),
    created_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS gates_project_name ON gates(project_id, name);
