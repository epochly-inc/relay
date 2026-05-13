-- W2.4 migration 0003: gate_decisions (canonical gate decision).
--
-- Mirrors spec A.2 schema. The local-sidecar SQLite variant uses TEXT for
-- UUID + timestamptz + jsonb (SQLite has no native types). Foreign-key
-- REFERENCES are omitted on this OSS local profile; the hosted Postgres
-- deployment enforces FKs.
--
-- Per CLAUDE.md keystone invariant #1: the ``decided_by = 'gate_engine'``
-- CHECK is the SQL-layer enforcement of "only the gate engine writes gate
-- decisions." Per spec A.2 schema enum, ``action`` is restricted to
-- ('accept','remediate','block','invalid').
--
-- Idempotent (CREATE ... IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS gate_decisions (
    gate_decision_id        TEXT    PRIMARY KEY NOT NULL,
    schema_version          TEXT    NOT NULL DEFAULT 'relay.gate_decision.v1',
    gate_id                 TEXT    NOT NULL,
    scope_type              TEXT    NOT NULL,
    scope_id                TEXT    NOT NULL,
    round                   INTEGER NOT NULL,
    action                  TEXT    NOT NULL,
    strict_pass             INTEGER NOT NULL DEFAULT 0,
    failed_assertion_ids    TEXT    NOT NULL DEFAULT '[]',
    unmet_conditions        TEXT    NOT NULL DEFAULT '[]',
    evidence_bundle_id      TEXT    NOT NULL,
    cascade_on_block        INTEGER NOT NULL DEFAULT 1,
    decided_by              TEXT    NOT NULL DEFAULT 'gate_engine',
    decided_at              TEXT    NOT NULL,
    manifest_commit_hash    TEXT    NOT NULL,
    actor_identity_hash     TEXT    NOT NULL,
    signature               TEXT    NOT NULL,
    signature_key_id        TEXT    NOT NULL,
    CONSTRAINT decided_by_gate_engine
        CHECK (decided_by = 'gate_engine'),
    CONSTRAINT gate_decisions_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    CONSTRAINT gate_decisions_action_enum
        CHECK (action IN ('accept','remediate','block','invalid')),
    CONSTRAINT gate_decisions_round_positive
        CHECK (round >= 1),
    UNIQUE(gate_id, scope_type, scope_id, round)
);

CREATE INDEX IF NOT EXISTS ix_gate_decisions_scope
    ON gate_decisions(scope_type, scope_id, round);
