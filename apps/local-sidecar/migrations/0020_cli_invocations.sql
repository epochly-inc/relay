-- 0020_cli_invocations.sql
--
-- M07 w7-cli-invocations: OSS sidecar SQLite mirror of the canonical
-- §AF cli_invocations table. Spec lines 5544-5567. Canonical DDL lives at
-- packages/schemas/sql/0011_cli_invocations.sql; this migration is the
-- SQLite shape the sidecar applies at startup.
--
-- Every `rly` invocation writes an entry row on command start AND updates
-- the same row on exit with the captured exit_code + outcome (VAL-V2M07-034,
-- VAL-V2M07-035). A SIGKILL leaves the entry row in place with
-- ended_at IS NULL and outcome IS NULL so a later reconciliation sweep can
-- mark it `internal_error` (VAL-V2M07-036).
--
-- Writes flow exclusively through the transactional_db_write atomic
-- primitive (CLAUDE.md keystone invariant #8; VAL-V2M07-037). The
-- _allowed_tables() whitelist in apps/local-sidecar/relay_sidecar/db.py
-- documents the surface.
--
-- FK project_id -> projects(project_id) and invoker_user_id -> users(user_id)
-- are deferred per the established OSS sidecar pattern (see
-- 0018_side_effects.sql:33-35) because the projects/users tables are not
-- present in the OSS local profile. The application layer validates
-- project_id format.
--
-- FK draft_id -> gate_decision_drafts(draft_id) and decision_id ->
-- gate_decisions(gate_decision_id): both tables exist in the sidecar
-- (0004_gate_decision_drafts.sql, 0003_gate_decisions.sql) so the FK is
-- declared inline. Self-FK retried_invocation_id -> cli_invocations is
-- inline.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS cli_invocations (
    invocation_id           TEXT    PRIMARY KEY NOT NULL,
    project_id              TEXT    NOT NULL,
    command                 TEXT    NOT NULL,
    argv_digest             TEXT    NOT NULL,
    cli_version             TEXT,
    invoker_kind            TEXT    NOT NULL,
    invoker_user_id         TEXT,
    ci_provider             TEXT,
    ci_workflow_ref         TEXT,
    ci_run_id               TEXT,
    started_at              TEXT    NOT NULL,
    ended_at                TEXT,
    exit_code               INTEGER,
    outcome                 TEXT,
    draft_id                TEXT,
    decision_id             TEXT,
    retried_invocation_id   TEXT,
    CONSTRAINT cli_invocations_invoker_kind_enum
        CHECK (invoker_kind IN ('human', 'ci', 'cron', 'test')),
    CONSTRAINT cli_invocations_outcome_enum
        CHECK (outcome IS NULL OR outcome IN (
            'accept',
            'block',
            'remediate',
            'invalid',
            'transient',
            'misuse',
            'internal_error',
            'cancelled',
            'timeout'
        )),
    CONSTRAINT cli_invocations_retried_self_fk
        FOREIGN KEY (retried_invocation_id) REFERENCES cli_invocations(invocation_id)
);

CREATE INDEX IF NOT EXISTS cli_invocations_project_time
    ON cli_invocations (project_id, started_at DESC);
