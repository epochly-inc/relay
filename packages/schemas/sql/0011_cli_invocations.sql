-- 0011_cli_invocations.sql
--
-- v0.2 OSS completeness, milestone M07 (w7-cli-invocations): canonical Postgres
-- DDL for the §AF cli_invocations table. Spec lines 5544-5567.
--
-- Every `rly` invocation MUST persist an entry-row on command start AND an
-- exit-row update on completion so the operator can reconstruct what ran,
-- by whom, against which manifest, and with what outcome. The row is
-- durable; even a process killed mid-invocation (SIGKILL) leaves its
-- entry-row in place for reconciliation (VAL-V2M07-036).
--
-- Per CLAUDE.md keystone invariant #1: cli_invocations are operator-audit
-- records, not canonical control-plane outcomes. The "outcome" field is a
-- summary derived from the process exit code; the canonical decision
-- (run_results, gate_decisions) is still written by the control plane.
--
-- Per CLAUDE.md keystone invariant #8: every persisted write to this table
-- passes through the transactional_db_write atomic primitive. Direct
-- conn.execute("INSERT INTO cli_invocations ...") outside the primitive is
-- a banned pattern and trips the CI lint guard (VAL-V2M07-037).
--
-- Per spec §G default-deny: argv_digest is a sha256 over the canonical
-- argv JSON with redaction-policy substitution applied first. Tokens
-- matching the policy (e.g., --token, --api-key, Bearer values) are
-- replaced with "<redacted>" before the digest is computed
-- (VAL-V2M07-038). Two invocations differing only in a redacted value
-- yield the same digest.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

CREATE TABLE IF NOT EXISTS cli_invocations (
    invocation_id           uuid        PRIMARY KEY,
    project_id              uuid        NOT NULL REFERENCES projects(project_id),
    command                 text        NOT NULL,
    argv_digest             text        NOT NULL,
    cli_version             text,
    invoker_kind            text        NOT NULL,
    invoker_user_id         uuid        REFERENCES users(user_id),
    ci_provider             text,
    ci_workflow_ref         text,
    ci_run_id               text,
    started_at              timestamptz NOT NULL DEFAULT now(),
    ended_at                timestamptz,
    exit_code               int,
    outcome                 text,
    draft_id                uuid        REFERENCES gate_decision_drafts(draft_id),
    decision_id             uuid        REFERENCES gate_decisions(gate_decision_id),
    retried_invocation_id   uuid        REFERENCES cli_invocations(invocation_id),
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
        ))
);

CREATE INDEX IF NOT EXISTS cli_invocations_project_time
    ON cli_invocations (project_id, started_at DESC);
