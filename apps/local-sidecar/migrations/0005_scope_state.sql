-- W2.4 migration 0005: scope_state (mutable scope state for compare_and_set_state).
--
-- Mirrors spec W (scope_state table; lines 5067-5093). This is the single
-- source of mutable scope state per (kind, id) referenced by the
-- ``compare_and_set_state`` primitive (spec C.4). ``epoch`` is the
-- optimistic-concurrency counter: a successful transition increments it by
-- exactly one (VAL-W2-027 stale-epoch race relies on this).
--
-- Per spec W initialization rules: the initial state must be a transition-
-- table-defined origin state for the scope kind. Enforcement of that rule
-- lives in the state-engine code, not in SQL (it depends on the YAML).
--
-- Per CLAUDE.md keystone invariant #1 + VAL-W2-058: writes to this table
-- are made ONLY by the state-engine module. Direct writes from other
-- callers are blocked by the grep-test + AST-lint guards in W2.4 tests.
--
-- Idempotent.

CREATE TABLE IF NOT EXISTS scope_state (
    scope_kind       TEXT    NOT NULL,
    scope_id         TEXT    NOT NULL,
    project_id       TEXT    NOT NULL,
    state            TEXT    NOT NULL,
    epoch            INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    PRIMARY KEY (scope_kind, scope_id),
    CONSTRAINT scope_state_kind_enum CHECK (scope_kind IN (
        'run','replay_case','gate_round','evidence_bundle','eval_run','release'
    )),
    CONSTRAINT scope_state_epoch_nonneg CHECK (epoch >= 0)
);

CREATE INDEX IF NOT EXISTS ix_scope_state_project_kind_state
    ON scope_state(project_id, scope_kind, state);
