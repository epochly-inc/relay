-- W9.1 migration 0001: eval_runs, eval_results, eval_run_deltas.
--
-- Adds the bookkeeping surface for VAL-W9-001 .. VAL-W9-008 + VAL-W9-021.
--
-- Spec anchors:
--   A   eval_runs (line 1899-1910): canonical aggregate row written by the
--       eval runner. Carries eval_run_id, dataset_id, agent_version,
--       release_sha, terminal status, score, and passed boolean.
--   AM.3 eval_run_deltas (line 5881-5898): delta-class table; append-only
--       per VAL-W9-004 -- a re-run against a new baseline writes new rows
--       carrying the new baseline_eval_run_id, never UPDATEs.
--
-- eval_results is not in spec A; W9.1 introduces it as the per-case
-- evidence-binding table. Each row binds to (artifact_hash, command_id,
-- exit_code, span_ids, manifest_commit_hash, assertion_id) per CLAUDE.md
-- keystone invariant #2 (pass without evidence is not a pass). A row
-- whose evidence is incomplete carries status='invalid', NOT 'failed'
-- (VAL-W9-007). The aggregate eval_runs row inherits status='invalid'
-- if any per-case row is invalid (VAL-W9-002).
--
-- The eval runner is forbidden from writing run_results or
-- gate_decisions (VAL-W9-008; CLAUDE.md keystone #1). Those tables live
-- in the sidecar migrations (apps/local-sidecar/migrations/) and are
-- written only by the state engine.
--
-- SQLite type accommodations:
--   - TEXT for uuid and timestamptz (ISO 8601 wire form)
--   - REAL for numeric (score in [0.0, 1.0])
--   - INTEGER for boolean (0 / 1)
--   - TEXT JSON for jsonb columns (summary, evidence_refs)
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- eval_runs  (spec A line 1899-1910; VAL-W9-001, VAL-W9-002, VAL-W9-007)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS eval_runs (
    eval_run_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL DEFAULT 'relay.eval_run.v1'
        CHECK (schema_version = 'relay.eval_run.v1'),
    project_id TEXT,
    dataset_id TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    release_sha TEXT NOT NULL,
    -- Closed five-member enum. Terminal states: passed, failed, invalid.
    -- pending and running are transient and may be written by the runner
    -- before the terminal write; the runner never returns from
    -- finalize_run with one of those as the persisted status.
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'running', 'passed', 'failed', 'invalid')),
    -- score is the per-case pass ratio in [0.0, 1.0]. Allowed NULL only
    -- while status IN ('pending', 'running') or when status='invalid' and
    -- the aggregate cannot be computed (VAL-W9-002).
    score REAL
        CHECK (score IS NULL OR (score >= 0.0 AND score <= 1.0)),
    passed INTEGER NOT NULL DEFAULT 0
        CHECK (passed IN (0, 1)),
    -- Required by VAL-W9-001: manifest_commit_hash is bound to the
    -- aggregate row so any down-stream evidence-bundle consumer can
    -- match the eval run against a manifest commit.
    manifest_commit_hash TEXT NOT NULL
        CHECK (manifest_commit_hash GLOB 'sha256-*'),
    -- VAL-W9-005: classifier parameter (flake_window_n) logged into
    -- summary alongside any other classifier metadata. Default '{}'
    -- keeps the column non-null.
    summary TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS eval_runs_dataset_agent
    ON eval_runs(dataset_id, agent_version, created_at DESC);

-- -----------------------------------------------------------------------------
-- eval_results  (W9.1 per-case evidence binding; VAL-W9-002, VAL-W9-007)
-- -----------------------------------------------------------------------------
--
-- Every per-case row binds to the five evidence anchors named in
-- CLAUDE.md keystone invariant #2 / VAL-W9-007:
--   (a) artifact_hash      -- SHA-256 of the input fixture
--   (b) command_id + exit_code -- evaluator invocation
--   (c) span_ids           -- trace spans covering the evaluator call
--   (d) manifest_commit_hash
--   (e) assertion_id       -- which assertion this case evaluates
--
-- A row missing any binding is persisted with status='invalid'; the
-- runner refuses to write status='passed' or status='failed' in that
-- case. Span ids are stored as a JSON array of strings (TEXT) under
-- span_ids. Pure-SQL enforcement of the inverse (status='passed' OR
-- 'failed' implies all five bindings present) is delegated to the
-- runner's finalize_case() and exercised by plumbing tests --
-- documented here to keep the migration narrow and idempotent.

CREATE TABLE IF NOT EXISTS eval_results (
    eval_result_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL DEFAULT 'relay.eval_result.v1'
        CHECK (schema_version = 'relay.eval_result.v1'),
    eval_run_id TEXT NOT NULL REFERENCES eval_runs(eval_run_id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    -- Closed three-member enum. invalid != failed: invalid means evidence
    -- is missing and the case has no admissible outcome; failed means
    -- evidence is complete and the assertion did not hold.
    status TEXT NOT NULL
        CHECK (status IN ('passed', 'failed', 'invalid')),
    -- Per-case observed and expected outcomes drive eval-delta classes
    -- (VAL-W9-003). Both are free-form TEXT to allow custom outcome
    -- spaces; the canonical pass_fail evaluator stores 'pass' / 'fail'.
    expected_outcome TEXT,
    observed_outcome TEXT,
    -- Evidence binding columns. Nullable in SQL; the runner enforces
    -- "status='passed' or 'failed' => all bindings present" at the
    -- Python layer (VAL-W9-007).
    artifact_hash TEXT
        CHECK (artifact_hash IS NULL OR artifact_hash GLOB 'sha256-*'),
    command_id TEXT,
    exit_code INTEGER,
    -- JSON array of trace span ids (strings).
    span_ids TEXT NOT NULL DEFAULT '[]',
    assertion_id TEXT,
    manifest_commit_hash TEXT
        CHECK (
            manifest_commit_hash IS NULL
            OR manifest_commit_hash GLOB 'sha256-*'
        ),
    -- Free-form context for the invalid-reason path (VAL-W9-007 evidence
    -- pairing guard log message).
    invalid_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (eval_run_id, case_id)
);

CREATE INDEX IF NOT EXISTS eval_results_run
    ON eval_results(eval_run_id);

-- -----------------------------------------------------------------------------
-- eval_run_deltas  (spec AM.3 line 5881-5898; VAL-W9-003, VAL-W9-004, VAL-W9-005)
-- -----------------------------------------------------------------------------
--
-- Append-only. A re-run of the eval-delta computation against the SAME
-- (eval_run_id, baseline_eval_run_id) pair MUST produce byte-identical
-- delta_id and row content (idempotent). A re-run with a DIFFERENT
-- baseline writes new rows tied to the new baseline_eval_run_id; old
-- rows remain unchanged (VAL-W9-004). The UNIQUE constraint enforces
-- the idempotency contract -- a duplicate (eval_run_id,
-- baseline_eval_run_id, case_id) INSERT is rejected.
--
-- delta_class enum: six members per spec AM.3 line 5886-5893.

CREATE TABLE IF NOT EXISTS eval_run_deltas (
    delta_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL DEFAULT 'relay.eval_run_delta.v1'
        CHECK (schema_version = 'relay.eval_run_delta.v1'),
    eval_run_id TEXT NOT NULL REFERENCES eval_runs(eval_run_id) ON DELETE CASCADE,
    baseline_eval_run_id TEXT NOT NULL REFERENCES eval_runs(eval_run_id),
    case_id TEXT NOT NULL,
    delta_class TEXT NOT NULL
        CHECK (delta_class IN (
            'net_new_failure',
            'net_new_success',
            'unchanged_pass',
            'unchanged_failure',
            'flaky',
            'baseline_absent'
        )),
    baseline_outcome TEXT,
    current_outcome TEXT,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (eval_run_id, baseline_eval_run_id, case_id)
);

CREATE INDEX IF NOT EXISTS eval_run_deltas_run
    ON eval_run_deltas(eval_run_id);

CREATE INDEX IF NOT EXISTS eval_run_deltas_baseline
    ON eval_run_deltas(baseline_eval_run_id);
