-- W1-5 v2 OSS completeness, milestone M01: SQLite sidecar mirror of the
-- three sectionAE evidence-binding tables landed in
-- packages/schemas/sql/0006_human_oversight.sql.
--
-- The local sidecar is the OSS persistence profile (spec H.5 + spec AN
-- local profile). It mirrors the Postgres canonical shape but relaxes:
--
--   * uuid types -> TEXT (SQLite has no native uuid)
--   * timestamptz types -> TEXT (RFC 3339 strings; the wire-format layer
--     enforces tz-awareness via Pydantic)
--   * jsonb types -> TEXT (JSON-encoded; readers parse on demand)
--   * numeric -> NUMERIC (SQLite's type-affinity preserves arbitrary
--     numeric strings without lossy coercion)
--   * FOREIGN KEY clauses to tables that do not yet exist on the
--     sidecar profile are dropped with an inline comment explaining the
--     deferred FK chain.
--
-- CHECK constraints are PRESERVED across the SQLite mirror so the
-- closed enums (oversight_kind, check_kind, outcome, source_kind)
-- cannot accept out-of-set values even on the local profile.
--
-- All statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT
-- EXISTS so re-running on startup is a no-op (the migration loader at
-- relay_sidecar/db.py applies every .sql in lex order).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- ---- human_oversight_events (VAL-V2M01-030) ----
-- FK project_id -> projects, run_id -> runs,
-- ai_system_classification_id -> ai_system_classifications,
-- actor_user_id -> users all deferred (parent tables land with M02 / M03
-- or are not present on the sidecar profile at all). The sidecar
-- enforces application-level identity uniqueness through the ingest
-- worker.

CREATE TABLE IF NOT EXISTS human_oversight_events (
    oversight_id                  TEXT    PRIMARY KEY NOT NULL,
    project_id                    TEXT    NOT NULL,
    run_id                        TEXT,
    ai_system_classification_id   TEXT,
    oversight_kind                TEXT    NOT NULL,
    actor_user_id                 TEXT,
    decision                      TEXT,
    rationale                     TEXT,
    evidence_refs                 TEXT    NOT NULL DEFAULT '[]',
    occurred_at                   TEXT    NOT NULL,
    CONSTRAINT human_oversight_events_oversight_kind_enum
        CHECK (oversight_kind IN (
            'pre_action_review',
            'post_action_review',
            'escalation',
            'override',
            'manual_classification',
            'content_review'
        ))
);

CREATE INDEX IF NOT EXISTS human_oversight_events_project
    ON human_oversight_events(project_id);
CREATE INDEX IF NOT EXISTS human_oversight_events_run
    ON human_oversight_events(run_id);

-- ---- data_quality_checks (VAL-V2M01-031) ----
-- FK project_id -> projects deferred. dataset_id is left unconstrained
-- because the canonical dataset registry is a M03/M04 concern; the
-- ingest worker normalizes.

CREATE TABLE IF NOT EXISTS data_quality_checks (
    data_quality_check_id   TEXT      PRIMARY KEY NOT NULL,
    project_id              TEXT      NOT NULL,
    dataset_id              TEXT,
    check_kind              TEXT      NOT NULL,
    check_name              TEXT      NOT NULL,
    inputs_ref              TEXT,
    outcome                 TEXT      NOT NULL,
    metric_value            NUMERIC,
    threshold_value         NUMERIC,
    evaluator               TEXT      NOT NULL,
    evidence_refs           TEXT      NOT NULL DEFAULT '[]',
    performed_at            TEXT      NOT NULL,
    CONSTRAINT data_quality_checks_check_kind_enum
        CHECK (check_kind IN (
            'lineage',
            'representativeness',
            'duplicate_detection',
            'schema_conformance',
            'pii_minimization',
            'licensing',
            'staleness'
        )),
    CONSTRAINT data_quality_checks_outcome_enum
        CHECK (outcome IN ('pass','fail','warn','skipped','error'))
);

CREATE INDEX IF NOT EXISTS data_quality_checks_project
    ON data_quality_checks(project_id);
CREATE INDEX IF NOT EXISTS data_quality_checks_dataset
    ON data_quality_checks(dataset_id);

-- ---- data_provenance_records (VAL-V2M01-032) ----
-- FK project_id -> projects, acquired_by_user_id -> users deferred.

CREATE TABLE IF NOT EXISTS data_provenance_records (
    provenance_id           TEXT    PRIMARY KEY NOT NULL,
    project_id              TEXT    NOT NULL,
    dataset_id              TEXT    NOT NULL,
    source_kind             TEXT    NOT NULL,
    license_ref             TEXT,
    acquired_at             TEXT,
    acquired_by_user_id     TEXT,
    notes                   TEXT,
    evidence_refs           TEXT    NOT NULL DEFAULT '[]',
    CONSTRAINT data_provenance_records_source_kind_enum
        CHECK (source_kind IN (
            'first_party',
            'licensed',
            'public_domain',
            'web_scrape',
            'synthetic',
            'user_generated'
        ))
);

CREATE INDEX IF NOT EXISTS data_provenance_records_project
    ON data_provenance_records(project_id);
CREATE INDEX IF NOT EXISTS data_provenance_records_dataset
    ON data_provenance_records(dataset_id);
