-- 0006_human_oversight.sql
--
-- v0.2 OSS completeness, milestone M01, feature w1-5 scope: canonical
-- Postgres DDL for the three sectionAE evidence-binding tables surfaced
-- by the 2026-05-16 spec audit as missing from public relay/. Without
-- first-class rows for human oversight, data-quality checks, and
-- data-provenance records, evidence claims that reference them are not
-- buildable (spec sectionAE line 5492: "Evidence claims reference these;
-- without first-class rows they are not buildable").
--
--   human_oversight_events     (spec AE lines 5494-5508)
--   data_quality_checks        (spec AE lines 5510-5525)
--   data_provenance_records    (spec AE lines 5527-5539)
--
-- Per CLAUDE.md keystone invariant #1 the canonical write path for these
-- tables is the control plane's result-writer / evidence-binding service.
-- The role-based grants land with the hosted API surface (M02); this
-- migration delivers DDL shape only.
--
-- Per CLAUDE.md keystone invariant #10 every persisted envelope carries
-- ``schema_version`` at the wire-format layer (relay_schemas.envelopes
-- pins via Literal[...]). The SQL tables do not store the envelope
-- ``schema_version`` literal directly; it is carried in the canonical
-- on-wire payload that flows through the ingest path.
--
-- Some FK targets (projects, runs, ai_system_classifications, users)
-- may not be present when this migration is applied against a fresh
-- database without those targets present. Following the conditional FK
-- pattern at packages/schemas/sql/0004_v2_canonical_tables.sql lines
-- 173-186, FKs to tables that may be deferred are declared inline; the
-- conditional resolution lives in subsequent migrations or the
-- project-creation bootstrap. The ``projects`` table is the canonical
-- tenant root and is required for every row in these three tables.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- human_oversight_events (spec AE lines 5494-5508; VAL-V2M01-030)
-- -----------------------------------------------------------------------------
--
-- Captures every human-in-the-loop oversight event tied to a project,
-- optional run, and optional AI-system classification (spec AC). The
-- closed six-member ``oversight_kind`` enum is locked at the SQL layer;
-- the wire-format layer mirrors the enum on the HumanOversightEvent
-- Pydantic model.
--
-- ``evidence_refs`` is a JSON array of evidence-bundle / evidence-claim
-- references (canonical Relay reference form, e.g.
-- ``"bundle:<bundle_id>"`` or ``"claim:<claim_id>"``) that bind the
-- oversight event to durable, signed evidence. Defaults to the empty
-- array so a freshly-created oversight event can be progressively
-- enriched before sealing.

CREATE TABLE human_oversight_events (
    oversight_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    run_id uuid REFERENCES runs(run_id),
    ai_system_classification_id uuid
        REFERENCES ai_system_classifications(classification_id),
    oversight_kind text NOT NULL
        CHECK (oversight_kind IN (
            'pre_action_review',
            'post_action_review',
            'escalation',
            'override',
            'manual_classification',
            'content_review'
        )),
    actor_user_id uuid REFERENCES users(user_id),
    decision text,
    rationale text,
    evidence_refs jsonb NOT NULL DEFAULT '[]',
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX human_oversight_events_project ON human_oversight_events(project_id);
CREATE INDEX human_oversight_events_run ON human_oversight_events(run_id);

-- -----------------------------------------------------------------------------
-- data_quality_checks (spec AE lines 5510-5525; VAL-V2M01-031)
-- -----------------------------------------------------------------------------
--
-- Per-dataset data-quality check rows. The closed seven-member
-- ``check_kind`` enum and closed five-member ``outcome`` enum are locked
-- at the SQL layer; the wire-format layer mirrors both enums on the
-- DataQualityCheck Pydantic model.
--
-- ``evaluator`` follows the spec sectionAE narrative: the canonical form
-- is ``code:<module>.<fn>:vN`` for a code-based check or
-- ``human:<user_id>`` for a human-evaluated check. The wire-format layer
-- does not lock the evaluator grammar; the ingest worker normalizes.
--
-- ``metric_value`` and ``threshold_value`` are unconstrained numerics --
-- the spec's example is a representativeness coverage ratio in [0, 1],
-- but other kinds (duplicate counts, staleness ages in seconds) require
-- the wider range. The wire-format layer does not impose a unit.

CREATE TABLE data_quality_checks (
    data_quality_check_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    dataset_id uuid,
    check_kind text NOT NULL
        CHECK (check_kind IN (
            'lineage',
            'representativeness',
            'duplicate_detection',
            'schema_conformance',
            'pii_minimization',
            'licensing',
            'staleness'
        )),
    check_name text NOT NULL,
    inputs_ref text,
    outcome text NOT NULL
        CHECK (outcome IN ('pass','fail','warn','skipped','error')),
    metric_value numeric,
    threshold_value numeric,
    evaluator text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]',
    performed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX data_quality_checks_project ON data_quality_checks(project_id);
CREATE INDEX data_quality_checks_dataset ON data_quality_checks(dataset_id);

-- -----------------------------------------------------------------------------
-- data_provenance_records (spec AE lines 5527-5539; VAL-V2M01-032)
-- -----------------------------------------------------------------------------
--
-- Per-dataset provenance row. The closed six-member ``source_kind`` enum
-- is locked at the SQL layer; the wire-format layer mirrors the enum on
-- the DataProvenanceRecord Pydantic model.
--
-- ``license_ref`` is the canonical license identifier (SPDX expression
-- preferred, e.g. ``"Apache-2.0"`` / ``"CC-BY-4.0"``) or a customer
-- license-registry URI. The wire-format layer does not lock the grammar;
-- the ingest worker normalizes. ``notes`` is a free-form audit field.

CREATE TABLE data_provenance_records (
    provenance_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    dataset_id uuid NOT NULL,
    source_kind text NOT NULL
        CHECK (source_kind IN (
            'first_party',
            'licensed',
            'public_domain',
            'web_scrape',
            'synthetic',
            'user_generated'
        )),
    license_ref text,
    acquired_at timestamptz,
    acquired_by_user_id uuid REFERENCES users(user_id),
    notes text,
    evidence_refs jsonb NOT NULL DEFAULT '[]'
);

CREATE INDEX data_provenance_records_project ON data_provenance_records(project_id);
CREATE INDEX data_provenance_records_dataset ON data_provenance_records(dataset_id);
