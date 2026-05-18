-- V3M1-F05 (2026-05-18) sidecar migration 0027: SQLite mirror of the
-- evidence_claims spec K shape extension.
--
-- Mirrors packages/schemas/sql/0014_v3_evidence_claim_shape.sql. Per
-- spec K lines 4388-4438 the EvidenceClaim envelope carries 7
-- new/restructured fields beyond the historical flat-subject shape
-- landed by 0003_evidence_replay.sql. This migration brings the OSS
-- sidecar SQLite mirror to parity with the hosted Postgres profile.
--
-- SQLite-vs-Postgres deltas (consistent with the rest of the sidecar
-- mirror set):
--   1. JSONB columns -> TEXT (SQLite has no native JSON type;
--      application layer parses/serializes JSON text).
--   2. TIMESTAMPTZ -> TEXT (SQLite stores timestamps as ISO 8601
--      strings; sidecar code normalizes RFC 3339 wire form).
--   3. CHECK constraints applied identically; SQLite supports them
--      via column-level / table-level syntax. SQLite does NOT support
--      ALTER TABLE ADD CONSTRAINT after the fact for CHECK, so we
--      attach the CHECK inline on the ADD COLUMN where possible.
--   4. Partial indexes (`WHERE col IS NOT NULL`) are supported by
--      SQLite 3.8.0+.
--
-- Per CLAUDE.md keystone invariant #1, writes to ``evidence_claims`` on
-- the sidecar are gated by the existing control-plane writer; this
-- migration adds no new write privileges.
--
-- Per CLAUDE.md keystone invariant #10, ``schema_version`` remains
-- pinned to ``relay.evidence_claim.v1``.
--
-- The sidecar SQL parser splits on semicolon-terminated statements;
-- each ALTER TABLE statement stands alone. No outer BEGIN/COMMIT
-- because the sidecar migration runner wraps the file in a single
-- implicit transaction (see relay_sidecar.migrations.apply()).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- evidence_refs (spec K line 4402-4406; VAL-V3M1-011)
-- -----------------------------------------------------------------------------
ALTER TABLE evidence_claims
    ADD COLUMN evidence_refs TEXT NOT NULL DEFAULT '[]';

-- -----------------------------------------------------------------------------
-- claim_predicate (spec K line 4407-4413; VAL-V3M1-012)
-- -----------------------------------------------------------------------------
ALTER TABLE evidence_claims
    ADD COLUMN claim_predicate TEXT;

-- -----------------------------------------------------------------------------
-- actor_kind (spec K line 4415; VAL-V3M1-013)
-- -----------------------------------------------------------------------------
-- Closed-enum CHECK mirrors the wire-format Literal in
-- packages/schemas/python/relay_schemas/envelopes.py::EvidenceClaim and
-- the Postgres CHECK in 0014_v3_evidence_claim_shape.sql.
ALTER TABLE evidence_claims
    ADD COLUMN actor_kind TEXT
        CHECK (
            actor_kind IS NULL
            OR actor_kind IN (
                'control_plane', 'gate_engine', 'worker', 'sdk', 'user', 'cron'
            )
        );

-- -----------------------------------------------------------------------------
-- actor_identity_hash (spec K line 4416; VAL-V3M1-013)
-- -----------------------------------------------------------------------------
-- sha256-<hex> wire form. SQLite does not support POSIX `~` regex
-- operator portably, so we use GLOB plus LIKE pattern guards mirroring
-- the regex semantics; the precise full-regex form is enforced at the
-- wire-format layer.
ALTER TABLE evidence_claims
    ADD COLUMN actor_identity_hash TEXT
        CHECK (
            actor_identity_hash IS NULL
            OR (
                length(actor_identity_hash) = 71
                AND actor_identity_hash LIKE 'sha256-%'
            )
        );

-- -----------------------------------------------------------------------------
-- occurred_at (spec K line 4417; VAL-V3M1-014)
-- -----------------------------------------------------------------------------
ALTER TABLE evidence_claims
    ADD COLUMN occurred_at TEXT;

-- -----------------------------------------------------------------------------
-- subject nested JSON object (spec K line 4397-4401; VAL-V3M1-015)
-- -----------------------------------------------------------------------------
-- Materialize from existing flat subject_kind / subject_id +
-- manifest_commit_hash columns. New writes supply ``subject`` directly.
ALTER TABLE evidence_claims
    ADD COLUMN subject TEXT;

UPDATE evidence_claims
    SET subject = json_object(
        'kind', subject_kind,
        'id', subject_id,
        'manifest_commit_hash', manifest_commit_hash
    )
    WHERE subject IS NULL;

-- -----------------------------------------------------------------------------
-- namespaces (spec K line 4421-4423; VAL-V3M1-021)
-- -----------------------------------------------------------------------------
ALTER TABLE evidence_claims
    ADD COLUMN namespaces TEXT;

-- -----------------------------------------------------------------------------
-- redaction_transform_version (spec K line 4414; VAL-V3M1-020)
-- -----------------------------------------------------------------------------
-- Already present on the sidecar evidence_claims table from the
-- historical schema landed alongside 0003_evidence_replay.sql; this
-- migration does NOT drop or alter it. VAL-V3M1-020 asserts the column
-- survives.

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS ix_evidence_claims_actor_identity_hash
    ON evidence_claims(actor_identity_hash)
    WHERE actor_identity_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_evidence_claims_occurred_at
    ON evidence_claims(occurred_at)
    WHERE occurred_at IS NOT NULL;
