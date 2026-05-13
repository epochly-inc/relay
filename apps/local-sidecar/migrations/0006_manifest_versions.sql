-- W2.4 migration 0006: manifest_versions + actors (three-anchor handoff registries).
--
-- The three-anchor handoff (spec C.5) requires two lookups:
--   1. ``actors(identity_hash)`` -- is the calling actor's identity_hash
--      registered AND not revoked? (VAL-W2-031)
--   2. ``manifest_versions(commit_hash)`` -- is the supplied
--      manifest_commit_hash currently active for the project, OR within
--      the rotation grace window? (VAL-W2-032)
--
-- The hosted Postgres profile carries these tables with full FK chains
-- (projects.manifests.manifest_versions). The OSS local sidecar stores a
-- minimal subset sufficient for the three-anchor handoff guard tests --
-- project_id is TEXT here without a projects FK.
--
-- Per CLAUDE.md keystone invariant #4: the three-anchor handoff is non-
-- optional. Every state transition rooted in a worker submission MUST
-- consult these tables.
--
-- Time semantics: ``effective_at`` and ``effective_until`` are RFC 3339 UTC
-- strings (matching the rest of the schema). The grace window is computed
-- as ``effective_until + grace_window_seconds`` -- not stored separately,
-- evaluated at lookup time against ``now()``.
--
-- Idempotent.

-- ---- actors registry (VAL-W2-031) ----
--
-- The identity_hash is the sha256-<hex> wire form (VAL-W1-009). ``kind``
-- distinguishes human operators from machine actors -- the W2.5 anti-bypass
-- guard checks ``kind = 'human'`` AND ``org_admin = 1`` to permit an
-- operator_override event log row.
--
-- ``revoked_at`` non-null means the actor's identity has been hard-revoked
-- (e.g., after a security incident). VAL-W2-031 asserts a revoked actor
-- fails handoff with ``ACTOR_NOT_REGISTERED``.

CREATE TABLE IF NOT EXISTS actors (
    identity_hash        TEXT    PRIMARY KEY NOT NULL,
    kind                 TEXT    NOT NULL,
    display_name         TEXT,
    org_admin            INTEGER NOT NULL DEFAULT 0,
    registered_at        TEXT    NOT NULL,
    revoked_at           TEXT,
    CONSTRAINT actors_kind_enum
        CHECK (kind IN ('human','machine','sdk','worker','gate_engine','result_writer','evidence_signer','cron','control_plane','validation_worker','ingest_worker','replay_worker')),
    CONSTRAINT actors_identity_hash_format
        CHECK (identity_hash LIKE 'sha256-%'),
    CONSTRAINT actors_org_admin_bool
        CHECK (org_admin IN (0,1))
);

-- ---- manifest_versions registry (VAL-W2-032) ----
--
-- Mirrors spec A.9 manifest_versions but flattened (no parent manifests
-- table on the OSS local profile yet -- manifest_id present as TEXT for
-- forward compatibility).
--
-- Two columns control activeness:
--   ``effective_at``        -- when this version became active.
--   ``effective_until``     -- when it was rotated out; NULL = currently active.
-- The grace window after rotation is encoded as
-- ``grace_window_seconds`` (default 86400 = 24h per spec C.5 "grace_window
-- after a rotation"). A hash is "in grace" when ``effective_until IS NOT
-- NULL AND now() <= effective_until + grace_window_seconds``.

CREATE TABLE IF NOT EXISTS manifest_versions (
    manifest_version_id      TEXT    PRIMARY KEY NOT NULL,
    manifest_id              TEXT    NOT NULL,
    project_id               TEXT    NOT NULL,
    commit_hash              TEXT    NOT NULL,
    schema_version           TEXT    NOT NULL DEFAULT 'relay.manifest.v1',
    effective_at             TEXT    NOT NULL,
    effective_until          TEXT,
    grace_window_seconds     INTEGER NOT NULL DEFAULT 86400,
    CONSTRAINT manifest_versions_commit_hash_format
        CHECK (commit_hash LIKE 'sha256-%'),
    CONSTRAINT manifest_versions_grace_nonneg
        CHECK (grace_window_seconds >= 0),
    UNIQUE(manifest_id, commit_hash)
);

CREATE INDEX IF NOT EXISTS ix_manifest_versions_project_active
    ON manifest_versions(project_id, effective_until);
CREATE INDEX IF NOT EXISTS ix_manifest_versions_commit_hash
    ON manifest_versions(commit_hash);
