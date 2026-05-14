-- W2.7 migration 0008: _sidecar_schema_version table.
--
-- Records the canonical schema-version integer that the running sidecar
-- binary supports. The recovery module (relay_sidecar.recovery) reads
-- this table at startup, compares against ``SUPPORTED_SCHEMA_VERSION``
-- (a constant in code), and refuses to start with
-- ``RELAY-SIDECAR-SCHEMA-VERSION-UNKNOWN`` + exit code 5 on mismatch
-- (VAL-W2-054).
--
-- Why a table (and not just ``PRAGMA user_version``):
--   PRAGMA user_version only stores a single 32-bit integer with no
--   schema for accompanying metadata. The table form lets us add
--   ``observed_at`` and ``installed_by`` columns later for forensic
--   trails without an ALTER. The single-row constraint (id=0) keeps
--   semantics identical to user_version in the simple case.
--
-- Bootstrap order:
--   This is the LAST migration (0008). When migrations run in lex
--   order, every prior migration has applied first; the version we
--   record here is the count of migrations that produced this schema.
--   The constant in code (SUPPORTED_SCHEMA_VERSION) MUST equal this
--   integer for the running binary to accept the database.
--
-- Idempotent: CREATE IF NOT EXISTS + INSERT OR IGNORE.

CREATE TABLE IF NOT EXISTS _sidecar_schema_version (
    id              INTEGER PRIMARY KEY CHECK (id = 0),
    version         INTEGER NOT NULL CHECK (version > 0),
    installed_at    TEXT    NOT NULL
);

-- Seed the row with version=8 (the integer matching this migration's
-- ordinal: 0001..0008 = eight migrations applied). The constant
-- SUPPORTED_SCHEMA_VERSION in relay_sidecar.recovery MUST equal 8.
INSERT OR IGNORE INTO _sidecar_schema_version (id, version, installed_at)
VALUES (0, 8, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
