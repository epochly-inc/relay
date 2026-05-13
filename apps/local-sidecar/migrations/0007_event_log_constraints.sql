-- W2.5 migration 0007: event_log_entries constraints + append-only triggers.
--
-- Extends the W2.3 0001_event_log_entries.sql base schema with the
-- guarantees required by W2.5 (eng plan A5 + CQ2 "never raw" schema, plus
-- the canonical control-plane invariant that audit rows are append-only).
--
-- Adds:
--   1. CHECK on schema_version pinned to 'relay.event_log_entry.v1' so any
--      direct insert with a different schema_version raises an IntegrityError
--      naming the constraint (VAL-W2-060).
--   2. CHECK on payload rejecting raw plaintext patterns. The W2.5 redaction
--      contract is "every plaintext key MUST have an HMAC digest sibling".
--      The CHECK matches the JSON keys "prompt", "completion", "messages"
--      (with surrounding quotes + JSON colon) UNLESS the payload also carries
--      a matching "<name>_digest" / "<name>_sha256" / "<name>_hmac" sibling
--      (VAL-W2-036). Detection is regex-based via SQLite's GLOB-like LIKE +
--      INSTR primitives; the production rejection path additionally runs the
--      Python anti_bypass module (VAL-W2-057) before INSERT for richer rules.
--   3. SQLite triggers event_log_entries_no_delete and event_log_entries_no_update
--      that RAISE(ABORT, ...) when the active role recorded in
--      _sidecar_role.role is anything other than 'relay_retention_archive'
--      (VAL-W2-061). Triggers are BEFORE DELETE / BEFORE UPDATE so the row
--      is never mutated.
--
-- Role emulation in SQLite:
--   SQLite has no native role concept. The _sidecar_role table carries one
--   row (id=0) holding the currently-active role for this connection. The
--   state engine and retention module UPDATE the row at the start of each
--   transaction inside the BEGIN IMMEDIATE..COMMIT window. The single-writer
--   asyncio.Lock guarantees one role transition at a time on the writer
--   connection.
--
-- Idempotent: every CREATE uses IF NOT EXISTS; the INSERT uses INSERT OR
-- IGNORE so re-running the migration on an already-migrated DB is a no-op.

-- ---- Role-state table (single row) ----
--
-- ``role`` is one of:
--   'relay_state_engine'       -- compare_and_set_state and friends
--   'relay_retention_archive'  -- the retention pass (the ONLY role permitted
--                                 to DELETE FROM event_log_entries).
--   'relay_anti_bypass'        -- anti-bypass detector (read-only; reserved
--                                 for future use; treated identically to
--                                 'relay_state_engine' by the triggers).
-- Any other value blocks both DELETE and UPDATE on event_log_entries.

CREATE TABLE IF NOT EXISTS _sidecar_role (
    id   INTEGER PRIMARY KEY CHECK (id = 0),
    role TEXT    NOT NULL DEFAULT 'relay_state_engine'
);

INSERT OR IGNORE INTO _sidecar_role (id, role) VALUES (0, 'relay_state_engine');

-- ---- VAL-W2-061 append-only triggers ----
--
-- Refuse DELETE / UPDATE on event_log_entries unless the active role is
-- 'relay_retention_archive'. The error message names the trigger so test
-- assertions can match on the trigger name (per VAL-W2-061 evidence).

DROP TRIGGER IF EXISTS event_log_entries_no_delete;
CREATE TRIGGER event_log_entries_no_delete
BEFORE DELETE ON event_log_entries
FOR EACH ROW
WHEN (SELECT role FROM _sidecar_role WHERE id = 0) != 'relay_retention_archive'
BEGIN
    SELECT RAISE(ABORT, 'event_log_entries_no_delete: append-only enforced; only relay_retention_archive role may delete');
END;

DROP TRIGGER IF EXISTS event_log_entries_no_update;
CREATE TRIGGER event_log_entries_no_update
BEFORE UPDATE ON event_log_entries
FOR EACH ROW
WHEN (SELECT role FROM _sidecar_role WHERE id = 0) != 'relay_retention_archive'
BEGIN
    SELECT RAISE(ABORT, 'event_log_entries_no_update: append-only enforced; updates forbidden');
END;

-- ---- VAL-W2-060 schema_version pin ----
--
-- A direct INSERT (e.g. from a misconfigured worker bypassing the state
-- engine) carrying schema_version != 'relay.event_log_entry.v1' MUST fail
-- with an IntegrityError naming the constraint.

DROP TRIGGER IF EXISTS event_log_entries_schema_version_check;
CREATE TRIGGER event_log_entries_schema_version_check
BEFORE INSERT ON event_log_entries
FOR EACH ROW
WHEN NEW.schema_version != 'relay.event_log_entry.v1'
BEGIN
    SELECT RAISE(ABORT, 'event_log_entries_schema_version_check: schema_version must be ''relay.event_log_entry.v1''');
END;

-- ---- VAL-W2-036 raw plaintext payload CHECK ----
--
-- Reject INSERT when payload carries one of the canonical plaintext JSON
-- keys ('"prompt":', '"completion":', '"messages":') AND lacks an
-- accompanying digest sibling ('"prompt_digest":', '"prompt_sha256":',
-- '"prompt_hmac":', and the same for completion / messages). The blob
-- spillover module replaces large payloads with {"_blob_sha256":"..."}
-- ahead of the INSERT so spilled rows pass trivially. Anti-bypass
-- (VAL-W2-057) runs in the Python layer ahead of this CHECK and produces
-- a richer error envelope; this trigger is the defence-in-depth backstop
-- for any direct INSERT that bypasses the Python layer.

DROP TRIGGER IF EXISTS event_log_entries_payload_raw_check;
CREATE TRIGGER event_log_entries_payload_raw_check
BEFORE INSERT ON event_log_entries
FOR EACH ROW
WHEN (
    (INSTR(NEW.payload, '"prompt":') > 0
        AND INSTR(NEW.payload, '"prompt_digest":') = 0
        AND INSTR(NEW.payload, '"prompt_sha256":') = 0
        AND INSTR(NEW.payload, '"prompt_hmac":') = 0)
    OR (INSTR(NEW.payload, '"completion":') > 0
        AND INSTR(NEW.payload, '"completion_digest":') = 0
        AND INSTR(NEW.payload, '"completion_sha256":') = 0
        AND INSTR(NEW.payload, '"completion_hmac":') = 0)
    OR (INSTR(NEW.payload, '"messages":') > 0
        AND INSTR(NEW.payload, '"messages_digest":') = 0
        AND INSTR(NEW.payload, '"messages_sha256":') = 0
        AND INSTR(NEW.payload, '"messages_hmac":') = 0)
)
BEGIN
    SELECT RAISE(ABORT, 'event_log_entries_payload_raw_check: raw plaintext JSON key without digest sibling; payload must spill to blob or carry a HMAC/sha256 digest');
END;
