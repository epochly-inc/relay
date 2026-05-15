-- W8.2 migration 0009: gate_decision_writer.
--
-- Three concerns land in this migration:
--
--   1. ``evidence_bundles`` table (spec K, lines 589-621). Every
--      gate_decisions row binds a non-null ``evidence_bundle_id``
--      (VAL-W8-016, FK enforced) to a bundle row that carries the ten
--      required fields (VAL-W8-017): artifact_digest, command, exit_code,
--      span_ids, manifest_commit_hash, agent_worker_id, timestamp,
--      environment, redaction_policy_version, contract_assertion_ids.
--
--   2. ``gate_rounds`` table (spec A.4, lines 3025-3045). Tracks per-round
--      bookkeeping: round number per scope, restart_predecessor for the
--      gate-restart rule (CLAUDE.md keystone invariant 5), and
--      gate_decision_id binding once the writer commits.
--
--   3. ``gate_decisions`` enforcement: extends migration 0003 with an
--      OSS-local emulation of the Postgres role grants required by
--      VAL-W8-011, plus immutability + signature triggers per VAL-W8-012,
--      VAL-W8-015, VAL-W8-019, VAL-W8-016 (FK to evidence_bundles), and
--      VAL-W8-043 (bundle.manifest_commit_hash binding).
--
--      The OSS-local profile uses SQLite so we cannot create real DB
--      roles. Instead, the migration extends the W2.5 ``_sidecar_role``
--      table (introduced in 0007) with the canonical role token
--      ``relay_gate_engine`` and uses BEFORE INSERT / BEFORE UPDATE /
--      BEFORE DELETE triggers that consult ``_sidecar_role.role`` to
--      enforce the same access pattern Postgres role grants enforce on
--      the hosted profile (VAL-W8-011 narrative). The hosted Postgres
--      migration in services/gate-engine/migrations/ uses real role
--      grants matched to the same role token; the test surface for
--      VAL-W8-011 / VAL-W8-012 / VAL-W8-015 is identical across both
--      profiles via the canonical role tokens listed in
--      ``packages/gate/src/relay_gate_engine/db_grants.py``.
--
-- Per CLAUDE.md keystone invariants 1, 2, 4, 8 and the gate guard tests:
--   keystone 1 (control plane writes): only the ``relay_gate_engine``
--     role may INSERT into ``gate_decisions``.
--   keystone 2 (pass without evidence is not a pass): every row binds a
--     non-null ``evidence_bundle_id`` referencing a real bundle row.
--   keystone 4 (three-anchor handoff): the W8.2 writer validates the
--     handoff BEFORE issuing the INSERT; this migration encodes the
--     binding ``evidence_bundles.manifest_commit_hash =
--     gate_decision_drafts.manifest_commit_hash`` (VAL-W8-043) via a
--     CHECK trigger on INSERT INTO gate_decisions.
--   keystone 8 (atomic primitives): the writer uses one BEGIN
--     IMMEDIATE..COMMIT block to insert evidence_bundles (if needed),
--     INSERT gate_decisions, UPDATE gate_rounds, INSERT event_log_entries
--     (VAL-W8-018).
--
-- Trigger evaluation order note: SQLite evaluates BEFORE INSERT triggers
-- in CREATE order. ``gate_decisions_evidence_fk`` is declared before
-- ``gate_decisions_bundle_manifest_match`` so the FK existence check
-- runs first; the manifest-match trigger then operates on a guaranteed
-- non-null subquery result.
--
-- Idempotent (CREATE ... IF NOT EXISTS; DROP TRIGGER IF EXISTS).

-- ---- evidence_bundles (VAL-W8-016, VAL-W8-017) ----
--
-- The ten required fields per VAL-W8-017 are ALL NOT NULL on the OSS
-- local profile (the hosted profile additionally pins types). Storage
-- format:
--   * artifact_digest        TEXT  sha256-<hex> wire form
--   * command                TEXT  manifest-resolved command line
--   * exit_code              INTEGER  process exit code (0..255)
--   * span_ids               TEXT  JSON array of trace span ids
--   * contract_assertion_ids TEXT  JSON array of assertion VAL-W{N}-NNN ids
--   * agent_worker_id        TEXT  worker / agent identifier
--   * manifest_commit_hash   TEXT  sha256-<hex> wire form
--   * timestamp              TEXT  RFC 3339 UTC with explicit Z offset
--   * environment            TEXT  short token (local | ci | prod | ...)
--   * redaction_policy_version TEXT version of the active redaction policy
--
-- ``bundle_digest`` is the sha256-<hex> over the canonical JSON of the
-- bundle body. The writer computes it before INSERT so VAL-W8-017
-- recomputed-vs-stored equality is enforceable.

CREATE TABLE IF NOT EXISTS evidence_bundles (
    bundle_id                  TEXT    PRIMARY KEY NOT NULL,
    schema_version             TEXT    NOT NULL DEFAULT 'relay.evidence_bundle.v1',
    artifact_digest            TEXT    NOT NULL,
    command                    TEXT    NOT NULL,
    exit_code                  INTEGER NOT NULL,
    span_ids                   TEXT    NOT NULL,
    contract_assertion_ids     TEXT    NOT NULL,
    agent_worker_id            TEXT    NOT NULL,
    manifest_commit_hash       TEXT    NOT NULL,
    timestamp                  TEXT    NOT NULL,
    environment                TEXT    NOT NULL,
    redaction_policy_version   TEXT    NOT NULL,
    bundle_digest              TEXT    NOT NULL,
    state                      TEXT    NOT NULL DEFAULT 'building',
    CONSTRAINT evidence_bundles_state_enum
        CHECK (state IN ('building','signed','published','superseded','revoked')),
    CONSTRAINT evidence_bundles_artifact_digest_format
        CHECK (artifact_digest LIKE 'sha256-%'),
    CONSTRAINT evidence_bundles_manifest_format
        CHECK (manifest_commit_hash LIKE 'sha256-%'),
    CONSTRAINT evidence_bundles_bundle_digest_format
        CHECK (bundle_digest LIKE 'sha256-%'),
    CONSTRAINT evidence_bundles_exit_code_range
        CHECK (exit_code >= 0 AND exit_code <= 255)
);

CREATE INDEX IF NOT EXISTS ix_evidence_bundles_manifest
    ON evidence_bundles(manifest_commit_hash);

-- ---- gate_rounds (spec A.4 lines 3025-3045) ----
--
-- One row per (scope_type, scope_id, round). The W8.2 writer sets
-- ``gate_decision_id`` after the gate_decisions INSERT in the same
-- transaction (VAL-W8-018). ``restart_predecessor`` is non-null when
-- the round was opened by the gate-restart rule (CLAUDE.md keystone 5;
-- VAL-W8-020 / VAL-W8-021 land in W8.3).
--
-- ``initiated_by`` is one of 'submission' (first round), 'remediation'
-- (restart after a late-gate failure), or 'admin_override' (org-admin
-- forced restart). Default 'submission' on first row insertion.

CREATE TABLE IF NOT EXISTS gate_rounds (
    gate_round_id          TEXT    PRIMARY KEY NOT NULL,
    schema_version         TEXT    NOT NULL DEFAULT 'relay.gate_round.v1',
    scope_type             TEXT    NOT NULL,
    scope_id               TEXT    NOT NULL,
    round                  INTEGER NOT NULL,
    initiated_by           TEXT    NOT NULL DEFAULT 'submission',
    restart_predecessor    TEXT,
    gate_decision_id       TEXT,
    opened_at              TEXT    NOT NULL,
    closed_at              TEXT,
    CONSTRAINT gate_rounds_initiated_by_enum
        CHECK (initiated_by IN ('submission','remediation','admin_override')),
    CONSTRAINT gate_rounds_round_positive
        CHECK (round >= 1),
    CONSTRAINT gate_rounds_scope_enum
        CHECK (scope_type IN ('run','replay','eval_run','release','domain_pack')),
    UNIQUE(scope_type, scope_id, round)
);

CREATE INDEX IF NOT EXISTS ix_gate_rounds_scope
    ON gate_rounds(scope_type, scope_id, round);

-- ---- _sidecar_role tightening for the writer ----
--
-- The W2.5 0007 migration created ``_sidecar_role`` with allowed roles
-- 'relay_state_engine' / 'relay_retention_archive' / 'relay_anti_bypass'.
-- W8.2 introduces 'relay_gate_engine' as the only role permitted to
-- INSERT into ``gate_decisions``. We do NOT add a CHECK on
-- ``_sidecar_role.role`` because future migrations may legitimately
-- introduce additional role tokens; instead the gate_decisions triggers
-- below enforce the role at INSERT/UPDATE/DELETE time.

-- ---- VAL-W8-011 emulation: only relay_gate_engine may INSERT ----
--
-- A direct INSERT from any other role (or from a role that is not the
-- canonical 'relay_gate_engine' token) MUST fail with an error message
-- naming the trigger. The canonical role token is consumed by the W8.2
-- decision_writer.py via db_grants.ROLE_GATE_ENGINE.

DROP TRIGGER IF EXISTS gate_decisions_role_check;
CREATE TRIGGER gate_decisions_role_check
BEFORE INSERT ON gate_decisions
FOR EACH ROW
WHEN (SELECT role FROM _sidecar_role WHERE id = 0) != 'relay_gate_engine'
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_role_check: only relay_gate_engine role may INSERT into gate_decisions');
END;

-- ---- VAL-W8-015 emulation: gate_decisions rows are immutable ----
--
-- Once written, no role may UPDATE the row. The W2.5 / 0003 migration
-- already declared the table; we add the immutability triggers here.
-- DELETE is also blocked (the row is canonical evidence; never deleted).

DROP TRIGGER IF EXISTS gate_decisions_no_update;
CREATE TRIGGER gate_decisions_no_update
BEFORE UPDATE ON gate_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_no_update: gate_decisions rows are immutable after insert');
END;

DROP TRIGGER IF EXISTS gate_decisions_no_delete;
CREATE TRIGGER gate_decisions_no_delete
BEFORE DELETE ON gate_decisions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_no_delete: gate_decisions rows are immutable after insert');
END;

-- ---- VAL-W8-016 emulation: evidence_bundle_id FK ----
--
-- The migration 0003 column already declared ``evidence_bundle_id TEXT
-- NOT NULL``. SQLite FOREIGN KEY constraints require ALTER TABLE rebuild
-- to add post-hoc, so we encode the FK via a BEFORE INSERT trigger that
-- asserts the referenced bundle row exists. The hosted Postgres profile
-- declares the FK natively. Trigger ordering: this trigger is declared
-- BEFORE gate_decisions_bundle_manifest_match so the existence check
-- fires first and the manifest-match trigger sees a guaranteed non-null
-- bundle row.

DROP TRIGGER IF EXISTS gate_decisions_evidence_fk;
CREATE TRIGGER gate_decisions_evidence_fk
BEFORE INSERT ON gate_decisions
FOR EACH ROW
WHEN (SELECT bundle_id FROM evidence_bundles WHERE bundle_id = NEW.evidence_bundle_id) IS NULL
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_evidence_fk: evidence_bundle_id does not reference a known evidence_bundles row');
END;

-- ---- VAL-W8-019 emulation: signature non-empty + key id non-empty ----
--
-- The 0003 schema declared signature/signature_key_id as NOT NULL but
-- accepted empty strings. W8.2 tightens to non-empty strings, enforcing
-- that the writer signed the row before commit (signature is computed
-- over the canonical JSON of the row body via Ed25519 in
-- packages/gate/src/relay_gate_engine/signed_decision.py).

DROP TRIGGER IF EXISTS gate_decisions_signature_required;
CREATE TRIGGER gate_decisions_signature_required
BEFORE INSERT ON gate_decisions
FOR EACH ROW
WHEN length(NEW.signature) = 0 OR length(NEW.signature_key_id) = 0
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_signature_required: signature and signature_key_id MUST be non-empty before commit');
END;

-- ---- VAL-W8-043 emulation: bundle.manifest_commit_hash matches row ----
--
-- The bundle bound to a gate_decision MUST carry the same
-- manifest_commit_hash as the decision row. This binds the three-anchor
-- handoff anchor through the bundle so a misconfigured bundle cannot be
-- attached to a decision with a different anchor.
--
-- SQLite evaluates triggers in ALPHABETICAL order by trigger name (not
-- CREATE order). To preserve the natural attribution ("missing bundle"
-- before "mismatched manifest"), the WHEN clause below explicitly
-- short-circuits when the bundle subquery returns NULL — that scenario
-- belongs to gate_decisions_evidence_fk and would otherwise fire here
-- (NULL IS NOT 'sha256-...' is TRUE) and mask the FK rejection. With
-- the ``EXISTS + IS NOT`` two-step guard, this trigger fires ONLY when
-- the bundle row exists AND its manifest_commit_hash differs from
-- NEW.manifest_commit_hash.

DROP TRIGGER IF EXISTS gate_decisions_bundle_manifest_match;
CREATE TRIGGER gate_decisions_bundle_manifest_match
BEFORE INSERT ON gate_decisions
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM evidence_bundles WHERE bundle_id = NEW.evidence_bundle_id
) AND (
    SELECT manifest_commit_hash
    FROM evidence_bundles
    WHERE bundle_id = NEW.evidence_bundle_id
) IS NOT NEW.manifest_commit_hash
BEGIN
    SELECT RAISE(ABORT, 'gate_decisions_bundle_manifest_match: evidence_bundles.manifest_commit_hash must equal gate_decisions.manifest_commit_hash (VAL-W8-043)');
END;
