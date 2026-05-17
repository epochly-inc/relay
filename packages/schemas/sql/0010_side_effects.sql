-- 0010_side_effects.sql
--
-- v0.2 OSS completeness, milestone M04 (w4-side-effects): canonical Postgres
-- DDL for the §X side-effect markers and proofs subsystem. These tables
-- close keystone invariant #6 (side-effect idempotency): a side-effecting
-- tool call requires a pre-action marker AND a post-success proof. The
-- doctrine has been there since v0.1; this migration lands the SQL home.
--
--   tool_side_effect_policies (spec X lines 5119-5133; VAL-V2M04-001..003)
--   side_effect_markers       (spec X lines 5135-5150; VAL-V2M04-004..007)
--   side_effect_proofs        (spec X lines 5152-5161; VAL-V2M04-008..010)
--
-- Per CLAUDE.md keystone invariant #1: these tables are subject to the
-- "control plane writes the result" rule. The hosted control plane's role
-- grants enforce that the SDK / agent / eval-worker write-restricted
-- ingest role has NO INSERT/UPDATE/DELETE permission on these tables;
-- only the sidecar control-plane role writes them. The role grants live
-- in M02 (m02-w2-api-surface) alongside the rest of the hosted API write
-- path; the SQLite mirror enforces the same invariant by routing every
-- write through the transactional_db_write atomic primitive (VAL-V2M04-033,
-- VAL-V2M04-034).
--
-- Per CLAUDE.md keystone invariant #8: every persisted write to these
-- tables passes through the transactional_db_write primitive. Direct
-- conn.execute("INSERT INTO side_effect_markers ...") outside the
-- primitive is a banned pattern and trips the lint guard.
--
-- Per CLAUDE.md keystone invariant #6: the unique constraint on
-- side_effect_markers.idempotency_key is load-bearing. It guarantees
-- only one worker proceeds per side effect (§X execution contract step
-- 2: "Unique constraint guarantees only one worker proceeds; the loser
-- observes the existing marker.").
--
-- Replay isolation (§X line 5176, VAL-V2M04-016, VAL-V2M04-017): markers
-- written during a replay run carry an idempotency_key prefixed with
-- "replay:<replay_case_id>:" so they never collide with production markers
-- sharing the same logical key. The application layer (side_effect_markers
-- module on the sidecar) enforces the prefix at insertion time and rejects
-- production-namespace writes during active replay context with
-- RELAY-SIDEEFFECT-REPLAY-PREFIX-MISSING.
--
-- Some FK targets (projects, runs, spans) are declared in earlier
-- migrations (0001_actors.sql for projects; 0004_v2_canonical_tables.sql
-- for runs + spans). The FKs are inlined here because those targets are
-- present by the time this migration applies; the migration lex order
-- guarantees it.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- tool_side_effect_policies (spec X lines 5119-5133; VAL-V2M04-001..003)
-- -----------------------------------------------------------------------------
--
-- Per-project per-tool side-effect classification + idempotency policy.
-- One row per (project_id, tool_name, effective_at). The effective_at +
-- effective_until pair models policy versioning: a new row supersedes the
-- prior at its effective_at boundary; the prior row's effective_until is
-- set to the new row's effective_at by the policy publisher service.
--
-- side_effect_class enum is the spec's canonical four (§E.3 lines 3931-3936):
--   read_only             - mocked from cassette; live exec allowed only on egress allowlist
--   mutating              - mocked from cassette; live exec requires dashboard JWT admin + audit
--   external_irreversible - mocked OR blocked; requires admin + 2-person approval; expires 24h
--   approval_required     - blocked until human approves; named human single-use token
--
-- The OSS-historical legacy strings "none" and "reversible" are explicitly
-- NOT in the enum. The grep guard at VAL-V2M04-023/024 enforces their
-- removal from packages/cli/src/relay_cli/commands/replay.py.

CREATE TABLE tool_side_effect_policies (
    policy_id              uuid PRIMARY KEY,
    project_id             uuid NOT NULL REFERENCES projects(project_id),
    tool_name              text NOT NULL,
    side_effect_class      text NOT NULL
        CHECK (side_effect_class IN (
            'read_only',
            'mutating',
            'external_irreversible',
            'approval_required'
        )),
    idempotency_key_template text,
    compensation_tool      text,
    max_retries            int NOT NULL DEFAULT 1
        CHECK (max_retries >= 0),
    approval_required      boolean NOT NULL DEFAULT false,
    approval_ttl_seconds   int NOT NULL DEFAULT 86400
        CHECK (approval_ttl_seconds > 0),
    effective_at           timestamptz NOT NULL DEFAULT now(),
    effective_until        timestamptz,
    UNIQUE (project_id, tool_name, effective_at)
);

CREATE INDEX tool_side_effect_policies_project_tool
    ON tool_side_effect_policies (project_id, tool_name);

-- -----------------------------------------------------------------------------
-- side_effect_markers (spec X lines 5135-5150; VAL-V2M04-004..007)
-- -----------------------------------------------------------------------------
--
-- A marker is written BEFORE a side-effecting tool attempts execution.
-- The UNIQUE constraint on idempotency_key (spec line 5148, load-bearing
-- for VAL-V2M04-006) guarantees only one worker proceeds; the loser
-- observes the existing marker and either attaches to its in-flight state
-- or returns the prior result idempotently.
--
-- state machine (spec line 5144):
--   pending             -> initial; the marker exists but the side effect has not yet attempted
--   in_flight           -> the winning worker has begun the side effect
--   succeeded           -> side effect completed; a side_effect_proofs row is present
--   failed              -> side effect failed; compensation_tool was enqueued (if defined)
--   compensated         -> compensation completed; marker is reset-eligible
--   blocked_by_approval -> approval_required class is awaiting a human single-use token
--
-- expires_at (spec line 5147): after this timestamp the marker is
-- reclaimable by the §X resurrection check at worker boot. The check
-- (VAL-V2M04-018..020) queries WHERE state='in_flight' AND expires_at < now()
-- and either enqueues compensation (if compensation_tool is defined) or
-- transitions the marker to failed.

CREATE TABLE side_effect_markers (
    marker_id        uuid PRIMARY KEY,
    run_id           uuid NOT NULL REFERENCES runs(run_id),
    span_id          uuid NOT NULL REFERENCES spans(span_id),
    tool_name        text NOT NULL,
    idempotency_key  text NOT NULL,
    policy_id        uuid NOT NULL REFERENCES tool_side_effect_policies(policy_id),
    state            text NOT NULL DEFAULT 'pending'
        CHECK (state IN (
            'pending',
            'in_flight',
            'succeeded',
            'failed',
            'compensated',
            'blocked_by_approval'
        )),
    created_at       timestamptz NOT NULL DEFAULT now(),
    in_flight_at     timestamptz,
    expires_at       timestamptz NOT NULL,
    UNIQUE (idempotency_key)
);

CREATE INDEX side_effect_markers_state
    ON side_effect_markers (state, expires_at);

-- -----------------------------------------------------------------------------
-- side_effect_proofs (spec X lines 5152-5161; VAL-V2M04-008..010)
-- -----------------------------------------------------------------------------
--
-- A proof is written AFTER a side effect successfully completes. It binds
-- the marker (FK requires the marker to pre-exist) to evidence of the
-- effect: an external system's row id, an HTTP response digest, a span
-- trace, a signed callback, or a user acknowledgement.
--
-- evidence_kind enum (spec line 5157):
--   exit_code            - process exit status (for tool calls that shell out)
--   external_id          - row id created in the customer's CRM / DB / etc.
--   http_response        - digest of the response from a downstream API
--   span_trace           - trace span IDs binding back to the tool call
--   signed_callback      - signed payload from the downstream system
--   user_acknowledgement - human user clicked an approval button

CREATE TABLE side_effect_proofs (
    proof_id        uuid PRIMARY KEY,
    marker_id       uuid NOT NULL REFERENCES side_effect_markers(marker_id),
    evidence_kind   text NOT NULL
        CHECK (evidence_kind IN (
            'exit_code',
            'external_id',
            'http_response',
            'span_trace',
            'signed_callback',
            'user_acknowledgement'
        )),
    evidence_digest text NOT NULL,
    external_id     text,
    recorded_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX side_effect_proofs_marker
    ON side_effect_proofs (marker_id);
