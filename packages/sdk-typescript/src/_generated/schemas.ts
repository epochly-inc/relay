/* GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
 * Regenerate: uv run python packages/schemas/scripts/codegen.py
 * Drift check: uv run python scripts/check-codegen-drift.py
 */

export interface paths {
    "/diagnostics/sqlite": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read sidecar SQLite journal_mode + busy_timeout
         * @description VAL-W2-014 diagnostic. Opens a short-lived aiosqlite connection
         *     and reports PRAGMA journal_mode + PRAGMA busy_timeout. Used to
         *     prove WAL mode is in effect after lifespan startup. Bearer-token
         *     authenticated; no body.
         */
        get: operations["getDiagnosticsSqlite"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/diagnostics/runtime": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read sidecar runtime diagnostics
         * @description Returns the current sidecar runtime state -- start time, uptime,
         *     active connections, lock state. Documented at
         *     apps/local-sidecar/relay_sidecar/runtime.py around the
         *     @app.get('/diagnostics/runtime') decorator. Authenticated via
         *     bearer token; no body.
         */
        get: operations["getDiagnosticsRuntime"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/diagnostics/quiesce": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read sidecar quiesce / draining state
         * @description Reports whether the runtime is currently draining for shutdown.
         *     Used by external supervisors to confirm SIGTERM has been
         *     observed and the in-flight tracker is unwinding.
         */
        get: operations["getDiagnosticsQuiesce"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/diagnostics/db": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read sidecar database connectivity diagnostics
         * @description Reports the active SidecarDatabase wiring (path, lock state,
         *     migration head). Used by self-test and ops smoke checks.
         */
        get: operations["getDiagnosticsDb"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/ingest": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Generic ingest probe endpoint
         * @description W2.6 placeholder ingest endpoint participating in the in-flight
         *     tracker so drain-path tests (VAL-W2-044) can exercise the
         *     draining handshake. Full ingest envelope validation lands in
         *     the typed ingest routes below.
         */
        post: operations["postV1Ingest"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/ingest/runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Ingest a run-lifecycle envelope
         * @description Submits a run lifecycle envelope (Run / RunResult-draft / etc).
         *     Canonical control plane writes the eventual run_result row.
         *     Spec B; envelope kinds defined in components.schemas.
         */
        post: operations["postV1IngestRuns"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/ingest/spans:batch": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Batch-ingest spans
         * @description Batch span submission. Enforces the §AI.1 per-envelope 256 KiB
         *     size cap and nesting depth <= 16 (RELAY-ING-041). Spec B.
         */
        post: operations["postV1IngestSpansBatch"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/ingest/contract-results:batch": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Batch-ingest contract evaluation results
         * @description Batch submission of ContractResult envelopes produced by the
         *     contract engine. Spec A.6, B. Canonical control plane resolves
         *     the join to run_results.
         */
        post: operations["postV1IngestContractResultsBatch"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/projects/{project_id}/runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List runs for a project
         * @description Paginated list of runs scoped to a single project. Cursor is
         *     signed + TTL'd per §B.3 (VAL-V3M2-009).
         */
        get: operations["listProjectRuns"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/runs/{run_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read a single run
         * @description Fetch the Run envelope by id.
         */
        get: operations["getRun"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/runs/{run_id}/trace": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read the span trace for a run
         * @description Paginated trace of spans bound to the run. Cursor is signed +
         *     TTL'd per §B.3.
         */
        get: operations["getRunTrace"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/runs/{run_id}/result": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read the canonical run_result for a run
         * @description Returns the run_result row (control-plane-authored, spec A.1).
         *     404 until the result-writer has resolved the run.
         */
        get: operations["getRunResult"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/runs/{run_id}/explain": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Read explain output (root-cause hypotheses) for a run
         * @description Returns ranked root-cause hypotheses associated with the run.
         *     Hypotheses are generator-versioned (spec §AJ).
         */
        get: operations["getRunExplain"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/replay-cases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create a replay case
         * @description Submits a ReplayCase envelope. Spec A.8.
         */
        post: operations["createReplayCase"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/replay-cases/{case_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read a replay case by id */
        get: operations["getReplayCase"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/replay-cases/{case_id}/fixtures": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Attach a replay fixture to a replay case
         * @description Appends a ReplayFixture to the case. Spec A.8, §E. Fixture
         *     side_effect_class governs whether the fixture is replayable.
         */
        post: operations["addReplayFixture"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/replay-cases/{case_id}/run": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Execute a replay case
         * @description Enqueues an execution of the replay case. Cassette mode is
         *     default; live mode requires explicit annotation. Spec §E.
         */
        post: operations["runReplayCase"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/replay-results/{result_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read a replay execution result */
        get: operations["getReplayResult"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/eval-datasets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create an eval dataset
         * @description Registers a dataset for use by eval runs. Spec §AM.
         */
        post: operations["createEvalDataset"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/eval-runs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create an eval run
         * @description Enqueues an eval run against a dataset. Spec §AM. The control
         *     plane writes the eval_run scope_state transitions.
         */
        post: operations["createEvalRun"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/eval-runs/{eval_run_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read an eval run */
        get: operations["getEvalRun"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/gates/{gate_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Upsert a gate definition
         * @description Creates or replaces the gate-definition row at gate_id. Spec
         *     A.5. Backed by the gate-engine writer; not gate_decisions.
         */
        put: operations["putGate"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/gate-policies/{policy_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /**
         * Upsert a gate policy version
         * @description Creates or replaces a gate-policy version. Spec A.5
         *     (VAL-V2M01-001). New versions become effective at the
         *     declared effective_at boundary.
         */
        put: operations["putGatePolicy"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/gates/{gate_id}/drafts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit a gate decision draft
         * @description Submits a GateDecisionDraft. Spec A.3. NOT authoritative; the
         *     state engine resolves at most one draft per (gate, scope,
         *     round) into a canonical gate_decision row written by the
         *     gate-engine service (keystone #1).
         */
        post: operations["submitGateDecisionDraft"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/gate-decisions/{decision_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read a canonical gate decision */
        get: operations["getGateDecision"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/gates/{gate_id}/rounds": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List gate rounds for a gate
         * @description Paginated list of GateRound rows for a single gate. Cursor is
         *     signed + TTL'd per §B.3 (VAL-V3M2-009).
         */
        get: operations["listGateRounds"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/evidence-bundles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create a signed evidence bundle
         * @description Creates an evidence bundle row + signed bundle artifact. Spec
         *     §K. Hosted bundles must be signed by the control-plane
         *     evidence-signer service.
         */
        post: operations["createEvidenceBundle"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/evidence-bundles/{bundle_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read an evidence bundle row */
        get: operations["getEvidenceBundle"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/evidence-bundles/{bundle_id}/download": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Download a signed evidence bundle artifact
         * @description Streams the signed bundle blob. Subject to legal-hold and
         *     redaction-tombstone semantics (spec Y).
         */
        get: operations["downloadEvidenceBundle"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/evidence-bundles/{bundle_id}/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Verify a signed evidence bundle
         * @description Runs the verifier against the bundle artifact. Returns the
         *     verification verdict + signer trust path (control_plane,
         *     local_dev, or unknown). Spec §K rule line 4427.
         */
        post: operations["verifyEvidenceBundle"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/manifests": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit a new manifest version
         * @description Submits a manifest version. commit_hash is the canonical
         *     sha256 wire form. Spec §F. The manifest is the source of
         *     truth for commands, ports, and side-effect policy.
         */
        post: operations["createManifestVersion"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/manifests/{manifest_id}/versions/{commit_hash}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read a specific manifest version */
        get: operations["getManifestVersion"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/redaction-policies": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Publish a new redaction-policy version
         * @description Publishes a redaction policy. Each regex matcher must clear
         *     the 50ms ReDoS budget (VAL-V3M5-001). raw_capture=true
         *     additionally requires a signed DPA + org-admin approver
         *     (CLAUDE.md keystone #7).
         */
        post: operations["createRedactionPolicy"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/redaction-policies/{policy_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Read a redaction policy version */
        get: operations["getRedactionPolicy"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/auth/tokens": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create an auth token
         * @description Issues a bearer token scoped to the calling principal. Token
         *     material is returned ONCE in the response body; subsequent
         *     reads expose only the token row metadata.
         */
        post: operations["createAuthToken"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/auth/tokens/{token_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /**
         * Revoke an auth token
         * @description Marks the token row as revoked. Revocation propagates to
         *     subsequent authn checks on the next request.
         */
        delete: operations["revokeAuthToken"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/state/transition": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Apply a state-engine transition
         * @description State-engine HTTP boundary. Validates the three-anchor
         *     handoff (scope_id, actor_identity_hash, manifest_commit_hash;
         *     keystone #4) BEFORE forwarding to compare_and_set_state.
         *     Stale or cross-project handoffs are rejected with the
         *     appropriate GUARD_FAILED code (e.g. RELAY-GATE-021).
         */
        post: operations["postV1StateTransition"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /**
         * @description Canonical Relay sha256 wire form: 'sha256-' + 64 lowercase hex chars.
         *     The colon form (sha256:<hex>) and bare-hex form are rejected
         *     (VAL-W1-009).
         */
        Sha256Hash: string;
        /**
         * @description Crockford-base32 ULID, 26 uppercase chars (spec B.6 line 3517).
         *     Lowercase letters not permitted; I, L, O, U excluded.
         */
        Ulid: string;
        /**
         * @description Canonical Relay error-code wire form per VAL-W1-029. Known values
         *     enumerated in packages/schemas/raw/relay-error-codes.yaml.
         */
        RelayErrorCodeStr: string;
        /**
         * @description Canonical run outcome. Written exclusively by the control plane.
         *     A successful run requires a bound evidence_bundle_id (CLAUDE.md
         *     keystone invariant #2). Spec A.1.
         */
        RunResult: {
            /** @constant */
            schema_version: "relay.run_result.v1";
            /** Format: uuid */
            run_result_id: string;
            /** Format: uuid */
            run_id: string;
            /** Format: uuid */
            project_id: string;
            /** @constant */
            written_by: "control_plane";
            /** @enum {string} */
            status: "accepted" | "remediate_required" | "blocked" | "invalid";
            primary_failure_class?: string | null;
            /** @default first_p0_then_highest_severity_then_earliest_span */
            error_priority_rule: string;
            evidence_bundle_id?: string | null;
            manifest_commit_hash: components["schemas"]["Sha256Hash"];
            actor_identity_hash: components["schemas"]["Sha256Hash"];
            /** Format: date-time */
            decided_at: string;
            /** @default 0 */
            decision_epoch: number;
            signature: string;
            signature_key_id: string;
        };
        /**
         * @description Canonical gate decision. Written exclusively by the gate engine.
         *     Spec A.2.
         */
        GateDecision: {
            /** @constant */
            schema_version: "relay.gate_decision.v1";
            /** Format: uuid */
            gate_decision_id: string;
            /** Format: uuid */
            gate_id: string;
            /** @enum {string} */
            scope_type: "run" | "replay" | "eval_run" | "release" | "domain_pack";
            /** Format: uuid */
            scope_id: string;
            round: number;
            /** @enum {string} */
            action: "accept" | "remediate" | "block" | "invalid";
            /** @default false */
            strict_pass: boolean;
            /** @default [] */
            failed_assertion_ids: string[];
            /** @default [] */
            unmet_conditions: unknown[];
            /** Format: uuid */
            evidence_bundle_id: string;
            /** @default true */
            cascade_on_block: boolean;
            /** @constant */
            decided_by: "gate_engine";
            /** Format: date-time */
            decided_at: string;
            manifest_commit_hash: components["schemas"]["Sha256Hash"];
            actor_identity_hash: components["schemas"]["Sha256Hash"];
            signature: string;
            signature_key_id: string;
            /** @default 0 */
            decision_epoch: number | null;
        };
        /**
         * @description Submitter-facing draft. NOT authoritative. Resolved into a
         *     gate_decision exactly once by the state engine. Spec A.3.
         */
        GateDecisionDraft: {
            /** @constant */
            schema_version: "relay.gate_decision_draft.v1";
            /** Format: uuid */
            draft_id: string;
            /** Format: uuid */
            gate_id: string;
            scope_type: string;
            /** Format: uuid */
            scope_id: string;
            round: number;
            release_sha?: string | null;
            /** @default [] */
            eval_run_ids: string[];
            /** @default [] */
            evidence_refs: unknown[];
            /** Format: uuid */
            worker_id: string;
            manifest_commit_hash: components["schemas"]["Sha256Hash"];
            actor_identity_hash: components["schemas"]["Sha256Hash"];
            /** Format: date-time */
            submitted_at: string;
            resolved_gate_decision_id?: string | null;
            /**
             * @default submitted
             * @enum {string}
             */
            draft_kind: "submitted" | "dry_run_unsigned";
            /**
             * @default pending
             * @enum {string}
             */
            resolution_state: "pending" | "resolved" | "rejected_handoff" | "expired" | "cancelled" | "duplicate_submission";
            cancelled_at?: string | null;
            cancellation_reason?: string | null;
        };
        /** @description Per-round audit trail. Spec A.4. */
        GateRound: {
            /** @constant */
            schema_version: "relay.gate_round.v1";
            /** Format: uuid */
            gate_round_id: string;
            /** Format: uuid */
            gate_id: string;
            scope_type: string;
            /** Format: uuid */
            scope_id: string;
            round: number;
            /** Format: date-time */
            initiated_at: string;
            /** @enum {string} */
            initiated_by: "control_plane" | "cron" | "user" | "remediation";
            initiation_reason?: string | null;
            gate_decision_id?: string | null;
            restart_predecessor?: string | null;
        };
        /**
         * @description Actor identity registry. FK target for the three-anchor handoff.
         *     Spec C.5. Audit-R3 (2026-05-18) widened the kind enum to align
         *     with the sidecar 12-value operational set; envelopes.yaml is
         *     the canonical reference.
         */
        Actor: {
            identity_hash: components["schemas"]["Sha256Hash"];
            /** @enum {string} */
            kind: "human" | "bot" | "reviewer" | "sdk" | "machine" | "worker" | "gate_engine" | "result_writer" | "evidence_signer" | "cron" | "control_plane" | "validation_worker" | "ingest_worker" | "replay_worker";
            /** Format: date-time */
            created_at: string;
            revoked_at?: string | null;
        };
        /**
         * @description A specific committed manifest version. commit_hash is the canonical
         *     Relay sha256 wire form (sha256-<64 lowercase hex>). Spec A.9.
         */
        ManifestVersion: {
            /** @constant */
            schema_version: "relay.manifest.v1";
            /** Format: uuid */
            manifest_version_id: string;
            /** Format: uuid */
            manifest_id: string;
            commit_hash: components["schemas"]["Sha256Hash"];
            body: {
                [key: string]: unknown;
            };
            signed_by?: string | null;
            signature?: string | null;
            signature_key_id?: string | null;
            /** Format: date-time */
            effective_at: string;
            effective_until?: string | null;
        };
        /**
         * @description Mutable scope state per (scope_kind, scope_id). Discriminated union
         *     on scope_kind so each kind's allowed state set (spec C.1, spec AM,
         *     spec Q.2) is statically enforced at the wire-format layer. Spec W
         *     lines 5072-5085 enumerate all six scope_kind values; eval_run and
         *     release land in milestone M01 feature w1.7 (VAL-V2M01-036).
         */
        ScopeState: components["schemas"]["RunScopeState"] | components["schemas"]["ReplayCaseScopeState"] | components["schemas"]["GateRoundScopeState"] | components["schemas"]["EvidenceBundleScopeState"] | components["schemas"]["EvalRunScopeState"] | components["schemas"]["ReleaseScopeState"];
        RunScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "run";
            /** @enum {string} */
            state: "pending" | "captured" | "validating" | "gated" | "result_written" | "terminal";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        ReplayCaseScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "replay_case";
            /** @enum {string} */
            state: "proposed" | "fixtures_ready" | "executing" | "analyzed" | "terminal";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        GateRoundScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "gate_round";
            /** @enum {string} */
            state: "open" | "draft_received" | "evaluating" | "decision_written" | "restarted" | "terminal";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        EvidenceBundleScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "evidence_bundle";
            /** @enum {string} */
            state: "building" | "signed" | "published" | "superseded" | "revoked";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        /**
         * @description scope_kind='eval_run' variant of ScopeState. Spec AM eval lifecycle:
         *     pending -> running -> scored | terminal. Initial state 'pending' per
         *     spec W lines 5101-5111. VAL-V2M01-036.
         */
        EvalRunScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "eval_run";
            /** @enum {string} */
            state: "pending" | "running" | "scored" | "terminal";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        /**
         * @description scope_kind='release' variant of ScopeState. Spec Q.2 release
         *     lifecycle: open -> gated -> released | rolled_back | terminal.
         *     Initial state 'open' per spec W lines 5101-5111. VAL-V2M01-036.
         */
        ReleaseScopeState: {
            /** @constant */
            schema_version: "relay.scope_state.v1";
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            scope_kind: "release";
            /** @enum {string} */
            state: "open" | "gated" | "released" | "rolled_back" | "terminal";
            /** Format: uuid */
            scope_id: string;
            /** Format: uuid */
            project_id: string;
            epoch: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        /**
         * @description Request dedupe record. idempotency_key is a Crockford-base32 ULID
         *     (spec B.2/B.6 line 3517). Spec A.12.
         */
        IdempotencyRecord: {
            /** @constant */
            schema_version: "relay.idempotency_record.v1";
            idempotency_key: components["schemas"]["Ulid"];
            /** Format: uuid */
            project_id: string;
            request_digest: components["schemas"]["Sha256Hash"];
            response_status: number;
            response_ref?: string | null;
            /** Format: date-time */
            first_seen_at: string;
            /** Format: date-time */
            expires_at: string;
        };
        /**
         * @description Append-only audit-trail row. occurred_at is RFC 3339 with a required
         *     timezone offset; naive timestamps fail at the hand-authored wrapper
         *     layer (VAL-W1-017). Spec A.11.
         */
        EventLogEntry: {
            /** @constant */
            schema_version: "relay.event_log_entry.v1";
            /** Format: uuid */
            event_id: string;
            /** Format: uuid */
            project_id: string;
            /** @enum {string} */
            scope_type: "run" | "replay" | "gate" | "eval_run" | "release" | "manifest" | "key" | "other";
            /** Format: uuid */
            scope_id: string;
            event_type: string;
            /** @enum {string} */
            actor_kind: "control_plane" | "gate_engine" | "worker" | "sdk" | "user" | "cron";
            actor_id?: string | null;
            manifest_commit_hash?: components["schemas"]["Sha256Hash"] | null;
            /** @default {} */
            payload: {
                [key: string]: unknown;
            };
            /** Format: date-time */
            occurred_at: string;
            ingest_sequence: number;
        };
        /** @description Signed evidence bundle row. Spec J line 2792-2810. */
        EvidenceBundle: {
            /** @constant */
            schema_version: "relay.evidence_bundle.v1";
            /** Format: uuid */
            evidence_bundle_id: string;
            /** Format: uuid */
            org_id: string;
            /** Format: uuid */
            project_id: string;
            scope_type: string;
            /** Format: uuid */
            scope_id: string;
            bundle_digest: components["schemas"]["Sha256Hash"];
            acef_core_version: string;
            relay_extension_version: string;
            signing_key_id?: string | null;
            signature_algorithm?: string | null;
            /** @enum {string} */
            verification_status: "unverified" | "verified" | "tampered" | "revoked";
            redaction_policy_version: string;
            manifest_commit_hash?: components["schemas"]["Sha256Hash"] | null;
            object_ref: string;
            supersedes_bundle_id?: string | null;
            /** Format: date-time */
            created_at: string;
        };
        /** @description Atomic claim inside an evidence bundle. Spec A.16 lines 3331-3353. */
        EvidenceClaim: {
            /** @constant */
            schema_version: "relay.evidence_claim.v1";
            /** Format: uuid */
            evidence_claim_id: string;
            /** Format: uuid */
            evidence_bundle_id: string;
            /** @enum {string} */
            claim_type: "run_result" | "gate_decision" | "contract_result" | "replay_result" | "human_oversight" | "incident" | "data_quality_check" | "provider_compatibility";
            subject_kind: string;
            /** Format: uuid */
            subject_id: string;
            claim_digest: components["schemas"]["Sha256Hash"];
            redaction_transform_version: string;
            manifest_commit_hash: components["schemas"]["Sha256Hash"];
            signer_key_id: string;
            signature: string;
            supersedes_claim_id?: string | null;
            /** Format: date-time */
            created_at: string;
        };
        /** @description Replay case row. Spec A.8 lines 3131-3145. */
        ReplayCase: {
            /** @constant */
            schema_version: "relay.replay_case.v1";
            /** Format: uuid */
            replay_case_id: string;
            /** Format: uuid */
            project_id: string;
            source_run_id?: string | null;
            failure_signature_hash: string;
            inputs_ref: string;
            inputs_digest: components["schemas"]["Sha256Hash"];
            /** @default [] */
            expected_assertion_ids: string[];
            /** @default false */
            human_reviewed: boolean;
            reviewer_email?: string | null;
            reviewed_at?: string | null;
            /**
             * @default proposed
             * @enum {string}
             */
            status: "proposed" | "approved" | "retired";
            /** Format: date-time */
            created_at: string;
        };
        /** @description Replay fixture row. Spec A.8 lines 3147-3168 + E.2-E.3. */
        ReplayFixture: {
            /** @constant */
            schema_version: "relay.replay_fixture.v1";
            /** Format: uuid */
            fixture_id: string;
            /** Format: uuid */
            replay_case_id: string;
            /** Format: uuid */
            source_span_id: string;
            /** @enum {string} */
            kind: "model_call" | "tool_call" | "retrieval" | "embedding" | "custom";
            /** @enum {string} */
            mode: "cassette" | "live" | "degraded_live" | "mock";
            redaction_policy_version: string;
            input_digest: components["schemas"]["Sha256Hash"];
            output_ref?: string | null;
            output_digest?: components["schemas"]["Sha256Hash"] | null;
            provider?: string | null;
            model?: string | null;
            model_signature?: string | null;
            /** Format: date-time */
            capture_clock: string;
            /**
             * @default invalidate_on_signature_change
             * @enum {string}
             */
            refresh_policy: "invalidate_on_signature_change" | "hold_forever" | "refresh_weekly" | "invalidate_on_model_version_change";
            /** @enum {string} */
            side_effect_class: "read_only" | "mutating" | "external_irreversible" | "approval_required";
            /** @default false */
            allowed_in_replay: boolean;
            /** Format: date-time */
            created_at: string;
        };
        RedactionPolicyMatcherRegex: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            kind: "regex";
            pattern: string;
        };
        RedactionPolicyMatcherJsonPointer: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            kind: "json_pointer";
            paths: string[];
        };
        /**
         * @description Tagged discriminated union on `kind` (VAL-W1-028). Spec G.2 lines
         *     4127-4133.
         */
        RedactionPolicyMatcher: components["schemas"]["RedactionPolicyMatcherRegex"] | components["schemas"]["RedactionPolicyMatcherJsonPointer"];
        /** @description Per-org redaction policy version. Spec A.10 lines 3219-3225. */
        RedactionPolicy: {
            /** @constant */
            schema_version: "relay.redaction.v1";
            /** Format: uuid */
            redaction_policy_id: string;
            /** Format: uuid */
            org_id: string;
            version: string;
            /** @default false */
            raw_capture: boolean;
            dpa_ref?: string | null;
            approver_user_id?: string | null;
            /** @default [] */
            matchers: components["schemas"]["RedactionPolicyMatcher"][];
            /** Format: date-time */
            created_at: string;
        };
        /** @description Canonical Relay error envelope. Spec B.4 lines 3392-3408. */
        ErrorEnvelope: {
            /** @constant */
            schema_version: "relay.error.v1";
            code: components["schemas"]["RelayErrorCodeStr"];
            http_status: number;
            blocked_surface: string;
            /** @enum {string} */
            retry_advice: "do_not_retry" | "after_fix" | "after_retry_after" | "after_split" | "after_recapture" | "after_re_auth";
            request_id: string;
            trace_id: string;
            message?: string | null;
            /** @default {} */
            details: {
                [key: string]: unknown;
            };
        };
        /** @description Per-gate policy version. Spec A.5 lines 3063-3076 (VAL-V2M01-001). */
        GatePolicy: {
            /** @constant */
            schema_version: "relay.gate_policy.v1";
            /** Format: uuid */
            gate_policy_id: string;
            /** Format: uuid */
            gate_id: string;
            policy_version: string;
            conditions: {
                [key: string]: unknown;
            };
            baseline_selector?: {
                [key: string]: unknown;
            } | null;
            flaky_quarantine_policy?: {
                [key: string]: unknown;
            } | null;
            /**
             * @default p0_only
             * @enum {string}
             */
            blocking_severity: "p0_only" | "p0_p1" | "any_failure";
            /** Format: date-time */
            effective_at: string;
            effective_until?: string | null;
        };
        /**
         * @description Per-run contract evaluation result. Spec A.6 lines 3082-3102
         *     (VAL-V2M01-002).
         */
        ContractResult: {
            /** @constant */
            schema_version: "relay.contract_result.v1";
            /** Format: uuid */
            contract_result_id: string;
            /** Format: uuid */
            run_id: string;
            /** Format: uuid */
            contract_id: string;
            contract_version: string;
            assertion_id?: string | null;
            span_id?: string | null;
            /** @enum {string} */
            outcome: "pass" | "fail" | "repaired" | "skipped" | "error";
            severity?: ("p0" | "p1" | "p2" | "info") | null;
            raw_signature_hash?: string | null;
            /** @default 0 */
            repair_attempt: number;
            evaluation_engine_version: string;
            /** Format: date-time */
            evaluated_at: string;
            /** @default {} */
            metadata: {
                [key: string]: unknown;
            };
        };
        /**
         * @description Atomic assertion definition. Spec A.7 lines 3108-3125
         *     (VAL-V2M01-003).
         */
        AssertionDefinition: {
            /** @constant */
            schema_version: "relay.assertion_definition.v1";
            assertion_id: string;
            /** Format: uuid */
            project_id: string;
            /** @enum {string} */
            kind: "schema_contract" | "behavioral" | "tool_arg" | "eval" | "coverage";
            /** @enum {string} */
            severity: "p0" | "p1" | "p2" | "info";
            title: string;
            description?: string | null;
            owner_email: string;
            expression: {
                [key: string]: unknown;
            };
            /** @default {} */
            applies_to: {
                [key: string]: unknown;
            };
            /**
             * @default draft
             * @enum {string}
             */
            lifecycle_state: "draft" | "active" | "deprecated" | "retired";
            /** @default 1 */
            current_version: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            updated_at: string;
        };
        /** @description Per-replay outcome row. Spec A.8 lines 3172-3187 (VAL-V2M01-004). */
        ReplayResult: {
            /** @constant */
            schema_version: "relay.replay_result.v1";
            /** Format: uuid */
            replay_result_id: string;
            /** Format: uuid */
            replay_case_id: string;
            /** Format: uuid */
            replay_run_id: string;
            /** @enum {string} */
            outcome: "reproduced" | "diverged" | "blocked" | "sandbox_error";
            failure_signature_match?: boolean | null;
            /** @default 0 */
            fixture_hits: number;
            /** @default 0 */
            fixture_misses: number;
            sandbox_driver: string;
            sandbox_id?: string | null;
            /** @default 0 */
            network_egress_denied: number;
            /** @default 0 */
            side_effect_attempts: number;
            /** @default 0 */
            side_effect_approved: number;
            evidence_bundle_id?: string | null;
            /** Format: date-time */
            created_at: string;
        };
        /**
         * @description Manifest parent identity row. Spec A.9 lines 3193-3199 (VAL-V2M01-005).
         *     Uses schema_version literal `relay.manifest_parent.v1` to avoid
         *     colliding with the existing ManifestVersion `relay.manifest.v1`.
         */
        Manifest: {
            /** @constant */
            schema_version: "relay.manifest_parent.v1";
            /** Format: uuid */
            manifest_id: string;
            /** Format: uuid */
            project_id: string;
            name: string;
            /** Format: date-time */
            created_at: string;
        };
        /** @description Incident cluster row. Spec A.13 lines 3274-3290 (VAL-V2M01-007). */
        Incident: {
            /** @constant */
            schema_version: "relay.incident.v1";
            /** Format: uuid */
            incident_id: string;
            /** Format: uuid */
            project_id: string;
            cluster_signature_hash: string;
            /** @enum {string} */
            severity: "sev1" | "sev2" | "sev3" | "sev4";
            /**
             * @default open
             * @enum {string}
             */
            state: "open" | "mitigated" | "closed" | "suppressed";
            /** @default [] */
            affected_run_ids: string[];
            /** Format: date-time */
            first_seen_at: string;
            /** Format: date-time */
            last_seen_at: string;
            owner_email?: string | null;
            postmortem_ref?: string | null;
            /** @default false */
            promoted_to_regression: boolean;
            created_at?: string | null;
        };
        /**
         * @description Explain root-cause hypothesis. Spec A.15 lines 3316-3328; sectionT
         *     (VAL-V2M01-008).
         */
        RootCauseHypothesis: {
            /** @constant */
            schema_version: "relay.root_cause_hypothesis.v1";
            /** Format: uuid */
            hypothesis_id: string;
            /** Format: uuid */
            run_id: string;
            span_id?: string | null;
            hypothesis_class: string;
            confidence: number;
            /** @default [] */
            evidence_refs: unknown[];
            generator: string;
            reviewer_email?: string | null;
            reviewer_decision?: ("accept" | "reject" | "modify" | "pending") | null;
            promoted_to_replay_case_id?: string | null;
            /** Format: date-time */
            created_at: string;
        };
        /**
         * @description Parent span row. Spec Z lines 1825-1836 (VAL-V2M01-009). span_type
         *     is the polymorphic discriminator that drives the typed-detail
         *     invariant: span_type in {model_call, tool_call, retrieval,
         *     embedding} MUST have a matching typed-detail row in the same
         *     INSERT transaction. span_type='custom' requires no typed-detail
         *     row. Canonical missing-detail error code:
         *     RELAY-INGEST-SPAN-DETAIL-MISSING.
         */
        Span: {
            /** @constant */
            schema_version: "relay.span.v1";
            /** Format: uuid */
            span_id: string;
            run_id?: string | null;
            parent_span_id?: string | null;
            /** @enum {string} */
            span_type: "model_call" | "tool_call" | "retrieval" | "embedding" | "custom";
            name: string;
            status: string;
            /** Format: date-time */
            started_at: string;
            ended_at?: string | null;
            error_class?: string | null;
            /** @default {} */
            metadata: {
                [key: string]: unknown;
            };
        };
        /**
         * @description Typed-detail row for span_type='model_call'. Spec Z lines 5226-5249
         *     (VAL-V2M01-010).
         */
        ModelCallSpan: {
            /** @constant */
            schema_version: "relay.model_call_span.v1";
            /** Format: uuid */
            span_id: string;
            provider: string;
            model: string;
            model_signature?: string | null;
            request_message_count?: number | null;
            request_token_count?: number | null;
            response_token_count?: number | null;
            cached_token_count?: number | null;
            reasoning_token_count?: number | null;
            cost_usd?: number | null;
            latency_ms?: number | null;
            finish_reason?: string | null;
            structured_output_mode?: string | null;
            schema_contract_id?: string | null;
            tool_choice_mode?: string | null;
            /** @default false */
            streaming: boolean;
            input_redaction_policy_version: string;
            input_digest?: string | null;
            output_digest?: string | null;
            http_status?: number | null;
            provider_error_code?: string | null;
            provider_error_class?: string | null;
        };
        /**
         * @description Typed-detail row for span_type='tool_call'. Spec Z lines 5251-5264
         *     (VAL-V2M01-011).
         */
        ToolCallSpan: {
            /** @constant */
            schema_version: "relay.tool_call_span.v1";
            /** Format: uuid */
            span_id: string;
            tool_name: string;
            side_effect_class: string;
            args_digest?: string | null;
            args_redaction_policy_version: string;
            args_schema_contract_id?: string | null;
            args_validation_outcome?: ("pass" | "fail" | "repaired" | "skipped" | "error") | null;
            result_digest?: string | null;
            status: string;
            latency_ms?: number | null;
            marker_id?: string | null;
            parallel_index?: number | null;
        };
        /**
         * @description Typed-detail row for span_type='retrieval'. Spec Z lines 5266-5279
         *     (VAL-V2M01-012).
         */
        RetrievalSpan: {
            /** @constant */
            schema_version: "relay.retrieval_span.v1";
            /** Format: uuid */
            span_id: string;
            retriever_name: string;
            query_digest?: string | null;
            query_redaction_policy_version: string;
            document_count?: number | null;
            duplicate_document_count?: number | null;
            /** @default false */
            empty_retrieval: boolean;
            relevance_proxy_score?: number | null;
            citation_coverage?: number | null;
            context_token_count?: number | null;
            context_waste_tokens?: number | null;
            latency_ms?: number | null;
        };
        /**
         * @description Typed-detail row for span_type='embedding'. Spec Z lines 5281-5290
         *     (VAL-V2M01-013).
         */
        EmbeddingSpan: {
            /** @constant */
            schema_version: "relay.embedding_span.v1";
            /** Format: uuid */
            span_id: string;
            provider: string;
            model: string;
            input_token_count?: number | null;
            embedding_dim?: number | null;
            /** @default false */
            cached: boolean;
            cost_usd?: number | null;
            latency_ms?: number | null;
        };
        /**
         * @description Legal hold row. Spec Y lines 5184-5200 (VAL-V2M01-026). scope_kind
         *     is the closed four-member set {org, project, run, evidence_bundle}.
         *     state is the closed two-member workflow {active, released}.
         */
        EvidenceLegalHold: {
            /** @constant */
            schema_version: "relay.evidence_legal_hold.v1";
            /** Format: uuid */
            hold_id: string;
            /** Format: uuid */
            org_id: string;
            /** @enum {string} */
            scope_kind: "org" | "project" | "run" | "evidence_bundle";
            /** Format: uuid */
            scope_id: string;
            reason: string;
            legal_matter_ref?: string | null;
            /** Format: uuid */
            imposed_by_user_id: string;
            counsel_signoff_at?: string | null;
            counsel_signoff_by?: string | null;
            /**
             * @default active
             * @enum {string}
             */
            state: "active" | "released";
            /** Format: date-time */
            imposed_at: string;
            released_at?: string | null;
            released_by_user_id?: string | null;
        };
        /**
         * @description Mutable sibling row to the immutable signed evidence_bundles
         *     table. Spec Y lines 5202-5213 (VAL-V2M01-027). state is the closed
         *     four-member machine {active, superseded, tombstoned, legal_hold}.
         *     Tombstoned is terminal and records the subject_redaction_tombstone
         *     claim that enables compliant deletion without mutating signed
         *     content (spec Y line 5219). State-machine transition rules beyond
         *     the closed enum live in
         *     relay_schemas.bundle_registry.validate_registry_transition.
         */
        EvidenceBundleRegistry: {
            /** @constant */
            schema_version: "relay.evidence_bundle_registry.v1";
            /** Format: uuid */
            evidence_bundle_id: string;
            /**
             * @default active
             * @enum {string}
             */
            state: "active" | "superseded" | "tombstoned" | "legal_hold";
            superseded_by?: string | null;
            /** @default false */
            subject_redacted_after_signing: boolean;
            redaction_event_ref?: string | null;
            legal_hold_id?: string | null;
            /** Format: date-time */
            last_state_change_at: string;
        };
        /**
         * @description RFC 3161 TSA timestamp row for an evidence bundle. Spec AB lines
         *     5421-5429 (VAL-V2M01-033). One row per bundle. tsa_genTime is
         *     parsed from the TimeStampResp CMS SignerInfo; tsa_response_ref
         *     points at the canonical .tsr blob; tsa_response_digest is the
         *     sha256 over the .tsr bytes so verifiers detect mutation.
         */
        EvidenceTimestamp: {
            /** @constant */
            schema_version: "relay.evidence_timestamp.v1";
            /** Format: uuid */
            evidence_bundle_id: string;
            tsa_url: string;
            tsa_response_digest: string;
            tsa_response_ref: string;
            tsa_serial_number?: string | null;
            /** Format: date-time */
            tsa_genTime: string;
            tsa_witness_signature?: string | null;
        };
        /**
         * @description Append-only public transparency log entry. Spec AB lines 5431-5439
         *     (VAL-V2M01-035). Inspired by Sigstore Rekor. log_index is the
         *     canonical 1-based serial index; tree_root_after is the Merkle root
         *     after the append; inclusion_proof_ref points at the served proof
         *     JSON. Per spec AB line 5445 the log is append-only; application
         *     role grants are INSERT,SELECT only.
         */
        TransparencyLogEntry: {
            /** @constant */
            schema_version: "relay.transparency_log_entry.v1";
            log_index: number;
            /** Format: uuid */
            evidence_bundle_id: string;
            bundle_digest: string;
            signer_key_id: string;
            /** Format: date-time */
            appended_at: string;
            tree_root_after: string;
            inclusion_proof_ref?: string | null;
        };
        /**
         * @description Human-in-the-loop oversight event row. Spec AE lines 5494-5508
         *     (VAL-V2M01-030). oversight_kind is the closed six-member enum
         *     {pre_action_review, post_action_review, escalation, override,
         *     manual_classification, content_review} mirrored from the SQL
         *     CHECK constraint. evidence_refs is a JSON array of evidence-bundle
         *     / evidence-claim references binding the event to durable evidence;
         *     defaults to [] so a freshly-created event can be progressively
         *     enriched before sealing.
         */
        HumanOversightEvent: {
            /** @constant */
            schema_version: "relay.human_oversight_event.v1";
            /** Format: uuid */
            oversight_id: string;
            /** Format: uuid */
            project_id: string;
            run_id?: string | null;
            ai_system_classification_id?: string | null;
            /** @enum {string} */
            oversight_kind: "pre_action_review" | "post_action_review" | "escalation" | "override" | "manual_classification" | "content_review";
            actor_user_id?: string | null;
            decision?: string | null;
            rationale?: string | null;
            /** @default [] */
            evidence_refs: unknown[];
            /** Format: date-time */
            occurred_at: string;
        };
        /**
         * @description Per-dataset data-quality check row. Spec AE lines 5510-5525
         *     (VAL-V2M01-031). check_kind is the closed seven-member enum
         *     {lineage, representativeness, duplicate_detection,
         *     schema_conformance, pii_minimization, licensing, staleness} and
         *     outcome is the closed five-member enum {pass, fail, warn,
         *     skipped, error}; both mirrored from the SQL CHECK constraints.
         *     evaluator canonical forms are 'code:<module>.<fn>:vN' or
         *     'human:<user_id>'; the wire-format layer does not lock the
         *     evaluator grammar.
         */
        DataQualityCheck: {
            /** @constant */
            schema_version: "relay.data_quality_check.v1";
            /** Format: uuid */
            data_quality_check_id: string;
            /** Format: uuid */
            project_id: string;
            dataset_id?: string | null;
            /** @enum {string} */
            check_kind: "lineage" | "representativeness" | "duplicate_detection" | "schema_conformance" | "pii_minimization" | "licensing" | "staleness";
            check_name: string;
            inputs_ref?: string | null;
            /** @enum {string} */
            outcome: "pass" | "fail" | "warn" | "skipped" | "error";
            metric_value?: number | null;
            threshold_value?: number | null;
            evaluator: string;
            /** @default [] */
            evidence_refs: unknown[];
            /** Format: date-time */
            performed_at: string;
        };
        /**
         * @description Per-dataset data-provenance row. Spec AE lines 5527-5539
         *     (VAL-V2M01-032). source_kind is the closed six-member enum
         *     {first_party, licensed, public_domain, web_scrape, synthetic,
         *     user_generated} mirrored from the SQL CHECK constraint.
         *     license_ref is the canonical license identifier (SPDX expression
         *     preferred, e.g. 'Apache-2.0' / 'CC-BY-4.0') or a customer
         *     license-registry URI; the wire-format layer does not lock the
         *     grammar.
         */
        DataProvenanceRecord: {
            /** @constant */
            schema_version: "relay.data_provenance_record.v1";
            /** Format: uuid */
            provenance_id: string;
            /** Format: uuid */
            project_id: string;
            /** Format: uuid */
            dataset_id: string;
            /** @enum {string} */
            source_kind: "first_party" | "licensed" | "public_domain" | "web_scrape" | "synthetic" | "user_generated";
            license_ref?: string | null;
            acquired_at?: string | null;
            acquired_by_user_id?: string | null;
            notes?: string | null;
            /** @default [] */
            evidence_refs: unknown[];
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    getDiagnosticsSqlite: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description SQLite diagnostics snapshot. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getDiagnosticsRuntime: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Runtime diagnostics snapshot */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Missing or invalid bearer token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getDiagnosticsQuiesce: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Quiesce-state snapshot. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getDiagnosticsDb: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Database diagnostics snapshot. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    postV1Ingest: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Ingest probe accepted. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Malformed request body. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Sidecar draining; retry after the indicated window. */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    postV1IngestRuns: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Run lifecycle envelope accepted for processing. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure or stale three-anchor handoff. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    postV1IngestSpansBatch: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Span batch accepted. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure (oversize, deep, or malformed). */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    postV1IngestContractResultsBatch: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Contract-result batch accepted. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Missing or invalid bearer token. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    listProjectRuns: {
        parameters: {
            query?: {
                cursor?: string;
                limit?: number;
            };
            header?: never;
            path: {
                project_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A paginated page of runs with a next_cursor field. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Invalid cursor or query parameters. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Run envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Run not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getRunTrace: {
        parameters: {
            query?: {
                cursor?: string;
            };
            header?: never;
            path: {
                run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of spans + next_cursor. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Run not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getRunResult: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Canonical RunResult envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunResult"];
                };
            };
            /** @description Run or run_result not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getRunExplain: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Explain result payload. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Run not found or no explain output yet. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createReplayCase: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReplayCase"];
            };
        };
        responses: {
            /** @description Replay case created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReplayCase"];
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getReplayCase: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description ReplayCase envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReplayCase"];
                };
            };
            /** @description Replay case not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    addReplayFixture: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReplayFixture"];
            };
        };
        responses: {
            /** @description Fixture attached. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReplayFixture"];
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Replay case not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    runReplayCase: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                case_id: string;
            };
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Replay execution enqueued. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure or policy violation. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Replay case not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getReplayResult: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                result_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description ReplayResult envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReplayResult"];
                };
            };
            /** @description Replay result not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createEvalDataset: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Eval dataset created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createEvalRun: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Eval run enqueued. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getEvalRun: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                eval_run_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Eval run envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Eval run not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    putGate: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                gate_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Gate definition upserted. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    putGatePolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                policy_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["GatePolicy"];
            };
        };
        responses: {
            /** @description Gate policy upserted. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GatePolicy"];
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    submitGateDecisionDraft: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                gate_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["GateDecisionDraft"];
            };
        };
        responses: {
            /** @description Draft accepted for resolution. */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GateDecisionDraft"];
                };
            };
            /** @description Validation failure or stale three-anchor handoff. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Conflicting in-flight draft for the same (scope, round). */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getGateDecision: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                decision_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Canonical GateDecision envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GateDecision"];
                };
            };
            /** @description Gate decision not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    listGateRounds: {
        parameters: {
            query?: {
                cursor?: string;
            };
            header?: never;
            path: {
                gate_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Page of gate rounds with next_cursor. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Invalid cursor. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createEvidenceBundle: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EvidenceBundle"];
            };
        };
        responses: {
            /** @description Evidence bundle created. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EvidenceBundle"];
                };
            };
            /** @description Validation failure or missing claim binding. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getEvidenceBundle: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                bundle_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Evidence bundle envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EvidenceBundle"];
                };
            };
            /** @description Bundle not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    downloadEvidenceBundle: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                bundle_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Bundle artifact bytes. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/octet-stream": string;
                };
            };
            /** @description Bundle not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Bundle tombstoned or under legal hold and not retrievable. */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    verifyEvidenceBundle: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                bundle_id: string;
            };
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Verification verdict payload. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Verification failed (tampered, missing artifact, etc). */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Bundle not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createManifestVersion: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ManifestVersion"];
            };
        };
        responses: {
            /** @description Manifest version recorded. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManifestVersion"];
                };
            };
            /** @description Validation failure or signature mismatch. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getManifestVersion: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
                commit_hash: components["schemas"]["Sha256Hash"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description ManifestVersion envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManifestVersion"];
                };
            };
            /** @description Manifest or version not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createRedactionPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RedactionPolicy"];
            };
        };
        responses: {
            /** @description Redaction policy published. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RedactionPolicy"];
                };
            };
            /** @description Validation failure, ReDoS-budget exceeded, or DPA missing. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    getRedactionPolicy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                policy_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description RedactionPolicy envelope. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RedactionPolicy"];
                };
            };
            /** @description Policy not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    createAuthToken: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Token issued. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation failure. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Caller not authorised to mint tokens. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    revokeAuthToken: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                token_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Token revoked. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Token not found. */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
    postV1StateTransition: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    [key: string]: unknown;
                };
            };
        };
        responses: {
            /** @description Transition applied; canonical scope_state updated. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Malformed body, missing anchors, or invalid transition. */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
            /** @description Stale three-anchor handoff or guard failure. */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ErrorEnvelope"];
                };
            };
        };
    };
}
