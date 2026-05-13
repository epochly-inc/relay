/* GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
 * Regenerate: uv run python packages/schemas/scripts/codegen.py
 * Drift check: uv run python scripts/check-codegen-drift.py
 */

export type paths = Record<string, never>;
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
         *     Spec C.5.
         */
        Actor: {
            identity_hash: components["schemas"]["Sha256Hash"];
            /** @enum {string} */
            kind: "human" | "bot" | "worker" | "reviewer";
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
         *     on scope_kind so each kind's allowed state set (spec C.1) is
         *     statically enforced at the wire-format layer. Spec W.
         */
        ScopeState: components["schemas"]["RunScopeState"] | components["schemas"]["ReplayCaseScopeState"] | components["schemas"]["GateRoundScopeState"] | components["schemas"]["EvidenceBundleScopeState"];
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
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
