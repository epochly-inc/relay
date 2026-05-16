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
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
