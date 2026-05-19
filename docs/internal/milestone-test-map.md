# Milestone Test Inventory

Fulfills: **VAL-V3M5-026** (W13/W14/W15 test inventory documented).

This document maps each operation milestone to the test files that provide its
evidence. It exists because the R5 audit flagged W13, W14, and W15 as "thin"
based on a `test_w*.py` filename-prefix count (one file each, versus 11-20
for neighboring milestones). The thin-count signal was a false positive: each
W13/W14/W15 test file is **a dense parser-driven harness covering 13 VAL
assertions** (one `@pytest.mark.fulfills` decorator per assertion), so the
per-assertion test coverage is comparable to or higher than the neighboring
milestones that use one-test-file-per-validator. This document records that
disposition so future audits do not re-raise the same false alarm.

The authoritative inventory is built from two sources of truth:

1. Filename prefix (`test_w<N>_*.py`) — the W1-W17 v0.1 OSS-wedge operation
   convention.
2. `@pytest.mark.fulfills("VAL-<MILESTONE>-NNN")` decorators — the
   gate-engine-readable binding from test cases to contract assertions.
   This is the authoritative source per CLAUDE.md "TDD ENFORCEMENT RULES"
   and `manifest.yaml::test_discovery.fulfills_marker_format`.

Counts in this document are produced by the inventory commands recorded in
the "Reproducing the inventory" section at the bottom.

---

## Operation: relay-v0.1-oss-wedge (W1..W17)

| Milestone | Named test files (`test_w<N>_*.py`) | Files w/ `VAL-W<N>-NNN` fulfills | Additional non-prefixed evidence |
|---|---|---|---|
| W1 (schemas, codegen) | 0 | 4 | `packages/schemas/python/tests/test_codegen_pipeline.py`, `test_envelopes.py`, `test_error_codes_coverage.py`, `test_golden_corpus.py` — all carry `VAL-W1-*` fulfills decorators. Filename prefix not used; the package-local naming convention took over. |
| W2 (sidecar) | 0 | 59 | Entire `apps/local-sidecar/tests/` suite (state engine, lockfile, WAL, retention, schema-version mismatch, NFS detection, lifespan, drain, three-anchor handoff). Files use descriptive names, not the `test_w2_*.py` prefix. |
| W3 (Python SDK) | 0 | 24 | Entire `packages/sdk-python/tests/` suite (adapters OpenAI/Anthropic, autospawn race, idempotency ULID, redaction, evidence submit, gate evaluate, replay create/mode, version-compat). Descriptive names. |
| W4 (TypeScript SDK) | 0 | 1 | `packages/sdk-python/tests/test_exit_code_parity.py` (cross-language exit-code parity guard). TS-side coverage lives in `packages/sdk-typescript/test/*.test.ts` and `packages/contracts-typescript/test/*.test.ts` (vitest, not pytest, so not enumerated by the pytest-prefix grep). |
| W5 (CLI) | `test_w5_1_skeleton.py`, `test_w5_2_sidecar_commands.py`, `test_w5_3_replay_commands.py`, `test_w5_4_evidence_commands.py`, `test_w5_5_verify_self.py` | 5 | — |
| W6 (contracts DSL) | `test_w6_1_evaluator.py`, `test_w6_3_behavior.py`, `test_w6_3_determinism.py`, `test_w6_3_registration.py`, `test_w6_3_timeout.py`, `test_w6_4_dsl_parser.py`, `test_w6_5_corpus.py`, `test_w6_6_contract_publish.py` | 7 | The corpus-driven `tests/conformance/cel/` tree adds breadth (UDF coverage, idiom coverage, purity, timing, release block). |
| W7 (replay proxy) | `test_w7_1_harness.py`, `test_w7_2_cassette_format.py`, `test_w7_2_cassette_security.py`, `test_w7_3_socket_deny.py`, `test_w7_5_egress_denial_python.py`, `test_w7_5_exit_code_matrix.py`, `test_w7_5_side_effects_and_replay.py`, `test_w7_5_subprocess_curl.py` | 7 | `tests/integration/test_egress_denial.py` (cross-transport egress block; called by `manifest.yaml::test-egress-denial`). |
| W8 (gate engine) | `test_w8_1_anti_bypass.py`, `test_w8_1_concurrent_draft.py`, `test_w8_1_determinism.py`, `test_w8_1_evidence_by_id.py`, `test_w8_1_pipeline_order.py`, `test_w8_1_priority_order.py`, `test_w8_1_ttl.py`, `test_w8_1_w6_conditions.py`, `test_w8_2_decision_writer.py`, `test_w8_3_restart.py`, `test_w8_4_admin_actions.py`, `test_w8_4_cap_config.py`, `test_w8_4_circuit_breaker.py` | 13 | — |
| W9 (evals + supply-chain CLI verifiers) | `test_w9_1_delta.py`, `test_w9_1_invariants.py`, `test_w9_1_runner.py`, `test_w9_2_templates.py`, `test_w9_3_llm_judge.py`, `test_w9_dependencies.py`, `test_w9_rekor_verifier.py`, `test_w9_sigstore_verifier.py`, `test_w9_tsa_verifier.py` | 5 | The W9-prefixed Sigstore/Rekor/TSA tests in `packages/cli/tests/` and `packages/verifier/tests/` add 4 files of supply-chain coverage; not all of these carry a `VAL-W9-NNN` fulfills decorator (some bind to W10 trust-anchor or W12 release assertions). |
| W10 (verifier) | `test_w10_1_default_jwks_url.py`, `test_w10_1_jwks_loader.py`, `test_w10_2_rfc7515_corpus.py`, `test_w10_3_bundle_digest.py`, `test_w10_3_jcs_corpus.py`, `test_w10_4_bundle_validator.py`, `test_w10_4_chain_and_invariants.py`, `test_w10_4_key_lifecycle.py`, `test_w10_4_retention_and_anchor.py`, `test_w10_4_round4_p1_fixes.py`, `test_w10_4_tsa_and_log.py` | 12 | `packages/verifier/tests/guards/test_default_trust_anchor_lock.py` (keystone #13 guard). |
| W11 (ACEF) | `test_w11_1_vendor_drift_guard.py`, `test_w11_2_x_relay_extensions.py`, `test_w11_3_acef_roundtrip.py` | 3 | — |
| W12 (release pipeline) | `test_w12_1_pre_announcement.py`, `test_w12_1_publish_workflow_guard.py`, `test_w12_1_semver_monotonic.py`, `test_w12_2_npm_publish_workflow_guard.py`, `test_w12_3_slsa_provenance.py`, `test_w12_4_in_toto_attestations.py`, `test_w12_5_build_driver.py`, `test_w12_5_sidecar_bundle_workflow.py`, `test_w12_6_release_evidence_bundle.py`, `test_w12_6_runbook_gate.py`, `test_w12_6_verify_install.py` | 11 | `scripts/check-npm-publish-workflow.py`, `scripts/check-in-toto-attestations.py` (manifest lint gates `lint-npm-publish-workflow`, `lint-in-toto-attestations-*`) provide additional automated checks. |
| **W13 (trust anchor governance doc)** | `tests/docs/test_w13_1_trust_anchor_governance_doc.py` (1 file, **13 fulfills decorators**) | 1 | The single test file is a parser-driven harness against `docs/legal/trust-anchor-governance.md` covering VAL-W13-001 through VAL-W13-013. Per-assertion coverage is dense, not thin. No additional non-prefixed evidence — this is the only validator and that is by design (the validator IS the doc parser). |
| **W14 (EU AI Act readiness doc)** | `tests/docs/test_w14_1_ai_act_readiness_doc.py` (1 file, **13 fulfills decorators**) | 1 | Parser-driven harness against `docs/internal/eu-ai-act-readiness-draft.md` covering VAL-W14-001 through VAL-W14-013. Includes the highest-stakes banned-copy assertion in the operation (VAL-W14-005, whole-file scan for the forbidden product-claim tokens including front-matter, closing C-GAP-007). Cross-reinforced by `scripts/lint-banned-copy.py` (manifest gate `lint-banned-copy`) which scans `docs/internal/eu-ai-act-readiness-draft.md` as part of the workspace-wide pass. The forbidden-token list is defined in the lint script. |
| **W15 (sandbox threat model doc)** | `tests/docs/test_w15_1_sandbox_threat_model_doc.py` (1 file, **13 fulfills decorators**) | 1 | Parser-driven harness against `docs/architecture/sandbox-threat-model.md` covering VAL-W15-001 through VAL-W15-013. Cross-reinforced by the existing replay-proxy and sandbox-protocol tests in `apps/replay-proxy/tests/` and `packages/replay-sandbox-protocol/tests/`, which exercise the controls the threat model documents (egress deny, subprocess curl block, side-effect class enforcement). |
| W16 (examples) | `test_w16_1_*` (5 files), `test_w16_2_*` (5), `test_w16_3_*` (5), `test_w16_4_*` (5) — 20 files across `tests/examples/` | 20 | Each example (openai-tool-agent, langchain-rag-agent, vercel-ai-tool-agent, mcp-tool-agent) gets 5 validators: cassettes, directory_structure, lifecycle_e2e, manifest_schema, readme. |
| W17 (conformance corpora) | `test_w17_1_rfc8785_corpus.py` (JCS), `test_w17_2_hs_helper_isolation.py`, `test_w17_2_rfc7515_appendix_a.py` (JWS), `test_w17_3_celspec_corpus.py` (CEL spec), `test_w17_4_*` (7 files, Relay CEL Corpus) | 11 | — |

### W13/W14/W15 — explicit disposition

**The R5 audit flag was a false positive.** A `find … -name 'test_w13_*.py'`
returns one file per milestone, which looks thin compared to W10 (11 files)
or W16 (20 files). However:

1. **Each W13/W14/W15 test file carries 13 `@pytest.mark.fulfills("VAL-W<N>-NNN")`
   decorators.** Per-assertion coverage is identical to a hypothetical
   13-files-of-1-assertion-each layout. The gate engine's coverage check
   does not care about file count; it cares about fulfills coverage of each
   contract assertion.

2. **The single-file-per-doc pattern is correct for doc-validator tests.**
   The validator is a Markdown parser (`markdown_it` for W13/W15,
   `markdown_it` + YAML front-matter parser for W14) that loads the doc
   once and runs all assertions against the parsed AST. Splitting that
   into 13 files would force the parser to re-read the doc 13 times
   without adding any coverage — it would be cargo-culting filename
   conventions.

3. **Cross-reinforcing evidence exists for each of W13/W14/W15:**
   - W13 (`trust-anchor-governance.md`) is cross-reinforced by
     `packages/verifier/tests/guards/test_default_trust_anchor_lock.py`
     (keystone invariant #13 — default trust anchor URL lock), the
     `test_w10_1_default_jwks_url.py` JWKS-URL test, and
     `lint-banned-copy.py`.
   - W14 (`eu-ai-act-readiness-draft.md`) is cross-reinforced by
     `scripts/lint-banned-copy.py` (manifest gate `lint-banned-copy`),
     which independently scans for the forbidden product-claim tokens
     across the whole workspace. The token list is defined in the lint
     script (see `_BANNED_REGEX` for the canonical pattern).
   - W15 (`sandbox-threat-model.md`) is cross-reinforced by:
     - `apps/replay-proxy/tests/test_w7_5_egress_denial_python.py`,
       `test_w7_5_subprocess_curl.py`, `test_w7_5_side_effects_and_replay.py`,
       `test_w7_3_socket_deny.py` — controls the threat model documents.
     - `packages/replay-sandbox-protocol/tests/test_v2m04_sandbox_protocol.py`
       — sandbox protocol envelope.
     - `tests/integration/test_egress_denial.py` — cross-transport block.

4. **Per VAL-V3M5-026 (option b), the cross-reference to non-prefixed
   tests covering the milestone's acceptance criteria is documented here.**
   Backfilling additional `test_w13_2_*.py` / `test_w14_2_*.py` /
   `test_w15_2_*.py` files for cosmetic count parity is explicitly NOT
   the chosen disposition; it would dilute the fulfills-per-file density
   and add no new coverage.

---

## Operation: relay-v0.2-spec-conformance (V2M01..V2M08)

| Milestone | Named test files (`test_v2m<NN>_*.py`) | Files w/ `VAL-V2M<NN>-NNN` fulfills | Additional non-prefixed evidence |
|---|---|---|---|
| V2M01 (schema closure) | `test_v2m01_envelopes.py`, `test_v2m01_evidence_timestamps.py`, `test_v2m01_human_oversight.py`, `test_v2m01_legal_holds.py`, `test_v2m01_scope_state_extension.py`, `test_v2m01_metric_catalog.py` | 6 | — |
| V2M02 (HTTP API completeness) | `test_v2m02_auth_scope.py`, `test_v2m02_eval_endpoints.py`, `test_v2m02_evidence_endpoints.py`, `test_v2m02_gate_endpoints.py`, `test_v2m02_idempotency.py`, `test_v2m02_ingest.py`, `test_v2m02_manifest_endpoints.py`, `test_v2m02_pagination.py`, `test_v2m02_rate_limit.py`, `test_v2m02_redaction_policy_endpoints.py`, `test_v2m02_replay_endpoints.py`, `test_v2m02_runs_endpoints.py` | 12 | — |
| V2M03 (state engine + manifest enforcement) | `test_v2m03_manifest_enforcement.py`, `test_v2m03_state_guards.py`, `test_v2m03_manifest.py` | 4 | `apps/local-sidecar/tests/test_local_two_layer_locked_write.py` (keystone #8 primitive). |
| V2M04 (side-effect classes + replay) | `test_v2m04_side_effects.py` (sidecar + schemas), `test_v2m04_replay.py`, `test_v2m04_constants_removed.py`, `test_v2m04_sandbox_protocol.py` | 5 | — |
| V2M05 (explain / hypothesis generation) | `test_v2m05_explain.py` | 1 | The single file is a dense harness covering the explain harness end-to-end (quality report, per-class breakdown via R5 follow-up, hypothesis generation). Pattern matches W13/14/15 — one-file-many-fulfills, not thin. |
| V2M06 | (none) | 0 | V2M06 was deleted/folded during /ops-plan revision; no contract assertions remain under that ID. |
| V2M07 (CLI completeness) | `test_v2m07_cli_completeness.py` | 2 | `tests/contract/cli/test_exit_code_7_removed.py`. |
| V2M08 (hardening + replay determinism) | `test_v2m08_replay_determinism.py`, `test_v2m08_redaction.py`, `test_v2m08_bundle_paths.py`, `test_v2m08_trust_anchor.py`, `test_v2m08_ai_hardening.py`, `test_v2m08_tooling.py` | 6 | — |

---

## Operation: relay-v0.3-audit-resolution (V3M1..V3M5) — in progress

This operation (the current one) follows the per-assertion `@pytest.mark.fulfills("VAL-V3M<N>-NNN")` binding convention and does NOT use the `test_w*.py` filename prefix. Test files are named for the area they cover (e.g., `test_audit_v3_join_tables.py`, `test_audit_v3_manifest_side_effect_binding.py`).

When V3M5 seals, this section will be backfilled with the final file inventory.

---

## Reproducing the inventory

```bash
# List every test_w<N>_*.py file (v0.1 OSS-wedge filename convention).
find packages/ apps/ tests/ -name 'test_w*.py' -type f | sort

# List every test_v2m<NN>_*.py file (v0.2 spec-conformance filename convention).
find packages/ apps/ tests/ -name 'test_v2m*.py' -type f | sort

# Count assertion-level fulfills per W milestone (authoritative coverage source).
for w in W1 W2 W3 W4 W5 W6 W7 W8 W9 W10 W11 W12 W13 W14 W15 W16 W17; do
  count=$(grep -rln "fulfills..VAL-${w}-" packages/ apps/ tests/ 2>/dev/null | wc -l | tr -d ' ')
  echo "${w}: ${count} files"
done

# Count individual @pytest.mark.fulfills decorators per W13/14/15 file
# (proves the per-file density).
grep -c '@pytest.mark.fulfills' \
  tests/docs/test_w13_1_trust_anchor_governance_doc.py \
  tests/docs/test_w14_1_ai_act_readiness_doc.py \
  tests/docs/test_w15_1_sandbox_threat_model_doc.py
```

Expected output of the per-W13/14/15 decorator count at the time this doc was
written (commit `4d181e6`, the worker-start commit for v0.3 m5-f15):

```
tests/docs/test_w13_1_trust_anchor_governance_doc.py: 14
tests/docs/test_w14_1_ai_act_readiness_doc.py: 14
tests/docs/test_w15_1_sandbox_threat_model_doc.py: 14
```

(14 = 13 `@pytest.mark.fulfills(...)` decorators on test functions + 1 mention
in the module docstring. The 13-assertion coverage per file is the load-bearing
number for the audit disposition.)
