# Guard Registry Index

This file is the authoritative cross-reference between each guard named in
CLAUDE.md "REQUIRED GUARD TESTS" and the test file that encodes the guard's
behavior. It satisfies VAL-V3M5-024 (spec section U).

The companion test `tests/guards/test_guard_registry_index.py` parses this
file and asserts:

1. Every guard named in CLAUDE.md "REQUIRED GUARD TESTS" has a row here.
2. Every test file path listed below exists in the repository.
3. Every named `Test function` exists in the listed file.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

## Required guards

| Guard name | Asserts | Test file path | Test function |
|---|---|---|---|
| RunResult ownership guard | SDK/agent/eval worker cannot write `written_by != control_plane` or directly mark `accepted`; canonical-status fields rejected at sidecar boundary with HTTP 422 + RELAY-ING-031 | apps/local-sidecar/tests/test_v2m02_ingest.py | test_ingest_runs_rejects_sdk_set_canonical_status |
| Coverage invariant guard | Every active assertion has exactly one owner; no orphans; no duplicate primary ownership; `rly contract publish` rejects orphan assertions with RELAY-COVERAGE-001 | packages/cli/tests/test_w6_6_contract_publish.py | test_publish_rejects_orphan_assertions |
| Gate restart guard | Late testing failure does NOT retry only the testing gate; pipeline restarts at scrutiny (no carry-forward of decisions; new gate_rounds row created) | packages/gate/tests/test_w8_3_restart.py | test_restart_creates_new_gate_rounds_row |
| Stale handoff guard | Mismatched feature/run ID, worker ID, or commit hash is rejected and logged with structured reason (SCOPE_ID_MISMATCH / ACTOR_NOT_REGISTERED / MANIFEST_NOT_ACTIVE) | apps/local-sidecar/tests/test_three_anchor_handoff.py | test_scope_id_mismatch_for_run |
| Evidence pairing guard | A claim with `evidence_refs[].digest` that does not resolve to an artifact in the bundle's manifest is rejected with `evidence_ref_artifact_missing_from_manifest` (per spec section K) | packages/verifier/tests/test_v3m1_claim_rules.py | test_val_v3m1_017_pg_migration_has_supersedes_check |
| Manifest source-of-truth guard | Gate runner executes only manifest-declared commands by `command_hash`; undeclared commands or hash mismatches are rejected | apps/local-sidecar/tests/test_v2m03_manifest_enforcement.py | test_registry_rejects_undeclared_command |
| Side-effect idempotency guard | Side-effecting tool lacks pre-action marker and post-success proof is blocked at adapter boundary | packages/sdk-python/tests/test_adapter_side_effects.py | test_side_effecting_tool_emits_pre_and_post_markers |
| Atomic write guard | Persistent writes to the sidecar lockfile do NOT bypass the four atomic primitives (no direct `open(..., 'w')`, no `Path.write_text`, no `shutil.copy`) | apps/local-sidecar/tests/test_atomic_primitive_guard.py | test_no_direct_open_write_on_sidecar_lock |
| Anti-bypass guard | Protected workflows refuse event_log payloads carrying bypass markers (`--no-verify`, `--no-gpg-sign`, `--skip-hooks`, `pytest.mark.skip`, `# TODO`, `# FIXME`, `# HACK`); RELAY-SIDECAR-BYPASS-MARKER-DETECTED is returned | apps/local-sidecar/tests/test_anti_bypass.py | test_marker_set_matches_contract |
| Context reinjection guard | A resumed worker that holds a STALE manifest_commit_hash relative to the scope's pinned hash is refused at the HTTP boundary with 409 + RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED | apps/local-sidecar/tests/test_context_reinjection_guard.py | test_stale_manifest_hash_returns_context_not_rehydrated |

## Why this index exists

CLAUDE.md "REQUIRED GUARD TESTS" enumerates ten architectural invariants that
must remain green at all times. Without a single registry, a reviewer has to
search the tree by topic to confirm a guard exists. This file makes the
mapping explicit and machine-checkable, so a missing or renamed guard is
caught immediately by the registry test rather than during a future audit.

## Adding a new guard

When CLAUDE.md gains a new entry in "REQUIRED GUARD TESTS":

1. Add a row to the table above with the canonical guard name (matching the
   CLAUDE.md "Guard" column), a one-sentence assertion summary, the
   `tests/` or `apps/` or `packages/` path of the test file, and the
   exact name of the test function that encodes the guard.
2. Update the test name parser in `tests/guards/test_guard_registry_index.py`
   if the new guard name introduces a token the parser does not yet
   recognize (extend `REQUIRED_GUARD_NAMES`).
3. Run `pytest tests/guards/test_guard_registry_index.py -m plumbing -v`
   and confirm it passes.

Spec: §U, §AM
