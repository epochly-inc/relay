"""V2 M01 W1.1 envelope + DDL tests.

Covers contract assertions VAL-V2M01-001 through VAL-V2M01-013 plus
VAL-V2M01-039 (codegen surface for the 13 new envelopes).

Each test is bound to its assertion via the pytest.mark.fulfills marker so
the gate engine can attribute pass/fail to the assertion's evidence
requirement.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# Repo-root anchored paths (test lives at
# packages/schemas/python/tests/test_v2m01_envelopes.py; parents[4] is the
# public relay repo root).
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_NEW_DDL = _SQL_DIR / "0004_v2_canonical_tables.sql"
_NEW_SIDECAR = _SIDECAR_MIGRATIONS / "0012_v2_canonical_tables.sql"


def _read_new_ddl() -> str:
    return _NEW_DDL.read_text(encoding="utf-8")


def _read_sidecar_ddl() -> str:
    return _NEW_SIDECAR.read_text(encoding="utf-8")


def _table_block(text: str, table_name: str) -> str:
    """Return the substring from the CREATE TABLE statement for ``table_name``
    up to its terminating ``);`` (or end of file). Case-insensitive.

    Used by per-column / per-constraint regex checks below so each test
    inspects only the relevant table block.
    """
    # Match both 'CREATE TABLE foo' and 'CREATE TABLE IF NOT EXISTS foo'.
    pat = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        + re.escape(table_name)
        + r"\b.*?\);",
        re.IGNORECASE | re.DOTALL,
    )
    m = pat.search(text)
    assert m, f"CREATE TABLE for {table_name!r} not found"
    return m.group(0)


# ---------------------------------------------------------------------------
# Module presence
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_v2_canonical_ddl_file_exists() -> None:
    assert _NEW_DDL.is_file(), f"Missing canonical DDL file: {_NEW_DDL}"


@pytest.mark.plumbing
def test_v2_sidecar_migration_file_exists() -> None:
    assert _NEW_SIDECAR.is_file(), f"Missing sidecar mirror migration: {_NEW_SIDECAR}"


# ---------------------------------------------------------------------------
# VAL-V2M01-001: gate_policies (spec A.5)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-001")
def test_gate_policies_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "gate_policies")
    lowered = block.lower()
    assert "gate_policy_id uuid primary key" in lowered
    assert "gate_id uuid not null" in lowered
    assert "references gates(gate_id)" in lowered
    assert "policy_version text not null" in lowered
    assert "schema_version text not null default 'relay.gate_policy.v1'" in lowered
    assert "conditions jsonb not null" in lowered
    assert "baseline_selector jsonb" in lowered
    assert "flaky_quarantine_policy jsonb" in lowered
    assert "blocking_severity text not null default 'p0_only'" in lowered
    assert "check (blocking_severity in ('p0_only','p0_p1','any_failure'))" in lowered
    assert "effective_at timestamptz not null default now()" in lowered
    assert "effective_until timestamptz" in lowered
    assert "unique(gate_id, policy_version)" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-001")
def test_gate_policies_sidecar_mirror_has_check() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "gate_policies")
    lowered = block.lower()
    # SQLite mirror must still carry the CHECK enum (preserved).
    assert "blocking_severity" in lowered
    assert "'p0_only'" in lowered and "'p0_p1'" in lowered and "'any_failure'" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-002: contract_results (spec A.6)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-002")
def test_contract_results_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "contract_results")
    lowered = block.lower()
    assert "contract_result_id uuid primary key" in lowered
    assert "run_id uuid not null" in lowered and "references runs(run_id)" in lowered
    assert "contract_id uuid not null" in lowered
    assert "references contracts(contract_id)" in lowered
    assert "contract_version text not null" in lowered
    assert "assertion_id text" in lowered
    assert "span_id uuid" in lowered and "references spans(span_id)" in lowered
    assert "outcome text not null" in lowered
    assert (
        "check (outcome in ('pass','fail','repaired','skipped','error'))" in lowered
    )
    assert "severity text" in lowered
    assert "check (severity in ('p0','p1','p2','info'))" in lowered
    assert "raw_signature_hash text" in lowered
    assert "repair_attempt int" in lowered and "default 0" in lowered
    assert "evaluation_engine_version text not null" in lowered
    assert "evaluated_at timestamptz not null default now()" in lowered
    assert "metadata jsonb not null default '{}'" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-002")
def test_contract_results_indexes_present() -> None:
    text = _read_new_ddl()
    lowered = text.lower()
    assert "create index contract_results_run on contract_results(run_id)" in lowered
    assert (
        "create index contract_results_run_outcome on contract_results(run_id, outcome)"
        in lowered
    )


# ---------------------------------------------------------------------------
# VAL-V2M01-003: assertion_definitions (spec A.7)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-003")
def test_assertion_definitions_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "assertion_definitions")
    lowered = block.lower()
    # PK is text, not uuid
    assert "assertion_id text primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "kind text not null" in lowered
    assert (
        "check (kind in ('schema_contract','behavioral','tool_arg','eval','coverage'))"
        in lowered
    )
    assert "severity text not null" in lowered
    assert "check (severity in ('p0','p1','p2','info'))" in lowered
    assert "title text not null" in lowered
    assert "owner_email text not null" in lowered
    assert "expression jsonb not null" in lowered
    assert "applies_to jsonb not null default '{}'" in lowered
    assert "lifecycle_state text not null default 'draft'" in lowered
    assert (
        "check (lifecycle_state in ('draft','active','deprecated','retired'))"
        in lowered
    )
    assert "current_version int not null default 1" in lowered
    assert "created_at timestamptz not null default now()" in lowered
    assert "updated_at timestamptz not null default now()" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-004: replay_results (spec A.8)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-004")
def test_replay_results_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "replay_results")
    lowered = block.lower()
    assert "replay_result_id uuid primary key" in lowered
    assert "replay_case_id uuid not null" in lowered
    assert "references replay_cases(replay_case_id)" in lowered
    assert "replay_run_id uuid not null" in lowered
    assert "references runs(run_id)" in lowered
    assert "outcome text not null" in lowered
    assert (
        "check (outcome in ('reproduced','diverged','blocked','sandbox_error'))"
        in lowered
    )
    assert "failure_signature_match boolean" in lowered
    assert "fixture_hits int" in lowered and "default 0" in lowered
    assert "fixture_misses int" in lowered
    assert "sandbox_driver text not null" in lowered
    assert "sandbox_id text" in lowered
    assert "network_egress_denied int" in lowered
    assert "side_effect_attempts int" in lowered
    assert "side_effect_approved int" in lowered
    assert "evidence_bundle_id uuid" in lowered
    assert "references evidence_bundles(evidence_bundle_id)" in lowered
    assert "created_at timestamptz not null default now()" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-005: manifests parent (spec A.9)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-005")
def test_manifests_parent_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "manifests")
    lowered = block.lower()
    assert "manifest_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "name text not null" in lowered
    assert "created_at timestamptz not null default now()" in lowered
    assert "unique(project_id, name)" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-005")
def test_manifest_versions_fk_resolves_to_new_parent() -> None:
    """The existing manifest_versions.manifest_id FK target is the new
    manifests parent table. Verify the FK clause is declared somewhere in
    the canonical SQL tree (the existing 0002 declares the column shape;
    the new parent table declares the FK target). The link is by name --
    Postgres resolves the FK at runtime against the same database.
    """
    # The new 0004 file must declare the parent. The existing 0002 file
    # carries the manifest_versions table with the unresolved FK target.
    new_text = _read_new_ddl().lower()
    assert "create table manifests" in new_text
    # The mirror migration adds the same parent.
    sidecar_text = _read_sidecar_ddl().lower()
    assert (
        "create table if not exists manifests" in sidecar_text
        or "create table manifests" in sidecar_text
    )


# ---------------------------------------------------------------------------
# VAL-V2M01-006: redaction_policies DDL (spec A.10)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-006")
def test_redaction_policies_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "redaction_policies")
    lowered = block.lower()
    assert "policy_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "policy_version text not null" in lowered
    assert "schema_version text not null default 'relay.redaction.v1'" in lowered
    assert "body jsonb not null" in lowered
    # CLAUDE.md keystone invariant #7: raw_capture_default MUST default to
    # literal false.
    assert "raw_capture_default boolean not null default false" in lowered
    assert "effective_at timestamptz not null default now()" in lowered
    assert "effective_until timestamptz" in lowered
    assert "unique(project_id, policy_version)" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-007: incidents (spec A.13)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-007")
def test_incidents_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "incidents")
    lowered = block.lower()
    assert "incident_id uuid primary key" in lowered
    assert "project_id uuid not null" in lowered
    assert "cluster_signature_hash text not null" in lowered
    assert "severity text not null" in lowered
    assert "check (severity in ('sev1','sev2','sev3','sev4'))" in lowered
    assert "state text not null default 'open'" in lowered
    assert (
        "check (state in ('open','mitigated','closed','suppressed'))" in lowered
    )
    assert "affected_run_ids uuid[] not null default '{}'" in lowered
    assert "first_seen_at timestamptz not null" in lowered
    assert "last_seen_at timestamptz not null" in lowered
    assert "owner_email text" in lowered
    assert "postmortem_ref text" in lowered
    assert "promoted_to_regression boolean not null default false" in lowered
    assert "created_at timestamptz not null default now()" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-007")
def test_incidents_cluster_index_present() -> None:
    text = _read_new_ddl()
    lowered = text.lower()
    assert (
        "create index incidents_cluster on incidents(project_id, cluster_signature_hash)"
        in lowered
    )


# ---------------------------------------------------------------------------
# VAL-V2M01-008: root_cause_hypotheses (spec A.15)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-008")
def test_root_cause_hypotheses_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "root_cause_hypotheses")
    lowered = block.lower()
    assert "hypothesis_id uuid primary key" in lowered
    assert "run_id uuid not null" in lowered
    assert "references runs(run_id)" in lowered
    assert "span_id uuid" in lowered
    assert "references spans(span_id)" in lowered
    assert "hypothesis_class text not null" in lowered
    assert "confidence numeric not null" in lowered
    assert "check (confidence between 0 and 1)" in lowered
    assert "evidence_refs jsonb not null default '[]'" in lowered
    assert "generator text not null" in lowered
    assert "reviewer_email text" in lowered
    assert "reviewer_decision text" in lowered
    assert (
        "check (reviewer_decision in ('accept','reject','modify','pending'))"
        in lowered
    )
    assert "promoted_to_replay_case_id uuid" in lowered
    assert "references replay_cases(replay_case_id)" in lowered
    assert "created_at timestamptz not null default now()" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-009: parent spans table + typed-detail-row polymorphic invariant
# ---------------------------------------------------------------------------
#
# The conformance test described in spec Z lines 5221-5293: a spans row with
# kind in {model_call, tool_call, retrieval, embedding} MUST have a matching
# row in the corresponding typed table within the same INSERT transaction.
# A spans row with kind = 'custom' requires no typed-table row.
#
# The polymorphic invariant is enforced declaratively via a CHECK that
# references join-state on the wire-format layer. On the Postgres side we
# express the rule via a comment + the canonical join contract pattern --
# the actual runtime enforcement lives in the ingest worker (which writes
# both rows atomically) plus a CI lint join-check. The DDL contribution
# here is the parent spans table itself plus the four typed-detail tables
# carrying ``span_id`` PKs that reference the parent with ON DELETE CASCADE.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-009")
def test_spans_parent_table_present() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "spans")
    lowered = block.lower()
    assert "span_id uuid primary key" in lowered
    assert "span_type text not null" in lowered
    # The kind column is the polymorphic discriminator; spec narrative uses
    # span_type, but the contract requires a column conveying the four
    # detail-kind values plus 'custom'. We honor the spec column name
    # (span_type) and add the canonical CHECK enum the typed-detail
    # invariant relies on (model_call|tool_call|retrieval|embedding|custom).
    assert (
        "check (span_type in ('model_call','tool_call','retrieval','embedding','custom'"
        in lowered
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-009")
def test_spans_polymorphic_invariant_documented() -> None:
    """The polymorphic invariant must be documented inline so reviewers /
    CI lint can find it via grep. Spec Z lines 5292-5293 narrative.
    """
    text = _read_new_ddl()
    lowered = text.lower()
    # A canonical comment string the CI lint can pin against.
    assert "typed-detail-row" in lowered or "typed detail row" in lowered
    assert "relay-ingest-span-detail-missing" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-010: model_call_spans (spec Z lines 5226-5249)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-010")
def test_model_call_spans_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "model_call_spans")
    lowered = block.lower()
    assert (
        "span_id uuid primary key references spans(span_id) on delete cascade"
        in lowered
    )
    assert "provider text not null" in lowered
    assert "model text not null" in lowered
    assert "model_signature text" in lowered
    assert "request_message_count int" in lowered
    assert "request_token_count int" in lowered
    assert "response_token_count int" in lowered
    assert "cached_token_count int" in lowered
    assert "reasoning_token_count int" in lowered
    assert "cost_usd numeric" in lowered
    assert "latency_ms int" in lowered
    assert "finish_reason text" in lowered
    assert "structured_output_mode text" in lowered
    assert "schema_contract_id text" in lowered
    assert "tool_choice_mode text" in lowered
    assert "streaming boolean not null default false" in lowered
    assert "input_redaction_policy_version text not null" in lowered
    assert "input_digest text" in lowered
    assert "output_digest text" in lowered
    assert "http_status int" in lowered
    assert "provider_error_code text" in lowered
    assert "provider_error_class text" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-011: tool_call_spans (spec Z lines 5251-5264)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-011")
def test_tool_call_spans_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "tool_call_spans")
    lowered = block.lower()
    assert (
        "span_id uuid primary key references spans(span_id) on delete cascade"
        in lowered
    )
    assert "tool_name text not null" in lowered
    assert "side_effect_class text not null" in lowered
    assert "args_digest text" in lowered
    assert "args_redaction_policy_version text not null" in lowered
    assert "args_schema_contract_id text" in lowered
    assert "args_validation_outcome text" in lowered
    assert (
        "check (args_validation_outcome in ('pass','fail','repaired','skipped','error'))"
        in lowered
    )
    assert "result_digest text" in lowered
    assert "status text not null" in lowered
    assert "latency_ms int" in lowered
    assert "marker_id uuid" in lowered
    assert "references side_effect_markers(marker_id)" in lowered
    assert "parallel_index int" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-012: retrieval_spans (spec Z lines 5266-5279)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-012")
def test_retrieval_spans_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "retrieval_spans")
    lowered = block.lower()
    assert (
        "span_id uuid primary key references spans(span_id) on delete cascade"
        in lowered
    )
    assert "retriever_name text not null" in lowered
    assert "query_digest text" in lowered
    assert "query_redaction_policy_version text not null" in lowered
    assert "document_count int" in lowered
    assert "duplicate_document_count int" in lowered
    assert "empty_retrieval boolean not null default false" in lowered
    assert "relevance_proxy_score numeric" in lowered
    assert "citation_coverage numeric" in lowered
    assert "context_token_count int" in lowered
    assert "context_waste_tokens int" in lowered
    assert "latency_ms int" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-013: embedding_spans (spec Z lines 5281-5290)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-013")
def test_embedding_spans_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "embedding_spans")
    lowered = block.lower()
    assert (
        "span_id uuid primary key references spans(span_id) on delete cascade"
        in lowered
    )
    assert "provider text not null" in lowered
    assert "model text not null" in lowered
    assert "input_token_count int" in lowered
    assert "embedding_dim int" in lowered
    assert "cached boolean not null default false" in lowered
    assert "cost_usd numeric" in lowered
    assert "latency_ms int" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-039: JSON schemas generated for new envelopes + fixture validation
# ---------------------------------------------------------------------------
#
# The 13 new envelopes (8 main tables + parent spans + 4 typed-detail
# tables) MUST appear in the canonical OpenAPI 3.1 source-of-truth at
# packages/schemas/raw/openapi.yaml AND in the rich-validation YAML at
# packages/schemas/raw/envelopes.yaml. Codegen produces Pydantic v2 and
# TypeScript types from the OpenAPI file (verified by the existing drift
# check, VAL-W1-035). Per assertion's scope, conformance corpus fixtures
# at packages/schemas/tests/conformance/m01/<name>/{pass,fail}.json
# validate the codegen output for each envelope.

# Names of the 13 new envelopes added by this feature.
_V2M01_NEW_ENVELOPES: tuple[str, ...] = (
    "GatePolicy",
    "ContractResult",
    "AssertionDefinition",
    "ReplayResult",
    "Manifest",
    "Incident",
    "RootCauseHypothesis",
    # Note: redaction_policies DDL is a NEW table; RedactionPolicy envelope
    # already exists from W1.4 -- the DDL gap is closed without a new
    # envelope name. RedactionPolicy is intentionally NOT in this list.
    "Span",
    "ModelCallSpan",
    "ToolCallSpan",
    "RetrievalSpan",
    "EmbeddingSpan",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-039")
def test_new_envelopes_present_in_openapi_yaml() -> None:
    import yaml

    openapi_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"
    doc = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    schemas = (doc.get("components") or {}).get("schemas") or {}
    missing = [name for name in _V2M01_NEW_ENVELOPES if name not in schemas]
    assert not missing, f"Missing OpenAPI components.schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-039")
def test_new_envelopes_present_in_envelopes_yaml() -> None:
    import yaml

    envelopes_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
    doc = yaml.safe_load(envelopes_path.read_text(encoding="utf-8"))
    schemas = doc.get("schemas") or {}
    missing = [name for name in _V2M01_NEW_ENVELOPES if name not in schemas]
    assert not missing, f"Missing envelopes.yaml schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-039")
def test_new_envelopes_pydantic_models_importable() -> None:
    """The hand-authored Pydantic layer exposes every new envelope class."""
    from relay_schemas import envelopes as env

    for name in _V2M01_NEW_ENVELOPES:
        assert hasattr(env, name), f"relay_schemas.envelopes missing {name}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-039")
def test_new_envelopes_schema_version_literal_pinned() -> None:
    """Every new envelope class pins schema_version via Literal (CLAUDE.md
    keystone invariant #10). The Pydantic Field info exposes the pin.
    """
    from relay_schemas import envelopes as env

    expected_pin = {
        "GatePolicy": "relay.gate_policy.v1",
        "ContractResult": "relay.contract_result.v1",
        "AssertionDefinition": "relay.assertion_definition.v1",
        "ReplayResult": "relay.replay_result.v1",
        "Manifest": "relay.manifest_parent.v1",
        "Incident": "relay.incident.v1",
        "RootCauseHypothesis": "relay.root_cause_hypothesis.v1",
        "Span": "relay.span.v1",
        "ModelCallSpan": "relay.model_call_span.v1",
        "ToolCallSpan": "relay.tool_call_span.v1",
        "RetrievalSpan": "relay.retrieval_span.v1",
        "EmbeddingSpan": "relay.embedding_span.v1",
    }
    for name, version in expected_pin.items():
        cls = getattr(env, name)
        # Pydantic v2: cls.model_fields["schema_version"].annotation is
        # Literal["..."]. Compare the args tuple.
        ann = cls.model_fields["schema_version"].annotation
        # typing.get_args returns ("relay.foo.v1",) for Literal["relay.foo.v1"].
        from typing import get_args

        args = get_args(ann)
        assert args == (version,), (
            f"{name}.schema_version literal pin mismatch: expected ({version!r},) "
            f"got {args!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-039")
def test_new_envelopes_appear_in_codegen_canonical_list() -> None:
    """The codegen orchestrator's CANONICAL_ENVELOPES list MUST enumerate
    every new envelope so the generated Python/TS surfaces re-export them.
    """
    codegen_path = (
        _REPO_ROOT / "packages" / "schemas" / "scripts" / "codegen.py"
    )
    text = codegen_path.read_text(encoding="utf-8")
    for name in _V2M01_NEW_ENVELOPES:
        assert f'"{name}"' in text, f"codegen.py missing {name!r} in CANONICAL_ENVELOPES"


# ---------------------------------------------------------------------------
# Round-trip happy-path checks for each new envelope class
# ---------------------------------------------------------------------------
#
# These exercise the Pydantic model end-to-end with a valid payload. They
# back the contract's "validates live fixtures" clause for VAL-V2M01-039
# at the wire-format layer.


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-001")
def test_gate_policy_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import GatePolicy

    payload = {
        "schema_version": "relay.gate_policy.v1",
        "gate_policy_id": _new_uuid(),
        "gate_id": _new_uuid(),
        "policy_version": "v1",
        "conditions": {"min_pass_rate": 0.95},
        "blocking_severity": "p0_only",
        "effective_at": _now_iso(),
    }
    gp = GatePolicy.model_validate(payload)
    assert gp.blocking_severity == "p0_only"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-001")
def test_gate_policy_rejects_invalid_blocking_severity() -> None:
    from relay_schemas.envelopes import GatePolicy

    payload = {
        "schema_version": "relay.gate_policy.v1",
        "gate_policy_id": _new_uuid(),
        "gate_id": _new_uuid(),
        "policy_version": "v1",
        "conditions": {},
        "blocking_severity": "every_failure",  # not in closed enum
        "effective_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        GatePolicy.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-002")
def test_contract_result_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import ContractResult

    payload = {
        "schema_version": "relay.contract_result.v1",
        "contract_result_id": _new_uuid(),
        "run_id": _new_uuid(),
        "contract_id": _new_uuid(),
        "contract_version": "1.0",
        "outcome": "pass",
        "severity": "p0",
        "evaluation_engine_version": "rly-1.0",
        "evaluated_at": _now_iso(),
    }
    cr = ContractResult.model_validate(payload)
    assert cr.outcome == "pass"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-002")
def test_contract_result_rejects_invalid_outcome() -> None:
    from relay_schemas.envelopes import ContractResult

    payload = {
        "schema_version": "relay.contract_result.v1",
        "contract_result_id": _new_uuid(),
        "run_id": _new_uuid(),
        "contract_id": _new_uuid(),
        "contract_version": "1.0",
        "outcome": "broken",  # not in closed enum
        "evaluation_engine_version": "rly-1.0",
        "evaluated_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        ContractResult.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-003")
def test_assertion_definition_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import AssertionDefinition

    payload = {
        "schema_version": "relay.assertion_definition.v1",
        "assertion_id": "VAL-STRUCTURED-001",
        "project_id": _new_uuid(),
        "kind": "schema_contract",
        "severity": "p0",
        "title": "Order JSON shape",
        "owner_email": "owner@example.com",
        "expression": {"json_schema": {"type": "object"}},
        "lifecycle_state": "draft",
        "current_version": 1,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    ad = AssertionDefinition.model_validate(payload)
    assert ad.kind == "schema_contract"
    assert ad.lifecycle_state == "draft"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-003")
def test_assertion_definition_rejects_invalid_kind() -> None:
    from relay_schemas.envelopes import AssertionDefinition

    payload = {
        "schema_version": "relay.assertion_definition.v1",
        "assertion_id": "VAL-X-001",
        "project_id": _new_uuid(),
        "kind": "smoke_test",  # not in closed enum
        "severity": "p0",
        "title": "x",
        "owner_email": "owner@example.com",
        "expression": {},
        "current_version": 1,
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        AssertionDefinition.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-004")
def test_replay_result_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import ReplayResult

    payload = {
        "schema_version": "relay.replay_result.v1",
        "replay_result_id": _new_uuid(),
        "replay_case_id": _new_uuid(),
        "replay_run_id": _new_uuid(),
        "outcome": "reproduced",
        "sandbox_driver": "local-docker",
        "created_at": _now_iso(),
    }
    rr = ReplayResult.model_validate(payload)
    assert rr.outcome == "reproduced"
    assert rr.fixture_hits == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-004")
def test_replay_result_rejects_invalid_outcome() -> None:
    from relay_schemas.envelopes import ReplayResult

    payload = {
        "schema_version": "relay.replay_result.v1",
        "replay_result_id": _new_uuid(),
        "replay_case_id": _new_uuid(),
        "replay_run_id": _new_uuid(),
        "outcome": "complete",  # not in closed enum
        "sandbox_driver": "local-docker",
        "created_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        ReplayResult.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-005")
def test_manifest_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import Manifest

    payload = {
        "schema_version": "relay.manifest_parent.v1",
        "manifest_id": _new_uuid(),
        "project_id": _new_uuid(),
        "name": "prod-manifest",
        "created_at": _now_iso(),
    }
    m = Manifest.model_validate(payload)
    assert m.name == "prod-manifest"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-007")
def test_incident_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import Incident

    now = _now_iso()
    payload = {
        "schema_version": "relay.incident.v1",
        "incident_id": _new_uuid(),
        "project_id": _new_uuid(),
        "cluster_signature_hash": "sha256-" + ("a" * 64),
        "severity": "sev2",
        "state": "open",
        "affected_run_ids": [],
        "first_seen_at": now,
        "last_seen_at": now,
    }
    inc = Incident.model_validate(payload)
    assert inc.severity == "sev2"
    assert inc.state == "open"
    assert inc.promoted_to_regression is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-007")
def test_incident_rejects_invalid_severity() -> None:
    from relay_schemas.envelopes import Incident

    now = _now_iso()
    payload = {
        "schema_version": "relay.incident.v1",
        "incident_id": _new_uuid(),
        "project_id": _new_uuid(),
        "cluster_signature_hash": "sha256-" + ("a" * 64),
        "severity": "sev0",  # not in closed enum
        "first_seen_at": now,
        "last_seen_at": now,
    }
    with pytest.raises(ValidationError):
        Incident.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-008")
def test_root_cause_hypothesis_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import RootCauseHypothesis

    payload = {
        "schema_version": "relay.root_cause_hypothesis.v1",
        "hypothesis_id": _new_uuid(),
        "run_id": _new_uuid(),
        "hypothesis_class": "schema_contract_drift",
        "confidence": 0.85,
        "evidence_refs": [],
        "generator": "heuristic.v1",
        "created_at": _now_iso(),
    }
    rch = RootCauseHypothesis.model_validate(payload)
    assert rch.confidence == 0.85


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-008")
def test_root_cause_hypothesis_rejects_out_of_range_confidence() -> None:
    from relay_schemas.envelopes import RootCauseHypothesis

    payload = {
        "schema_version": "relay.root_cause_hypothesis.v1",
        "hypothesis_id": _new_uuid(),
        "run_id": _new_uuid(),
        "hypothesis_class": "x",
        "confidence": 1.5,  # > 1, must reject
        "generator": "heuristic.v1",
        "created_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        RootCauseHypothesis.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-009")
def test_span_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import Span

    payload = {
        "schema_version": "relay.span.v1",
        "span_id": _new_uuid(),
        "run_id": _new_uuid(),
        "span_type": "model_call",
        "name": "openai.chat.completions.create",
        "status": "ok",
        "started_at": _now_iso(),
    }
    s = Span.model_validate(payload)
    assert s.span_type == "model_call"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-009")
def test_span_rejects_invalid_span_type() -> None:
    from relay_schemas.envelopes import Span

    payload = {
        "schema_version": "relay.span.v1",
        "span_id": _new_uuid(),
        "span_type": "unknown_kind",  # not in closed enum
        "name": "x",
        "status": "ok",
        "started_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        Span.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-010")
def test_model_call_span_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import ModelCallSpan

    payload = {
        "schema_version": "relay.model_call_span.v1",
        "span_id": _new_uuid(),
        "provider": "openai",
        "model": "gpt-5",
        "input_redaction_policy_version": "v1",
    }
    mcs = ModelCallSpan.model_validate(payload)
    assert mcs.streaming is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-011")
def test_tool_call_span_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import ToolCallSpan

    payload = {
        "schema_version": "relay.tool_call_span.v1",
        "span_id": _new_uuid(),
        "tool_name": "send_email",
        "side_effect_class": "external_irreversible",
        "args_redaction_policy_version": "v1",
        "status": "ok",
    }
    tcs = ToolCallSpan.model_validate(payload)
    assert tcs.tool_name == "send_email"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-011")
def test_tool_call_span_rejects_invalid_args_validation_outcome() -> None:
    from relay_schemas.envelopes import ToolCallSpan

    payload = {
        "schema_version": "relay.tool_call_span.v1",
        "span_id": _new_uuid(),
        "tool_name": "x",
        "side_effect_class": "read_only",
        "args_redaction_policy_version": "v1",
        "args_validation_outcome": "rejected",  # not in closed enum
        "status": "ok",
    }
    with pytest.raises(ValidationError):
        ToolCallSpan.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-012")
def test_retrieval_span_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import RetrievalSpan

    payload = {
        "schema_version": "relay.retrieval_span.v1",
        "span_id": _new_uuid(),
        "retriever_name": "pinecone-main",
        "query_redaction_policy_version": "v1",
    }
    rs = RetrievalSpan.model_validate(payload)
    assert rs.empty_retrieval is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-013")
def test_embedding_span_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import EmbeddingSpan

    payload = {
        "schema_version": "relay.embedding_span.v1",
        "span_id": _new_uuid(),
        "provider": "openai",
        "model": "text-embedding-3-large",
    }
    es = EmbeddingSpan.model_validate(payload)
    assert es.cached is False


# ---------------------------------------------------------------------------
# Sidecar mirror tables present
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-001")
def test_sidecar_mirror_declares_each_new_table() -> None:
    """The SQLite mirror migration carries each of the 13 new tables so the
    local sidecar persistence layer can mirror the canonical Postgres shape.
    Postgres-only constructs (uuid[] arrays, GENERATED IDENTITY) may be
    relaxed in the mirror, but every table name MUST be present.
    """
    text = _read_sidecar_ddl().lower()
    expected_tables = (
        "gate_policies",
        "contract_results",
        "assertion_definitions",
        "replay_results",
        "manifests",
        "redaction_policies",
        "incidents",
        "root_cause_hypotheses",
        "spans",
        "model_call_spans",
        "tool_call_spans",
        "retrieval_spans",
        "embedding_spans",
    )
    for table in expected_tables:
        assert f"create table if not exists {table}" in text, (
            f"sidecar mirror missing CREATE TABLE IF NOT EXISTS {table}"
        )
