"""Audit-R3 (2026-05-18) regression tests.

Locks in the schema-audit P0 fixes:

  D1  Postgres parent tables (runs, projects, contracts, gates) exist in
      packages/schemas/sql/0000_v2_parent_tables.sql so that the FK
      declarations at 0004_v2_canonical_tables.sql resolve at apply time.

  D2  tool_call_spans.marker_id FK to side_effect_markers is deferred to
      0010_side_effects.sql via ALTER TABLE (the inline form at 0004
      would fail because the FK target is created later in lex order).

  D3  Canonical Postgres DDL for run_results, gate_decisions,
      gate_decision_drafts, gate_rounds at
      0003a_canonical_run_results_and_gates.sql. CHECK constraints pin
      written_by='control_plane' and decided_by='gate_engine' per
      keystone invariant #1.

  D8  reviewer_decision CHECK aligned to spec line 3325 + envelopes.yaml
      canonical four-value set {accept, reject, modify, pending}.

  D9b Actor.kind enum widened to align with the sidecar 12-value
      operational set (envelopes.yaml is the canonical reference).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_RAW_DIR = _REPO_ROOT / "packages" / "schemas" / "raw"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# D1: parent tables exist in 0000_v2_parent_tables.sql
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_d1_parent_tables_exist() -> None:
    """0004_v2_canonical_tables.sql references runs/projects/contracts/
    gates as FK targets; 0000 must define all four parent tables."""
    text = _read(_SQL_DIR / "0000_v2_parent_tables.sql").lower()
    for table in ("runs", "projects", "contracts", "gates"):
        assert (
            f"create table if not exists {table}" in text
        ), f"parent table {table!r} missing from 0000_v2_parent_tables.sql"


@pytest.mark.plumbing
def test_d1_gates_table_schema_version_dropped_audit_r4() -> None:
    """Audit-R4 (2026-05-18): the schema_version column was removed from
    the canonical Postgres ``gates`` table because the corresponding
    literal ``relay.gate.v1`` is NOT in
    :data:`relay_evals.templates.schema_match.KNOWN_SCHEMA_IDS`, NOT in
    envelopes.yaml, and NOT in openapi.yaml -- the wire response for
    ``PUT /v1/gates`` had already dropped it in the audit-R3 batch. The
    stranded DDL pin contradicted that decision and violated CLAUDE.md
    keystone #10. This test guards against regression: no future PR may
    re-introduce a gates.schema_version CHECK pinning relay.gate.v1
    without first adding the literal to KNOWN_SCHEMA_IDS and envelopes.
    """
    text = _read(_SQL_DIR / "0000_v2_parent_tables.sql").lower()
    # The CHECK constraint must not exist.
    assert "check (schema_version = 'relay.gate.v1')" not in text, (
        "audit-R4 regression: gates.schema_version CHECK was re-introduced"
    )
    # The literal must not appear as a column DEFAULT either.
    assert "default 'relay.gate.v1'" not in text, (
        "audit-R4 regression: relay.gate.v1 literal re-introduced as DEFAULT"
    )


# ---------------------------------------------------------------------------
# D2: tool_call_spans.marker_id FK is deferred
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_d2_tool_call_spans_marker_fk_deferred_to_0010() -> None:
    """The FK is added in 0010 via ALTER TABLE (because side_effect_markers
    is created in 0010, after 0004)."""
    side_effects = _read(_SQL_DIR / "0010_side_effects.sql").lower()
    assert "tool_call_spans_marker_fk" in side_effects
    assert (
        "foreign key (marker_id) references side_effect_markers(marker_id)"
        in side_effects
    )


@pytest.mark.plumbing
def test_d2_tool_call_spans_marker_no_inline_fk_in_0004() -> None:
    """The inline FK was removed from 0004 (would fail at apply time)."""
    text = _read(_SQL_DIR / "0004_v2_canonical_tables.sql").lower()
    # The marker_id column is preserved but with no inline REFERENCES.
    pat = re.compile(
        r"create\s+table\s+tool_call_spans.*?\);",
        re.DOTALL,
    )
    block = pat.search(text)
    assert block is not None, "tool_call_spans block not found in 0004"
    block_text = block.group(0)
    assert "marker_id uuid" in block_text
    assert "references side_effect_markers" not in block_text


# ---------------------------------------------------------------------------
# D3: canonical Postgres DDL exists for run_results, gate_decisions,
# gate_decision_drafts, gate_rounds.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_d3_canonical_postgres_tables_exist() -> None:
    text = _read(_SQL_DIR / "0003a_canonical_run_results_and_gates.sql").lower()
    for table in (
        "run_results",
        "gate_decisions",
        "gate_decision_drafts",
        "gate_rounds",
    ):
        assert (
            f"create table if not exists {table}" in text
        ), f"canonical table {table!r} missing from 0003a"


@pytest.mark.plumbing
def test_d3_run_results_written_by_check_constraint() -> None:
    """run_results.written_by CHECK forces literal 'control_plane' per
    keystone invariant #1."""
    text = _read(_SQL_DIR / "0003a_canonical_run_results_and_gates.sql").lower()
    assert "check (written_by = 'control_plane')" in text


@pytest.mark.plumbing
def test_d3_gate_decisions_decided_by_check_constraint() -> None:
    """gate_decisions.decided_by CHECK forces literal 'gate_engine' per
    keystone invariant #1."""
    text = _read(_SQL_DIR / "0003a_canonical_run_results_and_gates.sql").lower()
    assert "check (decided_by = 'gate_engine')" in text


@pytest.mark.plumbing
def test_d3_run_results_accepted_requires_evidence() -> None:
    """Per keystone invariant #2: status='accepted' requires evidence_bundle_id."""
    text = _read(_SQL_DIR / "0003a_canonical_run_results_and_gates.sql").lower()
    assert "accepted_requires_evidence" in text
    assert "evidence_bundle_id is not null" in text


# ---------------------------------------------------------------------------
# D8: reviewer_decision enum aligned to spec line 3325 + envelopes.yaml.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_d8_postgres_reviewer_decision_includes_pending() -> None:
    """packages/schemas/sql/0009_explain.sql CHECK includes pending."""
    text = _read(_SQL_DIR / "0009_explain.sql").lower()
    # The relevant CHECK is on root_cause_hypotheses.reviewer_decision.
    # Canonical set per spec line 3325: {accept, reject, modify, pending}.
    assert (
        "reviewer_decision in ('accept','reject','modify','pending')"
        in text
    )


@pytest.mark.plumbing
def test_d8_python_reviewer_decisions_is_four_values() -> None:
    """REVIEWER_DECISIONS frozenset has exactly 4 values."""
    from relay_schemas.root_cause_hypothesis import REVIEWER_DECISIONS

    assert frozenset(
        {"accept", "reject", "modify", "pending"}
    ) == REVIEWER_DECISIONS


@pytest.mark.plumbing
def test_d8_root_cause_hypothesis_yaml_enum() -> None:
    """packages/schemas/raw/root-cause-hypothesis.v1.yaml carries pending."""
    text = _read(_RAW_DIR / "root-cause-hypothesis.v1.yaml")
    data = yaml.safe_load(text)
    enum_values = (
        data["json_schema"]["properties"]["reviewer_decision"]["enum"]
    )
    # The enum is a list mixing strings and a literal None for nullability.
    members = {v for v in enum_values if isinstance(v, str)}
    assert members == {"accept", "reject", "modify", "pending"}


# ---------------------------------------------------------------------------
# D9b: Actor.kind enum widened to include operational kinds.
# ---------------------------------------------------------------------------


# Audit-R4 (2026-05-18): the canonical Actor.kind enum is the closed
# 14-value set below. envelopes.yaml, openapi.yaml, and the sidecar
# SQLite CHECK (apps/local-sidecar/migrations/0006_manifest_versions.sql
# as broadened by 0024_audit_r4_actors_kind_alignment.sql) MUST be in
# byte-equal alignment. Any drift between the three layers is a P0
# bug: a wire payload accepted by codegen validation but rejected by
# sidecar INSERT (or vice versa) breaks the three-anchor handoff
# guarantee (keystone #4) by introducing an unobservable rejection path.
_ACTOR_KIND_CANONICAL: frozenset[str] = frozenset({
    "human",
    "bot",
    "reviewer",
    "sdk",
    "machine",
    "worker",
    "gate_engine",
    "result_writer",
    "evidence_signer",
    "cron",
    "control_plane",
    "validation_worker",
    "ingest_worker",
    "replay_worker",
})


@pytest.mark.plumbing
def test_d9b_actor_kind_envelopes_yaml_widened() -> None:
    """envelopes.yaml Actor.kind enum equals the canonical 14-value set.

    Audit-R4 hardened this from a 5-value subset assertion to full set
    equality so any drift between envelopes.yaml and the openapi.yaml /
    sidecar SQLite CHECK is caught at plumbing tier.
    """
    text = _read(_RAW_DIR / "envelopes.yaml")
    data = yaml.safe_load(text)
    kind_values = set(data["schemas"]["Actor"]["fields"]["kind"]["values"])
    assert kind_values == _ACTOR_KIND_CANONICAL, (
        f"Actor.kind drift in envelopes.yaml: "
        f"missing={_ACTOR_KIND_CANONICAL - kind_values}, "
        f"extra={kind_values - _ACTOR_KIND_CANONICAL}"
    )


@pytest.mark.plumbing
def test_d9b_actor_kind_openapi_yaml_widened() -> None:
    """openapi.yaml Actor.kind enum equals the canonical 14-value set.

    Audit-R4 hardened this from a 5-value subset assertion to full set
    equality so any drift between openapi.yaml and envelopes.yaml /
    sidecar SQLite CHECK is caught at plumbing tier.
    """
    text = _read(_RAW_DIR / "openapi.yaml")
    data = yaml.safe_load(text)
    kind_values = set(
        data["components"]["schemas"]["Actor"]["properties"]["kind"]["enum"]
    )
    assert kind_values == _ACTOR_KIND_CANONICAL, (
        f"Actor.kind drift in openapi.yaml: "
        f"missing={_ACTOR_KIND_CANONICAL - kind_values}, "
        f"extra={kind_values - _ACTOR_KIND_CANONICAL}"
    )
