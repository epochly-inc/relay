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
def test_d1_gates_table_schema_version_pinned() -> None:
    """gates carries schema_version CHECK pinning to relay.gate.v1 per
    keystone invariant #10."""
    text = _read(_SQL_DIR / "0000_v2_parent_tables.sql")
    assert "schema_version" in text
    assert "check (schema_version = 'relay.gate.v1')" in text.lower()


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

    assert REVIEWER_DECISIONS == frozenset(
        {"accept", "reject", "modify", "pending"}
    )


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


@pytest.mark.plumbing
def test_d9b_actor_kind_envelopes_yaml_widened() -> None:
    """envelopes.yaml Actor.kind enum includes the operational kinds used
    by the sidecar test fixtures (sdk, machine, gate_engine, etc.)."""
    text = _read(_RAW_DIR / "envelopes.yaml")
    data = yaml.safe_load(text)
    kind_values = data["schemas"]["Actor"]["fields"]["kind"]["values"]
    required = {"sdk", "machine", "gate_engine", "control_plane", "worker"}
    missing = required - set(kind_values)
    assert not missing, f"Actor.kind missing operational kinds: {missing}"


@pytest.mark.plumbing
def test_d9b_actor_kind_openapi_yaml_widened() -> None:
    """openapi.yaml Actor.kind enum matches envelopes.yaml."""
    text = _read(_RAW_DIR / "openapi.yaml")
    data = yaml.safe_load(text)
    kind_values = (
        data["components"]["schemas"]["Actor"]["properties"]["kind"]["enum"]
    )
    required = {"sdk", "machine", "gate_engine", "control_plane", "worker"}
    missing = required - set(kind_values)
    assert not missing, f"Actor.kind in openapi missing kinds: {missing}"
