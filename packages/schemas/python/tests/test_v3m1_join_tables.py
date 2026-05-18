"""V3M1-F01 (2026-05-18): run_result_contract_results +
run_result_gate_decisions join tables.

Per spec §A.1, the RunResult envelope binds to its contract results and
gate decisions via dedicated join tables (replacing the historical array
column form for FK integrity). This test locks in:

  VAL-V3M1-001  run_result_contract_results join table exists
                in both Postgres DDL and sidecar SQLite mirror.

  VAL-V3M1-002  run_result_gate_decisions join table exists
                in both Postgres DDL and sidecar SQLite mirror.

  VAL-V3M1-003  Atomic write primitive enforcement: both join table
                names appear in :func:`relay_sidecar.db._allowed_tables`
                so writes route through ``transactional_db_write_raw``
                per CLAUDE.md keystone invariant #8.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]
_PG_MIGRATION = (
    _REPO_ROOT / "packages" / "schemas" / "sql" / "0012_v3_join_tables.sql"
)
_SIDECAR_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0025_v3_join_tables.sql"
)
_SIDECAR_DB_PY = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "relay_sidecar"
    / "db.py"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# VAL-V3M1-001: run_result_contract_results join table exists (both tiers)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_001_pg_run_result_contract_results_table_exists() -> None:
    """Postgres migration declares the join table with composite PK +
    FKs to ``run_results`` and ``contract_results``."""
    text = _read(_PG_MIGRATION).lower()
    assert "create table if not exists run_result_contract_results" in text, (
        "VAL-V3M1-001: run_result_contract_results CREATE TABLE missing "
        "from packages/schemas/sql/0012_v3_join_tables.sql"
    )
    # FK to run_results
    assert re.search(
        r"run_result_id\s+uuid\s+not\s+null\s+references\s+run_results\s*\(\s*run_result_id\s*\)",
        text,
    ), "VAL-V3M1-001: run_result_id FK to run_results(run_result_id) missing"
    # FK to contract_results
    assert re.search(
        r"contract_result_id\s+uuid\s+not\s+null\s+references\s+contract_results\s*\(\s*contract_result_id\s*\)",
        text,
    ), (
        "VAL-V3M1-001: contract_result_id FK to "
        "contract_results(contract_result_id) missing"
    )
    # Composite primary key
    assert re.search(
        r"primary\s+key\s*\(\s*run_result_id\s*,\s*contract_result_id\s*\)",
        text,
    ), "VAL-V3M1-001: composite PK (run_result_id, contract_result_id) missing"


@pytest.mark.plumbing
def test_val_v3m1_001_sidecar_run_result_contract_results_table_exists() -> None:
    """Sidecar SQLite mirror declares the same join table with TEXT
    primary-key columns (SQLite has no native uuid type)."""
    text = _read(_SIDECAR_MIGRATION).lower()
    assert "create table if not exists run_result_contract_results" in text, (
        "VAL-V3M1-001: sidecar mirror missing run_result_contract_results"
    )
    # TEXT columns instead of uuid
    assert re.search(
        r"run_result_id\s+text\s+not\s+null",
        text,
    ), "VAL-V3M1-001: sidecar run_result_id TEXT NOT NULL column missing"
    assert re.search(
        r"contract_result_id\s+text\s+not\s+null",
        text,
    ), "VAL-V3M1-001: sidecar contract_result_id TEXT NOT NULL column missing"
    # Composite primary key
    assert re.search(
        r"primary\s+key\s*\(\s*run_result_id\s*,\s*contract_result_id\s*\)",
        text,
    ), "VAL-V3M1-001: sidecar composite PK missing"


# ---------------------------------------------------------------------------
# VAL-V3M1-002: run_result_gate_decisions join table exists (both tiers)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_002_pg_run_result_gate_decisions_table_exists() -> None:
    """Postgres migration declares the join table with composite PK +
    FKs to ``run_results`` and ``gate_decisions``."""
    text = _read(_PG_MIGRATION).lower()
    assert "create table if not exists run_result_gate_decisions" in text, (
        "VAL-V3M1-002: run_result_gate_decisions CREATE TABLE missing"
    )
    # FK to run_results
    assert re.search(
        r"run_result_id\s+uuid\s+not\s+null\s+references\s+run_results\s*\(\s*run_result_id\s*\)",
        text,
    ), "VAL-V3M1-002: run_result_id FK to run_results missing"
    # FK to gate_decisions
    assert re.search(
        r"gate_decision_id\s+uuid\s+not\s+null\s+references\s+gate_decisions\s*\(\s*gate_decision_id\s*\)",
        text,
    ), (
        "VAL-V3M1-002: gate_decision_id FK to "
        "gate_decisions(gate_decision_id) missing"
    )
    # Composite primary key
    assert re.search(
        r"primary\s+key\s*\(\s*run_result_id\s*,\s*gate_decision_id\s*\)",
        text,
    ), "VAL-V3M1-002: composite PK (run_result_id, gate_decision_id) missing"


@pytest.mark.plumbing
def test_val_v3m1_002_sidecar_run_result_gate_decisions_table_exists() -> None:
    """Sidecar SQLite mirror declares the same join table with TEXT
    columns (SQLite has no native uuid type)."""
    text = _read(_SIDECAR_MIGRATION).lower()
    assert "create table if not exists run_result_gate_decisions" in text, (
        "VAL-V3M1-002: sidecar mirror missing run_result_gate_decisions"
    )
    assert re.search(
        r"run_result_id\s+text\s+not\s+null",
        text,
    ), "VAL-V3M1-002: sidecar run_result_id TEXT NOT NULL column missing"
    assert re.search(
        r"gate_decision_id\s+text\s+not\s+null",
        text,
    ), "VAL-V3M1-002: sidecar gate_decision_id TEXT NOT NULL column missing"
    assert re.search(
        r"primary\s+key\s*\(\s*run_result_id\s*,\s*gate_decision_id\s*\)",
        text,
    ), "VAL-V3M1-002: sidecar composite PK missing"


# ---------------------------------------------------------------------------
# VAL-V3M1-003: atomic-write-primitive enforcement via _allowed_tables()
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_val_v3m1_003_join_tables_in_allowed_tables_source() -> None:
    """The new join tables MUST appear in ``_allowed_tables()`` so all
    INSERT writes route through ``transactional_db_write_raw`` (CLAUDE.md
    keystone invariant #8). This static source check guards the surface
    even if the running sidecar code path is not exercised by this test.
    """
    text = _read(_SIDECAR_DB_PY)
    # Locate the function body so we are matching the actual returned
    # tuple, not a comment elsewhere in the file.
    marker = "def _allowed_tables() -> Iterable[str]:"
    start = text.find(marker)
    assert start >= 0, "_allowed_tables() definition not found in db.py"
    # End at the next top-level dunder/def or EOF; safe upper-bound.
    end = text.find("\ndef ", start + len(marker))
    if end < 0:
        end = len(text)
    body = text[start:end]
    assert '"run_result_contract_results"' in body, (
        "VAL-V3M1-003: run_result_contract_results missing from "
        "_allowed_tables() allowlist in apps/local-sidecar/relay_sidecar/db.py"
    )
    assert '"run_result_gate_decisions"' in body, (
        "VAL-V3M1-003: run_result_gate_decisions missing from "
        "_allowed_tables() allowlist in apps/local-sidecar/relay_sidecar/db.py"
    )


@pytest.mark.plumbing
def test_val_v3m1_003_allowed_tables_runtime_contains_both_join_tables() -> None:
    """Runtime check: ``_allowed_tables()`` callable returns a tuple that
    contains both new join table names."""
    from relay_sidecar.db import _allowed_tables  # type: ignore[import-not-found]

    allowed = tuple(_allowed_tables())
    assert "run_result_contract_results" in allowed, (
        "VAL-V3M1-003: runtime _allowed_tables() missing "
        "'run_result_contract_results'"
    )
    assert "run_result_gate_decisions" in allowed, (
        "VAL-V3M1-003: runtime _allowed_tables() missing "
        "'run_result_gate_decisions'"
    )
