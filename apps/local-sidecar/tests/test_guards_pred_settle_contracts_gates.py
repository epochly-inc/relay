"""Direct-unit mutation-hardening suite for CLUSTER B guard predicates.

The 23 state-engine guard predicates are PURE async functions that are
normally exercised only INDIRECTLY through ``compare_and_set_state``
transitions. That indirection leaves their internal branches unpinned:
mutation testing showed ~78 percent survival because a flipped comparison
or a swapped boolean inside a guard never changes an observable transition
outcome in the existing tests.

This module imports four CLUSTER B predicates DIRECTLY and calls them with
an in-memory aiosqlite connection, asserting BOTH the returned bool AND a
distinguishing key/substring in the diagnostics dict for EVERY branch.
Each distinct branch is its own test so a mutation that flips that branch
is killed by a failing assertion rather than slipping through.

Predicates covered (apps/local-sidecar/relay_sidecar/state_engine/guards.py):
  - _guard_spans_batch_settled_or_client_lifecycle_terminal
  - _guard_all_required_contracts_evaluated
  - _guard_contract_results_written
  - _guard_all_bound_gates_decided

These are called as plain functions; we do NOT register_guard or route
through compare_and_set_state. ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import aiosqlite
import pytest

from relay_sidecar.state_engine.guards import (
    _guard_all_bound_gates_decided,
    _guard_all_required_contracts_evaluated,
    _guard_contract_results_written,
    _guard_spans_batch_settled_or_client_lifecycle_terminal,
)

# DDL for the minimal tables each guard SELECTs. Only the columns the guard
# touches are declared; the guards do not depend on a richer schema.
_DDL_CONTRACT_RESULTS = "CREATE TABLE contract_results (run_id TEXT, contract_id TEXT)"
_DDL_GATE_DECISIONS = (
    "CREATE TABLE gate_decisions "
    "(scope_type TEXT, scope_id TEXT, gate_id TEXT, action TEXT)"
)


# ---------------------------------------------------------------------------
# (1) _guard_spans_batch_settled_or_client_lifecycle_terminal  (no DB access)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_lifecycle_client_succeeded_passes() -> None:
    """client_succeeded is a terminal lifecycle -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {"client_lifecycle_status": "client_succeeded"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_lifecycle_client_failed_passes() -> None:
    """client_failed is a terminal lifecycle -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {"client_lifecycle_status": "client_failed"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_lifecycle_client_aborted_passes() -> None:
    """client_aborted is a terminal lifecycle -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {"client_lifecycle_status": "client_aborted"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_spans_batch_settled_true_passes() -> None:
    """spans_batch_settled is True -> (True, {}) even with no lifecycle key."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {"spans_batch_settled": True}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_non_terminal_lifecycle_present_fails() -> None:
    """A present-but-non-terminal lifecycle with no settled marker -> False."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {"client_lifecycle_status": "client_running"}, None
        )
    assert ok is False
    assert "neither spans batch settled nor lifecycle terminal" in diag["reason"]
    # Distinguishing key: the offending lifecycle value is echoed back.
    assert diag["client_lifecycle_status"] == "client_running"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_settle_empty_payload_passes_lenient() -> None:
    """Neither key present (legacy bootstrap) -> lenient (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_spans_batch_settled_or_client_lifecycle_terminal(
            conn, "run", "run-1", {}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (2) _guard_all_required_contracts_evaluated   (contract_results table)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_absent_key_passes_lenient() -> None:
    """No required_contract_ids in payload -> lenient (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_empty_list_passes_lenient() -> None:
    """An empty required_contract_ids list -> lenient (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {"required_contract_ids": []}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_non_list_passes_lenient() -> None:
    """A non-list required_contract_ids (str) is treated as absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {"required_contract_ids": "c1"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_table_absent_passes_with_note() -> None:
    """required present but contract_results table missing -> (True, note)."""
    async with aiosqlite.connect(":memory:") as conn:
        # Deliberately DO NOT create contract_results -> OperationalError path.
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {"required_contract_ids": ["c1"]}, None
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_missing_one_fails() -> None:
    """required c1+c2 but only c1 evaluated -> (False) with c2 in missing."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        await conn.execute(
            "INSERT INTO contract_results (run_id, contract_id) VALUES (?, ?)",
            ("run-1", "c1"),
        )
        await conn.commit()
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {"required_contract_ids": ["c1", "c2"]}, None
        )
    assert ok is False
    assert "not yet evaluated" in diag["reason"]
    assert "c2" in diag["missing"]
    assert "c1" not in diag["missing"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_required_contracts_all_evaluated_passes() -> None:
    """required c1 and a matching c1 row exists -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        await conn.execute(
            "INSERT INTO contract_results (run_id, contract_id) VALUES (?, ?)",
            ("run-1", "c1"),
        )
        await conn.commit()
        ok, diag = await _guard_all_required_contracts_evaluated(
            conn, "run", "run-1", {"required_contract_ids": ["c1"]}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (3) _guard_contract_results_written   (contract_results table)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_contract_written_absent_required_passes_lenient() -> None:
    """No required_contract_ids -> lenient (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        ok, diag = await _guard_contract_results_written(
            conn, "run", "run-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_contract_written_table_absent_passes_with_note() -> None:
    """required present but contract_results table missing -> (True, note)."""
    async with aiosqlite.connect(":memory:") as conn:
        # No table created -> OperationalError path.
        ok, diag = await _guard_contract_results_written(
            conn, "run", "run-1", {"required_contract_ids": ["c1"]}, None
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_contract_written_zero_rows_fails() -> None:
    """required present but COUNT(*) for run is 0 -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        # Row for a DIFFERENT run must not satisfy this run.
        await conn.execute(
            "INSERT INTO contract_results (run_id, contract_id) VALUES (?, ?)",
            ("other-run", "c1"),
        )
        await conn.commit()
        ok, diag = await _guard_contract_results_written(
            conn, "run", "run-1", {"required_contract_ids": ["c1"]}, None
        )
    assert ok is False
    assert "rows not written" in diag["reason"]
    assert diag["run_id"] == "run-1"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_contract_written_one_row_passes() -> None:
    """required present and at least one row for the run -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_CONTRACT_RESULTS)
        await conn.execute(
            "INSERT INTO contract_results (run_id, contract_id) VALUES (?, ?)",
            ("run-1", "c1"),
        )
        await conn.commit()
        ok, diag = await _guard_contract_results_written(
            conn, "run", "run-1", {"required_contract_ids": ["c1"]}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (4) _guard_all_bound_gates_decided   (gate_decisions table)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_bound_gates_absent_passes_lenient() -> None:
    """No bound_gate_ids -> lenient (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_GATE_DECISIONS)
        ok, diag = await _guard_all_bound_gates_decided(
            conn, "run", "run-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_bound_gates_table_absent_passes_with_note() -> None:
    """bound present but gate_decisions table missing -> (True, note)."""
    async with aiosqlite.connect(":memory:") as conn:
        # No table created -> OperationalError path.
        ok, diag = await _guard_all_bound_gates_decided(
            conn, "run", "run-1", {"bound_gate_ids": ["g1"]}, None
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_bound_gates_remediate_action_fails() -> None:
    """A bound gate whose decision action is 'remediate' -> (False, offenders)."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_GATE_DECISIONS)
        await conn.execute(
            "INSERT INTO gate_decisions (scope_type, scope_id, gate_id, action) "
            "VALUES (?, ?, ?, ?)",
            ("run", "run-1", "g1", "remediate"),
        )
        await conn.commit()
        ok, diag = await _guard_all_bound_gates_decided(
            conn, "run", "run-1", {"bound_gate_ids": ["g1"]}, None
        )
    assert ok is False
    assert "remediate or no decision" in diag["reason"]
    assert diag["offenders"]["g1"] == "remediate"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_bound_gates_missing_decision_fails() -> None:
    """g1 accepted, g2 has no row -> (False) with g2 mapped to 'no_decision'."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_GATE_DECISIONS)
        await conn.execute(
            "INSERT INTO gate_decisions (scope_type, scope_id, gate_id, action) "
            "VALUES (?, ?, ?, ?)",
            ("run", "run-1", "g1", "accept"),
        )
        await conn.commit()
        ok, diag = await _guard_all_bound_gates_decided(
            conn, "run", "run-1", {"bound_gate_ids": ["g1", "g2"]}, None
        )
    assert ok is False
    assert diag["offenders"]["g2"] == "no_decision"
    # g1 has an accept decision and must NOT be flagged.
    assert "g1" not in diag["offenders"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_bound_gates_accept_action_passes() -> None:
    """A single bound gate with an 'accept' decision -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_GATE_DECISIONS)
        await conn.execute(
            "INSERT INTO gate_decisions (scope_type, scope_id, gate_id, action) "
            "VALUES (?, ?, ?, ?)",
            ("run", "run-1", "g1", "accept"),
        )
        await conn.commit()
        ok, diag = await _guard_all_bound_gates_decided(
            conn, "run", "run-1", {"bound_gate_ids": ["g1"]}, None
        )
    assert ok is True
    assert diag == {}
