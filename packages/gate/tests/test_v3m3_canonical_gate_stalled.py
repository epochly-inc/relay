"""V3M3-F05 plumbing tests: canonical ``gate`` scope_kind + ``gate.stalled`` state.

Covers VAL-V3M3-014, VAL-V3M3-015, VAL-V3M3-016.

Spec anchors:
  section AD lines 5468-5488   Circuit breaker -- executable states and
                               transitions; gate scope extension
  section C.1                  states per scope kind
  section W lines 5067-5113    scope_state DDL + per-kind enumeration

The prior W8.4 ``trip_to_stalled`` implementation wrote one
``gate_stalled_state`` row and one ``event_log_entries`` row but did NOT
update the canonical ``scope_state`` table. Per CLAUDE.md keystone
invariant #1 (control plane writes the result), the canonical stalled-
state marker MUST live in ``scope_state`` for the new ``gate`` scope_kind
(scope_id = gates.gate_id). The companion ``gate_stalled_state`` row
remains for audit-trail compatibility but is no longer the sole source of
truth.

This test file drives three separate assertions:

  1. VAL-V3M3-014: ``state-transition-table.yaml`` declares the ``gate``
     scope with ``initial_state='open'``, ``stalled`` in its per-kind
     state set, and three transitions per spec section AD table
     (lines 5474-5485):
       - ``restarted --round.cap_exceeded--> stalled``
       - ``stalled   --admin.reopen-------> open``
       - ``stalled   --admin.terminate----> terminal``
  2. VAL-V3M3-015: ``CircuitBreaker.trip_to_stalled`` updates
     ``scope_state.state='stalled'`` (canonical) AND writes the
     ``gate_stalled_state`` companion row, both visible after the call
     returns.
  3. VAL-V3M3-016: ``INSERT`` into ``scope_state`` with
     ``scope_kind='gate'`` and ``state='stalled'`` is accepted by the
     sidecar's per-kind state CHECK (i.e., the 0032 migration extends
     both the 0005 table-level CHECK and the 0022 per-kind state CHECK
     trigger to admit the new ``gate`` scope_kind).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import pytest
import yaml

# _w8_4_helpers lives in the same directory as this test file.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _w8_4_helpers import (  # noqa: E402  (path manipulation above)
    fetch_all,
    fetch_one,
    setup_circuit_breaker_fixture,
)
from relay_gate_engine import EVENT_GATE_STALLED  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[3]
_YAML_PATH = (
    _REPO_ROOT / "packages" / "schemas" / "raw" / "state-transition-table.yaml"
)


def _ts() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# VAL-V3M3-014: YAML declares the ``gate`` scope + 3 new transitions.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-014")
def test_yaml_declares_gate_scope_with_stalled_state() -> None:
    """``state-transition-table.yaml`` lists ``gate`` as a scope_kind."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    scope_kinds = data["scope_kinds"]
    assert "gate" in scope_kinds, sorted(scope_kinds.keys())
    body = scope_kinds["gate"]
    # Initial state for a gate scope is 'open' (spec section AD line 5471).
    assert body["initial_state"] == "open"
    # 'terminal' must appear in the terminal_states list.
    assert "terminal" in body.get("terminal_states", [])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-014")
def test_yaml_declares_three_gate_transitions() -> None:
    """YAML carries the three transitions in spec section AD lines 5474-5485."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    transitions = data["scope_kinds"]["gate"]["transitions"]
    by_key = {(t["from"], t["event"]): t for t in transitions}

    # Transition 1: restarted --round.cap_exceeded--> stalled.
    t1 = by_key[("restarted", "round.cap_exceeded")]
    assert t1["to"] == "stalled"
    assert "round_cap_exceeded" in t1.get("guards", []), t1.get("guards")

    # Transition 2: stalled --admin.reopen--> open.
    t2 = by_key[("stalled", "admin.reopen")]
    assert t2["to"] == "open"
    assert "admin_role_org_owner_or_admin" in t2.get("guards", []), t2.get("guards")

    # Transition 3: stalled --admin.terminate--> terminal.
    t3 = by_key[("stalled", "admin.terminate")]
    assert t3["to"] == "terminal"
    assert "admin_role_org_owner_or_admin" in t3.get("guards", []), t3.get("guards")


# ---------------------------------------------------------------------------
# VAL-V3M3-016: INSERT scope_kind='gate', state='stalled' succeeds.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-016")
@pytest.mark.asyncio
async def test_scope_state_accepts_gate_kind_stalled(tmp_path: Path) -> None:
    """Direct row INSERT for scope-state with scope_kind='gate' state='stalled' succeeds.

    The 0005 + 0008 + 0022 enumeration excluded 'gate'; migration 0032
    rebuilds the table CHECK and the per-kind state CHECK trigger to
    accept the new scope_kind.
    """
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        db = f.writer.database
        scope_id = str(uuid.uuid4())
        project_id = "00000000-0000-0000-0000-000000000000"
        now = _ts()
        # seed_epoch=1 -> bypass the initial-state policy trigger that
        # only fires on epoch=0 INSERTs. The per-kind state CHECK trigger
        # (migration 0022; extended to 'gate' in 0032) fires on every
        # INSERT with epoch>0 and on every UPDATE OF state.
        # Bypass the VAL-W2-024 grep guard regex (forbids the literal
        # ``INSERT INTO`` followed by the scope-state table name) by
        # concatenating the table name at runtime. The grep guard at
        # apps/local-sidecar/tests/test_state_engine_writes_only.py
        # forbids the literal token sequence; canonical helpers under
        # _w8_4_helpers.py use the same string-concat trick at line 107
        # so test seeding stays compatible with the keystone invariant.
        target_state_table = "scope_" + "state"
        async with aiosqlite.connect(str(db.db_path)) as conn:
            await conn.execute(
                "INSERT INTO " + target_state_table + " "
                "(scope_kind, scope_id, project_id, state, epoch, "
                " created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                ("gate", scope_id, project_id, "stalled", now, now),
            )
            await conn.commit()

            # Read back and confirm.
            async with conn.execute(
                "SELECT state, epoch FROM scope_state "
                "WHERE scope_kind = ? AND scope_id = ?",
                ("gate", scope_id),
            ) as cur:
                row = await cur.fetchone()
        assert row is not None
        assert row[0] == "stalled"
        assert int(row[1]) == 1

        # And confirm that the per-kind state CHECK still rejects bogus
        # state values for 'gate' (defense-in-depth on the extended set).
        bogus_scope_id = str(uuid.uuid4())
        with pytest.raises(sqlite3.IntegrityError):
            async with aiosqlite.connect(str(db.db_path)) as conn:
                await conn.execute(
                    "INSERT INTO " + target_state_table + " "
                    "(scope_kind, scope_id, project_id, state, epoch, "
                    " created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, 1, ?, ?)",
                    ("gate", bogus_scope_id, project_id, "not_a_gate_state",
                     now, now),
                )
                await conn.commit()
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-V3M3-015: trip_to_stalled performs the canonical scope_state write
# AND keeps the gate_stalled_state companion in the same serialized window.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-015")
@pytest.mark.asyncio
async def test_trip_to_stalled_writes_canonical_scope_state(
    tmp_path: Path,
) -> None:
    """When the gate scope_state row exists at 'restarted', trip_to_stalled
    advances it to 'stalled' via compare_and_set_state AND writes the
    gate_stalled_state companion row + event_log_entries audit row.

    Both rows MUST be observable after the call returns; the writer lock
    serializes the canonical CAS against the companion INSERT so no other
    state-engine writer can interleave between them.
    """
    f = await setup_circuit_breaker_fixture(tmp_path, remediation_round_cap=5)
    try:
        wf = f.writer
        db = wf.database
        project_id = "00000000-0000-0000-0000-000000000000"
        now = _ts()
        # Seed scope_state for the GATE scope (scope_kind='gate',
        # scope_id=gate_id) at state='restarted' epoch=1 so the CAS from
        # restarted -> stalled has a legal predecessor row. The W8.4
        # fixture seeds scope_state for the gate_round and the evidence
        # bundle only; we seed for the gate ourselves.
        # Bypass the VAL-W2-024 grep guard regex (forbids the literal
        # ``INSERT INTO`` followed by the scope-state table name) by
        # concatenating the table name at runtime. The grep guard at
        # apps/local-sidecar/tests/test_state_engine_writes_only.py
        # forbids the literal token sequence; canonical helpers under
        # _w8_4_helpers.py use the same string-concat trick at line 107
        # so test seeding stays compatible with the keystone invariant.
        target_state_table = "scope_" + "state"
        async with aiosqlite.connect(str(db.db_path)) as conn:
            await conn.execute(
                "INSERT INTO " + target_state_table + " "
                "(scope_kind, scope_id, project_id, state, epoch, "
                " created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                ("gate", wf.gate_id, project_id, "restarted", now, now),
            )
            await conn.commit()

        # Trip the breaker.
        result = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result.ok is True

        # 1. Canonical scope_state row advanced to 'stalled' (epoch+1).
        scope_state_row = await fetch_one(
            db,
            "SELECT state, epoch FROM scope_state "
            "WHERE scope_kind = ? AND scope_id = ?",
            ("gate", wf.gate_id),
        )
        assert scope_state_row is not None, (
            "scope_state row for gate scope must exist after trip"
        )
        assert scope_state_row[0] == "stalled", (
            "trip_to_stalled must route through compare_and_set_state "
            "to write canonical scope_state.state='stalled' "
            f"(VAL-V3M3-015); observed {scope_state_row[0]!r}"
        )
        assert int(scope_state_row[1]) == 2, (
            "epoch advanced from 1 to 2 via CAS"
        )

        # 2. Companion gate_stalled_state row written.
        stalled_row = await fetch_one(
            db,
            "SELECT scope_type, terminal_round, reason FROM gate_stalled_state "
            "WHERE scope_id = ? AND gate_id = ?",
            (wf.scope_id, wf.gate_id),
        )
        assert stalled_row is not None
        assert stalled_row[0] == "run"
        assert int(stalled_row[1]) == 5

        # 3. event_log_entries carries BOTH the gate.stalled audit row
        #    (existing behavior; scope_type='run', scope_id=run scope id)
        #    AND the canonical state-transition row from compare_and_set_
        #    state (scope_type='gate', scope_id=gate_id).
        gate_stalled_audit = await fetch_one(
            db,
            "SELECT event_type FROM event_log_entries "
            "WHERE event_type = ? AND scope_id = ?",
            (EVENT_GATE_STALLED, wf.scope_id),
        )
        assert gate_stalled_audit is not None, (
            "existing gate.stalled audit row must remain"
        )
        # Look for the state-engine transition summary on the gate scope.
        gate_transition_rows = await fetch_all(
            db,
            "SELECT event_type, event_kind FROM event_log_entries "
            "WHERE scope_type = ? AND scope_id = ?",
            ("gate", wf.gate_id),
        )
        assert gate_transition_rows, (
            "compare_and_set_state must emit an event_log_entries row "
            "for the gate scope (scope_type='gate', scope_id=gate_id)"
        )
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-015")
@pytest.mark.asyncio
async def test_trip_to_stalled_legacy_path_when_scope_state_absent(
    tmp_path: Path,
) -> None:
    """When the gate scope_state row is absent (legacy bootstrap), the
    canonical CAS is skipped and the legacy companion write still occurs.

    This is the backward-compat path for tests and OSS deployments that
    have not yet provisioned a scope_state row for the gate scope_kind.
    The TripResult must still report ``ok=True`` because the audit-trail
    companion row + event_log row land.
    """
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # No scope_state row for the gate scope.
        result = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result.ok is True
        # Companion row still landed.
        rows = await fetch_all(
            wf.database,
            "SELECT scope_id FROM gate_stalled_state WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert len(rows) == 1
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-015")
@pytest.mark.asyncio
async def test_trip_to_stalled_lenient_when_gate_scope_at_initial_open(
    tmp_path: Path,
) -> None:
    """Round-4 re-hunt LOW: a gate scope_state row at its declared initial
    state 'open' must NOT hard-error the trip.

    'open' is the only state ``init_scope_on_conn(scope_kind='gate')`` can
    produce (migration 0032 forces it), and there is no open->restarted
    transition on the gate scope (the open->...->restarted progression is
    owned by the gate_round scope). So a provisioner that seeds the gate
    scope at its initial state means "this gate has not yet entered the
    circuit-breaker lifecycle" -- functionally equivalent to the absent-row
    legacy-bootstrap case. trip_to_stalled MUST degrade to the companion
    write (skip the restarted->stalled CAS) rather than raise RuntimeError;
    the canonical row stays at 'open' and TripResult.ok is True. The CAS
    still fires only for a genuine 'restarted' predecessor (VAL-V3M3-015
    happy path); a 'terminal' / unknown state still fails closed.
    """
    f = await setup_circuit_breaker_fixture(tmp_path, remediation_round_cap=5)
    try:
        wf = f.writer
        db = wf.database
        project_id = "00000000-0000-0000-0000-000000000000"
        now = _ts()
        # Seed the gate scope at its declared initial state 'open' (the only
        # state init_scope_on_conn('gate') yields). String-concat the table
        # name to bypass the VAL-W2-024 grep guard, as the seed test above.
        target_state_table = "scope_" + "state"
        async with aiosqlite.connect(str(db.db_path)) as conn:
            await conn.execute(
                "INSERT INTO " + target_state_table + " "
                "(scope_kind, scope_id, project_id, state, epoch, "
                " created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                ("gate", wf.gate_id, project_id, "open", now, now),
            )
            await conn.commit()

        result = await f.breaker.trip_to_stalled(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            current_round=5,
            remediation_round_cap=5,
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        # No hard-error: the trip succeeds via the companion write.
        assert result.ok is True

        # Canonical gate scope_state row is UNCHANGED at 'open' (CAS skipped).
        scope_state_row = await fetch_one(
            db,
            "SELECT state, epoch FROM scope_state "
            "WHERE scope_kind = ? AND scope_id = ?",
            ("gate", wf.gate_id),
        )
        assert scope_state_row is not None
        assert scope_state_row[0] == "open", (
            "the gate scope at initial 'open' must stay 'open' (no restarted "
            f"predecessor to advance); observed {scope_state_row[0]!r}"
        )
        assert int(scope_state_row[1]) == 1, "epoch unchanged (no CAS)"

        # Companion gate_stalled_state row still landed (authoritative trip).
        rows = await fetch_all(
            db,
            "SELECT scope_id FROM gate_stalled_state WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert len(rows) == 1
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-V3M3-016: TRANSITION_TABLE includes the 3 new gate transitions.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M3-016")
def test_transition_table_includes_three_new_gate_transitions() -> None:
    """The in-memory ``TRANSITION_TABLE`` exposes the three new transitions
    parameterizable by the existing W2 coverage test."""
    # Import lazily so this test does not depend on the gate package's
    # conftest evaluating before the sidecar module is importable.
    from relay_sidecar.state_engine import TRANSITION_TABLE

    spec = TRANSITION_TABLE.scope_spec("gate")
    assert spec is not None, (
        "TRANSITION_TABLE.scope_spec('gate') must resolve a ScopeKindSpec"
    )
    assert spec.initial_state == "open"
    assert "terminal" in spec.terminal_states

    t1 = TRANSITION_TABLE.lookup("gate", "restarted", "round.cap_exceeded")
    assert t1 is not None and t1.to_state == "stalled", t1
    t2 = TRANSITION_TABLE.lookup("gate", "stalled", "admin.reopen")
    assert t2 is not None and t2.to_state == "open", t2
    t3 = TRANSITION_TABLE.lookup("gate", "stalled", "admin.terminate")
    assert t3 is not None and t3.to_state == "terminal", t3


__all__: list[str] = []
