"""Mutation-gap closure for ``compare_and_set_state`` (cluster: main fn).

Each test below pins an assertion that BREAKS under a specific surviving
mutant on
``apps/local-sidecar/relay_sidecar/state_engine/compare_and_set.py`` while
PASSING on the real code. Survivors targeted (by source line):

  L381  project_id_eff = project_id or <sentinel>   [ReplaceOrWithAnd]
  L410  ok=False UNKNOWN_SCOPE                       [ReplaceFalseWithTrue]
  L446  ok=False TERMINAL_STATE                      [ReplaceFalseWithTrue]
  L549  "forensic_payload_sanitized": True           [ReplaceTrueWithFalse]
  L560  next_seq = int(row[0]) if row is not None    [AddNot, IsNot_Is]
  L578  json.dumps(..., sort_keys=True, ...)         [ReplaceTrueWithFalse]
  L627  ok=False UNKNOWN_GUARD                        [ReplaceFalseWithTrue]
  L667  if rowcount != 1 (==, <=, >= variants)       [ReplaceComparisonOperator]
  L691  new_epoch = current_epoch + 1                [ReplaceBinaryOperator_Add_*]
  L767  next_seq = int(row[0]) if row is not None    [IsNot_Is]
  L785  json.dumps(..., sort_keys=True, ...)         [ReplaceTrueWithFalse]
  L836  json.dumps(summary_payload, sort_keys=True)  [ReplaceTrueWithFalse]
  L838  next_seq + 1                                 [NumberReplacer + Add_* x13]

EQUIVALENT survivors (no forced test; justification recorded here and in the
structured report):

  L585  ``except BaseException:`` -> ``except Exception:`` -- defensive
        rollback handler. The only inputs that differ between the two are
        KeyboardInterrupt / SystemExit / GeneratorExit raised by the
        interpreter mid-INSERT; these are impractical to inject in a unit
        test and yield identical observable behaviour (ROLLBACK + re-raise).

  L667  the ``<`` / ``>`` ReplaceComparisonOperator variants of
        ``rowcount != 1`` -- at this line ``rowcount`` is INVARIANTLY 1: the
        UPDATE matches exactly one row by (scope_kind, scope_id, epoch) where
        ``epoch`` was read from that same row earlier in the SAME
        BEGIN IMMEDIATE transaction, under the single-writer
        ``_state_engine_writer_lock`` (no other writer can interleave). For
        the only reachable value 1, ``1 != 1`` == ``1 < 1`` == ``1 > 1`` ==
        False, so ``<`` / ``>`` are indistinguishable from ``!=``. (The
        ``==`` / ``<=`` / ``>=`` variants DO change behaviour on the success
        path and are killed by test_success_epoch_increments_across_chain.)

  L678  ``str(refreshed[0]) if refreshed is not None else current_state`` and
  L681  ``int(refreshed[1]) if refreshed is not None else current_epoch`` and
  L684  ``ok=False`` -- all three live inside the ``if rowcount != 1`` block,
        which is UNREACHABLE in the single-writer in-transaction model (see
        L667 reasoning). Mutations to dead code cannot be killed by a test.

  L725  ``conn if override_event_kind == OPERATOR_OVERRIDE_EVENT_KIND else
        None`` mutated ``==`` -> ``is`` -- ``override_event_kind`` is assigned
        literally ``OPERATOR_OVERRIDE_EVENT_KIND if ... else None`` two lines
        above, so when set it is the SAME object identity as the constant;
        ``is`` and ``==`` give identical results (both True when set, both
        False when None). Indistinguishable.

  L560 / L767  the NumberReplacer on the ``else 0`` branch -- the preceding
        ``SELECT COALESCE(MAX(ingest_sequence), -1) + 1`` always returns
        exactly one row, so ``row is not None`` is invariantly True and the
        ``else 0`` arm is dead. (The AddNot / IsNot_Is variants flip the live
        arm and ARE killed below.)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    EXPECTED_FROM_MISMATCH,
    INVALID_TRANSITION,
    TERMINAL_STATE,
    UNKNOWN_GUARD,
    UNKNOWN_SCOPE,
    ActorRef,
    ScopeKindSpec,
    Transition,
    TransitionTable,
    compare_and_set_state,
    init_scope,
)

_SENTINEL_PROJECT_ID = "00000000-0000-0000-0000-000000000000"
_ACTOR_HASH = "sha256-" + ("a" * 64)

# Canonical run-scope progression (state, event, actor_kind, to_state), drawn
# from packages/schemas/raw/state-transition-table.yaml. Every guard along
# this chain is lenient and passes with an empty/minimal payload.
RUN_STEPS: tuple[tuple[str, str, str, str], ...] = (
    ("pending", "ingest.run_received", "sdk", "captured"),
    ("captured", "validation.start", "ingest_worker", "validating"),
    ("validating", "validation.complete", "validation_worker", "gated"),
    ("gated", "gate.all_decided", "result_writer", "result_written"),
    ("result_written", "auto.terminal", "result_writer", "terminal"),
)


async def _seed_scope(
    db: SidecarDatabase, scope_kind: str = "run"
) -> tuple[str, str]:
    """Insert a scope_state row at the canonical initial state.

    Returns (scope_id, project_id).
    """
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    await init_scope(
        database=db,
        scope_kind=scope_kind,
        scope_id=scope_id,
        project_id=project_id,
    )
    return scope_id, project_id


async def _drive(db: SidecarDatabase, scope_id: str, project_id: str, n: int):
    """Apply the first ``n`` canonical run transitions; assert each succeeds."""
    results = []
    for frm, event, kind, to in RUN_STEPS[:n]:
        r = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from=frm,
            event=event,
            actor=ActorRef(kind=kind, identity_hash=_ACTOR_HASH),
            project_id=project_id,
        )
        assert r.ok is True, (frm, event, r)
        assert r.new_state == to, (frm, event, r)
        results.append(r)
    return results


def _top_keys(raw_payload: str) -> list[str]:
    """Top-level key order as it appears in a serialized JSON object string."""
    parsed = json.loads(raw_payload)
    assert isinstance(parsed, dict), raw_payload
    return list(parsed.keys())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_unknown_scope_returns_ok_false(tmp_path) -> None:
    """A CAS against an absent scope returns ok=False / UNKNOWN_SCOPE (L410).

    Mutation ReplaceFalseWithTrue flips ``ok=False`` to True; pinning
    ``ok is False`` plus the reason code breaks under it.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        # Deliberately do NOT init_scope: scope_state SELECT returns None.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=str(uuid.uuid4()),
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash=_ACTOR_HASH),
            project_id=str(uuid.uuid4()),
        )
        assert result.ok is False, result
        assert result.reason == UNKNOWN_SCOPE, result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_terminal_state_is_sticky_returns_ok_false(tmp_path) -> None:
    """A transition out of a terminal state returns ok=False / TERMINAL_STATE (L446).

    Drives run pending -> ... -> terminal, then attempts another transition
    FROM terminal. The terminal-stickiness branch must reject. Mutation
    ReplaceFalseWithTrue on ``ok=False`` is caught by ``ok is False``.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        await _drive(db, scope_id, project_id, 5)  # reach 'terminal'

        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="terminal",
            event="auto.terminal",
            actor=ActorRef(kind="result_writer", identity_hash=_ACTOR_HASH),
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == TERMINAL_STATE, result
        assert result.observed_state == "terminal", result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_unknown_guard_fails_closed_ok_false(tmp_path) -> None:
    """An unregistered guard name fails closed: ok=False / UNKNOWN_GUARD (L627).

    Uses a custom transition table whose only transition references a guard
    name absent from the registry, so ``get_guard`` returns None and the
    fail-closed branch fires. Mutation ReplaceFalseWithTrue on ``ok=False``
    is caught by ``ok is False``.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        custom = TransitionTable(
            {
                "run": ScopeKindSpec(
                    scope_kind="run",
                    initial_state="pending",
                    terminal_states=frozenset({"terminal"}),
                    transitions=(
                        Transition(
                            scope_kind="run",
                            from_state="pending",
                            event="ingest.run_received",
                            to_state="captured",
                            allowed_actor_kinds=("sdk",),
                            event_log_type="run.captured",
                            guard_names=("guard_that_is_not_registered_xyz",),
                        ),
                    ),
                )
            }
        )
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
            table=custom,
        )
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash=_ACTOR_HASH),
            project_id=project_id,
            table=custom,
        )
        assert result.ok is False, result
        assert result.reason == UNKNOWN_GUARD, result
        assert result.extras.get("failed_guard") == "guard_that_is_not_registered_xyz", result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_project_id_persisted_not_sentinel(tmp_path) -> None:
    """A non-empty project_id is recorded verbatim on the audit row (L381).

    ``project_id_eff = project_id or <sentinel>`` mutated to ``and`` would
    write the empty-UUID sentinel whenever a real project_id is supplied.
    Reading the persisted audit-row project_id pins the real value.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        assert project_id != _SENTINEL_PROJECT_ID  # premise: truthy, non-sentinel

        await _drive(db, scope_id, project_id, 1)

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT project_id FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "expected one state_transition audit row"
        assert row[0] == project_id, row
        assert row[0] != _SENTINEL_PROJECT_ID, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_success_epoch_increments_across_chain(tmp_path) -> None:
    """Each successful transition returns epoch = current_epoch + 1 (L691),
    and the CAS rowcount guard commits (not rejects) on success (L667).

    Drives four transitions and asserts the returned epoch is EXACTLY 1, 2,
    3, 4. The fourth assertion (current_epoch=3 -> 4) distinguishes ``+1``
    from every ReplaceBinaryOperator_Add_* mutant, including the bitwise
    ones: at c=3, c+1=4 differs from 3-1, 3*1, 3//1, 3%1, 3**1, 3<<1=6,
    3>>1=1, 3|1=3, 3&1=1, 3^1=2. Each step also asserts ``ok is True``,
    which fails under the ==/<=/>= ReplaceComparisonOperator mutants of
    ``rowcount != 1`` (they would divert a successful UPDATE into the
    mismatch-rollback branch and return ok=False).
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        results = await _drive(db, scope_id, project_id, 4)
        assert [r.epoch for r in results] == [1, 2, 3, 4], results

        # scope_state epoch independently confirms the 4th commit.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and row[0] == "result_written" and int(row[1]) == 4, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_invalid_transition_forensic_seq_and_jcs_sorted(tmp_path) -> None:
    """The INVALID_TRANSITION forensic row carries the real next ingest
    sequence (L560) and a JCS-canonical (sorted-keys) payload (L578).

    A successful transition is applied first (occupying ingest sequences 0
    and 1) so the forensic row's expected sequence is 2, not 0. The AddNot /
    IsNot_Is mutants on L560 would force next_seq to 0. A benign caller key
    that sorts AFTER the engine keys but is inserted FIRST makes the
    serialized key order differ from sorted order, so sort_keys=False (L578)
    is caught by the keys-sorted assertion.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        # One successful transition -> audit seq 0, summary seq 1 (global).
        await _drive(db, scope_id, project_id, 1)  # state now 'captured'

        max_before = await _max_ingest_seq(db)
        assert max_before == 1, max_before

        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="captured",
            event="no.such.event",
            actor=ActorRef(kind="ingest_worker", identity_hash=_ACTOR_HASH),
            # "zzz_extra" is inserted before the engine verdict keys but
            # sorts last; it is bypass-marker free so the screen passes.
            payload={"zzz_extra": "benign-value"},
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == INVALID_TRANSITION, result

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT ingest_sequence, payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_invalid_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "expected one forensic row"
        forensic_seq = int(row[0])
        assert forensic_seq == max_before + 1 == 2, forensic_seq

        keys = _top_keys(row[1])
        assert "zzz_extra" in keys and len(keys) >= 2, keys
        assert keys == sorted(keys), keys  # sort_keys=True canonical order
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_invalid_transition_sanitized_forensic_flag(tmp_path) -> None:
    """When the caller payload trips the anti-bypass screen, the forensic
    row is recorded with ``forensic_payload_sanitized: True`` (L549).

    Mutation ReplaceTrueWithFalse would record it as False; reading the
    persisted flag pins True. The screen rejection is caught internally and
    a sanitized (engine-keys-only) row is still committed, so the call
    returns ok=False rather than raising.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="no.such.event",
            actor=ActorRef(kind="sdk", identity_hash=_ACTOR_HASH),
            payload={"note": "git commit --no-verify"},  # trips the screen
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == INVALID_TRANSITION, result
        # A clean rejection vs screen-tripped rejection is signalled via extras.
        assert result.extras.get("secondary_error_reason") is not None, result

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_invalid_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "expected one sanitized forensic row"
        payload = json.loads(row[0])
        assert payload.get("forensic_payload_sanitized") is True, payload
        # The raw offending marker is dropped from the durable row.
        assert "note" not in payload, payload
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_success_audit_and_summary_sequencing_and_jcs(tmp_path) -> None:
    """The success path writes the audit row at the real next sequence (L767),
    the summary row at audit_seq + 1 (L838), and both payloads JCS-canonical
    (L785 audit, L836 summary).

    Setup engineers an ODD, non-1 next sequence (3) for the asserted
    transition so the full ReplaceBinaryOperator_Add_* set on
    ``next_seq + 1`` is killed (including bitwise | / ^ which equal +1 only
    for even operands, and << which equals +1 only at operand 1):
      - invalid transition  -> forensic seq 0
      - transition pending->captured -> audit seq 1, summary seq 2
      - transition captured->validating -> audit seq 3 (asserted), summary 4
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        # Forensic row (seq 0) -- makes the later audit next_seq land odd.
        bogus = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="no.such.event",
            actor=ActorRef(kind="sdk", identity_hash=_ACTOR_HASH),
            project_id=project_id,
        )
        assert bogus.ok is False and bogus.reason == INVALID_TRANSITION, bogus

        # First successful transition -> audit seq 1, summary seq 2.
        await _drive(db, scope_id, project_id, 1)  # state now 'captured'

        max_before = await _max_ingest_seq(db)
        assert max_before == 2, max_before

        # Asserted transition captured->validating: audit next_seq == 3 (odd, != 1).
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="captured",
            event="validation.start",
            actor=ActorRef(kind="ingest_worker", identity_hash=_ACTOR_HASH),
            payload={"zzz_extra": "benign-value"},  # out-of-order benign key
            project_id=project_id,
        )
        assert result.ok is True, result
        assert result.new_state == "validating", result
        assert result.epoch == 2, result

        reader = db.acquire_reader()

        # Audit row located by the event_id this call returned.
        async with reader.execute(
            "SELECT ingest_sequence, payload FROM event_log_entries "
            "WHERE event_id = ?",
            (result.event_id,),
        ) as cur:
            audit = await cur.fetchone()
        assert audit is not None, "expected the audit row by event_id"
        audit_seq = int(audit[0])
        assert audit_seq == max_before + 1 == 3, audit_seq  # L767
        audit_keys = _top_keys(audit[1])
        assert "zzz_extra" in audit_keys and len(audit_keys) >= 2, audit_keys
        assert audit_keys == sorted(audit_keys), audit_keys  # L785

        # Summary row is the most recent state_transition_summary on this scope.
        async with reader.execute(
            "SELECT ingest_sequence, payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition_summary' "
            "ORDER BY ingest_sequence DESC LIMIT 1",
            (scope_id,),
        ) as cur:
            summary = await cur.fetchone()
        assert summary is not None, "expected a summary row"
        summary_seq = int(summary[0])
        assert summary_seq == audit_seq + 1 == 4, summary_seq  # L838
        summary_keys = _top_keys(summary[1])
        assert summary_keys == ["epoch_after", "from_state", "to_state"], summary_keys  # L836
        assert summary_keys == sorted(summary_keys), summary_keys

        summary_payload = json.loads(summary[1])
        assert summary_payload["from_state"] == "captured", summary_payload
        assert summary_payload["to_state"] == "validating", summary_payload
        assert summary_payload["epoch_after"] == 2, summary_payload
    finally:
        await db.close()


async def _max_ingest_seq(db: SidecarDatabase) -> int:
    """Current MAX(ingest_sequence) over the whole event_log_entries table."""
    reader = db.acquire_reader()
    async with reader.execute(
        "SELECT COALESCE(MAX(ingest_sequence), -1) FROM event_log_entries"
    ) as cur:
        row = await cur.fetchone()
    return int(row[0])
