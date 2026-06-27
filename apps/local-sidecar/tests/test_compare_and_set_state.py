"""VAL-W2-027 / -028 / -029: compare_and_set_state happy path + race + idempotent + invalid.

These tests exercise the canonical control-plane primitive directly.

  VAL-W2-027: Two callers with same expected_from same epoch race ->
              first wins, second receives EXPECTED_FROM_MISMATCH.
  VAL-W2-028: Same (scope, expected_from, event) twice -> second call is
              idempotent (ok=True, idempotent=True), epoch NOT incremented
              twice, NO duplicate event_log row.
  VAL-W2-029: Unknown event for current state -> INVALID_TRANSITION reason
              AND one state.invalid_transition event_log row.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from relay_sidecar.anti_bypass import AntiBypassRejection
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    EXPECTED_FROM_MISMATCH,
    INVALID_TRANSITION,
    INVALID_TRANSITION_EVENT_TYPE,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


async def _seed_scope(
    db: SidecarDatabase, scope_kind: str = "run"
) -> tuple[str, str]:
    """Insert a scope_state row at the canonical initial state. Returns (scope_id, project_id)."""
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    await init_scope(
        database=db,
        scope_kind=scope_kind,
        scope_id=scope_id,
        project_id=project_id,
    )
    return scope_id, project_id


def _seed_admin_actor(db_path, *, identity_hash: str) -> None:
    """Insert a non-revoked human org_admin actors row (override path)."""
    import sqlite3
    from datetime import UTC, datetime

    now = (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, display_name, org_admin, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (identity_hash, "human", "test-admin", 1, now, None),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_stale_epoch_race_returns_expected_from_mismatch(tmp_path) -> None:
    """Two callers with same expected_from -> first wins, second rejected."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        # First call: pending -> captured via ingest.run_received.
        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert first.ok is True, first
        assert first.new_state == "captured"
        assert first.epoch == 1, first

        # Second call: still claims expected_from='pending' (stale) but
        # uses a DIFFERENT event so the idempotency probe does NOT match.
        # State is now 'captured', so EXPECTED_FROM_MISMATCH.
        second = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="validation.start",  # event name different from first
            actor=actor,
            project_id=project_id,
        )
        assert second.ok is False, second
        assert second.reason == EXPECTED_FROM_MISMATCH
        assert second.observed_state == "captured"
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotent_retry_does_not_double_increment(tmp_path) -> None:
    """Replaying the same (scope, expected_from, event) -> idempotent."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert first.ok is True
        assert first.epoch == 1

        # Replay with the SAME triple. State is now 'captured', not 'pending',
        # so the engine must consult the idempotency probe and return
        # ok=True, idempotent=True without bumping epoch.
        second = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert second.ok is True, second
        assert second.idempotent is True, second
        # Epoch did NOT increment a second time.
        assert second.epoch == 1, second

        # Verify state_state has exactly epoch=1.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert int(row[1]) == 1, row

        # Verify exactly ONE state_transition event_log row for this scope.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_invalid_transition_emits_state_invalid_event(tmp_path) -> None:
    """Unknown event for current state -> INVALID_TRANSITION + one log row."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        # 'pending' state has only one valid event (ingest.run_received);
        # send a bogus event.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
        )
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION
        assert result.observed_state == "pending"
        assert result.event_id is not None

        # The scope_state row is unchanged (epoch still 0).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row[0] == "pending"
        assert int(row[1]) == 0, row

        # Exactly one state.invalid_transition log row exists.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = ?",
            (scope_id, INVALID_TRANSITION_EVENT_TYPE),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_concurrent_compare_and_set_one_winner(tmp_path) -> None:
    """asyncio.gather(N=4) on same scope -> exactly one ok=True."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")

        async def one_call() -> bool:
            r = await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from="pending",
                event="ingest.run_received",
                actor=actor,
                project_id=project_id,
            )
            # ok=True occurs on the original winner; replays come back
            # ok=True, idempotent=True. The TWO outcomes must be
            # distinguishable: only ONE original winner (idempotent=False).
            return r.ok and not r.idempotent

        results = await asyncio.gather(*(one_call() for _ in range(4)))
        # Exactly one non-idempotent ok=True. The other three are
        # idempotent (ok=True, idempotent=True) because they replay the
        # same event after the winner committed.
        winners = sum(1 for r in results if r)
        assert winners == 1, results
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-057")
@pytest.mark.asyncio
async def test_override_claim_actor_hash_bound_to_authenticated_actor(
    tmp_path,
) -> None:
    """A non-admin caller MUST NOT bypass anti-bypass with a borrowed admin
    hash; the authenticated org_admin's own override still works.

    Security finding (anti-bypass keystone): the operator_override path took
    the override claim's ``actor_identity_hash`` straight from caller payload
    WITHOUT comparing it to the authenticated ``actor.identity_hash``. Admin
    hashes are NOT secret (they show up in audit columns), so any non-admin
    caller who has seen one admin hash could forge an override and commit a
    bypass-marker audit row. The fix binds the override claim's hash to the
    AUTHENTICATED actor.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        admin_identity = "sha256-" + ("a" * 64)
        attacker_identity = "sha256-" + ("e" * 64)
        _seed_admin_actor(tmp_path / "sidecar.db", identity_hash=admin_identity)

        # --- Attack: authenticated non-admin sdk actor supplies a BORROWED
        #     admin override claim plus a bypass marker. MUST be rejected. ---
        attack_scope, attack_project = await _seed_scope(db)
        attacker = ActorRef(kind="sdk", identity_hash=attacker_identity)
        with pytest.raises(AntiBypassRejection):
            await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=attack_scope,
                expected_from="pending",
                event="ingest.run_received",
                actor=attacker,
                payload={
                    "note": "git commit --no-verify",
                    "operator_override_claim": {
                        "actor_identity_hash": admin_identity,
                    },
                },
                project_id=attack_project,
            )

        # No marker-bearing audit row was committed for the attack scope, and
        # the state did NOT advance (the rejection aborts the transaction).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
            (attack_scope,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and row[0] == "pending" and int(row[1]) == 0, row
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries WHERE scope_id = ?",
            (attack_scope,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0, row

        # --- Legitimate: the AUTHENTICATED org_admin supplies its OWN
        #     override claim. The marker payload is recorded; state advances. ---
        admin_scope, admin_project = await _seed_scope(db)
        admin_actor = ActorRef(kind="sdk", identity_hash=admin_identity)
        ok_result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=admin_scope,
            expected_from="pending",
            event="ingest.run_received",
            actor=admin_actor,
            payload={
                "note": "git commit --no-verify",
                "operator_override_claim": {
                    "actor_identity_hash": admin_identity,
                },
            },
            project_id=admin_project,
        )
        assert ok_result.ok is True, ok_result
        assert ok_result.new_state == "captured", ok_result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-027")
@pytest.mark.asyncio
async def test_expected_from_mismatch_rejects_when_actual_sorts_after_expected(
    tmp_path,
) -> None:
    """The CAS guard must reject EVERY ``expected_from != current_state``,
    independent of lexicographic ordering (keystone #1).

    The existing mismatch test (VAL-W2-027) has current_state ``'captured'``
    sorting BEFORE the stale ``expected_from='pending'`` (``'captured' <
    'pending'``), so it does not distinguish ``current != expected`` from
    ``current < expected``. A mutation-testing gap on
    ``compare_and_set.py`` L417 (``ReplaceComparisonOperator_NotEq_Lt/LtE``)
    survived the full sidecar suite as a result: a ``<``-comparison guard
    would wrongly PROCEED with a transition from the wrong state whenever the
    actual state sorts AFTER the claimed expected_from.

    This pins the opposite ordering: a fresh scope is at the canonical initial
    ``'pending'`` and a wrong ``expected_from='captured'`` sorts BEFORE
    ``'pending'`` (``'captured' < 'pending'``), so the mutated ``<`` guard
    would NOT reject -- the real ``!=`` guard does.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")
        assert "captured" < "pending", "test premise: actual sorts after expected"
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="captured",  # wrong: scope is at 'pending'
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == EXPECTED_FROM_MISMATCH, result
        assert result.observed_state == "pending", result
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_scope_rejects_non_canonical_initial_state(tmp_path) -> None:
    """``init_scope`` must reject ANY ``initial_state`` other than the canonical
    transition-table origin, in BOTH lexicographic orderings (spec W
    "Initialization rules"). Mutation gap on ``compare_and_set.py`` L185
    (``actual_initial != spec.initial_state``): the ``<`` / ``>`` mutants
    survived because no test ever supplied a non-canonical ``initial_state``.
    The canonical 'run' origin is 'pending'; a value sorting BEFORE it
    ('aaaa...' < 'pending') AND one sorting AFTER it ('zzzz...' > 'pending')
    must both raise.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        for bad in ("aaaa_before_pending", "zzzz_after_pending"):
            with pytest.raises(ValueError, match="canonical initial state"):
                await init_scope(
                    database=db,
                    scope_kind="run",
                    scope_id=str(uuid.uuid4()),
                    project_id=str(uuid.uuid4()),
                    initial_state=bad,
                )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-009")
def test_actor_ref_is_frozen() -> None:
    """ActorRef is frozen (compare_and_set.py L61 @dataclass(frozen=True)): the
    actor reference recorded on the forensic event_log row must be immutable.
    Mutation gap: frozen=True -> frozen=False survived because no test asserted
    immutability of the actor anchor.
    """
    from dataclasses import FrozenInstanceError

    actor = ActorRef(kind="sdk", identity_hash="sha256-aaaa")
    with pytest.raises(FrozenInstanceError):
        actor.kind = "tampered"  # type: ignore[misc]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_scope_distinct_object_canonical_initial_succeeds(
    tmp_path,
) -> None:
    """A runtime-built 'pending' (equal to but NOT identical with the interned
    canonical origin) must be ACCEPTED by init_scope. Mutation gap L185
    ``actual_initial != spec.initial_state`` -> ``is not``: the real ``!=`` is
    False here (equal values -> insert), but ``is not`` between distinct-but-
    equal strings is True and would wrongly raise.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        canonical = "pending"
        dyn = "".join(["pend", "ing"])  # == 'pending' but a distinct object
        assert dyn == canonical
        assert dyn is not canonical  # premise (no literal -> no SyntaxWarning)
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=str(uuid.uuid4()),
            project_id=str(uuid.uuid4()),
            initial_state=dyn,
        )  # must NOT raise
    finally:
        await db.close()
