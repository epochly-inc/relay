"""Property-based suite for KEYSTONE INVARIANT #1 (ACCEPTANCE GATE #1,
formal-methods): the control-plane state machine only makes LEGAL transitions.

The example-based suites (``test_state_transition_coverage.py``,
``test_compare_and_set_state.py``) pin specific rows and specific races. This
suite encodes the same invariant as universally-quantified properties over a
GENERATED domain drawn from the transition table's OWN declared states/events
(via Hypothesis), so the legality guarantee is exercised across the whole
(state, event) cross-product rather than a handful of hand-picked examples.

Properties (cf. spec C.3 transition table + C.4 ``compare_and_set_state``):

  P1 LEGALITY (pure):  for a scope at state S and any event E, the transition
     table resolves (S, E) to EXACTLY its declared target when (S, E) is a
     declared row, and to NOTHING (lookup is None -> the engine rejects with
     INVALID_TRANSITION) when (S, E) is not declared. Generated over real
     states crossed with a mix of real and RANDOM (non-declared) events.

  P2 NO-UNDECLARED-TARGET (pure): every declared transition's target state is
     a member of the scope kind's declared state universe (initial state, a
     terminal state, or the source of some further transition). A target that
     is none of these (a typo'd / foreign state) is impossible.

  P3 LEGALITY (persisted): for a real scope seeded at a declared from-state,
     applying the declared event through ``compare_and_set_state`` SUCCEEDS and
     the PERSISTED state is EXACTLY the table-declared target -- and is a
     member of the declared state universe (never an undeclared target).

  P4 REJECTED-EVENTS-ARE-NOOPS (persisted): for a real scope seeded at a
     declared from-state, applying an UNDECLARED event FAILS with
     INVALID_TRANSITION and the persisted state is UNCHANGED (read-back equals
     the pre-state, and the epoch did not advance).

Design notes:
  * The pure properties drive ``TRANSITION_TABLE.lookup`` directly for breadth
    (no I/O, large ``max_examples``).
  * The persisted properties drive the real ``compare_and_set_state`` against a
    fresh on-disk ``SidecarDatabase`` per generated example. Each example runs
    its own event loop via ``asyncio.run`` (a fresh loop + fresh DB per example
    -- no fixture leakage across Hypothesis iterations), at a modest
    ``max_examples`` because every example runs the full migration set.
  * Generation is restricted to transitions whose guards are satisfiable with
    an empty payload (i.e. every declared transition EXCEPT the one carrying
    the strict three-anchor-handoff guard, which needs a heavyweight
    registry-backed payload exercised by the example-based coverage suite).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION,
    TRANSITION_TABLE,
    ActorRef,
    compare_and_set_state,
)
from relay_sidecar.state_engine.transitions import Transition

# --- Static views over the canonical transition table -----------------------
# Built once at import; the table is immutable post-construction.

_ALL_TRANSITIONS: list[Transition] = list(TRANSITION_TABLE.all_transitions())

# The strict three-anchor-handoff guard requires a registry-backed payload
# (seeded actors + manifest_versions rows). It is exercised by the
# example-based coverage suite; here we generate over the lenient remainder so
# an empty payload satisfies every guard.
_HANDOFF_GUARD = "three_anchor_handoff_valid"
_LENIENT_TRANSITIONS: list[Transition] = [
    t for t in _ALL_TRANSITIONS if _HANDOFF_GUARD not in t.guard_names
]

# Declared (scope_kind, from_state, event) keys -- the exact lookup domain.
_DECLARED_KEYS: frozenset[tuple[str, str, str]] = frozenset(
    (t.scope_kind, t.from_state, t.event) for t in _ALL_TRANSITIONS
)

# Declared targets, indexed by key, for the success-branch assertion.
_TARGET_BY_KEY: dict[tuple[str, str, str], str] = {
    (t.scope_kind, t.from_state, t.event): t.to_state for t in _ALL_TRANSITIONS
}

# Every event name that appears anywhere in the table (for the "real event"
# arm of the legality generator).
_ALL_EVENT_NAMES: list[str] = sorted({t.event for t in _ALL_TRANSITIONS})

# Per-scope canonical initial state (origin) used by the seeding rule below.
_ORIGIN_BY_SCOPE: dict[str, str] = {
    sk: TRANSITION_TABLE.scope_spec(sk).initial_state  # type: ignore[union-attr]
    for sk in TRANSITION_TABLE.scope_kinds
}

# Per-scope DECLARED STATE UNIVERSE: the initial state, every terminal state,
# and every state that is the SOURCE of some transition. A declared target
# MUST fall inside this set (P2 / NO-UNDECLARED-TARGET). Deliberately excludes
# to_states from the construction so the property is non-tautological: a target
# pointing at a state that is neither origin, terminal, nor a further source
# would be caught.
def _known_states(scope_kind: str) -> frozenset[str]:
    spec = TRANSITION_TABLE.scope_spec(scope_kind)
    assert spec is not None
    states = {spec.initial_state}
    states |= set(spec.terminal_states)
    states |= {t.from_state for t in spec.transitions}
    return frozenset(states)


_KNOWN_STATES_BY_SCOPE: dict[str, frozenset[str]] = {
    sk: _known_states(sk) for sk in TRANSITION_TABLE.scope_kinds
}

# (scope_kind, state) pairs spanning the FULL declared state universe -- the
# generation domain for the pure legality dichotomy (includes terminal and
# initial states with no outgoing edges, so "lookup -> None" is exercised).
_KNOWN_STATE_PAIRS: list[tuple[str, str]] = sorted(
    {
        (sk, state)
        for sk in TRANSITION_TABLE.scope_kinds
        for state in _KNOWN_STATES_BY_SCOPE[sk]
    }
)

# (scope_kind, from_state) pairs that are genuine transition sources -- the
# seedable, non-terminal states used by the persisted no-op property.
_FROM_PAIRS: list[tuple[str, str]] = sorted(
    {(t.scope_kind, t.from_state) for t in _ALL_TRANSITIONS}
)

# Event-name shaped alphabet for generated events: lowercase, dot, underscore.
# Keeps generated events free of anti-bypass markers (e.g. "--no-verify",
# "TODO") so the persisted no-op property exercises the pure INVALID_TRANSITION
# path rather than the anti-bypass-screen branch.
_EVENT_ALPHABET = "abcdefghijklmnopqrstuvwxyz._"

_IDENTITY_HASH = "sha256-" + ("a" * 64)


def _ts() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _seed_scope_at_state(
    db_path: Path, scope_kind: str, scope_id: str, state: str, project_id: str
) -> None:
    """Insert a scope_state row at ``state`` (mirrors the coverage suite).

    Migration 0016's initial-state policy trigger rejects epoch=0 inserts whose
    state is not the transition-table origin for the scope kind. Seed epoch=0
    only for the canonical origin; epoch=1 (one prior transition) for any other
    state so the row is no longer an "initial" row from the trigger's view.
    """
    seed_epoch = 0 if state == _ORIGIN_BY_SCOPE.get(scope_kind) else 1
    now = _ts()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO scope_state "
            "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scope_kind, scope_id, project_id, state, seed_epoch, now, now),
        )
        conn.commit()
    finally:
        conn.close()


async def _seed_apply_read(
    db_path: Path,
    *,
    scope_kind: str,
    scope_id: str,
    project_id: str,
    seed_state: str,
    expected_from: str,
    event: str,
    actor_kind: str,
) -> tuple[object, tuple[str, int]]:
    """Open a fresh DB, seed the scope, run ONE compare_and_set_state, read back.

    Returns ``(result, (persisted_state, persisted_epoch))``.
    """
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    await db.open()
    try:
        _seed_scope_at_state(db_path, scope_kind, scope_id, seed_state, project_id)
        actor = ActorRef(kind=actor_kind, identity_hash=_IDENTITY_HASH)
        result = await compare_and_set_state(
            database=db,
            scope_kind=scope_kind,
            scope_id=scope_id,
            expected_from=expected_from,
            event=event,
            actor=actor,
            payload={},
            project_id=project_id,
        )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state "
            "WHERE scope_kind = ? AND scope_id = ?",
            (scope_kind, scope_id),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None, "scope_state row vanished mid-test"
        return result, (str(row[0]), int(row[1]))
    finally:
        await db.close()


def _run_once(
    *,
    scope_kind: str,
    seed_state: str,
    expected_from: str,
    event: str,
    actor_kind: str,
) -> tuple[object, tuple[str, int]]:
    """Drive one DB-backed example in its own event loop + fresh temp DB."""
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "sidecar.db"
        return asyncio.run(
            _seed_apply_read(
                db_path,
                scope_kind=scope_kind,
                scope_id=scope_id,
                project_id=project_id,
                seed_state=seed_state,
                expected_from=expected_from,
                event=event,
                actor_kind=actor_kind,
            )
        )


# --- P1: LEGALITY (pure) -----------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
@given(
    pair=st.sampled_from(_KNOWN_STATE_PAIRS),
    event=st.one_of(
        st.sampled_from(_ALL_EVENT_NAMES),
        st.text(alphabet=_EVENT_ALPHABET, min_size=1, max_size=24),
    ),
)
@settings(max_examples=300, deadline=None)
def test_pure_legality_lookup_dichotomy(pair: tuple[str, str], event: str) -> None:
    """For ANY (scope_kind, state, event): the table resolves it to EXACTLY the
    declared target when declared, and to NOTHING (None) otherwise.

    This is the legality dichotomy at the table level. The success arm also
    asserts the resolved target lies in the declared state universe (P2),
    making "lands on an undeclared state" unrepresentable. Events are a mix of
    real names and random (overwhelmingly non-declared) strings.
    """
    scope_kind, state = pair
    looked = TRANSITION_TABLE.lookup(scope_kind, state, event)
    key = (scope_kind, state, event)
    if key in _DECLARED_KEYS:
        assert looked is not None, key
        assert looked.to_state == _TARGET_BY_KEY[key], (key, looked.to_state)
        assert looked.to_state in _KNOWN_STATES_BY_SCOPE[scope_kind], (
            key,
            looked.to_state,
        )
    else:
        # Non-declared (state, event): there is NO target. The engine maps this
        # to INVALID_TRANSITION (compare_and_set_state step 8).
        assert looked is None, (key, looked)


# --- P2: NO-UNDECLARED-TARGET (pure) ----------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
@given(transition=st.sampled_from(_ALL_TRANSITIONS))
@settings(max_examples=200, deadline=None)
def test_pure_declared_target_is_in_known_state_set(transition: Transition) -> None:
    """Every declared transition's target is a member of the scope kind's
    declared state universe (origin, a terminal state, or a further source).

    A transition whose ``to_state`` is none of these (a typo'd / foreign state)
    would be a state-machine that can land on an undeclared state -- forbidden.
    """
    known = _KNOWN_STATES_BY_SCOPE[transition.scope_kind]
    assert transition.to_state in known, (transition, sorted(known))
    # The source must also be declared (no transition out of a phantom state).
    assert transition.from_state in known, (transition, sorted(known))


# --- P3: LEGALITY (persisted) ------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
@given(transition=st.sampled_from(_LENIENT_TRANSITIONS))
@settings(max_examples=60, deadline=None)
def test_db_declared_transition_persists_table_target(
    transition: Transition,
) -> None:
    """A real scope seeded at S, given declared event E, advances to EXACTLY
    the table-declared target -- and the persisted state is in the declared
    state universe (never an undeclared target)."""
    actor_kind = transition.allowed_actor_kinds[0]
    result, (state, _epoch) = _run_once(
        scope_kind=transition.scope_kind,
        seed_state=transition.from_state,
        expected_from=transition.from_state,
        event=transition.event,
        actor_kind=actor_kind,
    )
    assert result.ok is True, (transition, result)  # type: ignore[attr-defined]
    assert result.new_state == transition.to_state, (  # type: ignore[attr-defined]
        transition,
        result,
    )
    # PERSISTED state equals the table target exactly...
    assert state == transition.to_state, (transition, state)
    # ...and is a member of the declared state universe (P2 at runtime).
    assert state in _KNOWN_STATES_BY_SCOPE[transition.scope_kind], (
        transition,
        state,
    )


# --- P4: REJECTED-EVENTS-ARE-NOOPS (persisted) ------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@given(
    pair=st.sampled_from(_FROM_PAIRS),
    event=st.text(alphabet=_EVENT_ALPHABET, min_size=1, max_size=24),
)
@settings(max_examples=80, deadline=None)
def test_db_undeclared_event_is_rejected_noop(
    pair: tuple[str, str], event: str
) -> None:
    """A real scope seeded at S, given an UNDECLARED event, is rejected with
    INVALID_TRANSITION and the persisted state is UNCHANGED (read-back == S,
    epoch did not advance). An illegal transition NEVER lands on a new state.
    """
    scope_kind, from_state = pair
    # Restrict to the undeclared half of the domain; the declared half is
    # covered by P3.
    assume((scope_kind, from_state, event) not in _DECLARED_KEYS)

    result, (state, epoch) = _run_once(
        scope_kind=scope_kind,
        seed_state=from_state,
        expected_from=from_state,
        event=event,
        actor_kind="sdk",
    )
    assert result.ok is False, (pair, event, result)  # type: ignore[attr-defined]
    assert result.reason == INVALID_TRANSITION, (  # type: ignore[attr-defined]
        pair,
        event,
        result,
    )
    # NO-OP: the persisted state is exactly the pre-state...
    assert state == from_state, (pair, event, state)
    # ...and the epoch is exactly the seeded epoch (no CAS UPDATE occurred).
    seed_epoch = 0 if from_state == _ORIGIN_BY_SCOPE[scope_kind] else 1
    assert epoch == seed_epoch, (pair, event, epoch, seed_epoch)
