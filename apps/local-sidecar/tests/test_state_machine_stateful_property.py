"""Generative STATEFUL property suite for KEYSTONE INVARIANTS #1 + #5 over the
control-plane ``compare_and_set_state`` primitive (spec C.3 transition table +
C.4 pseudocode).

The single-transition property suite (``test_state_machine_property.py``,
P1-P4) quantifies legality over the (state, event) cross-product but applies at
most ONE transition per generated scope. This suite raises the bar to
SEQUENCES: a Hypothesis-generated stream of directives is replayed against ONE
real on-disk scope, and a Python reference model is run in lockstep. The
invariants asserted at every step are the keystone properties the task names:

  (1) LEGALITY + NO-MUTATION-ON-REJECT (keystone #1 / spec C.4): from the
      current state S, applying the table-legal event advances the persisted
      state to EXACTLY the table-declared target and bumps epoch by exactly 1;
      applying any UNDECLARED event for S is rejected with the structured
      reason ``INVALID_TRANSITION`` and leaves scope_state byte-for-byte
      UNCHANGED (state and epoch both unchanged). An illegal transition never
      mutates the canonical row.

  (2) CONTROL-PLANE-WRITES-THE-RESULT (keystone #1): the persisted scope_state
      row, read back fresh before every directive, equals the reference model
      derived SOLELY from the outcomes of ``compare_and_set_state`` calls. The
      test never writes scope_state itself (only ``init_scope`` +
      ``compare_and_set_state`` ever touch the row). If any non-CAS path -- or
      a CAS bug -- moved the canonical row off the model trajectory, the
      pre-step read-back assertion fires. (The complementary "this module is
      the ONLY writer in the source tree" guarantee is enforced separately by
      the VAL-W2-024 / VAL-W2-058 grep guards.)

  (3) IDEMPOTENT RE-APPLY (keystone #5 / spec C.4 lines 3716-3718): replaying
      the immediately-preceding successful event with its now-STALE
      ``expected_from`` is a NO-OP that returns ``ok=True, idempotent=True``
      with ``new_state`` equal to the already-observed target, and does not
      advance epoch. The idempotency probe matches only the most-recent applied
      event (``applied_at_epoch == current_epoch - 1``), so the model replays
      exactly that event.

Design choice -- generative sequences, not ``RuleBasedStateMachine``:
  Hypothesis' ``RuleBasedStateMachine`` would reuse ONE event loop + one open
  ``SidecarDatabase`` (aiosqlite connections + a background writer task) across
  many rule invocations. The repo's pytest config sets ``filterwarnings =
  error`` and there is no async-DB-reuse-across-rules precedent in this suite;
  a stray ResourceWarning / unraisable-on-GC from a long-lived reused loop
  would escalate to a hard error. We therefore follow the proven, warning-clean
  pattern already used by ``test_state_machine_property.py``: a fresh temp DB
  driven by a single ``asyncio.run`` per generated example. The example IS a
  multi-step sequence, so the suite is genuinely stateful; it simply scopes the
  event loop to one example instead of one rule.

Scope kind: ``run`` (spec C.1) -- a linear lifecycle
    pending -> captured -> validating -> gated -> result_written -> terminal
  whose guards are all satisfiable with an empty payload (P3 of the sibling
  suite proves the whole chain advances with ``payload={}``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import tempfile
import uuid
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION,
    TRANSITION_TABLE,
    ActorRef,
    compare_and_set_state,
    init_scope,
)

# --- Test-local STATIC snapshot of the run-scope transition table -----------
#
# Built from the table DATA (``ScopeKindSpec.transitions``), NEVER via
# ``TRANSITION_TABLE.lookup``. This matters for the non-vacuity (RED) proof:
# breaking ``lookup`` in production must NOT silently flip these reference
# structures, or the test would mask the very bug it exists to catch. The
# reference model is the source of truth the engine is checked against.

_SCOPE_KIND = "run"
_SPEC = TRANSITION_TABLE.scope_spec(_SCOPE_KIND)
assert _SPEC is not None, "run scope kind must exist in the transition table"
_INITIAL_STATE = _SPEC.initial_state

# from_state -> (event, to_state, actor_kind). The run scope has exactly one
# outgoing edge per non-terminal state, so the legal next step is deterministic.
_LEGAL_BY_STATE: dict[str, tuple[str, str, str]] = {
    t.from_state: (t.event, t.to_state, t.allowed_actor_kinds[0])
    for t in _SPEC.transitions
}
# from_state -> frozenset(legal event names) for the "is this event illegal
# here?" reference check (static; immune to a broken production lookup).
_LEGAL_EVENTS_BY_STATE: dict[str, frozenset[str]] = {
    state: frozenset({_LEGAL_BY_STATE[state][0]})
    for state in _LEGAL_BY_STATE
}
# Every event name anywhere in the run scope -- used to generate "legal
# elsewhere but illegal HERE" events (a strong illegal arm).
_ALL_RUN_EVENTS: list[str] = sorted({t.event for t in _SPEC.transitions})

# Event-name shaped alphabet for random (overwhelmingly undeclared) events.
# Lowercase + dot + underscore keeps generated tokens free of anti-bypass
# markers (e.g. "TODO", "--no-verify") so the illegal arm exercises the pure
# INVALID_TRANSITION path rather than the anti-bypass screen.
_EVENT_ALPHABET = "abcdefghijklmnopqrstuvwxyz._"

_IDENTITY_HASH = "sha256-" + ("a" * 64)


# --- Directive grammar -------------------------------------------------------
# A generated example is a list of directives. Each is a (kind, arg) tuple:
#   ("legal", None)         -> apply the table-legal event for the cur. state
#   ("illegal", event_str)  -> apply an event (may be illegal for cur. state)
#   ("idempotent", None)    -> replay the last successful event (stale expect.)

_legal = st.tuples(st.just("legal"), st.none())
_idempotent = st.tuples(st.just("idempotent"), st.none())
_illegal = st.tuples(
    st.just("illegal"),
    st.one_of(
        st.sampled_from(_ALL_RUN_EVENTS),  # legal-elsewhere, illegal-here
        st.text(alphabet=_EVENT_ALPHABET, min_size=1, max_size=20),  # random
    ),
)
_DIRECTIVE = st.one_of(_legal, _illegal, _idempotent)


class _Model:
    """Reference model of one run scope, advanced ONLY by observed CAS outcomes."""

    def __init__(self) -> None:
        self.state: str = _INITIAL_STATE
        self.epoch: int = 0
        self.last_event: str | None = None
        self.last_from: str | None = None
        self.last_applied_epoch: int | None = None
        # Per-branch execution counters -- used to assert the example was not
        # vacuous (the deterministic test asserts each branch fired >= 1).
        self.applied_legal = 0
        self.rejected_illegal = 0
        self.replayed_idempotent = 0


async def _read_state(db: SidecarDatabase, scope_id: str) -> tuple[str, int]:
    reader = db.acquire_reader()
    async with reader.execute(
        "SELECT state, epoch FROM scope_state "
        "WHERE scope_kind = ? AND scope_id = ?",
        (_SCOPE_KIND, scope_id),
    ) as cur:
        row = await cur.fetchone()
    assert row is not None, "scope_state row vanished mid-sequence"
    return str(row[0]), int(row[1])


async def _drive(db_path: Path, directives: list[tuple[str, object]]) -> _Model:
    """Open a fresh DB, seed one run scope at ``pending``, replay ``directives``
    against the real ``compare_and_set_state`` while asserting the keystone
    properties in lockstep with a reference model. Returns the model so callers
    can assert which branches actually executed."""
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    model = _Model()

    db = SidecarDatabase(db_path=db_path, reader_count=1)
    await db.open()
    try:
        await init_scope(
            database=db,
            scope_kind=_SCOPE_KIND,
            scope_id=scope_id,
            project_id=project_id,
        )
        # Freshly-seeded canonical row matches the model origin.
        assert await _read_state(db, scope_id) == (model.state, model.epoch)

        for kind, arg in directives:
            # Property (2): the canonical row, read back fresh, ALWAYS equals
            # the model derived solely from prior CAS outcomes -- checked
            # before every directive so any off-trajectory mutation is caught.
            pre_state, pre_epoch = await _read_state(db, scope_id)
            assert (pre_state, pre_epoch) == (model.state, model.epoch), (
                kind,
                arg,
                (pre_state, pre_epoch),
                (model.state, model.epoch),
            )

            if kind == "legal":
                # Terminal / no-outgoing-edge states have nothing legal to do.
                if model.state not in _LEGAL_BY_STATE:
                    continue
                event, to_state, actor_kind = _LEGAL_BY_STATE[model.state]
                res = await compare_and_set_state(
                    database=db,
                    scope_kind=_SCOPE_KIND,
                    scope_id=scope_id,
                    expected_from=model.state,
                    event=event,
                    actor=ActorRef(kind=actor_kind, identity_hash=_IDENTITY_HASH),
                    payload={},
                    project_id=project_id,
                )
                # Property (1) success arm: ok, exact declared target, real
                # apply (not an idempotent dedupe), epoch bumped by one.
                assert res.ok is True, (model.state, event, res)
                assert res.idempotent is False, (model.state, event, res)
                assert res.new_state == to_state, (model.state, event, res)
                post = await _read_state(db, scope_id)
                assert post == (to_state, model.epoch + 1), (model.state, event, post)
                # Advance the model + idempotency bookkeeping.
                model.last_event = event
                model.last_from = model.state
                model.last_applied_epoch = model.epoch
                model.state = to_state
                model.epoch += 1
                model.applied_legal += 1

            elif kind == "illegal":
                bogus = str(arg)
                # Only assert the illegal contract when the directive is
                # GENUINELY illegal for the current state. The legality check
                # uses the STATIC reference snapshot (never the production
                # lookup), so a broken lookup cannot route a real illegal event
                # around this guard.
                if model.state not in _LEGAL_BY_STATE:
                    continue  # terminal -> would be TERMINAL_STATE, not INVALID
                if bogus in _LEGAL_EVENTS_BY_STATE[model.state]:
                    continue  # actually the legal event here -> not an illegal case
                res = await compare_and_set_state(
                    database=db,
                    scope_kind=_SCOPE_KIND,
                    scope_id=scope_id,
                    expected_from=model.state,
                    event=bogus,
                    actor=ActorRef(kind="sdk", identity_hash=_IDENTITY_HASH),
                    payload={},
                    project_id=project_id,
                )
                # Property (1) reject arm: structured rejection, NO mutation.
                assert res.ok is False, (model.state, bogus, res)
                assert res.reason == INVALID_TRANSITION, (model.state, bogus, res)
                post = await _read_state(db, scope_id)
                assert post == (model.state, model.epoch), (model.state, bogus, post)
                model.rejected_illegal += 1

            else:  # "idempotent"
                # Replay is observable only immediately after a legal step (the
                # probe matches applied_at_epoch == current_epoch - 1). Illegal
                # steps and prior replays do not advance epoch, so this holds
                # until the NEXT legal step.
                if (
                    model.last_event is None
                    or model.last_applied_epoch is None
                    or model.epoch != model.last_applied_epoch + 1
                ):
                    continue
                assert model.last_from is not None
                actor_kind = _LEGAL_BY_STATE[model.last_from][2]
                res = await compare_and_set_state(
                    database=db,
                    scope_kind=_SCOPE_KIND,
                    scope_id=scope_id,
                    expected_from=model.last_from,  # STALE on purpose
                    event=model.last_event,
                    actor=ActorRef(kind=actor_kind, identity_hash=_IDENTITY_HASH),
                    payload={},
                    project_id=project_id,
                )
                # Property (3): idempotent no-op, same observed state, no bump.
                assert res.ok is True, (model.last_event, res)
                assert res.idempotent is True, (model.last_event, res)
                assert res.new_state == model.state, (model.last_event, res)
                post = await _read_state(db, scope_id)
                assert post == (model.state, model.epoch), (model.last_event, post)
                model.replayed_idempotent += 1

        return model
    finally:
        await db.close()


def _run(directives: list[tuple[str, object]]) -> _Model:
    """Drive one sequence in its own event loop + fresh temp DB (warning-clean,
    mirrors the asyncio.run-per-example pattern of the sibling property suite)."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "sidecar.db"
        return asyncio.run(_drive(db_path, directives))


# --- Generative property: random directive sequences ------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
@given(directives=st.lists(_DIRECTIVE, min_size=1, max_size=14))
@settings(max_examples=40, deadline=None)
def test_run_scope_sequence_keeps_canonical_row_on_the_legal_trajectory(
    directives: list[tuple[str, object]],
) -> None:
    """Over an arbitrary sequence of legal / illegal / idempotent directives,
    the persisted canonical scope_state never leaves the model trajectory
    defined purely by ``compare_and_set_state`` outcomes: legal events advance
    to the declared target (+1 epoch), illegal events are rejected with
    INVALID_TRANSITION and mutate nothing, and stale replays are idempotent
    no-ops. All assertions live inside ``_drive``; reaching the end is the
    property holding for this sequence."""
    model = _run(directives)
    # Sanity: the model never advanced past the scope's terminal state and the
    # epoch equals the number of legal applies (each legal step bumps once;
    # illegal + idempotent steps never bump).
    assert model.epoch == model.applied_legal, model.__dict__
    assert model.state in (
        set(_LEGAL_BY_STATE) | set(_SPEC.terminal_states)
    ), model.state


# --- Deterministic branch-coverage driver: NON-VACUITY by construction ------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
def test_run_scope_explicit_branches_all_three_properties_fire() -> None:
    """A hand-built sequence that GUARANTEES each property branch executes at
    least once on every run, so the suite can never pass vacuously: walk the
    full pending->terminal chain, and after each legal step interleave a
    genuinely-illegal event (asserting INVALID_TRANSITION + no mutation) and a
    stale idempotent replay (asserting the no-op dedupe)."""
    directives: list[tuple[str, object]] = []
    # 5 legal steps (pending..result_written), each followed by an illegal
    # event drawn from the run vocabulary that is illegal in that state, plus a
    # stale idempotent replay of the step just applied.
    for _ in range(len(_LEGAL_BY_STATE)):
        directives.append(("legal", None))
        directives.append(("illegal", "gate.all_decided"))  # illegal in most states
        directives.append(("illegal", "definitely.not.an.event"))
        directives.append(("idempotent", None))

    model = _run(directives)

    # Every legal edge of the run scope was applied -> we reached terminal.
    assert model.applied_legal == len(_LEGAL_BY_STATE), model.__dict__
    assert model.state in _SPEC.terminal_states, model.state
    assert model.epoch == len(_LEGAL_BY_STATE), model.__dict__
    # The reject arm fired (illegal events were genuinely rejected, not skipped).
    assert model.rejected_illegal >= 1, model.__dict__
    # The idempotent-replay arm fired (stale re-apply was a recognised no-op).
    assert model.replayed_idempotent >= 1, model.__dict__


# --- UNKNOWN_SCOPE smoke (a CAS against a never-seeded scope is a no-op) -----


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
def test_cas_on_unseeded_scope_writes_nothing() -> None:
    """A ``compare_and_set_state`` against a scope that was never initialised is
    rejected (UNKNOWN_SCOPE) and creates no scope_state row -- the control plane
    does not conjure canonical rows from a bare CAS call."""

    async def _go() -> None:
        scope_id = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "sidecar.db"
            db = SidecarDatabase(db_path=db_path, reader_count=1)
            await db.open()
            try:
                res = await compare_and_set_state(
                    database=db,
                    scope_kind=_SCOPE_KIND,
                    scope_id=scope_id,
                    expected_from=_INITIAL_STATE,
                    event=_LEGAL_BY_STATE[_INITIAL_STATE][0],
                    actor=ActorRef(kind="sdk", identity_hash=_IDENTITY_HASH),
                    payload={},
                )
                assert res.ok is False, res
                assert res.reason == "UNKNOWN_SCOPE", res
                reader = db.acquire_reader()
                async with reader.execute(
                    "SELECT COUNT(*) FROM scope_state "
                    "WHERE scope_kind = ? AND scope_id = ?",
                    (_SCOPE_KIND, scope_id),
                ) as cur:
                    count_row = await cur.fetchone()
                assert count_row is not None and int(count_row[0]) == 0, count_row
            finally:
                await db.close()

    asyncio.run(_go())
