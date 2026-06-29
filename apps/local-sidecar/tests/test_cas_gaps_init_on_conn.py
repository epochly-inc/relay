"""Mutation-gap closure for ``init_scope_on_conn`` (compare_and_set.py L245-250).

These tests target surviving mutants in the validation prologue of
``init_scope_on_conn`` -- the inline-transaction variant of ``init_scope``
that runs INSIDE the caller's existing BEGIN IMMEDIATE..COMMIT (spec W line
5112 path used by canonical writers co-committing scope_state with their
object row). The existing sidecar suite exercises ``init_scope`` (the
``database=`` variant) but NEVER exercises ``init_scope_on_conn`` (the
``conn=`` variant), so its prologue mutated freely.

Surviving mutants closed here (each test breaks under the listed mutation):

  L245 ``tbl = table if table is not None else TRANSITION_TABLE``
       [AddNot, IsNot_Is] -> mutant picks ``table`` (None) so
       ``None.scope_spec(...)`` raises AttributeError on the default call.
       Killed by ``test_init_on_conn_default_args_inserts_canonical_row``
       (a default-table/default-initial call must SUCCEED).

  L247 ``if spec is None:`` [AddNot] -> mutant inverts the guard: it raises
       on a KNOWN scope_kind and skips the raise on an UNKNOWN one (then
       AttributeErrors on ``None.initial_state``). Killed by the default
       success test (must not raise on 'run') AND by
       ``test_init_on_conn_unknown_scope_kind_raises_value_error`` (unknown
       kind must raise ValueError, not AttributeError).

  L249 ``actual_initial = initial_state if initial_state is not None
       else spec.initial_state`` [AddNot, IsNot_Is] -> with default
       ``initial_state=None`` the mutant selects ``initial_state`` (None);
       L250 then sees ``None != 'pending'`` and raises ValueError. Killed by
       the default success test (must SUCCEED with initial_state=None).

  L250 ``if actual_initial != spec.initial_state:`` [Comparison x8] -> the
       only existing non-canonical-initial test (on ``init_scope``) hits one
       lexicographic ordering, so ``<`` / ``>`` / ``<=`` / ``>=`` / ``==`` /
       ``is`` / ``is not`` survived. Killed by driving BOTH orderings of a
       non-canonical value through ``test_init_on_conn_non_canonical_initial
       _both_orderings_raise`` (kills ``<``,``>``,``<=``,``>=``,``==``,``is``)
       PLUS ``test_init_on_conn_distinct_object_canonical_initial_succeeds``
       which passes a value EQUAL but NOT IDENTICAL to the canonical
       'pending' (kills ``is not``: ``!=`` is False so the real code inserts,
       while ``is not`` between two distinct equal strings is True and would
       wrongly raise).

EQUIVALENT survivors in this cluster: NONE. Every mutant on L245/L247/L249/
L250 is a real survivor with an observable behavioral difference (an
AttributeError, a spurious ValueError, or a missing ValueError), and each is
killed by a test below.

NOTE: ``init_scope_on_conn`` takes ``conn=`` (an aiosqlite.Connection), not
``database=``. The writer connection is obtained via the module's
``_borrow_writer`` context manager (the same primitive ``init_scope`` and
``compare_and_set_state`` use), and the surrounding transaction is managed by
the caller per the function contract.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import contextlib
import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import init_scope_on_conn
from relay_sidecar.state_engine.compare_and_set import _borrow_writer
from relay_sidecar.state_engine.transitions import TRANSITION_TABLE


async def _init_on_conn(db: SidecarDatabase, **kwargs) -> None:
    """Run ``init_scope_on_conn`` inside a caller-managed writer transaction.

    Mirrors how ``init_scope`` drives the conn= path: borrow the writer,
    BEGIN IMMEDIATE, insert, COMMIT (or ROLLBACK on error and re-raise).
    """
    async with _borrow_writer(db) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            await init_scope_on_conn(conn=conn, **kwargs)
            await conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                await conn.execute("ROLLBACK")
            raise


async def _read_scope_row(db: SidecarDatabase, scope_id: str):
    reader = db.acquire_reader()
    async with reader.execute(
        "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
        (scope_id,),
    ) as cur:
        return await cur.fetchone()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_on_conn_default_args_inserts_canonical_row(tmp_path) -> None:
    """Default table + default initial_state must INSERT the canonical row.

    Kills L245 [AddNot, IsNot_Is]: a flipped ``table is not None`` selects
    ``table`` (None) for ``tbl``, so ``None.scope_spec('run')`` raises
    AttributeError instead of succeeding.

    Kills L247 [AddNot]: an inverted ``spec is None`` raises
    ValueError("unknown scope_kind") on the KNOWN 'run' kind.

    Kills L249 [AddNot, IsNot_Is]: a flipped ``initial_state is not None``
    selects ``initial_state`` (None) so L250 sees ``None != 'pending'`` and
    raises ValueError. The real code must SUCCEED and persist state='pending'
    at epoch 0.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        # No table=, no initial_state= -> exercises both default branches.
        await _init_on_conn(
            db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        row = await _read_scope_row(db, scope_id)
        assert row is not None, "scope_state row was not inserted"
        assert row[0] == "pending", row
        assert int(row[1]) == 0, row
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_on_conn_unknown_scope_kind_raises_value_error(tmp_path) -> None:
    """An unknown scope_kind must raise ValueError (not AttributeError).

    Kills L247 [AddNot]: the real guard ``if spec is None`` raises
    ValueError("unknown scope_kind: ...") when the table has no spec. The
    mutant ``if spec is not None`` skips that raise, falls through to
    ``spec.initial_state`` with ``spec=None``, and raises AttributeError --
    which ``pytest.raises(ValueError)`` does NOT catch, failing the test.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        assert (
            TRANSITION_TABLE.scope_spec("definitely_not_a_real_scope_kind") is None
        ), "test premise: scope_kind must be unknown to the transition table"
        async with _borrow_writer(db) as conn:
            with pytest.raises(ValueError, match="unknown scope_kind"):
                await init_scope_on_conn(
                    conn=conn,
                    scope_kind="definitely_not_a_real_scope_kind",
                    scope_id=str(uuid.uuid4()),
                    project_id=str(uuid.uuid4()),
                )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_on_conn_non_canonical_initial_both_orderings_raise(
    tmp_path,
) -> None:
    """A non-canonical initial_state must raise in BOTH lexicographic orderings.

    Kills L250 [Comparison: <, <=, >, >=, ==, is]. The canonical 'run' origin
    is 'pending'. One bad value sorts BEFORE it ('aaaa...' < 'pending') and
    one sorts AFTER it ('zzzz...' > 'pending'); both are ``!= 'pending'`` so
    the real ``!=`` guard raises on both. Each ordering-sensitive mutant fails
    to raise on at least one input:
      - ``<``  : 'zzzz...' < 'pending' is False -> no raise -> killed.
      - ``<=`` : 'zzzz...' <= 'pending' is False -> no raise -> killed.
      - ``>``  : 'aaaa...' > 'pending' is False -> no raise -> killed.
      - ``>=`` : 'aaaa...' >= 'pending' is False -> no raise -> killed.
      - ``==`` : never equal to 'pending' -> no raise on either -> killed.
      - ``is`` : distinct objects -> False -> no raise on either -> killed.
    (``is not`` is killed by the distinct-object SUCCESS test below.)
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        before = "aaaa_before_pending"
        after = "zzzz_after_pending"
        assert before < "pending" < after, "test premise: straddle the origin"
        async with _borrow_writer(db) as conn:
            for bad in (before, after):
                with pytest.raises(ValueError, match="canonical initial state"):
                    await init_scope_on_conn(
                        conn=conn,
                        scope_kind="run",
                        scope_id=str(uuid.uuid4()),
                        project_id=str(uuid.uuid4()),
                        initial_state=bad,
                    )
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-029")
@pytest.mark.asyncio
async def test_init_on_conn_distinct_object_canonical_initial_succeeds(
    tmp_path,
) -> None:
    """A value EQUAL but NOT IDENTICAL to the canonical origin must SUCCEED.

    Kills L250 [Comparison: is not]. The real guard ``actual_initial !=
    spec.initial_state`` is False for a runtime-built 'pending' (string
    equality), so the row inserts. The ``is not`` mutant compares object
    identity: two distinct-but-equal strings are ``is not`` -> True, so the
    mutant would wrongly raise ValueError. Passing a non-interned 'pending'
    (built at runtime) makes the identity differ from the table's interned
    literal, exposing the mutation.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        canonical = TRANSITION_TABLE.scope_spec("run").initial_state
        dyn_initial = "".join(["pend", "ing"])  # equal to 'pending', new object
        assert dyn_initial == canonical, "test premise: value equals the origin"
        assert dyn_initial is not canonical, (
            "test premise: value must be a DISTINCT object so 'is not' diverges "
            "from '!='"
        )
        scope_id = str(uuid.uuid4())
        await _init_on_conn(
            db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=str(uuid.uuid4()),
            initial_state=dyn_initial,
        )
        row = await _read_scope_row(db, scope_id)
        assert row is not None, "scope_state row was not inserted"
        assert row[0] == "pending", row
        assert int(row[1]) == 0, row
    finally:
        await db.close()
