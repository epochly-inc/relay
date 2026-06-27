"""Mutation-gap closure for ``_was_event_already_applied`` (the idempotency
probe in ``relay_sidecar.state_engine.compare_and_set``).

Keystone invariant #6 (side-effect / replay idempotency): a replayed
``(scope, event)`` observed at the SAME post-transition epoch must be
recognised as already-applied so the engine returns ``ok=True,
idempotent=True`` rather than re-firing the transition or rejecting the
caller with ``EXPECTED_FROM_MISMATCH``.

The pre-existing suite (``test_compare_and_set_state.py``) exercised the
probe only on the canonical single-transition replay (current_epoch == 1,
stored applied_at_epoch == 0, matching event). Several surviving mutants in
``_was_event_already_applied`` were therefore never distinguished from the
real operator. This file drives the probe through inputs whose observable
outcome (idempotent vs mismatch vs raise) BREAKS under each mutation.

Surviving mutants targeted (compare_and_set.py):

  L299  target = {"event": event, "applied_at_epoch": current_epoch - 1}
        [Sub]  -> test_idempotency_probe_uses_exact_epoch_minus_one
        Drives the scope to epoch 2 so every arithmetic mutant of
        ``current_epoch - 1`` (``+ 1``, ``* 1``, ``% 1``, ``// 1`` ...) yields
        a value != the recorded applied_at_epoch and thus FAILS to detect the
        genuine idempotent replay. (At epoch 1 several mutants collapse to 0,
        e.g. ``1 % 1 == 0``, which is why they survived.)

  L303  except (TypeError, json.JSONDecodeError):
        [ExceptionReplacer]  -> test_idempotency_probe_skips_undecodable_payload
        A junk (non-JSON) state_transition row scanned BEFORE the genuine
        match. If the except no longer catches the decode error it propagates
        out of the probe and the whole CAS call raises; the real code skips it
        and still returns idempotent.

  L304  continue  (inside the json.loads except)
        [ReplaceContinueWithBreak]  -> test_idempotency_probe_skips_undecodable_payload
        Same setup: ``break`` would abandon the scan at the junk row and
        return False (mismatch); ``continue`` skips it and finds the later
        genuine match.

  L306  continue  (inside the ``not isinstance(payload, dict)`` guard)
        [ReplaceContinueWithBreak]  -> test_idempotency_probe_skips_non_dict_payload
        A valid-JSON NON-dict row (a JSON array) scanned BEFORE the genuine
        match. ``break`` returns False; ``continue`` finds the match.

  L308  payload.get("event") == target["event"]
        [Cmp Eq -> Lt/LtE/Gt/GtE/NotEq]  -> test_idempotency_probe_event_equality_rejects_both_orderings
        A non-matching event in BOTH lexicographic orderings, with the epoch
        clause held True, must yield EXPECTED_FROM_MISMATCH. An ordering
        mutant (e.g. ``>=``) would wrongly treat a different event as a replay.

  L309  payload.get("applied_at_epoch") == target["applied_at_epoch"]
        [Cmp Eq -> Lt/LtE/Gt/GtE/NotEq x3]  -> test_idempotency_probe_epoch_equality_rejects_both_orderings
        The SAME event with a stored applied_at_epoch != target, in BOTH
        directions (stored < target AND stored > target), must yield
        EXPECTED_FROM_MISMATCH. An ordering mutant would mis-detect idempotency.

Equivalent mutants in this cluster: none. (L304/L306 differ from ``break``
only when a later matching row exists; both tests construct exactly that. The
L303 except is exercised by a row whose payload genuinely fails json.loads.)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    EXPECTED_FROM_MISMATCH,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


def _now_rfc3339() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
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


def _insert_state_transition_row(
    db_path: Path,
    *,
    scope_id: str,
    project_id: str,
    payload_text: str,
    ingest_sequence: int,
    scope_kind: str = "run",
    event_type: str = "run.captured",
) -> None:
    """Directly insert one ``event_kind='state_transition'`` event_log row.

    Mirrors the ``_seed_admin_actor`` direct-sqlite3 pattern from
    ``test_compare_and_set_state.py``. ``payload_text`` is stored verbatim so
    the test can plant a row whose payload is undecodable JSON or a valid-JSON
    non-dict -- the exact inputs the probe's defensive branches must skip.
    ``ingest_sequence`` controls scan order (the probe reads DESC), so a junk
    row is given a high value to be visited BEFORE the genuine match.
    """
    now = _now_rfc3339()
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type, "
            "  scope_id, event_type, actor_kind, actor_id, "
            "  manifest_commit_hash, payload, occurred_at, "
            "  ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                "relay.event_log_entry.v1",
                project_id,
                scope_kind,
                scope_id,
                event_type,
                "sdk",
                "sha256-aaaa",
                None,
                payload_text,
                now,
                ingest_sequence,
                "state_transition",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _force_epoch(
    db_path: Path,
    *,
    scope_id: str,
    epoch: int,
    scope_kind: str = "run",
) -> None:
    """Force scope_state.epoch directly (state column untouched).

    The 0022 ``BEFORE UPDATE OF state`` per-kind trigger does NOT fire because
    we update only ``epoch`` / ``updated_at``; this lets a test pin an
    arbitrary current_epoch so the probe's ``current_epoch - 1`` target can be
    placed on either side of a planted applied_at_epoch.
    """
    now = _now_rfc3339()
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "UPDATE scope_state SET epoch = ?, updated_at = ? "
            "WHERE scope_kind = ? AND scope_id = ?",
            (epoch, now, scope_kind, scope_id),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotency_probe_uses_exact_epoch_minus_one(tmp_path) -> None:
    """L299: the idempotency target epoch is EXACTLY ``current_epoch - 1``.

    Two real transitions advance the run to epoch 2 (state 'validating'); the
    second transition recorded ``applied_at_epoch == 1``. Replaying that second
    event with a stale ``expected_from`` drives the probe with
    ``current_epoch == 2``, so the genuine offset is ``2 - 1 == 1`` and the
    replay is idempotent. Any arithmetic mutation of ``current_epoch - 1``
    (``+ 1`` -> 3, ``* 1`` -> 2, ``% 1`` -> 0, ``// 1`` -> 2, ...) misses the
    recorded epoch and degrades the replay to EXPECTED_FROM_MISMATCH.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert first.ok is True and first.new_state == "captured", first
        assert first.epoch == 1, first

        second = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="captured",
            event="validation.start",
            actor=ActorRef(kind="ingest_worker", identity_hash="sha256-bbbb"),
            project_id=project_id,
        )
        assert second.ok is True and second.new_state == "validating", second
        assert second.epoch == 2, second

        # Replay the SECOND event with a now-stale expected_from. Current state
        # is 'validating' (!= 'captured') so the mismatch branch consults the
        # probe with current_epoch == 2; the recorded applied_at_epoch is 1.
        replay = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="captured",
            event="validation.start",
            actor=ActorRef(kind="ingest_worker", identity_hash="sha256-bbbb"),
            project_id=project_id,
        )
        assert replay.ok is True, replay
        assert replay.idempotent is True, replay
        assert replay.new_state == "validating", replay
        assert replay.epoch == 2, replay
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotency_probe_skips_undecodable_payload(tmp_path) -> None:
    """L303 + L304: a row whose payload fails json.loads is SKIPPED, not fatal.

    A genuine idempotent replay exists (one real transition recorded
    ``ingest.run_received @ applied_at_epoch 0``). A junk row with a
    non-JSON payload is planted with a higher ingest_sequence so the probe
    visits it FIRST. The real code catches the decode error and ``continue``s
    to the genuine match, returning idempotent.

      - If the except no longer catches (L303), the error propagates and the
        whole CAS call raises -> this test errors.
      - If the except's ``continue`` becomes ``break`` (L304), the scan stops
        at the junk row and returns False -> EXPECTED_FROM_MISMATCH, failing
        the ``idempotent`` assertion.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert first.ok is True and first.epoch == 1, first

        # Junk row visited first (high ingest_sequence); payload is not JSON.
        _insert_state_transition_row(
            tmp_path / "sidecar.db",
            scope_id=scope_id,
            project_id=project_id,
            payload_text="this-is-not-json",
            ingest_sequence=1000,
        )

        replay = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert replay.ok is True, replay
        assert replay.idempotent is True, replay
        assert replay.epoch == 1, replay
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotency_probe_skips_non_dict_payload(tmp_path) -> None:
    """L306: a valid-JSON NON-dict row is SKIPPED, not treated as terminal.

    A JSON-array payload decodes cleanly but is not a dict. The real code
    ``continue``s past it to the genuine match. If the ``not isinstance(...,
    dict)`` ``continue`` becomes ``break`` (L306), the scan abandons at the
    array row and returns False (mismatch).
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert first.ok is True and first.epoch == 1, first

        # Valid JSON, but a list (not a dict): must be skipped, not terminal.
        _insert_state_transition_row(
            tmp_path / "sidecar.db",
            scope_id=scope_id,
            project_id=project_id,
            payload_text="[1, 2, 3]",
            ingest_sequence=1000,
        )

        replay = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert replay.ok is True, replay
        assert replay.idempotent is True, replay
        assert replay.epoch == 1, replay
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotency_probe_event_equality_rejects_both_orderings(
    tmp_path,
) -> None:
    """L308: the event match is EQUALITY, not an ordering comparison.

    One real transition records ``ingest.run_received @ applied_at_epoch 0``
    (scope now 'captured', epoch 1). Two stale replays are issued whose events
    are DIFFERENT from the stored event in BOTH lexicographic directions, while
    the epoch clause is held True (current_epoch - 1 == 0 == stored). Each must
    yield EXPECTED_FROM_MISMATCH. A ``<`` / ``<=`` mutant would wrongly match
    the after-sorting event; a ``>`` / ``>=`` mutant the before-sorting event;
    ``!=`` would match either.
    """
    assert "aaa.before.ingest" < "ingest.run_received" < "zzz.after.ingest", (
        "test premise: query events bracket the stored event lexically"
    )
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)

        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
            project_id=project_id,
        )
        assert first.ok is True and first.epoch == 1, first

        for query_event in ("zzz.after.ingest", "aaa.before.ingest"):
            res = await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                # Stale: current state is 'captured', so the mismatch branch
                # runs the probe. The event differs from the stored one, so a
                # correct EQUALITY check never treats this as a replay.
                expected_from="pending",
                event=query_event,
                actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
                project_id=project_id,
            )
            assert res.ok is False, (query_event, res)
            assert res.reason == EXPECTED_FROM_MISMATCH, (query_event, res)
            assert res.idempotent is False, (query_event, res)
            assert res.observed_state == "captured", (query_event, res)
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-028")
@pytest.mark.asyncio
async def test_idempotency_probe_epoch_equality_rejects_both_orderings(
    tmp_path,
) -> None:
    """L309: the applied_at_epoch match is EQUALITY, not an ordering comparison.

    The scope epoch is pinned to 5 (so the probe target epoch is 4) and a
    single planted state_transition row carries the SAME event as the replay
    but a DIFFERENT applied_at_epoch, tested in BOTH directions:

      * stored 2 < target 4  -> kills ``<`` / ``<=`` / ``!=`` mutants
      * stored 7 > target 4  -> kills ``>`` / ``>=`` / ``!=`` mutants

    Both must yield EXPECTED_FROM_MISMATCH; an ordering mutant would mis-detect
    idempotency whenever the epochs merely compare the wrong way.
    """
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()

        for stored_epoch in (2, 7):
            scope_id, project_id = await _seed_scope(db)
            _force_epoch(tmp_path / "sidecar.db", scope_id=scope_id, epoch=5)
            # Planted row: same event the replay will probe for, but its
            # applied_at_epoch is not (current_epoch - 1) == 4.
            payload = (
                '{"event": "probe.event", "applied_at_epoch": '
                + str(stored_epoch)
                + "}"
            )
            _insert_state_transition_row(
                tmp_path / "sidecar.db",
                scope_id=scope_id,
                project_id=project_id,
                payload_text=payload,
                ingest_sequence=1000,
            )

            res = await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                # Current state is 'pending' (forced epoch left state intact),
                # expected_from 'captured' is stale -> mismatch branch -> probe.
                expected_from="captured",
                event="probe.event",
                actor=ActorRef(kind="sdk", identity_hash="sha256-aaaa"),
                project_id=project_id,
            )
            assert res.ok is False, (stored_epoch, res)
            assert res.reason == EXPECTED_FROM_MISMATCH, (stored_epoch, res)
            assert res.idempotent is False, (stored_epoch, res)
            assert res.observed_state == "pending", (stored_epoch, res)
            assert res.epoch == 5, (stored_epoch, res)
    finally:
        await db.close()
