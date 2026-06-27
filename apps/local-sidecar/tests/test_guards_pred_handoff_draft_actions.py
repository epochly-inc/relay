"""Direct-unit mutation-hardening suite for state-engine guard predicates.

CLUSTER C: the six auto/handoff/draft/conditions/restart/terminal guard
predicates in ``relay_sidecar.state_engine.guards``:

  - ``_guard_auto_transition_allowed``
  - ``_guard_three_anchor_handoff_valid``
  - ``_guard_draft_not_expired``
  - ``_guard_all_conditions_evaluated``
  - ``_guard_restart_action_applies``
  - ``_guard_terminal_action_applies``

These predicates are normally exercised only INDIRECTLY through
``compare_and_set_state`` transitions, leaving their internal branches
unpinned (mutation testing showed ~78% mutant survival). This suite calls
each predicate DIRECTLY with an in-memory aiosqlite connection and asserts
BOTH the returned bool AND a distinguishing key in the diagnostics dict for
EVERY branch, so a mutation that flips any branch is killed. Each distinct
branch is a separate assertion.

The suite does NOT call ``register_guard`` and does NOT route through
``compare_and_set_state`` -- predicate calls only. Only the minimal table(s)
each guard SELECTs are created; the "table absent" branch deliberately omits
its table to drive the OperationalError fallback.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import aiosqlite
import pytest

from relay_sidecar.state_engine.guards import (
    _guard_all_conditions_evaluated,
    _guard_auto_transition_allowed,
    _guard_draft_not_expired,
    _guard_restart_action_applies,
    _guard_terminal_action_applies,
    _guard_three_anchor_handoff_valid,
)


async def _create_handoff_tables(
    conn: aiosqlite.Connection, *, with_scope_state: bool = True
) -> None:
    """Create the minimal tables ``validate_three_anchor_handoff`` SELECTs.

    The handoff validator reads ``actors`` (actor anchor) and
    ``manifest_versions`` (manifest anchor); ``_guard_three_anchor_handoff_valid``
    additionally reads ``scope_state`` to resolve project_id when the payload
    omits it. The "table absent" branch passes ``with_scope_state=False`` so
    the guard's scope_state SELECT raises OperationalError.
    """
    await conn.execute("CREATE TABLE actors (identity_hash TEXT, revoked_at TEXT)")
    await conn.execute(
        "CREATE TABLE manifest_versions ("
        "project_id TEXT, commit_hash TEXT, effective_until TEXT, "
        "grace_window_seconds INTEGER)"
    )
    if with_scope_state:
        await conn.execute(
            "CREATE TABLE scope_state "
            "(scope_kind TEXT, scope_id TEXT, project_id TEXT)"
        )
    await conn.commit()


# ---------------------------------------------------------------------------
# (1) _guard_auto_transition_allowed: unconditionally (True, {}).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_auto_transition_allowed_always_true() -> None:
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_auto_transition_allowed(
            conn, "run", "run-1", {"anything": "ignored"}, "sha256-mch"
        )
        assert ok is True
        assert diag == {}


# ---------------------------------------------------------------------------
# (2) _guard_three_anchor_handoff_valid: enrichment + delegation branches.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_payload_mch_takes_precedence_over_arg() -> None:
    # Branch (a): payload already carries manifest_commit_hash -> the
    # arg-injection branch is NOT taken. Only the PAYLOAD's hash is
    # registered as active; the arg's hash is absent. A mutation that
    # injects the arg over the payload value would look up an unregistered
    # hash and fail, so a True outcome pins the precedence.
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-a', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES "
            "('proj-a', 'sha256-mch-payload', NULL, 0)"
        )
        await conn.commit()
        payload = {
            "run_id": "run-a",
            "actor_identity_hash": "sha256-actor-a",
            "manifest_commit_hash": "sha256-mch-payload",
            "project_id": "proj-a",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-a", payload, "sha256-mch-ARG-DIFFERENT"
        )
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_arg_mch_injected_when_payload_omits() -> None:
    # Branch (b): payload omits manifest_commit_hash but the mch arg is not
    # None -> injection path. The arg's hash is the only registered active
    # manifest. A mutation that skips injection leaves manifest_commit_hash
    # absent -> MANIFEST_NOT_ACTIVE; a True outcome pins the injection.
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-b', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES ('proj-b', 'sha256-mch-b', NULL, 0)"
        )
        await conn.commit()
        payload = {
            "run_id": "run-b",
            "actor_identity_hash": "sha256-actor-b",
            "project_id": "proj-b",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-b", payload, "sha256-mch-b"
        )
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_payload_project_id_skips_scope_state() -> None:
    # Branch (c): payload carries a non-empty project_id -> scope_state read
    # is skipped. scope_state holds a CONFLICTING project_id; if a mutation
    # read it anyway it would override the payload's correct project_id and
    # the manifest lookup (bound by project_id) would miss -> False. A True
    # outcome pins that the scope_state read is skipped.
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-c', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES "
            "('proj-correct', 'sha256-mch-c', NULL, 0)"
        )
        await conn.execute(
            "INSERT INTO scope_state VALUES ('run', 'run-c', 'proj-WRONG')"
        )
        await conn.commit()
        payload = {
            "run_id": "run-c",
            "actor_identity_hash": "sha256-actor-c",
            "manifest_commit_hash": "sha256-mch-c",
            "project_id": "proj-correct",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-c", payload, None
        )
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_scope_state_supplies_project_id() -> None:
    # Branch (d): payload omits project_id; scope_state supplies it (read
    # path). The only registered manifest row is for a DIFFERENT project, so
    # the project-bound lookup using the scope_state project_id misses ->
    # MANIFEST_NOT_ACTIVE. A mutation that SKIPS the scope_state read leaves
    # project_id None, the validator falls back to a commit_hash-only lookup
    # that WOULD match the cross-project row -> True. Asserting False here
    # pins that the read path runs and enforces per-project scoping.
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-d', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES "
            "('proj-OTHER', 'sha256-mch-d', NULL, 0)"
        )
        await conn.execute(
            "INSERT INTO scope_state VALUES ('run', 'run-d', 'proj-from-state')"
        )
        await conn.commit()
        payload = {
            "run_id": "run-d",
            "actor_identity_hash": "sha256-actor-d",
            "manifest_commit_hash": "sha256-mch-d",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-d", payload, None
        )
        assert ok is False
        assert "three-anchor handoff failed" in diag["reason"]
        assert diag["handoff_reason"] == "MANIFEST_NOT_ACTIVE"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_scope_state_absent_falls_back() -> None:
    # Branch (e): scope_state table absent -> the guard's SELECT raises
    # aiosqlite.OperationalError, which is caught (fallback to commit_hash-
    # only validation). The handoff is otherwise fully valid, so the guard
    # returns (True, {}) WITHOUT crashing. A mutation removing the try/except
    # would let the OperationalError propagate and error the test.
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn, with_scope_state=False)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-e', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES ('proj-any', 'sha256-mch-e', NULL, 0)"
        )
        await conn.commit()
        payload = {
            "run_id": "run-e",
            "actor_identity_hash": "sha256-actor-e",
            "manifest_commit_hash": "sha256-mch-e",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-e", payload, None
        )
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_valid_handoff_passes() -> None:
    # Branch (f), positive: a fully-valid handoff -> (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute("INSERT INTO actors VALUES ('sha256-actor-f', NULL)")
        await conn.execute(
            "INSERT INTO manifest_versions VALUES ('proj-f', 'sha256-mch-f', NULL, 0)"
        )
        await conn.commit()
        payload = {
            "run_id": "run-f",
            "actor_identity_hash": "sha256-actor-f",
            "manifest_commit_hash": "sha256-mch-f",
            "project_id": "proj-f",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-f", payload, None
        )
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_three_anchor_missing_actor_fails() -> None:
    # Branch (f), negative: payload missing actor_identity_hash -> validator
    # returns ACTOR_NOT_REGISTERED -> guard returns
    # (False, reason "three-anchor handoff failed", handoff_reason present).
    async with aiosqlite.connect(":memory:") as conn:
        await _create_handoff_tables(conn)
        await conn.execute(
            "INSERT INTO manifest_versions VALUES ('proj-g', 'sha256-mch-g', NULL, 0)"
        )
        await conn.commit()
        payload = {
            "run_id": "run-g",
            "manifest_commit_hash": "sha256-mch-g",
            "project_id": "proj-g",
        }
        ok, diag = await _guard_three_anchor_handoff_valid(
            conn, "run", "run-g", payload, None
        )
        assert ok is False
        assert "three-anchor handoff failed" in diag["reason"]
        assert diag["handoff_reason"] == "ACTOR_NOT_REGISTERED"


# ---------------------------------------------------------------------------
# (3) _guard_draft_not_expired: RFC 3339 parsing + expiry comparison. No DB.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_draft_not_expired_absent_or_non_str_passes() -> None:
    # Branch (a): no draft_expires_at, or a non-string value -> (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        ok_absent, diag_absent = await _guard_draft_not_expired(
            conn, "gate", "g-1", {}, None
        )
        assert ok_absent is True
        assert diag_absent == {}
        ok_nonstr, diag_nonstr = await _guard_draft_not_expired(
            conn, "gate", "g-1", {"draft_expires_at": 1234567890}, None
        )
        assert ok_nonstr is True
        assert diag_nonstr == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_draft_not_expired_malformed_rejected() -> None:
    # Branch (b): malformed timestamp -> (False, reason "not RFC 3339").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_draft_not_expired(
            conn, "gate", "g-1", {"draft_expires_at": "not-a-date"}, None
        )
        assert ok is False
        assert "not RFC 3339" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_draft_not_expired_past_rejected() -> None:
    # Branch (c): timestamp in the past -> (False, reason "draft expired").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_draft_not_expired(
            conn, "gate", "g-1", {"draft_expires_at": "2000-01-01T00:00:00Z"}, None
        )
        assert ok is False
        assert "draft expired" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_draft_not_expired_future_passes() -> None:
    # Branch (d): far-future timestamps -> (True, {}). The "Z" suffix
    # exercises the normalization branch; a naive (no-tz) future timestamp
    # exercises the tzinfo-is-None replace branch.
    async with aiosqlite.connect(":memory:") as conn:
        ok_z, diag_z = await _guard_draft_not_expired(
            conn, "gate", "g-1", {"draft_expires_at": "2999-01-01T00:00:00Z"}, None
        )
        assert ok_z is True
        assert diag_z == {}
        ok_naive, diag_naive = await _guard_draft_not_expired(
            conn, "gate", "g-1", {"draft_expires_at": "2999-01-01T00:00:00"}, None
        )
        assert ok_naive is True
        assert diag_naive == {}


# ---------------------------------------------------------------------------
# (4) _guard_all_conditions_evaluated: conditions_pending identity check.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_all_conditions_pending_blocks() -> None:
    # conditions_pending is True -> (False, reason "conditions not fully
    # evaluated").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_all_conditions_evaluated(
            conn, "gate", "g-1", {"conditions_pending": True}, None
        )
        assert ok is False
        assert "conditions not fully evaluated" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_all_conditions_not_pending_passes() -> None:
    # Absent, explicit False, and a truthy non-True value all pass (pins the
    # ``is True`` identity check: only the literal True blocks).
    async with aiosqlite.connect(":memory:") as conn:
        ok_absent, diag_absent = await _guard_all_conditions_evaluated(
            conn, "gate", "g-1", {}, None
        )
        assert ok_absent is True
        assert diag_absent == {}
        ok_false, diag_false = await _guard_all_conditions_evaluated(
            conn, "gate", "g-1", {"conditions_pending": False}, None
        )
        assert ok_false is True
        assert diag_false == {}
        ok_truthy, diag_truthy = await _guard_all_conditions_evaluated(
            conn, "gate", "g-1", {"conditions_pending": "pending"}, None
        )
        assert ok_truthy is True
        assert diag_truthy == {}


# ---------------------------------------------------------------------------
# (5) _guard_restart_action_applies: action membership + cascade flag.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_restart_action_absent_passes() -> None:
    # Branch (a): no decision_action -> (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_restart_action_applies(conn, "gate", "g-1", {}, None)
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_restart_action_not_remediate_or_block_rejected() -> None:
    # Branch (b): decision_action "accept" is not in {remediate, block} ->
    # (False, reason "not in {remediate, block}").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_restart_action_applies(
            conn, "gate", "g-1", {"decision_action": "accept"}, None
        )
        assert ok is False
        assert "not in {remediate, block}" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_restart_action_block_no_cascade_rejected() -> None:
    # Branch (c): decision_action "block" with cascade_on_block False ->
    # (False, reason "cascade_on_block is false").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_restart_action_applies(
            conn,
            "gate",
            "g-1",
            {"decision_action": "block", "cascade_on_block": False},
            None,
        )
        assert ok is False
        assert "cascade_on_block is false" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_restart_action_remediate_default_cascade_passes() -> None:
    # Branch (d): decision_action "remediate" with no cascade key (defaults
    # True) -> (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_restart_action_applies(
            conn, "gate", "g-1", {"decision_action": "remediate"}, None
        )
        assert ok is True
        assert diag == {}


# ---------------------------------------------------------------------------
# (6) _guard_terminal_action_applies: action membership in {accept, invalid}.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_terminal_action_absent_passes() -> None:
    # Branch (a): no decision_action -> (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_terminal_action_applies(conn, "gate", "g-1", {}, None)
        assert ok is True
        assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_terminal_action_not_accept_or_invalid_rejected() -> None:
    # Branch (b): decision_action "block" is not in {accept, invalid} ->
    # (False, reason "not in {accept, invalid}").
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_terminal_action_applies(
            conn, "gate", "g-1", {"decision_action": "block"}, None
        )
        assert ok is False
        assert "not in {accept, invalid}" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_terminal_action_accept_and_invalid_pass() -> None:
    # Branch (c): decision_action "accept" -> (True, {}); "invalid" ->
    # (True, {}).
    async with aiosqlite.connect(":memory:") as conn:
        ok_accept, diag_accept = await _guard_terminal_action_applies(
            conn, "gate", "g-1", {"decision_action": "accept"}, None
        )
        assert ok_accept is True
        assert diag_accept == {}
        ok_invalid, diag_invalid = await _guard_terminal_action_applies(
            conn, "gate", "g-1", {"decision_action": "invalid"}, None
        )
        assert ok_invalid is True
        assert diag_invalid == {}
