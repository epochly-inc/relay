"""Direct-unit mutation-hardening suite for state-engine guard predicates.

CLUSTER E: signing-key revocation, retention-policy, retention-window /
legal-hold, remediation round-cap, and admin-role guards.

These five predicates are normally exercised only INDIRECTLY through
``compare_and_set_state`` transitions, which leaves their internal branches
unpinned (mutation testing showed ~78% survival). This suite calls each
predicate DIRECTLY against an in-memory aiosqlite connection and asserts BOTH
the returned boolean AND a distinguishing key in the diagnostics dict for
EVERY branch, so a mutation that flips any branch is killed by a dedicated
assertion.

The predicates under test (apps/local-sidecar/relay_sidecar/state_engine/
guards.py):
  - _guard_signing_key_not_revoked
  - _guard_retention_policy_applied
  - _guard_retention_window_elapsed_and_no_legal_hold
  - _guard_round_cap_exceeded
  - _guard_admin_role_org_owner_or_admin

Each test creates ONLY the minimal table(s) the guard SELECTs; for the
"table not present" branch the table is deliberately NOT created so the
guard's OperationalError handler is exercised.

ASCII-only per CLAUDE.md "ASCII-Safe Source". No register_guard, no
compare_and_set_state -- direct predicate calls only.
"""

from __future__ import annotations

import aiosqlite
import pytest
from relay_sidecar.state_engine.guards import (
    _guard_admin_role_org_owner_or_admin,
    _guard_retention_policy_applied,
    _guard_retention_window_elapsed_and_no_legal_hold,
    _guard_round_cap_exceeded,
    _guard_signing_key_not_revoked,
)

# DDL for the only table any cluster-E guard SELECTs.
_KEY_LIFECYCLE_DDL = (
    "CREATE TABLE key_lifecycle "
    "(key_id TEXT, event_type TEXT, event_at TEXT)"
)


# ---------------------------------------------------------------------------
# (1) _guard_signing_key_not_revoked
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_absent_passes_lenient() -> None:
    """Branch a: no signing_key_id key in payload -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_empty_string_passes_lenient() -> None:
    """Branch a: empty-string signing_key_id -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": ""}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_non_str_passes_lenient() -> None:
    """Branch a: non-str signing_key_id (int) -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": 12345}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_table_absent_passes_with_note() -> None:
    """Branch b: key present but key_lifecycle table missing -> note."""
    # Deliberately do NOT create the key_lifecycle table.
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": "k-1"}, None
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_no_lifecycle_rows_passes_with_note() -> None:
    """Branch c: key present, table empty for that key -> note."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": "k-1"}, None
        )
    assert ok is True
    assert "no lifecycle events" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_latest_revoke_fails() -> None:
    """Branch d: latest event_type is revoke -> (False, reason).

    Insert an earlier ``issue`` and a LATER ``revoke`` so that
    ``ORDER BY event_at DESC LIMIT 1`` selects the revoke row.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        await conn.execute(
            "INSERT INTO key_lifecycle VALUES (?, ?, ?)",
            ("k-1", "issue", "2026-01-01T00:00:00Z"),
        )
        await conn.execute(
            "INSERT INTO key_lifecycle VALUES (?, ?, ?)",
            ("k-1", "revoke", "2026-02-01T00:00:00Z"),
        )
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": "k-1"}, None
        )
    assert ok is False
    assert "signing key revoked" in diag["reason"]
    assert diag["signing_key_id"] == "k-1"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_latest_issue_after_revoke_passes() -> None:
    """Branch e: latest event is issue (after an earlier revoke) -> (True, {}).

    Confirms it is the LATEST event that matters: an earlier ``revoke``
    superseded by a later ``issue`` must PASS.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        await conn.execute(
            "INSERT INTO key_lifecycle VALUES (?, ?, ?)",
            ("k-1", "revoke", "2026-01-01T00:00:00Z"),
        )
        await conn.execute(
            "INSERT INTO key_lifecycle VALUES (?, ?, ?)",
            ("k-1", "issue", "2026-03-01T00:00:00Z"),
        )
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": "k-1"}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (2) _guard_retention_policy_applied
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_policy_false_fails() -> None:
    """Explicit False -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_policy_applied(
            conn, "evidence", "ev-1", {"retention_policy_applied": False}, None
        )
    assert ok is False
    assert "retention policy not applied" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_policy_absent_passes() -> None:
    """Absent marker -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_policy_applied(
            conn, "evidence", "ev-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_policy_true_passes() -> None:
    """Explicit True (truthy) -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_policy_applied(
            conn, "evidence", "ev-1", {"retention_policy_applied": True}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_policy_string_false_does_not_trip() -> None:
    """Pins ``is False``: the string "false" is not the bool False -> True."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_policy_applied(
            conn,
            "evidence",
            "ev-1",
            {"retention_policy_applied": "false"},
            None,
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (3) _guard_retention_window_elapsed_and_no_legal_hold
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_legal_hold_active_fails() -> None:
    """Branch a: legal_hold_active is True -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn, "evidence", "ev-1", {"legal_hold_active": True}, None
        )
    assert ok is False
    assert "legal hold active" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_window_not_elapsed_fails() -> None:
    """Branch b: retention_window_elapsed is False -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn,
            "evidence",
            "ev-1",
            {"retention_window_elapsed": False},
            None,
        )
    assert ok is False
    assert "window not yet elapsed" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_window_both_signals_absent_passes() -> None:
    """Branch c: both signals absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn, "evidence", "ev-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_window_elapsed_and_no_hold_passes() -> None:
    """Branch c: legal_hold False + window elapsed True -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn,
            "evidence",
            "ev-1",
            {"legal_hold_active": False, "retention_window_elapsed": True},
            None,
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (4) _guard_round_cap_exceeded
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_current_round_absent_passes() -> None:
    """Branch a: current_round absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn, "gate", "g-1", {"remediation_round_cap": 5}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_cap_absent_passes() -> None:
    """Branch a: remediation_round_cap absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn, "gate", "g-1", {"current_round": 3}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_non_integer_fails() -> None:
    """Branch b: non-integer current_round ("x") -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn,
            "gate",
            "g-1",
            {"current_round": "x", "remediation_round_cap": 5},
            None,
        )
    assert ok is False
    assert "not integers" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_below_boundary_not_authorized() -> None:
    """Branch c: cr=4, cap=5 -> 4+1 > 5 is False -> (False, reason).

    Boundary case cr+1 == cap: still NOT exceeded, transition unauthorized.
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn,
            "gate",
            "g-1",
            {"current_round": 4, "remediation_round_cap": 5},
            None,
        )
    assert ok is False
    assert "round cap not exceeded" in diag["reason"]
    assert diag["current_round"] == 4
    assert diag["remediation_round_cap"] == 5


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_at_boundary_exceeded() -> None:
    """Branch d: cr=5, cap=5 -> 5+1 > 5 is True -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn,
            "gate",
            "g-1",
            {"current_round": 5, "remediation_round_cap": 5},
            None,
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_above_boundary_exceeded() -> None:
    """Branch d: cr=6, cap=5 -> 6+1 > 5 is True -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn,
            "gate",
            "g-1",
            {"current_round": 6, "remediation_round_cap": 5},
            None,
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (5) _guard_admin_role_org_owner_or_admin
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_admin_role_absent_passes_lenient() -> None:
    """Branch a: no actor_role -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_admin_role_org_owner_or_admin(
            conn, "gate", "g-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_admin_role_org_owner_passes() -> None:
    """Branch b: actor_role org_owner -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_admin_role_org_owner_or_admin(
            conn, "gate", "g-1", {"actor_role": "org_owner"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_admin_role_org_admin_passes() -> None:
    """Branch b: actor_role org_admin -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_admin_role_org_owner_or_admin(
            conn, "gate", "g-1", {"actor_role": "org_admin"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_admin_role_member_fails() -> None:
    """Branch c: actor_role member -> (False, reason, echoed role)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_admin_role_org_owner_or_admin(
            conn, "gate", "g-1", {"actor_role": "member"}, None
        )
    assert ok is False
    assert "not in {org_owner, org_admin}" in diag["reason"]
    assert diag["actor_role"] == "member"


# ===========================================================================
# Mutation-survivor closers (cosmic-ray fixed-harness residuals).
#
# Each test below pins behavior that a SPECIFIC surviving mutant would flip.
# The existing tests above do not distinguish these mutants because their
# inputs collapse the two operators to the same result; the inputs here are
# chosen at the exact point where real and mutated code diverge.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_signing_key_latest_event_lexically_gt_revoke_passes() -> None:
    """Kill L783 ReplaceComparisonOperator_Eq_GtE.

    guards.py:783 is ``if str(row[0]) == "revoke":``. A latest event_type
    that sorts AFTER "revoke" lexicographically but is NOT "revoke" (here
    "rotate": 'o' > 'e' at index 1) is a non-revocation event, so the real
    guard PASSES. Under ``==`` -> ``>=`` the mutant would treat "rotate"
    (>= "revoke") as a revocation and FAIL. The existing revoke/issue tests
    cannot detect this: "revoke" >= "revoke" and "issue" >= "revoke" both
    agree with ``==`` on their respective rows.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_KEY_LIFECYCLE_DDL)
        await conn.execute(
            "INSERT INTO key_lifecycle VALUES (?, ?, ?)",
            ("k-1", "rotate", "2026-04-01T00:00:00Z"),
        )
        ok, diag = await _guard_signing_key_not_revoked(
            conn, "evidence", "ev-1", {"signing_key_id": "k-1"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_policy_int_zero_does_not_trip_identity() -> None:
    """Kill L802 ReplaceComparisonOperator_Is_Eq.

    guards.py:802 is ``... is False``. The integer 0 satisfies
    ``0 == False`` but NOT ``0 is False``, so the real (identity) guard
    treats 0 as "not the bool False" and PASSES. Under ``is`` -> ``==`` the
    mutant would FAIL with "retention policy not applied". The existing
    string-"false" test cannot detect this (``"false" == False`` is also
    False).
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_policy_applied(
            conn, "evidence", "ev-1", {"retention_policy_applied": 0}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_legal_hold_int_one_does_not_trip_identity() -> None:
    """Kill L820 ReplaceComparisonOperator_Is_Eq.

    guards.py:820 is ``... is True``. The integer 1 satisfies
    ``1 == True`` but NOT ``1 is True``; the real (identity) guard treats 1
    as "not the bool True" and, with retention_window_elapsed absent,
    PASSES. Under ``is`` -> ``==`` the mutant would FAIL with "legal hold
    active".
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn, "evidence", "ev-1", {"legal_hold_active": 1}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_retention_window_int_zero_does_not_trip_identity() -> None:
    """Kill L822 ReplaceComparisonOperator_Is_Eq.

    guards.py:822 is ``... is False``. The integer 0 satisfies
    ``0 == False`` but NOT ``0 is False``; with legal_hold absent the real
    (identity) guard treats 0 as "not the bool False" and PASSES. Under
    ``is`` -> ``==`` the mutant would FAIL with "retention window not yet
    elapsed".
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_retention_window_elapsed_and_no_legal_hold(
            conn, "evidence", "ev-1", {"retention_window_elapsed": 0}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_round_cap_strictly_below_cap_not_authorized() -> None:
    """Kill L882 ReplaceComparisonOperator_Gt_IsNot AND _Gt_NotEq.

    guards.py:882 is ``if cr + 1 > cap:``. With cr=3, cap=10 -> cr+1=4,
    which is STRICTLY LESS than the cap, so the real guard FAILS (the
    transition is not authorized). Both surviving mutants flip this:
    ``4 is not 10`` is True and ``4 != 10`` is True, so each mutant would
    instead authorize (return True). The existing boundary tests (cr+1==cap
    and cr+1>cap) cannot detect either: at equality both ``>`` and the
    mutated forms agree, and strictly above the cap all three agree.
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_round_cap_exceeded(
            conn,
            "gate",
            "g-1",
            {"current_round": 3, "remediation_round_cap": 10},
            None,
        )
    assert ok is False
    assert "round cap not exceeded" in diag["reason"]
    assert diag["current_round"] == 3
    assert diag["remediation_round_cap"] == 10
