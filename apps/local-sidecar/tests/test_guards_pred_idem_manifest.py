"""Direct-unit mutation-hardening suite for state-engine guard predicates.

CLUSTER A -- idempotency + manifest-commit-hash (DB-heavy).

The 23 guard predicates in ``relay_sidecar.state_engine.guards`` are PURE
async functions exercised only INDIRECTLY through
``compare_and_set_state`` transitions. That indirection leaves their
internal branches unpinned: a mutation testing pass showed ~78% survival
because no test calls a predicate directly and asserts the specific branch
it took.

This suite imports the assigned predicates and CALLS THEM DIRECTLY with an
in-memory ``aiosqlite`` connection. Every documented branch gets its own
test that asserts BOTH the returned bool AND a distinguishing key in the
returned diagnostics dict, so a mutation that flips that branch (negates a
condition, drops a clause of an ``and``/``or``, swaps a return value, or
rewrites a diagnostic) is killed by at least one assertion.

Predicates under test (guards.py):
  - ``_guard_valid_idempotency_key``          (run.pending -> run.captured)
  - ``_guard_valid_manifest_commit_hash``     (run.pending -> run.captured)

No ``register_guard`` and no ``compare_and_set_state``: direct predicate
calls only, with the minimal DDL each guard SELECTs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import aiosqlite
import pytest
import relay_sidecar.state_engine.guards as guards_module
from relay_sidecar.state_engine.guards import (
    _guard_valid_idempotency_key,
    _guard_valid_manifest_commit_hash,
)

# --- Minimal DDL (only the columns each guard SELECTs) ----------------------

_DDL_IDEMPOTENCY = (
    "CREATE TABLE idempotency_records "
    "(idempotency_key TEXT, request_digest TEXT, response_status INTEGER)"
)
_DDL_SCOPE_STATE = (
    "CREATE TABLE scope_state "
    "(scope_kind TEXT, scope_id TEXT, project_id TEXT)"
)
_DDL_MANIFEST_VERSIONS = (
    "CREATE TABLE manifest_versions "
    "(project_id TEXT, commit_hash TEXT, effective_until TEXT, "
    "grace_window_seconds INTEGER)"
)

_SCOPE_KIND = "run"
_SCOPE_ID = "run-1"


# ===========================================================================
# (1) _guard_valid_idempotency_key  (guards.py ~L143-199)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_a_explicit_invalid_marker() -> None:
    """Branch a: explicit ``idempotency_key_invalid: True`` -> hard fail."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key_invalid": True},
            None,
        )
    assert ok is False
    assert "explicit invalid marker" in diag["reason"]
    assert diag["field"] == "idempotency_key_invalid"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_b_missing_key() -> None:
    """Branch b: no idempotency_key in payload -> lenient pass (no DB touch)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_b_empty_string_key() -> None:
    """Branch b: empty-string key -> ``not key`` arm of the or -> pass."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {"idempotency_key": ""}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_b_nonstr_key() -> None:
    """Branch b: non-str key (int) -> ``not isinstance`` arm -> pass."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {"idempotency_key": 123}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_c_table_absent() -> None:
    """Branch c: key present but no idempotency_records table -> OperationalError pass."""
    async with aiosqlite.connect(":memory:") as conn:
        # Deliberately do NOT create idempotency_records.
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {"idempotency_key": "k1"}, None
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_d_no_matching_row() -> None:
    """Branch d: table exists, no row for the key -> lenient pass."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        # A row under a DIFFERENT key must not match.
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("other", "sha256-aaa", 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {"idempotency_key": "k1"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_e_reuse_mismatch() -> None:
    """Branch e: matching row with stored digest != payload request_hash -> fail."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("k1", "sha256-aaa", 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key": "k1", "request_hash": "sha256-bbb"},
            None,
        )
    assert ok is False
    assert "reuse with different request_digest" in diag["reason"]
    assert diag["idempotency_key"] == "k1"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_f_matching_digest_equal() -> None:
    """Branch f: matching row with stored digest == payload request_hash -> pass."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("k1", "sha256-aaa", 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key": "k1", "request_hash": "sha256-aaa"},
            None,
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_g1_no_request_hash() -> None:
    """Branch g: matching row but payload omits request_hash (expected None) -> pass.

    Pins the ``expected_request_hash is not None`` clause of the mismatch
    guard: a stored digest exists but no expected value is supplied.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("k1", "sha256-aaa", 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn, _SCOPE_KIND, _SCOPE_ID, {"idempotency_key": "k1"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_g2_stored_digest_null() -> None:
    """Branch g: matching row with NULL request_digest -> pass.

    Pins the ``stored_request_digest is not None`` clause: an expected hash
    is supplied but the stored digest column is NULL, so no mismatch.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("k1", None, 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key": "k1", "request_hash": "sha256-bbb"},
            None,
        )
    assert ok is True
    assert diag == {}


# ===========================================================================
# (2) _guard_valid_manifest_commit_hash  (guards.py ~L202-319)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_a_none_arg() -> None:
    """Branch a: no manifest_commit_hash claimed -> lenient pass."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_b_non_canonical_prefix() -> None:
    """Branch b: hash without sha256- prefix -> hard fail on wire form."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "deadbeef"
        )
    assert ok is False
    assert "canonical sha256-" in diag["reason"]
    assert diag["field"] == "manifest_commit_hash"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_c_versions_table_absent() -> None:
    """Branch c: scope_state resolves project_id but manifest_versions absent -> pass."""
    async with aiosqlite.connect(":memory:") as conn:
        # Create scope_state ONLY; manifest_versions deliberately absent.
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_d_registry_empty() -> None:
    """Branch d: project resolved, no rows, total count 0 -> legacy-bootstrap pass."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert "registry empty" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_e_cross_project() -> None:
    """Branch e: hash exists only under another project -> per-project mismatch fail."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        # Same hash, but registered for projB only.
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projB", "sha256-xyz", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-xyz"
        )
    assert ok is False
    assert "different project" in diag["reason"]
    assert diag["project_id"] == "projA"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_f_not_in_registry() -> None:
    """Branch f: registry non-empty for the project but hash absent everywhere -> fail."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        # A different hash exists for the SAME project; the queried hash does not.
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-other", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-missing"
        )
    assert ok is False
    assert "not in registry" in diag["reason"]
    assert diag["field"] == "manifest_commit_hash"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_g_effective_until_null() -> None:
    """Branch g: matching active row with NULL effective_until -> pass."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_h_future_within_grace() -> None:
    """Branch h: effective_until far in the FUTURE (Z form), grace 0 -> pass.

    Exercises the trailing-Z -> +00:00 normalization.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", "2999-01-01T00:00:00Z", 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_i_expired_beyond_grace() -> None:
    """Branch i: effective_until far in the PAST (Z form), grace 0 -> expired fail."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", "2000-01-01T00:00:00Z", 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is False
    assert "expired beyond grace" in diag["reason"]
    assert diag["field"] == "manifest_commit_hash"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_j_no_scope_state_commit_only() -> None:
    """Branch j: scope_state table absent -> project_id None -> commit-only lookup.

    The scope_state SELECT raises OperationalError (table not created), so
    project_id resolves to None and the guard falls back to the
    commit_hash-only manifest_versions lookup. A matching active row -> pass.
    """
    async with aiosqlite.connect(":memory:") as conn:
        # Create manifest_versions ONLY; scope_state deliberately absent.
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projWhatever", "sha256-abc", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


# ===========================================================================
# (3) Residual-mutant hardening (cosmic-ray survivors)
#
# Each test below pins a specific guard branch against a specific surviving
# mutation that no prior test in this file detects. The mutant operator and
# source line are named in the docstring so a future reader can trace it.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_a_identity_int_one_not_true() -> None:
    """Kill L160 ReplaceComparisonOperator_Is_Eq (``... is True`` -> ``== True``).

    The marker check uses *identity* on purpose. Integer ``1`` satisfies
    ``1 == True`` but NOT ``1 is True``. With ``idempotency_key_invalid: 1``
    the real guard takes the identity path (does NOT fail), no key is
    supplied, so it returns ``(True, {})``. Under the ``== True`` mutation it
    would hard-fail with the explicit-invalid-marker diagnostic.
    """
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key_invalid": 1},
            None,
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_idem_e_reuse_stored_greater_than_expected() -> None:
    """Kill L193 ReplaceComparisonOperator_NotEq_Lt (``!=`` -> ``<``).

    ``!=`` and ``<`` agree when stored < expected (which the existing
    ``test_idem_e_reuse_mismatch`` covers) but DIVERGE when stored > expected:
    ``!=`` is still True (mismatch -> fail) while ``<`` is False (would pass).
    Stored ``sha256-bbb`` > expected ``sha256-aaa`` lexicographically, so the
    real guard FAILS on reuse; the ``<`` mutation would PASS.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_IDEMPOTENCY)
        await conn.execute(
            "INSERT INTO idempotency_records VALUES (?, ?, ?)",
            ("k1", "sha256-bbb", 200),
        )
        await conn.commit()
        ok, diag = await _guard_valid_idempotency_key(
            conn,
            _SCOPE_KIND,
            _SCOPE_ID,
            {"idempotency_key": "k1", "request_hash": "sha256-aaa"},
            None,
        )
    assert ok is False
    assert "reuse with different request_digest" in diag["reason"]
    assert diag["idempotency_key"] == "k1"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_and_with_or_empty_project_id() -> None:
    """Kill L243 ReplaceAndWithOr x2 (both ``and`` -> ``or``).

    scope_state stores an EMPTY-STRING project_id. The real predicate
    ``row is not None and isinstance(row[0], str) and row[0]`` is falsy
    (``row[0] == ''`` fails the truthiness clause), so project_id stays None
    and the guard takes the commit-only lookup -> the row registered under
    ``realproj`` matches -> active (NULL effective_until) -> ``(True, {})``.

    Either ``and`` -> ``or`` mutation makes the expression truthy, assigning
    ``project_id = ''`` -> the project-scoped lookup finds nothing -> the
    cross-project arm fires -> ``(False, ...)``. So the real PASS distinguishes
    both mutants.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, ""),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("realproj", "sha256-abc", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_aware_non_z_future_passes() -> None:
    """Kill L307 AddNot (``if text.endswith("Z")`` -> ``if not ...``).

    With an AWARE, non-Z future timestamp (``...+00:00``) the real guard
    SKIPS the trailing-Z normalization, parses cleanly, and passes.
    The ``not`` mutation instead truncates the last char and appends
    ``+00:00`` (``...+00:0+00:00``), which fails ``fromisoformat`` with a
    ValueError -> the row is skipped -> ``(False, expired)``.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", "2999-01-01T00:00:00+00:00", 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_naive_future_tz_normalized() -> None:
    """Kill L310 AddNot AND L310 ReplaceComparisonOperator_Is_IsNot.

    A NAIVE future timestamp (no offset) parses to a tz-naive datetime. The
    real guard's ``if effective_until.tzinfo is None`` is True, so it stamps
    UTC and the aware<=aware comparison succeeds -> ``(True, {})``.

    Both the ``not (... is None)`` (AddNot) and the ``... is not None``
    (Is_IsNot) mutations SKIP the UTC stamp, leaving a naive datetime. The
    later ``now(aware) <= naive + timedelta`` comparison then raises
    TypeError (can't compare aware and naive) -> guard raises, distinguishing
    the real PASS.
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", "2999-01-01T00:00:00", 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_single_malformed_row_is_caught_not_raised() -> None:
    """Kill L312 ExceptionReplacer -- DETERMINISTICALLY, order-independently.

    ONE row whose ``effective_until`` is unparseable (``fromisoformat`` raises
    ValueError). The real guard catches the ValueError, ``continue``s past the
    only row, the loop ends, and it returns ``(False, "expired beyond grace
    window")``.

    L312 ExceptionReplacer rewrites ``except ValueError`` to
    ``except CosmicRayTestingException`` (which does NOT catch ValueError), so
    the ValueError propagates and the guard RAISES instead of returning a
    verdict. A single row makes this kill independent of row order. L313
    ``continue`` -> ``break`` is INDISTINGUISHABLE here (one row: both exit the
    loop to the same ``return``); it is killed separately and deterministically
    by ``test_manifest_malformed_before_active_continues_to_pass`` (two rows,
    explicit rowids + the guard's ``ORDER BY rowid``).
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", "not-a-valid-date", 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is False
    assert "expired beyond grace window" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_malformed_before_active_continues_to_pass() -> None:
    """Kill L313 ReplaceContinueWithBreak -- DETERMINISTICALLY.

    Two rows for the same (project, hash): rowid 1 has a malformed
    ``effective_until`` (``fromisoformat`` raises ValueError), rowid 2 is active
    (NULL effective_until). The real guard catches the ValueError, ``continue``s
    past the malformed row, reaches the active row, and returns ``(True, {})``.
    The ``continue`` -> ``break`` mutant exits at the malformed row and returns
    ``(False, expired)`` -- so the mutant VIOLATES the guard's contract (returns
    expired while an active row exists). That is a real, non-equivalent mutant.

    Determinism: the guard's manifest_versions query is ``ORDER BY rowid`` (added
    for deterministic, auditable control-plane evaluation), so visitation order is
    part of the QUERY CONTRACT, not the planner's discretion. Explicit ascending
    rowids therefore pin rowid 1 (malformed) strictly before rowid 2 (active),
    independent of SQLite version/planner/settings. Verified empirically: 10/10
    runs visit malformed-first and real(continue)=True vs mutant(break)=False.
    (roborev 3b33ebc: the prior scan-order reliance is replaced by an explicit
    ORDER BY; this is a
    deterministic kill, not an equivalence -- the earlier equivalent claim was
    withdrawn.)
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions"
            "(rowid, project_id, commit_hash, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?)",
            (1, "projA", "sha256-abc", "not-a-valid-date", 0),
        )
        await conn.execute(
            "INSERT INTO manifest_versions"
            "(rowid, project_id, commit_hash, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?)",
            (2, "projA", "sha256-abc", None, 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_within_grace_window_past() -> None:
    """Kill L314 ReplaceBinaryOperator_Add_Sub (``eu + grace`` -> ``eu - grace``).

    effective_until is 100s in the PAST with a 3600s grace window, so the
    real ``now <= effective_until + grace`` is ``now <= now+3500`` -> True
    (within grace) -> ``(True, {})``. The ``-`` mutation computes
    ``now <= now-3700`` -> False -> ``(False, expired)``. The ~3500s margin
    swamps any test-execution jitter.
    """
    now = datetime.now(UTC)
    effective_until = (now - timedelta(seconds=100)).isoformat()
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", effective_until, 3600),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}


_FROZEN_NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


class _FrozenDateTime(datetime):
    """``datetime`` subclass whose ``now()`` is frozen for boundary tests."""

    @classmethod
    def now(cls, tz=None):  # noqa: ARG003 - signature parity with datetime.now
        return _FROZEN_NOW


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_grace_boundary_equality(monkeypatch) -> None:
    """Kill L314 ReplaceComparisonOperator_LtE_Lt (``<=`` -> ``<``).

    ``<=`` and ``<`` only diverge at exact equality, which is unreachable
    against a live wall clock. We freeze ``datetime.now`` to a fixed instant
    and set effective_until to that SAME instant with a 0s grace window, so
    ``now <= effective_until + 0`` is an equality. The real ``<=`` passes;
    the ``<`` mutation fails (expired).
    """
    monkeypatch.setattr(guards_module, "datetime", _FrozenDateTime)
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_DDL_SCOPE_STATE)
        await conn.execute(_DDL_MANIFEST_VERSIONS)
        await conn.execute(
            "INSERT INTO scope_state VALUES (?, ?, ?)",
            (_SCOPE_KIND, _SCOPE_ID, "projA"),
        )
        await conn.execute(
            "INSERT INTO manifest_versions VALUES (?, ?, ?, ?)",
            ("projA", "sha256-abc", _FROZEN_NOW.isoformat(), 0),
        )
        await conn.commit()
        ok, diag = await _guard_valid_manifest_commit_hash(
            conn, _SCOPE_KIND, _SCOPE_ID, {}, "sha256-abc"
        )
    assert ok is True
    assert diag == {}
