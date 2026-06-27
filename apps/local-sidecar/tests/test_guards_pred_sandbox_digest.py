"""Direct-unit mutation-hardening suite for CLUSTER D guard predicates.

The state-engine guard predicates in
``relay_sidecar.state_engine.guards`` are normally exercised only
INDIRECTLY through ``compare_and_set_state`` transitions. That leaves
their internal branches unpinned: mutation testing showed ~78% of
mutants surviving because no test reaches a specific branch and asserts
both its boolean verdict AND its diagnostic payload.

This suite calls the predicates DIRECTLY with an in-memory aiosqlite
connection. Every distinct branch is a separate assertion -- both the
returned ``bool`` (via ``is True`` / ``is False``) and a stable
substring of the diagnostics dict (``reason`` / ``note``) or a key
presence -- so a mutation that flips that branch (e.g. inverts a
comparison, swaps an ``is False`` for ``==``, or deletes a reason
string) is killed.

Covered predicates (CLUSTER D -- replay-sandbox markers + manifest
digest):
  - _guard_fixtures_have_valid_digests
  - _guard_sandbox_provisioned
  - _guard_network_policy_applied
  - _guard_sandbox_exit_observed
  - _guard_manifest_digest_valid

No ``register_guard`` and no ``compare_and_set_state``: these are
direct predicate calls only. ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import aiosqlite
import pytest

from relay_sidecar.state_engine.guards import (
    _guard_fixtures_have_valid_digests,
    _guard_manifest_digest_valid,
    _guard_network_policy_applied,
    _guard_sandbox_exit_observed,
    _guard_sandbox_provisioned,
)

# A digest in the accepted sha256 wire form. The predicates only check the
# ``sha256-`` prefix, not the hex length, so this stable constant is enough.
_VALID_DIGEST = "sha256-" + "a" * 64

_MANIFEST_DDL = "CREATE TABLE manifest_versions (commit_hash TEXT)"


# ---------------------------------------------------------------------------
# (1) _guard_fixtures_have_valid_digests  -- no DB access
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_absent_passes() -> None:
    """Lenient branch: ``fixtures`` absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_empty_list_passes() -> None:
    """Lenient branch: empty list is falsy -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", {"fixtures": []}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_non_list_passes() -> None:
    """Lenient branch: a non-list ``fixtures`` is skipped -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", {"fixtures": "sha256-abc"}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_all_valid_digests_passes() -> None:
    """Happy path: every entry has a sha256 wire-form digest -> (True, {})."""
    payload = {"fixtures": [{"digest": "sha256-abc"}, {"digest": _VALID_DIGEST}]}
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", payload, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_non_dict_entry_fails() -> None:
    """Bad shape: a non-dict entry -> (False, reason + offending index)."""
    payload = {"fixtures": [{"digest": "sha256-ok"}, "sha256-not-a-dict"]}
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", payload, None
        )
    assert ok is False
    assert "missing or malformed digest" in diag["reason"]
    assert diag["indices"] == [1]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_dict_missing_digest_fails() -> None:
    """Bad shape: dict entry without a ``digest`` key -> (False, index 0)."""
    payload = {"fixtures": [{"span_id": "s1"}]}
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", payload, None
        )
    assert ok is False
    assert "missing or malformed digest" in diag["reason"]
    assert diag["indices"] == [0]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_fixtures_wrong_prefix_digest_fails() -> None:
    """Bad shape: digest not in sha256 wire form -> (False, index 0)."""
    payload = {"fixtures": [{"digest": "md5-deadbeef"}]}
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_fixtures_have_valid_digests(
            conn, "replay_case", "rc-1", payload, None
        )
    assert ok is False
    assert "missing or malformed digest" in diag["reason"]
    assert diag["indices"] == [0]


# ---------------------------------------------------------------------------
# (2) _guard_sandbox_provisioned
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_provisioned_false_fails() -> None:
    """Literal ``False`` marker -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_provisioned(
            conn, "replay_case", "rc-1", {"sandbox_provisioned": False}, None
        )
    assert ok is False
    assert "not provisioned" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_provisioned_true_passes() -> None:
    """``True`` marker -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_provisioned(
            conn, "replay_case", "rc-1", {"sandbox_provisioned": True}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_provisioned_absent_passes() -> None:
    """Lenient: marker absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_provisioned(
            conn, "replay_case", "rc-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_provisioned_truthy_string_passes() -> None:
    """Pins the ``is False`` identity check: a string ``"no"`` must NOT fail."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_provisioned(
            conn, "replay_case", "rc-1", {"sandbox_provisioned": "no"}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (3) _guard_network_policy_applied
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_network_policy_false_fails() -> None:
    """Literal ``False`` marker -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_network_policy_applied(
            conn, "replay_case", "rc-1", {"network_policy_applied": False}, None
        )
    assert ok is False
    assert "network policy not applied" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_network_policy_true_passes() -> None:
    """``True`` marker -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_network_policy_applied(
            conn, "replay_case", "rc-1", {"network_policy_applied": True}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_network_policy_absent_passes() -> None:
    """Lenient: marker absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_network_policy_applied(
            conn, "replay_case", "rc-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_network_policy_truthy_string_passes() -> None:
    """Pins the ``is False`` identity check: a string ``"no"`` must NOT fail."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_network_policy_applied(
            conn, "replay_case", "rc-1", {"network_policy_applied": "no"}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (4) _guard_sandbox_exit_observed
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_exit_false_fails() -> None:
    """Literal ``False`` marker -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_exit_observed(
            conn, "replay_case", "rc-1", {"sandbox_exit_observed": False}, None
        )
    assert ok is False
    assert "exit not observed" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_exit_true_passes() -> None:
    """``True`` marker -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_exit_observed(
            conn, "replay_case", "rc-1", {"sandbox_exit_observed": True}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_exit_absent_passes() -> None:
    """Lenient: marker absent -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_exit_observed(
            conn, "replay_case", "rc-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_sandbox_exit_truthy_string_passes() -> None:
    """Pins the ``is False`` identity check: a string ``"no"`` must NOT fail."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_sandbox_exit_observed(
            conn, "replay_case", "rc-1", {"sandbox_exit_observed": "no"}, None
        )
    assert ok is True
    assert diag == {}


# ---------------------------------------------------------------------------
# (5) _guard_manifest_digest_valid
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_no_digest_no_mch_passes() -> None:
    """No payload digest AND no manifest_commit_hash arg -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_manifest_digest_valid(
            conn, "evidence_bundle", "eb-1", {}, None
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_malformed_fails() -> None:
    """Malformed digest (no sha256 prefix) -> (False, wire-form reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_manifest_digest_valid(
            conn, "evidence_bundle", "eb-1", {"manifest_digest": "xx"}, None
        )
    assert ok is False
    assert "sha256-<hex> wire form" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_table_absent_notes() -> None:
    """Valid digest but ``manifest_versions`` table absent -> (True, note)."""
    # Deliberately create NO table so the SELECT raises OperationalError.
    async with aiosqlite.connect(":memory:") as conn:
        ok, diag = await _guard_manifest_digest_valid(
            conn,
            "evidence_bundle",
            "eb-1",
            {"manifest_digest": _VALID_DIGEST},
            None,
        )
    assert ok is True
    assert "table not present" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_registry_empty_notes() -> None:
    """Valid digest, table present but empty -> (True, registry-empty note)."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_MANIFEST_DDL)
        await conn.commit()
        ok, diag = await _guard_manifest_digest_valid(
            conn,
            "evidence_bundle",
            "eb-1",
            {"manifest_digest": _VALID_DIGEST},
            None,
        )
    assert ok is True
    assert "registry empty" in diag["note"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_not_registered_fails() -> None:
    """Valid digest, registry non-empty but digest absent -> (False, reason)."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_MANIFEST_DDL)
        await conn.execute(
            "INSERT INTO manifest_versions (commit_hash) VALUES (?)",
            ("sha256-" + "b" * 64,),
        )
        await conn.commit()
        ok, diag = await _guard_manifest_digest_valid(
            conn,
            "evidence_bundle",
            "eb-1",
            {"manifest_digest": _VALID_DIGEST},
            None,
        )
    assert ok is False
    assert "not registered" in diag["reason"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_match_passes() -> None:
    """Valid digest with a matching registry row -> (True, {})."""
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_MANIFEST_DDL)
        await conn.execute(
            "INSERT INTO manifest_versions (commit_hash) VALUES (?)",
            (_VALID_DIGEST,),
        )
        await conn.commit()
        ok, diag = await _guard_manifest_digest_valid(
            conn,
            "evidence_bundle",
            "eb-1",
            {"manifest_digest": _VALID_DIGEST},
            None,
        )
    assert ok is True
    assert diag == {}


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_digest_falls_back_to_mch_arg() -> None:
    """Payload lacks ``manifest_digest``; digest comes from the mch arg.

    The matching row is registered under the mch value, proving the
    ``payload.get(...) or manifest_commit_hash`` fallback is exercised
    (the match path returns (True, {})).
    """
    async with aiosqlite.connect(":memory:") as conn:
        await conn.execute(_MANIFEST_DDL)
        await conn.execute(
            "INSERT INTO manifest_versions (commit_hash) VALUES (?)",
            (_VALID_DIGEST,),
        )
        await conn.commit()
        ok, diag = await _guard_manifest_digest_valid(
            conn,
            "evidence_bundle",
            "eb-1",
            {},  # no manifest_digest in payload
            _VALID_DIGEST,  # falls back to this manifest_commit_hash arg
        )
    assert ok is True
    assert diag == {}
