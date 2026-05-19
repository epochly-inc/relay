"""V3 M5 F10 §F.6 manifest -> tool_side_effect_policies binding guard.

Fulfills VAL-V3M5-020.

Spec anchors:
  F.6 4007-4103   manifest is source of truth; every declared command,
                  validation surface, side_effect_tool, and mutation
                  boundary must resolve to a control-plane record.
  X.5119-5133     tool_side_effect_policies is the canonical registry of
                  side-effecting tools (policy_id, project_id, tool_name,
                  side_effect_class, ...).
  CLAUDE.md keystone invariant #3: manifest is the source of truth; ports,
  commands, side-effect tools are declared, not discovered.

This guard test asserts the cross-table referential integrity that the
spec requires but that SQLite's CHECK constraint mechanism cannot express
on its own: for every CURRENTLY-ACTIVE (or in-grace) manifest_versions
row, every tool name listed under the manifest's
``body.side_effect_tools[]`` aggregate AND every per-command
``commands[*].side_effect_tools[]`` array MUST resolve to at least one
ACTIVE row in ``tool_side_effect_policies`` whose ``project_id`` matches
the manifest's project_id AND whose ``tool_name`` equals the declared
string. An orphaned manifest entry (declared in the manifest but with
no matching policy row) is a §F.6 invariant violation and the guard
reports the offenders.

The guard is implemented inline in this test module (not as a sidecar
runtime path) per VAL-V3M5-020 scope: a TEST that fails when the
invariant is breached. The contract-state machine that consumes a
manifest at submit/publish time enforces this transitively via
``manifest_versions`` writes flowing through the four atomic primitives;
this guard provides an at-rest assertion that catches drift introduced
by direct DB manipulation, migrations, or seed scripts.

Active manifest definition (mirrors
``relay_sidecar/state_engine/handoff.py::_manifest_is_active_or_in_grace``):

  active = effective_until IS NULL
           OR datetime(now()) <= datetime(effective_until, '+'
                                           || grace_window_seconds
                                           || ' seconds')

Active policy definition (mirrors §X.5126-5131 + the OSS local profile
table at apps/local-sidecar/migrations/0018_side_effects.sql):

  active = effective_until IS NULL
           OR datetime(now()) <= datetime(effective_until)

The manifest's ``body`` is stored as JSON-as-TEXT in
``manifest_versions.body`` (added by sidecar migration 0023). The guard
parses it with the stdlib ``json`` module; a body that fails to parse is
itself an integrity failure and contributes an offender entry.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import pytest

_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[3]
_MIGRATIONS_DIR = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _ts(dt: datetime) -> str:
    """RFC 3339 UTC string with the canonical ``Z`` suffix used elsewhere."""
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha256_placeholder(seed: str) -> str:
    """Produce a wire-shape sha256-<64 hex> string from a seed.

    The manifest_versions CHECK constraint requires ``sha256-`` prefix; we
    do not need cryptographic strength here -- the guard is shape-only.
    """
    import hashlib

    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"sha256-{digest}"


# ---------------------------------------------------------------------------
# DB setup: apply every sidecar migration in lex order to an aiosqlite
# in-memory connection so the schema exactly matches a real sidecar boot.
# ---------------------------------------------------------------------------


async def _make_db_with_all_migrations() -> aiosqlite.Connection:
    """Apply every .sql under apps/local-sidecar/migrations/ in lex order.

    Mirrors ``SidecarDatabase._run_migrations`` (db.py:580) but for an
    in-memory aiosqlite handle so the test is hermetic. PRAGMA
    foreign_keys is ON to match production sidecar opener semantics.
    """
    conn = await aiosqlite.connect(":memory:")
    await conn.execute("PRAGMA foreign_keys = ON")
    for sql_file in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        sql_text = sql_file.read_text(encoding="utf-8")
        await conn.executescript(sql_text)
    await conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Seed helpers (test-only direct INSERTs; the guard is read-only).
# ---------------------------------------------------------------------------


async def _seed_manifest(
    conn: aiosqlite.Connection,
    *,
    project_id: str,
    body: dict,
    effective_at: datetime | None = None,
    effective_until: datetime | None = None,
    grace_window_seconds: int = 86400,
) -> str:
    """Insert one manifest_versions row; return its commit_hash."""
    mv_id = str(uuid.uuid4())
    manifest_id = str(uuid.uuid4())
    commit_hash = _sha256_placeholder(mv_id)
    eff_at = _ts(effective_at or _now())
    eff_until = _ts(effective_until) if effective_until is not None else None
    await conn.execute(
        "INSERT INTO manifest_versions ("
        " manifest_version_id, manifest_id, project_id, commit_hash,"
        " effective_at, effective_until, grace_window_seconds, body"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            mv_id,
            manifest_id,
            project_id,
            commit_hash,
            eff_at,
            eff_until,
            grace_window_seconds,
            json.dumps(body, sort_keys=True, separators=(",", ":")),
        ),
    )
    await conn.commit()
    return commit_hash


async def _seed_policy(
    conn: aiosqlite.Connection,
    *,
    project_id: str,
    tool_name: str,
    side_effect_class: str = "mutating",
    effective_at: datetime | None = None,
    effective_until: datetime | None = None,
) -> str:
    """Insert one tool_side_effect_policies row; return policy_id."""
    pid = str(uuid.uuid4())
    await conn.execute(
        "INSERT INTO tool_side_effect_policies ("
        " policy_id, project_id, tool_name, side_effect_class,"
        " effective_at, effective_until"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (
            pid,
            project_id,
            tool_name,
            side_effect_class,
            _ts(effective_at or _now()),
            _ts(effective_until) if effective_until is not None else None,
        ),
    )
    await conn.commit()
    return pid


# ---------------------------------------------------------------------------
# Guard implementation (the unit-under-test for this assertion).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Offender:
    """One manifest-declared tool with no resolving active policy.

    Attributes:
        project_id: manifest_versions.project_id.
        commit_hash: manifest_versions.commit_hash.
        tool_name: the orphan side-effect tool declared in the manifest.
        location: where in the manifest body the tool was declared --
            ``"manifest"`` for the top-level ``side_effect_tools`` array,
            ``"command:<command_id>"`` for a per-command array, or
            ``"body_parse_error"`` for a manifest with unparseable body.
    """

    project_id: str
    commit_hash: str
    tool_name: str
    location: str


def _extract_declared_tools(body: dict) -> set[tuple[str, str]]:
    """Walk a manifest body, returning ``(location, tool_name)`` pairs.

    Per spec F (manifest.v1.schema.json keys 184 + 275):
      * ``side_effect_tools`` at the top level is the aggregated list.
      * ``commands[*].side_effect_tools`` is the per-command list.
    The guard treats both as load-bearing -- a per-command declaration
    that lacks a matching policy is just as invalid as a top-level one.
    Non-string entries are skipped (a schema validator would have caught
    those earlier; the guard is concerned with referential integrity,
    not schema shape).
    """
    pairs: set[tuple[str, str]] = set()
    top = body.get("side_effect_tools") or []
    if isinstance(top, list):
        for t in top:
            if isinstance(t, str) and t:
                pairs.add(("manifest", t))
    cmds = body.get("commands") or []
    if isinstance(cmds, list):
        for cmd in cmds:
            if not isinstance(cmd, dict):
                continue
            cmd_id = cmd.get("id") or cmd.get("name") or "<unknown>"
            local = cmd.get("side_effect_tools") or []
            if not isinstance(local, list):
                continue
            for t in local:
                if isinstance(t, str) and t:
                    pairs.add((f"command:{cmd_id}", t))
    return pairs


async def find_manifest_side_effect_binding_offenders(
    conn: aiosqlite.Connection,
    *,
    at: datetime | None = None,
) -> list[Offender]:
    """Return offenders -- empty list iff the §F.6 invariant holds.

    For every manifest_versions row that is ACTIVE-or-in-grace at ``at``,
    for every tool name declared in its body's ``side_effect_tools[]``
    (top-level OR per-command), verify that at least one row exists in
    ``tool_side_effect_policies`` whose ``project_id`` matches AND
    ``tool_name`` matches AND the policy itself is active-or-in-future at
    ``at``. Tools without a matching policy contribute Offender entries.
    """
    now_dt = at or _now()
    now_iso = _ts(now_dt)

    # 1. Pull every active-or-in-grace manifest.
    #    A row is active when effective_until IS NULL.
    #    A row is in-grace when effective_until + grace_window_seconds >= now.
    rows = await (
        await conn.execute(
            "SELECT project_id, commit_hash, effective_until,"
            "       grace_window_seconds, body "
            "FROM manifest_versions "
            "WHERE effective_until IS NULL "
            "   OR datetime(effective_until, '+' "
            "               || grace_window_seconds || ' seconds') >= ?",
            (now_iso,),
        )
    ).fetchall()

    offenders: list[Offender] = []
    for project_id, commit_hash, _eff_until, _grace, body_text in rows:
        try:
            body = json.loads(body_text) if body_text else {}
        except (json.JSONDecodeError, TypeError):
            offenders.append(
                Offender(
                    project_id=project_id,
                    commit_hash=commit_hash,
                    tool_name="<unparseable_body>",
                    location="body_parse_error",
                )
            )
            continue
        if not isinstance(body, dict):
            offenders.append(
                Offender(
                    project_id=project_id,
                    commit_hash=commit_hash,
                    tool_name="<non_object_body>",
                    location="body_parse_error",
                )
            )
            continue

        declared = _extract_declared_tools(body)
        if not declared:
            continue

        # 2. For each declared (location, tool_name), check policy presence.
        for location, tool_name in sorted(declared):
            policy_row = await (
                await conn.execute(
                    "SELECT 1 FROM tool_side_effect_policies "
                    "WHERE project_id = ? "
                    "  AND tool_name = ? "
                    "  AND (effective_until IS NULL "
                    "       OR datetime(effective_until) >= ?) "
                    "LIMIT 1",
                    (project_id, tool_name, now_iso),
                )
            ).fetchone()
            if policy_row is None:
                offenders.append(
                    Offender(
                        project_id=project_id,
                        commit_hash=commit_hash,
                        tool_name=tool_name,
                        location=location,
                    )
                )
    return offenders


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_extractor_pulls_top_level_and_per_command_tools() -> None:
    """The extractor is part of the guard contract: both surfaces count.

    Spec F.6 manifest.v1.schema.json keys 184 (top-level) and 275
    (per-command) are both load-bearing.
    """
    body = {
        "side_effect_tools": ["create_case_note", "post_invoice"],
        "commands": [
            {
                "id": "publish",
                "side_effect_tools": ["send_email"],
            },
            {
                "name": "purge",
                "side_effect_tools": ["delete_record", "create_case_note"],
            },
            {"id": "noop"},
        ],
    }
    pairs = _extract_declared_tools(body)
    assert ("manifest", "create_case_note") in pairs
    assert ("manifest", "post_invoice") in pairs
    assert ("command:publish", "send_email") in pairs
    assert ("command:purge", "delete_record") in pairs
    assert ("command:purge", "create_case_note") in pairs
    # noop has no side_effect_tools -- it must not appear.
    assert not any(loc == "command:noop" for loc, _ in pairs)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_passes_when_every_declared_tool_has_active_policy() -> None:
    """Happy path: declared tools all resolve -> guard returns []."""
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        # Seed two policies (top-level + per-command coverage).
        await _seed_policy(conn, project_id=project_id, tool_name="create_case_note")
        await _seed_policy(conn, project_id=project_id, tool_name="send_email")
        # Seed an active manifest declaring exactly those two tools.
        await _seed_manifest(
            conn,
            project_id=project_id,
            body={
                "side_effect_tools": ["create_case_note"],
                "commands": [
                    {"id": "publish", "side_effect_tools": ["send_email"]},
                ],
            },
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert offenders == [], (
            f"Guard reported offenders on a clean manifest: {offenders!r}"
        )
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_fails_when_manifest_declares_unbound_tool() -> None:
    """Orphan path: a declared tool with no matching policy is reported.

    This is the load-bearing assertion for VAL-V3M5-020 -- the guard
    MUST detect the §F.6 violation when a manifest entry has no
    resolving policy row.
    """
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        # Seed ONE policy but the manifest will declare TWO tools --
        # the second is the offender.
        await _seed_policy(conn, project_id=project_id, tool_name="create_case_note")
        commit_hash = await _seed_manifest(
            conn,
            project_id=project_id,
            body={
                "side_effect_tools": ["create_case_note", "ghost_tool"],
            },
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert len(offenders) == 1, (
            f"Expected exactly one offender; got {offenders!r}"
        )
        off = offenders[0]
        assert off.project_id == project_id
        assert off.commit_hash == commit_hash
        assert off.tool_name == "ghost_tool"
        assert off.location == "manifest"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_fails_when_per_command_tool_is_unbound() -> None:
    """The per-command array (commands[*].side_effect_tools) is also enforced.

    Spec manifest.v1.schema.json key 184 is just as load-bearing as
    the top-level aggregate at key 275.
    """
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        # Top-level is clean; per-command has the offender.
        await _seed_policy(conn, project_id=project_id, tool_name="create_case_note")
        await _seed_manifest(
            conn,
            project_id=project_id,
            body={
                "side_effect_tools": ["create_case_note"],
                "commands": [
                    {
                        "id": "purge",
                        "side_effect_tools": ["delete_record"],
                    },
                ],
            },
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert len(offenders) == 1, offenders
        off = offenders[0]
        assert off.tool_name == "delete_record"
        assert off.location == "command:purge"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_rejects_policy_scoped_to_a_different_project() -> None:
    """Tenant scoping is load-bearing: a same-named policy in a different
    project does NOT satisfy the binding requirement (§A.9 +
    VAL-V3M3-001 cross-project scope rule)."""
    conn = await _make_db_with_all_migrations()
    try:
        project_a = str(uuid.uuid4())
        project_b = str(uuid.uuid4())
        # Policy lives under project A; manifest under project B references it.
        await _seed_policy(conn, project_id=project_a, tool_name="create_case_note")
        await _seed_manifest(
            conn,
            project_id=project_b,
            body={"side_effect_tools": ["create_case_note"]},
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert len(offenders) == 1, offenders
        assert offenders[0].project_id == project_b
        assert offenders[0].tool_name == "create_case_note"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_ignores_rotated_out_manifests() -> None:
    """Only active-or-in-grace manifests are checked.

    A manifest whose ``effective_until + grace_window_seconds`` has
    elapsed is no longer a source of truth -- it CANNOT cause a worker
    to execute. Including it in the guard would surface stale errors.
    """
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        long_ago = _now() - timedelta(days=30)
        # Effective window ended 30 days ago; default grace_window is 1 day.
        await _seed_manifest(
            conn,
            project_id=project_id,
            body={"side_effect_tools": ["ghost_tool"]},
            effective_at=long_ago - timedelta(days=1),
            effective_until=long_ago,
            grace_window_seconds=86400,
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert offenders == [], (
            f"Guard should ignore expired manifests; got {offenders!r}"
        )
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_treats_expired_policy_as_orphan() -> None:
    """An expired policy does not satisfy an active manifest's binding.

    A policy whose ``effective_until`` is in the past is no longer
    "active" -- the manifest entry pointing at it is effectively orphaned
    even though a row exists.
    """
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        long_ago = _now() - timedelta(days=30)
        # Expired policy: effective_until well in the past.
        await _seed_policy(
            conn,
            project_id=project_id,
            tool_name="create_case_note",
            effective_at=long_ago - timedelta(days=1),
            effective_until=long_ago,
        )
        await _seed_manifest(
            conn,
            project_id=project_id,
            body={"side_effect_tools": ["create_case_note"]},
        )

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert len(offenders) == 1, offenders
        assert offenders[0].tool_name == "create_case_note"
    finally:
        await conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-020")
@pytest.mark.asyncio
async def test_guard_reports_unparseable_body_as_offender() -> None:
    """A manifest_versions row with a non-JSON body is itself an integrity
    failure -- the guard surfaces it so the operator can investigate.

    NOTE: We must bypass the test-helper here because it always emits
    valid JSON. Insert directly with a deliberately malformed body.
    """
    conn = await _make_db_with_all_migrations()
    try:
        project_id = str(uuid.uuid4())
        mv_id = str(uuid.uuid4())
        commit_hash = _sha256_placeholder(mv_id)
        await conn.execute(
            "INSERT INTO manifest_versions ("
            " manifest_version_id, manifest_id, project_id, commit_hash,"
            " effective_at, effective_until, grace_window_seconds, body"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                mv_id,
                str(uuid.uuid4()),
                project_id,
                commit_hash,
                _ts(_now()),
                None,
                86400,
                "this-is-not-json",
            ),
        )
        await conn.commit()

        offenders = await find_manifest_side_effect_binding_offenders(conn)
        assert len(offenders) == 1, offenders
        assert offenders[0].location == "body_parse_error"
        assert offenders[0].commit_hash == commit_hash
    finally:
        await conn.close()
