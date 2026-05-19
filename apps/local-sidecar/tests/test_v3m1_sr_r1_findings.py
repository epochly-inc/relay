"""Structural-review M1 round-1 P1 finding regression guards.

Two fixes, two regression tests:

SR-M1-001 -- paired-row trigger lost on table rebuild.
    Migration ``apps/local-sidecar/migrations/0029_v3_schema_drift_fixes.sql``
    rebuilds the ``gate_rounds`` table via the SQLite CREATE-COPY-DROP-RENAME
    idiom. SQLite drops every trigger attached to a table when the table is
    dropped, so the ``gate_rounds_scope_state_paired_check`` BEFORE INSERT
    trigger defined in
    ``apps/local-sidecar/migrations/0016_scope_state_extension.sql`` lines
    168-178 was silently lost. Spec section W (line 5112) requires the paired
    ``scope_state`` row to be DB-enforced on every scope-creating INSERT.

    Regression: apply every sidecar migration in order against a fresh
    SQLite database and assert ``sqlite_master`` lists the
    ``gate_rounds_scope_state_paired_check`` trigger on ``gate_rounds``.

SR-M1-002 -- runtime.py:3880 enum violation.
    The HTTP ``POST /v1/gate-drafts`` handler at
    ``apps/local-sidecar/relay_sidecar/runtime.py`` line 3880 appended a
    ``GateRound``-shaped record with ``initiated_by='submission'``. The
    canonical envelope at
    ``packages/schemas/python/relay_schemas/envelopes.py`` line 381 Literal-
    pins ``initiated_by`` to the 4-value spec enum
    ``{control_plane, cron, user, remediation}``. ``'submission'`` is NOT in
    the enum and would fail Pydantic validation. The
    ``apps/local-sidecar/migrations/0029_v3_schema_drift_fixes.sql`` data
    migration maps ``'submission' -> 'control_plane'``; the runtime must
    emit the spec-aligned value at construction time so canonical envelope
    validation succeeds.

    Regression: read the literal ``initiated_by`` argument used at
    runtime.py:3880 (via source inspection so the test stays loosely
    coupled to surrounding payload fields), then construct a minimum-valid
    ``GateRound`` envelope using that literal and call
    ``GateRound.model_validate(...)``. The model_validate call MUST succeed
    after the fix and would have raised ``pydantic.ValidationError`` with
    the pre-fix ``'submission'`` value.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path

import aiosqlite
import pytest
from relay_schemas.envelopes import GateRound

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[1] / "migrations"
)
RUNTIME_PATH = (
    Path(__file__).resolve().parents[1]
    / "relay_sidecar"
    / "runtime.py"
)


async def _apply_all_migrations(db_path: Path) -> None:
    """Apply every sidecar migration in filename-sorted order with the
    same ``__schema_migrations`` tracker the FastAPI lifespan uses.
    Mirrors the helper in ``tests/test_scope_state_per_kind.py``.
    """

    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        for sql in sorted(MIGRATIONS_DIR.glob("*.sql")):
            filename = sql.name
            async with conn.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                if await cur.fetchone() is not None:
                    continue
            await conn.executescript(sql.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO __schema_migrations (filename) VALUES (?)",
                (filename,),
            )
        await conn.commit()


# ---------------------------------------------------------------------------
# SR-M1-001: paired-row trigger must survive the 0029 table rebuild.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_gate_rounds_paired_check_trigger_survives_rebuild(
    tmp_path: Path,
) -> None:
    """After all sidecar migrations apply, the
    ``gate_rounds_scope_state_paired_check`` BEFORE INSERT trigger on
    ``gate_rounds`` must exist. 0029 rebuilds the table; without
    explicit re-creation the trigger is silently lost.
    """

    db_path = tmp_path / "sidecar.db"
    await _apply_all_migrations(db_path)
    async with (
        aiosqlite.connect(str(db_path)) as conn,
        conn.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master "
            "WHERE type = 'trigger' "
            "  AND name = 'gate_rounds_scope_state_paired_check'"
        ) as cur,
    ):
        row = await cur.fetchone()
    assert row is not None, (
        "gate_rounds_scope_state_paired_check trigger missing after 0029 "
        "table rebuild; spec section W paired-row invariant is no longer "
        "DB-enforced on the OSS sidecar for gate_rounds."
    )
    name, tbl_name, sql_text = row
    assert tbl_name == "gate_rounds", (
        "trigger must be attached to gate_rounds, found tbl_name="
        f"{tbl_name!r}"
    )
    assert "RELAY-STATE-002" in (sql_text or ""), (
        "trigger SQL must raise RELAY-STATE-002 (matches the body in "
        "0016_scope_state_extension.sql lines 168-178)"
    )
    assert "scope_kind = 'gate_round'" in (sql_text or ""), (
        "trigger must check scope_state for scope_kind='gate_round'"
    )


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_gate_rounds_paired_check_trigger_fires(
    tmp_path: Path,
) -> None:
    """End-to-end: inserting into gate_rounds without a matching
    scope_state row MUST raise RELAY-STATE-002. Proves the trigger is
    not just present in sqlite_master but actually enforces the
    paired-row invariant.
    """

    db_path = tmp_path / "sidecar.db"
    await _apply_all_migrations(db_path)
    async with aiosqlite.connect(str(db_path)) as conn:
        # No prior INSERT into scope_state -> the BEFORE INSERT trigger
        # must abort with RELAY-STATE-002.
        with pytest.raises(aiosqlite.IntegrityError) as exc_info:
            await conn.execute(
                "INSERT INTO gate_rounds ("
                "  gate_round_id, scope_type, scope_id, round, "
                "  initiated_by, opened_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "11111111-1111-1111-1111-111111111111",
                    "run",
                    "22222222-2222-2222-2222-222222222222",
                    1,
                    "control_plane",
                    "2026-05-18T00:00:00Z",
                ),
            )
    assert "RELAY-STATE-002" in str(exc_info.value), exc_info.value


# ---------------------------------------------------------------------------
# SR-M1-002: runtime POST /v1/gate-drafts handler must emit a spec-aligned
# initiated_by value so the canonical GateRound envelope validates.
# ---------------------------------------------------------------------------


def _runtime_gate_round_initiated_by_literal() -> str:
    """Parse runtime.py and return the string literal passed as
    ``initiated_by`` inside the gate-draft handler's
    ``runtime.gate_rounds.setdefault(...).append({...})`` call. Source
    inspection keeps the test loosely coupled to surrounding payload
    fields (worker_id, manifest_commit_hash, etc.) that aren't part of
    the GateRound envelope.
    """

    source = RUNTIME_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    candidates: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        # Find a Dict literal whose keys include both 'gate_round_id'
        # and 'initiated_by' -- this is the gate-draft handler shape.
        key_names: set[str] = set()
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                key_names.add(key.value)
        if not {"gate_round_id", "initiated_by", "opened_at"}.issubset(
            key_names
        ):
            continue
        for key, value in zip(node.keys, node.values, strict=False):
            if (
                isinstance(key, ast.Constant)
                and key.value == "initiated_by"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                candidates.append(value.value)
    assert len(candidates) == 1, (
        "expected exactly one gate-draft handler dict literal with "
        f"initiated_by; found {len(candidates)}: {candidates!r}"
    )
    return candidates[0]


@pytest.mark.plumbing
def test_runtime_gate_round_initiated_by_is_in_spec_enum() -> None:
    """The literal value runtime.py:~3880 passes as initiated_by must
    be in the 4-value spec enum
    {control_plane, cron, user, remediation}. Pre-fix the literal was
    'submission', which is NOT in the enum.
    """

    value = _runtime_gate_round_initiated_by_literal()
    assert value in {"control_plane", "cron", "user", "remediation"}, (
        "runtime.py gate-draft handler emits initiated_by="
        f"{value!r}; the GateRound envelope at "
        "packages/schemas/python/relay_schemas/envelopes.py:381 "
        "Literal-pins this to {control_plane, cron, user, remediation}. "
        "Per m1-f08 data migration the spec-aligned mapping for "
        "'submission' is 'control_plane'."
    )


@pytest.mark.plumbing
def test_runtime_gate_round_dict_validates_against_envelope() -> None:
    """Pydantic round-trip: construct a minimum-valid GateRound dict
    using the runtime's emitted initiated_by literal and validate
    against the canonical envelope. Pre-fix this raises
    pydantic.ValidationError because 'submission' is not in the
    Literal enum.
    """

    initiated_by = _runtime_gate_round_initiated_by_literal()
    payload = {
        "schema_version": "relay.gate_round.v1",
        "gate_round_id": str(uuid.uuid4()),
        "gate_id": str(uuid.uuid4()),
        "scope_type": "run",
        "scope_id": str(uuid.uuid4()),
        "round": 1,
        "initiated_at": "2026-05-18T00:00:00Z",
        "initiated_by": initiated_by,
    }
    # MUST NOT raise. Pre-fix this raises with a Literal mismatch on
    # initiated_by; post-fix the value is 'control_plane' and the
    # model validates cleanly.
    envelope = GateRound.model_validate(payload)
    assert envelope.initiated_by == initiated_by


# ---------------------------------------------------------------------------
# SR-M1-002 source-level guard: the literal string 'submission' must not
# reappear in runtime.py as an initiated_by value. (Belt-and-braces; the
# AST guard above is the primary assertion.)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_runtime_does_not_emit_submission_as_initiated_by() -> None:
    """Grep guard: runtime.py must not contain
    ``"initiated_by": "submission"``. Catches future regressions in
    other handlers that copy-paste the broken pattern.
    """

    source = RUNTIME_PATH.read_text(encoding="utf-8")
    # Match both single- and double-quoted string forms with optional
    # surrounding whitespace.
    pattern = re.compile(
        r"""['"]initiated_by['"]\s*:\s*['"]submission['"]"""
    )
    matches = pattern.findall(source)
    assert not matches, (
        "runtime.py still contains an initiated_by='submission' "
        "literal; the spec enum at envelopes.py:381 does not accept "
        "'submission'. Use 'control_plane' (m1-f08 data-migration "
        f"mapping). Found {len(matches)} occurrence(s)."
    )
